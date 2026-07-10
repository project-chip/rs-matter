/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! Persisted state that lets a CASE session be resumed by its peer
//! without a full Sigma1/2/3 exchange (Matter Core spec §4.14.2.2).
//!
//! One [`ResumableSession`] holds exactly the five items the spec calls
//! "Session Resumption State" — `SharedSecret`, local fabric index,
//! peer node ID, peer CATs and the current `ResumptionID`. A bounded
//! LRU collection ([`ResumableSessions`]) owns these records at
//! runtime and mirrors them to a single KV blob under
//! [`CASE_RESUMPTION_KEY`].

use core::num::NonZeroU8;

use crate::crypto::CanonPkcSharedSecret;
use crate::error::Error;
use crate::fabric::MAX_FABRICS;
use crate::persist::{KvBlobStore, CASE_RESUMPTION_KEY};
use crate::tlv::{FromTLV, TLVElement, TLVTag, ToTLV};
use crate::transport::session::{NocCatIds, MAX_SESSIONS};
use crate::utils::init::{init, Init};
use crate::utils::storage::{Vec, WriteBuf};

use super::casep::CaseResumptionId;

const fn min3(a: usize, b: usize, c: usize) -> usize {
    let ab = if a < b { a } else { b };
    if ab < c {
        ab
    } else {
        c
    }
}

/// Capacity of the CASE session resumption cache.
///
/// Matches the connectedhomeip default (`3 × MAX_FABRICS`), further
/// capped by [`MAX_SESSIONS`] (never larger than the live-session
/// pool) and by an absolute ceiling of 16 (so a large `max-fabrics-*`
/// build cannot blow past the default 4 KiB KV buffer with the
/// resumption blob alone).
pub const MAX_RESUMPTION_RECORDS: usize = min3(3 * MAX_FABRICS, MAX_SESSIONS, 16);

/// A single peer's CASE session resumption state.
///
/// Fields match §4.14.2.2.1 of the Matter Core spec (R1.5.1):
/// SharedSecret, Local Fabric Index, Peer Node ID, Peer CATs,
/// ResumptionID. TLV representation is a context-tagged struct so it
/// is forward-compatible if we ever need to add an optional field.
#[derive(Debug, Clone, FromTLV, ToTLV)]
pub struct ResumableSession {
    /// Local fabric index the session belongs to.
    pub fab_idx: NonZeroU8,
    /// Peer's operational Node ID.
    pub peer_nodeid: u64,
    /// Peer's CASE Authenticated Tags (up to
    /// [`MAX_CAT_IDS_PER_NOC`](crate::transport::session::MAX_CAT_IDS_PER_NOC);
    /// zeroed slots mean absent).
    pub peer_cat_ids: NocCatIds,
    /// The `ResumptionID` last agreed with the peer. Rotated on every
    /// successful resumption (the responder mints a new ID in
    /// Sigma2_Resume and both sides overwrite this field).
    pub resumption_id: CaseResumptionId,
    /// The ECDH shared secret from the original full CASE handshake.
    /// Kept unchanged for the lifetime of the record — successful
    /// resumption rotates only [`Self::resumption_id`], never the
    /// secret (Matter Core spec §4.14.2.2).
    pub shared_secret: CanonPkcSharedSecret,
}

impl ResumableSession {
    /// True if this record belongs to the peer identified by
    /// `(fab_idx, peer_nodeid)`. Used by the initiator to decide
    /// whether to attempt resumption before sending Sigma1.
    pub fn is_for_peer(&self, fab_idx: NonZeroU8, peer_nodeid: u64) -> bool {
        self.fab_idx == fab_idx && self.peer_nodeid == peer_nodeid
    }

    /// True if this record's [`Self::resumption_id`] equals `id`. Used
    /// by the responder when it receives a Sigma1 with the optional
    /// resumption fields.
    pub fn has_resumption_id(&self, id: &[u8]) -> bool {
        self.resumption_id.reference().access().as_slice() == id
    }
}

/// Bounded LRU cache of [`ResumableSession`] records, persisted as a
/// single TLV blob under [`CASE_RESUMPTION_KEY`].
///
/// Ordering invariant: **newest at the tail, oldest at the head**.
/// [`Self::insert_or_update`] always ends with the freshly-written
/// record at the tail, so eviction under pressure drops the record
/// whose peer we have not spoken to for the longest.
pub struct ResumableSessions {
    records: Vec<ResumableSession, MAX_RESUMPTION_RECORDS>,
}

impl ResumableSessions {
    /// Create a new, empty cache.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// In-place initializer for a new, empty cache.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            records <- Vec::init(),
        })
    }

    /// Number of records currently held.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True if there are no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterate over the records in LRU order (oldest first).
    pub fn iter(&self) -> impl Iterator<Item = &ResumableSession> {
        self.records.iter()
    }

    /// Drop every record — in memory only, does not touch storage.
    pub fn reset(&mut self) {
        self.records.clear();
    }

    /// Look up a record by its resumption ID. Used by the responder on
    /// receipt of a Sigma1 that carries the optional resumption
    /// fields. Returns `None` if `resumption_id` has the wrong length
    /// or no matching record is held.
    pub fn find_by_resumption_id(&self, resumption_id: &[u8]) -> Option<&ResumableSession> {
        self.records
            .iter()
            .find(|r| r.has_resumption_id(resumption_id))
    }

    /// Look up a record by peer identity. Used by the initiator before
    /// building Sigma1 to decide whether to attempt resumption.
    pub fn find_by_peer(&self, fab_idx: NonZeroU8, peer_nodeid: u64) -> Option<&ResumableSession> {
        self.records
            .iter()
            .find(|r| r.is_for_peer(fab_idx, peer_nodeid))
    }

    /// Insert a fresh record or refresh an existing one identified by
    /// `(fab_idx, peer_nodeid)`. In either case the record ends up at
    /// the tail (most-recent). If the cache is at capacity, the head
    /// (least-recent) record is evicted to make room.
    ///
    /// This is a no-op if [`MAX_RESUMPTION_RECORDS`] is zero.
    pub fn insert_or_update(&mut self, record: ResumableSession) {
        if MAX_RESUMPTION_RECORDS == 0 {
            return;
        }

        // Drop any existing record for the same peer — the peer just
        // completed a fresh handshake or a successful resumption, so
        // any prior `resumption_id` / `shared_secret` for it is stale.
        let key = (record.fab_idx, record.peer_nodeid);
        self.records.retain(|r| (r.fab_idx, r.peer_nodeid) != key);

        if self.records.is_full() {
            // Evict the oldest record. `remove(0)` is O(N) on
            // `heapless::Vec` but N is bounded by
            // [`MAX_RESUMPTION_RECORDS`] (≤ 16) so the shuffle is
            // negligible against the cost of a fresh CASE handshake.
            self.records.remove(0);
        }

        // `push` cannot fail — either we started with room, or we just
        // evicted one entry.
        let _ = self.records.push(record);
    }

    /// Drop every record belonging to `fab_idx`. Call this from the
    /// fabric-removal path so removed-fabric peers cannot resume onto
    /// a fabric that no longer exists.
    pub fn remove_for_fabric(&mut self, fab_idx: NonZeroU8) {
        self.records.retain(|r| r.fab_idx != fab_idx);
    }

    /// Drop the record identified by peer identity, if any.
    pub fn remove_by_peer(&mut self, fab_idx: NonZeroU8, peer_nodeid: u64) {
        self.records
            .retain(|r| !r.is_for_peer(fab_idx, peer_nodeid));
    }

    /// Load the cache from `store` under [`CASE_RESUMPTION_KEY`].
    /// Missing key is not an error — the cache simply stays empty
    /// (first boot, or after [`Self::reset_persist`]).
    pub fn load_persist<S: KvBlobStore>(
        &mut self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.reset();

        let Some(data) = store.load(CASE_RESUMPTION_KEY, buf)? else {
            return Ok(());
        };

        let loaded =
            Vec::<ResumableSession, MAX_RESUMPTION_RECORDS>::from_tlv(&TLVElement::new(data))?;
        self.records = loaded;

        info!(
            "Loaded {} CASE session resumption record(s) from storage",
            self.records.len()
        );

        Ok(())
    }

    /// Serialise the current cache to `store` under
    /// [`CASE_RESUMPTION_KEY`]. Called from the background snapshot
    /// task whenever the in-memory cache diverges from what was last
    /// persisted.
    pub fn store_persist<S: KvBlobStore>(&self, mut store: S, buf: &mut [u8]) -> Result<(), Error> {
        // Serialise into `buf` first; then split it so the remainder
        // can serve as the KV store's own scratch space. This mirrors
        // the same split-and-lend pattern that [`Persist::store`] uses
        // through its access closure.
        let len = {
            let mut wb = WriteBuf::new(buf);
            self.records.to_tlv(&TLVTag::Anonymous, &mut wb)?;
            wb.get_tail()
        };

        let (data, scratch) = buf.split_at_mut(len);
        store.store(CASE_RESUMPTION_KEY, data, scratch)
    }

    /// Remove the persisted cache from `store` and wipe the in-memory
    /// copy. Used from [`crate::Matter::reset_persist`].
    pub fn reset_persist<S: KvBlobStore>(
        &mut self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.reset();
        store.remove(CASE_RESUMPTION_KEY, buf)?;

        info!("Removed CASE session resumption cache from storage");

        Ok(())
    }
}

impl Default for ResumableSessions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU8;

    use crate::crypto::CanonPkcSharedSecret;

    use super::super::casep::CaseResumptionId;
    use super::{ResumableSession, ResumableSessions, MAX_RESUMPTION_RECORDS};

    fn rec(fab: u8, nodeid: u64, rid_first_byte: u8) -> ResumableSession {
        let mut resumption_id = CaseResumptionId::new();
        resumption_id.access_mut()[0] = rid_first_byte;

        ResumableSession {
            fab_idx: NonZeroU8::new(fab).unwrap(),
            peer_nodeid: nodeid,
            peer_cat_ids: [0; 3],
            resumption_id,
            shared_secret: CanonPkcSharedSecret::new(),
        }
    }

    #[test]
    fn insert_moves_to_tail_and_dedupes_by_peer() {
        let mut cache = ResumableSessions::new();

        cache.insert_or_update(rec(1, 100, 0xA0));
        cache.insert_or_update(rec(1, 200, 0xB0));
        assert_eq!(cache.len(), 2);

        // Refreshing peer (1,100) with a new resumption_id should
        // replace, not duplicate, and move it to the tail.
        cache.insert_or_update(rec(1, 100, 0xC0));
        assert_eq!(cache.len(), 2);

        let ids: heapless::Vec<u8, 4> = cache
            .iter()
            .map(|r| r.resumption_id.reference().access()[0])
            .collect();
        assert_eq!(ids.as_slice(), &[0xB0, 0xC0]);
    }

    #[test]
    fn find_by_peer_and_by_resumption_id() {
        if MAX_RESUMPTION_RECORDS < 2 {
            return; // small builds where the cache is too tight for this test
        }

        let mut cache = ResumableSessions::new();
        cache.insert_or_update(rec(1, 100, 0xA0));
        cache.insert_or_update(rec(2, 200, 0xB0));

        assert!(cache
            .find_by_peer(NonZeroU8::new(1).unwrap(), 100)
            .is_some());
        assert!(cache
            .find_by_peer(NonZeroU8::new(2).unwrap(), 100)
            .is_none());

        let mut needle = [0u8; 16];
        needle[0] = 0xB0;
        assert!(cache.find_by_resumption_id(&needle).is_some());
        needle[0] = 0xFF;
        assert!(cache.find_by_resumption_id(&needle).is_none());

        // Wrong-length id must not match.
        assert!(cache.find_by_resumption_id(&[0xB0; 8]).is_none());
    }

    #[test]
    fn remove_for_fabric_drops_only_that_fabric() {
        if MAX_RESUMPTION_RECORDS < 3 {
            return;
        }

        let mut cache = ResumableSessions::new();
        cache.insert_or_update(rec(1, 100, 0xA0));
        cache.insert_or_update(rec(2, 100, 0xB0));
        cache.insert_or_update(rec(1, 200, 0xC0));
        assert_eq!(cache.len(), 3);

        cache.remove_for_fabric(NonZeroU8::new(1).unwrap());
        assert_eq!(cache.len(), 1);
        assert!(cache
            .find_by_peer(NonZeroU8::new(2).unwrap(), 100)
            .is_some());
    }
}
