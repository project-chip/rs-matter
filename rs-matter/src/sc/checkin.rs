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

//! The Check-In message: its payload codec and the low-level per-message send.
//!
//! The codec ([`CheckIn::generate`]/[`CheckIn::parse`]) is just crypto and byte
//! layout; [`CheckIn::send_to`] delivers a single message sessionlessly. The
//! Check-In Counter and the registration/key store live elsewhere.

use core::num::NonZeroU8;

use crate::crypto::{
    Aead, AeadNonce, CanonAeadKeyRef, Crypto, Digest, HmacHash, AEAD_CANON_KEY_LEN, AEAD_NONCE_LEN,
    AEAD_TAG_LEN,
};
use crate::dm::NodeId;
use crate::error::{Error, ErrorCode};
use crate::sc::OpCode;
use crate::transport::exchange::Exchange;
use crate::Matter;

/// The Check-In Counter, carried on the wire as a little-endian value inside the
/// encrypted section.
type Counter = u32;

/// Size (in bytes) of the Check-In Counter on the wire.
const COUNTER_LEN: usize = core::mem::size_of::<Counter>();

/// The minimum size of a Check-In payload: nonce + counter + MIC, i.e. a payload
/// carrying no application data.
pub const MIN_PAYLOAD_LEN: usize = AEAD_NONCE_LEN + COUNTER_LEN + AEAD_TAG_LEN;

/// Return the size of a Check-In payload carrying `app_data_len` bytes of
/// application data.
pub const fn payload_len(app_data_len: usize) -> usize {
    MIN_PAYLOAD_LEN + app_data_len
}

/// The decrypted content of a Check-In message.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CheckInPayload<'a> {
    /// The Check-In Counter carried by the message.
    pub counter: u32,
    /// The application data carried by the message (empty if the use case does
    /// not use it). Borrows from the caller's decryption buffer.
    pub app_data: &'a [u8],
}

/// The Check-In message codec, bound to a single symmetric key.
///
/// A thin, zero-copy view over a key that lives elsewhere (e.g. a registration
/// entry). The same key is used both to derive the per-message nonce (via HMAC)
/// and to encrypt the payload (via AEAD); there is no key derivation.
pub struct CheckIn<'k> {
    /// The symmetric key shared with the client.
    key: CanonAeadKeyRef<'k>,
}

impl<'k> CheckIn<'k> {
    /// Create a new [`CheckIn`] codec borrowing the given symmetric key.
    pub const fn new(key: CanonAeadKeyRef<'k>) -> Self {
        Self { key }
    }

    /// Generate (encrypt) a Check-In message payload.
    ///
    /// `counter` is the current Check-In Counter value; the caller owns its
    /// monotonicity and persistence. `app_data` is the use-case payload (empty
    /// if unused). `payload` is the output buffer, at least [`payload_len`]
    /// (`app_data.len()`) bytes long.
    ///
    /// On success returns the sub-slice of `payload` holding the complete
    /// message (`nonce || ciphertext || MIC`).
    pub fn generate<'p, C: Crypto>(
        &self,
        crypto: C,
        counter: Counter,
        app_data: &[u8],
        payload: &'p mut [u8],
    ) -> Result<&'p [u8], Error> {
        let total = payload_len(app_data.len());
        if payload.len() < total {
            Err(ErrorCode::NoSpace)?;
        }

        let nonce = self.generate_nonce(&crypto, counter)?;

        // Layout: nonce (plaintext) || counter || app_data || tag. The AEAD
        // encrypts the counter + app_data in place and appends the tag.
        let payload = &mut payload[..total];
        let (nonce_out, rest) = payload.split_at_mut(AEAD_NONCE_LEN);
        nonce_out.copy_from_slice(nonce.access());

        let plain_len = COUNTER_LEN + app_data.len();
        rest[..COUNTER_LEN].copy_from_slice(&counter.to_le_bytes());
        rest[COUNTER_LEN..plain_len].copy_from_slice(app_data);

        crypto
            .aead()?
            .encrypt_in_place(self.key, nonce.reference(), &[], rest, plain_len)?;

        Ok(payload)
    }

    /// Decrypt, authenticate and validate the nonce of a received Check-In
    /// message, returning its counter and application data.
    ///
    /// This is the *stateless* part of receiving: AEAD decryption/verification
    /// plus recomputing and checking the nonce. The stateful counter-validation
    /// and key-refresh (which need the stored starting counter and offset) are
    /// the caller's responsibility and are not done here.
    ///
    /// `payload` is decrypted in place; on success [`CheckInPayload::app_data`]
    /// borrows from it.
    pub fn parse<'p, C: Crypto>(
        &self,
        crypto: C,
        payload: &'p mut [u8],
    ) -> Result<CheckInPayload<'p>, Error> {
        if payload.len() < MIN_PAYLOAD_LEN {
            Err(ErrorCode::Invalid)?;
        }

        let (nonce_bytes, ciphertext) = payload.split_at_mut(AEAD_NONCE_LEN);

        let mut nonce = AeadNonce::new();
        nonce.access_mut().copy_from_slice(nonce_bytes);

        // Decrypt+verify strips the tag, leaving `counter || app_data`.
        let plaintext =
            crypto
                .aead()?
                .decrypt_in_place(self.key, nonce.reference(), &[], ciphertext)?;

        let counter = u32::from_le_bytes(unwrap!(plaintext[..COUNTER_LEN].try_into()));

        // The nonce is derived from the counter, so a valid decryption still has
        // to agree with the nonce that was sent.
        let expected_nonce = self.generate_nonce(&crypto, counter)?;
        if expected_nonce.access() != nonce_bytes {
            Err(ErrorCode::Invalid)?;
        }

        Ok(CheckInPayload {
            counter,
            app_data: &plaintext[COUNTER_LEN..],
        })
    }

    /// Derive the per-message nonce: the leading bytes of `HMAC(key, counter)`.
    fn generate_nonce<C: Crypto>(&self, crypto: C, counter: Counter) -> Result<AeadNonce, Error> {
        let mut mac = crypto.hmac::<AEAD_CANON_KEY_LEN>(self.key)?;
        mac.update(&counter.to_le_bytes())?;

        let mut hash = HmacHash::new();
        mac.finish(&mut hash)?;

        let mut nonce = AeadNonce::new();
        nonce
            .access_mut()
            .copy_from_slice(&hash.access()[..AEAD_NONCE_LEN]);

        Ok(nonce)
    }

    /// Build a Check-In message and send it to the node `(fab_idx, node_id)`,
    /// resolving its operational address over mDNS and sending sessionlessly
    /// (Secure Channel opcode `CheckIn`, no MRP).
    ///
    /// The low-level per-message primitive: it takes the exact `counter` and
    /// `app_data` to use, and depends on nothing but this codec's key. The
    /// caller owns the counter (a batch of messages can share one value) and the
    /// application data.
    ///
    /// Requires a running mDNS responder to service the address resolve.
    pub async fn send_to<C: Crypto>(
        &self,
        matter: &Matter<'_>,
        crypto: C,
        fab_idx: NonZeroU8,
        node_id: NodeId,
        counter: u32,
        app_data: &[u8],
    ) -> Result<(), Error> {
        let mut buf = [0u8; payload_len(2)];
        if app_data.len() > buf.len() - MIN_PAYLOAD_LEN {
            Err(ErrorCode::NoSpace)?;
        }

        let payload = self.generate(&crypto, counter, app_data, &mut buf)?;
        let len = payload.len();

        let mut exchange =
            Exchange::initiate_unsecured_operational(matter, &crypto, fab_idx, node_id).await?;

        exchange.send(OpCode::CheckIn, &buf[..len]).await
    }
}

/// The monotonic counter that seeds every Check-In message's nonce.
///
/// It must never repeat a value for a given key (a reused nonce breaks the
/// encryption), and must keep increasing across reboots and power loss. To avoid
/// a durable-storage write on every message, it persists in *epochs*: only the
/// next epoch boundary is stored, and after a restart the counter resumes from
/// that boundary — jumping forward by up to `epoch`, never backwards. So a value
/// is written to storage roughly once per `epoch` increments instead of every
/// time.
///
/// This type is storage-agnostic: it tracks when a persist is due and hands back
/// the value to write, but the caller owns the actual durable read/write (and
/// the random initial value picked on factory reset).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CheckInCounter {
    /// The last value that was used (the next message uses `value + 1`).
    value: u32,
    /// The next boundary at which the counter must be persisted. Also the value
    /// the counter will resume from after a restart.
    next_epoch: u32,
    /// How far ahead of the live value the persisted boundary is kept.
    epoch: u32,
}

impl CheckInCounter {
    /// Create a counter that resumes from `start`, persisting every `epoch`
    /// increments.
    ///
    /// `start` is the value read back from durable storage (or a fresh random
    /// value on first use / factory reset). Because the counter may already have
    /// advanced up to `epoch` past `start` before the last shutdown, it resumes
    /// exactly at `start` and the caller MUST immediately persist the returned
    /// boundary ([`persist_value`](Self::persist_value)) so the next restart
    /// resumes past every value this run might use.
    ///
    /// `epoch` must be non-zero.
    pub fn new(start: u32, epoch: u32) -> Self {
        debug_assert!(epoch != 0);

        Self {
            value: start,
            next_epoch: start.wrapping_add(epoch),
            epoch,
        }
    }

    /// The counter value to encrypt the next Check-In message with.
    ///
    /// This only peeks; it does not consume the value. Call [`advance`](Self::advance)
    /// once the message(s) using it have been produced. Peeking lets a batch of
    /// Check-Ins to several clients share a single counter value.
    pub fn next(&self) -> u32 {
        self.value.wrapping_add(1)
    }

    /// Consume the value returned by [`next`](Self::next), advancing the counter.
    ///
    /// Returns `Some(value)` when the counter has reached a new epoch boundary
    /// and that value MUST be persisted before any further Check-In is sent;
    /// returns `None` when no persist is due yet.
    #[must_use = "the returned value must be persisted before sending more Check-Ins"]
    pub fn advance(&mut self) -> Option<u32> {
        self.value = self.value.wrapping_add(1);

        // The counter advances one at a time and the boundary moves with it, so
        // it lands exactly on `next_epoch` once per epoch. When it does, move the
        // boundary forward and ask the caller to persist the new one.
        if self.value == self.next_epoch {
            self.next_epoch = self.next_epoch.wrapping_add(self.epoch);
            Some(self.next_epoch)
        } else {
            None
        }
    }

    /// Jump the counter forward by `delta` (wrapping), returning a new boundary
    /// to persist when the jump crosses one.
    ///
    /// Used to invalidate outstanding Check-In counter values in one step. The
    /// persist boundary is re-established one epoch past the new value, so a
    /// restart still resumes past everything this run may use.
    #[must_use = "the returned value must be persisted before sending more Check-Ins"]
    pub fn advance_by(&mut self, delta: u32) -> Option<u32> {
        self.value = self.value.wrapping_add(delta);

        // Re-anchor the boundary one epoch past the new value, unless the jump
        // stayed within the current epoch (then nothing new needs persisting).
        let next_epoch = self.value.wrapping_add(self.epoch);
        if next_epoch != self.next_epoch {
            self.next_epoch = next_epoch;
            Some(self.next_epoch)
        } else {
            None
        }
    }

    /// The boundary value that should currently be held in durable storage.
    ///
    /// Persist this right after [`new`](Self::new), so a restart resumes past
    /// every value this run may use.
    pub fn persist_value(&self) -> u32 {
        self.next_epoch
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{test_only_crypto, CanonAeadKeyRef};

    use super::{payload_len, CheckIn, CheckInCounter};

    /// A known-answer Check-In message test vector (shared with the reference
    /// implementation's fixtures); matching it byte-for-byte proves interop of
    /// the crypto and wire layout.
    struct Vector {
        key: [u8; 16],
        app_data: &'static [u8],
        counter: u32,
        payload: &'static [u8],
    }

    const VECTORS: &[Vector] = &[
        // Vector 1: empty application data.
        Vector {
            key: [
                0xd9, 0x0e, 0x13, 0x18, 0x0d, 0x00, 0xba, 0xad, 0xd2, 0x0c, 0xf5, 0xed, 0x49, 0x13,
                0xd3, 0xff,
            ],
            app_data: &[],
            counter: 12,
            payload: &[
                0x45, 0x80, 0xd2, 0xc6, 0xf1, 0x31, 0x0d, 0xc4, 0xeb, 0x64, 0xf1, 0xf8, 0xe8, 0xbd,
                0xc2, 0x1f, 0xb5, 0x19, 0x5d, 0x74, 0x7d, 0xd2, 0x87, 0x9b, 0x2b, 0x0d, 0x43, 0xce,
                0x5b, 0x1c, 0x56, 0x50, 0x78,
            ],
        },
        // Vector 2: application data "This".
        Vector {
            key: [
                0x18, 0xfd, 0xbc, 0xea, 0xef, 0x01, 0x95, 0x5b, 0x0e, 0xc8, 0x75, 0xed, 0xa3, 0xae,
                0x6e, 0xe8,
            ],
            app_data: &[0x54, 0x68, 0x69, 0x73],
            counter: 15,
            payload: &[
                0x9b, 0x02, 0xed, 0x21, 0xee, 0x0c, 0x7b, 0x49, 0x19, 0x85, 0x50, 0x2e, 0x37, 0x2d,
                0xbd, 0x7b, 0x3f, 0x8b, 0x4f, 0x8e, 0x3c, 0x5a, 0xd9, 0x94, 0x19, 0x38, 0x9f, 0x41,
                0xa8, 0xd6, 0x09, 0x93, 0x8c, 0x67, 0xa8, 0x6d, 0x65,
            ],
        },
        // Vector 3: application data "This is a".
        Vector {
            key: [
                0xd9, 0x0e, 0x13, 0x18, 0x0d, 0x00, 0xba, 0xad, 0xd2, 0x0c, 0xf5, 0xed, 0x49, 0x13,
                0xd3, 0xff,
            ],
            app_data: &[0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61],
            counter: 11,
            payload: &[
                0xaa, 0x84, 0xbc, 0x60, 0x88, 0x6a, 0x63, 0xa8, 0x47, 0x5d, 0x5d, 0xbe, 0xb5, 0x6d,
                0x63, 0x5f, 0xa9, 0x52, 0x85, 0xae, 0x33, 0x62, 0x66, 0x13, 0xc7, 0x63, 0x6c, 0xe3,
                0xe3, 0xb2, 0xa8, 0xb1, 0x3a, 0x8c, 0x89, 0xbe, 0xf7, 0x68, 0x91, 0xe8, 0xe2, 0x96,
            ],
        },
        // Vector 4: application data "This is a longer".
        Vector {
            key: [
                0xca, 0x67, 0xd4, 0x1f, 0xf7, 0x11, 0x29, 0x10, 0xfd, 0xd1, 0x8a, 0x1b, 0xf9, 0x9e,
                0xa9, 0x74,
            ],
            app_data: &[
                0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x6c, 0x6f, 0x6e, 0x67,
                0x65, 0x72,
            ],
            counter: 11,
            payload: &[
                0x7a, 0x97, 0x72, 0x24, 0x3c, 0x97, 0xc8, 0x7d, 0x5f, 0x3a, 0x31, 0xc4, 0xe6, 0xdb,
                0xbc, 0x1a, 0xa5, 0x66, 0xc4, 0x43, 0xc2, 0x05, 0x86, 0x06, 0x6b, 0x42, 0x7b, 0xfc,
                0xaa, 0xad, 0x78, 0xda, 0x4a, 0x10, 0x5a, 0x13, 0x42, 0xad, 0xbf, 0x3f, 0x47, 0x98,
                0xcd, 0x81, 0xb9, 0xef, 0x97, 0xbb, 0xb7,
            ],
        },
        // Vector 5: application data "This is a longer string".
        Vector {
            key: [
                0xca, 0x67, 0xd4, 0x1f, 0xf7, 0x11, 0x29, 0x10, 0xfd, 0xd1, 0x8a, 0x1b, 0xf9, 0x9e,
                0xa9, 0x74,
            ],
            app_data: &[
                0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x6c, 0x6f, 0x6e, 0x67,
                0x65, 0x72, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
            ],
            counter: 12,
            payload: &[
                0x06, 0x34, 0x67, 0x6e, 0xa6, 0xe0, 0x70, 0x7b, 0x7a, 0xd7, 0x81, 0x4f, 0xf8, 0x2e,
                0x5b, 0x18, 0xd1, 0x9a, 0x23, 0xb2, 0xe4, 0xfa, 0xdf, 0x82, 0x92, 0x53, 0x51, 0x7f,
                0xf3, 0xc9, 0x1d, 0x8d, 0x47, 0x84, 0x31, 0x5a, 0x1e, 0x32, 0x08, 0xb8, 0xec, 0xf6,
                0x11, 0x8b, 0x02, 0x1a, 0x5a, 0x4c, 0xd4, 0xe9, 0xd4, 0x13, 0x8d, 0xff, 0x29, 0x71,
            ],
        },
    ];

    #[test]
    fn generate_matches_reference_vectors() {
        let crypto = test_only_crypto();

        for (i, v) in VECTORS.iter().enumerate() {
            let checkin = CheckIn::new(CanonAeadKeyRef::new(&v.key));

            let mut buf = [0u8; 128];
            let out = checkin
                .generate(&crypto, v.counter, v.app_data, &mut buf)
                .unwrap_or_else(|e| panic!("vector {}: generate failed: {e:?}", i + 1));

            assert_eq!(
                out,
                v.payload,
                "vector {}: payload mismatch\n got: {:02x?}\nwant: {:02x?}",
                i + 1,
                out,
                v.payload
            );
        }
    }

    #[test]
    fn parse_recovers_counter_and_app_data() {
        let crypto = test_only_crypto();

        for (i, v) in VECTORS.iter().enumerate() {
            let checkin = CheckIn::new(CanonAeadKeyRef::new(&v.key));

            let mut buf = v.payload.to_vec();
            let parsed = checkin
                .parse(&crypto, &mut buf)
                .unwrap_or_else(|e| panic!("vector {}: parse failed: {e:?}", i + 1));

            assert_eq!(parsed.counter, v.counter, "vector {}: counter", i + 1);
            assert_eq!(parsed.app_data, v.app_data, "vector {}: app_data", i + 1);
        }
    }

    #[test]
    fn generate_then_parse_roundtrips() {
        let crypto = test_only_crypto();

        let key_bytes = [0x11u8; 16];
        let checkin = CheckIn::new(CanonAeadKeyRef::new(&key_bytes));
        let app_data = b"roundtrip";
        let counter = 0xdead_beef;

        let mut buf = [0u8; 128];
        let out = checkin
            .generate(&crypto, counter, app_data, &mut buf)
            .unwrap();

        let mut recv = out.to_vec();
        let parsed = checkin.parse(&crypto, &mut recv).unwrap();

        assert_eq!(parsed.counter, counter);
        assert_eq!(parsed.app_data, app_data);
    }

    #[test]
    fn parse_rejects_wrong_key() {
        let crypto = test_only_crypto();

        let v = &VECTORS[0];
        let mut wrong = v.key;
        wrong[0] ^= 0xff;
        let checkin = CheckIn::new(CanonAeadKeyRef::new(&wrong));

        let mut buf = v.payload.to_vec();
        assert!(checkin.parse(&crypto, &mut buf).is_err());
    }

    #[test]
    fn parse_rejects_tampered_ciphertext() {
        let crypto = test_only_crypto();

        let v = &VECTORS[0];
        let checkin = CheckIn::new(CanonAeadKeyRef::new(&v.key));

        let mut buf = v.payload.to_vec();
        // Flip a bit in the ciphertext (right after the 13-byte nonce).
        buf[13] ^= 0x01;
        assert!(checkin.parse(&crypto, &mut buf).is_err());
    }

    #[test]
    fn generate_rejects_small_buffer() {
        let crypto = test_only_crypto();

        let key_bytes = [0x22u8; 16];
        let checkin = CheckIn::new(CanonAeadKeyRef::new(&key_bytes));

        let mut buf = [0u8; payload_len(0) - 1];
        assert!(checkin.generate(&crypto, 1, &[], &mut buf).is_err());
    }

    #[test]
    fn counter_increments_by_one() {
        let mut ctr = CheckInCounter::new(100, 10);

        // `next` peeks; the value is not consumed until `advance`.
        assert_eq!(ctr.next(), 101);
        assert_eq!(ctr.next(), 101);

        let _ = ctr.advance();
        assert_eq!(ctr.next(), 102);
    }

    #[test]
    fn counter_persists_only_at_epoch_boundaries() {
        let epoch = 10;
        let mut ctr = CheckInCounter::new(100, epoch);

        // Boundary to hold in storage right after construction.
        assert_eq!(ctr.persist_value(), 110);

        // No persist is due until the value reaches the boundary...
        for expected in 101..110 {
            assert_eq!(ctr.next(), expected);
            assert_eq!(ctr.advance(), None, "unexpected persist at {expected}");
        }

        // ...then exactly at the boundary, the next boundary must be persisted.
        assert_eq!(ctr.next(), 110);
        assert_eq!(ctr.advance(), Some(120));

        // ...and not again until the following boundary.
        for _ in 111..120 {
            assert_eq!(ctr.advance(), None);
        }
        assert_eq!(ctr.advance(), Some(130));
    }

    #[test]
    fn counter_resumes_past_used_values_after_restart() {
        let epoch = 1000;

        // Session 1 starts from a persisted value and uses a few counters.
        let mut ctr = CheckInCounter::new(5000, epoch);
        let persisted = ctr.persist_value(); // stored right after construction
        assert_eq!(persisted, 6000);

        let mut last_used = 0;
        for _ in 0..7 {
            last_used = ctr.next();
            let _ = ctr.advance();
        }
        assert_eq!(last_used, 5007);

        // A restart (power loss) reads back only the persisted boundary — not the
        // live value — and resumes from there. Every value the next session
        // hands out must be strictly greater than anything session 1 used.
        let mut ctr = CheckInCounter::new(persisted, epoch);
        assert!(ctr.next() > last_used);
    }

    #[test]
    fn counter_wraps_around_the_32bit_space() {
        let epoch = 4;
        // Start near the top so both the value and the epoch boundary roll over.
        let mut ctr = CheckInCounter::new(u32::MAX - 2, epoch);

        let mut seen = alloc::vec::Vec::new();
        for _ in 0..8 {
            seen.push(ctr.next());
            let _ = ctr.advance();
        }

        // The value rolls over cleanly from u32::MAX to 0.
        assert_eq!(
            seen,
            [u32::MAX - 1, u32::MAX, 0, 1, 2, 3, 4, 5],
            "counter did not wrap cleanly"
        );
    }

    #[test]
    fn advance_by_jumps_the_counter_and_re_anchors_the_boundary() {
        let epoch = 100;
        let mut ctr = CheckInCounter::new(5000, epoch);
        assert_eq!(ctr.next(), 5001);

        // Half-range jump: the reported counter (`next`) moves by exactly the
        // delta, and a new boundary is persisted one epoch past the new value.
        let half = u32::MAX / 2;
        assert_eq!(
            ctr.advance_by(half),
            Some(5000u32.wrapping_add(half) + epoch)
        );
        assert_eq!(ctr.next(), 5001u32.wrapping_add(half));

        // Full-range jump wraps the 32-bit space (N -> N-1).
        let before = ctr.next();
        assert_eq!(ctr.advance_by(u32::MAX), Some(ctr.persist_value()));
        assert_eq!(ctr.next(), before.wrapping_add(u32::MAX));
    }
}
