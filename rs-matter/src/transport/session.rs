/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

use core::fmt;
use core::num::NonZeroU8;
use core::time::Duration;

use cfg_if::cfg_if;

use rand_core::RngCore;

use crate::crypto::{
    canon, CanonAeadKey, CanonAeadKeyRef, Crypto, CryptoSensitive, Kdf, AEAD_KEY_ZEROED,
};
use crate::error::*;
use crate::fabric::{FabricMgr, MAX_FABRICS, MAX_GROUPS_PER_FABRIC};
use crate::group_keys::KeySet;

use crate::transport::exchange::ExchangeId;
use crate::transport::mrp::ReliableMessage;
use crate::utils::cell::RefCell;
use crate::utils::epoch::Epoch;
use crate::utils::init::{init, Init, IntoFallibleInit};
use crate::utils::storage::{ParseBuf, WriteBuf};
use crate::Matter;

use super::dedup::{GroupCtrStore, RxCtrState};
use super::exchange::{ExchangeState, MessageMeta, Role};
use super::mrp::RetransEntry;
use super::network::Address;
use super::packet::PacketHdr;
use super::plain_hdr::PlainHdr;
use super::proto_hdr::ProtoHdr;
use super::Packet;

pub const MAX_CAT_IDS_PER_NOC: usize = 3;
pub type NocCatIds = [u32; MAX_CAT_IDS_PER_NOC];

/// Max number of pre-cached group operational keys.
/// Each fabric can have up to [`MAX_GROUP_KEY_MAP_ENTRIES_PER_FABRIC`] key map entries × 3 epoch keys.
pub const MAX_GROUP_OP_KEYS: usize = MAX_FABRICS * MAX_GROUPS_PER_FABRIC * 3;

pub const ATT_CHALLENGE_LEN: usize = 16;

canon!(
    ATT_CHALLENGE_LEN,
    ATT_CHALLENGE_ZEROED,
    AttChallenge,
    AttChallengeRef
);

/// A pre-derived group operational key entry for the session layer cache.
pub struct GroupOpKeyEntry {
    pub fab_idx: NonZeroU8,
    pub key_set_id: u16,
    pub group_id: u16,
    /// The derived Group Session ID for fast filtering.
    pub session_id: u16,
    /// The pre-derived operational key.
    pub op_key: CanonAeadKey,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SessionMode {
    // The Case session will capture the local fabric index
    // and the local fabric index
    Case {
        fab_idx: NonZeroU8,
        cat_ids: NocCatIds,
    },
    // The Pase session always starts with a fabric index of 0
    // (i.e. no fabric) but will be upgraded to the actual fabric index
    // once AddNOC or UpdateNOC is received
    Pase {
        fab_idx: u8,
    },
    // A group session used for group (multicast) messaging.
    Group {
        fab_idx: NonZeroU8,
        group_id: u16,
    },
    #[default]
    PlainText,
}

impl SessionMode {
    pub fn fab_idx(&self) -> u8 {
        match self {
            SessionMode::Case { fab_idx, .. } => fab_idx.get(),
            SessionMode::Pase { fab_idx, .. } => *fab_idx,
            SessionMode::Group { fab_idx, .. } => fab_idx.get(),
            SessionMode::PlainText => 0,
        }
    }
}

pub struct Session {
    // Internal ID which is guaranteeed to be unique accross all sessions and not change when sessions are added/removed
    pub(crate) id: u32,
    peer_addr: Address,
    local_nodeid: u64,
    peer_nodeid: Option<u64>,
    // I find the session initiator/responder role getting confused with exchange initiator/responder
    // So, we might keep this as enc_key and dec_key for now
    dec_key: CanonAeadKey,
    enc_key: CanonAeadKey,
    att_challenge: AttChallenge,
    local_sess_id: u16,
    peer_sess_id: u16,
    msg_ctr: u32,
    rx_ctr_state: RxCtrState,
    mode: SessionMode,
    pub(crate) exchanges: crate::utils::storage::Vec<Option<ExchangeState>, MAX_EXCHANGES>,
    last_use: Duration,
    /// If `true` then the session is considered "expired". Session expiration happens
    /// for the session on behalf of which a fabric is removed.
    ///
    /// Expired sessions can still process their ongoing exchanges, but do not accept any new ones.
    /// Furthermore, expired sessions are the prime candidates for eviction.
    expired: bool,
    reserved: bool,
}

impl Session {
    pub fn new(
        id: u32,
        msg_ctr: u32,
        reserved: bool,
        peer_addr: Address,
        peer_nodeid: Option<u64>,
        epoch: Epoch,
    ) -> Self {
        Self {
            id,
            reserved,
            peer_addr,
            local_nodeid: 0,
            peer_nodeid,
            dec_key: CanonAeadKey::new(),
            enc_key: CanonAeadKey::new(),
            att_challenge: AttChallenge::new(),
            peer_sess_id: 0,
            local_sess_id: 0,
            msg_ctr: msg_ctr & MATTER_MSG_CTR_RANGE,
            rx_ctr_state: RxCtrState::new(0),
            mode: SessionMode::PlainText,
            exchanges: crate::utils::storage::Vec::new(),
            last_use: epoch(),
            expired: false,
        }
    }

    pub fn init(
        id: u32,
        msg_ctr: u32,
        reserved: bool,
        peer_addr: Address,
        peer_nodeid: Option<u64>,
        epoch: Epoch,
    ) -> impl Init<Self> {
        init!(Self {
            id,
            reserved,
            peer_addr,
            local_nodeid: 0,
            peer_nodeid,
            dec_key <- CanonAeadKey::init(),
            enc_key <- CanonAeadKey::init(),
            att_challenge <- AttChallenge::init(),
            peer_sess_id: 0,
            local_sess_id: 0,
            msg_ctr: msg_ctr & MATTER_MSG_CTR_RANGE,
            rx_ctr_state: RxCtrState::new(0),
            mode: SessionMode::PlainText,
            exchanges: crate::utils::storage::Vec::new(),
            last_use: epoch(),
            expired: false,
        })
    }

    /// Get the internal ID of the session
    /// This ID is guaranteed to be unique across all sessions
    pub const fn id(&self) -> u32 {
        self.id
    }

    pub fn get_local_sess_id(&self) -> u16 {
        self.local_sess_id
    }

    #[cfg(test)]
    pub fn set_local_sess_id(&mut self, sess_id: u16) {
        self.local_sess_id = sess_id;
    }

    pub fn get_peer_sess_id(&self) -> u16 {
        self.peer_sess_id
    }

    pub fn get_peer_addr(&self) -> Address {
        self.peer_addr
    }

    pub fn is_encrypted(&self) -> bool {
        match self.mode {
            SessionMode::Case { .. } | SessionMode::Pase { .. } | SessionMode::Group { .. } => true,
            SessionMode::PlainText => false,
        }
    }

    pub fn get_peer_node_id(&self) -> Option<u64> {
        self.peer_nodeid
    }

    pub fn get_local_fabric_idx(&self) -> u8 {
        self.mode.fab_idx()
    }

    pub fn get_session_mode(&self) -> &SessionMode {
        &self.mode
    }

    pub(crate) fn set_session_mode(&mut self, mode: SessionMode) {
        self.mode = mode;
    }

    fn get_msg_ctr(&mut self) -> u32 {
        let ctr = self.msg_ctr;
        self.msg_ctr += 1;
        ctr
    }

    pub fn get_dec_key(&self) -> Option<CanonAeadKeyRef<'_>> {
        match self.mode {
            SessionMode::Case { .. } | SessionMode::Pase { .. } | SessionMode::Group { .. } => {
                Some(self.dec_key.reference())
            }
            SessionMode::PlainText => None,
        }
    }

    pub fn get_enc_key(&self) -> Option<CanonAeadKeyRef<'_>> {
        match self.mode {
            SessionMode::Case { .. } | SessionMode::Pase { .. } | SessionMode::Group { .. } => {
                Some(self.enc_key.reference())
            }
            SessionMode::PlainText => None,
        }
    }

    pub fn get_att_challenge(&self) -> Option<AttChallengeRef<'_>> {
        match self.mode {
            SessionMode::Case { .. } | SessionMode::Pase { .. } => {
                Some(self.att_challenge.reference())
            }
            SessionMode::PlainText | SessionMode::Group { .. } => None,
        }
    }

    pub(crate) fn is_for_node(&self, fabric_idx: u8, peer_node_id: u64, secure: bool) -> bool {
        self.get_local_fabric_idx() == fabric_idx
            && self.peer_nodeid == Some(peer_node_id)
            && self.is_encrypted() == secure
            && !self.reserved
    }

    pub(crate) fn is_for_rx(&self, rx_peer: &Address, rx_plain: &PlainHdr) -> bool {
        let nodeid_matches = self.peer_nodeid.is_none()
            || rx_plain.get_src_nodeid().is_none()
            || self.peer_nodeid == rx_plain.get_src_nodeid();

        nodeid_matches
            && self.local_sess_id == rx_plain.sess_id
            && self.peer_addr == *rx_peer
            && self.is_encrypted() == rx_plain.is_encrypted()
            && !self.reserved
    }

    pub(crate) fn is_for_tx(&self, session_id: u32) -> bool {
        self.id == session_id
    }

    /// Return `true` if the session is expired.
    pub(crate) fn is_expired(&self) -> bool {
        self.expired
    }

    pub fn upgrade_fabric_idx(&mut self, fabric_idx: NonZeroU8) -> Result<(), Error> {
        if let SessionMode::Pase { fab_idx } = &mut self.mode {
            if *fab_idx == 0 {
                *fab_idx = fabric_idx.get();
            } else {
                // Upgrading a PASE session can happen only once
                Err(ErrorCode::Invalid)?;
            }
        } else {
            // CASE sessions are not upgradeable, as per spec
            // And for plain text sessions - we shoudn't even get here in the first place
            Err(ErrorCode::Invalid)?;
        }

        Ok(())
    }

    /// Update the session state with the data in the received packet headers.
    ///
    /// Return `true` if a new exchange was created, and `false` otherwise.
    pub(crate) fn post_recv(&mut self, rx_header: &PacketHdr, epoch: Epoch) -> Result<bool, Error> {
        if !self
            .rx_ctr_state
            .post_recv(rx_header.plain.ctr, self.is_encrypted())
        {
            Err(ErrorCode::Duplicate)?;
        }

        let exch_index = self.get_exch_for_rx(&rx_header.proto);
        if let Some(exch_index) = exch_index {
            let exch = unwrap!(self.exchanges[exch_index].as_mut());

            exch.post_recv(&rx_header.plain, &rx_header.proto, epoch)?;

            Ok(false)
        } else {
            if !rx_header.proto.is_initiator()
                || !MessageMeta::from(&rx_header.proto).is_new_exchange()
            {
                // Do not create a new exchange if the peer is not an initiator, or if
                // the packet is NOT a candidate for a new exchange
                // (i.e. it is a standalone ACK or a SC status response)
                Err(ErrorCode::NoExchange)?;
            }

            if let Some(exch_index) =
                self.add_exch(rx_header.proto.exch_id, Role::Responder(Default::default()))
            {
                // unwrap is safe as we just created the exchange
                let exch = unwrap!(self.exchanges[exch_index].as_mut());

                exch.post_recv(&rx_header.plain, &rx_header.proto, epoch)?;

                Ok(true)
            } else {
                Err(ErrorCode::NoSpaceExchanges)?
            }
        }
    }

    pub(crate) fn pre_send(
        &mut self,
        exch_index: Option<usize>,
        tx_header: &mut PacketHdr,
        session_active_interval_ms: Option<u16>,
        session_idle_interval_ms: Option<u16>,
    ) -> Result<(Address, bool), Error> {
        let ctr = if let Some(exchange_index) = exch_index {
            let exchange = unwrap!(self.exchanges[exchange_index].as_mut());
            exchange.mrp.retrans.as_ref().map(RetransEntry::get_msg_ctr)
        } else {
            None
        };

        let retransmission = ctr.is_some();

        tx_header.plain.sess_id = self.get_peer_sess_id();
        tx_header.plain.ctr = ctr.unwrap_or_else(|| self.get_msg_ctr());
        tx_header.plain.set_src_nodeid(None);
        tx_header.plain.set_dst_unicast_nodeid(
            (self.mode == SessionMode::PlainText)
                .then_some(self.peer_nodeid)
                .flatten(),
        );

        tx_header.proto.adjust_reliability(false, &self.peer_addr);

        if let Some(exchange_index) = exch_index {
            let exchange = unwrap!(self.exchanges[exchange_index].as_mut());

            exchange.pre_send(
                &tx_header.plain,
                &mut tx_header.proto,
                session_active_interval_ms,
                session_idle_interval_ms,
            )?;
        }

        Ok((self.peer_addr, retransmission))
    }

    /// Decode the remaining part of the packet after the plain header and then consume the `ParseBuf`
    /// instance as it no longer would be necessary.
    ///
    /// Returns the range of the decoded packet payload
    pub(crate) fn decode_remaining<C: Crypto>(
        &self,
        crypto: C,
        rx_header: &mut PacketHdr,
        mut pb: ParseBuf,
    ) -> Result<(usize, usize), Error> {
        rx_header.decode_remaining(
            crypto,
            self.get_dec_key(),
            self.peer_nodeid.unwrap_or_default(),
            &mut pb,
        )?;

        rx_header.proto.adjust_reliability(true, &self.peer_addr);

        Ok(pb.slice_range())
    }

    pub(crate) fn encode<C: Crypto>(
        &self,
        crypto: C,
        tx: &PacketHdr,
        wb: &mut WriteBuf,
    ) -> Result<(), Error> {
        tx.encode(crypto, self.get_enc_key(), self.local_nodeid, wb)
    }

    fn update_last_used(&mut self, epoch: Epoch) {
        self.last_use = epoch();
    }

    pub(crate) fn get_exch_for_rx(&self, rx_proto: &ProtoHdr) -> Option<usize> {
        self.exchanges
            .iter()
            .enumerate()
            .filter(|(_, exch)| {
                exch.as_ref()
                    .map(|exch| exch.is_for_rx(rx_proto))
                    .unwrap_or(false)
            })
            .map(|(index, _)| index)
            .next()
    }

    pub(crate) fn add_exch(&mut self, exch_id: u16, role: Role) -> Option<usize> {
        let exch_state = Some(ExchangeState {
            exch_id,
            role,
            mrp: ReliableMessage::new(),
        });

        let exch_index = if self.exchanges.len() < MAX_EXCHANGES {
            let _ = self.exchanges.push(exch_state);

            self.exchanges.len() - 1
        } else {
            let index = self.exchanges.iter().position(Option::is_none);

            if let Some(index) = index {
                self.exchanges[index] = exch_state;

                index
            } else {
                error!(
                    "Too many exchanges for session {} [SID:{:x},RSID:{:x}]; exchange creation failed",
                    self.id,
                    self.get_local_sess_id(),
                    self.get_peer_sess_id()
                );

                return None;
            }
        };

        let exch_id = ExchangeId::new(self.id, exch_index);

        debug!("New exchange: {} :: {:?}", exch_id.display(self), role);

        Some(exch_index)
    }

    pub(crate) fn remove_exch(&mut self, index: usize) -> bool {
        let exchange = unwrap!(self.exchanges[index].as_mut());
        let exchange_id = ExchangeId::new(self.id, index);

        if exchange.mrp.is_retrans_pending() {
            exchange.role.set_dropped_state();
            error!("Exchange {}: A packet is still (re)transmitted! Marking as dropped, but session will be closed", exchange_id.display(self));

            false
        } else if exchange.mrp.is_ack_pending() {
            exchange.role.set_dropped_state();
            warn!(
                "Exchange {}: Pending ACK. Marking as dropped",
                exchange_id.display(self)
            );

            false
        } else {
            trace!("Exchange {}: Dropped cleanly", exchange_id.display(self));
            self.exchanges[index] = None;

            true
        }
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "peer: {:?}, peer_nodeid: {:?}, local: {}, remote: {}, msg_ctr: {}, mode: {:?}, ts: {:?}, expired: {}",
            self.peer_addr,
            self.peer_nodeid,
            self.local_sess_id,
            self.peer_sess_id,
            self.msg_ctr,
            self.mode,
            self.last_use,
            self.expired,
        )
    }
}

pub struct ReservedSession<'a> {
    id: u32,
    session_mgr: &'a RefCell<SessionMgr>,
    complete: bool,
}

impl<'a> ReservedSession<'a> {
    pub fn reserve_now<C: Crypto>(matter: &'a Matter<'a>, crypto: C) -> Result<Self, Error> {
        let mut mgr = matter.transport_mgr.session_mgr.borrow_mut();

        let mut rand = crypto.weak_rand()?;

        let id = mgr.add(rand.next_u32(), true, Address::new(), None)?.id;

        Ok(Self {
            id,
            session_mgr: &matter.transport_mgr.session_mgr,
            complete: false,
        })
    }

    pub async fn reserve<C: Crypto>(
        matter: &'a Matter<'a>,
        crypto: C,
    ) -> Result<ReservedSession<'a>, Error> {
        let session = Self::reserve_now(matter, &crypto);

        if let Ok(session) = session {
            Ok(session)
        } else {
            matter.transport_mgr.evict_some_session(&crypto).await?;

            Self::reserve_now(matter, &crypto)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &mut self,
        local_nodeid: u64,
        peer_nodeid: u64,
        peer_sessid: u16,
        local_sessid: u16,
        peer_addr: Address,
        mode: SessionMode,
        dec_key: Option<CanonAeadKeyRef<'_>>,
        enc_key: Option<CanonAeadKeyRef<'_>>,
        att_challenge: Option<AttChallengeRef<'_>>,
    ) -> Result<(), Error> {
        let mut mgr = self.session_mgr.borrow_mut();
        let session = mgr.get(self.id).ok_or(ErrorCode::NoSession)?;

        session.local_nodeid = local_nodeid;
        session.peer_nodeid = Some(peer_nodeid);
        session.peer_sess_id = peer_sessid;
        session.local_sess_id = local_sessid;
        session.peer_addr = peer_addr;
        session.mode = mode;

        if let Some(dec_key) = dec_key {
            session.dec_key.load(dec_key);
        }

        if let Some(enc_key) = enc_key {
            session.enc_key.load(enc_key);
        }

        if let Some(att_challenge) = att_challenge {
            session.att_challenge.load(att_challenge);
        }

        Ok(())
    }

    pub fn complete(mut self) {
        self.complete = true;
    }
}

impl Drop for ReservedSession<'_> {
    fn drop(&mut self) {
        if self.complete {
            let mut session_mgr = self.session_mgr.borrow_mut();
            let session = unwrap!(session_mgr.get(self.id));
            session.reserved = false;
        } else {
            self.session_mgr.borrow_mut().remove(self.id);
        }
    }
}

cfg_if! {
    if #[cfg(feature = "max-sessions-64")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 64;
    } else if #[cfg(feature = "max-sessions-32")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 32;
    } else if #[cfg(feature = "max-sessions-16")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 16;
    } else if #[cfg(feature = "max-sessions-8")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 8;
    } else if #[cfg(feature = "max-sessions-7")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 7;
    } else if #[cfg(feature = "max-sessions-6")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 6;
    } else if #[cfg(feature = "max-sessions-5")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 5;
    } else if #[cfg(feature = "max-sessions-4")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 4;
    } else if #[cfg(feature = "max-sessions-3")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 3;
    } else {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 16;
    }
}

cfg_if! {
    if #[cfg(feature = "max-exchanges-per-session-16")] {
        /// Max number of supported exchanges per session
        pub const MAX_EXCHANGES: usize = 16;
    } else if #[cfg(feature = "max-exchanges-per-session-8")] {
        /// Max number of supported exchanges per session
        pub const MAX_EXCHANGES: usize = 8;
    } else if #[cfg(feature = "max-exchanges-per-session-7")] {
        /// Max number of supported exchanges per session
        pub const MAX_EXCHANGES: usize = 7;
    } else if #[cfg(feature = "max-exchanges-per-session-6")] {
        /// Max number of supported exchanges per session
        pub const MAX_EXCHANGES: usize = 6;
    } else if #[cfg(feature = "max-exchanges-per-session-5")] {
        /// Max number of supported exchanges per session
        pub const MAX_EXCHANGES: usize = 5;
    } else if #[cfg(feature = "max-exchanges-per-session-4")] {
        /// Max number of supported exchanges per session
        pub const MAX_EXCHANGES: usize = 4;
    } else if #[cfg(feature = "max-exchanges-per-session-3")] {
        /// Max number of supported exchanges per session
        pub const MAX_EXCHANGES: usize = 3;
    } else {
        /// Max number of supported exchanges per session
        pub const MAX_EXCHANGES: usize = 5;
    }
}

const MATTER_MSG_CTR_RANGE: u32 = 0x0fffffff;

pub struct SessionMgr {
    next_sess_unique_id: u32,
    next_sess_id: u16,
    next_exch_id: u16,
    sessions: crate::utils::storage::Vec<Session, MAX_SESSIONS>,
    group_op_keys: crate::utils::storage::Vec<GroupOpKeyEntry, MAX_GROUP_OP_KEYS>,
    group_ctr_store: GroupCtrStore,
    pub(crate) epoch: Epoch,
}

impl SessionMgr {
    /// Create a new session manager.
    #[inline(always)]
    pub const fn new(epoch: Epoch) -> Self {
        Self {
            sessions: crate::utils::storage::Vec::new(),
            group_op_keys: crate::utils::storage::Vec::new(),
            group_ctr_store: GroupCtrStore::new(),
            next_sess_unique_id: 0,
            next_sess_id: 1,
            next_exch_id: 1,
            epoch,
        }
    }

    /// Create an in-place initializer for a new session manager.
    pub fn init(epoch: Epoch) -> impl Init<Self> {
        init!(Self {
            sessions <- crate::utils::storage::Vec::init(),
            group_op_keys: crate::utils::storage::Vec::new(),
            group_ctr_store: GroupCtrStore::new(),
            next_sess_unique_id: 0,
            next_sess_id: 1,
            next_exch_id: 1,
            epoch,
        })
    }

    pub fn reset(&mut self) {
        self.sessions.clear();
        self.group_op_keys.clear();
        self.group_ctr_store = GroupCtrStore::new();
        self.next_sess_id = 1;
        self.next_exch_id = 1;
    }

    /// Rebuild the group operational key cache from the current fabric state.
    ///
    /// Pre-derives all group operational keys so that the transport layer
    /// can decrypt group messages without needing access to `FabricMgr`.
    pub fn rebuild_group_op_keys<C: Crypto>(&mut self, crypto: &C, fabric_mgr: &FabricMgr) {
        self.group_op_keys.clear();

        for fabric in fabric_mgr.iter() {
            let fab_idx = fabric.fab_idx();
            let compressed_fabric_id = fabric.compressed_fabric_id();

            // For each group key map entry, derive op keys from the referenced key set
            for map_entry in fabric.group_key_map_iter() {
                let Some(key_set_entry) = fabric.group_key_set_get(map_entry.group_key_set_id)
                else {
                    continue;
                };

                for epoch_key_entry in key_set_entry.epoch_keys.iter() {
                    let mut temp_key_set = KeySet::new();
                    if temp_key_set
                        .update(
                            crypto,
                            epoch_key_entry.epoch_key.reference(),
                            &compressed_fabric_id,
                        )
                        .is_err()
                    {
                        continue;
                    }

                    let op_key_ref = temp_key_set.op_key();
                    if let Ok(session_id) = derive_group_session_id(crypto, op_key_ref) {
                        let mut op_key = AEAD_KEY_ZEROED;
                        op_key.load(op_key_ref);
                        if let Err(_err) = self.group_op_keys.push(GroupOpKeyEntry {
                            fab_idx,
                            key_set_id: map_entry.group_key_set_id,
                            group_id: map_entry.group_id,
                            session_id,
                            op_key,
                        }) {
                            warn!("Failed to save the operational keys for fabric index: {} group: {}", fab_idx, map_entry.group_id);
                        };
                    }
                }
            }
        }

        debug!(
            "Group: Rebuilt op key cache with {} entries",
            self.group_op_keys.len()
        );
    }

    /// Attempt to decrypt and accept a group (multicast) message.
    ///
    /// Iterates over pre-cached group operational keys matching the packet's
    /// `(session_id, group_id)`, tries to decrypt with each, validates the
    /// group message counter, and creates an ephemeral group session on success.
    ///
    /// Returns the created session and payload range, mirroring how unicast
    /// uses `get_for_rx()` + `decode_remaining()`.
    pub(crate) fn get_or_create_for_group_rx<const N: usize, C: Crypto>(
        &mut self,
        crypto: &C,
        packet: &mut Packet<N>,
    ) -> Result<(&mut Session, (usize, usize)), Error> {
        let src_nodeid = packet
            .header
            .plain
            .get_src_nodeid()
            .ok_or(ErrorCode::InvalidData)?;
        let group_id = packet
            .header
            .plain
            .get_dst_groupcast_nodeid()
            .ok_or(ErrorCode::InvalidData)?;
        let expected_sess_id = packet.header.plain.sess_id;
        let msg_ctr = packet.header.plain.ctr;

        debug!(
            "Group: Attempting decrypt for PEER={:?} SID=0x{:04x}, GRP=0x{:04x}, SRC=0x{:016x}, CTR={}",
            packet.peer, expected_sess_id, group_id, src_nodeid, msg_ctr
        );

        // Parse the plain header to determine encrypted portion offset
        let mut pb = ParseBuf::new(&mut packet.buf[packet.payload_start..]);
        packet.header.plain.decode(&mut pb)?;

        // Save the current
        let encrypted_offset = pb.read_off();
        let encrypted_len = pb.as_slice().len();
        let mut saved_encrypted = [0u8; 1280];
        if encrypted_len > saved_encrypted.len() {
            return Err(ErrorCode::BufferTooSmall.into());
        }
        saved_encrypted[..encrypted_len].copy_from_slice(pb.as_slice());

        // Try cached keys matching session_id AND group_id
        let mut group_key_found: Option<(NonZeroU8, (usize, usize))> = None;

        for entry in &self.group_op_keys {
            if entry.session_id != expected_sess_id || entry.group_id != group_id {
                continue;
            }

            if let Some(payload_range) = Self::try_group_decrypt(
                crypto,
                packet,
                &saved_encrypted[..encrypted_len],
                encrypted_offset,
                entry.op_key.reference(),
                src_nodeid,
            ) {
                group_key_found = Some((entry.fab_idx, payload_range));
                break;
            }
        }

        if group_key_found.is_none() {
            debug!(
                "Group: No key could decrypt the message (SID=0x{:04x}, GRP=0x{:04x})",
                expected_sess_id, group_id
            );
        }

        let (fab_idx, payload_range) = group_key_found.ok_or(ErrorCode::NoSession)?;

        // Validate group message counter before creating the session
        if !self
            .group_ctr_store
            .post_recv(fab_idx.get(), src_nodeid, msg_ctr)
        {
            debug!(
                "Group: Duplicate message counter {} from node 0x{:016x} fab_idx={}",
                msg_ctr, src_nodeid, fab_idx
            );
            return Err(ErrorCode::Duplicate.into());
        }

        // Create ephemeral group session
        let epoch = self.epoch;
        let peer = packet.peer;
        let mut rand = crypto.weak_rand()?;
        let session = match self.add(rand.next_u32(), false, peer, Some(src_nodeid)) {
            Ok(session) => session,
            Err(_) => {
                // Session table is full; evict the least-recently-used session
                if let Some(lru_id) = self.get_session_for_eviction().map(|sess| sess.id) {
                    debug!("Group: Evicting session {} to make room", lru_id);
                    self.remove(lru_id);
                    self.add(rand.next_u32(), false, peer, Some(src_nodeid))?
                } else {
                    return Err(ErrorCode::NoSpaceSessions.into());
                }
            }
        };
        session.set_session_mode(SessionMode::Group { fab_idx, group_id });
        session.local_sess_id = expected_sess_id;

        debug!(
            "Group: Created group session for fab_idx={}, group_id=0x{:04x}, src_nodeid=0x{:016x}",
            fab_idx, group_id, src_nodeid
        );

        // Re-borrow the current created session for returning
        let session = unwrap!(self.sessions.last_mut());
        session.update_last_used(epoch);

        Ok((session, payload_range))
    }

    /// Try to decrypt a group message with a candidate key.
    /// Restores the ciphertext before attempting.
    /// On success, returns the payload range; the packet buffer contains decrypted data.
    fn try_group_decrypt<const N: usize, C: Crypto>(
        crypto: &C,
        packet: &mut Packet<N>,
        saved_encrypted: &[u8],
        encrypted_offset: usize,
        op_key: CanonAeadKeyRef<'_>,
        src_nodeid: u64,
    ) -> Option<(usize, usize)> {
        // Restore ciphertext
        let start = packet.payload_start + encrypted_offset;
        let encrypted_len = saved_encrypted.len();
        packet.buf[start..start + encrypted_len].copy_from_slice(saved_encrypted);

        // Re-create ParseBuf and re-parse plain header
        let mut pb = ParseBuf::new(&mut packet.buf[packet.payload_start..]);
        if packet.header.plain.decode(&mut pb).is_err() {
            error!("Plain header parse error");
            return None;
        }

        if packet
            .header
            .decode_remaining(crypto, Some(op_key), src_nodeid, &mut pb)
            .is_ok()
        {
            packet.header.proto.adjust_reliability(true, &packet.peer);
            Some(pb.slice_range())
        } else {
            None
        }
    }

    pub fn get_next_sess_id(&mut self) -> u16 {
        let mut next_sess_id: u16;
        loop {
            next_sess_id = self.next_sess_id;

            // Increment next sess id
            self.next_sess_id = self.next_sess_id.overflowing_add(1).0;
            if self.next_sess_id == 0 {
                self.next_sess_id = 1;
            }

            // Ensure the currently selected id doesn't match any existing session
            if self
                .sessions
                .iter()
                .all(|sess| sess.get_local_sess_id() != next_sess_id)
            {
                break;
            }
        }
        next_sess_id
    }

    pub fn get_next_exch_id(&mut self) -> u16 {
        let mut next_exch_id: u16;
        loop {
            next_exch_id = self.next_exch_id;

            // Increment next exch id
            self.next_exch_id = self.next_exch_id.overflowing_add(1).0;
            if self.next_exch_id == 0 {
                self.next_exch_id = 1;
            }

            // Ensure the currently selected id doesn't match any existing exchange
            if self
                .sessions
                .iter()
                .flat_map(|sess| sess.exchanges.iter())
                .filter_map(|exch| exch.as_ref())
                .all(|exch| {
                    !matches!(exch.role, Role::Responder(_)) || exch.exch_id != next_exch_id
                })
            {
                break;
            }
        }
        next_exch_id
    }

    pub fn get_session_for_eviction(&mut self) -> Option<&mut Session> {
        let mut lru_index = None;
        let mut lru_ts = (self.epoch)();
        for (i, s) in self.sessions.iter().enumerate() {
            if (s.expired || s.last_use < lru_ts)
                && !s.reserved
                && s.exchanges.iter().all(Option::is_none)
            {
                lru_ts = s.last_use;
                lru_index = Some(i);

                if s.expired {
                    // Expired sessons are the prime candidates for eviction,
                    // so we can break early
                    break;
                }
            }
        }

        lru_index.map(|index| &mut self.sessions[index])
    }

    pub fn add(
        &mut self,
        msg_ctr: u32,
        reserved: bool,
        peer_addr: Address,
        peer_nodeid: Option<u64>,
    ) -> Result<&mut Session, Error> {
        let session_id = self.next_sess_unique_id;

        self.next_sess_unique_id += 1;
        if self.next_sess_unique_id > 0x0fff_ffff {
            // Reserve the upper 4 bits for the exchange index
            self.next_sess_unique_id = 0;
        }

        let session = Session::init(
            session_id,
            msg_ctr,
            reserved,
            peer_addr,
            peer_nodeid,
            self.epoch,
        );

        self.sessions
            .push_init(session.into_fallible::<Error>(), || {
                ErrorCode::NoSpaceSessions.into()
            })?;

        Ok(unwrap!(self.sessions.last_mut()))
    }

    /// This assumes that the higher layer has taken care of doing anything required
    /// as per the spec before the session is removed
    pub fn remove(&mut self, id: u32) -> Option<Session> {
        if let Some(index) = self.sessions.iter().position(|sess| sess.id == id) {
            Some(self.sessions.swap_remove(index))
        } else {
            None
        }
    }

    /// This assumes that the higher layer has taken care of doing anything required
    /// as per the spec before the sessions are removed or expired
    pub fn remove_for_fabric(&mut self, fabric_idx: NonZeroU8, expire_sess_id: Option<u32>) {
        while let Some(index) = self.sessions.iter().position(|sess| {
            sess.get_local_fabric_idx() == fabric_idx.get() && Some(sess.id) != expire_sess_id
        }) {
            info!(
                "Dropping session with ID {} for fabric index {} immediately",
                self.sessions[index].id, fabric_idx
            );
            self.sessions.swap_remove(index);
        }

        if let Some(expire_sess_id) = expire_sess_id {
            let expire_sess = self
                .sessions
                .iter_mut()
                .find(|sess| sess.id == expire_sess_id);
            if let Some(expire_sess) = expire_sess {
                expire_sess.expired = true;
                info!(
                    "Marking session with ID {} as expired for fabric index {}",
                    expire_sess_id,
                    fabric_idx.get()
                );
            } else {
                warn!(
                    "No session with ID {} found for fabric index {} to mark as expired",
                    expire_sess_id,
                    fabric_idx.get()
                );
            }
        }
    }

    pub fn get(&mut self, id: u32) -> Option<&mut Session> {
        let mut session = self.sessions.iter_mut().find(|sess| sess.id == id);

        if let Some(session) = session.as_mut() {
            session.update_last_used(self.epoch);
        }

        session
    }

    pub(crate) fn get_for_node(
        &mut self,
        fabric_idx: u8,
        peer_node_id: u64,
        secure: bool,
    ) -> Option<&mut Session> {
        let mut session = self
            .sessions
            .iter_mut()
            // Expired sessions are not allowed to initiate new exchanges
            .find(|sess| !sess.expired && sess.is_for_node(fabric_idx, peer_node_id, secure));

        if let Some(session) = session.as_mut() {
            session.update_last_used(self.epoch);
        }

        session
    }

    pub(crate) fn get_for_rx(
        &mut self,
        rx_peer: &Address,
        rx_plain: &PlainHdr,
    ) -> Option<&mut Session> {
        let mut session = self
            .sessions
            .iter_mut()
            .find(|sess| sess.is_for_rx(rx_peer, rx_plain));

        if let Some(session) = session.as_mut() {
            session.update_last_used(self.epoch);
        }

        session
    }

    pub(crate) fn get_for_tx(&mut self, session_id: u32) -> Option<&mut Session> {
        let mut session = self
            .sessions
            .iter_mut()
            .find(|sess| sess.is_for_tx(session_id));

        if let Some(session) = session.as_mut() {
            session.update_last_used(self.epoch);
        }

        session
    }

    pub(crate) fn get_exch<F>(&mut self, f: F) -> Option<(&mut Session, usize)>
    where
        F: Fn(&Session, &ExchangeState) -> bool,
    {
        let exch = self
            .sessions
            .iter()
            .flat_map(|sess| {
                sess.exchanges
                    .iter()
                    .enumerate()
                    .filter_map(move |(exch_index, exch)| {
                        exch.as_ref().map(|exch| (sess, exch, exch_index))
                    })
            })
            .filter(|(sess, exch, _)| f(sess, exch))
            .map(|(sess, _, exch_index)| (sess.id, exch_index))
            .next();

        if let Some((id, exch_index)) = exch {
            let epoch = self.epoch;
            let session = unwrap!(self.get(id));
            session.update_last_used(epoch);

            Some((session, exch_index))
        } else {
            None
        }
    }

    /// Iterate over the sessions
    pub fn iter(&self) -> impl Iterator<Item = &Session> {
        self.sessions.iter()
    }
}

impl fmt::Display for SessionMgr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{{[")?;
        for s in &self.sessions {
            writeln!(f, "{{ {}, }},", s)?;
        }
        write!(f, "], next_sess_id: {}", self.next_sess_id)?;
        write!(f, "}}")
    }
}

/// Derive the Group Session ID from an operational group key.
///
/// Per Matter Spec Section 4.17.3.6:
/// ```text
/// GroupKeyHash = Crypto_KDF(
///     InputKey = OperationalGroupKey,
///     Salt     = [],
///     Info     = "GroupKeyHash",
///     Length   = 16 bits
/// )
/// GroupSessionId = (GroupKeyHash[0] << 8) | GroupKeyHash[1]
/// ```
pub fn derive_group_session_id<C: Crypto>(
    crypto: C,
    op_key: CanonAeadKeyRef<'_>,
) -> Result<u16, Error> {
    const GRP_KEY_HASH_INFO: &[u8] = b"GroupKeyHash";

    let mut hash = CryptoSensitive::<2>::new();

    crypto
        .kdf()?
        .expand(&[], op_key, GRP_KEY_HASH_INFO, &mut hash)
        .map_err(|_| ErrorCode::InvalidData)?;

    let bytes = hash.access();
    Ok(((bytes[0] as u16) << 8) | (bytes[1] as u16))
}

#[cfg(test)]
mod tests {
    use crate::crypto::test_only_crypto;
    use crate::transport::network::Address;
    use crate::utils::epoch::dummy_epoch;

    use super::*;

    #[test]
    fn test_next_sess_id_doesnt_reuse() {
        let mut sm = SessionMgr::new(dummy_epoch);
        let sess = unwrap!(sm.add(0, false, Address::default(), None));
        sess.set_local_sess_id(1);
        assert_eq!(sm.get_next_sess_id(), 2);
        assert_eq!(sm.get_next_sess_id(), 3);
        let sess = unwrap!(sm.add(0, false, Address::default(), None));
        sess.set_local_sess_id(4);
        assert_eq!(sm.get_next_sess_id(), 5);
    }

    #[test]
    fn test_next_sess_id_overflows() {
        let mut sm = SessionMgr::new(dummy_epoch);
        let sess = unwrap!(sm.add(0, false, Address::default(), None));
        sess.set_local_sess_id(1);
        assert_eq!(sm.get_next_sess_id(), 2);
        sm.next_sess_id = 65534;
        assert_eq!(sm.get_next_sess_id(), 65534);
        assert_eq!(sm.get_next_sess_id(), 65535);
        assert_eq!(sm.get_next_sess_id(), 2);
    }

    #[test]
    fn test_derive_group_session_id() {
        // Spec test vector:
        // Operational Group Key: a6:f5:30:6b:af:6d:05:0a:f2:3b:a4:bd:6b:9d:d9:60
        // Expected GroupSessionId: 0xB9F7 (47607)
        let op_key_bytes: [u8; 16] = [
            0xa6, 0xf5, 0x30, 0x6b, 0xaf, 0x6d, 0x05, 0x0a, 0xf2, 0x3b, 0xa4, 0xbd, 0x6b, 0x9d,
            0xd9, 0x60,
        ];

        let mut op_key = AEAD_KEY_ZEROED;
        op_key.try_load_from_slice(&op_key_bytes).unwrap();

        let crypto = test_only_crypto();
        let session_id = derive_group_session_id(&crypto, op_key.reference()).unwrap();

        assert_eq!(
            session_id, 0xB9F7,
            "Group Session ID mismatch: got 0x{:04X}, expected 0xB9F7",
            session_id
        );
    }
}
