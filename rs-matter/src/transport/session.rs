/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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
use embassy_time::Instant;

use cfg_if::cfg_if;

use rand_core::RngCore;

use crate::crypto::{
    canon, CanonAeadKey, CanonAeadKeyRef, CanonPkcSharedSecret, CanonPkcSharedSecretRef, Crypto,
    CryptoSensitive, Kdf,
};
use crate::dm::clusters::basic_info::BasicInfoConfig;
use crate::error::{Error, ErrorCode};
#[cfg(feature = "groups")]
use crate::fabric::Fabrics;
#[cfg(feature = "groups")]
use crate::group_keys::KeySet;
#[cfg(feature = "groups")]
use crate::persist::{KvBlobStore, GROUP_DATA_COUNTER_KEY};
use crate::sc::SessionParameters;
use crate::transport::exchange::ExchangeId;
use crate::transport::mrp::{self, ReliableMessage};
use crate::transport::TransportRunner;
use crate::utils::init::{init, Init, IntoFallibleInit};
use crate::utils::storage::{ParseBuf, Vec, WriteBuf};
use crate::{Matter, MatterState};

#[cfg(feature = "groups")]
use super::dedup::GroupCtrStore;
use super::dedup::RxCtrState;
use super::exchange::{ExchangeState, MessageMeta, Role};
use super::mrp::{mrp_log, RetransEntry};
use super::network::Address;
use super::packet::PacketHdr;
use super::plain_hdr::PlainHdr;
use super::proto_hdr::ProtoHdr;
#[cfg(feature = "groups")]
use super::Packet;

/// Receive timeout for a TCP-backed session.
///
/// TCP handles its own retransmission, so there is no MRP ladder to derive from;
/// this is a flat upper bound on how long the peer may take to answer. The CHIP
/// SDK uses the same 30 seconds for `GetAckTimeout` / `GetMessageReceiptTimeout`
/// on TCP sessions.
const TCP_RX_TIMEOUT_MS: u64 = 30_000;

/// Receive timeout for a BTP (BLE) session.
///
/// BTP runs its own acknowledgement scheme underneath, so the MRP ladder does not
/// describe it; this matches the BTP layer's own ack timeout.
const BTP_RX_TIMEOUT_MS: u64 = 5_000;

pub const MAX_CAT_IDS_PER_NOC: usize = 3;
pub type NocCatIds = [u32; MAX_CAT_IDS_PER_NOC];

pub const ATT_CHALLENGE_LEN: usize = 16;

canon!(
    ATT_CHALLENGE_LEN,
    ATT_CHALLENGE_ZEROED,
    AttChallenge,
    AttChallengeRef
);

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
    /// The ECDH shared secret computed during the original full CASE
    /// handshake, retained on the session for the sole purpose of
    /// populating [`crate::sc::case::ResumableSession`] records for
    /// the resumption cache. Zeroed for non-CASE sessions.
    ///
    /// Kept as a field unconditionally so the `new`/`init` constructors
    /// need no `case-resumption`-specific variant; it is simply written
    /// but never read when resumption is off.
    #[cfg_attr(not(feature = "case-resumption"), allow(dead_code))]
    shared_secret: CanonPkcSharedSecret,
    att_challenge: AttChallenge,
    local_sess_id: u16,
    peer_sess_id: u16,
    msg_ctr: u32,
    rx_ctr_state: RxCtrState,
    mode: SessionMode,
    pub(crate) exchanges: Vec<Option<ExchangeState>, MAX_EXCHANGES>,
    last_use: Instant,
    /// Peer's effective `MRP_SESSION_ACTIVE_INTERVAL` (ms) — drives our
    /// MRP retransmission base interval when transmitting to this peer.
    peer_active_interval_ms: u32,
    /// Peer's effective `MRP_SESSION_IDLE_INTERVAL` (ms) — see
    /// `peer_active_interval_ms`. Currently informational on the responder
    /// side until idle-vs-active classification lands in the MRP code.
    peer_idle_interval_ms: u32,
    /// Peer's effective `MRP_SESSION_ACTIVE_THRESHOLD` (ms).
    peer_active_threshold_ms: u16,
    /// If `true` then the session is considered "expired". Session expiration happens
    /// for the session on behalf of which a fabric is removed, and for a CASE session
    /// whose peer stopped acknowledging (see [`Session::pre_send`]).
    ///
    /// Expired sessions can still process their ongoing exchanges, but do not accept any new ones.
    /// Furthermore, expired sessions are the prime candidates for eviction.
    expired: bool,
    reserved: bool,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u32,
        msg_ctr: u32,
        reserved: bool,
        peer_addr: Address,
        peer_nodeid: Option<u64>,
        peer_active_interval_ms: u32,
        peer_idle_interval_ms: u32,
        peer_active_threshold_ms: u16,
    ) -> Self {
        Self {
            id,
            reserved,
            peer_addr,
            local_nodeid: 0,
            peer_nodeid,
            dec_key: CanonAeadKey::new(),
            enc_key: CanonAeadKey::new(),
            shared_secret: CanonPkcSharedSecret::new(),
            att_challenge: AttChallenge::new(),
            peer_sess_id: 0,
            local_sess_id: 0,
            msg_ctr: msg_ctr & MATTER_MSG_CTR_RANGE,
            rx_ctr_state: RxCtrState::new(0),
            mode: SessionMode::PlainText,
            exchanges: Vec::new(),
            last_use: Instant::now(),
            peer_active_interval_ms,
            peer_idle_interval_ms,
            peer_active_threshold_ms,
            expired: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn init(
        id: u32,
        msg_ctr: u32,
        reserved: bool,
        peer_addr: Address,
        peer_nodeid: Option<u64>,
        peer_active_interval_ms: u32,
        peer_idle_interval_ms: u32,
        peer_active_threshold_ms: u16,
    ) -> impl Init<Self> {
        init!(Self {
            id,
            reserved,
            peer_addr,
            local_nodeid: 0,
            peer_nodeid,
            dec_key <- CanonAeadKey::init(),
            enc_key <- CanonAeadKey::init(),
            shared_secret <- CanonPkcSharedSecret::init(),
            att_challenge <- AttChallenge::init(),
            peer_sess_id: 0,
            local_sess_id: 0,
            msg_ctr: msg_ctr & MATTER_MSG_CTR_RANGE,
            rx_ctr_state: RxCtrState::new(0),
            mode: SessionMode::PlainText,
            exchanges <- Vec::init(),
            last_use: Instant::now(),
            peer_active_interval_ms,
            peer_idle_interval_ms,
            peer_active_threshold_ms,
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

    pub(crate) fn set_local_nodeid(&mut self, nodeid: u64) {
        self.local_nodeid = nodeid;
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

    #[cfg(feature = "groups")]
    pub(crate) fn set_session_mode(&mut self, mode: SessionMode) {
        self.mode = mode;
    }

    pub fn get_peer_active_interval_ms(&self) -> u32 {
        self.peer_active_interval_ms
    }

    pub fn get_peer_idle_interval_ms(&self) -> u32 {
        self.peer_idle_interval_ms
    }

    pub fn get_peer_active_threshold_ms(&self) -> u16 {
        self.peer_active_threshold_ms
    }

    /// Record the peer's `session_parameters` (any combination of `sai` /
    /// `sii` / `sat`) for use by MRP retransmission timing on later sends
    /// to this peer. Only the fields the peer actually advertised get
    /// overwritten; absent fields leave the seeded default in place so
    /// repeated handshakes don't clobber a stronger earlier hint with a
    /// later-but-emptier one.
    ///
    /// `Some(0)` is dropped (with a warning) — this method runs on
    /// Sigma1 / PBKDFParamRequest TLV from an unauthenticated peer, and
    /// an "interval" of zero would either collapse the MRP backoff to
    /// a tight retransmit loop or, in the SAT case, mark the session
    /// active for zero milliseconds. Neither is a legitimate value, so
    /// rejecting them protects against a trivial pre-auth DoS.
    pub(crate) fn set_peer_session_params(&mut self, params: &SessionParameters) {
        if let Some(sai) = params.sai {
            if sai > 0 {
                self.peer_active_interval_ms = sai;
            } else {
                warn!("Peer advertised session_parameters.sai=0; ignoring");
            }
        }

        if let Some(sii) = params.sii {
            if sii > 0 {
                self.peer_idle_interval_ms = sii;
            } else {
                warn!("Peer advertised session_parameters.sii=0; ignoring");
            }
        }

        if let Some(sat) = params.sat {
            if sat > 0 {
                self.peer_active_threshold_ms = sat;
            } else {
                warn!("Peer advertised session_parameters.sat=0; ignoring");
            }
        }
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

    /// The ECDH shared secret from the original full CASE handshake,
    /// or `None` for non-CASE sessions. Consumed by the background
    /// snapshot task to build [`crate::sc::case::ResumableSession`]
    /// records — the "SharedSecret" that the Matter spec lists as
    /// part of the Session Resumption State.
    #[cfg(feature = "case-resumption")]
    #[allow(dead_code)]
    pub fn get_shared_secret(&self) -> Option<CanonPkcSharedSecretRef<'_>> {
        match self.mode {
            SessionMode::Case { .. } => Some(self.shared_secret.reference()),
            SessionMode::Pase { .. } | SessionMode::Group { .. } | SessionMode::PlainText => None,
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

    /// Whether this is a CASE session to the given peer node ID and fabric index.
    pub(crate) fn is_for_node(&self, fabric_idx: NonZeroU8, peer_node_id: u64) -> bool {
        self.get_local_fabric_idx() == fabric_idx.get()
            && self.peer_nodeid == Some(peer_node_id)
            && self.is_encrypted()
            && !self.reserved
    }

    /// Whether this is a PASE session to the given peer address.
    ///
    /// PASE sessions are all keyed at fabric 0 / node 0 (no operational
    /// identity yet), so the peer *address* is what distinguishes one PASE
    /// session from another - which matters on a commissioner that may have
    /// several PASE sessions (to different devices) in flight at once.
    pub(crate) fn is_pase_for_addr(&self, peer_addr: &Address) -> bool {
        matches!(self.mode, SessionMode::Pase { .. })
            && self.peer_addr.canonical() == peer_addr.canonical()
            && !self.reserved
    }

    pub(crate) fn is_for_rx(&self, rx_peer: &Address, rx_plain: &PlainHdr) -> bool {
        let nodeid_matches = self.peer_nodeid.is_none()
            || rx_plain.get_src_nodeid().is_none()
            || self.peer_nodeid == rx_plain.get_src_nodeid();

        // For unsecured sessions, also match by destination node ID (the echoed
        // ephemeral initiator node ID) to disambiguate multiple unsecured sessions
        // for the same peer (spec).
        let dest_nodeid_matches = self.is_encrypted()
            || self.local_nodeid == 0
            || rx_plain.get_dst_unicast_nodeid().is_none()
            || rx_plain.get_dst_unicast_nodeid() == Some(self.local_nodeid);

        nodeid_matches
            && dest_nodeid_matches
            && self.local_sess_id == rx_plain.sess_id
            // Compare canonically: a dual-stack socket may report a peer as
            // `::ffff:a.b.c.d` on receive while the session stored the plain
            // `V4` address it was created with (or vice versa). Canonicalizing
            // only the *comparison* (not the stored address) lets the two match
            // without disturbing the address used for reply routing. See
            // `Address::canonical`.
            && self.peer_addr.canonical() == rx_peer.canonical()
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

    /// How long to wait for the peer's answer on this session before giving up
    /// with [`ErrorCode::RxTimeout`].
    ///
    /// Mirrors the CHIP SDK's `Session::ComputeRoundTripTimeout`, which is a sum
    /// of three terms rather than a single scaled backoff step:
    ///
    /// - the time our message may spend being retransmitted before it reaches the
    ///   peer, paced by the **peer's** advertised retry interval,
    /// - an allowance for the peer's upper layer to process the request,
    /// - the time the peer's answer may spend being retransmitted before it
    ///   reaches us, paced by **our own** retry interval.
    ///
    /// The two halves deliberately use different inputs: each direction is paced
    /// by the retry configuration of whichever side is doing the sending.
    ///
    /// The outbound half uses the peer's *idle* interval, because we cannot know
    /// whether the peer is awake when we first speak to it, while the inbound half
    /// uses the *active* interval, since the peer is by then answering a message
    /// it has just received. That is the same asymmetry CHIP encodes through its
    /// `isFirstMessageOnExchange` flag.
    ///
    /// Non-UDP transports derive nothing: TCP is a reliable stream with no MRP
    /// ladder to account for, and BTP carries its own acknowledgement timeout.
    pub(crate) fn rx_timeout_ms(&self, local_active_interval_ms: u32) -> u64 {
        match self.peer_addr {
            Address::Tcp(_) => TCP_RX_TIMEOUT_MS,
            Address::Btp(_) => BTP_RX_TIMEOUT_MS,
            Address::Udp(_) => {
                // Outbound: our message reaching the peer, paced by the peer's own
                // retry configuration, and allowed to fall back to its idle
                // interval since we cannot know whether it is awake.
                let outbound = mrp::RetransEntry::retransmission_timeout_ms(
                    self.peer_active_interval_ms,
                    self.peer_idle_interval_ms,
                    self.peer_active_threshold_ms,
                    false,
                );

                // Inbound: the peer's answer reaching us, paced by our own retry
                // configuration. Always active - the peer is answering a message
                // it just received, so it is demonstrably awake.
                let inbound = mrp::RetransEntry::retransmission_timeout_ms(
                    local_active_interval_ms,
                    local_active_interval_ms,
                    0,
                    true,
                );

                outbound + mrp::MRP_EXPECTED_PROCESSING_MS + inbound
            }
        }
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
    pub(crate) fn post_recv(&mut self, rx_header: &PacketHdr) -> Result<bool, Error> {
        if !self
            .rx_ctr_state
            .post_recv(rx_header.plain.ctr, self.is_encrypted(), false)
        {
            Err(ErrorCode::Duplicate)?;
        }

        let exch_index = self.get_exch_for_rx(&rx_header.proto);
        if let Some(exch_index) = exch_index {
            let exch = unwrap!(self.exchanges[exch_index].as_mut());

            exch.post_recv(&rx_header.plain, &rx_header.proto)?;

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

            if self.expired {
                // Per Matter Core spec, an expired session must not
                // accept new inbound messages. Skipping expired sessions here lets the
                // caller surface a `SessionNotFound` to the peer rather than running
                // the request through ACL checks against a removed fabric.
                Err(ErrorCode::NoSession)?;
            }

            if let Some(exch_index) =
                self.add_exch(rx_header.proto.exch_id, Role::Responder(Default::default()))
            {
                // unwrap is safe as we just created the exchange
                let exch = unwrap!(self.exchanges[exch_index].as_mut());

                exch.post_recv(&rx_header.plain, &rx_header.proto)?;

                Ok(true)
            } else {
                Err(ErrorCode::NoSpaceExchanges)?
            }
        }
    }

    /// Whether the session's peer address is a multicast address — true only
    /// for TX group sessions (see [`Sessions::get_or_create_for_group_tx`]).
    pub(crate) fn is_peer_multicast(&self) -> bool {
        match &self.peer_addr {
            Address::Udp(crate::transport::network::SocketAddr::V6(addr)) => {
                addr.ip().is_multicast()
            }
            Address::Udp(crate::transport::network::SocketAddr::V4(addr)) => {
                addr.ip().is_multicast()
            }
            _ => false,
        }
    }

    pub(crate) fn pre_send(
        &mut self,
        exch_index: Option<usize>,
        tx_header: &mut PacketHdr,
        session_active_interval_ms: Option<u32>,
        session_idle_interval_ms: Option<u32>,
    ) -> Result<(Address, bool), Error> {
        let ctr = if let Some(exchange_index) = exch_index {
            let exchange = unwrap!(self.exchanges[exchange_index].as_mut());
            exchange.mrp.retrans.as_ref().map(RetransEntry::get_msg_ctr)
        } else {
            None
        };

        // The group data message counter value reserved (and made durable)
        // for this exchange by `Exchange::initiate_group`.
        #[cfg(feature = "groups")]
        let group_data_ctr = exch_index.and_then(|exchange_index| {
            unwrap!(self.exchanges[exchange_index].as_mut())
                .group_data_ctr
                .take()
        });

        let retransmission = ctr.is_some();

        let is_group = matches!(self.mode, SessionMode::Group { .. });

        // Whether this outbound message is a control-plane message
        // (only MCSP opcodes today). Used to set the `C` bit, to pick
        // DSIZ = 1 vs. the groupcast destination, and to pick the
        // per-session vs. the global group data message counter.
        let is_control = is_group && MessageMeta::from(&tx_header.proto).is_control_msg();

        // For a group session, `local_sess_id == peer_sess_id` — both
        // hold the same Group Session Id derived from the operational
        // group key (see `get_or_create_for_group_rx`) — so this line
        // works uniformly for unicast replies and group control messages.
        tx_header.plain.sess_id = self.get_peer_sess_id();
        tx_header.plain.ctr = if let Some(ctr) = ctr {
            ctr
        } else if is_group && !is_control {
            // Group data messages carry the Global Group Encrypted Data
            // Message Counter — one counter across all groups, so the
            // per-source counter tracking on the receiving side stays
            // monotonic. The value was reserved by
            // `Exchange::initiate_group`, which also made the boundary
            // covering it durable before this send could happen.
            #[cfg(feature = "groups")]
            {
                group_data_ctr.ok_or(ErrorCode::InvalidState)?
            }
            // Group sessions are never created without the `groups` feature.
            #[cfg(not(feature = "groups"))]
            {
                Err(ErrorCode::InvalidState)?
            }
        } else {
            self.get_msg_ctr()
        };

        // Include the Source Node ID for:
        // - Unsecured initiator sessions (spec).
        // - Every outbound message on a group session, so receivers can
        //   look up the sender's Group Peer State.
        // CASE/PASE responder-side messages omit it.
        tx_header.plain.set_src_nodeid(
            ((!self.is_encrypted() || is_group) && self.local_nodeid != 0)
                .then_some(self.local_nodeid),
        );

        // Destination Node ID (DSIZ):
        // - Plaintext: echo `peer_nodeid` back to the initiator.
        // - Group control (MCSP reply): DSIZ = 1, destination =
        //   originator's Node ID.
        // - Group data: DSIZ = 2, destination = the target Group ID
        //   (carried by the session mode, see `get_or_create_for_group_tx`).
        // - CASE/PASE: no DSIZ; clear.
        #[allow(irrefutable_let_patterns)]
        if self.mode == SessionMode::PlainText || is_control {
            tx_header.plain.set_dst_unicast_nodeid(self.peer_nodeid);
        } else if let SessionMode::Group { group_id, .. } = self.mode {
            tx_header.plain.set_dst_groupcast_nodeid(Some(group_id));
        } else {
            tx_header.plain.set_dst_unicast_nodeid(None);
        }

        if is_group {
            use super::plain_hdr::SecFlags;
            tx_header.plain.sec_flags |= SecFlags::GROUP_SESSION;
            tx_header.plain.set_control_msg(is_control);
        }

        tx_header.proto.adjust_reliability(false, &self.peer_addr);

        if is_group && !is_control {
            // Group DATA messages never use MRP: they are multicast
            // fire-and-forget, so there is nobody to acknowledge them.
            // Group CONTROL messages (MCSP) are unicast-addressed and stay
            // reliable - which is also what keeps their (ephemeral) session
            // alive until the reply has been encoded.
            tx_header.proto.unset_reliable();
            tx_header.proto.set_ack(None);
        }

        if let Some(exchange_index) = exch_index {
            let exchange = unwrap!(self.exchanges[exchange_index].as_mut());

            let result = exchange.pre_send(
                &tx_header.plain,
                &mut tx_header.proto,
                session_active_interval_ms,
                session_idle_interval_ms,
            );

            if matches!(
                result.as_ref().map_err(Error::code),
                Err(ErrorCode::TxTimeout)
            ) && matches!(self.mode, SessionMode::Case { .. })
                && !self.expired
            {
                // The peer never acknowledged, which is the strongest evidence we
                // get that its recorded address no longer reaches it - it may have
                // renumbered, moved subnet, or the address picked out of the
                // resolve was never reachable in the first place.
                //
                // Expiring keeps the session usable for the exchanges already on
                // it (they fail on their own) while making `Transport::initiate`
                // skip it, so the next attempt re-resolves the peer and builds a
                // fresh session against the current candidate list.
                //
                // Only CASE sessions: PASE and plaintext are short-lived and
                // pinned to an address the caller supplied itself, so there is
                // nothing to re-resolve.
                warn!(
                    "Session {}: Peer did not acknowledge; marking the session as expired",
                    self.id
                );

                self.expired = true;
            }

            result?;
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

    fn update_last_used(&mut self) {
        self.last_use = Instant::now();
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
            #[cfg(feature = "groups")]
            group_data_ctr: None,
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
            mrp_log!(
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

/// A helper struct for reserving a session slot in the session table when we don't have all the necessary information to create a full session yet.
///
/// Public for testing purposes, but should not be used outside of the transport module.
pub struct ReservedSession<'a> {
    id: u32,
    matter: &'a Matter<'a>,
    complete: bool,
}

impl<'a> ReservedSession<'a> {
    pub fn reserve_now<C: Crypto>(matter: &'a Matter<'a>, crypto: C) -> Result<Self, Error> {
        let dev_det = matter.dev_det();
        matter.with_state(|state| {
            let mut rand = crypto.weak_rand()?;

            let id = state
                .sessions
                .add(rand.next_u32(), true, Address::new(), None, dev_det)?
                .id;

            Ok(Self {
                id,
                matter,
                complete: false,
            })
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
            TransportRunner::new(matter, &crypto)
                .evict_some_session()
                .await?;

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
        shared_secret: Option<CanonPkcSharedSecretRef<'_>>,
    ) -> Result<(), Error> {
        self.matter.with_state(|state| {
            self.update_with_state(
                state,
                local_nodeid,
                peer_nodeid,
                peer_sessid,
                local_sessid,
                peer_addr,
                mode,
                dec_key,
                enc_key,
                att_challenge,
                shared_secret,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_with_state(
        &mut self,
        state: &mut MatterState,
        local_nodeid: u64,
        peer_nodeid: u64,
        peer_sessid: u16,
        local_sessid: u16,
        peer_addr: Address,
        mode: SessionMode,
        dec_key: Option<CanonAeadKeyRef<'_>>,
        enc_key: Option<CanonAeadKeyRef<'_>>,
        att_challenge: Option<AttChallengeRef<'_>>,
        shared_secret: Option<CanonPkcSharedSecretRef<'_>>,
    ) -> Result<(), Error> {
        let session = state.sessions.get(self.id).ok_or(ErrorCode::NoSession)?;

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

        if let Some(shared_secret) = shared_secret {
            session.shared_secret.load(shared_secret);
        }

        Ok(())
    }

    /// Record the peer's MRP `session_parameters` (Sigma1 / Sigma2 /
    /// PBKDFParamRequest / PBKDFParamResponse) on the reserved session so
    /// they are in place by the time it transitions to a full Session.
    /// Per Matter Core spec, MRP retransmission backoff to this
    /// peer should derive from the peer-advertised `sai` (and idle
    /// detection later from `sii`/`sat`).
    pub(crate) fn set_peer_session_params(
        &mut self,
        params: &SessionParameters,
    ) -> Result<(), Error> {
        self.matter.with_state(|state| {
            let session = state.sessions.get(self.id).ok_or(ErrorCode::NoSession)?;
            session.set_peer_session_params(params);
            Ok(())
        })
    }

    pub fn complete(&mut self) {
        self.complete = true;
    }
}

impl Drop for ReservedSession<'_> {
    fn drop(&mut self) {
        self.matter.with_state(|state| {
            if self.complete {
                let session = unwrap!(state.sessions.get(self.id));
                session.reserved = false;
            } else {
                state.sessions.remove(self.id);
            }
        })
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

/// All sessions
pub struct Sessions {
    next_sess_unique_id: u32,
    next_sess_id: u16,
    next_exch_id: u16,
    sessions: Vec<Session, MAX_SESSIONS>,
    #[cfg(feature = "groups")]
    group_ctr_store: GroupCtrStore,
    /// The current Global Group Encrypted Data Message Counter reported
    /// to peers as the "Synchronized Counter" in `MsgCounterSyncRsp` and
    /// (once group-data sending is implemented) used to encode outgoing
    /// group data messages.
    ///
    /// `0` means "not yet initialized"; use
    /// [`Sessions::get_or_init_global_group_data_ctr`] to obtain a valid
    /// non-zero value.
    ///
    /// Persisted with an epoch/stride scheme (see
    /// [`Sessions::group_data_ctr_boundary`]) so it never goes backwards
    /// across reboots: a receiver tracking our source in its group counter
    /// store would otherwise reject our post-restart group data messages as
    /// replays until the fresh value exceeded the old one.
    #[cfg(feature = "groups")]
    global_group_data_ctr: u32,
    /// The boundary held in durable storage: it covers exactly the values in
    /// `[global_group_data_ctr, group_data_ctr_boundary)`, since a restart
    /// resumes *at* the stored boundary and is therefore past all of them.
    ///
    /// Equal to [`Sessions::global_group_data_ctr`] when nothing is covered -
    /// the state right after a resume or a first-use seed - which is what
    /// makes [`Sessions::reserve_global_group_data_ctr`] extend the boundary
    /// and demand a write before handing out a value.
    ///
    /// `0` when the counter is not yet initialized.
    #[cfg(feature = "groups")]
    group_data_ctr_boundary: u32,
}

/// How far ahead of the live Global Group Encrypted Data Message Counter the
/// persisted boundary is kept.
///
/// Every crossing costs one KV write, and every restart burns up to this many
/// counter values - so it trades flash wear against counter-space consumption.
/// At 1000, a device sending a group message every second writes once every
/// ~17 minutes.
#[cfg(feature = "groups")]
pub const GROUP_DATA_CTR_EPOCH: u32 = 1000;

impl Sessions {
    /// Create a new Sessions instance.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            sessions: Vec::new(),
            #[cfg(feature = "groups")]
            group_ctr_store: GroupCtrStore::new(),
            next_sess_unique_id: 0,
            next_sess_id: 1,
            next_exch_id: 0,
            #[cfg(feature = "groups")]
            global_group_data_ctr: 0,
            #[cfg(feature = "groups")]
            group_data_ctr_boundary: 0,
        }
    }

    /// Create an in-place initializer for a new Sessions instance.
    pub fn init() -> impl Init<Self> {
        // The `init!` macro does not accept `#[cfg]` on fields, so the two
        // group-only fields force two variants that differ only by them.
        #[cfg(feature = "groups")]
        let r = init!(Self {
            sessions <- Vec::init(),
            group_ctr_store: GroupCtrStore::new(),
            next_sess_unique_id: 0,
            next_sess_id: 1,
            next_exch_id: 0,
            global_group_data_ctr: 0,
            group_data_ctr_boundary: 0,
        });
        #[cfg(not(feature = "groups"))]
        let r = init!(Self {
            sessions <- Vec::init(),
            next_sess_unique_id: 0,
            next_sess_id: 1,
            next_exch_id: 0,
        });
        r
    }

    pub fn reset(&mut self) {
        self.sessions.clear();
        #[cfg(feature = "groups")]
        {
            self.group_ctr_store = GroupCtrStore::new();
        }
        self.next_sess_id = 1;
        self.next_exch_id = 0;
        // Deliberately keep `global_group_data_ctr`: a `reset` isn't a
        // factory reset, and rolling it back would break peers that
        // just learned it via MCSP.
    }
}

/// Group (multicast) session handling: on-the-fly key derivation for received
/// group-encrypted messages, and the global group data-message counter. Behind
/// the `groups` feature — a unicast-only device never creates group sessions.
#[cfg(feature = "groups")]
impl Sessions {
    /// Re-hydrate the Global Group Encrypted Data Message Counter from the
    /// provided KV store.
    ///
    /// Resuming at the stored boundary puts the counter past every value the
    /// previous run may have used - otherwise peers tracking us in their group
    /// counter store would drop our post-restart group messages as replays.
    ///
    /// Nothing is written here: the resumed counter covers no values yet, so
    /// the first group send extends the boundary and stores it before its
    /// value reaches the wire. A node that never sends a group message
    /// therefore never writes this key.
    ///
    /// An absent key means "first boot": the counter is instead seeded
    /// randomly on first use, which likewise stores its boundary first.
    pub fn load_persist<S: KvBlobStore>(
        &mut self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        if let Some(data) = store.load(GROUP_DATA_COUNTER_KEY, buf)? {
            let boundary = u32::from_le_bytes(data.try_into().map_err(|_| ErrorCode::InvalidData)?);

            self.resume_global_group_data_ctr(boundary);
        }

        Ok(())
    }

    /// Factory-reset the Global Group Encrypted Data Message Counter - both
    /// in-memory and in the provided KV store.
    ///
    /// Unlike [`Sessions::reset`], which deliberately keeps the counter
    /// running, a factory reset drops every fabric and group key, so no peer
    /// can still be tracking this node's counter. The next group send seeds it
    /// afresh at random and stores the new boundary before going on the wire.
    pub fn reset_persist<S: KvBlobStore>(
        &mut self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.global_group_data_ctr = 0;
        self.group_data_ctr_boundary = 0;

        store.remove(GROUP_DATA_COUNTER_KEY, buf)?;

        Ok(())
    }

    /// Return the current Global Group Encrypted Data Message Counter,
    /// lazily initialized to a random value in `[1, 2^28 - 1]` on first
    /// access. The upper 4 bits are kept zero to leave headroom for
    /// wrap-safe monotonic growth.
    pub(crate) fn get_or_init_global_group_data_ctr<C: Crypto>(
        &mut self,
        crypto: C,
    ) -> Result<u32, Error> {
        if self.global_group_data_ctr == 0 {
            // Draw once and fall back to 1 in the (astronomically
            // unlikely) all-zero case; peers ignore a `MsgCounterSyncRsp`
            // whose Synchronized Counter is 0.
            let candidate = crypto.rand()?.next_u32() & MATTER_MSG_CTR_RANGE;
            self.set_global_group_data_ctr(if candidate == 0 { 1 } else { candidate });
        }
        Ok(self.global_group_data_ctr)
    }

    /// Resume the Global Group Encrypted Data Message Counter at `start` - the
    /// boundary read back from durable storage, which is past every value the
    /// previous run may have used.
    pub(crate) fn resume_global_group_data_ctr(&mut self, start: u32) {
        self.set_global_group_data_ctr(if start == 0 { 1 } else { start });
    }

    /// Set the live counter, with the stored boundary covering nothing beyond
    /// it: the next reservation is what extends the boundary by an epoch and
    /// demands it be written.
    fn set_global_group_data_ctr(&mut self, value: u32) {
        self.global_group_data_ctr = value;
        self.group_data_ctr_boundary = value;
    }

    /// Advance a counter value by `delta`, staying inside the Matter message
    /// counter range and skipping 0 (the "uninitialized" marker here, and a
    /// value peers ignore in `MsgCounterSyncRsp`).
    fn advance_group_data_ctr(value: u32, delta: u32) -> u32 {
        let next = value.wrapping_add(delta) & MATTER_MSG_CTR_RANGE;
        if next == 0 {
            1
        } else {
            next
        }
    }

    /// Reserve the counter value for one outgoing group data message,
    /// lazily initializing the counter if this is the first use.
    ///
    /// Returns `(value, boundary_to_persist)`. The caller MUST durably store
    /// `boundary_to_persist` (when `Some`) *before* putting `value` on the
    /// wire: only then is a restart guaranteed to resume past it. Group data
    /// messages are one-per-exchange, so exactly one value is reserved per
    /// [`crate::transport::exchange::Exchange::initiate_group`].
    #[must_use = "a returned boundary must be persisted before the value is sent"]
    pub(crate) fn reserve_global_group_data_ctr<C: Crypto>(
        &mut self,
        crypto: C,
    ) -> Result<(u32, Option<u32>), Error> {
        // First use: seed the counter at random.
        self.get_or_init_global_group_data_ctr(crypto)?;

        // The stored boundary covers `[ctr, boundary)`. Once the counter has
        // caught up with it, the value about to be handed out is not covered
        // by anything durable: move the boundary an epoch further and have the
        // caller store it before sending. The counter advances one at a time,
        // so this happens exactly once per epoch.
        let to_persist = if self.global_group_data_ctr == self.group_data_ctr_boundary {
            self.group_data_ctr_boundary =
                Self::advance_group_data_ctr(self.global_group_data_ctr, GROUP_DATA_CTR_EPOCH);

            Some(self.group_data_ctr_boundary)
        } else {
            None
        };

        let value = self.global_group_data_ctr;

        self.global_group_data_ctr = Self::advance_group_data_ctr(value, 1);

        Ok((value, to_persist))
    }

    /// Get or create a TX group session for sending group data messages to
    /// `(fab_idx, group_id)`.
    ///
    /// The mirror image of [`Sessions::get_or_create_for_group_rx`]: keyed
    /// with the group's *active* operational key (the epoch key with the
    /// highest start time — RX tries all of them instead), carrying the
    /// derived Group Session ID in both session-id slots, and addressed at
    /// the group's multicast address per its multicast-address policy.
    ///
    /// Also seeds the Global Group Encrypted Data Message Counter, which
    /// [`Session::pre_send`] stamps into every outgoing group data message
    /// (via [`Sessions::next_global_group_data_ctr`]).
    pub(crate) fn get_or_create_for_group_tx<C: Crypto>(
        &mut self,
        crypto: C,
        fabrics: &Fabrics,
        fab_idx: NonZeroU8,
        group_id: u16,
        dev_det: &BasicInfoConfig<'_>,
    ) -> Result<&mut Session, Error> {
        use crate::dm::clusters::decl::groupcast::MulticastAddrPolicyEnum;
        use crate::transport::network::{SocketAddr, SocketAddrV6};

        let fabric = fabrics.fabric(fab_idx)?;

        // The group's security material: the first key set mapped to the
        // group, with its active epoch key.
        let map_entry = fabric
            .groups()
            .key_map_iter()
            .find(|entry| entry.group_id == group_id)
            .ok_or(ErrorCode::NotFound)?;
        let key_set = fabric
            .groups()
            .key_set_get(map_entry.group_key_set_id)
            .ok_or(ErrorCode::NotFound)?;
        let epoch_key_entry = key_set
            .epoch_keys
            .iter()
            .max_by_key(|entry| entry.epoch_start_time)
            .ok_or(ErrorCode::NotFound)?;

        let mut derived = KeySet::new();
        derived.update(
            &crypto,
            epoch_key_entry.epoch_key.reference(),
            &fabric.compressed_fabric_id(),
        )?;
        let op_key = derived.op_key();
        let session_id = derive_group_session_id(&crypto, op_key)?;

        // Destination: the group's multicast address, per its policy. A
        // group the sender is no member of (a sender-only role) has no
        // group-table entry and uses the `PerGroup` default.
        let ip = match fabric
            .groups()
            .get(group_id)
            .map(|entry| entry.effective_mcast_policy())
            .unwrap_or(MulticastAddrPolicyEnum::PerGroup)
        {
            MulticastAddrPolicyEnum::IanaAddr => crate::utils::ipv6::IANA_GROUPCAST_MULTICAST_ADDR,
            MulticastAddrPolicyEnum::PerGroup => {
                crate::utils::ipv6::compute_group_multicast_addr(fabric.fabric_id(), group_id)
            }
        };
        let peer = Address::Udp(SocketAddr::V6(SocketAddrV6::new(
            ip,
            crate::MATTER_PORT,
            0,
            0,
        )));
        let fabric_node_id = fabric.node_id();

        // Seed the global data counter while we hold a crypto instance.
        self.get_or_init_global_group_data_ctr(&crypto)?;

        // Reuse a previously-created TX session for this group: same mode
        // and the multicast peer address (RX-created group sessions carry
        // the sender's unicast address instead), still keyed with the
        // active key — checked via the derived Group Session ID, so a key
        // rotation transparently rolls onto a fresh session.
        let existing = self.sessions.iter().position(|sess| {
            matches!(
                sess.mode,
                SessionMode::Group {
                    fab_idx: f,
                    group_id: g
                } if f == fab_idx && g == group_id
            ) && sess.peer_addr == peer
                && sess.local_sess_id == session_id
        });

        if let Some(index) = existing {
            let session = unwrap!(self.sessions.get_mut(index));
            session.update_last_used();
            return Ok(session);
        }

        let mut rand = crypto.weak_rand()?;

        let session = match self.add(rand.next_u32(), false, peer, None, dev_det) {
            Ok(session) => session,
            Err(_) => {
                // Session table is full; evict the least-recently-used session
                if let Some(lru_id) = self.get_session_for_eviction().map(|sess| sess.id) {
                    debug!("Group TX: Evicting session {} to make room", lru_id);
                    self.remove(lru_id);
                    self.add(rand.next_u32(), false, peer, None, dev_det)?
                } else {
                    return Err(ErrorCode::NoSpaceSessions.into());
                }
            }
        };

        session.set_session_mode(SessionMode::Group { fab_idx, group_id });
        session.local_sess_id = session_id;
        session.peer_sess_id = session_id;
        // Group sessions always emit their Source Node ID.
        session.set_local_nodeid(fabric_node_id);
        session.enc_key.load(op_key);
        session.dec_key.load(op_key);

        debug!(
            "Group TX: Created group session for fab_idx={}, group_id=0x{:04x}, dst={}",
            fab_idx, group_id, peer
        );

        let session = unwrap!(self.sessions.last_mut());
        session.update_last_used();

        Ok(session)
    }

    /// Attempt to decrypt and accept a group-encrypted message.
    ///
    /// Handles two flavors of incoming group-encrypted packet:
    ///
    /// * Multicast group data message (groupcast destination Node ID):
    ///   match `(session_id, group_id)` against the fabric's group key
    ///   map, try each candidate operational key, and validate the
    ///   group data message counter (trust-first).
    /// * Unicast group-encrypted control message (unicast destination
    ///   Node ID equal to one of our fabric identities), e.g. an
    ///   MCSP `MsgCounterSyncReq`. There is no `group_id` filter here;
    ///   every group key mapped for the matching fabric is tried.
    ///
    /// On success the derived operational key is copied onto the newly
    /// created session (both `enc_key` and `dec_key`) so downstream
    /// handlers — in particular the MCSP responder — can encrypt their
    /// reply with the same key.
    ///
    /// Returns the created session and payload range, mirroring how
    /// unicast uses `get_for_rx()` + `decode_remaining()`.
    pub(crate) fn get_or_create_for_group_rx<const N: usize, C: Crypto>(
        &mut self,
        crypto: C,
        fabrics: &Fabrics,
        packet: &mut Packet<N>,
        dev_det: &BasicInfoConfig<'_>,
    ) -> Result<(&mut Session, (usize, usize)), Error> {
        let src_nodeid = packet
            .header
            .plain
            .get_src_nodeid()
            .ok_or(ErrorCode::InvalidData)?;
        // Either DSIZ = 2 (groupcast) or DSIZ = 1 (unicast to us, MCSP-style).
        // Anything else is malformed.
        let dst_group_id = packet.header.plain.get_dst_groupcast_nodeid();
        let dst_unicast_nodeid = packet.header.plain.get_dst_unicast_nodeid();

        if dst_group_id.is_none() && dst_unicast_nodeid.is_none() {
            return Err(ErrorCode::InvalidData.into());
        }

        let expected_sess_id = packet.header.plain.sess_id;
        let msg_ctr = packet.header.plain.ctr;
        let is_control = packet.header.plain.is_control_msg();

        debug!(
            "Group: Attempting decrypt for PEER={:?} SID=0x{:04x}, GRP={:?}, DSTU={:?}, SRC=0x{:016x}, CTR={}, C={}",
            packet.peer,
            expected_sess_id,
            dst_group_id,
            dst_unicast_nodeid,
            src_nodeid,
            msg_ctr,
            is_control
        );

        // Parse the plain header to determine encrypted portion offset
        let mut pb = ParseBuf::new(&mut packet.buf[packet.payload_start..]);
        packet.header.plain.decode(&mut pb)?;

        // Save the encrypted payload so we can restore it between decryption attempts
        let encrypted_offset = pb.read_off();
        let encrypted_len = pb.as_slice().len();
        let mut saved_encrypted = [0u8; 1280];

        if encrypted_len > saved_encrypted.len() {
            return Err(ErrorCode::BufferTooSmall.into());
        }

        saved_encrypted[..encrypted_len].copy_from_slice(pb.as_slice());

        // Derive keys on-the-fly and try each one. When a key decrypts,
        // we remember its operational key material so we can copy it
        // onto the created session (needed by the MCSP responder to
        // encrypt its reply with the same key).
        //
        // `effective_group_id` is:
        //   * the incoming groupcast id for the multicast flow, or
        //   * for the unicast/MCSP flow, the first group_id that maps to
        //     the matching key set (or 0 when the key set has no
        //     mapping) — MCSP itself is bound to a key, not a group, so
        //     any value is acceptable here.
        struct GroupKeyFound {
            fab_idx: NonZeroU8,
            group_id: u16,
            fabric_node_id: u64,
            op_key: CanonAeadKey,
            payload_range: (usize, usize),
        }

        let mut group_key_found: Option<GroupKeyFound> = None;
        // Whether at least one candidate key matched the message's group
        // session ID (and was therefore actually tried for decryption) -
        // distinguishes "authentication failed" from "no key available"
        // for Groupcast testing-mode diagnostics.
        let mut key_attempted = false;

        'outer: for fabric in fabrics.iter() {
            // For unicast (MCSP) messages the destination Node ID must
            // match one of our fabric identities; skip fabrics whose
            // node id doesn't match, to avoid pointlessly trying keys
            // that could not have secured a reply to us.
            if let Some(dst_node) = dst_unicast_nodeid {
                if fabric.node_id() != dst_node {
                    continue;
                }
            }

            let fab_idx = fabric.fab_idx();
            let compressed_fabric_id = fabric.compressed_fabric_id();
            let fabric_node_id = fabric.node_id();

            for map_entry in fabric.groups().key_map_iter() {
                // Multicast: restrict to the target group. Unicast MCSP:
                // any mapping is a candidate — the request is bound to
                // a key, not a group.
                if let Some(gid) = dst_group_id {
                    if map_entry.group_id != gid {
                        continue;
                    }
                }

                let Some(key_set_entry) = fabric.groups().key_set_get(map_entry.group_key_set_id)
                else {
                    continue;
                };

                for epoch_key_entry in key_set_entry.epoch_keys.iter() {
                    let mut temp_key_set = KeySet::new();

                    if temp_key_set
                        .update(
                            &crypto,
                            epoch_key_entry.epoch_key.reference(),
                            &compressed_fabric_id,
                        )
                        .is_err()
                    {
                        continue;
                    }

                    let op_key_ref = temp_key_set.op_key();

                    let Ok(session_id) = derive_group_session_id(&crypto, op_key_ref) else {
                        continue;
                    };

                    if session_id != expected_sess_id {
                        continue;
                    }

                    key_attempted = true;

                    if let Some(payload_range) = Self::try_group_decrypt(
                        &crypto,
                        packet,
                        &saved_encrypted[..encrypted_len],
                        encrypted_offset,
                        op_key_ref,
                        src_nodeid,
                    ) {
                        // Copy the op key so it survives past `temp_key_set`.
                        let mut op_key_owned = crate::crypto::AEAD_KEY_ZEROED;
                        op_key_owned.load(op_key_ref);
                        let effective_group_id = dst_group_id.unwrap_or(map_entry.group_id);
                        group_key_found = Some(GroupKeyFound {
                            fab_idx,
                            group_id: effective_group_id,
                            fabric_node_id,
                            op_key: op_key_owned,
                            payload_range,
                        });

                        break 'outer;
                    }
                }
            }
        }

        if group_key_found.is_none() {
            debug!(
                "Group: No key could decrypt the message (SID=0x{:04x}, GRP={:?}, DSTU={:?})",
                expected_sess_id, dst_group_id, dst_unicast_nodeid
            );
        }

        // `NoSession` = no candidate key was available for this message;
        // `InvalidSignature` = candidate key(s) matched the group session ID
        // but none authenticated the message. The distinction feeds the
        // `GroupcastTesting` event's result field (`NoAvailableKey` vs
        // `FailedAuth`).
        let GroupKeyFound {
            fab_idx,
            group_id,
            fabric_node_id,
            op_key,
            payload_range,
        } = group_key_found.ok_or(if key_attempted {
            ErrorCode::InvalidSignature
        } else {
            ErrorCode::NoSession
        })?;

        // Only data messages participate in this dedup: control
        // messages (`C = 1`) live on a separate control-counter space
        // that we don't track yet, and are trust-first regardless.
        if !is_control
            && !self
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
        let peer = packet.peer;
        let mut rand = crypto.weak_rand()?;

        let session = match self.add(rand.next_u32(), false, peer, Some(src_nodeid), dev_det) {
            Ok(session) => session,
            Err(_) => {
                // Session table is full; evict the least-recently-used session
                if let Some(lru_id) = self.get_session_for_eviction().map(|sess| sess.id) {
                    debug!("Group: Evicting session {} to make room", lru_id);
                    self.remove(lru_id);
                    self.add(rand.next_u32(), false, peer, Some(src_nodeid), dev_det)?
                } else {
                    return Err(ErrorCode::NoSpaceSessions.into());
                }
            }
        };

        session.set_session_mode(SessionMode::Group { fab_idx, group_id });
        session.local_sess_id = expected_sess_id;
        // Mirror the group session id onto the peer side so `pre_send`
        // emits the correct value when we reply.
        session.peer_sess_id = expected_sess_id;
        // Group sessions always emit their Source Node ID, so `pre_send`
        // needs this set to our identity for the matching fabric.
        session.set_local_nodeid(fabric_node_id);
        // Keep the operational key on the session so downstream
        // handlers (e.g. MCSP responder) can encrypt the reply with the
        // same key that decrypted the request.
        session.dec_key.load(op_key.reference());
        session.enc_key.load(op_key.reference());

        debug!(
            "Group: Created group session for fab_idx={}, group_id=0x{:04x}, src_nodeid=0x{:016x}",
            fab_idx, group_id, src_nodeid
        );

        // Re-borrow the current created session for returning
        let session = unwrap!(self.sessions.last_mut());
        session.update_last_used();

        Ok((session, payload_range))
    }

    /// Try to decrypt a group message with a candidate key.
    /// Restores the ciphertext before attempting.
    /// On success, returns the payload range; the packet buffer contains decrypted data.
    fn try_group_decrypt<const N: usize, C: Crypto>(
        crypto: C,
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
}

impl Sessions {
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

    pub fn get_next_exch_id<C: Crypto>(&mut self, crypto: C) -> Result<u16, Error> {
        if self.next_exch_id == 0 {
            // Per the Matter Core spec, the first exchange ID of an initiator
            // node must be a random integer, with all subsequent ones
            // incrementing by one. Seeding is lazy because the constructors
            // have no access to an RNG (`Sessions::new` is `const`).
            //
            // `0` is unambiguous as the "not seeded yet" sentinel, because the
            // counter below never assumes that value.
            let candidate = crypto.rand()?.next_u32() as u16;
            self.next_exch_id = if candidate == 0 { 1 } else { candidate };
        }

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

        Ok(next_exch_id)
    }

    pub fn get_session_for_eviction(&mut self) -> Option<&mut Session> {
        let mut lru_index = None;
        let mut lru_ts = Instant::now();
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
        dev_det: &BasicInfoConfig<'_>,
    ) -> Result<&mut Session, Error> {
        let session_id = self.next_sess_unique_id;

        self.next_sess_unique_id += 1;
        if self.next_sess_unique_id > 0x0fff_ffff {
            // Reserve the upper 4 bits for the exchange index
            self.next_sess_unique_id = 0;
        }

        // Seed the peer's MRP intervals from our own configured defaults;
        // they'll be overwritten by Sigma1 / PBKDFParamRequest (or the
        // initiator's Sigma2 / PBKDFParamResponse) once the peer
        // advertises its own `session_parameters`.
        let (peer_active_interval_ms, peer_idle_interval_ms, peer_active_threshold_ms) =
            mrp::default_peer_mrp_params(dev_det);

        let session = Session::init(
            session_id,
            msg_ctr,
            reserved,
            peer_addr,
            peer_nodeid,
            peer_active_interval_ms,
            peer_idle_interval_ms,
            peer_active_threshold_ms,
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
            session.update_last_used();
        }

        session
    }

    /// Find the operational (CASE) session for a `(fabric, node)` pair.
    ///
    /// Operational sessions are by definition encrypted and on a real fabric,
    /// so the lookup always matches an encrypted session - there is no
    /// "unsecured by node" lookup (unsecured/PASE sessions carry no operational
    /// identity; see [`Sessions::get_pase_for_addr`]).
    pub(crate) fn get_for_node(
        &mut self,
        fabric_idx: NonZeroU8,
        peer_node_id: u64,
    ) -> Option<&mut Session> {
        // Prefer a TCP-backed session (larger payloads, no MRP fragmentation
        // limits) over UDP when both are available for the same peer. This
        // is required e.g. for the WebRTC Transport Provider's outbound
        // `Answer(sdp)` invoke whose payload can easily exceed a UDP MTU.
        //
        // Among sessions of the same transport, prefer the most recently used
        // one: when several CASE sessions to the same peer exist, the freshest
        // is the one the peer is actually communicating on, so reports and other
        // outbound traffic reach the session it is listening on.
        let idx = self
            .sessions
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.expired && s.is_for_node(fabric_idx, peer_node_id))
            .max_by_key(|(_, s)| (s.peer_addr.is_tcp(), s.last_use))
            .map(|(i, _)| i)?;

        let session = &mut self.sessions[idx];

        session.update_last_used();

        Some(session)
    }

    /// Find an in-flight PASE session to the given peer address.
    ///
    /// Used by [`Exchange::initiate_pase`](crate::transport::exchange::Exchange::initiate_pase)
    /// to reuse a PASE session per peer (rather than assuming a single global
    /// one), so a commissioner can drive several concurrent commissionings.
    pub(crate) fn get_pase_for_addr(&mut self, peer_addr: &Address) -> Option<&mut Session> {
        let mut session = self
            .sessions
            .iter_mut()
            .find(|s| !s.expired && s.is_pase_for_addr(peer_addr));

        if let Some(session) = session.as_mut() {
            session.update_last_used();
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
            session.update_last_used();
        }

        session
    }

    pub(crate) fn get_for_tx(&mut self, session_id: u32) -> Option<&mut Session> {
        let mut session = self
            .sessions
            .iter_mut()
            .find(|sess| sess.is_for_tx(session_id));

        if let Some(session) = session.as_mut() {
            session.update_last_used();
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
            let session = unwrap!(self.get(id));
            session.update_last_used();

            Some((session, exch_index))
        } else {
            None
        }
    }

    /// Iterate over the sessions
    pub fn iter(&self) -> impl Iterator<Item = &Session> {
        self.sessions.iter()
    }

    /// Drop every PASE session, whether unpromoted (still
    /// `SessionMode::Pase { fab_idx: 0 }`) or already promoted to a
    /// fabric. Used by:
    ///
    /// * `RevokeCommissioning` and a fail-safe expiry over a PASE
    ///   session (Matter Core spec): when the
    ///   commissioning window is torn down, any in-flight PASE sessions
    ///   associated with it must be terminated. A PASE that was
    ///   promoted via `AddNOC` is rolled back by the same fail-safe
    ///   expiry, so its session must go too.
    /// * `CommissioningComplete` (Matter Core spec): once the device
    ///   transitions to operational state,
    ///   all PASE sessions SHALL be terminated. Without this each
    ///   commissioning round leaks the promoted PASE it ran on, and
    ///   the session table eventually exhausts — visible as `BUSY` on
    ///   the next round's `PBKDFParamRequest`.
    ///
    /// `expire_sess_id` is the optional ID of a session that should NOT
    /// be removed immediately — typically the session that issued the
    /// triggering command, so its response can still be sent. That
    /// session is marked as `expired` instead, so it stops accepting
    /// new exchanges but the in-flight one can complete; the transport
    /// reclaims the slot via the usual LRU eviction path.
    pub fn remove_pase(&mut self, expire_sess_id: Option<u32>) {
        while let Some(index) = self.sessions.iter().position(|sess| {
            matches!(sess.get_session_mode(), SessionMode::Pase { .. })
                && Some(sess.id) != expire_sess_id
        }) {
            info!("Dropping PASE session with ID {}", self.sessions[index].id);
            self.sessions.swap_remove(index);
        }

        if let Some(expire_sess_id) = expire_sess_id {
            if let Some(sess) = self.sessions.iter_mut().find(|sess| {
                sess.id == expire_sess_id
                    && matches!(sess.get_session_mode(), SessionMode::Pase { .. })
            }) {
                sess.expired = true;
                info!("Marking PASE session with ID {} as expired", expire_sess_id);
            }
        }
    }
}

impl Default for Sessions {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Sessions {
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
/// Per Matter Spec:
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
    use crate::crypto::{test_only_crypto, AEAD_KEY_ZEROED};
    use crate::dm::clusters::basic_info::BasicInfoConfig;
    use crate::transport::network::{Address, BtAddr};

    use super::*;

    /// Stand-in `BasicInfoConfig` for tests that don't care about the
    /// peer-MRP defaults — `Sessions::add` only reads `sai`/`sii` from it.
    const TEST_DEV_DET: BasicInfoConfig<'static> = BasicInfoConfig::new();

    #[test]
    fn test_next_sess_id_doesnt_reuse() {
        let mut sm = Sessions::new();
        let sess = unwrap!(sm.add(0, false, Address::default(), None, &TEST_DEV_DET));
        sess.set_local_sess_id(1);
        assert_eq!(sm.get_next_sess_id(), 2);
        assert_eq!(sm.get_next_sess_id(), 3);
        let sess = unwrap!(sm.add(0, false, Address::default(), None, &TEST_DEV_DET));
        sess.set_local_sess_id(4);
        assert_eq!(sm.get_next_sess_id(), 5);
    }

    #[test]
    fn test_next_sess_id_overflows() {
        let mut sm = Sessions::new();
        let sess = unwrap!(sm.add(0, false, Address::default(), None, &TEST_DEV_DET));
        sess.set_local_sess_id(1);
        assert_eq!(sm.get_next_sess_id(), 2);
        sm.next_sess_id = 65534;
        assert_eq!(sm.get_next_sess_id(), 65534);
        assert_eq!(sm.get_next_sess_id(), 65535);
        assert_eq!(sm.get_next_sess_id(), 2);
    }

    /// The receive timeout is derived per transport: only UDP has an MRP ladder
    /// to account for, while TCP and BTP carry their own reliability underneath.
    #[test]
    fn rx_timeout_is_per_transport() {
        use core::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

        let addr = |f: fn(SocketAddr) -> Address| {
            f(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                5540,
                0,
                0,
            )))
        };

        let session = |peer_addr| Session::new(1, 0, false, peer_addr, None, 300, 5000, 4000);

        assert_eq!(
            session(addr(Address::Tcp)).rx_timeout_ms(300),
            TCP_RX_TIMEOUT_MS
        );
        assert_eq!(
            session(Address::Btp(BtAddr([0; 6]))).rx_timeout_ms(300),
            BTP_RX_TIMEOUT_MS
        );

        // UDP sums both directions of the MRP ladder plus the processing
        // allowance, and is therefore strictly larger than either ladder alone.
        let udp = session(addr(Address::Udp)).rx_timeout_ms(300);
        let one_ladder = mrp::RetransEntry::retransmission_timeout_ms(300, 300, 0, true);

        assert_eq!(
            udp,
            one_ladder + mrp::MRP_EXPECTED_PROCESSING_MS + one_ladder
        );
        assert!(udp > one_ladder + mrp::MRP_EXPECTED_PROCESSING_MS);
    }

    /// The receive timeout must outlast the send-side give-up, or a peer that is
    /// merely slow would be abandoned before its answer could arrive.
    #[test]
    fn rx_timeout_outlasts_the_send_side_give_up() {
        use core::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

        let peer_addr = Address::Udp(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            5540,
            0,
            0,
        )));

        let rx = Session::new(1, 0, false, peer_addr, None, 300, 5000, 4000).rx_timeout_ms(300);
        let give_up = mrp::RetransEntry::retransmission_timeout_ms(300, 5000, 4000, false);

        assert!(
            rx > give_up,
            "receive timeout {rx}ms must exceed the retransmission give-up {give_up}ms"
        );
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

    /// The persisted-boundary bookkeeping of the global group data message
    /// counter. The invariant under test: every reserved value is covered by
    /// a boundary the caller was told to persist BEFORE that value can be
    /// sent - so a restart always resumes past everything handed out.
    #[cfg(feature = "groups")]
    #[test]
    fn test_group_data_ctr_reserve_boundary() {
        let crypto = test_only_crypto();

        let mut sessions = Sessions::new();

        // Resuming at a stored boundary covers nothing yet.
        sessions.resume_global_group_data_ctr(1000);

        // The first reservation hands out the stored boundary itself - past
        // every value the previous run could have used - and returns the new
        // boundary, to be made durable before that value is sent.
        let (value, boundary) = sessions.reserve_global_group_data_ctr(&crypto).unwrap();
        assert_eq!(value, 1000);
        assert_eq!(boundary, Some(1000 + GROUP_DATA_CTR_EPOCH));

        // The rest of the epoch is already covered, so no further writes are
        // demanded - and every handed-out value stays below what is durable.
        let durable = boundary.unwrap();
        for expected in 1001..1000 + GROUP_DATA_CTR_EPOCH {
            let (value, boundary) = sessions.reserve_global_group_data_ctr(&crypto).unwrap();
            assert_eq!(value, expected);
            assert_eq!(boundary, None);
            assert!(value < durable);
        }

        // The first value the stored boundary does *not* cover is the boundary
        // itself - reserving it demands the next one be written first.
        let (value, boundary) = sessions.reserve_global_group_data_ctr(&crypto).unwrap();
        assert_eq!(value, durable);
        assert_eq!(boundary, Some(1000 + 2 * GROUP_DATA_CTR_EPOCH));
    }

    /// A first-ever reservation seeds the counter and demands its boundary be
    /// persisted before the value is used - no send can precede a write.
    #[cfg(feature = "groups")]
    #[test]
    fn test_group_data_ctr_first_reservation_persists() {
        let crypto = test_only_crypto();

        let mut sessions = Sessions::new();

        let (value, boundary) = sessions.reserve_global_group_data_ctr(&crypto).unwrap();

        assert_ne!(value, 0);
        let boundary = boundary.expect("the first reservation must demand a persist");
        assert!(value < boundary);
    }

    /// The counter and its boundary stay inside the Matter message counter
    /// range and never land on 0 (the "uninitialized" marker, and a value
    /// peers ignore in `MsgCounterSyncRsp`).
    #[cfg(feature = "groups")]
    #[test]
    fn test_group_data_ctr_wraps_within_range() {
        let crypto = test_only_crypto();
        let top = MATTER_MSG_CTR_RANGE;

        let mut sessions = Sessions::new();
        sessions.resume_global_group_data_ctr(top);

        assert_eq!(
            sessions.reserve_global_group_data_ctr(&crypto).unwrap().0,
            top
        );
        // `top + 1` masks to 0 -> skipped to 1.
        assert_eq!(
            sessions.reserve_global_group_data_ctr(&crypto).unwrap().0,
            1
        );

        // A boundary that would land on 0 is likewise skipped.
        let mut sessions = Sessions::new();
        sessions.resume_global_group_data_ctr(top + 1 - GROUP_DATA_CTR_EPOCH);
        assert_eq!(
            sessions.reserve_global_group_data_ctr(&crypto).unwrap().1,
            Some(1)
        );
    }

    /// The safety invariant of the epoch scheme, checked across the 28-bit
    /// wrap: at every point, the boundary last handed out for persisting is a
    /// value that has *not* been used yet. A restart resumes exactly there, so
    /// this is what guarantees no counter value is ever re-issued - which for
    /// group messages would repeat an AEAD nonce under the same group key.
    #[cfg(all(feature = "groups", feature = "std"))]
    #[test]
    fn test_group_data_ctr_persist_covers_every_value_across_wrap() {
        let crypto = test_only_crypto();

        let mut sessions = Sessions::new();

        // Start two epochs below the top of the range, so the walk below runs
        // through the wrap.
        let start = MATTER_MSG_CTR_RANGE - 2 * GROUP_DATA_CTR_EPOCH;
        sessions.resume_global_group_data_ctr(start);

        let mut used = std::collections::HashSet::new();
        let mut last_stored = start;

        for _ in 0..5 * GROUP_DATA_CTR_EPOCH {
            let (value, boundary) = sessions.reserve_global_group_data_ctr(&crypto).unwrap();

            // `initiate_group` writes the boundary before the value is sent.
            if let Some(boundary) = boundary {
                last_stored = boundary;
            }

            used.insert(value);

            assert!(
                !used.contains(&last_stored),
                "a restart would resume at an already used counter value"
            );
        }
    }

    /// A resume value of 0 (a corrupt/blank stored boundary) must not leave
    /// the counter in the "uninitialized" state.
    #[cfg(feature = "groups")]
    #[test]
    fn test_group_data_ctr_resume_zero() {
        let crypto = test_only_crypto();

        let mut sessions = Sessions::new();
        sessions.resume_global_group_data_ctr(0);

        assert_eq!(
            sessions.reserve_global_group_data_ctr(&crypto).unwrap().0,
            1
        );
    }

    /// An in-memory [`KvBlobStore`](crate::persist::KvBlobStore) for the
    /// counter persistence tests below.
    #[cfg(all(feature = "groups", feature = "std"))]
    struct MemKv(std::collections::HashMap<u16, std::vec::Vec<u8>>);

    #[cfg(all(feature = "groups", feature = "std"))]
    impl crate::persist::KvBlobStore for &mut MemKv {
        fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
            Ok(self.0.get(&key).map(|v| {
                buf[..v.len()].copy_from_slice(v);
                &buf[..v.len()]
            }))
        }

        fn store(&mut self, key: u16, data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
            self.0.insert(key, data.to_vec());
            Ok(())
        }

        fn remove(&mut self, key: u16, _buf: &mut [u8]) -> Result<(), Error> {
            self.0.remove(&key);
            Ok(())
        }
    }

    /// The reboot-survival contract of [`crate::Matter::startup`]: it reads
    /// the boundary the previous run stored (same key, same encoding) and
    /// resumes the counter *at* it - past everything that run could have sent.
    ///
    /// Startup itself writes nothing; the first reservation is what extends
    /// the boundary and demands it be stored before its value is sent.
    #[cfg(all(feature = "groups", feature = "std"))]
    #[test]
    fn test_group_data_ctr_resumes_from_storage() {
        use crate::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
        use crate::persist::GROUP_DATA_COUNTER_KEY;
        use crate::Matter;

        /// The previous run's stored boundary.
        const STORED: u32 = 5000;

        let mut kv = MemKv(std::collections::HashMap::new());
        kv.0.insert(GROUP_DATA_COUNTER_KEY, STORED.to_le_bytes().to_vec());

        let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
        matter.startup(matter.kv(&mut kv)).unwrap();

        // Startup itself does not write - a node that never sends a group
        // message leaves the key exactly as the previous run left it.
        let stored = kv.0.get(&GROUP_DATA_COUNTER_KEY).unwrap();
        assert_eq!(
            u32::from_le_bytes(stored.as_slice().try_into().unwrap()),
            STORED
        );

        // The first value handed out is the stored boundary itself - past
        // everything the previous run could have used - and it comes with the
        // next boundary, which `initiate_group` stores before sending.
        let (first, boundary) = matter
            .with_state(|state| {
                state
                    .sessions
                    .reserve_global_group_data_ctr(test_only_crypto())
            })
            .unwrap();

        assert_eq!(first, STORED);
        assert_eq!(boundary, Some(STORED + GROUP_DATA_CTR_EPOCH));
    }

    /// A factory reset drops the stored boundary along with the fabrics and
    /// group keys it covered, and the next use seeds a fresh counter that is
    /// again persisted before anything can be sent.
    #[cfg(all(feature = "groups", feature = "std"))]
    #[test]
    fn test_group_data_ctr_factory_reset() {
        use crate::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
        use crate::persist::GROUP_DATA_COUNTER_KEY;
        use crate::Matter;

        let mut kv = MemKv(std::collections::HashMap::new());
        kv.0.insert(GROUP_DATA_COUNTER_KEY, 5000u32.to_le_bytes().to_vec());

        let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
        matter.startup(matter.kv(&mut kv)).unwrap();

        matter.factory_reset(matter.kv(&mut kv)).unwrap();

        assert!(!kv.0.contains_key(&GROUP_DATA_COUNTER_KEY));

        // The counter is back to "first boot": the next reservation seeds it
        // at random and hands back a boundary that must be stored first.
        let (value, boundary) = matter
            .with_state(|state| {
                state
                    .sessions
                    .reserve_global_group_data_ctr(test_only_crypto())
            })
            .unwrap();

        assert_ne!(value, 0);
        assert_eq!(boundary, Some(value + GROUP_DATA_CTR_EPOCH));
    }
}
