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

//! Opening exchanges over sessions which may have to be established first, i.e.
//! the part of initiating an exchange that needs the CASE and PASE initiators.

use core::num::NonZeroU8;

use crate::crypto::Crypto;
use crate::dm::NodeId;
use crate::error::Error;
#[cfg(feature = "case-responder-only")]
use crate::error::ErrorCode;
use crate::pase::PaseInitiator;
use crate::transport::exchange::Exchange;
use crate::transport::network::Address;
use crate::transport::TransportPreference;
use crate::ScHost;
#[cfg(not(feature = "case-responder-only"))]
use {
    crate::case::CaseInitiator,
    crate::error::ErrorCode,
    crate::transport::network::MatterRemoteService,
    crate::transport::session::PeerMrpParams,
    crate::transport::{CaseSetupTurn, Transport},
};

/// Opens exchanges over sessions which may have to be established first.
pub trait ExchangeInitiator<'a>: Sized {
    /// Open an exchange over a CASE session to an already-commissioned node.
    ///
    /// If a CASE session for `(fabric_idx, peer_node_id)` already exists, an
    /// exchange is opened on it directly via [`Exchange::initiate_for_session`]
    /// (the common case - session and peer address reused, no mDNS). Otherwise
    /// the peer's operational address is resolved over mDNS and a fresh CASE
    /// session is established (driving [`CaseInitiator`]) before
    /// the exchange is opened on it; the peer's MRP parameters advertised in the
    /// mDNS TXT records seed the handshake, and the ones it advertises in the
    /// handshake itself take precedence.
    ///
    /// Concurrent calls for a node that has no session share one handshake: the
    /// later ones wait for it and use its session, or get its error.
    ///
    /// Establishing requires a running mDNS responder (e.g.
    /// `BuiltinMdns::run`) to service the resolve; without one the
    /// resolve times out and this returns [`ErrorCode::NotFound`].
    ///
    /// With the `case-responder-only` feature the establish path is compiled
    /// out: only an existing session is reused, and if none exists this returns
    /// [`ErrorCode::NoSession`] instead of opening a new one. This lets the linker
    /// drop the CASE initiator and mDNS resolver from a node that never needs to
    /// initiate CASE (a pure accessory that only reports over sessions its peers
    /// established).
    async fn initiate<M: ScHost, C: Crypto>(
        matter: &'a M,
        crypto: C,
        fabric_idx: NonZeroU8,
        peer_node_id: NodeId,
    ) -> Result<Self, Error>;

    /// [`Self::initiate`], choosing the transport a newly established session
    /// runs over.
    ///
    /// Only matters when no session to the peer exists yet - an existing session
    /// is reused whatever it runs over. Pass
    /// [`TransportPreference::LargePayload`] to require TCP; the peer must have
    /// advertised TCP server support or establishment fails rather than silently
    /// downgrading. See [`TransportPreference`].
    async fn initiate_with_transport<M: ScHost, C: Crypto>(
        matter: &'a M,
        crypto: C,
        fabric_idx: NonZeroU8,
        peer_node_id: NodeId,
        transport: TransportPreference,
    ) -> Result<Self, Error>;

    /// Open an exchange over a **PASE** session to a not-yet-commissioned node
    /// at the given peer address (use-case 2).
    ///
    /// If a PASE session **to that peer** already exists, an exchange is opened on
    /// it directly via [`Exchange::initiate_for_session`]. Otherwise a new PASE
    /// session is established: a plaintext session is opened and the PASE protocol
    /// ([`PaseInitiator`]) is run with `passcode`, then an
    /// exchange is opened on the resulting PASE session.
    ///
    /// Reuse is keyed by peer address (not a single global PASE session), so a
    /// commissioner can drive several concurrent commissionings.
    ///
    /// The peer's MRP/session parameters are negotiated by PASE itself
    /// (PBKDFParamRequest/Response).
    ///
    /// Discovery of the address is out of scope here (it may come from mDNS - see
    /// [`crate::transport::Transport::browse`] - or from a BLE/BTP
    /// advertisement, etc.); this method is transport-agnostic and takes the
    /// already-known address.
    async fn initiate_pase<M: ScHost, C: Crypto>(
        matter: &'a M,
        crypto: C,
        peer_addr: Address,
        passcode: u32,
    ) -> Result<Self, Error>;
}

impl<'a> ExchangeInitiator<'a> for Exchange<'a> {
    #[inline(always)]
    async fn initiate<M: ScHost, C: Crypto>(
        matter: &'a M,
        crypto: C,
        fabric_idx: NonZeroU8,
        peer_node_id: NodeId,
    ) -> Result<Self, Error> {
        Self::initiate_with_transport(
            matter,
            crypto,
            fabric_idx,
            peer_node_id,
            TransportPreference::Mrp,
        )
        .await
    }

    async fn initiate_with_transport<M: ScHost, C: Crypto>(
        matter: &'a M,
        crypto: C,
        fabric_idx: NonZeroU8,
        peer_node_id: NodeId,
        transport: TransportPreference,
    ) -> Result<Self, Error> {
        // Reuse an existing CASE session if present.
        let existing = matter.with_sc_state(|state| {
            Ok::<_, Error>(
                state
                    .sessions
                    .get_for_node(fabric_idx, peer_node_id)
                    .map(|s| s.id),
            )
        })?;

        if let Some(session_id) = existing {
            return Self::initiate_for_session(matter.transport(), crypto, session_id);
        }

        initiate_new_case(matter, crypto, fabric_idx, peer_node_id, transport).await
    }

    async fn initiate_pase<M: ScHost, C: Crypto>(
        matter: &'a M,
        crypto: C,
        peer_addr: Address,
        passcode: u32,
    ) -> Result<Self, Error> {
        // Reuse an existing PASE session to this peer, if present.
        let existing = matter.with_sc_state(|state| {
            Ok::<_, Error>(state.sessions.get_pase_for_addr(&peer_addr).map(|s| s.id))
        })?;

        if let Some(session_id) = existing {
            return Self::initiate_for_session(matter.transport(), crypto, session_id);
        }

        // Establish a new PASE session to this peer.
        let exchange = Self::initiate_plaintext(matter.transport(), &crypto, peer_addr).await?;
        PaseInitiator::perform(matter, exchange, &crypto, passcode, None).await?;

        let session_id = matter.with_sc_state(|state| {
            state
                .sessions
                .get_pase_for_addr(&peer_addr)
                .map(|s| s.id)
                .ok_or_else(|| Error::from(ErrorCode::NoSession))
        })?;

        Self::initiate_for_session(matter.transport(), crypto, session_id)
    }
}

/// Establish a fresh CASE session to an already-commissioned peer (resolving
/// its operational address over mDNS), then open an exchange on it. Called by
/// `Exchange::initiate` only when no live session to the peer exists.
///
/// If another caller is already establishing the session, this waits for it
/// and uses its session, or returns its error.
///
/// With the `case-responder-only` feature this is compiled out and replaced
/// by an immediate [`ErrorCode::NoSession`]: reporting (and every other
/// on-demand initiator) then reuses an existing session or fails, and the
/// linker drops the whole CASE-initiator and mDNS-resolver machinery.
#[cfg(not(feature = "case-responder-only"))]
async fn initiate_new_case<'a, M: ScHost, C: Crypto>(
    matter: &'a M,
    crypto: C,
    fabric_idx: NonZeroU8,
    peer_node_id: NodeId,
    transport: TransportPreference,
) -> Result<Exchange<'a>, Error> {
    loop {
        match matter
            .transport()
            .case_setups()
            .enter(fabric_idx, peer_node_id)
        {
            CaseSetupTurn::Wait(setup) => setup.wait().await?,
            CaseSetupTurn::Establish(mut setup) => {
                let session_id =
                    establish_case(matter, &crypto, fabric_idx, peer_node_id, transport)
                        .await
                        .inspect_err(|err| setup.fail(err))?;

                return Exchange::initiate_for_session(matter.transport(), crypto, session_id);
            }
        }

        // The handshake waited for succeeded, or its initiator gave it up
        // and there is no session yet.
        let existing = matter.with_sc_state(|state| {
            Ok::<_, Error>(
                state
                    .sessions
                    .get_for_node(fabric_idx, peer_node_id)
                    .map(|s| s.id),
            )
        })?;

        if let Some(session_id) = existing {
            return Exchange::initiate_for_session(matter.transport(), crypto, session_id);
        }
    }
}

/// Resolve the peer's operational address over mDNS and establish a CASE
/// session to it. Returns the ID of the new session.
#[cfg(not(feature = "case-responder-only"))]
async fn establish_case<M: ScHost, C: Crypto>(
    matter: &M,
    crypto: &C,
    fabric_idx: NonZeroU8,
    peer_node_id: NodeId,
    transport: TransportPreference,
) -> Result<u32, Error> {
    let compressed_fabric_id = matter.with_sc_state(|state| {
        Ok::<_, Error>(state.fabrics.fabric(fabric_idx)?.compressed_fabric_id())
    })?;

    let service = MatterRemoteService::Operational {
        compressed_fabric_id,
        node_id: peer_node_id,
    };

    let resolved = matter
        .transport()
        .resolve(service, Transport::RESOLVE_TIMEOUT_MS)
        .await?;

    // Establish CASE over a fresh, one-shot unsecured exchange to the
    // resolved address. On success a secure session keyed at
    // `(fabric_idx, peer_node_id)` is recorded in the stack.
    //
    // The candidates are walked in score order, because the best-scored address is not
    // necessarily the reachable one.
    // The peer's advertised TCP support is a veto, not a trigger: a caller
    // that asked for a large payload gets an error rather than a UDP session
    // that silently cannot carry it.
    if matches!(transport, TransportPreference::LargePayload) && !resolved.tcp_capable {
        error!(
            "Large-payload session requested for node {:?} but it does not advertise TCP server support",
            peer_node_id
        );
        return Err(ErrorCode::NoNetworkInterface.into());
    }

    let peer_mrp = PeerMrpParams {
        sii: resolved.sii,
        sai: resolved.sai,
        sat: resolved.sat,
    };

    let mut last_err = Some(Error::from(ErrorCode::NotFound));

    for addr in resolved.addrs.iter().copied() {
        let peer = match transport {
            TransportPreference::Mrp => Address::Udp(addr),
            TransportPreference::LargePayload => Address::Tcp(addr),
        };

        match Exchange::initiate_plaintext(matter.transport(), crypto, peer).await {
            Ok(exchange) => {
                match CaseInitiator::perform(
                    matter,
                    exchange,
                    crypto,
                    fabric_idx,
                    peer_node_id,
                    Some(&peer_mrp),
                )
                .await
                {
                    Ok(()) => {
                        last_err = None;
                        break;
                    }
                    Err(err) if err.is_peer_unresponsive() => {
                        warn!("CASE to {} failed: {}; trying the next address", peer, err);
                        last_err = Some(err);
                    }
                    Err(err) => {
                        // The peer answered and rejected us, so it is
                        // reachable at this address and every remaining
                        // candidate leads to the same node. Fail now rather
                        // than replaying the rejection against each one.
                        warn!("CASE to {} failed: {}", peer, err);
                        return Err(err);
                    }
                }
            }
            Err(err) => {
                warn!("Unsecured session to {} failed: {}", peer, err);
                last_err = Some(err);
            }
        }
    }

    if let Some(err) = last_err {
        return Err(err);
    }

    matter.with_sc_state(|state| {
        let session = state
            .sessions
            .get_for_node(fabric_idx, peer_node_id)
            .ok_or(ErrorCode::NoSession)?;

        Ok::<_, Error>(session.id)
    })
}

/// The `case-responder-only` variant: never establish a new CASE session.
///
/// See the other `initiate_new_case` for why this
/// exists. Reporting (and any other on-demand initiator) reuses an existing
/// session or gets [`ErrorCode::NoSession`]; nothing here references the CASE
/// initiator or the mDNS resolver, so the linker can drop them.
#[cfg(feature = "case-responder-only")]
async fn initiate_new_case<'a, M: ScHost, C: Crypto>(
    _matter: &'a M,
    _crypto: C,
    _fabric_idx: NonZeroU8,
    _peer_node_id: NodeId,
    _transport: TransportPreference,
) -> Result<Exchange<'a>, Error> {
    Err(ErrorCode::NoSession.into())
}
