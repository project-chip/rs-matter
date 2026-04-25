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

use core::fmt::{self, Display};
use core::ops::{Deref, DerefMut};
use core::pin::pin;

use embassy_futures::select::{select, select3, select4};
use embassy_time::Timer;

use rand_core::RngCore;

use crate::crypto::Crypto;
use crate::dm::clusters::basic_info::BasicInfoConfig;
use crate::error::{Error, ErrorCode};
use crate::fabric::{MAX_FABRICS, MAX_GROUPS_PER_FABRIC};
use crate::fmt::Bytes;
use crate::sc::{sc_write, OpCode, SCStatusCodes, StatusReport, PROTO_ID_SECURE_CHANNEL};
use crate::tlv::TLVElement;
use crate::transport::network::NetworkMulticast;
use crate::utils::init::{init, Init};
use crate::utils::ipv6::compute_group_multicast_addr;
use crate::utils::select::Coalesce;
use crate::utils::storage::Vec;
use crate::utils::storage::{pooled::BufferAccess, ParseBuf, WriteBuf};
use crate::utils::sync::{IfMutex, IfMutexGuard, Notification};
use crate::{Matter, MATTER_PORT};

use exchange::{Exchange, ExchangeId, ExchangeState, MessageMeta, ResponderState, Role};
use network::{Address, Ipv6Addr, NetworkReceive, NetworkSend, SocketAddr, SocketAddrV6};
use packet::PacketHdr;
use proto_hdr::ProtoHdr;
use session::{Session, Sessions};

mod dedup;

pub mod exchange;
pub mod mrp;
pub mod network;
pub mod packet;
pub mod plain_hdr;
pub mod proto_hdr;
pub mod session;

pub const MATTER_SOCKET_BIND_ADDR: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MATTER_PORT, 0, 0));

const MAX_GROUP_ADDRS: usize = MAX_FABRICS * MAX_GROUPS_PER_FABRIC;

const ACCEPT_TIMEOUT_MS: u64 = 1000;

#[cfg(feature = "large-buffers")]
pub(crate) const MAX_RX_BUF_SIZE: usize = network::MAX_RX_LARGE_PACKET_SIZE;
#[cfg(feature = "large-buffers")]
pub(crate) const MAX_TX_BUF_SIZE: usize = network::MAX_TX_LARGE_PACKET_SIZE;

#[cfg(not(feature = "large-buffers"))]
pub(crate) const MAX_RX_BUF_SIZE: usize = network::MAX_RX_PACKET_SIZE;
#[cfg(not(feature = "large-buffers"))]
pub(crate) const MAX_TX_BUF_SIZE: usize = network::MAX_TX_PACKET_SIZE;

/// Represents the state of the transport layer of a `Matter` instance.
pub struct Transport {
    /// Buffer for an incoming (RX) packet.
    // TODO XXX FIXME: Needs multiple wakers for work-stealing executors
    rx: IfMutex<Packet<MAX_RX_BUF_SIZE>>,
    /// Buffer for an outgoing (TX) packet.
    // TODO XXX FIXME: Needs multiple wakers for work-stealing executors
    tx: IfMutex<Packet<MAX_TX_BUF_SIZE>>,
    /// List of currently joined group addresses, used for managing multicast group membership.
    group_addrs: IfMutex<Vec<Ipv6Addr, MAX_GROUP_ADDRS>>,
    /// Notification for when an exchange is dropped.
    exchange_dropped: Notification,
    /// Device SAI (Secure Association Identifier)
    device_sai: Option<u16>,
    /// Device SII (Secure Identity Identifier)
    device_sii: Option<u16>,
}

impl Transport {
    /// Create a new `Transport` with empty RX and TX buffers, and the given device SAI/SII.
    #[inline(always)]
    pub(crate) const fn new(dev_det: &BasicInfoConfig<'_>) -> Self {
        Self {
            rx: IfMutex::new(Packet::new()),
            tx: IfMutex::new(Packet::new()),
            group_addrs: IfMutex::new(Vec::new()),
            exchange_dropped: Notification::new(),
            device_sai: dev_det.sai,
            device_sii: dev_det.sii,
        }
    }

    /// Initialize the transport state by initializing the RX and TX buffers, and setting up the exchange dropped notification.
    pub(crate) fn init<'m>(dev_det: &'m BasicInfoConfig<'m>) -> impl Init<Self> + 'm {
        init!(Self {
            rx <- IfMutex::init(Packet::init()),
            tx <- IfMutex::init(Packet::init()),
            group_addrs <- IfMutex::init(Vec::new()),
            exchange_dropped: Notification::new(),
            device_sai: dev_det.sai,
            device_sii: dev_det.sii,
        })
    }

    /// Reset the transport state by clearing the RX buffer and the TX buffer
    /// NOTE: User should be careful _not_ to call this method while the transport layer and/or the built-in mDNS is running.
    pub fn reset(&self) -> Result<(), Error> {
        self.rx
            .try_lock()
            .map_err(|_| ErrorCode::InvalidState)?
            .buf
            .clear();
        self.tx
            .try_lock()
            .map_err(|_| ErrorCode::InvalidState)?
            .buf
            .clear();

        Ok(())
    }

    /// Return a reference to the transport RX buffer.
    ///
    /// Useful when external code (like i.e. a user-provided mDNS implementation)
    /// needs an RX buffer.
    pub fn rx_buffer(&self) -> PacketBufferExternalAccess<'_, MAX_RX_BUF_SIZE> {
        PacketBufferExternalAccess(&self.rx)
    }

    /// Return a reference to the transport TX buffer.
    ///
    /// Useful when external code (like i.e. a user-provided mDNS implementation)
    /// needs a TX buffer.
    pub fn tx_buffer(&self) -> PacketBufferExternalAccess<'_, MAX_TX_BUF_SIZE> {
        PacketBufferExternalAccess(&self.tx)
    }

    pub(crate) async fn accept_if<'a, F>(
        &self,
        matter: &'a Matter<'a>,
        mut f: F,
    ) -> Result<Exchange<'a>, Error>
    where
        F: FnMut(&Session, &ExchangeState, &Packet<MAX_RX_BUF_SIZE>) -> bool,
    {
        let exchange = self
            .rx
            .with(|packet| {
                matter.with_state(|state| {
                    let session = state
                        .sessions
                        .get_for_rx(&packet.peer, &packet.header.plain)?;
                    let exch_index = session.get_exch_for_rx(&packet.header.proto)?;

                    let matches = {
                        // `unwrap` is safe because the transport code is single threaded, and since we don't `await`
                        // after computing `exch_index` no code can remove the exchange from the session
                        let exch = unwrap!(session.exchanges[exch_index].as_ref());

                        matches!(exch.role, Role::Responder(ResponderState::AcceptPending))
                            && f(session, exch, packet)
                    };

                    if !matches {
                        return None;
                    }

                    // `unwrap` is safe because the transport code is single threaded, and since we don't `await`
                    // after computing `exch_index` no code can remove the exchange from the session
                    let exch = unwrap!(session.exchanges[exch_index].as_mut());

                    exch.role = Role::Responder(ResponderState::Owned);

                    let id = ExchangeId::new(session.id, exch_index);

                    debug!("Exchange {}: Accepted", id.display(session));

                    let exchange = Exchange::new(id, matter);

                    Some(exchange)
                })
            })
            .await;

        Ok(exchange)
    }

    pub(crate) async fn initiate<'a>(
        &self,
        matter: &'a Matter<'a>,
        fabric_idx: u8,
        peer_node_id: u64,
        secure: bool,
    ) -> Result<Exchange<'a>, Error> {
        // TODO: Future: once we have mDNS lookups in place
        // create a new session if no suitable one is found

        let session_id = matter.with_state(|state| {
            // (block necessary, or else we end up re-borrowing `Sessions` as mut twice)

            Ok::<_, ErrorCode>(
                state
                    .sessions
                    .get_for_node(fabric_idx, peer_node_id, secure)
                    .ok_or(ErrorCode::NoSession)?
                    .id,
            )
        })?;

        self.initiate_for_session(matter, session_id)
    }

    pub(crate) fn initiate_for_session<'a>(
        &self,
        matter: &'a Matter<'a>,
        session_id: u32,
    ) -> Result<Exchange<'a>, Error> {
        matter.with_state(|state| {
            state
                .sessions
                .get(session_id)
                // Expired sessions are not allowed to initiate new exchanges
                .filter(|sess| !sess.is_expired())
                .ok_or(ErrorCode::NoSession)?;

            let exch_id = state.sessions.get_next_exch_id();

            // `unwrap` is safe because we know we have a session or else the early return from above would've triggered
            // The reason why we call `get_for_node` twice is to ensure that we don't waste an `exch_id` in case
            // we don't have a session in the first place
            let session = unwrap!(state.sessions.get(session_id));

            let exch_index = session
                .add_exch(exch_id, Role::Initiator(Default::default()))
                .ok_or(ErrorCode::NoSpaceExchanges)?;

            let id = ExchangeId::new(session.id, exch_index);

            debug!("Exchange {}: Initiated", id.display(session));

            Ok(Exchange::new(id, matter))
        })
    }

    /// Create a new unsecured (plain-text) session to a given peer address.
    ///
    /// Returns the internal session ID that can be used with `initiate_for_session()`.
    ///
    /// This is the low-level building block for controller-initiated communication
    /// (e.g. PASE/CASE initiator flows), analogous to the SDK's
    /// `SessionManager::CreateUnauthenticatedSession()`.
    pub(crate) fn create_unsecured_session<C: Crypto>(
        &self,
        matter: &Matter<'_>,
        crypto: C,
        peer_addr: Address,
    ) -> Result<u32, Error> {
        matter.with_state(|state| {
            let mut rand = crypto.rand()?;

            let session = state
                .sessions
                .add(rand.next_u32(), false, peer_addr, None)?;

            // Generate ephemeral initiator node ID per spec 4.13.2.1:
            // "Randomly selected for each session by the initiator from the Operational Node ID range"
            // Operational Node ID range is 0x0000_0000_0000_0001 to 0xFFFF_FFEF_FFFF_FFFF
            // (spec Table 4, Section 2.5.5).
            const MAX_OPERATIONAL_NODE_ID: u64 = 0xFFFF_FFEF_FFFF_FFFF;
            let mut ephemeral_id = rand.next_u64();
            while ephemeral_id == 0 || ephemeral_id > MAX_OPERATIONAL_NODE_ID {
                ephemeral_id = rand.next_u64();
            }
            session.set_local_nodeid(ephemeral_id);

            let session_id = session.id;

            debug!(
                "Unsecured session {} created for peer {}",
                session_id, peer_addr
            );

            Ok(session_id)
        })
    }

    /// Create a new unsecured session and initiate an exchange on it in one step.
    ///
    /// This is a convenience method that combines `create_unsecured_session()` and
    /// `initiate_for_session()`. Fails immediately if there is no space for a new session.
    ///
    /// For flows that need the session ID (e.g. to upgrade the session after PASE/CASE),
    /// use `create_unsecured_session()` + `initiate_for_session()` separately.
    pub(crate) fn initiate_unsecured_now<'a, C: Crypto>(
        &self,
        matter: &'a Matter<'a>,
        crypto: C,
        peer_addr: Address,
    ) -> Result<Exchange<'a>, Error> {
        let session_id = self.create_unsecured_session(matter, crypto, peer_addr)?;

        matter.transport.initiate_for_session(matter, session_id)
    }

    pub(crate) async fn get_if_rx<F>(&self, f: F) -> PacketAccess<'_, MAX_RX_BUF_SIZE>
    where
        F: Fn(&Packet<MAX_RX_BUF_SIZE>) -> bool,
    {
        Self::get_if(&self.rx, f).await
    }

    pub(crate) async fn get_if_tx<F>(&self, f: F) -> PacketAccess<'_, MAX_TX_BUF_SIZE>
    where
        F: Fn(&Packet<MAX_TX_BUF_SIZE>) -> bool,
    {
        Self::get_if(&self.tx, f).await
    }

    async fn get_if<'b, F, const N: usize>(
        packet_mutex: &'b IfMutex<Packet<N>>,
        f: F,
    ) -> PacketAccess<'b, N>
    where
        F: Fn(&Packet<N>) -> bool,
    {
        PacketAccess(packet_mutex.lock_if(f).await, false)
    }
}

/// The Matter Transport Runner, responsible for running the network transport by processing incoming and ougoing packets
/// and thus also managing sessions and exchanges.
///
/// The transport runner is wrapping the whole Matter Object, because it needs access to various states, like
/// sessions, fabrics and the transport buffers / state itself.
pub struct TransportRunner<'a, C> {
    matter: &'a Matter<'a>,
    crypto: C,
}

impl<'a, C: Crypto> TransportRunner<'a, C> {
    /// Create a new `TransportRunner` instance with the given `Matter` instance and `Crypto` implementation.
    pub const fn new(matter: &'a Matter<'a>, crypto: C) -> Self {
        Self { matter, crypto }
    }

    /// Run the transport runner with the given network send, receive and multicast implementations.
    pub async fn run<S, R, M>(&mut self, send: S, recv: R, multicast: M) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
        M: NetworkMulticast,
    {
        info!("Running Matter transport");

        // Do not remove this logging line or change its formatting.
        // C++ E2E tests rely on this log line to determine when the tested app is ready
        debug!("APP STATUS: Starting event loop");

        let mut joined = self.matter.transport.group_addrs.lock().await;

        let send = IfMutex::new(send);

        let mut rx = pin!(self.process_rx(recv, &send));
        let mut tx = pin!(self.process_tx(&send));
        let mut orphaned = pin!(self.process_orphaned());
        let mut groups = pin!(self.process_groups(multicast, &mut joined));

        select4(&mut rx, &mut tx, &mut orphaned, &mut groups)
            .coalesce()
            .await
    }

    async fn process_groups<M>(
        &self,
        mut multicast: M,
        joined: &mut Vec<Ipv6Addr, MAX_GROUP_ADDRS>,
    ) -> Result<(), Error>
    where
        M: NetworkMulticast,
    {
        joined.clear();

        loop {
            let addr_op = self.matter.with_state(|state| {
                let group_addrs = || {
                    state.fabrics.iter().flat_map(|fabric| {
                        fabric.groups().iter().map(|group| {
                            compute_group_multicast_addr(fabric.fabric_id(), group.group_id)
                        })
                    })
                };

                if let Some(new_addr) = group_addrs().find(|addr| !joined.contains(addr)) {
                    Some((new_addr, true))
                } else {
                    joined
                        .iter()
                        .find(|addr| !group_addrs().any(|a| a == **addr))
                        .map(|&removed_addr| (removed_addr, false))
                }
            });

            match addr_op {
                Some((new_addr, true)) => {
                    match multicast.join(new_addr.into()).await {
                        Ok(_) => {
                            debug!("Joined multicast group: {}", new_addr);
                            // `joined` should be able to contain theoretical maximum number of multicast address
                            // So this unwrap should be safe
                            unwrap!(joined.push(new_addr));
                        }
                        Err(e) => error!(
                            "Joining multicast group {} failed with error: {}",
                            new_addr, e
                        ),
                    }
                }
                Some((removed_addr, false)) => match multicast.leave(removed_addr.into()).await {
                    Ok(_) => {
                        debug!("Left multicast group: {}", removed_addr);
                        let index = joined
                            .iter()
                            .position(|&addr| addr == removed_addr)
                            .unwrap();
                        joined.swap_remove(index);
                    }
                    Err(e) => error!(
                        "Leaving multicast group {} failed with error: {}",
                        removed_addr, e
                    ),
                },
                None => {
                    self.matter.groups_modified.wait().await;
                }
            }
        }
    }

    async fn process_tx<S>(&self, send: &IfMutex<S>) -> Result<(), Error>
    where
        S: NetworkSend,
    {
        loop {
            trace!("Waiting for outgoing packet");

            let mut tx = self
                .matter
                .transport
                .get_if_tx(|packet| !packet.buf.is_empty())
                .await;
            tx.clear_on_drop(true);

            if let TxPayloadState::NotEncoded { session_id } = tx.tx_info.payload_state {
                let encoded = self.matter.with_state(|state| {
                    if let Some(session) = state.sessions.get_for_tx(session_id) {
                        self.encode_packet(&mut tx, Some(session))?;

                        Ok::<_, Error>(true)
                    } else {
                        error!(
                            "TX packet has session ID {}, but no such session exists, dropping",
                            session_id
                        );

                        Ok(false)
                    }
                })?;

                if !encoded {
                    continue;
                }
            }

            Self::netw_send(send, tx.peer, &tx.buf[tx.payload_start..], false).await?;
        }
    }

    async fn process_rx<R, S>(&self, mut recv: R, send: &IfMutex<S>) -> Result<(), Error>
    where
        R: NetworkReceive,
        S: NetworkSend,
    {
        loop {
            trace!("Waiting for incoming packet");

            recv.wait_available().await?;

            let mut rx = self
                .matter
                .transport
                .get_if_rx(|packet| packet.buf.is_empty())
                .await;
            rx.clear_on_drop(true); // In case of error, or if the future is dropped

            // TODO: Resizing might be a bit expensive with large buffers
            // Resizing to `MAX_RX_BUF_SIZE` is always safe because the size of the `buf` heapless vec `MAX_RX_BUF_SIZE`
            unwrap!(rx.buf.resize_default(MAX_RX_BUF_SIZE));

            let (len, peer) = Self::netw_recv(&mut recv, &mut rx.buf).await?;

            rx.peer = peer;
            rx.buf.truncate(len);
            rx.payload_start = 0;

            match self.handle_rx_packet(&mut rx, send).await {
                Ok(true) => {
                    // Leave the packet in place for accepting by responders
                    rx.clear_on_drop(false);
                }
                Ok(false) => {
                    // Drop the packet, as no further processing is necessary
                }
                Err(e) => {
                    // Drop the packet and report the unexpected error
                    error!("UNEXPECTED RX ERROR: {:?}", e);
                }
            }
        }
    }

    async fn process_orphaned(&self) -> Result<(), Error> {
        let mut rx_accept_timeout = pin!(self.process_accept_timeout_rx());
        let mut rx_orphaned = pin!(self.process_orphaned_rx());
        let mut exch_dropped = pin!(self.process_dropped_exchanges());

        select3(&mut rx_accept_timeout, &mut rx_orphaned, &mut exch_dropped)
            .coalesce()
            .await
    }

    async fn process_accept_timeout_rx(&self) -> Result<(), Error> {
        loop {
            trace!("Waiting for accept timeout");

            let mut accept_timeout = pin!(self
                .matter
                .transport
                .rx
                .with(|packet| { self.handle_accept_timeout_rx_packet(packet).then_some(()) }));

            let mut timer = pin!(Timer::after(embassy_time::Duration::from_millis(50)));

            select(&mut accept_timeout, &mut timer).await;
        }
    }

    async fn process_orphaned_rx(&self) -> Result<(), Error> {
        loop {
            trace!("Waiting for orphaned RX packets");

            self.matter
                .transport
                .rx
                .with(|packet| self.handle_orphaned_rx_packet(packet).then_some(()))
                .await;
        }
    }

    async fn process_dropped_exchanges(&self) -> Result<(), Error> {
        loop {
            trace!("Waiting for dropped exchanges");

            let mut tx = self
                .matter
                .transport
                .get_if_tx(|packet| packet.buf.is_empty())
                .await;
            tx.clear_on_drop(true); // In case of error, or if the future is dropped

            let wait = match self.handle_dropped_exchange(&mut tx) {
                Ok(wait) => {
                    tx.clear_on_drop(false);
                    wait
                }
                Err(e) => {
                    error!("UNEXPECTED RX ERROR: {:?}", e);
                    false
                }
            };

            drop(tx);

            if wait {
                let mut timeout = pin!(Timer::after(embassy_time::Duration::from_millis(100)));
                let mut wait = pin!(self.matter.transport.exchange_dropped.wait());

                select(&mut timeout, &mut wait).await;
            }
        }
    }

    async fn handle_rx_packet<const N: usize, S>(
        &self,
        packet: &mut Packet<N>,
        send: &IfMutex<S>,
    ) -> Result<bool, Error>
    where
        S: NetworkSend,
    {
        let result = self.decode_packet(packet);
        match result {
            Err(e) if matches!(e.code(), ErrorCode::Duplicate) => {
                if packet.header.plain.is_group_session() {
                    // Group messages are multicast and don't use MRP; silently discard duplicates
                    debug!(
                        "\n>>RCV {}\n      => Duplicate group message, discarding",
                        packet
                    );
                } else if !packet.peer.is_reliable()
                    && !MessageMeta::from(&packet.header.proto).is_standalone_ack()
                {
                    debug!("\n>>RCV {}\n      => Duplicate, sending ACK", packet);

                    self.matter.with_state(|state| {
                        // `unwrap` is safe because we know we have a session.
                        // If we didn't have a session, the error code would've been `NoSession`
                        //
                        // Also, since the transport code is single threaded, and since we don't `await`
                        // after decoding the packet, no code can the session
                        let session = unwrap!(state
                            .sessions
                            .get_for_rx(&packet.peer, &packet.header.plain));

                        let ack = packet.header.plain.ctr;

                        packet.header.proto.toggle_initiator();
                        packet.header.proto.set_ack(Some(ack));

                        self.write_packet(packet, Some(session), None, true, |_| {
                            Ok(Some(OpCode::MRPStandAloneAck.into()))
                        })
                    })?;

                    Self::netw_send(send, packet.peer, &packet.buf[packet.payload_start..], true)
                        .await?;
                } else {
                    debug!("\n>>RCV {}\n      => Duplicate, discarding", packet);
                }
            }
            Err(e) if matches!(e.code(), ErrorCode::NoSpaceSessions) => {
                if !packet.header.plain.is_encrypted()
                    && MessageMeta::from(&packet.header.proto).is_new_session()
                {
                    warn!(
                        "\n>>RCV {}\n      => No space for a new unencrypted session, sending Busy",
                        packet
                    );

                    let ack = packet.header.plain.ctr;

                    packet.header.proto.toggle_initiator();
                    packet.header.proto.set_ack(Some(ack));

                    self.write_packet(packet, None, None, true, |wb| {
                        sc_write(wb, SCStatusCodes::Busy, &[0xF4, 0x01])
                    })?;

                    Self::netw_send(send, packet.peer, &packet.buf[packet.payload_start..], true)
                        .await?;

                    if self.write_evict_some_session_packet(packet, true)? {
                        Self::netw_send(
                            send,
                            packet.peer,
                            &packet.buf[packet.payload_start..],
                            true,
                        )
                        .await?;
                    }
                } else {
                    error!(
                        "\n>>RCV {}\n      => No space for a new encrypted session, dropping",
                        packet
                    );
                }
            }
            Err(e) if matches!(e.code(), ErrorCode::NoSpaceExchanges) => {
                // TODO: Before closing the session, try to take other measures:
                // - For CASESigma1 & PBKDFParamRequest - send Busy instead
                // - For Interaction Model interactions that do need an ACK - send IM Busy,
                //   wait for ACK and retransmit without releasing the RX buffer, potentially
                //   blocking all other interactions

                error!(
                    "\n>>RCV {}\n      => No space for a new exchange, closing session",
                    packet
                );

                self.matter.with_state(|state| {
                    // `unwrap` is safe because we know we have a session.
                    // If we didn't have a session, the error code would've been `NoSession`
                    //
                    // Also, since the transport code is single threaded, and since we don't `await`
                    // after decoding the packet, no code can the session
                    let session_id = unwrap!(state
                        .sessions
                        .get_for_rx(&packet.peer, &packet.header.plain))
                    .id;

                    packet.header.proto.exch_id = state.sessions.get_next_exch_id();
                    packet.header.proto.set_initiator();

                    // See above why `unwrap` is safe
                    let mut session = unwrap!(state.sessions.remove(session_id));
                    self.matter.session_removed.notify();

                    self.write_packet(packet, Some(&mut session), None, true, |wb| {
                        sc_write(wb, SCStatusCodes::CloseSession, &[])
                    })
                })?;

                Self::netw_send(send, packet.peer, &packet.buf[packet.payload_start..], true)
                    .await?;
            }
            Err(e) if matches!(e.code(), ErrorCode::NoExchange) => {
                warn!(
                    "\n>>RCV {}\n      => No valid exchange found, dropping",
                    packet
                );
            }
            Err(e) if matches!(e.code(), ErrorCode::NoSession) => {
                warn!(
                    "\n>>RCV {}\n      => No valid session found, dropping",
                    packet
                );
            }
            Err(e) => {
                error!("\n>>RCV {}\n      => Error ({:?}), dropping", packet, e);
            }
            Ok(new_exchange) => {
                let meta = MessageMeta::from(&packet.header.proto);

                if meta.is_standalone_ack() {
                    // No need to propagate this further
                    debug!("\n>>RCV {}\n      => Standalone Ack, dropping", packet);
                } else if meta.is_sc_status()
                    && matches!(
                        Self::is_close_session(&mut packet.buf[packet.payload_start..]),
                        Ok(true)
                    )
                {
                    warn!(
                        "\n>>RCV {}\n      => Close session received, removing this session",
                        packet
                    );

                    self.matter.with_state(|state| {
                        if let Some(session_id) = state
                            .sessions
                            .get_for_rx(&packet.peer, &packet.header.plain)
                            .map(|sess| sess.id)
                        {
                            state.sessions.remove(session_id);
                            self.matter.session_removed.notify();
                        }
                    });
                } else {
                    debug!(
                        "\n>>RCV {}\n      => Processing{}",
                        packet,
                        if new_exchange { " (new exchange)" } else { "" }
                    );

                    #[cfg(feature = "debug-tlv-payload")]
                    debug!(
                        "{}",
                        Packet::<0>::display_payload(
                            &packet.header.proto,
                            &packet.buf[core::cmp::min(packet.payload_start, packet.buf.len())..]
                        )
                    );

                    #[cfg(not(feature = "debug-tlv-payload"))]
                    trace!(
                        "{}",
                        Packet::<0>::display_payload(
                            &packet.header.proto,
                            &packet.buf[core::cmp::min(packet.payload_start, packet.buf.len())..]
                        )
                    );

                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn handle_accept_timeout_rx_packet<const N: usize>(&self, packet: &mut Packet<N>) -> bool {
        if packet.buf.is_empty() {
            return false;
        }

        self.matter.with_state(|state| {
            let epoch = state.sessions.epoch;

            let Some(session) = state
                .sessions
                .get_for_rx(&packet.peer, &packet.header.plain)
            else {
                return false;
            };

            let Some(exch_index) = session.get_exch_for_rx(&packet.header.proto) else {
                return false;
            };

            // `unwrap` is safe because we know we have a session and an exchange, or else the early returns from above would've triggered
            let exchange = unwrap!(session.exchanges[exch_index].as_mut());

            if !matches!(
                exchange.role,
                Role::Responder(ResponderState::AcceptPending)
            ) || !exchange.mrp.has_rx_timed_out(ACCEPT_TIMEOUT_MS, epoch)
            {
                return false;
            }

            warn!(
                "\n>>RCV {}\n => Accept timeout, marking exchange as dropped",
                packet
            );

            exchange.role = Role::Responder(ResponderState::Dropped);
            packet.buf.clear();
            self.matter.transport.exchange_dropped.notify();

            true
        })
    }

    fn handle_orphaned_rx_packet<const N: usize>(&self, packet: &mut Packet<N>) -> bool {
        if packet.buf.is_empty() {
            return false;
        }

        self.matter.with_state(|state| {
            let Some(session) = state
                .sessions
                .get_for_rx(&packet.peer, &packet.header.plain)
            else {
                warn!("\n>>RCV {}\n => No session, dropping", packet);

                packet.buf.clear();
                return true;
            };

            let Some(exch_index) = session.get_exch_for_rx(&packet.header.proto) else {
                warn!("\n>>RCV {}\n => No exchange, dropping", packet);

                packet.buf.clear();
                return true;
            };

            // `unwrap` is safe because we know we have a session and an exchange, or else the early returns from above would've triggered
            let exchange = unwrap!(session.exchanges[exch_index].as_mut());

            if exchange.role.is_dropped_state() {
                warn!(
                    "\n>>RCV {}\n => Owned by orphaned dropped {}, dropping packet",
                    packet,
                    ExchangeId::new(session.id, exch_index)
                );

                packet.buf.clear();
                return true;
            }

            false
        })
    }

    fn handle_dropped_exchange<const N: usize>(
        &self,
        packet: &mut Packet<N>,
    ) -> Result<bool, Error> {
        self.matter.with_state(|state| {
            let exch = state
                .sessions
                .get_exch(|_, exch| exch.role.is_dropped_state() && exch.mrp.is_retrans_pending())
                .map(|(sess, exch_index)| (sess.id, exch_index, true))
                .or_else(|| {
                    state
                        .sessions
                        .get_exch(|_, exch| {
                            exch.role.is_dropped_state() && !exch.mrp.is_retrans_pending()
                        })
                        .map(|(sess, exch_index)| (sess.id, exch_index, false))
                });

            let Some((session_id, exch_index, close_session)) = exch else {
                return Ok(exch.is_none());
            };

            let exchange_id = ExchangeId::new(session_id, exch_index);

            if close_session {
                // Found a dropped exchange which has an incomplete (re)transmission
                // Close the whole session

                error!(
                    "Dropped exchange {}: Closing session because the exchange cannot be closed cleanly",
                    exchange_id.display(unwrap!(state.sessions.get(session_id))) // Session exists or else we wouldn't be here
                );

                self.write_evict_session_packet(packet, &mut state.sessions, &self.matter.session_removed, session_id, false)?;
            } else {
                // Found a dropped exchange which has no outstanding (re)transmission
                // Send a standalone ACK if necessary and then close it

                // `unwrap` is safe because we know we have a session and an exchange, or else the early returns from above would've triggered
                let session = unwrap!(state.sessions.get(session_id));
                // Ditto
                let exchange = unwrap!(session.exchanges[exch_index].as_mut());

                if exchange.mrp.is_ack_pending() {
                    self.write_packet(
                        packet,
                        Some(session),
                        Some(exch_index),
                        false,
                        |_| Ok(Some(OpCode::MRPStandAloneAck.into())),
                    )?;
                }

                warn!("Dropped exchange {}: Closed", exchange_id.display(session));
                session.exchanges[exch_index] = None;
            }

            Ok(exch.is_none())
        })
    }

    pub(crate) async fn evict_some_session(&self) -> Result<(), Error> {
        let mut tx = self
            .matter
            .transport
            .get_if_tx(|packet| packet.buf.is_empty())
            .await;
        tx.clear_on_drop(true); // By default, if an error occurs

        let evicted = self.write_evict_some_session_packet(&mut tx, true)?;

        if evicted {
            // Send it
            tx.clear_on_drop(false);

            Ok(())
        } else {
            Err(ErrorCode::NoSpaceSessions.into())
        }
    }

    fn decode_packet<const N: usize>(&self, packet: &mut Packet<N>) -> Result<bool, Error> {
        self.matter.with_state(|state| {
            packet.header.reset();

            let mut pb = ParseBuf::new(&mut packet.buf[packet.payload_start..]);
            packet.header.plain.decode(&mut pb)?;

            let epoch = state.sessions.epoch;

            let set_payload = |packet: &mut Packet<N>, (start, end)| {
                packet.payload_start = start;
                packet.buf.truncate(end);
            };

            if let Some(session) = state
                .sessions
                .get_for_rx(&packet.peer, &packet.header.plain)
            {
                // Found existing session: decode, indicate packet payload slice and process further

                let payload_range =
                    session.decode_remaining(&self.crypto, &mut packet.header, pb)?;
                set_payload(packet, payload_range);

                return session.post_recv(&packet.header, epoch);
            }

            // No existing session: we either have to create one, or return an error

            if !packet.header.plain.is_encrypted() {
                // Unencrypted packets can be decoded without a session, and we need to anyway do that
                // in order to determine (based on proto hdr data) whether to create a new session or not
                packet
                    .header
                    .decode_remaining(&self.crypto, None, 0, &mut pb)?;
                packet.header.proto.adjust_reliability(true, &packet.peer);

                let payload_range = pb.slice_range();
                set_payload(packet, payload_range);

                if MessageMeta::from(&packet.header.proto).is_new_session() {
                    // As per spec, new unencrypted sessions are only created for
                    // `PBKDFParamRequest` or `CASESigma1` unencrypted messages

                    let mut rand = self.crypto.rand()?;

                    let session = state.sessions.add(
                        rand.next_u32(),
                        false,
                        packet.peer,
                        packet.header.plain.get_src_nodeid(),
                    )?;

                    // Session created successfully: decode, indicate packet payload slice and process further
                    return session.post_recv(&packet.header, epoch);
                }
            } else if packet.header.plain.is_group_session() {
                // Group (multicast) message — derive keys on-the-fly and decrypt
                let (session, payload_range) = state.sessions.get_or_create_for_group_rx(
                    &self.crypto,
                    &state.fabrics,
                    packet,
                )?;
                set_payload(packet, payload_range);

                return session.post_recv(&packet.header, epoch);
            } else {
                // Encrypted unicast packet with no matching session — cannot be decoded
                set_payload(packet, (0, 0));
            }

            Err(ErrorCode::NoSession.into())
        })
    }

    fn encode_packet<const N: usize>(
        &self,
        packet: &mut Packet<N>,
        session: Option<&mut Session>,
    ) -> Result<(), Error> {
        assert!(matches!(
            packet.tx_info.payload_state,
            TxPayloadState::NotEncoded { .. }
        ));

        let payload_end = packet.buf.len();

        debug!(
            "\n<<SND {}\n      => {}",
            Packet::<0>::display(&packet.peer, &packet.header),
            if packet.tx_info.retransmission {
                "Re-sending"
            } else {
                "Sending"
            }
        );

        #[cfg(feature = "debug-tlv-payload")]
        debug!(
            "{}",
            Packet::<0>::display_payload(
                &packet.header.proto,
                &packet.buf[packet.payload_start..payload_end]
            )
        );

        #[cfg(not(feature = "debug-tlv-payload"))]
        trace!(
            "{}",
            Packet::<0>::display_payload(
                &packet.header.proto,
                &packet.buf[packet.payload_start..payload_end]
            )
        );

        unwrap!(packet.buf.resize_default(N));

        let mut wb = WriteBuf::new_with(&mut packet.buf, packet.payload_start, payload_end);
        if let Some(session) = session {
            session.encode(&self.crypto, &packet.header, &mut wb)?;
        } else {
            packet.header.encode(&self.crypto, None, 0, &mut wb)?;
        }

        let encoded_payload_start = wb.get_start();
        let encoded_payload_end = wb.get_tail();

        packet.payload_start = encoded_payload_start;
        packet.tx_info.payload_state = TxPayloadState::Encoded;
        packet.buf.truncate(encoded_payload_end);

        Ok(())
    }

    fn write_packet<const N: usize, F>(
        &self,
        packet: &mut Packet<N>,
        mut session: Option<&mut Session>,
        exchange_index: Option<usize>,
        encode: bool,
        payload_writer: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut WriteBuf) -> Result<Option<MessageMeta>, Error>,
    {
        // TODO: Resizing might be a bit expensive with large buffers
        // Resizing to `N` is always safe because it is a responsibility of the caller to ensure that N is <= `MAX_RX_BUF_SIZE`,
        // which is the size of `buf` heapless vec
        unwrap!(packet.buf.resize_default(N));

        let mut wb = WriteBuf::new_with(
            &mut packet.buf,
            PacketHdr::HDR_RESERVE,
            PacketHdr::HDR_RESERVE,
        );

        let Some(meta) = payload_writer(&mut wb)? else {
            packet.buf.clear();
            return Ok(());
        };

        let (start, end) = (wb.get_start(), wb.get_tail());

        packet.payload_start = start;
        packet.buf.truncate(end);

        meta.set_into(&mut packet.header.proto);

        if let Some(session) = &mut session {
            packet.header.plain = Default::default();

            let (peer, retransmission) = session.pre_send(
                exchange_index,
                &mut packet.header,
                self.matter.transport.device_sai,
                self.matter.transport.device_sii,
            )?;

            packet.peer = peer;
            packet.tx_info.retransmission = retransmission;
            packet.tx_info.payload_state = TxPayloadState::NotEncoded {
                session_id: session.id,
            };
        } else {
            if packet.header.plain.is_encrypted()
                || packet.header.plain.get_src_nodeid().is_none()
                || packet.header.proto.is_reliable()
            {
                // We can encode packets without a session only when they are unencrypted and do not need a retransmission
                Err(ErrorCode::NoSession)?;
            }

            let src_nodeid = packet.header.plain.get_src_nodeid();

            packet.header.plain = Default::default();

            packet.header.plain.sess_id = 0;
            packet.header.plain.ctr = 1;
            packet.header.plain.set_src_nodeid(None);
            packet.header.plain.set_dst_unicast_nodeid(src_nodeid);

            packet.header.proto.unset_initiator();
            packet.header.proto.adjust_reliability(false, &packet.peer);

            packet.tx_info.retransmission = false;
            packet.tx_info.payload_state = TxPayloadState::NotEncoded { session_id: 0 };
        }

        if encode {
            self.encode_packet(packet, session)?;
        }

        Ok(())
    }

    fn write_evict_some_session_packet<const N: usize>(
        &self,
        packet: &mut Packet<N>,
        encode: bool,
    ) -> Result<bool, Error> {
        self.matter.with_state(|state| {
            let id = state
                .sessions
                .get_session_for_eviction()
                .map(|sess| sess.id);
            if let Some(id) = id {
                self.write_evict_session_packet(
                    packet,
                    &mut state.sessions,
                    &self.matter.session_removed,
                    id,
                    encode,
                )?;

                Ok(true)
            } else {
                error!("All sessions have active exchanges, cannot evict any session");

                Ok(false)
            }
        })
    }

    fn write_evict_session_packet<const N: usize>(
        &self,
        packet: &mut Packet<N>,
        sessions: &mut Sessions,
        session_removed: &Notification,
        id: u32,
        encode: bool,
    ) -> Result<(), Error> {
        packet.header.proto.exch_id = sessions.get_next_exch_id();
        packet.header.proto.set_initiator();

        // It is a responsibility of the caller to ensure that this method is called with a valid session ID
        let mut session = unwrap!(sessions.remove(id));
        session_removed.notify();

        debug!(
            "Evicting session {} [SID:{:x},RSID:{:x}]",
            session.id,
            session.get_local_sess_id(),
            session.get_peer_sess_id()
        );

        self.write_packet(packet, Some(&mut session), None, encode, |wb| {
            sc_write(wb, SCStatusCodes::CloseSession, &[])
        })?;

        Ok(())
    }

    fn is_close_session(payload: &mut [u8]) -> Result<bool, Error> {
        let mut pb = ParseBuf::new(payload);
        let report = StatusReport::read(&mut pb)?;

        let close_session = report.proto_id == PROTO_ID_SECURE_CHANNEL as u32
            && report.proto_code == SCStatusCodes::CloseSession as u16;

        Ok(close_session)
    }

    async fn netw_recv<R>(mut recv: R, buf: &mut [u8]) -> Result<(usize, Address), Error>
    where
        R: NetworkReceive,
    {
        match recv.recv_from(buf).await {
            Ok((len, addr)) => {
                trace!("\n>>RCV {} {}B:\n     {}", addr, len, Bytes(&buf[..len]));

                Ok((len, addr))
            }
            Err(e) => {
                error!("FAILED network recv: {:?}", e);

                Err(e)
            }
        }
    }

    async fn netw_send<S>(
        send: &IfMutex<S>,
        peer: Address,
        data: &[u8],
        system: bool,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
    {
        match send.lock().await.send_to(data, peer).await {
            Ok(_) => {
                trace!(
                    "\n<<SND {} {}B{}: {}",
                    peer,
                    data.len(),
                    if system { " (system)" } else { "" },
                    Bytes(data)
                );

                Ok(())
            }
            Err(e) => {
                error!(
                    "\n<<SND {} {}B{} !FAILED!: {:?}",
                    peer,
                    data.len(),
                    if system { " (system)" } else { "" },
                    e
                );

                // Do not return an error as that would unroll the main `rs-matter` loop
                // and sending errors are normal and can happen for various reasons
                // TODO: Provide the error as a feedback to the packet creator instead, in the mutex data
                Ok(())
            }
        }
    }
}

#[derive(Copy, Clone, Default, PartialEq, Eq, Debug, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum TxPayloadState {
    #[default]
    Encoded,
    NotEncoded {
        session_id: u32,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct TxInfo {
    pub(crate) retransmission: bool,
    pub(crate) payload_state: TxPayloadState,
}

impl TxInfo {
    pub const fn new() -> Self {
        Self {
            retransmission: false,
            payload_state: TxPayloadState::Encoded,
        }
    }
}

impl Default for TxInfo {
    fn default() -> Self {
        Self::new()
    }
}

// The internal representation of a packet in the transport layer.
// There are only two such packets - RX and TX.
//
// This type is only known and used by the `transport` and the `exchange` modules
pub(crate) struct Packet<const N: usize> {
    pub(crate) peer: Address,
    pub(crate) header: PacketHdr,
    pub(crate) buf: PacketBuffer<N>,
    pub(crate) payload_start: usize,
    pub(crate) tx_info: TxInfo,
}

impl<const N: usize> Packet<N> {
    #[inline(always)]
    pub(crate) const fn new() -> Self {
        Self {
            peer: Address::new(),
            header: PacketHdr::new(),
            buf: PacketBuffer::new(),
            payload_start: 0,
            tx_info: TxInfo::new(),
        }
    }

    pub(crate) fn init() -> impl Init<Self> {
        init!(Self {
            peer: Address::new(),
            header: PacketHdr::new(),
            buf <- PacketBuffer::init(),
            payload_start: 0,
            tx_info: TxInfo::new(),
        })
    }

    #[cfg(feature = "defmt")]
    pub fn display<'a>(
        peer: &'a Address,
        header: &'a PacketHdr,
    ) -> impl Display + defmt::Format + 'a {
        PacketInfo(peer, header)
    }

    #[cfg(not(feature = "defmt"))]
    pub fn display<'a>(peer: &'a Address, header: &'a PacketHdr) -> impl Display + 'a {
        PacketInfo(peer, header)
    }

    #[cfg(feature = "defmt")]
    pub fn display_payload<'a>(
        proto: &'a ProtoHdr,
        buf: &'a [u8],
    ) -> impl Display + defmt::Format + 'a {
        DetailedPacketInfo(proto, buf)
    }

    #[cfg(not(feature = "defmt"))]
    pub fn display_payload<'a>(proto: &'a ProtoHdr, buf: &'a [u8]) -> impl Display + 'a {
        DetailedPacketInfo(proto, buf)
    }

    fn fmt(f: &mut fmt::Formatter<'_>, peer: &Address, header: &PacketHdr) -> fmt::Result {
        write!(f, "{peer} {header}")?;

        if header.proto.is_decoded() {
            let meta = MessageMeta::from(&header.proto);

            write!(f, "\n      {meta}")?;
        }

        Ok(())
    }

    #[cfg(feature = "defmt")]
    fn format(f: defmt::Formatter<'_>, peer: &Address, header: &PacketHdr) {
        defmt::write!(f, "{} {}", peer, header);

        if header.proto.is_decoded() {
            let meta = MessageMeta::from(&header.proto);

            defmt::write!(f, "\n      {}", meta);
        }
    }

    fn fmt_payload(f: &mut fmt::Formatter<'_>, proto: &ProtoHdr, buf: &[u8]) -> fmt::Result {
        let meta = MessageMeta::from(proto);

        write!(f, "{meta}")?;

        if meta.is_tlv() {
            write!(
                f,
                "; TLV:\n----------------\n{}\n----------------\n",
                TLVElement::new(buf)
            )?;
        } else {
            write!(
                f,
                "; Payload:\n----------------\n{:02x?}\n----------------\n",
                buf
            )?;
        }

        Ok(())
    }

    #[cfg(feature = "defmt")]
    fn format_payload(f: defmt::Formatter<'_>, proto: &ProtoHdr, buf: &[u8]) {
        let meta = MessageMeta::from(proto);

        defmt::write!(f, "{}", meta);

        if meta.is_tlv() {
            defmt::write!(
                f,
                "; TLV:\n----------------\n{}\n----------------\n",
                TLVElement::new(buf)
            );
        } else {
            defmt::write!(
                f,
                "; Payload:\n----------------\n{}\n----------------\n",
                crate::fmt::Bytes(buf)
            );
        }
    }
}

impl<const N: usize> Display for Packet<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Self::fmt(f, &self.peer, &self.header)
    }
}

#[cfg(feature = "defmt")]
impl<const N: usize> defmt::Format for Packet<N> {
    fn format(&self, f: defmt::Formatter<'_>) {
        Self::format(f, &self.peer, &self.header)
    }
}

struct PacketInfo<'a>(&'a Address, &'a PacketHdr);

impl Display for PacketInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Packet::<0>::fmt(f, self.0, self.1)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PacketInfo<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        Packet::<0>::format(f, self.0, self.1)
    }
}

struct DetailedPacketInfo<'a>(&'a ProtoHdr, &'a [u8]);

impl Display for DetailedPacketInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Packet::<0>::fmt_payload(f, self.0, self.1)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for DetailedPacketInfo<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        Packet::<0>::format_payload(f, self.0, self.1)
    }
}

// The buffer used inside the pair of RX and TX `Packet` instances.
//
// The payload is allocated inline. With `large-buffers` enabled the inner
// `Vec` is ~1 MiB, so prefer constructing the buffer in place via
// [`PacketBuffer::init`].
// Constructing one by value with `new()` works too, as long as the resulting
// `Matter` is not moved through a small stack.
//
// This type is only known and used by the `transport` and the `exchange` modules
pub(crate) struct PacketBuffer<const N: usize> {
    buffer: crate::utils::storage::Vec<u8, N>,
}

impl<const N: usize> PacketBuffer<N> {
    pub const fn new() -> Self {
        Self {
            buffer: crate::utils::storage::Vec::new(),
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            buffer <- crate::utils::storage::Vec::init(),
        })
    }

    pub fn buf_mut(&mut self) -> &mut crate::utils::storage::Vec<u8, N> {
        &mut self.buffer
    }

    pub fn buf_ref(&self) -> &crate::utils::storage::Vec<u8, N> {
        &self.buffer
    }
}

impl<const N: usize> Deref for PacketBuffer<N> {
    type Target = crate::utils::storage::Vec<u8, N>;

    fn deref(&self) -> &Self::Target {
        self.buf_ref()
    }
}

impl<const N: usize> DerefMut for PacketBuffer<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf_mut()
    }
}

// Represents the fact that either `Transport` or some `Exchange` instace has an exclusive access to the
// RX or TX packet of the transport layer.
//
// At any point in time, either the `Transport` singleton, or exactly one `Exchange` instance, or nobody
// holds a lock on the RX or TX packet. This is enforced by protecting the packets with an `IfMutex` asynchronous mutex.
//
// This type is only known and used by the `transport` and the `exchange` modules
pub(crate) struct PacketAccess<'a, const N: usize>(IfMutexGuard<'a, Packet<N>>, bool);

impl<const N: usize> PacketAccess<'_, N> {
    pub fn clear_on_drop(&mut self, clear: bool) {
        self.1 = clear;
    }
}

impl<const N: usize> Deref for PacketAccess<'_, N> {
    type Target = Packet<N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for PacketAccess<'_, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> Drop for PacketAccess<'_, N> {
    fn drop(&mut self) {
        if self.1 {
            self.buf.clear();
        }
    }
}

impl<const N: usize> Display for PacketAccess<'_, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// Allows other code in `rs-matter` to (ab)use the packet buffers of the transport layer
// in case it needs temporary access to a `&mut [u8]`-shaped memory
//
// Used by the builtin mDNS responder, as well as by the QR code generator
pub struct PacketBufferExternalAccess<'a, const N: usize>(pub(crate) &'a IfMutex<Packet<N>>);

impl<const N: usize> BufferAccess<[u8]> for PacketBufferExternalAccess<'_, N> {
    type Buffer<'b>
        = ExternalPacketBuffer<'b, N>
    where
        Self: 'b;

    async fn get(&self) -> Option<ExternalPacketBuffer<'_, N>> {
        let mut packet = self.0.lock_if(|packet| packet.buf.is_empty()).await;

        // TODO: Resizing might be a bit expensive with large buffers
        // Resizing to `N` is always safe because the size of `buf` heapless vec is `N`
        unwrap!(packet.buf.resize_default(N));

        Some(ExternalPacketBuffer(packet))
    }

    fn get_immediate(&self) -> Option<Self::Buffer<'_>> {
        self.0
            .try_lock_if(|packet| packet.buf.is_empty())
            .ok()
            .map(|mut packet| {
                // TODO: Resizing might be a bit expensive with large buffers
                // Resizing to `N` is always safe because the size of `buf` heapless vec is `N`
                unwrap!(packet.buf.resize_default(N));

                ExternalPacketBuffer(packet)
            })
    }
}

// Wraps the RX or TX packet of the transport manager in something that looks like a `&mut [u8]` buffer.
pub struct ExternalPacketBuffer<'a, const N: usize>(IfMutexGuard<'a, Packet<N>>);

impl<const N: usize> Deref for ExternalPacketBuffer<'_, N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0.buf
    }
}

impl<const N: usize> DerefMut for ExternalPacketBuffer<'_, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0.buf
    }
}

impl<const N: usize> Drop for ExternalPacketBuffer<'_, N> {
    fn drop(&mut self) {
        self.0.buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_only_crypto;
    use crate::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
    use crate::utils::epoch::dummy_epoch;

    fn test_matter() -> Matter<'static> {
        Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, dummy_epoch, 0)
    }

    #[test]
    fn test_create_unsecured_session_creates_plaintext_session() {
        let matter = test_matter();
        let crypto = test_only_crypto();
        let peer = Address::new();

        let session_id = matter
            .transport
            .create_unsecured_session(&matter, &crypto, peer)
            .unwrap();

        matter.with_state(|state| {
            let session = state.sessions.get(session_id).unwrap();

            assert_eq!(session.id, session_id);
            assert!(!session.is_encrypted());
            assert_eq!(session.get_peer_node_id(), None);
            assert_eq!(*session.get_session_mode(), session::SessionMode::PlainText);
        });
    }

    #[test]
    fn test_initiate_unsecured_now_creates_initiator_exchange() {
        let matter = test_matter();
        let crypto = test_only_crypto();
        let peer = Address::new();

        let exchange = matter
            .transport
            .initiate_unsecured_now(&matter, &crypto, peer)
            .unwrap();

        exchange
            .with_state(|state| {
                let sess = exchange.id().session(&mut state.sessions);
                let exch = exchange.id().exch(sess);

                assert!(matches!(exch.role, Role::Initiator(_)));
                assert_eq!(sess.id, exchange.id().session_id());
                Ok(())
            })
            .unwrap();
    }
}
