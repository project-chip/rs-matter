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

use core::cell::RefCell;
use core::fmt::{self, Display};
use core::ops::{Deref, DerefMut};
use core::pin::pin;

use embassy_futures::select::{select, select3};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::Timer;

use log::{debug, error, info, trace, warn};

use crate::error::{Error, ErrorCode};
use crate::mdns::MdnsImpl;
use crate::secure_channel::common::{sc_write, OpCode, SCStatusCodes, PROTO_ID_SECURE_CHANNEL};
use crate::secure_channel::status_report::StatusReport;
use crate::tlv::TLVList;
use crate::utils::buf::BufferAccess;
use crate::utils::{
    epoch::Epoch,
    ifmutex::{IfMutex, IfMutexGuard},
    notification::Notification,
    parsebuf::ParseBuf,
    rand::Rand,
    select::Coalesce,
    writebuf::WriteBuf,
};
use crate::{Matter, MATTER_PORT};

use super::exchange::{Exchange, ExchangeId, ExchangeState, MessageMeta, ResponderState, Role};
use super::network::{
    self, Address, Ipv6Addr, NetworkReceive, NetworkSend, SocketAddr, SocketAddrV6,
};
use super::packet::PacketHdr;
use super::proto_hdr::ProtoHdr;
use super::session::{Session, SessionMgr};

#[cfg(all(feature = "large-buffers", feature = "alloc"))]
extern crate alloc;

pub const MATTER_SOCKET_BIND_ADDR: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MATTER_PORT, 0, 0));

const ACCEPT_TIMEOUT_MS: u64 = 1000;

#[cfg(all(feature = "large-buffers", feature = "alloc"))]
pub(crate) const MAX_RX_BUF_SIZE: usize = network::MAX_RX_LARGE_PACKET_SIZE;
#[cfg(all(feature = "large-buffers", feature = "alloc"))]
pub(crate) const MAX_TX_BUF_SIZE: usize = network::MAX_TX_LARGE_PACKET_SIZE;

#[cfg(not(all(feature = "large-buffers", feature = "alloc")))]
pub(crate) const MAX_RX_BUF_SIZE: usize = network::MAX_RX_PACKET_SIZE;
#[cfg(not(all(feature = "large-buffers", feature = "alloc")))]
pub(crate) const MAX_TX_BUF_SIZE: usize = network::MAX_TX_PACKET_SIZE;

/// Represents the transport layer of a `Matter` instance.
/// Each `Matter` instance has exactly one `TransportMgr` instance.
///
/// To the outside world, the transport layer is only visible and usable via the notion of `Exchange`.
pub struct TransportMgr<'m> {
    pub(crate) rx: IfMutex<NoopRawMutex, Packet<MAX_RX_BUF_SIZE>>,
    pub(crate) tx: IfMutex<NoopRawMutex, Packet<MAX_TX_BUF_SIZE>>,
    pub(crate) dropped: Notification<NoopRawMutex>,
    pub session_mgr: RefCell<SessionMgr>, // For testing
    pub(crate) mdns: MdnsImpl<'m>,
}

impl<'m> TransportMgr<'m> {
    #[inline(always)]
    pub(crate) const fn new(mdns: MdnsImpl<'m>, epoch: Epoch, rand: Rand) -> Self {
        Self {
            rx: IfMutex::new(Packet::new()),
            tx: IfMutex::new(Packet::new()),
            dropped: Notification::new(),
            session_mgr: RefCell::new(SessionMgr::new(epoch, rand)),
            mdns,
        }
    }

    #[cfg(all(feature = "large-buffers", feature = "alloc"))]
    pub fn initialize_buffers(&self) -> Result<(), Error> {
        let mut rx = self.rx.try_lock().map_err(|_| ErrorCode::InvalidState)?;
        let mut tx = self.tx.try_lock().map_err(|_| ErrorCode::InvalidState)?;

        if rx.buf.0.is_none() {
            rx.buf.0 = Some(alloc::boxed::Box::new(heapless::Vec::new()));
        }

        if tx.buf.0.is_none() {
            tx.buf.0 = Some(alloc::boxed::Box::new(heapless::Vec::new()));
        }

        Ok(())
    }

    #[cfg(not(all(feature = "large-buffers", feature = "alloc")))]
    pub fn initialize_buffers(&self) -> Result<(), Error> {
        // No-op, as buffers are allocated inline
        Ok(())
    }

    /// Resets the transport layer by clearing all sessions, exchanges, the RX buffer and the TX buffer
    /// NOTE: User should be careful _not_ to call this method while the transport layer and/or the built-in mDNS is running.
    pub fn reset(&self) -> Result<(), Error> {
        self.session_mgr.borrow_mut().reset();
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

    pub(crate) async fn initiate<'a>(
        &'a self,
        matter: &'a Matter<'a>,
        node_id: u64,
        secure: bool,
    ) -> Result<Exchange<'_>, Error> {
        let mut session_mgr = self.session_mgr.borrow_mut();

        session_mgr
            .get_for_node(node_id, secure)
            .ok_or(ErrorCode::NoSession)?;

        let exch_id = session_mgr.get_next_exch_id();

        // `unwrap` is safe because we know we have a session or else the early return from above would've triggered
        // The reason why we call `get_for_node` twice is to ensure that we don't waste an `exch_id` in case
        // we don't have a session in the first place
        let session = session_mgr.get_for_node(node_id, secure).unwrap();

        let exch_index = session
            .add_exch(exch_id, Role::Initiator(Default::default()))
            .ok_or(ErrorCode::NoSpaceExchanges)?;

        let id = ExchangeId::new(session.id, exch_index);

        info!("Exchange {}: Initiated", id.display(session));

        Ok(Exchange::new(id, matter))
    }

    pub(crate) async fn accept_if<'a, F>(
        &'a self,
        matter: &'a Matter<'a>,
        mut f: F,
    ) -> Result<Exchange<'_>, Error>
    where
        F: FnMut(&Session, &ExchangeState, &Packet<MAX_RX_BUF_SIZE>) -> bool,
    {
        let exchange = self
            .with_locked(&self.rx, |packet| {
                let mut session_mgr = self.session_mgr.borrow_mut();

                let session = session_mgr.get_for_rx(&packet.peer, &packet.header.plain)?;

                let exch_index = session.get_exch_for_rx(&packet.header.proto)?;

                let matches = {
                    // `unwrap` is safe because the transport code is single threaded, and since we don't `await`
                    // after computing `exch_index` no code can remove the exchange from the session
                    let exch = session.exchanges[exch_index].as_ref().unwrap();

                    matches!(exch.role, Role::Responder(ResponderState::AcceptPending))
                        && f(session, exch, packet)
                };

                if !matches {
                    return None;
                }

                // `unwrap` is safe because the transport code is single threaded, and since we don't `await`
                // after computing `exch_index` no code can remove the exchange from the session
                let exch = session.exchanges[exch_index].as_mut().unwrap();

                exch.role = Role::Responder(ResponderState::Owned);

                let id = ExchangeId::new(session.id, exch_index);

                info!("Exchange {}: Accepted", id.display(session));

                let exchange = Exchange::new(id, matter);

                Some(exchange)
            })
            .await;

        Ok(exchange)
    }

    pub async fn run<S, R>(&self, send: S, recv: R) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
    {
        info!("Running Matter transport");

        let send = IfMutex::new(send);

        let mut rx = pin!(self.process_rx(recv, &send));
        let mut tx = pin!(self.process_tx(&send));
        let mut orphaned = pin!(self.process_orphaned());

        select3(&mut rx, &mut tx, &mut orphaned).coalesce().await
    }

    #[cfg(not(all(
        feature = "std",
        any(target_os = "macos", all(feature = "zeroconf", target_os = "linux"))
    )))]
    pub async fn run_builtin_mdns<S, R>(
        &self,
        send: S,
        recv: R,
        host: crate::mdns::Host<'_>,
        interface: Option<u32>,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
    {
        info!("Running Matter built-in mDNS service");

        if let MdnsImpl::Builtin(mdns) = &self.mdns {
            mdns.run(
                send,
                recv,
                &PacketBufferExternalAccess(&self.tx),
                PacketBufferExternalAccess(&self.rx),
                host,
                interface,
            )
            .await
        } else {
            Err(ErrorCode::MdnsError.into())
        }
    }

    pub(crate) async fn get_if<'a, F, const N: usize>(
        &'a self,
        packet_mutex: &'a IfMutex<NoopRawMutex, Packet<N>>,
        f: F,
    ) -> PacketAccess<'a, N>
    where
        F: Fn(&Packet<N>) -> bool,
    {
        PacketAccess(packet_mutex.lock_if(f).await, false)
    }

    async fn with_locked<'a, F, R, T>(
        &'a self,
        packet_mutex: &'a IfMutex<NoopRawMutex, T>,
        f: F,
    ) -> R
    where
        F: FnMut(&mut T) -> Option<R>,
    {
        packet_mutex.with(f).await
    }

    async fn process_tx<S>(&self, send: &IfMutex<NoopRawMutex, S>) -> Result<(), Error>
    where
        S: NetworkSend,
    {
        loop {
            debug!("Waiting for outgoing packet");

            let mut tx = self.get_if(&self.tx, |packet| !packet.buf.is_empty()).await;
            tx.clear_on_drop(true);

            Self::netw_send(send, tx.peer, &tx.buf[tx.payload_start..], false).await?;
        }
    }

    async fn process_rx<R, S>(
        &self,
        mut recv: R,
        send: &IfMutex<NoopRawMutex, S>,
    ) -> Result<(), Error>
    where
        R: NetworkReceive,
        S: NetworkSend,
    {
        loop {
            debug!("Waiting for incoming packet");

            recv.wait_available().await?;

            let mut rx = self.get_if(&self.rx, |packet| packet.buf.is_empty()).await;
            rx.clear_on_drop(true); // In case of error, or if the future is dropped

            // TODO: Resizing might be a bit expensive with large buffers
            // Resizing to `MAX_RX_BUF_SIZE` is always safe because the size of the `buf` heapless vec `MAX_RX_BUF_SIZE`
            rx.buf.resize_default(MAX_RX_BUF_SIZE).unwrap();

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
                    error!("UNEXPECTED RX ERROR: {e:?}");
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

            let mut accept_timeout = pin!(self.with_locked(&self.rx, |packet| {
                self.handle_accept_timeout_rx_packet(packet).then_some(())
            }));

            let mut timer = pin!(Timer::after(embassy_time::Duration::from_millis(50)));

            select(&mut accept_timeout, &mut timer).await;
        }
    }

    async fn process_orphaned_rx(&self) -> Result<(), Error> {
        loop {
            info!("Waiting for orphaned RX packets");

            self.with_locked(&self.rx, |packet| {
                self.handle_orphaned_rx_packet(packet).then_some(())
            })
            .await;
        }
    }

    async fn process_dropped_exchanges(&self) -> Result<(), Error> {
        loop {
            trace!("Waiting for dropped exchanges");

            let mut tx = self.get_if(&self.tx, |packet| packet.buf.is_empty()).await;
            tx.clear_on_drop(true); // In case of error, or if the future is dropped

            let wait = match self.handle_dropped_exchange(&mut tx) {
                Ok(wait) => {
                    tx.clear_on_drop(false);
                    wait
                }
                Err(e) => {
                    error!("UNEXPECTED RX ERROR: {e:?}");
                    false
                }
            };

            drop(tx);

            if wait {
                let mut timeout = pin!(Timer::after(embassy_time::Duration::from_millis(100)));
                let mut wait = pin!(self.dropped.wait());

                select(&mut timeout, &mut wait).await;
            }
        }
    }

    async fn handle_rx_packet<const N: usize, S>(
        &self,
        packet: &mut Packet<N>,
        send: &IfMutex<NoopRawMutex, S>,
    ) -> Result<bool, Error>
    where
        S: NetworkSend,
    {
        let result = self.decode_packet(packet);
        match result {
            Err(e) if matches!(e.code(), ErrorCode::Duplicate) => {
                if !packet.peer.is_reliable() {
                    info!("\n>>>>> {packet}\n => Duplicate, sending ACK");

                    {
                        let mut session_mgr = self.session_mgr.borrow_mut();
                        let epoch = session_mgr.epoch;

                        // `unwrap` is safe because we know we have a session.
                        // If we didn't have a session, the error code would've been `NoSession`
                        //
                        // Also, since the transport code is single threaded, and since we don't `await`
                        // after decoding the packet, no code can the session
                        let session = session_mgr
                            .get_for_rx(&packet.peer, &packet.header.plain)
                            .unwrap();

                        let ack = packet.header.plain.ctr;

                        packet.header.proto.toggle_initiator();
                        packet.header.proto.set_ack(Some(ack));

                        self.encode_packet(packet, Some(session), None, epoch, |_| {
                            Ok(Some(OpCode::MRPStandAloneAck.into()))
                        })?;
                    }

                    Self::netw_send(send, packet.peer, &packet.buf[packet.payload_start..], true)
                        .await?;
                } else {
                    info!("\n>>>>> {packet}\n => Duplicate, discarding");
                }
            }
            Err(e) if matches!(e.code(), ErrorCode::NoSpaceSessions) => {
                if !packet.header.plain.is_encrypted()
                    && MessageMeta::from(&packet.header.proto).is_new_session()
                {
                    warn!("\n>>>>> {packet}\n => No space for a new unencrypted session, sending Busy");

                    let ack = packet.header.plain.ctr;

                    packet.header.proto.toggle_initiator();
                    packet.header.proto.set_ack(Some(ack));

                    self.encode_packet(
                        packet,
                        None,
                        None,
                        self.session_mgr.borrow().epoch,
                        |wb| sc_write(wb, SCStatusCodes::Busy, &[0xF4, 0x01]),
                    )?;

                    Self::netw_send(send, packet.peer, &packet.buf[packet.payload_start..], true)
                        .await?;

                    if self.encode_evict_some_session(packet)? {
                        Self::netw_send(
                            send,
                            packet.peer,
                            &packet.buf[packet.payload_start..],
                            true,
                        )
                        .await?;
                    }
                } else {
                    error!("\n>>>>> {packet}\n => No space for a new encrypted session, dropping");
                }
            }
            Err(e) if matches!(e.code(), ErrorCode::NoSpaceExchanges) => {
                // TODO: Before closing the session, try to take other measures:
                // - For CASESigma1 & PBKDFParamRequest - send Busy instead
                // - For Interaction Model interactions that do need an ACK - send IM Busy,
                //   wait for ACK and retransmit without releasing the RX buffer, potentially
                //   blocking all other interactions

                error!("\n>>>>> {packet}\n => No space for a new exchange, closing session");

                {
                    let mut session_mgr = self.session_mgr.borrow_mut();

                    // `unwrap` is safe because we know we have a session.
                    // If we didn't have a session, the error code would've been `NoSession`
                    //
                    // Also, since the transport code is single threaded, and since we don't `await`
                    // after decoding the packet, no code can the session
                    let session_id = session_mgr
                        .get_for_rx(&packet.peer, &packet.header.plain)
                        .unwrap()
                        .id;

                    packet.header.proto.exch_id = session_mgr.get_next_exch_id();
                    packet.header.proto.set_initiator();

                    // See above why `unwrap` is safe
                    let mut session = session_mgr.remove(session_id).unwrap();

                    self.encode_packet(
                        packet,
                        Some(&mut session),
                        None,
                        session_mgr.epoch,
                        |wb| sc_write(wb, SCStatusCodes::CloseSession, &[]),
                    )?;
                }

                Self::netw_send(send, packet.peer, &packet.buf[packet.payload_start..], true)
                    .await?;
            }
            Err(e) if matches!(e.code(), ErrorCode::NoExchange) => {
                warn!("\n>>>>> {packet}\n => No valid exchange found, dropping");
            }
            Err(e) if matches!(e.code(), ErrorCode::NoSession) => {
                warn!("\n>>>>> {packet}\n => No valid session found, dropping");
            }
            Err(e) => {
                error!("\n>>>>> {packet}\n => Error ({e:?}), dropping");
            }
            Ok(new_exchange) => {
                let meta = MessageMeta::from(&packet.header.proto);

                if meta.is_standalone_ack() {
                    // No need to propagate this further
                    info!("\n>>>>> {packet}\n => Standalone Ack, dropping");
                } else if meta.is_sc_status()
                    && matches!(
                        Self::is_close_session(&mut packet.buf[packet.payload_start..]),
                        Ok(true)
                    )
                {
                    warn!("\n>>>>> {packet}\n => Close session received, removing this session");

                    let mut session_mgr = self.session_mgr.borrow_mut();
                    if let Some(session_id) = session_mgr
                        .get_for_rx(&packet.peer, &packet.header.plain)
                        .map(|sess| sess.id)
                    {
                        session_mgr.remove(session_id);
                    }
                } else {
                    info!(
                        "\n>>>>> {packet}\n => Processing{}",
                        if new_exchange { " (new exchange)" } else { "" }
                    );

                    debug!(
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

        let mut session_mgr = self.session_mgr.borrow_mut();
        let epoch = session_mgr.epoch;

        let Some(session) = session_mgr.get_for_rx(&packet.peer, &packet.header.plain) else {
            return false;
        };

        let Some(exch_index) = session.get_exch_for_rx(&packet.header.proto) else {
            return false;
        };

        // `unwrap` is safe because we know we have a session and an exchange, or else the early returns from above would've triggered
        let exchange = session.exchanges[exch_index].as_mut().unwrap();

        if !matches!(
            exchange.role,
            Role::Responder(ResponderState::AcceptPending)
        ) || !exchange.mrp.has_rx_timed_out(ACCEPT_TIMEOUT_MS, epoch)
        {
            return false;
        }

        warn!("\n----- {packet}\n => Accept timeout, marking exchange as dropped");

        exchange.role = Role::Responder(ResponderState::Dropped);
        packet.buf.clear();
        self.dropped.notify();

        true
    }

    fn handle_orphaned_rx_packet<const N: usize>(&self, packet: &mut Packet<N>) -> bool {
        if packet.buf.is_empty() {
            return false;
        }

        let mut session_mgr = self.session_mgr.borrow_mut();

        let Some(session) = session_mgr.get_for_rx(&packet.peer, &packet.header.plain) else {
            warn!("\n----- {packet}\n => No session, dropping");

            packet.buf.clear();
            return true;
        };

        let Some(exch_index) = session.get_exch_for_rx(&packet.header.proto) else {
            warn!("\n----- {packet}\n => No exchange, dropping");

            packet.buf.clear();
            return true;
        };

        // `unwrap` is safe because we know we have a session and an exchange, or else the early returns from above would've triggered
        let exchange = session.exchanges[exch_index].as_mut().unwrap();

        if exchange.role.is_dropped_state() {
            warn!(
                "\n----- {packet}\n => Owned by orphaned dropped {}, dropping packet",
                ExchangeId::new(session.id, exch_index)
            );

            packet.buf.clear();
            return true;
        }

        false
    }

    fn handle_dropped_exchange<const N: usize>(
        &self,
        packet: &mut Packet<N>,
    ) -> Result<bool, Error> {
        let mut session_mgr = self.session_mgr.borrow_mut();

        let exch = session_mgr
            .get_exch(|_, exch| exch.role.is_dropped_state() && exch.mrp.is_retrans_pending())
            .map(|(sess, exch_index)| (sess.id, exch_index, true))
            .or_else(|| {
                session_mgr
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
                exchange_id.display(session_mgr.get(session_id).unwrap()) // Session exists or else we wouldn't be here
            );

            self.encode_evict_session(packet, &mut session_mgr, session_id)?;
        } else {
            // Found a dropped exchange which has no outstanding (re)transmission
            // Send a standalone ACK if necessary and then close it

            let epoch = session_mgr.epoch;

            // `unwrap` is safe because we know we have a session and an exchange, or else the early returns from above would've triggered
            let session = session_mgr.get(session_id).unwrap();
            // Ditto
            let exchange = session.exchanges[exch_index].as_mut().unwrap();

            if exchange.mrp.is_ack_pending() {
                self.encode_packet(packet, Some(session), Some(exch_index), epoch, |_| {
                    Ok(Some(OpCode::MRPStandAloneAck.into()))
                })?;
            }

            warn!("Dropped exchange {}: Closed", exchange_id.display(session));
            session.exchanges[exch_index] = None;
        }

        Ok(exch.is_none())
    }

    pub(crate) async fn evict_some_session(&self) -> Result<(), Error> {
        let mut tx = self.get_if(&self.tx, |packet| packet.buf.is_empty()).await;
        tx.clear_on_drop(true); // By default, if an error occurs

        let evicted = self.encode_evict_some_session(&mut tx)?;

        if evicted {
            // Send it
            tx.clear_on_drop(false);

            Ok(())
        } else {
            Err(ErrorCode::NoSpaceSessions.into())
        }
    }

    fn decode_packet<const N: usize>(&self, packet: &mut Packet<N>) -> Result<bool, Error> {
        packet.header.reset();

        let mut pb = ParseBuf::new(&mut packet.buf[packet.payload_start..]);
        packet.header.plain.decode(&mut pb)?;

        let mut session_mgr = self.session_mgr.borrow_mut();
        let epoch = session_mgr.epoch;

        let set_payload = |packet: &mut Packet<N>, (start, end)| {
            packet.payload_start = start;
            packet.buf.truncate(end);
        };

        if let Some(session) = session_mgr.get_for_rx(&packet.peer, &packet.header.plain) {
            // Found existing session: decode, indicate packet payload slice and process further

            let payload_range = session.decode_remaining(&mut packet.header, pb)?;
            set_payload(packet, payload_range);

            return session.post_recv(&packet.header, epoch);
        }

        // No existing session: we either have to create one, or return an error

        let mut error_code = ErrorCode::NoSession;

        if !packet.header.plain.is_encrypted() {
            // Unencrypted packets can be decoded without a session, and we need to anyway do that
            // in order to determine (based on proto hdr data) whether to create a new session or not
            packet.header.decode_remaining(&mut pb, 0, None)?;
            packet.header.proto.adjust_reliability(true, &packet.peer);

            let payload_range = pb.slice_range();
            set_payload(packet, payload_range);

            if MessageMeta::from(&packet.header.proto).is_new_session() {
                // As per spec, new unencrypted sessions are only created for
                // `PBKDFParamRequest` or `CASESigma1` unencrypted messages

                if let Some(session) =
                    session_mgr.add(false, packet.peer, packet.header.plain.get_src_nodeid())
                {
                    // Session created successfully: decode, indicate packet payload slice and process further
                    return session.post_recv(&packet.header, epoch);
                } else {
                    // We tried to create a new PASE session, but there was no space
                    error_code = ErrorCode::NoSpaceSessions;
                }
            }
        } else {
            // Packet cannot be decoded, set packet payload to empty
            set_payload(packet, (0, 0));
        }

        Err(error_code.into())
    }

    fn encode_packet<const N: usize, F>(
        &self,
        packet: &mut Packet<N>,
        mut session: Option<&mut Session>,
        exchange_index: Option<usize>,
        epoch: Epoch,
        payload_writer: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut WriteBuf) -> Result<Option<MessageMeta>, Error>,
    {
        // TODO: Resizing might be a bit expensive with large buffers
        // Resizing to `N` is always safe because it is a responsibility of the caller to ensure that N is <= `MAX_RX_BUF_SIZE`,
        // which is the size of `buf` heapless vec
        packet.buf.resize_default(N).unwrap();

        let mut wb = WriteBuf::new(&mut packet.buf);
        wb.reserve(PacketHdr::HDR_RESERVE)?;

        let Some(meta) = payload_writer(&mut wb)? else {
            packet.buf.clear();
            return Ok(());
        };

        meta.set_into(&mut packet.header.proto);

        let retransmission = if let Some(session) = &mut session {
            packet.header.plain = Default::default();

            let (peer, retransmission) =
                session.pre_send(exchange_index, &mut packet.header, epoch)?;

            packet.peer = peer;

            retransmission
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

            false
        };

        info!(
            "\n<<<<< {}\n => {} (system)",
            Packet::<0>::display(&packet.peer, &packet.header),
            if retransmission {
                "Re-sending"
            } else {
                "Sending"
            }
        );

        debug!(
            "{}",
            Packet::<0>::display_payload(&packet.header.proto, wb.as_slice())
        );

        if let Some(session) = session {
            session.encode(&packet.header, &mut wb)?;
        } else {
            packet.header.encode(&mut wb, 0, None)?;
        }

        let range = (wb.get_start(), wb.get_tail());

        packet.payload_start = range.0;
        packet.buf.truncate(range.1);

        Ok(())
    }

    fn encode_evict_some_session<const N: usize>(
        &self,
        packet: &mut Packet<N>,
    ) -> Result<bool, Error> {
        let mut session_mgr = self.session_mgr.borrow_mut();
        let id = session_mgr.get_session_for_eviction().map(|sess| sess.id);
        if let Some(id) = id {
            self.encode_evict_session(packet, &mut session_mgr, id)?;

            Ok(true)
        } else {
            error!("All sessions have active exchanges, cannot evict any session");

            Ok(false)
        }
    }

    fn encode_evict_session<const N: usize>(
        &self,
        packet: &mut Packet<N>,
        session_mgr: &mut SessionMgr,
        id: u32,
    ) -> Result<(), Error> {
        packet.header.proto.exch_id = session_mgr.get_next_exch_id();
        packet.header.proto.set_initiator();

        // It is a responsibility of the caller to ensure that this method is called with a valid session ID
        let mut session = session_mgr.remove(id).unwrap();

        info!(
            "Evicting session {} [SID:{:x},RSID:{:x}]",
            session.id,
            session.get_local_sess_id(),
            session.get_peer_sess_id()
        );

        self.encode_packet(packet, Some(&mut session), None, session_mgr.epoch, |wb| {
            sc_write(wb, SCStatusCodes::CloseSession, &[])
        })?;

        Ok(())
    }

    fn is_close_session(payload: &mut [u8]) -> Result<bool, Error> {
        let mut pb = ParseBuf::new(payload);
        let report = StatusReport::read(&mut pb)?;

        let close_session = report.proto_id == PROTO_ID_SECURE_CHANNEL as _
            && report.proto_code == SCStatusCodes::CloseSession as u16;

        Ok(close_session)
    }

    async fn netw_recv<R>(mut recv: R, buf: &mut [u8]) -> Result<(usize, Address), Error>
    where
        R: NetworkReceive,
    {
        match recv.recv_from(buf).await {
            Ok((len, addr)) => {
                debug!("\n>>>>> {} {}B:\n{:02x?}", addr, len, &buf[..len]);

                Ok((len, addr))
            }
            Err(e) => {
                error!("FAILED network recv: {e:?}");

                Err(e)
            }
        }
    }

    async fn netw_send<S>(
        send: &IfMutex<NoopRawMutex, S>,
        peer: Address,
        data: &[u8],
        system: bool,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
    {
        match send.lock().await.send_to(data, peer).await {
            Ok(_) => {
                debug!(
                    "\n<<<<< {} {}B{}: {:02x?}",
                    peer,
                    data.len(),
                    if system { " (system)" } else { "" },
                    data
                );

                Ok(())
            }
            Err(e) => {
                error!(
                    "\n<<<<< {} {}B{} !FAILED!: {e:?}: {:02x?}",
                    peer,
                    data.len(),
                    if system { " (system)" } else { "" },
                    data
                );

                Err(e)
            }
        }
    }
}

// The internal representation of a packet in the transport layer.
// There are only two such packets - RX and TX.
//
// This type is only known and used by `TransportMgr` and the `exchange` module
pub(crate) struct Packet<const N: usize> {
    pub(crate) peer: Address,
    pub(crate) header: PacketHdr,
    pub(crate) buf: PacketBuffer<N>,
    pub(crate) payload_start: usize,
}

impl<const N: usize> Packet<N> {
    #[inline(always)]
    pub(crate) const fn new() -> Self {
        Self {
            peer: Address::new(),
            header: PacketHdr::new(),
            buf: PacketBuffer::new(),
            payload_start: 0,
        }
    }

    pub fn display<'a>(peer: &'a Address, header: &'a PacketHdr) -> impl Display + 'a {
        struct PacketInfo<'a>(&'a Address, &'a PacketHdr);

        impl<'a> Display for PacketInfo<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                Packet::<0>::fmt(f, self.0, self.1)
            }
        }

        PacketInfo(peer, header)
    }

    pub fn display_payload<'a>(proto: &'a ProtoHdr, buf: &'a [u8]) -> impl Display + 'a {
        struct PacketInfo<'a>(&'a ProtoHdr, &'a [u8]);

        impl<'a> Display for PacketInfo<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                Packet::<0>::fmt_payload(f, self.0, self.1)
            }
        }

        PacketInfo(proto, buf)
    }

    fn fmt(f: &mut fmt::Formatter<'_>, peer: &Address, header: &PacketHdr) -> fmt::Result {
        write!(f, "{peer} {header}")?;

        if header.proto.is_decoded() {
            let meta = MessageMeta::from(&header.proto);

            write!(f, "\n{meta}")?;
        }

        Ok(())
    }

    fn fmt_payload(f: &mut fmt::Formatter<'_>, proto: &ProtoHdr, buf: &[u8]) -> fmt::Result {
        let meta = MessageMeta::from(proto);

        write!(f, "{meta}")?;

        if meta.is_tlv() {
            write!(
                f,
                "; TLV:\n----------------\n{}\n----------------\n",
                TLVList::new(buf)
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
}

impl<const N: usize> Display for Packet<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Self::fmt(f, &self.peer, &self.header)
    }
}

// The buffer used inside the pair of RX and TX `Packet` instances
// When the `alloc` and `large-buffers` features are enabled, the buffer payload is allocated on the heap
//
// This type is only known and used by `TransportMgr` and the `exchange` module
#[cfg(all(feature = "large-buffers", feature = "alloc"))]
pub(crate) struct PacketBuffer<const N: usize>(Option<alloc::boxed::Box<heapless::Vec<u8, N>>>);

// The buffer used inside the pair of RX and TX `Packet` instances
// When the either of the `alloc` and `large-buffers` features is not enabled, the buffer payload is allocated inline
//
// This type is only known and used by `TransportMgr` and the `exchange` module
#[cfg(not(all(feature = "large-buffers", feature = "alloc")))]
pub(crate) struct PacketBuffer<const N: usize>(heapless::Vec<u8, N>);

impl<const N: usize> PacketBuffer<N> {
    #[cfg(all(feature = "large-buffers", feature = "alloc"))]
    pub const fn new() -> Self {
        Self(None)
    }

    #[cfg(not(all(feature = "large-buffers", feature = "alloc")))]
    pub const fn new() -> Self {
        Self(heapless::Vec::new())
    }

    #[cfg(all(feature = "large-buffers", feature = "alloc"))]
    pub fn buf_mut(&mut self) -> &mut heapless::Vec<u8, N> {
        &mut *self
            .0
            .as_mut()
            .expect("Buffer is not allocated. Did you forget to call `initialize_buffers`?")
    }

    #[cfg(not(all(feature = "large-buffers", feature = "alloc")))]
    pub fn buf_mut(&mut self) -> &mut heapless::Vec<u8, N> {
        &mut self.0
    }

    #[cfg(all(feature = "large-buffers", feature = "alloc"))]
    pub fn buf_ref(&self) -> &heapless::Vec<u8, N> {
        self.0
            .as_ref()
            .expect("Buffer is not allocated. Did you forget to call `initialize_buffers`?")
    }

    #[cfg(not(all(feature = "large-buffers", feature = "alloc")))]
    pub fn buf_ref(&self) -> &heapless::Vec<u8, N> {
        &self.0
    }
}

impl<const N: usize> Deref for PacketBuffer<N> {
    type Target = heapless::Vec<u8, N>;

    fn deref(&self) -> &Self::Target {
        self.buf_ref()
    }
}

impl<const N: usize> DerefMut for PacketBuffer<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf_mut()
    }
}

// Represents the fact that either `TransportMgr` or some `Exchange` instace has an exclusive access to the
// RX or TX packet of the transport layer.
//
// At any point in time, either the `TransportMgr` singleton, or exactly one `Exchange` instance, or nobody
// holds a lock on the RX or TX packet. This is enforced by protecting the packets with an `IfMutex` asynchronous mutex.
//
// This type is only known and used by `TransportMgr` and the `exchange` module
pub(crate) struct PacketAccess<'a, const N: usize>(IfMutexGuard<'a, NoopRawMutex, Packet<N>>, bool);

impl<'a, const N: usize> PacketAccess<'a, N> {
    pub fn clear_on_drop(&mut self, clear: bool) {
        self.1 = clear;
    }
}

impl<'a, const N: usize> Deref for PacketAccess<'a, N> {
    type Target = Packet<N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, const N: usize> DerefMut for PacketAccess<'a, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a, const N: usize> Drop for PacketAccess<'a, N> {
    fn drop(&mut self) {
        if self.1 {
            self.buf.clear();
        }
    }
}

impl<'a, const N: usize> Display for PacketAccess<'a, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// Allows other code in `rs-matter` to (ab)use the packet buffers of the transport layer
// in case it needs temporary access to a `&mut [u8]`-shaped memory
//
// Used by the builtin mDNS responder, as well as by the QR code generator
pub(crate) struct PacketBufferExternalAccess<'a, const N: usize>(
    pub(crate) &'a IfMutex<NoopRawMutex, Packet<N>>,
);

impl<'a, const N: usize> BufferAccess<[u8]> for PacketBufferExternalAccess<'a, N> {
    type Buffer<'b> = ExternalPacketBuffer<'b, N> where Self: 'b;

    async fn get(&self) -> Option<ExternalPacketBuffer<'_, N>> {
        let mut packet = self.0.lock_if(|packet| packet.buf.is_empty()).await;

        // TODO: Resizing might be a bit expensive with large buffers
        // Resizing to `N` is always safe because the size of `buf` heapless vec is `N`
        packet.buf.resize_default(N).unwrap();

        Some(ExternalPacketBuffer(packet))
    }
}

// Wraps the RX or TX packet of the transport manager in something that looks like a `&mut [u8]` buffer.
pub struct ExternalPacketBuffer<'a, const N: usize>(IfMutexGuard<'a, NoopRawMutex, Packet<N>>);

impl<'a, const N: usize> Deref for ExternalPacketBuffer<'a, N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0.buf
    }
}

impl<'a, const N: usize> DerefMut for ExternalPacketBuffer<'a, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0.buf
    }
}

impl<'a, const N: usize> Drop for ExternalPacketBuffer<'a, N> {
    fn drop(&mut self) {
        self.0.buf.clear();
    }
}
