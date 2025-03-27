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
use core::pin::pin;

use embassy_futures::select::{select, select3, Either, Either3};
use embassy_time::{Duration, Instant, Timer};

use log::{debug, error, info, warn};

use crate::acl::Accessor;
use crate::error::{Error, ErrorCode};
use crate::interaction_model::{self, core::PROTO_ID_INTERACTION_MODEL};
use crate::secure_channel::{self, common::PROTO_ID_SECURE_CHANNEL};
use crate::utils::epoch::Epoch;
use crate::utils::storage::WriteBuf;
use crate::Matter;

use super::core::{Packet, PacketAccess, MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE};
use super::mrp::{ReliableMessage, RetransEntry};
use super::network;
use super::packet::PacketHdr;
use super::plain_hdr::PlainHdr;
use super::proto_hdr::ProtoHdr;
use super::session::Session;

/// Minimum buffer which should be allocated by user code that wants to pull RX messages via `Exchange::recv_into`
// TODO: Revisit with large packets
pub const MAX_EXCHANGE_RX_BUF_SIZE: usize = network::MAX_RX_PACKET_SIZE;

/// Maximum buffer which should be allocated and used by user code that wants to send messages via `Exchange::send`
// TODO: Revisit with large packets
pub const MAX_EXCHANGE_TX_BUF_SIZE: usize =
    network::MAX_TX_PACKET_SIZE - PacketHdr::HDR_RESERVE - PacketHdr::TAIL_RESERVE;

/// An exchange identifier, uniquely identifying a session and an exchange within that session for a given Matter stack.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExchangeId(u32);

impl ExchangeId {
    pub(crate) fn new(session_id: u32, exchange_index: usize) -> Self {
        if session_id > 0x0fff_ffff {
            panic!("Session ID out of range");
        }

        if exchange_index >= 16 {
            panic!("Exchange index out of range");
        }

        Self(((exchange_index as u32) << 28) | session_id)
    }

    pub(crate) fn session_id(&self) -> u32 {
        self.0 & 0x0fff_ffff
    }

    pub(crate) fn exchange_index(&self) -> usize {
        (self.0 >> 28) as _
    }

    pub(crate) fn display<'a>(&'a self, session: &'a Session) -> ExchangeIdDisplay<'a> {
        ExchangeIdDisplay { id: self, session }
    }

    async fn recv<'a>(&self, matter: &'a Matter<'a>) -> Result<RxMessage<'a>, Error> {
        self.check_no_pending_retrans(matter)?;

        let transport_mgr = &matter.transport_mgr;

        loop {
            let mut recv = pin!(transport_mgr.get_if(&transport_mgr.rx, |packet| {
                if packet.buf.is_empty() {
                    false
                } else {
                    let for_us = self.with_ctx(matter, |sess, exch_index| {
                        if sess.is_for_rx(&packet.peer, &packet.header.plain) {
                            let exchange = sess.exchanges[exch_index].as_ref().unwrap();

                            return Ok(exchange.is_for_rx(&packet.header.proto));
                        }

                        Ok(false)
                    });

                    for_us.unwrap_or(true)
                }
            }));

            let mut session_removed = pin!(transport_mgr.session_removed.wait());

            let mut timeout = pin!(Timer::after(Duration::from_millis(
                RetransEntry::new(matter.dev_det().sai, 0).max_delay_ms() * 3 / 2
            )));

            match select3(&mut recv, &mut session_removed, &mut timeout).await {
                Either3::First(mut packet) => {
                    packet.clear_on_drop(true);

                    self.check_no_pending_retrans(matter)?;

                    break Ok(RxMessage(packet));
                }
                Either3::Second(_) => {
                    // Session removed

                    // Bail out if it was ours
                    self.with_session(matter, |_| Ok(()))?;

                    // If not, go back waiting for a packet
                    continue;
                }
                Either3::Third(_) => {
                    // Timeout waiting for an answer from the other peer
                    Err(ErrorCode::RxTimeout)?;
                }
            };
        }
    }

    /// Gets access to the TX buffer of the Matter stack for constructing a new TX message.
    /// If the TX buffer is not available, the method will wait indefinitely until it becomes available.
    ///
    /// NOTE:
    /// This is a low-level method that leaves the re-transmission logic on the shoulders of the user.
    /// Therefore, prefer using `Exchange::sender`, `Exchange::send` or `Exchange::send_with` instead.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    async fn init_send<'a>(&self, matter: &'a Matter<'a>) -> Result<TxMessage<'a>, Error> {
        self.with_ctx(matter, |_, _| Ok(()))?;

        let transport_mgr = &matter.transport_mgr;

        let mut packet = transport_mgr
            .get_if(&transport_mgr.tx, |packet| {
                packet.buf.is_empty() || self.with_ctx(matter, |_, _| Ok(())).is_err()
            })
            .await;

        // TODO: Resizing might be a bit expensive with large buffers
        packet.buf.resize_default(MAX_TX_BUF_SIZE).unwrap();

        packet.clear_on_drop(true);

        let tx = TxMessage {
            exchange_id: *self,
            matter,
            packet,
        };

        self.with_ctx(matter, |_, _| Ok(()))?;

        Ok(tx)
    }

    /// Waits until the other side acknowledges the last message sent on this exchange,
    /// or until time for a re-transmission had come.
    ///
    /// If the last sent message was not using the MRP protocol, the method will return immediately with `TxOutcome::Done`.
    ///
    /// NOTE:
    /// This is a low-level method that leaves the re-transmission logic on the shoulders of the user.
    /// Therefore, prefer using `Exchange::sender`, `Exchange::send` or `Exchange::send_with` instead.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    async fn wait_tx<'a>(&self, matter: &'a Matter<'a>) -> Result<TxOutcome, Error> {
        if let Some(delay) = self.retrans_delay_ms(matter)? {
            let expired = Instant::now()
                .checked_add(Duration::from_millis(delay))
                .unwrap();

            loop {
                let mut notification = pin!(self.internal_wait_ack(matter));
                let mut session_removed = pin!(matter.transport_mgr.session_removed.wait());
                let mut timer = pin!(Timer::at(expired));

                if !matches!(
                    select3(&mut notification, &mut session_removed, &mut timer).await,
                    Either3::Second(_)
                ) {
                    break;
                }

                // Bail out if the removed session was ours
                self.with_session(matter, |_| Ok(()))?;
            }

            if self.retrans_delay_ms(matter)?.is_some() {
                Ok(TxOutcome::Retransmit)
            } else {
                Ok(TxOutcome::Done)
            }
        } else {
            Ok(TxOutcome::Done)
        }
    }

    fn accessor<'a>(&self, matter: &'a Matter<'a>) -> Result<Accessor<'a>, Error> {
        self.with_session(matter, |sess| {
            Ok(Accessor::for_session(sess, &matter.fabric_mgr))
        })
    }

    fn with_session<'a, F, T>(&self, matter: &'a Matter<'a>, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session) -> Result<T, Error>,
    {
        self.with_ctx(matter, |sess, _| f(sess))
    }

    fn with_ctx<'a, F, T>(&self, matter: &'a Matter<'a>, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session, usize) -> Result<T, Error>,
    {
        let mut session_mgr = matter.transport_mgr.session_mgr.borrow_mut();

        if let Some(session) = session_mgr.get(self.session_id()) {
            f(session, self.exchange_index())
        } else {
            warn!("Exchange {self}: No session");
            Err(ErrorCode::NoSession.into())
        }
    }

    async fn internal_wait_ack<'a>(&self, matter: &'a Matter<'a>) -> Result<(), Error> {
        let transport_mgr = &matter.transport_mgr;

        transport_mgr
            .get_if(&transport_mgr.rx, |_| {
                self.retrans_delay_ms(matter)
                    .map(|retrans| retrans.is_none())
                    .unwrap_or(true)
            })
            .await;

        self.with_ctx(matter, |_, _| Ok(()))
    }

    fn retrans_delay_ms<'a>(&self, matter: &'a Matter<'a>) -> Result<Option<u64>, Error> {
        self.with_ctx(matter, |sess, exch_index| {
            let exchange = sess.exchanges[exch_index].as_mut().unwrap();

            let mut jitter_rand = [0; 1];
            matter.rand()(&mut jitter_rand);

            Ok(exchange.retrans_delay_ms(jitter_rand[0]))
        })
    }

    fn check_no_pending_retrans<'a>(&self, matter: &'a Matter<'a>) -> Result<(), Error> {
        self.with_ctx(matter, |sess, exch_index| {
            let exchange = sess.exchanges[exch_index].as_mut().unwrap();

            if exchange.mrp.is_retrans_pending() {
                error!("Exchange {}: Retransmission pending", self.display(sess));
                Err(ErrorCode::InvalidState)?;
            }

            Ok(())
        })
    }

    fn pending_retrans<'a>(&self, matter: &'a Matter<'a>) -> Result<bool, Error> {
        Ok(self.retrans_delay_ms(matter)?.is_some())
    }

    fn pending_ack<'a>(&self, matter: &'a Matter<'a>) -> Result<bool, Error> {
        self.with_ctx(matter, |sess, exch_index| {
            let exchange = sess.exchanges[exch_index].as_ref().unwrap();

            Ok(exchange.mrp.is_ack_pending())
        })
    }
}

impl Display for ExchangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.session_id(), self.exchange_index())
    }
}

/// A display wrapper for `ExchangeId` which also displays
/// the packet session ID, packet peer session ID and packet exchange ID.
pub struct ExchangeIdDisplay<'a> {
    id: &'a ExchangeId,
    session: &'a Session,
}

impl Display for ExchangeIdDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.session.exchanges[self.id.exchange_index()].as_ref();

        if let Some(state) = state {
            write!(
                f,
                "{} [SID:{:x},RSID:{:x},EID:{:x}]",
                self.id,
                self.session.get_local_sess_id(),
                self.session.get_peer_sess_id(),
                state.exch_id
            )
        } else {
            // This should never happen, as that would mean we have invalid exchange index
            // but let's not crash when displaying that
            write!(f, "{}???", self.id)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
pub(crate) enum InitiatorState {
    #[default]
    Owned,
    Dropped,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
pub(crate) enum ResponderState {
    #[default]
    AcceptPending,
    Owned,
    Dropped,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub(crate) enum Role {
    Initiator(InitiatorState),
    Responder(ResponderState),
}

impl Role {
    pub fn is_dropped_state(&self) -> bool {
        match self {
            Self::Initiator(state) => *state == InitiatorState::Dropped,
            Self::Responder(state) => *state == ResponderState::Dropped,
        }
    }

    pub fn set_dropped_state(&mut self) {
        match self {
            Self::Initiator(state) => *state = InitiatorState::Dropped,
            Self::Responder(state) => *state = ResponderState::Dropped,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ExchangeState {
    pub(crate) exch_id: u16,
    pub(crate) role: Role,
    pub(crate) mrp: ReliableMessage,
}

impl ExchangeState {
    pub fn is_for_rx(&self, rx_proto: &ProtoHdr) -> bool {
        self.exch_id == rx_proto.exch_id
            && rx_proto.is_initiator() == matches!(self.role, Role::Responder(_))
    }

    pub fn post_recv(
        &mut self,
        rx_plain: &PlainHdr,
        rx_proto: &ProtoHdr,
        epoch: Epoch,
    ) -> Result<(), Error> {
        self.mrp.post_recv(rx_plain, rx_proto, epoch)?;

        Ok(())
    }

    pub fn pre_send(
        &mut self,
        tx_plain: &PlainHdr,
        tx_proto: &mut ProtoHdr,
        session_active_interval_ms: Option<u16>,
        session_idle_interval_ms: Option<u16>,
    ) -> Result<(), Error> {
        if matches!(self.role, Role::Initiator(_)) {
            tx_proto.set_initiator();
        } else {
            tx_proto.unset_initiator();
        }

        tx_proto.exch_id = self.exch_id;

        self.mrp.pre_send(
            tx_plain,
            tx_proto,
            session_active_interval_ms,
            session_idle_interval_ms,
        )
    }

    pub fn retrans_delay_ms(&mut self, jitter_rand: u8) -> Option<u64> {
        self.mrp
            .retrans
            .as_ref()
            .map(|retrans| retrans.delay_ms(jitter_rand))
    }
}

/// Meta-data when sending/receving messages via an Exchange.
/// Basically, the protocol ID, the protocol opcode and whether the message should be set in a reliable manner.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct MessageMeta {
    pub proto_id: u16,
    pub proto_opcode: u8,
    pub reliable: bool,
}

impl MessageMeta {
    // Create a new message meta-data instance
    pub const fn new(proto_id: u16, proto_opcode: u8, reliable: bool) -> Self {
        Self {
            proto_id,
            proto_opcode,
            reliable,
        }
    }

    /// Try to cast the protocol opcode to a specific type
    pub fn opcode<T: num::FromPrimitive>(&self) -> Result<T, Error> {
        num::FromPrimitive::from_u8(self.proto_opcode).ok_or(ErrorCode::InvalidOpcode.into())
    }

    /// Check if the protocol opcode is equal to a specific value
    pub fn check_opcode<T: num::FromPrimitive + PartialEq>(&self, opcode: T) -> Result<(), Error> {
        if self.opcode::<T>()? == opcode {
            Ok(())
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }

    /// Create an instance from a ProtoHdr instance
    pub fn from(proto: &ProtoHdr) -> Self {
        Self {
            proto_id: proto.proto_id,
            proto_opcode: proto.proto_opcode,
            reliable: proto.is_reliable(),
        }
    }

    /// Set the protocol ID and opcode into a ProtoHdr instance
    pub fn set_into(&self, proto: &mut ProtoHdr) {
        proto.proto_id = self.proto_id;
        proto.proto_opcode = self.proto_opcode;
        proto.set_vendor(None);

        if self.reliable {
            proto.set_reliable();
        } else {
            proto.unset_reliable();
        }
    }

    pub fn reliable(self, reliable: bool) -> Self {
        Self { reliable, ..self }
    }

    /// Utility method to check if the specific proto opcode in the instance is expecting a TLV payload.
    pub(crate) fn is_tlv(&self) -> bool {
        match self.proto_id {
            PROTO_ID_SECURE_CHANNEL => self
                .opcode::<secure_channel::common::OpCode>()
                .ok()
                .map(|op| op.is_tlv())
                .unwrap_or(false),
            PROTO_ID_INTERACTION_MODEL => self
                .opcode::<interaction_model::core::OpCode>()
                .ok()
                .map(|op| op.is_tlv())
                .unwrap_or(false),
            _ => false,
        }
    }

    /// Utility method to check if the protocol is Secure Channel, and the opcode is a standalone ACK (`MrpStandaloneAck`).
    pub(crate) fn is_standalone_ack(&self) -> bool {
        self.proto_id == PROTO_ID_SECURE_CHANNEL
            && self.proto_opcode == secure_channel::common::OpCode::MRPStandAloneAck as u8
    }

    /// Utility method to check if the protocol is Secure Channel, and the opcode is Status.
    pub(crate) fn is_sc_status(&self) -> bool {
        self.proto_id == PROTO_ID_SECURE_CHANNEL
            && self.proto_opcode == secure_channel::common::OpCode::StatusReport as u8
    }

    /// Utility method to check if the protocol is Secure Channel, and the opcode is a new session request.
    pub(crate) fn is_new_session(&self) -> bool {
        self.proto_id == PROTO_ID_SECURE_CHANNEL
            && (self.proto_opcode == secure_channel::common::OpCode::PBKDFParamRequest as u8
                || self.proto_opcode == secure_channel::common::OpCode::CASESigma1 as u8)
    }

    /// Utility method to check if the meta-data indicates a new exchange
    pub(crate) fn is_new_exchange(&self) -> bool {
        // Don't create new exchanges for standalone ACKs and for SC status codes
        !self.is_standalone_ack() && !self.is_sc_status()
    }
}

impl Display for MessageMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.proto_id {
            PROTO_ID_SECURE_CHANNEL => {
                if let Ok(opcode) = self.opcode::<secure_channel::common::OpCode>() {
                    write!(f, "SC::{:?}", opcode)
                } else {
                    write!(f, "SC::{:02x}", self.proto_opcode)
                }
            }
            PROTO_ID_INTERACTION_MODEL => {
                if let Ok(opcode) = self.opcode::<interaction_model::core::OpCode>() {
                    write!(f, "IM::{:?}", opcode)
                } else {
                    write!(f, "IM::{:02x}", self.proto_opcode)
                }
            }
            _ => write!(f, "{:02x}::{:02x}", self.proto_id, self.proto_opcode),
        }
    }
}

/// An RX message pending on an `Exchange` instance.
pub struct RxMessage<'a>(PacketAccess<'a, MAX_RX_BUF_SIZE>);

impl RxMessage<'_> {
    /// Get the meta-data of the pending message
    pub fn meta(&self) -> MessageMeta {
        MessageMeta::from(&self.0.header.proto)
    }

    /// Get the payload of the pending message
    pub fn payload(&self) -> &[u8] {
        &self.0.buf[self.0.payload_start..]
    }
}

/// Accessor to the TX message buffer of the underlying Matter transport stack.
///
/// This is used to construct a new TX message to be sent on an `Exchange` instance.
///
/// NOTE: It is strongly advised to use the `TxMessage` accessor in combination with the `Sender` utility,
/// which takes care of all message retransmission logic. Alternatively, one can use the
/// `Exchange::send` or `Exchange::send_with` which also take care of re-transmissions.
pub struct TxMessage<'a> {
    exchange_id: ExchangeId,
    matter: &'a Matter<'a>,
    packet: PacketAccess<'a, MAX_TX_BUF_SIZE>,
}

impl TxMessage<'_> {
    /// Get a reference to the payload buffer of the TX message being built
    pub fn payload(&mut self) -> &mut [u8] {
        &mut self.packet.buf[PacketHdr::HDR_RESERVE..MAX_TX_BUF_SIZE - PacketHdr::TAIL_RESERVE]
    }

    /// Complete and send a TX message by providing:
    /// - The payload size that was filled-in by user code in the payload buffer returned by `TxMessage::payload`
    /// - The TX message meta-data
    pub fn complete<M>(
        mut self,
        payload_start: usize,
        payload_end: usize,
        meta: M,
    ) -> Result<(), Error>
    where
        M: Into<MessageMeta>,
    {
        if payload_start > payload_end
            || payload_end > MAX_TX_BUF_SIZE - PacketHdr::HDR_RESERVE - PacketHdr::TAIL_RESERVE
        {
            Err(ErrorCode::Invalid)?;
        }

        let meta: MessageMeta = meta.into();

        self.packet.header.reset();

        meta.set_into(&mut self.packet.header.proto);

        let mut session_mgr = self.matter.transport_mgr.session_mgr.borrow_mut();

        let session = session_mgr
            .get(self.exchange_id.session_id())
            .ok_or(ErrorCode::NoSession)?;

        let (peer, retransmission) = session.pre_send(
            Some(self.exchange_id.exchange_index()),
            &mut self.packet.header,
            // NOTE: It is not entirely correct to use our own SAI/SII when sending to a peer,
            // as the peer might be slower than us
            //
            // However, given that for now `rs-matter` would be in the role of the device rather
            // than a controller, that's a good-enough approximation (i.e. if we are running on Thread,
            // the controller would either be running on Thread as well, or on a network faster than ours)
            self.matter.dev_det().sai,
            self.matter.dev_det().sii,
        )?;

        self.packet.peer = peer;

        info!(
            "\n<<SND {}\n      => {}",
            Packet::<0>::display(&self.packet.peer, &self.packet.header),
            if retransmission {
                "Re-sending"
            } else {
                "Sending"
            },
        );

        debug!(
            "{}",
            Packet::<0>::display_payload(
                &self.packet.header.proto,
                &self.packet.buf
                    [PacketHdr::HDR_RESERVE + payload_start..PacketHdr::HDR_RESERVE + payload_end]
            )
        );

        let packet = &mut *self.packet;

        let mut writebuf = WriteBuf::new_with(
            &mut packet.buf,
            PacketHdr::HDR_RESERVE + payload_start,
            PacketHdr::HDR_RESERVE + payload_end,
        );
        session.encode(&packet.header, &mut writebuf)?;

        let encoded_payload_start = writebuf.get_start();
        let encoded_payload_end = writebuf.get_tail();

        self.packet.payload_start = encoded_payload_start;
        self.packet.buf.truncate(encoded_payload_end);
        self.packet.clear_on_drop(false);

        Ok(())
    }
}

/// Outcome from calling `Exchange::wait_tx`
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum TxOutcome {
    /// The other side has acknowledged the last message or the last message was not using the MRP protocol
    /// Stop re-sending.
    Done,
    /// Need to re-send the last message.
    Retransmit,
}

impl TxOutcome {
    /// Check if the outcome is `Done`
    pub const fn is_done(&self) -> bool {
        matches!(self, Self::Done)
    }
}

pub struct SenderTx<'a, 'b> {
    sender: &'b mut Sender<'a>,
    message: TxMessage<'a>,
}

impl SenderTx<'_, '_> {
    pub fn split(&mut self) -> (&Exchange<'_>, &mut [u8]) {
        (self.sender.exchange, self.message.payload())
    }

    pub fn payload(&mut self) -> &mut [u8] {
        self.message.payload()
    }

    pub fn complete(
        self,
        payload_start: usize,
        payload_end: usize,
        meta: MessageMeta,
    ) -> Result<(), Error> {
        self.message.complete(payload_start, payload_end, meta)?;

        self.sender.initial = false;

        Ok(())
    }
}

/// Utility struct for sending a message with potential retransmissions.
pub struct Sender<'a> {
    exchange: &'a Exchange<'a>,
    initial: bool,
    complete: bool,
}

impl<'a> Sender<'a> {
    fn new(exchange: &'a Exchange<'a>) -> Result<Self, Error> {
        exchange.id.check_no_pending_retrans(exchange.matter)?;

        Ok(Self {
            exchange,
            initial: true,
            complete: false,
        })
    }

    /// Get the TX buffer of the underlying Matter stack for (re)constructing a new TX message,
    /// waiting for the TX buffer to become available, if it is not.
    ///
    /// If the method returns `None`, it means that the message was already acknowledged by the other side,
    /// or that the message does not need acknowledgement and re-transmissions.
    ///
    /// When called for the first time, the method will always return a `Some` value, as the message has not been sent even once yet.
    /// Once the method returns `None`, it will always return `None` on subsequent calls, as the message has been acknowledged by the other side.
    ///
    /// Example:
    /// ```ignore
    /// let exchange = ...;
    ///
    /// let sender = exchange.sender()?;
    ///
    /// while let Some(mut tx) = sender.tx().await? {
    ///     let (exchange, payload) = tx.split()?;
    ///
    ///     // Write the message payload in the `payload` `&mut [u8]` slice
    ///     // On every iteration of the loop, write the _same_ payload (as message re-transmission is idempotent w.r.t. the message)
    ///     ...
    ///
    ///     // Complete the payload by providing `MessageMeta`, payload start and payload end
    ///     // On every iteration of the loop, proide the _same_ meta-data (as message re-transmission is idempotent w.r.t. the message)
    ///     let meta = ...;
    ///     let payload_start = ...;
    ///     let payload_end = ...;
    ///
    ///     tx.complete(payload_start, payload_end, meta)?;
    /// }
    /// ```
    pub async fn tx(&mut self) -> Result<Option<SenderTx<'a, '_>>, Error> {
        if self.complete {
            return Ok(None);
        }

        if !self.initial
            && self
                .exchange
                .id
                .wait_tx(self.exchange.matter)
                .await?
                .is_done()
        {
            // No need to re-transmit
            self.complete = true;
            return Ok(None);
        }

        let id = self.exchange.id;
        let matter = self.exchange.matter;

        let tx = id.init_send(matter).await?;

        if self.initial || id.pending_retrans(matter)? {
            Ok(Some(SenderTx {
                sender: self,
                message: tx,
            }))
        } else {
            self.complete = true;
            Ok(None)
        }
    }
}

/// An exchange within a Matter stack, representing a session and an exchange within that session.
///
/// This is the main API for sending and receiving messages within the Matter stack.
/// Used by upper-level layers like the Secure Channel and Interaction Model.
pub struct Exchange<'a> {
    id: ExchangeId,
    matter: &'a Matter<'a>,
    rx: Option<RxMessage<'a>>,
}

impl<'a> Exchange<'a> {
    pub(crate) const fn new(id: ExchangeId, matter: &'a Matter<'a>) -> Self {
        Self {
            id,
            matter,
            rx: None,
        }
    }

    /// Get the Id of the exchange
    pub fn id(&self) -> ExchangeId {
        self.id
    }

    /// Get the Matter stack instance associated with this exchange
    pub fn matter(&self) -> &'a Matter<'a> {
        self.matter
    }

    /// Create a new initiator exchange on the provided Matter stack for the provided peer Node ID.
    ///
    /// For now, this method will fail if there is no existing session in the provided Matter stack
    /// for the provided peer Node ID.
    ///
    /// In future, this method will do an mDNS lookup and create a new session on its own.
    #[inline(always)]
    pub async fn initiate(
        matter: &'a Matter<'a>,
        fabric_idx: u8,
        peer_node_id: u64,
        secure: bool,
    ) -> Result<Self, Error> {
        matter
            .transport_mgr
            .initiate(matter, fabric_idx, peer_node_id, secure)
            .await
    }

    /// Create a new initiator exchange on the provided Matter stack for the provided session ID.
    #[inline(always)]
    pub fn initiate_for_session(matter: &'a Matter<'a>, session_id: u32) -> Result<Self, Error> {
        matter
            .transport_mgr
            .initiate_for_session(matter, session_id)
    }

    /// Accepts a new responder exchange pending on the provided Matter stack.
    ///
    /// If there is no new pending responder exchange, the method will wait indefinitely until one appears.
    #[inline(always)]
    pub async fn accept(matter: &'a Matter<'a>) -> Result<Self, Error> {
        Self::accept_after(matter, 0).await
    }

    /// Accepts a new responder exchange pending on the provided Matter stack, but only if the
    /// pending exchange was pending for longer than `received_timeout_ms`.
    ///
    /// If there is no new pending responder exchange, the method will wait indefinitely until one appears.
    pub async fn accept_after(
        matter: &'a Matter<'a>,
        received_timeout_ms: u32,
    ) -> Result<Self, Error> {
        if received_timeout_ms > 0 {
            let epoch = matter.epoch();

            loop {
                let mut accept = pin!(matter.transport_mgr.accept_if(matter, |_, exch, _| {
                    exch.mrp.has_rx_timed_out(received_timeout_ms as _, epoch)
                }));

                let mut timer = pin!(Timer::after(embassy_time::Duration::from_millis(
                    received_timeout_ms as u64
                )));

                if let Either::First(exchange) = select(&mut accept, &mut timer).await {
                    break exchange;
                }
            }
        } else {
            matter.transport_mgr.accept_if(matter, |_, _, _| true).await
        }
    }

    /// Get access to the pending RX message on this exchange, and consume it when the returned `RxMessage` instance is dropped.
    ///
    /// If there is no pending RX message, the method will wait indefinitely until one appears.
    ///
    /// Note that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    #[inline(always)]
    pub async fn recv(&mut self) -> Result<RxMessage<'_>, Error> {
        self.recv_fetch().await?;

        self.rx.take().ok_or(ErrorCode::InvalidState.into())
    }

    /// Get access to the pending RX message on this exchange, and consume it
    /// by copying the payload into the provided `WriteBuf` instance.
    ///
    /// A syntax sugar for calling ```self.recv().await?``` and then copying the payload.
    ///
    /// Returns the exchange message meta-data.
    ///
    /// If there is no pending RX message, the method will wait indefinitely until one appears.
    ///
    /// If there is already a pending RX message, which was already fetched using `Exchange::recv_fetch` and that
    /// message is not cleared yet using `Exchange::rx_done` or via some of the `Exchange::send*` methods,
    /// the method will return that message.
    ///
    /// Note that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    #[inline(always)]
    pub async fn recv_into(&mut self, wb: &mut WriteBuf<'_>) -> Result<MessageMeta, Error> {
        let rx = self.recv().await?;

        wb.reset();
        wb.append(rx.payload())?;

        Ok(rx.meta())
    }

    /// Return a _reference_ to the pending RX message on this exchange.
    ///
    /// If there is no pending RX message, the method will wait indefinitely until one appears.
    ///
    /// Unlike `recv` which returns the actual message object which - when dropped - allows the transport to
    /// fetch the _next_ RX message for this or other exchanges, `recv_fetch` keeps the received message around,
    /// which is convenient when the message needs to be examined / processed by multiple layers of application code.
    ///
    /// Note however that this does not come for free - keeping the RX message around means that the transport cannot receive
    /// _other_ RX messages which blocks the whole transport layer, as the transport layer uses a single RX message buffer.
    ///
    /// Therefore, calling `recv_fetch` should be done with care and the message should be marked as processed (and thus dropped) -
    /// via `rx_done` as soon as possible, ideally without `await`-ing between `recv_fetch` and `rx_done`
    ///
    /// Note that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    #[inline(always)]
    pub async fn recv_fetch(&mut self) -> Result<&RxMessage<'a>, Error> {
        if self.rx.is_none() {
            let rx = self.id.recv(self.matter).await?;

            self.rx = Some(rx);
        }

        self.rx()
    }

    /// Returns the RX message which was already fetched using a previous call to `recv_fetch`.
    /// If there is no fetched RX message, the method will fail with `ErrorCode::InvalidState`.
    ///
    /// This method only exists as a slight optimization for the cases where the user is sure, that there is
    /// an RX message already fetched with `recv_fetch`, as - unlike `recv_fetch` - this method does not `await` and hence
    /// variables used after calling `rx` do not have to be stored in the generated future.
    ///
    /// But in general and putting optimizations aside, it is always safe to replace calls to `rx` with calls to `recv_fetch`.
    #[inline(always)]
    pub fn rx(&self) -> Result<&RxMessage<'a>, Error> {
        self.rx.as_ref().ok_or(ErrorCode::InvalidState.into())
    }

    /// Clears the RX message which was already fetched using a previous call to `recv_fetch`.
    /// If there is no fetched RX message, the method will do nothing.
    #[inline(always)]
    pub fn rx_done(&mut self) -> Result<(), Error> {
        self.rx = None;

        Ok(())
    }

    /// Gets access to the TX buffer of the Matter stack for constructing a new TX message.
    /// If the TX buffer is not available, the method will wait indefinitely until it becomes available.
    ///
    /// NOTE:
    /// This is a low-level method that leaves the re-transmission logic on the shoulders of the user.
    /// Therefore, prefer using `Exchange::sender`, `Exchange::send` or `Exchange::send_with` instead.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    #[inline(always)]
    pub async fn init_send(&mut self) -> Result<TxMessage<'_>, Error> {
        self.rx = None;

        self.id.init_send(self.matter).await
    }

    /// Waits until the other side acknowledges the last message sent on this exchange,
    /// or until time for a re-transmission had come.
    ///
    /// If the last sent message was not using the MRP protocol, the method will return immediately with `TxOutcome::Done`.
    ///
    /// NOTE:
    /// This is a low-level method that leaves the re-transmission logic on the shoulders of the user.
    /// Therefore, prefer using `Exchange::sender`, `Exchange::send` or `Exchange::send_with` instead.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    #[inline(always)]
    pub async fn wait_tx(&mut self) -> Result<TxOutcome, Error> {
        self.rx = None;

        self.id.wait_tx(self.matter).await
    }

    /// Returns `true` if there is a pending message re-transmission.
    /// A re-transmission will be pending if the last sent message was using the MRP protocol, and
    /// an acknowledgement for the other side is still pending.
    ///
    /// NOTE:
    /// This is a low-level method that leaves the re-transmission logic on the shoulders of the user.
    /// Therefore, prefer using `Exchange::sender`, `Exchange::send` or `Exchange::send_with` instead.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    pub fn pending_retrans(&self) -> Result<bool, Error> {
        self.id.pending_retrans(self.matter)
    }

    /// Returns `true` if there is a pending message acknowledgement.
    /// An acknowledgement be pending if the last received message was using the MRP protocol, and we have to acknowledge it.
    ///
    /// NOTE:
    /// This is a low-level method that leaves the re-transmission logic on the shoulders of the user.
    /// Therefore, prefer using `Exchange::sender`, `Exchange::send` or `Exchange::send_with` instead.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    pub fn pending_ack(&self) -> Result<bool, Error> {
        self.id.pending_ack(self.matter)
    }

    /// Acknowledge the last message received on this exchange (by sending a `MrpStandaloneAck`).
    ///
    /// If the last message was already acknowledged
    /// (either by a previous call to this method, by piggy-backing on a reliable message, or by the Matter stack itself),
    /// this method does nothing.
    ///
    /// Note that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    #[inline(always)]
    pub async fn acknowledge(&mut self) -> Result<(), Error> {
        if self.pending_ack()? {
            self.send_with(|exchange, _| {
                Ok(exchange
                    .pending_ack()?
                    .then_some(secure_channel::common::OpCode::MRPStandAloneAck.into()))
            })
            .await?;
        }

        Ok(())
    }

    /// Utility for sending a message on this exchange that automatically handles all re-transmission logic
    /// in case the constructed message needs to be send reliably.
    ///
    /// Note that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    pub fn sender(&mut self) -> Result<Sender<'_>, Error> {
        self.rx = None;

        Sender::new(self)
    }

    /// Utility for sending a message on this exchange that automatically handles all re-transmission logic
    /// in case the constructed message needs to be send reliably.
    ///
    /// The message is constructed by the provided closure, which is given a `WriteBuf` instance to write the message payload into.
    ///
    /// Note that the closure is expected to construct the exact same message when called multiple times.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    pub async fn send_with<F>(&mut self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(&Exchange, &mut WriteBuf) -> Result<Option<MessageMeta>, Error>,
    {
        let mut sender = self.sender()?;

        while let Some(mut tx) = sender.tx().await? {
            let (exchange, payload) = tx.split();

            let mut wb = WriteBuf::new(payload);

            if let Some(meta) = f(exchange, &mut wb)? {
                let payload_start = wb.get_start();
                let payload_end = wb.get_tail();
                tx.complete(payload_start, payload_end, meta)?;
            } else {
                // Closure aborted sending
                break;
            }
        }

        Ok(())
    }

    /// Send the provided exchange meta-data and payload as part of this exchange.
    ///
    /// If the provided exchange meta-data indicates a reliable message, the message will be automatically re-transmitted until
    /// the other side acknowledges it.
    ///
    /// Note that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    pub async fn send<M>(&mut self, meta: M, payload: &[u8]) -> Result<(), Error>
    where
        M: Into<MessageMeta>,
    {
        let meta = meta.into();

        self.send_with(|_, wb| {
            wb.append(payload)?;

            Ok(Some(meta))
        })
        .await
    }

    pub(crate) fn accessor(&self) -> Result<Accessor<'a>, Error> {
        self.id.accessor(self.matter)
    }

    pub(crate) fn with_session<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session) -> Result<T, Error>,
    {
        self.id.with_session(self.matter, f)
    }

    pub(crate) fn with_ctx<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session, usize) -> Result<T, Error>,
    {
        self.id.with_ctx(self.matter, f)
    }
}

impl Drop for Exchange<'_> {
    fn drop(&mut self) {
        let closed = self.with_ctx(|sess, exch_index| Ok(sess.remove_exch(exch_index)));

        if !matches!(closed, Ok(true)) {
            self.matter.transport_mgr.dropped.notify();
        }
    }
}

impl Display for Exchange<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}
