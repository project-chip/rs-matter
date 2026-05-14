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

//! Interaction Model Client implementation.
//!
//! This module provides client-side functionality for sending IM requests
//! (Read, Write, Invoke) to Matter devices and processing their responses.

use either::Either;

pub use super::{AttrId, ClusterId, EndptId};

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVBuilderParent, TLVElement, TLVTag, TLVWrite, TagType, ToTLV};
use crate::transport::exchange::{Exchange, OwnedSender, OwnedSenderTx};

use super::{
    IMStatusCode, InvReqBuilder, InvokeResp, OpCode, ReadReqBuilder, ReportDataResp, StatusResp,
    TimedReq, WriteReqBuilder, WriteResp,
};

/// IM Client trait — extension over an [`Exchange`] that adds the
/// Matter Interaction Model client operations.
///
/// Implemented for [`Exchange<'a>`]; user code just `use`s this trait
/// to get method-syntax access on any exchange handle. Two flavours
/// of method live on this trait:
///
/// - `*_sender` — hands the caller a typed `*Sender` they drive
///   manually. Maximum control, full visibility into the retransmit
///   loop and chunked response iteration.
/// - `*_with` / `*_with_async` — takes a build closure that
///   writes the request straight into the TX buffer; the retransmit
///   loop is handled internally and the first response chunk is
///   handed back for the caller to iterate via `complete()`.
///
/// On top of these, the codegen-emitted per-cluster
/// `<ClusterName>Client<'a>` traits add high-level single-shot
/// methods (`<cluster>_<command>` / `<cluster>_<attr>_read` /
/// `<cluster>_<attr>_write`) that bake in the cluster/attr/cmd IDs
/// and the chunk-drain / status-to-error conversion for the common
/// case.
///
/// The trait sits over `Self: Into<Exchange<'a>>` so any type that
/// converts to an exchange can opt in via a one-line blanket impl;
/// `Exchange<'a>` itself implements `Into<Exchange<'a>>` for free via
/// the standard-library identity impl.
///
/// # Lifecycle
///
/// Every method **consumes** the exchange (`self` by value) — one
/// exchange is one IM transaction, end of story. After the method
/// returns, the exchange is closed and the slot is released; callers
/// wanting to issue another transaction must initiate a fresh
/// exchange.
pub trait ImClient<'a>: Sized + Into<Exchange<'a>> {
    /// Streaming counterpart to [`read_sender`](Self::read_sender).
    ///
    /// `build` is invoked with a typed
    /// [`ReadReqBuilder`] already opened on the outbound
    /// TX buffer; the closure must return the [the corresponding `*Sender`]
    /// produced by `ReadReqBuilder::end()` as the
    /// type-system proof that every container the builder opened has
    /// been closed. No intermediate `Vec<AttrPath>` is allocated.
    /// `on_report` is then invoked for each `ReportData` chunk the
    /// server returns; chunking flow control (ACK each chunk with
    /// `StatusResponse(SUCCESS)`, abort on callback error) is handled
    /// internally.
    ///
    /// `build` is `FnMut` and must be idempotent — the MRP layer may
    /// retransmit the request and re-invoke the closure with a fresh
    /// builder on each attempt. See
    /// [`write_with`](Self::write_with) for the rationale.
    ///
    /// `on_report` is `AsyncFnMut` so callers can `.await` while
    /// processing each chunk (e.g. forwarding values to an async
    /// sink, persisting them to KV, awaiting backpressure on a
    /// channel). The borrow of the chunk data is held across the
    /// await, but the rx buffer remains valid until the next chunk
    /// request, so this is safe.
    async fn read_with<B>(self, mut build: B) -> Result<ReadRespChunk<'a>, Error>
    where
        B: FnMut(ReadReqBuilder<ReadSender<'a>>) -> Result<ReadSender<'a>, Error>,
    {
        // Drives the retransmit loop on the caller's behalf
        // (build closure idempotency contract — same TLV bytes on
        // every call). First response chunk handed back; the caller
        // iterates further chunks via `chunk.complete()`.
        let mut sender = self.read_sender().await?;
        loop {
            match sender.tx().await? {
                TxOutcome::BuildRequest(builder) => {
                    sender = build(builder)?;
                }
                TxOutcome::GotResponse(chunk) => return Ok(chunk),
            }
        }
    }

    /// `read` entry point — sets up a [`ReadSender`] but does
    /// **no** I/O. The first call to [`ReadSender::tx`] yields the
    /// initial builder. See [`invoke_sender`](Self::invoke_sender) for the
    /// full pattern.
    async fn read_sender(self) -> Result<ReadSender<'a>, Error> {
        let exchange: Exchange<'a> = self.into();
        let sender = exchange.into_sender()?;
        Ok(ReadSender {
            state: ReadSenderState::Ready(sender),
        })
    }

    /// Streaming counterpart to [`write_sender`](Self::write_sender).
    ///
    /// Hands the caller a typed [`WriteReqBuilder`] already opened
    /// on the outgoing TX buffer and lets them stream the
    /// `WriteRequestMessage` directly. No intermediate `Vec`, no
    /// out-of-band payload buffer — every byte ends up in the TX
    /// buffer exactly once. This is what the power-user
    /// streaming client APIs use.
    ///
    /// The closure receives the message builder at typestate `0` and
    /// must return the [the corresponding `*Sender`] that
    /// `WriteReqBuilder::end()` produces — this is the
    /// type-system proof that the caller closed every container the
    /// builder opened (`.end()` on the array, then `.end()` on the
    /// message). Forgetting to close one is a compile error, not a
    /// runtime malformed-TLV bug.
    ///
    /// When `timed_timeout_ms` is `Some`, this method sends the
    /// `TimedRequest` handshake before the write — the caller's
    /// builder body should set `timed_request(true)` accordingly.
    ///
    /// # Idempotency requirement
    ///
    /// `build` is `FnMut` because Matter's reliable-messaging layer
    /// (MRP) may retransmit the request multiple times — each
    /// retransmit invokes the closure again on a fresh builder over
    /// a fresh TX buffer. The closure **must** produce the same TLV
    /// output on every call (i.e. its writes must be a pure function
    /// of any captured state, and that state must not be moved out /
    /// consumed by the first invocation). The typical idiomatic
    /// shape — build through the streaming
    /// `WriteReqBuilder` from values captured by
    /// reference — is naturally idempotent.
    async fn write_with<B>(
        self,
        timed_timeout_ms: Option<u16>,
        mut build: B,
    ) -> Result<WriteRespHandle<'a>, Error>
    where
        B: FnMut(WriteReqBuilder<WriteSender<'a>>) -> Result<WriteSender<'a>, Error>,
    {
        let mut sender = self.write_sender(timed_timeout_ms).await?;
        loop {
            match sender.tx().await? {
                TxOutcome::BuildRequest(builder) => {
                    sender = build(builder)?;
                }
                TxOutcome::GotResponse(handle) => return Ok(handle),
            }
        }
    }

    /// `write` entry point — sets up a [`WriteSender`]. If
    /// `timed_timeout_ms` is `Some`, performs the `TimedRequest`
    /// handshake first (the only I/O `write_sender` may do). The first
    /// call to [`WriteSender::tx`] yields the initial builder.
    async fn write_sender(self, timed_timeout_ms: Option<u16>) -> Result<WriteSender<'a>, Error> {
        let mut exchange: Exchange<'a> = self.into();
        if let Some(timeout_ms) = timed_timeout_ms {
            send_timed_request(&mut exchange, timeout_ms).await?;
        }
        let sender = exchange.into_sender()?;
        Ok(WriteSender {
            state: WriteSenderState::Ready(sender),
        })
    }

    /// `invoke` entry point — sets up an [`InvokeSender`] but
    /// does **no** I/O beyond an optional `TimedRequest` handshake
    /// (when `timed_timeout_ms` is `Some`). The first call to
    /// [`InvokeSender::tx`] yields the initial builder.
    ///
    /// This is the cornerstone of the IM client: closure-free,
    /// scratch-buffer-free, full user control over the retransmit
    /// loop. Higher-tier variants — closure-based
    /// ([`invoke_with`](Self::invoke_with)) and the snapshot-style
    /// [`invoke`](Self::invoke) — are layered on top of it.
    ///
    /// # Lifecycle
    ///
    /// 1. `let mut sender = exchange.invoke_sender(None).await?;`
    /// 2. `loop { match sender.tx().await? { TxOutcome::BuildRequest(b) => sender = build(b)?, TxOutcome::GotResponse(c) => break c } }`
    /// 3. `loop { let resp = chunk.response()?; …; match chunk.complete().await? { … } }`
    async fn invoke_sender(self, timed_timeout_ms: Option<u16>) -> Result<InvokeSender<'a>, Error> {
        let mut exchange: Exchange<'a> = self.into();
        if let Some(timeout_ms) = timed_timeout_ms {
            send_timed_request(&mut exchange, timeout_ms).await?;
        }
        let sender = exchange.into_sender()?;
        Ok(InvokeSender {
            state: InvokeSenderState::Ready(sender),
        })
    }

    /// Streaming counterpart to [`invoke_sender`](Self::invoke_sender).
    ///
    /// Hands the caller a typed [`InvReqBuilder`] already opened on
    /// the outbound TX buffer and lets them stream the
    /// `InvokeRequestMessage` directly. The closure must return the
    /// [`InvokeSender`] produced by `InvReqBuilder::end()` as the
    /// type-system proof of completeness. This is the MCU-friendly
    /// path for client clusters that send commands — the typed
    /// request-builder writes straight into the TX buffer, no
    /// out-of-band payload buffer needed.
    ///
    /// `build` is `FnMut` and must be idempotent — the MRP layer may
    /// retransmit the request and re-invoke the closure with a fresh
    /// builder on each attempt.
    ///
    /// `on_response` is invoked per `InvokeResponseMessage` chunk
    /// (see Matter Core spec §10.7.10 for when invoke responses
    /// chunk); chunking flow control is handled internally.
    /// `on_response` is `AsyncFnMut` — see [`read_with`](Self::read_with)
    /// for the rationale.
    async fn invoke_with<B>(
        self,
        timed_timeout_ms: Option<u16>,
        mut build: B,
    ) -> Result<InvokeRespChunk<'a>, Error>
    where
        B: FnMut(InvReqBuilder<InvokeSender<'a>>) -> Result<InvokeSender<'a>, Error>,
    {
        // Drives the retransmit loop on the caller's behalf:
        // the `build` closure is (re-)run on every framework attempt
        // (so it must remain idempotent — same TLV bytes on every
        // call), and the first response chunk is returned to the
        // caller for direct inspection / `complete()` iteration.
        let mut sender = self.invoke_sender(timed_timeout_ms).await?;
        loop {
            match sender.tx().await? {
                TxOutcome::BuildRequest(builder) => {
                    sender = build(builder)?;
                }
                TxOutcome::GotResponse(chunk) => return Ok(chunk),
            }
        }
    }
}

/// Blanket impl so any [`Exchange<'a>`] is an [`ImClient<'a>`] when
/// the trait is `use`d. The default-method bodies do all the work;
/// this impl just opts the type in.
impl<'a> ImClient<'a> for Exchange<'a> {}

/// Outcome of calling `.tx()` on a transaction sender (`*Sender`).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TxOutcome<F, S> {
    /// Framework needs the request bytes (re-)built into a fresh TX slot;
    BuildRequest(F),
    /// Framework has received the peer's ACK; here's the first response chunk.
    GotResponse(S),
}

// =====================================================================
// Transaction types for the `read` opcode.
//
// Mirrors the `invoke` set: `ReadSender` drives the MRP retransmit
// loop; the codegen `ReadReqBuilder` writes through `ReadSenderSlot`
// while the slot is live; `ReadRespChunk` gives chunk-by-chunk
// access to the resulting `ReportData` stream.
// =====================================================================

/// Cornerstone `read` transaction. See module docs for the
/// pattern. Returned by [`ImClient::read_sender`].
pub struct ReadSender<'a> {
    state: ReadSenderState<'a>,
}

enum ReadSenderState<'a> {
    Ready(OwnedSender<'a>),
    Slot(ReadSenderSlot<'a>),
}

impl<'a> ReadSender<'a> {
    /// Drive one round of the MRP retransmit loop. See
    /// [`InvokeSender::tx`] for the full contract; the read variant is
    /// identical except the right arm holds a [`ReadRespChunk`].
    pub async fn tx(
        mut self,
    ) -> Result<TxOutcome<ReadReqBuilder<ReadSender<'a>>, ReadRespChunk<'a>>, Error> {
        let sender = match self.state {
            ReadSenderState::Slot(slot) => slot.commit()?,
            ReadSenderState::Ready(s) => s,
        };

        match sender.tx().await? {
            Either::Left(tx) => {
                self.state = ReadSenderState::Slot(ReadSenderSlot { tx, cursor: 0 });
                let builder = ReadReqBuilder::new(self, &TLVTag::Anonymous)?;
                Ok(TxOutcome::BuildRequest(builder))
            }
            Either::Right(exchange) => Ok(TxOutcome::GotResponse(
                ReadRespChunk::receive(exchange).await?,
            )),
        }
    }
}

impl<'a> TLVBuilderParent for ReadSender<'a> {
    type Write = ReadSenderSlot<'a>;

    fn writer(&mut self) -> &mut Self::Write {
        match &mut self.state {
            ReadSenderState::Slot(slot) => slot,
            ReadSenderState::Ready(_) => panic!(
                "ReadSender::writer() called outside the build phase — \
                 only reachable via a ReadReqBuilder yielded by ReadSender::tx."
            ),
        }
    }
}

impl<'a> core::fmt::Debug for ReadSender<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ReadSender")
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for ReadSender<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "ReadSender")
    }
}

/// Internal serialization handle for the in-flight build of a
/// [`ReadSender`]. See [`InvokeSenderSlot`] for the design rationale —
/// this type exists only because [`TLVBuilderParent`] requires the
/// `Write` associated type to be a named type.
pub struct ReadSenderSlot<'a> {
    tx: OwnedSenderTx<'a>,
    cursor: usize,
}

impl<'a> ReadSenderSlot<'a> {
    fn commit(self) -> Result<OwnedSender<'a>, Error> {
        self.tx.complete(0, self.cursor, OpCode::ReadRequest.into())
    }
}

impl<'a> TLVWrite for ReadSenderSlot<'a> {
    type Position = usize;

    fn write(&mut self, byte: u8) -> Result<(), Error> {
        let payload = self.tx.payload();
        if self.cursor >= payload.len() {
            return Err(ErrorCode::NoSpace.into());
        }
        payload[self.cursor] = byte;
        self.cursor += 1;
        Ok(())
    }

    fn get_tail(&self) -> Self::Position {
        self.cursor
    }

    fn rewind_to(&mut self, pos: Self::Position) {
        self.cursor = pos;
    }
}

impl<'a> core::fmt::Debug for ReadSenderSlot<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ReadSenderSlot({})", self.cursor)
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for ReadSenderSlot<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "ReadSenderSlot({})", self.cursor)
    }
}

/// First (possibly only) response chunk of a `read`
/// transaction. Returned by [`ReadSender::tx`] once the peer has ACK-ed
/// the request and the first `ReportData` chunk is parsed.
///
/// Multi-chunk `ReportData` streams iterate via
/// [`complete`](Self::complete) — same shape as [`InvokeRespChunk`].
pub struct ReadRespChunk<'a> {
    exchange: Exchange<'a>,
}

impl<'a> ReadRespChunk<'a> {
    async fn receive(mut exchange: Exchange<'a>) -> Result<Self, Error> {
        exchange.recv_fetch().await?;
        {
            let rx = exchange.rx()?;
            check_opcode(rx.meta().proto_opcode, OpCode::ReportData)?;
        }
        Ok(Self { exchange })
    }

    /// Borrowed access to the parsed `ReportDataResp` for this chunk.
    pub fn response(&self) -> Result<ReportDataResp<'_>, Error> {
        let rx = self.exchange.rx()?;
        let element = TLVElement::new(rx.payload());
        ReportDataResp::from_tlv(&element)
    }

    /// ACK the current chunk; if `more_chunks=true`, fetch + parse
    /// the next chunk and return it as `Some(next)`. Otherwise drop
    /// the exchange and return `None`.
    pub async fn complete(mut self) -> Result<Option<Self>, Error> {
        let (more_chunks, suppress_response) = {
            let resp = self.response()?;
            (
                resp.more_chunks.unwrap_or(false),
                resp.suppress_response.unwrap_or(false),
            )
        };

        if more_chunks {
            // Request next chunk.
            self.exchange
                .send_with(|_, wb| {
                    StatusResp::write(wb, IMStatusCode::Success)?;
                    Ok(Some(OpCode::StatusResponse.into()))
                })
                .await?;

            self.exchange.recv_fetch().await?;
            {
                let rx = self.exchange.rx()?;
                check_opcode(rx.meta().proto_opcode, OpCode::ReportData)?;
            }

            Ok(Some(self))
        } else {
            if !suppress_response {
                self.exchange
                    .send_with(|_, wb| {
                        StatusResp::write(wb, IMStatusCode::Success)?;
                        Ok(Some(OpCode::StatusResponse.into()))
                    })
                    .await?;
            } else {
                self.exchange.acknowledge().await?;
            }
            Ok(None)
        }
    }
}

// =====================================================================
// Transaction types for the `write` opcode.
//
// Mirrors the `invoke` / `read` sets. `WriteResponseMessage`
// is single-message per spec (no chunking), so the receive side has
// a [`WriteRespHandle`] with just a [`response()`](WriteRespHandle::response)
// method — no `complete()` iteration.
// =====================================================================

/// Cornerstone `write` transaction. See module docs for the
/// pattern. Returned by [`ImClient::write_sender`].
pub struct WriteSender<'a> {
    state: WriteSenderState<'a>,
}

enum WriteSenderState<'a> {
    Ready(OwnedSender<'a>),
    Slot(WriteSenderSlot<'a>),
}

impl<'a> WriteSender<'a> {
    /// Drive one round of the MRP retransmit loop. Mirrors
    /// [`InvokeSender::tx`] / [`ReadSender::tx`] except the right arm
    /// returns a [`WriteRespHandle`] (no chunking on write).
    pub async fn tx(
        mut self,
    ) -> Result<TxOutcome<WriteReqBuilder<WriteSender<'a>>, WriteRespHandle<'a>>, Error> {
        let sender = match self.state {
            WriteSenderState::Slot(slot) => slot.commit()?,
            WriteSenderState::Ready(s) => s,
        };

        match sender.tx().await? {
            Either::Left(tx) => {
                self.state = WriteSenderState::Slot(WriteSenderSlot { tx, cursor: 0 });
                let builder = WriteReqBuilder::new(self, &TLVTag::Anonymous)?;
                Ok(TxOutcome::BuildRequest(builder))
            }
            Either::Right(exchange) => Ok(TxOutcome::GotResponse(
                WriteRespHandle::receive(exchange).await?,
            )),
        }
    }
}

impl<'a> TLVBuilderParent for WriteSender<'a> {
    type Write = WriteSenderSlot<'a>;

    fn writer(&mut self) -> &mut Self::Write {
        match &mut self.state {
            WriteSenderState::Slot(slot) => slot,
            WriteSenderState::Ready(_) => panic!(
                "WriteSender::writer() called outside the build phase — \
                 only reachable via a WriteReqBuilder yielded by WriteSender::tx."
            ),
        }
    }
}

impl<'a> core::fmt::Debug for WriteSender<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WriteSender")
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for WriteSender<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "WriteSender")
    }
}

/// Internal serialization handle for the in-flight build of a
/// [`WriteSender`]. See [`InvokeSenderSlot`] for the design rationale.
pub struct WriteSenderSlot<'a> {
    tx: OwnedSenderTx<'a>,
    cursor: usize,
}

impl<'a> WriteSenderSlot<'a> {
    fn commit(self) -> Result<OwnedSender<'a>, Error> {
        self.tx
            .complete(0, self.cursor, OpCode::WriteRequest.into())
    }
}

impl<'a> TLVWrite for WriteSenderSlot<'a> {
    type Position = usize;

    fn write(&mut self, byte: u8) -> Result<(), Error> {
        let payload = self.tx.payload();
        if self.cursor >= payload.len() {
            return Err(ErrorCode::NoSpace.into());
        }
        payload[self.cursor] = byte;
        self.cursor += 1;
        Ok(())
    }

    fn get_tail(&self) -> Self::Position {
        self.cursor
    }

    fn rewind_to(&mut self, pos: Self::Position) {
        self.cursor = pos;
    }
}

impl<'a> core::fmt::Debug for WriteSenderSlot<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WriteSenderSlot({})", self.cursor)
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for WriteSenderSlot<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "WriteSenderSlot({})", self.cursor)
    }
}

/// Handle to the (single, non-chunked) response of a `write`
/// transaction. Returned by [`WriteSender::tx`] once the peer has
/// ACK-ed the request and the response is parsed.
///
/// Unlike [`InvokeRespChunk`] / [`ReadRespChunk`], `WriteResponse`
/// is a single message per Matter Core spec §10.7.6 — no chunk
/// iteration is needed; just call [`response`](Self::response) to
/// inspect the parsed [`WriteResp`].
pub struct WriteRespHandle<'a> {
    exchange: Exchange<'a>,
}

impl<'a> WriteRespHandle<'a> {
    async fn receive(mut exchange: Exchange<'a>) -> Result<Self, Error> {
        exchange.recv_fetch().await?;
        {
            let rx = exchange.rx()?;
            check_opcode(rx.meta().proto_opcode, OpCode::WriteResponse)?;
        }
        // ACK here (via standalone `acknowledge()`, not `send_with`)
        // because `send_with` would clear the RX buffer and break
        // zero-copy access from `response()` below.
        exchange.acknowledge().await?;
        Ok(Self { exchange })
    }

    /// Borrowed access to the parsed `WriteResp`. The returned value
    /// points into the exchange's RX buffer, which stays valid until
    /// this handle is dropped.
    pub fn response(&self) -> Result<WriteResp<'_>, Error> {
        let rx = self.exchange.rx()?;
        WriteResp::from_tlv(&TLVElement::new(rx.payload()))
    }
}

// =====================================================================
// Transaction types for the `invoke` opcode.
//
// `InvokeSender` is the cornerstone of the closure-free, scratch-buffer-
// free IM client. It owns the exchange end-to-end (via `OwnedSender`
// internally) and exposes a `tx().await` method that drives one
// round of the MRP retransmit loop. The user matches on the result:
//
// - `TxOutcome::BuildRequest(builder)` → (re-)build the request bytes via the
//   typestate builder; `.end()` returns the `InvokeSender` back for the
//   next round.
// - `TxOutcome::GotResponse(chunk)` → the request has been ACK-ed; here's
//   the first response chunk. Iterate via `chunk.complete().await`.
//
// Closure-based and scratch-buffer-based variants
// will be layered on top, mirroring how `Exchange::send_with` and
// `Exchange::send` are layered on top of `Exchange::sender`.
// =====================================================================

/// Cornerstone `invoke` transaction. See module docs for the
/// pattern. Returned by [`ImClient::invoke_sender`].
///
/// Public surface is intentionally narrow: a single async
/// [`tx`](Self::tx) method that drives one round of the MRP loop.
/// The TLV-serialization plumbing the codegen request builder uses
/// to fill the request bytes lives in a separate
/// [`InvokeSenderSlot`] type accessed via [`TLVBuilderParent::writer`],
/// so that `u8` / `start_struct` / etc. don't appear directly on
/// `InvokeSender` and tempt users to drive the TX buffer by hand.
pub struct InvokeSender<'a> {
    state: InvokeSenderState<'a>,
}

enum InvokeSenderState<'a> {
    /// Between rounds: own a sender, no slot. The first `tx()` call
    /// from this state acquires a slot and hands back a builder. The
    /// `n`-th call (n ≥ 1) here means the previous round's bytes are
    /// in flight; we wait for the next framework event.
    Ready(OwnedSender<'a>),
    /// During build: own a fully-prepared [`InvokeSenderSlot`] (TX slot
    /// plus cursor) that the codegen builder writes into via
    /// [`TLVBuilderParent::writer`]. The next `tx()` call commits
    /// `slot`'s bytes via [`OwnedSenderTx::complete`] and transitions
    /// back to `Ready`.
    Slot(InvokeSenderSlot<'a>),
}

impl<'a> InvokeSender<'a> {
    /// Drive one round of the MRP retransmit loop.
    ///
    /// - Returns `TxOutcome::BuildRequest(builder)` when the framework needs
    ///   the request bytes (re-)built into a fresh TX slot. The
    ///   builder's `P` parent is this `InvokeSender`; calling `.end()`
    ///   on the message builder hands the `InvokeSender` back, ready
    ///   for the next `tx()` call.
    /// - Returns `TxOutcome::GotResponse(chunk)` once the framework has
    ///   received the peer's ACK; iterate the chunk loop via
    ///   [`InvokeRespChunk::complete`].
    ///
    /// The first call after [`ImClient::invoke_sender`] is guaranteed
    /// to yield `TxOutcome::BuildRequest(builder)` because no message has been sent yet.
    pub async fn tx(
        mut self,
    ) -> Result<TxOutcome<InvReqBuilder<InvokeSender<'a>>, InvokeRespChunk<'a>>, Error> {
        // 1. If we're in Slot state, commit the bytes we just built.
        let sender = match self.state {
            InvokeSenderState::Slot(slot) => slot.commit()?,
            InvokeSenderState::Ready(s) => s,
        };

        // 2. Ask the framework for the next event.
        match sender.tx().await? {
            Either::Left(tx) => {
                // Re-build needed (initial or retransmit). Move to
                // Slot state and hand back a fresh builder.
                self.state = InvokeSenderState::Slot(InvokeSenderSlot { tx, cursor: 0 });
                let builder = InvReqBuilder::new(self, &TLVTag::Anonymous)?;
                Ok(TxOutcome::BuildRequest(builder))
            }
            Either::Right(exchange) => {
                // ACK received — fetch and parse the first response chunk.
                Ok(TxOutcome::GotResponse(
                    InvokeRespChunk::receive(exchange).await?,
                ))
            }
        }
    }
}

impl<'a> TLVBuilderParent for InvokeSender<'a> {
    type Write = InvokeSenderSlot<'a>;

    fn writer(&mut self) -> &mut Self::Write {
        match &mut self.state {
            InvokeSenderState::Slot(slot) => slot,
            // The only way to reach `writer()` on an `InvokeSender` is
            // through the codegen builder constructed inside
            // [`InvokeSender::tx`]'s `TxOutcome::BuildRequest` arm, which transitions to
            // `Slot` state before yielding the builder. Hitting this
            // branch means the invariant was violated externally —
            // panic rather than corrupt the TX buffer silently.
            InvokeSenderState::Ready(_) => panic!(
                "InvokeSender::writer() called outside the build phase \
                 (state = Ready); only reachable via an InvReqBuilder \
                 yielded by InvokeSender::tx — see module docs."
            ),
        }
    }
}

impl<'a> core::fmt::Debug for InvokeSender<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "InvokeSender")
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for InvokeSender<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "InvokeSender")
    }
}

/// Internal serialization handle for the in-flight build of an
/// [`InvokeSender`].
///
/// This type only exists because [`TLVBuilderParent`] requires the
/// `Write` associated type to be a named type (so the codegen request
/// builders can write through it). Users should not interact with it
/// directly — go through [`InvokeSender::tx`] and the typed
/// [`InvReqBuilder`] it returns.
///
/// Fields are private to enforce that the only way to drive
/// `cursor` forward is by writing TLV through the
/// [`TLVWrite`] impl below.
pub struct InvokeSenderSlot<'a> {
    tx: OwnedSenderTx<'a>,
    cursor: usize,
}

impl<'a> InvokeSenderSlot<'a> {
    /// Consume the slot — commit the bytes accumulated in `cursor`
    /// via [`OwnedSenderTx::complete`] and return the
    /// [`OwnedSender`] for the next retransmit-loop iteration.
    fn commit(self) -> Result<OwnedSender<'a>, Error> {
        self.tx
            .complete(0, self.cursor, OpCode::InvokeRequest.into())
    }
}

impl<'a> TLVWrite for InvokeSenderSlot<'a> {
    type Position = usize;

    fn write(&mut self, byte: u8) -> Result<(), Error> {
        let payload = self.tx.payload();
        if self.cursor >= payload.len() {
            return Err(ErrorCode::NoSpace.into());
        }
        payload[self.cursor] = byte;
        self.cursor += 1;
        Ok(())
    }

    /// Byte offset into the active TX-slot payload at which the next
    /// `write()` would land. Used by the derived `ToTLV` impls (and
    /// similar helpers) to mark a rollback anchor before composing a
    /// TLV structure.
    fn get_tail(&self) -> Self::Position {
        self.cursor
    }

    /// Roll the cursor back to a position previously returned by
    /// [`get_tail`]. Used by derived `ToTLV` impls to unwind a
    /// partially-written TLV structure on error.
    fn rewind_to(&mut self, pos: Self::Position) {
        self.cursor = pos;
    }
}

impl<'a> core::fmt::Debug for InvokeSenderSlot<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "InvokeSenderSlot({})", self.cursor)
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for InvokeSenderSlot<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "InvokeSenderSlot({})", self.cursor)
    }
}

/// First (possibly only) response chunk of an `invoke`
/// transaction. Returned by [`InvokeSender::tx`] once the peer has
/// ACK-ed the request.
///
/// The borrowed [`response`](Self::response) method gives zero-copy
/// access to the parsed [`InvokeResp`] backed by the exchange's RX
/// buffer; the buffer stays valid until [`complete`](Self::complete)
/// is called.
///
/// For multi-chunk responses (the server signals `more_chunks=true`),
/// [`complete`](Self::complete) returns `Some(next_chunk)` so the
/// caller can iterate; otherwise it returns `None` and drops the
/// exchange.
///
/// Per Matter Core spec §10.7.10, a server MAY reply to a command
/// declared with `DefaultSuccess` (no explicit response struct) by
/// sending a plain `StatusResponse(Success)` instead of a full
/// `InvokeResponse`. In that case the chunk is *status-only*:
/// [`response`](Self::response) returns `None`, and
/// [`complete`](Self::complete) is terminal (returns `None`).
pub struct InvokeRespChunk<'a> {
    exchange: Exchange<'a>,
    /// `true` when the peer replied with `StatusResponse(Success)`
    /// instead of a real `InvokeResponse` (DefaultSuccess commands).
    status_only: bool,
}

impl<'a> InvokeRespChunk<'a> {
    async fn receive(mut exchange: Exchange<'a>) -> Result<Self, Error> {
        exchange.recv_fetch().await?;
        let opcode = exchange.rx()?.meta().proto_opcode;

        if opcode == OpCode::InvokeResponse as u8 {
            Ok(Self {
                exchange,
                status_only: false,
            })
        } else if opcode == OpCode::StatusResponse as u8 {
            // DefaultSuccess command — server replied with a plain
            // StatusResponse. Translate non-Success codes to errors;
            // otherwise treat as an empty (status-only) chunk.
            let status = {
                let rx = exchange.rx()?;
                let element = TLVElement::new(rx.payload());
                StatusResp::from_tlv(&element)?.status
            };
            if status == IMStatusCode::Success {
                Ok(Self {
                    exchange,
                    status_only: true,
                })
            } else {
                error!("Invoke reply: StatusResponse({:?})", status);
                Err(status.to_error_code().unwrap_or(ErrorCode::Failure).into())
            }
        } else {
            Err(ErrorCode::InvalidOpcode.into())
        }
    }

    /// Whether the peer replied with `StatusResponse(Success)`
    /// (DefaultSuccess command) rather than a real `InvokeResponse`.
    /// In that case [`response`](Self::response) returns `None`.
    pub fn is_status_only(&self) -> bool {
        self.status_only
    }

    /// Borrowed access to the parsed `InvokeResp` for this chunk —
    /// `None` if the chunk is status-only (see [`is_status_only`]).
    /// The returned value points into the exchange's RX buffer, so
    /// its lifetime is the borrow of this `InvokeRespChunk`.
    pub fn response(&self) -> Result<Option<InvokeResp<'_>>, Error> {
        if self.status_only {
            return Ok(None);
        }
        let rx = self.exchange.rx()?;
        let element = TLVElement::new(rx.payload());
        InvokeResp::from_tlv(&element).map(Some)
    }

    /// ACK the current chunk and, if the server signalled
    /// `more_chunks=true`, fetch + parse the next chunk and return
    /// it as `Some(next)`. Otherwise (final chunk, or status-only)
    /// drop the exchange and return `None`.
    pub async fn complete(mut self) -> Result<Option<Self>, Error> {
        if self.status_only {
            // Status-only chunks are terminal — no chunking, no
            // additional StatusResponse round-trip needed. Just ACK
            // the message at the MRP layer and we're done.
            self.exchange.acknowledge().await?;
            return Ok(None);
        }

        let (more_chunks, suppress_response) = {
            let resp = self
                .response()?
                .expect("status_only checked above; response() must be Some");
            (
                resp.more_chunks.unwrap_or(false),
                resp.suppress_response.unwrap_or(false),
            )
        };

        if more_chunks {
            // Spec forbids suppress_response=true with more_chunks=true
            if suppress_response {
                send_abort(&mut self.exchange).await?;
                return Err(ErrorCode::InvalidData.into());
            }

            // Request next chunk.
            self.exchange
                .send_with(|_, wb| {
                    StatusResp::write(wb, IMStatusCode::Success)?;
                    Ok(Some(OpCode::StatusResponse.into()))
                })
                .await?;

            self.exchange.recv_fetch().await?;
            {
                let rx = self.exchange.rx()?;
                check_opcode(rx.meta().proto_opcode, OpCode::InvokeResponse)?;
            }

            Ok(Some(self))
        } else {
            if !suppress_response {
                self.exchange
                    .send_with(|_, wb| {
                        StatusResp::write(wb, IMStatusCode::Success)?;
                        Ok(Some(OpCode::StatusResponse.into()))
                    })
                    .await?;
            } else {
                self.exchange.acknowledge().await?;
            }
            Ok(None)
        }
    }
}

// =====================================================================
// Module-private helpers shared by trait default impls.
//
// The IM-client trait below has default-impl methods that drive each
// IM transaction end-to-end. They share several response-loop bodies
// (chunked-response handling for read/invoke, single-response handling
// for write, the timed-request handshake, the abort path); those live
// here as freestanding `pub(crate)` fns rather than trait methods so
// that we don't have to expose them as required trait items the way
// trait inheritance would force.
// =====================================================================

/// Send a timed-request handshake and wait for `StatusResponse(Success)`.
/// Used before timed writes/invokes.
async fn send_timed_request(exchange: &mut Exchange<'_>, timeout_ms: u16) -> Result<(), Error> {
    let req = TimedReq {
        timeout: timeout_ms,
    };

    exchange
        .send_with(|_, wb| {
            req.to_tlv(&TagType::Anonymous, wb)?;
            Ok(Some(OpCode::TimedRequest.into()))
        })
        .await?;

    exchange.recv_fetch().await?;

    let rx = exchange.rx()?;
    check_opcode(rx.meta().proto_opcode, OpCode::StatusResponse)?;

    let status_resp = StatusResp::from_tlv(&TLVElement::new(rx.payload()))?;
    if status_resp.status != IMStatusCode::Success {
        error!("TimedRequest failed with status: {:?}", status_resp.status);
        return Err(status_resp
            .status
            .to_error_code()
            .unwrap_or(ErrorCode::Failure)
            .into());
    }

    Ok(())
}

/// Abort a chunked transaction by sending `StatusResponse(Failure)`.
///
/// This tells the server we are not continuing the transaction, preventing
/// it from waiting indefinitely for the next `StatusResponse(Success)`.
async fn send_abort(exchange: &mut Exchange<'_>) -> Result<(), Error> {
    exchange
        .send_with(|_, wb| {
            StatusResp::write(wb, IMStatusCode::Failure)?;
            Ok(Some(OpCode::StatusResponse.into()))
        })
        .await
}

/// Check that the received opcode matches the expected one.
fn check_opcode(received: u8, expected: OpCode) -> Result<(), Error> {
    if received != expected as u8 {
        error!(
            "Unexpected IM opcode: received {}, expected {:?}",
            received, expected
        );
        Err(ErrorCode::InvalidOpcode.into())
    } else {
        Ok(())
    }
}
