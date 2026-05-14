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

pub use super::{AttrId, ClusterId, EndptId};

use either::Either as EitherIo;

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVBuilderParent, TLVElement, TLVTag, TLVWrite, TagType, ToTLV};
use crate::transport::exchange::{Exchange, OwnedSender, OwnedSenderTx};

use super::{
    AttrData, AttrDataTag, AttrPath, AttrResp, CmdData, CmdDataTag, CmdPath, CmdResp,
    DataVersionFilter, EventFilter, EventPath, IMStatusCode, InvReqBuilder, InvokeResp, OpCode,
    ReadReqBuilder, ReportDataResp, StatusResp, TimedReq, WriteReqBuilder, WriteResp,
};

/// Builder for constructing ReadRequest messages.
///
/// Corresponds to the `ReadRequestMessage` TLV structure in the Interaction Model.
#[derive(Debug, Clone, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct ReadRequestBuilder<'a> {
    /// Attribute paths to read
    pub attr_requests: Option<&'a [AttrPath]>,
    /// Event paths to read
    pub event_requests: Option<&'a [EventPath]>,
    /// Event filters
    pub event_filters: Option<&'a [EventFilter]>,
    /// Whether to filter by fabric
    pub fabric_filtered: bool,
    /// Data version filters for conditional reads
    pub dataver_filters: Option<&'a [DataVersionFilter]>,
}

impl<'a> ReadRequestBuilder<'a> {
    /// Create a new ReadRequestBuilder for reading attributes
    pub const fn attributes(attr_requests: &'a [AttrPath], fabric_filtered: bool) -> Self {
        Self {
            attr_requests: Some(attr_requests),
            event_requests: None,
            event_filters: None,
            fabric_filtered,
            dataver_filters: None,
        }
    }
}

/// Builder for constructing WriteRequest messages.
///
/// Corresponds to the `WriteRequestMessage` TLV structure in the Interaction Model.
#[derive(Debug, Clone, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct WriteRequestBuilder<'a> {
    /// Whether to suppress the response
    pub suppress_response: Option<bool>,
    /// Whether this is a timed request
    pub timed_request: Option<bool>,
    /// Attribute data to write
    pub write_requests: &'a [AttrData<'a>],
    /// Whether there are more chunks coming
    pub more_chunks: Option<bool>,
}

impl<'a> WriteRequestBuilder<'a> {
    /// Create a new WriteRequestBuilder
    pub const fn new(write_requests: &'a [AttrData<'a>], timed: bool) -> Self {
        Self {
            suppress_response: None,
            timed_request: if timed { Some(true) } else { None },
            write_requests,
            more_chunks: None,
        }
    }
}

/// Builder for constructing InvokeRequest messages.
///
/// Corresponds to the `InvokeRequestMessage` TLV structure in the Interaction Model.
#[derive(Debug, Clone, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct InvokeRequestBuilder<'a> {
    /// Whether to suppress the response
    pub suppress_response: Option<bool>,
    /// Whether this is a timed request
    pub timed_request: Option<bool>,
    /// Command invocations
    pub invoke_requests: &'a [CmdData<'a>],
}

impl<'a> InvokeRequestBuilder<'a> {
    /// Create a new InvokeRequestBuilder
    pub const fn new(invoke_requests: &'a [CmdData<'a>], timed: bool) -> Self {
        Self {
            // Matter 1.5 Core spec §8.8.5: `SuppressResponse` and
            // `TimedRequest` are mandatory fields of `InvokeRequestMessage`
            // and MUST be present on the wire. Encode them explicitly so
            // strictly-validating peers (e.g. SmartThings) accept the
            // request instead of rejecting it with `INVALID_ACTION`.
            suppress_response: Some(false),
            timed_request: Some(timed),
            invoke_requests,
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

// =====================================================================
// Tier-1 transaction types for the `invoke` opcode.
//
// `InvokeTxn` is the cornerstone of the closure-free, scratch-buffer-
// free IM client. It owns the exchange end-to-end (via `OwnedSender`
// internally) and exposes a `tx().await` method that drives one
// round of the MRP retransmit loop. The user matches on the result:
//
// - `EitherIo::Left(builder)` → (re-)build the request bytes via the
//   typestate builder; `.end()` returns the `InvokeTxn` back for the
//   next round.
// - `EitherIo::Right(chunk)` → the request has been ACK-ed; here's
//   the first response chunk. Iterate via `chunk.complete().await`.
//
// Tier-2 (closure-based) and tier-3 (scratch-buffer-based) variants
// will be layered on top, mirroring how `Exchange::send_with` and
// `Exchange::send` are layered on top of `Exchange::sender`.
// =====================================================================

/// Cornerstone tier-1 `invoke` transaction. See module docs for the
/// pattern. Returned by [`ImClient::invoke_txn`].
///
/// Public surface is intentionally narrow: a single async
/// [`tx`](Self::tx) method that drives one round of the MRP loop.
/// The TLV-serialization plumbing the codegen request builder uses
/// to fill the request bytes lives in a separate
/// [`InvokeTxnSlot`] type accessed via [`TLVBuilderParent::writer`],
/// so that `u8` / `start_struct` / etc. don't appear directly on
/// `InvokeTxn` and tempt users to drive the TX buffer by hand.
pub struct InvokeTxn<'a> {
    state: InvokeTxnState<'a>,
}

enum InvokeTxnState<'a> {
    /// Between rounds: own a sender, no slot. The first `tx()` call
    /// from this state acquires a slot and hands back a builder. The
    /// `n`-th call (n ≥ 1) here means the previous round's bytes are
    /// in flight; we wait for the next framework event.
    Ready(OwnedSender<'a>),
    /// During build: own a fully-prepared [`InvokeTxnSlot`] (TX slot
    /// plus cursor) that the codegen builder writes into via
    /// [`TLVBuilderParent::writer`]. The next `tx()` call commits
    /// `slot`'s bytes via [`OwnedSenderTx::complete`] and transitions
    /// back to `Ready`.
    Slot(InvokeTxnSlot<'a>),
}

impl<'a> InvokeTxn<'a> {
    /// Drive one round of the MRP retransmit loop.
    ///
    /// - Returns `EitherIo::Left(builder)` when the framework needs
    ///   the request bytes (re-)built into a fresh TX slot. The
    ///   builder's `P` parent is this `InvokeTxn`; calling `.end()`
    ///   on the message builder hands the `InvokeTxn` back, ready
    ///   for the next `tx()` call.
    /// - Returns `EitherIo::Right(chunk)` once the framework has
    ///   received the peer's ACK; iterate the chunk loop via
    ///   [`InvokeRespChunk::complete`].
    ///
    /// The first call after [`ImClient::invoke_txn`] is guaranteed
    /// to yield `Left(builder)` because no message has been sent yet.
    pub async fn tx(
        mut self,
    ) -> Result<EitherIo<InvReqBuilder<InvokeTxn<'a>, 0>, InvokeRespChunk<'a>>, Error> {
        // 1. If we're in Slot state, commit the bytes we just built.
        let sender = match self.state {
            InvokeTxnState::Slot(slot) => slot.commit()?,
            InvokeTxnState::Ready(s) => s,
        };

        // 2. Ask the framework for the next event.
        match sender.tx().await? {
            EitherIo::Left(tx) => {
                // Re-build needed (initial or retransmit). Move to
                // Slot state and hand back a fresh builder.
                self.state = InvokeTxnState::Slot(InvokeTxnSlot { tx, cursor: 0 });
                let builder = InvReqBuilder::new(self, &TLVTag::Anonymous)?;
                Ok(EitherIo::Left(builder))
            }
            EitherIo::Right(exchange) => {
                // ACK received — fetch and parse the first response chunk.
                Ok(EitherIo::Right(InvokeRespChunk::receive(exchange).await?))
            }
        }
    }
}

impl<'a> TLVBuilderParent for InvokeTxn<'a> {
    type Write = InvokeTxnSlot<'a>;

    fn writer(&mut self) -> &mut Self::Write {
        match &mut self.state {
            InvokeTxnState::Slot(slot) => slot,
            // The only way to reach `writer()` on an `InvokeTxn` is
            // through the codegen builder constructed inside
            // [`InvokeTxn::tx`]'s `Left` arm, which transitions to
            // `Slot` state before yielding the builder. Hitting this
            // branch means the invariant was violated externally —
            // panic rather than corrupt the TX buffer silently.
            InvokeTxnState::Ready(_) => panic!(
                "InvokeTxn::writer() called outside the build phase \
                 (state = Ready); only reachable via an InvReqBuilder \
                 yielded by InvokeTxn::tx — see module docs."
            ),
        }
    }
}

impl<'a> core::fmt::Debug for InvokeTxn<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "InvokeTxn")
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for InvokeTxn<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "InvokeTxn")
    }
}

/// Internal serialization handle for the in-flight build of an
/// [`InvokeTxn`].
///
/// This type only exists because [`TLVBuilderParent`] requires the
/// `Write` associated type to be a named type (so the codegen request
/// builders can write through it). Users should not interact with it
/// directly — go through [`InvokeTxn::tx`] and the typed
/// [`InvReqBuilder`] it returns.
///
/// Fields are private to enforce that the only way to drive
/// `cursor` forward is by writing TLV through the
/// [`TLVWrite`] impl below.
pub struct InvokeTxnSlot<'a> {
    tx: OwnedSenderTx<'a>,
    cursor: usize,
}

impl<'a> InvokeTxnSlot<'a> {
    /// Consume the slot — commit the bytes accumulated in `cursor`
    /// via [`OwnedSenderTx::complete`] and return the
    /// [`OwnedSender`] for the next retransmit-loop iteration.
    fn commit(self) -> Result<OwnedSender<'a>, Error> {
        self.tx
            .complete(0, self.cursor, OpCode::InvokeRequest.into())
    }
}

impl<'a> TLVWrite for InvokeTxnSlot<'a> {
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

impl<'a> core::fmt::Debug for InvokeTxnSlot<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "InvokeTxnSlot({})", self.cursor)
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for InvokeTxnSlot<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "InvokeTxnSlot({})", self.cursor)
    }
}

/// First (possibly only) response chunk of a tier-1 `invoke`
/// transaction. Returned by [`InvokeTxn::tx`] once the peer has
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
pub struct InvokeRespChunk<'a> {
    exchange: Exchange<'a>,
}

impl<'a> InvokeRespChunk<'a> {
    async fn receive(mut exchange: Exchange<'a>) -> Result<Self, Error> {
        exchange.recv_fetch().await?;
        {
            let rx = exchange.rx()?;
            check_opcode(rx.meta().proto_opcode, OpCode::InvokeResponse)?;
        }
        Ok(Self { exchange })
    }

    /// Borrowed access to the parsed `InvokeResp` for this chunk.
    /// The returned value points into the exchange's RX buffer, so
    /// its lifetime is the borrow of this `InvokeRespChunk`.
    pub fn response(&self) -> Result<InvokeResp<'_>, Error> {
        let rx = self.exchange.rx()?;
        let element = TLVElement::new(rx.payload());
        InvokeResp::from_tlv(&element)
    }

    /// ACK the current chunk and, if the server signalled
    /// `more_chunks=true`, fetch + parse the next chunk and return
    /// it as `Some(next)`. Otherwise (final chunk) drop the exchange
    /// and return `None`.
    pub async fn complete(mut self) -> Result<Option<Self>, Error> {
        let (more_chunks, suppress_response) = {
            let resp = self.response()?;
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
// Tier-1 transaction types for the `read` opcode.
//
// Mirrors the `invoke` tier-1 set: `ReadTxn` drives the MRP retransmit
// loop; the codegen `ReadReqBuilder` writes through `ReadTxnSlot`
// while the slot is live; `ReadRespChunk` gives chunk-by-chunk
// access to the resulting `ReportData` stream.
// =====================================================================

/// Cornerstone tier-1 `read` transaction. See module docs for the
/// pattern. Returned by [`ImClient::read_txn`].
pub struct ReadTxn<'a> {
    state: ReadTxnState<'a>,
}

enum ReadTxnState<'a> {
    Ready(OwnedSender<'a>),
    Slot(ReadTxnSlot<'a>),
}

impl<'a> ReadTxn<'a> {
    /// Drive one round of the MRP retransmit loop. See
    /// [`InvokeTxn::tx`] for the full contract; the read variant is
    /// identical except the right arm holds a [`ReadRespChunk`].
    pub async fn tx(
        mut self,
    ) -> Result<EitherIo<ReadReqBuilder<ReadTxn<'a>, 0>, ReadRespChunk<'a>>, Error> {
        let sender = match self.state {
            ReadTxnState::Slot(slot) => slot.commit()?,
            ReadTxnState::Ready(s) => s,
        };

        match sender.tx().await? {
            EitherIo::Left(tx) => {
                self.state = ReadTxnState::Slot(ReadTxnSlot { tx, cursor: 0 });
                let builder = ReadReqBuilder::new(self, &TLVTag::Anonymous)?;
                Ok(EitherIo::Left(builder))
            }
            EitherIo::Right(exchange) => {
                Ok(EitherIo::Right(ReadRespChunk::receive(exchange).await?))
            }
        }
    }
}

impl<'a> TLVBuilderParent for ReadTxn<'a> {
    type Write = ReadTxnSlot<'a>;

    fn writer(&mut self) -> &mut Self::Write {
        match &mut self.state {
            ReadTxnState::Slot(slot) => slot,
            ReadTxnState::Ready(_) => panic!(
                "ReadTxn::writer() called outside the build phase — \
                 only reachable via a ReadReqBuilder yielded by ReadTxn::tx."
            ),
        }
    }
}

impl<'a> core::fmt::Debug for ReadTxn<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ReadTxn")
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for ReadTxn<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "ReadTxn")
    }
}

/// Internal serialization handle for the in-flight build of a
/// [`ReadTxn`]. See [`InvokeTxnSlot`] for the design rationale —
/// this type exists only because [`TLVBuilderParent`] requires the
/// `Write` associated type to be a named type.
pub struct ReadTxnSlot<'a> {
    tx: OwnedSenderTx<'a>,
    cursor: usize,
}

impl<'a> ReadTxnSlot<'a> {
    fn commit(self) -> Result<OwnedSender<'a>, Error> {
        self.tx.complete(0, self.cursor, OpCode::ReadRequest.into())
    }
}

impl<'a> TLVWrite for ReadTxnSlot<'a> {
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

impl<'a> core::fmt::Debug for ReadTxnSlot<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ReadTxnSlot({})", self.cursor)
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for ReadTxnSlot<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "ReadTxnSlot({})", self.cursor)
    }
}

/// First (possibly only) response chunk of a tier-1 `read`
/// transaction. Returned by [`ReadTxn::tx`] once the peer has ACK-ed
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
// Tier-1 transaction types for the `write` opcode.
//
// Mirrors the `invoke` / `read` tier-1 sets. `WriteResponseMessage`
// is single-message per spec (no chunking), so the receive side has
// a [`WriteRespHandle`] with just a [`response()`](WriteRespHandle::response)
// method — no `complete()` iteration.
// =====================================================================

/// Cornerstone tier-1 `write` transaction. See module docs for the
/// pattern. Returned by [`ImClient::write_txn`].
pub struct WriteTxn<'a> {
    state: WriteTxnState<'a>,
}

enum WriteTxnState<'a> {
    Ready(OwnedSender<'a>),
    Slot(WriteTxnSlot<'a>),
}

impl<'a> WriteTxn<'a> {
    /// Drive one round of the MRP retransmit loop. Mirrors
    /// [`InvokeTxn::tx`] / [`ReadTxn::tx`] except the right arm
    /// returns a [`WriteRespHandle`] (no chunking on write).
    pub async fn tx(
        mut self,
    ) -> Result<EitherIo<WriteReqBuilder<WriteTxn<'a>, 0>, WriteRespHandle<'a>>, Error> {
        let sender = match self.state {
            WriteTxnState::Slot(slot) => slot.commit()?,
            WriteTxnState::Ready(s) => s,
        };

        match sender.tx().await? {
            EitherIo::Left(tx) => {
                self.state = WriteTxnState::Slot(WriteTxnSlot { tx, cursor: 0 });
                let builder = WriteReqBuilder::new(self, &TLVTag::Anonymous)?;
                Ok(EitherIo::Left(builder))
            }
            EitherIo::Right(exchange) => {
                Ok(EitherIo::Right(WriteRespHandle::receive(exchange).await?))
            }
        }
    }
}

impl<'a> TLVBuilderParent for WriteTxn<'a> {
    type Write = WriteTxnSlot<'a>;

    fn writer(&mut self) -> &mut Self::Write {
        match &mut self.state {
            WriteTxnState::Slot(slot) => slot,
            WriteTxnState::Ready(_) => panic!(
                "WriteTxn::writer() called outside the build phase — \
                 only reachable via a WriteReqBuilder yielded by WriteTxn::tx."
            ),
        }
    }
}

impl<'a> core::fmt::Debug for WriteTxn<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WriteTxn")
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for WriteTxn<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "WriteTxn")
    }
}

/// Internal serialization handle for the in-flight build of a
/// [`WriteTxn`]. See [`InvokeTxnSlot`] for the design rationale.
pub struct WriteTxnSlot<'a> {
    tx: OwnedSenderTx<'a>,
    cursor: usize,
}

impl<'a> WriteTxnSlot<'a> {
    fn commit(self) -> Result<OwnedSender<'a>, Error> {
        self.tx
            .complete(0, self.cursor, OpCode::WriteRequest.into())
    }
}

impl<'a> TLVWrite for WriteTxnSlot<'a> {
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

impl<'a> core::fmt::Debug for WriteTxnSlot<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WriteTxnSlot({})", self.cursor)
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for WriteTxnSlot<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "WriteTxnSlot({})", self.cursor)
    }
}

/// Handle to the (single, non-chunked) response of a tier-1 `write`
/// transaction. Returned by [`WriteTxn::tx`] once the peer has
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

/// IM Client trait — extension over an [`Exchange`] that adds the
/// Matter Interaction Model client operations.
///
/// Implemented for [`Exchange<'a>`]; user code just `use`s this trait
/// to get method-syntax access on any exchange handle:
///
/// ```ignore
/// use rs_matter::im::client::ImClient;
///
/// let exchange = Exchange::initiate(matter, fab, peer, true).await?;
/// let value = exchange
///     .read_single_attr(1, OnOff::ID, OnOff::ON_OFF_ATTR_ID, true, |resp| {
///         match resp {
///             AttrResp::Data(d) => d.data.bool(),
///             AttrResp::Status(s) => Err(s.status.to_error_code().unwrap().into()),
///         }
///     })
///     .await?;
/// ```
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
/// exchange. Methods that need to surface zero-copy response data
/// ([`write`](Self::write), [`read_single_attr`](Self::read_single_attr),
/// [`invoke_single_cmd`](Self::invoke_single_cmd)) take an
/// `FnOnce(Resp<'_>) -> Result<T, Error>` callback so the borrowed
/// response can be inspected before the exchange is dropped; the
/// callback's return value is propagated as owned `T`.
pub trait ImClient<'a>: Sized + Into<Exchange<'a>> {
    /// Read attributes from a device with full chunking support.
    ///
    /// This is the lowest-level read API. It supports wildcard paths and
    /// handles chunked responses automatically, invoking the callback once
    /// per chunk.
    ///
    /// # Callback lifetime constraints
    ///
    /// The callback receives `&ReportDataResp<'_>` where the lifetime is
    /// tied to the exchange's RX buffer for the current chunk. Because the
    /// buffer is invalidated between chunks, **only owned/`Copy` data can
    /// be extracted** from the callback. Borrowed data (e.g., `TLVElement`,
    /// byte slices from `AttrData`) cannot escape the callback.
    ///
    /// For single-attribute reads where you need zero-copy access to
    /// borrowed response data, use [`read_single_attr`](Self::read_single_attr)
    /// instead.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `attr_paths` - Attribute paths to read
    /// - `fabric_filtered` - Whether to filter results by fabric
    /// - `on_report` - Callback invoked for each ReportData chunk
    async fn read<F>(
        self,
        attr_paths: &[AttrPath],
        fabric_filtered: bool,
        mut on_report: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&ReportDataResp<'_>) -> Result<(), Error>,
    {
        // Bridge: build through the streaming `ReadReqBuilder`, then
        // iterate the chunk loop calling `on_report` per chunk to
        // preserve the existing snapshot-API contract on top of the
        // new chunk-returning [`read_with`].
        let mut chunk = Self::read_with(self, |msg| {
            msg.attr_requests_from(attr_paths)?
                .fabric_filtered(fabric_filtered)?
                .end()
        })
        .await?;

        loop {
            {
                let resp = chunk.response()?;
                on_report(&resp)?;
            }
            match chunk.complete().await? {
                Some(next) => chunk = next,
                None => return Ok(()),
            }
        }
    }

    /// Streaming counterpart to [`read`](Self::read).
    ///
    /// `build` is invoked with a typed
    /// [`ReadReqBuilder`] already opened on the outbound
    /// TX buffer; the closure must return the [the corresponding `*Txn`]
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
        B: FnMut(ReadReqBuilder<ReadTxn<'a>, 0>) -> Result<ReadTxn<'a>, Error>,
    {
        // Drives the tier-1 retransmit loop on the caller's behalf
        // (build closure idempotency contract — same TLV bytes on
        // every call). First response chunk handed back; the caller
        // iterates further chunks via `chunk.complete()`.
        let mut txn = self.read_txn().await?;
        loop {
            match txn.tx().await? {
                EitherIo::Left(builder) => {
                    txn = build(builder)?;
                }
                EitherIo::Right(chunk) => return Ok(chunk),
            }
        }
    }

    /// Async-build counterpart to [`read_with`](Self::read_with).
    /// See [`write_with_async`](Self::write_with_async) for the
    /// TX-slot-lifetime caveat and the strengthened idempotency
    /// contract that apply to any async-build IM client path.
    async fn read_with_async<B>(self, mut build: B) -> Result<ReadRespChunk<'a>, Error>
    where
        B: AsyncFnMut(ReadReqBuilder<ReadTxn<'a>, 0>) -> Result<ReadTxn<'a>, Error>,
    {
        let mut txn = self.read_txn().await?;
        loop {
            match txn.tx().await? {
                EitherIo::Left(builder) => {
                    txn = build(builder).await?;
                }
                EitherIo::Right(chunk) => return Ok(chunk),
            }
        }
    }

    /// Tier-1 `read` entry point — sets up a [`ReadTxn`] but does
    /// **no** I/O. The first call to [`ReadTxn::tx`] yields the
    /// initial builder. See [`invoke_txn`](Self::invoke_txn) for the
    /// full pattern.
    async fn read_txn(self) -> Result<ReadTxn<'a>, Error> {
        let exchange: Exchange<'a> = self.into();
        let sender = exchange.into_sender()?;
        Ok(ReadTxn {
            state: ReadTxnState::Ready(sender),
        })
    }

    /// Tier-1 `invoke` entry point — sets up an [`InvokeTxn`] but
    /// does **no** I/O beyond an optional `TimedRequest` handshake
    /// (when `timed_timeout_ms` is `Some`). The first call to
    /// [`InvokeTxn::tx`] yields the initial builder.
    ///
    /// This is the cornerstone of the IM client: closure-free,
    /// scratch-buffer-free, full user control over the retransmit
    /// loop. Higher-tier variants — closure-based
    /// ([`invoke_with`](Self::invoke_with)) and the snapshot-style
    /// [`invoke`](Self::invoke) — are layered on top of it.
    ///
    /// # Lifecycle
    ///
    /// 1. `let mut txn = exchange.invoke_txn(None).await?;`
    /// 2. `loop { match txn.tx().await? { Left(b) => txn = build(b)?, Right(c) => break c } }`
    /// 3. `loop { let resp = chunk.response()?; …; match chunk.complete().await? { … } }`
    async fn invoke_txn(self, timed_timeout_ms: Option<u16>) -> Result<InvokeTxn<'a>, Error> {
        let mut exchange: Exchange<'a> = self.into();
        if let Some(timeout_ms) = timed_timeout_ms {
            send_timed_request(&mut exchange, timeout_ms).await?;
        }
        let sender = exchange.into_sender()?;
        Ok(InvokeTxn {
            state: InvokeTxnState::Ready(sender),
        })
    }

    /// Invoke one or more commands on a device with full chunking support.
    ///
    /// This is the lowest-level invoke API. It supports multiple commands per
    /// request and handles chunked responses automatically, invoking the
    /// callback once per chunk.
    ///
    /// # Callback lifetime constraints
    ///
    /// The callback receives `&InvokeResp<'_>` where the lifetime is tied to
    /// the exchange's RX buffer for the current chunk. Because the buffer is
    /// invalidated between chunks, **only owned/`Copy` data can be extracted**
    /// from the callback. Borrowed data (e.g., `TLVElement`, byte slices)
    /// cannot escape the callback.
    ///
    /// For single-command invocations where you need zero-copy access to
    /// borrowed response data, use [`invoke_single_cmd`](Self::invoke_single_cmd)
    /// instead.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `cmd_data` - One or more commands to invoke
    /// - `timed_timeout_ms` - Optional timeout for timed invoke (required for some commands)
    /// - `on_response` - Callback invoked for each InvokeResponse chunk
    async fn invoke<F>(
        self,
        cmd_data: &[CmdData<'_>],
        timed_timeout_ms: Option<u16>,
        mut on_response: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&InvokeResp<'_>) -> Result<(), Error>,
    {
        // Bridge: re-emit the pre-built `&[CmdData]` through the
        // streaming builder, then iterate the chunk loop ourselves —
        // calling the caller's `on_response` per chunk so the
        // existing snapshot-API contract (single `Result<(), Error>`)
        // is preserved on top of the new chunk-returning
        // [`invoke_with`].
        let mut chunk = Self::invoke_with(self, timed_timeout_ms, |msg| {
            let mut entries = msg
                .suppress_response(false)?
                .timed_request(timed_timeout_ms.is_some())?
                .invoke_requests()?;
            for cd in cmd_data {
                let entry = entries
                    .push()?
                    .path_from(&cd.path)?
                    .data(|w| cd.data.to_tlv(&TLVTag::Context(CmdDataTag::Data as u8), w))?;
                entries = match cd.command_ref {
                    Some(r) => entry.command_ref(r)?.end()?,
                    None => entry.end()?,
                };
            }
            entries.end()?.end()
        })
        .await?;

        loop {
            {
                let resp = chunk.response()?;
                on_response(&resp)?;
            }
            match chunk.complete().await? {
                Some(next) => chunk = next,
                None => return Ok(()),
            }
        }
    }

    /// Streaming counterpart to [`invoke`](Self::invoke).
    ///
    /// Where [`invoke`](Self::invoke) takes a pre-built `&[CmdData]`
    /// (each entry carrying a `TLVElement` for the command request
    /// body — meaning the body had to be serialised into a sibling
    /// buffer first), `invoke_with` hands the caller a typed
    /// [`InvReqBuilder`] already opened on the outbound
    /// TX buffer and lets them stream the `InvokeRequestMessage`
    /// directly. The closure must return the [the corresponding `*Txn`]
    /// produced by `InvReqBuilder::end()` as the
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
        B: FnMut(InvReqBuilder<InvokeTxn<'a>, 0>) -> Result<InvokeTxn<'a>, Error>,
    {
        // Drives the tier-1 retransmit loop on the caller's behalf:
        // the `build` closure is (re-)run on every framework attempt
        // (so it must remain idempotent — same TLV bytes on every
        // call), and the first response chunk is returned to the
        // caller for direct inspection / `complete()` iteration.
        let mut txn = self.invoke_txn(timed_timeout_ms).await?;
        loop {
            match txn.tx().await? {
                EitherIo::Left(builder) => {
                    txn = build(builder)?;
                }
                EitherIo::Right(chunk) => return Ok(chunk),
            }
        }
    }

    /// Async-build counterpart to [`invoke_with`](Self::invoke_with).
    /// The genuine MCU win for client clusters: a command-request
    /// build that needs to await (binding lookup, async telemetry,
    /// crypto sign) can do so directly into the TX buffer without
    /// a sibling buffer. See [`write_with_async`](Self::write_with_async)
    /// for the slot-lifetime and idempotency caveats.
    async fn invoke_with_async<B>(
        self,
        timed_timeout_ms: Option<u16>,
        mut build: B,
    ) -> Result<InvokeRespChunk<'a>, Error>
    where
        B: AsyncFnMut(InvReqBuilder<InvokeTxn<'a>, 0>) -> Result<InvokeTxn<'a>, Error>,
    {
        let mut txn = self.invoke_txn(timed_timeout_ms).await?;
        loop {
            match txn.tx().await? {
                EitherIo::Left(builder) => {
                    txn = build(builder).await?;
                }
                EitherIo::Right(chunk) => return Ok(chunk),
            }
        }
    }

    /// Write attributes to a device.
    ///
    /// Sends a WriteRequest, then invokes `on_resp` with the parsed
    /// WriteResponse (which borrows from the exchange's RX buffer).
    /// The callback's return value is propagated; the exchange is
    /// consumed and dropped at the end of the call.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session) —
    ///   consumed by the call (one exchange = one IM transaction)
    /// - `attr_data` - Attribute data to write
    /// - `timed_timeout_ms` - Optional timeout for timed write (required for some attributes)
    /// - `on_resp` - Callback invoked with the parsed `WriteResp` so
    ///   the caller can inspect per-attribute statuses with zero-copy
    ///   access and extract an owned result.
    async fn write<F, T>(
        self,
        attr_data: &[AttrData<'_>],
        timed_timeout_ms: Option<u16>,
        on_resp: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(WriteResp<'_>) -> Result<T, Error>,
    {
        // Bridge: build through the streaming `WriteReqBuilder`, then
        // invoke the caller's `on_resp` with the parsed `WriteResp`
        // borrowed from the handle. The handle is dropped on return,
        // releasing the exchange.
        let handle = Self::write_with(self, timed_timeout_ms, |msg| {
            // `SuppressResponse` is implicitly omitted (the legacy
            // snapshot did the same — `None` for that field). The
            // legacy snapshot also wrote `TimedRequest` only when
            // `timed=true`, so mirror that here.
            let mut entries = if timed_timeout_ms.is_some() {
                msg.timed_request(true)?.write_requests()?
            } else {
                msg.write_requests()?
            };
            for ad in attr_data {
                // Each `AttrDataBuilder<_, N>` is a different type per
                // typestate `N`; an if-else over `ad.data_ver` lets
                // both arms land at state 2 (via implicit
                // data_version skip on the None arm) and continue
                // uniformly.
                let entry = entries.push()?;
                entries = match ad.data_ver {
                    Some(dv) => entry.data_version(dv)?.path_from(&ad.path)?,
                    None => entry.path_from(&ad.path)?,
                }
                .data(|w| ad.data.to_tlv(&TLVTag::Context(AttrDataTag::Data as u8), w))?
                .end()?;
            }
            // `.end()` on the array closes it; the next `.end()` on
            // the message implicitly skips `MoreChunkedMessages` and
            // yields the root parent — proof that the message is
            // well-formed.
            entries.end()?.end()
        })
        .await?;

        on_resp(handle.response()?)
    }

    /// Streaming counterpart to [`write`](Self::write).
    ///
    /// Where [`write`](Self::write) takes a pre-built `&[AttrData]`
    /// slice (which means every attribute value had to be serialised
    /// into a sibling buffer first), `write_with` hands the caller a
    /// typed [`WriteReqBuilder`] already opened on the
    /// outgoing TX buffer and lets them stream the
    /// `WriteRequestMessage` directly. No intermediate `Vec`, no
    /// out-of-band payload buffer — every byte ends up in the TX
    /// buffer exactly once. This is what the "Tier-2" / power-user
    /// streaming client APIs use.
    ///
    /// The closure receives the message builder at typestate `0` and
    /// must return the [the corresponding `*Txn`] that
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
        B: FnMut(WriteReqBuilder<WriteTxn<'a>, 0>) -> Result<WriteTxn<'a>, Error>,
    {
        let mut txn = self.write_txn(timed_timeout_ms).await?;
        loop {
            match txn.tx().await? {
                EitherIo::Left(builder) => {
                    txn = build(builder)?;
                }
                EitherIo::Right(handle) => return Ok(handle),
            }
        }
    }

    /// Async-build counterpart to [`write_with`](Self::write_with).
    ///
    /// The `build` closure is `AsyncFnMut` and may `.await` while
    /// holding the typed [`WriteReqBuilder`] — useful when
    /// the attribute values must themselves be fetched asynchronously
    /// (KV lookup, sensor read, async crypto, …).
    ///
    /// **TX-slot lifetime caveat**: the underlying transport's TX
    /// buffer slot stays reserved for the entire duration of one
    /// closure invocation, including the time spent inside any
    /// `.await`. With a small TX-buffer pool, a slow-awaiting build
    /// can starve other concurrent exchanges. See
    /// [`Exchange::send_with_async`] for the full discussion. Prefer
    /// the sync [`write_with`](Self::write_with) when the build is
    /// already a pure TLV serialisation.
    ///
    /// **Idempotency**: same contract as [`write_with`]'s sync
    /// version — strengthened because the closure can now suspend
    /// and observe possibly-different external state on retransmit.
    /// Output must remain identical across retransmits.
    async fn write_with_async<B>(
        self,
        timed_timeout_ms: Option<u16>,
        mut build: B,
    ) -> Result<WriteRespHandle<'a>, Error>
    where
        B: AsyncFnMut(WriteReqBuilder<WriteTxn<'a>, 0>) -> Result<WriteTxn<'a>, Error>,
    {
        let mut txn = self.write_txn(timed_timeout_ms).await?;
        loop {
            match txn.tx().await? {
                EitherIo::Left(builder) => {
                    txn = build(builder).await?;
                }
                EitherIo::Right(handle) => return Ok(handle),
            }
        }
    }

    /// Tier-1 `write` entry point — sets up a [`WriteTxn`]. If
    /// `timed_timeout_ms` is `Some`, performs the `TimedRequest`
    /// handshake first (the only I/O `write_txn` may do). The first
    /// call to [`WriteTxn::tx`] yields the initial builder.
    async fn write_txn(self, timed_timeout_ms: Option<u16>) -> Result<WriteTxn<'a>, Error> {
        let mut exchange: Exchange<'a> = self.into();
        if let Some(timeout_ms) = timed_timeout_ms {
            send_timed_request(&mut exchange, timeout_ms).await?;
        }
        let sender = exchange.into_sender()?;
        Ok(WriteTxn {
            state: WriteTxnState::Ready(sender),
        })
    }

    // ---- Single-item convenience methods -------------------------------
    /// Read a single attribute and extract an owned value via callback.
    ///
    /// Convenience wrapper around [`read`](Self::read) for the common case
    /// of reading one attribute and extracting a single value from the
    /// response. The callback receives the first `AttrResp` and should
    /// return the extracted data.
    ///
    /// # Callback lifetime constraints
    ///
    /// The same lifetime constraints as [`read`](Self::read) apply: the
    /// callback's `AttrResp<'_>` borrows from a transient RX buffer, so
    /// only owned/`Copy` types can be returned as `T`. Returning borrowed
    /// types like `TLVElement<'_>` will not compile.
    ///
    /// For single-attribute reads where you need zero-copy access to the
    /// response's `TLVElement` data, use
    /// [`read_single_attr`](Self::read_single_attr) instead.
    ///
    /// # Returns
    /// The value returned by the callback, or an error if no attribute
    /// response was found or the read failed.
    async fn read_single<T, F>(
        self,
        endpoint: EndptId,
        cluster: ClusterId,
        attr: AttrId,
        fabric_filtered: bool,
        on_attr: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(&AttrResp<'_>) -> Result<T, Error>,
    {
        let path = AttrPath {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attr: Some(attr),
            ..Default::default()
        };

        let mut result: Option<Result<T, Error>> = None;
        let mut on_attr = Some(on_attr);

        Self::read(self, &[path], fabric_filtered, |report| {
            if result.is_none() {
                if let Some(attr_reports) = &report.attr_reports {
                    if let Some(attr_resp) = attr_reports.iter().next() {
                        if let Some(cb) = on_attr.take() {
                            match attr_resp {
                                Ok(resp) => result = Some(cb(&resp)),
                                Err(_) => {
                                    result = Some(Err(ErrorCode::InvalidData.into()));
                                }
                            }
                        }
                    }
                }
            }
            Ok(())
        })
        .await?;

        result.unwrap_or(Err(ErrorCode::InvalidData.into()))
    }

    /// Read a single attribute and return the response with zero-copy access.
    ///
    /// Unlike [`read_single`](Self::read_single), this method does not use a
    /// callback. Instead, it returns the `AttrResp` directly, with its
    /// `TLVElement` data borrowing from the exchange's RX buffer. This enables
    /// zero-copy access to attribute data without the lifetime constraints
    /// imposed by the callback pattern.
    ///
    /// This method follows the same pattern as [`write`](Self::write) and
    /// [`invoke_single_cmd`](Self::invoke_single_cmd): after receiving the
    /// response, it sends a standalone ACK (which preserves the RX buffer)
    /// and then parses the response from the still-valid buffer.
    ///
    /// # Limitations
    ///
    /// This method does **not** support chunked responses. If the server
    /// responds with `more_chunks=true`, an error is returned. For wildcard
    /// reads or large responses that may be chunked, use
    /// [`read`](Self::read) directly.
    ///
    /// This method requires the server to set `suppress_response=true` on
    /// the final ReportData chunk. This is standard behavior for
    /// non-subscription reads per the Matter specification. If the server
    /// sets `suppress_response=false`, the exchange is completed with
    /// `StatusResponse(Success)` and an error is returned; use
    /// [`read_single`](Self::read_single) with a callback for that case.
    ///
    /// `on_resp` is invoked synchronously with the borrowed
    /// `AttrResp` while the RX buffer is still valid; its return
    /// value is propagated as an owned `T`. The exchange is consumed
    /// and dropped on return.
    ///
    /// # Returns
    /// The value `on_resp` produced, or an error if no attribute
    /// response was found, the read failed, chunking was encountered,
    /// or `suppress_response` was false.
    async fn read_single_attr<F, T>(
        self,
        endpoint: EndptId,
        cluster: ClusterId,
        attr: AttrId,
        fabric_filtered: bool,
        on_resp: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(&AttrResp<'_>) -> Result<T, Error>,
    {
        let mut exchange: Exchange<'a> = self.into();
        let path = AttrPath {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attr: Some(attr),
            ..Default::default()
        };

        let paths = [path];
        let req = ReadRequestBuilder::attributes(&paths, fabric_filtered);

        exchange
            .send_with(|_, wb| {
                req.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::ReadRequest.into()))
            })
            .await?;

        exchange.recv_fetch().await?;

        // Check opcode and response flags before acknowledging
        let suppress_response = {
            let rx = exchange.rx()?;
            check_opcode(rx.meta().proto_opcode, OpCode::ReportData)?;

            let element = TLVElement::new(rx.payload());
            let resp = ReportDataResp::from_tlv(&element)?;

            if resp.more_chunks.unwrap_or(false) {
                send_abort(&mut exchange).await?;
                return Err(ErrorCode::InvalidData.into());
            }

            resp.suppress_response.unwrap_or(false)
        };

        if !suppress_response {
            // suppress_response=false means the server expects a StatusResponse,
            // which requires send_with() and clears the RX buffer, making
            // zero-copy access impossible. Complete the exchange properly,
            // then return an error. Use read_single() with a callback for
            // the suppress_response=false case.
            exchange
                .send_with(|_, wb| {
                    StatusResp::write(wb, IMStatusCode::Success)?;
                    Ok(Some(OpCode::StatusResponse.into()))
                })
                .await?;
            return Err(ErrorCode::InvalidData.into());
        }

        // suppress_response=true: send standalone ACK (preserves RX buffer)
        exchange.acknowledge().await?;

        // Parse response from the still-valid RX buffer
        let rx = exchange.rx()?;
        let element = TLVElement::new(rx.payload());
        let resp = ReportDataResp::from_tlv(&element)?;

        let attr_resp = resp
            .attr_reports
            .as_ref()
            .and_then(|reports| reports.iter().next())
            .ok_or(Error::from(ErrorCode::InvalidData))?
            .map_err(|_| Error::from(ErrorCode::InvalidData))?;

        on_resp(&attr_resp)
    }

    /// Invoke a single command and extract an owned value via callback.
    ///
    /// Convenience wrapper around [`invoke`](Self::invoke) for the common case
    /// of sending one command and extracting a single value from the response.
    /// The callback receives the first `CmdResp` and should return the
    /// extracted data.
    ///
    /// # Callback lifetime constraints
    ///
    /// The same lifetime constraints as [`invoke`](Self::invoke) apply: the
    /// callback's `CmdResp<'_>` borrows from a transient RX buffer, so
    /// only owned/`Copy` types can be returned as `T`. Returning borrowed
    /// types like `TLVElement<'_>` will not compile.
    ///
    /// For single-command invocations where you need zero-copy access to
    /// the response's `TLVElement` data, use
    /// [`invoke_single_cmd`](Self::invoke_single_cmd) instead.
    ///
    /// # Returns
    /// The value returned by the callback, or an error if no command
    /// response was found or the invoke failed.
    async fn invoke_single<T, F>(
        self,
        endpoint: EndptId,
        cluster: ClusterId,
        cmd: u32,
        cmd_data: TLVElement<'_>,
        timed_timeout_ms: Option<u16>,
        on_resp: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(CmdResp<'_>) -> Result<T, Error>,
    {
        let path = CmdPath {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            cmd: Some(cmd),
        };

        let data = CmdData {
            path,
            data: cmd_data,
            command_ref: None,
        };

        let mut result: Option<Result<T, Error>> = None;
        let mut on_resp = Some(on_resp);

        Self::invoke(self, &[data], timed_timeout_ms, |resp| {
            if result.is_none() {
                if let Some(invoke_responses) = &resp.invoke_responses {
                    if let Some(cmd_resp) = invoke_responses.iter().next() {
                        if let Some(cb) = on_resp.take() {
                            match cmd_resp {
                                Ok(resp) => result = Some(cb(resp)),
                                Err(_) => {
                                    result = Some(Err(ErrorCode::InvalidData.into()));
                                }
                            }
                        }
                    }
                }
            }
            Ok(())
        })
        .await?;

        result.unwrap_or(Err(ErrorCode::InvalidData.into()))
    }

    /// Invoke a single command and return the response with zero-copy access.
    ///
    /// Unlike [`invoke_single`](Self::invoke_single), this method does not use
    /// a callback. Instead, it returns the `CmdResp` directly, with its
    /// `TLVElement` data borrowing from the exchange's RX buffer. This enables
    /// zero-copy access to response fields without the lifetime constraints
    /// imposed by the callback pattern.
    ///
    /// This method follows the same pattern as [`write`](Self::write):
    /// after receiving the response, it sends a standalone ACK (which preserves
    /// the RX buffer) and then parses the response from the still-valid buffer.
    ///
    /// # Limitations
    ///
    /// This method does **not** support chunked responses. If the server
    /// responds with `more_chunks=true`, an error is returned. In practice
    /// this does not occur for single-command requests; if you need chunked
    /// response handling, use [`invoke`](Self::invoke) directly.
    ///
    /// **Note:** When the server sets `suppress_response=false` (the default
    /// for InvokeResponse), the spec requires the client to send
    /// `StatusResponse(Success)`. However, sending a StatusResponse clears
    /// the RX buffer, which would break zero-copy access. This method
    /// sends a standalone ACK instead, which completes the MRP-layer
    /// exchange but deviates from the IM-layer spec requirement. In
    /// practice this works because servers clean up the exchange on timeout.
    /// If strict spec compliance is required, use
    /// [`invoke_single`](Self::invoke_single) with a callback.
    ///
    /// The exchange remains borrowed for the lifetime of the returned
    /// `CmdResp`, since the response data points into the exchange's RX
    /// buffer.
    ///
    /// `on_resp` is invoked synchronously with the borrowed `CmdResp`
    /// while the RX buffer is still valid; its return value is
    /// propagated as an owned `T`. The exchange is consumed and
    /// dropped on return.
    ///
    /// # Returns
    /// The value `on_resp` produced, or an error if no response was
    /// found, the invoke failed, or chunking was encountered.
    async fn invoke_single_cmd<F, T>(
        self,
        endpoint: EndptId,
        cluster: ClusterId,
        cmd: u32,
        cmd_data: TLVElement<'_>,
        timed_timeout_ms: Option<u16>,
        on_resp: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(CmdResp<'_>) -> Result<T, Error>,
    {
        let mut exchange: Exchange<'a> = self.into();
        // If timed, send TimedRequest first
        if let Some(timeout_ms) = timed_timeout_ms {
            send_timed_request(&mut exchange, timeout_ms).await?;
        }

        let path = CmdPath {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            cmd: Some(cmd),
        };

        let cmd_data = [CmdData {
            path,
            data: cmd_data,
            command_ref: None,
        }];

        let req = InvokeRequestBuilder::new(&cmd_data, timed_timeout_ms.is_some());

        exchange
            .send_with(|_, wb| {
                req.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::InvokeRequest.into()))
            })
            .await?;

        exchange.recv_fetch().await?;

        // Servers MAY reply with a plain `StatusResponse` instead of a full
        // `InvokeResponse` for commands whose return is `DefaultSuccess`
        // (empty response body). Accept both.
        let opcode = exchange.rx()?.meta().proto_opcode;

        if opcode == OpCode::StatusResponse as u8 {
            // Parse status from the RX buffer, then ACK.
            let status = {
                let rx = exchange.rx()?;
                let element = TLVElement::new(rx.payload());
                StatusResp::from_tlv(&element)?.status
            };

            exchange.acknowledge().await?;

            if status == IMStatusCode::Success {
                let synth = CmdResp::status_new(
                    CmdPath {
                        endpoint: Some(endpoint),
                        cluster: Some(cluster),
                        cmd: Some(cmd),
                    },
                    IMStatusCode::Success,
                    None,
                    None,
                );
                return on_resp(synth);
            } else {
                error!("Invoke reply: StatusResponse({:?})", status);
                return Err(status
                    .to_error_code()
                    .unwrap_or(ErrorCode::InvalidData)
                    .into());
            }
        }

        // Check opcode and more_chunks before acknowledging
        {
            let rx = exchange.rx()?;
            check_opcode(rx.meta().proto_opcode, OpCode::InvokeResponse)?;

            let element = TLVElement::new(rx.payload());
            let resp = InvokeResp::from_tlv(&element)?;

            if resp.more_chunks.unwrap_or(false) {
                send_abort(&mut exchange).await?;
                return Err(ErrorCode::InvalidData.into());
            }
        }

        // Send ACK — this preserves the RX buffer (unlike send_with which clears it).
        // See doc comment on suppress_response handling above.
        exchange.acknowledge().await?;

        // Parse response from the still-valid RX buffer
        let rx = exchange.rx()?;
        let element = TLVElement::new(rx.payload());
        let resp = InvokeResp::from_tlv(&element)?;

        let cmd_resp = resp
            .invoke_responses
            .as_ref()
            .and_then(|responses| responses.iter().next())
            .ok_or(Error::from(ErrorCode::InvalidData))?
            .map_err(|_| Error::from(ErrorCode::InvalidData))?;

        on_resp(cmd_resp)
    }
}

/// Blanket impl so any [`Exchange<'a>`] is an [`ImClient<'a>`] when
/// the trait is `use`d. The default-method bodies do all the work;
/// this impl just opts the type in.
impl<'a> ImClient<'a> for Exchange<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::storage::WriteBuf;

    #[test]
    fn test_read_request_encoding() {
        let path = AttrPath {
            endpoint: Some(1),
            cluster: Some(0x0006),
            attr: Some(0x0000),
            ..Default::default()
        };

        let paths = [path];
        let req = ReadRequestBuilder::attributes(&paths, true);

        let mut buf = [0u8; 128];
        let mut wb = WriteBuf::new(&mut buf);
        req.to_tlv(&TagType::Anonymous, &mut wb).unwrap();

        assert!(!wb.as_slice().is_empty());
    }

    #[test]
    fn test_invoke_request_encoding() {
        let path = CmdPath {
            endpoint: Some(1),
            cluster: Some(0x0006),
            cmd: Some(0x02), // Toggle
        };

        let data = CmdData {
            path,
            data: TLVElement::new(&[]),
            command_ref: None,
        };

        let cmds = [data];
        let req = InvokeRequestBuilder::new(&cmds, false);

        let mut buf = [0u8; 128];
        let mut wb = WriteBuf::new(&mut buf);
        req.to_tlv(&TagType::Anonymous, &mut wb).unwrap();

        assert!(!wb.as_slice().is_empty());
    }

    #[test]
    fn test_write_request_encoding() {
        let path = AttrPath {
            endpoint: Some(1),
            cluster: Some(0x0006),
            attr: Some(0x0000),
            ..Default::default()
        };

        let data = AttrData {
            data_ver: None,
            path,
            data: TLVElement::new(&[]),
        };

        let attrs = [data];
        let req = WriteRequestBuilder::new(&attrs, false);

        let mut buf = [0u8; 128];
        let mut wb = WriteBuf::new(&mut buf);
        req.to_tlv(&TagType::Anonymous, &mut wb).unwrap();

        assert!(!wb.as_slice().is_empty());
    }
}
