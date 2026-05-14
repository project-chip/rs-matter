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
    IMStatusCode, InvReqBuilder, InvokeResp, OpCode, ReadReqBuilder, ReportDataResp, StatusResp,
    TimedReq, WriteReqBuilder, WriteResp,
};

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
    /// Streaming counterpart to [`read_txn`](Self::read_txn).
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

    /// Streaming counterpart to [`invoke_txn`](Self::invoke_txn).
    ///
    /// Hands the caller a typed [`InvReqBuilder`] already opened on
    /// the outbound TX buffer and lets them stream the
    /// `InvokeRequestMessage` directly. The closure must return the
    /// [`InvokeTxn`] produced by `InvReqBuilder::end()` as the
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

    /// Streaming counterpart to [`write_txn`](Self::write_txn).
    ///
    /// Hands the caller a typed [`WriteReqBuilder`] already opened
    /// on the outgoing TX buffer and lets them stream the
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
}

/// Blanket impl so any [`Exchange<'a>`] is an [`ImClient<'a>`] when
/// the trait is `use`d. The default-method bodies do all the work;
/// this impl just opts the type in.
impl<'a> ImClient<'a> for Exchange<'a> {}
