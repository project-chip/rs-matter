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

//! Bulk Data Exchange (BDX) protocol.
//!
//! BDX transfers an opaque "file" (a sequence of bytes plus optional metadata)
//! between two nodes over a single [`Exchange`](crate::transport::exchange::Exchange),
//! inside a PASE or CASE session. It is used, among other things, to download
//! Over-the-Air (OTA) software-update images.
//!
//! It provides the wire codec (the protocol id, opcodes, status codes, the
//! `TransferControl`/`RangeControl` flag fields, and the message types with
//! binary parse/encode) and a synchronous streaming engine on top of it: the
//! [`BdxPull`]/[`BdxPush`] initiator traits and the
//! [`BdxPullResponder`]/[`BdxPushResponder`] responders, which yield
//! [`BdxReader`]/[`BdxWriter`] byte-stream handles.
//!
//! All multi-byte integers are little-endian (as per the Matter Core spec).

use num::FromPrimitive;
use num_derive::FromPrimitive;

use crate::error::{Error, ErrorCode};
use crate::sc::{self, GeneralCode, StatusReport};
use crate::transport::exchange::{Exchange, MessageMeta};
use crate::utils::storage::WriteBuf;

/// The Matter protocol id for BDX.
pub const PROTO_ID_BDX: u16 = 0x0002;

/// The BDX protocol version implemented here. BDX Version 0 is the first (and,
/// as of Matter 1.5, only) version.
pub const BDX_VERSION: u8 = 0;

/// The BDX protocol message opcodes.
#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum OpCode {
    /// Initiator wants to be the Sender (upload).
    SendInit = 0x01,
    /// Responder accepts a `SendInit`.
    SendAccept = 0x02,
    /// Initiator wants to be the Receiver (download).
    ReceiveInit = 0x04,
    /// Responder accepts a `ReceiveInit`.
    ReceiveAccept = 0x05,
    /// Driving Receiver requests the next block.
    BlockQuery = 0x10,
    /// A block of data.
    Block = 0x11,
    /// The final block of a transfer (may be empty).
    BlockEof = 0x12,
    /// Acknowledges a received `Block`.
    BlockAck = 0x13,
    /// Acknowledges a received `BlockEof`; ends the session.
    BlockAckEof = 0x14,
    /// Like `BlockQuery`, but advances the sender's cursor first.
    BlockQueryWithSkip = 0x15,
}

impl OpCode {
    /// The [`MessageMeta`] for this opcode. All BDX messages are reliable: BDX
    /// runs only over reliable transports and uses MRP over UDP.
    pub fn meta(self) -> MessageMeta {
        MessageMeta {
            proto_id: PROTO_ID_BDX,
            proto_opcode: self as u8,
            reliable: true,
        }
    }
}

impl From<OpCode> for MessageMeta {
    fn from(op: OpCode) -> Self {
        op.meta()
    }
}

/// The BDX status codes carried in a `StatusReport` to fail or reject a transfer.
#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u16)]
pub enum BdxStatus {
    LengthTooLarge = 0x0012,
    LengthTooShort = 0x0013,
    LengthMismatch = 0x0014,
    LengthRequired = 0x0015,
    BadMessageContents = 0x0016,
    BadBlockCounter = 0x0017,
    UnexpectedMessage = 0x0018,
    ResponderBusy = 0x0019,
    TransferFailedUnknownError = 0x001F,
    TransferMethodNotSupported = 0x0050,
    FileDesignatorUnknown = 0x0051,
    StartOffsetNotSupported = 0x0052,
    VersionNotSupported = 0x0053,
    Unknown = 0x005F,
}

impl BdxStatus {
    /// Build the BDX failure [`StatusReport`] for this status code (`GeneralCode:
    /// FAILURE, ProtocolId: BDX`). BDX `StatusReport`s carry no extra data.
    pub fn as_report(self) -> StatusReport<'static> {
        StatusReport {
            general_code: GeneralCode::Failure,
            proto_id: PROTO_ID_BDX as u32,
            proto_code: self as u16,
            proto_data: &[],
        }
    }
}

/// The Proposed Transfer Control (PTC) / Transfer Control (TC) field of the
/// `*Init`/`*Accept` messages.
///
/// Carries the protocol [`version`](Self::version) in the low nibble and the
/// proposed/selected drive mode(s) in the high bits. In an `*Init` it is a *set*
/// of proposals; in an `*Accept` exactly one drive mode is selected.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TransferControl {
    /// Protocol version (bits 0-3).
    pub version: u8,
    /// Sender-drive mode (bit 4): the Sender paces the transfer via `Block`.
    pub sender_drive: bool,
    /// Receiver-drive mode (bit 5): the Receiver paces it via `BlockQuery`.
    pub receiver_drive: bool,
    /// Asynchronous mode (bit 6). Provisional - never selected by a Responder.
    pub async_mode: bool,
}

impl TransferControl {
    const SENDER_DRIVE: u8 = 1 << 4;
    const RECEIVER_DRIVE: u8 = 1 << 5;
    const ASYNC: u8 = 1 << 6;
    const VERSION_MASK: u8 = 0x0f;

    fn from_byte(b: u8) -> Self {
        Self {
            version: b & Self::VERSION_MASK,
            sender_drive: b & Self::SENDER_DRIVE != 0,
            receiver_drive: b & Self::RECEIVER_DRIVE != 0,
            async_mode: b & Self::ASYNC != 0,
        }
    }

    fn to_byte(self) -> u8 {
        let mut b = self.version & Self::VERSION_MASK;
        if self.sender_drive {
            b |= Self::SENDER_DRIVE;
        }
        if self.receiver_drive {
            b |= Self::RECEIVER_DRIVE;
        }
        if self.async_mode {
            b |= Self::ASYNC;
        }
        b
    }
}

/// The Range Control (RC) field of the `*Init`/`ReceiveAccept` messages.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RangeControl {
    /// A definite length is present (bit 0).
    pub def_len: bool,
    /// A start offset is present (bit 1). Not used in `ReceiveAccept`.
    pub start_offset: bool,
    /// Offset/length fields are 64-bit rather than 32-bit (bit 4).
    pub wide_range: bool,
}

impl RangeControl {
    const DEF_LEN: u8 = 1 << 0;
    const START_OFFSET: u8 = 1 << 1;
    const WIDE_RANGE: u8 = 1 << 4;

    fn from_byte(b: u8) -> Self {
        Self {
            def_len: b & Self::DEF_LEN != 0,
            start_offset: b & Self::START_OFFSET != 0,
            wide_range: b & Self::WIDE_RANGE != 0,
        }
    }

    fn to_byte(self) -> u8 {
        let mut b = 0;
        if self.def_len {
            b |= Self::DEF_LEN;
        }
        if self.start_offset {
            b |= Self::START_OFFSET;
        }
        if self.wide_range {
            b |= Self::WIDE_RANGE;
        }
        b
    }
}

/// A minimal little-endian cursor over a borrowed payload, yielding `'a` slices
/// for the variable-length tail fields (file designator, block data, metadata).
struct Cursor<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }

    fn u8(&mut self) -> Result<u8, Error> {
        let b = *self.buf.get(self.off).ok_or(ErrorCode::TruncatedPacket)?;
        self.off += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let slice = self.take(N)?;
        Ok(slice.try_into().unwrap())
    }

    /// A length-prefixed/sized slice of `n` bytes, borrowing the payload.
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.off.checked_add(n).ok_or(ErrorCode::TruncatedPacket)?;
        let slice = self
            .buf
            .get(self.off..end)
            .ok_or(ErrorCode::TruncatedPacket)?;
        self.off = end;
        Ok(slice)
    }

    /// The remainder of the payload (consumes it), borrowing the payload.
    fn rest(&mut self) -> &'a [u8] {
        let rest = &self.buf[self.off..];
        self.off = self.buf.len();
        rest
    }

    /// A range-controlled offset/length value (4 or 8 octets).
    fn range_val(&mut self, wide: bool) -> Result<u64, Error> {
        if wide {
            self.u64()
        } else {
            Ok(self.u32()? as u64)
        }
    }
}

fn put_range_val(wb: &mut WriteBuf, value: u64, wide: bool) -> Result<(), Error> {
    if wide {
        wb.le_u64(value)
    } else {
        wb.le_u32(value as u32)
    }
}

/// A `SendInit` (`OpCode::SendInit`) or `ReceiveInit` (`OpCode::ReceiveInit`)
/// message - the opening message of a BDX session.
///
/// The two share an identical wire format; the opcode distinguishes the
/// Initiator's intended role (Sender for `SendInit`, Receiver for `ReceiveInit`).
#[derive(Debug, Clone)]
pub struct TransferInit<'a> {
    /// Proposed transfer control (version + supported drive modes).
    pub transfer_control: TransferControl,
    /// Range control (length/offset presence + width).
    pub range_control: RangeControl,
    /// Proposed maximum block size, exclusive of the block counter.
    pub max_block_size: u16,
    /// Start offset within the file. Meaningful only if
    /// `range_control.start_offset`; `0` otherwise.
    pub start_offset: u64,
    /// Proposed/maximum length. Meaningful only if `range_control.def_len`;
    /// `0` (indefinite) otherwise.
    pub length: u64,
    /// The file designator chosen by the Initiator to identify the payload.
    pub file_designator: &'a [u8],
    /// Optional application metadata (raw TLV bytes; empty if absent).
    pub metadata: &'a [u8],
}

impl<'a> TransferInit<'a> {
    /// Parse a `SendInit`/`ReceiveInit` payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(payload);

        let transfer_control = TransferControl::from_byte(c.u8()?);
        let range_control = RangeControl::from_byte(c.u8()?);
        let max_block_size = c.u16()?;

        let start_offset = if range_control.start_offset {
            c.range_val(range_control.wide_range)?
        } else {
            0
        };
        let length = if range_control.def_len {
            c.range_val(range_control.wide_range)?
        } else {
            0
        };

        let fdl = c.u16()? as usize;
        let file_designator = c.take(fdl)?;
        let metadata = c.rest();

        Ok(Self {
            transfer_control,
            range_control,
            max_block_size,
            start_offset,
            length,
            file_designator,
            metadata,
        })
    }

    /// Encode this message's payload (without the protocol header).
    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        wb.le_u8(self.transfer_control.to_byte())?;
        wb.le_u8(self.range_control.to_byte())?;
        wb.le_u16(self.max_block_size)?;
        if self.range_control.start_offset {
            put_range_val(wb, self.start_offset, self.range_control.wide_range)?;
        }
        if self.range_control.def_len {
            put_range_val(wb, self.length, self.range_control.wide_range)?;
        }
        wb.le_u16(self.file_designator.len() as u16)?;
        wb.append(self.file_designator)?;
        wb.append(self.metadata)?;
        Ok(())
    }
}

/// A `SendAccept` (`OpCode::SendAccept`) or `ReceiveAccept`
/// (`OpCode::ReceiveAccept`) message.
///
/// `SendAccept` carries only the transfer control and max block size;
/// `ReceiveAccept` additionally carries the range control and (optionally) the
/// final length. The [`receive`](Self::receive) flag selects the wire format.
#[derive(Debug, Clone)]
pub struct TransferAccept<'a> {
    /// `true` for `ReceiveAccept` (carries range control + optional length),
    /// `false` for `SendAccept`.
    pub receive: bool,
    /// The selected transfer control (exactly one drive mode + version).
    pub transfer_control: TransferControl,
    /// Range control. `ReceiveAccept` only; ignored for `SendAccept`.
    pub range_control: RangeControl,
    /// The negotiated max block size (`<= max_block_size` of the `*Init`).
    pub max_block_size: u16,
    /// The final transfer length (`ReceiveAccept` + `range_control.def_len`);
    /// `0` (indefinite) otherwise.
    pub length: u64,
    /// Optional application metadata (raw TLV bytes; empty if absent).
    pub metadata: &'a [u8],
}

impl<'a> TransferAccept<'a> {
    /// Parse a `SendAccept` (`receive = false`) / `ReceiveAccept`
    /// (`receive = true`) payload.
    pub fn parse(receive: bool, payload: &'a [u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(payload);

        let transfer_control = TransferControl::from_byte(c.u8()?);

        let (range_control, length) = if receive {
            let range_control = RangeControl::from_byte(c.u8()?);
            // Max block size comes before the (optional) length.
            let max_block_size = c.u16()?;
            let length = if range_control.def_len {
                c.range_val(range_control.wide_range)?
            } else {
                0
            };
            return Ok(Self {
                receive,
                transfer_control,
                range_control,
                max_block_size,
                length,
                metadata: c.rest(),
            });
        } else {
            (RangeControl::default(), 0)
        };

        let max_block_size = c.u16()?;

        Ok(Self {
            receive,
            transfer_control,
            range_control,
            max_block_size,
            length,
            metadata: c.rest(),
        })
    }

    /// Encode this message's payload (without the protocol header).
    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        wb.le_u8(self.transfer_control.to_byte())?;
        if self.receive {
            wb.le_u8(self.range_control.to_byte())?;
            wb.le_u16(self.max_block_size)?;
            if self.range_control.def_len {
                put_range_val(wb, self.length, self.range_control.wide_range)?;
            }
        } else {
            wb.le_u16(self.max_block_size)?;
        }
        wb.append(self.metadata)?;
        Ok(())
    }
}

/// A `Block` (`OpCode::Block`) or `BlockEof` (`OpCode::BlockEof`) message - a
/// chunk of the transferred data tagged with its block counter.
#[derive(Debug, Clone)]
pub struct Block<'a> {
    /// The block counter (ascending, wrapping `mod 2^32`).
    pub block_counter: u32,
    /// The block data. `[0..=max_block_size]` for a `Block` (non-empty in
    /// practice), and possibly empty for a `BlockEof`.
    pub data: &'a [u8],
}

impl<'a> Block<'a> {
    /// Parse a `Block`/`BlockEof` payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(payload);
        let block_counter = c.u32()?;
        Ok(Self {
            block_counter,
            data: c.rest(),
        })
    }

    /// Encode this message's payload (without the protocol header).
    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        wb.le_u32(self.block_counter)?;
        wb.append(self.data)?;
        Ok(())
    }
}

/// A `BlockQuery` (`OpCode::BlockQuery`) message - a driving Receiver requesting
/// the next block.
///
/// `BlockAck`/`BlockAckEof` share the same single-`block_counter` wire format,
/// so this type doubles for them too.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BlockQuery {
    /// The block counter being requested/acknowledged.
    pub block_counter: u32,
}

impl BlockQuery {
    /// Parse a `BlockQuery`/`BlockAck`/`BlockAckEof` payload.
    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(payload);
        Ok(Self {
            block_counter: c.u32()?,
        })
    }

    /// Encode this message's payload (without the protocol header).
    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        wb.le_u32(self.block_counter)
    }
}

/// A `BlockQueryWithSkip` (`OpCode::BlockQueryWithSkip`) message - a `BlockQuery`
/// that first advances the Sender's cursor by `bytes_to_skip`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BlockQueryWithSkip {
    /// The block counter being requested.
    pub block_counter: u32,
    /// The number of bytes to skip forward before sending the next block.
    pub bytes_to_skip: u64,
}

impl BlockQueryWithSkip {
    /// Parse a `BlockQueryWithSkip` payload.
    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(payload);
        Ok(Self {
            block_counter: c.u32()?,
            bytes_to_skip: c.u64()?,
        })
    }

    /// Encode this message's payload (without the protocol header).
    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        wb.le_u32(self.block_counter)?;
        wb.le_u64(self.bytes_to_skip)?;
        Ok(())
    }
}

/// Try to interpret a `MessageMeta` as a BDX opcode.
pub(crate) fn opcode(meta: &MessageMeta) -> Option<OpCode> {
    (meta.proto_id == PROTO_ID_BDX).then(|| OpCode::from_u8(meta.proto_opcode))?
}

/// Map the meta of a freshly received transfer message to a BDX opcode. A
/// Secure Channel `StatusReport` means the peer aborted the transfer (mapped to
/// an error); anything else is a protocol violation.
fn classify(meta: &MessageMeta) -> Result<OpCode, Error> {
    if meta.proto_id == PROTO_ID_BDX {
        return opcode(meta).ok_or_else(|| ErrorCode::InvalidOpcode.into());
    }

    if meta.proto_id == sc::PROTO_ID_SECURE_CHANNEL
        && meta.proto_opcode == sc::OpCode::StatusReport as u8
    {
        error!("BDX: peer aborted the transfer with a StatusReport");
        return Err(ErrorCode::Invalid.into());
    }

    Err(ErrorCode::InvalidProto.into())
}

/// Send a BDX failure `StatusReport` (a Secure Channel `StatusReport` naming the
/// BDX protocol).
async fn send_status_report(exchange: &mut Exchange<'_>, status: BdxStatus) -> Result<(), Error> {
    exchange
        .send_with(|_, wb| {
            status.as_report().write(wb)?;
            Ok(Some(sc::OpCode::StatusReport.meta()))
        })
        .await
}

/// Send a BDX failure `StatusReport` and return an error, aborting the transfer.
async fn abort<T>(exchange: &mut Exchange<'_>, status: BdxStatus) -> Result<T, Error> {
    warn!("BDX: aborting the transfer ({:?})", status);

    send_status_report(exchange, status).await?;

    Err(ErrorCode::Invalid.into())
}

// ===========================================================================
// Streaming API: `BdxReader` / `BdxWriter` + the `BdxPull` / `BdxPush` traits.
//
// Unlike `download`/`serve` (which pump a whole transfer through a sink/source
// in one call), these expose byte-stream `read`/`write` handles that drive the
// BDX protocol incrementally. The same handle works whether this endpoint
// *drives* the synchronous transfer or *follows* the peer (selected during
// negotiation), so a reader on one side pairs with a writer on the other,
// regardless of which side initiated.
// ===========================================================================

/// The number of header bytes preceding a block's data (the 32-bit block counter).
const BLOCK_HEADER_LEN: usize = 4;

/// The block size proposed (and, for the writer, staged) by the streaming API.
/// This is the maximum size over non-TCP transports.
const STREAM_BLOCK_SIZE: u16 = 1024;

/// How this endpoint participates in a synchronous transfer.
///
/// This is the extension point for the (currently unimplemented) asynchronous
/// mode: adding an `Async` variant here, handled in the `read`/`write` step
/// helpers, would not change the public `read`/`write` surface.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Drive {
    /// We control the pace: as a receiver we send `BlockQuery`; as a sender we
    /// send `Block` and await `BlockAck`.
    Driver,
    /// We follow the peer's pace: as a receiver we await `Block` and send
    /// `BlockAck`; as a sender we await `BlockQuery` before sending `Block`.
    Follower,
}

/// Build the streaming `*Init` proposal (both drive modes, indefinite length).
async fn send_init(
    exchange: &mut Exchange<'_>,
    opcode: OpCode,
    file_designator: &[u8],
) -> Result<(), Error> {
    let init = TransferInit {
        transfer_control: TransferControl {
            version: BDX_VERSION,
            sender_drive: true,
            receiver_drive: true,
            async_mode: false,
        },
        range_control: RangeControl::default(),
        max_block_size: STREAM_BLOCK_SIZE,
        start_offset: 0,
        length: 0,
        file_designator,
        metadata: &[],
    };

    exchange
        .send_with(|_, wb| {
            init.write(wb)?;
            Ok(Some(opcode.into()))
        })
        .await
}

/// Send a streaming `*Accept` selecting the transfer control + block size, and
/// (for a `ReceiveAccept`) advertising the definite `length` if known.
async fn send_accept(
    exchange: &mut Exchange<'_>,
    receive: bool,
    transfer_control: TransferControl,
    max_block_size: u16,
    length: Option<u64>,
) -> Result<(), Error> {
    let accept = TransferAccept {
        receive,
        transfer_control,
        // Only a `ReceiveAccept` carries range control + length.
        range_control: RangeControl {
            def_len: receive && length.is_some(),
            start_offset: false,
            wide_range: length.is_some_and(|len| len > u32::MAX as u64),
        },
        max_block_size,
        length: length.unwrap_or(0),
        metadata: &[],
    };

    let opcode = if receive {
        OpCode::ReceiveAccept
    } else {
        OpCode::SendAccept
    };

    exchange
        .send_with(|_, wb| {
            accept.write(wb)?;
            Ok(Some(opcode.into()))
        })
        .await
}

/// Await the `*Accept` and return the negotiated transfer control, block size,
/// and definite length (if any), or `None` if no drive mode was selected.
async fn recv_accept(
    exchange: &mut Exchange<'_>,
    receive: bool,
) -> Result<Option<(TransferControl, u16, Option<u64>)>, Error> {
    let expected = if receive {
        OpCode::ReceiveAccept
    } else {
        OpCode::SendAccept
    };

    enum Outcome {
        Ok(TransferControl, u16, Option<u64>),
        NoMethod,
        Unexpected,
        Aborted(Error),
    }

    exchange.recv_fetch().await?;
    let meta = exchange.rx()?.meta();
    let outcome = {
        let payload = exchange.rx()?.payload();
        match classify(&meta) {
            Ok(op) if op == expected => {
                let accept = TransferAccept::parse(receive, payload)?;
                let tc = accept.transfer_control;
                if tc.sender_drive || tc.receiver_drive {
                    let length = (accept.range_control.def_len && accept.length > 0)
                        .then_some(accept.length);
                    Outcome::Ok(tc, accept.max_block_size, length)
                } else {
                    Outcome::NoMethod
                }
            }
            Ok(_) => Outcome::Unexpected,
            Err(e) => Outcome::Aborted(e),
        }
    };
    exchange.rx_done()?;

    match outcome {
        Outcome::Ok(tc, mbs, length) => Ok(Some((tc, mbs, length))),
        Outcome::NoMethod => Ok(None),
        Outcome::Unexpected => abort(exchange, BdxStatus::UnexpectedMessage).await,
        Outcome::Aborted(e) => Err(e),
    }
}

/// Await the opening `*Init` and *keep it held* in the exchange RX buffer (so the
/// file designator can be borrowed via [`held_fd`]). Returns the proposed
/// transfer control, block size, and definite length (if any). The caller is
/// responsible for eventually releasing the held message (`rx_done`).
async fn recv_init_hold(
    exchange: &mut Exchange<'_>,
    expected: OpCode,
) -> Result<(TransferControl, u16, Option<u64>), Error> {
    enum Outcome {
        Ok(TransferControl, u16, Option<u64>),
        Unexpected,
        Aborted(Error),
    }

    exchange.recv_fetch().await?;
    let meta = exchange.rx()?.meta();
    let outcome = {
        let payload = exchange.rx()?.payload();
        match classify(&meta) {
            Ok(op) if op == expected => {
                let init = TransferInit::parse(payload)?;
                let length = (init.range_control.def_len && init.length > 0).then_some(init.length);
                Outcome::Ok(init.transfer_control, init.max_block_size, length)
            }
            Ok(_) => Outcome::Unexpected,
            Err(e) => Outcome::Aborted(e),
        }
    };

    match outcome {
        // Leave the `*Init` held in RX; `held_fd` borrows its file designator.
        Outcome::Ok(tc, pmbs, length) => Ok((tc, pmbs, length)),
        Outcome::Unexpected => {
            exchange.rx_done()?;
            abort(exchange, BdxStatus::UnexpectedMessage).await
        }
        Outcome::Aborted(e) => {
            exchange.rx_done()?;
            Err(e)
        }
    }
}

/// Borrow the file designator of the `*Init` currently held in the exchange RX
/// buffer (see [`recv_init_hold`]). Empty if nothing valid is held.
fn held_fd<'x>(exchange: &'x Exchange<'_>) -> &'x [u8] {
    exchange
        .rx()
        .ok()
        .and_then(|rx| TransferInit::parse(rx.payload()).ok())
        .map(|init| init.file_designator)
        .unwrap_or(&[])
}

/// The transfer control to echo back in an `*Accept` to select a single drive
/// mode (with this protocol version, and no other proposals).
fn select(sender_drive: bool) -> TransferControl {
    TransferControl {
        version: BDX_VERSION,
        sender_drive,
        receiver_drive: !sender_drive,
        async_mode: false,
    }
}

/// An extension trait for initiating a BDX *download*: `pull` makes this node the
/// (typically driving) Receiver and returns a [`BdxReader`].
pub trait BdxPull<'a> {
    /// Initiate a BDX download of `file_designator`, negotiate the transfer, and
    /// return a reader positioned at the start of the data.
    async fn pull(self, file_designator: &[u8]) -> Result<BdxReader<'a>, Error>;
}

impl<'a> BdxPull<'a> for Exchange<'a> {
    async fn pull(mut self, file_designator: &[u8]) -> Result<BdxReader<'a>, Error> {
        send_init(&mut self, OpCode::ReceiveInit, file_designator).await?;

        match recv_accept(&mut self, true).await? {
            // We are the receiver: we drive iff receiver-drive was selected.
            Some((tc, _mbs, length)) => {
                let drive = if tc.receiver_drive {
                    Drive::Driver
                } else {
                    Drive::Follower
                };
                Ok(BdxReader::new(self, drive, length))
            }
            None => abort(&mut self, BdxStatus::TransferMethodNotSupported).await,
        }
    }
}

/// An extension trait for initiating a BDX *upload*: `push` makes this node the
/// (typically driving) Sender and returns a [`BdxWriter`].
pub trait BdxPush<'a> {
    /// Initiate a BDX upload of `file_designator`, negotiate the transfer, and
    /// return a writer ready to stream the data.
    async fn push(self, file_designator: &[u8]) -> Result<BdxWriter<'a>, Error>;
}

impl<'a> BdxPush<'a> for Exchange<'a> {
    async fn push(mut self, file_designator: &[u8]) -> Result<BdxWriter<'a>, Error> {
        send_init(&mut self, OpCode::SendInit, file_designator).await?;

        match recv_accept(&mut self, false).await? {
            // We are the sender: we drive iff sender-drive was selected.
            Some((tc, mbs, _length)) => {
                let drive = if tc.sender_drive {
                    Drive::Driver
                } else {
                    Drive::Follower
                };
                Ok(BdxWriter::new(self, drive, mbs))
            }
            None => abort(&mut self, BdxStatus::TransferMethodNotSupported).await,
        }
    }
}

/// The responding side of a [`pull`](BdxPull::pull): a peer requested a download
/// (sent a `ReceiveInit`), so this node becomes the Sender. Inspect the request
/// via [`fd`](Self::fd), then [`reply`](Self::reply) to obtain a [`BdxWriter`],
/// or [`reject`](Self::reject) it.
pub struct BdxPullResponder<'a> {
    exchange: Exchange<'a>,
    transfer_control: TransferControl,
    max_block_size: u16,
}

impl<'a> BdxPullResponder<'a> {
    /// Receive the incoming `ReceiveInit` on `exchange`, holding it until
    /// [`reply`](Self::reply)/[`reject`](Self::reject).
    pub async fn accept(mut exchange: Exchange<'a>) -> Result<Self, Error> {
        let (transfer_control, max_block_size, _length) =
            recv_init_hold(&mut exchange, OpCode::ReceiveInit).await?;
        Ok(Self {
            exchange,
            transfer_control,
            max_block_size,
        })
    }

    /// The file designator the initiator requested (borrowed from the held init).
    pub fn fd(&self) -> &[u8] {
        held_fd(&self.exchange)
    }

    /// Accept the transfer and start sending. `length` advertises a definite
    /// transfer length (enabling the receiver's progress reporting) when known.
    pub async fn reply(mut self, length: Option<u64>) -> Result<BdxWriter<'a>, Error> {
        // Prefer to let the initiating receiver drive (its `BdxReader` is the
        // "driving receiver"); otherwise drive ourselves.
        let tc = self.transfer_control;
        let drive = if tc.receiver_drive {
            Drive::Follower
        } else if tc.sender_drive {
            Drive::Driver
        } else {
            self.exchange.rx_done()?;
            return abort(&mut self.exchange, BdxStatus::TransferMethodNotSupported).await;
        };

        let mbs = self.max_block_size.clamp(1, STREAM_BLOCK_SIZE);
        self.exchange.rx_done()?;
        send_accept(
            &mut self.exchange,
            true,
            select(drive == Drive::Driver),
            mbs,
            length,
        )
        .await?;

        Ok(BdxWriter::new(self.exchange, drive, mbs))
    }

    /// Reject the transfer with the given status (e.g. `FileDesignatorUnknown`).
    pub async fn reject(mut self, status: BdxStatus) -> Result<(), Error> {
        self.exchange.rx_done()?;
        send_status_report(&mut self.exchange, status).await
    }
}

/// The responding side of a [`push`](BdxPush::push): a peer requested an upload
/// (sent a `SendInit`), so this node becomes the Receiver. Inspect the request
/// via [`fd`](Self::fd)/[`len`](Self::len), then [`reply`](Self::reply) to obtain
/// a [`BdxReader`], or [`reject`](Self::reject) it.
pub struct BdxPushResponder<'a> {
    exchange: Exchange<'a>,
    transfer_control: TransferControl,
    max_block_size: u16,
    length: Option<u64>,
}

impl<'a> BdxPushResponder<'a> {
    /// Receive the incoming `SendInit` on `exchange`, holding it until
    /// [`reply`](Self::reply)/[`reject`](Self::reject).
    pub async fn accept(mut exchange: Exchange<'a>) -> Result<Self, Error> {
        let (transfer_control, max_block_size, length) =
            recv_init_hold(&mut exchange, OpCode::SendInit).await?;
        Ok(Self {
            exchange,
            transfer_control,
            max_block_size,
            length,
        })
    }

    /// The file designator the initiator is sending (borrowed from the held init).
    pub fn fd(&self) -> &[u8] {
        held_fd(&self.exchange)
    }

    /// The definite length the initiator committed to, if any.
    #[allow(clippy::len_without_is_empty)] // A transfer length, not a collection count.
    pub fn len(&self) -> Option<u64> {
        self.length
    }

    /// Accept the transfer and start receiving, returning a [`BdxReader`].
    pub async fn reply(mut self) -> Result<BdxReader<'a>, Error> {
        // Prefer to let the initiating sender drive (its `BdxWriter` is the
        // "driving sender"); otherwise drive ourselves.
        let tc = self.transfer_control;
        let drive = if tc.sender_drive {
            Drive::Follower
        } else if tc.receiver_drive {
            Drive::Driver
        } else {
            self.exchange.rx_done()?;
            return abort(&mut self.exchange, BdxStatus::TransferMethodNotSupported).await;
        };

        let mbs = self.max_block_size.clamp(1, STREAM_BLOCK_SIZE);
        let length = self.length;
        self.exchange.rx_done()?;
        // A `SendAccept` carries no length; the receiver learned it from the `SendInit`.
        send_accept(
            &mut self.exchange,
            false,
            select(drive == Drive::Follower),
            mbs,
            None,
        )
        .await?;

        Ok(BdxReader::new(self.exchange, drive, length))
    }

    /// Reject the transfer with the given status.
    pub async fn reject(mut self, status: BdxStatus) -> Result<(), Error> {
        self.exchange.rx_done()?;
        send_status_report(&mut self.exchange, status).await
    }
}

/// A reader over a BDX transfer - the Receiver side.
///
/// Obtained from [`Exchange::pull`](BdxPull::pull) on the initiating side, or
/// from [`BdxPushResponder::reply`] on the responding side. [`read`](Self::read)
/// drives the protocol as needed and copies the next bytes of the transfer into
/// the caller's buffer, returning `0` at the end of the transfer.
pub struct BdxReader<'a> {
    exchange: Exchange<'a>,
    drive: Drive,
    /// The negotiated definite length of the transfer, if the sender committed
    /// to one.
    len: Option<u64>,
    /// Driver: the counter to put in the next `BlockQuery`. Follower: the
    /// expected counter of the next incoming block.
    counter: u32,
    /// The counter of the block currently held in the exchange RX buffer.
    held_counter: u32,
    /// Whether the held block is the final (`BlockEof`) block.
    held_eof: bool,
    /// How many bytes of the held block's data have been consumed.
    block_pos: usize,
    /// Whether a (partially consumed) block is held in the exchange RX buffer.
    holding: bool,
    /// Whether the transfer has completed.
    finished: bool,
}

impl<'a> BdxReader<'a> {
    fn new(exchange: Exchange<'a>, drive: Drive, len: Option<u64>) -> Self {
        Self {
            exchange,
            drive,
            len,
            counter: 0,
            held_counter: 0,
            held_eof: false,
            block_pos: 0,
            holding: false,
            finished: false,
        }
    }

    /// The total length of the transfer in bytes, if the sender committed to a
    /// definite length during negotiation (`None` for an indefinite transfer).
    #[allow(clippy::len_without_is_empty)] // A transfer length, not a collection count.
    pub fn len(&self) -> Option<u64> {
        self.len
    }

    /// Read the next bytes of the transfer into `buf`, returning the number of
    /// bytes read. Returns `0` once the whole transfer has been received.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            if self.finished {
                return Ok(0);
            }

            if self.holding {
                // Serve from the block held in the exchange RX buffer.
                let n = {
                    let payload = self.exchange.rx()?.payload();
                    let data = &payload[BLOCK_HEADER_LEN..];
                    if self.block_pos < data.len() {
                        let remaining = &data[self.block_pos..];
                        let n = remaining.len().min(buf.len());
                        buf[..n].copy_from_slice(&remaining[..n]);
                        Some(n)
                    } else {
                        None
                    }
                };

                if let Some(n) = n {
                    self.block_pos += n;
                    return Ok(n);
                }

                // The held block is fully consumed - acknowledge / advance.
                self.release_block().await?;
                continue;
            }

            // Nothing held and not finished: fetch the next block.
            self.receive_block().await?;
        }
    }

    /// Obtain the next block, holding it in the exchange RX buffer.
    async fn receive_block(&mut self) -> Result<(), Error> {
        enum Outcome {
            Ok(bool),
            BadCounter,
            Unexpected,
            Aborted(Error),
        }

        if matches!(self.drive, Drive::Driver) {
            // Request the next block (this also acknowledges the previous one).
            self.send_control(OpCode::BlockQuery, self.counter).await?;
        }

        self.exchange.recv_fetch().await?;
        let meta = self.exchange.rx()?.meta();
        let outcome = {
            let payload = self.exchange.rx()?.payload();
            match classify(&meta) {
                Ok(op) if matches!(op, OpCode::Block | OpCode::BlockEof) => {
                    let block = Block::parse(payload)?;
                    if block.block_counter != self.counter {
                        Outcome::BadCounter
                    } else {
                        Outcome::Ok(op == OpCode::BlockEof)
                    }
                }
                Ok(_) => Outcome::Unexpected,
                Err(e) => Outcome::Aborted(e),
            }
        };

        match outcome {
            Outcome::Ok(is_eof) => {
                // Keep the block held; `read` serves its data directly from RX.
                self.held_counter = self.counter;
                self.held_eof = is_eof;
                self.counter = self.counter.wrapping_add(1);
                self.block_pos = 0;
                self.holding = true;
                Ok(())
            }
            Outcome::BadCounter => {
                self.exchange.rx_done()?;
                abort(&mut self.exchange, BdxStatus::BadBlockCounter).await
            }
            Outcome::Unexpected => {
                self.exchange.rx_done()?;
                abort(&mut self.exchange, BdxStatus::UnexpectedMessage).await
            }
            Outcome::Aborted(e) => {
                self.exchange.rx_done()?;
                Err(e)
            }
        }
    }

    /// Acknowledge the consumed block and release the RX buffer, finalizing the
    /// transfer if it was the last block.
    async fn release_block(&mut self) -> Result<(), Error> {
        let counter = self.held_counter;

        if self.held_eof {
            self.send_control(OpCode::BlockAckEof, counter).await?;
            self.exchange.rx_done()?;
            self.exchange.acknowledge().await?;
            self.finished = true;
        } else if matches!(self.drive, Drive::Follower) {
            // Sender-driven: acknowledge so the next block is sent.
            self.send_control(OpCode::BlockAck, counter).await?;
            self.exchange.rx_done()?;
        } else {
            // Receiver-driven: the next `BlockQuery` is the acknowledgement.
            self.exchange.rx_done()?;
        }

        self.holding = false;
        Ok(())
    }

    /// Send a counter-only control message (`BlockQuery`/`BlockAck`/`BlockAckEof`).
    async fn send_control(&mut self, opcode: OpCode, counter: u32) -> Result<(), Error> {
        self.exchange
            .send_with(|_, wb| {
                BlockQuery {
                    block_counter: counter,
                }
                .write(wb)?;
                Ok(Some(opcode.into()))
            })
            .await
    }
}

/// A writer over a BDX transfer - the Sender side.
///
/// Obtained from [`Exchange::push`](BdxPush::push) on the initiating side, or
/// from [`BdxPullResponder::reply`] on the responding side. [`write`](Self::write)
/// stages and sends the data, driving the protocol as needed;
/// [`finish`](Self::finish) flushes the final block and completes the transfer.
pub struct BdxWriter<'a> {
    exchange: Exchange<'a>,
    drive: Drive,
    max_block_size: usize,
    /// Driver: the counter for the next block to send. Follower: the expected
    /// counter of the next `BlockQuery`.
    counter: u32,
    block: [u8; STREAM_BLOCK_SIZE as usize],
    block_len: usize,
}

impl<'a> BdxWriter<'a> {
    fn new(exchange: Exchange<'a>, drive: Drive, max_block_size: u16) -> Self {
        Self {
            exchange,
            drive,
            max_block_size: max_block_size.clamp(1, STREAM_BLOCK_SIZE) as usize,
            counter: 0,
            block: [0; STREAM_BLOCK_SIZE as usize],
            block_len: 0,
        }
    }

    /// Stage and send `data`, returning the number of bytes accepted (`< data.len()`
    /// only when the current block fills; call again with the remainder).
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        if data.is_empty() {
            return Ok(0);
        }

        let space = self.max_block_size - self.block_len;
        let n = space.min(data.len());
        self.block[self.block_len..self.block_len + n].copy_from_slice(&data[..n]);
        self.block_len += n;

        if self.block_len == self.max_block_size {
            self.flush(false).await?;
        }

        Ok(n)
    }

    /// Flush the final (possibly empty) block and complete the transfer.
    pub async fn finish(mut self) -> Result<(), Error> {
        self.flush(true).await?;
        self.exchange.acknowledge().await
    }

    /// Send the staged bytes as one block, driving/awaiting acknowledgement per
    /// the negotiated drive mode.
    async fn flush(&mut self, is_eof: bool) -> Result<(), Error> {
        let counter = self.counter;

        if matches!(self.drive, Drive::Follower) {
            // Receiver-driven: wait to be asked for this block.
            self.recv_control(OpCode::BlockQuery, counter).await?;
        }

        let opcode = if is_eof {
            OpCode::BlockEof
        } else {
            OpCode::Block
        };
        let len = self.block_len;
        {
            let data = &self.block[..len];
            self.exchange
                .send_with(|_, wb| {
                    Block {
                        block_counter: counter,
                        data,
                    }
                    .write(wb)?;
                    Ok(Some(opcode.into()))
                })
                .await?;
        }
        self.block_len = 0;

        if matches!(self.drive, Drive::Driver) {
            let ack = if is_eof {
                OpCode::BlockAckEof
            } else {
                OpCode::BlockAck
            };
            self.recv_control(ack, counter).await?;
        } else if is_eof {
            // Receiver-driven: the receiver acknowledges the final block.
            self.recv_control(OpCode::BlockAckEof, counter).await?;
        }

        self.counter = self.counter.wrapping_add(1);
        Ok(())
    }

    /// Await a specific counter-only control message and validate its counter.
    async fn recv_control(&mut self, expected: OpCode, expected_counter: u32) -> Result<(), Error> {
        enum Outcome {
            Ok,
            BadCounter,
            Unexpected,
            Aborted(Error),
        }

        self.exchange.recv_fetch().await?;
        let meta = self.exchange.rx()?.meta();
        let outcome = {
            let payload = self.exchange.rx()?.payload();
            match classify(&meta) {
                Ok(op) if op == expected => {
                    if BlockQuery::parse(payload)?.block_counter == expected_counter {
                        Outcome::Ok
                    } else {
                        Outcome::BadCounter
                    }
                }
                Ok(_) => Outcome::Unexpected,
                Err(e) => Outcome::Aborted(e),
            }
        };
        self.exchange.rx_done()?;

        match outcome {
            Outcome::Ok => Ok(()),
            Outcome::BadCounter => abort(&mut self.exchange, BdxStatus::BadBlockCounter).await,
            Outcome::Unexpected => abort(&mut self.exchange, BdxStatus::UnexpectedMessage).await,
            Outcome::Aborted(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::storage::WriteBuf;

    use super::*;

    fn roundtrip_init(msg: &TransferInit) {
        let mut buf = [0u8; 256];
        let mut wb = WriteBuf::new(&mut buf);
        msg.write(&mut wb).unwrap();
        let bytes = wb.as_slice().to_vec();

        let parsed = TransferInit::parse(&bytes).unwrap();
        assert_eq!(parsed.transfer_control, msg.transfer_control);
        assert_eq!(parsed.range_control, msg.range_control);
        assert_eq!(parsed.max_block_size, msg.max_block_size);
        assert_eq!(parsed.start_offset, msg.start_offset);
        assert_eq!(parsed.length, msg.length);
        assert_eq!(parsed.file_designator, msg.file_designator);
        assert_eq!(parsed.metadata, msg.metadata);
    }

    #[test]
    fn transfer_control_flags_roundtrip() {
        for tc in [
            TransferControl {
                version: 0,
                sender_drive: true,
                receiver_drive: false,
                async_mode: false,
            },
            TransferControl {
                version: 0,
                sender_drive: false,
                receiver_drive: true,
                async_mode: false,
            },
            TransferControl {
                version: 0,
                sender_drive: true,
                receiver_drive: true,
                async_mode: true,
            },
        ] {
            assert_eq!(TransferControl::from_byte(tc.to_byte()), tc);
        }
        // Wire layout: version low nibble, drive bits high.
        assert_eq!(
            TransferControl {
                version: 0,
                sender_drive: true,
                ..Default::default()
            }
            .to_byte(),
            0x10
        );
        assert_eq!(
            TransferControl {
                version: 0,
                receiver_drive: true,
                ..Default::default()
            }
            .to_byte(),
            0x20
        );
    }

    #[test]
    fn range_control_flags_roundtrip() {
        let rc = RangeControl {
            def_len: true,
            start_offset: true,
            wide_range: true,
        };
        assert_eq!(RangeControl::from_byte(rc.to_byte()), rc);
        assert_eq!(rc.to_byte(), 0x13); // DEFLEN(0) | STARTOFS(1) | WIDERANGE(4)
    }

    #[test]
    fn receive_init_minimal_roundtrip() {
        roundtrip_init(&TransferInit {
            transfer_control: TransferControl {
                version: 0,
                sender_drive: true,
                receiver_drive: true,
                async_mode: false,
            },
            range_control: RangeControl::default(),
            max_block_size: 1024,
            start_offset: 0,
            length: 0,
            file_designator: b"firmware.bin",
            metadata: &[],
        });
    }

    #[test]
    fn receive_init_with_offset_and_length_roundtrip() {
        roundtrip_init(&TransferInit {
            transfer_control: TransferControl {
                version: 0,
                receiver_drive: true,
                ..Default::default()
            },
            range_control: RangeControl {
                def_len: true,
                start_offset: true,
                wide_range: false,
            },
            max_block_size: 1024,
            start_offset: 0x1234,
            length: 0x5_6789,
            file_designator: b"img",
            metadata: &[0xde, 0xad],
        });
    }

    #[test]
    fn wide_range_uses_8_octets() {
        let msg = TransferInit {
            transfer_control: TransferControl {
                version: 0,
                sender_drive: true,
                ..Default::default()
            },
            range_control: RangeControl {
                def_len: true,
                start_offset: false,
                wide_range: true,
            },
            max_block_size: 512,
            start_offset: 0,
            length: 0x1_0000_0000, // > u32, requires wide range
            file_designator: b"x",
            metadata: &[],
        };
        roundtrip_init(&msg);
        // 1 (PTC) + 1 (RC) + 2 (PMBS) + 8 (LEN) + 2 (FDL) + 1 (FD) = 15 bytes.
        let mut buf = [0u8; 64];
        let mut wb = WriteBuf::new(&mut buf);
        msg.write(&mut wb).unwrap();
        assert_eq!(wb.as_slice().len(), 15);
    }

    #[test]
    fn send_accept_roundtrip() {
        let msg = TransferAccept {
            receive: false,
            transfer_control: TransferControl {
                version: 0,
                sender_drive: true,
                ..Default::default()
            },
            range_control: RangeControl::default(),
            max_block_size: 1024,
            length: 0,
            metadata: &[],
        };
        let mut buf = [0u8; 64];
        let mut wb = WriteBuf::new(&mut buf);
        msg.write(&mut wb).unwrap();
        // SendAccept = TC(1) + MBS(2) = 3 bytes (no RC, no LEN).
        assert_eq!(wb.as_slice().len(), 3);
        let bytes = wb.as_slice().to_vec();
        let parsed = TransferAccept::parse(false, &bytes).unwrap();
        assert!(parsed.transfer_control.sender_drive);
        assert_eq!(parsed.max_block_size, 1024);
    }

    #[test]
    fn receive_accept_roundtrip() {
        let msg = TransferAccept {
            receive: true,
            transfer_control: TransferControl {
                version: 0,
                sender_drive: true,
                ..Default::default()
            },
            range_control: RangeControl {
                def_len: true,
                start_offset: false,
                wide_range: false,
            },
            max_block_size: 1024,
            length: 123_456,
            metadata: &[],
        };
        let mut buf = [0u8; 64];
        let mut wb = WriteBuf::new(&mut buf);
        msg.write(&mut wb).unwrap();
        let bytes = wb.as_slice().to_vec();
        let parsed = TransferAccept::parse(true, &bytes).unwrap();
        assert!(parsed.transfer_control.sender_drive);
        assert_eq!(parsed.max_block_size, 1024);
        assert!(parsed.range_control.def_len);
        assert_eq!(parsed.length, 123_456);
    }

    #[test]
    fn block_roundtrip() {
        let msg = Block {
            block_counter: 7,
            data: b"hello world",
        };
        let mut buf = [0u8; 64];
        let mut wb = WriteBuf::new(&mut buf);
        msg.write(&mut wb).unwrap();
        let bytes = wb.as_slice().to_vec();
        let parsed = Block::parse(&bytes).unwrap();
        assert_eq!(parsed.block_counter, 7);
        assert_eq!(parsed.data, b"hello world");
    }

    #[test]
    fn block_eof_empty_roundtrip() {
        let msg = Block {
            block_counter: 0,
            data: &[],
        };
        let mut buf = [0u8; 8];
        let mut wb = WriteBuf::new(&mut buf);
        msg.write(&mut wb).unwrap();
        assert_eq!(wb.as_slice().len(), 4); // counter only
        let bytes = wb.as_slice().to_vec();
        let parsed = Block::parse(&bytes).unwrap();
        assert_eq!(parsed.block_counter, 0);
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn block_query_and_skip_roundtrip() {
        let mut buf = [0u8; 32];

        let mut wb = WriteBuf::new(&mut buf);
        BlockQuery { block_counter: 5 }.write(&mut wb).unwrap();
        assert_eq!(wb.as_slice().len(), 4);
        let bytes = wb.as_slice().to_vec();
        assert_eq!(BlockQuery::parse(&bytes).unwrap().block_counter, 5);

        let mut wb = WriteBuf::new(&mut buf);
        BlockQueryWithSkip {
            block_counter: 9,
            bytes_to_skip: 0x1_0000,
        }
        .write(&mut wb)
        .unwrap();
        assert_eq!(wb.as_slice().len(), 12); // 4 + 8
        let bytes = wb.as_slice().to_vec();
        let parsed = BlockQueryWithSkip::parse(&bytes).unwrap();
        assert_eq!(parsed.block_counter, 9);
        assert_eq!(parsed.bytes_to_skip, 0x1_0000);
    }

    #[test]
    fn truncated_is_rejected() {
        assert!(BlockQuery::parse(&[1, 2, 3]).is_err()); // need 4 bytes
        assert!(TransferInit::parse(&[0x00]).is_err()); // need at least PTC+RC+PMBS+FDL
    }

    #[test]
    fn opcode_meta_is_bdx_and_reliable() {
        let meta = OpCode::ReceiveInit.meta();
        assert_eq!(meta.proto_id, PROTO_ID_BDX);
        assert_eq!(meta.proto_opcode, 0x04);
        assert!(meta.reliable);
        assert_eq!(opcode(&meta), Some(OpCode::ReceiveInit));
    }
}
