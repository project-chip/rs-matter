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
//! This module is the *wire codec* layer: the protocol id, opcodes, status
//! codes, the `TransferControl`/`RangeControl` flag fields, and the message
//! types with binary parse/encode. The synchronous sender/receiver transfer
//! engines are built on top of it (see the `sender`/`receiver` submodules).
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

/// A sink for the bytes of a BDX download - the BDX Receiver side.
///
/// The transfer engine calls [`write`](Self::write) once per received block, in
/// ascending `offset` order, with the block's payload. A `write` error aborts
/// the transfer.
pub trait BdxSink {
    /// Called once, after transfer negotiation and before any [`write`](Self::write),
    /// with the total transfer length in bytes if the sender committed to a
    /// definite length (`None` for an indefinite transfer). The default does
    /// nothing; sinks that report progress override it.
    fn begin(&mut self, _total: Option<u64>) {}

    /// Store `data` at byte `offset` from the start of the transferred file.
    async fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), Error>;
}

impl<T> BdxSink for &mut T
where
    T: BdxSink,
{
    fn begin(&mut self, total: Option<u64>) {
        (**self).begin(total)
    }

    async fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        (**self).write(offset, data).await
    }
}

/// A source of the bytes of a BDX upload - the BDX Sender side.
///
/// The transfer engine calls [`read`](Self::read) repeatedly, in ascending
/// `offset` order, to fill each outgoing block. A read shorter than the
/// requested length (for an unknown-size source) or reaching
/// [`size`](Self::size) ends the transfer.
pub trait BdxSource {
    /// Called once with the requested file designator before any
    /// [`size`](Self::size)/[`read`](Self::read). Resolve it to a transferable
    /// payload, or return an error to reject the transfer (the engine then
    /// aborts with `FileDesignatorUnknown`). The designator borrows the incoming
    /// message, so a source that needs it later must copy it. Default: accept.
    fn begin(&mut self, _file_designator: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    /// The total length of the transfer in bytes, if known. `Some` enables a
    /// definite-length transfer; `None` an indefinite one.
    fn size(&self) -> Option<u64>;

    /// Read up to `buf.len()` bytes starting at `offset` into `buf`, returning
    /// the number of bytes read (`0` signals the end for an unknown-size source).
    async fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Error>;
}

impl<T> BdxSource for &mut T
where
    T: BdxSource,
{
    fn begin(&mut self, file_designator: &[u8]) -> Result<(), Error> {
        (**self).begin(file_designator)
    }

    fn size(&self) -> Option<u64> {
        (**self).size()
    }

    async fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        (**self).read(offset, buf).await
    }
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

/// Send a BDX failure `StatusReport` and return an error, aborting the transfer.
async fn abort<T>(exchange: &mut Exchange<'_>, status: BdxStatus) -> Result<T, Error> {
    warn!("BDX: aborting the transfer ({:?})", status);

    exchange
        .send_with(|_, wb| {
            status.as_report().write(wb)?;
            Ok(Some(sc::OpCode::StatusReport.meta()))
        })
        .await?;

    Err(ErrorCode::Invalid.into())
}

/// The outcome of receiving a single block (used to defer aborts until the
/// received message has been released, so the exchange can be borrowed to send).
enum BlockRecv {
    /// A valid block: `(is_eof, data_len)`.
    Ok(bool, u64),
    /// Block counter out of order.
    BadCounter,
    /// A message other than `Block`/`BlockEof`.
    Unexpected,
}

/// Receive one `Block`/`BlockEof`, validate its counter against `expected`, and
/// write its data to `sink` at `offset`. Returns `(is_eof, data_len)`.
async fn recv_block<S: BdxSink>(
    exchange: &mut Exchange<'_>,
    expected: u32,
    offset: u64,
    sink: &mut S,
) -> Result<(bool, u64), Error> {
    let recv = {
        let rx = exchange.recv_fetch().await?;
        let meta = rx.meta();
        let op = classify(&meta)?;

        if matches!(op, OpCode::Block | OpCode::BlockEof) {
            let block = Block::parse(rx.payload())?;
            if block.block_counter != expected {
                BlockRecv::BadCounter
            } else {
                sink.write(offset, block.data).await?;
                BlockRecv::Ok(op == OpCode::BlockEof, block.data.len() as u64)
            }
        } else {
            BlockRecv::Unexpected
        }
    };
    exchange.rx_done()?;

    match recv {
        BlockRecv::Ok(eof, len) => Ok((eof, len)),
        BlockRecv::BadCounter => abort(exchange, BdxStatus::BadBlockCounter).await,
        BlockRecv::Unexpected => abort(exchange, BdxStatus::UnexpectedMessage).await,
    }
}

/// The outcome of receiving the `ReceiveAccept` (deferred-abort, as above).
enum AcceptRecv {
    /// Accepted: sender-drive flag (`true` if the Sender drives) and the
    /// negotiated definite length, if any.
    Ok(bool, Option<u64>),
    /// Accepted but no drive mode was selected.
    NoMethod,
    /// A message other than `ReceiveAccept`.
    Unexpected,
}

/// Download a file into `sink`, acting as the BDX Initiator and Receiver.
///
/// Opens the transfer with a `ReceiveInit` proposing both drive modes and an
/// indefinite length, then pumps the negotiated transfer into `sink`. Returns
/// the total number of bytes received. `max_block_size` bounds the block size
/// we are willing to receive.
pub async fn download<S: BdxSink>(
    exchange: &mut Exchange<'_>,
    file_designator: &[u8],
    max_block_size: u16,
    sink: &mut S,
) -> Result<u64, Error> {
    let init = TransferInit {
        transfer_control: TransferControl {
            version: BDX_VERSION,
            sender_drive: true,
            receiver_drive: true,
            async_mode: false,
        },
        range_control: RangeControl::default(),
        max_block_size,
        start_offset: 0,
        length: 0,
        file_designator,
        metadata: &[],
    };

    exchange
        .send_with(|_, wb| {
            init.write(wb)?;
            Ok(Some(OpCode::ReceiveInit.into()))
        })
        .await?;

    // Await the ReceiveAccept and learn the selected drive mode.
    let recv = {
        let rx = exchange.recv_fetch().await?;
        let meta = rx.meta();
        if classify(&meta)? == OpCode::ReceiveAccept {
            let accept = TransferAccept::parse(true, rx.payload())?;
            let tc = accept.transfer_control;
            if tc.sender_drive || tc.receiver_drive {
                let total =
                    (accept.range_control.def_len && accept.length > 0).then_some(accept.length);
                AcceptRecv::Ok(tc.sender_drive, total)
            } else {
                AcceptRecv::NoMethod
            }
        } else {
            AcceptRecv::Unexpected
        }
    };
    exchange.rx_done()?;

    let (sender_drive, total) = match recv {
        AcceptRecv::Ok(sender_drive, total) => (sender_drive, total),
        AcceptRecv::NoMethod => {
            return abort(exchange, BdxStatus::TransferMethodNotSupported).await
        }
        AcceptRecv::Unexpected => return abort(exchange, BdxStatus::UnexpectedMessage).await,
    };

    sink.begin(total);

    let mut offset = 0;
    let mut counter = 0u32;
    loop {
        if !sender_drive {
            // We drive: request the next block.
            let c = counter;
            exchange
                .send_with(|_, wb| {
                    BlockQuery { block_counter: c }.write(wb)?;
                    Ok(Some(OpCode::BlockQuery.into()))
                })
                .await?;
        }

        let (is_eof, len) = recv_block(exchange, counter, offset, sink).await?;
        offset += len;

        // Acknowledge the block (with the same counter it carried).
        let ack = if is_eof {
            OpCode::BlockAckEof
        } else {
            OpCode::BlockAck
        };
        // In sender-drive we ack every block; in receiver-drive only the final
        // BlockEof is acknowledged (each non-final block is implicitly acked by
        // the next BlockQuery).
        if sender_drive || is_eof {
            let c = counter;
            exchange
                .send_with(|_, wb| {
                    BlockQuery { block_counter: c }.write(wb)?;
                    Ok(Some(ack.into()))
                })
                .await?;
        }

        if is_eof {
            break;
        }
        counter = counter.wrapping_add(1);
    }

    exchange.acknowledge().await?;

    Ok(offset)
}

/// The outcome of receiving the opening `ReceiveInit` (deferred-abort, as above).
enum InitRecv {
    /// A supported request: the proposed max block size.
    Ok(u16),
    /// A non-zero start offset, which we do not support.
    StartOffset,
    /// The Initiator did not propose Sender-drive, which is all we support here.
    Method,
    /// The source rejected the requested file designator.
    FileUnknown,
    /// A message other than `ReceiveInit`.
    Unexpected,
}

/// Serve a file from `source`, acting as the BDX Responder and Sender.
///
/// Expects the peer to open the transfer with a `ReceiveInit` (a download
/// request). Negotiates a Sender-driven transfer, then sends the file block by
/// block, awaiting an acknowledgement after each. `block_buf` stages each
/// outgoing block and bounds the negotiated block size. Returns the total number
/// of bytes sent.
pub async fn serve<S: BdxSource>(
    exchange: &mut Exchange<'_>,
    block_buf: &mut [u8],
    source: &mut S,
) -> Result<u64, Error> {
    let recv = {
        let rx = exchange.recv_fetch().await?;
        let meta = rx.meta();
        let op = classify(&meta)?;

        if op == OpCode::ReceiveInit {
            let init = TransferInit::parse(rx.payload())?;
            if init.range_control.start_offset && init.start_offset != 0 {
                InitRecv::StartOffset
            } else if !init.transfer_control.sender_drive {
                InitRecv::Method
            } else if source.begin(init.file_designator).is_err() {
                InitRecv::FileUnknown
            } else {
                InitRecv::Ok(init.max_block_size)
            }
        } else {
            InitRecv::Unexpected
        }
    };
    exchange.rx_done()?;

    let pmbs = match recv {
        InitRecv::Ok(pmbs) => pmbs,
        InitRecv::StartOffset => return abort(exchange, BdxStatus::StartOffsetNotSupported).await,
        InitRecv::Method => return abort(exchange, BdxStatus::TransferMethodNotSupported).await,
        InitRecv::FileUnknown => return abort(exchange, BdxStatus::FileDesignatorUnknown).await,
        InitRecv::Unexpected => return abort(exchange, BdxStatus::UnexpectedMessage).await,
    };

    let mbs = pmbs.min(block_buf.len() as u16).max(1);
    let total_size = source.size();

    let accept = TransferAccept {
        receive: true,
        transfer_control: TransferControl {
            version: BDX_VERSION,
            sender_drive: true,
            receiver_drive: false,
            async_mode: false,
        },
        range_control: RangeControl {
            def_len: total_size.is_some(),
            start_offset: false,
            wide_range: total_size.map(|l| l > u32::MAX as u64).unwrap_or(false),
        },
        max_block_size: mbs,
        length: total_size.unwrap_or(0),
        metadata: &[],
    };
    exchange
        .send_with(|_, wb| {
            accept.write(wb)?;
            Ok(Some(OpCode::ReceiveAccept.into()))
        })
        .await?;

    let mut offset = 0u64;
    let mut counter = 0u32;
    loop {
        let n = source.read(offset, &mut block_buf[..mbs as usize]).await?;
        let is_eof = match total_size {
            Some(size) => offset + n as u64 >= size,
            None => n < mbs as usize,
        };
        let op = if is_eof {
            OpCode::BlockEof
        } else {
            OpCode::Block
        };

        let data = &block_buf[..n];
        exchange
            .send_with(|_, wb| {
                Block {
                    block_counter: counter,
                    data,
                }
                .write(wb)?;
                Ok(Some(op.into()))
            })
            .await?;
        offset += n as u64;

        // Await the acknowledgement (Sender-drive).
        let ack = {
            let rx = exchange.recv_fetch().await?;
            let meta = rx.meta();
            let op = classify(&meta)?;
            if matches!(op, OpCode::BlockAck | OpCode::BlockAckEof) {
                Some((
                    op == OpCode::BlockAckEof,
                    BlockQuery::parse(rx.payload())?.block_counter,
                ))
            } else {
                None
            }
        };
        exchange.rx_done()?;

        match ack {
            Some((eof_ack, c)) if c == counter && eof_ack == is_eof => {}
            Some((_, c)) if c != counter => {
                return abort(exchange, BdxStatus::BadBlockCounter).await
            }
            _ => return abort(exchange, BdxStatus::UnexpectedMessage).await,
        }

        if is_eof {
            break;
        }
        counter = counter.wrapping_add(1);
    }

    exchange.acknowledge().await?;
    Ok(offset)
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

/// Send a streaming `*Accept` with the chosen transfer control and block size.
async fn send_accept(
    exchange: &mut Exchange<'_>,
    receive: bool,
    transfer_control: TransferControl,
    max_block_size: u16,
) -> Result<(), Error> {
    let accept = TransferAccept {
        receive,
        transfer_control,
        range_control: RangeControl::default(),
        max_block_size,
        length: 0,
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

/// Await the `*Accept` and return the negotiated transfer control + block size,
/// or `None` if the responder selected no drive mode.
async fn recv_accept(
    exchange: &mut Exchange<'_>,
    receive: bool,
) -> Result<Option<(TransferControl, u16)>, Error> {
    let expected = if receive {
        OpCode::ReceiveAccept
    } else {
        OpCode::SendAccept
    };

    enum Outcome {
        Ok(TransferControl, u16),
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
                    Outcome::Ok(tc, accept.max_block_size)
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
        Outcome::Ok(tc, mbs) => Ok(Some((tc, mbs))),
        Outcome::NoMethod => Ok(None),
        Outcome::Unexpected => abort(exchange, BdxStatus::UnexpectedMessage).await,
        Outcome::Aborted(e) => Err(e),
    }
}

/// Await the opening `*Init` and return its proposed transfer control + block
/// size (the responder side of a transfer).
async fn recv_init(
    exchange: &mut Exchange<'_>,
    expected: OpCode,
) -> Result<(TransferControl, u16), Error> {
    enum Outcome {
        Ok(TransferControl, u16),
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
                Outcome::Ok(init.transfer_control, init.max_block_size)
            }
            Ok(_) => Outcome::Unexpected,
            Err(e) => Outcome::Aborted(e),
        }
    };
    exchange.rx_done()?;

    match outcome {
        Outcome::Ok(tc, pmbs) => Ok((tc, pmbs)),
        Outcome::Unexpected => abort(exchange, BdxStatus::UnexpectedMessage).await,
        Outcome::Aborted(e) => Err(e),
    }
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
            Some((tc, _mbs)) => {
                let drive = if tc.receiver_drive {
                    Drive::Driver
                } else {
                    Drive::Follower
                };
                Ok(BdxReader::new(self, drive))
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
            Some((tc, mbs)) => {
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

/// A reader over a BDX transfer - the Receiver side.
///
/// Obtained from [`Exchange::pull`](BdxPull::pull) on the initiating side, or
/// [`BdxReader::accept`] on the responding side (the swapped counterpart of a
/// [`BdxWriter`]). [`read`](Self::read) drives the protocol as needed and copies
/// the next bytes of the transfer into the caller's buffer, returning `0` at the
/// end of the transfer.
pub struct BdxReader<'a> {
    exchange: Exchange<'a>,
    drive: Drive,
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
    fn new(exchange: Exchange<'a>, drive: Drive) -> Self {
        Self {
            exchange,
            drive,
            counter: 0,
            held_counter: 0,
            held_eof: false,
            block_pos: 0,
            holding: false,
            finished: false,
        }
    }

    /// Accept an incoming BDX upload (a `SendInit`) and become the Receiver,
    /// returning a reader for the data the initiator is pushing. The responder
    /// counterpart of [`Exchange::push`](BdxPush::push).
    pub async fn accept(mut exchange: Exchange<'a>) -> Result<Self, Error> {
        let (tc, _pmbs) = recv_init(&mut exchange, OpCode::SendInit).await?;

        // Let the initiating sender drive if it can; otherwise we drive.
        let drive = if tc.sender_drive {
            Drive::Follower
        } else if tc.receiver_drive {
            Drive::Driver
        } else {
            return abort(&mut exchange, BdxStatus::TransferMethodNotSupported).await;
        };

        send_accept(
            &mut exchange,
            false,
            select(drive == Drive::Follower),
            _pmbs.min(STREAM_BLOCK_SIZE),
        )
        .await?;

        Ok(Self::new(exchange, drive))
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
/// [`BdxWriter::accept`] on the responding side (the swapped counterpart of a
/// [`BdxReader`]). [`write`](Self::write) stages and sends the data, driving the
/// protocol as needed; [`finish`](Self::finish) flushes the final block and
/// completes the transfer.
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

    /// Accept an incoming BDX download (a `ReceiveInit`) and become the Sender,
    /// returning a writer for the data the initiator is pulling. The responder
    /// counterpart of [`Exchange::pull`](BdxPull::pull).
    pub async fn accept(mut exchange: Exchange<'a>) -> Result<Self, Error> {
        let (tc, pmbs) = recv_init(&mut exchange, OpCode::ReceiveInit).await?;

        // Let the initiating receiver drive if it can; otherwise we drive.
        let drive = if tc.receiver_drive {
            Drive::Follower
        } else if tc.sender_drive {
            Drive::Driver
        } else {
            return abort(&mut exchange, BdxStatus::TransferMethodNotSupported).await;
        };

        let mbs = pmbs.min(STREAM_BLOCK_SIZE);
        send_accept(&mut exchange, true, select(drive == Drive::Driver), mbs).await?;

        Ok(Self::new(exchange, drive, mbs))
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
