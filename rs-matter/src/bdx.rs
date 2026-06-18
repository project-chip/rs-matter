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
//! [`BdxDownloadInitiator`]/[`BdxUploadInitiator`] initiator traits and the
//! [`BdxDownloadResponder`]/[`BdxUploadResponder`] responders, which yield
//! [`BdxReader`]/[`BdxWriter`] byte-stream handles.
//!
//! All multi-byte integers are little-endian (as per the Matter Core spec).

use num::FromPrimitive;
use num_derive::FromPrimitive;

use crate::error::{Error, ErrorCode};
use crate::sc::{self, GeneralCode, StatusReport};
use crate::transport::exchange::{Exchange, MessageMeta};
use crate::transport::{MAX_RX_PAYLOAD_SIZE, MAX_TX_PAYLOAD_SIZE};
use crate::utils::storage::{ReadBuf, WriteBuf};

mod handler;
mod nego;
mod read;
mod write;

pub use handler::*;
pub use read::*;
pub use write::*;

/// The buffer a BDX transfer stages each block in. Aliases the central
/// [`Buffer`](crate::transport::exchange::Buffer) (same size as an Interaction
/// Model exchange buffer), so a single [`PooledBuffers`] pool can be shared with
/// the data model if desired.
///
/// [`PooledBuffers`]: crate::utils::storage::pooled::PooledBuffers
pub type BdxBuffer = crate::transport::exchange::Buffer;

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

    /// The transfer control a Responder echoes back in an `*Accept` to select a
    /// single (synchronous) drive mode: Sender-drive if `sender_drive`, else
    /// Receiver-drive, at this protocol version.
    pub(crate) const fn select(sender_drive: bool) -> Self {
        Self {
            version: BDX_VERSION,
            sender_drive,
            receiver_drive: !sender_drive,
            async_mode: false,
        }
    }

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
        let mut rb = ReadBuf::new(payload);

        let transfer_control = TransferControl::from_byte(rb.le_u8()?);
        let range_control = RangeControl::from_byte(rb.le_u8()?);
        let max_block_size = rb.le_u16()?;

        let start_offset = if range_control.start_offset {
            if range_control.wide_range {
                rb.le_u64()?
            } else {
                rb.le_u32()? as u64
            }
        } else {
            0
        };
        let length = if range_control.def_len {
            if range_control.wide_range {
                rb.le_u64()?
            } else {
                rb.le_u32()? as u64
            }
        } else {
            0
        };

        let fdl = rb.le_u16()? as usize;
        // The variable-length tail (file designator + metadata) is sliced out of
        // `payload` directly so it borrows for `'a` rather than for the `ReadBuf`.
        let off = rb.read_off();
        let end = off.checked_add(fdl).ok_or(ErrorCode::TruncatedPacket)?;
        let file_designator = payload.get(off..end).ok_or(ErrorCode::TruncatedPacket)?;
        let metadata = &payload[end..];

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
            if self.range_control.wide_range {
                wb.le_u64(self.start_offset)?;
            } else {
                wb.le_u32(self.start_offset as u32)?;
            }
        }

        if self.range_control.def_len {
            if self.range_control.wide_range {
                wb.le_u64(self.length)?;
            } else {
                wb.le_u32(self.length as u32)?;
            }
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
        let mut rb = ReadBuf::new(payload);

        let transfer_control = TransferControl::from_byte(rb.le_u8()?);

        let (range_control, max_block_size, length) = if receive {
            let range_control = RangeControl::from_byte(rb.le_u8()?);
            // Max block size comes before the (optional) length.
            let max_block_size = rb.le_u16()?;
            let length = if range_control.def_len {
                if range_control.wide_range {
                    rb.le_u64()?
                } else {
                    rb.le_u32()? as u64
                }
            } else {
                0
            };
            (range_control, max_block_size, length)
        } else {
            (RangeControl::default(), rb.le_u16()?, 0)
        };

        // Any trailing bytes are the (optional) metadata; borrow from `payload`.
        let metadata = &payload[rb.read_off()..];

        Ok(Self {
            receive,
            transfer_control,
            range_control,
            max_block_size,
            length,
            metadata,
        })
    }

    /// Encode this message's payload (without the protocol header).
    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        wb.le_u8(self.transfer_control.to_byte())?;

        if self.receive {
            wb.le_u8(self.range_control.to_byte())?;
            wb.le_u16(self.max_block_size)?;

            if self.range_control.def_len {
                if self.range_control.wide_range {
                    wb.le_u64(self.length)?;
                } else {
                    wb.le_u32(self.length as u32)?;
                }
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
        let mut rb = ReadBuf::new(payload);
        let block_counter = rb.le_u32()?;
        // The remaining bytes are the block data; borrow them from `payload`.
        let data = &payload[rb.read_off()..];

        Ok(Self {
            block_counter,
            data,
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
        let mut rb = ReadBuf::new(payload);

        Ok(Self {
            block_counter: rb.le_u32()?,
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
        let mut rb = ReadBuf::new(payload);

        Ok(Self {
            block_counter: rb.le_u32()?,
            bytes_to_skip: rb.le_u64()?,
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

// ===========================================================================
// Shared streaming primitives (block size + drive mode) used by both the `read`
// and `write` submodules. The negotiation/framing helpers live in `nego`, and
// the byte-stream handles in `read`/`write`:
// `BdxReader`/`BdxDownloadInitiator`/`BdxUploadResponder` in `read`, and
// `BdxWriter`/`BdxUploadInitiator`/`BdxDownloadResponder` in `write`.
// ===========================================================================

/// The number of header bytes preceding a block's data (the 32-bit block counter).
const BLOCK_HEADER_LEN: usize = 4;

/// The largest block *data* that fits in a `payload`-sized application payload
/// once the block counter is accounted for, capped to the `u16` of the BDX
/// max-block-size field.
const fn max_block_size(payload: usize) -> u16 {
    let data = payload - BLOCK_HEADER_LEN;

    if data > u16::MAX as usize {
        u16::MAX
    } else {
        data as u16
    }
}

/// The largest block the *receiver* (`BdxReader`) can accept: it streams block
/// data straight out of the exchange RX buffer, so its capacity is the RX
/// application payload (minus the block counter).
const MAX_RX_BLOCK_SIZE: u16 = max_block_size(MAX_RX_PAYLOAD_SIZE);

/// The largest block the *sender* (`BdxWriter`) can emit into the exchange TX
/// buffer. The writer additionally bounds the block size by its caller-provided
/// staging buffer.
const MAX_TX_BLOCK_SIZE: u16 = max_block_size(MAX_TX_PAYLOAD_SIZE);

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
    fn transfer_control_select_picks_one_drive() {
        let sender = TransferControl::select(true);
        assert!(sender.sender_drive && !sender.receiver_drive && !sender.async_mode);
        assert_eq!(sender.version, BDX_VERSION);

        let receiver = TransferControl::select(false);
        assert!(receiver.receiver_drive && !receiver.sender_drive && !receiver.async_mode);
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
