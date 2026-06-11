/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

//! This module defines the BDX transfer-initiation messages: `SendInit`, `SendAccept`,
//! `ReceiveInit` and `ReceiveAccept`, per the Matter Core Spec.

use core::borrow::Borrow;

use crate::error::{Error, ErrorCode};
use crate::tlv::TLVElement;
use crate::utils::storage::{ReadBuf, WriteBuf};

/// The number of low bits in the Transfer Control byte reserved for the BDX version.
const VERSION_MASK: u8 = 0x0f;

bitflags::bitflags! {
    /// Transfer control flags used in `SendInit`/`ReceiveInit`/`*Accept` messages
    #[repr(transparent)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct TransferControlFlags: u8 {
        const SENDER_DRIVE = 0x10;
        const RECEIVER_DRIVE = 0x20;
        const ASYNC = 0x40;
    }
}

bitflags::bitflags! {
    /// The Range Control flags carried in the second byte of a `SendInit`/`ReceiveInit`
    /// message. These indicate presence of optional length/offset fields and their width.
    #[repr(transparent)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct RangeControlFlags: u8 {
        /// The `max_length` field is present.
        const DEF_LEN = 0x01;
        /// The `start_offset` field is present.
        const START_OFFSET = 0x02;
        /// The `start_offset`/`max_length` fields are 64-bit (rather than 32-bit) wide.
        const WIDERANGE = 0x10;
    }
}

/// Several messages use fields with variable size (4 or 8 bytes); this reads those fields
fn read_range_field<T>(pb: &mut ReadBuf<T>, widerange: bool) -> Result<u64, Error>
where
    T: Borrow<[u8]>,
{
    if widerange {
        pb.le_u64()
    } else {
        pb.le_u32().map(|v| v as u64)
    }
}

/// Several messages use fields with variable size (4 or 8 bytes); this writes those fields
fn write_range_field(wb: &mut WriteBuf, value: u64, widerange: bool) -> Result<(), Error> {
    if widerange {
        wb.le_u64(value)
    } else {
        wb.le_u32(value as u32)
    }
}

/// The shared payload of the BDX `SendInit` and `ReceiveInit` messages, as per the Matter
/// Core Spec. Both messages have an identical wire format except for opcode, so we combine them here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferInit<'a> {
    /// The proposed transfer-control mode(s) (sender-drive / receiver-drive / async).
    pub transfer_ctl: TransferControlFlags,
    /// The highest BDX version supported by the sender (0..=15). Currently always 0.
    pub version: u8,
    /// The proposed maximum block size for the transfer.
    pub max_block_size: u16,
    /// Optional proposed start offset of the data; `None` if absent.
    pub start_offset: Option<u64>,
    /// The proposed maximum length of the data; `None` for an indefinite-length transfer.
    pub max_length: Option<u64>,
    /// The file designator, opaque byte string.
    pub file_designator: &'a [u8],
    /// Optional trailing metadata, as a TLV element; `None` if absent.
    pub metadata: Option<TLVElement<'a>>,
}

impl<'a> TransferInit<'a> {
    pub fn read<T>(pb: &'a mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        let transfer_ctl_byte = pb.le_u8()?;
        let version = transfer_ctl_byte & VERSION_MASK;
        let transfer_ctl = TransferControlFlags::from_bits_truncate(transfer_ctl_byte & !VERSION_MASK);

        let range_ctl = RangeControlFlags::from_bits_truncate(pb.le_u8()?);
        let max_block_size = pb.le_u16()?;

        let widerange = range_ctl.contains(RangeControlFlags::WIDERANGE);

        let start_offset = range_ctl
            .contains(RangeControlFlags::START_OFFSET)
            .then(|| read_range_field(pb, widerange))
            .transpose()?;

        let max_length = range_ctl
            .contains(RangeControlFlags::DEF_LEN)
            .then(|| read_range_field(pb, widerange))
            .transpose()?;

        let file_des_len = pb.le_u16()? as usize;

        // The file designator and the (optional) trailing metadata occupy the rest of the
        // buffer; the metadata is simply whatever follows the file designator.
        let rest = pb.as_slice();
        if rest.len() < file_des_len {
            Err(ErrorCode::TruncatedPacket)?;
        }

        let file_designator = &rest[..file_des_len];
        let metadata = (rest.len() > file_des_len).then(|| TLVElement::new(&rest[file_des_len..]));

        Ok(Self {
            transfer_ctl,
            version,
            max_block_size,
            start_offset,
            max_length,
            file_designator,
            metadata,
        })
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        // `WIDERANGE` is shared by both range fields, so it is set if *either* needs 64 bits.
        let widerange = self.start_offset.is_some_and(|v| v > u32::MAX as u64)
            || self.max_length.is_some_and(|v| v > u32::MAX as u64);

        let mut range_ctl = RangeControlFlags::empty();
        range_ctl.set(RangeControlFlags::DEF_LEN, self.max_length.is_some());
        range_ctl.set(RangeControlFlags::START_OFFSET, self.start_offset.is_some());
        range_ctl.set(RangeControlFlags::WIDERANGE, widerange);

        wb.le_u8((self.version & VERSION_MASK) | self.transfer_ctl.bits())?;
        wb.le_u8(range_ctl.bits())?;
        wb.le_u16(self.max_block_size)?;

        if let Some(start_offset) = self.start_offset {
            write_range_field(wb, start_offset, widerange)?;
        }
        if let Some(max_length) = self.max_length {
            write_range_field(wb, max_length, widerange)?;
        }

        wb.le_u16(self.file_designator.len() as u16)?;
        wb.copy_from_slice(self.file_designator)?;

        if let Some(metadata) = &self.metadata {
            wb.copy_from_slice(metadata.raw_data())?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendInit<'a>(pub TransferInit<'a>);

impl<'a> SendInit<'a> {
    pub fn read<T>(pb: &'a mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        Ok(Self(TransferInit::read(pb)?))
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        self.0.write(wb)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveInit<'a>(pub TransferInit<'a>);

impl<'a> ReceiveInit<'a> {
    pub fn read<T>(pb: &'a mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        Ok(Self(TransferInit::read(pb)?))
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        self.0.write(wb)
    }
}

/// A BDX `SendAccept` message, as per the Matter Core Spec.
///
/// Sent by a node accepting a peer's `ReceiveInit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendAccept<'a> {
    /// The chosen transfer-control mode (exactly one of sender-drive / receiver-drive / async).
    pub transfer_ctl: TransferControlFlags,
    /// The chosen BDX version for the transfer (0..=15). Currently always 0.
    pub version: u8,
    /// The chosen maximum block size for the transfer.
    pub max_block_size: u16,
    /// Optional trailing metadata, as a TLV element
    pub metadata: Option<TLVElement<'a>>,
}

impl<'a> SendAccept<'a> {
    pub fn read<T>(pb: &'a mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        let transfer_ctl_byte = pb.le_u8()?;
        let version = transfer_ctl_byte & VERSION_MASK;
        let transfer_ctl = TransferControlFlags::from_bits_truncate(transfer_ctl_byte & !VERSION_MASK);

        let max_block_size = pb.le_u16()?;

        // Whatever follows is metadata (possibly empty).
        let rest = pb.as_slice();
        let metadata = (!rest.is_empty()).then(|| TLVElement::new(rest));

        Ok(Self {
            transfer_ctl,
            version,
            max_block_size,
            metadata,
        })
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        wb.le_u8((self.version & VERSION_MASK) | self.transfer_ctl.bits())?;
        wb.le_u16(self.max_block_size)?;

        if let Some(metadata) = &self.metadata {
            wb.copy_from_slice(metadata.raw_data())?;
        }

        Ok(())
    }
}

/// A BDX `ReceiveAccept` message, as per the Matter Core Spec (Table 100).
///
/// Sent by a node accepting a peer's `SendInit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveAccept<'a> {
    /// The chosen transfer-control mode (exactly one of sender-drive / receiver-drive / async).
    pub transfer_ctl: TransferControlFlags,
    /// The chosen BDX version for the transfer (0..=15). Currently always 0.
    pub version: u8,
    /// The chosen maximum block size for the transfer.
    pub max_block_size: u16,
    /// The chosen length of the transfer; `None` for an indefinite-length transfer.
    pub length: Option<u64>,
    /// Optional trailing metadata, as a TLV element
    pub metadata: Option<TLVElement<'a>>,

    // n.b. the C++ SDK has an additional "start_offset" field on this message, but the Core Spec 
    // has no such field, see Table 100.
}

impl<'a> ReceiveAccept<'a> {
    pub fn read<T>(pb: &'a mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        let transfer_ctl_byte = pb.le_u8()?;
        let version = transfer_ctl_byte & VERSION_MASK;
        let transfer_ctl = TransferControlFlags::from_bits_truncate(transfer_ctl_byte & !VERSION_MASK);

        let range_ctl = RangeControlFlags::from_bits_truncate(pb.le_u8()?);
        let max_block_size = pb.le_u16()?;

        let widerange = range_ctl.contains(RangeControlFlags::WIDERANGE);

        let length = range_ctl
            .contains(RangeControlFlags::DEF_LEN)
            .then(|| read_range_field(pb, widerange))
            .transpose()?;

        // Whatever follows is metadata (possibly empty).
        let rest = pb.as_slice();
        let metadata = (!rest.is_empty()).then(|| TLVElement::new(rest));

        Ok(Self {
            transfer_ctl,
            version,
            max_block_size,
            length,
            metadata,
        })
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        let widerange = self.length.is_some_and(|v| v > u32::MAX as u64);

        let mut range_ctl = RangeControlFlags::empty();
        range_ctl.set(RangeControlFlags::DEF_LEN, self.length.is_some());
        range_ctl.set(RangeControlFlags::WIDERANGE, widerange);

        wb.le_u8((self.version & VERSION_MASK) | self.transfer_ctl.bits())?;
        wb.le_u8(range_ctl.bits())?;
        wb.le_u16(self.max_block_size)?;

        if let Some(length) = self.length {
            write_range_field(wb, length, widerange)?;
        }

        if let Some(metadata) = &self.metadata {
            wb.copy_from_slice(metadata.raw_data())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::storage::{ReadBuf, WriteBuf};

    use super::*;

    // Unlike im.rs, we can't lean on the TLV layer doing serialization, so we keep a little
    // suite here that checks the BDX-custom serialization works.

    
    #[test]
    fn send_init_minimal() {
        check_roundtrip_send_init(SendInit(TransferInit {
            transfer_ctl: TransferControlFlags::SENDER_DRIVE,
            version: 1,
            max_block_size: 1024,
            start_offset: None,
            max_length: None,
            file_designator: b"my-file",
            metadata: None,
        }));
    }

    #[test]
    fn send_init_with_range_and_metadata() {
        check_roundtrip_send_init(SendInit(TransferInit {
            transfer_ctl: TransferControlFlags::RECEIVER_DRIVE,
            version: 1,
            max_block_size: 512,
            start_offset: Some(42),
            max_length: Some(100_000),
            file_designator: b"ota.bin",
            // An (empty) anonymous TLV structure: 0x15 = struct start, 0x18 = end-of-container.
            metadata: Some(TLVElement::new(&[0x15, 0x18])),
        }));
    }

    #[test]
    fn send_init_widerange() {
        check_roundtrip_send_init(SendInit(TransferInit {
            transfer_ctl: TransferControlFlags::SENDER_DRIVE,
            version: 1,
            max_block_size: 1280,
            start_offset: Some(8),
            max_length: Some(u64::from(u32::MAX) + 1),
            file_designator: b"big",
            metadata: None,
        }));
    }

    #[test]
    fn send_accept_roundtrip() {
        check_roundtrip_send_accept(SendAccept {
            transfer_ctl: TransferControlFlags::SENDER_DRIVE,
            version: 1,
            max_block_size: 1024,
            // An (empty) anonymous TLV structure: 0x15 = struct start, 0x18 = end-of-container.
            metadata: Some(TLVElement::new(&[0x15, 0x18])),
        });
    }

    #[test]
    fn receive_accept_with_length_and_metadata() {
        check_roundtrip_receive_accept(ReceiveAccept {
            transfer_ctl: TransferControlFlags::RECEIVER_DRIVE,
            version: 1,
            max_block_size: 512,
            length: Some(100_000),
            metadata: Some(TLVElement::new(&[0x15, 0x18])),
        });
    }

    #[test]
    fn receive_accept_widerange() {
        check_roundtrip_receive_accept(ReceiveAccept {
            transfer_ctl: TransferControlFlags::RECEIVER_DRIVE,
            version: 1,
            max_block_size: 1280,
            length: Some(u64::from(u32::MAX) + 1),
            metadata: None,
        });
    }

    // Utilities for roundtrip testing

    fn check_roundtrip_send_init(msg: SendInit) {
        let mut buf = [0; 256];

        let mut wb = WriteBuf::new(&mut buf);
        msg.write(&mut wb).unwrap();
        let len = wb.as_slice().len();

        let mut rb = ReadBuf::new(&buf[..len]);
        let parsed = SendInit::read(&mut rb).unwrap();

        assert_eq!(msg, parsed);
    }

    fn check_roundtrip_send_accept(msg: SendAccept) {
        let mut buf = [0; 256];

        let mut wb = WriteBuf::new(&mut buf);
        msg.write(&mut wb).unwrap();
        let len = wb.as_slice().len();

        let mut rb = ReadBuf::new(&buf[..len]);
        let parsed = SendAccept::read(&mut rb).unwrap();

        assert_eq!(msg, parsed);
    }

    fn check_roundtrip_receive_accept(msg: ReceiveAccept) {
        let mut buf = [0; 256];

        let mut wb = WriteBuf::new(&mut buf);
        msg.write(&mut wb).unwrap();
        let len = wb.as_slice().len();

        let mut rb = ReadBuf::new(&buf[..len]);
        let parsed = ReceiveAccept::read(&mut rb).unwrap();

        assert_eq!(msg, parsed);
    }

}
