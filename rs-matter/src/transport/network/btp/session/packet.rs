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

use core::fmt;

use crate::error::{Error, ErrorCode};
use crate::utils::bitflags::bitflags;
use crate::utils::storage::WriteBuf;

bitflags! {
    /// Models the flags in the BTP header.
    ///
    /// Consult the Matter Core Specification for more information.
    #[repr(transparent)]
    #[derive(Default)]
    #[cfg_attr(not(feature = "defmt"), derive(Debug, Copy, Clone, Eq, PartialEq, Hash))]
    pub struct BtpFlags: u8 {
        const HANDSHAKE = 0x40;
        const MANAGEMENT = 0x20;
        const ACK = 0x08;
        const ENDING_SEGMENT = 0x04;
        // NOTE: NOT documented in the Matter Core Spec but specified here:
        // https://github.com/project-chip/connectedhomeip/blob/master/src/ble/BtpEngine.h#L83
        const CONTINUE = 0x02;
        const BEGINNING_SEGMENT = 0x01;
    }
}

impl fmt::Display for BtpFlags {
    // TODO: defmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = false;
        for flag in [
            Self::HANDSHAKE,
            Self::MANAGEMENT,
            Self::ACK,
            Self::BEGINNING_SEGMENT,
            Self::CONTINUE,
            Self::ENDING_SEGMENT,
        ] {
            if self.contains(flag) {
                if sep {
                    write!(f, "|")?;
                }

                let str = match flag {
                    Self::HANDSHAKE => "H",
                    Self::MANAGEMENT => "M",
                    Self::ACK => "A",
                    Self::BEGINNING_SEGMENT => "B",
                    Self::CONTINUE => "C",
                    Self::ENDING_SEGMENT => "E",
                    _ => "?",
                };

                write!(f, "{}", str)?;
                sep = true;
            }
        }

        Ok(())
    }
}

/// Models the BTP header.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BtpHdr {
    flags: BtpFlags,
    opcode: u8,
    ack_num: u8,
    seq_num: u8,
    msg_len: u16,
}

impl BtpHdr {
    /// Create a new BTP header.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            flags: BtpFlags::empty(),
            opcode: 0,
            ack_num: 0,
            seq_num: 0,
            msg_len: 0,
        }
    }

    /// Decode a BTP header from an iterator of bytes.
    pub fn from<I>(msg: I) -> Result<Self, Error>
    where
        I: Iterator<Item = u8>,
    {
        let mut hdr = Self::new();

        hdr.decode(msg)?;

        Ok(hdr)
    }

    /// Return `true` if the BTP header indicates a handshake message (request or response).
    pub fn is_handshake(&self) -> bool {
        self.flags.contains(BtpFlags::HANDSHAKE)
    }

    /// Set the BTP header to indicate a handshake message (request or response).
    pub fn set_handshake(&mut self) {
        self.flags |= BtpFlags::HANDSHAKE | BtpFlags::BEGINNING_SEGMENT | BtpFlags::ENDING_SEGMENT;
    }

    /// Get the opcode from the BTP header.
    /// An opcode will be present only if the header indicates a management message.
    pub fn get_opcode(&self) -> Option<u8> {
        self.flags
            .contains(BtpFlags::MANAGEMENT)
            .then_some(self.opcode)
    }

    /// Set (or clear) the opcode in the BTP header.
    /// This automatically marks/unmarks the message as a management message.
    pub fn set_opcode(&mut self, opcode: Option<u8>) {
        if let Some(opcode) = opcode {
            self.flags |= BtpFlags::MANAGEMENT;
            self.opcode = opcode
        } else {
            self.flags.remove(BtpFlags::MANAGEMENT);
            self.opcode = 0;
        }
    }

    /// Get the acknowledgement number from the BTP header.
    /// An acknowledgement number will be present only if the header indicates an acknowledgement.
    pub fn get_ack(&self) -> Option<u8> {
        self.flags.contains(BtpFlags::ACK).then_some(self.ack_num)
    }

    /// Set (or clear) the acknowledgement number in the BTP header.
    /// This automatically marks/unmarks the message with the acknowledgement flag.
    pub fn set_ack(&mut self, ack_num: Option<u8>) {
        if let Some(ack_num) = ack_num {
            self.flags |= BtpFlags::ACK;
            self.ack_num = ack_num;
        } else {
            self.flags.remove(BtpFlags::ACK);
            self.ack_num = 0;
        }
    }

    /// Get the sequence number from the BTP header.
    /// A sequence number will be present only if the header does not indicate a handshake message.
    pub fn get_seq(&self) -> Option<u8> {
        (!self.flags.contains(BtpFlags::HANDSHAKE)).then_some(self.seq_num)
    }

    /// Set (or clear) the sequence number in the BTP header.
    /// This automatically marks/unmarks the message as a handshake message.
    pub fn set_seq(&mut self, seq_num: Option<u8>) {
        if let Some(seq_num) = seq_num {
            self.flags.remove(BtpFlags::HANDSHAKE);
            self.seq_num = seq_num;
        } else {
            self.flags |= BtpFlags::HANDSHAKE;
            self.seq_num = 0;
        }
    }

    /// Indicate that the BTP header is a standalone acknowledgement.
    /// Turns out this is possible even if not clearly specified ion the Matter Core spec.
    /// Standalone ACKs seem to have the following properties:
    /// - No message length
    /// - No continue flag
    /// - No final segment
    /// - An acknowledgement number
    /// - A sequence number (obviously)
    pub fn is_standalone_ack(&self) -> bool {
        !self.is_handshake()
            && self.get_msg_len().is_none()
            && !self.is_continue()
            && !self.is_final()
            && self.get_ack().is_some()
    }

    /// Get the message length from the BTP header.
    /// A message length will be present only if the header indicates a beginning segment and the header does not
    /// indicate a handshake message.
    pub fn get_msg_len(&self) -> Option<u16> {
        (self.flags.contains(BtpFlags::BEGINNING_SEGMENT)
            && !self.flags.contains(BtpFlags::HANDSHAKE))
        .then_some(self.msg_len)
    }

    /// Set (or clear) the message length in the BTP header.
    /// This automatically marks/unmarks the message as a beginning segment.
    pub fn set_msg_len(&mut self, msg_len: Option<u16>) {
        if let Some(msg_len) = msg_len {
            self.flags |= BtpFlags::BEGINNING_SEGMENT;
            self.msg_len = msg_len;
        } else {
            self.flags.remove(BtpFlags::BEGINNING_SEGMENT);
            self.msg_len = 0;
        }
    }

    /// Return `true` if the BTP header indicates a continuation segment.
    /// Not specified in the Matter Core spec, but apparently exists.
    pub fn is_continue(&self) -> bool {
        self.flags.contains(BtpFlags::CONTINUE)
    }

    /// Set the BTP header to indicate a continuation segment.
    /// Not specified in the Matter Core spec, but apparently exists.
    pub fn set_continue(&mut self) {
        self.flags |= BtpFlags::CONTINUE;
    }

    /// Return `true` if the BTP header indicates the final segment of a message.
    pub fn is_final(&self) -> bool {
        self.flags.contains(BtpFlags::ENDING_SEGMENT)
    }

    /// Set the BTP header to indicate the final segment of a message.
    pub fn set_final(&mut self) {
        self.flags |= BtpFlags::ENDING_SEGMENT;
    }

    /// Load the header from a byte iterator.
    fn decode<I>(&mut self, mut msg: I) -> Result<(), Error>
    where
        I: Iterator<Item = u8>,
    {
        self.flags = BtpFlags::from_bits_truncate(msg.next().ok_or(ErrorCode::Invalid)?);

        if self.flags.contains(BtpFlags::MANAGEMENT) {
            self.opcode = msg.next().ok_or(ErrorCode::Invalid)?;
        }

        if self.flags.contains(BtpFlags::ACK) {
            self.ack_num = msg.next().ok_or(ErrorCode::Invalid)?;
        }

        if !self.flags.contains(BtpFlags::HANDSHAKE) {
            self.seq_num = msg.next().ok_or(ErrorCode::Invalid)?;
        }

        if self.flags.contains(BtpFlags::BEGINNING_SEGMENT)
            && !self.flags.contains(BtpFlags::HANDSHAKE)
        {
            let msg_len = [
                msg.next().ok_or(ErrorCode::Invalid)?,
                msg.next().ok_or(ErrorCode::Invalid)?,
            ];

            self.msg_len = u16::from_le_bytes(msg_len);
        }

        trace!("[decode] {}", self);
        Ok(())
    }

    /// Encode the header into a byte buffer.
    pub fn encode(&self, resp_buf: &mut WriteBuf) -> Result<(), Error> {
        trace!("[encode] {}", self);

        resp_buf.le_u8(self.flags.bits())?;

        if self.flags.contains(BtpFlags::MANAGEMENT) {
            resp_buf.le_u8(self.opcode)?;
        }

        if self.flags.contains(BtpFlags::ACK) {
            resp_buf.le_u8(self.ack_num)?;
        }

        if !self.flags.contains(BtpFlags::HANDSHAKE) {
            resp_buf.le_u8(self.seq_num)?;
        }

        if self.flags.contains(BtpFlags::BEGINNING_SEGMENT)
            && !self.flags.contains(BtpFlags::HANDSHAKE)
        {
            resp_buf.le_u16(self.msg_len)?;
        }

        Ok(())
    }

    /// Return the length of the encoded header in bytes.
    pub fn len(&self) -> usize {
        let mut len = 1; // Flags

        if self.flags.contains(BtpFlags::MANAGEMENT) {
            len += 1;
        }

        if self.flags.contains(BtpFlags::ACK) {
            len += 1;
        }

        if !self.flags.contains(BtpFlags::HANDSHAKE) {
            len += 1;
        }

        if self.flags.contains(BtpFlags::BEGINNING_SEGMENT)
            && !self.flags.contains(BtpFlags::HANDSHAKE)
        {
            len += 2;
        }

        len
    }
}

impl fmt::Display for BtpHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.flags.is_empty() {
            write!(f, "{}", self.flags)?;
        }

        if let Some(opcode) = self.get_opcode() {
            write!(f, ",OP:{:x}", opcode)?;
        }

        if let Some(ack_num) = self.get_ack() {
            write!(f, ",ACTR:{:x}", ack_num)?;
        }

        if let Some(seq_num) = self.get_seq() {
            write!(f, ",CTR:{:x}", seq_num)?;
        }

        if let Some(msg_len) = self.get_msg_len() {
            write!(f, ",LEN:{:x}", msg_len)?;
        }

        Ok(())
    }
}

/// Models the BTP handshake request.
#[derive(Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HandshakeReq {
    /// The versions supported by the BTP handshake request.
    versions: u32,
    /// The ATT MTU size supported by the BTP handshake request.
    pub mtu: u16,
    /// The window size supported by the BTP handshake request.
    pub window_size: u8,
}

impl HandshakeReq {
    /// Create a new BTP handshake request from a byte iterator representing the raw BTP packet.
    pub fn from<I>(msg: I) -> Result<Self, Error>
    where
        I: Iterator<Item = u8>,
    {
        let mut req = Self::default();

        req.decode(msg)?;

        Ok(req)
    }

    /// Return an iterator over the versions supported by the BTP handshake request.
    pub fn versions(&self) -> impl Iterator<Item = u8> + '_ {
        (0..7u8)
            .map(|index| ((self.versions >> (index * 4)) & 0xff) as u8)
            .filter(|version| *version > 0)
    }

    // Future
    // Set the versions supported by the BTP handshake request.
    // fn set_versions<I>(&mut self, versions: I)
    // where
    //     I: Iterator<Item = u8>,
    // {
    //     for (index, version) in (0_u8..).zip(versions) {
    //         self.versions |= (version as u32) << (index * 4);
    //     }
    // }

    /// Decode a BTP handshake request from a byte iterator representing the data payload of a BTP Handshake request packet.
    fn decode<I>(&mut self, mut msg: I) -> Result<(), Error>
    where
        I: Iterator<Item = u8>,
    {
        self.versions = u32::from_le_bytes([
            msg.next().ok_or(ErrorCode::Invalid)?,
            msg.next().ok_or(ErrorCode::Invalid)?,
            msg.next().ok_or(ErrorCode::Invalid)?,
            msg.next().ok_or(ErrorCode::Invalid)?,
        ]);
        self.mtu = u16::from_le_bytes([
            msg.next().ok_or(ErrorCode::Invalid)?,
            msg.next().ok_or(ErrorCode::Invalid)?,
        ]);
        self.window_size = msg.next().ok_or(ErrorCode::Invalid)?;

        Ok(())
    }

    // Future
    // Encode the BTP handshake request into a byte buffer.
    // fn encode(&self, resp_buf: &mut WriteBuf) -> Result<(), Error> {
    //     resp_buf.le_u32(self.versions)?;
    //     resp_buf.le_u16(self.mtu)?;
    //     resp_buf.le_u8(self.window_size)?;

    //     Ok(())
    // }
}

/// Models the BTP handshake response.
#[derive(Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HandshakeResp {
    /// The version of the BTP protocol supported by the responder.
    pub version: u8,
    /// The chosen ATT MTU size by the responder.
    pub mtu: u16,
    /// The chosen window size by the responder.
    pub window_size: u8,
}

impl HandshakeResp {
    // Future
    // // Decode a BTP handshake request from a byte iterator representing the data payload of a BTP Handshake request packet.
    // fn decode<I>(&mut self, mut msg: I) -> Result<(), Error>
    // where
    //     I: Iterator<Item = u8>,
    // {
    //     self.version = msg.next().ok_or(ErrorCode::Invalid)?;
    //     self.mtu = u16::from_le_bytes([
    //         msg.next().ok_or(ErrorCode::Invalid)?,
    //         msg.next().ok_or(ErrorCode::Invalid)?,
    //     ]);
    //     self.window_size = msg.next().ok_or(ErrorCode::Invalid)?;

    //     Ok(())
    // }

    /// Encode the BTP handshake response into a byte buffer.
    pub fn encode(&self, resp_buf: &mut WriteBuf) -> Result<(), Error> {
        resp_buf.le_u8(self.version)?;
        resp_buf.le_u16(self.mtu)?;
        resp_buf.le_u8(self.window_size)?;
        Ok(())
    }
}
