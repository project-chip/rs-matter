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

use crate::fmt::Bytes;
use crate::transport::plain_hdr;
use crate::utils::storage::{ParseBuf, WriteBuf};
use crate::{crypto, error::*};

use super::network::Address;

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct ExchFlags: u8 {
        const VENDOR = 0x10;
        const SECEX = 0x08;
        const RELIABLE = 0x04;
        const ACK = 0x02;
        const INITIATOR = 0x01;
    }
}

impl fmt::Display for ExchFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = false;
        for flag in [
            Self::INITIATOR,
            Self::ACK,
            Self::RELIABLE,
            Self::SECEX,
            Self::VENDOR,
        ] {
            if self.contains(flag) {
                if sep {
                    write!(f, "|")?;
                }

                let str = match flag {
                    Self::INITIATOR => "I",
                    Self::ACK => "A",
                    Self::RELIABLE => "R",
                    Self::SECEX => "SX",
                    Self::VENDOR => "V",
                    _ => "?",
                };

                write!(f, "{}", str)?;
                sep = true;
            }
        }

        Ok(())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for ExchFlags {
    fn format(&self, f: defmt::Formatter<'_>) {
        let mut sep = false;
        for flag in [
            Self::INITIATOR,
            Self::ACK,
            Self::RELIABLE,
            Self::SECEX,
            Self::VENDOR,
        ] {
            if self.contains(flag) {
                if sep {
                    defmt::write!(f, "|");
                }

                let str = match flag {
                    Self::INITIATOR => "I",
                    Self::ACK => "A",
                    Self::RELIABLE => "R",
                    Self::SECEX => "SX",
                    Self::VENDOR => "V",
                    _ => "?",
                };

                defmt::write!(f, "{}", str);
                sep = true;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtoHdr {
    pub exch_id: u16,
    exch_flags: ExchFlags,
    pub proto_id: u16,
    pub proto_opcode: u8,
    proto_vendor_id: u16,
    ack_msg_ctr: u32,
}

impl ProtoHdr {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            exch_id: 0,
            exch_flags: ExchFlags::empty(),
            proto_id: u16::MAX,
            proto_opcode: u8::MAX,
            proto_vendor_id: 0,
            ack_msg_ctr: 0,
        }
    }

    pub fn is_decoded(&self) -> bool {
        // TODO: In future, consider better ways of representing a not-yet-decoded header
        // in the packet - i.e. - `Option<ProtoHdr>` or similar
        self.proto_id != u16::MAX && self.proto_opcode != u8::MAX
    }

    pub fn opcode<T: num::FromPrimitive>(&self) -> Result<T, Error> {
        num::FromPrimitive::from_u8(self.proto_opcode).ok_or(ErrorCode::Invalid.into())
    }

    pub fn check_opcode<T: num::FromPrimitive + PartialEq>(&self, opcode: T) -> Result<(), Error> {
        if self.opcode::<T>()? == opcode {
            Ok(())
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }

    pub fn get_vendor(&self) -> Option<u16> {
        self.exch_flags
            .contains(ExchFlags::VENDOR)
            .then_some(self.proto_vendor_id)
    }

    pub fn set_vendor(&mut self, vendor_id: Option<u16>) {
        if let Some(vendor_id) = vendor_id {
            self.exch_flags |= ExchFlags::VENDOR;
            self.proto_vendor_id = vendor_id;
        } else {
            self.exch_flags.remove(ExchFlags::VENDOR);
            self.proto_vendor_id = 0;
        }
    }

    pub fn is_security_ext(&self) -> bool {
        self.exch_flags.contains(ExchFlags::SECEX)
    }

    pub fn is_reliable(&self) -> bool {
        self.exch_flags.contains(ExchFlags::RELIABLE)
    }

    pub fn unset_reliable(&mut self) {
        self.exch_flags.remove(ExchFlags::RELIABLE)
    }

    pub fn set_reliable(&mut self) {
        self.exch_flags |= ExchFlags::RELIABLE;
    }

    pub fn get_ack(&self) -> Option<u32> {
        self.exch_flags
            .contains(ExchFlags::ACK)
            .then_some(self.ack_msg_ctr)
    }

    pub fn set_ack(&mut self, ack_msg_ctr: Option<u32>) {
        if let Some(ack_msg_ctr) = ack_msg_ctr {
            self.exch_flags |= ExchFlags::ACK;
            self.ack_msg_ctr = ack_msg_ctr;
        } else {
            self.exch_flags.remove(ExchFlags::ACK);
            self.ack_msg_ctr = 0;
        }
    }

    pub fn is_initiator(&self) -> bool {
        self.exch_flags.contains(ExchFlags::INITIATOR)
    }

    pub fn unset_initiator(&mut self) {
        self.exch_flags.remove(ExchFlags::INITIATOR);
    }

    pub fn set_initiator(&mut self) {
        self.exch_flags |= ExchFlags::INITIATOR;
    }

    pub fn toggle_initiator(&mut self) {
        if self.is_initiator() {
            self.unset_initiator();
        } else {
            self.set_initiator();
        }
    }

    /// Adjusts the reliability settings (flags R and A) in the proto header
    /// by inspecting the reliability of the network protocol itself.
    ///
    /// In case the protocol is reliable - yet the message has the R or A flags set -
    /// these flags are lowered. Warnings will be logged in this case if the `rx` parameter
    /// is set to `true` (i.e. this is an incoming message), because this situation
    /// represents a Matter protocol violation, as per the Matter spec.
    pub fn adjust_reliability(&mut self, rx: bool, addr: &Address) {
        if addr.is_reliable() {
            if rx {
                if self.is_reliable() {
                    warn!("Detected a reliable message over a reliable transport; reliability request will not be honored with an ACK");
                }

                if self.get_ack().is_some() {
                    warn!("Detected an ACK counter over a reliable transport; ACK counter will be discarded");
                }
            }

            self.unset_reliable();
            self.set_ack(None);
        }
    }

    pub fn decrypt_and_decode(
        &mut self,
        plain_hdr: &plain_hdr::PlainHdr,
        parsebuf: &mut ParseBuf,
        peer_nodeid: u64,
        dec_key: Option<&[u8]>,
    ) -> Result<(), Error> {
        if let Some(d) = dec_key {
            // We decrypt only if the decryption key is valid
            decrypt_in_place(plain_hdr.ctr, peer_nodeid, parsebuf, d)?;
        }

        self.exch_flags = ExchFlags::from_bits(parsebuf.le_u8()?).ok_or(ErrorCode::Invalid)?;
        self.proto_opcode = parsebuf.le_u8()?;
        self.exch_id = parsebuf.le_u16()?;
        self.proto_id = parsebuf.le_u16()?;

        if self.exch_flags.contains(ExchFlags::VENDOR) {
            self.proto_vendor_id = parsebuf.le_u16()?;
        }
        if self.exch_flags.contains(ExchFlags::ACK) {
            self.ack_msg_ctr = parsebuf.le_u32()?;
        }
        trace!("[decode] {}", self);
        trace!("[rx payload]: {}", Bytes(parsebuf.as_mut_slice()));
        Ok(())
    }

    pub fn encode(&self, resp_buf: &mut WriteBuf) -> Result<(), Error> {
        trace!("[encode] {}", self);
        resp_buf.le_u8(self.exch_flags.bits())?;
        resp_buf.le_u8(self.proto_opcode)?;
        resp_buf.le_u16(self.exch_id)?;
        resp_buf.le_u16(self.proto_id)?;
        if let Some(vendor_id) = self.get_vendor() {
            resp_buf.le_u16(vendor_id)?;
        }
        if let Some(ack_msg_ctr) = self.get_ack() {
            resp_buf.le_u32(ack_msg_ctr)?;
        }
        Ok(())
    }
}

impl Default for ProtoHdr {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ProtoHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.is_decoded() {
            write!(f, "(encoded)")?;
            return Ok(());
        }

        if !self.exch_flags.is_empty() {
            write!(f, "{},", self.exch_flags)?;
        }

        write!(
            f,
            "EID:{:x},PROTO:{:x},OP:{:x}",
            self.exch_id, self.proto_id, self.proto_opcode
        )?;

        if let Some(ack_msg_ctr) = self.get_ack() {
            write!(f, ",ACTR:{:x}", ack_msg_ctr)?;
        }

        if let Some(vendor_id) = self.get_vendor() {
            write!(f, ",VID:{:x}", vendor_id)?;
        }

        Ok(())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for ProtoHdr {
    fn format(&self, f: defmt::Formatter<'_>) {
        if !self.is_decoded() {
            defmt::write!(f, "(encoded)");
            return;
        }

        if !self.exch_flags.is_empty() {
            defmt::write!(f, "{},", self.exch_flags);
        }

        defmt::write!(
            f,
            "EID:{:x},PROTO:{:x},OP:{:x}",
            self.exch_id,
            self.proto_id,
            self.proto_opcode
        );

        if let Some(ack_msg_ctr) = self.get_ack() {
            defmt::write!(f, ",ACTR:{:x}", ack_msg_ctr);
        }

        if let Some(vendor_id) = self.get_vendor() {
            defmt::write!(f, ",VID:{:x}", vendor_id);
        }
    }
}

fn get_iv(recvd_ctr: u32, peer_nodeid: u64, iv: &mut [u8]) -> Result<(), Error> {
    // The IV is the source address (64-bit) followed by the message counter (32-bit)
    let mut write_buf = WriteBuf::new(iv);
    // For some reason, this is 0 in the 'bypass' mode
    write_buf.le_u8(0)?;
    write_buf.le_u32(recvd_ctr)?;
    write_buf.le_u64(peer_nodeid)?;
    Ok(())
}

pub fn encrypt_in_place(
    send_ctr: u32,
    peer_nodeid: u64,
    plain_hdr: &[u8],
    writebuf: &mut WriteBuf,
    key: &[u8],
) -> Result<(), Error> {
    // IV
    let mut iv = [0_u8; crypto::AEAD_NONCE_LEN_BYTES];
    get_iv(send_ctr, peer_nodeid, &mut iv)?;

    // Cipher Text
    let tag_space = [0u8; crypto::AEAD_MIC_LEN_BYTES];
    writebuf.append(&tag_space)?;
    let cipher_text = writebuf.as_mut_slice();

    crypto::encrypt_in_place(
        key,
        &iv,
        plain_hdr,
        cipher_text,
        cipher_text.len() - crypto::AEAD_MIC_LEN_BYTES,
    )?;
    //println!("Cipher Text: {:x?}", cipher_text);

    Ok(())
}

fn decrypt_in_place(
    recvd_ctr: u32,
    peer_nodeid: u64,
    parsebuf: &mut ParseBuf,
    key: &[u8],
) -> Result<(), Error> {
    // AAD:
    //    the unencrypted header of this packet
    let mut aad = [0_u8; crypto::AEAD_AAD_LEN_BYTES];
    let parsed_slice = parsebuf.parsed_as_slice();
    if parsed_slice.len() == aad.len() {
        // The plain_header is variable sized in length, I wonder if the AAD is fixed at 8, or the variable size.
        // If so, we need to handle it cleanly here.
        aad.copy_from_slice(parsed_slice);
    } else {
        Err(ErrorCode::InvalidAAD)?;
    }

    // IV:
    //   the specific way for creating IV is in get_iv
    let mut iv = [0_u8; crypto::AEAD_NONCE_LEN_BYTES];
    get_iv(recvd_ctr, peer_nodeid, &mut iv)?;

    let cipher_text = parsebuf.as_mut_slice();
    //println!("AAD: {:x?}", aad);
    //println!("Cipher Text: {:x?}", cipher_text);
    //println!("IV: {:x?}", iv);
    //println!("Key: {:x?}", key);

    crypto::decrypt_in_place(key, &iv, &aad, cipher_text)?;
    // println!("Plain Text: {:x?}", cipher_text);
    parsebuf.tail(crypto::AEAD_MIC_LEN_BYTES)?;
    Ok(())
}

pub const fn max_proto_hdr_len() -> usize {
    // exchange flags
    1 +
    // protocol opcode
        1 +
    // exchange ID
        2 +
    // protocol ID
        2 +
    // [optional] protocol vendor ID
        2 +
    // [optional] acknowledged message counter
        4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_decrypt_success() {
        // These values are captured from an execution run of the chip-tool binary
        let recvd_ctr = 15287282;
        let mut input_buf: [u8; 71] = [
            0x0, 0x2, 0x0, 0x0, 0xf2, 0x43, 0xe9, 0x0, 0x31, 0xb5, 0x66, 0xec, 0x8b, 0x5b, 0xf4,
            0x17, 0xe4, 0x80, 0xf3, 0xd5, 0x11, 0x59, 0x19, 0xb5, 0x23, 0x91, 0x35, 0x37, 0xb,
            0xf9, 0xbf, 0x69, 0x55, 0x11, 0x75, 0x87, 0x77, 0x19, 0xfc, 0xf3, 0x5d, 0x4b, 0x47,
            0x1f, 0xb0, 0x5e, 0xbe, 0xb5, 0x10, 0xad, 0xc6, 0x78, 0x94, 0x50, 0xe5, 0xd2, 0xe0,
            0x80, 0xef, 0xa8, 0x3a, 0xf0, 0xa6, 0xaf, 0x1b, 0x2, 0x35, 0xa7, 0xd1, 0xc6, 0x32,
        ];
        let mut parsebuf = ParseBuf::new(&mut input_buf);
        let key = [
            0x66, 0x63, 0x31, 0x97, 0x43, 0x9c, 0x17, 0xb9, 0x7e, 0x10, 0xee, 0x47, 0xc8, 0x8,
            0x80, 0x4a,
        ];

        // decrypt_in_place() requires that the plain_text buffer of 8 bytes must be already parsed as AAD, we'll just fake it here
        parsebuf.le_u32().unwrap();
        parsebuf.le_u32().unwrap();

        decrypt_in_place(recvd_ctr, 0, &mut parsebuf, &key).unwrap();
        assert_eq!(
            parsebuf.as_slice(),
            [
                0x5, 0x8, 0x70, 0x0, 0x1, 0x0, 0x15, 0x28, 0x0, 0x28, 0x1, 0x36, 0x2, 0x15, 0x37,
                0x0, 0x24, 0x0, 0x0, 0x24, 0x1, 0x30, 0x24, 0x2, 0x2, 0x18, 0x35, 0x1, 0x24, 0x0,
                0x0, 0x2c, 0x1, 0x2, 0x57, 0x57, 0x24, 0x2, 0x3, 0x25, 0x3, 0xb8, 0xb, 0x18, 0x18,
                0x18, 0x18
            ]
        );
    }

    #[test]
    pub fn test_encrypt_success() {
        // These values are captured from an execution run of the chip-tool binary
        let send_ctr = 41;

        let mut main_buf: [u8; 52] = [0; 52];
        let mut writebuf = WriteBuf::new(&mut main_buf);

        let plain_hdr: [u8; 8] = [0x0, 0x11, 0x0, 0x0, 0x29, 0x0, 0x0, 0x0];

        let plain_text: [u8; 28] = [
            5, 8, 0x58, 0x28, 0x01, 0x00, 0x15, 0x36, 0x00, 0x15, 0x37, 0x00, 0x24, 0x00, 0x01,
            0x24, 0x02, 0x06, 0x24, 0x03, 0x01, 0x18, 0x35, 0x01, 0x18, 0x18, 0x18, 0x18,
        ];
        writebuf.append(&plain_text).unwrap();

        let key = [
            0x44, 0xd4, 0x3c, 0x91, 0xd2, 0x27, 0xf3, 0xba, 0x08, 0x24, 0xc5, 0xd8, 0x7c, 0xb8,
            0x1b, 0x33,
        ];

        encrypt_in_place(send_ctr, 0, &plain_hdr, &mut writebuf, &key).unwrap();
        assert_eq!(
            writebuf.as_slice(),
            [
                189, 83, 250, 121, 38, 87, 97, 17, 153, 78, 243, 20, 36, 11, 131, 142, 136, 165,
                227, 107, 204, 129, 193, 153, 42, 131, 138, 254, 22, 190, 76, 244, 116, 45, 156,
                215, 229, 130, 215, 147, 73, 21, 88, 216
            ]
        );
    }
}
