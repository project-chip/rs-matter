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

use core::fmt;

use crate::crypto::{self, Aead, Crypto};
use crate::error::{Error, ErrorCode};
use crate::fmt::Bytes;
use crate::transport::plain_hdr;
use crate::utils::storage::{ParseBuf, WriteBuf};

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
    /// Maximum length of the protocol header
    pub const MAX_LEN: usize =
        // exchange flags
        1
        // protocol opcode
        + 1
        // exchange ID
        + 2
        // protocol ID
        + 2
        // [optional] protocol vendor ID
        + 2
        // [optional] acknowledged message counter
        + 4;

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

    pub fn decrypt_and_decode<C: Crypto>(
        &mut self,
        crypto: C,
        dec_key: Option<crypto::CanonAeadKeyRef<'_>>,
        peer_nodeid: u64,
        plain_hdr: &plain_hdr::PlainHdr,
        parsebuf: &mut ParseBuf<'_>,
    ) -> Result<(), Error> {
        if let Some(key) = dec_key {
            // We decrypt only if the decryption key is valid
            decrypt_in_place(
                crypto,
                key,
                plain_hdr.sec_flags.bits(),
                plain_hdr.ctr,
                peer_nodeid,
                parsebuf,
            )?;
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
        trace!("[rx payload]: {}", Bytes(parsebuf.as_slice()));
        Ok(())
    }

    pub fn encode(&self, resp_buf: &mut WriteBuf<'_>) -> Result<(), Error> {
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

fn get_iv(
    sec_flags: u8,
    recvd_ctr: u32,
    peer_nodeid: u64,
    iv: &mut crypto::AeadNonce,
) -> Result<(), Error> {
    // The IV is the source address (64-bit) followed by the message counter (32-bit)
    let mut write_buf = WriteBuf::new(iv.access_mut());
    // First byte is the Security Flags from the plain header (Matter spec)
    write_buf.le_u8(sec_flags)?;
    write_buf.le_u32(recvd_ctr)?;
    write_buf.le_u64(peer_nodeid)?;
    Ok(())
}

pub fn encrypt_in_place<C: Crypto>(
    crypto: C,
    key: crypto::CanonAeadKeyRef<'_>,
    sec_flags: u8,
    send_ctr: u32,
    peer_nodeid: u64,
    aad: &[u8],
    writebuf: &mut WriteBuf<'_>,
) -> Result<(), Error> {
    // TODO: Get rid of the temporary buffers

    // IV
    let mut iv = crypto::AEAD_NONCE_ZEROED;
    get_iv(sec_flags, send_ctr, peer_nodeid, &mut iv)?;

    // Cipher Text
    let tag_space = crypto::AEAD_TAG_ZEROED;
    writebuf.append(tag_space.access())?;
    let cipher_text = writebuf.as_mut_slice();

    let mut cypher = crypto.aead()?;

    cypher.encrypt_in_place(
        key,
        iv.reference(),
        aad,
        cipher_text,
        cipher_text.len() - crypto::AEAD_TAG_LEN,
    )?;
    //println!("Cipher Text: {:x?}", cipher_text);

    Ok(())
}

fn decrypt_in_place<C: Crypto>(
    crypto: C,
    key: crypto::CanonAeadKeyRef<'_>,
    sec_flags: u8,
    recvd_ctr: u32,
    peer_nodeid: u64,
    parsebuf: &mut ParseBuf<'_>,
) -> Result<(), Error> {
    // AAD: the unencrypted header of this packet (variable length)
    // Copy to a local buffer to avoid borrow conflict with cipher_text
    let aad_slice = parsebuf.parsed_as_slice();
    let aad_len = aad_slice.len();

    // TODO: Temporary buffer
    let mut aad_buf = [0u8; plain_hdr::PlainHdr::MAX_LEN];
    aad_buf[..aad_len].copy_from_slice(aad_slice);
    let aad = &aad_buf[..aad_len];

    // IV:
    //   the specific way for creating IV is in get_iv
    let mut iv = crypto::AEAD_NONCE_ZEROED;
    get_iv(sec_flags, recvd_ctr, peer_nodeid, &mut iv)?;

    let cipher_text = parsebuf.as_mut_slice();
    //println!("AAD: {:x?}", aad);
    //println!("Cipher Text: {:x?}", cipher_text);
    //println!("IV: {:x?}", iv);
    //println!("Key: {:x?}", key);

    let mut cypher = crypto.aead()?;

    cypher.decrypt_in_place(key, iv.reference(), aad, cipher_text)?;
    // println!("Plain Text: {:x?}", cipher_text);
    parsebuf.tail(crypto::AEAD_TAG_LEN)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::crypto::{test_only_crypto, CanonAeadKeyRef};

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

        const KEY: CanonAeadKeyRef = CanonAeadKeyRef::new(&[
            0x66, 0x63, 0x31, 0x97, 0x43, 0x9c, 0x17, 0xb9, 0x7e, 0x10, 0xee, 0x47, 0xc8, 0x8,
            0x80, 0x4a,
        ]);

        // decrypt_in_place() requires that the plain_text buffer of 8 bytes must be already parsed as AAD, we'll just fake it here
        parsebuf.le_u32().unwrap();
        parsebuf.le_u32().unwrap();

        decrypt_in_place(test_only_crypto(), KEY, 0, recvd_ctr, 0, &mut parsebuf).unwrap();
        assert_eq!(
            parsebuf.as_slice(),
            &[
                0x5, 0x8, 0x70, 0x0, 0x1, 0x0, 0x15, 0x28, 0x0, 0x28, 0x1, 0x36, 0x2, 0x15, 0x37,
                0x0, 0x24, 0x0, 0x0, 0x24, 0x1, 0x30, 0x24, 0x2, 0x2, 0x18, 0x35, 0x1, 0x24, 0x0,
                0x0, 0x2c, 0x1, 0x2, 0x57, 0x57, 0x24, 0x2, 0x3, 0x25, 0x3, 0xb8, 0xb, 0x18, 0x18,
                0x18, 0x18
            ]
        );
    }

    #[test]
    pub fn test_decrypt_auth_fail_returns_err() {
        // Same captured frame as `test_decrypt_success`, but with the AEAD tag
        // corrupted so AES-CCM authentication fails. A received frame failing auth
        // is a normal runtime condition (replay / corruption / wrong key), so
        // decrypt must RETURN an error, not panic. Regression test for the mbedtls
        // backend, which previously panicked (`merr_check!`) on this.
        let recvd_ctr = 15287282;
        let mut input_buf: [u8; 71] = [
            0x0, 0x2, 0x0, 0x0, 0xf2, 0x43, 0xe9, 0x0, 0x31, 0xb5, 0x66, 0xec, 0x8b, 0x5b, 0xf4,
            0x17, 0xe4, 0x80, 0xf3, 0xd5, 0x11, 0x59, 0x19, 0xb5, 0x23, 0x91, 0x35, 0x37, 0xb,
            0xf9, 0xbf, 0x69, 0x55, 0x11, 0x75, 0x87, 0x77, 0x19, 0xfc, 0xf3, 0x5d, 0x4b, 0x47,
            0x1f, 0xb0, 0x5e, 0xbe, 0xb5, 0x10, 0xad, 0xc6, 0x78, 0x94, 0x50, 0xe5, 0xd2, 0xe0,
            0x80, 0xef, 0xa8, 0x3a, 0xf0, 0xa6, 0xaf, 0x1b, 0x2, 0x35, 0xa7, 0xd1, 0xc6, 0x32,
        ];
        input_buf[70] ^= 0xff; // corrupt the AEAD tag -> CCM auth must fail

        const KEY: CanonAeadKeyRef = CanonAeadKeyRef::new(&[
            0x66, 0x63, 0x31, 0x97, 0x43, 0x9c, 0x17, 0xb9, 0x7e, 0x10, 0xee, 0x47, 0xc8, 0x8,
            0x80, 0x4a,
        ]);

        let mut parsebuf = ParseBuf::new(&mut input_buf);
        // 8 bytes already parsed as AAD (see `test_decrypt_success`)
        parsebuf.le_u32().unwrap();
        parsebuf.le_u32().unwrap();

        assert!(decrypt_in_place(test_only_crypto(), KEY, 0, recvd_ctr, 0, &mut parsebuf).is_err());
    }

    #[test]
    pub fn test_encrypt_success() {
        // These values are captured from an execution run of the chip-tool binary
        let send_ctr = 41;

        let mut main_buf: [u8; 52] = [0; 52];
        let mut writebuf = WriteBuf::new(&mut main_buf);

        const PLAIN_HDR: &[u8] = &[0x0, 0x11, 0x0, 0x0, 0x29, 0x0, 0x0, 0x0];

        const PLAIN_TEXT: &[u8] = &[
            5, 8, 0x58, 0x28, 0x01, 0x00, 0x15, 0x36, 0x00, 0x15, 0x37, 0x00, 0x24, 0x00, 0x01,
            0x24, 0x02, 0x06, 0x24, 0x03, 0x01, 0x18, 0x35, 0x01, 0x18, 0x18, 0x18, 0x18,
        ];
        writebuf.append(PLAIN_TEXT).unwrap();

        const KEY: CanonAeadKeyRef = CanonAeadKeyRef::new(&[
            0x44, 0xd4, 0x3c, 0x91, 0xd2, 0x27, 0xf3, 0xba, 0x08, 0x24, 0xc5, 0xd8, 0x7c, 0xb8,
            0x1b, 0x33,
        ]);

        encrypt_in_place(
            test_only_crypto(),
            KEY,
            0,
            send_ctr,
            0,
            PLAIN_HDR,
            &mut writebuf,
        )
        .unwrap();
        assert_eq!(
            writebuf.as_slice(),
            &[
                189, 83, 250, 121, 38, 87, 97, 17, 153, 78, 243, 20, 36, 11, 131, 142, 136, 165,
                227, 107, 204, 129, 193, 153, 42, 131, 138, 254, 22, 190, 76, 244, 116, 45, 156,
                215, 229, 130, 215, 147, 73, 21, 88, 216
            ]
        );
    }

    /// Fixed part of the proto header: exchange flags, opcode, exchange ID,
    /// protocol ID.
    const FIXED_LEN: usize = 1 + 1 + 2 + 2;

    fn encode(hdr: &ProtoHdr) -> ([u8; ProtoHdr::MAX_LEN], usize) {
        let mut buf = [0; ProtoHdr::MAX_LEN];
        let mut wb = WriteBuf::new(&mut buf);
        unwrap!(hdr.encode(&mut wb));
        let len = wb.as_slice().len();
        (buf, len)
    }

    /// Decode without decryption.
    fn decode(bytes: &mut [u8]) -> Result<(ProtoHdr, usize), Error> {
        let mut pb = ParseBuf::new(bytes);
        let mut hdr = ProtoHdr::new();
        hdr.decrypt_and_decode(
            test_only_crypto(),
            None,
            0,
            &plain_hdr::PlainHdr::new(),
            &mut pb,
        )?;
        Ok((hdr, pb.as_slice().len()))
    }

    fn round_trip(hdr: &ProtoHdr, expected_len: usize) -> ProtoHdr {
        let (mut buf, len) = encode(hdr);
        assert_eq!(len, expected_len);

        let (decoded, left) = unwrap!(decode(&mut buf[..len]));
        assert_eq!(left, 0);

        assert_eq!(decoded.exch_flags, hdr.exch_flags);
        assert_eq!(decoded.exch_id, hdr.exch_id);
        assert_eq!(decoded.proto_id, hdr.proto_id);
        assert_eq!(decoded.proto_opcode, hdr.proto_opcode);
        assert_eq!(decoded.get_vendor(), hdr.get_vendor());
        assert_eq!(decoded.get_ack(), hdr.get_ack());

        decoded
    }

    /// A fresh header is "not decoded" until real protocol / opcode values
    /// land in it.
    #[test]
    fn new_header_is_not_decoded() {
        let hdr = ProtoHdr::new();
        assert!(!hdr.is_decoded());
        assert!(!hdr.is_initiator());
        assert!(!hdr.is_reliable());
        assert!(!hdr.is_security_ext());
        assert!(hdr.get_ack().is_none());
        assert!(hdr.get_vendor().is_none());

        let mut bytes = [0x00, 0x20, 0x01, 0x00, 0x00, 0x00];
        let (decoded, _) = unwrap!(decode(&mut bytes));
        assert!(decoded.is_decoded());
    }

    /// The minimal header is the fixed part, laid out little-endian.
    #[test]
    fn minimal_header_round_trip() {
        let mut hdr = ProtoHdr::new();
        hdr.exch_id = 0x1234;
        hdr.proto_id = 0x0001;
        hdr.proto_opcode = 0x08;

        round_trip(&hdr, FIXED_LEN);

        let (buf, len) = encode(&hdr);
        assert_eq!(&buf[..len], &[0x00, 0x08, 0x34, 0x12, 0x01, 0x00]);
    }

    /// All five exchange flags round-trip, with the vendor ID and ACK counter
    /// appended in that order; the result is exactly `MAX_LEN`.
    #[test]
    fn all_flags_round_trip() {
        let mut hdr = ProtoHdr::new();
        hdr.exch_id = 1;
        hdr.proto_id = 2;
        hdr.proto_opcode = 3;
        hdr.set_initiator();
        hdr.set_reliable();
        hdr.set_ack(Some(0xdead_beef));
        hdr.set_vendor(Some(0xfff1));
        hdr.exch_flags |= ExchFlags::SECEX;

        let decoded = round_trip(&hdr, ProtoHdr::MAX_LEN);
        assert!(decoded.is_initiator());
        assert!(decoded.is_reliable());
        assert!(decoded.is_security_ext());
        assert_eq!(decoded.get_ack(), Some(0xdead_beef));
        assert_eq!(decoded.get_vendor(), Some(0xfff1));

        let (buf, len) = encode(&hdr);
        assert_eq!(buf[0], ExchFlags::all().bits());
        assert_eq!(&buf[6..8], &[0xf1, 0xff]);
        assert_eq!(&buf[8..len], &[0xef, 0xbe, 0xad, 0xde]);
    }

    /// The vendor ID and ACK counter are each present exactly when their flag
    /// is set, and clearing the flag also forgets the value.
    #[test]
    fn optional_fields_follow_their_flags() {
        let mut hdr = ProtoHdr::new();
        hdr.proto_id = 1;
        hdr.proto_opcode = 1;

        hdr.set_vendor(Some(0x1234));
        assert!(hdr.exch_flags.contains(ExchFlags::VENDOR));
        round_trip(&hdr, FIXED_LEN + 2);

        hdr.set_vendor(None);
        assert!(!hdr.exch_flags.contains(ExchFlags::VENDOR));
        assert_eq!(hdr.proto_vendor_id, 0);
        round_trip(&hdr, FIXED_LEN);

        hdr.set_ack(Some(42));
        assert!(hdr.exch_flags.contains(ExchFlags::ACK));
        round_trip(&hdr, FIXED_LEN + 4);

        hdr.set_ack(None);
        assert!(!hdr.exch_flags.contains(ExchFlags::ACK));
        assert_eq!(hdr.ack_msg_ctr, 0);
        round_trip(&hdr, FIXED_LEN);

        // A raw A flag without the counter bytes is a truncated packet.
        let (mut buf, len) = encode(&hdr);
        buf[0] |= ExchFlags::ACK.bits();
        assert_eq!(
            unwrap!(decode(&mut buf[..len]).err()).code(),
            ErrorCode::TruncatedPacket
        );
    }

    /// Unknown exchange flag bits are rejected; a short header is truncated.
    #[test]
    fn decode_rejects_unknown_bits_and_truncation() {
        let mut hdr = ProtoHdr::new();
        hdr.proto_id = 1;
        hdr.proto_opcode = 1;
        hdr.set_vendor(Some(1));
        hdr.set_ack(Some(1));
        let (buf, len) = encode(&hdr);

        for bit in [0x20, 0x40, 0x80] {
            let mut bytes = buf;
            bytes[0] = bit;
            assert_eq!(
                unwrap!(decode(&mut bytes[..len]).err()).code(),
                ErrorCode::Invalid,
                "flag {bit:#x}"
            );
        }

        for cut in 0..len {
            let mut bytes = buf;
            assert_eq!(
                unwrap!(decode(&mut bytes[..cut]).err()).code(),
                ErrorCode::TruncatedPacket,
                "cut at {cut}"
            );
        }
    }

    /// The initiator flag toggles and the opcode helpers map to the given
    /// protocol's opcode enum.
    #[test]
    fn initiator_toggle_and_opcode_checks() {
        use crate::sc::OpCode;

        let mut hdr = ProtoHdr::new();
        hdr.toggle_initiator();
        assert!(hdr.is_initiator());
        hdr.toggle_initiator();
        assert!(!hdr.is_initiator());

        hdr.proto_opcode = OpCode::PBKDFParamRequest as u8;
        assert_eq!(unwrap!(hdr.opcode::<OpCode>()), OpCode::PBKDFParamRequest);
        unwrap!(hdr.check_opcode(OpCode::PBKDFParamRequest));
        assert_eq!(
            unwrap!(hdr.check_opcode(OpCode::CASESigma1).err()).code(),
            ErrorCode::Invalid
        );

        hdr.proto_opcode = 0xff;
        assert_eq!(
            unwrap!(hdr.opcode::<OpCode>().err()).code(),
            ErrorCode::Invalid
        );
    }

    /// Over a reliable transport the R and A flags are stripped (both ways);
    /// over UDP they are left alone.
    #[test]
    fn adjust_reliability_strips_mrp_flags_on_reliable_transports() {
        use core::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

        use crate::transport::network::BtAddr;

        let sock = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5540, 0, 0));

        let armed = || {
            let mut hdr = ProtoHdr::new();
            hdr.set_reliable();
            hdr.set_ack(Some(5));
            hdr
        };

        for rx in [false, true] {
            let mut hdr = armed();
            hdr.adjust_reliability(rx, &Address::Udp(sock));
            assert!(hdr.is_reliable());
            assert_eq!(hdr.get_ack(), Some(5));

            for addr in [Address::Tcp(sock), Address::Btp(BtAddr([0; 6]))] {
                let mut hdr = armed();
                hdr.adjust_reliability(rx, &addr);
                assert!(!hdr.is_reliable());
                assert!(hdr.get_ack().is_none());
            }
        }
    }
}
