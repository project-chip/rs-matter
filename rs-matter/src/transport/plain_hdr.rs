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

use crate::error::*;
use crate::utils::storage::{ParseBuf, WriteBuf};

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct MsgFlags: u8 {
        const DSIZ_UNICAST_NODEID = 0x01;
        const DSIZ_GROUPCAST_NODEID = 0x02;
        const SRC_ADDR_PRESENT = 0x04;
    }

    #[repr(transparent)]
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct SecFlags: u8 {
        /// Session Type is a Group Session (Session Type = 1).
        const GROUP_SESSION = 0x01;
        /// Message Extensions present.
        const MSG_EXT = 0x20;
        /// Control message. Messages with this bit use the peer's control
        /// message counter (not the data counter) for AEAD-nonce framing.
        const CONTROL_MSG = 0x40;
        /// Privacy-encoded message. Not currently produced or accepted by
        /// this crate; the bit is declared so an incoming value survives
        /// a round-trip through the bitflag rather than triggering
        /// `from_bits`-fails.
        const PRIVACY = 0x80;
    }
}

const DSIZ_MASK: MsgFlags = MsgFlags::DSIZ_UNICAST_NODEID.union(MsgFlags::DSIZ_GROUPCAST_NODEID);

impl fmt::Display for MsgFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = false;
        for flag in [
            Self::SRC_ADDR_PRESENT,
            Self::DSIZ_UNICAST_NODEID,
            Self::DSIZ_GROUPCAST_NODEID,
        ] {
            if self.contains(flag) {
                if sep {
                    write!(f, "|")?;
                }

                let str = match flag {
                    Self::DSIZ_UNICAST_NODEID => "U",
                    Self::DSIZ_GROUPCAST_NODEID => "G",
                    Self::SRC_ADDR_PRESENT => "S",
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
impl defmt::Format for MsgFlags {
    fn format(&self, f: defmt::Formatter<'_>) {
        let mut sep = false;
        for flag in [
            Self::SRC_ADDR_PRESENT,
            Self::DSIZ_UNICAST_NODEID,
            Self::DSIZ_GROUPCAST_NODEID,
        ] {
            if self.contains(flag) {
                if sep {
                    defmt::write!(f, "|");
                }

                let str = match flag {
                    Self::DSIZ_UNICAST_NODEID => "U",
                    Self::DSIZ_GROUPCAST_NODEID => "G",
                    Self::SRC_ADDR_PRESENT => "S",
                    _ => "?",
                };

                defmt::write!(f, "{}", str);
                sep = true;
            }
        }
    }
}

// This is the unencrypted message
#[derive(Debug, Default, Clone)]
pub struct PlainHdr {
    flags: MsgFlags,
    pub sess_id: u16,
    pub(crate) sec_flags: SecFlags,
    pub ctr: u32,
    src_nodeid: u64,
    dst_nodeid: u64,
}

impl PlainHdr {
    pub const MAX_LEN: usize =
        // [optional] msg len only for TCP
        2
        // flags
        + 1
        // security flags
        + 1
        // session ID
        + 2
        // message ctr
        + 4
        // [optional] source node ID
        + 8
        // [optional] destination node ID
        + 8;

    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            flags: MsgFlags::empty(),
            sess_id: 0,
            sec_flags: SecFlags::empty(),
            ctr: 0,
            src_nodeid: 0,
            dst_nodeid: 0,
        }
    }

    pub fn get_src_nodeid(&self) -> Option<u64> {
        if self.flags.contains(MsgFlags::SRC_ADDR_PRESENT) {
            Some(self.src_nodeid)
        } else {
            None
        }
    }

    pub fn set_src_nodeid(&mut self, id: Option<u64>) {
        if let Some(id) = id {
            self.flags |= MsgFlags::SRC_ADDR_PRESENT;
            self.src_nodeid = id;
        } else {
            self.flags.remove(MsgFlags::SRC_ADDR_PRESENT);
            self.src_nodeid = 0;
        }
    }

    pub fn get_dst_unicast_nodeid(&self) -> Option<u64> {
        if self.flags.intersection(DSIZ_MASK) == MsgFlags::DSIZ_UNICAST_NODEID {
            Some(self.dst_nodeid)
        } else {
            None
        }
    }

    pub fn set_dst_unicast_nodeid(&mut self, id: Option<u64>) {
        if let Some(id) = id {
            self.flags |= MsgFlags::DSIZ_UNICAST_NODEID;
            self.flags.remove(MsgFlags::DSIZ_GROUPCAST_NODEID);
            self.dst_nodeid = id;
        } else {
            self.flags.remove(DSIZ_MASK);
            self.dst_nodeid = 0;
        }
    }

    pub fn get_dst_groupcast_nodeid(&self) -> Option<u16> {
        if self.flags.intersection(DSIZ_MASK) == MsgFlags::DSIZ_GROUPCAST_NODEID {
            Some(self.dst_nodeid as u16)
        } else {
            None
        }
    }

    pub fn set_dst_groupcast_nodeid(&mut self, id: Option<u16>) {
        if let Some(id) = id {
            self.flags |= MsgFlags::DSIZ_GROUPCAST_NODEID;
            self.flags.remove(MsgFlags::DSIZ_UNICAST_NODEID);
            self.dst_nodeid = id as u64;
        } else {
            self.flags.remove(DSIZ_MASK);
            self.dst_nodeid = 0;
        }
    }

    // it will have an additional 'message length' field first
    pub fn decode(&mut self, msg: &mut ParseBuf) -> Result<(), Error> {
        self.flags = MsgFlags::from_bits(msg.le_u8()?).ok_or(ErrorCode::Invalid)?;
        self.sess_id = msg.le_u16()?;
        self.sec_flags = SecFlags::from_bits(msg.le_u8()?).ok_or(ErrorCode::Invalid)?;
        self.ctr = msg.le_u32()?;

        if self.flags.contains(MsgFlags::SRC_ADDR_PRESENT) {
            self.src_nodeid = msg.le_u64()?;
        }

        if !self.flags.contains(DSIZ_MASK) {
            if self.flags.contains(MsgFlags::DSIZ_UNICAST_NODEID) {
                self.dst_nodeid = msg.le_u64()?;
            } else if self.flags.contains(MsgFlags::DSIZ_GROUPCAST_NODEID) {
                self.dst_nodeid = msg.le_u16()? as u64;
            }
        }

        trace!("[decode] {}", self);
        Ok(())
    }

    pub fn encode(&self, resp_buf: &mut WriteBuf) -> Result<(), Error> {
        trace!("[encode] {}", self);
        resp_buf.le_u8(self.flags.bits())?;
        resp_buf.le_u16(self.sess_id)?;
        resp_buf.le_u8(self.sec_flags.bits())?;
        resp_buf.le_u32(self.ctr)?;

        if self.flags.contains(MsgFlags::SRC_ADDR_PRESENT) {
            resp_buf.le_u64(self.src_nodeid)?;
        }

        if !self.flags.contains(DSIZ_MASK) {
            if self.flags.contains(MsgFlags::DSIZ_UNICAST_NODEID) {
                resp_buf.le_u64(self.dst_nodeid)?;
            } else if self.flags.contains(MsgFlags::DSIZ_GROUPCAST_NODEID) {
                resp_buf.le_u16(self.dst_nodeid as u16)?;
            }
        }

        Ok(())
    }

    pub fn is_group_session(&self) -> bool {
        self.sec_flags.contains(SecFlags::GROUP_SESSION)
    }

    /// Set or clear the Group Session bit on the outgoing message.
    pub fn set_group_session(&mut self, group: bool) {
        if group {
            self.sec_flags |= SecFlags::GROUP_SESSION;
        } else {
            self.sec_flags.remove(SecFlags::GROUP_SESSION);
        }
    }

    /// Whether the message is a control message (Security Flags `C` bit).
    pub fn is_control_msg(&self) -> bool {
        self.sec_flags.contains(SecFlags::CONTROL_MSG)
    }

    /// Set or clear the control message (`C`) bit on the outgoing message.
    pub fn set_control_msg(&mut self, control: bool) {
        if control {
            self.sec_flags |= SecFlags::CONTROL_MSG;
        } else {
            self.sec_flags.remove(SecFlags::CONTROL_MSG);
        }
    }

    /// Whether the message declares itself privacy-encoded (Security Flags
    /// `P` bit). This crate does not yet produce or accept such messages;
    /// callers may use this to log or reject them explicitly.
    pub fn is_privacy(&self) -> bool {
        self.sec_flags.contains(SecFlags::PRIVACY)
    }

    pub fn is_encrypted(&self) -> bool {
        self.sess_id != 0 || self.is_group_session()
    }
}

impl fmt::Display for PlainHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.flags.is_empty() {
            write!(f, "{},", self.flags)?;
        }

        write!(f, "SID:{:x},CTR:{:x}", self.sess_id, self.ctr)?;

        if self.is_control_msg() {
            write!(f, ",C")?;
        }
        if self.is_privacy() {
            write!(f, ",P")?;
        }

        if let Some(src_nodeid) = self.get_src_nodeid() {
            write!(f, ",SRC:{:x}", src_nodeid)?;
        }

        if let Some(dst_nodeid) = self.get_dst_unicast_nodeid() {
            write!(f, ",DST:{:x}", dst_nodeid)?;
        }

        if let Some(dst_group_nodeid) = self.get_dst_groupcast_nodeid() {
            write!(f, ",GRP:{:x}", dst_group_nodeid)?;
        }

        Ok(())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PlainHdr {
    fn format(&self, f: defmt::Formatter<'_>) {
        if !self.flags.is_empty() {
            defmt::write!(f, "{},", self.flags);
        }

        defmt::write!(f, "SID:{:x},CTR:{:x}", self.sess_id, self.ctr);

        if self.is_control_msg() {
            defmt::write!(f, ",C");
        }
        if self.is_privacy() {
            defmt::write!(f, ",P");
        }

        if let Some(src_nodeid) = self.get_src_nodeid() {
            defmt::write!(f, ",SRC:{:x}", src_nodeid);
        }

        if let Some(dst_nodeid) = self.get_dst_unicast_nodeid() {
            defmt::write!(f, ",DST:{:x}", dst_nodeid);
        }

        if let Some(dst_group_nodeid) = self.get_dst_groupcast_nodeid() {
            defmt::write!(f, ",GRP:{:x}", dst_group_nodeid);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Fixed part of the plain header: flags, session ID, security flags,
    /// message counter.
    const FIXED_LEN: usize = 1 + 2 + 1 + 4;

    fn encode(hdr: &PlainHdr) -> ([u8; PlainHdr::MAX_LEN], usize) {
        let mut buf = [0; PlainHdr::MAX_LEN];
        let mut wb = WriteBuf::new(&mut buf);
        unwrap!(hdr.encode(&mut wb));
        let len = wb.as_slice().len();
        (buf, len)
    }

    fn decode(bytes: &mut [u8]) -> Result<(PlainHdr, usize), Error> {
        let mut pb = ParseBuf::new(bytes);
        let mut hdr = PlainHdr::new();
        hdr.decode(&mut pb)?;
        Ok((hdr, pb.as_slice().len()))
    }

    /// Encode, then decode, and check the decoded header reads back the same
    /// and the encoding had the expected length.
    fn round_trip(hdr: &PlainHdr, expected_len: usize) -> PlainHdr {
        let (mut buf, len) = encode(hdr);
        assert_eq!(len, expected_len);

        let (decoded, left) = unwrap!(decode(&mut buf[..len]));
        assert_eq!(left, 0);

        assert_eq!(decoded.flags, hdr.flags);
        assert_eq!(decoded.sec_flags, hdr.sec_flags);
        assert_eq!(decoded.sess_id, hdr.sess_id);
        assert_eq!(decoded.ctr, hdr.ctr);
        assert_eq!(decoded.get_src_nodeid(), hdr.get_src_nodeid());
        assert_eq!(
            decoded.get_dst_unicast_nodeid(),
            hdr.get_dst_unicast_nodeid()
        );
        assert_eq!(
            decoded.get_dst_groupcast_nodeid(),
            hdr.get_dst_groupcast_nodeid()
        );

        decoded
    }

    /// The minimal header carries neither node ID and is exactly the fixed
    /// part, laid out little-endian.
    #[test]
    fn minimal_header_round_trip() {
        let mut hdr = PlainHdr::new();
        hdr.sess_id = 0x1234;
        hdr.ctr = 0xdead_beef;

        let decoded = round_trip(&hdr, FIXED_LEN);
        assert!(decoded.get_src_nodeid().is_none());
        assert!(decoded.get_dst_unicast_nodeid().is_none());
        assert!(decoded.get_dst_groupcast_nodeid().is_none());

        let (buf, len) = encode(&hdr);
        assert_eq!(
            &buf[..len],
            &[0x00, 0x34, 0x12, 0x00, 0xef, 0xbe, 0xad, 0xde]
        );
    }

    /// Every combination of the optional address fields round-trips with the
    /// matching length.
    #[test]
    fn address_fields_round_trip() {
        let mut hdr = PlainHdr::new();
        hdr.set_src_nodeid(Some(0x0102_0304_0506_0708));
        round_trip(&hdr, FIXED_LEN + 8);

        hdr.set_dst_unicast_nodeid(Some(0x1112_1314_1516_1718));
        round_trip(&hdr, FIXED_LEN + 8 + 8);

        hdr.set_src_nodeid(None);
        round_trip(&hdr, FIXED_LEN + 8);

        hdr.set_dst_groupcast_nodeid(Some(0xabcd));
        round_trip(&hdr, FIXED_LEN + 2);

        hdr.set_src_nodeid(Some(1));
        round_trip(&hdr, FIXED_LEN + 8 + 2);

        hdr.set_dst_groupcast_nodeid(None);
        hdr.set_src_nodeid(None);
        round_trip(&hdr, FIXED_LEN);
    }

    /// Unicast and groupcast destinations are mutually exclusive: setting one
    /// replaces the other, and clearing either clears both.
    #[test]
    fn destination_kinds_are_exclusive() {
        let mut hdr = PlainHdr::new();

        hdr.set_dst_unicast_nodeid(Some(7));
        assert_eq!(hdr.get_dst_unicast_nodeid(), Some(7));
        assert!(hdr.get_dst_groupcast_nodeid().is_none());

        hdr.set_dst_groupcast_nodeid(Some(9));
        assert!(hdr.get_dst_unicast_nodeid().is_none());
        assert_eq!(hdr.get_dst_groupcast_nodeid(), Some(9));
        assert_eq!(hdr.flags & DSIZ_MASK, MsgFlags::DSIZ_GROUPCAST_NODEID);

        hdr.set_dst_unicast_nodeid(Some(7));
        assert_eq!(hdr.flags & DSIZ_MASK, MsgFlags::DSIZ_UNICAST_NODEID);

        hdr.set_dst_groupcast_nodeid(None);
        assert!(hdr.get_dst_unicast_nodeid().is_none());
        assert!(hdr.get_dst_groupcast_nodeid().is_none());
        assert!(hdr.flags.is_empty());
    }

    /// The security flags round-trip and drive the session-type predicates;
    /// a message is encrypted when it has a session ID or is a group message.
    #[test]
    fn security_flags_round_trip() {
        let mut hdr = PlainHdr::new();
        assert!(!hdr.is_encrypted());
        assert!(!hdr.is_group_session());
        assert!(!hdr.is_control_msg());
        assert!(!hdr.is_privacy());

        hdr.set_group_session(true);
        hdr.set_control_msg(true);
        let decoded = round_trip(&hdr, FIXED_LEN);
        assert!(decoded.is_group_session());
        assert!(decoded.is_control_msg());
        assert!(decoded.is_encrypted());

        // The privacy bit has no setter but survives decoding.
        let (mut buf, len) = encode(&hdr);
        buf[3] |= SecFlags::PRIVACY.bits();
        let (decoded, _) = unwrap!(decode(&mut buf[..len]));
        assert!(decoded.is_privacy());
        assert!(decoded.is_group_session());

        hdr.set_group_session(false);
        hdr.set_control_msg(false);
        assert!(hdr.sec_flags.is_empty());
        assert!(!hdr.is_encrypted());

        hdr.sess_id = 1;
        assert!(hdr.is_encrypted());
    }

    /// Unknown message flag bits (including a non-zero version nibble) and
    /// unknown security flag bits are rejected.
    #[test]
    fn decode_rejects_unknown_flag_bits() {
        let (buf, len) = encode(&PlainHdr::new());

        for bit in [0x08, 0x10, 0x80] {
            let mut bytes = buf;
            bytes[0] = bit;
            assert_eq!(
                unwrap!(decode(&mut bytes[..len]).err()).code(),
                ErrorCode::Invalid,
                "message flag {bit:#x}"
            );
        }

        for bit in [0x02, 0x04, 0x08, 0x10] {
            let mut bytes = buf;
            bytes[3] = bit;
            assert_eq!(
                unwrap!(decode(&mut bytes[..len]).err()).code(),
                ErrorCode::Invalid,
                "security flag {bit:#x}"
            );
        }
    }

    /// A header cut short anywhere - in the fixed part or in an optional node
    /// ID - is a truncated packet.
    #[test]
    fn decode_rejects_truncated_input() {
        let mut hdr = PlainHdr::new();
        hdr.set_src_nodeid(Some(1));
        hdr.set_dst_unicast_nodeid(Some(2));
        let (buf, len) = encode(&hdr);

        for cut in 0..len {
            let mut bytes = buf;
            assert_eq!(
                unwrap!(decode(&mut bytes[..cut]).err()).code(),
                ErrorCode::TruncatedPacket,
                "cut at {cut}"
            );
        }

        let mut bytes = buf;
        assert!(decode(&mut bytes[..len]).is_ok());
    }

    /// Both DSIZ bits set is a reserved combination: it decodes, but carries
    /// no destination and consumes no destination bytes.
    #[test]
    fn decode_both_dsiz_bits_carries_no_destination() {
        let mut bytes = [0x03, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb];

        let (decoded, left) = unwrap!(decode(&mut bytes));
        assert_eq!(decoded.flags, DSIZ_MASK);
        assert!(decoded.get_dst_unicast_nodeid().is_none());
        assert!(decoded.get_dst_groupcast_nodeid().is_none());
        assert_eq!(left, 2);

        // And it encodes back to the same fixed-length form.
        let (_, len) = encode(&decoded);
        assert_eq!(len, FIXED_LEN);
    }

    /// The maximum encoded length stays within `MAX_LEN`, which also leaves
    /// room for the TCP length prefix.
    #[test]
    fn max_len_covers_the_longest_encoding() {
        let mut hdr = PlainHdr::new();
        hdr.set_src_nodeid(Some(u64::MAX));
        hdr.set_dst_unicast_nodeid(Some(u64::MAX));
        hdr.sec_flags = SecFlags::all();

        let (_, len) = encode(&hdr);
        assert_eq!(len, PlainHdr::MAX_LEN - 2);
    }
}
