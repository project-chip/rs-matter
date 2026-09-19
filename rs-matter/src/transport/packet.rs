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

use crate::crypto::{self, Crypto};
use crate::error::Error;
use crate::fmt::Bytes;
use crate::utils::storage::{ParseBuf, WriteBuf};

use super::plain_hdr::PlainHdr;
use super::proto_hdr::{self, ProtoHdr};

#[derive(Debug, Default, Clone)]
pub struct PacketHdr {
    pub plain: PlainHdr,
    pub proto: ProtoHdr,
}

impl PacketHdr {
    pub const HDR_RESERVE: usize = PlainHdr::MAX_LEN + ProtoHdr::MAX_LEN;
    pub const TAIL_RESERVE: usize = crypto::AEAD_TAG_LEN;

    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            plain: PlainHdr::new(),
            proto: ProtoHdr::new(),
        }
    }

    pub fn reset(&mut self) {
        self.plain = Default::default();
        self.proto = Default::default();
        self.proto.set_reliable();
    }

    pub fn load(&mut self, packet: &PacketHdr) {
        self.plain = packet.plain.clone();
        self.proto = packet.proto.clone();
    }

    pub fn decode_plain_hdr(&mut self, pb: &mut ParseBuf) -> Result<(), Error> {
        self.plain.decode(pb)
    }

    pub fn decode_remaining<C: Crypto>(
        &mut self,
        crypto: C,
        dec_key: Option<crypto::CanonAeadKeyRef<'_>>,
        peer_nodeid: u64,
        pb: &mut ParseBuf,
    ) -> Result<(), Error> {
        self.proto
            .decrypt_and_decode(crypto, dec_key, peer_nodeid, &self.plain, pb)
    }

    pub fn encode<C: Crypto>(
        &self,
        crypto: C,
        enc_key: Option<crypto::CanonAeadKeyRef<'_>>,
        local_nodeid: u64,
        wb: &mut WriteBuf,
    ) -> Result<(), Error> {
        // TODO: Get rid of the temporary buffers

        let mut tmp_buf = [0_u8; ProtoHdr::MAX_LEN];
        let mut write_buf = WriteBuf::new(&mut tmp_buf);
        self.proto.encode(&mut write_buf)?;
        wb.prepend(write_buf.as_slice())?;

        let mut tmp_buf = [0_u8; PlainHdr::MAX_LEN];
        let mut write_buf = WriteBuf::new(&mut tmp_buf);
        self.plain.encode(&mut write_buf)?;
        let plain_hdr_bytes = write_buf.as_slice();

        trace!("Unencrypted packet: {}", Bytes(wb.as_slice()));
        let ctr = self.plain.ctr;
        if let Some(enc_key) = enc_key {
            proto_hdr::encrypt_in_place(
                crypto,
                enc_key,
                self.plain.sec_flags.bits(),
                ctr,
                local_nodeid,
                plain_hdr_bytes,
                wb,
            )?;
        }

        wb.prepend(plain_hdr_bytes)?;
        trace!("Full encrypted packet: {}", Bytes(wb.as_slice()));

        Ok(())
    }
}

impl fmt::Display for PacketHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}][{}]", self.plain, self.proto)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PacketHdr {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "[{}][{}]", self.plain, self.proto)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{test_only_crypto, CanonAeadKeyRef};
    use crate::error::ErrorCode;
    use crate::im::PROTO_ID_INTERACTION_MODEL;

    use super::*;

    const KEY: CanonAeadKeyRef = CanonAeadKeyRef::new(&[7; 16]);
    const PAYLOAD: &[u8] = b"hello";
    const NODE_ID: u64 = 0x0102_0304_0506_0708;

    /// A packet header with both node IDs and a typical IM proto header.
    fn header() -> PacketHdr {
        let mut hdr = PacketHdr::new();
        hdr.plain.sess_id = 0x1234;
        hdr.plain.ctr = 99;
        hdr.plain.set_src_nodeid(Some(NODE_ID));
        hdr.plain.set_dst_unicast_nodeid(Some(0x99));
        hdr.proto.exch_id = 7;
        hdr.proto.proto_id = PROTO_ID_INTERACTION_MODEL;
        hdr.proto.proto_opcode = 2;
        hdr.proto.set_initiator();
        hdr.proto.set_reliable();
        hdr.proto.set_ack(Some(98));
        hdr
    }

    /// Encode `header()` around `PAYLOAD` into `buf`, returning the packet range.
    fn encode_into(
        buf: &mut [u8],
        enc_key: Option<CanonAeadKeyRef<'_>>,
    ) -> Result<(usize, usize), Error> {
        let mut wb = WriteBuf::new_with(buf, PacketHdr::HDR_RESERVE, PacketHdr::HDR_RESERVE);
        wb.append(PAYLOAD)?;
        header().encode(test_only_crypto(), enc_key, NODE_ID, &mut wb)?;
        Ok((wb.get_start(), wb.get_tail()))
    }

    /// Decode a packet, returning the header and the payload range.
    fn decode(
        bytes: &mut [u8],
        dec_key: Option<CanonAeadKeyRef<'_>>,
        peer_nodeid: u64,
    ) -> Result<(PacketHdr, (usize, usize)), Error> {
        let mut pb = ParseBuf::new(bytes);
        let mut hdr = PacketHdr::new();
        hdr.decode_plain_hdr(&mut pb)?;
        hdr.decode_remaining(test_only_crypto(), dec_key, peer_nodeid, &mut pb)?;
        Ok((hdr, pb.slice_range()))
    }

    fn assert_header_matches(decoded: &PacketHdr) {
        let expected = header();
        assert_eq!(decoded.plain.sess_id, expected.plain.sess_id);
        assert_eq!(decoded.plain.ctr, expected.plain.ctr);
        assert_eq!(
            decoded.plain.get_src_nodeid(),
            expected.plain.get_src_nodeid()
        );
        assert_eq!(
            decoded.plain.get_dst_unicast_nodeid(),
            expected.plain.get_dst_unicast_nodeid()
        );
        assert_eq!(decoded.proto.exch_id, expected.proto.exch_id);
        assert_eq!(decoded.proto.proto_id, expected.proto.proto_id);
        assert_eq!(decoded.proto.proto_opcode, expected.proto.proto_opcode);
        assert!(decoded.proto.is_initiator());
        assert!(decoded.proto.is_reliable());
        assert_eq!(decoded.proto.get_ack(), Some(98));
    }

    /// The header reserve is the sum of the two maximum header lengths, and the
    /// longest possible headers fit inside it.
    #[test]
    fn hdr_reserve_covers_the_longest_headers() {
        assert_eq!(
            PacketHdr::HDR_RESERVE,
            PlainHdr::MAX_LEN + ProtoHdr::MAX_LEN
        );
        assert_eq!(PacketHdr::TAIL_RESERVE, crypto::AEAD_TAG_LEN);

        let mut hdr = header();
        hdr.proto.set_vendor(Some(0xfff1));

        let mut buf = [0; PacketHdr::HDR_RESERVE];
        let mut wb = WriteBuf::new_with(&mut buf, PacketHdr::HDR_RESERVE, PacketHdr::HDR_RESERVE);
        unwrap!(hdr.encode(test_only_crypto(), None, NODE_ID, &mut wb));
        assert!(wb.get_start() >= 2);
    }

    /// Without a key, encoding prepends the proto and plain headers in front
    /// of the payload and decoding hands the same headers and payload back.
    #[test]
    fn plaintext_packet_round_trip() {
        let mut buf = [0; PacketHdr::HDR_RESERVE + PAYLOAD.len()];
        let (start, end) = unwrap!(encode_into(&mut buf, None));

        // plain: 8 fixed + 8 src + 8 dst; proto: 6 fixed + 4 ack
        assert_eq!(end - start, 24 + 10 + PAYLOAD.len());
        assert_eq!(&buf[end - PAYLOAD.len()..end], PAYLOAD);

        let (decoded, (pstart, pend)) = unwrap!(decode(&mut buf[start..end], None, 0));
        assert_header_matches(&decoded);
        assert_eq!(&buf[start + pstart..start + pend], PAYLOAD);
    }

    /// With a key, the proto header and payload are encrypted under the plain
    /// header as AAD and the sender's node ID in the nonce: the right key and
    /// node ID recover them, anything else is rejected.
    #[test]
    fn encrypted_packet_round_trip() {
        let mut buf = [0; PacketHdr::HDR_RESERVE + PAYLOAD.len() + PacketHdr::TAIL_RESERVE];
        let (start, end) = unwrap!(encode_into(&mut buf, Some(KEY)));

        assert_eq!(end - start, 24 + 10 + PAYLOAD.len() + crypto::AEAD_TAG_LEN);
        assert!(!buf[start..end]
            .windows(PAYLOAD.len())
            .any(|window| window == PAYLOAD));

        let packet = buf;
        let mut bytes = packet;
        let (decoded, (pstart, pend)) = unwrap!(decode(&mut bytes[start..end], Some(KEY), NODE_ID));
        assert_header_matches(&decoded);
        assert_eq!(&bytes[start + pstart..start + pend], PAYLOAD);

        let mut bytes = packet;
        assert!(decode(&mut bytes[start..end], Some(KEY), NODE_ID + 1).is_err());

        const OTHER_KEY: CanonAeadKeyRef = CanonAeadKeyRef::new(&[8; 16]);
        let mut bytes = packet;
        assert!(decode(&mut bytes[start..end], Some(OTHER_KEY), NODE_ID).is_err());

        // A flipped bit in the AAD (plain header), ciphertext or tag fails auth.
        for index in [start + 4, start + 24, end - 1] {
            let mut bytes = packet;
            bytes[index] ^= 0x01;
            assert!(
                decode(&mut bytes[start..end], Some(KEY), NODE_ID).is_err(),
                "flipped byte {index}"
            );
        }
    }

    /// Encoding needs the header room in front of the payload.
    #[test]
    fn encode_fails_without_header_room() {
        let mut buf = [0; PacketHdr::HDR_RESERVE + PAYLOAD.len()];
        let mut wb = WriteBuf::new(&mut buf);
        unwrap!(wb.append(PAYLOAD));
        assert_eq!(
            unwrap!(header()
                .encode(test_only_crypto(), None, NODE_ID, &mut wb)
                .err())
            .code(),
            ErrorCode::NoSpace
        );

        // Room for the proto header only is not enough either.
        let mut wb = WriteBuf::new_with(&mut buf, ProtoHdr::MAX_LEN, ProtoHdr::MAX_LEN);
        unwrap!(wb.append(PAYLOAD));
        assert_eq!(
            unwrap!(header()
                .encode(test_only_crypto(), None, NODE_ID, &mut wb)
                .err())
            .code(),
            ErrorCode::NoSpace
        );
    }

    /// `reset` yields a blank header that is reliable by default; `load`
    /// copies another header wholesale.
    #[test]
    fn reset_and_load() {
        let mut hdr = header();
        hdr.reset();
        assert_eq!(hdr.plain.ctr, 0);
        assert_eq!(hdr.plain.sess_id, 0);
        assert!(hdr.plain.get_src_nodeid().is_none());
        assert!(hdr.proto.is_reliable());
        assert!(!hdr.proto.is_initiator());
        assert!(hdr.proto.get_ack().is_none());
        assert!(!hdr.proto.is_decoded());

        hdr.load(&header());
        assert_header_matches(&hdr);
    }
}
