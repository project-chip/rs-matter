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

use crate::crypto::{Crypto, AEAD_MIC_LEN_BYTES};
use crate::error::Error;
use crate::fmt::Bytes;
use crate::utils::storage::{ParseBuf, WriteBuf};

use super::{
    plain_hdr::{self, PlainHdr},
    proto_hdr::{self, ProtoHdr},
};

#[derive(Debug, Default, Clone)]
pub struct PacketHdr {
    pub plain: PlainHdr,
    pub proto: ProtoHdr,
}

impl PacketHdr {
    pub const HDR_RESERVE: usize = plain_hdr::max_plain_hdr_len() + proto_hdr::max_proto_hdr_len();
    pub const TAIL_RESERVE: usize = AEAD_MIC_LEN_BYTES;

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
        pb: &mut ParseBuf,
        peer_nodeid: u64,
        dec_key: Option<&[u8]>,
        crypto: C,
    ) -> Result<(), Error> {
        self.proto
            .decrypt_and_decode(&self.plain, pb, peer_nodeid, dec_key, crypto)
    }

    pub fn encode<C: Crypto>(
        &self,
        wb: &mut WriteBuf,
        local_nodeid: u64,
        enc_key: Option<&[u8]>,
        crypto: C,
    ) -> Result<(), Error> {
        // Generate encrypted header
        let mut tmp_buf = [0_u8; proto_hdr::max_proto_hdr_len()];
        let mut write_buf = WriteBuf::new(&mut tmp_buf);
        self.proto.encode(&mut write_buf)?;
        wb.prepend(write_buf.as_slice())?;

        let mut tmp_buf = [0_u8; plain_hdr::max_plain_hdr_len()];
        let mut write_buf = WriteBuf::new(&mut tmp_buf);
        self.plain.encode(&mut write_buf)?;
        let plain_hdr_bytes = write_buf.as_slice();

        trace!("Unencrypted packet: {}", Bytes(wb.as_slice()));
        let ctr = self.plain.ctr;
        if let Some(e) = enc_key {
            proto_hdr::encrypt_in_place(ctr, local_nodeid, plain_hdr_bytes, wb, e, crypto)?;
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
