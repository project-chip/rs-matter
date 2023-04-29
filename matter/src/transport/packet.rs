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

use log::error;

use crate::{
    error::{Error, ErrorCode},
    utils::{parsebuf::ParseBuf, writebuf::WriteBuf},
};

use super::{
    network::Address,
    plain_hdr::{self, PlainHdr},
    proto_hdr::{self, ProtoHdr},
};

pub const MAX_RX_BUF_SIZE: usize = 1583;
pub const MAX_TX_BUF_SIZE: usize = 1280 - 40/*IPV6 header size*/ - 8/*UDP header size*/;

#[derive(PartialEq)]
enum RxState {
    Uninit,
    PlainDecode,
    ProtoDecode,
}

enum Direction<'a> {
    Tx(WriteBuf<'a>),
    Rx(ParseBuf<'a>, RxState),
}

pub struct Packet<'a> {
    pub plain: PlainHdr,
    pub proto: ProtoHdr,
    pub peer: Address,
    data: Direction<'a>,
}

impl<'a> Packet<'a> {
    const HDR_RESERVE: usize = plain_hdr::max_plain_hdr_len() + proto_hdr::max_proto_hdr_len();

    pub fn new_rx(buf: &'a mut [u8]) -> Self {
        Self {
            plain: Default::default(),
            proto: Default::default(),
            peer: Address::default(),
            data: Direction::Rx(ParseBuf::new(buf), RxState::Uninit),
        }
    }

    pub fn new_tx(buf: &'a mut [u8]) -> Self {
        let mut wb = WriteBuf::new(buf);
        wb.reserve(Packet::HDR_RESERVE).unwrap();

        // Reliability on by default
        let mut proto: ProtoHdr = Default::default();
        proto.set_reliable();

        Self {
            plain: Default::default(),
            proto,
            peer: Address::default(),
            data: Direction::Tx(wb),
        }
    }

    pub fn reset(&mut self) -> () {
        if let Direction::Tx(wb) = &mut self.data {
            wb.reset();
            wb.reserve(Packet::HDR_RESERVE).unwrap();

            self.plain = Default::default();
            self.proto = Default::default();
            self.peer = Address::default();

            self.proto.set_reliable();
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match &self.data {
            Direction::Rx(pb, _) => pb.as_slice(),
            Direction::Tx(wb) => wb.as_slice(),
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match &mut self.data {
            Direction::Rx(pb, _) => pb.as_mut_slice(),
            Direction::Tx(wb) => wb.as_mut_slice(),
        }
    }

    pub fn get_parsebuf(&mut self) -> Result<&mut ParseBuf<'a>, Error> {
        if let Direction::Rx(pbuf, _) = &mut self.data {
            Ok(pbuf)
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }

    pub fn get_writebuf(&mut self) -> Result<&mut WriteBuf<'a>, Error> {
        if let Direction::Tx(wbuf) = &mut self.data {
            Ok(wbuf)
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }

    pub fn get_proto_id(&self) -> u16 {
        self.proto.proto_id
    }

    pub fn set_proto_id(&mut self, proto_id: u16) {
        self.proto.proto_id = proto_id;
    }

    pub fn get_proto_opcode(&self) -> u8 {
        self.proto.proto_opcode
    }

    pub fn set_proto_opcode(&mut self, proto_opcode: u8) {
        self.proto.proto_opcode = proto_opcode;
    }

    pub fn set_reliable(&mut self) {
        self.proto.set_reliable()
    }

    pub fn unset_reliable(&mut self) {
        self.proto.unset_reliable()
    }

    pub fn is_reliable(&mut self) -> bool {
        self.proto.is_reliable()
    }

    pub fn proto_decode(&mut self, peer_nodeid: u64, dec_key: Option<&[u8]>) -> Result<(), Error> {
        match &mut self.data {
            Direction::Rx(pb, state) => {
                if *state == RxState::PlainDecode {
                    *state = RxState::ProtoDecode;
                    self.proto
                        .decrypt_and_decode(&self.plain, pb, peer_nodeid, dec_key)
                } else {
                    error!("Invalid state for proto_decode");
                    Err(ErrorCode::InvalidState.into())
                }
            }
            _ => Err(ErrorCode::InvalidState.into()),
        }
    }

    pub fn is_plain_hdr_decoded(&self) -> Result<bool, Error> {
        match &self.data {
            Direction::Rx(_, state) => match state {
                RxState::Uninit => Ok(false),
                _ => Ok(true),
            },
            _ => Err(ErrorCode::InvalidState.into()),
        }
    }

    pub fn plain_hdr_decode(&mut self) -> Result<(), Error> {
        match &mut self.data {
            Direction::Rx(pb, state) => {
                if *state == RxState::Uninit {
                    *state = RxState::PlainDecode;
                    self.plain.decode(pb)
                } else {
                    error!("Invalid state for plain_decode");
                    Err(ErrorCode::InvalidState.into())
                }
            }
            _ => Err(ErrorCode::InvalidState.into()),
        }
    }
}
