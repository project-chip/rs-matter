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

use log::{error, trace};
use std::sync::Mutex;

use boxslab::box_slab;

use crate::{
    error::Error,
    sys::MAX_PACKET_POOL_SIZE,
    utils::{parsebuf::ParseBuf, writebuf::WriteBuf},
};

use super::{
    network::Address,
    plain_hdr::{self, PlainHdr},
    proto_hdr::{self, ProtoHdr},
};

pub const MAX_RX_BUF_SIZE: usize = 1583;
type Buffer = [u8; MAX_RX_BUF_SIZE];

// TODO: I am not very happy with this construction, need to find another way to do this
pub struct BufferPool {
    buffers: [Option<Buffer>; MAX_PACKET_POOL_SIZE],
}

impl BufferPool {
    const INIT: Option<Buffer> = None;
    fn get() -> &'static Mutex<BufferPool> {
        static mut BUFFER_HOLDER: Option<Mutex<BufferPool>> = None;
        static ONCE: Once = Once::new();
        unsafe {
            ONCE.call_once(|| {
                BUFFER_HOLDER = Some(Mutex::new(BufferPool {
                    buffers: [BufferPool::INIT; MAX_PACKET_POOL_SIZE],
                }));
            });
            BUFFER_HOLDER.as_ref().unwrap()
        }
    }

    pub fn alloc() -> Option<(usize, &'static mut Buffer)> {
        trace!("Buffer Alloc called\n");

        let mut pool = BufferPool::get().lock().unwrap();
        for i in 0..MAX_PACKET_POOL_SIZE {
            if pool.buffers[i].is_none() {
                pool.buffers[i] = Some([0; MAX_RX_BUF_SIZE]);
                // Sigh! to by-pass the borrow-checker telling us we are stealing a mutable reference
                // from under the lock
                // In this case the lock only protects against the setting of Some/None,
                // the objects then are independently accessed in a unique way
                let buffer = unsafe { &mut *(pool.buffers[i].as_mut().unwrap() as *mut Buffer) };
                return Some((i, buffer));
            }
        }
        None
    }

    pub fn free(index: usize) {
        trace!("Buffer Free called\n");
        let mut pool = BufferPool::get().lock().unwrap();
        if pool.buffers[index].is_some() {
            pool.buffers[index] = None;
        }
    }
}

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
    buffer_index: usize,
}

impl<'a> Packet<'a> {
    const HDR_RESERVE: usize = plain_hdr::max_plain_hdr_len() + proto_hdr::max_proto_hdr_len();

    pub fn new_rx() -> Result<Self, Error> {
        let (buffer_index, buffer) = BufferPool::alloc().ok_or(Error::NoSpace)?;
        let buf_len = buffer.len();
        Ok(Self {
            plain: Default::default(),
            proto: Default::default(),
            buffer_index,
            peer: Address::default(),
            data: Direction::Rx(ParseBuf::new(buffer, buf_len), RxState::Uninit),
        })
    }

    pub fn new_tx() -> Result<Self, Error> {
        let (buffer_index, buffer) = BufferPool::alloc().ok_or(Error::NoSpace)?;
        let buf_len = buffer.len();

        let mut wb = WriteBuf::new(buffer, buf_len);
        wb.reserve(Packet::HDR_RESERVE)?;

        let mut p = Self {
            plain: Default::default(),
            proto: Default::default(),
            buffer_index,
            peer: Address::default(),
            data: Direction::Tx(wb),
        };
        // Reliability on by default
        p.proto.set_reliable();
        Ok(p)
    }

    pub fn as_borrow_slice(&mut self) -> &mut [u8] {
        match &mut self.data {
            Direction::Rx(pb, _) => pb.as_borrow_slice(),
            Direction::Tx(wb) => wb.as_mut_slice(),
        }
    }

    pub fn get_parsebuf(&mut self) -> Result<&mut ParseBuf<'a>, Error> {
        if let Direction::Rx(pbuf, _) = &mut self.data {
            Ok(pbuf)
        } else {
            Err(Error::Invalid)
        }
    }

    pub fn get_writebuf(&mut self) -> Result<&mut WriteBuf<'a>, Error> {
        if let Direction::Tx(wbuf) = &mut self.data {
            Ok(wbuf)
        } else {
            Err(Error::Invalid)
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
                    Err(Error::InvalidState)
                }
            }
            _ => Err(Error::InvalidState),
        }
    }

    pub fn is_plain_hdr_decoded(&self) -> Result<bool, Error> {
        match &self.data {
            Direction::Rx(_, state) => match state {
                RxState::Uninit => Ok(false),
                _ => Ok(true),
            },
            _ => Err(Error::InvalidState),
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
                    Err(Error::InvalidState)
                }
            }
            _ => Err(Error::InvalidState),
        }
    }
}

impl<'a> Drop for Packet<'a> {
    fn drop(&mut self) {
        BufferPool::free(self.buffer_index);
        trace!("Dropping Packet......");
    }
}

box_slab!(PacketPool, Packet<'static>, MAX_PACKET_POOL_SIZE);
