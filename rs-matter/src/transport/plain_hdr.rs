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

use crate::error::*;
use crate::utils::parsebuf::ParseBuf;
use crate::utils::writebuf::WriteBuf;
use bitflags::bitflags;
use log::info;

#[derive(Debug, PartialEq, Eq, Default, Copy, Clone)]
pub enum SessionType {
    #[default]
    None,
    Encrypted,
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MsgFlags: u8 {
        const DSIZ_UNICAST_NODEID = 0x01;
        const DSIZ_GROUPCAST_NODEID = 0x02;
        const SRC_ADDR_PRESENT = 0x04;
    }
}

// This is the unencrypted message
#[derive(Debug, Default, Clone)]
pub struct PlainHdr {
    pub flags: MsgFlags,
    pub sess_type: SessionType,
    pub sess_id: u16,
    pub ctr: u32,
    peer_nodeid: Option<u64>,
}

impl PlainHdr {
    pub fn set_dest_u64(&mut self, id: u64) {
        self.flags |= MsgFlags::DSIZ_UNICAST_NODEID;
        self.peer_nodeid = Some(id);
    }

    pub fn get_src_u64(&self) -> Option<u64> {
        if self.flags.contains(MsgFlags::SRC_ADDR_PRESENT) {
            self.peer_nodeid
        } else {
            None
        }
    }
}

impl PlainHdr {
    // it will have an additional 'message length' field first
    pub fn decode(&mut self, msg: &mut ParseBuf) -> Result<(), Error> {
        self.flags = MsgFlags::from_bits(msg.le_u8()?).ok_or(ErrorCode::Invalid)?;
        self.sess_id = msg.le_u16()?;
        let _sec_flags = msg.le_u8()?;
        self.sess_type = if self.sess_id != 0 {
            SessionType::Encrypted
        } else {
            SessionType::None
        };
        self.ctr = msg.le_u32()?;

        if self.flags.contains(MsgFlags::SRC_ADDR_PRESENT) {
            self.peer_nodeid = Some(msg.le_u64()?);
        }

        info!(
            "[decode] flags: {:?}, session type: {:#?}, sess_id: {}, ctr: {}",
            self.flags, self.sess_type, self.sess_id, self.ctr
        );
        Ok(())
    }

    pub fn encode(&mut self, resp_buf: &mut WriteBuf) -> Result<(), Error> {
        resp_buf.le_u8(self.flags.bits())?;
        resp_buf.le_u16(self.sess_id)?;
        resp_buf.le_u8(0)?;
        resp_buf.le_u32(self.ctr)?;
        if let Some(d) = self.peer_nodeid {
            resp_buf.le_u64(d)?;
        }
        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        self.sess_type == SessionType::Encrypted
    }
}

pub const fn max_plain_hdr_len() -> usize {
    // [optional] msg len only for TCP
    2 +
    // flags
        1 +
    // security flags
        1 +
    // session ID
        2 +
    // message ctr
        4 +
    // [optional] source node ID
        8 +
    // [optional] destination node ID
        8
}
