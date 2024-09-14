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

use crate::error::*;
use crate::utils::storage::{ParseBuf, WriteBuf};
use bitflags::bitflags;
use log::trace;

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MsgFlags: u8 {
        const DSIZ_UNICAST_NODEID = 0x01;
        const DSIZ_GROUPCAST_NODEID = 0x02;
        const SRC_ADDR_PRESENT = 0x04;
    }
}

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

// This is the unencrypted message
#[derive(Debug, Default, Clone)]
pub struct PlainHdr {
    flags: MsgFlags,
    pub sess_id: u16,
    pub ctr: u32,
    src_nodeid: u64,
    dst_nodeid: u64,
}

impl PlainHdr {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            flags: MsgFlags::empty(),
            sess_id: 0,
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
        if self.flags.contains(MsgFlags::DSIZ_UNICAST_NODEID) {
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
            self.flags
                .remove(MsgFlags::DSIZ_UNICAST_NODEID | MsgFlags::DSIZ_GROUPCAST_NODEID);
            self.dst_nodeid = 0;
        }
    }

    pub fn get_dst_groupcast_nodeid(&self) -> Option<u16> {
        if self.flags.contains(MsgFlags::DSIZ_GROUPCAST_NODEID) {
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
            self.flags
                .remove(MsgFlags::DSIZ_UNICAST_NODEID | MsgFlags::DSIZ_GROUPCAST_NODEID);
            self.dst_nodeid = 0;
        }
    }

    // it will have an additional 'message length' field first
    pub fn decode(&mut self, msg: &mut ParseBuf) -> Result<(), Error> {
        self.flags = MsgFlags::from_bits(msg.le_u8()?).ok_or(ErrorCode::Invalid)?;
        self.sess_id = msg.le_u16()?;
        let _sec_flags = msg.le_u8()?;
        self.ctr = msg.le_u32()?;

        if self.flags.contains(MsgFlags::SRC_ADDR_PRESENT) {
            self.src_nodeid = msg.le_u64()?;
        }

        if !self
            .flags
            .contains(MsgFlags::DSIZ_UNICAST_NODEID | MsgFlags::DSIZ_GROUPCAST_NODEID)
        {
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
        resp_buf.le_u8(0)?;
        resp_buf.le_u32(self.ctr)?;

        if self.flags.contains(MsgFlags::SRC_ADDR_PRESENT) {
            resp_buf.le_u64(self.src_nodeid)?;
        }

        if !self
            .flags
            .contains(MsgFlags::DSIZ_UNICAST_NODEID | MsgFlags::DSIZ_GROUPCAST_NODEID)
        {
            if self.flags.contains(MsgFlags::DSIZ_UNICAST_NODEID) {
                resp_buf.le_u64(self.dst_nodeid)?;
            } else if self.flags.contains(MsgFlags::DSIZ_GROUPCAST_NODEID) {
                resp_buf.le_u16(self.dst_nodeid as u16)?;
            }
        }

        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        self.sess_id != 0
    }
}

impl fmt::Display for PlainHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.flags.is_empty() {
            write!(f, "{},", self.flags)?;
        }

        write!(f, "SID:{:x},CTR:{:x}", self.sess_id, self.ctr)?;

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
