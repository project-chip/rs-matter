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

//! This module defines the BDX block-transfer control messages: `BlockQuery`, `BlockAck`,
//! `BlockAckEOF` and `BlockQueryWithSkip`, per the Matter Core Spec. 

use core::borrow::Borrow;

use crate::error::Error;
use crate::utils::storage::{ReadBuf, WriteBuf};

/// A BDX block counter: a 32-bit index identifying a block within a transfer.
///
/// Block counters advance with modulo-2^32 arithmetic, so the counter following `0xFFFF_FFFF`
/// is `0x0000_0000` (Matter Core Spec, 11.22.6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockCounter(pub u32);

impl BlockCounter {
    pub fn read<T>(pb: &mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        Ok(Self(pb.le_u32()?))
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        wb.le_u32(self.0)
    }
}

/// A BDX `BlockQuery` message the receiver requests the block at this BlockCounter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockQuery(pub BlockCounter);

impl BlockQuery {
    pub fn read<T>(pb: &mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        Ok(Self(BlockCounter::read(pb)?))
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        self.0.write(wb)
    }
}

/// A BDX `BlockAck` message acknowledges the `Block` with the matching BlockCounter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockAck(pub BlockCounter);

impl BlockAck {
    pub fn read<T>(pb: &mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        Ok(Self(BlockCounter::read(pb)?))
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        self.0.write(wb)
    }
}

/// A BDX `BlockAckEOF` message, acknowledges the final `BlockEOF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockAckEOF(pub BlockCounter);

impl BlockAckEOF {
    pub fn read<T>(pb: &mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        Ok(Self(BlockCounter::read(pb)?))
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        self.0.write(wb)
    }
}

/// A BDX `BlockQueryWithSkip` message; like BlockQuery but asks to skip N bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockQueryWithSkip {
    /// The counter of the block being requested.
    pub block_counter: BlockCounter,
    /// The number of bytes the sender should skip before sending the next block.
    pub bytes_to_skip: u64,
}

impl BlockQueryWithSkip {
    pub fn read<T>(pb: &mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        Ok(Self {
            block_counter: BlockCounter::read(pb)?,
            bytes_to_skip: pb.le_u64()?,
        })
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        self.block_counter.write(wb)?;
        wb.le_u64(self.bytes_to_skip)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::storage::{ReadBuf, WriteBuf};

    use super::*;

    // Unlike im.rs, we can't lean on the TLV layer for testing, hence little suite for BDX serialization

    #[test]
    fn block_query_roundtrip() {
        // Use the wraparound edge value as the counter.
        let msg = BlockQuery(BlockCounter(0xFFFF_FFFF));

        let mut buf = [0; 16];
        let mut wb = WriteBuf::new(&mut buf);
        msg.write(&mut wb).unwrap();
        let len = wb.as_slice().len();

        let mut rb = ReadBuf::new(&buf[..len]);
        assert_eq!(msg, BlockQuery::read(&mut rb).unwrap());
    }

    #[test]
    fn block_query_with_skip_roundtrip() {
        // `bytes_to_skip` > u32::MAX to confirm the full 64-bit field round-trips.
        let msg = BlockQueryWithSkip {
            block_counter: BlockCounter(7),
            bytes_to_skip: u64::from(u32::MAX) + 1,
        };

        let mut buf = [0; 16];
        let mut wb = WriteBuf::new(&mut buf);
        msg.write(&mut wb).unwrap();
        let len = wb.as_slice().len();

        let mut rb = ReadBuf::new(&buf[..len]);
        assert_eq!(msg, BlockQueryWithSkip::read(&mut rb).unwrap());
    }
}
