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

use core::borrow::{Borrow, BorrowMut};

use crate::error::*;
use core::convert::TryInto;

/// A buffer for reading data from a byte slice.
pub struct ReadBuf<T> {
    buf: T,
    read_off: usize,
    left: usize,
}

impl<T> ReadBuf<T>
where
    T: Borrow<[u8]>,
{
    pub fn new(buf: T) -> Self {
        let left = buf.borrow().len();

        Self {
            buf,
            read_off: 0,
            left,
        }
    }

    pub fn reset(&mut self) {
        self.read_off = 0;
        self.left = self.buf.borrow().len();
    }

    pub fn load<Q>(&mut self, pb: &ReadBuf<Q>) -> Result<(), Error>
    where
        T: BorrowMut<[u8]>,
        Q: Borrow<[u8]>,
    {
        if self.buf.borrow().len() < pb.read_off + pb.left {
            Err(ErrorCode::BufferTooSmall)?;
        }

        self.buf.borrow_mut()[0..pb.read_off + pb.left]
            .copy_from_slice(&pb.buf.borrow()[..pb.read_off + pb.left]);
        self.read_off = pb.read_off;
        self.left = pb.left;

        Ok(())
    }

    pub fn set_len(&mut self, left: usize) {
        self.left = left;
    }

    pub fn slice_range(&self) -> (usize, usize) {
        (self.read_off, self.read_off + self.left)
    }

    // Return the data that is valid as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.buf.borrow()[self.read_off..(self.read_off + self.left)]
    }

    // Return the data that is valid as a slice
    pub fn as_mut_slice(&mut self) -> &mut [u8]
    where
        T: BorrowMut<[u8]>,
    {
        &mut self.buf.borrow_mut()[self.read_off..(self.read_off + self.left)]
    }

    pub fn parsed_as_slice(&self) -> &[u8] {
        &self.buf.borrow()[0..self.read_off]
    }

    pub fn tail(&mut self, size: usize) -> Result<&[u8], Error> {
        if size <= self.left {
            let end_offset = self.read_off + self.left;
            let tail = &self.buf.borrow()[(end_offset - size)..end_offset];
            self.left -= size;
            return Ok(tail);
        }
        Err(ErrorCode::TruncatedPacket.into())
    }

    fn advance(&mut self, len: usize) {
        self.read_off += len;
        self.left -= len;
    }

    pub fn parse_head_with<F, R>(&mut self, size: usize, f: F) -> Result<R, Error>
    where
        F: FnOnce(&mut Self) -> R,
    {
        if self.left >= size {
            let data = f(self);
            self.advance(size);
            return Ok(data);
        }
        Err(ErrorCode::TruncatedPacket.into())
    }

    pub fn parse_as_array<F, R, const N: usize>(&mut self, f: F) -> Result<R, Error>
    where
        F: FnOnce([u8; N]) -> R,
    {
        if self.left >= N {
            let end_offset = self.read_off + N;
            let data = f(self.buf.borrow()[self.read_off..end_offset]
                .try_into()
                .unwrap());
            self.advance(N);
            return Ok(data);
        }
        Err(ErrorCode::TruncatedPacket.into())
    }

    pub fn le_u8(&mut self) -> Result<u8, Error> {
        self.parse_head_with(1, |x| x.buf.borrow()[x.read_off])
    }

    pub fn le_u16(&mut self) -> Result<u16, Error> {
        self.parse_as_array(|x| u16::from_le_bytes(x))
    }

    pub fn le_u32(&mut self) -> Result<u32, Error> {
        self.parse_as_array(|x| u32::from_le_bytes(x))
    }

    pub fn le_u64(&mut self) -> Result<u64, Error> {
        self.parse_as_array(|x| u64::from_le_bytes(x))
    }
}

pub type ParseBuf<'a> = ReadBuf<&'a mut [u8]>;

#[cfg(test)]
mod tests {
    use crate::utils::storage::ParseBuf;

    #[test]
    fn test_parse_with_success() {
        let mut test_slice = [0x01, 65, 0, 0xbe, 0xba, 0xfe, 0xca, 0xa, 0xb, 0xc, 0xd];
        let mut buf = ParseBuf::new(&mut test_slice);

        assert_eq!(buf.le_u8().unwrap(), 0x01);
        assert_eq!(buf.le_u16().unwrap(), 65);
        assert_eq!(buf.le_u32().unwrap(), 0xcafebabe);
        assert_eq!(buf.as_slice(), [0xa, 0xb, 0xc, 0xd]);
    }

    #[test]
    fn test_parse_with_overrun() {
        let mut test_slice = [0x01, 65];
        let mut buf = ParseBuf::new(&mut test_slice);

        assert_eq!(buf.le_u8().unwrap(), 0x01);

        if buf.le_u16().is_ok() {
            panic!("This should have returned error")
        }

        if buf.le_u32().is_ok() {
            panic!("This should have returned error")
        }

        // Now consume the leftover byte
        assert_eq!(buf.le_u8().unwrap(), 65);

        if buf.le_u8().is_ok() {
            panic!("This should have returned error")
        }
        assert_eq!(buf.as_slice(), [] as [u8; 0]);
    }

    #[test]
    fn test_tail_with_success() {
        let mut test_slice = [0x01, 65, 0, 0xbe, 0xba, 0xfe, 0xca, 0xa, 0xb, 0xc, 0xd];
        let mut buf = ParseBuf::new(&mut test_slice);

        assert_eq!(buf.le_u8().unwrap(), 0x01);
        assert_eq!(buf.le_u16().unwrap(), 65);
        assert_eq!(buf.le_u32().unwrap(), 0xcafebabe);

        assert_eq!(buf.tail(2).unwrap(), [0xc, 0xd]);
        assert_eq!(buf.as_slice(), [0xa, 0xb]);

        assert_eq!(buf.tail(2).unwrap(), [0xa, 0xb]);
        assert_eq!(buf.as_slice(), [] as [u8; 0]);
    }

    #[test]
    fn test_tail_with_overrun() {
        let mut test_slice = [0x01, 65, 0, 0xbe, 0xba, 0xfe, 0xca, 0xa, 0xb, 0xc, 0xd];
        let mut buf = ParseBuf::new(&mut test_slice);

        assert_eq!(buf.le_u8().unwrap(), 0x01);
        assert_eq!(buf.le_u16().unwrap(), 65);
        assert_eq!(buf.le_u32().unwrap(), 0xcafebabe);
        if buf.tail(5).is_ok() {
            panic!("This should have returned error")
        }
        assert_eq!(buf.tail(2).unwrap(), [0xc, 0xd]);
    }

    #[test]
    fn test_parsed_as_slice() {
        let mut test_slice = [0x01, 65, 0, 0xbe, 0xba, 0xfe, 0xca, 0xa, 0xb, 0xc, 0xd];
        let mut buf = ParseBuf::new(&mut test_slice);

        assert_eq!(buf.parsed_as_slice(), [] as [u8; 0]);
        assert_eq!(buf.le_u8().unwrap(), 0x1);
        assert_eq!(buf.le_u16().unwrap(), 65);
        assert_eq!(buf.le_u32().unwrap(), 0xcafebabe);
        assert_eq!(buf.parsed_as_slice(), [0x01, 65, 0, 0xbe, 0xba, 0xfe, 0xca]);
    }
}
