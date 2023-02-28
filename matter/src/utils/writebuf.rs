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
use byteorder::{ByteOrder, LittleEndian};

/// Shrink WriteBuf
///
/// This Macro creates a new (child) WriteBuf which has a truncated slice end.
/// - It accepts a WriteBuf, and the size to reserve (truncate) towards the end.
/// - It returns the new (child) WriteBuf
#[macro_export]
macro_rules! wb_shrink {
    ($orig_wb:ident, $reserve:ident) => {{
        let m_data = $orig_wb.empty_as_mut_slice();
        let m_wb = WriteBuf::new(m_data, m_data.len() - $reserve);
        (m_wb)
    }};
}

/// Unshrink WriteBuf
///
/// This macro unshrinks the WriteBuf
/// - It accepts the original WriteBuf and the child WriteBuf (that was the result of wb_shrink)
/// After this call, the child WriteBuf shouldn't be used
#[macro_export]
macro_rules! wb_unshrink {
    ($orig_wb:ident, $new_wb:ident) => {{
        let m_data_len = $new_wb.as_slice().len();
        $orig_wb.forward_tail_by(m_data_len);
    }};
}

#[derive(Debug)]
pub struct WriteBuf<'a> {
    buf: &'a mut [u8],
    start: usize,
    end: usize,
}

impl<'a> WriteBuf<'a> {
    pub fn new(buf: &'a mut [u8], len: usize) -> WriteBuf<'a> {
        WriteBuf {
            buf: &mut buf[..len],
            start: 0,
            end: 0,
        }
    }

    pub fn get_tail(&self) -> usize {
        self.end
    }

    pub fn rewind_tail_to(&mut self, new_end: usize) {
        self.end = new_end;
    }

    pub fn forward_tail_by(&mut self, new_offset: usize) {
        self.end += new_offset
    }

    pub fn as_borrow_slice(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    pub fn as_slice(self) -> &'a [u8] {
        &self.buf[self.start..self.end]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.end]
    }

    pub fn empty_as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.end..]
    }

    pub fn reset(&mut self, reserve: usize) {
        self.start = reserve;
        self.end = reserve;
    }

    pub fn reserve(&mut self, reserve: usize) -> Result<(), Error> {
        if self.end != 0 || self.start != 0 {
            return Err(Error::Invalid);
        }
        self.reset(reserve);
        Ok(())
    }

    pub fn prepend_with<F>(&mut self, size: usize, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Self),
    {
        if size <= self.start {
            f(self);
            self.start -= size;
            return Ok(());
        }
        Err(Error::NoSpace)
    }

    pub fn prepend(&mut self, src: &[u8]) -> Result<(), Error> {
        self.prepend_with(src.len(), |x| {
            let dst_slice = &mut x.buf[(x.start - src.len())..x.start];
            dst_slice.copy_from_slice(src);
        })
    }

    pub fn append_with<F>(&mut self, size: usize, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Self),
    {
        if self.end + size <= self.buf.len() {
            f(self);
            self.end += size;
            return Ok(());
        }
        Err(Error::NoSpace)
    }

    pub fn append(&mut self, src: &[u8]) -> Result<(), Error> {
        self.copy_from_slice(src)
    }

    pub fn copy_from_slice(&mut self, src: &[u8]) -> Result<(), Error> {
        self.append_with(src.len(), |x| {
            x.buf[x.end..(x.end + src.len())].copy_from_slice(src);
        })
    }

    pub fn le_i8(&mut self, data: i8) -> Result<(), Error> {
        self.le_u8(data as u8)
    }

    pub fn le_u8(&mut self, data: u8) -> Result<(), Error> {
        self.append_with(1, |x| {
            x.buf[x.end] = data;
        })
    }

    pub fn le_u16(&mut self, data: u16) -> Result<(), Error> {
        self.append_with(2, |x| {
            LittleEndian::write_u16(&mut x.buf[x.end..], data);
        })
    }
    pub fn le_i16(&mut self, data: i16) -> Result<(), Error> {
        self.append_with(2, |x| {
            LittleEndian::write_i16(&mut x.buf[x.end..], data);
        })
    }

    pub fn le_u32(&mut self, data: u32) -> Result<(), Error> {
        self.append_with(4, |x| {
            LittleEndian::write_u32(&mut x.buf[x.end..], data);
        })
    }

    pub fn le_i32(&mut self, data: i32) -> Result<(), Error> {
        self.append_with(4, |x| {
            LittleEndian::write_i32(&mut x.buf[x.end..], data);
        })
    }

    pub fn le_u64(&mut self, data: u64) -> Result<(), Error> {
        self.append_with(8, |x| {
            LittleEndian::write_u64(&mut x.buf[x.end..], data);
        })
    }

    pub fn le_i64(&mut self, data: i64) -> Result<(), Error> {
        self.append_with(8, |x| {
            LittleEndian::write_i64(&mut x.buf[x.end..], data);
        })
    }

    pub fn le_uint(&mut self, nbytes: usize, data: u64) -> Result<(), Error> {
        self.append_with(nbytes, |x| {
            LittleEndian::write_uint(&mut x.buf[x.end..], data, nbytes);
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::writebuf::*;

    #[test]
    fn test_append_le_with_success() {
        let mut test_slice: [u8; 22] = [0; 22];
        let test_slice_len = test_slice.len();
        let mut buf = WriteBuf::new(&mut test_slice, test_slice_len);
        buf.reserve(5).unwrap();

        buf.le_u8(1).unwrap();
        buf.le_u16(65).unwrap();
        buf.le_u32(0xcafebabe).unwrap();
        buf.le_u64(0xcafebabecafebabe).unwrap();
        buf.le_uint(2, 64).unwrap();
        assert_eq!(
            test_slice,
            [
                0, 0, 0, 0, 0, 1, 65, 0, 0xbe, 0xba, 0xfe, 0xca, 0xbe, 0xba, 0xfe, 0xca, 0xbe,
                0xba, 0xfe, 0xca, 64, 0
            ]
        );
    }

    #[test]
    fn test_len_param() {
        let mut test_slice: [u8; 20] = [0; 20];
        let mut buf = WriteBuf::new(&mut test_slice, 5);
        buf.reserve(5).unwrap();

        let _ = buf.le_u8(1);
        let _ = buf.le_u16(65);
        let _ = buf.le_u32(0xcafebabe);
        let _ = buf.le_u64(0xcafebabecafebabe);
        // All of the above must return error, and hence the slice shouldn't change
        assert_eq!(test_slice, [0; 20]);
    }

    #[test]
    fn test_overrun() {
        let mut test_slice: [u8; 20] = [0; 20];
        let mut buf = WriteBuf::new(&mut test_slice, 20);
        buf.reserve(4).unwrap();
        buf.le_u64(0xcafebabecafebabe).unwrap();
        buf.le_u64(0xcafebabecafebabe).unwrap();
        // Now the buffer is fully filled up, so no further puts will happen

        if buf.le_u8(1).is_ok() {
            panic!("Should return error")
        }

        if buf.le_u16(65).is_ok() {
            panic!("Should return error")
        }

        if buf.le_u32(0xcafebabe).is_ok() {
            panic!("Should return error")
        }

        if buf.le_u64(0xcafebabecafebabe).is_ok() {
            panic!("Should return error")
        }
    }

    #[test]
    fn test_as_slice() {
        let mut test_slice: [u8; 20] = [0; 20];
        let mut buf = WriteBuf::new(&mut test_slice, 20);
        buf.reserve(5).unwrap();

        buf.le_u8(1).unwrap();
        buf.le_u16(65).unwrap();
        buf.le_u32(0xcafebabe).unwrap();
        buf.le_u64(0xcafebabecafebabe).unwrap();

        let new_slice: [u8; 3] = [0xa, 0xb, 0xc];
        buf.prepend(&new_slice).unwrap();

        assert_eq!(
            buf.as_slice(),
            [
                0xa, 0xb, 0xc, 1, 65, 0, 0xbe, 0xba, 0xfe, 0xca, 0xbe, 0xba, 0xfe, 0xca, 0xbe,
                0xba, 0xfe, 0xca
            ]
        );
    }

    #[test]
    fn test_copy_as_slice() {
        let mut test_slice: [u8; 20] = [0; 20];
        let mut buf = WriteBuf::new(&mut test_slice, 20);
        buf.reserve(5).unwrap();

        buf.le_u16(65).unwrap();
        let new_slice: [u8; 5] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        buf.copy_from_slice(&new_slice).unwrap();
        buf.le_u32(65).unwrap();
        assert_eq!(
            test_slice,
            [0, 0, 0, 0, 0, 65, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 65, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_copy_as_slice_overrun() {
        let mut test_slice: [u8; 20] = [0; 20];
        let mut buf = WriteBuf::new(&mut test_slice, 7);
        buf.reserve(5).unwrap();

        buf.le_u16(65).unwrap();
        let new_slice: [u8; 5] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        if buf.copy_from_slice(&new_slice).is_ok() {
            panic!("This should have returned error")
        }
    }

    #[test]
    fn test_prepend() {
        let mut test_slice: [u8; 20] = [0; 20];
        let mut buf = WriteBuf::new(&mut test_slice, 20);
        buf.reserve(5).unwrap();

        buf.le_u16(65).unwrap();
        let new_slice: [u8; 5] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        buf.prepend(&new_slice).unwrap();
        assert_eq!(
            test_slice,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_prepend_overrun() {
        let mut test_slice: [u8; 20] = [0; 20];
        let mut buf = WriteBuf::new(&mut test_slice, 20);
        buf.reserve(5).unwrap();

        buf.le_u16(65).unwrap();
        let new_slice: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        if buf.prepend(&new_slice).is_ok() {
            panic!("Prepend should return error")
        }
    }

    #[test]
    fn test_rewind_tail() {
        let mut test_slice: [u8; 20] = [0; 20];
        let mut buf = WriteBuf::new(&mut test_slice, 20);
        buf.reserve(5).unwrap();

        buf.le_u16(65).unwrap();

        let anchor = buf.get_tail();

        let new_slice: [u8; 5] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        buf.copy_from_slice(&new_slice).unwrap();
        assert_eq!(
            buf.as_borrow_slice(),
            [65, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,]
        );

        buf.rewind_tail_to(anchor);
        buf.le_u16(66).unwrap();
        assert_eq!(buf.as_borrow_slice(), [65, 0, 66, 0,]);
    }
}
