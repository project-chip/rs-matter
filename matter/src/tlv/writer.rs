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

use super::{TagType, TAG_SHIFT_BITS, TAG_SIZE_MAP};
use crate::{error::*, utils::writebuf::WriteBuf};
use log::error;

#[allow(dead_code)]
enum WriteElementType {
    S8 = 0,
    S16 = 1,
    S32 = 2,
    S64 = 3,
    U8 = 4,
    U16 = 5,
    U32 = 6,
    U64 = 7,
    False = 8,
    True = 9,
    F32 = 10,
    F64 = 11,
    Utf8l = 12,
    Utf16l = 13,
    Utf32l = 14,
    Utf64l = 15,
    Str8l = 16,
    Str16l = 17,
    Str32l = 18,
    Str64l = 19,
    Null = 20,
    Struct = 21,
    Array = 22,
    List = 23,
    EndCnt = 24,
    Last,
}

pub struct TLVWriter<'a, 'b> {
    buf: &'a mut WriteBuf<'b>,
}

impl<'a, 'b> TLVWriter<'a, 'b> {
    pub fn new(buf: &'a mut WriteBuf<'b>) -> Self {
        TLVWriter { buf }
    }

    // TODO: The current method of using writebuf's put methods force us to do
    // at max 3 checks while writing a single TLV (once for control, once for tag,
    // once for value), so do a single check and write the whole thing.
    #[inline(always)]
    fn put_control_tag(
        &mut self,
        tag_type: TagType,
        val_type: WriteElementType,
    ) -> Result<(), Error> {
        let (tag_id, tag_val) = match tag_type {
            TagType::Anonymous => (0_u8, 0),
            TagType::Context(v) => (1, v as u64),
            TagType::CommonPrf16(v) => (2, v as u64),
            TagType::CommonPrf32(v) => (3, v as u64),
            TagType::ImplPrf16(v) => (4, v as u64),
            TagType::ImplPrf32(v) => (5, v as u64),
            TagType::FullQual48(v) => (6, v),
            TagType::FullQual64(v) => (7, v),
        };
        self.buf
            .le_u8(((tag_id) << TAG_SHIFT_BITS) | (val_type as u8))?;
        if tag_type != TagType::Anonymous {
            self.buf.le_uint(TAG_SIZE_MAP[tag_id as usize], tag_val)?;
        }
        Ok(())
    }

    pub fn i8(&mut self, tag_type: TagType, data: i8) -> Result<(), Error> {
        self.put_control_tag(tag_type, WriteElementType::S8)?;
        self.buf.le_i8(data)
    }

    pub fn u8(&mut self, tag_type: TagType, data: u8) -> Result<(), Error> {
        self.put_control_tag(tag_type, WriteElementType::U8)?;
        self.buf.le_u8(data)
    }

    pub fn i16(&mut self, tag_type: TagType, data: i16) -> Result<(), Error> {
        if data >= i8::MIN as i16 && data <= i8::MAX as i16 {
            self.i8(tag_type, data as i8)
        } else {
            self.put_control_tag(tag_type, WriteElementType::S16)?;
            self.buf.le_i16(data)
        }
    }

    pub fn u16(&mut self, tag_type: TagType, data: u16) -> Result<(), Error> {
        if data <= 0xff {
            self.u8(tag_type, data as u8)
        } else {
            self.put_control_tag(tag_type, WriteElementType::U16)?;
            self.buf.le_u16(data)
        }
    }

    pub fn i32(&mut self, tag_type: TagType, data: i32) -> Result<(), Error> {
        if data >= i8::MIN as i32 && data <= i8::MAX as i32 {
            self.i8(tag_type, data as i8)
        } else if data >= i16::MIN as i32 && data <= i16::MAX as i32 {
            self.i16(tag_type, data as i16)
        } else {
            self.put_control_tag(tag_type, WriteElementType::S32)?;
            self.buf.le_i32(data)
        }
    }

    pub fn u32(&mut self, tag_type: TagType, data: u32) -> Result<(), Error> {
        if data <= 0xff {
            self.u8(tag_type, data as u8)
        } else if data <= 0xffff {
            self.u16(tag_type, data as u16)
        } else {
            self.put_control_tag(tag_type, WriteElementType::U32)?;
            self.buf.le_u32(data)
        }
    }

    pub fn i64(&mut self, tag_type: TagType, data: i64) -> Result<(), Error> {
        if data >= i8::MIN as i64 && data <= i8::MAX as i64 {
            self.i8(tag_type, data as i8)
        } else if data >= i16::MIN as i64 && data <= i16::MAX as i64 {
            self.i16(tag_type, data as i16)
        } else if data >= i32::MIN as i64 && data <= i32::MAX as i64 {
            self.i32(tag_type, data as i32)
        } else {
            self.put_control_tag(tag_type, WriteElementType::S64)?;
            self.buf.le_i64(data)
        }
    }

    pub fn u64(&mut self, tag_type: TagType, data: u64) -> Result<(), Error> {
        if data <= 0xff {
            self.u8(tag_type, data as u8)
        } else if data <= 0xffff {
            self.u16(tag_type, data as u16)
        } else if data <= 0xffffffff {
            self.u32(tag_type, data as u32)
        } else {
            self.put_control_tag(tag_type, WriteElementType::U64)?;
            self.buf.le_u64(data)
        }
    }

    pub fn str8(&mut self, tag_type: TagType, data: &[u8]) -> Result<(), Error> {
        if data.len() > 256 {
            error!("use str16() instead");
            return Err(Error::Invalid);
        }
        self.put_control_tag(tag_type, WriteElementType::Str8l)?;
        self.buf.le_u8(data.len() as u8)?;
        self.buf.copy_from_slice(data)
    }

    pub fn str16(&mut self, tag_type: TagType, data: &[u8]) -> Result<(), Error> {
        if data.len() <= 0xff {
            self.str8(tag_type, data)
        } else {
            self.put_control_tag(tag_type, WriteElementType::Str16l)?;
            self.buf.le_u16(data.len() as u16)?;
            self.buf.copy_from_slice(data)
        }
    }

    // This is quite hacky
    pub fn str16_as<F>(&mut self, tag_type: TagType, data_gen: F) -> Result<(), Error>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, Error>,
    {
        let anchor = self.buf.get_tail();
        self.put_control_tag(tag_type, WriteElementType::Str16l)?;

        let wb = self.buf.empty_as_mut_slice();
        // Reserve 2 spaces for the control and length
        let str = &mut wb[2..];
        let len = data_gen(str).unwrap_or_default();
        if len <= 0xff {
            // Shift everything by 1
            let str = &mut wb[1..];
            for i in 0..len {
                str[i] = str[i + 1];
            }
            self.buf.rewind_tail_to(anchor);
            self.put_control_tag(tag_type, WriteElementType::Str8l)?;
            self.buf.le_u8(len as u8)?;
        } else {
            self.buf.le_u16(len as u16)?;
        }
        self.buf.forward_tail_by(len);
        Ok(())
    }

    pub fn utf8(&mut self, tag_type: TagType, data: &[u8]) -> Result<(), Error> {
        self.put_control_tag(tag_type, WriteElementType::Utf8l)?;
        self.buf.le_u8(data.len() as u8)?;
        self.buf.copy_from_slice(data)
    }

    pub fn utf16(&mut self, tag_type: TagType, data: &[u8]) -> Result<(), Error> {
        if data.len() <= 0xff {
            self.utf8(tag_type, data)
        } else {
            self.put_control_tag(tag_type, WriteElementType::Utf16l)?;
            self.buf.le_u16(data.len() as u16)?;
            self.buf.copy_from_slice(data)
        }
    }

    fn no_val(&mut self, tag_type: TagType, element: WriteElementType) -> Result<(), Error> {
        self.put_control_tag(tag_type, element)
    }

    pub fn start_struct(&mut self, tag_type: TagType) -> Result<(), Error> {
        self.no_val(tag_type, WriteElementType::Struct)
    }

    pub fn start_array(&mut self, tag_type: TagType) -> Result<(), Error> {
        self.no_val(tag_type, WriteElementType::Array)
    }

    pub fn start_list(&mut self, tag_type: TagType) -> Result<(), Error> {
        self.no_val(tag_type, WriteElementType::List)
    }

    pub fn end_container(&mut self) -> Result<(), Error> {
        self.no_val(TagType::Anonymous, WriteElementType::EndCnt)
    }

    pub fn null(&mut self, tag_type: TagType) -> Result<(), Error> {
        self.no_val(tag_type, WriteElementType::Null)
    }

    pub fn bool(&mut self, tag_type: TagType, val: bool) -> Result<(), Error> {
        if val {
            self.no_val(tag_type, WriteElementType::True)
        } else {
            self.no_val(tag_type, WriteElementType::False)
        }
    }

    pub fn get_tail(&self) -> usize {
        self.buf.get_tail()
    }

    pub fn rewind_to(&mut self, anchor: usize) {
        self.buf.rewind_tail_to(anchor);
    }

    pub fn get_buf(&mut self) -> &mut WriteBuf<'b> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::{TLVWriter, TagType};
    use crate::utils::writebuf::WriteBuf;

    #[test]
    fn test_write_success() {
        let mut buf = [0; 20];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWriter::new(&mut writebuf);

        tw.start_struct(TagType::Anonymous).unwrap();
        tw.u8(TagType::Anonymous, 12).unwrap();
        tw.u8(TagType::Context(1), 13).unwrap();
        tw.u16(TagType::Anonymous, 0x1212).unwrap();
        tw.u16(TagType::Context(2), 0x1313).unwrap();
        tw.start_array(TagType::Context(3)).unwrap();
        tw.bool(TagType::Anonymous, true).unwrap();
        tw.end_container().unwrap();
        tw.end_container().unwrap();
        assert_eq!(
            buf,
            [21, 4, 12, 36, 1, 13, 5, 0x12, 0x012, 37, 2, 0x13, 0x13, 54, 3, 9, 24, 24, 0, 0]
        );
    }

    #[test]
    fn test_write_overflow() {
        let mut buf = [0; 6];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWriter::new(&mut writebuf);

        tw.u8(TagType::Anonymous, 12).unwrap();
        tw.u8(TagType::Context(1), 13).unwrap();
        if tw.u16(TagType::Anonymous, 12).is_ok() {
            panic!("This should have returned error")
        }
        if tw.u16(TagType::Context(2), 13).is_ok() {
            panic!("This should have returned error")
        }
        assert_eq!(buf, [4, 12, 36, 1, 13, 4]);
    }

    #[test]
    fn test_put_str8() {
        let mut buf = [0; 20];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWriter::new(&mut writebuf);

        tw.u8(TagType::Context(1), 13).unwrap();
        tw.str8(TagType::Anonymous, &[10, 11, 12, 13, 14]).unwrap();
        tw.u16(TagType::Context(2), 0x1313).unwrap();
        tw.str8(TagType::Context(3), &[20, 21, 22]).unwrap();
        assert_eq!(
            buf,
            [36, 1, 13, 16, 5, 10, 11, 12, 13, 14, 37, 2, 0x13, 0x13, 48, 3, 3, 20, 21, 22]
        );
    }

    #[test]
    fn test_put_str16_as() {
        let mut buf = [0; 20];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWriter::new(&mut writebuf);

        tw.u8(TagType::Context(1), 13).unwrap();
        tw.str8(TagType::Context(2), &[10, 11, 12, 13, 14]).unwrap();
        tw.str16_as(TagType::Context(3), |buf| {
            buf[0] = 10;
            buf[1] = 11;
            Ok(2)
        })
        .unwrap();
        tw.u8(TagType::Context(4), 13).unwrap();

        assert_eq!(
            buf,
            [36, 1, 13, 48, 2, 5, 10, 11, 12, 13, 14, 48, 3, 2, 10, 11, 36, 4, 13, 0]
        );
    }
}
