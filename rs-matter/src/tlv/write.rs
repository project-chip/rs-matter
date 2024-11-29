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

use num_traits::ToBytes;

use crate::error::{Error, ErrorCode};
use crate::utils::storage::WriteBuf;

use super::{TLVControl, TLVTag, TLVTagType, TLVValue, TLVValueType};

/// For backwards compatibility
pub struct TLVWriter<'a, 'b>(&'a mut WriteBuf<'b>);

impl<'a, 'b> TLVWriter<'a, 'b> {
    pub fn new(buf: &'a mut WriteBuf<'b>) -> Self {
        Self(buf)
    }

    /// Write a tag and a TLV Octet String to the TLV stream, where the Octet String is a slice of u8 bytes.
    ///
    /// The writing is done via a user-supplied callback `cb`, that is expected to fill the provided buffer with the data
    /// and to return the length of the written data.
    ///
    /// This method is useful when the data to be written needs to be computed first, and the computation needs a buffer where
    /// to operate.
    ///
    /// Note that this method always uses a Str16l value type to write the data, which restricts the data length to no more than
    /// 65535 bytes.
    pub fn str_cb(
        &mut self,
        tag: &TLVTag,
        cb: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<(), Error> {
        self.0.str_cb(tag, cb)
    }

    /// Write a tag and a TLV UTF-8 String to the TLV stream, where the UTF-8 String is a str.
    ///
    /// The writing is done via a user-supplied callback `cb`, that is expected to fill the provided buffer with the data
    /// and to return the length of the written data.
    ///
    /// This method is useful when the data to be written needs to be computed first, and the computation needs a buffer where
    /// to operate.
    ///
    /// Note that this method always uses a Utf16l value type to write the data, which restricts the data length to no more than
    /// 65535 bytes.
    pub fn utf8_cb(
        &mut self,
        tag: &TLVTag,
        cb: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<(), Error> {
        self.0.utf8_cb(tag, cb)
    }
}

impl TLVWrite for TLVWriter<'_, '_> {
    type Position = usize;

    fn write(&mut self, byte: u8) -> Result<(), Error> {
        WriteBuf::append(self.0, &[byte])
    }

    fn get_tail(&self) -> Self::Position {
        WriteBuf::get_tail(self.0)
    }

    fn rewind_to(&mut self, pos: Self::Position) {
        WriteBuf::rewind_tail_to(self.0, pos)
    }
}

/// A trait representing a storage where data can be serialized as a TLV stream.
/// by synchronously emitting bytes to the storage.
///
/// The one method that needs to be implemented by user code is `write`.
///
/// The trait operates in an append-only manner without requiring access to the serialized
/// TLV data, so it can be implemented with an in-memory storage, or a file storage, or anything
/// that can output a byte to somewhere (like the `Write` Rust traits).
///
/// With that said, the trait has two additional methods that (optionally) allow for "rewinding"
/// the storage. Implementing these is optional, and they currently exist only for backwards
/// compatibility with code implemented prior to the introduction of this trait.
///
/// For iterator-style TLV serialization look at the `ToTLVIter` trait.
pub trait TLVWrite {
    type Position;

    /// Write a TLV tag and value to the TLV stream.
    fn tlv(&mut self, tag: &TLVTag, value: &TLVValue) -> Result<(), Error> {
        self.raw_value(tag, value.value_type(), &[])?;

        match value {
            TLVValue::Str8l(a) => self.write_raw_data((a.len() as u8).to_le_bytes()),
            TLVValue::Str16l(a) => self.write_raw_data((a.len() as u16).to_le_bytes()),
            TLVValue::Str32l(a) => self.write_raw_data((a.len() as u32).to_le_bytes()),
            TLVValue::Str64l(a) => self.write_raw_data((a.len() as u64).to_le_bytes()),
            TLVValue::Utf8l(a) => self.write_raw_data((a.len() as u8).to_le_bytes()),
            TLVValue::Utf16l(a) => self.write_raw_data((a.len() as u16).to_le_bytes()),
            TLVValue::Utf32l(a) => self.write_raw_data((a.len() as u32).to_le_bytes()),
            TLVValue::Utf64l(a) => self.write_raw_data((a.len() as u64).to_le_bytes()),
            _ => Ok(()),
        }?;

        match value {
            TLVValue::S8(a) => self.write_raw_data(a.to_le_bytes()),
            TLVValue::S16(a) => self.write_raw_data(a.to_le_bytes()),
            TLVValue::S32(a) => self.write_raw_data(a.to_le_bytes()),
            TLVValue::S64(a) => self.write_raw_data(a.to_le_bytes()),
            TLVValue::U8(a) => self.write_raw_data(a.to_le_bytes()),
            TLVValue::U16(a) => self.write_raw_data(a.to_le_bytes()),
            TLVValue::U32(a) => self.write_raw_data(a.to_le_bytes()),
            TLVValue::U64(a) => self.write_raw_data(a.to_le_bytes()),
            TLVValue::False => Ok(()),
            TLVValue::True => Ok(()),
            TLVValue::F32(a) => self.write_raw_data(a.to_le_bytes()),
            TLVValue::F64(a) => self.write_raw_data(a.to_le_bytes()),
            TLVValue::Utf8l(a)
            | TLVValue::Utf16l(a)
            | TLVValue::Utf32l(a)
            | TLVValue::Utf64l(a) => self.write_raw_data(a.as_bytes().iter().copied()),
            TLVValue::Str8l(a)
            | TLVValue::Str16l(a)
            | TLVValue::Str32l(a)
            | TLVValue::Str64l(a) => self.write_raw_data(a.iter().copied()),
            TLVValue::Null
            | TLVValue::Struct
            | TLVValue::Array
            | TLVValue::List
            | TLVValue::EndCnt => Ok(()),
        }
    }

    /// Write a tag and a TLV S8 value to the TLV stream.
    fn i8(&mut self, tag: &TLVTag, data: i8) -> Result<(), Error> {
        self.raw_value(tag, TLVValueType::S8, &data.to_le_bytes())
    }

    /// Write a tag and a TLV U8 value to the TLV stream.
    fn u8(&mut self, tag: &TLVTag, data: u8) -> Result<(), Error> {
        self.raw_value(tag, TLVValueType::U8, &data.to_le_bytes())
    }

    /// Write a tag and a TLV S16 or (if the data is small enough) S8 value to the TLV stream.
    fn i16(&mut self, tag: &TLVTag, data: i16) -> Result<(), Error> {
        if data >= i8::MIN as i16 && data <= i8::MAX as i16 {
            self.i8(tag, data as i8)
        } else {
            self.raw_value(tag, TLVValueType::S16, &data.to_le_bytes())
        }
    }

    /// Write a tag and a TLV U16 or (if the data is small enough) U8 value to the TLV stream.
    fn u16(&mut self, tag: &TLVTag, data: u16) -> Result<(), Error> {
        if data <= u8::MAX as u16 {
            self.u8(tag, data as u8)
        } else {
            self.raw_value(tag, TLVValueType::U16, &data.to_le_bytes())
        }
    }

    /// Write a tag and a TLV S32 or (if the data is small enough) S16 or S8 value to the TLV stream.
    fn i32(&mut self, tag: &TLVTag, data: i32) -> Result<(), Error> {
        if data >= i16::MIN as i32 && data <= i16::MAX as i32 {
            self.i16(tag, data as i16)
        } else {
            self.raw_value(tag, TLVValueType::S32, &data.to_le_bytes())
        }
    }

    /// Write a tag and a TLV U32 or (if the data is small enough) U16 or U8 value to the TLV stream.
    fn u32(&mut self, tag: &TLVTag, data: u32) -> Result<(), Error> {
        if data <= u16::MAX as u32 {
            self.u16(tag, data as u16)
        } else {
            self.raw_value(tag, TLVValueType::U32, &data.to_le_bytes())
        }
    }

    /// Write a tag and a TLV S64 or (if the data is small enough) S32, S16, or S8 value to the TLV stream.
    fn i64(&mut self, tag: &TLVTag, data: i64) -> Result<(), Error> {
        if data >= i32::MIN as i64 && data <= i32::MAX as i64 {
            self.i32(tag, data as i32)
        } else {
            self.raw_value(tag, TLVValueType::S64, &data.to_le_bytes())
        }
    }

    /// Write a tag and a TLV U64 or (if the data is small enough) U32, U16, or U8 value to the TLV stream.
    fn u64(&mut self, tag: &TLVTag, data: u64) -> Result<(), Error> {
        if data <= u32::MAX as u64 {
            self.u32(tag, data as u32)
        } else {
            self.raw_value(tag, TLVValueType::U64, &data.to_le_bytes())
        }
    }

    /// Write a tag and a TLV F32 to the TLV stream.
    fn f32(&mut self, tag: &TLVTag, data: f32) -> Result<(), Error> {
        self.raw_value(tag, TLVValueType::F32, &data.to_le_bytes())
    }

    /// Write a tag and a TLV F64 to the TLV stream.
    fn f64(&mut self, tag: &TLVTag, data: f64) -> Result<(), Error> {
        self.raw_value(tag, TLVValueType::F64, &data.to_le_bytes())
    }

    /// Write a tag and a TLV Octet String to the TLV stream, where the Octet String is a slice of u8 bytes.
    ///
    /// The exact octet string type (Str8l, Str16l, Str32l, or Str64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    fn str(&mut self, tag: &TLVTag, data: &[u8]) -> Result<(), Error> {
        self.stri(tag, data.len(), data.iter().copied())
    }

    /// Write a tag and a TLV Octet String to the TLV stream, where the Octet String is
    /// anything that can be turned into an iterator of u8 bytes.
    ///
    /// The exact octet string type (Str8l, Str16l, Str32l, or Str64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    ///
    /// NOTE: The length of the Octet String must be provided by the user and it must match the
    /// number of bytes returned by the provided iterator, or else the generated TLV stream will be invalid.
    fn stri<I>(&mut self, tag: &TLVTag, len: usize, data: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = u8>,
    {
        if len <= u8::MAX as usize {
            self.raw_value(tag, TLVValueType::Str8l, &(len as u8).to_le_bytes())?;
        } else if len <= u16::MAX as usize {
            self.raw_value(tag, TLVValueType::Str16l, &(len as u16).to_le_bytes())?;
        } else if len <= u32::MAX as usize {
            self.raw_value(tag, TLVValueType::Str32l, &(len as u32).to_le_bytes())?;
        } else {
            self.raw_value(tag, TLVValueType::Str64l, &(len as u64).to_le_bytes())?;
        }

        self.write_raw_data(data)
    }

    /// Write a tag and a TLV UTF-8 String to the TLV stream, where the UTF-8 String is a str.
    ///
    /// The exact UTF-8 string type (Utf8l, Utf16l, Utf32l, or Utf64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    fn utf8(&mut self, tag: &TLVTag, data: &str) -> Result<(), Error> {
        self.utf8i(tag, data.len(), data.as_bytes().iter().copied())
    }

    /// Write a tag and a TLV UTF-8 String to the TLV stream, where the UTF-8 String is
    /// anything that can be turned into an iterator of u8 bytes.
    ///
    /// The exact UTF-8 string type (Utf8l, Utf16l, Utf32l, or Utf64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    ///
    /// NOTE 1: The length of the UTF-8 String must be provided by the user and it must match the
    /// number of bytes returned by the provided iterator, or else the generated TLV stream will be invalid.
    ///
    /// NOTE 2: The provided iterator must return valid UTF-8 bytes, or else the generated TLV stream will be invalid.
    fn utf8i<I>(&mut self, tag: &TLVTag, len: usize, data: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = u8>,
    {
        if len <= u8::MAX as usize {
            self.raw_value(tag, TLVValueType::Utf8l, &(len as u8).to_le_bytes())?;
        } else if len <= u16::MAX as usize {
            self.raw_value(tag, TLVValueType::Utf16l, &(len as u16).to_le_bytes())?;
        } else if len <= u32::MAX as usize {
            self.raw_value(tag, TLVValueType::Utf32l, &(len as u32).to_le_bytes())?;
        } else {
            self.raw_value(tag, TLVValueType::Utf64l, &(len as u64).to_le_bytes())?;
        }

        self.write_raw_data(data)
    }

    /// Write a tag and a value indicating the start of a Struct TLV container.
    ///
    /// NOTE: The user must call `end_container` after writing all the Struct fields
    /// to close the Struct container or else the generated TLV stream will be invalid.
    fn start_struct(&mut self, tag: &TLVTag) -> Result<(), Error> {
        self.raw_value(tag, TLVValueType::Struct, &[])
    }

    /// Write a tag and a value indicating the start of an Array TLV container.
    ///
    /// NOTE: The user must call `end_container` after writing all the Array elements
    /// to close the Array container or else the generated TLV stream will be invalid.
    fn start_array(&mut self, tag: &TLVTag) -> Result<(), Error> {
        self.raw_value(tag, TLVValueType::Array, &[])
    }

    /// Write a tag and a value indicating the start of a List TLV container.
    ///
    /// NOTE: The user must call `end_container` after writing all the List elements
    /// to close the List container or else the generated TLV stream will be invalid.
    fn start_list(&mut self, tag: &TLVTag) -> Result<(), Error> {
        self.raw_value(tag, TLVValueType::List, &[])
    }

    /// Write a tag and a value indicating the start of a Struct TLV container.
    ///
    /// NOTE: The user must call `end_container` after writing all the Struct fields
    /// to close the Struct container or else the generated TLV stream will be invalid.
    fn start_container(&mut self, tag: &TLVTag, container_type: TLVValueType) -> Result<(), Error> {
        if !container_type.is_container() {
            Err(ErrorCode::TLVTypeMismatch)?;
        }

        self.raw_value(tag, container_type, &[])
    }

    /// Write a value indicating the end of a Struct, Array, or List TLV container.
    ///
    /// NOTE: This method must be called only when the corresponding container has been opened
    /// using `start_struct`, `start_array`, or `start_list`, or else the generated TLV stream will be invalid.
    fn end_container(&mut self) -> Result<(), Error> {
        self.write(TLVControl::new(TLVTagType::Anonymous, TLVValueType::EndCnt).as_raw())
    }

    /// Write a tag and a TLV Null value to the TLV stream.
    fn null(&mut self, tag: &TLVTag) -> Result<(), Error> {
        self.raw_value(tag, TLVValueType::Null, &[])
    }

    /// Write a tag and a TLV True or False value to the TLV stream.
    fn bool(&mut self, tag: &TLVTag, val: bool) -> Result<(), Error> {
        self.raw_value(
            tag,
            if val {
                TLVValueType::True
            } else {
                TLVValueType::False
            },
            &[],
        )
    }

    /// Write a tag and a raw, already-encoded TLV value represented as a byte slice.
    fn raw_value(
        &mut self,
        tag: &TLVTag,
        value_type: TLVValueType,
        value_payload: &[u8],
    ) -> Result<(), Error> {
        self.write(TLVControl::new(tag.tag_type(), value_type).as_raw())?;

        match tag {
            TLVTag::Anonymous => Ok(()),
            TLVTag::Context(v) => self.write_raw_data(v.to_le_bytes()),
            TLVTag::CommonPrf16(v) | TLVTag::ImplPrf16(v) => self.write_raw_data(v.to_le_bytes()),
            TLVTag::CommonPrf32(v) | TLVTag::ImplPrf32(v) => self.write_raw_data(v.to_le_bytes()),
            TLVTag::FullQual48 {
                vendor_id,
                profile,
                tag,
            } => {
                self.write_raw_data(vendor_id.to_le_bytes())?;
                self.write_raw_data(profile.to_le_bytes())?;
                self.write_raw_data(tag.to_le_bytes())
            }
            TLVTag::FullQual64 {
                vendor_id,
                profile,
                tag,
            } => {
                self.write_raw_data(vendor_id.to_le_bytes())?;
                self.write_raw_data(profile.to_le_bytes())?;
                self.write_raw_data(tag.to_le_bytes())
            }
        }?;

        self.write_raw_data(value_payload.iter().copied())
    }

    /// Append multiple raw bytes to the TLV stream.
    fn write_raw_data<I>(&mut self, bytes: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = u8>,
    {
        for byte in bytes {
            self.write(byte)?;
        }

        Ok(())
    }

    fn write(&mut self, byte: u8) -> Result<(), Error>;

    fn get_tail(&self) -> Self::Position;

    fn rewind_to(&mut self, _pos: Self::Position);
}

impl<T> TLVWrite for &mut T
where
    T: TLVWrite,
{
    type Position = T::Position;

    fn write(&mut self, byte: u8) -> Result<(), Error> {
        (**self).write(byte)
    }

    fn get_tail(&self) -> Self::Position {
        (**self).get_tail()
    }

    fn rewind_to(&mut self, pos: Self::Position) {
        (**self).rewind_to(pos)
    }
}

impl TLVWrite for WriteBuf<'_> {
    type Position = usize;

    fn write(&mut self, byte: u8) -> Result<(), Error> {
        WriteBuf::append(self, &[byte])
    }

    fn get_tail(&self) -> Self::Position {
        WriteBuf::get_tail(self)
    }

    fn rewind_to(&mut self, pos: Self::Position) {
        WriteBuf::rewind_tail_to(self, pos)
    }
}

impl WriteBuf<'_> {
    /// Write a tag and a TLV Octet String to the TLV stream, where the Octet String is a slice of u8 bytes.
    ///
    /// The writing is done via a user-supplied callback `cb`, that is expected to fill the provided buffer with the data
    /// and to return the length of the written data.
    ///
    /// This method is useful when the data to be written needs to be computed first, and the computation needs a buffer where
    /// to operate.
    ///
    /// Note that this method always uses a Str16l value type to write the data, which restricts the data length to no more than
    /// 65535 bytes.
    pub fn str_cb(
        &mut self,
        tag: &TLVTag,
        cb: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<(), Error> {
        self.raw_value(tag, TLVValueType::Str16l, &0_u16.to_le_bytes())?;

        let value_offset = self.get_tail();

        let len = self.append_with_buf(cb)?;

        self.buf[value_offset - 2..value_offset].copy_from_slice(&(len as u16).to_le_bytes());

        Ok(())
    }

    /// Write a tag and a TLV UTF-8 String to the TLV stream, where the UTF-8 String is a str.
    ///
    /// The writing is done via a user-supplied callback `cb`, that is expected to fill the provided buffer with the data
    /// and to return the length of the written data.
    ///
    /// This method is useful when the data to be written needs to be computed first, and the computation needs a buffer where
    /// to operate.
    ///
    /// Note that this method always uses a Utf16l value type to write the data, which restricts the data length to no more than
    /// 65535 bytes.
    pub fn utf8_cb(
        &mut self,
        tag: &TLVTag,
        cb: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<(), Error> {
        self.raw_value(tag, TLVValueType::Utf16l, &0_u16.to_le_bytes())?;

        let value_offset = self.get_tail();

        let len = self.append_with_buf(cb)?;

        self.buf[value_offset - 2..value_offset].copy_from_slice(&(len as u16).to_le_bytes());

        Ok(())
    }
}

/// A TLVWrite implementation that counts the number of bytes written.
impl TLVWrite for usize {
    type Position = usize;

    fn write(&mut self, _byte: u8) -> Result<(), Error> {
        *self += 1;

        Ok(())
    }

    fn get_tail(&self) -> Self::Position {
        *self
    }

    fn rewind_to(&mut self, pos: Self::Position) {
        *self = pos;
    }
}

#[cfg(test)]
mod tests {
    use core::f32;

    use super::{TLVTag, TLVWrite};
    use crate::{tlv::TLVValue, utils::storage::WriteBuf};

    #[test]
    fn test_write_success() {
        let mut buf = [0; 20];
        let mut tw = WriteBuf::new(&mut buf);

        tw.start_struct(&TLVTag::Anonymous).unwrap();
        tw.u8(&TLVTag::Anonymous, 12).unwrap();
        tw.u8(&TLVTag::Context(1), 13).unwrap();
        tw.u16(&TLVTag::Anonymous, 0x1212).unwrap();
        tw.u16(&TLVTag::Context(2), 0x1313).unwrap();
        tw.start_array(&TLVTag::Context(3)).unwrap();
        tw.bool(&TLVTag::Anonymous, true).unwrap();
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
        let mut tw = WriteBuf::new(&mut buf);

        tw.u8(&TLVTag::Anonymous, 12).unwrap();
        tw.u8(&TLVTag::Context(1), 13).unwrap();
        if tw.u16(&TLVTag::Anonymous, 12).is_ok() {
            panic!("This should have returned error")
        }
        if tw.u16(&TLVTag::Context(2), 13).is_ok() {
            panic!("This should have returned error")
        }
        assert_eq!(buf, [4, 12, 36, 1, 13, 4]);
    }

    #[test]
    fn test_put_str8() {
        let mut buf = [0; 20];
        let mut tw = WriteBuf::new(&mut buf);

        tw.u8(&TLVTag::Context(1), 13).unwrap();
        tw.str(&TLVTag::Anonymous, &[10, 11, 12, 13, 14]).unwrap();
        tw.u16(&TLVTag::Context(2), 0x1313).unwrap();
        tw.str(&TLVTag::Context(3), &[20, 21, 22]).unwrap();
        assert_eq!(
            buf,
            [36, 1, 13, 16, 5, 10, 11, 12, 13, 14, 37, 2, 0x13, 0x13, 48, 3, 3, 20, 21, 22]
        );
    }

    #[test]
    fn test_matter_spec_examples() {
        let mut buf = [0; 200];
        let mut tw = WriteBuf::new(&mut buf);

        // Boolean false

        tw.bool(&TLVTag::Anonymous, false).unwrap();
        assert_eq!(&[0x08], tw.as_slice());

        // Boolean true

        tw.reset();
        tw.bool(&TLVTag::Anonymous, true).unwrap();
        assert_eq!(&[0x09], tw.as_slice());

        // Signed Integer, 1-octet, value 42

        tw.reset();
        tw.i8(&TLVTag::Anonymous, 42).unwrap();
        assert_eq!(&[0x00, 0x2a], tw.as_slice());

        // Signed Integer, 1-octet, value -17

        tw.reset();
        tw.i32(&TLVTag::Anonymous, -17).unwrap();
        assert_eq!(&[0x00, 0xef], tw.as_slice());

        // Unsigned Integer, 1-octet, value 42U

        tw.reset();
        tw.u8(&TLVTag::Anonymous, 42).unwrap();
        assert_eq!(&[0x04, 0x2a], tw.as_slice());

        // Signed Integer, 2-octet, value 422

        tw.reset();
        tw.i16(&TLVTag::Anonymous, 422).unwrap();
        assert_eq!(&[0x01, 0xa6, 0x01], tw.as_slice());

        // Signed Integer, 4-octet, value -170000

        tw.reset();
        tw.i32(&TLVTag::Anonymous, -170000).unwrap();
        assert_eq!(&[0x02, 0xf0, 0x67, 0xfd, 0xff], tw.as_slice());

        // Signed Integer, 8-octet, value 40000000000

        tw.reset();
        tw.i64(&TLVTag::Anonymous, 40000000000).unwrap();
        assert_eq!(
            &[0x03, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00],
            tw.as_slice()
        );

        // UTF-8 String, 1-octet length, "Hello!"

        tw.reset();
        tw.utf8(&TLVTag::Anonymous, "Hello!").unwrap();
        assert_eq!(
            &[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21],
            tw.as_slice()
        );

        // UTF-8 String, 1-octet length, "Tschüs"

        tw.reset();
        tw.utf8i(
            &TLVTag::Anonymous,
            "Tschüs".len(),
            "Tschüs".as_bytes().iter().copied(),
        )
        .unwrap();
        assert_eq!(
            &[0x0c, 0x07, 0x54, 0x73, 0x63, 0x68, 0xc3, 0xbc, 0x73],
            tw.as_slice()
        );

        // Octet String, 1-octet length, octets 00 01 02 03 04

        tw.reset();
        tw.str(&TLVTag::Anonymous, &[0x00, 0x01, 0x02, 0x03, 0x04])
            .unwrap();
        assert_eq!(&[0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04], tw.as_slice());

        // Null

        tw.reset();
        tw.tlv(&TLVTag::Anonymous, &TLVValue::Null).unwrap();
        assert_eq!(&[0x14], tw.as_slice());

        // Single precision floating point 0.0

        tw.reset();
        tw.tlv(&TLVTag::Anonymous, &TLVValue::F32(0.0)).unwrap();
        assert_eq!(&[0x0a, 0x00, 0x00, 0x00, 0x00], tw.as_slice());

        // Single precision floating point (1.0 / 3.0)

        tw.reset();
        tw.f32(&TLVTag::Anonymous, 1.0 / 3.0).unwrap();
        assert_eq!(&[0x0a, 0xab, 0xaa, 0xaa, 0x3e], tw.as_slice());

        // Single precision floating point 17.9

        tw.reset();
        tw.f32(&TLVTag::Anonymous, 17.9).unwrap();
        assert_eq!(&[0x0a, 0x33, 0x33, 0x8f, 0x41], tw.as_slice());

        // Single precision floating point infinity

        tw.reset();
        tw.f32(&TLVTag::Anonymous, f32::INFINITY).unwrap();
        assert_eq!(&[0x0a, 0x00, 0x00, 0x80, 0x7f], tw.as_slice());

        // Single precision floating point negative infinity

        tw.reset();
        tw.f32(&TLVTag::Anonymous, f32::NEG_INFINITY).unwrap();
        assert_eq!(&[0x0a, 0x00, 0x00, 0x80, 0xff], tw.as_slice());

        // Double precision floating point 0.0

        tw.reset();
        tw.f64(&TLVTag::Anonymous, 0.0).unwrap();
        assert_eq!(
            &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            tw.as_slice()
        );

        // Double precision floating point (1.0 / 3.0)

        tw.reset();
        tw.f64(&TLVTag::Anonymous, 1.0 / 3.0).unwrap();
        assert_eq!(
            &[0x0b, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xd5, 0x3f],
            tw.as_slice()
        );

        // Double precision floating point 17.9

        tw.reset();
        tw.f64(&TLVTag::Anonymous, 17.9).unwrap();
        assert_eq!(
            &[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40],
            tw.as_slice()
        );

        // Double precision floating point infinity (∞)

        tw.reset();
        tw.f64(&TLVTag::Anonymous, f64::INFINITY).unwrap();
        assert_eq!(
            &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f],
            tw.as_slice()
        );

        // Double precision floating point negative infinity

        tw.reset();
        tw.f64(&TLVTag::Anonymous, f64::NEG_INFINITY).unwrap();
        assert_eq!(
            &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff],
            tw.as_slice()
        );

        // Empty Structure, {}

        tw.reset();
        tw.start_struct(&TLVTag::Anonymous).unwrap();
        tw.end_container().unwrap();
        assert_eq!(&[0x15, 0x18], tw.as_slice());

        // Empty Array, []

        tw.reset();
        tw.start_array(&TLVTag::Anonymous).unwrap();
        tw.end_container().unwrap();
        assert_eq!(&[0x16, 0x18], tw.as_slice());

        // Empty List, []

        tw.reset();
        tw.start_list(&TLVTag::Anonymous).unwrap();
        tw.end_container().unwrap();
        assert_eq!(&[0x17, 0x18], tw.as_slice());

        // Structure, two context specific tags, Signed Integer, 1 octet values, {0 = 42, 1 = -17}

        tw.reset();
        tw.start_struct(&TLVTag::Anonymous).unwrap();
        tw.i8(&TLVTag::Context(0), 42).unwrap();
        tw.i32(&TLVTag::Context(1), -17).unwrap();
        tw.end_container().unwrap();
        assert_eq!(
            &[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18],
            tw.as_slice()
        );

        // Array, Signed Integer, 1-octet values, [0, 1, 2, 3, 4]

        tw.reset();
        tw.start_array(&TLVTag::Anonymous).unwrap();
        for i in 0..5 {
            tw.i8(&TLVTag::Anonymous, i as i8).unwrap();
        }
        tw.end_container().unwrap();
        assert_eq!(
            &[0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x18],
            tw.as_slice()
        );

        // List, mix of anonymous and context tags, Signed Integer, 1 octet values, [[1, 0 = 42, 2, 3, 0 = -17]]

        tw.reset();
        tw.start_list(&TLVTag::Anonymous).unwrap();
        tw.i64(&TLVTag::Anonymous, 1).unwrap();
        tw.i16(&TLVTag::Context(0), 42).unwrap();
        tw.i8(&TLVTag::Anonymous, 2).unwrap();
        tw.i8(&TLVTag::Anonymous, 3).unwrap();
        tw.i32(&TLVTag::Context(0), -17).unwrap();
        tw.end_container().unwrap();
        assert_eq!(
            &[0x17, 0x00, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x02, 0x00, 0x03, 0x20, 0x00, 0xef, 0x18],
            tw.as_slice()
        );

        // Array, mix of element types, [42, -170000, {}, 17.9, "Hello!"]

        tw.reset();
        tw.start_array(&TLVTag::Anonymous).unwrap();
        tw.i64(&TLVTag::Anonymous, 42).unwrap();
        tw.i64(&TLVTag::Anonymous, -170000).unwrap();
        tw.start_struct(&TLVTag::Anonymous).unwrap();
        tw.end_container().unwrap();
        tw.f32(&TLVTag::Anonymous, 17.9).unwrap();
        tw.utf8(&TLVTag::Anonymous, "Hello!").unwrap();
        tw.end_container().unwrap();
        assert_eq!(
            &[
                0x16, 0x00, 0x2a, 0x02, 0xf0, 0x67, 0xfd, 0xff, 0x15, 0x18, 0x0a, 0x33, 0x33, 0x8f,
                0x41, 0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x18,
            ],
            tw.as_slice()
        );

        // Anonymous tag, Unsigned Integer, 1-octet value, 42U

        tw.reset();
        tw.u64(&TLVTag::Anonymous, 42).unwrap();
        assert_eq!(&[0x04, 0x2a], tw.as_slice());

        // Context tag 1, Unsigned Integer, 1-octet value, 1 = 42U

        tw.reset();
        tw.u64(&TLVTag::Context(1), 42).unwrap();
        assert_eq!(&[0x24, 0x01, 0x2a], tw.as_slice());

        // Common profile tag 1, Unsigned Integer, 1-octet value, Matter::1 = 42U

        tw.reset();
        tw.u64(&TLVTag::CommonPrf16(1), 42).unwrap();
        assert_eq!(&[0x44, 0x01, 0x00, 0x2a], tw.as_slice());

        // Common profile tag 100000, Unsigned Integer, 1-octet value, Matter::100000 = 42U

        tw.reset();
        tw.u64(&TLVTag::CommonPrf32(100000), 42).unwrap();
        assert_eq!(&[0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a], tw.as_slice());

        // Fully qualified tag, Vendor ID 0xFFF1/65521, pro­file number 0xDEED/57069,
        // 2-octet tag 1, Unsigned Integer, 1-octet value 42, 65521::57069:1 = 42U

        tw.reset();
        tw.u64(
            &TLVTag::FullQual48 {
                vendor_id: 65521,
                profile: 57069,
                tag: 1,
            },
            42,
        )
        .unwrap();
        assert_eq!(
            &[0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a],
            tw.as_slice()
        );

        // Fully qualified tag, Vendor ID 0xFFF1/65521, pro­file number 0xDEED/57069,
        // 4-octet tag 0xAA55FEED/2857762541, Unsigned Integer, 1-octet value 42, 65521::57069:2857762541 = 42U

        tw.reset();
        tw.u64(
            &TLVTag::FullQual64 {
                vendor_id: 65521,
                profile: 57069,
                tag: 2857762541,
            },
            42,
        )
        .unwrap();
        assert_eq!(
            &[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a],
            tw.as_slice()
        );

        // Structure with the fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 2-octet tag 1. The structure contains a single ele­ment labeled using a fully qualified tag under
        // the same profile, with 2-octet tag 0xAA55/43605. 65521::57069:1 = {65521::57069:43605 = 42U}

        tw.reset();
        tw.start_struct(&TLVTag::FullQual48 {
            vendor_id: 65521,
            profile: 57069,
            tag: 1,
        })
        .unwrap();
        tw.u64(
            &TLVTag::FullQual48 {
                vendor_id: 65521,
                profile: 57069,
                tag: 43605,
            },
            42,
        )
        .unwrap();
        tw.end_container().unwrap();
        assert_eq!(
            &[
                0xd5, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0xc4, 0xf1, 0xff, 0xed, 0xde, 0x55, 0xaa,
                0x2a, 0x18,
            ],
            tw.as_slice()
        );
    }
}
