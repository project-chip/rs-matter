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

use core::borrow::Borrow;
use core::fmt;
use core::iter::Once;
use core::marker::PhantomData;

use num::FromPrimitive;
use num_traits::ToBytes;

use crate::error::{Error, ErrorCode};

pub use rs_matter_macros::{FromTLV, ToTLV};

pub use read::*;
pub use toiter::*;
pub use traits::*;
pub use write::*;

mod read;
mod toiter;
mod traits;
mod write;

/// Represents the TLV tag type encoded in the control byte of each TLV element.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, num_derive::FromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TLVTagType {
    Anonymous = 0,
    Context = 1,
    CommonPrf16 = 2,
    CommonPrf32 = 3,
    ImplPrf16 = 4,
    ImplPrf32 = 5,
    FullQual48 = 6,
    FullQual64 = 7,
}

impl TLVTagType {
    /// Return the size of the tag data following the control byte
    /// in the TLV element representation.
    pub const fn size(&self) -> usize {
        match self {
            Self::Anonymous => 0,
            Self::Context => 1,
            Self::CommonPrf16 => 2,
            Self::CommonPrf32 => 4,
            Self::ImplPrf16 => 2,
            Self::ImplPrf32 => 4,
            Self::FullQual48 => 6,
            Self::FullQual64 => 8,
        }
    }
}

impl fmt::Display for TLVTagType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => write!(f, "Anonymous"),
            Self::Context => write!(f, "Context"),
            Self::CommonPrf16 => write!(f, "CommonPrf16"),
            Self::CommonPrf32 => write!(f, "CommonPrf32"),
            Self::ImplPrf16 => write!(f, "ImplPrf16"),
            Self::ImplPrf32 => write!(f, "ImplPrf32"),
            Self::FullQual48 => write!(f, "FullQual48"),
            Self::FullQual64 => write!(f, "FullQual64"),
        }
    }
}

/// Represents the TLV value type encoded in the control byte of each TLV element.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, num_derive::FromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TLVValueType {
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
}

impl TLVValueType {
    /// Return the size of the value corresponding to this value type.
    ///
    /// If the value type has a variable size (i.e. octet and Utf8 strings), this function returns `None`.
    pub const fn fixed_size(&self) -> Option<usize> {
        match self {
            Self::S8 => Some(1),
            Self::S16 => Some(2),
            Self::S32 => Some(4),
            Self::S64 => Some(8),
            Self::U8 => Some(1),
            Self::U16 => Some(2),
            Self::U32 => Some(4),
            Self::U64 => Some(8),
            Self::F32 => Some(4),
            Self::F64 => Some(8),
            Self::Utf8l
            | Self::Utf16l
            | Self::Utf32l
            | Self::Utf64l
            | Self::Str8l
            | Self::Str16l
            | Self::Str32l
            | Self::Str64l => None,
            _ => Some(0),
        }
    }

    /// Return the size of the length field for variable size value types.
    ///
    /// if the value type has a fixed size, this function returns 0.
    /// Variable size types are only octet strings and utf8 strings.
    pub const fn variable_size_len(&self) -> usize {
        match self {
            Self::Utf8l | Self::Str8l => 1,
            Self::Utf16l | Self::Str16l => 2,
            Self::Utf32l | Self::Str32l => 4,
            Self::Utf64l | Self::Str64l => 8,
            _ => 0,
        }
    }

    /// Convenience method to check if the value type is a container type
    /// (container start or end).
    pub const fn is_container(&self) -> bool {
        self.is_container_start() || self.is_container_end()
    }

    /// Convenience method to check if the value type is a container start type.
    pub const fn is_container_start(&self) -> bool {
        matches!(self, Self::Struct | Self::Array | Self::List)
    }

    /// Convenience method to check if the value type is a container end type.
    pub const fn is_container_end(&self) -> bool {
        matches!(self, Self::EndCnt)
    }

    /// Convenience method to check if the value type is an Octet String type.
    pub const fn is_str(&self) -> bool {
        matches!(
            self,
            Self::Str8l | Self::Str16l | Self::Str32l | Self::Str64l
        )
    }

    /// Convenience method to check if the value type is a UTF-8 String type.
    pub const fn is_utf8(&self) -> bool {
        matches!(
            self,
            Self::Utf8l | Self::Utf16l | Self::Utf32l | Self::Utf64l
        )
    }

    pub fn container_value<'a>(&self) -> Result<TLVValue<'a>, Error> {
        Ok(match self {
            Self::Struct => TLVValue::Struct,
            Self::Array => TLVValue::Array,
            Self::List => TLVValue::List,
            Self::EndCnt => TLVValue::EndCnt,
            _ => Err(ErrorCode::TLVTypeMismatch)?,
        })
    }
}

impl fmt::Display for TLVValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::S8 => write!(f, "S8"),
            Self::S16 => write!(f, "S16"),
            Self::S32 => write!(f, "S32"),
            Self::S64 => write!(f, "S64"),
            Self::U8 => write!(f, "U8"),
            Self::U16 => write!(f, "U16"),
            Self::U32 => write!(f, "U32"),
            Self::U64 => write!(f, "U64"),
            Self::False => write!(f, "False"),
            Self::True => write!(f, "True"),
            Self::F32 => write!(f, "F32"),
            Self::F64 => write!(f, "F64"),
            Self::Utf8l => write!(f, "Utf8l"),
            Self::Utf16l => write!(f, "Utf16l"),
            Self::Utf32l => write!(f, "Utf32l"),
            Self::Utf64l => write!(f, "Utf64l"),
            Self::Str8l => write!(f, "Str8l"),
            Self::Str16l => write!(f, "Str16l"),
            Self::Str32l => write!(f, "Str32l"),
            Self::Str64l => write!(f, "Str64l"),
            Self::Null => write!(f, "Null"),
            Self::Struct => write!(f, "Struct"),
            Self::Array => write!(f, "Array"),
            Self::List => write!(f, "List"),
            Self::EndCnt => write!(f, "EndCnt"),
        }
    }
}

/// Represents the control byte of a TLV element (i.e. the tag type and the value type).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TLVControl {
    pub tag_type: TLVTagType,
    pub value_type: TLVValueType,
}

impl TLVControl {
    const TAG_SHIFT_BITS: u8 = 5;
    const TAG_MASK: u8 = 0xe0;
    const TYPE_MASK: u8 = 0x1f;

    /// Create a new TLV control byte by parsing the provided tag type and value type.
    #[inline(always)]
    pub const fn new(tag_type: TLVTagType, value_type: TLVValueType) -> Self {
        Self {
            tag_type,
            value_type,
        }
    }

    /// Create a new TLV control byte by parsing the provided control byte
    /// into a tag type and a value type.
    ///
    /// The function will return an error if the provided control byte is invalid.
    #[inline(always)]
    pub fn parse(control: u8) -> Result<Self, Error> {
        let tag_type = FromPrimitive::from_u8((control & Self::TAG_MASK) >> Self::TAG_SHIFT_BITS)
            .ok_or(ErrorCode::TLVTypeMismatch)?;
        let value_type =
            FromPrimitive::from_u8(control & Self::TYPE_MASK).ok_or(ErrorCode::TLVTypeMismatch)?;

        Ok(Self::new(tag_type, value_type))
    }

    /// Return the raw control byte.
    #[inline(always)]
    pub const fn as_raw(&self) -> u8 {
        ((self.tag_type as u8) << Self::TAG_SHIFT_BITS) | (self.value_type as u8)
    }

    /// Return `true` if the control byte represents a container start (struct, array or list).
    #[inline(always)]
    pub fn is_container_start(&self) -> bool {
        self.value_type.is_container_start()
    }

    /// Return `true` if the control byte represents a container end.
    #[inline(always)]
    pub fn is_container_end(&self) -> bool {
        matches!(self.tag_type, TLVTagType::Anonymous) && self.value_type.is_container_end()
    }

    /// Return an error if the control byte does not represent a container start.
    #[inline(always)]
    pub fn confirm_container_end(&self) -> Result<(), Error> {
        if !self.is_container_end() {
            return Err(ErrorCode::InvalidData.into());
        }

        Ok(())
    }
}

impl fmt::Display for TLVControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Control({} {})", self.tag_type, self.value_type)
    }
}

/// A high-level representation of a TLV tag + value.
///
/// Amongsat other things, it is a convenient way to emit TLV byte sequences.
///
/// A `TLV` can be constructed programmatically, or returned from a `TLVElement`.
///
/// Unlike a `TLVElement` however, a `TLV` does not represent a complete container,
/// but rather, its beginning or end.
///
/// I.e.
/// ```ignore
/// use rs_matter::tlv::{TLV, TLVTag, TLVValue};
///
/// let tlvs = &[
///     TLV::new(TLVTag::Anonymous, TLVValue::Struct),
///     TLV::new(TLVTag::Context(0), TLVValue::Utf8l("Hello, World!")),
///     TLV::new(TLVTag::Anonymous, TLVValue::EndCnt),
/// ];
///
/// let bytes_iter = tlvs.iter().flat_map(|tlv| tlv.bytes_iter());
/// for byte in bytes_iter {
///    println!("{:02X}", byte);
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TLV<'a> {
    pub tag: TLVTag,
    pub value: TLVValue<'a>,
}

impl<'a> TLV<'a> {
    /// Create a new TLV instance with the provided tag and value.
    pub const fn new(tag: TLVTag, value: TLVValue<'a>) -> Self {
        Self { tag, value }
    }

    /// Create a TLV with the given tag and the provided value as an S8 TLV.
    pub const fn i8(tag: TLVTag, value: i8) -> Self {
        Self::new(tag, TLVValue::i8(value))
    }

    /// Create a TLV with the given tag and the provided value as an S8 or S16 TLV,
    /// depending on whether the value is small enough to fit in an S8 TLV.
    pub const fn i16(tag: TLVTag, value: i16) -> Self {
        Self::new(tag, TLVValue::i16(value))
    }

    /// Create a TLV with the given tag and the provided value as an S8, S16, or S32 TLV,
    /// depending on whether the value is small enough to fit in an S8 or S16 TLV.
    pub const fn i32(tag: TLVTag, value: i32) -> Self {
        Self::new(tag, TLVValue::i32(value))
    }

    /// Create a TLV with the given tag and the provided value as an S8, S16, S32, or S64 TLV,
    /// depending on whether the value is small enough to fit in an S8, S16, or S32 TLV.
    pub const fn i64(tag: TLVTag, value: i64) -> Self {
        Self::new(tag, TLVValue::i64(value))
    }

    /// Create a TLV with the given tag and the provided value as a U8 TLV.
    pub const fn u8(tag: TLVTag, value: u8) -> Self {
        Self::new(tag, TLVValue::u8(value))
    }

    /// Create a TLV with the given tag and the provided value as a U8 or U16 TLV,
    /// depending on whether the value is small enough to fit in a U8 TLV.
    pub const fn u16(tag: TLVTag, value: u16) -> Self {
        Self::new(tag, TLVValue::u16(value))
    }

    /// Create a TLV with the given tag and the provided value as a U8, U16, or U32 TLV,
    /// depending on whether the value is small enough to fit in a U8 or U16 TLV.
    pub const fn u32(tag: TLVTag, value: u32) -> Self {
        Self::new(tag, TLVValue::u32(value))
    }

    /// Create a TLV with the given tag and the provided value as a U8, U16, U32, or U64 TLV,
    /// depending on whether the value is small enough to fit in a U8, U16, or U32 TLV.
    pub const fn u64(tag: TLVTag, value: u64) -> Self {
        Self::new(tag, TLVValue::u64(value))
    }

    /// Create a TLV with the given tag and the provided value as a F32 TLV.
    pub const fn f32(tag: TLVTag, value: f32) -> Self {
        Self::new(tag, TLVValue::f32(value))
    }

    /// Create a TLV with the given tag and the provided value as a F64 TLV.
    pub const fn f64(tag: TLVTag, value: f64) -> Self {
        Self::new(tag, TLVValue::f64(value))
    }

    /// Create a TLV with the given tag and the provided value as a UTF-8 TLV.
    /// The length of the string is encoded as 1, 2, 4 or 8 octets,
    /// depending on the length of the string.
    pub const fn utf8(tag: TLVTag, value: &'a str) -> Self {
        Self::new(tag, TLVValue::utf8(value))
    }

    /// Create a TLV with the given tag and the provided value as an octet string TLV.
    /// The length of the string is encoded as 1, 2, 4 or 8 octets,
    /// depending on the length of the string.
    pub const fn str(tag: TLVTag, value: &'a [u8]) -> Self {
        Self::new(tag, TLVValue::str(value))
    }

    /// Create a TLV with the given tag which will have a value of type Struct (start).
    pub const fn r#struct(tag: TLVTag) -> Self {
        Self::new(tag, TLVValue::r#struct())
    }

    /// Create a TLV with the given tag which will have a value of type Struct (start).
    pub const fn structure(tag: TLVTag) -> Self {
        Self::new(tag, TLVValue::structure())
    }

    /// Create a TLV with the given tag which will have a value of type Array (start).
    pub const fn array(tag: TLVTag) -> Self {
        Self::new(tag, TLVValue::array())
    }

    /// Create a TLV with the given tag which will have a value of type List (start).
    pub const fn list(tag: TLVTag) -> Self {
        Self::new(tag, TLVValue::list())
    }

    /// Create a TLV with the given tag which will have a value of type EndCnt (container end).
    pub const fn end_container() -> Self {
        Self::new(TLVTag::Anonymous, TLVValue::end_container())
    }

    /// Create a TLV with the given tag which will have a value of type Null.
    pub const fn null(tag: TLVTag) -> Self {
        Self::new(tag, TLVValue::null())
    }

    /// Create a TLV with the given tag which will have a value of type True.
    pub const fn bool(tag: TLVTag, value: bool) -> Self {
        Self::new(tag, TLVValue::bool(value))
    }

    /// Converts the TLV into an iterator with a single item - the TLV.
    pub fn into_tlv_iter(self) -> OnceTLVIter<'a> {
        core::iter::once(Ok(self))
    }

    /// Returns an iterator over the bytes of the TLV.
    pub fn bytes_iter(&self) -> TLVBytesIter<'a, &TLVTag, &TLVValue<'a>> {
        TLVBytesIter {
            control: core::iter::once(
                TLVControl::new(self.tag.tag_type(), self.value.value_type()).as_raw(),
            ),
            tag: self.tag.iter(),
            value: self.value.iter(),
        }
    }

    /// Converts the TLV into an iterator over its bytes.
    pub fn into_bytes_iter(self) -> TLVBytesIter<'a, TLVTag, TLVValue<'a>> {
        TLVBytesIter {
            control: core::iter::once(
                TLVControl::new(self.tag.tag_type(), self.value.value_type()).as_raw(),
            ),
            tag: self.tag.into_iterator(),
            value: self.value.into_iterator(),
        }
    }

    /// Converts the provided result into an iterator over the bytes of the TLV.
    pub fn result_into_bytes_iter(
        result: Result<Self, Error>,
    ) -> TLVResultBytesIter<'a, TLVTag, TLVValue<'a>> {
        TLVResultBytesIter::new(result)
    }
}

impl<'a> IntoIterator for TLV<'a> {
    type Item = u8;
    type IntoIter = TLVBytesIter<'a, TLVTag, TLVValue<'a>>;

    fn into_iter(self) -> Self::IntoIter {
        TLV::into_bytes_iter(self)
    }
}

impl<'s, 'a> IntoIterator for &'s TLV<'a> {
    type Item = u8;
    type IntoIter = TLVBytesIter<'a, &'s TLVTag, &'s TLVValue<'a>>;

    fn into_iter(self) -> Self::IntoIter {
        TLV::bytes_iter(self)
    }
}

/// An iterator over the bytes of a TLV that might return an error.
pub enum TLVResultBytesIter<'a, T, V>
where
    T: Borrow<TLVTag>,
    V: Borrow<TLVValue<'a>>,
{
    Ok(TLVBytesIter<'a, T, V>),
    Err(core::iter::Once<Result<u8, Error>>),
}

impl<'a> TLVResultBytesIter<'a, TLVTag, TLVValue<'a>> {
    pub fn new(result: Result<TLV<'a>, Error>) -> Self {
        match result {
            Ok(tlv) => Self::Ok(tlv.into_bytes_iter()),
            Err(err) => Self::Err(core::iter::once(Err(err))),
        }
    }
}

impl<'a, T, V> Iterator for TLVResultBytesIter<'a, T, V>
where
    T: Borrow<TLVTag>,
    V: Borrow<TLVValue<'a>>,
{
    type Item = Result<u8, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Ok(iter) => iter.next().map(Ok),
            Self::Err(iter) => iter.next(),
        }
    }
}

/// An iterator over the bytes of a TLV.
pub struct TLVBytesIter<'a, T, V>
where
    T: Borrow<TLVTag>,
    V: Borrow<TLVValue<'a>>,
{
    control: Once<u8>,
    tag: TLVTagIter<T>,
    value: TLVValueIter<'a, V>,
}

impl<'a, T, V> Iterator for TLVBytesIter<'a, T, V>
where
    T: Borrow<TLVTag>,
    V: Borrow<TLVValue<'a>>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.control
            .next()
            .or_else(|| self.tag.next())
            .or_else(|| self.value.next())
    }
}

/// The iterator type for a TLV that returns the TLV itself.
pub type OnceTLVIter<'s> = core::iter::Once<Result<TLV<'s>, Error>>;

/// For backwards compatibility
pub type TagType = TLVTag;

/// A high-level representation of a TLV tag (tag type and tag value).
///
/// A `TLVTag` can be constructed programmatically, or returned from a `TLVElement`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TLVTag {
    Anonymous,
    Context(u8),
    CommonPrf16(u16),
    CommonPrf32(u32),
    ImplPrf16(u16),
    ImplPrf32(u32),
    FullQual48 {
        vendor_id: u16,
        profile: u16,
        tag: u16,
    },
    FullQual64 {
        vendor_id: u16,
        profile: u16,
        tag: u32,
    },
}

impl TLVTag {
    /// Return the tag type of the TLV tag.
    pub const fn tag_type(&self) -> TLVTagType {
        match self {
            Self::Anonymous => TLVTagType::Anonymous,
            Self::Context(_) => TLVTagType::Context,
            Self::CommonPrf16(_) => TLVTagType::CommonPrf16,
            Self::CommonPrf32(_) => TLVTagType::CommonPrf32,
            Self::ImplPrf16(_) => TLVTagType::ImplPrf16,
            Self::ImplPrf32(_) => TLVTagType::ImplPrf32,
            Self::FullQual48 { .. } => TLVTagType::FullQual48,
            Self::FullQual64 { .. } => TLVTagType::FullQual64,
        }
    }

    /// Return an iterator over the bytes of the TLV tag.
    pub fn iter(&self) -> TLVTagIter<&Self> {
        TLVTagIter {
            value: self,
            index: 0,
        }
    }

    /// Converts itself into an iterator over the bytes of the TLV tag.
    pub fn into_iterator(self) -> TLVTagIter<Self> {
        TLVTagIter {
            value: self,
            index: 0,
        }
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TLVTag::Anonymous => Ok(()),
            TLVTag::Context(tag) => write!(f, "{tag}"),
            TLVTag::CommonPrf16(tag) => write!(f, "CommonPrf16({tag})"),
            TLVTag::CommonPrf32(tag) => write!(f, "CommonPrf32({tag})"),
            TLVTag::ImplPrf16(tag) => write!(f, "ImplPrf16({tag})"),
            TLVTag::ImplPrf32(tag) => write!(f, "ImplPrf32({tag})"),
            TLVTag::FullQual48 {
                vendor_id,
                profile,
                tag,
            } => write!(f, "FullQual48(VID:{vendor_id} PRF:{profile} {tag})"),
            TLVTag::FullQual64 {
                vendor_id,
                profile,
                tag,
            } => write!(f, "FullQual64(VID:{vendor_id} PRF:{profile} {tag})"),
        }
    }
}

impl IntoIterator for TLVTag {
    type Item = u8;
    type IntoIter = TLVTagIter<Self>;

    fn into_iter(self) -> Self::IntoIter {
        TLVTag::into_iterator(self)
    }
}

impl IntoIterator for &TLVTag {
    type Item = u8;
    type IntoIter = TLVTagIter<Self>;

    fn into_iter(self) -> Self::IntoIter {
        TLVTag::iter(self)
    }
}

/// An iterator over the bytes of a TLV tag.
pub struct TLVTagIter<T>
where
    T: Borrow<TLVTag>,
{
    value: T,
    index: usize,
}

impl<T> TLVTagIter<T>
where
    T: Borrow<TLVTag>,
{
    fn next_byte(&mut self, bytes: &[u8]) -> Option<u8> {
        self.next_byte_offset(0, bytes)
    }

    fn next_byte_offset(&mut self, offset: usize, bytes: &[u8]) -> Option<u8> {
        if self.index - offset < bytes.len() {
            let byte = bytes[self.index - offset];

            self.index += 1;

            Some(byte)
        } else {
            None
        }
    }
}

impl<T> Iterator for TLVTagIter<T>
where
    T: Borrow<TLVTag>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        match self.value.borrow() {
            TLVTag::Anonymous => None,
            TLVTag::Context(tag) => self.next_byte(&tag.to_le_bytes()),
            TLVTag::CommonPrf16(tag) => self.next_byte(&tag.to_le_bytes()),
            TLVTag::CommonPrf32(tag) => self.next_byte(&tag.to_le_bytes()),
            TLVTag::ImplPrf16(tag) => self.next_byte(&tag.to_le_bytes()),
            TLVTag::ImplPrf32(tag) => self.next_byte(&tag.to_le_bytes()),
            TLVTag::FullQual48 {
                vendor_id,
                profile,
                tag,
            } => {
                if self.index < 2 {
                    self.next_byte(&vendor_id.to_le_bytes())
                } else if self.index < 4 {
                    self.next_byte_offset(2, &profile.to_le_bytes())
                } else {
                    self.next_byte_offset(4, &tag.to_le_bytes())
                }
            }
            TLVTag::FullQual64 {
                vendor_id,
                profile,
                tag,
            } => {
                if self.index < 2 {
                    self.next_byte(&vendor_id.to_le_bytes())
                } else if self.index < 4 {
                    self.next_byte_offset(2, &profile.to_le_bytes())
                } else {
                    self.next_byte_offset(4, &tag.to_le_bytes())
                }
            }
        }
    }
}

impl fmt::Display for TLVTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TLVTag::Anonymous => write!(f, "Anonymous"),
            TLVTag::Context(tag) => write!(f, "Context({})", tag),
            _ => self.fmt(f),
        }
    }
}

/// For backwards compatibility
pub type ElementType<'a> = TLVValue<'a>;

/// A high-level representation of a TLV value.
///
/// Combined with `TLVTag` into a `TLV` struct it is a convenient way
/// to emit TLV byte sequences.
///
/// A `TLVValue` can be constructed programmatically, or returned from a `TLVElement`.
///
/// Unlike a `TLVElement` however, a `TLVValue` does not represent a complete container,
/// but rather, its beginning or end.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TLVValue<'a> {
    S8(i8),
    S16(i16),
    S32(i32),
    S64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    False,
    True,
    F32(f32),
    F64(f64),
    Utf8l(&'a str),
    Utf16l(&'a str),
    Utf32l(&'a str),
    Utf64l(&'a str),
    Str8l(&'a [u8]),
    Str16l(&'a [u8]),
    Str32l(&'a [u8]),
    Str64l(&'a [u8]),
    Null,
    Struct,
    Array,
    List,
    EndCnt,
}

impl<'a> TLVValue<'a> {
    /// Return the value type of the TLV value.
    pub const fn value_type(&self) -> TLVValueType {
        match self {
            Self::S8(_) => TLVValueType::S8,
            Self::S16(_) => TLVValueType::S16,
            Self::S32(_) => TLVValueType::S32,
            Self::S64(_) => TLVValueType::S64,
            Self::U8(_) => TLVValueType::U8,
            Self::U16(_) => TLVValueType::U16,
            Self::U32(_) => TLVValueType::U32,
            Self::U64(_) => TLVValueType::U64,
            Self::False => TLVValueType::False,
            Self::True => TLVValueType::True,
            Self::F32(_) => TLVValueType::F32,
            Self::F64(_) => TLVValueType::F64,
            Self::Utf8l(_) => TLVValueType::Utf8l,
            Self::Utf16l(_) => TLVValueType::Utf16l,
            Self::Utf32l(_) => TLVValueType::Utf32l,
            Self::Utf64l(_) => TLVValueType::Utf64l,
            Self::Str8l(_) => TLVValueType::Str8l,
            Self::Str16l(_) => TLVValueType::Str16l,
            Self::Str32l(_) => TLVValueType::Str32l,
            Self::Str64l(_) => TLVValueType::Str64l,
            Self::Null => TLVValueType::Null,
            Self::Struct => TLVValueType::Struct,
            Self::Array => TLVValueType::Array,
            Self::List => TLVValueType::List,
            Self::EndCnt => TLVValueType::EndCnt,
        }
    }

    /// Create a TLV value as an S8 TLV value.
    pub const fn i8(value: i8) -> Self {
        Self::S8(value)
    }

    /// Create a TLV value as an S8 or S16 TLV value,
    /// depending on whether the value is small enough to fit in an S8 TLV value.
    pub const fn i16(value: i16) -> Self {
        if value >= i8::MIN as i16 && value <= i8::MAX as i16 {
            Self::i8(value as i8)
        } else {
            Self::S16(value)
        }
    }

    /// Create a TLV value as an S8, S16, or S32 TLV value,
    /// depending on whether the value is small enough to fit in an S8 or S16 TLV value.
    pub const fn i32(value: i32) -> Self {
        if value >= i16::MIN as i32 && value <= i16::MAX as i32 {
            Self::i16(value as i16)
        } else {
            Self::S32(value)
        }
    }

    /// Create a TLV value as an S8, S16, S32, or S64 TLV value,
    /// depending on whether the value is small enough to fit in an S8, S16, or S32 TLV value.
    pub const fn i64(value: i64) -> Self {
        if value >= i32::MIN as i64 && value <= i32::MAX as i64 {
            Self::i32(value as i32)
        } else {
            Self::S64(value)
        }
    }

    /// Create a TLV value as a U8 TLV value.
    pub const fn u8(value: u8) -> Self {
        Self::U8(value)
    }

    /// Create a TLV value as a U8 or U16 TLV value,
    /// depending on whether the value is small enough to fit in a U8 TLV value.
    pub const fn u16(value: u16) -> Self {
        if value <= u8::MAX as u16 {
            Self::u8(value as u8)
        } else {
            Self::U16(value)
        }
    }

    /// Create a TLV value as a U8, U16, or U32 TLV value,
    /// depending on whether the value is small enough to fit in a U8 or U16 TLV value.
    pub const fn u32(value: u32) -> Self {
        if value <= u16::MAX as u32 {
            Self::u16(value as u16)
        } else {
            Self::U32(value)
        }
    }

    /// Create a TLV value as a U8, U16, U32, or U64 TLV value,
    /// depending on whether the value is small enough to fit in a U8, U16, or U32 TLV value.
    pub const fn u64(value: u64) -> Self {
        if value <= u32::MAX as u64 {
            Self::u32(value as u32)
        } else {
            Self::U64(value)
        }
    }

    /// Create a TLV value as an F32 TLV value.
    pub const fn f32(value: f32) -> Self {
        Self::F32(value)
    }

    /// Create a TLV value as an F64 TLV value.
    pub const fn f64(value: f64) -> Self {
        Self::F64(value)
    }

    /// Create a TLV value as a UTF-8 TLV value.
    /// The length of the string is encoded as 1, 2, 4 or 8 octets,
    /// depending on the length of the string.
    pub const fn utf8(value: &'a str) -> Self {
        let len = value.len();

        if len <= u8::MAX as usize {
            Self::Utf8l(value)
        } else if len <= u16::MAX as usize {
            Self::Utf16l(value)
        } else if len <= u32::MAX as usize {
            Self::Utf32l(value)
        } else {
            Self::Utf64l(value)
        }
    }

    /// Create a TLV value as an octet string TLV value.
    /// The length of the string is encoded as 1, 2, 4 or 8 octets,
    /// depending on the length of the string.
    pub const fn str(value: &'a [u8]) -> Self {
        let len = value.len();

        if len <= u8::MAX as usize {
            Self::Str8l(value)
        } else if len <= u16::MAX as usize {
            Self::Str16l(value)
        } else if len <= u32::MAX as usize {
            Self::Str32l(value)
        } else {
            Self::Str64l(value)
        }
    }

    /// Create a TLV value of type Struct (start).
    pub const fn r#struct() -> Self {
        Self::Struct
    }

    /// Create a TLV value of type Struct (start).
    pub const fn structure() -> Self {
        Self::Struct
    }

    /// Create a TLV value of type Array (start).
    pub const fn array() -> Self {
        Self::Array
    }

    /// Create a TLV value of type List (start).
    pub const fn list() -> Self {
        Self::List
    }

    /// Create a TLV value of type EndCnt (container end).
    pub const fn end_container() -> Self {
        Self::EndCnt
    }

    /// Create a TLV value of type Null.
    pub const fn null() -> Self {
        Self::Null
    }

    /// Create a TLV value of type boolean (True or False).
    pub const fn bool(value: bool) -> Self {
        if value {
            Self::True
        } else {
            Self::False
        }
    }

    /// Return an iterator over the bytes of the TLV value.
    pub fn iter(&self) -> TLVValueIter<'a, &Self> {
        TLVValueIter {
            value: self,
            _p: PhantomData,
            index: 0,
        }
    }

    /// Converts itself into an iterator over the bytes of the TLV value.
    pub fn into_iterator(self) -> TLVValueIter<'a, Self> {
        TLVValueIter {
            value: self,
            _p: PhantomData,
            index: 0,
        }
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::S8(a) => write!(f, "S8({a})"),
            Self::S16(a) => write!(f, "S16({a})"),
            Self::S32(a) => write!(f, "S32({a})"),
            Self::S64(a) => write!(f, "S64({a})"),
            Self::U8(a) => write!(f, "U8(0x{a:02x})"),
            Self::U16(a) => write!(f, "U16(0x{a:04x})"),
            Self::U32(a) => write!(f, "U32(0x{a:08x})"),
            Self::U64(a) => write!(f, "U64(0x{a:016x})"),
            Self::F32(a) => write!(f, "F32({a})"),
            Self::F64(a) => write!(f, "F64({a})"),
            Self::Null => write!(f, "Null"),
            Self::Struct => write!(f, "{{"),
            Self::Array => write!(f, "["),
            Self::List => write!(f, "("),
            Self::True => write!(f, "True"),
            Self::False => write!(f, "False"),
            Self::Utf8l(a) | Self::Utf16l(a) | Self::Utf32l(a) | Self::Utf64l(a) => {
                write!(f, "\"{a}\"")
            }
            Self::Str8l(a) | Self::Str16l(a) | Self::Str32l(a) | Self::Str64l(a) => {
                write!(f, "({}){a:02X?}", a.len())
            }
            Self::EndCnt => write!(f, ">"),
        }
    }
}

impl<'a> IntoIterator for TLVValue<'a> {
    type Item = u8;
    type IntoIter = TLVValueIter<'a, Self>;

    fn into_iter(self) -> Self::IntoIter {
        TLVValue::into_iterator(self)
    }
}

impl<'a> IntoIterator for &TLVValue<'a> {
    type Item = u8;
    type IntoIter = TLVValueIter<'a, Self>;

    fn into_iter(self) -> Self::IntoIter {
        TLVValue::iter(self)
    }
}

/// An iterator over the bytes of a TLV value.
pub struct TLVValueIter<'a, T>
where
    T: Borrow<TLVValue<'a>>,
{
    value: T,
    _p: PhantomData<&'a ()>,
    index: usize,
}

impl<'a, T> TLVValueIter<'a, T>
where
    T: Borrow<TLVValue<'a>>,
{
    fn variable_len_len(&self) -> usize {
        match self.value.borrow() {
            TLVValue::Utf8l(_) | TLVValue::Str8l(_) => 1,
            TLVValue::Utf16l(_) | TLVValue::Str16l(_) => 2,
            TLVValue::Utf32l(_) | TLVValue::Str32l(_) => 4,
            TLVValue::Utf64l(_) | TLVValue::Str64l(_) => 8,
            _ => 0,
        }
    }

    fn next_byte(&mut self, bytes: &[u8]) -> Option<u8> {
        self.next_byte_offset(0, bytes)
    }

    fn next_byte_offset(&mut self, offset: usize, bytes: &[u8]) -> Option<u8> {
        if self.index - offset < bytes.len() {
            let byte = bytes[self.index - offset];

            self.index += 1;

            Some(byte)
        } else {
            None
        }
    }
}

impl<'a, T> Iterator for TLVValueIter<'a, T>
where
    T: Borrow<TLVValue<'a>>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        match self.value.borrow() {
            TLVValue::S8(a) => self.next_byte(&a.to_le_bytes()),
            TLVValue::S16(a) => self.next_byte(&a.to_le_bytes()),
            TLVValue::S32(a) => self.next_byte(&a.to_le_bytes()),
            TLVValue::S64(a) => self.next_byte(&a.to_le_bytes()),
            TLVValue::U8(a) => self.next_byte(&a.to_le_bytes()),
            TLVValue::U16(a) => self.next_byte(&a.to_le_bytes()),
            TLVValue::U32(a) => self.next_byte(&a.to_le_bytes()),
            TLVValue::U64(a) => self.next_byte(&a.to_le_bytes()),
            TLVValue::F32(a) => self.next_byte(&a.to_le_bytes()),
            TLVValue::F64(a) => self.next_byte(&a.to_le_bytes()),
            TLVValue::Utf8l(a) | TLVValue::Utf16l(a) | TLVValue::Utf32l(a) => {
                let len_len = self.variable_len_len();
                if self.index < len_len {
                    self.next_byte(&a.len().to_le_bytes())
                } else {
                    self.next_byte_offset(len_len, a.as_bytes())
                }
            }
            TLVValue::Str8l(a) | TLVValue::Str16l(a) | TLVValue::Str32l(a) => {
                let len_len = self.variable_len_len();
                if self.index < len_len {
                    self.next_byte(&a.len().to_le_bytes())
                } else {
                    self.next_byte_offset(len_len, a)
                }
            }
            _ => None,
        }
    }
}

impl fmt::Display for TLVValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt(f)
    }
}

pub(crate) fn pad(ident: usize, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for _ in 0..ident {
        write!(f, "  ")?;
    }

    Ok(())
}

/// For backwards compatibility
pub fn get_root_node_struct(data: &[u8]) -> Result<TLVElement<'_>, Error> {
    // TODO: Check for trailing data
    let element = TLVElement::new(data);

    element.structure()?;

    Ok(element)
}
