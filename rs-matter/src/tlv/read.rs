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

use core::{cmp::Ordering, fmt};

use crate::error::{Error, ErrorCode};

use super::{pad, TLVControl, TLVTag, TLVTagType, TLVValue, TLVValueType, TLV};

/// A newtype for reading TLV-encoded data from Rust `&[u8]` slices.
///
/// Semantically, a `TLVElement` is just a byte slice of TLV-encoded data/stream, and the methods provided by this therefore
/// allow to parse - on the fly - the byte slice as TLV.
///
/// Note also, that - as per the Matter Core Spec:
/// - A valid TLV stream always represents a SINGLE TLV element (hence why this type is named `TLVElement` and why we claim
///   that it represents also a whole TLV stream)
/// - If there is a need to encode more than one TLV element, they should be encoded in a TLV container (array, list or struct),
///   hence we end up again with a single TLV element, which represents the whole container.
///
/// Parsing/reading/validating the TLV of the slice represented by a `TLVElement` is done on-demand. What this means is that:
/// - `TLVElement::new(slice)` always succeeds, even when the passed slice contains invalid TLV data
/// - As the various methods of `TLVElement` type are called, the data in the slice is parsed and validated on the fly. Hence why all methods
///   on `TLVElement` except `is_empty` are fallible.
///
/// A TLV element can currently be constructed from an empty `&[]` slice, but the empty slice does not actually represent a TLV element,
/// so all methods except `TLVElement::is_empty` would fail on a `TLVElement` constructed from an empty slice. The only reason why empty slices
/// are currently allowed is to simplify the `FromTLV` trait a bit by representing data which was not found (i.e. optional data in TLV structures)
/// as a TLVElement with an empty slice.
///
/// The design approach from above (on-demand parsing/validation) trades memory efficiency for extra computations, in that by simply decorating
/// a Rust `&[u8]` slice anbd post-poning everything else post-construction it ensures the size of a `TLVElement` is equal to the size of the wrapped
/// `&[u8]` slice - i.e., a regular Rust fat pointer (8 bytes on 32 bit archs and 16 bytes on 64 bit archs).
///
/// Furthermore, all accompanying types of `TLVElement`, like `TLVSequence`, `TLVContainerIter` and `TLVArray` are also just newtypes over byte slices
/// and therefore just as small.
///
/// (Keeping interim data is still optionally possible, by using the `TLV::tag` and `TLV::value`
/// methods to read the tag and value of a TLV as enums.)
///
/// As for representing the encoded TLV stream itself as a raw `&[u8]` slice - this trivializes the traversal of the stream
/// as the stream traversal is represented as returning sub-slices of the original slice. It also allows `FromTLV` implementations where
/// the data is borrowed directly from the `&[u8]` slice representing the encoded TLV stream without any data moves. Types that implement
/// such borrowing are e.g.:
/// - `&str` (used to represent borrowed TLV UTF-8 strings)
/// - `Bytes<'a>` (a newtype over `&'a [u8]` - used to represent TLV octet strings)
/// - `TLVArray`
/// - `TLVSequence` - discussed below
///
/// Also, this representation naturally allows random-access to the TLV stream, which is necessary for a number of reasons:
/// - Deserialization of TLV structs into Rust structs (with the `FromTLV` derive macro) where the order of the TLV elements
///   of the struct is not known in advance
/// - Delayed in-place initialization of large Rust types with `FromTLV::init_from_tlv` which requires random access for reasons
///   beyond the possible unordering of the TLV struct elements.
///
/// In practice, random access - and in general - representation of the TLV stream as a `&[u8]` slice should be natural and
/// convenient, as the TLV stream usually comes from the network UDP/TCP memory buffers of the Matter transport protocol, and
/// these can and are borrowed as `&[u8]` slices in the upper-layer code for direct reads.
#[derive(Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TLVElement<'a>(TLVSequence<'a>);

impl<'a> TLVElement<'a> {
    /// Create a new `TLVElement` from a byte slice, where the byte slice contains an encoded TLV stream (a TLV element).
    #[inline(always)]
    pub const fn new(data: &'a [u8]) -> Self {
        Self(TLVSequence(data))
    }

    /// Return `true` if the wrapped byte slice is the empty `&[]` slice.
    /// Empty byte slices do not represent valid TLV data, as the TLV data should be a valid TLV element,
    /// yet they are useful when implementing the `FromTLV` trait.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0 .0.is_empty()
    }

    /// Return `Some(self)` if the wrapped byte slice is not empty, `None` otherwise.
    pub fn non_empty(&self) -> Option<&TLVElement<'a>> {
        if self.is_empty() {
            None
        } else {
            Some(self)
        }
    }

    /// Return a copy of the wrapped TLV byte slice.
    #[inline(always)]
    pub const fn raw_data(&self) -> &'a [u8] {
        self.0 .0
    }

    /// Return the TLV control byte of the first TLV in the slice.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the first byte of the slice does
    /// not represent a valid TLV control byte or if the wrapped byte slice is empty.
    #[inline(always)]
    pub fn control(&self) -> Result<TLVControl, Error> {
        self.0.control()
    }

    /// Return a sub-slice of the wrapped byte slice that designates the encoded value
    /// of this `TLVElement` (i.e. the raw "value" aspect of the Tag-Length-Value encoding)
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// For getting a parsed value, use `value` or any of the other helper methods that
    /// retrieve a value of a certain type.
    #[inline(always)]
    pub fn raw_value(&self) -> Result<&'a [u8], Error> {
        self.0.raw_value()
    }

    /// Return a `TLV` struct representing the tag and value of this `TLVElement`.
    /// This method is a convenience method that combines the `tag` and `value` methods.
    pub fn tlv(&self) -> Result<TLV<'a>, Error> {
        Ok(TLV {
            tag: self.tag()?,
            value: self.value()?,
        })
    }

    /// Return a `TLVTag` enum representing the tag of this `TLVElement`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV
    /// byte slice contains malformed TLV data.
    #[inline(always)]
    pub fn tag(&self) -> Result<TLVTag, Error> {
        let tag_type = self.control()?.tag_type;

        let slice = self
            .0
            .tag_start()?
            .get(..tag_type.size())
            .ok_or(ErrorCode::TLVTypeMismatch)?;

        let tag = match tag_type {
            TLVTagType::Anonymous => TLVTag::Anonymous,
            TLVTagType::Context => TLVTag::Context(slice[0]),
            TLVTagType::CommonPrf16 => {
                TLVTag::CommonPrf16(u16::from_le_bytes(unwrap!(slice.try_into())))
            }
            TLVTagType::CommonPrf32 => {
                TLVTag::CommonPrf32(u32::from_le_bytes(unwrap!(slice.try_into())))
            }
            TLVTagType::ImplPrf16 => {
                TLVTag::ImplPrf16(u16::from_le_bytes(unwrap!(slice.try_into())))
            }
            TLVTagType::ImplPrf32 => {
                TLVTag::ImplPrf32(u32::from_le_bytes(unwrap!(slice.try_into())))
            }
            TLVTagType::FullQual48 => TLVTag::FullQual48 {
                vendor_id: u16::from_le_bytes([slice[0], slice[1]]),
                profile: u16::from_le_bytes([slice[2], slice[3]]),
                tag: u16::from_le_bytes([slice[4], slice[5]]),
            },
            TLVTagType::FullQual64 => TLVTag::FullQual64 {
                vendor_id: u16::from_le_bytes([slice[0], slice[1]]),
                profile: u16::from_le_bytes([slice[2], slice[3]]),
                tag: u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]),
            },
        };

        Ok(tag)
    }

    /// Return a `TLVValue` enum representing the value of this `TLVElement`.
    ///
    /// Note that if the TLV element is a container, the return `TLV` value would only deisgnate
    /// the container type (struct, array or list) and not the actual content of the container.
    pub fn value(&self) -> Result<TLVValue<'a>, Error> {
        let control = self.control()?;

        let slice = self.0.container_value(control)?;

        let value = match control.value_type {
            TLVValueType::S8 => TLVValue::S8(i8::from_le_bytes(unwrap!(slice.try_into()))),
            TLVValueType::S16 => TLVValue::S16(i16::from_le_bytes(unwrap!(slice.try_into()))),
            TLVValueType::S32 => TLVValue::S32(i32::from_le_bytes(unwrap!(slice.try_into()))),
            TLVValueType::S64 => TLVValue::S64(i64::from_le_bytes(unwrap!(slice.try_into()))),
            TLVValueType::U8 => TLVValue::U8(u8::from_le_bytes(unwrap!(slice.try_into()))),
            TLVValueType::U16 => TLVValue::U16(u16::from_le_bytes(unwrap!(slice.try_into()))),
            TLVValueType::U32 => TLVValue::U32(u32::from_le_bytes(unwrap!(slice.try_into()))),
            TLVValueType::U64 => TLVValue::U64(u64::from_le_bytes(unwrap!(slice.try_into()))),
            TLVValueType::False => TLVValue::False,
            TLVValueType::True => TLVValue::True,
            TLVValueType::F32 => TLVValue::F32(f32::from_le_bytes(unwrap!(slice.try_into()))),
            TLVValueType::F64 => TLVValue::F64(f64::from_le_bytes(unwrap!(slice.try_into()))),
            TLVValueType::Utf8l => TLVValue::Utf8l(
                core::str::from_utf8(slice).map_err(|_| ErrorCode::TLVTypeMismatch)?,
            ),
            TLVValueType::Utf16l => TLVValue::Utf16l(
                core::str::from_utf8(slice).map_err(|_| ErrorCode::TLVTypeMismatch)?,
            ),
            TLVValueType::Utf32l => TLVValue::Utf32l(
                core::str::from_utf8(slice).map_err(|_| ErrorCode::TLVTypeMismatch)?,
            ),
            TLVValueType::Utf64l => TLVValue::Utf64l(
                core::str::from_utf8(slice).map_err(|_| ErrorCode::TLVTypeMismatch)?,
            ),
            TLVValueType::Str8l => TLVValue::Str8l(slice),
            TLVValueType::Str16l => TLVValue::Str16l(slice),
            TLVValueType::Str32l => TLVValue::Str32l(slice),
            TLVValueType::Str64l => TLVValue::Str64l(slice),
            TLVValueType::Null => TLVValue::Null,
            TLVValueType::Struct => TLVValue::Struct,
            TLVValueType::Array => TLVValue::Array,
            TLVValueType::List => TLVValue::List,
            TLVValueType::EndCnt => TLVValue::EndCnt,
        };

        Ok(value)
    }

    /// Return the value of this TLV element as an `i8`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV S8 value.
    pub fn i8(&self) -> Result<i8, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::S8) {
            Ok(i8::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Return the value of this TLV element as a `u8`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV U8 value.
    pub fn u8(&self) -> Result<u8, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::U8) {
            Ok(u8::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Return the value of this TLV element as an `i16`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV S8 or S16 value.
    pub fn i16(&self) -> Result<i16, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::S16) {
            Ok(i16::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            self.i8().map(|a| a.into())
        }
    }

    /// Return the value of this TLV element as a `u16`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV U8 or U16 value.
    pub fn u16(&self) -> Result<u16, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::U16) {
            Ok(u16::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            self.u8().map(|a| a.into())
        }
    }

    /// Return the value of this TLV element as an `i32`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV S8, S16 or S32 value.
    pub fn i32(&self) -> Result<i32, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::S32) {
            Ok(i32::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            self.i16().map(|a| a.into())
        }
    }

    /// Return the value of this TLV element as a `u32`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV U8, U16 or U32 value.
    pub fn u32(&self) -> Result<u32, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::U32) {
            Ok(u32::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            self.u16().map(|a| a.into())
        }
    }

    /// Return the value of this TLV element as an `i64`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV S8, S16, S32 or S64 value.
    pub fn i64(&self) -> Result<i64, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::S64) {
            Ok(i64::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            self.i32().map(|a| a.into())
        }
    }

    /// Return the value of this TLV element as a `u64`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV U8, U16, U32 or U64 value.
    pub fn u64(&self) -> Result<u64, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::U64) {
            Ok(u64::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            self.u32().map(|a| a.into())
        }
    }

    /// Return the value of this TLV element as an `f32`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV F32 value.
    pub fn f32(&self) -> Result<f32, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::F32) {
            Ok(f32::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Return the value of this TLV element as an `f64`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV F64 value.
    pub fn f64(&self) -> Result<f64, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::F64) {
            Ok(f64::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Return the value of this TLV element as a byte slice.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV Octet String.
    pub fn str(&self) -> Result<&'a [u8], Error> {
        let control = self.control()?;

        if !control.value_type.is_str() {
            Err(ErrorCode::Invalid)?;
        }

        self.0.value(control)
    }

    /// Return the value of this TLV element as a UTF-8 string.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV UTF-8 String.
    pub fn utf8(&self) -> Result<&'a str, Error> {
        let control = self.control()?;

        if !control.value_type.is_utf8() {
            Err(ErrorCode::Invalid)?;
        }

        core::str::from_utf8(self.0.value(control)?).map_err(|_| ErrorCode::InvalidData.into())
    }

    /// Return the value of this TLV element as a UTF-16 string.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV UTF-8 String or a TLV octet string.
    pub fn octets(&self) -> Result<&'a [u8], Error> {
        let control = self.control()?;

        if control.value_type.variable_size_len() == 0 {
            Err(ErrorCode::Invalid)?;
        }

        self.0.value(control)
    }

    /// Return the value of this TLV element as a UTF-16 string.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV boolean.
    pub fn bool(&self) -> Result<bool, Error> {
        let control = self.control()?;

        match control.value_type {
            TLVValueType::False => Ok(false),
            TLVValueType::True => Ok(true),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    /// Return `true` if this TLV element is as a container (i.e., a struct, array or list).
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    pub fn is_container(&self) -> Result<bool, Error> {
        Ok(self.control()?.value_type.is_container())
    }

    /// Confirm that this TLV element contains a TLV null value.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV null value.
    pub fn null(&self) -> Result<(), Error> {
        if matches!(self.control()?.value_type, TLVValueType::Null) {
            Ok(())
        } else {
            Err(ErrorCode::InvalidData.into())
        }
    }

    /// Return the content of the struct container represented by this TLV element.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV struct.
    pub fn structure(&self) -> Result<TLVSequence<'a>, Error> {
        self.r#struct()
    }

    /// Return the content of the struct container represented by this TLV element.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV struct.
    ///
    /// (Same as method `structure` but with a special name to ease the `FromTLV` trait derivation for
    /// user types.)
    pub fn r#struct(&self) -> Result<TLVSequence<'a>, Error> {
        if matches!(self.control()?.value_type, TLVValueType::Struct) {
            self.0.next_enter()
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Return the content of the array container represented by this TLV element.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV array.
    pub fn array(&self) -> Result<TLVSequence<'a>, Error> {
        if matches!(self.control()?.value_type, TLVValueType::Array) {
            self.0.next_enter()
        } else {
            Err(ErrorCode::InvalidData.into())
        }
    }

    /// Return the content of the list container represented by this TLV element.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV list.
    pub fn list(&self) -> Result<TLVSequence<'a>, Error> {
        if matches!(self.control()?.value_type, TLVValueType::List) {
            self.0.next_enter()
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Return the content of the container (array, struct or list) represented by this TLV element.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV container.
    pub fn container(&self) -> Result<TLVSequence<'a>, Error> {
        if matches!(
            self.control()?.value_type,
            TLVValueType::List | TLVValueType::Array | TLVValueType::Struct
        ) {
            self.0.next_enter()
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Confirm that this TLV element is tagged with the anonymous tag (`TLVTag::Anonymous`).
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the tag of the TLV element is not
    /// the anonymous tag.
    pub fn confirm_anon(&self) -> Result<(), Error> {
        if matches!(self.control()?.tag_type, TLVTagType::Anonymous) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Retrieve the context ID of the element.
    /// If element is not tagged with a context tag, the method will return an error.
    pub fn ctx(&self) -> Result<u8, Error> {
        Ok(self.try_ctx()?.ok_or(ErrorCode::TLVTypeMismatch)?)
    }

    /// Retrieve the context ID of the element.
    /// If element is not tagged with a context tag, the method will return `None`.
    pub fn try_ctx(&self) -> Result<Option<u8>, Error> {
        let control = self.control()?;

        if matches!(control.tag_type, TLVTagType::Context) {
            Ok(Some(
                *self
                    .0
                    .tag(control.tag_type)?
                    .first()
                    .ok_or(ErrorCode::TLVTypeMismatch)?,
            ))
        } else {
            Ok(None)
        }
    }

    fn fmt(&self, indent: usize, f: &mut fmt::Formatter) -> fmt::Result {
        pad(indent, f)?;

        let tag = self.tag().map_err(|_| fmt::Error)?;

        tag.fmt(f)?;

        if !matches!(tag.tag_type(), TLVTagType::Anonymous) {
            write!(f, ": ")?;
        }

        let value = self.value().map_err(|_| fmt::Error)?;

        value.fmt(f)?;

        if value.value_type().is_container() {
            let mut empty = true;

            for (index, elem) in self.container().map_err(|_| fmt::Error)?.iter().enumerate() {
                if index > 0 {
                    writeln!(f, ",")?;
                } else {
                    writeln!(f)?;
                }

                elem.map_err(|_| fmt::Error)?.fmt(indent + 2, f)?;

                empty = false;
            }

            if !empty {
                writeln!(f)?;
                pad(indent, f)?;
            }

            match value.value_type() {
                TLVValueType::Struct => write!(f, "}}"),
                TLVValueType::Array => write!(f, "]"),
                TLVValueType::List => write!(f, ")"),
                _ => unreachable!(),
            }?;
        }

        Ok(())
    }
}

impl fmt::Debug for TLVElement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt(0, f)
    }
}

impl fmt::Display for TLVElement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt(0, f)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for TLVElement<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::Display2Format(self).format(f)
    }
}

/// A newtype for iterating over the `TLVElement` "child" instances contained in `TLVElement` which is a TLV container
/// (array, struct or list).
/// (Internally, `TLVSequence` might be used for other purposes, but the external contract is only the one from above.)
///
/// Just like `TLVElement`, `TLVSequence` is a newtype over a byte slice - the byte sub-slice of the parent `TLVElement`
/// container where its value starts.
///
/// Unlike `TLVElement`, `TLVSequence` - as the name suggests - represents a sequence of 0, 1 or more `TLVElements`.
/// The only public API of `TLVSequence` however is the `iter` method which returns a `TLVContainerIter` iterator over
/// the `TLVElement` instances in the sequence.
#[derive(Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TLVSequence<'a>(pub(crate) &'a [u8]);

impl<'a> TLVSequence<'a> {
    const EMPTY: Self = Self(&[]);

    /// Return an iterator over the `TLVElement` instances in this `TLVSequence`.
    #[inline(always)]
    pub fn iter(&self) -> TLVSequenceIter<'a> {
        TLVSequenceIter::new(self.clone())
    }

    /// Return an iterator over the `TLV` instances in this `TLVSequence`.
    ///
    /// The difference with `iter` is that for container elements, `tlv_iter`
    /// will return separate `TLV` instances for the container start, the container
    /// elements and the container end, where if an element in the container is
    /// itself a container, the algorithm will be applied recursively to the inner container.
    pub fn tlv_iter(&self) -> TLVSequenceTLVIter<'a> {
        TLVSequenceTLVIter::new(self.clone())
    }

    /// A convenience utility that returns the first `TLVElement` in the sequence
    /// which is tagged with a context tag (`TLVTag::Context`) where the context ID
    /// is matching the ID passed in the `ctx` parameter.
    ///
    /// If there is no TLV element tagged with a context tag with the matching ID, the method
    /// will return an error.
    pub fn ctx(&self, ctx: u8) -> Result<TLVElement<'a>, Error> {
        let element = self.find_ctx(ctx)?;

        if element.is_empty() {
            Err(ErrorCode::NotFound.into())
        } else {
            Ok(element)
        }
    }

    /// A convenience utility that returns the first `TLVElement` in the sequence
    /// which is tagged with a context tag (`TLVTag::Context`) where the context ID
    /// is matching the ID passed in the `ctx` parameter.
    ///
    /// If there is no TLV element tagged with a context tag with the matching ID, the method
    /// will return an empty `TLVElement`.
    pub fn find_ctx(&self, ctx: u8) -> Result<TLVElement<'a>, Error> {
        for elem in self.iter() {
            let elem = elem?;

            if let Some(elem_ctx) = elem.try_ctx()? {
                if elem_ctx == ctx {
                    return Ok(elem);
                }
            }
        }

        Ok(TLVElement(Self::EMPTY))
    }

    /// A convenience utility that returns the first `TLVElement` in the sequence
    /// which is tagged with a context tag (`TLVTag::Context`) where the context ID
    /// is equal to the ID passed in the `ctx` parameter.
    ///
    /// If there is no TLV element tagged with a context tag with the matching ID, the method
    /// will return an empty TLV element.
    ///
    /// As a side effect of calling this method, the `TLVSequence` instance will be updated
    /// to point to the next element after the found element, or if an element with the
    /// provided context ID does not exist, to the first element with a bigger context ID than
    /// the one we are looking for.
    pub fn scan_ctx(&mut self, ctx: u8) -> Result<TLVElement<'a>, Error> {
        self.scan_map(move |elem| {
            if elem.is_empty() {
                return Ok(Some(elem));
            }

            if let Some(elem_ctx) = elem.try_ctx()? {
                match elem_ctx.cmp(&ctx) {
                    Ordering::Equal => return Ok(Some(elem)),
                    Ordering::Greater => return Ok(Some(TLVElement(Self::EMPTY))),
                    _ => (),
                }
            }

            Ok(None)
        })
    }

    /// A convenience utility that returns scans the elements in the sequence,
    /// in-order and stops scanning once the provided mapping closure `f`
    /// returns a non-empty result.
    ///
    /// As a side effect of calling this method, the `TLVSequence` instance will be updated
    /// to point to the next element after the one on which the provided closure
    /// returned a non-empty result.
    ///
    /// Note that the closure _must_ ultimately return a non-empty result - if for nothing else
    /// then for the empty element that is passed to it when the sequence is exhausted,
    /// or else the method would loop forever.
    pub fn scan_map<F, T>(&mut self, mut f: F) -> Result<T, Error>
    where
        F: FnMut(TLVElement<'a>) -> Result<Option<T>, Error>,
    {
        loop {
            if let Some(elem) = f(self.current()?)? {
                return Ok(elem);
            }

            *self = self.container_next()?;
        }
    }

    /// Return a raw byte sub-slice representing the TLV-encoded elements and only those
    /// elements that belong to the TLV container whose elements are represented by this `TLVSequence` instance.
    ///
    /// This method is necessary, because both `TLVElement` instances, as well as `TLVSequence` instances - for optimization purposes -
    /// might be constructed during iteration on slices which are technically longer than the actual TLV-encoded data
    /// they represent.
    ///
    /// So in case the user is need of the actual, exact raw representation of a TLV container **value**, this method is provided.
    #[inline(always)]
    pub fn raw_value(&self) -> Result<&'a [u8], Error> {
        let control = self.control()?;

        self.container_value(control)
    }

    /// Return a sub-sequence representing the TLV-encoded elements after the first one on the sequence.
    ///
    /// As the name suggests, if the first TLV element in the sequence is a container, this method will return a sub-sequence
    /// which corresponds to the first element INSIDE the container.
    ///
    /// If the sequence is empty, or the sequence contains just one element, the method will return an empty `TLVSequence`.
    ///
    /// Note also that this method will also return sub-sequences where the first element might be a TLV `TLVValueType::EndCnt` marker,
    /// which - formally speaking - is not a TLVElement, but a TLV control byte that marks the end of a container.
    fn next_enter(&self) -> Result<Self, Error> {
        if self.0.is_empty() {
            return Ok(Self::EMPTY);
        }

        let control = self.control()?;

        Ok(Self(self.next_start(control)?))
    }

    /// Return a sub-sequence representing the TLV-encoded elements after the first one on the sequence.
    ///
    /// As the name suggests, if the first TLV element in the sequence is a container, this method will return a sub-sequence
    /// which corresponds to the elements AFTER the container element (i.e., the method "skips over" the elements of the container element).
    ///
    /// If the sequence is empty or the sequence starts with a container-end control byte, the method will return the current sequence.
    fn container_next(&self) -> Result<Self, Error> {
        if self.0.is_empty() {
            return Ok(Self::EMPTY);
        }

        let control = self.control()?;

        if control.value_type.is_container_end() {
            control.confirm_container_end()?;

            return Ok(self.clone());
        }

        let mut next = self.next_enter()?;

        if control.value_type.is_container() {
            let mut level = 1;

            while level > 0 {
                let control = next.control()?;

                if control.value_type.is_container_end() {
                    control.confirm_container_end()?;
                    level -= 1;
                } else if control.value_type.is_container() {
                    level += 1;
                }

                next = next.next_enter()?;
            }
        }

        Ok(next)
    }

    /// Return the first TLV element in the sequence.
    /// If the sequence is empty, or if the sequence starts with a container-end TLV,
    /// an empty element will be returned.
    fn current(&self) -> Result<TLVElement<'a>, Error> {
        if self.0.is_empty() {
            return Ok(TLVElement(Self::EMPTY));
        }

        let control = self.control()?;

        if control.value_type.is_container_end() {
            control.confirm_container_end()?;

            return Ok(TLVElement(Self::EMPTY));
        }

        Ok(TLVElement::new(self.0))
    }

    /// Return the TLV control byte of the first TLV in the sequence.
    /// If the sequence is empty, an error will be returned.
    #[inline(always)]
    fn control(&self) -> Result<TLVControl, Error> {
        TLVControl::parse(*self.0.first().ok_or(ErrorCode::TLVTypeMismatch)?)
    }

    /// Return a sub-slice of the wrapped byte slice that designates the START of the tag payload
    /// of the first TLV in the sequence.
    ///
    /// If there is no tag payload (i.e., the tag is of type `TLVTagType::Anonymous`), the returned sub-slice
    /// will designate the start of the TLV element value or value length.
    #[inline(always)]
    fn tag_start(&self) -> Result<&'a [u8], Error> {
        Ok(self.0.get(1..).ok_or(ErrorCode::TLVTypeMismatch)?)
    }

    /// Return a sub-slice of the wrapped byte slice that designates the exact raw slice representing the tag payload
    /// of the first TLV in the sequence.
    ///
    /// If there is no tag payload (i.e., the tag is of type `TLVTagType::Anonymous`), the returned sub-slice
    /// will be the empty slice.
    #[inline(always)]
    fn tag(&self, tag_type: TLVTagType) -> Result<&'a [u8], Error> {
        Ok(self
            .tag_start()?
            .get(..tag_type.size())
            .ok_or(ErrorCode::TLVTypeMismatch)?)
    }

    /// Return a sub-slice of the wrapped byte slice that designates the START of the value length field
    /// of the first TLV in the sequence.
    ///
    /// The value length field is the field that designates the length of the value of the TLV element.
    /// If the TLV element control byte designates an element with a fixed size or a container element,
    /// the returned sub-slice will designate the start of the value field.
    #[inline(always)]
    fn value_len_start(&self, tag_type: TLVTagType) -> Result<&'a [u8], Error> {
        Ok(unwrap!(self.tag_start())
            .get(tag_type.size()..)
            .ok_or(ErrorCode::TLVTypeMismatch)?)
    }

    /// Return a sub-slice of the wrapped byte slice that designates the START of the value field of
    /// the first TLV in the sequence.
    ///
    /// The value field is the field that designates the actual value of the TLV element.
    #[inline(always)]
    fn value_start(&self, control: TLVControl) -> Result<&'a [u8], Error> {
        Ok(self
            .value_len_start(control.tag_type)?
            .get(control.value_type.variable_size_len()..)
            .ok_or(ErrorCode::TLVTypeMismatch)?)
    }

    /// Return a sub-slice of the wrapped byte slice that designates the exact raw slice representing the value payload
    /// of the first TLV element in the sequence.
    ///
    /// For container elements, this method will return the empty slice. Use `container_value` (a more computationally expensive method)
    /// to get the exact taw slice of the first TLV element value that also works for containers.
    #[inline(always)]
    fn value(&self, control: TLVControl) -> Result<&'a [u8], Error> {
        let value_len = self.value_len(control)?;

        Ok(self
            .value_start(control)?
            .get(..value_len)
            .ok_or(ErrorCode::TLVTypeMismatch)?)
    }

    /// Return a sub-slice of the wrapped byte slice that designates the exact raw slice representing the value payload
    /// of the first TLV element in the sequence.
    #[inline(always)]
    fn container_value(&self, control: TLVControl) -> Result<&'a [u8], Error> {
        let value_len = self.container_value_len(control)?;

        Ok(self
            .value_start(control)?
            .get(..value_len)
            .ok_or(ErrorCode::TLVTypeMismatch)?)
    }

    /// Return the length of the value field of the first TLV element in the sequence.
    ///
    /// - For elements that do have a fixed size, the fixed size will be returned.
    /// - For UTF-8 and octet strings, the actual string length will be returned.
    /// - For containers, a length of 0 will be returned. Use `container_value_len`
    ///   (much more computationally expensive method) to get the exact length of the container.
    #[inline(always)]
    fn value_len(&self, control: TLVControl) -> Result<usize, Error> {
        if let Some(fixed_size) = control.value_type.fixed_size() {
            return Ok(fixed_size);
        }

        let size_len = control.value_type.variable_size_len();

        let value_len_slice = self
            .value_len_start(control.tag_type)?
            .get(..size_len)
            .ok_or(ErrorCode::TLVTypeMismatch)?;

        let len = match size_len {
            1 => u8::from_be_bytes(unwrap!(value_len_slice.try_into())) as usize,
            2 => u16::from_le_bytes(unwrap!(value_len_slice.try_into())) as usize,
            4 => u32::from_le_bytes(unwrap!(value_len_slice.try_into())) as usize,
            8 => u64::from_le_bytes(unwrap!(value_len_slice.try_into())) as usize,
            _ => unreachable!(),
        };

        Ok(len)
    }

    /// Return the length of the value field of the first TLV element in the sequence, regardless of the
    /// element type (fixed size, variable size, or container).
    #[inline(always)]
    fn container_value_len(&self, control: TLVControl) -> Result<usize, Error> {
        if control.value_type.is_container() {
            let mut next = self.clone();
            let mut len = 0;
            let mut level = 1;

            while level > 0 {
                next = next.next_enter()?;
                len += next.len()?;

                let control = next.control()?;

                if control.value_type.is_container_end() {
                    control.confirm_container_end()?;
                    level -= 1;
                } else if control.value_type.is_container() {
                    level += 1;
                }
            }

            Ok(len)
        } else {
            self.value_len(control)
        }
    }

    /// Return the length of the first TLV element in the sequence.
    ///
    /// For containers, the return length will NOT include the elements contained inside
    /// the container, nor the one-byte `EndCnt` marker.
    #[inline(always)]
    fn len(&self) -> Result<usize, Error> {
        let control = self.control()?;

        self.value_len(control).map(|value_len| {
            1 + control.tag_type.size() + control.value_type.variable_size_len() + value_len
        })
    }

    /// Return the length of the first TLV element in the sequence, regardless of the element type.
    #[inline(always)]
    pub(crate) fn container_len(&self) -> Result<usize, Error> {
        let control = self.control()?;

        self.container_value_len(control).map(|value_len| {
            1 + control.tag_type.size() + control.value_type.variable_size_len() + value_len
        })
    }

    /// Returns a sub-slice representing the start of the next TLV element in the sequence.
    /// If the sequence contains just one element, the method will return an empty slice.
    /// If the sequence contains no elements, the method will return an error with code `ErrorCode::TLVTypeMismatch`.
    ///
    /// Just like `next_enter` (wich is based on `next_start`) this method does "enter" container elements,
    /// and might return a sub-slice where the first element is the special `EndCnt` marker.
    #[inline(always)]
    fn next_start(&self, control: TLVControl) -> Result<&'a [u8], Error> {
        let value_len = self.value_len(control)?;

        Ok(self
            .value_start(control)?
            .get(value_len..)
            .ok_or(ErrorCode::TLVTypeMismatch)?)
    }

    pub(crate) fn fmt(&self, indent: usize, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;

        for elem in self.iter() {
            if first {
                first = false;
            } else {
                writeln!(f, ",")?;
            }

            let elem = elem.map_err(|_| fmt::Error)?;

            elem.fmt(indent, f)?;
        }

        if !first {
            writeln!(f)?;
        }

        Ok(())
    }
}

impl fmt::Debug for TLVSequence<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt(0, f)
    }
}

impl fmt::Display for TLVSequence<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt(0, f)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for TLVSequence<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::Display2Format(self).format(f)
    }
}

/// A type representing an iterator over the elements of a `TLVSequence` returning `TLV` instances.
#[derive(Clone)]
pub struct TLVSequenceTLVIter<'a> {
    seq: TLVSequence<'a>,
    nesting: usize,
}

impl<'a> TLVSequenceTLVIter<'a> {
    /// Create a new `TLVContainerIter` instance.
    const fn new(seq: TLVSequence<'a>) -> Self {
        Self { seq, nesting: 0 }
    }

    fn try_next(&mut self) -> Result<Option<TLV<'a>>, Error> {
        let current = self.seq.current()?;
        if current.is_empty() {
            return Ok(None);
        }

        self.advance()?;

        Ok(Some(TLV::new(current.tag()?, current.value()?)))
    }

    fn advance(&mut self) -> Result<(), Error> {
        if self.nesting > 0 || !self.seq.0.is_empty() && !self.seq.control()?.is_container_end() {
            self.seq = self.seq.next_enter()?;

            let control = self.seq.control()?;

            if control.is_container_start() {
                self.nesting += 1;
            } else if control.is_container_end() {
                self.nesting -= 1;
            }
        }

        Ok(())
    }
}

impl<'a> Iterator for TLVSequenceTLVIter<'a> {
    type Item = Result<TLV<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.try_next().transpose()
    }
}

/// A type representing an iterator over the elements of a `TLVSequence`.
#[derive(Clone)]
#[repr(transparent)]
pub struct TLVSequenceIter<'a>(TLVSequence<'a>);

impl<'a> TLVSequenceIter<'a> {
    /// Create a new `TLVContainerIter` instance.
    const fn new(seq: TLVSequence<'a>) -> Self {
        Self(seq)
    }

    fn advance(&mut self) -> Result<(), Error> {
        self.0 = self.0.container_next()?;

        Ok(())
    }
}

impl<'a> Iterator for TLVSequenceIter<'a> {
    type Item = Result<TLVElement<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .current()
            .and_then(|current| self.advance().map(|_| current))
            .map(|elem| (!elem.is_empty()).then_some(elem))
            .transpose()
    }
}

impl fmt::Debug for TLVSequenceIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(0, f)
    }
}

impl fmt::Display for TLVSequenceIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(0, f)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for TLVSequenceIter<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::Display2Format(self).format(f)
    }
}

#[cfg(test)]
mod tests {
    use core::{f32, f64};

    use super::TLVElement;
    use crate::{
        tlv::{TLVArray, TLVList, TLVSequence, TLVStruct, TLVTag, TLVValue, TLVWrite, TLV},
        utils::storage::WriteBuf,
    };

    #[test]
    fn test_no_container_for_int() {
        // The 0x24 is a a tagged integer, here the integer is 2
        let data = &[0x15, 0x24, 0x1, 0x2];
        let seq = TLVSequence(data);
        // Skip the 0x15
        let seq = seq.next_enter().unwrap();

        let elem = TLVElement(seq);
        assert!(elem.container().is_err());
    }

    #[test]
    fn test_struct_iteration_with_mix_values() {
        // This is a struct with 3 valid values
        let data = &[
            0x15, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10, 0x02, 0x00, 0x30, 0x3, 0x04, 0x73, 0x6d,
            0x61, 0x72,
        ];

        let mut root_iter = TLVElement::new(data).structure().unwrap().iter();
        assert_eq!(
            root_iter.next().unwrap().unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(0),
                value: TLVValue::U8(2),
            }
        );
        assert_eq!(
            root_iter.next().unwrap().unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(2),
                value: TLVValue::U32(135246),
            }
        );
        assert_eq!(
            root_iter.next().unwrap().unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(3),
                value: TLVValue::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
            }
        );
    }

    #[test]
    fn test_struct_find_element_mix_values() {
        // This is a struct with 3 valid values
        let data = &[
            0x15, 0x30, 0x3, 0x04, 0x73, 0x6d, 0x61, 0x72, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10,
            0x02, 0x00,
        ];
        let root = TLVElement::new(data).structure().unwrap();

        assert_eq!(
            root.find_ctx(0).unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(0),
                value: TLVValue::U8(2),
            }
        );
        assert_eq!(root.find_ctx(2).unwrap().tag().unwrap(), TLVTag::Context(2));
        assert_eq!(root.find_ctx(2).unwrap().u64().unwrap(), 135246);

        assert_eq!(root.find_ctx(3).unwrap().tag().unwrap(), TLVTag::Context(3));
        assert_eq!(
            root.find_ctx(3).unwrap().str().unwrap(),
            &[0x73, 0x6d, 0x61, 0x72]
        );
    }

    #[test]
    fn test_container_len() {
        let mut buf = [0; 200];
        let mut tw = WriteBuf::new(&mut buf);

        tw.start_struct(&TLVTag::Context(0)).unwrap();
        tw.u64(&TLVTag::Context(0), 1234).unwrap();
        tw.u64(&TLVTag::Context(1), 1234).unwrap();
        tw.end_container().unwrap();

        // container_len should exactly match the underlying slice holding the complete structure
        assert_eq!(tw.as_slice().len(), 11);
        assert_eq!(
            TLVSequence(tw.as_slice()).container_len().unwrap(),
            tw.as_slice().len()
        );
    }

    #[test]
    fn test_list_iteration_with_mix_values() {
        // This is a list with 3 valid values
        let data = &[
            0x17, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10, 0x02, 0x00, 0x30, 0x3, 0x04, 0x73, 0x6d,
            0x61, 0x72,
        ];
        let mut root_iter = TLVElement::new(data).list().unwrap().iter();
        assert_eq!(
            root_iter.next().unwrap().unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(0),
                value: TLVValue::U8(2),
            }
        );
        assert_eq!(
            root_iter.next().unwrap().unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(2),
                value: TLVValue::U32(135246),
            }
        );
        assert_eq!(
            root_iter.next().unwrap().unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(3),
                value: TLVValue::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
            }
        );
    }

    #[test]
    fn test_read_past_end_of_container() {
        let data = &[0x15, 0x35, 0x0, 0x24, 0x1, 0x2, 0x18, 0x24, 0x0, 0x2, 0x18];

        let mut struct2_iter = TLVElement::new(data)
            .structure()
            .unwrap()
            .find_ctx(0)
            .unwrap()
            .structure()
            .unwrap()
            .iter();

        assert_eq!(
            struct2_iter.next().unwrap().unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(1),
                value: TLVValue::U8(2),
            }
        );
        assert!(struct2_iter.next().is_none());
        // Call next, even after the first next returns None
        assert!(struct2_iter.next().is_none());
        assert!(struct2_iter.next().is_none());
    }

    #[test]
    fn test_iteration() {
        // This is the input we have
        // {
        //   0: [
        //     {
        //       0: L[ 0: 2, 2: 6, 3: 1],
        //       1: {},
        //     },
        //   ],
        // }

        let data = &[
            0x15, 0x36, 0x0, 0x15, 0x37, 0x0, 0x24, 0x0, 0x2, 0x24, 0x2, 0x6, 0x24, 0x3, 0x1, 0x18,
            0x35, 0x1, 0x18, 0x18, 0x18, 0x18,
        ];

        let struct0 = TLVStruct::<TLVElement>::new(TLVElement::new(data)).unwrap();

        assert_eq!(
            struct0.element().tlv().unwrap(),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Struct,
            }
        );
        assert_eq!(struct0.iter().count(), 1);

        let array = TLVArray::<TLVElement>::new(struct0.iter().next().unwrap().unwrap()).unwrap();

        assert_eq!(
            array.element().tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(0),
                value: TLVValue::Array,
            }
        );
        assert_eq!(array.iter().count(), 1);

        let struct1 = TLVStruct::<TLVElement>::new(array.iter().next().unwrap().unwrap()).unwrap();
        assert_eq!(
            struct1.element().tlv().unwrap(),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Struct,
            }
        );
        assert_eq!(struct1.iter().count(), 2);

        let mut struct1_iter = struct1.iter();

        let list = TLVList::<TLVElement>::new(struct1_iter.next().unwrap().unwrap()).unwrap();
        assert_eq!(
            list.element().tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(0),
                value: TLVValue::List,
            }
        );
        assert_eq!(list.iter().count(), 3);

        let mut list_iter = list.iter();

        let le1 = list_iter.next().unwrap().unwrap();
        assert_eq!(
            le1.tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(0),
                value: TLVValue::U8(2)
            }
        );

        let le2 = list_iter.next().unwrap().unwrap();
        assert_eq!(
            le2.tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(2),
                value: TLVValue::U8(6)
            }
        );

        let le3 = list_iter.next().unwrap().unwrap();
        assert_eq!(
            le3.tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(3),
                value: TLVValue::U8(1)
            }
        );

        assert!(list_iter.next().is_none());

        let struct2 = TLVStruct::<TLVElement>::new(struct1_iter.next().unwrap().unwrap()).unwrap();
        assert_eq!(
            struct2.element().tlv().unwrap(),
            TLV {
                tag: TLVTag::Context(1),
                value: TLVValue::Struct,
            }
        );
        assert_eq!(struct2.iter().count(), 0);
    }

    #[test]
    fn test_matter_spec_examples() {
        let tlv = |slice| TLVElement::new(slice).tlv().unwrap();

        // Boolean false

        assert_eq!(
            tlv(&[0x08]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::False,
            }
        );

        // Boolean true

        assert_eq!(
            tlv(&[0x09]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::True,
            }
        );

        // Signed Integer, 1-octet, value 42

        assert_eq!(
            tlv(&[0x00, 0x2a]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::S8(42),
            }
        );

        // Signed Integer, 1-octet, value -17

        assert_eq!(
            tlv(&[0x00, 0xef]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::S8(-17),
            }
        );

        // Unsigned Integer, 1-octet, value 42U

        assert_eq!(
            tlv(&[0x04, 0x2a]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::U8(42),
            }
        );

        // Signed Integer, 2-octet, value 42

        assert_eq!(
            tlv(&[0x01, 0x2a, 0x00]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::S16(42),
            }
        );

        // Signed Integer, 4-octet, value -170000

        assert_eq!(
            tlv(&[0x02, 0xf0, 0x67, 0xfd, 0xff]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::S32(-170000),
            }
        );

        // Signed Integer, 8-octet, value 40000000000

        assert_eq!(
            tlv(&[0x03, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::S64(40000000000),
            }
        );

        // UTF-8 String, 1-octet length, "Hello!"

        assert_eq!(
            tlv(&[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Utf8l("Hello!"),
            }
        );

        // UTF-8 String, 1-octet length, "Tschüs"

        assert_eq!(
            tlv(&[0x0c, 0x07, 0x54, 0x73, 0x63, 0x68, 0xc3, 0xbc, 0x73]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Utf8l("Tschüs"),
            }
        );

        // Octet String, 1-octet length, octets 00 01 02 03 04

        assert_eq!(
            tlv(&[0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Str8l(&[0x00, 0x01, 0x02, 0x03, 0x04]),
            }
        );

        // Null

        assert_eq!(
            tlv(&[0x14]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Null,
            }
        );

        // Single precision floating point 0.0

        assert_eq!(
            tlv(&[0x0a, 0x00, 0x00, 0x00, 0x00]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::F32(0.0),
            }
        );

        // Single precision floating point (1.0 / 3.0)

        assert_eq!(
            tlv(&[0x0a, 0xab, 0xaa, 0xaa, 0x3e]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::F32(1.0 / 3.0),
            }
        );

        // Single precision floating point 17.9

        assert_eq!(
            tlv(&[0x0a, 0x33, 0x33, 0x8f, 0x41]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::F32(17.9),
            }
        );

        // Single precision floating point infinity

        assert_eq!(
            tlv(&[0x0a, 0x00, 0x00, 0x80, 0x7f]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::F32(f32::INFINITY),
            }
        );

        // Single precision floating point negative infinity

        assert_eq!(
            tlv(&[0x0a, 0x00, 0x00, 0x80, 0xff]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::F32(f32::NEG_INFINITY),
            }
        );

        // Double precision floating point 0.0

        assert_eq!(
            tlv(&[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::F64(0.0),
            }
        );

        // Double precision floating point (1.0 / 3.0)

        assert_eq!(
            tlv(&[0x0b, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xd5, 0x3f]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::F64(1.0 / 3.0),
            }
        );

        // Double precision floating point 17.9

        assert_eq!(
            tlv(&[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::F64(17.9),
            }
        );

        // Double precision floating point infinity (∞)

        assert_eq!(
            tlv(&[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::F64(f64::INFINITY),
            }
        );

        // Double precision floating point negative infinity

        assert_eq!(
            tlv(&[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::F64(f64::NEG_INFINITY),
            }
        );

        // Empty Structure, {}

        assert_eq!(
            tlv(&[0x15, 0x18]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Struct,
            }
        );

        assert!(TLVElement::new(&[0x15, 0x18])
            .structure()
            .unwrap()
            .iter()
            .next()
            .is_none());

        // Empty Array, []

        assert_eq!(
            tlv(&[0x16, 0x18]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Array,
            }
        );

        assert!(TLVElement::new(&[0x16, 0x18])
            .array()
            .unwrap()
            .iter()
            .next()
            .is_none());

        // Empty List, []

        assert_eq!(
            tlv(&[0x17, 0x18]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::List,
            }
        );

        assert!(TLVElement::new(&[0x17, 0x18])
            .list()
            .unwrap()
            .iter()
            .next()
            .is_none());

        // Structure, two context specific tags, Signed Intger, 1 octet values, {0 = 42, 1 = -17}

        let data = &[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18];

        assert_eq!(
            tlv(data),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Struct,
            }
        );

        let mut iter = TLVElement::new(data).structure().unwrap().iter();

        let s1 = iter.next().unwrap().unwrap();
        assert_eq!(s1.tag().unwrap(), TLVTag::Context(0));
        assert_eq!(s1.i32().unwrap(), 42);

        let s2 = iter.next().unwrap().unwrap();
        assert_eq!(s2.tag().unwrap(), TLVTag::Context(1));
        assert_eq!(s2.i16().unwrap(), -17);

        assert!(iter.next().is_none());

        // Array, Signed Integer, 1-octet values, [0, 1, 2, 3, 4]

        let data = &[
            0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x18,
        ];

        assert_eq!(
            tlv(data),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Array,
            }
        );

        let iter = TLVElement::new(data).array().unwrap().iter().enumerate();

        for (index, elem) in iter {
            let elem = elem.unwrap();

            assert_eq!(elem.tag().unwrap(), TLVTag::Anonymous);
            assert_eq!(elem.i8().unwrap(), index as i8);
        }

        // List, mix of anonymous and context tags, Signed Integer, 1 octet values, [[1, 0 = 42, 2, 3, 0 = -17]]

        let data = &[
            0x17, 0x00, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x02, 0x00, 0x03, 0x20, 0x00, 0xef, 0x18,
        ];

        assert_eq!(
            tlv(data),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::List,
            }
        );

        let expected = &[
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::S8(1),
            },
            TLV {
                tag: TLVTag::Context(0),
                value: TLVValue::S8(42),
            },
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::S8(2),
            },
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::S8(3),
            },
            TLV {
                tag: TLVTag::Context(0),
                value: TLVValue::S8(-17),
            },
        ];

        let mut iter = TLVElement::new(data).list().unwrap().iter();

        for elem in expected {
            assert_eq!(iter.next().unwrap().unwrap().tlv().unwrap(), *elem);
        }

        assert!(iter.next().is_none());

        // Array, mix of element types, [42, -170000, {}, 17.9, "Hello!"]

        let data = &[
            0x16, 0x00, 0x2a, 0x02, 0xf0, 0x67, 0xfd, 0xff, 0x15, 0x18, 0x0a, 0x33, 0x33, 0x8f,
            0x41, 0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x18,
        ];

        assert_eq!(
            tlv(data),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Array,
            }
        );

        let mut iter = TLVElement::new(data).array().unwrap().iter();

        assert_eq!(
            iter.next().unwrap().unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::S8(42),
            }
        );

        assert_eq!(
            iter.next().unwrap().unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::S32(-170000),
            }
        );

        assert_eq!(
            iter.next().unwrap().unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Struct,
            }
        );

        assert_eq!(
            iter.next().unwrap().unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::F32(17.9),
            }
        );

        assert_eq!(
            iter.next().unwrap().unwrap().tlv().unwrap(),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::Utf8l("Hello!"),
            }
        );

        // Anonymous tag, Unsigned Integer, 1-octet value, 42U

        assert_eq!(
            tlv(&[0x04, 0x2a]),
            TLV {
                tag: TLVTag::Anonymous,
                value: TLVValue::U8(42),
            }
        );

        // Context tag 1, Unsigned Integer, 1-octet value, 1 = 42U

        assert_eq!(
            tlv(&[0x24, 0x01, 0x2a]),
            TLV {
                tag: TLVTag::Context(1),
                value: TLVValue::U8(42),
            }
        );

        // Common profile tag 1, Unsigned Integer, 1-octet value, Matter::1 = 42U

        assert_eq!(
            tlv(&[0x44, 0x01, 0x00, 0x2a]),
            TLV {
                tag: TLVTag::CommonPrf16(1),
                value: TLVValue::U8(42),
            }
        );

        // Common profile tag 100000, Unsigned Integer, 1-octet value, Matter::100000 = 42U

        assert_eq!(
            tlv(&[0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a]),
            TLV {
                tag: TLVTag::CommonPrf32(100000),
                value: TLVValue::U8(42),
            }
        );

        // Fully qualified tag, Vendor ID 0xFFF1/65521, pro­file number 0xDEED/57069,
        // 2-octet tag 1, Unsigned Integer, 1-octet value 42, 65521::57069:1 = 42U

        assert_eq!(
            tlv(&[0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a]),
            TLV {
                tag: TLVTag::FullQual48 {
                    vendor_id: 65521,
                    profile: 57069,
                    tag: 1,
                },
                value: TLVValue::U8(42),
            }
        );

        // Fully qualified tag, Vendor ID 0xFFF1/65521, pro­file number 0xDEED/57069,
        // 4-octet tag 0xAA55FEED/2857762541, Unsigned Integer, 1-octet value 42, 65521::57069:2857762541 = 42U

        assert_eq!(
            tlv(&[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a]),
            TLV {
                tag: TLVTag::FullQual64 {
                    vendor_id: 65521,
                    profile: 57069,
                    tag: 2857762541,
                },
                value: TLVValue::U8(42),
            }
        );

        // Structure with the fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 2-octet tag 1. The structure contains a single ele­ment labeled using a fully qualified tag under
        // the same profile, with 2-octet tag 0xAA55/43605. 65521::57069:1 = {65521::57069:43605 = 42U}

        let data = &[
            0xd5, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0xc4, 0xf1, 0xff, 0xed, 0xde, 0x55, 0xaa,
            0x2a, 0x18,
        ];

        assert_eq!(
            tlv(data),
            TLV {
                tag: TLVTag::FullQual48 {
                    vendor_id: 65521,
                    profile: 57069,
                    tag: 1,
                },
                value: TLVValue::Struct,
            }
        );

        let mut iter = TLVElement::new(data).structure().unwrap().iter();

        let u1 = iter.next().unwrap().unwrap();

        assert_eq!(
            u1.tag().unwrap(),
            TLVTag::FullQual48 {
                vendor_id: 65521,
                profile: 57069,
                tag: 43605,
            }
        );

        assert_eq!(u1.u8().unwrap(), 42);

        assert!(iter.next().is_none());
    }
}
