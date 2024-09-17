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

//! TLV support for octets representing valid utf8 sequences (i.e. utf8 strings).
//!
//! - `&str` is used for serializing and deserializing borrowed utf8 strings
//! - `String<N>` (from `heapless`) is used for serializing and deserializing owned strings of fixed length N
//!
//! Note that (for now) `String<N>` has no efficient in-place initialization, so it should not be used for
//! holding large strings, or else a stack overflow might occur.

use heapless::String;

use crate::error::{Error, ErrorCode};

use super::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};

/// For (partial) backwards compatibility
///
/// Partial because `UtfStr` used to be a newtype rather than a type alias,
/// and - furthermore - used to expose the Utf8 octets as raw bytes
/// rather than as the native Rust `str` type. The reason for that is probably
/// a misundersatanding that Utf16l, Utf32l and Utf64l are not UTF-8 strings,
/// while they actually are. Simply their length prefix is encoded variably.
pub type UtfStr<'a> = Utf8Str<'a>;

/// Necessary because the `FromTLV` proc macro impl currently cannot handle
/// reference types.
///
/// This restriction might be lifted in the future.
pub type Utf8Str<'a> = &'a str;

impl<'a> FromTLV<'a> for &'a str {
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        element.utf8()
    }
}

impl ToTLV for &str {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.utf8(tag, self)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        TLV::utf8(tag, self).into_tlv_iter()
    }
}

impl<'a, const N: usize> FromTLV<'a> for String<N> {
    fn from_tlv(element: &TLVElement<'a>) -> Result<String<N>, Error> {
        element
            .utf8()
            .and_then(|s| s.try_into().map_err(|_| ErrorCode::NoSpace.into()))
    }
}

impl<const N: usize> ToTLV for String<N> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.utf8(tag, self)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        TLV::utf8(tag, self.as_str()).into_tlv_iter()
    }
}
