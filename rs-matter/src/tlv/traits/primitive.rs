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

//! TLV support for Rust primitive types.

use crate::error::{Error, ErrorCode};

macro_rules! fromtlv_for {
    ($($t:ident)*) => {
        $(
            impl<'a> $crate::tlv::FromTLV<'a> for $t {
                fn from_tlv(element: &$crate::tlv::TLVElement<'a>) -> Result<Self, Error> {
                    element.$t()
                }
            }
        )*
    };
}

macro_rules! fromtlv_for_nonzero {
    ($($t:ident:$n:ty)*) => {
        $(
            impl<'a> $crate::tlv::FromTLV<'a> for $n {
                fn from_tlv(element: &$crate::tlv::TLVElement<'a>) -> Result<Self, Error> {
                    <$n>::new(element.$t()?).ok_or_else(|| ErrorCode::Invalid.into())
                }
            }
        )*
    };
}

macro_rules! totlv_for {
    ($($t:ident)*) => {
        $(
            impl $crate::tlv::ToTLV for $t {
                fn to_tlv<W: $crate::tlv::TLVWrite>(&self, tag: &$crate::tlv::TLVTag, mut tw: W) -> Result<(), Error> {
                    tw.$t(tag, *self)
                }

                fn tlv_iter(&self, tag: $crate::tlv::TLVTag) -> impl Iterator<Item = Result<$crate::tlv::TLV, Error>> {
                    $crate::tlv::TLV::$t(tag, *self).into_tlv_iter()
                }
            }
        )*
    };
}

macro_rules! totlv_for_nonzero {
    ($($t:ident:$n:ty)*) => {
        $(
            impl $crate::tlv::ToTLV for $n {
                fn to_tlv<W: $crate::tlv::TLVWrite>(&self, tag: &$crate::tlv::TLVTag, mut tw: W) -> Result<(), Error> {
                    tw.$t(tag, self.get())
                }

                fn tlv_iter(&self, tag: $crate::tlv::TLVTag) -> impl Iterator<Item = Result<$crate::tlv::TLV, Error>> {
                    $crate::tlv::TLV::$t(tag, self.get()).into_tlv_iter()
                }
            }
        )*
    };
}

fromtlv_for!(i8 u8 i16 u16 i32 u32 i64 u64 bool);
fromtlv_for_nonzero!(i8:core::num::NonZeroI8 u8:core::num::NonZeroU8 i16:core::num::NonZeroI16 u16:core::num::NonZeroU16 i32:core::num::NonZeroI32 u32:core::num::NonZeroU32 i64:core::num::NonZeroI64 u64:core::num::NonZeroU64);

totlv_for!(i8 u8 i16 u16 i32 u32 i64 u64 bool);
totlv_for_nonzero!(i8:core::num::NonZeroI8 u8:core::num::NonZeroU8 i16:core::num::NonZeroI16 u16:core::num::NonZeroU16 i32:core::num::NonZeroI32 u32:core::num::NonZeroU32 i64:core::num::NonZeroI64 u64:core::num::NonZeroU64);
