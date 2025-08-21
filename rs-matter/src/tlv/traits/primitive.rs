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

macro_rules! fromtlv_for_num {
    ($($t:ident)*) => {
        $(
            impl<'a> $crate::tlv::FromTLV<'a> for $t {
                fn from_tlv(element: &$crate::tlv::TLVElement<'a>) -> Result<Self, Error> {
                    element.$t()
                }

                fn nullable_from_tlv(element: &$crate::tlv::TLVElement<'a>) -> Result<Self, Error> {
                    let value = element.$t()?;

                    let in_range = if $t::MIN == 0 {
                        value != $t::MAX
                    } else {
                        value != $t::MIN
                    };

                    if in_range {
                        Ok(value)
                    } else {
                        Err(ErrorCode::ConstraintError.into())
                    }
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

                fn nullable_from_tlv(element: &$crate::tlv::TLVElement<'a>) -> Result<Self, Error> {
                    let value = element.$t()?;

                    let in_range = if $t::MIN == 0 {
                        value != $t::MAX
                    } else {
                        value != $t::MIN
                    };

                    if in_range {
                        <$n>::new(value).ok_or_else(|| ErrorCode::Invalid.into())
                    } else {
                        Err(ErrorCode::ConstraintError.into())
                    }
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

                fn tlv_iter(&self, tag: $crate::tlv::TLVTag) -> impl Iterator<Item = Result<$crate::tlv::TLV<'_>, Error>> {
                    $crate::tlv::TLV::$t(tag, *self).into_tlv_iter()
                }
            }
        )*
    };
}

macro_rules! totlv_for_num {
    ($($t:ident)*) => {
        $(
            impl $crate::tlv::ToTLV for $t {
                fn to_tlv<W: $crate::tlv::TLVWrite>(&self, tag: &$crate::tlv::TLVTag, mut tw: W) -> Result<(), Error> {
                    tw.$t(tag, *self)
                }

                fn tlv_iter(&self, tag: $crate::tlv::TLVTag) -> impl Iterator<Item = Result<$crate::tlv::TLV<'_>, Error>> {
                    $crate::tlv::TLV::$t(tag, *self).into_tlv_iter()
                }

                fn nullable_to_tlv<W: $crate::tlv::TLVWrite>(&self, tag: &$crate::tlv::TLVTag, mut tw: W) -> Result<(), Error> {
                    let in_range = if $t::MIN == 0 {
                        *self != $t::MAX
                    } else {
                        *self != $t::MIN
                    };

                    if in_range {
                        tw.$t(tag, *self)
                    } else {
                        Err(ErrorCode::ConstraintError.into())
                    }
                }

                fn nullable_tlv_iter(&self, tag: $crate::tlv::TLVTag) -> impl Iterator<Item = Result<$crate::tlv::TLV<'_>, Error>> {
                    let in_range = if $t::MIN == 0 {
                        *self != $t::MAX
                    } else {
                        *self != $t::MIN
                    };

                    if in_range {
                        $crate::tlv::EitherIter::First($crate::tlv::TLV::$t(tag, *self).into_tlv_iter())
                    } else {
                        $crate::tlv::EitherIter::Second(core::iter::once(Err(ErrorCode::ConstraintError.into())))
                    }
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

                fn tlv_iter(&self, tag: $crate::tlv::TLVTag) -> impl Iterator<Item = Result<$crate::tlv::TLV<'_>, Error>> {
                    $crate::tlv::TLV::$t(tag, self.get()).into_tlv_iter()
                }

                fn nullable_to_tlv<W: $crate::tlv::TLVWrite>(&self, tag: &$crate::tlv::TLVTag, mut tw: W) -> Result<(), Error> {
                    let in_range = if $t::MIN == 0 {
                        self.get() != $t::MAX
                    } else {
                        self.get() != $t::MIN
                    };

                    if in_range {
                        tw.$t(tag, self.get())
                    } else {
                        Err(ErrorCode::ConstraintError.into())
                    }
                }

                fn nullable_tlv_iter(&self, tag: $crate::tlv::TLVTag) -> impl Iterator<Item = Result<$crate::tlv::TLV<'_>, Error>> {
                    let in_range = if $t::MIN == 0 {
                        self.get() != $t::MAX
                    } else {
                        self.get() != $t::MIN
                    };

                    if in_range {
                        $crate::tlv::EitherIter::First($crate::tlv::TLV::$t(tag, self.get()).into_tlv_iter())
                    } else {
                        $crate::tlv::EitherIter::Second(core::iter::once(Err(ErrorCode::ConstraintError.into())))
                    }
                }
            }
        )*
    };
}

fromtlv_for!(f32 f64 bool);
fromtlv_for_num!(i8 u8 i16 u16 i32 u32 i64 u64);
fromtlv_for_nonzero!(i8:core::num::NonZeroI8 u8:core::num::NonZeroU8 i16:core::num::NonZeroI16 u16:core::num::NonZeroU16 i32:core::num::NonZeroI32 u32:core::num::NonZeroU32 i64:core::num::NonZeroI64 u64:core::num::NonZeroU64);

totlv_for!(f32 f64 bool);
totlv_for_num!(i8 u8 i16 u16 i32 u32 i64 u64);
totlv_for_nonzero!(i8:core::num::NonZeroI8 u8:core::num::NonZeroU8 i16:core::num::NonZeroI16 u16:core::num::NonZeroU16 i32:core::num::NonZeroI32 u32:core::num::NonZeroU32 i64:core::num::NonZeroI64 u64:core::num::NonZeroU64);
