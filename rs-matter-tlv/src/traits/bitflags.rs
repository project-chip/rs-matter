/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! TLV support for `bitflags!`.
//! Bitflags are serialized and deserialized as TLV enumerations.

/// Implements to/from TLV for the given enumeration that was
/// created using `bitflags!`
///
/// NOTE:
///   - bitflgs are generally unrestricted. The provided implementations
///     do NOT attempt to validate flags for validity and the entire
///     range of flags will be marshalled (including unknown flags)
#[macro_export]
macro_rules! bitflags_tlv {
    ($enum_name:ident, $type:ident) => {
        impl<'a> $crate::FromTLV<'a> for $enum_name {
            fn from_tlv(
                element: &$crate::TLVElement<'a>,
            ) -> Result<Self, $crate::__private::Error> {
                Self::from_bits($crate::TLVElement::$type(element)?).ok_or_else(|| {
                    $crate::__private::Error::from($crate::__private::ErrorCode::InvalidData)
                })
            }

            fn nullable_from_tlv(
                element: &$crate::TLVElement<'a>,
            ) -> Result<Self, $crate::__private::Error> {
                let value = $crate::TLVElement::$type(element)?;

                if value != $type::MAX {
                    Self::from_bits(value).ok_or_else(|| {
                        $crate::__private::Error::from($crate::__private::ErrorCode::InvalidData)
                    })
                } else {
                    Err($crate::__private::ErrorCode::ConstraintError.into())
                }
            }
        }

        impl $crate::ToTLV for $enum_name {
            fn to_tlv<W: $crate::TLVWrite>(
                &self,
                tag: &$crate::TLVTag,
                mut tw: W,
            ) -> Result<(), $crate::__private::Error> {
                tw.$type(tag, self.bits())
            }

            fn tlv_iter(
                &self,
                tag: $crate::TLVTag,
            ) -> impl Iterator<Item = Result<$crate::TLV<'_>, $crate::__private::Error>> {
                $crate::TLV::$type(tag, self.bits()).into_tlv_iter()
            }

            fn nullable_to_tlv<W: $crate::TLVWrite>(
                &self,
                tag: &$crate::TLVTag,
                mut tw: W,
            ) -> Result<(), $crate::__private::Error> {
                if self.bits() != $type::MAX {
                    tw.$type(tag, self.bits())
                } else {
                    Err($crate::__private::ErrorCode::ConstraintError.into())
                }
            }

            fn nullable_tlv_iter(
                &self,
                tag: $crate::TLVTag,
            ) -> impl Iterator<Item = Result<$crate::TLV<'_>, $crate::__private::Error>> {
                if self.bits() != $type::MAX {
                    $crate::EitherIter::First($crate::TLV::$type(tag, self.bits()).into_tlv_iter())
                } else {
                    $crate::EitherIter::Second(core::iter::once(Err(
                        $crate::__private::ErrorCode::ConstraintError.into(),
                    )))
                }
            }
        }
    };
}
