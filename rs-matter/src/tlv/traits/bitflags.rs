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
        impl<'a> $crate::tlv::FromTLV<'a> for $enum_name {
            fn from_tlv(element: &$crate::tlv::TLVElement<'a>) -> Result<Self, Error> {
                // Ok(Self::from_bits_retain($crate::tlv::TLVElement::$type(
                //     element,
                // )?))
                // TODO: defmt
                Self::from_bits($crate::tlv::TLVElement::$type(element)?).ok_or_else(|| {
                    $crate::error::Error::from($crate::error::ErrorCode::InvalidData)
                })
            }
        }

        impl $crate::tlv::ToTLV for $enum_name {
            fn to_tlv<W: $crate::tlv::TLVWrite>(
                &self,
                tag: &$crate::tlv::TLVTag,
                mut tw: W,
            ) -> Result<(), Error> {
                tw.$type(tag, self.bits())
            }

            fn tlv_iter(
                &self,
                tag: $crate::tlv::TLVTag,
            ) -> impl Iterator<Item = Result<$crate::tlv::TLV, Error>> {
                $crate::tlv::TLV::$type(tag, self.bits()).into_tlv_iter()
            }
        }
    };
}
