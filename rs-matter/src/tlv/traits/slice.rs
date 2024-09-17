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

//! TLV support for Rust slices `&[T]`.
//! Rust slices are serialized as TLV arrays.
//!
//! Note that only serialization `(trait `ToTLV`) is supported for Rust slices,
//! because deserialization (`FromTLV`) requires the deserialized Rust type
//! to be `Sized`, which slices aren't.
//!
//! (Deserializing strings as `&str` and octets as `Bytes<'a>` (which is really a newtype over
//! `&'a [u8]`) is supported, but that's because their deserialization works by borrowing their
//! content 1:1 from inside the byte slice of the `TLVElement`, which is not possible for a generic
//! `T` and only possible when `T` is a `u8`.)

use crate::error::Error;

use super::{TLVTag, TLVValue, TLVWrite, ToTLV, TLV};

/// This type alias is necessary, because `FromTLV` / `ToTLV` do not (yet) support
/// members that are slices.
///
/// Therefore, use `Slice<'a, T>` instead of `&'a [T]` as a syntax in your structs.
pub type Slice<'a, T> = &'a [T];

impl<'a, T: ToTLV> ToTLV for &'a [T]
where
    T: ToTLV,
{
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        to_tlv_array(tag, self.iter(), tw)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        tlv_array_iter(tag, self.iter())
    }
}

// TODO: Uncomment once `feature(impl_trait_in_assoc_type)` is stable
// pub struct IntoTLVIter<'a, T>(pub &'a TLVTag, pub T);

// impl<'a, T> IntoIterator for IntoTLVIter<'a, &'a [T]>
// where
//     T: ToTLV + 'a,
// {
//     type Item = Result<TLV<'a>, Error>;
//     type IntoIter = impl Iterator<Item = Self::Item>;

//     fn into_iter(self) -> Self::IntoIter {
//         tlv_array_iter(self.0.clone(), self.1.iter())
//     }
// }

pub(crate) fn to_tlv_array<I, W>(tag: &TLVTag, iter: I, mut tw: W) -> Result<(), Error>
where
    I: Iterator,
    I::Item: ToTLV,
    W: TLVWrite,
{
    tw.start_array(tag)?;

    for i in iter {
        i.to_tlv(&TLVTag::Anonymous, &mut tw)?;
    }

    tw.end_container()
}

pub(crate) fn tlv_array_iter<'s, I, T>(
    tag: TLVTag,
    iter: I,
) -> impl Iterator<Item = Result<TLV<'s>, Error>>
where
    I: Iterator<Item = &'s T> + 's,
    T: ToTLV + 's,
{
    tlv_container_iter(TLV::new(tag, TLVValue::Array), iter)
}

pub(crate) fn tlv_container_iter<'s, I, T>(
    tlv: TLV<'s>,
    iter: I,
) -> impl Iterator<Item = Result<TLV<'s>, Error>> + 's
where
    I: Iterator<Item = &'s T> + 's,
    T: ToTLV + 's,
{
    tlv.into_tlv_iter()
        .chain(iter.flat_map(|t| t.tlv_iter(TLVTag::Anonymous)))
        .chain(TLV::end_container().into_tlv_iter())
}
