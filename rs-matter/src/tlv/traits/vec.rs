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

//! TLV support for the `Vec<T, N>` type.
//! `Vec<T, N>` is serialized and deserialized as a TLV array.
//!
//! Unlike Rust `[T; N]` arrays, the `Vec` type can be efficiently deserialized in-place, so use it
//! when the array holds large structures (like fabrics, certificates, sessions and so on).
//!
//! Of course, the `Vec` type is always owned (even if the deserialized elements `T` do borrow from the
//! deserializer), so it might consume more memory than necessary, as its memory is statically allocated
//! to be N * size_of(T) bytes.
//!
//! For cases where the array does not need to be owned and instantiating `T` elements on the fly when
//! traversing the array is tolerable (i.e. `T` is small enough), prefer `TLVArray`, which operates
//! directly on the borrowed, encoded TLV representation of the whole array.

use crate::error::{Error, ErrorCode};
use crate::utils::init::{self, IntoFallibleInit};
use crate::utils::storage::Vec;

use super::{slice::tlv_array_iter, FromTLV, TLVArray, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};

impl<'a, T, const N: usize> FromTLV<'a> for Vec<T, N>
where
    T: FromTLV<'a> + 'a,
{
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        let mut vec = Vec::<T, N>::new();

        for item in TLVArray::new(element.clone())? {
            vec.push(item?).map_err(|_| ErrorCode::NoSpace)?;
        }

        Ok(vec)
    }

    fn init_from_tlv(tlv: TLVElement<'a>) -> impl init::Init<Self, Error> {
        init::Init::chain(Vec::<T, N>::init().into_fallible(), move |vec| {
            let mut iter = TLVArray::new(tlv)?.iter();

            while let Some(item) = iter.try_next_init() {
                vec.push_init(item?, || ErrorCode::NoSpace.into())?;
            }

            Ok(())
        })
    }
}

impl<T, const N: usize> ToTLV for Vec<T, N>
where
    T: ToTLV,
{
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        self.as_slice().to_tlv(tag, tw)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>> {
        tlv_array_iter(tag, self.iter())
    }
}
