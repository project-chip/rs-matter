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

//! TLV support for Rust built-in arrays.
//! Rust bilt-in arrays are serialized and deserialized as TLV arrays.
//!
//! The deserialization support requires `T` to implement `Default`, or else
//! the deserialization will not work for the cases where the deserialized TLV array
//! turns out to be shorter than the Rust array into which we deserialize.
//!
//! Note that the implementation below CANNOT efficiently in-place initialize the arrays,
//! as that would imply that the array elements should implement the unsafe `Zeroed` trait
//! instead of `Default`.
//! Since that would restrict the use-cases where built-in arrays can be utilized,
//! the implementation below requires `Default` instead for the array elements.
//!
//! Therefore, use `Vec` instead of built-in arrays if you need to efficiently in-place initialize
//! (potentially large) arrays.

use crate::error::{Error, ErrorCode};
use crate::utils::storage::Vec;

use super::{tlv_array_iter, FromTLV, TLVArray, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};

impl<'a, T, const N: usize> FromTLV<'a> for [T; N]
where
    T: FromTLV<'a> + Default,
{
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        let mut vec = Vec::<T, N>::new();

        for item in TLVArray::new(element.clone())? {
            vec.push(item?).map_err(|_| ErrorCode::NoSpace)?;
        }

        while !vec.is_full() {
            vec.push(Default::default())
                .map_err(|_| ErrorCode::NoSpace)?;
        }

        Ok(vec.into_array().map_err(|_| ErrorCode::NoSpace).unwrap())
    }

    fn check_from_tlv(element: &TLVElement<'a>) -> Result<(), Error> {
        let mut count = 0;

        while let Some(e) = element.clone().array()?.iter().next() {
            T::check_from_tlv(&e?)?;
            count += 1;
        }

        if count > N {
            Err(ErrorCode::NoSpace)?;
        }

        Ok(())
    }

    fn update_from_tlv(&mut self, element: &TLVElement<'a>) -> Result<(), Error> {
        Self::check_from_tlv(element)?;

        // Unwraps and indexing below should not trigger a panic, because we just checked the TLV data.

        let mut index = 0;

        for item in TLVArray::new(element.clone()).unwrap() {
            self[index] = item.unwrap();
            index += 1;
        }

        while index < self.len() {
            self[index] = Default::default();
            index += 1;
        }

        Ok(())
    }
}

impl<T, const N: usize> ToTLV for [T; N]
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
