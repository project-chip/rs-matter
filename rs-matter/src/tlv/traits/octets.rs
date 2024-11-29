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

//! TLV support for octet strings (i.e. byte arrays).
//!
//! Support is provided via two dedicated newtypes:
//! - `Octets<'a>` newtype which wraps an ordinary `&[u8]` - for borrowed byte arrays
//! - `OctetsOwned<const N>` newtype which wraps a `Vec<u8, N>` for owned byte arrays of fixed length N
//!
//! Newtype wrapping is necessary because naked Rust slices, arrays and the naked `Vec` type
//! serialize and deserialize as TLV arrays, rather than as octet strings.
//!
//! I.e. serializing `[0; 3]` will result in a TLV array with 3 elements of type u8 and value 0, rather than a TLV
//! octet string containing 3 zero bytes.

use core::borrow::{Borrow, BorrowMut};
use core::fmt::Debug;
use core::hash::Hash;
use core::ops::{Deref, DerefMut};

use crate::error::{Error, ErrorCode};
use crate::utils::init::{self, init, IntoFallibleInit};
use crate::utils::storage::Vec;

use super::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};

/// For backwards compatibility
pub type OctetStr<'a> = Octets<'a>;

/// For backwards compatibility
pub type OctetStrOwned<const N: usize> = OctetsOwned<N>;

/// Newtype for borrowed byte arrays
///
/// When deserializing, this type grabs the octet slice directly from the `TLVElement`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct Octets<'a>(pub &'a [u8]);

impl<'a> Octets<'a> {
    pub const fn new(slice: &'a [u8]) -> Self {
        Self(slice)
    }
}

impl Deref for Octets<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> FromTLV<'a> for Octets<'a> {
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        Ok(Octets(element.str()?))
    }
}

impl ToTLV for Octets<'_> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.str(tag, self.0)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>> {
        TLV::str(tag, self.0).into_tlv_iter()
    }
}

/// Newtype for owned byte arrays with a fixed maximum length
/// (represented by a `Vec<u8, N>`)
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct OctetsOwned<const N: usize> {
    pub vec: Vec<u8, N>,
}

impl<const N: usize> Default for OctetsOwned<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> OctetsOwned<N> {
    /// Create a new empty `OctetsOwned` instance
    pub const fn new() -> Self {
        Self {
            vec: Vec::<u8, N>::new(),
        }
    }

    /// Create an in-place initializer for an empty `OctetsOwned` instance
    pub fn init() -> impl init::Init<Self> {
        init!(Self {
            vec <- Vec::<u8, N>::init(),
        })
    }
}

impl<const N: usize> Borrow<[u8]> for OctetsOwned<N> {
    fn borrow(&self) -> &[u8] {
        &self.vec
    }
}

impl<const N: usize> BorrowMut<[u8]> for OctetsOwned<N> {
    fn borrow_mut(&mut self) -> &mut [u8] {
        &mut self.vec
    }
}

impl<const N: usize> Deref for OctetsOwned<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.vec
    }
}

impl<const N: usize> DerefMut for OctetsOwned<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vec
    }
}

impl<'a, const N: usize> FromTLV<'a> for OctetsOwned<N> {
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        Ok(Self {
            vec: element.str()?.try_into().map_err(|_| ErrorCode::NoSpace)?,
        })
    }

    fn init_from_tlv(element: TLVElement<'a>) -> impl init::Init<Self, Error> {
        init::Init::chain(OctetsOwned::init().into_fallible(), move |bytes| {
            bytes
                .vec
                .extend_from_slice(element.str()?)
                .map_err(|_| ErrorCode::NoSpace)?;

            Ok(())
        })
    }
}

impl<const N: usize> ToTLV for OctetsOwned<N> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.str(tag, &self.vec)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>> {
        TLV::str(tag, self.vec.as_slice()).into_tlv_iter()
    }
}
