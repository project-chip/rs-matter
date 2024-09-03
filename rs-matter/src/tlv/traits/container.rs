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

//! A container type (`TLVContainer`) and an iterator type (`TLVContainerIter`) that represent and iterate directly over serialized TLV containers.
//! As such, the memory prepresentation of `TLVContainer` and `TLVContainerIter` is just a byte slice (`&[u8]`),
//! and the container elements are materialized (with `FromTLV`) only when the container is iterated over.
//!
//! The difference between `TLVContainer` and `TLVContainerIter` on one side, and `TLVElement`, `TLVSequence` and `TLVSequenceIter` on the other
//! is that the former are generified by type `T: FromTLV<'_>` and can directly yield values of type `T` when iterated over,
//! while iterating over a `TLVSequence` with a `TLVSequenceIter` always yields elements of type `TLVElement`.
//!
//! Thus, a `TLVContainer<TLVElement<'_>, ()`> is equivalent to a `TLVElement` which represents a container and
//! `TLVContainerIter<TLVElement<'_>>` is equivalent to a `TLVSequenceIter<'_>` that is obtained by `element.container()?.iter()`.

use core::fmt;
use core::marker::PhantomData;

use crate::error::Error;
use crate::utils::init;

use super::{EitherIter, FromTLV, TLVElement, TLVSequenceIter, TLVTag, TLVWrite, ToTLV, TLV};

/// A type-state that indicates that the container can be any type of container (array, list or struct).
pub type AnyContainer = ();

/// A type-state that indicates that the container should be an array.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArrayContainer;

/// A type-state that indicates that the container should be a list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListContainer;

/// A type-state that indicates that the container should be a struct.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StructContainer;

/// A type alias for an array TLV container.
pub type TLVArray<'a, T> = TLVContainer<'a, T, ArrayContainer>;
/// A type alias for a list TLV container.
pub type TLVList<'a, T> = TLVContainer<'a, T, ListContainer>;
/// A type alias for a struct TLV container.
pub type TLVStruct<'a, T> = TLVContainer<'a, T, StructContainer>;

/// `TLVContainer` is an efficient (memory-wise) way to represent a serialized TLV container, in that
/// it does not materialize the container elements until the container is iterated over.
///
/// Therefore, `TLVContainer` is just a wrapper (newtype) of the serialized TLV container `&[u8]` slice.
#[derive(Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TLVContainer<'a, T, C = AnyContainer> {
    element: TLVElement<'a>,
    _type: PhantomData<fn() -> T>,
    _container_type: PhantomData<C>,
}

impl<'a, T, C> TLVContainer<'a, T, C>
where
    T: FromTLV<'a>,
{
    /// Creates a new `TLVContainer` from a TLV element.
    /// The constructor does not check whether the passed slice is a valid TLV container.
    pub const fn new_unchecked(element: TLVElement<'a>) -> Self {
        Self {
            element,
            _type: PhantomData,
            _container_type: PhantomData,
        }
    }

    pub fn element(&self) -> &TLVElement<'a> {
        &self.element
    }

    /// Returns an iterator over the elements of the container.
    pub fn iter(&self) -> TLVContainerIter<'a, T> {
        TLVContainerIter::new(self.element.container().unwrap().iter())
    }
}

impl<'a, T> TLVContainer<'a, T, AnyContainer>
where
    T: FromTLV<'a>,
{
    /// Creates a new `TLVContainer` from a TLV element that can be any container.
    pub fn new(element: TLVElement<'a>) -> Result<Self, Error> {
        if !element.is_empty() {
            element.container()?;
        }

        Ok(Self::new_unchecked(element))
    }
}

impl<'a, T> TLVContainer<'a, T, ArrayContainer>
where
    T: FromTLV<'a>,
{
    /// Creates a new `TLVContainer` from a TLV element that is expected to be of type array.
    pub fn new(element: TLVElement<'a>) -> Result<Self, Error> {
        if !element.is_empty() {
            element.array()?;
        }

        Ok(Self::new_unchecked(element))
    }
}

impl<'a, T> TLVContainer<'a, T, ListContainer>
where
    T: FromTLV<'a>,
{
    /// Creates a new `TLVContainer` from a TLV element that is expected to be of type list.
    pub fn new(element: TLVElement<'a>) -> Result<Self, Error> {
        if !element.is_empty() {
            element.list()?;
        }

        Ok(Self::new_unchecked(element))
    }
}

impl<'a, T> TLVContainer<'a, T, StructContainer>
where
    T: FromTLV<'a>,
{
    /// Creates a new `TLVContainer` from a TLV element that is expected to be of type struct.
    pub fn new(element: TLVElement<'a>) -> Result<Self, Error> {
        if !element.is_empty() {
            element.structure()?;
        }

        Ok(Self::new_unchecked(element))
    }
}

impl<'a, T, C> IntoIterator for TLVContainer<'a, T, C>
where
    T: FromTLV<'a>,
{
    type Item = Result<T, Error>;
    type IntoIter = TLVContainerIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T, C> IntoIterator for &TLVContainer<'a, T, C>
where
    T: FromTLV<'a>,
{
    type Item = Result<T, Error>;
    type IntoIter = TLVContainerIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T, C> fmt::Debug for TLVContainer<'a, T, C>
where
    T: FromTLV<'a> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;

        let mut first = true;

        for elem in self.iter() {
            if first {
                first = false;
            } else {
                write!(f, ", ")?;
            }

            write!(f, "{elem:?}")?;
        }

        write!(f, "]")
    }
}

impl<'a, T, C> FromTLV<'a> for TLVContainer<'a, T, C>
where
    T: FromTLV<'a>,
    C: 'a,
{
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        Ok(Self::new_unchecked(element.clone()))
    }
}

impl<'a, T, C> ToTLV for TLVContainer<'a, T, C> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        self.element.to_tlv(tag, tw)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>> {
        self.element.tlv_iter(tag)
    }
}

/// An iterator over a serialized TLV container.
#[repr(transparent)]
pub struct TLVContainerIter<'a, T> {
    iter: TLVSequenceIter<'a>,
    _type: PhantomData<fn() -> T>,
}

impl<'a, T> TLVContainerIter<'a, T>
where
    T: FromTLV<'a>,
{
    /// Create a new `TLVContainerIter` from a TLV sequence iterator.
    pub const fn new(iter: TLVSequenceIter<'a>) -> Self {
        Self {
            iter,
            _type: PhantomData,
        }
    }

    pub fn try_next(&mut self) -> Option<Result<T, Error>> {
        let tlv = self.iter.next()?;

        Some(tlv.and_then(|tlv| T::from_tlv(&tlv)))
    }

    pub fn try_next_init(&mut self) -> Option<Result<impl init::Init<T, Error> + 'a, Error>> {
        let tlv = self.iter.next()?;

        Some(tlv.map(|tlv| T::init_from_tlv(tlv)))
    }
}

impl<'a, T> Iterator for TLVContainerIter<'a, T>
where
    T: FromTLV<'a>,
{
    type Item = Result<T, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.try_next()
    }
}

/// A container type that can represent either a serialized TLV array or a slice of elements.
///
/// Necessary for the few cases in the code where deserialized TLV structures are mutated -
/// post deserialization - with custom array data.
#[derive(Debug, Clone)]
pub enum TLVArrayOrSlice<'a, T>
where
    T: FromTLV<'a>,
{
    Array(TLVArray<'a, T>),
    Slice(&'a [T]),
}

impl<'a, T> TLVArrayOrSlice<'a, T>
where
    T: FromTLV<'a>,
{
    /// Creates a new `TLVArrayOrSlice` from a TLV slice.
    pub const fn new_array(array: TLVArray<'a, T>) -> Self {
        Self::Array(array)
    }

    /// Creates a new `TLVArrayOrSlice` from a slice.
    pub const fn new_slice(slice: &'a [T]) -> Self {
        Self::Slice(slice)
    }

    /// Returns an iterator over the elements of the array.
    pub fn iter(&self) -> Result<TLVArrayOrSliceIter<'a, T>, Error> {
        match self {
            Self::Array(array) => Ok(TLVArrayOrSliceIter::Array(array.iter())),
            Self::Slice(slice) => Ok(TLVArrayOrSliceIter::Slice(slice.iter())),
        }
    }
}

impl<'a, T> FromTLV<'a> for TLVArrayOrSlice<'a, T>
where
    T: FromTLV<'a>,
{
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        Ok(Self::new_array(TLVArray::new(element.clone())?))
    }
}

impl<'a, T> ToTLV for TLVArrayOrSlice<'a, T>
where
    T: FromTLV<'a>,
    T: ToTLV,
{
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        match self {
            Self::Array(array) => array.to_tlv(tag, tw),
            Self::Slice(slice) => slice.to_tlv(tag, tw),
        }
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>> {
        match self {
            Self::Array(array) => EitherIter::First(array.tlv_iter(tag)),
            Self::Slice(slice) => EitherIter::Second(slice.tlv_iter(tag)),
        }
    }
}

/// An iterator over the `TLVArrayOrSlice` elements.
pub enum TLVArrayOrSliceIter<'a, T> {
    Array(TLVContainerIter<'a, T>),
    Slice(core::slice::Iter<'a, T>),
}

impl<'a, T> Iterator for TLVArrayOrSliceIter<'a, T>
where
    T: FromTLV<'a> + Clone,
{
    type Item = Result<T, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Array(array) => array.next(),
            Self::Slice(slice) => slice.next().cloned().map(|t| Ok(t)),
        }
    }
}

// impl<'a, T: ToTLV + FromTLV<'a> + Clone> TLVArray<'a, T> {
//     pub fn get_index(&self, index: usize) -> T {
//         for (curr, element) in self.iter().enumerate() {
//             if curr == index {
//                 return element;
//             }
//         }
//         panic!("Out of bounds");
//     }
// }

// // impl<'a, 'b, T> PartialEq<TLVArray<'b, T>> for TLVArray<'a, T>
// // where
// //     T: ToTLV + FromTLV<'a> + Clone + PartialEq,
// //     'b: 'a,
// // {
// //     fn eq(&self, other: &TLVArray<'b, T>) -> bool {
// //         let mut iter1 = self.iter();
// //         let mut iter2 = other.iter();
// //         loop {
// //             match (iter1.next(), iter2.next()) {
// //                 (None, None) => return true,
// //                 (Some(x), Some(y)) => {
// //                     if x != y {
// //                         return false;
// //                     }
// //                 }
// //                 _ => return false,
// //             }
// //         }
// //     }
// // }

// // impl<'a, T> PartialEq<&[T]> for TLVArray<'a, T>
// // where
// //     T: ToTLV + FromTLV<'a> + Clone + PartialEq,
// // {
// //     fn eq(&self, other: &&[T]) -> bool {
// //         let mut iter1 = self.iter();
// //         let mut iter2 = other.iter();
// //         loop {
// //             match (iter1.next(), iter2.next()) {
// //                 (None, None) => return true,
// //                 (Some(x), Some(y)) => {
// //                     if x != *y {
// //                         return false;
// //                     }
// //                 }
// //                 _ => return false,
// //             }
// //         }
// //     }
// // }

// impl<'a, T> FromTLV<'a> for TLVArray<'a, T> {
//     fn from_tlv(t: TLVElement<'a>) -> Result<Self, Error> {
//         TLVArray::new(t)
//     }
// }

// impl<'a, T> ToTLV for TLVArray<'a, T> {
//     fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
//         tw.start_array(tag_type)?;
//         for a in self.iter() {
//             a.to_tlv(tw, TagType::Anonymous)?;
//         }
//         tw.end_container()
//         // match *self {
//         //     Self::Slice(s) => {
//         //         tw.start_array(tag_type)?;
//         //         for a in s {
//         //             a.to_tlv(tw, TagType::Anonymous)?;
//         //         }
//         //         tw.end_container()
//         //     }
//         //     Self::Ptr(t) => t.to_tlv(tw, tag_type), <-- TODO: this fails the unit tests of Cert from/to TLV
//         // }
//     }

//     fn tlv_iter(&self, tag: TagType) -> impl Iterator<Item = u8> + '_ {
//         empty()
//             .start_array(tag)
//             .chain(self.iter().flat_map(move |i| i.into_tlv_iter(TagType::Anonymous)))
//             .end_container()
//     }

//     fn into_tlv_iter(self, tag: TagType) -> impl Iterator<Item = u8> where Self: Sized {
//         empty()
//             .start_array(tag)
//             .chain(self.into_iter().flat_map(move |i| i.into_tlv_iter(TagType::Anonymous)))
//             .end_container()
//     }
// }

// impl<'a, T: Debug + ToTLV + FromTLV<'a> + Clone> Debug for TLVArray<'a, T> {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         write!(f, "TLVArray [")?;
//         let mut first = true;
//         for i in self.iter() {
//             if !first {
//                 write!(f, ", ")?;
//             }

//             write!(f, "{:?}", i)?;
//             first = false;
//         }
//         write!(f, "]")
//     }
// }
