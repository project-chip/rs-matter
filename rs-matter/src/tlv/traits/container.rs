/*
 *
 *    Copyright (c) 2024-2025 Project CHIP Authors
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ArrayContainer;

/// A type-state that indicates that the container should be a list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ListContainer;

/// A type-state that indicates that the container should be a struct.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
        TLVContainerIter::new(unwrap!(self.element.container()).iter())
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
                write!(f, "{elem:?}")?;
            } else {
                write!(f, ", {elem:?}")?;
            }
        }

        write!(f, "]")
    }
}

#[cfg(feature = "defmt")]
impl<'a, T, C> defmt::Format for TLVContainer<'a, T, C>
where
    T: FromTLV<'a> + defmt::Format,
{
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "[");

        let mut first = true;

        for elem in self.iter() {
            if first {
                first = false;
                defmt::write!(f, "{:?}", elem);
            } else {
                defmt::write!(f, ", {:?}", elem);
            }
        }

        defmt::write!(f, "]")
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

impl<T, C> ToTLV for TLVContainer<'_, T, C> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        self.element.to_tlv(tag, tw)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
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

// impl<'a, T: Debug + ToTLV + FromTLV<'a> + Clone> Debug for TLVArray<'a, T> { // TODO: defmt
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use core::mem::MaybeUninit;

    use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};
    use crate::utils::init::InitMaybeUninit;
    use crate::utils::storage::WriteBuf;

    use super::{TLVArray, TLVArrayOrSlice, TLVContainer, TLVList, TLVStruct};

    const ARRAY: &[u8] = &[0x16, 0x04, 1, 0x04, 2, 0x18];
    const LIST: &[u8] = &[0x17, 0x04, 1, 0x18];
    const STRUCT: &[u8] = &[0x15, 0x24, 0, 1, 0x18];
    const SCALAR: &[u8] = &[0x04, 1];

    #[derive(FromTLV, Debug, PartialEq)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    struct Pair {
        a: u8,
        b: u16,
    }

    #[test]
    fn typed_constructors_check_container_type() {
        assert!(TLVArray::<u8>::new(TLVElement::new(ARRAY)).is_ok());
        assert!(TLVArray::<u8>::new(TLVElement::new(LIST)).is_err());
        assert!(TLVArray::<u8>::new(TLVElement::new(STRUCT)).is_err());
        assert!(TLVArray::<u8>::new(TLVElement::new(SCALAR)).is_err());

        assert!(TLVList::<u8>::new(TLVElement::new(LIST)).is_ok());
        assert!(TLVList::<u8>::new(TLVElement::new(ARRAY)).is_err());
        assert!(TLVList::<u8>::new(TLVElement::new(SCALAR)).is_err());

        assert!(TLVStruct::<u8>::new(TLVElement::new(STRUCT)).is_ok());
        assert!(TLVStruct::<u8>::new(TLVElement::new(LIST)).is_err());
        assert!(TLVStruct::<u8>::new(TLVElement::new(SCALAR)).is_err());

        // The untyped container accepts any container kind, but still no scalars
        assert!(TLVContainer::<u8>::new(TLVElement::new(ARRAY)).is_ok());
        assert!(TLVContainer::<u8>::new(TLVElement::new(LIST)).is_ok());
        assert!(TLVContainer::<u8>::new(TLVElement::new(STRUCT)).is_ok());
        assert!(TLVContainer::<u8>::new(TLVElement::new(SCALAR)).is_err());

        // An empty element is accepted by every constructor
        assert!(TLVArray::<u8>::new(TLVElement::new(&[])).is_ok());
        assert!(TLVList::<u8>::new(TLVElement::new(&[])).is_ok());
        assert!(TLVStruct::<u8>::new(TLVElement::new(&[])).is_ok());
        assert!(TLVContainer::<u8>::new(TLVElement::new(&[])).is_ok());

        // `new_unchecked` performs no validation and exposes the wrapped element as-is
        let arr = TLVArray::<u8>::new_unchecked(TLVElement::new(SCALAR));
        assert_eq!(arr.element(), &TLVElement::new(SCALAR));
    }

    #[test]
    fn iter_yields_typed_values_in_order() {
        let arr = TLVArray::<u8>::new(TLVElement::new(ARRAY)).unwrap();
        assert!(arr.iter().map(Result::unwrap).eq([1, 2]));
        assert!((&arr).into_iter().map(Result::unwrap).eq([1, 2]));
        assert!(arr.into_iter().map(Result::unwrap).eq([1, 2]));

        let list = TLVList::<u8>::new(TLVElement::new(LIST)).unwrap();
        assert!(list.iter().map(Result::unwrap).eq([1]));

        // Struct elements: every field is materialized as `T` regardless of its context tag
        let strct = TLVStruct::<u8>::new(TLVElement::new(STRUCT)).unwrap();
        assert!(strct.iter().map(Result::unwrap).eq([1]));

        // Nested: an array of structs and an array of arrays
        let mut buf = [0; 32];
        let mut wb = WriteBuf::new(&mut buf);
        wb.start_array(&TLVTag::Anonymous).unwrap();
        wb.start_struct(&TLVTag::Anonymous).unwrap();
        wb.u8(&TLVTag::Context(0), 1).unwrap();
        wb.u16(&TLVTag::Context(1), 0x1234).unwrap();
        wb.end_container().unwrap();
        wb.start_struct(&TLVTag::Anonymous).unwrap();
        wb.u8(&TLVTag::Context(0), 2).unwrap();
        wb.u16(&TLVTag::Context(1), 3).unwrap();
        wb.end_container().unwrap();
        wb.end_container().unwrap();

        let pairs = TLVArray::<Pair>::new(TLVElement::new(wb.as_slice())).unwrap();
        assert!(pairs
            .iter()
            .map(Result::unwrap)
            .eq([Pair { a: 1, b: 0x1234 }, Pair { a: 2, b: 3 }]));

        wb.reset();
        wb.start_array(&TLVTag::Anonymous).unwrap();
        wb.start_array(&TLVTag::Anonymous).unwrap();
        wb.u8(&TLVTag::Anonymous, 1).unwrap();
        wb.end_container().unwrap();
        wb.start_array(&TLVTag::Anonymous).unwrap();
        wb.end_container().unwrap();
        wb.end_container().unwrap();

        let outer = TLVArray::<TLVArray<u8>>::new(TLVElement::new(wb.as_slice())).unwrap();
        let mut outer_iter = outer.iter();
        let inner = outer_iter.next().unwrap().unwrap();
        assert!(inner.iter().map(Result::unwrap).eq([1]));
        let inner = outer_iter.next().unwrap().unwrap();
        assert_eq!(inner.iter().count(), 0);
        assert!(outer_iter.next().is_none());
    }

    #[test]
    fn iter_reports_type_mismatch_and_truncation() {
        // A UTF-8 string where a `u8` is expected fails at materialization,
        // the preceding element is still delivered
        let mixed = [0x16, 0x04, 1, 0x0C, 1, b'x', 0x18];
        let arr = TLVArray::<u8>::new(TLVElement::new(&mixed)).unwrap();
        let mut iter = arr.iter();
        assert_eq!(iter.next().unwrap().unwrap(), 1);
        assert!(iter.next().unwrap().is_err());

        // A truncated stream fails when the iterator reaches the cut
        let truncated = [0x16, 0x04, 1, 0x04];
        let arr = TLVArray::<u8>::new(TLVElement::new(&truncated)).unwrap();
        let mut iter = arr.iter();
        assert_eq!(iter.next().unwrap().unwrap(), 1);
        assert!(matches!(iter.next(), Some(Err(_))));
    }

    #[test]
    fn try_next_init_materializes_in_place() {
        let arr = TLVArray::<u8>::new(TLVElement::new(ARRAY)).unwrap();
        let mut iter = arr.iter();

        let init = iter.try_next_init().unwrap().unwrap();
        let mut slot = MaybeUninit::<u8>::uninit();
        assert_eq!(*slot.try_init_with(init).unwrap(), 1);

        let init = iter.try_next_init().unwrap().unwrap();
        let mut slot = MaybeUninit::<u8>::uninit();
        assert_eq!(*slot.try_init_with(init).unwrap(), 2);

        assert!(iter.try_next_init().is_none());
        assert!(iter.try_next().is_none());
    }

    #[test]
    fn debug_lists_elements() {
        let arr = TLVArray::<u8>::new(TLVElement::new(ARRAY)).unwrap();
        assert_eq!(format!("{arr:?}"), "[Ok(1), Ok(2)]");

        let empty = TLVArray::<u8>::new(TLVElement::new(&[0x16, 0x18])).unwrap();
        assert_eq!(format!("{empty:?}"), "[]");
    }

    #[test]
    fn to_tlv_and_from_tlv_preserve_bytes() {
        let tagged = [0x36, 3, 0x04, 1, 0x04, 2, 0x18];
        let arr = TLVArray::<u8>::from_tlv(&TLVElement::new(&tagged)).unwrap();
        assert!(arr.iter().map(Result::unwrap).eq([1, 2]));

        let mut buf = [0; 16];
        let mut wb = WriteBuf::new(&mut buf);

        // Same tag: identical bytes
        arr.to_tlv(&TLVTag::Context(3), &mut wb).unwrap();
        assert_eq!(wb.as_slice(), &tagged);

        // Different tag: only the tag changes
        wb.reset();
        arr.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        assert_eq!(wb.as_slice(), ARRAY);
    }

    #[test]
    fn tlv_iter_matches_to_tlv() {
        let arr = TLVArray::<u8>::from_tlv(&TLVElement::new(ARRAY)).unwrap();

        let mut buf = [0; 16];
        let mut wb = WriteBuf::new(&mut buf);
        for byte in arr
            .tlv_iter(TLVTag::Anonymous)
            .flat_map(TLV::result_into_bytes_iter)
        {
            wb.append(&[byte.unwrap()]).unwrap();
        }
        assert_eq!(wb.as_slice(), ARRAY);

        let slice = TLVArrayOrSlice::new_slice(&[1u8, 2]);
        let array = TLVArrayOrSlice::<u8>::from_tlv(&TLVElement::new(ARRAY)).unwrap();
        for variant in [&slice, &array] {
            wb.reset();
            for byte in variant
                .tlv_iter(TLVTag::Anonymous)
                .flat_map(TLV::result_into_bytes_iter)
            {
                wb.append(&[byte.unwrap()]).unwrap();
            }
            assert_eq!(wb.as_slice(), ARRAY);
        }
    }

    #[test]
    fn array_or_slice_iterates_both_variants() {
        let slice = TLVArrayOrSlice::new_slice(&[1u8, 2]);
        assert!(slice.iter().unwrap().map(Result::unwrap).eq([1, 2]));

        let array = TLVArrayOrSlice::<u8>::from_tlv(&TLVElement::new(ARRAY)).unwrap();
        assert!(matches!(array, TLVArrayOrSlice::Array(_)));
        assert!(array.iter().unwrap().map(Result::unwrap).eq([1, 2]));

        // Only arrays are accepted when deserializing
        assert!(TLVArrayOrSlice::<u8>::from_tlv(&TLVElement::new(STRUCT)).is_err());

        // Both variants serialize to the same bytes
        let mut buf = [0; 16];
        let mut wb = WriteBuf::new(&mut buf);
        slice.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        assert_eq!(wb.as_slice(), ARRAY);

        wb.reset();
        array.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        assert_eq!(wb.as_slice(), ARRAY);
    }
}
