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

use super::{ElementType, TLVContainerIterator, TLVElement, TLVWriter, TagType};
use crate::error::{Error, ErrorCode};
use core::fmt::Debug;
use core::slice::Iter;
use log::error;

pub trait FromTLV<'a> {
    fn from_tlv(t: &TLVElement<'a>) -> Result<Self, Error>
    where
        Self: Sized;

    // I don't think anybody except Option<T> will define this
    fn tlv_not_found() -> Result<Self, Error>
    where
        Self: Sized,
    {
        Err(ErrorCode::TLVNotFound.into())
    }
}

impl<'a, T: FromTLV<'a> + Default, const N: usize> FromTLV<'a> for [T; N] {
    fn from_tlv(t: &TLVElement<'a>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        t.confirm_array()?;

        let mut a = heapless::Vec::<T, N>::new();
        if let Some(tlv_iter) = t.enter() {
            for element in tlv_iter {
                a.push(T::from_tlv(&element)?)
                    .map_err(|_| ErrorCode::NoSpace)?;
            }
        }

        // TODO: This was the old behavior before rebasing the
        // implementation on top of heapless::Vec (to avoid requiring Copy)
        // Not sure why we actually need that yet, but without it unit tests fail
        while a.len() < N {
            a.push(Default::default()).map_err(|_| ErrorCode::NoSpace)?;
        }

        a.into_array().map_err(|_| ErrorCode::Invalid.into())
    }
}

pub fn from_tlv<'a, T: FromTLV<'a>, const N: usize>(
    vec: &mut heapless::Vec<T, N>,
    t: &TLVElement<'a>,
) -> Result<(), Error> {
    vec.clear();

    t.confirm_array()?;

    if let Some(tlv_iter) = t.enter() {
        for element in tlv_iter {
            vec.push(T::from_tlv(&element)?)
                .map_err(|_| ErrorCode::NoSpace)?;
        }
    }

    Ok(())
}

macro_rules! fromtlv_for {
    ($($t:ident)*) => {
        $(
            impl<'a> FromTLV<'a> for $t {
                fn from_tlv(t: &TLVElement) -> Result<Self, Error> {
                    t.$t()
                }
            }
        )*
    };
}

fromtlv_for!(i8 u8 i16 u16 i32 u32 i64 u64 bool);

pub trait ToTLV {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error>;
}

impl<T> ToTLV for &T
where
    T: ToTLV,
{
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        (**self).to_tlv(tw, tag)
    }
}

macro_rules! totlv_for {
    ($($t:ident)*) => {
        $(
            impl ToTLV for $t {
                fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
                    tw.$t(tag, *self)
                }
            }
        )*
    };
}

impl<T: ToTLV, const N: usize> ToTLV for [T; N] {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        tw.start_array(tag)?;
        for i in self {
            i.to_tlv(tw, TagType::Anonymous)?;
        }
        tw.end_container()
    }
}

impl<'a, T: ToTLV> ToTLV for &'a [T] {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        tw.start_array(tag)?;
        for i in *self {
            i.to_tlv(tw, TagType::Anonymous)?;
        }
        tw.end_container()
    }
}

// Generate ToTLV for standard data types
totlv_for!(i8 u8 i16 u16 i32 u32 i64 u64 bool);

// We define a few common data types that will be required here
//
// - UtfStr, OctetStr: These are versions that map to utfstr and ostr in the TLV spec
//     - These only have references into the original list
// - heapless::String<N>, Vheapless::ec<u8, N>: Is the owned version of utfstr and ostr, data is cloned into this
//     - heapless::String is only partially implemented
//
// - TLVArray: Is an array of entries, with reference within the original list

/// Implements UTFString from the spec
#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub struct UtfStr<'a>(pub &'a [u8]);

impl<'a> UtfStr<'a> {
    pub const fn new(str: &'a [u8]) -> Self {
        Self(str)
    }

    pub fn as_str(&self) -> Result<&str, Error> {
        core::str::from_utf8(self.0).map_err(|_| ErrorCode::Invalid.into())
    }
}

impl<'a> ToTLV for UtfStr<'a> {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        tw.utf16(tag, self.0)
    }
}

impl<'a> FromTLV<'a> for UtfStr<'a> {
    fn from_tlv(t: &TLVElement<'a>) -> Result<UtfStr<'a>, Error> {
        t.slice().map(UtfStr)
    }
}

/// Implements OctetString from the spec
#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub struct OctetStr<'a>(pub &'a [u8]);

impl<'a> OctetStr<'a> {
    pub fn new(str: &'a [u8]) -> Self {
        Self(str)
    }
}

impl<'a> FromTLV<'a> for OctetStr<'a> {
    fn from_tlv(t: &TLVElement<'a>) -> Result<OctetStr<'a>, Error> {
        t.slice().map(OctetStr)
    }
}

impl<'a> ToTLV for OctetStr<'a> {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        tw.str16(tag, self.0)
    }
}

/// Implements the Owned version of Octet String
impl<const N: usize> FromTLV<'_> for heapless::Vec<u8, N> {
    fn from_tlv(t: &TLVElement) -> Result<heapless::Vec<u8, N>, Error> {
        heapless::Vec::from_slice(t.slice()?).map_err(|_| ErrorCode::NoSpace.into())
    }
}

impl<const N: usize> ToTLV for heapless::Vec<u8, N> {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        tw.str16(tag, self.as_slice())
    }
}

/// Implements the Owned version of UTF String
impl<const N: usize> FromTLV<'_> for heapless::String<N> {
    fn from_tlv(t: &TLVElement) -> Result<heapless::String<N>, Error> {
        let mut string = heapless::String::new();

        string
            .push_str(core::str::from_utf8(t.slice()?)?)
            .map_err(|_| ErrorCode::NoSpace)?;

        Ok(string)
    }
}

impl<const N: usize> ToTLV for heapless::String<N> {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        tw.utf16(tag, self.as_bytes())
    }
}

/// Applies to all the Option<> Processing
impl<'a, T: FromTLV<'a>> FromTLV<'a> for Option<T> {
    fn from_tlv(t: &TLVElement<'a>) -> Result<Option<T>, Error> {
        Ok(Some(T::from_tlv(t)?))
    }

    fn tlv_not_found() -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(None)
    }
}

impl<T: ToTLV> ToTLV for Option<T> {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        match self {
            Some(s) => s.to_tlv(tw, tag),
            None => Ok(()),
        }
    }
}

/// Represent a nullable value
///
/// The value may be null or a valid value
/// Note: Null is different from Option. If the value is optional, include Option<> too. For
/// example, Option<Nullable<T>>
#[derive(Copy, Clone, PartialEq, Debug, Hash, Eq)]
pub enum Nullable<T> {
    Null,
    NotNull(T),
}

impl<T> Nullable<T> {
    pub fn as_mut(&mut self) -> Nullable<&mut T> {
        match self {
            Nullable::Null => Nullable::Null,
            Nullable::NotNull(t) => Nullable::NotNull(t),
        }
    }

    pub fn as_ref(&self) -> Nullable<&T> {
        match self {
            Nullable::Null => Nullable::Null,
            Nullable::NotNull(t) => Nullable::NotNull(t),
        }
    }

    pub fn is_null(&self) -> bool {
        match self {
            Nullable::Null => true,
            Nullable::NotNull(_) => false,
        }
    }

    pub fn notnull(self) -> Option<T> {
        match self {
            Nullable::Null => None,
            Nullable::NotNull(t) => Some(t),
        }
    }
}

impl<'a, T: FromTLV<'a>> FromTLV<'a> for Nullable<T> {
    fn from_tlv(t: &TLVElement<'a>) -> Result<Nullable<T>, Error> {
        match t.get_element_type() {
            ElementType::Null => Ok(Nullable::Null),
            _ => Ok(Nullable::NotNull(T::from_tlv(t)?)),
        }
    }
}

impl<T: ToTLV> ToTLV for Nullable<T> {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        match self {
            Nullable::Null => tw.null(tag),
            Nullable::NotNull(s) => s.to_tlv(tw, tag),
        }
    }
}

#[derive(Clone)]
pub enum TLVArray<'a, T> {
    // This is used for the to-tlv path
    Slice(&'a [T]),
    // This is used for the from-tlv path
    Ptr(TLVElement<'a>),
}

pub enum TLVArrayIter<'a, T> {
    Slice(Iter<'a, T>),
    Ptr(Option<TLVContainerIterator<'a>>),
}

impl<'a, T: ToTLV> TLVArray<'a, T> {
    pub fn new(slice: &'a [T]) -> Self {
        Self::Slice(slice)
    }

    pub fn iter(&self) -> TLVArrayIter<'a, T> {
        match self {
            Self::Slice(s) => TLVArrayIter::Slice(s.iter()),
            Self::Ptr(p) => TLVArrayIter::Ptr(p.enter()),
        }
    }
}

impl<'a, T: ToTLV + FromTLV<'a> + Clone> TLVArray<'a, T> {
    pub fn get_index(&self, index: usize) -> T {
        for (curr, element) in self.iter().enumerate() {
            if curr == index {
                return element;
            }
        }
        panic!("Out of bounds");
    }
}

impl<'a, T: FromTLV<'a> + Clone> Iterator for TLVArrayIter<'a, T> {
    type Item = T;
    /* Code for going to the next Element */
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Slice(s_iter) => s_iter.next().cloned(),
            Self::Ptr(p_iter) => {
                if let Some(tlv_iter) = p_iter.as_mut() {
                    let e = tlv_iter.next();
                    if let Some(element) = e {
                        T::from_tlv(&element).ok()
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        }
    }
}

impl<'a, 'b, T> PartialEq<TLVArray<'b, T>> for TLVArray<'a, T>
where
    T: ToTLV + FromTLV<'a> + Clone + PartialEq,
    'b: 'a,
{
    fn eq(&self, other: &TLVArray<'b, T>) -> bool {
        let mut iter1 = self.iter();
        let mut iter2 = other.iter();
        loop {
            match (iter1.next(), iter2.next()) {
                (None, None) => return true,
                (Some(x), Some(y)) => {
                    if x != y {
                        return false;
                    }
                }
                _ => return false,
            }
        }
    }
}

impl<'a, T> PartialEq<&[T]> for TLVArray<'a, T>
where
    T: ToTLV + FromTLV<'a> + Clone + PartialEq,
{
    fn eq(&self, other: &&[T]) -> bool {
        let mut iter1 = self.iter();
        let mut iter2 = other.iter();
        loop {
            match (iter1.next(), iter2.next()) {
                (None, None) => return true,
                (Some(x), Some(y)) => {
                    if x != *y {
                        return false;
                    }
                }
                _ => return false,
            }
        }
    }
}

impl<'a, T: FromTLV<'a> + Clone + ToTLV> ToTLV for TLVArray<'a, T> {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        tw.start_array(tag_type)?;
        for a in self.iter() {
            a.to_tlv(tw, TagType::Anonymous)?;
        }
        tw.end_container()
        // match *self {
        //     Self::Slice(s) => {
        //         tw.start_array(tag_type)?;
        //         for a in s {
        //             a.to_tlv(tw, TagType::Anonymous)?;
        //         }
        //         tw.end_container()
        //     }
        //     Self::Ptr(t) => t.to_tlv(tw, tag_type), <-- TODO: this fails the unit tests of Cert from/to TLV
        // }
    }
}

impl<'a, T> FromTLV<'a> for TLVArray<'a, T> {
    fn from_tlv(t: &TLVElement<'a>) -> Result<Self, Error> {
        t.confirm_array()?;
        Ok(Self::Ptr(t.clone()))
    }
}

impl<'a, T: Debug + ToTLV + FromTLV<'a> + Clone> Debug for TLVArray<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TLVArray [")?;
        let mut first = true;
        for i in self.iter() {
            if !first {
                write!(f, ", ")?;
            }

            write!(f, "{:?}", i)?;
            first = false;
        }
        write!(f, "]")
    }
}

impl<'a> ToTLV for TLVElement<'a> {
    fn to_tlv(&self, tw: &mut TLVWriter, _tag_type: TagType) -> Result<(), Error> {
        match self.get_element_type() {
            ElementType::S8(v) => v.to_tlv(tw, self.get_tag()),
            ElementType::U8(v) => v.to_tlv(tw, self.get_tag()),
            ElementType::U16(v) => v.to_tlv(tw, self.get_tag()),
            ElementType::S16(v) => v.to_tlv(tw, self.get_tag()),
            ElementType::U32(v) => v.to_tlv(tw, self.get_tag()),
            ElementType::S32(v) => v.to_tlv(tw, self.get_tag()),
            ElementType::U64(v) => v.to_tlv(tw, self.get_tag()),
            ElementType::S64(v) => v.to_tlv(tw, self.get_tag()),
            ElementType::False => tw.bool(self.get_tag(), false),
            ElementType::True => tw.bool(self.get_tag(), true),
            ElementType::Utf8l(v) | ElementType::Utf16l(v) => tw.utf16(self.get_tag(), v),
            ElementType::Str8l(v) | ElementType::Str16l(v) => tw.str16(self.get_tag(), v),
            ElementType::Null => tw.null(self.get_tag()),
            ElementType::Struct(_) => tw.start_struct(self.get_tag()),
            ElementType::Array(_) => tw.start_array(self.get_tag()),
            ElementType::List(_) => tw.start_list(self.get_tag()),
            ElementType::EndCnt => tw.end_container(),
            _ => {
                error!("ToTLV Not supported");
                Err(ErrorCode::Invalid.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FromTLV, OctetStr, TLVWriter, TagType, ToTLV};
    use crate::{error::Error, tlv::TLVList, utils::writebuf::WriteBuf};
    use rs_matter_macros::{FromTLV, ToTLV};

    #[derive(ToTLV)]
    struct TestDerive {
        a: u16,
        b: u32,
    }
    #[test]
    fn test_derive_totlv() {
        let mut buf = [0; 20];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWriter::new(&mut writebuf);

        let abc = TestDerive {
            a: 0x1010,
            b: 0x20202020,
        };
        abc.to_tlv(&mut tw, TagType::Anonymous).unwrap();
        assert_eq!(
            buf,
            [21, 37, 0, 0x10, 0x10, 38, 1, 0x20, 0x20, 0x20, 0x20, 24, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[derive(FromTLV)]
    struct TestDeriveSimple {
        a: u16,
        b: u32,
    }

    #[test]
    fn test_derive_fromtlv() {
        let b = [
            21, 37, 0, 10, 0, 38, 1, 20, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let root = TLVList::new(&b).iter().next().unwrap();
        let test = TestDeriveSimple::from_tlv(&root).unwrap();
        assert_eq!(test.a, 10);
        assert_eq!(test.b, 20);
    }

    #[derive(FromTLV)]
    #[tlvargs(lifetime = "'a")]
    struct TestDeriveStr<'a> {
        a: u16,
        b: OctetStr<'a>,
    }

    #[test]
    fn test_derive_fromtlv_str() {
        let b = [21, 37, 0, 10, 0, 0x30, 0x01, 0x03, 10, 11, 12, 0];
        let root = TLVList::new(&b).iter().next().unwrap();
        let test = TestDeriveStr::from_tlv(&root).unwrap();
        assert_eq!(test.a, 10);
        assert_eq!(test.b, OctetStr(&[10, 11, 12]));
    }

    #[derive(FromTLV, Debug)]
    struct TestDeriveOption {
        a: u16,
        b: Option<u16>,
        c: Option<u16>,
    }

    #[test]
    fn test_derive_fromtlv_option() {
        let b = [21, 37, 0, 10, 0, 37, 2, 11, 0];
        let root = TLVList::new(&b).iter().next().unwrap();
        let test = TestDeriveOption::from_tlv(&root).unwrap();
        assert_eq!(test.a, 10);
        assert_eq!(test.b, None);
        assert_eq!(test.c, Some(11));
    }

    #[derive(FromTLV, ToTLV, Debug)]
    struct TestDeriveFabScoped {
        a: u16,
        #[tagval(0xFE)]
        fab_idx: u16,
    }
    #[test]
    fn test_derive_fromtlv_fab_scoped() {
        let b = [21, 37, 0, 10, 0, 37, 0xFE, 11, 0];
        let root = TLVList::new(&b).iter().next().unwrap();
        let test = TestDeriveFabScoped::from_tlv(&root).unwrap();
        assert_eq!(test.a, 10);
        assert_eq!(test.fab_idx, 11);
    }

    #[test]
    fn test_derive_totlv_fab_scoped() {
        let mut buf = [0; 20];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWriter::new(&mut writebuf);

        let abc = TestDeriveFabScoped { a: 20, fab_idx: 3 };

        abc.to_tlv(&mut tw, TagType::Anonymous).unwrap();
        assert_eq!(
            buf,
            [21, 36, 0, 20, 36, 0xFE, 3, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[derive(ToTLV, FromTLV, PartialEq, Debug)]
    enum TestDeriveEnum {
        ValueA(u32),
        ValueB(u32),
    }

    #[test]
    fn test_derive_from_to_tlv_enum() {
        // Test FromTLV
        let b = [21, 36, 0, 100, 24, 0];
        let root = TLVList::new(&b).iter().next().unwrap();
        let mut enum_val = TestDeriveEnum::from_tlv(&root).unwrap();
        assert_eq!(enum_val, TestDeriveEnum::ValueA(100));

        // Modify the value and test ToTLV
        enum_val = TestDeriveEnum::ValueB(10);

        // Test ToTLV
        let mut buf = [0; 20];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWriter::new(&mut writebuf);

        enum_val.to_tlv(&mut tw, TagType::Anonymous).unwrap();
        assert_eq!(
            buf,
            [21, 36, 1, 10, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
