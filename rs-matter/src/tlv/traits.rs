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

use crate::error::Error;
use crate::utils::init;

use super::{
    EitherIter, TLVElement, TLVSequenceIter, TLVSequenceTLVIter, TLVTag, TLVValue, TLVValueType,
    TLVWrite, TLV,
};

pub use container::*;
pub use maybe::*;
pub use octets::*;
pub use slice::*;
pub use str::*;

mod array;
mod bitflags;
mod container;
mod maybe;
mod octets;
mod primitive;
mod slice;
mod str;
mod vec;

/// A trait representing Rust types that can deserialize themselves from
/// a TLV-encoded byte slice.
pub trait FromTLV<'a>: Sized + 'a {
    /// Deserialize the type from a TLV-encoded element.
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error>;

    /// Generate an in-place initializer for the type that initializes
    /// the type from a TLV-encoded element.
    fn init_from_tlv(element: TLVElement<'a>) -> impl init::Init<Self, Error> {
        unsafe {
            init::init_from_closure(move |slot| {
                core::ptr::write(slot, Self::from_tlv(&element)?);

                Ok(())
            })
        }
    }
}

/// A trait representing Rust types that can serialize themselves to
/// a TLV-encoded stream.
pub trait ToTLV {
    /// Serialize the type to a TLV-encoded stream.
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error>;

    /// Serialize the type as an iterator of `TLV` instances by potentially borrowing
    /// data from the type.
    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>>;
}

impl<T> ToTLV for &T
where
    T: ToTLV,
{
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        (*self).to_tlv(tag, tw)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>> {
        (*self).tlv_iter(tag)
    }
}

impl<'a> FromTLV<'a> for TLVElement<'a> {
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        Ok(element.clone())
    }
}

impl ToTLV for TLVElement<'_> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        if self.is_empty() {
            // Special-case serializing empty TLV elements to nothing
            // Useful in tests
            Ok(())
        } else {
            tw.raw_value(tag, self.control()?.value_type, self.raw_value()?)
        }
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>> {
        TLVElementTLVIter::Start(tag, self.clone())
    }
}

enum TLVElementTLVIter<'a> {
    Start(TLVTag, TLVElement<'a>),
    Seq(TLVSequenceTLVIter<'a>),
    Finished,
}

impl<'a> Iterator for TLVElementTLVIter<'a> {
    type Item = Result<TLV<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match core::mem::replace(self, Self::Finished) {
            TLVElementTLVIter::Start(tag, elem) => {
                if elem.is_empty() {
                    // Special-case serializing empty TLV elements to nothing
                    // Useful in tests
                    None
                } else {
                    let value = elem.value().map(|value| TLV::new(tag, value));

                    if let Ok(seq) = elem.container() {
                        *self = Self::Seq(seq.tlv_iter());
                    } else {
                        *self = TLVElementTLVIter::Finished;
                    }

                    Some(value)
                }
            }
            TLVElementTLVIter::Seq(mut iter) => {
                if let Some(value) = iter.next() {
                    *self = TLVElementTLVIter::Seq(iter);
                    Some(value)
                } else {
                    Some(Ok(TLV::end_container()))
                }
            }
            TLVElementTLVIter::Finished => None,
        }
    }
}

impl<'a> FromTLV<'a> for TLVValue<'a> {
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        element.value()
    }
}

impl ToTLV for TLVValue<'_> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.tlv(tag, self)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>> {
        TLV::new(tag, self.clone()).into_tlv_iter()
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Debug;
    use core::mem::MaybeUninit;

    use rs_matter_macros::{FromTLV, ToTLV};

    use crate::tlv::{Octets, TLVElement, TLVWriter, TLV};
    use crate::utils::init::InitMaybeUninit;
    use crate::utils::storage::WriteBuf;

    use super::{FromTLV, OctetStr, TLVTag, ToTLV};

    fn test_from_tlv<'a, T: FromTLV<'a> + PartialEq + Debug>(data: &'a [u8], expected: T) {
        let root = TLVElement::new(data);
        let test = T::from_tlv(&root).unwrap();
        assert_eq!(test, expected);

        let test_init = T::init_from_tlv(root);

        let mut test = MaybeUninit::<T>::uninit();

        let test = test.try_init_with(test_init).unwrap();

        assert_eq!(*test, expected);
    }

    fn test_to_tlv<T: ToTLV>(t: T, expected: &[u8]) {
        let mut buf = [0; 20];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWriter::new(&mut writebuf);

        t.to_tlv(&TLVTag::Anonymous, &mut tw).unwrap();

        assert_eq!(writebuf.as_slice(), expected);

        writebuf.reset();

        let mut iter = t
            .tlv_iter(TLVTag::Anonymous)
            .flat_map(TLV::result_into_bytes_iter);
        loop {
            match iter.next() {
                Some(Ok(byte)) => writebuf.append(&[byte]).unwrap(),
                None => break,
                _ => panic!("Error in iterator"),
            }
        }

        assert_eq!(writebuf.as_slice(), expected);
    }

    #[derive(ToTLV)]
    struct TestDerive {
        a: u16,
        b: u32,
    }

    #[test]
    fn test_derive_totlv() {
        test_to_tlv(
            TestDerive {
                a: 0x1010,
                b: 0x20202020,
            },
            &[21, 37, 0, 0x10, 0x10, 38, 1, 0x20, 0x20, 0x20, 0x20, 24],
        );
    }

    #[derive(FromTLV, Debug, PartialEq)]
    struct TestDeriveSimple {
        a: u16,
        b: u32,
    }

    #[test]
    fn test_derive_fromtlv() {
        test_from_tlv(
            &[21, 37, 0, 10, 0, 38, 1, 20, 0, 0, 0, 24],
            TestDeriveSimple { a: 10, b: 20 },
        );
    }

    #[derive(FromTLV, Debug, PartialEq)]
    #[tlvargs(lifetime = "'a")]
    struct TestDeriveStr<'a> {
        a: u16,
        b: OctetStr<'a>,
    }

    #[test]
    fn test_derive_fromtlv_str() {
        test_from_tlv(
            &[21, 37, 0, 10, 0, 0x30, 0x01, 0x03, 10, 11, 12, 0],
            TestDeriveStr {
                a: 10,
                b: Octets(&[10, 11, 12]),
            },
        );
    }

    #[derive(FromTLV, Debug, PartialEq)]
    struct TestDeriveOption {
        a: u16,
        b: Option<u16>,
        c: Option<u16>,
    }

    #[test]
    fn test_derive_fromtlv_option() {
        test_from_tlv(
            &[21, 37, 0, 10, 0, 37, 2, 11, 0],
            TestDeriveOption {
                a: 10,
                b: None,
                c: Some(11),
            },
        );
    }

    #[derive(FromTLV, ToTLV, Debug, PartialEq)]
    struct TestDeriveFabScoped {
        a: u16,
        #[tagval(0xFE)]
        fab_idx: u16,
    }

    #[test]
    fn test_derive_fromtlv_fab_scoped() {
        test_from_tlv(
            &[21, 37, 0, 10, 0, 37, 0xFE, 11, 0],
            TestDeriveFabScoped { a: 10, fab_idx: 11 },
        );
    }

    #[test]
    fn test_derive_totlv_fab_scoped() {
        test_to_tlv(
            TestDeriveFabScoped { a: 20, fab_idx: 3 },
            &[21, 36, 0, 20, 36, 0xFE, 3, 24],
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
        test_from_tlv(&[21, 36, 0, 100, 24, 0], TestDeriveEnum::ValueA(100));

        // Test ToTLV
        test_to_tlv(TestDeriveEnum::ValueB(10), &[21, 36, 1, 10, 24]);
    }
}
