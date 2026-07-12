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

use pinned_init::init_from_closure;

use crate::error::Error;
use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};
use crate::utils::init::{try_init, Init, InitDefault, IntoFallibleInit};

/// A wrapper for a type `T` which might not always be present in the TLV stream.
///
/// Unlike `Option<T>` and `Optional<T>` though, `Skippable<T>` is NOT initialized
/// to `None` when the value is not present in the TLV stream, but to a default `T`.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Skippable<T> {
    value: T,
}

impl<T> Skippable<T>
where
    T: Default + InitDefault,
{
    /// Create a new `Skippable<T>` with the default value of `T`.
    pub fn new_default() -> Self {
        Self::new(T::default())
    }

    /// Create a new `Skippable<T>` with the given value.
    pub const fn new(value: T) -> Self {
        Self { value }
    }

    /// Initialize a `Skippable<T>` with the default value of `T`.
    pub fn init_default() -> impl Init<Self> {
        Self::init(T::init_default().into_fallible())
    }

    /// Initialize a `Skippable<T>` with the given initializer.
    pub fn init<I: Init<T, E>, E>(value: I) -> impl Init<Self, E> {
        try_init!(Self {
            value <- value,
        }? E)
    }

    pub const fn value(&self) -> &T {
        &self.value
    }

    pub const fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<'a, T> FromTLV<'a> for Skippable<T>
where
    T: FromTLV<'a> + Default + InitDefault,
{
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        if element.is_empty() {
            Ok(Self::new_default())
        } else {
            Ok(Self::new(T::from_tlv(element)?))
        }
    }

    fn init_from_tlv(element: TLVElement<'a>) -> impl Init<Self, Error> {
        unsafe {
            init_from_closure(move |slot| {
                if element.is_empty() {
                    Self::init(T::init_default().into_fallible()).__init(slot)
                } else {
                    Self::init(T::init_from_tlv(element)).__init(slot)
                }
            })
        }
    }
}

impl<T> ToTLV for Skippable<T>
where
    T: ToTLV,
{
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        self.value.to_tlv(tag, tw)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        self.value.tlv_iter(tag)
    }
}

#[cfg(test)]
mod tests {
    use crate::tlv::{FromTLV, TLVElement, TLVTag, ToTLV};
    use crate::utils::init::InitMaybeUninit;
    use crate::utils::storage::{Vec, WriteBuf};

    use super::Skippable;

    /// Serialize `t` (anonymous tag) into a fresh buffer and return the bytes.
    fn to_bytes<T: ToTLV>(t: &T, buf: &mut [u8]) -> usize {
        let mut wb = WriteBuf::new(buf);
        t.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        wb.get_tail()
    }

    // `Skippable<T>` requires `T: Default + InitDefault`, so these tests use
    // `Vec<u16, N>` (which implements both) rather than a bare primitive.
    type Inner = Vec<u16, 4>;

    fn inner(items: &[u16]) -> Inner {
        let mut v = Inner::new();
        for &i in items {
            v.push(i).unwrap();
        }
        v
    }

    /// A present value round-trips through `to_tlv` / `from_tlv`.
    #[test]
    fn present_value_roundtrips() {
        let mut buf = [0u8; 32];
        let len = to_bytes(&Skippable::new(inner(&[42, 43])), &mut buf);

        let back = Skippable::<Inner>::from_tlv(&TLVElement::new(&buf[..len])).unwrap();
        assert_eq!(back.value().as_slice(), &[42, 43]);
    }

    /// `from_tlv` on an EMPTY element yields the default value (not an error, and
    /// not a `None` — `Skippable` has no `None` variant).
    #[test]
    fn missing_value_from_tlv_is_default() {
        let empty = TLVElement::new(&[]);
        assert!(empty.is_empty());

        let s = Skippable::<Inner>::from_tlv(&empty).unwrap();
        assert!(s.value().is_empty());
    }

    /// `init_from_tlv` mirrors `from_tlv`: default on empty, parsed otherwise.
    #[test]
    fn init_from_tlv_defaults_on_empty_and_parses_otherwise() {
        // Empty -> default.
        let mut slot = core::mem::MaybeUninit::<Skippable<Inner>>::uninit();
        let s = slot
            .try_init_with(Skippable::<Inner>::init_from_tlv(TLVElement::new(&[])))
            .unwrap();
        assert!(s.value().is_empty());

        // Present -> parsed.
        let mut buf = [0u8; 32];
        let len = to_bytes(&Skippable::new(inner(&[7])), &mut buf);
        let mut slot = core::mem::MaybeUninit::<Skippable<Inner>>::uninit();
        let s = slot
            .try_init_with(Skippable::<Inner>::init_from_tlv(TLVElement::new(
                &buf[..len],
            )))
            .unwrap();
        assert_eq!(s.value().as_slice(), &[7]);
    }

    /// The real use case (mirrors `Fabric` gaining a trailing `groups` field):
    /// an older struct lacking the trailing `Skippable` field deserializes into
    /// the newer struct with that field defaulted.
    #[test]
    fn missing_trailing_skippable_field_deserializes_to_default() {
        // Older shape: two fields, no trailing field.
        #[derive(Debug, ToTLV)]
        struct Old {
            a: u16,
            b: u16,
        }

        // Newer shape: same positional tags plus a trailing `Skippable` field.
        #[derive(Debug, FromTLV)]
        struct New {
            a: u16,
            b: u16,
            trailing: Skippable<Vec<u16, 4>>,
        }

        let mut buf = [0u8; 64];
        let len = to_bytes(&Old { a: 7, b: 9 }, &mut buf);

        let new = New::from_tlv(&TLVElement::new(&buf[..len])).unwrap();
        assert_eq!((new.a, new.b), (7, 9));
        assert!(new.trailing.value().is_empty());
    }

    /// A written `Skippable` field is read back unchanged (round-trip within a
    /// struct, both fields present).
    #[test]
    fn trailing_skippable_field_roundtrips_when_present() {
        #[derive(Debug, FromTLV, ToTLV)]
        struct S {
            a: u16,
            trailing: Skippable<Vec<u16, 4>>,
        }

        let mut inner = Vec::new();
        inner.push(1).unwrap();
        inner.push(2).unwrap();

        let mut buf = [0u8; 64];
        let len = to_bytes(
            &S {
                a: 5,
                trailing: Skippable::new(inner),
            },
            &mut buf,
        );

        let back = S::from_tlv(&TLVElement::new(&buf[..len])).unwrap();
        assert_eq!(back.a, 5);
        assert_eq!(back.trailing.value().as_slice(), &[1, 2]);
    }
}
