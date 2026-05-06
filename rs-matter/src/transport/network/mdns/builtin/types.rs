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

use core::cmp::Ordering;
use core::ops::RangeBounds;

use domain::base::name::{Label, ToLabelIter};
use domain::base::rdata::ComposeRecordData;
use domain::base::wire::Composer;
use domain::base::{RecordData, Rtype, ToName};
use domain::dep::octseq::{FreezeBuilder, FromBuilder, Octets, OctetsBuilder, ShortBuf, Truncate};

/// This newtype struct allows the construction of a `domain` lib Name from
/// a bunch of `&str` labels represented as a slice.
///
/// Implements the `domain` lib `ToName` trait.
#[derive(Debug, Clone)]
pub struct NameSlice<'a, const N: usize>([&'a str; N]);

impl<'a, const N: usize> NameSlice<'a, N> {
    /// Create a new `NameSlice` instance from a slice of `&str` labels.
    pub const fn new(labels: [&'a str; N]) -> Self {
        Self(labels)
    }
}

impl<const N: usize> core::fmt::Display for NameSlice<'_, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for label in self.0 {
            write!(f, "{}.", label)?;
        }

        Ok(())
    }
}

#[cfg(feature = "defmt")]
impl<const N: usize> defmt::Format for NameSlice<'_, N> {
    fn format(&self, f: defmt::Formatter<'_>) {
        for label in self.0 {
            defmt::write!(f, "{}.", label);
        }
    }
}

impl<const N: usize> ToName for NameSlice<'_, N> {}

/// An iterator over the labels in a `NameSlice` instance.
#[derive(Clone)]
pub struct NameSliceIter<'a, const N: usize> {
    name: &'a NameSlice<'a, N>,
    index: usize,
}

impl<'a, const N: usize> Iterator for NameSliceIter<'a, N> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        match self.index.cmp(&self.name.0.len()) {
            Ordering::Less => {
                let label = unwrap!(
                    Label::from_slice(self.name.0[self.index].as_bytes()),
                    "Unreachable"
                );
                self.index += 1;
                Some(label)
            }
            Ordering::Equal => {
                let label = Label::root();
                self.index += 1;
                Some(label)
            }
            Ordering::Greater => None,
        }
    }
}

impl<const N: usize> DoubleEndedIterator for NameSliceIter<'_, N> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.index > 0 {
            self.index -= 1;
            if self.index == self.name.0.len() {
                let label = Label::root();
                Some(label)
            } else {
                let label = unwrap!(
                    Label::from_slice(self.name.0[self.index].as_bytes()),
                    "Unreachable"
                );
                Some(label)
            }
        } else {
            None
        }
    }
}

impl<const N: usize> ToLabelIter for NameSlice<'_, N> {
    type LabelIter<'t>
        = NameSliceIter<'t, N>
    where
        Self: 't;

    fn iter_labels(&self) -> Self::LabelIter<'_> {
        NameSliceIter {
            name: self,
            index: 0,
        }
    }
}

/// A custom struct for representing a TXT data record off from a slice of
/// key-value `&str` pairs.
#[derive(Debug, Clone)]
pub struct Txt<T>(T);

impl<T> Txt<T> {
    pub const fn new(txt: T) -> Self {
        Self(txt)
    }
}

impl<'a, T> core::fmt::Display for Txt<T>
where
    T: Iterator<Item = (&'a str, &'a str)> + Clone,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Txt [")?;

        for (i, (k, v)) in self.0.clone().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }

            write!(f, "{}={}", k, v)?;
        }

        write!(f, "]")?;

        Ok(())
    }
}

#[cfg(feature = "defmt")]
impl<'a, T> defmt::Format for Txt<T>
where
    T: Iterator<Item = (&'a str, &'a str)> + Clone,
{
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Txt [");

        for (i, (k, v)) in self.0.clone().enumerate() {
            if i > 0 {
                defmt::write!(f, ", ");
            }

            defmt::write!(f, "{}={}", k, v);
        }

        defmt::write!(f, "]");
    }
}

impl<T> RecordData for Txt<T> {
    fn rtype(&self) -> Rtype {
        Rtype::TXT
    }
}

impl<'a, T> ComposeRecordData for Txt<T>
where
    T: Iterator<Item = (&'a str, &'a str)> + Clone,
{
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        None
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        if self.0.clone().count() == 0 {
            target.append_slice(&[0])?;
        } else {
            // TODO: Will not work for (k, v) pairs larger than 254 bytes in length
            for (k, v) in self.0.clone() {
                target.append_slice(&[(k.len() + v.len() + 1) as u8])?;
                target.append_slice(k.as_bytes())?;
                target.append_slice(b"=")?;
                target.append_slice(v.as_bytes())?;
            }
        }

        Ok(())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

/// This struct allows one to use a regular `&mut [u8]` slice as an octet buffer
/// with the `domain` library.
///
/// Useful when a `domain` message needs to be constructed in a `&mut [u8]` slice.
pub struct Buf<'a>(pub &'a mut [u8], pub usize);

impl<'a> Buf<'a> {
    /// Create a new `Buf` instance from a mutable slice.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self(buf, 0)
    }
}

impl FreezeBuilder for Buf<'_> {
    type Octets = Self;

    fn freeze(self) -> Self {
        self
    }
}

impl Octets for Buf<'_> {
    type Range<'r>
        = &'r [u8]
    where
        Self: 'r;

    fn range(&self, range: impl RangeBounds<usize>) -> Self::Range<'_> {
        self.0[..self.1].range(range)
    }
}

impl<'a> FromBuilder for Buf<'a> {
    type Builder = Buf<'a>;

    fn from_builder(builder: Self::Builder) -> Self {
        Buf(&mut builder.0[builder.1..], 0)
    }
}

impl Composer for Buf<'_> {}

impl OctetsBuilder for Buf<'_> {
    type AppendError = ShortBuf;

    fn append_slice(&mut self, slice: &[u8]) -> Result<(), Self::AppendError> {
        if self.1 + slice.len() <= self.0.len() {
            let end = self.1 + slice.len();
            self.0[self.1..end].copy_from_slice(slice);
            self.1 = end;

            Ok(())
        } else {
            Err(ShortBuf)
        }
    }
}

impl Truncate for Buf<'_> {
    fn truncate(&mut self, len: usize) {
        self.1 = len;
    }
}

impl AsMut<[u8]> for Buf<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..self.1]
    }
}

impl AsRef<[u8]> for Buf<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..self.1]
    }
}
