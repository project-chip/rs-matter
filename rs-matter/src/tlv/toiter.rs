use core::iter::{Chain, Once};

use crate::error::{Error, ErrorCode};

use super::{OnceTLVIter, TLVTag, TLVValue, TLVValueType, TLV};

type TLVResult<'a> = Result<TLV<'a>, Error>;
type ChainedTLVIter<'a, C> = Chain<C, OnceTLVIter<'a>>;

/// A decorator trait for serializing data as TLV in the form of an
/// `Iterator` of `Result<TLV<'a>, Error>` bytes.
///
/// The trait provides additional combinators on top of the standard `Iterator`
/// trait combinators (e.g. `map`, `filter`, `flat_map`, etc.) that allow for serializing TLV elements.
///
/// The trait is already implemented for any `Iterator` that yields items of type `Result<TLV<'a>, Error>`,
/// so users are not expected to provide implementations of it.
///
/// Using an Iterator approach to TLV serialization is useful when the data is not serialized to its
/// final location (be it in the storage or in an outgoing network packet) - but rather - is serialized
/// so that it is afterwards consumed as a stream of bytes by another component - say - a hash signature
/// algorithm that operates on the TLV representation of the data.
///
/// This way, the need for an interim buffer for the serialized TLV data might be avoided.
///
/// NOTE:
/// Keep in mind that the resulting iterator might quickly become rather large if the serialized
/// TLV data contains many small TLV elements, as each TLV element is represented as multiple compositions
/// of the Rust `Iterator` combinators (e.g. `chain`, `map`, `flat_map`, etc.), and - moreover -
/// the size of each `TLV` itself is rather large (~ 32 bytes on 32bit archs).
///
/// Therefore, the iterator TLV serialization is only useful when the serialized TLV data contains few but
/// large non-container TLV elements, like octet strings or utf8 strings
/// (which is typical for e.g. TLV-encoded certificates).
///
/// For other cases, allocating a temporary memory buffer and serializing into it with `TLVWrite` might result
/// in less memory overhead (and better performance when reading the raw serialized TLV data) by the code that
/// operates on it.
pub trait TLVIter<'a>: Iterator<Item = TLVResult<'a>> + Sized {
    fn flatten(value: Result<Self, Error>) -> EitherIter<Self, Once<TLVResult<'a>>> {
        match value {
            Ok(value) => EitherIter::First(value),
            Err(err) => EitherIter::Second(core::iter::once(Err(err))),
        }
    }

    /// Serialize a TLV tag and value.
    fn tlv(self, tag: TLVTag, value: TLVValue<'a>) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::new(tag, value).into_tlv_iter())
    }

    /// Serialize the given tag and the provided value as an S8 TLV value.
    fn i8(self, tag: TLVTag, data: i8) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::i8(tag, data).into_tlv_iter())
    }

    /// Serialize the given tag and the provided value as a U8 TLV value.
    fn u8(self, tag: TLVTag, data: u8) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::u8(tag, data).into_tlv_iter())
    }

    /// Serialize the given tag and the provided value as an S16 TLV value,
    /// or as an S8 TLV value if the provided data can fit in the S8 domain range.
    fn i16(self, tag: TLVTag, data: i16) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::i16(tag, data).into_tlv_iter())
    }

    /// Serialize the given tag and the provided value as a U16 TLV value,
    /// or as a U8 TLV value if the provided data can fit in the U8 domain range.
    fn u16(self, tag: TLVTag, data: u16) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::u16(tag, data).into_tlv_iter())
    }

    /// Serialize the given tag and the provided value as an S32 TLV value,
    /// or as an S16 / S8 TLV value if the provided data can fit in a smaller domain range.
    fn i32(self, tag: TLVTag, data: i32) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::i32(tag, data).into_tlv_iter())
    }

    /// Serialize the given tag and the provided value as a U32 TLV value,
    /// or as a U16 / U8 TLV value if the provided data can fit in a smaller domain range.
    fn u32(self, tag: TLVTag, data: u32) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::u32(tag, data).into_tlv_iter())
    }

    /// Serialize the given tag and the provided value as an S64 TLV value,
    /// or as an S32 / S16 / S8 TLV value if the provided data can fit in a smaller domain range.
    fn i64(self, tag: TLVTag, data: i64) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::i64(tag, data).into_tlv_iter())
    }

    /// Serialize the given tag and the provided value as a U64 TLV value,
    /// or as a U32 / U16 / U8 TLV value if the provided data can fit in a smaller domain range.
    fn u64(self, tag: TLVTag, data: u64) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::u64(tag, data).into_tlv_iter())
    }

    /// Serialize the given tag and the provided value as an F32 TLV value.
    fn f32(self, tag: TLVTag, data: f32) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::f32(tag, data).into_tlv_iter())
    }

    /// Serialize the given tag and the provided value as an F64 TLV value.
    fn f64(self, tag: TLVTag, data: f64) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::f64(tag, data).into_tlv_iter())
    }

    /// Serialize the given tag and the provided value as a TLV Octet String.
    ///
    /// The exact octet string type (Str8l, Str16l, Str32l, or Str64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    fn str(self, tag: TLVTag, data: &'a [u8]) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::str(tag, data).into_tlv_iter())
    }

    /// Serialize the given tag and the provided value as a TLV UTF-8 String.
    ///
    /// The exact UTF-8 string type (Utf8l, Utf16l, Utf32l, or Utf64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    fn utf8(self, tag: TLVTag, data: &'a str) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::utf8(tag, data).into_tlv_iter())
    }

    /// Serialize the given tag and a value indicating the start of a Struct TLV container.
    ///
    /// NOTE: The user must call `end_container` after serializing all the Struct fields
    /// to close the Struct container or else the generated TLV stream will be invalid.
    fn start_struct(self, tag: TLVTag) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::structure(tag).into_tlv_iter())
    }

    /// Serialize the given tag and a value indicating the start of an Array TLV container.
    ///
    /// NOTE: The user must call `end_container` after serializing all the Array elements
    /// to close the Array container or else the generated TLV stream will be invalid.
    fn start_array(self, tag: TLVTag) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::array(tag).into_tlv_iter())
    }

    /// Serialize the given tag and a value indicating the start of a List TLV container.
    ///
    /// NOTE: The user must call `end_container` after serializing all the List elements
    /// to close the List container or else the generated TLV stream will be invalid.
    fn start_list(self, tag: TLVTag) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::list(tag).into_tlv_iter())
    }

    /// Serialize the given tag and a value indicating the start of a TLV container.
    ///
    /// NOTE: The user must call `end_container` after serializing all the container fields
    /// to close the Struct container or else the generated TLV stream will be invalid.
    fn start_container(self, tag: TLVTag, container_type: TLVValueType) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        match container_type {
            TLVValueType::Struct => self.start_struct(tag),
            TLVValueType::Array => self.start_array(tag),
            TLVValueType::List => self.start_list(tag),
            _ => self.chain(core::iter::once(Err(ErrorCode::TLVTypeMismatch.into()))),
        }
    }

    /// Serialize a value indicating the end of a Struct, Array, or List TLV container.
    ///
    /// NOTE: This method must be called only when the corresponding container has been opened
    /// using `start_struct`, `start_array`, or `start_list`, or else the generated TLV stream will be invalid.
    fn end_container(self) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::end_container().into_tlv_iter())
    }

    /// Serialize the given tag and a value indicating a Null TLV value.
    fn null(self, tag: TLVTag) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::null(tag).into_tlv_iter())
    }

    /// Serialize the given tag and a value indicating a True or False TLV value.
    fn bool(self, tag: TLVTag, data: bool) -> ChainedTLVIter<'a, Self>
    where
        Self: 'a,
    {
        self.chain(TLV::bool(tag, data).into_tlv_iter())
    }
}

impl<'a, T> TLVIter<'a> for T where T: Iterator<Item = TLVResult<'a>> {}

/// A decorator enum type wrapping two iterators and implementing
/// the `Iterator` trait.
///
/// Useful when the "to-tlv-iter" implementation needs to return
/// one of two iterators based on some condition.
pub enum EitherIter<F, S> {
    First(F),
    Second(S),
}

impl<F, S> Iterator for EitherIter<F, S>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(i) => i.next(),
            Self::Second(i) => i.next(),
        }
    }
}

/// A decorator enum type wrapping three iterators and implementing
/// the `Iterator` trait.
///
/// Useful when the "to-tlv-iter" implementation needs to return
/// one of three iterators based on some condition.
pub enum Either3Iter<F, S, T> {
    First(F),
    Second(S),
    Third(T),
}

impl<F, S, T> Iterator for Either3Iter<F, S, T>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
    T: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(i) => i.next(),
            Self::Second(i) => i.next(),
            Self::Third(i) => i.next(),
        }
    }
}

/// A decorator enum type wrapping four iterators and implementing
/// the `Iterator` trait.
///
/// Useful when the "to-tlv-iter" implementation needs to return
/// one of four iterators based on some condition.
pub enum Either4Iter<F, S, T, U> {
    First(F),
    Second(S),
    Third(T),
    Fourth(U),
}

impl<F, S, T, U> Iterator for Either4Iter<F, S, T, U>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
    T: Iterator<Item = F::Item>,
    U: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(i) => i.next(),
            Self::Second(i) => i.next(),
            Self::Third(i) => i.next(),
            Self::Fourth(i) => i.next(),
        }
    }
}

/// A decorator enum type wrapping five iterators and implementing
/// the `Iterator` trait.
///
/// Useful when the "to-tlv-iter" implementation needs to return
/// one of five iterators based on some condition.
pub enum Either5Iter<F, S, T, U, I> {
    First(F),
    Second(S),
    Third(T),
    Fourth(U),
    Fifth(I),
}

impl<F, S, T, U, I> Iterator for Either5Iter<F, S, T, U, I>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
    T: Iterator<Item = F::Item>,
    U: Iterator<Item = F::Item>,
    I: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(i) => i.next(),
            Self::Second(i) => i.next(),
            Self::Third(i) => i.next(),
            Self::Fourth(i) => i.next(),
            Self::Fifth(i) => i.next(),
        }
    }
}

/// A decorator enum type wrapping six iterators and implementing
/// the `Iterator` trait.
///
/// Useful when the "to-tlv-iter" implementation needs to return
/// one of six iterators based on some condition.
pub enum Either6Iter<F, S, T, U, I, X> {
    First(F),
    Second(S),
    Third(T),
    Fourth(U),
    Fifth(I),
    Sixth(X),
}

impl<F, S, T, U, I, X> Iterator for Either6Iter<F, S, T, U, I, X>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
    T: Iterator<Item = F::Item>,
    U: Iterator<Item = F::Item>,
    I: Iterator<Item = F::Item>,
    X: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(i) => i.next(),
            Self::Second(i) => i.next(),
            Self::Third(i) => i.next(),
            Self::Fourth(i) => i.next(),
            Self::Fifth(i) => i.next(),
            Self::Sixth(i) => i.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::{f32, iter::empty};

    use crate::tlv::TLV;

    use super::{TLVIter, TLVResult, TLVTag};

    fn expect<'a, I>(iter: I, expected: &[u8])
    where
        I: Iterator<Item = TLVResult<'a>>,
    {
        let mut iter = iter.map(|r| r.unwrap()).flat_map(TLV::into_bytes_iter);
        let mut expected = expected.iter().copied();

        loop {
            match (iter.next(), expected.next()) {
                (Some(a), Some(b)) => assert_eq!(a, b),
                (None, None) => break,
                (Some(_), None) => panic!("Iterator has more bytes than expected"),
                (None, Some(_)) => panic!("Iterator has fewer bytes than expected"),
            }
        }
    }

    #[test]
    fn test_write_success() {
        expect(
            empty()
                .start_struct(TLVTag::Anonymous)
                .u8(TLVTag::Anonymous, 12)
                .u8(TLVTag::Context(1), 13)
                .u16(TLVTag::Anonymous, 0x1212)
                .u16(TLVTag::Context(2), 0x1313)
                .start_array(TLVTag::Context(3))
                .bool(TLVTag::Anonymous, true)
                .end_container()
                .end_container(),
            &[
                21, 4, 12, 36, 1, 13, 5, 0x12, 0x012, 37, 2, 0x13, 0x13, 54, 3, 9, 24, 24,
            ],
        );
    }

    #[test]
    fn test_put_str8() {
        expect(
            empty()
                .u8(TLVTag::Context(1), 13)
                .str(TLVTag::Anonymous, &[10, 11, 12, 13, 14])
                .u16(TLVTag::Context(2), 0x1313)
                .str(TLVTag::Context(3), &[20, 21, 22]),
            &[
                36, 1, 13, 16, 5, 10, 11, 12, 13, 14, 37, 2, 0x13, 0x13, 48, 3, 3, 20, 21, 22,
            ],
        );
    }

    #[test]
    fn test_matter_spec_examples() {
        // Boolean false

        expect(empty().bool(TLVTag::Anonymous, false), &[0x08]);

        // Boolean true

        expect(empty().bool(TLVTag::Anonymous, true), &[0x09]);

        // Signed Integer, 1-octet, value 42

        expect(empty().i8(TLVTag::Anonymous, 42), &[0x00, 0x2a]);

        // Signed Integer, 1-octet, value -17

        expect(empty().i8(TLVTag::Anonymous, -17), &[0x00, 0xef]);

        // Unsigned Integer, 1-octet, value 42U

        expect(empty().u8(TLVTag::Anonymous, 42), &[0x04, 0x2a]);

        // Signed Integer, 2-octet, value 422

        expect(empty().i16(TLVTag::Anonymous, 422), &[0x01, 0xa6, 0x01]);

        // Signed Integer, 4-octet, value -170000

        expect(
            empty().i64(TLVTag::Anonymous, -170000),
            &[0x02, 0xf0, 0x67, 0xfd, 0xff],
        );

        // Signed Integer, 8-octet, value 40000000000

        expect(
            empty().i64(TLVTag::Anonymous, 40000000000),
            &[0x03, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00],
        );

        // UTF-8 String, 1-octet length, "Hello!"

        expect(
            empty().utf8(TLVTag::Anonymous, "Hello!"),
            &[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21],
        );

        // UTF-8 String, 1-octet length, "Tschüs"

        expect(
            empty().utf8(TLVTag::Anonymous, "Tschüs"),
            &[0x0c, 0x07, 0x54, 0x73, 0x63, 0x68, 0xc3, 0xbc, 0x73],
        );

        // Octet String, 1-octet length, octets 00 01 02 03 04

        expect(
            empty().str(TLVTag::Anonymous, &[0x00, 0x01, 0x02, 0x03, 0x04]),
            &[0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04],
        );

        // Null

        expect(empty().null(TLVTag::Anonymous), &[0x14]);

        // Single precision floating point 0.0

        expect(
            empty().f32(TLVTag::Anonymous, 0.0),
            &[0x0a, 0x00, 0x00, 0x00, 0x00],
        );

        // Single precision floating point (1.0 / 3.0)

        expect(
            empty().f32(TLVTag::Anonymous, 1.0 / 3.0),
            &[0x0a, 0xab, 0xaa, 0xaa, 0x3e],
        );

        // Single precision floating point 17.9

        expect(
            empty().f32(TLVTag::Anonymous, 17.9),
            &[0x0a, 0x33, 0x33, 0x8f, 0x41],
        );

        // Single precision floating point infinity

        expect(
            empty().f32(TLVTag::Anonymous, f32::INFINITY),
            &[0x0a, 0x00, 0x00, 0x80, 0x7f],
        );

        // Single precision floating point negative infinity

        expect(
            empty().f32(TLVTag::Anonymous, f32::NEG_INFINITY),
            &[0x0a, 0x00, 0x00, 0x80, 0xff],
        );

        // Double precision floating point 0.0

        expect(
            empty().f64(TLVTag::Anonymous, 0.0),
            &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );

        // Double precision floating point (1.0 / 3.0)

        expect(
            empty().f64(TLVTag::Anonymous, 1.0 / 3.0),
            &[0x0b, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xd5, 0x3f],
        );

        // Double precision floating point 17.9

        expect(
            empty().f64(TLVTag::Anonymous, 17.9),
            &[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40],
        );

        // Double precision floating point infinity (∞)

        expect(
            empty().f64(TLVTag::Anonymous, f64::INFINITY),
            &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f],
        );

        // Double precision floating point negative infinity

        expect(
            empty().f64(TLVTag::Anonymous, f64::NEG_INFINITY),
            &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff],
        );

        // Empty Structure, {}

        expect(
            empty().start_struct(TLVTag::Anonymous).end_container(),
            &[0x15, 0x18],
        );

        // Empty Array, []

        expect(
            empty().start_array(TLVTag::Anonymous).end_container(),
            &[0x16, 0x18],
        );

        // Empty List, []

        expect(
            empty().start_list(TLVTag::Anonymous).end_container(),
            &[0x17, 0x18],
        );

        // Structure, two context specific tags, Signed Integer, 1 octet values, {0 = 42, 1 = -17}

        expect(
            empty()
                .start_struct(TLVTag::Anonymous)
                .i8(TLVTag::Context(0), 42)
                .i32(TLVTag::Context(1), -17)
                .end_container(),
            &[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18],
        );

        // Array, Signed Integer, 1-octet values, [0, 1, 2, 3, 4]

        expect(
            empty()
                .start_array(TLVTag::Anonymous)
                .i8(TLVTag::Anonymous, 0)
                .i8(TLVTag::Anonymous, 1)
                .i8(TLVTag::Anonymous, 2)
                .i8(TLVTag::Anonymous, 3)
                .i8(TLVTag::Anonymous, 4)
                .end_container(),
            &[
                0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x18,
            ],
        );

        // List, mix of anonymous and context tags, Signed Integer, 1 octet values, [[1, 0 = 42, 2, 3, 0 = -17]]

        expect(
            empty()
                .start_list(TLVTag::Anonymous)
                .i64(TLVTag::Anonymous, 1)
                .i16(TLVTag::Context(0), 42)
                .i8(TLVTag::Anonymous, 2)
                .i8(TLVTag::Anonymous, 3)
                .i32(TLVTag::Context(0), -17)
                .end_container(),
            &[
                0x17, 0x00, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x02, 0x00, 0x03, 0x20, 0x00, 0xef, 0x18,
            ],
        );

        // Array, mix of element types, [42, -170000, {}, 17.9, "Hello!"]

        expect(
            empty()
                .start_array(TLVTag::Anonymous)
                .i64(TLVTag::Anonymous, 42)
                .i64(TLVTag::Anonymous, -170000)
                .start_struct(TLVTag::Anonymous)
                .end_container()
                .f32(TLVTag::Anonymous, 17.9)
                .utf8(TLVTag::Anonymous, "Hello!")
                .end_container(),
            &[
                0x16, 0x00, 0x2a, 0x02, 0xf0, 0x67, 0xfd, 0xff, 0x15, 0x18, 0x0a, 0x33, 0x33, 0x8f,
                0x41, 0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x18,
            ],
        );

        // Anonymous tag, Unsigned Integer, 1-octet value, 42U

        expect(empty().u64(TLVTag::Anonymous, 42), &[0x04, 0x2a]);

        // Context tag 1, Unsigned Integer, 1-octet value, 1 = 42U

        expect(empty().u16(TLVTag::Context(1), 42), &[0x24, 0x01, 0x2a]);

        // Common profile tag 1, Unsigned Integer, 1-octet value, Matter::1 = 42U

        expect(
            empty().u16(TLVTag::CommonPrf16(1), 42),
            &[0x44, 0x01, 0x00, 0x2a],
        );

        // Common profile tag 100000, Unsigned Integer, 1-octet value, Matter::100000 = 42U

        expect(
            empty().u16(TLVTag::CommonPrf32(100000), 42),
            &[0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a],
        );

        // Fully qualified tag, Vendor ID 0xFFF1/65521, pro­file number 0xDEED/57069,
        // 2-octet tag 1, Unsigned Integer, 1-octet value 42, 65521::57069:1 = 42U

        expect(
            empty().u16(
                TLVTag::FullQual48 {
                    vendor_id: 65521,
                    profile: 57069,
                    tag: 1,
                },
                42,
            ),
            &[0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a],
        );

        // Fully qualified tag, Vendor ID 0xFFF1/65521, pro­file number 0xDEED/57069,
        // 4-octet tag 0xAA55FEED/2857762541, Unsigned Integer, 1-octet value 42, 65521::57069:2857762541 = 42U

        expect(
            empty().u16(
                TLVTag::FullQual64 {
                    vendor_id: 65521,
                    profile: 57069,
                    tag: 2857762541,
                },
                42,
            ),
            &[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a],
        );

        // Structure with the fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 2-octet tag 1. The structure contains a single ele­ment labeled using a fully qualified tag under
        // the same profile, with 2-octet tag 0xAA55/43605. 65521::57069:1 = {65521::57069:43605 = 42U}

        expect(
            empty()
                .start_struct(TLVTag::FullQual48 {
                    vendor_id: 65521,
                    profile: 57069,
                    tag: 1,
                })
                .u64(
                    TLVTag::FullQual48 {
                        vendor_id: 65521,
                        profile: 57069,
                        tag: 43605,
                    },
                    42,
                )
                .end_container(),
            &[
                0xd5, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0xc4, 0xf1, 0xff, 0xed, 0xde, 0x55, 0xaa,
                0x2a, 0x18,
            ],
        );
    }
}
