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

//! The error type of `rs-matter-tlv`.

// Only for the bridge to the legacy `Error` below
use rs_matter_utils::error::{Error, ErrorCode};

rs_matter_utils::error_type!(
    /// The error of `rs-matter-tlv`.
    pub TlvError, TlvErrorCode
);

/// The errors raised when reading or writing Matter TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TlvErrorCode {
    // TODO: Drop the explicit values together with the bridge below. Until then
    // each code has the value of the legacy `ErrorCode` it maps to, so that the
    // bridge compiles to nothing.
    /// The byte stream is not well-formed TLV.
    Malformed = ErrorCode::InvalidData as u8,
    /// The element is well-formed but not of the requested type.
    TypeMismatch = ErrorCode::TLVTypeMismatch as u8,
    /// A required element or context tag is absent.
    NotFound = ErrorCode::NotFound as u8,
    /// The element has the right type, but the value is not an acceptable one.
    InvalidValue = ErrorCode::Invalid as u8,
    /// The destination container could not hold the decoded data.
    CapacityExceeded = ErrorCode::ConstraintError as u8,
    /// The TLV writer ran out of room.
    NoSpace = ErrorCode::NoSpace as u8,
    /// The value is the reserved null sentinel where null is not permitted.
    UnexpectedNull = ErrorCode::TLVUnexpectedNull as u8,
}

// TODO: Remove this bridge once all dependent crates have been refactored to
// explicitly handle `TlvError`.
impl From<TlvErrorCode> for ErrorCode {
    fn from(value: TlvErrorCode) -> Self {
        match value {
            TlvErrorCode::Malformed => ErrorCode::InvalidData,
            TlvErrorCode::TypeMismatch => ErrorCode::TLVTypeMismatch,
            TlvErrorCode::NotFound => ErrorCode::NotFound,
            TlvErrorCode::InvalidValue => ErrorCode::Invalid,
            TlvErrorCode::CapacityExceeded => ErrorCode::ConstraintError,
            TlvErrorCode::UnexpectedNull => ErrorCode::TLVUnexpectedNull,
            TlvErrorCode::NoSpace => ErrorCode::NoSpace,
        }
    }
}

impl From<TlvErrorCode> for Error {
    fn from(value: TlvErrorCode) -> Self {
        ErrorCode::from(value).into()
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU8;

    use crate::utils::storage::{String, Vec, WriteBuf};
    use crate::{FromTLV, Nullable, TLVElement, TLVTag, TLVValueType, TLVWrite, ToTLV};

    use super::*;

    fn code<T>(result: Result<T, TlvError>) -> TlvErrorCode {
        match result {
            Ok(_) => panic!("Expected an error"),
            Err(err) => err.code(),
        }
    }

    #[test]
    fn malformed() {
        // No control byte
        assert_eq!(code(TLVElement::new(&[]).u8()), TlvErrorCode::Malformed);
        // A reserved element type
        assert_eq!(code(TLVElement::new(&[0x19]).u8()), TlvErrorCode::Malformed);
        // A U16 with one value byte only
        assert_eq!(
            code(TLVElement::new(&[0x05, 0x01]).u16()),
            TlvErrorCode::Malformed
        );
        // A UTF-8 string that is not valid UTF-8
        assert_eq!(
            code(TLVElement::new(&[0x0c, 0x01, 0xff]).utf8()),
            TlvErrorCode::Malformed
        );
    }

    #[test]
    fn type_mismatch() {
        let element = TLVElement::new(&[0x04, 0x05]);

        assert_eq!(code(element.i8()), TlvErrorCode::TypeMismatch);
        assert_eq!(code(element.bool()), TlvErrorCode::TypeMismatch);
        assert_eq!(code(element.str()), TlvErrorCode::TypeMismatch);
        assert_eq!(code(element.utf8()), TlvErrorCode::TypeMismatch);
        assert_eq!(code(element.structure()), TlvErrorCode::TypeMismatch);
        // An anonymous tag where a context tag is expected
        assert_eq!(code(element.ctx()), TlvErrorCode::TypeMismatch);

        let mut buf = [0; 8];
        let mut wb = WriteBuf::new(&mut buf);
        assert_eq!(
            code(wb.start_container(&TLVTag::Anonymous, TLVValueType::U8)),
            TlvErrorCode::TypeMismatch
        );
    }

    #[test]
    fn not_found() {
        // A struct with context tag 0 only
        let element = TLVElement::new(&[0x15, 0x24, 0x00, 0x05, 0x18]);

        assert_eq!(code(element.read::<u8>(1)), TlvErrorCode::NotFound);
        assert_eq!(
            code(element.structure().unwrap().ctx(1)),
            TlvErrorCode::NotFound
        );
    }

    #[test]
    fn invalid_value() {
        let element = TLVElement::new(&[0x04, 0x00]);

        assert_eq!(
            code(NonZeroU8::from_tlv(&element)),
            TlvErrorCode::InvalidValue
        );
    }

    #[test]
    fn capacity_exceeded() {
        // "abc" into a string of two bytes
        let element = TLVElement::new(&[0x0c, 0x03, b'a', b'b', b'c']);
        assert_eq!(
            code(String::<2>::from_tlv(&element)),
            TlvErrorCode::CapacityExceeded
        );

        // An array of two `u8`s into a vector of one
        let element = TLVElement::new(&[0x16, 0x04, 0x01, 0x04, 0x02, 0x18]);
        assert_eq!(
            code(Vec::<u8, 1>::from_tlv(&element)),
            TlvErrorCode::CapacityExceeded
        );
    }

    #[test]
    fn unexpected_null() {
        // 255 is the null marker of a nullable `u8`, and -128 of a nullable `i8`
        assert_eq!(
            code(Nullable::<u8>::from_tlv(&TLVElement::new(&[0x04, 0xff]))),
            TlvErrorCode::UnexpectedNull
        );
        assert_eq!(
            code(Nullable::<i8>::from_tlv(&TLVElement::new(&[0x00, 0x80]))),
            TlvErrorCode::UnexpectedNull
        );

        let mut buf = [0; 8];
        let mut wb = WriteBuf::new(&mut buf);
        assert_eq!(
            code(Nullable::some(u8::MAX).to_tlv(&TLVTag::Anonymous, &mut wb)),
            TlvErrorCode::UnexpectedNull
        );
    }

    #[test]
    fn no_space() {
        // A U16 needs three bytes
        let mut buf = [0; 2];
        let mut wb = WriteBuf::new(&mut buf);

        assert_eq!(
            code(wb.u16(&TLVTag::Anonymous, 0x1234)),
            TlvErrorCode::NoSpace
        );
    }

    #[test]
    fn bridge_keeps_the_value() {
        for code in [
            TlvErrorCode::Malformed,
            TlvErrorCode::TypeMismatch,
            TlvErrorCode::NotFound,
            TlvErrorCode::InvalidValue,
            TlvErrorCode::CapacityExceeded,
            TlvErrorCode::NoSpace,
            TlvErrorCode::UnexpectedNull,
        ] {
            assert_eq!(ErrorCode::from(code) as u8, code as u8);
        }
    }
}
