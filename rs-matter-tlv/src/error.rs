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

use rs_matter_utils::error::Error2;

// TODO: Remove once the TLV traits (`ToTLV`, `FromTLV`, `TLVBuilder`) report
// `TlvError` too. Until then their implementors still name the shared `Error`,
// and reach it through this module.
use rs_matter_utils::error::{Error, ErrorCode};

pub type TlvError = Error2<TlvErrorCode>;

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
impl From<TlvErrorCode> for Error {
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
        .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!(Error::from(code).code() as u8, code as u8);
        }
    }
}
