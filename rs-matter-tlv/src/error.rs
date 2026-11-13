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
pub use rs_matter_utils::error::{Error, ErrorCode};

pub type TlvError = Error2<TlvErrorCode>;

/// The errors raised when reading or writing Matter TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlvErrorCode {
    /// The byte stream is not well-formed TLV.
    Malformed,
    /// The element is well-formed but not of the requested type.
    TypeMismatch,
    /// A required element or context tag is absent.
    NotFound,
    /// The element has the right type, but the value is not an acceptable one.
    InvalidValue,
    /// The destination container could not hold the decoded data.
    CapacityExceeded,
    /// The value is the reserved null sentinel where null is not permitted.
    UnexpectedNull,
    /// The TLV writer ran out of room.
    NoSpace,
}

// TODO: Remove this bridge once all dependent crates have been refactored to
// explicitly handle `TlvError`.
impl From<TlvErrorCode> for Error {
    fn from(value: TlvErrorCode) -> Self {
        match value {
            TlvErrorCode::Malformed => ErrorCode::InvalidData.into(),
            TlvErrorCode::TypeMismatch => ErrorCode::TLVTypeMismatch.into(),
            TlvErrorCode::NotFound => ErrorCode::NotFound.into(),
            TlvErrorCode::InvalidValue => ErrorCode::Invalid.into(),
            TlvErrorCode::CapacityExceeded | TlvErrorCode::UnexpectedNull => {
                ErrorCode::ConstraintError.into()
            }
            TlvErrorCode::NoSpace => ErrorCode::NoSpace.into(),
        }
    }
}
