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

//! The error type of `rs-matter-pairing`.

// Only for the bridge to the legacy `Error` below
use rs_matter_utils::error::{Error, ErrorCode};

rs_matter_utils::error_type!(
    /// The error of `rs-matter-pairing`.
    pub PairingError, PairingErrorCode
);

/// The errors raised when building or parsing onboarding payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum PairingErrorCode {
    // TODO: Drop the explicit values together with the bridge below. Until then
    // each code has the value of the legacy `ErrorCode` it maps to, so that the
    // bridge compiles to nothing.
    /// Not a valid onboarding payload, manual pairing code or verifier: a wrong
    /// prefix, character, length or check digit, or a field out of range. Also a
    /// payload too long for an NDEF short record.
    InvalidInput = ErrorCode::InvalidData as u8,
    /// A buffer supplied by the caller is too small for the result.
    BufferTooSmall = ErrorCode::BufferTooSmall as u8,
}

// TODO: Remove this bridge once all dependent crates have been refactored to
// explicitly handle `PairingError`.
impl From<PairingErrorCode> for ErrorCode {
    fn from(value: PairingErrorCode) -> Self {
        match value {
            PairingErrorCode::InvalidInput => ErrorCode::InvalidData,
            PairingErrorCode::BufferTooSmall => ErrorCode::BufferTooSmall,
        }
    }
}

impl From<PairingErrorCode> for Error {
    fn from(value: PairingErrorCode) -> Self {
        ErrorCode::from(value).into()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn bridge_keeps_the_value() {
        for code in [
            PairingErrorCode::InvalidInput,
            PairingErrorCode::BufferTooSmall,
        ] {
            assert_eq!(ErrorCode::from(code) as u8, code as u8);
        }
    }
}
