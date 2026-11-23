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

//! The error type of `rs-matter-cert`.

use crate::crypto::{CryptoError, CryptoErrorCode};
use crate::tlv::{TlvError, TlvErrorCode};

// Only for the bridge to the legacy `Error` below
use rs_matter_utils::error::{Error, ErrorCode};

rs_matter_utils::error_type!(
    /// The error of `rs-matter-cert`.
    pub CertError, CertErrorCode
);

/// The errors raised when decoding, verifying or writing certificates, CSRs and
/// certification declarations.
///
/// The codes say what happened, not to which object: the caller knows whether it
/// checked e.g. a DAC, a PAI or a certification declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum CertErrorCode {
    // TODO: Drop the explicit values together with the bridge below. Until then
    // each code has the value of the legacy `ErrorCode` it maps to, so that the
    // bridge compiles to nothing.
    /// A certificate, a CSR or a certification declaration cannot be decoded, or
    /// breaks the format that Matter requires for it, e.g. the basic constraints
    /// or the key usage of a certificate for its place in the chain.
    InvalidFormat = ErrorCode::InvalidData as u8,
    /// The certificate was not issued by the one given as its issuer: their key
    /// identifiers differ.
    WrongIssuer = ErrorCode::InvalidAuthKey as u8,
    /// A signature does not verify.
    InvalidSignature = ErrorCode::InvalidSignature as u8,
    /// The certificate is not valid at the given time: it has expired, or it is
    /// not valid yet.
    OutsideValidityPeriod = ErrorCode::InvalidTime as u8,
    /// What was looked up is not there: a PAA in a trust store, the key that
    /// signed a certification declaration, or an attribute of a certificate.
    NotFound = ErrorCode::NotFound as u8,
    /// A vendor ID does not match, e.g. the one of a certification declaration.
    VendorIdMismatch = ErrorCode::CdInvalidVendorId as u8,
    /// A product ID does not match, e.g. the ones of a certification declaration.
    ProductIdMismatch = ErrorCode::CdInvalidProductId as u8,
    /// The certification declaration does not authorize the PAA.
    PaaNotAuthorized = ErrorCode::CdInvalidPaa as u8,
    /// A buffer supplied by the caller is too small for the result.
    BufferTooSmall = ErrorCode::BufferTooSmall as u8,
    /// The crypto backend could not allocate memory.
    NoMemory = ErrorCode::NoMemory as u8,
}

impl From<TlvErrorCode> for CertErrorCode {
    fn from(value: TlvErrorCode) -> Self {
        match value {
            TlvErrorCode::NoSpace => Self::BufferTooSmall,
            _ => Self::InvalidFormat,
        }
    }
}

impl From<TlvError> for CertError {
    fn from(err: TlvError) -> Self {
        let code = err.code().into();
        err.convert(code).into()
    }
}

impl From<CryptoErrorCode> for CertErrorCode {
    fn from(value: CryptoErrorCode) -> Self {
        match value {
            CryptoErrorCode::InvalidInput => Self::InvalidFormat,
            CryptoErrorCode::NoMemory => Self::NoMemory,
            CryptoErrorCode::BufferTooSmall => Self::BufferTooSmall,
        }
    }
}

impl From<CryptoError> for CertError {
    fn from(err: CryptoError) -> Self {
        let code = err.code().into();
        err.convert(code).into()
    }
}

// TODO: Remove this bridge once all dependent crates have been refactored to
// explicitly handle `CertError`.
impl From<CertErrorCode> for ErrorCode {
    fn from(value: CertErrorCode) -> Self {
        match value {
            CertErrorCode::InvalidFormat => ErrorCode::InvalidData,
            CertErrorCode::WrongIssuer => ErrorCode::InvalidAuthKey,
            CertErrorCode::InvalidSignature => ErrorCode::InvalidSignature,
            CertErrorCode::OutsideValidityPeriod => ErrorCode::InvalidTime,
            CertErrorCode::NotFound => ErrorCode::NotFound,
            CertErrorCode::VendorIdMismatch => ErrorCode::CdInvalidVendorId,
            CertErrorCode::ProductIdMismatch => ErrorCode::CdInvalidProductId,
            CertErrorCode::PaaNotAuthorized => ErrorCode::CdInvalidPaa,
            CertErrorCode::BufferTooSmall => ErrorCode::BufferTooSmall,
            CertErrorCode::NoMemory => ErrorCode::NoMemory,
        }
    }
}

impl From<CertErrorCode> for Error {
    fn from(value: CertErrorCode) -> Self {
        ErrorCode::from(value).into()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn tlv_and_crypto_errors_convert() {
        let code = |err: CertError| err.code();

        assert_eq!(
            code(TlvError::new(TlvErrorCode::NoSpace).into()),
            CertErrorCode::BufferTooSmall
        );
        assert_eq!(
            code(TlvError::new(TlvErrorCode::TypeMismatch).into()),
            CertErrorCode::InvalidFormat
        );

        assert_eq!(
            code(CryptoError::new(CryptoErrorCode::InvalidInput).into()),
            CertErrorCode::InvalidFormat
        );
        assert_eq!(
            code(CryptoError::new(CryptoErrorCode::NoMemory).into()),
            CertErrorCode::NoMemory
        );
    }

    #[test]
    fn bridge_keeps_the_value() {
        for code in [
            CertErrorCode::InvalidFormat,
            CertErrorCode::WrongIssuer,
            CertErrorCode::InvalidSignature,
            CertErrorCode::OutsideValidityPeriod,
            CertErrorCode::NotFound,
            CertErrorCode::VendorIdMismatch,
            CertErrorCode::ProductIdMismatch,
            CertErrorCode::PaaNotAuthorized,
            CertErrorCode::BufferTooSmall,
            CertErrorCode::NoMemory,
        ] {
            assert_eq!(ErrorCode::from(code) as u8, code as u8);
        }
    }
}
