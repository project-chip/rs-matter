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

//! PAA (Product Attestation Authority) trust store for device attestation.
//!
//! Provides the [`AttestationTrustStore`] trait for PAA certificate lookup by SKID,
//! and two concrete implementations:
//!
//! - `&[&[u8]]`: no-alloc, const-constructible. Stores `&'static [u8]` references —
//!   certificates embedded via `include_bytes!` stay in flash (rodata) with no RAM copy.
//!
//! - [`FileAttestationTrustStore`]: heap-backed, owns DER bytes. Loads PAA certificates
//!   from a directory of `.der` files at runtime (`std` only).

use crate::cert::x509::PaaCert;
use crate::error::{Error, ErrorCode};

/// Matter certificate key identifier (SKID/AKID): 20-byte SHA-1 hash of the public key.
/// Matter spec Section 6.1.2 mandates 20 octets, per RFC 5280 method (1).
pub type KeyId = [u8; 20];

/// Maximum length of a DER-encoded PAA certificate.
/// Matches C++ SDK `kMaxDERCertLength` (CHIPCert.h).
pub const MAX_PAA_CERT_DER_LEN: usize = 600;

/// Trait for looking up PAA certificates by Subject Key Identifier (SKID).
///
/// Used during device commissioning to find the PAA that issued a device's PAI,
/// by matching the PAI's Authority Key Identifier (AKID) against PAA SKIDs.
pub trait AttestationTrustStore {
    /// Look up a PAA certificate by its Subject Key Identifier.
    ///
    /// Returns the DER-encoded PAA certificate, or `ErrorCode::NotFound`
    /// if no PAA with the given SKID is present in the store.
    fn paa(&self, skid: &KeyId) -> Result<&[u8], Error>;
}

impl<T: AttestationTrustStore> AttestationTrustStore for &T {
    fn paa(&self, skid: &KeyId) -> Result<&[u8], Error> {
        (**self).paa(skid)
    }
}

/// Extract and validate the Subject Key Identifier from a DER-encoded certificate.
pub(crate) fn extract_skid(cert: &[u8]) -> Result<KeyId, Error> {
    PaaCert::new(cert)?
        .subject_key_id()?
        .try_into()
        .map_err(|_| ErrorCode::InvalidData.into())
}

/// `AttestationTrustStore` implementation for a slice of DER-encoded certificates.
///
/// # Example
///
/// ```ignore
/// const PAA_STORE: &[&[u8]] = &[PAA_CERT_1, PAA_CERT_2];
/// let paa = PAA_STORE.paa(&skid)?;
/// ```
impl AttestationTrustStore for &[&[u8]] {
    fn paa(&self, skid: &KeyId) -> Result<&[u8], Error> {
        for cert in self.iter() {
            if let Ok(cert_skid) = extract_skid(cert) {
                if cert_skid == *skid {
                    return Ok(cert);
                }
            }
        }

        Err(ErrorCode::NotFound.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::test_paa::*;
    use crate::error::ErrorCode;

    #[test]
    fn store_finds_known_skid() {
        let store: &[&[u8]] = &[TEST_PAA_FFF1_CERT];
        let result = store.paa(&TEST_PAA_FFF1_SKID);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TEST_PAA_FFF1_CERT);
    }

    #[test]
    fn store_not_found_unknown_skid() {
        let store: &[&[u8]] = &[TEST_PAA_FFF1_CERT];
        let unknown_skid = [0xFF; 20];
        let result = store.paa(&unknown_skid);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), ErrorCode::NotFound);
    }

    #[test]
    fn store_multiple_certs() {
        let store = TEST_PAA_STORE;
        assert_eq!(store.len(), 2);

        let fff1 = store.paa(&TEST_PAA_FFF1_SKID).unwrap();
        assert_eq!(fff1, TEST_PAA_FFF1_CERT);

        let novid = store.paa(&TEST_PAA_NOVID_SKID).unwrap();
        assert_eq!(novid, TEST_PAA_NOVID_CERT);
    }

    #[test]
    fn store_empty() {
        let store: &[&[u8]] = &[];
        let result = store.paa(&TEST_PAA_FFF1_SKID);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), ErrorCode::NotFound);
    }
}
