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
//! - [`ArrayAttestationTrustStore`]: no-alloc, backed by a fixed-capacity `heapless::Vec`.
//!   Stores `&'static [u8]` references — certificates embedded via `include_bytes!` stay
//!   in flash (rodata) with no RAM copy.
//!
//! - [`FileAttestationTrustStore`]: heap-backed, owns DER bytes. Loads PAA certificates
//!   from a directory of `.der` files at runtime (`std` only).

use crate::cert::x509::PaaCert;
use crate::error::{Error, ErrorCode};

const SKID_LEN: usize = 20;

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
    fn get_paa(&self, skid: &[u8]) -> Result<&[u8], Error>;
}

/// Extract and validate the Subject Key Identifier from a DER-encoded certificate.
fn extract_skid(cert: &[u8]) -> Result<[u8; SKID_LEN], Error> {
    PaaCert::new(cert)?
        .subject_key_id()?
        .try_into()
        .map_err(|_| ErrorCode::InvalidData.into())
}

/// A single PAA certificate entry for [`ArrayAttestationTrustStore`]:
/// pre-extracted SKID + reference to borrowed DER bytes.
struct BorrowedPaaCertEntry<'a> {
    skid: [u8; SKID_LEN],
    der: &'a [u8],
}

/// PAA trust store backed by a fixed-capacity `heapless::Vec`.
///
/// Stores `&'a [u8]` references to DER bytes — no RAM copy of certificate data.
/// Certificates embedded via `include_bytes!` are `'static` and live in flash (rodata);
///
/// The const generic `N` is the maximum number of PAA certificates.
///
/// To load PAAs from the filesystem at runtime, use [`FileAttestationTrustStore`].
///
/// # Example
///
/// ```ignore
/// use rs_matter::credentials::trust_store::ArrayAttestationTrustStore;
///
/// static PAA_CERT: &[u8] = include_bytes!("my-paa.der");
///
/// let store = ArrayAttestationTrustStore::<1>::from_certs(&[PAA_CERT]).unwrap();
/// ```
pub struct ArrayAttestationTrustStore<'a, const N: usize> {
    certs: heapless::Vec<BorrowedPaaCertEntry<'a>, N>,
}

impl<'a, const N: usize> ArrayAttestationTrustStore<'a, N> {
    /// Create a trust store from DER-encoded PAA certificate slices.
    ///
    /// Extracts the SKID from each certificate and stores a reference to the original
    /// bytes — the DER data is not copied into RAM.
    ///
    /// Returns `ErrorCode::InvalidData` if a certificate exceeds [`MAX_PAA_CERT_DER_LEN`],
    /// is malformed, or has no SKID.
    /// Returns `ErrorCode::NoSpace` if the number of certificates exceeds capacity `N`.
    pub fn from_certs(certs: &[&'a [u8]]) -> Result<Self, Error> {
        let mut store = Self {
            certs: heapless::Vec::new(),
        };

        for cert in certs {
            store.push_cert(cert)?;
        }

        Ok(store)
    }

    /// Number of PAA certificates in the store.
    pub fn paa_count(&self) -> usize {
        self.certs.len()
    }

    fn push_cert(&mut self, der: &'a [u8]) -> Result<(), Error> {
        if der.len() > MAX_PAA_CERT_DER_LEN {
            return Err(ErrorCode::InvalidData.into());
        }

        let skid = extract_skid(der)?;

        self.certs
            .push(BorrowedPaaCertEntry { skid, der })
            .map_err(|_| ErrorCode::NoSpace)?;

        Ok(())
    }
}

impl<'a, const N: usize> AttestationTrustStore for ArrayAttestationTrustStore<'a, N> {
    fn get_paa(&self, skid: &[u8]) -> Result<&[u8], Error> {
        if skid.len() != SKID_LEN {
            return Err(ErrorCode::InvalidArgument.into());
        }

        for entry in &self.certs {
            if entry.skid.as_slice() == skid {
                return Ok(entry.der);
            }
        }

        Err(ErrorCode::NotFound.into())
    }
}

/// A single PAA certificate entry for [`FileAttestationTrustStore`]:
/// pre-extracted SKID + owned DER bytes.
#[cfg(feature = "std")]
struct OwnedPaaCertEntry {
    skid: [u8; SKID_LEN],
    der: Vec<u8>,
}

/// PAA trust store that loads certificates from a directory of `.der` files.
///
/// Owns the DER bytes for each certificate. Loads all valid `.der` files from a
/// directory at construction time via [`from_directory`](Self::from_directory).
///
/// For compile-time embedded certificates, use [`ArrayAttestationTrustStore`] instead
/// — it is zero-copy and does not require `std`.
///
/// # Example
///
/// ```ignore
/// use rs_matter::credentials::trust_store::FileAttestationTrustStore;
///
/// let store = FileAttestationTrustStore::from_directory(
///     std::path::Path::new("/etc/matter/paa-certs")
/// ).unwrap();
/// ```
#[cfg(feature = "std")]
pub struct FileAttestationTrustStore {
    certs: Vec<OwnedPaaCertEntry>,
}

#[cfg(feature = "std")]
impl FileAttestationTrustStore {
    /// Load PAA certificates from `.der` files in the given directory.
    ///
    /// Skips files that:
    /// - Don't have a `.der` extension
    /// - Are larger than [`MAX_PAA_CERT_DER_LEN`] bytes
    /// - Fail to parse (invalid DER or missing SKID extension)
    ///
    /// Returns `ErrorCode::StdIoError` if the directory cannot be read.
    pub fn from_directory(dir: &std::path::Path) -> Result<Self, Error> {
        let mut store = Self { certs: Vec::new() };

        let entries = std::fs::read_dir(dir).map_err(|_| ErrorCode::StdIoError)?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path();

            // Only process .der files
            if path.extension().is_none_or(|ext| ext != "der") {
                continue;
            }

            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unknown>");

            // Check file size before reading
            let metadata = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        "Skipping PAA cert {}: cannot read metadata: {}",
                        file_name,
                        e.to_string()
                    );
                    continue;
                }
            };

            if metadata.len() > MAX_PAA_CERT_DER_LEN as u64 {
                warn!(
                    "Skipping PAA cert {}: file too large ({} bytes, max {})",
                    file_name,
                    metadata.len(),
                    MAX_PAA_CERT_DER_LEN,
                );
                continue;
            }

            // Read file contents — fs::read handles opening and allocation safely
            let der = match std::fs::read(&path) {
                Ok(data) => data,
                Err(e) => {
                    warn!(
                        "Skipping PAA cert {}: read error: {}",
                        file_name,
                        e.to_string()
                    );
                    continue;
                }
            };

            match store.push_cert_owned(der) {
                Ok(()) => {}
                Err(_) => {
                    warn!(
                        "Skipping PAA cert {}: invalid certificate or missing SKID",
                        file_name,
                    );
                }
            }
        }

        Ok(store)
    }

    /// Number of PAA certificates in the store.
    pub fn paa_count(&self) -> usize {
        self.certs.len()
    }

    fn push_cert_owned(&mut self, der: Vec<u8>) -> Result<(), Error> {
        let skid = extract_skid(&der)?;
        self.certs.push(OwnedPaaCertEntry { skid, der });
        Ok(())
    }
}

#[cfg(feature = "std")]
impl AttestationTrustStore for FileAttestationTrustStore {
    fn get_paa(&self, skid: &[u8]) -> Result<&[u8], Error> {
        if skid.len() != SKID_LEN {
            return Err(ErrorCode::InvalidArgument.into());
        }

        for entry in &self.certs {
            if entry.skid.as_slice() == skid {
                return Ok(&entry.der);
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

    // --- ArrayAttestationTrustStore tests ---

    #[test]
    fn store_finds_known_skid() {
        let store = ArrayAttestationTrustStore::<2>::from_certs(&[TEST_PAA_FFF1_CERT]).unwrap();
        assert_eq!(store.paa_count(), 1);
        let result = store.get_paa(&TEST_PAA_FFF1_SKID);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TEST_PAA_FFF1_CERT);
    }

    #[test]
    fn store_not_found_unknown_skid() {
        let store = ArrayAttestationTrustStore::<2>::from_certs(&[TEST_PAA_FFF1_CERT]).unwrap();
        assert_eq!(store.paa_count(), 1);
        let unknown_skid = [0xFF; 20];
        let result = store.get_paa(&unknown_skid);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), ErrorCode::NotFound);
    }

    #[test]
    fn store_multiple_certs() {
        let store = test_paa_store();
        assert_eq!(store.paa_count(), 2);

        let fff1 = store.get_paa(&TEST_PAA_FFF1_SKID).unwrap();
        assert_eq!(fff1, TEST_PAA_FFF1_CERT);

        let novid = store.get_paa(&TEST_PAA_NOVID_SKID).unwrap();
        assert_eq!(novid, TEST_PAA_NOVID_CERT);
    }

    #[test]
    fn store_empty() {
        let store = ArrayAttestationTrustStore::<2>::from_certs(&[]).unwrap();
        assert_eq!(store.paa_count(), 0);
        let result = store.get_paa(&TEST_PAA_FFF1_SKID);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), ErrorCode::NotFound);
    }

    #[test]
    fn store_wrong_skid_length() {
        let store = ArrayAttestationTrustStore::<2>::from_certs(&[TEST_PAA_FFF1_CERT]).unwrap();
        let short_skid = [0xFF; 19];
        let long_skid = [0xFF; 21];
        assert_eq!(
            store.get_paa(&short_skid).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            store.get_paa(&long_skid).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn store_capacity_exceeded() {
        let result =
            ArrayAttestationTrustStore::<1>::from_certs(&[TEST_PAA_FFF1_CERT, TEST_PAA_NOVID_CERT]);
        match result {
            Err(e) => assert_eq!(e.code(), ErrorCode::NoSpace),
            Ok(_) => panic!("expected NoSpace error"),
        }
    }

    #[test]
    fn store_cert_too_large() {
        static OVERSIZED: [u8; MAX_PAA_CERT_DER_LEN + 1] = [0u8; MAX_PAA_CERT_DER_LEN + 1];
        let result = ArrayAttestationTrustStore::<2>::from_certs(&[&OVERSIZED]);
        match result {
            Err(e) => assert_eq!(e.code(), ErrorCode::InvalidData),
            Ok(_) => panic!("expected InvalidData error"),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod std_tests {
    use super::*;
    use crate::credentials::test_paa::*;

    const TEST_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/credentials");

    /// Unique temp path for a test, avoiding collisions via PID.
    fn test_path(test_name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("paa_test_{}_{}", std::process::id(), test_name))
    }

    /// RAII guard that removes its directory on drop, even if a test panics.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Create a temp directory pre-populated with the contents of `credentials/`.
    fn create_test_dir(test_name: &str) -> TempDir {
        let path = test_path(test_name);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();

        for entry in std::fs::read_dir(TEST_DATA_DIR).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), path.join(entry.file_name())).unwrap();
        }

        TempDir(path)
    }

    /// Create an empty temp directory.
    fn create_empty_test_dir(test_name: &str) -> TempDir {
        let path = test_path(test_name);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();

        TempDir(path)
    }

    fn write_file(dir: &std::path::Path, name: &str, data: &[u8]) {
        use std::io::Write;
        let path = dir.join(name);
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(data).unwrap();
    }

    #[test]
    fn from_directory_loads() {
        let dir = create_test_dir("loads");
        write_file(dir.path(), "readme.txt", b"not a cert");

        let store = FileAttestationTrustStore::from_directory(dir.path()).unwrap();
        assert_eq!(store.paa_count(), 2);
    }

    #[test]
    fn from_directory_skips_invalid() {
        let dir = create_test_dir("skips");
        write_file(dir.path(), "garbage.der", &[0xDE, 0xAD, 0xBE, 0xEF]);
        write_file(dir.path(), "toobig.der", &[0u8; 700]);

        let store = FileAttestationTrustStore::from_directory(dir.path()).unwrap();
        assert_eq!(store.paa_count(), 2);
    }

    #[test]
    fn from_directory_lookup() {
        let dir = create_test_dir("lookup");

        let store = FileAttestationTrustStore::from_directory(dir.path()).unwrap();

        let fff1 = store.get_paa(&TEST_PAA_FFF1_SKID).unwrap();
        assert_eq!(fff1, TEST_PAA_FFF1_CERT);

        let novid = store.get_paa(&TEST_PAA_NOVID_SKID).unwrap();
        assert_eq!(novid, TEST_PAA_NOVID_CERT);

        let unknown = store.get_paa(&[0xFF; 20]);
        assert!(unknown.is_err());
    }

    #[test]
    fn from_directory_empty() {
        let dir = create_empty_test_dir("empty");

        let store = FileAttestationTrustStore::from_directory(dir.path()).unwrap();
        assert_eq!(store.paa_count(), 0);
        assert!(store.get_paa(&TEST_PAA_FFF1_SKID).is_err());
    }

    #[test]
    fn from_directory_nonexistent() {
        let dir = test_path("nonexistent");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(FileAttestationTrustStore::from_directory(&dir).is_err());
    }
}
