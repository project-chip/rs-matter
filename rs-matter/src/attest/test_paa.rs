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

//! Test PAA (Product Attestation Authority) certificates for development/testing.
//!
//! These are the test certificates from the C++ SDK:
//! `connectedhomeip/credentials/development/paa-root-certs/`
//!
//! Two PAAs are provided:
//! - `TEST_PAA_FFF1_CERT`: Vendor-scoped PAA for test vendor 0xFFF1
//! - `TEST_PAA_NOVID_CERT`: Non-vendor-scoped PAA (no Vendor ID)

/// DER-encoded test PAA certificate for vendor 0xFFF1 (449 bytes).
///
/// Subject: CN=Matter Test PAA, VID=FFF1
/// SKID: 6A:FD:22:77:1F:51:1F:EC:BF:16:41:97:67:10:DC:DC:31:A1:71:7E
///
/// Source: connectedhomeip/credentials/development/paa-root-certs/Chip-Test-PAA-FFF1-Cert.der
pub const TEST_PAA_FFF1_CERT: &[u8] = include_bytes!("test_paa/Chip-Test-PAA-FFF1-Cert.der");

/// Expected SKID for TEST_PAA_FFF1_CERT.
pub const TEST_PAA_FFF1_SKID: super::trust_store::KeyId = [
    0x6A, 0xFD, 0x22, 0x77, 0x1F, 0x51, 0x1F, 0xEC, 0xBF, 0x16, 0x41, 0x97, 0x67, 0x10, 0xDC, 0xDC,
    0x31, 0xA1, 0x71, 0x7E,
];

/// DER-encoded test PAA certificate with no Vendor ID (405 bytes).
///
/// Subject: CN=Matter Test PAA
/// SKID: 78:5C:E7:05:B8:6B:8F:4E:6F:C7:93:AA:60:CB:43:EA:69:68:82:D5
///
/// Source: connectedhomeip/credentials/development/paa-root-certs/Chip-Test-PAA-NoVID-Cert.der
pub const TEST_PAA_NOVID_CERT: &[u8] = include_bytes!("test_paa/Chip-Test-PAA-NoVID-Cert.der");

/// Expected SKID for TEST_PAA_NOVID_CERT.
pub const TEST_PAA_NOVID_SKID: super::trust_store::KeyId = [
    0x78, 0x5C, 0xE7, 0x05, 0xB8, 0x6B, 0x8F, 0x4E, 0x6F, 0xC7, 0x93, 0xAA, 0x60, 0xCB, 0x43, 0xEA,
    0x69, 0x68, 0x82, 0xD5,
];

/// Test trust store containing both test PAAs.
///
/// Use this for development and testing. For production, use
/// [`FileAttestationTrustStore::from_directory`](super::trust_store::FileAttestationTrustStore::from_directory)
/// (std) or a `&[&[u8]]` slice with real PAA certificates.
pub const TEST_PAA_STORE: &[&[u8]] = &[TEST_PAA_FFF1_CERT, TEST_PAA_NOVID_CERT];
