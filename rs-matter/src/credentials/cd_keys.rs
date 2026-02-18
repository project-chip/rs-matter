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

//! Well-known CSA Certification Declaration signing key trust store.
//!
//! Contains the 6 well-known CD signing keys from the Matter specification:
//! - 1 test key (self-signed, for development/testing only)
//! - 5 official CSA signing keys (chaining to the CSA "Matter Certification and Testing CA")
//!
//! Reference: connectedhomeip `src/credentials/attestation_verifier/DefaultDeviceAttestationVerifier.cpp`

/// Length of a Subject Key Identifier (SHA-1 hash), in bytes.
/// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2
pub const KEY_IDENTIFIER_LEN: usize = 20;

/// Length of an uncompressed P-256 public key (0x04 || X || Y), in bytes.
pub const P256_PUBLIC_KEY_LEN: usize = 65;

/// A CD signing key entry: Subject Key Identifier + P-256 uncompressed public key.
struct CdSigningKey {
    kid: [u8; KEY_IDENTIFIER_LEN],
    pubkey: [u8; P256_PUBLIC_KEY_LEN],
}

// ---------------------------------------------------------------------------
// Test CD Signing Key
//
// Self-signed "Matter Test CD Signing Authority" certificate.
// This key does NOT chain to the CSA root. It is only valid for
// CertificationType::DevelopmentAndTest (and optionally Provisional).
//
// Certificate PEM: connectedhomeip `credentials/test/certification-declaration/Chip-Test-CD-Signing-Cert.pem`
//
// -----BEGIN CERTIFICATE-----
// MIIBszCCAVqgAwIBAgIIRdrzneR6oI8wCgYIKoZIzj0EAwIwKzEpMCcGA1UEAwwg
// TWF0dGVyIFRlc3QgQ0QgU2lnbmluZyBBdXRob3JpdHkwIBcNMjEwNjI4MTQyMzQz
// WhgPOTk5OTEyMzEyMzU5NTlaMCsxKTAnBgNVBAMMIE1hdHRlciBUZXN0IENEIFNp
// Z25pbmcgQXV0aG9yaXR5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPDmJIkUr
// VcrzicJb0bykZWlSzLkOiGkkmthHRlMBTL+V1oeWXgNrUhxRA35rjO3vyh60QEZp
// T6CIgu7WUZ3suqNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMC
// AQYwHQYDVR0OBBYEFGL6gjNZrPqplj4c+hQK3fUE83FgMB8GA1UdIwQYMBaAFGL6
// gjNZrPqplj4c+hQK3fUE83FgMAoGCCqGSM49BAMCA0cAMEQCICxUXOTkV9im8NnZ
// u+vW7OHd/n+MbZps83UyH8b6xxOEAiBUB3jodDlyUn7t669YaGIgtUB48s1OYqdq
// 58u5L/VMiw==
// -----END CERTIFICATE-----
// ---------------------------------------------------------------------------

/// Subject Key Identifier for the test CD signing key.
pub const TEST_CD_KID: [u8; KEY_IDENTIFIER_LEN] = [
    0x62, 0xfa, 0x82, 0x33, 0x59, 0xac, 0xfa, 0xa9, 0x96, 0x3e, 0x1c, 0xfa, 0x14, 0x0a, 0xdd, 0xf5,
    0x04, 0xf3, 0x71, 0x60,
];

const TEST_CD_PUBKEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0x3c, 0x39, 0x89, 0x22, 0x45, 0x2b, 0x55, 0xca, 0xf3, 0x89, 0xc2, 0x5b, 0xd1, 0xbc, 0xa4,
    0x65, 0x69, 0x52, 0xcc, 0xb9, 0x0e, 0x88, 0x69, 0x24, 0x9a, 0xd8, 0x47, 0x46, 0x53, 0x01, 0x4c,
    0xbf, 0x95, 0xd6, 0x87, 0x96, 0x5e, 0x03, 0x6b, 0x52, 0x1c, 0x51, 0x03, 0x7e, 0x6b, 0x8c, 0xed,
    0xef, 0xca, 0x1e, 0xb4, 0x40, 0x46, 0x69, 0x4f, 0xa0, 0x88, 0x82, 0xee, 0xd6, 0x51, 0x9d, 0xec,
    0xba,
];

// ---------------------------------------------------------------------------
// Official CD Signing Key 001
// Issued by CSA "Matter Certification and Testing CA"
//
// -----BEGIN CERTIFICATE-----
// MIICBzCCAa2gAwIBAgIHY3NhY2RrMTAKBggqhkjOPQQDAjBSMQwwCgYDVQQKDAND
// U0ExLDAqBgNVBAMMI01hdHRlciBDZXJ0aWZpY2F0aW9uIGFuZCBUZXN0aW5nIENB
// MRQwEgYKKwYBBAGConwCAQwEQzVBMDAgFw0yMjEwMDMxOTI4NTVaGA8yMDcyMDky
// MDE5Mjg1NVowWDEMMAoGA1UECgwDQ1NBMTIwMAYDVQQDDClDZXJ0aWZpY2F0aW9u
// IERlY2xhcmF0aW9uIFNpZ25pbmcgS2V5IDAwMTEUMBIGCisGAQQBgqJ8AgEMBEM1
// QTAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATN7uk+RPi3K+PRqcB+IZaLmv/z
// tAPwXhZp17Hlyu5vx3FLQufiNpXpLNdjVHOigK5ojze7lInhFim5uU/3sJkpo2Yw
// ZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU
// /jQ/lZlHdjth7kU5ExM4SU/mfY4wHwYDVR0jBBgwFoAUl+Rp0MUEFMJvxwH3fpR3
// OQmN9qUwCgYIKoZIzj0EAwIDSAAwRQIgEDWOcdKsVGtUh3evHbBd1lq4aS7yQtOp
// 6GrOQ3/zXBsCIQDxorh2RXSaI8m2RCcoWaiWa0nLzQepNm3C2jrQVJmC2Q==
// -----END CERTIFICATE-----
// ---------------------------------------------------------------------------

const CD_SIGNING_KEY_001_KID: [u8; KEY_IDENTIFIER_LEN] = [
    0xFE, 0x34, 0x3F, 0x95, 0x99, 0x47, 0x76, 0x3B, 0x61, 0xEE, 0x45, 0x39, 0x13, 0x13, 0x38, 0x49,
    0x4F, 0xE6, 0x7D, 0x8E,
];

const CD_SIGNING_KEY_001_PUBKEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0xcd, 0xee, 0xe9, 0x3e, 0x44, 0xf8, 0xb7, 0x2b, 0xe3, 0xd1, 0xa9, 0xc0, 0x7e, 0x21, 0x96,
    0x8b, 0x9a, 0xff, 0xf3, 0xb4, 0x03, 0xf0, 0x5e, 0x16, 0x69, 0xd7, 0xb1, 0xe5, 0xca, 0xee, 0x6f,
    0xc7, 0x71, 0x4b, 0x42, 0xe7, 0xe2, 0x36, 0x95, 0xe9, 0x2c, 0xd7, 0x63, 0x54, 0x73, 0xa2, 0x80,
    0xae, 0x68, 0x8f, 0x37, 0xbb, 0x94, 0x89, 0xe1, 0x16, 0x29, 0xb9, 0xb9, 0x4f, 0xf7, 0xb0, 0x99,
    0x29,
];

// ---------------------------------------------------------------------------
// Official CD Signing Key 002
//
// -----BEGIN CERTIFICATE-----
// MIICCDCCAa2gAwIBAgIHY3NhY2RrMjAKBggqhkjOPQQDAjBSMQwwCgYDVQQKDAND
// U0ExLDAqBgNVBAMMI01hdHRlciBDZXJ0aWZpY2F0aW9uIGFuZCBUZXN0aW5nIENB
// MRQwEgYKKwYBBAGConwCAQwEQzVBMDAgFw0yMjEwMDMxOTM2NDZaGA8yMDcyMDky
// MDE5MzY0NlowWDEMMAoGA1UECgwDQ1NBMTIwMAYDVQQDDClDZXJ0aWZpY2F0aW9u
// IERlY2xhcmF0aW9uIFNpZ25pbmcgS2V5IDAwMjEUMBIGCisGAQQBgqJ8AgEMBEM1
// QTAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQDGTfo+UJRBF3ydFe7RiU+43VO
// jBKuKFV9gCe51MNW2RtAjP8yJ1AXsl+Mi6IFFtXIOvK3JBKAE9/Mj5XSAKkLo2Yw
// ZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU
// 3QTbWFshTBxYFYfmVo30h7bdxwEwHwYDVR0jBBgwFoAUl+Rp0MUEFMJvxwH3fpR3
// OQmN9qUwCgYIKoZIzj0EAwIDSQAwRgIhAJruzxZ806cP/LoQ07PN9xAbjLdwUalV
// h0Qfx304Tb92AiEAk+jnf2qtyfKyTEHpT3Xf3bfekqUOA+8ikB1yjL5oTsI=
// -----END CERTIFICATE-----
// ---------------------------------------------------------------------------

const CD_SIGNING_KEY_002_KID: [u8; KEY_IDENTIFIER_LEN] = [
    0xDD, 0x04, 0xDB, 0x58, 0x5B, 0x21, 0x4C, 0x1C, 0x58, 0x15, 0x87, 0xE6, 0x56, 0x8D, 0xF4, 0x87,
    0xB6, 0xDD, 0xC7, 0x01,
];

const CD_SIGNING_KEY_002_PUBKEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0x03, 0x19, 0x37, 0xe8, 0xf9, 0x42, 0x51, 0x04, 0x5d, 0xf2, 0x74, 0x57, 0xbb, 0x46, 0x25,
    0x3e, 0xe3, 0x75, 0x4e, 0x8c, 0x12, 0xae, 0x28, 0x55, 0x7d, 0x80, 0x27, 0xb9, 0xd4, 0xc3, 0x56,
    0xd9, 0x1b, 0x40, 0x8c, 0xff, 0x32, 0x27, 0x50, 0x17, 0xb2, 0x5f, 0x8c, 0x8b, 0xa2, 0x05, 0x16,
    0xd5, 0xc8, 0x3a, 0xf2, 0xb7, 0x24, 0x12, 0x80, 0x13, 0xdf, 0xcc, 0x8f, 0x95, 0xd2, 0x00, 0xa9,
    0x0b,
];

// ---------------------------------------------------------------------------
// Official CD Signing Key 003
//
// -----BEGIN CERTIFICATE-----
// MIICBjCCAa2gAwIBAgIHY3NhY2RrMzAKBggqhkjOPQQDAjBSMQwwCgYDVQQKDAND
// U0ExLDAqBgNVBAMMI01hdHRlciBDZXJ0aWZpY2F0aW9uIGFuZCBUZXN0aW5nIENB
// MRQwEgYKKwYBBAGConwCAQwEQzVBMDAgFw0yMjEwMDMxOTQxMDFaGA8yMDcyMDky
// MDE5NDEwMVowWDEMMAoGA1UECgwDQ1NBMTIwMAYDVQQDDClDZXJ0aWZpY2F0aW9u
// IERlY2xhcmF0aW9uIFNpZ25pbmcgS2V5IDAwMzEUMBIGCisGAQQBgqJ8AgEMBEM1
// QTAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASfV1zV/bdSHxCk3zHwc5ErYUco
// 8tN/W2uWvCy/fAsRlpBXfVVdIaCWYKiwgqM56lMPeoEthpO1b9dkGF+rzTL1o2Yw
// ZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU
// RxA158BOqqi+fE1ME+PkwgmVqEswHwYDVR0jBBgwFoAUl+Rp0MUEFMJvxwH3fpR3
// OQmN9qUwCgYIKoZIzj0EAwIDRwAwRAIgIFecbY+1mVVNqxH9+8IMB8+safdyIJU2
// AqqtZ/w7AkQCIHiVlYTaCnJsnW5/cvj9GfIv7Eb0cjdmcAkrYGbnPQzX
// -----END CERTIFICATE-----
// ---------------------------------------------------------------------------

const CD_SIGNING_KEY_003_KID: [u8; KEY_IDENTIFIER_LEN] = [
    0x47, 0x10, 0x35, 0xE7, 0xC0, 0x4E, 0xAA, 0xA8, 0xBE, 0x7C, 0x4D, 0x4C, 0x13, 0xE3, 0xE4, 0xC2,
    0x09, 0x95, 0xA8, 0x4B,
];

const CD_SIGNING_KEY_003_PUBKEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0x9f, 0x57, 0x5c, 0xd5, 0xfd, 0xb7, 0x52, 0x1f, 0x10, 0xa4, 0xdf, 0x31, 0xf0, 0x73, 0x91,
    0x2b, 0x61, 0x47, 0x28, 0xf2, 0xd3, 0x7f, 0x5b, 0x6b, 0x96, 0xbc, 0x2c, 0xbf, 0x7c, 0x0b, 0x11,
    0x96, 0x90, 0x57, 0x7d, 0x55, 0x5d, 0x21, 0xa0, 0x96, 0x60, 0xa8, 0xb0, 0x82, 0xa3, 0x39, 0xea,
    0x53, 0x0f, 0x7a, 0x81, 0x2d, 0x86, 0x93, 0xb5, 0x6f, 0xd7, 0x64, 0x18, 0x5f, 0xab, 0xcd, 0x32,
    0xf5,
];

// ---------------------------------------------------------------------------
// Official CD Signing Key 004
//
// -----BEGIN CERTIFICATE-----
// MIICBjCCAa2gAwIBAgIHY3NhY2RrNDAKBggqhkjOPQQDAjBSMQwwCgYDVQQKDAND
// U0ExLDAqBgNVBAMMI01hdHRlciBDZXJ0aWZpY2F0aW9uIGFuZCBUZXN0aW5nIENB
// MRQwEgYKKwYBBAGConwCAQwEQzVBMDAgFw0yMjEwMDMxOTQzMjFaGA8yMDcyMDky
// MDE5NDMyMVowWDEMMAoGA1UECgwDQ1NBMTIwMAYDVQQDDClDZXJ0aWZpY2F0aW9u
// IERlY2xhcmF0aW9uIFNpZ25pbmcgS2V5IDAwNDEUMBIGCisGAQQBgqJ8AgEMBEM1
// QTAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR8/I2IEKic9PoZF3jyr+x4+FF6
// l6Plf8ITutiI42EedP+2hL3rqKaLJSNKXDWPNzurm20wThMG3XYgpSjRFhwLo2Yw
// ZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU
// 9oYDo2kumBByQZ6h4as4VL13ldMwHwYDVR0jBBgwFoAUl+Rp0MUEFMJvxwH3fpR3
// OQmN9qUwCgYIKoZIzj0EAwIDRwAwRAIgLqAfkbtLYYdmQsnbn0CWv3G1/lbE36nz
// HbLbW5t6PY4CIE8oyIHsVhNSTPcb3mwRp+Vxhs8tKhbAdwv5BGgDaAHj
// -----END CERTIFICATE-----
// ---------------------------------------------------------------------------

const CD_SIGNING_KEY_004_KID: [u8; KEY_IDENTIFIER_LEN] = [
    0xF6, 0x86, 0x03, 0xA3, 0x69, 0x2E, 0x98, 0x10, 0x72, 0x41, 0x9E, 0xA1, 0xE1, 0xAB, 0x38, 0x54,
    0xBD, 0x77, 0x95, 0xD3,
];

const CD_SIGNING_KEY_004_PUBKEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0x7c, 0xfc, 0x8d, 0x88, 0x10, 0xa8, 0x9c, 0xf4, 0xfa, 0x19, 0x17, 0x78, 0xf2, 0xaf, 0xec,
    0x78, 0xf8, 0x51, 0x7a, 0x97, 0xa3, 0xe5, 0x7f, 0xc2, 0x13, 0xba, 0xd8, 0x88, 0xe3, 0x61, 0x1e,
    0x74, 0xff, 0xb6, 0x84, 0xbd, 0xeb, 0xa8, 0xa6, 0x8b, 0x25, 0x23, 0x4a, 0x5c, 0x35, 0x8f, 0x37,
    0x3b, 0xab, 0x9b, 0x6d, 0x30, 0x4e, 0x13, 0x06, 0xdd, 0x76, 0x20, 0xa5, 0x28, 0xd1, 0x16, 0x1c,
    0x0b,
];

// ---------------------------------------------------------------------------
// Official CD Signing Key 005
//
// -----BEGIN CERTIFICATE-----
// MIICBzCCAa2gAwIBAgIHY3NhY2RrNTAKBggqhkjOPQQDAjBSMQwwCgYDVQQKDAND
// U0ExLDAqBgNVBAMMI01hdHRlciBDZXJ0aWZpY2F0aW9uIGFuZCBUZXN0aW5nIENB
// MRQwEgYKKwYBBAGConwCAQwEQzVBMDAgFw0yMjEwMDMxOTQ3MTVaGA8yMDcyMDky
// MDE5NDcxNVowWDEMMAoGA1UECgwDQ1NBMTIwMAYDVQQDDClDZXJ0aWZpY2F0aW9u
// IERlY2xhcmF0aW9uIFNpZ25pbmcgS2V5IDAwNTEUMBIGCisGAQQBgqJ8AgEMBEM1
// QTAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARDilLGYqKm1yZH+V63UxNu5K4P
// 2zqpwWkxQms9CGf5EDrn16G4h+n4E6byb3a7zak1k3h8EneMqPKXXcRaIEL5o2Yw
// ZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU
// Y38mNK1i6v5q9mLvuW9v0vy//C8wHwYDVR0jBBgwFoAUl+Rp0MUEFMJvxwH3fpR3
// OQmN9qUwCgYIKoZIzj0EAwIDSAAwRQIhAM1HQpvkHKxLJByWaSYAPRZgh3Bis18W
// AViq7c/mtzEAAiBZO0lVe6Qo9iQPIBWZaVx/S/YSNO9uKNa/pvFu3V+nIg==
// -----END CERTIFICATE-----
// ---------------------------------------------------------------------------

const CD_SIGNING_KEY_005_KID: [u8; KEY_IDENTIFIER_LEN] = [
    0x63, 0x7F, 0x26, 0x34, 0xAD, 0x62, 0xEA, 0xFE, 0x6A, 0xF6, 0x62, 0xEF, 0xB9, 0x6F, 0x6F, 0xD2,
    0xFC, 0xBF, 0xFC, 0x2F,
];

const CD_SIGNING_KEY_005_PUBKEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0x43, 0x8a, 0x52, 0xc6, 0x62, 0xa2, 0xa6, 0xd7, 0x26, 0x47, 0xf9, 0x5e, 0xb7, 0x53, 0x13,
    0x6e, 0xe4, 0xae, 0x0f, 0xdb, 0x3a, 0xa9, 0xc1, 0x69, 0x31, 0x42, 0x6b, 0x3d, 0x08, 0x67, 0xf9,
    0x10, 0x3a, 0xe7, 0xd7, 0xa1, 0xb8, 0x87, 0xe9, 0xf8, 0x13, 0xa6, 0xf2, 0x6f, 0x76, 0xbb, 0xcd,
    0xa9, 0x35, 0x93, 0x78, 0x7c, 0x12, 0x77, 0x8c, 0xa8, 0xf2, 0x97, 0x5d, 0xc4, 0x5a, 0x20, 0x42,
    0xf9,
];

// ---------------------------------------------------------------------------
// Trust store: all 6 well-known keys
// ---------------------------------------------------------------------------

const WELL_KNOWN_CD_SIGNING_KEYS: [CdSigningKey; 6] = [
    CdSigningKey {
        kid: TEST_CD_KID,
        pubkey: TEST_CD_PUBKEY,
    },
    CdSigningKey {
        kid: CD_SIGNING_KEY_001_KID,
        pubkey: CD_SIGNING_KEY_001_PUBKEY,
    },
    CdSigningKey {
        kid: CD_SIGNING_KEY_002_KID,
        pubkey: CD_SIGNING_KEY_002_PUBKEY,
    },
    CdSigningKey {
        kid: CD_SIGNING_KEY_003_KID,
        pubkey: CD_SIGNING_KEY_003_PUBKEY,
    },
    CdSigningKey {
        kid: CD_SIGNING_KEY_004_KID,
        pubkey: CD_SIGNING_KEY_004_PUBKEY,
    },
    CdSigningKey {
        kid: CD_SIGNING_KEY_005_KID,
        pubkey: CD_SIGNING_KEY_005_PUBKEY,
    },
];

/// Look up a CD signing key by Subject Key Identifier.
///
/// Searches the 6 well-known CSA CD signing keys (1 test + 5 official).
/// Returns the P-256 uncompressed public key bytes if a matching KID is found.
pub fn lookup_cd_signing_key(kid: &[u8]) -> Option<&'static [u8; P256_PUBLIC_KEY_LEN]> {
    if kid.len() != KEY_IDENTIFIER_LEN {
        return None;
    }

    for key in &WELL_KNOWN_CD_SIGNING_KEYS {
        if key.kid == kid {
            return Some(&key.pubkey);
        }
    }

    None
}

/// Check if a Key ID corresponds to the test CD signing key.
///
/// The test key is self-signed and does not chain to the CSA root.
/// It should only be accepted for `CertificationType::DevelopmentAndTest`
/// (and optionally `Provisional`).
pub fn is_test_cd_key(kid: &[u8]) -> bool {
    kid.len() == KEY_IDENTIFIER_LEN && kid == TEST_CD_KID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_test_key() {
        let pubkey = lookup_cd_signing_key(&TEST_CD_KID);
        assert!(pubkey.is_some());
        // Verify it starts with 0x04 (uncompressed point prefix)
        assert_eq!(pubkey.unwrap()[0], 0x04);
    }

    #[test]
    fn test_lookup_official_keys() {
        // All 5 official keys should be found
        let kids = [
            &CD_SIGNING_KEY_001_KID,
            &CD_SIGNING_KEY_002_KID,
            &CD_SIGNING_KEY_003_KID,
            &CD_SIGNING_KEY_004_KID,
            &CD_SIGNING_KEY_005_KID,
        ];

        for kid in &kids {
            assert!(lookup_cd_signing_key(*kid).is_some());
        }
    }

    #[test]
    fn test_lookup_unknown_key() {
        let unknown_kid = [0xFFu8; KEY_IDENTIFIER_LEN];
        assert!(lookup_cd_signing_key(&unknown_kid).is_none());
    }

    #[test]
    fn test_lookup_wrong_length() {
        // Too short
        assert!(lookup_cd_signing_key(&[0x62, 0xfa]).is_none());
        // Too long
        assert!(lookup_cd_signing_key(&[0u8; 21]).is_none());
        // Empty
        assert!(lookup_cd_signing_key(&[]).is_none());
    }

    #[test]
    fn test_is_test_key() {
        assert!(is_test_cd_key(&TEST_CD_KID));
        assert!(!is_test_cd_key(&CD_SIGNING_KEY_001_KID));
        assert!(!is_test_cd_key(&[0u8; KEY_IDENTIFIER_LEN]));
        assert!(!is_test_cd_key(&[]));
    }
}
