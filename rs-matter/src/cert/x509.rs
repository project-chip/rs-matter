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

//! X.509 DER certificate parsing utilities for extracting Matter-specific data.

use crate::crypto::PKC_CANON_PUBLIC_KEY_LEN;
use crate::error::{Error, ErrorCode};

use der::asn1::{AnyRef, BitStringRef, GeneralizedTime, ObjectIdentifier, OctetStringRef, UtcTime};
use der::{Choice, Sequence, Tag};

pub mod cert;
pub mod csr;

/// OID 1.2.840.10045.4.3.2 — ECDSA with SHA256
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// OID 1.2.840.10045.2.1 — ecPublicKey (Elliptic Curve Public Key)
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// OID 1.2.840.10045.3.1.7 — prime256v1 (secp256r1 / P-256)
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// OID 2.5.29.14 — Subject Key Identifier
const OID_SUBJECT_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
/// OID 2.5.29.35 — Authority Key Identifier
const OID_AUTHORITY_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
/// OID 2.5.29.19 — Basic Constraints
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
/// OID 2.5.29.15 — Key Usage
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

/// Matter uses the P-256 uncompressed public key length
/// (0x04 || X || Y = 65 bytes)
const P256_PUBLIC_KEY_LEN: usize = PKC_CANON_PUBLIC_KEY_LEN;

/// AlgorithmIdentifier ::= SEQUENCE {
///   algorithm  OBJECT IDENTIFIER,
///   parameters ANY DEFINED BY algorithm OPTIONAL
/// }
///
/// https://www.rfc-editor.org/rfc/rfc5280#appendix-A.1
#[derive(Sequence)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<AnyRef<'a>>,
}

/// SubjectPublicKeyInfo ::= SEQUENCE {
///   algorithm        AlgorithmIdentifier,
///   subjectPublicKey BIT STRING
/// }
/// https://www.rfc-editor.org/rfc/rfc5280#appendix-A.1
struct SubjectPublicKeyInfo<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    subject_public_key: BitStringRef<'a>,
}

impl<'a> der::FixedTag for SubjectPublicKeyInfo<'a> {
    const TAG: Tag = Tag::Sequence;
}

/// AttributeTypeAndValue ::= SEQUENCE {
///   type   OBJECT IDENTIFIER,
///   value  ANY
/// }
///
/// https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4
#[derive(Sequence)]
struct AttributeTypeAndValue<'a> {
    oid: ObjectIdentifier,
    value: AnyRef<'a>,
}

/// BasicConstraints ::= SEQUENCE {
///   cA                 BOOLEAN DEFAULT FALSE,
///   pathLenConstraint  INTEGER (0..MAX) OPTIONAL
/// }
///
/// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9
#[derive(Sequence)]
struct BasicConstraints {
    #[asn1(default = "default_false")]
    ca: bool,
    path_len_constraint: Option<u8>,
}

fn default_false() -> bool {
    false
}

/// X.509 KeyUsage bit flags in DER BIT STRING format.
///
/// In X.509 DER encoding, bit 0 is the MSB (leftmost bit) in the bit string.
/// When represented as a u16, bit 0 corresponds to 0x8000.
///
/// KeyUsage ::= BIT STRING {
///   digitalSignature   (0),
///   nonRepudiation     (1),
///   keyEncipherment    (2),
///   dataEncipherment   (3),
///   keyAgreement       (4),
///   keyCertSign        (5),
///   cRLSign            (6),
///   encipherOnly       (7),
///   decipherOnly       (8)
/// }
/// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3
pub mod key_usage_der {
    pub const DIGITAL_SIGNATURE: u16 = 0x8000;
    pub const NON_REPUDIATION: u16 = 0x4000;
    pub const KEY_ENCIPHERMENT: u16 = 0x2000;
    pub const DATA_ENCIPHERMENT: u16 = 0x1000;
    pub const KEY_AGREEMENT: u16 = 0x0800;
    pub const KEY_CERT_SIGN: u16 = 0x0400;
    pub const CRL_SIGN: u16 = 0x0200;
    pub const ENCIPHER_ONLY: u16 = 0x0100;
    pub const DECIPHER_ONLY: u16 = 0x0080;
}

/// Matter TLV KeyUsage bit flags.
///
/// In Matter TLV encoding, the KeyUsage is stored as a plain u16 value
/// where bit 0 is the LSB (standard bit numbering).
///
/// Bit positions follow the same naming as X.509 but use standard u16 bit positions.
pub mod key_usage_tlv {
    pub const DIGITAL_SIGNATURE: u16 = 0x0001;
    pub const NON_REPUDIATION: u16 = 0x0002;
    pub const KEY_ENCIPHERMENT: u16 = 0x0004;
    pub const DATA_ENCIPHERMENT: u16 = 0x0008;
    pub const KEY_AGREEMENT: u16 = 0x0010;
    pub const KEY_CERT_SIGN: u16 = 0x0020;
    pub const CRL_SIGN: u16 = 0x0040;
    pub const ENCIPHER_ONLY: u16 = 0x0080;
    pub const DECIPHER_ONLY: u16 = 0x0100;
}

struct KeyUsage {
    bits: u16,
}

impl KeyUsage {
    fn digital_signature(&self) -> bool {
        self.bits & key_usage_der::DIGITAL_SIGNATURE != 0
    }

    fn key_cert_sign(&self) -> bool {
        self.bits & key_usage_der::KEY_CERT_SIGN != 0
    }

    fn crl_sign(&self) -> bool {
        self.bits & key_usage_der::CRL_SIGN != 0
    }

    /// Check that only the specified bits are set (exact match)
    fn has_only_bits(&self, mask: u16) -> bool {
        self.bits == mask
    }
}

impl<'a> From<BitStringRef<'a>> for KeyUsage {
    fn from(bs: BitStringRef<'a>) -> Self {
        let bytes = bs.raw_bytes();
        let unused = bs.unused_bits();

        // Reject malformed bitstrings longer than 2 bytes since KeyUsage has a 9 bit max
        if bytes.len() > 2 {
            // Return empty KeyUsage for invalid input
            return Self { bits: 0 };
        }

        // Load bytes big-endian
        let mut buf = [0u8; 2];
        let len = bytes.len();
        buf[..len].copy_from_slice(&bytes[..len]);

        let mut bits = u16::from_be_bytes(buf);

        // Mask off unused padding bits in the last byte
        if unused > 0 && len > 0 {
            // For len=1: unused bits are in byte[0] (upper 8 bits of u16)
            // For len=2: unused bits are in byte[1] (lower 8 bits of u16)
            let shift = if len == 1 { 8 } else { 0 };
            let mask = !((1u16 << unused) - 1) << shift;
            bits &= mask;
        }

        Self { bits }
    }
}

/// AuthorityKeyIdentifier ::= SEQUENCE {
///   keyIdentifier             [0] KeyIdentifier OPTIONAL,
///   authorityCertIssuer       [1] GeneralNames OPTIONAL,
///   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
/// }
///
/// KeyIdentifier ::= OCTET STRING
///
/// We only need the keyIdentifier field. The `[0]` is IMPLICIT.
#[derive(Sequence)]
struct AuthorityKeyIdentifier<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    key_identifier: OctetStringRef<'a>,
}

/// Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
#[derive(Choice)]
enum Time {
    #[asn1(type = "UTCTime")]
    Utc(UtcTime),
    #[asn1(type = "GeneralizedTime")]
    General(GeneralizedTime),
}

/// Validity ::= SEQUENCE {
///   notBefore Time,
///   notAfter  Time
/// }
#[derive(Sequence)]
struct Validity {
    not_before: Time,
    not_after: Time,
}

/// Parse a hex character (0-9, A-F, a-f) into its numeric value.
fn hex_digit(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(ErrorCode::InvalidData.into()),
    }
}

/// Parse a hex string into a u16.
///
/// Used for Vendor ID and Product ID which are stored as UTF8String
/// hex values in the Subject DN.
fn parse_hex_u16(s: &[u8]) -> Result<u16, Error> {
    if s.len() != 4 {
        return Err(ErrorCode::InvalidData.into());
    }

    let mut val: u16 = 0;
    // build hex number
    for &b in s {
        val = val << 4 | hex_digit(b)? as u16;
    }
    Ok(val)
}

/// Convert a `Time` value (UTCTime or GeneralizedTime) to Unix epoch seconds (u64).
///
/// For GeneralizedTime with year 9999 (DateTime::INFINITY), returns `u64::MAX`
/// to indicate no expiry.
fn time_to_unix_secs(time: &Time) -> Result<u64, Error> {
    let dt = match time {
        Time::Utc(utc) => utc.to_date_time(),
        Time::General(gt) => gt.to_date_time(),
    };

    // Check for the "no expiry" sentinel: 9999-12-31T23:59:59Z
    if dt == der::DateTime::INFINITY {
        return Ok(u64::MAX);
    }

    Ok(dt.unix_duration().as_secs())
}
