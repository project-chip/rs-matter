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

//! X.509 DER certificate parsing utilities for extracting Matter-specific data in
//! DAC, PAI, and PAA certificates.
//!
//! This module parses DER-encoded X.509 certificates with Matter specific constraints
//! as defined in the Matter specification 6.2.2.3.
//!
//! It extracts fields needed for Matter device attestation verification: Subject Key
//! Identifier (SKID), Authority Key Identifier (AKID), public key, Matter Vendor ID,
//! Matter Product ID, and validity periods.

use crate::error::{Error, ErrorCode};

use der::asn1::{
    AnyRef, BitStringRef, GeneralizedTime, ObjectIdentifier, OctetStringRef, UintRef, UtcTime,
};
use der::{
    Choice, Decode, DecodeValue, EncodeValue, FixedTag, Header, Reader, Sequence, SliceReader, Tag,
};

/// Type alias for DAC (Device Attestation Certificate)
pub type DacCert<'a> = X509Cert<'a, DacExtensions<'a>>;

/// Type alias for PAI (Product Attestation Intermediate) Certificate
pub type PaiCert<'a> = X509Cert<'a, PaiExtensions<'a>>;

/// Type alias for PAA (Product Attestation Authority) Certificate
pub type PaaCert<'a> = X509Cert<'a, PaaExtensions<'a>>;

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

/// OID 1.3.6.1.4.1.37244.2.1 — Matter Vendor ID
const OID_MATTER_VENDOR_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.2.1");
/// OID 1.3.6.1.4.1.37244.2.2 — Matter Product ID
const OID_MATTER_PRODUCT_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.2.2");

/// Matter uses the P-256 uncompressed public key length
/// (0x04 || X || Y = 65 bytes)
const P256_PUBLIC_KEY_LEN: usize = 65;

/// AlgorithmIdentifier ::= SEQUENCE {
///   algorithm  OBJECT IDENTIFIER,
///   parameters ANY DEFINED BY algorithm OPTIONAL
/// }
///
/// https://www.rfc-editor.org/rfc/rfc5280#appendix-A.1
#[derive(Sequence)]
struct AlgorithmIdentifier<'a> {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<AnyRef<'a>>,
}

/// SubjectPublicKeyInfo ::= SEQUENCE {
///   algorithm        AlgorithmIdentifier,
///   subjectPublicKey BIT STRING
/// }
/// https://www.rfc-editor.org/rfc/rfc5280#appendix-A.1
#[derive(Sequence)]
struct SubjectPublicKeyInfo<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    subject_public_key: BitStringRef<'a>,
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
///   cA                 BOOLEAN DEFAULT TRUE,
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
struct KeyUsage {
    bits: u16,
}

#[allow(unused)]
impl KeyUsage {
    // Bit positions
    const DIGITAL_SIGNATURE: u16 = 0x8000;
    const NON_REPUDIATION: u16 = 0x4000;
    const KEY_ENCIPHERMENT: u16 = 0x2000;
    const DATA_ENCIPHERMENT: u16 = 0x1000;
    const KEY_AGREEMENT: u16 = 0x0800;
    const KEY_CERT_SIGN: u16 = 0x0400;
    const CRL_SIGN: u16 = 0x0200;
    const ENCIPHER_ONLY: u16 = 0x0100;
    const DECIPHER_ONLY: u16 = 0x0080;

    fn digital_signature(&self) -> bool {
        self.bits & Self::DIGITAL_SIGNATURE != 0
    }

    fn key_cert_sign(&self) -> bool {
        self.bits & Self::KEY_CERT_SIGN != 0
    }

    fn crl_sign(&self) -> bool {
        self.bits & Self::CRL_SIGN != 0
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

        // Load up to 2 bytes in (big-endian)
        let mut buf = [0u8; 2];
        let len = bytes.len().min(2);
        buf[..len].copy_from_slice(&bytes[..len]);

        let mut bits = u16::from_be_bytes(buf);

        // Mask off unused padding bits
        if unused > 0 {
            let mask = !((1u16 << unused) - 1);
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

/// A parsed extension with its critical flag and typed value.
struct ParsedExtension<T> {
    critical: bool,
    value: T,
}

/// Helper structure to hold parsed extension fields during decoding
struct ParsedExtensionFields<'a> {
    basic_constraints: Option<ParsedExtension<BasicConstraints>>,
    key_usage: Option<ParsedExtension<KeyUsage>>,
    subject_key_id: Option<ParsedExtension<OctetStringRef<'a>>>,
    authority_key_id: Option<ParsedExtension<AuthorityKeyIdentifier<'a>>>,
}

impl<'a> ParsedExtensionFields<'a> {
    /// Parse X.509 extensions from a reader
    fn parse<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let mut basic_constraints: Option<ParsedExtension<BasicConstraints>> = None;
        let mut key_usage: Option<ParsedExtension<KeyUsage>> = None;
        let mut subject_key_id: Option<ParsedExtension<OctetStringRef<'a>>> = None;
        let mut authority_key_id: Option<ParsedExtension<AuthorityKeyIdentifier<'a>>> = None;

        // Iterate through SEQUENCE OF Extension
        while !reader.is_finished() {
            // Each Extension is a SEQUENCE, so we decode it to get its contents
            let ext_any = AnyRef::decode(reader)?;
            let mut ext_reader = SliceReader::new(ext_any.value())?;

            // extnID OBJECT IDENTIFIER
            let extn_id = ObjectIdentifier::decode(&mut ext_reader)?;

            // critical BOOLEAN DEFAULT FALSE
            let critical = if !ext_reader.is_finished() && ext_reader.peek_tag()? == Tag::Boolean {
                bool::decode(&mut ext_reader)?
            } else {
                false
            };

            // extnValue OCTET STRING
            let extn_value = OctetStringRef::decode(&mut ext_reader)?;
            let value_bytes = extn_value.as_bytes();

            if extn_id == OID_BASIC_CONSTRAINTS {
                let bc = BasicConstraints::from_der(value_bytes)?;
                basic_constraints = Some(ParsedExtension {
                    critical,
                    value: bc,
                });
            } else if extn_id == OID_KEY_USAGE {
                let bs = BitStringRef::from_der(value_bytes)?;
                key_usage = Some(ParsedExtension {
                    critical,
                    value: bs.into(),
                });
            } else if extn_id == OID_SUBJECT_KEY_ID {
                let skid = OctetStringRef::from_der(value_bytes)?;
                subject_key_id = Some(ParsedExtension {
                    critical,
                    value: skid,
                });
            } else if extn_id == OID_AUTHORITY_KEY_ID {
                let akid = AuthorityKeyIdentifier::from_der(value_bytes)?;
                authority_key_id = Some(ParsedExtension {
                    critical,
                    value: akid,
                });
            }
            // Ignore other optional extensions
        }

        Ok(Self {
            basic_constraints,
            key_usage,
            subject_key_id,
            authority_key_id,
        })
    }
}

/// Trait for certificate extension types (DAC, PAI, PAA).
///
/// Each certificate type has different extension requirements (Matter Spec 6.2).
/// Implementations must:
/// - Parse extensions from DER-encoded data
/// - Validate requirements during parsing (fail if invalid)
/// - Provide access to Subject Key Identifier and Authority Key Identifier
pub trait CertExtensions<'a>: DecodeValue<'a> + der::FixedTag + der::EncodeValue {
    /// Get subject key identifier if present for this certificate type
    fn subject_key_id(&self) -> Option<&'a [u8]>;

    /// Get authority key identifier if present for this certificate type
    /// Note: PAA certificates do not have AKID (self-signed)
    fn authority_key_id(&self) -> Option<&'a [u8]>;
}

/// DAC (Device Attestation Certificate) Extensions
///
/// A DAC SHALL have (Matter Spec 6.2.2.3):
/// - Basic Constraints: critical=TRUE, cA=FALSE
/// - Key Usage: critical=TRUE, only digitalSignature bit set
/// - Authority Key Identifier: present
/// - Subject Key Identifier: present
#[allow(unused)]
pub struct DacExtensions<'a> {
    basic_constraints: ParsedExtension<BasicConstraints>,
    key_usage: ParsedExtension<KeyUsage>,
    subject_key_id: ParsedExtension<OctetStringRef<'a>>,
    authority_key_id: ParsedExtension<AuthorityKeyIdentifier<'a>>,
}

// DAC Extensions parsing with validation
impl<'a> DecodeValue<'a> for DacExtensions<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            // Parse all extension fields
            let fields = ParsedExtensionFields::parse(reader)?;

            // Validate DAC requirements: all fields must be present
            let basic_constraints = fields
                .basic_constraints
                .ok_or(der::Error::from(der::ErrorKind::Failed))?;
            let key_usage = fields
                .key_usage
                .ok_or(der::Error::from(der::ErrorKind::Failed))?;
            let subject_key_id = fields
                .subject_key_id
                .ok_or(der::Error::from(der::ErrorKind::Failed))?;
            let authority_key_id = fields
                .authority_key_id
                .ok_or(der::Error::from(der::ErrorKind::Failed))?;

            // Basic Constraints: SHALL be critical and cA SHALL be FALSE
            if !basic_constraints.critical {
                return Err(der::ErrorKind::Failed.into());
            }
            if basic_constraints.value.ca {
                return Err(der::ErrorKind::Failed.into());
            }

            // Key Usage: SHALL be critical, SHALL only have digitalSignature bit set
            if !key_usage.critical {
                return Err(der::ErrorKind::Failed.into());
            }
            if !key_usage.value.digital_signature() {
                return Err(der::ErrorKind::Failed.into());
            }
            // Only digitalSignature bit should be set (no other bits)
            if !key_usage.value.has_only_bits(KeyUsage::DIGITAL_SIGNATURE) {
                return Err(der::ErrorKind::Failed.into());
            }

            Ok(Self {
                basic_constraints,
                key_usage,
                subject_key_id,
                authority_key_id,
            })
        })
    }
}

impl<'a> der::FixedTag for DacExtensions<'a> {
    const TAG: Tag = Tag::Sequence;
}

// Dummy EncodeValue implementation
// Required by der verision 0.7 for use with #[derive(Sequence)] on structs that contain Extensions.
// TODO Remove when upgrading to der 0.8+ which separates Encode/Decode traits.
impl<'a> der::EncodeValue for DacExtensions<'a> {
    fn value_len(&self) -> der::Result<der::Length> {
        // This should never be called since we only parse certificates, never create them
        unimplemented!("DacExtensions encoding is not supported")
    }

    fn encode_value(&self, _writer: &mut impl der::Writer) -> der::Result<()> {
        // This should never be called since we only parse certificates, never create them
        unimplemented!("DacExtensions encoding is not supported")
    }
}

impl<'a> CertExtensions<'a> for DacExtensions<'a> {
    fn subject_key_id(&self) -> Option<&'a [u8]> {
        Some(self.subject_key_id.value.as_bytes())
    }

    fn authority_key_id(&self) -> Option<&'a [u8]> {
        Some(self.authority_key_id.value.key_identifier.as_bytes())
    }
}

/// PAI (Product Attestation Intermediate) Certificate Extensions
///
/// A PAI SHALL have (Matter Spec 6.2.2.4):
/// - Basic Constraints: critical=TRUE, cA=TRUE, pathLen=0
/// - Key Usage: critical=TRUE, keyCertSign and cRLSign bits set, digitalSignature MAY be set
/// - Authority Key Identifier: present
/// - Subject Key Identifier: present
#[allow(unused)]
pub struct PaiExtensions<'a> {
    basic_constraints: ParsedExtension<BasicConstraints>,
    key_usage: ParsedExtension<KeyUsage>,
    subject_key_id: ParsedExtension<OctetStringRef<'a>>,
    authority_key_id: ParsedExtension<AuthorityKeyIdentifier<'a>>,
}

// PAI Extensions parsing with validation
impl<'a> DecodeValue<'a> for PaiExtensions<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            // Parse all extension fields
            let fields = ParsedExtensionFields::parse(reader)?;

            // Validate PAI requirements: all fields must be present
            let basic_constraints = fields
                .basic_constraints
                .ok_or(der::Error::from(der::ErrorKind::Failed))?;
            let key_usage = fields
                .key_usage
                .ok_or(der::Error::from(der::ErrorKind::Failed))?;
            let subject_key_id = fields
                .subject_key_id
                .ok_or(der::Error::from(der::ErrorKind::Failed))?;
            let authority_key_id = fields
                .authority_key_id
                .ok_or(der::Error::from(der::ErrorKind::Failed))?;

            // Basic Constraints: SHALL be critical, cA SHALL be TRUE, pathLen SHALL be 0
            if !basic_constraints.critical {
                return Err(der::ErrorKind::Failed.into());
            }
            if !basic_constraints.value.ca {
                return Err(der::ErrorKind::Failed.into());
            }
            // pathLen must be present and equal to 0
            if basic_constraints.value.path_len_constraint != Some(0) {
                return Err(der::ErrorKind::Failed.into());
            }

            // Key Usage: SHALL be critical
            if !key_usage.critical {
                return Err(der::ErrorKind::Failed.into());
            }
            // Both keyCertSign and cRLSign SHALL be set
            if !key_usage.value.key_cert_sign() || !key_usage.value.crl_sign() {
                return Err(der::ErrorKind::Failed.into());
            }
            // digitalSignature MAY be set, but no other bits should be set
            let allowed_bits =
                KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN | KeyUsage::DIGITAL_SIGNATURE;
            if (key_usage.value.bits & !allowed_bits) != 0 {
                return Err(der::ErrorKind::Failed.into());
            }

            Ok(Self {
                basic_constraints,
                key_usage,
                subject_key_id,
                authority_key_id,
            })
        })
    }
}

impl<'a> der::FixedTag for PaiExtensions<'a> {
    const TAG: Tag = Tag::Sequence;
}

// TODO Remove when upgrading to der 0.8+ which separates Encode/Decode traits.
impl<'a> der::EncodeValue for PaiExtensions<'a> {
    fn value_len(&self) -> der::Result<der::Length> {
        unimplemented!("PaiExtensions encoding is not supported")
    }

    fn encode_value(&self, _writer: &mut impl der::Writer) -> der::Result<()> {
        unimplemented!("PaiExtensions encoding is not supported")
    }
}

impl<'a> CertExtensions<'a> for PaiExtensions<'a> {
    fn subject_key_id(&self) -> Option<&'a [u8]> {
        Some(self.subject_key_id.value.as_bytes())
    }

    fn authority_key_id(&self) -> Option<&'a [u8]> {
        Some(self.authority_key_id.value.key_identifier.as_bytes())
    }
}

/// PAA (Product Attestation Authority) Certificate Extensions
///
/// A PAA SHALL have (Matter Spec 6.2.2.4):
/// - Basic Constraints: critical=TRUE, cA=TRUE, pathLen MAY be present and if so must be 1
/// - Key Usage: critical=TRUE, keyCertSign and cRLSign bits set, digitalSignature MAY be set
/// - Subject Key Identifier: present
/// - Authority Key Identifier: NOT required (self-signed), but may be present
#[allow(unused)]
pub struct PaaExtensions<'a> {
    basic_constraints: ParsedExtension<BasicConstraints>,
    key_usage: ParsedExtension<KeyUsage>,
    subject_key_id: ParsedExtension<OctetStringRef<'a>>,
    authority_key_id: Option<ParsedExtension<AuthorityKeyIdentifier<'a>>>,
}

// PAA Extensions parsing with validation
impl<'a> DecodeValue<'a> for PaaExtensions<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            // Parse all extension fields
            let fields = ParsedExtensionFields::parse(reader)?;

            // Validate PAA requirements
            let basic_constraints = fields
                .basic_constraints
                .ok_or(der::Error::from(der::ErrorKind::Failed))?;
            let key_usage = fields
                .key_usage
                .ok_or(der::Error::from(der::ErrorKind::Failed))?;
            let subject_key_id = fields
                .subject_key_id
                .ok_or(der::Error::from(der::ErrorKind::Failed))?;

            // AKID is optional for PAA
            let authority_key_id = fields.authority_key_id;

            // Basic Constraints: SHALL be critical, cA SHALL be TRUE
            if !basic_constraints.critical || !basic_constraints.value.ca {
                return Err(der::ErrorKind::Failed.into());
            }

            // pathLen MAY be present, and if present it SHALL be 1
            if let Some(path_len) = basic_constraints.value.path_len_constraint {
                if path_len != 1 {
                    return Err(der::ErrorKind::Failed.into());
                }
            }

            // Key Usage: SHALL be critical
            if !key_usage.critical {
                return Err(der::ErrorKind::Failed.into());
            }
            // Both keyCertSign and cRLSign SHALL be set
            if !key_usage.value.key_cert_sign() || !key_usage.value.crl_sign() {
                return Err(der::ErrorKind::Failed.into());
            }
            // digitalSignature MAY be set, but no other bits should be set
            let allowed_bits =
                KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN | KeyUsage::DIGITAL_SIGNATURE;
            if (key_usage.value.bits & !allowed_bits) != 0 {
                return Err(der::ErrorKind::Failed.into());
            }

            Ok(Self {
                basic_constraints,
                key_usage,
                subject_key_id,
                authority_key_id,
            })
        })
    }
}

impl<'a> FixedTag for PaaExtensions<'a> {
    const TAG: Tag = Tag::Sequence;
}

// TODO Remove when upgrading to der 0.8+ which separates Encode/Decode traits.
impl<'a> EncodeValue for PaaExtensions<'a> {
    fn value_len(&self) -> der::Result<der::Length> {
        unimplemented!("PaaExtensions encoding is not supported")
    }

    fn encode_value(&self, _writer: &mut impl der::Writer) -> der::Result<()> {
        unimplemented!("PaaExtensions encoding is not supported")
    }
}

impl<'a> CertExtensions<'a> for PaaExtensions<'a> {
    fn subject_key_id(&self) -> Option<&'a [u8]> {
        Some(self.subject_key_id.value.as_bytes())
    }

    fn authority_key_id(&self) -> Option<&'a [u8]> {
        // PAA certificates do not require AKID, but may have it
        self.authority_key_id
            .as_ref()
            .map(|ext| ext.value.key_identifier.as_bytes())
    }
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

/// TBSCertificate (To Be Signed Certificate)
///
/// Generic over extension type E to support DAC, PAI, and PAA certificates.
///
/// TBSCertificate ::= SEQUENCE {
///   version [0] EXPLICIT INTEGER DEFAULT v1,
///   serialNumber INTEGER,
///   signature AlgorithmIdentifier,
///   issuer Name,
///   validity Validity,
///   subject Name,
///   subjectPublicKeyInfo SubjectPublicKeyInfo,
///   extensions [3] EXPLICIT Extensions
/// }
#[derive(Sequence)]
struct TbsCertificate<'a, E: CertExtensions<'a>> {
    /// Version number (0=v1, 1=v2, 2=v3).
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    version: UintRef<'a>,
    /// Raw bytes of the serial number INTEGER value.
    serial_number: AnyRef<'a>,
    /// Signature algorithm.
    signature: AlgorithmIdentifier<'a>,
    /// Issuer RDNSequence (kept as raw AnyRef for walking).
    issuer: AnyRef<'a>,
    /// Validity period.
    validity: Validity,
    /// Subject RDNSequence (kept as raw AnyRef for walking).
    subject: AnyRef<'a>,
    /// Subject public key info.
    subject_public_key_info: SubjectPublicKeyInfo<'a>,
    /// Extensions field. Always present for Matter certificates (context tag [3]).
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT")]
    extensions: E,
}

/// Top-level Certificate structure.
///
/// Generic over extension type E to support DAC, PAI, and PAA certificates.
///
/// Certificate ::= SEQUENCE {
///   tbsCertificate     TBSCertificate,
///   signatureAlgorithm AlgorithmIdentifier,
///   signatureValue     BIT STRING
/// }
#[allow(unused)]
struct Certificate<'a, E: CertExtensions<'a>> {
    tbs_certificate: TbsCertificate<'a, E>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature_value: BitStringRef<'a>,
}

impl<'a, E: CertExtensions<'a>> DecodeValue<'a> for Certificate<'a, E> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            let tbs_certificate = TbsCertificate::decode(reader)?;

            // Validate that version is 2 (v3 certificate)
            let version_value = tbs_certificate.version.as_bytes();
            if version_value.len() != 1 || version_value[0] != 2 {
                return Err(der::ErrorKind::Failed.into());
            }

            // Validate that signature algorithm in TBS is ECDSA with SHA256
            if tbs_certificate.signature.algorithm != OID_ECDSA_WITH_SHA256 {
                return Err(der::ErrorKind::Failed.into());
            }

            // Validate that subjectPublicKeyInfo algorithm is ecPublicKey with prime256v1 curve
            let spki_algo = &tbs_certificate.subject_public_key_info.algorithm;
            if spki_algo.algorithm != OID_EC_PUBLIC_KEY {
                return Err(der::ErrorKind::Failed.into());
            }

            // The parameters field must contain the named curve OID for prime256v1
            // ECParameters ::= CHOICE { namedCurve OBJECT IDENTIFIER, ... }
            // For Matter certs, only namedCurve is used, so we decode directly as an OID
            // https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1
            let params = spki_algo.parameters.ok_or(der::ErrorKind::Failed)?;
            let curve_oid: ObjectIdentifier =
                params.try_into().map_err(|_| der::ErrorKind::Failed)?;

            if curve_oid != OID_PRIME256V1 {
                return Err(der::ErrorKind::Failed.into());
            }

            let signature_algorithm = AlgorithmIdentifier::decode(reader)?;
            let signature_value = BitStringRef::decode(reader)?;
            Ok(Self {
                tbs_certificate,
                signature_algorithm,
                signature_value,
            })
        })
    }
}

impl<'a, E: CertExtensions<'a>> der::FixedTag for Certificate<'a, E> {
    const TAG: Tag = Tag::Sequence;
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

/// A parsed DER-encoded X.509 certificate.
///
/// Generic over extension type E to support DAC, PAI, and PAA certificates.
/// Use the type aliases `DacCert`, `PaiCert`, and `PaaCert` for convenience.
///
/// Validates the incoming bytes are correctly DER-encoded x509 certificates
/// with the appropriate extensions for the certificate type.
///
/// # Example
///
/// ```ignore
/// let cert = DacCert::new(der_bytes)?;
/// let skid = cert.subject_key_id()?;
/// let pubkey = cert.public_key()?;
/// let vid = cert.vendor_id()?;
/// ```
pub struct X509Cert<'a, E: CertExtensions<'a>> {
    cert: Certificate<'a, E>,
}

impl<'a, E: CertExtensions<'a>> X509Cert<'a, E> {
    /// Create a new `X509Cert` from DER-encoded certificate bytes.
    ///
    /// Validates that the certificate parses correctly and has the required
    /// extensions for the certificate type E.
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        let cert = Certificate::from_der(data).map_err(|_| Error::from(ErrorCode::InvalidData))?;

        Ok(Self { cert })
    }

    /// Extract the Subject Key Identifier extension value.
    ///
    /// The extnValue of the SubjectKeyIdentifier extension is an
    /// OCTET STRING containing the 20-byte key identifier.
    pub fn subject_key_id(&self) -> Result<&'a [u8], Error> {
        self.cert
            .tbs_certificate
            .extensions
            .subject_key_id()
            .ok_or(Error::from(ErrorCode::NotFound))
    }

    /// Extract the Authority Key Identifier extension value.
    ///
    /// The extnValue contains a SEQUENCE with a context-specific `[0]`
    /// field holding the 20-byte key identifier.
    ///
    /// Note: This will return NotFound for PAA certificates (which are self-signed
    /// and do not have an Authority Key Identifier).
    pub fn authority_key_id(&self) -> Result<&'a [u8], Error> {
        self.cert
            .tbs_certificate
            .extensions
            .authority_key_id()
            .ok_or(Error::from(ErrorCode::NotFound))
    }

    /// Extract the subject public key bytes.
    ///
    /// Returns the raw bytes of the BIT STRING value from SubjectPublicKeyInfo,
    /// excluding the unused-bits prefix byte. For P-256 this is the 65-byte
    /// uncompressed point (0x04 || X || Y).
    pub fn public_key(&self) -> Result<&'a [u8], Error> {
        let spli_bytes = &self
            .cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();

        if spli_bytes.len() != P256_PUBLIC_KEY_LEN {
            return Err(ErrorCode::InvalidData.into());
        }

        Ok(spli_bytes)
    }

    /// Extract the Matter Vendor ID from the Subject DN.
    ///
    /// Searches for OID 1.3.6.1.4.1.37244.2.1 in the Subject distinguished
    /// name. The value is a UTF8String containing the hex representation
    /// (e.g., "FFF1"), which is parsed to a `u16`.
    ///
    /// Returns `ErrorCode::NotFound` if not present in the Subject DN.
    pub fn vendor_id(&self) -> Result<u16, Error> {
        let attr = Self::find_rdn_attr(
            self.cert.tbs_certificate.subject.value(),
            &OID_MATTER_VENDOR_ID,
        )?
        .ok_or(Error::from(ErrorCode::NotFound))?;

        parse_hex_u16(attr)
    }

    /// Extract the Matter Product ID from the Subject DN.
    ///
    /// Searches for OID 1.3.6.1.4.1.37244.2.2 in the Subject distinguished
    /// name. The value is a UTF8String containing the hex representation
    /// (e.g., "8000"), which is parsed to a `u16`.
    ///
    /// Returns `ErrorCode::NotFound` if not present in the Subject DN.
    pub fn product_id(&self) -> Result<u16, Error> {
        let attr = Self::find_rdn_attr(
            self.cert.tbs_certificate.subject.value(),
            &OID_MATTER_PRODUCT_ID,
        )?
        .ok_or(Error::from(ErrorCode::NotFound))?;

        parse_hex_u16(attr)
    }

    fn find_rdn_attr(
        rdn_bytes: &'a [u8],
        target_oid: &ObjectIdentifier,
    ) -> Result<Option<&'a [u8]>, Error> {
        // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
        // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        let mut outer =
            SliceReader::new(rdn_bytes).map_err(|_| Error::from(ErrorCode::InvalidData))?;

        while !outer.is_finished() {
            // Each RDN is a SET
            let rdn_set =
                AnyRef::decode(&mut outer).map_err(|_| Error::from(ErrorCode::InvalidData))?;
            let mut set_reader = SliceReader::new(rdn_set.value())
                .map_err(|_| Error::from(ErrorCode::InvalidData))?;

            while !set_reader.is_finished() {
                let atv = AttributeTypeAndValue::decode(&mut set_reader)
                    .map_err(|_| Error::from(ErrorCode::InvalidData))?;

                if atv.oid == *target_oid {
                    return Ok(Some(atv.value.value()));
                }
            }
        }

        Ok(None)
    }

    /// Extract the NotBefore time as Unix epoch seconds.
    ///
    /// Parses UTCTime ("YYMMDDHHMMSSZ") or GeneralizedTime ("YYYYMMDDHHMMSSZ")
    /// from the validity field of the tbsCertificate.
    pub fn not_before_unix(&self) -> Result<u64, Error> {
        time_to_unix_secs(&self.cert.tbs_certificate.validity.not_before)
    }

    /// Extract the NotAfter time as Unix epoch seconds.
    ///
    /// Parses UTCTime or GeneralizedTime. For GeneralizedTime
    /// "99991231235959Z", returns `u64::MAX` to indicate no expiry.
    pub fn not_after_unix(&self) -> Result<u64, Error> {
        time_to_unix_secs(&self.cert.tbs_certificate.validity.not_after)
    }

    /// Check if the certificate is valid at the given Unix epoch time (seconds).
    ///
    /// Returns `true` if `not_before <= now_unix_secs <= not_after`.
    /// A `not_after` of `u64::MAX` (from "99991231235959Z") is always
    /// considered valid (no expiry).
    pub fn is_valid_at(&self, now_unix_secs: u64) -> Result<bool, Error> {
        let not_before = self.not_before_unix()?;
        let not_after = self.not_after_unix()?;

        Ok(now_unix_secs >= not_before && now_unix_secs <= not_after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Matter Development PAA certificate (self-signed, no VID/PID)
    // From connectedhomeip/credentials/development/attestation/Chip-Development-PAA-Cert.der
    const PAA_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0xa0, 0x30, 0x82, 0x01, 0x46, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08,
        0x57, 0xd3, 0xa2, 0xd0, 0x1e, 0x31, 0x81, 0x90, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x21, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x16, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x44, 0x65, 0x76, 0x65, 0x6c,
        0x6f, 0x70, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x50, 0x41, 0x41, 0x30, 0x20, 0x17, 0x0d, 0x32,
        0x31, 0x30, 0x36, 0x32, 0x38, 0x31, 0x34, 0x32, 0x33, 0x34, 0x33, 0x5a, 0x18, 0x0f, 0x39,
        0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30,
        0x21, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16, 0x4d, 0x61, 0x74,
        0x74, 0x65, 0x72, 0x20, 0x44, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x6d, 0x65, 0x6e, 0x74,
        0x20, 0x50, 0x41, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        0x04, 0x1b, 0x0f, 0x25, 0x94, 0x2e, 0x3d, 0x92, 0xab, 0xd6, 0x70, 0x4c, 0x1a, 0x27, 0x81,
        0xa0, 0x38, 0xec, 0x53, 0x21, 0x2c, 0x4d, 0xab, 0x58, 0xb0, 0xbe, 0x3c, 0x40, 0xbd, 0xfb,
        0x49, 0x23, 0x23, 0x42, 0x1c, 0x79, 0xdc, 0xc7, 0xad, 0x70, 0x18, 0x10, 0x07, 0x12, 0x0d,
        0xc8, 0x6f, 0x0a, 0x89, 0x25, 0x3d, 0x89, 0x93, 0xeb, 0x37, 0xab, 0x65, 0x2e, 0xf8, 0xdb,
        0x13, 0x75, 0xe5, 0xb1, 0x45, 0xa3, 0x66, 0x30, 0x64, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d,
        0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01, 0x30,
        0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06,
        0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xfa, 0x92, 0xcf, 0x09,
        0x5e, 0xfa, 0x42, 0xe1, 0x14, 0x30, 0x65, 0x16, 0x32, 0xfe, 0xfe, 0x1b, 0x2c, 0x77, 0xa7,
        0xc8, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xfa,
        0x92, 0xcf, 0x09, 0x5e, 0xfa, 0x42, 0xe1, 0x14, 0x30, 0x65, 0x16, 0x32, 0xfe, 0xfe, 0x1b,
        0x2c, 0x77, 0xa7, 0xc8, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
        0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x50, 0xa7, 0x90, 0x33, 0x64, 0xb6, 0x53,
        0xff, 0x0e, 0xa4, 0x63, 0xdc, 0x68, 0x4a, 0x86, 0xdd, 0x25, 0xc7, 0x31, 0xa3, 0x9e, 0xfe,
        0xb3, 0xc2, 0x0c, 0xd2, 0xde, 0xd1, 0xb6, 0x60, 0x7e, 0x2f, 0x02, 0x21, 0x00, 0xaf, 0xd4,
        0xed, 0x4b, 0x6a, 0x99, 0xe5, 0xf8, 0xc5, 0x52, 0x1d, 0x70, 0x1e, 0xbc, 0xf9, 0xfd, 0x53,
        0xb9, 0x39, 0x4f, 0xd8, 0x0f, 0xc5, 0x99, 0x92, 0xff, 0x3e, 0x5b, 0xbb, 0xb6, 0x0a, 0x35,
    ];

    // Matter Development PAI certificate (VID=FFF1, no PID)
    // From connectedhomeip/credentials/development/attestation/Matter-Development-PAI-FFF1-noPID-Cert.der
    const PAI_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0xcb, 0x30, 0x82, 0x01, 0x71, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08,
        0x56, 0xad, 0x82, 0x22, 0xad, 0x94, 0x5b, 0x64, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x30, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x0f, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20,
        0x50, 0x41, 0x41, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
        0xa2, 0x7c, 0x02, 0x01, 0x0c, 0x04, 0x46, 0x46, 0x46, 0x31, 0x30, 0x20, 0x17, 0x0d, 0x32,
        0x32, 0x30, 0x32, 0x30, 0x35, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x39,
        0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30,
        0x3d, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1c, 0x4d, 0x61, 0x74,
        0x74, 0x65, 0x72, 0x20, 0x44, 0x65, 0x76, 0x20, 0x50, 0x41, 0x49, 0x20, 0x30, 0x78, 0x46,
        0x46, 0x46, 0x31, 0x20, 0x6e, 0x6f, 0x20, 0x50, 0x49, 0x44, 0x31, 0x14, 0x30, 0x12, 0x06,
        0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02, 0x01, 0x0c, 0x04, 0x46, 0x46,
        0x46, 0x31, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x41,
        0x9a, 0x93, 0x15, 0xc2, 0x17, 0x3e, 0x0c, 0x8c, 0x87, 0x6d, 0x03, 0xcc, 0xfc, 0x94, 0x48,
        0x52, 0x64, 0x7f, 0x7f, 0xec, 0x5e, 0x50, 0x82, 0xf4, 0x05, 0x99, 0x28, 0xec, 0xa8, 0x94,
        0xc5, 0x94, 0x15, 0x13, 0x09, 0xac, 0x63, 0x1e, 0x4c, 0xb0, 0x33, 0x92, 0xaf, 0x68, 0x4b,
        0x0b, 0xaf, 0xb7, 0xe6, 0x5b, 0x3b, 0x81, 0x62, 0xc2, 0xf5, 0x2b, 0xf9, 0x31, 0xb8, 0xe7,
        0x7a, 0xaa, 0x82, 0xa3, 0x66, 0x30, 0x64, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
        0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x06,
        0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x1d,
        0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x63, 0x54, 0x0e, 0x47, 0xf6, 0x4b,
        0x1c, 0x38, 0xd1, 0x38, 0x84, 0xa4, 0x62, 0xd1, 0x6c, 0x19, 0x5d, 0x8f, 0xfb, 0x3c, 0x30,
        0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6a, 0xfd, 0x22,
        0x77, 0x1f, 0x51, 0x1f, 0xec, 0xbf, 0x16, 0x41, 0x97, 0x67, 0x10, 0xdc, 0xdc, 0x31, 0xa1,
        0x71, 0x7e, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
        0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xb2, 0xef, 0x27, 0xf4, 0x9a, 0xe9, 0xb5, 0x0f,
        0xb9, 0x1e, 0xea, 0xc9, 0x4c, 0x4d, 0x0b, 0xdb, 0xb8, 0xd7, 0x92, 0x9c, 0x6c, 0xb8, 0x8f,
        0xac, 0xe5, 0x29, 0x36, 0x8d, 0x12, 0x05, 0x4c, 0x0c, 0x02, 0x20, 0x65, 0x5d, 0xc9, 0x2b,
        0x86, 0xbd, 0x90, 0x98, 0x82, 0xa6, 0xc6, 0x21, 0x77, 0xb8, 0x25, 0xd7, 0xd0, 0x5e, 0xdb,
        0xe7, 0xc2, 0x2f, 0x9f, 0xea, 0x71, 0x22, 0x0e, 0x7e, 0xa7, 0x03, 0xf8, 0x91,
    ];

    // Matter Development DAC certificate (VID=FFF1, PID=8000)
    // From connectedhomeip/credentials/development/attestation/Matter-Development-DAC-FFF1-8000-Cert.der
    const DAC_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0xe9, 0x30, 0x82, 0x01, 0x8e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08,
        0x23, 0x8a, 0x64, 0x7b, 0xbc, 0x4c, 0x30, 0xdd, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x3d, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x1c, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x44, 0x65, 0x76, 0x20, 0x50,
        0x41, 0x49, 0x20, 0x30, 0x78, 0x46, 0x46, 0x46, 0x31, 0x20, 0x6e, 0x6f, 0x20, 0x50, 0x49,
        0x44, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c,
        0x02, 0x01, 0x0c, 0x04, 0x46, 0x46, 0x46, 0x31, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x32, 0x30,
        0x32, 0x30, 0x35, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39,
        0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x53, 0x31,
        0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1c, 0x4d, 0x61, 0x74, 0x74, 0x65,
        0x72, 0x20, 0x44, 0x65, 0x76, 0x20, 0x44, 0x41, 0x43, 0x20, 0x30, 0x78, 0x46, 0x46, 0x46,
        0x31, 0x2f, 0x30, 0x78, 0x38, 0x30, 0x30, 0x30, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b,
        0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02, 0x01, 0x0c, 0x04, 0x46, 0x46, 0x46, 0x31,
        0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02,
        0x02, 0x0c, 0x04, 0x38, 0x30, 0x30, 0x30, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00, 0x04, 0x62, 0xdb, 0x16, 0xba, 0xde, 0xa3, 0x26, 0xa6, 0xdb, 0x84, 0x81,
        0x4a, 0x06, 0x3f, 0xc6, 0xc7, 0xe9, 0xe2, 0xb1, 0x01, 0xb7, 0x21, 0x64, 0x8e, 0xba, 0x4e,
        0x5a, 0xc8, 0x40, 0xf5, 0xda, 0x30, 0x1e, 0xe6, 0x18, 0x12, 0x4e, 0xb4, 0x18, 0x0e, 0x2f,
        0xc3, 0xa2, 0x04, 0x7a, 0x56, 0x4b, 0xa9, 0xbc, 0xfa, 0x0b, 0xf7, 0x1f, 0x60, 0xce, 0x89,
        0x30, 0xf1, 0xe7, 0xf6, 0x6e, 0xc8, 0xd7, 0x28, 0xa3, 0x60, 0x30, 0x5e, 0x30, 0x0c, 0x06,
        0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03,
        0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x1d, 0x06,
        0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xbc, 0xf7, 0xb0, 0x07, 0x49, 0x70, 0x63,
        0x60, 0x6a, 0x26, 0xbe, 0x4e, 0x08, 0x7c, 0x59, 0x56, 0x87, 0x74, 0x5a, 0x5a, 0x30, 0x1f,
        0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x63, 0x54, 0x0e, 0x47,
        0xf6, 0x4b, 0x1c, 0x38, 0xd1, 0x38, 0x84, 0xa4, 0x62, 0xd1, 0x6c, 0x19, 0x5d, 0x8f, 0xfb,
        0x3c, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49,
        0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0x97, 0x97, 0x11, 0xec, 0x9e, 0x76, 0x18, 0xce, 0x41,
        0x80, 0x11, 0x32, 0xc2, 0x50, 0xdb, 0x70, 0x76, 0x74, 0x63, 0x0c, 0xd5, 0x8c, 0x12, 0xc6,
        0xe2, 0x31, 0x5f, 0x08, 0xd0, 0x1e, 0xe1, 0x78, 0x02, 0x21, 0x00, 0xec, 0xfc, 0x13, 0x06,
        0xbd, 0x2a, 0x13, 0x3d, 0x12, 0x2a, 0x27, 0x86, 0x10, 0xea, 0x3d, 0xca, 0x47, 0xf0, 0x5c,
        0x7a, 0x8b, 0x80, 0x5f, 0xa7, 0x1c, 0x6f, 0xf4, 0x15, 0x38, 0xa8, 0x64, 0xc8,
    ];

    #[test]
    fn test_paa_skid() {
        let cert = PaaCert::new(PAA_DER).unwrap();
        let skid = cert.subject_key_id().unwrap();
        assert_eq!(
            skid,
            &[
                0xFA, 0x92, 0xCF, 0x09, 0x5E, 0xFA, 0x42, 0xE1, 0x14, 0x30, 0x65, 0x16, 0x32, 0xFE,
                0xFE, 0x1B, 0x2C, 0x77, 0xA7, 0xC8
            ]
        );
    }

    #[test]
    fn test_paa_self_signed_akid_equals_skid() {
        // PAA certificates may have AKID (for self-signed certs, AKID should equal SKID)
        let cert = PaaCert::new(PAA_DER).unwrap();
        let skid = cert.subject_key_id().unwrap();
        let akid = cert.authority_key_id().unwrap();
        assert_eq!(skid, akid);
    }

    #[test]
    fn test_pai_skid() {
        let cert = PaiCert::new(PAI_DER).unwrap();
        let skid = cert.subject_key_id().unwrap();
        assert_eq!(
            skid,
            &[
                0x63, 0x54, 0x0E, 0x47, 0xF6, 0x4B, 0x1C, 0x38, 0xD1, 0x38, 0x84, 0xA4, 0x62, 0xD1,
                0x6C, 0x19, 0x5D, 0x8F, 0xFB, 0x3C
            ]
        );
    }

    #[test]
    fn test_dac_skid() {
        let cert = DacCert::new(DAC_DER).unwrap();
        let skid = cert.subject_key_id().unwrap();
        assert_eq!(
            skid,
            &[
                0xBC, 0xF7, 0xB0, 0x07, 0x49, 0x70, 0x63, 0x60, 0x6A, 0x26, 0xBE, 0x4E, 0x08, 0x7C,
                0x59, 0x56, 0x87, 0x74, 0x5A, 0x5A
            ]
        );
    }

    #[test]
    fn test_dac_akid_matches_pai_skid() {
        let dac = DacCert::new(DAC_DER).unwrap();
        let pai = PaiCert::new(PAI_DER).unwrap();
        assert_eq!(
            dac.authority_key_id().unwrap(),
            pai.subject_key_id().unwrap()
        );
    }

    #[test]
    fn test_paa_public_key() {
        let cert = PaaCert::new(PAA_DER).unwrap();
        let pk = cert.public_key().unwrap();
        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04); // uncompressed point marker
        assert_eq!(
            pk,
            &[
                0x04, 0x1b, 0x0f, 0x25, 0x94, 0x2e, 0x3d, 0x92, 0xab, 0xd6, 0x70, 0x4c, 0x1a, 0x27,
                0x81, 0xa0, 0x38, 0xec, 0x53, 0x21, 0x2c, 0x4d, 0xab, 0x58, 0xb0, 0xbe, 0x3c, 0x40,
                0xbd, 0xfb, 0x49, 0x23, 0x23, 0x42, 0x1c, 0x79, 0xdc, 0xc7, 0xad, 0x70, 0x18, 0x10,
                0x07, 0x12, 0x0d, 0xc8, 0x6f, 0x0a, 0x89, 0x25, 0x3d, 0x89, 0x93, 0xeb, 0x37, 0xab,
                0x65, 0x2e, 0xf8, 0xdb, 0x13, 0x75, 0xe5, 0xb1, 0x45,
            ]
        );
    }

    #[test]
    fn test_dac_public_key() {
        let cert = DacCert::new(DAC_DER).unwrap();
        let pk = cert.public_key().unwrap();
        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04);
        assert_eq!(
            pk,
            &[
                0x04, 0x62, 0xdb, 0x16, 0xba, 0xde, 0xa3, 0x26, 0xa6, 0xdb, 0x84, 0x81, 0x4a, 0x06,
                0x3f, 0xc6, 0xc7, 0xe9, 0xe2, 0xb1, 0x01, 0xb7, 0x21, 0x64, 0x8e, 0xba, 0x4e, 0x5a,
                0xc8, 0x40, 0xf5, 0xda, 0x30, 0x1e, 0xe6, 0x18, 0x12, 0x4e, 0xb4, 0x18, 0x0e, 0x2f,
                0xc3, 0xa2, 0x04, 0x7a, 0x56, 0x4b, 0xa9, 0xbc, 0xfa, 0x0b, 0xf7, 0x1f, 0x60, 0xce,
                0x89, 0x30, 0xf1, 0xe7, 0xf6, 0x6e, 0xc8, 0xd7, 0x28,
            ]
        );
    }

    #[test]
    fn test_dac_vendor_id() {
        let cert = DacCert::new(DAC_DER).unwrap();
        assert_eq!(cert.vendor_id().unwrap(), 0xFFF1);
    }

    #[test]
    fn test_dac_product_id() {
        let cert = DacCert::new(DAC_DER).unwrap();
        assert_eq!(cert.product_id().unwrap(), 0x8000);
    }

    #[test]
    fn test_pai_vendor_id() {
        let cert = PaiCert::new(PAI_DER).unwrap();
        assert_eq!(cert.vendor_id().unwrap(), 0xFFF1);
    }

    #[test]
    fn test_pai_no_product_id() {
        let cert = PaiCert::new(PAI_DER).unwrap();
        assert_eq!(
            cert.product_id().map_err(|e| e.code()),
            Err(ErrorCode::NotFound)
        );
    }

    #[test]
    fn test_paa_no_vendor_id() {
        let cert = PaaCert::new(PAA_DER).unwrap();
        assert_eq!(
            cert.vendor_id().map_err(|e| e.code()),
            Err(ErrorCode::NotFound)
        );
    }

    #[test]
    fn test_paa_no_product_id() {
        let cert = PaaCert::new(PAA_DER).unwrap();
        assert_eq!(
            cert.product_id().map_err(|e| e.code()),
            Err(ErrorCode::NotFound)
        );
    }

    #[test]
    fn test_dac_not_before() {
        let cert = DacCert::new(DAC_DER).unwrap();
        let nb = cert.not_before_unix().unwrap();
        // 2022-02-05 00:00:00 UTC = 1644019200
        assert_eq!(nb, 1644019200);
    }

    #[test]
    fn test_dac_not_after_no_expiry() {
        let cert = DacCert::new(DAC_DER).unwrap();
        let na = cert.not_after_unix().unwrap();
        // 99991231235959Z => u64::MAX (no expiry)
        assert_eq!(na, u64::MAX);
    }

    #[test]
    fn test_paa_not_before() {
        let cert = PaaCert::new(PAA_DER).unwrap();
        let nb = cert.not_before_unix().unwrap();
        // 2021-06-28 14:23:43 UTC = 1624890223
        assert_eq!(nb, 1624890223);
    }

    #[test]
    fn test_dac_is_valid_at() {
        let cert = DacCert::new(DAC_DER).unwrap();
        // A time well after NotBefore (2023-11-14)
        assert!(cert.is_valid_at(1700000000).unwrap());
        // A time before NotBefore (2021-09-13)
        assert!(!cert.is_valid_at(1600000000).unwrap());
    }

    #[test]
    fn test_invalid_empty_input() {
        assert!(DacCert::new(&[]).is_err());
    }

    #[test]
    fn test_invalid_not_sequence() {
        assert!(DacCert::new(&[0x01, 0x02, 0x03]).is_err());
    }

    #[test]
    fn test_invalid_empty_sequence() {
        assert!(DacCert::new(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn test_tbs_field_version_error_when_absent() {
        let mut der = PAA_DER.to_vec();
        let version_field_len: usize = 5;
        let version_start: usize = 8;

        // remove version field length from DER length
        der[3] -= version_field_len as u8;
        // remove version field length from tbs certificate length
        der[7] -= version_field_len as u8;
        // remove version field from the certificate
        der.drain(version_start..version_start + version_field_len);

        assert!(PaaCert::new(&der).is_err());
    }

    #[test]
    fn test_version_must_be_v3() {
        let mut der = PAA_DER.to_vec();

        // Change version from v3 (2) to v2 (1)
        der[12] = 1;
        // Matter certificate versions must be v3
        assert!(PaaCert::new(&der).is_err());
    }

    #[test]
    fn test_parse_hex_u16() {
        assert_eq!(parse_hex_u16(b"FFF1").unwrap(), 0xFFF1);
        assert_eq!(parse_hex_u16(b"8000").unwrap(), 0x8000);
        assert_eq!(parse_hex_u16(b"0000").unwrap(), 0x0000);
        assert_eq!(parse_hex_u16(b"FFFF").unwrap(), 0xFFFF);
        assert_eq!(parse_hex_u16(b"abcd").unwrap(), 0xABCD);
        assert!(parse_hex_u16(b"FFF").is_err()); // too short
        assert!(parse_hex_u16(b"FFFFF").is_err()); // too long
        assert!(parse_hex_u16(b"GHIJ").is_err()); // invalid chars
    }
}
