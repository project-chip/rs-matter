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

//! Certification Declaration (CD) parsing, verification, and validation.
//!
//! A Certification Declaration is a CMS (RFC 5652) SignedData structure containing
//! a TLV-encoded payload that attests to a device's certification status.
//! It is issued by the CSA (Connectivity Standards Alliance) and signed with
//! one of the well-known CD signing keys.
//!
//! This module implements:
//! - CMS SignedData envelope parsing (extracting signer KID, CD content, signature)
//! - DER-encoded ECDSA signature to raw (r || s) conversion
//! - CD TLV payload decoding into [`CertificationElements`]
//! - Signature verification using the [`Crypto`] trait
//! - CD content validation against device identity (Matter Spec 6.3.1)
//!
//! Reference: connectedhomeip `src/credentials/CertificationDeclaration.cpp`

use crate::cert::der_utils::ecdsa_der_to_raw;
use crate::cert::x509::AlgorithmIdentifier;
use crate::credentials::cd_keys::{self, KEY_IDENTIFIER_LEN};
use crate::crypto::{CanonPkcPublicKeyRef, CanonPkcSignatureRef, Crypto, PublicKey};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVElement, TLVSequence};

use der::asn1::{AnyRef, ObjectIdentifier, OctetStringRef};
use der::{
    Decode, DecodeValue, EncodeValue, FixedTag, Header, Reader, Sequence, Tag, TagNumber, Tagged,
};

/// https://www.rfc-editor.org/rfc/rfc5652#section-12.1
/// OID: 1.2.840.113549.1.7.2 (id-signedData)
const OID_PKCS7_SIGNED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// OID: 1.2.840.113549.1.7.1 (id-data)
const OID_PKCS7_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// https://www.rfc-editor.org/rfc/rfc5758.html#section-2
/// OID: 2.16.840.1.101.3.4.2.1 (id-sha256)
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// OID: 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// P-256 field element length in bytes (ECDSA signature r and s values).
const P256_FE_LEN: usize = 32;

/// Raw ECDSA signature length: r (32 bytes) || s (32 bytes).
const RAW_SIGNATURE_LEN: usize = P256_FE_LEN * 2;

/// ContentInfo ::= SEQUENCE {
///   contentType OBJECT IDENTIFIER,
///   content [0] EXPLICIT ANY DEFINED BY contentType
/// }
///
/// https://www.rfc-editor.org/rfc/rfc5652#section-3
#[allow(unused)]
struct ContentInfo<'a> {
    content_type: ObjectIdentifier,
    /// The raw bytes of the SignedData SEQUENCE (after [0] EXPLICIT unwrapping)
    signed_data_bytes: &'a [u8],
}

impl<'a> DecodeValue<'a> for ContentInfo<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            // contentType OBJECT IDENTIFIER
            let content_type = ObjectIdentifier::decode(reader)?;

            // Validate contentType is id-signedData
            if content_type != OID_PKCS7_SIGNED_DATA {
                return Err(der::ErrorKind::Failed.into());
            }

            // content [0] EXPLICIT - we need to unwrap and get the inner bytes
            // Read the [0] context tag (should be context-specific, constructed, number 0)
            let context_header = Header::decode(reader)?;
            // Check for context-specific tag [0] constructed (0xA0)
            if context_header.tag.number() != TagNumber::new(0)
                || !context_header.tag.is_constructed()
            {
                return Err(der::ErrorKind::Failed.into());
            }

            // The content inside [0] is the SignedData SEQUENCE (the whole TLV)
            let signed_data_bytes = reader.read_slice(context_header.length)?;

            Ok(Self {
                content_type,
                signed_data_bytes,
            })
        })
    }
}

impl<'a> FixedTag for ContentInfo<'a> {
    const TAG: Tag = Tag::Sequence;
}

// TODO Remove when upgrading to der 0.8+ which separates Encode/Decode traits.
impl<'a> EncodeValue for ContentInfo<'a> {
    fn value_len(&self) -> der::Result<der::Length> {
        unimplemented!("ContentInfo encoding is not supported")
    }

    fn encode_value(&self, _writer: &mut impl der::Writer) -> der::Result<()> {
        unimplemented!("ContentInfo encoding is not supported")
    }
}

/// EncapsulatedContentInfo ::= SEQUENCE {
///   eContentType OBJECT IDENTIFIER,
///   eContent [0] EXPLICIT OCTET STRING
/// }
///
/// https://www.rfc-editor.org/rfc/rfc5652#section-5.2
#[derive(Sequence)]
struct EncapsulatedContentInfo<'a> {
    econtent_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    econtent: OctetStringRef<'a>,
}

/// SignedData ::= SEQUENCE {
///   version INTEGER,
///   digestAlgorithms DigestAlgorithmIdentifiers,
///   encapContentInfo EncapsulatedContentInfo,
///   signerInfos SignerInfos
/// }
///
/// https://www.rfc-editor.org/rfc/rfc5652#section-5.1
#[allow(unused)]
struct SignedData<'a> {
    version: u8,
    encap_content_info: EncapsulatedContentInfo<'a>,
    /// SignerInfos is a SET OF, but store as AnyRef for manual parsing
    /// to extract the single SignerInfo
    signer_infos: AnyRef<'a>,
}

impl<'a> DecodeValue<'a> for SignedData<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            // version INTEGER (v3 = 3)
            let version = u8::decode(reader)?;
            if version != 3 {
                return Err(der::ErrorKind::Failed.into());
            }

            // skip digestAlgorithms SET OF
            let _digest_algorithms = AnyRef::decode(reader)?;
            if _digest_algorithms.tag() != Tag::Set {
                return Err(der::ErrorKind::Failed.into());
            }

            // encapContentInfo EncapsulatedContentInfo
            let encap_content_info = EncapsulatedContentInfo::decode(reader)?;

            // Validate eContentType is pkcs7-data
            if encap_content_info.econtent_type != OID_PKCS7_DATA {
                return Err(der::ErrorKind::Failed.into());
            }

            // signerInfos SET OF
            let signer_infos = AnyRef::decode(reader)?;
            if signer_infos.tag() != Tag::Set {
                return Err(der::ErrorKind::Failed.into());
            }

            Ok(Self {
                version,
                encap_content_info,
                signer_infos,
            })
        })
    }
}

impl<'a> FixedTag for SignedData<'a> {
    const TAG: Tag = Tag::Sequence;
}

// TODO Remove when upgrading to der 0.8+ which separates Encode/Decode traits.
impl<'a> EncodeValue for SignedData<'a> {
    fn value_len(&self) -> der::Result<der::Length> {
        unimplemented!("SignedData encoding is not supported")
    }

    fn encode_value(&self, _writer: &mut impl der::Writer) -> der::Result<()> {
        unimplemented!("SignedData encoding is not supported")
    }
}

/// SignerInfo ::= SEQUENCE {
///   version INTEGER,
///   subjectKeyIdentifier [0] IMPLICIT OCTET STRING,
///   digestAlgorithm AlgorithmIdentifier,
///   signatureAlgorithm AlgorithmIdentifier,
///   signature OCTET STRING
/// }
///
/// Matter-specific SignerInfo with subjectKeyIdentifier instead of SignerIdentifier.
///
/// https://www.rfc-editor.org/rfc/rfc5652#section-5.3
#[allow(unused)]
struct SignerInfo<'a> {
    version: u8,
    subject_key_identifier: &'a [u8],
    digest_algorithm: AlgorithmIdentifier<'a>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: OctetStringRef<'a>,
}

impl<'a> DecodeValue<'a> for SignerInfo<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            // version INTEGER (v3 = 3)
            let version = u8::decode(reader)?;
            if version != 3 {
                return Err(der::ErrorKind::Failed.into());
            }

            // subjectKeyIdentifier [0] IMPLICIT OCTET STRING
            let ski_header = Header::decode(reader)?;

            // Check for context-specific tag [0] primitive
            if ski_header.tag.number() != TagNumber::new(0) || ski_header.tag.is_constructed() {
                return Err(der::ErrorKind::Failed.into());
            }

            let subject_key_identifier = reader.read_slice(ski_header.length)?;

            // Validate SKI is exactly 20 bytes
            if subject_key_identifier.len() != KEY_IDENTIFIER_LEN {
                return Err(der::ErrorKind::Failed.into());
            }

            // digestAlgorithm AlgorithmIdentifier
            let digest_algorithm = AlgorithmIdentifier::decode(reader)?;

            // Validate digest algorithm is SHA256
            if digest_algorithm.algorithm != OID_SHA256 {
                return Err(der::ErrorKind::Failed.into());
            }

            // signatureAlgorithm AlgorithmIdentifier
            let signature_algorithm = AlgorithmIdentifier::decode(reader)?;

            // Validate signature algorithm is ECDSA with SHA256
            if signature_algorithm.algorithm != OID_ECDSA_WITH_SHA256 {
                return Err(der::ErrorKind::Failed.into());
            }

            // signature OCTET STRING (contains DER-encoded ECDSA signature)
            let signature = OctetStringRef::decode(reader)?;

            Ok(Self {
                version,
                subject_key_identifier,
                digest_algorithm,
                signature_algorithm,
                signature,
            })
        })
    }
}

impl<'a> FixedTag for SignerInfo<'a> {
    const TAG: Tag = Tag::Sequence;
}

// Dummy EncodeValue implementation
// Required by der version 0.7 for use with #[derive(Sequence)] on structs that contain this type.
// TODO: Remove when upgrading to der 0.8+ which separates Encode/Decode traits.
impl<'a> EncodeValue for SignerInfo<'a> {
    fn value_len(&self) -> der::Result<der::Length> {
        unimplemented!("SignerInfo encoding is not supported")
    }

    fn encode_value(&self, _writer: &mut impl der::Writer) -> der::Result<()> {
        unimplemented!("SignerInfo encoding is not supported")
    }
}

/// Parsed contents of a CMS SignedData envelope
pub struct CmsSignedData<'a> {
    /// SubjectKeyIdentifier from the SignerInfo (identifies the signing key)
    pub signer_key_id: &'a [u8],
    /// Raw TLV CD payload (the encapsulated content)
    pub cd_content: &'a [u8],
    /// ECDSA signature in raw (r || s) format, 64 bytes
    pub signature_raw: [u8; RAW_SIGNATURE_LEN],
}

impl<'a> CmsSignedData<'a> {
    /// Parse a CMS SignedData message, extracting the signer key ID,
    /// encapsulated CD content, and ECDSA signature (converted from DER to raw).
    ///
    /// Expects the profiled CMS structure used by Matter CDs (Matter Spec 6.3.1):
    /// https://www.rfc-editor.org/rfc/rfc5652#section-5.2
    /// ```text
    /// ContentInfo ::= SEQUENCE {
    ///   contentType OBJECT IDENTIFIER id-signedData (1.2.840.113549.1.7.2),
    ///   content [0] EXPLICIT SignedData
    /// }
    ///
    /// SignedData ::= SEQUENCE {
    ///   version INTEGER (v3(3)),
    ///   digestAlgorithms SET { OBJECT IDENTIFIER sha256 (2.16.840.1.101.3.4.2.1) },
    ///   encapContentInfo EncapsulatedContentInfo,
    ///   signerInfos SET { SignerInfo }
    /// }
    ///
    /// EncapsulatedContentInfo ::= SEQUENCE {
    ///   eContentType OBJECT IDENTIFIER pkcs7-data (1.2.840.113549.1.7.1),
    ///   eContent [0] EXPLICIT OCTET STRING cd_content
    /// }
    ///
    /// SignerInfo ::= SEQUENCE {
    ///   version INTEGER (v3(3)),
    ///   subjectKeyIdentifier [0] IMPLICIT OCTET STRING,
    ///   digestAlgorithm OBJECT IDENTIFIER sha256 (2.16.840.1.101.3.4.2.1),
    ///   signatureAlgorithm OBJECT IDENTIFIER ecdsa-with-SHA256 (1.2.840.10045.4.3.2),
    ///   signature OCTET STRING
    /// }
    /// ```
    pub fn parse(cms_message: &'a [u8]) -> Result<Self, Error> {
        // Parse ContentInfo
        let content_info = ContentInfo::from_der(cms_message)
            .map_err(|_| Error::from(ErrorCode::CdInvalidFormat))?;

        // Parse SignedData from the raw bytes (includes SEQUENCE tag + length + value)
        let signed_data = SignedData::from_der(content_info.signed_data_bytes)
            .map_err(|_| Error::from(ErrorCode::CdInvalidFormat))?;

        // Extract CD content (TLV payload)
        let cd_content = signed_data.encap_content_info.econtent.as_bytes();

        // Parse SignerInfo from signerInfos SET to extract key ID and signature
        let signer_info = SignerInfo::from_der(signed_data.signer_infos.value())
            .map_err(|_| Error::from(ErrorCode::CdInvalidFormat))?;

        // Convert DER-encoded ECDSA signature to raw (r || s) format
        let signature_raw = ecdsa_der_to_raw(signer_info.signature.as_bytes())?;

        Ok(Self {
            signer_key_id: signer_info.subject_key_identifier,
            cd_content,
            signature_raw,
        })
    }
}

/// Matter TLV context tags for CD elements (Matter Spec 6.3.1)
const CD_TAG_FORMAT_VERSION: u8 = 0;
const CD_TAG_VENDOR_ID: u8 = 1;
const CD_TAG_PRODUCT_ID_ARRAY: u8 = 2;
const CD_TAG_DEVICE_TYPE_ID: u8 = 3;
const CD_TAG_CERTIFICATE_ID: u8 = 4;
const CD_TAG_SECURITY_LEVEL: u8 = 5;
const CD_TAG_SECURITY_INFORMATION: u8 = 6;
const CD_TAG_VERSION_NUMBER: u8 = 7;
const CD_TAG_CERTIFICATION_TYPE: u8 = 8;
const CD_TAG_DAC_ORIGIN_VENDOR_ID: u8 = 9;
const CD_TAG_DAC_ORIGIN_PRODUCT_ID: u8 = 10;
const CD_TAG_AUTHORIZED_PAA_LIST: u8 = 11;

/// Maximum number of product IDs in a CD
pub const MAX_PRODUCT_IDS: usize = 100;

/// Fixed length of the certificate_id string
pub const CERTIFICATE_ID_LEN: usize = 19;

/// Maximum number of authorized PAA entries in a CD
pub const MAX_AUTHORIZED_PAA_LIST: usize = 10;

/// Certification type (Matter Spec 6.3.1.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum CertificationType {
    /// Development and test devices
    DevelopmentAndTest = 0,
    /// Provisionally certified devices
    Provisional = 1,
    /// Officially certified devices
    Official = 2,
}

impl CertificationType {
    /// Try to parse a certification type from a raw u8 value.
    pub fn from_u8(value: u8) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::DevelopmentAndTest),
            1 => Ok(Self::Provisional),
            2 => Ok(Self::Official),
            _ => Err(ErrorCode::CdInvalidFormat.into()),
        }
    }
}

/// Decoded Certification Declaration payload (Matter Spec 6.3.1.)
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CertificationElements {
    pub format_version: u16,
    pub vendor_id: u16,
    pub product_ids: [u16; MAX_PRODUCT_IDS],
    pub product_ids_count: usize,
    pub device_type_id: u32,
    pub certificate_id: [u8; CERTIFICATE_ID_LEN],
    pub security_level: u8,
    pub security_information: u16,
    pub version_number: u16,
    pub certification_type: CertificationType,
    /// DAC origin vendor ID (present only if `dac_origin_vid_pid_present` is true).
    pub dac_origin_vendor_id: u16,
    /// DAC origin product ID (present only if `dac_origin_vid_pid_present` is true).
    pub dac_origin_product_id: u16,
    /// Whether `dac_origin_vendor_id` and `dac_origin_product_id` are present.
    pub dac_origin_vid_pid_present: bool,
    /// Authorized PAA Subject Key Identifiers.
    pub authorized_paa_list: [[u8; KEY_IDENTIFIER_LEN]; MAX_AUTHORIZED_PAA_LIST],
    /// Number of entries in `authorized_paa_list`.
    pub authorized_paa_list_count: usize,
}

impl Default for CertificationElements {
    fn default() -> Self {
        Self {
            format_version: 0,
            vendor_id: 0,
            product_ids: [0u16; MAX_PRODUCT_IDS],
            product_ids_count: 0,
            device_type_id: 0,
            certificate_id: [0u8; CERTIFICATE_ID_LEN],
            security_level: 0,
            security_information: 0,
            version_number: 0,
            certification_type: CertificationType::DevelopmentAndTest,
            dac_origin_vendor_id: 0,
            dac_origin_product_id: 0,
            dac_origin_vid_pid_present: false,
            authorized_paa_list: [[0u8; KEY_IDENTIFIER_LEN]; MAX_AUTHORIZED_PAA_LIST],
            authorized_paa_list_count: 0,
        }
    }
}

impl CertificationElements {
    /// Decode a TLV-encoded CD payload into [`CertificationElements`].
    ///
    /// Validates the TLV structure, field types, and constraints per the Matter spec:
    /// - Tags 0-8 are mandatory and must appear in order.
    /// - Tags 9-10 (DAC origin) are optional but must appear together.
    /// - Tag 11 (authorized PAA list) is optional.
    /// - Product IDs array must have 1..=100 entries.
    /// - Certificate ID must be exactly 19 bytes.
    /// - Authorized PAA entries must each be exactly 20 bytes.
    pub fn decode(cd_content: &[u8]) -> Result<Self, Error> {
        let elem = TLVElement::new(cd_content);
        let structure = elem.structure()?;

        let format_version = structure.find_ctx(CD_TAG_FORMAT_VERSION)?.u16()?;
        if format_version != 1 {
            return Err(ErrorCode::CdInvalidFormat.into());
        }

        let (product_ids, product_ids_count) = Self::parse_product_ids(&structure)?;
        let certificate_id = Self::parse_certificate_id(&structure)?;
        let (dac_origin_vendor_id, dac_origin_product_id, dac_origin_vid_pid_present) =
            Self::parse_dac_origin(&structure)?;
        let (authorized_paa_list, authorized_paa_list_count) =
            Self::parse_authorized_paa_list(&structure)?;

        Ok(Self {
            format_version,
            vendor_id: structure.find_ctx(CD_TAG_VENDOR_ID)?.u16()?,
            product_ids,
            product_ids_count,
            device_type_id: structure.find_ctx(CD_TAG_DEVICE_TYPE_ID)?.u32()?,
            certificate_id,
            security_level: structure.find_ctx(CD_TAG_SECURITY_LEVEL)?.u8()?,
            security_information: structure.find_ctx(CD_TAG_SECURITY_INFORMATION)?.u16()?,
            version_number: structure.find_ctx(CD_TAG_VERSION_NUMBER)?.u16()?,
            certification_type: CertificationType::from_u8(
                structure.find_ctx(CD_TAG_CERTIFICATION_TYPE)?.u8()?,
            )?,
            dac_origin_vendor_id,
            dac_origin_product_id,
            dac_origin_vid_pid_present,
            authorized_paa_list,
            authorized_paa_list_count,
        })
    }

    /// Parse the product ID array from TLV structure.
    /// Returns (product_ids array, count of valid entries).
    fn parse_product_ids(
        structure: &TLVSequence,
    ) -> Result<([u16; MAX_PRODUCT_IDS], usize), Error> {
        let pid_array = structure.find_ctx(CD_TAG_PRODUCT_ID_ARRAY)?;
        let pid_seq = pid_array.array()?;

        let mut product_ids = [0u16; MAX_PRODUCT_IDS];
        let mut count = 0usize;

        for pid_elem in pid_seq.iter() {
            let pid_elem: TLVElement<'_> = pid_elem?;
            if count >= MAX_PRODUCT_IDS {
                return Err(ErrorCode::CdInvalidFormat.into());
            }
            product_ids[count] = pid_elem.u16()?;
            count += 1;
        }

        if count == 0 {
            return Err(ErrorCode::CdInvalidFormat.into());
        }

        Ok((product_ids, count))
    }

    /// Parse the certificate ID from TLV structure.
    /// Returns a fixed-length array of exactly CERTIFICATE_ID_LEN bytes.
    fn parse_certificate_id(structure: &TLVSequence) -> Result<[u8; CERTIFICATE_ID_LEN], Error> {
        let cert_id_str = structure.find_ctx(CD_TAG_CERTIFICATE_ID)?.utf8()?;
        if cert_id_str.len() != CERTIFICATE_ID_LEN {
            return Err(ErrorCode::CdInvalidFormat.into());
        }

        let mut certificate_id = [0u8; CERTIFICATE_ID_LEN];
        certificate_id.copy_from_slice(cert_id_str.as_bytes());
        Ok(certificate_id)
    }

    /// Parse optional DAC origin vendor/product IDs from TLV structure.
    /// Returns (dac_origin_vendor_id, dac_origin_product_id, is_present).
    fn parse_dac_origin(structure: &TLVSequence) -> Result<(u16, u16, bool), Error> {
        let vid_elem = structure.find_ctx(CD_TAG_DAC_ORIGIN_VENDOR_ID)?;
        let pid_elem = structure.find_ctx(CD_TAG_DAC_ORIGIN_PRODUCT_ID)?;

        // Both must be present or both must be absent
        if vid_elem.is_empty() != pid_elem.is_empty() {
            return Err(ErrorCode::CdInvalidFormat.into());
        }

        if !vid_elem.is_empty() {
            Ok((vid_elem.u16()?, pid_elem.u16()?, true))
        } else {
            Ok((0, 0, false))
        }
    }

    /// Parse optional authorized PAA list from TLV structure.
    /// Returns (authorized_paa_list array, count of valid entries).
    fn parse_authorized_paa_list(
        structure: &TLVSequence,
    ) -> Result<([[u8; KEY_IDENTIFIER_LEN]; MAX_AUTHORIZED_PAA_LIST], usize), Error> {
        let paa_elem = structure.find_ctx(CD_TAG_AUTHORIZED_PAA_LIST)?;

        let mut authorized_paa_list = [[0u8; KEY_IDENTIFIER_LEN]; MAX_AUTHORIZED_PAA_LIST];
        let mut paa_count = 0usize;

        if !paa_elem.is_empty() {
            let paa_seq = paa_elem.array()?;
            for paa_entry in paa_seq.iter() {
                let paa_entry: TLVElement<'_> = paa_entry?;
                if paa_count >= MAX_AUTHORIZED_PAA_LIST {
                    return Err(ErrorCode::CdInvalidFormat.into());
                }
                let paa_bytes = paa_entry.str()?;
                if paa_bytes.len() != KEY_IDENTIFIER_LEN {
                    return Err(ErrorCode::CdInvalidFormat.into());
                }
                authorized_paa_list[paa_count].copy_from_slice(paa_bytes);
                paa_count += 1;
            }
        }

        Ok((authorized_paa_list, paa_count))
    }

    /// Verify a CMS-signed Certification Declaration.
    ///
    /// 1. Parses the CMS envelope
    /// 2. Looks up the signing key by Key ID in the well-known trust store
    /// 3. Enforces test key policy (test keys only for DevelopmentAndTest/Provisional)
    /// 4. Verifies the ECDSA-SHA256 signature over the CD content
    /// 5. Decodes the CD TLV payload
    ///
    /// # Arguments
    /// - `crypto`: Cryptographic backend for ECDSA verification.
    /// - `cms_message`: The complete CMS-signed CD message bytes.
    /// - `allow_test_cd_signing_key`: If `false`, CDs signed with the test key are rejected.
    ///
    /// # Returns
    /// The decoded [`CertificationElements`] on success.
    pub fn verify<C: Crypto>(
        crypto: &C,
        cms_message: &[u8],
        allow_test_cd_signing_key: bool,
    ) -> Result<Self, Error> {
        // Parse CMS envelope
        let cms = CmsSignedData::parse(cms_message)?;

        // Look up signing key
        let pubkey_bytes = cd_keys::lookup_cd_signing_key(cms.signer_key_id)
            .ok_or(Error::new(ErrorCode::CdSigningKeyNotFound))?;

        // Test key policy
        let is_test_key = cd_keys::is_test_cd_key(cms.signer_key_id);
        if is_test_key && !allow_test_cd_signing_key {
            return Err(ErrorCode::CdSigningKeyNotFound.into());
        }

        // Verify ECDSA-SHA256 signature over the raw CD content
        let pubkey_ref = CanonPkcPublicKeyRef::try_new(pubkey_bytes)?;
        let pubkey = crypto.pub_key(pubkey_ref)?;

        let sig_ref = CanonPkcSignatureRef::new(
            <&[u8; RAW_SIGNATURE_LEN]>::try_from(&cms.signature_raw[..])
                .map_err(|_| Error::new(ErrorCode::CdInvalidSignature))?,
        );

        let valid = pubkey.verify(cms.cd_content, sig_ref)?;
        if !valid {
            return Err(ErrorCode::CdInvalidSignature.into());
        }

        // Decode CD TLV payload
        let cd = CertificationElements::decode(cms.cd_content)?;

        // Post-signature test key policy enforcement
        // Test key may only sign DevelopmentAndTest (and optionally Provisional) CDs
        if is_test_key && cd.certification_type == CertificationType::Official {
            return Err(ErrorCode::CdSigningKeyNotFound.into());
        }

        Ok(cd)
    }

    /// Validate CD content against device identity.
    ///
    /// Implements the CD validation rules (Matter Spec Section 6.3.1).
    ///
    /// # Validation rules
    ///
    /// 1. `format_version` must be 1.
    /// 2. `certification_type` must be valid (0, 1, or 2) -- already enforced by decoding.
    /// 3. CD `vendor_id` must match device's BasicInformation VendorID.
    /// 4. Device's BasicInformation ProductID must be in CD's `product_id_array`.
    /// 5. If `dac_origin_vid_pid_present`:
    ///    - DAC VID must match `dac_origin_vendor_id`
    ///    - PAI VID must match `dac_origin_vendor_id`
    ///    - DAC PID must match `dac_origin_product_id`
    ///    - If PAI has PID, it must match `dac_origin_product_id`
    /// 6. If NOT `dac_origin_vid_pid_present`:
    ///    - DAC VID must match CD `vendor_id`
    ///    - PAI VID must match CD `vendor_id`
    ///    - DAC PID must be in CD `product_id_array`
    ///    - If PAI has PID, it must be in CD `product_id_array`
    /// 7. If `authorized_paa_list` is present, PAA's SKID must be in the list.
    ///
    /// Note: `security_level`, `security_information`, and `version_number` are
    /// explicitly ignored per the specification.
    pub fn validate(&self, device_info: &DeviceInfoForAttestation) -> Result<(), Error> {
        // Rule 1: format_version must be 1
        if self.format_version != 1 {
            return Err(ErrorCode::CdInvalidFormat.into());
        }

        // Rule 2: certification_type is already validated by decode

        // Rule 3: CD vendor_id must match device's BasicInformation VendorID
        if self.vendor_id != device_info.vendor_id {
            return Err(ErrorCode::CdInvalidVendorId.into());
        }

        // Rule 4: Device's ProductID must be in the CD's product_id_array
        if !product_id_in_list(device_info.product_id, self) {
            return Err(ErrorCode::CdInvalidProductId.into());
        }

        // Rules 5-6: VID/PID matching depends on dac_origin_vid_pid_present
        if self.dac_origin_vid_pid_present {
            // Rule 5: dacOriginVIDandPID present
            if device_info.dac_vendor_id != self.dac_origin_vendor_id {
                return Err(ErrorCode::CdInvalidVendorId.into());
            }
            if device_info.pai_vendor_id != self.dac_origin_vendor_id {
                return Err(ErrorCode::CdInvalidVendorId.into());
            }
            if device_info.dac_product_id != self.dac_origin_product_id {
                return Err(ErrorCode::CdInvalidProductId.into());
            }
            if device_info.pai_product_id != 0
                && device_info.pai_product_id != self.dac_origin_product_id
            {
                return Err(ErrorCode::CdInvalidProductId.into());
            }
        } else {
            // Rule 6: dacOriginVIDandPID NOT present
            if device_info.dac_vendor_id != self.vendor_id {
                return Err(ErrorCode::CdInvalidVendorId.into());
            }
            if device_info.pai_vendor_id != self.vendor_id {
                return Err(ErrorCode::CdInvalidVendorId.into());
            }
            if !product_id_in_list(device_info.dac_product_id, self) {
                return Err(ErrorCode::CdInvalidProductId.into());
            }
            if device_info.pai_product_id != 0
                && !product_id_in_list(device_info.pai_product_id, self)
            {
                return Err(ErrorCode::CdInvalidProductId.into());
            }
        }

        // Rule 7: Authorized PAA list check
        if self.authorized_paa_list_count > 0 {
            let mut found = false;
            for i in 0..self.authorized_paa_list_count {
                if self.authorized_paa_list[i] == device_info.paa_skid {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(ErrorCode::CdInvalidPaa.into());
            }
        }

        Ok(())
    }
}

/// Device identity information for CD validation.
///
/// Carries the identity data extracted from the device's BasicInformation cluster
/// and its certificate chain (DAC, PAI, PAA).
pub struct DeviceInfoForAttestation {
    /// Vendor ID from the BasicInformation cluster.
    pub vendor_id: u16,
    /// Product ID from the BasicInformation cluster.
    pub product_id: u16,
    /// Vendor ID extracted from the DAC certificate.
    pub dac_vendor_id: u16,
    /// Product ID extracted from the DAC certificate.
    pub dac_product_id: u16,
    /// Vendor ID extracted from the PAI certificate.
    pub pai_vendor_id: u16,
    /// Product ID extracted from the PAI certificate (0 if not present).
    pub pai_product_id: u16,
    /// Subject Key Identifier of the PAA certificate.
    pub paa_skid: [u8; KEY_IDENTIFIER_LEN],
}

/// Check if a product ID is present in the CD's product_id_array.
fn product_id_in_list(pid: u16, cd: &CertificationElements) -> bool {
    for i in 0..cd.product_ids_count {
        if cd.product_ids[i] == pid {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_only_crypto;

    // ---- Test vector 1: single product ID, no DAC origin ----
    // Signed with the "Matter Test CD Signing Authority" key.
    // -> format_version = 1
    // -> vendor_id = 0xFFF1
    // -> product_id_array = [ 0x8000 ]
    // -> device_type_id = 0x1234
    // -> certificate_id = "ZIG20141ZB330001-24"
    // -> security_level = 0
    // -> security_information = 0
    // -> version_number = 0x2694
    // -> certification_type = 0
    // -> dac_origin_vendor_id is not present
    // -> dac_origin_product_id is not present

    fn expected_cd_01() -> CertificationElements {
        let mut cd = CertificationElements::default();
        cd.format_version = 1;
        cd.vendor_id = 0xFFF1;
        cd.product_ids[0] = 0x8000;
        cd.product_ids_count = 1;
        cd.device_type_id = 0x1234;
        cd.certificate_id.copy_from_slice(b"ZIG20141ZB330001-24");
        cd.version_number = 0x2694;
        cd
    }

    const TEST_CMS_CD_CONTENT_01: &[u8] = &[
        0x15, 0x24, 0x00, 0x01, 0x25, 0x01, 0xf1, 0xff, 0x36, 0x02, 0x05, 0x00, 0x80, 0x18, 0x25,
        0x03, 0x34, 0x12, 0x2c, 0x04, 0x13, 0x5a, 0x49, 0x47, 0x32, 0x30, 0x31, 0x34, 0x31, 0x5a,
        0x42, 0x33, 0x33, 0x30, 0x30, 0x30, 0x31, 0x2d, 0x32, 0x34, 0x24, 0x05, 0x00, 0x24, 0x06,
        0x00, 0x25, 0x07, 0x94, 0x26, 0x24, 0x08, 0x00, 0x18,
    ];

    const TEST_CMS_SIGNED_MESSAGE_01: &[u8] = &[
        0x30, 0x81, 0xe8, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0,
        0x81, 0xda, 0x30, 0x81, 0xd7, 0x02, 0x01, 0x03, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60,
        0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x45, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x38, 0x04, 0x36, 0x15, 0x24, 0x00, 0x01, 0x25,
        0x01, 0xf1, 0xff, 0x36, 0x02, 0x05, 0x00, 0x80, 0x18, 0x25, 0x03, 0x34, 0x12, 0x2c, 0x04,
        0x13, 0x5a, 0x49, 0x47, 0x32, 0x30, 0x31, 0x34, 0x31, 0x5a, 0x42, 0x33, 0x33, 0x30, 0x30,
        0x30, 0x31, 0x2d, 0x32, 0x34, 0x24, 0x05, 0x00, 0x24, 0x06, 0x00, 0x25, 0x07, 0x94, 0x26,
        0x24, 0x08, 0x00, 0x18, 0x31, 0x7c, 0x30, 0x7a, 0x02, 0x01, 0x03, 0x80, 0x14, 0x62, 0xfa,
        0x82, 0x33, 0x59, 0xac, 0xfa, 0xa9, 0x96, 0x3e, 0x1c, 0xfa, 0x14, 0x0a, 0xdd, 0xf5, 0x04,
        0xf3, 0x71, 0x60, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x04, 0x46,
        0x30, 0x44, 0x02, 0x20, 0x43, 0xa6, 0x3f, 0x2b, 0x94, 0x3d, 0xf3, 0x3c, 0x38, 0xb3, 0xe0,
        0x2f, 0xca, 0xa7, 0x5f, 0xe3, 0x53, 0x2a, 0xeb, 0xbf, 0x5e, 0x63, 0xf5, 0xbb, 0xdb, 0xc0,
        0xb1, 0xf0, 0x1d, 0x3c, 0x4f, 0x60, 0x02, 0x20, 0x4c, 0x1a, 0xbf, 0x5f, 0x18, 0x07, 0xb8,
        0x18, 0x94, 0xb1, 0x57, 0x6c, 0x47, 0xe4, 0x72, 0x4e, 0x4d, 0x96, 0x6c, 0x61, 0x2e, 0xd3,
        0xfa, 0x25, 0xc1, 0x18, 0xc3, 0xf2, 0xb3, 0xf9, 0x03, 0x69,
    ];

    // ---- Test vector 2: two product IDs, with DAC origin ----
    // -> format_version = 1
    // -> vendor_id = 0xFFF2
    // -> product_id_array = [ 0x8001, 0x8002 ]
    // -> device_type_id = 0x1234
    // -> certificate_id = "ZIG20142ZB330002-24"
    // -> security_level = 0
    // -> security_information = 0
    // -> version_number = 0x2694
    // -> certification_type = 0
    // -> dac_origin_vendor_id = 0xFFF1
    // -> dac_origin_product_id = 0x8000

    fn expected_cd_02() -> CertificationElements {
        let mut cd = CertificationElements::default();
        cd.format_version = 1;
        cd.vendor_id = 0xFFF2;
        cd.product_ids[0] = 0x8001;
        cd.product_ids[1] = 0x8002;
        cd.product_ids_count = 2;
        cd.device_type_id = 0x1234;
        cd.certificate_id.copy_from_slice(b"ZIG20142ZB330002-24");
        cd.version_number = 0x2694;
        cd.dac_origin_vendor_id = 0xFFF1;
        cd.dac_origin_product_id = 0x8000;
        cd.dac_origin_vid_pid_present = true;
        cd
    }

    const TEST_CMS_CD_CONTENT_02: &[u8] = &[
        0x15, 0x24, 0x00, 0x01, 0x25, 0x01, 0xf2, 0xff, 0x36, 0x02, 0x05, 0x01, 0x80, 0x05, 0x02,
        0x80, 0x18, 0x25, 0x03, 0x34, 0x12, 0x2c, 0x04, 0x13, 0x5a, 0x49, 0x47, 0x32, 0x30, 0x31,
        0x34, 0x32, 0x5a, 0x42, 0x33, 0x33, 0x30, 0x30, 0x30, 0x32, 0x2d, 0x32, 0x34, 0x24, 0x05,
        0x00, 0x24, 0x06, 0x00, 0x25, 0x07, 0x94, 0x26, 0x24, 0x08, 0x00, 0x25, 0x09, 0xf1, 0xff,
        0x25, 0x0a, 0x00, 0x80, 0x18,
    ];

    const TEST_CMS_SIGNED_MESSAGE_02: &[u8] = &[
        0x30, 0x81, 0xf5, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0,
        0x81, 0xe7, 0x30, 0x81, 0xe4, 0x02, 0x01, 0x03, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60,
        0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x50, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x43, 0x04, 0x41, 0x15, 0x24, 0x00, 0x01, 0x25,
        0x01, 0xf2, 0xff, 0x36, 0x02, 0x05, 0x01, 0x80, 0x05, 0x02, 0x80, 0x18, 0x25, 0x03, 0x34,
        0x12, 0x2c, 0x04, 0x13, 0x5a, 0x49, 0x47, 0x32, 0x30, 0x31, 0x34, 0x32, 0x5a, 0x42, 0x33,
        0x33, 0x30, 0x30, 0x30, 0x32, 0x2d, 0x32, 0x34, 0x24, 0x05, 0x00, 0x24, 0x06, 0x00, 0x25,
        0x07, 0x94, 0x26, 0x24, 0x08, 0x00, 0x25, 0x09, 0xf1, 0xff, 0x25, 0x0a, 0x00, 0x80, 0x18,
        0x31, 0x7e, 0x30, 0x7c, 0x02, 0x01, 0x03, 0x80, 0x14, 0x62, 0xfa, 0x82, 0x33, 0x59, 0xac,
        0xfa, 0xa9, 0x96, 0x3e, 0x1c, 0xfa, 0x14, 0x0a, 0xdd, 0xf5, 0x04, 0xf3, 0x71, 0x60, 0x30,
        0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x0a, 0x06,
        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x04, 0x48, 0x30, 0x46, 0x02, 0x21,
        0x00, 0x92, 0x62, 0x96, 0xf7, 0x57, 0x81, 0x58, 0xbe, 0x7c, 0x45, 0x93, 0x88, 0x33, 0x6c,
        0xa7, 0x38, 0x37, 0x66, 0xc9, 0xee, 0xdd, 0x98, 0x55, 0xcb, 0xda, 0x6f, 0x4c, 0xf6, 0xbd,
        0xf4, 0x32, 0x11, 0x02, 0x21, 0x00, 0xe0, 0xdb, 0xf4, 0xa2, 0xbc, 0xec, 0x4e, 0xa2, 0x74,
        0xba, 0xf0, 0xde, 0xa2, 0x08, 0xb3, 0x36, 0x5c, 0x6e, 0xd5, 0x44, 0x08, 0x6d, 0x10, 0x1a,
        0xfd, 0xaf, 0x07, 0x9a, 0x2c, 0x23, 0xe0, 0xde,
    ];

    // ---- CMS parsing tests ----

    #[test]
    fn test_parse_cms_signed_data_01() {
        let cms = unwrap!(CmsSignedData::parse(TEST_CMS_SIGNED_MESSAGE_01));

        // Verify signer KID is the test key
        assert_eq!(cms.signer_key_id, &cd_keys::TEST_CD_KID);

        // Verify extracted CD content matches raw content
        assert_eq!(cms.cd_content, TEST_CMS_CD_CONTENT_01);

        // Verify signature is 64 bytes (non-zero)
        assert!(cms.signature_raw.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_parse_cms_signed_data_02() {
        let cms = unwrap!(CmsSignedData::parse(TEST_CMS_SIGNED_MESSAGE_02));

        assert_eq!(cms.signer_key_id, &cd_keys::TEST_CD_KID);
        assert_eq!(cms.cd_content, TEST_CMS_CD_CONTENT_02);
    }

    #[test]
    fn test_cms_extract_cd_content() {
        let cms = unwrap!(CmsSignedData::parse(TEST_CMS_SIGNED_MESSAGE_01));
        assert_eq!(cms.cd_content, TEST_CMS_CD_CONTENT_01);
    }

    #[test]
    fn test_cms_extract_key_id() {
        let cms = unwrap!(CmsSignedData::parse(TEST_CMS_SIGNED_MESSAGE_01));
        assert_eq!(cms.signer_key_id, &cd_keys::TEST_CD_KID);
    }

    #[test]
    fn test_parse_cms_invalid_data() {
        // Empty
        assert!(CmsSignedData::parse(&[]).is_err());

        // Random garbage
        assert!(CmsSignedData::parse(&[0x01, 0x02, 0x03]).is_err());

        // Valid SEQUENCE but wrong OID
        assert!(CmsSignedData::parse(&[0x30, 0x06, 0x06, 0x02, 0x55, 0x04, 0x00, 0x00]).is_err());
    }

    // ---- TLV decoding tests ----

    #[test]
    fn test_decode_cd_content_01() {
        let cd = unwrap!(CertificationElements::decode(TEST_CMS_CD_CONTENT_01));
        assert_eq!(cd, expected_cd_01());
    }

    #[test]
    fn test_decode_cd_content_02() {
        let cd = unwrap!(CertificationElements::decode(TEST_CMS_CD_CONTENT_02));
        assert_eq!(cd, expected_cd_02());
    }

    // ---- Signature verification tests ----

    #[test]
    fn test_verify_cd_01_with_test_key_allowed() {
        let crypto = test_only_crypto();
        let cd = unwrap!(CertificationElements::verify(
            &crypto,
            TEST_CMS_SIGNED_MESSAGE_01,
            true,
        ));

        assert_eq!(cd, expected_cd_01());
    }

    #[test]
    fn test_verify_cd_02_with_test_key_allowed() {
        let crypto = test_only_crypto();
        let cd = unwrap!(CertificationElements::verify(
            &crypto,
            TEST_CMS_SIGNED_MESSAGE_02,
            true,
        ));

        assert_eq!(cd, expected_cd_02());
    }

    #[test]
    fn test_verify_cd_test_key_not_allowed() {
        let crypto = test_only_crypto();
        let result = CertificationElements::verify(
            &crypto,
            TEST_CMS_SIGNED_MESSAGE_01,
            false, // test key NOT allowed
        );

        assert_eq!(
            result.map_err(|e| e.code()),
            Err(ErrorCode::CdSigningKeyNotFound)
        );
    }

    // ---- Content validation tests ----

    #[test]
    fn test_validate_cd_success_basic() {
        let cd = unwrap!(CertificationElements::decode(TEST_CMS_CD_CONTENT_01));
        let device_info = DeviceInfoForAttestation {
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            dac_vendor_id: 0xFFF1,
            dac_product_id: 0x8000,
            pai_vendor_id: 0xFFF1,
            pai_product_id: 0, // PAI without PID
            paa_skid: [0u8; KEY_IDENTIFIER_LEN],
        };

        unwrap!(cd.validate(&device_info));
    }

    #[test]
    fn test_validate_cd_wrong_vendor_id() {
        let cd = unwrap!(CertificationElements::decode(TEST_CMS_CD_CONTENT_01));
        let device_info = DeviceInfoForAttestation {
            vendor_id: 0xFFF2, // Wrong: CD has 0xFFF1
            product_id: 0x8000,
            dac_vendor_id: 0xFFF1,
            dac_product_id: 0x8000,
            pai_vendor_id: 0xFFF1,
            pai_product_id: 0,
            paa_skid: [0u8; KEY_IDENTIFIER_LEN],
        };

        assert_eq!(
            cd.validate(&device_info).map_err(|e| e.code()),
            Err(ErrorCode::CdInvalidVendorId)
        );
    }

    #[test]
    fn test_validate_cd_wrong_product_id() {
        let cd = unwrap!(CertificationElements::decode(TEST_CMS_CD_CONTENT_01));
        let device_info = DeviceInfoForAttestation {
            vendor_id: 0xFFF1,
            product_id: 0x9999, // Wrong: not in [0x8000]
            dac_vendor_id: 0xFFF1,
            dac_product_id: 0x8000,
            pai_vendor_id: 0xFFF1,
            pai_product_id: 0,
            paa_skid: [0u8; KEY_IDENTIFIER_LEN],
        };

        assert_eq!(
            cd.validate(&device_info).map_err(|e| e.code()),
            Err(ErrorCode::CdInvalidProductId)
        );
    }

    #[test]
    fn test_validate_cd_wrong_dac_vendor_id() {
        // CD01 has no dac_origin, so DAC VID must match CD vendor_id
        let cd = unwrap!(CertificationElements::decode(TEST_CMS_CD_CONTENT_01));
        let device_info = DeviceInfoForAttestation {
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            dac_vendor_id: 0xFFF2, // Wrong: must match CD vendor_id (0xFFF1)
            dac_product_id: 0x8000,
            pai_vendor_id: 0xFFF1,
            pai_product_id: 0,
            paa_skid: [0u8; KEY_IDENTIFIER_LEN],
        };

        assert_eq!(
            cd.validate(&device_info).map_err(|e| e.code()),
            Err(ErrorCode::CdInvalidVendorId)
        );
    }

    #[test]
    fn test_validate_cd_with_dac_origin() {
        // CD02 has dac_origin_vid=0xFFF1, dac_origin_pid=0x8000
        let cd = unwrap!(CertificationElements::decode(TEST_CMS_CD_CONTENT_02));
        let device_info = DeviceInfoForAttestation {
            vendor_id: 0xFFF2,
            product_id: 0x8001,     // Must be in [0x8001, 0x8002]
            dac_vendor_id: 0xFFF1,  // Must match dac_origin_vendor_id
            dac_product_id: 0x8000, // Must match dac_origin_product_id
            pai_vendor_id: 0xFFF1,  // Must match dac_origin_vendor_id
            pai_product_id: 0,
            paa_skid: [0u8; KEY_IDENTIFIER_LEN],
        };

        unwrap!(cd.validate(&device_info));
    }

    #[test]
    fn test_validate_cd_dac_origin_wrong_dac_vid() {
        let cd = unwrap!(CertificationElements::decode(TEST_CMS_CD_CONTENT_02));
        let device_info = DeviceInfoForAttestation {
            vendor_id: 0xFFF2,
            product_id: 0x8001,
            dac_vendor_id: 0xFFF2, // Wrong: must match dac_origin_vid (0xFFF1)
            dac_product_id: 0x8000,
            pai_vendor_id: 0xFFF1,
            pai_product_id: 0,
            paa_skid: [0u8; KEY_IDENTIFIER_LEN],
        };

        assert_eq!(
            cd.validate(&device_info).map_err(|e| e.code()),
            Err(ErrorCode::CdInvalidVendorId)
        );
    }

    #[test]
    fn test_validate_cd_wrong_format_version() {
        // Manually construct a CD with format_version = 2
        let mut cd = unwrap!(CertificationElements::decode(TEST_CMS_CD_CONTENT_01));
        cd.format_version = 2;
        let device_info = DeviceInfoForAttestation {
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            dac_vendor_id: 0xFFF1,
            dac_product_id: 0x8000,
            pai_vendor_id: 0xFFF1,
            pai_product_id: 0,
            paa_skid: [0u8; KEY_IDENTIFIER_LEN],
        };

        assert_eq!(
            cd.validate(&device_info).map_err(|e| e.code()),
            Err(ErrorCode::CdInvalidFormat)
        );
    }

    // ---- CertificationType tests ----

    #[test]
    fn test_certification_type_from_u8() {
        assert_eq!(
            unwrap!(CertificationType::from_u8(0)),
            CertificationType::DevelopmentAndTest
        );
        assert_eq!(
            unwrap!(CertificationType::from_u8(1)),
            CertificationType::Provisional
        );
        assert_eq!(
            unwrap!(CertificationType::from_u8(2)),
            CertificationType::Official
        );
        assert!(CertificationType::from_u8(3).is_err());
        assert!(CertificationType::from_u8(255).is_err());
    }
}
