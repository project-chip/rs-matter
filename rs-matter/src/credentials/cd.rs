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

use crate::cert::x509::DerReader;
use crate::credentials::cd_keys::{self, KEY_IDENTIFIER_LEN};
use crate::crypto::{CanonPkcPublicKeyRef, CanonPkcSignatureRef, Crypto, PublicKey};
use crate::error::{Error, ErrorCode};
use crate::tlv::TLVElement;

/// ASN.1 DER tag constants
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;

/// Context specific tags
const TAG_CONTEXT_0: u8 = 0xA0;
const TAG_CONTEXT_0_PRIM: u8 = 0x80; // SubjectKeyIdentifier in SignerInfo

/// https://www.rfc-editor.org/rfc/rfc5652#section-12.1
/// OID: 1.2.840.113549.1.7.2 (id-signedData)
const OID_PKCS7_SIGNED_DATA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
/// OID: 1.2.840.113549.1.7.1 (id-data)
const OID_PKCS7_DATA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];

/// https://www.rfc-editor.org/rfc/rfc5758.html#section-2
/// OID: 2.16.840.1.101.3.4.2.1 (id-sha256)
const OID_SHA256: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// OID: 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
const OID_ECDSA_WITH_SHA256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

/// P-256 field element length in bytes (ECDSA signature r and s values).
const P256_FE_LEN: usize = 32;

/// Raw ECDSA signature length: r (32 bytes) || s (32 bytes).
const RAW_SIGNATURE_LEN: usize = P256_FE_LEN * 2;

/// Parsed contents of a CMS SignedData envelope
pub struct CmsSignedData<'a> {
    /// SubjectKeyIdentifier from the SignerInfo (identifies the signing key)
    pub signer_key_id: &'a [u8],
    /// Raw TLV CD payload (the encapsulated content)
    pub cd_content: &'a [u8],
    /// ECDSA signature in raw (r || s) format, 64 bytes
    pub signature_raw: [u8; RAW_SIGNATURE_LEN],
}

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
pub fn parse_cms_signed_data(cms_message: &[u8]) -> Result<CmsSignedData<'_>, Error> {
    let reader = DerReader::new(cms_message);

    // ContentInfo: SEQUENCE
    let (tag, content_info, _rest) = reader.enter()?;
    if tag != TAG_SEQUENCE {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // ContentInfo.contentType: OID id-signedData (1.2.840.113549.1.7.2)
    let (tag, oid_value, after_oid) = content_info.read_tlv()?;
    if tag != TAG_OID || oid_value != OID_PKCS7_SIGNED_DATA {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // ContentInfo.content: [0] EXPLICIT SignedData
    let context0 = DerReader::new(after_oid);
    let (tag, signed_data_inner, _rest) = context0.enter()?;
    if tag != TAG_CONTEXT_0 {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // SignedData: SEQUENCE
    let (tag, signed_data, _rest) = signed_data_inner.enter()?;
    if tag != TAG_SEQUENCE {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // SignedData.version: INTEGER v3(3)
    let (tag, version_bytes, after_version) = signed_data.read_tlv()?;
    if tag != TAG_INTEGER || version_bytes.len() != 1 || version_bytes[0] != 3 {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // SignedData.digestAlgorithms: SET { OBJECT IDENTIFIER sha256 }
    let digest_algos = DerReader::new(after_version);
    let (tag, _digest_algos_value, after_digest_algos) = digest_algos.read_tlv()?;
    if tag != TAG_SET {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // SignedData.encapContentInfo: EncapsulatedContentInfo
    let encap = DerReader::new(after_digest_algos);
    let (tag, encap_inner, after_encap) = encap.enter()?;
    if tag != TAG_SEQUENCE {
        return Err(ErrorCode::CdInvalidFormat.into());
    }
    let cd_content = decode_encapsulated_content(encap_inner)?;

    // SignedData.signerInfos: SET { SignerInfo }
    let signer_infos = DerReader::new(after_encap);
    let (tag, signer_infos_inner, _rest) = signer_infos.enter()?;
    if tag != TAG_SET {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    let (signer_key_id, signature_raw) = decode_signer_info(signer_infos_inner)?;

    Ok(CmsSignedData {
        signer_key_id,
        cd_content,
        signature_raw,
    })
}

/// Extract just the CD content from a CMS message without signature verification.
pub fn cms_extract_cd_content(cms_message: &[u8]) -> Result<&[u8], Error> {
    let parsed = parse_cms_signed_data(cms_message)?;
    Ok(parsed.cd_content)
}

/// Extract just the signer Key ID from a CMS message.
pub fn cms_extract_key_id(cms_message: &[u8]) -> Result<&[u8], Error> {
    let parsed = parse_cms_signed_data(cms_message)?;
    Ok(parsed.signer_key_id)
}

/// Decode the EncapsulatedContentInfo to extract the OCTET STRING payload.
///
/// Structure:
/// ```text
/// EncapsulatedContentInfo ::= SEQUENCE {
///   eContentType OBJECT IDENTIFIER pkcs7-data (1.2.840.113549.1.7.1),
///   eContent [0] EXPLICIT OCTET STRING
/// }
/// ```
fn decode_encapsulated_content<'a>(reader: DerReader<'a>) -> Result<&'a [u8], Error> {
    // EncapsulatedContentInfo.eContentType: OID pkcs7-data (1.2.840.113549.1.7.1)
    let (tag, oid_value, after_oid) = reader.read_tlv()?;
    if tag != TAG_OID || oid_value != OID_PKCS7_DATA {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // EncapsulatedContentInfo.eContent: [0] EXPLICIT OCTET STRING
    let context0 = DerReader::new(after_oid);
    let (tag, context0_inner, _rest) = context0.enter()?;
    if tag != TAG_CONTEXT_0 {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    let (tag, content, _rest) = context0_inner.read_tlv()?;
    if tag != TAG_OCTET_STRING {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    Ok(content)
}

/// Decode the SignerInfo, extracting the Key ID and converting
/// the DER-encoded ECDSA signature to raw format.
///
/// Structure:
/// ```text
/// SignerInfo ::= SEQUENCE {
///   version INTEGER (v3(3)),
///   subjectKeyIdentifier [0] IMPLICIT OCTET STRING,
///   digestAlgorithm OBJECT IDENTIFIER sha256 (2.16.840.1.101.3.4.2.1),
///   signatureAlgorithm OBJECT IDENTIFIER ecdsa-with-SHA256 (1.2.840.10045.4.3.2),
///   signature OCTET STRING
/// }
/// ```
fn decode_signer_info<'a>(
    reader: DerReader<'a>,
) -> Result<(&'a [u8], [u8; RAW_SIGNATURE_LEN]), Error> {
    // SignerInfo: SEQUENCE
    let (tag, signer_info, _rest) = reader.enter()?;
    if tag != TAG_SEQUENCE {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // SignerInfo.version: INTEGER v3(3)
    let (tag, version_bytes, after_version) = signer_info.read_tlv()?;
    if tag != TAG_INTEGER || version_bytes.len() != 1 || version_bytes[0] != 3 {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // SignerInfo.subjectKeyIdentifier: [0] IMPLICIT OCTET STRING
    let kid_reader = DerReader::new(after_version);
    let (tag, kid, after_kid) = kid_reader.read_tlv()?;
    if tag != TAG_CONTEXT_0_PRIM {
        return Err(ErrorCode::CdInvalidFormat.into());
    }
    if kid.len() != KEY_IDENTIFIER_LEN {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // SignerInfo.digestAlgorithm: OBJECT IDENTIFIER sha256
    let digest_algo = DerReader::new(after_kid);
    let (tag, digest_algo_inner, after_digest) = digest_algo.enter()?;
    if tag != TAG_SEQUENCE {
        return Err(ErrorCode::CdInvalidFormat.into());
    }
    let (tag, oid_value, _rest) = digest_algo_inner.read_tlv()?;
    if tag != TAG_OID || oid_value != OID_SHA256 {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // SignerInfo.signatureAlgorithm: OBJECT IDENTIFIER ecdsa-with-SHA256
    let sig_algo = DerReader::new(after_digest);
    let (tag, sig_algo_inner, after_sig_algo) = sig_algo.enter()?;
    if tag != TAG_SEQUENCE {
        return Err(ErrorCode::CdInvalidFormat.into());
    }
    let (tag, oid_value, _rest) = sig_algo_inner.read_tlv()?;
    if tag != TAG_OID || oid_value != OID_ECDSA_WITH_SHA256 {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // SignerInfo.signature: OCTET STRING (DER-encoded ECDSA signature)
    let sig_reader = DerReader::new(after_sig_algo);
    let (tag, sig_der, _rest) = sig_reader.read_tlv()?;
    if tag != TAG_OCTET_STRING {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    let signature_raw = ecdsa_der_to_raw(sig_der)?;

    Ok((kid, signature_raw))
}

/// Convert a DER-encoded ECDSA signature to raw (r || s) format.
///
/// DER format: `SEQUENCE { INTEGER r, INTEGER s }`
/// Raw format: `r[32] || s[32]` (each padded/trimmed to exactly 32 bytes)
///
/// DER INTEGERs may have a leading 0x00 byte for positive representation,
/// which must be stripped. They may also be shorter than 32 bytes.
fn ecdsa_der_to_raw(der: &[u8]) -> Result<[u8; RAW_SIGNATURE_LEN], Error> {
    let reader = DerReader::new(der);

    // SEQUENCE
    let (tag, seq_inner, _rest) = reader.enter()?;
    if tag != TAG_SEQUENCE {
        return Err(ErrorCode::CdInvalidSignature.into());
    }

    let inner = seq_inner;

    // INTEGER r
    let (tag, r_bytes, after_r) = inner.read_tlv()?;
    if tag != TAG_INTEGER {
        return Err(ErrorCode::CdInvalidSignature.into());
    }

    // INTEGER s
    let s_reader = DerReader::new(after_r);
    let (tag, s_bytes, _rest) = s_reader.read_tlv()?;
    if tag != TAG_INTEGER {
        return Err(ErrorCode::CdInvalidSignature.into());
    }

    let mut raw = [0u8; RAW_SIGNATURE_LEN];
    copy_integer_to_fixed(&mut raw[..P256_FE_LEN], r_bytes)?;
    copy_integer_to_fixed(&mut raw[P256_FE_LEN..], s_bytes)?;

    Ok(raw)
}

/// Copy a DER INTEGER value into a fixed-length buffer, right-aligned.
///
/// Strips leading zero bytes (DER positive sign padding) and pads with
/// zeros on the left to fill the target buffer.
fn copy_integer_to_fixed(target: &mut [u8], integer: &[u8]) -> Result<(), Error> {
    // Strip leading zeros
    let mut src = integer;
    while src.len() > 1 && src[0] == 0 {
        src = &src[1..];
    }

    if src.len() > target.len() {
        return Err(ErrorCode::CdInvalidSignature.into());
    }

    // Right-align: pad with zeros on the left
    let offset = target.len() - src.len();
    target[..offset].fill(0);
    target[offset..].copy_from_slice(src);

    Ok(())
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

/// Decode a TLV-encoded CD payload into [`CertificationElements`].
///
/// Validates the TLV structure, field types, and constraints per the Matter spec:
/// - Tags 0-8 are mandatory and must appear in order.
/// - Tags 9-10 (DAC origin) are optional but must appear together.
/// - Tag 11 (authorized PAA list) is optional.
/// - Product IDs array must have 1..=100 entries.
/// - Certificate ID must be exactly 19 bytes.
/// - Authorized PAA entries must each be exactly 20 bytes.
#[allow(clippy::field_reassign_with_default)]
pub fn decode_certification_elements(cd_content: &[u8]) -> Result<CertificationElements, Error> {
    let elem = TLVElement::new(cd_content);
    let structure = elem.structure()?;

    let mut cd = CertificationElements::default();

    // Tag 0: format_version (mandatory)
    cd.format_version = structure.find_ctx(CD_TAG_FORMAT_VERSION)?.u16()?;

    // Tag 1: vendor_id (mandatory)
    cd.vendor_id = structure.find_ctx(CD_TAG_VENDOR_ID)?.u16()?;

    // Tag 2: product_id_array (mandatory, 1..=100 entries)
    let pid_array = structure.find_ctx(CD_TAG_PRODUCT_ID_ARRAY)?;
    let pid_seq = pid_array.array()?;
    let mut count = 0usize;
    for pid_elem in pid_seq.iter() {
        let pid_elem: TLVElement<'_> = pid_elem?;
        if count >= MAX_PRODUCT_IDS {
            return Err(ErrorCode::CdInvalidFormat.into());
        }
        cd.product_ids[count] = pid_elem.u16()?;
        count += 1;
    }
    if count == 0 {
        return Err(ErrorCode::CdInvalidFormat.into());
    }
    cd.product_ids_count = count;

    // Tag 3: device_type_id (mandatory)
    cd.device_type_id = structure.find_ctx(CD_TAG_DEVICE_TYPE_ID)?.u32()?;

    // Tag 4: certificate_id (mandatory, exactly 19 bytes UTF-8 string)
    let cert_id_str = structure.find_ctx(CD_TAG_CERTIFICATE_ID)?.utf8()?;
    if cert_id_str.len() != CERTIFICATE_ID_LEN {
        return Err(ErrorCode::CdInvalidFormat.into());
    }
    cd.certificate_id.copy_from_slice(cert_id_str.as_bytes());

    // Tag 5: security_level (mandatory)
    cd.security_level = structure.find_ctx(CD_TAG_SECURITY_LEVEL)?.u8()?;

    // Tag 6: security_information (mandatory)
    cd.security_information = structure.find_ctx(CD_TAG_SECURITY_INFORMATION)?.u16()?;

    // Tag 7: version_number (mandatory)
    cd.version_number = structure.find_ctx(CD_TAG_VERSION_NUMBER)?.u16()?;

    // Tag 8: certification_type (mandatory)
    let cert_type_raw = structure.find_ctx(CD_TAG_CERTIFICATION_TYPE)?.u8()?;
    cd.certification_type = CertificationType::from_u8(cert_type_raw)?;

    // Tag 9 & 10: dac_origin_vendor_id and dac_origin_product_id (optional, must appear together)
    let vid_elem = structure.find_ctx(CD_TAG_DAC_ORIGIN_VENDOR_ID)?;
    let pid_elem = structure.find_ctx(CD_TAG_DAC_ORIGIN_PRODUCT_ID)?;
    // Both must be present or both must be absent
    if vid_elem.is_empty() != pid_elem.is_empty() {
        return Err(ErrorCode::CdInvalidFormat.into());
    }
    if !vid_elem.is_empty() {
        cd.dac_origin_vendor_id = vid_elem.u16()?;
        cd.dac_origin_product_id = pid_elem.u16()?;
        cd.dac_origin_vid_pid_present = true;
    }

    // Tag 11: authorized_paa_list (optional)
    let paa_elem = structure.find_ctx(CD_TAG_AUTHORIZED_PAA_LIST)?;
    if !paa_elem.is_empty() {
        let paa_seq = paa_elem.array()?;
        let mut paa_count = 0usize;
        for paa_entry in paa_seq.iter() {
            let paa_entry: TLVElement<'_> = paa_entry?;
            if paa_count >= MAX_AUTHORIZED_PAA_LIST {
                return Err(ErrorCode::CdInvalidFormat.into());
            }
            let paa_bytes = paa_entry.str()?;
            if paa_bytes.len() != KEY_IDENTIFIER_LEN {
                return Err(ErrorCode::CdInvalidFormat.into());
            }
            cd.authorized_paa_list[paa_count].copy_from_slice(paa_bytes);
            paa_count += 1;
        }
        cd.authorized_paa_list_count = paa_count;
    }

    Ok(cd)
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
pub fn verify_certification_declaration<C: Crypto>(
    crypto: &C,
    cms_message: &[u8],
    allow_test_cd_signing_key: bool,
) -> Result<CertificationElements, Error> {
    // Parse CMS envelope
    let cms = parse_cms_signed_data(cms_message)?;

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
    let cd = decode_certification_elements(cms.cd_content)?;

    // Post-signature test key policy enforcement
    // Test key may only sign DevelopmentAndTest (and optionally Provisional) CDs
    if is_test_key && cd.certification_type == CertificationType::Official {
        return Err(ErrorCode::CdSigningKeyNotFound.into());
    }

    Ok(cd)
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
pub fn validate_cd(
    cd: &CertificationElements,
    device_info: &DeviceInfoForAttestation,
) -> Result<(), Error> {
    // Rule 1: format_version must be 1
    if cd.format_version != 1 {
        return Err(ErrorCode::CdInvalidFormat.into());
    }

    // Rule 2: certification_type is already validated by decode

    // Rule 3: CD vendor_id must match device's BasicInformation VendorID
    if cd.vendor_id != device_info.vendor_id {
        return Err(ErrorCode::CdInvalidVendorId.into());
    }

    // Rule 4: Device's ProductID must be in the CD's product_id_array
    if !product_id_in_list(device_info.product_id, cd) {
        return Err(ErrorCode::CdInvalidProductId.into());
    }

    // Rules 5-6: VID/PID matching depends on dac_origin_vid_pid_present
    if cd.dac_origin_vid_pid_present {
        // Rule 5: dacOriginVIDandPID present
        if device_info.dac_vendor_id != cd.dac_origin_vendor_id {
            return Err(ErrorCode::CdInvalidVendorId.into());
        }
        if device_info.pai_vendor_id != cd.dac_origin_vendor_id {
            return Err(ErrorCode::CdInvalidVendorId.into());
        }
        if device_info.dac_product_id != cd.dac_origin_product_id {
            return Err(ErrorCode::CdInvalidProductId.into());
        }
        if device_info.pai_product_id != 0 && device_info.pai_product_id != cd.dac_origin_product_id
        {
            return Err(ErrorCode::CdInvalidProductId.into());
        }
    } else {
        // Rule 6: dacOriginVIDandPID NOT present
        if device_info.dac_vendor_id != cd.vendor_id {
            return Err(ErrorCode::CdInvalidVendorId.into());
        }
        if device_info.pai_vendor_id != cd.vendor_id {
            return Err(ErrorCode::CdInvalidVendorId.into());
        }
        if !product_id_in_list(device_info.dac_product_id, cd) {
            return Err(ErrorCode::CdInvalidProductId.into());
        }
        if device_info.pai_product_id != 0 && !product_id_in_list(device_info.pai_product_id, cd) {
            return Err(ErrorCode::CdInvalidProductId.into());
        }
    }

    // Rule 7: Authorized PAA list check
    if cd.authorized_paa_list_count > 0 {
        let mut found = false;
        for i in 0..cd.authorized_paa_list_count {
            if cd.authorized_paa_list[i] == device_info.paa_skid {
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
        let cms = unwrap!(parse_cms_signed_data(TEST_CMS_SIGNED_MESSAGE_01));

        // Verify signer KID is the test key
        assert_eq!(cms.signer_key_id, &cd_keys::TEST_CD_KID);

        // Verify extracted CD content matches raw content
        assert_eq!(cms.cd_content, TEST_CMS_CD_CONTENT_01);

        // Verify signature is 64 bytes (non-zero)
        assert!(cms.signature_raw.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_parse_cms_signed_data_02() {
        let cms = unwrap!(parse_cms_signed_data(TEST_CMS_SIGNED_MESSAGE_02));

        assert_eq!(cms.signer_key_id, &cd_keys::TEST_CD_KID);
        assert_eq!(cms.cd_content, TEST_CMS_CD_CONTENT_02);
    }

    #[test]
    fn test_cms_extract_cd_content() {
        let content = unwrap!(cms_extract_cd_content(TEST_CMS_SIGNED_MESSAGE_01));
        assert_eq!(content, TEST_CMS_CD_CONTENT_01);
    }

    #[test]
    fn test_cms_extract_key_id() {
        let kid = unwrap!(cms_extract_key_id(TEST_CMS_SIGNED_MESSAGE_01));
        assert_eq!(kid, &cd_keys::TEST_CD_KID);
    }

    #[test]
    fn test_parse_cms_invalid_data() {
        // Empty
        assert!(parse_cms_signed_data(&[]).is_err());

        // Random garbage
        assert!(parse_cms_signed_data(&[0x01, 0x02, 0x03]).is_err());

        // Valid SEQUENCE but wrong OID
        assert!(parse_cms_signed_data(&[0x30, 0x06, 0x06, 0x02, 0x55, 0x04, 0x00, 0x00]).is_err());
    }

    // ---- TLV decoding tests ----

    #[test]
    fn test_decode_cd_content_01() {
        let cd = unwrap!(decode_certification_elements(TEST_CMS_CD_CONTENT_01));
        assert_eq!(cd, expected_cd_01());
    }

    #[test]
    fn test_decode_cd_content_02() {
        let cd = unwrap!(decode_certification_elements(TEST_CMS_CD_CONTENT_02));
        assert_eq!(cd, expected_cd_02());
    }

    // ---- Signature verification tests ----

    #[test]
    fn test_verify_cd_01_with_test_key_allowed() {
        let crypto = test_only_crypto();
        let cd = unwrap!(verify_certification_declaration(
            &crypto,
            TEST_CMS_SIGNED_MESSAGE_01,
            true,
        ));

        assert_eq!(cd, expected_cd_01());
    }

    #[test]
    fn test_verify_cd_02_with_test_key_allowed() {
        let crypto = test_only_crypto();
        let cd = unwrap!(verify_certification_declaration(
            &crypto,
            TEST_CMS_SIGNED_MESSAGE_02,
            true,
        ));

        assert_eq!(cd, expected_cd_02());
    }

    #[test]
    fn test_verify_cd_test_key_not_allowed() {
        let crypto = test_only_crypto();
        let result = verify_certification_declaration(
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
        let cd = unwrap!(decode_certification_elements(TEST_CMS_CD_CONTENT_01));
        let device_info = DeviceInfoForAttestation {
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            dac_vendor_id: 0xFFF1,
            dac_product_id: 0x8000,
            pai_vendor_id: 0xFFF1,
            pai_product_id: 0, // PAI without PID
            paa_skid: [0u8; KEY_IDENTIFIER_LEN],
        };

        unwrap!(validate_cd(&cd, &device_info));
    }

    #[test]
    fn test_validate_cd_wrong_vendor_id() {
        let cd = unwrap!(decode_certification_elements(TEST_CMS_CD_CONTENT_01));
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
            validate_cd(&cd, &device_info).map_err(|e| e.code()),
            Err(ErrorCode::CdInvalidVendorId)
        );
    }

    #[test]
    fn test_validate_cd_wrong_product_id() {
        let cd = unwrap!(decode_certification_elements(TEST_CMS_CD_CONTENT_01));
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
            validate_cd(&cd, &device_info).map_err(|e| e.code()),
            Err(ErrorCode::CdInvalidProductId)
        );
    }

    #[test]
    fn test_validate_cd_wrong_dac_vendor_id() {
        // CD01 has no dac_origin, so DAC VID must match CD vendor_id
        let cd = unwrap!(decode_certification_elements(TEST_CMS_CD_CONTENT_01));
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
            validate_cd(&cd, &device_info).map_err(|e| e.code()),
            Err(ErrorCode::CdInvalidVendorId)
        );
    }

    #[test]
    fn test_validate_cd_with_dac_origin() {
        // CD02 has dac_origin_vid=0xFFF1, dac_origin_pid=0x8000
        let cd = unwrap!(decode_certification_elements(TEST_CMS_CD_CONTENT_02));
        let device_info = DeviceInfoForAttestation {
            vendor_id: 0xFFF2,
            product_id: 0x8001,     // Must be in [0x8001, 0x8002]
            dac_vendor_id: 0xFFF1,  // Must match dac_origin_vendor_id
            dac_product_id: 0x8000, // Must match dac_origin_product_id
            pai_vendor_id: 0xFFF1,  // Must match dac_origin_vendor_id
            pai_product_id: 0,
            paa_skid: [0u8; KEY_IDENTIFIER_LEN],
        };

        unwrap!(validate_cd(&cd, &device_info));
    }

    #[test]
    fn test_validate_cd_dac_origin_wrong_dac_vid() {
        let cd = unwrap!(decode_certification_elements(TEST_CMS_CD_CONTENT_02));
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
            validate_cd(&cd, &device_info).map_err(|e| e.code()),
            Err(ErrorCode::CdInvalidVendorId)
        );
    }

    #[test]
    fn test_validate_cd_wrong_format_version() {
        // Manually construct a CD with format_version = 2
        let mut cd = unwrap!(decode_certification_elements(TEST_CMS_CD_CONTENT_01));
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
            validate_cd(&cd, &device_info).map_err(|e| e.code()),
            Err(ErrorCode::CdInvalidFormat)
        );
    }

    // ---- DER signature conversion tests ----

    #[test]
    fn test_ecdsa_der_to_raw_basic() {
        // Simple case: both r and s are exactly 32 bytes (no leading zero)
        let mut der = [0u8; 70];
        let r = [0x01u8; 32];
        let s = [0x02u8; 32];

        // Build DER: SEQUENCE { INTEGER r, INTEGER s }
        // Each INTEGER: 0x02, len, data
        // SEQUENCE length = 2 + 32 + 2 + 32 = 68
        der[0] = 0x30; // SEQUENCE
        der[1] = 68;
        der[2] = 0x02; // INTEGER r
        der[3] = 32;
        der[4..36].copy_from_slice(&r);
        der[36] = 0x02; // INTEGER s
        der[37] = 32;
        der[38..70].copy_from_slice(&s);

        let raw = unwrap!(ecdsa_der_to_raw(&der[..70]));
        assert_eq!(&raw[..32], &r);
        assert_eq!(&raw[32..], &s);
    }

    #[test]
    fn test_ecdsa_der_to_raw_with_leading_zeros() {
        // Case: r has a leading 0x00 (33 bytes DER -> 32 bytes raw)
        let mut der = [0u8; 72];
        let r = [0x80u8; 32]; // High bit set, so DER prepends 0x00
        let s = [0x01u8; 32];

        der[0] = 0x30; // SEQUENCE
        der[1] = 69; // 2+32+1 + 2+32 = 69 = 70
        der[2] = 0x02; // INTEGER r
        der[3] = 33;
        der[4] = 0x00; // leading zero
        der[5..37].copy_from_slice(&r);
        der[37] = 0x02; // INTEGER s
        der[38] = 32;
        der[39..71].copy_from_slice(&s);

        let raw = unwrap!(ecdsa_der_to_raw(&der[..71]));
        assert_eq!(&raw[..32], &r);
        assert_eq!(&raw[32..], &s);
    }

    #[test]
    fn test_ecdsa_der_to_raw_short_integer() {
        // Case: s is short (e.g., 31 bytes, needs left-padding with zero)
        let mut der = [0u8; 70];
        let r = [0x42u8; 32];
        let s_short = [0x05u8; 31]; // 31 bytes

        der[0] = 0x30;
        der[1] = 67; // 2+32 + 2+31
        der[2] = 0x02;
        der[3] = 32;
        der[4..36].copy_from_slice(&r);
        der[36] = 0x02;
        der[37] = 31;
        der[38..69].copy_from_slice(&s_short);

        let raw = unwrap!(ecdsa_der_to_raw(&der[..69]));
        assert_eq!(&raw[..32], &r);
        assert_eq!(raw[32], 0x00); // left-padded zero
        assert_eq!(&raw[33..], &s_short);
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
