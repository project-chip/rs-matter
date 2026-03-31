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

//! Certificate builder for creating Matter TLV-encoded certificates.
//!
//! This module provides builders for creating Node Operational Certificates (NOC),
//! Intermediate CA Certificates (ICAC), and Root CA Certificates (RCAC) in Matter
//! TLV format. (Matter Specification 6.5 "Operational Certificate Encoding")

use crate::cert::CertRef;
use crate::credentials::trust_store::{compute_key_id, KeyId};
use crate::crypto::{
    CanonPkcSignature, Crypto, CryptoSensitive, PublicKey, PKC_CANON_PUBLIC_KEY_LEN,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVElement, TLVTag, TLVWrite};
use crate::utils::storage::WriteBuf;

use super::{x509::key_usage_tlv, CertTag, DNTag};

/// Certificate type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertType {
    /// Root CA Certificate (self-signed, is_ca=true, path_len=1)
    Rcac,
    /// Intermediate CA Certificate (signed by RCAC, is_ca=true, path_len=0)
    Icac,
    /// Node Operational Certificate (end entity, is_ca=false)
    Noc,
}

/// Internal shared certificate builder implementation.
///
/// Contains all the common logic for building Noc, Icac, and Rcac certificates.
struct CertBuilderCore<'a> {
    buf: &'a mut [u8],
}

pub struct IssuerDN {
    pub(crate) ca_id: Option<u64>,
    pub(crate) fabric_id: Option<u64>,
    pub(crate) is_rcac: bool,
}

#[derive(Clone, Copy)]
pub struct SubjectDN<'a> {
    pub(crate) node_id: Option<u64>,
    pub(crate) fabric_id: Option<u64>,
    pub(crate) cat_ids: &'a [u32],
    pub(crate) ca_id: Option<u64>,
}

#[derive(Clone, Copy)]
pub struct Validity {
    pub(crate) not_before: u32,
    pub(crate) not_after: u32,
}

impl<'a> CertBuilderCore<'a> {
    /// Create a new certificate builder core with the given buffer.
    const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf }
    }

    /// Build a certificate with the given parameters.
    ///
    /// Internal for specific certificate builders.
    #[allow(clippy::too_many_arguments)]
    fn build_cert<C: Crypto>(
        &mut self,
        crypto: &C,
        cert_type: CertType,
        serial_number: &[u8],
        validity: Validity,
        subject_pubkey: &C::PublicKey<'_>,
        signing_key: &C::SecretKey<'_>,
        issuer_pubkey: Option<&C::PublicKey<'_>>,
        subject: SubjectDN,
        issuer: IssuerDN,
    ) -> Result<usize, Error> {
        // Validate serial number
        Self::validate_serial_number(serial_number)?;

        // Convert public keys to canonical byte representation
        let mut subject_pubkey_bytes = CryptoSensitive::<PKC_CANON_PUBLIC_KEY_LEN>::new();
        subject_pubkey.write_canon(&mut subject_pubkey_bytes)?;
        let subject_key_id = compute_key_id(crypto, subject_pubkey_bytes.access())?;

        let authority_key_id = if let Some(issuer_pk) = issuer_pubkey {
            let mut bytes = CryptoSensitive::<PKC_CANON_PUBLIC_KEY_LEN>::new();
            issuer_pk.write_canon(&mut bytes)?;
            compute_key_id(crypto, bytes.access())?
        } else {
            // Self-signed: AKID = SKID
            subject_key_id
        };

        // Build the TBS (To-Be-Signed) certificate
        let tbs_len = self.write_tbs_certificate(
            serial_number,
            validity,
            subject_pubkey_bytes.access(),
            &subject_key_id,
            &authority_key_id,
            cert_type,
            subject,
            issuer,
        )?;

        // Convert TBS to ASN1 format for signing
        // According to the Matter Spec 6.5.2. "Matter certificate", the signature is over the
        // "corresponding X.509 certificate, not a signature of the preceding Matter TLV data."
        let (tlv_buf, asn1_buf) = self.buf.split_at_mut(tbs_len);
        let tbs_cert_ref = CertRef::new(TLVElement::new(tlv_buf));
        let asn1_len = tbs_cert_ref.as_asn1(asn1_buf)?;

        // Sign the ASN1-encoded TBS certificate
        let signature = Self::sign_tbs::<C>(&asn1_buf[..asn1_len], signing_key)?;

        // Append signature to complete the certificate
        self.append_signature(&signature, tbs_len)
    }

    /// Write the TBS (To-Be-Signed) certificate structure.
    ///
    /// This creates the certificate without the signature.
    #[allow(clippy::too_many_arguments)]
    fn write_tbs_certificate(
        &mut self,
        serial_number: &[u8],
        validity: Validity,
        pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        subject_key_id: &KeyId,
        authority_key_id: &KeyId,
        cert_type: CertType,
        subject: SubjectDN,
        issuer: IssuerDN,
    ) -> Result<usize, Error> {
        let mut tw = WriteBuf::new(self.buf);

        tw.start_struct(&TLVTag::Anonymous)?;

        // 1. Serial Number
        tw.str(&TLVTag::Context(CertTag::SerialNum as _), serial_number)?;

        // 2. Signature Algorithm (1 = ECDSA-SHA256)
        tw.u8(&TLVTag::Context(CertTag::SignAlgo as _), 1)?;

        // 3. Issuer
        tw.start_list(&TLVTag::Context(CertTag::Issuer as _))?;
        match cert_type {
            CertType::Rcac => {
                // Self-signed: issuer = subject
                if let Some(id) = subject.ca_id {
                    tw.u64(&TLVTag::Context(DNTag::RootCaId as u8), id)?;
                }
                if let Some(fid) = subject.fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?; // Fabric ID
                }
            }
            CertType::Icac | CertType::Noc => {
                // Use provided issuer information
                if let Some(id) = issuer.ca_id {
                    let tag = if issuer.is_rcac {
                        DNTag::RootCaId as u8
                    } else {
                        DNTag::IcaId as u8
                    };
                    tw.u64(&TLVTag::Context(tag), id)?;
                }
                if let Some(fid) = issuer.fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?;
                }
            }
        }
        tw.end_container()?;

        // 4. Not Before
        tw.u32(
            &TLVTag::Context(CertTag::NotBefore as u8),
            validity.not_before,
        )?;

        // 5. Not After (0 = no expiry)
        tw.u32(
            &TLVTag::Context(CertTag::NotAfter as u8),
            validity.not_after,
        )?;

        // 6. Subject
        tw.start_list(&TLVTag::Context(CertTag::Subject as u8))?;
        match cert_type {
            CertType::Noc => {
                // NOC Subject: NodeId, FabricId, optional CAT IDs
                if let Some(nid) = subject.node_id {
                    tw.u64(&TLVTag::Context(DNTag::NodeId as u8), nid)?;
                }
                if let Some(fid) = subject.fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?
                }
                for cat_id in subject.cat_ids {
                    tw.u64(&TLVTag::Context(DNTag::NocCat as u8), *cat_id as u64)?;
                }
            }
            CertType::Icac => {
                // ICAC Subject: ICAC ID, FabricId
                if let Some(id) = subject.ca_id {
                    tw.u64(&TLVTag::Context(DNTag::IcaId as u8), id)?;
                }
                if let Some(fid) = subject.fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?;
                }
            }
            CertType::Rcac => {
                // RCAC Subject: RCAC ID, FabricId
                if let Some(id) = subject.ca_id {
                    tw.u64(&TLVTag::Context(DNTag::RootCaId as u8), id)?;
                }
                if let Some(fid) = subject.fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?;
                }
            }
        }
        tw.end_container()?;

        // 7. Public Key Algorithm (1 = EC Public Key)
        tw.u8(&TLVTag::Context(CertTag::PubKeyAlgo as u8), 1)?;

        // 8. EC Curve ID (1 = prime256v1)
        tw.u8(&TLVTag::Context(CertTag::EcCurveId as u8), 1)?;

        // 9. EC Public Key
        tw.str(&TLVTag::Context(CertTag::EcPubKey as u8), pubkey)?;

        // 10. Extensions
        tw.start_list(&TLVTag::Context(CertTag::Extensions as u8))?;
        Self::write_extensions(&mut tw, cert_type, subject_key_id, authority_key_id)?;
        tw.end_container()?;

        tw.end_container()?;

        Ok(tw.get_tail())
    }

    /// Write certificate extensions.
    fn write_extensions(
        tw: &mut impl TLVWrite,
        cert_type: CertType,
        subject_key_id: &KeyId,
        authority_key_id: &KeyId,
    ) -> Result<(), Error> {
        // 1. Basic Constraints
        tw.start_struct(&TLVTag::Context(1))?;
        match cert_type {
            CertType::Rcac => {
                tw.bool(&TLVTag::Context(1), true)?; // is_ca = true
                tw.u8(&TLVTag::Context(2), 1)?; // path_len = 1
            }
            CertType::Icac => {
                tw.bool(&TLVTag::Context(1), true)?; // is_ca = true
                tw.u8(&TLVTag::Context(2), 0)?; // path_len = 0
            }
            CertType::Noc => {
                tw.bool(&TLVTag::Context(1), false)?; // is_ca = false
                                                      // No path_len for end entity
            }
        }
        tw.end_container()?;

        // 2. Key Usage
        let key_usage = match cert_type {
            CertType::Rcac | CertType::Icac => {
                key_usage_tlv::KEY_CERT_SIGN | key_usage_tlv::CRL_SIGN
            }
            CertType::Noc => key_usage_tlv::DIGITAL_SIGNATURE,
        };
        tw.u16(&TLVTag::Context(2), key_usage)?;

        // 3. Extended Key Usage - for NOC only
        if cert_type == CertType::Noc {
            tw.start_array(&TLVTag::Context(3))?;
            tw.u8(&TLVTag::Anonymous, 1)?; // ServerAuth
            tw.u8(&TLVTag::Anonymous, 2)?; // ClientAuth
            tw.end_container()?;
        }

        // 4. Subject Key Identifier
        tw.str(&TLVTag::Context(4), subject_key_id)?;

        // 5. Authority Key Identifier (not present for self-signed RCAC in some cases,
        //    but Matter spec recommends including it)
        tw.str(&TLVTag::Context(5), authority_key_id)?;

        Ok(())
    }

    /// Sign the TBS certificate data.
    fn sign_tbs<C: Crypto>(
        tbs_data: &[u8],
        signing_key: &C::SecretKey<'_>,
    ) -> Result<CanonPkcSignature, Error> {
        use crate::crypto::SigningSecretKey;

        let mut signature = CanonPkcSignature::new();
        signing_key.sign(tbs_data, &mut signature)?;
        Ok(signature)
    }

    /// Append the signature to complete the certificate.
    ///
    /// This reads the TBS data, parses out the structure, and re-writes it
    /// with the signature field added.
    fn append_signature(
        &mut self,
        signature: &CanonPkcSignature,
        tbs_len: usize,
    ) -> Result<usize, Error> {
        if tbs_len == 0 || self.buf[tbs_len - 1] != 0x18 {
            return Err(ErrorCode::InvalidData.into());
        }

        let insert_pos = tbs_len - 1;

        // Use proper TLV encoding via WriteBuf
        let mut tw = WriteBuf::new(&mut self.buf[insert_pos..]);
        tw.str(
            &TLVTag::Context(CertTag::Signature as u8),
            signature.access(),
        )?;
        tw.end_container()?;

        Ok(insert_pos + tw.get_tail())
    }

    /// Validate serial number format.
    fn validate_serial_number(serial: &[u8]) -> Result<(), Error> {
        if serial.is_empty() {
            return Err(ErrorCode::InvalidData.into());
        }
        // Check for unnecessary leading zeros (except one needed for positive sign)
        if serial.len() > 1 && serial[0] == 0 && (serial[1] & 0x80) == 0 {
            return Err(ErrorCode::InvalidData.into());
        }
        Ok(())
    }
}

/// Builder for creating Node Operational Certificates (NOC).
///
/// NOCs are end-entity certificates used to identify devices on a Matter fabric.
/// They contain a node ID, fabric ID, and optional CASE Authenticated Tags (CATs).
pub struct NocBuilder<'a> {
    core: CertBuilderCore<'a>,
}

impl<'a> NocBuilder<'a> {
    /// Create a new NOC builder with the given buffer.
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self {
            core: CertBuilderCore::new(buf),
        }
    }

    /// Build a Node Operational Certificate (NOC).
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `subject` - Subject DN fields (node_id, fabric_id, cat_ids)
    /// * `validity` - Certificate validity period
    /// * `subject_pubkey` - The device's public key (from CSR)
    /// * `issuer_pubkey` - The issuer's public key (ICAC or RCAC)
    /// * `issuer_privkey` - The issuer's signing key
    /// * `serial_number` - Certificate serial number
    /// * `issuer` - Issuer RDN fields
    ///
    /// # Returns
    /// The length of the encoded certificate in the buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn build<C: Crypto>(
        &mut self,
        crypto: &C,
        subject: SubjectDN,
        validity: Validity,
        subject_pubkey: &C::PublicKey<'_>,
        issuer_pubkey: &C::PublicKey<'_>,
        issuer_privkey: &C::SecretKey<'_>,
        serial_number: &[u8],
        issuer: IssuerDN,
    ) -> Result<usize, Error> {
        // Validate NOC-specific requirements
        if subject.ca_id.is_some() {
            return Err(ErrorCode::InvalidData.into());
        }

        if subject.cat_ids.len() > 3 {
            return Err(ErrorCode::InvalidData.into());
        }

        for &cat_id in subject.cat_ids {
            Self::validate_cat_id(cat_id)?;
        }

        self.core.build_cert(
            crypto,
            CertType::Noc,
            serial_number,
            validity,
            subject_pubkey,
            issuer_privkey,
            Some(issuer_pubkey),
            subject,
            issuer,
        )
    }

    /// Validate CAT ID format per Matter spec.
    /// CAT ID format: upper 16 bits = version (must be non-zero), lower 16 bits = identifier
    fn validate_cat_id(cat_id: u32) -> Result<(), Error> {
        let version = (cat_id >> 16) as u16;
        if version == 0 {
            return Err(ErrorCode::InvalidData.into());
        }
        Ok(())
    }
}

/// Builder for creating Intermediate CA Certificates (ICAC).
///
/// ICACs are intermediate CA certificates used to sign Node Operational Certificates.
/// They are always signed by a Root CA (RCAC).
pub struct IcacBuilder<'a> {
    core: CertBuilderCore<'a>,
}

impl<'a> IcacBuilder<'a> {
    /// Create a new ICAC builder with the given buffer.
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self {
            core: CertBuilderCore::new(buf),
        }
    }

    /// Build an Intermediate CA Certificate (ICAC).
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `subject` - Subject DN fields (ca_id as ICAC ID, fabric_id)
    /// * `validity` - Certificate validity period
    /// * `subject_pubkey` - The ICAC's public key
    /// * `rcac_pubkey` - The RCAC's public key
    /// * `rcac_privkey` - The RCAC's signing key
    /// * `serial_number` - Certificate serial number
    /// * `issuer` - Issuer RDN fields (RCAC)
    ///
    /// # Returns
    /// The length of the encoded certificate in the buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn build<C: Crypto>(
        &mut self,
        crypto: &C,
        subject: SubjectDN,
        validity: Validity,
        subject_pubkey: &C::PublicKey<'_>,
        rcac_pubkey: &C::PublicKey<'_>,
        rcac_privkey: &C::SecretKey<'_>,
        serial_number: &[u8],
        issuer: IssuerDN,
    ) -> Result<usize, Error> {
        // Validate ICAC-specific requirements
        if subject.node_id.is_some() {
            return Err(ErrorCode::InvalidData.into());
        }

        if !subject.cat_ids.is_empty() {
            return Err(ErrorCode::InvalidData.into());
        }

        if subject.ca_id.is_none() {
            return Err(ErrorCode::InvalidData.into());
        }

        self.core.build_cert(
            crypto,
            CertType::Icac,
            serial_number,
            validity,
            subject_pubkey,
            rcac_privkey,
            Some(rcac_pubkey),
            subject,
            issuer,
        )
    }
}

/// Builder for creating Root CA Certificates (RCAC).
///
/// RCACs are self-signed root certificates used to sign Intermediate CA Certificates
/// or Node Operational Certificates directly.
pub struct RcacBuilder<'a> {
    core: CertBuilderCore<'a>,
}

impl<'a> RcacBuilder<'a> {
    /// Create a new RCAC builder with the given buffer.
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self {
            core: CertBuilderCore::new(buf),
        }
    }

    /// Build a Root CA Certificate (RCAC).
    ///
    /// The RCAC is self-signed.
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `subject` - Subject DN fields (ca_id as RCAC ID, fabric_id)
    /// * `validity` - Certificate validity period
    /// * `pubkey` - The RCAC's public key
    /// * `privkey` - The RCAC's signing key (for self-signing)
    /// * `serial_number` - Certificate serial number
    ///
    /// # Returns
    /// The length of the encoded certificate in the buffer.
    pub fn build<C: Crypto>(
        &mut self,
        crypto: &C,
        subject: SubjectDN,
        validity: Validity,
        pubkey: &C::PublicKey<'_>,
        privkey: &C::SecretKey<'_>,
        serial_number: &[u8],
    ) -> Result<usize, Error> {
        // Validate RCAC-specific requirements
        if subject.node_id.is_some() {
            return Err(ErrorCode::InvalidData.into());
        }

        if !subject.cat_ids.is_empty() {
            return Err(ErrorCode::InvalidData.into());
        }

        if subject.ca_id.is_none() {
            return Err(ErrorCode::InvalidData.into());
        }

        let issuer = IssuerDN {
            ca_id: None,     // Self-signed: no issuer CA ID
            fabric_id: None, // Self-signed: no issuer fabric ID
            is_rcac: false,  // Not used for RCAC,
        };

        self.core.build_cert(
            crypto,
            CertType::Rcac,
            serial_number,
            validity,
            pubkey,
            privkey,
            None, // Self-signed: no separate issuer key
            subject,
            issuer,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cert::{MAX_CERT_TLV_AND_ASN1_LEN, MAX_CERT_TLV_LEN},
        crypto::{test_only_crypto, CanonPkcPublicKey, PublicKey, SigningSecretKey},
    };

    #[test]
    fn test_validate_cat_id_valid() {
        // Version = 1, identifier = 0x1234
        assert!(NocBuilder::validate_cat_id(0x00011234).is_ok());
        // Version = 0xFFFF, identifier = 0xFFFF
        assert!(NocBuilder::validate_cat_id(0xFFFFFFFF).is_ok());
    }

    #[test]
    fn test_validate_cat_id_invalid() {
        // Version = 0 is invalid
        assert!(NocBuilder::validate_cat_id(0x00001234).is_err());
        assert!(NocBuilder::validate_cat_id(0x00000000).is_err());
    }

    #[test]
    fn test_validate_serial_number_valid() {
        assert!(CertBuilderCore::validate_serial_number(&[0x01]).is_ok());
        assert!(CertBuilderCore::validate_serial_number(&[0x00, 0x80]).is_ok()); // Leading zero needed for positive
        assert!(CertBuilderCore::validate_serial_number(&[0x7F]).is_ok());
    }

    #[test]
    fn test_validate_serial_number_invalid() {
        assert!(CertBuilderCore::validate_serial_number(&[]).is_err()); // Empty
        assert!(CertBuilderCore::validate_serial_number(&[0x00, 0x01]).is_err());
        // Unnecessary leading zero
    }

    /// Test building a self-signed RCAC
    #[test]
    fn test_build_rcac() {
        let crypto = test_only_crypto();

        // Generate a keypair for the RCAC
        let rcac_secret_key = unwrap!(crypto.generate_secret_key());
        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();

        let serial_number = &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let rcac_id = 0x1234567890u64;
        let fabric_id = 0x0000000000000001u64;
        let not_before = 0u32; // Matter epoch start
        let not_after = 0u32; // No expiry

        let subject = SubjectDN {
            node_id: None,
            fabric_id: Some(fabric_id),
            cat_ids: &[],
            ca_id: Some(rcac_id),
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut builder = RcacBuilder::new(&mut cert_buf);

        let len = unwrap!(builder.build(
            &crypto,
            subject,
            validity,
            &rcac_pubkey,
            &rcac_secret_key,
            serial_number,
        ));

        assert!(len > 100);
        assert!(len < MAX_CERT_TLV_LEN);
    }

    /// Test building an ICAC signed by RCAC
    #[test]
    fn test_build_icac() {
        let crypto = test_only_crypto();

        // Generate RCAC keypair (issuer)
        let rcac_secret_key = unwrap!(crypto.generate_secret_key());
        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();

        // Generate ICAC keypair
        let icac_secret_key = unwrap!(crypto.generate_secret_key());
        let icac_pubkey = icac_secret_key.pub_key().unwrap();

        let serial_number = &[0x01, 0x02, 0x03, 0x04];
        let icac_id = 0x1234u64;
        let rcac_id = 0x5678u64;
        let fabric_id = 0x0000000000000001u64;
        let not_before = 0u32;
        let not_after = 0u32;

        let subject = SubjectDN {
            node_id: None,
            fabric_id: Some(fabric_id),
            cat_ids: &[],
            ca_id: Some(icac_id),
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let issuer = IssuerDN {
            ca_id: Some(rcac_id),
            fabric_id: Some(fabric_id),
            is_rcac: true,
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut builder = IcacBuilder::new(&mut cert_buf);

        let len = unwrap!(builder.build(
            &crypto,
            subject,
            validity,
            &icac_pubkey,
            &rcac_pubkey,
            &rcac_secret_key,
            serial_number,
            issuer,
        ));

        assert!(len > 100);
        assert!(len < MAX_CERT_TLV_LEN);
    }

    /// Test building a NOC signed by RCAC
    #[test]
    fn test_build_noc_signed_by_rcac() {
        let crypto = test_only_crypto();

        // Generate RCAC keypair (issuer)
        let rcac_secret_key = unwrap!(crypto.generate_secret_key());
        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();

        // Generate NOC keypair
        let noc_secret_key = unwrap!(crypto.generate_secret_key());
        let noc_pubkey = noc_secret_key.pub_key().unwrap();

        let serial_number = &[0xAA, 0xBB, 0xCC];
        let node_id = 0x1122334455667788u64;
        let fabric_id = 0x0000000000000001u64;
        let rcac_id = 0x9999u64;
        let not_before = 0u32;
        let not_after = 0u32;

        let subject = SubjectDN {
            node_id: Some(node_id),
            fabric_id: Some(fabric_id),
            cat_ids: &[], // No CAT IDs
            ca_id: None,
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let issuer = IssuerDN {
            ca_id: Some(rcac_id),
            fabric_id: Some(fabric_id),
            is_rcac: true, // Issuer is RCAC
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut builder = NocBuilder::new(&mut cert_buf);

        let len = unwrap!(builder.build(
            &crypto,
            subject,
            validity,
            &noc_pubkey,
            &rcac_pubkey,
            &rcac_secret_key,
            serial_number,
            issuer,
        ));

        assert!(len > 100);
        assert!(len < MAX_CERT_TLV_LEN);
    }

    /// Test building a NOC with CAT IDs
    #[test]
    fn test_build_noc_with_cat_ids() {
        let crypto = test_only_crypto();

        // Generate RCAC keypair (issuer)
        let rcac_secret_key = unwrap!(crypto.generate_secret_key());
        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();

        // Generate NOC keypair
        let noc_secret_key = unwrap!(crypto.generate_secret_key());
        let noc_pubkey = noc_secret_key.pub_key().unwrap();

        let serial_number = &[0x01];
        let node_id = 0x0000000000000001u64;
        let fabric_id = 0x0000000000000001u64;
        let rcac_id = 0x1000u64;
        let cat_ids = &[0x00011111u32, 0x00022222u32, 0x00033333u32]; // Valid CAT IDs (version != 0)
        let not_before = 0u32;
        let not_after = 0u32;

        let subject = SubjectDN {
            node_id: Some(node_id),
            fabric_id: Some(fabric_id),
            cat_ids,
            ca_id: None,
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let issuer = IssuerDN {
            ca_id: Some(rcac_id),
            fabric_id: Some(fabric_id),
            is_rcac: true,
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut builder = NocBuilder::new(&mut cert_buf);

        let len = unwrap!(builder.build(
            &crypto,
            subject,
            validity,
            &noc_pubkey,
            &rcac_pubkey,
            &rcac_secret_key,
            serial_number,
            issuer,
        ));

        assert!(len > 100);
        assert!(len < MAX_CERT_TLV_LEN);
    }

    /// Test building a NOC signed by ICAC (3-cert chain)
    #[test]
    fn test_build_noc_signed_by_icac() {
        let crypto = test_only_crypto();

        // Generate ICAC keypair (issuer)
        let icac_secret_key = unwrap!(crypto.generate_secret_key());
        let icac_pubkey = icac_secret_key.pub_key().unwrap();

        // Generate NOC keypair
        let noc_secret_key = unwrap!(crypto.generate_secret_key());
        let noc_pubkey = noc_secret_key.pub_key().unwrap();

        let serial_number = &[0xFF];
        let node_id = 0xDEADBEEFu64;
        let fabric_id = 0x0000000000000001u64;
        let icac_id = 0x2468u64;
        let not_before = 0u32;
        let not_after = 0u32;

        let subject = SubjectDN {
            node_id: Some(node_id),
            fabric_id: Some(fabric_id),
            cat_ids: &[], // No CAT IDs
            ca_id: None,
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let issuer = IssuerDN {
            ca_id: Some(icac_id),
            fabric_id: Some(fabric_id),
            is_rcac: false, // Issuer is ICAC, not RCAC
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut builder = NocBuilder::new(&mut cert_buf);

        let len = unwrap!(builder.build(
            &crypto,
            subject,
            validity,
            &noc_pubkey,
            &icac_pubkey,
            &icac_secret_key,
            serial_number,
            issuer,
        ));

        assert!(len > 100);
        assert!(len < MAX_CERT_TLV_LEN);
    }

    /// Test complete certificate chain (RCAC -> ICAC -> NOC)
    #[test]
    fn test_build_complete_cert_chain() {
        let crypto = test_only_crypto();

        let fabric_id = 0x0000000000000001u64;
        let rcac_id = 0x1111111111u64;
        let icac_id = 0x2222u64;
        let node_id = 0x3333333333333333u64;
        let not_before = 0u32;
        let not_after = 0u32;

        // 1. Build RCAC
        let rcac_secret_key = unwrap!(crypto.generate_secret_key());
        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();

        let rcac_subject = SubjectDN {
            node_id: None,
            fabric_id: Some(fabric_id),
            cat_ids: &[],
            ca_id: Some(rcac_id),
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut rcac_builder = RcacBuilder::new(&mut rcac_buf);
        let rcac_len = unwrap!(rcac_builder.build(
            &crypto,
            rcac_subject,
            validity,
            &rcac_pubkey,
            &rcac_secret_key,
            &[0x01],
        ));
        assert!(rcac_len > 0);

        // 2. Build ICAC signed by RCAC
        let icac_secret_key = unwrap!(crypto.generate_secret_key());
        let icac_pubkey = icac_secret_key.pub_key().unwrap();

        let icac_subject = SubjectDN {
            node_id: None,
            fabric_id: Some(fabric_id),
            cat_ids: &[],
            ca_id: Some(icac_id),
        };

        let icac_issuer = IssuerDN {
            ca_id: Some(rcac_id),
            fabric_id: Some(fabric_id),
            is_rcac: true,
        };

        let mut icac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut icac_builder = IcacBuilder::new(&mut icac_buf);
        let icac_len = unwrap!(icac_builder.build(
            &crypto,
            icac_subject,
            validity,
            &icac_pubkey,
            &rcac_pubkey,
            &rcac_secret_key,
            &[0x02],
            icac_issuer,
        ));
        assert!(icac_len > 0);

        // 3. Build NOC signed by ICAC
        let noc_secret_key = unwrap!(crypto.generate_secret_key());
        let noc_pubkey = noc_secret_key.pub_key().unwrap();

        let noc_subject = SubjectDN {
            node_id: Some(node_id),
            fabric_id: Some(fabric_id),
            cat_ids: &[],
            ca_id: None,
        };

        let noc_issuer = IssuerDN {
            ca_id: Some(icac_id),
            fabric_id: Some(fabric_id),
            is_rcac: false, // Issuer is ICAC
        };

        let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut noc_builder = NocBuilder::new(&mut noc_buf);

        let noc_len = unwrap!(noc_builder.build(
            &crypto,
            noc_subject,
            validity,
            &noc_pubkey,
            &icac_pubkey,
            &icac_secret_key,
            &[0x03],
            noc_issuer,
        ));
        assert!(noc_len > 0);

        // All certificates should be valid sizes
        assert!(rcac_len > 100 && rcac_len < MAX_CERT_TLV_LEN);
        assert!(icac_len > 100 && icac_len < MAX_CERT_TLV_LEN);
        assert!(noc_len > 100 && noc_len < MAX_CERT_TLV_LEN);
    }

    /// Test NOC with too many CAT IDs
    #[test]
    fn test_build_noc_too_many_cat_ids() {
        let crypto = test_only_crypto();

        let rcac_secret_key = unwrap!(crypto.generate_secret_key());
        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();

        let noc_secret_key = unwrap!(crypto.generate_secret_key());
        let noc_pubkey = noc_secret_key.pub_key().unwrap();

        // Too many CAT IDs (max is 3)
        let cat_ids = &[0x00011111u32, 0x00022222u32, 0x00033333u32, 0x00044444u32];

        let subject = SubjectDN {
            node_id: Some(0x1234u64),
            fabric_id: Some(0x0001u64),
            cat_ids,
            ca_id: None,
        };

        let validity = Validity {
            not_before: 0u32,
            not_after: 0u32,
        };

        let issuer = IssuerDN {
            ca_id: Some(0x5678u64),
            fabric_id: Some(0x0001u64),
            is_rcac: true,
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut builder = NocBuilder::new(&mut cert_buf);

        let result = builder.build(
            &crypto,
            subject,
            validity,
            &noc_pubkey,
            &rcac_pubkey,
            &rcac_secret_key,
            &[0x01],
            issuer,
        );

        assert!(result.is_err());
    }

    /// Test NOC with invalid CAT ID (version = 0, should fail)
    #[test]
    fn test_build_noc_invalid_cat_id() {
        let crypto = test_only_crypto();

        let rcac_secret_key = unwrap!(crypto.generate_secret_key());
        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();

        let noc_secret_key = unwrap!(crypto.generate_secret_key());
        let noc_pubkey = noc_secret_key.pub_key().unwrap();

        // Invalid CAT ID (version = 0)
        let cat_ids = &[0x00001234u32];

        let subject = SubjectDN {
            node_id: Some(0x1234u64),
            fabric_id: Some(0x0001u64),
            cat_ids,
            ca_id: None,
        };

        let validity = Validity {
            not_before: 0u32,
            not_after: 0u32,
        };

        let issuer = IssuerDN {
            ca_id: Some(0x5678u64),
            fabric_id: Some(0x0001u64),
            is_rcac: true,
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut builder = NocBuilder::new(&mut cert_buf);

        let result = builder.build(
            &crypto,
            subject,
            validity,
            &noc_pubkey,
            &rcac_pubkey,
            &rcac_secret_key,
            &[0x01],
            issuer,
        );

        assert!(result.is_err());
    }

    /// Test certificate with validity period
    #[test]
    fn test_build_cert_with_validity() {
        let crypto = test_only_crypto();

        let rcac_secret_key = unwrap!(crypto.generate_secret_key());
        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();

        // Matter epoch: seconds since 2000-01-01 00:00:00 UTC
        // Year 2021: approximately 662688000 seconds
        let not_before = 662688000u32;
        // 10 years later
        let not_after = not_before + (10 * 365 * 24 * 60 * 60);

        let subject = SubjectDN {
            node_id: None,
            fabric_id: Some(0x0000000000000001u64),
            cat_ids: &[],
            ca_id: Some(0x1234567890u64),
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut builder = RcacBuilder::new(&mut cert_buf);

        let len = unwrap!(builder.build(
            &crypto,
            subject,
            validity,
            &rcac_pubkey,
            &rcac_secret_key,
            &[0x01],
        ));

        assert!(len > 100);
        assert!(len < MAX_CERT_TLV_LEN);
    }

    /// Test key identifier computation
    #[test]
    fn test_compute_key_id() {
        let crypto = test_only_crypto();

        let secret_key = unwrap!(crypto.generate_secret_key());
        let mut pubkey = CanonPkcPublicKey::new();
        unwrap!(secret_key.pub_key().unwrap().write_canon(&mut pubkey));

        let key_id = unwrap!(compute_key_id(&crypto, pubkey.access()));

        // Key ID should be deterministic for the same public key
        let key_id2 = unwrap!(compute_key_id(&crypto, pubkey.access()));
        assert_eq!(key_id, key_id2);
    }

    /// Test that different public keys produce different key IDs
    #[test]
    fn test_different_keys_different_ids() {
        let crypto = test_only_crypto();

        let secret_key1 = unwrap!(crypto.generate_secret_key());
        let mut pubkey1 = CanonPkcPublicKey::new();
        unwrap!(secret_key1.pub_key().unwrap().write_canon(&mut pubkey1));

        let secret_key2 = unwrap!(crypto.generate_secret_key());
        let mut pubkey2 = CanonPkcPublicKey::new();
        unwrap!(secret_key2.pub_key().unwrap().write_canon(&mut pubkey2));

        let key_id1 = unwrap!(compute_key_id(&crypto, pubkey1.access()));
        let key_id2 = unwrap!(compute_key_id(&crypto, pubkey2.access()));

        // Different keys should produce different IDs
        assert_ne!(key_id1, key_id2);
    }
}
