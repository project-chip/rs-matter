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

use crate::credentials::trust_store::SKID_LEN;
use crate::crypto::{
    CanonPkcSignature, Crypto, Digest, PKC_CANON_PUBLIC_KEY_LEN, PKC_SIGNATURE_LEN,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVTag, TLVWrite};
use crate::utils::storage::WriteBuf;

use super::{x509::key_usage_tlv, CertTag, DNTag, MAX_CERT_TLV_LEN};

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

impl<'a> CertBuilderCore<'a> {
    /// Create a new certificate builder core with the given buffer.
    fn new(buf: &'a mut [u8]) -> Self {
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
        not_before: u32,
        not_after: u32,
        subject_pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        signing_key: &C::SecretKey<'_>,
        issuer_pubkey: Option<&[u8; PKC_CANON_PUBLIC_KEY_LEN]>,
        // Subject DN fields
        node_id: Option<u64>,
        fabric_id: Option<u64>,
        cat_ids: &[u32],
        ca_id: Option<u64>,
        // Issuer DN fields
        issuer_ca_id: Option<u64>,
        issuer_fabric_id: Option<u64>,
        is_issuer_rcac: bool,
    ) -> Result<usize, Error> {
        // Validate serial number
        validate_serial_number(serial_number)?;

        // Compute subject and authority key identifiers
        let subject_key_id = Self::compute_key_id(crypto, subject_pubkey)?;
        let authority_key_id = if let Some(issuer_pk) = issuer_pubkey {
            Self::compute_key_id(crypto, issuer_pk)?
        } else {
            // Self-signed: AKID = SKID
            subject_key_id
        };

        // Build the TBS (To-Be-Signed) certificate
        let tbs_len = self.write_tbs_certificate(
            serial_number,
            not_before,
            not_after,
            subject_pubkey,
            &subject_key_id,
            &authority_key_id,
            cert_type,
            node_id,
            fabric_id,
            cat_ids,
            ca_id,
            issuer_ca_id,
            issuer_fabric_id,
            is_issuer_rcac,
        )?;

        let mut tbs_copy = [0u8; MAX_CERT_TLV_LEN];
        tbs_copy[..tbs_len].copy_from_slice(&self.buf[..tbs_len]);

        // Sign the TBS certificate
        let signature = self.sign_tbs(crypto, &tbs_copy[..tbs_len], signing_key)?;

        // Append signature to complete the certificate
        self.append_signature(&signature, tbs_len)
    }

    /// Compute the Subject Key Identifier (SHA-256 hash of public key truncated to 20 bytes).
    ///
    /// Per the Matter specification, the key identifier is the first 20 bytes of the
    /// SHA-256 hash of the public key.
    fn compute_key_id<C: Crypto>(
        crypto: &C,
        pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
    ) -> Result<[u8; SKID_LEN], Error> {
        let mut hash = crate::crypto::Hash::new();
        let mut hasher = crypto.hash()?;
        hasher.update(pubkey)?;
        hasher.finish(&mut hash)?;

        let mut key_id = [0u8; SKID_LEN];
        key_id.copy_from_slice(&hash.access()[..SKID_LEN]);
        Ok(key_id)
    }

    /// Write the TBS (To-Be-Signed) certificate structure.
    ///
    /// This creates the certificate without the signature.
    #[allow(clippy::too_many_arguments)]
    fn write_tbs_certificate(
        &mut self,
        serial_number: &[u8],
        not_before: u32,
        not_after: u32,
        pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        subject_key_id: &[u8; SKID_LEN],
        authority_key_id: &[u8; SKID_LEN],
        cert_type: CertType,
        node_id: Option<u64>,
        fabric_id: Option<u64>,
        cat_ids: &[u32],
        ca_id: Option<u64>,
        issuer_ca_id: Option<u64>,
        issuer_fabric_id: Option<u64>,
        is_issuer_rcac: bool,
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
                if let Some(id) = ca_id {
                    tw.u64(&TLVTag::Context(DNTag::RootCaId as u8), id)?;
                }
                if let Some(fid) = fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?; // Fabric ID
                }
            }
            CertType::Icac | CertType::Noc => {
                // Use provided issuer information
                if let Some(id) = issuer_ca_id {
                    let tag = if is_issuer_rcac {
                        DNTag::RootCaId as u8
                    } else {
                        DNTag::IcaId as u8
                    };
                    tw.u64(&TLVTag::Context(tag), id)?;
                }
                if let Some(fid) = issuer_fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?;
                }
            }
        }
        tw.end_container()?;

        // 4. Not Before
        tw.u32(&TLVTag::Context(CertTag::NotBefore as u8), not_before)?;

        // 5. Not After (0 = no expiry)
        tw.u32(&TLVTag::Context(CertTag::NotAfter as u8), not_after)?;

        // 6. Subject
        tw.start_list(&TLVTag::Context(CertTag::Subject as u8))?;
        match cert_type {
            CertType::Noc => {
                // NOC Subject: NodeId, FabricId, optional CAT IDs
                if let Some(nid) = node_id {
                    tw.u64(&TLVTag::Context(DNTag::NodeId as u8), nid)?;
                }
                if let Some(fid) = fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?
                }
                for cat_id in cat_ids {
                    tw.u64(&TLVTag::Context(DNTag::NocCat as u8), *cat_id as u64)?;
                }
            }
            CertType::Icac => {
                // ICAC Subject: ICAC ID, FabricId
                if let Some(id) = ca_id {
                    tw.u64(&TLVTag::Context(DNTag::IcaId as u8), id)?;
                }
                if let Some(fid) = fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?;
                }
            }
            CertType::Rcac => {
                // RCAC Subject: RCAC ID, FabricId
                if let Some(id) = ca_id {
                    tw.u64(&TLVTag::Context(DNTag::RootCaId as u8), id)?;
                }
                if let Some(fid) = fabric_id {
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
        subject_key_id: &[u8; SKID_LEN],
        authority_key_id: &[u8; SKID_LEN],
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
        &self,
        _crypto: &C,
        tbs_data: &[u8],
        signing_key: &C::SecretKey<'_>,
    ) -> Result<[u8; PKC_SIGNATURE_LEN], Error> {
        use crate::crypto::SigningSecretKey;

        let mut signature = CanonPkcSignature::new();
        signing_key.sign(tbs_data, &mut signature)?;

        let mut result = [0u8; PKC_SIGNATURE_LEN];
        result.copy_from_slice(signature.access());
        Ok(result)
    }

    /// Append the signature to complete the certificate.
    ///
    /// This reads the TBS data, parses out the structure, and re-writes it
    /// with the signature field added.
    fn append_signature(
        &mut self,
        signature: &[u8; PKC_SIGNATURE_LEN],
        tbs_len: usize,
    ) -> Result<usize, Error> {
        if tbs_len == 0 || self.buf[tbs_len - 1] != 0x18 {
            return Err(ErrorCode::InvalidData.into());
        }

        let insert_pos = tbs_len - 1;

        // Use proper TLV encoding via WriteBuf
        let mut tw = WriteBuf::new(&mut self.buf[insert_pos..]);
        tw.str(&TLVTag::Context(CertTag::Signature as u8), signature)?;
        tw.end_container()?;

        Ok(insert_pos + tw.get_tail())
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
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            core: CertBuilderCore::new(buf),
        }
    }

    /// Build a Node Operational Certificate (NOC).
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `node_id` - The node identifier for this device
    /// * `fabric_id` - The fabric identifier
    /// * `cat_ids` - CASE Authentication Tags (up to 3)
    /// * `subject_pubkey` - The device's public key (from CSR)
    /// * `issuer_pubkey` - The issuer's public key (ICAC or RCAC)
    /// * `issuer_privkey` - The issuer's signing key
    /// * `serial_number` - Certificate serial number
    /// * `not_before` - Validity start (Matter epoch seconds)
    /// * `not_after` - Validity end (0 = no expiry)
    /// * `issuer_ca_id` - The issuer's CA identifier (ICAC or RCAC ID)
    /// * `issuer_fabric_id` - The issuer's fabric identifier
    /// * `is_issuer_rcac` - True if issuer is RCAC, false if ICAC
    ///
    /// # Returns
    /// The length of the encoded certificate in the buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn build<C: Crypto>(
        &mut self,
        crypto: &C,
        node_id: u64,
        fabric_id: u64,
        cat_ids: &[u32],
        subject_pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        issuer_pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        issuer_privkey: &C::SecretKey<'_>,
        serial_number: &[u8],
        not_before: u32,
        not_after: u32,
        issuer_ca_id: u64,
        issuer_fabric_id: u64,
        is_issuer_rcac: bool,
    ) -> Result<usize, Error> {
        // Validate NOC-specific requirements
        if cat_ids.len() > 3 {
            return Err(ErrorCode::InvalidData.into());
        }

        for &cat_id in cat_ids {
            validate_cat_id(cat_id)?;
        }

        self.core.build_cert(
            crypto,
            CertType::Noc,
            serial_number,
            not_before,
            not_after,
            subject_pubkey,
            issuer_privkey,
            Some(issuer_pubkey),
            Some(node_id),
            Some(fabric_id),
            cat_ids,
            None, // No CA ID for NOC subject
            Some(issuer_ca_id),
            Some(issuer_fabric_id),
            is_issuer_rcac,
        )
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
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            core: CertBuilderCore::new(buf),
        }
    }

    /// Build an Intermediate CA Certificate (ICAC).
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `icac_id` - The ICAC identifier
    /// * `fabric_id` - The fabric identifier
    /// * `subject_pubkey` - The ICAC's public key
    /// * `rcac_pubkey` - The RCAC's public key
    /// * `rcac_privkey` - The RCAC's signing key
    /// * `serial_number` - Certificate serial number
    /// * `not_before` - Validity start (Matter epoch seconds)
    /// * `not_after` - Validity end (0 = no expiry)
    /// * `rcac_id` - The issuer RCAC's identifier
    /// * `rcac_fabric_id` - The issuer's fabric identifier
    ///
    /// # Returns
    /// The length of the encoded certificate in the buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn build<C: Crypto>(
        &mut self,
        crypto: &C,
        icac_id: u64,
        fabric_id: u64,
        subject_pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        rcac_pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        rcac_privkey: &C::SecretKey<'_>,
        serial_number: &[u8],
        not_before: u32,
        not_after: u32,
        rcac_id: u64,
        rcac_fabric_id: u64,
    ) -> Result<usize, Error> {
        self.core.build_cert(
            crypto,
            CertType::Icac,
            serial_number,
            not_before,
            not_after,
            subject_pubkey,
            rcac_privkey,
            Some(rcac_pubkey),
            None, // No node ID
            Some(fabric_id),
            &[], // No CAT IDs
            Some(icac_id),
            Some(rcac_id),
            Some(rcac_fabric_id),
            true, // Issuer is always RCAC for ICAC
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
    pub fn new(buf: &'a mut [u8]) -> Self {
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
    /// * `rcac_id` - The RCAC identifier
    /// * `fabric_id` - The fabric identifier
    /// * `pubkey` - The RCAC's public key
    /// * `privkey` - The RCAC's signing key (for self-signing)
    /// * `serial_number` - Certificate serial number
    /// * `not_before` - Validity start (Matter epoch seconds)
    /// * `not_after` - Validity end (0 = no expiry)
    ///
    /// # Returns
    /// The length of the encoded certificate in the buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn build<C: Crypto>(
        &mut self,
        crypto: &C,
        rcac_id: u64,
        fabric_id: u64,
        pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        privkey: &C::SecretKey<'_>,
        serial_number: &[u8],
        not_before: u32,
        not_after: u32,
    ) -> Result<usize, Error> {
        self.core.build_cert(
            crypto,
            CertType::Rcac,
            serial_number,
            not_before,
            not_after,
            pubkey,
            privkey,
            None, // Self-signed: no separate issuer key
            None, // No node ID
            Some(fabric_id),
            &[], // No CAT IDs
            Some(rcac_id),
            None,  // Self-signed: no issuer CA ID
            None,  // Self-signed: no issuer fabric ID
            false, // Not used for RCAC
        )
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_cat_id_valid() {
        // Version = 1, identifier = 0x1234
        assert!(validate_cat_id(0x00011234).is_ok());
        // Version = 0xFFFF, identifier = 0xFFFF
        assert!(validate_cat_id(0xFFFFFFFF).is_ok());
    }

    #[test]
    fn test_validate_cat_id_invalid() {
        // Version = 0 is invalid
        assert!(validate_cat_id(0x00001234).is_err());
        assert!(validate_cat_id(0x00000000).is_err());
    }

    #[test]
    fn test_validate_serial_number_valid() {
        assert!(validate_serial_number(&[0x01]).is_ok());
        assert!(validate_serial_number(&[0x00, 0x80]).is_ok()); // Leading zero needed for positive
        assert!(validate_serial_number(&[0x7F]).is_ok());
    }

    #[test]
    fn test_validate_serial_number_invalid() {
        assert!(validate_serial_number(&[]).is_err()); // Empty
        assert!(validate_serial_number(&[0x00, 0x01]).is_err()); // Unnecessary leading zero
    }
}
