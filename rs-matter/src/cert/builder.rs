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
//! This module provides a builder for creating Node Operational Certificates (NOC),
//! Intermediate CA Certificates (ICAC), and Root CA Certificates (RCAC) in Matter
//! TLV format.

use crate::crypto::{
    CanonPkcSignature, Crypto, Digest, PKC_CANON_PUBLIC_KEY_LEN, PKC_SIGNATURE_LEN,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVTag, TLVWrite};
use crate::utils::storage::WriteBuf;

use super::{x509::key_usage_tlv, CertTag, DNTag, MAX_CERT_TLV_LEN};

/// Subject Key Identifier length (SHA-1 hash)
const SUBJECT_KEY_ID_LEN: usize = 20;

/// Certificate type for builder
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertType {
    /// Root CA Certificate (self-signed, is_ca=true, path_len=1)
    Rcac,
    /// Intermediate CA Certificate (signed by RCAC, is_ca=true, path_len=0)
    Icac,
    /// Node Operational Certificate (end entity, is_ca=false)
    Noc,
}

/// Builder for creating Matter TLV-encoded certificates.
///
/// This builder constructs certificates field-by-field and then signs them.
pub struct CertBuilder<'a> {
    buf: &'a mut [u8],
}

impl<'a> CertBuilder<'a> {
    /// Create a new certificate builder with the given buffer.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf }
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
    /// * `issuer_key` - The issuer's signing key
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
    pub fn build_noc<C: Crypto>(
        &mut self,
        crypto: &C,
        node_id: u64,
        fabric_id: u64,
        cat_ids: &[u32],
        subject_pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        issuer_pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        issuer_key: &C::SecretKey<'_>,
        serial_number: &[u8],
        not_before: u32,
        not_after: u32,
        issuer_ca_id: u64,
        issuer_fabric_id: u64,
        is_issuer_rcac: bool,
    ) -> Result<usize, Error> {
        // Validate serial number
        validate_serial_number(serial_number)?;

        if cat_ids.len() > 3 {
            return Err(ErrorCode::InvalidData.into());
        }

        // Validate CAT IDs
        for &cat_id in cat_ids {
            validate_cat_id(cat_id)?;
        }

        // Compute subject and authority key identifiers
        let subject_key_id = Self::compute_key_id(crypto, subject_pubkey)?;
        let authority_key_id = Self::compute_key_id(crypto, issuer_pubkey)?;

        // Build the TBS (To-Be-Signed) certificate
        let tbs_len = self.write_tbs_certificate(
            serial_number,
            not_before,
            not_after,
            subject_pubkey,
            &subject_key_id,
            &authority_key_id,
            CertType::Noc,
            Some(node_id),
            Some(fabric_id),
            cat_ids,
            None, // No RCAC/ICAC ID for NOC subject
            Some(issuer_ca_id),
            Some(issuer_fabric_id),
            is_issuer_rcac,
        )?;

        // Copy TBS data before signing (needed due to borrowing)
        let mut tbs_copy = [0u8; MAX_CERT_TLV_LEN];
        tbs_copy[..tbs_len].copy_from_slice(&self.buf[..tbs_len]);

        // Sign the TBS certificate
        let signature = self.sign_tbs(crypto, &tbs_copy[..tbs_len], issuer_key)?;

        // Append signature to complete the certificate
        self.append_signature(&signature, tbs_len)
    }

    /// Build an Intermediate CA Certificate (ICAC).
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `icac_id` - The ICAC identifier
    /// * `fabric_id` - The fabric identifier
    /// * `subject_pubkey` - The ICAC's public key
    /// * `issuer_pubkey` - The RCAC's public key
    /// * `issuer_key` - The RCAC's signing key
    /// * `serial_number` - Certificate serial number
    /// * `not_before` - Validity start (Matter epoch seconds)
    /// * `not_after` - Validity end (0 = no expiry)
    /// * `issuer_rcac_id` - The issuer RCAC's identifier
    /// * `issuer_fabric_id` - The issuer's fabric identifier
    ///
    /// # Returns
    /// The length of the encoded certificate in the buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn build_icac<C: Crypto>(
        &mut self,
        crypto: &C,
        icac_id: u64,
        fabric_id: u64,
        subject_pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        issuer_pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        issuer_key: &C::SecretKey<'_>,
        serial_number: &[u8],
        not_before: u32,
        not_after: u32,
        issuer_rcac_id: u64,
        issuer_fabric_id: u64,
    ) -> Result<usize, Error> {
        // Validate serial number
        validate_serial_number(serial_number)?;

        // Compute subject and authority key identifiers
        let subject_key_id = Self::compute_key_id(crypto, subject_pubkey)?;
        let authority_key_id = Self::compute_key_id(crypto, issuer_pubkey)?;

        // Build the TBS certificate
        let tbs_len = self.write_tbs_certificate(
            serial_number,
            not_before,
            not_after,
            subject_pubkey,
            &subject_key_id,
            &authority_key_id,
            CertType::Icac,
            None,            // No node ID
            Some(fabric_id), // Fabric ID in subject
            &[],             // No CAT IDs
            Some(icac_id),   // ICAC ID
            Some(issuer_rcac_id),
            Some(issuer_fabric_id),
            true, // is_issuer_rcac = true for ICAC
        )?;

        // Copy TBS data before signing (needed due to borrowing)
        let mut tbs_copy = [0u8; MAX_CERT_TLV_LEN];
        tbs_copy[..tbs_len].copy_from_slice(&self.buf[..tbs_len]);

        // Sign the TBS certificate
        let signature = self.sign_tbs(crypto, &tbs_copy[..tbs_len], issuer_key)?;

        // Append signature to complete the certificate
        self.append_signature(&signature, tbs_len)
    }

    /// Build a Root CA Certificate (RCAC).
    ///
    /// The RCAC is self-signed.
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `rcac_id` - The RCAC identifier
    /// * `fabric_id` - The fabric identifier
    /// * `subject_pubkey` - The RCAC's public key
    /// * `subject_key` - The RCAC's signing key (for self-signing)
    /// * `serial_number` - Certificate serial number
    /// * `not_before` - Validity start (Matter epoch seconds)
    /// * `not_after` - Validity end (0 = no expiry)
    ///
    /// # Returns
    /// The length of the encoded certificate in the buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn build_rcac<C: Crypto>(
        &mut self,
        crypto: &C,
        rcac_id: u64,
        fabric_id: u64,
        subject_pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        subject_key: &C::SecretKey<'_>,
        serial_number: &[u8],
        not_before: u32,
        not_after: u32,
    ) -> Result<usize, Error> {
        // Validate serial number
        validate_serial_number(serial_number)?;

        // Compute subject key identifier (self-signed, so SKID = AKID)
        let subject_key_id = Self::compute_key_id(crypto, subject_pubkey)?;

        // Build the TBS certificate (no authority key ID for self-signed root)
        let tbs_len = self.write_tbs_certificate(
            serial_number,
            not_before,
            not_after,
            subject_pubkey,
            &subject_key_id,
            &subject_key_id, // Self-signed: AKID = SKID
            CertType::Rcac,
            None,            // No node ID
            Some(fabric_id), // Fabric ID in subject
            &[],             // No CAT IDs
            Some(rcac_id),   // RCAC ID
            None,            // No issuer CA ID (self-signed)
            None,            // No issuer fabric ID (self-signed)
            false,           // is_issuer_rcac (not used for RCAC)
        )?;

        // Copy TBS data before signing (needed due to borrowing)
        let mut tbs_copy = [0u8; MAX_CERT_TLV_LEN];
        tbs_copy[..tbs_len].copy_from_slice(&self.buf[..tbs_len]);

        // Sign the TBS certificate with our own key
        let signature = self.sign_tbs(crypto, &tbs_copy[..tbs_len], subject_key)?;

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
    ) -> Result<[u8; SUBJECT_KEY_ID_LEN], Error> {
        let mut hash = crate::crypto::Hash::new();
        let mut hasher = crypto.hash()?;
        hasher.update(pubkey)?;
        hasher.finish(&mut hash)?;

        let mut key_id = [0u8; SUBJECT_KEY_ID_LEN];
        key_id.copy_from_slice(&hash.access()[..SUBJECT_KEY_ID_LEN]);
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
        subject_key_id: &[u8; SUBJECT_KEY_ID_LEN],
        authority_key_id: &[u8; SUBJECT_KEY_ID_LEN],
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
        tw.u32(&TLVTag::Context(CertTag::NotBefore as _), not_before)?;

        // 5. Not After (0 = no expiry)
        tw.u32(&TLVTag::Context(CertTag::NotAfter as _), not_after)?;

        // 6. Subject
        tw.start_list(&TLVTag::Context(CertTag::Subject as _))?;
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
        tw.u8(&TLVTag::Context(CertTag::PubKeyAlgo as _), 1)?;

        // 8. EC Curve ID (1 = prime256v1)
        tw.u8(&TLVTag::Context(CertTag::EcCurveId as _), 1)?;

        // 9. EC Public Key
        tw.str(&TLVTag::Context(CertTag::EcPubKey as _), pubkey)?;

        // 10. Extensions
        tw.start_list(&TLVTag::Context(CertTag::Extensions as _))?;
        Self::write_extensions(&mut tw, cert_type, subject_key_id, authority_key_id)?;
        tw.end_container()?;

        tw.end_container()?;

        Ok(tw.get_tail())
    }

    /// Write certificate extensions.
    fn write_extensions(
        tw: &mut impl TLVWrite,
        cert_type: CertType,
        subject_key_id: &[u8; SUBJECT_KEY_ID_LEN],
        authority_key_id: &[u8; SUBJECT_KEY_ID_LEN],
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
    fn test_cert_type_enum() {
        assert_eq!(CertType::Rcac, CertType::Rcac);
        assert_ne!(CertType::Rcac, CertType::Icac);
        assert_ne!(CertType::Icac, CertType::Noc);
    }

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
