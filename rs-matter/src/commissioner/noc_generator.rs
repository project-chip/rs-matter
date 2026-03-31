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

//! NOC (Node Operational Certificate) generation for Matter commissioning.
//!
//! This module provides the `NocGenerator` type which can create the certificate
//! chain needed to commission a device into a fabric:
//! - Root CA Certificate (RCAC)
//! - Optional Intermediate CA Certificate (ICAC)
//! - Node Operational Certificate (NOC)

use crate::cert::builder::{IcacBuilder, IssuerDN, NocBuilder, RcacBuilder};
use crate::cert::csr::CsrRef;
use crate::cert::{MAX_CERT_TLV_AND_ASN1_LEN, MAX_CERT_TLV_LEN};
use crate::crypto::{
    CanonPkcPublicKey, CanonPkcPublicKeyRef, CanonPkcSecretKey, Crypto, PublicKey, RngCore,
    SecretKey, SigningSecretKey,
};
use crate::error::{Error, ErrorCode};

/// Generated NOC credentials for a device.
#[derive(Debug)]
pub struct NocCredentials {
    /// NOC certificate (TLV encoded)
    pub noc: heapless::Vec<u8, MAX_CERT_TLV_LEN>,
    /// Node ID assigned to this device
    pub node_id: u64,
}

/// NOC generator for fabric credential provisioning.
///
/// The `NocGenerator` holds the CA credentials for a fabric and can generate
/// NOCs for devices being commissioned.
///
/// # Example
///
/// ```ignore
/// let mut generator = NocGenerator::new(&crypto, fabric_id)?;
/// let csr = device.csr_request(&crypto, nonce)?;
/// let credentials = generator.generate_noc(&crypto, &csr, node_id, &[])?;
/// device.add_noc(credentials.noc, generator.root_cert(), ipk)?;
/// ```
pub struct NocGenerator {
    /// Root CA private key
    root_privkey: CanonPkcSecretKey,
    /// Root CA public key
    root_pubkey: CanonPkcPublicKey,
    /// Root CA certificate (TLV encoded)
    root_cert: heapless::Vec<u8, MAX_CERT_TLV_LEN>,
    /// Optional ICAC private key
    icac_privkey: Option<CanonPkcSecretKey>,
    /// Optional ICAC public key
    icac_pubkey: Option<CanonPkcPublicKey>,
    /// Optional ICAC certificate (TLV encoded)
    icac_cert: Option<heapless::Vec<u8, MAX_CERT_TLV_LEN>>,
    /// Fabric ID for this generator
    fabric_id: u64,
    /// RCAC ID
    rcac_id: u64,
    /// Optional ICAC ID (if ICAC was generated)
    icac_id: Option<u64>,
    /// Next serial number for certificates
    next_serial: u64,
}

impl NocGenerator {
    /// Create a new NOC generator with a fresh Root CA.
    ///
    /// This generates a new P-256 keypair for the Root CA and creates
    /// a self-signed RCAC.
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `fabric_id` - The fabric identifier for this CA
    ///
    /// # Returns
    /// A new `NocGenerator` ready to issue NOCs.
    pub fn new<C: Crypto>(crypto: &C, fabric_id: u64) -> Result<Self, Error> {
        // Generate a random RCAC ID
        let mut rcac_id_bytes = [0u8; 8];
        crypto.rand()?.fill_bytes(&mut rcac_id_bytes);
        let rcac_id = u64::from_be_bytes(rcac_id_bytes);

        // Generate root CA keypair
        let root_key = crypto.generate_secret_key()?;

        let mut root_pubkey = CanonPkcPublicKey::new();
        root_key.pub_key()?.write_canon(&mut root_pubkey)?;

        let mut root_privkey = CanonPkcSecretKey::new();
        root_key.write_canon(&mut root_privkey)?;

        // Generate serial number
        let mut serial_bytes = [0u8; 8];
        crypto.rand()?.fill_bytes(&mut serial_bytes);

        // Build the RCAC
        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];

        // Load the secret key for signing
        let signing_key = crypto.secret_key(root_privkey.reference())?;

        let subject = crate::cert::builder::SubjectDN {
            node_id: None,
            fabric_id: Some(fabric_id),
            cat_ids: &[],
            ca_id: Some(rcac_id),
        };

        let validity = crate::cert::builder::Validity {
            not_before: 0, // epoch start
            not_after: 0,  // no expiry
        };

        let cert_len = RcacBuilder::new(&mut cert_buf).build(
            crypto,
            subject,
            validity,
            &root_key.pub_key()?,
            &signing_key,
            &serial_bytes,
        )?;

        let mut root_cert = heapless::Vec::new();
        root_cert
            .extend_from_slice(&cert_buf[..cert_len])
            .map_err(|_| Error::from(ErrorCode::BufferTooSmall))?;

        Ok(Self {
            root_privkey,
            root_pubkey,
            root_cert,
            icac_privkey: None,
            icac_pubkey: None,
            icac_cert: None,
            fabric_id,
            rcac_id,
            icac_id: None,
            next_serial: 1,
        })
    }

    /// Create a NOC generator from existing Root CA credentials.
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `root_privkey` - The Root CA private key
    /// * `root_cert` - The Root CA certificate (TLV encoded)
    /// * `fabric_id` - The fabric identifier
    /// * `rcac_id` - The RCAC identifier
    pub fn from_root_ca<C: Crypto>(
        crypto: &C,
        root_privkey: CanonPkcSecretKey,
        root_cert: &[u8],
        fabric_id: u64,
        rcac_id: u64,
    ) -> Result<Self, Error> {
        // Derive public key from private key
        let root_key = crypto.secret_key(root_privkey.reference())?;
        let mut root_pubkey = CanonPkcPublicKey::new();
        root_key.pub_key()?.write_canon(&mut root_pubkey)?;

        let mut cert_vec = heapless::Vec::new();
        cert_vec
            .extend_from_slice(root_cert)
            .map_err(|_| Error::from(ErrorCode::BufferTooSmall))?;

        Ok(Self {
            root_privkey,
            root_pubkey,
            root_cert: cert_vec,
            icac_privkey: None,
            icac_pubkey: None,
            icac_cert: None,
            fabric_id,
            rcac_id,
            icac_id: None,
            next_serial: 1,
        })
    }

    /// Generate an ICAC for this fabric.
    ///
    /// The ICAC is optional - if not generated, NOCs will be signed directly
    /// by the RCAC.
    ///
    /// # Returns
    /// A reference to the generated ICAC certificate.
    pub fn generate_icac<C: Crypto>(&mut self, crypto: &C) -> Result<&[u8], Error> {
        // Generate a random ICAC ID
        let mut icac_id_bytes = [0u8; 8];
        crypto.rand()?.fill_bytes(&mut icac_id_bytes);
        let icac_id = u64::from_be_bytes(icac_id_bytes);

        // Generate ICAC keypair
        let icac_key = crypto.generate_secret_key()?;

        let mut icac_pubkey = CanonPkcPublicKey::new();
        icac_key.pub_key()?.write_canon(&mut icac_pubkey)?;

        let mut icac_privkey = CanonPkcSecretKey::new();
        icac_key.write_canon(&mut icac_privkey)?;

        // Generate and encode serial number as ASN.1 INTEGER
        let serial = self.next_serial();
        let serial_bytes_vec = Self::encode_serial_asn1(serial);
        let serial_bytes = serial_bytes_vec.as_slice();

        // Build the ICAC (signed by RCAC)
        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];

        let root_signing_key = crypto.secret_key(self.root_privkey.reference())?;

        let subject = crate::cert::builder::SubjectDN {
            node_id: None,
            fabric_id: Some(self.fabric_id),
            cat_ids: &[],
            ca_id: Some(icac_id),
        };

        let validity = crate::cert::builder::Validity {
            not_before: 0, // epoch start
            not_after: 0,  // no expiry
        };

        let issuer = crate::cert::builder::IssuerDN {
            ca_id: Some(self.rcac_id),
            fabric_id: Some(self.fabric_id),
            is_rcac: true,
        };

        let cert_len = IcacBuilder::new(&mut cert_buf).build(
            crypto,
            subject,
            validity,
            &icac_key.pub_key()?,
            &root_signing_key.pub_key()?,
            &root_signing_key,
            serial_bytes,
            issuer,
        )?;

        let mut icac_cert = heapless::Vec::new();
        icac_cert
            .extend_from_slice(&cert_buf[..cert_len])
            .map_err(|_| Error::from(ErrorCode::BufferTooSmall))?;

        self.icac_privkey = Some(icac_privkey);
        self.icac_pubkey = Some(icac_pubkey);
        self.icac_cert = Some(icac_cert);
        self.icac_id = Some(icac_id);

        Ok(self.icac_cert.as_ref().unwrap().as_slice())
    }

    /// Generate a NOC from a CSR.
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `csr` - The device's Certificate Signing Request (DER encoded)
    /// * `node_id` - The node ID to assign to this device
    /// * `cat_ids` - CASE Authentication Tags (up to 3)
    ///
    /// # Returns
    /// The generated NOC credentials.
    pub fn generate_noc<C: Crypto>(
        &mut self,
        crypto: &C,
        csr: &[u8],
        node_id: u64,
        cat_ids: &[u32],
    ) -> Result<NocCredentials, Error> {
        // Parse CSR to extract public key
        let csr_ref = CsrRef::new(csr)?;
        let device_pubkey = csr_ref.pubkey()?;

        // Verify the CSR signature
        csr_ref.verify(crypto)?;

        // Generate and encode serial number as ASN.1 INTEGER
        let serial = self.next_serial();
        let serial_bytes_vec = Self::encode_serial_asn1(serial);
        let serial_bytes = serial_bytes_vec.as_slice();

        // Determine signing key and issuer public key
        let (signing_privkey, issuer_pubkey) = if let Some(ref icac_privkey) = self.icac_privkey {
            (icac_privkey, self.icac_pubkey.as_ref().unwrap())
        } else {
            (&self.root_privkey, &self.root_pubkey)
        };

        // Build the NOC
        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];

        let signing_key = crypto.secret_key(signing_privkey.reference())?;

        // Determine issuer CA ID and whether issuer is RCAC
        let (issuer_ca_id, is_issuer_rcac) = if let Some(icac_id) = self.icac_id {
            (icac_id, false) // Signed by ICAC
        } else {
            (self.rcac_id, true) // Signed directly by RCAC
        };

        let issuer = IssuerDN {
            ca_id: Some(issuer_ca_id),
            fabric_id: Some(self.fabric_id),
            is_rcac: is_issuer_rcac,
        };

        let subject = crate::cert::builder::SubjectDN {
            node_id: Some(node_id),
            fabric_id: Some(self.fabric_id),
            cat_ids,
            ca_id: None,
        };

        let validity = crate::cert::builder::Validity {
            not_before: 0, // epoch start
            not_after: 0,  // no expiry
        };

        let cert_len = NocBuilder::new(&mut cert_buf).build(
            crypto,
            subject,
            validity,
            &crypto.pub_key(CanonPkcPublicKeyRef::try_new(&device_pubkey)?)?,
            &crypto.pub_key(issuer_pubkey.reference())?,
            &signing_key,
            serial_bytes,
            issuer,
        )?;

        let mut noc = heapless::Vec::new();
        noc.extend_from_slice(&cert_buf[..cert_len])
            .map_err(|_| Error::from(ErrorCode::BufferTooSmall))?;

        Ok(NocCredentials { noc, node_id })
    }

    /// Get the Root CA certificate.
    pub fn root_cert(&self) -> &[u8] {
        &self.root_cert
    }

    /// Get the ICAC certificate (if generated).
    pub fn icac_cert(&self) -> Option<&[u8]> {
        self.icac_cert.as_ref().map(|v| v.as_slice())
    }

    /// Get the fabric ID.
    pub fn fabric_id(&self) -> u64 {
        self.fabric_id
    }

    /// Get the RCAC ID.
    pub fn rcac_id(&self) -> u64 {
        self.rcac_id
    }

    /// Get the ICAC ID (if ICAC was generated).
    pub fn icac_id(&self) -> Option<u64> {
        self.icac_id
    }

    /// Encode a u64 serial number as an ASN.1 INTEGER.
    ///
    /// ASN.1 DER encoding rules require:
    /// 1. Strip all leading zero bytes
    /// 2. If the high bit of the resulting first byte is set (>= 0x80),
    ///    prepend a 0x00 byte to indicate it's a positive number
    /// 3. The leftmost 9 bits must not be all 0's or all 1's
    fn encode_serial_asn1(serial: u64) -> heapless::Vec<u8, 9> {
        // Convert to big-endian bytes
        let serial_bytes_full = serial.to_be_bytes();

        // Find first non-zero byte
        let start = serial_bytes_full
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(serial_bytes_full.len() - 1);
        let stripped = &serial_bytes_full[start..];

        // Create result vec
        let mut vec = heapless::Vec::<u8, 9>::new();

        // If high bit is set, prepend 0x00 to indicate positive number
        if !stripped.is_empty() && (stripped[0] & 0x80) != 0 {
            vec.push(0).unwrap();
        }
        vec.extend_from_slice(stripped).unwrap();

        vec
    }

    /// Get the next serial number and increment the counter.
    fn next_serial(&mut self) -> u64 {
        let serial = self.next_serial;
        self.next_serial += 1;
        serial
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::CertRef;
    use crate::crypto::test_only_crypto;
    use crate::tlv::TLVElement;

    /// Known valid CSR from C++ test vectors (TestChipCryptoPAL.cpp)
    /// This CSR has a valid signature and can be verified.
    const GOOD_CSR: &[u8] = &[
        0x30, 0x81, 0xca, 0x30, 0x70, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06,
        0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 0x43, 0x53, 0x52, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
        0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa3, 0xbe, 0xa1, 0xf5, 0x42, 0x01, 0x07, 0x3c, 0x4b,
        0x75, 0x85, 0xd8, 0xe2, 0x98, 0xac, 0x2f, 0xf6, 0x98, 0xdb, 0xd9, 0x5b, 0xe0, 0x7e, 0xc1,
        0x04, 0xd5, 0x73, 0xc5, 0xb0, 0x90, 0x77, 0x27, 0x00, 0x1e, 0x22, 0xc7, 0x89, 0x5e, 0x4d,
        0x75, 0x07, 0x89, 0x82, 0x0f, 0x49, 0xb6, 0x59, 0xd5, 0xc5, 0x15, 0x7d, 0x93, 0xe6, 0x80,
        0x5c, 0x70, 0x89, 0x0a, 0x43, 0x10, 0x3d, 0xeb, 0x3d, 0x4a, 0xa0, 0x00, 0x30, 0x0c, 0x06,
        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x00, 0x03, 0x48, 0x00, 0x30,
        0x45, 0x02, 0x20, 0x1d, 0x86, 0x21, 0xb4, 0xc2, 0xe1, 0xa9, 0xf3, 0xbc, 0xc8, 0x7c, 0xda,
        0xb4, 0xb9, 0xc6, 0x8c, 0xd0, 0xe4, 0x9a, 0x9c, 0xef, 0x02, 0x93, 0x98, 0x27, 0x7e, 0x81,
        0x21, 0x5d, 0x20, 0x9d, 0x32, 0x02, 0x21, 0x00, 0x8b, 0x6b, 0x49, 0xb6, 0x7d, 0x3e, 0x67,
        0x9e, 0xb1, 0x22, 0xd3, 0x63, 0x82, 0x40, 0x4f, 0x49, 0xa4, 0xdc, 0x17, 0x35, 0xac, 0x4b,
        0x7a, 0xbf, 0x52, 0x05, 0x58, 0x68, 0xe0, 0xaa, 0xd2, 0x8e,
    ];

    /// CSR with bad signature (should fail verification)
    /// One byte changed in signature (0xb1, 0x21 instead of 0xb1, 0x22)
    const BAD_SIGNATURE_CSR: &[u8] = &[
        0x30, 0x81, 0xca, 0x30, 0x70, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06,
        0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 0x43, 0x53, 0x52, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
        0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa3, 0xbe, 0xa1, 0xf5, 0x42, 0x01, 0x07, 0x3c, 0x4b,
        0x75, 0x85, 0xd8, 0xe2, 0x98, 0xac, 0x2f, 0xf6, 0x98, 0xdb, 0xd9, 0x5b, 0xe0, 0x7e, 0xc1,
        0x04, 0xd5, 0x73, 0xc5, 0xb0, 0x90, 0x77, 0x27, 0x00, 0x1e, 0x22, 0xc7, 0x89, 0x5e, 0x4d,
        0x75, 0x07, 0x89, 0x82, 0x0f, 0x49, 0xb6, 0x59, 0xd5, 0xc5, 0x15, 0x7d, 0x93, 0xe6, 0x80,
        0x5c, 0x70, 0x89, 0x0a, 0x43, 0x10, 0x3d, 0xeb, 0x3d, 0x4a, 0xa0, 0x00, 0x30, 0x0c, 0x06,
        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x00, 0x03, 0x48, 0x00, 0x30,
        0x45, 0x02, 0x20, 0x1d, 0x86, 0x21, 0xb4, 0xc2, 0xe1, 0xa9, 0xf3, 0xbc, 0xc8, 0x7c, 0xda,
        0xb4, 0xb9, 0xc6, 0x8c, 0xd0, 0xe4, 0x9a, 0x9c, 0xef, 0x02, 0x93, 0x98, 0x27, 0x7e, 0x81,
        0x21, 0x5d, 0x20, 0x9d, 0x32, 0x02, 0x21, 0x00, 0x8b, 0x6b, 0x49, 0xb6, 0x7d, 0x3e, 0x67,
        0x9e, 0xb1, 0x21, 0xd3, 0x63, 0x82, 0x40, 0x4f, 0x49, 0xa4, 0xdc, 0x17, 0x35, 0xac, 0x4b,
        0x7a, 0xbf, 0x52, 0x05, 0x58, 0x68, 0xe0, 0xaa, 0xd2, 0x8e,
    ];

    #[test]
    fn test_new_creates_valid_generator() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1234_5678_9ABC_DEF0;

        let generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        // Verify fabric_id is stored
        assert_eq!(generator.fabric_id(), fabric_id);

        // Verify RCAC was generated
        assert!(generator.root_cert().len() > 0);

        // Verify RCAC ID was set
        assert!(generator.rcac_id() > 0);

        // Verify ICAC not yet generated
        assert!(generator.icac_cert().is_none());
        assert!(generator.icac_id().is_none());

        // Verify serial counter initialized to 1
        assert_eq!(generator.next_serial, 1);
    }

    #[test]
    fn test_from_root_ca_preserves_credentials() {
        let crypto = test_only_crypto();
        let fabric_id = 0xABCD;

        let gen1 = unwrap!(NocGenerator::new(&crypto, fabric_id));
        let root_cert = gen1.root_cert();
        let rcac_id = gen1.rcac_id();

        let mut root_cert_copy = heapless::Vec::<u8, MAX_CERT_TLV_LEN>::new();
        unwrap!(root_cert_copy.extend_from_slice(root_cert));
        let root_privkey = gen1.root_privkey.clone();

        // Create new generator from existing root CA
        let gen2 = unwrap!(NocGenerator::from_root_ca(
            &crypto,
            root_privkey,
            &root_cert_copy,
            fabric_id,
            rcac_id
        ));

        // Verify credentials match
        assert_eq!(gen2.fabric_id(), fabric_id);
        assert_eq!(gen2.rcac_id(), rcac_id);
        assert_eq!(gen2.root_cert(), root_cert);
    }

    #[test]
    fn test_generate_icac_creates_certificate() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        let icac = unwrap!(generator.generate_icac(&crypto));

        // ICAC should be non-empty
        assert!(icac.len() > 0);

        // Should be able to parse as TLV
        let _cert_ref = CertRef::new(TLVElement::new(icac));
    }

    #[test]
    fn test_icac_cert_available_after_generation() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        // Before generation, icac_cert() should return None
        assert!(generator.icac_cert().is_none());
        // Before generation, icac_id() should return None
        assert!(generator.icac_id().is_none());

        // Generate ICAC
        unwrap!(generator.generate_icac(&crypto));

        // After generation, icac_cert() should return Some
        assert!(generator.icac_cert().is_some());
        assert!(generator.icac_cert().unwrap().len() > 0);

        // After generation, icac_id() should return Some
        assert!(generator.icac_id().is_some());
        assert!(generator.icac_id().unwrap() > 0);
    }

    #[test]
    fn test_multiple_icac_calls_replace_previous() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        // Generate first ICAC
        unwrap!(generator.generate_icac(&crypto));
        let icac1_id = generator.icac_id().unwrap();

        // Copy first ICAC
        let mut icac1_copy = heapless::Vec::<u8, MAX_CERT_TLV_LEN>::new();
        unwrap!(icac1_copy.extend_from_slice(generator.icac_cert().unwrap()));

        // Generate second ICAC
        unwrap!(generator.generate_icac(&crypto));
        let icac2_id = generator.icac_id().unwrap();

        // IDs should be different (randomly generated)
        assert_ne!(icac1_id, icac2_id);

        // Second ICAC should replace the first
        let icac2 = generator.icac_cert().unwrap();
        assert_ne!(icac2, icac1_copy.as_slice());
    }

    #[test]
    fn test_generate_noc_basic() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        let node_id = 0x1234;
        let creds = unwrap!(generator.generate_noc(&crypto, GOOD_CSR, node_id, &[]));

        // NOC should be non-empty
        assert!(creds.noc.len() > 0);

        // Node ID should match
        assert_eq!(creds.node_id, node_id);

        // Should be able to parse as TLV
        let _cert_ref = CertRef::new(TLVElement::new(&creds.noc));
    }

    #[test]
    fn test_generate_noc_with_icac() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        // Generate ICAC first
        unwrap!(generator.generate_icac(&crypto));

        let node_id = 0x5678;
        let creds = unwrap!(generator.generate_noc(&crypto, GOOD_CSR, node_id, &[]));

        // NOC should be generated successfully
        assert!(creds.noc.len() > 0);
        assert_eq!(creds.node_id, node_id);

        // Should be able to parse
        let _cert_ref = CertRef::new(TLVElement::new(&creds.noc));
    }

    #[test]
    fn test_generate_noc_with_cat_ids() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        let node_id = 0xABCD;
        let cat_ids = [0x0001_0001, 0x0001_0002, 0x0001_0003];

        let creds = unwrap!(generator.generate_noc(&crypto, GOOD_CSR, node_id, &cat_ids));

        // NOC should be generated successfully with CAT IDs
        assert!(creds.noc.len() > 0);
        assert_eq!(creds.node_id, node_id);

        // Parse and verify CAT IDs are present
        let cert_ref = CertRef::new(TLVElement::new(&creds.noc));
        let mut parsed_cat_ids = [0u32; 3];
        unwrap!(cert_ref.get_cat_ids(&mut parsed_cat_ids));
        assert_eq!(parsed_cat_ids, cat_ids);
    }

    #[test]
    fn test_generate_noc_increments_serial() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        // Initial serial should be 1
        assert_eq!(generator.next_serial, 1);

        // Generate first NOC
        unwrap!(generator.generate_noc(&crypto, GOOD_CSR, 1, &[]));

        // Serial should have incremented
        assert_eq!(generator.next_serial, 2);

        // Generate second NOC
        unwrap!(generator.generate_noc(&crypto, GOOD_CSR, 2, &[]));

        // Serial should have incremented again
        assert_eq!(generator.next_serial, 3);
    }

    #[test]
    fn test_noc_contains_correct_node_id() {
        let crypto = test_only_crypto();
        let fabric_id = 0x9999;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        let node_id = 0xDEAD_BEEF_CAFE_BABE;
        let creds = unwrap!(generator.generate_noc(&crypto, GOOD_CSR, node_id, &[]));

        // Parse NOC and extract node_id
        let cert_ref = CertRef::new(TLVElement::new(&creds.noc));
        let parsed_node_id = unwrap!(cert_ref.get_node_id());

        assert_eq!(parsed_node_id, node_id);
    }

    #[test]
    fn test_noc_contains_device_pubkey_from_csr() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        let creds = unwrap!(generator.generate_noc(&crypto, GOOD_CSR, 1, &[]));

        // Parse CSR to get public key
        let csr_ref = unwrap!(CsrRef::new(GOOD_CSR));
        let csr_pubkey = unwrap!(csr_ref.pubkey());

        // Parse NOC to get public key
        let cert_ref = CertRef::new(TLVElement::new(&creds.noc));
        let noc_pubkey = unwrap!(cert_ref.pubkey());

        // Public keys should match
        assert_eq!(noc_pubkey, csr_pubkey);
    }

    #[test]
    fn test_encode_serial_small_value() {
        // Serial = 1 should encode as [0x01]
        let encoded = NocGenerator::encode_serial_asn1(1);
        assert_eq!(encoded.as_slice(), &[0x01]);
    }

    #[test]
    fn test_encode_serial_no_leading_zeros() {
        // Serial = 256 (0x0100) should encode as [0x01, 0x00]
        let encoded = NocGenerator::encode_serial_asn1(256);
        assert_eq!(encoded.as_slice(), &[0x01, 0x00]);
    }

    #[test]
    fn test_encode_serial_large_value() {
        // Serial = 0x123456 should encode as [0x12, 0x34, 0x56]
        let encoded = NocGenerator::encode_serial_asn1(0x123456);
        assert_eq!(encoded.as_slice(), &[0x12, 0x34, 0x56]);
    }

    #[test]
    fn test_encode_serial_strips_leading_zeros() {
        // Serial = 0x00000100 should strip leading zeros to [0x01, 0x00]
        let encoded = NocGenerator::encode_serial_asn1(0x100);
        assert_eq!(encoded.as_slice(), &[0x01, 0x00]);

        // Verify no leading zeros
        assert_ne!(encoded.as_slice(), &[0x00, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_serial_prepends_zero_when_needed() {
        // Serial = 0x8000 has high bit set, should prepend 0x00
        let encoded = NocGenerator::encode_serial_asn1(0x8000);
        assert_eq!(encoded.as_slice(), &[0x00, 0x80, 0x00]);

        // Serial = 0xFF00 should also prepend
        let encoded = NocGenerator::encode_serial_asn1(0xFF00);
        assert_eq!(encoded.as_slice(), &[0x00, 0xFF, 0x00]);
    }

    #[test]
    fn test_generate_noc_bad_signature_fails() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        // CSR with bad signature should fail verification
        let result = generator.generate_noc(&crypto, BAD_SIGNATURE_CSR, 1, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_noc_too_many_cat_ids_fails() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        // More than 3 CAT IDs should fail
        let too_many_cat_ids = [0x0001_0001, 0x0001_0002, 0x0001_0003, 0x0001_0004];

        let result = generator.generate_noc(&crypto, GOOD_CSR, 1, &too_many_cat_ids);
        assert!(result.is_err());
    }

    #[test]
    fn test_generated_rcac_can_be_parsed() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1234;
        let generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        let rcac = generator.root_cert();

        // Should be able to parse as TLV certificate
        let cert_ref = CertRef::new(TLVElement::new(rcac));

        // Should be able to extract fabric_id
        let parsed_fabric_id = unwrap!(cert_ref.get_fabric_id());
        assert_eq!(parsed_fabric_id, fabric_id);
    }

    #[test]
    fn test_generated_icac_can_be_parsed() {
        let crypto = test_only_crypto();
        let fabric_id = 0x5678;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        let icac = unwrap!(generator.generate_icac(&crypto));

        // Should be able to parse as TLV certificate
        let cert_ref = CertRef::new(TLVElement::new(icac));

        // Should be able to extract fabric_id
        let parsed_fabric_id = unwrap!(cert_ref.get_fabric_id());
        assert_eq!(parsed_fabric_id, fabric_id);
    }

    #[test]
    fn test_generated_noc_can_be_parsed() {
        let crypto = test_only_crypto();
        let fabric_id = 0xABCD;
        let mut generator = unwrap!(NocGenerator::new(&crypto, fabric_id));

        let node_id = 0x9999;
        let creds = unwrap!(generator.generate_noc(&crypto, GOOD_CSR, node_id, &[]));

        // Should be able to parse as TLV certificate
        let cert_ref = CertRef::new(TLVElement::new(&creds.noc));

        // Should be able to extract both fabric_id and node_id
        let parsed_fabric_id = unwrap!(cert_ref.get_fabric_id());
        let parsed_node_id = unwrap!(cert_ref.get_node_id());

        assert_eq!(parsed_fabric_id, fabric_id);
        assert_eq!(parsed_node_id, node_id);
    }
}
