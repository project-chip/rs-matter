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

use crate::cert::builder::{IcacBuilder, NocBuilder, RcacBuilder};
use crate::cert::csr::CsrRef;
use crate::cert::MAX_CERT_TLV_LEN;
use crate::crypto::{
    CanonPkcPublicKey, CanonPkcSecretKey, Crypto, PublicKey, RngCore, SecretKey, SigningSecretKey,
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
        let mut cert_buf = [0u8; MAX_CERT_TLV_LEN];

        // Load the secret key for signing
        let signing_key = crypto.secret_key(root_privkey.reference())?;

        let cert_len = RcacBuilder::new(&mut cert_buf).build(
            crypto,
            rcac_id,
            fabric_id,
            root_pubkey.access(),
            &signing_key,
            &serial_bytes,
            0, // not_before = 0 (epoch start)
            0, // not_after = 0 (no expiry)
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
        let mut cert_buf = [0u8; MAX_CERT_TLV_LEN];

        let root_signing_key = crypto.secret_key(self.root_privkey.reference())?;

        let cert_len = IcacBuilder::new(&mut cert_buf).build(
            crypto,
            icac_id,
            self.fabric_id,
            icac_pubkey.access(),
            self.root_pubkey.access(),
            &root_signing_key,
            serial_bytes,
            0,              // not_before
            0,              // not_after (no expiry)
            self.rcac_id,   // rcac_id
            self.fabric_id, // rcac_fabric_id
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
            (
                icac_privkey.clone(),
                self.icac_pubkey.as_ref().unwrap().clone(),
            )
        } else {
            (self.root_privkey.clone(), self.root_pubkey.clone())
        };

        // Build the NOC
        let mut cert_buf = [0u8; MAX_CERT_TLV_LEN];

        let signing_key = crypto.secret_key(signing_privkey.reference())?;

        // Determine issuer CA ID and whether issuer is RCAC
        let (issuer_ca_id, is_issuer_rcac) = if let Some(icac_id) = self.icac_id {
            (icac_id, false) // Signed by ICAC
        } else {
            (self.rcac_id, true) // Signed directly by RCAC
        };

        let cert_len = NocBuilder::new(&mut cert_buf).build(
            crypto,
            node_id,
            self.fabric_id,
            cat_ids,
            &device_pubkey,
            issuer_pubkey.access(),
            &signing_key,
            &serial_bytes,
            0, // not_before
            0, // not_after (no expiry)
            issuer_ca_id,
            self.fabric_id, // issuer_fabric_id
            is_issuer_rcac,
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
    // Integration tests would require a crypto backend
    // These would be placed in a test module with feature flags
}
