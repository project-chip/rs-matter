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

//! Fabric credential management for Matter commissioning.
//!
//! This module provides a high-level API for managing fabric credentials
//! during commissioning. It combines NOC generation with IPK management
//! and node ID assignment.

use crate::cert::MAX_CERT_TLV_LEN;
use crate::crypto::Crypto;
use crate::error::Error;

use super::ipk::{IpkEpochKey, IPK_LEN};
use super::noc_generator::NocGenerator;

/// Credentials to provision to a device via AddNOC.
///
/// This contains all the certificates and keys needed to add a device
/// to a fabric.
#[derive(Debug)]
pub struct DeviceCredentials {
    /// NOC certificate (TLV encoded)
    pub noc: heapless::Vec<u8, MAX_CERT_TLV_LEN>,
    /// ICAC certificate (TLV encoded, optional)
    pub icac: Option<heapless::Vec<u8, MAX_CERT_TLV_LEN>>,
    /// Root CA certificate (TLV encoded)
    pub root_cert: heapless::Vec<u8, MAX_CERT_TLV_LEN>,
    /// IPK value
    pub ipk: [u8; IPK_LEN],
    /// Assigned node ID
    pub node_id: u64,
}

/// Fabric credentials for commissioning devices.
///
/// This is the main high-level API for commissioners. It manages:
/// - The CA certificate chain (RCAC, optional ICAC)
/// - The IPK for the fabric
/// - Node ID assignment
///
/// # Example
///
/// ```ignore
/// // Create new fabric credentials
/// let mut creds = FabricCredentials::new(&crypto, fabric_id)?;
///
/// // Commission a device
/// let csr = device.csr_request(&crypto, nonce)?;
/// let device_creds = creds.generate_device_credentials(&crypto, &csr, &[])?;
///
/// // Use device_creds with AddNOC command
/// device.add_noc(
///     device_creds.noc,
///     device_creds.icac,
///     device_creds.ipk,
///     admin_subject,
///     vendor_id
/// )?;
/// device.add_trusted_root_certificate(device_creds.root_cert)?;
/// ```
pub struct FabricCredentials {
    /// NOC generator for this fabric
    noc_generator: NocGenerator,
    /// IPK for this fabric
    ipk: IpkEpochKey,
    /// Next node ID to assign
    next_node_id: u64,
}

impl FabricCredentials {
    /// Create new fabric credentials with a new Root CA.
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `fabric_id` - The fabric identifier
    pub fn new<C: Crypto>(crypto: &C, fabric_id: u64) -> Result<Self, Error> {
        let noc_generator = NocGenerator::new(crypto, fabric_id)?;
        let ipk = IpkEpochKey::generate(crypto)?;

        Ok(Self {
            noc_generator,
            ipk,
            next_node_id: 1,
        })
    }

    /// Create fabric credentials with a specific starting node ID.
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `fabric_id` - The fabric identifier
    /// * `starting_node_id` - The first node ID to assign
    pub fn with_starting_node_id<C: Crypto>(
        crypto: &C,
        fabric_id: u64,
        starting_node_id: u64,
    ) -> Result<Self, Error> {
        let mut creds = Self::new(crypto, fabric_id)?;
        creds.next_node_id = starting_node_id;
        Ok(creds)
    }

    /// Enable ICAC for this fabric.
    ///
    /// By default, NOCs are signed directly by the RCAC. Calling this method
    /// generates an ICAC and future NOCs will be signed by the ICAC instead.
    pub fn enable_icac<C: Crypto>(&mut self, crypto: &C) -> Result<(), Error> {
        self.noc_generator.generate_icac(crypto)?;
        Ok(())
    }

    /// Generate credentials for a new device.
    ///
    /// This method:
    /// 1. Parses and verifies the CSR
    /// 2. Assigns a node ID
    /// 3. Generates the NOC
    /// 4. Returns all credentials needed for AddNOC
    ///
    /// # Arguments
    /// * `crypto` - Cryptographic backend
    /// * `csr` - The device's Certificate Signing Request (DER encoded)
    /// * `cat_ids` - CASE Authentication Tags (up to 3)
    pub fn generate_device_credentials<C: Crypto>(
        &mut self,
        crypto: &C,
        csr: &[u8],
        cat_ids: &[u32],
    ) -> Result<DeviceCredentials, Error> {
        let node_id = self.next_node_id();

        let noc_creds = self
            .noc_generator
            .generate_noc(crypto, csr, node_id, cat_ids)?;

        // Copy root cert
        let mut root_cert = heapless::Vec::new();
        root_cert
            .extend_from_slice(self.noc_generator.root_cert())
            .map_err(|_| crate::error::ErrorCode::BufferTooSmall)?;

        // Copy ICAC if present
        let icac = if let Some(icac_slice) = self.noc_generator.icac_cert() {
            let mut icac_vec = heapless::Vec::new();
            icac_vec
                .extend_from_slice(icac_slice)
                .map_err(|_| crate::error::ErrorCode::BufferTooSmall)?;
            Some(icac_vec)
        } else {
            None
        };

        Ok(DeviceCredentials {
            noc: noc_creds.noc,
            icac,
            root_cert,
            ipk: *self.ipk.as_bytes(),
            node_id,
        })
    }

    /// Generate credentials for a device with a specific node ID.
    ///
    /// Use this when you want to assign a specific node ID rather than
    /// using auto-assignment.
    pub fn generate_device_credentials_with_node_id<C: Crypto>(
        &mut self,
        crypto: &C,
        csr: &[u8],
        node_id: u64,
        cat_ids: &[u32],
    ) -> Result<DeviceCredentials, Error> {
        let noc_creds = self
            .noc_generator
            .generate_noc(crypto, csr, node_id, cat_ids)?;

        // Copy root cert
        let mut root_cert = heapless::Vec::new();
        root_cert
            .extend_from_slice(self.noc_generator.root_cert())
            .map_err(|_| crate::error::ErrorCode::BufferTooSmall)?;

        // Copy ICAC if present
        let icac = if let Some(icac_slice) = self.noc_generator.icac_cert() {
            let mut icac_vec = heapless::Vec::new();
            icac_vec
                .extend_from_slice(icac_slice)
                .map_err(|_| crate::error::ErrorCode::BufferTooSmall)?;
            Some(icac_vec)
        } else {
            None
        };

        Ok(DeviceCredentials {
            noc: noc_creds.noc,
            icac,
            root_cert,
            ipk: *self.ipk.as_bytes(),
            node_id,
        })
    }

    /// Get the Root CA certificate.
    pub fn root_cert(&self) -> &[u8] {
        self.noc_generator.root_cert()
    }

    /// Get the ICAC certificate (if enabled).
    pub fn icac_cert(&self) -> Option<&[u8]> {
        self.noc_generator.icac_cert()
    }

    /// Get the IPK value for AddNOC.
    pub fn ipk(&self) -> &[u8; IPK_LEN] {
        self.ipk.as_bytes()
    }

    /// Get the fabric ID.
    pub fn fabric_id(&self) -> u64 {
        self.noc_generator.fabric_id()
    }

    /// Get the next node ID without incrementing.
    pub fn peek_next_node_id(&self) -> u64 {
        self.next_node_id
    }

    /// Get the next node ID and increment the counter.
    fn next_node_id(&mut self) -> u64 {
        let id = self.next_node_id;
        self.next_node_id += 1;
        id
    }

    /// Set the IPK to a specific value.
    ///
    /// Use this if you need to use a pre-existing IPK.
    pub fn set_ipk(&mut self, ipk: [u8; IPK_LEN]) {
        self.ipk = IpkEpochKey::from_bytes(ipk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipk_len() {
        assert_eq!(IPK_LEN, 16);
    }

    // Integration tests would require a crypto backend
}
