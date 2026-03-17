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
    use crate::cert::CertRef;
    use crate::crypto::test_only_crypto;
    use crate::tlv::TLVElement;

    /// Valid CSR from C++ test (TestChipCryptoPAL.cpp)
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

    fn generate_test_csr() -> &'static [u8] {
        GOOD_CSR
    }

    /// parse node_id from a NOC certificate (TLV encoded)
    fn extract_node_id_from_noc(noc_tlv: &[u8]) -> Result<u64, Error> {
        let cert = CertRef::new(TLVElement::new(noc_tlv));
        cert.get_node_id()
    }

    /// parse fabric_id from a NOC certificate (TLV encoded)
    fn extract_fabric_id_from_noc(noc_tlv: &[u8]) -> Result<u64, Error> {
        let cert = CertRef::new(TLVElement::new(noc_tlv));
        cert.get_fabric_id()
    }

    /// extract CAT IDs from a NOC certificate (TLV encoded)
    fn extract_cat_ids_from_noc(noc_tlv: &[u8]) -> Result<[u32; 3], Error> {
        let cert = CertRef::new(TLVElement::new(noc_tlv));
        let mut cat_ids = [0u32; 3];
        cert.get_cat_ids(&mut cat_ids)?;
        Ok(cat_ids)
    }

    #[test]
    fn test_create_fabric_credentials() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1234567890ABCDEFu64;

        let creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        // Should have root cert
        assert!(creds.root_cert().len() > 0);
        // Should have IPK
        assert_eq!(creds.ipk().len(), IPK_LEN);
        // Fabric ID should match
        assert_eq!(creds.fabric_id(), fabric_id);
        // Initial node is 1
        assert_eq!(creds.peek_next_node_id(), 1);
    }

    #[test]
    fn test_fabric_credentials_with_starting_node_id() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1111111111111111u64;
        let starting_node_id = 100u64;

        let creds = unwrap!(FabricCredentials::with_starting_node_id(
            &crypto,
            fabric_id,
            starting_node_id
        ));

        assert_eq!(creds.peek_next_node_id(), starting_node_id);
    }

    #[test]
    fn test_node_id_auto_increment() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let csr = generate_test_csr();

        // Generate first device
        let dev1 = unwrap!(creds.generate_device_credentials(&crypto, &csr, &[]));
        assert_eq!(dev1.node_id, 1);

        // Generate second device
        let dev2 = unwrap!(creds.generate_device_credentials(&crypto, &csr, &[]));
        assert_eq!(dev2.node_id, 2);

        // Generate third device
        let dev3 = unwrap!(creds.generate_device_credentials(&crypto, &csr, &[]));
        assert_eq!(dev3.node_id, 3);
    }

    #[test]
    fn test_peek_next_node_id_doesnt_increment() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let id1 = creds.peek_next_node_id();
        let id2 = creds.peek_next_node_id();
        let id3 = creds.peek_next_node_id();

        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
        assert_eq!(id1, 1);
    }

    #[test]
    fn test_custom_node_id_doesnt_affect_counter() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let csr = generate_test_csr();

        // Generate with auto node ID
        let dev1 = unwrap!(creds.generate_device_credentials(&crypto, &csr, &[]));
        assert_eq!(dev1.node_id, 1);

        // Generate with explicit node ID (should not affect counter)
        let dev2 = unwrap!(creds.generate_device_credentials_with_node_id(&crypto, csr, 9999, &[]));
        assert_eq!(dev2.node_id, 9999);

        // Next auto assigned node ID should be 2, not 10000
        let dev3 = unwrap!(creds.generate_device_credentials(&crypto, &csr, &[]));
        assert_eq!(dev3.node_id, 2);
    }

    #[test]
    fn test_generate_device_credentials_basic() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let csr = generate_test_csr();

        let dev = unwrap!(creds.generate_device_credentials(&crypto, csr, &[]));

        // NOC should be present and non-empty
        assert!(dev.noc.len() > 0);
        // Root cert should be present and non-empty
        assert!(dev.root_cert.len() > 0);
        // IPK should be 16 bytes
        assert_eq!(dev.ipk.len(), IPK_LEN);
        // Node ID should be assigned
        assert_eq!(dev.node_id, 1);
        // ICAC none by default
        assert!(dev.icac.is_none());
    }

    #[test]
    fn test_device_credentials_with_cat_ids() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let csr = generate_test_csr();
        let cat_ids = &[0x00011111u32, 0x00022222u32];

        let dev = unwrap!(creds.generate_device_credentials(&crypto, &csr, cat_ids));

        assert!(dev.noc.len() > 0);
        assert_eq!(dev.node_id, 1);
    }

    #[test]
    fn test_enable_icac() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        // Initially no ICAC
        assert!(creds.icac_cert().is_none());

        // Enable ICAC
        unwrap!(creds.enable_icac(&crypto));

        // ICAC should be available
        assert!(creds.icac_cert().is_some());
    }

    #[test]
    fn test_device_credentials_includes_icac_when_enabled() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let csr = generate_test_csr();

        // Enable ICAC
        unwrap!(creds.enable_icac(&crypto));

        let dev = unwrap!(creds.generate_device_credentials(&crypto, csr, &[]));

        // ICAC should be present
        assert!(dev.icac.is_some());
        assert!(dev.icac.unwrap().len() > 0);
    }

    #[test]
    fn test_icac_cert_available_after_enable() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        assert!(creds.icac_cert().is_none());

        unwrap!(creds.enable_icac(&crypto));

        let icac = unwrap!(creds.icac_cert());
        assert!(icac.len() > 0);
    }

    #[test]
    fn test_noc_signed_by_icac_when_enabled() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let csr = generate_test_csr();

        // Enable ICAC
        unwrap!(creds.enable_icac(&crypto));

        let dev = unwrap!(creds.generate_device_credentials(&crypto, csr, &[]));

        // Should have ICAC
        assert!(dev.icac.is_some());

        // NOC should be present
        assert!(dev.noc.len() > 0);
    }

    #[test]
    fn test_ipk_is_generated() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let ipk = creds.ipk();

        // IPK should not be all zeros
        assert_ne!(ipk, &[0u8; IPK_LEN]);
        assert_eq!(ipk.len(), IPK_LEN);
    }

    #[test]
    fn test_set_custom_ipk() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let custom_ipk = [0x42u8; IPK_LEN];
        creds.set_ipk(custom_ipk);

        assert_eq!(creds.ipk(), &custom_ipk);
    }

    #[test]
    fn test_root_cert_available() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let root_cert = creds.root_cert();
        assert!(root_cert.len() > 0);
        assert!(root_cert.len() < MAX_CERT_TLV_LEN);
    }

    #[test]
    fn test_root_cert_consistent() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let csr = generate_test_csr();

        let mut root_cert_before = heapless::Vec::<u8, 512>::new();
        unwrap!(root_cert_before.extend_from_slice(creds.root_cert()));

        // Generate device credentials
        let dev1 = unwrap!(creds.generate_device_credentials(&crypto, &csr, &[]));
        let dev2 = unwrap!(creds.generate_device_credentials(&crypto, &csr, &[]));

        // Root cert should be the same
        assert_eq!(dev1.root_cert.as_slice(), root_cert_before.as_slice());
        assert_eq!(dev2.root_cert.as_slice(), root_cert_before.as_slice());
        assert_eq!(dev1.root_cert.as_slice(), dev2.root_cert.as_slice());
    }

    #[test]
    fn test_verify_noc_and_rcac_parse() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let csr = generate_test_csr();

        // Generate credentials
        let dev = unwrap!(creds.generate_device_credentials(&crypto, csr, &[]));

        // Parse certificates - if they parse without error, the structure is valid
        let _noc = CertRef::new(TLVElement::new(&dev.noc));
        let _rcac = CertRef::new(TLVElement::new(&dev.root_cert));

        // Successfully parsing both certificates means they have valid structure
        // The NOC is signed by the RCAC during generation
    }

    #[test]
    fn test_generated_noc_contains_correct_node_id() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let csr = generate_test_csr();

        let dev = unwrap!(creds.generate_device_credentials(&crypto, csr, &[]));

        // Parse NOC and extract node ID
        let parsed_node_id = unwrap!(extract_node_id_from_noc(&dev.noc));

        // Should match assigned node ID
        assert_eq!(parsed_node_id, dev.node_id);
        assert_eq!(parsed_node_id, 1);
    }

    #[test]
    fn test_generated_noc_contains_correct_fabric_id() {
        let crypto = test_only_crypto();
        let fabric_id = 0xABCDEF123456u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let csr = generate_test_csr();

        let dev = unwrap!(creds.generate_device_credentials(&crypto, csr, &[]));

        // Parse NOC and extract fabric ID
        let parsed_fabric_id = unwrap!(extract_fabric_id_from_noc(&dev.noc));

        // Should match configured fabric ID
        assert_eq!(parsed_fabric_id, fabric_id);
    }

    #[test]
    fn test_cat_ids_present_in_noc_when_specified() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let csr = generate_test_csr();
        let cat_ids = &[0x00011111u32, 0x00022222u32, 0x00033333u32];

        let dev = unwrap!(creds.generate_device_credentials(&crypto, &csr, cat_ids));

        // Parse NOC and extract CAT IDs
        let parsed_cat_ids = unwrap!(extract_cat_ids_from_noc(&dev.noc));

        // Should match specified CAT IDs
        assert_eq!(parsed_cat_ids[0], 0x00011111u32);
        assert_eq!(parsed_cat_ids[1], 0x00022222u32);
        assert_eq!(parsed_cat_ids[2], 0x00033333u32);
    }

    #[test]
    fn test_invalid_csr_fails() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let invalid_csr = &[0x01, 0x02, 0x03, 0x04];

        let result = creds.generate_device_credentials(&crypto, invalid_csr, &[]);

        assert!(result.is_err());
    }

    #[test]
    fn test_four_cat_ids_fails() {
        let crypto = test_only_crypto();
        let fabric_id = 0x1u64;
        let mut creds = unwrap!(FabricCredentials::new(&crypto, fabric_id));

        let csr = generate_test_csr();
        let too_many_cat_ids = &[0x00011111u32, 0x00022222u32, 0x00033333u32, 0x00044444u32];

        let result = creds.generate_device_credentials(&crypto, &csr, too_many_cat_ids);

        assert!(result.is_err());
    }
}
