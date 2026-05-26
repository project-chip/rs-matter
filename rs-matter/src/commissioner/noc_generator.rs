/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! Controller-side signing material for issuing operational
//! certificates (NOCs).
//!
//! Holds the Root CA private signing key + the per-fabric metadata
//! needed to mint NOCs (fabric ID, RCAC subject ID, monotonic serial
//! counter, default validity). The corresponding **cert bytes** (RCAC)
//! are NOT stored here — the caller owns the bytes (typically by
//! installing them in [`crate::fabric::Fabric`] via
//! [`crate::fabric::Fabrics::add`]).
//!
//! ICAC support is intentionally omitted in this slice: rs-matter
//! controllers commission directly off the RCAC. A two-tier hierarchy
//! can be added later without breaking this API.

use crate::cert::builder::{IssuerDN, NocBuilder, RcacBuilder, SubjectDN, Validity};
use crate::cert::x509::csr::CsrRef;
use crate::cert::{MAX_CERT_TLV_AND_ASN1_LEN, MAX_CERT_TLV_LEN};
use crate::crypto::{
    CanonPkcPublicKey, CanonPkcPublicKeyRef, CanonPkcSecretKey, CanonPkcSecretKeyRef, Crypto,
    PublicKey, RngCore, SecretKey, SigningSecretKey,
};
use crate::error::{Error, ErrorCode};

/// NOC issuer for a single Matter fabric.
///
/// Stateful only in the controller's monotonic serial counter; the
/// signing key + IDs are immutable after construction.
pub struct NocGenerator {
    /// Root CA private key
    root_privkey: CanonPkcSecretKey,
    /// Root CA public key
    root_pubkey: CanonPkcPublicKey,
    /// Fabric ID for this generator
    fabric_id: u64,
    /// RCAC ID
    rcac_id: u64,
    /// Next serial number for certificates
    next_serial: u64,
    /// Validity period for certificates
    validity: Validity,
}

impl NocGenerator {
    /// Generate a fresh Root CA: P-256 keypair + self-signed RCAC.
    ///
    /// Returns the configured generator alongside the RCAC TLV bytes.
    /// The caller is responsible for installing the RCAC bytes in the
    /// fabric table (see [`crate::fabric::Fabrics::add`]).
    pub fn new<C: Crypto>(
        crypto: C,
        fabric_id: u64,
        validity: Validity,
    ) -> Result<(Self, heapless::Vec<u8, MAX_CERT_TLV_LEN>), Error> {
        // Per-fabric RCAC subject ID — random 64-bit value, scoped to
        // the fabric. Embedded in the RCAC subject DN (and echoed in
        // every NOC's `Issuer.ca_id`).
        let mut rcac_id_bytes = [0u8; 8];
        crypto.rand()?.fill_bytes(&mut rcac_id_bytes);
        let rcac_id = u64::from_be_bytes(rcac_id_bytes);

        let root_key = crypto.generate_secret_key()?;
        let mut root_pubkey = CanonPkcPublicKey::new();
        root_key.pub_key()?.write_canon(&mut root_pubkey)?;
        let mut root_privkey = CanonPkcSecretKey::new();
        root_key.write_canon(&mut root_privkey)?;

        // RCAC serial — also random; cert chain validation only cares
        // about uniqueness within the issuer's scope.
        let mut serial_bytes = [0u8; 8];
        crypto.rand()?.fill_bytes(&mut serial_bytes);

        let signing_key = crypto.secret_key(root_privkey.reference())?;
        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];

        let cert_len = RcacBuilder::new(&mut cert_buf).build(
            &crypto,
            SubjectDN {
                node_id: None,
                fabric_id: Some(fabric_id),
                cat_ids: &[],
                ca_id: Some(rcac_id),
            },
            validity,
            &root_key.pub_key()?,
            &signing_key,
            &serial_bytes,
        )?;

        let mut rcac = heapless::Vec::new();
        rcac.extend_from_slice(&cert_buf[..cert_len])
            .map_err(|_| Error::from(ErrorCode::BufferTooSmall))?;

        Ok((
            Self {
                root_privkey,
                root_pubkey,
                fabric_id,
                rcac_id,
                next_serial: 1,
                validity,
            },
            rcac,
        ))
    }

    /// Restore a generator from previously-persisted Root CA material.
    /// Pair with [`Self::root_secret_key`] / [`Self::rcac_id`] /
    /// [`Self::fabric_id`] snapshots taken before shutdown.
    pub fn from_root_ca<C: Crypto>(
        crypto: C,
        root_privkey: CanonPkcSecretKey,
        fabric_id: u64,
        rcac_id: u64,
        validity: Validity,
    ) -> Result<Self, Error> {
        let root_key = crypto.secret_key(root_privkey.reference())?;
        let mut root_pubkey = CanonPkcPublicKey::new();
        root_key.pub_key()?.write_canon(&mut root_pubkey)?;
        Ok(Self {
            root_privkey,
            root_pubkey,
            fabric_id,
            rcac_id,
            next_serial: 1,
            validity,
        })
    }

    /// Issue an NOC for a device whose public key the supplied CSR
    /// carries. The NOC's subject is `(fabric_id, node_id, cat_ids)`
    /// and the issuer is the configured RCAC.
    pub fn generate_noc<C: Crypto>(
        &mut self,
        crypto: C,
        csr: &[u8],
        node_id: u64,
        cat_ids: &[u32],
    ) -> Result<heapless::Vec<u8, MAX_CERT_TLV_LEN>, Error> {
        let csr_ref = CsrRef::new(csr)?;
        let device_pubkey = csr_ref.pubkey()?;
        csr_ref.verify(&crypto)?;

        let serial_bytes_vec = Self::encode_serial_asn1(self.next_serial());
        let serial_bytes = serial_bytes_vec.as_slice();

        let signing_key = crypto.secret_key(self.root_privkey.reference())?;
        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];

        let cert_len = NocBuilder::new(&mut cert_buf).build(
            &crypto,
            SubjectDN {
                node_id: Some(node_id),
                fabric_id: Some(self.fabric_id),
                cat_ids,
                ca_id: None,
            },
            self.validity,
            &crypto.pub_key(CanonPkcPublicKeyRef::try_new(&device_pubkey)?)?,
            &crypto.pub_key(self.root_pubkey.reference())?,
            &signing_key,
            serial_bytes,
            IssuerDN {
                ca_id: Some(self.rcac_id),
                fabric_id: Some(self.fabric_id),
                is_rcac: true,
            },
        )?;

        let mut noc = heapless::Vec::new();
        noc.extend_from_slice(&cert_buf[..cert_len])
            .map_err(|_| Error::from(ErrorCode::BufferTooSmall))?;
        Ok(noc)
    }

    pub fn fabric_id(&self) -> u64 {
        self.fabric_id
    }

    pub fn rcac_id(&self) -> u64 {
        self.rcac_id
    }

    /// Reference to the Root CA private key — for persistence only.
    /// Treat as highly sensitive: it's the trust anchor for the fabric.
    pub fn root_secret_key(&self) -> CanonPkcSecretKeyRef<'_> {
        self.root_privkey.reference()
    }

    /// ASN.1 DER `INTEGER` encoding of a 64-bit serial number per
    /// X.690 §8.3 — strip leading zero bytes, then prepend a single
    /// `0x00` if the top bit of the result is set (to keep the value
    /// positive).
    fn encode_serial_asn1(serial: u64) -> heapless::Vec<u8, 9> {
        let serial_bytes_full = serial.to_be_bytes();
        let start = serial_bytes_full
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(serial_bytes_full.len() - 1);
        let stripped = &serial_bytes_full[start..];

        let mut vec = heapless::Vec::<u8, 9>::new();
        if !stripped.is_empty() && (stripped[0] & 0x80) != 0 {
            vec.push(0).unwrap();
        }
        vec.extend_from_slice(stripped).unwrap();
        vec
    }

    fn next_serial(&mut self) -> u64 {
        let serial = self.next_serial;
        self.next_serial += 1;
        serial
    }
}

#[cfg(test)]
mod tests {
    use crate::cert::builder::VALID_FOREVER;
    use crate::cert::CertRef;
    use crate::crypto::test_only_crypto;
    use crate::tlv::TLVElement;

    use super::*;

    /// Known valid CSR from C++ test vectors (TestChipCryptoPAL.cpp).
    /// Signature verifies under its embedded P-256 pubkey.
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

    fn extract_node_id_from_noc(noc_tlv: &[u8]) -> Result<u64, Error> {
        CertRef::new(TLVElement::new(noc_tlv)).get_node_id()
    }

    fn extract_fabric_id_from_noc(noc_tlv: &[u8]) -> Result<u64, Error> {
        CertRef::new(TLVElement::new(noc_tlv)).get_fabric_id()
    }

    fn extract_cat_ids_from_noc(noc_tlv: &[u8]) -> Result<[u32; 3], Error> {
        let mut cat_ids = [0u32; 3];
        CertRef::new(TLVElement::new(noc_tlv)).get_cat_ids(&mut cat_ids)?;
        Ok(cat_ids)
    }

    #[test]
    fn new_returns_rcac_bytes() {
        let crypto = test_only_crypto();
        let (gen, rcac) = unwrap!(NocGenerator::new(&crypto, 0x1u64, VALID_FOREVER));
        assert!(!rcac.is_empty());
        assert_eq!(gen.fabric_id(), 0x1);
        // RCAC ID is random — just ensure it's been initialised.
        let _ = gen.rcac_id();
    }

    #[test]
    fn generates_noc_with_correct_subject() {
        let crypto = test_only_crypto();
        let fabric_id = 0xABCDEF123456u64;
        let (mut gen, _rcac) = unwrap!(NocGenerator::new(&crypto, fabric_id, VALID_FOREVER));

        let noc = unwrap!(gen.generate_noc(&crypto, GOOD_CSR, 0x42, &[]));

        assert_eq!(unwrap!(extract_node_id_from_noc(&noc)), 0x42);
        assert_eq!(unwrap!(extract_fabric_id_from_noc(&noc)), fabric_id);
    }

    #[test]
    fn cat_ids_embedded_in_noc() {
        let crypto = test_only_crypto();
        let (mut gen, _rcac) = unwrap!(NocGenerator::new(&crypto, 0x1u64, VALID_FOREVER));
        let cat_ids = &[0x00011111u32, 0x00022222u32, 0x00033333u32];

        let noc = unwrap!(gen.generate_noc(&crypto, GOOD_CSR, 1, cat_ids));

        let parsed = unwrap!(extract_cat_ids_from_noc(&noc));
        assert_eq!(parsed, *cat_ids);
    }

    #[test]
    fn invalid_csr_rejected() {
        let crypto = test_only_crypto();
        let (mut gen, _rcac) = unwrap!(NocGenerator::new(&crypto, 0x1u64, VALID_FOREVER));
        assert!(gen
            .generate_noc(&crypto, &[0x01, 0x02, 0x03], 1, &[])
            .is_err());
    }

    #[test]
    fn too_many_cat_ids_rejected() {
        let crypto = test_only_crypto();
        let (mut gen, _rcac) = unwrap!(NocGenerator::new(&crypto, 0x1u64, VALID_FOREVER));
        let too_many = &[1u32, 2, 3, 4];
        assert!(gen.generate_noc(&crypto, GOOD_CSR, 1, too_many).is_err());
    }
}
