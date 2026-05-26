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
//! Supports both Matter PKI shapes per spec §6.5:
//!
//! 1. **ICAC tier** (recommended for any real deployment) — NOCs are
//!    signed by an ICAC, the ICAC is signed by an RCAC, and the RCAC
//!    private key is **not** held by the running controller. Only the
//!    ICAC private key sits in [`NocGenerator`]. This matches the
//!    real-world model where the RCAC key lives in an HSM and is
//!    used only at chain-bootstrap time. See [`Self::new_icac_signed`].
//!
//! 2. **RCAC-direct** (simpler, fine for small / test setups) — NOCs
//!    are signed directly by the RCAC; the controller holds the RCAC
//!    private key. See [`Self::new_rcac_signed`].
//!
//! Either way, the cert *bytes* (RCAC, optional ICAC) are NOT stored
//! here — the caller owns them, typically by installing them in
//! [`crate::fabric::Fabric`] via [`crate::fabric::Fabrics::add`].

use crate::cert::builder::{IcacBuilder, IssuerDN, NocBuilder, RcacBuilder, SubjectDN, Validity};
use crate::cert::x509::csr::CsrRef;
use crate::cert::{MAX_CERT_TLV_AND_ASN1_LEN, MAX_CERT_TLV_LEN};
use crate::crypto::{
    CanonPkcPublicKey, CanonPkcPublicKeyRef, CanonPkcSecretKey, CanonPkcSecretKeyRef, Crypto,
    PublicKey, RngCore, SecretKey, SigningSecretKey,
};
use crate::error::{Error, ErrorCode};

/// NOC issuer for a single Matter fabric.
///
/// Holds the NOC-signing private key — either the RCAC private key
/// (RCAC-direct mode) or the ICAC private key (ICAC-tier mode),
/// depending on the constructor that produced it. The [`Self::icac_id`]
/// accessor is the discriminator: `None` ⇒ RCAC-direct, `Some(_)` ⇒
/// ICAC-tier.
pub struct NocGenerator {
    /// Private key that signs each NOC's `signature` field.
    signing_privkey: CanonPkcSecretKey,
    /// Public key paired with `signing_privkey`. Stamped into every
    /// NOC's issuer-pubkey TBS slot.
    signing_pubkey: CanonPkcPublicKey,
    /// Fabric ID — embedded in every NOC's subject + issuer DN.
    fabric_id: u64,
    /// RCAC subject ID. Always tracked (it's part of the persisted
    /// fabric identity), but only used as an *issuer* DN if there's
    /// no ICAC tier (`icac_id == None`).
    rcac_id: u64,
    /// ICAC subject ID. `None` ⇒ RCAC-direct mode; `Some(_)` ⇒
    /// ICAC-tier mode.
    icac_id: Option<u64>,
    /// Monotonic NOC serial counter (scoped to this issuer).
    next_serial: u64,
    /// Default validity period applied to every issued NOC.
    validity: Validity,
}

impl NocGenerator {
    /// **ICAC tier** (recommended). Build a fresh RCAC + ICAC chain.
    /// The RCAC private key is used **once** to sign the ICAC, then
    /// dropped — only the ICAC private key is retained. Subsequent
    /// [`Self::generate_noc`] calls produce NOCs signed by the ICAC,
    /// yielding the spec-standard `[RCAC, ICAC, NOC]` chain.
    ///
    /// Returns the configured generator alongside the RCAC and ICAC
    /// TLV byte blobs. The caller installs **both** in the fabric
    /// table via `Fabrics::add(..., rcac, ..., icac, ...)`.
    pub fn new_icac_signed<C: Crypto>(
        crypto: C,
        fabric_id: u64,
        validity: Validity,
    ) -> Result<
        (
            Self,
            heapless::Vec<u8, MAX_CERT_TLV_LEN>,
            heapless::Vec<u8, MAX_CERT_TLV_LEN>,
        ),
        Error,
    > {
        // Random 64-bit subject IDs for RCAC and ICAC. They live in
        // different DN-tag slots so collision doesn't matter, but
        // we keep them independent for clarity.
        let rcac_id = Self::random_id(&crypto)?;
        let icac_id = Self::random_id(&crypto)?;

        // Ephemeral RCAC keypair — discarded at the end of this fn.
        let rcac_key = crypto.generate_secret_key()?;

        // Build the self-signed RCAC.
        let mut serial_bytes = [0u8; 8];
        crypto.rand()?.fill_bytes(&mut serial_bytes);
        let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let rcac_len = RcacBuilder::new(&mut rcac_buf).build(
            &crypto,
            SubjectDN {
                node_id: None,
                fabric_id: Some(fabric_id),
                cat_ids: &[],
                ca_id: Some(rcac_id),
            },
            validity,
            &rcac_key.pub_key()?,
            &rcac_key,
            &serial_bytes,
        )?;
        let mut rcac = heapless::Vec::new();
        rcac.extend_from_slice(&rcac_buf[..rcac_len])
            .map_err(|_| Error::from(ErrorCode::BufferTooSmall))?;

        // Generate the ICAC keypair (retained).
        let icac_key = crypto.generate_secret_key()?;
        let mut signing_pubkey = CanonPkcPublicKey::new();
        icac_key.pub_key()?.write_canon(&mut signing_pubkey)?;
        let mut signing_privkey = CanonPkcSecretKey::new();
        icac_key.write_canon(&mut signing_privkey)?;

        // Build the ICAC, signed by the RCAC. Use serial=1 (under
        // RCAC's scope, separate from the NOC serial counter under
        // ICAC's scope below).
        let icac_serial = Self::encode_serial_asn1(1);
        let mut icac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let icac_len = IcacBuilder::new(&mut icac_buf).build(
            &crypto,
            SubjectDN {
                node_id: None,
                fabric_id: Some(fabric_id),
                cat_ids: &[],
                ca_id: Some(icac_id),
            },
            validity,
            &icac_key.pub_key()?,
            &rcac_key.pub_key()?,
            &rcac_key,
            icac_serial.as_slice(),
            IssuerDN {
                ca_id: Some(rcac_id),
                fabric_id: Some(fabric_id),
                is_rcac: true,
            },
        )?;
        let mut icac = heapless::Vec::new();
        icac.extend_from_slice(&icac_buf[..icac_len])
            .map_err(|_| Error::from(ErrorCode::BufferTooSmall))?;

        // `rcac_key` (the RCAC private key) is dropped here — we do
        // not retain it. Only `signing_privkey` (the ICAC private
        // key) is held by `Self` from this point on.
        drop(rcac_key);

        Ok((
            Self {
                signing_privkey,
                signing_pubkey,
                fabric_id,
                rcac_id,
                icac_id: Some(icac_id),
                next_serial: 1,
                validity,
            },
            rcac,
            icac,
        ))
    }

    /// **RCAC-direct** (simpler, less production-realistic). Build a
    /// fresh self-signed RCAC and **retain** its private key.
    /// Subsequent [`Self::generate_noc`] calls produce NOCs signed
    /// directly by the RCAC, yielding the shorter `[RCAC, NOC]` chain.
    ///
    /// Returns the configured generator alongside the RCAC TLV bytes.
    /// Fine for tests and small deployments; not appropriate where the
    /// RCAC private key shouldn't live on the running controller
    /// (most real fabrics) — use [`Self::new_icac_signed`] for that.
    pub fn new_rcac_signed<C: Crypto>(
        crypto: C,
        fabric_id: u64,
        validity: Validity,
    ) -> Result<(Self, heapless::Vec<u8, MAX_CERT_TLV_LEN>), Error> {
        let rcac_id = Self::random_id(&crypto)?;

        let root_key = crypto.generate_secret_key()?;
        let mut signing_pubkey = CanonPkcPublicKey::new();
        root_key.pub_key()?.write_canon(&mut signing_pubkey)?;
        let mut signing_privkey = CanonPkcSecretKey::new();
        root_key.write_canon(&mut signing_privkey)?;

        let mut serial_bytes = [0u8; 8];
        crypto.rand()?.fill_bytes(&mut serial_bytes);
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
            &root_key,
            &serial_bytes,
        )?;

        let mut rcac = heapless::Vec::new();
        rcac.extend_from_slice(&cert_buf[..cert_len])
            .map_err(|_| Error::from(ErrorCode::BufferTooSmall))?;

        Ok((
            Self {
                signing_privkey,
                signing_pubkey,
                fabric_id,
                rcac_id,
                icac_id: None,
                next_serial: 1,
                validity,
            },
            rcac,
        ))
    }

    /// Restore an **ICAC-tier** generator from previously-persisted
    /// material. Counterpart of [`Self::new_icac_signed`].
    pub fn from_persisted_icac_signed<C: Crypto>(
        crypto: C,
        icac_privkey: CanonPkcSecretKey,
        fabric_id: u64,
        rcac_id: u64,
        icac_id: u64,
        validity: Validity,
    ) -> Result<Self, Error> {
        let icac_key = crypto.secret_key(icac_privkey.reference())?;
        let mut signing_pubkey = CanonPkcPublicKey::new();
        icac_key.pub_key()?.write_canon(&mut signing_pubkey)?;
        Ok(Self {
            signing_privkey: icac_privkey,
            signing_pubkey,
            fabric_id,
            rcac_id,
            icac_id: Some(icac_id),
            next_serial: 1,
            validity,
        })
    }

    /// Restore an **RCAC-direct** generator from previously-persisted
    /// material. Counterpart of [`Self::new_rcac_signed`].
    pub fn from_persisted_rcac_signed<C: Crypto>(
        crypto: C,
        rcac_privkey: CanonPkcSecretKey,
        fabric_id: u64,
        rcac_id: u64,
        validity: Validity,
    ) -> Result<Self, Error> {
        let root_key = crypto.secret_key(rcac_privkey.reference())?;
        let mut signing_pubkey = CanonPkcPublicKey::new();
        root_key.pub_key()?.write_canon(&mut signing_pubkey)?;
        Ok(Self {
            signing_privkey: rcac_privkey,
            signing_pubkey,
            fabric_id,
            rcac_id,
            icac_id: None,
            next_serial: 1,
            validity,
        })
    }

    /// Issue an NOC for a device whose pubkey the supplied CSR
    /// carries. Signed by the ICAC (ICAC-tier mode) or the RCAC
    /// (RCAC-direct mode); the issuer DN is set accordingly.
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

        let signing_key = crypto.secret_key(self.signing_privkey.reference())?;
        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];

        // Issuer DN switches on whether we're signing as ICAC or RCAC.
        let (issuer_ca_id, is_rcac) = match self.icac_id {
            Some(icac_id) => (icac_id, false),
            None => (self.rcac_id, true),
        };

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
            &crypto.pub_key(self.signing_pubkey.reference())?,
            &signing_key,
            serial_bytes,
            IssuerDN {
                ca_id: Some(issuer_ca_id),
                fabric_id: Some(self.fabric_id),
                is_rcac,
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

    /// `Some(_)` ⇒ ICAC tier (signing key is the ICAC priv key);
    /// `None` ⇒ RCAC-direct (signing key is the RCAC priv key).
    pub fn icac_id(&self) -> Option<u64> {
        self.icac_id
    }

    /// Reference to the NOC-signing private key — either RCAC or
    /// ICAC depending on construction mode. For persistence only;
    /// treat as highly sensitive (it can sign new fabric members).
    pub fn signing_secret_key(&self) -> CanonPkcSecretKeyRef<'_> {
        self.signing_privkey.reference()
    }

    fn random_id<C: Crypto>(crypto: &C) -> Result<u64, Error> {
        let mut bytes = [0u8; 8];
        crypto.rand()?.fill_bytes(&mut bytes);
        Ok(u64::from_be_bytes(bytes))
    }

    /// ASN.1 DER `INTEGER` encoding of a 64-bit serial per X.690
    /// §8.3 — strip leading zero bytes, then prepend a single `0x00`
    /// if the top bit of the result is set (to keep the value positive).
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

    fn node_id_from(noc: &[u8]) -> Result<u64, Error> {
        CertRef::new(TLVElement::new(noc)).get_node_id()
    }

    fn fabric_id_from(noc: &[u8]) -> Result<u64, Error> {
        CertRef::new(TLVElement::new(noc)).get_fabric_id()
    }

    #[test]
    fn rcac_signed_returns_only_rcac() {
        let crypto = test_only_crypto();
        let (gen, rcac) = unwrap!(NocGenerator::new_rcac_signed(
            &crypto,
            0x1u64,
            VALID_FOREVER
        ));
        assert!(!rcac.is_empty());
        assert_eq!(gen.fabric_id(), 0x1);
        assert!(gen.icac_id().is_none());
    }

    #[test]
    fn icac_signed_returns_rcac_and_icac() {
        let crypto = test_only_crypto();
        let (gen, rcac, icac) = unwrap!(NocGenerator::new_icac_signed(
            &crypto,
            0x1u64,
            VALID_FOREVER
        ));
        assert!(!rcac.is_empty());
        assert!(!icac.is_empty());
        assert!(gen.icac_id().is_some());
    }

    #[test]
    fn rcac_signed_noc_carries_correct_ids() {
        let crypto = test_only_crypto();
        let fabric_id = 0xABCDEF123456u64;
        let (mut gen, _rcac) = unwrap!(NocGenerator::new_rcac_signed(
            &crypto,
            fabric_id,
            VALID_FOREVER
        ));

        let noc = unwrap!(gen.generate_noc(&crypto, GOOD_CSR, 0x42, &[]));

        assert_eq!(unwrap!(node_id_from(&noc)), 0x42);
        assert_eq!(unwrap!(fabric_id_from(&noc)), fabric_id);
    }

    #[test]
    fn icac_signed_noc_carries_correct_ids() {
        let crypto = test_only_crypto();
        let fabric_id = 0xABCDEF123456u64;
        let (mut gen, _rcac, _icac) = unwrap!(NocGenerator::new_icac_signed(
            &crypto,
            fabric_id,
            VALID_FOREVER
        ));

        let noc = unwrap!(gen.generate_noc(&crypto, GOOD_CSR, 0x42, &[]));

        assert_eq!(unwrap!(node_id_from(&noc)), 0x42);
        assert_eq!(unwrap!(fabric_id_from(&noc)), fabric_id);
    }

    #[test]
    fn invalid_csr_rejected() {
        let crypto = test_only_crypto();
        let (mut gen, _rcac) = unwrap!(NocGenerator::new_rcac_signed(
            &crypto,
            0x1u64,
            VALID_FOREVER
        ));
        assert!(gen
            .generate_noc(&crypto, &[0x01, 0x02, 0x03], 1, &[])
            .is_err());
    }

    #[test]
    fn too_many_cat_ids_rejected() {
        let crypto = test_only_crypto();
        let (mut gen, _rcac) = unwrap!(NocGenerator::new_rcac_signed(
            &crypto,
            0x1u64,
            VALID_FOREVER
        ));
        let too_many = &[1u32, 2, 3, 4];
        assert!(gen.generate_noc(&crypto, GOOD_CSR, 1, too_many).is_err());
    }
}
