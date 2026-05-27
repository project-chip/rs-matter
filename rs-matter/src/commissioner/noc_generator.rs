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

//! Controller-side **NOC** (Node Operational Certificate) issuer.
//!
//! Issues NOCs against an already-existing CA chain. The chain itself
//! (RCAC + optional ICAC) is built by [`super::ca_chain`] — that
//! separation reflects the real-world flow: chain generation happens
//! once (often offline, with HSM-controlled RCAC keys), NOC signing
//! happens many times at runtime as new devices are commissioned.
//!
//! Supports both Matter PKI shapes per spec §6.5:
//!
//! 1. **ICAC tier** (recommended for any real deployment) — `icac_id`
//!    is `Some(_)`; the `signing_privkey` is the ICAC private key.
//!    NOCs ship as `[RCAC, ICAC, NOC]`. The RCAC private key is
//!    **not** held by the running controller.
//!
//! 2. **RCAC-direct** (simpler, fine for tests / small private
//!    deployments) — `icac_id` is `None`; the `signing_privkey` is
//!    the RCAC private key. NOCs ship as `[RCAC, NOC]`.

use core::num::NonZeroU8;

use crate::cert::builder::{IssuerDN, NocBuilder, SubjectDN, Validity};
use crate::cert::x509::csr::CsrRef;
use crate::cert::CertRef;
use crate::crypto::{CanonPkcPublicKey, CanonPkcSecretKeyRef, Crypto, PublicKey, SigningSecretKey};
use crate::error::{Error, ErrorCode};
use crate::tlv::TLVElement;
use crate::Matter;

/// NOC issuer for a single Matter fabric.
///
/// Stateless besides the monotonic serial counter — the signing key
/// and cached cert IDs are immutable after construction. Build via
/// [`Self::new`] from already-existing chain material (see the module
/// docs for how that chain is produced).
pub struct NocGenerator<'a> {
    /// Private key that signs each NOC's `signature` field.
    signing_privkey: CanonPkcSecretKeyRef<'a>,
    /// Cached fabric ID — read once from the supplied RCAC cert.
    fabric_id: u64,
    /// Cached RCAC subject ID. Used as issuer DN when this generator
    /// signs NOCs in RCAC-direct mode (`icac_id == None`); tracked
    /// in both modes for diagnostics.
    rcac_id: u64,
    /// Cached ICAC subject ID. `None` ⇒ RCAC-direct mode (signing
    /// key is the RCAC priv key); `Some(_)` ⇒ ICAC-tier mode (signing
    /// key is the ICAC priv key, this is the ICAC's subject ID, and
    /// becomes the issuer DN on each NOC).
    icac_id: Option<u64>,
    /// A buffer supplied by the caller that the generator can use for
    /// scratch space when building certs.
    buf: &'a mut [u8],
}

impl<'a> NocGenerator<'a> {
    pub fn new(
        matter: &Matter<'_>,
        signing_privkey: CanonPkcSecretKeyRef<'a>,
        fab_idx: NonZeroU8,
        buf: &'a mut [u8],
    ) -> Result<Self, Error> {
        matter.with_state(|state| {
            let fabric = state.fabrics.fabric(fab_idx)?;

            Self::create(signing_privkey, fabric.root_ca(), fabric.icac(), buf)
        })
    }

    /// Build a NOC generator from already-existing chain material.
    ///
    /// Inputs:
    ///   - `signing_privkey` — the private key that will sign NOCs.
    ///     In ICAC-tier mode this is the **ICAC** private key; in
    ///     RCAC-direct mode it's the **RCAC** private key. Must match
    ///     the choice expressed by `icac` (non-empty ⇒ ICAC, empty ⇒
    ///     RCAC).
    ///   - `rcac` — the RCAC's TLV cert. Always required (it's
    ///     where the fabric ID + RCAC subject ID come from).
    ///   - `icac` — non-empty for an ICAC-tier fabric (NOCs
    ///     ship `[RCAC, ICAC, NOC]`); empty for RCAC-direct (NOCs
    ///     ship `[RCAC, NOC]`).
    ///
    /// Used identically at first-time bootstrap (with freshly-built
    /// chain bytes) and at restart (with chain bytes loaded from
    /// [`crate::fabric::Fabric`]).
    pub fn create(
        signing_privkey: CanonPkcSecretKeyRef<'a>,
        rcac: &[u8],
        icac: &[u8],
        buf: &'a mut [u8],
    ) -> Result<Self, Error> {
        let rcac = CertRef::new(TLVElement::new(rcac));

        let fabric_id = rcac.get_fabric_id()?;

        let rcac_id = rcac.get_ca_id()?;
        let icac_id = (!icac.is_empty())
            .then(|| {
                let icac = CertRef::new(TLVElement::new(icac));
                if icac.get_fabric_id()? != fabric_id {
                    return Err(Error::from(ErrorCode::InvalidData));
                }

                icac.get_ca_id()
            })
            .transpose()?;

        Ok(Self {
            signing_privkey,
            fabric_id,
            rcac_id,
            icac_id,
            buf,
        })
    }

    /// Issue an NOC for a device whose pubkey the supplied CSR
    /// carries. Signed by the ICAC (ICAC-tier mode) or the RCAC
    /// (RCAC-direct mode); the issuer DN is set accordingly.
    pub fn generate<C: Crypto>(
        &mut self,
        crypto: C,
        csr: &[u8],
        node_id: u64,
        cat_ids: &[u32],
        serial: u64,
        validity: Validity,
    ) -> Result<&[u8], Error> {
        let csr_ref = CsrRef::new(csr)?;
        csr_ref.verify(&crypto)?;

        let device_pubkey = csr_ref.pubkey()?;

        let serial_bytes_vec = Self::encode_serial_asn1(serial);
        let serial_bytes = serial_bytes_vec.as_slice();

        // Issuer DN switches on whether we're signing as ICAC or RCAC.
        let (issuer_ca_id, is_rcac) = match self.icac_id {
            Some(icac_id) => (icac_id, false),
            None => (self.rcac_id, true),
        };

        let signing_privkey = crypto.secret_key(self.signing_privkey)?;

        let mut pubkey_canon = CanonPkcPublicKey::new();
        signing_privkey.pub_key()?.write_canon(&mut pubkey_canon)?;

        let cert_len = NocBuilder::new(self.buf).build(
            &crypto,
            SubjectDN {
                node_id: Some(node_id),
                fabric_id: Some(self.fabric_id),
                cat_ids,
                ca_id: None,
            },
            validity,
            device_pubkey,
            pubkey_canon.reference(),
            &signing_privkey,
            serial_bytes,
            IssuerDN {
                ca_id: Some(issuer_ca_id),
                fabric_id: Some(self.fabric_id),
                is_rcac,
            },
        )?;

        Ok(&self.buf[..cert_len])
    }

    /// Fabric ID this generator signs NOCs for. Cached from the RCAC
    /// cert at construction.
    pub fn fabric_id(&self) -> u64 {
        self.fabric_id
    }

    /// `Some(_)` ⇒ ICAC tier (signing key is the ICAC priv key);
    /// `None` ⇒ RCAC-direct (signing key is the RCAC priv key).
    pub fn icac_id(&self) -> Option<u64> {
        self.icac_id
    }

    /// Reference to the NOC-signing private key — either RCAC or
    /// ICAC depending on construction mode. This is the **only**
    /// piece of [`NocGenerator`] state that needs to be persisted by
    /// the caller across a controller restart; everything else
    /// (fabric ID, CA IDs) is re-derived from the cert bytes the
    /// caller supplies to a subsequent [`Self::new`].
    ///
    /// Treat the returned bytes as highly sensitive — they can sign
    /// new fabric members.
    pub fn signing_secret_key(&self) -> CanonPkcSecretKeyRef<'_> {
        self.signing_privkey
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
}

#[cfg(test)]
mod tests {
    use crate::cert::builder::VALID_FOREVER;
    use crate::cert::{CertRef, MAX_CERT_TLV_AND_ASN1_LEN};
    use crate::commissioner::ca_chain::{IcacGenerator, RcacGenerator};
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
    fn rcac_direct_mode_noc_carries_correct_ids() {
        let crypto = test_only_crypto();
        let fabric_id = 0xABCDEF123456u64;

        let mut cert_buf1 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut rcac_gen = RcacGenerator::new(&mut cert_buf1);
        let (rcac_priv, rcac) = rcac_gen
            .generate(&crypto, fabric_id, VALID_FOREVER)
            .unwrap();

        let mut cert_buf2 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut gen =
            NocGenerator::create(rcac_priv.reference(), rcac, &[], &mut cert_buf2).unwrap();

        assert!(gen.icac_id().is_none());
        assert_eq!(gen.fabric_id(), fabric_id);

        let noc = gen
            .generate(&crypto, GOOD_CSR, 0x42, &[], 1, VALID_FOREVER)
            .unwrap();
        assert_eq!(node_id_from(noc).unwrap(), 0x42);
        assert_eq!(fabric_id_from(noc).unwrap(), fabric_id);
    }

    #[test]
    fn icac_tier_mode_noc_carries_correct_ids() {
        let crypto = test_only_crypto();
        let fabric_id = 0xABCDEF123456u64;

        let mut cert_buf1 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut rcac_gen = RcacGenerator::new(&mut cert_buf1);
        let (rcac_priv, rcac) = rcac_gen
            .generate(&crypto, fabric_id, VALID_FOREVER)
            .unwrap();

        let mut cert_buf2 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut icac_gen = IcacGenerator::new(&mut cert_buf2);
        let (icac_priv, icac) = icac_gen
            .generate(&crypto, rcac_priv.reference(), rcac, VALID_FOREVER)
            .unwrap();

        // Production-shape: drop the RCAC private key once the ICAC
        // has been signed.
        drop(rcac_priv);

        let mut cert_buf3 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut gen =
            NocGenerator::create(icac_priv.reference(), rcac, icac, &mut cert_buf3).unwrap();

        assert!(gen.icac_id().is_some());
        assert_eq!(gen.fabric_id(), fabric_id);

        let noc = gen
            .generate(&crypto, GOOD_CSR, 0x42, &[], 1, VALID_FOREVER)
            .unwrap();
        assert_eq!(node_id_from(noc).unwrap(), 0x42);
        assert_eq!(fabric_id_from(noc).unwrap(), fabric_id);
    }

    #[test]
    fn invalid_csr_rejected() {
        let crypto = test_only_crypto();

        let mut cert_buf1 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut rcac_gen = RcacGenerator::new(&mut cert_buf1);
        let (rcac_priv, rcac) = rcac_gen.generate(&crypto, 0x1u64, VALID_FOREVER).unwrap();

        let mut cert_buf2 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut gen =
            NocGenerator::create(rcac_priv.reference(), rcac, &[], &mut cert_buf2).unwrap();

        assert!(gen
            .generate(&crypto, &[0x01, 0x02, 0x03], 1, &[], 1, VALID_FOREVER)
            .is_err());
    }

    #[test]
    fn too_many_cat_ids_rejected() {
        let crypto = test_only_crypto();

        let mut cert_buf1 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut rcac_gen = RcacGenerator::new(&mut cert_buf1);
        let (rcac_priv, rcac) = rcac_gen.generate(&crypto, 0x1u64, VALID_FOREVER).unwrap();

        let mut cert_buf2 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut gen =
            NocGenerator::create(rcac_priv.reference(), rcac, &[], &mut cert_buf2).unwrap();

        let too_many = &[1u32, 2, 3, 4];
        assert!(gen
            .generate(&crypto, GOOD_CSR, 1, too_many, 1, VALID_FOREVER)
            .is_err());
    }

    #[test]
    fn icac_with_mismatched_fabric_id_rejected() {
        let crypto = test_only_crypto();

        let mut cert_buf1 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut rcac_gen = RcacGenerator::new(&mut cert_buf1);
        let (_, rcac_a) = rcac_gen.generate(&crypto, 0xAA, VALID_FOREVER).unwrap();

        let mut cert_buf2 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut icac_gen = IcacGenerator::new(&mut cert_buf2);
        let (icac_priv_b, icac_b) = {
            let mut cert_buf3 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
            let mut rcac_gen_b = RcacGenerator::new(&mut cert_buf3);
            let (rcac_priv_b, rcac_b) = rcac_gen_b.generate(&crypto, 0xBB, VALID_FOREVER).unwrap();

            icac_gen
                .generate(&crypto, rcac_priv_b.reference(), rcac_b, VALID_FOREVER)
                .unwrap()
        };

        // RCAC says fabric=0xAA, ICAC says fabric=0xBB → reject.
        let mut cert_buf4 = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        assert!(
            NocGenerator::create(icac_priv_b.reference(), rcac_a, icac_b, &mut cert_buf4).is_err()
        );
    }
}
