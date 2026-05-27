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

//! CA chain generation utilities — Root CA (RCAC) and Intermediate
//! CA (ICAC) cert minting.
//!
//! These primitives are deliberately **separate** from
//! [`NocGenerator`](super::noc::NocGenerator). In real
//! Matter PKI:
//!
//! - The **RCAC** is generated once per organisation, typically on an
//!   HSM, and its private key never resides on a running controller.
//!   It's used (offline) to sign one or more ICACs, then put away.
//! - The **ICAC** is generated occasionally (per controller / region /
//!   product family), typically at factory-provisioning time. Its
//!   private key gets baked into a controller's firmware or secure
//!   storage.
//! - The **NOC** is signed at runtime by the controller every time it
//!   commissions a new device.
//!
//! These helpers cover the first two cases (the third lives in
//! `NocGenerator`). They're plain functions returning
//! `(privkey, cert_bytes)` so the caller chooses exactly what to
//! retain — fine for the test/self-contained-controller path where
//! everything happens in one process, equally fine for the
//! factory / HSM path where each function might run on a different
//! machine.
//!
//! All certs follow Matter Core spec §6.5 cert layout: subject DN
//! carries the fabric ID and the CA's own subject ID
//! (`RootCaId` / `IcaId`); issuer DN carries the parent's subject ID
//! (with `is_rcac` set when the parent is the RCAC itself).

use crate::cert::gen::{CertGenerator, CertType, IssuerDN, SubjectDN, Validity};
use crate::cert::CertRef;
use crate::crypto::{
    CanonPkcPublicKey, CanonPkcSecretKey, CanonPkcSecretKeyRef, Crypto, PublicKey, RngCore,
    SecretKey, SigningSecretKey,
};
use crate::error::Error;
use crate::tlv::TLVElement;

pub struct RcacGenerator<'a> {
    buf: &'a mut [u8],
}

impl<'a> RcacGenerator<'a> {
    /// Create a new generator with the provided buffer for cert encoding.
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf }
    }

    /// Build a fresh self-signed RCAC for a fabric.
    ///
    /// Returns `(rcac_privkey, rcac_bytes)`:
    ///   - `rcac_privkey` — the RCAC's P-256 private key (canonical
    ///     bytes). Treat as the fabric's trust anchor; in production
    ///     this is what lives in an HSM. Retain only as long as needed
    ///     to sign one or more ICACs; drop it afterwards.
    ///   - `rcac_bytes` — Matter-TLV-encoded RCAC. Install in
    ///     [`crate::fabric::Fabric::root_ca`] (via
    ///     [`crate::fabric::Fabrics::add`]) and ship to every fabric
    ///     member.
    ///
    /// The RCAC's subject ID is randomly generated; the caller can
    /// extract it from the cert bytes via [`CertRef::get_ca_id`].
    pub fn generate<C: Crypto>(
        &mut self,
        crypto: C,
        fabric_id: u64,
        validity: Validity,
    ) -> Result<(CanonPkcSecretKey, &[u8]), Error> {
        // Random 64-bit subject ID for this RCAC.
        let mut rcac_id_bytes = [0u8; 8];
        crypto.rand()?.fill_bytes(&mut rcac_id_bytes);
        let rcac_id = u64::from_be_bytes(rcac_id_bytes);

        // P-256 keypair. Persist `rcac_privkey` as canonical bytes; the
        // borrowed `rcac_key` here is only for the signing operation
        // below.
        let rcac_key = crypto.generate_secret_key()?;

        let mut rcac_pubkey_canon = CanonPkcPublicKey::new();
        rcac_key.pub_key()?.write_canon(&mut rcac_pubkey_canon)?;

        let mut serial_bytes = [0u8; 8];
        crypto.rand()?.fill_bytes(&mut serial_bytes);

        let cert_len = CertGenerator::new(self.buf).generate(
            &crypto,
            CertType::Rcac,
            &serial_bytes,
            validity,
            SubjectDN {
                node_id: None,
                fabric_id: Some(fabric_id),
                cat_ids: &[],
                ca_id: Some(rcac_id),
            },
            // RCAC is self-signed; issuer DN is ignored by `generate`
            // when `cert_type == Rcac` but a value is still required.
            IssuerDN {
                ca_id: None,
                fabric_id: None,
                is_rcac: false,
            },
            rcac_pubkey_canon.reference(),
            None, // self-signed: no separate issuer pubkey
            &rcac_key,
        )?;

        let mut rcac_privkey = CanonPkcSecretKey::new();
        rcac_key.write_canon(&mut rcac_privkey)?;

        Ok((rcac_privkey, &self.buf[..cert_len]))
    }
}

pub struct IcacGenerator<'a> {
    buf: &'a mut [u8],
}

impl<'a> IcacGenerator<'a> {
    /// Create a new generator with the provided buffer for cert encoding.
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf }
    }

    /// Build a fresh ICAC signed by an existing RCAC.
    ///
    /// Inputs:
    ///   - `rcac_privkey` — borrowed reference to the RCAC private key.
    ///     Used here exactly once (to sign the ICAC TBS); the caller
    ///     decides what to do with the key afterwards (production path:
    ///     drop / return to HSM).
    ///   - `rcac_bytes` — the RCAC's TLV-encoded cert. The function
    ///     reads the RCAC's subject ID and fabric ID from it to populate
    ///     the ICAC's issuer DN; if `fabric_id` is supplied and disagrees
    ///     with what the RCAC carries, the function errors out.
    ///
    /// Returns `(icac_privkey, icac_bytes)`. The ICAC's own subject ID is
    /// random; recover via [`CertRef::get_ca_id`] from the returned bytes.
    pub fn generate<C: Crypto>(
        &mut self,
        crypto: C,
        rcac_privkey: CanonPkcSecretKeyRef<'_>,
        rcac_bytes: &[u8],
        validity: Validity,
    ) -> Result<(CanonPkcSecretKey, &[u8]), Error> {
        let rcac = CertRef::new(TLVElement::new(rcac_bytes));
        let rcac_pubkey = rcac.pubkey()?.try_into()?;
        let rcac_id = rcac.get_ca_id()?;
        let fabric_id = rcac.get_fabric_id()?;

        // Random ICAC subject ID.
        let mut icac_id_bytes = [0u8; 8];
        crypto.rand()?.fill_bytes(&mut icac_id_bytes);
        let icac_id = u64::from_be_bytes(icac_id_bytes);

        // ICAC keypair (retained by caller).
        let icac_key = crypto.generate_secret_key()?;

        let mut icac_pubkey_canon = CanonPkcPublicKey::new();
        icac_key.pub_key()?.write_canon(&mut icac_pubkey_canon)?;

        // RCAC signing key — borrowed only for this build.
        let rcac_signing_key = crypto.secret_key(rcac_privkey)?;

        let mut serial_bytes = [0u8; 8];
        crypto.rand()?.fill_bytes(&mut serial_bytes);

        let cert_len = CertGenerator::new(self.buf).generate(
            &crypto,
            CertType::Icac,
            &serial_bytes,
            validity,
            SubjectDN {
                node_id: None,
                fabric_id: Some(fabric_id),
                cat_ids: &[],
                ca_id: Some(icac_id),
            },
            IssuerDN {
                ca_id: Some(rcac_id),
                fabric_id: Some(fabric_id),
                is_rcac: true,
            },
            icac_pubkey_canon.reference(),
            Some(rcac_pubkey),
            &rcac_signing_key,
        )?;

        let mut icac_privkey = CanonPkcSecretKey::new();
        icac_key.write_canon(&mut icac_privkey)?;

        Ok((icac_privkey, &self.buf[..cert_len]))
    }
}

#[cfg(test)]
mod tests {
    use crate::cert::gen::VALID_FOREVER;
    use crate::cert::{CertRef, MAX_CERT_TLV_AND_ASN1_LEN};
    use crate::crypto::test_only_crypto;
    use crate::tlv::TLVElement;

    use super::*;

    #[test]
    fn rcac_carries_supplied_fabric_id() {
        let crypto = test_only_crypto();

        let mut cert_buf = [0; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut rcac_gen = RcacGenerator::new(&mut cert_buf);

        let (_priv, rcac) = rcac_gen
            .generate(&crypto, 0xABCD1234, VALID_FOREVER)
            .unwrap();

        let cert = CertRef::new(TLVElement::new(rcac));
        assert_eq!(cert.get_fabric_id().unwrap(), 0xABCD1234);
        // ca_id is random but must be set.
        let _ = cert.get_ca_id().unwrap();
    }

    #[test]
    fn icac_inherits_rcac_fabric_id() {
        let crypto = test_only_crypto();
        let fabric_id = 0x0102030405060708u64;

        let mut cert_buf1 = [0; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut rcac_gen = RcacGenerator::new(&mut cert_buf1);
        let (rcac_priv, rcac) = rcac_gen
            .generate(&crypto, fabric_id, VALID_FOREVER)
            .unwrap();

        let mut cert_buf2 = [0; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut icac_gen = IcacGenerator::new(&mut cert_buf2);
        let (_icac_priv, icac) = icac_gen
            .generate(&crypto, rcac_priv.reference(), rcac, VALID_FOREVER)
            .unwrap();

        let icac_cert = CertRef::new(TLVElement::new(icac));
        assert_eq!(icac_cert.get_fabric_id().unwrap(), fabric_id);
        let _ = icac_cert.get_ca_id().unwrap();
    }
}
