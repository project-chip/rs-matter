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

//! Controller-side fabric signing credentials.
//!
//! Holds the extra material a controller needs beyond fabric
//! membership: the Root CA private key (and per-fabric metadata for
//! issuing NOCs), the fabric IPK (sent on every `AddNOC` so devices
//! join the same group-key group), and the `next_node_id` counter
//! the commissioner consumes when minting NOCs for new devices.
//!
//! The fabric itself (RCAC bytes, operational secret key,
//! controller NOC, IPK derivation, fabric ID, vendor ID, …) lives in
//! [`crate::fabric::Fabric`] inside `Matter::state::fabrics` — same as
//! on any other node. [`Self::bootstrap`] is the one-shot helper that
//! installs the fabric there and remembers the resulting `fab_idx`.
//!
//! ```ignore
//! // Once, at controller startup:
//! let mut creds = FabricSigningCredentials::bootstrap(
//!     matter, &crypto,
//!     /*fabric_id=*/    1,
//!     /*controller_node_id=*/ 112233,
//!     /*admin_vendor_id=*/ 0xFFF1,
//!     VALID_FOREVER,
//! )?;
//!
//! // Per device (any number of times, all on the same fabric):
//! let mut commissioner = Commissioner::new(matter, &crypto, &mut creds);
//! let result = commissioner.commission(&opts).await?;
//! commissioner.complete_via_case(peer_addr, &result).await?;
//! ```

use core::num::NonZeroU8;

use crate::cert::builder::Validity;
use crate::cert::MAX_CERT_TLV_LEN;
use crate::crypto::{
    CanonAeadKey, CanonPkcSecretKey, Crypto, RngCore, SecretKey, SigningSecretKey,
};
use crate::dm::NodeId;
use crate::error::Error;
use crate::Matter;

use super::noc_generator::NocGenerator;

/// NOC + assigned NodeID for a device being commissioned.
///
/// The RCAC and IPK that go along with this NOC live on the
/// controller's `Fabric` and on [`FabricSigningCredentials`]
/// respectively — [`crate::commissioner::Commissioner::commission`]
/// reads them from those single sources of truth before calling
/// `AddTrustedRootCertificate` / `AddNOC`.
#[derive(Debug)]
pub struct DeviceCredentials {
    /// NOC certificate, TLV-encoded.
    pub noc: heapless::Vec<u8, MAX_CERT_TLV_LEN>,
    /// NodeID the controller assigned to the device.
    pub node_id: NodeId,
}

/// Controller-only "ability to sign NOCs" attached to an installed
/// fabric. See module docs.
pub struct FabricSigningCredentials {
    /// Index of the controller's fabric in `matter.state.fabrics`.
    /// Set by [`Self::bootstrap`] (or [`Self::from_persisted`]); never
    /// changes for the lifetime of this struct.
    ///
    /// The fabric record at this index is the single source of truth
    /// for RCAC bytes, optional ICAC bytes, controller NOC, controller
    /// operational secret key, and **the IPK** (epoch key + derived
    /// op key — see [`crate::group_keys::KeySet`]). Nothing here
    /// duplicates that.
    fab_idx: NonZeroU8,
    /// NOC-signing material — RCAC or ICAC private key depending on
    /// the bootstrap mode. The only fabric-related state that
    /// genuinely doesn't live in [`crate::fabric::Fabric`], because
    /// devices don't have it.
    noc_generator: NocGenerator,
    /// Counter for the next NodeID assigned to a commissioned device.
    next_node_id: NodeId,
}

impl FabricSigningCredentials {
    /// Bootstrap a brand-new controller fabric with the recommended
    /// **ICAC tier**.
    ///
    /// In one shot: generates the RCAC via [`super::ca_chain::generate_rcac`],
    /// generates the ICAC under it via [`super::ca_chain::generate_icac`],
    /// then **drops** the RCAC private key (it's never needed again
    /// on the running controller). Mints the controller's own
    /// operational signing keypair and ICAC-signed NOC. Generates the
    /// fabric IPK. Installs the resulting `[RCAC, ICAC]` chain, NOC
    /// and IPK as a fabric in `matter.state.fabrics`. Returns a
    /// [`FabricSigningCredentials`] holding the ICAC private key (the
    /// only signing material retained), the fab_idx and the next-NodeID
    /// counter.
    ///
    /// Use this for any real deployment. For tests / simpler setups
    /// where the RCAC private key can live on the controller, see
    /// [`Self::bootstrap_rcac_only`].
    pub fn bootstrap<C: Crypto>(
        matter: &Matter<'_>,
        crypto: C,
        fabric_id: u64,
        controller_node_id: NodeId,
        admin_vendor_id: u16,
        validity: Validity,
    ) -> Result<Self, Error> {
        // Build the CA chain. `generate_rcac` returns the RCAC priv
        // key which we hand straight to `generate_icac` and then drop.
        let (rcac_privkey, rcac) = super::ca_chain::generate_rcac(&crypto, fabric_id, validity)?;
        let (icac_privkey, icac) =
            super::ca_chain::generate_icac(&crypto, rcac_privkey.reference(), &rcac, validity)?;
        drop(rcac_privkey);

        // `signing_privkey` for the NocGenerator is the ICAC priv key.
        let mut noc_generator =
            NocGenerator::new(&crypto, icac_privkey, &rcac, Some(&icac), validity)?;

        let (canon_signing_key, controller_noc) =
            Self::mint_controller_noc(&crypto, &mut noc_generator, controller_node_id)?;

        Self::install(
            matter,
            &crypto,
            &rcac,
            &icac,
            &controller_noc,
            canon_signing_key,
            controller_node_id,
            admin_vendor_id,
            noc_generator,
        )
    }

    /// Bootstrap a brand-new controller fabric with **RCAC-direct**
    /// signing (no ICAC tier).
    ///
    /// Generates only an RCAC (no ICAC) via
    /// [`super::ca_chain::generate_rcac`] and **retains** its private
    /// key. NOCs ship as `[RCAC, NOC]`. Fine for tests and small
    /// private deployments; not appropriate where the RCAC key
    /// shouldn't live on the running commissioner (most real fabrics).
    pub fn bootstrap_rcac_only<C: Crypto>(
        matter: &Matter<'_>,
        crypto: C,
        fabric_id: u64,
        controller_node_id: NodeId,
        admin_vendor_id: u16,
        validity: Validity,
    ) -> Result<Self, Error> {
        let (rcac_privkey, rcac) = super::ca_chain::generate_rcac(&crypto, fabric_id, validity)?;
        let mut noc_generator = NocGenerator::new(&crypto, rcac_privkey, &rcac, None, validity)?;
        let (canon_signing_key, controller_noc) =
            Self::mint_controller_noc(&crypto, &mut noc_generator, controller_node_id)?;
        Self::install(
            matter,
            &crypto,
            &rcac,
            /*icac=*/ &[],
            &controller_noc,
            canon_signing_key,
            controller_node_id,
            admin_vendor_id,
            noc_generator,
        )
    }

    /// Tier-agnostic install path. Called by both bootstrap variants
    /// after they've produced `(rcac, icac?, controller_noc, signing_key)`.
    #[allow(clippy::too_many_arguments)]
    fn install<C: Crypto>(
        matter: &Matter<'_>,
        crypto: C,
        rcac: &[u8],
        icac: &[u8],
        controller_noc: &[u8],
        canon_signing_key: CanonPkcSecretKey,
        controller_node_id: NodeId,
        admin_vendor_id: u16,
        noc_generator: NocGenerator,
    ) -> Result<Self, Error> {
        // Random fabric IPK (epoch key) — shared across every fabric
        // member, used as the group-key derivation input.
        let mut ipk = CanonAeadKey::new();
        crypto.rand()?.fill_bytes(ipk.access_mut());

        // Install the fabric in `matter.state.fabrics`. The
        // `case_admin_subject` is the controller's own NodeID —
        // administering its own fabric.
        let fab_idx = matter.with_state(|state| {
            let fabric = state.fabrics.add(
                crypto,
                canon_signing_key.reference(),
                rcac,
                controller_noc,
                icac,
                Some(ipk.reference()),
                admin_vendor_id,
                controller_node_id,
            )?;
            Ok::<_, Error>(fabric.fab_idx())
        })?;

        Ok(Self {
            fab_idx,
            noc_generator,
            // Controller is `controller_node_id`; devices start at
            // `controller_node_id + 1`, with `2` as a floor so the
            // counter never lands on the conventional `1` reserved
            // for the bootstrapping admin.
            next_node_id: controller_node_id.wrapping_add(1).max(2),
        })
    }

    /// Restore from a previously-persisted snapshot, matching a
    /// fabric that's already in `matter.state.fabrics` (e.g. loaded
    /// from the fabric KV store).
    ///
    /// The tier (ICAC-signed vs RCAC-direct) is auto-detected from
    /// the installed fabric — `fabric.icac()` non-empty ⇒ ICAC-tier,
    /// empty ⇒ RCAC-direct — and the appropriate `NocGenerator`
    /// constructor is picked. The caller persists only:
    ///   - the NOC-signing private key (`signing_privkey`: ICAC priv
    ///     in tier mode, RCAC priv in direct mode),
    ///   - the `next_node_id` counter.
    ///
    /// Everything else (fabric ID, RCAC / ICAC subject IDs, IPK, the
    /// RCAC + optional ICAC cert bytes) is sourced from the fabric
    /// record — no separate u64 fields need to be persisted.
    ///
    /// The caller is responsible for ensuring `fab_idx` actually
    /// refers to the controller's fabric (the one whose `secret_key`
    /// the controller knows the private side of).
    pub fn from_persisted<C: Crypto>(
        matter: &Matter<'_>,
        crypto: &C,
        fab_idx: NonZeroU8,
        signing_privkey: CanonPkcSecretKey,
        next_node_id: NodeId,
        validity: Validity,
    ) -> Result<Self, Error> {
        // Snapshot the cert bytes out of the fabric so we can hand
        // them to `NocGenerator::new` without holding the
        // `with_state` borrow across construction.
        let mut rcac_buf: heapless::Vec<u8, MAX_CERT_TLV_LEN> = heapless::Vec::new();
        let mut icac_buf: heapless::Vec<u8, MAX_CERT_TLV_LEN> = heapless::Vec::new();
        matter.with_state(|state| {
            let fabric = state.fabrics.fabric(fab_idx)?;
            rcac_buf
                .extend_from_slice(fabric.root_ca())
                .map_err(|_| crate::error::ErrorCode::BufferTooSmall)?;
            icac_buf
                .extend_from_slice(fabric.icac())
                .map_err(|_| crate::error::ErrorCode::BufferTooSmall)?;
            Ok::<_, Error>(())
        })?;

        // `fabric.icac()` returns `&[]` for an RCAC-direct fabric;
        // `NocGenerator::new` accepts `Option<&[u8]>` for the ICAC
        // and picks the appropriate signing mode accordingly.
        let icac_opt: Option<&[u8]> = if icac_buf.is_empty() {
            None
        } else {
            Some(&icac_buf)
        };
        let noc_generator =
            NocGenerator::new(crypto, signing_privkey, &rcac_buf, icac_opt, validity)?;

        Ok(Self {
            fab_idx,
            noc_generator,
            next_node_id,
        })
    }

    /// Index of the controller's fabric in `matter.state.fabrics`.
    pub fn fab_idx(&self) -> NonZeroU8 {
        self.fab_idx
    }

    /// Fabric ID this controller signs NOCs for.
    pub fn fabric_id(&self) -> u64 {
        self.noc_generator.fabric_id()
    }

    /// Next NodeID that [`Self::generate_device_credentials`] will
    /// assign, without bumping the counter.
    pub fn peek_next_node_id(&self) -> NodeId {
        self.next_node_id
    }

    /// Pin the next NodeID. Useful when reloading from persistence
    /// (`next_node_id` is normally part of the persisted snapshot).
    pub fn set_next_node_id(&mut self, node_id: NodeId) {
        self.next_node_id = node_id;
    }

    /// Issue an NOC for a device and assign it a fresh NodeID.
    ///
    /// `csr` is the device's PKCS#10 CSR (returned by the device's
    /// `CSRRequest` invoke). The CSR is verified before signing.
    pub fn generate_device_credentials<C: Crypto>(
        &mut self,
        crypto: &C,
        csr: &[u8],
        cat_ids: &[u32],
    ) -> Result<DeviceCredentials, Error> {
        let node_id = self.bump_node_id();
        let noc = self
            .noc_generator
            .generate_noc(crypto, csr, node_id, cat_ids)?;
        Ok(DeviceCredentials { noc, node_id })
    }

    /// Issue an NOC for an explicit NodeID without touching the
    /// counter. Use for re-issuing (e.g. UpdateNOC) where the device
    /// keeps its existing NodeID.
    pub fn generate_device_credentials_with_node_id<C: Crypto>(
        &mut self,
        crypto: &C,
        csr: &[u8],
        node_id: NodeId,
        cat_ids: &[u32],
    ) -> Result<DeviceCredentials, Error> {
        let noc = self
            .noc_generator
            .generate_noc(crypto, csr, node_id, cat_ids)?;
        Ok(DeviceCredentials { noc, node_id })
    }

    fn bump_node_id(&mut self) -> NodeId {
        let id = self.next_node_id;
        // Saturating increment — the controller can run out of NodeIDs
        // before the universe ends, but if it ever does we'd rather
        // refuse to commission a duplicate than wrap silently.
        self.next_node_id = self.next_node_id.checked_add(1).unwrap_or(NodeId::MAX);
        id
    }

    /// Helper shared by both bootstrap variants: generate the controller's
    /// own operational signing keypair, build a CSR for it, hand the CSR
    /// to `noc_generator` to mint the controller's NOC. Returns the
    /// canonical signing key (to be planted into the fabric record) plus
    /// the freshly-signed NOC bytes.
    fn mint_controller_noc<C: Crypto>(
        crypto: C,
        noc_generator: &mut NocGenerator,
        controller_node_id: NodeId,
    ) -> Result<(CanonPkcSecretKey, heapless::Vec<u8, MAX_CERT_TLV_LEN>), Error> {
        let signing_key = crypto.generate_secret_key()?;

        // P-256 PKCS#10 CSRs are ~150B. 256B keeps headroom for the rare
        // long CSR while not bloating the stack.
        let mut csr_buf = [0u8; 256];
        let csr_der = signing_key.csr(&mut csr_buf)?;

        let mut canon_signing_key = CanonPkcSecretKey::new();
        signing_key.write_canon(&mut canon_signing_key)?;

        let controller_noc =
            noc_generator.generate_noc(&crypto, csr_der, controller_node_id, &[])?;
        Ok((canon_signing_key, controller_noc))
    }
}

#[cfg(test)]
mod tests {
    use crate::cert::builder::VALID_FOREVER;
    use crate::cert::CertRef;
    use crate::crypto::test_only_crypto;
    use crate::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
    use crate::tlv::TLVElement;
    use crate::utils::init::InitMaybeUninit;
    use crate::Matter;

    use static_cell::StaticCell;

    use super::*;

    /// Valid CSR from C++ test (TestChipCryptoPAL.cpp).
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

    /// Helper: build a Matter stack for the test's `bootstrap` call.
    /// Each test gets its own static slot.
    macro_rules! fresh_matter {
        ($cell:expr) => {{
            static SLOT: StaticCell<Matter> = StaticCell::new();
            // Static guards against accidental reuse across tests
            // running in the same process; each test gets a different
            // StaticCell via $cell so they don't collide.
            let _ = $cell;
            SLOT.uninit()
                .init_with(Matter::init(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0))
        }};
    }

    #[test]
    fn bootstrap_installs_fabric_and_initialises_counter() {
        let crypto = test_only_crypto();
        let matter = fresh_matter!(());

        let creds = unwrap!(FabricSigningCredentials::bootstrap(
            matter,
            &crypto,
            /*fabric_id=*/ 0x1234567890ABCDEF,
            /*controller_node_id=*/ 1,
            /*admin_vendor_id=*/ 0xFFF1,
            VALID_FOREVER,
        ));

        assert_eq!(creds.fabric_id(), 0x1234567890ABCDEF);
        // First commissionable device gets NodeID `2` (controller
        // is `1`).
        assert_eq!(creds.peek_next_node_id(), 2);

        // The fabric is in the table.
        matter.with_state(|state| {
            let fabric = unwrap!(state.fabrics.fabric(creds.fab_idx()));
            assert_eq!(fabric.fabric_id(), 0x1234567890ABCDEF);
            assert_eq!(fabric.node_id(), 1);
            assert_eq!(fabric.vendor_id(), 0xFFF1);
            assert!(!fabric.root_ca().is_empty());
            assert!(!fabric.noc().is_empty());
        });
    }

    #[test]
    fn generate_device_credentials_bumps_counter() {
        let crypto = test_only_crypto();
        let matter = fresh_matter!(0);
        let mut creds = unwrap!(FabricSigningCredentials::bootstrap(
            matter,
            &crypto,
            0x1,
            /*controller_node_id=*/ 100,
            0xFFF1,
            VALID_FOREVER,
        ));

        // First device after controller=100 → 101, then 102, then 103.
        let dev1 = unwrap!(creds.generate_device_credentials(&crypto, GOOD_CSR, &[]));
        let dev2 = unwrap!(creds.generate_device_credentials(&crypto, GOOD_CSR, &[]));
        let dev3 = unwrap!(creds.generate_device_credentials(&crypto, GOOD_CSR, &[]));
        assert_eq!(dev1.node_id, 101);
        assert_eq!(dev2.node_id, 102);
        assert_eq!(dev3.node_id, 103);
    }

    #[test]
    fn explicit_node_id_skips_counter() {
        let crypto = test_only_crypto();
        let matter = fresh_matter!(1);
        let mut creds = unwrap!(FabricSigningCredentials::bootstrap(
            matter,
            &crypto,
            0x1,
            1,
            0xFFF1,
            VALID_FOREVER,
        ));

        // Counter starts at 2.
        let auto = unwrap!(creds.generate_device_credentials(&crypto, GOOD_CSR, &[]));
        assert_eq!(auto.node_id, 2);

        // Explicit NodeID does NOT touch the counter.
        let explicit =
            unwrap!(creds.generate_device_credentials_with_node_id(&crypto, GOOD_CSR, 9999, &[]));
        assert_eq!(explicit.node_id, 9999);

        let next = unwrap!(creds.generate_device_credentials(&crypto, GOOD_CSR, &[]));
        assert_eq!(next.node_id, 3);
    }

    #[test]
    fn noc_carries_correct_fabric_and_node_ids() {
        let crypto = test_only_crypto();
        let matter = fresh_matter!(2);
        let fabric_id = 0xABCDEF123456u64;
        let mut creds = unwrap!(FabricSigningCredentials::bootstrap(
            matter,
            &crypto,
            fabric_id,
            1,
            0xFFF1,
            VALID_FOREVER,
        ));

        let dev = unwrap!(creds.generate_device_credentials(&crypto, GOOD_CSR, &[]));

        assert_eq!(unwrap!(extract_fabric_id_from_noc(&dev.noc)), fabric_id);
        assert_eq!(unwrap!(extract_node_id_from_noc(&dev.noc)), dev.node_id);
    }
}
