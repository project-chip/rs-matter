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

//! Matter Commissioner support.
//!
//! Building blocks for the **controller / commissioner** role — driving
//! a freshly-paired accessory through the standard commissioning
//! sequence and onto a fabric.
//!
//! # Overview
//!
//! A commissioner needs to:
//! 1. Discover commissionable devices (via mDNS).
//! 2. Establish a PASE session using the device's setup code.
//! 3. Configure the device (regulatory config, time, etc.).
//! 4. Generate and provision operational credentials (NOC, ICAC, RCAC).
//! 5. Establish a CASE session using the provisioned credentials.
//!
//! Submodules provide the credential-generation building blocks
//! ([`fabric_credentials`], [`noc_generator`]). The top-level
//! [`Commissioner`] type chains the post-PASE invokes
//! (`ArmFailSafe → CSRRequest → AddTrustedRootCertificate → AddNOC`,
//! and — once phase 2 lands — `CASE + CommissioningComplete`) into a
//! single async call.
//!
//! # Example
//!
//! ```ignore
//! use rs_matter::commissioner::{CommissionOptions, Commissioner, FabricCredentials};
//!
//! // Pre-condition: caller has already driven `PaseInitiator::initiate`
//! // against the device on `matter`'s transport.
//!
//! let mut fabric_creds = FabricCredentials::new(&crypto, fabric_id, validity)?;
//! let mut commissioner = Commissioner::new(matter, &crypto, &mut fabric_creds);
//!
//! let result = commissioner
//!     .commission(&CommissionOptions {
//!         allow_test_attestation: true,
//!         ..Default::default()
//!     })
//!     .await?;
//!
//! // result.fabric_index / result.device_node_id are now valid on the device,
//! // pending phase 2 (CASE + CommissioningComplete — follow-up PR).
//! ```

use core::num::NonZeroU8;

use crate::crypto::{
    CanonAeadKeyRef, CanonPkcSecretKey, Crypto, RngCore, SecretKey, SigningSecretKey,
};
use crate::dm::clusters::gen_comm::{CommissioningErrorEnum, GeneralCommissioningClient};
use crate::dm::clusters::noc::{NodeOperationalCertStatusEnum, OperationalCredentialsClient};
use crate::dm::endpoints::ROOT_ENDPOINT_ID;
use crate::dm::NodeId;
use crate::error::{Error, ErrorCode};
use crate::sc::case::CaseInitiator;
use crate::tlv::{FromTLV, OctetStr, TLVElement};
use crate::transport::exchange::Exchange;
use crate::transport::network::Address;
use crate::Matter;

pub use fabric_credentials::{DeviceCredentials, FabricCredentials};
pub use noc_generator::{NocCredentials, NocGenerator};

pub mod fabric_credentials;
pub mod noc_generator;

// =====================================================================
// Post-PASE commissioning orchestration.
//
// Builds on the `FabricCredentials` / `NocGenerator` building blocks
// above and the cluster-codegen client traits (see
// `crate::dm::clusters::gen_comm` / `crate::dm::clusters::noc`) to
// drive a freshly-PASE-paired accessory through the spec-mandated
// commissioning sequence.
//
// The flow is split in two phases because the rs-matter device
// responder requires `CommissioningComplete` to arrive over a CASE
// session, not PASE (Matter Core spec §11.10.6.6 — and enforced by
// `Failsafe::disarm` which calls `get_case_fab_idx`).
//
// Phase 1 — `Commissioner::commission` (over PASE):
//   1. `GeneralCommissioning::ArmFailSafe`
//   2. (future) Device Attestation request + chain validation
//   3. `OperationalCredentials::CSRRequest` with a fresh 32-byte nonce
//   4. Mint a NOC for the device via
//      `FabricCredentials::generate_device_credentials`
//   5. `OperationalCredentials::AddTrustedRootCertificate`
//   6. `OperationalCredentials::AddNOC`
//
// Phase 2 — `Commissioner::complete_via_case` (over CASE):
//   7. Operational discovery (mDNS `_matter._tcp`) + CASE establishment
//   8. `GeneralCommissioning::CommissioningComplete`
//
// Phase 2 is the planned follow-up; the current implementation returns
// `ErrorCode::InvalidState` so callers can't accidentally treat
// "phase 1 only" as a completed commissioning.
// =====================================================================

/// NOCSRElements ([Matter Core spec §11.18.6.5.2]) is a struct with:
///   ctx(0) = `csr` (PKCS#10 CertificationRequest, DER-encoded)
///   ctx(1) = `CSRNonce` (32 bytes — must echo what we sent)
///   ctx(2..4) = vendor-reserved (ignored here)
const NOCSR_TAG_CSR: u8 = 1;
const NOCSR_TAG_NONCE: u8 = 2;

/// Knobs for [`Commissioner::commission`].
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CommissionOptions {
    /// `CaseAdminSubject` field in `AddNOC` — the NodeID the device
    /// records as the administering controller. Used by the device
    /// to bootstrap its ACL.
    pub admin_case_subject: u64,
    /// `AdminVendorId` field in `AddNOC` — the controller's vendor ID
    /// recorded in the device's Fabrics list. Use `0xFFF1`..=`0xFFF4`
    /// for development / test controllers.
    pub admin_vendor_id: u16,
    /// `ExpiryLengthSeconds` for `ArmFailSafe`. The whole commissioning
    /// flow must complete before this expires, otherwise the device
    /// rolls back any partial state.
    pub fail_safe_secs: u16,
    /// Skip Device Attestation verification.
    ///
    /// Real DCL fetch + cert-chain validation is deferred to a follow-up.
    /// Until then the only supported mode is `true` (accept the device's
    /// attestation unconditionally) — suitable only for test devices like
    /// `chip-all-clusters-app`. Setting `false` causes commissioning to
    /// fail with [`ErrorCode::Failure`] (no verification path exists yet).
    pub allow_test_attestation: bool,
}

impl CommissionOptions {
    /// Canonical chip-tool defaults.
    pub const fn new() -> Self {
        Self {
            admin_case_subject: 112233,
            admin_vendor_id: 0xFFF1,
            fail_safe_secs: 60,
            allow_test_attestation: false,
        }
    }
}

impl Default for CommissionOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// What [`Commissioner::commission`] returns on success.
///
/// Also the handoff between phase 1 (`commission`) and phase 2
/// ([`Commissioner::complete_via_case`]). All fields are required by
/// the CASE establishment that follows, so they're packaged here.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CommissionResult {
    /// Fabric slot the **device** assigned to us. Needed for subsequent
    /// `UpdateNOC` / `RemoveFabric` / `UpdateFabricLabel` invocations.
    /// (Independent of whatever local fabric index the **controller**
    /// assigned to the same fabric.)
    ///
    /// `NonZeroU8` because the Matter Core spec reserves `fabric_index=0`
    /// for "no fabric" / PASE — a successful `NOCResponse` carrying a
    /// device-side fabric slot is, by definition, non-zero.
    pub fabric_index: NonZeroU8,
    /// NodeID the controller assigned to the device. Persist this
    /// alongside the fabric — it's the operational address for CASE.
    pub device_node_id: NodeId,
    /// NodeID the controller claimed for itself when issuing the
    /// device's NOC (echo of [`CommissionOptions::admin_case_subject`]).
    /// The same NodeID is used when the controller installs its own
    /// fabric and signs its own operational NOC for CASE — and the
    /// device's admin ACL grants this NodeID administer privilege.
    pub controller_node_id: NodeId,
    /// Vendor ID the controller declared in `AddNOC.AdminVendorId`
    /// (echo of [`CommissionOptions::admin_vendor_id`]). Carried into
    /// the controller's own fabric record for consistency.
    pub admin_vendor_id: u16,
}

/// Stateful commissioner.
///
/// Holds the references needed for the whole flow so individual steps
/// don't have to take them. `&mut FabricCredentials` because each
/// commissioning bumps the fabric's `next_node_id` counter.
pub struct Commissioner<'a, C: Crypto> {
    matter: &'a Matter<'a>,
    crypto: C,
    fabric_creds: &'a mut FabricCredentials,
    /// Local `fab_idx` of the controller's *own* fabric in
    /// `matter.state.fabrics`, installed lazily on the first
    /// [`Self::complete_via_case`] call. `None` until then.
    ///
    /// The controller needs an entry in its own fabric table to drive
    /// CASE as initiator ([`CaseInitiator::initiate`] looks the fabric
    /// up by this index). The entry holds the controller's signing
    /// key, NOC, the fabric's RCAC + IPK — minted from
    /// [`Self::fabric_creds`] the first time we need them.
    self_fab_idx: Option<NonZeroU8>,
}

impl<'a, C: Crypto> Commissioner<'a, C> {
    /// Create a commissioner bound to the given Matter stack, crypto
    /// backend, and fabric credentials.
    pub const fn new(
        matter: &'a Matter<'a>,
        crypto: C,
        fabric_creds: &'a mut FabricCredentials,
    ) -> Self {
        Self {
            matter,
            crypto,
            fabric_creds,
            self_fab_idx: None,
        }
    }

    /// Local `fab_idx` of the controller's own fabric in
    /// `matter.state.fabrics`, once installed by
    /// [`Self::complete_via_case`]. `None` before phase 2 has run.
    ///
    /// Callers use this with `Exchange::initiate(matter, fab_idx.get(),
    /// device_node_id, true)` to open exchanges on the post-commissioning
    /// CASE session.
    pub fn self_fab_idx(&self) -> Option<NonZeroU8> {
        self.self_fab_idx
    }

    /// Phase 1 — drive `ArmFailSafe` through `AddNOC` over PASE.
    ///
    /// Pre-condition: PASE handshake against the device has completed
    /// successfully on `matter`'s transport. The function locates that
    /// PASE session by the `(fab=0, peer=0, secure=true)` lookup tuple
    /// every step uses — it implicitly assumes a single in-flight PASE
    /// session, which is the case in practice for a controller driving
    /// one device at a time.
    ///
    /// On success the device has accepted our RCAC + NOC and assigned
    /// us a [`CommissionResult::fabric_index`], but its fail-safe is
    /// still armed and PASE is still live. Phase 2 ([`Self::complete_via_case`])
    /// finalises commissioning over CASE; if the caller doesn't run it
    /// before the fail-safe expires the device rolls back.
    pub async fn commission(
        &mut self,
        opts: &CommissionOptions,
    ) -> Result<CommissionResult, Error> {
        self.arm_fail_safe(opts.fail_safe_secs).await?;

        // Device Attestation — structural hook. See [`CommissionOptions::allow_test_attestation`].
        self.verify_device_attestation(opts).await?;

        // CSRRequest: random 32B nonce, then validate the device's echo
        // and mint the operational NOC in the same scope where the CSR
        // is borrowed from the response RX buffer — no per-call staging
        // copy of the (up to ~400-byte) DER blob on our stack.
        let mut csr_nonce = [0u8; 32];
        self.crypto.rand()?.fill_bytes(&mut csr_nonce);

        let matter = self.matter;
        let device_creds = Self::csr_request(matter, &csr_nonce, |csr_der| {
            self.fabric_creds
                .generate_device_credentials(&self.crypto, csr_der, &[])
        })
        .await?;

        let device_node_id = device_creds.node_id;

        // AddTrustedRootCertificate first — once the device has our
        // RCAC the subsequent NOC chain validates.
        self.add_trusted_root_certificate(&device_creds.root_cert)
            .await?;

        // AddNOC.
        let icac: &[u8] = device_creds.icac.as_deref().unwrap_or(&[]);
        let ipk_ref = device_creds.ipk.reference();
        let fabric_index = self
            .add_noc(
                &device_creds.noc,
                icac,
                ipk_ref.access(),
                opts.admin_case_subject,
                opts.admin_vendor_id,
            )
            .await?;

        Ok(CommissionResult {
            fabric_index,
            device_node_id,
            controller_node_id: opts.admin_case_subject,
            admin_vendor_id: opts.admin_vendor_id,
        })
    }

    /// Phase 2 — establish CASE against the device's freshly-installed
    /// operational identity and invoke `CommissioningComplete` over it.
    ///
    /// `peer_addr` is the device's operational endpoint. In production
    /// it's discovered via `_matter._tcp` mDNS; in tests / examples it
    /// can be the same address PASE used, since the device announces on
    /// the same UDP port post-AddNOC.
    ///
    /// Steps:
    ///   1. Install the **controller's** own fabric in
    ///      `matter.state.fabrics` if not already installed (lazily —
    ///      see [`Self::install_self_fabric`]).
    ///   2. Open a fresh **unsecured** exchange to `peer_addr` and run
    ///      [`CaseInitiator::initiate`] (Sigma1 → Sigma2 → Sigma3 →
    ///      StatusReport). On success the new CASE session is keyed in
    ///      `matter.state.sessions` at `(self_fab_idx, device_node_id,
    ///      secure=true)`.
    ///   3. Open a CASE-secured exchange on that session and invoke
    ///      `GeneralCommissioning::CommissioningComplete`. The device
    ///      disarms its fail-safe and persists the new fabric.
    pub async fn complete_via_case(
        &mut self,
        peer_addr: Address,
        phase1: &CommissionResult,
    ) -> Result<(), Error> {
        // 1. Ensure the controller's fabric is in the local fabric table.
        let fab_idx =
            self.install_self_fabric(phase1.controller_node_id, phase1.admin_vendor_id)?;

        // 2. CASE handshake over a fresh unsecured exchange.
        {
            let mut exchange =
                Exchange::initiate_unsecured(self.matter, &self.crypto, peer_addr).await?;

            CaseInitiator::initiate(&mut exchange, &self.crypto, fab_idx, phase1.device_node_id)
                .await?;

            // The CASE-establishment exchange is one-shot; drop it
            // here so we open a fresh one on the new CASE session.
        }

        // 3. CommissioningComplete on the CASE session.
        self.commissioning_complete(fab_idx, phase1.device_node_id)
            .await
    }

    /// Install the controller's own fabric in `matter.state.fabrics`,
    /// or return the cached local `fab_idx` if it's already installed.
    ///
    /// Idempotent: the first call generates a controller signing
    /// keypair, mints a self-signed NOC against [`Self::fabric_creds`],
    /// hands the (key, NOC, RCAC, IPK) tuple to `Fabrics::add`, and
    /// caches the resulting `fab_idx`. Subsequent calls return the
    /// cached value.
    fn install_self_fabric(
        &mut self,
        controller_node_id: NodeId,
        admin_vendor_id: u16,
    ) -> Result<NonZeroU8, Error> {
        if let Some(fab_idx) = self.self_fab_idx {
            return Ok(fab_idx);
        }

        // Generate the controller's operational signing keypair. The
        // CSR side wants a `SecretKey` (to sign the PKCS#10), and the
        // fabric-table install wants the same key in canonical-bytes
        // form (for storage via `Fabric::secret_key`).
        let signing_key = self.crypto.generate_secret_key()?;

        let mut csr_buf = [0u8; 256]; // P-256 PKCS#10 CSRs are ~150B. TODO: LARGE BUFFER
        let csr_der = signing_key.csr(&mut csr_buf)?;

        let mut canon_secret_key = CanonPkcSecretKey::new();
        signing_key.write_canon(&mut canon_secret_key)?;

        // Mint the controller's own NOC against the fabric's RCAC
        // (or ICAC if `fabric_creds.enable_icac()` was called).
        let creds = self.fabric_creds.generate_device_credentials_with_node_id(
            &self.crypto,
            csr_der,
            controller_node_id,
            &[],
        )?;

        let icac_slice: &[u8] = creds.icac.as_deref().unwrap_or(&[]);

        let ipk_ref: CanonAeadKeyRef<'_> = creds.ipk.reference();
        let canon_ref = canon_secret_key.reference();

        let crypto = &self.crypto;

        let fab_idx = self.matter.with_state(|state| {
            // `case_admin_subject = controller_node_id`: the
            // controller administers its own fabric.
            let fabric = state.fabrics.add(
                crypto,
                canon_ref,
                &creds.root_cert,
                &creds.noc,
                icac_slice,
                Some(ipk_ref),
                admin_vendor_id,
                controller_node_id,
            )?;
            Ok::<_, Error>(fabric.fab_idx())
        })?;

        self.self_fab_idx = Some(fab_idx);

        Ok(fab_idx)
    }

    /// `GeneralCommissioning::ArmFailSafe(expiry, breadcrumb=0)`.
    pub(crate) async fn arm_fail_safe(&self, expiry_seconds: u16) -> Result<(), Error> {
        let exchange = self.open_pase_exchange().await?;

        let handle = exchange
            .general_commissioning()
            .arm_fail_safe(ROOT_ENDPOINT_ID, |req| {
                req.expiry_length_seconds(expiry_seconds)?
                    .breadcrumb(0)?
                    .end()
            })
            .await?;

        let code = handle.response()?.error_code()?;

        handle.complete().await?;

        if code != CommissioningErrorEnum::OK {
            return Err(ErrorCode::Failure.into());
        }

        Ok(())
    }

    /// `OperationalCredentials::CSRRequest(nonce)` — hands the
    /// DER-encoded PKCS#10 CSR pulled out of the NOCSRElements payload
    /// to `use_csr` (with the nonce echo already validated).
    ///
    /// The CSR slice handed to the closure is borrowed *directly* from
    /// the response RX buffer — no per-call staging copy. The buffer
    /// stays alive for the duration of `use_csr`; the trailing
    /// `StatusResponse(Success)` ACK is sent after it returns.
    ///
    /// Static-style (no `&self` receiver) so the caller can pass a
    /// closure that re-borrows other `Commissioner` fields (e.g.
    /// `fabric_creds`, `crypto`) without conflicting with a `&self`
    /// borrow on this method.
    pub(crate) async fn csr_request<F, R>(
        matter: &Matter<'_>,
        csr_nonce: &[u8; 32],
        use_csr: F,
    ) -> Result<R, Error>
    where
        F: FnOnce(&[u8]) -> Result<R, Error>,
    {
        let exchange = Exchange::initiate(matter, 0, 0, true).await?;

        let handle = exchange
            .operational_credentials()
            .csr_request(ROOT_ENDPOINT_ID, |req| {
                req.csr_nonce(OctetStr::new(csr_nonce))?
                    .is_for_update_noc(None)?
                    .end()
            })
            .await?;

        let result = {
            let resp = handle.response()?;
            let nocsr_bytes = resp.nocsr_elements()?;

            // NOCSRElements is itself TLV — its `csr` and `CSRNonce`
            // fields live at ctx(1) and ctx(2) of an anonymous struct.
            let root = TLVElement::new(nocsr_bytes.0).structure()?;
            let csr_tlv = OctetStr::from_tlv(&root.ctx(NOCSR_TAG_CSR)?)?;
            let nonce_echo = OctetStr::from_tlv(&root.ctx(NOCSR_TAG_NONCE)?)?;

            if nonce_echo.0 != csr_nonce {
                // Replay / freshness failure — abort before minting a NOC.
                return Err(ErrorCode::Failure.into());
            }

            use_csr(csr_tlv.0)?
        };

        handle.complete().await?;

        Ok(result)
    }

    /// `OperationalCredentials::AddTrustedRootCertificate(rcac_tlv)`.
    pub(crate) async fn add_trusted_root_certificate(&self, rcac_tlv: &[u8]) -> Result<(), Error> {
        let exchange = self.open_pase_exchange().await?;

        exchange
            .operational_credentials()
            .add_trusted_root_certificate(ROOT_ENDPOINT_ID, |req| {
                req.root_ca_certificate(OctetStr::new(rcac_tlv))?.end()
            })
            .await
    }

    /// `OperationalCredentials::AddNOC(noc, icac?, ipk, admin_subject,
    /// admin_vendor_id)` — returns the FabricIndex the device assigned.
    ///
    /// Pass an empty `icac` slice when the controller signs NOCs
    /// directly off the RCAC (no ICAC tier).
    pub(crate) async fn add_noc(
        &self,
        noc: &[u8],
        icac: &[u8],
        ipk: &[u8],
        admin_case_subject: u64,
        admin_vendor_id: u16,
    ) -> Result<NonZeroU8, Error> {
        let exchange = self.open_pase_exchange().await?;

        let handle = exchange
            .operational_credentials()
            .add_noc(ROOT_ENDPOINT_ID, |req| {
                req.noc_value(OctetStr::new(noc))?
                    .icac_value(if icac.is_empty() {
                        None
                    } else {
                        Some(OctetStr::new(icac))
                    })?
                    .ipk_value(OctetStr::new(ipk))?
                    .case_admin_subject(admin_case_subject)?
                    .admin_vendor_id(admin_vendor_id)?
                    .end()
            })
            .await?;

        let (status, fabric_index) = {
            let resp = handle.response()?;
            (resp.status_code()?, resp.fabric_index()?)
        };

        handle.complete().await?;

        if status != NodeOperationalCertStatusEnum::OK {
            return Err(ErrorCode::Failure.into());
        }

        // Spec reserves `fabric_index=0` for PASE / no-fabric; the
        // device must assign a non-zero slot on a successful `AddNOC`.
        // A missing field or a zero value is a peer-side bug — surface
        // it as `InvalidData` rather than silently widening.
        fabric_index
            .and_then(NonZeroU8::new)
            .ok_or_else(|| ErrorCode::InvalidData.into())
    }

    /// `GeneralCommissioning::CommissioningComplete()` over the CASE
    /// session keyed by `(fab_idx, peer_node_id, secure=true)`.
    ///
    /// **Must be invoked over CASE**, not PASE — the device responder
    /// rejects it over PASE (`Failsafe::disarm` requires a CASE
    /// `fab_idx`). [`Self::complete_via_case`] is the only caller.
    pub(crate) async fn commissioning_complete(
        &self,
        fab_idx: NonZeroU8,
        peer_node_id: NodeId,
    ) -> Result<(), Error> {
        let exchange = Exchange::initiate(self.matter, fab_idx.get(), peer_node_id, true).await?;

        let handle = exchange
            .general_commissioning()
            .commissioning_complete(ROOT_ENDPOINT_ID)
            .await?;

        let code = handle.response()?.error_code()?;

        handle.complete().await?;

        if code != CommissioningErrorEnum::OK {
            return Err(ErrorCode::Failure.into());
        }

        Ok(())
    }

    /// Open a fresh exchange over the established PASE session.
    ///
    /// `(fab=0, peer=0, secure=true)` is rs-matter's lookup tuple for the
    /// PASE session — there is at most one in flight on a given Matter
    /// stack at a time, which is the controller's normal case.
    async fn open_pase_exchange(&self) -> Result<Exchange<'_>, Error> {
        Exchange::initiate(self.matter, 0, 0, true).await
    }

    /// DAC verification placeholder.
    ///
    /// Returns `Ok(())` iff `allow_test_attestation` is set; real
    /// verification (RequestAttestation → DCL chain validation) lands
    /// in a follow-up.
    async fn verify_device_attestation(&self, opts: &CommissionOptions) -> Result<(), Error> {
        if opts.allow_test_attestation {
            return Ok(());
        }

        Err(ErrorCode::Failure.into())
    }
}
