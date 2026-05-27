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
//! # Scope and non-scope
//!
//! The types here orchestrate the *on-wire* commissioning flow only:
//! post-PASE invokes ([`Commissioner::commission`]) and post-AddNOC
//! CASE + `CommissioningComplete` ([`Commissioner::complete_via_case`]).
//!
//! Everything *off* the wire is the caller's responsibility:
//!
//!   - CA chain (RCAC, optional ICAC) generation — use [`cac::RcacGenerator`]
//!     / [`cac::IcacGenerator`]. In a real deployment the RCAC is
//!     minted once offline (typically on an HSM) and the ICAC at
//!     factory provisioning time. The commissioner only needs the ICAC
//!     private key + the RCAC and ICAC TLV certs at runtime.
//!   - Fabric install — i.e. [`crate::fabric::Fabrics::add`] with the
//!     controller's NOC, the RCAC/ICAC chain and an IPK. The caller
//!     does this once before running any commissioning, then reuses
//!     the resulting `fab_idx` for every device.
//!   - NodeID allocation — devices get NodeIDs the caller picks (whatever
//!     scheme they prefer: counter, hash, configuration). Same for the
//!     NOC's ASN.1 serial number; the caller can simply pass
//!     `serial == node_id` if they have no other constraint.
//!   - Persistence — everything the caller wants to survive a restart
//!     (ICAC private key, `fab_idx`, NOC-serial / next-NodeID counters,
//!     the fabric itself) is theirs to write and read back.
//!
//! See `tests/commissioning.rs` and `examples/src/bin/commissioner_test.rs`
//! for a fully-worked example wiring of all of the above against a
//! single in-process fabric.
//!
//! # Phase split
//!
//! [`Commissioner::commission`] (over PASE) and
//! [`Commissioner::complete_via_case`] (over CASE) are split because
//! the rs-matter device responder requires `CommissioningComplete` to
//! arrive over a CASE session (Matter Core spec §11.10.6.6 — and
//! enforced by `Failsafe::disarm` which calls `get_case_fab_idx`).

use core::num::NonZeroU8;

use crate::cert::gen::Validity;
use crate::crypto::{Crypto, RngCore, AEAD_CANON_KEY_LEN};
use crate::dm::clusters::gen_comm::{CommissioningErrorEnum, GeneralCommissioningClient};
use crate::dm::clusters::noc::{NodeOperationalCertStatusEnum, OperationalCredentialsClient};
use crate::dm::endpoints::ROOT_ENDPOINT_ID;
use crate::dm::NodeId;
use crate::error::{Error, ErrorCode};
use crate::onboard::noc::NocGenerator;
use crate::sc::case::CaseInitiator;
use crate::tlv::{FromTLV, OctetStr, TLVElement};
use crate::transport::exchange::Exchange;
use crate::transport::network::Address;
use crate::Matter;

pub mod cac;
pub mod noc;

/// NOCSRElements ([Matter Core spec §11.18.6.5.2]) is a struct with:
///   ctx(0) = `csr` (PKCS#10 CertificationRequest, DER-encoded)
///   ctx(1) = `CSRNonce` (32 bytes — must echo what we sent)
///   ctx(2..4) = vendor-reserved (ignored here)
const NOCSR_TAG_CSR: u8 = 1;
const NOCSR_TAG_NONCE: u8 = 2;

/// Knobs for [`Commissioner::commission`].
///
/// Per-device material (NodeID, validity) is passed as separate
/// arguments to [`Commissioner::commission`] — it's expected to vary
/// every call. This struct carries only the per-flow tunables.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CommissionOptions {
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
    pub const fn new() -> Self {
        Self {
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
/// ([`Commissioner::complete_via_case`]).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CommissionResult {
    /// Fabric slot the **device** assigned to us. Needed for subsequent
    /// `UpdateNOC` / `RemoveFabric` / `UpdateFabricLabel` invocations.
    /// (Independent of whatever local fabric index the **controller**
    /// recorded for the same fabric — see [`Commissioner::fab_idx`].)
    ///
    /// `NonZeroU8` because the Matter Core spec reserves `fabric_index=0`
    /// for "no fabric" / PASE — a successful `NOCResponse` carrying a
    /// device-side fabric slot is, by definition, non-zero.
    pub fabric_index: NonZeroU8,
    /// Echo of the NodeID the caller supplied to
    /// [`Commissioner::commission`] — kept here so the same struct can
    /// be threaded into [`Commissioner::complete_via_case`] without the
    /// caller having to plumb it separately.
    pub device_node_id: NodeId,
}

/// Stateful commissioner.
///
/// Holds the references needed for the whole flow so individual steps
/// don't have to take them. `&mut NocGenerator` because each
/// `commission()` call mutably borrows the generator's scratch buffer
/// to write the device NOC into; `&mut [u8] buf` is a caller-owned
/// scratch slice used to stage the fabric's RCAC and ICAC bytes
/// across the on-wire async calls (the fabric record itself can only
/// be borrowed inside [`Matter::with_state`], which doesn't compose
/// with `await`).
///
/// **The controller's fabric is expected to already be in
/// `matter.state.fabrics`** at the given `fab_idx` — the caller installs
/// it once via [`crate::fabric::Fabrics::add`] before constructing any
/// commissioner. A single `Commissioner` instance can then be reused to
/// commission any number of devices onto that fabric.
pub struct Commissioner<'a, C: Crypto> {
    matter: &'a Matter<'a>,
    crypto: C,
    fab_idx: NonZeroU8,
    noc_generator: &'a mut NocGenerator<'a>,
    buf: &'a mut [u8],
}

impl<'a, C: Crypto> Commissioner<'a, C> {
    /// Create a commissioner bound to a Matter stack, crypto backend,
    /// an already-installed fabric (`fab_idx`), an already-constructed
    /// NOC generator that signs against the chain stored on that
    /// fabric, and a scratch buffer.
    ///
    /// `buf` is used to copy the fabric's RCAC and (optionally) ICAC
    /// bytes out of the locked fabric table so they can be passed to
    /// the asynchronous `AddTrustedRootCertificate` / `AddNOC` invokes.
    /// It must be at least [`crate::cert::MAX_CERT_TLV_LEN`] bytes; the
    /// commissioner sequences the two transfers (RCAC first, then ICAC
    /// re-uses the same slot) so a single-cert worth of memory is
    /// enough.
    pub const fn new(
        matter: &'a Matter<'a>,
        crypto: C,
        fab_idx: NonZeroU8,
        noc_generator: &'a mut NocGenerator<'a>,
        buf: &'a mut [u8],
    ) -> Self {
        Self {
            matter,
            crypto,
            fab_idx,
            noc_generator,
            buf,
        }
    }

    /// Index of the controller's fabric in `matter.state.fabrics`. The
    /// caller picked this when installing the fabric; the commissioner
    /// simply propagates it (e.g. into [`CommissionResult`] callers
    /// build on top).
    pub const fn fab_idx(&self) -> NonZeroU8 {
        self.fab_idx
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
    /// `device_node_id` is the NodeID the caller wishes to assign to
    /// the device on the controller's fabric. `validity` is the NOC's
    /// validity window — typically [`crate::cert::gen::VALID_FOREVER`]
    /// for long-lived deployments, or a bounded window for short-lived
    /// re-issuance. The NOC's ASN.1 serial number is derived from the
    /// NodeID (see [`NocGenerator::generate`]).
    ///
    /// On success the device has accepted our RCAC + NOC and assigned
    /// us a [`CommissionResult::fabric_index`], but its fail-safe is
    /// still armed and PASE is still live. Phase 2
    /// ([`Self::complete_via_case`]) finalises commissioning over
    /// CASE; if the caller doesn't run it before the fail-safe expires
    /// the device rolls back.
    pub async fn commission(
        &mut self,
        opts: &CommissionOptions,
        device_node_id: NodeId,
        validity: Validity,
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

        // Field-projection borrows so the closure passed to
        // `csr_request` (and the buf-staged AddTrustedRoot / AddNOC
        // calls below) don't conflict with a `&self` borrow.
        let matter = self.matter;
        let crypto = &self.crypto;
        let fab_idx = self.fab_idx;
        let noc_generator = &mut *self.noc_generator;
        let buf = &mut *self.buf;

        // Sign the device NOC. The returned slice lives in
        // `noc_generator.buf` — independent of `buf`, so we can use
        // both side-by-side below.
        let noc = Self::csr_request(matter, &csr_nonce, |csr_der| {
            noc_generator.generate(crypto, csr_der, device_node_id, &[], validity)
        })
        .await?;

        // Stage the RCAC in `buf`, send `AddTrustedRootCertificate`,
        // then re-use the same slot for the ICAC + grab IPK and admin
        // scalars on the way. Two `with_state` passes (cheap — mutex
        // + table lookup) keep the staging buffer to a single
        // `MAX_CERT_TLV_LEN` slot. IPK is a 16-byte fixed-size stack
        // array — trivial.
        let rcac_len = matter.with_state(|state| {
            let fabric = state.fabrics.fabric(fab_idx)?;
            let rcac = fabric.root_ca();
            if rcac.len() > buf.len() {
                return Err(Error::from(ErrorCode::BufferTooSmall));
            }
            buf[..rcac.len()].copy_from_slice(rcac);
            Ok::<_, Error>(rcac.len())
        })?;
        Self::add_trusted_root_certificate(matter, &buf[..rcac_len]).await?;

        // IPK as sent on the wire is the **epoch key** (the raw
        // 16-byte input to the group-key derivation), not the
        // per-fabric derived `op_key`. `KeySet` stores both;
        // `.epoch_key()` is the right one.
        let mut ipk_bytes = [0u8; AEAD_CANON_KEY_LEN];
        let (icac_len, admin_node_id, admin_vendor_id) = matter.with_state(|state| {
            let fabric = state.fabrics.fabric(fab_idx)?;
            let icac = fabric.icac();
            if icac.len() > buf.len() {
                return Err(Error::from(ErrorCode::BufferTooSmall));
            }
            buf[..icac.len()].copy_from_slice(icac);
            ipk_bytes.copy_from_slice(fabric.ipk().epoch_key().access());
            Ok::<_, Error>((icac.len(), fabric.node_id(), fabric.vendor_id()))
        })?;

        // AddNOC. `&buf[..icac_len]` is empty for RCAC-direct fabrics
        // (the codegen builder skips the field entirely); non-empty ⇒
        // the full `[RCAC, ICAC, NOC]` chain is shipped.
        let fabric_index = Self::add_noc(
            matter,
            noc,
            &buf[..icac_len],
            &ipk_bytes,
            admin_node_id,
            admin_vendor_id,
        )
        .await?;

        Ok(CommissionResult {
            fabric_index,
            device_node_id,
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
    ///   1. Open a fresh **unsecured** exchange to `peer_addr` and run
    ///      [`CaseInitiator::initiate`] (Sigma1 → Sigma2 → Sigma3 →
    ///      StatusReport). On success the new CASE session is keyed in
    ///      `matter.state.sessions` at `(fab_idx, device_node_id,
    ///      secure=true)`.
    ///   2. Open a CASE-secured exchange on that session and invoke
    ///      `GeneralCommissioning::CommissioningComplete`. The device
    ///      disarms its fail-safe and persists the new fabric.
    pub async fn complete_via_case(
        &mut self,
        peer_addr: Address,
        phase1: &CommissionResult,
    ) -> Result<(), Error> {
        let fab_idx = self.fab_idx;

        // CASE handshake over a fresh unsecured exchange.
        {
            let mut exchange =
                Exchange::initiate_unsecured(self.matter, &self.crypto, peer_addr).await?;

            CaseInitiator::initiate(&mut exchange, &self.crypto, fab_idx, phase1.device_node_id)
                .await?;

            // The CASE-establishment exchange is one-shot; drop it
            // here so we open a fresh one on the new CASE session.
        }

        // CommissioningComplete on the CASE session.
        self.commissioning_complete(fab_idx, phase1.device_node_id)
            .await
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
    /// `noc_generator`, `crypto`) without conflicting with a `&self`
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
    ///
    /// Static-style for the same reason as [`Self::csr_request`] — the
    /// caller in [`Self::commission`] is holding a `&mut self.noc_generator`
    /// projection borrow when it invokes this.
    pub(crate) async fn add_trusted_root_certificate(
        matter: &Matter<'_>,
        rcac_tlv: &[u8],
    ) -> Result<(), Error> {
        let exchange = Exchange::initiate(matter, 0, 0, true).await?;

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
    ///
    /// Static-style: see [`Self::add_trusted_root_certificate`].
    pub(crate) async fn add_noc(
        matter: &Matter<'_>,
        noc: &[u8],
        icac: &[u8],
        ipk: &[u8],
        admin_case_subject: u64,
        admin_vendor_id: u16,
    ) -> Result<NonZeroU8, Error> {
        let exchange = Exchange::initiate(matter, 0, 0, true).await?;

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
