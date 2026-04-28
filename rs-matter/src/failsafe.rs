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

use core::num::NonZeroU8;
use core::time::Duration;

use crate::cert::{CertRef, MAX_CERT_TLV_LEN};
use crate::crypto::{
    CanonAeadKeyRef, CanonPkcSecretKey, CanonPkcSecretKeyRef, Crypto, PublicKey, SecretKey,
    SigningSecretKey, PKC_SECRET_KEY_ZEROED,
};
use crate::dm::clusters::net_comm::NetworksAccess;
use crate::dm::endpoints::ROOT_ENDPOINT_ID;
use crate::dm::{ClusterId, EndptId};
use crate::error::{Error, ErrorCode};
use crate::fabric::{Fabric, Fabrics};
use crate::im::IMStatusCode;
use crate::persist::{KvBlobStoreAccess, NETWORKS_KEY};
use crate::sc::pase::Pase;
use crate::tlv::TLVElement;
use crate::transport::session::SessionMode;
use crate::utils::bitflags::bitflags;
use crate::utils::epoch::Epoch;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;

bitflags! {
    #[repr(transparent)]
    #[derive(Default)]
    #[cfg_attr(not(feature = "defmt"), derive(Debug, Copy, Clone, Eq, PartialEq, Hash))]
    pub struct NocFlags: u8 {
        const ADD_CSR_REQ_RECVD = 0x01;
        const UPDATE_CSR_REQ_RECVD = 0x02;
        const ADD_ROOT_CERT_RECVD = 0x04;
        const ADD_NOC_RECVD = 0x08;
        const UPDATE_NOC_RECVD = 0x10;
    }
}

#[derive(PartialEq)]
pub struct ArmedCtx {
    armed_at: Duration,
    timeout_secs: u16,
    fab_idx: u8,
    flags: NocFlags,
}

#[derive(PartialEq)]
pub enum State {
    Idle,
    Armed(ArmedCtx),
}

pub enum IMError {
    Error(Error),
    Status(IMStatusCode),
}

impl From<Error> for IMError {
    fn from(e: Error) -> Self {
        IMError::Error(e)
    }
}

impl From<IMStatusCode> for IMError {
    fn from(e: IMStatusCode) -> Self {
        IMError::Status(e)
    }
}

/// Default fail-safe expiry length used when the device implicitly arms the
/// fail-safe (e.g. on PASE session establishment). Mirrors
/// `CHIP_DEVICE_CONFIG_FAILSAFE_EXPIRY_LENGTH_SEC` from the reference SDK.
pub const DEFAULT_FAILSAFE_EXPIRY_SECS: u16 = 60;

pub struct FailSafe {
    state: State,
    secret_key: CanonPkcSecretKey,
    root_ca: Vec<u8, { MAX_CERT_TLV_LEN }>,
    epoch: Epoch,
    breadcrumb: u64,
}

impl FailSafe {
    #[inline(always)]
    pub const fn new(epoch: Epoch) -> Self {
        Self {
            state: State::Idle,
            secret_key: PKC_SECRET_KEY_ZEROED,
            root_ca: Vec::new(),
            epoch,
            breadcrumb: 0,
        }
    }

    pub fn init(epoch: Epoch) -> impl Init<Self> {
        init!(Self {
            state: State::Idle,
            secret_key <- CanonPkcSecretKey::init(),
            root_ca <- Vec::init(),
            epoch,
            breadcrumb: 0
        })
    }

    /// Check if the fail-safe timer has expired and if so disarms and restores the state of the fabric as well as
    /// the basic info settings.
    ///
    /// This should be called periodically to ensure that the fail-safe state is updated in a timely manner.
    /// Ideally, it should also be called at the beginning of any API that requires the fail-safe to be armed to ensure that the state is up to date.
    pub fn check_failsafe_timeout<S, N>(
        &mut self,
        fabrics: &mut Fabrics,
        networks: N,
        kv: S,
        mdns_notif: impl FnMut(),
        notify_change: impl FnMut(EndptId, ClusterId),
    ) -> Result<bool, Error>
    where
        S: KvBlobStoreAccess,
        N: NetworksAccess,
    {
        if let State::Armed(ctx) = &self.state {
            let now = (self.epoch)();
            if now >= ctx.armed_at + Duration::from_secs(ctx.timeout_secs as u64) {
                self.expire(fabrics, networks, kv, mdns_notif, notify_change)?;
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Force the fail-safe context to expire immediately, rolling back any
    /// fabric / network changes that the in-flight commissioning had staged
    /// and resetting the breadcrumb to 0.
    pub fn expire<S, N>(
        &mut self,
        fabrics: &mut Fabrics,
        networks: N,
        kv: S,
        mut mdns_notif: impl FnMut(),
        mut notify_change: impl FnMut(EndptId, ClusterId),
    ) -> Result<bool, Error>
    where
        S: KvBlobStoreAccess,
        N: NetworksAccess,
    {
        let State::Armed(ctx) = &self.state else {
            return Ok(false);
        };

        warn!(
            "Fail-Safe timeout expired for fabric {}, disarming",
            ctx.fab_idx
        );

        let fab_idx_raw = ctx.fab_idx;

        kv.access(|mut kv, buf| {
            if let Some(fab_idx) = NonZeroU8::new(fab_idx_raw) {
                fabrics.remove(fab_idx)?;
                fabrics.add_load(fab_idx.get(), &mut kv, buf)?;
            }

            networks.access(|networks| {
                let data = kv.load(NETWORKS_KEY, buf)?;

                if let Some(data) = data {
                    networks.load(data)
                } else {
                    networks.reset()
                }
            })
        })?;

        self.state = State::Idle;
        self.breadcrumb = 0;

        mdns_notif();

        // The rollback above restores attributes visible to subscribers —
        // `OperationalCredentials::NOCs` / `Fabrics` (including `vvsc`,
        // `VIDVerificationStatement`, `vendorID` mutated in-failsafe by
        // `SetVIDVerificationStatement`) and `NetworkCommissioning::Networks`
        // — to their persisted values. Notify so any active subscriptions
        // re-report.
        //
        // TODO: this only flags subscriptions for re-reporting; it does
        // *not* bump the affected clusters' data versions. `Failsafe`
        // has no handle to the cluster meta needed to do that. Pre-existing
        // limitation, not introduced by the timeout-vs-force-expiry path.
        notify_change(
            ROOT_ENDPOINT_ID,
            crate::dm::clusters::decl::operational_credentials::FULL_CLUSTER.id,
        );
        notify_change(
            ROOT_ENDPOINT_ID,
            crate::dm::clusters::decl::network_commissioning::FULL_CLUSTER.id,
        );

        Ok(true)
    }

    pub fn arm(
        &mut self,
        timeout_secs: u16,
        breadcrumb: u64,
        session_mode: &SessionMode,
        pase: &mut Pase,
    ) -> Result<(), Error> {
        if matches!(self.state, State::Idle) {
            if matches!(session_mode, SessionMode::PlainText) {
                // Only PASE and CASE sessions supported
                return Err(ErrorCode::GennCommInvalidAuthentication)?;
            }

            if pase.comm_window().is_some() && matches!(session_mode, SessionMode::Case { .. }) {
                // Cannot arm via CASE while there's an active window
                return Err(ErrorCode::Busy)?;
            }

            // if pase.comm_window().is_none() && !matches!(session_mode, SessionMode::Case { .. }) {
            //     // Cannot arm via PASE if there is no active commissioning window
            //     return Err(ErrorCode::GennCommInvalidAuthentication)?;
            // }

            self.state = State::Armed(ArmedCtx {
                armed_at: (self.epoch)(),
                timeout_secs,
                fab_idx: session_mode.fab_idx(),
                flags: NocFlags::empty(),
            });
            self.breadcrumb = breadcrumb;

            return Ok(());
        }

        // Re-arm

        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::empty(),
            NocFlags::empty(),
        )?;

        let State::Armed(ctx) = &mut self.state else {
            // Impossible, as we checked for Idle above
            unreachable!();
        };

        if timeout_secs > 0 {
            ctx.armed_at = (self.epoch)();
            ctx.timeout_secs = timeout_secs;
            self.breadcrumb = breadcrumb;
        } else {
            // As per the spec, when timeout seconds is 0, we have to actually disarm
            self.state = State::Idle;
            self.breadcrumb = 0;
        }

        Ok(())
    }

    pub fn disarm<'a>(
        &mut self,
        session_mode: &SessionMode,
        fabrics: &'a mut Fabrics,
    ) -> Result<&'a mut Fabric, Error> {
        if matches!(self.state, State::Idle) {
            error!("Received Fail-Safe Disarm without it being armed");
            return Err(ErrorCode::FailSafeRequired)?;
        }

        // Has to be a CASE session
        let fab_idx = Self::get_case_fab_idx(session_mode)?;

        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::empty(),
            NocFlags::empty(),
        )?;

        let fabric = fabrics.fabric_mut(fab_idx)?;

        self.state = State::Idle;
        self.breadcrumb = 0;

        Ok(fabric)
    }

    pub fn is_armed(&self) -> bool {
        matches!(self.state, State::Armed(_))
    }

    /// Return the trusted root certificate that has been staged via
    /// `AddTrustedRootCertificate` while the fail-safe is armed but has not
    /// yet been bound to a fabric via `AddNOC` / `UpdateNOC`.
    ///
    /// Once `AddNOC` or `UpdateNOC` is processed the root certificate is
    /// owned by the (new or updated) fabric and is reported through the
    /// fabric table; until then it has no fabric association but the spec
    /// still requires it to appear in the `TrustedRootCertificates` list
    /// (Matter Core spec, NodeOperationalCredentials cluster).
    pub fn pending_root_ca(&self) -> Option<&[u8]> {
        let State::Armed(ctx) = &self.state else {
            return None;
        };

        if !ctx.flags.contains(NocFlags::ADD_ROOT_CERT_RECVD) {
            return None;
        }

        if ctx
            .flags
            .intersects(NocFlags::ADD_NOC_RECVD | NocFlags::UPDATE_NOC_RECVD)
        {
            return None;
        }

        (!self.root_ca.is_empty()).then_some(self.root_ca.as_slice())
    }

    pub fn is_armed_for(&self, caller_fab_idx: u8) -> bool {
        match self.state {
            State::Idle => false,
            State::Armed(ArmedCtx { fab_idx, .. }) => fab_idx == caller_fab_idx,
        }
    }

    /// Whether the current fail-safe context already has an in-flight
    /// `AddNOC` or `UpdateNOC` for `caller_fab_idx`. Used by
    /// `SetVIDVerificationStatement` to decide whether the VID-verification
    /// mutation rides along with the pending fabric (and thus rolls back
    /// on fail-safe expiry) or is committed to storage immediately.
    pub fn has_pending_noc_for(&self, caller_fab_idx: NonZeroU8) -> bool {
        let State::Armed(ctx) = &self.state else {
            return false;
        };
        ctx.fab_idx == caller_fab_idx.get()
            && ctx
                .flags
                .intersects(NocFlags::ADD_NOC_RECVD | NocFlags::UPDATE_NOC_RECVD)
    }

    pub fn check_armed(&self, session_mode: &SessionMode) -> Result<(), Error> {
        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::empty(),
            NocFlags::empty(),
        )
    }

    pub fn add_trusted_root_cert<C: Crypto>(
        &mut self,
        crypto: C,
        session_mode: &SessionMode,
        root_ca: &[u8],
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::ADD_ROOT_CERT_RECVD,
            NocFlags::ADD_ROOT_CERT_RECVD,
        )?;

        // Validate the candidate RCAC by checking its self-signature (a Matter
        // RCAC is self-issued, so the certificate's own public key must verify
        // the certificate's signature). Any decode or signature failure must
        // surface as `INVALID_COMMAND` per Matter Core spec section 11.18.6.13
        // (`AddTrustedRootCertificate`), not as the generic `Failure` we'd
        // otherwise get from `ErrorCode::InvalidSignature`.
        {
            let root_ref = CertRef::new(TLVElement::new(root_ca));
            root_ref
                .verify_chain_start(&crypto)
                .finalise(buf)
                .map_err(|_| ErrorCode::InvalidCommand)?;
        }

        self.root_ca.clear();
        self.root_ca
            .extend_from_slice(root_ca)
            .map_err(|_| ErrorCode::InvalidCommand)?;

        self.add_flags(NocFlags::ADD_ROOT_CERT_RECVD);

        Ok(())
    }

    pub fn add_csr_req<C: Crypto>(
        &mut self,
        crypto: C,
        session_mode: &SessionMode,
    ) -> Result<CanonPkcSecretKeyRef<'_>, Error> {
        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::ADD_CSR_REQ_RECVD | NocFlags::UPDATE_CSR_REQ_RECVD,
            NocFlags::ADD_CSR_REQ_RECVD,
        )?;

        let crypto_secret_key = crypto.generate_secret_key()?;
        crypto_secret_key.write_canon(&mut self.secret_key)?;

        self.add_flags(NocFlags::ADD_CSR_REQ_RECVD);

        Ok(self.secret_key.reference())
    }

    pub fn update_csr_req<C: Crypto>(
        &mut self,
        crypto: C,
        session_mode: &SessionMode,
    ) -> Result<CanonPkcSecretKeyRef<'_>, Error> {
        // Must be a CASE session
        Self::get_case_fab_idx(session_mode)?;

        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::ADD_CSR_REQ_RECVD | NocFlags::UPDATE_CSR_REQ_RECVD,
            NocFlags::UPDATE_CSR_REQ_RECVD,
        )?;

        crypto
            .generate_secret_key()?
            .write_canon(&mut self.secret_key)?;

        self.add_flags(NocFlags::UPDATE_CSR_REQ_RECVD);

        Ok(self.secret_key.reference())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_noc<'a, C: Crypto>(
        &mut self,
        crypto: C,
        fabrics: &'a mut Fabrics,
        session_mode: &SessionMode,
        icac: Option<&[u8]>,
        noc: &[u8],
        buf: &mut [u8],
        mut mdns_notif: impl FnMut(),
    ) -> Result<&'a mut Fabric, Error> {
        let fab_idx = Self::get_case_fab_idx(session_mode)?;

        // `UpdateNOC` only requires the corresponding `CSRRequest` (with
        // `isForUpdateNOC=true`) to have been processed in this fail-safe
        // context. Per Matter Core spec section 11.18.6.7 it must NOT
        // have been preceded by `AddTrustedRootCertificate`, `AddNOC`,
        // `UpdateNOC`, or a CSRRequest of the wrong kind — those go in
        // `absent`. `validate_certs` further down uses the *committed*
        // root cert (`fabrics.fabric(fab_idx).root_ca()`), not anything
        // staged via AddTrustedRootCertificate.
        self.check_state(
            session_mode,
            NocFlags::UPDATE_CSR_REQ_RECVD,
            NocFlags::ADD_ROOT_CERT_RECVD
                | NocFlags::ADD_NOC_RECVD
                | NocFlags::ADD_CSR_REQ_RECVD
                | NocFlags::UPDATE_NOC_RECVD,
            NocFlags::UPDATE_NOC_RECVD,
        )?;

        {
            let noc_ref = CertRef::new(TLVElement::new(noc));
            let icac_ref = icac.map(|icac| CertRef::new(TLVElement::new(icac)));
            // `UpdateNOC` re-uses the existing fabric's root cert; it does
            // not consume one staged via `AddTrustedRootCertificate` (the
            // `absent` constraint above ensures none was staged).
            let fabric_root_ca = fabrics.fabric(fab_idx)?.root_ca();
            let root_ref = CertRef::new(TLVElement::new(fabric_root_ca));

            // Validate the certs first. A chain that doesn't pass
            // signature verification (or that doesn't chain back to the
            // staged root) is reported as `kInvalidNOC` cluster status per
            // Matter Core spec section 11.18.6.7 (`UpdateNOC`).
            Self::validate_certs(&crypto, &noc_ref, icac_ref.as_ref(), &root_ref, buf)
                .map_err(|_| ErrorCode::NocInvalidNoc)?;

            // The NOC's public key must match the public key derived from
            // the most recent `CSRRequest(isForUpdateNOC=true)` (Matter
            // Core spec section 11.18.6.7).
            let mut csr_pubkey = crate::crypto::CanonPkcPublicKey::new();
            crypto
                .secret_key(self.secret_key.reference())?
                .pub_key()?
                .write_canon(&mut csr_pubkey)?;
            if csr_pubkey.access().as_slice() != noc_ref.pubkey()? {
                Err(ErrorCode::NocInvalidPublicKey)?;
            }

            // Check that the fabric ID in the NOC matches the fabric
            // being updated. The root cert pubkey check is implicit: the
            // chain validation above used the fabric's own root cert.

            let fabric_id = noc_ref.get_fabric_id()?;
            let fabric = fabrics.fabric(fab_idx)?;

            if fabric_id != fabric.fabric_id() {
                Err(ErrorCode::NocFabricConflict)?;
            }
        }

        // `Fabrics::update` keeps the existing root cert in place — no
        // need (and no reason) to copy it out of the fabric just to pass
        // it back in.
        let fabric = fabrics.update(
            &crypto,
            fab_idx,
            self.secret_key.reference(),
            noc,
            icac.unwrap_or(&[]),
        )?;

        let State::Armed(ctx) = &mut self.state else {
            // Impossible to be in any other state because otherwise
            // check_state would have failed
            unreachable!();
        };

        ctx.fab_idx = fabric.fab_idx().get();
        self.add_flags(NocFlags::UPDATE_NOC_RECVD);

        mdns_notif();

        Ok(fabric)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_noc<'a, C: Crypto>(
        &mut self,
        crypto: C,
        fabrics: &'a mut Fabrics,
        session_mode: &SessionMode,
        vendor_id: u16,
        icac: Option<&[u8]>,
        noc: &[u8],
        ipk: &[u8],
        case_admin_subject: u64,
        buf: &mut [u8],
        mut mdns_notif: impl FnMut(),
    ) -> Result<&'a mut Fabric, Error> {
        self.check_state(
            session_mode,
            NocFlags::ADD_ROOT_CERT_RECVD | NocFlags::ADD_CSR_REQ_RECVD,
            NocFlags::ADD_NOC_RECVD | NocFlags::UPDATE_CSR_REQ_RECVD | NocFlags::UPDATE_NOC_RECVD,
            NocFlags::ADD_NOC_RECVD,
        )?;

        // CaseAdminSubject must be either a valid Operational Node ID or a
        // CASE Authenticated Tag (CAT) — Matter Core spec section 11.18.6.6
        // (`AddNOC`). Anything else (most commonly 0) is reported as
        // `kInvalidAdminSubject` cluster status.
        if !crate::acl::is_node(case_admin_subject) && !crate::acl::is_noc_cat(case_admin_subject) {
            Err(ErrorCode::NocInvalidAdminSubject)?;
        }

        {
            let noc_ref = CertRef::new(TLVElement::new(noc));
            let icac_ref = icac.map(|icac| CertRef::new(TLVElement::new(icac)));
            let root_ref = CertRef::new(TLVElement::new(&self.root_ca));

            // Validate the certs first. A chain that doesn't pass
            // signature verification (or that doesn't chain back to the
            // staged root) is reported as `kInvalidNOC` cluster status per
            // Matter Core spec section 11.18.6.6 (`AddNOC`).
            Self::validate_certs(&crypto, &noc_ref, icac_ref.as_ref(), &root_ref, buf)
                .map_err(|_| ErrorCode::NocInvalidNoc)?;

            // The NOC's public key must match the public key derived from
            // the most recent `CSRRequest` (Matter Core spec section
            // 11.18.6.6). The CSR's secret key is stashed in
            // `self.secret_key` by `add_csr_req` / `update_csr_req`.
            let mut csr_pubkey = crate::crypto::CanonPkcPublicKey::new();
            crypto
                .secret_key(self.secret_key.reference())?
                .pub_key()?
                .write_canon(&mut csr_pubkey)?;
            if csr_pubkey.access().as_slice() != noc_ref.pubkey()? {
                Err(ErrorCode::NocInvalidPublicKey)?;
            }

            // Check that there is no fabric with the same fabric ID and root cert pubkey
            // as the one in the NOC, to avoid adding duplicate fabrics

            let fabric_id = noc_ref.get_fabric_id()?;
            let root_cert_pubkey = root_ref.pubkey()?;

            for fabric in fabrics.iter() {
                if fabric_id == fabric.fabric_id() {
                    let f_root_ref = CertRef::new(TLVElement::new(fabric.root_ca()));
                    let f_root_pubkey = f_root_ref.pubkey()?;

                    if root_cert_pubkey == f_root_pubkey {
                        // A fabric with the same ID and root cert pubkey already exists,
                        // which means that this NOC cannot be accepted
                        Err(ErrorCode::NocFabricConflict)?;
                    }
                }
            }
        }

        let fabric = fabrics
            .add(
                &crypto,
                self.secret_key.reference(),
                &self.root_ca,
                noc,
                icac.unwrap_or(&[]),
                Some(CanonAeadKeyRef::try_new(ipk)?),
                vendor_id,
                case_admin_subject,
            )
            .map_err(|e| {
                if e.code() == ErrorCode::ResourceExhausted {
                    ErrorCode::NocFabricTableFull.into()
                } else {
                    e
                }
            })?;

        info!(
            "Added operational fabric with local index {}",
            fabric.fab_idx()
        );

        let State::Armed(ctx) = &mut self.state else {
            // Impossible to be in any other state because otherwise
            // check_state would have failed
            unreachable!();
        };

        ctx.fab_idx = fabric.fab_idx().get();
        self.add_flags(NocFlags::ADD_NOC_RECVD);

        mdns_notif();

        Ok(fabric)
    }

    pub fn breadcrumb(&self) -> u64 {
        self.breadcrumb
    }

    pub fn set_breadcrumb(&mut self, value: u64) {
        self.breadcrumb = value;
    }

    fn validate_certs<C: Crypto>(
        crypto: C,
        noc: &CertRef,
        icac: Option<&CertRef>,
        root: &CertRef,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let mut verifier = noc.verify_chain_start(crypto);

        if let Some(icac) = icac {
            // If ICAC is present handle it. Reject the case where the
            // commissioner re-uses the RCAC as the ICAC: Matter Core spec
            // section 6.5 requires the ICAC to be a separate CA cert
            // (i.e. not self-signed).
            if icac.is_self_signed()? {
                return Err(ErrorCode::InvalidData.into());
            }
            verifier = verifier.add_cert(icac, buf)?;
        }

        verifier.add_cert(root, buf)?.finalise(buf)
    }

    fn get_case_fab_idx(session_mode: &SessionMode) -> Result<NonZeroU8, Error> {
        if let SessionMode::Case { fab_idx, .. } = session_mode {
            Ok(*fab_idx)
        } else {
            // Only CASE session supported
            Err(ErrorCode::GennCommInvalidAuthentication.into())
        }
    }

    fn check_state(
        &self,
        session_mode: &SessionMode,
        present: NocFlags,
        absent: NocFlags,
        op: NocFlags,
    ) -> Result<(), Error> {
        if let State::Armed(ctx) = &self.state {
            if matches!(session_mode, SessionMode::PlainText) {
                // Session is plain text
                Err(ErrorCode::GennCommInvalidAuthentication)?;
            }

            if op == NocFlags::UPDATE_NOC_RECVD && !matches!(session_mode, SessionMode::Case { .. })
            {
                // Update NOC requires a CASE session
                Err(ErrorCode::GennCommInvalidAuthentication)?;
            }

            if ctx.fab_idx != session_mode.fab_idx() {
                // Fabric index does not match
                Err(ErrorCode::NocInvalidFabricIndex)?;
            }

            if !ctx.flags.contains(present) {
                // State is not what is expected for that concrete command.
                //
                // Disambiguate "no CSR at all" from "wrong CSR type" per
                // Matter Core spec sections 11.18.6.6 (`AddNOC`) and
                // 11.18.6.7 (`UpdateNOC`):
                //   * No `CSRRequest` of either kind seen yet for this
                //     fail-safe context → `kMissingCsr` cluster status.
                //   * A CSR was issued but with the opposite
                //     `isForUpdateNOC` flag from the command being
                //     processed (e.g. `UpdateNOC` after a CSR for
                //     `AddNOC`) → IM `CONSTRAINT_ERROR`.
                let any_csr = ctx
                    .flags
                    .intersects(NocFlags::ADD_CSR_REQ_RECVD | NocFlags::UPDATE_CSR_REQ_RECVD);
                if (op == NocFlags::ADD_NOC_RECVD || op == NocFlags::UPDATE_NOC_RECVD) && !any_csr {
                    Err(ErrorCode::NocMissingCsr)?;
                }

                Err(ErrorCode::ConstraintError)?;
            }

            if !ctx.flags.intersection(absent).is_empty() {
                // State is not what is expected for that concrete command.
                //
                // Two flavours both surface as IM `CONSTRAINT_ERROR` per
                // Matter Core spec sections 11.18.6.6 (`AddNOC`) and
                // 11.18.6.7 (`UpdateNOC`):
                //   * the same `Add`/`UpdateNOC` was already received in
                //     this fail-safe context
                //   * the most recent `CSRRequest` had the wrong
                //     `isForUpdateNOC` flag for the command being
                //     processed (e.g. UpdateNOC after an AddNOC-style CSR)
                Err(ErrorCode::ConstraintError)?;
            }
        } else {
            // Fail-safe is not armed
            Err(ErrorCode::FailSafeRequired)?;
        }

        Ok(())
    }

    fn add_flags(&mut self, flags: NocFlags) {
        match &mut self.state {
            State::Armed(ctx) => ctx.flags |= flags,
            _ => panic!("Not armed"),
        }
    }
}
