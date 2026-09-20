/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

use embassy_time::{Duration, Instant};

use crate::cert::{CertRef, MAX_CERT_TLV_LEN};
use crate::crypto::{
    CanonAeadKeyRef, CanonPkcSecretKey, CanonPkcSecretKeyRef, Crypto, PublicKey, SecretKey,
    SigningSecretKey, PKC_SECRET_KEY_ZEROED,
};
use crate::dm::clusters::net_comm::NetworksAccess;
use crate::dm::clusters::time_sync::UtcTime;
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
    armed_at: Instant,
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
    breadcrumb: u64,
}

impl FailSafe {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: State::Idle,
            secret_key: PKC_SECRET_KEY_ZEROED,
            root_ca: Vec::new(),
            breadcrumb: 0,
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            state: State::Idle,
            secret_key <- CanonPkcSecretKey::init(),
            root_ca <- Vec::init(),
            breadcrumb: 0
        })
    }

    /// Check if the fail-safe timer has expired and if so disarms and restores the state of the fabric as well as
    /// the basic info settings.
    ///
    /// This should be called periodically to ensure that the fail-safe state is updated in a timely manner.
    /// Ideally, it should also be called at the beginning of any API that requires the fail-safe to be armed to ensure that the state is up to date.
    ///
    /// Returns the local index of the fabric that ended up removed by the
    /// rollback (see [`Failsafe::expire`]), if any - the caller must follow
    /// up with a `HandlerContext::notify_fabric_removed` broadcast once the
    /// Matter state lock is released.
    #[allow(clippy::too_many_arguments)]
    pub fn check_failsafe_timeout<S, N>(
        &mut self,
        fabrics: &mut Fabrics,
        sessions: &mut crate::transport::session::Sessions,
        networks: N,
        kv: S,
        expire_sess_id: Option<u32>,
        mdns_notif: impl FnMut(),
        notify_change: impl FnMut(EndptId, ClusterId),
    ) -> Result<Option<NonZeroU8>, Error>
    where
        S: KvBlobStoreAccess,
        N: NetworksAccess,
    {
        if let State::Armed(ctx) = &self.state {
            let now = Instant::now();
            if now
                >= ctx
                    .armed_at
                    .saturating_add(Duration::from_secs(ctx.timeout_secs as u64))
            {
                // Timeout path: no caller exchange to preserve, so wipe
                // every PASE session along with the fabric / networks
                // rollback.
                return self.expire(
                    fabrics,
                    sessions,
                    expire_sess_id,
                    networks,
                    kv,
                    mdns_notif,
                    notify_change,
                );
            }
        }

        Ok(None)
    }

    /// Force the fail-safe context to expire immediately, rolling back any
    /// fabric / network changes that the in-flight commissioning had staged
    /// and resetting the breadcrumb to 0.
    ///
    /// `expire_sess_id` is the optional session ID of the exchange that
    /// triggered the expiry — typically passed when the trigger arrived
    /// over PASE, so the response can still be sent before the slot is
    /// reclaimed. `None` for the timeout-driven path or when the trigger
    /// arrived over CASE.
    ///
    /// Returns the local index of the fabric the rollback ended up removing,
    /// if any: a fabric added by the in-flight `AddNOC` has no persisted copy
    /// yet and is simply dropped, whereas a pre-existing fabric mutated by
    /// `UpdateNOC` is resurrected from its persisted copy (and is thus NOT
    /// reported as removed). The caller must follow up with a
    /// `HandlerContext::notify_fabric_removed` broadcast for a reported
    /// removal, once the Matter state lock is released.
    #[allow(clippy::too_many_arguments)]
    pub fn expire<S, N>(
        &mut self,
        fabrics: &mut Fabrics,
        sessions: &mut crate::transport::session::Sessions,
        expire_sess_id: Option<u32>,
        networks: N,
        kv: S,
        mut mdns_notif: impl FnMut(),
        mut notify_change: impl FnMut(EndptId, ClusterId),
    ) -> Result<Option<NonZeroU8>, Error>
    where
        S: KvBlobStoreAccess,
        N: NetworksAccess,
    {
        let State::Armed(ctx) = &self.state else {
            return Ok(None);
        };

        warn!(
            "Fail-Safe timeout expired for fabric {}, disarming",
            ctx.fab_idx
        );

        let fab_idx_raw = ctx.fab_idx;
        let mut removed_fabric = None;

        kv.access(|mut kv, buf| {
            if let Some(fab_idx) = NonZeroU8::new(fab_idx_raw) {
                fabrics.remove(fab_idx)?;
                fabrics.add_load(fab_idx.get(), &mut kv, buf)?;

                removed_fabric = fabrics.get(fab_idx).is_none().then_some(fab_idx);
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

        // Any PASE session that was in flight under this fail-safe is
        // now orphaned: its commissioning attempt was rolled back, so the
        // session has nothing to do and should not stick around to fill
        // the session table (same leak class fixed for
        // `CommissioningComplete`). `Sessions::remove_pase` keeps
        // `expire_sess_id` alive (marked expired) so any in-flight
        // response can complete.
        sessions.remove_pase(expire_sess_id);

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

        Ok(removed_fabric)
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
                return Err(ErrorCode::GennCommInvalidAuthentication.into());
            }

            if pase.comm_window().is_some() && matches!(session_mode, SessionMode::Case { .. }) {
                // Cannot arm via CASE while there's an active window
                return Err(ErrorCode::Busy.into());
            }

            // if pase.comm_window().is_none() && !matches!(session_mode, SessionMode::Case { .. }) {
            //     // Cannot arm via PASE if there is no active commissioning window
            //     return Err(ErrorCode::GennCommInvalidAuthentication.into());
            // }

            if timeout_secs == 0 {
                // Expiring a fail-safe which is not armed succeeds without side effects
                return Ok(());
            }

            self.state = State::Armed(ArmedCtx {
                armed_at: Instant::now(),
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
            ctx.armed_at = Instant::now();
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
            return Err(ErrorCode::FailSafeRequired.into());
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
        time: UtcTime,
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
        // surface as `INVALID_COMMAND` per Matter Core spec
        // (`AddTrustedRootCertificate`), not as the generic `Failure` we'd
        // otherwise get from `ErrorCode::InvalidSignature`.
        {
            let root_ref = CertRef::new(TLVElement::new(root_ca));
            root_ref
                .verify_chain_start(&crypto, time)
                .finalise(buf)
                .map_err(|_| ErrorCode::InvalidCommand)?;

            // Matter spec extra: an RCAC SHALL NOT carry a
            // `pathLenConstraint` greater than `1` — the deepest valid
            // Matter chain is RCAC → ICAC → NOC, i.e. at most one
            // intermediate CA below the root. Mirrors CHIP's
            // `ValidateChipRCAC`.
            if let Some(path_len) = root_ref
                .basic_constraints_path_len()
                .map_err(|_| ErrorCode::InvalidCommand)?
            {
                if path_len > 1 {
                    Err(ErrorCode::InvalidCommand)?;
                }
            }
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
        time: UtcTime,
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
        // context. Per Matter Core spec it must NOT
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
            // Matter Core spec (`UpdateNOC`).
            Self::validate_certs(&crypto, time, &noc_ref, icac_ref.as_ref(), &root_ref, buf)
                .map_err(|_| ErrorCode::NocInvalidNoc)?;

            // The NOC's public key must match the public key derived from
            // the most recent `CSRRequest(isForUpdateNOC=true)` (Matter
            // Core spec).
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
        time: UtcTime,
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
        // CASE Authenticated Tag (CAT) — Matter Core spec
        // (`AddNOC`). Anything else (most commonly 0) is reported as
        // `kInvalidAdminSubject` cluster status.
        if !crate::acl::is_node(case_admin_subject) && !crate::acl::is_noc_cat(case_admin_subject) {
            Err(ErrorCode::NocInvalidAdminSubject)?;
        }

        // `self.secret_key` was stashed by `add_csr_req`
        Self::check_new_noc(
            &crypto,
            time,
            fabrics,
            &self.root_ca,
            icac,
            noc,
            self.secret_key.reference(),
            buf,
        )?;

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

    /// The fabric added by `AddNOC` in the current fail-safe context and the
    /// seconds left until expiry; `None` if there is no such fabric.
    pub fn pending_add_noc(&self) -> Option<(NonZeroU8, u16)> {
        let State::Armed(ctx) = &self.state else {
            return None;
        };

        if !ctx.flags.contains(NocFlags::ADD_NOC_RECVD) {
            return None;
        }

        let fab_idx = NonZeroU8::new(ctx.fab_idx)?;

        let elapsed_secs = ctx.armed_at.elapsed().as_secs().min(u16::MAX as u64) as u16;

        Some((fab_idx, ctx.timeout_secs.saturating_sub(elapsed_secs)))
    }

    /// Arm the fail-safe for a fabric resumed from a commissioning handover,
    /// as if `AddNOC` had just been processed for it. `Busy` if already armed.
    pub fn arm_resumed(
        &mut self,
        fab_idx: NonZeroU8,
        timeout_secs: u16,
        breadcrumb: u64,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::Idle) {
            return Err(ErrorCode::Busy.into());
        }

        self.state = State::Armed(ArmedCtx {
            armed_at: Instant::now(),
            timeout_secs,
            fab_idx: fab_idx.get(),
            flags: NocFlags::ADD_ROOT_CERT_RECVD
                | NocFlags::ADD_CSR_REQ_RECVD
                | NocFlags::ADD_NOC_RECVD,
        });
        self.breadcrumb = breadcrumb;

        Ok(())
    }

    /// Check that a NOC is acceptable for a new fabric: the chain verifies
    /// against `root_ca`, the NOC public key matches `secret_key`, and no
    /// existing fabric has the same fabric ID under the same root.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn check_new_noc<C: Crypto>(
        crypto: &C,
        time: UtcTime,
        fabrics: &Fabrics,
        root_ca: &[u8],
        icac: Option<&[u8]>,
        noc: &[u8],
        secret_key: CanonPkcSecretKeyRef<'_>,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let noc_ref = CertRef::new(TLVElement::new(noc));
        let icac_ref = icac.map(|icac| CertRef::new(TLVElement::new(icac)));
        let root_ref = CertRef::new(TLVElement::new(root_ca));

        // Validate the certs first. A chain that doesn't pass
        // signature verification (or that doesn't chain back to the
        // staged root) is reported as `kInvalidNOC` cluster status per
        // Matter Core spec (`AddNOC`).
        Self::validate_certs(crypto, time, &noc_ref, icac_ref.as_ref(), &root_ref, buf)
            .map_err(|_| ErrorCode::NocInvalidNoc)?;

        // The NOC's public key must match the public key derived from
        // the most recent `CSRRequest` (Matter Core spec).
        let mut csr_pubkey = crate::crypto::CanonPkcPublicKey::new();
        crypto
            .secret_key(secret_key)?
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

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_certs<C: Crypto>(
        crypto: C,
        time: UtcTime,
        noc: &CertRef,
        icac: Option<&CertRef>,
        root: &CertRef,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let mut verifier = noc.verify_chain_start(crypto, time);

        if let Some(icac) = icac {
            // If ICAC is present handle it. Reject the case where the
            // commissioner re-uses the RCAC as the ICAC:
            // the spec requires the ICAC to be a separate CA cert
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
                // Matter Core spec, `AddNOC` / `UpdateNOC`:
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
                // Matter Core spec, `AddNOC` / `UpdateNOC`:
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

impl Default for FailSafe {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU8;

    use crate::cert::gen::VALID_FOREVER;
    use crate::crypto::{test_only_crypto, CanonPkcSecretKey, Crypto, PKC_CANON_SECRET_KEY_LEN};
    use crate::dm::clusters::net_comm::DummyNetworkAccess;
    use crate::dm::clusters::time_sync::UtcTime;
    use crate::dm::devices::test::TEST_DEV_COMM;
    use crate::dm::endpoints::ROOT_ENDPOINT_ID;
    use crate::dm::{ClusterId, EndptId};
    use crate::error::{Error, ErrorCode};
    use crate::fabric::tests::{
        add_fabric, mint_icac, mint_noc, mint_noc_for_pubkey, mint_rcac, pubkey_of, MemKv,
        MemKvBlobStore, TestRcac, TEST_IPK,
    };
    use crate::fabric::{FabricPersist, Fabrics, MAX_FABRICS};
    use crate::sc::pase::Pase;
    use crate::transport::session::{SessionMode, Sessions};

    use super::{FailSafe, DEFAULT_FAILSAFE_EXPIRY_SECS};

    fn pase(fab_idx: u8) -> SessionMode {
        SessionMode::Pase { fab_idx }
    }

    fn case(fab_idx: u8) -> SessionMode {
        SessionMode::Case {
            fab_idx: NonZeroU8::new(fab_idx).unwrap(),
            cat_ids: Default::default(),
        }
    }

    fn idx(i: u8) -> NonZeroU8 {
        NonZeroU8::new(i).unwrap()
    }

    /// A UTC time inside the validity window of every minted certificate.
    fn now() -> UtcTime {
        UtcTime::Reliable(VALID_FOREVER.not_before as u64 * 1_000_000)
    }

    fn code<T>(r: Result<T, Error>) -> ErrorCode {
        r.err().expect("expected an error").code()
    }

    /// Arm a fresh fail-safe over `session_mode` with the default expiry.
    fn armed(session_mode: &SessionMode) -> FailSafe {
        let mut fs = FailSafe::new();
        fs.arm(
            DEFAULT_FAILSAFE_EXPIRY_SECS,
            0,
            session_mode,
            &mut Pase::new(),
        )
        .unwrap();
        fs
    }

    /// Open a basic commissioning window on `pase`.
    fn open_window(pase: &mut Pase) {
        pase.open_basic_comm_window(
            1,
            &[0x11; 16],
            TEST_DEV_COMM.password.reference(),
            TEST_DEV_COMM.discriminator,
            180,
            None,
            || {},
            |_, _| {},
        )
        .unwrap();
    }

    /// Stage `rcac` via `AddTrustedRootCertificate`, then issue an `AddNOC`-style
    /// CSR and return the generated secret key.
    fn stage_root_and_csr<C: Crypto>(
        crypto: &C,
        fs: &mut FailSafe,
        session_mode: &SessionMode,
        rcac: &TestRcac,
    ) -> CanonPkcSecretKey {
        let mut buf = [0u8; 1024];
        fs.add_trusted_root_cert(crypto, now(), session_mode, &rcac.cert, &mut buf)
            .unwrap();

        CanonPkcSecretKey::new_from_ref(fs.add_csr_req(crypto, session_mode).unwrap())
    }

    /// Drive the full `AddNOC` flow over PASE for a new fabric with
    /// `fabric_id` / `node_id`, returning the staged RCAC and the local index
    /// of the pending fabric.
    fn add_noc_flow<C: Crypto>(
        crypto: &C,
        fs: &mut FailSafe,
        fabrics: &mut Fabrics,
        fabric_id: u64,
        node_id: u64,
    ) -> (TestRcac, NonZeroU8) {
        let rcac = mint_rcac(crypto, fabric_id, 0x77);
        let key = stage_root_and_csr(crypto, fs, &pase(0), &rcac);
        let noc = mint_noc_for_pubkey(
            crypto,
            &rcac,
            true,
            pubkey_of(crypto, key.reference()).reference(),
            node_id,
        );

        let mut buf = [0u8; 1024];
        let fab_idx = fs
            .add_noc(
                crypto,
                now(),
                fabrics,
                &pase(0),
                0xfff1,
                None,
                &noc,
                &TEST_IPK,
                node_id,
                &mut buf,
                || {},
            )
            .unwrap()
            .fab_idx();

        (rcac, fab_idx)
    }

    #[test]
    fn new_and_init_are_idle() {
        use crate::utils::init::InitMaybeUninit;

        let mut init = core::mem::MaybeUninit::<FailSafe>::uninit();
        let init = init.init_with(FailSafe::init());

        for fs in [&FailSafe::new(), &FailSafe::default(), &*init] {
            assert!(!fs.is_armed());
            assert!(!fs.is_armed_for(0));
            assert!(!fs.has_pending_noc_for(idx(1)));
            assert_eq!(fs.breadcrumb(), 0);
            assert!(fs.pending_root_ca().is_none());
            assert!(fs.pending_add_noc().is_none());
            assert_eq!(code(fs.check_armed(&pase(0))), ErrorCode::FailSafeRequired);
            assert_eq!(code(fs.check_armed(&case(1))), ErrorCode::FailSafeRequired);
        }
    }

    #[test]
    fn arm_over_pase_from_idle() {
        let mut fs = FailSafe::new();
        fs.arm(60, 7, &pase(0), &mut Pase::new()).unwrap();

        assert!(fs.is_armed());
        assert!(fs.is_armed_for(0));
        assert!(!fs.is_armed_for(1));
        assert!(!fs.has_pending_noc_for(idx(1)));
        assert_eq!(fs.breadcrumb(), 7);
        assert!(fs.pending_root_ca().is_none());
        assert!(fs.pending_add_noc().is_none());

        fs.check_armed(&pase(0)).unwrap();
        assert_eq!(
            code(fs.check_armed(&case(1))),
            ErrorCode::NocInvalidFabricIndex
        );
        assert_eq!(
            code(fs.check_armed(&pase(1))),
            ErrorCode::NocInvalidFabricIndex
        );
        assert_eq!(
            code(fs.check_armed(&SessionMode::PlainText)),
            ErrorCode::GennCommInvalidAuthentication
        );
    }

    #[test]
    fn arm_over_case_from_idle() {
        let mut fs = FailSafe::new();
        fs.arm(60, 1, &case(2), &mut Pase::new()).unwrap();

        assert!(fs.is_armed());
        assert!(fs.is_armed_for(2));
        assert!(!fs.is_armed_for(0));
        assert_eq!(fs.breadcrumb(), 1);

        fs.check_armed(&case(2)).unwrap();
        assert_eq!(
            code(fs.check_armed(&case(1))),
            ErrorCode::NocInvalidFabricIndex
        );
        assert_eq!(
            code(fs.check_armed(&pase(0))),
            ErrorCode::NocInvalidFabricIndex
        );
    }

    #[test]
    fn arm_rejects_plaintext_sessions() {
        let mut fs = FailSafe::new();

        assert_eq!(
            code(fs.arm(60, 1, &SessionMode::PlainText, &mut Pase::new())),
            ErrorCode::GennCommInvalidAuthentication
        );
        assert!(!fs.is_armed());
        assert_eq!(fs.breadcrumb(), 0);
    }

    #[test]
    fn arm_over_case_with_open_commissioning_window_is_busy() {
        let mut pase_state = Pase::new();
        open_window(&mut pase_state);

        let mut fs = FailSafe::new();
        assert_eq!(
            code(fs.arm(60, 1, &case(1), &mut pase_state)),
            ErrorCode::Busy
        );
        assert!(!fs.is_armed());

        // PASE arming is fine while the window is open
        fs.arm(60, 1, &pase(0), &mut pase_state).unwrap();
        assert!(fs.is_armed_for(0));
    }

    #[test]
    fn rearm_from_same_session_extends_and_updates_breadcrumb() {
        let mut fs = FailSafe::new();
        fs.arm(60, 1, &pase(0), &mut Pase::new()).unwrap();
        fs.arm(120, 2, &pase(0), &mut Pase::new()).unwrap();

        assert!(fs.is_armed_for(0));
        assert_eq!(fs.breadcrumb(), 2);

        // A commissioning window opened meanwhile does not affect re-arming
        let mut pase_state = Pase::new();
        open_window(&mut pase_state);
        let mut fs = FailSafe::new();
        fs.arm(60, 1, &case(1), &mut Pase::new()).unwrap();
        fs.arm(60, 3, &case(1), &mut pase_state).unwrap();
        assert!(fs.is_armed_for(1));
        assert_eq!(fs.breadcrumb(), 3);
    }

    #[test]
    fn rearm_from_other_session_is_rejected() {
        let mut fs = FailSafe::new();
        fs.arm(60, 1, &pase(0), &mut Pase::new()).unwrap();

        assert_eq!(
            code(fs.arm(60, 2, &case(1), &mut Pase::new())),
            ErrorCode::NocInvalidFabricIndex
        );
        assert_eq!(
            code(fs.arm(60, 2, &SessionMode::PlainText, &mut Pase::new())),
            ErrorCode::GennCommInvalidAuthentication
        );

        assert!(fs.is_armed_for(0));
        assert_eq!(fs.breadcrumb(), 1);

        let mut fs = FailSafe::new();
        fs.arm(60, 1, &case(1), &mut Pase::new()).unwrap();
        assert_eq!(
            code(fs.arm(60, 2, &case(2), &mut Pase::new())),
            ErrorCode::NocInvalidFabricIndex
        );
        assert!(fs.is_armed_for(1));
    }

    #[test]
    fn rearm_with_zero_timeout_disarms() {
        let mut fs = FailSafe::new();
        fs.arm(60, 5, &case(1), &mut Pase::new()).unwrap();

        fs.arm(0, 9, &case(1), &mut Pase::new()).unwrap();

        assert!(!fs.is_armed());
        assert_eq!(fs.breadcrumb(), 0);
    }

    #[test]
    fn arm_from_idle_with_zero_timeout_is_a_noop() {
        let mut fs = FailSafe::new();
        fs.set_breadcrumb(3);
        fs.arm(0, 5, &pase(0), &mut Pase::new()).unwrap();
        assert!(!fs.is_armed());
        assert_eq!(fs.breadcrumb(), 3);

        // The session checks still apply
        assert_eq!(
            fs.arm(0, 5, &SessionMode::PlainText, &mut Pase::new())
                .unwrap_err()
                .code(),
            ErrorCode::GennCommInvalidAuthentication
        );
    }

    /// The `(endpoint, cluster)` notifications an expiry emits.
    fn expected_expiry_changes() -> std::vec::Vec<(EndptId, ClusterId)> {
        std::vec![
            (
                ROOT_ENDPOINT_ID,
                crate::dm::clusters::decl::operational_credentials::FULL_CLUSTER.id,
            ),
            (
                ROOT_ENDPOINT_ID,
                crate::dm::clusters::decl::network_commissioning::FULL_CLUSTER.id,
            ),
        ]
    }

    #[test]
    fn check_failsafe_timeout_before_expiry_is_a_noop() {
        let mut fs = armed(&pase(0));
        let mut fabrics = Fabrics::new();
        let mut sessions = Sessions::new();
        let kv = MemKv::new(MemKvBlobStore::default());
        let mut mdns = 0;

        let removed = fs
            .check_failsafe_timeout(
                &mut fabrics,
                &mut sessions,
                DummyNetworkAccess,
                &kv,
                None,
                || mdns += 1,
                |_, _| panic!("no change expected"),
            )
            .unwrap();

        assert_eq!(removed, None);
        assert!(fs.is_armed_for(0));
        assert_eq!(mdns, 0);

        // Nor does it do anything when idle
        let mut fs = FailSafe::new();
        let removed = fs
            .check_failsafe_timeout(
                &mut fabrics,
                &mut sessions,
                DummyNetworkAccess,
                &kv,
                None,
                || mdns += 1,
                |_, _| panic!("no change expected"),
            )
            .unwrap();
        assert_eq!(removed, None);
        assert_eq!(mdns, 0);
    }

    #[test]
    fn disarm_requires_case_session_matching_the_armed_fabric() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();
        add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);

        // Not armed
        let mut fs = FailSafe::new();
        assert_eq!(
            code(fs.disarm(&case(1), &mut fabrics)),
            ErrorCode::FailSafeRequired
        );

        // Armed over PASE: PASE cannot disarm, nor can a CASE session of
        // another fabric
        let mut fs = armed(&pase(0));
        assert_eq!(
            code(fs.disarm(&pase(0), &mut fabrics)),
            ErrorCode::GennCommInvalidAuthentication
        );
        assert_eq!(
            code(fs.disarm(&case(1), &mut fabrics)),
            ErrorCode::NocInvalidFabricIndex
        );
        assert!(fs.is_armed_for(0));

        // Armed over CASE for a fabric that is not in the table
        let mut fs = armed(&case(2));
        assert_eq!(code(fs.disarm(&case(2), &mut fabrics)), ErrorCode::NotFound);
        assert!(fs.is_armed_for(2));

        // Armed over CASE for an existing fabric
        let mut fs = FailSafe::new();
        fs.arm(60, 4, &case(1), &mut Pase::new()).unwrap();
        let fabric = fs.disarm(&case(1), &mut fabrics).unwrap();
        assert_eq!(fabric.fab_idx(), idx(1));
        assert!(!fs.is_armed());
        assert_eq!(fs.breadcrumb(), 0);
    }

    #[test]
    fn breadcrumb_is_settable_and_reset_on_arm_and_disarm() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();
        add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);

        let mut fs = FailSafe::new();
        fs.set_breadcrumb(42);
        assert_eq!(fs.breadcrumb(), 42);

        fs.arm(60, 7, &case(1), &mut Pase::new()).unwrap();
        assert_eq!(fs.breadcrumb(), 7);

        fs.set_breadcrumb(99);
        assert_eq!(fs.breadcrumb(), 99);

        fs.disarm(&case(1), &mut fabrics).unwrap();
        assert_eq!(fs.breadcrumb(), 0);
    }

    #[test]
    fn add_trusted_root_cert_stages_a_pending_root_ca() {
        let crypto = test_only_crypto();
        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let mut buf = [0u8; 1024];

        // Not armed
        let mut fs = FailSafe::new();
        assert_eq!(
            code(fs.add_trusted_root_cert(&crypto, now(), &pase(0), &rcac.cert, &mut buf)),
            ErrorCode::FailSafeRequired
        );

        let mut fs = armed(&pase(0));

        // Wrong session
        assert_eq!(
            code(fs.add_trusted_root_cert(&crypto, now(), &case(1), &rcac.cert, &mut buf)),
            ErrorCode::NocInvalidFabricIndex
        );

        // Garbage and non-self-signed certs are INVALID_COMMAND
        assert_eq!(
            code(fs.add_trusted_root_cert(&crypto, now(), &pase(0), &[1, 2, 3], &mut buf)),
            ErrorCode::InvalidCommand
        );
        let icac = mint_icac(&crypto, &rcac);
        assert_eq!(
            code(fs.add_trusted_root_cert(&crypto, now(), &pase(0), &icac.cert, &mut buf)),
            ErrorCode::InvalidCommand
        );
        assert!(fs.pending_root_ca().is_none());

        fs.add_trusted_root_cert(&crypto, now(), &pase(0), &rcac.cert, &mut buf)
            .unwrap();
        assert_eq!(fs.pending_root_ca(), Some(rcac.cert.as_slice()));

        // Only once per fail-safe context
        assert_eq!(
            code(fs.add_trusted_root_cert(&crypto, now(), &pase(0), &rcac.cert, &mut buf)),
            ErrorCode::ConstraintError
        );
        assert_eq!(fs.pending_root_ca(), Some(rcac.cert.as_slice()));
    }

    #[test]
    fn add_csr_req_is_once_per_context_and_pase_cannot_update() {
        let crypto = test_only_crypto();

        let mut fs = FailSafe::new();
        assert_eq!(
            code(fs.add_csr_req(&crypto, &pase(0))),
            ErrorCode::FailSafeRequired
        );

        let mut fs = armed(&pase(0));
        assert_eq!(
            code(fs.add_csr_req(&crypto, &case(1))),
            ErrorCode::NocInvalidFabricIndex
        );

        let key = CanonPkcSecretKey::new_from_ref(fs.add_csr_req(&crypto, &pase(0)).unwrap());
        assert_ne!(key.access(), &[0u8; PKC_CANON_SECRET_KEY_LEN]);

        assert_eq!(
            code(fs.add_csr_req(&crypto, &pase(0))),
            ErrorCode::ConstraintError
        );
        assert_eq!(
            code(fs.update_csr_req(&crypto, &pase(0))),
            ErrorCode::GennCommInvalidAuthentication
        );
    }

    #[test]
    fn update_csr_req_over_case_is_once_per_context() {
        let crypto = test_only_crypto();

        let mut fs = armed(&case(1));
        assert_eq!(
            code(fs.update_csr_req(&crypto, &case(2))),
            ErrorCode::NocInvalidFabricIndex
        );

        let key = CanonPkcSecretKey::new_from_ref(fs.update_csr_req(&crypto, &case(1)).unwrap());
        assert_ne!(key.access(), &[0u8; PKC_CANON_SECRET_KEY_LEN]);

        assert_eq!(
            code(fs.update_csr_req(&crypto, &case(1))),
            ErrorCode::ConstraintError
        );
        assert_eq!(
            code(fs.add_csr_req(&crypto, &case(1))),
            ErrorCode::ConstraintError
        );
    }

    #[test]
    fn noc_command_ordering_matrix() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();
        add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let mut buf = [0u8; 1024];

        // AddNOC on an armed context that has seen no CSR at all
        let mut fs = armed(&pase(0));
        fs.add_trusted_root_cert(&crypto, now(), &pase(0), &rcac.cert, &mut buf)
            .unwrap();
        assert_eq!(
            code(fs.add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(0),
                0xfff1,
                None,
                &[],
                &TEST_IPK,
                0x1a,
                &mut buf,
                || {}
            )),
            ErrorCode::NocMissingCsr
        );

        // AddNOC after a CSR but without a trusted root
        let mut fs = armed(&pase(0));
        fs.add_csr_req(&crypto, &pase(0)).unwrap();
        assert_eq!(
            code(fs.add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(0),
                0xfff1,
                None,
                &[],
                &TEST_IPK,
                0x1a,
                &mut buf,
                || {}
            )),
            ErrorCode::ConstraintError
        );

        // UpdateNOC over PASE is never allowed
        assert_eq!(
            code(fs.update_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(0),
                None,
                &[],
                &mut buf,
                || {}
            )),
            ErrorCode::GennCommInvalidAuthentication
        );

        // UpdateNOC over CASE without any CSR
        let mut fs = armed(&case(1));
        assert_eq!(
            code(fs.update_noc(
                &crypto,
                now(),
                &mut fabrics,
                &case(1),
                None,
                &[],
                &mut buf,
                || {}
            )),
            ErrorCode::NocMissingCsr
        );

        // UpdateNOC over CASE after an AddNOC-style CSR
        fs.add_csr_req(&crypto, &case(1)).unwrap();
        assert_eq!(
            code(fs.update_noc(
                &crypto,
                now(),
                &mut fabrics,
                &case(1),
                None,
                &[],
                &mut buf,
                || {}
            )),
            ErrorCode::ConstraintError
        );

        // AddNOC over CASE after an UpdateNOC-style CSR
        let mut fs = armed(&case(1));
        fs.update_csr_req(&crypto, &case(1)).unwrap();
        assert_eq!(
            code(fs.add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &case(1),
                0xfff1,
                None,
                &[],
                &TEST_IPK,
                0x1a,
                &mut buf,
                || {}
            )),
            ErrorCode::ConstraintError
        );

        // A trusted root staged in an UpdateNOC context blocks UpdateNOC
        fs.add_trusted_root_cert(&crypto, now(), &case(1), &rcac.cert, &mut buf)
            .unwrap();
        assert_eq!(
            code(fs.update_noc(
                &crypto,
                now(),
                &mut fabrics,
                &case(1),
                None,
                &[],
                &mut buf,
                || {}
            )),
            ErrorCode::ConstraintError
        );

        // Nothing is allowed from another session
        assert_eq!(
            code(fs.update_noc(
                &crypto,
                now(),
                &mut fabrics,
                &case(2),
                None,
                &[],
                &mut buf,
                || {}
            )),
            ErrorCode::NocInvalidFabricIndex
        );
    }

    #[test]
    fn add_noc_creates_a_pending_fabric() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();
        let mut fs = armed(&pase(0));

        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let key = stage_root_and_csr(&crypto, &mut fs, &pase(0), &rcac);
        assert!(fs.pending_root_ca().is_some());

        let noc = mint_noc_for_pubkey(
            &crypto,
            &rcac,
            true,
            pubkey_of(&crypto, key.reference()).reference(),
            0x1234,
        );

        let mut buf = [0u8; 1024];
        let mut mdns = 0;
        let fabric = fs
            .add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(0),
                0xfff1,
                None,
                &noc,
                &TEST_IPK,
                0x1a,
                &mut buf,
                || mdns += 1,
            )
            .unwrap();

        assert_eq!(mdns, 1);
        assert_eq!(fabric.fab_idx(), idx(1));
        assert_eq!(fabric.node_id(), 0x1234);
        assert_eq!(fabric.fabric_id(), 0xfab);
        assert_eq!(fabric.vendor_id(), 0xfff1);
        assert_eq!(fabric.root_ca(), rcac.cert.as_slice());
        assert_eq!(fabric.noc(), noc.as_slice());
        assert!(fabric.icac().is_empty());
        assert_eq!(fabric.secret_key().access(), key.access());
        assert_eq!(fabric.ipk().epoch_key().access(), &TEST_IPK);
        assert_eq!(fabric.acl().len(), 1);

        // The context now follows the new fabric
        assert!(fs.is_armed_for(1));
        assert!(!fs.is_armed_for(0));
        assert!(fs.has_pending_noc_for(idx(1)));
        assert!(!fs.has_pending_noc_for(idx(2)));
        assert!(fs.pending_root_ca().is_none());
        let (fab_idx, secs_left) = fs.pending_add_noc().unwrap();
        assert_eq!(fab_idx, idx(1));
        assert!(secs_left <= DEFAULT_FAILSAFE_EXPIRY_SECS);
        assert!(secs_left > 0);

        // The PASE session is expected to be upgraded to the new fabric
        assert_eq!(
            code(fs.check_armed(&pase(0))),
            ErrorCode::NocInvalidFabricIndex
        );
        fs.check_armed(&pase(1)).unwrap();

        // Only one AddNOC per context
        assert_eq!(
            code(fs.add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(1),
                0xfff1,
                None,
                &noc,
                &TEST_IPK,
                0x1a,
                &mut buf,
                || {}
            )),
            ErrorCode::ConstraintError
        );
        assert_eq!(
            code(fs.add_csr_req(&crypto, &pase(1))),
            ErrorCode::ConstraintError
        );
        assert_eq!(fabrics.iter().count(), 1);
    }

    #[test]
    fn add_noc_with_icac() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();
        let mut fs = armed(&pase(0));

        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let icac = mint_icac(&crypto, &rcac);
        let key = stage_root_and_csr(&crypto, &mut fs, &pase(0), &rcac);
        let noc = mint_noc_for_pubkey(
            &crypto,
            &icac,
            false,
            pubkey_of(&crypto, key.reference()).reference(),
            0x1234,
        );

        let mut buf = [0u8; 1024];
        let fabric = fs
            .add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(0),
                0xfff1,
                Some(&icac.cert),
                &noc,
                &TEST_IPK,
                0x1a,
                &mut buf,
                || {},
            )
            .unwrap();

        assert_eq!(fabric.icac(), icac.cert.as_slice());
        assert_eq!(fabric.node_id(), 0x1234);

        // Passing the RCAC itself as the ICAC is rejected
        let mut fs = armed(&pase(0));
        let key = stage_root_and_csr(&crypto, &mut fs, &pase(0), &rcac);
        let noc = mint_noc_for_pubkey(
            &crypto,
            &rcac,
            true,
            pubkey_of(&crypto, key.reference()).reference(),
            0x1235,
        );
        assert_eq!(
            code(fs.add_noc(
                &crypto,
                now(),
                &mut Fabrics::new(),
                &pase(0),
                0xfff1,
                Some(&rcac.cert),
                &noc,
                &TEST_IPK,
                0x1a,
                &mut buf,
                || {}
            )),
            ErrorCode::NocInvalidNoc
        );
    }

    #[test]
    fn add_noc_rejects_bad_admin_subject_key_mismatch_and_foreign_chains() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();
        let mut buf = [0u8; 1024];

        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let mut fs = armed(&pase(0));
        let key = stage_root_and_csr(&crypto, &mut fs, &pase(0), &rcac);
        let pubkey = pubkey_of(&crypto, key.reference());
        let noc = mint_noc_for_pubkey(&crypto, &rcac, true, pubkey.reference(), 0x1234);

        // CaseAdminSubject must be a node ID or a CAT
        assert_eq!(
            code(fs.add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(0),
                0xfff1,
                None,
                &noc,
                &TEST_IPK,
                0,
                &mut buf,
                || {}
            )),
            ErrorCode::NocInvalidAdminSubject
        );

        // A NOC for some other key than the CSR's
        let other_noc = mint_noc(&crypto, &rcac, true, 0x1234);
        assert_eq!(
            code(fs.add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(0),
                0xfff1,
                None,
                &other_noc.cert,
                &TEST_IPK,
                0x1a,
                &mut buf,
                || {}
            )),
            ErrorCode::NocInvalidPublicKey
        );

        // A NOC not chaining to the staged root
        let other_rcac = mint_rcac(&crypto, 0xfab, 0x78);
        let foreign_noc =
            mint_noc_for_pubkey(&crypto, &other_rcac, true, pubkey.reference(), 0x1234);
        assert_eq!(
            code(fs.add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(0),
                0xfff1,
                None,
                &foreign_noc,
                &TEST_IPK,
                0x1a,
                &mut buf,
                || {}
            )),
            ErrorCode::NocInvalidNoc
        );

        // A malformed IPK
        assert_eq!(
            code(fs.add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(0),
                0xfff1,
                None,
                &noc,
                &TEST_IPK[..15],
                0x1a,
                &mut buf,
                || {}
            )),
            ErrorCode::InvalidData
        );

        // None of the failures consumed the context or added a fabric
        assert!(fs.is_armed_for(0));
        assert!(fs.pending_root_ca().is_some());
        assert!(fs.pending_add_noc().is_none());
        assert_eq!(fabrics.iter().count(), 0);

        // A CAT admin subject is accepted
        fs.add_noc(
            &crypto,
            now(),
            &mut fabrics,
            &pase(0),
            0xfff1,
            None,
            &noc,
            &TEST_IPK,
            0xffff_fffd_0001_0001,
            &mut buf,
            || {},
        )
        .unwrap();
        assert_eq!(fabrics.iter().count(), 1);
    }

    #[test]
    fn add_noc_rejects_duplicate_fabric_and_full_table() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();
        let mut buf = [0u8; 1024];

        // A fabric with the same fabric ID under the same root already exists
        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let existing = mint_noc(&crypto, &rcac, true, 0x1111);
        fabrics
            .add(
                &crypto,
                existing.key.reference(),
                &rcac.cert,
                &existing.cert,
                &[],
                Some(crate::crypto::CanonAeadKeyRef::new(&TEST_IPK)),
                0xfff1,
                0x1111,
            )
            .unwrap();

        let mut fs = armed(&pase(0));
        let key = stage_root_and_csr(&crypto, &mut fs, &pase(0), &rcac);
        let noc = mint_noc_for_pubkey(
            &crypto,
            &rcac,
            true,
            pubkey_of(&crypto, key.reference()).reference(),
            0x2222,
        );
        assert_eq!(
            code(fs.add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(0),
                0xfff1,
                None,
                &noc,
                &TEST_IPK,
                0x1a,
                &mut buf,
                || {}
            )),
            ErrorCode::NocFabricConflict
        );
        assert_eq!(fabrics.iter().count(), 1);

        // Same fabric ID under a different root is a different fabric
        let mut fabrics = Fabrics::new();
        for i in 0..MAX_FABRICS as u64 {
            add_fabric(&crypto, &mut fabrics, 0x100 + i, 0x200 + i);
        }
        assert_eq!(
            code(fs.add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(0),
                0xfff1,
                None,
                &noc,
                &TEST_IPK,
                0x1a,
                &mut buf,
                || {}
            )),
            ErrorCode::NocFabricTableFull
        );
        assert_eq!(fabrics.iter().count(), MAX_FABRICS);
        assert!(fs.pending_add_noc().is_none());
    }

    #[test]
    fn update_noc_replaces_the_fabric_noc() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();
        let mut buf = [0u8; 1024];

        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let original = mint_noc(&crypto, &rcac, true, 0x1111);
        fabrics
            .add(
                &crypto,
                original.key.reference(),
                &rcac.cert,
                &original.cert,
                &[],
                Some(crate::crypto::CanonAeadKeyRef::new(&TEST_IPK)),
                0xfff1,
                0x1111,
            )
            .unwrap();
        fabrics.update_label(idx(1), "home").unwrap();

        let mut fs = armed(&case(1));
        let key = CanonPkcSecretKey::new_from_ref(fs.update_csr_req(&crypto, &case(1)).unwrap());
        let pubkey = pubkey_of(&crypto, key.reference());

        // A NOC for some other key than the CSR's
        assert_eq!(
            code(fs.update_noc(
                &crypto,
                now(),
                &mut fabrics,
                &case(1),
                None,
                &original.cert,
                &mut buf,
                || {}
            )),
            ErrorCode::NocInvalidPublicKey
        );

        // A NOC not chaining to the fabric's root
        let other_rcac = mint_rcac(&crypto, 0xfab, 0x78);
        let foreign = mint_noc_for_pubkey(&crypto, &other_rcac, true, pubkey.reference(), 0x2222);
        assert_eq!(
            code(fs.update_noc(
                &crypto,
                now(),
                &mut fabrics,
                &case(1),
                None,
                &foreign,
                &mut buf,
                || {}
            )),
            ErrorCode::NocInvalidNoc
        );
        assert_eq!(fabrics.get(idx(1)).unwrap().node_id(), 0x1111);
        assert!(!fs.has_pending_noc_for(idx(1)));

        let noc = mint_noc_for_pubkey(&crypto, &rcac, true, pubkey.reference(), 0x2222);
        let mut mdns = 0;
        let fabric = fs
            .update_noc(
                &crypto,
                now(),
                &mut fabrics,
                &case(1),
                None,
                &noc,
                &mut buf,
                || mdns += 1,
            )
            .unwrap();

        assert_eq!(mdns, 1);
        assert_eq!(fabric.fab_idx(), idx(1));
        assert_eq!(fabric.node_id(), 0x2222);
        assert_eq!(fabric.noc(), noc.as_slice());
        assert_eq!(fabric.secret_key().access(), key.access());
        assert_eq!(fabric.root_ca(), rcac.cert.as_slice());
        assert_eq!(fabric.label(), "home");

        assert!(fs.is_armed_for(1));
        assert!(fs.has_pending_noc_for(idx(1)));
        // Only `AddNOC` reports a pending fabric
        assert!(fs.pending_add_noc().is_none());
        assert!(fs.pending_root_ca().is_none());

        // Only one UpdateNOC per context
        assert_eq!(
            code(fs.update_noc(
                &crypto,
                now(),
                &mut fabrics,
                &case(1),
                None,
                &noc,
                &mut buf,
                || {}
            )),
            ErrorCode::ConstraintError
        );
    }

    #[test]
    fn expire_when_idle_is_a_noop() {
        let mut fs = FailSafe::new();
        fs.set_breadcrumb(5);

        let removed = fs
            .expire(
                &mut Fabrics::new(),
                &mut Sessions::new(),
                None,
                DummyNetworkAccess,
                MemKv::new(MemKvBlobStore::default()),
                || panic!("no mdns notification expected"),
                |_, _| panic!("no change expected"),
            )
            .unwrap();

        assert_eq!(removed, None);
        assert_eq!(fs.breadcrumb(), 5);
    }

    #[test]
    fn expire_drops_a_fabric_pending_from_add_noc() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();
        let mut fs = armed(&pase(0));
        fs.set_breadcrumb(3);

        let (_, fab_idx) = add_noc_flow(&crypto, &mut fs, &mut fabrics, 0xfab, 0x1234);
        assert_eq!(fab_idx, idx(1));
        assert!(fabrics.get(idx(1)).is_some());

        let mut mdns = 0;
        let mut changes = std::vec::Vec::new();
        let removed = fs
            .expire(
                &mut fabrics,
                &mut Sessions::new(),
                None,
                DummyNetworkAccess,
                MemKv::new(MemKvBlobStore::default()),
                || mdns += 1,
                |ep, cl| changes.push((ep, cl)),
            )
            .unwrap();

        assert_eq!(removed, Some(idx(1)));
        assert!(fabrics.get(idx(1)).is_none());
        assert_eq!(fabrics.iter().count(), 0);
        assert!(!fs.is_armed());
        assert_eq!(fs.breadcrumb(), 0);
        assert!(fs.pending_add_noc().is_none());
        assert_eq!(mdns, 1);
        assert_eq!(changes, expected_expiry_changes());
    }

    #[test]
    fn expire_restores_a_persisted_fabric_after_update_noc() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();
        let mut buf = [0u8; 1024];

        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let original = mint_noc(&crypto, &rcac, true, 0x1111);
        fabrics
            .add(
                &crypto,
                original.key.reference(),
                &rcac.cert,
                &original.cert,
                &[],
                Some(crate::crypto::CanonAeadKeyRef::new(&TEST_IPK)),
                0xfff1,
                0x1111,
            )
            .unwrap();
        fabrics.update_label(idx(1), "home").unwrap();

        let kv = MemKv::new(MemKvBlobStore::default());
        FabricPersist::new(&kv)
            .store(fabrics.get(idx(1)).unwrap())
            .unwrap();

        let mut fs = armed(&case(1));
        let key = CanonPkcSecretKey::new_from_ref(fs.update_csr_req(&crypto, &case(1)).unwrap());
        let noc = mint_noc_for_pubkey(
            &crypto,
            &rcac,
            true,
            pubkey_of(&crypto, key.reference()).reference(),
            0x2222,
        );
        fs.update_noc(
            &crypto,
            now(),
            &mut fabrics,
            &case(1),
            None,
            &noc,
            &mut buf,
            || {},
        )
        .unwrap();
        assert_eq!(fabrics.get(idx(1)).unwrap().node_id(), 0x2222);

        let removed = fs
            .expire(
                &mut fabrics,
                &mut Sessions::new(),
                None,
                DummyNetworkAccess,
                &kv,
                || {},
                |_, _| {},
            )
            .unwrap();

        // The fabric is resurrected from storage rather than removed
        assert_eq!(removed, None);
        let fabric = fabrics.get(idx(1)).unwrap();
        assert_eq!(fabric.node_id(), 0x1111);
        assert_eq!(fabric.noc(), original.cert.as_slice());
        assert_eq!(fabric.secret_key().access(), original.key.access());
        assert_eq!(fabric.label(), "home");
        assert!(!fs.is_armed());
    }

    #[test]
    fn expire_of_a_context_without_pending_noc_keeps_fabrics() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();
        add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);

        let kv = MemKv::new(MemKvBlobStore::default());
        FabricPersist::new(&kv)
            .store(fabrics.get(idx(1)).unwrap())
            .unwrap();

        // Armed over CASE for fabric 1 but nothing staged: the fabric is
        // reloaded from its persisted copy and reported as kept
        let mut fs = armed(&case(1));
        let removed = fs
            .expire(
                &mut fabrics,
                &mut Sessions::new(),
                None,
                DummyNetworkAccess,
                &kv,
                || {},
                |_, _| {},
            )
            .unwrap();
        assert_eq!(removed, None);
        assert_eq!(fabrics.get(idx(1)).unwrap().node_id(), 0x1a);

        // Armed over PASE with no fabric involved: nothing to roll back
        let mut fs = armed(&pase(0));
        let removed = fs
            .expire(
                &mut fabrics,
                &mut Sessions::new(),
                None,
                DummyNetworkAccess,
                &kv,
                || {},
                |_, _| {},
            )
            .unwrap();
        assert_eq!(removed, None);
        assert_eq!(fabrics.iter().count(), 1);
    }

    #[cfg(feature = "groups")]
    #[test]
    fn expire_removes_pase_sessions_but_keeps_the_triggering_one() {
        use crate::dm::devices::test::TEST_DEV_DET;
        use crate::transport::network::Address;

        let mut sessions = Sessions::new();
        let mut ids = std::vec::Vec::new();
        for mode in [pase(0), pase(0), case(1)] {
            let session = sessions
                .add(0, false, Address::new(), None, &TEST_DEV_DET)
                .unwrap();
            session.set_session_mode(mode);
            ids.push(session.id);
        }
        assert_eq!(sessions.iter().count(), 3);

        let mut fs = armed(&pase(0));
        fs.expire(
            &mut Fabrics::new(),
            &mut sessions,
            Some(ids[1]),
            DummyNetworkAccess,
            MemKv::new(MemKvBlobStore::default()),
            || {},
            |_, _| {},
        )
        .unwrap();

        let remaining: std::vec::Vec<_> = sessions.iter().map(|s| s.id).collect();
        assert_eq!(remaining.len(), 2);
        assert!(remaining.contains(&ids[1]));
        assert!(remaining.contains(&ids[2]));
        assert!(sessions.get(ids[1]).unwrap().is_expired());
        assert!(!sessions.get(ids[2]).unwrap().is_expired());

        // With no session to preserve, every PASE session goes
        let mut fs = armed(&pase(0));
        fs.expire(
            &mut Fabrics::new(),
            &mut sessions,
            None,
            DummyNetworkAccess,
            MemKv::new(MemKvBlobStore::default()),
            || {},
            |_, _| {},
        )
        .unwrap();
        let remaining: std::vec::Vec<_> = sessions.iter().map(|s| s.id).collect();
        assert_eq!(remaining, [ids[2]]);
    }

    #[test]
    fn arm_resumed_behaves_like_a_context_after_add_noc() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();
        let mut buf = [0u8; 1024];

        let mut fs = FailSafe::new();
        fs.arm_resumed(idx(3), 30, 11).unwrap();

        assert!(fs.is_armed_for(3));
        assert!(fs.has_pending_noc_for(idx(3)));
        assert_eq!(fs.breadcrumb(), 11);
        let (fab_idx, secs_left) = fs.pending_add_noc().unwrap();
        assert_eq!(fab_idx, idx(3));
        assert!(secs_left <= 30);
        // No root cert bytes were staged, so none is pending
        assert!(fs.pending_root_ca().is_none());

        // Already armed
        assert_eq!(code(fs.arm_resumed(idx(4), 30, 12)), ErrorCode::Busy);
        assert!(fs.is_armed_for(3));

        // The NOC commands are consumed, exactly as after a real AddNOC
        assert_eq!(
            code(fs.add_csr_req(&crypto, &pase(3))),
            ErrorCode::ConstraintError
        );
        assert_eq!(
            code(fs.add_noc(
                &crypto,
                now(),
                &mut fabrics,
                &pase(3),
                0xfff1,
                None,
                &[],
                &TEST_IPK,
                0x1a,
                &mut buf,
                || {}
            )),
            ErrorCode::ConstraintError
        );

        // Re-arming from the same session and disarming work as usual
        fs.arm(60, 13, &pase(3), &mut Pase::new()).unwrap();
        assert_eq!(fs.breadcrumb(), 13);
        fs.arm(0, 0, &pase(3), &mut Pase::new()).unwrap();
        assert!(!fs.is_armed());

        // Arming normally after that is fine again
        fs.arm_resumed(idx(4), 30, 12).unwrap();
        assert!(fs.is_armed_for(4));
    }
}
