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

//! This module contains the implementation of the Node Operational Credentials cluster and its handler.

use core::cell::Cell;
use core::mem::MaybeUninit;
use core::num::NonZeroU8;

use crate::acl::AclEntry;
use crate::cert::CertRef;
use crate::crypto::{CanonPkcSignature, Crypto, SigningSecretKey};
use crate::dm::clusters::acl::{emit_acl_entry_changed, ChangeTypeEnum};
use crate::dm::clusters::adm_comm;
use crate::dm::clusters::dev_att::DeviceAttestation;
use crate::dm::clusters::gen_comm::GenCommHandler;
use crate::dm::endpoints::ROOT_ENDPOINT_ID;
use crate::dm::{ArrayAttributeRead, Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::fabric::{Fabric, FabricPersist, MAX_FABRICS};
use crate::tlv::{
    Nullable, Octets, OctetsArrayBuilder, OctetsBuilder, TLVBuilder, TLVBuilderParent, TLVElement,
    TLVTag, TLVWrite,
};
use crate::transport::session::{AttChallengeRef, SessionMode};
use crate::utils::init::InitMaybeUninit;
use crate::utils::storage::WriteBuf;

pub use crate::dm::clusters::decl::operational_credentials::*;

impl NodeOperationalCertStatusEnum {
    fn map(result: Result<(), Error>) -> Result<Self, Error> {
        match result {
            Ok(()) => Ok(Self::OK),
            Err(err) => match err.code() {
                ErrorCode::NocFabricTableFull => Ok(Self::TableFull),
                ErrorCode::NocInvalidFabricIndex => Ok(Self::InvalidFabricIndex),
                ErrorCode::NocFabricConflict => Ok(Self::FabricConflict),
                ErrorCode::NocLabelConflict => Ok(Self::LabelConflict),
                ErrorCode::NocInvalidNoc => Ok(Self::InvalidNOC),
                ErrorCode::NocInvalidPublicKey => Ok(Self::InvalidPublicKey),
                ErrorCode::NocInvalidAdminSubject => Ok(Self::InvalidAdminSubject),
                ErrorCode::NocMissingCsr => Ok(Self::MissingCsr),
                // Bare `ConstraintError` from `FailSafe::check_state`
                // (e.g. "AddNOC received twice in the same fail-safe
                // context", spec section 11.18.6.6) is reported as an
                // IM-level status code per the spec, not as a
                // `NodeOperationalCertStatusEnum` cluster status — let it
                // propagate.
                _ => Err(err),
            },
        }
    }
}

/// The system implementation of a handler for the Node Operational Credentials Matter cluster.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NocHandler {
    dataver: Dataver,
}

impl NocHandler {
    /// Creates a new instance of the `NocHandler` with the given `Dataver`.
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    /// Computes the attestation signature using the provided `DeviceAttestation`
    fn compute_attestation_signature<C: Crypto>(
        crypto: C,
        dev_att: &dyn DeviceAttestation,
        attest_element: &mut WriteBuf,
        attest_challenge: AttChallengeRef<'_>,
        signature: &mut CanonPkcSignature,
    ) -> Result<(), Error> {
        let dac_key = crypto.secret_key(dev_att.dac_priv_key())?;

        attest_element.copy_from_slice(attest_challenge.access())?;
        dac_key.sign(attest_element.as_slice(), signature)?;

        Ok(())
    }
}

impl ClusterHandler for NocHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn nocs<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<NOCStructArrayBuilder<P>, NOCStructBuilder<P>>,
    ) -> Result<P, Error> {
        fn read_into<P: TLVBuilderParent>(
            fabric: &Fabric,
            builder: NOCStructBuilder<P>,
        ) -> Result<P, Error> {
            builder
                .noc(Octets::new(fabric.noc()))?
                .icac(Nullable::new(
                    (!fabric.icac().is_empty()).then(|| Octets::new(fabric.icac())),
                ))?
                .vvsc(None)?
                .fabric_index(Some(fabric.fab_idx().get()))?
                .end()
        }

        let attr = ctx.attr();

        ctx.exchange().with_state(|state| {
            let mut fabrics = state.fabrics.iter().filter(|fabric| {
                (!attr.fab_filter || attr.fab_idx == fabric.fab_idx().get())
                    && !fabric.root_ca().is_empty()
            });

            match builder {
                ArrayAttributeRead::ReadAll(mut builder) => {
                    for fabric in fabrics {
                        if attr.fab_idx != fabric.fab_idx().get() {
                            continue;
                        }

                        builder = read_into(fabric, builder.push()?)?;
                    }

                    builder.end()
                }
                ArrayAttributeRead::ReadOne(index, builder) => {
                    let fabric = fabrics.nth(index as _);

                    if let Some(fabric) = fabric {
                        if attr.fab_idx != fabric.fab_idx().get() {
                            Err(ErrorCode::ConstraintError.into())
                        } else {
                            read_into(fabric, builder)
                        }
                    } else {
                        Err(ErrorCode::ConstraintError.into())
                    }
                }
                ArrayAttributeRead::ReadNone(builder) => builder.end(),
            }
        })
    }

    fn fabrics<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            FabricDescriptorStructArrayBuilder<P>,
            FabricDescriptorStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        fn read_into<P: TLVBuilderParent>(
            fabric: &Fabric,
            builder: FabricDescriptorStructBuilder<P>,
        ) -> Result<P, Error> {
            // Empty `root_ca` might happen in the E2E tests
            let root_ca_cert = CertRef::new(TLVElement::new(fabric.root_ca()));

            builder
                .root_public_key(Octets::new(root_ca_cert.pubkey()?))?
                .vendor_id(fabric.vendor_id())?
                .fabric_id(fabric.fabric_id())?
                .node_id(fabric.node_id())?
                .label(fabric.label())?
                .vid_verification_statement(None)?
                .fabric_index(Some(fabric.fab_idx().get()))?
                .end()
        }

        let attr = ctx.attr();

        ctx.exchange().with_state(|state| {
            let mut fabrics = state.fabrics.iter().filter(|fabric| {
                (!attr.fab_filter || attr.fab_idx == fabric.fab_idx().get())
                    && !fabric.root_ca().is_empty()
            });

            match builder {
                ArrayAttributeRead::ReadAll(mut builder) => {
                    for fabric in fabrics {
                        builder = read_into(fabric, builder.push()?)?;
                    }

                    builder.end()
                }
                ArrayAttributeRead::ReadOne(index, builder) => {
                    let fabric = fabrics.nth(index as _);

                    if let Some(fabric) = fabric {
                        read_into(fabric, builder)
                    } else {
                        Err(ErrorCode::ConstraintError.into())
                    }
                }
                ArrayAttributeRead::ReadNone(builder) => builder.end(),
            }
        })
    }

    fn supported_fabrics(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(MAX_FABRICS as u8)
    }

    fn commissioned_fabrics(&self, ctx: impl ReadContext) -> Result<u8, Error> {
        ctx.exchange()
            .with_state(|state| Ok(state.fabrics.iter().count() as u8))
    }

    fn trusted_root_certificates<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<OctetsArrayBuilder<P>, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        ctx.exchange().with_state(|state| {
            // `TrustedRootCertificates` is a plain `list[octet_string]`, not a
            // fabric-scoped struct list, so fabric filtering does not apply
            // here — every committed fabric's root cert is reported.
            let fabric_certs = state
                .fabrics
                .iter()
                .filter(|fabric| !fabric.root_ca().is_empty())
                .map(|fabric| fabric.root_ca());

            // While the fail-safe is armed, an `AddTrustedRootCertificate`
            // command stages a root certificate that is not yet bound to a
            // fabric. Per the Matter Core spec it must still appear in the
            // `TrustedRootCertificates` list until the fail-safe expires or
            // the cert is consumed by `AddNOC` / `UpdateNOC` (at which point
            // the fabric table reports it).
            let mut certs = fabric_certs.chain(state.failsafe.pending_root_ca());

            match builder {
                ArrayAttributeRead::ReadAll(mut builder) => {
                    for cert in certs {
                        builder = builder.push(Octets::new(cert))?;
                    }

                    builder.end()
                }
                ArrayAttributeRead::ReadOne(index, builder) => {
                    if let Some(cert) = certs.nth(index as _) {
                        builder.set(Octets::new(cert))
                    } else {
                        Err(ErrorCode::ConstraintError.into())
                    }
                }
                ArrayAttributeRead::ReadNone(builder) => builder.end(),
            }
        })
    }

    fn current_fabric_index(&self, ctx: impl ReadContext) -> Result<u8, Error> {
        let attr = ctx.attr();
        Ok(attr.fab_idx)
    }

    fn handle_attestation_request<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: AttestationRequestRequest<'_>,
        response: AttestationResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!("Got Attestation Request");

        ctx.exchange().with_state(|state| {
            let sess = ctx.exchange().id().session(&mut state.sessions);

            // Switch to raw writer for the response
            // Necessary, as we want to take advantage of the `TLVWrite::str_cb` method
            // to in-place compute and write the attestation response and the signature as an octet string
            let mut parent = response.unchecked_into_parent();
            let writer = parent.writer();

            // Struct is already started
            // writer.start_struct(&CmdDataWriter::TAG)?;

            let epoch = (ctx.exchange().matter().epoch())().as_secs() as u32;

            let mut signature = MaybeUninit::uninit();
            let signature = signature.init_with(CanonPkcSignature::init()); // TODO MEDIUM BUFFER

            writer.str_cb(&TLVTag::Context(0), |buf| {
                let dev_att = ctx.exchange().matter().dev_att();

                let mut wb = WriteBuf::new(buf);
                wb.start_struct(&TLVTag::Anonymous)?;
                wb.str(&TLVTag::Context(1), dev_att.cert_declaration())?;
                wb.str(&TLVTag::Context(2), request.attestation_nonce()?.0)?;
                wb.u32(&TLVTag::Context(3), epoch)?;
                wb.end_container()?;

                let len = wb.get_tail();

                Self::compute_attestation_signature(
                    ctx.crypto(),
                    dev_att,
                    &mut wb,
                    sess.get_att_challenge().ok_or(ErrorCode::InvalidState)?,
                    signature,
                )?;

                Ok(len)
            })?;

            writer.str(&TLVTag::Context(1), signature.access())?;

            writer.end_container()?;

            Ok(parent)
        })
    }

    fn handle_certificate_chain_request<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: CertificateChainRequestRequest<'_>,
        response: CertificateChainResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!("Got Cert Chain Request");

        // Switch to raw writer for the response
        // Necessary, as we want to take advantage of the `TLVWrite::str_cb` method
        // to emplace the attestation certificate as an octet string
        let mut parent = response.unchecked_into_parent();
        let writer = parent.writer();

        // Struct is already started
        // writer.start_struct(&CmdDataWriter::TAG)?;

        let dev_att = ctx.exchange().matter().dev_att();

        writer.str(
            &TLVTag::Context(0),
            match request.certificate_type()? {
                CertificateChainTypeEnum::DACCertificate => dev_att.dac(),
                CertificateChainTypeEnum::PAICertificate => dev_att.pai(),
            },
        )?;

        writer.end_container()?;

        Ok(parent)
    }

    fn handle_csr_request<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: CSRRequestRequest<'_>,
        response: CSRResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!("Got CSR Request");

        let is_for_update_noc = request.is_for_update_noc()?.unwrap_or(false);

        GenCommHandler::with_armed_failsafe(&ctx, |state, _| {
            let sess = ctx.exchange().id().session(&mut state.sessions);

            // Per Matter Core spec section 11.18.6.5 (`CSRRequest`),
            // `isForUpdateNOC=true` is only valid over CASE — UpdateNOC
            // can never run over PASE. A CSRRequest of that flavour over
            // PASE is rejected with IM `INVALID_COMMAND` rather than
            // bubbling up the generic auth failure as `Failure`.
            if is_for_update_noc && !matches!(sess.get_session_mode(), SessionMode::Case { .. }) {
                return Err(ErrorCode::InvalidCommand.into());
            }

            let secret_key = if is_for_update_noc {
                state
                    .failsafe
                    .update_csr_req(ctx.crypto(), sess.get_session_mode())?
            } else {
                state
                    .failsafe
                    .add_csr_req(ctx.crypto(), sess.get_session_mode())?
            };

            // Switch to raw writer for the response
            // Necessary, as we want to take advantage of the `TLVWrite::str_cb` method
            // to in-place compute and write the CSR response and the signature as an octet string
            let mut parent = response.unchecked_into_parent();
            let writer = parent.writer();

            // Struct is already started
            // writer.start_struct(&CmdDataWriter::TAG)?;

            let mut signature = MaybeUninit::uninit();
            let signature = signature.init_with(CanonPkcSignature::init()); // TODO MEDIUM BUFFER

            writer.str_cb(&TLVTag::Context(0), |buf| {
                let mut wb = WriteBuf::new(buf);

                wb.start_struct(&TLVTag::Anonymous)?;
                wb.str_cb(&TLVTag::Context(1), |buf| {
                    ctx.crypto()
                        .secret_key(secret_key)?
                        .csr(buf)
                        .map(|slice| slice.len())
                })?;
                wb.str(&TLVTag::Context(2), request.csr_nonce()?.0)?;
                wb.end_container()?;

                let len = wb.get_tail();

                Self::compute_attestation_signature(
                    ctx.crypto(),
                    ctx.exchange().matter().dev_att(),
                    &mut wb,
                    sess.get_att_challenge().ok_or(ErrorCode::InvalidState)?,
                    signature,
                )?;

                Ok(len)
            })?;

            writer.str(&TLVTag::Context(1), signature.access())?;

            writer.end_container()?;

            Ok(parent)
        })
    }

    fn handle_add_noc<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: AddNOCRequest<'_>,
        mut response: NOCResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!("Got Add NOC Request");

        let icac = request
            .icac_value()?
            .as_ref()
            .map(|icac| icac.0)
            .filter(|icac| !icac.is_empty());

        let mut added_fab_idx = None;
        // Captured inside the closure so we can emit `AccessControlEntryChanged`
        // for the auto-created admin ACL entry *after* the failsafe-armed
        // closure unwinds successfully (Matter Core spec section 9.10.7).
        let mut admin_acl_entry: Option<AclEntry> = None;

        let buf = response.writer().available_space();

        let status = NodeOperationalCertStatusEnum::map(GenCommHandler::with_armed_failsafe(
            &ctx,
            |state, mut notify_mdns| {
                let sess = ctx.exchange().id().session(&mut state.sessions);

                let fabric = state.failsafe.add_noc(
                    ctx.crypto(),
                    &mut state.fabrics,
                    sess.get_session_mode(),
                    request.admin_vendor_id()?,
                    icac,
                    request.noc_value()?.0,
                    request.ipk_value()?.0,
                    request.case_admin_subject()?,
                    buf,
                    &mut notify_mdns,
                )?;

                let fab_idx = fabric.fab_idx();
                // Snapshot the freshly seeded admin ACL entry while we still
                // hold the state lock; we'll emit the event once we're sure
                // the fabric stays committed (i.e. no rollback happened).
                let captured_admin_entry = fabric.acl_iter().next().cloned();
                let succeeded = Cell::new(false);

                let _fab_guard = scopeguard::guard(fab_idx, |fab_idx| {
                    if !succeeded.get() {
                        // Remove the fabric if we fail further down this function
                        warn!("Removing fabric {} due to failure", fab_idx.get());

                        unwrap!(state.fabrics.remove(fab_idx));

                        notify_mdns();
                    }
                });

                if matches!(sess.get_session_mode(), SessionMode::Pase { .. }) {
                    sess.upgrade_fabric_idx(fab_idx)?;
                }

                succeeded.set(true);
                added_fab_idx = Some(fab_idx.get());
                admin_acl_entry = captured_admin_entry;

                Ok(())
            },
        ))?;

        // AddNOC mutates NOCs, Fabrics, CommissionedFabrics, TrustedRootCerts, etc.
        ctx.notify_own_cluster_changed();

        // Emit the `AccessControlEntryChanged` event for the auto-created admin
        // entry. AddNOC happens over PASE during commissioning, so per Matter
        // Core spec 9.10.7 the event has `adminNodeID = null` and
        // `adminPasscodeID = 0`.
        if let (Some(fab_idx), Some(entry)) = (added_fab_idx, &admin_acl_entry) {
            emit_acl_entry_changed(
                &ctx,
                crate::tlv::Nullable::none(),
                crate::tlv::Nullable::some(0u16),
                ChangeTypeEnum::Added,
                entry,
                fab_idx,
            )?;
        }

        response
            .status_code(status)?
            .fabric_index(added_fab_idx)?
            .debug_text(None)?
            .end()
    }

    fn handle_update_noc<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: UpdateNOCRequest<'_>,
        mut response: NOCResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!("Got Update NOC Request");

        let icac = request
            .icac_value()?
            .as_ref()
            .map(|icac| icac.0)
            .filter(|icac| !icac.is_empty());

        let buf = response.writer().available_space();

        let status = NodeOperationalCertStatusEnum::map(GenCommHandler::with_armed_failsafe(
            &ctx,
            |state, notify_mdns| {
                let sess = ctx.exchange().id().session(&mut state.sessions);

                state.failsafe.update_noc(
                    ctx.crypto(),
                    &mut state.fabrics,
                    sess.get_session_mode(),
                    icac,
                    request.noc_value()?.0,
                    buf,
                    notify_mdns,
                )?;

                Ok(())
            },
        ))?;

        // UpdateNOC mutates the NOCs / Fabrics lists for the calling fabric
        ctx.notify_own_cluster_changed();

        response
            .status_code(status)?
            .fabric_index(Some(ctx.cmd().fab_idx))?
            .debug_text(None)?
            .end()
    }

    fn handle_update_fabric_label<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: UpdateFabricLabelRequest<'_>,
        response: NOCResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!("Got Update Fabric Label Request: {:?}", request.label());

        let mut updated_fab_idx = None;

        let status = NodeOperationalCertStatusEnum::map(ctx.exchange().with_state(|state| {
            let sess = ctx.exchange().id().session(&mut state.sessions);

            // `UpdateFabricLabel` is fabric-scoped and the IM access-control
            // check (see `cluster::check_cmd_access`) already rejects calls
            // from a session with no associated fabric (PASE pre-AddNOC) with
            // `UnsupportedAccess`. Anything that gets here therefore has an
            // accessing fabric — and per the spec / CHIP reference impl,
            // that includes a PASE session whose fab_idx was upgraded by
            // `AddNOC` (`session.upgrade_fabric_idx`). So allow Case *and*
            // Pase as long as fab_idx > 0; the `accessing_fab_idx()` helper
            // returns 0 only for plain-text / un-upgraded PASE.
            let fab_idx = NonZeroU8::new(sess.get_local_fabric_idx())
                .ok_or(ErrorCode::GennCommInvalidAuthentication)?;

            let fabric = state
                .fabrics
                .update_label(fab_idx, request.label()?)
                .map_err(|e| {
                    if e.code() == ErrorCode::Invalid {
                        ErrorCode::NocLabelConflict.into()
                    } else {
                        e
                    }
                })?;

            updated_fab_idx = Some(fabric.fab_idx().get());

            Ok(())
        }))?;

        // UpdateFabricLabel mutates the Fabrics list
        ctx.notify_own_cluster_changed();

        response
            .status_code(status)?
            .fabric_index(updated_fab_idx)?
            .debug_text(None)?
            .end()
    }

    fn handle_remove_fabric<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: RemoveFabricRequest<'_>,
        response: NOCResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!("Got Remove Fabric Request");

        let fab_idx = NonZeroU8::new(request.fabric_index()?).ok_or(ErrorCode::ConstraintError)?;

        let notify_mdns = || ctx.exchange().matter().notify_mdns_changed();

        let mut persist = FabricPersist::new(ctx.kv());

        let (status, opener_fabric_removed) = ctx.exchange().with_state(|state| {
            let sess = ctx.exchange().id().session(&mut state.sessions);

            if state.fabrics.remove(fab_idx).is_ok() {
                // If our own session is running on the fabric being removed,
                // we need to expire it rather than immediately remove it, so that
                // the response can be sent back properly
                let expire_sess_id =
                    (sess.get_local_fabric_idx() == fab_idx.get()).then_some(sess.id());

                // Remove all sessions related to the fabric being removed
                // If `expire_sess_id` is Some, the session will be expired instead of removed.
                state.sessions.remove_for_fabric(fab_idx, expire_sess_id);

                // Notify that a session was removed
                ctx.exchange().matter().session_removed.notify();

                // Notify that our mDNS records might have changed
                notify_mdns();

                // Note that since we might have removed our own session, the exchange
                // will terminate with a "NoSession" error, but that's OK and handled properly

                persist.remove(fab_idx)?;

                info!("Removed operational fabric with local index {}", fab_idx);

                // If the removed fabric was the one that opened the current
                // commissioning window, `AdminFabricIndex` (and `AdminVendorId`)
                // transition to null and subscribers must be notified — see
                // Matter Core spec section 11.18.7.
                let opener_fabric_removed = state
                    .pase
                    .comm_window()
                    .and_then(|w| w.opener())
                    .map(|opener| opener.fab_idx == fab_idx)
                    .unwrap_or(false);

                Ok::<_, Error>((NodeOperationalCertStatusEnum::OK, opener_fabric_removed))
            } else {
                Ok((NodeOperationalCertStatusEnum::InvalidFabricIndex, false))
            }
        })?;

        persist.run()?;

        // RemoveFabric mutates NOCs, Fabrics, CommissionedFabrics, TrustedRootCerts
        ctx.notify_own_cluster_changed();

        if opener_fabric_removed {
            ctx.notify_cluster_changed(ROOT_ENDPOINT_ID, adm_comm::FULL_CLUSTER.id);
        }

        response
            .status_code(status)?
            .fabric_index(Some(fab_idx.get()))?
            .debug_text(None)?
            .end()
    }

    fn handle_add_trusted_root_certificate(
        &self,
        ctx: impl InvokeContext,
        request: AddTrustedRootCertificateRequest<'_>,
    ) -> Result<(), Error> {
        info!("Got Add Trusted Root Cert Request");

        // Self-signature validation in `add_trusted_root_cert` re-encodes the
        // RCAC into ASN.1 to feed it to ECDSA verify; sized to
        // `MAX_CERT_ASN1_LEN` (the same bound `validate_certs` uses for the
        // NOC chain).
        // TODO XXX FIXME: LARGE BUFFER.
        // We can avoid it if we had access to
        // the output buffer (TX), but this is not possible yet for handler methods
        // that are not expected to return command responses other than status result.
        let mut buf = [0u8; crate::cert::MAX_CERT_ASN1_LEN];

        GenCommHandler::with_armed_failsafe(&ctx, |state, _| {
            let sess = ctx.exchange().id().session(&mut state.sessions);

            state.failsafe.add_trusted_root_cert(
                ctx.crypto(),
                sess.get_session_mode(),
                request.root_ca_certificate()?.0,
                &mut buf,
            )
        })
    }

    fn handle_set_vid_verification_statement(
        &self,
        _ctx: impl InvokeContext,
        _request: SetVIDVerificationStatementRequest<'_>,
    ) -> Result<(), Error> {
        Ok(()) // TODO
    }

    fn handle_sign_vid_verification_request<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: SignVIDVerificationRequestRequest<'_>,
        _response: SignVIDVerificationResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }
}
