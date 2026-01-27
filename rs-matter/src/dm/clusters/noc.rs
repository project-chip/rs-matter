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

use crate::cert::CertRef;
use crate::crypto::{CanonPkcSignature, Crypto, SigningSecretKey};
use crate::dm::clusters::dev_att::DeviceAttestation;
use crate::dm::{ArrayAttributeRead, Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::fabric::{Fabric, MAX_FABRICS};
use crate::tlv::{
    Nullable, Octets, OctetsArrayBuilder, OctetsBuilder, TLVBuilder, TLVBuilderParent, TLVElement,
    TLVTag, TLVWrite,
};
use crate::transport::session::SessionMode;
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
                ErrorCode::ConstraintError => Ok(Self::MissingCsr),
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
    fn compute_attestation_signature<C: Crypto, D: DeviceAttestation>(
        dev_att: D,
        attest_element: &mut WriteBuf,
        attest_challenge: &[u8],
        signature: &mut CanonPkcSignature,
        crypto: C,
    ) -> Result<(), Error> {
        let dac_key = crypto.secret_key(dev_att.dac_priv_key())?;

        attest_element.copy_from_slice(attest_challenge)?;
        dac_key.sign(attest_element.as_slice(), signature);

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
        let fabric_mgr = ctx.exchange().matter().fabric_mgr.borrow();
        let mut fabrics = fabric_mgr.iter().filter(|fabric| {
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
        let fabric_mgr = ctx.exchange().matter().fabric_mgr.borrow();
        let mut fabrics = fabric_mgr.iter().filter(|fabric| {
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
    }

    fn supported_fabrics(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(MAX_FABRICS as u8)
    }

    fn commissioned_fabrics(&self, ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(ctx.exchange().matter().fabric_mgr.borrow().iter().count() as _)
    }

    fn trusted_root_certificates<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<OctetsArrayBuilder<P>, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        let attr = ctx.attr();
        let fabric_mgr = ctx.exchange().matter().fabric_mgr.borrow();
        let mut fabrics = fabric_mgr.iter().filter(|fabric| {
            (!attr.fab_filter || attr.fab_idx == fabric.fab_idx().get())
                && !fabric.root_ca().is_empty()
        });

        match builder {
            ArrayAttributeRead::ReadAll(mut builder) => {
                for fabric in fabrics {
                    builder = builder.push(Octets::new(fabric.root_ca()))?;
                }

                builder.end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let fabric = fabrics.nth(index as _);

                if let Some(fabric) = fabric {
                    builder.set(Octets::new(fabric.root_ca()))
                } else {
                    Err(ErrorCode::ConstraintError.into())
                }
            }
            ArrayAttributeRead::ReadNone(builder) => builder.end(),
        }
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

        ctx.exchange().with_session(|sess| {
            // Switch to raw writer for the response
            // Necessary, as we want to take advantage of the `TLVWrite::str_cb` method
            // to in-place compute and write the attestation response and the signature as an octet string
            let mut parent = response.unchecked_into_parent();
            let writer = parent.writer();

            // Struct is already started
            // writer.start_struct(&CmdDataWriter::TAG)?;

            let epoch = (ctx.exchange().matter().epoch())().as_secs() as u32;

            let mut signature = MaybeUninit::<CanonPkcSignature>::uninit(); // TODO MEDIUM BUFFER
            let signature = signature.init_zeroed();

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
                    dev_att,
                    &mut wb,
                    sess.get_att_challenge(),
                    signature,
                    ctx.crypto(),
                )?;

                Ok(len)
            })?;

            writer.str(&TLVTag::Context(1), signature)?;

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

        ctx.exchange().with_session(|sess| {
            let mut failsafe = ctx.exchange().matter().failsafe.borrow_mut();

            let secret_key = if request.is_for_update_noc()?.unwrap_or(false) {
                failsafe.update_csr_req(sess.get_session_mode(), ctx.crypto())
            } else {
                failsafe.add_csr_req(sess.get_session_mode(), ctx.crypto())
            }?;

            // Switch to raw writer for the response
            // Necessary, as we want to take advantage of the `TLVWrite::str_cb` method
            // to in-place compute and write the CSR response and the signature as an octet string
            let mut parent = response.unchecked_into_parent();
            let writer = parent.writer();

            // Struct is already started
            // writer.start_struct(&CmdDataWriter::TAG)?;

            let mut signature = MaybeUninit::<CanonPkcSignature>::uninit(); // TODO MEDIUM BUFFER
            let signature = signature.init_zeroed();

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
                    ctx.exchange().matter().dev_att(),
                    &mut wb,
                    sess.get_att_challenge(),
                    signature,
                    ctx.crypto(),
                )?;

                Ok(len)
            })?;

            writer.str(&TLVTag::Context(1), signature)?;

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

        let buf = response.writer().available_space();

        let status = NodeOperationalCertStatusEnum::map(ctx.exchange().with_session(|sess| {
            let matter = ctx.exchange().matter();
            let fab_idx = ctx.exchange().matter().failsafe.borrow_mut().add_noc(
                &ctx.exchange().matter().fabric_mgr,
                sess.get_session_mode(),
                request.admin_vendor_id()?,
                icac,
                request.noc_value()?.0,
                request.ipk_value()?.0,
                request.case_admin_subject()?,
                buf,
                &mut || matter.notify_mdns(),
                ctx.crypto(),
            )?;

            let succeeded = Cell::new(false);

            let _fab_guard = scopeguard::guard(fab_idx, |fab_idx| {
                if !succeeded.get() {
                    // Remove the fabric if we fail further down this function
                    warn!("Removing fabric {} due to failure", fab_idx.get());

                    unwrap!(matter
                        .fabric_mgr
                        .borrow_mut()
                        .remove(fab_idx, &mut || ctx.exchange().matter().notify_mdns()));
                }
            });

            if matches!(sess.get_session_mode(), SessionMode::Pase { .. }) {
                sess.upgrade_fabric_idx(fab_idx)?;
            }

            succeeded.set(true);

            added_fab_idx = Some(fab_idx.get());

            Ok(())
        }))?;

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

        let status = NodeOperationalCertStatusEnum::map(ctx.exchange().with_session(|sess| {
            ctx.exchange().matter().failsafe.borrow_mut().update_noc(
                &ctx.exchange().matter().fabric_mgr,
                sess.get_session_mode(),
                icac,
                request.noc_value()?.0,
                buf,
                &mut || ctx.exchange().matter().notify_mdns(),
                ctx.crypto(),
            )?;

            Ok(())
        }))?;

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

        let status = NodeOperationalCertStatusEnum::map(ctx.exchange().with_session(|sess| {
            let SessionMode::Case { fab_idx, .. } = sess.get_session_mode() else {
                return Err(ErrorCode::GennCommInvalidAuthentication.into());
            };

            updated_fab_idx = Some(fab_idx.get());

            ctx.exchange()
                .matter()
                .fabric_mgr
                .borrow_mut()
                .update_label(*fab_idx, request.label()?)
                .map_err(|e| {
                    if e.code() == ErrorCode::Invalid {
                        ErrorCode::NocLabelConflict.into()
                    } else {
                        e
                    }
                })
        }))?;

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

        let status = if ctx
            .exchange()
            .matter()
            .fabric_mgr
            .borrow_mut()
            .remove(fab_idx, &mut || ctx.exchange().matter().notify_mdns())
            .is_ok()
        {
            // If our own session is running on the fabric being removed,
            // we need to expire it rather than immediately remove it, so that
            // the response can be sent back properly
            let expire_sess_id = ctx.exchange().with_session(|sess| {
                Ok((sess.get_local_fabric_idx() == fab_idx.get()).then_some(sess.id()))
            })?;

            // Remove all sessions related to the fabric being removed
            // If `expire_sess_id` is Some, the session will be expired instead of removed.
            ctx.exchange()
                .matter()
                .transport_mgr
                .session_mgr
                .borrow_mut()
                .remove_for_fabric(fab_idx, expire_sess_id);

            // Notify that the fabrics need to be persisted
            // We need to explicitly do this because if the fabric being removed
            // is the one on which the session is running, the session will be removed
            // and the response will fail
            ctx.exchange().matter().notify_persist();

            // Notify that a session was removed
            ctx.exchange()
                .matter()
                .transport_mgr
                .session_removed
                .notify();

            // Note that since we might have removed our own session, the exchange
            // will terminate with a "NoSession" error, but that's OK and handled properly

            info!("Removed operational fabric with local index {}", fab_idx);

            NodeOperationalCertStatusEnum::OK
        } else {
            NodeOperationalCertStatusEnum::InvalidFabricIndex
        };

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

        ctx.exchange().with_session(|sess| {
            ctx.exchange()
                .matter()
                .failsafe
                .borrow_mut()
                .add_trusted_root_cert(sess.get_session_mode(), request.root_ca_certificate()?.0)
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
