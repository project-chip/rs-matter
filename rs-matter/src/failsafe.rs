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
use crate::crypto::KeyPair;
use crate::dm::BasicContext;
use crate::error::{Error, ErrorCode};
use crate::fabric::FabricMgr;
use crate::im::IMStatusCode;
use crate::tlv::TLVElement;
use crate::transport::session::SessionMode;
use crate::utils::bitflags::bitflags;
use crate::utils::cell::RefCell;
use crate::utils::epoch::Epoch;
use crate::utils::init::{init, Init};
use crate::utils::rand::Rand;
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

pub struct FailSafe {
    state: State,
    key_pair: Option<KeyPair>,
    root_ca: Vec<u8, { MAX_CERT_TLV_LEN }>,
    epoch: Epoch,
    rand: Rand,
    breadcrumb: u64,
}

impl FailSafe {
    #[inline(always)]
    pub const fn new(epoch: Epoch, rand: Rand) -> Self {
        Self {
            state: State::Idle,
            key_pair: None,
            root_ca: Vec::new(),
            epoch,
            rand,
            breadcrumb: 0,
        }
    }

    pub fn init(epoch: Epoch, rand: Rand) -> impl Init<Self> {
        init!(Self {
            state: State::Idle,
            key_pair: None,
            root_ca <- Vec::init(),
            epoch,
            rand,
            breadcrumb: 0
        })
    }

    pub fn arm(
        &mut self,
        timeout_secs: u16,
        breadcrumb: u64,
        session_mode: &SessionMode,
        ctx: impl BasicContext,
    ) -> Result<(), Error> {
        self.update_state_timeout();

        if matches!(self.state, State::Idle) {
            if matches!(session_mode, SessionMode::PlainText) {
                // Only PASE and CASE sessions supported
                return Err(ErrorCode::GennCommInvalidAuthentication)?;
            }

            // Cannot arm via CASE while there's an active window
            if ctx
                .matter()
                .pase_mgr
                .borrow_mut()
                .comm_window(&ctx)?
                .is_some()
                && matches!(session_mode, SessionMode::Case { .. })
            {
                return Err(ErrorCode::Busy)?;
            }

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

        ctx.armed_at = (self.epoch)();
        ctx.timeout_secs = timeout_secs;
        self.breadcrumb = breadcrumb;

        Ok(())
    }

    pub fn disarm(&mut self, session_mode: &SessionMode) -> Result<(), Error> {
        self.update_state_timeout();

        if matches!(self.state, State::Idle) {
            error!("Received Fail-Safe Disarm without it being armed");
            return Err(ErrorCode::FailSafeRequired)?;
        }

        // Has to be a CASE session
        Self::get_case_fab_idx(session_mode)?;

        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::empty(),
            NocFlags::empty(),
        )?;
        self.state = State::Idle;
        self.breadcrumb = 0;

        Ok(())
    }

    pub fn add_trusted_root_cert(
        &mut self,
        session_mode: &SessionMode,
        root_ca: &[u8],
    ) -> Result<(), Error> {
        self.update_state_timeout();

        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::ADD_ROOT_CERT_RECVD,
            NocFlags::ADD_ROOT_CERT_RECVD,
        )?;

        self.root_ca.clear();
        self.root_ca
            .extend_from_slice(root_ca)
            .map_err(|_| ErrorCode::InvalidCommand)?;

        self.add_flags(NocFlags::ADD_ROOT_CERT_RECVD);

        Ok(())
    }

    pub fn add_csr_req(&mut self, session_mode: &SessionMode) -> Result<&KeyPair, Error> {
        self.update_state_timeout();

        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::ADD_CSR_REQ_RECVD | NocFlags::UPDATE_CSR_REQ_RECVD,
            NocFlags::ADD_CSR_REQ_RECVD,
        )?;

        self.key_pair = Some(KeyPair::new(self.rand)?);

        self.add_flags(NocFlags::ADD_CSR_REQ_RECVD);

        Ok(unwrap!(self.key_pair.as_ref()))
    }

    pub fn update_csr_req(&mut self, session_mode: &SessionMode) -> Result<&KeyPair, Error> {
        self.update_state_timeout();

        // Must be a CASE session
        Self::get_case_fab_idx(session_mode)?;

        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::ADD_CSR_REQ_RECVD | NocFlags::UPDATE_CSR_REQ_RECVD,
            NocFlags::UPDATE_CSR_REQ_RECVD,
        )?;

        self.key_pair = Some(KeyPair::new(self.rand)?);

        self.add_flags(NocFlags::UPDATE_CSR_REQ_RECVD);

        Ok(unwrap!(self.key_pair.as_ref()))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_noc(
        &mut self,
        fabric_mgr: &RefCell<FabricMgr>,
        session_mode: &SessionMode,
        icac: Option<&[u8]>,
        noc: &[u8],
        buf: &mut [u8],
        mdns_notif: &mut dyn FnMut(),
    ) -> Result<(), Error> {
        self.update_state_timeout();

        let fab_idx = Self::get_case_fab_idx(session_mode)?;

        self.check_state(
            session_mode,
            NocFlags::ADD_ROOT_CERT_RECVD | NocFlags::UPDATE_CSR_REQ_RECVD,
            NocFlags::ADD_NOC_RECVD | NocFlags::ADD_CSR_REQ_RECVD | NocFlags::UPDATE_NOC_RECVD,
            NocFlags::UPDATE_NOC_RECVD,
        )?;

        Self::validate_certs(
            &CertRef::new(TLVElement::new(noc)),
            icac.map(|icac| CertRef::new(TLVElement::new(icac)))
                .as_ref(),
            &CertRef::new(TLVElement::new(&self.root_ca)),
            buf,
        )?;

        fabric_mgr.borrow_mut().update(
            fab_idx,
            unwrap!(self.key_pair.take()),
            &self.root_ca,
            noc,
            icac.unwrap_or(&[]),
            mdns_notif,
        )?;

        self.add_flags(NocFlags::UPDATE_NOC_RECVD);

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_noc(
        &mut self,
        fabric_mgr: &RefCell<FabricMgr>,
        session_mode: &SessionMode,
        vendor_id: u16,
        icac: Option<&[u8]>,
        noc: &[u8],
        ipk: &[u8],
        case_admin_subject: u64,
        buf: &mut [u8],
        mdns_notif: &mut dyn FnMut(),
    ) -> Result<NonZeroU8, Error> {
        self.update_state_timeout();

        self.check_state(
            session_mode,
            NocFlags::ADD_ROOT_CERT_RECVD | NocFlags::ADD_CSR_REQ_RECVD,
            NocFlags::ADD_NOC_RECVD | NocFlags::UPDATE_CSR_REQ_RECVD | NocFlags::UPDATE_NOC_RECVD,
            NocFlags::ADD_NOC_RECVD,
        )?;

        Self::validate_certs(
            &CertRef::new(TLVElement::new(noc)),
            icac.map(|icac| CertRef::new(TLVElement::new(icac)))
                .as_ref(),
            &CertRef::new(TLVElement::new(&self.root_ca)),
            buf,
        )?;

        // TODO: Copy functionality from C++ FabricTable::FindExistingFabricByNocChaining
        // i.e. need to check to see if a fabric with these creds are already present

        let fab_idx = fabric_mgr
            .borrow_mut()
            .add(
                unwrap!(self.key_pair.take()),
                &self.root_ca,
                noc,
                icac.unwrap_or(&[]),
                ipk,
                vendor_id,
                case_admin_subject,
                mdns_notif,
            )
            .map_err(|e| {
                if e.code() == ErrorCode::ResourceExhausted {
                    ErrorCode::NocFabricTableFull.into()
                } else {
                    e
                }
            })?
            .fab_idx();

        info!("Added operational fabric with local index {}", fab_idx);

        let State::Armed(ctx) = &mut self.state else {
            // Impossible to be in any other state because otherwise
            // check_state would have failed
            unreachable!();
        };

        ctx.fab_idx = fab_idx.get();
        self.add_flags(NocFlags::ADD_NOC_RECVD);

        Ok(fab_idx)
    }

    pub fn breadcrumb(&mut self) -> u64 {
        self.update_state_timeout();
        self.breadcrumb
    }

    pub fn set_breadcrumb(&mut self, value: u64) {
        self.breadcrumb = value;
    }

    fn validate_certs(
        noc: &CertRef,
        icac: Option<&CertRef>,
        root: &CertRef,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let mut verifier = noc.verify_chain_start();

        if let Some(icac) = icac {
            // If ICAC is present handle it
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
                // State is not what is expected for that concrete command

                if op == NocFlags::ADD_NOC_RECVD
                    && !ctx.flags.contains(NocFlags::UPDATE_CSR_REQ_RECVD)
                    || op == NocFlags::UPDATE_NOC_RECVD
                        && !ctx.flags.contains(NocFlags::UPDATE_CSR_REQ_RECVD)
                {
                    // Return a more concrete error if the problem is that the CSR request is missing
                    Err(ErrorCode::NocMissingCsr)?;
                }

                Err(ErrorCode::ConstraintError)?;
            }

            if !ctx.flags.intersection(absent).is_empty() {
                // State is not what is expected for that concrete command

                if op == NocFlags::ADD_NOC_RECVD
                    && ctx.flags.contains(NocFlags::UPDATE_CSR_REQ_RECVD)
                    || op == NocFlags::UPDATE_NOC_RECVD
                        && ctx.flags.contains(NocFlags::ADD_CSR_REQ_RECVD)
                {
                    // Return a more concrete error if the problem is an add/update NOC mismatch
                    Err(ErrorCode::NocFabricConflict)?;
                }

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

    fn update_state_timeout(&mut self) {
        if let State::Armed(ctx) = &mut self.state {
            let now = (self.epoch)();
            if now >= ctx.armed_at + Duration::from_secs(ctx.timeout_secs as u64) {
                self.state = State::Idle;
                self.breadcrumb = 0;
            }
        }
    }
}
