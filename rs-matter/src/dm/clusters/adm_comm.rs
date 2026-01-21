/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
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

//! This module contains the implementation of the Administrative Commissioning cluster and its handler.

use crate::dm::{Cluster, Context, Dataver, InvokeContext, ReadContext};
use crate::error::Error;
use crate::sc::pase::{CommWindowOpener, CommWindowType};
use crate::tlv::Nullable;

pub use crate::dm::clusters::decl::administrator_commissioning::*;
use crate::transport::session::SessionMode;

/// The system implementation of a handler for the Administrative Commissioning Matter cluster.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AdminCommHandler {
    dataver: Dataver,
}

impl AdminCommHandler {
    /// Create a new instance of `AdminCommHandler` with the given `Dataver`.
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    /// Return a `CommWindowOpener` instance for the current session
    ///
    /// Used when opening a new commissioning window so as to preserve the fabric index and vendor ID
    /// of the admin fabric which opened the current commissioning window.
    fn current_window_opener(&self, ctx: impl Context) -> Result<Option<CommWindowOpener>, Error> {
        ctx.exchange().with_session(|session| {
            Ok(match session.get_session_mode() {
                SessionMode::Case { fab_idx, .. } => Some(CommWindowOpener {
                    fab_idx: *fab_idx,
                    vendor_id: unwrap!(ctx.exchange().matter().fabric_mgr.borrow().get(*fab_idx))
                        .vendor_id(),
                }),
                _ => None,
            })
        })
    }
}

impl ClusterHandler for AdminCommHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_features(Feature::BASIC.bits());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn window_status(&self, ctx: impl ReadContext) -> Result<CommissioningWindowStatusEnum, Error> {
        let matter = ctx.exchange().matter();
        let mut pase_mgr = matter.pase_mgr.borrow_mut();
        let comm_window = pase_mgr.comm_window(&ctx)?;

        let window_type = comm_window.map(|comm_window| comm_window.comm_window_type());

        Ok(match window_type {
            Some(CommWindowType::Basic) => CommissioningWindowStatusEnum::BasicWindowOpen,
            Some(CommWindowType::Enhanced) => CommissioningWindowStatusEnum::EnhancedWindowOpen,
            None => CommissioningWindowStatusEnum::WindowNotOpen,
        })
    }

    fn admin_fabric_index(&self, ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        let matter = ctx.exchange().matter();
        let mut pase_mgr = matter.pase_mgr.borrow_mut();
        let comm_window = pase_mgr.comm_window(&ctx)?;

        if let Some(opener) = comm_window.and_then(|comm_window| comm_window.opener()) {
            if ctx
                .exchange()
                .matter()
                .fabric_mgr
                .borrow()
                .get(opener.fab_idx)
                .is_some()
            {
                // Fabric is still around, return its index
                // If it is not around - and contrary to vendor ID - we should NOT return it
                return Ok(Nullable::some(opener.fab_idx.get()));
            }
        }

        Ok(Nullable::none())
    }

    fn admin_vendor_id(&self, ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        let matter = ctx.exchange().matter();
        let mut pase_mgr = matter.pase_mgr.borrow_mut();
        let comm_window = pase_mgr.comm_window(&ctx)?;

        Ok(Nullable::new(
            comm_window
                .and_then(|comm_window| comm_window.opener())
                .map(|opener| opener.vendor_id),
        ))
    }

    fn handle_open_commissioning_window(
        &self,
        ctx: impl InvokeContext,
        request: OpenCommissioningWindowRequest<'_>,
    ) -> Result<(), Error> {
        let opener = self.current_window_opener(&ctx)?;
        let matter = ctx.matter();

        matter.pase_mgr.borrow_mut().open_comm_window(
            request.pake_passcode_verifier()?.0,
            request.salt()?.0,
            request.iterations()?,
            request.discriminator()?,
            request.commissioning_timeout()?,
            opener,
            &ctx,
        )
    }

    fn handle_open_basic_commissioning_window(
        &self,
        ctx: impl InvokeContext,
        request: OpenBasicCommissioningWindowRequest<'_>,
    ) -> Result<(), Error> {
        let opener = self.current_window_opener(&ctx)?;
        let matter = ctx.matter();

        matter.pase_mgr.borrow_mut().open_basic_comm_window(
            matter.dev_comm().password,
            matter.dev_comm().discriminator,
            request.commissioning_timeout()?,
            opener,
            &ctx,
        )
    }

    fn handle_revoke_commissioning(&self, ctx: impl InvokeContext) -> Result<(), Error> {
        ctx.matter().pase_mgr.borrow_mut().close_comm_window(&ctx)?;

        // TODO: Send status code if no commissioning window is open?

        Ok(())
    }
}
