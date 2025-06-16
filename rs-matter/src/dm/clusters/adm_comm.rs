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

use core::num::NonZeroU8;

use crate::dm::objects::{Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::Error;
use crate::sc::pake::PaseSessionType;
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
}

impl ClusterHandler for AdminCommHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_features(Feature::BASIC.bits());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn window_status(&self, ctx: &ReadContext<'_>) -> Result<CommissioningWindowStatusEnum, Error> {
        let session_type = ctx.exchange().matter().pase_mgr.borrow().session_type();

        Ok(match session_type {
            Some(PaseSessionType::Basic) => CommissioningWindowStatusEnum::BasicWindowOpen,
            Some(PaseSessionType::Enhanced) => CommissioningWindowStatusEnum::EnhancedWindowOpen,
            None => CommissioningWindowStatusEnum::WindowNotOpen,
        })
    }

    fn admin_fabric_index(&self, ctx: &ReadContext<'_>) -> Result<Nullable<u8>, Error> {
        let session_mgr = ctx.exchange().matter().transport_mgr.session_mgr.borrow();

        let fab_idx = session_mgr.iter().find_map(|session| {
            if let SessionMode::Pase { fab_idx } = session.get_session_mode() {
                Some(*fab_idx)
            } else {
                None
            }
        });

        Ok(Nullable::new(fab_idx))
    }

    fn admin_vendor_id(&self, ctx: &ReadContext<'_>) -> Result<Nullable<u16>, Error> {
        let session_mgr = ctx.exchange().matter().transport_mgr.session_mgr.borrow();
        let fabric_mgr = ctx.exchange().matter().fabric_mgr.borrow();

        let fab_idx = session_mgr.iter().find_map(|session| {
            if let SessionMode::Pase { fab_idx } = session.get_session_mode() {
                Some(*fab_idx)
            } else {
                None
            }
        });

        let vendor_id = fab_idx
            .and_then(NonZeroU8::new)
            .and_then(|idx| fabric_mgr.get(idx))
            .map(|fabric| fabric.vendor_id());

        Ok(Nullable::new(vendor_id))
    }

    fn handle_open_commissioning_window(
        &self,
        ctx: &InvokeContext<'_>,
        request: OpenCommissioningWindowRequest<'_>,
    ) -> Result<(), Error> {
        let matter = ctx.exchange().matter();

        matter.pase_mgr.borrow_mut().enable_pase_session(
            request.pake_passcode_verifier()?.0,
            request.salt()?.0,
            request.iterations()?,
            request.discriminator()?,
            request.commissioning_timeout()?,
            &matter.transport_mgr.mdns,
        )
    }

    fn handle_open_basic_commissioning_window(
        &self,
        ctx: &InvokeContext<'_>,
        request: OpenBasicCommissioningWindowRequest<'_>,
    ) -> Result<(), Error> {
        let matter = ctx.exchange().matter();

        matter.pase_mgr.borrow_mut().enable_basic_pase_session(
            matter.dev_comm().password,
            matter.dev_comm().discriminator,
            request.commissioning_timeout()?,
            &matter.transport_mgr.mdns,
        )
    }

    fn handle_revoke_commissioning(&self, ctx: &InvokeContext<'_>) -> Result<(), Error> {
        let matter = ctx.exchange().matter();

        matter
            .pase_mgr
            .borrow_mut()
            .disable_pase_session(&matter.transport_mgr.mdns)?;

        // TODO: Send status code if no commissioning window is open?

        Ok(())
    }
}
