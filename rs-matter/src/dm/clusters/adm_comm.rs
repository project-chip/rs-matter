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

use rand_core::RngCore;

use crate::crypto::Crypto;
use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::Error;
use crate::sc::pase::spake2p::SPAKE2P_VERIFIER_SALT_ZEROED;
use crate::sc::pase::{CommWindowOpener, CommWindowType};
use crate::tlv::Nullable;
use crate::MatterState;

pub use crate::dm::clusters::decl::administrator_commissioning::*;
use crate::transport::exchange::ExchangeId;
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
    fn current_window_opener(state: &mut MatterState, id: &ExchangeId) -> Option<CommWindowOpener> {
        let session = id.session(&mut state.sessions);

        match session.get_session_mode() {
            SessionMode::Case { fab_idx, .. } => Some(CommWindowOpener {
                fab_idx: *fab_idx,
                vendor_id: unwrap!(state.fabrics.get(*fab_idx)).vendor_id(),
            }),
            _ => None,
        }
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
        let notify_mdns = || ctx.exchange().matter().notify_mdns_changed();
        let notify_change =
            |endpt_id, clust_id, attr_id| ctx.notify_attr_changed(endpt_id, clust_id, attr_id);

        ctx.exchange().with_state(|state| {
            state
                .pase
                .check_comm_window_timeout(notify_mdns, notify_change)?;

            let comm_window = state.pase.comm_window();

            let window_type = comm_window.map(|comm_window| comm_window.comm_window_type());

            Ok(match window_type {
                Some(CommWindowType::Basic) => CommissioningWindowStatusEnum::BasicWindowOpen,
                Some(CommWindowType::Enhanced) => CommissioningWindowStatusEnum::EnhancedWindowOpen,
                None => CommissioningWindowStatusEnum::WindowNotOpen,
            })
        })
    }

    fn admin_fabric_index(&self, ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        let notify_mdns = || ctx.exchange().matter().notify_mdns_changed();
        let notify_change =
            |endpt_id, clust_id, attr_id| ctx.notify_attr_changed(endpt_id, clust_id, attr_id);

        ctx.exchange().with_state(|state| {
            state
                .pase
                .check_comm_window_timeout(notify_mdns, notify_change)?;

            let comm_window = state.pase.comm_window();

            if let Some(opener) = comm_window.and_then(|comm_window| comm_window.opener()) {
                if state.fabrics.get(opener.fab_idx).is_some() {
                    // Fabric is still around, return its index
                    // If it is not around - and contrary to vendor ID - we should NOT return it
                    return Ok(Nullable::some(opener.fab_idx.get()));
                }
            }

            Ok(Nullable::none())
        })
    }

    fn admin_vendor_id(&self, ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        let notify_mdns = || ctx.exchange().matter().notify_mdns_changed();
        let notify_change =
            |endpt_id, clust_id, attr_id| ctx.notify_attr_changed(endpt_id, clust_id, attr_id);

        ctx.exchange().with_state(|state| {
            state
                .pase
                .check_comm_window_timeout(notify_mdns, notify_change)?;

            let comm_window = state.pase.comm_window();

            Ok(Nullable::new(
                comm_window
                    .and_then(|comm_window| comm_window.opener())
                    .map(|opener| opener.vendor_id),
            ))
        })
    }

    fn handle_open_commissioning_window(
        &self,
        ctx: impl InvokeContext,
        request: OpenCommissioningWindowRequest<'_>,
    ) -> Result<(), Error> {
        let notify_mdns = || ctx.exchange().matter().notify_mdns_changed();
        let notify_change =
            |endpt_id, clust_id, attr_id| ctx.notify_attr_changed(endpt_id, clust_id, attr_id);

        ctx.exchange().with_state(|state| {
            state
                .pase
                .check_comm_window_timeout(notify_mdns, notify_change)?;

            let opener = Self::current_window_opener(state, &ctx.exchange().id());

            let mdns_id = ctx.crypto().rand()?.next_u64();

            state.pase.open_comm_window(
                mdns_id,
                request.pake_passcode_verifier()?.0.try_into()?,
                request.salt()?.0.try_into()?,
                request.iterations()?,
                request.discriminator()?,
                request.commissioning_timeout()?,
                opener,
                notify_mdns,
                notify_change,
            )
        })
    }

    fn handle_open_basic_commissioning_window(
        &self,
        ctx: impl InvokeContext,
        request: OpenBasicCommissioningWindowRequest<'_>,
    ) -> Result<(), Error> {
        let notify_mdns = || ctx.exchange().matter().notify_mdns_changed();
        let notify_change =
            |endpt_id, clust_id, attr_id| ctx.notify_attr_changed(endpt_id, clust_id, attr_id);

        ctx.exchange().with_state(|state| {
            state
                .pase
                .check_comm_window_timeout(notify_mdns, notify_change)?;

            let opener = Self::current_window_opener(state, &ctx.exchange().id());
            let dev_comm = ctx.exchange().matter().dev_comm();

            let crypto = ctx.crypto();
            let mut rand = crypto.rand()?;

            let mdns_id = rand.next_u64();

            let mut salt = SPAKE2P_VERIFIER_SALT_ZEROED;
            rand.fill_bytes(salt.access_mut());

            state.pase.open_basic_comm_window(
                mdns_id,
                salt.reference(),
                dev_comm.password.reference(),
                dev_comm.discriminator,
                request.commissioning_timeout()?,
                opener,
                notify_mdns,
                notify_change,
            )
        })
    }

    fn handle_revoke_commissioning(&self, ctx: impl InvokeContext) -> Result<(), Error> {
        let notify_mdns = || ctx.exchange().matter().notify_mdns_changed();
        let notify_change =
            |endpt_id, clust_id, attr_id| ctx.notify_attr_changed(endpt_id, clust_id, attr_id);

        ctx.exchange()
            .with_state(|state| state.pase.close_comm_window(notify_mdns, notify_change))?;

        // TODO: Send status code if no commissioning window is open?

        Ok(())
    }
}
