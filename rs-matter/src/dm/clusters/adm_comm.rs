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
use crate::error::{Error, ErrorCode};
use crate::sc::pase::spake2p::SPAKE2P_VERIFIER_SALT_ZEROED;
use crate::sc::pase::{CommWindowOpener, CommWindowType};
use crate::tlv::Nullable;
use crate::MatterState;

pub use crate::dm::clusters::decl::administrator_commissioning::*;
use crate::transport::exchange::ExchangeId;
use crate::transport::session::SessionMode;

/// PAKE iteration count bounds (Matter Core spec section 11.18.6.1.4).
const MIN_PBKDF_ITERATIONS: u32 = 1000;
const MAX_PBKDF_ITERATIONS: u32 = 100_000;

/// PAKE salt length bounds (Matter Core spec section 11.18.6.1.4 / 5.1.6.1).
const MIN_PAKE_SALT_LEN: usize = 16;
const MAX_PAKE_SALT_LEN: usize = 32;

/// SPAKE2+ verifier length: W0 (32) || L (65) = 97 octets
/// (Matter Core spec section 3.10).
const PAKE_VERIFIER_LEN: usize = 97;

/// Stash an `AdministratorCommissioning` cluster-specific status on the
/// invoke context so the IM layer surfaces it in `StatusIB.clusterStatus`,
/// then build the matching `Failure(0x01)` error to return from the handler.
fn cluster_status_err(ctx: &impl InvokeContext, status: StatusCode) -> Error {
    ctx.cmd().set_cluster_status(status as u8);
    Error::new(ErrorCode::Failure)
}

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
        let notify_change = |_, _| ctx.notify_own_cluster_changed();

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
        let notify_change = |_, _| ctx.notify_own_cluster_changed();

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
        let notify_change = |_, _| ctx.notify_own_cluster_changed();

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
        let notify_change = |_, _| ctx.notify_own_cluster_changed();

        // Validate the PAKE parameters up front so we can surface
        // `PAKEParameterError` as the cluster-specific status (Matter Core
        // spec section 11.18.6.1.4).
        let iterations = request.iterations()?;
        if !(MIN_PBKDF_ITERATIONS..=MAX_PBKDF_ITERATIONS).contains(&iterations) {
            return Err(cluster_status_err(&ctx, StatusCode::PAKEParameterError));
        }

        let salt = request.salt()?;
        if !(MIN_PAKE_SALT_LEN..=MAX_PAKE_SALT_LEN).contains(&salt.0.len()) {
            return Err(cluster_status_err(&ctx, StatusCode::PAKEParameterError));
        }

        let verifier = request.pake_passcode_verifier()?;
        if verifier.0.len() != PAKE_VERIFIER_LEN {
            return Err(cluster_status_err(&ctx, StatusCode::PAKEParameterError));
        }

        ctx.exchange().with_state(|state| {
            state
                .pase
                .check_comm_window_timeout(notify_mdns, notify_change)?;

            let opener = Self::current_window_opener(state, &ctx.exchange().id());

            let mdns_id = ctx.crypto().rand()?.next_u64();

            state
                .pase
                .open_comm_window(
                    mdns_id,
                    verifier.0.try_into()?,
                    salt.0.try_into()?,
                    iterations,
                    request.discriminator()?,
                    request.commissioning_timeout()?,
                    opener,
                    notify_mdns,
                    notify_change,
                )
                .map_err(|err| map_open_window_err(&ctx, err))
        })
    }

    fn handle_open_basic_commissioning_window(
        &self,
        ctx: impl InvokeContext,
        request: OpenBasicCommissioningWindowRequest<'_>,
    ) -> Result<(), Error> {
        let notify_mdns = || ctx.exchange().matter().notify_mdns_changed();
        let notify_change = |_, _| ctx.notify_own_cluster_changed();

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

            state
                .pase
                .open_basic_comm_window(
                    mdns_id,
                    salt.reference(),
                    dev_comm.password.reference(),
                    dev_comm.discriminator,
                    request.commissioning_timeout()?,
                    opener,
                    notify_mdns,
                    notify_change,
                )
                .map_err(|err| map_open_window_err(&ctx, err))
        })
    }

    fn handle_revoke_commissioning(&self, ctx: impl InvokeContext) -> Result<(), Error> {
        let notify_mdns = || ctx.exchange().matter().notify_mdns_changed();
        let notify_change = |_, _| ctx.notify_own_cluster_changed();

        // Per Matter Core spec section 11.18.6.2 (and CHIP's
        // `AdministratorCommissioningLogic::RevokeCommissioning`), revoking
        // the commissioning window also:
        //
        //  1. Forces any in-flight fail-safe context to expire. Otherwise
        //     stale state — e.g. the breadcrumb value an interrupted
        //     commissioning attempt left behind — leaks into the next
        //     `OpenCommissioningWindow` round and causes the commissioner to
        //     skip past `ArmFailSafe` (it reads `breadcrumb > 0` and assumes
        //     an in-progress commission, per the CHIP
        //     `AutoCommissioner::GetNextCommissioningStageInternal` post-NOC
        //     recovery path).
        //
        //  2. Tears down any PASE sessions that were established under that
        //     commissioning window but never promoted to a fabric. CHIP ties
        //     this to fail-safe expiry inside `CommissioningWindowManager`;
        //     we do it explicitly here so accumulated dangling PASE sessions
        //     don't confuse the commissioner across multiple rounds (see
        //     TC_CGEN_2_4, which iterates open / commission / revoke 8x).
        ctx.exchange().with_state(|state| {
            state
                .failsafe
                .expire(&mut state.fabrics, ctx.networks(), ctx.kv(), notify_mdns)?;

            // If RevokeCommissioning came in over a PASE session, don't
            // drop it before we've sent the response — mark it as expired
            // instead so it lingers just long enough for the in-flight
            // exchange to complete, then can't accept new ones.
            let sess = ctx.exchange().id().session(&mut state.sessions);
            let expire_sess_id = matches!(
                sess.get_session_mode(),
                crate::transport::session::SessionMode::Pase { .. }
            )
            .then(|| sess.id());
            state.sessions.remove_pase(expire_sess_id);
            ctx.exchange().matter().session_removed.notify();
            Ok::<_, Error>(())
        })?;

        ctx.exchange().with_state(|state| {
            state
                .pase
                .close_comm_window(notify_mdns, notify_change)
                .map_err(|err| map_revoke_err(&ctx, err))
        })?;

        Ok(())
    }
}

/// Map errors returned by `Pase::open_*_comm_window` to
/// `AdministratorCommissioning` cluster-specific status codes (Matter Core
/// spec section 11.18.6). `Busy` is the only cluster status the open paths
/// surface today; other transport-level errors (e.g. invalid timeout) bubble
/// up unchanged so the IM layer turns them into the generic `InvalidCommand`.
fn map_open_window_err(ctx: &impl InvokeContext, err: Error) -> Error {
    if err.code() == ErrorCode::Busy {
        cluster_status_err(ctx, StatusCode::Busy)
    } else {
        err
    }
}

/// Same idea for `RevokeCommissioning`: per spec, attempting to revoke when
/// no window is open SHALL return `WindowNotOpen`. `Pase::close_comm_window`
/// reports this as `ErrorCode::Invalid`.
fn map_revoke_err(ctx: &impl InvokeContext, err: Error) -> Error {
    if matches!(err.code(), ErrorCode::Invalid) {
        cluster_status_err(ctx, StatusCode::WindowNotOpen)
    } else {
        err
    }
}
