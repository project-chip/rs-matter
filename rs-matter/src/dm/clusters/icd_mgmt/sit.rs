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

//! The ICD Management cluster of a Short Idle Time (SIT) only device.

use crate::dm::{Cluster, Dataver, HandlerContext, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::TLVBuilderParent;
use crate::with;

use super::*;

/// The ICD Management cluster handler of a Short Idle Time (SIT) only device.
///
/// Such a device is reachable within its `SESSION_IDLE_INTERVAL` at all times
/// (at most 15 s), so it has nothing for clients to register for: the cluster
/// claims none of the Check-In Protocol, Long Idle Time and Dynamic SIT/LIT
/// features, and serves the mandatory mode timings alone - plus, with
/// [`CLUSTER_UAT`](Self::CLUSTER_UAT), the user active mode trigger. The
/// device advertises no `ICD` DNS-SD TXT key.
///
/// Backed by an [`Icd`], whose power mode state machine it drives from its
/// `run` hook.
pub struct SitIcdMgmtHandler<'a> {
    dataver: Dataver,
    icd: &'a Icd,
}

impl<'a> SitIcdMgmtHandler<'a> {
    /// The cluster metadata of a SIT device with a user active mode trigger:
    /// the `UserActiveModeTrigger` feature and its hint / instruction
    /// attributes, served from [`IcdModeConfig`].
    pub const CLUSTER_UAT: Cluster<'static> = FULL_CLUSTER
        .with_features(Feature::USER_ACTIVE_MODE_TRIGGER.bits())
        .with_attrs(with!(required;
            AttributeId::UserActiveModeTriggerHint
                | AttributeId::UserActiveModeTriggerInstruction))
        .with_cmds(with!());

    /// Create a handler backed by the shared [`Icd`] state.
    pub const fn new(dataver: Dataver, icd: &'a Icd) -> Self {
        Self { dataver, icd }
    }

    /// Adapt this handler to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for SitIcdMgmtHandler<'_> {
    /// No features: the mandatory mode timings, and no commands.
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required)).with_cmds(with!());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        self.icd.run(ctx, &()).await
    }

    fn idle_mode_duration(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.icd.mode.idle_mode_duration_s)
    }

    fn active_mode_duration(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.icd.mode.active_mode_duration_ms)
    }

    fn active_mode_threshold(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(self.icd.mode.active_mode_threshold_ms)
    }

    fn user_active_mode_trigger_hint(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<UserActiveModeTriggerBitmap, Error> {
        Ok(UserActiveModeTriggerBitmap::from_bits_truncate(
            self.icd.mode.user_active_mode_trigger_hint,
        ))
    }

    fn user_active_mode_trigger_instruction<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: crate::tlv::Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(self.icd.mode.user_active_mode_trigger_instruction)
    }

    // A SIT-only device has nothing to register for and no StayActiveRequest
    // to honor; its metadata declares none of these commands, so they are
    // never dispatched here.

    fn handle_register_client<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: RegisterClientRequest<'_>,
        _response: RegisterClientResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    fn handle_unregister_client(
        &self,
        _ctx: impl InvokeContext,
        _request: UnregisterClientRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    fn handle_stay_active_request<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: StayActiveRequestRequest<'_>,
        _response: StayActiveResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::CommandNotFound.into())
    }
}
