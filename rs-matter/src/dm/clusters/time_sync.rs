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

//! Stub implementation of the Time Synchronization cluster.
//!
//! This handler advertises the cluster on the root endpoint with **no
//! features claimed** — i.e. no time-zone support, no NTP client/
//! server, no trusted-time-source support. The mandatory `UTCTime`
//! and `Granularity` attributes are served with spec-compliant
//! "we don't know the time" defaults:
//!
//! - `UTCTime` → `Null` (no current time available)
//! - `Granularity` → `NoTimeGranularity` (paired-state, required
//!   when `UTCTime` is Null per Matter Core spec §11.16.8)
//!
//! `TimeSource` is also opted in (advertised in `AttributeList` so the
//! Matter test harness's `has_attribute(TimeSource)` gate passes; the
//! attribute itself is spec-optional when no time-sync features are
//! claimed), returning `None` — "no time source configured".
//!
//! All five commands (`SetUTCTime`, `SetTrustedTimeSource`,
//! `SetTimeZone`, `SetDSTOffset`, `SetDefaultNTP`) are stubbed to
//! return `CommandNotFound`. The cluster metadata still advertises
//! them via codegen `FULL_CLUSTER`, but with no feature bits set
//! they should never be dispatched on a conformance peer; returning
//! `CommandNotFound` cleanly refuses any peer probe.
//!
//! Wiring this minimal handler unlocks `TC_TIMESYNC_2_1` — the only
//! TimeSync conformance test gated by `run_if_endpoint_matches`
//! (`has_cluster(TimeSynchronization) and has_attribute(TimeSource)`).
//! The other TimeSync tests (TC_TIMESYNC_2_2 onwards) use bare
//! `@async_test_body` and exercise the feature-gated paths; making
//! them pass requires actually claiming the relevant features and
//! implementing the corresponding read/write/invoke logic — a
//! follow-up.

use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::Nullable;
use crate::with;

pub use crate::dm::clusters::decl::time_synchronization::*;

/// The system implementation of a handler for the Time Synchronization
/// Matter cluster.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TimeSyncHandler {
    dataver: Dataver,
}

impl TimeSyncHandler {
    /// Create a new instance of `TimeSyncHandler` with the given `Dataver`.
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for TimeSyncHandler {
    // Cluster metadata: required globals + the two mandatory attrs
    // (`UTCTime`, `Granularity`) + `TimeSource` (opted in so the
    // Python `has_attribute(TimeSource)` gate on TC_TIMESYNC_2_1
    // passes). No feature bits, no commands.
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_attrs(with!(required; AttributeId::TimeSource))
        .with_cmds(with!());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn utc_time(&self, _ctx: impl ReadContext) -> Result<Nullable<u64>, Error> {
        // We don't track wall-clock time. Pair with Granularity =
        // NoTimeGranularity below — see Matter Core spec §11.16.8:
        // when `UTCTime` is `Null`, `Granularity` MUST be
        // `NoTimeGranularity`.
        Ok(Nullable::none())
    }

    fn granularity(&self, _ctx: impl ReadContext) -> Result<GranularityEnum, Error> {
        Ok(GranularityEnum::NoTimeGranularity)
    }

    fn time_source(&self, _ctx: impl ReadContext) -> Result<TimeSourceEnum, Error> {
        // "No time source configured" — sane companion to a Null
        // `UTCTime` / `NoTimeGranularity` pair.
        Ok(TimeSourceEnum::None)
    }

    // ---- Commands: feature-gated; we claim no features so the peer
    // shouldn't dispatch any of these. Returning `CommandNotFound`
    // refuses cleanly regardless.

    fn handle_set_utc_time(
        &self,
        _ctx: impl InvokeContext,
        _request: SetUTCTimeRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    fn handle_set_trusted_time_source(
        &self,
        _ctx: impl InvokeContext,
        _request: SetTrustedTimeSourceRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    fn handle_set_time_zone<P: crate::tlv::TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: SetTimeZoneRequest<'_>,
        _response: SetTimeZoneResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    fn handle_set_dst_offset(
        &self,
        _ctx: impl InvokeContext,
        _request: SetDSTOffsetRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    fn handle_set_default_ntp(
        &self,
        _ctx: impl InvokeContext,
        _request: SetDefaultNTPRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }
}
