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

//! Implementation of the Time Synchronization cluster.
//!
//! The cluster is advertised on the root endpoint with **no feature
//! bits claimed** — no time-zone support, no NTP client/server, no
//! trusted-time-source support. What the cluster *does* expose:
//!
//! - The two mandatory attributes (`UTCTime`, `Granularity`).
//! - `TimeSource` (spec-optional when no features are claimed; we
//!   opt in so the Matter test harness's `has_attribute(TimeSource)`
//!   gate on `TC_TIMESYNC_2_1` matches and the test runs rather
//!   than skipping).
//!
//! All five commands (`SetUTCTime`, `SetTrustedTimeSource`,
//! `SetTimeZone`, `SetDSTOffset`, `SetDefaultNTP`) are stubbed to
//! return `CommandNotFound` — they're feature-gated and no conformant
//! peer should dispatch them with no features claimed.
//!
//! # Pluggable data source — [`TimeSync`]
//!
//! [`TimeSyncHandler`] is **not** a fixed-value stub: it borrows a
//! `&dyn TimeSync` data provider and forwards each attribute read to
//! it. A real implementation backed by the device's wall clock
//! exposes real time on the wire; the no-op default — `impl TimeSync
//! for ()`, used via `&()` — returns the "we don't know the time"
//! triple (`UTCTime = Null`, `Granularity = NoTimeGranularity`,
//! `TimeSource = None`) and is spec-compliant per Matter Core spec
//! §11.16.8 ("when `UTCTime` is `Null`, `Granularity` MUST be
//! `NoTimeGranularity`").
//!
//! # Scope and follow-ups
//!
//! Wiring this handler unlocks `TC_TIMESYNC_2_1`. The other TimeSync
//! tests (TC_TIMESYNC_2_2 onwards) use bare `@async_test_body` and
//! exercise the feature-gated paths; making them pass requires
//! actually claiming the relevant features (`TimeZone`, `NTPClient`,
//! `NTPServer`, `TimeSyncClient`) and implementing the corresponding
//! read/write/invoke logic — a future expansion of [`TimeSync`].

use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::Nullable;
use crate::with;

pub use crate::dm::clusters::decl::time_synchronization::*;

/// Pluggable data source for the TimeSync cluster handler.
///
/// All methods have sensible "we don't know" defaults so an
/// implementor can opt in to just the bits the device can actually
/// provide. `impl TimeSync for ()` lets `&()` stand in as the no-op
/// provider when a caller has nothing real to plug in yet.
///
/// # Spec invariant (Matter Core spec §11.16.8)
///
/// When [`utc_time`](Self::utc_time) returns `Nullable::none()`,
/// [`granularity`](Self::granularity) **MUST** return
/// `GranularityEnum::NoTimeGranularity`. The default implementations
/// satisfy this; custom implementors that override one but not the
/// other should preserve the pairing.
pub trait TimeSync {
    /// Current wall-clock time as microseconds since the Matter epoch
    /// (2000-01-01T00:00:00Z UTC), or `Null` if no time is currently
    /// available.
    fn utc_time(&self) -> Result<Nullable<u64>, Error>;

    /// Granularity of the value reported by
    /// [`utc_time`](Self::utc_time). Must be `NoTimeGranularity`
    /// whenever `utc_time` returns `Null`.
    fn granularity(&self) -> Result<GranularityEnum, Error>;

    /// Where the device got its current time from. `None` means
    /// "no source configured".
    fn time_source(&self) -> Result<TimeSourceEnum, Error>;
}

impl<T> TimeSync for &T
where
    T: TimeSync,
{
    fn utc_time(&self) -> Result<Nullable<u64>, Error> {
        (*self).utc_time()
    }
    fn granularity(&self) -> Result<GranularityEnum, Error> {
        (*self).granularity()
    }
    fn time_source(&self) -> Result<TimeSourceEnum, Error> {
        (*self).time_source()
    }
}

/// No-op `TimeSync` provider used as `&()` to mean "we don't know
/// the time" — matches the convention used by [`WifiDiag`], etc.
impl TimeSync for () {
    fn utc_time(&self) -> Result<Nullable<u64>, Error> {
        Ok(Nullable::none())
    }

    fn granularity(&self) -> Result<GranularityEnum, Error> {
        Ok(GranularityEnum::NoTimeGranularity)
    }

    fn time_source(&self) -> Result<TimeSourceEnum, Error> {
        Ok(TimeSourceEnum::None)
    }
}

/// Handler for the Time Synchronization Matter cluster.
///
/// Borrows a `&dyn TimeSync` data provider for the lifetime `'a`
/// and forwards each attribute read into it. The cluster's wire
/// metadata is fixed at the type-level (`CLUSTER` const): required
/// globals + the two mandatory attrs + `TimeSource`, no features,
/// no commands.
#[derive(Clone)]
pub struct TimeSyncHandler<'a> {
    dataver: Dataver,
    time_sync: &'a dyn TimeSync,
}

impl<'a> TimeSyncHandler<'a> {
    /// Create a new handler bound to `time_sync` for its lifetime.
    /// Pass `&()` (the no-op [`TimeSync`] impl) when no real time
    /// source is available.
    pub const fn new(dataver: Dataver, time_sync: &'a dyn TimeSync) -> Self {
        Self { dataver, time_sync }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for TimeSyncHandler<'_> {
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
        self.time_sync.utc_time()
    }

    fn granularity(&self, _ctx: impl ReadContext) -> Result<GranularityEnum, Error> {
        self.time_sync.granularity()
    }

    fn time_source(&self, _ctx: impl ReadContext) -> Result<TimeSourceEnum, Error> {
        self.time_sync.time_source()
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

impl core::fmt::Debug for TimeSyncHandler<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TimeSyncHandler")
            .field("dataver", &self.dataver)
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for TimeSyncHandler<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "TimeSyncHandler {{ dataver: {} }}", self.dataver.get());
    }
}
