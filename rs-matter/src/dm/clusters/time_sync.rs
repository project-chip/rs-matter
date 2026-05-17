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
//! # Cluster-shape selection — endpoint-side, via [`Options`]
//!
//! Each Matter feature (`TIME_ZONE`, `NTP_CLIENT`, `NTP_SERVER`,
//! `TIME_SYNC_CLIENT`) is mirrored 1:1 by a bit in the [`Options`]
//! bitflags type, consumed by the [`cluster`] const-generic fn which
//! returns the matching `Cluster<'static>` metadata.
//!
//! The shape is picked **endpoint-side**, on the `clusters!` /
//! `root_endpoint!` macros — e.g. `clusters!(eth, time_sync(time_zone,
//! ntp_client); …)` — not on the handler. [`TimeSyncHandler`] itself
//! is non-generic and its [`Self::CLUSTER`](ClusterHandler::CLUSTER)
//! is pinned to the empty-options shape; only `CLUSTER.id` is
//! actually consulted by the dispatcher, and the per-attribute /
//! per-command dispatch is driven by what the endpoint advertises.
//!
//! Spec invariant carried over independently of features: `TimeSource`
//! is opted in even in the empty-options shape so the Matter test
//! harness's `has_attribute(TimeSource)` gate on `TC_TIMESYNC_2_1`
//! matches and the test runs rather than skipping.
//!
//! # Pluggable data source — [`TimeSync`]
//!
//! [`TimeSyncHandler`] borrows a `&dyn TimeSync` data provider and
//! forwards every attribute read / command invoke to it. The trait
//! carries methods for every feature-gated attribute and command; the
//! three always-exposed reads (`utc_time`, `granularity`, `time_source`)
//! have no defaults — implementors must answer them explicitly — while
//! feature-gated members have sensible "we don't expose this" defaults
//! (empty lists, `Null`, `CommandNotFound`) so an implementor only
//! overrides the methods matching the options they picked.
//!
//! [`impl TimeSync for ()`] is the canonical no-op provider —
//! `UTCTime = Null`, `Granularity = NoTimeGranularity`,
//! `TimeSource = None`, spec-compliant per Matter Core spec §11.16.8.

use bitflags::bitflags;

use crate::dm::{
    ArrayAttributeRead, Attribute, Cluster, Command, Dataver, InvokeContext, Quality, ReadContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{Nullable, NullableBuilder, TLVBuilderParent, Utf8StrBuilder};

pub use crate::dm::clusters::decl::time_synchronization::*;

bitflags! {
    /// Cluster-shape selectors for the [`TimeSyncHandler`]. Each bit
    /// turns on exactly one Matter `Feature` — there are no
    /// independent-optional toggles on this cluster, so the mapping
    /// is 1:1.
    ///
    /// Used as the const-generic argument to [`cluster`] (via its
    /// `bits()` value) to compute the matching `Cluster<'static>`
    /// metadata, which is then installed onto the endpoint via the
    /// `clusters!` / `root_endpoint!` macros (e.g.
    /// `clusters!(eth, time_sync(time_zone, ntp_client); …)`).
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct Options: u8 {
        /// Claim the Matter `TIME_ZONE` feature. Advertises `TimeZone`,
        /// `DSTOffset`, `LocalTime`, `TimeZoneDatabase`,
        /// `TimeZoneListMaxSize`, `DSTOffsetListMaxSize` attributes
        /// and the `SetTimeZone` + `SetDSTOffset` commands.
        const TIME_ZONE = 0x1;
        /// Claim the Matter `NTP_CLIENT` feature. Advertises
        /// `DefaultNTP` + `SupportsDNSResolve` attributes and the
        /// `SetDefaultNTP` command.
        const NTP_CLIENT = 0x2;
        /// Claim the Matter `NTP_SERVER` feature. Advertises the
        /// `NTPServerAvailable` attribute.
        const NTP_SERVER = 0x4;
        /// Claim the Matter `TIME_SYNC_CLIENT` feature. Advertises the
        /// `TrustedTimeSource` attribute and the `SetTrustedTimeSource`
        /// command.
        const TIME_SYNC_CLIENT = 0x8;
    }
}

/// One time-zone entry yielded by [`TimeSync::time_zone`] via the
/// visitor callback. The lifetime `'a` is the borrow of the
/// implementor's internal storage for the duration of the visit, so
/// `name` can point straight into the implementor's table without
/// copying.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TimeZoneEntry<'a> {
    /// Offset from UTC, in seconds.
    pub offset: i32,
    /// Matter-epoch microseconds after which this offset takes effect.
    pub valid_at: u64,
    /// Human-readable IANA time-zone name (`Europe/Sofia` …); `None`
    /// if the implementation doesn't track names.
    pub name: Option<&'a str>,
}

/// One DST-offset entry yielded by [`TimeSync::dst_offset`] via the
/// visitor callback.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct DSTOffsetEntry {
    /// Offset from local standard time, in seconds, while DST is in
    /// effect.
    pub offset: i32,
    /// Matter-epoch microseconds at which the offset becomes valid.
    pub valid_starting: u64,
    /// Matter-epoch microseconds at which the offset stops being
    /// valid. `None` means "indefinitely" (`Null` on the wire).
    pub valid_until: Option<u64>,
}

/// Snapshot of the device's currently-configured trusted time source.
/// Returned by [`TimeSync::trusted_time_source`] wrapped in a
/// [`Nullable`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct TrustedTimeSourceData {
    /// Fabric index that configured this trusted time source.
    pub fabric_index: u8,
    /// Node ID of the trusted source.
    pub node_id: u64,
    /// Endpoint on the trusted source's node.
    pub endpoint: u16,
}

/// Pluggable data source for the Time Synchronization cluster
/// handler. The three always-exposed reads (`utc_time`, `granularity`,
/// `time_source`) have no defaults — every implementor must answer
/// them explicitly. Feature-gated members have "no value" defaults so
/// an implementor only overrides what matches the options they picked.
///
/// # Spec invariant (Matter Core spec §11.16.8)
///
/// When [`utc_time`](Self::utc_time) returns `Nullable::none()`,
/// [`granularity`](Self::granularity) **MUST** return
/// `GranularityEnum::NoTimeGranularity`. Custom implementors that
/// override one but not the other should preserve the pairing.
pub trait TimeSync {
    // ---- Always-exposed reads (mandatory + TimeSource opt-in)

    /// Current wall-clock time as microseconds since the Matter epoch
    /// (2000-01-01T00:00:00Z UTC), or `Null` if no time is currently
    /// available.
    fn utc_time(&self) -> Result<Nullable<u64>, Error>;

    /// Granularity of the value reported by
    /// [`utc_time`](Self::utc_time). Must be `NoTimeGranularity`
    /// whenever `utc_time` returns `Null`.
    fn granularity(&self) -> Result<GranularityEnum, Error>;

    /// Where the device got its current time from. `None` means "no
    /// source configured".
    fn time_source(&self) -> Result<TimeSourceEnum, Error>;

    // ---- TIME_SYNC_CLIENT feature

    /// Currently-configured trusted time source, or `Null` if none.
    fn trusted_time_source(&self) -> Result<Nullable<TrustedTimeSourceData>, Error> {
        Ok(Nullable::none())
    }

    // ---- NTP_CLIENT feature

    /// Hostname or IP address of the default NTP server, or `Null` if
    /// none is configured.
    fn default_ntp(&self) -> Result<Nullable<&str>, Error> {
        Ok(Nullable::none())
    }

    /// Whether the device's NTP-client resolver supports DNS names
    /// (vs. only literal IP addresses).
    fn supports_dns_resolve(&self) -> Result<bool, Error> {
        Ok(false)
    }

    // ---- NTP_SERVER feature

    /// Whether the device is currently serving NTP queries.
    fn ntp_server_available(&self) -> Result<bool, Error> {
        Ok(false)
    }

    // ---- TIME_ZONE feature

    /// Stream the active time-zone entries into `visit`. Default:
    /// emit nothing (empty list on the wire).
    fn time_zone(
        &self,
        _visit: &mut dyn FnMut(&TimeZoneEntry<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Stream the active DST-offset entries into `visit`. Default:
    /// emit nothing.
    fn dst_offset(
        &self,
        _visit: &mut dyn FnMut(&DSTOffsetEntry) -> Result<(), Error>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Current local time in Matter-epoch microseconds, or `Null`.
    fn local_time(&self) -> Result<Nullable<u64>, Error> {
        Ok(Nullable::none())
    }

    /// How complete the device's IANA time-zone database is.
    fn time_zone_database(&self) -> Result<TimeZoneDatabaseEnum, Error> {
        Ok(TimeZoneDatabaseEnum::None)
    }

    /// Maximum length of the `TimeZone` list this device accepts.
    fn time_zone_list_max_size(&self) -> Result<u8, Error> {
        Ok(0)
    }

    /// Maximum length of the `DSTOffset` list this device accepts.
    fn dst_offset_list_max_size(&self) -> Result<u8, Error> {
        Ok(0)
    }

    // ---- Commands (feature-gated; default to `CommandNotFound`)

    /// Handle `SetUTCTime`. Mandatory when any feature is claimed.
    fn set_utc_time(&self, _request: &SetUTCTimeRequest<'_>) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    /// Handle `SetTrustedTimeSource` — gated by `TIME_SYNC_CLIENT`.
    fn set_trusted_time_source(
        &self,
        _request: &SetTrustedTimeSourceRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    /// Handle `SetTimeZone` — gated by `TIME_ZONE`. Returns the
    /// `DSTOffsetRequired` field for the response.
    fn set_time_zone(&self, _request: &SetTimeZoneRequest<'_>) -> Result<bool, Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    /// Handle `SetDSTOffset` — gated by `TIME_ZONE`.
    fn set_dst_offset(&self, _request: &SetDSTOffsetRequest<'_>) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    /// Handle `SetDefaultNTP` — gated by `NTP_CLIENT`.
    fn set_default_ntp(&self, _request: &SetDefaultNTPRequest<'_>) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }
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
    fn trusted_time_source(&self) -> Result<Nullable<TrustedTimeSourceData>, Error> {
        (*self).trusted_time_source()
    }
    fn default_ntp(&self) -> Result<Nullable<&str>, Error> {
        (*self).default_ntp()
    }
    fn supports_dns_resolve(&self) -> Result<bool, Error> {
        (*self).supports_dns_resolve()
    }
    fn ntp_server_available(&self) -> Result<bool, Error> {
        (*self).ntp_server_available()
    }
    fn time_zone(
        &self,
        visit: &mut dyn FnMut(&TimeZoneEntry<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        (*self).time_zone(visit)
    }
    fn dst_offset(
        &self,
        visit: &mut dyn FnMut(&DSTOffsetEntry) -> Result<(), Error>,
    ) -> Result<(), Error> {
        (*self).dst_offset(visit)
    }
    fn local_time(&self) -> Result<Nullable<u64>, Error> {
        (*self).local_time()
    }
    fn time_zone_database(&self) -> Result<TimeZoneDatabaseEnum, Error> {
        (*self).time_zone_database()
    }
    fn time_zone_list_max_size(&self) -> Result<u8, Error> {
        (*self).time_zone_list_max_size()
    }
    fn dst_offset_list_max_size(&self) -> Result<u8, Error> {
        (*self).dst_offset_list_max_size()
    }
    fn set_utc_time(&self, request: &SetUTCTimeRequest<'_>) -> Result<(), Error> {
        (*self).set_utc_time(request)
    }
    fn set_trusted_time_source(
        &self,
        request: &SetTrustedTimeSourceRequest<'_>,
    ) -> Result<(), Error> {
        (*self).set_trusted_time_source(request)
    }
    fn set_time_zone(&self, request: &SetTimeZoneRequest<'_>) -> Result<bool, Error> {
        (*self).set_time_zone(request)
    }
    fn set_dst_offset(&self, request: &SetDSTOffsetRequest<'_>) -> Result<(), Error> {
        (*self).set_dst_offset(request)
    }
    fn set_default_ntp(&self, request: &SetDefaultNTPRequest<'_>) -> Result<(), Error> {
        (*self).set_default_ntp(request)
    }
}

/// No-op `TimeSync` provider used as `&()` to mean "we don't know the
/// time and we expose no time-related features" — spec-compliant
/// minimum.
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

// ---- Cluster-shape selection -------------------------------------------------

fn time_sync_attrs<const OPTS: u8>(attr: &Attribute, _: u16, _: u32) -> bool {
    use AttributeId as A;
    // Mandatory always (UTCTime, Granularity)
    if !attr.quality.contains(Quality::OPTIONAL) {
        return true;
    }
    // TimeSource: always exposed independently of features so the
    // Matter test harness's TC_TIMESYNC_2_1 gate matches.
    if attr.id == A::TimeSource as u32 {
        return true;
    }
    let opts = Options::from_bits_truncate(OPTS);
    if opts.contains(Options::TIME_ZONE)
        && (attr.id == A::TimeZone as u32
            || attr.id == A::DSTOffset as u32
            || attr.id == A::LocalTime as u32
            || attr.id == A::TimeZoneDatabase as u32
            || attr.id == A::TimeZoneListMaxSize as u32
            || attr.id == A::DSTOffsetListMaxSize as u32)
    {
        return true;
    }
    if opts.contains(Options::NTP_CLIENT)
        && (attr.id == A::DefaultNTP as u32 || attr.id == A::SupportsDNSResolve as u32)
    {
        return true;
    }
    if opts.contains(Options::NTP_SERVER) && attr.id == A::NTPServerAvailable as u32 {
        return true;
    }
    if opts.contains(Options::TIME_SYNC_CLIENT) && attr.id == A::TrustedTimeSource as u32 {
        return true;
    }
    false
}

fn time_sync_cmds<const OPTS: u8>(cmd: &Command, _: u16, _: u32) -> bool {
    use CommandId as C;
    let opts = Options::from_bits_truncate(OPTS);
    if opts.is_empty() {
        return false;
    }
    // `SetUTCTime` is mandatory whenever any feature is claimed.
    if cmd.id == C::SetUTCTime as u32 {
        return true;
    }
    if opts.contains(Options::TIME_ZONE)
        && (cmd.id == C::SetTimeZone as u32 || cmd.id == C::SetDSTOffset as u32)
    {
        return true;
    }
    if opts.contains(Options::NTP_CLIENT) && cmd.id == C::SetDefaultNTP as u32 {
        return true;
    }
    if opts.contains(Options::TIME_SYNC_CLIENT) && cmd.id == C::SetTrustedTimeSource as u32 {
        return true;
    }
    false
}

/// Compute the `Cluster<'static>` metadata for a TimeSync handler
/// advertising the features encoded in `OPTS` (the [`Options::bits`]
/// value). See the [`Options`] flags for the per-bit detail.
///
/// Pair the returned shape with a [`TimeSync`] implementation whose
/// methods supply real values for the corresponding option bits.
pub const fn cluster<const OPTS: u8>() -> Cluster<'static> {
    let opts = Options::from_bits_truncate(OPTS);
    let mut features = 0u32;
    if opts.contains(Options::TIME_ZONE) {
        features |= Feature::TIME_ZONE.bits();
    }
    if opts.contains(Options::NTP_CLIENT) {
        features |= Feature::NTP_CLIENT.bits();
    }
    if opts.contains(Options::NTP_SERVER) {
        features |= Feature::NTP_SERVER.bits();
    }
    if opts.contains(Options::TIME_SYNC_CLIENT) {
        features |= Feature::TIME_SYNC_CLIENT.bits();
    }
    Cluster {
        feature_map: features,
        with_attrs: time_sync_attrs::<OPTS>,
        with_cmds: time_sync_cmds::<OPTS>,
        ..FULL_CLUSTER
    }
}

// ---- Handler -----------------------------------------------------------------

/// Handler for the Time Synchronization Matter cluster.
///
/// Borrows a `&dyn TimeSync` data provider for the lifetime `'a` and
/// forwards every attribute read / command invoke to it.
///
/// The handler is **not** parameterized by cluster shape:
/// [`Self::CLUSTER`](ClusterHandler::CLUSTER) is pinned to the
/// empty-options form and only its `id` is consulted by the
/// dispatcher. The on-wire shape — which optional attributes /
/// commands / features are advertised — is decided by the cluster
/// metadata supplied on the endpoint side (e.g. `clusters!(eth,
/// time_sync(time_zone, ntp_client); …)`); per-attribute dispatch
/// follows the endpoint's metadata, so the handler answers exactly
/// what the endpoint exposes.
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
    const CLUSTER: Cluster<'static> = cluster::<0>();

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    // ---- Always-on reads

    fn utc_time(&self, _ctx: impl ReadContext) -> Result<Nullable<u64>, Error> {
        self.time_sync.utc_time()
    }

    fn granularity(&self, _ctx: impl ReadContext) -> Result<GranularityEnum, Error> {
        self.time_sync.granularity()
    }

    fn time_source(&self, _ctx: impl ReadContext) -> Result<TimeSourceEnum, Error> {
        self.time_sync.time_source()
    }

    // ---- Feature-gated reads

    fn trusted_time_source<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: NullableBuilder<P, TrustedTimeSourceStructBuilder<P>>,
    ) -> Result<P, Error> {
        match self.time_sync.trusted_time_source()?.into_option() {
            Some(data) => builder
                .non_null()?
                .fabric_index(data.fabric_index)?
                .node_id(data.node_id)?
                .endpoint(data.endpoint)?
                .end(),
            None => builder.null(),
        }
    }

    fn default_ntp<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: NullableBuilder<P, Utf8StrBuilder<P>>,
    ) -> Result<P, Error> {
        match self.time_sync.default_ntp()?.into_option() {
            Some(s) => builder.non_null()?.set(s),
            None => builder.null(),
        }
    }

    fn supports_dns_resolve(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        self.time_sync.supports_dns_resolve()
    }

    fn ntp_server_available(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        self.time_sync.ntp_server_available()
    }

    fn time_zone<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<TimeZoneStructArrayBuilder<P>, TimeZoneStructBuilder<P>>,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(array) => {
                let mut array_opt = Some(array);
                self.time_sync.time_zone(&mut |entry| {
                    let array = unwrap!(array_opt.take());
                    let next = array
                        .push()?
                        .offset(entry.offset)?
                        .valid_at(entry.valid_at)?
                        .name(entry.name)?
                        .end()?;
                    array_opt = Some(next);
                    Ok(())
                })?;
                unwrap!(array_opt.take()).end()
            }
            ArrayAttributeRead::ReadOne(index, item_builder) => {
                let mut item_opt = Some(item_builder);
                let mut returned: Option<P> = None;
                let mut current = 0u16;
                self.time_sync.time_zone(&mut |entry| {
                    if returned.is_none() && current == index {
                        let b = unwrap!(item_opt.take());
                        returned = Some(
                            b.offset(entry.offset)?
                                .valid_at(entry.valid_at)?
                                .name(entry.name)?
                                .end()?,
                        );
                    }
                    current = current.saturating_add(1);
                    Ok(())
                })?;
                returned.ok_or_else(|| ErrorCode::ConstraintError.into())
            }
            ArrayAttributeRead::ReadNone(array) => array.end(),
        }
    }

    fn dst_offset<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<DSTOffsetStructArrayBuilder<P>, DSTOffsetStructBuilder<P>>,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(array) => {
                let mut array_opt = Some(array);
                self.time_sync.dst_offset(&mut |entry| {
                    let array = unwrap!(array_opt.take());
                    let next = array
                        .push()?
                        .offset(entry.offset)?
                        .valid_starting(entry.valid_starting)?
                        .valid_until(Nullable::new(entry.valid_until))?
                        .end()?;
                    array_opt = Some(next);
                    Ok(())
                })?;
                unwrap!(array_opt.take()).end()
            }
            ArrayAttributeRead::ReadOne(index, item_builder) => {
                let mut item_opt = Some(item_builder);
                let mut returned: Option<P> = None;
                let mut current = 0u16;
                self.time_sync.dst_offset(&mut |entry| {
                    if returned.is_none() && current == index {
                        let b = unwrap!(item_opt.take());
                        returned = Some(
                            b.offset(entry.offset)?
                                .valid_starting(entry.valid_starting)?
                                .valid_until(Nullable::new(entry.valid_until))?
                                .end()?,
                        );
                    }
                    current = current.saturating_add(1);
                    Ok(())
                })?;
                returned.ok_or_else(|| ErrorCode::ConstraintError.into())
            }
            ArrayAttributeRead::ReadNone(array) => array.end(),
        }
    }

    fn local_time(&self, _ctx: impl ReadContext) -> Result<Nullable<u64>, Error> {
        self.time_sync.local_time()
    }

    fn time_zone_database(&self, _ctx: impl ReadContext) -> Result<TimeZoneDatabaseEnum, Error> {
        self.time_sync.time_zone_database()
    }

    fn time_zone_list_max_size(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        self.time_sync.time_zone_list_max_size()
    }

    fn dst_offset_list_max_size(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        self.time_sync.dst_offset_list_max_size()
    }

    // ---- Commands

    fn handle_set_utc_time(
        &self,
        _ctx: impl InvokeContext,
        request: SetUTCTimeRequest<'_>,
    ) -> Result<(), Error> {
        self.time_sync.set_utc_time(&request)
    }

    fn handle_set_trusted_time_source(
        &self,
        _ctx: impl InvokeContext,
        request: SetTrustedTimeSourceRequest<'_>,
    ) -> Result<(), Error> {
        self.time_sync.set_trusted_time_source(&request)
    }

    fn handle_set_time_zone<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        request: SetTimeZoneRequest<'_>,
        response: SetTimeZoneResponseBuilder<P>,
    ) -> Result<P, Error> {
        let dst_offset_required = self.time_sync.set_time_zone(&request)?;
        response.dst_offset_required(dst_offset_required)?.end()
    }

    fn handle_set_dst_offset(
        &self,
        _ctx: impl InvokeContext,
        request: SetDSTOffsetRequest<'_>,
    ) -> Result<(), Error> {
        self.time_sync.set_dst_offset(&request)
    }

    fn handle_set_default_ntp(
        &self,
        _ctx: impl InvokeContext,
        request: SetDefaultNTPRequest<'_>,
    ) -> Result<(), Error> {
        self.time_sync.set_default_ntp(&request)
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
