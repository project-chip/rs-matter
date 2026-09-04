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
//! The cluster's mandatory members (`UTCTime`, `Granularity`,
//! `TimeSource`, and the `SetUTCTime` command) are handled by
//! [`TimeSyncHandler`] directly against the Matter-wide
//! [Last-Known-Good UTC Time](crate::Matter::last_known_utc_time)
//! state — they require no implementor input.
//!
//! [`TimeSync`] only carries the feature-gated members
//! (`TIME_ZONE` / `NTP_CLIENT` / `NTP_SERVER` / `TIME_SYNC_CLIENT`).
//! Every method has a "no value" default so `impl TimeSync for ()`
//! is a fully usable no-op provider; implementors only override the
//! methods matching the options they advertised.

use core::num::NonZeroU8;

use bitflags::bitflags;

use heapless::String;

use embassy_futures::select::select;

use crate::dm::endpoints::ROOT_ENDPOINT_ID;
use crate::dm::{
    ArrayAttributeRead, AttrChangeNotifier, Attribute, Cluster, Command, Dataver, EndptId,
    EventEmitter, HandlerContext, InvokeContext, LifecycleOp, NodeId, Quality, ReadContext,
};
use crate::error::{Error, ErrorCode};
use crate::persist::{
    KvBlobStore, KvBlobStoreAccess, Persist, LKG_UTC_KEY, TIME_ZONE_KEY, TRUSTED_TIME_SOURCE_KEY,
};
use crate::tlv::{
    FromTLV, Nullable, NullableBuilder, TLVBuilderParent, TLVElement, TLVTag, TLVWrite, ToTLV,
    Utf8StrBuilder, TLV,
};
use crate::utils::cell::RefCell;
use crate::utils::epoch::FIRMWARE_BUILD_MATTER_US;
use crate::utils::init::{init, into_init, try_init, Init};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;

pub use crate::dm::clusters::decl::time_synchronization::*;

pub mod client;

/// An enum describing the current UTC timestamp the real-time clock is aware of.
///
/// The timestamp is expressed as Matter-epoch microseconds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum UtcTime {
    /// The RTC is actively tracking the current time, anchored at the given Matter-epoch microseconds value.
    Reliable(u64),
    /// The RTC is not currently tracking the current time, but the given Matter-epoch microseconds value is
    /// the last known good UTC time persisted on the device.
    ///
    /// Do note that a "last known" time is always available, as the firmware build timestamp is used as the
    /// initial value on a freshly-flashed device.
    LastKnown(u64),
}

impl UtcTime {
    /// Return the current UTC time if available, or `None` if no reliable time is currently tracked.
    pub const fn reliable(&self) -> Option<u64> {
        match self {
            UtcTime::Reliable(utc) => Some(*utc),
            UtcTime::LastKnown(_) => None,
        }
    }

    /// Return the current UTC time if available, or the persisted LKG UTC otherwise.
    pub const fn any(&self) -> u64 {
        match self {
            UtcTime::Reliable(utc) | UtcTime::LastKnown(utc) => *utc,
        }
    }

    /// Return the current UTC time in seconds if available, or `None` if no reliable time is currently tracked.
    pub const fn reliable_secs(&self) -> Option<u64> {
        match self {
            UtcTime::Reliable(utc) => Some(*utc / 1_000_000),
            UtcTime::LastKnown(_) => None,
        }
    }

    /// Return the current UTC time in seconds if available, or the persisted LKG UTC otherwise.
    pub const fn any_secs(&self) -> u64 {
        match self {
            UtcTime::Reliable(utc) | UtcTime::LastKnown(utc) => *utc / 1_000_000,
        }
    }
}

/// Last-Known-Good UTC Time tracking for the device (Matter Core spec).
///
/// The persisted `utc_us` field is the spec-mandated stored
/// fallback used by cert path validation when no live time
/// synchronization is available; it is seeded from
/// [`crate::utils::epoch::FIRMWARE_BUILD_MATTER_US`] on a
/// freshly-flashed device.
///
/// `anchor`, `granularity`, and `source` are **volatile** — they
/// describe the current monotonic-clock anchoring around the most
/// recent [`Matter::set_utc_time`] call. After reboot, `anchor` is
/// `None` (no live current-time tracking is active), so the TimeSync
/// cluster reports `UTCTime = Null`, `Granularity = NoTimeGranularity`
/// and `TimeSource = None` (per spec) — while
/// `utc_us` still carries the persisted LKG value for cert validity.
pub struct Rtc {
    /// Last-Known-Good UTC time, Matter-epoch microseconds.
    utc_us: u64,
    /// Same as `utc_us` except always equal to the last persisted value.
    utc_us_persisted: u64,
    /// Granularity at the time of the last `set_utc_time` call, with
    /// the "one level lower than supplied" step-down already
    /// applied and floored at `MinutesGranularity`.
    /// **Not persisted** — resets to `NoTimeGranularity` at boot,
    /// matching the `anchor = None` post-reboot state.
    granularity: GranularityEnum,
    /// Authority that last called `set_utc_time`. **Not persisted** —
    /// resets to `None` at boot.
    source: TimeSourceEnum,
    /// `Instant::now()` captured at the last `set_utc_time` call.
    /// Volatile — `None` after reboot until next set.
    anchor: Option<embassy_time::Instant>,
    /// Configured Trusted Time Source for the device (Matter Core spec).
    /// At most one entry; the fabric that
    /// installed it owns it and is cleared on fabric removal.
    /// Persisted under [`crate::persist::TRUSTED_TIME_SOURCE_KEY`].
    trusted_time_source: Option<TrustedTimeSource>,
}

impl Rtc {
    #[inline(always)]
    pub(crate) const fn new() -> Self {
        Self {
            utc_us: FIRMWARE_BUILD_MATTER_US,
            utc_us_persisted: FIRMWARE_BUILD_MATTER_US,
            granularity: GranularityEnum::NoTimeGranularity,
            source: TimeSourceEnum::None,
            anchor: None,
            trusted_time_source: None,
        }
    }

    /// Return an in-place initializer for `LkgUtc`.
    pub(crate) fn init() -> impl Init<Self> {
        init!(Self {
            utc_us: FIRMWARE_BUILD_MATTER_US,
            utc_us_persisted: FIRMWARE_BUILD_MATTER_US,
            granularity: GranularityEnum::NoTimeGranularity,
            source: TimeSourceEnum::None,
            anchor: None,
            trusted_time_source: None,
        })
    }

    fn reset(&mut self) {
        self.utc_us = FIRMWARE_BUILD_MATTER_US;
        self.utc_us_persisted = FIRMWARE_BUILD_MATTER_US;
        self.granularity = GranularityEnum::NoTimeGranularity;
        self.source = TimeSourceEnum::None;
        self.anchor = None;
        self.trusted_time_source = None;
    }

    pub(crate) fn reset_persist<S: KvBlobStore>(
        &mut self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.reset();

        store.remove(LKG_UTC_KEY, buf)?;
        store.remove(TRUSTED_TIME_SOURCE_KEY, buf)?;
        Ok(())
    }

    pub(crate) fn load_persist<S: KvBlobStore>(
        &mut self,
        mut kv: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.reset();

        // Load the persisted Last-Known-Good UTC Time, if any.
        // Floor at `FIRMWARE_BUILD_MATTER_US` per Matter Core spec -
        // the on-disk value must never regress us
        // below the build timestamp (the documented lower bound
        // we never adjust backwards past).
        if let Some(data) = kv.load(LKG_UTC_KEY, buf)? {
            let stored = u64::from_tlv(&TLVElement::new(data))?;
            let floor = FIRMWARE_BUILD_MATTER_US;

            self.utc_us_persisted = stored;
            self.utc_us = stored.max(floor);
        }

        // Load the persisted Trusted Time Source, if any.
        if let Some(data) = kv.load(TRUSTED_TIME_SOURCE_KEY, buf)? {
            self.trusted_time_source = Some(TrustedTimeSource::from_tlv(&TLVElement::new(data))?);
        }

        Ok(())
    }

    /// Return the configured Trusted Time Source, or `None` if unset
    /// (Matter Core spec).
    pub fn trusted_time_source(&self) -> Option<TrustedTimeSource> {
        self.trusted_time_source
    }

    /// Install or clear the Trusted Time Source (Matter Core spec).
    /// `fab_idx` is the fabric performing the change —
    /// recorded so that fabric removal can clear an entry it owns.
    pub fn set_trusted_time_source<E: EventEmitter>(
        &mut self,
        source: Option<TrustedTimeSource>,
        change_notifier: &dyn AttrChangeNotifier,
        event_emitter: E,
    ) -> Result<(), Error> {
        if self.trusted_time_source != source {
            let previous = self.trusted_time_source;

            self.trusted_time_source = source;

            change_notifier.notify_attr_changed(
                ROOT_ENDPOINT_ID,
                TimeSyncHandler::CLUSTER.id,
                AttributeId::TrustedTimeSource as _,
            );

            // Matter Core spec: emit `MissingTrustedTimeSource`
            // when SetTrustedTimeSource clears a previously-set entry (null
            // request payload, transitioning from `Some(..)` → `None`).
            if self.trusted_time_source.is_none() && previous.is_some() {
                MissingTrustedTimeSource::emit_for(event_emitter, ROOT_ENDPOINT_ID, |b| b.end())?;
            }
        }

        Ok(())
    }

    /// Install or clear the Trusted Time Source (Matter Core spec).
    /// `fab_idx` is the fabric performing the change —
    /// recorded so that fabric removal can clear an entry it owns.
    /// `source = None` clears any existing entry.
    ///
    /// Updates in-memory state, persists under
    /// [`crate::persist::TRUSTED_TIME_SOURCE_KEY`], and notifies
    /// subscribers of the `TrustedTimeSource` attribute change.
    pub(crate) fn set_trusted_time_source_persist<S: KvBlobStoreAccess, E: EventEmitter>(
        &mut self,
        source: Option<TrustedTimeSource>,
        persist: &mut Persist<S>,
        change_notifier: &dyn AttrChangeNotifier,
        event_emitter: E,
    ) -> Result<(), Error> {
        if self.trusted_time_source != source {
            self.set_trusted_time_source(source, change_notifier, event_emitter)?;

            match source {
                Some(source) => {
                    persist.store_tlv(TRUSTED_TIME_SOURCE_KEY, source)?;
                }
                None => {
                    persist.remove(TRUSTED_TIME_SOURCE_KEY)?;
                }
            }
        }

        Ok(())
    }

    /// Return the current UTC time if available, or the persisted Last-Known-Good UTC Time otherwise.
    pub fn utc_time(&self) -> UtcTime {
        if let Some(anchor) = self.anchor {
            let elapsed_us = embassy_time::Instant::now()
                .checked_duration_since(anchor)
                .map(|d| d.as_micros())
                .unwrap_or(0);

            UtcTime::Reliable(self.utc_us.saturating_add(elapsed_us))
        } else {
            UtcTime::LastKnown(self.utc_us)
        }
    }

    /// Return the Granularity reported on the wire for the TimeSync
    /// cluster's `Granularity` attribute, derived from the most
    /// recent [`Self::set_utc_time`] (with the spec-required
    /// step-down and floor already applied) — or `NoTimeGranularity`
    /// if no `set_utc_time` has been called since boot (per
    /// the spec, which forbids `NoTimeGranularity` only while
    /// `UTCTime ≠ Null`).
    pub fn utc_time_granularity(&self) -> GranularityEnum {
        if self.anchor.is_some() {
            self.granularity
        } else {
            GranularityEnum::NoTimeGranularity
        }
    }

    /// Return the TimeSource reported on the wire for the TimeSync
    /// cluster's `TimeSource` attribute — `None` until the first
    /// [`Self::set_utc_time`] (per spec).
    pub fn utc_time_source(&self) -> TimeSourceEnum {
        if self.anchor.is_some() {
            self.source
        } else {
            TimeSourceEnum::None
        }
    }

    /// Update the Last-Known-Good UTC Time (Matter Core spec),
    /// capturing a fresh monotonic anchor so subsequent
    /// [`Self::utc_time`] reads advance from the supplied value.
    ///
    /// Per the spec: the supplied `granularity` is recorded
    /// stepped-down by one level (with a floor of
    /// `MinutesGranularity` per spec); the supplied `source`
    /// is recorded verbatim.
    ///
    /// The new value is written to the in-memory state immediately.
    /// Persistence to `LKG_UTC_KEY` happens separately — the
    /// TimeSync cluster handler invokes this from inside a
    /// `kv.access(...)` closure and writes through the same handle.
    /// Direct callers that need on-disk durability should call
    /// [`Self::persist_lkg_utc`] explicitly.
    pub fn set_utc_time(
        &mut self,
        utc_us: u64,
        granularity: GranularityEnum,
        source: TimeSourceEnum,
        change_notifier: &dyn AttrChangeNotifier,
    ) -> bool {
        let stepped = match granularity {
            GranularityEnum::MicrosecondsGranularity => GranularityEnum::MillisecondsGranularity,
            GranularityEnum::MillisecondsGranularity => GranularityEnum::SecondsGranularity,
            GranularityEnum::SecondsGranularity => GranularityEnum::MinutesGranularity,
            // Minutes / NoTime → floor at Minutes
            // (spec forbids NoTime while UTCTime is non-null).
            _ => GranularityEnum::MinutesGranularity,
        };

        let changed = self.utc_us != utc_us || self.granularity != stepped || self.source != source;

        if changed || self.anchor.is_none() {
            self.utc_us = utc_us;
            self.granularity = stepped;
            self.source = source;
            self.anchor = Some(embassy_time::Instant::now());

            change_notifier.notify_attr_changed(
                ROOT_ENDPOINT_ID,
                TimeSyncHandler::CLUSTER.id,
                AttributeId::UTCTime as _,
            );
            change_notifier.notify_attr_changed(
                ROOT_ENDPOINT_ID,
                TimeSyncHandler::CLUSTER.id,
                AttributeId::Granularity as _,
            );
            change_notifier.notify_attr_changed(
                ROOT_ENDPOINT_ID,
                TimeSyncHandler::CLUSTER.id,
                AttributeId::TimeSource as _,
            );
        }

        changed
    }

    pub(crate) fn set_utc_time_persist<S: KvBlobStoreAccess>(
        &mut self,
        utc_us: u64,
        granularity: GranularityEnum,
        source: TimeSourceEnum,
        persist: &mut Persist<S>,
        change_notifier: &dyn AttrChangeNotifier,
    ) -> Result<(), Error> {
        const DELTA: u64 = 24 * 60 * 60 * 1_000_000; // 1 day in microseconds

        let delta = self.utc_us_persisted.abs_diff(utc_us);

        self.set_utc_time(utc_us, granularity, source, change_notifier);

        if delta >= DELTA {
            // As per the Matter Core spec, we have to persist the new LKG UTC at least once per month
            // Since this would be an involved math, we instead persist if the new LKG UTC is different
            // by more than a day than the previous one, which should be good enough to cover the requirement
            // without needing a separate timer for periodic persistence.

            info!("TimeSync: UTC time changed by more than a day, persisting");

            persist.store_tlv(LKG_UTC_KEY, utc_us.to_le_bytes())?;
            self.utc_us_persisted = utc_us;
        }

        Ok(())
    }
}

/// Persisted Trusted Time Source descriptor (Matter Core spec).
/// Records which fabric configured the source so that fabric removal can
/// clear it and emit `MissingTrustedTimeSource`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TrustedTimeSource {
    /// Fabric that installed the source (the `FabricIndex` injected by
    /// the IM dispatcher into the `SetTrustedTimeSource` invoke).
    pub fab_idx: NonZeroU8,
    /// Node ID of the trusted source on that fabric.
    pub node_id: NodeId,
    /// Endpoint on the trusted source's node that hosts the TimeSync
    /// cluster server.
    pub endpoint: EndptId,
}

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
#[derive(Debug, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
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

/// Pluggable data source for the feature-gated members of the Time
/// Synchronization cluster (`TIME_ZONE` / `NTP_CLIENT` / `NTP_SERVER`).
///
/// The mandatory members — `UTCTime`, `Granularity`, `TimeSource`,
/// and the `SetUTCTime` command — are handled by [`TimeSyncHandler`] directly
/// against the built-in Matter RTC state and do **not** appear on this trait.
///
/// The `TIME_SYNC_CLIENT` feature (if enabled) is also handled by the handler
/// directly against the `TrustedTimeSource` entry in the built-in Matter RTC state,
/// so it also doesn't appear here.
/// Data provider for the `TIME_ZONE` feature: the `TimeZone` / `DSTOffset`
/// lists and their `SetTimeZone` / `SetDSTOffset` mutations.
///
/// Implemented by [`TimeZoneStore`], the batteries-included validated
/// storage; custom implementors take over validation and storage themselves.
pub trait TimeZones {
    /// Stream the active time-zone entries into `visit`.
    fn time_zone(
        &self,
        visit: &mut dyn FnMut(&TimeZoneEntry<'_>) -> Result<(), Error>,
    ) -> Result<(), Error>;

    /// Stream the active DST-offset entries into `visit`.
    fn dst_offset(
        &self,
        visit: &mut dyn FnMut(&DSTOffsetEntry) -> Result<(), Error>,
    ) -> Result<(), Error>;

    /// How complete the device's IANA time-zone database is.
    fn time_zone_database(&self) -> Result<TimeZoneDatabaseEnum, Error>;

    /// Maximum length of the `TimeZone` list this device accepts.
    fn time_zone_list_max_size(&self) -> Result<u8, Error>;

    /// Maximum length of the `DSTOffset` list this device accepts.
    fn dst_offset_list_max_size(&self) -> Result<u8, Error>;

    /// Handle `SetTimeZone`. Returns the `DSTOffsetRequired` field for the
    /// response.
    fn set_time_zone(&self, request: &SetTimeZoneRequest<'_>) -> Result<bool, Error>;

    /// Handle `SetDSTOffset`.
    fn set_dst_offset(&self, request: &SetDSTOffsetRequest<'_>) -> Result<(), Error>;
}

impl<T> TimeZones for &T
where
    T: TimeZones,
{
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

    fn time_zone_database(&self) -> Result<TimeZoneDatabaseEnum, Error> {
        (*self).time_zone_database()
    }

    fn time_zone_list_max_size(&self) -> Result<u8, Error> {
        (*self).time_zone_list_max_size()
    }

    fn dst_offset_list_max_size(&self) -> Result<u8, Error> {
        (*self).dst_offset_list_max_size()
    }

    fn set_time_zone(&self, request: &SetTimeZoneRequest<'_>) -> Result<bool, Error> {
        (*self).set_time_zone(request)
    }

    fn set_dst_offset(&self, request: &SetDSTOffsetRequest<'_>) -> Result<(), Error> {
        (*self).set_dst_offset(request)
    }
}

/// Data provider for the `NTP_CLIENT` feature.
pub trait NtpClient {
    /// Hostname or IP address of the default NTP server, or `Null` if
    /// none is configured.
    fn default_ntp(&self) -> Result<Nullable<&str>, Error>;

    /// Whether the device's NTP-client resolver supports DNS names
    /// (vs. only literal IP addresses).
    fn supports_dns_resolve(&self) -> Result<bool, Error>;

    /// Handle `SetDefaultNTP`.
    fn set_default_ntp(&self, request: &SetDefaultNTPRequest<'_>) -> Result<(), Error>;
}

impl<T> NtpClient for &T
where
    T: NtpClient,
{
    fn default_ntp(&self) -> Result<Nullable<&str>, Error> {
        (*self).default_ntp()
    }

    fn supports_dns_resolve(&self) -> Result<bool, Error> {
        (*self).supports_dns_resolve()
    }

    fn set_default_ntp(&self, request: &SetDefaultNTPRequest<'_>) -> Result<(), Error> {
        (*self).set_default_ntp(request)
    }
}

/// Data provider for the `NTP_SERVER` feature.
pub trait NtpServer {
    /// Whether the device is currently serving NTP queries.
    fn ntp_server_available(&self) -> Result<bool, Error>;
}

impl<T> NtpServer for &T
where
    T: NtpServer,
{
    fn ntp_server_available(&self) -> Result<bool, Error> {
        (*self).ntp_server_available()
    }
}

/// Maximum byte length of a `TimeZoneStruct::name` (spec constraint 0..=64).
pub const TIME_ZONE_NAME_MAX: usize = 64;

/// One owned `TimeZone` entry as stored by [`TimeZoneStore`].
#[derive(FromTLV, ToTLV)]
struct TimeZoneOwned {
    offset: i32,
    valid_at: u64,
    name: Option<String<TIME_ZONE_NAME_MAX>>,
}

/// The persisted shape of [`TimeZoneStore`]: both `nonVolatile`-quality lists
/// as one TLV blob under [`TIME_ZONE_KEY`].
struct TimeZoneStoreData<const TIME_ZONE_MAX: usize, const DST_OFFSET_MAX: usize> {
    time_zone: Vec<TimeZoneOwned, TIME_ZONE_MAX>,
    dst_offset: Vec<DSTOffsetEntry, DST_OFFSET_MAX>,
}

impl<const TIME_ZONE_MAX: usize, const DST_OFFSET_MAX: usize>
    TimeZoneStoreData<TIME_ZONE_MAX, DST_OFFSET_MAX>
{
    const fn new() -> Self {
        Self {
            time_zone: Vec::new(),
            dst_offset: Vec::new(),
        }
    }

    fn init() -> impl Init<Self> {
        init!(Self {
            time_zone <- Vec::init(),
            dst_offset <- Vec::init(),
        })
    }
}

impl<'a, const TIME_ZONE_MAX: usize, const DST_OFFSET_MAX: usize> FromTLV<'a>
    for TimeZoneStoreData<TIME_ZONE_MAX, DST_OFFSET_MAX>
{
    fn from_tlv(tlv: &TLVElement<'a>) -> Result<Self, Error> {
        let tlv = tlv.structure()?;

        Ok(Self {
            time_zone: FromTLV::from_tlv(&tlv.ctx(0)?)?,
            dst_offset: FromTLV::from_tlv(&tlv.ctx(1)?)?,
        })
    }

    fn init_from_tlv(tlv: TLVElement<'a>) -> impl Init<Self, Error> {
        into_init(move || {
            let seq = tlv.structure()?;

            let init = try_init!(Self {
                time_zone <- Vec::<TimeZoneOwned, TIME_ZONE_MAX>::init_from_tlv(seq.ctx(0)?),
                dst_offset <- Vec::<DSTOffsetEntry, DST_OFFSET_MAX>::init_from_tlv(seq.ctx(1)?),
            }? Error);

            Ok(init)
        })
    }
}

impl<const TIME_ZONE_MAX: usize, const DST_OFFSET_MAX: usize> ToTLV
    for TimeZoneStoreData<TIME_ZONE_MAX, DST_OFFSET_MAX>
{
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.start_struct(tag)?;

        self.time_zone.to_tlv(&TLVTag::Context(0), &mut tw)?;
        self.dst_offset.to_tlv(&TLVTag::Context(1), &mut tw)?;

        tw.end_container()
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        use crate::tlv::TLVIter;

        core::iter::empty()
            .start_struct(tag)
            .chain_iter(self.time_zone.tlv_iter(TLVTag::Context(0)))
            .chain_iter(self.dst_offset.tlv_iter(TLVTag::Context(1)))
            .end_container()
    }
}

/// The mutable innards of [`TimeZoneStore`].
struct TimeZoneStoreState<const TIME_ZONE_MAX: usize, const DST_OFFSET_MAX: usize> {
    data: TimeZoneStoreData<TIME_ZONE_MAX, DST_OFFSET_MAX>,
    /// Bumped on every accepted `SetTimeZone` / `SetDSTOffset`, so the
    /// transition timer can re-evaluate its schedule.
    generation: u32,
}

impl<const TIME_ZONE_MAX: usize, const DST_OFFSET_MAX: usize>
    TimeZoneStoreState<TIME_ZONE_MAX, DST_OFFSET_MAX>
{
    const fn new() -> Self {
        Self {
            data: TimeZoneStoreData::new(),
            generation: 0,
        }
    }

    fn init() -> impl Init<Self> {
        init!(Self {
            data <- TimeZoneStoreData::init(),
            generation: 0,
        })
    }
}

/// A concrete [`TimeSync`] provider implementing the `TIME_ZONE` feature's
/// storage and validation: the `TimeZone` / `DSTOffset` lists with all the
/// Matter Core spec constraint checks on `SetTimeZone` / `SetDSTOffset`.
///
/// Pure validated storage: event emission, persistence and `LocalTime`
/// computation are orchestrated by [`TimeSyncHandler`], which has the
/// contexts this store deliberately does not.
///
/// `TimeZoneDatabase` is reported as `None` - names are stored and echoed
/// back verbatim, but never interpreted.
pub struct TimeZoneStore<const TIME_ZONE_MAX: usize = 2, const DST_OFFSET_MAX: usize = 2> {
    state: Mutex<RefCell<TimeZoneStoreState<TIME_ZONE_MAX, DST_OFFSET_MAX>>>,
    /// Signalled on every accepted mutation (and by the handler when UTC time
    /// is set), so the transition timer in [`TimeSyncHandler::run`] can
    /// re-evaluate its schedule.
    changed: Notification,
}

impl<const TIME_ZONE_MAX: usize, const DST_OFFSET_MAX: usize>
    TimeZoneStore<TIME_ZONE_MAX, DST_OFFSET_MAX>
{
    /// Create a store with the spec-default single `{offset: 0, valid_at: 0}`
    /// time-zone entry and no DST offsets.
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(TimeZoneStoreState::new())),
            changed: Notification::new(),
        }
    }

    /// Return an in-place initializer for `TimeZoneStore`.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            state <- Mutex::init(RefCell::init(TimeZoneStoreState::init())),
            changed <- Notification::init(),
        })
    }

    /// Wait until the store's contents (or the node's UTC time) may have
    /// changed. Used by the transition timer.
    pub async fn wait_changed(&self) {
        self.changed.wait().await
    }

    /// Signal [`Self::wait_changed`] waiters. Called internally on accepted
    /// mutations; also called by the handler when UTC time is (re)set, since
    /// that changes which entries are active.
    pub fn note_changed(&self) {
        self.changed.notify();
    }

    /// Re-hydrate both lists from `store` under [`TIME_ZONE_KEY`].
    ///
    /// Driven by [`LifecycleOp::Startup`], before the data model starts
    /// serving operations. A missing key (first boot / cleared persistence)
    /// leaves the defaults.
    fn load_persist<S: KvBlobStore>(&self, mut store: S, buf: &mut [u8]) -> Result<(), Error> {
        let Some(data) = store.load(TIME_ZONE_KEY, buf)? else {
            return Ok(());
        };

        // TODO: LARGE BUFFER
        let loaded = TimeZoneStoreData::from_tlv(&TLVElement::new(data))?;

        self.state.lock(|state| {
            let mut state = state.borrow_mut();

            state.data = loaded;
        });

        info!("Loaded TimeZone / DSTOffset lists from storage");

        Ok(())
    }

    /// Reset both lists to their factory defaults - an empty `TimeZone` list
    /// (which reads back as the implicit `{offset: 0, valid_at: 0}` entry) and
    /// an empty `DSTOffset` list - and remove [`TIME_ZONE_KEY`] from `store`.
    ///
    /// Driven by [`LifecycleOp::FactoryReset`]. The counterpart of
    /// [`Self::load_persist`]: both lists are `nonVolatile` quality, so a
    /// factory reset has to clear them here as well as in memory.
    fn reset_persist<S: KvBlobStore>(&self, mut store: S, buf: &mut [u8]) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();

            state.data = TimeZoneStoreData::new();
            state.generation = state.generation.wrapping_add(1);
        });

        store.remove(TIME_ZONE_KEY, buf)?;

        // A factory reset can land while the node is running, so wake the
        // transition timer to re-evaluate against the now-empty lists.
        self.changed.notify();

        info!("Removed TimeZone / DSTOffset lists from storage");

        Ok(())
    }

    /// Serialise both lists to `kv` under [`TIME_ZONE_KEY`]. Called by the
    /// handler after every accepted mutation (the lists are `nonVolatile`
    /// quality per the Matter Core spec).
    fn store_persist<S: KvBlobStoreAccess>(&self, kv: S) -> Result<(), Error> {
        let mut persist = Persist::new(kv);

        self.state.lock(|state| {
            let state = state.borrow();

            persist.store_tlv(TIME_ZONE_KEY, &state.data)
        })?;

        persist.run()
    }

    /// The current change generation; bumped on every accepted mutation.
    pub fn generation(&self) -> u32 {
        self.state.lock(|state| state.borrow().generation)
    }

    /// The `(offset, name)` of the currently-active time-zone entry: the last
    /// entry whose `valid_at` has passed, or the implicit `(0, None)` default
    /// when the list is empty.
    pub fn active_time_zone(&self, now: u64) -> (i32, Option<String<TIME_ZONE_NAME_MAX>>) {
        self.state.lock(|state| {
            let state = state.borrow();

            state
                .data
                .time_zone
                .iter()
                .rfind(|entry| entry.valid_at <= now)
                .map(|entry| (entry.offset, entry.name.clone()))
                .unwrap_or((0, None))
        })
    }

    /// The DST offset active at `now`, if any.
    pub fn active_dst_offset(&self, now: u64) -> Option<i32> {
        self.state.lock(|state| {
            let state = state.borrow();

            state
                .data
                .dst_offset
                .iter()
                .find(|entry| {
                    entry.valid_starting <= now
                        && entry.valid_until.map(|until| now < until).unwrap_or(true)
                })
                .map(|entry| entry.offset)
        })
    }

    /// Whether the DST table is empty.
    pub fn dst_table_empty(&self) -> bool {
        self.state
            .lock(|state| state.borrow().data.dst_offset.is_empty())
    }

    /// Whether the DST table still carries usable information at `now`: at
    /// least one entry is active or scheduled (its `valid_until` is Null or in
    /// the future).
    ///
    /// `false` covers both "empty" (e.g. just cleared by `SetTimeZone`) and
    /// "exhausted" (every entry expired). `DSTTableEmpty` is emitted on the
    /// usable -> not-usable *edge* - `TC_TIMESYNC_2_10` requires it both when
    /// `SetTimeZone` clears a non-empty table and when the last entry expires
    /// naturally. Entries are deliberately *retained* rather than pruned:
    /// `TestTimeSynchronization` (and chip) expect `DSTOffset` reads to return
    /// exactly what was written.
    pub fn dst_usable(&self, now: u64) -> bool {
        self.state.lock(|state| {
            let state = state.borrow();

            state
                .data
                .dst_offset
                .iter()
                .any(|entry| entry.valid_until.map(|until| now < until).unwrap_or(true))
        })
    }

    /// The next Matter-epoch-microseconds instant after `now` at which the
    /// active time zone or DST state can change - i.e. the earliest
    /// `valid_at` / `valid_starting` / `valid_until` still in the future.
    /// `None` when no transition is scheduled.
    pub fn next_transition(&self, now: u64) -> Option<u64> {
        self.state.lock(|state| {
            let state = state.borrow();

            let tz = state
                .data
                .time_zone
                .iter()
                .map(|entry| entry.valid_at)
                .filter(|at| *at > now)
                .min();

            let dst = state
                .data
                .dst_offset
                .iter()
                .flat_map(|entry| {
                    [Some(entry.valid_starting), entry.valid_until]
                        .into_iter()
                        .flatten()
                })
                .filter(|at| *at > now)
                .min();

            match (tz, dst) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            }
        })
    }

    /// The `SetDSTOffset` constraint checks, factored out so the caller can
    /// clear the table on rejection:
    /// - at most [`DST_OFFSET_MAX`] entries, else RESOURCE_EXHAUSTED
    /// - sorted ascending by `validStarting`, else CONSTRAINT_ERROR
    /// - ranges must not overlap: an entry must not start before its
    ///   predecessor's `validUntil`, else CONSTRAINT_ERROR
    /// - only the last entry may have a Null `validUntil`, else
    ///   CONSTRAINT_ERROR
    /// - `validStarting < validUntil` within an entry, else CONSTRAINT_ERROR
    fn validate_dst_offset(&self, request: &SetDSTOffsetRequest<'_>) -> Result<(), Error> {
        let mut prev_starting: Option<u64> = None;
        let mut prev_until: Option<u64> = None;
        let mut seen_null_until = false;

        for (index, entry) in request.dst_offset()?.iter().enumerate() {
            let entry = entry?;

            if index == DST_OFFSET_MAX {
                return Err(ErrorCode::ResourceExhausted.into());
            }

            // A Null `validUntil` on a previous entry means that entry was
            // not last - reject.
            if seen_null_until {
                Err(ErrorCode::ConstraintError)?;
            }

            let starting = entry.valid_starting()?;

            if let Some(prev) = prev_starting {
                if starting <= prev {
                    Err(ErrorCode::ConstraintError)?;
                }
            }

            if let Some(until) = prev_until {
                if starting < until {
                    // Overlaps the predecessor's still-valid range.
                    Err(ErrorCode::ConstraintError)?;
                }
            }

            match entry.valid_until()?.into_option() {
                Some(until) => {
                    if starting >= until {
                        Err(ErrorCode::ConstraintError)?;
                    }

                    prev_until = Some(until);
                }
                None => seen_null_until = true,
            }

            prev_starting = Some(starting);
        }

        Ok(())
    }
}

impl<const TIME_ZONE_MAX: usize, const DST_OFFSET_MAX: usize> Default
    for TimeZoneStore<TIME_ZONE_MAX, DST_OFFSET_MAX>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const TIME_ZONE_MAX: usize, const DST_OFFSET_MAX: usize> TimeZones
    for TimeZoneStore<TIME_ZONE_MAX, DST_OFFSET_MAX>
{
    fn time_zone(
        &self,
        visit: &mut dyn FnMut(&TimeZoneEntry<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.state.lock(|state| {
            let state = state.borrow();

            if state.data.time_zone.is_empty() {
                // The spec-default entry: reported even before any
                // `SetTimeZone`, as the `TimeZone` list has a min size of 1.
                return visit(&TimeZoneEntry {
                    offset: 0,
                    valid_at: 0,
                    name: None,
                });
            }

            for entry in state.data.time_zone.iter() {
                visit(&TimeZoneEntry {
                    offset: entry.offset,
                    valid_at: entry.valid_at,
                    name: entry.name.as_deref(),
                })?;
            }

            Ok(())
        })
    }

    fn dst_offset(
        &self,
        visit: &mut dyn FnMut(&DSTOffsetEntry) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.state.lock(|state| {
            let state = state.borrow();

            for entry in state.data.dst_offset.iter() {
                visit(entry)?;
            }

            Ok(())
        })
    }

    fn time_zone_database(&self) -> Result<TimeZoneDatabaseEnum, Error> {
        Ok(TimeZoneDatabaseEnum::None)
    }

    fn time_zone_list_max_size(&self) -> Result<u8, Error> {
        Ok(TIME_ZONE_MAX as u8)
    }

    fn dst_offset_list_max_size(&self) -> Result<u8, Error> {
        Ok(DST_OFFSET_MAX as u8)
    }

    fn set_time_zone(&self, request: &SetTimeZoneRequest<'_>) -> Result<bool, Error> {
        // First pass: validate every constraint before mutating anything, so
        // a rejected request leaves the stored list untouched.
        //
        // Matter Core spec (and `TestTimeSynchronization` step-for-step):
        // - at most `TimeZoneListMaxSize` entries, else RESOURCE_EXHAUSTED
        // - first entry `validAt` SHALL be 0, else CONSTRAINT_ERROR
        // - subsequent entries `validAt` SHALL NOT be 0, else CONSTRAINT_ERROR
        // - strictly ascending by `validAt`, else CONSTRAINT_ERROR. NB: the
        //   spec states no such rule explicitly - it doesn't need to: with the
        //   spec's own cap of 2 entries (`TimeZoneListMaxSize` "may take the
        //   value of 1 or 2") the two checks above already force
        //   ascending order. The explicit check is defense-in-depth for
        //   larger `TIME_ZONE_MAX` instantiations (themselves off-spec, but
        //   expressible), where an unsorted list would silently corrupt the
        //   active-entry resolution in `active_time_zone` /
        //   `next_transition` / the LocalTime computation, all of which
        //   assume ascending order.
        // - `offset` in -12h..=+14h, `name` at most 64 bytes, else
        //   CONSTRAINT_ERROR
        // - an *empty* list is valid and resets to the default entry
        let mut prev_valid_at: Option<u64> = None;

        for (index, entry) in request.time_zone()?.iter().enumerate() {
            let entry = entry?;

            if index == TIME_ZONE_MAX {
                return Err(ErrorCode::ResourceExhausted.into());
            }

            let valid_at = entry.valid_at()?;

            if (index == 0) != (valid_at == 0) {
                Err(ErrorCode::ConstraintError)?;
            }

            if let Some(prev) = prev_valid_at {
                if valid_at <= prev {
                    Err(ErrorCode::ConstraintError)?;
                }
            }

            prev_valid_at = Some(valid_at);

            let offset = entry.offset()?;

            if !(-12 * 3600..=14 * 3600).contains(&offset) {
                Err(ErrorCode::ConstraintError)?;
            }

            if let Some(name) = entry.name()? {
                if name.len() > TIME_ZONE_NAME_MAX {
                    Err(ErrorCode::ConstraintError)?;
                }
            }
        }

        // Second pass: commit. Per the spec, an accepted `SetTimeZone` also
        // clears the DST table (the handler emits the matching events).
        self.state.lock(|state| {
            let mut state = state.borrow_mut();

            state.data.time_zone.clear();

            for entry in request.time_zone()?.iter() {
                let entry = entry?;

                let name = match entry.name()? {
                    Some(name) => {
                        Some(String::try_from(name).map_err(|_| ErrorCode::ConstraintError)?)
                    }
                    None => None,
                };

                // `unwrap` is safe: the first pass bounded the count.
                unwrap!(state
                    .data
                    .time_zone
                    .push(TimeZoneOwned {
                        offset: entry.offset()?,
                        valid_at: entry.valid_at()?,
                        name,
                    })
                    .ok());
            }

            state.data.dst_offset.clear();
            state.generation = state.generation.wrapping_add(1);

            Ok::<_, Error>(())
        })?;

        self.note_changed();

        // `DSTOffsetRequired`: with `TimeZoneDatabase = None` the device can
        // never compute DST itself, so offsets are always required.
        Ok(true)
    }

    fn set_dst_offset(&self, request: &SetDSTOffsetRequest<'_>) -> Result<(), Error> {
        // Matter Core spec (and `TestTimeSynchronization`):
        // - at most `DSTOffsetListMaxSize` entries, else RESOURCE_EXHAUSTED
        // - sorted ascending by `validStarting`, else CONSTRAINT_ERROR
        // - only the last entry may have a Null `validUntil`, else
        //   CONSTRAINT_ERROR
        // - `validStarting < validUntil` within an entry, else
        //   CONSTRAINT_ERROR
        // - an empty list is valid and clears the table
        // Per the Matter Core spec (and `TC_TIMESYNC_2_5` steps 5/7/9), a
        // *rejected* `SetDSTOffset` still clears the stored list - the command
        // semantically replaces the table, and a failed replacement leaves it
        // empty rather than restoring the old contents.
        let validated = self.validate_dst_offset(request);

        if let Err(e) = validated {
            self.state.lock(|state| {
                let mut state = state.borrow_mut();

                state.data.dst_offset.clear();
                state.generation = state.generation.wrapping_add(1);
            });

            self.note_changed();

            return Err(e);
        }

        self.state.lock(|state| {
            let mut state = state.borrow_mut();

            state.data.dst_offset.clear();

            for entry in request.dst_offset()?.iter() {
                let entry = entry?;

                // `unwrap` is safe: the first pass bounded the count.
                unwrap!(state
                    .data
                    .dst_offset
                    .push(DSTOffsetEntry {
                        offset: entry.offset()?,
                        valid_starting: entry.valid_starting()?,
                        valid_until: entry.valid_until()?.into_option(),
                    })
                    .ok());
            }

            state.generation = state.generation.wrapping_add(1);

            Ok::<_, Error>(())
        })?;

        self.note_changed();

        Ok(())
    }
}

// ---- Cluster-shape selection -------------------------------------------------

const fn time_sync_attrs<const OPTS: u8>(attr: &Attribute, _: u16, _: u32) -> bool {
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

const fn time_sync_cmds<const OPTS: u8>(cmd: &Command, _: u16, _: u32) -> bool {
    use CommandId as C;

    // `SetUTCTime` is mandatory whenever the cluster is present
    // (Matter Core spec, conformance `M`), independent of
    // features. Devices reporting `Granularity = NoTimeGranularity`
    // are additionally required to accept it.
    if cmd.id == C::SetUTCTime as u32 {
        return true;
    }

    let opts = Options::from_bits_truncate(OPTS);

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
/// forwards every non-builtin attribute read / command invoke to it.
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
    /// `TIME_ZONE` feature provider; `None` when the feature is not hosted.
    time_zones: Option<&'a dyn TimeZones>,
    /// `NTP_CLIENT` feature provider; `None` when the feature is not hosted.
    ntp_client: Option<&'a dyn NtpClient>,
    /// `NTP_SERVER` feature provider; `None` when the feature is not hosted.
    ntp_server: Option<&'a dyn NtpServer>,
    /// Set when the `TimeZones` provider is a [`TimeZoneStore`]: enables the
    /// transition timer in the `Handler::run` impl (TimeZoneStatus /
    /// DSTStatus / DSTTableEmpty events) and persistence of the `nonVolatile`
    /// lists. `None` for custom [`TimeZones`] providers, which own those
    /// concerns themselves.
    tz_store: Option<&'a TimeZoneStore>,
}

impl<'a> TimeSyncHandler<'a> {
    /// Create a handler with no feature providers: only the always-mandatory
    /// members (`UTCTime` / `Granularity` / `TimeSource` / `SetUTCTime`, plus
    /// the `TIME_SYNC_CLIENT` state), all served from the Matter-wide RTC.
    pub const fn new(dataver: Dataver) -> Self {
        Self {
            dataver,
            time_zones: None,
            ntp_client: None,
            ntp_server: None,
            tz_store: None,
        }
    }

    /// Create a handler backed by a [`TimeZoneStore`] - the batteries-included
    /// `TIME_ZONE` feature shape: SetTimeZone/SetDSTOffset validation and
    /// storage, transition events driven by the `Handler::run` impl, and
    /// persistence of the lists under [`TIME_ZONE_KEY`].
    pub const fn new_with_time_zone(dataver: Dataver, store: &'a TimeZoneStore) -> Self {
        Self {
            dataver,
            time_zones: Some(store),
            ntp_client: None,
            ntp_server: None,
            tz_store: Some(store),
        }
    }

    /// Provide a custom [`TimeZones`] implementation.
    pub const fn with_time_zones(mut self, time_zones: &'a dyn TimeZones) -> Self {
        self.time_zones = Some(time_zones);
        self
    }

    /// Provide an [`NtpClient`] implementation.
    pub const fn with_ntp_client(mut self, ntp_client: &'a dyn NtpClient) -> Self {
        self.ntp_client = Some(ntp_client);
        self
    }

    /// Provide an [`NtpServer`] implementation.
    pub const fn with_ntp_server(mut self, ntp_server: &'a dyn NtpServer) -> Self {
        self.ntp_server = Some(ntp_server);
        self
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait.
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

    fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        // Only the batteries-included `TimeZoneStore` shape persists anything
        // of its own; custom `TimeZones` providers own their storage, and the
        // Matter-wide RTC half of this cluster (`UTCTime` / `TrustedTimeSource`)
        // is driven by `Matter::startup` / `Matter::factory_reset`.
        let Some(store) = self.tz_store else {
            return Ok(());
        };

        match op {
            LifecycleOp::Startup => ctx.kv().access(|kv, buf| store.load_persist(kv, buf)),
            LifecycleOp::FactoryReset => ctx.kv().access(|kv, buf| store.reset_persist(kv, buf)),
            LifecycleOp::FabricRemoval { .. } => Ok(()),
        }
    }

    // ---- Always-on reads (served from Matter-wide LKG state, not
    // from the user-supplied `TimeSync` provider).

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        // The transition timer only exists for the batteries-included
        // [`TimeZoneStore`] shape; custom providers drive their own events.
        let Some(store) = self.tz_store else {
            return core::future::pending().await;
        };

        // Change-edge state. `None` = not yet evaluated (no valid UTC time) -
        // the first evaluation baselines silently, so a boot does not emit
        // spurious "changed to inactive" events; every later divergence emits.
        let mut last_tz: Option<i32> = None;
        let mut last_dst_active: Option<bool> = None;
        let mut last_dst_usable: Option<bool> = None;

        loop {
            let now = ctx
                .matter()
                .with_state(|state| state.rtc.utc_time())
                .reliable();

            let next = if let Some(now) = now {
                // ---- TimeZoneStatus: the active offset changed.
                let (tz_offset, tz_name) = store.active_time_zone(now);

                if last_tz != Some(tz_offset) {
                    if last_tz.is_some() {
                        let emitted = TimeZoneStatus::emit_for(&ctx, ROOT_ENDPOINT_ID, |event| {
                            event.offset(tz_offset)?.name(tz_name.as_deref())?.end()
                        });

                        if let Err(e) = emitted {
                            warn!("Failed to emit TimeZoneStatus: {:?}", e);
                        }
                    }

                    last_tz = Some(tz_offset);
                }

                // ---- DSTStatus: DST became active / inactive.
                let dst_active = store.active_dst_offset(now).is_some();

                if last_dst_active != Some(dst_active) {
                    if last_dst_active.is_some() || dst_active {
                        let emitted = DSTStatus::emit_for(&ctx, ROOT_ENDPOINT_ID, |event| {
                            event.dst_offset_active(dst_active)?.end()
                        });

                        if let Err(e) = emitted {
                            warn!("Failed to emit DSTStatus: {:?}", e);
                        }
                    }

                    last_dst_active = Some(dst_active);
                }

                // ---- DSTTableEmpty: the table just ran out of usable DST
                // information - cleared (e.g. by SetTimeZone) or every entry
                // expired. Edge-triggered on usable -> not-usable; see
                // `dst_usable`.
                let dst_usable = store.dst_usable(now);

                if last_dst_usable != Some(dst_usable) {
                    if !dst_usable && last_dst_usable == Some(true) {
                        let emitted =
                            DSTTableEmpty::emit_for(&ctx, ROOT_ENDPOINT_ID, |event| event.end());

                        if let Err(e) = emitted {
                            warn!("Failed to emit DSTTableEmpty: {:?}", e);
                        }
                    }

                    last_dst_usable = Some(dst_usable);
                }

                store.next_transition(now)
            } else {
                // No valid UTC time - nothing is "active"; wait for a change
                // (SetUTCTime wakes us via `note_changed`).
                None
            };

            // Sleep until the next scheduled boundary (with a small margin so
            // we evaluate just *after* it), or until the store changes.
            let boundary = async {
                match (next, now) {
                    (Some(at), Some(now)) => {
                        let delta_us = at.saturating_sub(now).saturating_add(100_000);

                        embassy_time::Timer::after(embassy_time::Duration::from_micros(delta_us))
                            .await
                    }
                    _ => core::future::pending().await,
                }
            };

            select(boundary, store.wait_changed()).await;
        }
    }

    fn utc_time(&self, ctx: impl ReadContext) -> Result<Nullable<u64>, Error> {
        Ok(Nullable::new(
            ctx.matter()
                .with_state(|state| state.rtc.utc_time())
                .reliable(),
        ))
    }

    fn granularity(&self, ctx: impl ReadContext) -> Result<GranularityEnum, Error> {
        Ok(ctx
            .matter()
            .with_state(|state| state.rtc.utc_time_granularity()))
    }

    fn time_source(&self, ctx: impl ReadContext) -> Result<TimeSourceEnum, Error> {
        Ok(ctx.matter().with_state(|state| state.rtc.utc_time_source()))
    }

    // ---- Feature-gated reads

    // Served directly from the Matter-wide TrustedTimeSource state
    // (Matter Core spec) — fabric-scoped storage lives on
    // `MatterState::rtc`, not on the user-supplied `TimeSync` provider.
    fn trusted_time_source<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: NullableBuilder<P, TrustedTimeSourceStructBuilder<P>>,
    ) -> Result<P, Error> {
        match ctx
            .matter()
            .with_state(|state| state.rtc.trusted_time_source())
        {
            Some(tts) => builder
                .non_null()?
                .fabric_index(tts.fab_idx.get())?
                .node_id(tts.node_id)?
                .endpoint(tts.endpoint)?
                .end(),
            None => builder.null(),
        }
    }

    fn default_ntp<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: NullableBuilder<P, Utf8StrBuilder<P>>,
    ) -> Result<P, Error> {
        match self
            .ntp_client
            .ok_or(ErrorCode::AttributeNotFound)?
            .default_ntp()?
            .into_option()
        {
            Some(s) => builder.non_null()?.set(s),
            None => builder.null(),
        }
    }

    fn supports_dns_resolve(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        self.ntp_client
            .ok_or(ErrorCode::AttributeNotFound)?
            .supports_dns_resolve()
    }

    fn ntp_server_available(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        self.ntp_server
            .ok_or(ErrorCode::AttributeNotFound)?
            .ntp_server_available()
    }

    fn time_zone<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<TimeZoneStructArrayBuilder<P>, TimeZoneStructBuilder<P>>,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(array) => {
                let mut array_opt = Some(array);
                self.time_zones
                    .ok_or(ErrorCode::AttributeNotFound)?
                    .time_zone(&mut |entry| {
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
                self.time_zones
                    .ok_or(ErrorCode::AttributeNotFound)?
                    .time_zone(&mut |entry| {
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
                self.time_zones
                    .ok_or(ErrorCode::AttributeNotFound)?
                    .dst_offset(&mut |entry| {
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
                self.time_zones
                    .ok_or(ErrorCode::AttributeNotFound)?
                    .dst_offset(&mut |entry| {
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

    fn local_time(&self, ctx: impl ReadContext) -> Result<Nullable<u64>, Error> {
        // Matter Core spec: `LocalTime = UTCTime + active-TimeZone.offset +
        // active-DSTOffset.offset`, Null whenever UTC time is unknown. Computed
        // here - like `UTCTime`/`Granularity`, which are also handler-owned -
        // because no provider can derive it without the RTC: the provider only
        // owns the *lists*.
        let Some(utc) = ctx
            .matter()
            .with_state(|state| state.rtc.utc_time())
            .reliable()
        else {
            return Ok(Nullable::none());
        };

        let mut offset_secs: i64 = 0;

        // Active time zone: the last entry whose `valid_at` has passed.
        self.time_zones
            .ok_or(ErrorCode::AttributeNotFound)?
            .time_zone(&mut |entry| {
                if entry.valid_at <= utc {
                    offset_secs = entry.offset as i64;
                }
                Ok(())
            })?;

        // The DST component is *required*, not additive-when-present: per the
        // Matter Core spec (via `TC_TIMESYNC_2_8` steps 11 and 20), `LocalTime`
        // is Null exactly when the DST table carries no usable information -
        // empty, or every entry expired. While the table is usable, the DST
        // contribution is the currently-active entry's offset, or zero
        // *between* windows (an expired entry followed by a future one).
        let mut usable = false;
        let mut active: Option<i32> = None;

        self.time_zones
            .ok_or(ErrorCode::AttributeNotFound)?
            .dst_offset(&mut |entry| {
                let unexpired = entry.valid_until.map(|u| utc < u).unwrap_or(true);

                if unexpired {
                    usable = true;

                    if entry.valid_starting <= utc {
                        active = Some(entry.offset);
                    }
                }

                Ok(())
            })?;

        if !usable {
            return Ok(Nullable::none());
        }

        offset_secs += active.unwrap_or(0) as i64;

        Ok(Nullable::some(utc.saturating_add_signed(
            offset_secs.saturating_mul(1_000_000),
        )))
    }

    fn time_zone_database(&self, _ctx: impl ReadContext) -> Result<TimeZoneDatabaseEnum, Error> {
        self.time_zones
            .ok_or(ErrorCode::AttributeNotFound)?
            .time_zone_database()
    }

    fn time_zone_list_max_size(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        self.time_zones
            .ok_or(ErrorCode::AttributeNotFound)?
            .time_zone_list_max_size()
    }

    fn dst_offset_list_max_size(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        self.time_zones
            .ok_or(ErrorCode::AttributeNotFound)?
            .dst_offset_list_max_size()
    }

    // ---- Commands

    fn handle_set_utc_time(
        &self,
        ctx: impl InvokeContext,
        request: SetUTCTimeRequest<'_>,
    ) -> Result<(), Error> {
        // Matter Core spec: regardless of the optional
        // `TimeSource` field in the request, the device SHALL set
        // `TimeSource` to `Admin` when `SetUTCTime` populates UTCTime.
        let utc_us = request.utc_time()?;
        let granularity = request.granularity()?;
        ctx.matter().with_state(|state| {
            state
                .rtc
                .set_utc_time(utc_us, granularity, TimeSourceEnum::Admin, &ctx)
        });

        // A (re)set clock changes which TimeZone/DSTOffset entries are
        // active - let the transition timer re-evaluate.
        if let Some(store) = self.tz_store {
            store.note_changed();
        }

        Ok(())
    }

    // Matter Core spec — installs or clears the per-device
    // Trusted Time Source. The fabric performing the change is
    // recorded so that fabric removal can clear an entry it owns
    // and emit `MissingTrustedTimeSource`.
    fn handle_set_trusted_time_source(
        &self,
        ctx: impl InvokeContext,
        request: SetTrustedTimeSourceRequest<'_>,
    ) -> Result<(), Error> {
        let fab_idx = NonZeroU8::new(ctx.cmd().fab_idx).ok_or(ErrorCode::InvalidCommand)?;

        let source = request
            .trusted_time_source()?
            .into_option()
            .map(|tts| {
                Ok::<_, Error>(TrustedTimeSource {
                    fab_idx,
                    node_id: tts.node_id()?,
                    endpoint: tts.endpoint()?,
                })
            })
            .transpose()?;

        let mut persist = Persist::new(ctx.kv());

        ctx.matter().with_state(|state| {
            state
                .rtc
                .set_trusted_time_source_persist(source, &mut persist, &ctx, &ctx)
        })?;

        persist.run()?;

        Ok(())
    }

    fn handle_set_time_zone<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: SetTimeZoneRequest<'_>,
        response: SetTimeZoneResponseBuilder<P>,
    ) -> Result<P, Error> {
        let dst_offset_required = self
            .time_zones
            .ok_or(ErrorCode::CommandNotFound)?
            .set_time_zone(&request)?;

        // An accepted SetTimeZone mutates the (nonVolatile) `TimeZone` list
        // and clears `DSTOffset`; persist and report both. The
        // TimeZoneStatus/DSTStatus/DSTTableEmpty *events* are emitted by the
        // transition timer in [`Self::run`], the single emission authority -
        // it was woken by the store on commit.
        if let Some(store) = self.tz_store {
            store.store_persist(ctx.kv())?;
        }

        ctx.notify_own_attr_changed(AttributeId::TimeZone as _);
        ctx.notify_own_attr_changed(AttributeId::DSTOffset as _);

        response.dst_offset_required(dst_offset_required)?.end()
    }

    fn handle_set_dst_offset(
        &self,
        ctx: impl InvokeContext,
        request: SetDSTOffsetRequest<'_>,
    ) -> Result<(), Error> {
        self.time_zones
            .ok_or(ErrorCode::CommandNotFound)?
            .set_dst_offset(&request)?;

        if let Some(store) = self.tz_store {
            store.store_persist(ctx.kv())?;
        }

        ctx.notify_own_attr_changed(AttributeId::DSTOffset as _);

        Ok(())
    }

    fn handle_set_default_ntp(
        &self,
        _ctx: impl InvokeContext,
        request: SetDefaultNTPRequest<'_>,
    ) -> Result<(), Error> {
        self.ntp_client
            .ok_or(ErrorCode::CommandNotFound)?
            .set_default_ntp(&request)
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
