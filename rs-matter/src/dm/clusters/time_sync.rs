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

use crate::dm::endpoints::ROOT_ENDPOINT_ID;
use crate::dm::{
    ArrayAttributeRead, AttrChangeNotifier, Attribute, Cluster, Command, Dataver, EndptId,
    EventEmitter, InvokeContext, NodeId, Quality, ReadContext,
};
use crate::error::{Error, ErrorCode};
use crate::persist::{
    KvBlobStore, KvBlobStoreAccess, Persist, LKG_UTC_KEY, TRUSTED_TIME_SOURCE_KEY,
};
use crate::tlv::{
    FromTLV, Nullable, NullableBuilder, TLVBuilderParent, TLVElement, ToTLV, Utf8StrBuilder,
};
use crate::utils::epoch::FIRMWARE_BUILD_MATTER_US;
use crate::utils::init::{init, Init};

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

    pub fn reset_persist<S: KvBlobStore>(
        &mut self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.reset();

        store.remove(LKG_UTC_KEY, buf)?;
        store.remove(TRUSTED_TIME_SOURCE_KEY, buf)?;
        Ok(())
    }

    pub fn load_persist<S: KvBlobStore>(&mut self, mut kv: S, buf: &mut [u8]) -> Result<(), Error> {
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
    pub fn set_trusted_time_source_persist<S: KvBlobStoreAccess, E: EventEmitter>(
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

    pub fn set_utc_time_persist<S: KvBlobStoreAccess>(
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

/// Pluggable data source for the feature-gated members of the Time
/// Synchronization cluster (`TIME_ZONE` / `NTP_CLIENT` / `NTP_SERVER`
/// / `TIME_SYNC_CLIENT`).
///
/// The mandatory members — `UTCTime`, `Granularity`, `TimeSource`,
/// and the `SetUTCTime` command — are handled by [`TimeSyncHandler`] directly
/// against the built-in Matter RTC state and do **not** appear on this trait.
///
/// The `TIME_SYNC_CLIENT` feature (if enabled) is also handled by the handler
/// directly against the `TrustedTimeSource` entry in the built-in Matter RTC state,
/// so it also doesn't appear here.
pub trait TimeSync {
    // ---- NTP_CLIENT feature

    /// Hostname or IP address of the default NTP server, or `Null` if
    /// none is configured.
    fn default_ntp(&self) -> Result<Nullable<&str>, Error>;

    /// Whether the device's NTP-client resolver supports DNS names
    /// (vs. only literal IP addresses).
    fn supports_dns_resolve(&self) -> Result<bool, Error>;

    // ---- NTP_SERVER feature

    /// Whether the device is currently serving NTP queries.
    fn ntp_server_available(&self) -> Result<bool, Error>;

    // ---- TIME_ZONE feature

    /// Stream the active time-zone entries into `visit`.
    fn time_zone(
        &self,
        _visit: &mut dyn FnMut(&TimeZoneEntry<'_>) -> Result<(), Error>,
    ) -> Result<(), Error>;

    /// Stream the active DST-offset entries into `visit`.
    fn dst_offset(
        &self,
        _visit: &mut dyn FnMut(&DSTOffsetEntry) -> Result<(), Error>,
    ) -> Result<(), Error>;

    /// Current local time in Matter-epoch microseconds, or `Null`.
    fn local_time(&self) -> Result<Nullable<u64>, Error>;

    /// How complete the device's IANA time-zone database is.
    fn time_zone_database(&self) -> Result<TimeZoneDatabaseEnum, Error>;

    /// Maximum length of the `TimeZone` list this device accepts.
    fn time_zone_list_max_size(&self) -> Result<u8, Error>;

    /// Maximum length of the `DSTOffset` list this device accepts.
    fn dst_offset_list_max_size(&self) -> Result<u8, Error>;

    // ---- Commands (feature-gated; default to `CommandNotFound`)

    /// Handle `SetTimeZone` — gated by `TIME_ZONE`. Returns the
    /// `DSTOffsetRequired` field for the response.
    fn set_time_zone(&self, _request: &SetTimeZoneRequest<'_>) -> Result<bool, Error>;

    /// Handle `SetDSTOffset` — gated by `TIME_ZONE`.
    fn set_dst_offset(&self, _request: &SetDSTOffsetRequest<'_>) -> Result<(), Error>;

    /// Handle `SetDefaultNTP` — gated by `NTP_CLIENT`.
    fn set_default_ntp(&self, _request: &SetDefaultNTPRequest<'_>) -> Result<(), Error>;
}

impl<T> TimeSync for &T
where
    T: TimeSync,
{
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

/// Default [`TimeSync`] implementation.
///
/// Suitable for devices that don't advertise the features
/// `TIME_ZONE` / `NTP_CLIENT` / `NTP_SERVER`.
impl TimeSync for () {
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

    // ---- Always-on reads (served from Matter-wide LKG state, not
    // from the user-supplied `TimeSync` provider).

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
