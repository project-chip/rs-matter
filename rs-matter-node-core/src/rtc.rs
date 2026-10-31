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

//! The clock of the node: its Last-Known-Good UTC Time, the current UTC time
//! when it is known, and the Trusted Time Source.

use core::num::NonZeroU8;

use crate::dm::{
    AttrChangeNotifier, AttrId, ClusterId, EndptId, EventEmitter, EventId, NodeId, EVENT_DATA_TAG,
    ROOT_ENDPOINT_ID,
};
use crate::error::Error;
use crate::im::EventPriority;
use crate::persist::{
    KvBlobStore, KvBlobStoreAccess, Persist, LKG_UTC_KEY, TRUSTED_TIME_SOURCE_KEY,
};
use crate::tlv::{FromTLV, TLVWrite, ToTLV};
use crate::utils::epoch::{UtcTime, FIRMWARE_BUILD_MATTER_US};
use crate::utils::init::{init, Init};
use crate::utils::timers::Instant;

// The IDs of the Time Synchronization cluster, of the attributes the clock
// changes, and of its `MissingTrustedTimeSource` event
const TIME_SYNC_CLUSTER_ID: ClusterId = 0x0038;
const UTC_TIME_ATTR_ID: AttrId = 0x00;
const GRANULARITY_ATTR_ID: AttrId = 0x01;
const TIME_SOURCE_ATTR_ID: AttrId = 0x02;
const TRUSTED_TIME_SOURCE_ATTR_ID: AttrId = 0x03;
const MISSING_TRUSTED_TIME_SOURCE_EVENT_ID: EventId = 0x04;

/// The granularity of the current UTC time.
///
/// The variants are the ones of the Time Synchronization cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TimeGranularity {
    NoTime,
    Minutes,
    Seconds,
    Milliseconds,
    Microseconds,
}

/// The source of the current UTC time.
///
/// The variants are the ones of the Time Synchronization cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TimeSource {
    None,
    Unknown,
    Admin,
    NodeTimeCluster,
    NonMatterSNTP,
    NonMatterNTP,
    MatterSNTP,
    MatterNTP,
    MixedNTP,
    NonMatterSNTPNTS,
    NonMatterNTPNTS,
    MatterSNTPNTS,
    MatterNTPNTS,
    MixedNTPNTS,
    CloudSource,
    PTP,
    GNSS,
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
/// recent `set_utc_time` call. After reboot, `anchor` is
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
    granularity: TimeGranularity,
    /// Authority that last called `set_utc_time`. **Not persisted** —
    /// resets to `None` at boot.
    source: TimeSource,
    /// `Instant::now()` captured at the last `set_utc_time` call.
    /// Volatile — `None` after reboot until next set.
    anchor: Option<Instant>,
    /// Configured Trusted Time Source for the device (Matter Core spec).
    /// At most one entry; the fabric that
    /// installed it owns it and is cleared on fabric removal.
    /// Persisted under [`crate::persist::TRUSTED_TIME_SOURCE_KEY`].
    trusted_time_source: Option<TrustedTimeSource>,
}

impl Default for Rtc {
    fn default() -> Self {
        Self::new()
    }
}

impl Rtc {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            utc_us: FIRMWARE_BUILD_MATTER_US,
            utc_us_persisted: FIRMWARE_BUILD_MATTER_US,
            granularity: TimeGranularity::NoTime,
            source: TimeSource::None,
            anchor: None,
            trusted_time_source: None,
        }
    }

    /// Return an in-place initializer for `LkgUtc`.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            utc_us: FIRMWARE_BUILD_MATTER_US,
            utc_us_persisted: FIRMWARE_BUILD_MATTER_US,
            granularity: TimeGranularity::NoTime,
            source: TimeSource::None,
            anchor: None,
            trusted_time_source: None,
        })
    }

    fn reset(&mut self) {
        self.utc_us = FIRMWARE_BUILD_MATTER_US;
        self.utc_us_persisted = FIRMWARE_BUILD_MATTER_US;
        self.granularity = TimeGranularity::NoTime;
        self.source = TimeSource::None;
        self.anchor = None;
        self.trusted_time_source = None;
    }

    /// Reset the clock and remove what is persisted for it from `store`
    pub fn reset_persist<S: KvBlobStore>(
        &mut self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.reset();

        let result = store.remove(LKG_UTC_KEY, buf);

        result.and(store.remove(TRUSTED_TIME_SOURCE_KEY, buf))
    }

    /// Load the Last-Known-Good UTC Time and the Trusted Time Source from `kv`
    pub fn load_persist<S: KvBlobStoreAccess>(&mut self, kv: S) -> Result<(), Error> {
        self.reset();

        let mut persist = Persist::new(kv);

        // Load the persisted Last-Known-Good UTC Time, if any.
        // Floor at `FIRMWARE_BUILD_MATTER_US` per Matter Core spec -
        // the on-disk value must never regress us
        // below the build timestamp (the documented lower bound
        // we never adjust backwards past).
        if let Some(stored) = persist.load_tlv::<u64>(LKG_UTC_KEY)? {
            let floor = FIRMWARE_BUILD_MATTER_US;

            self.utc_us_persisted = stored;
            self.utc_us = stored.max(floor);
        }

        // Load the persisted Trusted Time Source, if any.
        self.trusted_time_source = persist.load_tlv(TRUSTED_TIME_SOURCE_KEY)?;

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
                TIME_SYNC_CLUSTER_ID,
                TRUSTED_TIME_SOURCE_ATTR_ID,
            );

            // Matter Core spec: emit `MissingTrustedTimeSource`
            // when SetTrustedTimeSource clears a previously-set entry (null
            // request payload, transitioning from `Some(..)` → `None`).
            if self.trusted_time_source.is_none() && previous.is_some() {
                // The event has no fields
                event_emitter.emit_event(
                    ROOT_ENDPOINT_ID,
                    TIME_SYNC_CLUSTER_ID,
                    MISSING_TRUSTED_TIME_SOURCE_EVENT_ID,
                    EventPriority::Info,
                    |mut tw| {
                        tw.start_struct(&EVENT_DATA_TAG)?;
                        tw.end_container()
                    },
                )?;
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
            let elapsed_us = Instant::now()
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
    pub fn utc_time_granularity(&self) -> TimeGranularity {
        if self.anchor.is_some() {
            self.granularity
        } else {
            TimeGranularity::NoTime
        }
    }

    /// Return the TimeSource reported on the wire for the TimeSync
    /// cluster's `TimeSource` attribute — `None` until the first
    /// [`Self::set_utc_time`] (per spec).
    pub fn utc_time_source(&self) -> TimeSource {
        if self.anchor.is_some() {
            self.source
        } else {
            TimeSource::None
        }
    }

    /// Update the Last-Known-Good UTC Time (Matter Core spec),
    /// capturing a fresh monotonic anchor so subsequent
    /// [`Self::utc_time`] reads advance from the supplied value.
    ///
    /// Per the spec: the supplied `granularity` is recorded
    /// stepped-down by one level (with a floor of
    /// `Minutes` per spec); the supplied `source`
    /// is recorded verbatim.
    ///
    /// The new value is written to the in-memory state only. Callers that
    /// need it persisted to `LKG_UTC_KEY` use [`Self::set_utc_time_persist`].
    pub fn set_utc_time(
        &mut self,
        utc_us: u64,
        granularity: TimeGranularity,
        source: TimeSource,
        change_notifier: &dyn AttrChangeNotifier,
    ) -> bool {
        let stepped = match granularity {
            TimeGranularity::Microseconds => TimeGranularity::Milliseconds,
            TimeGranularity::Milliseconds => TimeGranularity::Seconds,
            TimeGranularity::Seconds => TimeGranularity::Minutes,
            // Minutes / NoTime → floor at Minutes
            // (spec forbids NoTime while UTCTime is non-null).
            _ => TimeGranularity::Minutes,
        };

        let changed = self.utc_us != utc_us || self.granularity != stepped || self.source != source;

        if changed || self.anchor.is_none() {
            self.utc_us = utc_us;
            self.granularity = stepped;
            self.source = source;
            self.anchor = Some(Instant::now());

            change_notifier.notify_attr_changed(
                ROOT_ENDPOINT_ID,
                TIME_SYNC_CLUSTER_ID,
                UTC_TIME_ATTR_ID,
            );
            change_notifier.notify_attr_changed(
                ROOT_ENDPOINT_ID,
                TIME_SYNC_CLUSTER_ID,
                GRANULARITY_ATTR_ID,
            );
            change_notifier.notify_attr_changed(
                ROOT_ENDPOINT_ID,
                TIME_SYNC_CLUSTER_ID,
                TIME_SOURCE_ATTR_ID,
            );
        }

        changed
    }

    /// Like [`Self::set_utc_time`], and persist the new Last-Known-Good UTC
    /// Time when it moved by a day or more since it was last persisted
    pub fn set_utc_time_persist<S: KvBlobStoreAccess>(
        &mut self,
        utc_us: u64,
        granularity: TimeGranularity,
        source: TimeSource,
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

            persist.store_tlv(LKG_UTC_KEY, utc_us)?;
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::persist::{MemKv, MemKvBlobStore};

    use super::*;

    #[test]
    fn persisted_utc_time_loads_back() {
        let kv = MemKv::new(MemKvBlobStore::default());
        let utc_us = FIRMWARE_BUILD_MATTER_US + 7 * 24 * 60 * 60 * 1_000_000;

        let mut rtc = Rtc::new();
        rtc.set_utc_time_persist(
            utc_us,
            TimeGranularity::Seconds,
            TimeSource::Admin,
            &mut Persist::new(&kv),
            &(),
        )
        .unwrap();

        let mut rtc = Rtc::new();
        rtc.load_persist(&kv).unwrap();

        assert_eq!(rtc.utc_time(), UtcTime::LastKnown(utc_us));
    }
}
