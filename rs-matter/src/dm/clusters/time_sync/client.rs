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

//! Time Synchronization initiator-side client (Matter Core spec).
//!
//! Refreshes the device's
//! [Last-Known-Good UTC Time](crate::Matter::last_known_utc_time) by
//! opening a CASE-secured exchange to the configured
//! [Trusted Time Source](crate::Matter::trusted_time_source) (set via
//! the `SetTrustedTimeSource` command, Matter Core spec),
//! reading its `UTCTime` attribute, and calling
//! [`Matter::set_utc_time`] with the result. An update getting no time
//! emits the `TimeFailure` event, and one without a reachable source the
//! `MissingTrustedTimeSource` event, each at most once an hour.
//!
//! Drive it from your application's async runtime:
//!
//! ```ignore
//! let client = TimeSyncClient::new(&matter, &crypto);
//! let _ = client.run(
//!     embassy_time::Duration::from_secs(60 * 60),
//!     persist_access,
//!     &dm,
//! ).await;
//! ```

use core::cell::Cell;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Instant, Timer};

use crate::crypto::Crypto;
use crate::dm::clusters::decl::time_synchronization::{
    GranularityEnum, MissingTrustedTimeSource, TimeFailure, TimeSourceEnum,
    TimeSynchronizationAttrReads as _, TimeSynchronizationAttrResponses as _,
};
use crate::dm::endpoints::ROOT_ENDPOINT_ID;
use crate::dm::{AttrChangeNotifier, EventEmitter};
use crate::error::Error;
use crate::im::client::ImClient as _;
use crate::persist::{KvBlobStoreAccess, Persist};
use crate::transport::exchange::Exchange;
use crate::Matter;

/// How soon [`TimeSyncClient::run`] first retries a refresh getting no time;
/// each further retry waits twice as long.
pub const RETRY_MIN: Duration = Duration::from_secs(60);

/// How often a failing time update emits `TimeFailure` and
/// `MissingTrustedTimeSource`, at most.
const TIME_EVENTS_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Initiator-side TimeSync client. Periodically reads `UTCTime` from
/// the configured trusted source and stores it as the device's new
/// Last-Known-Good UTC Time (Matter Core spec).
///
/// Holds a borrow of the [`Matter`] instance for its lifetime; the
/// `run` / `refresh_once` methods take the KV-store handle and the
/// attribute-change notifier and event emitter (typically your
/// `InteractionModel`) by reference so the same client struct can be re-used
/// across refresh cycles.
pub struct TimeSyncClient<'a, C> {
    matter: &'a Matter<'a>,
    crypto: C,
    /// When a failed time update last emitted `TimeFailure`, and
    /// `MissingTrustedTimeSource`.
    time_failure_at: Cell<Option<Instant>>,
    missing_source_at: Cell<Option<Instant>>,
}

impl<'a, C: Crypto> TimeSyncClient<'a, C> {
    /// Create a new client bound to `matter`.
    ///
    /// `crypto` is needed because reading the trusted time source may require
    /// establishing a fresh CASE session (via [`Exchange::initiate`]) when none
    /// is cached.
    pub const fn new(matter: &'a Matter<'a>, crypto: C) -> Self {
        Self {
            matter,
            crypto,
            time_failure_at: Cell::new(None),
            missing_source_at: Cell::new(None),
        }
    }

    /// Run the refresh loop: refresh at once, then every `period` while it
    /// works. A refresh getting no time is retried after
    /// [`RETRY_MIN`], twice that the next time, and so on up to `period`.
    /// With no Trusted Time Source configured, it waits for one - no timer
    /// runs. Setting or changing it refreshes at once. Never returns under
    /// normal operation.
    pub async fn run<S, N>(&self, period: Duration, kv: S, notify: &N) -> Result<(), Error>
    where
        S: KvBlobStoreAccess,
        N: AttrChangeNotifier + EventEmitter,
    {
        let first_retry = RETRY_MIN.min(period);
        let mut retry = first_retry;

        loop {
            let mut wait = match self.attempt(&kv, notify).await {
                Ok(Refresh::Applied) => {
                    retry = first_retry;
                    Some(period)
                }
                Ok(Refresh::NoSource) => None,
                Ok(Refresh::NoTime) => Some(back_off(&mut retry, period)),
                Err(e) => {
                    warn!("TimeSync client: refresh failed: {}", e);
                    Some(back_off(&mut retry, period))
                }
            };

            // A new source starts the retries over. A cleared one is waited
            // out: clearing it emitted `MissingTrustedTimeSource` already.
            while !self.wait_due(wait).await {
                retry = first_retry;

                if self
                    .matter
                    .with_state(|state| state.rtc.trusted_time_source().is_some())
                {
                    break;
                }

                wait = None;
            }
        }
    }

    /// Wait for `wait` - forever if `None` - or until the Trusted Time
    /// Source changes; whether the wait was over.
    async fn wait_due(&self, wait: Option<Duration>) -> bool {
        let changed = self.matter.wait_trusted_time_source_changed();

        match wait {
            Some(wait) => matches!(select(Timer::after(wait), changed).await, Either::First(_)),
            None => {
                changed.await;
                false
            }
        }
    }

    /// Perform a single refresh cycle.
    ///
    /// - If no Trusted Time Source is configured, returns `Ok(())` having
    ///   got no time.
    /// - Otherwise opens a CASE-secured initiator exchange to the
    ///   configured `(fab_idx, node_id)`, reads the `UTCTime` and
    ///   `Granularity` attributes on the configured `endpoint`, and on a
    ///   non-null time from a source that has one calls
    ///   [`Matter::set_utc_time`] with the source's granularity (at most
    ///   milliseconds: the read itself takes a round trip) and
    ///   `TimeSource = NodeTimeCluster` (per spec — the source
    ///   that this device used to sync its time was another node's
    ///   TimeSync cluster). The RTC steps the granularity down by one:
    ///   minutes for a source within minutes or seconds, seconds for a finer one.
    ///
    /// Having got no time, it emits `TimeFailure`; with no source configured,
    /// or one that does not answer, also `MissingTrustedTimeSource`; each at
    /// most once an hour by this client, so reuse it across refreshes.
    pub async fn refresh_once<S, N>(&self, kv: S, notify: &N) -> Result<(), Error>
    where
        S: KvBlobStoreAccess,
        N: AttrChangeNotifier + EventEmitter,
    {
        self.attempt(kv, notify).await.map(|_| ())
    }

    /// [`Self::refresh_once`], answering what it got.
    async fn attempt<S, N>(&self, kv: S, notify: &N) -> Result<Refresh, Error>
    where
        S: KvBlobStoreAccess,
        N: AttrChangeNotifier + EventEmitter,
    {
        let refreshed = self.refresh(kv, notify).await;

        let (failed, no_source) = match &refreshed {
            Ok(Refresh::Applied) => (false, false),
            Ok(Refresh::NoTime) => (true, false),
            Ok(Refresh::NoSource) | Err(_) => (true, true),
        };
        // A missing diagnostic event must not fail the refresh.
        if no_source && hourly(&self.missing_source_at) {
            let emitted =
                MissingTrustedTimeSource::emit_for(notify, ROOT_ENDPOINT_ID, |event| event.end());
            if let Err(e) = emitted {
                warn!(
                    "TimeSync client: failed to emit MissingTrustedTimeSource: {}",
                    e
                );
            }
        }
        if failed && hourly(&self.time_failure_at) {
            if let Err(e) = TimeFailure::emit_for(notify, ROOT_ENDPOINT_ID, |event| event.end()) {
                warn!("TimeSync client: failed to emit TimeFailure: {}", e);
            }
        }

        refreshed
    }

    /// Get the time from the Trusted Time Source; an error if it could not
    /// be reached.
    async fn refresh<S, N>(&self, kv: S, notify: &N) -> Result<Refresh, Error>
    where
        S: KvBlobStoreAccess,
        N: AttrChangeNotifier,
    {
        let Some(tts) = self
            .matter
            .with_state(|state| state.rtc.trusted_time_source())
        else {
            return Ok(Refresh::NoSource);
        };

        info!(
            "TimeSync client: refreshing from fabric {}, node 0x{:016x}, endpoint {}",
            tts.fab_idx, tts.node_id, tts.endpoint
        );

        let exchange =
            Exchange::initiate(self.matter, &self.crypto, tts.fab_idx, tts.node_id).await?;

        let mut chunk = exchange
            .read_with(|msg| {
                msg.attr_requests()?
                    .time_synchronization_read()
                    .utc_time(tts.endpoint)?
                    .granularity(tts.endpoint)?
                    .end()?
                    .fabric_filtered(true)?
                    .end()
            })
            .await?;

        let (mut utc_time, mut granularity) = (None, None);

        loop {
            {
                let resp = chunk.response()?;
                let attrs = resp.time_synchronization_read_resp();

                if let Some((_, value)) = attrs.utc_time().next() {
                    utc_time = Some(value?.into_option());
                }
                if let Some((_, Ok(value))) = attrs.granularity().next() {
                    granularity = Some(value);
                };
            }

            match chunk.complete().await? {
                Some(next) => chunk = next,
                None => break,
            }
        }

        // Mandatory on the source; what we assumed of it without.
        let granularity = match granularity.unwrap_or(GranularityEnum::SecondsGranularity) {
            GranularityEnum::NoTimeGranularity => {
                warn!("TimeSync client: trusted source has no time");
                return Ok(Refresh::NoTime);
            }
            GranularityEnum::MicrosecondsGranularity => GranularityEnum::MillisecondsGranularity,
            granularity => granularity,
        };

        if let Some(utc_us) = utc_time.flatten() {
            let mut persist = Persist::new(kv);

            self.matter.with_state(|state| {
                state.rtc.set_utc_time_persist(
                    utc_us,
                    granularity,
                    TimeSourceEnum::NodeTimeCluster,
                    &mut persist,
                    notify,
                )
            })?;

            persist.run()?;

            info!(
                "TimeSync client: applied UTCTime = {} \u{00b5}s from trusted source",
                utc_us
            );

            Ok(Refresh::Applied)
        } else {
            warn!("TimeSync client: trusted source returned null UTCTime");

            Ok(Refresh::NoTime)
        }
    }
}

/// What a refresh got.
enum Refresh {
    /// The time, applied.
    Applied,
    /// No time: the source has none.
    NoTime,
    /// No time: no source is configured.
    NoSource,
}

/// Whether an event emitted at most hourly, last `at`, is due; notes it as
/// emitted now if so.
fn hourly(at: &Cell<Option<Instant>>) -> bool {
    let now = Instant::now();
    let due = at
        .get()
        .is_none_or(|at| now.duration_since(at) >= TIME_EVENTS_INTERVAL);
    if due {
        at.set(Some(now));
    }

    due
}

/// The wait before the next retry, `retry`; doubles `retry`, up to `period`.
fn back_off(retry: &mut Duration, period: Duration) -> Duration {
    let wait = *retry;
    *retry = (*retry * 2).min(period);

    wait
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use core::cell::Cell;

    use embassy_time::Duration;

    use super::{back_off, hourly, RETRY_MIN};

    #[test]
    fn time_failures_are_reported_hourly_at_most() {
        let at = Cell::new(None);

        assert!(hourly(&at));
        assert!(!hourly(&at));
    }

    #[test]
    fn retries_back_off_up_to_the_period() {
        let period = Duration::from_secs(10 * 60);
        let mut retry = RETRY_MIN;

        let waits: heapless::Vec<u64, 6> = (0..6)
            .map(|_| back_off(&mut retry, period).as_secs())
            .collect();
        assert_eq!(waits.as_slice(), [60, 120, 240, 480, 600, 600]);
    }
}
