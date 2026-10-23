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

use embassy_time::{Duration, Timer};

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
}

impl<'a, C: Crypto> TimeSyncClient<'a, C> {
    /// Create a new client bound to `matter`.
    ///
    /// `crypto` is needed because reading the trusted time source may require
    /// establishing a fresh CASE session (via [`Exchange::initiate`]) when none
    /// is cached.
    pub const fn new(matter: &'a Matter<'a>, crypto: C) -> Self {
        Self { matter, crypto }
    }

    /// Run the periodic refresh loop. Calls
    /// [`Self::refresh_once`] every `period`; logs and continues on
    /// any per-cycle error so a single bad exchange doesn't take the
    /// task down. Never returns under normal operation.
    pub async fn run<S, N>(&self, period: Duration, kv: S, notify: &N) -> Result<(), Error>
    where
        S: KvBlobStoreAccess,
        N: AttrChangeNotifier + EventEmitter,
    {
        loop {
            let period = if let Err(e) = self.refresh_once(&kv, notify).await {
                warn!("TimeSync client: refresh failed: {}", e);

                // On error, retry sooner than the normal period to avoid
                // long outages if the trusted source is temporarily
                // unavailable.
                Duration::from_secs(60).min(period)
            } else {
                period
            };

            Timer::after(period).await;
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
    /// most once an hour.
    pub async fn refresh_once<S, N>(&self, kv: S, notify: &N) -> Result<(), Error>
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
        if no_source
            && self
                .matter
                .with_state(|state| state.rtc.missing_source_due())
        {
            MissingTrustedTimeSource::emit_for(notify, ROOT_ENDPOINT_ID, |event| event.end())?;
        }
        if failed && self.matter.with_state(|state| state.rtc.time_failure_due()) {
            TimeFailure::emit_for(notify, ROOT_ENDPOINT_ID, |event| event.end())?;
        }

        refreshed.map(|_| ())
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
