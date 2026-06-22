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
//! [`Matter::set_utc_time`] with the result.
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
    GranularityEnum, TimeSourceEnum, TimeSynchronizationClient as _,
};
use crate::dm::AttrChangeNotifier;
use crate::error::Error;
use crate::persist::{KvBlobStoreAccess, Persist};
use crate::transport::exchange::Exchange;
use crate::Matter;

/// Initiator-side TimeSync client. Periodically reads `UTCTime` from
/// the configured trusted source and stores it as the device's new
/// Last-Known-Good UTC Time (Matter Core spec).
///
/// Holds a borrow of the [`Matter`] instance for its lifetime; the
/// `run` / `refresh_once` methods take the KV-store handle and the
/// attribute-change notifier (typically your `InteractionModel`) by reference
/// so the same client struct can be re-used across refresh cycles.
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
        N: AttrChangeNotifier,
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
    /// - If no Trusted Time Source is configured, returns `Ok(())` with
    ///   no action.
    /// - Otherwise opens a CASE-secured initiator exchange to the
    ///   configured `(fab_idx, node_id)`, reads the `UTCTime` attribute
    ///   on the configured `endpoint`, and on a non-null result calls
    ///   [`Matter::set_utc_time`] with
    ///   `Granularity = SecondsGranularity` and
    ///   `TimeSource = NodeTimeCluster` (per spec — the source
    ///   that this device used to sync its time was another node's
    ///   TimeSync cluster).
    pub async fn refresh_once<S, N>(&self, kv: S, notify: &N) -> Result<(), Error>
    where
        S: KvBlobStoreAccess,
        N: AttrChangeNotifier,
    {
        let Some(tts) = self
            .matter
            .with_state(|state| state.rtc.trusted_time_source())
        else {
            // No trusted source configured — nothing to do.
            return Ok(());
        };

        info!(
            "TimeSync client: refreshing from fabric {}, node 0x{:016x}, endpoint {}",
            tts.fab_idx, tts.node_id, tts.endpoint
        );

        let exchange =
            Exchange::initiate(self.matter, &self.crypto, tts.fab_idx, tts.node_id).await?;

        let result = exchange
            .time_synchronization()
            .utc_time_read(tts.endpoint)
            .await?;

        if let Some(utc_us) = result.into_option() {
            let mut persist = Persist::new(kv);

            self.matter.with_rtc(|rtc| {
                rtc.set_utc_time_persist(
                    utc_us,
                    GranularityEnum::SecondsGranularity,
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
        } else {
            warn!("TimeSync client: trusted source returned null UTCTime");
        }

        Ok(())
    }
}
