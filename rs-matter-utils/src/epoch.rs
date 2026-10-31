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

//! Wall-clock constants: Matter-epoch conversion, the cert
//! `NotAfter = no-expiration` sentinel, and the firmware build-time
//! seed emitted by `build.rs`.
//!
//! Every rs-matter consumer that needs calendar time (cert path
//! validation, the TimeSync cluster's mandatory `UTCTime` /
//! `Granularity` / `TimeSource` / `SetUTCTime`, the NOC attestation
//! timestamp, …) reads / writes the Last-Known-Good UTC Time on the
//! [`crate::Matter`] object via [`crate::Matter::last_known_utc_time`]
//! / [`crate::Matter::utc_time`] / [`crate::Matter::set_utc_time`].
//! That value is persisted (per Matter Core spec), seeded
//! from [`FIRMWARE_BUILD_MATTER_US`] on a freshly-flashed device, and
//! is the single source of truth — application code that has access
//! to a real-time clock or NTP samples should feed those into
//! [`crate::Matter::set_utc_time`] directly.

/// Seconds between the UNIX epoch (1970-01-01T00:00:00Z UTC) and the
/// Matter epoch (2000-01-01T00:00:00Z UTC). Add this constant to a
/// Matter-epoch value to get a UNIX-epoch value, or subtract it from
/// a UNIX-epoch value to get a Matter-epoch value.
pub const MATTER_EPOCH_SECS: u64 = 946_684_800;

/// Matter-epoch value used in cert `NotAfter` fields to mean "no
/// expiration" — corresponds to the X.509 `99991231235959Z`
/// generalized-time sentinel translated to Matter-epoch seconds.
///
/// `MATTER_CERT_DOESNT_EXPIRE = epoch(99991231235959Z) - MATTER_EPOCH_SECS`.
pub const MATTER_CERT_DOESNT_EXPIRE: u64 = 252_455_615_999;

// Pulls in `pub const FIRMWARE_BUILD_MATTER_US: u64 = …;` written by
// `build.rs`. Used by `MatterState::LkgUtc` as the seed value for the
// Last-Known-Good UTC Time on a freshly-flashed device.
include!(concat!(env!("OUT_DIR"), "/build_time.rs"));

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
