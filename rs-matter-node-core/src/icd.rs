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

//! What an Intermittently Connected Device (ICD) advertises about itself.

/// The operating mode of a Long-Idle-Time-capable ICD.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum IcdOperatingMode {
    /// Short Idle Time
    Sit,
    /// Long Idle Time
    Lit,
}

/// What an ICD advertises about itself, over DNS-SD and in the session
/// parameters of its CASE / PASE handshakes - and what its subscriptions are
/// paced by.
///
/// The ICD Management handler keeps `Matter` supplied with it
/// (see `Matter::icd_advertisement`); a node
/// that is not an ICD advertises none.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct IcdAdvertisement {
    /// The `ActiveModeThreshold`, in milliseconds: the advertised
    /// `SESSION_ACTIVE_THRESHOLD` (`SAT` TXT key).
    pub active_threshold_ms: u16,
    /// The slow polling interval in effect, in milliseconds: what the device is
    /// reachable within while idle, so the least `SESSION_IDLE_INTERVAL`
    /// (`SII` TXT key) it may advertise.
    pub slow_poll_ms: u32,
    /// The current operating mode of a Long-Idle-Time-capable ICD: the `ICD`
    /// TXT key (`0` for `SIT`, `1` for `LIT`). `None` for a SIT-only ICD, which
    /// has no `ICD` key.
    pub operating_mode: Option<IcdOperatingMode>,
    /// The idle mode duration, in seconds. Subscriptions to the device pick
    /// their max interval from it, so that their reports wake the device no
    /// more often than idle mode ends anyway.
    pub idle_mode_duration_s: u32,
}
