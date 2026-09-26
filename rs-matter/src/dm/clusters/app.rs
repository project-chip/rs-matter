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

//! Application-level cluster handlers (i.e. clusters not used by the
//! `rs-matter` core itself).
//!
//! This currently includes:
//! - `OnOff` and `LevelControl` — for demoing purposes.
//! - `Thermostat` — a heating-only implementation of the HVAC cluster.
//! - `FanControl` — the fan speed cluster, with all six of its features.
//! - `PowerTopology`, `ElectricalPowerMeasurement` and
//!   `ElectricalEnergyMeasurement` — the Electrical Sensor trio, reporting
//!   what a device's equipment draws now and has drawn over time.
//! - The Matter 1.5 camera / streaming clusters
//!   (`CameraAvStreamManagement`, `CameraAvSettingsUserLevelManagement`,
//!   `WebRTCTransportProvider`, `WebRTCTransportRequestor`,
//!   `PushAvStreamTransport`, `Chime`, `ZoneManagement`) — currently
//!   exposed as thin re-export modules over the IDL-generated scaffolding;
//!   spec-aware handlers are planned but not yet implemented.

pub mod cam_av_settings;
pub mod cam_av_stream;
pub mod chime;
pub mod color_control;
pub(crate) mod deferred_persist;
pub mod elec_energy_meas;
pub mod elec_pwr_meas;
pub mod fan_control;
pub mod level_control;
pub mod measurement;
pub mod on_off;
pub mod power_topology;
pub mod push_av_stream;
#[cfg(test)]
pub mod test_util;
pub mod thermostat;
pub mod webrtc_prov;
pub mod webrtc_req;
pub mod zone_mgmt;
