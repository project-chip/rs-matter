/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

//! zbus proxies for BlueZ.
//!
//! All proxy traits are either:
//! - Generated using introspection (i.e. `zbus-xmlgen system zbus-xmlgen system org.bluez /org/bluez`)
//! - ... or by introspecting predefined introspection XML files from here: https://github.com/bluez-rs/bluez-async/tree/main/bluez-generated/specs
//! - ... or manually by consulting the BlueZ D-Bus interface definitions as documented here:
//!   https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc circa 2025-07-15
//! - ... or by running the `bluezapi2qt` tool from https://github.com/KDE/bluez-qt/tree/master/tools/bluezapi2qt on the ".txt" BlueZ API definitions
//!   as available in the BlueZ GIT repo from above until commit hash 85460c32d1334f5edad021d214eb997e6f462b30

pub mod adapter;
pub mod admin_policy_set;
pub mod agent;
pub mod agent_manager;
pub mod battery;
pub mod battery_provider_manager;
pub mod device;
pub mod gatt_characteristic;
pub mod gatt_descriptor;
pub mod gatt_manager;
pub mod gatt_profile;
pub mod gatt_service;
pub mod health_device;
pub mod health_manager;
pub mod le_advertisement;
pub mod le_advertising_manager;
pub mod media;
pub mod media_control;
pub mod network;
pub mod network_server;
pub mod profile_manager;
pub mod sim_access;
pub mod thermometer_manager;
pub mod thermometer_watcher;
