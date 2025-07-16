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

//! zbus proxies for NetworkManager.
//!
//! All proxy traits are either generated using introspection (i.e. `zbus-xmlgen system org.freedesktop.NetworkManager /org/freedesktop/NetworkManager`)
//! or manually by consulting the NetworkManager D-Bus interface definitions
//! as documented here: https://networkmanager.dev/docs/api/latest/spec.html circa 2025-07-15

pub mod access_point;
pub mod active;
pub mod agent_manager;
pub mod checkpoint;
pub mod connection;
pub mod device;
pub mod dhcp4config;
pub mod dhcp6config;
pub mod dns_manager;
pub mod ip4config;
pub mod ip6config;
pub mod network_manager;
pub mod ppp;
pub mod settings;
pub mod vpn_connection;
pub mod wifi_p2ppeer;
