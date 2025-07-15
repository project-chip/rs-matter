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

//! zbus proxies for wpa-supplicant.
//!
//! All proxy traits are manually implemented based on the wpa-supplicant D-Bus interface definitions
//! as documented here: https://w1.fi/wpa_supplicant/devel/dbus.html circa 2025-07-15

pub mod bss;
pub mod group;
pub mod interface;
pub mod network;
pub mod p2pdevice;
pub mod peer;
pub mod persistent_group;
pub mod wpa_supplicant;
pub mod wps;
