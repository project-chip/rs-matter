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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.AccessPoint`

use zbus::proxy;

#[proxy(
    interface = "org.freedesktop.NetworkManager.WifiP2PPeer",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait WifiP2PPeer {
    /// Name property
    #[zbus(property)]
    fn name(&self) -> zbus::Result<String>;

    /// Flags property
    #[zbus(property)]
    fn flags(&self) -> zbus::Result<u32>;

    /// Manufacturer property
    #[zbus(property)]
    fn manufacturer(&self) -> zbus::Result<String>;

    /// Model property
    #[zbus(property)]
    fn model(&self) -> zbus::Result<String>;

    /// ModelNumber property
    #[zbus(property)]
    fn model_number(&self) -> zbus::Result<String>;

    /// Serial property
    #[zbus(property)]
    fn serial(&self) -> zbus::Result<String>;

    /// WfdIEs property
    #[zbus(property)]
    fn wfd_ies(&self) -> zbus::Result<Vec<u8>>;

    /// HwAddress property
    #[zbus(property)]
    fn hw_address(&self) -> zbus::Result<String>;

    /// Strength property
    #[zbus(property)]
    fn strength(&self) -> zbus::Result<u8>;

    /// LastSeen property
    #[zbus(property)]
    fn last_seen(&self) -> zbus::Result<i32>;
}
