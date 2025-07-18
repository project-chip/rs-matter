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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Device.Tun`

use zbus::proxy;

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.Tun",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Tun {
    /// Owner property
    #[zbus(property)]
    fn owner(&self) -> zbus::Result<i64>;

    /// Group
    #[zbus(property)]
    fn group(&self) -> zbus::Result<i64>;

    /// Mode property
    #[zbus(property)]
    fn mode(&self) -> zbus::Result<u32>;

    /// NoPi property
    #[zbus(property)]
    fn no_pi(&self) -> zbus::Result<bool>;

    /// VnetHdr property
    #[zbus(property)]
    fn vnet_hdr(&self) -> zbus::Result<bool>;

    /// MultiQueue property
    #[zbus(property)]
    fn multi_queue(&self) -> zbus::Result<bool>;

    /// HwAddress property
    #[zbus(property)]
    fn hw_address(&self) -> zbus::Result<String>;
}
