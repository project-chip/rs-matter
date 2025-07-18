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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Device.Hsr`

use zbus::{proxy, zvariant::OwnedObjectPath};

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.Hsr",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Hsr {
    /// SupervisionAddress property
    #[zbus(property)]
    fn supervision_address(&self) -> zbus::Result<String>;

    /// Port1 property
    #[zbus(property)]
    fn port1(&self) -> zbus::Result<OwnedObjectPath>;

    /// Port2 property
    #[zbus(property)]
    fn port2(&self) -> zbus::Result<OwnedObjectPath>;

    /// MulticastSpec property
    #[zbus(property)]
    fn multicast_spec(&self) -> zbus::Result<u8>;

    /// Prp property
    #[zbus(property)]
    fn prp(&self) -> zbus::Result<bool>;
}
