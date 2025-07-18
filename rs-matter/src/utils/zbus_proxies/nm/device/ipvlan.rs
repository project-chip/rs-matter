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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Device.Ipvlan`

use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.Ipvlan",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Ipvlan {
    /// Parent property
    #[zbus(property)]
    fn parent(&self) -> zbus::Result<OwnedObjectPath>;

    /// Vepa property
    #[zbus(property)]
    fn vepa(&self) -> zbus::Result<bool>;

    /// Mode property
    #[zbus(property)]
    fn mode(&self) -> zbus::Result<String>;

    /// Private property
    #[zbus(property)]
    fn private(&self) -> zbus::Result<bool>;
}
