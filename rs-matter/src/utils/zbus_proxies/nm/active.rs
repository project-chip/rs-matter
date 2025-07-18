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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Connection.Active`

use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;

#[proxy(
    interface = "org.freedesktop.NetworkManager.Connection.Active",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Active {
    /// StateChanged signal
    #[zbus(signal, name = "StateChanged")]
    fn act_state_changed_signal(&self, state: u32, reason: u32) -> zbus::Result<()>;

    /// Connection property
    #[zbus(property)]
    fn connection(&self) -> zbus::Result<OwnedObjectPath>;

    /// Controller property
    #[zbus(property)]
    fn controller(&self) -> zbus::Result<OwnedObjectPath>;

    /// Default property
    #[zbus(property)]
    fn default(&self) -> zbus::Result<bool>;

    /// Default6 property
    #[zbus(property)]
    fn default6(&self) -> zbus::Result<bool>;

    /// Devices property
    #[zbus(property)]
    fn devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Dhcp4Config property
    #[zbus(property)]
    fn dhcp4_config(&self) -> zbus::Result<OwnedObjectPath>;

    /// Dhcp6Config property
    #[zbus(property)]
    fn dhcp6_config(&self) -> zbus::Result<OwnedObjectPath>;

    /// Id property
    #[zbus(property)]
    fn id(&self) -> zbus::Result<String>;

    /// Ip4Config property
    #[zbus(property)]
    fn ip4_config(&self) -> zbus::Result<OwnedObjectPath>;

    /// Ip6Config property
    #[zbus(property)]
    fn ip6_config(&self) -> zbus::Result<OwnedObjectPath>;

    /// Master property
    #[zbus(property)]
    fn master(&self) -> zbus::Result<OwnedObjectPath>;

    /// SpecificObject property
    #[zbus(property)]
    fn specific_object(&self) -> zbus::Result<OwnedObjectPath>;

    /// State property
    #[zbus(property, name = "State")]
    fn act_state(&self) -> zbus::Result<u32>;

    /// StateFlags property
    #[zbus(property)]
    fn state_flags(&self) -> zbus::Result<u32>;

    /// Type property
    #[zbus(property)]
    fn type_(&self) -> zbus::Result<String>;

    /// Uuid property
    #[zbus(property)]
    fn uuid(&self) -> zbus::Result<String>;

    /// Vpn property
    #[zbus(property)]
    fn vpn(&self) -> zbus::Result<bool>;
}
