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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Device.IPTunnel`

use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.IPTunnel",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait IPTunnel {
    /// Mode property
    #[zbus(property)]
    fn mode(&self) -> zbus::Result<u32>;

    /// Parent property
    #[zbus(property)]
    fn parent(&self) -> zbus::Result<OwnedObjectPath>;

    /// Local property
    #[zbus(property)]
    fn local(&self) -> zbus::Result<String>;

    /// Remote property
    #[zbus(property)]
    fn remote(&self) -> zbus::Result<String>;

    /// Ttl property
    #[zbus(property)]
    fn ttl(&self) -> zbus::Result<u8>;

    /// Tos property
    #[zbus(property)]
    fn tos(&self) -> zbus::Result<u8>;

    /// PathMtuDiscovery property
    #[zbus(property)]
    fn path_mtu_discovery(&self) -> zbus::Result<bool>;

    /// InputKey property
    #[zbus(property)]
    fn input_key(&self) -> zbus::Result<String>;

    /// OutputKey property
    #[zbus(property)]
    fn output_key(&self) -> zbus::Result<String>;

    /// EncapsulationLimit property
    #[zbus(property)]
    fn encapsulation_limit(&self) -> zbus::Result<u8>;

    /// FlowLabel property
    #[zbus(property)]
    fn flow_label(&self) -> zbus::Result<u32>;

    /// FwMark property
    #[zbus(property)]
    fn fw_mark(&self) -> zbus::Result<u32>;

    /// Flags property
    #[zbus(property)]
    fn flags(&self) -> zbus::Result<u32>;
}
