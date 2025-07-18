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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Device.Vxlan`

use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.Vxlan",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Vxlan {
    /// HwAddress property
    #[zbus(property)]
    fn hw_address(&self) -> zbus::Result<String>;

    /// Parent property
    #[zbus(property)]
    fn parent(&self) -> zbus::Result<OwnedObjectPath>;

    /// Id property
    #[zbus(property)]
    fn id(&self) -> zbus::Result<u32>;

    /// Group property
    #[zbus(property)]
    fn group(&self) -> zbus::Result<String>;

    /// Local property
    #[zbus(property)]
    fn local(&self) -> zbus::Result<String>;

    /// Tos property
    #[zbus(property)]
    fn tos(&self) -> zbus::Result<u8>;

    /// Ttl property
    #[zbus(property)]
    fn ttl(&self) -> zbus::Result<u8>;

    /// Learning property
    #[zbus(property)]
    fn learning(&self) -> zbus::Result<bool>;

    /// Ageing property
    #[zbus(property)]
    fn ageing(&self) -> zbus::Result<u32>;

    /// Limit property
    #[zbus(property)]
    fn limit(&self) -> zbus::Result<u32>;

    /// DstPort property
    #[zbus(property)]
    fn dst_port(&self) -> zbus::Result<u16>;

    /// SrcPortMin property
    #[zbus(property)]
    fn src_port_min(&self) -> zbus::Result<u16>;

    /// SrcPortMax property
    #[zbus(property)]
    fn src_port_max(&self) -> zbus::Result<u16>;

    /// Proxy property
    #[zbus(property)]
    fn proxy(&self) -> zbus::Result<bool>;

    /// Rsc property
    #[zbus(property)]
    fn rsc(&self) -> zbus::Result<bool>;

    /// L2miss property
    #[zbus(property)]
    fn l2miss(&self) -> zbus::Result<bool>;

    /// L3miss property
    #[zbus(property)]
    fn l3miss(&self) -> zbus::Result<bool>;
}
