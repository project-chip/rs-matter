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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.VPN.Connection`

use zbus::proxy;

#[proxy(
    interface = "org.freedesktop.NetworkManager.VPN.Connection",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait VPNConnection {
    /// VpnStateChanged signal
    #[zbus(signal)]
    fn vpn_state_changed_signal(&self, state: u32, reason: u32) -> zbus::Result;

    /// VpnState property
    #[zbus(property)]
    fn vpn_state(&self) -> zbus::Result<u32>;

    /// Banner property
    #[zbus(property)]
    fn banner(&self) -> zbus::Result<String>;
}
