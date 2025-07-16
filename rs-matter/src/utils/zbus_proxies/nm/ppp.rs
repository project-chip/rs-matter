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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.PPP`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::Value;

#[proxy(
    interface = "org.freedesktop.NetworkManager.PPP",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait PPP {
    /// NeedSecrets method
    fn need_secrets(&self) -> zbus::Result<(String, String)>;

    /// SetIpv4Config method
    fn set_ipv4_config(&self, config: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// SetIpv6Config method
    fn set_ipv6_config(&self, config: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// SetState method
    fn set_state(&self, state: u32) -> zbus::Result<()>;

    /// SetIfindex method
    fn set_ifindex(&self, ifindex: i32) -> zbus::Result<()>;
}
