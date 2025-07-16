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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Device.WifiP2P`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.WifiP2P",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait WifiP2P {
    /// StartFind method
    fn start_find(&self, options: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// StopFind method
    fn stop_find(&self) -> zbus::Result<()>;

    /// PeerAdded signal
    #[zbus(signal)]
    fn peer_added(&self, peer: ObjectPath<'_>) -> zbus::Result<()>;

    /// PeerRemoved signal
    #[zbus(signal)]
    fn peer_removed(&self, peer: ObjectPath<'_>) -> zbus::Result<()>;

    /// HwAddress property
    #[zbus(property)]
    fn hw_address(&self) -> zbus::Result<String>;

    /// Peers property
    #[zbus(property)]
    fn peers(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
}
