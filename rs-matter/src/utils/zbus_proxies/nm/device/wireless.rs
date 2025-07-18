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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Device.Wireless`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.Wireless",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Wireless {
    /// GetAccessPoints method
    fn get_access_points(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// GetAllAccessPoints method
    fn get_all_access_points(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// RequestScan method
    fn request_scan(&self, options: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// AccessPointAdded signal
    #[zbus(signal)]
    fn access_point_added(&self, access_point: ObjectPath<'_>) -> zbus::Result<()>;

    /// AccessPointRemoved signal
    #[zbus(signal)]
    fn access_point_removed(&self, access_point: ObjectPath<'_>) -> zbus::Result<()>;

    /// AccessPoints property
    #[zbus(property)]
    fn access_points(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// ActiveAccessPoint property
    #[zbus(property)]
    fn active_access_point(&self) -> zbus::Result<OwnedObjectPath>;

    /// Bitrate property
    #[zbus(property)]
    fn bitrate(&self) -> zbus::Result<u32>;

    /// HwAddress property
    #[zbus(property)]
    fn hw_address(&self) -> zbus::Result<String>;

    /// LastScan property
    #[zbus(property)]
    fn last_scan(&self) -> zbus::Result<i64>;

    /// Mode property
    #[zbus(property)]
    fn mode(&self) -> zbus::Result<u32>;

    /// PermHwAddress property
    #[zbus(property)]
    fn perm_hw_address(&self) -> zbus::Result<String>;

    /// WirelessCapabilities property
    #[zbus(property)]
    fn wireless_capabilities(&self) -> zbus::Result<u32>;
}
