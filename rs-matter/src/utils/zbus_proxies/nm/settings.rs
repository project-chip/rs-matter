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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Settings`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

#[proxy(
    interface = "org.freedesktop.NetworkManager.Settings",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager/Settings"
)]
pub trait Settings {
    /// AddConnection method
    fn add_connection(
        &self,
        connection: HashMap<&str, HashMap<&str, &Value<'_>>>,
    ) -> zbus::Result<OwnedObjectPath>;

    /// AddConnection2 method
    fn add_connection2(
        &self,
        settings: HashMap<&str, HashMap<&str, &Value<'_>>>,
        flags: u32,
        args: HashMap<&str, &Value<'_>>,
    ) -> zbus::Result<(OwnedObjectPath, HashMap<String, OwnedValue>)>;

    /// AddConnectionUnsaved method
    fn add_connection_unsaved(
        &self,
        connection: HashMap<&str, HashMap<&str, &Value<'_>>>,
    ) -> zbus::Result<OwnedObjectPath>;

    /// GetConnectionByUuid method
    fn get_connection_by_uuid(&self, uuid: &str) -> zbus::Result<OwnedObjectPath>;

    /// ListConnections method
    fn list_connections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// LoadConnections method
    fn load_connections(&self, filenames: &[&str]) -> zbus::Result<(bool, Vec<String>)>;

    /// ReloadConnections method
    fn reload_connections(&self) -> zbus::Result<bool>;

    /// SaveHostname method
    fn save_hostname(&self, hostname: &str) -> zbus::Result<()>;

    /// ConnectionRemoved signal
    #[zbus(signal)]
    fn connection_removed(&self, connection: ObjectPath<'_>) -> zbus::Result<()>;

    /// NewConnection signal
    #[zbus(signal)]
    fn new_connection(&self, connection: ObjectPath<'_>) -> zbus::Result<()>;

    /// CanModify property
    #[zbus(property)]
    fn can_modify(&self) -> zbus::Result<bool>;

    /// Connections property
    #[zbus(property)]
    fn connections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Hostname property
    #[zbus(property)]
    fn hostname(&self) -> zbus::Result<String>;
}
