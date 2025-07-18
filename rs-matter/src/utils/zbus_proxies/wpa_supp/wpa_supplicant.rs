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

//! # D-Bus interface proxy for: `fi.w1.wpa_supplicant1`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};

#[proxy(
    interface = "fi.w1.wpa_supplicant1",
    default_service = "fi.w1.wpa_supplicant1",
    default_path = "/fi/w1/wpa_supplicant1"
)]
pub trait WPASupplicant {
    /// CreateInterface method
    fn create_interface(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<OwnedObjectPath>;

    /// ExpectDisconnect method
    fn expect_disconnect(&self) -> zbus::Result<()>;

    /// GetInterface method
    fn get_interface(&self, ifname: &str) -> zbus::Result<OwnedObjectPath>;

    /// RemoveInterface method
    fn remove_interface(&self, path: &ObjectPath<'_>) -> zbus::Result<()>;

    /// InterfaceAdded signal
    #[zbus(signal)]
    fn interface_added(
        &self,
        path: ObjectPath<'_>,
        properties: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;

    /// InterfaceRemoved signal
    #[zbus(signal)]
    fn interface_removed(&self, path: ObjectPath<'_>) -> zbus::Result<()>;

    /// PropertiesChanged signal
    #[zbus(signal)]
    fn properties_changed(&self, properties: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// Capabilities property
    #[zbus(property)]
    fn capabilities(&self) -> zbus::Result<Vec<String>>;

    /// DebugLevel property
    #[zbus(property)]
    fn debug_level(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_debug_level(&self, value: &str) -> zbus::Result<()>;

    /// DebugShowKeys property
    #[zbus(property)]
    fn debug_show_keys(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_debug_show_keys(&self, value: bool) -> zbus::Result<()>;

    /// DebugTimestamp property
    #[zbus(property)]
    fn debug_timestamp(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_debug_timestamp(&self, value: bool) -> zbus::Result<()>;

    /// EapMethods property
    #[zbus(property)]
    fn eap_methods(&self) -> zbus::Result<Vec<String>>;

    /// Interfaces property
    #[zbus(property)]
    fn interfaces(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// WFDIEs property
    #[zbus(property, name = "WFDIEs")]
    fn wfdies(&self) -> zbus::Result<Vec<u8>>;
    #[zbus(property, name = "WFDIEs")]
    fn set_wfdies(&self, value: &[u8]) -> zbus::Result<()>;
}
