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

//! # D-Bus interface proxy for: `fi.w1.wpa_supplicant1.Interface.Group`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};

#[proxy(
    interface = "fi.w1.wpa_supplicant1.Group",
    default_service = "fi.w1.wpa_supplicant1"
)]
pub trait Group {
    /// PropertiesChanged signal
    #[zbus(signal)]
    fn properties_changed(&self, properties: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// Members property
    #[zbus(property)]
    fn members(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Group property
    #[zbus(property)]
    fn group(&self) -> zbus::Result<OwnedObjectPath>;

    /// Role property
    #[zbus(property)]
    fn role(&self) -> zbus::Result<String>;

    /// SSID property
    #[zbus(property, name = "SSID")]
    fn ssid(&self) -> zbus::Result<Vec<u8>>;

    /// BSSID property
    #[zbus(property, name = "BSSID")]
    fn bssid(&self) -> zbus::Result<Vec<u8>>;

    /// Frequency property
    #[zbus(property)]
    fn frequency(&self) -> zbus::Result<u16>;

    /// Passphrase property
    #[zbus(property)]
    fn passphrase(&self) -> zbus::Result<String>;

    /// PSK property
    #[zbus(property)]
    fn psk(&self) -> zbus::Result<Vec<u8>>;

    /// WPSVendorExtensions property
    #[zbus(property, name = "WPSVendorExtensions")]
    fn wps_vendor_extensions(&self) -> zbus::Result<Vec<Vec<u8>>>;

    /// PeerJoined signal
    #[zbus(signal)]
    fn peer_joined(
        &self,
        path: ObjectPath<'_>,
        properties: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;

    /// PeerDisconnected signal
    #[zbus(signal)]
    fn peer_disconnected(
        &self,
        path: ObjectPath<'_>,
        properties: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;
}
