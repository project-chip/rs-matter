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

//! # D-Bus interface proxy for: `fi.w1.wpa_supplicant1.Interface.BSS`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{OwnedValue, Value};

#[proxy(
    interface = "fi.w1.wpa_supplicant1.Interface.BSS",
    assume_defaults = true
)]
pub trait BSS {
    /// PropertiesChanged signal
    #[zbus(signal)]
    fn properties_changed(&self, properties: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// BSSID property
    #[zbus(property)]
    fn bssid(&self) -> zbus::Result<Vec<u8>>;

    /// SSID property
    #[zbus(property)]
    fn ssid(&self) -> zbus::Result<Vec<u8>>;

    /// WPA property
    #[zbus(property)]
    fn wpa(&self) -> zbus::Result<HashMap<String, OwnedValue>>;

    /// RSN property
    #[zbus(property)]
    fn rsn(&self) -> zbus::Result<HashMap<String, OwnedValue>>;

    /// WPS property
    #[zbus(property)]
    fn wps(&self) -> zbus::Result<HashMap<String, OwnedValue>>;

    /// IEs property
    #[zbus(property)]
    fn ies(&self) -> zbus::Result<Vec<u8>>;

    /// Privacy property
    #[zbus(property)]
    fn privacy(&self) -> zbus::Result<bool>;

    /// Mode property
    #[zbus(property)]
    fn mode(&self) -> zbus::Result<String>;

    /// Frequency property
    #[zbus(property)]
    fn frequency(&self) -> zbus::Result<u16>;

    /// Rates property
    #[zbus(property)]
    fn rates(&self) -> zbus::Result<Vec<u32>>;

    /// Signal property
    #[zbus(property)]
    fn signal(&self) -> zbus::Result<i16>;

    /// Age property
    #[zbus(property)]
    fn age(&self) -> zbus::Result<u32>;
}
