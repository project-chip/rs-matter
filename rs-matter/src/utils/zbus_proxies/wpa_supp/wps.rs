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

//! # D-Bus interface proxy for: `fi.w1.wpa_supplicant1.Interface.WPS`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{OwnedValue, Value};

#[proxy(
    interface = "fi.w1.wpa_supplicant1.Interface.WPS",
    default_service = "fi.w1.wpa_supplicant1"
)]
pub trait WPS {
    /// Start method
    fn start(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<HashMap<String, OwnedValue>>;

    /// Cancel method
    fn cancel(&self) -> zbus::Result<()>;

    /// Credentials signal
    #[zbus(signal)]
    fn credentials(&self, credentials: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// Event signal
    #[zbus(signal)]
    fn event(&self, name: &str, args: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// PropertiesChanged signal
    #[zbus(signal)]
    fn properties_changed(&self, properties: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// ConfigMethods property
    #[zbus(property)]
    fn config_methods(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_config_methods(&self, value: &str) -> zbus::Result<()>;

    /// ProcessCredentials property
    #[zbus(property)]
    fn process_credentials(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_process_credentials(&self, value: bool) -> zbus::Result<()>;
}
