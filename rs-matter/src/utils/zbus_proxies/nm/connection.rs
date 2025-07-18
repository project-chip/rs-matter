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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Settings.Connection`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{OwnedValue, Value};

#[proxy(
    interface = "org.freedesktop.NetworkManager.Settings.Connection",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Connection {
    /// ClearSecrets method
    fn clear_secrets(&self) -> zbus::Result<()>;

    /// Delete method
    fn delete(&self) -> zbus::Result<()>;

    /// GetSecrets method
    fn get_secrets(
        &self,
        setting_name: &str,
    ) -> zbus::Result<HashMap<String, HashMap<String, OwnedValue>>>;

    /// GetSettings method
    fn get_settings(&self) -> zbus::Result<HashMap<String, HashMap<String, OwnedValue>>>;

    /// Save method
    fn save(&self) -> zbus::Result<()>;

    /// Update method
    fn update(&self, properties: HashMap<&str, HashMap<&str, &Value<'_>>>) -> zbus::Result<()>;

    /// Update2 method
    fn update2(
        &self,
        settings: HashMap<&str, HashMap<&str, &Value<'_>>>,
        flags: u32,
        args: HashMap<&str, &Value<'_>>,
    ) -> zbus::Result<HashMap<String, OwnedValue>>;

    /// UpdateUnsaved method
    fn update_unsaved(
        &self,
        properties: HashMap<&str, HashMap<&str, &Value<'_>>>,
    ) -> zbus::Result<()>;

    /// Removed signal
    #[zbus(signal)]
    fn removed(&self) -> zbus::Result<()>;

    /// Updated signal
    #[zbus(signal)]
    fn updated(&self) -> zbus::Result<()>;

    /// Filename property
    #[zbus(property)]
    fn filename(&self) -> zbus::Result<String>;

    /// Flags property
    #[zbus(property)]
    fn flags(&self) -> zbus::Result<u32>;

    /// Unsaved property
    #[zbus(property)]
    fn unsaved(&self) -> zbus::Result<bool>;

    /// VersionId property
    #[zbus(property)]
    fn version_id(&self) -> zbus::Result<u64>;
}
