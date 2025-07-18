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

//! # D-Bus interface proxy for: `org.bluez.LEAdvertisingManager1`

use std::collections::HashMap;

use zbus::{
    proxy,
    zvariant::{ObjectPath, Value},
};

#[proxy(
    interface = "org.bluez.LEAdvertisingManager1",
    default_service = "org.bluez"
)]
pub trait LEAdvertisingManager {
    /// RegisterAdvertisement method
    fn register_advertisement(
        &self,
        advertisement: &ObjectPath<'_>,
        options: HashMap<&str, &Value<'_>>,
    ) -> zbus::Result<()>;

    /// UnregisterAdvertisement method
    fn unregister_advertisement(&self, service: &ObjectPath<'_>) -> zbus::Result<()>;

    /// ActiveInstances property
    #[zbus(property)]
    fn active_instances(&self) -> zbus::Result<u8>;

    /// SupportedIncludes property
    #[zbus(property)]
    fn supported_includes(&self) -> zbus::Result<Vec<String>>;

    /// SupportedInstances property
    #[zbus(property)]
    fn supported_instances(&self) -> zbus::Result<u8>;

    /// SupportedSecondaryChannels property
    #[zbus(property)]
    fn supported_secondary_channels(&self) -> zbus::Result<Vec<String>>;
}
