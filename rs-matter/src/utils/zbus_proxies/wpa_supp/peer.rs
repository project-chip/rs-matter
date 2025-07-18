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

//! # D-Bus interface proxy for: `fi.w1.wpa_supplicant1.Interface.Peer`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{OwnedObjectPath, Value};

#[proxy(
    interface = "fi.w1.wpa_supplicant1.Interface.Peer",
    assume_defaults = true
)]
pub trait Peer {
    /// PropertiesChanged signal
    #[zbus(signal)]
    fn properties_changed(&self, properties: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// DeviceName property
    #[zbus(property)]
    fn device_name(&self) -> zbus::Result<String>;

    /// Manufacturer property
    #[zbus(property)]
    fn manufacturer(&self) -> zbus::Result<String>;

    /// ModelName property
    #[zbus(property)]
    fn model_name(&self) -> zbus::Result<String>;

    /// ModelNumber property
    #[zbus(property)]
    fn model_number(&self) -> zbus::Result<String>;

    /// SerialNumber property
    #[zbus(property)]
    fn serial_number(&self) -> zbus::Result<String>;

    /// PrimaryDeviceType property
    #[zbus(property)]
    fn primary_device_type(&self) -> zbus::Result<Vec<u8>>;

    /// ConfigMethod property
    #[zbus(property)]
    fn config_method(&self) -> zbus::Result<u16>;

    /// Level property
    #[zbus(property)]
    fn level(&self) -> zbus::Result<i32>;

    /// DeviceCapability property
    #[zbus(property)]
    fn device_capability(&self) -> zbus::Result<u8>;

    /// GroupCapability property
    #[zbus(property)]
    fn group_capability(&self) -> zbus::Result<u8>;

    /// SecondaryDeviceTypes property
    #[zbus(property)]
    fn secondary_device_types(&self) -> zbus::Result<Vec<Vec<u8>>>;

    /// VendorExtension property
    #[zbus(property)]
    fn vendor_extension(&self) -> zbus::Result<Vec<Vec<u8>>>;

    /// IEs property
    #[zbus(property)]
    fn ies(&self) -> zbus::Result<Vec<u8>>;

    /// DeviceAddress property
    #[zbus(property)]
    fn device_address(&self) -> zbus::Result<Vec<u8>>;

    /// Groups property
    #[zbus(property)]
    fn groups(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
}
