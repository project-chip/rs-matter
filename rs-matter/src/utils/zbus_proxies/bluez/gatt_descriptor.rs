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

//! # D-Bus interface proxy for: `org.bluez.GattDescriptor1`

use std::collections::HashMap;

use zbus::{
    proxy,
    zvariant::{OwnedObjectPath, Value},
};

#[proxy(interface = "org.bluez.GattDescriptor1", assume_defaults = true)]
pub trait GattDescriptor {
    /// ReadValue method
    fn read_value(&self, options: HashMap<&str, &Value<'_>>) -> zbus::Result<Vec<u8>>;

    /// WriteValue method
    fn write_value(&self, value: &[u8], options: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// Characteristic property
    #[zbus(property)]
    fn characteristic(&self) -> zbus::Result<OwnedObjectPath>;

    /// UUID property
    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> zbus::Result<String>;

    /// Value property
    #[zbus(property)]
    fn value(&self) -> zbus::Result<Vec<u8>>;
}
