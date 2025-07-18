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

//! # D-Bus interface proxy for: `org.bluez.GattCharacteristic1`

use std::collections::HashMap;

use zbus::{
    proxy,
    zvariant::{OwnedFd, OwnedObjectPath, Value},
};

#[proxy(interface = "org.bluez.GattCharacteristic1", assume_defaults = true)]
pub trait GattCharacteristic {
    /// AcquireNotify method
    fn acquire_notify(&self, options: HashMap<&str, &Value<'_>>) -> zbus::Result<(OwnedFd, u16)>;

    /// AcquireWrite method
    fn acquire_write(&self, options: HashMap<&str, &Value<'_>>) -> zbus::Result<(OwnedFd, u16)>;

    /// ReadValue method
    fn read_value(&self, options: HashMap<&str, &Value<'_>>) -> zbus::Result<Vec<u8>>;

    /// StartNotify method
    fn start_notify(&self) -> zbus::Result<()>;

    /// StopNotify method
    fn stop_notify(&self) -> zbus::Result<()>;

    /// WriteValue method
    fn write_value(&self, value: &[u8], options: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// Flags property
    #[zbus(property)]
    fn flags(&self) -> zbus::Result<Vec<String>>;

    /// MTU property
    #[zbus(property, name = "MTU")]
    fn mtu(&self) -> zbus::Result<u16>;

    /// NotifyAcquired property
    #[zbus(property)]
    fn notify_acquired(&self) -> zbus::Result<bool>;

    /// Notifying property
    #[zbus(property)]
    fn notifying(&self) -> zbus::Result<bool>;

    /// Service property
    #[zbus(property)]
    fn service(&self) -> zbus::Result<OwnedObjectPath>;

    /// UUID property
    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> zbus::Result<String>;

    /// Value property
    #[zbus(property)]
    fn value(&self) -> zbus::Result<Vec<u8>>;

    /// WriteAcquired property
    #[zbus(property)]
    fn write_acquired(&self) -> zbus::Result<bool>;
}
