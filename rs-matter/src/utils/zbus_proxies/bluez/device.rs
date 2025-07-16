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

//! # D-Bus interface proxy for: `org.bluez.Device1`

use std::collections::HashMap;

use zbus::{
    proxy,
    zvariant::{OwnedObjectPath, OwnedValue},
};

#[proxy(interface = "org.bluez.Device1", assume_defaults = true)]
pub trait Device {
    /// CancelPairing method
    fn cancel_pairing(&self) -> zbus::Result<()>;

    /// Connect method
    fn connect(&self) -> zbus::Result<()>;

    /// ConnectProfile method
    fn connect_profile(&self, uuid: &str) -> zbus::Result<()>;

    /// Disconnect method
    fn disconnect(&self) -> zbus::Result<()>;

    /// DisconnectProfile method
    fn disconnect_profile(&self, uuid: &str) -> zbus::Result<()>;

    /// Pair method
    fn pair(&self) -> zbus::Result<()>;

    /// Adapter property
    #[zbus(property)]
    fn adapter(&self) -> zbus::Result<OwnedObjectPath>;

    /// Address property
    #[zbus(property)]
    fn address(&self) -> zbus::Result<String>;

    /// AddressType property
    #[zbus(property)]
    fn address_type(&self) -> zbus::Result<String>;

    /// Alias property
    #[zbus(property)]
    fn alias(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_alias(&self, value: &str) -> zbus::Result<()>;

    /// Appearance property
    #[zbus(property)]
    fn appearance(&self) -> zbus::Result<u16>;

    /// Blocked property
    #[zbus(property)]
    fn blocked(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_blocked(&self, value: bool) -> zbus::Result<()>;

    /// Class property
    #[zbus(property)]
    fn class(&self) -> zbus::Result<u32>;

    /// Connected property
    #[zbus(property)]
    fn connected(&self) -> zbus::Result<bool>;

    /// Icon property
    #[zbus(property)]
    fn icon(&self) -> zbus::Result<String>;

    /// LegacyPairing property
    #[zbus(property)]
    fn legacy_pairing(&self) -> zbus::Result<bool>;

    /// ManufacturerData property
    #[zbus(property)]
    fn manufacturer_data(&self) -> zbus::Result<HashMap<u16, OwnedValue>>;

    /// Modalias property
    #[zbus(property)]
    fn modalias(&self) -> zbus::Result<String>;

    /// Name property
    #[zbus(property)]
    fn name(&self) -> zbus::Result<String>;

    /// Paired property
    #[zbus(property)]
    fn paired(&self) -> zbus::Result<bool>;

    /// RSSI property
    #[zbus(property, name = "RSSI")]
    fn rssi(&self) -> zbus::Result<i16>;

    /// ServiceData property
    #[zbus(property)]
    fn service_data(&self) -> zbus::Result<HashMap<String, OwnedValue>>;

    /// ServicesResolved property
    #[zbus(property)]
    fn services_resolved(&self) -> zbus::Result<bool>;

    /// Trusted property
    #[zbus(property)]
    fn trusted(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_trusted(&self, value: bool) -> zbus::Result<()>;

    /// TxPower property
    #[zbus(property)]
    fn tx_power(&self) -> zbus::Result<i16>;

    /// UUIDs property
    #[zbus(property, name = "UUIDs")]
    fn uuids(&self) -> zbus::Result<Vec<String>>;
}
