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

//! # D-Bus interface proxy for: `org.bluez.Network1`

use zbus::proxy;

#[proxy(interface = "org.bluez.Network1", assume_defaults = true)]
pub trait Network {
    /// Connect method
    fn connect(&self, uuid: &str) -> zbus::Result<String>;

    /// Disconnect method
    fn disconnect(&self) -> zbus::Result<()>;

    /// Connected property
    #[zbus(property)]
    fn connected(&self) -> zbus::Result<bool>;

    /// Interface property
    #[zbus(property)]
    fn interface(&self) -> zbus::Result<String>;

    /// UUID property
    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> zbus::Result<String>;
}
