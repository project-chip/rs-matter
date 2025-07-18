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

//! # D-Bus interface proxy for: `org.freedesktop.Avahi.EntryGroup`

use zbus::proxy;

#[proxy(
    interface = "org.freedesktop.Avahi.EntryGroup",
    default_service = "org.freedesktop.Avahi"
)]
pub trait EntryGroup {
    /// AddAddress method
    fn add_address(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        address: &str,
    ) -> zbus::Result<()>;

    /// AddRecord method
    #[allow(clippy::too_many_arguments)]
    fn add_record(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        clazz: u16,
        type_: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> zbus::Result<()>;

    /// AddService method
    #[allow(clippy::too_many_arguments)]
    fn add_service(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        type_: &str,
        domain: &str,
        host: &str,
        port: u16,
        txt: &[&[u8]],
    ) -> zbus::Result<()>;

    /// AddServiceSubtype method
    #[allow(clippy::too_many_arguments)]
    fn add_service_subtype(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        type_: &str,
        domain: &str,
        subtype: &str,
    ) -> zbus::Result<()>;

    /// Commit method
    fn commit(&self) -> zbus::Result<()>;

    /// Free method
    fn free(&self) -> zbus::Result<()>;

    /// GetState method
    fn get_state(&self) -> zbus::Result<i32>;

    /// IsEmpty method
    fn is_empty(&self) -> zbus::Result<bool>;

    /// Reset method
    fn reset(&self) -> zbus::Result<()>;

    /// UpdateServiceTxt method
    #[allow(clippy::too_many_arguments)]
    fn update_service_txt(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        type_: &str,
        domain: &str,
        txt: &[&[u8]],
    ) -> zbus::Result<()>;

    /// StateChanged signal
    #[zbus(signal)]
    fn state_changed(&self, state: i32, error: &str) -> zbus::Result<()>;
}
