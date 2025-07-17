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

//! # D-Bus interface proxy for: `org.freedesktop.Avahi.Server2`

#![allow(clippy::type_complexity)]

use zbus::{proxy, zvariant::OwnedObjectPath};

#[proxy(
    interface = "org.freedesktop.Avahi.Server2",
    default_service = "org.freedesktop.Avahi",
    default_path = "/"
)]
pub trait Server2 {
    /// AddressResolverPrepare method
    fn address_resolver_prepare(
        &self,
        interface: i32,
        protocol: i32,
        address: &str,
        flags: u32,
    ) -> zbus::Result<OwnedObjectPath>;

    /// DomainBrowserPrepare method
    fn domain_browser_prepare(
        &self,
        interface: i32,
        protocol: i32,
        domain: &str,
        btype: i32,
        flags: u32,
    ) -> zbus::Result<OwnedObjectPath>;

    /// EntryGroupNew method
    fn entry_group_new(&self) -> zbus::Result<OwnedObjectPath>;

    /// GetAPIVersion method
    #[zbus(name = "GetAPIVersion")]
    fn get_apiversion(&self) -> zbus::Result<u32>;

    /// GetAlternativeHostName method
    fn get_alternative_host_name(&self, name: &str) -> zbus::Result<String>;

    /// GetAlternativeServiceName method
    fn get_alternative_service_name(&self, name: &str) -> zbus::Result<String>;

    /// GetDomainName method
    fn get_domain_name(&self) -> zbus::Result<String>;

    /// GetHostName method
    fn get_host_name(&self) -> zbus::Result<String>;

    /// GetHostNameFqdn method
    fn get_host_name_fqdn(&self) -> zbus::Result<String>;

    /// GetLocalServiceCookie method
    fn get_local_service_cookie(&self) -> zbus::Result<u32>;

    /// GetNetworkInterfaceIndexByName method
    fn get_network_interface_index_by_name(&self, name: &str) -> zbus::Result<i32>;

    /// GetNetworkInterfaceNameByIndex method
    fn get_network_interface_name_by_index(&self, index: i32) -> zbus::Result<String>;

    /// GetState method
    fn get_state(&self) -> zbus::Result<i32>;

    /// GetVersionString method
    fn get_version_string(&self) -> zbus::Result<String>;

    /// HostNameResolverPrepare method
    fn host_name_resolver_prepare(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        aprotocol: i32,
        flags: u32,
    ) -> zbus::Result<OwnedObjectPath>;

    /// IsNSSSupportAvailable method
    #[zbus(name = "IsNSSSupportAvailable")]
    fn is_nsssupport_available(&self) -> zbus::Result<bool>;

    /// RecordBrowserPrepare method
    #[allow(clippy::too_many_arguments)]
    fn record_browser_prepare(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        clazz: u16,
        type_: u16,
        flags: u32,
    ) -> zbus::Result<OwnedObjectPath>;

    /// ResolveAddress method
    #[allow(clippy::too_many_arguments)]
    fn resolve_address(
        &self,
        interface: i32,
        protocol: i32,
        address: &str,
        flags: u32,
    ) -> zbus::Result<(i32, i32, i32, String, String, u32)>;

    /// ResolveHostName method
    #[allow(clippy::too_many_arguments)]
    fn resolve_host_name(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        aprotocol: i32,
        flags: u32,
    ) -> zbus::Result<(i32, i32, String, i32, String, u32)>;

    /// ResolveService method
    #[allow(clippy::too_many_arguments)]
    fn resolve_service(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        type_: &str,
        domain: &str,
        aprotocol: i32,
        flags: u32,
    ) -> zbus::Result<(
        i32,
        i32,
        String,
        String,
        String,
        String,
        i32,
        String,
        u16,
        Vec<Vec<u8>>,
        u32,
    )>;

    /// ServiceBrowserPrepare method
    fn service_browser_prepare(
        &self,
        interface: i32,
        protocol: i32,
        type_: &str,
        domain: &str,
        flags: u32,
    ) -> zbus::Result<OwnedObjectPath>;

    /// ServiceResolverPrepare method
    #[allow(clippy::too_many_arguments)]
    fn service_resolver_prepare(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        type_: &str,
        domain: &str,
        aprotocol: i32,
        flags: u32,
    ) -> zbus::Result<OwnedObjectPath>;

    /// ServiceTypeBrowserPrepare method
    fn service_type_browser_prepare(
        &self,
        interface: i32,
        protocol: i32,
        domain: &str,
        flags: u32,
    ) -> zbus::Result<OwnedObjectPath>;

    /// SetHostName method
    fn set_host_name(&self, name: &str) -> zbus::Result<()>;

    /// StateChanged signal
    #[zbus(signal)]
    fn state_changed(&self, state: i32, error: &str) -> zbus::Result<()>;
}
