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

//! # D-Bus interface proxy for: `org.freedesktop.resolve1.Manager`

#![allow(clippy::type_complexity)]

use std::collections::HashMap;

use zbus::{
    proxy,
    zvariant::{ObjectPath, OwnedObjectPath},
};

#[proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1"
)]
pub trait Manager {
    /// FlushCaches method
    fn flush_caches(&self) -> zbus::Result<()>;

    /// GetLink method
    fn get_link(&self, ifindex: i32) -> zbus::Result<OwnedObjectPath>;

    /// RegisterService method
    #[allow(clippy::too_many_arguments)]
    fn register_service(
        &self,
        name: &str,
        name_template: &str,
        type_: &str,
        service_port: u16,
        service_priority: u16,
        service_weight: u16,
        txt_datas: &[HashMap<&str, &[u8]>],
    ) -> zbus::Result<OwnedObjectPath>;

    /// ResetServerFeatures method
    fn reset_server_features(&self) -> zbus::Result<()>;

    /// ResetStatistics method
    fn reset_statistics(&self) -> zbus::Result<()>;

    /// ResolveAddress method
    fn resolve_address(
        &self,
        ifindex: i32,
        family: i32,
        address: &[u8],
        flags: u64,
    ) -> zbus::Result<(Vec<(i32, String)>, u64)>;

    /// ResolveHostname method
    #[allow(clippy::too_many_arguments)]
    fn resolve_hostname(
        &self,
        ifindex: i32,
        name: &str,
        family: i32,
        flags: u64,
    ) -> zbus::Result<(Vec<(i32, i32, Vec<u8>)>, String, u64)>;

    /// ResolveRecord method
    #[allow(clippy::too_many_arguments)]
    fn resolve_record(
        &self,
        ifindex: i32,
        name: &str,
        class: u16,
        type_: u16,
        flags: u64,
    ) -> zbus::Result<(Vec<(i32, u16, u16, Vec<u8>)>, u64)>;

    /// ResolveService method
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn resolve_service(
        &self,
        ifindex: i32,
        name: &str,
        type_: &str,
        domain: &str,
        family: i32,
        flags: u64,
    ) -> zbus::Result<(
        Vec<(u16, u16, u16, String, Vec<(i32, i32, Vec<u8>)>, String)>,
        Vec<Vec<u8>>,
        String,
        String,
        String,
        u64,
    )>;

    /// RevertLink method
    fn revert_link(&self, ifindex: i32) -> zbus::Result<()>;

    /// SetLinkDNS method
    #[zbus(name = "SetLinkDNS")]
    fn set_link_dns(&self, ifindex: i32, addresses: &[&(i32, &[u8])]) -> zbus::Result<()>;

    /// SetLinkDNSEx method
    #[zbus(name = "SetLinkDNSEx")]
    fn set_link_dnsex(
        &self,
        ifindex: i32,
        addresses: &[&(i32, &[u8], u16, &str)],
    ) -> zbus::Result<()>;

    /// SetLinkDNSOverTLS method
    #[zbus(name = "SetLinkDNSOverTLS")]
    fn set_link_dnsover_tls(&self, ifindex: i32, mode: &str) -> zbus::Result<()>;

    /// SetLinkDNSSEC method
    #[zbus(name = "SetLinkDNSSEC")]
    fn set_link_dnssec(&self, ifindex: i32, mode: &str) -> zbus::Result<()>;

    /// SetLinkDNSSECNegativeTrustAnchors method
    #[zbus(name = "SetLinkDNSSECNegativeTrustAnchors")]
    fn set_link_dnssecnegative_trust_anchors(
        &self,
        ifindex: i32,
        names: &[&str],
    ) -> zbus::Result<()>;

    /// SetLinkDefaultRoute method
    fn set_link_default_route(&self, ifindex: i32, enable: bool) -> zbus::Result<()>;

    /// SetLinkDomains method
    fn set_link_domains(&self, ifindex: i32, domains: &[&(&str, bool)]) -> zbus::Result<()>;

    /// SetLinkLLMNR method
    #[zbus(name = "SetLinkLLMNR")]
    fn set_link_llmnr(&self, ifindex: i32, mode: &str) -> zbus::Result<()>;

    /// SetLinkMulticastDNS method
    #[zbus(name = "SetLinkMulticastDNS")]
    fn set_link_multicast_dns(&self, ifindex: i32, mode: &str) -> zbus::Result<()>;

    /// UnregisterService method
    fn unregister_service(&self, service_path: &ObjectPath<'_>) -> zbus::Result<()>;

    /// CacheStatistics property
    #[zbus(property)]
    fn cache_statistics(&self) -> zbus::Result<(u64, u64, u64)>;

    /// CurrentDNSServer property
    #[zbus(property, name = "CurrentDNSServer")]
    fn current_dnsserver(&self) -> zbus::Result<(i32, i32, Vec<u8>)>;

    /// CurrentDNSServerEx property
    #[zbus(property, name = "CurrentDNSServerEx")]
    fn current_dnsserver_ex(&self) -> zbus::Result<(i32, i32, Vec<u8>, u16, String)>;

    /// DNS property
    #[zbus(property, name = "DNS")]
    fn dns(&self) -> zbus::Result<Vec<(i32, i32, Vec<u8>)>>;

    /// DNSEx property
    #[zbus(property, name = "DNSEx")]
    fn dnsex(&self) -> zbus::Result<Vec<(i32, i32, Vec<u8>, u16, String)>>;

    /// DNSOverTLS property
    #[zbus(property, name = "DNSOverTLS")]
    fn dnsover_tls(&self) -> zbus::Result<String>;

    /// DNSSEC property
    #[zbus(property, name = "DNSSEC")]
    fn dnssec(&self) -> zbus::Result<String>;

    /// DNSSECNegativeTrustAnchors property
    #[zbus(property, name = "DNSSECNegativeTrustAnchors")]
    fn dnssecnegative_trust_anchors(&self) -> zbus::Result<Vec<String>>;

    /// DNSSECStatistics property
    #[zbus(property, name = "DNSSECStatistics")]
    fn dnssecstatistics(&self) -> zbus::Result<(u64, u64, u64, u64)>;

    /// DNSSECSupported property
    #[zbus(property, name = "DNSSECSupported")]
    fn dnssecsupported(&self) -> zbus::Result<bool>;

    /// DNSStubListener property
    #[zbus(property, name = "DNSStubListener")]
    fn dnsstub_listener(&self) -> zbus::Result<String>;

    /// Domains property
    #[zbus(property)]
    fn domains(&self) -> zbus::Result<Vec<(i32, String, bool)>>;

    /// FallbackDNS property
    #[zbus(property, name = "FallbackDNS")]
    fn fallback_dns(&self) -> zbus::Result<Vec<(i32, i32, Vec<u8>)>>;

    /// FallbackDNSEx property
    #[zbus(property, name = "FallbackDNSEx")]
    fn fallback_dnsex(&self) -> zbus::Result<Vec<(i32, i32, Vec<u8>, u16, String)>>;

    /// LLMNR property
    #[zbus(property, name = "LLMNR")]
    fn llmnr(&self) -> zbus::Result<String>;

    /// LLMNRHostname property
    #[zbus(property, name = "LLMNRHostname")]
    fn llmnrhostname(&self) -> zbus::Result<String>;

    /// MulticastDNS property
    #[zbus(property, name = "MulticastDNS")]
    fn multicast_dns(&self) -> zbus::Result<String>;

    /// ResolvConfMode property
    #[zbus(property)]
    fn resolv_conf_mode(&self) -> zbus::Result<String>;

    /// TransactionStatistics property
    #[zbus(property)]
    fn transaction_statistics(&self) -> zbus::Result<(u64, u64)>;
}
