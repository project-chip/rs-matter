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

use core::fmt::Write;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use crate::dm::clusters::basic_info::BasicInfoConfig;
use crate::error::Error;
use crate::{MatterMdnsService, MATTER_SERVICE_MAX_NAME_LEN};

#[cfg(feature = "astro-dnssd")]
pub mod astro;
#[cfg(feature = "zbus")]
pub mod avahi;
pub mod builtin;
#[cfg(feature = "zbus")]
pub mod resolve;
#[cfg(feature = "zeroconf")]
pub mod zeroconf;

/// The standard mDNS IPv6 broadcast address
pub const MDNS_IPV6_BROADCAST_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

/// The standard mDNS IPv4 broadcast address
pub const MDNS_IPV4_BROADCAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// The standard mDNS port
pub const MDNS_PORT: u16 = 5353;

/// A default bind address for mDNS sockets. Binds to all available interfaces
pub const MDNS_SOCKET_DEFAULT_BIND_ADDR: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0));

/// A trait for resolving Matter nodes to socket addresses over mDNS
pub trait MdnsResolver {
    /// Resolve a Matter node's address using mDNS.
    ///
    /// # Arguments
    /// - `compressed_fabric_id`: The compressed fabric ID of the Matter node.
    /// - `node_id`: The node ID of the Matter node.
    async fn resolve(
        &mut self,
        compressed_fabric_id: u64,
        node_id: u64,
    ) -> Result<SocketAddr, Error>;
}

impl<T> MdnsResolver for &mut T
where
    T: MdnsResolver,
{
    async fn resolve(
        &mut self,
        compressed_fabric_id: u64,
        node_id: u64,
    ) -> Result<SocketAddr, Error> {
        (*self).resolve(compressed_fabric_id, node_id).await
    }
}

/// A utility type for expanding a `MatterMdnsService` type into a full mDNS service description
///
/// Useful as an implementation detail when interfacing with OS-specific mDNS libraries.
pub struct Service<'a> {
    /// The name of the service, typically the mDNS name
    pub name: &'a str,
    /// The service type, e.g. "_matter" or "_matterc"
    pub service: &'a str,
    /// The protocol used, e.g. "_tcp" or "_udp"
    pub protocol: &'a str,
    /// The service and protocol combined, e.g. "_matter._tcp" or "_matterc._udp"
    pub service_protocol: &'a str,
    /// The port number the service is running on
    pub port: u16,
    /// Optional service subtypes, e.g. "_L1234" or "_S12"
    pub service_subtypes: &'a [&'a str],
    /// Key-value pairs for TXT records, e.g. ("D", "1234")
    pub txt_kvs: &'a [(&'a str, &'a str)],
}

impl Service<'_> {
    /// Asynchronously expand a `MatterMdnsService` into a full service description
    ///
    /// # Arguments
    /// - `matter_service`: The Matter mDNS service to expand.
    /// - `dev_det`: The device details configuration.
    /// - `matter_port`: The port number the Matter service is running on.
    /// - `f`: A closure that takes a reference to the expanded service and returns a result.
    pub async fn async_call_with<R, F: for<'a> AsyncFnOnce(&'a Service<'a>) -> Result<R, Error>>(
        matter_service: &MatterMdnsService,
        dev_det: &BasicInfoConfig<'_>,
        matter_port: u16,
        f: F,
    ) -> Result<R, Error> {
        let mut name_buf = [0; MATTER_SERVICE_MAX_NAME_LEN];

        match matter_service {
            MatterMdnsService::Commissioned { .. } => {
                f(&Service {
                    name: matter_service.name(&mut name_buf),
                    service: "_matter",
                    protocol: "_tcp",
                    service_protocol: "_matter._tcp",
                    port: matter_port,
                    service_subtypes: &[],
                    // Some mDNS responders do not accept empty TXT records
                    txt_kvs: &[("dummy", "dummy")],
                })
                .await
            }
            MatterMdnsService::Commissionable { discriminator, .. } => {
                let discriminator_str = Self::get_discriminator_str(*discriminator);
                let vp = Self::get_vp(dev_det.vid, dev_det.pid);

                let mut sai_str = heapless::String::<5>::new();
                write_unwrap!(sai_str, "{}", dev_det.sai.unwrap_or(300));

                let mut sii_str = heapless::String::<5>::new();
                write_unwrap!(sii_str, "{}", dev_det.sii.unwrap_or(5000));

                let txt_kvs = &[
                    ("D", discriminator_str.as_str()),
                    ("CM", "1"),
                    ("DN", dev_det.device_name),
                    ("VP", &vp),
                    ("SAI", sai_str.as_str()), // Session Active Interval
                    ("SII", sii_str.as_str()), // Session Idle Interval
                    ("PH", "33"),              // Pairing Hint
                    ("PI", ""),                // Pairing Instruction
                ];

                f(&Service {
                    name: matter_service.name(&mut name_buf),
                    service: "_matterc",
                    protocol: "_udp",
                    service_protocol: "_matterc._udp",
                    port: matter_port,
                    service_subtypes: &[
                        &Self::get_long_service_subtype(*discriminator),
                        &Self::get_short_service_type(*discriminator),
                        "_CM",
                    ],
                    txt_kvs,
                })
                .await
            }
        }
    }

    /// Expand a `MatterMdnsService` into a full service description
    ///
    /// # Arguments
    /// - `matter_service`: The Matter mDNS service to expand.
    /// - `dev_det`: The device details configuration.
    /// - `matter_port`: The port number the Matter service is running on.
    /// - `f`: A closure that takes a reference to the expanded service and returns a result.
    pub fn call_with<R, F: for<'a> FnOnce(&'a Service<'a>) -> Result<R, Error>>(
        matter_service: &MatterMdnsService,
        dev_det: &BasicInfoConfig<'_>,
        matter_port: u16,
        f: F,
    ) -> Result<R, Error> {
        let mut name_buf = [0; MATTER_SERVICE_MAX_NAME_LEN];

        match matter_service {
            MatterMdnsService::Commissioned { .. } => f(&Service {
                name: matter_service.name(&mut name_buf),
                service: "_matter",
                protocol: "_tcp",
                service_protocol: "_matter._tcp",
                port: matter_port,
                service_subtypes: &[],
                // Some mDNS responders do not accept empty TXT records
                txt_kvs: &[("dummy", "dummy")],
            }),
            MatterMdnsService::Commissionable { discriminator, .. } => {
                let discriminator_str = Self::get_discriminator_str(*discriminator);
                let vp = Self::get_vp(dev_det.vid, dev_det.pid);

                let mut sai_str = heapless::String::<5>::new();
                write_unwrap!(sai_str, "{}", dev_det.sai.unwrap_or(300));

                let mut sii_str = heapless::String::<5>::new();
                write_unwrap!(sii_str, "{}", dev_det.sii.unwrap_or(5000));

                let txt_kvs = &[
                    ("D", discriminator_str.as_str()),
                    ("CM", "1"),
                    ("DN", dev_det.device_name),
                    ("VP", &vp),
                    ("SAI", sai_str.as_str()), // Session Active Interval
                    ("SII", sii_str.as_str()), // Session Idle Interval
                    ("PH", "33"),              // Pairing Hint
                    ("PI", ""),                // Pairing Instruction
                ];

                f(&Service {
                    name: matter_service.name(&mut name_buf),
                    service: "_matterc",
                    protocol: "_udp",
                    service_protocol: "_matterc._udp",
                    port: matter_port,
                    service_subtypes: &[
                        &Self::get_long_service_subtype(*discriminator),
                        &Self::get_short_service_type(*discriminator),
                        "_CM",
                    ],
                    txt_kvs,
                })
            }
        }
    }

    fn get_long_service_subtype(discriminator: u16) -> heapless::String<32> {
        let mut serv_type = heapless::String::new();
        write_unwrap!(&mut serv_type, "_L{}", discriminator);

        serv_type
    }

    fn get_short_service_type(discriminator: u16) -> heapless::String<32> {
        let short = Self::compute_short_discriminator(discriminator);

        let mut serv_type = heapless::String::new();
        write_unwrap!(&mut serv_type, "_S{}", short);

        serv_type
    }

    fn get_discriminator_str(discriminator: u16) -> heapless::String<5> {
        unwrap!(discriminator.try_into())
    }

    fn get_vp(vid: u16, pid: u16) -> heapless::String<11> {
        let mut vp = heapless::String::new();

        write_unwrap!(&mut vp, "{}+{}", vid, pid);

        vp
    }

    fn compute_short_discriminator(discriminator: u16) -> u16 {
        const SHORT_DISCRIMINATOR_MASK: u16 = 0xF00;
        const SHORT_DISCRIMINATOR_SHIFT: u16 = 8;

        (discriminator & SHORT_DISCRIMINATOR_MASK) >> SHORT_DISCRIMINATOR_SHIFT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_compute_short_discriminator() {
        let discriminator: u16 = 0b0000_1111_0000_0000;
        let short = Service::compute_short_discriminator(discriminator);
        assert_eq!(short, 0b1111);

        let discriminator: u16 = 840;
        let short = Service::compute_short_discriminator(discriminator);
        assert_eq!(short, 3);
    }
}
