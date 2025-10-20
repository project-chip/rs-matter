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
use core::future::Future;
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
    fn resolve(
        &mut self,
        compressed_fabric_id: u64,
        node_id: u64,
    ) -> impl Future<Output = Result<SocketAddr, Error>> {
        (*self).resolve(compressed_fabric_id, node_id)
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
                // "_L{u16}""
                let mut discr_svc_str = heapless::String::<7>::new();
                // "_S{u16}""
                let mut short_discr_svc_str = heapless::String::<7>::new();
                // "_V{u16}P{u16}""
                let mut vp_svc_str = heapless::String::<13>::new();

                // "{u16}
                let mut discr_str = heapless::String::<5>::new();
                // "{u16}+{u16}"
                let mut vp_str = heapless::String::<11>::new();
                // "{u16}"
                let mut sai_str = heapless::String::<5>::new();
                // "{u16}"
                let mut sii_str = heapless::String::<5>::new();
                // "{u16}"
                let mut dt_str = heapless::String::<6>::new();
                // "{u32}"
                let mut ph_str = heapless::String::<12>::new();

                let mut txt_kvs = heapless::Vec::<_, 9>::new();

                write_unwrap!(&mut discr_svc_str, "_L{}", *discriminator);
                write_unwrap!(
                    &mut short_discr_svc_str,
                    "_S{}",
                    Self::compute_short_discriminator(*discriminator)
                );
                write_unwrap!(&mut vp_svc_str, "_V{}P{}", dev_det.vid, dev_det.pid);

                write_unwrap!(discr_str, "{}", *discriminator);
                unwrap!(txt_kvs.push(("D", discr_str.as_str())));

                unwrap!(txt_kvs.push(("CM", "1")));

                write_unwrap!(&mut vp_str, "{}+{}", dev_det.vid, dev_det.pid);
                unwrap!(txt_kvs.push(("VP", &vp_str)));

                write_unwrap!(sai_str, "{}", dev_det.sai.unwrap_or(300));
                unwrap!(txt_kvs.push(("SAI", sai_str.as_str())));

                write_unwrap!(sii_str, "{}", dev_det.sii.unwrap_or(5000));
                unwrap!(txt_kvs.push(("SII", sii_str.as_str())));

                if !dev_det.device_name.is_empty() {
                    unwrap!(txt_kvs.push(("DN", dev_det.device_name)));
                }

                if let Some(device_type) = dev_det.device_type {
                    write_unwrap!(&mut dt_str, "{}", device_type);
                    unwrap!(txt_kvs.push(("DT", dt_str.as_str())));
                }

                if !dev_det.pairing_hint.is_empty() {
                    write_unwrap!(&mut ph_str, "{}", dev_det.pairing_hint.bits());
                    unwrap!(txt_kvs.push(("PH", ph_str.as_str())));
                }

                if !dev_det.pairing_instruction.is_empty() {
                    unwrap!(txt_kvs.push(("PI", dev_det.pairing_instruction)));
                }

                f(&Service {
                    name: matter_service.name(&mut name_buf),
                    service: "_matterc",
                    protocol: "_udp",
                    service_protocol: "_matterc._udp",
                    port: matter_port,
                    service_subtypes: &[
                        discr_svc_str.as_str(),
                        short_discr_svc_str.as_str(),
                        vp_svc_str.as_str(),
                        "_CM",
                    ],
                    txt_kvs: txt_kvs.as_slice(),
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
        // Not the most elegant solution to cut down on code duplication,
        // but works fine because we _know_ the future will resolve immediately,
        // because the `f` closure does not block and resolves immediately as well.
        embassy_futures::block_on(Self::async_call_with(
            matter_service,
            dev_det,
            matter_port,
            async |service| f(service),
        ))
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
