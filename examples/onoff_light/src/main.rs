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

use core::borrow::Borrow;
use core::pin::pin;
use std::net::UdpSocket;

use embassy_futures::select::select3;

use log::info;

use rs_matter::core::{CommissioningData, Matter};
use rs_matter::data_model::cluster_basic_information::BasicInfoConfig;
use rs_matter::data_model::cluster_on_off;
use rs_matter::data_model::device_types::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::data_model::objects::*;
use rs_matter::data_model::root_endpoint;
use rs_matter::data_model::system_model::descriptor;
use rs_matter::error::Error;
use rs_matter::mdns::MdnsService;
use rs_matter::persist::Psm;
use rs_matter::secure_channel::spake2p::VerifierData;
use rs_matter::transport::core::{PacketBuffers, MATTER_SOCKET_BIND_ADDR};
use rs_matter::utils::select::EitherUnwrap;
use rs_matter::MATTER_PORT;

mod dev_att;

fn main() -> Result<(), Error> {
    let thread = std::thread::Builder::new()
        // Increase the stack size until the example can work without stack blowups.
        // Note that the used stack size increases exponentially by lowering the level of compiler optimizations,
        // as lower optimization settings prevent the Rust compiler from inlining constructor functions
        // which often results in (unnecessary) memory moves and increased stack utilization:
        // e.g., an opt-level of "0" will require a several times' larger stack.
        //
        // Optimizing/lowering `rs-matter` memory consumption is an ongoing topic.
        .stack_size(180 * 1024)
        .spawn(run)
        .unwrap();

    thread.join().unwrap()
}

fn run() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    info!(
        "Matter memory: Matter={}, PacketBuffers={}",
        core::mem::size_of::<Matter>(),
        core::mem::size_of::<PacketBuffers>(),
    );

    let dev_det = BasicInfoConfig {
        vid: 0xFFF1,
        pid: 0x8000,
        hw_ver: 2,
        sw_ver: 1,
        sw_ver_str: "1",
        serial_no: "aabbccdd",
        device_name: "OnOff Light",
        product_name: "Light123",
        vendor_name: "Vendor PQR",
    };

    let dev_att = dev_att::HardCodedDevAtt::new();

    // NOTE:
    // For `no_std` environments, provide your own epoch and rand functions here
    let epoch = rs_matter::utils::epoch::sys_epoch;
    let rand = rs_matter::utils::rand::sys_rand;

    let matter = Matter::new(
        // vid/pid should match those in the DAC
        &dev_det,
        &dev_att,
        MdnsService::Builtin,
        epoch,
        rand,
        MATTER_PORT,
    );

    info!("Matter initialized");

    let handler = HandlerCompat(handler(&matter));

    // NOTE:
    // When using a custom UDP stack (e.g. for `no_std` environments), replace with a UDP socket bind for your custom UDP stack
    // The returned socket should be splittable into two halves, where each half implements `UdpSend` and `UdpReceive` respectively
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    let mut packet_buffers = PacketBuffers::new();
    let mut runner = pin!(matter.run(
        &socket,
        &socket,
        &mut packet_buffers,
        CommissioningData {
            // TODO: Hard-coded for now
            verifier: VerifierData::new_with_pw(123456, *matter.borrow()),
            discriminator: 250,
        },
        &handler,
    ));

    let mut mdns_runner = pin!(run_mdns(&matter));

    // NOTE:
    // Replace with your own persister for e.g. `no_std` environments
    let mut psm = Psm::new(&matter, std::env::temp_dir().join("rs-matter"))?;
    let mut psm_runner = pin!(psm.run());

    let runner = select3(&mut runner, &mut mdns_runner, &mut psm_runner);

    // NOTE:
    // Replace with a different executor for e.g. `no_std` environments
    futures_lite::future::block_on(runner).unwrap()?;

    Ok(())
}

const NODE: Node<'static> = Node {
    id: 0,
    endpoints: &[
        root_endpoint::endpoint(0),
        Endpoint {
            id: 1,
            device_type: DEV_TYPE_ON_OFF_LIGHT,
            clusters: &[descriptor::CLUSTER, cluster_on_off::CLUSTER],
        },
    ],
};

fn handler<'a>(matter: &'a Matter<'a>) -> impl Metadata + NonBlockingHandler + 'a {
    (
        NODE,
        root_endpoint::handler(0, matter)
            .chain(
                1,
                descriptor::ID,
                descriptor::DescriptorCluster::new(*matter.borrow()),
            )
            .chain(
                1,
                cluster_on_off::ID,
                cluster_on_off::OnOffCluster::new(*matter.borrow()),
            ),
    )
}

#[cfg(all(
    feature = "std",
    any(target_os = "macos", all(feature = "zeroconf", target_os = "linux"))
))]
async fn run_mdns(_matter: &Matter<'_>) -> Result<(), Error> {
    // Nothing to run
    core::future::pending().await
}

#[cfg(not(all(
    feature = "std",
    any(target_os = "macos", all(feature = "zeroconf", target_os = "linux"))
)))]
async fn run_mdns(matter: &Matter<'_>) -> Result<(), Error> {
    use rs_matter::transport::network::{Ipv4Addr, Ipv6Addr};

    // NOTE:
    // Replace with your own network initialization for e.g. `no_std` environments
    fn initialize_network() -> Result<(Ipv4Addr, Ipv6Addr, u32), Error> {
        use log::error;
        use nix::{net::if_::InterfaceFlags, sys::socket::SockaddrIn6};
        use rs_matter::error::ErrorCode;
        let interfaces = || {
            nix::ifaddrs::getifaddrs().unwrap().filter(|ia| {
                ia.flags
                    .contains(InterfaceFlags::IFF_UP | InterfaceFlags::IFF_BROADCAST)
                    && !ia
                        .flags
                        .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
            })
        };

        // A quick and dirty way to get a network interface that has a link-local IPv6 address assigned as well as a non-loopback IPv4
        // Most likely, this is the interface we need
        // (as opposed to all the docker and libvirt interfaces that might be assigned on the machine and which seem by default to be IPv4 only)
        let (iname, ip, ipv6) = interfaces()
            .filter_map(|ia| {
                ia.address
                    .and_then(|addr| addr.as_sockaddr_in6().map(SockaddrIn6::ip))
                    .filter(|ip| ip.octets()[..2] == [0xfe, 0x80])
                    .map(|ipv6| (ia.interface_name, ipv6))
            })
            .filter_map(|(iname, ipv6)| {
                interfaces()
                    .filter(|ia2| ia2.interface_name == iname)
                    .find_map(|ia2| {
                        ia2.address
                            .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip().into()))
                            .map(|ip: std::net::Ipv4Addr| (iname.clone(), ip, ipv6))
                    })
            })
            .next()
            .ok_or_else(|| {
                error!("Cannot find network interface suitable for mDNS broadcasting");
                ErrorCode::StdIoError
            })?;

        info!(
            "Will use network interface {} with {}/{} for mDNS",
            iname, ip, ipv6
        );

        Ok((ip.octets().into(), ipv6.octets().into(), 0 as _))
    }

    let (ipv4_addr, ipv6_addr, interface) = initialize_network()?;

    use rs_matter::mdns::{
        Host, MDNS_IPV4_BROADCAST_ADDR, MDNS_IPV6_BROADCAST_ADDR, MDNS_SOCKET_BIND_ADDR,
    };

    // NOTE:
    // When using a custom UDP stack (e.g. for `no_std` environments), replace with a UDP socket bind + multicast join for your custom UDP stack
    // The returned socket should be splittable into two halves, where each half implements `UdpSend` and `UdpReceive` respectively
    let socket = async_io::Async::<UdpSocket>::bind(MDNS_SOCKET_BIND_ADDR)?;
    socket
        .get_ref()
        .join_multicast_v6(&MDNS_IPV6_BROADCAST_ADDR, interface)?;
    socket
        .get_ref()
        .join_multicast_v4(&MDNS_IPV4_BROADCAST_ADDR, &ipv4_addr)?;

    matter
        .run_builtin_mdns(
            &socket,
            &socket,
            Host {
                id: 0,
                hostname: "rs-matter-demo",
                ip: ipv4_addr.octets(),
                ipv6: Some(ipv6_addr.octets()),
            },
            Some(interface),
        )
        .await
}
