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

use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::{select, select4};

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{Duration, Timer};
use log::info;

use rs_matter::core::{BasicCommData, Matter, MATTER_PORT};
use rs_matter::data_model::cluster_basic_information::BasicInfoConfig;
use rs_matter::data_model::cluster_on_off;
use rs_matter::data_model::core::IMBuffer;
use rs_matter::data_model::device_types::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::data_model::objects::*;
use rs_matter::data_model::root_endpoint;
use rs_matter::data_model::subscriptions::Subscriptions;
use rs_matter::data_model::system_model::descriptor;
use rs_matter::error::Error;
use rs_matter::mdns::MdnsService;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::Psm;
use rs_matter::respond::DefaultResponder;
use rs_matter::transport::core::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;

use static_cell::StaticCell;

mod dev_att;

static DEV_DET: BasicInfoConfig = BasicInfoConfig {
    vid: 0xFFF1,
    pid: 0x8001,
    hw_ver: 2,
    sw_ver: 1,
    sw_ver_str: "1",
    serial_no: "aabbccdd",
    device_name: "OnOff Light",
    product_name: "Light123",
    vendor_name: "Vendor PQR",
    sai: None,
    sii: None,
};

static DEV_COMM: BasicCommData = BasicCommData {
    password: 20202021,
    discriminator: 3840,
};

static DEV_ATT: dev_att::HardCodedDevAtt = dev_att::HardCodedDevAtt::new();

static MATTER: StaticCell<Matter> = StaticCell::new();

static BUFFERS: StaticCell<PooledBuffers<10, NoopRawMutex, IMBuffer>> = StaticCell::new();

static SUBSCRIPTIONS: StaticCell<Subscriptions<3>> = StaticCell::new();

static PSM: StaticCell<Psm<4096>> = StaticCell::new();

fn main() -> Result<(), Error> {
    let thread = std::thread::Builder::new()
        // Increase the stack size until the example can work without stack blowups.
        // Note that the used stack size increases exponentially by lowering the level of compiler optimizations,
        // as lower optimization settings prevent the Rust compiler from inlining constructor functions
        // which often results in (unnecessary) memory moves and increased stack utilization:
        // e.g., an opt-level of "0" will require a several times' larger stack.
        //
        // Optimizing/lowering `rs-matter` memory consumption is an ongoing topic.
        .stack_size(45 * 1024)
        .spawn(run)
        .unwrap();

    thread.join().unwrap()
}

fn run() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    info!(
        "Matter memory: Matter (BSS)={}B, IM Buffers (BSS)={}B, Subscriptions (BSS)={}B",
        core::mem::size_of::<Matter>(),
        core::mem::size_of::<PooledBuffers<10, NoopRawMutex, IMBuffer>>(),
        core::mem::size_of::<Subscriptions<3>>()
    );

    let matter = MATTER.uninit().init_with(Matter::init(
        &DEV_DET,
        DEV_COMM,
        &DEV_ATT,
        // NOTE:
        // For `no_std` environments, provide your own epoch and rand functions here
        MdnsService::Builtin,
        rs_matter::utils::epoch::sys_epoch,
        rs_matter::utils::rand::sys_rand,
        MATTER_PORT,
    ));

    matter.initialize_transport_buffers()?;

    info!("Matter initialized");

    let buffers = BUFFERS.uninit().init_with(PooledBuffers::init(0));

    info!("IM buffers initialized");

    let on_off = cluster_on_off::OnOffCluster::new(Dataver::new_rand(matter.rand()));

    let subscriptions = SUBSCRIPTIONS.uninit().init_with(Subscriptions::init());

    // Assemble our Data Model handler by composing the predefined Root Endpoint handler with our custom On/Off clusters
    let dm_handler = HandlerCompat(dm_handler(&matter, &on_off));

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&matter, buffers, &subscriptions, dm_handler);
    info!(
        "Responder memory: Responder (stack)={}B, Runner fut (stack)={}B",
        core::mem::size_of_val(&responder),
        core::mem::size_of_val(&responder.run::<4, 4>())
    );

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    let mut respond = pin!(responder.run::<4, 4>());
    //let mut respond = responder_fut(responder);

    // This is a sample code that simulates state changes triggered by the HAL
    // Changes will be properly communicated to the Matter controllers and other Matter apps (i.e. Google Home, Alexa), thanks to subscriptions
    let mut device = pin!(async {
        loop {
            Timer::after(Duration::from_secs(5)).await;

            on_off.set(!on_off.get());
            subscriptions.notify_changed();

            info!("Lamp toggled");
        }
    });

    // NOTE:
    // When using a custom UDP stack (e.g. for `no_std` environments), replace with a UDP socket bind for your custom UDP stack
    // The returned socket should be splittable into two halves, where each half implements `UdpSend` and `UdpReceive` respectively
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter and mDNS transports
    info!(
        "Transport memory: Transport fut (stack)={}B, mDNS fut (stack)={}B",
        core::mem::size_of_val(&matter.run(&socket, &socket, DiscoveryCapabilities::IP)),
        core::mem::size_of_val(&run_mdns(&matter))
    );

    let mut mdns = pin!(run_mdns(&matter));

    let mut transport = pin!(matter.run(&socket, &socket, DiscoveryCapabilities::IP));

    // NOTE:
    // Replace with your own persister for e.g. `no_std` environments
    let psm = PSM.uninit().init_with(Psm::init());

    info!(
        "Persist memory: Persist (BSS)={}B, Persist fut (stack)={}B",
        core::mem::size_of::<Psm<4096>>(),
        core::mem::size_of_val(&psm.run(std::env::temp_dir().join("rs-matter"), &matter))
    );

    let dir = std::env::temp_dir().join("rs-matter");

    psm.load(&dir, &matter)?;

    let mut persist = pin!(psm.run(dir, &matter));

    // Combine all async tasks in a single one
    let all = select4(
        &mut transport,
        &mut mdns,
        &mut persist,
        select(&mut respond, &mut device).coalesce(),
    );

    // NOTE:
    // Replace with a different executor for e.g. `no_std` environments
    futures_lite::future::block_on(all.coalesce())
}

// #[inline(never)]
// pub fn responder_fut<const N: usize, B, T>(responder: &'static DefaultResponder<N, B, T>) -> Box<impl Future<Output = Result<(), Error>>>
// where
//     B: BufferAccess<IMBuffer>,
//     T: DataModelHandler,
// {
//     Box::new(responder.run::<4, 4>())
// }

const NODE: Node<'static> = Node {
    id: 0,
    endpoints: &[
        root_endpoint::endpoint(0, root_endpoint::OperNwType::Ethernet),
        Endpoint {
            id: 1,
            device_types: &[DEV_TYPE_ON_OFF_LIGHT],
            clusters: &[descriptor::CLUSTER, cluster_on_off::CLUSTER],
        },
    ],
};

fn dm_handler<'a>(
    matter: &'a Matter<'a>,
    on_off: &'a cluster_on_off::OnOffCluster,
) -> impl Metadata + NonBlockingHandler + 'a {
    (
        NODE,
        root_endpoint::eth_handler(0, matter.rand())
            .chain(
                1,
                descriptor::ID,
                descriptor::DescriptorCluster::new(Dataver::new_rand(matter.rand())),
            )
            .chain(1, cluster_on_off::ID, on_off),
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
    #[inline(never)]
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
            &Host {
                id: 0,
                hostname: "rs-matter-demo",
                ip: ipv4_addr,
                ipv6: ipv6_addr,
            },
            Some(ipv4_addr),
            Some(interface),
        )
        .await
}
