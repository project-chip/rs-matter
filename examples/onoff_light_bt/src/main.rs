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

//! On/Off Light Example with provisioning over Bluetooth (Linux only)
//!
//! Build with:
//! `cargo build --features os,async-io,async-compat,zeroconf --example onoff_light_bt`
//! or - if you don't use Avahi:
//! `cargo build --features os,async-io,async-compat --example onoff_light_bt`
//!
//! Note that - in the absence of capabilities in the `rs-matter` core to setup and control
//! Wifi networks - this example implements a _fake_ NwCommCluster which only pretends to manage
//! Wifi networks, but in reality expects a pre-existing connection over Ethernet and/or Wifi on
//! the host machine where the example would run.
//!
//! In real-world scenarios, the user is expected to provide an actual NwCommCluster implementation
//! that can manage Wifi networks on the device by using the device-specific APIs.
//! (For (embedded) Linux, this could be done using `nmcli` or `wpa_supplicant`.)

use core::pin::pin;

use std::net::UdpSocket;

use comm::WifiNwCommCluster;
use embassy_futures::select::{select, select4};

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{Duration, Timer};
use log::{info, warn};

use rs_matter::core::{CommissioningData, Matter};
use rs_matter::data_model::cluster_basic_information::BasicInfoConfig;
use rs_matter::data_model::cluster_on_off;
use rs_matter::data_model::core::IMBuffer;
use rs_matter::data_model::device_types::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::data_model::objects::*;
use rs_matter::data_model::root_endpoint;
use rs_matter::data_model::sdm::wifi_nw_diagnostics::{
    self, WiFiSecurity, WiFiVersion, WifiNwDiagCluster, WifiNwDiagData,
};
use rs_matter::data_model::subscriptions::Subscriptions;
use rs_matter::data_model::system_model::descriptor;
use rs_matter::error::Error;
use rs_matter::mdns::MdnsService;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::Psm;
use rs_matter::respond::DefaultResponder;
use rs_matter::secure_channel::spake2p::VerifierData;
use rs_matter::transport::core::MATTER_SOCKET_BIND_ADDR;
use rs_matter::transport::network::btp::{Btp, BtpContext};
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::utils::sync::{blocking::raw::StdRawMutex, Notification};
use rs_matter::MATTER_PORT;

mod comm;
// TODO: Now that we have two examples, move common stuff to a `common` filder
// The `dev_att` module would be a prime candidate for this.
mod dev_att;

static BTP_CONTEXT: BtpContext<StdRawMutex> = BtpContext::<StdRawMutex>::new();

fn main() -> Result<(), Error> {
    let thread = std::thread::Builder::new()
        // Increase the stack size until the example can work without stack blowups.
        // Note that the used stack size increases exponentially by lowering the level of compiler optimizations,
        // as lower optimization settings prevent the Rust compiler from inlining constructor functions
        // which often results in (unnecessary) memory moves and increased stack utilization:
        // e.g., an opt-level of "0" will require a several times' larger stack.
        //
        // Optimizing/lowering `rs-matter` memory consumption is an ongoing topic.
        .stack_size(200 * 1024)
        .spawn(run)
        .unwrap();

    thread.join().unwrap()
}

fn run() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    info!(
        "Matter memory: Matter={}B, IM Buffers={}B",
        core::mem::size_of::<Matter>(),
        core::mem::size_of::<PooledBuffers<10, NoopRawMutex, IMBuffer>>()
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

    let matter = Matter::new(
        &dev_det,
        &dev_att,
        // NOTE:
        // For `no_std` environments, provide your own epoch and rand functions here
        MdnsService::Builtin,
        rs_matter::utils::epoch::sys_epoch,
        rs_matter::utils::rand::sys_rand,
        MATTER_PORT,
    );

    let dev_comm = CommissioningData {
        // TODO: Hard-coded for now
        verifier: VerifierData::new_with_pw(123456, matter.rand()),
        discriminator: 250,
    };

    let discovery_caps = DiscoveryCapabilities::new(false, true, false);

    matter.initialize_transport_buffers()?;

    info!("Matter initialized");

    let buffers = PooledBuffers::<10, NoopRawMutex, _>::new(0);

    info!("IM buffers initialized");

    let mut mdns = pin!(run_mdns(&matter));

    let on_off = cluster_on_off::OnOffCluster::new(Dataver::new_rand(matter.rand()));

    let subscriptions = Subscriptions::<3>::new();

    let wifi_complete = Notification::new();

    // Assemble our Data Model handler by composing the predefined Root Endpoint handler with our custom On/Off clusters
    let dm_handler = HandlerCompat(dm_handler(&matter, &on_off, &wifi_complete));

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&matter, &buffers, &subscriptions, dm_handler);
    info!(
        "Responder memory: Responder={}B, Runner={}B",
        core::mem::size_of_val(&responder),
        core::mem::size_of_val(&responder.run::<4, 4>())
    );

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultenously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    let mut respond = pin!(responder.run::<4, 4>());

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
    // Replace with your own persister for e.g. `no_std` environments
    let mut psm: Psm<4096> = Psm::new();
    let mut persist = pin!(psm.run(std::env::temp_dir().join("rs-matter"), &matter));

    if !matter.is_commissioned() {
        // Not commissioned yet, start commissioning first

        let btp = Btp::new_builtin(&BTP_CONTEXT);
        let mut bluetooth = pin!(btp.run("MT", &dev_det, &dev_comm));

        let mut transport = pin!(matter.run(&btp, &btp, Some((dev_comm, discovery_caps))));

        let mut wifi_complete_task = pin!(async {
            wifi_complete.wait().await;
            warn!(
                "Wifi setup complete, giving 4 seconds to BTP to finish any outstanding messages"
            );

            Timer::after(Duration::from_secs(4)).await;

            Ok(())
        });

        let all = select4(
            &mut transport,
            &mut bluetooth,
            select(&mut wifi_complete_task, &mut persist).coalesce(),
            select(&mut respond, &mut device).coalesce(),
        );

        // NOTE:
        // Replace with a different executor for e.g. `no_std` environments
        futures_lite::future::block_on(async_compat::Compat::new(all.coalesce()))?;

        matter.reset_transport()?;
    }

    // NOTE:
    // When using a custom UDP stack (e.g. for `no_std` environments), replace with a UDP socket bind for your custom UDP stack
    // The returned socket should be splittable into two halves, where each half implements `UdpSend` and `UdpReceive` respectively
    let udp = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter transport
    let mut transport = pin!(matter.run(&udp, &udp, None));

    // Combine all async tasks in a single one
    let all = select4(
        &mut transport,
        &mut mdns,
        &mut persist,
        select(&mut respond, &mut device).coalesce(),
    );

    // NOTE:
    // Replace with a different executor for e.g. `no_std` environments
    futures_lite::future::block_on(async_compat::Compat::new(all.coalesce()))
}

const NODE: Node<'static> = Node {
    id: 0,
    endpoints: &[
        root_endpoint::endpoint(0, root_endpoint::OperNwType::Wifi),
        Endpoint {
            id: 1,
            device_type: DEV_TYPE_ON_OFF_LIGHT,
            clusters: &[descriptor::CLUSTER, cluster_on_off::CLUSTER],
        },
    ],
};

fn dm_handler<'a>(
    matter: &'a Matter<'a>,
    on_off: &'a cluster_on_off::OnOffCluster,
    wifi_complete: &'a Notification<NoopRawMutex>,
) -> impl Metadata + NonBlockingHandler + 'a {
    (
        NODE,
        root_endpoint::handler(
            0,
            HandlerCompat(WifiNwCommCluster::new(
                Dataver::new_rand(matter.rand()),
                &wifi_complete,
            )),
            wifi_nw_diagnostics::ID,
            HandlerCompat(WifiNwDiagCluster::new(
                Dataver::new_rand(matter.rand()),
                WifiNwDiagData {
                    bssid: [0; 6],
                    security_type: WiFiSecurity::Wpa2Personal,
                    wifi_version: WiFiVersion::B,
                    channel_number: 20,
                    rssi: 0,
                },
            )),
            false,
            matter.rand(),
        )
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
                ip: ipv4_addr.octets(),
                ipv6: Some(ipv6_addr.octets()),
            },
            Some(interface),
        )
        .await
}
