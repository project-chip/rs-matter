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
use rs_matter::mdns::{MdnsRunBuffers, MdnsService};
use rs_matter::secure_channel::spake2p::VerifierData;
use rs_matter::transport::core::RunBuffers;
use rs_matter::transport::network::{Ipv4Addr, Ipv6Addr, NetworkStack};
use rs_matter::utils::select::EitherUnwrap;

mod dev_att;

#[cfg(feature = "std")]
fn main() -> Result<(), Error> {
    let thread = std::thread::Builder::new()
        .stack_size(150 * 1024)
        .spawn(run)
        .unwrap();

    thread.join().unwrap()
}

// NOTE (no_std): For no_std, name this entry point according to your MCU platform
#[cfg(not(feature = "std"))]
#[no_mangle]
fn app_main() {
    run().unwrap();
}

fn run() -> Result<(), Error> {
    initialize_logger();

    info!(
        "Matter memory: mDNS={}, Matter={}, MdnsBuffers={}, RunBuffers={}",
        core::mem::size_of::<MdnsService>(),
        core::mem::size_of::<Matter>(),
        core::mem::size_of::<MdnsRunBuffers>(),
        core::mem::size_of::<RunBuffers>(),
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

    let (ipv4_addr, ipv6_addr, interface) = initialize_network()?;

    let dev_att = dev_att::HardCodedDevAtt::new();

    #[cfg(feature = "std")]
    let epoch = rs_matter::utils::epoch::sys_epoch;

    #[cfg(feature = "std")]
    let rand = rs_matter::utils::rand::sys_rand;

    // NOTE (no_std): For no_std, provide your own function here
    #[cfg(not(feature = "std"))]
    let epoch = rs_matter::utils::epoch::dummy_epoch;

    // NOTE (no_std): For no_std, provide your own function here
    #[cfg(not(feature = "std"))]
    let rand = rs_matter::utils::rand::dummy_rand;

    let mdns = MdnsService::new(
        0,
        "rs-matter-demo",
        ipv4_addr.octets(),
        Some((ipv6_addr.octets(), interface)),
        &dev_det,
        rs_matter::MATTER_PORT,
    );

    info!("mDNS initialized");

    let matter = Matter::new(
        // vid/pid should match those in the DAC
        &dev_det,
        &dev_att,
        &mdns,
        epoch,
        rand,
        rs_matter::MATTER_PORT,
    );

    info!("Matter initialized");

    #[cfg(all(feature = "std", not(target_os = "espidf")))]
    let mut psm = rs_matter::persist::Psm::new(&matter, std::env::temp_dir().join("rs-matter"))?;

    let handler = HandlerCompat(handler(&matter));

    // When using a custom UDP stack, remove the network stack initialization below
    // and call `Matter::run_piped()` instead, by utilizing the TX & RX `Pipe` structs
    // to push/pull your UDP packets from/to the Matter stack.
    // Ditto for `MdnsService`.
    //
    // When using the `embassy-net` feature (as opposed to the Rust Standard Library network stack),
    // this initialization would be more complex.
    let stack = NetworkStack::new();

    let mut mdns_buffers = MdnsRunBuffers::new();
    let mut mdns_runner = pin!(mdns.run(&stack, &mut mdns_buffers));

    let mut buffers = RunBuffers::new();
    let runner = matter.run(
        &stack,
        &mut buffers,
        CommissioningData {
            // TODO: Hard-coded for now
            verifier: VerifierData::new_with_pw(123456, *matter.borrow()),
            discriminator: 250,
        },
        &handler,
    );

    info!(
        "Matter transport runner memory: {}",
        core::mem::size_of_val(&runner)
    );

    let mut runner = pin!(runner);

    #[cfg(all(feature = "std", not(target_os = "espidf")))]
    let mut psm_runner = pin!(psm.run());

    #[cfg(not(all(feature = "std", not(target_os = "espidf"))))]
    let mut psm_runner = pin!(core::future::pending());

    let runner = select3(&mut runner, &mut mdns_runner, &mut psm_runner);

    #[cfg(feature = "std")]
    async_io::block_on(runner).unwrap()?;

    // NOTE (no_std): For no_std, replace with your own more efficient no_std executor,
    // because the executor used below is a simple busy-loop poller
    #[cfg(not(feature = "std"))]
    embassy_futures::block_on(&mut runner).unwrap()?;

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

// NOTE (no_std): For no_std, implement here your own way of initializing the logger
#[cfg(all(not(feature = "std"), not(target_os = "espidf")))]
#[inline(never)]
fn initialize_logger() {}

// NOTE (no_std): For no_std, implement here your own way of initializing the network
#[cfg(all(not(feature = "std"), not(target_os = "espidf")))]
#[inline(never)]
fn initialize_network() -> Result<(Ipv4Addr, Ipv6Addr, u32), Error> {
    Ok((Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED, 0))
}

#[cfg(all(feature = "std", not(target_os = "espidf")))]
#[inline(never)]
fn initialize_logger() {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
}

#[cfg(all(feature = "std", not(target_os = "espidf")))]
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
                        .map(|ip| (iname.clone(), ip, ipv6))
                })
        })
        .next()
        .ok_or_else(|| {
            error!("Cannot find network interface suitable for mDNS broadcasting");
            ErrorCode::Network
        })?;

    info!(
        "Will use network interface {} with {}/{} for mDNS",
        iname, ip, ipv6
    );

    Ok((ip, ipv6, 0 as _))
}

#[cfg(target_os = "espidf")]
#[inline(never)]
fn initialize_logger() {
    esp_idf_svc::log::EspLogger::initialize_default();
}

#[cfg(target_os = "espidf")]
#[inline(never)]
fn initialize_network() -> Result<(Ipv4Addr, Ipv6Addr, u32), Error> {
    use core::time::Duration;

    use embedded_svc::wifi::{AuthMethod, ClientConfiguration, Configuration};
    use esp_idf_hal::prelude::Peripherals;
    use esp_idf_svc::handle::RawHandle;
    use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
    use esp_idf_svc::{eventloop::EspSystemEventLoop, nvs::EspDefaultNvsPartition};
    use esp_idf_sys::{
        self as _, esp, esp_ip6_addr_t, esp_netif_create_ip6_linklocal, esp_netif_get_ip6_linklocal,
    }; // If using the `binstart` feature of `esp-idf-sys`, always keep this module imported

    const SSID: &'static str = env!("WIFI_SSID");
    const PASSWORD: &'static str = env!("WIFI_PASS");

    #[allow(clippy::needless_update)]
    {
        // VFS is necessary for poll-based async IO
        esp_idf_sys::esp!(unsafe {
            esp_idf_sys::esp_vfs_eventfd_register(&esp_idf_sys::esp_vfs_eventfd_config_t {
                max_fds: 5,
                ..Default::default()
            })
        })?;
    }

    let peripherals = Peripherals::take().unwrap();
    let sys_loop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    let mut wifi = EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs))?;

    let mut bwifi = BlockingWifi::wrap(&mut wifi, sys_loop)?;

    let wifi_configuration: Configuration = Configuration::Client(ClientConfiguration {
        ssid: SSID.into(),
        bssid: None,
        auth_method: AuthMethod::WPA2Personal,
        password: PASSWORD.into(),
        channel: None,
    });

    bwifi.set_configuration(&wifi_configuration)?;

    bwifi.start()?;
    info!("Wifi started");

    bwifi.connect()?;
    info!("Wifi connected");

    esp!(unsafe {
        esp_netif_create_ip6_linklocal(bwifi.wifi_mut().sta_netif_mut().handle() as _)
    })?;

    bwifi.wait_netif_up()?;
    info!("Wifi netif up");

    let ip_info = wifi.sta_netif().get_ip_info()?;

    let mut ipv6: esp_ip6_addr_t = Default::default();

    info!("Waiting for IPv6 address");

    while esp!(unsafe { esp_netif_get_ip6_linklocal(wifi.sta_netif().handle() as _, &mut ipv6) })
        .is_err()
    {
        info!("Waiting...");
        std::thread::sleep(Duration::from_secs(2));
    }

    info!("Wifi DHCP info: {:?}, IPv6: {:?}", ip_info, ipv6.addr);

    let ipv4_octets = ip_info.ip.octets();
    let ipv6_octets = [
        ipv6.addr[0].to_le_bytes()[0],
        ipv6.addr[0].to_le_bytes()[1],
        ipv6.addr[0].to_le_bytes()[2],
        ipv6.addr[0].to_le_bytes()[3],
        ipv6.addr[1].to_le_bytes()[0],
        ipv6.addr[1].to_le_bytes()[1],
        ipv6.addr[1].to_le_bytes()[2],
        ipv6.addr[1].to_le_bytes()[3],
        ipv6.addr[2].to_le_bytes()[0],
        ipv6.addr[2].to_le_bytes()[1],
        ipv6.addr[2].to_le_bytes()[2],
        ipv6.addr[2].to_le_bytes()[3],
        ipv6.addr[3].to_le_bytes()[0],
        ipv6.addr[3].to_le_bytes()[1],
        ipv6.addr[3].to_le_bytes()[2],
        ipv6.addr[3].to_le_bytes()[3],
    ];

    let interface = wifi.sta_netif().get_index();

    // Not OK of course, but for a demo this is good enough
    // Wifi will continue to be available and working in the background
    core::mem::forget(wifi);

    Ok((ipv4_octets.into(), ipv6_octets.into(), interface))
}
