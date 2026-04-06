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

//! Full in-process commissioning integration test.
//!
//! Exercises the complete flow:
//! 1. Device (in-process) starts with a full DataModel + mDNS responder
//! 2. Controller discovers the device via mDNS
//! 3. PASE session established over UDP
//! 4. IM read on OnOff attribute (ep 1) — assert initial value is `false`
//! 5. IM invoke Toggle command
//! 6. IM read again — assert value flipped to `true`
//!
//! ## Platform support
//!
//! - **Linux** (no extra features): uses `BuiltinMdnsResponder` + builtin
//!   multicast querier on the device and controller sides respectively.
//! - **macOS** (with `astro-dnssd` feature): uses `AstroMdnsResponder` on the
//!   device side (integrates with the OS Bonjour daemon, so no port-5353
//!   conflict) and `astro::discover_commissionable` on the controller side.

#![cfg(all(
    feature = "std",
    feature = "async-io",
    any(target_os = "linux", feature = "astro-dnssd")
))]

use core::pin::pin;
use std::net::UdpSocket;

use embassy_futures::select::{select, select4, Either};
use embassy_time::{Duration, Timer};

use log::{debug, info, warn};

use rand_core::RngCore;

use rs_matter::persist::DummyKvBlobStoreAccess;
use socket2::{Domain, Protocol, Socket, Type};

use static_cell::StaticCell;

use rs_matter::crypto::{test_only_crypto, Crypto};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::level_control::LevelControlHooks;
use rs_matter::dm::clusters::net_comm::NetworkType;
use rs_matter::dm::clusters::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints;
use rs_matter::dm::events::NO_EVENTS;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::subscriptions::DefaultSubscriptions;
use rs_matter::dm::IMBuffer;
use rs_matter::dm::{
    Async, AsyncHandler, AsyncMetadata, DataModel, Dataver, EmptyHandler, Endpoint, EpClMatcher,
    Node,
};
use rs_matter::error::Error;
use rs_matter::im::client::ImClient;
use rs_matter::im::{AttrResp, CmdResp, IMStatusCode};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::{PaseInitiator, MAX_COMM_WINDOW_TIMEOUT_SECS};
use rs_matter::tlv::{TLVElement, TLVTag, TLVWrite};
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::mdns::{CommissionableFilter, DiscoveredDevice};
use rs_matter::transport::network::{Address, NoNetwork, SocketAddr, SocketAddrV6};
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::epoch::sys_epoch;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::utils::storage::WriteBuf;
use rs_matter::{clusters, devices, Matter, MATTER_PORT};

use crate::common::{init_env_logger, run_device_controller, run_with_transport};

#[allow(dead_code)]
mod common;

/// Passcode used by `TEST_DEV_COMM`
const TEST_PASSCODE: u32 = 20202021;
/// Discriminator used by `TEST_DEV_COMM`
const TEST_DISCRIMINATOR: u16 = 3840;

const CLUSTER_ON_OFF: u32 = 0x0006;
const ATTR_ON_OFF: u32 = 0x0000;
const CMD_TOGGLE: u32 = 0x0002;
const PASE_TIMEOUT_SECS: u64 = 30;
const IM_TIMEOUT_SECS: u64 = 10;
const DISCOVERY_TIMEOUT_MS: u32 = 30_000;
const MAX_DEVICE_ADDRESSES: usize = 4;
#[cfg(not(feature = "astro-dnssd"))]
const MAX_DISCOVERED_DEVICES: usize = 8;

static DEVICE_MATTER: StaticCell<Matter> = StaticCell::new();
static DEVICE_BUFFERS: StaticCell<PooledBuffers<10, IMBuffer>> = StaticCell::new();
static DEVICE_SUBSCRIPTIONS: StaticCell<DefaultSubscriptions> = StaticCell::new();
static CTRL_MATTER: StaticCell<Matter> = StaticCell::new();

// ============================================================================
// Device data model — copied from examples/src/bin/onoff_light.rs
// ============================================================================

const NODE: Node<'static> = Node {
    id: 0,
    endpoints: &[
        endpoints::root_endpoint(NetworkType::Ethernet),
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters: clusters!(desc::DescHandler::CLUSTER, TestOnOffDeviceLogic::CLUSTER),
        },
    ],
};

fn dm_handler<'a, OH: OnOffHooks, LH: LevelControlHooks>(
    mut rand: impl RngCore + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
) -> impl AsyncMetadata + AsyncHandler + 'a {
    (
        NODE,
        endpoints::with_eth(
            &(),
            &UnixNetifs,
            rand,
            endpoints::with_sys(
                &false,
                rand,
                EmptyHandler
                    .chain(
                        EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                        Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                        on_off::HandlerAsyncAdaptor(on_off),
                    ),
            ),
        ),
    )
}

#[test]
fn test_commissioning_onoff_cluster() {
    let thread = std::thread::spawn(|| {
        init_env_logger();
        futures_lite::future::block_on(async {
            run_test().await.unwrap();
        });
    });
    thread.join().unwrap();
}

async fn run_test() -> Result<(), Error> {
    let device_matter = DEVICE_MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        sys_epoch,
        MATTER_PORT,
    ));
    device_matter.initialize_transport_buffers()?;

    let device_crypto = test_only_crypto();
    let mut rand = device_crypto.rand()?;

    let device_buffers = DEVICE_BUFFERS.uninit().init_with(PooledBuffers::init(0));
    let device_subscriptions = DEVICE_SUBSCRIPTIONS
        .uninit()
        .init_with(DefaultSubscriptions::init());

    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(false),
    );

    let dm = DataModel::new(
        device_matter,
        &device_crypto,
        device_buffers,
        device_subscriptions,
        NO_EVENTS,
        dm_handler(rand, &on_off_handler),
        DummyKvBlobStoreAccess,
    );

    // Open commissioning window before starting the mDNS responder so the
    // `wait_mdns` signal is already set when the broadcast loop first runs.
    device_matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &device_crypto, &())?;

    let device_socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;
    let responder = DefaultResponder::new(&dm);

    let ctrl_matter = CTRL_MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        sys_epoch,
        0,
    ));
    ctrl_matter.initialize_transport_buffers()?;
    let ctrl_crypto = test_only_crypto();
    let ctrl_socket = create_dual_stack_socket()?;

    info!("Device and controller initialized, starting commissioning test...");

    let device_fut = async {
        select4(
            device_matter.run(&device_crypto, &device_socket, &device_socket, NoNetwork),
            // `run_mdns` dispatches to the right backend for the current platform:
            // builtin multicast on Linux, AstroMdnsResponder (Bonjour) on macOS.
            common::mdns::run_mdns(device_matter, test_only_crypto(), dm.change_notify()),
            responder.run::<4, 4>(),
            dm.run(),
        )
        .coalesce()
        .await
    };

    let controller_fut = run_with_transport(
        ctrl_matter.run(&ctrl_crypto, &ctrl_socket, &ctrl_socket, NoNetwork),
        run_controller_flow(ctrl_matter, &ctrl_crypto),
    );

    run_device_controller(device_fut, controller_fut).await
}

async fn run_controller_flow<C: Crypto>(matter: &Matter<'_>, crypto: &C) -> Result<(), Error> {
    info!("=== Phase 1: mDNS Discovery ===");
    let peer_addr = discover_and_resolve_device(DISCOVERY_TIMEOUT_MS).await?;

    info!("=== Phase 2: PASE Session Establishment ===");
    establish_pase_session(matter, crypto, peer_addr, TEST_PASSCODE).await?;

    info!("=== Phase 3: Interaction Model Operations ===");
    test_onoff_cluster(matter).await?;

    info!("=== All commissioning test phases completed successfully! ===");
    Ok(())
}

// ============================================================================
// Phase 1: mDNS Discovery
// ============================================================================

async fn discover_and_resolve_device(timeout_ms: u32) -> Result<Address, Error> {
    info!("Starting mDNS discovery with discriminator: {TEST_DISCRIMINATOR}");
    let filter = CommissionableFilter {
        discriminator: Some(TEST_DISCRIMINATOR),
        ..Default::default()
    };
    let device = discover_device::<MAX_DEVICE_ADDRESSES>(&filter, timeout_ms).await?;

    info!(
        "Discovered: {} with {} address(es), discriminator={}",
        device.instance_name,
        device.addresses().len(),
        device.discriminator,
    );
    for addr in device.addresses() {
        info!("  Address: {addr}");
    }

    resolve_device_address(&device)
}

#[cfg(feature = "astro-dnssd")]
async fn discover_device<const A: usize>(
    discriminator: u16,
    timeout_ms: u32,
) -> Result<DiscoveredDevice<A>, Error> {
    use rs_matter::transport::network::mdns::astro;

    let (tx, rx) = async_channel::bounded(1);
    std::thread::spawn(move || {
        let filter = CommissionableFilter {
            discriminator: Some(discriminator),
            ..Default::default()
        };
        let _ = tx.send_blocking(astro::discover_commissionable::<A>(&filter, timeout_ms));
    });

    let devices = rx
        .recv()
        .await
        .map_err(|_| Error::from(rs_matter::error::ErrorCode::Failure))??;

    devices.into_iter().next().ok_or_else(|| {
        warn!("No devices found matching discriminator {discriminator}");
        rs_matter::error::ErrorCode::NotFound.into()
    })
}

#[cfg(not(feature = "astro-dnssd"))]
async fn discover_device<const A: usize>(
    filter: &CommissionableFilter,
    timeout_ms: u32,
) -> Result<DiscoveredDevice<A>, Error> {
    use rs_matter::transport::network::mdns::builtin::discover_commissionable;
    use rs_matter::transport::network::mdns::{MDNS_IPV4_BROADCAST_ADDR, MDNS_IPV6_BROADCAST_ADDR};

    // Create a dedicated mDNS socket bound to port 5353
    // This is separate from the Matter communication socket because mDNS
    // responses are sent as multicast to port 5353
    let mdns_socket = create_mdns_socket()?;

    let (ipv4_addr, ipv6_available, interface) = find_network_interface()?;

    // Join multicast groups
    if ipv6_available {
        mdns_socket
            .get_ref()
            .join_multicast_v6(&MDNS_IPV6_BROADCAST_ADDR, interface)
            .map_err(|e| {
                warn!("Failed to join IPv6 multicast: {e}");
                rs_matter::error::ErrorCode::NoNetworkInterface
            })?;
    }

    mdns_socket
        .get_ref()
        .join_multicast_v4(&MDNS_IPV4_BROADCAST_ADDR, &ipv4_addr)
        .map_err(|e| {
            warn!("Failed to join IPv4 multicast: {e}");
            rs_matter::error::ErrorCode::NoNetworkInterface
        })?;

    info!("Joined multicast groups on interface (IPv6: {ipv6_available})");

    let ipv6_interface = if ipv6_available {
        Some(interface)
    } else {
        None
    };

    let mut mdns_buf = [0u8; 1500];
    let devices = discover_commissionable::<_, _, MAX_DISCOVERED_DEVICES, A>(
        &mut &mdns_socket,
        &mut &mdns_socket,
        filter,
        timeout_ms,
        &mut mdns_buf,
        Some(ipv4_addr),
        ipv6_interface,
    )
    .await?;

    devices.into_iter().next().ok_or_else(|| {
        warn!(
            "No devices found matching discriminator {:#?}",
            filter.discriminator
        );
        rs_matter::error::ErrorCode::NotFound.into()
    })
}

fn resolve_device_address<const A: usize>(device: &DiscoveredDevice<A>) -> Result<Address, Error> {
    let interface_index = get_default_interface_index().unwrap_or(0);

    let device_addr = device
        .addresses()
        .iter()
        .filter(|addr| {
            if let std::net::IpAddr::V6(v6) = addr {
                // fe80::1 is often returned incorrectly by DNS resolution on macOS
                if v6.segments() == [0xfe80, 0, 0, 0, 0, 0, 0, 1] {
                    debug!("Skipping fe80::1 (likely incorrect DNS resolution)");
                    return false;
                }
            }
            true
        })
        .min_by_key(|addr| match addr {
            std::net::IpAddr::V4(_) => 0, // prefer IPv4 to avoid scope-id issues
            std::net::IpAddr::V6(_) => 1,
        })
        .ok_or_else(|| {
            warn!("Discovered device has no usable address");
            rs_matter::error::ErrorCode::InvalidData
        })?;

    info!("Using address: {}:{}", device_addr, device.port);

    let peer_addr = match device_addr {
        std::net::IpAddr::V4(v4) => {
            let ipv6 = v4.to_ipv6_mapped();
            Address::Udp(SocketAddr::V6(SocketAddrV6::new(ipv6, device.port, 0, 0)))
        }
        std::net::IpAddr::V6(v6) => {
            let scope_id = if is_ipv6_link_local(v6) {
                interface_index
            } else {
                0
            };
            Address::Udp(SocketAddr::V6(SocketAddrV6::new(
                *v6,
                device.port,
                0,
                scope_id,
            )))
        }
    };

    info!("Peer address: {peer_addr}");
    Ok(peer_addr)
}

// ============================================================================
// Phase 2: PASE Session
// ============================================================================

async fn establish_pase_session<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    peer_addr: Address,
    passcode: u32,
) -> Result<(), Error> {
    let mut exchange = Exchange::initiate_unsecured(matter, crypto, peer_addr).await?;
    info!("Unsecured exchange initiated: {}", exchange.id());

    let mut pase_fut = pin!(PaseInitiator::initiate(&mut exchange, crypto, passcode));
    let mut timeout = pin!(Timer::after(Duration::from_secs(PASE_TIMEOUT_SECS)));

    match select(&mut pase_fut, &mut timeout).await {
        Either::First(Ok(())) => {
            info!("PASE session established successfully!");
            Ok(())
        }
        Either::First(Err(e)) => {
            warn!("PASE handshake failed: {e:?}");
            Err(e)
        }
        Either::Second(_) => {
            warn!("PASE handshake timed out after {PASE_TIMEOUT_SECS} seconds");
            Err(rs_matter::error::ErrorCode::RxTimeout.into())
        }
    }
}

// ============================================================================
// Phase 3: Interaction Model Operations
// ============================================================================

async fn test_onoff_cluster(matter: &Matter<'_>) -> Result<(), Error> {
    info!("Step 3a: Reading initial OnOff attribute...");
    let initial_value = read_onoff_with_timeout(matter).await?;
    info!("Initial OnOff value: {initial_value}");
    assert!(!initial_value, "Expected initial OnOff value to be false");

    info!("Step 3b: Invoking Toggle command...");
    let status = invoke_toggle_with_timeout(matter).await?;
    info!("Toggle completed with status: {status:?}");

    info!("Step 3c: Verifying toggle effect...");
    let final_value = read_onoff_with_timeout(matter).await?;
    info!("Final OnOff value: {final_value}");

    assert!(
        final_value,
        "Expected OnOff to be true after toggle, got {final_value}"
    );
    info!("Toggle verified: {initial_value} -> {final_value}");

    Ok(())
}

async fn read_onoff_with_timeout(matter: &Matter<'_>) -> Result<bool, Error> {
    let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
    debug!("IM read exchange initiated: {}", exchange.id());

    let mut read_fut = pin!(read_onoff(&mut exchange));
    let mut timeout = pin!(Timer::after(Duration::from_secs(IM_TIMEOUT_SECS)));

    match select(&mut read_fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => {
            warn!("Read operation timed out");
            Err(rs_matter::error::ErrorCode::RxTimeout.into())
        }
    }
}

async fn read_onoff(exchange: &mut Exchange<'_>) -> Result<bool, Error> {
    let resp = ImClient::read_single_attr(exchange, 1, CLUSTER_ON_OFF, ATTR_ON_OFF, true).await?;

    match resp {
        AttrResp::Data(data) => data.data.bool(),
        AttrResp::Status(status) => {
            warn!("Read returned status: {:?}", status.status);
            Err(rs_matter::error::ErrorCode::InvalidData.into())
        }
    }
}

async fn invoke_toggle_with_timeout(matter: &Matter<'_>) -> Result<IMStatusCode, Error> {
    let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
    debug!("Invoke exchange initiated: {}", exchange.id());

    let mut invoke_fut = pin!(invoke_toggle(&mut exchange));
    let mut timeout = pin!(Timer::after(Duration::from_secs(IM_TIMEOUT_SECS)));

    match select(&mut invoke_fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => {
            warn!("Invoke operation timed out");
            Err(rs_matter::error::ErrorCode::RxTimeout.into())
        }
    }
}

async fn invoke_toggle(exchange: &mut Exchange<'_>) -> Result<IMStatusCode, Error> {
    let mut buf = [0u8; 8];
    let tail = {
        let mut wb = WriteBuf::new(&mut buf);
        wb.start_struct(&TLVTag::Anonymous)?;
        wb.end_container()?;
        wb.get_tail()
    };

    let resp = ImClient::invoke_single_cmd(
        exchange,
        1,
        CLUSTER_ON_OFF,
        CMD_TOGGLE,
        TLVElement::new(&buf[..tail]),
        None,
    )
    .await?;

    match resp {
        CmdResp::Status(s) => Ok(s.status.status),
        CmdResp::Cmd(_) => Ok(IMStatusCode::Success),
    }
}

// ============================================================================
// Network Utilities
// ============================================================================

/// Create a dual-stack UDP socket for Matter communication (ephemeral port).
fn create_dual_stack_socket() -> Result<async_io::Async<UdpSocket>, Error> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_reuse_address(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_only_v6(false)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    let bind_addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0);
    socket
        .bind(&bind_addr.into())
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    let socket: UdpSocket = socket.into();
    async_io::Async::new_nonblocking(socket)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface.into())
}

/// Create a controller-side mDNS discovery socket.
///
/// `SO_REUSEPORT` lets this socket share port 5353 with the device's mDNS
/// socket when both run in the same process. Multicast loopback ensures
/// the device's broadcasts are receivable on the same host.
#[cfg(not(feature = "astro-dnssd"))]
fn create_mdns_socket() -> Result<async_io::Async<UdpSocket>, Error> {
    use rs_matter::transport::network::mdns::MDNS_PORT;

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_reuse_address(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_reuse_port(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_only_v6(false)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_multicast_loop_v4(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_multicast_loop_v6(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    let bind_addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0);
    socket
        .bind(&bind_addr.into())
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    let socket: UdpSocket = socket.into();
    async_io::Async::new_nonblocking(socket)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface.into())
}

/// Find a suitable network interface for mDNS.
///
/// Returns `(ipv4_addr, ipv6_addr_opt, interface_index)`.
/// Falls back to IPv4-only when no dual-stack interface is available.
#[cfg(not(feature = "astro-dnssd"))]
fn find_network_interface() -> Result<(std::net::Ipv4Addr, bool, u32), Error> {
    use nix::net::if_::InterfaceFlags;
    use nix::sys::socket::SockaddrIn6;

    let interfaces = || {
        nix::ifaddrs::getifaddrs().unwrap().filter(|ia| {
            ia.flags.contains(InterfaceFlags::IFF_UP)
                && ia
                    .flags
                    .intersects(InterfaceFlags::IFF_BROADCAST | InterfaceFlags::IFF_MULTICAST)
                && !ia
                    .flags
                    .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
        })
    };

    // Prefer interface with both IPv4 and IPv6
    let result = interfaces()
        .filter_map(|ia| {
            ia.address
                .and_then(|addr| addr.as_sockaddr_in6().map(SockaddrIn6::ip))
                .map(|_ipv6| ia.interface_name.clone())
        })
        .find_map(|iname| {
            interfaces()
                .filter(|ia2| ia2.interface_name == iname)
                .find_map(|ia2| {
                    ia2.address
                        .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip()))
                        .map(|ip: std::net::Ipv4Addr| (iname.clone(), ip, true))
                })
        });

    // Fallback to IPv4 only
    let (iname, ip, ipv6_available) = result
        .or_else(|| {
            interfaces().find_map(|ia| {
                ia.address
                    .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip()))
                    .map(|ip: std::net::Ipv4Addr| (ia.interface_name.clone(), ip, false))
            })
        })
        .ok_or_else(|| {
            warn!("Cannot find network interface suitable for mDNS");
            rs_matter::error::ErrorCode::NoNetworkInterface
        })?;

    let if_index = nix::net::if_::if_nametoindex::<str>(iname.as_str()).unwrap_or(0);

    info!("Using network interface {iname} (index {if_index}) with {ip} (IPv6: {ipv6_available})");

    Ok((ip, ipv6_available, if_index))
}

fn get_default_interface_index() -> Option<u32> {
    use nix::net::if_::InterfaceFlags;

    nix::ifaddrs::getifaddrs()
        .ok()?
        .filter(|ia| {
            ia.flags.contains(InterfaceFlags::IFF_UP)
                && ia
                    .flags
                    .intersects(InterfaceFlags::IFF_BROADCAST | InterfaceFlags::IFF_MULTICAST)
                && !ia
                    .flags
                    .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
        })
        .find_map(|ia| {
            let has_ipv6 = ia
                .address
                .map(|addr| addr.as_sockaddr_in6().is_some())
                .unwrap_or(false);
            if has_ipv6 {
                nix::net::if_::if_nametoindex::<str>(ia.interface_name.as_str()).ok()
            } else {
                None
            }
        })
}

fn is_ipv6_link_local(addr: &std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}
