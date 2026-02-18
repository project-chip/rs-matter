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

//! Combined integration test for the full Matter commissioning flow.
//!
//! This test exercises the complete flow from discovery to device control:
//! 1. mDNS Discovery - Discover the device on the network
//! 2. PASE Handshake - Authenticate with passcode
//! 3. IM Operations - Read/Write/Invoke on device clusters
//!
//! Uses the `onoff_light` example as the test device.
//!
//! ## Platform Support
//!
//! - **macOS**: Uses `astro-dnssd` for mDNS discovery (wraps native Bonjour)
//! - **Linux**: Uses the builtin mDNS querier with multicast sockets

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{self, Context};
use log::{debug, info, warn};
use socket2::{Domain, Protocol, Socket, Type};

use embassy_futures::select::{select, Either};
use embassy_time::Timer;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::basic_info::BasicInfoConfig;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::Error;
use rs_matter::im::client::ImClient;
use rs_matter::im::{AttrResp, CmdResp, IMStatusCode};
use rs_matter::sc::pase::PaseInitiator;
use rs_matter::tlv::{TLVElement, TLVTag, TLVWrite};
use rs_matter::utils::storage::WriteBuf;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::mdns::{CommissionableFilter, DiscoveredDevice};
use rs_matter::transport::network::{Address, SocketAddr, SocketAddrV6};
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::Matter;

use static_cell::StaticCell;

/// Default Matter passcode used by test devices
pub const DEFAULT_PASSCODE: u32 = 20202021;

/// Default discriminator for test devices
pub const DEFAULT_DISCRIMINATOR: u16 = 3840;

/// OnOff cluster ID
const CLUSTER_ON_OFF: u32 = 0x0006;

/// OnOff attribute ID
const ATTR_ON_OFF: u32 = 0x0000;

/// Toggle command ID
const CMD_TOGGLE: u32 = 0x0002;

/// Timeout for PASE handshake in seconds
const PASE_TIMEOUT_SECS: u64 = 30;

/// Timeout for IM operations in seconds
const IM_TIMEOUT_SECS: u64 = 10;

static MATTER: StaticCell<Matter> = StaticCell::new();

/// Minimal basic info config for the controller (test only)
const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    device_name: "CommissioningTest",
    product_name: "CommissioningTest",
    vendor_name: "TestVendor",
    serial_no: "CommissioningTest",
    ..TEST_DEV_DET
};

/// Combined commissioning test runner.
pub struct CommissioningTests {
    workspace_dir: PathBuf,
    print_cmd_output: bool,
}

impl CommissioningTests {
    /// Create a new `CommissioningTests` instance.
    pub fn new(workspace_dir: PathBuf, print_cmd_output: bool) -> Self {
        Self {
            workspace_dir,
            print_cmd_output,
        }
    }

    /// Run the full commissioning test.
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &self,
        device_bin: &str,
        features: &[String],
        profile: &str,
        device_wait_ms: u64,
        passcode: u32,
        discriminator: u16,
        discovery_timeout_ms: u32,
    ) -> anyhow::Result<()> {
        let profile = normalize_profile(profile)?;
        let features = resolve_features(features);

        // Step 1: Build the device example
        self.build_examples(&[device_bin], &features, profile)?;

        // Step 2: Start the device
        warn!("Starting device example: {device_bin}");
        let child = self.start_device_example(device_bin, profile)?;
        let mut device_process = ChildProcessGuard::new(child);

        // Wait for device to initialize
        thread::sleep(Duration::from_millis(device_wait_ms));

        // Step 3: Run the full test flow
        let result = run_commissioning_test(passcode, discriminator, discovery_timeout_ms);

        // Cleanup
        info!("Stopping device example...");
        device_process.stop_now();

        match result {
            Ok(()) => {
                info!("Commissioning test PASSED");
                Ok(())
            }
            Err(e) => {
                warn!("Commissioning test FAILED: {e:?}");
                anyhow::bail!("commissioning_test failed: {e:?}");
            }
        }
    }

    fn build_examples(
        &self,
        bins: &[&str],
        features: &[String],
        profile: &str,
    ) -> anyhow::Result<()> {
        warn!("Building examples: {}", bins.join(", "));
        if !features.is_empty() {
            info!("Features: {}", features.join(","));
        }

        let mut cmd = Command::new("cargo");
        cmd.current_dir(&self.workspace_dir)
            .arg("build")
            .arg("-p")
            .arg("rs-matter-examples");

        for bin in bins {
            cmd.arg("--bin").arg(bin);
        }

        if profile == "release" {
            cmd.arg("--release");
        }

        if !features.is_empty() {
            cmd.arg("--features").arg(features.join(","));
        }

        self.run_command(&mut cmd)?;
        Ok(())
    }

    fn start_device_example(&self, device_bin: &str, profile: &str) -> anyhow::Result<Child> {
        let exe = self.examples_exe_path(device_bin, profile);
        if !exe.exists() {
            anyhow::bail!("Device binary not found at {}", exe.display());
        }

        let mut cmd = Command::new(&exe);
        if self.print_cmd_output {
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        } else {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }

        debug!("Running: {cmd:?}");

        cmd.spawn()
            .with_context(|| format!("Failed to start device example: {}", exe.display()))
    }

    fn examples_exe_path(&self, bin: &str, profile: &str) -> PathBuf {
        self.workspace_dir.join("target").join(profile).join(bin)
    }

    fn run_command(&self, cmd: &mut Command) -> anyhow::Result<()> {
        debug!("Running: {cmd:?}");

        let cmd = cmd.stdin(Stdio::null());

        if !self.print_cmd_output {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }

        let status = cmd
            .status()
            .with_context(|| format!("Failed to execute command: {cmd:?}"))?;

        if !status.success() {
            anyhow::bail!("Command failed with status: {status}");
        }

        Ok(())
    }
}

struct ChildProcessGuard {
    child: Option<Child>,
}

impl ChildProcessGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn stop_now(&mut self) {
        if let Some(mut child) = self.child.take() {
            if let Err(e) = child.kill() {
                debug!("Failed to kill device process (may have exited): {e}");
            }
            let _ = child.wait();
        }
    }
}

impl Drop for ChildProcessGuard {
    fn drop(&mut self) {
        self.stop_now();
    }
}

// ============================================================================
// Platform Configuration
// ============================================================================

fn normalize_profile(profile: &str) -> anyhow::Result<&str> {
    match profile {
        "debug" | "release" => Ok(profile),
        _ => anyhow::bail!("Invalid profile: {profile} (expected 'debug' or 'release')"),
    }
}

/// Resolve features for the device example based on platform.
fn resolve_features(features: &[String]) -> Vec<String> {
    if !features.is_empty() {
        return features.to_vec();
    }

    // Default features per platform
    match std::env::consts::OS {
        // macOS: Use astro-dnssd for mDNS (wraps native Bonjour)
        "macos" => vec!["astro-dnssd".to_string()],
        // Linux: Use builtin mDNS (no external daemon required)
        _ => Vec::new(),
    }
}

// ============================================================================
// Test Implementation
// ============================================================================

fn run_commissioning_test(
    passcode: u32,
    discriminator: u16,
    discovery_timeout_ms: u32,
) -> Result<(), Error> {
    warn!("Running full commissioning integration test...");
    info!("Discriminator: {discriminator}");
    info!("Passcode: {passcode}");

    // Initialize Matter stack
    let matter = MATTER.uninit().init_with(Matter::init(
        &BASIC_INFO,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        rs_matter::utils::epoch::sys_epoch,
        0, // bind to any port
    ));

    matter.initialize_transport_buffers()?;

    let crypto = default_crypto::<embassy_sync::blocking_mutex::raw::NoopRawMutex, _>(
        rand::thread_rng(),
        DAC_PRIVKEY,
    );

    // Create dual-stack UDP socket
    let socket = create_dual_stack_socket()?;
    info!(
        "Bound to local address: {:?}",
        socket.get_ref().local_addr()
    );

    // Run the async test
    futures_lite::future::block_on(async {
        let mut transport = core::pin::pin!(matter.run_transport(&crypto, &socket, &socket));
        let mut test = core::pin::pin!(run_commissioning_flow(
            matter,
            &crypto,
            passcode,
            discriminator,
            discovery_timeout_ms,
        ));

        match select(&mut transport, &mut test).await {
            Either::First(transport_result) => {
                warn!("Transport exited prematurely: {:?}", transport_result);
                transport_result
            }
            Either::Second(test_result) => {
                // Flush any pending messages
                let mut flush =
                    core::pin::pin!(Timer::after(embassy_time::Duration::from_millis(500)));
                let _ = select(&mut transport, &mut flush).await;
                test_result
            }
        }
    })
}

/// Create a dual-stack UDP socket for Matter communication.
///
/// This socket is used for Matter protocol communication (PASE, IM operations).
/// It binds to an ephemeral port since it doesn't need to receive mDNS responses.
fn create_dual_stack_socket() -> Result<async_io::Async<UdpSocket>, Error> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    socket
        .set_reuse_address(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // Allow IPv4 connections on IPv6 socket (dual-stack)
    socket
        .set_only_v6(false)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // Bind to ephemeral port on all interfaces
    let bind_addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0);
    socket
        .bind(&bind_addr.into())
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    let socket: UdpSocket = socket.into();
    async_io::Async::new_nonblocking(socket)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface.into())
}

/// Create a socket for mDNS discovery.
///
/// This socket binds to port 5353 with SO_REUSEPORT to allow sharing the mDNS port
/// with the device's mDNS responder. This is necessary because mDNS responses are
/// sent as multicast to port 5353.
#[cfg(not(target_os = "macos"))]
fn create_mdns_socket() -> Result<async_io::Async<UdpSocket>, Error> {
    use rs_matter::transport::network::mdns::MDNS_PORT;

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    socket
        .set_reuse_address(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // Allow multiple sockets to bind to the same port (needed for mDNS)
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // Allow IPv4 connections on IPv6 socket (dual-stack)
    socket
        .set_only_v6(false)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // Enable multicast loopback so we can receive mDNS responses from
    // devices running on the same machine (important for CI testing)
    socket
        .set_multicast_loop_v4(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_multicast_loop_v6(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // Bind to mDNS port to receive multicast responses
    let bind_addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0);
    socket
        .bind(&bind_addr.into())
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    let socket: UdpSocket = socket.into();
    async_io::Async::new_nonblocking(socket)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface.into())
}

async fn run_commissioning_flow<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    passcode: u32,
    discriminator: u16,
    discovery_timeout_ms: u32,
) -> Result<(), Error> {
    // Phase 1: mDNS Discovery
    info!("=== Phase 1: mDNS Discovery ===");
    let peer_addr = discover_and_resolve_device(discriminator, discovery_timeout_ms).await?;

    // Phase 2: PASE Session Establishment
    info!("=== Phase 2: PASE Session Establishment ===");
    establish_pase_session(matter, crypto, peer_addr, passcode).await?;
    log_session_info(matter);

    // Phase 3: Interaction Model Operations
    info!("=== Phase 3: Interaction Model Operations ===");
    test_onoff_cluster(matter).await?;

    info!("=== All commissioning test phases completed successfully! ===");
    Ok(())
}

// ============================================================================
// Phase 1: mDNS Discovery
// ============================================================================

async fn discover_and_resolve_device(
    discriminator: u16,
    timeout_ms: u32,
) -> Result<Address, Error> {
    let device = discover_device(discriminator, timeout_ms).await?;

    info!(
        "Discovered device: {} with {} address(es)",
        device.instance_name,
        device.addresses().len()
    );
    info!("  Discriminator: {}", device.discriminator);
    info!("  Vendor ID: {}", device.vendor_id);
    info!("  Product ID: {}", device.product_id);

    for addr in device.addresses() {
        info!("  Address: {}", addr);
    }

    resolve_device_address(&device)
}

/// Discover a Matter device using mDNS.
///
/// Platform-specific implementation:
/// - macOS: Uses astro-dnssd (native Bonjour)
/// - Linux: Uses builtin mDNS querier with multicast sockets
async fn discover_device(discriminator: u16, timeout_ms: u32) -> Result<DiscoveredDevice, Error> {
    let filter = CommissionableFilter {
        discriminator: Some(discriminator),
        ..Default::default()
    };

    info!("Starting mDNS discovery with discriminator filter: {discriminator}");

    #[cfg(target_os = "macos")]
    let devices = discover_device_macos(&filter, timeout_ms)?;

    #[cfg(not(target_os = "macos"))]
    let devices = discover_device_linux(&filter, timeout_ms).await?;

    info!("Discovery complete. Found {} device(s)", devices.len());

    devices.into_iter().next().ok_or_else(|| {
        warn!("No devices found matching discriminator {discriminator}");
        rs_matter::error::ErrorCode::NotFound.into()
    })
}

/// macOS: Use astro-dnssd which wraps native Bonjour.
#[cfg(target_os = "macos")]
fn discover_device_macos(
    filter: &CommissionableFilter,
    timeout_ms: u32,
) -> Result<Vec<DiscoveredDevice>, Error> {
    use rs_matter::transport::network::mdns::astro::discover_commissionable;
    discover_commissionable(filter, timeout_ms)
}

/// Linux: Use builtin mDNS querier with multicast sockets.
#[cfg(not(target_os = "macos"))]
async fn discover_device_linux(
    filter: &CommissionableFilter,
    timeout_ms: u32,
) -> Result<Vec<DiscoveredDevice>, Error> {
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

    let devices = discover_commissionable(
        &mut &mdns_socket,
        &mut &mdns_socket,
        filter,
        timeout_ms,
        Some(ipv4_addr),
        ipv6_interface,
    )
    .await?;

    // Convert heapless::Vec to std::vec::Vec
    Ok(devices.into_iter().collect())
}

/// Resolve a discovered device to a Matter address.
///
/// Handles platform-specific quirks:
/// - Filters out incorrect addresses (e.g., fe80::1 on macOS)
/// - Prefers IPv4 for local testing to avoid scope ID issues
/// - Sets scope ID for link-local IPv6 addresses
fn resolve_device_address(device: &DiscoveredDevice) -> Result<Address, Error> {
    let interface_index = get_default_interface_index().unwrap_or(0);

    // Select the best address:
    // 1. Filter out problematic addresses
    // 2. Prefer IPv4 for local testing (avoids scope ID issues)
    let device_addr = device
        .addresses()
        .iter()
        .filter(|addr| {
            // Filter out fe80::1 which is often incorrectly returned by DNS resolution on macOS
            if let std::net::IpAddr::V6(v6) = addr {
                if v6.segments() == [0xfe80, 0, 0, 0, 0, 0, 0, 1] {
                    debug!("Skipping fe80::1 (likely incorrect DNS resolution)");
                    return false;
                }
            }
            true
        })
        .min_by_key(|addr| match addr {
            std::net::IpAddr::V4(_) => 0, // Prefer IPv4
            std::net::IpAddr::V6(_) => 1,
        })
        .ok_or_else(|| {
            warn!("Discovered device has no usable address");
            rs_matter::error::ErrorCode::InvalidData
        })?;

    info!("Using address: {}:{}", device_addr, device.port);

    // Convert to Matter address format
    let peer_addr = match device_addr {
        std::net::IpAddr::V4(v4) => {
            let ipv6 = v4.to_ipv6_mapped();
            Address::Udp(SocketAddr::V6(SocketAddrV6::new(ipv6, device.port, 0, 0)))
        }
        std::net::IpAddr::V6(v6) => {
            // Set scope ID for link-local addresses
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

    let mut pase_fut = core::pin::pin!(PaseInitiator::initiate(&mut exchange, crypto, passcode));
    let mut timeout = core::pin::pin!(Timer::after(embassy_time::Duration::from_secs(
        PASE_TIMEOUT_SECS
    )));

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

fn log_session_info(matter: &Matter<'_>) {
    let session_mgr = matter.transport_mgr.session_mgr.borrow();
    info!("Sessions established: {}", session_mgr.iter().count());
    for sess in session_mgr.iter() {
        info!(
            "  Session: local_id={}, peer_id={}, encrypted={}",
            sess.get_local_sess_id(),
            sess.get_peer_sess_id(),
            sess.is_encrypted(),
        );
    }
}

// ============================================================================
// Phase 3: Interaction Model Operations
// ============================================================================

async fn test_onoff_cluster(matter: &Matter<'_>) -> Result<(), Error> {
    // Read initial state
    info!("Step 3a: Reading initial OnOff attribute...");
    let initial_value = read_onoff_with_timeout(matter).await?;
    info!("Initial OnOff value: {initial_value}");

    // Toggle
    info!("Step 3b: Invoking Toggle command...");
    let status = invoke_toggle_with_timeout(matter).await?;
    info!("Toggle command completed with status: {status:?}");

    // Verify toggle worked
    info!("Step 3c: Verifying toggle effect...");
    let final_value = read_onoff_with_timeout(matter).await?;
    info!("Final OnOff value: {final_value}");

    if final_value == initial_value {
        warn!("OnOff value didn't change after toggle!");
    } else {
        info!("Toggle verified successfully: {initial_value} -> {final_value}");
    }

    Ok(())
}

async fn read_onoff_with_timeout(matter: &Matter<'_>) -> Result<bool, Error> {
    let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
    debug!("IM exchange initiated: {}", exchange.id());

    let mut read_fut = core::pin::pin!(read_onoff(&mut exchange));
    let mut timeout = core::pin::pin!(Timer::after(embassy_time::Duration::from_secs(
        IM_TIMEOUT_SECS
    )));

    match select(&mut read_fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => {
            warn!("Read operation timed out");
            Err(rs_matter::error::ErrorCode::RxTimeout.into())
        }
    }
}

async fn read_onoff(exchange: &mut Exchange<'_>) -> Result<bool, Error> {
    let resp =
        ImClient::read_single_attr(exchange, 1, CLUSTER_ON_OFF, ATTR_ON_OFF, true).await?;

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

    let mut invoke_fut = core::pin::pin!(invoke_toggle(&mut exchange));
    let mut timeout = core::pin::pin!(Timer::after(embassy_time::Duration::from_secs(
        IM_TIMEOUT_SECS
    )));

    match select(&mut invoke_fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => {
            warn!("Invoke operation timed out");
            Err(rs_matter::error::ErrorCode::RxTimeout.into())
        }
    }
}

async fn invoke_toggle(exchange: &mut Exchange<'_>) -> Result<IMStatusCode, Error> {
    // Toggle command has no data - build empty TLV struct
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

/// Find a suitable network interface for mDNS discovery (Linux only).
#[cfg(not(target_os = "macos"))]
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

/// Get the default network interface index for link-local IPv6 addresses.
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

/// Check if an IPv6 address is link-local (fe80::/10).
fn is_ipv6_link_local(addr: &std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}
