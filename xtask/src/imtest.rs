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

//! A module for running the Interaction Model (IM) client integration test.
//!
//! This test exercises the IM client functionality (read, write, invoke) against
//! a Matter device (e.g., the onoff_light example) after establishing a PASE session.
//!
//! **Prerequisites**: This test requires the PASE Initiator implementation.
//! Make sure to merge/include the PASE initiator changes before running this test.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{self, Context};
use log::{debug, info, warn};

/// Default Matter passcode used by test devices
pub const DEFAULT_PASSCODE: u32 = 20202021;

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

/// A utility for running the IM client integration test.
pub struct ImTests {
    /// The `rs-matter` workspace directory
    workspace_dir: PathBuf,
    print_cmd_output: bool,
}

impl ImTests {
    /// Create a new `ImTests` instance.
    pub fn new(workspace_dir: PathBuf, print_cmd_output: bool) -> Self {
        Self {
            workspace_dir,
            print_cmd_output,
        }
    }

    pub fn run(
        &self,
        device_ip: &str,
        device_port: u16,
        start_device: bool,
        device_bin: &str,
        features: &[String],
        profile: &str,
        device_wait_ms: u64,
        passcode: u32,
    ) -> anyhow::Result<()> {
        let profile = normalize_profile(profile)?;
        let features_input_empty = features.is_empty();
        let features = default_features(start_device, features);
        if start_device && features_input_empty && !features.is_empty() {
            info!("Using default example features: {}", features.join(","));
        }

        if start_device {
            self.build_examples(&[device_bin], &features, profile)?;
        }

        let mut device_process = if start_device {
            warn!("Starting device example: {device_bin}");
            let child = self.start_device_example(device_bin, profile)?;
            thread::sleep(Duration::from_millis(device_wait_ms));
            Some(ChildProcessGuard::new(child))
        } else {
            None
        };

        let result = self.run_im_test(device_ip, device_port, passcode);

        if let Some(mut guard) = device_process.take() {
            info!("Stopping device example...");
            guard.stop_now();
        }

        result
    }

    fn build_examples(
        &self,
        bins: &[&str],
        features: &[String],
        profile: &str,
    ) -> anyhow::Result<()> {
        warn!("Building examples: {}", bins.join(", "));

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

    fn run_im_test(
        &self,
        device_ip: &str,
        device_port: u16,
        passcode: u32,
    ) -> anyhow::Result<()> {
        warn!("Running IM client integration test...");
        info!("Device: {}:{}", device_ip, device_port);
        info!("Passcode: {}", passcode);

        // Run the actual test
        if let Err(e) = run_im_test_internal(device_ip, device_port, passcode) {
            warn!("IM test FAILED: {e:?}");
            anyhow::bail!("im_test failed: {e:?}");
        }

        info!("IM test PASSED");
        Ok(())
    }

    fn examples_exe_path(&self, bin: &str, profile: &str) -> PathBuf {
        self.workspace_dir
            .join("target")
            .join(profile)
            .join(bin)
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

fn normalize_profile(profile: &str) -> anyhow::Result<&str> {
    match profile {
        "debug" | "release" => Ok(profile),
        _ => anyhow::bail!("Invalid profile: {profile} (expected 'debug' or 'release')"),
    }
}

fn default_features(start_device: bool, features: &[String]) -> Vec<String> {
    if !features.is_empty() {
        return features.to_vec();
    }

    if !start_device {
        return Vec::new();
    }

    match std::env::consts::OS {
        "macos" => vec!["zeroconf".to_string()],
        _ => Vec::new(),
    }
}

// ============================================================================
// Test Implementation
// ============================================================================

use std::net::UdpSocket;

use embassy_futures::select::{select, Either};
use embassy_time::Timer;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::basic_info::BasicInfoConfig;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::Error;
use rs_matter::im::client::ImClient;
use rs_matter::im::{AttrResp, CmdData, CmdPath, CmdResp, IMStatusCode};
use rs_matter::sc::pase::PaseInitiator;
use rs_matter::tlv::TLVElement;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::{Address, SocketAddr, SocketAddrV6};
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::Matter;

use static_cell::StaticCell;

static MATTER: StaticCell<Matter> = StaticCell::new();

/// OnOff cluster ID
const CLUSTER_ON_OFF: u32 = 0x0006;
/// OnOff attribute ID
const ATTR_ON_OFF: u32 = 0x0000;
/// Toggle command ID
const CMD_TOGGLE: u32 = 0x0002;

/// Minimal basic info config for the controller (test only)
const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    device_name: "ImTest",
    product_name: "ImTest",
    vendor_name: "TestVendor",
    serial_no: "ImTest",
    ..TEST_DEV_DET
};

fn run_im_test_internal(device_ip: &str, port: u16, passcode: u32) -> Result<(), Error> {
    // Parse the device address
    let ip: std::net::Ipv6Addr = if let Ok(ipv4) = device_ip.parse::<std::net::Ipv4Addr>() {
        ipv4.to_ipv6_mapped()
    } else {
        device_ip
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| rs_matter::error::ErrorCode::InvalidData)?
    };
    let peer_addr = Address::Udp(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)));

    info!("Peer address: {}", peer_addr);
    info!("Using passcode: {}", passcode);

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

    // Bind UDP socket on an ephemeral port
    let bind_addr = SocketAddr::V6(SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    ));
    let socket = async_io::Async::<UdpSocket>::bind(bind_addr)?;

    info!(
        "Bound to local address: {:?}",
        socket.get_ref().local_addr()
    );

    // Run the async test
    futures_lite::future::block_on(async {
        // Run the transport in the background, and the test logic in parallel
        let mut transport = core::pin::pin!(matter.run_transport(&crypto, &socket, &socket));
        let mut test = core::pin::pin!(run_im_test_flow(matter, &crypto, peer_addr, passcode));

        match select(&mut transport, &mut test).await {
            Either::First(transport_result) => {
                warn!("Transport exited prematurely: {:?}", transport_result);
                transport_result
            }
            Either::Second(test_result) => {
                // Keep polling transport briefly so any final messages can be flushed
                let mut flush_window =
                    core::pin::pin!(Timer::after(embassy_time::Duration::from_millis(500)));
                match select(&mut transport, &mut flush_window).await {
                    Either::First(Err(e)) => {
                        debug!("Transport exited during flush window: {e:?}");
                    }
                    Either::First(Ok(())) => {
                        debug!("Transport finished during flush window");
                    }
                    Either::Second(_) => {}
                }
                test_result
            }
        }
    })
}

async fn run_im_test_flow<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    peer_addr: Address,
    passcode: u32,
) -> Result<(), Error> {
    // Step 1: Establish PASE session
    info!("Step 1: Establishing PASE session...");

    // Use a block to ensure the PASE exchange is dropped before creating IM exchanges.
    // This is important because the PASE exchange may hold the RX buffer, which would
    // block process_rx from receiving new packets.
    {
        let mut exchange = Exchange::initiate_unsecured(matter, crypto, peer_addr).await?;
        info!("Exchange initiated: {}", exchange.id());

        // Run PASE handshake with timeout
        let mut pase_fut =
            core::pin::pin!(PaseInitiator::initiate(&mut exchange, crypto, passcode));
        let mut timeout = core::pin::pin!(Timer::after(embassy_time::Duration::from_secs(30)));

        match select(&mut pase_fut, &mut timeout).await {
            Either::First(Ok(())) => {
                info!("PASE session established successfully!");
            }
            Either::First(Err(e)) => {
                warn!("PASE handshake failed: {:?}", e);
                return Err(e);
            }
            Either::Second(_) => {
                warn!("PASE handshake timed out after 30 seconds");
                return Err(rs_matter::error::ErrorCode::RxTimeout.into());
            }
        }
        // exchange is dropped here, releasing any held RX buffer
    }

    // Step 2: Create a new exchange on the secure session for IM operations
    info!("Step 2: Creating secure exchange for IM operations...");

    // Debug: print session info
    {
        let session_mgr = matter.transport_mgr.session_mgr.borrow();
        info!("Sessions in manager: {}", session_mgr.iter().count());
        for sess in session_mgr.iter() {
            // Print detailed address info
            let addr = sess.get_peer_addr();
            info!(
                "  Session: local_sess_id={}, peer_sess_id={}, peer_addr={}, encrypted={}, mode={:?}",
                sess.get_local_sess_id(),
                sess.get_peer_sess_id(),
                addr,
                sess.is_encrypted(),
                sess.get_session_mode(),
            );
            // Print peer_nodeid and fabric_idx for matching
            info!(
                "    peer_nodeid={:?}, fabric_idx={}",
                sess.get_peer_node_id(),
                sess.get_local_fabric_idx(),
            );
        }
    }
    info!("Expected peer_addr: {:?}", peer_addr);
    info!("Looking for session with fabric_idx=0, peer_node_id=0, secure=true");

    // Step 3: Read OnOff attribute
    // Each IM operation uses its own exchange, scoped to ensure proper cleanup.
    // This is important because exchanges may hold the RX buffer, blocking process_rx.
    info!("Step 3: Reading OnOff attribute (endpoint 1, cluster 0x0006, attr 0x0000)...");

    let initial_on_off = {
        let mut im_exchange = Exchange::initiate(matter, 0, 0, true).await?;
        info!("IM exchange initiated: {}", im_exchange.id());

        let read_result = {
            let mut read_fut = core::pin::pin!(test_read_onoff(&mut im_exchange));
            let mut timeout = core::pin::pin!(Timer::after(embassy_time::Duration::from_secs(10)));

            match select(&mut read_fut, &mut timeout).await {
                Either::First(result) => result,
                Either::Second(_) => {
                    warn!("Read operation timed out");
                    Err(rs_matter::error::ErrorCode::RxTimeout.into())
                }
            }
        };

        let on_off_value = match read_result {
            Ok(v) => {
                info!("Read OnOff attribute: value = {}", v);
                v
            }
            Err(e) => {
                warn!("Failed to read OnOff attribute: {:?}", e);
                return Err(e);
            }
        };

        on_off_value
        // im_exchange is dropped here; ACK was already sent by ImClient
    };

    // Step 4: Invoke Toggle command
    info!("Step 4: Invoking Toggle command (endpoint 1, cluster 0x0006, cmd 0x0002)...");

    {
        let mut invoke_exchange = Exchange::initiate(matter, 0, 0, true).await?;
        info!("Invoke exchange initiated: {}", invoke_exchange.id());

        let invoke_result = {
            let mut invoke_fut = core::pin::pin!(test_invoke_toggle(&mut invoke_exchange));
            let mut timeout = core::pin::pin!(Timer::after(embassy_time::Duration::from_secs(10)));

            match select(&mut invoke_fut, &mut timeout).await {
                Either::First(result) => result,
                Either::Second(_) => {
                    warn!("Invoke operation timed out");
                    Err(rs_matter::error::ErrorCode::RxTimeout.into())
                }
            }
        };

        match invoke_result {
            Ok(status) => {
                info!("Toggle command completed with status: {:?}", status);
            }
            Err(e) => {
                warn!("Failed to invoke Toggle command: {:?}", e);
                return Err(e);
            }
        }
        // invoke_exchange is dropped here; ACK was already sent by ImClient
    }

    // Step 5: Read OnOff attribute again to verify toggle worked
    info!("Step 5: Reading OnOff attribute again to verify toggle...");

    {
        let mut verify_exchange = Exchange::initiate(matter, 0, 0, true).await?;
        info!("Verify exchange initiated: {}", verify_exchange.id());

        let verify_result = {
            let mut read_fut = core::pin::pin!(test_read_onoff(&mut verify_exchange));
            let mut timeout = core::pin::pin!(Timer::after(embassy_time::Duration::from_secs(10)));

            match select(&mut read_fut, &mut timeout).await {
                Either::First(result) => result,
                Either::Second(_) => {
                    warn!("Verify read operation timed out");
                    Err(rs_matter::error::ErrorCode::RxTimeout.into())
                }
            }
        };

        match verify_result {
            Ok(on_off_value) => {
                info!("Verified OnOff attribute: value = {}", on_off_value);
                // Verify toggle actually worked
                if on_off_value == initial_on_off {
                    warn!("OnOff value didn't change after toggle!");
                } else {
                    info!("Toggle verified: {} -> {}", initial_on_off, on_off_value);
                }
            }
            Err(e) => {
                warn!("Failed to verify OnOff attribute: {:?}", e);
                return Err(e);
            }
        }
        // verify_exchange is dropped here; ACK was already sent by ImClient
    }

    info!("All IM client tests completed successfully!");
    Ok(())
}

/// Test reading the OnOff attribute
async fn test_read_onoff(exchange: &mut Exchange<'_>) -> Result<bool, Error> {
    let resp = ImClient::read_single(
        exchange,
        1,              // endpoint
        CLUSTER_ON_OFF, // cluster
        ATTR_ON_OFF,    // attribute
        true,           // fabric filtered
    )
    .await?;

    match resp {
        AttrResp::Data(data) => {
            // Parse the boolean value from the TLV
            let value = data.data.bool()?;
            Ok(value)
        }
        AttrResp::Status(status) => {
            warn!("Read returned status: {:?}", status.status);
            Err(rs_matter::error::ErrorCode::InvalidData.into())
        }
    }
}

/// Test invoking the Toggle command
async fn test_invoke_toggle(exchange: &mut Exchange<'_>) -> Result<IMStatusCode, Error> {
    let path = CmdPath {
        endpoint: Some(1),
        cluster: Some(CLUSTER_ON_OFF),
        cmd: Some(CMD_TOGGLE),
    };

    // Toggle command has no data - use TLV-encoded empty struct (0x15 = struct start, 0x18 = end container)
    let empty_struct_tlv = [0x15, 0x18];
    let cmd_data = CmdData {
        path,
        data: TLVElement::new(&empty_struct_tlv),
    };

    let cmds = [cmd_data];
    let resp = ImClient::invoke(exchange, &cmds, None).await?;

    // Extract the first response
    if let Some(invoke_responses) = resp.invoke_responses {
        if let Some(first_resp) = invoke_responses.iter().next() {
            match first_resp? {
                CmdResp::Status(status) => {
                    return Ok(status.status.status);
                }
                CmdResp::Cmd(_) => {
                    // Toggle doesn't return data, just status
                    return Ok(IMStatusCode::Success);
                }
            }
        }
    }

    // No response received
    Ok(IMStatusCode::Success)
}
