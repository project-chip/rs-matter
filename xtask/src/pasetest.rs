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

//! A module for running the PASE (Passcode-Authenticated Session Establishment) integration test.
//!
//! This test exercises the full PASE handshake between a commissioner (this test) and a
//! Matter device (e.g., the onoff_light example).

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{self, Context};
use embassy_futures::select::{select, Either};
use embassy_time::Timer;
use log::{debug, info, warn};

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::basic_info::BasicInfoConfig;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::Error;
use rs_matter::sc::pase::PaseInitiator;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::{Address, SocketAddr, SocketAddrV6};
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::Matter;

use static_cell::StaticCell;

static MATTER: StaticCell<Matter> = StaticCell::new();

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

/// A utility for running the PASE integration test.
pub struct PaseTests {
    /// The `rs-matter` workspace directory
    workspace_dir: PathBuf,
    print_cmd_output: bool,
}

impl PaseTests {
    /// Create a new `PaseTests` instance.
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

        let result = self.run_pase_test(device_ip, device_port, passcode);

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
        cmd.arg("build")
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

    fn run_pase_test(
        &self,
        device_ip: &str,
        device_port: u16,
        passcode: u32,
    ) -> anyhow::Result<()> {
        warn!("Running PASE integration test...");

        if let Err(e) = run_pase_test_internal(device_ip, device_port, passcode) {
            warn!("PASE test FAILED: {e:?}");
            anyhow::bail!("pase_test failed: {e:?}");
        }

        info!("PASE test PASSED");
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

/// Minimal basic info config for the controller (test only)
const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    device_name: "PaseTest",
    product_name: "PaseTest",
    vendor_name: "TestVendor",
    serial_no: "PaseTest",
    ..TEST_DEV_DET
};

fn run_pase_test_internal(device_ip: &str, port: u16, passcode: u32) -> Result<(), Error> {
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
        let mut test = core::pin::pin!(run_pase_handshake(matter, &crypto, peer_addr, passcode));

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

async fn run_pase_handshake<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    peer_addr: Address,
    passcode: u32,
) -> Result<(), Error> {
    info!("Creating unsecured session and initiating PASE handshake...");

    // Step 1: Create unsecured session + exchange
    let mut exchange = Exchange::initiate_unsecured(matter, crypto, peer_addr).await?;

    info!("Exchange initiated: {}", exchange.id());

    // Step 2: Run the PASE handshake with a timeout
    info!("Starting PASE handshake with passcode {}...", passcode);

    let pase_result = {
        let mut pase_fut = core::pin::pin!(PaseInitiator::initiate(
            &mut exchange,
            crypto,
            passcode
        ));
        let mut timeout = core::pin::pin!(Timer::after(embassy_time::Duration::from_secs(30)));

        match select(&mut pase_fut, &mut timeout).await {
            Either::First(result) => result,
            Either::Second(_) => {
                warn!("PASE handshake timed out after 30 seconds");
                return Err(rs_matter::error::ErrorCode::RxTimeout.into());
            }
        }
    };

    match pase_result {
        Ok(()) => {
            info!("PASE handshake completed successfully!");
            info!("Secure session established with device");
            Ok(())
        }
        Err(e) => {
            warn!("PASE handshake failed: {:?}", e);
            Err(e)
        }
    }
}
