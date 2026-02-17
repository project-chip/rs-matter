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

//! A module for testing mDNS discovery against chip-all-clusters-app.

use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{self, Context};

use log::{debug, info, warn};

use rs_matter::transport::network::mdns::builtin::discover_commissionable;
use rs_matter::transport::network::mdns::{
    CommissionableFilter, DiscoveredDevice, MDNS_IPV4_BROADCAST_ADDR, MDNS_IPV6_BROADCAST_ADDR,
};

/// Default discriminator for chip-all-clusters-app
const DEFAULT_DISCRIMINATOR: u16 = 3840;
/// Default passcode for chip-all-clusters-app
const DEFAULT_PASSCODE: u32 = 20202021;
/// Default discovery timeout in milliseconds
const DEFAULT_DISCOVERY_TIMEOUT_MS: u32 = 10000;

/// The default Git reference to use for the Chip repository
pub const CHIP_DEFAULT_GITREF: &str = "v1.4.2-branch";
/// The directory where the Chip repository will be cloned
const CHIP_DIR: &str = ".build/mdnstest/connectedhomeip";

/// The tooling that is checked for presence in the command line
const REQUIRED_TOOLING: &[&str] = &[
    "bash",
    "git",
    "gcc",
    "g++",
    "pkg-config",
    "ninja",
    "cmake",
    "unzip",
    "gn",
    "python3",
    "pip3",
];

/// The Debian/Ubuntu-specific packages that need to be installed
const REQUIRED_PACKAGES: &[&str] = &[
    "git",
    "gcc",
    "g++",
    "pkg-config",
    "ninja-build",
    "cmake",
    "unzip",
    "gn",
    "python3",
    "python3-pip",
    "python3-venv",
    "python3-dev",
    "libgirepository1.0-dev",
    "libcairo2-dev",
    "libreadline-dev",
    "libssl-dev",
    "libdbus-1-dev",
    "libglib2.0-dev",
    "libavahi-client-dev",
];

/// A utility for testing mDNS discovery.
pub struct MdnsTests {
    /// The `rs-matter` workspace directory
    workspace_dir: PathBuf,
    print_cmd_output: bool,
}

impl MdnsTests {
    /// Create a new `MdnsTests` instance.
    ///
    /// # Arguments
    /// - `workspace_dir`: The path to the `rs-matter` workspace directory.
    /// - `print_cmd_output`: Whether to print command output to the console.
    pub fn new(workspace_dir: PathBuf, print_cmd_output: bool) -> Self {
        MdnsTests {
            workspace_dir,
            print_cmd_output,
        }
    }

    /// Print the required system tools for mDNS tests.
    pub fn print_tooling(&self) -> anyhow::Result<()> {
        let tooling = REQUIRED_TOOLING.to_vec().join(" ");

        warn!("Printing required system tools for mDNS tests");
        info!("{tooling}");

        println!("{tooling}");

        Ok(())
    }

    /// Print the required Debian/Ubuntu system packages for mDNS tests.
    pub fn print_packages(&self) -> anyhow::Result<()> {
        let packages = REQUIRED_PACKAGES.to_vec().join(" ");

        warn!("Printing required Debian/Ubuntu system packages for mDNS tests");
        info!("{packages}");

        println!("{packages}");

        Ok(())
    }

    /// Setup the environment for mDNS testing.
    ///
    /// This will:
    /// - Check system dependencies
    /// - Clone the connectedhomeip repository
    /// - Build chip-all-clusters-app
    pub fn setup(&self, chip_gitref: Option<&str>, force_rebuild: bool) -> anyhow::Result<()> {
        warn!("Setting up mDNS test environment...");

        // Check system dependencies
        self.check_tooling()?;

        // Setup connectedhomeip and build chip-all-clusters-app
        self.setup_chip_all_clusters_app(chip_gitref, force_rebuild)?;

        info!("mDNS test environment setup completed successfully.");

        Ok(())
    }

    /// Run the mDNS discovery test.
    ///
    /// This will:
    /// 1. Start chip-all-clusters-app with the specified discriminator and passcode
    /// 2. Wait for it to initialize
    /// 3. Run mDNS discovery filtered by the discriminator
    /// 4. Verify that exactly one device is found with matching parameters
    /// 5. Clean up the chip-all-clusters-app process
    pub fn run(&self, discriminator: u16, passcode: u32, timeout_ms: u32) -> anyhow::Result<()> {
        warn!("Running mDNS discovery test...");

        let chip_all_clusters_app_path = self.chip_all_clusters_app_path();

        if !chip_all_clusters_app_path.exists() {
            anyhow::bail!(
                "chip-all-clusters-app not found at {}. Run `cargo xtask mdnstest-setup` first.",
                chip_all_clusters_app_path.display()
            );
        }

        info!("Discriminator: {}", discriminator);
        info!("Passcode: {}", passcode);
        info!("Discovery timeout: {}ms", timeout_ms);

        // Start chip-all-clusters-app
        let mut app_process =
            self.start_chip_all_clusters_app(&chip_all_clusters_app_path, discriminator, passcode)?;

        // Run the test with cleanup on both success and failure
        let result = self.run_discovery_test(discriminator, timeout_ms);

        // Always clean up the process
        info!("Stopping chip-all-clusters-app...");
        if let Err(e) = app_process.kill() {
            debug!(
                "Failed to kill chip-all-clusters-app (may have already exited): {}",
                e
            );
        }
        let _ = app_process.wait();

        result
    }

    fn setup_chip_all_clusters_app(
        &self,
        chip_gitref: Option<&str>,
        force_rebuild: bool,
    ) -> anyhow::Result<()> {
        warn!("Setting up chip-all-clusters-app...");

        let chip_dir = self.chip_dir();
        let chip_gitref = chip_gitref.unwrap_or(CHIP_DEFAULT_GITREF);

        // Clone or update Chip repository
        if !chip_dir.exists() {
            info!("Cloning connectedhomeip repository...");

            // Ensure parent directories exist
            if let Some(parent) = chip_dir.parent() {
                fs::create_dir_all(parent)
                    .context("Failed to create parent directories for connectedhomeip")?;
            }

            let mut cmd = Command::new("git");

            cmd.arg("clone")
                .arg("https://github.com/project-chip/connectedhomeip.git")
                .arg(&chip_dir);

            if !self.print_cmd_output {
                cmd.arg("--quiet");
            }

            self.run_command(&mut cmd)?;

            File::create(chip_dir.join(chip_gitref))?;
        } else {
            info!("connectedhomeip repository already exists");

            if force_rebuild || !chip_dir.join(chip_gitref).exists() {
                info!("Force rebuild requested, cleaning build artifacts...");

                let out_dir = chip_dir.join("out");
                if out_dir.exists() {
                    fs::remove_dir_all(&out_dir)
                        .context("Failed to remove existing out directory")?;
                }
            }
        }

        // Checkout the specified reference
        info!("Checking out connectedhomeip GIT reference: {chip_gitref}...");

        let mut cmd = Command::new("git");

        cmd.current_dir(&chip_dir).arg("switch").arg(chip_gitref);

        if !self.print_cmd_output {
            cmd.arg("--quiet");
        }

        // Add `--` to disambiguate checkout between branch and file
        cmd.arg("--");

        self.run_command(&mut cmd)?;

        // Detect host platform for selective submodule initialization
        let platform = self.host_platform()?;
        info!("Detected platform: {platform}");

        // Initialize submodules selectively for host platform only
        info!("Initializing submodules for platform: {platform}...");

        let mut cmd = Command::new("python3");

        cmd.current_dir(&chip_dir)
            .arg("scripts/checkout_submodules.py")
            .arg("--shallow")
            .arg("--platform")
            .arg(platform);

        self.run_command_with(&mut cmd, !self.print_cmd_output)?;

        // Setup Python environment
        self.setup_py_env(&chip_dir)?;

        // Build chip-all-clusters-app if not cached or force rebuild
        let app_path = self.chip_all_clusters_app_path();
        if !app_path.exists() || force_rebuild {
            self.build_chip_all_clusters_app(&chip_dir)?;
        } else {
            info!("Using existing chip-all-clusters-app build");
        }

        info!("chip-all-clusters-app setup completed.");

        Ok(())
    }

    fn build_chip_all_clusters_app(&self, chip_dir: &Path) -> anyhow::Result<()> {
        warn!("Building chip-all-clusters-app...");

        // Build using gn_build_example.sh
        let build_script = chip_dir.join("scripts/examples/gn_build_example.sh");

        let build_script = format!(
            r#"
            {} examples/all-clusters-app/linux out/host
            "#,
            build_script.display(),
        );

        self.run_command_with(
            Command::new("bash")
                .current_dir(chip_dir)
                .arg("-c")
                .arg(&build_script),
            !self.print_cmd_output,
        )?;

        info!("chip-all-clusters-app built successfully");

        Ok(())
    }

    fn setup_py_env(&self, chip_dir: &Path) -> anyhow::Result<()> {
        info!("Setting up Python environment...");

        let venv_dir = chip_dir.join("venv");

        // Create virtual environment if it doesn't exist
        if !venv_dir.exists() {
            self.run_command(
                Command::new("python3")
                    .arg("-m")
                    .arg("venv")
                    .arg("venv")
                    .current_dir(chip_dir),
            )?;
        }

        // Install requirements
        let requirements_path = chip_dir.join("scripts/tests/requirements.txt");
        if requirements_path.exists() {
            let pip_path = venv_dir.join("bin/pip");

            self.run_command(
                Command::new(&pip_path)
                    .current_dir(chip_dir)
                    .arg("install")
                    .arg("--upgrade")
                    .arg("pip")
                    .arg("wheel"),
            )?;

            self.run_command(
                Command::new(&pip_path)
                    .env("PW_PROJECT_ROOT", chip_dir)
                    .current_dir(chip_dir)
                    .arg("install")
                    .arg("-r")
                    .arg("scripts/tests/requirements.txt"),
            )?;
        }

        let bootstrap_script = chip_dir.join("scripts/bootstrap.sh");
        let run_bootstrap = format!(
            r#"
            source "{}"
            "#,
            bootstrap_script.display(),
        );

        self.run_command_with(
            Command::new("bash")
                .current_dir(chip_dir)
                .arg("-c")
                .arg(&run_bootstrap),
            !self.print_cmd_output,
        )?;

        Ok(())
    }

    fn start_chip_all_clusters_app(
        &self,
        app_path: &Path,
        discriminator: u16,
        passcode: u32,
    ) -> anyhow::Result<Child> {
        info!("Starting chip-all-clusters-app...");
        info!("  Path: {}", app_path.display());

        // Create a temporary KVS file path
        let kvs_path = self.workspace_dir.join(".build/mdnstest/chip_kvs");
        if let Some(parent) = kvs_path.parent() {
            fs::create_dir_all(parent).context("Failed to create directory for KVS file")?;
        }

        // Remove existing KVS to ensure clean state
        if kvs_path.exists() {
            fs::remove_file(&kvs_path).context("Failed to remove existing KVS file")?;
        }

        let mut cmd = Command::new(app_path);
        cmd.arg("--discriminator")
            .arg(discriminator.to_string())
            .arg("--passcode")
            .arg(passcode.to_string())
            .arg("--KVS")
            .arg(kvs_path.to_str().unwrap());

        if self.print_cmd_output {
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        } else {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        }

        debug!("Running: {:?}", cmd);

        let mut child = cmd
            .spawn()
            .context("Failed to start chip-all-clusters-app")?;

        // Wait for the app to initialize by checking for mDNS advertisement
        info!("Waiting for chip-all-clusters-app to initialize...");

        if !self.print_cmd_output {
            // Try to detect when the app is ready by reading its output
            if let Some(stderr) = child.stderr.take() {
                let reader = BufReader::new(stderr);
                let handle = thread::spawn(move || {
                    for line in reader.lines() {
                        if let Ok(line) = line {
                            // Look for indication that mDNS is advertising
                            if line.contains("CHIP:DIS: Advertise operational node")
                                || line.contains("CHIP:DIS: Advertise commission")
                                || line.contains("mDNS service published")
                            {
                                debug!("Detected app ready: {}", line);
                                return true;
                            }
                        }
                    }
                    false
                });

                // Wait up to 10 seconds for the app to be ready
                thread::sleep(Duration::from_secs(5));
                drop(handle); // Don't wait for the thread, it will be cleaned up
            } else {
                // Fallback: just wait a fixed amount of time
                thread::sleep(Duration::from_secs(5));
            }
        } else {
            // When printing output, just wait a fixed amount of time
            thread::sleep(Duration::from_secs(5));
        }

        info!("chip-all-clusters-app should be ready");

        Ok(child)
    }

    fn run_discovery_test(&self, discriminator: u16, timeout_ms: u32) -> anyhow::Result<()> {
        info!(
            "Running mDNS discovery with discriminator filter: {}",
            discriminator
        );

        // Run the async discovery using futures-lite block_on
        futures_lite::future::block_on(self.run_discovery_test_async(discriminator, timeout_ms))
    }

    async fn run_discovery_test_async(
        &self,
        discriminator: u16,
        timeout_ms: u32,
    ) -> anyhow::Result<()> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::UdpSocket;

        // Initialize network interface
        let (ipv4_addr, ipv6_available, interface) =
            Self::initialize_network().context("Failed to initialize network")?;

        // Create UDP socket for mDNS querying
        // We bind to port 0 (ephemeral port) instead of 5353 to avoid conflicts
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
            .context("Failed to create socket")?;
        socket
            .set_reuse_address(true)
            .context("Failed to set SO_REUSEADDR")?;
        socket.set_only_v6(false).context("Failed to set IPV6_V6ONLY")?;

        // Bind to ephemeral port
        let bind_addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0);
        socket
            .bind(&bind_addr.into())
            .context("Failed to bind socket")?;

        let socket: UdpSocket = socket.into();
        let socket =
            async_io::Async::new_nonblocking(socket).context("Failed to create async socket")?;

        let local_port = socket
            .get_ref()
            .local_addr()
            .context("Failed to get local address")?
            .port();
        info!("Socket bound to port {}", local_port);

        // Join multicast groups to receive multicast responses
        if ipv6_available {
            socket
                .get_ref()
                .join_multicast_v6(&MDNS_IPV6_BROADCAST_ADDR, interface)
                .context("Failed to join IPv6 multicast group")?;
        }
        socket
            .get_ref()
            .join_multicast_v4(&MDNS_IPV4_BROADCAST_ADDR, &ipv4_addr)
            .context("Failed to join IPv4 multicast group")?;

        info!(
            "Socket bound and multicast groups joined (IPv6: {})",
            ipv6_available
        );

        // Create filter for the specific discriminator
        let filter = CommissionableFilter {
            discriminator: Some(discriminator),
            ..Default::default()
        };

        let ipv6_interface = if ipv6_available { Some(interface) } else { None };

        // Run discovery using the builtin mDNS querier
        let devices = discover_commissionable(
            &mut &socket,
            &mut &socket,
            &filter,
            timeout_ms,
            Some(ipv4_addr),
            ipv6_interface,
        )
        .await
        .context("mDNS discovery failed")?;

        info!("Discovery complete. Found {} device(s)", devices.len());

        // Verify results
        self.verify_discovery_results(&devices, discriminator)
    }

    /// Find a suitable network interface for mDNS discovery.
    ///
    /// Returns the IPv4 address, whether IPv6 is available, and the interface index.
    fn initialize_network() -> anyhow::Result<(std::net::Ipv4Addr, bool, u32)> {
        use nix::net::if_::InterfaceFlags;
        use nix::sys::socket::SockaddrIn6;

        let interfaces = || {
            nix::ifaddrs::getifaddrs().unwrap().filter(|ia| {
                // Interface must be up and support either broadcast or multicast (for mDNS)
                ia.flags.contains(InterfaceFlags::IFF_UP)
                    && ia
                        .flags
                        .intersects(InterfaceFlags::IFF_BROADCAST | InterfaceFlags::IFF_MULTICAST)
                    && !ia
                        .flags
                        .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
            })
        };

        // Find a suitable network interface - first try to find one with both IPv4 and IPv6
        let result = interfaces()
            .filter_map(|ia| {
                ia.address
                    .and_then(|addr| addr.as_sockaddr_in6().map(SockaddrIn6::ip))
                    .map(|ipv6| (ia.interface_name, ipv6))
            })
            .filter_map(|(iname, _ipv6)| {
                interfaces()
                    .filter(|ia2| ia2.interface_name == iname)
                    .find_map(|ia2| {
                        ia2.address
                            .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip().into()))
                            .map(|ip: std::net::Ipv4Addr| (iname.clone(), ip, true))
                    })
            })
            .next();

        // If no interface with both IPv4 and IPv6, try to find one with just IPv4
        let (iname, ip, ipv6_available) = result
            .or_else(|| {
                interfaces()
                    .filter_map(|ia| {
                        ia.address
                            .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip().into()))
                            .map(|ip: std::net::Ipv4Addr| (ia.interface_name, ip, false))
                    })
                    .next()
            })
            .ok_or_else(|| anyhow::anyhow!("Cannot find network interface suitable for mDNS"))?;

        // Get the interface index for multicast operations
        let if_index = nix::net::if_::if_nametoindex(iname.as_str()).unwrap_or(0);

        info!(
            "Using network interface {} (index {}) with {} (IPv6: {})",
            iname, if_index, ip, ipv6_available
        );

        Ok((ip, ipv6_available, if_index))
    }

    fn verify_discovery_results(
        &self,
        devices: &[DiscoveredDevice],
        expected_discriminator: u16,
    ) -> anyhow::Result<()> {
        // Check that we found exactly one device
        if devices.is_empty() {
            anyhow::bail!(
                "No devices found with discriminator {}. \
                 Make sure chip-all-clusters-app is running and advertising.",
                expected_discriminator
            );
        }

        if devices.len() > 1 {
            warn!("Found {} devices, expected exactly 1", devices.len());
            for (i, device) in devices.iter().enumerate() {
                warn!(
                    "  Device {}: addr={:?}, discriminator={}, instance={}",
                    i + 1,
                    device.addr(),
                    device.discriminator,
                    device.instance_name
                );
            }
            anyhow::bail!(
                "Found {} devices with discriminator {}, expected exactly 1. \
                 There may be other Matter devices on the network with the same discriminator.",
                devices.len(),
                expected_discriminator
            );
        }

        let device = &devices[0];

        info!("Found device:");
        info!("  Address: {:?}", device.addr());
        info!("  Discriminator: {}", device.discriminator);
        info!("  Vendor ID: {}", device.vendor_id);
        info!("  Product ID: {}", device.product_id);
        if !device.device_name.is_empty() {
            info!("  Device Name: {}", device.device_name);
        }
        info!("  Instance: {}", device.instance_name);

        // Verify the discriminator matches
        if device.discriminator != expected_discriminator {
            anyhow::bail!(
                "Device discriminator mismatch: expected {}, got {}",
                expected_discriminator,
                device.discriminator
            );
        }

        info!("mDNS discovery test PASSED");

        Ok(())
    }

    fn check_tooling(&self) -> anyhow::Result<()> {
        for tool in REQUIRED_TOOLING {
            if which::which(tool).is_err() {
                anyhow::bail!("Required tool '{tool}' not found in $PATH");
            }
        }

        info!("System tools check passed");

        Ok(())
    }

    fn run_command(&self, cmd: &mut Command) -> anyhow::Result<()> {
        self.run_command_with(cmd, false)
    }

    fn run_command_with(&self, cmd: &mut Command, suppress_err: bool) -> anyhow::Result<()> {
        debug!("Running: {cmd:?}");

        let cmd = cmd.stdin(Stdio::null());

        if !self.print_cmd_output {
            cmd.stdout(Stdio::null());
        }

        if suppress_err {
            cmd.stderr(Stdio::null());
        }

        let status = cmd
            .status()
            .with_context(|| format!("Failed to execute command: {cmd:?}"))?;

        if !status.success() {
            anyhow::bail!("Command failed with status: {status}");
        }

        Ok(())
    }

    fn chip_dir(&self) -> PathBuf {
        self.workspace_dir.join(CHIP_DIR)
    }

    fn chip_all_clusters_app_path(&self) -> PathBuf {
        self.chip_dir().join("out/host/chip-all-clusters-app")
    }

    fn host_platform(&self) -> anyhow::Result<&str> {
        let os = env::consts::OS;
        let chip_platform = match os {
            "linux" => "linux",
            "macos" => "darwin",
            _ => anyhow::bail!("Unsupported host OS: {os}"),
        };

        Ok(chip_platform)
    }
}

/// Get the default discriminator value.
pub fn default_discriminator() -> u16 {
    DEFAULT_DISCRIMINATOR
}

/// Get the default passcode value.
pub fn default_passcode() -> u32 {
    DEFAULT_PASSCODE
}

/// Get the default discovery timeout in milliseconds.
pub fn default_timeout_ms() -> u32 {
    DEFAULT_DISCOVERY_TIMEOUT_MS
}
