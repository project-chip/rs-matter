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

//! A module for running Chip integration tests on the `rs-matter` project.

use core::iter::once;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{self, Context};

use log::{debug, info, warn};

/// Default tests
const DEFAULT_TESTS: &[&str] = &[
    "TestAttributesById",
    "TestCommandsById",
    "TestCluster",
    "TestClusterComplexTypes",
    "TestBasicInformation",
    "TestAccessControlCluster",
    "TestArmFailSafe",
    "TestSelfFabricRemoval",
    "TestClusterMultiFabric",
    "TestCommissionerNodeId",
];

/// The default Git reference to use for the Chip repository
pub const CHIP_DEFAULT_GITREF: &str = "v1.3.0.0"; //"master";
/// The directory where the Chip repository will be cloned
const CHIP_DIR: &str = ".build/itest/connectedhomeip";

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

/// A utility for running Chip integration tests for `rs-matter`.
/// (currently the YAML ones, Python ones would be supported in future too)
pub struct ITests {
    /// The `rs-matter` workspace directory
    workspace_dir: PathBuf,
    print_cmd_output: bool,
}

impl ITests {
    /// Create a new `ITests` instance.
    ///
    /// # Arguments
    /// - `workspace_dir`: The path to the `rs-matter` workspace directory.
    /// # - `print_cmd_output`: Whether to print command output to the console.
    pub fn new(workspace_dir: PathBuf, print_cmd_output: bool) -> Self {
        ITests {
            workspace_dir,
            print_cmd_output,
        }
    }

    /// Print the required system tools for Chip integration tests.
    pub fn print_tooling(&self) -> anyhow::Result<()> {
        let tooling = REQUIRED_TOOLING.to_vec().join(" ");

        warn!("Printing required system tools for Chip integration tests");
        info!("{tooling}");

        println!("{tooling}");

        Ok(())
    }

    /// Print the required Debian/Ubuntu system packages for Chip integration tests.
    pub fn print_packages(&self) -> anyhow::Result<()> {
        let packages = REQUIRED_PACKAGES.to_vec().join(" ");

        warn!("Printing required Debian/Ubuntu system packages for Chip integration tests");
        info!("{packages}");

        println!("{packages}");

        Ok(())
    }

    /// Setup the Chip environment so that integration tests can be run.
    ///
    /// In details:
    /// - Check system dependencies for building `chip-tool` (git, python3, pip3, etc.)
    /// - Clone the Chip repo if it doesn't exist, or updates it if it does
    /// - Activate the Chip environment
    /// - Build `chip-tool`
    pub fn setup(&self, chip_gitref: Option<&str>, force_rebuild: bool) -> anyhow::Result<()> {
        self.setup_chip_tool(chip_gitref, force_rebuild)
    }

    /// Build the executable (`chip-tool-tests`) that is to be tested with the Chip integration tests.
    pub fn build<'a>(
        &self,
        profile: &str,
        target: &str,
        features: impl IntoIterator<Item = &'a String>,
        force_rebuild: bool,
    ) -> anyhow::Result<()> {
        self.build_test_exe(profile, target, features, force_rebuild)
    }

    /// Run integration tests
    pub fn run<'a>(
        &self,
        tests: impl IntoIterator<Item = &'a String> + Clone,
        test_timeout_secs: u32,
        profile: &str,
        target: &str,
    ) -> anyhow::Result<()> {
        self.run_tests(tests, test_timeout_secs, profile, target)
    }

    fn setup_chip_tool(
        &self,
        chip_gitref: Option<&str>,
        force_rebuild: bool,
    ) -> anyhow::Result<()> {
        warn!("Setting up Chip environment...");

        let chip_dir = self.workspace_dir.join(CHIP_DIR);
        let chip_gitref = chip_gitref.unwrap_or(CHIP_DEFAULT_GITREF);

        // Check system dependencies
        self.check_tooling()?;

        // Clone or update Chip repository
        if !chip_dir.exists() {
            info!("Cloning Chip repository...");

            // Ensure parent directories exist
            if let Some(parent) = chip_dir.parent() {
                fs::create_dir_all(parent)
                    .context("Failed to create parent directories for Chip")?;
            }

            let mut cmd = Command::new("git");

            cmd.arg("clone")
                .arg("https://github.com/project-chip/connectedhomeip.git")
                .arg(&chip_dir);

            if !self.print_cmd_output {
                cmd.arg("--quiet");
            }

            self.run_command(&mut cmd)?;
        } else {
            info!("Chip repository already exists");

            if force_rebuild {
                info!("Force rebuild requested, cleaning build artifacts...");

                let out_dir = chip_dir.join("out");
                if out_dir.exists() {
                    fs::remove_dir_all(&out_dir)
                        .context("Failed to remove existing out directory")?;
                }
            }
        }

        // Checkout the specified reference
        info!("Checking out Chip GIT reference: {chip_gitref}...");

        let mut cmd = Command::new("git");

        cmd.current_dir(&chip_dir).arg("checkout").arg(chip_gitref);

        if !self.print_cmd_output {
            cmd.arg("--quiet");
        }

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

        // Build chip-tool if not cached or force rebuild
        let chip_tool_path = chip_dir.join("out/host/chip-tool");
        if !chip_tool_path.exists() || force_rebuild {
            self.build_chip_tool(&chip_dir)?;
        } else {
            info!("Using existing chip-tool build");
        }

        info!("Chip environment setup completed successfully.");

        Ok(())
    }

    fn run_tests<'a>(
        &self,
        tests: impl IntoIterator<Item = &'a String> + Clone,
        test_timeout_secs: u32,
        profile: &str,
        target: &str,
    ) -> anyhow::Result<()> {
        warn!("Running tests...");

        let chip_dir = self.chip_dir();

        // Verify Chip is set up
        if !chip_dir.exists() {
            anyhow::bail!("Chip environment not found. Run `cargo xtask itest-setup` first.");
        }

        let chip_tool_path = chip_dir.join("out/host/chip-tool");
        if !chip_tool_path.exists() {
            anyhow::bail!("`chip-tool` not found. Run `cargo xtask itest-setup` first.");
        }

        // Determine which tests to run
        let tests = if tests.clone().into_iter().next().is_some() {
            tests.into_iter().map(|s| s.as_str()).collect::<Vec<_>>()
        } else {
            info!("Using default tests");

            DEFAULT_TESTS.to_vec()
        };

        if tests.is_empty() {
            info!("No tests specified and no default tests enabled.");
            return Ok(());
        }

        debug!("About to run tests: {tests:?}");

        // Run each test
        for test_name in tests {
            self.run_test(test_name, test_timeout_secs, profile, target)?;
        }

        info!("All tests completed successfully.");

        Ok(())
    }

    fn run_test(
        &self,
        test_name: &str,
        timeout_secs: u32,
        profile: &str,
        target: &str,
    ) -> anyhow::Result<()> {
        // TODO: Running test-by-test is slow. Turn this into a run-multiple-tests function.

        info!("=> Running test `{test_name}` with timeout {timeout_secs}s...");

        let chip_dir = self.chip_dir();

        let test_suite_path = chip_dir.join("scripts/tests/run_test_suite.py");
        let chip_tool_path = chip_dir.join("out/host/chip-tool");
        let test_exe_path = self.test_exe_path(profile, target);
        let test_pics_path = self.test_pics_path(target);

        let test_command = format!(
            "{} --log-level warn --target {} --runner chip_tool_python --chip-tool {} run --iterations 1 --test-timeout-seconds {} --all-clusters-app {} --pics-file {}",
            test_suite_path.display(),
            test_name,
            chip_tool_path.display(),
            timeout_secs,
            test_exe_path.display(),
            test_pics_path.display(),
        );

        let script_path = chip_dir.join("scripts/run_in_build_env.sh");

        let mut cmd = Command::new(&script_path);
        cmd.current_dir(&chip_dir)
            .env("CHIP_HOME", chip_dir)
            .arg(test_command);

        self.run_command(&mut cmd)?;

        info!("Test `{test_name}` completed successfully");

        Ok(())
    }

    fn build_test_exe<'a>(
        &self,
        profile: &str,
        target: &str,
        additional_features: impl IntoIterator<Item = &'a String>,
        force_rebuild: bool,
    ) -> anyhow::Result<()> {
        warn!("Building test executable `{target}`...");

        let test_exe_crate_dir = self.workspace_dir.join("examples");

        if force_rebuild {
            info!("Force rebuild requested, cleaning previous build artifacts...");

            let mut cmd = Command::new("cargo");

            cmd.arg("clean").current_dir(&test_exe_crate_dir);

            if profile == "release" {
                cmd.arg("--release");
            }

            if !self.print_cmd_output {
                cmd.arg("--quiet");
            }

            self.run_command(&mut cmd)?;
        }

        let features = once("log")
            .chain(additional_features.into_iter().map(|s| s.as_str()))
            .collect::<Vec<_>>()
            .join(",");

        let mut cmd = Command::new("cargo");

        cmd.arg("build")
            .arg("--bin")
            .arg(target)
            .arg("--features")
            .arg(&features)
            .current_dir(&test_exe_crate_dir);

        if profile == "release" {
            cmd.arg("--release");
        }

        if !self.print_cmd_output {
            cmd.arg("--quiet");
        }

        self.run_command(&mut cmd)?;

        info!("Test executable `{target}` built successfully");

        Ok(())
    }

    fn build_chip_tool(&self, chip_dir: &Path) -> anyhow::Result<()> {
        warn!("Building `chip-tool`...");

        // Source the activation script and build
        let activate_script = chip_dir.join("scripts/activate.sh");

        let build_script = format!(
            r#"
            source "{}" &&
            gn gen out/host --args='is_debug=false' &&
            ninja -C out/host chip-tool
            "#,
            activate_script.display(),
        );

        self.run_command_with(
            Command::new("bash")
                .current_dir(chip_dir)
                .arg("-c")
                .arg(&build_script),
            !self.print_cmd_output,
        )?;

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
        let requirements_path = chip_dir.join("scripts/requirements.txt");
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
                    .current_dir(chip_dir)
                    .arg("install")
                    .arg("-r")
                    .arg("scripts/requirements.txt"),
            )?;
        }

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

    fn test_exe_path(&self, profile: &str, target: &str) -> PathBuf {
        self.workspace_dir.join("target").join(profile).join(target)
    }

    fn test_pics_path(&self, target: &str) -> PathBuf {
        self.workspace_dir
            .join("examples")
            .join("src")
            .join("bin")
            .join(format!("{target}.pics"))
    }

    fn chip_dir(&self) -> PathBuf {
        self.workspace_dir.join(CHIP_DIR)
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
