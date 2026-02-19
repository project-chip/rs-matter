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

//! A common module for setting up the connectedhomeip repo

use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{self, Context};

use log::{debug, info, warn};

/// The default Git reference to use for the Chip repository
pub const CHIP_DEFAULT_GITREF: &str = "v1.4.2-branch"; //"master";

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

/// Execute command with stderr always surpressed
pub fn run_command(cmd: &mut Command, print_cmd_output: bool) -> anyhow::Result<()> {
    run_command_with(cmd, print_cmd_output, false)
}

fn run_command_with(
    cmd: &mut Command,
    print_cmd_output: bool,
    suppress_err: bool,
) -> anyhow::Result<()> {
    debug!("Running: {cmd:?}");

    let cmd = cmd.stdin(Stdio::null());

    if !print_cmd_output {
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

pub struct ChipBuilder {
    chip_dir: PathBuf,
    print_cmd_output: bool,
}

impl ChipBuilder {
    pub fn new(chip_dir: PathBuf, print_cmd_output: bool) -> Self {
        Self {
            chip_dir,
            print_cmd_output,
        }
    }

    pub fn print_tooling(&self) -> anyhow::Result<()> {
        let tooling = REQUIRED_TOOLING.to_vec().join(" ");

        warn!("Printing required system tools for Chip integration tests");
        info!("{tooling}");

        println!("{tooling}");

        Ok(())
    }

    pub fn print_packages(&self) -> anyhow::Result<()> {
        let packages = REQUIRED_PACKAGES.to_vec().join(" ");

        warn!("Printing required Debian/Ubuntu system packages for Chip integration tests");
        info!("{packages}");

        println!("{packages}");

        Ok(())
    }

    pub fn chip_dir(&self) -> &Path {
        &self.chip_dir
    }

    /// Build the chip_tool binary.
    ///
    /// Handles Chip repo setup if required and acitvates the Chip
    /// environment for building
    pub fn build_chip_tool(
        &self,
        chip_gitref: Option<&str>,
        force_rebuild: bool,
    ) -> anyhow::Result<()> {
        let chip_dir = self.chip_dir();

        self.setup_chip(chip_dir, chip_gitref, force_rebuild)?;

        // Build chip-tool if not cached or force rebuild
        let chip_tool_path = chip_dir.join("out/host/chip-tool");
        if !chip_tool_path.exists() || force_rebuild {
            warn!("Building `chip-tool`...");

            self.build_example("examples/chip-tool", "out/host")?;
        } else {
            info!("Using existing chip-tool build");
        }

        Ok(())
    }

    /// Build the chip_all_clusters_app binary.
    ///
    /// Handles Chip repo setup if required and acitvates the Chip
    /// environment for building
    pub fn build_chip_all_clusters_app(
        &self,
        chip_gitref: Option<&str>,
        force_rebuild: bool,
    ) -> anyhow::Result<()> {
        let chip_dir = self.chip_dir();

        self.setup_chip(chip_dir, chip_gitref, force_rebuild)?;

        // Build chip-all-clusters-app if not cached or force rebuild
        let app_path = chip_dir.join("out/host/chip-all-clusters-app");
        if !app_path.exists() || force_rebuild {
            warn!("Building chip-all-clusters-app...");

            self.build_example("examples/all-clusters-app/linux", "out/host")?;
        } else {
            info!("Using existing chip-all-clusters-app build");
        }

        Ok(())
    }

    /// Setup the Chip environment
    ///
    /// In details:
    /// - Check system dependencies for building `chip-tool` (git, python3, pip3, etc.)
    /// - Clone the Chip repo if it doesn't exist, or updates it if it does
    /// - Activate the Chip environment
    fn setup_chip(
        &self,
        chip_dir: &Path,
        chip_gitref: Option<&str>,
        force_rebuild: bool,
    ) -> anyhow::Result<()> {
        warn!("Setting up Chip environment...");

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
                .arg(chip_dir);

            if !self.print_cmd_output {
                cmd.arg("--quiet");
            }

            run_command(&mut cmd, self.print_cmd_output)?;

            File::create(chip_dir.join(chip_gitref))?;
        } else {
            info!("Chip repository already exists");

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
        info!("Checking out Chip GIT reference: {chip_gitref}...");

        let mut cmd = Command::new("git");

        cmd.current_dir(chip_dir).arg("checkout").arg(chip_gitref);

        if !self.print_cmd_output {
            cmd.arg("--quiet");
        }

        // Add `--` to disambiguate checkout between branch and file
        cmd.arg("--");

        run_command(&mut cmd, self.print_cmd_output)?;

        // Detect host platform for selective submodule initialization
        let platform = self.host_platform()?;
        info!("Detected platform: {platform}");

        // Initialize submodules selectively for host platform only
        info!("Initializing submodules for platform: {platform}...");

        let mut cmd = Command::new("python3");

        cmd.current_dir(chip_dir)
            .arg("scripts/checkout_submodules.py")
            .arg("--shallow")
            .arg("--platform")
            .arg(platform);

        run_command_with(&mut cmd, self.print_cmd_output, !self.print_cmd_output)?;

        // Setup Python environment
        self.setup_py_env(chip_dir)?;

        info!("Chip environment setup completed successfully.");

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

    fn host_platform(&self) -> anyhow::Result<&str> {
        let os = env::consts::OS;
        let chip_platform = match os {
            "linux" => "linux",
            "macos" => "darwin",
            _ => anyhow::bail!("Unsupported host OS: {os}"),
        };

        Ok(chip_platform)
    }

    fn setup_py_env(&self, chip_dir: &Path) -> anyhow::Result<()> {
        info!("Setting up Python environment...");

        let venv_dir = chip_dir.join("venv");

        // Create virtual environment if it doesn't exist
        if !venv_dir.exists() {
            run_command(
                Command::new("python3")
                    .arg("-m")
                    .arg("venv")
                    .arg("venv")
                    .current_dir(chip_dir),
                self.print_cmd_output,
            )?;
        }

        // Install requirements
        let requirements_path = chip_dir.join("scripts/tests/requirements.txt");
        if requirements_path.exists() {
            let pip_path = venv_dir.join("bin/pip");

            run_command(
                Command::new(&pip_path)
                    .current_dir(chip_dir)
                    .arg("install")
                    .arg("--upgrade")
                    .arg("pip")
                    .arg("wheel"),
                self.print_cmd_output,
            )?;

            run_command(
                Command::new(&pip_path)
                    .env("PW_PROJECT_ROOT", chip_dir)
                    .current_dir(chip_dir)
                    .arg("install")
                    .arg("-r")
                    .arg("scripts/tests/requirements.txt"),
                self.print_cmd_output,
            )?;

            run_command(
                Command::new(&pip_path)
                    .env("PW_PROJECT_ROOT", chip_dir)
                    .current_dir(chip_dir)
                    .arg("install")
                    .arg("-r")
                    .arg("scripts/tests/requirements.txt"),
                self.print_cmd_output,
            )?;
        }

        let bootstrap_script = chip_dir.join("scripts/bootstrap.sh");
        let run_bootstrap = format!(
            r#"
            source "{}"
            "#,
            bootstrap_script.display(),
        );

        run_command_with(
            Command::new("bash")
                .current_dir(chip_dir)
                .arg("-c")
                .arg(&run_bootstrap),
            self.print_cmd_output,
            !self.print_cmd_output,
        )?;

        Ok(())
    }

    fn build_example(&self, example_dir: &str, output_dir: &str) -> anyhow::Result<()> {
        let chip_dir = self.chip_dir();

        // Source the activation script and build; both done by gn_build_example.sh
        let build_script = chip_dir.join("scripts/examples/gn_build_example.sh");

        let build_script = format!(
            r#"
            {} {} {}
            "#,
            build_script.display(),
            example_dir,
            output_dir,
        );

        run_command_with(
            Command::new("bash")
                .current_dir(chip_dir)
                .arg("-c")
                .arg(&build_script),
            self.print_cmd_output,
            !self.print_cmd_output,
        )?;

        Ok(())
    }
}
