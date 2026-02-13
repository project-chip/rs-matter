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

use crate::common::{run_command, ChipBuilder};

use core::iter::once;

use std::path::PathBuf;
use std::process::Command;

use log::{debug, info, warn};

/// Default tests
const DEFAULT_TESTS: &[&str] = &[
    "Test_AddNewFabricFromExistingFabric",
    "TestAccessControlCluster",
    "TestAccessControlConstraints",
    "TestArmFailSafe",
    "TestAttributesById",
    "TestBasicInformation",
    // "TestBinding", // TODO: specific cluster, to be implemented with all others
    "TestCASERecovery",
    "TestCluster",
    "TestClusterComplexTypes",
    "TestClusterMultiFabric",
    "TestCommandsById",
    "TestCommissionerNodeId",
    "TestCommissioningWindow",
    "TestConfigVariables",
    "TestConstraints",
    "TestDelayCommands",
    //"TestDescriptorCluster", // TODO: Assumes a Power Source device type and expects a lot of clusters to be there
    // "TestDiagnosticLogs", // TODO: specific cluster, to be implemented with all others
    "TestDiscovery",
    "TestEqualities",
    // "TestEvents", // TODO: specific cluster, to be implemented with all others
    // "TestEventsById", // TODO: specific cluster, to be implemented with all others
    "TestFabricRemovalWhileSubscribed",
    "TestGeneralCommissioning",
    // "TestGroupMessaging", // TODO: specific cluster, to be implemented with all others
    "TestGroupsCluster",
    "TestGroupKeyManagementCluster",
    // "TestIdentifyCluster", // TODO: specific cluster, to be implemented with all others
    "TestLogCommands",
    // "TestMultiAdmin", // TODO: Involved fix to not add duplicate NOC, see failsafe.rs & FabricTable::FindExistingFabricByNocChaining
    "TestOperationalCredentialsCluster",
    // "TestOperationalState", // TODO: specific cluster, to be implemented with all others
    "TestSelfFabricRemoval",
    "TestSubscribe_AdministratorCommissioning",
    "TestSubscribe_OnOff",
    // "TestSystemCommands", // TODO: Error attempting to start secondary device
    // "TestUserLabelCluster",  // TODO: specific cluster, to be implemented with all others
    // "TestUserLabelClusterConstraints",  // TODO: specific cluster, to be implemented with all others
];

/// The directory where the Chip repository will be cloned
const CHIP_DIR: &str = ".build/itest/connectedhomeip";

/// A utility for running Chip integration tests for `rs-matter`.
/// (currently the YAML ones, Python ones would be supported in future too)
pub struct ITests {
    /// The `rs-matter` workspace directory
    workspace_dir: PathBuf,
    print_cmd_output: bool,
    chip_builder: ChipBuilder,
}

impl ITests {
    /// Create a new `ITests` instance.
    ///
    /// # Arguments
    /// - `workspace_dir`: The path to the `rs-matter` workspace directory.
    /// # - `print_cmd_output`: Whether to print command output to the console.
    pub fn new(workspace_dir: PathBuf, print_cmd_output: bool) -> Self {
        let chip_dir = workspace_dir.join(CHIP_DIR);

        ITests {
            workspace_dir,
            print_cmd_output,
            chip_builder: ChipBuilder::new(chip_dir, print_cmd_output),
        }
    }

    /// Print the required system tools for Chip integration tests.
    pub fn print_tooling(&self) -> anyhow::Result<()> {
        self.chip_builder.print_tooling()
    }

    /// Print the required Debian/Ubuntu system packages for Chip integration tests.
    pub fn print_packages(&self) -> anyhow::Result<()> {
        self.chip_builder.print_packages()
    }

    /// Setup the Chip environment so that integration tests can be run.
    pub fn setup(&self, chip_gitref: Option<&str>, force_rebuild: bool) -> anyhow::Result<()> {
        self.chip_builder
            .build_chip_tool(chip_gitref, force_rebuild)
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

    fn run_tests<'a>(
        &self,
        tests: impl IntoIterator<Item = &'a String> + Clone,
        test_timeout_secs: u32,
        profile: &str,
        target: &str,
    ) -> anyhow::Result<()> {
        warn!("Running tests...");

        let chip_dir = self.chip_builder.chip_dir();

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

        let chip_dir = self.chip_builder.chip_dir();

        info!("Killing all netns processes in app namespace to clean previous runs");
        // If this fails, that's ok; best-effort
        _ = run_command(
            Command::new("ip")
                .arg("netns")
                .arg("exec")
                .arg("app")
                .arg("pkill")
                .arg("-f")
                .arg(".*")
                .current_dir(chip_dir),
            self.print_cmd_output,
        );

        let test_suite_path = chip_dir.join("scripts/tests/run_test_suite.py");
        let chip_tool_path = chip_dir.join("out/host/chip-tool");
        let test_exe_path = self.test_exe_path(profile, target);
        let test_pics_path = self.test_pics_path(target);

        let test_command = format!(
            "{} --log-level warn --target {} --runner chip_tool_python --chip-tool {} run --iterations 1 --test-timeout-seconds {} --all-clusters-app '{}' --pics-file {}",
            test_suite_path.display(),
            test_name,
            chip_tool_path.display(),
            timeout_secs,
            test_exe_path.display(),
            test_pics_path.display(),
        );

        let script_path = chip_dir.join("scripts/run_in_build_env.sh");

        let mut cmd = Command::new(&script_path);
        cmd.current_dir(chip_dir)
            .env("CHIP_HOME", chip_dir)
            .arg(&test_command);

        match run_command(&mut cmd, self.print_cmd_output) {
            Ok(()) => info!("Test `{test_name}` completed successfully"),
            Err(err) => {
                info!("Command failed: {}", test_command);
                return Err(err);
            }
        };

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

            run_command(&mut cmd, self.print_cmd_output)?;
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

        run_command(&mut cmd, self.print_cmd_output)?;

        info!("Test executable `{target}` built successfully");

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
}
