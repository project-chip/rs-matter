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
///
/// Names matching the `TC_*` convention are dispatched to
/// `scripts/tests/run_python_test.py` and target a `MatterBaseTest`
/// in `src/python_testing/`. All other names are YAML test suites
/// dispatched to `scripts/tests/run_test_suite.py`.
const DEFAULT_TESTS: &[&str] = &[
    //
    // YAML tests — general Matter protocol & system clusters
    //
    "Test_AddNewFabricFromExistingFabric",
    "TestAccessControlCluster",
    "TestAccessControlConstraints",
    "TestArmFailSafe",
    "TestAttributesById",
    "TestBasicInformation",
    // "TestBinding", // TODO: Binding cluster not yet implemented
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
    // "TestDescriptorCluster", // TODO: Assumes a Power Source device type and expects a lot of clusters to be there
    // "TestDiagnosticLogs", // TODO: Diagnostic Logs cluster not yet implemented
    "TestDiscovery",
    "TestEqualities",
    "TestEvents",
    "TestEventsById",
    "TestFabricRemovalWhileSubscribed",
    "TestGeneralCommissioning",
    "TestGroupMessaging",
    "TestGroupsCluster",
    "TestGroupKeyManagementCluster",
    // "TestIdentifyCluster", // TODO: Identify cluster not yet implemented
    "TestLogCommands",
    "TestMultiAdmin",
    "TestOperationalCredentialsCluster",
    // "TestOperationalState", // TODO: Operational State cluster not yet implemented
    "TestReadNoneSubscribeNone",
    // "TestSaveAs", // TODO: not yet verified
    "TestSelfFabricRemoval",
    "TestSubscribe_AdministratorCommissioning",
    "TestSubscribe_OnOff",
    // "TestSystemCommands", // TODO: Error attempting to start secondary device
    // "TestUserLabelCluster", // TODO: User Label cluster not yet implemented
    // "TestUserLabelClusterConstraints", // TODO: User Label cluster not yet implemented

    //
    // Python tests — Interaction Data Model (general Matter protocol)
    //
    "TC_IDM_2_2",
    "TC_IDM_1_2",
    "TC_IDM_1_4",
    "TC_IDM_4_2",

    //
    // Python tests — Access Control (system cluster)
    //
    "TC_ACE_1_2",
    "TC_ACE_1_3",
    "TC_ACE_1_4",
    "TC_ACE_1_5",
    "TC_ACL_2_2",
    // "TC_ACL_2_3", // Skipped: tests the optional `AccessControlExtension` feature (Extension attribute), not implemented by rs-matter.
    "TC_ACL_2_4",
    // "TC_ACL_2_5", // Skipped: tests the optional `AccessControlExtension` feature (Extension attribute), not implemented by rs-matter.
    "TC_ACL_2_6",
    // "TC_ACL_2_7", // Skipped: tests the optional `AccessControlExtension` feature (Extension attribute), not implemented by rs-matter.
    // "TC_ACL_2_8", // Skipped: the test re-runs itself internally with legacy list encoding after the modern-encoding pass. The Python framework's between-runs controller cleanup is buggy (`object NoneType can't be used in 'await' expression`) and leaves stale fabrics on the DUT, so the second commissioning fails with `Incorrect state`. The modern-encoding pass — including fabric-scoped event filtering — is exercised end-to-end and passes.
    "TC_ACL_2_9",
    "TC_ACL_2_10",
    // "TC_ACL_2_11", // Skipped: tests the provisional `ManagedAclRestrictions` feature (ARL attribute) and requires manufacturer-specific access restrictions to be pre-configured. rs-matter does not implement this feature.

    //
    // Python tests — General & Administrator Commissioning (system clusters)
    //
    // "TC_CADMIN_1_3_4", // TODO: not yet verified
    // "TC_CADMIN_1_5",   // TODO: not yet verified
    // "TC_CADMIN_1_9",   // TODO: not yet verified
    // "TC_CADMIN_1_11",  // TODO: not yet verified
    // "TC_CADMIN_1_15",  // TODO: not yet verified
    // "TC_CADMIN_1_19",  // TODO: not yet verified
    // "TC_CADMIN_1_22",  // TODO: not yet verified
    // "TC_CADMIN_1_25",  // TODO: not yet verified
    // "TC_CADMIN_1_27",  // TODO: not yet verified
    // "TC_CADMIN_1_28",  // TODO: not yet verified
    // "TC_CGEN_2_1",     // TODO: not yet verified
    // "TC_CGEN_2_2",     // TODO: not yet verified
    // "TC_CGEN_2_4",     // TODO: not yet verified
    // "TC_CGEN_2_5",     // TODO: not yet verified
    // "TC_CGEN_2_6",     // TODO: not yet verified
    // "TC_CGEN_2_7",     // TODO: not yet verified
    // "TC_CGEN_2_8",     // TODO: not yet verified
    // "TC_CGEN_2_9",     // TODO: not yet verified
    // "TC_CGEN_2_10",    // TODO: not yet verified
    // "TC_CGEN_2_11",    // TODO: not yet verified

    //
    // Python tests — Operational Credentials (system cluster)
    //
    // "TC_OPCREDS_3_1", // TODO: not yet verified
    // "TC_OPCREDS_3_2", // TODO: not yet verified
    // "TC_OPCREDS_3_4", // TODO: not yet verified
    // "TC_OPCREDS_3_5", // TODO: not yet verified
    // "TC_OPCREDS_3_8", // TODO: not yet verified

    //
    // Python tests — Session/Commissioning (general Matter protocol)
    //
    // "TC_SC_3_4", // TODO: not yet verified
    // "TC_SC_3_5", // TODO: not yet verified
    // "TC_SC_3_6", // TODO: not yet verified
    // "TC_SC_4_1", // TODO: not yet verified
    // "TC_SC_4_3", // TODO: not yet verified
    // "TC_SC_7_1", // TODO: not yet verified

    //
    // Python tests — Basic Information (system cluster)
    //
    // "TC_BINFO_3_2", // TODO: not yet verified

    //
    // Python tests — Groups (system cluster)
    //
    // "TC_G_2_2", // TODO: not yet verified

    //
    // Python tests — General Diagnostics (system cluster)
    //
    // "TC_DGGEN_2_4", // TODO: not yet verified
    // "TC_DGGEN_3_2", // TODO: not yet verified

    //
    // Python tests — Device Attestation (commissioning)
    //
    // "TC_DA_1_2", // TODO: not yet verified
    // "TC_DA_1_5", // TODO: not yet verified
    // "TC_DA_1_7", // TODO: not yet verified
    // "TC_DA_1_9", // TODO: not yet verified

    //
    // Python tests — Device Discovery (general)
    //
    // "TC_DD_1_16_17", // TODO: not yet verified
    // "TC_DD_3_23",    // TODO: not yet verified

    //
    // Python tests — Device Composition / Conformance (general)
    //
    // "TC_DeviceBasicComposition", // TODO: not yet verified
    // "TC_DeviceConformance",      // TODO: not yet verified
];

/// The directory where the Chip repository will be cloned
const CHIP_DIR: &str = ".build/itest/connectedhomeip";

/// A utility for running Chip integration tests for `rs-matter`.
///
/// Supports both YAML test suites (dispatched to
/// `scripts/tests/run_test_suite.py`) and Python `MatterBaseTest`
/// scripts (dispatched to `scripts/tests/run_python_test.py`). Names
/// starting with `TC_` are treated as Python; everything else is YAML.
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
            .build_chip_tool(chip_gitref, force_rebuild)?;
        // Required so that `TC_*` Python tests can be dispatched via
        // `scripts/tests/run_python_test.py`.
        self.chip_builder.build_python_wheel(force_rebuild)
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

        let test_command = if Self::is_python_test(test_name) {
            self.python_test_command(test_name, timeout_secs, profile, target)?
        } else {
            self.yaml_test_command(test_name, timeout_secs, profile, target)
        };

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

    /// `TC_*` (camelCase) is the upstream filename convention for
    /// CHIP `MatterBaseTest`-style Python tests in
    /// `src/python_testing/`. Anything else is a YAML test suite.
    fn is_python_test(test_name: &str) -> bool {
        test_name.starts_with("TC_")
    }

    fn yaml_test_command(
        &self,
        test_name: &str,
        timeout_secs: u32,
        profile: &str,
        target: &str,
    ) -> String {
        let chip_dir = self.chip_builder.chip_dir();
        let test_suite_path = chip_dir.join("scripts/tests/run_test_suite.py");
        let chip_tool_path = chip_dir.join("out/host/chip-tool");
        let test_exe_path = self.test_exe_path(profile, target);
        let test_pics_path = self.test_pics_path(target);

        format!(
            "{} --log-level warn --target {} --runner chip_tool_python --chip-tool {} run --iterations 1 --test-timeout-seconds {} --all-clusters-app '{}' --pics-file {}",
            test_suite_path.display(),
            test_name,
            chip_tool_path.display(),
            timeout_secs,
            test_exe_path.display(),
            test_pics_path.display(),
        )
    }

    fn python_test_command(
        &self,
        test_name: &str,
        timeout_secs: u32,
        profile: &str,
        target: &str,
    ) -> anyhow::Result<String> {
        let chip_dir = self.chip_builder.chip_dir();
        let runner_path = chip_dir.join("scripts/tests/run_python_test.py");
        let test_exe_path = self.test_exe_path(profile, target);
        let script_path = chip_dir
            .join("src/python_testing")
            .join(format!("{test_name}.py"));

        if !script_path.exists() {
            anyhow::bail!(
                "Python test script not found: {} (expected for test `{test_name}`)",
                script_path.display(),
            );
        }

        // Standard rs-matter test commissioning values, sourced directly
        // from `rs_matter::dm::devices::test::TEST_DEV_COMM`.
        let test_comm = &rs_matter::dm::devices::test::TEST_DEV_COMM;
        let discriminator: u16 = test_comm.discriminator;
        let passcode: u32 = u32::from_le_bytes(*test_comm.password.access());

        // The Python test framework drives commissioning itself via
        // `--script-args`; the rs-matter test executable is launched
        // by `run_python_test.py` and passed via `--app`.
        //
        // `--storage-path` must be specified so that `--factory-reset` in
        // `run_python_test.py` also deletes the controller-side fabric state.
        // Without it, the Python SDK reuses stale fabric storage from previous
        // runs while the device has been factory-reset, causing AddNOC to fail.
        let extra_args = Self::extra_python_script_args(test_name);
        let script_args = format!(
            "--storage-path /tmp/rs_matter_python_test_storage.json \
             --commissioning-method on-network --discriminator {discriminator} \
             --passcode {passcode} --endpoint 1 \
             --paa-trust-store-path credentials/development/paa-root-certs{extra_args}"
        );

        Ok(format!(
            "timeout --kill-after=10s {timeout_secs}s \
             {} --app '{}' --factory-reset --script {} --script-args \"{}\"",
            runner_path.display(),
            test_exe_path.display(),
            script_path.display(),
            script_args,
        ))
    }

    /// Test-specific extra `--script-args` for `run_python_test.py`.
    ///
    /// Some `MatterBaseTest`-style scripts require PIXIT/PICS values supplied
    /// on the command line via the `--int-arg`, `--string-arg`, `--hex-arg`
    /// flags. Map them here per test, keyed by file stem, so the rest of the
    /// dispatch path stays uniform.
    fn extra_python_script_args(test_name: &str) -> &'static str {
        match test_name {
            // TC_ACE_1_4 needs the PIXITs that point at the application
            // endpoint/cluster/attribute exposed by `chip_tool_tests`. Endpoint 1
            // hosts the OnOff cluster on a `DEV_TYPE_ON_OFF_LIGHT` (device type
            // 0x0100 == 256).
            "TC_ACE_1_4" => {
                " --int-arg PIXIT.ACE.APPENDPOINT:1 \
                 --string-arg PIXIT.ACE.APPCLUSTER:OnOff \
                 --string-arg PIXIT.ACE.APPATTRIBUTE:OnOff \
                 --int-arg PIXIT.ACE.APPDEVTYPEID:256"
            }
            // ACL tests target the AccessControl cluster which lives on
            // endpoint 0. The default `--endpoint 1` we pass for application
            // tests would route ancillary helpers like
            // `get_latest_event_number` at endpoint 1, where there are no
            // ACL events. argparse keeps the last `--endpoint`, so appending
            // here wins.
            "TC_ACL_2_6" | "TC_ACL_2_7" | "TC_ACL_2_8" => " --endpoint 0",
            _ => "",
        }
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
