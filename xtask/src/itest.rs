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

use std::path::PathBuf;
use std::process::Command;

use clap::ValueEnum;

use log::{debug, info, warn};

use crate::common::{run_command, ChipBuilder};

/// System cluster tests + general Matter protocol/IM/SC tests.
///
/// Run against the `chip_tool_tests` example. This is the default suite
/// when `cargo xtask itest` is invoked without `--suite`.
///
/// Names matching the `TC_*` convention are dispatched to
/// `scripts/tests/run_python_test.py` and target a `MatterBaseTest`
/// in `src/python_testing/`. All other names are YAML test suites
/// dispatched to `scripts/tests/run_test_suite.py`.
pub(crate) const SYS_TESTS: &[&str] = &[
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
    "TC_IDM_1_2",
    "TC_IDM_1_4",
    "TC_IDM_2_2",
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
    "TC_CADMIN_1_3_4",
    // "TC_CADMIN_1_5", // Hits a CHIP-framework cleanup bug we can't patch
    //                  // from the device side. Step 7 (commission after the
    //                  // window has been revoked) expects exactly
    //                  // `CHIP_ERROR_TIMEOUT (0x32)`. To produce 0x32 the
    //                  // device must NOT reply to the PBKDFParamRequest —
    //                  // any status-report response surfaces as
    //                  // `INVALID_PASE_PARAMETER (0x38)`. The PASE responder
    //                  // (`pase/responder.rs`) does drop closed-window PASE
    //                  // attempts silently, which is CHIP-style behavior; with
    //                  // that, the controller's mDNS browse for the device's
    //                  // discriminator times out at 30 s, mapped to
    //                  // `CHIP_ERROR_TIMEOUT`, and step 7 *does* pass.
    //                  // However, `DeviceCommissioner::EstablishPASEConnection`
    //                  // (`CHIPDeviceController.cpp:734`) sets
    //                  // `mDeviceInPASEEstablishment` at the start of step 7
    //                  // and only clears it on the PASE-failure paths
    //                  // (`OnSessionEstablishmentError`); the
    //                  // mDNS-discovery-timeout path leaves it non-null.
    //                  // Step 15's `CommissionOnNetwork` then hits the
    //                  // `VerifyOrExit(mDeviceInPASEEstablishment == nullptr,
    //                  // INCORRECT_STATE)` guard and fails with 0x03 before
    //                  // ever leaving the controller. The other CADMIN tests
    //                  // (1_3_4, 1_9, 1_11, 1_15, 1_19, 1_22, 1_25) pass with
    //                  // the silent-drop change.
    "TC_CADMIN_1_9",
    "TC_CADMIN_1_11",
    "TC_CADMIN_1_15",
    "TC_CADMIN_1_19",
    "TC_CADMIN_1_22",
    "TC_CADMIN_1_25",
    // "TC_CADMIN_1_27",  // Skipped: requires the CHIP `jfc-server-app` (Joint Fabric Controller); rs-matter does not implement JF.
    // "TC_CADMIN_1_28",  // Skipped: requires the CHIP `jfc-server-app` (Joint Fabric Controller); rs-matter does not implement JF.
    "TC_CGEN_2_1",
    "TC_CGEN_2_2",
    "TC_CGEN_2_4",
    // "TC_CGEN_2_5",  // Skipped: requires `CGEN.S.F00` (TermsAndConditions feature); rs-matter does not implement TC.
    // "TC_CGEN_2_6",  // Skipped: requires `CGEN.S.F00` (TermsAndConditions feature); rs-matter does not implement TC.
    // "TC_CGEN_2_7",  // Skipped: requires `CGEN.S.F00` (TermsAndConditions feature); rs-matter does not implement TC.
    // "TC_CGEN_2_8",  // Skipped: requires `CGEN.S.F00` (TermsAndConditions feature); rs-matter does not implement TC.
    // "TC_CGEN_2_9",  // Skipped: requires `CGEN.S.F00` (TermsAndConditions feature); rs-matter does not implement TC.
    // "TC_CGEN_2_10", // Skipped: requires `CGEN.S.F00` (TermsAndConditions feature); rs-matter does not implement TC.
    // "TC_CGEN_2_11", // Skipped: requires `CGEN.S.F00` (TermsAndConditions feature); rs-matter does not implement TC.

    //
    // Python tests — Operational Credentials (system cluster)
    //
    "TC_OPCREDS_3_1",
    "TC_OPCREDS_3_2",
    "TC_OPCREDS_3_4",
    "TC_OPCREDS_3_5",
    "TC_OPCREDS_3_8",
    //
    // Python tests — Session/Commissioning (general Matter protocol)
    //
    "TC_SC_3_4",
    // "TC_SC_3_5", // Skipped: covers "CASE Error Handling [DUT_Initiator]" with a
    //              // *separate* CHIP `chip-all-clusters-app` running as TH_SERVER
    //              // (faulted via `FaultInjection` cluster on its CASE Sigma2). The
    //              // test executable build is wired (via `build_chip_all_clusters_app`,
    //              // triggered lazily by `needs_th_server_app`), `--string-arg
    //              // th_server_app_path` is passed, and the rs-matter DUT is moved off
    //              // port 5540 so TH_SERVER can take it (`--port 5541` via
    //              // `app_args_override`). The remaining blocker is that both apps
    //              // need to bind UDP/5353 for mDNS at the same time: CHIP CI gives
    //              // each app its own network namespace, but our wrapper does not
    //              // (the `Cannot open network namespace "app"` warning earlier in
    //              // the run is the framework giving up on netns isolation), so the
    //              // TH_SERVER's mDNS records are not visible to the test framework's
    //              // controller and `CommissionOnNetwork` for TH_SERVER fails with
    //              // `INVALID_PASE_PARAMETER`. Even with that resolved, the test
    //              // is a `MCORE.ROLE.COMMISSIONER` test and in `is_pics_sdk_ci_only`
    //              // mode all DUT_Commissioner steps short-circuit to "Y" — so it
    //              // exercises the all-clusters-app's FaultInjection cluster, not
    //              // any rs-matter code path.
    "TC_SC_3_6",
    // NOTE: TC_SC_4_1 step 11 asserts there is exactly one
    // `_CM._sub._matterc._udp.local.` PTR record on the LAN. It passes on
    // a clean network (e.g. a GitHub Actions runner) but breaks in dev
    // environments that already host another commissionable Matter device
    // (Home Assistant Matter bridge, ESP32 fixture, …). If you're seeing
    // this fail locally, it's the LAN, not rs-matter — comment the entry
    // back out for the duration of your local run.
    "TC_SC_4_1",
    "TC_SC_4_3",
    "TC_SC_7_1",
    //
    // Python tests — Basic Information (system cluster)
    //
    // The default `BasicInfoHandler` metadata excludes `ConfigurationVersion`
    // (provisional in Matter 1.5; upstream pulled it from the 1.5 dataset in
    // CHIP commit faf4d09ad1), so `TestBasicInformation`'s exact-set assertion
    // on `AttributeList` keeps passing. For `TC_BINFO_3_2` the
    // `chip_tool_tests` binary swaps in an alternate `Node` whose
    // `BasicInformation` cluster metadata exposes `ConfigurationVersion` — see
    // `NODE_BINFO_CV_EXPOSED` in `examples/src/bin/chip_tool_tests.rs`. The
    // switch is gated on the presence of `--app-pipe` (see `app_args_override`
    // below), which only this test passes.
    "TC_BINFO_3_2",
    //
    // Python tests — Groups (system cluster)
    //
    "TC_G_2_2",
    //
    // Python tests — General Diagnostics (system cluster)
    //
    "TC_DGGEN_2_4",
    // "TC_DGGEN_3_2", // TODO: requires `BasicInformation::MaxPathsPerInvoke`; same gap as TC_BINFO_3_2 — needs the attribute exposed.

    //
    // Python tests — Device Attestation (commissioning)
    //
    // "TC_DA_1_2", // TODO: `AttestationRequest` invoke fails (likely needs an armed fail-safe or different access path in rs-matter). Needs attestation flow review.
    // "TC_DA_1_5", // TODO: same setup issue as TC_DA_1_2 — DA test infrastructure needs the attestation invoke path to succeed before any of the cert-chain assertions can run.
    // "TC_DA_1_7", // Skipped: requires two distinct discriminators (DUT + reference DUT). The xtask wrapper only commissions one device.
    // "TC_DA_1_9", // TODO: not yet verified

    //
    // Python tests — Device Discovery (general)
    //
    // "TC_DD_1_16_17", // Skipped: must be invoked with `--manual-code`. The xtask wrapper passes `--discriminator`/`--passcode` instead.
    // "TC_DD_3_23",    // Skipped: requires PC/SC smart-card subsystem (`smartcard.pcsc`). Not available in the CI environment.

    //
    // Python tests — Device Composition / Conformance (general)
    //
    // "TC_DeviceBasicComposition", // TODO: wildcard read returns `InvalidDataType`/`Failure` for some attribute on cluster 49 (NetworkCommissioning). Likely encoder gap on a specific attribute.
    // "TC_DeviceConformance",      // TODO: device type revisions on the example endpoints don't match the spec-mandated values for the device types being advertised. Update the example apps' device-type revisions.
];

/// Camera cluster tests — run against the `camera_tests` example.
///
/// These target the clusters introduced in Matter 1.5 (Chime, CameraAvStream,
/// CameraAvSettings, ZoneManagement, PushAvStreamTransport, WebRTCProvider).
/// Only the _2_1 attribute-read tests are listed here; add more as they pass.
pub(crate) const CAMERA_TESTS: &[&str] = &[
    "TC_CHIME_2_1",
    "TC_AVSM_2_1",
    "TC_AVSUM_2_1",
    "TC_ZONEMGMT_2_1",
    "TC_PAVST_2_1",
    // WebRTC provider attribute read
    "TC_WEBRTCP_2_1",
];

/// LevelControl + OnOff YAML tests — run against the `dimmable_light` example.
///
/// Mirrors the list in `.github/workflows/chiptool-tests.yml`. Requires the
/// `chip-test` cargo feature on the build (see [`TestSuite::default_features`]).
pub(crate) const LIGHT_TESTS: &[&str] = &[
    "Test_TC_LVL_2_1",
    "Test_TC_LVL_2_2",
    "Test_TC_LVL_3_1",
    // "Test_TC_LVL_4_1", // TODO: not yet passing
    "Test_TC_LVL_5_1",
    "Test_TC_LVL_6_1",
    "Test_TC_LVL_7_1",
    // "Test_TC_LVL_9_1", // TODO: not yet passing
    "Test_TC_OO_2_1",
    "Test_TC_OO_2_2",
    "Test_TC_OO_2_4",
    "Test_TC_OO_2_6",
    // "Test_TC_OO_2_7", // TODO: not yet passing
];

/// A pre-canned test suite. Selects a default test list, the example
/// binary they run against, the cargo features it must be built with,
/// and a per-test timeout suitable for that suite.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum TestSuite {
    /// System clusters + general Matter protocol/IM/SC. Default suite.
    #[default]
    System,
    /// Same as `System` but only the Python `MatterBaseTest` scripts
    /// (names starting with `TC_`); skips the chip-tool YAML suites.
    /// Useful when iterating on a Python-test failure without paying the
    /// (long) cost of the full YAML pass that runs first in `System`.
    SystemPython,
    /// Same as `System` but only the chip-tool YAML suites (names not
    /// starting with `TC_`); skips the Python `MatterBaseTest` scripts.
    /// The mirror image of `SystemPython` — handy when iterating on a
    /// YAML-test regression in isolation.
    SystemYaml,
    /// Matter 1.5 camera-related clusters.
    Camera,
    /// OnOff + LevelControl, exercising the dimmable_light example.
    Light,
}

impl TestSuite {
    /// Default list of tests for this suite.
    pub(crate) fn default_tests(&self) -> Vec<&'static str> {
        match self {
            Self::System => SYS_TESTS.to_vec(),
            // YAML test suites have names like `TestFoo`; Python
            // `MatterBaseTest` scripts use the `TC_*` convention. Filter
            // the system suite down to just the latter.
            Self::SystemPython => SYS_TESTS
                .iter()
                .copied()
                .filter(|name| name.starts_with("TC_"))
                .collect(),
            // Mirror image: only YAML test suites.
            Self::SystemYaml => SYS_TESTS
                .iter()
                .copied()
                .filter(|name| !name.starts_with("TC_"))
                .collect(),
            Self::Camera => CAMERA_TESTS.to_vec(),
            Self::Light => LIGHT_TESTS.to_vec(),
        }
    }

    /// Default `--target` (example binary) for this suite.
    pub(crate) fn default_target(&self) -> &'static str {
        match self {
            Self::System | Self::SystemPython | Self::SystemYaml => "chip_tool_tests",
            Self::Camera => "camera_tests",
            Self::Light => "dimmable_light",
        }
    }

    /// Cargo features the example binary must be built with for this suite.
    pub(crate) fn default_features(&self) -> &'static [&'static str] {
        match self {
            Self::System | Self::SystemPython | Self::SystemYaml | Self::Camera => &[],
            Self::Light => &["chip-test"],
        }
    }

    /// Default per-test timeout in seconds.
    pub(crate) fn default_timeout_secs(&self) -> u32 {
        match self {
            Self::System | Self::SystemPython | Self::SystemYaml => 120,
            Self::Camera => 180,
            Self::Light => 500,
        }
    }
}

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
            info!("Using default (system) tests");

            SYS_TESTS.to_vec()
        };

        if tests.is_empty() {
            info!("No tests specified and no default tests enabled.");
            return Ok(());
        }

        debug!("About to run tests: {tests:?}");

        // Lazily build `chip-all-clusters-app` if any test in the list
        // needs a CHIP TH_SERVER (it's a heavy GN/ninja build, so we don't
        // pay for it in the common case). Cached on disk after the first
        // build.
        if tests.iter().any(|t| Self::needs_th_server_app(t)) {
            self.chip_builder.build_chip_all_clusters_app(None, false)?;
        }

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

        // Some tests legitimately need more wall-clock time than the default
        // (e.g. those that wait for a commissioning window to expire on its
        // own). Allow per-test overrides while keeping the global `--timeout`
        // as the floor for everything else.
        let timeout_secs = Self::per_test_timeout_secs(test_name).unwrap_or(timeout_secs);

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
        // Some tests (e.g. TC_SC_4_1) need to be commissioned via a setup
        // payload (manual or QR code) rather than the raw discriminator /
        // passcode pair, because their script logic inspects
        // `matter_test_config.manual_code` / `qr_code_content` to choose
        // between long- and short-discriminator mDNS subtypes. Passing
        // both `--discriminator`/`--passcode` *and* `--manual-code` makes
        // the framework attempt commissioning twice (once per setup
        // payload) and the second attempt times out, so we must drop the
        // raw form here.
        let commissioning_args = match Self::setup_payload_override(test_name) {
            Some(setup_payload) => setup_payload.to_string(),
            None => format!("--discriminator {discriminator} --passcode {passcode}"),
        };
        // A handful of tests (e.g. TC_SC_7_1) only do PASE establishment in
        // the test body itself, and assert that the device starts factory
        // reset. Pre-test commissioning would add a fabric and break the
        // assertion, so omit `--commissioning-method` for those tests.
        let commissioning_method = if Self::skip_pre_commissioning(test_name) {
            ""
        } else {
            "--commissioning-method on-network "
        };
        // A few tests need a *second* Matter device under the test framework's
        // control (`AppServerSubprocess`) — TC-SC-3.5 in particular, which
        // injects faults into a separate "TH_SERVER" Matter app. The CHIP
        // `chip-all-clusters-app` is the canonical implementation; its path
        // is plumbed in via the `th_server_app_path` string user-param.
        let th_server_arg = if Self::needs_th_server_app(test_name) {
            let app = chip_dir.join("out/host/chip-all-clusters-app");
            format!(" --string-arg th_server_app_path:{}", app.display())
        } else {
            String::new()
        };
        let script_args = format!(
            "--storage-path /tmp/rs_matter_python_test_storage.json \
             {commissioning_method}{commissioning_args} --endpoint 1 \
             --paa-trust-store-path credentials/development/paa-root-certs{extra_args}{th_server_arg}"
        );

        // Optional `--app-args` passed through to `chip_tool_tests`. Used by
        // tests like TC_SC_7_1 that require non-default discriminator /
        // passcode values, which the test then asserts (`assert_not_equal`
        // against `3840` / `20202021`).
        let app_args_clause = match Self::app_args_override(test_name) {
            Some(args) => format!(" --app-args '{args}'"),
            None => String::new(),
        };

        // Block the runner until the rs-matter app has actually started
        // serving on the wire before it is allowed to SIGTERM the previous
        // instance during `request_device_reboot()`. Without this the
        // monitor thread starts the new app and immediately tears down the
        // old one, while the controller — which has just expired its
        // sessions — re-handshakes against whichever process answers first.
        // That race lets a fresh CASE session get pinned to the dying
        // process; the next invoke (e.g. `RemoveFabric` in TC_ACL_2_10
        // step 14) then hits the new app, which has no such session, and
        // times out with `SessionNotFound`. The pattern matches the
        // `info!("Running Matter transport")` line emitted from
        // `rs_matter::transport::TransportRunner::run`.
        Ok(format!(
            "timeout --kill-after=10s {timeout_secs}s \
             {} --app '{}'{} --app-ready-pattern 'Running Matter transport' \
             --factory-reset --script {} --script-args \"{}\"",
            runner_path.display(),
            test_exe_path.display(),
            app_args_clause,
            script_path.display(),
            script_args,
        ))
    }

    /// Test-specific timeout override (in seconds) for tests that legitimately
    /// need more wall-clock time than the default. Returning `None` falls
    /// back to whatever `--timeout` was passed on the `cargo xtask itest`
    /// command line.
    fn per_test_timeout_secs(test_name: &str) -> Option<u32> {
        match test_name {
            // Several CADMIN tests open commissioning windows and then wait
            // for them to expire on the device side, which takes 180s+ by
            // construction.
            "TC_CADMIN_1_3_4" | "TC_CADMIN_1_5" | "TC_CADMIN_1_9" | "TC_CADMIN_1_11"
            | "TC_CADMIN_1_15" | "TC_CADMIN_1_22" | "TC_CADMIN_1_25" => Some(300),
            // TC_OPCREDS_3_8 exercises the VID-Verification feature (Matter
            // 1.4): it sets a 400-byte VVSC and an 85-byte
            // VIDVerificationStatement on a fabric and then issues
            // non-fabric-filtered reads of `NOCs` / `Fabrics` covering both
            // fabrics. With two ~750-byte struct entries plus the 400-byte
            // VVSC the response cannot fit in a single MTU and rs-matter
            // falls back to its chunked-read path, which on the debug
            // profile is dominated by per-error backtrace dumps. Bump the
            // per-test ceiling so the chunked transfer has time to
            // complete; the test passes in well under a minute on release.
            "TC_OPCREDS_3_8" => Some(300),
            _ => None,
        }
    }

    /// Replace the default `--discriminator`/`--passcode` commissioning
    /// arguments with a setup-payload form (e.g. `--manual-code <code>`)
    /// for tests whose script logic requires it. Returns `None` for tests
    /// that take the default raw-credentials form.
    ///
    /// rs-matter's standard test pairing code is printed by the test
    /// executable at startup as `PairingCode: [3497-0112-332]`
    /// (digits `34970112332`); it encodes `discriminator=3840` and
    /// `passcode=20202021` from `TEST_DEV_COMM`.
    fn setup_payload_override(test_name: &str) -> Option<&'static str> {
        match test_name {
            // TC_SC_4_1 inspects `matter_test_config.manual_code` /
            // `qr_code_content` to decide between long- and
            // short-discriminator mDNS subtypes (`_L<id>` vs `_S<id>`).
            // Without one of those fields its
            // `setup_code_type = NONE_SUPLIED` and step 9 bails.
            "TC_SC_4_1" => Some("--manual-code 34970112332"),
            // TC_SC_7_1 in post-cert mode asserts the device is *not* using
            // the spec-default discriminator (3840) / passcode (20202021).
            // The QR code matches the values we pass to `chip_tool_tests`
            // via `--app-args` (see `app_args_override`).
            "TC_SC_7_1" => Some("--qr-code MT:-24J0KCZ16N71648G00"),
            _ => None,
        }
    }

    /// Tests that should NOT trigger the framework's pre-test commissioning
    /// pass. Returning `true` causes `--commissioning-method` to be omitted
    /// from `--script-args`, so `MatterBaseTest` skips its `CommissionDevice`
    /// step and the test body runs against a factory-fresh device.
    fn skip_pre_commissioning(test_name: &str) -> bool {
        // TC_SC_7_1 only does PASE establishment in the test body and
        // explicitly asserts that no fabrics exist on the device when
        // step 1 runs.
        matches!(test_name, "TC_SC_7_1")
    }

    /// Tests that need the CHIP `chip-all-clusters-app` binary spawned as a
    /// secondary "TH_SERVER" Matter device under the test framework's
    /// control (`matter.testing.apps.AppServerSubprocess`). `setup()` builds
    /// the app once into the chip output tree; here we just signal that the
    /// test needs the `th_server_app_path` string user-param injected.
    fn needs_th_server_app(test_name: &str) -> bool {
        // TC_SC_3_5 ("CASE Error Handling [DUT_Initiator]") spawns a TH_SERVER
        // and uses CHIP's `FaultInjection` cluster on it to corrupt Sigma2
        // fields (NOC, ICAC, signature, TBEData2). The test bails out of
        // `setup_class` if the path isn't supplied.
        matches!(test_name, "TC_SC_3_5")
    }

    /// Optional `--app-args` passed straight through to `chip_tool_tests`.
    ///
    /// `chip_tool_tests` recognises `--discriminator <u16>` and
    /// `--passcode <u32>`; both override the spec-default `TEST_DEV_COMM`
    /// values for tests that demand non-defaults.
    fn app_args_override(test_name: &str) -> Option<&'static str> {
        match test_name {
            // Match the values encoded in the QR code returned by
            // `setup_payload_override` for this test (MT:-24J0KCZ16N71648G00).
            "TC_SC_7_1" => Some("--discriminator 2222 --passcode 20202024"),
            // TC_SC_3_5 spawns `chip-all-clusters-app` as TH_SERVER on the
            // default Matter port (5540). The rs-matter DUT must move to a
            // different port so the two apps don't fight over the bind.
            "TC_SC_3_5" => Some("--port 5541"),
            // TC_BINFO_3_2 simulates a configuration-version change via the
            // CHIP `app-pipe` mechanism — the test writes
            // `{"Name":"SimulateConfigurationVersionChange"}` to the named
            // pipe and the DUT translates that into a
            // `DataModel::bump_configuration_version` call.
            "TC_BINFO_3_2" => Some("--app-pipe /tmp/rs_matter_bin_info_3_2_fifo"),
            _ => None,
        }
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
            // TC_CGEN_2_2 lives on the root endpoint (GeneralCommissioning /
            // OperationalCredentials clusters) and uses
            // `PIXIT.CGEN.FailsafeExpiryLengthSeconds` to bound the fail-safe
            // window for several "arm → mutate → read" sub-flows. With the CI
            // default of 1s the fail-safe expires mid-way through chunked
            // reads of the (relatively large) `TrustedRootCertificates`
            // attribute on a debug build, so the pending root certificate is
            // dropped before the response finishes serializing. Bump it to a
            // value that survives chunking on a slow build while keeping the
            // overall test runtime reasonable.
            //
            // The `--PICS` file enables `PICS_SDK_CI_ONLY=1`, which the test
            // uses to skip the step #38–#44 sub-flow. Those steps reassign
            // the test's local `maxFailsafe` to `failsafe_expiration_seconds`
            // and then assert that the *device's* fail-safe times out after
            // that shortened window — which only holds if the device's
            // `BasicCommissioningInfo.MaxCumulativeFailsafeSeconds` is set
            // to the same small value. rs-matter advertises 900s here (see
            // `CommPolicy::failsafe_max_cml_secs`), so the Cert path's
            // assumption does not match this device and step #44 would always
            // see the still-armed pending root cert. CI mode covers the same
            // attribute / command surface without that assumption.
            "TC_CGEN_2_2" => {
                " --endpoint 0 --int-arg PIXIT.CGEN.FailsafeExpiryLengthSeconds:10 \
                 --PICS src/app/tests/suites/certification/ci-pics-values"
            }
            "TC_CGEN_2_4" => " --endpoint 0",
            // TC_BINFO_3_2 (BasicInformation::ConfigurationVersion) takes the
            // simulated-bump path only when `is_pics_sdk_ci_only` is True, so
            // we must hand the controller a PICS file that sets
            // `PICS_SDK_CI_ONLY=1`. The matching `--app-pipe` path is
            // mirrored on the DUT side via `app_args_override`.
            "TC_BINFO_3_2" => {
                " --endpoint 0 \
                 --PICS src/app/tests/suites/certification/ci-pics-values \
                 --app-pipe /tmp/rs_matter_bin_info_3_2_fifo"
            }
            // TC_OPCREDS_3_8 reads `NOCs` non-fabric-filtered with two
            // fabrics, each carrying a max-sized 400-byte VVSC; the
            // resulting payload is well past one MTU and rs-matter falls
            // back to chunked reads. On the debug profile every chunk
            // boundary triggers an `Error::NoSpace` whose backtrace dump
            // dominates the per-chunk wall-clock. Bumping the test's
            // `default_timeout` (90 s) past the per_endpoint_runner
            // wait_for is enough to let the chunked transfers finish; the
            // test passes in well under 30 s on release.
            "TC_OPCREDS_3_8" => " --endpoint 0 --timeout 240",
            // TC_SC_4_1: setup payload is supplied via
            // `setup_payload_override`; this entry just routes it to
            // endpoint 0 like the other root-endpoint tests.
            "TC_SC_4_1" => " --endpoint 0",
            // CADMIN (Administrator Commissioning) tests target the root
            // endpoint via `@run_if_endpoint_matches(has_cluster(...))`.
            "TC_CADMIN_1_3_4"
            | "TC_CADMIN_1_5"
            | "TC_CADMIN_1_9"
            | "TC_CADMIN_1_11"
            | "TC_CADMIN_1_15"
            | "TC_CADMIN_1_22"
            | "TC_CADMIN_1_25"
            // CGEN (General Commissioning) tests target the root endpoint
            // where the GeneralCommissioning cluster lives.
            | "TC_CGEN_2_1"
            // OPCREDS (Operational Credentials) tests live on the root
            // endpoint.
            | "TC_OPCREDS_3_1"
            | "TC_OPCREDS_3_2"
            | "TC_OPCREDS_3_4"
            | "TC_OPCREDS_3_5"
            // SC (Secure Channel) tests target the root endpoint.
            // (TC_SC_4_1 has its own arm above for the `--manual-code`
            // setup-payload form.)
            | "TC_SC_3_4"
            | "TC_SC_3_6"
            | "TC_SC_4_3"
            // DGGEN (General Diagnostics) lives on the root endpoint.
            | "TC_DGGEN_2_4"
            | "TC_DGGEN_3_2"
            // Groups (TC_G_2_2) defaults to endpoint 0 if not provided.
            | "TC_G_2_2"
            // Device Attestation (DA) covers attestation primitives on the
            // root endpoint.
            | "TC_DA_1_2"
            | "TC_DA_1_5"
            | "TC_DA_1_7" => " --endpoint 0",
            // TC_SC_7_1 supports a "post-cert" single-DUT mode that swaps
            // the two-device commissioning-codes assertion for direct
            // factory-state and non-default-credentials checks against the
            // sole DUT. Without `post_cert_test:true` the test bails out
            // before step 1 demanding a second discriminator. Routes to
            // endpoint 0 like the other root-endpoint SC tests.
            "TC_SC_7_1" => " --bool-arg post_cert_test:true --endpoint 0",
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
