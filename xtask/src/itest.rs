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
    "TC_CADMIN_1_5",
    "TC_CADMIN_1_9",
    "TC_CADMIN_1_11",
    "TC_CADMIN_1_15",
    // "TC_CADMIN_1_19",  // TODO: multi-fabric stress test commissions `SupportedFabrics` controllers back-to-back. Fails part-way with `Incorrect state` from the Python pairing controller. Likely needs deeper investigation of CASE setup between rapid commissioning rounds; not blocking other coverage.
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
    // "TC_OPCREDS_3_4", // TODO: `UpdateNOC` returns `FailSafeRequired` / `NocMissingCsr` on the negative paths, but the test expects the spec's specific `NodeOperationalCertStatusEnum` values for each error condition. Needs alignment of error mapping.
    // "TC_OPCREDS_3_5", // TODO: `UpdateNOC` returns `kMissingCsr` instead of `kOk` even on the valid happy path — looks like the CSR slot is being cleared too eagerly between the CSR request and the `UpdateNOC` call.
    // "TC_OPCREDS_3_8", // TODO: a second-fabric NOC entry is not visible in the `NOCs` attribute when read non-fabric-filtered — likely a fabric-scoped attribute filter incorrectly applied to a non-fabric-filtered read.

    //
    // Python tests — Session/Commissioning (general Matter protocol)
    //
    // "TC_SC_3_4", // TODO: a negative-path assertion expects `ChipStackError` to be raised but rs-matter accepts the request. Needs investigation of which validation step is missing.
    // "TC_SC_3_5", // Skipped: requires the CHIP `all-clusters-app` (`--string-arg th_server_app_path`); rs-matter does not provide the secondary TH server app this test relies on.
    // "TC_SC_3_6", // TODO: triggers an internal exception during the multi-fabric subscription scenario; needs investigation alongside the other multi-fabric stress tests.
    // "TC_SC_4_1", // Skipped: must be invoked with `--qr-code`/`--manual-code` setup payloads instead of `--discriminator`/`--passcode`. The xtask wrapper passes the latter.
    // "TC_SC_4_3", // TODO: the discovery PTR record `D4E76DDAABB4974F-0000000012344321` is not advertised on the loopback mDNS the test scrapes. Needs the rs-matter mDNS layer to publish the operational instance name in that test environment.
    // "TC_SC_7_1", // Skipped: must be invoked with `--qr-code`/`--manual-code` setup payloads instead of `--discriminator`/`--passcode`. The xtask wrapper passes the latter.

    //
    // Python tests — Basic Information (system cluster)
    //
    // "TC_BINFO_3_2", // TODO: requires `BasicInformation::ConfigurationVersion` (1.5+ attribute); rs-matter returns `UnsupportedCluster` on the read. Add the attribute to the BINFO cluster.

    //
    // Python tests — Groups (system cluster)
    //
    "TC_G_2_2",
    //
    // Python tests — General Diagnostics (system cluster)
    //
    // "TC_DGGEN_2_4", // TODO: rs-matter does not advertise `GeneralDiagnostics::UpTime` (returns `UnsupportedAttribute`). Implement the attribute in the diagnostics cluster.
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
    /// Matter 1.5 camera-related clusters.
    Camera,
    /// OnOff + LevelControl, exercising the dimmable_light example.
    Light,
}

impl TestSuite {
    /// Default list of tests for this suite.
    pub(crate) fn default_tests(&self) -> &'static [&'static str] {
        match self {
            Self::System => SYS_TESTS,
            Self::Camera => CAMERA_TESTS,
            Self::Light => LIGHT_TESTS,
        }
    }

    /// Default `--target` (example binary) for this suite.
    pub(crate) fn default_target(&self) -> &'static str {
        match self {
            Self::System => "chip_tool_tests",
            Self::Camera => "camera_tests",
            Self::Light => "dimmable_light",
        }
    }

    /// Cargo features the example binary must be built with for this suite.
    pub(crate) fn default_features(&self) -> &'static [&'static str] {
        match self {
            Self::System | Self::Camera => &[],
            Self::Light => &["chip-test"],
        }
    }

    /// Default per-test timeout in seconds.
    pub(crate) fn default_timeout_secs(&self) -> u32 {
        match self {
            Self::System => 120,
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
        let script_args = format!(
            "--storage-path /tmp/rs_matter_python_test_storage.json \
             --commissioning-method on-network --discriminator {discriminator} \
             --passcode {passcode} --endpoint 1 \
             --paa-trust-store-path credentials/development/paa-root-certs{extra_args}"
        );

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
             {} --app '{}' --app-ready-pattern 'Running Matter transport' \
             --factory-reset --script {} --script-args \"{}\"",
            runner_path.display(),
            test_exe_path.display(),
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
            | "TC_OPCREDS_3_8"
            // SC (Secure Channel) tests target the root endpoint.
            | "TC_SC_3_4"
            | "TC_SC_3_6"
            | "TC_SC_4_1"
            | "TC_SC_4_3"
            | "TC_SC_7_1"
            // BINFO (Basic Information), DGGEN (General Diagnostics) live on
            // the root endpoint.
            | "TC_BINFO_3_2"
            | "TC_DGGEN_2_4"
            | "TC_DGGEN_3_2"
            // Groups (TC_G_2_2) defaults to endpoint 0 if not provided.
            | "TC_G_2_2"
            // Device Attestation (DA) covers attestation primitives on the
            // root endpoint.
            | "TC_DA_1_2"
            | "TC_DA_1_5"
            | "TC_DA_1_7" => " --endpoint 0",
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
