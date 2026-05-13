/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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
    "TestBinding",
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
    "TestIdentifyCluster",
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
    "TestUserLabelCluster",
    "TestUserLabelClusterConstraints",
    // "TestTimeSynchronization", // Skipped: TimeSynchronization cluster not implemented by rs-matter (optional, Matter spec §11.16).
    // "TestIcdManagementCluster", // Skipped: ICD Management cluster not implemented (rs-matter doesn't ship Intermittently Connected Device support).
    "TestUnitTestingClusterMei",
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
    "TC_ACL_2_5", // Tests the optional `AccessControlExtension` feature (Extension attribute) — `@run_if_endpoint_matches(has_attribute(AccessControl.Extension))` skips cleanly via `no_fail_on_skipped.py`.
    "TC_ACL_2_6",
    // "TC_ACL_2_7", // Skipped: tests the optional `AccessControlExtension` feature (Extension attribute), not implemented by rs-matter.
    // "TC_ACL_2_8", // Skipped: the test re-runs itself internally with legacy list encoding after the modern-encoding pass. The Python framework's between-runs controller cleanup is buggy (`object NoneType can't be used in 'await' expression`) and leaves stale fabrics on the DUT, so the second commissioning fails with `Incorrect state`. The modern-encoding pass — including fabric-scoped event filtering — is exercised end-to-end and passes.
    "TC_ACL_2_9",
    "TC_ACL_2_10",
    // "TC_ACL_2_11", // Skipped: tests the provisional `ManagedAclRestrictions` feature (ARL attribute) and requires manufacturer-specific access restrictions to be pre-configured. rs-matter does not implement this feature.
    // TC_AccessChecker subclasses `BasicCompositionTests` and calls
    // `setup_class_helper()` with the default `allow_pase=True`. The
    // resulting PASE+CASE race is fragile against a recently-commissioned
    // rs-matter DUT regardless of BLE/BlueZ availability: with no BlueZ it
    // hangs ~25 s on `org.bluez` D-Bus activation; with BlueZ active it
    // discovers via mDNS, sends a `PBKDFParamRequest`, gets silently
    // dropped (closed-window — needed for TC_CADMIN_1_5), and the
    // controller leaks a stale "in-progress PASE" entry which a later
    // `GetConnectedDevice(allowPASE=True)` picks up. Either path lands at
    // `CHIP Error 0x00000048: Not connected` in the test body. We route
    // this test through `xtask/scripts/no_pase_setup_class_helper.py`
    // (see `Self::needs_no_pase_shim`) which monkey-patches
    // `setup_class_helper`'s default to `allow_pase=False`, so the PASE
    // leg never fires and neither failure mode can.
    "TC_AccessChecker",
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
    // TC_CGEN_2_5..2_11 verify the TermsAndConditions feature (Matter 1.4+,
    // `CGEN.S.F00`). rs-matter does not implement TC and each test body
    // gates itself on `check_pics("CGEN.S.F00")` to skip cleanly. We route
    // them through the `no_fail_on_skipped.py` wrapper (see
    // `Self::needs_no_fail_on_skipped`) so the framework's hardcoded
    // `--fail-on-skipped` does not flip a clean skip into a runner failure.
    // PIXIT.CGEN.* dummy values are supplied via `extra_python_script_args`.
    "TC_CGEN_2_5",
    "TC_CGEN_2_6",
    "TC_CGEN_2_7",
    "TC_CGEN_2_8",
    "TC_CGEN_2_9",
    "TC_CGEN_2_10",
    "TC_CGEN_2_11",
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
    // [TC-SC-3.5] CASE Error Handling [DUT_Initiator]: spawns a *separate* CHIP
    // `chip-all-clusters-app` (TH_SERVER) and uses its `FaultInjection` cluster
    // to corrupt fields in the Sigma2 it sends back during CASE Handshake — the
    // test then drives a DUT_Commissioner through the resulting CASE failures.
    // We pass `--string-arg th_server_app_path:<chip-all-clusters-app>` (built
    // lazily via `needs_chip_all_clusters_app`), move chip_tool_tests off the
    // default Matter port via `--port 5541` so TH_SERVER can take 5540, and
    // hand the test `--PICS ci-pics-values` so `is_pics_sdk_ci_only=True` —
    // without that flag, every "TH prompts the user to commission DUT" step
    // requires a real DUT_Commissioner, which rs-matter isn't, and the steps
    // hang on `wait_for_user_input`. With the flag, those DUT_Commissioner
    // steps short-circuit to "Y" and the test verifies the framework
    // controller's CASE-error handling against the FaultInjection-corrupted
    // chip-all-clusters-app. NB: rs-matter code is exercised only via the
    // initial CommissionDeviceTest commissioning of chip_tool_tests itself —
    // the body of the test then drives the controller against TH_SERVER, not
    // against the rs-matter DUT.
    "TC_SC_3_5",
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
    // Python tests — Network Commissioning (system cluster)
    //
    "TC_CNET_1_4",
    // "TC_CNET_4_1",  // TODO: Wi-Fi network provisioning.
    // "TC_CNET_4_2",  // TODO: Wi-Fi network provisioning.
    // "TC_CNET_4_3",  // TODO: Wi-Fi network provisioning.
    // "TC_CNET_4_4",  // TODO: Thread network provisioning.
    // "TC_CNET_4_9",  // TODO: Thread network provisioning.
    // "TC_CNET_4_10", // TODO: Wi-Fi network provisioning.
    // "TC_CNET_4_12", // TODO: Wi-Fi network provisioning.
    // "TC_CNET_4_15", // TODO: Wi-Fi network provisioning.
    // "TC_CNET_4_16", // TODO: Wi-Fi network provisioning.
    // "TC_CNET_4_22", // TODO: Thread network provisioning.

    //
    // Python tests — General Diagnostics (system cluster)
    //
    "TC_DGGEN_2_4",
    "TC_DGGEN_3_2",
    "TC_TestEventTrigger",
    //
    // Python tests — Software Diagnostics (optional system cluster)
    //
    // SoftwareDiagnostics cluster not implemented by rs-matter (optional, Matter spec §11.13);
    // both tests use `@run_if_endpoint_matches(has_cluster(SoftwareDiagnostics))` which skips cleanly
    // via `no_fail_on_skipped.py`.
    "TC_DGSW_2_1",
    "TC_DGSW_2_2",
    //
    // Python tests — Time Synchronization (optional system cluster)
    //
    "TC_TIMESYNC_2_1", // TimeSynchronization not implemented (optional, Matter spec §11.16); `@run_if_endpoint_matches(has_cluster(TimeSynchronization) and has_attribute(TimeSource))` skips cleanly via `no_fail_on_skipped.py`.
    // "TC_TIMESYNC_2_2",  // Skipped: TimeSynchronization cluster not implemented by rs-matter.
    // "TC_TIMESYNC_2_4",  // Skipped: TimeSynchronization cluster not implemented by rs-matter.
    // "TC_TIMESYNC_2_5",  // Skipped: TimeSynchronization cluster not implemented by rs-matter.
    // "TC_TIMESYNC_2_6",  // Skipped: TimeSynchronization cluster not implemented by rs-matter.
    // "TC_TIMESYNC_2_7",  // Skipped: TimeSynchronization cluster not implemented by rs-matter.
    // "TC_TIMESYNC_2_8",  // Skipped: TimeSynchronization cluster not implemented by rs-matter.
    // "TC_TIMESYNC_2_9",  // Skipped: TimeSynchronization cluster not implemented by rs-matter.
    // "TC_TIMESYNC_2_10", // Skipped: TimeSynchronization cluster not implemented by rs-matter.
    // "TC_TIMESYNC_2_11", // Skipped: TimeSynchronization cluster not implemented by rs-matter.
    // "TC_TIMESYNC_2_12", // Skipped: TimeSynchronization cluster not implemented by rs-matter.
    // "TC_TIMESYNC_2_13", // Skipped: TimeSynchronization cluster not implemented by rs-matter.
    // "TC_TIMESYNC_3_1",  // Skipped: TimeSynchronization cluster not implemented by rs-matter.

    //
    // Python tests — ICD Management (optional system cluster)
    //
    // "TC_ICDM_2_1", // Skipped: ICD Management cluster not implemented by rs-matter (Intermittently Connected Devices, optional, Matter spec §9.17).
    // "TC_ICDM_3_1", // Skipped: ICD Management cluster not implemented by rs-matter.
    // "TC_ICDM_3_2", // Skipped: ICD Management cluster not implemented by rs-matter.
    // "TC_ICDM_3_3", // Skipped: ICD Management cluster not implemented by rs-matter.
    // "TC_ICDM_3_4", // Skipped: ICD Management cluster not implemented by rs-matter.
    // "TC_ICDM_5_1", // Skipped: ICD Management cluster not implemented by rs-matter.
    // "TC_ICDManagementCluster", // Skipped: ICD Management cluster not implemented by rs-matter.

    //
    // Python tests — Localization clusters (optional)
    //
    // Localization clusters not implemented by rs-matter (optional, Matter spec §11.4–11.6);
    // each test uses `@run_if_endpoint_matches(has_cluster(...))` which skips cleanly via `no_fail_on_skipped.py`.
    "TC_LCFG_2_1",
    "TC_LTIME_3_1",
    "TC_LUNIT_3_1",
    //
    // Python tests — Power Source (optional system cluster)
    //
    // "TC_PS_2_3", // Skipped: PowerSource cluster not implemented by rs-matter (optional, Matter spec §11.7).

    //
    // Python tests — Fixed Label (optional system cluster)
    //
    "TC_FLABEL_2_1", // FixedLabel wired on EP1 of `chip_tool_tests` with two static
    //                  spec-conformant entries (see `FIXED_LABELS_EP1`). The test reads
    //                  the list, attempts a write (expected `UnsupportedWrite` since
    //                  `LabelList` is read-only), and re-reads to confirm stability.
    //
    // Python tests — Bridged Device Basic Information (optional, bridges)
    //
    // "TC_BRBINFO_3_2", // Skipped: rs-matter does not implement bridge devices (BridgedDeviceBasicInformation cluster, Matter spec §9.13).
    // "TC_BRBINFO_4_1", // Skipped: rs-matter does not implement bridge devices.

    //
    // Python tests — Switch (optional application cluster)
    //
    "TC_SWTCH", // Switch cluster not implemented (Matter spec §1.13); 5 inner test methods, each `@run_if_endpoint_matches(has_feature(Switch, ...))`, all skip cleanly via `no_fail_on_skipped.py`.
    //
    // Python tests — Device Attestation (commissioning)
    //
    "TC_DA_1_2",
    "TC_DA_1_5",
    "TC_DA_1_7",
    "TC_DA_1_9",
    //
    // Python tests — Device Discovery (general)
    //
    "TC_DD_1_16_17",
    // "TC_DD_3_23", // Skipped: triple blocker. (1) The test imports
    //               // `matter.testing.matter_nfc_interaction`, which itself
    //               // imports `smartcard.System` — the `smartcard` PC/SC
    //               // Python binding isn't installed in the chip pigweed venv,
    //               // so the script fails at import time. (2) Even with the
    //               // module, `connect_read_nfc_tag_data` drives a physical
    //               // PC/SC NFC reader connected to the host, which the CI
    //               // environment doesn't provide. (3) rs-matter does not
    //               // implement Matter 1.5's NFC-based commissioning transport,
    //               // so step 2's `supports_nfc_commissioning` assertion would
    //               // fail even if (1) and (2) were resolved. Re-enable once
    //               // the NFC commissioning device-side feature lands.

    //
    // Python tests — Device Composition / Conformance (general)
    //
    // "TC_DeviceBasicComposition",
    //   // Bundles several MatterBaseTests run after a single wildcard read.
    //   // The `BasicCompositionTests.setup_class_helper()` PASE blocker that
    //   // hits TC_AccessChecker is already worked around for this test too
    //   // (added to `Self::needs_no_pase_shim` — re-enable here when the
    //   // gaps below are closed and the PASE shim already routes setup
    //   // through `xtask/scripts/no_pase_setup_class_helper.py`). The
    //   // remaining independent gaps:
    //   //
    //   // 1. `test_TC_DESC_2_2` — checks `Descriptor::TagList` /
    //   //    `EndpointUniqueID` semantic-tag attributes per Matter Core
    //   //    spec §9.5 to validate tree-composition tagging on every
    //   //    endpoint. rs-matter's `DescHandler` doesn't yet expose these.
    //   //
    //   // 2. `test_TC_IDM_10_1` — performs a wildcard *event* subscribe
    //   //    across all endpoints/clusters and asserts no failures. Needs
    //   //    a triage pass over rs-matter's event-subscription surface.
    //   //
    //   // 3. The wildcard read also pulls
    //   //    `UnitTesting::GeneralErrorBoolean` (attr 0x31, returns
    //   //    `InvalidDataType`) and `UnitTesting::ClusterErrorBoolean`
    //   //    (0x32, returns `Invalid`) — see `unit_testing.rs:1042-1048`.
    //   //    They're spec-mandated to error out (test fixtures for cluster
    //   //    error handling), but `TC_IDM_12_1`'s JSON dump records them as
    //   //    `49:ERROR` / `50:ERROR` and the surrounding tests treat the
    //   //    decode failures as device problems.
    //
    // "TC_DeviceConformance",
    //   // Runs the upstream device-conformance suite (six sub-tests:
    //   // `test_TC_DESC_2_3`, `test_TC_IDM_10_2`/`_3`/`_5`/`_6`,
    //   // `test_TC_IDM_14_1`) after a wildcard read of the full
    //   // attribute/command surface. The PASE+CASE race in
    //   // `BasicCompositionTests.setup_class_helper` is already worked
    //   // around via `Self::needs_no_pase_shim` (which routes setup
    //   // through `xtask/scripts/no_pase_setup_class_helper.py`), and
    //   // the suite is invoked with
    //   // `--bool-arg ignore_in_progress:True allow_provisional:True`
    //   // plus `--PICS .../ci-pics-values` (see
    //   // `Self::extra_python_script_args`).
    //   //
    //   // Current status: **5 of 6 sub-tests pass**
    //   //   - DESC_2_3 ✓
    //   //   - IDM_10_2 ✓ (cleared by `gen_comm.rs:220`'s
    //   //     `with_cmds(except!(CommandId::SetTCAcknowledgements))` —
    //   //     drops the TC-feature-gated commands from
    //   //     `AcceptedCommandList` per Matter Core spec §11.10.5)
    //   //   - IDM_10_3 ✓
    //   //   - IDM_10_5 ✗ (the only remaining failure — see below)
    //   //   - IDM_10_6 ✓ (cleared by bumping `DEV_TYPE_ROOT_NODE.drev`
    //   //     1→4 and `DEV_TYPE_ON_OFF_LIGHT.drev` 2→3 in
    //   //     `rs-matter/src/dm/devices.rs`; rev-4 Root Node additions
    //   //     are all conditional/optional, rev-3 On/Off Light just
    //   //     swaps deprecated Scenes 0x0005 for Scenes Management
    //   //     0x0062 — see Device Library §2.1.1 / §4.1.1)
    //   //   - IDM_14_1 ✓
    //   //
    //   // `test_TC_IDM_10_5` (device-type conformance) still fails on
    //   // two problem entries:
    //   //
    //   //   a. **Groups on EP0** (1 problem, deliberate). The
    //   //      `chip_tool_tests` fixture re-adds Groups at root for
    //   //      the `TestGroupMessaging` YAML test (group-addressed
    //   //      writes to `BasicInformation::NodeLabel` need EP0 to be
    //   //      a member of a multicast group, which only works via
    //   //      per-endpoint Groups membership per App Cluster §1.3).
    //   //      Matter Core §7.16.4 explicitly permits extra clusters
    //   //      on an endpoint, but the conformance checker takes a
    //   //      strict view. See the `NODE` doc comment in
    //   //      `examples/src/bin/chip_tool_tests.rs` for the full
    //   //      rationale; the library-level `with_*_sys()` chain and
    //   //      the `g*` macro variants no longer add Groups at root,
    //   //      so device-type-pure compositions are the *default*.
    //   //
    //   //   b. **Scenes Management cluster** missing on EP1/EP2
    //   //      (2 problems). On/Off Light at rev 3 mandates Scenes
    //   //      Management (0x0062). This is a substantial new cluster
    //   //      implementation (multiple commands — `AddScene`,
    //   //      `ViewScene`, `RemoveScene`, `RemoveAllScenes`,
    //   //      `StoreScene`, `RecallScene`, `GetSceneMembership`,
    //   //      `CopyScene` — plus persistent scene-table storage).
    //   //      Tracked separately as a future workstream.
    //   //
    //   // Re-enable once Scenes Management is implemented.
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
        // needs a secondary CHIP Matter device (TH_SERVER for TC-SC-3.5, or
        // the spawn-and-commission-revoked-DAC fixtures used by TC-DA-1.9).
        // It's a heavy GN/ninja build, so we don't pay for it in the common
        // case. Cached on disk after the first build.
        if tests.iter().any(|t| Self::needs_chip_all_clusters_app(t)) {
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
        let extra_args_clause = if extra_args.is_empty() {
            String::new()
        } else {
            format!(" {extra_args}")
        };
        let script_args = format!(
            "--storage-path /tmp/rs_matter_python_test_storage.json \
             {commissioning_method}{commissioning_args} --endpoint 1 \
             --paa-trust-store-path credentials/development/paa-root-certs{extra_args_clause}{th_server_arg}"
        );

        // Optional `--app-args` passed through to `chip_tool_tests`. Used by
        // tests like TC_SC_7_1 that require non-default discriminator /
        // passcode values, which the test then asserts (`assert_not_equal`
        // against `3840` / `20202021`).
        let app_args_clause = match Self::app_args_override(test_name) {
            Some(args) => format!(" --app-args '{args}'"),
            None => String::new(),
        };

        // Some tests need a vendored Python wrapper substituted in place of
        // the real test script — the wrapper monkey-patches state /
        // sys.argv, then `runpy`s the real script as `__main__`. The real
        // path is communicated via the `RS_MATTER_REAL_TEST_SCRIPT` env var.
        //
        //  * `no_pase_setup_class_helper.py` — flips
        //    `BasicCompositionTests.setup_class_helper`'s `allow_pase`
        //    default to `False` (see `Self::needs_no_pase_shim`).
        //
        //  * `no_fail_on_skipped.py` — strips `--fail-on-skipped` from
        //    `sys.argv` so test bodies that gracefully skip on a missing
        //    optional feature (e.g. TC) don't flip the run exit code (see
        //    `Self::needs_no_fail_on_skipped`).
        //
        // The two are mutually exclusive in the current test list; if a
        // future test ever needs both, write a combined shim rather than
        // chaining them.
        let (effective_script, real_script_env) = if Self::needs_no_pase_shim(test_name) {
            (
                self.workspace_dir
                    .join("xtask/scripts/no_pase_setup_class_helper.py"),
                format!("RS_MATTER_REAL_TEST_SCRIPT='{}' ", script_path.display(),),
            )
        } else if Self::needs_no_fail_on_skipped(test_name) {
            (
                self.workspace_dir
                    .join("xtask/scripts/no_fail_on_skipped.py"),
                format!("RS_MATTER_REAL_TEST_SCRIPT='{}' ", script_path.display(),),
            )
        } else {
            (script_path.clone(), String::new())
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
            "{real_script_env}timeout --kill-after=10s {timeout_secs}s \
             {} --app '{}'{} --app-ready-pattern 'Running Matter transport' \
             --factory-reset --script '{}' --script-args \"{}\"",
            runner_path.display(),
            test_exe_path.display(),
            app_args_clause,
            effective_script.display(),
            script_args,
        ))
    }

    /// Tests whose `setup_class_helper()` PASE leg has to be force-disabled
    /// via the vendored monkey-patching wrapper at
    /// `xtask/scripts/no_pase_setup_class_helper.py`. Each of these tests
    /// inherits from `BasicCompositionTests` and calls the helper with the
    /// default `allow_pase=True`, which on `v1.5-branch` triggers a fresh
    /// `EstablishPASESession` against a closed-window DUT and either hangs
    /// 25 s on BlueZ activation or leaks a stale "in-progress PASE" entry
    /// in the controller. Upstream fix `b180d46945` (PR #41712) on `master`
    /// switches to `FindOrEstablishPASESession`; once that lands on
    /// `v1.5-branch` (or we move to a newer chip gitref), this shim and
    /// the entire `xtask/scripts/no_pase_setup_class_helper.py` wrapper
    /// can be retired. See the script's docstring for the full diagnosis.
    fn needs_no_pase_shim(test_name: &str) -> bool {
        matches!(
            test_name,
            "TC_AccessChecker" | "TC_DeviceBasicComposition" | "TC_DeviceConformance"
        )
    }

    /// Tests whose bodies legitimately call `asserts.skip(...)` because the
    /// device under test correctly does not implement the optional feature
    /// the test exercises. Without intervention, CHIP's
    /// `run_python_test.py` hardcodes `--fail-on-skipped`, which the matter
    /// testing framework converts into a non-zero exit on any skipped
    /// result — even though the test bodies completed cleanly. We route
    /// these through `xtask/scripts/no_fail_on_skipped.py`, which strips
    /// the flag from `sys.argv` before `runpy`-ing the real script. See
    /// the wrapper's docstring for the full diagnosis.
    ///
    /// Two patterns produce a clean skip on rs-matter:
    ///
    /// 1. **Body-level PICS gate**: the test starts with
    ///    `if not self.check_pics(<feature>): asserts.skip(...); return`.
    ///    With our PICS dict empty for the unimplemented feature,
    ///    `check_pics()` returns False and the body never runs. Example:
    ///    `TC_CGEN_2_5..2_11` (TermsAndConditions, `CGEN.S.F00`). These
    ///    tests still need any PIXIT.* values that they read *before*
    ///    the PICS gate — see `Self::extra_python_script_args`.
    ///
    /// 2. **`@run_if_endpoint_matches(...)` decorator**: the matter
    ///    testing framework's decorator (`matter/testing/decorators.py`)
    ///    pre-reads the device's wildcard composition and, if no endpoint
    ///    on the DUT satisfies the predicate, calls `asserts.skip(...)`
    ///    before the test body ever runs. Tests targeting a cluster that
    ///    rs-matter does not implement *anywhere* (e.g.
    ///    `TimeSynchronization`, `SoftwareDiagnostics`,
    ///    `LocalizationConfiguration`, `Switch`, ...) match no endpoint
    ///    and skip cleanly without needing any PIXIT supply.
    fn needs_no_fail_on_skipped(test_name: &str) -> bool {
        matches!(
            test_name,
            // Pattern 1: body-level PICS gate (CGEN TermsAndConditions feature).
            "TC_CGEN_2_5"
                | "TC_CGEN_2_6"
                | "TC_CGEN_2_7"
                | "TC_CGEN_2_8"
                | "TC_CGEN_2_9"
                | "TC_CGEN_2_10"
                | "TC_CGEN_2_11"
                // Pattern 2: `@run_if_endpoint_matches(...)` against clusters/
                // features rs-matter does not implement on any endpoint.
                | "TC_TIMESYNC_2_1"  // has_cluster(TimeSynchronization) and has_attribute(TimeSource)
                | "TC_DGSW_2_1"      // has_cluster(SoftwareDiagnostics)
                | "TC_DGSW_2_2"      // has_cluster(SoftwareDiagnostics)
                | "TC_LCFG_2_1"      // has_cluster(LocalizationConfiguration)
                | "TC_LTIME_3_1"     // has_cluster(TimeFormatLocalization)
                | "TC_LUNIT_3_1"     // has_cluster(UnitLocalization) and has_attribute(TemperatureUnit)
                | "TC_SWTCH"         // 5 inner methods, each has_feature(Switch, ...)
                | "TC_ACL_2_5" // has_attribute(AccessControl.Extension)
        )
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
            // TC_DA_1_9 commissions seven different revoked-DAC variants
            // back-to-back; each commissioning attempt blocks for ~30 s, so
            // the wall-clock budget needs ~210 s + setup overhead.
            "TC_DA_1_9" => Some(360),
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
            // TC_DD_1_16_17 bundles two MatterBaseTests:
            //  - `test_TC_DD_1_16` parses `matter_test_config.qr_code_content`
            //  - `test_TC_DD_1_17` parses `matter_test_config.manual_code`
            // so we have to hand the framework both forms. The values are
            // the spec-default chip_tool_tests credentials (discriminator
            // 3840, passcode 20202021) — same as
            // `rs_matter::dm::devices::test::TEST_DEV_COMM`. The QR code is
            // what `chip_tool_tests` prints at startup as
            // `INFO: SetupQRCode: [...]`.
            "TC_DD_1_16_17" => Some(
                "--manual-code 34970112332 \
                 --qr-code MT:-24J0AFN00KA064IJ3P0WISA0DK5N1K8SQ1RYCU1O0",
            ),
            _ => None,
        }
    }

    /// Tests that should NOT trigger the framework's pre-test commissioning
    /// pass. Returning `true` causes `--commissioning-method` to be omitted
    /// from `--script-args`, so `MatterBaseTest` skips its `CommissionDevice`
    /// step and the test body runs against a factory-fresh device.
    fn skip_pre_commissioning(test_name: &str) -> bool {
        match test_name {
            // TC_SC_7_1 only does PASE establishment in the test body and
            // explicitly asserts that no fabrics exist on the device when
            // step 1 runs.
            "TC_SC_7_1" => true,
            // TC_DD_1_16_17 doesn't commission at all — both
            // `test_TC_DD_1_16` and `test_TC_DD_1_17` only mDNS-browse for
            // the device's commissionable advertisement (`ensure_advertising`
            // → `DiscoverCommissionableNodes` → `assert_greater_equal(...,
            // 1)`). Commissioning the DUT first flips its mDNS service
            // from `Commissionable` to `Commissioned` and the assertion
            // fails on any host without a stale mDNS cache (CI runners are
            // exactly that — they nuke their state between jobs). Upstream's
            // own CI args for this test omit `--commissioning-method` for
            // the same reason; we match that.
            "TC_DD_1_16_17" => true,
            _ => false,
        }
    }

    /// Tests that need the CHIP `chip-all-clusters-app` binary built into
    /// the chip output tree (whether spawned by the test itself or by the
    /// framework as a TH_SERVER). Drives the lazy build in `run_tests`.
    fn needs_chip_all_clusters_app(test_name: &str) -> bool {
        // TC_SC_3_5 plumbs the path through `--string-arg th_server_app_path`
        // (see `needs_th_server_app`). TC_DA_1_9 spawns the binary itself
        // via `--string-arg app_path:out/host/chip-all-clusters-app` (see
        // `extra_python_script_args`).
        matches!(test_name, "TC_SC_3_5" | "TC_DA_1_9")
    }

    /// Tests that need the CHIP `chip-all-clusters-app` binary path injected
    /// as the `th_server_app_path` string user-param (consumed by
    /// `matter.testing.apps.AppServerSubprocess`).
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
            // TC_DA_1_9 likewise spawns `chip-all-clusters-app` (with
            // various revoked DAC/PAI configurations) at the Matter default
            // port; we must vacate 5540 for the same reason.
            "TC_DA_1_9" => Some("--port 5541"),
            // TC_BINFO_3_2 simulates a configuration-version change via the
            // CHIP `app-pipe` mechanism — the test writes
            // `{"Name":"SimulateConfigurationVersionChange"}` to the named
            // pipe and the DUT translates that into a
            // `DataModel::bump_configuration_version` call.
            "TC_BINFO_3_2" => Some("--app-pipe /tmp/rs_matter_bin_info_3_2_fifo"),
            // TC_TestEventTrigger validates `GeneralDiagnostics::TestEventTrigger`
            // key/trigger handling — needs the canonical CHIP enable-key
            // 000102030405060708090a0b0c0d0e0f plumbed through to the device's
            // `GenDiag::test_event_trigger` impl. The chip_tool_tests app
            // accepts `--enable-key <hex32>` (see `parse_enable_key_override`
            // in that binary) and wires it into a `TestEventTriggerDiag`
            // wrapper around `()` that flips `TestEventTriggersEnabled` to
            // true and validates the key/trigger per spec §11.12.7.1.
            "TC_TestEventTrigger" => Some("--enable-key 000102030405060708090a0b0c0d0e0f"),
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
                "--int-arg PIXIT.ACE.APPENDPOINT:1 \
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
            "TC_ACL_2_6" | "TC_ACL_2_7" | "TC_ACL_2_8" => "--endpoint 0",
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
                "--endpoint 0 --int-arg PIXIT.CGEN.FailsafeExpiryLengthSeconds:10 \
                 --PICS src/app/tests/suites/certification/ci-pics-values"
            }
            "TC_CGEN_2_4" => "--endpoint 0",
            // TC_CGEN_2_5..2_11 verify the General Commissioning
            // *Terms-and-Conditions* (TC, Matter 1.4+, `CGEN.S.F00`)
            // feature. rs-matter does not implement TC, and each test body
            // gates itself on `check_pics("CGEN.S.F00")` to skip cleanly
            // when the device doesn't claim the feature. We deliberately
            // do *not* pass `--PICS`: with an empty PICS dict
            // `check_pics()` returns False (`matter_testing.py:709`), the
            // bodies skip before any TC assertion runs, and the
            // `no_fail_on_skipped.py` wrapper (see
            // `Self::needs_no_fail_on_skipped`) keeps the runner from
            // turning that clean skip into a non-zero exit. The
            // PIXIT.CGEN.* lookups happen *before* the PICS gate in 5/7
            // of the tests (only 2_6 and 2_10 PICS-check first), so we
            // supply dummy values uniformly — they're never used.
            "TC_CGEN_2_5"
            | "TC_CGEN_2_6"
            | "TC_CGEN_2_7"
            | "TC_CGEN_2_8"
            | "TC_CGEN_2_9"
            | "TC_CGEN_2_10"
            | "TC_CGEN_2_11" => {
                "--endpoint 0 \
                 --int-arg PIXIT.CGEN.FailsafeExpiryLengthSeconds:900 \
                 --int-arg PIXIT.CGEN.TCRevision:1 \
                 --int-arg PIXIT.CGEN.RequiredTCAcknowledgements:1"
            }
            // TC_BINFO_3_2 (BasicInformation::ConfigurationVersion) takes the
            // simulated-bump path only when `is_pics_sdk_ci_only` is True, so
            // we must hand the controller a PICS file that sets
            // `PICS_SDK_CI_ONLY=1`. The matching `--app-pipe` path is
            // mirrored on the DUT side via `app_args_override`.
            "TC_BINFO_3_2" => {
                "--endpoint 0 \
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
            "TC_OPCREDS_3_8" => "--endpoint 0 --timeout 240",
            // TC_SC_4_1: setup payload is supplied via
            // `setup_payload_override`; this entry just routes it to
            // endpoint 0 like the other root-endpoint tests.
            "TC_SC_4_1" => "--endpoint 0",
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
            | "TC_TestEventTrigger" => "--endpoint 0",
            // TC_G_2_2 sends Groups commands against
            // `self.matter_test_config.endpoint` (e.g. lines 125/133/172/197)
            // while `GroupKeyManagement` reads stay hard-coded at EP0.
            // `chip_tool_tests` no longer advertises Groups at the root
            // endpoint (Matter Core spec §9.11 — Root Node device type
            // doesn't list Groups, see the comment on `NODE` in
            // `chip_tool_tests.rs`); Groups now lives on EP1/EP2 under the
            // On/Off Light device type, so target EP1.
            "TC_G_2_2" => "--endpoint 1",
            // TC_DA_1_7 ("device attestation: distinct keys per DUT") normally
            // requires two distinct DUTs with different DAC keys. The test
            // also supports a single-DUT mode for CI when `allow_sdk_dac:true`
            // is passed: it then runs steps 1.x against one device and skips
            // the two-DUT public-key inequality check at step 3 (the inner
            // PAI-AKID denylist check is also skipped under that flag).
            "TC_DA_1_7" => "--endpoint 0 --bool-arg allow_sdk_dac:true",
            // TC_SC_3_5 needs `is_pics_sdk_ci_only=True` so the
            // DUT_Commissioner steps short-circuit to "Y" — see the
            // explanatory comment in `SYS_TESTS` above. Without the CI PICS
            // file the test hangs on `wait_for_user_input` waiting for an
            // operator to commission the DUT_Commissioner from chip_tool_tests
            // (which doesn't act as a commissioner).
            "TC_SC_3_5" => "--PICS src/app/tests/suites/certification/ci-pics-values",
            // TC_DA_1_9 ("device attestation: revocation [DUT-Commissioner]")
            // is a commissioner-side test: it spawns `chip-all-clusters-app`
            // with a series of revoked DAC/PAI configurations and uses the
            // *test framework's* `ChipDeviceCtrl.CommissionWithCode` to verify
            // that revoked credentials are rejected. The chip_tool_tests app
            // we launch is sidelined (the framework drives the controller
            // directly), but we still need to point the test at the cached
            // chip output from `cargo xtask itest-setup` and bump its
            // per-test timeout (default 90 s) past the seven 30-s commission
            // attempts the test performs.
            "TC_DA_1_9" => {
                "--PICS src/app/tests/suites/certification/ci-pics-values \
                 --string-arg app_path:out/host/chip-all-clusters-app \
                 --string-arg dac_provider_base_path:credentials/test/revoked-attestation-certificates/dac-provider-test-vectors \
                 --string-arg revocation_set_base_path:credentials/test/revoked-attestation-certificates/revocation-sets \
                 --timeout 300"
            }
            // Device Attestation (DA) covers attestation primitives on the
            // root endpoint. The Vendor-ID range / certification-type checks
            // in step 6.x of TC_DA_1_2 (and the analogous steps in TC_DA_1_5)
            // are gated on `is_pics_sdk_ci_only`: without that gate the test
            // rejects test-VID CDs (rs-matter ships a Test CD with VID 0xFFF1
            // — line 366 of TC_DA_1_2.py: `assert_in(vendor_id, range(1,
            // 0xfff0))`). Enabling the CI PICS file flips
            // `is_pics_sdk_ci_only` to true and the rest of the cert-chain
            // assertions still exercise the attestation invoke surface.
            "TC_DA_1_2" | "TC_DA_1_5" => {
                "--endpoint 0 \
                 --PICS src/app/tests/suites/certification/ci-pics-values"
            }
            // TC_SC_7_1 supports a "post-cert" single-DUT mode that swaps
            // the two-device commissioning-codes assertion for direct
            // factory-state and non-default-credentials checks against the
            // sole DUT. Without `post_cert_test:true` the test bails out
            // before step 1 demanding a second discriminator. Routes to
            // endpoint 0 like the other root-endpoint SC tests.
            "TC_SC_7_1" => "--bool-arg post_cert_test:true --endpoint 0",
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
