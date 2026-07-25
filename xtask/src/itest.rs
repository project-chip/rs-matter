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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

use clap::ValueEnum;

use log::{debug, info, warn};

use self::ble_env::BleEnv;
use self::common::{run_command, ChipBuilder};
use self::otbr_env::OtbrEnv;

pub(crate) mod ble_env;
pub(crate) mod common;
pub(crate) mod otbr_env;

/// System cluster tests + general Matter protocol/IM/SC tests.
///
/// Run against the `system_tests` example. This is the default suite
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
    // "TestDescriptorCluster", // Skipped: hardcodes upstream `all-clusters-app`'s exact EP0 shape. The Power Source device-type half is now satisfiable (DEV_TYPE_POWER_SOURCE + the PowerSource cluster exist), but it also requires `ServerList` to contain FaultInjection (0xFFF1FC06, a chip test cluster), `PartsList == [1,2,3,4]` (four child endpoints) and an exact EP0 `TagList` — mirroring all-clusters-app rather than testing conformance.
    "TestDiagnosticLogs",
    // Skipped: every Ethernet Network Diagnostics attribute (PHYRate ..
    // TimeSinceReset) is optional and `ResetCounts` is its only command, while
    // `eth_diag::EthDiagHandler` declares `with_attrs(with!(required))` and
    // `with_cmds(with!())` - so it serves the global attributes and nothing
    // else. Both tests read the optional attributes under PICS gates, so
    // enabling them requires the handler to source real interface counters;
    // claiming them in the `.pics` without that just buys a vacuous pass.
    // "Test_TC_DGETH_2_1",
    // "Test_TC_DGETH_2_2",
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
    // `nullable_boolean` must default to `false` (not null) per the upstream
    // test-cluster XML - see the note in `unit_testing.rs`; everything else
    // passed as-is on first verification.
    // Dedicated PowerSource attribute test. Targets the EP1 instance (the
    // YAML's `config.endpoint: 1` is not overridable by the harness); the
    // battery-attribute steps are skipped via the `PS.S.*=0` PICS entries.
    "Test_TC_PS_2_1",
    "TestSaveAs",
    "TestSelfFabricRemoval",
    "TestSubscribe_AdministratorCommissioning",
    "TestSubscribe_OnOff",
    // Starts/stops/restarts the DUT via the harness's SystemCommands pseudo
    // cluster, then spawns a *second* accessory from the `lock` app slot and
    // commissions it. The DUT binary is registered under `lock:` as well (see
    // `yaml_test_command`) so that second instance is just another
    // `system_tests`.
    "TestSystemCommands",
    "TestUserLabelCluster",
    "TestUserLabelClusterConstraints",
    // SetTimeZone / SetDSTOffset constraint checking against the `TimeZone`
    // (F00) feature, served by `time_sync::TimeZoneStore`.
    "TestTimeSynchronization",
    // End-to-end LIT-ICD lifecycle: the runner commissions with
    // `--icd-registration true` (this DUT is routed into the `lit-icd` app
    // slot, see `yaml_test_command`), so the commissioner registers itself as a
    // Check-In client; the test then reboots the DUT and verifies the registered
    // client and the ICDCounter survive (counter resumes one epoch ahead). Also
    // checks OperatingMode flips LIT→SIT on UnregisterClient.
    "TestIcdManagementCluster",
    "TestUnitTestingClusterMei",
    //
    // Python tests — Interaction Data Model (general Matter protocol)
    //
    "TC_IDM_1_2",
    "TC_IDM_1_4",
    "TC_IDM_2_2",
    // Batched reads incl. `CapabilityMinima`; targets clusters on the root
    // endpoint, hence the `--endpoint 0` extra arg.
    "TC_IDM_2_3",
    // Write Response Action: statuses for writes to unsupported
    // endpoints/clusters/attributes.
    "TC_IDM_3_2",
    "TC_IDM_4_2",
    // Subscription reporting semantics (KeepSubscriptions, intervals,
    // wildcards). Uses `setup_class_helper`, so it is routed through the
    // no-PASE shim like `TC_DeviceBasicComposition` (see
    // `Self::needs_no_pase_shim`).
    "TC_IDM_4_3",
    // Timed Request handling.
    "TC_IDM_5_2",
    "TC_IDM_9_1",
    //
    // Python tests — Access Control (system cluster)
    //
    "TC_ACE_1_2",
    "TC_ACE_1_3",
    "TC_ACE_1_4",
    "TC_ACE_1_5",
    // Group-auth access enforcement over REAL multicast: the TH sends
    // group-addressed invokes at the DUT and asserts the
    // `Groupcast.GroupcastTesting` events the (armed) DUT emits about them
    // — including access grants coming solely from the Groupcast-synthesized
    // `AuxiliaryACL`. Runs against the `NODE_GROUPCAST` app composition
    // (see `app_args_override`).
    "TC_ACE_1_6",
    "TC_ACL_2_2",
    // TC_ACL_2_3/2_5/2_7 test the optional `AccessControlExtension` feature
    // (Extension attribute), which rs-matter does not implement:
    // `@run_if_endpoint_matches(has_attribute(AccessControl.Extension))` skips
    // them cleanly (converted to a pass via `no_fail_on_skipped.py` — see
    // `needs_no_fail_on_skipped`). Note this is the `EXTENSION` feature, NOT
    // the `AUXILIARY` feature (AuxiliaryACL attribute) that rs-matter *does*
    // implement.
    "TC_ACL_2_3",
    "TC_ACL_2_4",
    "TC_ACL_2_5",
    "TC_ACL_2_6",
    "TC_ACL_2_7",
    "TC_ACL_2_8",
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
    // The CHIP-framework cleanup bug that used to break this test is another
    // chip-master-only regression absent from the pinned `v1.6-branch`
    // framework. Needs the raised timeouts in `per_test_timeout_secs` /
    // `per_test_framework_timeout_secs` (a ~180s window-expiry wait).
    "TC_CADMIN_1_5",
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
    // Repeated OpenCommissioningWindow / PASE-attempt handling; reads
    // `SpecificationVersion` on EP0, hence the `--endpoint 0` extra arg.
    "TC_CADMIN_1_10",
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
    // lazily via `needs_chip_all_clusters_app`), move system_tests off the
    // default Matter port via `--port 5541` so TH_SERVER can take 5540, and
    // hand the test `--PICS ci-pics-values` so `is_pics_sdk_ci_only=True` —
    // without that flag, every "TH prompts the user to commission DUT" step
    // requires a real DUT_Commissioner, which rs-matter isn't, and the steps
    // hang on `wait_for_user_input`. With the flag, those DUT_Commissioner
    // steps short-circuit to "Y" and the test verifies the framework
    // controller's CASE-error handling against the FaultInjection-corrupted
    // chip-all-clusters-app. NB: rs-matter code is exercised only via the
    // initial CommissionDeviceTest commissioning of system_tests itself —
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
    // The default `BasicInfoHandler` metadata excludes the provisional
    // `DeviceLocation` attribute, so `TestBasicInformation`'s exact-set
    // assertion on `AttributeList` keeps passing. For `TC_BINFO_3_2` the
    // `system_tests` binary swaps in an alternate `Node` whose
    // `BasicInformation` cluster metadata exposes `DeviceLocation` — see
    // `NODE_BINFO_PROVISIONAL` in `examples/src/bin/system_tests.rs`. The
    // switch is gated on the presence of `--app-pipe` (see `app_args_override`
    // below), which only this test passes.
    "TC_BINFO_3_2",
    //
    // Python tests — Groups (system cluster)
    //
    "TC_G_2_2",
    //
    // Python tests — Groupcast (system cluster, provisional in Matter 1.6)
    //
    // The whole `TC_GC_2_x` suite is driven over unicast IM (JoinGroup /
    // LeaveGroup / UpdateGroupKey / ConfigureAuxiliaryACL /
    // GroupcastTesting commands plus attribute and event subscriptions);
    // no real multicast traffic is involved. `TC_GC_2_6` and `TC_GC_2_7`
    // commission (and later remove) a second test fabric.
    "TC_GC_2_1",
    "TC_GC_2_2",
    "TC_GC_2_3",
    // "TC_GC_2_4", // Skipped: flaky harness-side timing race, not a DUT bug.
    // Steps 6-8 do `LeaveGroup(0)` (leave all groups) -> `membership_sub.reset()`
    // -> await a fresh *empty* `Membership` report. With `min_interval=0` the
    // DUT correctly emits the empty-`Membership` report the instant the command
    // is handled (spec: report ASAP), so it reaches the harness in the ~2 ms
    // between the `LeaveGroup(0)` response and the step-7 `reset()` - which then
    // discards it. Step 8 then waits the full max interval for another
    // *data-bearing* report that never comes (membership is stable-empty and
    // max-interval reports are empty liveness heartbeats), and times out. The
    // test implicitly assumes reporting is deferred past the reset (as CHIP's
    // scheduled reporting engine happens to be); rs-matter reports synchronously
    // and loses the race. No DUT timing change can deterministically win a
    // wall-clock race against the harness's reset, so re-enable this only once
    // the reporter defers post-command reports (or the upstream test stops
    // reset-then-awaiting the same change).
    "TC_GC_2_5",
    "TC_GC_2_6",
    "TC_GC_2_7",
    "TC_GC_2_8",
    //
    // Python tests — Network Commissioning (system cluster)
    //
    "TC_CNET_1_4",
    // The Ethernet variant of the attribute-check test, gated on
    // `has_feature(kEthernetNetworkInterface)`. `system_tests` claims that
    // feature (`net_comm::NetworkType::Ethernet` on EP0, `CNET.S.F02` in the
    // `.pics`), so the test runs rather than skipping.
    "TC_CNET_4_3",
    //
    // The remaining `TC_CNET_4_*` tests target the Wi-Fi (`CNET.S.F00`) and
    // Thread (`CNET.S.F01`) features. `system_tests` claims neither, so their
    // `has_feature(...)` decorators / FeatureMap gates skip them. Upstream
    // lists all of them under `not_automated` in
    // `src/python_testing/test_metadata.yaml` and runs none of them in CI.
    //
    // Most do not actually need a radio, only a DUT that claims the feature
    // and a `NetCtl` that answers `scan`/`connect` locally — see
    // `dm::networks::wireless::NoopWirelessNetCtl` for the shape:
    //   4_1  Wi-Fi   attribute reads only
    //   4_2  Thread  attribute reads only; needs the network entry to report
    //                `connected: true`, else the body skips at step 3
    //   4_4  Wi-Fi   ScanNetworks; the directed-scan SSID is read back from
    //                the DUT's own `Networks` entry, not supplied as a PIXIT
    //   4_9  Wi-Fi   RemoveNetwork/ConnectNetwork under an armed failsafe;
    //                no reboot and no operator prompt anywhere in the body
    //   4_10 Thread  as 4_9
    //   4_15 Wi-Fi   NetworkIDNotFound for a bogus network ID; the ID is
    //                hardcoded in the test, so no PIXIT is needed
    //   4_16 Thread  as 4_15
    //   4_22 Thread  ScanNetworks
    // These need a wireless example binary to run against; they cannot run
    // against `system_tests`, whose CNET cluster is Ethernet-only.
    //
    // `4_12` (Thread ConnectNetwork) is the exception: it moves the DUT
    // between two live PANs and re-discovers it on each, so a local `NetCtl`
    // would satisfy it only vacuously. It needs real Thread.
    //
    // On the YAML side, `Test_TC_CNET_4_5` / `_4_6` (Wi-Fi / Thread
    // FAILSAFE_REQUIRED) are four executable commands each and equally
    // radio-free, while `Test_TC_CNET_4_11` needs two live access points.
    // `Test_TC_CNET_4_13`, `_4_14`, `_4_20` and `_4_21` carry no executable
    // steps at all (every step is `disabled: true`) — they are operator
    // procedures, not runnable tests, and are deliberately not tracked here.

    //
    // Python tests — General Diagnostics (system cluster)
    //
    "TC_DGGEN_2_4",
    "TC_DGGEN_3_2",
    "TC_TestEventTrigger",
    //
    // Python tests — Software Diagnostics (system cluster)
    //
    // rs-matter ships a minimal stub handler (no heap/thread metrics features
    // claimed, no optional commands), which is enough for these conformance
    // tests to find the cluster on the root endpoint and exercise the
    // required globals.
    "TC_DGSW_2_1",
    "TC_DGSW_2_2",
    //
    // Python tests — Time Synchronization (system cluster)
    //
    // rs-matter implements the spec-mandatory TimeSynchronization
    // surface on the root endpoint: the `UTCTime` / `Granularity` /
    // `TimeSource` attributes and the `SetUTCTime` command, all
    // wired to the Matter-wide Last-Known-Good UTC Time state on
    // `Matter`/`MatterState` (Matter Core spec §3.5.6.1, §11.17.8,
    // §11.17.9.1).
    //
    // The remaining (commented-out) tests gate on feature bits we
    // don't claim yet:
    //   - `F00` (TimeZone):       2_4, 2_5, 2_7..2_12
    //   - `F01` (NTP_CLIENT):     2_6
    "TC_TIMESYNC_2_1",
    "TC_TIMESYNC_2_2",
    // The `TimeZone` (F00) feature set: TimeZone/DSTOffset lists, LocalTime,
    // SetTimeZone / SetDSTOffset - served by `time_sync::TimeZoneStore` plus
    // the transition-event timer in the TimeSync handler's `Handler::run`.
    "TC_TIMESYNC_2_4",
    "TC_TIMESYNC_2_5",
    // "TC_TIMESYNC_2_6",  // Skipped: needs `F01` (NTP_CLIENT) — DefaultNTP / SupportsDNSResolve + SetDefaultNTP.
    "TC_TIMESYNC_2_7",
    "TC_TIMESYNC_2_8",
    "TC_TIMESYNC_2_9",
    "TC_TIMESYNC_2_10",
    // Real-time DST-transition events (DSTStatus at validStarting/validUntil
    // boundaries, ~40s of scheduled transitions).
    "TC_TIMESYNC_2_11",
    // Real-time TimeZoneStatus events at `validAt` boundaries.
    "TC_TIMESYNC_2_12",
    "TC_TIMESYNC_2_13",
    "TC_TIMESYNC_3_1",
    //
    // Python tests — ICD Management (optional system cluster)
    //
    // rs-matter implements the Check-In Protocol (CIP feature): the
    // RegisterClient / UnregisterClient / StayActiveRequest commands and the
    // RegisteredClients / ICDCounter / ClientsSupportedPerFabric /
    // MaximumCheckInBackOff attributes. It is not a Long-Idle-Time ICD (no LITS
    // feature, no OperatingMode) and does not register clients at commissioning
    // time. TC_ICDM_2_1 reads and range-checks the attribute surface — it passes
    // with the PICS claiming only F00.
    "TC_ICDM_2_1",
    // Exercises the full register/unregister flow: ResourceExhausted when a
    // fabric's registration slot is full, NotFound on unknown unregister, and
    // read-back of the RegisteredClients entries. Steps 2a/2b use the
    // GeneralDiagnostics `kAddActiveModeReq` ICD trigger, accepted as a no-op by
    // the `system_tests` DUT (see `app_args_override` for the enable-key).
    "TC_ICDM_3_1",
    // Verification-key access control plus a reboot check. The reboot leg is
    // gated on `not is_ci`; our PICS carries `PICS_SDK_CI_ONLY=1`, so the CI path
    // runs (register/read-back/verification-key) and skips the physical reboot,
    // which the harness can't drive. RegisteredClients are still persisted.
    "TC_ICDM_3_2",
    "TC_ICDM_3_3",
    // ICDCounter monotonicity across a reboot. The reboot leg is `not is_ci`;
    // with `PICS_SDK_CI_ONLY=1` the CI path just reads the counter twice and
    // asserts it never decreases. The counter is persisted for the real path.
    "TC_ICDM_3_4",
    // Operating mode (LITS): reads the OperatingMode attribute and the operational
    // `ICD` DNS-SD TXT key, asserting both are SIT with no clients, flip to LIT
    // after RegisterClient, and back to SIT after UnregisterClient. Needs `--PICS`
    // (the F02 gate) and browses the DUT's operational mDNS.
    "TC_ICDM_5_1",
    // Drives the ICD Check-In counter-invalidation TestEventTriggers
    // (`kInvalidateHalf/AllCounterValues`) and asserts the ICDCounter jumps by
    // exactly half / all of the u32 range. The DUT applies the jump in place and
    // persists the new boundary (see `app_args_override` for the enable-key).
    "TC_ICDManagementCluster",
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
    // PowerSource is hosted (featureless/wired) on EP0 of `system_tests`.
    // The battery-attribute reporting-rate checks are vacuously satisfied on
    // a wired source; the wildcard subscription over the cluster is the part
    // genuinely exercised.
    "TC_PS_2_3",
    //
    // Python tests — Basic Information (system cluster)
    //
    // `TC_BINFO_2_1`'s `DeviceLocation` steps 24-28 skip via
    // `attribute_guard` — deliberately; see the `TC_BINFO_2_1` note in
    // `app_args_override` for why they cannot be made to run.
    "TC_BINFO_2_1",
    "TC_BINFO_2_2",
    "TC_BINFO_3_1",
    "TC_DGGEN_2_5",
    //
    // Python tests — Fixed Label (optional system cluster)
    //
    "TC_FLABEL_2_1", // FixedLabel wired on EP1 of `system_tests` with two static
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
    // NOC wiped on factory reset.
    "TC_DA_1_1",
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
    // Bundles several `MatterBaseTest`s run after a single wildcard read.
    // `BasicCompositionTests.setup_class_helper()`'s PASE leg is routed through
    // `xtask/scripts/no_pase_setup_class_helper.py` (see
    // `Self::needs_no_pase_shim`), and the test is handed the target `.pics`
    // (see `Self::needs_target_pics`) because `test_TC_IDM_10_1` only tolerates
    // the test-vendor identifiers the example fixtures use when
    // `PICS_SDK_CI_ONLY` is set.
    //
    // `test_TC_SM_1_1`'s Groupcast conformance block is skipped because the
    // device declares `SpecificationVersion` 1.6.0 - see
    // `basic_info::DEFAULT_MATTER_SPEC_VERSION`, which documents why, and what
    // has to be implemented before that can be raised to 1.6.1.
    "TC_DeviceBasicComposition",
    //
    // Runs the upstream device-conformance suite (six sub-tests:
    // `test_TC_DESC_2_3`, `test_TC_IDM_10_2`/`_3`/`_5`/`_6`,
    // `test_TC_IDM_14_1`) after a wildcard read of the full
    // attribute/command surface. The PASE+CASE race in
    // `BasicCompositionTests.setup_class_helper` is worked around via
    // `Self::needs_no_pase_shim`, and the suite is invoked with
    // `--bool-arg ignore_in_progress:True allow_provisional:True
    // fail_on_extra_clusters:False` plus the target `.pics` (see
    // `Self::extra_python_script_args` / `Self::needs_target_pics`).
    //
    // `fail_on_extra_clusters:False` is what makes `test_TC_IDM_10_5`
    // pass with `Groups` deliberately re-added at the root endpoint for
    // `TestGroupMessaging` (group-addressed writes to
    // `BasicInformation::NodeLabel` need EP0 to be a group member). Matter
    // Core spec 7.16.4 permits extra clusters on an endpoint; the
    // conformance checker takes a stricter view by default, and upstream
    // provides this flag for exactly that reason - `all-clusters-app` puts
    // `Groups` on EP0 too.
    //
    // This suite is the automated check for revision-conditional
    // conformance (`Rev >= vN`), which the `.matter` IDL cannot express and
    // which therefore compiles clean when wrong - keep it enabled.
    "TC_DeviceConformance",
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

/// OnOff + LevelControl + ColorControl YAML/Python tests — run
/// against the `light_tests` example.
pub(crate) const LIGHT_TESTS: &[&str] = &[
    // OnOff
    "Test_TC_OO_2_1",
    "Test_TC_OO_2_2",
    "Test_TC_OO_2_4",
    "Test_TC_OO_2_6",
    // "Test_TC_OO_2_7", // TODO: not yet passing
    // LevelControl
    "Test_TC_LVL_2_1",
    "Test_TC_LVL_2_2",
    "Test_TC_LVL_3_1",
    // "Test_TC_LVL_4_1", // TODO: not yet passing
    "Test_TC_LVL_5_1",
    "Test_TC_LVL_6_1",
    "Test_TC_LVL_7_1",
    // "Test_TC_LVL_9_1", // TODO: not yet passing
    // ColorControl — attribute reads + write validation (Python).
    "TC_CC_2_1",
    "TC_CC_2_2",
    // ColorControl — Hue (HUE_AND_SATURATION).
    "Test_TC_CC_3_1",
    "Test_TC_CC_3_2",
    "Test_TC_CC_3_3",
    // ColorControl — Saturation (HUE_AND_SATURATION).
    "Test_TC_CC_4_1",
    "Test_TC_CC_4_2",
    "Test_TC_CC_4_3",
    "Test_TC_CC_4_4",
    // ColorControl — XY.
    "Test_TC_CC_5_1",
    "Test_TC_CC_5_2",
    "Test_TC_CC_5_3",
    // ColorControl — Color temperature.
    "Test_TC_CC_6_1",
    "Test_TC_CC_6_2",
    "Test_TC_CC_6_3",
    // "Test_TC_CC_6_5", // TODO: needs persistence of
    // StartUpColorTemperatureMireds + ColorTemperatureMireds across
    // reboots, which the light_tests example doesn't implement.
    // ColorControl — Enhanced hue.
    "Test_TC_CC_7_1",
    "Test_TC_CC_7_2",
    "Test_TC_CC_7_3",
    "Test_TC_CC_7_4",
    // ColorControl — Enhanced MoveToHueAndSaturation.
    "Test_TC_CC_8_1",
    // ColorControl — Color loop.
    "Test_TC_CC_9_1",
    "Test_TC_CC_9_2",
    "Test_TC_CC_9_3",
];

/// Scenes Management YAML tests — run against the `scenes_tests` example.
pub(crate) const SCENES_TESTS: &[&str] = &[
    "Test_TC_S_2_1",
    "Test_TC_S_2_2",
    "Test_TC_S_2_3",
    "Test_TC_S_2_4",
    "Test_TC_S_2_5",
    "Test_TC_S_2_6",
    "Test_TC_S_3_1",
    "TestScenesFabricSceneInfo",
    "TestScenesMultiFabric",
    "TestScenesFabricRemoval",
    "TestScenesMaxCapacity",
];

/// OTA Software Update tests — run against the `system_tests` example, which
/// plays the rs-matter OTA *role* (Provider or Requestor) while the counterpart
/// node is a CHIP `chip-ota-{provider,requestor}-app`. Only the CI-automatable
/// `OTA_SuccessfulTransfer` YAML exists upstream (the `TC_SU_*`/`TC_BDX_*`
/// certification suites are all manual). Role selection is by which slot
/// `system_tests` occupies — see [`ITests::yaml_test_command`].
pub(crate) const OTA_TESTS: &[&str] = &[
    // rs-matter as the Provider; CHIP `chip-ota-requestor-app` is the DUT that
    // downloads the image over BDX and prints "OTA image downloaded".
    "OTA_SuccessfulTransfer",
    // rs-matter as the Requestor (DUT); CHIP `chip-ota-provider-app` serves. The
    // `@requestor` suffix selects the role and is stripped before the YAML runs.
    "OTA_SuccessfulTransfer@requestor",
];

/// Network Commissioning tests for the wireless network types — run against the
/// `wireless_tests` binary, whose `NetCtl` answers `ScanNetworks` /
/// `ConnectNetwork` from a canned table instead of a radio.
///
/// Upstream lists every one of these under `not_automated` in
/// `src/python_testing/test_metadata.yaml` because `chip-all-clusters-app` binds
/// the cluster straight to the platform's Wi-Fi / Thread stack, leaving nowhere
/// to stand in for the radio. The `NetCtl` trait is that seam here.
///
/// The Thread entries drive the same binary in its Thread flavour — see
/// `Self::app_args_override`.
pub(crate) const WIRELESS_TESTS: &[&str] = &[
    // Wi-Fi
    "TC_CNET_4_1",
    "TC_CNET_4_4",
    "TC_CNET_4_9",
    "TC_CNET_4_15",
    // Thread
    "TC_CNET_4_2",
    "TC_CNET_4_10",
    "TC_CNET_4_16",
    "TC_CNET_4_22",
    //
    // YAML: the provisioning commands must be refused without an armed
    // failsafe. Four executable commands each, no radio involved.
    "Test_TC_CNET_4_5",
    "Test_TC_CNET_4_6",
    //
    // YAML: the mandatory Wi-Fi / Thread diagnostics attributes, answered by
    // `MockNetCtl` from the provisioned network.
    //
    // Their siblings stay off because `WifiDiagHandler` / `ThreadDiagHandler`
    // are `with_attrs(with!(required))` / `with_cmds(with!())`: everything they
    // gate on is either an optional counter or `ResetCounts`, none of which is
    // implemented, so they would run no steps at all -
    //   `Test_TC_DGWIFI_2_3`    counters + ResetCounts
    //   `Test_TC_DGTHREAD_2_2`  Tx counters (MACCounts)
    //   `Test_TC_DGTHREAD_2_3`  Rx counters (MACCounts)
    //   `Test_TC_DGTHREAD_2_4`  OverrunCount + ResetCounts
    // Enabling those means implementing the counters first, exactly as for the
    // Ethernet diagnostics.
    "Test_TC_DGWIFI_2_1",
    "Test_TC_DGTHREAD_2_1",
    //
    // "TC_CNET_4_12", // Skipped: moves the node between two live PANs and
    //                 // re-discovers it on each. A canned `NetCtl` reports
    //                 // success without the node ever moving, so this would go
    //                 // green without testing anything. Needs real Thread.
    //
    // `Test_TC_CNET_4_5` (Wi-Fi) and `Test_TC_CNET_4_6` (Thread) are equally
    // radio-free — four commands each, checking that the provisioning commands
    // are rejected without an armed failsafe. They are YAML, so the runner
    // always hands them `--pics-file <target>.pics`, and they gate on
    // `CNET.S.F00` / `CNET.S.F01` respectively. One `.pics` per target cannot
    // claim both, so enabling them needs the Wi-Fi and Thread flavours split
    // into two `[[bin]]` targets sharing one source file.
];

/// Which flavour of the `wireless_tests` binary a test drives.
///
/// The Wi-Fi and Thread network stores are distinct types, so the binary picks
/// one at startup; and because the two claim different Network Commissioning
/// features (`CNET.S.F00` vs `CNET.S.F01`) plus different diagnostics clusters,
/// they also need different `.pics` files.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum WirelessFlavour {
    Wifi,
    Thread,
}

impl WirelessFlavour {
    /// The flavour a test needs, or `None` if it does not run against
    /// `wireless_tests` at all.
    fn of(test_name: &str) -> Option<Self> {
        let flavour = match test_name {
            "TC_CNET_4_1" | "TC_CNET_4_4" | "TC_CNET_4_9" | "TC_CNET_4_15" | "Test_TC_CNET_4_5"
            | "Test_TC_DGWIFI_2_1" | "Test_TC_DGWIFI_2_3" => Self::Wifi,
            "TC_CNET_4_2"
            | "TC_CNET_4_10"
            | "TC_CNET_4_16"
            | "TC_CNET_4_22"
            | "Test_TC_CNET_4_6"
            | "Test_TC_DGTHREAD_2_1"
            | "Test_TC_DGTHREAD_2_2"
            | "Test_TC_DGTHREAD_2_3"
            | "Test_TC_DGTHREAD_2_4" => Self::Thread,
            _ => return None,
        };

        Some(flavour)
    }

    /// The `.pics` basename this flavour declares.
    fn pics_target(&self) -> &'static str {
        match self {
            Self::Wifi => "wireless_tests_wifi",
            Self::Thread => "wireless_tests_thread",
        }
    }
}

/// Tests re-run with commissioning over **BLE** instead of on-network, against
/// the `ble_tests` driver.
///
/// These add no new certification test names - the point is the transport: the
/// whole BTP / GATT / BlueZ path plus the non-concurrent provisioning flow
/// (`AddOrUpdateWiFiNetwork` + `ConnectNetwork` carried over BTP) has no other
/// automated coverage. `TC_CNET_4_1` is a good vehicle because it then reads
/// back the network the commissioner actually provisioned, rather than one the
/// device seeded for itself.
pub(crate) const BLE_TESTS: &[&str] = &[
    "TC_CNET_4_1",
    // The BLE-**Thread** flow, against the `--thread` flavour of `ble_tests`:
    // same BTP transport, but the provisioned network is a real Thread PAN
    // (`otbr-agent` joins the mock-Bluetooth bus, radio simulated as in the
    // `thread` suite). This is the only e2e of the **non-concurrent**
    // provisioning contract: the DUT answers `ConnectNetwork` over BTP
    // without touching the radio, then replays the attach via
    // `InteractionModel::connect_once` once BTP is torn down, and the
    // commissioner completes commissioning over the operational (UDP)
    // network. `TC_CNET_4_2` then reads back the genuinely-attached network.
    "TC_CNET_4_2",
    // "TC_CNET_4_1@bluer", // Skipped: the `bluer` backend cannot complete BTP
    //                      // against a BlueZ that confirms indications over the
    //                      // `AcquireNotify` socket (>= 5.80, and `bluezoo`).
    //                      // `bluer` exposes that socket as a write-only
    //                      // `CharacteristicWriter` and never drains the
    //                      // confirmation byte, so the session stalls after the
    //                      // first indication - the same defect that
    //                      // `gatt::bluez::wait_complete` handles on our side,
    //                      // but inside the crate where we cannot fix it.
    //                      // The `--bluer` switch and this entry are kept so the
    //                      // backend can be exercised by hand against an older
    //                      // BlueZ, and re-enabled once `bluer` reads the
    //                      // confirmation.
];

/// The first Thread operational dataset for the `thread` suite — the network
/// the DUT driver auto-attaches to at startup (handed to it via the
/// `RS_MATTER_THREAD_DATASET` env var), and the `--thread-dataset-hex` the
/// Python tests receive.
///
/// Layout is exactly what `ot-ctl dataset init new` emits: ActiveTimestamp,
/// Channel (17), ChannelMask, ExtPANID, NetworkName ("rsm-thread-1"), PSKc,
/// NetworkKey, MeshLocalPrefix, PanId (0x1234), SecurityPolicy.
///
/// NB: the Extended PAN ID deliberately avoids `1111111122222222` - that is
/// `TC_CNET_4_16`'s hardcoded "unknown second network" ID, which must NOT
/// match the commissioned network.
const THREAD_DATASET_1: &str = "0e080000000000010000\
     0003000011\
     35060004001fffe0\
     02081a2b3c4d5e6f7081\
     030c72736d2d7468726561642d31\
     0410c3f59368445a1b6106be420a706d4cc9\
     051000112233445566778899aabbccddeeff\
     0708fd11111111220000\
     01021234\
     0c0402a0f7f8";

/// The second Thread operational dataset (`PIXIT.CNET.THREAD_2ND_OPERATIONALDATASET`):
/// the network `TC_CNET_4_12` moves the DUT onto and back off of. Distinct
/// channel (22), ExtPANID, name ("rsm-thread-2"), keys, prefix and PanId
/// (0xabcd) from [`THREAD_DATASET_1`].
const THREAD_DATASET_2: &str = "0e080000000000010000\
     0003000016\
     35060004001fffe0\
     02088888888877777777\
     030c72736d2d7468726561642d32\
     0410d4e6f8a91b2c3d4e5f60718293a4b5c6\
     0510ffeeddccbbaa99887766554433221100\
     0708fd22222222330000\
     0102abcd\
     0c0402a0f7f8";

/// Thread tests against a REAL Thread stack: the `thread_tests` driver wired
/// to `otbr-agent` over D-Bus (see [`crate::otbr_env::OtbrEnv`]), radio
/// defaulting to OpenThread's simulated RCP. Unlike the `wireless` suite,
/// `ScanNetworks`/`ConnectNetwork` here actually form and switch PANs.
pub(crate) const THREAD_TESTS: &[&str] = &[
    // The mandatory Thread diagnostics attributes, now answered from the live
    // stack (channel, routing role, neighbor table, ...) instead of a mock.
    "Test_TC_DGTHREAD_2_1",
    // The optional MAC Tx / Rx counter attributes (`MACCNT` feature), served
    // off `otbr-agent`'s MAC counters D-Bus property via
    // `ThreadDiag::mac_counters`. `Test_TC_DGTHREAD_2_4` stays off: it needs
    // `ResetCounts`, which the otbr D-Bus API does not expose at all.
    "Test_TC_DGTHREAD_2_2",
    "Test_TC_DGTHREAD_2_3",
    //
    // The one CNET test that a canned `NetCtl` can only satisfy vacuously
    // (see the note in `WIRELESS_TESTS`): the DUT moves between two live
    // PANs. With the simulated radio the DUT genuinely detaches from
    // `thread_dataset_1` and forms/joins `thread_dataset_2` as its own
    // partition — `Networks[].connected` reflects the real device role.
    "TC_CNET_4_12",
    // Re-runs of the `wireless` suite's Thread CNET set against the real
    // stack: attribute reads off a genuinely-attached network (4_2),
    // RemoveNetwork/ConnectNetwork under an armed fail-safe with a real
    // revert-and-reattach (4_10 — the e2e for the `WirelessMgr` fail-safe
    // reconnect), and NetworkIDNotFound refusal (4_16). Their
    // `--thread-dataset-hex` is the suite's real dataset here (see
    // `extra_python_script_args`); the mock TLV serves the wireless suite.
    "TC_CNET_4_2",
    "TC_CNET_4_10",
    "TC_CNET_4_16",
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
    /// OnOff + LevelControl + ColorControl, exercising the `light_tests` example.
    Light,
    /// Scenes Management cluster — runs against the `scenes_tests` example.
    Scenes,
    /// OTA Software Update — `system_tests` plays an rs-matter OTA role against a
    /// CHIP `chip-ota-{provider,requestor}-app` counterpart.
    Ota,
    /// Network Commissioning for the wireless network types, against the
    /// `wireless_tests` binary and its canned `NetCtl`. Needs no radio.
    Wireless,
    /// Thread tests against a real Thread stack: `otbr-agent` + the
    /// `thread_tests` driver, on OpenThread's simulated radio by default
    /// (no hardware needed; set `RS_MATTER_THREAD_RADIO_URL` for a real
    /// RCP dongle). Local-only for now; requires `sudo` for the TUN
    /// interface.
    Thread,
    /// Commissioning over BLE, against the `ble_tests` driver. Runs on a mock
    /// BlueZ (`bluezoo`), so it needs no Bluetooth hardware.
    Ble,
    /// **Inverted** suite — rs-matter as the **commissioner** driving
    /// upstream `chip-all-clusters-app` (the device under test). Builds
    /// both binaries, spawns the CHIP app on `[::1]:<port>` with known
    /// passcode/discriminator, then runs the `commissioner_tests`
    /// example binary against it and asserts exit 0.
    Commissioner,
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
            Self::Scenes => SCENES_TESTS.to_vec(),
            Self::Ota => OTA_TESTS.to_vec(),
            Self::Wireless => WIRELESS_TESTS.to_vec(),
            Self::Thread => THREAD_TESTS.to_vec(),
            Self::Ble => BLE_TESTS.to_vec(),
            // One synthetic case — the dispatch in `ITests::run` picks
            // this up and routes to `run_commissioner_suite`, which
            // ignores the test list (there's nothing to parameterise yet).
            Self::Commissioner => vec![COMMISSIONER_PHASE1_TEST],
        }
    }

    /// Default `--target` (example binary) for this suite.
    pub(crate) fn default_target(&self) -> &'static str {
        match self {
            Self::System | Self::SystemPython | Self::SystemYaml => "system_tests",
            Self::Camera => "camera_tests",
            Self::Light => "light_tests",
            Self::Scenes => "scenes_tests",
            // rs-matter plays its OTA role from the `system_tests` binary.
            Self::Ota => "system_tests",
            Self::Wireless => "wireless_tests",
            Self::Thread => THREAD_TARGET,
            Self::Ble => "ble_tests",
            Self::Commissioner => "commissioner_tests",
        }
    }

    /// Cargo features the example binary must be built with for this suite.
    pub(crate) fn default_features(&self) -> &'static [&'static str] {
        match self {
            Self::System
            | Self::SystemPython
            | Self::SystemYaml
            | Self::Camera
            | Self::Light
            | Self::Scenes
            | Self::Ota
            | Self::Wireless
            | Self::Commissioner => &[],
            // The otbr D-Bus client (`OtbrNetCtl` + the `BorderRouterProxy`)
            // lives behind `zbus`.
            Self::Thread => &["zbus"],
            // The BlueZ GATT peripheral lives behind `zbus`; `bluer` adds the
            // alternative backend, selected per-test with `--bluer`.
            Self::Ble => &["ble", "bluer"],
        }
    }

    /// Default per-test timeout in seconds.
    pub(crate) fn default_timeout_secs(&self) -> u32 {
        match self {
            Self::System | Self::SystemPython | Self::SystemYaml => 120,
            Self::Camera => 180,
            Self::Light => 500,
            // Scenes tests include some long composite YAML suites
            // (multi-fabric/max-capacity); match `Light`'s budget.
            Self::Scenes => 500,
            // A full OTA flow commissions two nodes and transfers an image over
            // BDX; give it headroom.
            Self::Ota => 300,
            Self::Wireless => 120,
            // Real (if simulated-radio) Thread attaches: PAN formation plus
            // the `ConnectMaxTimeSeconds + fudge` settling waits.
            Self::Thread => 300,
            // BLE discovery plus the BTP handshake are slower than plain UDP.
            Self::Ble => 300,
            Self::Commissioner => 120,
        }
    }
}

/// The directory where the Chip repository will be cloned
const CHIP_DIR: &str = ".build/itest/connectedhomeip";

/// The `--target` whose tests are commissioned over BLE.
const BLE_TARGET: &str = "ble_tests";

/// The `--target` whose tests run against a real Thread stack (`otbr-agent`,
/// stood up by [`OtbrEnv`]). Its driver receives the startup dataset via the
/// `RS_MATTER_THREAD_DATASET` env var.
const THREAD_TARGET: &str = "thread_tests";

/// The workspace crate holding the device-under-test drivers (`*_tests`
/// binaries) and their `.pics` files.
const TEST_CRATE_DIR: &str = "tests";

/// Synthetic test name surfaced for [`TestSuite::Commissioner`] — picked
/// up by [`ITests::run_tests`] and routed to [`ITests::run_commissioner_suite`].
pub(crate) const COMMISSIONER_PHASE1_TEST: &str = "commissioner_phase_1";

/// Passcode the commissioner suite hands to `chip-all-clusters-app`. Any
/// value that satisfies the Matter spec (1..2^27-1, not in the reserved
/// list) works — pick the rs-matter test fixture so the example's
/// default also works without arguments.
const COMMISSIONER_PASSCODE: u32 = 20202021;
/// Discriminator handed to `chip-all-clusters-app`. Currently only used
/// for the CLI flag — the controller skips mDNS discovery and talks to
/// `[::1]:<port>` directly.
const COMMISSIONER_DISCRIMINATOR: u16 = 3840;
/// Port the spawned `chip-all-clusters-app` binds. Picked off the
/// canonical 5540 so a local rs-matter device can co-exist on 5540
/// during ad-hoc work.
const COMMISSIONER_DEVICE_PORT: u16 = 5550;

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
        self.chip_builder.build_python_wheel(force_rebuild)?;
        // The `thread` suite's Thread stack (`otbr-agent` + the simulation
        // `ot-rcp`). Built here - and not only lazily by the suite itself -
        // so that in CI the artifacts end up in the Chip build cache: the
        // cache is saved by a different matrix leg (`system-python`) than the
        // one running the thread suite (`rest`), and a lazily-built tree
        // would be rebuilt on every run without ever being saved.
        self.chip_builder.build_otbr(chip_gitref, force_rebuild)
    }

    /// Build the executable (`system-tests`) that is to be tested with the Chip integration tests.
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

        // Commissioner suite — rs-matter is the controller, the upstream
        // `chip-all-clusters-app` is the DUT. The test list will be the
        // single synthetic `COMMISSIONER_PHASE1_TEST` name. Route to the
        // dedicated path *before* the chip-tool check — that suite uses
        // neither chip-tool nor the python wheel.
        if tests
            .clone()
            .into_iter()
            .any(|t| t == COMMISSIONER_PHASE1_TEST)
        {
            return self.run_commissioner_suite(test_timeout_secs, profile, target);
        }

        let chip_tool_path = self.chip_builder.chip_tool_path();
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

        // OTA tests need a CHIP OTA app as the counterpart node. Provider-role
        // configs (rs-matter is the Provider) use `chip-ota-requestor-app` as the
        // requestor DUT; requestor-role configs would use the provider app.
        // Build both lazily (cached) so either role works.
        if tests.iter().any(|t| t.starts_with("OTA_")) {
            self.chip_builder
                .build_chip_ota_requestor_app(None, false)?;
            self.chip_builder.build_chip_ota_provider_app(None, false)?;
        }

        // The thread suite's DUT-side Thread stack is `otbr-agent` plus (by
        // default) the simulated `ot-rcp` radio; both are built lazily out of
        // the submodules vendored in the Chip checkout (cached on disk). The
        // BLE suite needs the same stack for its BLE-Thread flow.
        if target == THREAD_TARGET || tests.iter().any(|t| Self::ble_thread(t, target)) {
            self.chip_builder.build_otbr(None, false)?;
        }

        // Re-assert the CHIP Python wheel *after* the lazy app builds above.
        //
        // Each of them re-enters `setup_chip`, which re-provisions the pigweed
        // virtualenv and thereby drops everything pip-installed into it from
        // the outside - including the `matter` wheels that `run_python_test.py`
        // imports. Installing them once during `itest-setup` is therefore not
        // enough: a suite that pulls in a CHIP counterpart app (the commissioner
        // suite via `chip-all-clusters-app`, the `OTA_*` tests via the OTA apps)
        // silently unprovisions every Python test that runs after it, which
        // surfaces as `ModuleNotFoundError: No module named 'matter.testing'`.
        //
        // `build_python_wheel` probes before doing any work, so this is close to
        // free when the venv is intact.
        self.chip_builder.build_python_wheel(false)?;

        // Activate the CHIP build environment ONCE and capture the resulting
        // environment variables. `scripts/run_in_build_env.sh` re-runs the full
        // pigweed activation (CIPD manifest regeneration, `pw_activate`, git
        // submodule probes) on every invocation - several seconds each - so
        // per-test activation used to be a fixed tax on all ~150 tests of a
        // system-suite run. The activated environment is just a set of
        // variables that is a pure function of the checkout, so one capture
        // serves every test. This mirrors CHIP's own CI, which activates once
        // around a whole batch runner.
        let chip_env = self.capture_chip_env()?;

        // Run the tests. Python (`TC_*`) tests keep one process each - their
        // wrappers, shims and timeouts are all per-test - while YAML tests
        // sharing the same per-invocation configuration (see
        // `Self::yaml_batch_key`) are folded into a single `run_test_suite.py`
        // invocation. The runner still restarts and re-pairs the app for every
        // test inside a batch; what is amortized is the (multi-second) Python
        // runner startup and network-namespace setup, once per batch instead
        // of once per test.
        let mut done = vec![false; tests.len()];
        for i in 0..tests.len() {
            if done[i] {
                continue;
            }

            if Self::is_python_test(tests[i]) {
                done[i] = true;
                self.run_python_test(tests[i], test_timeout_secs, profile, target, &chip_env)?;
            } else {
                let key = Self::yaml_batch_key(tests[i]);

                let mut batch = Vec::new();
                for j in i..tests.len() {
                    if !done[j]
                        && !Self::is_python_test(tests[j])
                        && Self::yaml_batch_key(tests[j]) == key
                    {
                        done[j] = true;
                        batch.push(tests[j]);
                    }
                }

                self.run_yaml_batch(&batch, test_timeout_secs, profile, target, &chip_env)?;
            }
        }

        info!("All tests completed successfully.");

        Ok(())
    }

    /// Grouping key for folding YAML tests into one `run_test_suite.py`
    /// invocation. Tests may share an invocation only when they agree on
    /// everything that is fixed per-invocation:
    /// - the `.pics` file and the `RS_MATTER_WIRELESS_THREAD` device-flavour
    ///   selection, both determined by [`WirelessFlavour::of`];
    /// - the OTA app-path wiring, which is role-specific - so `OTA_*` tests
    ///   stay singleton batches, keyed by their own (role-suffixed) name.
    fn yaml_batch_key(test_name: &str) -> (Option<WirelessFlavour>, Option<&str>) {
        let real_name = test_name.strip_suffix("@requestor").unwrap_or(test_name);

        (
            WirelessFlavour::of(test_name),
            real_name.starts_with("OTA_").then_some(test_name),
        )
    }

    /// Activate the CHIP build environment and capture the resulting process
    /// environment, NUL-separated via a temp file (the activation itself
    /// prints to stdout, so stdout cannot carry the dump).
    fn capture_chip_env(&self) -> anyhow::Result<HashMap<String, String>> {
        info!("Capturing the CHIP build environment (one-time activation)...");

        let chip_dir = self.chip_builder.chip_dir();
        let script_path = chip_dir.join("scripts/run_in_build_env.sh");

        // A `NamedTempFile` rather than a hand-rolled path in the shared temp
        // dir: the file is pre-created 0600 with an unpredictable name (no
        // symlink-clobber window), and it is deleted on drop, early returns
        // included.
        let env_file = tempfile::NamedTempFile::new()?;

        let mut cmd = Command::new(&script_path);
        cmd.current_dir(chip_dir)
            .env("CHIP_HOME", chip_dir)
            .arg(format!("env -0 > '{}'", env_file.path().display()));

        run_command(&mut cmd, self.print_cmd_output)?;

        let data = fs::read(env_file.path()).map_err(|e| {
            anyhow::anyhow!(
                "CHIP environment activation did not produce {}: {e}",
                env_file.path().display()
            )
        })?;

        let mut env_map = HashMap::new();
        for entry in data.split(|byte| *byte == 0) {
            let entry = String::from_utf8_lossy(entry);
            if let Some((key, value)) = entry.split_once('=') {
                if !key.is_empty() {
                    env_map.insert(key.to_string(), value.to_string());
                }
            }
        }

        // A capture without PATH means the activation output is unusable -
        // every test command resolves python/chip-tool through it.
        if !env_map.contains_key("PATH") {
            anyhow::bail!("CHIP environment capture has no PATH; activation output looks corrupt");
        }

        info!(
            "CHIP build environment captured ({} variables)",
            env_map.len()
        );

        Ok(env_map)
    }

    /// Best-effort cleanup of processes left in the `app` network namespace by
    /// a previous (possibly crashed) run.
    fn kill_netns_leftovers(&self, chip_dir: &Path) {
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
    }

    fn run_python_test(
        &self,
        test_name: &str,
        timeout_secs: u32,
        profile: &str,
        target: &str,
        chip_env: &HashMap<String, String>,
    ) -> anyhow::Result<()> {
        // Some tests legitimately need more wall-clock time than the default
        // (e.g. those that wait for a commissioning window to expire on its
        // own). Allow per-test overrides while keeping the global `--timeout`
        // as the floor for everything else.
        let timeout_secs = Self::per_test_timeout_secs(test_name).unwrap_or(timeout_secs);

        info!("=> Running test `{test_name}` with timeout {timeout_secs}s...");

        let chip_dir = self.chip_builder.chip_dir();

        self.kill_netns_leftovers(chip_dir);

        let test_command = self.python_test_command(test_name, timeout_secs, profile, target)?;

        // `run_python_test.py` has no equivalent of `run_test_suite.py`'s
        // `--ble-wifi`, so the mock Bluetooth stack is stood up here and torn
        // down when `_ble_env` drops at the end of this function.
        let _ble_env = (target == BLE_TARGET)
            .then(|| BleEnv::start(chip_dir))
            .transpose()?;

        // Likewise the Thread stack: one fresh `otbr-agent` per test, so a
        // dataset the previous test attached to can't leak into the next one
        // (the app itself is factory-reset by the runner, but the Thread
        // stack lives in the agent). For the BLE-Thread flow the agent joins
        // the mock-Bluetooth bus instead of owning one, so that the single
        // `DBUS_SYSTEM_BUS_ADDRESS` the processes inherit reaches both
        // `org.bluez` and `io.openthread.BorderRouter`.
        let _otbr_env = if target == THREAD_TARGET {
            Some(OtbrEnv::start(
                &self.chip_builder.otbr_agent_path(),
                &self.chip_builder.ot_rcp_sim_path(),
            ))
        } else {
            _ble_env
                .as_ref()
                .filter(|_| Self::ble_thread(test_name, target))
                .map(|ble_env| {
                    OtbrEnv::start_on(
                        &ble_env.dbus_address(),
                        &self.chip_builder.otbr_agent_path(),
                        &self.chip_builder.ot_rcp_sim_path(),
                    )
                })
        }
        .transpose()?;

        // The command runs with the pre-captured CHIP build environment
        // injected (see `Self::capture_chip_env`) instead of being wrapped in
        // `run_in_build_env.sh`, which would re-do the activation every time.
        let mut cmd = Command::new("bash");
        cmd.current_dir(chip_dir)
            .envs(chip_env)
            .env("CHIP_HOME", chip_dir)
            .arg("-c")
            .arg(&test_command);

        if let Some(ble_env) = &_ble_env {
            cmd.env("DBUS_SYSTEM_BUS_ADDRESS", ble_env.dbus_address());
        }

        if let Some(otbr_env) = &_otbr_env {
            // The driver finds `otbr-agent` through the private bus (in the
            // BLE-Thread case this is the mock-Bluetooth bus again). Only the
            // `thread` suite's driver auto-attaches to the suite's first
            // dataset at startup - in the BLE flow the commissioner provisions
            // the network itself.
            cmd.env("DBUS_SYSTEM_BUS_ADDRESS", otbr_env.dbus_address());

            if target == THREAD_TARGET {
                cmd.env("RS_MATTER_THREAD_DATASET", THREAD_DATASET_1);
            }
        }

        // The Thread flavour of `wireless_tests` is selected out of the
        // environment (inherited by the app the runner launches). Only for
        // that target — the same test names in the `thread` suite drive a
        // driver with no flavour switch.
        if target == "wireless_tests"
            && matches!(
                WirelessFlavour::of(test_name),
                Some(WirelessFlavour::Thread)
            )
        {
            cmd.env("RS_MATTER_WIRELESS_THREAD", "1");
        }

        match run_command(&mut cmd, self.print_cmd_output) {
            Ok(()) => info!("Test `{test_name}` completed successfully"),
            Err(err) => {
                info!("Command failed: {}", test_command);
                return Err(err);
            }
        };

        Ok(())
    }

    /// Run a batch of YAML tests in a single `run_test_suite.py` invocation.
    ///
    /// All batch members share one per-invocation configuration - guaranteed
    /// by [`Self::yaml_batch_key`] - and none of them has a
    /// [`Self::per_test_timeout_secs`] override (those are all `TC_*` Python
    /// tests), so the suite default applies to every member, enforced
    /// per-test by the runner itself via `--test-timeout-seconds`.
    fn run_yaml_batch(
        &self,
        batch: &[&str],
        timeout_secs: u32,
        profile: &str,
        target: &str,
        chip_env: &HashMap<String, String>,
    ) -> anyhow::Result<()> {
        info!(
            "=> Running YAML test batch of {} test(s) with per-test timeout {timeout_secs}s: {batch:?}...",
            batch.len()
        );

        let chip_dir = self.chip_builder.chip_dir();

        self.kill_netns_leftovers(chip_dir);

        let test_command = self.yaml_batch_command(batch, timeout_secs, profile, target);

        // One `otbr-agent` for the whole batch: the YAML Thread tests only
        // read diagnostics, so cross-test dataset leakage is not a concern
        // and the (several-second) agent startup is better amortized.
        let _otbr_env = (target == THREAD_TARGET)
            .then(|| {
                OtbrEnv::start(
                    &self.chip_builder.otbr_agent_path(),
                    &self.chip_builder.ot_rcp_sim_path(),
                )
            })
            .transpose()?;

        // See `run_python_test` for why the captured environment replaces the
        // `run_in_build_env.sh` wrapper.
        let mut cmd = Command::new("bash");
        cmd.current_dir(chip_dir)
            .envs(chip_env)
            .env("CHIP_HOME", chip_dir)
            .arg("-c")
            .arg(&test_command);

        if let Some(otbr_env) = &_otbr_env {
            cmd.env("DBUS_SYSTEM_BUS_ADDRESS", otbr_env.dbus_address());
            cmd.env("RS_MATTER_THREAD_DATASET", THREAD_DATASET_1);
        }

        // `run_test_suite.py` spawns the device itself and takes no per-app
        // arguments, so the Thread flavour of `wireless_tests` is selected out
        // of the environment instead (inherited by the app it launches).
        // Uniform across the batch by construction of the batch key, and only
        // meaningful for the `wireless_tests` target (see `run_python_test`).
        if target == "wireless_tests"
            && matches!(WirelessFlavour::of(batch[0]), Some(WirelessFlavour::Thread))
        {
            cmd.env("RS_MATTER_WIRELESS_THREAD", "1");
        }

        match run_command(&mut cmd, self.print_cmd_output) {
            Ok(()) => {
                // A zero exit status is NOT sufficient for the YAML suites:
                // `run_test_suite.py` has been observed to exit 0 while
                // individual tests were marked failed, so a failing YAML test
                // would silently pass the whole run (and CI with it). It also
                // merely logs (and skips) `--target` names it does not know,
                // which with a batched invocation would silently drop
                // coverage e.g. across an upstream test rename. Consult the
                // JSON run summary instead - that is the authoritative
                // per-test verdict - and require every batch member to appear
                // in it as passed.
                Self::assert_yaml_summary_clean(batch)?;

                info!("YAML test batch completed successfully: {batch:?}")
            }
            Err(err) => {
                info!("Command failed: {}", test_command);

                // Best-effort: surface which test(s) of the batch failed,
                // if the runner got as far as writing the summary.
                if let Err(summary_err) = Self::assert_yaml_summary_clean(batch) {
                    warn!("{summary_err}");
                }

                return Err(err);
            }
        };

        Ok(())
    }

    /// Path of the JSON run summary that `run_test_suite.py` is asked to write
    /// for a batch (see `--summary-file` in [`Self::yaml_batch_command`]).
    /// Keyed by the batch's first test name, which is unique within a run.
    fn yaml_summary_path(batch: &[&str]) -> PathBuf {
        env::temp_dir().join(format!("xtask-yaml-summary-{}.json", batch[0]))
    }

    /// Fail unless the batch's YAML run summary records every requested test
    /// as passed.
    ///
    /// Two failure modes are covered:
    /// - a test ran and failed (`run_test_suite.py` has been observed to exit
    ///   0 in that situation);
    /// - a test never ran at all: the runner only *logs* an unknown `--target`
    ///   name and carries on with the rest, so e.g. an upstream rename would
    ///   otherwise silently drop coverage from a batch.
    fn assert_yaml_summary_clean(batch: &[&str]) -> anyhow::Result<()> {
        let path = Self::yaml_summary_path(batch);

        let Ok(summary) = fs::read_to_string(&path) else {
            // No summary: an older `run_test_suite.py` without `--summary-file`,
            // or a run that died before writing it. Don't turn that into a
            // failure - the exit status already passed - but make the loss of
            // coverage visible rather than silently trusting the exit code.
            warn!(
                "YAML batch {batch:?}: no run summary at {} - cannot verify per-test results",
                path.display()
            );
            return Ok(());
        };

        let summary: serde_json::Value = serde_json::from_str(&summary).map_err(|e| {
            anyhow::anyhow!(
                "YAML batch {batch:?}: run summary at {} is not valid JSON: {e}",
                path.display()
            )
        })?;

        let results = summary["results"].as_array().cloned().unwrap_or_default();

        for test_name in batch {
            // OTA role suffixes are an xtask-ism; the runner reports the
            // upstream name.
            let real_name = test_name.strip_suffix("@requestor").unwrap_or(test_name);

            // The runner matches `--target` names case-insensitively, so
            // mirror that when looking its reports back up.
            let result = results.iter().find(|result| {
                result["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case(real_name))
            });

            let Some(result) = result else {
                anyhow::bail!(
                    "Test `{test_name}` is absent from the run summary ({}) - \
                     most likely `run_test_suite.py` did not recognize the target name",
                    path.display()
                );
            };

            // `TestStatus` is a `StrEnum`, so statuses serialize as lowercase
            // strings ("passed" / "failed" / "cancelled" / "dry_run").
            let status = result["status"].as_str().unwrap_or("<unknown>");
            if status != "passed" {
                anyhow::bail!(
                    "Test `{test_name}` reported status `{status}` in the run summary ({})",
                    path.display()
                );
            }
        }

        Ok(())
    }

    /// `TC_*` (camelCase) is the upstream filename convention for
    /// CHIP `MatterBaseTest`-style Python tests in
    /// `src/python_testing/`. Anything else is a YAML test suite.
    fn is_python_test(test_name: &str) -> bool {
        test_name.starts_with("TC_")
    }

    /// Drive the [`TestSuite::Commissioner`] flow end-to-end.
    ///
    /// Builds `chip-all-clusters-app` (cached), spawns it on
    /// `[::1]:<COMMISSIONER_DEVICE_PORT>` with a known passcode +
    /// discriminator + an ephemeral KVS file (so commissioning state
    /// doesn't carry across runs), then runs the rs-matter
    /// `commissioner_tests` example against it. Asserts the example
    /// exits 0 and prints the expected `commissioner_tests: ok …` line.
    /// Kills the spawned app on success or failure.
    fn run_commissioner_suite(
        &self,
        test_timeout_secs: u32,
        profile: &str,
        target: &str,
    ) -> anyhow::Result<()> {
        use std::io::{BufRead, BufReader};
        use std::process::Stdio;
        use std::sync::mpsc;
        use std::thread;
        use std::time::{Duration, Instant};

        warn!(
            "=> Running commissioner suite (rs-matter as controller, chip-all-clusters-app as DUT)"
        );

        // 1. Build the upstream device binary lazily (cached).
        self.chip_builder.build_chip_all_clusters_app(None, false)?;

        let app_path = self.chip_builder.all_clusters_app_path();
        if !app_path.exists() {
            anyhow::bail!(
                "`chip-all-clusters-app` not found at {}",
                app_path.display()
            );
        }

        let test_exe_path = self.test_exe_path(profile, target);
        if !test_exe_path.exists() {
            anyhow::bail!(
                "`{target}` not found at {} — run `cargo xtask itest-exe --target {target}` first",
                test_exe_path.display(),
            );
        }

        // 2. Fresh KVS per run — chip-all-clusters-app persists fabric
        //    state, and we want each run to start from factory-reset.
        let kvs_path =
            std::env::temp_dir().join(format!("rs-matter-commissioner-kvs-{}", std::process::id()));
        let _ = std::fs::remove_file(&kvs_path);

        // 3. Spawn the DUT. Bind to IPv6 loopback only (matches what
        //    `commissioner_tests` peers against by default). Drain its
        //    stdout/stderr to a background thread so the pipe buffer
        //    doesn't fill up and stall the subprocess.
        info!(
            "Spawning chip-all-clusters-app on [::1]:{} (passcode={}, discriminator={})",
            COMMISSIONER_DEVICE_PORT, COMMISSIONER_PASSCODE, COMMISSIONER_DISCRIMINATOR,
        );
        let mut app = Command::new(&app_path)
            .arg("--passcode")
            .arg(COMMISSIONER_PASSCODE.to_string())
            .arg("--discriminator")
            .arg(COMMISSIONER_DISCRIMINATOR.to_string())
            .arg("--secured-device-port")
            .arg(COMMISSIONER_DEVICE_PORT.to_string())
            .arg("--KVS")
            .arg(&kvs_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn chip-all-clusters-app: {e}"))?;

        // Drain stdout in a thread + signal when the app reports it's
        // ready. CHIP prints a line containing "Listening" or
        // "CHIP minimal mDNS started" once it's accepting commissioning.
        // Use a tolerant marker — any log line is fine for readiness;
        // the controller's PASE attempt will retry briefly on its own.
        let app_stdout = app.stdout.take().expect("piped");
        let app_stderr = app.stderr.take().expect("piped");
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let ready_tx_clone = ready_tx.clone();
        let print_app_output = self.print_cmd_output;
        let stdout_thread = thread::spawn(move || {
            let mut signalled = false;
            let reader = BufReader::new(app_stdout);
            for line in reader.lines().map_while(Result::ok) {
                if print_app_output {
                    println!("[chip-all-clusters-app stdout] {line}");
                }
                if !signalled && line.contains("CHIP minimal mDNS started") {
                    let _ = ready_tx_clone.send(());
                    signalled = true;
                }
            }
        });
        let stderr_thread = thread::spawn(move || {
            let reader = BufReader::new(app_stderr);
            for line in reader.lines().map_while(Result::ok) {
                if print_app_output {
                    eprintln!("[chip-all-clusters-app stderr] {line}");
                }
            }
        });

        // 4. Wait up to 10 s for the DUT to advertise. Fall through
        //    after the timeout — the rs-matter PASE initiator retries
        //    internally, so a small startup race is fine.
        let _ = ready_rx.recv_timeout(Duration::from_secs(10));
        info!("chip-all-clusters-app appears ready");

        // 5. Run the rs-matter controller binary against it. Time-bound
        //    so a hung commissioning doesn't deadlock the suite.
        let mut controller = Command::new(&test_exe_path)
            .arg(COMMISSIONER_PASSCODE.to_string())
            .arg(format!("[::1]:{COMMISSIONER_DEVICE_PORT}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn commissioner_tests: {e}"))?;

        let controller_stdout = controller.stdout.take().expect("piped");
        let controller_stderr = controller.stderr.take().expect("piped");

        // Capture controller stdout to extract the `commissioner_tests:
        // ok ...` line; also stream stderr to the operator.
        let (success_tx, success_rx) = mpsc::channel::<String>();
        let success_tx_clone = success_tx.clone();
        let print_ctrl_output = self.print_cmd_output;
        let ctrl_stdout_thread = thread::spawn(move || {
            let reader = BufReader::new(controller_stdout);
            for line in reader.lines().map_while(Result::ok) {
                if print_ctrl_output {
                    println!("[commissioner_tests stdout] {line}");
                }
                if line.starts_with("commissioner_tests: ok ") {
                    let _ = success_tx_clone.send(line);
                }
            }
        });
        let ctrl_stderr_thread = thread::spawn(move || {
            let reader = BufReader::new(controller_stderr);
            for line in reader.lines().map_while(Result::ok) {
                if print_ctrl_output {
                    eprintln!("[commissioner_tests stderr] {line}");
                } else {
                    // The example logs operationally on stderr; in normal
                    // verbosity we still want it visible on failure.
                    eprintln!("[commissioner_tests] {line}");
                }
            }
        });

        // Poll for completion or timeout.
        let deadline = Instant::now() + Duration::from_secs(test_timeout_secs as u64);
        let controller_status = loop {
            match controller.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() >= deadline => {
                    warn!("commissioner_tests timed out after {test_timeout_secs}s; killing");
                    let _ = controller.kill();
                    let _ = controller.wait();
                    let _ = app.kill();
                    let _ = app.wait();
                    let _ = stdout_thread.join();
                    let _ = stderr_thread.join();
                    let _ = ctrl_stdout_thread.join();
                    let _ = ctrl_stderr_thread.join();
                    anyhow::bail!("commissioner_tests timed out");
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(200)),
                Err(e) => {
                    let _ = app.kill();
                    let _ = app.wait();
                    anyhow::bail!("waiting on commissioner_tests failed: {e}");
                }
            }
        };
        let _ = ctrl_stdout_thread.join();
        let _ = ctrl_stderr_thread.join();

        // 6. Tear down the DUT regardless of the controller's outcome.
        let _ = app.kill();
        let _ = app.wait();
        let _ = stdout_thread.join();
        let _ = stderr_thread.join();
        let _ = std::fs::remove_file(&kvs_path);

        // 7. Assertions: clean exit *and* the success line was emitted.
        if !controller_status.success() {
            anyhow::bail!(
                "commissioner_tests exited with {:?} (expected success)",
                controller_status.code(),
            );
        }
        let success_line = success_rx.try_recv().map_err(|_| {
            anyhow::anyhow!("commissioner_tests did not emit a `commissioner_tests: ok ...` line")
        })?;
        info!("commissioner suite passed: {success_line}");
        // Suppress unused-channel warning on the unused sender.
        drop(success_tx);

        Ok(())
    }

    fn yaml_batch_command(
        &self,
        batch: &[&str],
        timeout_secs: u32,
        profile: &str,
        target: &str,
    ) -> String {
        let chip_dir = self.chip_builder.chip_dir();
        let test_suite_path = chip_dir.join("scripts/tests/run_test_suite.py");
        let chip_tool_path = self.chip_builder.chip_tool_path();
        let test_exe_path = self.test_exe_path(profile, target);
        // Uniform across the batch by construction of the batch key (the
        // wireless flavour is the only thing that changes it for a fixed
        // `target`).
        let test_pics_path = self.test_pics_path(batch[0], target);

        // OTA tests (`OTA_*`) run as a 3-party flow: the YAML commissions both an
        // OTA provider and an OTA requestor. We slot the rs-matter `system_tests`
        // binary into one role and a CHIP `chip-ota-{provider,requestor}-app` into
        // the other. A `@requestor` suffix on the test name selects the role
        // (rs-matter as the requestor DUT); default is rs-matter as the provider.
        // The suffix is stripped before the YAML name is handed to the runner.
        // OTA tests are singleton batches (see `Self::yaml_batch_key`), so
        // inspecting `batch[0]` covers them fully.
        let (real_first, rs_is_requestor) = match batch[0].strip_suffix("@requestor") {
            Some(name) => (name, true),
            None => (batch[0], false),
        };
        let ota_app_clause = if real_first.starts_with("OTA_") {
            let chip_requestor = self.chip_builder.ota_requestor_app_path();
            let chip_provider = self.chip_builder.ota_provider_app_path();
            if rs_is_requestor {
                format!(
                    " --app-path 'ota-requestor:{}' --app-path 'ota-provider:{}'",
                    test_exe_path.display(),
                    chip_provider.display(),
                )
            } else {
                format!(
                    " --app-path 'ota-provider:{}' --app-path 'ota-requestor:{}'",
                    test_exe_path.display(),
                    chip_requestor.display(),
                )
            }
        } else {
            String::new()
        };

        // One `--target` per batch member; the runner takes the option
        // repeatedly and runs the matches in the given order.
        let targets_clause = batch
            .iter()
            .map(|test_name| {
                format!(
                    " --target {}",
                    test_name.strip_suffix("@requestor").unwrap_or(test_name)
                )
            })
            .collect::<String>();

        // Ask for a JSON run summary and drop any stale one first: a zero exit
        // status from `run_test_suite.py` does not imply the tests passed (see
        // `Self::assert_yaml_summary_clean`), so this file is what we actually
        // judge the run by.
        let summary_path = Self::yaml_summary_path(batch);
        _ = fs::remove_file(&summary_path);

        // NB: `--tool-path` / `--app-path` are options of the `run` subcommand,
        // whereas the `--chip-tool` flag they replace was a group-level one -
        // hence the tool path now sits *after* `run`, not before it.
        //
        // The DUT binary is registered under *both* the `all-clusters` and
        // `all-devices` keys because the runner picks the slot from the test's
        // own target (`Test_TC_OO_*` resolve to `all-devices`, the YAML suites
        // to `all-clusters`) and errors with `KeyError: 'default'` when that
        // slot is empty. The `lock` slot serves `TestSystemCommands`, which
        // spawns a second accessory from it. The `lit-icd` slot serves the
        // `TestIcd*` suites, which the runner classifies as the `LIT_ICD`
        // target: it launches the DUT from that slot and pairs with
        // `--icd-registration true`, driving commissioning-time ICD client
        // registration. Registering a slot no test selects is free: the
        // runner only ever starts the app it resolved to `default` (plus, for
        // `TestSystemCommands`, the explicitly-started second instance).
        // `--log-level info` (not `warn`): with a whole batch inside one
        // invocation, the per-test "Executing ..." progress lines have to come
        // from the runner itself, or a hung batch is a silent wall of nothing
        // in the CI log until the job-level timeout kills it.
        format!(
            "{} --log-level info{} --runner chip_tool_python run --iterations 1 --test-timeout-seconds {} --tool-path 'chip-tool:{}' --app-path 'all-clusters:{}' --app-path 'all-devices:{}' --app-path 'lock:{}' --app-path 'lit-icd:{}'{} --pics-file {} --summary-file '{}'",
            test_suite_path.display(),
            targets_clause,
            timeout_secs,
            chip_tool_path.display(),
            test_exe_path.display(),
            test_exe_path.display(),
            test_exe_path.display(),
            test_exe_path.display(),
            ota_app_clause,
            test_pics_path.display(),
            summary_path.display(),
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

        // A `@bluer` suffix re-runs the same test against the alternative BLE
        // backend; it is stripped before the script name is resolved.
        let (test_name, bluer) = match test_name.strip_suffix("@bluer") {
            Some(name) => (name, true),
            None => (test_name, false),
        };

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
        let extra_args = Self::extra_python_script_args(test_name, target);
        // Some tests (e.g. TC_SC_4_1) need to be commissioned via a setup
        // payload (manual or QR code) rather than the raw discriminator /
        // passcode pair, because their script logic inspects
        // `matter_test_config.manual_code` / `qr_code_content` to choose
        // between long- and short-discriminator mDNS subtypes. Passing
        // both `--discriminator`/`--passcode` *and* `--manual-code` makes
        // the framework attempt commissioning twice (once per setup
        // payload) and the second attempt times out, so we must drop the
        // raw form here.
        let ble = target == BLE_TARGET;

        let commissioning_args = match Self::setup_payload_override(test_name) {
            Some(setup_payload) => setup_payload.to_string(),
            None => format!("--discriminator {discriminator} --passcode {passcode}"),
        };
        // The device takes `hci0` and the commissioner `hci1`, so the two ends
        // of the link are distinct adapters - the arrangement CHIP's own
        // BLE-Wi-Fi harness uses, and the one `bluezoo` publishes by default.
        //
        // The network credentials are what the commissioner provisions the DUT
        // with over BTP: mock Wi-Fi ones, or - for the BLE-Thread flow - the
        // suite's first (real) operational dataset, which then doubles as the
        // network the CNET test expects to read back.
        let ble_thread = Self::ble_thread(test_name, target);
        let commissioning_args = if ble_thread {
            format!(
                "{commissioning_args} --ble-controller 1 --thread-dataset-hex {THREAD_DATASET_1}"
            )
        } else if ble {
            format!(
                "{commissioning_args} --ble-controller 1 \
                 --wifi-ssid MatterAP --wifi-passphrase MatterAPPassword"
            )
        } else {
            commissioning_args
        };
        // A handful of tests (e.g. TC_SC_7_1) only do PASE establishment in
        // the test body itself, and assert that the device starts factory
        // reset. Pre-test commissioning would add a fabric and break the
        // assertion, so omit `--commissioning-method` for those tests.
        let commissioning_method = if Self::skip_pre_commissioning(test_name) {
            ""
        } else if ble_thread {
            "--commissioning-method ble-thread "
        } else if ble {
            "--commissioning-method ble-wifi "
        } else {
            "--commissioning-method on-network "
        };
        // A few tests need a *second* Matter device under the test framework's
        // control (`AppServerSubprocess`) — TC-SC-3.5 in particular, which
        // injects faults into a separate "TH_SERVER" Matter app. The CHIP
        // `chip-all-clusters-app` is the canonical implementation; its path
        // is plumbed in via the `th_server_app_path` string user-param.
        let th_server_arg = if Self::needs_th_server_app(test_name) {
            let app = self.chip_builder.all_clusters_app_path();
            format!(" --string-arg th_server_app_path:{}", app.display())
        } else {
            String::new()
        };
        // Tests that spawn `chip-all-clusters-app` themselves take its path via
        // the `app_path` string user-param instead.
        let app_path_arg = if Self::needs_all_clusters_app_arg(test_name) {
            let app = self.chip_builder.all_clusters_app_path();
            format!(" --string-arg app_path:{}", app.display())
        } else {
            String::new()
        };
        let extra_args_clause = if extra_args.is_empty() {
            String::new()
        } else {
            format!(" {extra_args}")
        };
        // Python `MatterBaseTest` scripts don't receive the YAML runner's
        // `--pics-file`; a script that gates its steps on `check_pics(...)`
        // sees an empty PICS dict unless we hand it a `--PICS` file. Point the
        // ones that need it at the target's own `.pics` (the same file the YAML
        // runner uses), by absolute path since the runner's CWD is `chip_dir`.
        let pics_clause = if Self::needs_target_pics(test_name) {
            format!(
                " --PICS {}",
                self.test_pics_path(test_name, target).display()
            )
        } else {
            String::new()
        };
        // Override the framework's 90s per-test `asyncio` budget for tests
        // whose body legitimately runs longer (e.g. a 180s window-expiry wait).
        let framework_timeout_clause = Self::per_test_framework_timeout_secs(test_name)
            .map(|secs| format!(" --timeout {secs}"))
            .unwrap_or_default();

        let script_args = format!(
            "--storage-path /tmp/rs_matter_python_test_storage.json \
             {commissioning_method}{commissioning_args} --endpoint 1 \
             --paa-trust-store-path credentials/development/paa-root-certs{framework_timeout_clause}{extra_args_clause}{pics_clause}{th_server_arg}{app_path_arg}"
        );

        // Optional `--app-args` passed through to `system_tests`. Used by
        // tests like TC_SC_7_1 that require non-default discriminator /
        // passcode values, which the test then asserts (`assert_not_equal`
        // against `3840` / `20202021`).
        let backend = if bluer { " --bluer" } else { "" };
        let app_args_clause = match (ble, Self::app_args_override(test_name, target)) {
            (true, Some(args)) => {
                format!(" --app-args '--ble-controller 0{backend} {args}'")
            }
            (true, None) => format!(" --app-args '--ble-controller 0{backend}'"),
            (false, Some(args)) => format!(" --app-args '{args}'"),
            (false, None) => String::new(),
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
    /// default `allow_pase=True`, which on `v1.5-branch` triggered a fresh
    /// `EstablishPASESession` against a closed-window DUT and either hung
    /// 25 s on BlueZ activation or leaked a stale "in-progress PASE" entry
    /// in the controller. See the script's docstring for the full diagnosis.
    ///
    /// RETIRABLE: the upstream fix (`b180d46945`, PR #41712) *is* present at
    /// the commit `CHIP_DEFAULT_GITREF` now pins - `basic_composition.py` there
    /// calls `FindOrEstablishPASESession`, so the session is reused instead of
    /// re-established and the race this works around is gone. The shim is kept
    /// for now only so that the Matter 1.6 bump and this cleanup can be
    /// bisected apart: removing it changes how three certification tests set
    /// up, and that is only observable in a full `cargo xtask itest` run. Drop
    /// this function, the branch in `yaml_test_command`, and
    /// `xtask/scripts/no_pase_setup_class_helper.py` once a cert run has gone
    /// green with the 1.6 data model.
    fn needs_no_pase_shim(test_name: &str) -> bool {
        matches!(
            test_name,
            "TC_AccessChecker"
                | "TC_DeviceBasicComposition"
                | "TC_DeviceConformance"
                // Same `setup_class_helper` PASE+CASE race as the three above.
                | "TC_IDM_4_3"
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
    ///    `LocalizationConfiguration`, `Switch`, …) match no endpoint
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
                | "TC_LCFG_2_1"      // has_cluster(LocalizationConfiguration)
                | "TC_LTIME_3_1"     // has_cluster(TimeFormatLocalization)
                | "TC_LUNIT_3_1"     // has_cluster(UnitLocalization) and has_attribute(TemperatureUnit)
                | "TC_SWTCH"         // 5 inner methods, each has_feature(Switch, ...)
                // All three test the optional `AccessControlExtension`
                // feature (Extension attribute); rs-matter does not implement
                // it, so `has_attribute(AccessControl.Extension)` skips cleanly.
                | "TC_ACL_2_3"
                | "TC_ACL_2_5"
                | "TC_ACL_2_7"
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
            // construction. `TC_CADMIN_1_3_4` runs *two* such test methods
            // (`test_TC_CADMIN_1_3` and `_1_4`) back-to-back in one process,
            // so this whole-process ceiling must cover both, each with the
            // per-method budget in `per_test_framework_timeout_secs`.
            "TC_CADMIN_1_3_4" => Some(600),
            // Sends several real multicast group commands with fixed 3s
            // settling sleeps in between, plus event-report awaits.
            "TC_ACE_1_6" => Some(360),
            "TC_CADMIN_1_5" | "TC_CADMIN_1_9" | "TC_CADMIN_1_11" | "TC_CADMIN_1_15"
            | "TC_CADMIN_1_22" | "TC_CADMIN_1_25" => Some(360),
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
            // Declares its own `default_timeout = 600` (subscription-interval
            // waits across 12+ steps); the process ceiling must exceed it.
            "TC_IDM_4_3" => Some(700),
            // Three PAN switches, each followed by a
            // `ConnectMaxTimeSeconds + fudge` settling sleep plus a CASE
            // re-establishment against the moved DUT.
            "TC_CNET_4_12" => Some(600),
            _ => None,
        }
    }

    /// The Matter test framework's *per-test-method* `asyncio` budget, passed
    /// as `--timeout`. Distinct from [`Self::per_test_timeout_secs`], which is
    /// the process-level wall-clock kill covering the whole invocation.
    ///
    /// Without `--timeout` the framework uses its 90s `default_timeout`, and a
    /// test method that waits ~180s for a commissioning window to expire is
    /// cancelled mid-flight the instant that wait ends — surfacing as an
    /// `asyncio` `CancelledError`/`TimeoutError`, not an rs-matter fault.
    /// Upstream passes `--timeout` in the test's metadata `script-args` for the
    /// same reason; we build our own script args, so we set it here.
    fn per_test_framework_timeout_secs(test_name: &str) -> Option<u32> {
        match test_name {
            // Each of `test_TC_CADMIN_1_3` / `_1_4` waits ~180s for a
            // commissioning window to expire before opening the next one.
            "TC_CADMIN_1_3_4" | "TC_CADMIN_1_5" | "TC_CADMIN_1_9" | "TC_CADMIN_1_11"
            | "TC_CADMIN_1_15" | "TC_CADMIN_1_22" | "TC_CADMIN_1_25" => Some(300),
            // The settling sleeps alone (3 × `ConnectMaxTimeSeconds + fudge`)
            // exceed the framework's default 90s per-method budget.
            "TC_CNET_4_12" => Some(480),
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
            // The QR code matches the values we pass to `system_tests`
            // via `--app-args` (see `app_args_override`).
            "TC_SC_7_1" => Some("--qr-code MT:-24J0KCZ16N71648G00"),
            // TC_DD_1_16_17 bundles two MatterBaseTests:
            //  - `test_TC_DD_1_16` parses `matter_test_config.qr_code_content`
            //  - `test_TC_DD_1_17` parses `matter_test_config.manual_code`
            // so we have to hand the framework both forms. The values are
            // the spec-default system_tests credentials (discriminator
            // 3840, passcode 20202021) — same as
            // `rs_matter::dm::devices::test::TEST_DEV_COMM`. The QR code is
            // what `system_tests` prints at startup as
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
        // (see `needs_th_server_app`). TC_DA_1_9 spawns the binary itself and
        // takes it via `--string-arg app_path` (see
        // `needs_all_clusters_app_arg`).
        matches!(test_name, "TC_SC_3_5" | "TC_DA_1_9")
    }

    /// Tests that need the CHIP `chip-all-clusters-app` binary path injected
    /// as the `th_server_app_path` string user-param (consumed by
    /// `matter.testing.apps.AppServerSubprocess`).
    /// Tests that spawn `chip-all-clusters-app` themselves and take its path
    /// via the `app_path` string user-param.
    fn needs_all_clusters_app_arg(test_name: &str) -> bool {
        // TC_DA_1_9 launches the binary repeatedly, each time with a different
        // revoked DAC/PAI configuration.
        matches!(test_name, "TC_DA_1_9")
    }

    fn needs_th_server_app(test_name: &str) -> bool {
        // TC_SC_3_5 ("CASE Error Handling [DUT_Initiator]") spawns a TH_SERVER
        // and uses CHIP's `FaultInjection` cluster on it to corrupt Sigma2
        // fields (NOC, ICAC, signature, TBEData2). The test bails out of
        // `setup_class` if the path isn't supplied.
        matches!(test_name, "TC_SC_3_5")
    }

    /// Whether this Python test must be handed the target's own `.pics` file.
    ///
    /// Tests that read attributes conditionally on `check_pics(...)` (and assert
    /// that a mandatory attribute *is* in the PICS) need the DUT's real PICS
    /// claims, not the empty default. `TC_ICDM_2_1` gates every attribute read
    /// this way; `TC_ICDM_3_2/3_3/3_4` gate on `ICDM.S.F00`, and the target
    /// `.pics` also carries `PICS_SDK_CI_ONLY=1` so 3_2/3_4 take their
    /// reboot-free CI path.
    fn needs_target_pics(test_name: &str) -> bool {
        matches!(
            test_name,
            "TC_ICDM_2_1" | "TC_ICDM_3_2" | "TC_ICDM_3_3" | "TC_ICDM_3_4" | "TC_ICDM_5_1"
            // `TC_BINFO_2_2` cross-checks the events it observes against the
            // declared PICS (`BINFO.S.E02` for `Leave`): with no `--PICS`,
            // `check_pics` answers false and an *emitted* Leave event fails
            // the consistency assert.
            | "TC_BINFO_2_2"
            // `TC_IDM_10_1` (a sub-test of `TC_DeviceBasicComposition`) rejects
            // identifiers carrying a *test* vendor prefix (0xFFF1..=0xFFF4)
            // unless `PICS_SDK_CI_ONLY` is set, in which case it only rejects
            // 0xFFF5 and above. The example fixtures legitimately use test
            // vendor IDs - the `UnitTesting` cluster is 0xFFF1FC05 and carries
            // MEI attributes/commands under the 0xFFF2 prefix - exactly as
            // CHIP's own example apps do. The target `.pics` sets
            // `PICS_SDK_CI_ONLY=1`, so handing it over is what makes the check
            // apply the SDK-example rule rather than the shipping-product one.
            | "TC_DeviceBasicComposition"
            // `TC_DeviceConformance` likewise reads `is_pics_sdk_ci_only`
            // (in `check_conformance`), so it needs the target `.pics` too.
            | "TC_DeviceConformance"
        )
    }

    /// Whether this test runs the BLE suite's BLE-**Thread** flow: commissioned
    /// with `--commissioning-method ble-thread`, against the `--thread` flavour
    /// of `ble_tests` plus an `otbr-agent` on the same mock-Bluetooth bus.
    ///
    /// Piggy-backs on [`WirelessFlavour`]: the same Wi-Fi/Thread split decides
    /// which network type a BLE commissioning provisions.
    fn ble_thread(test_name: &str, target: &str) -> bool {
        let test_name = test_name.strip_suffix("@bluer").unwrap_or(test_name);

        target == BLE_TARGET
            && matches!(
                WirelessFlavour::of(test_name),
                Some(WirelessFlavour::Thread)
            )
    }

    /// Optional `--app-args` passed straight through to `system_tests`.
    ///
    /// `system_tests` recognises `--discriminator <u16>` and
    /// `--passcode <u32>`; both override the spec-default `TEST_DEV_COMM`
    /// values for tests that demand non-defaults.
    fn app_args_override(test_name: &str, target: &str) -> Option<&'static str> {
        // The BLE-Thread flow drives the `--thread` flavour of `ble_tests`.
        if Self::ble_thread(test_name, target) {
            return Some("--thread");
        }

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
            // NOTE: do NOT route `TC_BINFO_2_1` at the `--app-pipe` app
            // variant, even though that would let its `DeviceLocation` steps
            // 24-28 execute (rs-matter implements the attribute — see
            // `basic_info::CLUSTER_DEVICE_LOCATION`). Upstream's
            // `support_modules/binfo_attributes_verification.py` cannot run
            // those steps against ANY conformant DUT: it references a
            // `BasicInformation.Structs.DeviceLocationStruct` class the
            // generated cluster objects never define (the attribute is typed
            // as the global `LocationDescriptorStruct`), its null checks
            // compare the decoded `NullValue` sentinel against Python `None`
            // (step 24 `is None` / step 26 `assert_equal(..., None)`), and
            // its step-25 write passes `areaType=None`, which the cluster
            // object encoder rejects for a nullable-but-not-optional field
            // (`NullValue` is required). Upstream CI never notices because
            // its reference apps do not advertise the provisional attribute,
            // so `attribute_guard` always skips the steps. Until that module
            // is fixed upstream, the steps skip here too, and the attribute
            // is covered by rs-matter's own e2e test instead.
            "TC_BINFO_3_2" => Some("--app-pipe /tmp/rs_matter_bin_info_3_2_fifo"),
            // The `TC_GC_*` suite runs against the Groupcast-enabled app
            // composition (`NODE_GROUPCAST` in `system_tests`): the
            // Groupcast cluster on EP0 plus the aux-ACL-enabled Access
            // Control metadata. Deliberately NOT the default composition:
            // with `AUXILIARY` advertised, wildcard-target Group-auth ACL
            // entries no longer cover EP0 (Matter Core spec), which would
            // break `TestGroupMessaging`'s legacy group-addressed writes to
            // root-endpoint attributes - upstream likewise runs that suite
            // against a non-groupcast app variant.
            "TC_GC_2_1" | "TC_GC_2_2" | "TC_GC_2_3" | "TC_GC_2_4" | "TC_GC_2_5" | "TC_GC_2_6"
            | "TC_GC_2_7" | "TC_GC_2_8" | "TC_ACE_1_6" => Some("--groupcast"),
            // TC_TestEventTrigger validates `GeneralDiagnostics::TestEventTrigger`
            // key/trigger handling — needs the canonical CHIP enable-key
            // 000102030405060708090a0b0c0d0e0f plumbed through to the device's
            // `GenDiag::test_event_trigger` impl. The system_tests app
            // accepts `--enable-key <hex32>` (see `parse_enable_key_override`
            // in that binary) and wires it into a `TestEventTriggerDiag`
            // wrapper around `()` that flips `TestEventTriggersEnabled` to
            // true and validates the key/trigger per spec §11.12.7.1.
            "TC_TestEventTrigger" => Some("--enable-key 000102030405060708090a0b0c0d0e0f"),
            // The Thread half of the `wireless` suite drives the same
            // `wireless_tests` binary in its Thread flavour; the Wi-Fi tests
            // take the default. The two network stores are distinct types, so
            // the binary picks one at startup rather than switching later.
            // Only for that target: the same test names in the `thread` suite
            // drive `thread_tests`, which has no flavour switch.
            "TC_CNET_4_2" | "TC_CNET_4_10" | "TC_CNET_4_16" | "TC_CNET_4_22"
                if target == "wireless_tests" =>
            {
                Some("--thread")
            }
            // TC_DGSW_2_2 triggers a `SoftwareFault` event via
            // `GeneralDiagnostics::TestEventTrigger` (trigger code
            // 0x0034000000000000, Matter spec §11.13.7). The Python helper
            // `send_test_event_triggers` defaults `enableKey` to the canonical
            // sequence below — wire the same value into the DUT so the
            // key check in `TestEventTriggerDiag::test_event_trigger` accepts.
            "TC_DGSW_2_2" => Some("--enable-key 000102030405060708090a0b0c0d0e0f"),
            // TC_ICDM_3_1 drives the ICD registration flow but first sends the
            // `kAddActiveModeReq` / `kRemoveActiveModeReq` ICD triggers via
            // `GeneralDiagnostics::TestEventTrigger`. It defaults `enableKey` to
            // the canonical sequence, so wire the same value into the DUT.
            "TC_ICDM_3_1" => Some("--enable-key 000102030405060708090a0b0c0d0e0f"),
            // TC_ICDManagementCluster invalidates the ICD Check-In counter via
            // `GeneralDiagnostics::TestEventTrigger` with the canonical enable
            // key; wire the same value into the DUT.
            "TC_ICDManagementCluster" => Some("--enable-key 000102030405060708090a0b0c0d0e0f"),
            _ => None,
        }
    }

    /// Test-specific extra `--script-args` for `run_python_test.py`.
    ///
    /// Some `MatterBaseTest`-style scripts require PIXIT/PICS values supplied
    /// on the command line via the `--int-arg`, `--string-arg`, `--hex-arg`
    /// flags. Map them here per test, keyed by file stem, so the rest of the
    /// dispatch path stays uniform.
    fn extra_python_script_args(test_name: &str, target: &str) -> String {
        // Thread-suite only (`THREAD_TESTS`). The first dataset reaches
        // `matter_test_config.thread_operational_dataset` via
        // `--thread-dataset-hex` — kept by the framework because
        // `--in-test-commissioning-method` is a wireless one, exactly as for
        // `TC_CNET_4_9`/`4_10` below; commissioning itself is still
        // on-network. The second dataset is read with `user_params.get()`
        // followed by `bytes.fromhex()`, so it must arrive as a hex *string*
        // (`--string-arg`, not `--hex-arg`). Composed at runtime from the
        // dataset consts — the only entry that cannot be a `'static` literal.
        // Against the real-otbr `thread_tests` driver, the Thread CNET tests
        // are handed the suite's REAL dataset; the mock xpan-only TLV in the
        // static arm below belongs to `MockNetCtl`'s canned network and is
        // what the same tests receive in the `wireless` suite.
        if target == THREAD_TARGET && matches!(test_name, "TC_CNET_4_10" | "TC_CNET_4_16") {
            return format!(
                "--endpoint 0 --in-test-commissioning-method ble-thread \
                 --thread-dataset-hex {THREAD_DATASET_1}"
            );
        }

        if test_name == "TC_CNET_4_12" {
            return format!(
                "--endpoint 0 --in-test-commissioning-method ble-thread \
                 --thread-dataset-hex {THREAD_DATASET_1} \
                 --string-arg PIXIT.CNET.THREAD_2ND_OPERATIONALDATASET:{THREAD_DATASET_2}"
            );
        }

        let args: &'static str = match test_name {
            // TC_ACE_1_4 needs the PIXITs that point at the application
            // endpoint/cluster/attribute exposed by `system_tests`. Endpoint 1
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
            // These ICDM tests read/write the AccessControl cluster (to drop the
            // TH to Manage privilege) via `get_endpoint()`, which defaults to the
            // `--endpoint 1` we pass for application tests. AccessControl lives on
            // the root endpoint, so pin the default there. The ICDM helpers
            // themselves already target endpoint 0 explicitly.
            "TC_ICDM_3_2" | "TC_ICDM_3_3" | "TC_ICDM_3_4" => "--endpoint 0",
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
            // The wireless Network Commissioning tests read the network they
            // expect the DUT to be provisioned with out of the commissioning
            // arguments, even when - as here - the node was commissioned
            // on-network. The values have to match what `wireless_tests` seeds
            // itself with; see `MOCK_WIFI_SSID` / `MOCK_THREAD_DATASET` in
            // `tests/src/common/mock_net_ctl.rs`.
            //
            // `--in-test-commissioning-method` is what makes the framework keep
            // them: it copies the Wi-Fi / Thread credentials into the test
            // config only when the commissioning method is a wireless one
            // (`runner.py`, `commissioning_method = args.in_test_commissioning_method
            // or args.commissioning_method`), otherwise they are parsed and
            // dropped. It does not change how the node is actually commissioned
            // - `--commissioning-method on-network` still governs that.
            "TC_CNET_4_9" => {
                "--endpoint 0 --in-test-commissioning-method ble-wifi \
                 --wifi-ssid MatterAP --wifi-passphrase MatterAPPassword"
            }
            // `0208` is the Extended PAN ID TLV header (type 2, length 8),
            // followed by the mock network's Extended PAN ID.
            "TC_CNET_4_10" | "TC_CNET_4_16" => {
                "--endpoint 0 --in-test-commissioning-method ble-thread \
                 --thread-dataset-hex 0208123456789abcdef0"
            }
            // Gates on `MCORE.ROLE.COMMISSIONEE` + `G.S`; `--endpoint 1` is
            // `PIXIT.G.ENDPOINT` (the default script args already carry it).
            "TC_ACE_1_6" => "--PICS src/app/tests/suites/certification/ci-pics-values",
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
            // `test_TC_IDM_10_5` flags every server cluster that is not part of
            // some device type declared on its endpoint. `system_tests` hosts
            // `Groups` on EP0 so `TestGroupMessaging` can group-address writes
            // to `BasicInformation::NodeLabel` (group membership is
            // per-endpoint, per App Cluster spec 1.3), and no device type grants
            // `Groups` on a root node - so this cannot be resolved by declaring
            // more device types, the way the OTA clusters were.
            //
            // Matter Core spec 7.16.4 permits extra clusters on an endpoint;
            // the checker is strict by default and parameterised for exactly
            // this case. CHIP's own `all-clusters-app` is in the same position
            // (its EP0 declares only `ma_rootdevice` + `ma_powersource`, yet
            // hosts `Groups`), which is why upstream provides the knob. With it
            // off, such findings are recorded as warnings rather than errors.
            "TC_DeviceConformance" => "--bool-arg fail_on_extra_clusters:false",
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
            // IDM_2_3 batch-reads `BasicInformation` et al on the root endpoint;
            // CADMIN_1_10 reads `SpecificationVersion` there.
            | "TC_IDM_2_3"
            | "TC_CADMIN_1_10"
            // CNET (Network Commissioning) is served on the root endpoint;
            // the `@run_if_endpoint_matches(has_feature(...))` gates on these
            // find the Ethernet / Wi-Fi / Thread feature only there, and would
            // otherwise skip (which `--fail-on-skipped` turns into a failure).
            | "TC_CNET_4_3"
            | "TC_CNET_4_1"
            | "TC_CNET_4_2"
            | "TC_CNET_4_4"
            | "TC_CNET_4_15"
            | "TC_CNET_4_22"
            // DGGEN (General Diagnostics) lives on the root endpoint.
            | "TC_DGGEN_2_4"
            | "TC_DGGEN_2_5"
            | "TC_DGGEN_3_2"
            // BINFO (Basic Information) lives on the root endpoint.
            | "TC_BINFO_2_1"
            | "TC_BINFO_2_2"
            | "TC_BINFO_3_1"
            // PS (Power Source) is hosted on the root endpoint.
            | "TC_PS_2_3"
            // DGSW (Software Diagnostics) lives on the root endpoint
            // — `@run_if_endpoint_matches(has_cluster(SoftwareDiagnostics))`
            // skips unless we point the runner at EP0.
            | "TC_DGSW_2_1"
            | "TC_DGSW_2_2"
            // TIMESYNC (Time Synchronization) lives on the root endpoint
            // — `@run_if_endpoint_matches(has_cluster(TimeSynchronization))`
            // skips unless we point the runner at EP0.
            | "TC_TIMESYNC_2_1"
            | "TC_TIMESYNC_2_2"
            | "TC_TIMESYNC_2_4"
            | "TC_TIMESYNC_2_5"
            | "TC_TIMESYNC_2_6"
            | "TC_TIMESYNC_2_7"
            | "TC_TIMESYNC_2_8"
            | "TC_TIMESYNC_2_9"
            | "TC_TIMESYNC_2_10"
            | "TC_TIMESYNC_2_11"
            | "TC_TIMESYNC_2_12"
            | "TC_TIMESYNC_2_13"
            | "TC_TIMESYNC_3_1"
            | "TC_TestEventTrigger" => "--endpoint 0",
            // TC_G_2_2 sends Groups commands against
            // `self.matter_test_config.endpoint` (e.g. lines 125/133/172/197)
            // while `GroupKeyManagement` reads stay hard-coded at EP0.
            // `system_tests` no longer advertises Groups at the root
            // endpoint (Matter Core spec §9.11 — Root Node device type
            // doesn't list Groups, see the comment on `NODE` in
            // `system_tests.rs`); Groups now lives on EP1/EP2 under the
            // On/Off Light device type, so target EP1.
            "TC_G_2_2" => "--endpoint 1",
            // The Groupcast cluster lives on the root endpoint.
            "TC_GC_2_1" | "TC_GC_2_2" | "TC_GC_2_3" | "TC_GC_2_4" | "TC_GC_2_5" | "TC_GC_2_6"
            | "TC_GC_2_7" | "TC_GC_2_8" => "--endpoint 0",
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
            // operator to commission the DUT_Commissioner from system_tests
            // (which doesn't act as a commissioner).
            "TC_SC_3_5" => "--PICS src/app/tests/suites/certification/ci-pics-values",
            // TC_DA_1_9 ("device attestation: revocation [DUT-Commissioner]")
            // is a commissioner-side test: it spawns `chip-all-clusters-app`
            // with a series of revoked DAC/PAI configurations and uses the
            // *test framework's* `ChipDeviceCtrl.CommissionWithCode` to verify
            // that revoked credentials are rejected. The system_tests app
            // we launch is sidelined (the framework drives the controller
            // directly), but we still need to point the test at the cached
            // chip output from `cargo xtask itest-setup` and bump its
            // per-test timeout (default 90 s) past the seven 30-s commission
            // attempts the test performs.
            // The `app_path` pointing at that binary is appended separately (see
            // `needs_all_clusters_app_arg`), since only that path is resolved
            // against the chip output tree rather than being a fixed literal.
            "TC_DA_1_9" => {
                "--PICS src/app/tests/suites/certification/ci-pics-values \
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
        };

        args.to_string()
    }

    fn build_test_exe<'a>(
        &self,
        profile: &str,
        target: &str,
        additional_features: impl IntoIterator<Item = &'a String>,
        force_rebuild: bool,
    ) -> anyhow::Result<()> {
        warn!("Building test executable `{target}`...");

        let test_exe_crate_dir = self.workspace_dir.join(TEST_CRATE_DIR);

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

    fn test_pics_path(&self, test_name: &str, target: &str) -> PathBuf {
        // The Wi-Fi/Thread flavour split (and its per-flavour `.pics`) is a
        // `wireless_tests` concept; the same test names running against
        // another target (e.g. `Test_TC_DGTHREAD_2_1` in the `thread` suite)
        // use that target's own `.pics`.
        let target = if target == "wireless_tests" {
            WirelessFlavour::of(test_name)
                .map(|flavour| flavour.pics_target())
                .unwrap_or(target)
        } else {
            target
        };

        self.workspace_dir
            .join(TEST_CRATE_DIR)
            .join("src")
            .join("bin")
            .join(format!("{target}.pics"))
    }
}
