/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! A node boots over a store whose every value cannot be decoded - e.g. one
//! written in the formats of another firmware - starting with defaults instead,
//! and over a store that cannot be written to.

#![cfg(all(feature = "std", feature = "async-io"))]

use rs_matter::crypto::{test_only_crypto, Crypto};
use rs_matter::dm::clusters::app::color_control::{
    self, test::TestColorControlDeviceLogic, ColorControlHooks as _,
};
use rs_matter::dm::clusters::app::fan_control::{
    self, test::TestFanDeviceLogic, FanControlHooks as _,
};
use rs_matter::dm::clusters::app::level_control::{
    self, test::TestLevelControlDeviceLogic, LevelControlHooks as _,
};
use rs_matter::dm::clusters::app::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks as _};
use rs_matter::dm::clusters::app::thermostat::{
    self, test::TestThermostatDeviceLogic, ThermostatHooks as _,
};
use rs_matter::dm::clusters::binding::{self, BindingHandler, Bindings};
use rs_matter::dm::clusters::decl::scenes_management::FULL_CLUSTER as SCENES_CLUSTER;
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::icd_mgmt::{IcdModeConfig, LitIcd, LitIcdMgmtHandler};
use rs_matter::dm::clusters::mode::{
    laundry_washer_mode, Mode, ModeChangeError, ModeHandler, ModeHooks, ModeId, ModeTag,
};
use rs_matter::dm::clusters::mode_select::{self, ModeSelectHandler, ModeSelectHooks, SemanticTag};
use rs_matter::dm::clusters::net_comm;
use rs_matter::dm::clusters::ota_req::{
    ClusterHandler as _, OtaRequestorHandler, OtaState, Providers,
};
use rs_matter::dm::clusters::scenes::{ScenesHandler, ScenesState};
use rs_matter::dm::clusters::time_sync::{
    self, ClusterHandler as _, TimeSyncHandler, TimeZoneStore,
};
use rs_matter::dm::clusters::user_label::{self, UserLabelHandler, UserLabels};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE};
use rs_matter::dm::endpoints::{self, ROOT_ENDPOINT_ID};
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::networks::wireless::WifiNetworks;
use rs_matter::dm::{Async, Cluster, Dataver, Endpoint, Node};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::im::{InteractionModel, InteractionModelState};
use rs_matter::persist::{KvBlobStore, KvBlobStoreAccess, NETWORKS_KEY, VENDOR_KEYS_START};
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::{clusters, devices, Matter};

use crate::common::{init_env_logger, MemKvBlobStore};

#[allow(dead_code)]
mod common;

const ENDPOINT: u16 = 1;

const ON_OFF_KEY: u16 = VENDOR_KEYS_START;
const LEVEL_KEY: u16 = VENDOR_KEYS_START + 1;
const COLOR_KEY: u16 = VENDOR_KEYS_START + 2;
const THERMOSTAT_KEY: u16 = VENDOR_KEYS_START + 3;
const FAN_KEY: u16 = VENDOR_KEYS_START + 4;
const MODE_KEY: u16 = VENDOR_KEYS_START + 5;
const MODE_SELECT_KEY: u16 = VENDOR_KEYS_START + 6;

/// Past every key above.
const KEYS_END: u16 = VENDOR_KEYS_START + 0x10;

const ICD_MODE: IcdModeConfig = IcdModeConfig {
    idle_mode_duration_s: 3600,
    active_mode_duration_ms: 10000,
    active_mode_threshold_ms: 5000,
    user_active_mode_trigger_hint: 0,
    user_active_mode_trigger_instruction: "",
};

const NODE: Node<'static> = Node {
    endpoints: &[
        Endpoint::new(
            ROOT_ENDPOINT_ID,
            devices!(DEV_TYPE_ROOT_NODE),
            clusters!(
                eth,
                time_sync(time_zone);
                user_label::CLUSTER,
                binding::CLUSTER,
                OtaRequestorHandler::CLUSTER,
                LitIcdMgmtHandler::CLUSTER_DSLS
            ),
        ),
        Endpoint::new(
            ENDPOINT,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(
                desc::DescHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                TestLevelControlDeviceLogic::CLUSTER,
                TestColorControlDeviceLogic::CLUSTER,
                TestThermostatDeviceLogic::CLUSTER,
                TestFanDeviceLogic::CLUSTER,
                WasherModes::CLUSTER,
                Patterns::CLUSTER,
                SCENES_CLUSTER,
            ),
        ),
    ],
};

const WASHER_MODES: &[Mode<laundry_washer_mode::ModeTag>] = &[
    Mode::new(
        0,
        "Normal",
        &[ModeTag::Standard(laundry_washer_mode::ModeTag::Normal)],
    ),
    Mode::new(
        1,
        "Delicate",
        &[ModeTag::Standard(laundry_washer_mode::ModeTag::Delicate)],
    ),
];

struct WasherModes;

impl ModeHooks for WasherModes {
    const CLUSTER: Cluster<'static> = laundry_washer_mode::CLUSTER;

    type ModeTag = laundry_washer_mode::ModeTag;

    fn supported_modes(&self) -> &[Mode<'_, Self::ModeTag>] {
        WASHER_MODES
    }

    fn change_to_mode(&self, _mode: ModeId) -> Result<(), ModeChangeError> {
        Ok(())
    }
}

const PATTERNS: &[mode_select::Mode] = &[
    mode_select::Mode::new(0, "Steady", &[SemanticTag::new(0xFFF1, 0x8000)]),
    mode_select::Mode::new(1, "Blink", &[SemanticTag::new(0xFFF1, 0x8001)]),
];

struct Patterns;

impl ModeSelectHooks for Patterns {
    const CLUSTER: Cluster<'static> = mode_select::CLUSTER;

    fn description(&self) -> &str {
        "Patterns"
    }

    fn supported_modes(&self) -> &[mode_select::Mode<'_>] {
        PATTERNS
    }

    fn change_to_mode(&self, _mode: mode_select::ModeId) -> Result<(), Error> {
        Ok(())
    }
}

/// A store whose every write and removal fails.
struct ReadOnlyStore(MemKvBlobStore);

impl KvBlobStore for ReadOnlyStore {
    fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        self.0.load(key, buf)
    }

    fn store(&mut self, _key: u16, _data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
        Err(ErrorCode::StdIoError.into())
    }

    fn remove(&mut self, _key: u16, _buf: &mut [u8]) -> Result<(), Error> {
        Err(ErrorCode::StdIoError.into())
    }
}

/// A store with an undecodable value under every key rs-matter and the
/// clusters of [`NODE`] use.
fn unreadable_store() -> MemKvBlobStore {
    let mut store = MemKvBlobStore::default();

    for key in 0..KEYS_END {
        store.store(key, &[0xff], &mut []).unwrap();
    }

    store
}

/// `Matter::startup` and `InteractionModel::startup` succeed over a store none
/// of whose values decode, and the node starts with defaults.
#[test]
fn test_unreadable_persistence_boots() {
    // A data model with this many clusters does not fit the default 2 MiB
    // test-thread stack.
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            init_env_logger();
            futures_lite::future::block_on(run_unreadable_persistence_boots());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn run_unreadable_persistence_boots() {
    let store = unreadable_store();

    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
    let kv = matter.kv(store.clone());

    matter.startup(&kv).unwrap();

    matter.with_state(|state| assert_eq!(state.fabrics.iter().count(), 0));
    assert_eq!(matter.reboot_count(), 1);
    assert_eq!(matter.total_operational_hours(), 0);

    startup_data_model(&matter, &kv).await;

    // The networks of a Wi-Fi or Thread node, whose handler needs a network
    // controller and is therefore not part of `NODE`.
    let mut networks = WifiNetworks::<2>::new();
    net_comm::load_networks(&mut networks, NETWORKS_KEY, &kv).unwrap();

    let mut count = 0;
    networks
        .networks(|_| {
            count += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(count, 0);

    // The unreadable record does not stick: the next boot counts from this one.
    matter.persist_reboot_count(&kv).unwrap();

    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
    matter.startup(matter.kv(store)).unwrap();

    assert_eq!(matter.reboot_count(), 2);
}

/// `Matter::startup` and `InteractionModel::startup` succeed over a store none
/// of whose values decode and that refuses every write and removal.
#[test]
fn test_failing_writes_boot() {
    // See `test_unreadable_persistence_boots`
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            init_env_logger();
            futures_lite::future::block_on(run_failing_writes_boot());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn run_failing_writes_boot() {
    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
    let kv = matter.kv(ReadOnlyStore(unreadable_store()));

    matter.startup(&kv).unwrap();

    startup_data_model(&matter, &kv).await;
}

/// Run `InteractionModel::startup` over the clusters of [`NODE`], asserting it
/// succeeds.
async fn startup_data_model<K: KvBlobStoreAccess>(matter: &Matter<'_>, kv: K) {
    let crypto = test_only_crypto();
    let mut rand = crypto.rand().unwrap();

    let user_labels = UserLabels::<1>::new();
    let bindings = Bindings::<4>::new();
    let time_zone_store = TimeZoneStore::new();
    let time_sync =
        TimeSyncHandler::new_with_time_zone(Dataver::new_rand(&mut rand), matter, &time_zone_store);
    let ota_providers = Providers::new();
    let ota_state = OtaState::new(ROOT_ENDPOINT_ID);
    let icd = LitIcd::new(100, ICD_MODE, 5000);
    let scenes_state = ScenesState::<4>::new();

    let on_off = on_off::OnOffHandler::new(
        Dataver::new_rand(&mut rand),
        ENDPOINT,
        ON_OFF_KEY,
        TestOnOffDeviceLogic::new(false),
    );
    let level = level_control::LevelControlHandler::new(
        Dataver::new_rand(&mut rand),
        ENDPOINT,
        LEVEL_KEY,
        TestLevelControlDeviceLogic::new(),
    );
    let color = color_control::ColorControlHandler::new(
        Dataver::new_rand(&mut rand),
        ENDPOINT,
        COLOR_KEY,
        TestColorControlDeviceLogic::new(),
    );

    on_off.init(Some(&level));
    level.init(Some(&on_off));
    color.init(Some(&on_off));

    let thermostat = thermostat::ThermostatHandler::new(
        Dataver::new_rand(&mut rand),
        ENDPOINT,
        THERMOSTAT_KEY,
        TestThermostatDeviceLogic::new(),
    );
    let fan = fan_control::FanControlHandler::new(
        Dataver::new_rand(&mut rand),
        ENDPOINT,
        FAN_KEY,
        TestFanDeviceLogic::new(),
    );

    let dm = (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&UnixNetifs)
            .build(matter, rand)
            .chain(
                |e, c| e == ROOT_ENDPOINT_ID && c == TimeSyncHandler::CLUSTER.id,
                Async(time_sync::HandlerAdaptor(&time_sync)),
            )
            .chain(
                |e, c| e == ROOT_ENDPOINT_ID && c == user_label::CLUSTER.id,
                Async(
                    UserLabelHandler::new(
                        Dataver::new_rand(&mut rand),
                        ROOT_ENDPOINT_ID,
                        &user_labels,
                    )
                    .adapt(),
                ),
            )
            .chain(
                |e, c| e == ROOT_ENDPOINT_ID && c == binding::CLUSTER.id,
                Async(
                    BindingHandler::new(Dataver::new_rand(&mut rand), ROOT_ENDPOINT_ID, &bindings)
                        .adapt(),
                ),
            )
            .chain(
                |e, c| e == ROOT_ENDPOINT_ID && c == OtaRequestorHandler::CLUSTER.id,
                Async(
                    OtaRequestorHandler::new(
                        Dataver::new_rand(&mut rand),
                        matter,
                        &ota_providers,
                        &ota_state,
                    )
                    .adapt(),
                ),
            )
            .chain(
                |e, c| e == ROOT_ENDPOINT_ID && c == LitIcdMgmtHandler::CLUSTER_DSLS.id,
                Async(LitIcdMgmtHandler::new(Dataver::new_rand(&mut rand), matter, &icd).adapt()),
            )
            .chain(
                |e, c| e == ENDPOINT && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == ENDPOINT && c == TestOnOffDeviceLogic::CLUSTER.id,
                Async(on_off::HandlerAdaptor(&on_off)),
            )
            .chain(
                |e, c| e == ENDPOINT && c == TestLevelControlDeviceLogic::CLUSTER.id,
                Async(level_control::HandlerAdaptor(&level)),
            )
            .chain(
                |e, c| e == ENDPOINT && c == TestColorControlDeviceLogic::CLUSTER.id,
                Async(color_control::HandlerAdaptor(&color)),
            )
            .chain(
                |e, c| e == ENDPOINT && c == TestThermostatDeviceLogic::CLUSTER.id,
                Async(thermostat::HandlerAdaptor(&thermostat)),
            )
            .chain(
                |e, c| e == ENDPOINT && c == TestFanDeviceLogic::CLUSTER.id,
                Async(fan_control::HandlerAdaptor(&fan)),
            )
            .chain(
                |e, c| e == ENDPOINT && c == WasherModes::CLUSTER.id,
                Async(laundry_washer_mode::HandlerAdaptor(ModeHandler::new(
                    Dataver::new_rand(&mut rand),
                    MODE_KEY,
                    WasherModes,
                ))),
            )
            .chain(
                |e, c| e == ENDPOINT && c == Patterns::CLUSTER.id,
                Async(
                    ModeSelectHandler::new(Dataver::new_rand(&mut rand), MODE_SELECT_KEY, Patterns)
                        .adapt(),
                ),
            )
            .chain(
                |e, c| e == ENDPOINT && c == SCENES_CLUSTER.id,
                ScenesHandler::new(Dataver::new_rand(&mut rand), matter, &scenes_state, ()).adapt(),
            ),
    );

    let buffers: MatterBuffers = MatterBuffers::new();
    let state: InteractionModelState = InteractionModelState::new();

    let im = InteractionModel::new(matter, &crypto, &buffers, dm, kv, &state);

    im.startup().await.unwrap();
}
