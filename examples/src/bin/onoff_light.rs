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

//! An example Matter device that implements the On/Off Light cluster over Ethernet.
//!
//! Endpoint 1 also carries a `ModeSelect` instance as an *extra* cluster - the
//! endpoint keeps On/Off Light as its single Application device type, since
//! Core spec 9.2.1 allows only one per Simple endpoint and Mode Select
//! (`0x0027`) is itself an application type. This mirrors CHIP's
//! `all-clusters-app`, which likewise carries ModeSelect on its On/Off Light
//! endpoint without declaring the Mode Select device type. It demonstrates the generic
//! "pick one of N vendor-defined options" cluster: it chooses the light's
//! pattern. Because the same endpoint hosts On/Off, it also demonstrates the
//! `ON_OFF` (`DEPONOFF`) feature - switching the light on snaps the pattern
//! back to `OnMode`, its power-on default.

use core::pin::pin;

use log::info;

use rand::rngs::StdRng;

use rand::Rng;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::{
    self, test::TestOnOffDeviceLogic, NoLevelControl, OnOffHooks,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::mode_select::{
    self, Mode, ModeId, ModeSelectHandler, ModeSelectHooks, SemanticTag,
};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, Cluster, DataModel, Dataver, EmptyHandler, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::persist::DirKvBlobStore;
use rs_matter::tlv::Nullable;
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::sync::blocking::Mutex;
use rs_matter::{clusters, devices, root_endpoint, with, Matter};

use rs_matter::stack::eth::EthMatterStack;
use rs_matter::stack::net::std::StdNetStack;
use rs_matter::utils::init::InitMaybeUninit;

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

/// The vendor ID whose namespace our semantic tags live in. `TEST_DEV_DET`
/// commissions as vendor `0xFFF1` (the CSA test vendor).
const TEST_VENDOR: u16 = 0xFFF1;

/// Our own semantic tag values. Manufacturer specific tags live in
/// `0x8000..=0xBFFF`; within that range the meaning is ours to define.
const TAG_STEADY: u16 = 0x8000;
const TAG_BLINK: u16 = 0x8001;
const TAG_PULSE: u16 = 0x8002;

/// The light patterns this device can be set to.
///
/// `ModeSelect` has no standard vocabulary for "light pattern", which is
/// exactly when it is the right cluster to reach for: the purpose is carried
/// by the `Description` string and the tags are ours. A Mode Base derived
/// cluster would need a cluster ID the spec does not define for this.
///
/// Mode `4` is deliberately present because CHIP's `Test_TC_MOD_2_1` defaults
/// its `NewMode` argument to 4.
const LIGHT_PATTERNS: &[Mode] = &[
    Mode::new(0, "Steady", &[SemanticTag::new(TEST_VENDOR, TAG_STEADY)]),
    Mode::new(4, "Blink", &[SemanticTag::new(TEST_VENDOR, TAG_BLINK)]),
    Mode::new(7, "Pulse", &[SemanticTag::new(TEST_VENDOR, TAG_PULSE)]),
];

/// Device logic behind the `ModeSelect` instance on endpoint 1.
///
/// The handler owns and persists `CurrentMode`, `StartUpMode` and `OnMode`;
/// this logic would drive the LED from `change_to_mode`, and just logs.
struct LightPatternLogic {
    state: Mutex<RefCell<LightPatternState>>,
}

struct LightPatternState {
    current: ModeId,
}

impl LightPatternLogic {
    const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(LightPatternState { current: 0 })),
        }
    }
}

impl ModeSelectHooks for LightPatternLogic {
    // `StartUpMode` and `OnMode` are optional, and `OnMode` is what the
    // `ON_OFF` feature adds - so both must be opted into explicitly.
    const CLUSTER: Cluster<'static> = mode_select::FULL_CLUSTER
        .with_features(mode_select::Feature::ON_OFF.bits())
        .with_attrs(with!(
            required;
            mode_select::AttributeId::StartUpMode | mode_select::AttributeId::OnMode
        ));

    // Come up blinking after a power cycle...
    const START_UP_MODE: Option<ModeId> = Some(4);

    // ...but snap to steady whenever the light is switched on.
    const ON_MODE: Option<ModeId> = Some(0);

    fn description(&self) -> &str {
        "Light pattern"
    }

    // Null: our tags are all manufacturer specific, so there is no standard
    // namespace to point at.
    fn standard_namespace(&self) -> Nullable<u16> {
        Nullable::none()
    }

    fn supported_modes(&self) -> &[Mode<'_>] {
        LIGHT_PATTERNS
    }

    fn change_to_mode(&self, mode: ModeId) -> Result<(), Error> {
        info!("Light pattern -> {mode}");

        // A real device drives its LED here; the handler owns and persists
        // `CurrentMode`.
        self.state.lock(|s| s.borrow_mut().current = mode);

        Ok(())
    }
}

/// The bump allocator size of the stack, in bytes.
///
/// If it is not enough, the stack panics while it starts. The futures of an
/// unoptimized build are much bigger than those of an optimized one.
const BUMP_SIZE: usize = 32 * 1024;

/// The stack is allocated statically to avoid program stack blowups.
static MATTER_STACK: StaticCell<EthMatterStack<BUMP_SIZE, ()>> = StaticCell::new();

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let stack = MATTER_STACK.uninit().init_with(EthMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));

    // Persistence
    let mut store = DirKvBlobStore::new_default();

    // Create the crypto instance
    // `rand::rng()` is not `Send`
    let crypto = default_crypto(rand::make_rng::<StdRng>(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // Re-hydrate the persisted state. If the device is not commissioned yet, this also
    // prints the QR text and code to the console and enables basic commissioning.
    futures_lite::future::block_on(stack.startup(&crypto, &mut store))?;

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = stack.kv(store);

    // Our mode-select cluster, choosing the light's pattern
    let mode_select_handler = ModeSelectHandler::new(
        Dataver::new_rand(&mut rand),
        rs_matter::persist::VENDOR_KEYS_START + 0x11,
        LightPatternLogic::new(),
    );

    // Our on-off cluster, coupled to the mode-select one so that switching the
    // light on applies `OnMode` (the ModeSelect `ON_OFF` feature). This is the
    // long form of `new_standalone`, so the coupling can be attached before
    // `init`.
    let on_off_handler = on_off::OnOffHandler::<_, NoLevelControl>::new(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x10,
        TestOnOffDeviceLogic::new(true),
    )
    .with_on_mode_applier(&mode_select_handler);

    on_off_handler.init(None);

    // Run the stack, which adds the operational network clusters of endpoint 0 by itself
    let matter = pin!(stack.run_preex(
        // The UDP sockets of the node
        StdNetStack::new(),
        // The network interfaces of the host
        SysNetifs,
        // No Ethernet diagnostics to report
        &(),
        mdns::create_mdns(),
        &crypto,
        data_model(stack.matter(), rand, &on_off_handler, &mode_select_handler),
        kv,
        // No user task to run
        (),
    ));

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(matter)
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                LightPatternLogic::CLUSTER
            ),
        ),
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off handler and its descriptor.
fn data_model<'a, OH: OnOffHooks, LH: LevelControlHooks, MH: ModeSelectHooks>(
    matter: &'a Matter<'a>,
    mut rand: impl Rng + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
    mode_select: &'a ModeSelectHandler<MH>,
) -> impl DataModel + 'a {
    (
        NODE,
        EmptyHandler
            .chain(
                |e, _| e == ROOT_ENDPOINT_ID,
                Async(EthMatterStack::<0, ()>::root_handler(matter, &(), rand)),
            )
            .chain(
                |e, c| e == 1 && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == groups::GroupsHandler::CLUSTER.id,
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand), matter).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == TestOnOffDeviceLogic::CLUSTER.id,
                Async(on_off::HandlerAdaptor(on_off)),
            )
            .chain(
                |e, c| e == 1 && c == LightPatternLogic::CLUSTER.id,
                Async(mode_select::HandlerAdaptor(mode_select)),
            ),
    )
}
