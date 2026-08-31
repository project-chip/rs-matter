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
//! Endpoint 1 also carries a `ModeSelect` instance, demonstrating the generic
//! "pick one of N vendor-defined options" cluster: it chooses the light's
//! pattern. Because the same endpoint hosts On/Off, it also demonstrates the
//! `ON_OFF` (`DEPONOFF`) feature - switching the light on snaps the pattern
//! back to `OnMode`, its power-on default.

use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::select4;

use log::info;

use rand::RngCore;

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
use rs_matter::dm::devices::{DEV_TYPE_MODE_SELECT, DEV_TYPE_ON_OFF_LIGHT};
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, Cluster, DataModel, Dataver, Endpoint, EpClMatcher, Node};
use rs_matter::error::Error;
use rs_matter::im::{EthInteractionModelState, InteractionModel};
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::DirKvBlobStore;
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::tlv::Nullable;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::sync::blocking::Mutex;
use rs_matter::{clusters, devices, root_endpoint, with, Matter, MATTER_PORT};

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
/// A real device would persist `current`, `start_up` and `on_mode` - all three
/// are non-volatile - and drive the LED from `change_to_mode`. This example
/// keeps them in RAM and just logs.
struct LightPatternLogic {
    state: Mutex<RefCell<LightPatternState>>,
}

struct LightPatternState {
    current: ModeId,
    start_up: Option<ModeId>,
    on_mode: Option<ModeId>,
}

impl LightPatternLogic {
    const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(LightPatternState {
                current: 0,
                // Come up blinking after a power cycle...
                start_up: Some(4),
                // ...but snap to steady whenever the light is switched on.
                on_mode: Some(0),
            })),
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

    fn current_mode(&self) -> ModeId {
        self.state.lock(|s| s.borrow().current)
    }

    fn change_to_mode(&self, mode: ModeId) -> Result<(), Error> {
        info!("Light pattern -> {mode}");

        // A real device drives its LED here. `CurrentMode` is non-volatile, so
        // this is also where it would be persisted.
        self.state.lock(|s| s.borrow_mut().current = mode);

        Ok(())
    }

    fn start_up_mode(&self) -> Nullable<ModeId> {
        Nullable::new(self.state.lock(|s| s.borrow().start_up))
    }

    fn set_start_up_mode(&self, value: Nullable<ModeId>) -> Result<(), Error> {
        self.state
            .lock(|s| s.borrow_mut().start_up = value.into_option());

        Ok(())
    }

    fn on_mode(&self) -> Nullable<ModeId> {
        Nullable::new(self.state.lock(|s| s.borrow().on_mode))
    }

    fn set_on_mode(&self, value: Nullable<ModeId>) -> Result<(), Error> {
        self.state
            .lock(|s| s.borrow_mut().on_mode = value.into_option());

        Ok(())
    }
}

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    // Persistence
    let store = DirKvBlobStore::new_default();

    // Create the transport buffers
    let buffers: MatterBuffers = MatterBuffers::new();

    // Create the data model state (subscriptions table, events queue, network
    // store).
    let state: EthInteractionModelState = EthInteractionModelState::new(EthNetwork::new_default());

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = matter.kv(store);

    // Re-hydrate the `Matter` instance (fabrics, ACLs, basic info).
    matter.startup(&kv)?;

    // Create the crypto instance
    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // Our mode-select cluster, choosing the light's pattern
    let mode_select_handler =
        ModeSelectHandler::new(Dataver::new_rand(&mut rand), LightPatternLogic::new());

    // Our on-off cluster, coupled to the mode-select one so that switching the
    // light on applies `OnMode` (the ModeSelect `ON_OFF` feature). This is the
    // long form of `new_standalone`, so the coupling can be attached before
    // `init`.
    let on_off_handler = on_off::OnOffHandler::<_, NoLevelControl>::new(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(true),
    )
    .with_on_mode_applier(&mode_select_handler);

    on_off_handler.init(None);

    // Create the Data Model instance
    let im = InteractionModel::new(
        &matter,
        &crypto,
        &buffers,
        data_model(rand, &on_off_handler, &mode_select_handler),
        &kv,
        &state,
    );

    // Bring the Data Model to its operational state: re-hydrate its persisted
    // state and deliver the `Startup` lifecycle op to all cluster handlers.
    futures_lite::future::block_on(im.startup())?;

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&im);

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    let mut respond = pin!(responder.run::<4, 4>());

    // Run the background job of the data model
    let mut im_job = pin!(im.run());

    // Create, load and run the persister
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(&matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket, &socket));

    if !matter.has_fabrics() {
        // If the device is not commissioned yet, print the QR text and code to the console
        // and enable basic commissioning

        matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;
    }

    // Combine all async tasks in a single one
    let all = select4(&mut transport, &mut mdns, &mut respond, &mut im_job).coalesce();

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all)
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_MODE_SELECT),
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
    mut rand: impl RngCore + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
    mode_select: &'a ModeSelectHandler<MH>,
) -> impl DataModel + 'a {
    (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&SysNetifs)
            .build(rand)
            .chain(
                EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(groups::GroupsHandler::CLUSTER.id)),
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                on_off::HandlerAsyncAdaptor(on_off),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(LightPatternLogic::CLUSTER.id)),
                Async(mode_select::HandlerAdaptor(mode_select)),
            ),
    )
}
