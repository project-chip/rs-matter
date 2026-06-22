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

//! An example Matter **On/Off Light Switch** device over Ethernet.
//!
//! Unlike `onoff_light` (which *serves* the OnOff cluster), this device is a
//! *controller*: it has OnOff in its **client** list and a **Binding** cluster
//! (its address book). A commissioner writes the Binding attribute to point this
//! switch at one or more On/Off lights (`(node, endpoint)` targets on the same
//! fabric). The example's switch task then periodically reads its bindings and
//! sends an `OnOff::Toggle` to each bound light.
//!
//! Sending a command to a remote node exercises the **operational discovery
//! (resolve)** path: with no existing CASE session, `Exchange::initiate` resolves
//! `<compressed-fabric-id>-<node-id>._matter._tcp` over mDNS, establishes CASE,
//! and then invokes — so this example is a way to exercise the resolve path of
//! whichever mDNS responder is running (here, the built-in one).
//!
//! Try it with the `onoff_light` example running as the bound light on the same
//! fabric; bind this switch to it via your controller, and watch the light
//! toggle every few seconds.

use core::num::NonZeroU8;
use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::{select, select4};

use futures_lite::io::{AsyncBufReadExt, BufReader};

use log::{info, warn};

use rand::RngCore;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::on_off;
use rs_matter::dm::clusters::binding::{self, BindingHandler, Bindings};
use rs_matter::dm::clusters::decl::switch::{
    self, ClusterHandler as _, Feature as SwitchFeature, InitialPress, ShortRelease,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_GENERIC_SWITCH, DEV_TYPE_ON_OFF_LIGHT_SWITCH};
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, DataModel, Dataver, Endpoint, EpClMatcher, EventEmitter, Node};
use rs_matter::error::Error;
use rs_matter::im::{EthInteractionModelState, InteractionModel};
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{DirKvBlobStore, KvBlobStoreAccess};
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::select::Coalesce;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

// `OnOffClient` brings the `.on_off()` IM-client method into scope on `Exchange`.
use rs_matter::dm::clusters::app::on_off::OnOffClient as _;

#[path = "../common/mdns.rs"]
mod mdns;

/// The local endpoint that hosts the binding-based switch (OnOff client +
/// Binding) — drives bound lights directly via `Exchange::initiate`.
const SWITCH_ENDPOINT: u16 = 1;

/// The local endpoint that hosts the events-based Generic Switch (`Switch`
/// server cluster) — emits press events that ecosystems surface as automation
/// triggers.
const GENERIC_SWITCH_ENDPOINT: u16 = 2;

/// How many binding entries the device can hold (across all fabrics/endpoints).
const MAX_BINDINGS: usize = 16;

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    // Persistence
    let store = DirKvBlobStore::new_default();

    let buffers: MatterBuffers = MatterBuffers::new();

    // Create the data model state. This device EMITS events (the Generic Switch
    // press events), so - unlike the examples that use `NoEvents` - the default
    // state carries a real (non-zero) event queue that holds them until
    // subscribers read them.
    let mut state: EthInteractionModelState =
        EthInteractionModelState::new(EthNetwork::new_default());

    // The Binding registry (the switch's address book), loaded from persistence.
    let bindings = Bindings::<MAX_BINDINGS>::new();

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = matter.kv(store);

    // Re-hydrate persisted state.
    futures_lite::future::block_on(matter.load_persist(&kv))?;
    kv.access(|store, buf| futures_lite::future::block_on(bindings.load_persist(store, buf)))?;
    futures_lite::future::block_on(state.load_persist(&kv))?;

    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);
    let rand = crypto.rand()?;

    let im = InteractionModel::new(
        &matter,
        &crypto,
        &buffers,
        data_model(rand, &bindings),
        &kv,
        &state,
    );

    let responder = rs_matter::respond::DefaultResponder::new(&im);
    let mut respond = pin!(responder.run::<4, 4>());

    let mut im_job = pin!(im.run());

    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    let mut mdns = pin!(mdns::run_mdns(&matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket, &socket));

    if !matter.is_commissioned() {
        matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;
        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;
    }

    // The switch task: on each Enter, emit Generic Switch press events and
    // toggle every bound light. `&im` is the `EventEmitter` used to publish the
    // Generic Switch events.
    let mut switch = pin!(run_switch(&matter, &crypto, &bindings, &im));

    // Combine the core Matter tasks, then add the switch task alongside.
    let mut core = pin!(select4(&mut transport, &mut mdns, &mut respond, &mut im_job,).coalesce());

    let all = select(&mut core, &mut switch).coalesce();

    futures_lite::future::block_on(all)
}

/// The switch loop: on every line read from stdin (i.e. each time you press
/// Enter in the console), walk the binding registry and send `OnOff::Toggle` to
/// each unicast `(node, endpoint)` target on [`SWITCH_ENDPOINT`]. Each
/// [`Binding`] carries its own `local_endpoint` and `fab_idx`, so no separate
/// fabric enumeration is needed.
///
/// Driving the toggle by key press (rather than a timer) makes it easy to test
/// against the `onoff_light` example: that device already blinks on its own
/// timer, so a keyboard-triggered switch toggle is unambiguously observable.
async fn run_switch<const N: usize>(
    matter: &Matter<'_>,
    crypto: &impl Crypto,
    bindings: &Bindings<N>,
    emitter: impl EventEmitter,
) -> Result<(), Error> {
    // Async stdin: `blocking::Unblock` moves the blocking `Stdin` onto a thread
    // pool so reads don't stall the executor.
    let mut stdin = BufReader::new(blocking::Unblock::new(std::io::stdin()));
    let mut line = String::new();

    info!("Switch ready: press Enter to (1) emit Generic Switch press events and (2) toggle all bound lights.");

    loop {
        line.clear();
        let n = stdin.read_line(&mut line).await?;
        if n == 0 {
            // EOF on stdin — stop the switch loop.
            info!("stdin closed; switch loop exiting");
            return Ok(());
        }

        info!("Switch: Enter pressed; emitting events and toggling bound lights...");

        // (1) Generic Switch (endpoint 2): emit a full momentary press/release
        // cycle. Ecosystems surface these events as automation triggers.
        // `InitialPress.NewPosition = 1` (pressed), `ShortRelease.PreviousPosition = 1`.
        match InitialPress::emit_for(&emitter, GENERIC_SWITCH_ENDPOINT, |b| {
            b.new_position(1)?.end()
        }) {
            Ok(n) => info!("Generic Switch: emitted InitialPress (event #{n})"),
            Err(e) => warn!("Generic Switch: InitialPress emit failed: {:?}", e),
        }
        match ShortRelease::emit_for(&emitter, GENERIC_SWITCH_ENDPOINT, |b| {
            b.previous_position(1)?.end()
        }) {
            Ok(n) => info!("Generic Switch: emitted ShortRelease (event #{n})"),
            Err(e) => warn!("Generic Switch: ShortRelease emit failed: {:?}", e),
        }

        // (2) Binding-based switch (endpoint 1): drive the bound lights.

        // Iterate by index; `get` clones each entry out (lock released per call)
        // so we can `await` the remote invoke below.
        for i in 0..bindings.len() {
            let Some(binding) = bindings.get(i) else {
                break;
            };

            // Only this switch's endpoint.
            if binding.local_endpoint != SWITCH_ENDPOINT {
                continue;
            }

            // Only unicast OnOff targets (node + endpoint present).
            let (Some(node), Some(endpoint)) = (binding.node, binding.endpoint) else {
                continue;
            };

            // If a specific cluster is bound, it must be OnOff.
            if let Some(cluster) = binding.cluster {
                if cluster != on_off::FULL_CLUSTER.id {
                    continue;
                }
            }

            info!(
                "Switch: toggling fabric {}, node 0x{:016X}, endpoint {}",
                binding.fab_idx, node, endpoint
            );

            // Resolve (if needed) + CASE + invoke `OnOff::Toggle`.
            match toggle(matter, crypto, binding.fab_idx, node, endpoint).await {
                Ok(()) => info!("Switch: toggle ok"),
                Err(e) => warn!("Switch: toggle failed: {:?}", e),
            }
        }
    }
}

/// Open (or reuse) a CASE session to `(fab_idx, node)` and send `OnOff::Toggle`
/// to `endpoint`. `Exchange::initiate` performs the operational mDNS resolve when
/// no session exists yet.
async fn toggle(
    matter: &Matter<'_>,
    crypto: &impl Crypto,
    fab_idx: NonZeroU8,
    node: u64,
    endpoint: u16,
) -> Result<(), Error> {
    let exchange = Exchange::initiate(matter, crypto, fab_idx, node).await?;

    exchange.on_off().toggle(endpoint).await
}

/// A minimal **momentary** Generic Switch cluster handler.
///
/// Exposes the two mandatory attributes (`NumberOfPositions` = 2, a simple
/// push-button; `CurrentPosition` = 0, i.e. released — we report the resting
/// state and convey presses purely through events). The press *events* are
/// emitted by the app (see [`run_switch`]) via the generated `InitialPress` /
/// `ShortRelease` `emit_for` helpers, not by this handler.
#[derive(Clone)]
struct SwitchHandler {
    dataver: Dataver,
}

impl SwitchHandler {
    const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    fn adapt(self) -> switch::HandlerAdaptor<Self> {
        switch::HandlerAdaptor(self)
    }
}

impl switch::ClusterHandler for SwitchHandler {
    // Momentary switch with release (MS | MSR): a stateless push-button that
    // reports both the press (`InitialPress`) and the completed short press
    // (`ShortRelease`). Per the Switch cluster spec, `ShortRelease` is only a
    // valid event when the `MOMENTARY_SWITCH_RELEASE` (MSR) feature is set - so
    // we must advertise it, not just `MOMENTARY_SWITCH`. `ShortRelease` is the
    // canonical "single press completed" event ecosystems trigger on.
    const CLUSTER: rs_matter::dm::Cluster<'static> = switch::FULL_CLUSTER
        .with_features(
            SwitchFeature::MOMENTARY_SWITCH
                .union(SwitchFeature::MOMENTARY_SWITCH_RELEASE)
                .bits(),
        )
        .with_attrs(rs_matter::with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn number_of_positions(&self, _ctx: impl rs_matter::dm::ReadContext) -> Result<u8, Error> {
        Ok(2)
    }

    fn current_position(&self, _ctx: impl rs_matter::dm::ReadContext) -> Result<u8, Error> {
        // Always resting/released; the press is conveyed via events.
        Ok(0)
    }
}

/// The Node meta-data describing our Matter switch device.
///
/// It exposes BOTH switch paradigms, on two endpoints:
/// - endpoint 1: On/Off Light Switch (`0x0103`) — OnOff *client* + Binding;
///   drives bound lights directly.
/// - endpoint 2: Generic Switch (`0x000F`) — `Switch` *server*; emits press
///   events ecosystems use as automation triggers.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new_with_clients(
            SWITCH_ENDPOINT,
            devices!(DEV_TYPE_ON_OFF_LIGHT_SWITCH),
            // Server clusters: Descriptor + Binding (our address book).
            clusters!(desc::DescHandler::CLUSTER, binding::CLUSTER),
            // Client clusters: OnOff (we *initiate* OnOff commands).
            &[on_off::FULL_CLUSTER.id],
        ),
        Endpoint::new(
            GENERIC_SWITCH_ENDPOINT,
            devices!(DEV_TYPE_GENERIC_SWITCH),
            // Server clusters: Descriptor + Switch (emits press events).
            clusters!(desc::DescHandler::CLUSTER, SwitchHandler::CLUSTER),
        ),
    ],
};

/// The Data Model handler: root endpoint 0 + the Descriptor and Binding handlers
/// on the switch endpoint.
fn data_model<'a, const N: usize>(
    mut rand: impl RngCore + Copy,
    bindings: &'a Bindings<N>,
) -> impl DataModel + 'a {
    (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&SysNetifs)
            .build(rand)
            .chain(
                EpClMatcher::new(Some(SWITCH_ENDPOINT), Some(desc::DescHandler::CLUSTER.id)),
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(SWITCH_ENDPOINT), Some(binding::CLUSTER.id)),
                Async(
                    BindingHandler::new(Dataver::new_rand(&mut rand), SWITCH_ENDPOINT, bindings)
                        .adapt(),
                ),
            )
            // Endpoint 2: the Generic Switch — Descriptor + Switch server.
            .chain(
                EpClMatcher::new(
                    Some(GENERIC_SWITCH_ENDPOINT),
                    Some(desc::DescHandler::CLUSTER.id),
                ),
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(
                    Some(GENERIC_SWITCH_ENDPOINT),
                    Some(SwitchHandler::CLUSTER.id),
                ),
                Async(SwitchHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            ),
    )
}
