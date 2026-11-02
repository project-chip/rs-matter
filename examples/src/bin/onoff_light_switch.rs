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
//! fabric). On every press of Enter in the console, the example sends an
//! `OnOff::Toggle` to each bound light and emits Generic Switch press events.
//!
//! Sending a command to a remote node exercises the **operational discovery
//! (resolve)** path: with no existing CASE session, `Exchange::initiate` resolves
//! `<compressed-fabric-id>-<node-id>._matter._tcp` over mDNS, establishes CASE,
//! and then invokes — so this example is a way to exercise the resolve path of
//! whichever mDNS responder is running (here, the built-in one).
//!
//! The loop lives in the `run` method of a handler that serves no cluster
//! ([`SwitchTask`]), which receives what it needs from the Interaction Model, as
//! the `ota_requestor` example explains.
//!
//! Try it with the `onoff_light` example running as the bound light on the same
//! fabric; bind this switch to it via your controller, and press Enter. This
//! example listens on [`PORT`], so both can run on one machine.

use core::future::{pending, Future};
use core::num::NonZeroU8;
use core::pin::pin;

use futures_lite::io::{AsyncBufReadExt, BufReader};

use log::{info, warn};

use rand::rngs::StdRng;
use rand::Rng;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::on_off;
use rs_matter::dm::clusters::binding::{self, BindingHandler, Bindings};
use rs_matter::dm::clusters::decl::switch::{
    self, ClusterHandler as _, Feature as SwitchFeature, InitialPress, ShortRelease,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_GENERIC_SWITCH, DEV_TYPE_ON_OFF_LIGHT_SWITCH};
use rs_matter::dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{
    Async, DataModel, Dataver, EmptyHandler, Endpoint, Handler, HandlerContext, MatchContext, Node,
    NonBlockingHandler, ReadContext, ReadReply,
};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::persist::{DirKvBlobStore, KvBlobStoreAccess};
use rs_matter::sc::ExchangeInitiator as _;
use rs_matter::transport::exchange::Exchange;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::sync::MaybeSend;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

use rs_matter::stack::eth::EthMatterStack;
use rs_matter::stack::net::std::StdNetStack;

// `OnOffClient` brings the `.on_off()` IM-client method into scope on `Exchange`.
use rs_matter::dm::clusters::app::on_off::OnOffClient as _;

use static_cell::StaticCell;

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

/// The port this example listens on. Not the default one, which the `onoff_light`
/// example takes, so that both can run on one machine.
const PORT: u16 = MATTER_PORT + 1;

/// The bump allocator size of the stack, in bytes.
///
/// If it is not enough, the stack panics while it starts. The futures of an
/// unoptimized build are much bigger than those of an optimized one.
const BUMP_SIZE: usize = 36 * 1024;

/// The stack is allocated statically to avoid program stack blowups.
static MATTER_STACK: StaticCell<EthMatterStack<BUMP_SIZE, ()>> = StaticCell::new();

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let stack = MATTER_STACK
        .uninit()
        .init_with(EthMatterStack::init_with_port(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
            PORT,
        ));

    // Persistence
    let mut store = DirKvBlobStore::new_default();

    // Create the crypto instance
    let crypto = default_crypto(rand::make_rng::<StdRng>(), DAC_PRIVKEY);

    let rand = crypto.rand()?;

    // Re-hydrate the persisted state. If the device is not commissioned yet, this also
    // prints the QR text and code to the console and enables basic commissioning.
    futures_lite::future::block_on(stack.startup(&crypto, &mut store))?;

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = stack.kv(store);

    // The Binding registry (the switch's address book), re-hydrated by the cluster on startup.
    let bindings = Bindings::<MAX_BINDINGS>::new();

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
        data_model(stack.matter(), rand, &bindings),
        kv,
        // No user task to run
        (),
    ));

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(matter)
}

/// The switch loop, as a handler that only has a `run` method: on every line read from stdin (i.e. each time you press
/// Enter in the console), walk the binding registry and send `OnOff::Toggle` to
/// each unicast `(node, endpoint)` target on [`SWITCH_ENDPOINT`]. Each
/// [`Binding`] carries its own `local_endpoint` and `fab_idx`, so no separate
/// fabric enumeration is needed.
///
/// Driving the toggle by key press (rather than a timer) makes it easy to test
/// against the `onoff_light` example: that device already blinks on its own
/// timer, so a keyboard-triggered switch toggle is unambiguously observable.
struct SwitchTask<'a, const N: usize> {
    matter: &'a Matter<'a>,
    bindings: &'a Bindings<N>,
}

impl<const N: usize> SwitchTask<'_, N> {
    async fn run_switch(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        // Async stdin: `blocking::Unblock` moves the blocking `Stdin` onto a thread
        // pool so reads don't stall the executor.
        let mut stdin = BufReader::new(blocking::Unblock::new(std::io::stdin()));
        let mut line = String::new();

        info!("Switch ready: press Enter to (1) emit Generic Switch press events and (2) toggle all bound lights.");

        loop {
            line.clear();
            let n = stdin.read_line(&mut line).await?;
            if n == 0 {
                // `run` must not return, as that would stop the node. It just has
                // nothing left to do here.
                info!("stdin closed; there will be no more presses");
                return pending().await;
            }

            info!("Switch: Enter pressed; emitting events and toggling bound lights...");

            // (1) Generic Switch (endpoint 2): emit a full momentary press/release
            // cycle. Ecosystems surface these events as automation triggers.
            // `InitialPress.NewPosition = 1` (pressed), `ShortRelease.PreviousPosition = 1`.
            match InitialPress::emit_for(&ctx, GENERIC_SWITCH_ENDPOINT, |b| {
                b.new_position(1)?.end()
            }) {
                Ok(n) => info!("Generic Switch: emitted InitialPress (event #{n})"),
                Err(e) => warn!("Generic Switch: InitialPress emit failed: {:?}", e),
            }
            match ShortRelease::emit_for(&ctx, GENERIC_SWITCH_ENDPOINT, |b| {
                b.previous_position(1)?.end()
            }) {
                Ok(n) => info!("Generic Switch: emitted ShortRelease (event #{n})"),
                Err(e) => warn!("Generic Switch: ShortRelease emit failed: {:?}", e),
            }

            // (2) Binding-based switch (endpoint 1): drive the bound lights.

            // Iterate by index; `get` clones each entry out (lock released per call)
            // so we can `await` the remote invoke below.
            for i in 0..self.bindings.len() {
                let Some(binding) = self.bindings.get(i) else {
                    break;
                };

                // Only this switch's endpoint.
                if binding.local_endpoint != SWITCH_ENDPOINT {
                    continue;
                }

                // If a specific cluster is bound, it must be OnOff.
                if let Some(cluster) = binding.cluster {
                    if cluster != on_off::FULL_CLUSTER.id {
                        continue;
                    }
                }

                // Group targets: multicast an encrypted, fire-and-forget Toggle
                // to the whole group, with an endpoint-less command path —
                // receivers apply it to their group-member endpoints.
                if let Some(group_id) = binding.group {
                    info!(
                        "Switch: group-toggling fabric {}, group 0x{:04X}",
                        binding.fab_idx, group_id
                    );

                    match group_toggle(
                        self.matter,
                        ctx.crypto(),
                        ctx.kv(),
                        binding.fab_idx,
                        group_id,
                    )
                    .await
                    {
                        Ok(()) => info!("Switch: group toggle ok"),
                        Err(e) => warn!("Switch: group toggle failed: {:?}", e),
                    }

                    continue;
                }

                // Unicast OnOff targets (node + endpoint present).
                let (Some(node), Some(endpoint)) = (binding.node, binding.endpoint) else {
                    continue;
                };

                info!(
                    "Switch: toggling fabric {}, node 0x{:016X}, endpoint {}",
                    binding.fab_idx, node, endpoint
                );

                // Resolve (if needed) + CASE + invoke `OnOff::Toggle`.
                match toggle(self.matter, ctx.crypto(), binding.fab_idx, node, endpoint).await {
                    Ok(()) => info!("Switch: toggle ok"),
                    Err(e) => warn!("Switch: toggle failed: {:?}", e),
                }
            }
        }
    }
}

impl<const N: usize> Handler for SwitchTask<'_, N> {
    fn read(&self, _ctx: impl ReadContext, _reply: impl ReadReply) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    fn bump_dataver(&self, _ctx: impl MatchContext) {}

    fn run(&self, ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        self.run_switch(ctx)
    }
}

impl<const N: usize> NonBlockingHandler for SwitchTask<'_, N> {}

/// Open (or reuse) a CASE session to `(fab_idx, node)` and send `OnOff::Toggle`
/// to `endpoint`. `Exchange::initiate` performs the operational mDNS resolve when
/// no session exists yet.
async fn toggle(
    matter: &Matter<'_>,
    crypto: impl Crypto,
    fab_idx: NonZeroU8,
    node: u64,
    endpoint: u16,
) -> Result<(), Error> {
    let exchange = Exchange::initiate(matter, crypto, fab_idx, node).await?;

    exchange.on_off().toggle(endpoint).await
}

/// Multicast an encrypted, fire-and-forget `OnOff::Toggle` to `group_id`.
async fn group_toggle(
    matter: &Matter<'_>,
    crypto: impl Crypto,
    kv: impl KvBlobStoreAccess,
    fab_idx: NonZeroU8,
    group_id: u16,
) -> Result<(), Error> {
    use rs_matter::im::{CmdDataTag, CmdPath};
    use rs_matter::tlv::{TLVTag, TLVWrite};

    let exchange = Exchange::initiate_group(matter, crypto, kv, fab_idx, group_id)?;

    exchange
        .group_invoke_with(|b| {
            b.push()?
                .path_from(&CmdPath::new(
                    None,
                    Some(on_off::FULL_CLUSTER.id),
                    Some(on_off::CommandId::Toggle as u32),
                ))?
                .data(|w| {
                    w.start_struct(&TLVTag::Context(CmdDataTag::Data as u8))?;
                    w.end_container()
                })?
                .end()
        })
        .await
}

/// A minimal **momentary** Generic Switch cluster handler.
///
/// Exposes the two mandatory attributes (`NumberOfPositions` = 2, a simple
/// push-button; `CurrentPosition` = 0, i.e. released — we report the resting
/// state and convey presses purely through events). The press *events* are
/// emitted by the app (see [`SwitchTask`]) via the generated `InitialPress` /
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

/// The Data Model handler: root endpoint 0, the Descriptor and Binding handlers on
/// the switch endpoint, the Generic Switch, and the switch loop.
fn data_model<'a, const N: usize>(
    matter: &'a Matter<'a>,
    mut rand: impl Rng + Copy,
    bindings: &'a Bindings<N>,
) -> impl DataModel + 'a {
    (
        NODE,
        EmptyHandler
            .chain(
                |e, _| e == ROOT_ENDPOINT_ID,
                Async(EthMatterStack::<0, ()>::root_handler(matter, &(), rand)),
            )
            .chain(
                |e, c| e == SWITCH_ENDPOINT && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == SWITCH_ENDPOINT && c == binding::CLUSTER.id,
                Async(
                    BindingHandler::new(Dataver::new_rand(&mut rand), SWITCH_ENDPOINT, bindings)
                        .adapt(),
                ),
            )
            // Endpoint 2: the Generic Switch — Descriptor + Switch server.
            .chain(
                |e, c| e == GENERIC_SWITCH_ENDPOINT && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == GENERIC_SWITCH_ENDPOINT && c == SwitchHandler::CLUSTER.id,
                Async(SwitchHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            // It serves no cluster, so it matches nothing; only its `run` matters.
            .chain(|_, _| false, Async(SwitchTask { matter, bindings })),
    )
}
