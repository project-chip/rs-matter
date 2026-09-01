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

//! Example Matter device exercising OnOff + LevelControl + ColorControl
//! over Ethernet. Used to drive the chip-tool `light` itest suite
//! (`Test_TC_OO_*`, `Test_TC_LVL_*`, `Test_TC_CC_*`).
//!
//! Besides the Extended Color Light on endpoint 1, the device hosts an
//! **On/Off Light Switch** (`0x0103`) on endpoint 2 — OnOff in its *client*
//! list plus a Binding cluster — so the same binary also exercises the
//! client role: the `switch` itest suite runs two instances of it, binds one
//! instance's switch endpoint to the other's light endpoint, and triggers a
//! "switch press" via the `--app-pipe` command channel, making the first
//! instance resolve + CASE + `OnOff::Toggle` the second.
#![recursion_limit = "256"]
#![allow(clippy::uninlined_format_args)]

use core::cell::Cell;
use core::num::NonZeroU8;
use core::pin::pin;

use std::fs;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::path::PathBuf;

use embassy_futures::select::{select3, select4};

use async_signal::{Signal, Signals};
use log::{error, info, trace};

use futures_lite::StreamExt;

use rand::RngCore;
use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::color_control::test::TestColorControlDeviceLogic;
use rs_matter::dm::clusters::app::color_control::{self, ColorControlHooks};
use rs_matter::dm::clusters::app::level_control::{self, LevelControlHooks};
use rs_matter::dm::clusters::app::on_off::{self, OnOffHooks, StartUpOnOffEnum};
use rs_matter::dm::clusters::binding::{self, BindingHandler, Bindings};
use rs_matter::dm::clusters::decl::level_control::{
    AttributeId, CommandId, OptionsBitmap, FULL_CLUSTER as LEVEL_CONTROL_FULL_CLUSTER,
};
use rs_matter::dm::clusters::decl::on_off as on_off_cluster;
use rs_matter::dm::clusters::decl::switch::{
    self as switch_cluster, ClusterHandler as _, Feature as SwitchFeature, InitialPress, LongPress,
    LongRelease,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::identify::{self, IdentifyHandler};
use rs_matter::dm::clusters::mode_select::{
    self, Mode, ModeId, ModeSelectHandler, ModeSelectHooks, SemanticTag,
};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_DET};
use rs_matter::dm::devices::{
    DEV_TYPE_EXTENDED_COLOR_LIGHT, DEV_TYPE_GENERIC_SWITCH, DEV_TYPE_ON_OFF_LIGHT_SWITCH,
};
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{
    Async, AttrChangeNotifier, Cluster, DataModel, Dataver, Endpoint, EpClMatcher, EventEmitter,
    Node, ReadContext,
};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::im::{EthInteractionModelState, InteractionModel};
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::KvBlobStoreAccess;
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::tlv::Nullable;
use rs_matter::transport::exchange::{Exchange, MatterBuffers};
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::sync::Notification;
use rs_matter::{clusters, devices, root_endpoint, with, Matter};

// `OnOffClient` brings the `.on_off()` IM-client method into scope on
// `Exchange`; `ImClient` brings `group_invoke_with`.
use rs_matter::dm::clusters::app::on_off::OnOffClient as _;
use rs_matter::im::client::ImClient as _;

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

#[path = "../common/args.rs"]
mod args;

#[path = "../common/pipe.rs"]
mod pipe;

/// The local endpoint hosting the On/Off Light Switch (OnOff client + Binding).
const SWITCH_ENDPOINT: u16 = 2;

/// The local endpoint hosting the Generic Switch (`Switch` server cluster,
/// press events) — exercised by the `TC_SWTCH` Python test via its
/// `--app-pipe` button simulator.
const GENERIC_SWITCH_ENDPOINT: u16 = 3;

/// How many binding entries the device can hold (across all fabrics/endpoints).
const MAX_BINDINGS: usize = 8;

static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static STATE: StaticCell<EthInteractionModelState> = StaticCell::new();

fn main() -> Result<(), Error> {
    env_logger::builder()
        .format(|buf, record| {
            use std::io::Write;
            writeln!(buf, "{}: {}", record.level(), record.args())
        })
        .target(env_logger::Target::Stdout)
        .filter_level(::log::LevelFilter::Debug)
        .init();

    let matter = MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        args::comm_overrides(),
        &TEST_DEV_ATT,
        args::port_override(),
    ));

    let store = args::file_kv_store();

    let buffers = BUFFERS.uninit().init_with(MatterBuffers::init());

    // Create the data model state (subscriptions, events, network store).
    let state = STATE.init(EthInteractionModelState::new(EthNetwork::new_default()));

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = matter.kv(store);

    // Re-hydrate the `Matter` instance (fabrics, basic info, RTC).
    matter.startup(&kv)?;

    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);
    let mut rand = crypto.rand()?;

    // ModeSelect cluster setup - an *extra* cluster on EP1 (Core spec 9.2.1
    // allows only one Application device type per Simple endpoint, so the
    // endpoint keeps Extended Color Light and does not declare Mode Select).
    let mode_select_handler =
        ModeSelectHandler::new(Dataver::new_rand(&mut rand), ModeSelectDeviceLogic::new());

    // OnOff cluster setup, coupled to ModeSelect so that an OFF -> ON
    // transition applies `OnMode` (the ModeSelect `ON_OFF` feature) - the
    // behaviour `Test_TC_MOD_3_1` verifies.
    let on_off_handler =
        on_off::OnOffHandler::new(Dataver::new_rand(&mut rand), 1, OnOffDeviceLogic::new())
            .with_on_mode_applier(&mode_select_handler);

    // LevelControl cluster setup
    let level_control_handler = level_control::LevelControlHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        LevelControlDeviceLogic::new(),
        level_control::AttributeDefaults {
            on_level: Nullable::some(42),
            options: OptionsBitmap::from_bits(OptionsBitmap::EXECUTE_IF_OFF.bits()).unwrap(),
            ..Default::default()
        },
    );

    // OnOff↔LC wiring
    on_off_handler.init(Some(&level_control_handler));
    level_control_handler.init(Some(&on_off_handler));

    // ColorControl cluster setup — coupled to the same OnOff so
    // EXECUTE_IF_OFF gating works.
    let color_control_handler = color_control::ColorControlHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        ColorControlDeviceLogic::new(),
        color_control::AttributeDefaults::default(),
    );
    color_control_handler.init(Some(&on_off_handler));

    // The Binding registry (the switch endpoint's address book), re-hydrated
    // from KV by the `Startup` lifecycle op delivered below.
    let bindings = Bindings::<MAX_BINDINGS>::new();

    // The Generic Switch's current position, shared between its cluster
    // handler and the button-simulator task.
    let switch_position = Cell::new(0u8);

    let im = InteractionModel::new(
        matter,
        &crypto,
        buffers,
        data_model(
            rand,
            &on_off_handler,
            &level_control_handler,
            &mode_select_handler,
            &color_control_handler,
            &bindings,
            &switch_position,
        ),
        &kv,
        state,
    );

    // Bring the Data Model to its operational state: re-hydrate its persisted
    // state and deliver the `Startup` lifecycle op to all cluster handlers.
    futures_lite::future::block_on(im.startup())?;

    let responder = DefaultResponder::new(&im);

    let mut respond = pin!(responder.run::<4, 4>());
    let mut im_job = pin!(im.run());

    let socket = async_io::Async::<UdpSocket>::bind(args::bind_addr())?;

    let mut mdns = pin!(mdns::run_mdns(matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket, &socket));

    matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;

    if !matter.has_fabrics() {
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;
        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;
    }

    #[cfg(not(windows))]
    let mut term_signal = Signals::new([Signal::Term])?;
    #[cfg(windows)]
    let mut term_signal = Signals::new([Signal::Int])?;
    let mut term = pin!(async {
        term_signal.next().await;
        Ok(())
    });

    // The switch-press trigger: the itest orchestration sends
    // `{"Name": "Toggle"}` over the `--app-pipe` FIFO to simulate a press,
    // and the switch task reacts by toggling every bound light.
    let toggle_requested = Notification::new();

    // The Generic Switch button simulator, driven by `TC_SWTCH` over the
    // same `--app-pipe` FIFO (`SimulateLongPress` / `SimulateSwitchIdle`).
    let sim = SimChannel::new();

    let mut pipe_job = pin!(pipe::run_app_pipe_actions(
        args::parse_arg_opt_override("--app-pipe", |s| s.to_string()),
        |line| {
            if line.contains("\"Toggle\"") {
                toggle_requested.notify();
                Ok(true)
            } else if line.contains("\"SimulateLongPress\"") {
                sim.send(SimCommand::LongPress {
                    button: json_u64(&line, "ButtonId").unwrap_or(1) as u8,
                    delay_ms: json_u64(&line, "LongPressDelayMillis").unwrap_or(4500),
                    duration_ms: json_u64(&line, "LongPressDurationMillis").unwrap_or(5000),
                });
                Ok(true)
            } else if line.contains("\"SimulateSwitchIdle\"") {
                sim.send(SimCommand::Idle);
                Ok(true)
            } else {
                Ok(false)
            }
        }
    ));

    let mut switch_job = pin!(run_switch(
        matter,
        &crypto,
        &kv,
        &bindings,
        &toggle_requested
    ));
    let mut sim_job = pin!(run_switch_simulation(&im, &switch_position, &sim));

    let all = select3(
        &mut transport,
        &mut mdns,
        select4(
            &mut respond,
            &mut im_job,
            &mut term,
            select3(&mut pipe_job, &mut switch_job, &mut sim_job).coalesce(),
        )
        .coalesce(),
    );

    futures_lite::future::block_on(all.coalesce())
}

/// The switch loop: on every requested "press", walk the binding registry and
/// send `OnOff::Toggle` to each unicast `(node, endpoint)` target bound on
/// [`SWITCH_ENDPOINT`]. Each binding carries its own `fab_idx`, and
/// `Exchange::initiate` performs the operational mDNS resolve + CASE when no
/// session to the target exists yet.
async fn run_switch<const N: usize>(
    matter: &Matter<'_>,
    crypto: &impl Crypto,
    kv: impl KvBlobStoreAccess,
    bindings: &Bindings<N>,
    toggle_requested: &Notification,
) -> Result<(), Error> {
    loop {
        toggle_requested.wait().await;

        info!("Switch: toggling all bound lights...");

        // Iterate by index; `get` clones each entry out (lock released per
        // call) so we can `await` the remote invoke below.
        for i in 0..bindings.len() {
            let Some(binding) = bindings.get(i) else {
                break;
            };

            // Only this switch's endpoint.
            if binding.local_endpoint != SWITCH_ENDPOINT {
                continue;
            }

            // If a specific cluster is bound, it must be OnOff.
            if let Some(cluster) = binding.cluster {
                if cluster != on_off_cluster::FULL_CLUSTER.id {
                    continue;
                }
            }

            // Group target: multicast an encrypted, fire-and-forget Toggle
            // to the whole group, with an endpoint-less command path —
            // receivers apply it to their group-member endpoints.
            if let Some(group_id) = binding.group {
                info!(
                    "Switch: group-toggling fabric {}, group 0x{:04X}",
                    binding.fab_idx, group_id
                );

                match group_toggle(matter, crypto, &kv, binding.fab_idx, group_id).await {
                    Ok(()) => info!("Switch: group toggle ok"),
                    Err(e) => error!("Switch: group toggle failed: {:?}", e),
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

            match toggle(matter, crypto, binding.fab_idx, node, endpoint).await {
                Ok(()) => info!("Switch: toggle ok"),
                Err(e) => error!("Switch: toggle failed: {:?}", e),
            }
        }
    }
}

/// Open (or reuse) a CASE session to `(fab_idx, node)` and send `OnOff::Toggle`
/// to `endpoint`.
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

/// Multicast an encrypted, fire-and-forget `OnOff::Toggle` to `group_id`.
async fn group_toggle(
    matter: &Matter<'_>,
    crypto: &impl Crypto,
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
                    Some(on_off_cluster::FULL_CLUSTER.id),
                    Some(on_off_cluster::CommandId::Toggle as u32),
                ))?
                .data(|w| {
                    w.start_struct(&TLVTag::Context(CmdDataTag::Data as u8))?;
                    w.end_container()
                })?
                .end()
        })
        .await
}

const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_EXTENDED_COLOR_LIGHT),
            clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                OnOffDeviceLogic::CLUSTER,
                LevelControlDeviceLogic::CLUSTER,
                ColorControlDeviceLogic::CLUSTER,
                ModeSelectDeviceLogic::CLUSTER,
            ),
        ),
        // The On/Off Light Switch (`0x0103`): OnOff in the *client* list plus
        // the Binding cluster (its address book) — the `switch_binding` Rust
        // integration test and the (manual) TC-BIND certification procedures
        // drive a bound light through this endpoint.
        Endpoint::new_with_clients(
            SWITCH_ENDPOINT,
            devices!(DEV_TYPE_ON_OFF_LIGHT_SWITCH),
            clusters!(
                desc::DescHandler::CLUSTER,
                identify::CLUSTER,
                binding::CLUSTER,
            ),
            &[on_off_cluster::FULL_CLUSTER.id],
        ),
        // The Generic Switch (`0x000F`): a momentary push-button (`Switch`
        // server cluster) whose presses are simulated over the `--app-pipe`
        // channel — exercised by the `TC_SWTCH` Python test.
        Endpoint::new(
            GENERIC_SWITCH_ENDPOINT,
            devices!(DEV_TYPE_GENERIC_SWITCH),
            clusters!(desc::DescHandler::CLUSTER, SwitchHandler::CLUSTER),
        ),
    ],
};

fn data_model<
    'a,
    LH: LevelControlHooks,
    OH: OnOffHooks,
    CH: ColorControlHooks,
    MH: ModeSelectHooks,
>(
    mut rand: impl RngCore + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
    level_control: &'a level_control::LevelControlHandler<'a, LH, OH>,
    mode_select: &'a ModeSelectHandler<MH>,
    color_control: &'a color_control::ColorControlHandler<'a, CH, OH, LH>,
    bindings: &'a Bindings<MAX_BINDINGS>,
    switch_position: &'a Cell<u8>,
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
                EpClMatcher::new(Some(1), Some(OnOffDeviceLogic::CLUSTER.id)),
                on_off::HandlerAsyncAdaptor(on_off),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(LevelControlDeviceLogic::CLUSTER.id)),
                level_control::HandlerAsyncAdaptor(level_control),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(ColorControlDeviceLogic::CLUSTER.id)),
                color_control::HandlerAsyncAdaptor(color_control),
            )
            // Clusters for the switch endpoint
            .chain(
                EpClMatcher::new(Some(SWITCH_ENDPOINT), Some(desc::DescHandler::CLUSTER.id)),
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(SWITCH_ENDPOINT), Some(identify::CLUSTER.id)),
                Async(IdentifyHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(SWITCH_ENDPOINT), Some(binding::CLUSTER.id)),
                Async(
                    BindingHandler::new(Dataver::new_rand(&mut rand), SWITCH_ENDPOINT, bindings)
                        .adapt(),
                ),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(ModeSelectDeviceLogic::CLUSTER.id)),
                Async(mode_select::HandlerAdaptor(mode_select)),
            )
            // Clusters for the Generic Switch endpoint
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
                Async(SwitchHandler::new(Dataver::new_rand(&mut rand), switch_position).adapt()),
            ),
    )
}

// ---- Generic Switch: cluster handler + button simulator ----

/// A momentary Generic Switch cluster handler: `MS | MSR | MSL` — a
/// push-button reporting `InitialPress` on press and, for the (simulated)
/// long presses `TC_SWTCH` drives, `LongPress` / `LongRelease`.
///
/// The `CurrentPosition` state is shared (by reference) with the button
/// simulator task, which mutates it and emits the events.
struct SwitchHandler<'a> {
    dataver: Dataver,
    position: &'a Cell<u8>,
}

impl<'a> SwitchHandler<'a> {
    const fn new(dataver: Dataver, position: &'a Cell<u8>) -> Self {
        Self { dataver, position }
    }

    fn adapt(self) -> switch_cluster::HandlerAdaptor<Self> {
        switch_cluster::HandlerAdaptor(self)
    }
}

impl switch_cluster::ClusterHandler for SwitchHandler<'_> {
    const CLUSTER: Cluster<'static> = switch_cluster::FULL_CLUSTER
        .with_features(
            SwitchFeature::MOMENTARY_SWITCH
                .union(SwitchFeature::MOMENTARY_SWITCH_RELEASE)
                .union(SwitchFeature::MOMENTARY_SWITCH_LONG_PRESS)
                .bits(),
        )
        .with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn number_of_positions(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(2)
    }

    fn current_position(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.position.get())
    }
}

/// A button-simulator command, parsed off the `--app-pipe` channel.
#[derive(Copy, Clone, Debug)]
enum SimCommand {
    /// `SimulateLongPress`: press `button`, emit `LongPress` after
    /// `delay_ms`, release (with `LongRelease`) at `duration_ms`.
    LongPress {
        button: u8,
        delay_ms: u64,
        duration_ms: u64,
    },
    /// `SimulateSwitchIdle`: return the button to its resting position.
    Idle,
}

/// The single-slot channel from the (sync) app-pipe action closure to the
/// (async) button-simulator task.
struct SimChannel {
    cmd: Cell<Option<SimCommand>>,
    notify: Notification,
}

impl SimChannel {
    const fn new() -> Self {
        Self {
            cmd: Cell::new(None),
            notify: Notification::new(),
        }
    }

    fn send(&self, cmd: SimCommand) {
        self.cmd.set(Some(cmd));
        self.notify.notify();
    }
}

/// The Generic Switch button simulator: play each [`SimCommand`] against the
/// shared `CurrentPosition` state, notifying subscribers of the position
/// changes and emitting the press events, with the command's timing.
async fn run_switch_simulation(
    notifier: &(impl EventEmitter + AttrChangeNotifier),
    position: &Cell<u8>,
    sim: &SimChannel,
) -> Result<(), Error> {
    fn set_position(notifier: &impl AttrChangeNotifier, position: &Cell<u8>, value: u8) {
        if position.replace(value) != value {
            notifier.notify_attr_changed(
                GENERIC_SWITCH_ENDPOINT,
                switch_cluster::FULL_CLUSTER.id,
                switch_cluster::AttributeId::CurrentPosition as _,
            );
        }
    }

    loop {
        sim.notify.wait().await;

        let Some(cmd) = sim.cmd.take() else {
            continue;
        };

        info!("Switch simulator: {cmd:?}");

        match cmd {
            SimCommand::Idle => set_position(notifier, position, 0),
            SimCommand::LongPress {
                button,
                delay_ms,
                duration_ms,
            } => {
                set_position(notifier, position, button);
                if let Err(e) = InitialPress::emit_for(notifier, GENERIC_SWITCH_ENDPOINT, |b| {
                    b.new_position(button)?.end()
                }) {
                    error!("InitialPress emit failed: {e:?}");
                }

                embassy_time::Timer::after(embassy_time::Duration::from_millis(delay_ms)).await;
                if let Err(e) = LongPress::emit_for(notifier, GENERIC_SWITCH_ENDPOINT, |b| {
                    b.new_position(button)?.end()
                }) {
                    error!("LongPress emit failed: {e:?}");
                }

                embassy_time::Timer::after(embassy_time::Duration::from_millis(
                    duration_ms.saturating_sub(delay_ms),
                ))
                .await;
                set_position(notifier, position, 0);
                if let Err(e) = LongRelease::emit_for(notifier, GENERIC_SWITCH_ENDPOINT, |b| {
                    b.previous_position(button)?.end()
                }) {
                    error!("LongRelease emit failed: {e:?}");
                }
            }
        }
    }
}

/// Extract a `"key": <number>` field from a single-line JSON dict — the
/// app-pipe protocol is simple enough to not warrant a JSON dependency.
fn json_u64(line: &str, key: &str) -> Option<u64> {
    let pos = line.find(&format!("\"{key}\""))?;
    let rest = &line[pos..];
    let rest = &rest[rest.find(':')? + 1..];
    let rest = rest.trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

// ---- ColorControl business logic ----
//
// The cluster owns all attribute state internally, so this is the bundled
// `TestColorControlDeviceLogic` (all 5 features enabled, stub actuator)
// with one addition: `StartUpColorTemperatureMireds` is persisted to a
// file rather than kept in RAM, so it survives the device restart that
// `TC_CC_6_5` performs. (The cluster handler itself already applies the
// persisted value to `ColorTemperatureMireds` at power-up - see
// `ColorControlHandler::init`.)

pub struct ColorControlDeviceLogic {
    inner: TestColorControlDeviceLogic,
    storage_path: PathBuf,
}

const CT_STORAGE_FILE_NAME: &str = "rs-matter-light-tests-start-up-ct";

impl Default for ColorControlDeviceLogic {
    fn default() -> Self {
        Self::new()
    }
}

impl ColorControlDeviceLogic {
    pub fn new() -> Self {
        // Tie the state file to `--KVS` when given, so concurrent
        // instances don't clobber each other (same reasoning as
        // `OnOffDeviceLogic`).
        let storage_path = match args::kvs_override() {
            Some(kvs) => PathBuf::from(format!("{kvs}-start-up-ct")),
            None => std::env::temp_dir().join(CT_STORAGE_FILE_NAME),
        };

        let inner = TestColorControlDeviceLogic::new();

        // Re-hydrate: a 2-byte little-endian value, or absent for null.
        if let Ok(mut file) = fs::File::open(storage_path.as_path()) {
            let mut buf = [0u8; 2];
            if file.read_exact(&mut buf).is_ok() {
                let value = u16::from_le_bytes(buf);
                let _ = inner.set_start_up_color_temperature_mireds(Nullable::some(value));
            }
        }

        Self {
            inner,
            storage_path,
        }
    }
}

impl ColorControlHooks for ColorControlDeviceLogic {
    const CLUSTER: Cluster<'static> = TestColorControlDeviceLogic::CLUSTER;
    const COLOR_CAPABILITIES: color_control::ColorCapabilitiesBitmap =
        TestColorControlDeviceLogic::COLOR_CAPABILITIES;
    const COLOR_TEMP_PHYSICAL_MIN_MIREDS: u16 =
        TestColorControlDeviceLogic::COLOR_TEMP_PHYSICAL_MIN_MIREDS;
    const COLOR_TEMP_PHYSICAL_MAX_MIREDS: u16 =
        TestColorControlDeviceLogic::COLOR_TEMP_PHYSICAL_MAX_MIREDS;
    const COUPLE_COLOR_TEMP_TO_LEVEL_MIN_MIREDS: u16 =
        TestColorControlDeviceLogic::COUPLE_COLOR_TEMP_TO_LEVEL_MIN_MIREDS;

    fn set_device_color(&self, target: color_control::SetDeviceColor) -> Result<(), ()> {
        self.inner.set_device_color(target)
    }

    fn start_up_color_temperature_mireds(&self) -> Result<Nullable<u16>, Error> {
        self.inner.start_up_color_temperature_mireds()
    }

    fn set_start_up_color_temperature_mireds(&self, value: Nullable<u16>) -> Result<(), Error> {
        self.inner
            .set_start_up_color_temperature_mireds(value.clone())?;

        match value.into_option() {
            Some(mireds) => {
                let mut file = fs::File::create(self.storage_path.as_path())?;
                file.write_all(&mireds.to_le_bytes())?;
            }
            // Null: drop the file so the next boot starts with no value.
            None => {
                let _ = fs::remove_file(self.storage_path.as_path());
            }
        }

        Ok(())
    }
}

// ---- LevelControl business logic (identical to dimmable_light) ----

pub struct LevelControlDeviceLogic {
    current_level: Cell<Option<u8>>,
    start_up_current_level: Cell<Option<u8>>,
}

impl Default for LevelControlDeviceLogic {
    fn default() -> Self {
        Self::new()
    }
}

impl LevelControlDeviceLogic {
    pub const fn new() -> Self {
        Self {
            current_level: Cell::new(Some(1)),
            start_up_current_level: Cell::new(None),
        }
    }
}

impl LevelControlHooks for LevelControlDeviceLogic {
    const MIN_LEVEL: u8 = 1;
    const MAX_LEVEL: u8 = 254;
    const FASTEST_RATE: u8 = 50;
    const CLUSTER: Cluster<'static> = LEVEL_CONTROL_FULL_CLUSTER
        .with_features(
            level_control::Feature::LIGHTING.bits() | level_control::Feature::ON_OFF.bits(),
        )
        .with_attrs(with!(
            required;
            AttributeId::CurrentLevel
            | AttributeId::RemainingTime
            | AttributeId::MinLevel
            | AttributeId::MaxLevel
            | AttributeId::OnOffTransitionTime
            | AttributeId::OnLevel
            | AttributeId::OnTransitionTime
            | AttributeId::OffTransitionTime
            | AttributeId::DefaultMoveRate
            | AttributeId::Options
            | AttributeId::StartUpCurrentLevel
        ))
        .with_cmds(with!(
            CommandId::MoveToLevel
                | CommandId::Move
                | CommandId::Step
                | CommandId::Stop
                | CommandId::MoveToLevelWithOnOff
                | CommandId::MoveWithOnOff
                | CommandId::StepWithOnOff
                | CommandId::StopWithOnOff
        ));

    fn set_device_level(&self, level: u8) -> Result<Option<u8>, ()> {
        Ok(Some(level))
    }

    fn current_level(&self) -> Option<u8> {
        self.current_level.get()
    }

    fn set_current_level(&self, level: Option<u8>) {
        info!("set_current_level: {:?}", level);
        self.current_level.set(level);
    }

    fn start_up_current_level(&self) -> Result<Option<u8>, Error> {
        Ok(self.start_up_current_level.get())
    }

    fn set_start_up_current_level(&self, value: Option<u8>) -> Result<(), Error> {
        self.start_up_current_level.set(value);
        Ok(())
    }
}

// ---- OnOff business logic (identical to dimmable_light) ----

#[derive(Default)]
struct OnOffPersistentState {
    on_off: bool,
    start_up_on_off: Option<StartUpOnOffEnum>,
}

impl OnOffPersistentState {
    fn to_bytes_from_values(on_off: bool, start_up_on_off: Option<StartUpOnOffEnum>) -> u8 {
        let on_off = on_off as u8;
        let start_up_on_off: u8 = match start_up_on_off {
            Some(StartUpOnOffEnum::Off) => 0,
            Some(StartUpOnOffEnum::On) => 1,
            Some(StartUpOnOffEnum::Toggle) => 2,
            None => 3,
        };
        on_off + (start_up_on_off << 1)
    }

    fn from_bytes(data: u8) -> Result<Self, Error> {
        Ok(Self {
            on_off: data & 1 != 0,
            start_up_on_off: match data >> 1 {
                0 => Some(StartUpOnOffEnum::Off),
                1 => Some(StartUpOnOffEnum::On),
                2 => Some(StartUpOnOffEnum::Toggle),
                3 => None,
                _ => return Err(ErrorCode::Failure.into()),
            },
        })
    }
}

/// The vendor ID whose namespace our semantic tags live in - the CSA test
/// vendor, matching `TEST_DEV_DET`.
const TEST_VENDOR: u16 = 0xFFF1;

/// The light patterns the ModeSelect instance on EP1 chooses between.
///
/// Mode ids are deliberately non-contiguous: `Mode` is an identifier, not an
/// index into this list, and a table like this catches any code that confuses
/// the two. Id `4` is present because `Test_TC_MOD_2_1` defaults its `NewMode`
/// argument to 4.
const LIGHT_PATTERNS: &[Mode] = &[
    Mode::new(0, "Steady", &[SemanticTag::new(TEST_VENDOR, 0x8000)]),
    Mode::new(4, "Blink", &[SemanticTag::new(TEST_VENDOR, 0x8001)]),
    Mode::new(7, "Pulse", &[SemanticTag::new(TEST_VENDOR, 0x8002)]),
];

/// Device logic behind the ModeSelect instance on EP1.
///
/// State is in-memory: the enabled ModeSelect tests
/// (`TestModeSelectCluster`, `Test_TC_MOD_2_1`, `Test_TC_MOD_3_1`) never
/// restart the DUT. The two that would exercise the non-volatile quality of
/// `CurrentMode` / `StartUpMode` - `Test_TC_MOD_3_2` and `3_4` - gate their
/// power-cycle step on `PICS_USER_PROMPT` and are not enabled, so persisting
/// here would buy nothing testable.
struct ModeSelectDeviceLogic {
    current: Cell<ModeId>,
    start_up: Cell<Option<ModeId>>,
    on_mode: Cell<Option<ModeId>>,
}

impl ModeSelectDeviceLogic {
    pub const fn new() -> Self {
        Self {
            current: Cell::new(0),
            // Non-null on purpose. `StartUpMode` is nullable per the spec
            // (quality `NX`), but `TC_MOD_1_2` asserts `isinstance(_, int)`
            // for it with no `NullValue` branch - unlike `OnMode` two lines
            // above in the same test, which does accept null. Ship a real
            // start-up cycle so the attribute is meaningful either way.
            start_up: Cell::new(Some(0)),
            // `Test_TC_MOD_3_1` writes `OnMode` itself, then toggles OnOff and
            // checks `CurrentMode` followed it. Start null so the test drives
            // the whole sequence.
            on_mode: Cell::new(None),
        }
    }
}

impl ModeSelectHooks for ModeSelectDeviceLogic {
    // `StartUpMode` and `OnMode` are optional; `OnMode` is what the `ON_OFF`
    // feature adds. `Test_TC_MOD_3_1` needs both the feature and the
    // attribute, so opt into them explicitly.
    const CLUSTER: Cluster<'static> = mode_select::FULL_CLUSTER
        .with_features(mode_select::Feature::ON_OFF.bits())
        .with_attrs(with!(
            required;
            mode_select::AttributeId::StartUpMode | mode_select::AttributeId::OnMode
        ));

    fn description(&self) -> &str {
        "Light pattern"
    }

    fn supported_modes(&self) -> &[Mode<'_>] {
        LIGHT_PATTERNS
    }

    fn current_mode(&self) -> ModeId {
        self.current.get()
    }

    fn change_to_mode(&self, mode: ModeId) -> Result<(), Error> {
        trace!("ModeSelectDeviceLogic: light pattern -> {mode}");
        self.current.set(mode);

        Ok(())
    }

    fn start_up_mode(&self) -> Nullable<ModeId> {
        Nullable::new(self.start_up.get())
    }

    fn set_start_up_mode(&self, value: Nullable<ModeId>) -> Result<(), Error> {
        self.start_up.set(value.into_option());

        Ok(())
    }

    fn on_mode(&self) -> Nullable<ModeId> {
        Nullable::new(self.on_mode.get())
    }

    fn set_on_mode(&self, value: Nullable<ModeId>) -> Result<(), Error> {
        self.on_mode.set(value.into_option());

        Ok(())
    }
}

#[derive(Default)]
pub struct OnOffDeviceLogic {
    on_off: Cell<bool>,
    start_up_on_off: Cell<Option<StartUpOnOffEnum>>,
    storage_path: PathBuf,
}

const STORAGE_FILE_NAME: &str = "rs-matter-light-tests-on-off-state";

impl OnOffDeviceLogic {
    pub fn new() -> Self {
        // Tie the OnOff state file to the `--KVS` path when one is given, so
        // multiple simultaneous instances (the two-node `switch` itest suite)
        // don't clobber each other's persisted OnOff state.
        let storage_path = match args::kvs_override() {
            Some(kvs) => PathBuf::from(format!("{kvs}-on-off-state")),
            None => std::env::temp_dir().join(STORAGE_FILE_NAME),
        };
        let persisted_state = match fs::File::open(storage_path.as_path()) {
            Ok(mut file) => {
                let mut buf: [u8; 1] = [0];
                file.read_exact(&mut buf).unwrap();
                trace!("OnOffDeviceLogic::new: read {:0x}", buf[0]);
                OnOffPersistentState::from_bytes(buf[0]).unwrap()
            }
            Err(_) => OnOffPersistentState::default(),
        };
        Self {
            on_off: Cell::new(persisted_state.on_off),
            start_up_on_off: Cell::new(persisted_state.start_up_on_off),
            storage_path,
        }
    }

    fn save_state(&self) -> Result<(), Error> {
        let mut file = fs::File::create(self.storage_path.as_path())?;
        let value = OnOffPersistentState::to_bytes_from_values(
            self.on_off.get(),
            self.start_up_on_off.get(),
        );
        file.write_all(&[value])?;
        Ok(())
    }
}

impl OnOffHooks for OnOffDeviceLogic {
    const CLUSTER: Cluster<'static> = on_off_cluster::FULL_CLUSTER
        .with_revision(6)
        .with_features(on_off_cluster::Feature::LIGHTING.bits())
        .with_attrs(with!(
            required;
            on_off_cluster::AttributeId::OnOff
            | on_off_cluster::AttributeId::GlobalSceneControl
            | on_off_cluster::AttributeId::OnTime
            | on_off_cluster::AttributeId::OffWaitTime
            | on_off_cluster::AttributeId::StartUpOnOff
        ))
        .with_cmds(with!(
            on_off_cluster::CommandId::Off
                | on_off_cluster::CommandId::On
                | on_off_cluster::CommandId::Toggle
                | on_off_cluster::CommandId::OffWithEffect
                | on_off_cluster::CommandId::OnWithRecallGlobalScene
                | on_off_cluster::CommandId::OnWithTimedOff
        ));

    fn on_off(&self) -> bool {
        self.on_off.get()
    }

    fn set_on_off(&self, on: bool) {
        self.on_off.set(on);
        info!("OnOff state set to: {}", on);
        if let Err(err) = self.save_state() {
            error!("Error saving state: {}", err);
        }
    }

    fn start_up_on_off(&self) -> Nullable<on_off::StartUpOnOffEnum> {
        match self.start_up_on_off.get() {
            Some(value) => Nullable::some(value),
            None => Nullable::none(),
        }
    }

    fn set_start_up_on_off(&self, value: Nullable<on_off::StartUpOnOffEnum>) -> Result<(), Error> {
        self.start_up_on_off.set(value.into_option());
        self.save_state()
    }

    async fn handle_off_with_effect(&self, _effect: on_off::EffectVariantEnum) {
        // no effect
    }
}
