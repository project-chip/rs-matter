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

//! Device under test for the `fan` itest suite (`TC_FAN_*`,
//! `Test_TC_FAN_*`).
//!
//! Endpoint 1 is a Fan (`0x002B`): a simulated ten-speed fan with every
//! feature the Fan Control cluster has - `MultiSpeed`, `Auto`, `Rocking`,
//! `Wind`, `Step` and `AirflowDirection` - beside the On/Off cluster the
//! device type pairs it with. The fan reaches a setting the moment it is
//! asked for, which is what the certification suites' immediate read-backs
//! expect.
//!
//! On/Off is wired the way the Device Library describes: switching the fan
//! off through it stops the blades - `PercentCurrent` and `SpeedCurrent` go
//! to zero - and leaves `FanMode`, `PercentSetting` and `SpeedSetting` where
//! they were, so that switching it back on resumes them. `TC_FAN_4_1` checks
//! exactly that.
#![allow(clippy::uninlined_format_args)]

use core::cell::Cell;
use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::select3;

use async_signal::{Signal, Signals};
use log::info;

use futures_lite::StreamExt;

use rand::Rng;
use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::fan_control::{
    self, AirflowDirectionEnum, CurrentSpeed, FanControlHooks, FanModeSequenceEnum, FanSetting,
    Feature, OutOfBandMessage, RockBitmap, WindBitmap,
};
use rs_matter::dm::clusters::app::on_off::{self, OnOffHooks};
use rs_matter::dm::clusters::decl::fan_control as fan_control_cluster;
use rs_matter::dm::clusters::decl::on_off as on_off_cluster;
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::identify::{self, IdentifyHandler};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_FAN;
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, Cluster, DataModel, Dataver, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::im::{EthInteractionModelState, InteractionModel};
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::sync::blocking::Mutex;
use rs_matter::utils::sync::Notification;
use rs_matter::{clusters, devices, root_endpoint, with, Matter};

use static_cell::StaticCell;

#[path = "../common/args.rs"]
mod args;

#[path = "../common/logging.rs"]
mod logging;

#[path = "../common/mdns.rs"]
mod mdns;

/// The endpoint hosting the fan.
const FAN_ENDPOINT: u16 = 1;

/// KV keys for the attributes the two cluster handlers persist. In the
/// vendor range, spaced so that a handler that grows to need a second key
/// does not collide with its neighbour.
const KV_ON_OFF: u16 = rs_matter::persist::VENDOR_KEYS_START + 0x10;
const KV_FAN_CONTROL: u16 = rs_matter::persist::VENDOR_KEYS_START + 0x20;

/// The speed the simulated fan settles on under `Auto`.
const AUTO_SPEED: u8 = 5;

// Statically allocate in BSS the bigger objects
static MATTER: StaticCell<Matter> = StaticCell::new();
// A bigger buffer pool than the default: `TC_FAN_3_1` and `TC_FAN_3_2` hold
// five single-attribute subscriptions open while writing as fast as they can,
// and every report in flight holds a buffer. When the pool runs dry the next
// write is answered with IM BUSY (status 0x9c).
static BUFFERS: StaticCell<MatterBuffers<20>> = StaticCell::new();
static STATE: StaticCell<EthInteractionModelState> = StaticCell::new();

fn main() -> Result<(), Error> {
    logging::init();

    let matter = MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        args::comm_overrides(),
        &TEST_DEV_ATT,
        args::port_override(),
    ));

    // Dump the data model as JSON for `cargo xtask pics`, then exit.
    if args::dump_pics_json(matter, &NODE)? {
        return Ok(());
    }

    // Persistence
    let store = args::file_kv_store();

    // Create the transport buffers
    let buffers = BUFFERS.uninit().init_with(MatterBuffers::init());

    // Create the data model state (subscriptions, events, network store).
    let state = STATE.init(EthInteractionModelState::new(EthNetwork::new_default()));

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = matter.kv(store);

    // Re-hydrate the `Matter` instance (fabrics, basic info, RTC).
    matter.startup(&kv)?;

    // Create the crypto instance
    let crypto = default_crypto(rand::rng(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // The simulated fan, shared by the two clusters that drive it.
    let fan = FanDevice::new();

    // Neither cluster is coupled to the other at the handler level - the
    // Device Library keeps On/Off and Fan Control independent - so there is
    // no `init()` step. Both restore their persisted state on the `Startup`
    // lifecycle op.
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        FAN_ENDPOINT,
        KV_ON_OFF,
        OnOffDeviceLogic::new(&fan),
    );

    let fan_handler = fan_control::FanControlHandler::new(
        Dataver::new_rand(&mut rand),
        FAN_ENDPOINT,
        KV_FAN_CONTROL,
        FanDeviceLogic::new(&fan),
    );

    // Create the Data Model instance
    let im = InteractionModel::new(
        matter,
        &crypto,
        buffers,
        data_model(rand, &on_off_handler, &fan_handler),
        &kv,
        state,
    );

    // Bring the Data Model to its operational state: re-hydrate its persisted
    // state and deliver the `Startup` lifecycle op to all cluster handlers.
    futures_lite::future::block_on(im.startup())?;

    let responder = DefaultResponder::new(&im);

    // Run the responder with up to 16 handlers (i.e. 16 exchanges can be
    // handled simultaneously), so that the reports on the five subscriptions
    // the fan suites hold open never crowd out the next write.
    let mut respond = pin!(responder.run::<16, 4>());

    // Run the background job of the data model
    let mut im_job = pin!(im.run());

    let socket = async_io::Async::<UdpSocket>::bind(args::bind_addr())?;

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket, &socket));

    // We need to always print the QR text, because the test runner expects it to be printed
    // even if the device is already commissioned
    matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;

    if !matter.has_fabrics() {
        // If the device is not commissioned yet, print the QR code to the console
        // and enable basic commissioning

        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;
    }

    // Listen to SIGTERM (or Ctrl-C on Windows, where SIGTERM is not
    // supported by `async-signal`) because at the end of the test we'll
    // receive it.
    #[cfg(not(windows))]
    let mut term_signal = Signals::new([Signal::Term])?;
    #[cfg(windows)]
    let mut term_signal = Signals::new([Signal::Int])?;
    let mut term = pin!(async {
        term_signal.next().await;
        Ok(())
    });

    // Combine all async tasks in a single one
    let all = select3(
        &mut transport,
        &mut mdns,
        select3(&mut respond, &mut im_job, &mut term).coalesce(),
    );

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all.coalesce())
}

/// The Node meta-data describing our Matter device.
///
/// EP1 carries the Fan device type (`0x002B`), whose cluster set - Descriptor,
/// Identify, Groups, Fan Control, plus the optional On/Off - is what
/// `TC_DeviceConformance` reads.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            FAN_ENDPOINT,
            devices!(DEV_TYPE_FAN),
            clusters!(
                desc::DescHandler::CLUSTER,
                identify::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                OnOffDeviceLogic::CLUSTER,
                FanDeviceLogic::CLUSTER,
            ),
        ),
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the fan endpoint's clusters.
fn data_model<'a, OH: OnOffHooks, FH: FanControlHooks>(
    mut rand: impl Rng + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, on_off::NoLevelControl>,
    fan: &'a fan_control::FanControlHandler<FH>,
) -> impl DataModel + 'a {
    (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&SysNetifs)
            .build(rand)
            .chain(
                |e, c| e == FAN_ENDPOINT && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == FAN_ENDPOINT && c == identify::CLUSTER.id,
                Async(IdentifyHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == FAN_ENDPOINT && c == groups::GroupsHandler::CLUSTER.id,
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == FAN_ENDPOINT && c == OnOffDeviceLogic::CLUSTER.id,
                Async(on_off::HandlerAdaptor(on_off)),
            )
            .chain(
                |e, c| e == FAN_ENDPOINT && c == FanDeviceLogic::CLUSTER.id,
                Async(fan_control::HandlerAdaptor(fan)),
            ),
    )
}

// Implementing the fan business logic

/// The simulated fan: the thing both clusters drive.
///
/// The blades follow the setting the moment they are given it, gated by the
/// On/Off switch: while that is off they stand still, whatever the setting.
pub struct FanDevice {
    state: Mutex<Cell<FanDeviceState>>,
    /// Raised whenever the speed the blades turn at may have changed, so the
    /// Fan Control handler re-reads and re-reports it.
    changed: Notification,
}

/// The fan's state, behind one lock.
#[derive(Clone, Copy)]
struct FanDeviceState {
    /// The On/Off switch.
    on: bool,
    /// The setting Fan Control last asked for.
    setting: FanSetting,
    rock: RockBitmap,
    wind: WindBitmap,
    direction: AirflowDirectionEnum,
}

impl FanDevice {
    /// Switched on, and stopped: what the runner's factory reset leaves.
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(Cell::new(FanDeviceState {
                on: true,
                setting: FanSetting::Off,
                rock: RockBitmap::empty(),
                wind: WindBitmap::empty(),
                direction: AirflowDirectionEnum::Forward,
            })),
            changed: Notification::new(),
        }
    }

    fn update(&self, f: impl FnOnce(&mut FanDeviceState)) {
        self.state.lock(|cell| {
            let mut state = cell.get();
            f(&mut state);
            cell.set(state);
        });

        self.changed.notify();
    }

    /// The speed the blades turn at: the setting's speed, or 0 while the
    /// switch is off.
    fn speed(&self) -> u8 {
        let state = self.state.lock(|cell| cell.get());

        if !state.on {
            return 0;
        }

        match state.setting {
            FanSetting::Off => 0,
            FanSetting::Auto => AUTO_SPEED,
            FanSetting::Manual { speed, .. } => speed,
        }
    }
}

impl Default for FanDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// The Fan Control half of the device.
pub struct FanDeviceLogic<'a> {
    fan: &'a FanDevice,
}

impl<'a> FanDeviceLogic<'a> {
    pub const fn new(fan: &'a FanDevice) -> Self {
        Self { fan }
    }
}

impl FanControlHooks for FanDeviceLogic<'_> {
    /// Every feature the cluster has, and every attribute and command they
    /// add. Revision 6 is the Matter 1.6 cluster; the IDL is a revision
    /// behind, and `TC_DeviceConformance` checks the claim against the spec.
    const CLUSTER: Cluster<'static> = fan_control_cluster::FULL_CLUSTER
        .with_revision(6)
        .with_features(
            Feature::MULTI_SPEED.bits()
                | Feature::AUTO.bits()
                | Feature::ROCKING.bits()
                | Feature::WIND.bits()
                | Feature::STEP.bits()
                | Feature::AIRFLOW_DIRECTION.bits(),
        )
        .with_attrs(with!(
            required;
            fan_control_cluster::AttributeId::SpeedMax
                | fan_control_cluster::AttributeId::SpeedSetting
                | fan_control_cluster::AttributeId::SpeedCurrent
                | fan_control_cluster::AttributeId::RockSupport
                | fan_control_cluster::AttributeId::RockSetting
                | fan_control_cluster::AttributeId::WindSupport
                | fan_control_cluster::AttributeId::WindSetting
                | fan_control_cluster::AttributeId::AirflowDirection
        ))
        .with_cmds(with!(fan_control_cluster::CommandId::Step));

    const FAN_MODE_SEQUENCE: FanModeSequenceEnum = FanModeSequenceEnum::OffLowMedHighAuto;
    const SPEED_MAX: u8 = 10;

    /// Left-right or up-down, but not round - so that `TC_FAN_3_3` exercises
    /// the `CONSTRAINT_ERROR` path as well as the accepting one.
    const ROCK_SUPPORT: RockBitmap = RockBitmap::ROCK_LEFT_RIGHT.union(RockBitmap::ROCK_UP_DOWN);

    /// Natural wind only, for the same reason (`TC_FAN_3_4`).
    const WIND_SUPPORT: WindBitmap = WindBitmap::NATURAL_WIND;

    // Tests restart the device right after a change, so persist at once.
    const PERSIST_DELAY_MS: u32 = 0;

    fn set_fan(&self, setting: FanSetting) -> Result<(), ()> {
        info!("Emulation: fan setting {:?}", setting);

        self.fan.update(|state| state.setting = setting);

        Ok(())
    }

    fn current_speed(&self) -> CurrentSpeed {
        CurrentSpeed::Speed(self.fan.speed())
    }

    /// Every combination of the supported motions is taken as-is. The spec
    /// would let a fan that cannot do a combination fall back to its lowest
    /// bit, but `TC_FAN_2_3` writes a random subset of `RockSupport` and
    /// expects it to read back unchanged.
    fn set_rock_setting(&self, setting: RockBitmap) -> RockBitmap {
        info!("Emulation: rocking {:?}", setting);

        self.fan.update(|state| state.rock = setting);

        setting
    }

    fn set_wind_setting(&self, setting: WindBitmap) -> WindBitmap {
        info!("Emulation: wind {:?}", setting);

        self.fan.update(|state| state.wind = setting);

        setting
    }

    fn set_airflow_direction(&self, direction: AirflowDirectionEnum) {
        info!("Emulation: airflow {:?}", direction);

        self.fan.update(|state| state.direction = direction);
    }

    /// The blades follow the On/Off switch as much as the setting, and the
    /// switch is not this cluster's: say so whenever either moved.
    async fn run<F: Fn(OutOfBandMessage)>(&self, notify: F) {
        loop {
            self.fan.changed.wait().await;

            notify(OutOfBandMessage::CurrentSpeed);
        }
    }
}

/// The On/Off half of the device.
pub struct OnOffDeviceLogic<'a> {
    fan: &'a FanDevice,
}

impl<'a> OnOffDeviceLogic<'a> {
    pub const fn new(fan: &'a FanDevice) -> Self {
        Self { fan }
    }
}

impl OnOffHooks for OnOffDeviceLogic<'_> {
    /// The bare cluster: no `LIGHTING`, which would drag in the timed-off
    /// attributes and commands a fan has no use for.
    const CLUSTER: Cluster<'static> = on_off_cluster::FULL_CLUSTER
        .with_attrs(with!(required))
        .with_cmds(with!(
            on_off_cluster::CommandId::Off
                | on_off_cluster::CommandId::On
                | on_off_cluster::CommandId::Toggle
        ));

    /// Switched on after a factory reset, so that the fan suites find a fan
    /// that turns.
    const ON_OFF: bool = true;

    // Tests restart the device right after a change, so persist at once.
    const PERSIST_DELAY_MS: u32 = 0;

    fn set_on_off(&self, on: bool) {
        info!("Emulation: switch {}", if on { "ON" } else { "OFF" });

        self.fan.update(|state| state.on = on);
    }

    /// `OffWithEffect` belongs to `LIGHTING` and is not served, so this is
    /// never reached; the trait has no default for it.
    async fn handle_off_with_effect(&self, _effect: on_off::EffectVariantEnum) {
        self.set_on_off(false);
    }
}
