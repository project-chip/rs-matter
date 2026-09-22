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

//! Device under test for the chip-tool `thermostat` itest suite
//! (`Test_TC_TSTAT_2_1`, `TC_TSTAT_2_2`, `TC_PWRTL_2_1`, `TC_EPM_2_1`,
//! `TC_EEM_2_1`).
//!
//! Endpoint 1 is a Thermostat (`0x0301`) with the `HEAT` feature only, backed
//! by a simulated room: the local temperature drifts towards the heating
//! setpoint while `SystemMode` is `Heat`, and back towards ambient otherwise.
//! Beside it sits an Electrical Sensor (`0x0510`) metering the simulated 1 kW
//! heating element, as `examples/src/bin/thermostat.rs` does.
//!
//! Structurally the `examples/src/bin/thermostat.rs` device plus the harness
//! plumbing the runner needs — the `--pics-json` dump, the runner's command
//! line overrides, and the four non-volatile attributes kept in the *Matter*
//! KVS rather than a file of their own, so that the factory reset the harness
//! performs between tests really does bring the device back with default
//! application state.
#![allow(clippy::uninlined_format_args)]

use core::cell::Cell;
use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::select3;

use async_signal::{Signal, Signals};
use log::{error, info, trace, warn};

use futures_lite::StreamExt;

use rand::Rng;
use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::elec_energy_meas::{
    self, ElecEnergyMeasHooks, EnergyMeasurement, Timestamp,
};
use rs_matter::dm::clusters::app::elec_pwr_meas::{self, ElecPwrMeasHooks, PowerModeEnum};
use rs_matter::dm::clusters::app::measurement::{MeasurementAccuracy, MeasurementAccuracyRange};
use rs_matter::dm::clusters::app::power_topology::{self, PowerTopologyHandler};
use rs_matter::dm::clusters::app::thermostat::{
    self, ControlSequenceOfOperationEnum, OutOfBandMessage, RelayStateBitmap, SystemModeEnum,
    ThermostatHooks,
};
use rs_matter::dm::clusters::decl::globals::MeasurementTypeEnum;
use rs_matter::dm::clusters::decl::thermostat as thermostat_cluster;
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::gen_diag::GenDiag;
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::identify::{self, IdentifyHandler};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_ELECTRICAL_SENSOR, DEV_TYPE_THERMOSTAT};
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, Cluster, DataModel, Dataver, Endpoint, Node};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::im::{EthInteractionModelState, InteractionModel};
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::sync::blocking::Mutex;
use rs_matter::{clusters, devices, root_endpoint, with, Matter};

use static_cell::StaticCell;

use vendor_kv::VendorKv;

#[path = "../common/args.rs"]
mod args;

#[path = "../common/logging.rs"]
mod logging;

#[path = "../common/mdns.rs"]
mod mdns;

#[path = "../common/vendor_kv.rs"]
mod vendor_kv;

/// The endpoint hosting the thermostat.
const THERMOSTAT_ENDPOINT: u16 = 1;

// Statically allocate in BSS the bigger objects
static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
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

    // Thermostat cluster setup. The Thermostat cluster is not coupled to any
    // other cluster, so there is no `init()` step: validation and the repair of
    // the persisted state happen on the `Startup` lifecycle op.
    // The simulated heating element, shared by the thermostat (which switches
    // it) and the two metering clusters (which report on it).
    let element = HeatingElement::new(&kv);

    let thermostat_handler = thermostat::ThermostatHandler::new(
        Dataver::new_rand(&mut rand),
        THERMOSTAT_ENDPOINT,
        ThermostatDeviceLogic::new(&kv, &element),
    );

    let power_handler = elec_pwr_meas::ElecPwrMeasHandler::new(
        Dataver::new_rand(&mut rand),
        THERMOSTAT_ENDPOINT,
        ElecPwrDeviceLogic::new(&element),
    );

    let energy_handler = elec_energy_meas::ElecEnergyMeasHandler::new(
        Dataver::new_rand(&mut rand),
        THERMOSTAT_ENDPOINT,
        ElecEnergyDeviceLogic::new(&kv, &element),
    );

    // The GeneralDiagnostics test-event triggers, which is how the CHIP
    // energy-reporting suites ask for a changing reading.
    let triggers = TestEventTriggers::new(&element);

    // Create the Data Model instance
    let im = InteractionModel::new(
        matter,
        &crypto,
        buffers,
        data_model(
            rand,
            &thermostat_handler,
            &power_handler,
            &energy_handler,
            &triggers,
        ),
        &kv,
        state,
    );

    // Bring the Data Model to its operational state: re-hydrate its persisted
    // state and deliver the `Startup` lifecycle op to all cluster handlers.
    futures_lite::future::block_on(im.startup())?;

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&im);

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    let mut respond = pin!(responder.run::<4, 4>());

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
/// EP1 carries the Thermostat device type (`0x0301`), whose mandatory cluster
/// set — Descriptor, Identify, Thermostat, plus Groups for a device that does
/// groupcast — is what `TC_DeviceConformance` reads. Beside it, the Electrical
/// Sensor (`0x0510`) adds Power Topology plus the two measurement clusters;
/// being a *utility* device type it shares the endpoint rather than needing one
/// of its own (Core spec 9.2.1), so `TC_DeviceConformance` now checks two
/// device types' cluster sets here.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            THERMOSTAT_ENDPOINT,
            devices!(DEV_TYPE_THERMOSTAT, DEV_TYPE_ELECTRICAL_SENSOR),
            clusters!(
                desc::DescHandler::CLUSTER,
                identify::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                ThermostatDeviceLogic::CLUSTER,
                power_topology::CLUSTER,
                ElecPwrDeviceLogic::CLUSTER,
                ElecEnergyDeviceLogic::CLUSTER,
            ),
        ),
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the thermostat endpoint's clusters.
fn data_model<'a, H: ThermostatHooks, P: ElecPwrMeasHooks, E: ElecEnergyMeasHooks>(
    mut rand: impl Rng + Copy,
    thermostat: &'a thermostat::ThermostatHandler<H>,
    power: &'a elec_pwr_meas::ElecPwrMeasHandler<P>,
    energy: &'a elec_energy_meas::ElecEnergyMeasHandler<E>,
    triggers: &'a TestEventTriggers<'a>,
) -> impl DataModel + 'a {
    (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&SysNetifs)
            .gen_diag(triggers)
            .build(rand)
            .chain(
                |e, c| e == THERMOSTAT_ENDPOINT && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == THERMOSTAT_ENDPOINT && c == identify::CLUSTER.id,
                Async(IdentifyHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == THERMOSTAT_ENDPOINT && c == groups::GroupsHandler::CLUSTER.id,
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == THERMOSTAT_ENDPOINT && c == ThermostatDeviceLogic::CLUSTER.id,
                thermostat::HandlerAsyncAdaptor(thermostat),
            )
            .chain(
                |e, c| e == THERMOSTAT_ENDPOINT && c == power_topology::CLUSTER.id,
                Async(PowerTopologyHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == THERMOSTAT_ENDPOINT && c == ElecPwrDeviceLogic::CLUSTER.id,
                Async(elec_pwr_meas::HandlerAdaptor(power)),
            )
            .chain(
                |e, c| e == THERMOSTAT_ENDPOINT && c == ElecEnergyDeviceLogic::CLUSTER.id,
                Async(elec_energy_meas::HandlerAdaptor(energy)),
            ),
    )
}

// Implementing the Thermostat business logic

/// How often the simulated room temperature is recomputed.
const TICK: embassy_time::Duration = embassy_time::Duration::from_secs(5);

/// How fast the room warms towards the setpoint while heating, in 0.01degC per
/// [`TICK`].
const HEATING_RATE: i16 = 20;

/// How fast the room cools towards [`AMBIENT`] while idle, in 0.01degC per
/// [`TICK`].
const COOLING_RATE: i16 = 10;

/// How often the electrical readings are resampled. Faster than [`TICK`] so
/// that closing the relay shows up promptly in `ActivePower`.
const METER_TICK: embassy_time::Duration = embassy_time::Duration::from_secs(1);

/// The temperature the simulated room drifts to with the heating off, in
/// 0.01degC.
const AMBIENT: i16 = 1600;

/// The rated power of the simulated heating element, in milliwatts.
const ELEMENT_POWER_MW: i64 = 1_000_000;

/// The nominal supply voltage, in millivolts.
const SUPPLY_VOLTAGE_MV: i64 = 230_000;

/// The nominal supply frequency, in millihertz.
const SUPPLY_FREQUENCY_MHZ: i64 = 50_000;

/// A purely resistive load draws all of its current in phase with the supply,
/// so its power factor is unity - 100.00%, in the hundredths of a percent
/// `PowerFactor` is expressed in.
const UNITY_POWER_FACTOR: i64 = 10_000;

/// The top of the metering hardware's measurable ranges.
const MAX_VOLTAGE_MV: i64 = 400_000;
const MAX_CURRENT_MA: i64 = 16_000;
const MAX_POWER_MW: i64 = 3_680_000;

/// The top of the lifetime energy counter's range, in milliwatt-hours.
///
/// The counter is an `i64` of milliwatt-*seconds*, so this is where it rolls
/// over - which is what `MaxMeasuredValue` is asking for. (Quoting `i64::MAX`
/// there, as this used to, claims a range the counter cannot reach.)
const MAX_ENERGY_MWH: i64 = i64::MAX / 3600;

/// The top of the `Frequency` and `PowerFactor` ranges, which the spec fixes
/// rather than the hardware.
const MAX_FREQUENCY_MHZ: i64 = 1_000_000;
const MAX_POWER_FACTOR: i64 = 10_000;

/// How accurate the simulated meter claims to be, in hundredths of a percent.
const METER_ACCURACY: u16 = 500;

/// One `Accuracy` entry: a quantity the simulated meter reads across
/// `0..=$max`, at [`METER_ACCURACY`] throughout that range.
///
/// Section 2.13.6.3's list is what tells a client which quantities the meter
/// actually measures, so it has to carry an entry for every reading served -
/// which is why it is as long as it is.
macro_rules! meter_accuracy {
    ($type:ident, $max:expr) => {
        MeasurementAccuracy::new(
            MeasurementTypeEnum::$type,
            0,
            $max,
            &[MeasurementAccuracyRange::percent(0, $max, METER_ACCURACY)],
        )
    };
}

/// How long a measurement period runs while the element is on its own relay.
const PERIOD_MS: u64 = 5_000;

/// How long one runs while a test-event fake load is switched in. The CHIP
/// energy-reporting suites read a reading, wait three seconds and read again,
/// so a period has to close well inside that window.
const FAKE_PERIOD_MS: u64 = 1_000;

/// The `EnableKey` the CHIP test harness sends unless it is given
/// `--hex-arg enableKey:<hex>`: the sixteen bytes `00..0f`. The Matter Core
/// spec requires the server to reject a `TestEventTrigger` whose key does not
/// match the one it was configured with.
const TEST_EVENT_ENABLE_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

/// The energy-reporting test-event triggers, as
/// `src/app/clusters/electrical-energy-measurement-server/EnergyReportingTestEventTriggerHandler.h`
/// defines them.
const TRIGGER_FAKE_READINGS_STOP: u64 = 0x0091_0000_0000_0000;
const TRIGGER_FAKE_LOAD_1KW: u64 = 0x0091_0000_0000_0001;
const TRIGGER_FAKE_GENERATOR_3KW: u64 = 0x0091_0000_0000_0002;

/// Bits 32..=47 of an event trigger carry the endpoint it is aimed at; the
/// harness fills them in from its own `--endpoint` argument
/// (`MatterBaseTest._update_legacy_test_event_triggers`), and zero means "the
/// device", as the pre-1.4 triggers did.
const TRIGGER_ENDPOINT_MASK: u64 = 0xFFFF << 32;

/// The sweep the fake load's readings walk, in milliwatts around
/// [`ELEMENT_POWER_MW`] and millivolts around [`SUPPLY_VOLTAGE_MV`].
///
/// The SDK's own fake readings pick a *random* value in a +/-20 W, +/-1 V band
/// around the same means, and `TC_EPM_2_2` and `TC_EEM_2_4` then assert that
/// two readings three seconds apart differ. A sweep stays inside the bands
/// those tests check while making "differ" a certainty rather than a
/// probability: four steps, sampled once a second, never repeat across a
/// three-second gap.
const FAKE_POWER_OFFSETS_MW: [i64; 4] = [-18_000, -6_000, 6_000, 18_000];
const FAKE_VOLTAGE_OFFSETS_MV: [i64; 4] = [-900, -300, 300, 900];

/// What a measurement tick moved, as [`HeatingElement::accumulate`] reports it.
///
/// The two readings do not move together: the lifetime counter only changes
/// when the running total crosses a whole milliwatt-hour, while a measurement
/// period closes whenever the element ran during it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Accumulated {
    /// `CumulativeEnergyImported` changed.
    cumulative: bool,
    /// A new `PeriodicEnergyImported` reading is available.
    periodic: bool,
}

/// The simulated heating element: the load the thermostat switches and the two
/// Electrical Sensor clusters report on.
///
/// Its lifetime energy counter lives in the Matter KVS, so the harness's
/// factory reset between tests clears it along with everything else. The
/// element only reads it, at construction; the one loop that closes a
/// measurement period - [`ElecEnergyDeviceLogic::run`] - writes it back.
pub struct HeatingElement {
    state: Mutex<RefCell<ElementState>>,
    /// Whether the lifetime counter started this boot at zero because there
    /// was nothing to restore - which, for a device whose counter lives in the
    /// Matter KVS, is what a factory reset leaves behind. Fixed at
    /// construction, so it needs no lock.
    reset_at_boot: bool,
}

/// The element's state, behind one lock the way `on_off` keeps its own.
///
/// It has to be a lock rather than a set of `Cell`s: the element is reachable
/// from the `GenDiag` hook below, which the data model takes as a `dyn` trait
/// object, and every `rs-matter` `dyn` trait extends `DynBase` - which under
/// the `sync-mutex` feature means `Send + Sync`. Without that feature the
/// mutex is a `NoopRawMutex` and costs nothing.
struct ElementState {
    /// Whether the relay is closed and the element is drawing power.
    heating: bool,
    /// The fake load a `TestEventTrigger` has switched in, if any, as the
    /// index of its sweep step. `None` means the readings come from the real
    /// relay.
    fake: Option<usize>,
    /// When the energy counters were last brought up to date, in milliseconds
    /// since boot.
    mark_ms: u64,
    /// Energy drawn in the open measurement period, in milliwatt-seconds.
    period_mws: i64,
    /// When the open measurement period began, in milliseconds since boot.
    period_start_ms: u64,
    /// The last measurement period that actually drew something: the energy
    /// in it, in milliwatt-hours, and the window it covers in milliseconds
    /// since boot. `None` until the element has run at all, which is what
    /// makes `PeriodicEnergyImported` report null on a freshly reset device.
    period: Option<(i64, u64, u64)>,
    /// Energy drawn over the device's lifetime, in milliwatt-*seconds* so that
    /// a whole number of seconds at a whole number of milliwatts stays exact.
    energy_mws: i64,
    /// The lifetime figure, in milliwatt-hours, as last reported - so that a
    /// closing period can say whether `CumulativeEnergyImported` moved.
    reported_mwh: i64,
}

impl ElementState {
    /// Whether a test-event fake load is currently switched in.
    fn faking(&self) -> bool {
        self.fake.is_some()
    }

    /// The power drawn right now, in milliwatts.
    fn active_power_mw(&self) -> i64 {
        match self.fake {
            Some(step) => {
                ELEMENT_POWER_MW + FAKE_POWER_OFFSETS_MW[step % FAKE_POWER_OFFSETS_MW.len()]
            }
            None if self.heating => ELEMENT_POWER_MW,
            None => 0,
        }
    }

    /// The supply voltage right now, in millivolts. Nominal unless a fake load
    /// is sweeping it.
    fn voltage_mv(&self) -> i64 {
        match self.fake {
            Some(step) => {
                SUPPLY_VOLTAGE_MV + FAKE_VOLTAGE_OFFSETS_MV[step % FAKE_VOLTAGE_OFFSETS_MV.len()]
            }
            None => SUPPLY_VOLTAGE_MV,
        }
    }

    /// The current drawn right now, in milliamps, derived from the power and
    /// the supply voltage so the three reported readings stay consistent.
    fn active_current_ma(&self) -> i64 {
        self.active_power_mw() * 1000 / self.voltage_mv()
    }

    /// The energy drawn over the device's lifetime, in milliwatt-hours.
    fn energy_mwh(&self) -> i64 {
        self.energy_mws / 3600
    }

    /// Bring both energy counters up to now, at the power drawn since the last
    /// time this ran.
    ///
    /// A real meter integrates continuously; this one integrates once per
    /// sample, which is the same thing as long as the power only changes at a
    /// sample boundary - and every path that changes it does this first.
    fn integrate(&mut self) {
        let now = embassy_time::Instant::now().as_millis();
        let elapsed_ms = now.saturating_sub(self.mark_ms) as i64;

        self.mark_ms = now;

        let drawn_mws = self.active_power_mw() * elapsed_ms / 1000;

        self.energy_mws += drawn_mws;
        self.period_mws += drawn_mws;
    }

    /// Restart the open measurement period as of `now`.
    fn restart_period(&mut self, now: u64) {
        self.mark_ms = now;
        self.period_mws = 0;
        self.period_start_ms = now;
        self.period = None;
    }
}

impl HeatingElement {
    pub fn new(kv: &dyn VendorKv) -> Self {
        let mut buf = [0u8; 8];

        let (energy_mws, reset_at_boot) =
            match kv.load_blob(vendor_kv::HEATING_ELEMENT_ENERGY_KEY, &mut buf) {
                Ok(Some(8)) => (i64::from_le_bytes(buf), false),
                _ => (0, true),
            };

        let now = embassy_time::Instant::now().as_millis();

        Self {
            state: Mutex::new(RefCell::new(ElementState {
                heating: false,
                fake: None,
                mark_ms: now,
                period_mws: 0,
                period_start_ms: now,
                period: None,
                energy_mws,
                reported_mwh: energy_mws / 3600,
            })),
            reset_at_boot,
        }
    }

    /// Open or close the relay.
    fn set_heating(&self, heating: bool) {
        let changed = self.state.lock(|state| {
            let mut state = state.borrow_mut();

            // Bring the counters up to date at the old power before the relay
            // changes it.
            state.integrate();

            let changed = state.heating != heating;
            state.heating = heating;

            changed
        });

        if changed {
            info!("Emulation: heating {}", if heating { "ON" } else { "OFF" });
        }
    }

    /// Switch in the fake 1 kW load a `TestEventTrigger` asks for, or - with
    /// `None` - hand the readings back to the real relay.
    ///
    /// Either way the open measurement period is restarted, which is what the
    /// SDK's own fake readings do (`bReset = true`): a period straddling the
    /// switch would report energy at a power that was never drawn for all of
    /// it.
    fn set_fake_load(&self, fake: Option<usize>) {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();

            state.integrate();
            state.fake = fake;

            state.restart_period(embassy_time::Instant::now().as_millis());
        });
    }

    /// Whether the element is currently drawing power.
    fn heating(&self) -> bool {
        self.state.lock(|state| state.borrow().heating)
    }

    /// The power drawn right now, in milliwatts.
    fn active_power_mw(&self) -> i64 {
        self.state.lock(|state| state.borrow().active_power_mw())
    }

    /// The supply voltage right now, in millivolts. Nominal unless a fake load
    /// is sweeping it.
    fn voltage_mv(&self) -> i64 {
        self.state.lock(|state| state.borrow().voltage_mv())
    }

    /// The current drawn right now, in milliamps, derived from the power and
    /// the supply voltage so the three reported readings stay consistent.
    fn active_current_ma(&self) -> i64 {
        self.state.lock(|state| state.borrow().active_current_ma())
    }

    /// The energy drawn over the device's lifetime, in milliwatt-*seconds*:
    /// the unit the counter is persisted in.
    fn energy_mws(&self) -> i64 {
        self.state.lock(|state| state.borrow().energy_mws)
    }

    /// The energy drawn over the device's lifetime, in milliwatt-hours.
    fn energy_mwh(&self) -> i64 {
        self.state.lock(|state| state.borrow().energy_mwh())
    }

    /// When the lifetime counter was last zeroed, as far as this device can
    /// tell.
    ///
    /// It has no wall clock and no record of resets before the current boot,
    /// so the only reset it can date is the one it came up from: the counter
    /// was restored as empty, which is what a factory reset leaves. Anything
    /// earlier is unknown, and reads as null.
    fn reset_at(&self) -> Option<Timestamp> {
        self.reset_at_boot.then(|| Timestamp::systime(0))
    }

    /// The last measurement period that drew anything: its energy in
    /// milliwatt-hours, and the window it covers in milliseconds since boot.
    fn last_period(&self) -> Option<(i64, u64, u64)> {
        self.state.lock(|state| state.borrow().period)
    }

    /// One sampling step of the meter: integrate what has been drawn since the
    /// last one, then advance a fake load's sweep so the next sample reads
    /// differently.
    fn sample(&self) {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();

            state.integrate();

            if let Some(step) = state.fake {
                state.fake = Some(step.wrapping_add(1));
            }
        });
    }

    /// Close the open measurement period if it has run its course, and report
    /// which readings moved.
    ///
    /// Whether the period is due and the closing of it are one step under one
    /// lock: asking first and closing afterwards would let the answer go stale
    /// in between.
    fn close_period_if_due(&self) -> Option<Accumulated> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();

            // Shorter while a test-event fake load is switched in, because the
            // CHIP energy suites read twice three seconds apart.
            let length = if state.faking() {
                FAKE_PERIOD_MS
            } else {
                PERIOD_MS
            };

            let end = embassy_time::Instant::now().as_millis();

            if end - state.period_start_ms < length {
                return None;
            }

            state.integrate();

            let start = state.period_start_ms;
            let drawn_mws = state.period_mws;

            state.period_start_ms = end;
            state.period_mws = 0;

            // A period in which nothing was drawn carries no information, and
            // publishing one every tick would have an idle device emitting
            // `PeriodicEnergyMeasured` forever. The window is still advanced,
            // so the next period covers only the time the element actually ran.
            if drawn_mws == 0 {
                return Some(Accumulated::default());
            }

            state.period = Some((drawn_mws / 3600, start, end));

            let energy_mwh = state.energy_mwh();
            let reported = state.reported_mwh;

            state.reported_mwh = energy_mwh;

            Some(Accumulated {
                cumulative: energy_mwh != reported,
                periodic: true,
            })
        })
    }
}

/// The four non-volatile Thermostat attributes, as they are laid out in the
/// KVS blob under [`vendor_kv::THERMOSTAT_STATE_KEY`].
struct ThermostatPersistentState {
    system_mode: SystemModeEnum,
    occupied_heating_setpoint: i16,
    min_heat_setpoint_limit: i16,
    max_heat_setpoint_limit: i16,
}

impl ThermostatPersistentState {
    const LEN: usize = 7;

    fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut buf = [0u8; Self::LEN];

        buf[0] = self.system_mode as u8;
        buf[1..3].copy_from_slice(&self.occupied_heating_setpoint.to_le_bytes());
        buf[3..5].copy_from_slice(&self.min_heat_setpoint_limit.to_le_bytes());
        buf[5..7].copy_from_slice(&self.max_heat_setpoint_limit.to_le_bytes());

        buf
    }

    fn from_bytes(buf: &[u8; Self::LEN]) -> Option<Self> {
        // Only the two modes a heating-only thermostat can be in; anything
        // else would be rejected by the handler's startup repair anyway.
        let system_mode = match buf[0] {
            m if m == SystemModeEnum::Off as u8 => SystemModeEnum::Off,
            m if m == SystemModeEnum::Heat as u8 => SystemModeEnum::Heat,
            _ => {
                trace!("Thermostat: persisted SystemMode is not a supported value");
                return None;
            }
        };

        Some(Self {
            system_mode,
            occupied_heating_setpoint: i16::from_le_bytes([buf[1], buf[2]]),
            min_heat_setpoint_limit: i16::from_le_bytes([buf[3], buf[4]]),
            max_heat_setpoint_limit: i16::from_le_bytes([buf[5], buf[6]]),
        })
    }
}

impl Default for ThermostatPersistentState {
    fn default() -> Self {
        Self {
            system_mode: SystemModeEnum::Off,
            occupied_heating_setpoint: 2000,
            min_heat_setpoint_limit: ThermostatDeviceLogic::ABS_MIN_HEAT_SETPOINT,
            max_heat_setpoint_limit: ThermostatDeviceLogic::ABS_MAX_HEAT_SETPOINT,
        }
    }
}

/// A simulated heating thermostat, with the four non-volatile attributes kept
/// in the Matter KVS.
pub struct ThermostatDeviceLogic<'a> {
    state: Mutex<RefCell<ThermostatState>>,
    /// The load this thermostat switches. Its relay flag is the thermostat's
    /// output and the meters' input.
    element: &'a HeatingElement,
    kv: &'a dyn VendorKv,
}

/// The thermostat's own state, behind one lock - see [`ElementState`].
struct ThermostatState {
    /// Volatile: a sensor reading, recomputed from [`AMBIENT`] on every boot.
    local_temperature: i16,
    occupied_heating_setpoint: i16,
    min_heat_setpoint_limit: i16,
    max_heat_setpoint_limit: i16,
    system_mode: SystemModeEnum,
}

impl<'a> ThermostatDeviceLogic<'a> {
    pub fn new(kv: &'a dyn VendorKv, element: &'a HeatingElement) -> Self {
        let mut buf = [0u8; ThermostatPersistentState::LEN];

        let state = match kv.load_blob(vendor_kv::THERMOSTAT_STATE_KEY, &mut buf) {
            Ok(Some(ThermostatPersistentState::LEN)) => {
                ThermostatPersistentState::from_bytes(&buf).unwrap_or_default()
            }
            _ => ThermostatPersistentState::default(),
        };

        Self {
            state: Mutex::new(RefCell::new(ThermostatState {
                local_temperature: AMBIENT,
                occupied_heating_setpoint: state.occupied_heating_setpoint,
                min_heat_setpoint_limit: state.min_heat_setpoint_limit,
                max_heat_setpoint_limit: state.max_heat_setpoint_limit,
                system_mode: state.system_mode,
            })),
            element,
            kv,
        }
    }

    fn save_state(&self) -> Result<(), Error> {
        let state = self.state.lock(|state| {
            let state = state.borrow();

            ThermostatPersistentState {
                system_mode: state.system_mode,
                occupied_heating_setpoint: state.occupied_heating_setpoint,
                min_heat_setpoint_limit: state.min_heat_setpoint_limit,
                max_heat_setpoint_limit: state.max_heat_setpoint_limit,
            }
        });

        self.kv
            .store_blob(vendor_kv::THERMOSTAT_STATE_KEY, &state.to_bytes())
    }

    /// Advance the room simulation by one [`TICK`], returning `true` if the
    /// local temperature changed.
    fn tick(&self) -> bool {
        let heating = self.element.heating();

        let (previous, temperature) = self.state.lock(|state| {
            let mut state = state.borrow_mut();

            let previous = state.local_temperature;

            let temperature = if heating {
                previous.saturating_add(HEATING_RATE)
            } else {
                previous.saturating_sub(COOLING_RATE).max(AMBIENT)
            };

            state.local_temperature = temperature;

            (previous, temperature)
        });

        // Out of the lock: the relay is the element's state, not ours.
        self.update_relay();

        temperature != previous
    }

    /// Re-evaluate the heat demand, with a one-notch hysteresis band around the
    /// setpoint so the simulated relay does not chatter every tick.
    fn update_relay(&self) {
        let (system_mode, setpoint, temperature) = self.state.lock(|state| {
            let state = state.borrow();

            (
                state.system_mode,
                state.occupied_heating_setpoint,
                state.local_temperature,
            )
        });

        let heating = matches!(system_mode, SystemModeEnum::Heat)
            && if self.element.heating() {
                temperature < setpoint.saturating_add(HEATING_RATE)
            } else {
                temperature < setpoint.saturating_sub(HEATING_RATE)
            };

        self.element.set_heating(heating);
    }
}

impl ThermostatHooks for ThermostatDeviceLogic<'_> {
    /// A heating-only thermostat: the `HEAT` feature alone, the four mandatory
    /// attributes plus the optional heat setpoint limits, and the one mandatory
    /// command. See the `rs_matter::dm::clusters::app::thermostat` module docs
    /// for why the limits come as a set of four.
    const CLUSTER: Cluster<'static> = thermostat_cluster::FULL_CLUSTER
        .with_revision(11)
        .with_features(thermostat_cluster::Feature::HEATING.bits())
        .with_attrs(with!(
            required;
            thermostat_cluster::AttributeId::AbsMinHeatSetpointLimit
                | thermostat_cluster::AttributeId::AbsMaxHeatSetpointLimit
                | thermostat_cluster::AttributeId::OccupiedHeatingSetpoint
                | thermostat_cluster::AttributeId::MinHeatSetpointLimit
                | thermostat_cluster::AttributeId::MaxHeatSetpointLimit
                | thermostat_cluster::AttributeId::ThermostatRunningState
        ))
        .with_cmds(with!(thermostat_cluster::CommandId::SetpointRaiseLower))
        .with_events(with!());

    const CONTROL_SEQUENCE_OF_OPERATION: ControlSequenceOfOperationEnum =
        ControlSequenceOfOperationEnum::HeatingOnly;

    fn local_temperature(&self) -> Option<i16> {
        Some(self.state.lock(|state| state.borrow().local_temperature))
    }

    fn occupied_heating_setpoint(&self) -> i16 {
        self.state
            .lock(|state| state.borrow().occupied_heating_setpoint)
    }

    fn set_occupied_heating_setpoint(&self, value: i16) -> Result<(), Error> {
        self.state
            .lock(|state| state.borrow_mut().occupied_heating_setpoint = value);
        self.save_state()
    }

    fn min_heat_setpoint_limit(&self) -> i16 {
        self.state
            .lock(|state| state.borrow().min_heat_setpoint_limit)
    }

    fn set_min_heat_setpoint_limit(&self, value: i16) -> Result<(), Error> {
        self.state
            .lock(|state| state.borrow_mut().min_heat_setpoint_limit = value);
        self.save_state()
    }

    fn max_heat_setpoint_limit(&self) -> i16 {
        self.state
            .lock(|state| state.borrow().max_heat_setpoint_limit)
    }

    fn set_max_heat_setpoint_limit(&self, value: i16) -> Result<(), Error> {
        self.state
            .lock(|state| state.borrow_mut().max_heat_setpoint_limit = value);
        self.save_state()
    }

    fn system_mode(&self) -> SystemModeEnum {
        self.state.lock(|state| state.borrow().system_mode)
    }

    fn set_system_mode(&self, value: SystemModeEnum) -> Result<(), Error> {
        self.state
            .lock(|state| state.borrow_mut().system_mode = value);
        self.save_state()
    }

    /// The simulated equipment is a single-stage heater with no fan, so the
    /// only relay it can ever have energised is `Heat` - and the element the
    /// metering clusters watch is the relay, so it can answer for itself.
    fn running_state(&self) -> RelayStateBitmap {
        if self.element.heating() {
            RelayStateBitmap::HEAT
        } else {
            RelayStateBitmap::empty()
        }
    }

    /// A heating-only device: the cooling setpoint is whatever the hook
    /// default returns, and means nothing here.
    fn apply(&self, system_mode: SystemModeEnum, heating_setpoint: i16, _cooling_setpoint: i16) {
        let temperature = self.state.lock(|state| state.borrow().local_temperature);

        info!(
            "Emulation: system mode {:?}, heating setpoint {}.{:02}C, room {}.{:02}C",
            system_mode,
            heating_setpoint / 100,
            (heating_setpoint % 100).abs(),
            temperature / 100,
            (temperature % 100).abs(),
        );

        // Re-evaluate the relay immediately rather than waiting a tick, so that
        // switching to `Heat` has a visible effect right away.
        self.update_relay();
    }

    async fn run<F: Fn(OutOfBandMessage)>(&self, notify: F) {
        loop {
            // In a real device we would wait on a temperature sensor.
            embassy_time::Timer::after(TICK).await;

            let heating = self.element.heating();

            if self.tick() {
                notify(OutOfBandMessage::LocalTemperature);
            }

            // The hysteresis band can move the relay with nobody having
            // written anything, so this is the one relay transition the
            // handler cannot see for itself.
            if self.element.heating() != heating {
                notify(OutOfBandMessage::RunningState);
            }
        }
    }
}

// Implementing the General Diagnostics test-event triggers

/// The device's `GenDiag` hook, which exists for one reason: the CHIP
/// energy-reporting suites (`TC_EPM_2_2`, `TC_EEM_2_2`, `TC_EEM_2_4`) drive a
/// *changing* reading, and the only way they have of asking a DUT for one is
/// the GeneralDiagnostics `TestEventTrigger` command. Without it those suites
/// can only read a device sitting still.
///
/// `TestEventTriggersEnabled` is therefore true here. That is a
/// certification-harness setting, not a production one: the Matter Core spec
/// requires a device with test event triggers enabled to be out of normal
/// operation, which is exactly what this binary is.
pub struct TestEventTriggers<'a> {
    element: &'a HeatingElement,
}

impl<'a> TestEventTriggers<'a> {
    pub const fn new(element: &'a HeatingElement) -> Self {
        Self { element }
    }
}

impl rs_matter::utils::sync::DynBase for TestEventTriggers<'_> {}

impl GenDiag for TestEventTriggers<'_> {
    fn test_event_triggers_enabled(&self) -> Result<bool, Error> {
        Ok(true)
    }

    fn test_event_trigger(&self, key: &[u8], trigger: u64) -> Result<(), Error> {
        // Matter Core spec: the command SHALL be rejected with
        // CONSTRAINT_ERROR when the EnableKey does not match the one the
        // device was configured with.
        if key != TEST_EVENT_ENABLE_KEY {
            warn!("TestEventTrigger: wrong EnableKey");
            Err(ErrorCode::ConstraintError)?;
        }

        // Split off the endpoint the trigger is aimed at. The meters live on
        // the one endpoint this device has besides the root, so anything else
        // is a trigger for hardware that is not here.
        let endpoint = ((trigger & TRIGGER_ENDPOINT_MASK) >> 32) as u16;

        if endpoint != 0 && endpoint != THERMOSTAT_ENDPOINT {
            warn!("TestEventTrigger: no such endpoint: {}", endpoint);
            Err(ErrorCode::InvalidCommand)?;
        }

        match trigger & !TRIGGER_ENDPOINT_MASK {
            TRIGGER_FAKE_LOAD_1KW => {
                info!("TestEventTrigger: starting the fake 1kW load");
                self.element.set_fake_load(Some(0));
            }
            TRIGGER_FAKE_READINGS_STOP => {
                info!("TestEventTrigger: stopping the fake readings");
                self.element.set_fake_load(None);
            }
            // The 3 kW generator is an *export*, and this device serves no
            // exported-energy attribute to put it in.
            TRIGGER_FAKE_GENERATOR_3KW => {
                warn!("TestEventTrigger: the fake generator needs the EXPE feature");
                Err(ErrorCode::InvalidCommand)?;
            }
            _ => {
                warn!("TestEventTrigger: unknown trigger 0x{:016x}", trigger);
                Err(ErrorCode::InvalidCommand)?;
            }
        }

        Ok(())
    }
}

// Implementing the Electrical Power Measurement business logic

/// What the element is drawing right now.
pub struct ElecPwrDeviceLogic<'a> {
    element: &'a HeatingElement,
    /// The last `ActivePower` handed to a subscriber, so `run` only notifies
    /// when the reading actually moved.
    reported_power_mw: Mutex<Cell<i64>>,
}

impl<'a> ElecPwrDeviceLogic<'a> {
    pub fn new(element: &'a HeatingElement) -> Self {
        Self {
            element,
            reported_power_mw: Mutex::new(Cell::new(element.active_power_mw())),
        }
    }
}

impl ElecPwrMeasHooks for ElecPwrDeviceLogic<'_> {
    /// A single-phase AC load: the `AC` feature, the four mandatory attributes
    /// and the two optional readings that make the power figure checkable.
    const CLUSTER: Cluster<'static> = elec_pwr_meas::FULL_CLUSTER
        .with_revision(3)
        .with_features(elec_pwr_meas::Feature::ALTERNATING_CURRENT.bits())
        .with_attrs(with!(
            required;
            elec_pwr_meas::AttributeId::Voltage
                | elec_pwr_meas::AttributeId::ActiveCurrent
                | elec_pwr_meas::AttributeId::ReactiveCurrent
                | elec_pwr_meas::AttributeId::ApparentCurrent
                | elec_pwr_meas::AttributeId::ReactivePower
                | elec_pwr_meas::AttributeId::ApparentPower
                | elec_pwr_meas::AttributeId::RMSVoltage
                | elec_pwr_meas::AttributeId::RMSCurrent
                | elec_pwr_meas::AttributeId::RMSPower
                | elec_pwr_meas::AttributeId::Frequency
                | elec_pwr_meas::AttributeId::PowerFactor
        ))
        .with_cmds(with!())
        .with_events(with!());

    const POWER_MODE: PowerModeEnum = PowerModeEnum::AC;

    const ACCURACY: &'static [MeasurementAccuracy] = &[
        meter_accuracy!(Voltage, MAX_VOLTAGE_MV),
        meter_accuracy!(RMSVoltage, MAX_VOLTAGE_MV),
        meter_accuracy!(ActiveCurrent, MAX_CURRENT_MA),
        meter_accuracy!(ReactiveCurrent, MAX_CURRENT_MA),
        meter_accuracy!(ApparentCurrent, MAX_CURRENT_MA),
        meter_accuracy!(RMSCurrent, MAX_CURRENT_MA),
        meter_accuracy!(ActivePower, MAX_POWER_MW),
        meter_accuracy!(ReactivePower, MAX_POWER_MW),
        meter_accuracy!(ApparentPower, MAX_POWER_MW),
        meter_accuracy!(RMSPower, MAX_POWER_MW),
        meter_accuracy!(Frequency, MAX_FREQUENCY_MHZ),
        meter_accuracy!(PowerFactor, MAX_POWER_FACTOR),
    ];

    fn active_power(&self) -> Option<i64> {
        Some(self.element.active_power_mw())
    }

    fn voltage(&self) -> Option<i64> {
        Some(self.element.voltage_mv())
    }

    fn active_current(&self) -> Option<i64> {
        Some(self.element.active_current_ma())
    }

    // A resistive element on a sinusoidal supply draws all of its current in
    // phase: the RMS readings are the readings, the apparent quantities equal
    // the active ones, and nothing is reactive. Real metering hardware would
    // measure each of these rather than deriving them, which is the whole
    // reason the spec has them as separate readings.

    fn rms_voltage(&self) -> Option<i64> {
        Some(self.element.voltage_mv())
    }

    fn rms_current(&self) -> Option<i64> {
        Some(self.element.active_current_ma())
    }

    fn rms_power(&self) -> Option<i64> {
        Some(self.element.active_power_mw())
    }

    fn apparent_current(&self) -> Option<i64> {
        Some(self.element.active_current_ma())
    }

    fn apparent_power(&self) -> Option<i64> {
        Some(self.element.active_power_mw())
    }

    fn reactive_current(&self) -> Option<i64> {
        Some(0)
    }

    fn reactive_power(&self) -> Option<i64> {
        Some(0)
    }

    fn frequency(&self) -> Option<i64> {
        Some(SUPPLY_FREQUENCY_MHZ)
    }

    fn power_factor(&self) -> Option<i64> {
        Some(UNITY_POWER_FACTOR)
    }

    async fn run<F: Fn(elec_pwr_meas::OutOfBandMessage)>(&self, notify: F) {
        loop {
            embassy_time::Timer::after(METER_TICK).await;

            // This loop is the meter's sample clock: it integrates the energy
            // drawn since the last sample and advances a fake load's sweep.
            // The energy cluster's own loop only closes periods.
            self.element.sample();

            let power = self.element.active_power_mw();

            if power != self.reported_power_mw.lock(|reported| reported.get()) {
                self.reported_power_mw.lock(|reported| reported.set(power));

                // `Voltage` and `ActiveCurrent` move with the same sample, so
                // all three readings are re-reported together.
                notify(elec_pwr_meas::OutOfBandMessage::Update);
            }
        }
    }
}

// Implementing the Electrical Energy Measurement business logic

/// What the element has drawn over the device's lifetime.
pub struct ElecEnergyDeviceLogic<'a> {
    element: &'a HeatingElement,
    kv: &'a dyn VendorKv,
}

impl<'a> ElecEnergyDeviceLogic<'a> {
    pub fn new(kv: &'a dyn VendorKv, element: &'a HeatingElement) -> Self {
        Self { element, kv }
    }

    /// Write the element's lifetime energy counter to the KVS.
    ///
    /// The counter is the backing store of `CumulativeEnergyImported`, and
    /// this cluster's loop is the only thing that closes a measurement period,
    /// so this is the one place it has to be saved from.
    fn save_energy(&self) {
        if let Err(err) = self.kv.store_blob(
            vendor_kv::HEATING_ELEMENT_ENERGY_KEY,
            &self.element.energy_mws().to_le_bytes(),
        ) {
            error!("Error saving the energy counter: {}", err);
        }
    }
}

impl ElecEnergyMeasHooks for ElecEnergyDeviceLogic<'_> {
    /// Imported energy, both ways round: `IMPE | CUME | PERE`. Each of the
    /// latter two brings an attribute and makes the matching event mandatory -
    /// the lifetime total the device has drawn, and the energy of the most
    /// recent measurement period.
    const CLUSTER: Cluster<'static> = elec_energy_meas::FULL_CLUSTER
        .with_revision(2)
        .with_features(
            elec_energy_meas::Feature::IMPORTED_ENERGY.bits()
                | elec_energy_meas::Feature::CUMULATIVE_ENERGY.bits()
                | elec_energy_meas::Feature::PERIODIC_ENERGY.bits(),
        )
        .with_attrs(with!(
            required;
            elec_energy_meas::AttributeId::CumulativeEnergyImported
                | elec_energy_meas::AttributeId::PeriodicEnergyImported
                | elec_energy_meas::AttributeId::CumulativeEnergyReset
        ))
        .with_cmds(with!())
        .with_events(with!(
            elec_energy_meas::EventId::CumulativeEnergyMeasured
                | elec_energy_meas::EventId::PeriodicEnergyMeasured
        ));

    const ACCURACY: MeasurementAccuracy = meter_accuracy!(ElectricalEnergy, MAX_ENERGY_MWH);

    fn cumulative_energy_imported(&self) -> Option<EnergyMeasurement> {
        // This device has no wall clock, so the reading is located in time by
        // uptime alone - which is what section 2.12.5.2.5 asks for.
        Some(EnergyMeasurement::cumulative(
            self.element.energy_mwh(),
            Timestamp::systime(embassy_time::Instant::now().as_millis()),
        ))
    }

    fn cumulative_energy_reset(&self) -> Option<Timestamp> {
        self.element.reset_at()
    }

    /// Section 2.12.5.2: a periodic reading needs both ends of its window.
    /// This device has no wall clock, so both are uptimes.
    fn periodic_energy_imported(&self) -> Option<EnergyMeasurement> {
        let (energy, start, end) = self.element.last_period()?;

        Some(EnergyMeasurement::periodic(
            energy,
            Timestamp::systime(start),
            Timestamp::systime(end),
        ))
    }

    async fn run<F: Fn(elec_energy_meas::OutOfBandMessage)>(&self, notify: F) {
        loop {
            // Woken on the meter's sample clock, but a period only closes
            // once it has run its course.
            embassy_time::Timer::after(METER_TICK).await;

            let Some(moved) = self.element.close_period_if_due() else {
                continue;
            };

            // A period that drew something advanced the lifetime counter too,
            // whether or not it moved by a whole milliwatt-hour.
            if moved.periodic {
                self.save_energy();
            }

            // Two notifications from one tick, which the handler's pending
            // mask keeps apart - see `elec_energy_meas::OutOfBandMessage`.
            if moved.cumulative {
                notify(elec_energy_meas::OutOfBandMessage::CumulativeEnergyImported);
            }

            if moved.periodic {
                notify(elec_energy_meas::OutOfBandMessage::PeriodicEnergyImported);
            }
        }
    }
}
