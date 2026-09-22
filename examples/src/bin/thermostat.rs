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

//! An example Matter device implementing the heating-only Thermostat cluster
//! over Ethernet, metering its own heating element.
//!
//! Endpoint 1 carries two device types. The Thermostat (`0x0301`, `HEAT`) is
//! backed by a simulated room: the local temperature drifts towards the heating
//! setpoint while `SystemMode` is `Heat`, and back towards ambient otherwise.
//! Beside it sits an Electrical Sensor (`0x0510`) — a *utility* device type, so
//! the two share an endpoint — reporting a dummy 1 kW heating element through
//! Power Topology, Electrical Power Measurement and Electrical Energy
//! Measurement: what the element draws while the relay is closed, and how much
//! energy it has drawn over the device's lifetime.
//!
//! Drive it with `chip-tool` once commissioned, e.g.
//!
//! ```sh
//! chip-tool thermostat read occupied-heating-setpoint <node-id> 1
//! chip-tool thermostat write system-mode 4 <node-id> 1
//! chip-tool thermostat setpoint-raise-lower 0 10 <node-id> 1
//! chip-tool thermostat subscribe local-temperature 1 10 <node-id> 1
//!
//! chip-tool electricalpowermeasurement read active-power <node-id> 1
//! chip-tool electricalenergymeasurement read cumulative-energy-imported <node-id> 1
//! chip-tool electricalenergymeasurement subscribe-event cumulative-energy-measured 1 10 <node-id> 1
//! ```
#![allow(clippy::uninlined_format_args)]

use core::cell::Cell;
use core::pin::pin;

use std::fs;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::path::PathBuf;

use embassy_futures::select::select3;

use async_signal::{Signal, Signals};
use log::{error, info, trace};

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
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::identify::{self, IdentifyHandler};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_ELECTRICAL_SENSOR, DEV_TYPE_THERMOSTAT};
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
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::sync::blocking::Mutex;
use rs_matter::{clusters, devices, root_endpoint, with, Matter, MATTER_PORT};

#[path = "../common/mdns.rs"]
mod mdns;

/// The endpoint hosting the thermostat.
const THERMOSTAT_ENDPOINT: u16 = 1;

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    // Persistence
    let store = rs_matter::persist::DirKvBlobStore::new_default();

    // Create the transport buffers
    let buffers: MatterBuffers = MatterBuffers::new();

    // Create the data model state (subscriptions, events, network store).
    let state: EthInteractionModelState = EthInteractionModelState::new(EthNetwork::new_default());

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = matter.kv(store);

    // Re-hydrate the `Matter` instance (fabrics, basic info, RTC).
    matter.startup(&kv)?;

    // Create the crypto instance
    let crypto = default_crypto(rand::rng(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // The simulated heating element, shared by the thermostat (which opens and
    // closes its relay) and the two metering clusters (which report what it
    // draws). A plain shared reference is enough: the device state behind it
    // is kept in an `rs-matter` `Mutex`, so it is `Sync` when the crate is
    // built with the `sync-mutex` feature and free of charge when it is not.
    let element = HeatingElement::new();

    // Thermostat cluster setup. The Thermostat cluster is not coupled to any
    // other cluster, so there is no `init()` step: validation and the repair of
    // the persisted state happen on the `Startup` lifecycle op.
    let thermostat_handler = thermostat::ThermostatHandler::new(
        Dataver::new_rand(&mut rand),
        THERMOSTAT_ENDPOINT,
        ThermostatDeviceLogic::new(&element),
    );

    // The Electrical Sensor clusters. Power Topology carries no state at all -
    // with the `NODE` topology it has no attributes to serve.
    let power_handler = elec_pwr_meas::ElecPwrMeasHandler::new(
        Dataver::new_rand(&mut rand),
        THERMOSTAT_ENDPOINT,
        ElecPwrDeviceLogic::new(&element),
    );

    let energy_handler = elec_energy_meas::ElecEnergyMeasHandler::new(
        Dataver::new_rand(&mut rand),
        THERMOSTAT_ENDPOINT,
        ElecEnergyDeviceLogic::new(&element),
    );

    // Create the Data Model instance
    let im = InteractionModel::new(
        &matter,
        &crypto,
        &buffers,
        data_model(rand, &thermostat_handler, &power_handler, &energy_handler),
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

    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(&matter, &crypto));
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
/// EP1 carries two device types: the Thermostat, which is an *application*
/// device type, and the Electrical Sensor, which is a *utility* one. Core spec
/// 9.2.1 allows a simple endpoint only one application device type but any
/// number of utility ones, which is what lets the thermostat meter itself on
/// the same endpoint rather than needing a second.
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
) -> impl DataModel + 'a {
    (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&SysNetifs)
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

// Implementing the simulated heating element

/// How often the simulated room temperature is recomputed.
const TICK: embassy_time::Duration = embassy_time::Duration::from_secs(5);

/// How often the electrical readings are resampled. Faster than [`TICK`] so
/// that closing the relay shows up promptly in `ActivePower`.
const METER_TICK: embassy_time::Duration = embassy_time::Duration::from_secs(1);

/// How fast the room warms towards the setpoint while heating, in 0.01degC per
/// [`TICK`].
const HEATING_RATE: i16 = 20;

/// How fast the room cools towards [`AMBIENT`] while idle, in 0.01degC per
/// [`TICK`].
const COOLING_RATE: i16 = 10;

/// The temperature the simulated room drifts to with the heating off, in
/// 0.01degC.
const AMBIENT: i16 = 1600;

/// The rated power of the simulated heating element, in milliwatts: a dummy
/// 1 kW element.
const ELEMENT_POWER_MW: i64 = 1_000_000;

/// The nominal supply voltage, in millivolts.
const SUPPLY_VOLTAGE_MV: i64 = 230_000;

/// The nominal supply frequency, in millihertz.
const SUPPLY_FREQUENCY_MHZ: i64 = 50_000;

/// A purely resistive load draws all of its current in phase with the supply,
/// so its power factor is unity - 100.00%, in the hundredths of a percent
/// `PowerFactor` is expressed in.
const UNITY_POWER_FACTOR: i64 = 10_000;

/// The top of the metering hardware's measurable range, in milliamps.
const MAX_CURRENT_MA: i64 = 16_000;

/// The top of the metering hardware's measurable range, in milliwatts.
const MAX_POWER_MW: i64 = 3_680_000;

/// The top of the metering hardware's measurable range, in millivolts.
const MAX_VOLTAGE_MV: i64 = 400_000;

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
/// The `Accuracy` list is what tells a client which quantities the meter
/// actually measures, so it needs an entry for every reading served.
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

/// The simulated heating element: a resistive load the thermostat switches on
/// and off, and the two Electrical Sensor clusters report on.
///
/// It is the single source of truth for "is the element drawing power": the
/// thermostat writes that flag from its control loop, the meters read it.
pub struct HeatingElement {
    state: Mutex<RefCell<ElementState>>,
}

/// The element's state, behind one lock the way `on_off` keeps its own: the
/// mutex is a no-op unless `rs-matter` is built with the `sync-mutex` feature,
/// and with it the device logic is `Sync`.
struct ElementState {
    /// Whether the relay is closed and the element is drawing power.
    heating: bool,
    /// When the counters were last brought up to date, in milliseconds since
    /// boot. See [`ElementState::integrate`].
    mark_ms: u64,
    /// Energy drawn in the open measurement period, in milliwatt-seconds.
    period_mws: i64,
    /// When the open measurement period began, in milliseconds since boot.
    period_start_ms: u64,
    /// The last measurement period that actually drew something: the energy
    /// in it, in milliwatt-hours, and the window it covers in milliseconds
    /// since boot. `None` until the element has run at all, which is what
    /// makes `PeriodicEnergyImported` report null on a cold device.
    period: Option<(i64, u64, u64)>,
    /// Energy drawn over the device's lifetime.
    ///
    /// Accumulated in milliwatt-*seconds* rather than milliwatt-hours so that a
    /// whole number of seconds at a whole number of milliwatts stays exact;
    /// `CumulativeEnergyImported` wants mWh, which is just a division away.
    energy_mws: i64,
    /// The lifetime figure in milliwatt-hours as last reported, so a closing
    /// period can say whether `CumulativeEnergyImported` actually moved.
    reported_mwh: i64,
    /// Whether the counter started this run at zero because there was nothing
    /// to restore - the nearest this example has to a factory reset.
    reset_at_boot: bool,
}

impl ElementState {
    /// The power drawn right now, in milliwatts.
    fn active_power_mw(&self) -> i64 {
        if self.heating {
            ELEMENT_POWER_MW
        } else {
            0
        }
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
    /// sample boundary - and [`HeatingElement::set_heating`] does this first so
    /// that it does. Sampling the relay at the *end* of a fixed tick and
    /// crediting the whole tick at that power, as this used to, silently drops
    /// the energy of a relay that opened mid-tick and invents energy for one
    /// that closed late.
    fn integrate(&mut self) {
        let now = embassy_time::Instant::now().as_millis();
        let elapsed_ms = now.saturating_sub(self.mark_ms) as i64;

        self.mark_ms = now;

        let drawn_mws = self.active_power_mw() * elapsed_ms / 1000;

        self.energy_mws += drawn_mws;
        self.period_mws += drawn_mws;
    }
}

impl HeatingElement {
    /// Create the element, restoring its lifetime energy counter.
    pub fn new() -> Self {
        let now = embassy_time::Instant::now().as_millis();

        let (energy_mws, reset_at_boot) = Self::load_state();

        Self {
            state: Mutex::new(RefCell::new(ElementState {
                heating: false,
                mark_ms: now,
                period_mws: 0,
                period_start_ms: now,
                period: None,
                energy_mws,
                reported_mwh: energy_mws / 3600,
                reset_at_boot,
            })),
        }
    }

    /// Where the lifetime energy counter is kept between runs. A real device
    /// would put it in its own KV store; see `tests/src/bin/thermostat_tests.rs`
    /// for the `HandlerContext::kv` route.
    fn state_path() -> PathBuf {
        std::env::temp_dir().join("rs-matter-example-thermostat-energy")
    }

    /// The persisted lifetime energy counter in milliwatt-seconds, and whether
    /// it had to be started from zero because there was nothing to restore.
    fn load_state() -> (i64, bool) {
        let mut buf = [0u8; 8];

        let Ok(mut file) = fs::File::open(Self::state_path()) else {
            return (0, true);
        };

        if file.read_exact(&mut buf).is_err() {
            trace!("Heating element: no usable persisted energy counter");
            return (0, true);
        }

        (i64::from_le_bytes(buf), false)
    }

    /// Write the lifetime energy counter out. Called with the lock released:
    /// a file write has no business happening inside it.
    fn save_state(energy_mws: i64) {
        let saved = fs::File::create(Self::state_path())
            .and_then(|mut file| file.write_all(&energy_mws.to_le_bytes()))
            .is_ok();

        if !saved {
            error!("Heating element: could not persist the energy counter");
        }
    }

    /// Open or close the relay.
    fn set_heating(&self, heating: bool) {
        let changed = self.state.lock(|state| {
            let mut state = state.borrow_mut();

            // Bring the counters up to date at the old power before the relay
            // changes it, so no energy is credited at a power that was never
            // drawn.
            state.integrate();

            let changed = state.heating != heating;
            state.heating = heating;

            changed
        });

        if changed {
            info!("Emulation: heating {}", if heating { "ON" } else { "OFF" });
        }
    }

    /// Whether the element is currently drawing power.
    fn heating(&self) -> bool {
        self.state.lock(|state| state.borrow().heating)
    }

    /// The power drawn right now, in milliwatts.
    fn active_power_mw(&self) -> i64 {
        self.state.lock(|state| state.borrow().active_power_mw())
    }

    /// The current drawn right now, in milliamps, derived from the power and
    /// the nominal supply voltage so that the three reported readings stay
    /// consistent with one another.
    fn active_current_ma(&self) -> i64 {
        self.active_power_mw() * 1000 / SUPPLY_VOLTAGE_MV
    }

    /// The energy drawn over the device's lifetime, in milliwatt-hours.
    fn energy_mwh(&self) -> i64 {
        self.state.lock(|state| state.borrow().energy_mwh())
    }

    /// When the lifetime counter was last zeroed, as far as this device can
    /// tell.
    ///
    /// It has no wall clock and no record of resets before the current run, so
    /// the only reset it can date is the one it came up from: nothing was
    /// there to restore. Anything earlier is unknown, and reads as null.
    fn reset_at(&self) -> Option<Timestamp> {
        self.state
            .lock(|state| state.borrow().reset_at_boot)
            .then(|| Timestamp::systime(0))
    }

    /// The last measurement period that drew anything: its energy in
    /// milliwatt-hours, and the window it covers in milliseconds since boot.
    fn last_period(&self) -> Option<(i64, u64, u64)> {
        self.state.lock(|state| state.borrow().period)
    }

    /// Close the open measurement period and report which readings moved.
    fn close_period(&self) -> Accumulated {
        let (accumulated, energy_mws) = self.state.lock(|state| {
            let mut state = state.borrow_mut();

            state.integrate();

            let end = embassy_time::Instant::now().as_millis();
            let start = state.period_start_ms;
            let drawn_mws = state.period_mws;

            state.period_start_ms = end;
            state.period_mws = 0;

            // A period in which nothing was drawn carries no information, and
            // publishing one every tick would have an idle device emitting
            // `PeriodicEnergyMeasured` forever. The window is still advanced,
            // so the next period covers only the time the element actually ran.
            if drawn_mws == 0 {
                return (Accumulated::default(), state.energy_mws);
            }

            state.period = Some((drawn_mws / 3600, start, end));

            let energy_mwh = state.energy_mwh();
            let reported = state.reported_mwh;

            state.reported_mwh = energy_mwh;

            (
                Accumulated {
                    cumulative: energy_mwh != reported,
                    periodic: true,
                },
                state.energy_mws,
            )
        });

        // Only on a period that drew something, so an idle device does not
        // rewrite the file every tick. A real device would batch this harder
        // still - flash has a write budget.
        if accumulated.periodic {
            Self::save_state(energy_mws);
        }

        accumulated
    }
}

impl Default for HeatingElement {
    fn default() -> Self {
        Self::new()
    }
}

// Implementing the Thermostat business logic

/// A simulated heating thermostat with file-backed persistence of the four
/// non-volatile attributes.
pub struct ThermostatDeviceLogic<'a> {
    state: Mutex<RefCell<ThermostatState>>,
    /// The load this thermostat switches. Its relay flag is the thermostat's
    /// output and the meters' input.
    element: &'a HeatingElement,
}

/// The thermostat's own state, behind one lock - see [`ElementState`].
struct ThermostatState {
    local_temperature: i16,
    occupied_heating_setpoint: i16,
    min_heat_setpoint_limit: i16,
    max_heat_setpoint_limit: i16,
    system_mode: SystemModeEnum,
    /// Counts `run` ticks, so the simulated front panel can nudge the setpoint
    /// once in a while.
    ticks: u32,
}

impl<'a> ThermostatDeviceLogic<'a> {
    pub fn new(element: &'a HeatingElement) -> Self {
        Self {
            state: Mutex::new(RefCell::new(Self::load_state())),
            element,
        }
    }

    /// The blob laid out by [`Self::save_state`]: `SystemMode`, then
    /// `OccupiedHeatingSetpoint`, `MinHeatSetpointLimit` and
    /// `MaxHeatSetpointLimit` as little-endian `i16`s. The same four the DUT
    /// keeps under `vendor_kv::THERMOSTAT_STATE_KEY`.
    ///
    /// `LocalTemperature` is deliberately absent: it is a live sensor reading,
    /// not non-volatile state, and restoring a stale room temperature across a
    /// restart would only make the simulation lie.
    const STATE_LEN: usize = 7;

    /// Where the non-volatile attributes are kept between runs. A real device
    /// would put them in its own KV store; see `tests/src/bin/light_tests.rs`
    /// for the `HandlerContext::kv` route.
    fn state_path() -> PathBuf {
        std::env::temp_dir().join("rs-matter-example-thermostat-state")
    }

    /// The persisted state, or the power-on defaults when there is none.
    ///
    /// `LocalTemperature` and the tick counter are always started fresh: the
    /// first is a live sensor reading, the second is nobody's business but the
    /// simulated front panel's.
    fn load_state() -> ThermostatState {
        let default = ThermostatState {
            local_temperature: AMBIENT,
            occupied_heating_setpoint: 2000,
            min_heat_setpoint_limit: Self::ABS_MIN_HEAT_SETPOINT,
            max_heat_setpoint_limit: Self::ABS_MAX_HEAT_SETPOINT,
            system_mode: SystemModeEnum::Off,
            ticks: 0,
        };

        let mut buf = [0u8; Self::STATE_LEN];

        let Ok(mut file) = fs::File::open(Self::state_path()) else {
            return default;
        };

        if file.read_exact(&mut buf).is_err() {
            trace!("Thermostat: no usable persisted state");
            return default;
        }

        // Only the two modes a heating-only thermostat can be in; anything
        // else would be rejected by the handler's startup repair anyway.
        let system_mode = match buf[0] {
            m if m == SystemModeEnum::Off as u8 => SystemModeEnum::Off,
            m if m == SystemModeEnum::Heat as u8 => SystemModeEnum::Heat,
            _ => {
                trace!("Thermostat: persisted SystemMode is not a supported value");
                return default;
            }
        };

        ThermostatState {
            system_mode,
            occupied_heating_setpoint: i16::from_le_bytes([buf[1], buf[2]]),
            min_heat_setpoint_limit: i16::from_le_bytes([buf[3], buf[4]]),
            max_heat_setpoint_limit: i16::from_le_bytes([buf[5], buf[6]]),
            ..default
        }
    }

    /// Write the four non-volatile attributes out. The file write happens with
    /// the lock released - see [`HeatingElement::save_state`].
    fn save_state(&self) {
        let buf = self.state.lock(|state| {
            let state = state.borrow();

            let mut buf = [0u8; Self::STATE_LEN];

            buf[0] = state.system_mode as u8;
            buf[1..3].copy_from_slice(&state.occupied_heating_setpoint.to_le_bytes());
            buf[3..5].copy_from_slice(&state.min_heat_setpoint_limit.to_le_bytes());
            buf[5..7].copy_from_slice(&state.max_heat_setpoint_limit.to_le_bytes());

            buf
        });

        let saved = fs::File::create(Self::state_path())
            .and_then(|mut file| file.write_all(&buf))
            .is_ok();

        if !saved {
            error!("Thermostat: could not persist the cluster state");
        }
    }

    /// Move the heating setpoint by half a degree, the way a press of the
    /// front-panel up/down buttons would, bouncing off the configured limits.
    ///
    /// Because this happens behind the cluster's back, the handler attributes
    /// it to `Manual` rather than `External` - the whole point of
    /// `SetpointChangeSource`.
    fn nudge_setpoint(&self) {
        const STEP: i16 = 50;

        let (previous, next) = self.state.lock(|state| {
            let mut state = state.borrow_mut();

            let previous = state.occupied_heating_setpoint;

            let next = if previous.saturating_add(STEP) > state.max_heat_setpoint_limit {
                state.min_heat_setpoint_limit
            } else {
                previous.saturating_add(STEP)
            };

            state.occupied_heating_setpoint = next;

            (previous, next)
        });

        self.save_state();
        self.update_relay();

        info!(
            "Emulation: front panel moved the heating setpoint {:.2}C -> {:.2}C",
            previous as f32 / 100.0,
            next as f32 / 100.0
        );
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
                // How the setpoint last moved, which lets a controller tell
                // a turn of the knob from its own write. Neither
                // feature-gated nor provisional, unlike the `TEVT` event set,
                // which this example leaves off.
                | thermostat_cluster::AttributeId::SetpointChangeSource
                | thermostat_cluster::AttributeId::SetpointChangeAmount
                | thermostat_cluster::AttributeId::SetpointChangeSourceTimestamp
        ))
        .with_cmds(with!(thermostat_cluster::CommandId::SetpointRaiseLower))
        .with_events(with!());

    const CONTROL_SEQUENCE_OF_OPERATION: ControlSequenceOfOperationEnum =
        ControlSequenceOfOperationEnum::HeatingOnly;

    // `utc_now_secs` is deliberately not implemented: this device has no clock
    // of its own, so `SetpointChangeSourceTimestamp` is stamped from the node's
    // Last-Known-Good UTC time, which the handler reads for itself.

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
        self.save_state();

        Ok(())
    }

    fn min_heat_setpoint_limit(&self) -> i16 {
        self.state
            .lock(|state| state.borrow().min_heat_setpoint_limit)
    }

    fn set_min_heat_setpoint_limit(&self, value: i16) -> Result<(), Error> {
        self.state
            .lock(|state| state.borrow_mut().min_heat_setpoint_limit = value);
        self.save_state();

        Ok(())
    }

    fn max_heat_setpoint_limit(&self) -> i16 {
        self.state
            .lock(|state| state.borrow().max_heat_setpoint_limit)
    }

    fn set_max_heat_setpoint_limit(&self, value: i16) -> Result<(), Error> {
        self.state
            .lock(|state| state.borrow_mut().max_heat_setpoint_limit = value);
        self.save_state();

        Ok(())
    }

    fn system_mode(&self) -> SystemModeEnum {
        self.state.lock(|state| state.borrow().system_mode)
    }

    fn set_system_mode(&self, value: SystemModeEnum) -> Result<(), Error> {
        self.state
            .lock(|state| state.borrow_mut().system_mode = value);
        self.save_state();

        Ok(())
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

            // Stand in for somebody pressing the front-panel buttons, once a
            // minute, so the `Manual` attribution is visible in a running
            // example. A real device would do this from its input handling.
            let ticks = self.state.lock(|state| {
                let mut state = state.borrow_mut();

                state.ticks = state.ticks.wrapping_add(1);

                state.ticks
            });

            if ticks.is_multiple_of(12) {
                self.nudge_setpoint();
                notify(OutOfBandMessage::OccupiedHeatingSetpoint);
            }

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

// Implementing the Electrical Power Measurement business logic

/// What the element is drawing right now.
pub struct ElecPwrDeviceLogic<'a> {
    element: &'a HeatingElement,
    /// The last `ActivePower` handed to a subscriber, so that
    /// [`ElecPwrMeasHooks::run`] only notifies when the reading actually moved.
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

    /// One entry per reading served. A real device would quote its meter's
    /// datasheet here.
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
        Some(SUPPLY_VOLTAGE_MV)
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
        Some(SUPPLY_VOLTAGE_MV)
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
            // In a real device we would wait on the metering chip rather than
            // poll a simulation.
            embassy_time::Timer::after(METER_TICK).await;

            let power = self.element.active_power_mw();

            if power != self.reported_power_mw.lock(|reported| reported.get()) {
                self.reported_power_mw.lock(|reported| reported.set(power));

                // `ActiveCurrent` is derived from the same relay state, so both
                // readings move together.
                notify(elec_pwr_meas::OutOfBandMessage::Update);
            }
        }
    }
}

// Implementing the Electrical Energy Measurement business logic

/// What the element has drawn over the device's lifetime.
pub struct ElecEnergyDeviceLogic<'a> {
    element: &'a HeatingElement,
}

impl<'a> ElecEnergyDeviceLogic<'a> {
    pub fn new(element: &'a HeatingElement) -> Self {
        Self { element }
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
        // No wall clock, so the reading is located in time by uptime alone,
        // which is conformant.
        Some(EnergyMeasurement::cumulative(
            self.element.energy_mwh(),
            Timestamp::systime(embassy_time::Instant::now().as_millis()),
        ))
    }

    fn cumulative_energy_reset(&self) -> Option<Timestamp> {
        self.element.reset_at()
    }

    /// A periodic reading needs both ends of its window; with no wall clock,
    /// both are uptimes.
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
            embassy_time::Timer::after(TICK).await;

            // Closing the period here rather than in the thermostat's own tick
            // keeps the energy counter owned by the cluster that reports it.
            let moved = self.element.close_period();

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
