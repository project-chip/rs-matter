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
//! Implementation of the Matter Thermostat cluster (`0x0201`), Matter 1.6
//! Application Cluster spec section 4.3, `ClusterRevision` 11.
//!
//! The FeatureMap this handler accepts is any combination of `HEAT`, `COOL`
//! and `AUTO` (optionally plus `LTNE`), which covers the heating-only,
//! cooling-only and full heat/cool/auto thermostats. See [`ThermostatHooks`]
//! for the device-specific logic the consumer supplies.
//!
//! Key features:
//! - Provides hooks for device-specific logic and persistence via the
//!   [`ThermostatHooks`] trait.
//! - Validates the cluster configuration and feature selection at startup.
//! - Enforces the setpoint-limit constraint chain of spec section 4.3.6 across
//!   every mutation path, including the asymmetry the spec requires: the
//!   `SetpointRaiseLower` command clamps silently, while an attribute write
//!   out of range is a `CONSTRAINT_ERROR`.
//! - With `AUTO`, maintains the `MinSetpointDeadBand` between the heating and
//!   cooling halves of that chain, adjusting the opposite setpoint rather than
//!   rejecting the write where section 4.3.11 says to.
//!
//! Attributes served (section 4.3.11):
//!
//! | ID       | Name                         | Conformance    |
//! | -------- | ---------------------------- | -------------- |
//! | `0x0000` | `LocalTemperature`           | M              |
//! | `0x0003` | `AbsMinHeatSetpointLimit`    | `[HEAT]`       |
//! | `0x0004` | `AbsMaxHeatSetpointLimit`    | `[HEAT]`       |
//! | `0x0005` | `AbsMinCoolSetpointLimit`    | `[COOL]`       |
//! | `0x0006` | `AbsMaxCoolSetpointLimit`    | `[COOL]`       |
//! | `0x0011` | `OccupiedCoolingSetpoint`    | `COOL`         |
//! | `0x0012` | `OccupiedHeatingSetpoint`    | `HEAT`         |
//! | `0x0015` | `MinHeatSetpointLimit`       | `[HEAT]`       |
//! | `0x0016` | `MaxHeatSetpointLimit`       | `[HEAT]`       |
//! | `0x0017` | `MinCoolSetpointLimit`       | `[COOL]`       |
//! | `0x0018` | `MaxCoolSetpointLimit`       | `[COOL]`       |
//! | `0x0019` | `MinSetpointDeadBand`        | `AUTO`         |
//! | `0x001B` | `ControlSequenceOfOperation` | M              |
//! | `0x001C` | `SystemMode`                 | M              |
//! | `0x001E` | `ThermostatRunningMode`      | `[AUTO]`       |
//! | `0x0029` | `ThermostatRunningState`     | O              |
//! | `0x0030` | `SetpointChangeSource`       | O              |
//! | `0x0031` | `SetpointChangeAmount`       | O              |
//! | `0x0032` | `SetpointChangeSourceTimestamp` | O           |
//!
//! The `Min`/`Max` setpoint limits are optional, but the `CONSTRAINT_ERROR`
//! and clamping rules are written in terms of them, so each temperature's four
//! limits are either all served or all omitted — see
//! [`ThermostatHandler::validate`].
//!
//! `ThermostatRunningState` is the one place where the device's own control
//! algorithm becomes visible over Matter, which is why it is answered by
//! [`ThermostatHooks::running_state`] rather than derived by the handler.
//! `ThermostatRunningMode`, in contrast, *is* derived — it is the same relay
//! state narrowed to the "is it heating or cooling right now" question that
//! `SystemMode = Auto` leaves open. Both are optional; omit them from the
//! served set and the hook is never called.
//!
//! The last three (section 4.3.11.30-32) say *how* the setpoint last moved.
//! They are the only spec-sanctioned way to tell a change the user made on the
//! device itself from one that arrived over Matter: this handler records
//! `Manual` for anything the device did behind the cluster's back and
//! `External` for an attribute write or `SetpointRaiseLower`. `Schedule` is
//! unreachable here - its conformance is `[MSCH]`, a feature this handler
//! rejects. `SetpointChangeSourceTimestamp` needs a clock, and takes the
//! node's own Last-Known-Good UTC time by default; a device with a better one
//! overrides [`ThermostatHooks::utc_now_secs`].
//!
//! The only command served is `SetpointRaiseLower` (`0x00`), the sole
//! unconditionally mandatory one (section 4.3.12.1).
//!
//! # Events (section 4.3.13)
//!
//! All of them are gated on the `TEVT` feature, and **every one is
//! `provisional` in Matter 1.6 and still in 1.7**. Nothing in this crate turns
//! `TEVT` on by default; a consumer that sets the bit is opting into an
//! element set that must not ship on a certified product. The certification
//! device-under-test in `tests/src/bin` deliberately leaves it off.
//!
//! With `TEVT` the applicable events are *mandatory*, not optional - each is
//! `mandatoryConform{TEVT & ...}` - so the handler serves the whole set its
//! state can support, and [`ThermostatHandler::validate`] rejects a partial
//! one:
//!
//! | ID       | Name                     | Conformance      |
//! | -------- | ------------------------ | ---------------- |
//! | `0x00`   | `SystemModeChange`       | `TEVT`           |
//! | `0x01`   | `LocalTemperatureChange` | `TEVT & !LTNE`   |
//! | `0x03`   | `SetpointChange`         | `TEVT`           |
//! | `0x04`   | `RunningStateChange`     | `TEVT`           |
//! | `0x05`   | `RunningModeChange`      | `TEVT & AUTO`    |
//!
//! `OccupancyChange` (`0x02`), `ActiveScheduleChange` (`0x06`) and
//! `ActivePresetChange` (`0x07`) need `OCC`, `MSCH` and `PRES`, which this
//! handler does not implement, so they can never be served.
//!
//! Two rules are worth singling out:
//!
//! - `SetpointChange` is *source-agnostic*. Section 4.3.13.4 fires it whenever
//!   any setpoint attribute changes, whoever changed it, and its `SystemMode`
//!   field names **which setpoint moved** rather than the `SystemMode`
//!   attribute (section 4.3.13.4.1) - a heating-only device reports `Heat`
//!   even while it sits in `Off`. To tell a local change from a remote one, a
//!   controller reads `SetpointChangeSource` alongside.
//! - `LocalTemperatureChange` is rate-limited to once every 60 seconds
//!   (section 4.3.13.2) and only fires on a "significant" change - a null
//!   transition, or a movement of at least
//!   [`ThermostatHooks::LOCAL_TEMPERATURE_EVENT_DELTA`].
//!
//! Events are emitted from the handler's `run` task, which diffs a shadow of
//! the last reported state against the device. A consumer serving them must
//! give its `InteractionModelState` a non-zero events buffer; with `NoEvents`
//! every emission fails and is only logged.
//!
//! Unsupported features, all of them optional in the spec:
//! - `OCC` (occupancy) and therefore the unoccupied setpoints.
//! - `MSCH` (schedules), `PRES` (presets) and `TSUGGEST` (thermostat
//!   suggestions), along with their commands and the global
//!   `AtomicRequest`/`AtomicResponse` pair — atomic writes are only needed for
//!   the `Presets`/`Schedules` attributes. These features additionally require
//!   the device to support time synchronization.
//! - `SB` (setback), deprecated in cluster revision 10.
//!
//! The legacy weekly-schedule feature was removed from the Matter 1.6 data
//! model altogether; its commands (`0x01`..=`0x03`) survive in the IDL we
//! generate from, but they are not served.
//!
//! There is no Scenes Management integration, and none is possible: section
//! 1.4.7.5.5 says "a Scene Table Extension SHALL only use attributes with the
//! Scene quality", and in the 1.6 data model no Thermostat attribute carries
//! it — `OnOff`, `LevelControl` and `ColorControl` are the only clusters that
//! do. The Thermostat scene extension of the older ZCL specifications did not
//! survive into Matter.

use core::future::{ready, Future};
use core::pin::pin;

use embassy_futures::select::{select3, Either3};
use embassy_time::{Duration, Instant, Timer};

use crate::dm::types::EndptId;
use crate::dm::{
    AttrChangeNotifier, AttrId, Cluster, Dataver, EventEmitter, HandlerContext, InvokeContext,
    LifecycleOp, ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{Nullable, TLVBuilderParent};
use crate::utils::cell::RefCell;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Signal;

pub use crate::dm::clusters::decl::thermostat::*;

/// The `ClusterRevision` this handler implements (Matter 1.6).
const CLUSTER_REVISION: u16 = 11;

/// The features this handler knows how to serve. Anything else in a
/// [`ThermostatHooks::CLUSTER`] FeatureMap is rejected by
/// [`ThermostatHandler::validate`].
/// `EVENTS` is provisional in Matter 1.6 (and still in 1.7): a consumer that
/// sets the bit is opting into an element set that must not ship on a
/// certified product. Nothing in this crate enables it by default.
const SUPPORTED_FEATURES: u32 = Feature::HEATING.bits()
    | Feature::COOLING.bits()
    | Feature::AUTO_MODE.bits()
    | Feature::LOCAL_TEMPERATURE_NOT_EXPOSED.bits()
    | Feature::EVENTS.bits();

/// Section 4.3.13.2: "LocalTemperatureChange events SHALL NOT be generated
/// more often than once every 60 seconds."
const LOCAL_TEMPERATURE_EVENT_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Section 4.3.5: `MinSetpointDeadBand` is a `SignedTemperature`, in units of
/// 0.1°C, while every setpoint is a `temperature`, in units of 0.01°C. "Where
/// calculations or comparisons are performed, attribute values SHALL be
/// converted to a common type."
const DEAD_BAND_SCALE: i16 = 10;

/// Messages passed to the `notify` closure of [`ThermostatHooks::run`].
///
/// They tell the handler that the device changed an attribute behind the
/// cluster's back — a new sensor reading, a turn of a knob on the device's own
/// front panel — so that the handler can re-report it to any subscriber.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OutOfBandMessage {
    /// [`ThermostatHooks::local_temperature`] changed.
    LocalTemperature,
    /// [`ThermostatHooks::occupied_heating_setpoint`] changed.
    OccupiedHeatingSetpoint,
    /// [`ThermostatHooks::occupied_cooling_setpoint`] changed.
    OccupiedCoolingSetpoint,
    /// [`ThermostatHooks::system_mode`] changed.
    SystemMode,
    /// Any of the four user-configurable setpoint limits changed.
    SetpointLimits,
    /// [`ThermostatHooks::running_state`] changed.
    ///
    /// Only needed for a relay that moves on its own - one the handler drives
    /// through [`ThermostatHooks::apply`] is re-reported by the handler itself.
    RunningState,
    /// Any or all of the above changed.
    Update,
}

impl OutOfBandMessage {
    /// The set of attributes this message marks as needing a re-report.
    const fn pending(&self) -> u16 {
        match self {
            Self::LocalTemperature => PENDING_LOCAL_TEMPERATURE,
            Self::OccupiedHeatingSetpoint => PENDING_OCCUPIED_HEATING_SETPOINT,
            Self::OccupiedCoolingSetpoint => PENDING_OCCUPIED_COOLING_SETPOINT,
            Self::SystemMode => PENDING_SYSTEM_MODE,
            Self::SetpointLimits => {
                PENDING_MIN_HEAT_LIMIT
                    | PENDING_MAX_HEAT_LIMIT
                    | PENDING_MIN_COOL_LIMIT
                    | PENDING_MAX_COOL_LIMIT
            }
            Self::RunningState => PENDING_RUNNING_STATE,
            Self::Update => PENDING_ALL,
        }
    }
}

const PENDING_LOCAL_TEMPERATURE: u16 = 1 << 0;
const PENDING_OCCUPIED_HEATING_SETPOINT: u16 = 1 << 1;
const PENDING_OCCUPIED_COOLING_SETPOINT: u16 = 1 << 2;
const PENDING_SYSTEM_MODE: u16 = 1 << 3;
const PENDING_MIN_HEAT_LIMIT: u16 = 1 << 4;
const PENDING_MAX_HEAT_LIMIT: u16 = 1 << 5;
const PENDING_MIN_COOL_LIMIT: u16 = 1 << 6;
const PENDING_MAX_COOL_LIMIT: u16 = 1 << 7;
const PENDING_RUNNING_STATE: u16 = 1 << 8;

/// "Sweep the shadow for events", rung by [`ThermostatHandler::apply`].
///
/// Deliberately absent from both [`PENDING_ATTRS`] and [`PENDING_ALL`]: it
/// re-reports nothing. Every event this handler serves is defined as "attribute
/// X changed" (section 4.3.13), so the drain can decide all of them by diffing
/// the shadow against the hooks - it needs a wake-up, not a bit per event.
///
/// The out-of-band path already wakes `run`. What the in-band paths lacked is
/// exactly this: they re-report synchronously, from the context that carried
/// the write, and so never touched the mask at all. `apply` is the one place
/// they all pass through.
const PENDING_EVENT_SWEEP: u16 = 1 << 9;

const PENDING_ALL: u16 = PENDING_LOCAL_TEMPERATURE
    | PENDING_OCCUPIED_HEATING_SETPOINT
    | PENDING_OCCUPIED_COOLING_SETPOINT
    | PENDING_SYSTEM_MODE
    | PENDING_MIN_HEAT_LIMIT
    | PENDING_MAX_HEAT_LIMIT
    | PENDING_MIN_COOL_LIMIT
    | PENDING_MAX_COOL_LIMIT
    | PENDING_RUNNING_STATE;

/// The pending-notification bit to attribute ID mapping, in ascending
/// attribute order.
///
/// `ThermostatRunningMode` shares the relay's bit: it is a narrowing of the
/// same state, so the two never move independently.
const PENDING_ATTRS: &[(u16, AttributeId)] = &[
    (PENDING_LOCAL_TEMPERATURE, AttributeId::LocalTemperature),
    (
        PENDING_OCCUPIED_COOLING_SETPOINT,
        AttributeId::OccupiedCoolingSetpoint,
    ),
    (
        PENDING_OCCUPIED_HEATING_SETPOINT,
        AttributeId::OccupiedHeatingSetpoint,
    ),
    (PENDING_MIN_HEAT_LIMIT, AttributeId::MinHeatSetpointLimit),
    (PENDING_MAX_HEAT_LIMIT, AttributeId::MaxHeatSetpointLimit),
    (PENDING_MIN_COOL_LIMIT, AttributeId::MinCoolSetpointLimit),
    (PENDING_MAX_COOL_LIMIT, AttributeId::MaxCoolSetpointLimit),
    (PENDING_SYSTEM_MODE, AttributeId::SystemMode),
    (PENDING_RUNNING_STATE, AttributeId::ThermostatRunningMode),
    (PENDING_RUNNING_STATE, AttributeId::ThermostatRunningState),
];

/// A Thermostat cluster handler.
///
/// The Thermostat cluster is not coupled to any other cluster, so the handler
/// needs no wiring step: construct it with [`ThermostatHandler::new`] and chain
/// it. Configuration validation and the repair of persisted state both happen
/// on the `Startup` lifecycle operation.
pub struct ThermostatHandler<H: ThermostatHooks> {
    dataver: Dataver,
    /// Needed to address `notify_attr_changed` from [`Self::run`], which has
    /// only a [`HandlerContext`] and hence no notion of a "current" endpoint.
    endpoint_id: EndptId,
    hooks: H,
    /// Bitmask of attributes awaiting a subscription re-report, fed by
    /// [`Self::out_of_band_message`] and drained by [`Self::run`].
    ///
    /// A `Signal<Option<OutOfBandMessage>>` would be the more obvious choice,
    /// but it is a single slot that *replaces* on signal: two out-of-band
    /// changes landing back to back would lose the first. Accumulating into a
    /// mask instead makes the path lossless.
    ///
    /// Carries [`PENDING_EVENT_SWEEP`] besides the attribute bits.
    pending: Signal<u16>,
    /// What the last sweep left behind - see [`EventState`].
    /// When `LocalTemperatureChange` was last emitted, for the 60-second floor
    /// of section 4.3.13.2.
    ///
    /// `None` rather than a zero `Instant` so that the very first change is
    /// not swallowed for a minute after boot - an embassy `Instant` counts
    /// from boot, so zero is a *real* timestamp, not a sentinel.
    event_state: Mutex<RefCell<EventState>>,
    /// Section 4.3.11.30-32: how the setpoint last moved. Bookkeeping about
    /// the *path* a change took, which only the handler knows, so unlike the
    /// rest of the cluster's state it does not live in the hooks.
    setpoint_change: SetpointChangeRecord,
}

/// The node's Last-Known-Good UTC time in Matter-epoch seconds, or `None`
/// while nothing has set it.
///
/// Section 4.3.11.32 wants `SetpointChangeSourceTimestamp` "in UTC", and the
/// node already tracks exactly that. Reading it here rather than asking the
/// consumer to hand it back through [`ThermostatHooks::utc_now_secs`] keeps a
/// device that has no clock of its own from having to hold a `&Matter` purely
/// to answer a question the handler could answer itself.
fn node_utc_now_secs(ctx: &impl HandlerContext) -> Option<u32> {
    ctx.matter()
        .with_rtc(|rtc| rtc.utc_time().reliable_secs())
        .map(|secs| secs.try_into().unwrap_or(u32::MAX))
}

/// Wait until `deadline`, or forever when there is none.
async fn wait_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => Timer::at(deadline).await,
        None => core::future::pending().await,
    }
}

/// The "significant change" half of section 4.3.13.2, without the rate limit.
fn local_temperature_change_significant(
    previous: Option<i16>,
    current: Option<i16>,
    delta: i16,
) -> bool {
    match (previous, current) {
        (Some(previous), Some(current)) => previous.abs_diff(current) >= delta.unsigned_abs(),
        // Exactly one of them is null: always significant. Both null is not a
        // change at all.
        (previous, current) => previous.is_some() != current.is_some(),
    }
}

/// Whether a `LocalTemperature` movement is worth a `LocalTemperatureChange`.
///
/// Section 4.3.13.2: "This event SHALL be generated when the LocalTemperature
/// attribute changes significantly. Significant changes are: Changes from null
/// to not null, or from not null to null. Changes from one not-null value to
/// another not-null value that are sufficiently large, as determined by the
/// server." Then, as a separate and unconditional sentence:
/// "LocalTemperatureChange events SHALL NOT be generated more often than once
/// every 60 seconds."
///
/// So a null transition escapes the threshold but *not* the rate limit. A free
/// function taking `now` so that both halves are testable without a clock.
fn local_temperature_event_due(
    previous: Option<i16>,
    current: Option<i16>,
    delta: i16,
    last: Option<Instant>,
    now: Instant,
) -> bool {
    if !local_temperature_change_significant(previous, current, delta) {
        return false;
    }

    match last {
        // The floor is only meaningful once one has been emitted; an embassy
        // `Instant` counts from boot, so there is no "long ago" to start at.
        Some(last) => now.saturating_duration_since(last) >= LOCAL_TEMPERATURE_EVENT_MIN_INTERVAL,
        None => true,
    }
}

/// Everything the five served events report, in one `Copy` value.
///
/// `local_temperature` is an `Option<i16>` rather than a [`Nullable`] because
/// `Nullable` has a `Drop` impl and so is not `Copy` - it cannot live in a
/// [`Cell`]. It is converted at the boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Snapshot {
    local_temperature: Option<i16>,
    heating_setpoint: i16,
    cooling_setpoint: i16,
    system_mode: SystemModeEnum,
    running_state: RelayStateBitmap,
    running_mode: ThermostatRunningModeEnum,
}

/// A change a sweep decided to report, as plain values.
///
/// Separating the decision from the TLV keeps every rule of section 4.3.13
/// unit-testable: [`ThermostatHandler::take_events`] needs neither a context
/// nor an emitter, and [`ThermostatHandler::emit_pending`] is then nothing but
/// serialisation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum ThermostatEvent {
    SystemMode {
        previous: Option<SystemModeEnum>,
        current: SystemModeEnum,
    },
    LocalTemperature {
        current: Option<i16>,
    },
    Setpoint {
        /// Section 4.3.13.4.1: which setpoint moved, *not* the `SystemMode`
        /// attribute - a heating-only thermostat reports `Heat` here even
        /// while its mode is `Off`.
        system_mode: SystemModeEnum,
        previous: Option<i16>,
        current: i16,
    },
    RunningState {
        previous: Option<RelayStateBitmap>,
        current: RelayStateBitmap,
    },
    RunningMode {
        previous: Option<ThermostatRunningModeEnum>,
        current: ThermostatRunningModeEnum,
    },
}

/// What the event sweep has to remember between runs.
///
/// Both fields are read, diffed and committed by [`ThermostatHandler::take_events`],
/// so they share one lock: a sweep can never act on half of a newer one.
struct EventState {
    /// Everything an event reports, as of the last sweep, so that the
    /// `Previous*` fields of section 4.3.13 have something to name.
    ///
    /// The pending mask says only *that* something moved; by the time `run`
    /// drains it, the old value is gone from the hooks. `None` means "not
    /// seeded yet" - the first sweep seeds and emits nothing.
    shadow: Option<Snapshot>,
    /// When `LocalTemperatureChange` was last emitted.
    last_local_temperature: Option<Instant>,
}

/// Section 4.3.11.30-32, as a unit: the three attributes move together.
///
/// Its fields live behind one `Mutex<RefCell<_>>`, the way `on_off` keeps its
/// cluster state: with the `sync-mutex` feature the handler is then `Sync`,
/// and without it the mutex is a `NoopRawMutex` and costs nothing.
struct SetpointChangeRecord(Mutex<RefCell<SetpointChangeState>>);

/// The state behind a [`SetpointChangeRecord`].
///
/// Named `...State` rather than `SetpointChange`, which is the generated
/// event struct of section 4.3.13.4.
#[derive(Clone, Copy)]
struct SetpointChangeState {
    /// Section 4.3.11.30. The XML default is 0, i.e. `Manual`.
    source: SetpointChangeSourceEnum,
    /// Section 4.3.11.31, in 0.01°C. `None` reads back as null - "the previous
    /// setpoint was unknown".
    amount: Option<i16>,
    /// Section 4.3.11.32, in Matter-epoch seconds. Zero means "nothing
    /// recorded since boot, or no reliable clock" - `epoch-s` is not nullable,
    /// so there is no spec-blessed way to say "unknown".
    timestamp: u32,
    /// The `(heating, cooling)` pair as last *attributed* to a source.
    ///
    /// Distinct from [`Snapshot`], which only advances when an event is
    /// emitted. The invariant is one sentence: an in-band change attributes
    /// itself as it happens, so anything the sweep still finds unattributed
    /// came from the device itself and is therefore `Manual`.
    attributed: Option<(i16, i16)>,
    /// The node's UTC time as of the operation currently in flight.
    ///
    /// Every mutation path below takes an [`AttrChangeNotifier`] rather than
    /// the context that carried the request, so that each rule of section
    /// 4.3.6 stays unit-testable without a live `Matter` - which also leaves
    /// none of them able to read a clock. [`ThermostatHandler::arm_clock`]
    /// fills this in at the one boundary that does hold a [`HandlerContext`],
    /// which keeps that property and spares the consumer from wiring the
    /// node's RTC back into its hooks by hand.
    ///
    /// Consumed rather than read, so a stamp armed by a write can never be
    /// mistaken for the time of a later change the device made on its own.
    armed: Option<u32>,
}

impl SetpointChangeRecord {
    const fn new() -> Self {
        Self(Mutex::new(RefCell::new(SetpointChangeState {
            source: SetpointChangeSourceEnum::Manual,
            amount: None,
            timestamp: 0,
            attributed: None,
            armed: None,
        })))
    }

    /// The record as it stands. All five fields are `Copy`, so one read
    /// serves the three attributes of section 4.3.11.30-32 and the sweep.
    fn get(&self) -> SetpointChangeState {
        self.0.lock(|state| *state.borrow())
    }

    /// Claim `current` as attributed, so the sweep does not call it `Manual`.
    fn attribute(&self, current: (i16, i16)) {
        self.0
            .lock(|state| state.borrow_mut().attributed = Some(current));
    }

    /// Stash the node's idea of the time for the operation in flight.
    fn arm(&self, now: Option<u32>) {
        self.0.lock(|state| state.borrow_mut().armed = now);
    }

    /// Record a setpoint movement of `amount` from `source`, as of `now`.
    ///
    /// `now` is whatever [`ThermostatHooks::utc_now_secs`] answered; a device
    /// with a better clock than the node's therefore wins. Failing that the
    /// stamp armed from the request's context is used. The armed slot is taken
    /// either way, so it can never go stale.
    ///
    /// With no clock at all this stores zero rather than leaving the previous
    /// stamp in place: a stale timestamp against a fresh amount is an active
    /// lie, while zero is conventionally "unknown".
    fn record(&self, source: SetpointChangeSourceEnum, amount: i16, now: Option<u32>) {
        self.0.lock(|state| {
            let mut state = state.borrow_mut();

            let armed = state.armed.take();

            state.source = source;
            state.amount = Some(amount);
            state.timestamp = now.or(armed).unwrap_or(0);
        });
    }
}

impl<H: ThermostatHooks> ThermostatHandler<H> {
    /// Create a new `ThermostatHandler` with the given hooks.
    ///
    /// # Arguments
    /// - `dataver` - the cluster data version.
    /// - `endpoint_id` - the endpoint hosting this cluster instance.
    /// - `hooks` - the device-specific thermostat logic and persistence.
    pub const fn new(dataver: Dataver, endpoint_id: EndptId, hooks: H) -> Self {
        Self {
            dataver,
            endpoint_id,
            hooks,
            pending: Signal::new(0),
            event_state: Mutex::new(RefCell::new(EventState {
                shadow: None,
                last_local_temperature: None,
            })),
            setpoint_change: SetpointChangeRecord::new(),
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }

    /// Whether the configured FeatureMap contains all of `features`.
    fn supports_feature(features: u32) -> bool {
        H::CLUSTER.feature_map & features != 0
    }

    /// Whether this thermostat can heat.
    fn heats() -> bool {
        Self::supports_feature(Feature::HEATING.bits())
    }

    /// Whether this thermostat can cool.
    fn cools() -> bool {
        Self::supports_feature(Feature::COOLING.bits())
    }

    /// Whether this thermostat supports `SystemMode = Auto`, and with it the
    /// deadband half of section 4.3.6.
    fn auto() -> bool {
        Self::supports_feature(Feature::AUTO_MODE.bits())
    }

    /// Whether the given attribute is part of the served set.
    fn serves(attr: AttributeId) -> bool {
        H::CLUSTER.attribute(attr as _).is_some()
    }

    /// Whether the user-configurable heating limits are served. They are
    /// either all present or all absent - [`Self::validate`] enforces that.
    fn has_heat_limits() -> bool {
        Self::serves(AttributeId::MinHeatSetpointLimit)
    }

    /// Whether the user-configurable cooling limits are served.
    fn has_cool_limits() -> bool {
        Self::serves(AttributeId::MinCoolSetpointLimit)
    }

    /// `MinSetpointDeadBand` converted to the setpoints' own units, or zero
    /// when the cluster has no deadband at all. Section 4.3.6: the deadband
    /// clauses apply "if, and only if, the AUTO feature is supported".
    fn dead_band() -> i16 {
        if Self::auto() {
            H::MIN_SETPOINT_DEAD_BAND as i16 * DEAD_BAND_SCALE
        } else {
            0
        }
    }

    /// The effective lower bound on the heating setpoint: the user-configurable
    /// limit when served, else the manufacturer's absolute limit.
    fn min_heat_setpoint(&self) -> i16 {
        if Self::has_heat_limits() {
            self.hooks.min_heat_setpoint_limit()
        } else {
            H::ABS_MIN_HEAT_SETPOINT
        }
    }

    /// The effective upper bound on the heating setpoint.
    fn max_heat_setpoint(&self) -> i16 {
        if Self::has_heat_limits() {
            self.hooks.max_heat_setpoint_limit()
        } else {
            H::ABS_MAX_HEAT_SETPOINT
        }
    }

    /// The effective lower bound on the cooling setpoint.
    fn min_cool_setpoint(&self) -> i16 {
        if Self::has_cool_limits() {
            self.hooks.min_cool_setpoint_limit()
        } else {
            H::ABS_MIN_COOL_SETPOINT
        }
    }

    /// The effective upper bound on the cooling setpoint.
    fn max_cool_setpoint(&self) -> i16 {
        if Self::has_cool_limits() {
            self.hooks.max_cool_setpoint_limit()
        } else {
            H::ABS_MAX_COOL_SETPOINT
        }
    }

    /// Clamp a candidate heating setpoint into the effective limits.
    ///
    /// Takes an `i32` because the `SetpointRaiseLower` arithmetic can overflow
    /// `i16` before it is clamped.
    fn clamp_heat_setpoint(&self, value: i32) -> i16 {
        value.clamp(
            self.min_heat_setpoint() as i32,
            self.max_heat_setpoint() as i32,
        ) as i16
    }

    /// Clamp a candidate cooling setpoint into the effective limits.
    fn clamp_cool_setpoint(&self, value: i32) -> i16 {
        value.clamp(
            self.min_cool_setpoint() as i32,
            self.max_cool_setpoint() as i32,
        ) as i16
    }

    /// Section 4.3.10.16: which `SystemMode` values the configured
    /// `ControlSequenceOfOperation` leaves possible. With `HeatingOnly` /
    /// `HeatingWithReheat` "cool and precooling are not possible"; with
    /// `CoolingOnly` / `CoolingWithReheat` "heat and emergency are not
    /// possible".
    fn sequence_heats() -> bool {
        matches!(
            H::CONTROL_SEQUENCE_OF_OPERATION,
            ControlSequenceOfOperationEnum::HeatingOnly
                | ControlSequenceOfOperationEnum::HeatingWithReheat
                | ControlSequenceOfOperationEnum::CoolingAndHeating
                | ControlSequenceOfOperationEnum::CoolingAndHeatingWithReheat
        )
    }

    /// The cooling half of [`Self::sequence_heats`].
    fn sequence_cools() -> bool {
        matches!(
            H::CONTROL_SEQUENCE_OF_OPERATION,
            ControlSequenceOfOperationEnum::CoolingOnly
                | ControlSequenceOfOperationEnum::CoolingWithReheat
                | ControlSequenceOfOperationEnum::CoolingAndHeating
                | ControlSequenceOfOperationEnum::CoolingAndHeatingWithReheat
        )
    }

    /// Whether `mode` is a `SystemMode` this thermostat can be put into.
    ///
    /// Section 4.3.11.22: "Its value SHALL be limited by the
    /// ControlSequenceOfOperation attribute." Of the values that survive that
    /// limit, `Precooling`, `EmergencyHeat`, `FanOnly`, `Dry` and `Sleep` need
    /// equipment - second-stage emergency heat, a fan, a dehumidifier - that
    /// this handler knows nothing about, so they are refused too.
    fn is_supported_system_mode(mode: SystemModeEnum) -> bool {
        match mode {
            SystemModeEnum::Off => true,
            SystemModeEnum::Heat => Self::sequence_heats(),
            SystemModeEnum::Cool => Self::sequence_cools(),
            SystemModeEnum::Auto => Self::auto(),
            _ => false,
        }
    }

    /// The relays a thermostat in this configuration can have.
    ///
    /// Section 4.3.11.29: "Unimplemented outputs SHALL be treated as if they
    /// were Off", and a server whose `ControlSequenceOfOperation` rules
    /// cooling out has no cooling relay to report on, whatever
    /// [`ThermostatHooks::running_state`] says. A fan is always possible: a
    /// forced-air furnace has one.
    fn relay_mask() -> RelayStateBitmap {
        let mut mask =
            RelayStateBitmap::FAN | RelayStateBitmap::FAN_STAGE_2 | RelayStateBitmap::FAN_STAGE_3;

        if Self::sequence_heats() {
            mask |= RelayStateBitmap::HEAT | RelayStateBitmap::HEAT_STAGE_2;
        }

        if Self::sequence_cools() {
            mask |= RelayStateBitmap::COOL | RelayStateBitmap::COOL_STAGE_2;
        }

        mask
    }

    /// `ThermostatRunningState` (section 4.3.11.29), as this handler reports
    /// it - see [`Self::relay_mask`].
    fn running_state(&self) -> RelayStateBitmap {
        self.hooks.running_state().intersection(Self::relay_mask())
    }

    /// `ThermostatRunningMode` (section 4.3.11.23): "the same values as
    /// SystemModeEnum but can only be Off, Cool or Heat [...] intended to
    /// provide additional information when the thermostat's system mode is in
    /// auto mode."
    ///
    /// Derived from the relay state rather than hooked separately: which of
    /// the two the equipment is doing right now *is* which relay is closed.
    fn running_mode(&self) -> ThermostatRunningModeEnum {
        let state = self.running_state();

        if state.intersects(RelayStateBitmap::HEAT | RelayStateBitmap::HEAT_STAGE_2) {
            ThermostatRunningModeEnum::Heat
        } else if state.intersects(RelayStateBitmap::COOL | RelayStateBitmap::COOL_STAGE_2) {
            ThermostatRunningModeEnum::Cool
        } else {
            ThermostatRunningModeEnum::Off
        }
    }

    /// Push the current control state onto the device, re-reporting
    /// `ThermostatRunningState` if the relay moved as a result.
    ///
    /// This is the only path by which the handler itself can change heat or
    /// cool demand, so it is the only one that has to watch for it; a relay
    /// that moves on the device's own account reports through
    /// [`OutOfBandMessage::RunningState`] instead.
    fn apply(&self, notifier: &impl AttrChangeNotifier) {
        let before = self.running_state();

        self.hooks.apply(
            self.hooks.system_mode(),
            self.hooks.occupied_heating_setpoint(),
            self.hooks.occupied_cooling_setpoint(),
        );

        if self.running_state() != before {
            self.notify(notifier, AttributeId::ThermostatRunningState);
            self.notify(notifier, AttributeId::ThermostatRunningMode);
        }

        // Every in-band mutation - the six attribute writes,
        // `SetpointRaiseLower` and `repair` - ends here, so this is the one
        // place that can ask `run` to sweep for events on their behalf. They
        // re-report synchronously and otherwise never touch the mask.
        //
        // `repair` rings it too, harmlessly: the shadow is seeded at the top
        // of `run`, after `Startup`, so the first sweep diffs to nothing.
        if Self::emits_any() {
            self.raise(PENDING_EVENT_SWEEP);
        }
    }

    /// Stash the node's clock for the operation about to run.
    ///
    /// Called from each [`ClusterAsyncHandler`] method that can move a
    /// setpoint, and from the sweep in [`Self::run`] - the boundaries that
    /// hold a [`HandlerContext`]. Everything below them takes only an
    /// [`AttrChangeNotifier`], by design; see `SetpointChangeRecord::armed`.
    ///
    /// Skipped when `SetpointChangeSourceTimestamp` is not served, so a device
    /// that does not report the stamp never pays for the state lock
    /// [`crate::Matter::with_rtc`] takes.
    fn arm_clock(&self, ctx: &impl HandlerContext) {
        if Self::serves(AttributeId::SetpointChangeSourceTimestamp) {
            self.setpoint_change.arm(node_utc_now_secs(ctx));
        }
    }

    /// Mark a set of attributes as needing a re-report and wake [`Self::run`].
    ///
    /// Public so that a consumer holding the handler can poke it directly,
    /// besides the `notify` closure handed to [`ThermostatHooks::run`].
    pub fn out_of_band_message(&self, message: OutOfBandMessage) {
        // An out-of-band change has nothing but the doorbell, so it asks for
        // the event sweep too - nobody else will.
        self.raise(message.pending() | PENDING_EVENT_SWEEP);
    }

    /// Raise a set of mask bits and wake [`Self::run`].
    fn raise(&self, bits: u16) {
        self.pending.modify(|pending| {
            *pending |= bits;
            (true, ())
        });
    }

    /// Wait until at least one bit is pending, then take the whole mask.
    async fn wait_pending(&self) -> u16 {
        self.pending
            .wait(|pending| (*pending != 0).then(|| core::mem::take(pending)))
            .await
    }

    /// Emit one `notify_attr_changed` per pending attribute.
    ///
    /// Takes an [`AttrChangeNotifier`] rather than the [`HandlerContext`] it is
    /// called with, so that the losslessness of the mask can be pinned down in
    /// a unit test with a counting notifier.
    fn notify_pending(&self, notifier: &impl AttrChangeNotifier, pending: u16) {
        for (bit, attr) in PENDING_ATTRS {
            if pending & bit != 0 {
                self.notify(notifier, *attr);
            }
        }
    }

    /// Re-report a single attribute of this cluster instance, if it is served
    /// at all.
    fn notify(&self, notifier: &impl AttrChangeNotifier, attr: AttributeId) {
        if Self::serves(attr) {
            notifier.notify_attr_changed(self.endpoint_id, Self::CLUSTER.id, attr as AttrId);
        }
    }

    // Events (section 4.3.13)

    /// Whether the given event is part of the served set.
    fn emits(event: EventId) -> bool {
        H::CLUSTER.event(event as _).is_some()
    }

    /// Whether this configuration serves any event at all.
    ///
    /// The whole sweep is skipped when it does not, so an event-free
    /// deployment - which is every one that has not opted into the provisional
    /// `TEVT` feature - pays nothing for this machinery.
    fn emits_any() -> bool {
        H::CLUSTER.events().next().is_some()
    }

    /// `LocalTemperature` as the attribute reports it (section 4.3.11.2).
    ///
    /// Shared with the accessor so that `LocalTemperatureChange` can never
    /// disagree with the attribute it mirrors: section 4.3.13.2 says the event
    /// carries "the current value of the LocalTemperature attribute", and
    /// under `LTNE` that value is always null.
    fn reported_local_temperature(&self) -> Option<i16> {
        if Self::supports_feature(Feature::LOCAL_TEMPERATURE_NOT_EXPOSED.bits()) {
            None
        } else {
            self.hooks.local_temperature().into_option()
        }
    }

    /// Everything the event set reports, right now.
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            local_temperature: self.reported_local_temperature(),
            heating_setpoint: self.hooks.occupied_heating_setpoint(),
            cooling_setpoint: self.hooks.occupied_cooling_setpoint(),
            system_mode: self.hooks.system_mode(),
            running_state: self.running_state(),
            running_mode: self.running_mode(),
        }
    }

    /// Prime the shadow so that the first sweep has something to diff against.
    ///
    /// Called from the top of [`Self::run`] rather than from
    /// `lifecycle(Startup)`: `Startup` is not delivered in every embedding
    /// (the in-crate end-to-end runner does not), while `run` always is, and
    /// is polled before any exchange can arrive.
    ///
    /// Without this the first sweep would report all five events at once, with
    /// every `Previous*` omitted - noise that says nothing happened.
    fn seed_events(&self) {
        let snapshot = self.snapshot();

        self.event_state
            .lock(|state| state.borrow_mut().shadow = Some(snapshot));
        self.claim_setpoints();
    }

    /// Diff the shadow against the device and decide what to report.
    ///
    /// Takes no context and no emitter, so every rule in section 4.3.13 can be
    /// pinned down by a unit test. `now` is a parameter rather than an
    /// `Instant::now()` so that the 60-second floor is testable too.
    ///
    /// Commits as it goes: a field advances only when an event for it is
    /// produced. That is load-bearing for `LocalTemperature` - advancing the
    /// shadow on a suppressed change would let a slow drift in sub-threshold
    /// steps climb forever without ever reporting.
    fn take_events(&self, now: Instant) -> heapless::Vec<ThermostatEvent, 6> {
        let mut events = heapless::Vec::new();

        let current = self.snapshot();

        // One pass under one lock: the shadow and the last-event stamp are
        // read, diffed and committed together, so two sweeps cannot interleave
        // and leave the pair disagreeing. Nothing in here reaches for a hook -
        // `current` was taken above.
        let seeded = self.event_state.lock(|state| {
            let mut state = state.borrow_mut();

            let Some(previous) = state.shadow else {
                // Not seeded yet: adopt the world as it is and report nothing.
                return false;
            };

            if previous == current {
                return true;
            }

            // Ascending event ID, and within `SetpointChange` ascending attribute
            // ID - cooling (0x11) before heating (0x12) - to match the order
            // `PENDING_ATTRS` re-reports in.
            let mut committed = previous;

            if current.system_mode != previous.system_mode && Self::emits(EventId::SystemModeChange)
            {
                unwrap!(events.push(ThermostatEvent::SystemMode {
                    previous: Some(previous.system_mode),
                    current: current.system_mode,
                }));

                committed.system_mode = current.system_mode;
            }

            if Self::emits(EventId::LocalTemperatureChange)
                && local_temperature_event_due(
                    previous.local_temperature,
                    current.local_temperature,
                    H::LOCAL_TEMPERATURE_EVENT_DELTA,
                    state.last_local_temperature,
                    now,
                )
            {
                unwrap!(events.push(ThermostatEvent::LocalTemperature {
                    current: current.local_temperature,
                }));

                committed.local_temperature = current.local_temperature;
                state.last_local_temperature = Some(now);
            }

            if Self::emits(EventId::SetpointChange) {
                // Each half is gated on its feature: a heating-only device has no
                // `OccupiedCoolingSetpoint` attribute to report a change to, and
                // the hook default behind it is not a real setpoint.
                for (changed, system_mode, previous_sp, current_sp) in [
                    (
                        Self::cools() && current.cooling_setpoint != previous.cooling_setpoint,
                        SystemModeEnum::Cool,
                        previous.cooling_setpoint,
                        current.cooling_setpoint,
                    ),
                    (
                        Self::heats() && current.heating_setpoint != previous.heating_setpoint,
                        SystemModeEnum::Heat,
                        previous.heating_setpoint,
                        current.heating_setpoint,
                    ),
                ] {
                    if changed {
                        unwrap!(events.push(ThermostatEvent::Setpoint {
                            system_mode,
                            previous: Some(previous_sp),
                            current: current_sp,
                        }));
                    }
                }

                committed.heating_setpoint = current.heating_setpoint;
                committed.cooling_setpoint = current.cooling_setpoint;
            }

            if current.running_state != previous.running_state
                && Self::emits(EventId::RunningStateChange)
            {
                unwrap!(events.push(ThermostatEvent::RunningState {
                    previous: Some(previous.running_state),
                    current: current.running_state,
                }));

                committed.running_state = current.running_state;
            }

            if current.running_mode != previous.running_mode
                && Self::emits(EventId::RunningModeChange)
            {
                unwrap!(events.push(ThermostatEvent::RunningMode {
                    previous: Some(previous.running_mode),
                    current: current.running_mode,
                }));

                committed.running_mode = current.running_mode;
            }

            state.shadow = Some(committed);

            true
        });

        if !seeded {
            self.seed_events();
        }

        events
    }

    /// Attribute a setpoint movement that arrived over Matter.
    ///
    /// Called from [`Self::store_heating_setpoint`] and its cooling twin, at
    /// the point where the previous value is still in hand. Section 4.3.11.30:
    /// `External` is "Externally-initiated setpoint change (e.g., DRLC cluster
    /// command, attribute write)".
    ///
    /// Only the setpoint the client actually addressed is attributed. The
    /// deadband may drag the *opposite* setpoint along (section 4.3.11.12),
    /// but that is a side effect, not the change the client made, and
    /// `SetpointChangeAmount` is singular - "the delta between the current
    /// active OccupiedCoolingSetpoint or OccupiedHeatingSetpoint and the
    /// previous active setpoint". It still produces its own `SetpointChange`
    /// event, which is right: section 4.3.13.4 fires on *any* of the four
    /// setpoint attributes changing.
    fn attribute_external_change(&self, notifier: &impl AttrChangeNotifier, amount: i16) {
        self.setpoint_change.record(
            SetpointChangeSourceEnum::External,
            amount,
            self.hooks.utc_now_secs(),
        );

        self.notify_source_attrs(notifier);
    }

    /// Claim the current setpoint pair as attributed.
    ///
    /// Called at the *end* of each `store_*`, once the deadband has had its
    /// say: claiming earlier would leave the setpoint the deadband dragged
    /// along looking unattributed, and the sweep would call it `Manual`.
    fn claim_setpoints(&self) {
        self.setpoint_change.attribute(self.served_setpoints());
    }

    /// The `(heating, cooling)` pair, with the half this configuration does
    /// not serve pinned to zero.
    ///
    /// The hook behind an unserved setpoint returns whatever its default is,
    /// which is not a setpoint anybody can change - letting it into the
    /// comparison would attribute a phantom change to the front panel.
    fn served_setpoints(&self) -> (i16, i16) {
        let heating = if Self::heats() {
            self.hooks.occupied_heating_setpoint()
        } else {
            0
        };

        let cooling = if Self::cools() {
            self.hooks.occupied_cooling_setpoint()
        } else {
            0
        };

        (heating, cooling)
    }

    /// When a `LocalTemperatureChange` that the 60-second floor deferred
    /// becomes due, if one is waiting.
    ///
    /// Without this the deferred event would simply be dropped: the sweep only
    /// runs when something rings the doorbell, and a temperature that moves
    /// once and then settles rings it no more. The shadow does not advance on
    /// a suppressed change, so the event is still owed.
    fn deferred_local_temperature_deadline(&self) -> Option<Instant> {
        if !Self::emits(EventId::LocalTemperatureChange) {
            return None;
        }

        let (shadow, last) = self.event_state.lock(|state| {
            let state = state.borrow();

            (state.shadow, state.last_local_temperature)
        });

        let shadow = shadow?;

        if !local_temperature_change_significant(
            shadow.local_temperature,
            self.reported_local_temperature(),
            H::LOCAL_TEMPERATURE_EVENT_DELTA,
        ) {
            return None;
        }

        // Nothing has been emitted yet, so nothing is being held back.
        let last = last?;

        Some(last + LOCAL_TEMPERATURE_EVENT_MIN_INTERVAL)
    }

    /// Attribute any setpoint movement the in-band paths did not claim.
    ///
    /// [`Self::store_heating_setpoint`] and its cooling twin record `External`
    /// as they happen, so whatever is left over came from the device itself -
    /// the knob on the front panel - and is `Manual` (section 4.3.11.30).
    ///
    /// `Schedule` is unreachable here: its conformance is `[MSCH]`, and
    /// [`Self::validate`] rejects that feature.
    fn attribute_local_setpoint_change(&self, notifier: &impl AttrChangeNotifier) {
        let current = self.served_setpoints();

        let Some(attributed) = self.setpoint_change.get().attributed else {
            self.setpoint_change.attribute(current);
            return;
        };

        if attributed == current {
            return;
        }

        // Whichever moved; if both did, the heating one is reported, matching
        // the singular "the current active ... setpoint" of section 4.3.11.31.
        let amount = if current.0 != attributed.0 {
            current.0.saturating_sub(attributed.0)
        } else {
            current.1.saturating_sub(attributed.1)
        };

        self.setpoint_change.record(
            SetpointChangeSourceEnum::Manual,
            amount,
            self.hooks.utc_now_secs(),
        );
        self.setpoint_change.attribute(current);

        self.notify_source_attrs(notifier);
    }

    /// Re-report whichever of the three section 4.3.11.30-32 attributes are
    /// served.
    fn notify_source_attrs(&self, notifier: &impl AttrChangeNotifier) {
        self.notify(notifier, AttributeId::SetpointChangeSource);
        self.notify(notifier, AttributeId::SetpointChangeAmount);
        self.notify(notifier, AttributeId::SetpointChangeSourceTimestamp);
    }

    /// Serialise the swept events onto the wire.
    ///
    /// Takes a bare [`EventEmitter`] rather than the [`HandlerContext`] it is
    /// called with, so that nothing but the TLV writing needs a live `Matter`.
    ///
    /// Emission is best-effort: a full event buffer must not take down the
    /// handler's `run` task, so a failure is logged and the next change tries
    /// again. The shadow has already advanced, so that one event's
    /// `Previous*` is lost - the same trade the other measurement handlers
    /// make.
    fn emit_pending(&self, emitter: &impl EventEmitter, events: &[ThermostatEvent]) {
        for event in events {
            let emitted = match *event {
                ThermostatEvent::SystemMode { previous, current } => {
                    SystemModeChange::emit_for(emitter, self.endpoint_id, |event| {
                        event
                            .previous_system_mode(previous)?
                            .current_system_mode(current)?
                            .end()
                    })
                }
                ThermostatEvent::LocalTemperature { current } => {
                    LocalTemperatureChange::emit_for(emitter, self.endpoint_id, |event| {
                        event
                            .current_local_temperature(Nullable::new(current))?
                            .end()
                    })
                }
                ThermostatEvent::Setpoint {
                    system_mode,
                    previous,
                    current,
                } => SetpointChange::emit_for(emitter, self.endpoint_id, |event| {
                    event
                        .system_mode(system_mode)?
                        // Section 4.3.13.4.2: the field is `[OCC]`, and this
                        // handler does not implement occupancy.
                        .occupancy(None)?
                        .previous_setpoint(previous)?
                        .current_setpoint(current)?
                        .end()
                }),
                ThermostatEvent::RunningState { previous, current } => {
                    RunningStateChange::emit_for(emitter, self.endpoint_id, |event| {
                        event
                            .previous_running_state(previous)?
                            .current_running_state(current)?
                            .end()
                    })
                }
                ThermostatEvent::RunningMode { previous, current } => {
                    RunningModeChange::emit_for(emitter, self.endpoint_id, |event| {
                        event
                            .previous_running_mode(previous)?
                            .current_running_mode(current)?
                            .end()
                    })
                }
            };

            if let Err(e) = emitted {
                warn!("Failed to emit a Thermostat event: {:?}", e);
            }
        }
    }

    /// Store an already-range-checked `OccupiedHeatingSetpoint`, keeping the
    /// deadband against the cooling setpoint.
    ///
    /// Section 4.3.11.12: "If this attribute is set to a value that is greater
    /// than (OccupiedCoolingSetpoint - MinSetpointDeadBand), the value of
    /// OccupiedCoolingSetpoint SHALL be adjusted to (OccupiedHeatingSetpoint +
    /// MinSetpointDeadBand)." Note that it is the *other* setpoint that moves:
    /// this one is not rejected and not clamped.
    fn store_heating_setpoint(
        &self,
        notifier: &impl AttrChangeNotifier,
        value: i16,
    ) -> Result<(), Error> {
        let previous = self.hooks.occupied_heating_setpoint();

        if value != previous {
            self.hooks.set_occupied_heating_setpoint(value)?;
            self.notify(notifier, AttributeId::OccupiedHeatingSetpoint);
            self.attribute_external_change(notifier, value.saturating_sub(previous));
        }

        let dead_band = Self::dead_band();

        if Self::auto() && value > self.hooks.occupied_cooling_setpoint() - dead_band {
            // The limit chain of section 4.3.6 keeps
            // `MaxHeatSetpointLimit <= MaxCoolSetpointLimit - MinSetpointDeadBand`,
            // so the clamp here can never actually bite; it is in place for
            // the one case it can - a device that restored limits which
            // `repair` has not run over yet.
            let cooling = self.clamp_cool_setpoint(value as i32 + dead_band as i32);

            if cooling != self.hooks.occupied_cooling_setpoint() {
                self.hooks.set_occupied_cooling_setpoint(cooling)?;
                self.notify(notifier, AttributeId::OccupiedCoolingSetpoint);
            }
        }

        self.claim_setpoints();

        Ok(())
    }

    /// Store an already-range-checked `OccupiedCoolingSetpoint`, keeping the
    /// deadband against the heating setpoint - section 4.3.11.11, the mirror
    /// image of [`Self::store_heating_setpoint`].
    fn store_cooling_setpoint(
        &self,
        notifier: &impl AttrChangeNotifier,
        value: i16,
    ) -> Result<(), Error> {
        let previous = self.hooks.occupied_cooling_setpoint();

        if value != previous {
            self.hooks.set_occupied_cooling_setpoint(value)?;
            self.notify(notifier, AttributeId::OccupiedCoolingSetpoint);
            self.attribute_external_change(notifier, value.saturating_sub(previous));
        }

        let dead_band = Self::dead_band();

        if Self::auto() && value < self.hooks.occupied_heating_setpoint() + dead_band {
            let heating = self.clamp_heat_setpoint(value as i32 - dead_band as i32);

            if heating != self.hooks.occupied_heating_setpoint() {
                self.hooks.set_occupied_heating_setpoint(heating)?;
                self.notify(notifier, AttributeId::OccupiedHeatingSetpoint);
            }
        }

        self.claim_setpoints();

        Ok(())
    }

    /// `OccupiedHeatingSetpoint` write, section 4.3.11.12: "If an attempt is
    /// made to set this attribute to a value greater than MaxHeatSetpointLimit
    /// or less than MinHeatSetpointLimit, a response with the status code
    /// CONSTRAINT_ERROR SHALL be returned."
    ///
    /// Note the contrast with `SetpointRaiseLower`, which clamps instead - see
    /// [`Self::raise_lower_setpoint`].
    fn write_occupied_heating_setpoint(
        &self,
        notifier: impl AttrChangeNotifier,
        value: i16,
    ) -> Result<(), Error> {
        if value < self.min_heat_setpoint() || value > self.max_heat_setpoint() {
            Err(ErrorCode::ConstraintError)?;
        }

        self.store_heating_setpoint(&notifier, value)?;
        self.apply(&notifier);

        Ok(())
    }

    /// `OccupiedCoolingSetpoint` write, section 4.3.11.11 - the mirror image
    /// of [`Self::write_occupied_heating_setpoint`].
    fn write_occupied_cooling_setpoint(
        &self,
        notifier: impl AttrChangeNotifier,
        value: i16,
    ) -> Result<(), Error> {
        if value < self.min_cool_setpoint() || value > self.max_cool_setpoint() {
            Err(ErrorCode::ConstraintError)?;
        }

        self.store_cooling_setpoint(&notifier, value)?;
        self.apply(&notifier);

        Ok(())
    }

    /// `MinHeatSetpointLimit` write, section 4.3.11.15: "If an attempt is made
    /// to set this attribute to a value which conflicts with setpoint values
    /// then those setpoints SHALL be adjusted by the minimum amount to permit
    /// this attribute to be set to the desired value. If an attempt is made to
    /// set this attribute to a value which is not consistent with the
    /// constraints and cannot be resolved by modifying setpoints then a
    /// response with the status code CONSTRAINT_ERROR SHALL be returned."
    ///
    /// Raising the floor above `MaxHeatSetpointLimit`, dropping it below
    /// `AbsMinHeatSetpointLimit`, or - with `AUTO` - pushing it past
    /// `MinCoolSetpointLimit - MinSetpointDeadBand` all break the section
    /// 4.3.6 chain against another *limit*, which no setpoint adjustment can
    /// fix. Those are the `CONSTRAINT_ERROR` cases.
    fn write_min_heat_setpoint_limit(
        &self,
        notifier: impl AttrChangeNotifier,
        value: i16,
    ) -> Result<(), Error> {
        if value < H::ABS_MIN_HEAT_SETPOINT || value > self.hooks.max_heat_setpoint_limit() {
            Err(ErrorCode::ConstraintError)?;
        }

        if Self::auto() && value > self.min_cool_setpoint() - Self::dead_band() {
            Err(ErrorCode::ConstraintError)?;
        }

        self.hooks.set_min_heat_setpoint_limit(value)?;
        self.notify(&notifier, AttributeId::MinHeatSetpointLimit);

        // Drag the setpoint up by the minimum amount, if it now sits below the
        // new floor.
        if self.hooks.occupied_heating_setpoint() < value {
            self.store_heating_setpoint(&notifier, value)?;
        }

        self.apply(&notifier);

        Ok(())
    }

    /// `MaxHeatSetpointLimit` write, section 4.3.11.16 - the mirror image of
    /// [`Self::write_min_heat_setpoint_limit`].
    fn write_max_heat_setpoint_limit(
        &self,
        notifier: impl AttrChangeNotifier,
        value: i16,
    ) -> Result<(), Error> {
        if value > H::ABS_MAX_HEAT_SETPOINT || value < self.hooks.min_heat_setpoint_limit() {
            Err(ErrorCode::ConstraintError)?;
        }

        if Self::auto() && value > self.max_cool_setpoint() - Self::dead_band() {
            Err(ErrorCode::ConstraintError)?;
        }

        self.hooks.set_max_heat_setpoint_limit(value)?;
        self.notify(&notifier, AttributeId::MaxHeatSetpointLimit);

        if self.hooks.occupied_heating_setpoint() > value {
            self.store_heating_setpoint(&notifier, value)?;
        }

        self.apply(&notifier);

        Ok(())
    }

    /// `MinCoolSetpointLimit` write, section 4.3.11.17 - the cooling half of
    /// [`Self::write_min_heat_setpoint_limit`].
    fn write_min_cool_setpoint_limit(
        &self,
        notifier: impl AttrChangeNotifier,
        value: i16,
    ) -> Result<(), Error> {
        if value < H::ABS_MIN_COOL_SETPOINT || value > self.hooks.max_cool_setpoint_limit() {
            Err(ErrorCode::ConstraintError)?;
        }

        if Self::auto() && value < self.min_heat_setpoint() + Self::dead_band() {
            Err(ErrorCode::ConstraintError)?;
        }

        self.hooks.set_min_cool_setpoint_limit(value)?;
        self.notify(&notifier, AttributeId::MinCoolSetpointLimit);

        if self.hooks.occupied_cooling_setpoint() < value {
            self.store_cooling_setpoint(&notifier, value)?;
        }

        self.apply(&notifier);

        Ok(())
    }

    /// `MaxCoolSetpointLimit` write, section 4.3.11.18.
    fn write_max_cool_setpoint_limit(
        &self,
        notifier: impl AttrChangeNotifier,
        value: i16,
    ) -> Result<(), Error> {
        if value > H::ABS_MAX_COOL_SETPOINT || value < self.hooks.min_cool_setpoint_limit() {
            Err(ErrorCode::ConstraintError)?;
        }

        if Self::auto() && value < self.max_heat_setpoint() + Self::dead_band() {
            Err(ErrorCode::ConstraintError)?;
        }

        self.hooks.set_max_cool_setpoint_limit(value)?;
        self.notify(&notifier, AttributeId::MaxCoolSetpointLimit);

        if self.hooks.occupied_cooling_setpoint() > value {
            self.store_cooling_setpoint(&notifier, value)?;
        }

        self.apply(&notifier);

        Ok(())
    }

    /// `SystemMode` write, section 4.3.11.22: the value "SHALL be limited by
    /// the ControlSequenceOfOperation attribute" - see
    /// [`Self::is_supported_system_mode`].
    fn write_system_mode(
        &self,
        notifier: impl AttrChangeNotifier,
        value: SystemModeEnum,
    ) -> Result<(), Error> {
        if !Self::is_supported_system_mode(value) {
            Err(ErrorCode::ConstraintError)?;
        }

        self.hooks.set_system_mode(value)?;

        self.apply(&notifier);
        self.notify(&notifier, AttributeId::SystemMode);

        Ok(())
    }

    /// The `SetpointRaiseLower` command, section 4.3.12.1.
    ///
    /// - `Mode = Heat` / `Mode = Cool`: "if the server does not support the
    ///   HEAT [COOL] feature then it SHALL respond with INVALID_COMMAND".
    /// - `Mode = Both`: "The client MAY indicate Both regardless of the server
    ///   feature support. The server SHALL only adjust the setpoint that it
    ///   supports and not respond with an error."
    /// - `amount` is "the amount (possibly negative) that should be added to
    ///   the setpoint(s), in steps of 0.1degC", whereas the setpoint attributes
    ///   are in 0.01degC - hence the factor of ten.
    /// - "If the resulting value is outside the limits imposed by
    ///   MinCoolSetpointLimit, MaxCoolSetpointLimit, MinHeatSetpointLimit and
    ///   MaxHeatSetpointLimit, the value is clamped to those limits. This is
    ///   not considered an error condition."
    /// - And where a clamped setpoint would then break the deadband, sections
    ///   4.3.12.1.1.1/2 say the *other* setpoint moves to make room, which is
    ///   what [`Self::store_heating_setpoint`] does anyway.
    fn raise_lower_setpoint(
        &self,
        notifier: impl AttrChangeNotifier,
        mode: SetpointRaiseLowerModeEnum,
        amount: i8,
    ) -> Result<(), Error> {
        let (heat, cool) = match mode {
            SetpointRaiseLowerModeEnum::Heat => (true, false),
            SetpointRaiseLowerModeEnum::Cool => (false, true),
            SetpointRaiseLowerModeEnum::Both => (Self::heats(), Self::cools()),
        };

        if (heat && !Self::heats()) || (cool && !Self::cools()) {
            Err(ErrorCode::InvalidCommand)?;
        }

        let delta = amount as i32 * DEAD_BAND_SCALE as i32;

        if heat {
            let target =
                self.clamp_heat_setpoint(self.hooks.occupied_heating_setpoint() as i32 + delta);
            self.store_heating_setpoint(&notifier, target)?;
        }

        if cool {
            let target =
                self.clamp_cool_setpoint(self.hooks.occupied_cooling_setpoint() as i32 + delta);
            self.store_cooling_setpoint(&notifier, target)?;
        }

        self.apply(&notifier);

        Ok(())
    }

    /// Panic unless every attribute in `attrs` is served, or none of them is.
    fn validate_limit_set(attrs: &[AttributeId], what: &str) {
        let served = attrs.iter().filter(|attr| Self::serves(**attr)).count();

        if served != 0 && served != attrs.len() {
            panic!(
                "Thermostat validation: the {} setpoint limit attributes must either all be present or all be absent",
                what
            );
        }
    }

    /// Check the served event set against the conformance of section 4.3.13.
    ///
    /// Every event this cluster defines is `otherwiseConform{provisional,
    /// mandatory{TEVT & ...}}`, so `TEVT` both unlocks the set and makes the
    /// applicable part of it mandatory - there is no "serve one event and not
    /// the others". The three this handler cannot support are gated on
    /// features it rejects outright.
    fn validate_events() {
        let tevt = Self::supports_feature(Feature::EVENTS.bits());

        // `[OCC]`, `[MSCH]` and `[PRES]` respectively - features this handler
        // does not implement, so the events can never be emitted.
        for (event, feature) in [
            (EventId::OccupancyChange, "OCC"),
            (EventId::ActiveScheduleChange, "MSCH"),
            (EventId::ActivePresetChange, "PRES"),
        ] {
            if Self::emits(event) {
                panic!(
                    "Thermostat validation: the {:?} event requires the {} feature, which this handler does not implement",
                    event, feature
                );
            }
        }

        // Each remaining event, and whether this configuration must serve it.
        // `None` means "not applicable": the secondary gate is closed, so the
        // event must be absent whether or not TEVT is set.
        for (event, applicable) in [
            (EventId::SystemModeChange, true),
            (
                EventId::LocalTemperatureChange,
                !Self::supports_feature(Feature::LOCAL_TEMPERATURE_NOT_EXPOSED.bits()),
            ),
            (EventId::SetpointChange, true),
            (EventId::RunningStateChange, true),
            (EventId::RunningModeChange, Self::auto()),
        ] {
            let served = Self::emits(event);

            if served && !tevt {
                panic!(
                    "Thermostat validation: the {:?} event is served without the TEVT feature it is gated on - pass `.with_events(with!())` or enable TEVT",
                    event
                );
            }

            if !applicable {
                if served {
                    panic!(
                        "Thermostat validation: the {:?} event is served but the feature it is conditional on is not enabled",
                        event
                    );
                }

                continue;
            }

            if tevt && !served {
                panic!(
                    "Thermostat validation: the TEVT feature is enabled but the {:?} event is not served - with TEVT the whole applicable event set is mandatory",
                    event
                );
            }
        }

        // Section 4.3.11.31, a SHOULD rather than a SHALL: "devices
        // implementing SetpointChangeAmount SHOULD also implement
        // SetpointChangeSource". Everything else in `validate` is a SHALL, so
        // this warns rather than panicking.
        if Self::serves(AttributeId::SetpointChangeAmount)
            && !Self::serves(AttributeId::SetpointChangeSource)
        {
            warn!("Thermostat: SetpointChangeAmount is served without SetpointChangeSource; section 4.3.11.31 says it SHOULD be");
        }

        if Self::serves(AttributeId::SetpointChangeSourceTimestamp)
            && !Self::serves(AttributeId::SetpointChangeAmount)
        {
            warn!("Thermostat: SetpointChangeSourceTimestamp is served without the SetpointChangeAmount it timestamps");
        }

        if H::LOCAL_TEMPERATURE_EVENT_DELTA < 0 {
            panic!(
                "Thermostat validation: LOCAL_TEMPERATURE_EVENT_DELTA must not be negative, got {}",
                H::LOCAL_TEMPERATURE_EVENT_DELTA
            );
        }
    }

    /// Check that the cluster is configured in a way this handler can serve.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message if [`ThermostatHooks::CLUSTER`] is
    /// misconfigured. This is a programming error caught once at startup, not
    /// a runtime condition, which is why it is a panic rather than an `Error`.
    fn validate(&self) {
        if H::CLUSTER.revision != CLUSTER_REVISION {
            panic!(
                "Thermostat validation: incorrect revision number: expected {} got {}",
                CLUSTER_REVISION,
                H::CLUSTER.revision
            );
        }

        if H::CLUSTER.feature_map & !SUPPORTED_FEATURES != 0 {
            panic!(
                "Thermostat validation: unsupported features in the feature map: 0x{:08x}. Only HEAT, COOL, AUTO, LTNE and TEVT are implemented",
                H::CLUSTER.feature_map & !SUPPORTED_FEATURES
            );
        }

        // Section 4.3.4: HEAT and COOL are both `AUTO, O.a+` - at least one of
        // the pair, and both of them once AUTO is in play.
        if !Self::heats() && !Self::cools() {
            panic!(
                "Thermostat validation: at least one of the HEAT and COOL features must be enabled"
            );
        }

        if Self::auto() && !(Self::heats() && Self::cools()) {
            panic!("Thermostat validation: the AUTO feature requires both HEAT and COOL - there is nothing to switch between otherwise");
        }

        // Mandatory attributes: section 4.3.11 marks `LocalTemperature`,
        // `ControlSequenceOfOperation` and `SystemMode` as `M`, the occupied
        // setpoints as mandatory given their feature, and
        // `MinSetpointDeadBand` as mandatory given `AUTO`.
        for (attr, required, why) in [
            (AttributeId::LocalTemperature, true, "M"),
            (AttributeId::ControlSequenceOfOperation, true, "M"),
            (AttributeId::SystemMode, true, "M"),
            (AttributeId::OccupiedHeatingSetpoint, Self::heats(), "HEAT"),
            (AttributeId::OccupiedCoolingSetpoint, Self::cools(), "COOL"),
            (AttributeId::MinSetpointDeadBand, Self::auto(), "AUTO"),
        ] {
            if required && !Self::serves(attr) {
                panic!(
                    "Thermostat validation: missing attribute {:?}, which is mandatory ({})",
                    attr, why
                );
            }

            if !required && Self::serves(attr) {
                panic!(
                    "Thermostat validation: attribute {:?} is served without the {} feature it is conditional on",
                    attr, why
                );
            }
        }

        // The setpoint limits are individually optional, but the constraint
        // chain of section 4.3.6 and the `CONSTRAINT_ERROR` rules of sections
        // 4.3.11.12/15/16 are written in terms of all four of a temperature's
        // limits. Serving a strict subset would leave one end of the chain
        // unenforceable.
        Self::validate_limit_set(
            &[
                AttributeId::AbsMinHeatSetpointLimit,
                AttributeId::AbsMaxHeatSetpointLimit,
                AttributeId::MinHeatSetpointLimit,
                AttributeId::MaxHeatSetpointLimit,
            ],
            "heating",
        );

        Self::validate_limit_set(
            &[
                AttributeId::AbsMinCoolSetpointLimit,
                AttributeId::AbsMaxCoolSetpointLimit,
                AttributeId::MinCoolSetpointLimit,
                AttributeId::MaxCoolSetpointLimit,
            ],
            "cooling",
        );

        if Self::has_heat_limits() && !Self::heats() {
            panic!("Thermostat validation: the heating setpoint limits are served without the HEAT feature");
        }

        if Self::has_cool_limits() && !Self::cools() {
            panic!("Thermostat validation: the cooling setpoint limits are served without the COOL feature");
        }

        // With AUTO the deadband clauses of section 4.3.6 tie the two halves
        // of the chain together, so half a chain cannot be enforced.
        if Self::auto() && Self::has_heat_limits() != Self::has_cool_limits() {
            panic!("Thermostat validation: with AUTO the heating and cooling setpoint limits must either both be served or both be absent");
        }

        // `ThermostatRunningMode` is `[AUTO]`, and meaningless without it: it
        // exists to say which way an `Auto` thermostat is currently going.
        if Self::serves(AttributeId::ThermostatRunningMode) && !Self::auto() {
            panic!("Thermostat validation: ThermostatRunningMode is served without the AUTO feature it is conditional on");
        }

        Self::validate_events();

        if H::CLUSTER
            .command(CommandId::SetpointRaiseLower as _)
            .is_none()
        {
            panic!("Thermostat validation: missing required command: SetpointRaiseLower");
        }

        if H::ABS_MIN_HEAT_SETPOINT > H::ABS_MAX_HEAT_SETPOINT {
            panic!(
                "Thermostat validation: ABS_MIN_HEAT_SETPOINT ({}) must not exceed ABS_MAX_HEAT_SETPOINT ({})",
                H::ABS_MIN_HEAT_SETPOINT,
                H::ABS_MAX_HEAT_SETPOINT
            );
        }

        if H::ABS_MIN_COOL_SETPOINT > H::ABS_MAX_COOL_SETPOINT {
            panic!(
                "Thermostat validation: ABS_MIN_COOL_SETPOINT ({}) must not exceed ABS_MAX_COOL_SETPOINT ({})",
                H::ABS_MIN_COOL_SETPOINT,
                H::ABS_MAX_COOL_SETPOINT
            );
        }

        if Self::auto() {
            // Section 4.3.11.19 constrains `MinSetpointDeadBand` to 0..=127 -
            // 0.0degC to 12.7degC. (Before cluster revision 8 the ceiling was
            // 2.5degC.)
            if H::MIN_SETPOINT_DEAD_BAND < 0 {
                panic!(
                    "Thermostat validation: MIN_SETPOINT_DEAD_BAND ({}) must not be negative",
                    H::MIN_SETPOINT_DEAD_BAND
                );
            }

            // Section 4.3.6, the two deadband clauses over the device limits.
            // Unlike the user-configurable ones these are compiled in, so a
            // violation can only ever be a programming error.
            let dead_band = Self::dead_band();

            if H::ABS_MIN_HEAT_SETPOINT > H::ABS_MIN_COOL_SETPOINT - dead_band
                || H::ABS_MAX_HEAT_SETPOINT > H::ABS_MAX_COOL_SETPOINT - dead_band
            {
                panic!("Thermostat validation: with AUTO, section 4.3.6 requires ABS_MIN_HEAT_SETPOINT <= ABS_MIN_COOL_SETPOINT - MIN_SETPOINT_DEAD_BAND and the same for the maxima");
            }
        }

        // Section 4.3.10.16: the control sequence decides which system modes
        // are possible at all, so a server that advertises HEAT and a
        // cooling-only sequence has a mandatory `OccupiedHeatingSetpoint` it
        // can never act on.
        if Self::heats() != Self::sequence_heats() || Self::cools() != Self::sequence_cools() {
            panic!("Thermostat validation: CONTROL_SEQUENCE_OF_OPERATION does not match the HEAT/COOL features");
        }
    }

    /// Pull persisted state back into the section 4.3.6 constraint chain.
    ///
    /// The limits and the setpoints are non-volatile and restored by the
    /// consumer, while the absolute limits and the deadband are compiled in. A
    /// firmware update that narrows `ABS_MIN_HEAT_SETPOINT`/
    /// `ABS_MAX_HEAT_SETPOINT`, or widens `MIN_SETPOINT_DEAD_BAND`, or a
    /// corrupt restore, can therefore leave stored values out of bounds. Fix
    /// them up once at startup rather than leaving the cluster reporting values
    /// it would reject on a write.
    fn repair(&self) -> Result<(), Error> {
        let dead_band = Self::dead_band();

        if Self::has_heat_limits() {
            // AbsMinHeatSetpointLimit <= MinHeatSetpointLimit <= MaxHeatSetpointLimit <= AbsMaxHeatSetpointLimit
            let min = self
                .hooks
                .min_heat_setpoint_limit()
                .clamp(H::ABS_MIN_HEAT_SETPOINT, H::ABS_MAX_HEAT_SETPOINT);
            if min != self.hooks.min_heat_setpoint_limit() {
                self.hooks.set_min_heat_setpoint_limit(min)?;
            }

            let max = self
                .hooks
                .max_heat_setpoint_limit()
                .clamp(min, H::ABS_MAX_HEAT_SETPOINT);
            if max != self.hooks.max_heat_setpoint_limit() {
                self.hooks.set_max_heat_setpoint_limit(max)?;
            }
        }

        if Self::has_cool_limits() {
            let min = self
                .hooks
                .min_cool_setpoint_limit()
                .clamp(H::ABS_MIN_COOL_SETPOINT, H::ABS_MAX_COOL_SETPOINT);
            if min != self.hooks.min_cool_setpoint_limit() {
                self.hooks.set_min_cool_setpoint_limit(min)?;
            }

            let max = self
                .hooks
                .max_cool_setpoint_limit()
                .clamp(min, H::ABS_MAX_COOL_SETPOINT);
            if max != self.hooks.max_cool_setpoint_limit() {
                self.hooks.set_max_cool_setpoint_limit(max)?;
            }
        }

        // Section 4.3.6 with AUTO: MinHeatSetpointLimit <= (MinCoolSetpointLimit -
        // MinSetpointDeadBand), and the same for the maxima. `validate` has
        // already established that the *absolute* limits leave room for the
        // deadband, so pulling the heating limits down is always possible.
        if Self::auto() && Self::has_heat_limits() {
            let min = self
                .hooks
                .min_heat_setpoint_limit()
                .min(self.hooks.min_cool_setpoint_limit() - dead_band);
            if min != self.hooks.min_heat_setpoint_limit() {
                self.hooks.set_min_heat_setpoint_limit(min)?;
            }

            let max = self
                .hooks
                .max_heat_setpoint_limit()
                .min(self.hooks.max_cool_setpoint_limit() - dead_band)
                .max(min);
            if max != self.hooks.max_heat_setpoint_limit() {
                self.hooks.set_max_heat_setpoint_limit(max)?;
            }
        }

        // MinHeatSetpointLimit <= OccupiedHeatingSetpoint <= MaxHeatSetpointLimit,
        // and the same for the cooling pair.
        if Self::heats() {
            let setpoint = self.clamp_heat_setpoint(self.hooks.occupied_heating_setpoint() as i32);
            if setpoint != self.hooks.occupied_heating_setpoint() {
                self.hooks.set_occupied_heating_setpoint(setpoint)?;
            }
        }

        if Self::cools() {
            let setpoint = self.clamp_cool_setpoint(self.hooks.occupied_cooling_setpoint() as i32);
            if setpoint != self.hooks.occupied_cooling_setpoint() {
                self.hooks.set_occupied_cooling_setpoint(setpoint)?;
            }
        }

        // OccupiedHeatingSetpoint <= (OccupiedCoolingSetpoint - MinSetpointDeadBand).
        // Give way on the cooling side first, which is what a write to the
        // heating setpoint would do; only pull the heating setpoint down if
        // the cooling limits leave no room.
        if Self::auto() {
            let cooling = self.clamp_cool_setpoint(
                self.hooks
                    .occupied_cooling_setpoint()
                    .max(self.hooks.occupied_heating_setpoint() + dead_band) as i32,
            );
            if cooling != self.hooks.occupied_cooling_setpoint() {
                self.hooks.set_occupied_cooling_setpoint(cooling)?;
            }

            let heating = self.clamp_heat_setpoint(
                self.hooks
                    .occupied_heating_setpoint()
                    .min(cooling - dead_band) as i32,
            );
            if heating != self.hooks.occupied_heating_setpoint() {
                self.hooks.set_occupied_heating_setpoint(heating)?;
            }
        }

        if !Self::is_supported_system_mode(self.hooks.system_mode()) {
            warn!("Thermostat: persisted SystemMode is not supported; falling back to Off");
            self.hooks.set_system_mode(SystemModeEnum::Off)?;
        }

        self.apply(&());

        Ok(())
    }
}

impl<H: ThermostatHooks> ClusterAsyncHandler for ThermostatHandler<H> {
    #[doc = "The cluster-metadata corresponding to this handler trait."]
    const CLUSTER: Cluster<'static> = H::CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn lifecycle(&self, _ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        if matches!(op, LifecycleOp::Startup) {
            self.validate();
            self.repair()?;
        }

        Ok(())
    }

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        let mut hooks_fut = pin!(self.hooks.run(|message| self.out_of_band_message(message)));

        // Before anything can change: the first sweep has to diff against the
        // world as it was, not against nothing.
        self.seed_events();

        loop {
            // Re-armed every turn: a temperature event the 60-second floor of
            // section 4.3.13.2 held back is owed, and nothing else may ring
            // the doorbell again to deliver it.
            let deferred = self.deferred_local_temperature_deadline();

            match select3(
                &mut hooks_fut,
                self.wait_pending(),
                wait_until(deferred),
            )
            .await
            {
                Either3::First(_) => panic!("ThermostatHooks::run returned; implementers MUST not return. Implementations should loop forever or await core::future::pending::<()>()."),
                Either3::Second(pending) => {
                    self.notify_pending(&ctx, pending);

                    if pending & PENDING_EVENT_SWEEP != 0 {
                        // Anything the in-band paths did not claim was the
                        // device's own doing - the knob on the front panel.
                        self.arm_clock(&ctx);
                        self.attribute_local_setpoint_change(&ctx);

                        let events = self.take_events(Instant::now());
                        self.emit_pending(&ctx, &events);
                    }
                }
                Either3::Third(()) => {
                    let events = self.take_events(Instant::now());
                    self.emit_pending(&ctx, &events);
                }
            }
        }
    }

    // Attribute accessors

    /// Section 4.3.11.2: the Calculated Local Temperature, or null when it is
    /// unavailable. With the `LTNE` feature the attribute "SHALL always report
    /// null" - the equipment still controls off the calculated value, there is
    /// simply no feedback for it over Matter.
    async fn local_temperature(&self, _ctx: impl ReadContext) -> Result<Nullable<i16>, Error> {
        Ok(Nullable::new(self.reported_local_temperature()))
    }

    fn abs_min_heat_setpoint_limit(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<i16, Error>> {
        ready(Ok(H::ABS_MIN_HEAT_SETPOINT))
    }

    fn abs_max_heat_setpoint_limit(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<i16, Error>> {
        ready(Ok(H::ABS_MAX_HEAT_SETPOINT))
    }

    fn abs_min_cool_setpoint_limit(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<i16, Error>> {
        ready(Ok(H::ABS_MIN_COOL_SETPOINT))
    }

    fn abs_max_cool_setpoint_limit(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<i16, Error>> {
        ready(Ok(H::ABS_MAX_COOL_SETPOINT))
    }

    fn occupied_heating_setpoint(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<i16, Error>> {
        ready(Ok(self.hooks.occupied_heating_setpoint()))
    }

    fn occupied_cooling_setpoint(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<i16, Error>> {
        ready(Ok(self.hooks.occupied_cooling_setpoint()))
    }

    fn min_heat_setpoint_limit(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<i16, Error>> {
        ready(Ok(self.hooks.min_heat_setpoint_limit()))
    }

    fn max_heat_setpoint_limit(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<i16, Error>> {
        ready(Ok(self.hooks.max_heat_setpoint_limit()))
    }

    fn min_cool_setpoint_limit(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<i16, Error>> {
        ready(Ok(self.hooks.min_cool_setpoint_limit()))
    }

    fn max_cool_setpoint_limit(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<i16, Error>> {
        ready(Ok(self.hooks.max_cool_setpoint_limit()))
    }

    /// Section 4.3.11.19: "the minimum difference between the Heat Setpoint
    /// and the Cool Setpoint", in units of 0.1degC.
    fn min_setpoint_dead_band(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<i8, Error>> {
        ready(Ok(H::MIN_SETPOINT_DEAD_BAND))
    }

    async fn control_sequence_of_operation(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<ControlSequenceOfOperationEnum, Error> {
        Ok(H::CONTROL_SEQUENCE_OF_OPERATION)
    }

    async fn system_mode(&self, _ctx: impl ReadContext) -> Result<SystemModeEnum, Error> {
        Ok(self.hooks.system_mode())
    }

    /// See [`Self::running_mode`].
    async fn thermostat_running_mode(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<ThermostatRunningModeEnum, Error> {
        Ok(self.running_mode())
    }

    /// Section 4.3.11.29: "the current relay state of the heat, cool, and fan
    /// relays. Unimplemented outputs SHALL be treated as if they were Off."
    async fn thermostat_running_state(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<RelayStateBitmap, Error> {
        Ok(self.running_state())
    }

    /// Section 4.3.11.30: "the source of the current active
    /// OccupiedCoolingSetpoint or OccupiedHeatingSetpoint (i.e., who or what
    /// determined the current setpoint)."
    ///
    /// Only ever `Manual` or `External` here: `Schedule` is `[MSCH]`, and
    /// [`Self::validate`] rejects that feature.
    async fn setpoint_change_source(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<SetpointChangeSourceEnum, Error> {
        Ok(self.setpoint_change.get().source)
    }

    /// Section 4.3.11.31: "the delta between the current active
    /// OccupiedCoolingSetpoint or OccupiedHeatingSetpoint and the previous
    /// active setpoint [...] The null value indicates that the previous
    /// setpoint was unknown."
    async fn setpoint_change_amount(&self, _ctx: impl ReadContext) -> Result<Nullable<i16>, Error> {
        Ok(Nullable::new(self.setpoint_change.get().amount))
    }

    /// Section 4.3.11.32: "the time in UTC at which the SetpointChangeAmount
    /// attribute change was recorded", in Matter-epoch seconds.
    ///
    /// Zero until a setpoint has moved while the node (or
    /// [`ThermostatHooks::utc_now_secs`]) had a reliable clock to offer -
    /// `epoch-s` is not nullable, so there is no way to say "unknown"
    /// outright.
    async fn setpoint_change_source_timestamp(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.setpoint_change.get().timestamp)
    }

    // Attribute writes

    /// See [`Self::write_occupied_heating_setpoint`].
    fn set_occupied_heating_setpoint(
        &self,
        ctx: impl WriteContext,
        value: i16,
    ) -> impl Future<Output = Result<(), Error>> {
        self.arm_clock(&ctx);

        ready(self.write_occupied_heating_setpoint(&ctx, value))
    }

    /// See [`Self::write_occupied_cooling_setpoint`].
    fn set_occupied_cooling_setpoint(
        &self,
        ctx: impl WriteContext,
        value: i16,
    ) -> impl Future<Output = Result<(), Error>> {
        self.arm_clock(&ctx);

        ready(self.write_occupied_cooling_setpoint(&ctx, value))
    }

    /// See [`Self::write_min_heat_setpoint_limit`].
    fn set_min_heat_setpoint_limit(
        &self,
        ctx: impl WriteContext,
        value: i16,
    ) -> impl Future<Output = Result<(), Error>> {
        self.arm_clock(&ctx);

        ready(self.write_min_heat_setpoint_limit(&ctx, value))
    }

    /// See [`Self::write_max_heat_setpoint_limit`].
    fn set_max_heat_setpoint_limit(
        &self,
        ctx: impl WriteContext,
        value: i16,
    ) -> impl Future<Output = Result<(), Error>> {
        self.arm_clock(&ctx);

        ready(self.write_max_heat_setpoint_limit(&ctx, value))
    }

    /// See [`Self::write_min_cool_setpoint_limit`].
    fn set_min_cool_setpoint_limit(
        &self,
        ctx: impl WriteContext,
        value: i16,
    ) -> impl Future<Output = Result<(), Error>> {
        self.arm_clock(&ctx);

        ready(self.write_min_cool_setpoint_limit(&ctx, value))
    }

    /// See [`Self::write_max_cool_setpoint_limit`].
    fn set_max_cool_setpoint_limit(
        &self,
        ctx: impl WriteContext,
        value: i16,
    ) -> impl Future<Output = Result<(), Error>> {
        self.arm_clock(&ctx);

        ready(self.write_max_cool_setpoint_limit(&ctx, value))
    }

    /// Section 4.3.11.19: "For backwards compatibility, this attribute is
    /// optionally writeable. However any writes to this attribute SHALL be
    /// silently ignored." Same shape as
    /// [`Self::set_control_sequence_of_operation`], and the same reason the
    /// value is a hooks const with no setter.
    async fn set_min_setpoint_dead_band(
        &self,
        _ctx: impl WriteContext,
        _value: i8,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Section 4.3.11.21: "If an attempt is made to write to this attribute,
    /// the server SHALL silently ignore the write and the value of this
    /// attribute SHALL remain unchanged. This behavior is in place for
    /// backwards compatibility with existing thermostats."
    ///
    /// "Silently" means `SUCCESS` with no state change - not
    /// `UNSUPPORTED_WRITE`, and no change notification either.
    async fn set_control_sequence_of_operation(
        &self,
        _ctx: impl WriteContext,
        _value: ControlSequenceOfOperationEnum,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// See [`Self::write_system_mode`].
    async fn set_system_mode(
        &self,
        ctx: impl WriteContext,
        value: SystemModeEnum,
    ) -> Result<(), Error> {
        self.write_system_mode(&ctx, value)
    }

    // Commands

    /// See [`Self::raise_lower_setpoint`].
    async fn handle_setpoint_raise_lower(
        &self,
        ctx: impl InvokeContext,
        request: SetpointRaiseLowerRequest<'_>,
    ) -> Result<(), Error> {
        self.arm_clock(&ctx);

        self.raise_lower_setpoint(&ctx, request.mode()?, request.amount()?)
    }

    // Commands that belong to features this handler does not implement. They
    // are filtered out of `AcceptedCommandList` by `with_cmds`, so the adaptor
    // rejects them before they reach us; these impls only exist because the
    // generated trait has no defaults for command handlers.

    async fn handle_set_weekly_schedule(
        &self,
        _ctx: impl InvokeContext,
        _request: SetWeeklyScheduleRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_get_weekly_schedule<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: GetWeeklyScheduleRequest<'_>,
        _response: GetWeeklyScheduleResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_clear_weekly_schedule(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_set_active_schedule_request(
        &self,
        _ctx: impl InvokeContext,
        _request: SetActiveScheduleRequestRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_set_active_preset_request(
        &self,
        _ctx: impl InvokeContext,
        _request: SetActivePresetRequestRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_add_thermostat_suggestion<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: AddThermostatSuggestionRequest<'_>,
        _response: AddThermostatSuggestionResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_remove_thermostat_suggestion(
        &self,
        _ctx: impl InvokeContext,
        _request: RemoveThermostatSuggestionRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_atomic_request<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: AtomicRequestRequest<'_>,
        _response: AtomicResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::CommandNotFound.into())
    }
}

/// The device-specific half of a thermostat.
///
/// The handler owns every spec rule; the hooks own the hardware and the
/// persistence. Each `set_*` method below backs a non-volatile attribute and
/// SHALL persist its value across reboots. None of them should validate or
/// clamp - the handler has already done that, and re-checking here would only
/// let the two disagree.
///
/// The cooling half has defaults throughout, so a heating-only device
/// implements exactly what it did before the `COOL` feature existed; the same
/// goes the other way for the heating half.
pub trait ThermostatHooks {
    /// The cluster metadata, which selects the features, attributes and
    /// commands this instance serves. See [`ThermostatHandler::validate`] for
    /// what a valid configuration has to look like.
    const CLUSTER: Cluster<'static>;

    /// `AbsMinHeatSetpointLimit` (section 4.3.11.5): "the absolute minimum
    /// level that the heating setpoint MAY be set to. This is a limitation
    /// imposed by the manufacturer." Its `fixed` quality is why it is a const.
    ///
    /// In 0.01°C; the spec default is 700 (7.00°C).
    const ABS_MIN_HEAT_SETPOINT: i16 = 700;

    /// `AbsMaxHeatSetpointLimit` (section 4.3.11.6), in 0.01°C; the spec
    /// default is 3000 (30.00°C).
    const ABS_MAX_HEAT_SETPOINT: i16 = 3000;

    /// `AbsMinCoolSetpointLimit` (section 4.3.11.7), in 0.01°C; the spec
    /// default is 1600 (16.00°C).
    const ABS_MIN_COOL_SETPOINT: i16 = 1600;

    /// `AbsMaxCoolSetpointLimit` (section 4.3.11.8), in 0.01°C; the spec
    /// default is 3200 (32.00°C).
    const ABS_MAX_COOL_SETPOINT: i16 = 3200;

    /// `MinSetpointDeadBand` (section 4.3.11.19): "the minimum difference
    /// between the Heat Setpoint and the Cool Setpoint", in units of 0.1°C and
    /// constrained to 0..=127. Only consulted with the `AUTO` feature, which
    /// is the only case in which the deadband clauses of section 4.3.6 apply
    /// at all.
    ///
    /// A const because writes to the attribute "SHALL be silently ignored", so
    /// it never changes. The spec default is 20 (2.0°C).
    const MIN_SETPOINT_DEAD_BAND: i8 = 20;

    /// `ControlSequenceOfOperation` (section 4.3.11.21). A const because
    /// writes to the attribute are silently ignored, so it never changes.
    ///
    /// It has to agree with the `HEAT` and `COOL` features - see
    /// [`ThermostatHandler::validate`].
    const CONTROL_SEQUENCE_OF_OPERATION: ControlSequenceOfOperationEnum =
        ControlSequenceOfOperationEnum::HeatingOnly;

    /// The Calculated Local Temperature in 0.01°C, or null when the reading is
    /// unavailable (section 4.3.11.1).
    fn local_temperature(&self) -> Nullable<i16>;

    /// Raw `OccupiedHeatingSetpoint` getter, in 0.01°C.
    ///
    /// Only called with the `HEAT` feature; the default is the value least
    /// likely to disturb the deadband arithmetic of a cooling-only device.
    fn occupied_heating_setpoint(&self) -> i16 {
        Self::ABS_MIN_HEAT_SETPOINT
    }

    /// Raw `OccupiedHeatingSetpoint` setter. This value SHALL be persisted
    /// across reboots.
    fn set_occupied_heating_setpoint(&self, _value: i16) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    /// Raw `OccupiedCoolingSetpoint` getter, in 0.01°C.
    ///
    /// Only called with the `COOL` feature.
    fn occupied_cooling_setpoint(&self) -> i16 {
        Self::ABS_MAX_COOL_SETPOINT
    }

    /// Raw `OccupiedCoolingSetpoint` setter. This value SHALL be persisted
    /// across reboots.
    fn set_occupied_cooling_setpoint(&self, _value: i16) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    /// Raw `MinHeatSetpointLimit` getter, in 0.01°C.
    ///
    /// Only called when the setpoint-limit attributes are served; the default
    /// returns [`Self::ABS_MIN_HEAT_SETPOINT`] for devices that omit them.
    fn min_heat_setpoint_limit(&self) -> i16 {
        Self::ABS_MIN_HEAT_SETPOINT
    }

    /// Raw `MinHeatSetpointLimit` setter. This value SHALL be persisted across
    /// reboots.
    fn set_min_heat_setpoint_limit(&self, _value: i16) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    /// Raw `MaxHeatSetpointLimit` getter, in 0.01°C.
    fn max_heat_setpoint_limit(&self) -> i16 {
        Self::ABS_MAX_HEAT_SETPOINT
    }

    /// Raw `MaxHeatSetpointLimit` setter. This value SHALL be persisted across
    /// reboots.
    fn set_max_heat_setpoint_limit(&self, _value: i16) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    /// Raw `MinCoolSetpointLimit` getter, in 0.01°C.
    fn min_cool_setpoint_limit(&self) -> i16 {
        Self::ABS_MIN_COOL_SETPOINT
    }

    /// Raw `MinCoolSetpointLimit` setter. This value SHALL be persisted across
    /// reboots.
    fn set_min_cool_setpoint_limit(&self, _value: i16) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    /// Raw `MaxCoolSetpointLimit` getter, in 0.01°C.
    fn max_cool_setpoint_limit(&self) -> i16 {
        Self::ABS_MAX_COOL_SETPOINT
    }

    /// Raw `MaxCoolSetpointLimit` setter. This value SHALL be persisted across
    /// reboots.
    fn set_max_cool_setpoint_limit(&self, _value: i16) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    /// Raw `SystemMode` getter.
    fn system_mode(&self) -> SystemModeEnum;

    /// Raw `SystemMode` setter. This value SHALL be persisted across reboots.
    fn set_system_mode(&self, value: SystemModeEnum) -> Result<(), Error>;

    /// `ThermostatRunningState` (section 4.3.11.29): which relays the
    /// equipment currently has energised.
    ///
    /// This is the one place where the device's own control algorithm - the
    /// thing [`Self::apply`] feeds - becomes visible over Matter, so it is the
    /// device that answers it, not the cluster. The default reports nothing
    /// energised, which is the right answer for a device that omits the
    /// attribute, and a conformant one for a device that cannot tell.
    ///
    /// The handler masks the result to the relays the configured feature set
    /// allows, so a stray `Cool` bit from a heating-only device never reaches
    /// the wire. `ThermostatRunningMode` is derived from the same answer.
    fn running_state(&self) -> RelayStateBitmap {
        RelayStateBitmap::empty()
    }

    /// Push the resolved control state onto the equipment.
    ///
    /// Called after every change to `SystemMode` or either setpoint, and once
    /// at startup. The Matter spec deliberately does not define the control
    /// algorithm, so turning `(mode, setpoints, local temperature)` into heat
    /// or cool demand - with whatever hysteresis or PI loop the hardware needs
    /// - is the device's business, not the cluster's.
    ///
    /// The setpoint for a temperature the device does not serve is whatever
    /// the corresponding hook default returns, and should be ignored.
    fn apply(&self, system_mode: SystemModeEnum, heating_setpoint: i16, cooling_setpoint: i16);

    /// The current UTC time in Matter-epoch seconds (seconds since
    /// 2000-01-01T00:00:00Z), or `None` while the device has no reliable
    /// clock.
    ///
    /// **An override, not a requirement.** Leave it alone and
    /// `SetpointChangeSourceTimestamp` (section 4.3.11.32) is stamped from the
    /// node's own Last-Known-Good UTC time, which the handler reads through
    /// its context. Implement it only when the device has a clock it trusts
    /// more than the node's - a real RTC, or a time source of its own - in
    /// which case this wins.
    ///
    /// Only consulted when `SetpointChangeSourceTimestamp` is served.
    fn utc_now_secs(&self) -> Option<u32> {
        None
    }

    /// How far `LocalTemperature` must move before it is worth a
    /// `LocalTemperatureChange` event, in 0.01°C.
    ///
    /// Section 4.3.13.2 leaves the threshold to the server - "sufficiently
    /// large, as determined by the server" - and only fixes the 60-second
    /// floor, which the handler applies regardless. The default is 0.50°C.
    const LOCAL_TEMPERATURE_EVENT_DELTA: i16 = 50;

    /// Background task for out-of-band notifications to the handler.
    ///
    /// This future MUST NOT return. Implementers should either loop forever or
    /// await `core::future::pending::<()>()`, so the SDK's task does not
    /// observe a completed future.
    ///
    /// # Panics
    /// The SDK will panic if this method returns.
    async fn run<F: Fn(OutOfBandMessage)>(&self, _notify: F) {
        core::future::pending::<()>().await
    }
}

impl<T> ThermostatHooks for &T
where
    T: ThermostatHooks,
{
    const CLUSTER: Cluster<'static> = T::CLUSTER;
    const ABS_MIN_HEAT_SETPOINT: i16 = T::ABS_MIN_HEAT_SETPOINT;
    const ABS_MAX_HEAT_SETPOINT: i16 = T::ABS_MAX_HEAT_SETPOINT;
    const ABS_MIN_COOL_SETPOINT: i16 = T::ABS_MIN_COOL_SETPOINT;
    const ABS_MAX_COOL_SETPOINT: i16 = T::ABS_MAX_COOL_SETPOINT;
    const MIN_SETPOINT_DEAD_BAND: i8 = T::MIN_SETPOINT_DEAD_BAND;
    const CONTROL_SEQUENCE_OF_OPERATION: ControlSequenceOfOperationEnum =
        T::CONTROL_SEQUENCE_OF_OPERATION;
    const LOCAL_TEMPERATURE_EVENT_DELTA: i16 = T::LOCAL_TEMPERATURE_EVENT_DELTA;

    fn utc_now_secs(&self) -> Option<u32> {
        (*self).utc_now_secs()
    }

    fn local_temperature(&self) -> Nullable<i16> {
        (*self).local_temperature()
    }

    fn occupied_heating_setpoint(&self) -> i16 {
        (*self).occupied_heating_setpoint()
    }

    fn set_occupied_heating_setpoint(&self, value: i16) -> Result<(), Error> {
        (*self).set_occupied_heating_setpoint(value)
    }

    fn occupied_cooling_setpoint(&self) -> i16 {
        (*self).occupied_cooling_setpoint()
    }

    fn set_occupied_cooling_setpoint(&self, value: i16) -> Result<(), Error> {
        (*self).set_occupied_cooling_setpoint(value)
    }

    fn min_heat_setpoint_limit(&self) -> i16 {
        (*self).min_heat_setpoint_limit()
    }

    fn set_min_heat_setpoint_limit(&self, value: i16) -> Result<(), Error> {
        (*self).set_min_heat_setpoint_limit(value)
    }

    fn max_heat_setpoint_limit(&self) -> i16 {
        (*self).max_heat_setpoint_limit()
    }

    fn set_max_heat_setpoint_limit(&self, value: i16) -> Result<(), Error> {
        (*self).set_max_heat_setpoint_limit(value)
    }

    fn min_cool_setpoint_limit(&self) -> i16 {
        (*self).min_cool_setpoint_limit()
    }

    fn set_min_cool_setpoint_limit(&self, value: i16) -> Result<(), Error> {
        (*self).set_min_cool_setpoint_limit(value)
    }

    fn max_cool_setpoint_limit(&self) -> i16 {
        (*self).max_cool_setpoint_limit()
    }

    fn set_max_cool_setpoint_limit(&self, value: i16) -> Result<(), Error> {
        (*self).set_max_cool_setpoint_limit(value)
    }

    fn system_mode(&self) -> SystemModeEnum {
        (*self).system_mode()
    }

    fn set_system_mode(&self, value: SystemModeEnum) -> Result<(), Error> {
        (*self).set_system_mode(value)
    }

    fn running_state(&self) -> RelayStateBitmap {
        (*self).running_state()
    }

    fn apply(&self, system_mode: SystemModeEnum, heating_setpoint: i16, cooling_setpoint: i16) {
        (*self).apply(system_mode, heating_setpoint, cooling_setpoint)
    }

    fn run<F: Fn(OutOfBandMessage)>(&self, notify: F) -> impl Future<Output = ()> {
        (*self).run(notify)
    }
}

pub mod test {
    use crate::utils::cell::RefCell;
    use crate::utils::sync::blocking::Mutex;

    use embassy_time::{Duration, Timer};

    use crate::dm::clusters::decl::thermostat as thermostat_cluster;
    use crate::dm::Cluster;
    use crate::error::Error;
    use crate::tlv::Nullable;
    use crate::with;

    use super::{OutOfBandMessage, RelayStateBitmap, SystemModeEnum, ThermostatHooks};

    /// How often the simulated room temperature is recomputed.
    const TICK: Duration = Duration::from_secs(5);

    /// How fast the room warms towards the setpoint while heating, in 0.01°C
    /// per [`TICK`].
    const HEATING_RATE: i16 = 20;

    /// How fast the room cools towards [`AMBIENT`] while idle, in 0.01°C per
    /// [`TICK`].
    const COOLING_RATE: i16 = 10;

    /// The temperature the simulated room drifts to with the heating off.
    const AMBIENT: i16 = 1600;

    /// A simulated heating thermostat.
    ///
    /// Note that a real device would persist the four non-volatile attributes;
    /// this one keeps them in RAM, so they reset on restart. See
    /// `examples/src/bin/dimmable_light.rs` and `tests/src/bin/light_tests.rs`
    /// for file- and KV-backed persistence of hook state.
    pub struct TestThermostatDeviceLogic {
        state: Mutex<RefCell<TestThermostatState>>,
    }

    /// The simulated thermostat's state, behind one lock the way `on_off`
    /// keeps its own.
    struct TestThermostatState {
        local_temperature: i16,
        occupied_heating_setpoint: i16,
        min_heat_setpoint_limit: i16,
        max_heat_setpoint_limit: i16,
        system_mode: SystemModeEnum,
        heating: bool,
    }

    impl TestThermostatDeviceLogic {
        /// Create a new simulated thermostat, idle at [`AMBIENT`] with the
        /// spec-default setpoint of 20.00°C.
        pub const fn new() -> Self {
            Self {
                state: Mutex::new(RefCell::new(TestThermostatState {
                    local_temperature: AMBIENT,
                    occupied_heating_setpoint: 2000,
                    min_heat_setpoint_limit: Self::ABS_MIN_HEAT_SETPOINT,
                    max_heat_setpoint_limit: Self::ABS_MAX_HEAT_SETPOINT,
                    system_mode: SystemModeEnum::Off,
                    heating: false,
                })),
            }
        }

        /// Whether the simulated heater is currently calling for heat.
        pub fn heating(&self) -> bool {
            self.state.lock(|state| state.borrow().heating)
        }

        /// Advance the room simulation by one [`TICK`], returning `true` if the
        /// local temperature changed.
        fn tick(&self) -> bool {
            self.state.lock(|state| {
                let mut state = state.borrow_mut();

                let previous = state.local_temperature;

                let temperature = if state.heating {
                    previous.saturating_add(HEATING_RATE)
                } else {
                    previous.saturating_sub(COOLING_RATE).max(AMBIENT)
                };

                state.local_temperature = temperature;

                // A one-notch hysteresis band around the setpoint, so the
                // simulated relay does not chatter every tick.
                let setpoint = state.occupied_heating_setpoint;
                state.heating = matches!(state.system_mode, SystemModeEnum::Heat)
                    && if state.heating {
                        temperature < setpoint.saturating_add(HEATING_RATE)
                    } else {
                        temperature < setpoint.saturating_sub(HEATING_RATE)
                    };

                temperature != previous
            })
        }
    }

    impl Default for TestThermostatDeviceLogic {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ThermostatHooks for TestThermostatDeviceLogic {
        /// A heating-only thermostat: the `HEAT` feature, the four mandatory
        /// attributes plus the optional heat setpoint limits, and the one
        /// mandatory command.
        ///
        /// It also opts into `TEVT` and the section 4.3.11.30-32 trio, so that
        /// the event and setpoint-attribution paths are exercised somewhere.
        /// `TEVT` is *provisional* in Matter 1.6 and 1.7 - this is a test
        /// fixture, and a shippable device should not copy that part. The
        /// certification device-under-test in `tests/src/bin` deliberately
        /// does not.
        const CLUSTER: Cluster<'static> = thermostat_cluster::FULL_CLUSTER
            .with_revision(11)
            .with_features(
                thermostat_cluster::Feature::HEATING.bits()
                    | thermostat_cluster::Feature::EVENTS.bits(),
            )
            .with_attrs(with!(
                required;
                thermostat_cluster::AttributeId::AbsMinHeatSetpointLimit
                    | thermostat_cluster::AttributeId::AbsMaxHeatSetpointLimit
                    | thermostat_cluster::AttributeId::OccupiedHeatingSetpoint
                    | thermostat_cluster::AttributeId::MinHeatSetpointLimit
                    | thermostat_cluster::AttributeId::MaxHeatSetpointLimit
                    | thermostat_cluster::AttributeId::ThermostatRunningState
                    | thermostat_cluster::AttributeId::SetpointChangeSource
                    | thermostat_cluster::AttributeId::SetpointChangeAmount
                    | thermostat_cluster::AttributeId::SetpointChangeSourceTimestamp
            ))
            .with_cmds(with!(thermostat_cluster::CommandId::SetpointRaiseLower))
            // No `RunningModeChange`: that one is `[AUTO]`, and this is a
            // heating-only device.
            .with_events(with!(
                thermostat_cluster::EventId::SystemModeChange
                    | thermostat_cluster::EventId::LocalTemperatureChange
                    | thermostat_cluster::EventId::SetpointChange
                    | thermostat_cluster::EventId::RunningStateChange
            ));

        /// A fixed clock, so the timestamp a test reads back is predictable.
        fn utc_now_secs(&self) -> Option<u32> {
            Some(1000)
        }

        fn local_temperature(&self) -> Nullable<i16> {
            Nullable::some(self.state.lock(|state| state.borrow().local_temperature))
        }

        fn occupied_heating_setpoint(&self) -> i16 {
            self.state
                .lock(|state| state.borrow().occupied_heating_setpoint)
        }

        fn set_occupied_heating_setpoint(&self, value: i16) -> Result<(), Error> {
            self.state
                .lock(|state| state.borrow_mut().occupied_heating_setpoint = value);
            Ok(())
        }

        fn min_heat_setpoint_limit(&self) -> i16 {
            self.state
                .lock(|state| state.borrow().min_heat_setpoint_limit)
        }

        fn set_min_heat_setpoint_limit(&self, value: i16) -> Result<(), Error> {
            self.state
                .lock(|state| state.borrow_mut().min_heat_setpoint_limit = value);
            Ok(())
        }

        fn max_heat_setpoint_limit(&self) -> i16 {
            self.state
                .lock(|state| state.borrow().max_heat_setpoint_limit)
        }

        fn set_max_heat_setpoint_limit(&self, value: i16) -> Result<(), Error> {
            self.state
                .lock(|state| state.borrow_mut().max_heat_setpoint_limit = value);
            Ok(())
        }

        fn system_mode(&self) -> SystemModeEnum {
            self.state.lock(|state| state.borrow().system_mode)
        }

        fn set_system_mode(&self, value: SystemModeEnum) -> Result<(), Error> {
            self.state
                .lock(|state| state.borrow_mut().system_mode = value);
            Ok(())
        }

        /// The simulated equipment is a single-stage heater with no fan, so
        /// the only relay it ever has energised is `Heat`.
        fn running_state(&self) -> RelayStateBitmap {
            if self.heating() {
                RelayStateBitmap::HEAT
            } else {
                RelayStateBitmap::empty()
            }
        }

        /// A heating-only device: the cooling setpoint is whatever the hook
        /// default returns, and means nothing here.
        fn apply(
            &self,
            system_mode: SystemModeEnum,
            heating_setpoint: i16,
            _cooling_setpoint: i16,
        ) {
            info!(
                "Emulation: system mode {:?}, heating setpoint {}.{:02}C",
                system_mode,
                heating_setpoint / 100,
                (heating_setpoint % 100).abs()
            );

            // Re-evaluate the relay immediately rather than waiting a tick, so
            // that switching to `Heat` has a visible effect right away.
            self.state.lock(|state| {
                let mut state = state.borrow_mut();

                state.heating = matches!(system_mode, SystemModeEnum::Heat)
                    && state.local_temperature < heating_setpoint;
            });
        }

        async fn run<F: Fn(OutOfBandMessage)>(&self, notify: F) {
            loop {
                // In a real device we would wait on a temperature sensor.
                Timer::after(TICK).await;

                let heating = self.heating();

                if self.tick() {
                    notify(OutOfBandMessage::LocalTemperature);
                }

                // The hysteresis band can move the relay without anyone having
                // written anything, so this is the one relay transition the
                // handler cannot see for itself.
                if self.heating() != heating {
                    notify(OutOfBandMessage::RunningState);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the spec rules [`ThermostatHandler`] enforces.
    //!
    //! They drive the context-free helpers the `ClusterAsyncHandler` methods
    //! delegate to, rather than the methods themselves: a `ReadContext` /
    //! `WriteContext` can only be built around a live `Matter` instance,
    //! whereas the helpers need nothing but an [`AttrChangeNotifier`] - and
    //! `()` is a no-op one.

    use embassy_futures::block_on;

    use crate::dm::clusters::app::test_util::RecordingNotifier;
    use crate::dm::clusters::decl::thermostat as thermostat_cluster;
    use crate::dm::{
        Access, AttrId, Attribute, Cluster, CmdId, Dataver, Event, EventId as RawEventId,
        Privilege, Quality,
    };
    use crate::error::{Error, ErrorCode};
    use crate::tlv::Nullable;
    use crate::utils::cell::RefCell;
    use crate::utils::sync::blocking::Mutex;
    use crate::with;

    use embassy_time::{Duration, Instant};

    use super::test::TestThermostatDeviceLogic;
    use super::{
        local_temperature_event_due, AttributeId, CommandId, ControlSequenceOfOperationEnum,
        EventId, OutOfBandMessage, RelayStateBitmap, SetpointChangeSourceEnum,
        SetpointRaiseLowerModeEnum, SystemModeEnum, ThermostatEvent, ThermostatHandler,
        ThermostatHooks, ThermostatRunningModeEnum, PENDING_EVENT_SWEEP,
    };

    /// `()` is a no-op `AttrChangeNotifier`, which is all the helpers need.
    const NULL_CTX: &() = &();

    /// The served set of a device that implements everything this handler can,
    /// narrowed by the FeatureMap it is asked about.
    ///
    /// `with_attrs` matchers are handed the feature map, which is what lets one
    /// `CLUSTER` const back every feature combination the tests walk.
    fn mock_attrs(attr: &Attribute, _revision: u16, features: u32) -> bool {
        let has = |feature: thermostat_cluster::Feature| features & feature.bits() != 0;

        if !attr.quality.contains(Quality::OPTIONAL) {
            return true;
        }

        let Ok(id) = attr.id.try_into() else {
            return false;
        };

        match id {
            AttributeId::AbsMinHeatSetpointLimit
            | AttributeId::AbsMaxHeatSetpointLimit
            | AttributeId::OccupiedHeatingSetpoint
            | AttributeId::MinHeatSetpointLimit
            | AttributeId::MaxHeatSetpointLimit => has(thermostat_cluster::Feature::HEATING),
            AttributeId::AbsMinCoolSetpointLimit
            | AttributeId::AbsMaxCoolSetpointLimit
            | AttributeId::OccupiedCoolingSetpoint
            | AttributeId::MinCoolSetpointLimit
            | AttributeId::MaxCoolSetpointLimit => has(thermostat_cluster::Feature::COOLING),
            AttributeId::MinSetpointDeadBand | AttributeId::ThermostatRunningMode => {
                has(thermostat_cluster::Feature::AUTO_MODE)
            }
            AttributeId::ThermostatRunningState => true,
            // Deliberately *not* the section 4.3.11.30-32 trio: they are not
            // feature-gated, so serving them here would add three re-reports
            // to every setpoint write and disturb the notification-order
            // assertions the rest of these tests make. `SourceMockHooks`
            // serves them instead.
            _ => false,
        }
    }

    /// The served event set, mirroring [`mock_attrs`]: the conformance of
    /// section 4.3.13, driven off the feature map.
    fn mock_events(event: &Event, _revision: u16, features: u32) -> bool {
        let has = |feature: thermostat_cluster::Feature| features & feature.bits() != 0;

        if !has(thermostat_cluster::Feature::EVENTS) {
            return false;
        }

        let Ok(id) = event.id.try_into() else {
            return false;
        };

        match id {
            EventId::SystemModeChange | EventId::SetpointChange | EventId::RunningStateChange => {
                true
            }
            EventId::LocalTemperatureChange => {
                !has(thermostat_cluster::Feature::LOCAL_TEMPERATURE_NOT_EXPOSED)
            }
            EventId::RunningModeChange => has(thermostat_cluster::Feature::AUTO_MODE),
            // `[OCC]`, `[MSCH]` and `[PRES]` - features this handler rejects.
            EventId::OccupancyChange
            | EventId::ActiveScheduleChange
            | EventId::ActivePresetChange => false,
        }
    }

    /// Hooks whose feature map is a const parameter, so each test can pick its
    /// own cluster configuration. Mirrors `color_control::tests::MockHooks`.
    struct MockHooks<const F: u32> {
        state: Mutex<RefCell<MockState>>,
    }

    /// The attributes [`MockHooks`] stands in for, behind one lock.
    struct MockState {
        local_temperature: Option<i16>,
        occupied_heating_setpoint: i16,
        occupied_cooling_setpoint: i16,
        min_heat_setpoint_limit: i16,
        max_heat_setpoint_limit: i16,
        min_cool_setpoint_limit: i16,
        max_cool_setpoint_limit: i16,
        system_mode: SystemModeEnum,
        running_state: RelayStateBitmap,
        /// How many times [`ThermostatHooks::apply`] has been called.
        applied: u32,
    }

    impl<const F: u32> MockHooks<F> {
        const fn new() -> Self {
            Self {
                state: Mutex::new(RefCell::new(MockState {
                    local_temperature: Some(1900),
                    occupied_heating_setpoint: 2000,
                    occupied_cooling_setpoint: 2600,
                    min_heat_setpoint_limit: Self::ABS_MIN_HEAT_SETPOINT,
                    max_heat_setpoint_limit: Self::ABS_MAX_HEAT_SETPOINT,
                    min_cool_setpoint_limit: Self::ABS_MIN_COOL_SETPOINT,
                    max_cool_setpoint_limit: Self::ABS_MAX_COOL_SETPOINT,
                    system_mode: SystemModeEnum::Off,
                    running_state: RelayStateBitmap::empty(),
                    applied: 0,
                })),
            }
        }

        /// Read one field of the simulated device.
        fn get<R>(&self, f: impl FnOnce(&MockState) -> R) -> R {
            self.state.lock(|state| f(&state.borrow()))
        }

        /// Set one field of the simulated device, as the device itself would.
        fn set(&self, f: impl FnOnce(&mut MockState)) {
            self.state.lock(|state| f(&mut state.borrow_mut()));
        }
    }

    impl<const F: u32> ThermostatHooks for MockHooks<F> {
        const CLUSTER: Cluster<'static> = thermostat_cluster::FULL_CLUSTER
            .with_revision(11)
            .with_features(F)
            .with_attrs(mock_attrs)
            .with_cmds(with!(thermostat_cluster::CommandId::SetpointRaiseLower))
            .with_events(mock_events);

        const CONTROL_SEQUENCE_OF_OPERATION: ControlSequenceOfOperationEnum =
            if F & thermostat_cluster::Feature::HEATING.bits() != 0
                && F & thermostat_cluster::Feature::COOLING.bits() != 0
            {
                ControlSequenceOfOperationEnum::CoolingAndHeating
            } else if F & thermostat_cluster::Feature::COOLING.bits() != 0 {
                ControlSequenceOfOperationEnum::CoolingOnly
            } else {
                ControlSequenceOfOperationEnum::HeatingOnly
            };

        fn local_temperature(&self) -> Nullable<i16> {
            Nullable::new(self.get(|state| state.local_temperature))
        }

        fn occupied_heating_setpoint(&self) -> i16 {
            self.get(|state| state.occupied_heating_setpoint)
        }

        fn set_occupied_heating_setpoint(&self, value: i16) -> Result<(), Error> {
            self.set(|state| state.occupied_heating_setpoint = value);
            Ok(())
        }

        fn occupied_cooling_setpoint(&self) -> i16 {
            self.get(|state| state.occupied_cooling_setpoint)
        }

        fn set_occupied_cooling_setpoint(&self, value: i16) -> Result<(), Error> {
            self.set(|state| state.occupied_cooling_setpoint = value);
            Ok(())
        }

        fn min_heat_setpoint_limit(&self) -> i16 {
            self.get(|state| state.min_heat_setpoint_limit)
        }

        fn set_min_heat_setpoint_limit(&self, value: i16) -> Result<(), Error> {
            self.set(|state| state.min_heat_setpoint_limit = value);
            Ok(())
        }

        fn max_heat_setpoint_limit(&self) -> i16 {
            self.get(|state| state.max_heat_setpoint_limit)
        }

        fn set_max_heat_setpoint_limit(&self, value: i16) -> Result<(), Error> {
            self.set(|state| state.max_heat_setpoint_limit = value);
            Ok(())
        }

        fn min_cool_setpoint_limit(&self) -> i16 {
            self.get(|state| state.min_cool_setpoint_limit)
        }

        fn set_min_cool_setpoint_limit(&self, value: i16) -> Result<(), Error> {
            self.set(|state| state.min_cool_setpoint_limit = value);
            Ok(())
        }

        fn max_cool_setpoint_limit(&self) -> i16 {
            self.get(|state| state.max_cool_setpoint_limit)
        }

        fn set_max_cool_setpoint_limit(&self, value: i16) -> Result<(), Error> {
            self.set(|state| state.max_cool_setpoint_limit = value);
            Ok(())
        }

        fn system_mode(&self) -> SystemModeEnum {
            self.get(|state| state.system_mode)
        }

        fn set_system_mode(&self, value: SystemModeEnum) -> Result<(), Error> {
            self.set(|state| state.system_mode = value);
            Ok(())
        }

        fn running_state(&self) -> RelayStateBitmap {
            self.get(|state| state.running_state)
        }

        /// Stands in for the device's control algorithm: call for heat while
        /// the room is below the heating setpoint, for cool while it is above
        /// the cooling one.
        fn apply(&self, system_mode: SystemModeEnum, heating_setpoint: i16, cooling_setpoint: i16) {
            self.set(|state| {
                state.applied += 1;

                let Some(temperature) = state.local_temperature else {
                    return;
                };

                let heat = matches!(system_mode, SystemModeEnum::Heat | SystemModeEnum::Auto)
                    && temperature < heating_setpoint;
                let cool = matches!(system_mode, SystemModeEnum::Cool | SystemModeEnum::Auto)
                    && temperature > cooling_setpoint;

                let mut relays = RelayStateBitmap::empty();
                if heat {
                    relays |= RelayStateBitmap::HEAT;
                }
                if cool {
                    relays |= RelayStateBitmap::COOL;
                }

                state.running_state = relays;
            });
        }
    }

    const HEAT: u32 = thermostat_cluster::Feature::HEATING.bits();
    const COOL: u32 = thermostat_cluster::Feature::COOLING.bits();
    const HEAT_LTNE: u32 = HEAT | thermostat_cluster::Feature::LOCAL_TEMPERATURE_NOT_EXPOSED.bits();
    const AUTO: u32 = HEAT | COOL | thermostat_cluster::Feature::AUTO_MODE.bits();
    /// The provisional `TEVT` bit, on its own.
    const TEVT: u32 = thermostat_cluster::Feature::EVENTS.bits();
    const HEAT_EVT: u32 = HEAT | TEVT;
    const HEAT_LTNE_EVT: u32 = HEAT_LTNE | TEVT;
    const AUTO_EVT: u32 = AUTO | TEVT;

    /// `MinSetpointDeadBand`'s default of 20 (2.0degC), in the setpoints' own
    /// units of 0.01degC.
    const DEAD_BAND: i16 = 200;

    fn mock_handler<const F: u32>() -> ThermostatHandler<MockHooks<F>> {
        ThermostatHandler::new(Dataver::new(1), 1, MockHooks::<F>::new())
    }

    /// A seeded handler: what `run` hands the first sweep.
    fn seeded_handler<const F: u32>() -> ThermostatHandler<MockHooks<F>> {
        let handler = mock_handler::<F>();
        handler.seed_events();
        handler
    }

    /// Hooks that additionally serve the section 4.3.11.30-32 trio, which
    /// `mock_attrs` deliberately leaves out. A newtype so that the extra
    /// re-reports land only in the tests that ask for them.
    struct SourceMockHooks<const F: u32>(MockHooks<F>);

    impl<const F: u32> SourceMockHooks<F> {
        const fn new() -> Self {
            Self(MockHooks::<F>::new())
        }
    }

    fn source_handler<const F: u32>() -> ThermostatHandler<SourceMockHooks<F>> {
        ThermostatHandler::new(Dataver::new(1), 1, SourceMockHooks::<F>::new())
    }

    impl<const F: u32> ThermostatHooks for SourceMockHooks<F> {
        const CLUSTER: Cluster<'static> =
            <MockHooks<F> as ThermostatHooks>::CLUSTER.with_attrs(|attr, revision, features| {
                matches!(
                    attr.id.try_into(),
                    Ok(AttributeId::SetpointChangeSource
                        | AttributeId::SetpointChangeAmount
                        | AttributeId::SetpointChangeSourceTimestamp)
                ) || mock_attrs(attr, revision, features)
            });

        const CONTROL_SEQUENCE_OF_OPERATION: ControlSequenceOfOperationEnum =
            <MockHooks<F> as ThermostatHooks>::CONTROL_SEQUENCE_OF_OPERATION;

        /// A clock that is always 1000 seconds past the Matter epoch, so the
        /// stamp is distinguishable from the "no clock" zero.
        fn utc_now_secs(&self) -> Option<u32> {
            Some(1000)
        }

        fn local_temperature(&self) -> Nullable<i16> {
            self.0.local_temperature()
        }

        fn occupied_heating_setpoint(&self) -> i16 {
            self.0.occupied_heating_setpoint()
        }

        fn set_occupied_heating_setpoint(&self, value: i16) -> Result<(), Error> {
            self.0.set_occupied_heating_setpoint(value)
        }

        fn occupied_cooling_setpoint(&self) -> i16 {
            self.0.occupied_cooling_setpoint()
        }

        fn set_occupied_cooling_setpoint(&self, value: i16) -> Result<(), Error> {
            self.0.set_occupied_cooling_setpoint(value)
        }

        fn min_heat_setpoint_limit(&self) -> i16 {
            self.0.min_heat_setpoint_limit()
        }

        fn set_min_heat_setpoint_limit(&self, value: i16) -> Result<(), Error> {
            self.0.set_min_heat_setpoint_limit(value)
        }

        fn max_heat_setpoint_limit(&self) -> i16 {
            self.0.max_heat_setpoint_limit()
        }

        fn set_max_heat_setpoint_limit(&self, value: i16) -> Result<(), Error> {
            self.0.set_max_heat_setpoint_limit(value)
        }

        fn min_cool_setpoint_limit(&self) -> i16 {
            self.0.min_cool_setpoint_limit()
        }

        fn set_min_cool_setpoint_limit(&self, value: i16) -> Result<(), Error> {
            self.0.set_min_cool_setpoint_limit(value)
        }

        fn max_cool_setpoint_limit(&self) -> i16 {
            self.0.max_cool_setpoint_limit()
        }

        fn set_max_cool_setpoint_limit(&self, value: i16) -> Result<(), Error> {
            self.0.set_max_cool_setpoint_limit(value)
        }

        fn system_mode(&self) -> SystemModeEnum {
            self.0.system_mode()
        }

        fn set_system_mode(&self, value: SystemModeEnum) -> Result<(), Error> {
            self.0.set_system_mode(value)
        }

        fn running_state(&self) -> RelayStateBitmap {
            self.0.running_state()
        }

        fn apply(&self, system_mode: SystemModeEnum, heating: i16, cooling: i16) {
            self.0.apply(system_mode, heating, cooling)
        }
    }

    fn code<T>(result: Result<T, Error>) -> Result<T, ErrorCode> {
        result.map_err(|e| e.code())
    }

    /// Catches drift between `TestThermostatDeviceLogic::CLUSTER` and
    /// `ThermostatHandler::validate()`.
    #[test]
    fn test_logic_passes_handler_validate() {
        let logic = TestThermostatDeviceLogic::new();
        let handler = ThermostatHandler::new(Dataver::new(1), 1, &logic);

        handler.validate();
        handler.repair().unwrap();
    }

    /// The same for each feature combination the mock can be built with - the
    /// configurations every other test in this module then leans on.
    #[test]
    fn every_mock_configuration_passes_handler_validate() {
        mock_handler::<HEAT>().validate();
        mock_handler::<COOL>().validate();
        mock_handler::<HEAT_LTNE>().validate();
        mock_handler::<{ HEAT | COOL }>().validate();
        mock_handler::<AUTO>().validate();
    }

    /// Section 4.3.11.2: with `LTNE` the attribute "SHALL always report null",
    /// whatever the sensor says.
    #[test]
    fn local_temperature_is_null_with_ltne() {
        assert!(!ThermostatHandler::<MockHooks<HEAT>>::supports_feature(
            super::Feature::LOCAL_TEMPERATURE_NOT_EXPOSED.bits()
        ));
        assert!(ThermostatHandler::<MockHooks<HEAT_LTNE>>::supports_feature(
            super::Feature::LOCAL_TEMPERATURE_NOT_EXPOSED.bits()
        ));

        assert_eq!(
            mock_handler::<HEAT>().hooks.local_temperature(),
            Nullable::some(1900)
        );
    }

    /// Section 4.3.11.22: `SystemMode` is limited by
    /// `ControlSequenceOfOperation`; with `HeatingOnly` only `Off` and `Heat`
    /// remain.
    #[test]
    fn system_mode_write_rejects_unsupported_modes() {
        let handler = mock_handler::<HEAT>();

        for mode in [
            SystemModeEnum::Cool,
            SystemModeEnum::Auto,
            SystemModeEnum::Precooling,
            SystemModeEnum::EmergencyHeat,
            SystemModeEnum::FanOnly,
        ] {
            assert_eq!(
                code(handler.write_system_mode(NULL_CTX, mode)),
                Err(ErrorCode::ConstraintError),
                "SystemMode {mode:?} should not be accepted"
            );
        }

        for mode in [SystemModeEnum::Off, SystemModeEnum::Heat] {
            handler.write_system_mode(NULL_CTX, mode).unwrap();
            assert_eq!(handler.hooks.system_mode(), mode);
        }
    }

    /// The cooling and auto halves of the same rule: `Cool` needs a cooling
    /// sequence and `Auto` needs the `AUTO` feature, and neither the fan nor
    /// the dehumidifier modes are ever accepted.
    #[test]
    fn system_mode_write_follows_the_feature_set() {
        let cooling = mock_handler::<COOL>();

        assert_eq!(
            code(cooling.write_system_mode(NULL_CTX, SystemModeEnum::Heat)),
            Err(ErrorCode::ConstraintError)
        );
        assert_eq!(
            code(cooling.write_system_mode(NULL_CTX, SystemModeEnum::Auto)),
            Err(ErrorCode::ConstraintError)
        );
        cooling
            .write_system_mode(NULL_CTX, SystemModeEnum::Cool)
            .unwrap();

        // Both features, no AUTO: heat and cool, but not auto.
        let both = mock_handler::<{ HEAT | COOL }>();

        both.write_system_mode(NULL_CTX, SystemModeEnum::Heat)
            .unwrap();
        both.write_system_mode(NULL_CTX, SystemModeEnum::Cool)
            .unwrap();
        assert_eq!(
            code(both.write_system_mode(NULL_CTX, SystemModeEnum::Auto)),
            Err(ErrorCode::ConstraintError)
        );

        let auto = mock_handler::<AUTO>();

        for mode in [
            SystemModeEnum::Off,
            SystemModeEnum::Heat,
            SystemModeEnum::Cool,
            SystemModeEnum::Auto,
        ] {
            auto.write_system_mode(NULL_CTX, mode).unwrap();
        }

        for mode in [
            SystemModeEnum::Precooling,
            SystemModeEnum::EmergencyHeat,
            SystemModeEnum::FanOnly,
            SystemModeEnum::Dry,
            SystemModeEnum::Sleep,
        ] {
            assert_eq!(
                code(auto.write_system_mode(NULL_CTX, mode)),
                Err(ErrorCode::ConstraintError),
                "SystemMode {mode:?} needs equipment this handler knows nothing about"
            );
        }
    }

    /// Section 4.3.11.12: out-of-range writes are a `CONSTRAINT_ERROR`, in
    /// contrast to `SetpointRaiseLower`, which clamps.
    #[test]
    fn occupied_heating_setpoint_write_out_of_range_is_constraint_error() {
        let handler = mock_handler::<HEAT>();

        handler
            .write_min_heat_setpoint_limit(NULL_CTX, 1500)
            .unwrap();
        handler
            .write_max_heat_setpoint_limit(NULL_CTX, 2500)
            .unwrap();

        assert_eq!(
            code(handler.write_occupied_heating_setpoint(NULL_CTX, 2501)),
            Err(ErrorCode::ConstraintError)
        );
        assert_eq!(
            code(handler.write_occupied_heating_setpoint(NULL_CTX, 1499)),
            Err(ErrorCode::ConstraintError)
        );

        // The bounds themselves are in range.
        handler
            .write_occupied_heating_setpoint(NULL_CTX, 2500)
            .unwrap();
        handler
            .write_occupied_heating_setpoint(NULL_CTX, 1500)
            .unwrap();
        assert_eq!(handler.hooks.occupied_heating_setpoint(), 1500);
    }

    /// Section 4.3.11.11, the cooling mirror of the same rule.
    #[test]
    fn occupied_cooling_setpoint_write_out_of_range_is_constraint_error() {
        let handler = mock_handler::<COOL>();

        handler
            .write_min_cool_setpoint_limit(NULL_CTX, 2000)
            .unwrap();
        handler
            .write_max_cool_setpoint_limit(NULL_CTX, 2800)
            .unwrap();

        assert_eq!(
            code(handler.write_occupied_cooling_setpoint(NULL_CTX, 2801)),
            Err(ErrorCode::ConstraintError)
        );
        assert_eq!(
            code(handler.write_occupied_cooling_setpoint(NULL_CTX, 1999)),
            Err(ErrorCode::ConstraintError)
        );

        handler
            .write_occupied_cooling_setpoint(NULL_CTX, 2800)
            .unwrap();
        handler
            .write_occupied_cooling_setpoint(NULL_CTX, 2000)
            .unwrap();
        assert_eq!(handler.hooks.occupied_cooling_setpoint(), 2000);
    }

    /// Section 4.3.11.15/16: a limit write that conflicts with the setpoint
    /// drags the setpoint along by the minimum amount.
    #[test]
    fn setpoint_limit_writes_adjust_the_setpoint() {
        let handler = mock_handler::<HEAT>();

        // Floor above the setpoint pushes it up.
        handler
            .write_min_heat_setpoint_limit(NULL_CTX, 2200)
            .unwrap();
        assert_eq!(handler.hooks.occupied_heating_setpoint(), 2200);

        // Ceiling below the setpoint pulls it down.
        handler
            .write_min_heat_setpoint_limit(NULL_CTX, 700)
            .unwrap();
        handler
            .write_max_heat_setpoint_limit(NULL_CTX, 1800)
            .unwrap();
        assert_eq!(handler.hooks.occupied_heating_setpoint(), 1800);

        // And the same on the cooling side.
        let cooling = mock_handler::<COOL>();

        cooling
            .write_min_cool_setpoint_limit(NULL_CTX, 2700)
            .unwrap();
        assert_eq!(cooling.hooks.occupied_cooling_setpoint(), 2700);

        cooling
            .write_min_cool_setpoint_limit(NULL_CTX, 1600)
            .unwrap();
        cooling
            .write_max_cool_setpoint_limit(NULL_CTX, 2400)
            .unwrap();
        assert_eq!(cooling.hooks.occupied_cooling_setpoint(), 2400);
    }

    /// Section 4.3.6: user-configurable limits stay inside the device limits
    /// and do not cross each other. Those writes cannot be resolved by moving a
    /// setpoint, so they are a `CONSTRAINT_ERROR`.
    #[test]
    fn setpoint_limit_writes_outside_the_constraint_chain_are_rejected() {
        let handler = mock_handler::<HEAT>();

        assert_eq!(
            code(handler.write_min_heat_setpoint_limit(NULL_CTX, 699)),
            Err(ErrorCode::ConstraintError)
        );
        assert_eq!(
            code(handler.write_max_heat_setpoint_limit(NULL_CTX, 3001)),
            Err(ErrorCode::ConstraintError)
        );

        handler
            .write_max_heat_setpoint_limit(NULL_CTX, 2000)
            .unwrap();
        assert_eq!(
            code(handler.write_min_heat_setpoint_limit(NULL_CTX, 2001)),
            Err(ErrorCode::ConstraintError)
        );
        assert_eq!(
            code(handler.write_max_heat_setpoint_limit(NULL_CTX, 699)),
            Err(ErrorCode::ConstraintError)
        );

        let cooling = mock_handler::<COOL>();

        assert_eq!(
            code(cooling.write_min_cool_setpoint_limit(NULL_CTX, 1599)),
            Err(ErrorCode::ConstraintError)
        );
        assert_eq!(
            code(cooling.write_max_cool_setpoint_limit(NULL_CTX, 3201)),
            Err(ErrorCode::ConstraintError)
        );
    }

    /// Section 4.3.6, the deadband clauses: with `AUTO` the two halves of the
    /// limit chain are tied together, and a limit write that would close the
    /// gap is a `CONSTRAINT_ERROR` - there is no setpoint that could be moved
    /// to resolve a conflict between two *limits*.
    #[test]
    fn auto_keeps_the_deadband_between_the_limits() {
        let handler = mock_handler::<AUTO>();

        // MinHeatSetpointLimit <= MinCoolSetpointLimit - MinSetpointDeadBand,
        // i.e. 1600 - 200 = 1400 with the defaults.
        handler
            .write_min_heat_setpoint_limit(NULL_CTX, 1400)
            .unwrap();
        assert_eq!(
            code(handler.write_min_heat_setpoint_limit(NULL_CTX, 1401)),
            Err(ErrorCode::ConstraintError)
        );

        // MaxHeatSetpointLimit <= MaxCoolSetpointLimit - MinSetpointDeadBand,
        // i.e. 3200 - 200 = 3000.
        handler
            .write_max_heat_setpoint_limit(NULL_CTX, 3000)
            .unwrap();

        // Pulled from the other end: the cooling floor may not drop below the
        // heating floor plus the deadband.
        assert_eq!(
            code(handler.write_min_cool_setpoint_limit(NULL_CTX, 1599)),
            Err(ErrorCode::ConstraintError)
        );
        handler
            .write_min_cool_setpoint_limit(NULL_CTX, 1600)
            .unwrap();

        assert_eq!(
            code(handler.write_max_cool_setpoint_limit(NULL_CTX, 3199)),
            Err(ErrorCode::ConstraintError)
        );

        // Without AUTO none of that applies: the two chains are independent.
        let unlinked = mock_handler::<{ HEAT | COOL }>();

        unlinked
            .write_max_heat_setpoint_limit(NULL_CTX, 3000)
            .unwrap();
        unlinked
            .write_max_cool_setpoint_limit(NULL_CTX, 1700)
            .unwrap();
    }

    /// Section 4.3.11.12: "If this attribute is set to a value that is greater
    /// than (OccupiedCoolingSetpoint - MinSetpointDeadBand), the value of
    /// OccupiedCoolingSetpoint SHALL be adjusted". The write itself succeeds -
    /// it is the *other* setpoint that gives way.
    #[test]
    fn auto_moves_the_opposite_setpoint_to_keep_the_deadband() {
        let handler = mock_handler::<AUTO>();

        assert_eq!(handler.hooks.occupied_heating_setpoint(), 2000);
        assert_eq!(handler.hooks.occupied_cooling_setpoint(), 2600);

        // Still 200 below the cooling setpoint: nothing moves.
        handler
            .write_occupied_heating_setpoint(NULL_CTX, 2400)
            .unwrap();
        assert_eq!(handler.hooks.occupied_cooling_setpoint(), 2600);

        // Past it: the cooling setpoint is pushed up to heating + deadband.
        handler
            .write_occupied_heating_setpoint(NULL_CTX, 2500)
            .unwrap();
        assert_eq!(handler.hooks.occupied_heating_setpoint(), 2500);
        assert_eq!(handler.hooks.occupied_cooling_setpoint(), 2500 + DEAD_BAND);

        // Section 4.3.11.11, the mirror image: the heating setpoint gives way.
        handler
            .write_occupied_cooling_setpoint(NULL_CTX, 2000)
            .unwrap();
        assert_eq!(handler.hooks.occupied_cooling_setpoint(), 2000);
        assert_eq!(handler.hooks.occupied_heating_setpoint(), 2000 - DEAD_BAND);
    }

    /// A limit write that drags a setpoint has to keep the deadband too - the
    /// drag is a setpoint change like any other.
    #[test]
    fn auto_keeps_the_deadband_when_a_limit_drags_a_setpoint() {
        let handler = mock_handler::<AUTO>();

        // Heating floor up to 2600 drags the heating setpoint (2000) with it,
        // which in turn pushes the cooling setpoint (2600) up to 2800.
        handler
            .write_min_cool_setpoint_limit(NULL_CTX, 2800)
            .unwrap();
        handler
            .write_min_heat_setpoint_limit(NULL_CTX, 2600)
            .unwrap();

        assert_eq!(handler.hooks.occupied_heating_setpoint(), 2600);
        assert_eq!(handler.hooks.occupied_cooling_setpoint(), 2800);
    }

    /// Section 4.3.12.1.1.1/2: a server without the feature "SHALL respond
    /// with INVALID_COMMAND" to the corresponding mode.
    #[test]
    fn setpoint_raise_lower_rejects_a_mode_it_has_no_setpoint_for() {
        let heating = mock_handler::<HEAT>();

        assert_eq!(
            code(heating.raise_lower_setpoint(NULL_CTX, SetpointRaiseLowerModeEnum::Cool, 10)),
            Err(ErrorCode::InvalidCommand)
        );
        assert_eq!(heating.hooks.occupied_heating_setpoint(), 2000);

        let cooling = mock_handler::<COOL>();

        assert_eq!(
            code(cooling.raise_lower_setpoint(NULL_CTX, SetpointRaiseLowerModeEnum::Heat, 10)),
            Err(ErrorCode::InvalidCommand)
        );
        assert_eq!(cooling.hooks.occupied_cooling_setpoint(), 2600);
    }

    /// Section 4.3.12.1.2: `Amount` is in steps of 0.1degC while the setpoint
    /// attribute is in 0.01degC. Section 4.3.12.1.1.3: `Both` is accepted
    /// regardless of feature support and adjusts only what the server has.
    #[test]
    fn setpoint_raise_lower_applies_tenths_of_a_degree() {
        for mode in [
            SetpointRaiseLowerModeEnum::Heat,
            SetpointRaiseLowerModeEnum::Both,
        ] {
            let handler = mock_handler::<HEAT>();

            handler.raise_lower_setpoint(NULL_CTX, mode, 10).unwrap();
            assert_eq!(handler.hooks.occupied_heating_setpoint(), 2100);

            handler.raise_lower_setpoint(NULL_CTX, mode, -25).unwrap();
            assert_eq!(handler.hooks.occupied_heating_setpoint(), 1850);
        }
    }

    /// Section 4.3.12.1.1.3: `Both` on a server with both setpoints moves both
    /// and, with `AUTO`, keeps the deadband as it goes.
    #[test]
    fn setpoint_raise_lower_both_moves_both_setpoints() {
        let handler = mock_handler::<AUTO>();

        handler
            .raise_lower_setpoint(NULL_CTX, SetpointRaiseLowerModeEnum::Both, 10)
            .unwrap();

        assert_eq!(handler.hooks.occupied_heating_setpoint(), 2100);
        assert_eq!(handler.hooks.occupied_cooling_setpoint(), 2700);

        handler
            .raise_lower_setpoint(NULL_CTX, SetpointRaiseLowerModeEnum::Both, -30)
            .unwrap();

        assert_eq!(handler.hooks.occupied_heating_setpoint(), 1800);
        assert_eq!(handler.hooks.occupied_cooling_setpoint(), 2400);
    }

    /// Section 4.3.12.1.1.1: "If the server supports the AUTO feature and the
    /// resulting setpoint would be invalid solely due to MinSetpointDeadBand
    /// then the Cooling setpoint SHALL be increased sufficiently to maintain
    /// the deadband."
    #[test]
    fn setpoint_raise_lower_heat_pushes_the_cooling_setpoint() {
        let handler = mock_handler::<AUTO>();

        handler
            .raise_lower_setpoint(NULL_CTX, SetpointRaiseLowerModeEnum::Heat, 60)
            .unwrap();

        assert_eq!(handler.hooks.occupied_heating_setpoint(), 2600);
        assert_eq!(handler.hooks.occupied_cooling_setpoint(), 2600 + DEAD_BAND);

        // And the other way: lowering the cooling setpoint drags the heating
        // one down with it.
        handler
            .raise_lower_setpoint(NULL_CTX, SetpointRaiseLowerModeEnum::Cool, -100)
            .unwrap();

        assert_eq!(handler.hooks.occupied_cooling_setpoint(), 1800);
        assert_eq!(handler.hooks.occupied_heating_setpoint(), 1800 - DEAD_BAND);
    }

    /// Section 4.3.12.1.3: "If the resulting value is outside the limits [...]
    /// the value is clamped to those limits. This is not considered an error
    /// condition."
    #[test]
    fn setpoint_raise_lower_clamps_without_erroring() {
        let handler = mock_handler::<HEAT>();

        handler
            .write_min_heat_setpoint_limit(NULL_CTX, 1500)
            .unwrap();
        handler
            .write_max_heat_setpoint_limit(NULL_CTX, 2500)
            .unwrap();

        handler
            .raise_lower_setpoint(NULL_CTX, SetpointRaiseLowerModeEnum::Heat, 127)
            .unwrap();
        assert_eq!(handler.hooks.occupied_heating_setpoint(), 2500);

        handler
            .raise_lower_setpoint(NULL_CTX, SetpointRaiseLowerModeEnum::Heat, -128)
            .unwrap();
        assert_eq!(handler.hooks.occupied_heating_setpoint(), 1500);
    }

    /// Section 4.3.11.21: the `ControlSequenceOfOperation` a thermostat
    /// reports is fixed, and writes to it are silently ignored - which is why
    /// it is a hooks const with no setter at all. Section 4.3.11.19 says the
    /// same about `MinSetpointDeadBand`.
    #[test]
    fn the_fixed_attributes_are_hooks_consts() {
        assert_eq!(
            <MockHooks<HEAT> as ThermostatHooks>::CONTROL_SEQUENCE_OF_OPERATION,
            ControlSequenceOfOperationEnum::HeatingOnly
        );
        assert_eq!(
            <MockHooks<AUTO> as ThermostatHooks>::CONTROL_SEQUENCE_OF_OPERATION,
            ControlSequenceOfOperationEnum::CoolingAndHeating
        );
        assert_eq!(
            <MockHooks<AUTO> as ThermostatHooks>::MIN_SETPOINT_DEAD_BAND as i16 * 10,
            DEAD_BAND
        );
    }

    /// Section 4.3.6: startup pulls persisted state back into the chain.
    #[test]
    fn repair_restores_the_constraint_chain() {
        let handler = mock_handler::<HEAT>();

        // Values a narrowed firmware range or a bad restore could leave behind.
        handler
            .hooks
            .set(|state| state.min_heat_setpoint_limit = 100);
        handler
            .hooks
            .set(|state| state.max_heat_setpoint_limit = 9000);
        handler
            .hooks
            .set(|state| state.occupied_heating_setpoint = 8000);
        handler
            .hooks
            .set(|state| state.system_mode = SystemModeEnum::Cool);

        handler.repair().unwrap();

        assert_eq!(
            handler.hooks.get(|state| state.min_heat_setpoint_limit),
            700
        );
        assert_eq!(
            handler.hooks.get(|state| state.max_heat_setpoint_limit),
            3000
        );
        assert_eq!(
            handler.hooks.get(|state| state.occupied_heating_setpoint),
            3000
        );
        assert_eq!(
            handler.hooks.get(|state| state.system_mode),
            SystemModeEnum::Off
        );
    }

    /// And with `AUTO`, the deadband half of it: both the limits and the
    /// setpoints have to come back inside the gap.
    #[test]
    fn repair_restores_the_deadband() {
        let handler = mock_handler::<AUTO>();

        // A restore in which the heating half has crept up over the cooling
        // half, deadband and all.
        handler
            .hooks
            .set(|state| state.min_heat_setpoint_limit = 1800);
        handler
            .hooks
            .set(|state| state.max_heat_setpoint_limit = 3000);
        handler
            .hooks
            .set(|state| state.min_cool_setpoint_limit = 1600);
        handler
            .hooks
            .set(|state| state.max_cool_setpoint_limit = 3000);
        handler
            .hooks
            .set(|state| state.occupied_heating_setpoint = 2600);
        handler
            .hooks
            .set(|state| state.occupied_cooling_setpoint = 2600);

        handler.repair().unwrap();

        let hooks = &handler.hooks;

        assert!(
            hooks.get(|state| state.min_heat_setpoint_limit)
                <= hooks.get(|state| state.min_cool_setpoint_limit) - DEAD_BAND
        );
        assert!(
            hooks.get(|state| state.max_heat_setpoint_limit)
                <= hooks.get(|state| state.max_cool_setpoint_limit) - DEAD_BAND
        );
        assert!(
            hooks.get(|state| state.occupied_heating_setpoint)
                <= hooks.get(|state| state.occupied_cooling_setpoint) - DEAD_BAND
        );
        assert!(
            hooks.get(|state| state.occupied_heating_setpoint)
                >= hooks.get(|state| state.min_heat_setpoint_limit)
        );
        assert!(
            hooks.get(|state| state.occupied_cooling_setpoint)
                <= hooks.get(|state| state.max_cool_setpoint_limit)
        );
    }

    /// Pin the wire-visible shape of the endpoint: the `AttributeList`,
    /// `AcceptedCommandList` and `EventList` a controller reads back, and the
    /// `FeatureMap` and `ClusterRevision` that go with them.
    #[test]
    fn serves_the_heating_only_element_set() {
        let cluster = <TestThermostatDeviceLogic as ThermostatHooks>::CLUSTER;

        assert_eq!(cluster.id, 0x0201);
        assert_eq!(cluster.revision, 11);
        assert_eq!(cluster.feature_map, HEAT_EVT);

        let attrs: heapless::Vec<_, 12> = cluster
            .attributes()
            .map(|attr| attr.id)
            .filter(|id| *id < 0xF000) // skip the global attributes
            .collect();

        assert_eq!(
            attrs,
            [
                AttributeId::LocalTemperature as AttrId,
                AttributeId::AbsMinHeatSetpointLimit as AttrId,
                AttributeId::AbsMaxHeatSetpointLimit as AttrId,
                AttributeId::OccupiedHeatingSetpoint as AttrId,
                AttributeId::MinHeatSetpointLimit as AttrId,
                AttributeId::MaxHeatSetpointLimit as AttrId,
                AttributeId::ControlSequenceOfOperation as AttrId,
                AttributeId::SystemMode as AttrId,
                AttributeId::ThermostatRunningState as AttrId,
                AttributeId::SetpointChangeSource as AttrId,
                AttributeId::SetpointChangeAmount as AttrId,
                AttributeId::SetpointChangeSourceTimestamp as AttrId,
            ]
        );

        let cmds: heapless::Vec<_, 1> = cluster.commands().map(|cmd| cmd.id).collect();

        assert_eq!(cmds, [CommandId::SetpointRaiseLower as CmdId]);

        let events: heapless::Vec<_, 4> = cluster.events().map(|event| event.id).collect();

        assert_eq!(
            events,
            [
                EventId::SystemModeChange as RawEventId,
                EventId::LocalTemperatureChange as RawEventId,
                EventId::SetpointChange as RawEventId,
                EventId::RunningStateChange as RawEventId,
            ]
        );
    }

    /// And the full heat/cool/auto shape, which is what the extra attributes
    /// of section 4.3.11 hang off.
    #[test]
    fn serves_the_auto_element_set() {
        let cluster = <MockHooks<AUTO> as ThermostatHooks>::CLUSTER;

        let attrs: heapless::Vec<_, 16> = cluster
            .attributes()
            .map(|attr| attr.id)
            .filter(|id| *id < 0xF000)
            .collect();

        assert_eq!(
            attrs,
            [
                AttributeId::LocalTemperature as AttrId,
                AttributeId::AbsMinHeatSetpointLimit as AttrId,
                AttributeId::AbsMaxHeatSetpointLimit as AttrId,
                AttributeId::AbsMinCoolSetpointLimit as AttrId,
                AttributeId::AbsMaxCoolSetpointLimit as AttrId,
                AttributeId::OccupiedCoolingSetpoint as AttrId,
                AttributeId::OccupiedHeatingSetpoint as AttrId,
                AttributeId::MinHeatSetpointLimit as AttrId,
                AttributeId::MaxHeatSetpointLimit as AttrId,
                AttributeId::MinCoolSetpointLimit as AttrId,
                AttributeId::MaxCoolSetpointLimit as AttrId,
                AttributeId::MinSetpointDeadBand as AttrId,
                AttributeId::ControlSequenceOfOperation as AttrId,
                AttributeId::SystemMode as AttrId,
                AttributeId::ThermostatRunningMode as AttrId,
                AttributeId::ThermostatRunningState as AttrId,
            ]
        );
    }

    /// A misconfigured `CLUSTER` is a programming error, caught once at startup.
    #[test]
    #[should_panic(expected = "at least one of the HEAT and COOL features")]
    fn validate_rejects_a_cluster_without_heat_or_cool() {
        mock_handler::<0>().validate();
    }

    #[test]
    #[should_panic(expected = "unsupported features in the feature map")]
    fn validate_rejects_unsupported_features() {
        const PRESETS: u32 = HEAT | thermostat_cluster::Feature::PRESETS.bits();

        mock_handler::<PRESETS>().validate();
    }

    #[test]
    #[should_panic(expected = "the AUTO feature requires both HEAT and COOL")]
    fn validate_rejects_auto_without_both_temperatures() {
        const HEAT_AUTO: u32 = HEAT | thermostat_cluster::Feature::AUTO_MODE.bits();

        mock_handler::<HEAT_AUTO>().validate();
    }

    /// `ControlSequenceOfOperation` decides which system modes are possible at
    /// all (section 4.3.10.16), so a feature it rules out is a feature the
    /// device can never act on.
    #[test]
    #[should_panic(expected = "CONTROL_SEQUENCE_OF_OPERATION does not match")]
    fn validate_rejects_a_sequence_that_contradicts_the_features() {
        struct Mismatched;

        impl ThermostatHooks for Mismatched {
            const CLUSTER: Cluster<'static> = <MockHooks<HEAT> as ThermostatHooks>::CLUSTER;
            const CONTROL_SEQUENCE_OF_OPERATION: ControlSequenceOfOperationEnum =
                ControlSequenceOfOperationEnum::CoolingOnly;

            fn local_temperature(&self) -> Nullable<i16> {
                Nullable::none()
            }

            fn system_mode(&self) -> SystemModeEnum {
                SystemModeEnum::Off
            }

            fn set_system_mode(&self, _value: SystemModeEnum) -> Result<(), Error> {
                Ok(())
            }

            fn apply(&self, _mode: SystemModeEnum, _heating: i16, _cooling: i16) {}
        }

        ThermostatHandler::new(Dataver::new(1), 1, Mismatched).validate();
    }

    /// The reason `pending` is a bitmask and not a `Signal<Option<_>>`: two
    /// out-of-band changes landing between two turns of `run` must both be
    /// re-reported, not just the later one.
    #[test]
    fn out_of_band_messages_accumulate_without_loss() {
        let handler = mock_handler::<HEAT>();
        let notifier = RecordingNotifier::default();

        // Both land before `run` gets a chance to drain the slot.
        handler.out_of_band_message(OutOfBandMessage::LocalTemperature);
        handler.out_of_band_message(OutOfBandMessage::OccupiedHeatingSetpoint);

        // Ready immediately - the mask is non-empty, so this does not block.
        let pending = block_on(handler.wait_pending());
        handler.notify_pending(&notifier, pending);

        assert_eq!(
            notifier.attrs(),
            [
                AttributeId::LocalTemperature as AttrId,
                AttributeId::OccupiedHeatingSetpoint as AttrId,
            ]
        );

        // And the mask is empty again afterwards, so nothing is re-reported
        // twice.
        assert_eq!(handler.pending.modify(|pending| (false, *pending)), 0);
    }

    /// Every `OutOfBandMessage` maps onto the attributes it names, and
    /// `Update` onto all of them. The drain is in ascending attribute order,
    /// whatever order the messages arrived in, and skips whatever this
    /// configuration does not serve.
    #[test]
    fn out_of_band_messages_report_the_attributes_they_name() {
        let handler = mock_handler::<AUTO>();
        let notifier = RecordingNotifier::default();

        let drain = |handler: &ThermostatHandler<MockHooks<AUTO>>| {
            handler.notify_pending(&notifier, block_on(handler.wait_pending()));
            notifier.attrs()
        };

        for (message, expected) in [
            (
                OutOfBandMessage::LocalTemperature,
                &[AttributeId::LocalTemperature as AttrId][..],
            ),
            (
                OutOfBandMessage::OccupiedHeatingSetpoint,
                &[AttributeId::OccupiedHeatingSetpoint as AttrId][..],
            ),
            (
                OutOfBandMessage::OccupiedCoolingSetpoint,
                &[AttributeId::OccupiedCoolingSetpoint as AttrId][..],
            ),
            (
                OutOfBandMessage::SystemMode,
                &[AttributeId::SystemMode as AttrId][..],
            ),
            (
                OutOfBandMessage::SetpointLimits,
                &[
                    AttributeId::MinHeatSetpointLimit as AttrId,
                    AttributeId::MaxHeatSetpointLimit as AttrId,
                    AttributeId::MinCoolSetpointLimit as AttrId,
                    AttributeId::MaxCoolSetpointLimit as AttrId,
                ][..],
            ),
            (
                OutOfBandMessage::RunningState,
                &[
                    AttributeId::ThermostatRunningMode as AttrId,
                    AttributeId::ThermostatRunningState as AttrId,
                ][..],
            ),
            (
                OutOfBandMessage::Update,
                &[
                    AttributeId::LocalTemperature as AttrId,
                    AttributeId::OccupiedCoolingSetpoint as AttrId,
                    AttributeId::OccupiedHeatingSetpoint as AttrId,
                    AttributeId::MinHeatSetpointLimit as AttrId,
                    AttributeId::MaxHeatSetpointLimit as AttrId,
                    AttributeId::MinCoolSetpointLimit as AttrId,
                    AttributeId::MaxCoolSetpointLimit as AttrId,
                    AttributeId::SystemMode as AttrId,
                    AttributeId::ThermostatRunningMode as AttrId,
                    AttributeId::ThermostatRunningState as AttrId,
                ][..],
            ),
        ] {
            handler.out_of_band_message(message);
            assert_eq!(drain(&handler), expected, "{message:?}");
        }
    }

    /// A heating-only device serves neither the cooling attributes nor
    /// `ThermostatRunningMode`, so no re-report is ever emitted for them - not
    /// even by `Update`.
    #[test]
    fn unserved_attributes_are_never_reported() {
        let handler = mock_handler::<HEAT>();
        let notifier = RecordingNotifier::default();

        handler.out_of_band_message(OutOfBandMessage::Update);
        handler.notify_pending(&notifier, block_on(handler.wait_pending()));

        assert_eq!(
            notifier.attrs(),
            [
                AttributeId::LocalTemperature as AttrId,
                AttributeId::OccupiedHeatingSetpoint as AttrId,
                AttributeId::MinHeatSetpointLimit as AttrId,
                AttributeId::MaxHeatSetpointLimit as AttrId,
                AttributeId::SystemMode as AttrId,
                AttributeId::ThermostatRunningState as AttrId,
            ]
        );
    }

    /// A limit write that drags the setpoint along has to re-report both
    /// attributes - a subscriber to `OccupiedHeatingSetpoint` alone must still
    /// see the value move.
    #[test]
    fn a_dragged_setpoint_is_reported_too() {
        let handler = mock_handler::<HEAT>();
        let notifier = RecordingNotifier::default();

        handler
            .write_min_heat_setpoint_limit(&notifier, 2200)
            .unwrap();
        assert_eq!(
            notifier.attrs(),
            [
                AttributeId::MinHeatSetpointLimit as AttrId,
                AttributeId::OccupiedHeatingSetpoint as AttrId,
            ]
        );

        // A limit write that leaves the setpoint alone reports only itself.
        handler
            .write_max_heat_setpoint_limit(&notifier, 2900)
            .unwrap();
        assert_eq!(
            notifier.attrs(),
            [AttributeId::MaxHeatSetpointLimit as AttrId]
        );

        // And a rejected write reports nothing at all.
        assert!(handler
            .write_occupied_heating_setpoint(&notifier, 3001)
            .is_err());
        assert!(notifier.attrs().is_empty());
    }

    /// The same for a setpoint moved to keep the deadband: it is a change like
    /// any other and gets its own report.
    #[test]
    fn a_setpoint_moved_by_the_deadband_is_reported_too() {
        let handler = mock_handler::<AUTO>();
        let notifier = RecordingNotifier::default();

        handler
            .write_occupied_heating_setpoint(&notifier, 2500)
            .unwrap();

        assert_eq!(
            notifier.attrs(),
            [
                AttributeId::OccupiedHeatingSetpoint as AttrId,
                AttributeId::OccupiedCoolingSetpoint as AttrId,
            ]
        );
    }

    /// Section 4.3.11.29: "the current relay state of the heat, cool, and fan
    /// relays. Unimplemented outputs SHALL be treated as if they were Off." A
    /// heating-only server has no cooling relay, so a `Cool` bit from a
    /// confused device never reaches the wire.
    #[test]
    fn running_state_is_masked_to_the_relays_the_features_allow() {
        let handler = mock_handler::<HEAT>();

        handler
            .hooks
            .set(|state| state.running_state = RelayStateBitmap::all());

        assert_eq!(
            handler.running_state(),
            RelayStateBitmap::HEAT
                | RelayStateBitmap::HEAT_STAGE_2
                | RelayStateBitmap::FAN
                | RelayStateBitmap::FAN_STAGE_2
                | RelayStateBitmap::FAN_STAGE_3
        );

        handler
            .hooks
            .set(|state| state.running_state = RelayStateBitmap::COOL);
        assert_eq!(handler.running_state(), RelayStateBitmap::empty());

        // A cooling-only server is the mirror image.
        let cooling = mock_handler::<COOL>();

        cooling
            .hooks
            .set(|state| state.running_state = RelayStateBitmap::all());
        assert_eq!(
            cooling.running_state(),
            RelayStateBitmap::COOL
                | RelayStateBitmap::COOL_STAGE_2
                | RelayStateBitmap::FAN
                | RelayStateBitmap::FAN_STAGE_2
                | RelayStateBitmap::FAN_STAGE_3
        );
    }

    /// Section 4.3.11.23: `ThermostatRunningMode` answers "which way is this
    /// `Auto` thermostat going right now", which is exactly which relay is
    /// closed.
    #[test]
    fn running_mode_narrows_the_relay_state() {
        let handler = mock_handler::<AUTO>();

        for (state, mode) in [
            (RelayStateBitmap::empty(), ThermostatRunningModeEnum::Off),
            (RelayStateBitmap::FAN, ThermostatRunningModeEnum::Off),
            (RelayStateBitmap::HEAT, ThermostatRunningModeEnum::Heat),
            (
                RelayStateBitmap::HEAT_STAGE_2,
                ThermostatRunningModeEnum::Heat,
            ),
            (RelayStateBitmap::COOL, ThermostatRunningModeEnum::Cool),
        ] {
            handler.hooks.set(|hooks| hooks.running_state = state);
            assert_eq!(handler.running_mode(), mode, "{state:?}");
        }
    }

    /// Every mutation goes through `apply`, so that is where a relay moved by
    /// the handler's own doing gets re-reported - the hooks' `run` only has to
    /// report the ones the device moves on its own.
    #[test]
    fn a_relay_moved_by_apply_is_reported() {
        let handler = mock_handler::<HEAT>();
        let notifier = RecordingNotifier::default();

        // Room at 19.00C, setpoint at 20.00C: switching to `Heat` calls for
        // heat, and the relay moves along with the mode.
        handler
            .write_system_mode(&notifier, SystemModeEnum::Heat)
            .unwrap();
        assert_eq!(handler.running_state(), RelayStateBitmap::HEAT);
        assert_eq!(
            notifier.attrs(),
            [
                AttributeId::ThermostatRunningState as AttrId,
                AttributeId::SystemMode as AttrId,
            ]
        );

        // Dropping the setpoint below the room temperature drops the relay.
        handler
            .write_occupied_heating_setpoint(&notifier, 1800)
            .unwrap();
        assert_eq!(handler.running_state(), RelayStateBitmap::empty());
        assert_eq!(
            notifier.attrs(),
            [
                AttributeId::OccupiedHeatingSetpoint as AttrId,
                AttributeId::ThermostatRunningState as AttrId,
            ]
        );

        // A write that leaves the relay where it is reports only itself.
        handler
            .write_occupied_heating_setpoint(&notifier, 1700)
            .unwrap();
        assert_eq!(
            notifier.attrs(),
            [AttributeId::OccupiedHeatingSetpoint as AttrId]
        );
    }

    /// Section 4.3.11.12 and the ACL metadata that comes with it:
    /// `OccupiedHeatingSetpoint` is the one writable attribute on this cluster
    /// that an `operate`-privileged fabric may change - a thermostat is worth
    /// nothing if adjusting the temperature needs an administrator. The
    /// setpoint *limits* are commissioning-time configuration and stay at
    /// `manage`.
    #[test]
    fn only_the_setpoints_are_writable_with_operate_privilege() {
        let cluster = <MockHooks<AUTO> as ThermostatHooks>::CLUSTER;

        let writable_with = |attr: AttributeId, privilege: Privilege| {
            unwrap!(cluster.attribute(attr as _))
                .access
                .is_ok(Access::WRITE, privilege)
        };

        for attr in [
            AttributeId::OccupiedHeatingSetpoint,
            AttributeId::OccupiedCoolingSetpoint,
        ] {
            assert!(writable_with(attr, Privilege::OPERATE), "{attr:?}");
        }

        for attr in [
            AttributeId::MinHeatSetpointLimit,
            AttributeId::MaxHeatSetpointLimit,
            AttributeId::MinCoolSetpointLimit,
            AttributeId::MaxCoolSetpointLimit,
            AttributeId::MinSetpointDeadBand,
            AttributeId::ControlSequenceOfOperation,
            AttributeId::SystemMode,
        ] {
            assert!(
                !writable_with(attr, Privilege::OPERATE),
                "{attr:?} should need more than `operate` to write"
            );
            assert!(
                writable_with(attr, Privilege::MANAGE),
                "{attr:?} should be writable with `manage`"
            );
        }

        // The absolute limits are the manufacturer's, and read-only for
        // everyone.
        for attr in [
            AttributeId::AbsMinHeatSetpointLimit,
            AttributeId::AbsMaxHeatSetpointLimit,
            AttributeId::AbsMinCoolSetpointLimit,
            AttributeId::AbsMaxCoolSetpointLimit,
            AttributeId::LocalTemperature,
            AttributeId::ThermostatRunningMode,
            AttributeId::ThermostatRunningState,
        ] {
            assert!(
                !writable_with(attr, Privilege::ADMIN),
                "{attr:?} should not be writable at all"
            );
        }
    }

    /// A hooks stub whose only interesting part is the cluster metadata.
    ///
    /// `validate` runs before any accessor is reachable, so the rest can be
    /// the thinnest thing that satisfies the trait.
    macro_rules! stub_hooks {
        ($name:ident, $cluster:expr) => {
            struct $name;

            impl ThermostatHooks for $name {
                const CLUSTER: Cluster<'static> = $cluster;

                fn local_temperature(&self) -> Nullable<i16> {
                    Nullable::none()
                }
                fn occupied_heating_setpoint(&self) -> i16 {
                    2000
                }
                fn set_occupied_heating_setpoint(&self, _value: i16) -> Result<(), Error> {
                    Ok(())
                }
                fn system_mode(&self) -> SystemModeEnum {
                    SystemModeEnum::Off
                }
                fn set_system_mode(&self, _value: SystemModeEnum) -> Result<(), Error> {
                    Ok(())
                }
                fn apply(&self, _mode: SystemModeEnum, _heating: i16, _cooling: i16) {}
            }
        };
    }

    // Events (section 4.3.13)

    /// The served set follows the conformance: nothing without `TEVT`, and
    /// with it everything whose secondary gate is open.
    #[test]
    fn serves_the_expected_event_list() {
        let ids = |cluster: Cluster<'static>| {
            cluster
                .events()
                .map(|event| event.id)
                .collect::<heapless::Vec<RawEventId, 8>>()
        };

        assert!(ids(<MockHooks<HEAT> as ThermostatHooks>::CLUSTER).is_empty());

        assert_eq!(
            ids(<MockHooks<HEAT_EVT> as ThermostatHooks>::CLUSTER),
            [
                EventId::SystemModeChange as RawEventId,
                EventId::LocalTemperatureChange as RawEventId,
                EventId::SetpointChange as RawEventId,
                EventId::RunningStateChange as RawEventId,
            ]
        );

        // `LocalTemperatureChange` is `TEVT & !LTNE`.
        assert_eq!(
            ids(<MockHooks<HEAT_LTNE_EVT> as ThermostatHooks>::CLUSTER),
            [
                EventId::SystemModeChange as RawEventId,
                EventId::SetpointChange as RawEventId,
                EventId::RunningStateChange as RawEventId,
            ]
        );

        // `RunningModeChange` is `TEVT & AUTO`.
        assert_eq!(
            ids(<MockHooks<AUTO_EVT> as ThermostatHooks>::CLUSTER),
            [
                EventId::SystemModeChange as RawEventId,
                EventId::LocalTemperatureChange as RawEventId,
                EventId::SetpointChange as RawEventId,
                EventId::RunningStateChange as RawEventId,
                EventId::RunningModeChange as RawEventId,
            ]
        );
    }

    #[test]
    #[should_panic(expected = "is served without the TEVT feature it is gated on")]
    fn validate_rejects_an_event_without_tevt() {
        stub_hooks!(
            NoTevt,
            <MockHooks<HEAT> as ThermostatHooks>::CLUSTER
                .with_events(with!(thermostat_cluster::EventId::SetpointChange))
        );

        ThermostatHandler::new(Dataver::new(1), 1, NoTevt).validate();
    }

    #[test]
    #[should_panic(expected = "the whole applicable event set is mandatory")]
    fn validate_rejects_tevt_with_an_incomplete_event_set() {
        stub_hooks!(
            PartialSet,
            <MockHooks<HEAT_EVT> as ThermostatHooks>::CLUSTER
                .with_events(with!(thermostat_cluster::EventId::SetpointChange))
        );

        ThermostatHandler::new(Dataver::new(1), 1, PartialSet).validate();
    }

    #[test]
    #[should_panic(expected = "requires the OCC feature")]
    fn validate_rejects_the_events_whose_features_are_unimplemented() {
        stub_hooks!(
            Occupancy,
            <MockHooks<HEAT_EVT> as ThermostatHooks>::CLUSTER
                .with_events(with!(thermostat_cluster::EventId::OccupancyChange))
        );

        ThermostatHandler::new(Dataver::new(1), 1, Occupancy).validate();
    }

    /// Every mock configuration that enables `TEVT` must also pass
    /// `validate`, the same way the event-free ones do.
    #[test]
    fn every_event_configuration_passes_handler_validate() {
        mock_handler::<HEAT_EVT>().validate();
        mock_handler::<HEAT_LTNE_EVT>().validate();
        mock_handler::<AUTO_EVT>().validate();
    }

    /// The first sweep has nothing to diff against, so it seeds and reports
    /// nothing rather than announcing the whole world.
    #[test]
    fn an_unseeded_sweep_seeds_and_emits_nothing() {
        let handler = mock_handler::<HEAT_EVT>();

        assert!(handler.take_events(Instant::from_secs(0)).is_empty());
        // ... and it is seeded now, so a real change is picked up.
        handler
            .hooks
            .set(|state| state.occupied_heating_setpoint = 2100);
        assert_eq!(handler.take_events(Instant::from_secs(0)).len(), 1);
    }

    #[test]
    fn a_quiet_handler_emits_nothing() {
        let handler = seeded_handler::<HEAT_EVT>();

        assert!(handler.take_events(Instant::from_secs(0)).is_empty());
    }

    /// Section 4.3.13.4: the event fires on any setpoint change, and section
    /// 4.3.13.4.1 fixes `SystemMode` to *which* setpoint moved.
    #[test]
    fn an_out_of_band_setpoint_change_yields_a_setpoint_change() {
        let handler = seeded_handler::<HEAT_EVT>();

        // The device moves its own setpoint - a turn of the front-panel knob.
        handler
            .hooks
            .set(|state| state.occupied_heating_setpoint = 2150);

        assert_eq!(
            handler.take_events(Instant::from_secs(0)).as_slice(),
            [ThermostatEvent::Setpoint {
                system_mode: SystemModeEnum::Heat,
                previous: Some(2000),
                current: 2150,
            }]
        );
    }

    /// Section 4.3.13.4.1 again, from the other side: a heating-only
    /// thermostat sitting in `Off` still reports `Heat`, because the field
    /// names the setpoint, not the mode.
    #[test]
    fn the_setpoint_change_system_mode_names_the_setpoint_not_the_mode() {
        let handler = seeded_handler::<AUTO_EVT>();

        assert_eq!(
            handler.hooks.get(|state| state.system_mode),
            SystemModeEnum::Off
        );

        handler
            .hooks
            .set(|state| state.occupied_cooling_setpoint = 2700);
        handler
            .hooks
            .set(|state| state.occupied_heating_setpoint = 2100);

        let events = handler.take_events(Instant::from_secs(0));

        // Ascending attribute ID: cooling (0x11) before heating (0x12).
        assert_eq!(
            events.as_slice(),
            [
                ThermostatEvent::Setpoint {
                    system_mode: SystemModeEnum::Cool,
                    previous: Some(2600),
                    current: 2700,
                },
                ThermostatEvent::Setpoint {
                    system_mode: SystemModeEnum::Heat,
                    previous: Some(2000),
                    current: 2100,
                },
            ]
        );
    }

    #[test]
    fn a_system_mode_change_is_reported() {
        let handler = seeded_handler::<HEAT_EVT>();

        handler
            .hooks
            .set(|state| state.system_mode = SystemModeEnum::Heat);

        assert_eq!(
            handler.take_events(Instant::from_secs(0)).as_slice(),
            [ThermostatEvent::SystemMode {
                previous: Some(SystemModeEnum::Off),
                current: SystemModeEnum::Heat,
            }]
        );
    }

    #[test]
    fn a_relay_move_reports_running_state_and_running_mode() {
        let handler = seeded_handler::<AUTO_EVT>();

        handler
            .hooks
            .set(|state| state.running_state = RelayStateBitmap::HEAT);

        assert_eq!(
            handler.take_events(Instant::from_secs(0)).as_slice(),
            [
                ThermostatEvent::RunningState {
                    previous: Some(RelayStateBitmap::empty()),
                    current: RelayStateBitmap::HEAT,
                },
                ThermostatEvent::RunningMode {
                    previous: Some(ThermostatRunningModeEnum::Off),
                    current: ThermostatRunningModeEnum::Heat,
                },
            ]
        );
    }

    /// An event outside the served set is never produced, however much the
    /// state it mirrors moves.
    #[test]
    fn unserved_events_are_never_produced() {
        let handler = seeded_handler::<HEAT>();

        handler
            .hooks
            .set(|state| state.occupied_heating_setpoint = 2200);
        handler
            .hooks
            .set(|state| state.system_mode = SystemModeEnum::Heat);
        handler
            .hooks
            .set(|state| state.local_temperature = Some(3000));

        assert!(handler.take_events(Instant::from_secs(0)).is_empty());
    }

    /// Two changes between sweeps report the value from before the *first* of
    /// them - the shadow only advances when an event is produced.
    #[test]
    fn coalesced_changes_report_the_pre_burst_previous_value() {
        let handler = seeded_handler::<HEAT_EVT>();

        handler
            .hooks
            .set(|state| state.occupied_heating_setpoint = 2100);
        handler
            .hooks
            .set(|state| state.occupied_heating_setpoint = 2200);

        assert_eq!(
            handler.take_events(Instant::from_secs(0)).as_slice(),
            [ThermostatEvent::Setpoint {
                system_mode: SystemModeEnum::Heat,
                previous: Some(2000),
                current: 2200,
            }]
        );
    }

    /// Section 4.3.13.2, the three clauses: the threshold, the null
    /// transitions that bypass it, and the 60-second floor that nothing
    /// bypasses.
    #[test]
    fn local_temperature_significance_and_rate_limit() {
        const DELTA: i16 = 50;

        let t0 = Instant::from_secs(0);
        let t59 = t0 + Duration::from_secs(59);
        let t60 = t0 + Duration::from_secs(60);

        // Below the threshold.
        assert!(!local_temperature_event_due(
            Some(1900),
            Some(1930),
            DELTA,
            None,
            t0
        ));
        // At it.
        assert!(local_temperature_event_due(
            Some(1900),
            Some(1950),
            DELTA,
            None,
            t0
        ));
        // Either direction.
        assert!(local_temperature_event_due(
            Some(1900),
            Some(1850),
            DELTA,
            None,
            t0
        ));

        // Null transitions are significant whatever the threshold says.
        assert!(local_temperature_event_due(
            None,
            Some(1900),
            DELTA,
            None,
            t0
        ));
        assert!(local_temperature_event_due(
            Some(1900),
            None,
            DELTA,
            None,
            t0
        ));
        // Null to null is not a change.
        assert!(!local_temperature_event_due(None, None, DELTA, None, t0));

        // The floor applies to a significant change, including a null one.
        assert!(!local_temperature_event_due(
            Some(1900),
            Some(2000),
            DELTA,
            Some(t0),
            t59
        ));
        assert!(local_temperature_event_due(
            Some(1900),
            Some(2000),
            DELTA,
            Some(t0),
            t60
        ));
        assert!(!local_temperature_event_due(
            Some(1900),
            None,
            DELTA,
            Some(t0),
            t59
        ));
    }

    /// The load-bearing consequence of only advancing the shadow when an
    /// event is produced: a drift in sub-threshold steps still reports once it
    /// has accumulated, instead of creeping forever unnoticed.
    #[test]
    fn a_suppressed_temperature_change_does_not_move_the_shadow() {
        let handler = seeded_handler::<HEAT_EVT>();

        // Two 0.3degC steps: each below the 0.5degC default on its own.
        handler
            .hooks
            .set(|state| state.local_temperature = Some(1930));
        assert!(handler.take_events(Instant::from_secs(0)).is_empty());

        handler
            .hooks
            .set(|state| state.local_temperature = Some(1960));

        assert_eq!(
            handler.take_events(Instant::from_secs(0)).as_slice(),
            [ThermostatEvent::LocalTemperature {
                current: Some(1960)
            }]
        );
    }

    /// A temperature event inside the floor is suppressed, and the change is
    /// still pending afterwards rather than lost.
    #[test]
    fn local_temperature_events_are_rate_limited_in_the_sweep() {
        let handler = seeded_handler::<HEAT_EVT>();

        handler
            .hooks
            .set(|state| state.local_temperature = Some(2000));
        assert_eq!(handler.take_events(Instant::from_secs(0)).len(), 1);

        handler
            .hooks
            .set(|state| state.local_temperature = Some(2100));
        assert!(handler.take_events(Instant::from_secs(30)).is_empty());

        // Still pending, and reported once the floor has passed.
        assert_eq!(
            handler.take_events(Instant::from_secs(60)).as_slice(),
            [ThermostatEvent::LocalTemperature {
                current: Some(2100)
            }]
        );
    }

    /// A temperature event the floor held back is still owed, and `run` needs
    /// a deadline to come back and deliver it - nothing else will ring the
    /// doorbell once the temperature settles.
    #[test]
    fn a_deferred_temperature_event_re_arms_the_run_loop() {
        let handler = seeded_handler::<HEAT_EVT>();

        // Nothing emitted yet, so nothing is being held back.
        assert_eq!(handler.deferred_local_temperature_deadline(), None);

        handler
            .hooks
            .set(|state| state.local_temperature = Some(2000));
        assert_eq!(handler.take_events(Instant::from_secs(0)).len(), 1);
        assert_eq!(handler.deferred_local_temperature_deadline(), None);

        // A second significant change inside the floor is deferred, not lost.
        handler
            .hooks
            .set(|state| state.local_temperature = Some(2100));
        assert!(handler.take_events(Instant::from_secs(30)).is_empty());

        assert_eq!(
            handler.deferred_local_temperature_deadline(),
            Some(Instant::from_secs(0) + Duration::from_secs(60))
        );

        // An insignificant one is not owed anything.
        let handler = seeded_handler::<HEAT_EVT>();
        handler
            .hooks
            .set(|state| state.local_temperature = Some(1920));
        assert!(handler.take_events(Instant::from_secs(0)).is_empty());
        assert_eq!(handler.deferred_local_temperature_deadline(), None);
    }

    /// A heating-only device has no `OccupiedCoolingSetpoint` to report a
    /// change to, so the cooling half of the sweep must stay quiet whatever
    /// the unused hook default does.
    #[test]
    fn a_heating_only_device_never_reports_a_cooling_setpoint_change() {
        let handler = seeded_handler::<HEAT_EVT>();

        handler
            .hooks
            .set(|state| state.occupied_cooling_setpoint = 2900);

        assert!(handler.take_events(Instant::from_secs(0)).is_empty());
    }

    /// An unserved `LocalTemperatureChange` is never owed either.
    #[test]
    fn an_unserved_temperature_event_is_never_deferred() {
        let handler = seeded_handler::<HEAT_LTNE_EVT>();

        handler
            .hooks
            .set(|state| state.local_temperature = Some(3000));

        assert_eq!(handler.deferred_local_temperature_deadline(), None);
    }

    // Section 4.3.11.30-32: who moved the setpoint

    /// A write that arrived over Matter is `External`.
    #[test]
    fn an_in_band_setpoint_write_is_attributed_to_external() {
        let handler = source_handler::<HEAT>();

        handler
            .write_occupied_heating_setpoint(NULL_CTX, 2200)
            .unwrap();

        assert_eq!(
            handler.setpoint_change.get().source,
            SetpointChangeSourceEnum::External
        );
        assert_eq!(handler.setpoint_change.get().amount, Some(200));
        assert_eq!(handler.setpoint_change.get().timestamp, 1000);
    }

    /// `SetpointRaiseLower` is just as external as a write.
    #[test]
    fn setpoint_raise_lower_is_attributed_to_external() {
        let handler = source_handler::<HEAT>();

        handler
            .raise_lower_setpoint(NULL_CTX, SetpointRaiseLowerModeEnum::Heat, -10)
            .unwrap();

        assert_eq!(
            handler.setpoint_change.get().source,
            SetpointChangeSourceEnum::External
        );
        assert_eq!(handler.setpoint_change.get().amount, Some(-100));
    }

    /// A change the device made itself is `Manual` - the front-panel knob,
    /// which is the whole point of the trio.
    #[test]
    fn an_out_of_band_setpoint_change_is_attributed_to_manual() {
        let handler = source_handler::<HEAT>();
        handler.seed_events();

        handler
            .hooks
            .0
            .set(|state| state.occupied_heating_setpoint = 2350);
        handler.attribute_local_setpoint_change(NULL_CTX);

        assert_eq!(
            handler.setpoint_change.get().source,
            SetpointChangeSourceEnum::Manual
        );
        assert_eq!(handler.setpoint_change.get().amount, Some(350));
        assert_eq!(handler.setpoint_change.get().timestamp, 1000);
    }

    /// The deadband may drag the opposite setpoint along, but that is a side
    /// effect of the client's write, not a second, local change.
    #[test]
    fn a_deadband_side_effect_is_not_attributed_to_manual() {
        let handler = source_handler::<AUTO>();
        handler.seed_events();

        // Pushing the heating setpoint up past the deadband drags cooling.
        handler
            .write_occupied_heating_setpoint(NULL_CTX, 2500)
            .unwrap();

        assert_eq!(handler.hooks.occupied_cooling_setpoint(), 2700);
        assert_eq!(
            handler.setpoint_change.get().source,
            SetpointChangeSourceEnum::External
        );
        // The addressed setpoint's delta, not the dragged one's.
        assert_eq!(handler.setpoint_change.get().amount, Some(500));

        // And the sweep must not then call the dragged setpoint a local change.
        handler.attribute_local_setpoint_change(NULL_CTX);

        assert_eq!(
            handler.setpoint_change.get().source,
            SetpointChangeSourceEnum::External
        );
        assert_eq!(handler.setpoint_change.get().amount, Some(500));
    }

    /// ... and the same for the attribution: an unserved cooling setpoint is
    /// not something the front panel can have moved.
    #[test]
    fn a_heating_only_device_never_attributes_a_cooling_change() {
        let handler = source_handler::<HEAT>();
        handler.seed_events();

        handler
            .hooks
            .0
            .set(|state| state.occupied_cooling_setpoint = 2900);
        handler.attribute_local_setpoint_change(NULL_CTX);

        assert_eq!(handler.setpoint_change.get().amount, None);
    }

    /// Startup repair rearranges the setpoints, and must not look like
    /// somebody changing them.
    #[test]
    fn repair_records_no_setpoint_source() {
        let handler = source_handler::<HEAT>();

        handler.repair().unwrap();
        handler.seed_events();
        handler.attribute_local_setpoint_change(NULL_CTX);

        // Still the untouched defaults: `Manual` with a null amount.
        assert_eq!(
            handler.setpoint_change.get().source,
            SetpointChangeSourceEnum::Manual
        );
        assert_eq!(handler.setpoint_change.get().amount, None);
        assert_eq!(handler.setpoint_change.get().timestamp, 0);
    }

    /// The three attributes are re-reported when they move, and only when
    /// they are served.
    #[test]
    fn the_source_attributes_are_re_reported() {
        let handler = source_handler::<HEAT>();
        let notifier = RecordingNotifier::default();

        handler
            .write_occupied_heating_setpoint(&notifier, 2200)
            .unwrap();

        let attrs = notifier.attrs();

        assert!(attrs.contains(&(AttributeId::SetpointChangeSource as AttrId)));
        assert!(attrs.contains(&(AttributeId::SetpointChangeAmount as AttrId)));
        assert!(attrs.contains(&(AttributeId::SetpointChangeSourceTimestamp as AttrId)));

        // A handler that does not serve them says nothing about them.
        let plain = mock_handler::<HEAT>();
        let notifier = RecordingNotifier::default();

        plain
            .write_occupied_heating_setpoint(&notifier, 2200)
            .unwrap();

        assert_eq!(
            notifier.attrs(),
            [AttributeId::OccupiedHeatingSetpoint as AttrId]
        );
    }

    /// The sweep bit rides the same mask as the attribute bits without
    /// disturbing them: it re-reports nothing and drains cleanly.
    #[test]
    fn the_event_sweep_bit_does_not_disturb_the_attribute_mask() {
        let handler = mock_handler::<HEAT_EVT>();
        let notifier = RecordingNotifier::default();

        // `apply` rings it, and nothing else.
        handler.apply(NULL_CTX);

        let pending = handler.pending.modify(|pending| (false, *pending));
        assert_eq!(pending, PENDING_EVENT_SWEEP);

        handler.notify_pending(&notifier, pending);
        assert!(notifier.attrs().is_empty());

        // An out-of-band message carries both halves.
        handler.out_of_band_message(OutOfBandMessage::OccupiedHeatingSetpoint);

        let pending = block_on(handler.wait_pending());
        assert!(pending & PENDING_EVENT_SWEEP != 0);

        handler.notify_pending(&notifier, pending);
        assert_eq!(
            notifier.attrs(),
            [AttributeId::OccupiedHeatingSetpoint as AttrId]
        );

        assert_eq!(handler.pending.modify(|pending| (false, *pending)), 0);
    }

    /// An event-free configuration never rings the sweep bit at all.
    #[test]
    fn an_event_free_handler_never_rings_the_sweep() {
        let handler = mock_handler::<HEAT>();

        handler.apply(NULL_CTX);

        assert_eq!(handler.pending.modify(|pending| (false, *pending)), 0);
    }
}
