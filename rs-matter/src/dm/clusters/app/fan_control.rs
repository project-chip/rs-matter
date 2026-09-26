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

//! Fan Control cluster handler (Matter Application Cluster spec).
//!
//! Fan Control (`0x0202`) sets the speed of a fan, and lets a client do so in
//! three coordinated ways: as a `FanMode` (Off / Low / Medium / High / Auto),
//! as a `PercentSetting` (0..=100) and, with the `MultiSpeed` feature, as a
//! `SpeedSetting` (0..=`SpeedMax`). The spec requires the three to stay
//! consistent — a write to any one moves the other two — and this handler
//! owns that cascade, so that the device only ever sees one thing: the speed
//! it is being asked for.
//!
//! # What the handler owns
//!
//! - The setting: `FanMode`, `PercentSetting` and `SpeedSetting`, kept as a
//!   single percentage (`null` under `Auto`) from which the other two are
//!   derived, so they cannot drift apart. It is persisted, and restored at
//!   startup — see [`FanControlHooks::set_fan`] for what the device is told.
//! - `RockSetting`, `WindSetting` and `AirflowDirection`, validated against
//!   `RockSupport` / `WindSupport` and persisted alongside.
//! - The `Step` command, stepping through the fan's speeds (with `MultiSpeed`)
//!   or its modes (without), with the wrap and lowest-off rules of the spec.
//! - `PercentCurrent` and `SpeedCurrent`, derived from what the device says it
//!   is actually running at ([`FanControlHooks::current_speed`]). For a fan
//!   with discrete speeds this is where the slider stays put: see
//!   [`CurrentSpeed`].
//!
//! # What the device supplies
//!
//! [`FanControlHooks`]: the cluster configuration (`FanModeSequence`,
//! `SpeedMax`, the rock and wind capabilities), the one method that drives
//! the fan, a getter for what it is doing, and — for a fan whose speed can
//! change behind Matter's back, or that takes time to reach a setting — a
//! background task that says so through [`OutOfBandMessage`].
//!
//! # Interaction with On/Off
//!
//! The Fan device type pairs this cluster with `OnOff` so that switching the
//! fan off keeps the setting: the Device Library asks that `OnOff` = false
//! zero `PercentCurrent` / `SpeedCurrent` and leave `FanMode`,
//! `PercentSetting` and `SpeedSetting` alone. That is entirely the device's
//! business here: while it is off it reports [`CurrentSpeed`] zero, and the
//! setting is untouched because nothing asked the handler to touch it.
//!
//! # Usage
//!
//! ```ignore
//! use rs_matter::dm::clusters::app::fan_control::{
//!     self, CurrentSpeed, FanControlHandler, FanControlHooks, FanModeSequenceEnum, FanSetting,
//!     Feature, FULL_CLUSTER,
//! };
//!
//! struct CeilingFan { /* ... */ }
//!
//! impl FanControlHooks for CeilingFan {
//!     // Revision 6 is the Matter 1.6 cluster; the IDL is a revision behind.
//!     const CLUSTER: Cluster<'static> = FULL_CLUSTER
//!         .with_revision(6)
//!         .with_features(Feature::MULTI_SPEED.bits() | Feature::AUTO.bits())
//!         .with_attrs(with!(
//!             required;
//!             fan_control::AttributeId::SpeedMax
//!                 | fan_control::AttributeId::SpeedSetting
//!                 | fan_control::AttributeId::SpeedCurrent
//!         ))
//!         .with_cmds(with!());
//!
//!     const FAN_MODE_SEQUENCE: FanModeSequenceEnum = FanModeSequenceEnum::OffLowMedHighAuto;
//!     const SPEED_MAX: u8 = 3;
//!
//!     fn set_fan(&self, setting: FanSetting) -> Result<(), ()> {
//!         match setting {
//!             FanSetting::Off => self.stop(),
//!             FanSetting::Auto => self.run_thermostatically(),
//!             FanSetting::Manual { speed, .. } => self.select_winding(speed),
//!         }
//!
//!         Ok(())
//!     }
//!
//!     fn current_speed(&self) -> CurrentSpeed {
//!         CurrentSpeed::Speed(self.winding())
//!     }
//! }
//!
//! // The handler owns and persists the settings under this KV key.
//! let handler = FanControlHandler::new(Dataver::new_rand(rand), 1, VENDOR_KEYS_START, CeilingFan::new());
//!
//! let device_handler = EmptyHandler.chain(
//!     |e, c| e == 1 && c == CeilingFan::CLUSTER.id,
//!     fan_control::HandlerAdaptor(handler),
//! );
//! ```

use core::cell::Cell;
use core::future::{pending, Future};

use embassy_futures::select::{select, Either};

use crate::dm::clusters::app::deferred_persist::DeferredPersist;
pub use crate::dm::clusters::decl::fan_control::*;
use crate::dm::{
    AttrChangeNotifier, Cluster, Dataver, EndptId, HandlerContext, InvokeContext, LifecycleOp,
    ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::im::Percent;
use crate::persist::{KvBlobStoreAccess, Persist};
use crate::tlv::{FromTLV, Nullable, ToTLV};
use crate::utils::sync::blocking::Mutex;

/// Messages passed to the `notify` closure of [`FanControlHooks::run`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OutOfBandMessage {
    /// [`FanControlHooks::current_speed`] changed: the fan reached the speed
    /// it was asked for, somebody turned the knob on the unit, a coupled
    /// `OnOff` switched it off. `PercentCurrent` and `SpeedCurrent` are
    /// re-read and re-reported.
    CurrentSpeed,
    /// The device set `FanMode` itself. `PercentSetting` and `SpeedSetting`
    /// follow, as they would for a write; the device is not driven.
    FanMode(FanModeEnum),
    /// The device set `PercentSetting` itself.
    PercentSetting(Percent),
    /// The device set `SpeedSetting` itself.
    SpeedSetting(u8),
    /// The device set `RockSetting` itself.
    RockSetting(RockBitmap),
    /// The device set `WindSetting` itself.
    WindSetting(WindBitmap),
    /// The device set `AirflowDirection` itself.
    AirflowDirection(AirflowDirectionEnum),
}

/// The speed the handler asks the device for.
///
/// One value, in the three forms the cluster keeps consistent, so a device
/// picks whichever it understands: a fan with a tap changer reads `speed`, a
/// PWM fan reads `percent`, a fan with three relays reads `mode`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FanSetting {
    /// `FanMode` Off: stop the fan.
    Off,
    /// `FanMode` Auto: the device chooses its own speed from here on.
    Auto,
    /// A speed the client chose.
    Manual {
        /// `FanMode`: `Low`, `Medium` or `High`.
        mode: FanModeEnum,
        /// `PercentSetting`, 1..=100.
        percent: Percent,
        /// `SpeedSetting`, 1..=[`FanControlHooks::SPEED_MAX`]. Always 1 for
        /// a fan without the `MultiSpeed` feature.
        speed: u8,
    },
}

/// What the fan is actually running at, as the device knows it.
///
/// This is the source of `PercentCurrent` and `SpeedCurrent`, and the device
/// reports it in whichever quantity it has:
///
/// - a continuously variable fan knows a percentage;
/// - a fan with `SpeedMax` discrete speeds knows which one is engaged;
/// - a fan whose speeds *are* its modes — three relays — knows the mode.
///
/// For the two discrete forms the handler does not simply requantise: a
/// client that wrote `PercentSetting` 64 to a three-speed fan reads
/// `PercentCurrent` 64 once the fan reaches the speed 64 maps to, not the
/// speed's nominal 66. The spec allows `PercentCurrent` to differ from the
/// setting only *temporarily*, and an ecosystem that draws its slider from
/// `PercentCurrent` would otherwise see it jump on every re-read. While the
/// fan is between two speeds the percentage it last delivered at its present
/// speed is held, so the attribute never reports the fan moving in a direction
/// it did not move in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CurrentSpeed {
    /// The percentage of full speed the fan is running at; 0 when stopped.
    Percent(Percent),
    /// The discrete speed the fan is running at, 1..=`SpeedMax`; 0 when
    /// stopped.
    Speed(u8),
    /// The mode the fan is running in: `Off`, `Low`, `Medium` or `High`.
    Mode(FanModeEnum),
}

/// Whether `sequence` includes the `Low` mode.
pub const fn sequence_has_low(sequence: FanModeSequenceEnum) -> bool {
    matches!(
        sequence,
        FanModeSequenceEnum::OffLowMedHigh
            | FanModeSequenceEnum::OffLowHigh
            | FanModeSequenceEnum::OffLowMedHighAuto
            | FanModeSequenceEnum::OffLowHighAuto
    )
}

/// Whether `sequence` includes the `Medium` mode.
pub const fn sequence_has_medium(sequence: FanModeSequenceEnum) -> bool {
    matches!(
        sequence,
        FanModeSequenceEnum::OffLowMedHigh | FanModeSequenceEnum::OffLowMedHighAuto
    )
}

/// Whether `sequence` includes the `Auto` mode, which is what the `AUTO`
/// feature means.
pub const fn sequence_has_auto(sequence: FanModeSequenceEnum) -> bool {
    matches!(
        sequence,
        FanModeSequenceEnum::OffLowMedHighAuto
            | FanModeSequenceEnum::OffLowHighAuto
            | FanModeSequenceEnum::OffHighAuto
    )
}

/// Whether `mode` is one of the values `FanMode` can take under `sequence`.
///
/// `On` and `Smart` are deprecated aliases a client may still write, which
/// the handler translates; they are never *supported* as such.
pub const fn sequence_supports(sequence: FanModeSequenceEnum, mode: FanModeEnum) -> bool {
    match mode {
        FanModeEnum::Off | FanModeEnum::High => true,
        FanModeEnum::Low => sequence_has_low(sequence),
        FanModeEnum::Medium => sequence_has_medium(sequence),
        FanModeEnum::Auto => sequence_has_auto(sequence),
        FanModeEnum::On | FanModeEnum::Smart => false,
    }
}

/// How many speed modes (`Low`, `Medium`, `High`) `sequence` has: 1, 2 or 3.
pub const fn sequence_speed_modes(sequence: FanModeSequenceEnum) -> u8 {
    1 + sequence_has_low(sequence) as u8 + sequence_has_medium(sequence) as u8
}

/// The `FanMode` a `PercentSetting` maps to under `sequence`.
///
/// The percent rules: 0 is `Off`, and the rest of 0..=100 is cut into one
/// contiguous range per speed mode — thirds for three modes, halves for two,
/// the whole for one.
pub const fn mode_of_percent(sequence: FanModeSequenceEnum, percent: Percent) -> FanModeEnum {
    if percent == 0 {
        FanModeEnum::Off
    } else if sequence_has_medium(sequence) {
        if percent <= 33 {
            FanModeEnum::Low
        } else if percent <= 66 {
            FanModeEnum::Medium
        } else {
            FanModeEnum::High
        }
    } else if sequence_has_low(sequence) {
        if percent <= 50 {
            FanModeEnum::Low
        } else {
            FanModeEnum::High
        }
    } else {
        FanModeEnum::High
    }
}

/// The `PercentSetting` a written `FanMode` sets: the top of the mode's
/// range under `sequence`, or `None` for a mode with no range — `Auto`, and
/// the deprecated `On` / `Smart`.
pub const fn percent_of_mode(sequence: FanModeSequenceEnum, mode: FanModeEnum) -> Option<Percent> {
    match mode {
        FanModeEnum::Off => Some(0),
        FanModeEnum::Low if sequence_has_medium(sequence) => Some(33),
        FanModeEnum::Low if sequence_has_low(sequence) => Some(50),
        FanModeEnum::Medium if sequence_has_medium(sequence) => Some(66),
        FanModeEnum::High => Some(100),
        _ => None,
    }
}

/// The speed a percentage maps to: `ceil(SpeedMax * percent / 100)`, so
/// that any percentage above zero engages at least the lowest speed.
pub const fn speed_of_percent(speed_max: u8, percent: Percent) -> u8 {
    (speed_max as u16 * percent as u16).div_ceil(100) as u8
}

/// The percentage a speed maps to: `floor(speed / SpeedMax * 100)`.
///
/// The exact inverse of [`speed_of_percent`] for every `SpeedMax` up to 100,
/// which is what lets a written `SpeedSetting` read back unchanged.
pub const fn percent_of_speed(speed_max: u8, speed: u8) -> Percent {
    (speed as u16 * 100 / speed_max as u16) as u8
}

/// Device-specific logic behind the Fan Control cluster.
pub trait FanControlHooks {
    /// The cluster metadata this handler exposes: the features, and the
    /// attributes and commands that go with them. Checked at startup, see
    /// [`FanControlHandler`].
    const CLUSTER: Cluster<'static>;

    /// The `FanModeSequence`: which of `Low`, `Medium` and `Auto` the fan
    /// has, besides the mandatory `Off` and `High`. Fixed for the life of the
    /// firmware, and it must agree with the `AUTO` feature.
    const FAN_MODE_SEQUENCE: FanModeSequenceEnum;

    /// `SpeedMax`, with the `MultiSpeed` feature: how many discrete speeds
    /// the fan has, 1..=100, and at least as many as it has speed modes.
    /// Meaningless without the feature, where it stays at 1.
    const SPEED_MAX: u8 = 1;

    /// `RockSupport`, with the `Rocking` feature: at least one bit.
    const ROCK_SUPPORT: RockBitmap = RockBitmap::empty();

    /// `WindSupport`, with the `Wind` feature: at least one bit.
    const WIND_SUPPORT: WindBitmap = WindBitmap::empty();

    // Initial values of the attributes the handler persists itself, under
    // the KV key it is constructed with.

    /// The initial `PercentSetting`, used until the handler has persisted
    /// one. `None` is null, i.e. `FanMode` Auto, and needs the `AUTO`
    /// feature. `FanMode` and `SpeedSetting` follow from it.
    const PERCENT_SETTING: Option<Percent> = Some(0);

    /// The initial `RockSetting`. Must be within [`Self::ROCK_SUPPORT`].
    const ROCK_SETTING: RockBitmap = RockBitmap::empty();

    /// The initial `WindSetting`. Must be within [`Self::WIND_SUPPORT`].
    const WIND_SETTING: WindBitmap = WindBitmap::empty();

    /// The initial `AirflowDirection`.
    const AIRFLOW_DIRECTION: AirflowDirectionEnum = AirflowDirectionEnum::Forward;

    /// How long the settings have to stay unchanged before the handler
    /// persists them, in milliseconds. A slider being dragged writes
    /// `PercentSetting` many times a second; this turns that into one flash
    /// write once it settles, at the cost of losing the last change on a
    /// power loss within the window.
    const PERSIST_DELAY_MS: u32 = 3000;

    /// Drive the fan to `setting`.
    ///
    /// Called for every successful write to `FanMode`, `PercentSetting` or
    /// `SpeedSetting` and for every `Step` command — always with a setting
    /// that differs from the current one — and once at startup, with the
    /// restored setting, so that the fan comes up as it was left. The
    /// startup call is made even if the setting is the initial
    /// [`Self::PERCENT_SETTING`]: the attribute says nothing about the state
    /// the hardware powered up in.
    ///
    /// `Err(())` means the fan cannot switch to `setting` right now. The
    /// client sees `INVALID_IN_STATE` and nothing changes; at startup the
    /// handler falls back to `Off`.
    ///
    /// This asks; it does not wait. A fan that takes time to spin up reports
    /// its progress through [`Self::current_speed`], and says when that has
    /// moved through [`OutOfBandMessage::CurrentSpeed`].
    #[allow(clippy::result_unit_err)]
    fn set_fan(&self, setting: FanSetting) -> Result<(), ()>;

    /// What the fan is running at right now.
    ///
    /// Read after every [`Self::set_fan`], on every
    /// [`OutOfBandMessage::CurrentSpeed`] and whenever a client reads
    /// `PercentCurrent` or `SpeedCurrent`. A fan that reaches its setting
    /// the moment it is asked can answer from the setting it was last given.
    fn current_speed(&self) -> CurrentSpeed;

    /// Start rocking as `setting` says, and return what was actually taken.
    ///
    /// Only called with the `Rocking` feature, with a `setting` within
    /// `RockSupport` that differs from the current one, and once at startup
    /// with the restored value. A device that does not support the
    /// *combination* it was given may return the lowest of its bits alone,
    /// which is what the spec asks it to do; the default takes every
    /// combination. Note that the certification suite (`TC_FAN_2_3`, and
    /// `TC_FAN_2_4` for wind) writes a random subset of the supported bits
    /// and expects it back unchanged, so a device that reduces combinations
    /// will not pass it.
    fn set_rock_setting(&self, setting: RockBitmap) -> RockBitmap {
        setting
    }

    /// Start the wind emulation `setting` says, and return what was actually
    /// taken. The `Wind` counterpart of [`Self::set_rock_setting`].
    fn set_wind_setting(&self, setting: WindBitmap) -> WindBitmap {
        setting
    }

    /// Reverse the airflow. Only called with the `AirflowDirection` feature,
    /// with a direction that differs from the current one, and once at
    /// startup with the restored value.
    fn set_airflow_direction(&self, direction: AirflowDirectionEnum) {
        let _ = direction;
    }

    /// Background task for out-of-band notifications to the handler: the fan
    /// reaching its setting, or being changed at the unit itself.
    ///
    /// This future MUST NOT return. Implementers should either loop forever
    /// or await `core::future::pending::<()>()`, so the SDK's task does not
    /// observe a completed future.
    ///
    /// # Panics
    /// The SDK will panic if this method returns.
    fn run<F: Fn(OutOfBandMessage)>(&self, _notify: F) -> impl Future<Output = ()> {
        pending::<()>()
    }
}

impl<T> FanControlHooks for &T
where
    T: FanControlHooks,
{
    const CLUSTER: Cluster<'static> = T::CLUSTER;
    const FAN_MODE_SEQUENCE: FanModeSequenceEnum = T::FAN_MODE_SEQUENCE;
    const SPEED_MAX: u8 = T::SPEED_MAX;
    const ROCK_SUPPORT: RockBitmap = T::ROCK_SUPPORT;
    const WIND_SUPPORT: WindBitmap = T::WIND_SUPPORT;
    const PERCENT_SETTING: Option<Percent> = T::PERCENT_SETTING;
    const ROCK_SETTING: RockBitmap = T::ROCK_SETTING;
    const WIND_SETTING: WindBitmap = T::WIND_SETTING;
    const AIRFLOW_DIRECTION: AirflowDirectionEnum = T::AIRFLOW_DIRECTION;
    const PERSIST_DELAY_MS: u32 = T::PERSIST_DELAY_MS;

    fn set_fan(&self, setting: FanSetting) -> Result<(), ()> {
        (*self).set_fan(setting)
    }

    fn current_speed(&self) -> CurrentSpeed {
        (*self).current_speed()
    }

    fn set_rock_setting(&self, setting: RockBitmap) -> RockBitmap {
        (*self).set_rock_setting(setting)
    }

    fn set_wind_setting(&self, setting: WindBitmap) -> WindBitmap {
        (*self).set_wind_setting(setting)
    }

    fn set_airflow_direction(&self, direction: AirflowDirectionEnum) {
        (*self).set_airflow_direction(direction)
    }

    fn run<F: Fn(OutOfBandMessage)>(&self, notify: F) -> impl Future<Output = ()> {
        (*self).run(notify)
    }
}

/// The attributes the handler persists under its KV key.
///
/// The speed setting is one percentage: `FanMode` and `SpeedSetting` are
/// derived from it at load, so a firmware update that changes the mode
/// sequence or `SpeedMax` cannot restore an inconsistent triple. The spec
/// marks only `FanMode` as non-volatile; the percentage carries more, and
/// the rest ride along so the fan comes back exactly as it was left.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromTLV, ToTLV)]
struct PersistedAttrs {
    /// `PercentSetting`; `None` is null, i.e. `FanMode` Auto.
    setting: Option<Percent>,
    rock_setting: RockBitmap,
    wind_setting: WindBitmap,
    airflow_direction: AirflowDirectionEnum,
}

impl PersistedAttrs {
    /// The initial values, as supplied by the hooks.
    const fn new<H: FanControlHooks>() -> Self {
        Self {
            setting: H::PERCENT_SETTING,
            rock_setting: H::ROCK_SETTING,
            wind_setting: H::WIND_SETTING,
            airflow_direction: H::AIRFLOW_DIRECTION,
        }
    }
}

/// The handler's state, behind one lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    /// The persisted attributes, as they are now.
    attrs: PersistedAttrs,
    /// `PercentCurrent` as last observed - the percentage the fan was last
    /// known to deliver, which is what a discrete fan between two speeds
    /// keeps reporting. See [`CurrentSpeed`].
    percent_current: Percent,
    /// `SpeedCurrent` as last observed.
    speed_current: u8,
}

/// The handler for the Fan Control Matter cluster.
///
/// One instance serves one endpoint. Adapt it to the generic `rs-matter`
/// handler trait with [`FanControlHandler::adapt`].
///
/// # Startup validation
///
/// At [`LifecycleOp::Startup`] the handler checks the configuration the hooks
/// supply and **panics** on a violation — these are firmware bugs, not
/// anything a device can recover from:
///
/// - the mandatory attributes are exposed;
/// - each feature is declared if and only if the attributes (or, for `STEP`,
///   the command) it adds are exposed;
/// - the `AUTO` feature agrees with [`FanControlHooks::FAN_MODE_SEQUENCE`];
/// - with `MultiSpeed`, [`FanControlHooks::SPEED_MAX`] is 1..=100 and at
///   least the number of speed modes in the sequence, so that every mode has
///   a speed of its own;
/// - with `Rocking` / `Wind`, the support bitmap has a bit set and the
///   initial setting is within it;
/// - the initial [`FanControlHooks::PERCENT_SETTING`] is at most 100, and
///   null only with `AUTO`.
///
/// It then restores the persisted settings and puts the fan in them.
pub struct FanControlHandler<H> {
    dataver: Dataver,
    endpoint_id: EndptId,
    hooks: H,
    /// The KV store key the settings are persisted under.
    kv_key: u16,
    state: Mutex<Cell<State>>,
    persist: DeferredPersist,
}

impl<H> FanControlHandler<H>
where
    H: FanControlHooks,
{
    /// Create a handler serving Fan Control on `endpoint_id`.
    ///
    /// `kv_key` is the KV store key under which the handler persists the
    /// attributes it owns (`FanMode` / `PercentSetting` / `SpeedSetting`,
    /// `RockSetting`, `WindSetting` and `AirflowDirection`). It must be unique
    /// across everything stored in the KV store, e.g. a key in the vendor
    /// range starting at [`crate::persist::VENDOR_KEYS_START`].
    pub const fn new(dataver: Dataver, endpoint_id: EndptId, kv_key: u16, hooks: H) -> Self {
        Self {
            dataver,
            endpoint_id,
            hooks,
            kv_key,
            state: Mutex::new(Cell::new(State {
                attrs: PersistedAttrs::new::<H>(),
                percent_current: 0,
                speed_current: 0,
            })),
            persist: DeferredPersist::new(),
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    /// The application's hooks.
    pub fn hooks(&self) -> &H {
        &self.hooks
    }

    /// `FanMode`, as it is now.
    pub fn fan_mode(&self) -> FanModeEnum {
        Self::mode_of_setting(self.state().attrs.setting)
    }

    /// `PercentSetting`, as it is now; `None` is null, i.e. `FanMode` Auto.
    pub fn percent_setting(&self) -> Option<Percent> {
        self.state().attrs.setting
    }

    /// `SpeedSetting`, as it is now; `None` is null, i.e. `FanMode` Auto.
    pub fn speed_setting(&self) -> Option<u8> {
        Self::speed_of_setting(self.state().attrs.setting)
    }

    /// `PercentCurrent`, as the device reports it right now.
    pub fn percent_current(&self) -> Percent {
        self.current().0
    }

    /// `SpeedCurrent`, as the device reports it right now.
    pub fn speed_current(&self) -> u8 {
        self.current().1
    }

    /// `RockSetting`, as it is now.
    pub fn rock_setting(&self) -> RockBitmap {
        self.state().attrs.rock_setting
    }

    /// `WindSetting`, as it is now.
    pub fn wind_setting(&self) -> WindBitmap {
        self.state().attrs.wind_setting
    }

    /// `AirflowDirection`, as it is now.
    pub fn airflow_direction(&self) -> AirflowDirectionEnum {
        self.state().attrs.airflow_direction
    }

    fn state(&self) -> State {
        self.state.lock(|state| state.get())
    }

    /// Whether the cluster declares `feature`.
    const fn has(feature: Feature) -> bool {
        H::CLUSTER.feature_map & feature.bits() != 0
    }

    /// Whether `mode` is one of the values `FanMode` can take here.
    pub const fn supports_mode(mode: FanModeEnum) -> bool {
        sequence_supports(H::FAN_MODE_SEQUENCE, mode)
    }

    /// The `FanMode` a setting represents.
    const fn mode_of_setting(setting: Option<Percent>) -> FanModeEnum {
        match setting {
            None => FanModeEnum::Auto,
            Some(percent) => mode_of_percent(H::FAN_MODE_SEQUENCE, percent),
        }
    }

    /// The `SpeedSetting` a setting represents.
    const fn speed_of_setting(setting: Option<Percent>) -> Option<u8> {
        match setting {
            None => None,
            Some(percent) => Some(speed_of_percent(H::SPEED_MAX, percent)),
        }
    }

    /// The setting a device is asked for.
    const fn fan_setting(setting: Option<Percent>) -> FanSetting {
        match setting {
            None => FanSetting::Auto,
            Some(0) => FanSetting::Off,
            Some(percent) => FanSetting::Manual {
                mode: mode_of_percent(H::FAN_MODE_SEQUENCE, percent),
                percent,
                speed: speed_of_percent(H::SPEED_MAX, percent),
            },
        }
    }

    /// `(PercentCurrent, SpeedCurrent)` for what the device reports, given
    /// the state as last observed. Pure, so that a read and the report that
    /// follows an observation cannot disagree.
    fn current_of(state: &State, current: CurrentSpeed) -> (Percent, u8) {
        // Off zeroes both, whatever the fan is still doing: the spec makes
        // that a consequence of the write, not of the blades stopping.
        match state.attrs.setting {
            Some(0) => (0, 0),
            setting => Self::requantise(state, setting, current),
        }
    }

    /// [`Self::current_of`] once Off has been dealt with: `setting` is the
    /// non-zero `PercentSetting`, or `None` under Auto.
    fn requantise(state: &State, setting: Option<Percent>, current: CurrentSpeed) -> (Percent, u8) {
        match current {
            CurrentSpeed::Percent(percent) => {
                let percent = percent.min(100);

                (percent, speed_of_percent(H::SPEED_MAX, percent))
            }
            CurrentSpeed::Speed(speed) => {
                let speed = speed.min(H::SPEED_MAX);

                if speed == 0 {
                    return (0, 0);
                }

                // Settled at the speed the setting maps to: the setting is
                // what the fan delivers, verbatim. Otherwise, in transition:
                // hold the percentage last delivered at this speed, and only
                // fall back to the speed's nominal percentage when nothing is
                // known - the first observation, a knob turned on the unit.
                let percent = match setting {
                    Some(setting) if speed_of_percent(H::SPEED_MAX, setting) == speed => setting,
                    _ if speed_of_percent(H::SPEED_MAX, state.percent_current) == speed => {
                        state.percent_current
                    }
                    _ => percent_of_speed(H::SPEED_MAX, speed),
                };

                (percent, speed)
            }
            CurrentSpeed::Mode(mode) => {
                // The deprecated aliases resolve to `High`, as a write would.
                let mode = match mode {
                    FanModeEnum::Off => return (0, 0),
                    FanModeEnum::Low | FanModeEnum::Medium => mode,
                    _ => FanModeEnum::High,
                };

                let sequence = H::FAN_MODE_SEQUENCE;

                let percent = match setting {
                    Some(setting) if mode_of_percent(sequence, setting) == mode => setting,
                    _ if mode_of_percent(sequence, state.percent_current) == mode => {
                        state.percent_current
                    }
                    _ => percent_of_mode(sequence, mode).unwrap_or(100),
                };

                (percent, speed_of_percent(H::SPEED_MAX, percent))
            }
        }
    }

    /// `(PercentCurrent, SpeedCurrent)` right now.
    fn current(&self) -> (Percent, u8) {
        let state = self.state();

        Self::current_of(&state, self.hooks.current_speed())
    }

    /// Ask the device what it is running at, and re-report `PercentCurrent`
    /// and `SpeedCurrent` if that moved.
    fn observe_current(&self, notifier: &impl AttrChangeNotifier) {
        let current = self.hooks.current_speed();

        let (percent_changed, speed_changed) = self.state.lock(|cell| {
            let mut state = cell.get();

            let (percent, speed) = Self::current_of(&state, current);

            let percent_changed = percent != state.percent_current;
            let speed_changed = speed != state.speed_current;

            state.percent_current = percent;
            state.speed_current = speed;

            cell.set(state);

            (percent_changed, speed_changed)
        });

        if percent_changed {
            self.notify(notifier, AttributeId::PercentCurrent);
        }

        if speed_changed && Self::has(Feature::MULTI_SPEED) {
            self.notify(notifier, AttributeId::SpeedCurrent);
        }
    }

    /// Update the persisted attributes, to be saved once they settle.
    /// Returns the values before and after.
    fn update_attrs<F>(&self, f: F) -> (PersistedAttrs, PersistedAttrs)
    where
        F: FnOnce(&mut PersistedAttrs),
    {
        let (before, after) = self.state.lock(|cell| {
            let mut state = cell.get();
            let before = state.attrs;

            f(&mut state.attrs);
            cell.set(state);

            (before, state.attrs)
        });

        if before != after {
            self.persist.mark_dirty();
        }

        (before, after)
    }

    /// Restore the persisted attributes, if any.
    fn load_persisted(&self, kv: impl KvBlobStoreAccess) -> Result<(), Error> {
        if let Some(persisted) = Persist::new(kv).load_tlv::<PersistedAttrs>(self.kv_key)? {
            self.state.lock(|cell| {
                let mut state = cell.get();
                state.attrs = persisted;
                cell.set(state);
            });
        }

        Ok(())
    }

    /// Save the persisted attributes now.
    fn save(&self, kv: impl KvBlobStoreAccess) -> Result<(), Error> {
        self.persist.clear();

        Persist::new(kv).store_tlv(self.kv_key, self.state().attrs)
    }

    fn notify(&self, notifier: &impl AttrChangeNotifier, attr: AttributeId) {
        notifier.notify_attr_changed(self.endpoint_id, H::CLUSTER.id, attr as _);
    }

    /// Take `setting` over as the speed setting, without telling the device,
    /// which either set it itself or has just been told, and report
    /// whichever of `FanMode`, `PercentSetting` and `SpeedSetting` moved.
    fn adopt(&self, notifier: &impl AttrChangeNotifier, setting: Option<Percent>) {
        let (before, after) = self.update_attrs(|attrs| attrs.setting = setting);

        if before.setting == after.setting {
            return;
        }

        if Self::mode_of_setting(before.setting) != Self::mode_of_setting(after.setting) {
            self.notify(notifier, AttributeId::FanMode);
        }

        self.notify(notifier, AttributeId::PercentSetting);

        if Self::has(Feature::MULTI_SPEED)
            && Self::speed_of_setting(before.setting) != Self::speed_of_setting(after.setting)
        {
            self.notify(notifier, AttributeId::SpeedSetting);
        }
    }

    /// Ask the device for `setting` and, if it agrees, take it over: the
    /// cascade behind every write to `FanMode`, `PercentSetting` and
    /// `SpeedSetting`, and behind `Step`.
    fn apply(
        &self,
        notifier: &impl AttrChangeNotifier,
        setting: Option<Percent>,
    ) -> Result<(), Error> {
        if self.hooks.set_fan(Self::fan_setting(setting)).is_err() {
            return Err(ErrorCode::InvalidInState.into());
        }

        self.adopt(notifier, setting);
        self.observe_current(notifier);

        Ok(())
    }

    /// Serve a write to `FanMode`.
    ///
    /// The deprecated `On` is `High`, and `Smart` is `Auto` where the fan has
    /// it and `High` where it does not. A mode the sequence does not include
    /// is a `CONSTRAINT_ERROR`. A mode the fan is already in changes nothing;
    /// in particular it leaves a `PercentSetting` elsewhere in the mode's
    /// range alone, which the spec allows.
    pub fn write_fan_mode(
        &self,
        notifier: &impl AttrChangeNotifier,
        value: FanModeEnum,
    ) -> Result<(), Error> {
        let mode = match value {
            FanModeEnum::On => FanModeEnum::High,
            FanModeEnum::Smart if Self::supports_mode(FanModeEnum::Auto) => FanModeEnum::Auto,
            FanModeEnum::Smart => FanModeEnum::High,
            mode => mode,
        };

        if !Self::supports_mode(mode) {
            return Err(ErrorCode::ConstraintError.into());
        }

        if self.fan_mode() == mode {
            return Ok(());
        }

        let setting = match mode {
            FanModeEnum::Auto => None,
            mode => percent_of_mode(H::FAN_MODE_SEQUENCE, mode),
        };

        self.apply(notifier, setting)
    }

    /// Serve a write to `PercentSetting`.
    ///
    /// Null is not a value a client can ask for - it is what `FanMode` Auto
    /// sets - so writing it is `INVALID_IN_STATE` unless the fan is in Auto
    /// already, in which case there is nothing to change.
    pub fn write_percent_setting(
        &self,
        notifier: &impl AttrChangeNotifier,
        value: Nullable<Percent>,
    ) -> Result<(), Error> {
        let current = self.percent_setting();

        let Some(percent) = value.into_option() else {
            return Self::null_write(current);
        };

        if percent > 100 {
            return Err(ErrorCode::ConstraintError.into());
        }

        if current == Some(percent) {
            return Ok(());
        }

        self.apply(notifier, Some(percent))
    }

    /// Serve a write to `SpeedSetting`. Null is treated as for
    /// [`Self::write_percent_setting`].
    pub fn write_speed_setting(
        &self,
        notifier: &impl AttrChangeNotifier,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        let current = self.percent_setting();

        let Some(speed) = value.into_option() else {
            return Self::null_write(current);
        };

        if speed > H::SPEED_MAX {
            return Err(ErrorCode::ConstraintError.into());
        }

        if Self::speed_of_setting(current) == Some(speed) {
            return Ok(());
        }

        self.apply(notifier, Some(percent_of_speed(H::SPEED_MAX, speed)))
    }

    /// The status of a null write to `PercentSetting` or `SpeedSetting`.
    fn null_write(current: Option<Percent>) -> Result<(), Error> {
        if current.is_none() {
            Ok(())
        } else {
            Err(ErrorCode::InvalidInState.into())
        }
    }

    /// Serve a write to `RockSetting`: a bit outside `RockSupport` is a
    /// `CONSTRAINT_ERROR`; the device decides what it makes of a combination.
    pub fn write_rock_setting(
        &self,
        notifier: &impl AttrChangeNotifier,
        value: RockBitmap,
    ) -> Result<(), Error> {
        if !H::ROCK_SUPPORT.contains(value) {
            return Err(ErrorCode::ConstraintError.into());
        }

        if self.rock_setting() != value {
            let taken = self.hooks.set_rock_setting(value) & H::ROCK_SUPPORT;

            self.adopt_rock_setting(notifier, taken);
        }

        Ok(())
    }

    /// Serve a write to `WindSetting`; see [`Self::write_rock_setting`].
    pub fn write_wind_setting(
        &self,
        notifier: &impl AttrChangeNotifier,
        value: WindBitmap,
    ) -> Result<(), Error> {
        if !H::WIND_SUPPORT.contains(value) {
            return Err(ErrorCode::ConstraintError.into());
        }

        if self.wind_setting() != value {
            let taken = self.hooks.set_wind_setting(value) & H::WIND_SUPPORT;

            self.adopt_wind_setting(notifier, taken);
        }

        Ok(())
    }

    /// Serve a write to `AirflowDirection`.
    pub fn write_airflow_direction(
        &self,
        notifier: &impl AttrChangeNotifier,
        value: AirflowDirectionEnum,
    ) -> Result<(), Error> {
        if self.airflow_direction() != value {
            self.hooks.set_airflow_direction(value);

            self.adopt_airflow_direction(notifier, value);
        }

        Ok(())
    }

    fn adopt_rock_setting(&self, notifier: &impl AttrChangeNotifier, value: RockBitmap) {
        let (before, after) = self.update_attrs(|attrs| attrs.rock_setting = value);

        if before != after {
            self.notify(notifier, AttributeId::RockSetting);
        }
    }

    fn adopt_wind_setting(&self, notifier: &impl AttrChangeNotifier, value: WindBitmap) {
        let (before, after) = self.update_attrs(|attrs| attrs.wind_setting = value);

        if before != after {
            self.notify(notifier, AttributeId::WindSetting);
        }
    }

    fn adopt_airflow_direction(
        &self,
        notifier: &impl AttrChangeNotifier,
        value: AirflowDirectionEnum,
    ) {
        let (before, after) = self.update_attrs(|attrs| attrs.airflow_direction = value);

        if before != after {
            self.notify(notifier, AttributeId::AirflowDirection);
        }
    }

    /// Serve a `Step` command.
    ///
    /// The step values are the fan's speeds 1..=`SpeedMax` with the
    /// `MultiSpeed` feature and its speed modes without, plus Off when
    /// `lowest_off` says so. From wherever the setting is - `Auto` counts as
    /// off - one step up or down; at the end of the range the setting either
    /// wraps around or stays put.
    pub fn step(
        &self,
        notifier: &impl AttrChangeNotifier,
        direction: StepDirectionEnum,
        wrap: bool,
        lowest_off: bool,
    ) -> Result<(), Error> {
        let multi_speed = Self::has(Feature::MULTI_SPEED);
        let sequence = H::FAN_MODE_SEQUENCE;

        let highest = if multi_speed {
            H::SPEED_MAX
        } else {
            sequence_speed_modes(sequence)
        };
        let lowest = if lowest_off { 0 } else { 1 };

        let setting = self.percent_setting();

        let position = if multi_speed {
            Self::speed_of_setting(setting).unwrap_or(0)
        } else {
            Self::speed_mode_index(setting)
        };

        let target = match direction {
            StepDirectionEnum::Increase if position < highest => position + 1,
            StepDirectionEnum::Increase if wrap => lowest,
            StepDirectionEnum::Increase => highest,
            StepDirectionEnum::Decrease if position > lowest => position - 1,
            StepDirectionEnum::Decrease if wrap => highest,
            StepDirectionEnum::Decrease => lowest,
        };

        let target = if target == 0 {
            Some(0)
        } else if multi_speed {
            Some(percent_of_speed(H::SPEED_MAX, target))
        } else {
            percent_of_mode(sequence, Self::speed_mode_at(target))
        };

        if target == setting {
            return Ok(());
        }

        self.apply(notifier, target)
    }

    /// The position of a setting among the speed modes of the sequence: 0 for
    /// Off (and Auto), then 1 per mode in ascending order.
    const fn speed_mode_index(setting: Option<Percent>) -> u8 {
        let sequence = H::FAN_MODE_SEQUENCE;

        match Self::mode_of_setting(setting) {
            FanModeEnum::Low => 1,
            FanModeEnum::Medium => 2,
            FanModeEnum::High => sequence_speed_modes(sequence),
            _ => 0,
        }
    }

    /// The inverse of [`Self::speed_mode_index`] for `index` 1..=modes.
    const fn speed_mode_at(index: u8) -> FanModeEnum {
        let sequence = H::FAN_MODE_SEQUENCE;

        // Below the top, an index is only ever reached by a sequence that has
        // the mode: 2 needs `Medium`, 1 needs `Low`.
        if index >= sequence_speed_modes(sequence) {
            FanModeEnum::High
        } else if index == 2 {
            FanModeEnum::Medium
        } else {
            FanModeEnum::Low
        }
    }

    /// Put the fan in the restored settings, at power up.
    ///
    /// The device is told even when the settings equal the initial ones:
    /// they were restored from the store and say nothing about the state the
    /// hardware powered up in. A fan that refuses the restored speed is
    /// switched off instead, that being the one setting every fan can take.
    fn startup_device(&self, notifier: &impl AttrChangeNotifier) {
        let attrs = self.state().attrs;

        if self
            .hooks
            .set_fan(Self::fan_setting(attrs.setting))
            .is_err()
        {
            warn!(
                "FanControl: the device refused the restored setting {:?}; switching off",
                attrs.setting
            );

            self.adopt(notifier, Some(0));

            if self.hooks.set_fan(FanSetting::Off).is_err() {
                error!("FanControl: the device refused to switch off at startup");
            }
        }

        if Self::has(Feature::ROCKING) {
            let taken = self.hooks.set_rock_setting(attrs.rock_setting) & H::ROCK_SUPPORT;

            self.adopt_rock_setting(notifier, taken);
        }

        if Self::has(Feature::WIND) {
            let taken = self.hooks.set_wind_setting(attrs.wind_setting) & H::WIND_SUPPORT;

            self.adopt_wind_setting(notifier, taken);
        }

        if Self::has(Feature::AIRFLOW_DIRECTION) {
            self.hooks.set_airflow_direction(attrs.airflow_direction);
        }

        self.observe_current(notifier);
    }

    /// Reset the settings to their initial values, drop any pending save and
    /// remove the persisted ones. The fan keeps running as it is until the
    /// next write.
    fn factory_reset(&self, ctx: &impl HandlerContext) -> Result<(), Error> {
        self.persist.clear();
        self.state.lock(|cell| {
            let mut state = cell.get();
            state.attrs = PersistedAttrs::new::<H>();
            cell.set(state);
        });

        ctx.notify_cluster_changed(self.endpoint_id, H::CLUSTER.id);

        Persist::new(ctx.kv()).remove(self.kv_key)
    }

    /// Take a change the device made on its own into the attributes.
    fn out_of_band_message(&self, notifier: &impl AttrChangeNotifier, message: OutOfBandMessage) {
        match message {
            OutOfBandMessage::CurrentSpeed => self.observe_current(notifier),
            OutOfBandMessage::FanMode(mode) => {
                let mode = match mode {
                    FanModeEnum::On => FanModeEnum::High,
                    FanModeEnum::Smart if Self::supports_mode(FanModeEnum::Auto) => {
                        FanModeEnum::Auto
                    }
                    FanModeEnum::Smart => FanModeEnum::High,
                    mode => mode,
                };

                if !Self::supports_mode(mode) {
                    warn!(
                        "FanControl: ignoring unsupported FanMode {:?} from the device",
                        mode
                    );
                    return;
                }

                if self.fan_mode() != mode {
                    let setting = match mode {
                        FanModeEnum::Auto => None,
                        mode => percent_of_mode(H::FAN_MODE_SEQUENCE, mode),
                    };

                    self.adopt(notifier, setting);
                }

                self.observe_current(notifier);
            }
            OutOfBandMessage::PercentSetting(percent) => {
                if percent > 100 {
                    warn!(
                        "FanControl: ignoring PercentSetting {} from the device",
                        percent
                    );
                    return;
                }

                self.adopt(notifier, Some(percent));
                self.observe_current(notifier);
            }
            OutOfBandMessage::SpeedSetting(speed) => {
                if speed > H::SPEED_MAX {
                    warn!(
                        "FanControl: ignoring SpeedSetting {} from the device",
                        speed
                    );
                    return;
                }

                if self.speed_setting() != Some(speed) {
                    self.adopt(notifier, Some(percent_of_speed(H::SPEED_MAX, speed)));
                }

                self.observe_current(notifier);
            }
            OutOfBandMessage::RockSetting(setting) => {
                if !H::ROCK_SUPPORT.contains(setting) {
                    warn!(
                        "FanControl: ignoring RockSetting {:?} from the device",
                        setting
                    );
                    return;
                }

                self.adopt_rock_setting(notifier, setting);
            }
            OutOfBandMessage::WindSetting(setting) => {
                if !H::WIND_SUPPORT.contains(setting) {
                    warn!(
                        "FanControl: ignoring WindSetting {:?} from the device",
                        setting
                    );
                    return;
                }

                self.adopt_wind_setting(notifier, setting);
            }
            OutOfBandMessage::AirflowDirection(direction) => {
                self.adopt_airflow_direction(notifier, direction);
            }
        }
    }

    /// Check the handler configuration.
    ///
    /// # Panics
    /// Panics with a describing message if the handler is misconfigured.
    fn validate(&self) {
        let attr = |id: AttributeId| H::CLUSTER.attribute(id as _).is_some();

        for id in [
            AttributeId::FanMode,
            AttributeId::FanModeSequence,
            AttributeId::PercentSetting,
            AttributeId::PercentCurrent,
        ] {
            if !attr(id) {
                panic!(
                    "FanControl validation: missing required attribute: {:?}",
                    id
                );
            }
        }

        // Each feature and the attributes it adds travel together, in both
        // directions.
        let feature_attrs: [(Feature, &str, &[AttributeId]); 4] = [
            (
                Feature::MULTI_SPEED,
                "MULTI_SPEED",
                &[
                    AttributeId::SpeedMax,
                    AttributeId::SpeedSetting,
                    AttributeId::SpeedCurrent,
                ],
            ),
            (
                Feature::ROCKING,
                "ROCKING",
                &[AttributeId::RockSupport, AttributeId::RockSetting],
            ),
            (
                Feature::WIND,
                "WIND",
                &[AttributeId::WindSupport, AttributeId::WindSetting],
            ),
            (
                Feature::AIRFLOW_DIRECTION,
                "AIRFLOW_DIRECTION",
                &[AttributeId::AirflowDirection],
            ),
        ];

        for (feature, name, attrs) in feature_attrs {
            for id in attrs {
                if Self::has(feature) && !attr(*id) {
                    panic!(
                        "FanControl validation: missing attribute required by the {} feature: {:?}",
                        name, id
                    );
                }

                if !Self::has(feature) && attr(*id) {
                    panic!(
                        "FanControl validation: the {:?} attribute requires the {} feature",
                        id, name
                    );
                }
            }
        }

        let step = H::CLUSTER.command(CommandId::Step as _).is_some();

        if Self::has(Feature::STEP) && !step {
            panic!("FanControl validation: missing command required by the STEP feature: Step");
        }

        if !Self::has(Feature::STEP) && step {
            panic!("FanControl validation: the Step command requires the STEP feature");
        }

        let sequence = H::FAN_MODE_SEQUENCE;

        if Self::has(Feature::AUTO) != sequence_has_auto(sequence) {
            panic!(
                "FanControl validation: FanModeSequence {:?} and the AUTO feature disagree",
                sequence
            );
        }

        if Self::has(Feature::MULTI_SPEED) {
            if H::SPEED_MAX == 0 || H::SPEED_MAX > 100 {
                panic!(
                    "FanControl validation: SPEED_MAX must be 1..=100, got {}",
                    H::SPEED_MAX
                );
            }

            if H::SPEED_MAX < sequence_speed_modes(sequence) {
                panic!(
                    "FanControl validation: SPEED_MAX {} is less than the {} speed modes in FanModeSequence {:?}",
                    H::SPEED_MAX,
                    sequence_speed_modes(sequence),
                    sequence
                );
            }
        }

        if Self::has(Feature::ROCKING) {
            if H::ROCK_SUPPORT.is_empty() {
                panic!("FanControl validation: ROCK_SUPPORT must have at least one bit set");
            }

            if !H::ROCK_SUPPORT.contains(H::ROCK_SETTING) {
                panic!(
                    "FanControl validation: ROCK_SETTING {:?} is not within ROCK_SUPPORT {:?}",
                    H::ROCK_SETTING,
                    H::ROCK_SUPPORT
                );
            }
        }

        if Self::has(Feature::WIND) {
            if H::WIND_SUPPORT.is_empty() {
                panic!("FanControl validation: WIND_SUPPORT must have at least one bit set");
            }

            if !H::WIND_SUPPORT.contains(H::WIND_SETTING) {
                panic!(
                    "FanControl validation: WIND_SETTING {:?} is not within WIND_SUPPORT {:?}",
                    H::WIND_SETTING,
                    H::WIND_SUPPORT
                );
            }
        }

        match H::PERCENT_SETTING {
            Some(percent) if percent > 100 => {
                panic!(
                    "FanControl validation: PERCENT_SETTING must be at most 100, got {}",
                    percent
                );
            }
            None if !Self::has(Feature::AUTO) => {
                panic!("FanControl validation: a null PERCENT_SETTING requires the AUTO feature");
            }
            _ => {}
        }
    }
}

impl<H> ClusterHandler for FanControlHandler<H>
where
    H: FanControlHooks,
{
    const CLUSTER: Cluster<'static> = H::CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        match op {
            LifecycleOp::Startup => {
                self.validate();
                self.load_persisted(ctx.kv())?;
                self.startup_device(&ctx);

                ctx.notify_cluster_changed(self.endpoint_id, H::CLUSTER.id);

                Ok(())
            }
            LifecycleOp::FactoryReset => self.factory_reset(&ctx),
            LifecycleOp::FabricRemoval { .. } => Ok(()),
        }
    }

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        let persist = self
            .persist
            .run(H::PERSIST_DELAY_MS, || self.save(ctx.kv()));

        let hooks = self
            .hooks
            .run(|message| self.out_of_band_message(&ctx, message));

        match select(persist, hooks).await {
            Either::First(()) => unreachable!(),
            Either::Second(()) => panic!("FanControlHooks::run returned; implementers MUST not return. Implementations should loop forever or await core::future::pending::<()>()."),
        }
    }

    fn fan_mode(&self, _ctx: impl ReadContext) -> Result<FanModeEnum, Error> {
        Ok(FanControlHandler::fan_mode(self))
    }

    fn fan_mode_sequence(&self, _ctx: impl ReadContext) -> Result<FanModeSequenceEnum, Error> {
        Ok(H::FAN_MODE_SEQUENCE)
    }

    fn percent_setting(&self, _ctx: impl ReadContext) -> Result<Nullable<Percent>, Error> {
        Ok(Nullable::new(FanControlHandler::percent_setting(self)))
    }

    fn percent_current(&self, _ctx: impl ReadContext) -> Result<Percent, Error> {
        Ok(FanControlHandler::percent_current(self))
    }

    fn speed_max(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(H::SPEED_MAX)
    }

    fn speed_setting(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        Ok(Nullable::new(FanControlHandler::speed_setting(self)))
    }

    fn speed_current(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(FanControlHandler::speed_current(self))
    }

    fn rock_support(&self, _ctx: impl ReadContext) -> Result<RockBitmap, Error> {
        Ok(H::ROCK_SUPPORT)
    }

    fn rock_setting(&self, _ctx: impl ReadContext) -> Result<RockBitmap, Error> {
        Ok(FanControlHandler::rock_setting(self))
    }

    fn wind_support(&self, _ctx: impl ReadContext) -> Result<WindBitmap, Error> {
        Ok(H::WIND_SUPPORT)
    }

    fn wind_setting(&self, _ctx: impl ReadContext) -> Result<WindBitmap, Error> {
        Ok(FanControlHandler::wind_setting(self))
    }

    fn airflow_direction(&self, _ctx: impl ReadContext) -> Result<AirflowDirectionEnum, Error> {
        Ok(FanControlHandler::airflow_direction(self))
    }

    fn set_fan_mode(&self, ctx: impl WriteContext, value: FanModeEnum) -> Result<(), Error> {
        self.write_fan_mode(&ctx, value)
    }

    fn set_percent_setting(
        &self,
        ctx: impl WriteContext,
        value: Nullable<Percent>,
    ) -> Result<(), Error> {
        self.write_percent_setting(&ctx, value)
    }

    fn set_speed_setting(&self, ctx: impl WriteContext, value: Nullable<u8>) -> Result<(), Error> {
        self.write_speed_setting(&ctx, value)
    }

    fn set_rock_setting(&self, ctx: impl WriteContext, value: RockBitmap) -> Result<(), Error> {
        self.write_rock_setting(&ctx, value)
    }

    fn set_wind_setting(&self, ctx: impl WriteContext, value: WindBitmap) -> Result<(), Error> {
        self.write_wind_setting(&ctx, value)
    }

    fn set_airflow_direction(
        &self,
        ctx: impl WriteContext,
        value: AirflowDirectionEnum,
    ) -> Result<(), Error> {
        self.write_airflow_direction(&ctx, value)
    }

    fn handle_step(&self, ctx: impl InvokeContext, request: StepRequest<'_>) -> Result<(), Error> {
        let direction = request.direction()?;
        // The spec's fallbacks: no wrap, and Off counts as a step.
        let wrap = request.wrap()?.unwrap_or(false);
        let lowest_off = request.lowest_off()?.unwrap_or(true);

        self.step(&ctx, direction, wrap, lowest_off)
    }
}

pub mod test {
    //! A simulated fan, for tests that need a whole one rather than a mock:
    //! ten discrete speeds, every feature, and a setting that is reached the
    //! moment it is asked for.

    use core::cell::Cell;

    use crate::dm::Cluster;
    use crate::utils::sync::blocking::Mutex;
    use crate::with;

    use super::{
        AirflowDirectionEnum, AttributeId, CommandId, CurrentSpeed, FanControlHooks,
        FanModeSequenceEnum, FanSetting, Feature, RockBitmap, WindBitmap, FULL_CLUSTER,
    };

    /// The speed the simulated fan picks under `Auto`.
    pub const AUTO_SPEED: u8 = 5;

    /// A ten-speed fan with rocking, wind emulation, a reversible airflow and
    /// the `Step` command - everything the cluster can do.
    ///
    /// It rocks left-right or up-down but not both at once, and only has the
    /// natural wind, so both "unsupported" paths of the settings are
    /// exercised somewhere.
    pub struct TestFanDeviceLogic {
        state: Mutex<Cell<TestFanState>>,
    }

    /// The simulated fan's state, behind one lock.
    #[derive(Clone, Copy)]
    struct TestFanState {
        setting: FanSetting,
        /// The speed the blades turn at. Follows `setting` at once, unless
        /// the test pins it to simulate a fan in transition.
        speed: u8,
        /// Whether the next `set_fan` is refused, to simulate a fan that
        /// cannot switch right now.
        refuse: bool,
        rock: RockBitmap,
        wind: WindBitmap,
        direction: AirflowDirectionEnum,
    }

    impl TestFanDeviceLogic {
        /// Stopped, not rocking, blowing forward.
        pub const fn new() -> Self {
            Self {
                state: Mutex::new(Cell::new(TestFanState {
                    setting: FanSetting::Off,
                    speed: 0,
                    refuse: false,
                    rock: RockBitmap::empty(),
                    wind: WindBitmap::empty(),
                    direction: AirflowDirectionEnum::Forward,
                })),
            }
        }

        /// The setting the fan was last given.
        pub fn setting(&self) -> FanSetting {
            self.state.lock(|state| state.get().setting)
        }

        /// The speed the blades turn at.
        pub fn speed(&self) -> u8 {
            self.state.lock(|state| state.get().speed)
        }

        /// Pin the speed the blades turn at, as a fan that has not yet
        /// reached its setting would report.
        pub fn set_speed(&self, speed: u8) {
            self.update(|state| state.speed = speed);
        }

        /// Refuse (or stop refusing) the next settings.
        pub fn refuse(&self, refuse: bool) {
            self.update(|state| state.refuse = refuse);
        }

        /// The rocking motion in effect.
        pub fn rock(&self) -> RockBitmap {
            self.state.lock(|state| state.get().rock)
        }

        /// The wind emulation in effect.
        pub fn wind(&self) -> WindBitmap {
            self.state.lock(|state| state.get().wind)
        }

        /// The airflow direction in effect.
        pub fn direction(&self) -> AirflowDirectionEnum {
            self.state.lock(|state| state.get().direction)
        }

        fn update(&self, f: impl FnOnce(&mut TestFanState)) {
            self.state.lock(|cell| {
                let mut state = cell.get();
                f(&mut state);
                cell.set(state);
            });
        }
    }

    impl Default for TestFanDeviceLogic {
        fn default() -> Self {
            Self::new()
        }
    }

    impl FanControlHooks for TestFanDeviceLogic {
        const CLUSTER: Cluster<'static> = FULL_CLUSTER
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
                AttributeId::SpeedMax
                    | AttributeId::SpeedSetting
                    | AttributeId::SpeedCurrent
                    | AttributeId::RockSupport
                    | AttributeId::RockSetting
                    | AttributeId::WindSupport
                    | AttributeId::WindSetting
                    | AttributeId::AirflowDirection
            ))
            .with_cmds(with!(CommandId::Step));

        const FAN_MODE_SEQUENCE: FanModeSequenceEnum = FanModeSequenceEnum::OffLowMedHighAuto;
        const SPEED_MAX: u8 = 10;
        const ROCK_SUPPORT: RockBitmap =
            RockBitmap::ROCK_LEFT_RIGHT.union(RockBitmap::ROCK_UP_DOWN);
        const WIND_SUPPORT: WindBitmap = WindBitmap::NATURAL_WIND;

        // Tests restart the device right after a change, so persist at once.
        const PERSIST_DELAY_MS: u32 = 0;

        fn set_fan(&self, setting: FanSetting) -> Result<(), ()> {
            if self.state.lock(|state| state.get().refuse) {
                return Err(());
            }

            self.update(|state| {
                state.setting = setting;
                state.speed = match setting {
                    FanSetting::Off => 0,
                    FanSetting::Auto => AUTO_SPEED,
                    FanSetting::Manual { speed, .. } => speed,
                };
            });

            Ok(())
        }

        fn current_speed(&self) -> CurrentSpeed {
            CurrentSpeed::Speed(self.speed())
        }

        /// One motion at a time: a combination is reduced to its lowest bit.
        fn set_rock_setting(&self, setting: RockBitmap) -> RockBitmap {
            let taken = if setting.bits().count_ones() > 1 {
                RockBitmap::from_bits_truncate(1 << setting.bits().trailing_zeros())
            } else {
                setting
            };

            self.update(|state| state.rock = taken);

            taken
        }

        fn set_wind_setting(&self, setting: WindBitmap) -> WindBitmap {
            self.update(|state| state.wind = setting);

            setting
        }

        fn set_airflow_direction(&self, direction: AirflowDirectionEnum) {
            self.update(|state| state.direction = direction);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the rules [`FanControlHandler`] enforces.
    //!
    //! They drive the context-free helpers the `ClusterHandler` methods
    //! delegate to, rather than the methods themselves: a `ReadContext` /
    //! `WriteContext` can only be built around a live `Matter` instance,
    //! whereas the helpers need nothing but an [`AttrChangeNotifier`] - and
    //! `()` is a no-op one.

    use core::cell::Cell;

    use crate::dm::clusters::app::test_util::RecordingNotifier;
    use crate::dm::{AttrId, Cluster, Dataver};
    use crate::error::{Error, ErrorCode};
    use crate::fabric::tests::MemKvBlobStore;
    use crate::persist::SharedKvBlobStore;
    use crate::tlv::Nullable;
    use crate::utils::sync::blocking::Mutex;
    use crate::with;

    use super::*;

    /// `()` is a no-op `AttrChangeNotifier`, which is all the helpers need.
    const NULL_CTX: &() = &();

    /// The KV key the tested handlers persist under.
    const KV_KEY: u16 = crate::persist::VENDOR_KEYS_START;

    /// Every feature.
    const ALL: u32 = Feature::MULTI_SPEED.bits()
        | Feature::AUTO.bits()
        | Feature::ROCKING.bits()
        | Feature::WIND.bits()
        | Feature::STEP.bits()
        | Feature::AIRFLOW_DIRECTION.bits();

    /// The sequence for a given feature set, as a `const` parameter can only
    /// be an integer.
    const fn sequence(features: u32, low: bool, medium: bool) -> FanModeSequenceEnum {
        let auto = features & Feature::AUTO.bits() != 0;

        match (low, medium, auto) {
            (true, true, false) => FanModeSequenceEnum::OffLowMedHigh,
            (true, false, false) => FanModeSequenceEnum::OffLowHigh,
            (true, true, true) => FanModeSequenceEnum::OffLowMedHighAuto,
            (true, false, true) => FanModeSequenceEnum::OffLowHighAuto,
            (false, _, true) => FanModeSequenceEnum::OffHighAuto,
            (false, _, false) => FanModeSequenceEnum::OffHigh,
        }
    }

    /// Hooks whose feature map, sequence and `SpeedMax` are const parameters,
    /// so each test can pick its own cluster configuration.
    ///
    /// Records what the device was told, and reports what a test says the
    /// blades are doing.
    struct MockHooks<const F: u32, const LOW: bool, const MEDIUM: bool, const M: u8> {
        state: Mutex<Cell<MockState>>,
    }

    #[derive(Clone, Copy)]
    struct MockState {
        /// The last `set_fan`, and how many there were.
        setting: Option<FanSetting>,
        set_fan_calls: usize,
        refuse: bool,
        current: CurrentSpeed,
        rock: Option<RockBitmap>,
        wind: Option<WindBitmap>,
        direction: Option<AirflowDirectionEnum>,
    }

    impl<const F: u32, const LOW: bool, const MEDIUM: bool, const M: u8> MockHooks<F, LOW, MEDIUM, M> {
        const fn new() -> Self {
            Self {
                state: Mutex::new(Cell::new(MockState {
                    setting: None,
                    set_fan_calls: 0,
                    refuse: false,
                    current: CurrentSpeed::Speed(0),
                    rock: None,
                    wind: None,
                    direction: None,
                })),
            }
        }

        fn get(&self) -> MockState {
            self.state.lock(|state| state.get())
        }

        fn update(&self, f: impl FnOnce(&mut MockState)) {
            self.state.lock(|cell| {
                let mut state = cell.get();
                f(&mut state);
                cell.set(state);
            });
        }

        fn set_current(&self, current: CurrentSpeed) {
            self.update(|state| state.current = current);
        }
    }

    impl<const F: u32, const LOW: bool, const MEDIUM: bool, const M: u8> FanControlHooks
        for MockHooks<F, LOW, MEDIUM, M>
    {
        const CLUSTER: Cluster<'static> = FULL_CLUSTER
            .with_features(F)
            .with_attrs(with!(
                required;
                AttributeId::SpeedMax
                    | AttributeId::SpeedSetting
                    | AttributeId::SpeedCurrent
                    | AttributeId::RockSupport
                    | AttributeId::RockSetting
                    | AttributeId::WindSupport
                    | AttributeId::WindSetting
                    | AttributeId::AirflowDirection
            ))
            .with_cmds(with!(CommandId::Step));

        const FAN_MODE_SEQUENCE: FanModeSequenceEnum = sequence(F, LOW, MEDIUM);
        const SPEED_MAX: u8 = M;
        const ROCK_SUPPORT: RockBitmap =
            RockBitmap::ROCK_LEFT_RIGHT.union(RockBitmap::ROCK_UP_DOWN);
        const WIND_SUPPORT: WindBitmap = WindBitmap::NATURAL_WIND;

        fn set_fan(&self, setting: FanSetting) -> Result<(), ()> {
            if self.get().refuse {
                return Err(());
            }

            self.update(|state| {
                state.setting = Some(setting);
                state.set_fan_calls += 1;
            });

            Ok(())
        }

        fn current_speed(&self) -> CurrentSpeed {
            self.get().current
        }

        /// Rocks one way at a time: a combination is reduced to its lowest
        /// bit.
        fn set_rock_setting(&self, setting: RockBitmap) -> RockBitmap {
            let taken = if setting.bits().count_ones() > 1 {
                RockBitmap::from_bits_truncate(1 << setting.bits().trailing_zeros())
            } else {
                setting
            };

            self.update(|state| state.rock = Some(taken));

            taken
        }

        fn set_wind_setting(&self, setting: WindBitmap) -> WindBitmap {
            self.update(|state| state.wind = Some(setting));

            setting
        }

        fn set_airflow_direction(&self, direction: AirflowDirectionEnum) {
            self.update(|state| state.direction = Some(direction));
        }
    }

    /// A three-speed fan with everything: `OffLowMedHighAuto`, `SpeedMax` 3.
    type ThreeSpeed = MockHooks<ALL, true, true, 3>;
    type ThreeSpeedHandler = FanControlHandler<ThreeSpeed>;

    /// A fan without `MultiSpeed` (and without `STEP` attributes to check):
    /// `OffLowHigh`, driven by its modes alone.
    const NO_SPEED: u32 = Feature::STEP.bits();
    type TwoMode = MockHooks<NO_SPEED, true, false, 1>;
    type TwoModeHandler = FanControlHandler<TwoMode>;

    fn three_speed() -> ThreeSpeedHandler {
        FanControlHandler::new(Dataver::new(0), 1, KV_KEY, ThreeSpeed::new())
    }

    fn two_mode() -> TwoModeHandler {
        FanControlHandler::new(Dataver::new(0), 1, KV_KEY, TwoMode::new())
    }

    fn code(result: Result<(), Error>) -> Result<(), ErrorCode> {
        result.map_err(|e| e.code())
    }

    /// `(FanMode, PercentSetting, SpeedSetting)` as a client would read them.
    fn setting<H: FanControlHooks>(
        handler: &FanControlHandler<H>,
    ) -> (FanModeEnum, Option<Percent>, Option<u8>) {
        (
            handler.fan_mode(),
            handler.percent_setting(),
            handler.speed_setting(),
        )
    }

    // The mapping rules

    #[test]
    fn percent_ranges_follow_the_sequence() {
        use FanModeEnum::*;
        use FanModeSequenceEnum::*;

        for sequence in [OffLowMedHigh, OffLowMedHighAuto] {
            assert_eq!(mode_of_percent(sequence, 0), Off);
            assert_eq!(mode_of_percent(sequence, 1), Low);
            assert_eq!(mode_of_percent(sequence, 33), Low);
            assert_eq!(mode_of_percent(sequence, 34), Medium);
            assert_eq!(mode_of_percent(sequence, 66), Medium);
            assert_eq!(mode_of_percent(sequence, 67), High);
            assert_eq!(mode_of_percent(sequence, 100), High);
        }

        for sequence in [OffLowHigh, OffLowHighAuto] {
            assert_eq!(mode_of_percent(sequence, 1), Low);
            assert_eq!(mode_of_percent(sequence, 50), Low);
            assert_eq!(mode_of_percent(sequence, 51), High);
        }

        for sequence in [OffHigh, OffHighAuto] {
            assert_eq!(mode_of_percent(sequence, 0), Off);
            assert_eq!(mode_of_percent(sequence, 1), High);
            assert_eq!(mode_of_percent(sequence, 100), High);
        }
    }

    #[test]
    fn a_mode_maps_to_the_top_of_its_own_range() {
        use FanModeEnum::*;
        use FanModeSequenceEnum::*;

        for sequence in [
            OffLowMedHigh,
            OffLowHigh,
            OffLowMedHighAuto,
            OffLowHighAuto,
            OffHighAuto,
            OffHigh,
        ] {
            for mode in [Off, Low, Medium, High] {
                if !sequence_supports(sequence, mode) {
                    assert_eq!(percent_of_mode(sequence, mode), None, "{sequence:?}");
                    continue;
                }

                let percent = percent_of_mode(sequence, mode).unwrap();

                assert_eq!(mode_of_percent(sequence, percent), mode, "{sequence:?}");
                assert!(
                    percent == 100 || mode_of_percent(sequence, percent + 1) != mode,
                    "{sequence:?} {mode:?}: {percent} is not the top of its range"
                );
            }

            assert_eq!(percent_of_mode(sequence, Auto), None);
            assert_eq!(percent_of_mode(sequence, On), None);
            assert_eq!(percent_of_mode(sequence, Smart), None);
        }
    }

    #[test]
    fn speed_and_percent_round_trip_for_every_speed_max() {
        // `floor` on the way out and `ceil` on the way back are exact
        // inverses up to `SpeedMax` 100, which is what lets a written
        // `SpeedSetting` read back unchanged.
        for max in 1..=100u8 {
            for speed in 0..=max {
                let percent = percent_of_speed(max, speed);

                assert!(percent <= 100);
                assert_eq!(speed_of_percent(max, percent), speed, "max {max}");
            }

            // And any percentage above zero engages at least the first speed.
            for percent in 1..=100u8 {
                let speed = speed_of_percent(max, percent);

                assert!((1..=max).contains(&speed), "max {max} percent {percent}");
            }
        }
    }

    // The write cascade

    #[test]
    fn a_percent_write_sets_the_mode_and_the_speed() {
        let handler = three_speed();

        handler
            .write_percent_setting(NULL_CTX, Nullable::some(64))
            .unwrap();

        assert_eq!(setting(&handler), (FanModeEnum::Medium, Some(64), Some(2)));
        assert_eq!(
            handler.hooks().get().setting,
            Some(FanSetting::Manual {
                mode: FanModeEnum::Medium,
                percent: 64,
                speed: 2
            })
        );

        // Kept exactly as written, never requantised to the speed's 66.
        for percent in 1..=100u8 {
            handler
                .write_percent_setting(NULL_CTX, Nullable::some(percent))
                .unwrap();

            assert_eq!(handler.percent_setting(), Some(percent));
        }
    }

    #[test]
    fn a_speed_write_sets_the_percent_and_the_mode() {
        let handler = three_speed();

        for (speed, percent, mode) in [
            (1, 33, FanModeEnum::Low),
            (2, 66, FanModeEnum::Medium),
            (3, 100, FanModeEnum::High),
            (0, 0, FanModeEnum::Off),
        ] {
            handler
                .write_speed_setting(NULL_CTX, Nullable::some(speed))
                .unwrap();

            assert_eq!(setting(&handler), (mode, Some(percent), Some(speed)));
        }

        assert_eq!(
            code(handler.write_speed_setting(NULL_CTX, Nullable::some(4))),
            Err(ErrorCode::ConstraintError)
        );
    }

    #[test]
    fn a_mode_write_sets_the_percent_and_the_speed() {
        let handler = three_speed();

        for (mode, percent, speed) in [
            (FanModeEnum::Low, 33, 1),
            (FanModeEnum::Medium, 66, 2),
            (FanModeEnum::High, 100, 3),
            (FanModeEnum::Off, 0, 0),
        ] {
            handler.write_fan_mode(NULL_CTX, mode).unwrap();

            assert_eq!(setting(&handler), (mode, Some(percent), Some(speed)));
        }

        handler.write_fan_mode(NULL_CTX, FanModeEnum::Auto).unwrap();
        assert_eq!(setting(&handler), (FanModeEnum::Auto, None, None));
        assert_eq!(handler.hooks().get().setting, Some(FanSetting::Auto));
    }

    #[test]
    fn a_mode_the_fan_is_already_in_leaves_the_percent_alone() {
        let handler = three_speed();

        handler
            .write_percent_setting(NULL_CTX, Nullable::some(40))
            .unwrap();
        let calls = handler.hooks().get().set_fan_calls;

        // 40 is Medium; asking for Medium again is not a change.
        handler
            .write_fan_mode(NULL_CTX, FanModeEnum::Medium)
            .unwrap();

        assert_eq!(handler.percent_setting(), Some(40));
        assert_eq!(handler.hooks().get().set_fan_calls, calls);
    }

    #[test]
    fn the_deprecated_modes_are_translated() {
        let handler = three_speed();

        handler.write_fan_mode(NULL_CTX, FanModeEnum::On).unwrap();
        assert_eq!(handler.fan_mode(), FanModeEnum::High);

        handler
            .write_fan_mode(NULL_CTX, FanModeEnum::Smart)
            .unwrap();
        assert_eq!(handler.fan_mode(), FanModeEnum::Auto);

        // Without AUTO, Smart is High.
        let handler = two_mode();

        handler
            .write_fan_mode(NULL_CTX, FanModeEnum::Smart)
            .unwrap();
        assert_eq!(handler.fan_mode(), FanModeEnum::High);
    }

    #[test]
    fn a_mode_outside_the_sequence_is_a_constraint_error() {
        let handler = two_mode();

        assert_eq!(
            code(handler.write_fan_mode(NULL_CTX, FanModeEnum::Medium)),
            Err(ErrorCode::ConstraintError)
        );
        assert_eq!(
            code(handler.write_fan_mode(NULL_CTX, FanModeEnum::Auto)),
            Err(ErrorCode::ConstraintError)
        );

        // Low's range is the lower half here, and Low is where 50% lands.
        handler.write_fan_mode(NULL_CTX, FanModeEnum::Low).unwrap();
        assert_eq!(handler.percent_setting(), Some(50));
        assert_eq!(handler.fan_mode(), FanModeEnum::Low);

        assert_eq!(
            code(handler.write_percent_setting(NULL_CTX, Nullable::some(101))),
            Err(ErrorCode::ConstraintError)
        );
    }

    #[test]
    fn a_null_write_is_invalid_in_state_unless_the_fan_is_in_auto() {
        let handler = three_speed();

        handler
            .write_percent_setting(NULL_CTX, Nullable::some(50))
            .unwrap();

        assert_eq!(
            code(handler.write_percent_setting(NULL_CTX, Nullable::none())),
            Err(ErrorCode::InvalidInState)
        );
        assert_eq!(
            code(handler.write_speed_setting(NULL_CTX, Nullable::none())),
            Err(ErrorCode::InvalidInState)
        );
        assert_eq!(handler.percent_setting(), Some(50));

        handler.write_fan_mode(NULL_CTX, FanModeEnum::Auto).unwrap();

        handler
            .write_percent_setting(NULL_CTX, Nullable::none())
            .unwrap();
        handler
            .write_speed_setting(NULL_CTX, Nullable::none())
            .unwrap();
        assert_eq!(handler.percent_setting(), None);
    }

    #[test]
    fn a_refused_setting_is_invalid_in_state_and_changes_nothing() {
        let handler = three_speed();

        handler
            .write_percent_setting(NULL_CTX, Nullable::some(50))
            .unwrap();

        handler.hooks().update(|state| state.refuse = true);

        assert_eq!(
            code(handler.write_percent_setting(NULL_CTX, Nullable::some(80))),
            Err(ErrorCode::InvalidInState)
        );
        assert_eq!(
            code(handler.write_fan_mode(NULL_CTX, FanModeEnum::Off)),
            Err(ErrorCode::InvalidInState)
        );

        assert_eq!(setting(&handler), (FanModeEnum::Medium, Some(50), Some(2)));
    }

    #[test]
    fn a_write_reports_only_what_moved() {
        let handler = three_speed();
        let notifier = RecordingNotifier::default();

        // Off -> 64%: everything moves, and the fan reaches it at once.
        handler.hooks().set_current(CurrentSpeed::Speed(2));
        handler
            .write_percent_setting(&notifier, Nullable::some(64))
            .unwrap();

        assert_eq!(
            notifier.attrs(),
            [
                AttributeId::FanMode as AttrId,
                AttributeId::PercentSetting as AttrId,
                AttributeId::SpeedSetting as AttrId,
                AttributeId::PercentCurrent as AttrId,
                AttributeId::SpeedCurrent as AttrId,
            ]
        );

        // 64% -> 50%: the same mode and speed; only the percentages move.
        handler
            .write_percent_setting(&notifier, Nullable::some(50))
            .unwrap();

        assert_eq!(
            notifier.attrs(),
            [
                AttributeId::PercentSetting as AttrId,
                AttributeId::PercentCurrent as AttrId,
            ]
        );
    }

    // What the fan reports

    #[test]
    fn a_variable_fan_reports_its_percentage_verbatim() {
        let handler = three_speed();

        handler
            .write_percent_setting(NULL_CTX, Nullable::some(64))
            .unwrap();

        handler.hooks().set_current(CurrentSpeed::Percent(40));

        assert_eq!(handler.percent_current(), 40);
        assert_eq!(handler.speed_current(), 2);
    }

    #[test]
    fn a_discrete_fan_settled_at_its_setting_reports_the_setting() {
        // The setting is what the fan delivers once it reaches the speed the
        // setting maps to: 64%, not the speed's nominal 66%.
        let handler = three_speed();

        handler
            .write_percent_setting(NULL_CTX, Nullable::some(64))
            .unwrap();
        handler.hooks().set_current(CurrentSpeed::Speed(2));

        assert_eq!(handler.percent_current(), 64);
        assert_eq!(handler.speed_current(), 2);

        // Running slower than asked - a transition, or a knob on the unit -
        // and nothing known about that speed: its nominal percentage.
        handler.hooks().set_current(CurrentSpeed::Speed(1));

        assert_eq!(handler.percent_current(), 33);
        assert_eq!(handler.speed_current(), 1);
    }

    #[test]
    fn asking_for_a_lower_percentage_never_reports_the_fan_speeding_up() {
        // Settled at 87% (speed 3), a client asks for 64% (speed 2). Until
        // the fan slows down it is still delivering 87%, and reporting the
        // speed's nominal 100% would show it speeding *up* in answer to a
        // request to slow down - which an ecosystem drawing its slider from
        // `PercentCurrent` then writes back.
        let handler = three_speed();

        handler
            .write_percent_setting(NULL_CTX, Nullable::some(87))
            .unwrap();
        handler.hooks().set_current(CurrentSpeed::Speed(3));
        handler.observe_current(NULL_CTX);
        assert_eq!(handler.percent_current(), 87);

        handler
            .write_percent_setting(NULL_CTX, Nullable::some(64))
            .unwrap();
        assert_eq!(handler.percent_current(), 87, "still delivering 87%");
        assert_eq!(handler.speed_current(), 3);

        handler.hooks().set_current(CurrentSpeed::Speed(2));
        handler.observe_current(NULL_CTX);
        assert_eq!(handler.percent_current(), 64);
        assert_eq!(handler.speed_current(), 2);
    }

    #[test]
    fn a_relay_fan_reports_by_mode() {
        let handler = two_mode();

        handler
            .write_percent_setting(NULL_CTX, Nullable::some(40))
            .unwrap();
        handler
            .hooks()
            .set_current(CurrentSpeed::Mode(FanModeEnum::Low));
        assert_eq!(handler.percent_current(), 40);

        // Still on the High relay from before: High's nominal percentage,
        // as nothing else was ever delivered at High.
        handler
            .hooks()
            .set_current(CurrentSpeed::Mode(FanModeEnum::High));
        assert_eq!(handler.percent_current(), 100);

        handler
            .hooks()
            .set_current(CurrentSpeed::Mode(FanModeEnum::Off));
        assert_eq!(handler.percent_current(), 0);
    }

    #[test]
    fn off_zeroes_the_current_values_at_once() {
        let handler = three_speed();

        handler
            .write_percent_setting(NULL_CTX, Nullable::some(100))
            .unwrap();
        handler.hooks().set_current(CurrentSpeed::Speed(3));
        assert_eq!(handler.percent_current(), 100);

        // The blades are still turning, but Off is Off.
        handler.write_fan_mode(NULL_CTX, FanModeEnum::Off).unwrap();

        assert_eq!(handler.percent_current(), 0);
        assert_eq!(handler.speed_current(), 0);
    }

    #[test]
    fn under_auto_the_current_values_follow_the_fan() {
        let handler = three_speed();

        handler.write_fan_mode(NULL_CTX, FanModeEnum::Auto).unwrap();
        handler.hooks().set_current(CurrentSpeed::Speed(2));

        assert_eq!(setting(&handler), (FanModeEnum::Auto, None, None));
        assert_eq!(handler.percent_current(), 66);
        assert_eq!(handler.speed_current(), 2);
    }

    #[test]
    fn a_fan_that_switched_itself_off_keeps_its_setting() {
        // What a coupled On/Off does: the blades stop, the setting stays.
        let handler = three_speed();
        let notifier = RecordingNotifier::default();

        handler
            .write_percent_setting(&notifier, Nullable::some(100))
            .unwrap();
        handler.hooks().set_current(CurrentSpeed::Speed(3));
        handler.observe_current(&notifier);
        let _ = notifier.take();

        handler.hooks().set_current(CurrentSpeed::Speed(0));
        handler.out_of_band_message(&notifier, OutOfBandMessage::CurrentSpeed);

        assert_eq!(
            notifier.attrs(),
            [
                AttributeId::PercentCurrent as AttrId,
                AttributeId::SpeedCurrent as AttrId,
            ]
        );
        assert_eq!(setting(&handler), (FanModeEnum::High, Some(100), Some(3)));
        assert_eq!(handler.percent_current(), 0);
    }

    // Out-of-band settings

    #[test]
    fn a_setting_from_the_device_is_adopted_without_driving_it() {
        let handler = three_speed();
        let notifier = RecordingNotifier::default();
        let calls = handler.hooks().get().set_fan_calls;

        handler.out_of_band_message(&notifier, OutOfBandMessage::FanMode(FanModeEnum::High));
        assert_eq!(setting(&handler), (FanModeEnum::High, Some(100), Some(3)));

        handler.out_of_band_message(&notifier, OutOfBandMessage::SpeedSetting(1));
        assert_eq!(setting(&handler), (FanModeEnum::Low, Some(33), Some(1)));

        handler.out_of_band_message(&notifier, OutOfBandMessage::PercentSetting(64));
        assert_eq!(setting(&handler), (FanModeEnum::Medium, Some(64), Some(2)));

        assert_eq!(handler.hooks().get().set_fan_calls, calls);

        // Out of range: ignored.
        handler.out_of_band_message(&notifier, OutOfBandMessage::SpeedSetting(9));
        handler.out_of_band_message(&notifier, OutOfBandMessage::PercentSetting(101));
        assert_eq!(handler.percent_setting(), Some(64));

        let handler = two_mode();
        handler.out_of_band_message(&notifier, OutOfBandMessage::FanMode(FanModeEnum::Medium));
        assert_eq!(handler.fan_mode(), FanModeEnum::Off);
    }

    // Rock, wind, direction

    #[test]
    fn rock_and_wind_settings_are_bounded_by_their_support() {
        let handler = three_speed();

        assert_eq!(
            code(handler.write_rock_setting(NULL_CTX, RockBitmap::ROCK_ROUND)),
            Err(ErrorCode::ConstraintError)
        );
        assert_eq!(
            code(handler.write_wind_setting(NULL_CTX, WindBitmap::SLEEP_WIND)),
            Err(ErrorCode::ConstraintError)
        );

        handler
            .write_rock_setting(NULL_CTX, RockBitmap::ROCK_UP_DOWN)
            .unwrap();
        assert_eq!(handler.rock_setting(), RockBitmap::ROCK_UP_DOWN);
        assert_eq!(handler.hooks().get().rock, Some(RockBitmap::ROCK_UP_DOWN));

        handler
            .write_wind_setting(NULL_CTX, WindBitmap::NATURAL_WIND)
            .unwrap();
        assert_eq!(handler.wind_setting(), WindBitmap::NATURAL_WIND);

        // A combination the device cannot do: its lowest bit alone.
        handler
            .write_rock_setting(
                NULL_CTX,
                RockBitmap::ROCK_LEFT_RIGHT | RockBitmap::ROCK_UP_DOWN,
            )
            .unwrap();
        assert_eq!(handler.rock_setting(), RockBitmap::ROCK_LEFT_RIGHT);

        handler
            .write_rock_setting(NULL_CTX, RockBitmap::empty())
            .unwrap();
        assert_eq!(handler.rock_setting(), RockBitmap::empty());
    }

    #[test]
    fn airflow_direction_is_forwarded_when_it_changes() {
        let handler = three_speed();

        handler
            .write_airflow_direction(NULL_CTX, AirflowDirectionEnum::Forward)
            .unwrap();
        assert_eq!(handler.hooks().get().direction, None, "no change");

        handler
            .write_airflow_direction(NULL_CTX, AirflowDirectionEnum::Reverse)
            .unwrap();
        assert_eq!(handler.airflow_direction(), AirflowDirectionEnum::Reverse);
        assert_eq!(
            handler.hooks().get().direction,
            Some(AirflowDirectionEnum::Reverse)
        );
    }

    // Step

    #[test]
    fn step_walks_the_speeds_of_a_multi_speed_fan() {
        use StepDirectionEnum::*;

        let handler = three_speed();

        // From 50% (speed 2): up to 3, then held at the top without wrap.
        handler
            .write_percent_setting(NULL_CTX, Nullable::some(50))
            .unwrap();
        handler.step(NULL_CTX, Increase, false, true).unwrap();
        assert_eq!(setting(&handler), (FanModeEnum::High, Some(100), Some(3)));
        handler.step(NULL_CTX, Increase, false, true).unwrap();
        assert_eq!(handler.speed_setting(), Some(3));

        // Wrapping from the top: to the lowest step, which is 1 or Off.
        handler.step(NULL_CTX, Increase, true, false).unwrap();
        assert_eq!(handler.speed_setting(), Some(1));

        handler
            .write_speed_setting(NULL_CTX, Nullable::some(3))
            .unwrap();
        handler.step(NULL_CTX, Increase, true, true).unwrap();
        assert_eq!(setting(&handler), (FanModeEnum::Off, Some(0), Some(0)));

        // Down from 1: held there without lowest-off...
        handler
            .write_speed_setting(NULL_CTX, Nullable::some(1))
            .unwrap();
        handler.step(NULL_CTX, Decrease, false, false).unwrap();
        assert_eq!(handler.speed_setting(), Some(1));
        // ...wrapped to the top with wrap...
        handler.step(NULL_CTX, Decrease, true, false).unwrap();
        assert_eq!(handler.speed_setting(), Some(3));
        // ...and to Off when Off is a step.
        handler
            .write_speed_setting(NULL_CTX, Nullable::some(1))
            .unwrap();
        handler.step(NULL_CTX, Decrease, false, true).unwrap();
        assert_eq!(handler.speed_setting(), Some(0));

        // Down from Off with Off a step: wraps to the top.
        handler.step(NULL_CTX, Decrease, true, true).unwrap();
        assert_eq!(handler.speed_setting(), Some(3));

        // Auto counts as off: up goes to the first speed.
        handler.write_fan_mode(NULL_CTX, FanModeEnum::Auto).unwrap();
        handler.step(NULL_CTX, Increase, false, true).unwrap();
        assert_eq!(setting(&handler), (FanModeEnum::Low, Some(33), Some(1)));
    }

    #[test]
    fn step_walks_the_modes_of_a_fan_without_speeds() {
        use StepDirectionEnum::*;

        let handler = two_mode();

        handler.step(NULL_CTX, Increase, false, true).unwrap();
        assert_eq!(setting(&handler), (FanModeEnum::Low, Some(50), Some(1)));

        handler.step(NULL_CTX, Increase, false, true).unwrap();
        assert_eq!(handler.fan_mode(), FanModeEnum::High);

        handler.step(NULL_CTX, Increase, false, true).unwrap();
        assert_eq!(handler.fan_mode(), FanModeEnum::High);

        handler.step(NULL_CTX, Decrease, false, true).unwrap();
        assert_eq!(handler.fan_mode(), FanModeEnum::Low);

        handler.step(NULL_CTX, Decrease, false, true).unwrap();
        assert_eq!(handler.fan_mode(), FanModeEnum::Off);

        handler.step(NULL_CTX, Decrease, true, false).unwrap();
        assert_eq!(handler.fan_mode(), FanModeEnum::High);
    }

    // Startup and persistence

    #[test]
    fn startup_puts_the_fan_in_the_restored_setting() {
        let buf = Mutex::new(crate::utils::cell::RefCell::new([0u8; 256]));
        let kv = SharedKvBlobStore::new(MemKvBlobStore::default(), &buf);

        // What a previous run of the handler would have saved.
        {
            let handler = three_speed();

            handler
                .write_percent_setting(NULL_CTX, Nullable::some(64))
                .unwrap();
            handler
                .write_rock_setting(NULL_CTX, RockBitmap::ROCK_UP_DOWN)
                .unwrap();
            handler
                .write_airflow_direction(NULL_CTX, AirflowDirectionEnum::Reverse)
                .unwrap();

            handler.save(&kv).unwrap();
        }

        let handler = three_speed();

        handler.load_persisted(&kv).unwrap();
        handler.startup_device(NULL_CTX);

        assert_eq!(setting(&handler), (FanModeEnum::Medium, Some(64), Some(2)));

        // The device was told all of it, even the direction it defaults to.
        let device = handler.hooks().get();
        assert_eq!(
            device.setting,
            Some(FanSetting::Manual {
                mode: FanModeEnum::Medium,
                percent: 64,
                speed: 2
            })
        );
        assert_eq!(device.rock, Some(RockBitmap::ROCK_UP_DOWN));
        assert_eq!(device.wind, Some(WindBitmap::empty()));
        assert_eq!(device.direction, Some(AirflowDirectionEnum::Reverse));
    }

    #[test]
    fn startup_tells_the_device_even_the_initial_setting() {
        let handler = three_speed();

        handler.startup_device(NULL_CTX);

        assert_eq!(handler.hooks().get().setting, Some(FanSetting::Off));
    }

    #[test]
    fn a_refused_restored_setting_falls_back_to_off() {
        let handler = three_speed();

        handler
            .write_percent_setting(NULL_CTX, Nullable::some(64))
            .unwrap();
        handler.hooks().update(|state| state.refuse = true);

        handler.startup_device(NULL_CTX);

        assert_eq!(setting(&handler), (FanModeEnum::Off, Some(0), Some(0)));
    }

    // Validation

    #[test]
    fn a_consistent_configuration_validates() {
        three_speed().validate();
    }

    #[test]
    #[should_panic(expected = "SPEED_MAX 2 is less than the 3 speed modes")]
    fn fewer_speeds_than_modes_is_rejected() {
        FanControlHandler::new(
            Dataver::new(0),
            1,
            KV_KEY,
            MockHooks::<ALL, true, true, 2>::new(),
        )
        .validate();
    }

    #[test]
    #[should_panic(expected = "AUTO feature disagree")]
    fn a_sequence_that_disagrees_with_the_auto_feature_is_rejected() {
        // Every feature but AUTO, with an Auto sequence.
        struct AutoSequenceNoFeature;

        impl FanControlHooks for AutoSequenceNoFeature {
            const CLUSTER: Cluster<'static> =
                ThreeSpeed::CLUSTER.with_features(ALL & !Feature::AUTO.bits());
            const FAN_MODE_SEQUENCE: FanModeSequenceEnum = FanModeSequenceEnum::OffLowMedHighAuto;
            const SPEED_MAX: u8 = 3;
            const ROCK_SUPPORT: RockBitmap = RockBitmap::ROCK_LEFT_RIGHT;
            const WIND_SUPPORT: WindBitmap = WindBitmap::NATURAL_WIND;

            fn set_fan(&self, _setting: FanSetting) -> Result<(), ()> {
                Ok(())
            }

            fn current_speed(&self) -> CurrentSpeed {
                CurrentSpeed::Speed(0)
            }
        }

        FanControlHandler::new(Dataver::new(0), 1, KV_KEY, AutoSequenceNoFeature).validate();
    }

    #[test]
    #[should_panic(expected = "requires the MULTI_SPEED feature")]
    fn a_speed_attribute_without_the_feature_is_rejected() {
        // `TwoMode` serves the speed attributes but declares only STEP.
        struct SpeedAttrsNoFeature;

        impl FanControlHooks for SpeedAttrsNoFeature {
            const CLUSTER: Cluster<'static> = FULL_CLUSTER
                .with_features(0)
                .with_attrs(with!(required; AttributeId::SpeedMax))
                .with_cmds(with!());
            const FAN_MODE_SEQUENCE: FanModeSequenceEnum = FanModeSequenceEnum::OffHigh;

            fn set_fan(&self, _setting: FanSetting) -> Result<(), ()> {
                Ok(())
            }

            fn current_speed(&self) -> CurrentSpeed {
                CurrentSpeed::Speed(0)
            }
        }

        FanControlHandler::new(Dataver::new(0), 1, KV_KEY, SpeedAttrsNoFeature).validate();
    }
}
