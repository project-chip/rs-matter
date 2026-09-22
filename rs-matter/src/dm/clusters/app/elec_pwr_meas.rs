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

//! Matter Electrical Power Measurement cluster (`0x0090`), cluster
//! revision 3.
//!
//! Reports what the equipment on this endpoint is drawing *right now*; its
//! sibling [`super::elec_energy_meas`] reports what it has drawn over time.
//! Both hang off the Electrical Sensor device type
//! ([`crate::dm::devices::DEV_TYPE_ELECTRICAL_SENSOR`]) alongside
//! [`super::power_topology`].
//!
//! The device supplies readings through [`ElecPwrMeasHooks`]; the handler owns
//! the metadata, the accuracy encoding and the re-reporting.
//!
//! Every reading but `ActivePower` is optional, and each one served needs its
//! own entry in [`ElecPwrMeasHooks::ACCURACY`] - that list is what tells a
//! client which quantities the meter actually measures.
//! `NumberOfMeasurementTypes` is its length rather than a free-standing
//! number, so the two cannot drift apart.
//!
//! One of `DC` and `AC` must be selected and `PowerMode` has to agree, both
//! enforced by [`ElecPwrMeasHandler::validate`].
//!
//! There are no commands. The single event, `MeasurementPeriodRanges`, is
//! mandatory only given the optional `Ranges` attribute, which is not served -
//! nor are `POLY`, `HARM` and `PWRQ`, each of which makes further attributes
//! mandatory.

use core::pin::pin;

use embassy_futures::select::{select, Either};

use crate::dm::clusters::decl::globals::{
    MeasurementAccuracyStructArrayBuilder, MeasurementAccuracyStructBuilder, MeasurementTypeEnum,
};
use crate::dm::types::EndptId;
use crate::dm::{
    ArrayAttributeRead, AttrChangeNotifier, AttrId, Cluster, Dataver, HandlerContext, LifecycleOp,
    ReadContext,
};
use crate::error::{Error, ErrorCode};
use crate::im::{AmperageMilliA, PowerMilliVA, PowerMilliVAR, PowerMilliW, VoltageMilliV};
use crate::tlv::{Nullable, TLVBuilderParent};
use crate::utils::sync::Signal;

use super::measurement::{write_accuracy, MeasurementAccuracy};

pub use crate::dm::clusters::decl::electrical_power_measurement::*;

const CLUSTER_REVISION: u16 = 3;

/// Features this handler serves; anything else in an
/// [`ElecPwrMeasHooks::CLUSTER`] FeatureMap is rejected by
/// [`ElecPwrMeasHandler::validate`].
const SUPPORTED_FEATURES: u32 =
    Feature::DIRECT_CURRENT.bits() | Feature::ALTERNATING_CURRENT.bits();

/// Messages passed to the `notify` closure of [`ElecPwrMeasHooks::run`].
///
/// Every attribute here is a live reading, so all of them arrive out of band -
/// there is no write path that could notify on the device's behalf.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OutOfBandMessage {
    /// [`ElecPwrMeasHooks::active_power`] changed.
    ActivePower,
    /// [`ElecPwrMeasHooks::voltage`] changed.
    Voltage,
    /// [`ElecPwrMeasHooks::active_current`] changed.
    ActiveCurrent,
    /// [`ElecPwrMeasHooks::frequency`] changed.
    ///
    /// Its own message: supply frequency moves independently of the load.
    Frequency,
    /// [`ElecPwrMeasHooks::power_factor`] changed.
    ///
    /// Likewise independent: phase is a property of the load, not of how much
    /// of it is switched in.
    PowerFactor,
    /// Any or all of the readings changed — the usual message for a device
    /// whose readings all come from one sampling tick.
    Update,
}

impl OutOfBandMessage {
    /// The set of attributes this message marks as needing a re-report.
    const fn pending(&self) -> u16 {
        match self {
            Self::ActivePower => PENDING_ACTIVE_POWER,
            Self::Voltage => PENDING_VOLTAGE,
            Self::ActiveCurrent => PENDING_ACTIVE_CURRENT,
            Self::Frequency => PENDING_FREQUENCY,
            Self::PowerFactor => PENDING_POWER_FACTOR,
            Self::Update => PENDING_ALL,
        }
    }
}

// One bit per reading the hooks can answer. All twelve are here, not just the
// three mandatory ones: `notify_attr_changed` is matched per attribute path by
// `Subscriptions::find_report_due`, so a reading with no bit is never
// re-reported on change and a subscriber to it waits out the max interval.
// `notify_pending` skips whatever `CLUSTER` does not serve, so a device that
// omits the `[ALTC]` readings pays nothing for their bits.
const PENDING_VOLTAGE: u16 = 1 << 0;
const PENDING_ACTIVE_CURRENT: u16 = 1 << 1;
const PENDING_REACTIVE_CURRENT: u16 = 1 << 2;
const PENDING_APPARENT_CURRENT: u16 = 1 << 3;
const PENDING_ACTIVE_POWER: u16 = 1 << 4;
const PENDING_REACTIVE_POWER: u16 = 1 << 5;
const PENDING_APPARENT_POWER: u16 = 1 << 6;
const PENDING_RMS_VOLTAGE: u16 = 1 << 7;
const PENDING_RMS_CURRENT: u16 = 1 << 8;
const PENDING_RMS_POWER: u16 = 1 << 9;
const PENDING_FREQUENCY: u16 = 1 << 10;
const PENDING_POWER_FACTOR: u16 = 1 << 11;

const PENDING_ALL: u16 = PENDING_VOLTAGE
    | PENDING_ACTIVE_CURRENT
    | PENDING_REACTIVE_CURRENT
    | PENDING_APPARENT_CURRENT
    | PENDING_ACTIVE_POWER
    | PENDING_REACTIVE_POWER
    | PENDING_APPARENT_POWER
    | PENDING_RMS_VOLTAGE
    | PENDING_RMS_CURRENT
    | PENDING_RMS_POWER
    | PENDING_FREQUENCY
    | PENDING_POWER_FACTOR;

/// The pending-notification bit to attribute ID mapping, in ascending
/// attribute order.
const PENDING_ATTRS: &[(u16, AttributeId)] = &[
    (PENDING_VOLTAGE, AttributeId::Voltage),
    (PENDING_ACTIVE_CURRENT, AttributeId::ActiveCurrent),
    (PENDING_REACTIVE_CURRENT, AttributeId::ReactiveCurrent),
    (PENDING_APPARENT_CURRENT, AttributeId::ApparentCurrent),
    (PENDING_ACTIVE_POWER, AttributeId::ActivePower),
    (PENDING_REACTIVE_POWER, AttributeId::ReactivePower),
    (PENDING_APPARENT_POWER, AttributeId::ApparentPower),
    (PENDING_RMS_VOLTAGE, AttributeId::RMSVoltage),
    (PENDING_RMS_CURRENT, AttributeId::RMSCurrent),
    (PENDING_RMS_POWER, AttributeId::RMSPower),
    (PENDING_FREQUENCY, AttributeId::Frequency),
    (PENDING_POWER_FACTOR, AttributeId::PowerFactor),
];

/// An Electrical Power Measurement cluster handler.
///
/// Not coupled to any other cluster, so it needs no wiring step: construct it
/// with [`ElecPwrMeasHandler::new`] and chain it. Validation happens on
/// `Startup`.
pub struct ElecPwrMeasHandler<H: ElecPwrMeasHooks> {
    dataver: Dataver,
    /// Needed to address `notify_attr_changed` from [`Self::run`], which has
    /// only a [`HandlerContext`] and hence no notion of a "current" endpoint.
    endpoint_id: EndptId,
    hooks: H,
    /// Bitmask of attributes awaiting a re-report, fed by
    /// [`Self::out_of_band_message`] and drained by [`Self::run`].
    ///
    /// As in [`super::thermostat`], a mask rather than a `Signal` payload: a
    /// `Signal` replaces on signal, so two readings landing back to back would
    /// lose the first.
    pending: Signal<u16>,
}

impl<H: ElecPwrMeasHooks> ElecPwrMeasHandler<H> {
    /// Create a new `ElecPwrMeasHandler` with the given hooks.
    pub const fn new(dataver: Dataver, endpoint_id: EndptId, hooks: H) -> Self {
        Self {
            dataver,
            endpoint_id,
            hooks,
            pending: Signal::new(0),
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    /// Whether the configured FeatureMap contains *any* of `features`.
    fn supports_any_feature(features: u32) -> bool {
        H::CLUSTER.feature_map & features != 0
    }

    /// Whether `attr` is in the served set.
    fn serves(attr: AttributeId) -> bool {
        H::CLUSTER.attribute(attr as _).is_some()
    }

    /// Mark a set of attributes as needing a re-report and wake [`Self::run`].
    ///
    /// Public so a consumer holding the handler can poke it directly, besides
    /// the `notify` closure handed to [`ElecPwrMeasHooks::run`].
    pub fn out_of_band_message(&self, message: OutOfBandMessage) {
        let bits = message.pending();

        self.pending.modify(|pending| {
            *pending |= bits;
            (true, ())
        });
    }

    /// Wait until at least one attribute is pending, then take the whole mask.
    async fn wait_pending(&self) -> u16 {
        self.pending
            .wait(|pending| (*pending != 0).then(|| core::mem::take(pending)))
            .await
    }

    /// Emit one `notify_attr_changed` per pending attribute that is served.
    ///
    /// Takes an [`AttrChangeNotifier`] rather than the [`HandlerContext`] it
    /// is called with, so a unit test can pin the mask's losslessness down
    /// with a recording notifier.
    fn notify_pending(&self, notifier: &impl AttrChangeNotifier, pending: u16) {
        for (bit, attr) in PENDING_ATTRS {
            if pending & bit != 0 && Self::serves(*attr) {
                notifier.notify_attr_changed(self.endpoint_id, Self::CLUSTER.id, *attr as AttrId);
            }
        }
    }

    /// Check that the cluster is configured in a way this handler can serve.
    ///
    /// # Panics
    ///
    /// If [`ElecPwrMeasHooks::CLUSTER`] is misconfigured - a programming error
    /// caught once at startup, not a runtime condition.
    fn validate(&self) {
        if H::CLUSTER.revision != CLUSTER_REVISION {
            panic!(
                "ElectricalPowerMeasurement validation: incorrect revision number: expected {} got {}",
                CLUSTER_REVISION, H::CLUSTER.revision
            );
        }

        // DC and AC are a choice of at least one; there is no meaningful
        // reading without one.
        if !Self::supports_any_feature(SUPPORTED_FEATURES) {
            panic!("ElectricalPowerMeasurement validation: one of the DC or AC features must be enabled");
        }

        if H::CLUSTER.feature_map & !SUPPORTED_FEATURES != 0 {
            panic!(
                "ElectricalPowerMeasurement validation: unsupported features in the feature map: 0x{:08x}. Only DC and AC are implemented",
                H::CLUSTER.feature_map & !SUPPORTED_FEATURES
            );
        }

        // `PowerMode` describes the supply the readings are taken from, so it
        // has to agree with the feature selection.
        let expected = if Self::supports_any_feature(Feature::ALTERNATING_CURRENT.bits()) {
            PowerModeEnum::AC
        } else {
            PowerModeEnum::DC
        };

        if H::POWER_MODE != expected {
            panic!(
                "ElectricalPowerMeasurement validation: POWER_MODE is {:?} but the feature map selects {:?}",
                H::POWER_MODE, expected
            );
        }

        for attr in [
            AttributeId::PowerMode,
            AttributeId::NumberOfMeasurementTypes,
            AttributeId::Accuracy,
            AttributeId::ActivePower,
        ] {
            if !Self::serves(attr) {
                panic!(
                    "ElectricalPowerMeasurement validation: missing required attribute: {:?}",
                    attr
                );
            }
        }

        // Nine of the optional readings are `[ALTC]`: they describe an
        // alternating supply and mean nothing on a DC one.
        if !Self::supports_any_feature(Feature::ALTERNATING_CURRENT.bits()) {
            for attr in [
                AttributeId::ReactiveCurrent,
                AttributeId::ApparentCurrent,
                AttributeId::ReactivePower,
                AttributeId::ApparentPower,
                AttributeId::RMSVoltage,
                AttributeId::RMSCurrent,
                AttributeId::RMSPower,
                AttributeId::Frequency,
                AttributeId::PowerFactor,
            ] {
                if Self::serves(attr) {
                    panic!(
                        "ElectricalPowerMeasurement validation: {:?} is served without the AC feature it is conditional on",
                        attr
                    );
                }
            }
        }

        // The single event is mandatory given the optional `Ranges`
        // attribute, which this handler does not serve, so an event in the
        // served set would be advertised in `EventList` and never emitted.
        if H::CLUSTER.events().next().is_some() {
            panic!("ElectricalPowerMeasurement validation: no event can be served without the Ranges attribute - pass `.with_events(with!())`");
        }

        if H::ACCURACY.is_empty() {
            panic!("ElectricalPowerMeasurement validation: ACCURACY must describe at least one measurement type");
        }

        // `NumberOfMeasurementTypes` is a `uint8` reporting this length.
        if H::ACCURACY.len() > u8::MAX as usize {
            panic!(
                "ElectricalPowerMeasurement validation: ACCURACY has {} entries, more than NumberOfMeasurementTypes can report",
                H::ACCURACY.len()
            );
        }

        for accuracy in H::ACCURACY {
            accuracy.validate("ElectricalPowerMeasurement");
        }

        // The `Accuracy` list describes the measurement types the server
        // supports, so every served reading needs an entry.
        for (attr, measurement_type) in [
            (AttributeId::Voltage, MeasurementTypeEnum::Voltage),
            (
                AttributeId::ActiveCurrent,
                MeasurementTypeEnum::ActiveCurrent,
            ),
            (AttributeId::ActivePower, MeasurementTypeEnum::ActivePower),
            (
                AttributeId::ReactiveCurrent,
                MeasurementTypeEnum::ReactiveCurrent,
            ),
            (
                AttributeId::ApparentCurrent,
                MeasurementTypeEnum::ApparentCurrent,
            ),
            (
                AttributeId::ReactivePower,
                MeasurementTypeEnum::ReactivePower,
            ),
            (
                AttributeId::ApparentPower,
                MeasurementTypeEnum::ApparentPower,
            ),
            (AttributeId::RMSVoltage, MeasurementTypeEnum::RMSVoltage),
            (AttributeId::RMSCurrent, MeasurementTypeEnum::RMSCurrent),
            (AttributeId::RMSPower, MeasurementTypeEnum::RMSPower),
            (AttributeId::Frequency, MeasurementTypeEnum::Frequency),
            (AttributeId::PowerFactor, MeasurementTypeEnum::PowerFactor),
        ] {
            if Self::serves(attr)
                && !H::ACCURACY
                    .iter()
                    .any(|accuracy| accuracy.measurement_type == measurement_type)
            {
                panic!(
                    "ElectricalPowerMeasurement validation: {:?} is served but ACCURACY has no {:?} entry",
                    attr, measurement_type
                );
            }
        }
    }
}

impl<H: ElecPwrMeasHooks> ClusterHandler for ElecPwrMeasHandler<H> {
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
        }

        Ok(())
    }

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        let mut hooks_fut = pin!(self.hooks.run(|message| self.out_of_band_message(message)));

        loop {
            match select(&mut hooks_fut, self.wait_pending()).await {
                Either::First(_) => panic!("ElecPwrMeasHooks::run returned; implementers MUST not return. Implementations should loop forever or await core::future::pending::<()>()."),
                Either::Second(pending) => self.notify_pending(&ctx, pending),
            }
        }
    }

    // Attribute accessors

    /// The kind of supply the readings describe. Fixed at manufacture, and
    /// checked against the feature map by [`Self::validate`].
    fn power_mode(&self, _ctx: impl ReadContext) -> Result<PowerModeEnum, Error> {
        Ok(H::POWER_MODE)
    }

    /// The number of measurement types supported: the `Accuracy` list's
    /// length.
    fn number_of_measurement_types(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(H::ACCURACY.len() as u8)
    }

    /// How accurately each supported quantity is measured.
    fn accuracy<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            MeasurementAccuracyStructArrayBuilder<P>,
            MeasurementAccuracyStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(mut array) => {
                for accuracy in H::ACCURACY {
                    array = write_accuracy(array.push()?, accuracy)?;
                }

                array.end()
            }
            ArrayAttributeRead::ReadOne(index, item) => {
                let Some(accuracy) = H::ACCURACY.get(index as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };

                write_accuracy(item, accuracy)
            }
            ArrayAttributeRead::ReadNone(array) => array.end(),
        }
    }

    fn voltage(&self, _ctx: impl ReadContext) -> Result<Nullable<VoltageMilliV>, Error> {
        Ok(self.hooks.voltage().into())
    }

    fn active_current(&self, _ctx: impl ReadContext) -> Result<Nullable<AmperageMilliA>, Error> {
        Ok(self.hooks.active_current().into())
    }

    fn active_power(&self, _ctx: impl ReadContext) -> Result<Nullable<PowerMilliW>, Error> {
        Ok(self.hooks.active_power().into())
    }

    fn reactive_current(&self, _ctx: impl ReadContext) -> Result<Nullable<AmperageMilliA>, Error> {
        Ok(self.hooks.reactive_current().into())
    }

    fn apparent_current(&self, _ctx: impl ReadContext) -> Result<Nullable<AmperageMilliA>, Error> {
        Ok(self.hooks.apparent_current().into())
    }

    fn reactive_power(&self, _ctx: impl ReadContext) -> Result<Nullable<PowerMilliVAR>, Error> {
        Ok(self.hooks.reactive_power().into())
    }

    fn apparent_power(&self, _ctx: impl ReadContext) -> Result<Nullable<PowerMilliVA>, Error> {
        Ok(self.hooks.apparent_power().into())
    }

    fn rms_voltage(&self, _ctx: impl ReadContext) -> Result<Nullable<VoltageMilliV>, Error> {
        Ok(self.hooks.rms_voltage().into())
    }

    fn rms_current(&self, _ctx: impl ReadContext) -> Result<Nullable<AmperageMilliA>, Error> {
        Ok(self.hooks.rms_current().into())
    }

    fn rms_power(&self, _ctx: impl ReadContext) -> Result<Nullable<PowerMilliW>, Error> {
        Ok(self.hooks.rms_power().into())
    }

    fn frequency(&self, _ctx: impl ReadContext) -> Result<Nullable<i64>, Error> {
        Ok(self.hooks.frequency().into())
    }

    fn power_factor(&self, _ctx: impl ReadContext) -> Result<Nullable<i64>, Error> {
        Ok(self.hooks.power_factor().into())
    }
}

/// Device-specific hooks for the Electrical Power Measurement cluster.
///
/// Every reading is optional: a device that cannot currently measure a
/// quantity answers `None` rather than a stale or invented number.
pub trait ElecPwrMeasHooks {
    /// The features and attributes this instance serves. See
    /// [`ElecPwrMeasHandler::validate`] for what a serveable configuration
    /// is.
    const CLUSTER: Cluster<'static>;

    /// `PowerMode`. A const because the supply a device is
    /// wired to does not change; it must agree with the `DC`/`AC` feature.
    const POWER_MODE: PowerModeEnum;

    /// The `Accuracy` list, one entry per measurement type served; its length
    /// is reported as `NumberOfMeasurementTypes`. A const because metering
    /// accuracy is a property of the hardware.
    const ACCURACY: &'static [MeasurementAccuracy];

    /// `ActivePower` in milliwatts, or `None` when unavailable.
    fn active_power(&self) -> Option<PowerMilliW>;

    /// `Voltage` in millivolts. Only called when the attribute is served; the
    /// defaults throughout suit a device that omits it.
    fn voltage(&self) -> Option<VoltageMilliV> {
        None
    }

    /// `ActiveCurrent` in milliamps.
    fn active_current(&self) -> Option<AmperageMilliA> {
        None
    }

    /// `ReactiveCurrent` in milliamps. `[ALTC]`.
    fn reactive_current(&self) -> Option<AmperageMilliA> {
        None
    }

    /// `ApparentCurrent` in milliamps. `[ALTC]`.
    fn apparent_current(&self) -> Option<AmperageMilliA> {
        None
    }

    /// `ReactivePower` in millivolt-amperes reactive. `[ALTC]`.
    fn reactive_power(&self) -> Option<PowerMilliVAR> {
        None
    }

    /// `ApparentPower` in millivolt-amperes. `[ALTC]`.
    fn apparent_power(&self) -> Option<PowerMilliVA> {
        None
    }

    /// `RMSVoltage` in millivolts. `[ALTC]`.
    fn rms_voltage(&self) -> Option<VoltageMilliV> {
        None
    }

    /// `RMSCurrent` in milliamps. `[ALTC]`.
    fn rms_current(&self) -> Option<AmperageMilliA> {
        None
    }

    /// `RMSPower` in milliwatts. `[ALTC]`.
    fn rms_power(&self) -> Option<PowerMilliW> {
        None
    }

    /// `Frequency` in millihertz, constrained to `0..=1000000`. `[ALTC]`.
    fn frequency(&self) -> Option<i64> {
        None
    }

    /// `PowerFactor` in hundredths of a percent, constrained to
    /// `-10000..=10000`. `[ALTC]`.
    fn power_factor(&self) -> Option<i64> {
        None
    }

    /// Background task for out-of-band notifications: sample the hardware,
    /// then call `notify` to re-report the changed attributes.
    ///
    /// Note the direction. The example and itest driver poll a simulated
    /// element on a timer because a simulation has nothing else to do, but
    /// that is not the shape to copy - an ADC or metering chip raises an
    /// interrupt or fills a FIFO, and this future should await *that*. Polling
    /// a real meter faster than it samples only burns power.
    ///
    /// # Panics
    /// This future must not return; the SDK panics if it does. Loop forever,
    /// or await `core::future::pending::<()>()`.
    async fn run<F: Fn(OutOfBandMessage)>(&self, _notify: F) {
        core::future::pending::<()>().await
    }
}

impl<T> ElecPwrMeasHooks for &T
where
    T: ElecPwrMeasHooks,
{
    const CLUSTER: Cluster<'static> = T::CLUSTER;
    const POWER_MODE: PowerModeEnum = T::POWER_MODE;
    const ACCURACY: &'static [MeasurementAccuracy] = T::ACCURACY;

    fn active_power(&self) -> Option<PowerMilliW> {
        (*self).active_power()
    }

    fn voltage(&self) -> Option<VoltageMilliV> {
        (*self).voltage()
    }

    fn active_current(&self) -> Option<AmperageMilliA> {
        (*self).active_current()
    }

    fn reactive_current(&self) -> Option<AmperageMilliA> {
        (*self).reactive_current()
    }

    fn apparent_current(&self) -> Option<AmperageMilliA> {
        (*self).apparent_current()
    }

    fn reactive_power(&self) -> Option<PowerMilliVAR> {
        (*self).reactive_power()
    }

    fn apparent_power(&self) -> Option<PowerMilliVA> {
        (*self).apparent_power()
    }

    fn rms_voltage(&self) -> Option<VoltageMilliV> {
        (*self).rms_voltage()
    }

    fn rms_current(&self) -> Option<AmperageMilliA> {
        (*self).rms_current()
    }

    fn rms_power(&self) -> Option<PowerMilliW> {
        (*self).rms_power()
    }

    fn frequency(&self) -> Option<i64> {
        (*self).frequency()
    }

    fn power_factor(&self) -> Option<i64> {
        (*self).power_factor()
    }

    async fn run<F: Fn(OutOfBandMessage)>(&self, notify: F) {
        (*self).run(notify).await
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the cluster-configuration rules [`ElecPwrMeasHandler`]
    //! enforces.
    //!
    //! They drive `validate()` directly rather than through a `Startup`
    //! lifecycle op: the op only exists to pick a moment to run these checks,
    //! and a `HandlerContext` can only be built around a live `Matter`.

    use embassy_futures::block_on;

    use crate::dm::clusters::app::test_util::RecordingNotifier;
    use crate::dm::clusters::decl::electrical_power_measurement as cluster;
    use crate::dm::{AttrId, Dataver};
    use crate::im::PowerMilliW;
    use crate::with;

    use super::super::measurement::{MeasurementAccuracy, MeasurementAccuracyRange};
    use super::*;

    const RANGE: &[MeasurementAccuracyRange] = &[MeasurementAccuracyRange::percent(0, 1_000, 500)];

    /// Describes every reading the mock serves.
    const FULL_ACCURACY: &[MeasurementAccuracy] = &[
        MeasurementAccuracy::new(MeasurementTypeEnum::Voltage, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::ActiveCurrent, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::ActivePower, 0, 1_000, RANGE),
    ];

    /// Describes every reading `FullAcHooks` serves - `validate` wants an
    /// `Accuracy` entry per served measurement type.
    const ALL_ACCURACY: &[MeasurementAccuracy] = &[
        MeasurementAccuracy::new(MeasurementTypeEnum::Voltage, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::ActiveCurrent, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::ActivePower, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::ReactiveCurrent, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::ApparentCurrent, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::ReactivePower, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::ApparentPower, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::RMSVoltage, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::RMSCurrent, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::RMSPower, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::Frequency, 0, 1_000, RANGE),
        MeasurementAccuracy::new(MeasurementTypeEnum::PowerFactor, 0, 1_000, RANGE),
    ];

    /// Describes only `ActivePower`, while the mock also serves `Voltage`.
    const PARTIAL_ACCURACY: &[MeasurementAccuracy] = &[MeasurementAccuracy::new(
        MeasurementTypeEnum::ActivePower,
        0,
        1_000,
        RANGE,
    )];

    const AC: u32 = cluster::Feature::ALTERNATING_CURRENT.bits();
    const DC: u32 = cluster::Feature::DIRECT_CURRENT.bits();

    /// A mock parameterised by its feature map, so a test can ask for a
    /// configuration the handler is supposed to reject.
    struct MockHooks<const F: u32>;

    impl<const F: u32> ElecPwrMeasHooks for MockHooks<F> {
        const CLUSTER: Cluster<'static> = cluster::FULL_CLUSTER
            .with_revision(3)
            .with_features(F)
            .with_attrs(with!(
                required;
                cluster::AttributeId::Voltage | cluster::AttributeId::ActiveCurrent
            ))
            .with_cmds(with!())
            .with_events(with!());

        const POWER_MODE: PowerModeEnum = PowerModeEnum::AC;
        const ACCURACY: &'static [MeasurementAccuracy] = FULL_ACCURACY;

        fn active_power(&self) -> Option<PowerMilliW> {
            Some(1_000)
        }

        fn voltage(&self) -> Option<VoltageMilliV> {
            Some(230_000)
        }

        fn active_current(&self) -> Option<AmperageMilliA> {
            Some(4_348)
        }
    }

    /// AC in the feature map, but a `PowerMode` saying otherwise.
    struct MismatchedModeHooks;

    impl ElecPwrMeasHooks for MismatchedModeHooks {
        const CLUSTER: Cluster<'static> = <MockHooks<AC> as ElecPwrMeasHooks>::CLUSTER;
        const POWER_MODE: PowerModeEnum = PowerModeEnum::DC;
        const ACCURACY: &'static [MeasurementAccuracy] = FULL_ACCURACY;

        fn active_power(&self) -> Option<PowerMilliW> {
            None
        }
    }

    /// Serves `Voltage` without describing its accuracy.
    struct PartialAccuracyHooks;

    impl ElecPwrMeasHooks for PartialAccuracyHooks {
        const CLUSTER: Cluster<'static> = <MockHooks<AC> as ElecPwrMeasHooks>::CLUSTER;
        const POWER_MODE: PowerModeEnum = PowerModeEnum::AC;
        const ACCURACY: &'static [MeasurementAccuracy] = PARTIAL_ACCURACY;

        fn active_power(&self) -> Option<PowerMilliW> {
            None
        }

        fn voltage(&self) -> Option<VoltageMilliV> {
            Some(230_000)
        }
    }

    fn handler<H: ElecPwrMeasHooks>(hooks: H) -> ElecPwrMeasHandler<H> {
        ElecPwrMeasHandler::new(Dataver::new(1), 1, hooks)
    }

    #[test]
    fn validate_accepts_a_single_phase_ac_load() {
        handler(MockHooks::<AC>).validate();
    }

    #[test]
    fn validate_accepts_a_dc_load() {
        struct DcHooks;

        impl ElecPwrMeasHooks for DcHooks {
            const CLUSTER: Cluster<'static> = <MockHooks<DC> as ElecPwrMeasHooks>::CLUSTER;
            const POWER_MODE: PowerModeEnum = PowerModeEnum::DC;
            const ACCURACY: &'static [MeasurementAccuracy] = FULL_ACCURACY;

            fn active_power(&self) -> Option<PowerMilliW> {
                None
            }
        }

        handler(DcHooks).validate();
    }

    /// The served set is what a controller reads first, so pin it down.
    #[test]
    fn cluster_serves_the_expected_attributes() {
        let cluster = <MockHooks<AC> as ElecPwrMeasHooks>::CLUSTER;

        let attrs: heapless::Vec<_, 16> = cluster
            .attributes()
            .map(|attr| attr.id)
            .filter(|id| *id < 0xF000)
            .collect();

        assert_eq!(
            attrs,
            [
                AttributeId::PowerMode as AttrId,
                AttributeId::NumberOfMeasurementTypes as AttrId,
                AttributeId::Accuracy as AttrId,
                AttributeId::Voltage as AttrId,
                AttributeId::ActiveCurrent as AttrId,
                AttributeId::ActivePower as AttrId,
            ]
        );

        assert_eq!(cluster.commands().count(), 0);
    }

    /// The reason `pending` is a bitmask and not a `Signal<Option<_>>`: two
    /// readings landing between two turns of `run` must both be re-reported,
    /// not just the later one. A sampling tick that moves voltage and current
    /// together is the normal case here, not a corner one.
    #[test]
    fn out_of_band_messages_accumulate_without_loss() {
        let handler = handler(MockHooks::<AC>);
        let notifier = RecordingNotifier::default();

        handler.out_of_band_message(OutOfBandMessage::Voltage);
        handler.out_of_band_message(OutOfBandMessage::ActiveCurrent);

        // Ready immediately - the mask is non-empty, so this does not block.
        let pending = block_on(handler.wait_pending());
        handler.notify_pending(&notifier, pending);

        assert_eq!(
            notifier.attrs(),
            [
                AttributeId::Voltage as AttrId,
                AttributeId::ActiveCurrent as AttrId,
            ]
        );

        // And the mask is empty again, so nothing is re-reported twice.
        assert_eq!(handler.pending.modify(|pending| (false, *pending)), 0);
    }

    /// Every `OutOfBandMessage` maps onto the attribute it names, and `Update`
    /// onto all of them, in ascending attribute order.
    #[test]
    fn out_of_band_messages_report_the_attributes_they_name() {
        let handler = handler(MockHooks::<AC>);
        let notifier = RecordingNotifier::default();

        for (message, expected) in [
            (
                OutOfBandMessage::Voltage,
                &[AttributeId::Voltage as AttrId][..],
            ),
            (
                OutOfBandMessage::ActiveCurrent,
                &[AttributeId::ActiveCurrent as AttrId][..],
            ),
            (
                OutOfBandMessage::ActivePower,
                &[AttributeId::ActivePower as AttrId][..],
            ),
            (
                OutOfBandMessage::Update,
                &[
                    AttributeId::Voltage as AttrId,
                    AttributeId::ActiveCurrent as AttrId,
                    AttributeId::ActivePower as AttrId,
                ][..],
            ),
        ] {
            handler.out_of_band_message(message);
            handler.notify_pending(&notifier, block_on(handler.wait_pending()));

            assert_eq!(notifier.attrs(), expected, "{message:?}");
        }
    }

    /// A meter serving every reading the hooks can answer, so that the
    /// `[ALTC]` half of the pending mask is exercised.
    struct FullAcHooks;

    impl ElecPwrMeasHooks for FullAcHooks {
        const CLUSTER: Cluster<'static> = cluster::FULL_CLUSTER
            .with_revision(3)
            .with_features(AC)
            .with_attrs(with!(
                required;
                cluster::AttributeId::Voltage
                    | cluster::AttributeId::ActiveCurrent
                    | cluster::AttributeId::ReactiveCurrent
                    | cluster::AttributeId::ApparentCurrent
                    | cluster::AttributeId::ReactivePower
                    | cluster::AttributeId::ApparentPower
                    | cluster::AttributeId::RMSVoltage
                    | cluster::AttributeId::RMSCurrent
                    | cluster::AttributeId::RMSPower
                    | cluster::AttributeId::Frequency
                    | cluster::AttributeId::PowerFactor
            ))
            .with_cmds(with!())
            .with_events(with!());

        const POWER_MODE: PowerModeEnum = PowerModeEnum::AC;
        const ACCURACY: &'static [MeasurementAccuracy] = ALL_ACCURACY;

        fn active_power(&self) -> Option<PowerMilliW> {
            Some(1_000)
        }
    }

    /// Regression test for the nine `[ALTC]` readings having no pending bit:
    /// they were served but never re-reported, so a subscriber to `RMSPower`
    /// only ever heard from the max interval.
    #[test]
    fn update_reports_every_served_reading() {
        let handler = handler(FullAcHooks);
        let notifier = RecordingNotifier::default();

        handler.out_of_band_message(OutOfBandMessage::Update);
        handler.notify_pending(&notifier, block_on(handler.wait_pending()));

        assert_eq!(
            notifier.attrs(),
            [
                AttributeId::Voltage as AttrId,
                AttributeId::ActiveCurrent as AttrId,
                AttributeId::ReactiveCurrent as AttrId,
                AttributeId::ApparentCurrent as AttrId,
                AttributeId::ActivePower as AttrId,
                AttributeId::ReactivePower as AttrId,
                AttributeId::ApparentPower as AttrId,
                AttributeId::RMSVoltage as AttrId,
                AttributeId::RMSCurrent as AttrId,
                AttributeId::RMSPower as AttrId,
                AttributeId::Frequency as AttrId,
                AttributeId::PowerFactor as AttrId,
            ]
        );
    }

    /// The two readings that move on their own address themselves.
    #[test]
    fn the_independent_readings_have_their_own_messages() {
        let handler = handler(FullAcHooks);
        let notifier = RecordingNotifier::default();

        for (message, expected) in [
            (OutOfBandMessage::Frequency, AttributeId::Frequency),
            (OutOfBandMessage::PowerFactor, AttributeId::PowerFactor),
        ] {
            handler.out_of_band_message(message);
            handler.notify_pending(&notifier, block_on(handler.wait_pending()));

            assert_eq!(notifier.attrs(), [expected as AttrId], "{message:?}");
        }
    }

    #[test]
    #[should_panic(expected = "one of the DC or AC features must be enabled")]
    fn validate_rejects_a_cluster_with_neither_dc_nor_ac() {
        handler(MockHooks::<0>).validate();
    }

    #[test]
    #[should_panic(expected = "unsupported features in the feature map")]
    fn validate_rejects_polyphase() {
        const POLY: u32 = AC | cluster::Feature::POLYPHASE_POWER.bits();

        handler(MockHooks::<POLY>).validate();
    }

    /// Nine of the optional readings describe an alternating supply, and a DC
    /// meter has no business advertising them.
    #[test]
    #[should_panic(expected = "is served without the AC feature")]
    fn validate_rejects_an_ac_only_reading_on_a_dc_meter() {
        struct DcWithRmsHooks;

        impl ElecPwrMeasHooks for DcWithRmsHooks {
            const CLUSTER: Cluster<'static> = cluster::FULL_CLUSTER
                .with_revision(3)
                .with_features(DC)
                .with_attrs(with!(required; cluster::AttributeId::RMSVoltage))
                .with_cmds(with!())
                .with_events(with!());

            const POWER_MODE: PowerModeEnum = PowerModeEnum::DC;
            const ACCURACY: &'static [MeasurementAccuracy] = FULL_ACCURACY;

            fn active_power(&self) -> Option<PowerMilliW> {
                None
            }
        }

        handler(DcWithRmsHooks).validate();
    }

    #[test]
    #[should_panic(expected = "but the feature map selects")]
    fn validate_rejects_a_power_mode_disagreeing_with_the_features() {
        handler(MismatchedModeHooks).validate();
    }

    #[test]
    #[should_panic(expected = "ACCURACY has no")]
    fn validate_rejects_a_served_reading_with_no_accuracy_entry() {
        handler(PartialAccuracyHooks).validate();
    }
}
