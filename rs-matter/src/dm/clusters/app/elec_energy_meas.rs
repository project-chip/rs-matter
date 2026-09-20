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

//! Implementation of the Matter Electrical Energy Measurement cluster
//! (`0x0091`), Matter 1.6 Application Cluster spec section 2.12,
//! `ClusterRevision` 2.
//!
//! Where [`super::elec_pwr_meas`] reports what the equipment is drawing right
//! now, this cluster reports what it has drawn *over time*. Both hang off the
//! Electrical Sensor device type
//! ([`crate::dm::devices::DEV_TYPE_ELECTRICAL_SENSOR`]) alongside
//! [`super::power_topology`].
//!
//! This is an **import-only** implementation: the FeatureMap it accepts is
//! `IMPE` plus at least one of `CUME` and `PERE`. A device that also generates
//! (`EXPE`) needs the mirrored exported attributes, which are not served.
//!
//! Attributes served (section 2.12.6):
//!
//! | ID       | Name                       | Conformance   |
//! | -------- | -------------------------- | ------------- |
//! | `0x0000` | `Accuracy`                 | M             |
//! | `0x0001` | `CumulativeEnergyImported` | `IMPE & CUME` |
//! | `0x0003` | `PeriodicEnergyImported`   | `IMPE & PERE` |
//!
//! Events (section 2.12.7), each mandatory given its feature and emitted from
//! [`ElecEnergyMeasHandler::run`] whenever the device reports a new reading:
//!
//! | ID     | Name                       | Conformance |
//! | ------ | -------------------------- | ----------- |
//! | `0x00` | `CumulativeEnergyMeasured` | `CUME`      |
//! | `0x01` | `PeriodicEnergyMeasured`   | `PERE`      |
//!
//! The cluster has no commands.
//!
//! # Timestamps, and why this needs no Time Synchronization
//!
//! An `EnergyMeasurementStruct` locates its reading in time twice over: in UTC
//! (`StartTimestamp`/`EndTimestamp`) and as time since boot
//! (`StartSystime`/`EndSystime`). Sections 2.12.5.2.2 through 2.12.5.2.5 make
//! the UTC pair conditional on the server having determined the time, and
//! require the systime pair precisely when it has not. A device with no clock
//! is therefore fully conformant reporting systime alone — see [`Timestamp`].
//!
//! The other rule those sections state is that a *cumulative* reading has no
//! beginning: it runs from the device's lifetime origin, so `StartTimestamp`
//! and `StartSystime` "SHALL be omitted". The handler enforces that itself
//! rather than trusting the hooks — see [`EnergyMeasurement::as_cumulative`].

use core::pin::pin;

use embassy_futures::select::{select, Either};

use crate::dm::clusters::decl::globals::{MeasurementAccuracyStructBuilder, MeasurementTypeEnum};
use crate::dm::types::EndptId;
use crate::dm::{
    AttrChangeNotifier, AttrId, Cluster, Dataver, HandlerContext, LifecycleOp, ReadContext,
};
use crate::error::Error;
use crate::im::EnergyMilliWh;
use crate::tlv::{Nullable, NullableBuilder, TLVBuilderParent};
use crate::utils::sync::Signal;

use super::measurement::{write_accuracy, MeasurementAccuracy};

pub use crate::dm::clusters::decl::electrical_energy_measurement::*;

/// The `ClusterRevision` this handler implements (Matter 1.6).
const CLUSTER_REVISION: u16 = 2;

/// The features this handler knows how to serve. Anything else in an
/// [`ElecEnergyMeasHooks::CLUSTER`] FeatureMap is rejected by
/// [`ElecEnergyMeasHandler::validate`].
const SUPPORTED_FEATURES: u32 = Feature::IMPORTED_ENERGY.bits()
    | Feature::CUMULATIVE_ENERGY.bits()
    | Feature::PERIODIC_ENERGY.bits();

/// When a reading was taken.
///
/// Both representations are optional and at least one must be present
/// (sections 2.12.5.2.3 and 2.12.5.2.5): a device that has determined the time
/// in UTC reports [`Timestamp::utc`], one that has not reports
/// [`Timestamp::systime`], and a device that knows both may report both.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Timestamp {
    /// Seconds since the Matter epoch (2000-01-01T00:00:00Z UTC).
    pub utc: Option<u32>,
    /// Milliseconds since boot.
    pub systime: Option<u64>,
}

impl Timestamp {
    /// A moment known in UTC, in seconds since the Matter epoch.
    pub const fn utc(seconds: u32) -> Self {
        Self {
            utc: Some(seconds),
            systime: None,
        }
    }

    /// A moment known only as time since boot, in milliseconds — the right
    /// answer for a device with no clock.
    pub const fn systime(millis: u64) -> Self {
        Self {
            utc: None,
            systime: Some(millis),
        }
    }

    /// A moment known both ways.
    pub const fn both(seconds: u32, millis: u64) -> Self {
        Self {
            utc: Some(seconds),
            systime: Some(millis),
        }
    }

    /// Whether this timestamp says anything at all.
    const fn is_known(&self) -> bool {
        self.utc.is_some() || self.systime.is_some()
    }
}

/// One `EnergyMeasurementStruct` worth of reading (section 2.12.5.2).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EnergyMeasurement {
    /// The energy measured, in milliwatt-hours.
    pub energy: EnergyMilliWh,
    /// When the measurement period began. Ignored for a cumulative reading.
    pub start: Timestamp,
    /// When the measurement period ended — or, for a cumulative reading, when
    /// the running total was last updated.
    pub end: Timestamp,
}

impl EnergyMeasurement {
    /// A cumulative reading: lifetime energy as of `end`.
    pub const fn cumulative(energy: EnergyMilliWh, end: Timestamp) -> Self {
        Self {
            energy,
            start: Timestamp {
                utc: None,
                systime: None,
            },
            end,
        }
    }

    /// A periodic reading: the energy measured between `start` and `end`.
    pub const fn periodic(energy: EnergyMilliWh, start: Timestamp, end: Timestamp) -> Self {
        Self { energy, start, end }
    }

    /// Sections 2.12.5.2.2 and 2.12.5.2.4: a cumulative reading has no
    /// beginning, so `StartTimestamp` and `StartSystime` SHALL be omitted.
    ///
    /// Returns `None` when the reading cannot be encoded conformantly because
    /// its end is unknown — sections 2.12.5.2.3 and 2.12.5.2.5 require one of
    /// the two end fields. The attribute then reports null, which is what a
    /// server with no reading to give is supposed to say.
    fn as_cumulative(&self) -> Option<Self> {
        self.end.is_known().then_some(Self {
            energy: self.energy,
            start: Timestamp {
                utc: None,
                systime: None,
            },
            end: self.end,
        })
    }

    /// The periodic counterpart of [`Self::as_cumulative`]. A period needs both
    /// of its ends, so both have to be known.
    fn as_periodic(&self) -> Option<Self> {
        (self.start.is_known() && self.end.is_known()).then_some(*self)
    }
}

/// Messages passed to the `notify` closure of [`ElecEnergyMeasHooks::run`].
///
/// Besides re-reporting the attribute, each of these emits the corresponding
/// event — that is what makes a new reading visible to a subscriber that is
/// watching events rather than polling.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OutOfBandMessage {
    /// [`ElecEnergyMeasHooks::cumulative_energy_imported`] changed.
    CumulativeEnergyImported,
    /// [`ElecEnergyMeasHooks::periodic_energy_imported`] changed.
    PeriodicEnergyImported,
    /// Any or all of the above changed.
    Update,
}

impl OutOfBandMessage {
    /// The set of attributes this message marks as needing a re-report.
    const fn pending(&self) -> u8 {
        match self {
            Self::CumulativeEnergyImported => PENDING_CUMULATIVE_IMPORTED,
            Self::PeriodicEnergyImported => PENDING_PERIODIC_IMPORTED,
            Self::Update => PENDING_ALL,
        }
    }
}

const PENDING_CUMULATIVE_IMPORTED: u8 = 1 << 0;
const PENDING_PERIODIC_IMPORTED: u8 = 1 << 1;
const PENDING_ALL: u8 = PENDING_CUMULATIVE_IMPORTED | PENDING_PERIODIC_IMPORTED;

/// The pending-notification bit to attribute ID mapping, in ascending
/// attribute order.
///
/// `Accuracy` and `CumulativeEnergyReset` are deliberately absent. The first is
/// a hooks const and so cannot move at all; the second changes only when the
/// lifetime counter is zeroed, which on a real device means a factory reset -
/// i.e. a reboot, after which a subscriber re-reads it anyway. Add a bit and a
/// message for it if a device ever learns to zero the counter while running.
const PENDING_ATTRS: &[(u8, AttributeId)] = &[
    (
        PENDING_CUMULATIVE_IMPORTED,
        AttributeId::CumulativeEnergyImported,
    ),
    (
        PENDING_PERIODIC_IMPORTED,
        AttributeId::PeriodicEnergyImported,
    ),
];

/// An import-only Electrical Energy Measurement cluster handler.
///
/// The cluster is not coupled to any other cluster, so the handler needs no
/// wiring step: construct it with [`ElecEnergyMeasHandler::new`] and chain it.
/// Configuration validation happens on the `Startup` lifecycle operation.
pub struct ElecEnergyMeasHandler<H: ElecEnergyMeasHooks> {
    dataver: Dataver,
    /// Needed to address `notify_attr_changed` and `emit_event` from
    /// [`Self::run`], which has only a [`HandlerContext`] and hence no notion
    /// of a "current" endpoint.
    endpoint_id: EndptId,
    hooks: H,
    /// Bitmask of readings awaiting a re-report and an event, fed by
    /// [`Self::out_of_band_message`] and drained by [`Self::run`].
    pending: Signal<u8>,
}

impl<H: ElecEnergyMeasHooks> ElecEnergyMeasHandler<H> {
    /// Create a new `ElecEnergyMeasHandler` with the given hooks.
    ///
    /// # Arguments
    /// - `dataver` - the cluster data version.
    /// - `endpoint_id` - the endpoint hosting this cluster instance.
    /// - `hooks` - the device-specific energy counters.
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

    /// Whether the configured FeatureMap contains all of `features`.
    fn supports_feature(features: u32) -> bool {
        H::CLUSTER.feature_map & features != 0
    }

    /// Whether `attr` is in the served set.
    fn serves(attr: AttributeId) -> bool {
        H::CLUSTER.attribute(attr as _).is_some()
    }

    /// Whether `event` is in the served set.
    fn emits(event: EventId) -> bool {
        H::CLUSTER.event(event as _).is_some()
    }

    /// The cumulative reading, normalised per section 2.12.5.2.
    fn cumulative_imported(&self) -> Option<EnergyMeasurement> {
        self.hooks
            .cumulative_energy_imported()
            .as_ref()
            .and_then(EnergyMeasurement::as_cumulative)
    }

    /// The periodic reading, normalised per section 2.12.5.2.
    fn periodic_imported(&self) -> Option<EnergyMeasurement> {
        self.hooks
            .periodic_energy_imported()
            .as_ref()
            .and_then(EnergyMeasurement::as_periodic)
    }

    /// Mark a set of readings as needing a re-report and wake [`Self::run`].
    ///
    /// Public so that a consumer holding the handler can poke it directly,
    /// besides the `notify` closure handed to [`ElecEnergyMeasHooks::run`].
    pub fn out_of_band_message(&self, message: OutOfBandMessage) {
        let bits = message.pending();

        self.pending.modify(|pending| {
            *pending |= bits;
            (true, ())
        });
    }

    /// Wait until at least one reading is pending, then take the whole mask.
    async fn wait_pending(&self) -> u8 {
        self.pending
            .wait(|pending| (*pending != 0).then(|| core::mem::take(pending)))
            .await
    }

    /// Emit one `notify_attr_changed` per pending attribute that is served.
    ///
    /// Takes an [`AttrChangeNotifier`] rather than the [`HandlerContext`] it is
    /// called with, so that the losslessness of the mask can be pinned down in
    /// a unit test with a recording notifier.
    fn notify_pending(&self, notifier: &impl AttrChangeNotifier, pending: u8) {
        for (bit, attr) in PENDING_ATTRS {
            if pending & bit != 0 && Self::serves(*attr) {
                notifier.notify_attr_changed(self.endpoint_id, Self::CLUSTER.id, *attr as AttrId);
            }
        }
    }

    /// Emit the measurement events for the pending readings.
    ///
    /// Emission is best-effort: a full event buffer must not take down the
    /// handler's `run` task, so a failure is logged and the next reading tries
    /// again.
    fn emit_pending(&self, ctx: impl HandlerContext, pending: u8) {
        if pending & PENDING_CUMULATIVE_IMPORTED != 0
            && Self::emits(EventId::CumulativeEnergyMeasured)
        {
            let reading = self.cumulative_imported();

            let emitted = CumulativeEnergyMeasured::emit_for(&ctx, self.endpoint_id, |event| {
                let event = event
                    .energy_imported()?
                    .with_some(reading, |reading, builder| write_energy(builder, reading))?;

                event.energy_exported()?.none().end()
            });

            if let Err(e) = emitted {
                warn!("Failed to emit CumulativeEnergyMeasured: {:?}", e);
            }
        }

        if pending & PENDING_PERIODIC_IMPORTED != 0 && Self::emits(EventId::PeriodicEnergyMeasured)
        {
            let reading = self.periodic_imported();

            let emitted = PeriodicEnergyMeasured::emit_for(&ctx, self.endpoint_id, |event| {
                let event = event
                    .energy_imported()?
                    .with_some(reading, |reading, builder| write_energy(builder, reading))?;

                event.energy_exported()?.none().end()
            });

            if let Err(e) = emitted {
                warn!("Failed to emit PeriodicEnergyMeasured: {:?}", e);
            }
        }
    }

    /// Check that the cluster is configured in a way this handler can serve.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message if [`ElecEnergyMeasHooks::CLUSTER`] is
    /// misconfigured. This is a programming error caught once at startup, not
    /// a runtime condition, which is why it is a panic rather than an `Error`.
    fn validate(&self) {
        if H::CLUSTER.revision != CLUSTER_REVISION {
            panic!(
                "ElectricalEnergyMeasurement validation: incorrect revision number: expected {} got {}",
                CLUSTER_REVISION, H::CLUSTER.revision
            );
        }

        if !Self::supports_feature(Feature::IMPORTED_ENERGY.bits()) {
            panic!("ElectricalEnergyMeasurement validation: the IMPE feature must be enabled - this handler only implements imported energy");
        }

        if H::CLUSTER.feature_map & !SUPPORTED_FEATURES != 0 {
            panic!(
                "ElectricalEnergyMeasurement validation: unsupported features in the feature map: 0x{:08x}. Only IMPE, CUME and PERE are implemented",
                H::CLUSTER.feature_map & !SUPPORTED_FEATURES
            );
        }

        // Section 2.12.4: CUME and PERE are a choice of which at least one must
        // be selected - without one there is no energy attribute at all.
        if !Self::supports_feature(
            Feature::CUMULATIVE_ENERGY.bits() | Feature::PERIODIC_ENERGY.bits(),
        ) {
            panic!("ElectricalEnergyMeasurement validation: one of the CUME or PERE features must be enabled");
        }

        if !Self::serves(AttributeId::Accuracy) {
            panic!("ElectricalEnergyMeasurement validation: missing required attribute: Accuracy");
        }

        // Each feature brings both an attribute and an event, and neither is
        // any use without the other.
        for (feature, attr, event) in [
            (
                Feature::CUMULATIVE_ENERGY,
                AttributeId::CumulativeEnergyImported,
                EventId::CumulativeEnergyMeasured,
            ),
            (
                Feature::PERIODIC_ENERGY,
                AttributeId::PeriodicEnergyImported,
                EventId::PeriodicEnergyMeasured,
            ),
        ] {
            if !Self::supports_feature(feature.bits()) {
                // The mirror image: an event in the served set is advertised in
                // `EventList`, and without its feature nothing would ever emit
                // it.
                if Self::emits(event) {
                    panic!(
                        "ElectricalEnergyMeasurement validation: the {:?} event is served but {:?} is not enabled",
                        event, feature
                    );
                }

                continue;
            }

            if !Self::serves(attr) {
                panic!(
                    "ElectricalEnergyMeasurement validation: {:?} is enabled but {:?} is not served",
                    feature, attr
                );
            }

            if !Self::emits(event) {
                panic!(
                    "ElectricalEnergyMeasurement validation: {:?} is enabled but the {:?} event is not served",
                    feature, event
                );
            }
        }

        // Section 2.12.6.1: the accuracy this cluster describes is that of its
        // own measurement.
        if H::ACCURACY.measurement_type != MeasurementTypeEnum::ElectricalEnergy {
            panic!(
                "ElectricalEnergyMeasurement validation: ACCURACY describes {:?}, expected ElectricalEnergy",
                H::ACCURACY.measurement_type
            );
        }

        H::ACCURACY.validate("ElectricalEnergyMeasurement");
    }
}

impl<H: ElecEnergyMeasHooks> ClusterHandler for ElecEnergyMeasHandler<H> {
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
                Either::First(_) => panic!("ElecEnergyMeasHooks::run returned; implementers MUST not return. Implementations should loop forever or await core::future::pending::<()>()."),
                Either::Second(pending) => {
                    self.notify_pending(&ctx, pending);
                    self.emit_pending(&ctx, pending);
                }
            }
        }
    }

    // Attribute accessors

    /// Section 2.12.6.1: how accurately this server measures energy. Fixed at
    /// manufacture.
    fn accuracy<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: MeasurementAccuracyStructBuilder<P>,
    ) -> Result<P, Error> {
        write_accuracy(builder, &H::ACCURACY)
    }

    /// Section 2.12.6.2: energy imported over the device's lifetime.
    fn cumulative_energy_imported<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: NullableBuilder<P, EnergyMeasurementStructBuilder<P>>,
    ) -> Result<P, Error> {
        match self.cumulative_imported() {
            Some(reading) => write_energy(builder.non_null()?, &reading),
            None => builder.null(),
        }
    }

    /// Section 2.12.6.4: energy imported during the most recent measurement
    /// period.
    fn periodic_energy_imported<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: NullableBuilder<P, EnergyMeasurementStructBuilder<P>>,
    ) -> Result<P, Error> {
        match self.periodic_imported() {
            Some(reading) => write_energy(builder.non_null()?, &reading),
            None => builder.null(),
        }
    }

    /// Section 2.12.6.6: when the lifetime counters were last reset, or null
    /// if they never have been.
    ///
    /// The exported half is always omitted: `EXPE` is rejected by
    /// [`Self::validate`], and section 2.12.6.6's fields are each conditional
    /// on their direction's feature.
    fn cumulative_energy_reset<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: NullableBuilder<P, CumulativeEnergyResetStructBuilder<P>>,
    ) -> Result<P, Error> {
        let Some(reset) = self.hooks.cumulative_energy_reset() else {
            return builder.null();
        };

        builder
            .non_null()?
            .imported_reset_timestamp(Some(Nullable::new(reset.utc)))?
            .exported_reset_timestamp(None)?
            .imported_reset_systime(Some(Nullable::new(reset.systime)))?
            .exported_reset_systime(None)?
            .end()
    }
}

/// Encode one `EnergyMeasurementStruct`.
///
/// `ApparentEnergy` and `ReactiveEnergy` are provisional in Matter 1.6 and
/// their features are rejected by [`ElecEnergyMeasHandler::validate`], so they
/// are always omitted.
fn write_energy<P>(
    builder: EnergyMeasurementStructBuilder<P>,
    reading: &EnergyMeasurement,
) -> Result<P, Error>
where
    P: TLVBuilderParent,
{
    builder
        .energy(reading.energy)?
        .start_timestamp(reading.start.utc)?
        .end_timestamp(reading.end.utc)?
        .start_systime(reading.start.systime)?
        .end_systime(reading.end.systime)?
        .apparent_energy(None)?
        .reactive_energy(None)?
        .end()
}

/// Device-specific hooks for the Electrical Energy Measurement cluster.
pub trait ElecEnergyMeasHooks {
    /// The cluster metadata, which selects the features, attributes and events
    /// this instance serves. See [`ElecEnergyMeasHandler::validate`] for what a
    /// serveable configuration has to look like.
    const CLUSTER: Cluster<'static>;

    /// The `Accuracy` attribute (section 2.12.6.1). Its `measurement_type` must
    /// be [`MeasurementTypeEnum::ElectricalEnergy`].
    ///
    /// A const because metering accuracy is a property of the hardware.
    const ACCURACY: MeasurementAccuracy;

    /// `CumulativeEnergyImported` (section 2.12.6.2): energy imported over the
    /// device's lifetime, or `None` when no reading is available.
    ///
    /// This value SHALL survive a reboot for a device that claims a lifetime
    /// total. Only called when the `CUME` feature is enabled; the default is
    /// for devices that report periodic energy only.
    ///
    /// The `start` of the returned measurement is ignored — the handler drops
    /// it, as section 2.12.5.2.2 requires.
    fn cumulative_energy_imported(&self) -> Option<EnergyMeasurement> {
        None
    }

    /// `PeriodicEnergyImported` (section 2.12.6.4): energy imported during the
    /// most recent measurement period. The server chooses the period, and
    /// consecutive periods may overlap (section 2.12.4.4).
    fn periodic_energy_imported(&self) -> Option<EnergyMeasurement> {
        None
    }

    /// `CumulativeEnergyReset` (section 2.12.6.6): when
    /// [`Self::cumulative_energy_imported`] was last set back to zero, or
    /// `None` if it never has been.
    ///
    /// Only meaningful for a device that can be reset at all - a factory reset
    /// is the usual occasion - which is why it is optional and defaults to
    /// null. A device with no wall clock answers with
    /// [`Timestamp::systime`], as everywhere else in this cluster.
    fn cumulative_energy_reset(&self) -> Option<Timestamp> {
        None
    }

    /// Background task for out-of-band notifications to the handler.
    ///
    /// This is where a device publishes a new reading: update the counter, then
    /// call `notify` so the handler re-reports the attribute and emits the
    /// matching measurement event.
    ///
    /// Note the direction. The example and the itest driver in this repository
    /// poll their simulated element on a timer, because there is nothing else
    /// a simulation can do, but that is not the shape to copy: a metering chip
    /// signals when its accumulator has moved, and this future should await
    /// *that*.
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

impl<T> ElecEnergyMeasHooks for &T
where
    T: ElecEnergyMeasHooks,
{
    const CLUSTER: Cluster<'static> = T::CLUSTER;
    const ACCURACY: MeasurementAccuracy = T::ACCURACY;

    fn cumulative_energy_imported(&self) -> Option<EnergyMeasurement> {
        (*self).cumulative_energy_imported()
    }

    fn periodic_energy_imported(&self) -> Option<EnergyMeasurement> {
        (*self).periodic_energy_imported()
    }

    async fn run<F: Fn(OutOfBandMessage)>(&self, notify: F) {
        (*self).run(notify).await
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the two things this handler decides on its own: the
    //! section 2.12.5.2 timestamp rules, and whether a cluster configuration is
    //! serveable at all.
    //!
    //! Both are context-free, so they need no live `Matter` instance.

    use embassy_futures::block_on;

    use crate::dm::clusters::app::test_util::RecordingNotifier;
    use crate::dm::clusters::decl::electrical_energy_measurement as cluster;
    use crate::dm::{AttrId, Dataver, EventId as RawEventId};
    use crate::with;

    use super::super::measurement::{MeasurementAccuracy, MeasurementAccuracyRange};
    use super::*;

    const RANGE: &[MeasurementAccuracyRange] = &[MeasurementAccuracyRange::percent(0, 1_000, 500)];

    const ENERGY_ACCURACY: MeasurementAccuracy =
        MeasurementAccuracy::new(MeasurementTypeEnum::ElectricalEnergy, 0, i64::MAX, RANGE);

    const IMPE: u32 = cluster::Feature::IMPORTED_ENERGY.bits();
    const CUME: u32 = cluster::Feature::CUMULATIVE_ENERGY.bits();
    const PERE: u32 = cluster::Feature::PERIODIC_ENERGY.bits();
    const EXPE: u32 = cluster::Feature::EXPORTED_ENERGY.bits();

    /// A mock parameterised by its feature map.
    struct MockHooks<const F: u32>;

    impl<const F: u32> ElecEnergyMeasHooks for MockHooks<F> {
        const CLUSTER: Cluster<'static> = cluster::FULL_CLUSTER
            .with_revision(2)
            .with_features(F)
            // Both the attributes and the events follow the features, so a
            // rejection has to come from the feature choice itself rather than
            // from a mismatch the mock invented. The matchers are handed the
            // feature map, which is what lets one `CLUSTER` const cover every
            // combination the const generic can name.
            .with_attrs(
                |attr, _, features| match cluster::AttributeId::try_from(attr.id) {
                    Ok(cluster::AttributeId::CumulativeEnergyImported) => features & CUME != 0,
                    Ok(cluster::AttributeId::PeriodicEnergyImported) => features & PERE != 0,
                    _ => !attr.quality.contains(crate::dm::Quality::OPTIONAL),
                },
            )
            .with_cmds(with!())
            .with_events(
                |event, _, features| match cluster::EventId::try_from(event.id) {
                    Ok(cluster::EventId::CumulativeEnergyMeasured) => features & CUME != 0,
                    Ok(cluster::EventId::PeriodicEnergyMeasured) => features & PERE != 0,
                    _ => false,
                },
            );

        const ACCURACY: MeasurementAccuracy = ENERGY_ACCURACY;
    }

    /// Enables `CUME` but keeps the matching event out of the served set.
    struct NoEventHooks;

    impl ElecEnergyMeasHooks for NoEventHooks {
        const CLUSTER: Cluster<'static> = cluster::FULL_CLUSTER
            .with_revision(2)
            .with_features(IMPE | CUME)
            .with_attrs(with!(
                required;
                cluster::AttributeId::CumulativeEnergyImported
            ))
            .with_cmds(with!())
            .with_events(with!());

        const ACCURACY: MeasurementAccuracy = ENERGY_ACCURACY;
    }

    fn handler<H: ElecEnergyMeasHooks>(hooks: H) -> ElecEnergyMeasHandler<H> {
        ElecEnergyMeasHandler::new(Dataver::new(1), 1, hooks)
    }

    // --- Section 2.12.5.2: what a reading may and may not carry ---

    /// Sections 2.12.5.2.2 and 2.12.5.2.4: a cumulative reading runs from the
    /// device's lifetime origin, so it has no start.
    #[test]
    fn a_cumulative_reading_drops_the_period_start() {
        let reading = EnergyMeasurement::periodic(
            42,
            Timestamp::both(1_000, 2_000),
            Timestamp::both(3_000, 4_000),
        );

        let normalised = unwrap!(reading.as_cumulative());

        assert_eq!(normalised.energy, 42);
        assert_eq!(normalised.start, Timestamp::default());
        assert_eq!(normalised.end, Timestamp::both(3_000, 4_000));
    }

    /// Sections 2.12.5.2.3 and 2.12.5.2.5: one of the two end fields SHALL be
    /// indicated. A reading that can say neither is not encodable, and the
    /// attribute reports null instead.
    #[test]
    fn a_reading_with_no_end_is_not_encodable() {
        let reading = EnergyMeasurement::cumulative(42, Timestamp::default());

        assert_eq!(reading.as_cumulative(), None);
    }

    /// A device with no wall clock reports uptime alone - which is exactly
    /// what section 2.12.5.2.5 asks of it.
    #[test]
    fn a_systime_only_reading_is_encodable() {
        let reading = EnergyMeasurement::cumulative(42, Timestamp::systime(5_000));

        let normalised = unwrap!(reading.as_cumulative());

        assert_eq!(normalised.end.utc, None);
        assert_eq!(normalised.end.systime, Some(5_000));
    }

    /// A period needs both of its ends.
    #[test]
    fn a_periodic_reading_needs_a_start_and_an_end() {
        let complete =
            EnergyMeasurement::periodic(42, Timestamp::systime(1_000), Timestamp::systime(2_000));
        assert!(complete.as_periodic().is_some());

        let no_start =
            EnergyMeasurement::periodic(42, Timestamp::default(), Timestamp::systime(2_000));
        assert_eq!(no_start.as_periodic(), None);

        let no_end =
            EnergyMeasurement::periodic(42, Timestamp::systime(1_000), Timestamp::default());
        assert_eq!(no_end.as_periodic(), None);
    }

    // --- Cluster configuration ---

    #[test]
    fn validate_accepts_imported_cumulative_energy() {
        handler(MockHooks::<{ IMPE | CUME }>).validate();
    }

    #[test]
    fn validate_accepts_imported_periodic_energy() {
        handler(MockHooks::<{ IMPE | PERE }>).validate();
    }

    #[test]
    fn cluster_serves_the_expected_elements() {
        let cluster = <NoEventHooks as ElecEnergyMeasHooks>::CLUSTER;

        let attrs: heapless::Vec<_, 8> = cluster
            .attributes()
            .map(|attr| attr.id)
            .filter(|id| *id < 0xF000)
            .collect();

        assert_eq!(
            attrs,
            [
                AttributeId::Accuracy as AttrId,
                AttributeId::CumulativeEnergyImported as AttrId,
            ]
        );

        // The `PERE` half of the cluster stays out of the served set.
        let with_event = <MockHooks<{ IMPE | CUME }> as ElecEnergyMeasHooks>::CLUSTER;
        let events: heapless::Vec<_, 4> = with_event.events().map(|event| event.id).collect();

        assert!(events.contains(&(EventId::CumulativeEnergyMeasured as RawEventId)));
    }

    /// The reason `pending` is a bitmask and not a `Signal<Option<_>>`: two
    /// readings landing between two turns of `run` must both be re-reported,
    /// not just the later one. A device that keeps a lifetime counter and a
    /// per-period one updates both from the same tick.
    #[test]
    fn out_of_band_messages_accumulate_without_loss() {
        let handler = handler(MockHooks::<{ IMPE | CUME | PERE }>);
        let notifier = RecordingNotifier::default();

        handler.out_of_band_message(OutOfBandMessage::CumulativeEnergyImported);
        handler.out_of_band_message(OutOfBandMessage::PeriodicEnergyImported);

        // Ready immediately - the mask is non-empty, so this does not block.
        let pending = block_on(handler.wait_pending());
        handler.notify_pending(&notifier, pending);

        assert_eq!(
            notifier.attrs(),
            [
                AttributeId::CumulativeEnergyImported as AttrId,
                AttributeId::PeriodicEnergyImported as AttrId,
            ]
        );

        // And the mask is empty again, so nothing is re-reported twice.
        assert_eq!(handler.pending.modify(|pending| (false, *pending)), 0);
    }

    /// An attribute the configuration does not serve is never re-reported,
    /// not even by `Update` - a `CUME`-only device has no periodic reading.
    #[test]
    fn unserved_readings_are_never_reported() {
        let handler = handler(MockHooks::<{ IMPE | CUME }>);
        let notifier = RecordingNotifier::default();

        handler.out_of_band_message(OutOfBandMessage::Update);
        handler.notify_pending(&notifier, block_on(handler.wait_pending()));

        assert_eq!(
            notifier.attrs(),
            [AttributeId::CumulativeEnergyImported as AttrId]
        );
    }

    #[test]
    #[should_panic(expected = "the IMPE feature must be enabled")]
    fn validate_rejects_a_cluster_without_imported_energy() {
        handler(MockHooks::<CUME>).validate();
    }

    #[test]
    #[should_panic(expected = "unsupported features in the feature map")]
    fn validate_rejects_exported_energy() {
        handler(MockHooks::<{ IMPE | CUME | EXPE }>).validate();
    }

    #[test]
    #[should_panic(expected = "one of the CUME or PERE features must be enabled")]
    fn validate_rejects_a_cluster_with_neither_cume_nor_pere() {
        handler(MockHooks::<IMPE>).validate();
    }

    /// Each feature brings an attribute *and* an event; a reading nobody can
    /// subscribe to is not what the spec asks for.
    #[test]
    #[should_panic(expected = "event is not served")]
    fn validate_rejects_cume_without_its_event() {
        handler(NoEventHooks).validate();
    }
}
