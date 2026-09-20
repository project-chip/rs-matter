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

//! The measurement-accuracy description shared by the electrical measurement
//! clusters.
//!
//! `MeasurementAccuracyStruct` and `MeasurementAccuracyRangeStruct` are
//! *global* Matter data types, so the same description and the same TLV writer
//! serve both [`super::elec_pwr_meas`] (where `Accuracy` is a list, one entry
//! per measurement type) and [`super::elec_energy_meas`] (where it is a single
//! struct).
//!
//! The accuracy of a device's metering hardware is fixed at manufacture, so
//! both clusters take it as an associated const on their hooks trait and this
//! module only has to encode it.

use crate::dm::clusters::decl::globals::{MeasurementAccuracyStructBuilder, MeasurementTypeEnum};
use crate::error::Error;
use crate::im::Percent100ths;
use crate::tlv::TLVBuilderParent;

/// A `MeasurementAccuracyStruct` (Matter 1.6 Application Cluster spec section
/// 2.1.4.4): how accurately the server measures one quantity, over one or more
/// ranges of that quantity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MeasurementAccuracy {
    /// Which quantity this entry describes.
    pub measurement_type: MeasurementTypeEnum,
    /// Whether the quantity is actually measured, as opposed to estimated from
    /// other measurements or taken from a nameplate rating.
    pub measured: bool,
    /// The smallest value the server can measure, in the quantity's own unit.
    pub min_measured_value: i64,
    /// The largest value the server can measure, in the quantity's own unit.
    pub max_measured_value: i64,
    /// The accuracy over each range of the measured span. At least one entry;
    /// see [`MeasurementAccuracy::validate`].
    pub ranges: &'static [MeasurementAccuracyRange],
}

impl MeasurementAccuracy {
    /// A quantity the device genuinely measures (as opposed to estimating it
    /// from other readings or taking it from a nameplate rating).
    pub const fn new(
        measurement_type: MeasurementTypeEnum,
        min_measured_value: i64,
        max_measured_value: i64,
        ranges: &'static [MeasurementAccuracyRange],
    ) -> Self {
        Self {
            measurement_type,
            measured: true,
            min_measured_value,
            max_measured_value,
            ranges,
        }
    }

    /// Check that this description is encodable and self-consistent.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message naming `cluster`. Like the rest of the
    /// cluster-configuration validation, this is a programming error caught
    /// once at startup rather than a runtime condition.
    pub fn validate(&self, cluster: &str) {
        if self.min_measured_value > self.max_measured_value {
            panic!(
                "{} validation: accuracy for {:?} has MinMeasuredValue ({}) above MaxMeasuredValue ({})",
                cluster, self.measurement_type, self.min_measured_value, self.max_measured_value
            );
        }

        // `AccuracyRanges` is mandatory and a list with no entries would say
        // nothing about the accuracy it exists to describe.
        if self.ranges.is_empty() {
            panic!(
                "{} validation: accuracy for {:?} has no AccuracyRanges entries",
                cluster, self.measurement_type
            );
        }

        for range in self.ranges {
            range.validate(cluster, self.measurement_type);
        }
    }
}

/// One entry of a `MeasurementAccuracyStruct`'s `AccuracyRanges` list
/// (spec section 2.1.4.5): the accuracy that holds between `range_min` and
/// `range_max`.
///
/// The percentage and fixed-quantity field groups are a `choice` of which at
/// least one must be present, and within each group the fields cascade — a
/// `*_min` is only meaningful alongside its `*_max`, and a `*_typical` only
/// alongside its `*_min`. [`MeasurementAccuracyRange::validate`] enforces that.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MeasurementAccuracyRange {
    /// The lower bound of the span this entry describes.
    pub range_min: i64,
    /// The upper bound of the span this entry describes.
    pub range_max: i64,
    /// Worst-case error as a percentage, in hundredths of a percent.
    pub percent_max: Option<Percent100ths>,
    /// Best-case error as a percentage, in hundredths of a percent.
    pub percent_min: Option<Percent100ths>,
    /// Typical error as a percentage, in hundredths of a percent.
    pub percent_typical: Option<Percent100ths>,
    /// Worst-case error as a fixed quantity, in the measured quantity's unit.
    pub fixed_max: Option<u64>,
    /// Best-case error as a fixed quantity.
    pub fixed_min: Option<u64>,
    /// Typical error as a fixed quantity.
    pub fixed_typical: Option<u64>,
}

impl MeasurementAccuracyRange {
    /// A range whose accuracy is given as a worst-case percentage, in
    /// hundredths of a percent (so 5% is `500`).
    pub const fn percent(range_min: i64, range_max: i64, percent_max: Percent100ths) -> Self {
        Self {
            range_min,
            range_max,
            percent_max: Some(percent_max),
            percent_min: None,
            percent_typical: None,
            fixed_max: None,
            fixed_min: None,
            fixed_typical: None,
        }
    }

    /// Check the `choice` and cascade rules described on the struct.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message naming `cluster`.
    pub fn validate(&self, cluster: &str, measurement_type: MeasurementTypeEnum) {
        if self.range_min > self.range_max {
            panic!(
                "{} validation: accuracy range for {:?} has RangeMin ({}) above RangeMax ({})",
                cluster, measurement_type, self.range_min, self.range_max
            );
        }

        if self.percent_max.is_none() && self.fixed_max.is_none() {
            panic!(
                "{} validation: accuracy range for {:?} declares neither PercentMax nor FixedMax; at least one of the two groups is required",
                cluster, measurement_type
            );
        }

        if self.percent_min.is_some() && self.percent_max.is_none() {
            panic!(
                "{} validation: accuracy range for {:?} has PercentMin without PercentMax",
                cluster, measurement_type
            );
        }

        if self.percent_typical.is_some() && self.percent_min.is_none() {
            panic!(
                "{} validation: accuracy range for {:?} has PercentTypical without PercentMin",
                cluster, measurement_type
            );
        }

        if self.fixed_min.is_some() && self.fixed_max.is_none() {
            panic!(
                "{} validation: accuracy range for {:?} has FixedMin without FixedMax",
                cluster, measurement_type
            );
        }

        if self.fixed_typical.is_some() && self.fixed_min.is_none() {
            panic!(
                "{} validation: accuracy range for {:?} has FixedTypical without FixedMin",
                cluster, measurement_type
            );
        }
    }
}

/// Encode one `MeasurementAccuracyStruct`, including its nested
/// `AccuracyRanges` list.
pub(crate) fn write_accuracy<P>(
    builder: MeasurementAccuracyStructBuilder<P>,
    accuracy: &MeasurementAccuracy,
) -> Result<P, Error>
where
    P: TLVBuilderParent,
{
    let mut ranges = builder
        .measurement_type(accuracy.measurement_type)?
        .measured(accuracy.measured)?
        .min_measured_value(accuracy.min_measured_value)?
        .max_measured_value(accuracy.max_measured_value)?
        .accuracy_ranges()?;

    for range in accuracy.ranges {
        ranges = ranges
            .push()?
            .range_min(range.range_min)?
            .range_max(range.range_max)?
            .percent_max(range.percent_max)?
            .percent_min(range.percent_min)?
            .percent_typical(range.percent_typical)?
            .fixed_max(range.fixed_max)?
            .fixed_min(range.fixed_min)?
            .fixed_typical(range.fixed_typical)?
            .end()?;
    }

    ranges.end()?.end()
}

#[cfg(test)]
mod tests {
    //! Round-trip tests for the accuracy encoder.
    //!
    //! `MeasurementAccuracyStructBuilder` is a typestate builder whose fields
    //! must be written in order, and whose `AccuracyRanges` list nests a second
    //! builder inside the first. Getting that wrong produces TLV that still
    //! encodes but decodes to the wrong fields, so the tests read the bytes
    //! back rather than just asserting the writer returned `Ok`.

    use crate::dm::clusters::decl::globals::{
        MeasurementAccuracyStruct, MeasurementAccuracyStructBuilder, MeasurementTypeEnum,
    };
    use crate::tlv::{TLVElement, TLVTag, TLVWriteParent};
    use crate::utils::storage::WriteBuf;

    use super::{write_accuracy, MeasurementAccuracy, MeasurementAccuracyRange};

    const RANGES: &[MeasurementAccuracyRange] = &[
        MeasurementAccuracyRange::percent(0, 1_000, 500),
        MeasurementAccuracyRange {
            range_min: 1_001,
            range_max: 10_000,
            percent_max: Some(250),
            percent_min: Some(100),
            percent_typical: Some(150),
            fixed_max: None,
            fixed_min: None,
            fixed_typical: None,
        },
    ];

    const ACCURACY: MeasurementAccuracy =
        MeasurementAccuracy::new(MeasurementTypeEnum::ActivePower, 0, 10_000, RANGES);

    /// Encode `accuracy` and hand the bytes to `f` as a parsed struct.
    fn round_trip(accuracy: &MeasurementAccuracy, f: impl FnOnce(MeasurementAccuracyStruct<'_>)) {
        let mut buf = [0u8; 256];
        let mut wb = WriteBuf::new(&mut buf);

        {
            let builder = unwrap!(MeasurementAccuracyStructBuilder::new(
                TLVWriteParent::new((), &mut wb),
                &TLVTag::Anonymous
            ));

            unwrap!(write_accuracy(builder, accuracy));
        }

        f(MeasurementAccuracyStruct::new(TLVElement::new(
            wb.as_slice(),
        )));
    }

    #[test]
    fn accuracy_round_trips_its_scalar_fields() {
        round_trip(&ACCURACY, |parsed| {
            assert_eq!(
                unwrap!(parsed.measurement_type()),
                MeasurementTypeEnum::ActivePower
            );
            assert!(unwrap!(parsed.measured()));
            assert_eq!(unwrap!(parsed.min_measured_value()), 0);
            assert_eq!(unwrap!(parsed.max_measured_value()), 10_000);
        });
    }

    #[test]
    fn accuracy_round_trips_its_nested_ranges() {
        round_trip(&ACCURACY, |parsed| {
            let ranges = unwrap!(parsed.accuracy_ranges());

            let mut iter = ranges.iter();

            let first = unwrap!(unwrap!(iter.next()));
            assert_eq!(unwrap!(first.range_min()), 0);
            assert_eq!(unwrap!(first.range_max()), 1_000);
            assert_eq!(unwrap!(first.percent_max()), Some(500));
            // The cascade fields this range leaves out must stay absent, not
            // arrive as zeroes.
            assert_eq!(unwrap!(first.percent_min()), None);
            assert_eq!(unwrap!(first.fixed_max()), None);

            let second = unwrap!(unwrap!(iter.next()));
            assert_eq!(unwrap!(second.range_min()), 1_001);
            assert_eq!(unwrap!(second.percent_max()), Some(250));
            assert_eq!(unwrap!(second.percent_min()), Some(100));
            assert_eq!(unwrap!(second.percent_typical()), Some(150));

            assert!(iter.next().is_none());
        });
    }

    #[test]
    #[should_panic(expected = "has no AccuracyRanges entries")]
    fn validate_rejects_an_empty_range_list() {
        MeasurementAccuracy::new(MeasurementTypeEnum::Voltage, 0, 1, &[]).validate("Test");
    }

    #[test]
    #[should_panic(expected = "above MaxMeasuredValue")]
    fn validate_rejects_an_inverted_measured_span() {
        MeasurementAccuracy::new(MeasurementTypeEnum::Voltage, 10, 1, RANGES).validate("Test");
    }

    #[test]
    #[should_panic(expected = "declares neither PercentMax nor FixedMax")]
    fn validate_rejects_a_range_with_no_accuracy() {
        const EMPTY: &[MeasurementAccuracyRange] = &[MeasurementAccuracyRange {
            range_min: 0,
            range_max: 1,
            percent_max: None,
            percent_min: None,
            percent_typical: None,
            fixed_max: None,
            fixed_min: None,
            fixed_typical: None,
        }];

        MeasurementAccuracy::new(MeasurementTypeEnum::Voltage, 0, 1, EMPTY).validate("Test");
    }

    #[test]
    #[should_panic(expected = "has PercentTypical without PercentMin")]
    fn validate_rejects_a_broken_percent_cascade() {
        const BROKEN: &[MeasurementAccuracyRange] = &[MeasurementAccuracyRange {
            percent_typical: Some(100),
            ..MeasurementAccuracyRange::percent(0, 1, 500)
        }];

        MeasurementAccuracy::new(MeasurementTypeEnum::Voltage, 0, 1, BROKEN).validate("Test");
    }
}
