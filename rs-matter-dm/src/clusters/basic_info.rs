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

//! This module contains the implementation of the Basic Information cluster and its handler.

use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext, TransactionId, WriteContext};
use crate::error::{Error, ErrorCode};
use crate::persist::Persist;
use crate::tlv::{
    FromTLV, Nullable, NullableBuilder, TLVBuilderParent, TLVElement, TLVTag, TLVWrite,
    Utf8StrBuilder,
};
use crate::utils::storage::WriteBuf;
use crate::{except, with, Matter};
use rs_matter_node::Transaction as _;

pub use crate::basic_info::{
    BasicInfoConfig, BasicInfoSettings, CapabilityMinima, DeviceLocation, DeviceLocationConfig,
    PairingHintFlags, ProductAppearance, ProductColor, ProductFinish, DEFAULT_DATA_MODEL_REVISION,
    DEFAULT_MATTER_SPEC_VERSION, DEFAULT_MAX_PATHS_PER_INVOKE,
    DEFAULT_MIN_SUBSCRIPTION_MAX_INTERVAL_SECS,
};
pub use crate::dm::clusters::decl::basic_information::*;
pub use crate::dm::clusters::decl::globals::{
    AreaTypeTag, LocationDescriptorStruct, LocationDescriptorStructBuilder,
};

/// The system implementation of a handler for the Basic Information Matter cluster.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BasicInfoHandler<'a> {
    dataver: Dataver,
    matter: &'a Matter<'a>,
}

impl<'a> BasicInfoHandler<'a> {
    /// Create a new instance of `BasicInfoHandler` with the given `Dataver`,
    /// serving the basic information of `matter`
    pub fn new(dataver: Dataver, matter: &'a Matter<'a>) -> Self {
        Self { dataver, matter }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    fn config(&self) -> &'a BasicInfoConfig<'a> {
        self.matter.dev_det()
    }

    fn with_settings<F, R>(&self, transaction_id: TransactionId, f: F) -> Result<R, Error>
    where
        F: FnOnce(&mut BasicInfoSettings) -> Result<R, Error>,
    {
        transaction_id.with_state(self.matter, |state| f(state.basic_info_settings))
    }
}

/// `BasicInformation` cluster metadata that additionally advertises the
/// provisional `DeviceLocation` attribute (admin-writable, persisted in
/// [`BasicInfoSettings`]).
///
/// Use this in place of [`BasicInfoHandler::CLUSTER`] to serve the attribute -
/// the handler itself always implements it. It is deliberately not the
/// default: the attribute is provisional, and reference test suites that pin
/// `BasicInformation::AttributeList` to an exact set reject its presence.
///
/// The initial value is `Null`; set [`BasicInfoConfig::device_location`] for
/// a device whose location is factory-provisioned.
pub const CLUSTER_DEVICE_LOCATION: Cluster<'static> = FULL_CLUSTER
    .with_attrs(except!(AttributeId::Reachable))
    .with_cmds(with!());

impl ClusterHandler for BasicInfoHandler<'_> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        // Hide `Reachable` (TODO) from the default metadata.
        //
        // `DeviceLocation` IS implemented (see `device_location` /
        // `set_device_location` below) but stays out of the default metadata
        // because it is provisional: upstream's reference apps do not
        // advertise it, and test suites that pin `AttributeList` to an exact
        // set (e.g. the `TestBasicInformation` YAML) reject its presence.
        // Opt in with [`CLUSTER_DEVICE_LOCATION`].
        .with_attrs(except!(
            AttributeId::Reachable | AttributeId::DeviceLocation
        ))
        .with_cmds(with!());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn data_model_revision(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(self.config().data_model_revision)
    }

    fn vendor_id(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(self.config().vid)
    }

    fn vendor_name<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(self.config().vendor_name)
    }

    fn product_id(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(self.config().pid)
    }

    fn product_name<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(self.config().product_name)
    }

    fn hardware_version(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(self.config().hw_ver)
    }

    fn hardware_version_string<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(self.config().hw_ver_str)
    }

    fn software_version(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.config().sw_ver)
    }

    fn software_version_string<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(self.config().sw_ver_str)
    }

    fn node_label<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        self.with_settings(ctx.transaction_id(), |settings| {
            out.set(settings.node_label.as_str())
        })
    }

    fn set_node_label(&self, ctx: impl WriteContext, label: &str) -> Result<(), Error> {
        if label.len() > 32 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let mut persist = Persist::new(ctx.kv());

        self.with_settings(ctx.transaction_id(), |settings| {
            settings.node_label.clear();
            settings
                .node_label
                .push_str(label)
                .map_err(|_| ErrorCode::ConstraintError)?;

            settings.store_persist(&mut persist)
        })?;

        persist.run()
    }

    fn location<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        // Until a value is set at runtime (`Location` write /
        // `SetRegulatoryConfig`), report the factory default from
        // `BasicInfoConfig`, falling back to the "unknown" country code.
        let config = self.config();

        self.with_settings(ctx.transaction_id(), |settings| {
            out.set(
                settings
                    .location
                    .as_deref()
                    .or(config.location)
                    .unwrap_or("XX"),
            )
        })
    }

    fn set_location(&self, ctx: impl WriteContext, location: &str) -> Result<(), Error> {
        if location.len() != 2 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let mut persist = Persist::new(ctx.kv());

        self.with_settings(ctx.transaction_id(), |settings| {
            settings.set_location(location);

            settings.store_persist(&mut persist)
        })?;

        persist.run()
    }

    fn capability_minima<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: CapabilityMinimaStructBuilder<P>,
    ) -> Result<P, Error> {
        let cm = self.config().capability_minima;

        builder
            .case_sessions_per_fabric(cm.case_sessions_per_fabric)?
            .subscriptions_per_fabric(cm.subscriptions_per_fabric)?
            .simultaneous_invocations_supported(Some(cm.simultaneous_invocations_supported))?
            .simultaneous_writes_supported(Some(cm.simultaneous_writes_supported))?
            .read_paths_supported(Some(cm.read_paths_supported))?
            .subscribe_paths_supported(Some(cm.subscribe_paths_supported))?
            .end()
    }

    fn specification_version(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.config().specification_version)
    }

    fn max_paths_per_invoke(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(self.config().max_paths_per_invoke)
    }

    fn configuration_version(&self, ctx: impl ReadContext) -> Result<u32, Error> {
        // Non-volatile, runtime-mutable. Lives in `BasicInfoSettings`,
        // bumped via `InteractionModel::bump_configuration_version`.
        self.with_settings(ctx.transaction_id(), |settings| {
            Ok(settings.configuration_version)
        })
    }

    // Deliberately outlined (`inline(never)`): inlining duplicates the
    // builder chain in every read-dispatch instantiation (flash size)
    #[inline(never)]
    fn device_location<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: NullableBuilder<P, LocationDescriptorStructBuilder<P>>,
    ) -> Result<P, Error> {
        let config = self.config();

        self.with_settings(ctx.transaction_id(), |settings| {
            // An admin-written value - including an explicitly-written `Null`
            // - takes precedence; until one exists, report the factory
            // default from `BasicInfoConfig`, falling back to `Null`.
            let (location_name, floor_number, area_type) = match settings.device_location.as_ref() {
                Some(location) => match location.as_opt_ref() {
                    Some(location) => (
                        location.location_name.as_str(),
                        location.floor_number,
                        location.area_type,
                    ),
                    None => return builder.null(),
                },
                None => match config.device_location {
                    Some(location) => (
                        location.location_name,
                        location.floor_number,
                        location.area_type,
                    ),
                    None => return builder.null(),
                },
            };

            builder
                .non_null()?
                .location_name(location_name)?
                .floor_number(Nullable::new(floor_number))?
                .area_type(Nullable::new(
                    area_type.map(area_type_from_value).transpose()?,
                ))?
                .end()
        })
    }

    // Deliberately outlined (`inline(never)`): cold path with sizeable
    // TLV-parsing and persistence code (flash size)
    #[inline(never)]
    fn set_device_location(
        &self,
        ctx: impl WriteContext,
        value: Nullable<LocationDescriptorStruct<'_>>,
    ) -> Result<(), Error> {
        let mut persist = Persist::new(ctx.kv());

        self.with_settings(ctx.transaction_id(), |settings| {
            if let Some(value) = value.as_opt_ref() {
                // Parse and validate everything up-front, so that a failed
                // write leaves the stored value intact
                let location_name = value.location_name()?;
                if location_name.len() > 128 {
                    return Err(ErrorCode::ConstraintError.into());
                }

                let floor_number = value.floor_number()?.into_option();
                let area_type = value
                    .area_type()?
                    .into_option()
                    .map(|area_type| area_type as u8);

                // ... and then update the stored value in-place: going
                // through an owned `DeviceLocation` temporary would move the
                // ~150-byte value several times through the stack (flash and
                // stack size)
                let location = settings.device_location.get_or_insert_with(Nullable::none);
                if location.is_none() {
                    *location = Nullable::some(DeviceLocation::new());
                }

                let location = unwrap!(location.as_opt_mut());

                location.location_name.clear();
                unwrap!(location.location_name.push_str(location_name));
                location.floor_number = floor_number;
                location.area_type = area_type;
            } else {
                settings.device_location = Some(Nullable::none());
            }

            settings.store_persist(&mut persist)
        })?;

        persist.run()
    }

    fn handle_mfg_specific_ping(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    fn manufacturing_date<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(self.config().manufacturing_date)
    }

    fn part_number<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(self.config().part_number)
    }

    fn product_url<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(self.config().product_url)
    }

    fn product_label<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(self.config().product_label)
    }

    fn serial_number<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(self.config().serial_no)
    }

    fn local_config_disabled(&self, ctx: impl ReadContext) -> Result<bool, Error> {
        self.with_settings(ctx.transaction_id(), |settings| {
            Ok(settings.local_config_disabled)
        })
    }

    fn set_local_config_disabled(&self, ctx: impl WriteContext, value: bool) -> Result<(), Error> {
        let mut persist = Persist::new(ctx.kv());

        self.with_settings(ctx.transaction_id(), |settings| {
            settings.local_config_disabled = value;

            settings.store_persist(&mut persist)
        })?;

        persist.run()
    }

    fn unique_id<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(self.config().unique_id)
    }

    fn product_appearance<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ProductAppearanceStructBuilder<P>,
    ) -> Result<P, Error> {
        let appearance = self.config().product_appearance;

        builder
            .finish(product_finish_to_cluster(appearance.finish))?
            .primary_color(Nullable::new(
                appearance.color.map(product_color_to_cluster),
            ))?
            .end()
    }
}

/// Convert a stored area type value to the `AreaTypeTag` enum
fn area_type_from_value(value: u8) -> Result<AreaTypeTag, Error> {
    // The generated enum converts from TLV only
    let mut buf = [0; 2];
    let mut wb = WriteBuf::new(&mut buf);
    wb.u8(&TLVTag::Anonymous, value)?;

    AreaTypeTag::from_tlv(&TLVElement::new(wb.as_slice()))
}

/// Convert a product finish of the node to the cluster's one
fn product_finish_to_cluster(finish: ProductFinish) -> ProductFinishEnum {
    match finish {
        ProductFinish::Other => ProductFinishEnum::Other,
        ProductFinish::Matte => ProductFinishEnum::Matte,
        ProductFinish::Satin => ProductFinishEnum::Satin,
        ProductFinish::Polished => ProductFinishEnum::Polished,
        ProductFinish::Rugged => ProductFinishEnum::Rugged,
        ProductFinish::Fabric => ProductFinishEnum::Fabric,
    }
}

/// Convert a product color of the node to the cluster's one
fn product_color_to_cluster(color: ProductColor) -> ColorEnum {
    match color {
        ProductColor::Black => ColorEnum::Black,
        ProductColor::Navy => ColorEnum::Navy,
        ProductColor::Green => ColorEnum::Green,
        ProductColor::Teal => ColorEnum::Teal,
        ProductColor::Maroon => ColorEnum::Maroon,
        ProductColor::Purple => ColorEnum::Purple,
        ProductColor::Olive => ColorEnum::Olive,
        ProductColor::Gray => ColorEnum::Gray,
        ProductColor::Blue => ColorEnum::Blue,
        ProductColor::Lime => ColorEnum::Lime,
        ProductColor::Aqua => ColorEnum::Aqua,
        ProductColor::Red => ColorEnum::Red,
        ProductColor::Fuchsia => ColorEnum::Fuchsia,
        ProductColor::Yellow => ColorEnum::Yellow,
        ProductColor::White => ColorEnum::White,
        ProductColor::Nickel => ColorEnum::Nickel,
        ProductColor::Chrome => ColorEnum::Chrome,
        ProductColor::Brass => ColorEnum::Brass,
        ProductColor::Copper => ColorEnum::Copper,
        ProductColor::Silver => ColorEnum::Silver,
        ProductColor::Gold => ColorEnum::Gold,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{area_type_from_value, AreaTypeTag};

    #[test]
    fn area_type_from_its_value() {
        assert_eq!(
            area_type_from_value(AreaTypeTag::Kitchen as u8).unwrap(),
            AreaTypeTag::Kitchen
        );
        assert!(area_type_from_value(u8::MAX).is_err());
    }
}
