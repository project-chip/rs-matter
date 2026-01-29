/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

use core::str::FromStr;

use crate::dm::subscriptions::DEFAULT_MAX_SUBSCRIPTIONS;
use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext, WriteContext};
use crate::error::{Error, ErrorCode};
use crate::fabric::MAX_FABRICS;
use crate::tlv::{FromTLV, Nullable, TLVBuilderParent, TLVElement, TLVTag, ToTLV, Utf8StrBuilder};
use crate::transport::exchange::Exchange;
use crate::transport::session::MAX_SESSIONS;
use crate::utils::bitflags::bitflags;
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::WriteBuf;
use crate::{except, with};

pub use crate::dm::clusters::decl::basic_information::*;
pub use crate::dm::clusters::decl::general_commissioning::RegulatoryLocationTypeEnum;

/// The default Matter App Clusters specification version
///
/// Currently set to V1.4.2.0
pub const DEFAULT_MATTER_SPEC_VERSION: u32 = 0x01040200;

/// The default Matter Data Model revision
///
/// Currently set to V19, which was released with Matter Core spec V1.4.2
pub const DEFAULT_DATA_MODEL_REVISION: u16 = 19;

/// The default maximum number of paths that can be included in an Invoke request
///
/// Set to 1
pub const DEFAULT_MAX_PATHS_PER_INVOKE: u16 = 1;

bitflags! {
    #[repr(transparent)]
    #[derive(Default)]
    #[cfg_attr(not(feature = "defmt"), derive(Debug, Copy, Clone, Eq, PartialEq, Hash))]
    pub struct PairingHintFlags: u32 {
        /// Power Cycle False The Device will automatically enter Commissioning Mode upon
        /// power cycle (unplug/replug, remove/re-insert batteries).
        /// This bit SHALL be set to 1 for devices using Standard Commissioning Flow,
        /// and set to 0 otherwise.
        const POWER_CYCLE = 0x0000_0001;
        /// This SHALL be set to 1 for devices requiring Custom Commissioning
        /// Flow before they can be available for Commissioning by any Commissioner.
        /// For such a flow, the user SHOULD be sent to the URL specified in the
        /// CommissioningCustomFlowUrl of the DeviceModel schema entry indexed by the
        /// Vendor ID and Product ID (e.g., as found in the announcement) in the
        /// Distributed Compliance Ledger.
        const DEV_MANUFACTURER_URL = 0x0000_0002;
        /// The Device has been commissioned. Any Administrator that commissioned the
        /// device provides a user interface that may be used to put the device
        /// into Commissioning Mode.
        const ADMINISTRATOR = 0x0000_0004;
        /// The settings menu on the Device provides instructions to put it
        /// into Commissioning Mode.
        const SETTINGS_MENU = 0x0000_0008;
        /// The PI key/value pair describes a custom way to put the Device into
        /// Commissioning Mode. This Custom Instruction option is NOT recommended
        /// for use by a Device that does not have knowledge of the user's language preference.
        const CUSTOM_INSTRUCTION = 0x0000_0010;
        /// The Device Manual provides special instructions to put the Device
        /// into Commissioning Mode (see Section 11.23.5.8, "UserManualUrl" in the Core Spec).
        /// This is a catchall option to capture user interactions that are not codified by
        /// other options in this flags type.
        const DEVICE_MANUAL = 0x0000_0020;
        /// The Device will enter Commissioning Mode when reset button is pressed.
        const PRESS_RESET_BUTTON = 0x0000_0040;
        /// The Device will enter Commissioning Mode when reset button is pressed when applying power to it.
        const PRESS_RESET_BUTTON_WITH_POWER = 0x0000_0080;
        /// The Device will enter Commissioning Mode when reset button is pressed for N seconds.
        /// The exact value of N SHALL be made available via PI key.
        const PRESS_RESET_BUTTON_FOR_N_SECONDS = 0x0000_0100;
        /// The Device will enter Commissioning Mode when reset button is pressed until associated light blinks.
        /// Information on color of light MAY be made available via PI key.
        const PRESS_RESET_BUTTON_UNTIL_LIGHT_BLINKS = 0x0000_0200;
        /// The Device will enter Commissioning Mode when reset button is pressed for N seconds
        /// when applying power to it. The exact value of N SHALL be made available via PI key.
        const PRESS_RESET_BUTTON_FOR_N_SECONDS_WITH_POWER = 0x0000_0400;
        /// The Device will enter Commissioning Mode when reset button is pressed until associated
        /// light blinks when applying power to the Device. Information on color of light MAY be
        /// made available via PI key.
        const PRESS_RESET_BUTTON_UNTIL_LIGHT_BLINKS_WITH_POWER = 0x0000_0800;
        /// The Device will enter Commissioning Mode when reset button is pressed N times
        /// with maximum 1 second between each press. The exact value of N SHALL be made available via PI key.
        const PRESS_RESET_BUTTON_N_TIMES = 0x0000_1000;
        /// The Device will enter Commissioning Mode when setup button is pressed.
        const PRESS_SETUP_BUTTON = 0x0000_2000;
        /// The Device will enter Commissioning Mode when setup button is pressed when applying power to it.
        const PRESS_SETUP_BUTTON_WITH_POWER = 0x0000_4000;
        /// The Device will enter Commissioning Mode when setup button is pressed for N seconds.
        /// The exact value of N SHALL be made available via PI key.
        const PRESS_SETUP_BUTTON_FOR_N_SECONDS = 0x0000_8000;
        /// The Device will enter Commissioning Mode when setup button is pressed until associated
        /// light blinks. Information on color of light MAY be made available via PI key.
        const PRESS_SETUP_BUTTON_UNTIL_LIGHT_BLINKS = 0x0001_0000;
        /// The Device will enter Commissioning Mode when setup button is pressed for N seconds
        /// when applying power to it. The exact value of N SHALL be made available via PI key.
        const PRESS_SETUP_BUTTON_FOR_N_SECONDS_WITH_POWER = 0x0002_0000;
        /// The Device will enter Commissioning Mode when setup button is pressed until associated
        /// light blinks when applying power to the Device. Information on color of light MAY be
        /// made available via PI key.
        const PRESS_SETUP_BUTTON_UNTIL_LIGHT_BLINKS_WITH_POWER = 0x0004_0000;
        /// The Device will enter Commissioning Mode when setup button is pressed N times with
        /// maximum 1 second between each press. The exact value of N SHALL be made available via PI key.
        const PRESS_SETUP_BUTTON_N_TIMES = 0x0008_0000;
    }
}

pub const DEFAULT_MATTER_CONFIGURATION_VERSION: u32 = 1;

/// Basic information which is immutable
/// (i.e. valid for the lifetime of the device firmware)
///
/// Note that some of the fields will be reported only if their corresponding optional attributes are enabled.
///
/// By default, `BasicInfoHandler::CLUSTER` enables ALL optional attributes except `reachable` which is only valid for
/// bridged devices.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BasicInfoConfig<'a> {
    /// Vendor name (up to 32 characters)
    pub vendor_name: &'a str,
    /// Vendor ID
    pub vid: u16,
    /// Product name (up to 32 characters)
    pub product_name: &'a str,
    /// Product ID
    pub pid: u16,
    /// Hardware version
    pub hw_ver: u16,
    /// Hardware version string (up to 64 characters)
    pub hw_ver_str: &'a str,
    /// Software version
    pub sw_ver: u32,
    /// Software version string (up to 64 characters)
    pub sw_ver_str: &'a str,
    /// Manufacturing date (up to 16 characters)
    pub manufacturing_date: &'a str,
    /// Part number (up to 32 characters)
    pub part_number: &'a str,
    /// Product URL (up to 256 characters)
    pub product_url: &'a str,
    /// Product label (up to 64 characters)
    pub product_label: &'a str,
    /// Serial number (up to 32 characters)
    pub serial_no: &'a str,
    /// Unique ID (up to 64 characters)
    pub unique_id: &'a str,
    /// Capability Minima
    pub capability_minima: CapabilityMinima,
    /// Product Appearance
    pub product_appearance: ProductAppearance,
    /// Specification Version
    pub specification_version: u32,
    /// Data Model Revision
    pub data_model_revision: u16,
    /// Max Paths Per Invoke
    pub max_paths_per_invoke: u16,
    pub configuration_version: u32,
    /// Device Name
    ///
    /// Not a real attribute; used in the mDNS commissioning advertisement
    pub device_name: &'a str,
    /// Device Type
    ///
    /// Not a real attribute; used in the mDNS commissioning advertisement
    pub device_type: Option<u16>,
    /// Pairing Hint
    ///
    /// Not a real attribute; used in the mDNS commissioning advertisement
    pub pairing_hint: PairingHintFlags,
    /// Pairing Instruction
    ///
    /// Not a real attribute; used in the mDNS commissioning advertisement
    pub pairing_instruction: &'a str,
    /// Session Active Interval in ms
    /// If not specified, defaults to 300
    ///
    /// Not a real attribute, just used to configure the session timeouts
    pub sai: Option<u16>,
    /// Session Idle Interval in ms
    /// If not specified, defaults to 5000
    ///
    /// Not a real attribute, just used to configure the session timeouts
    pub sii: Option<u16>,
}

impl BasicInfoConfig<'_> {
    pub const fn new() -> Self {
        Self {
            vid: 0,
            pid: 0,
            hw_ver: 0,
            hw_ver_str: "",
            sw_ver: 0,
            sw_ver_str: "",
            serial_no: "",
            product_name: "",
            vendor_name: "",
            manufacturing_date: "",
            part_number: "",
            product_url: "",
            product_label: "",
            unique_id: "",
            capability_minima: CapabilityMinima::new(),
            product_appearance: ProductAppearance::new(),
            specification_version: DEFAULT_MATTER_SPEC_VERSION,
            data_model_revision: DEFAULT_DATA_MODEL_REVISION,
            max_paths_per_invoke: DEFAULT_MAX_PATHS_PER_INVOKE,
            configuration_version: DEFAULT_MATTER_CONFIGURATION_VERSION,
            device_name: "",
            device_type: None,
            pairing_hint: PairingHintFlags::empty(),
            pairing_instruction: "",
            sai: None,
            sii: None,
        }
    }
}

impl Default for BasicInfoConfig<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Capability Minima as reported in the Basic Information cluster
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CapabilityMinima {
    /// Maximum CASE sessions per fabric
    pub case_sessions_per_fabric: u16,
    /// Maximum subscriptions per fabric
    pub subscriptions_per_fabric: u16,
}

impl CapabilityMinima {
    /// Create a default instance of `CapabilityMinima`,
    /// with actual CASE sessions per fabric and subscriptions per fabric based on `DEFAULT_MAX_SUBSCRIPTIONS`.
    pub const fn new() -> Self {
        Self {
            case_sessions_per_fabric: (MAX_SESSIONS / MAX_FABRICS) as _,
            subscriptions_per_fabric: (DEFAULT_MAX_SUBSCRIPTIONS / MAX_FABRICS) as _,
        }
    }
}

impl Default for CapabilityMinima {
    fn default() -> Self {
        Self::new()
    }
}

/// Product Appearance as reported in the Basic Information cluster
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProductAppearance {
    /// Product finish type
    pub finish: ProductFinishEnum,
    /// Product primary color
    pub color: Option<ColorEnum>,
}

impl ProductAppearance {
    /// Create a default instance of `ProductAppearance`,
    /// with `Other` finish and no color.
    pub const fn new() -> Self {
        Self {
            finish: ProductFinishEnum::Other,
            color: None,
        }
    }
}

impl Default for ProductAppearance {
    fn default() -> Self {
        Self::new()
    }
}

/// Mutable basic information
#[derive(Debug, Clone, Eq, PartialEq, Hash, ToTLV, FromTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BasicInfoSettings {
    pub node_label: heapless::String<32>, // Max node-label as per the spec
    pub location: Option<heapless::String<2>>, // Max location as per the spec
    pub location_type: RegulatoryLocationTypeEnum,
    pub local_config_disabled: bool,
    pub changed: bool,
}

impl BasicInfoSettings {
    /// Create a new instance of `BasicInfoSettings`
    pub const fn new() -> Self {
        Self {
            node_label: heapless::String::new(),
            location: None,
            location_type: RegulatoryLocationTypeEnum::IndoorOutdoor,
            local_config_disabled: false,
            changed: false,
        }
    }

    /// Return an in-place initializer for `BasicInfoSettings`
    pub fn init() -> impl Init<Self> {
        init!(Self {
            node_label: heapless::String::new(),
            location: None,
            location_type: RegulatoryLocationTypeEnum::IndoorOutdoor,
            local_config_disabled: false,
            changed: false,
        })
    }

    /// Resets the basic info to initial values
    ///
    /// # Arguments
    /// - `flag_changed`: whether to mark the basic info settings as changed
    pub fn reset(&mut self, flag_changed: bool) {
        self.node_label.clear();
        self.location = None;
        self.local_config_disabled = false;
        self.changed = flag_changed;
    }

    /// Load the basic info settings from the provided TLV data
    pub fn load(&mut self, data: &[u8]) -> Result<(), Error> {
        *self = FromTLV::from_tlv(&TLVElement::new(data))?;

        self.changed = false;

        Ok(())
    }

    /// Store the basic info settings into the provided buffer as TLV data
    pub fn store(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut wb = WriteBuf::new(buf);

        self.to_tlv(&TLVTag::Anonymous, &mut wb)
            .map_err(|_| ErrorCode::NoSpace)?;

        self.changed = false;

        let len = wb.get_tail();

        Ok(len)
    }

    pub fn set_location(&mut self, location: &str) {
        if location == "XX" {
            self.location = None;
        } else {
            self.location = Some(unwrap!(heapless::String::<2>::from_str(location)));
        }
        self.changed = true;
    }
}

impl Default for BasicInfoSettings {
    fn default() -> Self {
        Self::new()
    }
}

/// The system implementation of a handler for the Basic Information Matter cluster.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BasicInfoHandler(Dataver);

impl BasicInfoHandler {
    /// Create a new instance of `BasicInfoHandler` with the given `Dataver`
    pub fn new(dataver: Dataver) -> Self {
        Self(dataver)
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    fn config<'a>(exchange: &'a Exchange) -> &'a BasicInfoConfig<'a> {
        exchange.matter().dev_det()
    }

    fn settings<'a>(exchange: &'a Exchange) -> &'a RefCell<BasicInfoSettings> {
        &exchange.matter().basic_info_settings
    }
}

impl ClusterHandler for BasicInfoHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_attrs(except!(AttributeId::Reachable))
        .with_cmds(with!());

    fn dataver(&self) -> u32 {
        self.0.get()
    }

    fn dataver_changed(&self) {
        self.0.changed();
    }
}

impl ClusterSyncHandler for BasicInfoHandler {
    fn data_model_revision(&self, ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(Self::config(ctx.exchange()).data_model_revision)
    }

    fn vendor_id(&self, ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(Self::config(ctx.exchange()).vid)
    }

    fn vendor_name<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).vendor_name)
    }

    fn product_id(&self, ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(Self::config(ctx.exchange()).pid)
    }

    fn product_name<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).product_name)
    }

    fn hardware_version(&self, ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(Self::config(ctx.exchange()).hw_ver)
    }

    fn hardware_version_string<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).hw_ver_str)
    }

    fn software_version(&self, ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(Self::config(ctx.exchange()).sw_ver)
    }

    fn software_version_string<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).sw_ver_str)
    }

    fn node_label<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::settings(ctx.exchange()).borrow().node_label.as_str())
    }

    fn set_node_label(&self, ctx: impl WriteContext, label: &str) -> Result<(), Error> {
        if label.len() > 32 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let mut settings = Self::settings(ctx.exchange()).borrow_mut();

        settings.node_label.clear();
        settings
            .node_label
            .push_str(label)
            .map_err(|_| ErrorCode::ConstraintError)?;
        settings.changed = true;

        ctx.exchange().matter().notify_persist();

        Ok(())
    }

    fn location<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        let settings = Self::settings(ctx.exchange()).borrow();
        out.set(settings.location.as_ref().map_or("XX", |loc| loc.as_str()))
    }

    fn set_location(&self, ctx: impl WriteContext, location: &str) -> Result<(), Error> {
        if location.len() != 2 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let mut settings = Self::settings(ctx.exchange()).borrow_mut();

        settings.set_location(location);

        ctx.exchange().matter().notify_persist();

        Ok(())
    }

    fn capability_minima<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: CapabilityMinimaStructBuilder<P>,
    ) -> Result<P, Error> {
        let cm = Self::config(ctx.exchange()).capability_minima;

        builder
            .case_sessions_per_fabric(cm.case_sessions_per_fabric)?
            .subscriptions_per_fabric(cm.subscriptions_per_fabric)?
            .end()
    }

    fn specification_version(&self, ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(Self::config(ctx.exchange()).specification_version)
    }

    fn max_paths_per_invoke(&self, ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(Self::config(ctx.exchange()).max_paths_per_invoke)
    }

    fn configuration_version(&self, ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(Self::config(ctx.exchange()).configuration_version)
    }

    fn handle_mfg_specific_ping(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn manufacturing_date<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Self::config(ctx.exchange()).manufacturing_date)
    }

    fn part_number<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Self::config(ctx.exchange()).part_number)
    }

    fn product_url<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Self::config(ctx.exchange()).product_url)
    }

    fn product_label<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Self::config(ctx.exchange()).product_label)
    }

    fn serial_number<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Self::config(ctx.exchange()).serial_no)
    }

    fn local_config_disabled(&self, ctx: impl ReadContext) -> Result<bool, Error> {
        Ok(Self::settings(ctx.exchange())
            .borrow()
            .local_config_disabled)
    }

    fn set_local_config_disabled(&self, ctx: impl WriteContext, value: bool) -> Result<(), Error> {
        let mut settings = Self::settings(ctx.exchange()).borrow_mut();

        settings.local_config_disabled = value;
        settings.changed = true;

        ctx.exchange().matter().notify_persist();

        Ok(())
    }

    fn unique_id<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Self::config(ctx.exchange()).unique_id)
    }

    fn product_appearance<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ProductAppearanceStructBuilder<P>,
    ) -> Result<P, Error> {
        let appearance = Self::config(ctx.exchange()).product_appearance;

        builder
            .finish(appearance.finish)?
            .primary_color(Nullable::new(appearance.color))?
            .end()
    }
}
