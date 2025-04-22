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

use core::str::FromStr;

use rs_matter_macros::idl_import;

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVBuilderParent, TLVElement, TLVTag, ToTLV, Utf8StrBuilder};
use crate::transport::exchange::Exchange;
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::WriteBuf;

use super::objects::{Dataver, InvokeContext, ReadContext, WriteContext};

idl_import!(clusters = ["BasicInformation"]);

const SUPPORTED_MATTER_SPEC_VERSION: u32 = 0x01000000;

/// Basic infomration which is immutable
/// (i.e. valid for the lifetime of the device firmware)
#[derive(Default, Clone, Eq, PartialEq, Hash)]
pub struct BasicInfoConfig<'a> {
    pub vid: u16,
    pub pid: u16,
    pub hw_ver: u16,
    pub hw_ver_str: &'a str,
    pub sw_ver: u32,
    pub sw_ver_str: &'a str,
    pub serial_no: &'a str,
    /// Device name; up to 32 characters
    pub device_name: &'a str,
    pub vendor_name: &'a str,
    pub product_name: &'a str,
    /// Session Active Interval in ms
    /// If not specified, defaults to 300
    pub sai: Option<u16>,
    /// Session Idle Interval in ms
    /// If not specified, defaults to 5000
    pub sii: Option<u16>,
}

/// Mutable basic information
#[derive(Debug, Clone, Eq, PartialEq, Hash, ToTLV, FromTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BasicInfoSettings {
    pub node_label: heapless::String<32>, // Max node-label as per the spec
    pub location: Option<heapless::String<2>>, // Max location as per the spec
    pub changed: bool,
}

impl BasicInfoSettings {
    /// Create a new instance of `BasicInfoSettings`
    pub const fn new() -> Self {
        Self {
            node_label: heapless::String::new(),
            location: None,
            changed: false,
        }
    }

    /// Return an in-place initializer for `BasicInfoSettings`
    pub fn init() -> impl Init<Self> {
        init!(Self {
            node_label: heapless::String::new(),
            location: None,
            changed: false,
        })
    }

    /// Resets the basic info to initial values
    pub fn reset(&mut self) {
        self.node_label.clear();
        self.location = None;
        self.changed = false;
    }

    /// Load the basic info settings from the provided TLV data
    pub fn load(&mut self, data: &[u8]) -> Result<(), Error> {
        *self = FromTLV::from_tlv(&TLVElement::new(data))?;

        self.changed = false;

        Ok(())
    }

    /// Store the basic info settings into the provided buffer as TLV data
    ///
    /// If the basic info has not changed since the last store operation, the
    /// function returns `None` and does not store the basic info.
    pub fn store<'a>(&mut self, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        if !self.changed {
            return Ok(None);
        }

        let mut wb = WriteBuf::new(buf);

        self.to_tlv(&TLVTag::Anonymous, &mut wb)
            .map_err(|_| ErrorCode::NoSpace)?;

        self.changed = false;

        let len = wb.get_tail();

        Ok(Some(&buf[..len]))
    }
}

impl Default for BasicInfoSettings {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct BasicInfoCluster(Dataver);

impl BasicInfoCluster {
    pub fn new(dataver: Dataver) -> Self {
        Self(dataver)
    }

    fn config<'a>(exchange: &'a Exchange) -> &'a BasicInfoConfig<'a> {
        exchange.matter().dev_det()
    }

    fn settings<'a>(exchange: &'a Exchange) -> &'a RefCell<BasicInfoSettings> {
        &exchange.matter().basic_info_settings
    }
}

impl BasicInformationHandler for BasicInfoCluster {
    fn dataver(&self) -> u32 {
        self.0.get()
    }

    fn dataver_changed(&self) {
        self.0.changed();
    }

    fn data_model_revision(&self, _ctx: &ReadContext) -> Result<u16, Error> {
        Ok(0) // TODO
    }

    fn vendor_id(&self, ctx: &ReadContext) -> Result<u16, Error> {
        Ok(Self::config(ctx.exchange()).vid)
    }

    fn vendor_name<P: TLVBuilderParent>(
        &self,
        ctx: &ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).vendor_name)
    }

    fn product_id(&self, ctx: &ReadContext) -> Result<u16, Error> {
        Ok(Self::config(ctx.exchange()).pid)
    }

    fn product_name<P: TLVBuilderParent>(
        &self,
        ctx: &ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).product_name)
    }

    fn serial_number<P: TLVBuilderParent>(
        &self,
        ctx: &ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).serial_no)
    }

    fn hardware_version(&self, ctx: &ReadContext) -> Result<u16, Error> {
        Ok(Self::config(ctx.exchange()).hw_ver)
    }

    fn hardware_version_string<P: TLVBuilderParent>(
        &self,
        ctx: &ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).hw_ver_str)
    }

    fn software_version(&self, ctx: &ReadContext) -> Result<u32, Error> {
        Ok(Self::config(ctx.exchange()).sw_ver)
    }

    fn software_version_string<P: TLVBuilderParent>(
        &self,
        ctx: &ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).sw_ver_str)
    }

    fn node_label<P: TLVBuilderParent>(
        &self,
        ctx: &ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::settings(ctx.exchange()).borrow().node_label.as_str())
    }

    fn set_node_label(&self, ctx: &WriteContext, label: &str) -> Result<(), Error> {
        if label.len() > 32 {
            return Err(ErrorCode::InvalidAction.into());
        }

        let mut settings = Self::settings(ctx.exchange()).borrow_mut();
        settings.node_label.clear();
        settings
            .node_label
            .push_str(label)
            .map_err(|_| ErrorCode::NoSpace)?;
        settings.changed = true;

        settings.changed = true;
        ctx.exchange().matter().notify_persist();

        Ok(())
    }

    fn location<P: TLVBuilderParent>(
        &self,
        ctx: &ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        let settings = Self::settings(ctx.exchange()).borrow();
        out.set(settings.location.as_ref().map_or("XX", |loc| loc.as_str()))
    }

    fn set_location(&self, ctx: &WriteContext, location: &str) -> Result<(), Error> {
        if location.len() != 2 {
            return Err(ErrorCode::InvalidAction.into());
        }

        let mut settings = Self::settings(ctx.exchange()).borrow_mut();
        if location == "XX" {
            settings.location = None;
        } else {
            settings.location = Some(unwrap!(heapless::String::<2>::from_str(location)));
            settings.changed = true;
        }

        settings.changed = true;
        ctx.exchange().matter().notify_persist();

        Ok(())
    }

    fn capability_minima<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext,
        out: CapabilityMinimaStructBuilder<P>,
    ) -> Result<P, Error> {
        // TODO: Report real values
        out.case_sessions_per_fabric(3)?
            .subscriptions_per_fabric(3)?
            .finish()
    }

    fn specification_version(&self, _ctx: &ReadContext) -> Result<u32, Error> {
        Ok(SUPPORTED_MATTER_SPEC_VERSION)
    }

    fn max_paths_per_invoke(&self, _ctx: &ReadContext) -> Result<u16, Error> {
        Ok(1) // TODO: Report real value
    }

    fn product_label<P: TLVBuilderParent>(
        &self,
        ctx: &ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).product_name)
    }

    fn handle_mfg_specific_ping(&self, _ctx: &InvokeContext) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }
}
