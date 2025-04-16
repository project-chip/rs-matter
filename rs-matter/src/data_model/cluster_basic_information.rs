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

use rs_matter_macros::idl_import;

use strum::FromRepr;

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVElement, TLVTag, ToTLV};
use crate::transport::exchange::Exchange;
use crate::utils::init::{init, Init};
use crate::utils::storage::WriteBuf;
use crate::{attribute_enum, cluster_attrs};

use super::objects::*;

idl_import!(clusters = ["BasicInformation"]);

pub use basic_information::ID;

const SUPPORTED_MATTER_SPEC_VERSION: u32 = 0x01000000;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CapabilityMinima {
    pub case_sessions_per_fabric: u16,
    pub subscriptions_per_fabric: u16,
}

#[derive(Clone, Copy, Debug, FromRepr)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u16)]
pub enum Attributes {
    DMRevision(AttrType<u8>) = 0,
    VendorName(AttrUtfType) = 1,
    VendorId(AttrType<u16>) = 2,
    ProductName(AttrUtfType) = 3,
    ProductId(AttrType<u16>) = 4,
    NodeLabel(AttrUtfType) = 5,
    Location(AttrUtfType) = 6,
    HwVer(AttrType<u16>) = 7,
    HwVerString(AttrUtfType) = 8,
    SwVer(AttrType<u32>) = 9,
    SwVerString(AttrUtfType) = 0xa,
    SerialNo(AttrUtfType) = 0x0f,
    CapabilityMinima(AttrType<CapabilityMinima>) = 0x13,
    SpecificationVersion(AttrType<u32>) = 0x15,
    MaxPathsPerInvoke(AttrType<u16>) = 0x16,
}

attribute_enum!(Attributes);

pub enum AttributesDiscriminants {
    DMRevision = 0,
    VendorName = 1,
    VendorId = 2,
    ProductName = 3,
    ProductId = 4,
    NodeLabel = 5,
    Location = 6,
    HwVer = 7,
    HwVerString = 8,
    SwVer = 9,
    SwVerString = 0xa,
    SerialNo = 0x0f,
    CapabilityMinima = 0x13,
    SpecificationVersion = 0x15,
    MaxPathsPerInvoke = 0x16,
}

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

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    revision: 1,
    feature_map: 0,
    attributes: cluster_attrs!(
        Attribute::new(
            AttributesDiscriminants::DMRevision as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::VendorName as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::VendorId as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::ProductName as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::ProductId as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::NodeLabel as u16,
            Access::RWVM,
            Quality::N,
        ),
        Attribute::new(
            AttributesDiscriminants::Location as u16,
            Access::RWVA,
            Quality::N,
        ),
        Attribute::new(
            AttributesDiscriminants::HwVer as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::HwVerString as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::SwVer as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::SwVerString as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::SerialNo as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::CapabilityMinima as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::SpecificationVersion as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::MaxPathsPerInvoke as u16,
            Access::RV,
            Quality::FIXED,
        ),
    ),
    accepted_commands: &[],
    generated_commands: &[],
};

#[derive(Clone)]
pub struct BasicInfoCluster {
    data_ver: Dataver,
}

impl BasicInfoCluster {
    pub fn new(data_ver: Dataver) -> Self {
        Self { data_ver }
    }

    pub fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        if let Some(writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                let cfg = exchange.matter().dev_det();
                let info = &exchange.matter().basic_info_settings;

                match attr.attr_id.try_into()? {
                    Attributes::DMRevision(codec) => codec.encode(writer, 1),
                    Attributes::VendorName(codec) => codec.encode(writer, cfg.vendor_name),
                    Attributes::VendorId(codec) => codec.encode(writer, cfg.vid),
                    Attributes::ProductName(codec) => codec.encode(writer, cfg.product_name),
                    Attributes::ProductId(codec) => codec.encode(writer, cfg.pid),
                    Attributes::NodeLabel(codec) => {
                        codec.encode(writer, info.borrow().node_label.as_str())
                    }
                    Attributes::Location(codec) => codec.encode(
                        writer,
                        info.borrow()
                            .location
                            .as_ref()
                            .map(|location| location.as_str())
                            .unwrap_or("XX"),
                    ),
                    Attributes::HwVer(codec) => codec.encode(writer, cfg.hw_ver),
                    Attributes::HwVerString(codec) => codec.encode(writer, cfg.hw_ver_str),
                    Attributes::SwVer(codec) => codec.encode(writer, cfg.sw_ver),
                    Attributes::SwVerString(codec) => codec.encode(writer, cfg.sw_ver_str),
                    Attributes::SerialNo(codec) => codec.encode(writer, cfg.serial_no),
                    Attributes::CapabilityMinima(codec) => {
                        codec.encode(
                            writer,
                            CapabilityMinima {
                                // Minimum that should be supported as per spec
                                // TODO: Report real values
                                // TODO: Restrict # of case sessions per fabric in the code
                                case_sessions_per_fabric: 3,
                                // Minimum that should be supported as per spec
                                // TODO: Report real values
                                // TODO: Restrict # of subscriptions per fabric in the code
                                subscriptions_per_fabric: 3,
                            },
                        )
                    }
                    Attributes::SpecificationVersion(codec) => {
                        codec.encode(writer, SUPPORTED_MATTER_SPEC_VERSION)
                    }
                    // TODO: Report a real value
                    Attributes::MaxPathsPerInvoke(codec) => codec.encode(writer, 1),
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn write(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        data: AttrData,
    ) -> Result<(), Error> {
        let data = data.with_dataver(self.data_ver.get())?;
        let info = &exchange.matter().basic_info_settings;

        match attr.attr_id.try_into()? {
            Attributes::NodeLabel(codec) => {
                info.borrow_mut().node_label = unwrap!(codec
                    .decode(data)
                    .map_err(|_| Error::new(ErrorCode::InvalidAction))?
                    .try_into());
                info.borrow_mut().changed = true;
            }
            Attributes::Location(codec) => {
                info.borrow_mut().location = Some(unwrap!(codec
                    .decode(data)
                    .map_err(|_| Error::new(ErrorCode::InvalidAction))?
                    .try_into()));
                info.borrow_mut().changed = true;
            }
            _ => return Err(Error::new(ErrorCode::InvalidAction)),
        }

        self.data_ver.changed();

        Ok(())
    }
}

impl Handler for BasicInfoCluster {
    fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        BasicInfoCluster::read(self, exchange, attr, encoder)
    }

    fn write(&self, exchange: &Exchange, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        BasicInfoCluster::write(self, exchange, attr, data)
    }
}

impl NonBlockingHandler for BasicInfoCluster {}

impl ChangeNotifier<()> for BasicInfoCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
