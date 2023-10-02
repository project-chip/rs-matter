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

use core::{cell::RefCell, convert::TryInto};

use super::objects::*;
use crate::{
    attribute_enum,
    error::{Error, ErrorCode},
    utils::rand::Rand,
};
use heapless::String;
use strum::FromRepr;

pub const ID: u32 = 0x0028;

#[derive(Clone, Copy, Debug, FromRepr)]
#[repr(u16)]
pub enum Attributes {
    DMRevision(AttrType<u8>) = 0,
    VendorName(AttrUtfType) = 1,
    VendorId(AttrType<u16>) = 2,
    ProductName(AttrUtfType) = 3,
    ProductId(AttrType<u16>) = 4,
    NodeLabel(AttrUtfType) = 5,
    HwVer(AttrType<u16>) = 7,
    SwVer(AttrType<u32>) = 9,
    SwVerString(AttrUtfType) = 0xa,
    SerialNo(AttrUtfType) = 0x0f,
    UniqueId(AttrUtfType) = 0x12,
}

attribute_enum!(Attributes);

pub enum AttributesDiscriminants {
    DMRevision = 0,
    VendorName = 1,
    VendorId = 2,
    ProductName = 3,
    ProductId = 4,
    NodeLabel = 5,
    HwVer = 7,
    SwVer = 9,
    SwVerString = 0xa,
    SerialNo = 0x0f,
    UniqueId = 0x12,
}

#[derive(Default)]
pub struct BasicInfoConfig<'a> {
    pub vid: u16,
    pub pid: u16,
    pub hw_ver: u16,
    pub sw_ver: u32,
    pub sw_ver_str: &'a str,
    pub serial_no: &'a str,
    /// Device name; up to 32 characters
    pub device_name: &'a str,
    pub vendor_name: &'a str,
    pub product_name: &'a str,
    pub unique_id: &'a str,
}

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    feature_map: 0,
    attributes: &[
        FEATURE_MAP,
        ATTRIBUTE_LIST,
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
            AttributesDiscriminants::HwVer as u16,
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
            AttributesDiscriminants::UniqueId as u16,
            Access::RV,
            Quality::FIXED,
        ),
    ],
    commands: &[],
};

pub struct BasicInfoCluster<'a> {
    data_ver: Dataver,
    cfg: &'a BasicInfoConfig<'a>,
    node_label: RefCell<String<32>>, // Max node-label as per the spec
}

impl<'a> BasicInfoCluster<'a> {
    pub fn new(cfg: &'a BasicInfoConfig<'a>, rand: Rand) -> Self {
        let node_label = RefCell::new(String::from(""));
        Self {
            data_ver: Dataver::new(rand),
            cfg,
            node_label,
        }
    }

    pub fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::DMRevision(codec) => codec.encode(writer, 1),
                    Attributes::VendorName(codec) => codec.encode(writer, self.cfg.vendor_name),
                    Attributes::VendorId(codec) => codec.encode(writer, self.cfg.vid),
                    Attributes::ProductName(codec) => codec.encode(writer, self.cfg.product_name),
                    Attributes::ProductId(codec) => codec.encode(writer, self.cfg.pid),
                    Attributes::NodeLabel(codec) => {
                        codec.encode(writer, self.node_label.borrow().as_str())
                    }
                    Attributes::HwVer(codec) => codec.encode(writer, self.cfg.hw_ver),
                    Attributes::SwVer(codec) => codec.encode(writer, self.cfg.sw_ver),
                    Attributes::SwVerString(codec) => codec.encode(writer, self.cfg.sw_ver_str),
                    Attributes::SerialNo(codec) => codec.encode(writer, self.cfg.serial_no),
                    Attributes::UniqueId(codec) => codec.encode(writer, self.cfg.unique_id),
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        let data = data.with_dataver(self.data_ver.get())?;

        match attr.attr_id.try_into()? {
            Attributes::NodeLabel(codec) => {
                *self.node_label.borrow_mut() = String::from(
                    codec
                        .decode(data)
                        .map_err(|_| Error::new(ErrorCode::InvalidAction))?,
                );
            }
            _ => return Err(Error::new(ErrorCode::InvalidAction)),
        }

        self.data_ver.changed();

        Ok(())
    }
}

impl<'a> Handler for BasicInfoCluster<'a> {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        BasicInfoCluster::read(self, attr, encoder)
    }

    fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        BasicInfoCluster::write(self, attr, data)
    }
}

impl<'a> NonBlockingHandler for BasicInfoCluster<'a> {}

impl<'a> ChangeNotifier<()> for BasicInfoCluster<'a> {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
