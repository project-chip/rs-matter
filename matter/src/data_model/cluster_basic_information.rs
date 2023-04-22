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

use core::convert::TryInto;

use super::objects::*;
use crate::{attribute_enum, error::Error, utils::rand::Rand};
use strum::FromRepr;

pub const ID: u32 = 0x0028;

#[derive(Clone, Copy, Debug, FromRepr)]
#[repr(u16)]
pub enum Attributes {
    DMRevision(AttrType<u8>) = 0,
    VendorId(AttrType<u16>) = 2,
    ProductId(AttrType<u16>) = 4,
    HwVer(AttrType<u16>) = 7,
    SwVer(AttrType<u32>) = 9,
    SwVerString(AttrUtfType) = 0xa,
    SerialNo(AttrUtfType) = 0x0f,
}

attribute_enum!(Attributes);

pub enum AttributesDiscriminants {
    DMRevision = 0,
    VendorId = 2,
    ProductId = 4,
    HwVer = 7,
    SwVer = 9,
    SwVerString = 0xa,
    SerialNo = 0x0f,
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
            AttributesDiscriminants::VendorId as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::ProductId as u16,
            Access::RV,
            Quality::FIXED,
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
    ],
    commands: &[],
};

pub struct BasicInfoCluster<'a> {
    data_ver: Dataver,
    cfg: &'a BasicInfoConfig<'a>,
}

impl<'a> BasicInfoCluster<'a> {
    pub fn new(cfg: &'a BasicInfoConfig<'a>, rand: Rand) -> Self {
        Self {
            data_ver: Dataver::new(rand),
            cfg,
        }
    }

    pub fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::DMRevision(codec) => codec.encode(writer, 1),
                    Attributes::VendorId(codec) => codec.encode(writer, self.cfg.vid),
                    Attributes::ProductId(codec) => codec.encode(writer, self.cfg.pid),
                    Attributes::HwVer(codec) => codec.encode(writer, self.cfg.hw_ver),
                    Attributes::SwVer(codec) => codec.encode(writer, self.cfg.sw_ver),
                    Attributes::SwVerString(codec) => codec.encode(writer, self.cfg.sw_ver_str),
                    Attributes::SerialNo(codec) => codec.encode(writer, self.cfg.serial_no),
                }
            }
        } else {
            Ok(())
        }
    }
}

impl<'a> Handler for BasicInfoCluster<'a> {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        BasicInfoCluster::read(self, attr, encoder)
    }
}

impl<'a> NonBlockingHandler for BasicInfoCluster<'a> {}

impl<'a> ChangeNotifier<()> for BasicInfoCluster<'a> {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
