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

use super::objects::*;
use crate::error::*;
use num_derive::FromPrimitive;

pub const ID: u32 = 0x0028;

#[derive(FromPrimitive)]
enum Attributes {
    DMRevision = 0,
    VendorId = 2,
    ProductId = 4,
    HwVer = 7,
    SwVer = 9,
    SwVerString = 0xa,
    SerialNo = 0x0f,
}

#[derive(Default)]
pub struct BasicInfoConfig {
    pub vid: u16,
    pub pid: u16,
    pub hw_ver: u16,
    pub sw_ver: u32,
    pub sw_ver_str: String,
    pub serial_no: String,
    /// Device name; up to 32 characters
    pub device_name: String,
}

pub struct BasicInfoCluster {
    base: Cluster,
}

impl BasicInfoCluster {
    pub fn new(cfg: BasicInfoConfig) -> Result<Box<Self>, Error> {
        let mut cluster = Box::new(BasicInfoCluster {
            base: Cluster::new(ID)?,
        });

        let attrs = [
            Attribute::new(
                Attributes::DMRevision as u16,
                AttrValue::Uint8(1),
                Access::RV,
                Quality::FIXED,
            )?,
            Attribute::new(
                Attributes::VendorId as u16,
                AttrValue::Uint16(cfg.vid),
                Access::RV,
                Quality::FIXED,
            )?,
            Attribute::new(
                Attributes::ProductId as u16,
                AttrValue::Uint16(cfg.pid),
                Access::RV,
                Quality::FIXED,
            )?,
            Attribute::new(
                Attributes::HwVer as u16,
                AttrValue::Uint16(cfg.hw_ver),
                Access::RV,
                Quality::FIXED,
            )?,
            Attribute::new(
                Attributes::SwVer as u16,
                AttrValue::Uint32(cfg.sw_ver),
                Access::RV,
                Quality::FIXED,
            )?,
            Attribute::new(
                Attributes::SwVerString as u16,
                AttrValue::Utf8(cfg.sw_ver_str),
                Access::RV,
                Quality::FIXED,
            )?,
            Attribute::new(
                Attributes::SerialNo as u16,
                AttrValue::Utf8(cfg.serial_no),
                Access::RV,
                Quality::FIXED,
            )?,
        ];
        cluster.base.add_attributes(&attrs[..])?;

        Ok(cluster)
    }
}

impl ClusterType for BasicInfoCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }
}
