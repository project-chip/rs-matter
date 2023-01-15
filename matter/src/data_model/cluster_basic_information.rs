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
    SerialNo = 0x0f,
}

pub struct BasicInfoConfig {
    pub vid: u16,
    pub pid: u16,
    pub hw_ver: u16,
    pub sw_ver: u32,
    pub serial_no: String,
}

fn attr_dm_rev_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::DMRevision as u16,
        AttrValue::Uint8(1),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_vid_new(vid: u16) -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::VendorId as u16,
        AttrValue::Uint16(vid),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_pid_new(pid: u16) -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::ProductId as u16,
        AttrValue::Uint16(pid),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_hw_ver_new(hw_ver: u16) -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::HwVer as u16,
        AttrValue::Uint16(hw_ver),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_sw_ver_new(sw_ver: u32) -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::SwVer as u16,
        AttrValue::Uint32(sw_ver),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_serial_no_new(label: String) -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::SerialNo as u16,
        AttrValue::Utf8(label),
        Access::RV,
        Quality::FIXED,
    )
}
pub struct BasicInfoCluster {
    base: Cluster,
}

impl BasicInfoCluster {
    pub fn new(cfg: BasicInfoConfig) -> Result<Box<Self>, Error> {
        let mut cluster = Box::new(BasicInfoCluster {
            base: Cluster::new(ID)?,
        });
        cluster.base.add_attribute(attr_dm_rev_new()?)?;
        cluster.base.add_attribute(attr_vid_new(cfg.vid)?)?;
        cluster.base.add_attribute(attr_pid_new(cfg.pid)?)?;
        cluster.base.add_attribute(attr_hw_ver_new(cfg.hw_ver)?)?;
        cluster.base.add_attribute(attr_sw_ver_new(cfg.sw_ver)?)?;
        cluster
            .base
            .add_attribute(attr_serial_no_new(cfg.serial_no)?)?;
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
