/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
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

use crate::cmd_enter;
use crate::data_model::objects::*;
use crate::interaction_model::core::IMStatusCode;
use crate::tlv::{FromTLV, Nullable, OctetStr, TLVElement};
use crate::{error::*, interaction_model::command::CommandReq};
use log::{error, info};
use num_derive::FromPrimitive;

pub const ID: u32 = 0x003C;

#[derive(FromPrimitive, Debug, Copy, Clone, PartialEq)]
pub enum WindowStatus {
    WindowNotOpen = 0,
    EnhancedWindowOpen = 1,
    BasicWindowOpen = 2,
}

#[derive(FromPrimitive)]
pub enum Attributes {
    WindowStatus = 0,
    AdminFabricIndex = 1,
    AdminVendorId = 2,
}

#[derive(FromPrimitive)]
pub enum Commands {
    OpenCommWindow = 0x00,
    OpenBasicCommWindow = 0x01,
    RevokeComm = 0x02,
}

fn attr_window_status_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::WindowStatus as u16,
        AttrValue::Custom,
        Access::RV,
        Quality::NONE,
    )
}

fn attr_admin_fabid_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::AdminFabricIndex as u16,
        AttrValue::Custom,
        Access::RV,
        Quality::NULLABLE,
    )
}

fn attr_admin_vid_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::AdminVendorId as u16,
        AttrValue::Custom,
        Access::RV,
        Quality::NULLABLE,
    )
}

pub struct AdminCommCluster {
    window_status: WindowStatus,
    base: Cluster,
}

impl ClusterType for AdminCommCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }

    fn read_custom_attribute(&self, encoder: &mut dyn Encoder, attr: &AttrDetails) {
        match num::FromPrimitive::from_u16(attr.attr_id) {
            Some(Attributes::WindowStatus) => {
                let status = self.window_status as u8;
                encoder.encode(EncodeValue::Value(&status))
            }
            Some(Attributes::AdminVendorId) => {
                let vid = if self.window_status == WindowStatus::WindowNotOpen {
                    Nullable::Null
                } else {
                    Nullable::NotNull(1_u8)
                };
                encoder.encode(EncodeValue::Value(&vid))
            }
            Some(Attributes::AdminFabricIndex) => {
                let vid = if self.window_status == WindowStatus::WindowNotOpen {
                    Nullable::Null
                } else {
                    Nullable::NotNull(1_u8)
                };
                encoder.encode(EncodeValue::Value(&vid))
            }
            _ => {
                error!("Unsupported Attribute: this shouldn't happen");
            }
        }
    }
    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req
            .cmd
            .path
            .leaf
            .map(num::FromPrimitive::from_u32)
            .ok_or(IMStatusCode::UnsupportedCommand)?
            .ok_or(IMStatusCode::UnsupportedCommand)?;
        match cmd {
            Commands::OpenCommWindow => self.handle_command_opencomm_win(cmd_req),
            _ => Err(IMStatusCode::UnsupportedCommand),
        }
    }
}

impl AdminCommCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        let mut c = Box::new(AdminCommCluster {
            window_status: WindowStatus::WindowNotOpen,
            base: Cluster::new(ID)?,
        });
        c.base.add_attribute(attr_window_status_new()?)?;
        c.base.add_attribute(attr_admin_fabid_new()?)?;
        c.base.add_attribute(attr_admin_vid_new()?)?;
        Ok(c)
    }

    fn handle_command_opencomm_win(
        &mut self,
        cmd_req: &mut CommandReq,
    ) -> Result<(), IMStatusCode> {
        cmd_enter!("Open Commissioning Window");
        let _req =
            OpenCommWindowReq::from_tlv(&cmd_req.data).map_err(|_| IMStatusCode::InvalidCommand)?;
        self.window_status = WindowStatus::EnhancedWindowOpen;
        Err(IMStatusCode::Sucess)
    }
}

#[derive(FromTLV)]
#[tlvargs(lifetime = "'a")]
pub struct OpenCommWindowReq<'a> {
    _timeout: u16,
    _verifier: OctetStr<'a>,
    _discriminator: u16,
    _iterations: u32,
    _salt: OctetStr<'a>,
}
