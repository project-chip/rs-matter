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
use crate::{
    cmd_enter,
    error::*,
    interaction_model::{command::CommandReq, core::IMStatusCode},
};
use log::info;
use num_derive::FromPrimitive;

pub const ID: u32 = 0x0006;

pub enum Attributes {
    OnOff = 0x0,
}

#[derive(FromPrimitive)]
pub enum Commands {
    Off = 0x0,
    On = 0x01,
    Toggle = 0x02,
}

fn attr_on_off_new() -> Result<Attribute, Error> {
    // OnOff, Value: false
    Attribute::new(
        Attributes::OnOff as u16,
        AttrValue::Bool(false),
        Access::RV,
        Quality::PERSISTENT,
    )
}

pub struct OnOffCluster {
    base: Cluster,
}

impl OnOffCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        let mut cluster = Box::new(OnOffCluster {
            base: Cluster::new(ID)?,
        });
        cluster.base.add_attribute(attr_on_off_new()?)?;
        Ok(cluster)
    }
}

impl ClusterType for OnOffCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
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
            Commands::Off => {
                cmd_enter!("Off");
                let value = self
                    .base
                    .read_attribute_raw(Attributes::OnOff as u16)
                    .unwrap();
                if AttrValue::Bool(true) == *value {
                    self.base
                        .write_attribute_raw(Attributes::OnOff as u16, AttrValue::Bool(false))
                        .map_err(|_| IMStatusCode::Failure)?;
                }
                cmd_req.trans.complete();
                Err(IMStatusCode::Success)
            }
            Commands::On => {
                cmd_enter!("On");
                let value = self
                    .base
                    .read_attribute_raw(Attributes::OnOff as u16)
                    .unwrap();
                if AttrValue::Bool(false) == *value {
                    self.base
                        .write_attribute_raw(Attributes::OnOff as u16, AttrValue::Bool(true))
                        .map_err(|_| IMStatusCode::Failure)?;
                }

                cmd_req.trans.complete();
                Err(IMStatusCode::Success)
            }
            Commands::Toggle => {
                cmd_enter!("Toggle");
                let value = match self
                    .base
                    .read_attribute_raw(Attributes::OnOff as u16)
                    .unwrap()
                {
                    &AttrValue::Bool(v) => v,
                    _ => false,
                };
                self.base
                    .write_attribute_raw(Attributes::OnOff as u16, AttrValue::Bool(!value))
                    .map_err(|_| IMStatusCode::Failure)?;
                cmd_req.trans.complete();
                Err(IMStatusCode::Success)
            }
        }
    }
}
