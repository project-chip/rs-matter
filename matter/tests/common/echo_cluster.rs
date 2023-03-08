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

use std::sync::{Arc, Mutex, Once};

use matter::{
    data_model::objects::{
        Access, AttrDetails, AttrValue, Attribute, Cluster, ClusterType, EncodeValue, Encoder,
        Quality,
    },
    error::Error,
    interaction_model::{
        command::CommandReq,
        core::IMStatusCode,
        messages::ib::{self, attr_list_write, ListOperation},
    },
    tlv::{TLVElement, TLVWriter, TagType, ToTLV},
};
use num_derive::FromPrimitive;

pub const ID: u32 = 0xABCD;

#[derive(FromPrimitive)]
pub enum Commands {
    EchoReq = 0x00,
    EchoResp = 0x01,
}

/// This is used in the tests to validate any settings that may have happened
/// to the custom data parts of the cluster
pub struct TestChecker {
    pub write_list: [Option<u16>; WRITE_LIST_MAX],
}

static mut G_TEST_CHECKER: Option<Arc<Mutex<TestChecker>>> = None;
static INIT: Once = Once::new();

impl TestChecker {
    fn new() -> Self {
        Self {
            write_list: [None; WRITE_LIST_MAX],
        }
    }

    /// Get a handle to the globally unique mDNS instance
    pub fn get() -> Result<Arc<Mutex<Self>>, Error> {
        unsafe {
            INIT.call_once(|| {
                G_TEST_CHECKER = Some(Arc::new(Mutex::new(Self::new())));
            });
            Ok(G_TEST_CHECKER.as_ref().ok_or(Error::Invalid)?.clone())
        }
    }
}

pub const WRITE_LIST_MAX: usize = 5;
pub struct EchoCluster {
    pub base: Cluster,
    pub multiplier: u8,
}

#[derive(FromPrimitive)]
pub enum Attributes {
    Att1 = 0,
    Att2 = 1,
    AttWrite = 2,
    AttCustom = 3,
    AttWriteList = 4,
}

pub const ATTR_CUSTOM_VALUE: u32 = 0xcafebeef;
pub const ATTR_WRITE_DEFAULT_VALUE: u16 = 0xcafe;

impl ClusterType for EchoCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }

    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }

    fn read_custom_attribute(&self, encoder: &mut dyn Encoder, attr: &AttrDetails) {
        match num::FromPrimitive::from_u16(attr.attr_id) {
            Some(Attributes::AttCustom) => encoder.encode(EncodeValue::Closure(&|tag, tw| {
                let _ = tw.u32(tag, ATTR_CUSTOM_VALUE);
            })),
            Some(Attributes::AttWriteList) => {
                let tc_handle = TestChecker::get().unwrap();
                let tc = tc_handle.lock().unwrap();
                encoder.encode(EncodeValue::Closure(&|tag, tw| {
                    let _ = tw.start_array(tag);
                    for i in tc.write_list.iter().flatten() {
                        let _ = tw.u16(TagType::Anonymous, *i);
                    }
                    let _ = tw.end_container();
                }))
            }
            _ => (),
        }
    }

    fn write_attribute(
        &mut self,
        attr: &AttrDetails,
        data: &TLVElement,
    ) -> Result<(), IMStatusCode> {
        match num::FromPrimitive::from_u16(attr.attr_id) {
            Some(Attributes::AttWriteList) => {
                attr_list_write(attr, data, |op, data| self.write_attr_list(&op, data))
            }
            _ => self.base.write_attribute_from_tlv(attr.attr_id, data),
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
            // This will generate an echo response on the same endpoint
            // with data multiplied by the multiplier
            Commands::EchoReq => {
                let a = cmd_req.data.u8().unwrap();
                let mut echo_response = cmd_req.cmd;
                echo_response.path.leaf = Some(Commands::EchoResp as u32);

                let cmd_data = |tag: TagType, t: &mut TLVWriter| {
                    let _ = t.start_struct(tag);
                    // Echo = input * self.multiplier
                    let _ = t.u8(TagType::Context(0), a * self.multiplier);
                    let _ = t.end_container();
                };

                let invoke_resp = ib::InvResp::Cmd(ib::CmdData::new(
                    echo_response,
                    EncodeValue::Closure(&cmd_data),
                ));
                let _ = invoke_resp.to_tlv(cmd_req.resp, TagType::Anonymous);
                cmd_req.trans.complete();
            }
            _ => {
                return Err(IMStatusCode::UnsupportedCommand);
            }
        }
        Ok(())
    }
}

impl EchoCluster {
    pub fn new(multiplier: u8) -> Result<Box<Self>, Error> {
        let mut c = Box::new(Self {
            base: Cluster::new(ID)?,
            multiplier,
        });
        c.base.add_attribute(Attribute::new(
            Attributes::Att1 as u16,
            AttrValue::Uint16(0x1234),
            Access::RV,
            Quality::NONE,
        ))?;
        c.base.add_attribute(Attribute::new(
            Attributes::Att2 as u16,
            AttrValue::Uint16(0x5678),
            Access::RV,
            Quality::NONE,
        ))?;
        c.base.add_attribute(Attribute::new(
            Attributes::AttWrite as u16,
            AttrValue::Uint16(ATTR_WRITE_DEFAULT_VALUE),
            Access::WRITE | Access::NEED_ADMIN,
            Quality::NONE,
        ))?;
        c.base.add_attribute(Attribute::new(
            Attributes::AttCustom as u16,
            AttrValue::Custom,
            Access::READ | Access::NEED_VIEW,
            Quality::NONE,
        ))?;
        c.base.add_attribute(Attribute::new(
            Attributes::AttWriteList as u16,
            AttrValue::Custom,
            Access::WRITE | Access::NEED_ADMIN,
            Quality::NONE,
        ))?;
        Ok(c)
    }

    fn write_attr_list(
        &mut self,
        op: &ListOperation,
        data: &TLVElement,
    ) -> Result<(), IMStatusCode> {
        let tc_handle = TestChecker::get().unwrap();
        let mut tc = tc_handle.lock().unwrap();
        match op {
            ListOperation::AddItem => {
                let data = data.u16().map_err(|_| IMStatusCode::Failure)?;
                for i in 0..WRITE_LIST_MAX {
                    if tc.write_list[i].is_none() {
                        tc.write_list[i] = Some(data);
                        return Ok(());
                    }
                }
                Err(IMStatusCode::ResourceExhausted)
            }
            ListOperation::EditItem(index) => {
                let data = data.u16().map_err(|_| IMStatusCode::Failure)?;
                if tc.write_list[*index as usize].is_some() {
                    tc.write_list[*index as usize] = Some(data);
                    Ok(())
                } else {
                    Err(IMStatusCode::InvalidAction)
                }
            }
            ListOperation::DeleteItem(index) => {
                if tc.write_list[*index as usize].is_some() {
                    tc.write_list[*index as usize] = None;
                    Ok(())
                } else {
                    Err(IMStatusCode::InvalidAction)
                }
            }
            ListOperation::DeleteList => {
                for i in 0..WRITE_LIST_MAX {
                    tc.write_list[i] = None;
                }
                Ok(())
            }
        }
    }
}
