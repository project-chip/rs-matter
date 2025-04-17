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

use core::cell::Cell;
use core::fmt::Debug;

use std::sync::{Arc, Mutex, Once};

use num_derive::FromPrimitive;

use strum::{EnumDiscriminants, FromRepr};

use rs_matter::data_model::objects::{
    Access, AttrDataEncoder, AttrDataWriter, AttrDetails, AttrType, Attribute, Cluster,
    CmdDataEncoder, CmdDataWriter, CmdDetails, Dataver, Handler, NonBlockingHandler, Quality,
};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::interaction_model::messages::ib::{attr_list_write, ListOperation};
use rs_matter::tlv::{TLVElement, TLVTag, TLVWrite};
use rs_matter::transport::exchange::Exchange;
use rs_matter::{attribute_enum, cluster_attrs, command_enum};

pub const WRITE_LIST_MAX: usize = 5;

pub const ATTR_CUSTOM_VALUE: u32 = 0xcafebeef;
pub const ATTR_WRITE_DEFAULT_VALUE: u16 = 0xcafe;

pub const ID: u32 = 0xABCD;

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u32)]
pub enum Attributes {
    Att1(AttrType<u16>) = 0,
    Att2(AttrType<u16>) = 1,
    AttWrite(AttrType<u16>) = 2,
    AttCustom(AttrType<u32>) = 3,
    AttWriteList(()) = 4,
}

attribute_enum!(Attributes);

#[derive(FromRepr)]
#[repr(u32)]
pub enum Commands {
    EchoReq = 0x00,
}

command_enum!(Commands);

#[derive(FromPrimitive)]
pub enum RespCommands {
    EchoResp = 0x01,
}

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID,
    revision: 1,
    feature_map: 0,
    attributes: cluster_attrs!(
        Attribute::new(
            AttributesDiscriminants::Att1 as _,
            Access::RV,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::Att2 as _,
            Access::RV,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::AttWrite as _,
            Access::WRITE.union(Access::NEED_ADMIN),
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::AttCustom as _,
            Access::READ.union(Access::NEED_VIEW),
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::AttWriteList as _,
            Access::WRITE.union(Access::NEED_ADMIN),
            Quality::NONE,
        ),
    ),
    accepted_commands: &[Commands::EchoReq as _],
    generated_commands: &[RespCommands::EchoResp as _],
};

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
    #[allow(static_mut_refs)]
    pub fn get() -> Result<Arc<Mutex<Self>>, Error> {
        unsafe {
            INIT.call_once(|| {
                G_TEST_CHECKER = Some(Arc::new(Mutex::new(Self::new())));
            });
            Ok(G_TEST_CHECKER.as_ref().ok_or(ErrorCode::Invalid)?.clone())
        }
    }
}

/// A sample cluster that echoes back the input data. Useful for testing.
pub struct EchoCluster {
    pub data_ver: Dataver,
    pub multiplier: u8,
    pub att1: Cell<u16>,
    pub att2: Cell<u16>,
    pub att_write: Cell<u16>,
    pub att_custom: Cell<u32>,
}

impl EchoCluster {
    pub const fn new(multiplier: u8, data_ver: Dataver) -> Self {
        Self {
            data_ver,
            multiplier,
            att1: Cell::new(0x1234),
            att2: Cell::new(0x5678),
            att_write: Cell::new(ATTR_WRITE_DEFAULT_VALUE),
            att_custom: Cell::new(ATTR_CUSTOM_VALUE),
        }
    }

    pub fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::Att1(codec) => codec.encode(writer, 0x1234),
                    Attributes::Att2(codec) => codec.encode(writer, 0x5678),
                    Attributes::AttWrite(codec) => codec.encode(writer, ATTR_WRITE_DEFAULT_VALUE),
                    Attributes::AttCustom(codec) => codec.encode(writer, ATTR_CUSTOM_VALUE),
                    Attributes::AttWriteList(_) => {
                        let tc_handle = TestChecker::get().unwrap();
                        let tc = tc_handle.lock().unwrap();

                        writer.start_array(&AttrDataWriter::TAG)?;
                        for i in tc.write_list.iter().flatten() {
                            writer.u16(&TLVTag::Anonymous, *i)?;
                        }
                        writer.end_container()?;

                        writer.complete()
                    }
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn write(
        &self,
        attr: &AttrDetails,
        data: rs_matter::data_model::objects::AttrData,
    ) -> Result<(), Error> {
        let data = data.with_dataver(self.data_ver.get())?;

        match attr.attr_id.try_into()? {
            Attributes::Att1(codec) => self.att1.set(codec.decode(data)?),
            Attributes::Att2(codec) => self.att2.set(codec.decode(data)?),
            Attributes::AttWrite(codec) => self.att_write.set(codec.decode(data)?),
            Attributes::AttCustom(codec) => self.att_custom.set(codec.decode(data)?),
            Attributes::AttWriteList(_) => {
                attr_list_write(attr, data, |op, data| self.write_attr_list(&op, data))?
            }
        }

        self.data_ver.changed();

        Ok(())
    }

    pub fn invoke(
        &self,
        _exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        match cmd.cmd_id.try_into()? {
            // This will generate an echo response on the same endpoint
            // with data multiplied by the multiplier
            Commands::EchoReq => {
                let a = data.u8()?;

                let mut writer = encoder.with_command(RespCommands::EchoResp as _)?;

                // Echo = input * self.multiplier
                writer.u8(&CmdDataWriter::TAG, a * self.multiplier)?;

                writer.complete()
            }
        }
    }

    fn write_attr_list(&self, op: &ListOperation, data: &TLVElement) -> Result<(), Error> {
        let tc_handle = TestChecker::get().unwrap();
        let mut tc = tc_handle.lock().unwrap();
        match op {
            ListOperation::AddItem => {
                let data = data.u16()?;
                for i in 0..WRITE_LIST_MAX {
                    if tc.write_list[i].is_none() {
                        tc.write_list[i] = Some(data);
                        return Ok(());
                    }
                }

                Err(ErrorCode::ResourceExhausted.into())
            }
            ListOperation::EditItem(index) => {
                let data = data.u16()?;
                if tc.write_list[*index as usize].is_some() {
                    tc.write_list[*index as usize] = Some(data);
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ListOperation::DeleteItem(index) => {
                if tc.write_list[*index as usize].is_some() {
                    tc.write_list[*index as usize] = None;
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
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

impl Handler for EchoCluster {
    fn read(
        &self,
        _exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        EchoCluster::read(self, attr, encoder)
    }

    fn write(
        &self,
        _exchange: &Exchange,
        attr: &AttrDetails,
        data: rs_matter::data_model::objects::AttrData,
    ) -> Result<(), Error> {
        EchoCluster::write(self, attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        EchoCluster::invoke(self, exchange, cmd, data, encoder)
    }
}

impl NonBlockingHandler for EchoCluster {}
