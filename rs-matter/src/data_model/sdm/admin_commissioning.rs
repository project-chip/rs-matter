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

use core::cell::RefCell;

use crate::data_model::objects::*;
use crate::mdns::Mdns;
use crate::secure_channel::pake::PaseMgr;
use crate::secure_channel::spake2p::VerifierData;
use crate::tlv::{FromTLV, Nullable, OctetStr, TLVElement};
use crate::transport::exchange::Exchange;
use crate::utils::rand::Rand;
use crate::{attribute_enum, cmd_enter};
use crate::{command_enum, error::*};
use log::info;
use num_derive::FromPrimitive;
use strum::{EnumDiscriminants, FromRepr};

pub const ID: u32 = 0x003C;

#[derive(FromPrimitive, Debug, Copy, Clone, PartialEq)]
pub enum WindowStatus {
    WindowNotOpen = 0,
    EnhancedWindowOpen = 1,
    BasicWindowOpen = 2,
}

#[derive(Copy, Clone, Debug, FromRepr, EnumDiscriminants)]
#[repr(u16)]
pub enum Attributes {
    WindowStatus(AttrType<u8>) = 0,
    AdminFabricIndex(AttrType<Nullable<u8>>) = 1,
    AdminVendorId(AttrType<Nullable<u8>>) = 2,
}

attribute_enum!(Attributes);

#[derive(FromRepr)]
#[repr(u32)]
pub enum Commands {
    OpenCommWindow = 0x00,
    OpenBasicCommWindow = 0x01,
    RevokeComm = 0x02,
}

command_enum!(Commands);

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    feature_map: 0,
    attributes: &[
        FEATURE_MAP,
        ATTRIBUTE_LIST,
        Attribute::new(
            AttributesDiscriminants::WindowStatus as u16,
            Access::RV,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::AdminFabricIndex as u16,
            Access::RV,
            Quality::NULLABLE,
        ),
        Attribute::new(
            AttributesDiscriminants::AdminVendorId as u16,
            Access::RV,
            Quality::NULLABLE,
        ),
    ],
    commands: &[
        Commands::OpenCommWindow as _,
        // Commands::OpenBasicCommWindow as _,
        Commands::RevokeComm as _,
    ],
};

#[derive(FromTLV)]
#[tlvargs(lifetime = "'a")]
pub struct OpenCommWindowReq<'a> {
    _timeout: u16,
    verifier: OctetStr<'a>,
    discriminator: u16,
    iterations: u32,
    salt: OctetStr<'a>,
}

#[derive(Clone)]
pub struct AdminCommCluster<'a> {
    data_ver: Dataver,
    pase_mgr: &'a RefCell<PaseMgr>,
    mdns: &'a dyn Mdns,
}

impl<'a> AdminCommCluster<'a> {
    pub fn new(pase_mgr: &'a RefCell<PaseMgr>, mdns: &'a dyn Mdns, rand: Rand) -> Self {
        Self {
            data_ver: Dataver::new(rand),
            pase_mgr,
            mdns,
        }
    }

    pub fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::WindowStatus(codec) => codec.encode(writer, 1),
                    Attributes::AdminVendorId(codec) => codec.encode(writer, Nullable::NotNull(1)),
                    Attributes::AdminFabricIndex(codec) => {
                        codec.encode(writer, Nullable::NotNull(1))
                    }
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn invoke(
        &self,
        cmd: &CmdDetails,
        data: &TLVElement,
        _encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        match cmd.cmd_id.try_into()? {
            Commands::OpenCommWindow => self.handle_command_opencomm_win(data)?,
            Commands::RevokeComm => self.handle_command_revokecomm_win(data)?,
            _ => Err(ErrorCode::CommandNotFound)?,
        }

        self.data_ver.changed();

        Ok(())
    }

    fn handle_command_opencomm_win(&self, data: &TLVElement) -> Result<(), Error> {
        cmd_enter!("Open Commissioning Window");
        let req = OpenCommWindowReq::from_tlv(data)?;
        let verifier = VerifierData::new(req.verifier.0, req.iterations, req.salt.0);
        self.pase_mgr
            .borrow_mut()
            .enable_pase_session(verifier, req.discriminator, self.mdns)?;

        Ok(())
    }

    fn handle_command_revokecomm_win(&self, _data: &TLVElement) -> Result<(), Error> {
        cmd_enter!("Revoke Commissioning Window");
        self.pase_mgr.borrow_mut().disable_pase_session(self.mdns)?;

        // TODO: Send status code if no commissioning window is open

        Ok(())
    }
}

impl<'a> Handler for AdminCommCluster<'a> {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        AdminCommCluster::read(self, attr, encoder)
    }

    fn invoke(
        &self,
        _exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        AdminCommCluster::invoke(self, cmd, data, encoder)
    }
}

impl<'a> NonBlockingHandler for AdminCommCluster<'a> {}

impl<'a> ChangeNotifier<()> for AdminCommCluster<'a> {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
