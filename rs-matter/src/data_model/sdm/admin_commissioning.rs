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

use num_derive::FromPrimitive;

use strum::{EnumDiscriminants, FromRepr};

use crate::data_model::objects::*;
use crate::tlv::{FromTLV, Nullable, OctetStr, TLVElement};
use crate::transport::exchange::Exchange;
use crate::{attribute_enum, cluster_attrs, cmd_enter};
use crate::{command_enum, error::*};

pub const ID: u32 = 0x003C;

#[derive(FromPrimitive, Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum WindowStatus {
    WindowNotOpen = 0,
    EnhancedWindowOpen = 1,
    BasicWindowOpen = 2,
}

#[derive(Clone, Debug, FromRepr, EnumDiscriminants)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u32)]
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
    revision: 1,
    feature_map: 0,
    attributes: cluster_attrs!(
        Attribute::new(
            AttributesDiscriminants::WindowStatus as _,
            Access::RV,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::AdminFabricIndex as _,
            Access::RV,
            Quality::NULLABLE,
        ),
        Attribute::new(
            AttributesDiscriminants::AdminVendorId as _,
            Access::RV,
            Quality::NULLABLE,
        ),
    ),
    accepted_commands: &[
        Commands::OpenCommWindow as _,
        Commands::OpenBasicCommWindow as _,
        Commands::RevokeComm as _,
    ],
    generated_commands: &[],
};

#[derive(FromTLV)]
#[tlvargs(lifetime = "'a")]
pub struct OpenCommWindowReq<'a> {
    timeout: u16,
    verifier: OctetStr<'a>,
    discriminator: u16,
    iterations: u32,
    salt: OctetStr<'a>,
}

#[derive(FromTLV)]
pub struct OpenBasicCommWindowReq {
    timeout: u16,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AdminCommCluster {
    data_ver: Dataver,
}

impl AdminCommCluster {
    pub const fn new(data_ver: Dataver) -> Self {
        Self { data_ver }
    }

    pub fn read(
        &self,
        _exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        if let Some(writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::WindowStatus(codec) => codec.encode(writer, 1),
                    Attributes::AdminVendorId(codec) => codec.encode(writer, Nullable::some(1)),
                    Attributes::AdminFabricIndex(codec) => codec.encode(writer, Nullable::some(1)),
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        _encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        match cmd.cmd_id.try_into()? {
            Commands::OpenCommWindow => self.handle_command_opencomm_win(exchange, data)?,
            Commands::OpenBasicCommWindow => {
                self.handle_command_open_basic_comm_win(exchange, data)?
            }
            Commands::RevokeComm => self.handle_command_revokecomm_win(exchange, data)?,
        }

        self.data_ver.changed();

        Ok(())
    }

    fn handle_command_opencomm_win(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
    ) -> Result<(), Error> {
        cmd_enter!("Open Commissioning Window");
        let req = OpenCommWindowReq::from_tlv(data)?;

        exchange.matter().pase_mgr.borrow_mut().enable_pase_session(
            req.verifier.0,
            req.salt.0,
            req.iterations,
            req.discriminator,
            req.timeout,
            &exchange.matter().transport_mgr.mdns,
        )
    }

    fn handle_command_open_basic_comm_win(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
    ) -> Result<(), Error> {
        cmd_enter!("Open Basic Commissioning Window");
        let req = OpenBasicCommWindowReq::from_tlv(data)?;

        exchange
            .matter()
            .pase_mgr
            .borrow_mut()
            .enable_basic_pase_session(
                exchange.matter().dev_comm().password,
                exchange.matter().dev_comm().discriminator,
                req.timeout,
                &exchange.matter().transport_mgr.mdns,
            )
    }

    fn handle_command_revokecomm_win(
        &self,
        exchange: &Exchange,
        _data: &TLVElement,
    ) -> Result<(), Error> {
        cmd_enter!("Revoke Commissioning Window");
        exchange
            .matter()
            .pase_mgr
            .borrow_mut()
            .disable_pase_session(&exchange.matter().transport_mgr.mdns)?;

        // TODO: Send status code if no commissioning window is open

        Ok(())
    }
}

impl Handler for AdminCommCluster {
    fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        AdminCommCluster::read(self, exchange, attr, encoder)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        AdminCommCluster::invoke(self, exchange, cmd, data, encoder)
    }
}

impl NonBlockingHandler for AdminCommCluster {}

impl ChangeNotifier<()> for AdminCommCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
