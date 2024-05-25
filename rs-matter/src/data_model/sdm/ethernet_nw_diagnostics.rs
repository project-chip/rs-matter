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
use crate::{
    attribute_enum, cmd_enter, command_enum, data_model::objects::*, error::Error, tlv::TLVElement,
    transport::exchange::Exchange, utils::rand::Rand,
};
use log::info;
use rs_matter_macros::idl_import;
use strum::{EnumDiscriminants, FromRepr};

idl_import!(clusters = ["EthernetNetworkDiagnostics"]);

pub use ethernet_network_diagnostics::Commands;
pub use ethernet_network_diagnostics::CommandsDiscriminants;
pub use ethernet_network_diagnostics::ID;

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u16)]
pub enum Attributes {
    PacketRxCount(AttrType<u64>) = 0x02,
    PacketTxCount(AttrType<u64>) = 0x03,
}

attribute_enum!(Attributes);

command_enum!(Commands);

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    feature_map: 0,
    attributes: &[
        FEATURE_MAP,
        ATTRIBUTE_LIST,
        Attribute::new(
            AttributesDiscriminants::PacketRxCount as u16,
            Access::RV,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::PacketTxCount as u16,
            Access::RV,
            Quality::FIXED,
        ),
    ],
    commands: &[CommandsDiscriminants::ResetCounts as _],
};

#[derive(Clone)]
pub struct EthNwDiagCluster {
    data_ver: Dataver,
}

impl EthNwDiagCluster {
    pub fn new(rand: Rand) -> Self {
        Self {
            data_ver: Dataver::new(rand),
        }
    }

    pub fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::PacketRxCount(codec) => codec.encode(writer, 1),
                    Attributes::PacketTxCount(codec) => codec.encode(writer, 1),
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn write(&self, _attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        let _data = data.with_dataver(self.data_ver.get())?;

        self.data_ver.changed();

        Ok(())
    }

    pub fn invoke(
        &self,
        _exchange: &Exchange,
        cmd: &CmdDetails,
        _data: &TLVElement,
        _encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        match cmd.cmd_id.try_into()? {
            Commands::ResetCounts => {
                cmd_enter!("ResetCounts: Not yet supported");
            }
        }

        self.data_ver.changed();

        Ok(())
    }
}

impl Handler for EthNwDiagCluster {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        EthNwDiagCluster::read(self, attr, encoder)
    }

    fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        EthNwDiagCluster::write(self, attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        EthNwDiagCluster::invoke(self, exchange, cmd, data, encoder)
    }
}

// TODO: Might be removed once the `on` member is externalized
impl NonBlockingHandler for EthNwDiagCluster {}

impl ChangeNotifier<()> for EthNwDiagCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
