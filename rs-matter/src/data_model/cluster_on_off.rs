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

use core::{cell::Cell, convert::TryInto};

use super::objects::*;
use crate::{
    attribute_enum, cmd_enter, command_enum, error::Error, tlv::TLVElement,
    transport::exchange::Exchange, utils::rand::Rand,
};
use log::info;
use rs_matter_macros::idl_import;
use strum::{EnumDiscriminants, FromRepr};

idl_import!("on_off.matter");

pub use on_off::ID;

pub use on_off::Commands;
pub use on_off::CommandsDiscriminants;

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u16)]
pub enum Attributes {
    OnOff(AttrType<bool>) = 0x0,
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
            AttributesDiscriminants::OnOff as u16,
            Access::RV,
            Quality::SN,
        ),
    ],
    commands: &[
        CommandsDiscriminants::Off as _,
        CommandsDiscriminants::On as _,
        CommandsDiscriminants::Toggle as _,
    ],
};

pub struct OnOffCluster {
    data_ver: Dataver,
    on: Cell<bool>,
}

impl OnOffCluster {
    pub fn new(rand: Rand) -> Self {
        Self {
            data_ver: Dataver::new(rand),
            on: Cell::new(false),
        }
    }

    pub fn set(&self, on: bool) {
        if self.on.get() != on {
            self.on.set(on);
            self.data_ver.changed();
        }
    }

    pub fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::OnOff(codec) => codec.encode(writer, self.on.get()),
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        let data = data.with_dataver(self.data_ver.get())?;

        match attr.attr_id.try_into()? {
            Attributes::OnOff(codec) => self.set(codec.decode(data)?),
        }

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
            Commands::Off => {
                cmd_enter!("Off");
                self.set(false);
            }
            Commands::On => {
                cmd_enter!("On");
                self.set(true);
            }
            Commands::Toggle => {
                cmd_enter!("Toggle");
                self.set(!self.on.get());
            }
            Commands::OffWithEffect
            | Commands::OnWithRecallGlobalScene
            | Commands::OnWithTimedOff => todo!(),
        }

        self.data_ver.changed();

        Ok(())
    }
}

impl Handler for OnOffCluster {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        OnOffCluster::read(self, attr, encoder)
    }

    fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        OnOffCluster::write(self, attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        OnOffCluster::invoke(self, exchange, cmd, data, encoder)
    }
}

// TODO: Might be removed once the `on` member is externalized
impl NonBlockingHandler for OnOffCluster {}

impl ChangeNotifier<()> for OnOffCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
