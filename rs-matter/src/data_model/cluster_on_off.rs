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

use rs_matter_macros::idl_import;

use strum::{EnumDiscriminants, FromRepr};

use crate::error::Error;
use crate::tlv::TLVElement;
use crate::transport::exchange::Exchange;
use crate::{attribute_enum, cluster_attrs, cmd_enter};

use super::objects::*;

idl_import!(clusters = ["OnOff"]);

pub use on_off::{AttributeId, CommandId, ID};

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u32)]
pub enum Attributes {
    OnOff(AttrType<bool>) = 0x0,
}

attribute_enum!(Attributes);

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    revision: 1,
    feature_map: 0,
    attributes: cluster_attrs!(Attribute::new(
        AttributeId::OnOff as _,
        Access::RV,
        Quality::SN,
    ),),
    accepted_commands: &[
        CommandId::Off as _,
        CommandId::On as _,
        CommandId::Toggle as _,
    ],
    generated_commands: &[],
};

#[derive(Clone)]
pub struct OnOffCluster {
    data_ver: Dataver,
    on: Cell<bool>,
}

impl OnOffCluster {
    pub const fn new(data_ver: Dataver) -> Self {
        Self {
            data_ver,
            on: Cell::new(false),
        }
    }

    pub fn get(&self) -> bool {
        self.on.get()
    }

    pub fn set(&self, on: bool) {
        if self.on.get() != on {
            self.on.set(on);
            self.data_ver.changed();
        }
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
                    Attributes::OnOff(codec) => codec.encode(writer, self.on.get()),
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn write(
        &self,
        _exchange: &Exchange,
        attr: &AttrDetails,
        data: AttrData,
    ) -> Result<(), Error> {
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
            CommandId::Off => {
                cmd_enter!("Off");
                self.set(false);
            }
            CommandId::On => {
                cmd_enter!("On");
                self.set(true);
            }
            CommandId::Toggle => {
                cmd_enter!("Toggle");
                self.set(!self.on.get());
            }
            CommandId::OffWithEffect
            | CommandId::OnWithRecallGlobalScene
            | CommandId::OnWithTimedOff => todo!(),
        }

        self.data_ver.changed();

        Ok(())
    }
}

impl Handler for OnOffCluster {
    fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        OnOffCluster::read(self, exchange, attr, encoder)
    }

    fn write(&self, exchange: &Exchange, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        OnOffCluster::write(self, exchange, attr, data)
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
