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

use strum::{EnumDiscriminants, FromRepr};

use crate::data_model::objects::{
    Access, AttrDataEncoder, AttrType, Attribute, Cluster, CmdDataEncoder, Command, Dataver,
    Handler, InvokeContext, NonBlockingHandler, Quality, ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::{attribute_enum, attributes, cmd_enter, command_enum, commands};

pub const ID: u32 = 0x0033;

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u32)]
pub enum Attributes {
    NetworkInterfaces(()) = 0x00,
    RebootCount(AttrType<u16>) = 0x01,
    TestEventTriggersEnabled(AttrType<bool>) = 0x08,
}

attribute_enum!(Attributes);

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u32)]
pub enum Commands {
    TestEventTrigger = 0x0,
}

command_enum!(Commands);

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    revision: 1,
    feature_map: 0,
    attributes: attributes!(
        Attribute::new(
            AttributesDiscriminants::NetworkInterfaces as _,
            Access::RV,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::RebootCount as _,
            Access::RV,
            Quality::PERSISTENT,
        ),
        Attribute::new(
            AttributesDiscriminants::TestEventTriggersEnabled as _,
            Access::RV,
            Quality::NONE,
        ),
    ),
    commands: commands!(Command::new(
        CommandsDiscriminants::TestEventTrigger as _,
        None,
        Access::WA,
    )),
    with_attrs: Cluster::with_all_attrs,
    with_cmds: Cluster::with_all_cmds,
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GenDiagCluster {
    data_ver: Dataver,
}

impl GenDiagCluster {
    pub const fn new(data_ver: Dataver) -> Self {
        Self { data_ver }
    }

    pub fn read(
        &self,
        ctx: &ReadContext<'_>,
        encoder: AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        let attr = ctx.attr();

        if let Some(writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::RebootCount(codec) => codec.encode(writer, 1),
                    _ => Err(ErrorCode::AttributeNotFound.into()),
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
        ctx.attr().check_dataver(self.data_ver.get())?;

        self.data_ver.changed();

        Ok(())
    }

    pub fn invoke(
        &self,
        ctx: &InvokeContext<'_>,
        _encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        let cmd = ctx.cmd();

        match cmd.cmd_id.try_into()? {
            Commands::TestEventTrigger => {
                cmd_enter!("TestEventTrigger: Not yet supported");
            }
        }

        self.data_ver.changed();

        Ok(())
    }
}

impl Handler for GenDiagCluster {
    fn read(
        &self,
        ctx: &ReadContext<'_>,
        encoder: AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        GenDiagCluster::read(self, ctx, encoder)
    }

    fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
        GenDiagCluster::write(self, ctx)
    }

    fn invoke(
        &self,
        ctx: &InvokeContext<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        GenDiagCluster::invoke(self, ctx, encoder)
    }
}

// TODO: Might be removed once the `on` member is externalized
impl NonBlockingHandler for GenDiagCluster {}
