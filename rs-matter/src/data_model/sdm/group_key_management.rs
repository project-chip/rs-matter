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
use crate::{attribute_enum, attributes, cmd_enter, command_enum, commands, with};

pub const ID: u32 = 0x003F;

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u32)]
pub enum Attributes {
    GroupKeyMap(()) = 0x00,
    GroupTable(()) = 0x01,
    MaxGroupsPerFabric(AttrType<u16>) = 0x02,
    MaxGroupKeysPerFabric(AttrType<u16>) = 0x03,
}

attribute_enum!(Attributes);

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u32)]
pub enum Commands {
    KeySetWrite = 0x0,
}

command_enum!(Commands);

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    revision: 1,
    feature_map: 0,
    attributes: attributes!(
        Attribute::new(
            AttributesDiscriminants::GroupKeyMap as _,
            Access::RWFVM,
            Quality::PERSISTENT,
        ),
        Attribute::new(
            AttributesDiscriminants::GroupTable as _,
            Access::RF.union(Access::NEED_VIEW),
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::MaxGroupsPerFabric as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::MaxGroupKeysPerFabric as _,
            Access::RV,
            Quality::FIXED,
        ),
    ),
    commands: commands!(Command::new(
        CommandsDiscriminants::KeySetWrite as _,
        None,
        Access::WA,
    ),),
    with_attrs: with!(all),
    with_cmds: with!(all),
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GrpKeyMgmtCluster {
    data_ver: Dataver,
}

impl GrpKeyMgmtCluster {
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
                    Attributes::MaxGroupsPerFabric(codec) => codec.encode(writer, 1),
                    Attributes::MaxGroupKeysPerFabric(codec) => codec.encode(writer, 1),
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
            Commands::KeySetWrite => {
                cmd_enter!("KeySetWrite: Not yet supported");
            }
        }

        self.data_ver.changed();

        Ok(())
    }
}

impl Handler for GrpKeyMgmtCluster {
    fn read(
        &self,
        ctx: &ReadContext<'_>,
        encoder: AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        GrpKeyMgmtCluster::read(self, ctx, encoder)
    }

    fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
        GrpKeyMgmtCluster::write(self, ctx)
    }

    fn invoke(
        &self,
        ctx: &InvokeContext<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        GrpKeyMgmtCluster::invoke(self, ctx, encoder)
    }
}

// TODO: Might be removed once the `on` member is externalized
impl NonBlockingHandler for GrpKeyMgmtCluster {}
