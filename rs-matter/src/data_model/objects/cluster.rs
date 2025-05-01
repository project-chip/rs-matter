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

use core::fmt::{self, Debug};

use crate::acl::{AccessReq, Accessor};
use crate::data_model::objects::*;
use crate::error::{Error, ErrorCode};
use crate::interaction_model::core::IMStatusCode;
use crate::interaction_model::messages::GenericPath;
use crate::tlv::{TLVTag, TLVWrite};

/// A struct modeling the cluster meta-data
/// (i.e. what is the cluster ID, revision, features, attributes and their access, commands and their access)
/// in the Matter data model.
#[derive(Debug, Clone)]
pub struct Cluster<'a> {
    pub id: ClusterId,
    pub revision: u16,
    pub feature_map: u32,
    pub attributes: &'a [Attribute],
    pub commands: &'a [Command],
    pub with_attrs: fn(&Attribute, u16, u32) -> bool,
    pub with_cmds: fn(&Command, u16, u32) -> bool,
}

impl<'a> Cluster<'a> {
    /// Create a new cluster
    ///
    /// # Arguments
    /// - `id`: The ID of the cluster
    /// - `revision`: The revision of the cluster
    /// - `feature_map`: The feature map of the cluster
    /// - `attributes`: The attributes of the cluster
    /// - `commands`: The commands of the cluster
    /// - `with_attrs`: A function that takes an attribute and returns a boolean indicating if the attribute should be included
    /// - `with_cmds`: A function that takes a command and returns a boolean indicating if the command should be included
    pub const fn new(
        id: ClusterId,
        revision: u16,
        feature_map: u32,
        attributes: &'a [Attribute],
        commands: &'a [Command],
        with_attrs: fn(&Attribute, u16, u32) -> bool,
        with_cmds: fn(&Command, u16, u32) -> bool,
    ) -> Self {
        Self {
            id,
            revision,
            feature_map,
            attributes,
            commands,
            with_attrs,
            with_cmds,
        }
    }

    /// Create a new cluster based on this one but adjusted with the provided configuration
    ///
    /// # Arguments
    /// - `revision`: The revision of the cluster
    /// - `feature_map`: The feature map of the cluster
    /// - `with_attrs`: A function that takes an attribute and returns a boolean indicating if the attribute should be included
    /// - `with_cmds`: A function that takes a command and returns a boolean indicating if the command should be included
    pub const fn conf(
        self,
        revision: u16,
        feature_map: u32,
        with_attrs: fn(&Attribute, u16, u32) -> bool,
        with_cmds: fn(&Command, u16, u32) -> bool,
    ) -> Self {
        Self {
            revision,
            feature_map,
            with_attrs,
            with_cmds,
            ..self
        }
    }

    /// Check if the accessor has the required permissions to access the attribute
    /// designated by the provided path.
    ///
    /// if `write` is true, the operation is a write operation, otherwise it is a read operation.
    pub(crate) fn check_attr_access(
        &self,
        accessor: &Accessor,
        path: GenericPath,
        write: bool,
        attr_id: AttrId,
    ) -> Result<(), IMStatusCode> {
        let mut access_req = AccessReq::new(
            accessor,
            path,
            if write { Access::WRITE } else { Access::READ },
        );

        let target_perms = self
            .attributes
            .iter()
            .find(|attr| attr.id == attr_id)
            .map(|attr| attr.access)
            .unwrap_or(Access::empty());

        if !target_perms.contains(access_req.operation()) {
            Err(if matches!(access_req.operation(), Access::WRITE) {
                IMStatusCode::UnsupportedWrite
            } else {
                IMStatusCode::UnsupportedRead
            })?;
        }

        access_req.set_target_perms(target_perms);
        if access_req.allow() {
            Ok(())
        } else {
            Err(IMStatusCode::UnsupportedAccess)
        }
    }

    /// Check if the accessor has the required permissions to access the command
    /// designated by the provided path.
    pub(crate) fn check_cmd_access(
        &self,
        accessor: &Accessor,
        path: GenericPath,
        cmd_id: CmdId,
    ) -> Result<(), IMStatusCode> {
        let mut access_req = AccessReq::new(accessor, path, Access::WRITE);

        let target_perms = self
            .commands
            .iter()
            .find(|cmd| cmd.id == cmd_id)
            .map(|cmd| cmd.access)
            .unwrap_or(Access::empty());

        access_req.set_target_perms(target_perms);
        if access_req.allow() {
            Ok(())
        } else {
            Err(IMStatusCode::UnsupportedAccess)
        }
    }

    /// Return an iterator over the attributes of the cluster which are
    /// configured to be included based on the provided configuration.
    pub(crate) fn attributes(&self) -> impl Iterator<Item = &Attribute> + '_ {
        self.attributes
            .iter()
            .filter(|attr| (self.with_attrs)(attr, self.revision, self.feature_map))
    }

    /// Return an iterator over the commands of the cluster which are
    /// configured to be included based on the provided configuration.
    pub(crate) fn commands(&self) -> impl Iterator<Item = &Command> + '_ {
        self.commands
            .iter()
            .filter(|cmd| (self.with_cmds)(cmd, self.revision, self.feature_map))
    }

    /// Performs an IM attribute read for the given attribute ID.
    ///
    /// The provided attribute ID must be a global attribute, or else
    /// an error will be returned.
    pub fn read(&self, attr: AttrId, mut writer: AttrDataWriter) -> Result<(), Error> {
        match attr.try_into()? {
            GlobalElements::GeneratedCmdList => {
                self.encode_generated_command_ids(&AttrDataWriter::TAG, &mut *writer)?;
                writer.complete()
            }
            GlobalElements::AcceptedCmdList => {
                self.encode_accepted_command_ids(&AttrDataWriter::TAG, &mut *writer)?;
                writer.complete()
            }
            GlobalElements::EventList => {
                self.encode_event_ids(&AttrDataWriter::TAG, &mut *writer)?;
                writer.complete()
            }
            GlobalElements::AttributeList => {
                self.encode_attribute_ids(&AttrDataWriter::TAG, &mut *writer)?;
                writer.complete()
            }
            GlobalElements::FeatureMap => writer.set(self.feature_map),
            GlobalElements::ClusterRevision => writer.set(self.revision),
            other => {
                error!("This attribute is not yet handled {:?}", other);
                Err(ErrorCode::AttributeNotFound.into())
            }
        }
    }

    fn encode_attribute_ids<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.start_array(tag)?;
        for a in self.attributes() {
            tw.u32(&TLVTag::Anonymous, a.id)?;
        }

        tw.end_container()
    }

    fn encode_accepted_command_ids<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        Self::encode_command_ids(tag, tw, self.commands().map(|cmd| cmd.id))
    }

    fn encode_generated_command_ids<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        Self::encode_command_ids(tag, tw, self.commands().filter_map(|cmd| cmd.resp_id))
    }

    fn encode_event_ids<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        // No events for now
        tw.start_array(tag)?;
        tw.end_container()
    }

    fn encode_command_ids<W: TLVWrite>(
        tag: &TLVTag,
        mut tw: W,
        cmds: impl Iterator<Item = CmdId>,
    ) -> Result<(), Error> {
        tw.start_array(tag)?;
        for cmd in cmds {
            tw.u32(&TLVTag::Anonymous, cmd)?;
        }

        tw.end_container()
    }

    /// An attribute filtering function that always returns true.
    pub fn with_all_attrs(_attr: &Attribute, _revision: u16, _feature_map: u32) -> bool {
        true
    }

    /// An attribute filtering function that returns true if the attribute is not optional.
    pub fn with_mandatory_attrs(attr: &Attribute, _revision: u16, _feature_map: u32) -> bool {
        !attr.quality.contains(Quality::OPTIONAL)
    }

    /// A command filtering function that always returns true.
    pub fn with_all_cmds(_cmd: &Command, _revision: u16, _feature_map: u32) -> bool {
        true
    }

    /// A command filtering function that always returns false.
    pub fn with_no_cmds(_cmd: &Command, _revision: u16, _feature_map: u32) -> bool {
        false
    }
}

impl core::fmt::Display for Cluster<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id: {}, ", self.id)?;

        write!(f, "attrs [")?;
        for (index, attr) in self.attributes().enumerate() {
            if index > 0 {
                write!(f, ", {}", attr)?;
            } else {
                write!(f, "{}", attr)?;
            }
        }

        write!(f, "], cmds [")?;
        for (index, cmd) in self.commands().enumerate() {
            if index > 0 {
                write!(f, ", {}", cmd)?;
            } else {
                write!(f, "{}", cmd)?;
            }
        }

        write!(f, "]")
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Cluster<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "id: {}, ", self.id);

        defmt::write!(f, "attrs [");
        for (index, attr) in self.attributes().enumerate() {
            if index > 0 {
                defmt::write!(f, ", {}", attr);
            } else {
                defmt::write!(f, "{}", attr);
            }
        }

        defmt::write!(f, "], cmds [");
        for (index, cmd) in self.commands().enumerate() {
            if index > 0 {
                defmt::write!(f, ", {}", cmd);
            } else {
                defmt::write!(f, "{}", cmd);
            }
        }

        defmt::write!(f, "]")
    }
}
