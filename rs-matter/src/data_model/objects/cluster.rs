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

use strum::FromRepr;

use crate::{
    acl::{AccessReq, Accessor},
    attribute_enum,
    data_model::objects::*,
    error::{Error, ErrorCode},
    interaction_model::{
        core::IMStatusCode,
        messages::{
            ib::{AttrPath, AttrStatus, CmdPath, CmdStatus},
            GenericPath,
        },
    },
    // TODO: This layer shouldn't really depend on the TLV layer, should create an abstraction layer
    tlv::{Nullable, TLVTag, TLVWrite},
};
use core::fmt::{self, Debug};

#[derive(Clone, Copy, Debug, Eq, PartialEq, FromRepr)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u32)]
pub enum GlobalElements {
    ClusterRevision = 0xFFFD,
    FeatureMap = 0xFFFC,
    AttributeList = 0xFFFB,
    _EventList = 0xFFFA,
    AcceptedCmdList = 0xFFF9,
    GeneratedCmdList = 0xFFF8,
    FabricIndex = 0xFE,
}

attribute_enum!(GlobalElements);

pub const CLUSTER_REVISION: Attribute = Attribute::new(
    GlobalElements::ClusterRevision as _,
    Access::RV,
    Quality::NONE,
);

pub const FEATURE_MAP: Attribute =
    Attribute::new(GlobalElements::FeatureMap as _, Access::RV, Quality::NONE);

pub const ATTRIBUTE_LIST: Attribute = Attribute::new(
    GlobalElements::AttributeList as _,
    Access::RV,
    Quality::NONE,
);

pub const ACCEPTED_COMMAND_LIST: Attribute = Attribute::new(
    GlobalElements::AcceptedCmdList as _,
    Access::RV,
    Quality::NONE,
);

pub const GENERATED_COMMAND_LIST: Attribute = Attribute::new(
    GlobalElements::GeneratedCmdList as _,
    Access::RV,
    Quality::NONE,
);

#[allow(unused_macros)]
#[macro_export]
macro_rules! cluster_attrs {
    () => {
        &[
            $crate::data_model::objects::CLUSTER_REVISION,
            $crate::data_model::objects::FEATURE_MAP,
            $crate::data_model::objects::ATTRIBUTE_LIST,
            $crate::data_model::objects::ACCEPTED_COMMAND_LIST,
            $crate::data_model::objects::GENERATED_COMMAND_LIST,
        ]
    };
    ($attr0:expr $(, $attr:expr)* $(,)?) => {
        &[
            $crate::data_model::objects::CLUSTER_REVISION,
            $crate::data_model::objects::FEATURE_MAP,
            $crate::data_model::objects::ATTRIBUTE_LIST,
            $crate::data_model::objects::ACCEPTED_COMMAND_LIST,
            $crate::data_model::objects::GENERATED_COMMAND_LIST,
            $attr0,
            $($attr,)*
        ]
    }
}

// TODO: What if we instead of creating this, we just pass the AttrData/AttrPath to the read/write
// methods?
/// The Attribute Details structure records the details about the attribute under consideration.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttrDetails<'a> {
    pub node: &'a Node<'a>,
    /// The actual endpoint ID
    pub endpoint_id: EndptId,
    /// The actual cluster ID
    pub cluster_id: ClusterId,
    /// The actual attribute ID
    pub attr_id: AttrId,
    /// List Index, if any
    pub list_index: Option<Nullable<u16>>,
    /// The current Fabric Index
    pub fab_idx: u8,
    /// Fabric Filtering Activated
    pub fab_filter: bool,
    pub dataver: Option<u32>,
    pub wildcard: bool,
}

impl AttrDetails<'_> {
    pub fn is_system(&self) -> bool {
        Attribute::is_system_attr(self.attr_id)
    }

    pub fn path(&self) -> AttrPath {
        AttrPath {
            endpoint: Some(self.endpoint_id),
            cluster: Some(self.cluster_id),
            attr: Some(self.attr_id),
            list_index: self.list_index.clone(),
            ..Default::default()
        }
    }

    pub fn status(&self, status: IMStatusCode) -> Result<Option<AttrStatus>, Error> {
        if self.should_report(status) {
            Ok(Some(AttrStatus::new(
                &GenericPath {
                    endpoint: Some(self.endpoint_id),
                    cluster: Some(self.cluster_id),
                    leaf: Some(self.attr_id as _),
                },
                status,
                0,
            )))
        } else {
            Ok(None)
        }
    }

    fn should_report(&self, status: IMStatusCode) -> bool {
        !self.wildcard
            || !matches!(
                status,
                IMStatusCode::UnsupportedEndpoint
                    | IMStatusCode::UnsupportedCluster
                    | IMStatusCode::UnsupportedAttribute
                    | IMStatusCode::UnsupportedCommand
                    | IMStatusCode::UnsupportedAccess
                    | IMStatusCode::UnsupportedRead
                    | IMStatusCode::UnsupportedWrite
                    | IMStatusCode::DataVersionMismatch
            )
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CmdDetails<'a> {
    pub node: &'a Node<'a>,
    pub endpoint_id: EndptId,
    pub cluster_id: ClusterId,
    pub cmd_id: CmdId,
    pub wildcard: bool,
}

impl CmdDetails<'_> {
    pub fn path(&self) -> CmdPath {
        CmdPath::new(
            Some(self.endpoint_id),
            Some(self.cluster_id),
            Some(self.cmd_id),
        )
    }

    pub fn success(&self, tracker: &CmdDataTracker) -> Option<CmdStatus> {
        if tracker.needs_status() {
            self.status(IMStatusCode::Success)
        } else {
            None
        }
    }

    pub fn status(&self, status: IMStatusCode) -> Option<CmdStatus> {
        if self.should_report(status) {
            Some(CmdStatus::new(
                CmdPath::new(
                    Some(self.endpoint_id),
                    Some(self.cluster_id),
                    Some(self.cmd_id),
                ),
                status,
                0,
            ))
        } else {
            None
        }
    }

    fn should_report(&self, status: IMStatusCode) -> bool {
        !self.wildcard
            || !matches!(
                status,
                IMStatusCode::UnsupportedEndpoint
                    | IMStatusCode::UnsupportedCluster
                    | IMStatusCode::UnsupportedAttribute
                    | IMStatusCode::UnsupportedCommand
                    | IMStatusCode::UnsupportedAccess
                    | IMStatusCode::UnsupportedRead
                    | IMStatusCode::UnsupportedWrite
            )
    }
}

#[derive(Debug, Clone)]
pub struct Cluster<'a> {
    pub id: ClusterId,
    pub revision: u16,
    pub feature_map: u32,
    pub attributes: &'a [Attribute],
    pub accepted_commands: &'a [CmdId],
    pub generated_commands: &'a [CmdId],
}

impl<'a> Cluster<'a> {
    /// Create a new cluster with the provided parameters.
    pub const fn new(
        id: ClusterId,
        revision: u16,
        feature_map: u32,
        attributes: &'a [Attribute],
        accepted_commands: &'a [CmdId],
        generated_commands: &'a [CmdId],
    ) -> Self {
        Self {
            id,
            revision,
            feature_map,
            attributes,
            accepted_commands,
            generated_commands,
        }
    }

    /// Check if the accessor has the required permissions to access the attribute
    /// designated by the provided path.
    ///
    /// if `write` is true, the operation is a write operation, otherwise it is a read operation.
    pub(crate) fn check_attr_access(
        accessor: &Accessor,
        path: GenericPath,
        write: bool,
        target_perms: Access,
    ) -> Result<(), IMStatusCode> {
        let mut access_req = AccessReq::new(
            accessor,
            path,
            if write { Access::WRITE } else { Access::READ },
        );

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
        accessor: &Accessor,
        path: GenericPath,
    ) -> Result<(), IMStatusCode> {
        let mut access_req = AccessReq::new(accessor, path, Access::WRITE);

        access_req.set_target_perms(
            Access::WRITE
                .union(Access::NEED_OPERATE)
                .union(Access::NEED_MANAGE)
                .union(Access::NEED_ADMIN),
        ); // TODO
        if access_req.allow() {
            Ok(())
        } else {
            Err(IMStatusCode::UnsupportedAccess)
        }
    }

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
        for a in self.attributes.iter().filter(|a| !a.is_system()) {
            tw.u32(&TLVTag::Anonymous, a.id)?;
        }

        tw.u32(&TLVTag::Anonymous, GlobalElements::GeneratedCmdList as _)?;
        tw.u32(&TLVTag::Anonymous, GlobalElements::AcceptedCmdList as _)?;
        tw.u32(&TLVTag::Anonymous, GlobalElements::AttributeList as _)?;
        tw.u32(&TLVTag::Anonymous, GlobalElements::FeatureMap as _)?;
        tw.u32(&TLVTag::Anonymous, GlobalElements::ClusterRevision as _)?;

        tw.end_container()
    }

    fn encode_accepted_command_ids<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        Self::encode_command_ids(tag, tw, &self.accepted_commands)
    }

    fn encode_generated_command_ids<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        Self::encode_command_ids(tag, tw, &self.generated_commands)
    }

    fn encode_command_ids<W: TLVWrite>(
        tag: &TLVTag,
        mut tw: W,
        cmds: &[CmdId],
    ) -> Result<(), Error> {
        tw.start_array(tag)?;
        for a in cmds {
            tw.u32(&TLVTag::Anonymous, *a)?;
        }

        tw.end_container()
    }
}

impl core::fmt::Display for Cluster<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id: {}, ", self.id)?;

        write!(f, "attrs [")?;
        for (index, attr) in self.attributes.iter().enumerate() {
            if index > 0 {
                write!(f, ", {}", attr)?;
            } else {
                write!(f, ", {}", attr)?;
            }
        }

        write!(f, " ], acc-cmds [")?;
        for (index, cmd) in self.accepted_commands.iter().enumerate() {
            if index > 0 {
                write!(f, ", {}", cmd)?;
            } else {
                write!(f, ", {}", cmd)?;
            }
        }

        write!(f, " ], gen-cmds [")?;
        for (index, cmd) in self.generated_commands.iter().enumerate() {
            if index > 0 {
                write!(f, ", {}", cmd)?;
            } else {
                write!(f, ", {}", cmd)?;
            }
        }

        write!(f, " ]")
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Cluster<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "id: {}, ", self.id);

        defmt::write!(f, "attrs [");
        for (index, attr) in self.attributes.iter().enumerate() {
            if index > 0 {
                defmt::write!(f, ", {}", attr);
            } else {
                defmt::write!(f, ", {}", attr);
            }
        }

        defmt::write!(f, " ], acc-cmds [");
        for (index, cmd) in self.accepted_commands.iter().enumerate() {
            if index > 0 {
                write!(f, ", {}", cmd)?;
            } else {
                write!(f, ", {}", cmd)?;
            }
        }

        defmt::write!(f, " ], gen-cmds [");
        for (index, cmd) in self.generated_commands.iter().enumerate() {
            if index > 0 {
                defmt::write!(f, ", {}", cmd);
            } else {
                defmt::write!(f, ", {}", cmd);
            }
        }

        defmt::write!(f, " ]")
    }
}
