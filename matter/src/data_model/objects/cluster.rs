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

use log::error;
use strum::FromRepr;

use crate::{
    acl::{AccessReq, Accessor},
    attribute_enum,
    data_model::objects::*,
    error::Error,
    interaction_model::{
        core::IMStatusCode,
        messages::{
            ib::{AttrPath, AttrStatus, CmdPath, CmdStatus},
            GenericPath,
        },
    },
    // TODO: This layer shouldn't really depend on the TLV layer, should create an abstraction layer
    tlv::{Nullable, TLVWriter, TagType},
};
use core::{
    convert::TryInto,
    fmt::{self, Debug},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, FromRepr)]
#[repr(u16)]
pub enum GlobalElements {
    _ClusterRevision = 0xFFFD,
    FeatureMap = 0xFFFC,
    AttributeList = 0xFFFB,
    _EventList = 0xFFFA,
    _ClientGenCmd = 0xFFF9,
    ServerGenCmd = 0xFFF8,
    FabricIndex = 0xFE,
}

attribute_enum!(GlobalElements);

pub const FEATURE_MAP: Attribute =
    Attribute::new(GlobalElements::FeatureMap as _, Access::RV, Quality::NONE);

pub const ATTRIBUTE_LIST: Attribute = Attribute::new(
    GlobalElements::AttributeList as _,
    Access::RV,
    Quality::NONE,
);

// TODO: What if we instead of creating this, we just pass the AttrData/AttrPath to the read/write
// methods?
/// The Attribute Details structure records the details about the attribute under consideration.
#[derive(Debug)]
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

impl<'a> AttrDetails<'a> {
    pub fn is_system(&self) -> bool {
        Attribute::is_system_attr(self.attr_id)
    }

    pub fn path(&self) -> AttrPath {
        AttrPath {
            endpoint: Some(self.endpoint_id),
            cluster: Some(self.cluster_id),
            attr: Some(self.attr_id),
            list_index: self.list_index,
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
pub struct CmdDetails<'a> {
    pub node: &'a Node<'a>,
    pub endpoint_id: EndptId,
    pub cluster_id: ClusterId,
    pub cmd_id: CmdId,
    pub wildcard: bool,
}

impl<'a> CmdDetails<'a> {
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
    pub feature_map: u32,
    pub attributes: &'a [Attribute],
    pub commands: &'a [CmdId],
}

impl<'a> Cluster<'a> {
    pub const fn new(
        id: ClusterId,
        feature_map: u32,
        attributes: &'a [Attribute],
        commands: &'a [CmdId],
    ) -> Self {
        Self {
            id,
            feature_map,
            attributes,
            commands,
        }
    }

    pub fn match_attributes(
        &self,
        attr: Option<AttrId>,
    ) -> impl Iterator<Item = &'_ Attribute> + '_ {
        self.attributes
            .iter()
            .filter(move |attribute| attr.map(|attr| attr == attribute.id).unwrap_or(true))
    }

    pub fn match_commands(&self, cmd: Option<CmdId>) -> impl Iterator<Item = CmdId> + '_ {
        self.commands
            .iter()
            .filter(move |id| cmd.map(|cmd| **id == cmd).unwrap_or(true))
            .copied()
    }

    pub fn check_attribute(
        &self,
        accessor: &Accessor,
        ep: EndptId,
        attr: AttrId,
        write: bool,
    ) -> Result<(), IMStatusCode> {
        let attribute = self
            .attributes
            .iter()
            .find(|attribute| attribute.id == attr)
            .ok_or(IMStatusCode::UnsupportedAttribute)?;

        Self::check_attr_access(
            accessor,
            GenericPath::new(Some(ep), Some(self.id), Some(attr as _)),
            write,
            attribute.access,
        )
    }

    pub fn check_command(
        &self,
        accessor: &Accessor,
        ep: EndptId,
        cmd: CmdId,
    ) -> Result<(), IMStatusCode> {
        self.commands
            .iter()
            .find(|id| **id == cmd)
            .ok_or(IMStatusCode::UnsupportedCommand)?;

        Self::check_cmd_access(
            accessor,
            GenericPath::new(Some(ep), Some(self.id), Some(cmd)),
        )
    }

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
            GlobalElements::AttributeList => {
                self.encode_attribute_ids(AttrDataWriter::TAG, &mut writer)?;
                writer.complete()
            }
            GlobalElements::FeatureMap => writer.set(self.feature_map),
            other => {
                error!("This attribute is not yet handled {:?}", other);
                Err(Error::AttributeNotFound)
            }
        }
    }

    fn encode_attribute_ids(&self, tag: TagType, tw: &mut TLVWriter) -> Result<(), Error> {
        tw.start_array(tag)?;
        for a in self.attributes {
            tw.u16(TagType::Anonymous, a.id)?;
        }

        tw.end_container()
    }
}

impl<'a> core::fmt::Display for Cluster<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id:{}, ", self.id)?;
        write!(f, "attrs[")?;
        let mut comma = "";
        for element in self.attributes.iter() {
            write!(f, "{} {}", comma, element)?;
            comma = ",";
        }
        write!(f, " ], ")
    }
}
