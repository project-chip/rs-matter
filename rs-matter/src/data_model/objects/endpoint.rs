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

use crate::{acl::Accessor, interaction_model::core::IMStatusCode};

use core::fmt;

use super::{AttrId, Attribute, Cluster, ClusterId, CmdId, DeviceType, EndptId};

#[derive(Debug, Clone)]
pub struct Endpoint<'a> {
    pub id: EndptId,
    pub device_types: &'a [DeviceType],
    pub clusters: &'a [Cluster<'a>],
}

impl<'a> Endpoint<'a> {
    pub fn match_attributes(
        &self,
        cl: Option<ClusterId>,
        attr: Option<AttrId>,
    ) -> impl Iterator<Item = (&'_ Cluster, &'_ Attribute)> + '_ {
        self.match_clusters(cl).flat_map(move |cluster| {
            cluster
                .match_attributes(attr)
                .map(move |attr| (cluster, attr))
        })
    }

    pub fn match_commands(
        &self,
        cl: Option<ClusterId>,
        cmd: Option<CmdId>,
    ) -> impl Iterator<Item = (&'_ Cluster, CmdId)> + '_ {
        self.match_clusters(cl)
            .flat_map(move |cluster| cluster.match_commands(cmd).map(move |cmd| (cluster, cmd)))
    }

    pub fn check_attribute(
        &self,
        accessor: &Accessor,
        cl: ClusterId,
        attr: AttrId,
        write: bool,
    ) -> Result<(), IMStatusCode> {
        self.check_cluster(cl)
            .and_then(|cluster| cluster.check_attribute(accessor, self.id, attr, write))
    }

    pub fn check_command(
        &self,
        accessor: &Accessor,
        cl: ClusterId,
        cmd: CmdId,
    ) -> Result<(), IMStatusCode> {
        self.check_cluster(cl)
            .and_then(|cluster| cluster.check_command(accessor, self.id, cmd))
    }

    pub fn match_clusters(&self, cl: Option<ClusterId>) -> impl Iterator<Item = &'_ Cluster> + '_ {
        self.clusters
            .iter()
            .filter(move |cluster| cl.map(|id| id == cluster.id).unwrap_or(true))
    }

    pub fn check_cluster(&self, cl: ClusterId) -> Result<&Cluster, IMStatusCode> {
        self.clusters
            .iter()
            .find(|cluster| cluster.id == cl)
            .ok_or(IMStatusCode::UnsupportedCluster)
    }
}

impl<'a> core::fmt::Display for Endpoint<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "clusters:[")?;
        let mut comma = "";
        for cluster in self.clusters {
            write!(f, "{} {{ {} }}", comma, cluster)?;
            comma = ", ";
        }

        write!(f, "]")
    }
}
