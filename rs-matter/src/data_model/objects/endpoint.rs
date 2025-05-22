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

use core::fmt;

use super::{Cluster, ClusterId, DeviceType, EndptId};

/// A type modeling the endpoint meta-data in the Matter data model.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Endpoint<'a> {
    /// The endpoint ID.
    pub id: EndptId,
    /// The list of device types associated with this endpoint.
    pub device_types: &'a [DeviceType],
    /// The list of clusters associated with this endpoint.
    pub clusters: &'a [Cluster<'a>],
}

impl<'a> Endpoint<'a> {
    /// Create a new `Endpoint` instance.
    pub const fn new(
        id: EndptId,
        device_types: &'a [DeviceType],
        clusters: &'a [Cluster<'a>],
    ) -> Self {
        Self {
            id,
            device_types,
            clusters,
        }
    }

    /// Return a reference to the cluster with the given ID, if it exists.
    pub fn cluster(&self, id: ClusterId) -> Option<&Cluster<'a>> {
        self.clusters.iter().find(|cluster| cluster.id == id)
    }
}

impl core::fmt::Display for Endpoint<'_> {
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
