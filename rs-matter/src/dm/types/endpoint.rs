/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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
    /// The list of *server* clusters present on this endpoint. These
    /// are advertised via `Descriptor::ServerList` and dispatched by
    /// the `Handler` chain on inbound IM messages.
    pub clusters: &'a [Cluster<'a>],
    /// The list of *client* cluster IDs present on this endpoint —
    /// i.e. clusters this endpoint **initiates** interactions for,
    /// rather than serves. Advertised verbatim via
    /// `Descriptor::ClientList` so commissioners know which Binding
    /// targets are meaningful for this endpoint. Empty by default;
    /// only meaningful on endpoints whose device type prescribes
    /// client clusters (e.g. `OnOffLightSwitch = 0x0103` lists
    /// `OnOff` as a mandatory client). No `Cluster<'a>` value is
    /// needed because a client cluster has no attribute/command
    /// surface of its own — see Matter Core spec §9.5.4 for the
    /// `Descriptor::ClientList` semantics.
    pub client_clusters: &'a [ClusterId],
}

impl<'a> Endpoint<'a> {
    /// Create a new `Endpoint` instance with no client clusters.
    ///
    /// Use [`Self::new_with_clients`] when this endpoint should
    /// advertise client clusters via `Descriptor::ClientList`.
    pub const fn new(
        id: EndptId,
        device_types: &'a [DeviceType],
        clusters: &'a [Cluster<'a>],
    ) -> Self {
        Self {
            id,
            device_types,
            clusters,
            client_clusters: &[],
        }
    }

    /// Create a new `Endpoint` instance that advertises the given
    /// client cluster IDs in addition to its server clusters.
    pub const fn new_with_clients(
        id: EndptId,
        device_types: &'a [DeviceType],
        clusters: &'a [Cluster<'a>],
        client_clusters: &'a [ClusterId],
    ) -> Self {
        Self {
            id,
            device_types,
            clusters,
            client_clusters,
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
