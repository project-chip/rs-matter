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

use super::{Cluster, ClusterId, DeviceType, EndptId, SemanticTag};

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
    /// surface of its own — see Matter Core spec for the
    /// `Descriptor::ClientList` semantics.
    pub client_clusters: &'a [ClusterId],
    /// The endpoint's unique ID, advertised via
    /// `Descriptor::EndpointUniqueID`. `None` by default.
    ///
    /// A manufacturer-assigned string (at most 32 bytes) that identifies this
    /// endpoint uniquely within the node, so that machine-to-machine
    /// integrations can keep addressing "the same" endpoint even if endpoint
    /// IDs get renumbered across software updates or bridge re-compositions.
    ///
    /// Populating this also requires the endpoint's `Descriptor` metadata to
    /// advertise the optional `EndpointUniqueID` attribute - see
    /// [`crate::dm::clusters::desc::CLUSTER_ENDPOINT_UNIQUE_ID`].
    pub unique_id: Option<&'a str>,
    /// The semantic tags describing this endpoint, advertised via
    /// `Descriptor::TagList`. Empty by default.
    ///
    /// These are only *required* when the node exposes several endpoints with
    /// the same device type under one parent: Matter Core spec 9.5 then demands
    /// that each carries a non-empty, mutually distinct `TagList` so the
    /// endpoints can be told apart. Populating this also requires the endpoint's
    /// `Descriptor` metadata to advertise the `TagList` feature and attribute -
    /// see [`crate::dm::clusters::desc::CLUSTER_TAG_LIST`].
    pub semantic_tags: &'a [SemanticTag<'a>],
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
            unique_id: None,
            semantic_tags: &[],
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
            unique_id: None,
            semantic_tags: &[],
        }
    }

    /// Return this endpoint with the given semantic tags attached, to be
    /// advertised via `Descriptor::TagList`.
    ///
    /// The endpoint's `Descriptor` cluster metadata must also advertise the
    /// attribute and feature - use
    /// [`crate::dm::clusters::desc::CLUSTER_TAG_LIST`] in place of the default
    /// `DescHandler::CLUSTER`, otherwise the tags are never reported.
    pub const fn with_tags(self, semantic_tags: &'a [SemanticTag<'a>]) -> Self {
        Self {
            id: self.id,
            device_types: self.device_types,
            clusters: self.clusters,
            client_clusters: self.client_clusters,
            unique_id: self.unique_id,
            semantic_tags,
        }
    }

    /// Return this endpoint with the given unique ID attached, to be
    /// advertised via `Descriptor::EndpointUniqueID`.
    ///
    /// The endpoint's `Descriptor` cluster metadata must also advertise the
    /// attribute - use
    /// [`crate::dm::clusters::desc::CLUSTER_ENDPOINT_UNIQUE_ID`] in place of
    /// the default `DescHandler::CLUSTER`, otherwise the ID is never reported.
    pub const fn with_unique_id(self, unique_id: &'a str) -> Self {
        Self {
            id: self.id,
            device_types: self.device_types,
            clusters: self.clusters,
            client_clusters: self.client_clusters,
            unique_id: Some(unique_id),
            semantic_tags: self.semantic_tags,
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
