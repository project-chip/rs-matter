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

use crate::acl::Accessor;
use crate::dm::{Cluster, Endpoint};
use crate::im::encoding::{AttrPath, EventPath, GenericPath, IMStatusCode};
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;

use super::{EndptId, NodeId};

/// The main Matter metadata type describing a Matter Node.
///
/// # Invariants
///
/// 1. Endpoints must be in **strictly increasing order** of `Endpoint::id`.
/// 2. Per-endpoint shape is **stable for the endpoint's lifetime**.
///    Once an endpoint with a given id has been added to a `Node`, its
///    `clusters` slice and each cluster's attribute / command / event
///    lists must not change. Whole endpoints may still be added or
///    removed at runtime. Mutating a cluster's attribute or server
///    list is a change to F-quality metadata (Matter Core spec
///    `AttributeList` / `ServerList`) and must be
///    accompanied by a `ConfigurationVersion` bump, which in practice
///    means a restart of the `rs-matter` service and likely - of the
///    whole process anyway.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Node<'a> {
    /// The endpoints of the (one and only) node in the Interaction & Data Model.
    ///
    /// See the [`Node`] type-level docs for the invariants this slice
    /// must satisfy.
    pub endpoints: &'a [Endpoint<'a>],
}

impl<'a> Node<'a> {
    /// Create a new node with the given endpoints.
    pub const fn new(endpoints: &'a [Endpoint<'a>]) -> Self {
        Self { endpoints }
    }

    /// Return a reference to the endpoint with the given ID, if it exists.
    pub fn endpoint(&self, id: EndptId) -> Option<&Endpoint<'a>> {
        self.endpoints.iter().find(|endpoint| endpoint.id == id)
    }

    pub(crate) fn validate_attr_path(
        &self,
        path: &AttrPath,
        timed: bool,
        write: bool,
        accessor: &Accessor<'_>,
    ) -> Result<(), IMStatusCode> {
        if let Some(node_id) = path.node {
            self.validate_node_id(node_id, accessor)?;
        }

        let gp = path.to_gp();

        let Some((endpoint, cluster, attr_id)) = self.validate_cluster_path(&gp)? else {
            return Ok(());
        };

        let Some(attr) = cluster.attribute(attr_id) else {
            return Err(IMStatusCode::UnsupportedAttribute);
        };

        cluster.check_attr_access(accessor, timed, gp, endpoint.device_types, write, attr.id)
    }

    pub(crate) fn validate_event_path(
        &self,
        path: &EventPath,
        accessor: &Accessor<'_>,
    ) -> Result<(), IMStatusCode> {
        if let Some(node_id) = path.node {
            self.validate_node_id(node_id, accessor)?;
        }

        let gp = path.to_gp();

        let Some((endpoint, cluster, event_id)) = self.validate_cluster_path(&gp)? else {
            return Ok(());
        };

        let Some(event) = cluster.event(event_id) else {
            return Err(IMStatusCode::UnsupportedEvent);
        };

        cluster.check_event_access(accessor, gp, endpoint.device_types, event.id)
    }

    fn validate_cluster_path(
        &self,
        path: &GenericPath,
    ) -> Result<Option<(&Endpoint<'_>, &Cluster<'_>, u32)>, IMStatusCode> {
        let Some(endpoint_id) = path.endpoint else {
            return Ok(None);
        };

        let Some(endpoint) = self.endpoint(endpoint_id) else {
            // Endpoint does not exist
            return Err(IMStatusCode::UnsupportedEndpoint);
        };

        let Some(cluster_id) = path.cluster else {
            return Ok(None);
        };

        let Some(cluster) = endpoint.cluster(cluster_id) else {
            // Cluster does not exist on this endpoint
            return Err(IMStatusCode::UnsupportedCluster);
        };

        let Some(leaf_id) = path.leaf else {
            return Ok(None);
        };

        Ok(Some((endpoint, cluster, leaf_id)))
    }

    fn validate_node_id(
        &self,
        node_id: NodeId,
        accessor: &Accessor<'_>,
    ) -> Result<(), IMStatusCode> {
        let Some(accessor_node_id) = accessor.node_id() else {
            return Err(IMStatusCode::UnsupportedNode);
        };

        if node_id != accessor_node_id {
            return Err(IMStatusCode::UnsupportedNode);
        }

        Ok(())
    }

    /// Return `true` if at least one attribute matching the (potentially wildcard) path
    /// is accessible to the given accessor. Used for subscription validation.
    pub(crate) fn has_accessible_attr(&self, path: &AttrPath, accessor: &Accessor<'_>) -> bool {
        for endpoint in self.endpoints.iter() {
            if let Some(ep_id) = path.endpoint {
                if endpoint.id != ep_id {
                    continue;
                }
            }

            for cluster in endpoint.clusters.iter() {
                if let Some(cluster_id) = path.cluster {
                    if cluster.id != cluster_id {
                        continue;
                    }
                }

                for attr in cluster.attributes.iter() {
                    if let Some(attr_id) = path.attr {
                        if attr.id != attr_id {
                            continue;
                        }
                    }

                    let gp = GenericPath::new(Some(endpoint.id), Some(cluster.id), Some(attr.id));

                    if cluster
                        .check_attr_access(
                            accessor,
                            false,
                            gp,
                            endpoint.device_types,
                            false,
                            attr.id,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
            }
        }

        false
    }
}

impl core::fmt::Display for Node<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "node:")?;
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            writeln!(f, "endpoint {}: {}", index, endpoint)?;
        }

        write!(f, "")
    }
}

/// A dynamic node that can be modified at runtime.
pub struct DynamicNode<'a, const N: usize> {
    endpoints: Vec<Endpoint<'a>, N>,
}

impl<'a, const N: usize> DynamicNode<'a, N> {
    /// Create a new dynamic node.
    pub const fn new() -> Self {
        Self {
            endpoints: Vec::new(),
        }
    }

    /// Return an in-place initializer for `DynamicNode`.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            endpoints <- Vec::init(),
        })
    }

    /// Return a static node view of the dynamic node.
    ///
    /// Necessary, because the `Metadata` trait needs a `Node` type
    pub fn node(&self) -> Node<'_> {
        Node {
            endpoints: &self.endpoints,
        }
    }

    /// Add an endpoint to the dynamic node.
    ///
    /// The endpoint is inserted so that [`Node::endpoints`] stays
    /// sorted by id (see the [`Node`] invariants).
    pub fn add(&mut self, endpoint: Endpoint<'a>) -> Result<(), Endpoint<'a>> {
        match self.endpoints.iter().position(|ep| ep.id >= endpoint.id) {
            Some(i) if self.endpoints[i].id == endpoint.id => Err(endpoint),
            Some(i) => self.endpoints.insert(i, endpoint),
            None => self.endpoints.push(endpoint),
        }
    }

    /// Remove an endpoint from the dynamic node.
    ///
    /// Uses an order-preserving `remove` (rather than `swap_remove`)
    /// to keep [`Node::endpoints`] sorted by id.
    pub fn remove(&mut self, endpoint_id: u16) -> Option<Endpoint<'a>> {
        let index = self.endpoints.iter().position(|ep| ep.id == endpoint_id)?;
        Some(self.endpoints.remove(index))
    }
}

impl<const N: usize> core::fmt::Display for DynamicNode<'_, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.node().fmt(f)
    }
}

impl<'a, const N: usize> Default for DynamicNode<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}
