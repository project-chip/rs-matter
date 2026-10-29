/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::ROOT_ENDPOINT_ID;
use crate::{Endpoint, Metadata};

use super::{ClusterId, EndptId};

/// The ID of the Access Control cluster.
const ACCESS_CONTROL_CLUSTER_ID: ClusterId = 0x001F;
/// The `AUXILIARY` feature bit of the Access Control cluster.
const ACCESS_CONTROL_FEATURE_AUXILIARY: u32 = 0x04;

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

    /// Return true if the node metadata advertises the `AUXILIARY` feature, which
    /// indicates that the node has a feature (e.g. a Groupcast cluster) that
    /// synthesizes auxiliary ACL entries and requires the special access-control
    /// behavior mandated by the Matter Core spec for nodes with the feature.
    pub fn aux_acl_enabled(&self) -> bool {
        self.endpoint(ROOT_ENDPOINT_ID)
            .and_then(|endpoint| endpoint.cluster(ACCESS_CONTROL_CLUSTER_ID))
            .is_some_and(|cluster| cluster.feature_map & ACCESS_CONTROL_FEATURE_AUXILIARY != 0)
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

pub trait AuxAclCheck {
    /// Return true if the metadata advertises the `AUXILIARY` feature, which
    /// indicates that the node has a feature (e.g. a Groupcast cluster) that
    /// synthesizes auxiliary ACL entries and requires the special access-control
    /// behavior mandated by the Matter Core spec for nodes with the feature.
    fn aux_acl_enabled(&self) -> bool;
}

impl<T> AuxAclCheck for T
where
    T: Metadata,
{
    fn aux_acl_enabled(&self) -> bool {
        self.access(|node| node.aux_acl_enabled())
    }
}
