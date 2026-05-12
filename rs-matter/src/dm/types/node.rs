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

use core::cell::Cell;
use core::fmt;

use crate::acl::Accessor;
use crate::dm::{Cluster, Endpoint, Metadata, Quality};
use crate::error::Error;
use crate::im::{
    AttrData, AttrPath, AttrStatus, CmdData, CmdStatus, DataVersionFilter, EventPath, GenericPath,
    IMStatusCode, InvReq, NodeId, ReportDataReq, WriteReq,
};
use crate::tlv::{TLVArray, TLVElement};
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;

use super::{AttrDetails, ClusterId, CmdDetails, EndptId};

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
///    §7.13.2.2 `AttributeList`, §7.13.2.4 `ServerList`) and must be
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

/// Expand (potentially wildcard) read requests into concrete attribute details
/// using the node metadata.
///
/// As part of the expansion, the method will check whether the attributes are
/// accessible by the accessor and whether they should be served based on the
/// fabric filtering and dataver filtering rules and filter out the inaccessible ones (wildcard reads)
/// or report an error status for the non-wildcard ones.
pub fn expand_read<'m, M, F>(
    metadata: M,
    req: &'m ReportDataReq,
    accessor: &'m Accessor<'m>,
    filter: F,
) -> Result<impl Iterator<Item = Result<Result<AttrDetails, AttrStatus>, Error>> + 'm, Error>
where
    M: Metadata + 'm,
    F: FnMut(EndptId, ClusterId, u32) -> bool + 'm,
{
    let dataver_filters = req.dataver_filters()?;
    let fabric_filtered = req.fabric_filtered()?;

    Ok(PathExpanderIterator::new(
        metadata,
        accessor,
        false,
        req.attr_requests()?.map(|reqs| {
            reqs.into_iter().map(move |path_result| {
                path_result.map(|path| AttrReadPath {
                    path,
                    dataver_filters: dataver_filters.clone(),
                    fabric_filtered,
                })
            })
        }),
        filter,
    ))
}

/// Expand (potentially wildcard) write requests into concrete attribute details
/// using the node metadata.
///
/// As part of the expansion, the method will check whether the attributes are
/// accessible by the accessor and filter out the inaccessible ones (wildcard writes)
/// or report an error status for the non-wildcard ones.
#[allow(clippy::type_complexity)]
pub fn expand_write<'m, M>(
    metadata: M,
    req: &'m WriteReq,
    accessor: &'m Accessor<'m>,
) -> Result<
    impl Iterator<Item = Result<Result<(AttrDetails, TLVElement<'m>), AttrStatus>, Error>> + 'm,
    Error,
>
where
    M: Metadata + 'm,
{
    Ok(PathExpanderIterator::new(
        metadata,
        accessor,
        req.timed_request()?,
        Some(req.write_requests()?.into_iter()),
        |_, _, _| true,
    ))
}

/// Expand (potentially wildcard) invoke requests into concrete command details
/// using the node metadata.
///
/// As part of the expansion, the method will check whether the commands are
/// accessible by the accessor and filter out the inaccessible ones (wildcard invocations)
/// or report an error status for the non-wildcard ones.
#[allow(clippy::type_complexity)]
pub fn expand_invoke<'m, M>(
    metadata: M,
    req: &'m InvReq,
    accessor: &'m Accessor<'m>,
) -> Result<
    impl Iterator<Item = Result<Result<(CmdDetails, TLVElement<'m>), CmdStatus>, Error>> + 'm,
    Error,
>
where
    M: Metadata + 'm,
{
    Ok(PathExpanderIterator::new(
        metadata,
        accessor,
        req.timed_request()?,
        req.inv_requests()?.map(move |reqs| reqs.into_iter()),
        |_, _, _| true,
    ))
}

/// A helper type for `AttrPath` that enriches it with the request-scope information
/// of whether the attributes served as part of that request should be fabric filtered
/// as well as with information which attributes should only be served if their
/// dataver had changed.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct AttrReadPath<'a> {
    path: AttrPath,
    dataver_filters: Option<TLVArray<'a, DataVersionFilter>>,
    fabric_filtered: bool,
}

/// A helper type for `PathExpander` that captures what type of expansion is being done:
/// Read requests, write requests, or invoke requests.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Operation {
    Read,
    Write,
    Invoke,
}

/// A helper trait type for `PathExpander` modeling a generic "item which can be expanded".
///
/// The item must contain a path (`GenericPath`) but might contain other data as well,
/// which needs to be carried over to the expanded output.
trait PathExpansionItem<'a> {
    /// Path of expansion for what type of operation: read (or subscribe which is considered the same), write or invoke
    const OPERATION: Operation;

    /// The type of the expanded item
    type Expanded<'n>;
    /// The type of the error status if expansion of that particular item failed
    type Status;

    /// The path of the item to be expanded
    fn path(&self) -> GenericPath;

    /// Expand the item into the expanded output.
    ///
    /// When expanding, the provided endpoint/cluser/leaf IDs are used
    /// as the original ones might be wildcarded.
    fn expand(
        &self,
        accessor: &Accessor<'_>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        leaf_id: u32,
        array: bool,
    ) -> Result<Self::Expanded<'a>, Error>;

    /// Convert the item into an error status if the expansion failed.
    fn into_status(self, status: IMStatusCode) -> Self::Status;
}

/// `PathExpansionItem` implementation for `AttrReadPath` (attr read requests expansion).
impl<'a> PathExpansionItem<'a> for AttrReadPath<'a> {
    const OPERATION: Operation = Operation::Read;

    type Expanded<'n> = AttrDetails;
    type Status = AttrStatus;

    fn path(&self) -> GenericPath {
        self.path.to_gp()
    }

    fn expand(
        &self,
        accessor: &Accessor<'_>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        leaf_id: u32,
        array: bool,
    ) -> Result<Self::Expanded<'a>, Error> {
        Ok(AttrDetails {
            endpoint_id,
            cluster_id,
            attr_id: leaf_id as _,
            wildcard: self.path.to_gp().is_wildcard(),
            list_index: self.path.list_index.clone(),
            list_chunked: false,
            fab_idx: accessor.fab_idx,
            fab_filter: self.fabric_filtered,
            dataver: dataver(self.dataver_filters.as_ref(), endpoint_id, cluster_id)?,
            array,
            cluster_status: Cell::new(0),
        })
    }

    fn into_status(self, status: IMStatusCode) -> Self::Status {
        AttrStatus::new(self.path, status, None)
    }
}

/// `PathExpansionItem` implementation for `AttrData` (attr write requests expansion).
impl<'a> PathExpansionItem<'a> for AttrData<'a> {
    const OPERATION: Operation = Operation::Write;

    type Expanded<'n> = (AttrDetails, TLVElement<'n>);
    type Status = AttrStatus;

    fn path(&self) -> GenericPath {
        self.path.to_gp()
    }

    fn expand(
        &self,
        accessor: &Accessor<'_>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        leaf_id: u32,
        array: bool,
    ) -> Result<Self::Expanded<'a>, Error> {
        let expanded = (
            AttrDetails {
                endpoint_id,
                cluster_id,
                attr_id: leaf_id as _,
                wildcard: self.path.to_gp().is_wildcard(),
                list_index: self.path.list_index.clone(),
                list_chunked: false,
                fab_idx: accessor.fab_idx,
                // As per the Matter Core spec, Attribute Write requests
                // are assumed to be always fabric-filtered
                fab_filter: true,
                dataver: self.data_ver,
                array,
                cluster_status: Cell::new(0),
            },
            self.data.clone(),
        );

        Ok(expanded)
    }

    fn into_status(self, status: IMStatusCode) -> Self::Status {
        AttrStatus::new(self.path, status, None)
    }
}

/// `PathExpansionItem` implementation for `CmdData` (command requests expansion).
impl<'a> PathExpansionItem<'a> for CmdData<'a> {
    const OPERATION: Operation = Operation::Invoke;

    type Expanded<'n> = (CmdDetails, TLVElement<'n>);
    type Status = CmdStatus;

    fn path(&self) -> GenericPath {
        self.path.to_gp()
    }

    fn expand(
        &self,
        accessor: &Accessor<'_>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        leaf_id: u32,
        _array: bool,
    ) -> Result<Self::Expanded<'a>, Error> {
        let expanded = (
            CmdDetails::new(
                endpoint_id,
                cluster_id,
                leaf_id,
                accessor.fab_idx,
                false,
                self.command_ref,
            ),
            self.data.clone(),
        );

        Ok(expanded)
    }

    fn into_status(self, status: IMStatusCode) -> Self::Status {
        CmdStatus::new(self.path, status, None, self.command_ref)
    }
}

/// An iterator that expands a list of paths into concrete attribute/command details.
///
/// While the iterator can be (and used to be) implemented by using monadic combinators,
/// this implementation is done in a more imperative way to avoid the overhead of monadic
/// combinators in terms of memory size.
struct PathExpander<'a, T, I, F> {
    /// The accessor to check the access rights.
    accessor: &'a Accessor<'a>,
    /// Where the paths are part of a timed interaction
    timed: bool,
    /// The paths to expand.
    items: Option<I>,
    /// The current path item being expanded.
    item: Option<T>,
    /// The id of the endpoint currently anchoring the scan, or `None`
    /// before the first endpoint has been entered (or right after the
    /// item changes / the previous endpoint has been exhausted). This
    /// is the *only* state needed to resume correctly across
    /// metadata-lock releases:
    ///
    /// At the top of every `next_for_path` call we look the id up in
    /// `Node::endpoints` via `binary_search_by_key`:
    /// - `Ok(i)` — endpoint is still there (possibly at a different
    ///   index); use `i` as `endpoint_index` and trust the existing
    ///   `cluster_index` / `leaf_index` (Node-level invariant: an
    ///   endpoint's cluster shape is stable for its lifetime).
    /// - `Err(i)` — endpoint is gone; resume at `endpoint_index = i`
    ///   (the insertion point — strictly past everything we've already
    ///   yielded, because endpoints are sorted ascending by id) with
    ///   `cluster_index` / `leaf_index` zeroed.
    ///
    /// `cluster_index` / `leaf_index` are not separately mirrored by
    /// id: the per-endpoint shape invariant means the array slot we
    /// were about to read next is still the right one, so positional
    /// indices suffice once the endpoint is re-anchored.
    ///
    /// The endpoint array *index* is not held on `self` at all — it
    /// is derived fresh at the top of every `next_for_path` call from
    /// this id (via `binary_search_by_key`), since the array layout
    /// can shift between calls. Within a single call it lives on the
    /// stack as the outer-loop counter.
    endpoint_id: Option<EndptId>,
    /// The current cluster index within the anchored endpoint.
    cluster_index: u16,
    /// The current leaf index within the anchored cluster.
    leaf_index: u16,
    /// Filter the expanded item or not
    filter: F,
    /// Last concrete `(endpoint_id, cluster_id, leaf_id)` triple whose
    /// access check succeeded during this expansion run. When the next
    /// expanded leaf matches this triple, the access check is bypassed.
    ///
    /// This is the mechanism that resolves the "DeleteAll + Add×N on the
    /// ACL cluster within one WriteRequest" tension (Matter Core spec
    /// §10.6.4): chip-tool serializes a list-replace as `DeleteAll`
    /// followed by N per-element `Add`s, all targeting the **same**
    /// concrete attribute path. The first op authorizes against the
    /// fabric's current ACL; subsequent same-path ops cache-hit and
    /// bypass the re-check — so an admin's permission isn't accidentally
    /// revoked midway through replacing their own ACL with a new entry.
    /// Mirrors `mLastSuccessfullyWrittenPath` in CHIP's `WriteHandler`.
    ///
    /// Soundness: the required privilege for a given concrete path is
    /// constant (cluster-metadata-defined), and the accessor / session
    /// doesn't change within an expansion, so re-using a prior
    /// authorization for the same path is safe. The cache is **not**
    /// reset when advancing to a new item from `items` — that's
    /// deliberate: `DeleteAll + Add×N` arrives as N+1 separate
    /// `AttrData` items in the same WriteRequest, and they all need
    /// to share one access decision for the operation to be atomic.
    /// A different concrete `(endpoint, cluster, leaf)` triple simply
    /// misses the cache and re-runs the check.
    last_authorized: Option<(EndptId, ClusterId, u32)>,
}

impl<'a, T, I, F> PathExpander<'a, T, I, F>
where
    I: Iterator<Item = Result<T, Error>>,
    T: PathExpansionItem<'a>,
    F: FnMut(EndptId, ClusterId, u32) -> bool,
{
    /// Create a new path expander with the given accessor and paths.
    pub const fn new(accessor: &'a Accessor<'a>, timed: bool, paths: Option<I>, filter: F) -> Self {
        Self {
            accessor,
            timed,
            items: paths,
            item: None,
            endpoint_id: None,
            cluster_index: 0,
            leaf_index: 0,
            filter,
            last_authorized: None,
        }
    }

    #[allow(clippy::type_complexity)]
    fn next(
        &mut self,
        node: &Node<'_>,
    ) -> Option<Result<Result<T::Expanded<'a>, T::Status>, Error>> {
        loop {
            // Fetch an item to expand if not already there
            if self.item.is_none() {
                let item = self.items.as_mut().and_then(|items| items.next())?;

                match item {
                    Err(err) => break Some(Err(err)),
                    Ok(item) => self.item = Some(item),
                }

                // Each new item starts expansion from scratch; the
                // endpoint-id resume anchor is per-item.
                self.endpoint_id = None;
                self.cluster_index = 0;
                self.leaf_index = 0;
            }

            // From here on, we do have a valid `self.item` to expand

            // Step on the first/next expanded path of the item
            match self.next_for_path(node) {
                Ok(Some((endpoint_id, cluster_id, leaf_id, array))) => {
                    // Next expansion of the path

                    let expanded = unwrap!(self.item.as_ref()).expand(
                        self.accessor,
                        endpoint_id,
                        cluster_id,
                        leaf_id,
                        array,
                    );

                    if !unwrap!(self.item.as_ref()).path().is_wildcard() {
                        // Non-wildcard path, remove the current item
                        self.item = None;
                    }

                    break Some(expanded.map(Ok));
                }
                Ok(None) => {
                    // This path is exhausted, time to move to the next one
                    self.item = None;
                }
                Err(status) => {
                    // Report an error status and remove the current item
                    break Some(Ok(Err(unwrap!(self.item.take()).into_status(status))));
                }
            }
        }
    }

    /// Move to the next (endpoint, cluster, leaf) triple that matches the path
    /// of the current item.
    ///
    /// Returns an error status if no match is found, where the error status indicates
    /// whether the endpoint, the cluster, or the leaf is not matching.
    ///
    /// This method should only be called when `self.item` is `Some` or else it will panic.
    fn next_for_path(
        &mut self,
        node: &Node<'_>,
    ) -> Result<Option<(EndptId, ClusterId, u32, bool)>, IMStatusCode> {
        let path = unwrap!(self.item.as_ref().map(PathExpansionItem::path));

        let command = matches!(T::OPERATION, Operation::Invoke);
        let attr_read = matches!(T::OPERATION, Operation::Read);

        // Do some basic checks on wildcards, as not all wildcards are supported for each type of operation
        if !attr_read {
            if path.cluster.is_none() {
                return Err(IMStatusCode::UnsupportedCluster);
            }

            if path.leaf.is_none() {
                return Err(IMStatusCode::UnsupportedAttribute);
            }
        }

        // Re-anchor the scan against the *current* Node before
        // resuming. If the Node hasn't changed since the previous
        // call this is an O(log N) check; otherwise we recover by
        // looking up the endpoint id we were last anchored at.
        // See the `endpoint_id` field doc-comment for semantics.
        let mut endpoint_index = self.resume_endpoint_index(node);

        while endpoint_index < node.endpoints.len() {
            let endpoint = &node.endpoints[endpoint_index];
            // Remember the id of the endpoint we're entering so the
            // next `next_for_path` call can re-anchor against it even
            // if the underlying `Node` has been swapped in between.
            self.endpoint_id = Some(endpoint.id);

            if (path.endpoint.is_none() || path.endpoint == Some(endpoint.id))
                && self.accessor.is_endpoint_accessible(endpoint.id)
            {
                while (self.cluster_index as usize) < endpoint.clusters.len() {
                    let cluster = &endpoint.clusters[self.cluster_index as usize];

                    if path.cluster.is_none() || path.cluster == Some(cluster.id) {
                        let cluster_leaves_len = if command {
                            cluster.commands().count()
                        } else {
                            cluster.attributes().count()
                        };

                        while (self.leaf_index as usize) < cluster_leaves_len {
                            let leaf_id = if command {
                                unwrap!(cluster
                                    .commands()
                                    .map(|cmd| cmd.id)
                                    .nth(self.leaf_index as usize))
                            } else {
                                unwrap!(cluster
                                    .attributes()
                                    .map(|attr| attr.id)
                                    .nth(self.leaf_index as usize))
                            };

                            if path.leaf.is_none() || path.leaf == Some(leaf_id as _) {
                                // Leaf found, filter and check its access rights

                                #[allow(clippy::if_same_then_else)]
                                let check = if (self.filter)(endpoint.id, cluster.id, leaf_id) {
                                    if self.last_authorized
                                        == Some((endpoint.id, cluster.id, leaf_id))
                                    {
                                        Ok(true)
                                    } else if command {
                                        cluster
                                            .check_cmd_access(
                                                self.accessor,
                                                self.timed,
                                                GenericPath::new(
                                                    Some(endpoint.id),
                                                    Some(cluster.id),
                                                    Some(leaf_id),
                                                ),
                                                endpoint.device_types,
                                                unwrap!(cluster
                                                    .commands()
                                                    .map(|cmd| cmd.id)
                                                    .nth(self.leaf_index as usize)),
                                            )
                                            .map(|_| true)
                                    } else {
                                        // TODO: Need to also check that the code is not trying to access an element of an array
                                        // when the attribute is not an array

                                        cluster
                                            .check_attr_access(
                                                self.accessor,
                                                self.timed,
                                                GenericPath::new(
                                                    Some(endpoint.id),
                                                    Some(cluster.id),
                                                    Some(leaf_id),
                                                ),
                                                endpoint.device_types,
                                                !attr_read,
                                                unwrap!(cluster
                                                    .attributes()
                                                    .map(|attr| attr.id)
                                                    .nth(self.leaf_index as usize)),
                                            )
                                            .map(|_| true)
                                    }
                                } else {
                                    Ok(false)
                                };

                                match check {
                                    Ok(true) => {
                                        // Because on the next call we should start from the next leaf or if leaves
                                        // are over, from the next cluster and so on. `endpoint_id` is
                                        // already set to `endpoint.id` at the top of the outer loop,
                                        // which is how the next call re-anchors to this endpoint even
                                        // if the underlying Node has been mutated in between.
                                        self.leaf_index += 1;

                                        // Cache this concrete triple as the
                                        // last-authorized one. The next
                                        // expansion that lands on the same
                                        // (endpoint, cluster, leaf) — typical
                                        // for chip-tool's list-write
                                        // `DeleteAll + Add×N` encoding — will
                                        // bypass the access re-check above.
                                        self.last_authorized =
                                            Some((endpoint.id, cluster.id, leaf_id));

                                        let array = !command
                                            && cluster
                                                .attribute(leaf_id)
                                                .map(|attr| attr.quality.contains(Quality::ARRAY))
                                                .unwrap_or(false);

                                        return Ok(Some((endpoint.id, cluster.id, leaf_id, array)));
                                    }
                                    Ok(false) => {
                                        // Filtered out. For a non-wildcard path the
                                        // leaf exists but the filter explicitly rejected
                                        // it - treat this as "no output" rather than
                                        // reporting `UnsupportedAttribute`/`UnsupportedCommand`.
                                        if !path.is_wildcard() {
                                            self.leaf_index += 1;
                                            return Ok(None);
                                        }
                                        // Else: just skip it and continue scanning
                                    }
                                    Err(status) => {
                                        if !path.is_wildcard() {
                                            // Only return if non-wildcard, else just skip the error and
                                            // continue scanning
                                            return Err(status);
                                        }
                                    }
                                }
                            }

                            self.leaf_index += 1;
                        }

                        if !path.is_wildcard() {
                            if command {
                                return Err(IMStatusCode::UnsupportedCommand);
                            } else {
                                return Err(IMStatusCode::UnsupportedAttribute);
                            }
                        }

                        self.leaf_index = 0;
                    }

                    self.cluster_index += 1;
                }

                if !path.is_wildcard() {
                    return Err(IMStatusCode::UnsupportedCluster);
                }

                self.cluster_index = 0;
            }

            endpoint_index += 1;
        }

        if !path.is_wildcard() {
            Err(IMStatusCode::UnsupportedEndpoint)
        } else {
            Ok(None)
        }
    }

    /// Compute the starting `endpoint_index` for the outer loop in
    /// `next_for_path` by re-anchoring against the *current* `node`
    /// using the `endpoint_id` we last entered. Called once at the
    /// top of every `next_for_path` so the scan resumes correctly
    /// even if the underlying `Node` has been swapped or mutated
    /// since the last `next` call.
    ///
    /// Relies on the [`Node`]-level invariants:
    /// - **`endpoints` sorted ascending by id, no duplicates** —
    ///   enables `binary_search_by_key` and means the insertion point
    ///   on a miss is strictly past everything we've already yielded.
    /// - **Per-endpoint shape is stable for the endpoint's lifetime**
    ///   — means `cluster_index` and `leaf_index` are still valid
    ///   positional cursors whenever the endpoint is found again.
    ///
    /// Returns `0` when `endpoint_id` is `None` (we haven't entered
    /// any endpoint yet for the current item; the cluster / leaf
    /// cursors are already at `0/0`).
    fn resume_endpoint_index(&mut self, node: &Node<'_>) -> usize {
        let Some(ep_id) = self.endpoint_id else {
            return 0;
        };

        debug_assert!(
            node.endpoints.windows(2).all(|w| w[0].id < w[1].id),
            "Node::endpoints must be sorted ascending by id and contain no duplicates",
        );

        match node.endpoints.binary_search_by_key(&ep_id, |e| e.id) {
            // Same endpoint, possibly at a different slot. The
            // per-endpoint shape invariant means `cluster_index` and
            // `leaf_index` still point at the array slot we were
            // going to read next, so leave them alone.
            Ok(i) => i,
            Err(i) => {
                // Endpoint is gone. The insertion point `i` is the
                // index of the first remaining endpoint whose id is
                // strictly greater than ours — i.e. one we have not
                // yielded yet (would have come after the lost
                // endpoint in the previous-Node iteration order).
                // Reset the cluster / leaf cursors and clear the
                // anchor so the outer loop reads the new endpoint
                // fresh.
                self.cluster_index = 0;
                self.leaf_index = 0;
                self.endpoint_id = None;
                i
            }
        }
    }
}

struct PathExpanderIterator<'a, M, T, I, F> {
    metadata: M,
    expander: PathExpander<'a, T, I, F>,
}

impl<'a, M, T, I, F> PathExpanderIterator<'a, M, T, I, F>
where
    M: Metadata,
    I: Iterator<Item = Result<T, Error>>,
    T: PathExpansionItem<'a>,
    F: FnMut(EndptId, ClusterId, u32) -> bool,
{
    /// Create a new path expander iterator with the given metadata, accessor and paths.
    pub const fn new(
        metadata: M,
        accessor: &'a Accessor<'a>,
        timed: bool,
        paths: Option<I>,
        filter: F,
    ) -> Self {
        Self {
            metadata,
            expander: PathExpander::new(accessor, timed, paths, filter),
        }
    }
}

impl<'a, M, T, I, F> Iterator for PathExpanderIterator<'a, M, T, I, F>
where
    M: Metadata,
    I: Iterator<Item = Result<T, Error>>,
    T: PathExpansionItem<'a>,
    F: FnMut(EndptId, ClusterId, u32) -> bool,
{
    type Item = Result<Result<T::Expanded<'a>, T::Status>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let metadata = &self.metadata;
        let expander = &mut self.expander;

        metadata.access(|node| expander.next(node))
    }
}

/// Helper function to get the data version for a given endpoint and cluster
/// from the provided collection of filters
fn dataver(
    dataver_filters: Option<&TLVArray<DataVersionFilter>>,
    ep: EndptId,
    cl: ClusterId,
) -> Result<Option<u32>, Error> {
    if let Some(dataver_filters) = dataver_filters {
        for filter in dataver_filters {
            let filter = filter?;

            if filter.path.endpoint == ep && filter.path.cluster == cl {
                return Ok(Some(filter.data_ver));
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod test {
    use crate::acl::{Accessor, AccessorSubjects, AuthMode};
    use crate::dm::{
        Access, Attribute, Cluster, ClusterId, Command, DeviceType, Endpoint, EndptId, Quality,
    };
    use crate::error::{Error, ErrorCode};
    use crate::im::GenericPath;
    use crate::im::IMStatusCode;
    use crate::test::test_matter;

    use super::{Node, Operation, PathExpanderIterator, PathExpansionItem};

    // For tests
    impl<'a> PathExpansionItem<'a> for GenericPath {
        const OPERATION: Operation = Operation::Read;

        type Expanded<'n> = GenericPath;
        type Status = IMStatusCode;

        fn path(&self) -> GenericPath {
            self.clone()
        }

        fn expand(
            &self,
            _accessor: &Accessor<'_>,
            endpoint_id: EndptId,
            cluster_id: ClusterId,
            leaf_id: u32,
            _array: bool,
        ) -> Result<Self::Expanded<'a>, Error> {
            Ok(GenericPath::new(
                Some(endpoint_id),
                Some(cluster_id),
                Some(leaf_id),
            ))
        }

        fn into_status(self, status: IMStatusCode) -> Self::Status {
            status
        }
    }

    /// Compare an input of paths against their expanded expectations.
    fn test(
        node: &Node,
        input: &[GenericPath],
        expected: &[Result<Result<GenericPath, IMStatusCode>, ErrorCode>],
    ) {
        test_with_filter(node, input, |_, _, _| true, expected)
    }

    /// Compare an input of paths against their expanded expectations,
    /// using the provided per-(endpoint, cluster, leaf) filter.
    fn test_with_filter(
        node: &Node,
        input: &[GenericPath],
        filter: impl FnMut(EndptId, ClusterId, u32) -> bool,
        expected: &[Result<Result<GenericPath, IMStatusCode>, ErrorCode>],
    ) {
        let matter = test_matter();
        let accessor = Accessor::new(0, AccessorSubjects::new(0), Some(AuthMode::Pase), &matter);

        let expander = PathExpanderIterator::new(
            node,
            &accessor,
            false,
            Some(input.iter().cloned().map(Ok)),
            filter,
        );

        assert_eq!(
            expander
                .map(|r| r.map_err(|e| e.code()))
                .collect::<alloc::vec::Vec<_>>()
                .as_slice(),
            expected
        );
    }

    #[test]
    fn test_none() {
        static NODE: Node = Node::new(&[]);

        // Invalid endpoint with wildcard paths should not return anything
        test(&NODE, &[GenericPath::new(Some(0), None, None)], &[]);

        // Invalid cluster with wildcard paths should not return anything
        test(&NODE, &[GenericPath::new(None, Some(0), None)], &[]);

        // Invalid leaf with wildcard paths should not return anything
        test(&NODE, &[GenericPath::new(None, None, Some(0))], &[]);

        // Invalid endpoint with non-wildcard paths should return an err status
        test(
            &NODE,
            &[GenericPath::new(Some(0), Some(0), Some(0))],
            &[Ok(Err(IMStatusCode::UnsupportedEndpoint))],
        );
    }

    #[test]
    fn test_one_all() {
        static NODE: Node = Node::new(&[Endpoint::new(
            0,
            &[DeviceType { dtype: 0, drev: 0 }],
            &[Cluster::new(
                0,
                1,
                0,
                &[Attribute::new(0, Access::all(), Quality::all())],
                &[Command::new(0, None, Access::all())],
                &[],
                |_, _, _| true,
                |_, _, _| true,
                |_, _, _| true,
            )],
        )]);

        // Happy path, wildcard
        test(
            &NODE,
            &[GenericPath::new(None, None, None)],
            &[Ok(Ok(GenericPath::new(Some(0), Some(0), Some(0))))],
        );

        // Happy path, non-wildcard
        test(
            &NODE,
            &[GenericPath::new(Some(0), Some(0), Some(0))],
            &[Ok(Ok(GenericPath::new(Some(0), Some(0), Some(0))))],
        );

        // Invalid cluster with non-wildcard paths should return an err status
        test(
            &NODE,
            &[GenericPath::new(Some(0), Some(1), Some(0))],
            &[Ok(Err(IMStatusCode::UnsupportedCluster))],
        );

        // Invalid leaf with non-wildcard paths should return an err status
        test(
            &NODE,
            &[GenericPath::new(Some(0), Some(0), Some(1))],
            &[Ok(Err(IMStatusCode::UnsupportedAttribute))],
        );

        // Multiple wildcard paths with an empty node should not return anything
        test(
            &Node::new(&[]),
            &[
                GenericPath::new(None, None, None),
                GenericPath::new(None, None, None),
            ],
            &[],
        );

        // Multiple wildcard paths with non-empty node should return twice the output
        test(
            &NODE,
            &[
                GenericPath::new(None, None, None),
                GenericPath::new(None, None, None),
            ],
            &[
                Ok(Ok(GenericPath::new(Some(0), Some(0), Some(0)))),
                Ok(Ok(GenericPath::new(Some(0), Some(0), Some(0)))),
            ],
        );

        // One wildcard and one non-wildcard should also return twice the output
        test(
            &NODE,
            &[
                GenericPath::new(None, None, None),
                GenericPath::new(Some(0), Some(0), Some(0)),
            ],
            &[
                Ok(Ok(GenericPath::new(Some(0), Some(0), Some(0)))),
                Ok(Ok(GenericPath::new(Some(0), Some(0), Some(0)))),
            ],
        );

        // One correct non-wildcard and one incorrect wildcard should return once the output
        test(
            &NODE,
            &[
                GenericPath::new(Some(0), Some(0), Some(0)),
                GenericPath::new(None, Some(1), None),
            ],
            &[Ok(Ok(GenericPath::new(Some(0), Some(0), Some(0))))],
        );

        // One incorrect non-wildcard and one correct wildcard should return once an error and once the output
        test(
            &NODE,
            &[
                GenericPath::new(Some(0), Some(1), Some(0)),
                GenericPath::new(None, Some(0), Some(0)),
            ],
            &[
                Ok(Err(IMStatusCode::UnsupportedCluster)),
                Ok(Ok(GenericPath::new(Some(0), Some(0), Some(0)))),
            ],
        );
    }

    #[test]
    fn test_multiple() {
        static NODE: Node = Node::new(&[
            Endpoint::new(
                0,
                &[DeviceType { dtype: 0, drev: 0 }],
                &[
                    Cluster::new(
                        1,
                        1,
                        0,
                        &[Attribute::new(1, Access::all(), Quality::all())],
                        &[Command::new(1, None, Access::all())],
                        &[],
                        |_, _, _| true,
                        |_, _, _| true,
                        |_, _, _| true,
                    ),
                    Cluster::new(
                        10,
                        1,
                        0,
                        &[Attribute::new(1, Access::all(), Quality::all())],
                        &[Command::new(1, None, Access::all())],
                        &[],
                        |_, _, _| true,
                        |_, _, _| true,
                        |_, _, _| true,
                    ),
                ],
            ),
            Endpoint::new(
                5,
                &[DeviceType { dtype: 0, drev: 0 }],
                &[
                    Cluster::new(
                        1,
                        1,
                        0,
                        &[Attribute::new(1, Access::all(), Quality::all())],
                        &[Command::new(1, None, Access::all())],
                        &[],
                        |_, _, _| true,
                        |_, _, _| true,
                        |_, _, _| true,
                    ),
                    Cluster::new(
                        20,
                        1,
                        0,
                        &[
                            Attribute::new(20, Access::all(), Quality::all()),
                            Attribute::new(30, Access::all(), Quality::all()),
                        ],
                        &[
                            Command::new(20, None, Access::all()),
                            Command::new(30, None, Access::all()),
                        ],
                        &[],
                        |_, _, _| true,
                        |_, _, _| true,
                        |_, _, _| true,
                    ),
                ],
            ),
        ]);

        // Test with a single, global wildcard
        test(
            &NODE,
            &[GenericPath::new(None, None, None)],
            &[
                Ok(Ok(GenericPath::new(Some(0), Some(1), Some(1)))),
                Ok(Ok(GenericPath::new(Some(0), Some(10), Some(1)))),
                Ok(Ok(GenericPath::new(Some(5), Some(1), Some(1)))),
                Ok(Ok(GenericPath::new(Some(5), Some(20), Some(20)))),
                Ok(Ok(GenericPath::new(Some(5), Some(20), Some(30)))),
            ],
        );

        // Test with two concrete correct non-wildcards,
        // one incorrect non-wildcard and one incorrect wildcard
        test(
            &NODE,
            &[
                GenericPath::new(Some(0), Some(1), Some(1)),
                GenericPath::new(Some(5), Some(20), Some(20)),
                GenericPath::new(Some(0), Some(1), Some(11)),
                GenericPath::new(None, Some(2), None),
            ],
            &[
                Ok(Ok(GenericPath::new(Some(0), Some(1), Some(1)))),
                Ok(Ok(GenericPath::new(Some(5), Some(20), Some(20)))),
                Ok(Err(IMStatusCode::UnsupportedAttribute)),
            ],
        );

        // Test with a global wildcard, two concrete correct non-wildcards,
        // one incorrect non-wildcard and one incorrect wildcard
        test(
            &NODE,
            &[
                GenericPath::new(None, None, None),
                GenericPath::new(Some(0), Some(1), Some(1)),
                GenericPath::new(Some(5), Some(20), Some(20)),
                GenericPath::new(Some(0), Some(1), Some(11)),
                GenericPath::new(None, Some(2), None),
            ],
            &[
                Ok(Ok(GenericPath::new(Some(0), Some(1), Some(1)))),
                Ok(Ok(GenericPath::new(Some(0), Some(10), Some(1)))),
                Ok(Ok(GenericPath::new(Some(5), Some(1), Some(1)))),
                Ok(Ok(GenericPath::new(Some(5), Some(20), Some(20)))),
                Ok(Ok(GenericPath::new(Some(5), Some(20), Some(30)))),
                Ok(Ok(GenericPath::new(Some(0), Some(1), Some(1)))),
                Ok(Ok(GenericPath::new(Some(5), Some(20), Some(20)))),
                Ok(Err(IMStatusCode::UnsupportedAttribute)),
            ],
        );
    }

    #[test]
    fn test_filter() {
        static NODE: Node = Node::new(&[
            Endpoint::new(
                0,
                &[DeviceType { dtype: 0, drev: 0 }],
                &[Cluster::new(
                    1,
                    1,
                    0,
                    &[
                        Attribute::new(1, Access::all(), Quality::all()),
                        Attribute::new(2, Access::all(), Quality::all()),
                    ],
                    &[Command::new(1, None, Access::all())],
                    &[],
                    |_, _, _| true,
                    |_, _, _| true,
                    |_, _, _| true,
                )],
            ),
            Endpoint::new(
                5,
                &[DeviceType { dtype: 0, drev: 0 }],
                &[Cluster::new(
                    1,
                    1,
                    0,
                    &[Attribute::new(1, Access::all(), Quality::all())],
                    &[Command::new(1, None, Access::all())],
                    &[],
                    |_, _, _| true,
                    |_, _, _| true,
                    |_, _, _| true,
                )],
            ),
        ]);

        // Non-wildcard path, leaf exists but is filtered out: the expander
        // must yield nothing for this input (neither an expansion nor an
        // `UnsupportedAttribute` status).
        test_with_filter(
            &NODE,
            &[GenericPath::new(Some(0), Some(1), Some(1))],
            |_, _, _| false,
            &[],
        );

        // Non-wildcard path, leaf does not exist: filter must not be consulted
        // and the expander must still produce `UnsupportedAttribute`.
        test_with_filter(
            &NODE,
            &[GenericPath::new(Some(0), Some(1), Some(99))],
            |_, _, _| true,
            &[Ok(Err(IMStatusCode::UnsupportedAttribute))],
        );

        // Wildcard path, filter rejects everything: empty output, no errors.
        test_with_filter(
            &NODE,
            &[GenericPath::new(None, None, None)],
            |_, _, _| false,
            &[],
        );

        // Wildcard path, filter rejects some leaves: the accepted ones are
        // yielded and the rejected ones are silently skipped.
        test_with_filter(
            &NODE,
            &[GenericPath::new(None, None, None)],
            |_, _, leaf| leaf == 1,
            &[
                Ok(Ok(GenericPath::new(Some(0), Some(1), Some(1)))),
                Ok(Ok(GenericPath::new(Some(5), Some(1), Some(1)))),
            ],
        );

        // Mixed: a non-wildcard filtered-out path followed by a wildcard
        // should only yield items from the wildcard.
        test_with_filter(
            &NODE,
            &[
                GenericPath::new(Some(0), Some(1), Some(1)),
                GenericPath::new(None, None, None),
            ],
            |_ep, _cl, leaf| leaf != 1,
            &[Ok(Ok(GenericPath::new(Some(0), Some(1), Some(2))))],
        );
    }

    // -----------------------------------------------------------------
    // Recovery from concurrent Node mutations between `next()` calls.
    //
    // The `Metadata` lock is now acquired afresh per `next()` call (see
    // `PathExpanderIterator`), so the application is free to swap in a
    // different `Node` between iterations. `PathExpander` is expected
    // to recover by ID — these tests pin down the behaviour:
    // - stable Node                                  → unchanged output
    // - endpoint added/removed between iterations    → graceful advance
    // - cluster added/removed                        → graceful advance
    // - attribute added/removed                      → graceful advance
    // - whole Node swapped                           → best-effort
    // -----------------------------------------------------------------

    use core::cell::Cell;

    use crate::dm::Metadata;

    /// A `Metadata` impl whose backing `Node` can be hot-swapped between
    /// `access` calls — the test simulator for concurrent application
    /// mutations.
    struct SwappableMetadata {
        current: Cell<&'static Node<'static>>,
    }

    impl SwappableMetadata {
        fn new(node: &'static Node<'static>) -> Self {
            Self {
                current: Cell::new(node),
            }
        }

        fn swap(&self, new_node: &'static Node<'static>) {
            self.current.set(new_node);
        }
    }

    impl Metadata for SwappableMetadata {
        fn access<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&Node<'_>) -> R,
        {
            f(self.current.get())
        }
    }

    /// Run the expander interactively, invoking `after_yield(i, &metadata)`
    /// after each `next()` result so the test can swap the Node in
    /// between iterations. Compares the cumulative output to `expected`.
    fn test_swap(
        initial: &'static Node<'static>,
        input: &[GenericPath],
        mut after_yield: impl FnMut(usize, &SwappableMetadata),
        expected: &[Result<Result<GenericPath, IMStatusCode>, ErrorCode>],
    ) {
        let matter = test_matter();
        let accessor = Accessor::new(0, AccessorSubjects::new(0), Some(AuthMode::Pase), &matter);

        let metadata = SwappableMetadata::new(initial);

        let mut expander = PathExpanderIterator::new(
            &metadata,
            &accessor,
            false,
            Some(input.iter().cloned().map(Ok::<_, Error>)),
            |_, _, _| true,
        );

        let mut actual: alloc::vec::Vec<_> = alloc::vec::Vec::new();
        let mut i = 0;
        while let Some(result) = expander.next() {
            actual.push(result.map_err(|e| e.code()));
            after_yield(i, &metadata);
            i += 1;
        }

        assert_eq!(actual.as_slice(), expected);
    }

    // ---- Fixtures used across the recovery tests ------------------------

    /// Sanity check: with no mutations the swap-aware test path matches
    /// the static-Node test path.
    #[test]
    fn recovery_stable_node() {
        static EP0_C1_A12: [Cluster; 1] = [make_cluster_const(1, &[1, 2])];
        static NODE: Node = Node::new(&[Endpoint::new(0, &[], &EP0_C1_A12)]);

        test_swap(
            &NODE,
            &[GenericPath::new(None, None, None)],
            |_, _| {}, // no swap
            &[
                Ok(Ok(GenericPath::new(Some(0), Some(1), Some(1)))),
                Ok(Ok(GenericPath::new(Some(0), Some(1), Some(2)))),
            ],
        );
    }

    /// New endpoint inserted *after* the yielded one. We must continue
    /// from where we left off and then also visit the newcomer.
    #[test]
    fn recovery_endpoint_inserted_after_yield() {
        static EP0_C1_A1: [Cluster; 1] = [make_cluster_const(1, &[1])];
        static EP7_C1_A1: [Cluster; 1] = [make_cluster_const(1, &[1])];

        static ONE_EP: [Endpoint; 1] = [Endpoint::new(0, &[], &EP0_C1_A1)];
        static TWO_EPS: [Endpoint; 2] = [
            Endpoint::new(0, &[], &EP0_C1_A1),
            Endpoint::new(7, &[], &EP7_C1_A1),
        ];

        static NODE_BEFORE: Node = Node::new(&ONE_EP);
        static NODE_AFTER: Node = Node::new(&TWO_EPS);

        test_swap(
            &NODE_BEFORE,
            &[GenericPath::new(None, None, None)],
            |i, m| {
                // After the first yield, swap in the larger Node.
                if i == 0 {
                    m.swap(&NODE_AFTER);
                }
            },
            &[
                Ok(Ok(GenericPath::new(Some(0), Some(1), Some(1)))),
                Ok(Ok(GenericPath::new(Some(7), Some(1), Some(1)))),
            ],
        );
    }

    /// Endpoint *removed* between two yields (the one we just yielded
    /// against): we must still visit the remaining endpoints exactly
    /// once each.
    #[test]
    fn recovery_endpoint_removed_after_yield() {
        static EP0_C1_A1: [Cluster; 1] = [make_cluster_const(1, &[1])];
        static EP5_C1_A1: [Cluster; 1] = [make_cluster_const(1, &[1])];
        static EP7_C1_A1: [Cluster; 1] = [make_cluster_const(1, &[1])];

        static THREE_EPS: [Endpoint; 3] = [
            Endpoint::new(0, &[], &EP0_C1_A1),
            Endpoint::new(5, &[], &EP5_C1_A1),
            Endpoint::new(7, &[], &EP7_C1_A1),
        ];
        // After yield #1 we remove endpoint 5 (which was at index 1).
        // Endpoint 7 shifts to index 1.
        static TWO_EPS: [Endpoint; 2] = [
            Endpoint::new(0, &[], &EP0_C1_A1),
            Endpoint::new(7, &[], &EP7_C1_A1),
        ];

        static NODE_BEFORE: Node = Node::new(&THREE_EPS);
        static NODE_AFTER: Node = Node::new(&TWO_EPS);

        test_swap(
            &NODE_BEFORE,
            &[GenericPath::new(None, None, None)],
            |i, m| {
                // After yielding ep=0, drop ep=5. `binary_search` for
                // ep_id=0 still finds it at slot 0; we exhaust it,
                // advance to slot 1 — now ep=7 in the new array — and
                // yield once from there. ep=5 is never re-visited.
                if i == 0 {
                    m.swap(&NODE_AFTER);
                }
            },
            &[
                Ok(Ok(GenericPath::new(Some(0), Some(1), Some(1)))),
                Ok(Ok(GenericPath::new(Some(7), Some(1), Some(1)))),
            ],
        );
    }

    /// Cluster removed from the endpoint we're currently iterating
    /// after we yielded against it. NB: this scenario *violates* the
    /// [`Node`] per-endpoint-shape-stability invariant — once an
    /// endpoint with a given id is exposed, its cluster slice must
    /// not change. The test stays in place as defence-in-depth:
    /// even under that contract violation the expander must not
    /// panic or duplicate yields, it just exits gracefully when the
    /// cluster array turns out shorter than the cursor.
    #[test]
    fn recovery_cluster_removed_after_yield() {
        static C1_A1: [Cluster; 1] = [make_cluster_const(1, &[1])];
        static C1_C10: [Cluster; 2] = [make_cluster_const(1, &[1]), make_cluster_const(10, &[1])];

        static EP_BEFORE: [Endpoint; 1] = [Endpoint::new(0, &[], &C1_C10)];
        // After yield #1 we drop cluster 10. Cluster 1 is still there.
        static EP_AFTER: [Endpoint; 1] = [Endpoint::new(0, &[], &C1_A1)];

        static NODE_BEFORE: Node = Node::new(&EP_BEFORE);
        static NODE_AFTER: Node = Node::new(&EP_AFTER);

        test_swap(
            &NODE_BEFORE,
            &[GenericPath::new(None, None, None)],
            |i, m| {
                if i == 0 {
                    // We just yielded (ep=0, cluster=1, attr=1).
                    // Now remove cluster 10. The expander should
                    // notice the cluster array shortened and exit
                    // gracefully.
                    m.swap(&NODE_AFTER);
                }
            },
            &[Ok(Ok(GenericPath::new(Some(0), Some(1), Some(1))))],
        );
    }

    /// Attribute appended to the cluster after the slot we just
    /// yielded against. As with `recovery_cluster_removed_after_yield`,
    /// this scenario *violates* the [`Node`] per-endpoint-shape-stability
    /// invariant; the test remains as defence-in-depth, documenting that
    /// the expander deterministically picks up an extended attribute
    /// list rather than panicking or skipping.
    #[test]
    fn recovery_attribute_appended() {
        static C1_A1: [Cluster; 1] = [make_cluster_const(1, &[1])];
        static C1_A1_A2: [Cluster; 1] = [make_cluster_const(1, &[1, 2])];

        static EP_BEFORE: [Endpoint; 1] = [Endpoint::new(0, &[], &C1_A1)];
        static EP_AFTER: [Endpoint; 1] = [Endpoint::new(0, &[], &C1_A1_A2)];

        static NODE_BEFORE: Node = Node::new(&EP_BEFORE);
        static NODE_AFTER: Node = Node::new(&EP_AFTER);

        test_swap(
            &NODE_BEFORE,
            &[GenericPath::new(None, None, None)],
            |i, m| {
                if i == 0 {
                    // Append attribute id=2 to cluster 1 after we
                    // yielded attribute id=1.
                    m.swap(&NODE_AFTER);
                }
            },
            &[
                Ok(Ok(GenericPath::new(Some(0), Some(1), Some(1)))),
                // The newly-appended attribute is picked up.
                Ok(Ok(GenericPath::new(Some(0), Some(1), Some(2)))),
            ],
        );
    }

    /// Whole Node replaced after the first yield — best-effort
    /// continuation. Documents the observable behaviour rather than
    /// asserting a specific "right" answer; the contract is that the
    /// expander does not panic and does not infinite-loop.
    #[test]
    fn recovery_whole_node_swapped() {
        static C1_A1: [Cluster; 1] = [make_cluster_const(1, &[1])];
        static EP0_ORIG: [Endpoint; 1] = [Endpoint::new(0, &[], &C1_A1)];
        static EP99_NEW: [Endpoint; 1] = [Endpoint::new(99, &[], &C1_A1)];

        static NODE_BEFORE: Node = Node::new(&EP0_ORIG);
        static NODE_AFTER: Node = Node::new(&EP99_NEW);

        test_swap(
            &NODE_BEFORE,
            &[GenericPath::new(None, None, None)],
            |i, m| {
                if i == 0 {
                    m.swap(&NODE_AFTER);
                }
            },
            // After yielding (0, 1, 1) we swap to a Node whose only
            // endpoint is id=99. `binary_search` for ep_id=0 in [99]
            // returns `Err(0)` — the insertion point is index 0, so
            // we resume there onto the new endpoint with the cluster /
            // leaf cursors reset to 0.
            &[
                Ok(Ok(GenericPath::new(Some(0), Some(1), Some(1)))),
                Ok(Ok(GenericPath::new(Some(99), Some(1), Some(1)))),
            ],
        );
    }

    /// Helper: `const fn` wrapper around `Cluster::new` for use inside
    /// `static` initializers. Equivalent to the `make_cluster` runtime
    /// helper but evaluable at compile time, which is what `static`
    /// arrays require.
    const fn make_cluster_const(id: ClusterId, attr_ids: &[u32]) -> Cluster<'static> {
        // Specialised for the attribute layouts we use in recovery
        // fixtures: [1], [1, 2], [1, 2, 3], [10], [20].
        static ATTRS_1: [Attribute; 1] = [Attribute::new(1, Access::all(), Quality::all())];
        static ATTRS_10: [Attribute; 1] = [Attribute::new(10, Access::all(), Quality::all())];
        static ATTRS_20: [Attribute; 1] = [Attribute::new(20, Access::all(), Quality::all())];
        static ATTRS_1_2: [Attribute; 2] = [
            Attribute::new(1, Access::all(), Quality::all()),
            Attribute::new(2, Access::all(), Quality::all()),
        ];
        static ATTRS_1_2_3: [Attribute; 3] = [
            Attribute::new(1, Access::all(), Quality::all()),
            Attribute::new(2, Access::all(), Quality::all()),
            Attribute::new(3, Access::all(), Quality::all()),
        ];

        let slice: &[Attribute] = if attr_ids.len() == 1 {
            match attr_ids[0] {
                1 => &ATTRS_1,
                10 => &ATTRS_10,
                20 => &ATTRS_20,
                _ => panic!("unsupported single-attr fixture"),
            }
        } else if attr_ids.len() == 2 {
            match (attr_ids[0], attr_ids[1]) {
                (1, 2) => &ATTRS_1_2,
                _ => panic!("unsupported two-attr fixture"),
            }
        } else if attr_ids.len() == 3 {
            match (attr_ids[0], attr_ids[1], attr_ids[2]) {
                (1, 2, 3) => &ATTRS_1_2_3,
                _ => panic!("unsupported three-attr fixture"),
            }
        } else {
            panic!("unsupported attr_ids len");
        };

        Cluster::new(
            id,
            1,
            0,
            slice,
            &[],
            &[],
            |_, _, _| true,
            |_, _, _| true,
            |_, _, _| true,
        )
    }
}
