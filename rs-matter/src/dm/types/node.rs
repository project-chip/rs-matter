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

use crate::acl::Accessor;
use crate::dm::Endpoint;
use crate::error::Error;
use crate::im::{
    AttrData, AttrPath, AttrStatus, CmdData, CmdStatus, DataVersionFilter, GenericPath,
    IMStatusCode, InvReqRef, ReportDataReq, WriteReqRef,
};
use crate::tlv::{TLVArray, TLVElement};

use super::{AttrDetails, ClusterId, CmdDetails, EndptId};

/// The main Matter metadata type describing a Matter Node.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Node<'a> {
    /// The ID of the node.
    pub id: u16,
    /// The endpoints of the node.
    pub endpoints: &'a [Endpoint<'a>],
}

impl<'a> Node<'a> {
    /// Create a new node with the given ID and endpoints.
    pub const fn new(id: u16, endpoints: &'a [Endpoint<'a>]) -> Self {
        Self { id, endpoints }
    }

    /// Return a reference to the endpoint with the given ID, if it exists.
    pub fn endpoint(&self, id: EndptId) -> Option<&Endpoint<'a>> {
        self.endpoints.iter().find(|endpoint| endpoint.id == id)
    }

    /// Expand (potentially wildcard) read requests into concrete attribute details
    /// using the node metadata.
    ///
    /// As part of the expansion, the method will check whether the attributes are
    /// accessible by the accessor and whether they should be served based on the
    /// fabric filtering and dataver filtering rules and filter out the inaccessible ones (wildcard reads)
    /// or report an error status for the non-wildcard ones.
    pub fn read<'m>(
        &'m self,
        req: &'m ReportDataReq,
        accessor: &'m Accessor<'m>,
    ) -> Result<impl Iterator<Item = Result<Result<AttrDetails<'m>, AttrStatus>, Error>> + 'm, Error>
    {
        let dataver_filters = req.dataver_filters()?;
        let fabric_filtered = req.fabric_filtered()?;

        Ok(PathExpander::new(
            self,
            accessor,
            req.attr_requests()?.map(|reqs| {
                reqs.into_iter().map(move |path_result| {
                    path_result.map(|path| AttrReadPath {
                        path,
                        dataver_filters: dataver_filters.clone(),
                        fabric_filtered,
                    })
                })
            }),
        ))
    }

    /// Expand (potentially wildcard) write requests into concrete attribute details
    /// using the node metadata.
    ///
    /// As part of the expansion, the method will check whether the attributes are
    /// accessible by the accessor and filter out the inaccessible ones (wildcard writes)
    /// or report an error status for the non-wildcard ones.
    #[allow(clippy::type_complexity)]
    pub fn write<'m>(
        &'m self,
        req: &'m WriteReqRef,
        accessor: &'m Accessor<'m>,
    ) -> Result<
        impl Iterator<Item = Result<Result<(AttrDetails<'m>, TLVElement<'m>), AttrStatus>, Error>> + 'm,
        Error,
    > {
        Ok(PathExpander::new(
            self,
            accessor,
            Some(req.write_requests()?.into_iter()),
        ))
    }

    /// Expand (potentially wildcard) invoke requests into concrete command details
    /// using the node metadata.
    ///
    /// As part of the expansion, the method will check whether the commands are
    /// accessible by the accessor and filter out the inaccessible ones (wildcard invocations)
    /// or report an error status for the non-wildcard ones.
    #[allow(clippy::type_complexity)]
    pub fn invoke<'m>(
        &'m self,
        req: &'m InvReqRef,
        accessor: &'m Accessor<'m>,
    ) -> Result<
        impl Iterator<Item = Result<Result<(CmdDetails<'m>, TLVElement<'m>), CmdStatus>, Error>> + 'm,
        Error,
    > {
        Ok(PathExpander::new(
            self,
            accessor,
            req.inv_requests()?.map(move |reqs| reqs.into_iter()),
        ))
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
    id: u16,
    endpoints: heapless::Vec<Endpoint<'a>, N>,
}

impl<'a, const N: usize> DynamicNode<'a, N> {
    /// Create a new dynamic node with the given ID.
    pub const fn new(id: u16) -> Self {
        Self {
            id,
            endpoints: heapless::Vec::new(),
        }
    }

    /// Return a static node view of the dynamic node.
    ///
    /// Necessary, because the `Metadata` trait needs a `Node` type
    pub fn node(&self) -> Node<'_> {
        Node {
            id: self.id,
            endpoints: &self.endpoints,
        }
    }

    /// Add an endpoint to the dynamic node.
    pub fn add(&mut self, endpoint: Endpoint<'a>) -> Result<(), Endpoint<'a>> {
        if !self.endpoints.iter().any(|ep| ep.id == endpoint.id) {
            self.endpoints.push(endpoint)
        } else {
            Err(endpoint)
        }
    }

    /// Remove an endpoint from the dynamic node.
    pub fn remove(&mut self, endpoint_id: u16) -> Option<Endpoint<'a>> {
        let index = self
            .endpoints
            .iter()
            .enumerate()
            .find_map(|(index, ep)| (ep.id == endpoint_id).then_some(index));

        if let Some(index) = index {
            Some(self.endpoints.swap_remove(index))
        } else {
            None
        }
    }
}

impl<const N: usize> core::fmt::Display for DynamicNode<'_, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.node().fmt(f)
    }
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
        node: &'a Node<'a>,
        accessor: &'a Accessor<'a>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        leaf_id: u32,
    ) -> Result<Self::Expanded<'a>, Error>;

    /// Convert the item into an error status if the expansion failed.
    fn into_status(self, status: IMStatusCode) -> Self::Status;
}

/// `PathExpansionItem` implementation for `AttrReadPath` (attr read requests expansion).
impl<'a> PathExpansionItem<'a> for AttrReadPath<'a> {
    const OPERATION: Operation = Operation::Read;

    type Expanded<'n> = AttrDetails<'n>;
    type Status = AttrStatus;

    fn path(&self) -> GenericPath {
        self.path.to_gp()
    }

    fn expand(
        &self,
        node: &'a Node<'a>,
        accessor: &'a Accessor<'a>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        leaf_id: u32,
    ) -> Result<Self::Expanded<'a>, Error> {
        Ok(AttrDetails {
            node,
            endpoint_id,
            cluster_id,
            attr_id: leaf_id as _,
            wildcard: self.path.to_gp().is_wildcard(),
            list_index: self.path.list_index.clone(),
            fab_idx: accessor.fab_idx,
            fab_filter: self.fabric_filtered,
            dataver: dataver(self.dataver_filters.as_ref(), endpoint_id, cluster_id)?,
        })
    }

    fn into_status(self, status: IMStatusCode) -> Self::Status {
        AttrStatus::new(&self.path.to_gp(), status, 0)
    }
}

/// `PathExpansionItem` implementation for `AttrData` (attr write requests expansion).
impl<'a> PathExpansionItem<'a> for AttrData<'a> {
    const OPERATION: Operation = Operation::Write;

    type Expanded<'n> = (AttrDetails<'n>, TLVElement<'n>);
    type Status = AttrStatus;

    fn path(&self) -> GenericPath {
        self.path.to_gp()
    }

    fn expand(
        &self,
        node: &'a Node<'a>,
        accessor: &'a Accessor<'a>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        leaf_id: u32,
    ) -> Result<Self::Expanded<'a>, Error> {
        let expanded = (
            AttrDetails {
                node,
                endpoint_id,
                cluster_id,
                attr_id: leaf_id as _,
                wildcard: self.path.to_gp().is_wildcard(),
                list_index: self.path.list_index.clone(),
                fab_idx: accessor.fab_idx,
                fab_filter: false,
                dataver: self.data_ver,
            },
            self.data.clone(),
        );

        Ok(expanded)
    }

    fn into_status(self, status: IMStatusCode) -> Self::Status {
        AttrStatus::new(&self.path.to_gp(), status, 0)
    }
}

/// `PathExpansionItem` implementation for `CmdData` (command requests expansion).
impl<'a> PathExpansionItem<'a> for CmdData<'a> {
    const OPERATION: Operation = Operation::Invoke;

    type Expanded<'n> = (CmdDetails<'n>, TLVElement<'n>);
    type Status = CmdStatus;

    fn path(&self) -> GenericPath {
        self.path.path.clone()
    }

    fn expand(
        &self,
        node: &'a Node<'a>,
        _accessor: &'a Accessor<'a>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        leaf_id: u32,
    ) -> Result<Self::Expanded<'a>, Error> {
        let expanded = (
            CmdDetails {
                node,
                endpoint_id,
                cluster_id,
                cmd_id: leaf_id,
                wildcard: false,
            },
            self.data.clone(),
        );

        Ok(expanded)
    }

    fn into_status(self, status: IMStatusCode) -> Self::Status {
        CmdStatus::new(self.path, status, 0)
    }
}

/// An iterator that expands a list of paths into concrete attribute/command details.
///
/// While the iterator can be (and used to be) implemented by using monadic combinators,
/// this implementation is done in a more imperative way to avoid the overhead of monadic
/// combinators in terms of memory size.
struct PathExpander<'a, T, I>
where
    I: Iterator<Item = Result<T, Error>>,
{
    /// The metatdata node to expand the paths on.
    node: &'a Node<'a>,
    /// The accessor to check the access rights.
    accessor: &'a Accessor<'a>,
    /// The paths to expand.
    items: Option<I>,
    /// The current path item being expanded.
    item: Option<T>,
    /// The current endpoint index if the path is a wildcard one.
    endpoint_index: u32,
    /// The current cluster index.
    cluster_index: u16,
    /// The current leaf index.
    leaf_index: u16,
}

impl<'a, T, I> PathExpander<'a, T, I>
where
    I: Iterator<Item = Result<T, Error>>,
    T: PathExpansionItem<'a>,
{
    /// Create a new path expander with the given node, accessor, and paths.
    pub const fn new(node: &'a Node<'a>, accessor: &'a Accessor<'a>, paths: Option<I>) -> Self {
        Self {
            node,
            accessor,
            items: paths,
            item: None,
            endpoint_index: 0,
            cluster_index: 0,
            leaf_index: 0,
        }
    }

    /// Move to the next (endpoint, cluster, leaf) triple that matches the path
    /// of the current item.
    ///
    /// Returns an error status if no match is found, where the error status indicates
    /// whether the endpoint, the cluster, or the leaf is not matching.
    ///
    /// This method should only be called when `self.item` is `Some` or else it will panic.
    fn next_for_path(&mut self) -> Result<Option<(EndptId, ClusterId, u32)>, IMStatusCode> {
        let path = unwrap!(self.item.as_ref().map(PathExpansionItem::path));

        let command = matches!(T::OPERATION, Operation::Invoke);

        // Do some basic checks on wildcards, as not all wildcards are supported for each type of operation
        if !matches!(T::OPERATION, Operation::Read) {
            if path.cluster.is_none() {
                return Err(IMStatusCode::UnsupportedCluster);
            }

            if path.leaf.is_none() {
                return Err(IMStatusCode::UnsupportedAttribute);
            }
        }

        while (self.endpoint_index as usize) < self.node.endpoints.len() {
            let endpoint = &self.node.endpoints[self.endpoint_index as usize];

            if path.endpoint.is_none() || path.endpoint == Some(endpoint.id) {
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
                                // Leaf found, check its access rights

                                let check = if matches!(T::OPERATION, Operation::Invoke) {
                                    cluster.check_cmd_access(
                                        self.accessor,
                                        GenericPath::new(
                                            Some(endpoint.id),
                                            Some(cluster.id),
                                            Some(leaf_id),
                                        ),
                                        unwrap!(cluster
                                            .commands()
                                            .map(|cmd| cmd.id)
                                            .nth(self.leaf_index as usize)),
                                    )
                                } else {
                                    cluster.check_attr_access(
                                        self.accessor,
                                        GenericPath::new(
                                            Some(endpoint.id),
                                            Some(cluster.id),
                                            Some(leaf_id),
                                        ),
                                        matches!(T::OPERATION, Operation::Write),
                                        unwrap!(cluster
                                            .attributes()
                                            .map(|attr| attr.id)
                                            .nth(self.leaf_index as usize)),
                                    )
                                };

                                match check {
                                    Ok(()) => {
                                        // Because on the next call we should start from the next leaf or if leaves
                                        // are over, from the next cluster and so on
                                        self.leaf_index += 1;

                                        return Ok(Some((endpoint.id, cluster.id, leaf_id)));
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

            self.endpoint_index += 1;
        }

        if !path.is_wildcard() {
            Err(IMStatusCode::UnsupportedEndpoint)
        } else {
            Ok(None)
        }
    }
}

impl<'a, T, I> Iterator for PathExpander<'a, T, I>
where
    I: Iterator<Item = Result<T, Error>>,
    T: PathExpansionItem<'a>,
{
    type Item = Result<Result<T::Expanded<'a>, T::Status>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Fetch an item to expand if not already there
            if self.item.is_none() {
                let item = self.items.as_mut().and_then(|items| items.next())?;

                match item {
                    Err(err) => break Some(Err(err)),
                    Ok(item) => self.item = Some(item),
                }

                self.endpoint_index = 0;
                self.cluster_index = 0;
                self.leaf_index = 0;
            }

            // From here on, we do have a valid `self.item` to expand

            // Step on the first/next expanded path of the item
            match self.next_for_path() {
                Ok(Some((endpoint_id, cluster_id, leaf_id))) => {
                    // Next expansion of the path

                    let expanded = unwrap!(self.item.as_ref()).expand(
                        self.node,
                        self.accessor,
                        endpoint_id,
                        cluster_id,
                        leaf_id,
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
    use crate::fabric::FabricMgr;
    use crate::im::GenericPath;
    use crate::im::IMStatusCode;
    use crate::utils::cell::RefCell;

    use super::{Node, Operation, PathExpander, PathExpansionItem};

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
            _node: &'a Node<'a>,
            _accessor: &'a Accessor<'a>,
            endpoint_id: EndptId,
            cluster_id: ClusterId,
            leaf_id: u32,
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
        let fab_mgr = RefCell::new(FabricMgr::new());
        let accessor = Accessor::new(0, AccessorSubjects::new(0), Some(AuthMode::Pase), &fab_mgr);

        let expander = PathExpander::new(node, &accessor, Some(input.iter().cloned().map(Ok)));

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
        static NODE: Node = Node::new(0, &[]);

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
        static NODE: Node = Node::new(
            0,
            &[Endpoint::new(
                0,
                &[DeviceType { dtype: 0, drev: 0 }],
                &[Cluster::new(
                    0,
                    1,
                    0,
                    &[Attribute::new(0, Access::all(), Quality::all())],
                    &[Command::new(0, None, Access::all())],
                    |_, _, _| true,
                    |_, _, _| true,
                )],
            )],
        );

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
            &Node::new(0, &[]),
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
        static NODE: Node = Node::new(
            0,
            &[
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
                            |_, _, _| true,
                            |_, _, _| true,
                        ),
                        Cluster::new(
                            10,
                            1,
                            0,
                            &[Attribute::new(1, Access::all(), Quality::all())],
                            &[Command::new(1, None, Access::all())],
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
                            |_, _, _| true,
                            |_, _, _| true,
                        ),
                    ],
                ),
            ],
        );

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
}
