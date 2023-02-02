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

use crate::{
    acl::Accessor,
    data_model::objects::Endpoint,
    interaction_model::{
        core::IMStatusCode,
        messages::{
            ib::{AttrStatus, CmdStatus},
            msg::{InvReq, ReadReq, WriteReq},
            GenericPath,
        },
    },
    // TODO: This layer shouldn't really depend on the TLV layer, should create an abstraction layer
    tlv::TLVElement,
};
use core::{
    fmt,
    iter::{once, Once},
};

use super::{AttrDetails, AttrId, ClusterId, CmdDetails, CmdId, EndptId};

enum WildcardIter<T, E> {
    None,
    Single(Once<E>),
    Wildcard(T),
}

impl<T, E> Iterator for WildcardIter<T, E>
where
    T: Iterator<Item = E>,
{
    type Item = E;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::None => None,
            Self::Single(iter) => iter.next(),
            Self::Wildcard(iter) => iter.next(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Node<'a> {
    pub id: u16,
    pub endpoints: &'a [Endpoint<'a>],
}

impl<'a> Node<'a> {
    pub fn read<'s, 'm>(
        &'s self,
        req: &'m ReadReq,
        accessor: &'m Accessor<'m>,
    ) -> impl Iterator<Item = Result<AttrDetails, AttrStatus>> + 'm
    where
        's: 'm,
    {
        if let Some(attr_requests) = req.attr_requests.as_ref() {
            WildcardIter::Wildcard(attr_requests.iter().flat_map(
                move |path| match self.expand_attr(accessor, path.to_gp(), false) {
                    Ok(iter) => {
                        let wildcard = matches!(iter, WildcardIter::Wildcard(_));

                        WildcardIter::Wildcard(iter.map(move |(ep, cl, attr)| {
                            let dataver_filter = req
                                .dataver_filters
                                .as_ref()
                                .iter()
                                .flat_map(|array| array.iter())
                                .find_map(|filter| {
                                    (filter.path.endpoint == ep && filter.path.cluster == cl)
                                        .then_some(filter.data_ver)
                                });

                            Ok(AttrDetails {
                                node: self,
                                endpoint_id: ep,
                                cluster_id: cl,
                                attr_id: attr,
                                list_index: path.list_index,
                                fab_idx: accessor.fab_idx,
                                fab_filter: req.fabric_filtered,
                                dataver: dataver_filter,
                                wildcard,
                            })
                        }))
                    }
                    Err(err) => {
                        WildcardIter::Single(once(Err(AttrStatus::new(&path.to_gp(), err, 0))))
                    }
                },
            ))
        } else {
            WildcardIter::None
        }
    }

    pub fn write<'m>(
        &'m self,
        req: &'m WriteReq,
        accessor: &'m Accessor<'m>,
    ) -> impl Iterator<Item = Result<(AttrDetails, TLVElement<'m>), AttrStatus>> + 'm {
        req.write_requests.iter().flat_map(move |attr_data| {
            if attr_data.path.cluster.is_none() {
                WildcardIter::Single(once(Err(AttrStatus::new(
                    &attr_data.path.to_gp(),
                    IMStatusCode::UnsupportedCluster,
                    0,
                ))))
            } else if attr_data.path.attr.is_none() {
                WildcardIter::Single(once(Err(AttrStatus::new(
                    &attr_data.path.to_gp(),
                    IMStatusCode::UnsupportedAttribute,
                    0,
                ))))
            } else {
                match self.expand_attr(accessor, attr_data.path.to_gp(), true) {
                    Ok(iter) => {
                        let wildcard = matches!(iter, WildcardIter::Wildcard(_));

                        WildcardIter::Wildcard(iter.map(move |(ep, cl, attr)| {
                            Ok((
                                AttrDetails {
                                    node: self,
                                    endpoint_id: ep,
                                    cluster_id: cl,
                                    attr_id: attr,
                                    list_index: attr_data.path.list_index,
                                    fab_idx: accessor.fab_idx,
                                    fab_filter: false,
                                    dataver: attr_data.data_ver,
                                    wildcard,
                                },
                                attr_data.data.unwrap_tlv().unwrap(),
                            ))
                        }))
                    }
                    Err(err) => WildcardIter::Single(once(Err(AttrStatus::new(
                        &attr_data.path.to_gp(),
                        err,
                        0,
                    )))),
                }
            }
        })
    }

    pub fn invoke<'m>(
        &'m self,
        req: &'m InvReq,
        accessor: &'m Accessor<'m>,
    ) -> impl Iterator<Item = Result<(CmdDetails, TLVElement<'m>), CmdStatus>> + 'm {
        if let Some(inv_requests) = req.inv_requests.as_ref() {
            WildcardIter::Wildcard(inv_requests.iter().flat_map(move |cmd_data| {
                match self.expand_cmd(accessor, cmd_data.path.path) {
                    Ok(iter) => {
                        let wildcard = matches!(iter, WildcardIter::Wildcard(_));

                        WildcardIter::Wildcard(iter.map(move |(ep, cl, cmd)| {
                            Ok((
                                CmdDetails {
                                    node: self,
                                    endpoint_id: ep,
                                    cluster_id: cl,
                                    cmd_id: cmd,
                                    wildcard,
                                },
                                cmd_data.data.unwrap_tlv().unwrap(),
                            ))
                        }))
                    }
                    Err(err) => {
                        WildcardIter::Single(once(Err(CmdStatus::new(cmd_data.path, err, 0))))
                    }
                }
            }))
        } else {
            WildcardIter::None
        }
    }

    fn expand_attr<'m>(
        &'m self,
        accessor: &'m Accessor<'m>,
        path: GenericPath,
        write: bool,
    ) -> Result<
        WildcardIter<
            impl Iterator<Item = (EndptId, ClusterId, AttrId)> + 'm,
            (EndptId, ClusterId, AttrId),
        >,
        IMStatusCode,
    > {
        if path.is_wildcard() {
            Ok(WildcardIter::Wildcard(self.match_attributes(
                accessor,
                path.endpoint,
                path.cluster,
                path.leaf.map(|leaf| leaf as u16),
                write,
            )))
        } else {
            self.check_attribute(
                accessor,
                path.endpoint.unwrap(),
                path.cluster.unwrap(),
                path.leaf.unwrap() as _,
                write,
            )?;

            Ok(WildcardIter::Single(once((
                path.endpoint.unwrap(),
                path.cluster.unwrap(),
                path.leaf.unwrap() as _,
            ))))
        }
    }

    fn expand_cmd<'m>(
        &'m self,
        accessor: &'m Accessor<'m>,
        path: GenericPath,
    ) -> Result<
        WildcardIter<
            impl Iterator<Item = (EndptId, ClusterId, CmdId)> + 'm,
            (EndptId, ClusterId, CmdId),
        >,
        IMStatusCode,
    > {
        if path.is_wildcard() {
            Ok(WildcardIter::Wildcard(self.match_commands(
                accessor,
                path.endpoint,
                path.cluster,
                path.leaf,
            )))
        } else {
            self.check_command(
                accessor,
                path.endpoint.unwrap(),
                path.cluster.unwrap(),
                path.leaf.unwrap(),
            )?;

            Ok(WildcardIter::Single(once((
                path.endpoint.unwrap(),
                path.cluster.unwrap(),
                path.leaf.unwrap(),
            ))))
        }
    }

    fn match_attributes<'m>(
        &'m self,
        accessor: &'m Accessor<'m>,
        ep: Option<EndptId>,
        cl: Option<ClusterId>,
        attr: Option<AttrId>,
        write: bool,
    ) -> impl Iterator<Item = (EndptId, ClusterId, AttrId)> + 'm {
        self.match_endpoints(ep).flat_map(move |endpoint| {
            endpoint
                .match_attributes(accessor, cl, attr, write)
                .map(move |(cl, attr)| (endpoint.id, cl, attr))
        })
    }

    fn match_commands<'m>(
        &'m self,
        accessor: &'m Accessor<'m>,
        ep: Option<EndptId>,
        cl: Option<ClusterId>,
        cmd: Option<CmdId>,
    ) -> impl Iterator<Item = (EndptId, ClusterId, CmdId)> + 'm {
        self.match_endpoints(ep).flat_map(move |endpoint| {
            endpoint
                .match_commands(accessor, cl, cmd)
                .map(move |(cl, cmd)| (endpoint.id, cl, cmd))
        })
    }

    fn check_attribute(
        &self,
        accessor: &Accessor,
        ep: EndptId,
        cl: ClusterId,
        attr: AttrId,
        write: bool,
    ) -> Result<(), IMStatusCode> {
        self.check_endpoint(ep)
            .and_then(|endpoint| endpoint.check_attribute(accessor, cl, attr, write))
    }

    fn check_command(
        &self,
        accessor: &Accessor,
        ep: EndptId,
        cl: ClusterId,
        cmd: CmdId,
    ) -> Result<(), IMStatusCode> {
        self.check_endpoint(ep)
            .and_then(|endpoint| endpoint.check_command(accessor, cl, cmd))
    }

    fn match_endpoints(&self, ep: Option<EndptId>) -> impl Iterator<Item = &Endpoint> + '_ {
        self.endpoints
            .iter()
            .filter(move |endpoint| ep.map(|id| id == endpoint.id).unwrap_or(true))
    }

    fn check_endpoint(&self, ep: EndptId) -> Result<&Endpoint, IMStatusCode> {
        self.endpoints
            .iter()
            .find(|endpoint| endpoint.id == ep)
            .ok_or(IMStatusCode::UnsupportedEndpoint)
    }
}

impl<'a> core::fmt::Display for Node<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "node:")?;
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            writeln!(f, "endpoint {}: {}", index, endpoint)?;
        }

        write!(f, "")
    }
}

pub struct DynamicNode<'a, const N: usize> {
    id: u16,
    endpoints: heapless::Vec<Endpoint<'a>, N>,
}

impl<'a, const N: usize> DynamicNode<'a, N> {
    pub const fn new(id: u16) -> Self {
        Self {
            id,
            endpoints: heapless::Vec::new(),
        }
    }

    pub fn node(&self) -> Node<'_> {
        Node {
            id: self.id,
            endpoints: &self.endpoints,
        }
    }

    pub fn add(&mut self, endpoint: Endpoint<'a>) -> Result<(), Endpoint<'a>> {
        if !self.endpoints.iter().any(|ep| ep.id == endpoint.id) {
            self.endpoints.push(endpoint)
        } else {
            Err(endpoint)
        }
    }

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

impl<'a, const N: usize> core::fmt::Display for DynamicNode<'a, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.node().fmt(f)
    }
}
