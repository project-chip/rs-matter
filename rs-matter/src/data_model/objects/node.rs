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
    error::Error,
    interaction_model::{
        core::{IMStatusCode, ReportDataReq},
        messages::{
            ib::{AttrStatus, CmdStatus, DataVersionFilter},
            msg::{InvReqRef, WriteReqRef},
            GenericPath,
        },
    },
    tlv::{TLVArray, TLVElement},
};
use core::{
    fmt,
    iter::{once, Once},
};

use super::{AttrDetails, AttrId, Attribute, Cluster, ClusterId, CmdDetails, CmdId, EndptId};

pub enum WildcardIter<T, E> {
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
    pub fn read<'m>(
        &'m self,
        req: &'m ReportDataReq,
        from: Option<GenericPath>,
        accessor: &'m Accessor<'m>,
        with_dataver_filters: bool,
    ) -> Result<impl Iterator<Item = Result<Result<AttrDetails, AttrStatus>, Error>> + 'm, Error>
    {
        let dataver_filters = req.dataver_filters()?;
        let fabric_filtered = req.fabric_filtered()?;

        let iter = req
            .attr_requests()?
            .into_iter()
            .flat_map(|reqs| reqs.into_iter())
            .flat_map(move |path| {
                let path = match path {
                    Ok(path) => path,
                    Err(e) => return WildcardIter::Single(once(Err(e))),
                };

                if path.to_gp().is_wildcard() {
                    let from = from.clone();
                    let dataver_filters = dataver_filters.clone();

                    let iter = self
                        .match_attributes(path.endpoint, path.cluster, path.attr)
                        .skip_while(move |(ep, cl, attr)| {
                            !Self::matches(from.as_ref(), ep.id, cl.id, attr.id as _)
                        })
                        .filter(|(ep, cl, attr)| {
                            Cluster::check_attr_access(
                                accessor,
                                GenericPath::new(Some(ep.id), Some(cl.id), Some(attr.id as _)),
                                false,
                                attr.access,
                            )
                            .is_ok()
                        })
                        .map(move |(ep, cl, attr)| {
                            let dataver = with_dataver_filters
                                .then(|| Self::dataver(dataver_filters.as_ref(), ep.id, cl.id))
                                .transpose()?
                                .flatten();

                            Ok(Ok(AttrDetails {
                                node: self,
                                endpoint_id: ep.id,
                                cluster_id: cl.id,
                                attr_id: attr.id,
                                list_index: path.list_index,
                                fab_idx: accessor.fab_idx,
                                fab_filter: fabric_filtered,
                                dataver,
                                wildcard: true,
                            }))
                        });

                    WildcardIter::Wildcard(iter)
                } else {
                    let ep = path.endpoint.unwrap();
                    let cl = path.cluster.unwrap();
                    let attr = path.attr.unwrap();

                    let result = match self.check_attribute(accessor, ep, cl, attr, false) {
                        Ok(()) => Self::dataver(dataver_filters.as_ref(), ep, cl).map(|dataver| {
                            Ok(AttrDetails {
                                node: self,
                                endpoint_id: ep,
                                cluster_id: cl,
                                attr_id: attr,
                                list_index: path.list_index,
                                fab_idx: accessor.fab_idx,
                                fab_filter: fabric_filtered,
                                dataver,
                                wildcard: false,
                            })
                        }),
                        Err(err) => Ok(Err(AttrStatus::new(&path.to_gp(), err, 0))),
                    };

                    WildcardIter::Single(once(result))
                }
            });

        Ok(iter)
    }

    pub fn write<'m>(
        &'m self,
        req: &'m WriteReqRef,
        accessor: &'m Accessor<'m>,
    ) -> Result<
        impl Iterator<Item = Result<Result<(AttrDetails, TLVElement<'m>), AttrStatus>, Error>> + 'm,
        Error,
    > {
        let iter = req
            .write_requests()?
            .into_iter()
            .flat_map(move |attr_data| {
                let attr_data = match attr_data {
                    Ok(attr_data) => attr_data,
                    Err(e) => return WildcardIter::Single(once(Err(e))),
                };

                if attr_data.path.cluster.is_none() {
                    WildcardIter::Single(once(Ok(Err(AttrStatus::new(
                        &attr_data.path.to_gp(),
                        IMStatusCode::UnsupportedCluster,
                        0,
                    )))))
                } else if attr_data.path.attr.is_none() {
                    WildcardIter::Single(once(Ok(Err(AttrStatus::new(
                        &attr_data.path.to_gp(),
                        IMStatusCode::UnsupportedAttribute,
                        0,
                    )))))
                } else if attr_data.path.to_gp().is_wildcard() {
                    let iter = self
                        .match_attributes(
                            attr_data.path.endpoint,
                            attr_data.path.cluster,
                            attr_data.path.attr,
                        )
                        .filter(move |(ep, cl, attr)| {
                            Cluster::check_attr_access(
                                accessor,
                                GenericPath::new(Some(ep.id), Some(cl.id), Some(attr.id as _)),
                                true,
                                attr.access,
                            )
                            .is_ok()
                        })
                        .map(move |(ep, cl, attr)| {
                            Ok(Ok((
                                AttrDetails {
                                    node: self,
                                    endpoint_id: ep.id,
                                    cluster_id: cl.id,
                                    attr_id: attr.id,
                                    list_index: attr_data.path.list_index,
                                    fab_idx: accessor.fab_idx,
                                    fab_filter: false,
                                    dataver: attr_data.data_ver,
                                    wildcard: true,
                                },
                                attr_data.data.clone(),
                            )))
                        });

                    WildcardIter::Wildcard(iter)
                } else {
                    let ep = attr_data.path.endpoint.unwrap();
                    let cl = attr_data.path.cluster.unwrap();
                    let attr = attr_data.path.attr.unwrap();

                    let result = match self.check_attribute(accessor, ep, cl, attr, true) {
                        Ok(()) => Ok(Ok((
                            AttrDetails {
                                node: self,
                                endpoint_id: ep,
                                cluster_id: cl,
                                attr_id: attr,
                                list_index: attr_data.path.list_index,
                                fab_idx: accessor.fab_idx,
                                fab_filter: false,
                                dataver: attr_data.data_ver,
                                wildcard: false,
                            },
                            attr_data.data,
                        ))),
                        Err(err) => Ok(Err(AttrStatus::new(&attr_data.path.to_gp(), err, 0))),
                    };

                    WildcardIter::Single(once(result))
                }
            });

        Ok(iter)
    }

    pub fn invoke<'m>(
        &'m self,
        req: &'m InvReqRef,
        accessor: &'m Accessor<'m>,
    ) -> Result<
        impl Iterator<Item = Result<Result<(CmdDetails, TLVElement<'m>), CmdStatus>, Error>> + 'm,
        Error,
    > {
        let iter = req
            .inv_requests()?
            .into_iter()
            .flat_map(|reqs| reqs.into_iter())
            .flat_map(move |cmd_data| {
                let cmd_data = match cmd_data {
                    Ok(cmd_data) => cmd_data,
                    Err(e) => return WildcardIter::Single(once(Err(e))),
                };

                if cmd_data.path.path.is_wildcard() {
                    let iter = self
                        .match_commands(
                            cmd_data.path.path.endpoint,
                            cmd_data.path.path.cluster,
                            cmd_data.path.path.leaf.map(|leaf| leaf as _),
                        )
                        .filter(move |(ep, cl, cmd)| {
                            Cluster::check_cmd_access(
                                accessor,
                                GenericPath::new(Some(ep.id), Some(cl.id), Some(*cmd)),
                            )
                            .is_ok()
                        })
                        .map(move |(ep, cl, cmd)| {
                            Ok(Ok((
                                CmdDetails {
                                    node: self,
                                    endpoint_id: ep.id,
                                    cluster_id: cl.id,
                                    cmd_id: cmd,
                                    wildcard: true,
                                },
                                cmd_data.data.clone(),
                            )))
                        });

                    WildcardIter::Wildcard(iter)
                } else {
                    let ep = cmd_data.path.path.endpoint.unwrap();
                    let cl = cmd_data.path.path.cluster.unwrap();
                    let cmd = cmd_data.path.path.leaf.unwrap();

                    let result = match self.check_command(accessor, ep, cl, cmd) {
                        Ok(()) => Ok(Ok((
                            CmdDetails {
                                node: self,
                                endpoint_id: cmd_data.path.path.endpoint.unwrap(),
                                cluster_id: cmd_data.path.path.cluster.unwrap(),
                                cmd_id: cmd_data.path.path.leaf.unwrap(),
                                wildcard: false,
                            },
                            cmd_data.data,
                        ))),
                        Err(err) => Ok(Err(CmdStatus::new(cmd_data.path, err, 0))),
                    };

                    WildcardIter::Single(once(result))
                }
            });

        Ok(iter)
    }

    fn matches(path: Option<&GenericPath>, ep: EndptId, cl: ClusterId, leaf: u32) -> bool {
        if let Some(path) = path {
            path.endpoint.map(|id| id == ep).unwrap_or(true)
                && path.cluster.map(|id| id == cl).unwrap_or(true)
                && path.leaf.map(|id| id == leaf).unwrap_or(true)
        } else {
            true
        }
    }

    pub fn match_attributes(
        &self,
        ep: Option<EndptId>,
        cl: Option<ClusterId>,
        attr: Option<AttrId>,
    ) -> impl Iterator<Item = (&'_ Endpoint, &'_ Cluster, &'_ Attribute)> + '_ {
        self.match_endpoints(ep).flat_map(move |endpoint| {
            endpoint
                .match_attributes(cl, attr)
                .map(move |(cl, attr)| (endpoint, cl, attr))
        })
    }

    pub fn match_commands(
        &self,
        ep: Option<EndptId>,
        cl: Option<ClusterId>,
        cmd: Option<CmdId>,
    ) -> impl Iterator<Item = (&'_ Endpoint, &'_ Cluster, CmdId)> + '_ {
        self.match_endpoints(ep).flat_map(move |endpoint| {
            endpoint
                .match_commands(cl, cmd)
                .map(move |(cl, cmd)| (endpoint, cl, cmd))
        })
    }

    pub fn check_attribute(
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

    pub fn check_command(
        &self,
        accessor: &Accessor,
        ep: EndptId,
        cl: ClusterId,
        cmd: CmdId,
    ) -> Result<(), IMStatusCode> {
        self.check_endpoint(ep)
            .and_then(|endpoint| endpoint.check_command(accessor, cl, cmd))
    }

    pub fn match_endpoints(&self, ep: Option<EndptId>) -> impl Iterator<Item = &'_ Endpoint> + '_ {
        self.endpoints
            .iter()
            .filter(move |endpoint| ep.map(|id| id == endpoint.id).unwrap_or(true))
    }

    pub fn check_endpoint(&self, ep: EndptId) -> Result<&Endpoint, IMStatusCode> {
        self.endpoints
            .iter()
            .find(|endpoint| endpoint.id == ep)
            .ok_or(IMStatusCode::UnsupportedEndpoint)
    }

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
