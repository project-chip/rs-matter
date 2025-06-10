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

//! This module contains the implementation of the Descriptor cluster and its handler.

use core::fmt::Debug;

use crate::data_model::objects::{
    ArrayAttributeRead, Cluster, Dataver, Endpoint, EndptId, ReadContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVBuilderParent, ToTLVArrayBuilder, ToTLVBuilder};
use crate::with;

pub use crate::data_model::clusters::descriptor::*;

/// A parts matcher suitable for regular Matter devices
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct StandardPartsMatcher;

impl PartsMatcher for StandardPartsMatcher {
    fn matches(&self, our_endpoint: EndptId, endpoint: EndptId) -> bool {
        our_endpoint == 0 && endpoint != our_endpoint
    }
}

/// A parts matcher suitable for the aggregator endpoints of bridged Matter devices
///
/// This matcher matches ALL endpoints that are not the root endpoint (0) and not the aggregator endpoint itself.
///
/// For more complex scenarios, where the node needs to contain multiple aggregators, or where the node
/// might contain non-bridged endpoints, user needs to supply its own `PartsMatcher` implementation.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct AggregatorPartsMatcher;

impl PartsMatcher for AggregatorPartsMatcher {
    fn matches(&self, our_endpoint: EndptId, endpoint: EndptId) -> bool {
        endpoint != our_endpoint && endpoint != 0
    }
}

/// A trait for describing which endpoints (parts) should be returned
/// from the POV of our endpoint
///
/// For standard Matter devices, all endpoints should be returned as parts.
/// However - for queries on aggregator endpoints (i.e. those present in Matter bridges) -
/// only endpoints different from the aggregator and from the root endpoint should be returned.
pub trait PartsMatcher: Debug {
    /// Return `true` if the endpoint should be returned as a part
    ///
    /// # Arguments
    /// - `our_endpoint`: The endpoint ID of the endpoint that is being queried
    /// - `endpoint`: The endpoint ID of the endpoint that is being checked
    fn matches(&self, our_endpoint: EndptId, endpoint: EndptId) -> bool;
}

impl<T> PartsMatcher for &T
where
    T: PartsMatcher,
{
    fn matches(&self, our_endpoint: EndptId, endpoint: EndptId) -> bool {
        (**self).matches(our_endpoint, endpoint)
    }
}

impl<T> PartsMatcher for &mut T
where
    T: PartsMatcher,
{
    fn matches(&self, our_endpoint: EndptId, endpoint: EndptId) -> bool {
        (**self).matches(our_endpoint, endpoint)
    }
}

/// The system implementation of a handler for the Descriptor Matter cluster.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DescHandler<'a> {
    dataver: Dataver,
    matcher: &'a dyn PartsMatcher,
}

impl DescHandler<'static> {
    /// Create a new instance of `DescHandler` with the given `Dataver`
    /// and a matcher suitable for regular Matter devices
    pub const fn new(dataver: Dataver) -> Self {
        Self::new_matching(dataver, &StandardPartsMatcher)
    }

    /// Create a new instance of `DescHandler` with the given `Dataver`
    /// and a matcher suitable for aggregator endpoints
    pub const fn new_aggregator(dataver: Dataver) -> Self {
        Self::new_matching(dataver, &AggregatorPartsMatcher)
    }
}

impl<'a> DescHandler<'a> {
    /// Create a new instance of `DescHandler` with the given `Dataver`
    /// and a custom matcher
    pub const fn new_matching(dataver: Dataver, matcher: &'a dyn PartsMatcher) -> DescHandler<'a> {
        Self { dataver, matcher }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    fn endpoint<'b>(ctx: &'b ReadContext<'_>) -> Result<&'b Endpoint<'b>, Error> {
        ctx.attr()
            .node
            .endpoint(ctx.attr().endpoint_id)
            .ok_or_else(|| ErrorCode::EndpointNotFound.into())
    }
}

impl ClusterHandler for DescHandler<'_> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_revision(1)
        .with_attrs(with!(required))
        .with_cmds(with!());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn device_type_list<P: TLVBuilderParent>(
        &self,
        ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<DeviceTypeStructArrayBuilder<P>, DeviceTypeStructBuilder<P>>,
    ) -> Result<P, Error> {
        let endpoint = Self::endpoint(ctx)?;

        match builder {
            ArrayAttributeRead::ReadAll(mut builder) => {
                for dev_type in endpoint.device_types {
                    builder = builder
                        .push()?
                        .device_type(dev_type.dtype as _)?
                        .revision(dev_type.drev)?
                        .end()?;
                }

                builder.end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let Some(dev_type) = endpoint.device_types.get(index as usize) else {
                    return Err(ErrorCode::InvalidAction.into()); // TODO
                };

                builder
                    .device_type(dev_type.dtype as _)?
                    .revision(dev_type.drev)?
                    .end()
            }
        }
    }

    fn server_list<P: TLVBuilderParent>(
        &self,
        ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<ToTLVArrayBuilder<P, u32>, ToTLVBuilder<P, u32>>,
    ) -> Result<P, Error> {
        let endpoint = Self::endpoint(ctx)?;

        match builder {
            ArrayAttributeRead::ReadAll(mut builder) => {
                for cluster in endpoint.clusters {
                    builder = builder.push(&cluster.id)?;
                }

                builder.end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let Some(cluster) = endpoint.clusters.get(index as usize) else {
                    return Err(ErrorCode::InvalidAction.into()); // TODO
                };

                builder.set(&cluster.id)
            }
        }
    }

    fn client_list<P: TLVBuilderParent>(
        &self,
        ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<ToTLVArrayBuilder<P, u32>, ToTLVBuilder<P, u32>>,
    ) -> Result<P, Error> {
        let _endpoint = Self::endpoint(ctx)?;

        // Client clusters not support yet
        match builder {
            ArrayAttributeRead::ReadAll(builder) => builder.end(),
            ArrayAttributeRead::ReadOne(_, _) => Err(ErrorCode::InvalidAction.into()), // TODO
        }
    }

    fn parts_list<P: TLVBuilderParent>(
        &self,
        ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<ToTLVArrayBuilder<P, u16>, ToTLVBuilder<P, u16>>,
    ) -> Result<P, Error> {
        let mut ep_ids = ctx
            .attr()
            .node
            .endpoints
            .iter()
            .map(|e| e.id)
            .filter(|e| self.matcher.matches(ctx.attr().endpoint_id, *e));

        match builder {
            ArrayAttributeRead::ReadAll(mut builder) => {
                for id in ep_ids {
                    builder = builder.push(&id)?;
                }

                builder.end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let Some(ep_id) = ep_ids.nth(index as usize) else {
                    return Err(ErrorCode::InvalidAction.into()); // TODO
                };

                builder.set(&ep_id)
            }
        }
    }
}
