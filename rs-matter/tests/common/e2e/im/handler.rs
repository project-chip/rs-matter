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

use rs_matter::data_model::basic_info::{BasicInfoHandler, ClusterHandler as _};
use rs_matter::data_model::device_types::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE};
use rs_matter::data_model::objects::{
    AsyncHandler, AsyncMetadata, AttrDataEncoder, CmdDataEncoder, Dataver, Endpoint, Handler,
    InvokeContext, Metadata, Node, NonBlockingHandler, ReadContext, WriteContext,
};
use rs_matter::data_model::on_off::{self, ClusterHandler as _, OnOffHandler};
use rs_matter::data_model::root_endpoint::{self, EthRootEndpointHandler};
use rs_matter::data_model::sdm::admin_commissioning;
use rs_matter::data_model::sdm::gen_comm::{ClusterHandler as _, GenCommHandler};
use rs_matter::data_model::sdm::noc;
use rs_matter::data_model::sdm::nw_commissioning;
use rs_matter::data_model::system_model::access_control;
use rs_matter::data_model::system_model::descriptor::{self, DescriptorCluster};
use rs_matter::error::Error;
use rs_matter::handler_chain_type;
use rs_matter::Matter;

use crate::common::e2e::E2eRunner;

use super::echo_cluster::{self, EchoCluster};

/// A sample handler for E2E IM tests.
pub struct E2eTestHandler<'a>(
    handler_chain_type!(on_off::HandlerAdaptor<OnOffHandler>, EchoCluster, DescriptorCluster<'static>, EchoCluster | EthRootEndpointHandler<'a>),
);

impl<'a> E2eTestHandler<'a> {
    pub const NODE: Node<'static> = Node {
        id: 0,
        endpoints: &[
            Endpoint {
                id: 0,
                clusters: &[
                    descriptor::CLUSTER,
                    BasicInfoHandler::CLUSTER,
                    GenCommHandler::CLUSTER,
                    nw_commissioning::ETH_CLUSTER,
                    admin_commissioning::CLUSTER,
                    noc::CLUSTER,
                    access_control::CLUSTER,
                    echo_cluster::CLUSTER,
                ],
                device_types: &[DEV_TYPE_ROOT_NODE],
            },
            Endpoint {
                id: 1,
                clusters: &[
                    descriptor::CLUSTER,
                    OnOffHandler::CLUSTER,
                    echo_cluster::CLUSTER,
                ],
                device_types: &[DEV_TYPE_ON_OFF_LIGHT],
            },
        ],
    };

    pub fn new(matter: &'a Matter<'a>) -> Self {
        let handler = root_endpoint::eth_handler(0, matter.rand())
            .chain(
                0,
                echo_cluster::ID,
                EchoCluster::new(2, Dataver::new_rand(matter.rand())),
            )
            .chain(
                1,
                descriptor::ID,
                DescriptorCluster::new(Dataver::new_rand(matter.rand())),
            )
            .chain(
                1,
                echo_cluster::ID,
                EchoCluster::new(3, Dataver::new_rand(matter.rand())),
            )
            .chain(
                1,
                OnOffHandler::CLUSTER.id,
                OnOffHandler::new(Dataver::new_rand(matter.rand())).adapt(),
            );

        Self(handler)
    }

    pub fn echo_cluster(&self, endpoint: u16) -> &EchoCluster {
        match endpoint {
            0 => &self.0.next.next.next.handler,
            1 => &self.0.next.handler,
            _ => panic!(),
        }
    }
}

impl Handler for E2eTestHandler<'_> {
    fn read(
        &self,
        ctx: &ReadContext<'_>,
        encoder: AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        self.0.read(ctx, encoder)
    }

    fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
        self.0.write(ctx)
    }

    fn invoke(
        &self,
        ctx: &InvokeContext<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        self.0.invoke(ctx, encoder)
    }
}

impl NonBlockingHandler for E2eTestHandler<'_> {}

impl AsyncHandler for E2eTestHandler<'_> {
    fn read_awaits(&self, _ctx: &ReadContext<'_>) -> bool {
        false
    }

    fn write_awaits(&self, _ctx: &WriteContext<'_>) -> bool {
        false
    }

    fn invoke_awaits(&self, _ctx: &InvokeContext<'_>) -> bool {
        false
    }

    async fn read(
        &self,
        ctx: &ReadContext<'_>,
        encoder: AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        self.0.read(ctx, encoder)
    }

    async fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
        self.0.write(ctx)
    }

    async fn invoke(
        &self,
        ctx: &InvokeContext<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        self.0.invoke(ctx, encoder)
    }
}

impl Metadata for E2eTestHandler<'_> {
    type MetadataGuard<'g>
        = Node<'g>
    where
        Self: 'g;

    fn lock(&self) -> Self::MetadataGuard<'_> {
        Self::NODE
    }
}

impl AsyncMetadata for E2eTestHandler<'_> {
    type MetadataGuard<'g>
        = Node<'g>
    where
        Self: 'g;

    async fn lock(&self) -> Self::MetadataGuard<'_> {
        Self::NODE
    }
}

impl E2eRunner {
    // For backwards compatibility
    pub fn handler(&self) -> E2eTestHandler<'_> {
        E2eTestHandler::new(&self.matter)
    }
}
