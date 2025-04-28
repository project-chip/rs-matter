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

use rs_matter::data_model::basic_info;
use rs_matter::data_model::device_types::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE};
use rs_matter::data_model::objects::{
    AsyncHandler, AsyncMetadata, AttrDataEncoder, AttrDetails, CmdDataEncoder, CmdDetails, Dataver,
    Endpoint, Handler, Metadata, Node, NonBlockingHandler,
};
use rs_matter::data_model::on_off::{self, OnOffHandler};
use rs_matter::data_model::root_endpoint::{self, EthRootEndpointHandler};
use rs_matter::data_model::sdm::admin_commissioning;
use rs_matter::data_model::sdm::gen_comm;
use rs_matter::data_model::sdm::noc;
use rs_matter::data_model::sdm::nw_commissioning;
use rs_matter::data_model::system_model::access_control;
use rs_matter::data_model::system_model::descriptor::{self, DescriptorCluster};
use rs_matter::error::Error;
use rs_matter::handler_chain_type;
use rs_matter::tlv::TLVElement;
use rs_matter::transport::exchange::Exchange;
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
                    basic_info::CLUSTER,
                    gen_comm::CLUSTER,
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
                clusters: &[descriptor::CLUSTER, on_off::CLUSTER, echo_cluster::CLUSTER],
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
                on_off::ID,
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
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        self.0.read(exchange, attr, encoder)
    }

    fn write(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        data: rs_matter::data_model::objects::AttrData,
    ) -> Result<(), Error> {
        self.0.write(exchange, attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        self.0.invoke(exchange, cmd, data, encoder)
    }
}

impl NonBlockingHandler for E2eTestHandler<'_> {}

impl AsyncHandler for E2eTestHandler<'_> {
    async fn read(
        &self,
        exchange: &Exchange<'_>,
        attr: &AttrDetails<'_>,
        encoder: AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        self.0.read(exchange, attr, encoder)
    }

    fn read_awaits(&self, _exchange: &Exchange, _attr: &AttrDetails) -> bool {
        false
    }

    fn write_awaits(&self, _exchange: &Exchange, _attr: &AttrDetails) -> bool {
        false
    }

    fn invoke_awaits(&self, _exchange: &Exchange, _cmd: &CmdDetails) -> bool {
        false
    }

    async fn write(
        &self,
        exchange: &Exchange<'_>,
        attr: &AttrDetails<'_>,
        data: rs_matter::data_model::objects::AttrData<'_>,
    ) -> Result<(), Error> {
        self.0.write(exchange, attr, data)
    }

    async fn invoke(
        &self,
        exchange: &Exchange<'_>,
        cmd: &CmdDetails<'_>,
        data: &TLVElement<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        self.0.invoke(exchange, cmd, data, encoder)
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
