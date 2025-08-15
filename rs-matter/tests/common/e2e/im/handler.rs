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

use rs_matter::dm::clusters::desc::{self, ClusterHandler as _, DescHandler};
use rs_matter::dm::clusters::on_off::{self, ClusterHandler as _, OnOffHandler};
use rs_matter::dm::devices::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE};
use rs_matter::dm::endpoints::{with_eth, with_sys, EthHandler, SysHandler, ROOT_ENDPOINT_ID};
use rs_matter::dm::{
    Async, AsyncHandler, AsyncMetadata, ChainedHandler, Dataver, EmptyHandler, Endpoint,
    EpClMatcher, InvokeContext, InvokeReply, Node, ReadContext, ReadReply, WriteContext,
};
use rs_matter::error::Error;
use rs_matter::Matter;
use rs_matter::{clusters, handler_chain_type};

use crate::common::e2e::E2eRunner;

use super::echo_cluster::{self, EchoHandler};

/// A sample handler for E2E IM tests.
pub struct E2eTestHandler<'a>(
    handler_chain_type!(
        EpClMatcher => Async<on_off::HandlerAdaptor<OnOffHandler>>,
        EpClMatcher => Async<EchoHandler>,
        EpClMatcher => Async<desc::HandlerAdaptor<DescHandler<'static>>>,
        EpClMatcher => Async<EchoHandler>
        | EthHandler<'a, SysHandler<'a, EmptyHandler>>),
);

impl<'a> E2eTestHandler<'a> {
    pub const NODE: Node<'static> = Node {
        id: 0,
        endpoints: &[
            Endpoint {
                id: 0,
                clusters: clusters!(eth; echo_cluster::CLUSTER),
                device_types: &[DEV_TYPE_ROOT_NODE],
            },
            Endpoint {
                id: 1,
                clusters: clusters!(
                    DescHandler::CLUSTER,
                    OnOffHandler::CLUSTER,
                    echo_cluster::CLUSTER,
                ),
                device_types: &[DEV_TYPE_ON_OFF_LIGHT],
            },
        ],
    };

    pub fn new(matter: &'a Matter<'a>) -> Self {
        let handler = with_eth(
            &(),
            &(),
            matter.rand(),
            with_sys(&false, matter.rand(), EmptyHandler),
        );

        let handler = ChainedHandler::new(
            EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(echo_cluster::ID)),
            Async(EchoHandler::new(2, Dataver::new_rand(matter.rand()))),
            handler,
        )
        .chain(
            EpClMatcher::new(Some(1), Some(DescHandler::CLUSTER.id)),
            Async(DescHandler::new(Dataver::new_rand(matter.rand())).adapt()),
        )
        .chain(
            EpClMatcher::new(Some(1), Some(echo_cluster::ID)),
            Async(EchoHandler::new(3, Dataver::new_rand(matter.rand()))),
        )
        .chain(
            EpClMatcher::new(Some(1), Some(OnOffHandler::CLUSTER.id)),
            Async(OnOffHandler::new(Dataver::new_rand(matter.rand())).adapt()),
        );

        Self(handler)
    }

    pub fn echo_cluster(&self, endpoint: u16) -> &EchoHandler {
        match endpoint {
            0 => &self.0.next.next.next.handler.0,
            1 => &self.0.next.handler.0,
            _ => panic!(),
        }
    }
}

impl AsyncHandler for E2eTestHandler<'_> {
    fn read_awaits(&self, _ctx: impl ReadContext) -> bool {
        false
    }

    fn write_awaits(&self, _ctx: impl WriteContext) -> bool {
        false
    }

    fn invoke_awaits(&self, _ctx: impl InvokeContext) -> bool {
        false
    }

    async fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error> {
        self.0.read(ctx, reply).await
    }

    async fn write(&self, ctx: impl WriteContext) -> Result<(), Error> {
        self.0.write(ctx).await
    }

    async fn invoke(&self, ctx: impl InvokeContext, reply: impl InvokeReply) -> Result<(), Error> {
        self.0.invoke(ctx, reply).await
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
