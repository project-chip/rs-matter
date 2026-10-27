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

//! Checks that with feature `send-sync` the futures a node runs - the transport, the mDNS
//! responder, the data model job and the responder - are `Send + 'static`, so that they can be
//! spawned on a work-stealing executor.
//!
//! The futures are only created, never run.

use std::net::UdpSocket;

use rs_matter::crypto::{test_only_crypto, Crypto};
use rs_matter::dm::clusters::app::on_off::OnOffHooks;
use rs_matter::dm::clusters::app::on_off::{self, test::TestOnOffDeviceLogic, NoLevelControl};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _, DescHandler};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints::{self, EthSysHandler};
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, Dataver, Endpoint, FnMatcher, Node};
use rs_matter::error::Error;
use rs_matter::im::{InteractionModel, InteractionModelState};
use rs_matter::persist::DummyKvBlobStore;
use rs_matter::respond::DefaultResponder;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::transport::network::mdns::builtin::{BuiltinMdns, Host};
use rs_matter::transport::network::Ipv4Addr;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::{clusters, devices, handler_chain_type, root_endpoint, Matter, MATTER_PORT};

use static_cell::StaticCell;

type DmHandler<'a> = handler_chain_type!(
    FnMatcher => Async<on_off::HandlerAdaptor<on_off::OnOffHandler<'a, TestOnOffDeviceLogic, NoLevelControl>>>,
    FnMatcher => Async<desc::HandlerAdaptor<DescHandler<'a>>>
    | EthSysHandler<'a>
);

const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(desc::DescHandler::CLUSTER, TestOnOffDeviceLogic::CLUSTER),
        ),
    ],
};

const HOST: Host<'static> = Host {
    hostname: "rs-matter",
    ip: Ipv4Addr::LOCALHOST,
    ipv6: &[],
};

static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static STATE: StaticCell<InteractionModelState> = StaticCell::new();

#[test]
fn node_futures_are_send() -> Result<(), Error> {
    // Everything the futures borrow is `'static`, as on an executor which requires `'static`
    // futures (e.g. `tokio::spawn`).
    let matter = &*MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        MATTER_PORT,
    ));
    let buffers = &*BUFFERS.uninit().init_with(MatterBuffers::init());
    let state = &*STATE.init(InteractionModelState::new());
    let kv = &*Box::leak(Box::new(matter.kv(DummyKvBlobStore)));
    let crypto = &*Box::leak(Box::new(test_only_crypto()));

    let mut rand = crypto.rand()?;

    let on_off = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x10,
        TestOnOffDeviceLogic::new(true),
    );

    let handler: DmHandler<'static> = endpoints::EthSysHandlerBuilder::new()
        .netif_diag(&SysNetifs)
        .build(rand)
        .chain(
            |e, c| e == 1 && c == desc::DescHandler::CLUSTER.id,
            Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
        )
        .chain(
            |e, c| e == 1 && c == TestOnOffDeviceLogic::CLUSTER.id,
            Async(on_off::HandlerAdaptor(on_off)),
        );

    let im = &*Box::leak(Box::new(InteractionModel::new(
        matter,
        crypto,
        buffers,
        (NODE, handler),
        kv,
        state,
    )));
    let responder = &*Box::leak(Box::new(DefaultResponder::new(im)));
    let socket = &*Box::leak(Box::new(async_io::Async::<UdpSocket>::bind((
        [127, 0, 0, 1],
        0,
    ))?));
    let mdns = Box::leak(Box::new(BuiltinMdns::new()));

    let transport = matter.run(crypto, socket, socket, socket);
    let mdns = mdns.run(socket, socket, &HOST, None, None, matter, crypto);
    let im_job = im.run();
    let respond = responder.run::<4, 4>();

    assert_spawnable(&transport);
    assert_spawnable(&mdns);
    assert_spawnable(&im_job);
    assert_spawnable(&respond);

    Ok(())
}

/// The bounds a work-stealing executor puts on the futures it spawns.
fn assert_spawnable<F: Send + 'static>(_: &F) {}
