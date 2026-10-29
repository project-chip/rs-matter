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

//! A variation of the sample Ethernet Matter On/Off Light device
//! where `rs-matter` is built with the `send-sync` feature enabled, which makes `rs-matter` futures
//! `Send` and allows those to be scheduled in a work-stealing executor.
//!
//! The futures are spawned on an `async-executor` executor, which runs on several threads.

use std::net::UdpSocket;

use rand::rngs::StdRng;
use rand::Rng;

use rs_matter::crypto::backend::rustcrypto::RustCrypto;
use rs_matter::crypto::Crypto;
use rs_matter::dm::clusters::app::on_off::NoLevelControl;
use rs_matter::dm::clusters::app::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _, DescHandler};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints::{self, EthSysHandler};
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, Dataver, Endpoint, FnMatcher, Node};
use rs_matter::error::Error;
use rs_matter::im::{InteractionModel, InteractionModelState};
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::DirKvBlobStore;
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::{clusters, devices, handler_chain_type, root_endpoint, Matter, MATTER_PORT};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

/// The number of responder handlers, and of busy responder handlers.
const HANDLERS: usize = 4;

type AppDmHandler<'a> = handler_chain_type!(
    FnMatcher => Async<on_off::HandlerAdaptor<on_off::OnOffHandler<'a, TestOnOffDeviceLogic, NoLevelControl>>>,
    FnMatcher => Async<desc::HandlerAdaptor<DescHandler<'a>>>
    | EthSysHandler<'a>
);

// Statically allocate in BSS the bigger objects
// `rs-matter` supports efficient initialization of BSS objects (with `init`)
// as well as just allocating the objects on-stack or on the heap.
static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static STATE: StaticCell<InteractionModelState> = StaticCell::new();
static CRYPTO: StaticCell<RustCrypto<'static, StdRng>> = StaticCell::new();

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let matter = MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        MATTER_PORT,
    ));

    // Persistence
    let store = DirKvBlobStore::new_default();

    // Create the transport buffers
    let buffers = &*BUFFERS.uninit().init_with(MatterBuffers::init());

    // Create the data model state (subscriptions, events).
    let state = STATE.init(InteractionModelState::new());

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = matter.kv(store);

    // Re-hydrate the `Matter` instance (fabrics, basic info, RTC).
    matter.startup(&kv)?;

    // Create the crypto instance
    let crypto = &*CRYPTO.init(RustCrypto::new(rand::make_rng(), DAC_PRIVKEY));

    let mut rand = crypto.rand()?;

    // Our on-off cluster
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x10,
        TestOnOffDeviceLogic::new(true),
    );

    // Create the Data Model instance
    let im = InteractionModel::new(
        matter,
        crypto,
        buffers,
        (NODE, data_model(matter, rand, on_off_handler)),
        &kv,
        state,
    );

    // Bring the Data Model to its operational state: re-hydrate its persisted
    // state and deliver the `Startup` lifecycle op to all cluster handlers.
    futures_lite::future::block_on(im.startup())?;

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&im);

    // Run the background job of the data model
    let im_job = im.run();

    // Create, load and run the persister
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter and mDNS transports
    let mdns = mdns::run_mdns(matter, crypto);
    let transport = matter.run(crypto, &socket, &socket, &socket);

    if !matter.has_fabrics() {
        // If the device is not commissioned yet, print the QR text and code to the console
        // and enable basic commissioning

        matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, crypto, &())?;
    }

    let executor = async_executor::Executor::new();

    executor.spawn(transport).detach();
    executor.spawn(mdns).detach();
    executor.spawn(im_job).detach();

    // Each responder handler is a task of its own, so that the executor can run several of them at
    // once on different threads: `HANDLERS` handlers answer the exchanges (i.e. that many exchanges
    // can be handled simultaneously), and `HANDLERS` more answer "I'm busy, please try again later"
    // to the exchanges the first ones do not take in time.
    for handler_id in 0..HANDLERS {
        executor
            .spawn(responder.responder().handle(handler_id))
            .detach();
        executor
            .spawn(responder.busy_responder().handle(handler_id))
            .detach();
    }

    // Run the executor on several threads, which take over each other's tasks when idle
    let threads = std::thread::available_parallelism().map_or(2, |threads| threads.get());

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                futures_lite::future::block_on(executor.run(core::future::pending::<()>()))
            });
        }
    });

    Ok(())
}

/// The Node meta-data describing our Matter device.
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

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off handler and its descriptor.
fn data_model<'a>(
    matter: &'a Matter<'a>,
    mut rand: impl Rng + Copy,
    on_off: on_off::OnOffHandler<'a, TestOnOffDeviceLogic, NoLevelControl>,
) -> AppDmHandler<'a> {
    endpoints::EthSysHandlerBuilder::new()
        .netif_diag(&SysNetifs)
        .build(matter, rand)
        .chain(
            |e, c| e == 1 && c == desc::DescHandler::CLUSTER.id,
            Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
        )
        .chain(
            |e, c| e == 1 && c == TestOnOffDeviceLogic::CLUSTER.id,
            Async(on_off::HandlerAdaptor(on_off)),
        )
}
