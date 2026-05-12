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
//! where `rs-matter` is built with the `sync-mutex` feature enabled, which makes `rs-matter` futures
//! `Send` and allows those to be scheduled in a work-stealing executor.
//!
//! NOTE: Work-stealing execution with `rs-matter` is NOT ready yet!

use std::net::UdpSocket;

use log::info;

use rand::{CryptoRng, RngCore};

use rs_matter::crypto::backend::rustcrypto::RustCrypto;
use rs_matter::crypto::Crypto;
use rs_matter::dm::clusters::app::on_off::NoLevelControl;
use rs_matter::dm::clusters::app::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _, DescHandler};
use rs_matter::dm::clusters::net_comm::SharedNetworks;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints::{self, EthSysHandler};
use rs_matter::dm::events::Events;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::subscriptions::Subscriptions;
use rs_matter::dm::IMBuffer;
use rs_matter::dm::{Async, DataModel, Dataver, EmptyHandler, Endpoint, EpClMatcher, Node};
use rs_matter::error::Error;
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{DirKvBlobStore, SharedKvBlobStore};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, handler_chain_type, root_endpoint, Matter, MATTER_PORT};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

type AppHandler<'a> = handler_chain_type!(
    EpClMatcher => on_off::HandlerAsyncAdaptor<on_off::OnOffHandler<'a, TestOnOffDeviceLogic, NoLevelControl>>,
    EpClMatcher => Async<desc::HandlerAdaptor<DescHandler<'a>>>
    | EmptyHandler
);
type AppDmHandler<'a> = EthSysHandler<'a, AppHandler<'a>>;

// Statically allocate in BSS the bigger objects
// `rs-matter` supports efficient initialization of BSS objects (with `init`)
// as well as just allocating the objects on-stack or on the heap.
static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<PooledBuffers<10, IMBuffer>> = StaticCell::new();
static SUBSCRIPTIONS: StaticCell<Subscriptions> = StaticCell::new();
static EVENTS: StaticCell<Events> = StaticCell::new();
static CRYPTO: StaticCell<RustCrypto<'static, FakeRng>> = StaticCell::new();
static KV_BUF: StaticCell<[u8; 4096]> = StaticCell::new();

fn main() -> Result<(), Error> {
    let thread = std::thread::Builder::new()
        // Increase the stack size until the example can work without stack blowups.
        // Note that the used stack size increases exponentially by lowering the level of compiler optimizations,
        // as lower optimization settings prevent the Rust compiler from inlining constructor functions
        // which often results in (unnecessary) memory moves and increased stack utilization:
        // e.g., an opt-level of "0" will require a several times' larger stack.
        //
        // Optimizing/lowering `rs-matter` memory consumption is an ongoing topic.
        .stack_size(550 * 1024)
        .spawn(run)
        .unwrap();

    thread.join().unwrap()
}

fn run() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug"),
    );

    info!(
        "Matter memory: Matter (BSS)={}B, IM Buffers (BSS)={}B, Subscriptions (BSS)={}B",
        core::mem::size_of::<Matter>(),
        core::mem::size_of::<PooledBuffers<10, IMBuffer>>(),
        core::mem::size_of::<Subscriptions>()
    );

    let matter = MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        rs_matter::utils::epoch::sys_epoch,
        MATTER_PORT,
    ));

    // Create the events
    let events = EVENTS.uninit().init_with(Events::init_default());

    // Persistence
    let kv_buf = KV_BUF.uninit().init_zeroed().as_mut_slice();
    let mut kv = DirKvBlobStore::new_default();
    futures_lite::future::block_on(matter.load_persist(&mut kv, kv_buf))?;
    futures_lite::future::block_on(events.load_persist(&mut kv, kv_buf))?;

    // Create the transport buffers
    let buffers = &*BUFFERS.uninit().init_with(PooledBuffers::init(0));

    // Create the subscriptions
    let subscriptions = &*SUBSCRIPTIONS.uninit().init_with(Subscriptions::init());

    // Create the crypto instance
    let crypto = &*CRYPTO.init(RustCrypto::new(FakeRng, DAC_PRIVKEY));

    let mut rand = crypto.rand()?;

    // Our on-off cluster
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(true),
    );

    // Create the Data Model instance
    let dm = DataModel::new(
        matter,
        crypto,
        buffers,
        subscriptions,
        events,
        (NODE, dm_handler(rand, on_off_handler)),
        SharedKvBlobStore::new(kv, kv_buf),
        SharedNetworks::new(EthNetwork::new_default()),
    );

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&dm);
    info!(
        "Responder memory: Responder (stack)={}B, Runner fut (stack)={}B",
        core::mem::size_of_val(&responder),
        core::mem::size_of_val(&responder.run::<4, 4>())
    );

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    #[allow(unused)]
    let respond = responder.run::<4, 4>();

    // Run the background job of the data model
    #[allow(unused)]
    let dm_job = dm.run();

    // Create, load and run the persister
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    info!(
        "Transport memory: Transport fut (stack)={}B, mDNS fut (stack)={}B",
        core::mem::size_of_val(&matter.run(crypto, &socket, &socket, &socket)),
        core::mem::size_of_val(&mdns::run_mdns(matter, crypto))
    );

    // Run the Matter and mDNS transports
    #[allow(unused)]
    let mdns = mdns::run_mdns(matter, crypto);
    let transport = matter.run(crypto, &socket, &socket, &socket);

    if !matter.is_commissioned() {
        // If the device is not commissioned yet, print the QR text and code to the console
        // and enable basic commissioning

        matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, crypto, &())?;
    }

    let executor = async_executor::Executor::new();

    executor.spawn(transport).detach();
    // TODO: Now also fails with "lifetime not general enough"
    // executor.spawn(mdns).detach();

    // NOTE: Commented out because compiling this line blocks forever
    //executor.spawn(dm_job).detach();

    // NOTE: Commented out because compiling this line spits out the following errors:
    // (Likely, we are experiencing https://github.com/rust-lang/rust/issues/64552)
    //
    // ```
    // error: implementation of `Crypto` is not general enough
    //    --> examples/src/bin/onoff_light_work_stealing.rs:207:5
    //     |
    // 207 |     executor.spawn(respond).detach();
    //     |     ^^^^^^^^^^^^^^^^^^^^^^^ implementation of `Crypto` is not general enough
    //     |
    //     = note: `Crypto` would have to be implemented for the type `&'0 &RustCrypto<'_, FakeRng>`, for any lifetime `'0`...
    //     = note: ...but `Crypto` is actually implemented for the type `&'1 &RustCrypto<'_, FakeRng>`, for some specific lifetime `'1`
    //
    // error: implementation of `Send` is not general enough
    //    --> examples/src/bin/onoff_light_work_stealing.rs:219:5
    //     |
    // 219 |     executor.spawn(respond).detach();
    //     |     ^^^^^^^^^^^^^^^^^^^^^^^ implementation of `Send` is not general enough
    //     |
    //     = note: `Send` would have to be implemented for the type `&Notification`
    //     = note: ...but `Send` is actually implemented for the type `&'0 Notification`, for some specific lifetime `'0`
    // error: implementation of `Send` is not general enough
    //    --> examples/src/bin/onoff_light_work_stealing.rs:229:5
    //     |
    // 229 |     executor.spawn(respond).detach();
    //     |     ^^^^^^^^^^^^^^^^^^^^^^^ implementation of `Send` is not general enough
    //     |
    //     = note: `Send` would have to be implemented for the type `&Responder<'_, ChainedExchangeHandler<&DataModel<'_, 15, 0, &RustCrypto<'_, FakeRng>, PooledBuffers<10, heapless::vec::Vec<u8, 1583>>, (Node<'_>, ChainedHandler<EpClMatcher, rs_matter::dm::clusters::net_comm::HandlerAsyncAdaptor<NetCommHandler<'_, EthNetCtl>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::eth_diag::HandlerAdaptor<EthDiagHandler>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::gen_diag::HandlerAdaptor<GenDiagHandler<'_>>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::desc::HandlerAdaptor<DescHandler<'_>>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::basic_info::HandlerAdaptor<BasicInfoHandler>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::gen_comm::HandlerAdaptor<GenCommHandler<'_>>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::adm_comm::HandlerAdaptor<AdminCommHandler>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::noc::HandlerAdaptor<NocHandler>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::acl::HandlerAdaptor<AclHandler>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::grp_key_mgmt::HandlerAdaptor<GrpKeyMgmtHandler>>, ChainedHandler<EpClMatcher, rs_matter::dm::clusters::app::on_off::HandlerAsyncAdaptor<OnOffHandler<'_, TestOnOffDeviceLogic, NoLevelControl>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::desc::HandlerAdaptor<DescHandler<'_>>>, EmptyHandler>>>>>>>>>>>>)>, SecureChannel<'_, &&RustCrypto<'_, FakeRng>>>>`
    //     = note: ...but `Send` is actually implemented for the type `&'0 Responder<'_, ChainedExchangeHandler<&DataModel<'_, 15, 0, &RustCrypto<'_, FakeRng>, PooledBuffers<10, heapless::vec::Vec<u8, 1583>>, (Node<'_>, ChainedHandler<EpClMatcher, rs_matter::dm::clusters::net_comm::HandlerAsyncAdaptor<NetCommHandler<'_, EthNetCtl>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::eth_diag::HandlerAdaptor<EthDiagHandler>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::gen_diag::HandlerAdaptor<GenDiagHandler<'_>>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::desc::HandlerAdaptor<DescHandler<'_>>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::basic_info::HandlerAdaptor<BasicInfoHandler>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::gen_comm::HandlerAdaptor<GenCommHandler<'_>>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::adm_comm::HandlerAdaptor<AdminCommHandler>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::noc::HandlerAdaptor<NocHandler>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::acl::HandlerAdaptor<AclHandler>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::grp_key_mgmt::HandlerAdaptor<GrpKeyMgmtHandler>>, ChainedHandler<EpClMatcher, rs_matter::dm::clusters::app::on_off::HandlerAsyncAdaptor<OnOffHandler<'_, TestOnOffDeviceLogic, NoLevelControl>>, ChainedHandler<EpClMatcher, rs_matter::dm::Async<rs_matter::dm::clusters::desc::HandlerAdaptor<DescHandler<'_>>>, EmptyHandler>>>>>>>>>>>>)>, SecureChannel<'_, &&RustCrypto<'_, FakeRng>>>>`, for some specific lifetime `'0`
    //```
    //executor.spawn(respond).detach();

    futures_lite::future::block_on(executor.run(core::future::pending::<()>()));

    Ok(())
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters: clusters!(desc::DescHandler::CLUSTER, TestOnOffDeviceLogic::CLUSTER),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off handler and its descriptor.
fn dm_handler<'a>(
    mut rand: impl RngCore + Copy,
    on_off: on_off::OnOffHandler<'a, TestOnOffDeviceLogic, NoLevelControl>,
) -> AppDmHandler<'a> {
    endpoints::with_eth_sys(
        &false,
        &(),
        &SysNetifs,
        rand,
        EmptyHandler
            .chain(
                EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                on_off::HandlerAsyncAdaptor(on_off),
            ),
    )
}

// For now, as `thread_rng` is not `Send`
struct FakeRng;

impl RngCore for FakeRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = 0;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FakeRng {}
