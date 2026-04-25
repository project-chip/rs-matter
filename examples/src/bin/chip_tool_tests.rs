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

//! A dedicated Matter device for ConnectedHomeIP YAML integration tests.
//! Implements On/Off and Unit Testing clusters over Ethernet.

use core::pin::pin;

use std::net::UdpSocket;

use async_signal::{Signal, Signals};

use embassy_futures::select::select3;

use futures_lite::StreamExt;

use log::info;

use rand::RngCore;
use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::test::TestOnOffDeviceLogic;
use rs_matter::dm::clusters::app::on_off::{self, OnOffHandler, OnOffHooks};
use rs_matter::dm::clusters::basic_info::{
    BasicInfoConfig, ColorEnum, PairingHintFlags, ProductAppearance, ProductFinishEnum,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::SharedNetworks;
use rs_matter::dm::clusters::unit_testing::{
    ClusterHandler as _, UnitTestingHandler, UnitTestingHandlerData,
};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints;
use rs_matter::dm::events::Events;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::subscriptions::Subscriptions;
use rs_matter::dm::{
    Async, AsyncHandler, AsyncMetadata, DataModel, Dataver, EmptyHandler, Endpoint, EpClMatcher,
    Node,
};
use rs_matter::error::Error;
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{FileKvBlobStore, SharedKvBlobStore};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

// Statically allocate in BSS the bigger objects
// `rs-matter` supports efficient initialization of BSS objects (with `init`)
// as well as just allocating the objects on-stack or on the heap.
static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<PooledBuffers<10, rs_matter::dm::IMBuffer>> = StaticCell::new();
static SUBSCRIPTIONS: StaticCell<Subscriptions> = StaticCell::new();
static EVENTS: StaticCell<Events> = StaticCell::new();
static KV_BUF: StaticCell<[u8; 4096]> = StaticCell::new();
static UNIT_TESTING_DATA: StaticCell<RefCell<UnitTestingHandlerData>> = StaticCell::new();

fn main() -> Result<(), Error> {
    // Enable detailed backtraces for debugging test failures
    std::env::set_var("RUST_BACKTRACE", "1");

    // Special logging configuration compatible with ConnectedHomeIP YAML tests
    // Log to stdout with simplified format at debug level as required by chip-tool tests
    env_logger::builder()
        .format(|buf, record| {
            use std::io::Write;
            writeln!(buf, "{}: {}", record.level(), record.args())
        })
        .target(env_logger::Target::Stdout)
        .filter_level(::log::LevelFilter::Debug)
        .init();

    info!(
        "Matter memory: Matter (BSS)={}B, IM Buffers (BSS)={}B, Subscriptions (BSS)={}B",
        core::mem::size_of::<Matter>(),
        core::mem::size_of::<PooledBuffers<10, rs_matter::dm::IMBuffer>>(),
        core::mem::size_of::<Subscriptions>()
    );

    let matter = MATTER.uninit().init_with(Matter::init(
        &BASIC_INFO,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        rs_matter::utils::epoch::sys_epoch,
        MATTER_PORT,
    ));

    // Create the event queue
    let events = EVENTS.uninit().init_with(Events::init_default());

    // Persistence
    let kv_buf = KV_BUF.uninit().init_zeroed().as_mut_slice();
    let mut kv = FileKvBlobStore::new_default();
    futures_lite::future::block_on(matter.load_persist(&mut kv, kv_buf))?;
    futures_lite::future::block_on(events.load_persist(&mut kv, kv_buf))?;

    // Create the transport buffers
    let buffers = BUFFERS.uninit().init_with(PooledBuffers::init(0));

    // Create the subscriptions
    let subscriptions = SUBSCRIPTIONS.uninit().init_with(Subscriptions::init());

    // Create the crypto instance
    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // Our on-off cluster
    let on_off_handler_1 = OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(false),
    );

    // On-off cluster for 2nd endpoint
    let on_off_handler_2 = OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        2,
        TestOnOffDeviceLogic::new(false),
    );

    // Our unit testing cluster data
    let unit_testing_data = UNIT_TESTING_DATA
        .uninit()
        .init_with(RefCell::init(UnitTestingHandlerData::init()));

    // Create the Data Model instance
    let dm = DataModel::new(
        matter,
        &crypto,
        buffers,
        subscriptions,
        events,
        dm_handler(
            rand,
            unit_testing_data,
            &on_off_handler_1,
            &on_off_handler_2,
        ),
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
    let mut respond = pin!(responder.run::<4, 4>());

    // Run the background job of the data model
    let mut dm_job = pin!(dm.run());

    // Bind the UDP socket
    let udp_socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    #[allow(unused_mut)]
    let (mut net_send, mut net_recv, mut net_multicast) = (&udp_socket, &udp_socket, &udp_socket);

    // Optionally bind a TCP listener as well
    #[cfg(feature = "test-tcp")]
    let tcp = {
        use rs_matter::transport::network::tcp::TcpNetwork;

        let tcp_socket = async_io::Async::<std::net::TcpListener>::bind(MATTER_SOCKET_BIND_ADDR)?;

        info!(
            "TCP transport enabled, listening on {}",
            MATTER_SOCKET_BIND_ADDR
        );

        TcpNetwork::<8>::new(tcp_socket)
    };

    // Optionally create a chained UDP+TCP network
    #[cfg(feature = "test-tcp")]
    let (mut net_send, mut net_recv, mut net_multicast) = {
        use rs_matter::transport::network::{Address, ChainedNetwork};

        let net_send = ChainedNetwork::new(|addr: &Address| addr.is_tcp(), &tcp, net_send);
        let net_recv = ChainedNetwork::new(|addr: &Address| addr.is_tcp(), &tcp, net_recv);

        (net_send, net_recv, net_multicast)
    };

    info!(
        "Transport memory: Transport fut (stack)={}B, mDNS fut (stack)={}B",
        core::mem::size_of_val(&matter.run(
            &crypto,
            &mut net_send,
            &mut net_recv,
            &mut net_multicast
        )),
        core::mem::size_of_val(&mdns::run_mdns(matter, &crypto))
    );

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &mut net_send, &mut net_recv, &mut net_multicast));

    // We need to always print the QR text, because the test runner expects it to be printed
    // even if the device is already commissioned
    matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;

    if !matter.is_commissioned() {
        // If the device is not commissioned yet, print the QR code to the console
        // and enable basic commissioning

        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, dm.change_notify())?;
    }

    // Listen to SIGTERM (or Ctrl-C on Windows, where SIGTERM is not
    // supported by `async-signal`) because at the end of the test we'll
    // receive it.
    #[cfg(not(windows))]
    let mut term_signal = Signals::new([Signal::Term])?;
    #[cfg(windows)]
    let mut term_signal = Signals::new([Signal::Int])?;
    let mut term = pin!(async {
        term_signal.next().await;
        Ok(())
    });

    // Combine all async tasks in a single one
    let all = select3(
        &mut transport,
        &mut mdns,
        select3(&mut respond, &mut dm_job, &mut term).coalesce(),
    );

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all.coalesce())
}

/// Overriden so that:
/// - We can set the product appearance to what the `TestBasicInformation` tests expect;
/// - We can set the device type and pairing hint to what the `TestDiscovery` tests expect.
/// - When the `test-tcp` feature is enabled, we advertise TCP support via mDNS (`T=1`).
const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    product_appearance: ProductAppearance {
        finish: ProductFinishEnum::Satin,
        color: Some(ColorEnum::Purple),
    },
    device_type: Some(0x0101),
    pairing_hint: PairingHintFlags::PRESS_RESET_BUTTON,
    tcp_supported: cfg!(feature = "test-tcp"),
    ..TEST_DEV_DET
};

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(geth),
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                UnitTestingHandler::CLUSTER
            ),
        },
        Endpoint {
            id: 2,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER
            ),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off and unit testing handlers.
fn dm_handler<'a, OH: OnOffHooks, LH: LevelControlHooks>(
    mut rand: impl RngCore + Copy,
    unit_testing_data: &'a RefCell<UnitTestingHandlerData>,
    on_off_1: &'a OnOffHandler<'a, OH, LH>,
    on_off_2: &'a OnOffHandler<'a, OH, LH>,
) -> impl AsyncMetadata + AsyncHandler + 'a {
    (
        NODE,
        endpoints::with_eth_sys(
            &false,
            &(),
            &SysNetifs,
            rand,
            EmptyHandler
                // Clusters for Endpoint 1
                .chain(
                    EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                    Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(groups::GroupsHandler::CLUSTER.id)),
                    Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                    on_off::HandlerAsyncAdaptor(on_off_1),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(UnitTestingHandler::CLUSTER.id)),
                    Async(
                        UnitTestingHandler::new(Dataver::new_rand(&mut rand), unit_testing_data)
                            .adapt(),
                    ),
                )
                // (mostly) Similar Clusters for Endpoint 2
                .chain(
                    EpClMatcher::new(Some(2), Some(desc::DescHandler::CLUSTER.id)),
                    Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                )
                .chain(
                    EpClMatcher::new(Some(2), Some(groups::GroupsHandler::CLUSTER.id)),
                    Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                )
                .chain(
                    EpClMatcher::new(Some(2), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                    on_off::HandlerAsyncAdaptor(on_off_2),
                ),
        ),
    )
}
