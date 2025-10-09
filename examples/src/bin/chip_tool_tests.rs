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

use core::cell::Cell;
use core::pin::pin;

use std::net::UdpSocket;
use std::path::PathBuf;

use async_signal::{Signal, Signals};

use embassy_futures::select::{select3, select4};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use futures_lite::StreamExt;

use log::info;

use rs_matter::dm::clusters::basic_info::{
    BasicInfoConfig, ColorEnum, ProductAppearance, ProductFinishEnum,
};
use rs_matter::dm::clusters::decl::on_off as on_off_cluster;
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::level_control::LevelControlHooks;
use rs_matter::dm::clusters::net_comm::NetworkType;
use rs_matter::dm::clusters::on_off::{
    self, EffectVariantEnum, OnOffHandler, OnOffHooks, StartUpOnOffEnum,
};
use rs_matter::dm::clusters::unit_testing::{
    ClusterHandler as _, UnitTestingHandler, UnitTestingHandlerData,
};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::subscriptions::DefaultSubscriptions;
use rs_matter::dm::{
    Async, AsyncHandler, AsyncMetadata, Cluster, DataModel, Dataver, EmptyHandler, Endpoint,
    EpClMatcher, Node,
};
use rs_matter::error::Error;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{Psm, NO_NETWORKS};
use rs_matter::respond::DefaultResponder;
use rs_matter::tlv::Nullable;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::with;
use rs_matter::{clusters, devices, Matter, MATTER_PORT};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

/// The `chip-tool` tests expect the persistent storage location
/// to be `/tmp/chip_kvs`.
///
/// Moreover, this _must_ be a file rather than a directory.
///
/// While there seem to be some facilities to change that in some of the Python scripts,
/// these facilities are simply not exposed at the top level test suite Python runner.
/// TODO: Open a bug for that (and for the single-file expectation) in the `connectedhomeip` repo.
const PERSIST_FILE_NAME: &str = "/tmp/chip_kvs";

// Statically allocate in BSS the bigger objects
// `rs-matter` supports efficient initialization of BSS objects (with `init`)
// as well as just allocating the objects on-stack or on the heap.
static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<PooledBuffers<10, NoopRawMutex, rs_matter::dm::IMBuffer>> =
    StaticCell::new();
static SUBSCRIPTIONS: StaticCell<DefaultSubscriptions> = StaticCell::new();
static PSM: StaticCell<Psm<32768>> = StaticCell::new();
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
        core::mem::size_of::<PooledBuffers<10, NoopRawMutex, rs_matter::dm::IMBuffer>>(),
        core::mem::size_of::<DefaultSubscriptions>()
    );

    let matter = MATTER.uninit().init_with(Matter::init(
        &BASIC_INFO,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        rs_matter::utils::epoch::sys_epoch,
        rs_matter::utils::rand::sys_rand,
        MATTER_PORT,
    ));

    // Need to call this once
    matter.initialize_transport_buffers()?;

    // Create the transport buffers
    let buffers = BUFFERS.uninit().init_with(PooledBuffers::init(0));

    // Create the subscriptions
    let subscriptions = SUBSCRIPTIONS
        .uninit()
        .init_with(DefaultSubscriptions::init());

    // Our on-off cluster
    let on_off_handler =
        OnOffHandler::new_standalone(Dataver::new_rand(matter.rand()), 1, OnOffDeviceLogic::new());

    // Our unit testing cluster data
    let unit_testing_data = UNIT_TESTING_DATA
        .uninit()
        .init_with(RefCell::init(UnitTestingHandlerData::init()));

    // Create the Data Model instance
    let dm = DataModel::new(
        matter,
        buffers,
        subscriptions,
        dm_handler(matter, unit_testing_data, &on_off_handler),
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

    // Create, load and run the persister
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    info!(
        "Transport memory: Transport fut (stack)={}B, mDNS fut (stack)={}B",
        core::mem::size_of_val(&matter.run(&socket, &socket, DiscoveryCapabilities::IP)),
        core::mem::size_of_val(&mdns::run_mdns(matter))
    );

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(matter));
    let mut transport = pin!(async {
        // Unconditionally enable basic commissioning because the `chip-tool` tests
        // expect that - even if the device is already commissioned,
        // as the code path always unconditionally scans for the QR code.
        //
        // TODO: Figure out why the test suite has this expectation and also whether
        // to instead just always enable printing the QR code to the console at startup
        // rather than to enable basic commissioning.
        matter
            .enable_basic_commissioning(DiscoveryCapabilities::IP, 0)
            .await?;

        matter.run_transport(&socket, &socket).await
    });

    // Create, load and run the persister
    let psm = PSM.uninit().init_with(Psm::init());
    let path = PathBuf::from(PERSIST_FILE_NAME);

    info!(
        "Persist memory: Persist (BSS)={}B, Persist fut (stack)={}B",
        core::mem::size_of::<Psm<4096>>(),
        core::mem::size_of_val(&psm.run(&path, matter, NO_NETWORKS,))
    );

    psm.load(&path, matter, NO_NETWORKS)?;

    let mut persist = pin!(psm.run(&path, matter, NO_NETWORKS));

    // Listen to SIGTERM because at the end of the test we'll receive it
    let mut term_signal = Signals::new([Signal::Term])?;
    let mut term = pin!(async {
        term_signal.next().await;
        Ok(())
    });

    // Combine all async tasks in a single one
    let all = select4(
        &mut transport,
        &mut mdns,
        &mut persist,
        select3(&mut respond, &mut dm_job, &mut term).coalesce(),
    );

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all.coalesce())
}

/// Overriden so that we can set the product appearance to
/// what the `TestBasicInformation` tests expect.
const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    product_appearance: ProductAppearance {
        finish: ProductFinishEnum::Satin,
        color: Some(ColorEnum::Purple),
    },
    ..TEST_DEV_DET
};

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    id: 0,
    endpoints: &[
        endpoints::root_endpoint(NetworkType::Ethernet),
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                OnOffDeviceLogic::CLUSTER,
                UnitTestingHandler::CLUSTER
            ),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off and unit testing handlers.
fn dm_handler<'a, OH: OnOffHooks, LH: LevelControlHooks>(
    matter: &'a Matter<'a>,
    unit_testing_data: &'a RefCell<UnitTestingHandlerData>,
    on_off: &'a OnOffHandler<'a, OH, LH>,
) -> impl AsyncMetadata + AsyncHandler + 'a {
    (
        NODE,
        endpoints::with_eth(
            &(),
            &UnixNetifs,
            matter.rand(),
            endpoints::with_sys(
                &false,
                matter.rand(),
                EmptyHandler
                    .chain(
                        EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                        Async(desc::DescHandler::new(Dataver::new_rand(matter.rand())).adapt()),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(OnOffDeviceLogic::CLUSTER.id)),
                        on_off::HandlerAsyncAdaptor(on_off),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(UnitTestingHandler::CLUSTER.id)),
                        Async(
                            UnitTestingHandler::new(
                                Dataver::new_rand(matter.rand()),
                                unit_testing_data,
                            )
                            .adapt(),
                        ),
                    ),
            ),
        ),
    )
}

// Implementing the OnOff business logic

#[derive(Default)]
pub struct OnOffDeviceLogic {
    on_off: Cell<bool>,
    start_up_on_off: Cell<Option<StartUpOnOffEnum>>,
}

impl OnOffDeviceLogic {
    pub fn new() -> Self {
        Self {
            on_off: Cell::new(false),
            start_up_on_off: Cell::new(None),
        }
    }
}

impl OnOffHooks for OnOffDeviceLogic {
    const CLUSTER: Cluster<'static> = on_off_cluster::FULL_CLUSTER
        .with_revision(6)
        .with_features(on_off_cluster::Feature::LIGHTING.bits())
        .with_attrs(with!(
            required;
            on_off_cluster::AttributeId::OnOff
            | on_off_cluster::AttributeId::GlobalSceneControl
            | on_off_cluster::AttributeId::OnTime
            | on_off_cluster::AttributeId::OffWaitTime
            | on_off_cluster::AttributeId::StartUpOnOff
        ))
        .with_cmds(with!(
            on_off_cluster::CommandId::Off
                | on_off_cluster::CommandId::On
                | on_off_cluster::CommandId::Toggle
                | on_off_cluster::CommandId::OffWithEffect
                | on_off_cluster::CommandId::OnWithRecallGlobalScene
                | on_off_cluster::CommandId::OnWithTimedOff
        ));

    fn on_off(&self) -> bool {
        self.on_off.get()
    }

    fn set_on_off(&self, on: bool) {
        self.on_off.set(on);
    }

    fn start_up_on_off(&self) -> Nullable<StartUpOnOffEnum> {
        match self.start_up_on_off.get() {
            Some(value) => Nullable::some(value),
            None => Nullable::none(),
        }
    }

    fn set_start_up_on_off(&self, value: Nullable<StartUpOnOffEnum>) -> Result<(), Error> {
        self.start_up_on_off.set(value.into_option());
        Ok(())
    }

    async fn handle_off_with_effect(&self, _effect: EffectVariantEnum) {
        // no effect
    }
}
