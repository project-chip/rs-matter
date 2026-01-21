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

//! An example Matter device that implements the On/Off and LevelControl cluster over Ethernet.
#![allow(clippy::uninlined_format_args)]

use core::cell::Cell;
use core::pin::pin;

use std::fs;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::path::PathBuf;

use embassy_futures::select::{select3, select4};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use async_signal::{Signal, Signals};
use log::{error, info, trace};

use futures_lite::StreamExt;

use rs_matter::dm::clusters::decl::level_control::{
    AttributeId, CommandId, OptionsBitmap, FULL_CLUSTER as LEVEL_CONTROL_FULL_CLUSTER,
};
use rs_matter::dm::clusters::decl::on_off as on_off_cluster;
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::level_control::{self, LevelControlHooks};
use rs_matter::dm::clusters::net_comm::NetworkType;
use rs_matter::dm::clusters::on_off::{self, OnOffHooks, StartUpOnOffEnum};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_DIMMABLE_LIGHT;
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::subscriptions::DefaultSubscriptions;
use rs_matter::dm::IMBuffer;
use rs_matter::dm::{
    Async, AsyncHandler, AsyncMetadata, Cluster, DataModel, Dataver, EmptyHandler, Endpoint,
    EpClMatcher, Node,
};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{Psm, NO_NETWORKS};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::tlv::Nullable;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, with, Matter, MATTER_PORT};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

// Statically allocate in BSS the bigger objects
// `rs-matter` supports efficient initialization of BSS objects (with `init`)
// as well as just allocating the objects on-stack or on the heap.
static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<PooledBuffers<10, NoopRawMutex, IMBuffer>> = StaticCell::new();
static SUBSCRIPTIONS: StaticCell<DefaultSubscriptions> = StaticCell::new();
static PSM: StaticCell<Psm<4096>> = StaticCell::new();

#[cfg(feature = "chip-test")]
const PERSIST_FILE_NAME: &str = "/tmp/chip_kvs";

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
    #[cfg(not(feature = "chip-test"))]
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug"),
    );

    #[cfg(feature = "chip-test")]
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
        core::mem::size_of::<PooledBuffers<10, NoopRawMutex, IMBuffer>>(),
        core::mem::size_of::<DefaultSubscriptions>()
    );

    let matter = MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
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

    // OnOff cluster setup
    let on_off_handler =
        on_off::OnOffHandler::new(Dataver::new_rand(matter.rand()), 1, OnOffDeviceLogic::new());

    // LevelControl cluster setup
    let level_control_handler = level_control::LevelControlHandler::new(
        Dataver::new_rand(matter.rand()),
        1,
        LevelControlDeviceLogic::new(),
        level_control::AttributeDefaults {
            on_level: Nullable::some(42),
            options: OptionsBitmap::from_bits(OptionsBitmap::EXECUTE_IF_OFF.bits()).unwrap(),
            ..Default::default()
        },
    );

    // Cluster wiring, validation and initialisation
    on_off_handler.init(Some(&level_control_handler));
    level_control_handler.init(Some(&on_off_handler));

    // Create the Data Model instance
    let dm = DataModel::new(
        matter,
        buffers,
        subscriptions,
        dm_handler(matter, &on_off_handler, &level_control_handler),
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

    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    info!(
        "Transport memory: Transport fut (stack)={}B, mDNS fut (stack)={}B",
        core::mem::size_of_val(&matter.run(&socket, &socket)),
        core::mem::size_of_val(&mdns::run_mdns(matter))
    );

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(matter));
    let mut transport = pin!(matter.run(&socket, &socket));

    // Create, load and run the persister
    let psm = PSM.uninit().init_with(Psm::init());
    #[cfg(not(feature = "chip-test"))]
    let path = std::env::temp_dir().join("rs-matter");
    #[cfg(feature = "chip-test")]
    let path = PathBuf::from(PERSIST_FILE_NAME);

    info!(
        "Persist memory: Persist (BSS)={}B, Persist fut (stack)={}B, Persist path={}",
        core::mem::size_of::<Psm<4096>>(),
        core::mem::size_of_val(&psm.run(&path, matter, NO_NETWORKS)),
        path.as_path().to_str().unwrap_or("none")
    );

    psm.load(&path, matter, NO_NETWORKS)?;

    // We need to always print the QR text, because the test runner expects it to be printed
    // even if the device is already commissioned
    matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;

    if !matter.is_commissioned() {
        // If the device is not commissioned yet, print the QR code to the console
        // and enable basic commissioning

        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS)?;
    }

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

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    id: 0,
    endpoints: &[
        endpoints::root_endpoint(NetworkType::Ethernet),
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_DIMMABLE_LIGHT),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                OnOffDeviceLogic::CLUSTER,
                LevelControlDeviceLogic::CLUSTER,
            ),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off handler and its descriptor.
fn dm_handler<'a, LH: LevelControlHooks, OH: OnOffHooks>(
    matter: &'a Matter<'a>,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
    level_control: &'a level_control::LevelControlHandler<'a, LH, OH>,
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
                        EpClMatcher::new(Some(1), Some(LevelControlDeviceLogic::CLUSTER.id)),
                        level_control::HandlerAsyncAdaptor(level_control),
                    ),
            ),
        ),
    )
}

// Implementing the LevelControl business logic
pub struct LevelControlDeviceLogic {
    current_level: Cell<Option<u8>>,
    start_up_current_level: Cell<Option<u8>>,
}

impl Default for LevelControlDeviceLogic {
    fn default() -> Self {
        Self::new()
    }
}

impl LevelControlDeviceLogic {
    pub const fn new() -> Self {
        Self {
            current_level: Cell::new(Some(1)),
            start_up_current_level: Cell::new(None),
        }
    }
}

impl LevelControlHooks for LevelControlDeviceLogic {
    const MIN_LEVEL: u8 = 1;
    const MAX_LEVEL: u8 = 254;
    const FASTEST_RATE: u8 = 50;
    const CLUSTER: Cluster<'static> = LEVEL_CONTROL_FULL_CLUSTER
        .with_features(
            level_control::Feature::LIGHTING.bits() | level_control::Feature::ON_OFF.bits(),
        )
        .with_attrs(with!(
            required;
            AttributeId::CurrentLevel
            | AttributeId::RemainingTime
            | AttributeId::MinLevel
            | AttributeId::MaxLevel
            | AttributeId::OnOffTransitionTime
            | AttributeId::OnLevel
            | AttributeId::OnTransitionTime
            | AttributeId::OffTransitionTime
            | AttributeId::DefaultMoveRate
            | AttributeId::Options
            | AttributeId::StartUpCurrentLevel
        ))
        .with_cmds(with!(
            CommandId::MoveToLevel
                | CommandId::Move
                | CommandId::Step
                | CommandId::Stop
                | CommandId::MoveToLevelWithOnOff
                | CommandId::MoveWithOnOff
                | CommandId::StepWithOnOff
                | CommandId::StopWithOnOff
        ));

    fn set_device_level(&self, level: u8) -> Result<Option<u8>, ()> {
        // This is where business logic is implemented to physically change the level of the device.
        Ok(Some(level))
    }

    fn current_level(&self) -> Option<u8> {
        self.current_level.get()
    }

    fn set_current_level(&self, level: Option<u8>) {
        info!(
            "LevelControlDeviceLogic::set_current_level: setting level to {:?}",
            level
        );
        self.current_level.set(level);
    }

    fn start_up_current_level(&self) -> Result<Option<u8>, Error> {
        Ok(self.start_up_current_level.get())
    }

    fn set_start_up_current_level(&self, value: Option<u8>) -> Result<(), Error> {
        self.start_up_current_level.set(value);
        Ok(())
    }
}

// Implementing the OnOff business logic

// A simple serializer and deserializer for persisting the OnOff state in a single byte.
// Stores the on_off state in the first bit.
// Stores the start_up_on_off state in the remaining bits.
#[derive(Default)]
struct OnOffPersistentState {
    on_off: bool,
    start_up_on_off: Option<StartUpOnOffEnum>,
}

impl OnOffPersistentState {
    fn to_bytes_from_values(on_off: bool, start_up_on_off: Option<StartUpOnOffEnum>) -> u8 {
        trace!(
            "to_bytes_from_values: got on_off: {} | start_up_on_off: {:?}",
            on_off,
            start_up_on_off
        );
        let on_off = on_off as u8;
        let start_up_on_off: u8 = match start_up_on_off {
            Some(StartUpOnOffEnum::Off) => 0,
            Some(StartUpOnOffEnum::On) => 1,
            Some(StartUpOnOffEnum::Toggle) => 2,
            None => 3,
        };
        trace!(
            "to_bytes_from_values: vals before writing on_off: {} | start_up_on_off: {}",
            on_off,
            start_up_on_off
        );
        trace!("final val: {}", on_off + (start_up_on_off << 1));
        on_off + (start_up_on_off << 1)
    }

    fn from_bytes(data: u8) -> Result<Self, Error> {
        Ok(Self {
            on_off: data & 1 != 0,
            start_up_on_off: match data >> 1 {
                0 => Some(StartUpOnOffEnum::Off),
                1 => Some(StartUpOnOffEnum::On),
                2 => Some(StartUpOnOffEnum::Toggle),
                3 => None,
                _ => return Err(ErrorCode::Failure.into()),
            },
        })
    }
}

#[derive(Default)]
pub struct OnOffDeviceLogic {
    on_off: Cell<bool>,
    start_up_on_off: Cell<Option<StartUpOnOffEnum>>,
    storage_path: PathBuf,
}

const STORAGE_FILE_NAME: &str = "rs-matter-on-off-state";

impl OnOffDeviceLogic {
    pub fn new() -> Self {
        let storage_path = std::env::temp_dir().join(STORAGE_FILE_NAME);
        info!(
            "OnOffDeviceLogic using storage path: {}",
            storage_path.as_path().to_str().unwrap_or("none")
        );

        let persisted_state = match fs::File::open(storage_path.as_path()) {
            Ok(mut file) => {
                let mut buf: [u8; 1] = [0];
                file.read_exact(&mut buf).unwrap();

                trace!("OnOffDeviceLogic::new: read from storage: {:0x}", buf[0]);

                OnOffPersistentState::from_bytes(buf[0]).unwrap()
            }
            Err(_) => OnOffPersistentState::default(),
        };

        Self {
            on_off: Cell::new(persisted_state.on_off),
            start_up_on_off: Cell::new(persisted_state.start_up_on_off),
            storage_path,
        }
    }

    fn save_state(&self) -> Result<(), Error> {
        let mut file = fs::File::create(self.storage_path.as_path())?;

        let value = OnOffPersistentState::to_bytes_from_values(
            self.on_off.get(),
            self.start_up_on_off.get(),
        );

        let buf = &[value];

        trace!("save_storage: wrote {:0x}", value);

        file.write_all(buf)?;

        Ok(())
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
        info!("OnOff state set to: {}", on);
        if let Err(err) = self.save_state() {
            error!("Error saving state: {}", err);
        }
    }

    fn start_up_on_off(&self) -> Nullable<on_off::StartUpOnOffEnum> {
        match self.start_up_on_off.get() {
            Some(value) => Nullable::some(value),
            None => Nullable::none(),
        }
    }

    fn set_start_up_on_off(&self, value: Nullable<on_off::StartUpOnOffEnum>) -> Result<(), Error> {
        self.start_up_on_off.set(value.into_option());
        self.save_state()
    }

    async fn handle_off_with_effect(&self, _effect: on_off::EffectVariantEnum) {
        // no effect
    }
}
