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
#![recursion_limit = "4000"]
use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::{select3, select4};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use log::info;

use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::NetworkType;
use rs_matter::dm::clusters::on_off::{self, ClusterHandler as _};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_DIMMABLE_LIGHT;
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::subscriptions::DefaultSubscriptions;
use rs_matter::dm::IMBuffer;
use rs_matter::dm::{
    Async, AsyncHandler, AsyncMetadata, Dataver, EmptyHandler, Endpoint, EpClMatcher, Node,
};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{Psm, NO_NETWORKS};
use rs_matter::respond::DefaultResponder;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, Matter, MATTER_PORT};

use rs_matter::dm::clusters::level_control::{self, ClusterAsyncHandler as _, LevelControlState};

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

    // NOTE: chip-tool tests need the log to go to `stdout` instead
    // env_logger::builder()
    //     .format(|buf, record| {
    //         use std::io::Write;
    //         writeln!(buf, "{}: {}", record.level(), record.args())
    //     })
    //     .target(env_logger::Target::Stdout)
    //     .filter_level(::log::LevelFilter::Info)
    //     .init();

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

    // Our on-off cluster
    let on_off = on_off::OnOffHandler::new(Dataver::new_rand(matter.rand()));

    let level_control_handler = LevelControlHandler::new();
    let level_control_state = LevelControlState::new(&level_control_handler);
    let level_control_cluster = level_control::LevelControlCluster::new(Dataver::new_rand(matter.rand()), &level_control_state);
    level_control_cluster.set_on_off_cluster(&on_off);
    let mut level_control_job = pin!(level_control_cluster.run());

    // Assemble our Data Model handler by composing the predefined Root Endpoint handler with the On/Off handler
    let dm_handler = dm_handler(matter, &on_off, &level_control_cluster);

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(matter, buffers, subscriptions, &dm_handler);
    info!(
        "Responder memory: Responder (stack)={}B, Runner fut (stack)={}B",
        core::mem::size_of_val(&responder),
        core::mem::size_of_val(&responder.run::<4, 4>())
    );

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    let mut respond = pin!(responder.run::<4, 4>());

    // Run the background job the handler might be having
    let mut dm_handler_job = pin!(dm_handler.run());

    // This is a sample code that simulates state changes triggered by the HAL
    // Changes will be properly communicated to the Matter controllers and other Matter apps (i.e. Google Home, Alexa), thanks to subscriptions
    // let mut device = pin!(async {
    //     loop {
    //         Timer::after(Duration::from_secs(5)).await;

    //         on_off.set(!on_off.get());
    //         subscriptions.notify_changed();

    //         info!("Lamp toggled");
    //     }
    // });

    // Create, load and run the persister
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    info!(
        "Transport memory: Transport fut (stack)={}B, mDNS fut (stack)={}B",
        core::mem::size_of_val(&matter.run(&socket, &socket, DiscoveryCapabilities::IP)),
        core::mem::size_of_val(&mdns::run_mdns(matter))
    );

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(matter));
    let mut transport = pin!(matter.run(&socket, &socket, DiscoveryCapabilities::IP));

    // Create, load and run the persister
    let psm = PSM.uninit().init_with(Psm::init());
    let path = std::env::temp_dir().join("rs-matter");

    info!(
        "Persist memory: Persist (BSS)={}B, Persist fut (stack)={}B",
        core::mem::size_of::<Psm<4096>>(),
        core::mem::size_of_val(&psm.run(&path, matter, NO_NETWORKS))
    );

    psm.load(&path, matter, NO_NETWORKS)?;

    let mut persist = pin!(psm.run(&path, matter, NO_NETWORKS));

    // Combine all async tasks in a single one
    let all = select4(
        &mut transport,
        &mut mdns,
        &mut persist,
        select3(&mut respond, &mut dm_handler_job, &mut level_control_job).coalesce(),
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
                on_off::OnOffHandler::CLUSTER,
                level_control::LevelControlCluster::<LevelControlHandler>::CLUSTER,
            ),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off handler and its descriptor.
fn dm_handler<'a, 'oc, 'lc, LH: LevelControlHooks>(
    matter: &'a Matter<'a>,
    on_off: &'oc on_off::OnOffHandler,
    level_control: &'lc level_control::LevelControlCluster<'a, LH>,
) -> impl AsyncMetadata + AsyncHandler + 'a + 'oc + 'lc
where
    'oc: 'a,
    'a: 'oc,
    'lc: 'a
{
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
                        EpClMatcher::new(Some(1), Some(on_off::OnOffHandler::CLUSTER.id)),
                        Async(on_off::HandlerAdaptor(on_off)),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(level_control::LevelControlCluster::<'a, LH>::CLUSTER.id)),
                        level_control::HandlerAsyncAdaptor(level_control),
                    ),
            ),
        ),
    )
}

// Implementing the LevelControl business logic

use core::cell::Cell;
use rs_matter::tlv::Nullable;
use rs_matter::dm::clusters::decl::level_control::OptionsBitmap;
use rs_matter::dm::clusters::level_control::{LevelControlHooks};

pub struct LevelControlHandler {
    options: Cell<OptionsBitmap>,
    on_level: Cell<Nullable<u8>>,
    current_level: Cell<u8>,
    startup_current_level: Cell<Nullable<u8>>,
    remaining_time: Cell<u16>,
}

impl LevelControlHandler {
    pub const fn new() -> Self {
        Self {
            options: Cell::new(OptionsBitmap::from_bits(OptionsBitmap::EXECUTE_IF_OFF.bits() as u8)
                .unwrap()),
            on_level: Cell::new(Nullable::some(42)),
            current_level: Cell::new(1),
            startup_current_level: Cell::new(Nullable::some(73)),
            remaining_time: Cell::new(0),
        }
    }
}


impl LevelControlHooks for LevelControlHandler {
    const MIN_LEVEL: u8 = 1;
    const MAX_LEVEL: u8 = 254;
    const FASTEST_RATE: u8 = 50;

    fn set_level(&self, level: u8) -> Result<(), Error> {
        // This is where business logic is implemented to physically change the level.
        info!("LevelControlHandler::set_level: setting level to {}", level);
        Ok(())
    }
    
    fn raw_get_options(&self) -> Result<OptionsBitmap, Error> {
        Ok(self.options.get())
    }
    
    fn raw_set_options(&self, value: OptionsBitmap) -> Result<(), Error> {
        self.options.set(value);
        Ok(())
    }
    
    fn raw_get_on_level(&self) -> Result<Nullable<u8>, Error> {
        // todo can we impl Copy for Nullable?
        let val = self.on_level.take();
        self.on_level.set(val.clone());
        Ok(val)
    }
    
    fn raw_set_on_level(&self, value: Nullable<u8>) -> Result<(), Error> {
        self.on_level.set(value);
        Ok(())
    }
    
    fn raw_get_current_level(&self) -> Result<Nullable<u8>, Error> {
        Ok(Nullable::some(self.current_level.get()))
    }
    
    fn raw_set_current_level(&self, value: Nullable<u8>) -> Result<(), Error> {
        match value.into_option() {
            Some(value) => self.current_level.set(value),
            None => return Err(ErrorCode::InvalidData.into()),
        }
        Ok(())
    }
    
    fn raw_get_startup_current_level(&self) -> Result<Nullable<u8>, Error> {
        let val = self.startup_current_level.take();
        self.startup_current_level.set(val.clone());
        Ok(val)
    }
    
    fn raw_set_startup_current_level(&self, value: Nullable<u8>) -> Result<(), Error> {
        self.startup_current_level.set(value);
        Ok(())
    }
    
    fn raw_get_remaining_time(&self) -> Result<u16, Error> {
        Ok(self.remaining_time.get())
    }
    
    fn raw_set_remaining_time(&self, value: u16) -> Result<(), Error> {
        self.remaining_time.set(value);
        Ok(())
    }
}