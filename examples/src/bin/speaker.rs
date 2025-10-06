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

//! An example Matter device that implements a Speaker device over Ethernet.
//! Demonstrates how to make use of the `rs_matter::import` macro for `LevelControl`.

use core::cell::Cell;
use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::{select, select4};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use log::info;

use rs_matter::dm::clusters::decl::level_control::{
    AttributeId, CommandId, FULL_CLUSTER as LEVEL_CONTROL_FULL_CLUSTER,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::level_control::{
    self, AttributeDefaults, LevelControlHandler, LevelControlHooks, OptionsBitmap,
};
use rs_matter::dm::clusters::net_comm::NetworkType;
use rs_matter::dm::clusters::on_off::{self, test::TestOnOffDeviceLogic, OnOffHandler, OnOffHooks};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_SMART_SPEAKER;
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
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, with, Matter, MATTER_PORT};

#[path = "../common/mdns.rs"]
mod mdns;

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // Create the Matter object
    let matter = Matter::new_default(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    // Need to call this once
    matter.initialize_transport_buffers()?;

    // Create the transport buffers
    let buffers = PooledBuffers::<10, NoopRawMutex, _>::new(0);

    // Create the subscriptions
    let subscriptions = DefaultSubscriptions::new();

    // OnOff cluster setup
    let on_off_device_logic = TestOnOffDeviceLogic::new();
    let on_off_handler =
        on_off::OnOffHandler::new(Dataver::new_rand(matter.rand()), 1, &on_off_device_logic);

    // LevelControl cluster setup
    let level_control_device_logic = LevelControlDeviceLogic::new();
    let level_control_defaults = AttributeDefaults {
        on_level: Nullable::some(42),
        options: OptionsBitmap::from_bits(OptionsBitmap::EXECUTE_IF_OFF.bits()).unwrap(),
        on_off_transition_time: 0,
        on_transition_time: Nullable::none(),
        off_transition_time: Nullable::none(),
        default_move_rate: Nullable::none(),
    };
    let level_control_handler = LevelControlHandler::new(
        Dataver::new_rand(matter.rand()),
        1,
        &level_control_device_logic,
        level_control_defaults,
    );

    // Cluster wiring, validation and initialisation
    on_off_handler.init(Some(&level_control_handler));
    level_control_handler.init(Some(&on_off_handler));

    // Create the Data Model instance
    let dm = DataModel::new(
        &matter,
        &buffers,
        &subscriptions,
        dm_handler(&matter, &on_off_handler, &level_control_handler),
    );

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&dm);

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    let mut respond = pin!(responder.run::<4, 4>());

    // Run the background job of the data model
    let mut dm_job = pin!(dm.run());

    // Create the Matter UDP socket
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(&matter));
    let mut transport = pin!(matter.run(&socket, &socket, DiscoveryCapabilities::IP));

    // Create, load and run the persister
    let mut psm: Psm<4096> = Psm::new();
    let path = std::env::temp_dir().join("rs-matter");

    psm.load(&path, &matter, NO_NETWORKS)?;

    let mut persist = pin!(psm.run(&path, &matter, NO_NETWORKS));

    // Combine all async tasks in a single one
    let all = select4(
        &mut transport,
        &mut mdns,
        &mut persist,
        select(&mut respond, &mut dm_job).coalesce(),
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
            device_types: devices!(DEV_TYPE_SMART_SPEAKER),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                LevelControlDeviceLogic::CLUSTER
            ),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the Speaker handler.
fn dm_handler<'a, LH: LevelControlHooks, OH: OnOffHooks>(
    matter: &Matter<'_>,
    on_off: &'a OnOffHandler<'a, OH, LH>,
    level_control: &'a LevelControlHandler<'a, LH, OH>,
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
                        EpClMatcher::new(Some(1), Some(LevelControlDeviceLogic::CLUSTER.id)),
                        level_control::HandlerAsyncAdaptor(level_control),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                        on_off::HandlerAsyncAdaptor(on_off),
                    ),
            ),
        ),
    )
}

pub struct LevelControlDeviceLogic {
    current_level: Cell<u8>,
    start_up_current_level: Cell<Nullable<u8>>,
}

impl Default for LevelControlDeviceLogic {
    fn default() -> Self {
        Self::new()
    }
}

impl LevelControlDeviceLogic {
    pub const fn new() -> Self {
        Self {
            current_level: Cell::new(1),
            start_up_current_level: Cell::new(Nullable::none()),
        }
    }
}

impl LevelControlHooks for LevelControlDeviceLogic {
    const MIN_LEVEL: u8 = 1;
    const MAX_LEVEL: u8 = 254;
    const FASTEST_RATE: u8 = 50;
    const CLUSTER: Cluster<'static> = LEVEL_CONTROL_FULL_CLUSTER
        .with_revision(5)
        .with_features(level_control::Feature::ON_OFF.bits())
        .with_attrs(with!(
            required;
            AttributeId::CurrentLevel
            | AttributeId::MinLevel
            | AttributeId::MaxLevel
            | AttributeId::OnLevel
            | AttributeId::Options
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

    fn set_level(&self, level: u8) -> Option<u8> {
        // This is where business logic is implemented to physically change the level.
        info!("LevelControlHandler::set_level: setting level to {}", level);
        self.current_level.set(level);
        Some(level)
    }

    fn get_level(&self) -> Option<u8> {
        Some(self.current_level.get())
    }

    fn start_up_current_level(&self) -> Result<Nullable<u8>, Error> {
        let val = self.start_up_current_level.take();
        self.start_up_current_level.set(val.clone());
        Ok(val)
    }

    fn set_start_up_current_level(&self, value: Nullable<u8>) -> Result<(), Error> {
        self.start_up_current_level.set(value);
        Ok(())
    }
}
