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

use embassy_futures::select::select4;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use log::info;

use level_control::{
    ClusterAsyncHandler as _, MoveRequest, MoveToClosestFrequencyRequest, MoveToLevelRequest,
    MoveToLevelWithOnOffRequest, MoveWithOnOffRequest, OptionsBitmap, StepRequest,
    StepWithOnOffRequest, StopRequest, StopWithOnOffRequest,
};

use rs_matter::core::{Matter, MATTER_PORT};
use rs_matter::dm::device_types::DEV_TYPE_SMART_SPEAKER;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::objects::{
    Async, AsyncHandler, AsyncMetadata, Cluster, Dataver, EmptyHandler, Endpoint, EpClMatcher,
    InvokeContext, Node, ReadContext, WriteContext,
};
use rs_matter::dm::on_off::{ClusterHandler as _, OnOffHandler};
use rs_matter::dm::root_endpoint;
use rs_matter::dm::sdm::net_comm::NetworkType;
use rs_matter::dm::subscriptions::Subscriptions;
use rs_matter::dm::system_model::desc::{self, ClusterHandler as _};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::mdns::MdnsService;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::Psm;
use rs_matter::respond::DefaultResponder;
use rs_matter::tlv::Nullable;
use rs_matter::transport::core::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, test_device};
use rs_matter::{devices, with};

// Import the LevelControl cluster from `rs-matter`.
//
// This will auto-generate all Rust types related to the LevelControl cluster
// in a module named `level_control`.
//
// User needs to implement the `ClusterAsyncHandler` trait or the `ClusterHandler` trait
// so as to handle the requests from the controller.
rs_matter::import!(LevelControl);

#[path = "../common/mdns.rs"]
mod mdns;

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // Create the Matter object
    let matter = Matter::new_default(
        &test_device::TEST_DEV_DET,
        test_device::TEST_DEV_COMM,
        &test_device::TEST_DEV_ATT,
        MdnsService::Builtin,
        MATTER_PORT,
    );

    // Need to call this once
    matter.initialize_transport_buffers()?;

    // Create the transport buffers
    let buffers = PooledBuffers::<10, NoopRawMutex, _>::new(0);

    // Create the subscriptions
    let subscriptions = Subscriptions::<3>::new();

    // Assemble our Data Model handler by composing the predefined Root Endpoint handler with our custom Speaker handler
    let dm_handler = dm_handler(&matter);

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&matter, &buffers, &subscriptions, dm_handler);

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    let mut respond = pin!(responder.run::<4, 4>());

    // Create the Matter UDP socket
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(&matter));
    let mut transport = pin!(matter.run(&socket, &socket, DiscoveryCapabilities::IP));

    // Create, load and run the persister
    let mut psm: Psm<4096> = Psm::new();

    let dir = std::env::temp_dir().join("rs-matter");

    psm.load(&dir, &matter)?;

    let mut persist = pin!(psm.run(dir, &matter));

    // Combine all async tasks in a single one
    let all = select4(&mut transport, &mut mdns, &mut persist, &mut respond);

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all.coalesce())
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    id: 0,
    endpoints: &[
        root_endpoint::root_endpoint(NetworkType::Ethernet),
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_SMART_SPEAKER),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                OnOffHandler::CLUSTER,
                LevelControlHandler::CLUSTER
            ),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the Speaker handler.
fn dm_handler(matter: &Matter<'_>) -> impl AsyncMetadata + AsyncHandler + 'static {
    (
        NODE,
        root_endpoint::with_eth(
            &(),
            &UnixNetifs,
            matter.rand(),
            root_endpoint::with_sys(
                &false,
                matter.rand(),
                EmptyHandler
                    .chain(
                        EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                        Async(desc::DescHandler::new(Dataver::new_rand(matter.rand())).adapt()),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(LevelControlHandler::CLUSTER.id)),
                        LevelControlHandler::new(Dataver::new_rand(matter.rand())).adapt(),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(OnOffHandler::CLUSTER.id)),
                        Async(OnOffHandler::new(Dataver::new_rand(matter.rand())).adapt()),
                    ),
            ),
        ),
    )
}

/// A sample NOOP handler for the LevelControl cluster.
pub struct LevelControlHandler {
    dataver: Dataver,
    level: Cell<u8>,
}

impl LevelControlHandler {
    /// Create a new instance of the handler
    pub const fn new(dataver: Dataver) -> Self {
        Self {
            dataver,
            level: Cell::new(0),
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `AsyncHandler` trait
    pub const fn adapt(self) -> level_control::HandlerAsyncAdaptor<Self> {
        level_control::HandlerAsyncAdaptor(self)
    }

    /// Update the volume level of the handler
    fn set_level(&self, state: u8, ctx: &InvokeContext<'_>) {
        let old_state = self.level.replace(state);

        if old_state != state {
            // Update the cluster data version and notify potential subscribers
            self.dataver.changed();
            ctx.notify_changed();
        }
    }
}

impl level_control::ClusterAsyncHandler for LevelControlHandler {
    /// The metadata cluster definition corresponding to the handler
    const CLUSTER: Cluster<'static> = level_control::FULL_CLUSTER
        .with_revision(1)
        .with_attrs(with!(required))
        .with_cmds(with!(
            level_control::CommandId::MoveToLevel
                | level_control::CommandId::Move
                | level_control::CommandId::Step
                | level_control::CommandId::Stop
                | level_control::CommandId::MoveToLevelWithOnOff
                | level_control::CommandId::MoveWithOnOff
                | level_control::CommandId::StepWithOnOff
                | level_control::CommandId::StopWithOnOff
        ));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn current_level(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u8>, Error> {
        Ok(Nullable::some(self.level.get()))
    }

    async fn options(&self, _ctx: &ReadContext<'_>) -> Result<OptionsBitmap, Error> {
        Ok(OptionsBitmap::empty())
    }

    async fn set_options(
        &self,
        _ctx: &WriteContext<'_>,
        _value: OptionsBitmap,
    ) -> Result<(), Error> {
        Ok(())
    }

    async fn on_level(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u8>, Error> {
        Ok(Nullable::none())
    }

    async fn set_on_level(
        &self,
        _ctx: &WriteContext<'_>,
        _value: Nullable<u8>,
    ) -> Result<(), Error> {
        Ok(())
    }

    async fn handle_move_to_level(
        &self,
        ctx: &InvokeContext<'_>,
        request: MoveToLevelRequest<'_>,
    ) -> Result<(), Error> {
        info!("Moving to level: {}", request.level()?);

        self.set_level(request.level()?, ctx);

        Ok(())
    }

    async fn handle_move(
        &self,
        _ctx: &InvokeContext<'_>,
        request: MoveRequest<'_>,
    ) -> Result<(), Error> {
        info!(
            "Moving {:?} with rate: {:?}",
            request.move_mode()?,
            request.rate()?
        );

        Ok(())
    }

    async fn handle_step(
        &self,
        _ctx: &InvokeContext<'_>,
        request: StepRequest<'_>,
    ) -> Result<(), Error> {
        info!(
            "Stepping {:?} with step size: {} and transition time: {:?}",
            request.step_mode()?,
            request.step_size()?,
            request.transition_time()?
        );

        Ok(())
    }

    async fn handle_stop(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: StopRequest<'_>,
    ) -> Result<(), Error> {
        info!("Stopping");

        Ok(())
    }

    async fn handle_move_to_level_with_on_off(
        &self,
        ctx: &InvokeContext<'_>,
        request: MoveToLevelWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("Moving to level with on/off: {}", request.level()?);

        self.set_level(request.level()?, ctx);

        Ok(())
    }

    async fn handle_move_with_on_off(
        &self,
        _ctx: &InvokeContext<'_>,
        request: MoveWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!(
            "Moving with on/off: {:?} with rate: {:?}",
            request.move_mode()?,
            request.rate()?
        );

        Ok(())
    }

    async fn handle_step_with_on_off(
        &self,
        _ctx: &InvokeContext<'_>,
        request: StepWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!(
            "Stepping with on/off: {:?} with step size: {} and transition time: {:?}",
            request.step_mode()?,
            request.step_size()?,
            request.transition_time()?
        );

        Ok(())
    }

    async fn handle_stop_with_on_off(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: StopWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("Stopping with on/off");

        Ok(())
    }

    async fn handle_move_to_closest_frequency(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: MoveToClosestFrequencyRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }
}
