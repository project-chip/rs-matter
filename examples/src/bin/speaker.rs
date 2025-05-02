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

//! An example Matter device that implements the MediaPlayback cluster over Ethernet.
//! Demonstrates how to make use of the `rs_matter::import` macro.

use core::cell::Cell;
use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::select4;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use media_playback::{
    ActivateAudioTrackRequest, ActivateTextTrackRequest, ClusterAsyncHandler as _,
    FastForwardRequest, PlaybackResponseBuilder, PlaybackStateEnum, RewindRequest, SeekRequest,
    SkipBackwardRequest, SkipForwardRequest, StatusEnum,
};

use rs_matter::core::{Matter, MATTER_PORT};
use rs_matter::data_model::device_types::DEV_TYPE_SMART_SPEAKER;
use rs_matter::data_model::objects::{InvokeContext, ReadContext, *};
use rs_matter::data_model::root_endpoint;
use rs_matter::data_model::subscriptions::Subscriptions;
use rs_matter::data_model::system_model::descriptor;
use rs_matter::error::{Error, ErrorCode};
use rs_matter::mdns::MdnsService;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::Psm;
use rs_matter::respond::DefaultResponder;
use rs_matter::test_device;
use rs_matter::tlv::TLVBuilderParent;
use rs_matter::transport::core::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::with;

// Import the MediaPlayback cluster from `rs-matter`.
//
// This will auto-generate all Rust types related to the MediaPlayback cluster
// in a module named `media_playback`.
//
// User needs to implement the `ClusterAsyncHandler` trait or the `ClusterHandler` trait
// so as to handle the requests from the controller.
rs_matter::import!(MediaPlayback);

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
        root_endpoint::endpoint(0, root_endpoint::OperNwType::Ethernet),
        Endpoint {
            id: 1,
            device_types: &[DEV_TYPE_SMART_SPEAKER],
            clusters: &[descriptor::CLUSTER, SpeakerHandler::CLUSTER],
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the Speaker handler and its descriptor.
fn dm_handler<'a>(matter: &Matter<'_>) -> impl AsyncMetadata + AsyncHandler + 'a {
    (
        NODE,
        root_endpoint::eth_handler(0, matter.rand())
            .chain(
                1,
                descriptor::ID,
                Async(descriptor::DescriptorCluster::new(Dataver::new_rand(
                    matter.rand(),
                ))),
            )
            .chain(
                1,
                SpeakerHandler::CLUSTER.id,
                media_playback::HandlerAsyncAdaptor(SpeakerHandler::new(Dataver::new_rand(
                    matter.rand(),
                ))),
            ),
    )
}

/// A sample NOOP handler for the MediaPlayback cluster.
pub struct SpeakerHandler {
    dataver: Dataver,
    state: Cell<media_playback::PlaybackStateEnum>,
}

impl SpeakerHandler {
    pub const fn new(dataver: Dataver) -> Self {
        Self {
            dataver,
            state: Cell::new(media_playback::PlaybackStateEnum::NotPlaying),
        }
    }
}

impl media_playback::ClusterAsyncHandler for SpeakerHandler {
    /// The metadata cluster definition corresponding to the handler
    const CLUSTER: Cluster<'static> = media_playback::FULL_CLUSTER
        .with_revision(1)
        .with_attrs(with!(required))
        .with_cmds(with!(
            media_playback::CommandId::Play
                | media_playback::CommandId::Pause
                | media_playback::CommandId::Stop
        ));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn current_state(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<media_playback::PlaybackStateEnum, Error> {
        Ok(self.state.get())
    }

    async fn handle_play<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        response: media_playback::PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        self.state.set(PlaybackStateEnum::Playing);

        response.status(StatusEnum::Success)?.data(None)?.end()
    }

    async fn handle_pause<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        self.state.set(PlaybackStateEnum::Paused);

        response.status(StatusEnum::Success)?.data(None)?.end()
    }

    async fn handle_stop<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        self.state.set(PlaybackStateEnum::NotPlaying);

        response.status(StatusEnum::Success)?.data(None)?.end()
    }

    async fn handle_start_over<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_previous<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_next<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_rewind<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: RewindRequest<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_fast_forward<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: FastForwardRequest<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_skip_forward<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: SkipForwardRequest<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_skip_backward<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: SkipBackwardRequest<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_seek<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: SeekRequest<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_activate_audio_track(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: ActivateAudioTrackRequest<'_>,
    ) -> Result<(), Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_activate_text_track(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: ActivateTextTrackRequest<'_>,
    ) -> Result<(), Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_deactivate_text_track(&self, _ctx: &InvokeContext<'_>) -> Result<(), Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }
}
