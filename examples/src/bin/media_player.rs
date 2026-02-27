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

//! An example Matter device that implements a MediaPlayback device over Ethernet.
//! Demonstrates how to make use of the `rs_matter::import` macro.
//!
//! Note that - unfortunately - the `ContentLauncher` (and `KeypadInput`) clusters
//! don't seem to be supported by the Google / Apple / Alexa controllers yet,
//! so launching videos - Chromecast style - would not work.

use core::cell::Cell;
use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::{select, select4};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use log::info;

use rand::RngCore;
use rs_matter::crypto::{default_crypto, Crypto};
// Import the MediaPlayback, ContentLauncher and KeypadInput clusters from `rs-matter`.
//
// User needs to implement the `ClusterAsyncHandler` trait or the `ClusterHandler` trait
// so as to handle the requests from the controller.
use rs_matter::dm::clusters::decl::content_launcher::{
    self, ClusterAsyncHandler as _, LaunchContentRequest, LaunchURLRequest,
    LauncherResponseBuilder, SupportedProtocolsBitmap,
};

use rs_matter::dm::clusters::decl::keypad_input::{
    self, ClusterAsyncHandler as _, SendKeyRequest, SendKeyResponseBuilder,
};

use rs_matter::dm::clusters::decl::media_playback::{
    self, ActivateAudioTrackRequest, ActivateTextTrackRequest, ClusterAsyncHandler as _,
    FastForwardRequest, PlaybackResponseBuilder, PlaybackStateEnum, RewindRequest, SeekRequest,
    SkipBackwardRequest, SkipForwardRequest, StatusEnum,
};

use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::level_control::LevelControlHooks;
use rs_matter::dm::clusters::net_comm::NetworkType;
use rs_matter::dm::clusters::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_CASTING_VIDEO_PLAYER;
use rs_matter::dm::endpoints;
use rs_matter::dm::events::DefaultEvents;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::subscriptions::DefaultSubscriptions;
use rs_matter::dm::{
    ArrayAttributeRead, Async, AsyncHandler, AsyncMetadata, Cluster, DataModel, Dataver,
    EmptyHandler, Endpoint, EpClMatcher, InvokeContext, Node, ReadContext,
};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::group_keys::GroupStoreImpl;
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{Psm, NO_NETWORKS};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::tlv::{TLVBuilderParent, Utf8StrArrayBuilder, Utf8StrBuilder};
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
    let mut matter = Matter::new_default(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    // Configure the group store for groupcast support
    let group_store = Box::leak(Box::new(GroupStoreImpl::<2>::new())); // 1 endpoint + root endpoint
    matter.set_group_store(group_store);

    // Need to call this once
    matter.initialize_transport_buffers()?;

    // Create the transport buffers
    let buffers = PooledBuffers::<10, NoopRawMutex, _>::new(0);

    // Create the subscriptions
    let subscriptions = DefaultSubscriptions::new();

    // Create the crypto instance
    let crypto = default_crypto::<NoopRawMutex, _>(rand::thread_rng(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // Create the event queue
    let events = DefaultEvents::new_default();

    // Assemble our Data Model handler by composing the predefined Root Endpoint handler with our custom Speaker handler
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(false),
    );

    // Create the Data Model instance
    let dm = DataModel::new(
        &matter,
        &crypto,
        &buffers,
        &subscriptions,
        Some(&events),
        dm_handler(rand, &on_off_handler),
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
    let mut mdns = pin!(mdns::run_mdns(&matter, &crypto, &dm));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket, Some(&socket)));

    // Create, load and run the persister
    let mut psm: Psm<4096> = Psm::new();
    let path = std::env::temp_dir().join("rs-matter");

    psm.load(&path, &matter, NO_NETWORKS, Some(&events))?;

    if !matter.is_commissioned() {
        // If the device is not commissioned yet, print the QR text and code to the console
        // and enable basic commissioning

        matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &dm)?;
    }

    let mut persist = pin!(psm.run(&path, &matter, NO_NETWORKS, Some(&events)));

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
            device_types: devices!(DEV_TYPE_CASTING_VIDEO_PLAYER),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                MediaHandler::CLUSTER,
                ContentHandler::CLUSTER,
                KeypadInputHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER
            ),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the Media Player cluster handlers.
fn dm_handler<'a, OH: OnOffHooks, LH: LevelControlHooks>(
    mut rand: impl RngCore + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
) -> impl AsyncMetadata + AsyncHandler + 'a {
    (
        NODE,
        endpoints::with_eth(
            &(),
            &UnixNetifs,
            rand,
            endpoints::with_sys(
                &false,
                rand,
                EmptyHandler
                    .chain(
                        EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                        Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(MediaHandler::CLUSTER.id)),
                        MediaHandler::new(Dataver::new_rand(&mut rand)).adapt(),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(ContentHandler::CLUSTER.id)),
                        ContentHandler::new(Dataver::new_rand(&mut rand)).adapt(),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(KeypadInputHandler::CLUSTER.id)),
                        KeypadInputHandler::new(Dataver::new_rand(&mut rand)).adapt(),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                        on_off::HandlerAsyncAdaptor(on_off),
                    ),
            ),
        ),
    )
}

/// A sample NOOP handler for the MediaPlayback cluster.
pub struct MediaHandler {
    dataver: Dataver,
    state: Cell<media_playback::PlaybackStateEnum>,
}

impl MediaHandler {
    /// Create a new instance of the handler
    pub const fn new(dataver: Dataver) -> Self {
        Self {
            dataver,
            state: Cell::new(media_playback::PlaybackStateEnum::NotPlaying),
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `AsyncHandler` trait
    pub const fn adapt(self) -> media_playback::HandlerAsyncAdaptor<Self> {
        media_playback::HandlerAsyncAdaptor(self)
    }

    /// Update the state of the handler
    fn set_state(&self, state: PlaybackStateEnum, ctx: impl InvokeContext) {
        let old_state = self.state.replace(state);

        if old_state != state {
            // Update the cluster data version and notify potential subscribers
            self.dataver.changed();
            ctx.notify_changed();
        }
    }
}

impl media_playback::ClusterAsyncHandler for MediaHandler {
    /// The metadata cluster definition corresponding to the handler
    const CLUSTER: Cluster<'static> = media_playback::FULL_CLUSTER
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
        _ctx: impl ReadContext,
    ) -> Result<media_playback::PlaybackStateEnum, Error> {
        Ok(self.state.get())
    }

    async fn handle_play<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        response: media_playback::PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!("Playback started");

        self.set_state(PlaybackStateEnum::Playing, ctx);

        response.status(StatusEnum::Success)?.data(None)?.end()
    }

    async fn handle_pause<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!("Playback paused");

        self.set_state(PlaybackStateEnum::Paused, ctx);

        response.status(StatusEnum::Success)?.data(None)?.end()
    }

    async fn handle_stop<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!("Playback stopped");

        self.set_state(PlaybackStateEnum::NotPlaying, ctx);

        response.status(StatusEnum::Success)?.data(None)?.end()
    }

    async fn handle_start_over<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_previous<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_next<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_rewind<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: RewindRequest<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_fast_forward<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: FastForwardRequest<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_skip_forward<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: SkipForwardRequest<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_skip_backward<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: SkipBackwardRequest<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_seek<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: SeekRequest<'_>,
        _response: PlaybackResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_activate_audio_track(
        &self,
        _ctx: impl InvokeContext,
        _request: ActivateAudioTrackRequest<'_>,
    ) -> Result<(), Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_activate_text_track(
        &self,
        _ctx: impl InvokeContext,
        _request: ActivateTextTrackRequest<'_>,
    ) -> Result<(), Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }

    async fn handle_deactivate_text_track(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        // Not supported
        Err(ErrorCode::InvalidCommand.into())
    }
}

#[derive(Clone, Debug)]
pub struct ContentHandler {
    dataver: Dataver,
}

impl ContentHandler {
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    /// Adapt the handler instance to the generic `rs-matter` `AsyncHandler` trait
    pub const fn adapt(self) -> content_launcher::HandlerAsyncAdaptor<Self> {
        content_launcher::HandlerAsyncAdaptor(self)
    }
}

impl content_launcher::ClusterAsyncHandler for ContentHandler {
    const CLUSTER: Cluster<'static> = content_launcher::FULL_CLUSTER
        .with_features(0b11)
        .with_attrs(
            with!(required; content_launcher::AttributeId::AcceptHeader | content_launcher::AttributeId::SupportedStreamingProtocols),
        )
        .with_cmds(with!(content_launcher::CommandId::LaunchURL | content_launcher::CommandId::LaunchContent));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn accept_header<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<Utf8StrArrayBuilder<P>, Utf8StrBuilder<P>>,
    ) -> Result<P, Error> {
        const RANDOM_MEDIA_HEADERS: &[&str] = &[
            "audio/mpeg",
            "audio/aac",
            "audio/ogg",
            "video/mp4",
            "video/webm",
            "video/ogg",
            "video/x-matroska",
            "video/x-msvideo",
            "video/x-flv",
            "application/x-mpegURL",
            "application/dash+xml",
            "application/vnd.apple.mpegurl",
            "application/x-matroska",
        ];

        // TODO
        match builder {
            ArrayAttributeRead::ReadAll(mut builder) => {
                for header in RANDOM_MEDIA_HEADERS {
                    builder = builder.push(header)?;
                }

                builder.end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let index = index as usize;

                if index >= RANDOM_MEDIA_HEADERS.len() {
                    return Err(ErrorCode::ConstraintError.into());
                }

                builder.set(RANDOM_MEDIA_HEADERS[index])
            }
            ArrayAttributeRead::ReadNone(builder) => builder.end(),
        }
    }

    async fn supported_streaming_protocols(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<SupportedProtocolsBitmap, Error> {
        Ok(SupportedProtocolsBitmap::all())
    }

    async fn handle_launch_url<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        request: LaunchURLRequest<'_>,
        response: LauncherResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!("Launching URL: {}", request.content_url()?);

        response
            .status(content_launcher::StatusEnum::Success)?
            .data(None)?
            .end()
    }

    async fn handle_launch_content<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        request: LaunchContentRequest<'_>,
        response: LauncherResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!("Launching content: {:?}", request.data()?);

        response
            .status(content_launcher::StatusEnum::Success)?
            .data(None)?
            .end()
    }
}

#[derive(Clone, Debug)]
pub struct KeypadInputHandler {
    dataver: Dataver,
}

impl KeypadInputHandler {
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    /// Adapt the handler instance to the generic `rs-matter` `AsyncHandler` trait
    pub const fn adapt(self) -> keypad_input::HandlerAsyncAdaptor<Self> {
        keypad_input::HandlerAsyncAdaptor(self)
    }
}

impl keypad_input::ClusterAsyncHandler for KeypadInputHandler {
    const CLUSTER: Cluster<'static> = keypad_input::FULL_CLUSTER
        .with_attrs(with!(required))
        .with_cmds(with!(keypad_input::CommandId::SendKey));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn handle_send_key<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        request: SendKeyRequest<'_>,
        response: SendKeyResponseBuilder<P>,
    ) -> Result<P, Error> {
        info!(
            "KeypadInputHandler: Received SendKey command {:?}",
            request.key_code()?
        );

        response
            .status(keypad_input::StatusEnum::UnsupportedKey)?
            .end()
    }
}
