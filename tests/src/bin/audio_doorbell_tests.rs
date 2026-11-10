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

//! A dedicated Matter Audio Doorbell device for ConnectedHomeIP Python integration tests.
//!
//! Implements on endpoint 1:
//! - `CameraAvStreamManagement` (0x0551) – audio-only, with a pre-seeded stream
//! - `Chime` (0x0556)
#![recursion_limit = "256"]

use core::pin::pin;

use std::net::{TcpListener, UdpSocket};

use async_signal::{Signal, Signals};

use futures_lite::StreamExt;

use rand::Rng;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::audio_av_stream::{
    AudioAvStreamConfig, AudioAvStreamHandler, AudioAvStreamHooks, AudioCapabilitiesConfig,
    AudioCodecEnum, AudioLevelConfig, AudioStream, CamAvError, TwoWayTalkSupportTypeEnum,
};
use rs_matter::dm::clusters::basic_info::{
    BasicInfoConfig, PairingHintFlags, ProductAppearance, ProductColor, ProductFinish,
};
use rs_matter::dm::clusters::decl::globals::StreamUsageEnum;
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::power_source::{self, PowerSourceConfig, PowerSourceHandler};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_AUDIO_DOORBELL, DEV_TYPE_POWER_SOURCE, DEV_TYPE_ROOT_NODE};
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, DataModel, Dataver, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::im::InteractionModel;
use rs_matter::im::InteractionModelState;
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::utils::futures::{select3, Coalesce};
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::{clusters, devices, Matter};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

#[path = "../common/args.rs"]
mod args;

#[path = "../common/logging.rs"]
mod logging;

// ---------------------------------------------------------------------------
// Audio hooks – stub
// ---------------------------------------------------------------------------

struct StubAudioHooks;

impl AudioAvStreamHooks for StubAudioHooks {
    async fn on_audio_allocated(&self, _stream: &AudioStream) -> Result<(), CamAvError> {
        Ok(())
    }

    async fn on_audio_deallocated(&self, _stream_id: u16) -> Result<(), CamAvError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Capacity constants
// ---------------------------------------------------------------------------

const AUDIO_NA: usize = 4;

type AudioAv = AudioAvStreamHandler<'static, StubAudioHooks, AUDIO_NA>;

// ---------------------------------------------------------------------------
// Static storage
// ---------------------------------------------------------------------------

static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static AUDIO_AV: StaticCell<AudioAv> = StaticCell::new();

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Error> {
    logging::init();

    let matter = MATTER.uninit().init_with(Matter::init(
        &BASIC_INFO,
        args::comm_overrides(),
        &TEST_DEV_ATT,
        args::port_override(),
    ));

    // Dump the data model as JSON for `cargo xtask pics`, then exit.
    if args::dump_pics_json(matter, &NODE)? {
        return Ok(());
    }

    let store = args::file_kv_store();

    let buffers = BUFFERS.uninit().init_with(MatterBuffers::init());

    // Create the data model state (subscriptions, events).
    let state: InteractionModelState = InteractionModelState::new();

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = matter.kv(store);

    // Re-hydrate the `Matter` instance (fabrics, basic info, RTC).
    matter.startup(&kv)?;

    let crypto = default_crypto(rand::rng(), DAC_PRIVKEY);
    let mut rand = crypto.rand()?;

    const STREAM_USAGES: &[StreamUsageEnum] = &[StreamUsageEnum::LiveView];
    const SUPPORTED_CODECS: &[AudioCodecEnum] = &[AudioCodecEnum::OPUS];
    const SAMPLE_RATES: &[u32] = &[16_000, 48_000];
    const BIT_DEPTHS: &[u8] = &[16];

    const MIC_CAPS: AudioCapabilitiesConfig<'static> = AudioCapabilitiesConfig {
        max_channels: 1,
        supported_codecs: SUPPORTED_CODECS,
        supported_sample_rates: SAMPLE_RATES,
        supported_bit_depths: BIT_DEPTHS,
    };

    const SPK_CAPS: AudioCapabilitiesConfig<'static> = AudioCapabilitiesConfig {
        max_channels: 1,
        supported_codecs: SUPPORTED_CODECS,
        supported_sample_rates: SAMPLE_RATES,
        supported_bit_depths: BIT_DEPTHS,
    };

    let audio_av = AUDIO_AV.init(AudioAvStreamHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        AudioAvStreamConfig {
            mic_capabilities: MIC_CAPS,
            speaker_capabilities: SPK_CAPS,
            max_content_buffer_size: 0,
            max_network_bandwidth: 64_000,
            two_way_talk: TwoWayTalkSupportTypeEnum::FullDuplex,
            supported_stream_usages: STREAM_USAGES,
            default_stream_usage_priorities: STREAM_USAGES,
            mic_level: AudioLevelConfig::new(0, 100, 75),
            speaker_level: AudioLevelConfig::new(0, 100, 80),
        },
        StubAudioHooks,
    ));

    let im = InteractionModel::new(
        matter,
        &crypto,
        buffers,
        data_model(matter, rand, audio_av),
        &kv,
        &state,
    );

    // Bring the Data Model to its operational state: re-hydrate its persisted
    // state and deliver the `Startup` lifecycle op to all cluster handlers.
    futures_lite::future::block_on(im.startup())?;

    let responder = DefaultResponder::new(&im);
    let mut respond = pin!(responder.run::<4, 4>());
    let mut im_job = pin!(im.run());

    let udp_socket = async_io::Async::<UdpSocket>::bind(args::bind_addr())?;
    let tcp_socket = async_io::Async::<TcpListener>::bind(args::bind_addr())?;
    let tcp = rs_matter::transport::network::tcp::TcpNetwork::<8>::new(tcp_socket);
    let (mut net_send, mut net_recv, mut net_multicast) = {
        use rs_matter::transport::network::{Address, ChainedNetwork};
        let net_send = ChainedNetwork::new(|addr: &Address| addr.is_tcp(), &tcp, &udp_socket);
        let net_recv = ChainedNetwork::new(|addr: &Address| addr.is_tcp(), &tcp, &udp_socket);
        (net_send, net_recv, &udp_socket)
    };

    let mut mdns = pin!(mdns::run_mdns(matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &mut net_send, &mut net_recv, &mut net_multicast));

    matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;

    if !matter.has_fabrics() {
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;
        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;
    }

    #[cfg(not(windows))]
    let mut term_signal = Signals::new([Signal::Term])?;
    #[cfg(windows)]
    let mut term_signal = Signals::new([Signal::Int])?;
    let mut term = pin!(async {
        term_signal.next().await;
        Ok(())
    });

    let all = select3(
        &mut transport,
        &mut mdns,
        select3(&mut respond, &mut im_job, &mut term).coalesce(),
    );

    futures_lite::future::block_on(all.coalesce())
}

// ---------------------------------------------------------------------------
// BasicInfo
// ---------------------------------------------------------------------------

const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    product_appearance: ProductAppearance {
        finish: ProductFinish::Satin,
        color: Some(ProductColor::Purple),
    },
    device_type: Some(DEV_TYPE_AUDIO_DOORBELL.dtype),
    pairing_hint: PairingHintFlags::PRESS_RESET_BUTTON,
    tcp_supported: true,
    ..TEST_DEV_DET
};

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

const POWER_SOURCE: PowerSourceConfig = PowerSourceConfig {
    description: "Mains",
    ..PowerSourceConfig::MAINS
};

const NODE: Node<'static> = Node {
    endpoints: &[
        Endpoint {
            id: endpoints::ROOT_ENDPOINT_ID,
            device_types: devices!(DEV_TYPE_ROOT_NODE, DEV_TYPE_POWER_SOURCE),
            clusters: clusters!(eth; power_source::CLUSTER),
            client_clusters: &[],
            unique_id: None,
            semantic_tags: &[],
        },
        Endpoint::new(
            1,
            devices!(DEV_TYPE_AUDIO_DOORBELL),
            clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                AudioAv::CLUSTER
            ),
        ),
    ],
};

// ---------------------------------------------------------------------------
// Handler wiring
// ---------------------------------------------------------------------------

fn data_model<'a>(
    matter: &'a Matter<'a>,
    mut rand: impl Rng + Copy,
    audio_av: &'a AudioAv,
) -> impl DataModel + 'a {
    (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&SysNetifs)
            .build(matter, rand)
            .chain(
                |e, c| e == 1 && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == groups::GroupsHandler::CLUSTER.id,
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand), matter).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == AudioAv::CLUSTER.id,
                rs_matter::dm::clusters::decl::camera_av_stream_management::HandlerAsyncAdaptor(
                    audio_av,
                ),
            )
            .chain(
                |e, c| e == endpoints::ROOT_ENDPOINT_ID && c == power_source::CLUSTER.id,
                Async(PowerSourceHandler::new(Dataver::new_rand(&mut rand), &POWER_SOURCE).adapt()),
            ),
    )
}
