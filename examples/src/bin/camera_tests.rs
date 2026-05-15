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

//! A dedicated Matter Camera device for ConnectedHomeIP Python integration tests.
//!
//! Implements on endpoint 1:
//! - `CameraAvStreamManagement` (0x0560) – video-only, with a pre-seeded stream
//! - `CameraAvSettingsUserLevelManagement` (0x0561) – DPTZ only
//! - `ZoneManagement` (0x0550)
//! - `PushAvStreamTransport` (0x0555)
//! - `WebRTCTransportProvider` (0x0553) – stub (no real ICE/DTLS)
//! - `Chime` (0x0556)

use core::pin::pin;

use std::net::{TcpListener, UdpSocket};

use async_signal::{Signal, Signals};

use embassy_futures::select::select3;

use futures_lite::StreamExt;

use log::info;

use rand::RngCore;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::cam_av_settings::{
    CamAvSettingsConfig, CamAvSettingsHandler, CamAvSettingsHooks, DptzView, CLUSTER_DPTZ_ONLY,
};
use rs_matter::dm::clusters::app::cam_av_stream::{
    AudioCapabilitiesConfig, AudioCodecEnum, AudioStream, CamAvError, CameraAvStreamConfig,
    CameraAvStreamHandler, CameraAvStreamHooks, RateDistortionPoint, StreamUsageEnum,
    VideoCodecEnum, VideoSensorParams, VideoStream,
};
use rs_matter::dm::clusters::app::push_av_stream::{
    AllocatePushTransportRequest, ContainerFormatEnum, IngestMethodsEnum, PushAvError,
    PushAvStreamConfig, PushAvStreamHandler, PushAvStreamHooks, SupportedFormat,
};
use rs_matter::dm::clusters::app::webrtc_prov::{
    AnswerOutcome, HandlerAsyncAdaptor as WebRtcAdaptor, OfferParams, SolicitOutcome, WebRtcError,
    WebRtcHooks, WebRtcProvHandler,
};
use rs_matter::dm::clusters::app::zone_mgmt::{
    HandlerAsyncAdaptor as ZoneMgmtAdaptor, ZoneMgmtConfig, ZoneMgmtHandler, ZoneMgmtHooks,
};
use rs_matter::dm::clusters::basic_info::{
    BasicInfoConfig, ColorEnum, PairingHintFlags, ProductAppearance, ProductFinishEnum,
};
use rs_matter::dm::clusters::decl::chime::{
    self as chime_decl, ChimeSoundStructArrayBuilder, ClusterHandler as ChimeClusterHandler,
    HandlerAdaptor as ChimeHandlerAdaptor, PlayChimeSoundRequest,
};
use rs_matter::dm::clusters::decl::globals::ICECandidateStruct;
use rs_matter::dm::clusters::decl::globals::WebRTCEndReasonEnum;
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::SharedNetworks;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::events::NoEvents;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::subscriptions::Subscriptions;
use rs_matter::dm::{endpoints, DataModel};
use rs_matter::dm::{
    ArrayAttributeRead, Async, DataModelHandler, Dataver, DeviceType, EmptyHandler, Endpoint,
    EpClMatcher, InvokeContext, Node, ReadContext, WriteContext,
};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::im::FabricIndex;
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{FileKvBlobStore, SharedKvBlobStore};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::tlv::{TLVArray, TLVBuilderParent};
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

// ---------------------------------------------------------------------------
// Device type
// ---------------------------------------------------------------------------

const DEV_TYPE_MATTER_CAMERA: DeviceType = DeviceType {
    dtype: 0x0142,
    drev: 1,
};

// ---------------------------------------------------------------------------
// CameraAvStream hooks – stub
// ---------------------------------------------------------------------------

struct StubCamHooks {
    cam_av_settings: &'static CamAvSettingsHandler<
        StubCamAvSettingsHooks,
        CAM_AV_SETTINGS_NP,
        CAM_AV_SETTINGS_NS,
    >,
}

impl CameraAvStreamHooks for StubCamHooks {
    async fn allocate_video(&self, stream: &VideoStream) -> Result<(), CamAvError> {
        let view = DptzView {
            video_stream_id: stream.video_stream_id,
            x1: 0,
            y1: 0,
            x2: 1920,
            y2: 1080,
        };
        self.cam_av_settings.add_preallocated_dptz(view).ok();
        Ok(())
    }

    async fn modify_video(
        &self,
        _id: u16,
        _watermark: Option<bool>,
        _osd: Option<bool>,
    ) -> Result<(), CamAvError> {
        Ok(())
    }

    async fn deallocate_video(&self, id: u16) -> Result<(), CamAvError> {
        self.cam_av_settings.remove_dptz_stream(id).ok();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CamAvSettings hooks – stub (all methods have defaults, empty impl is enough)
// ---------------------------------------------------------------------------

struct StubCamAvSettingsHooks;

impl CamAvSettingsHooks for StubCamAvSettingsHooks {}

// ---------------------------------------------------------------------------
// ZoneMgmt hooks – stub (all methods have defaults)
// ---------------------------------------------------------------------------

struct StubZoneHooks;

impl<const NV: usize> ZoneMgmtHooks<NV> for StubZoneHooks {}

// ---------------------------------------------------------------------------
// PushAvStream hooks – stub
// ---------------------------------------------------------------------------

struct StubPushHooks;

impl PushAvStreamHooks for StubPushHooks {
    async fn on_allocate(
        &self,
        _connection_id: u16,
        _fabric_index: FabricIndex,
        _request: &AllocatePushTransportRequest<'_>,
    ) -> Result<(), PushAvError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WebRTC hooks – validates stream IDs for TC_WEBRTCP_2_1
// ---------------------------------------------------------------------------

struct StubWebRtcHooks {
    cam_av: &'static CameraAvStreamHandler<'static, StubCamHooks, CAM_AV_NV, CAM_AV_NA>,
}

impl WebRtcHooks for StubWebRtcHooks {
    async fn on_solicit_offer(
        &self,
        _session_id: u16,
        params: &OfferParams,
    ) -> Result<SolicitOutcome, WebRtcError> {
        // Both absent → InvalidCommand (TC_WEBRTCP_2_1 step 2)
        if params.video_stream_id.is_none() && params.audio_stream_id.is_none() {
            return Err(WebRtcError::InvalidCommand);
        }
        // Concrete video stream ID that doesn't exist → DynamicConstraint (step 3)
        if let Some(Some(vid)) = params.video_stream_id {
            let found = self
                .cam_av
                .video_streams()
                .iter()
                .any(|s| s.video_stream_id == vid);
            if !found {
                return Err(WebRtcError::DynamicConstraint);
            }
        }
        // Concrete audio stream ID that doesn't exist → DynamicConstraint (step 4)
        if let Some(Some(aid)) = params.audio_stream_id {
            let found = self
                .cam_av
                .audio_streams()
                .iter()
                .any(|s| s.audio_stream_id == aid);
            if !found {
                return Err(WebRtcError::DynamicConstraint);
            }
        }
        // NullValue for both → deferred offer (step 6)
        Ok(SolicitOutcome {
            deferred: true,
            video_stream_id: None,
            audio_stream_id: None,
        })
    }

    async fn on_offer(
        &self,
        _session_id: u16,
        _sdp: &str,
        _params: &OfferParams,
    ) -> Result<AnswerOutcome, WebRtcError> {
        Err(WebRtcError::InvalidInState)
    }

    async fn on_answer(&self, _session_id: u16, _sdp: &str) -> Result<(), WebRtcError> {
        Err(WebRtcError::InvalidInState)
    }

    async fn on_ice_candidates(
        &self,
        _session_id: u16,
        _candidates: &TLVArray<'_, ICECandidateStruct<'_>>,
    ) -> Result<(), WebRtcError> {
        Err(WebRtcError::InvalidInState)
    }

    async fn on_end_session(
        &self,
        _session_id: u16,
        _reason: WebRTCEndReasonEnum,
    ) -> Result<(), WebRtcError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Chime handler – one built-in chime sound
// ---------------------------------------------------------------------------

struct ChimeHandler {
    dataver: Dataver,
    selected: u8,
    enabled: bool,
}

impl ChimeHandler {
    const fn new(dataver: Dataver) -> Self {
        Self {
            dataver,
            selected: 0,
            enabled: true,
        }
    }
}

impl ChimeClusterHandler for ChimeHandler {
    const CLUSTER: rs_matter::dm::Cluster<'static> = chime_decl::FULL_CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn installed_chime_sounds<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            ChimeSoundStructArrayBuilder<P>,
            chime_decl::ChimeSoundStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(b) => {
                let item_b = b.push()?;
                item_b.chime_id(0)?.name("Default")?.end()?.end()
            }
            ArrayAttributeRead::ReadOne(idx, b) => {
                if idx != 0 {
                    return Err(ErrorCode::ConstraintError.into());
                }
                b.chime_id(0)?.name("Default")?.end()
            }
            ArrayAttributeRead::ReadNone(b) => b.end(),
        }
    }

    fn selected_chime(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.selected)
    }

    fn enabled(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        Ok(self.enabled)
    }

    fn set_selected_chime(&self, _ctx: impl WriteContext, _value: u8) -> Result<(), Error> {
        // Read-only in stub; spec allows writes but we treat as no-op
        Ok(())
    }

    fn set_enabled(&self, _ctx: impl WriteContext, _value: bool) -> Result<(), Error> {
        Ok(())
    }

    fn handle_play_chime_sound(
        &self,
        _ctx: impl InvokeContext,
        _request: PlayChimeSoundRequest<'_>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Capacity constants
// ---------------------------------------------------------------------------

const CAM_AV_NV: usize = 4;
const CAM_AV_NA: usize = 4;

const CAM_AV_SETTINGS_NP: usize = 0;
const CAM_AV_SETTINGS_NS: usize = 2;

const ZONE_NZ: usize = 5;
const ZONE_NV: usize = 8;
const ZONE_NT: usize = 4;

const PUSH_NC: usize = 4;

const N_SESSIONS: usize = 4;
const SDP_LEN: usize = 8 * 1024;
const OUT_LEN: usize = SDP_LEN + 1024;
// Per-invoke ICE candidate snapshot bounds — see `webrtc_camera.rs` for
// the rationale. The stub hook doesn't actually emit candidates, but
// `WebRtcProvHandler` still needs the const generics to compile.
const CAND_LEN: usize = 256;
const MAX_CAND: usize = 16;

type CamAv = CameraAvStreamHandler<'static, StubCamHooks, CAM_AV_NV, CAM_AV_NA>;
type WebRtc = WebRtcProvHandler<StubWebRtcHooks, N_SESSIONS, SDP_LEN, OUT_LEN, CAND_LEN, MAX_CAND>;

// ---------------------------------------------------------------------------
// Static storage
// ---------------------------------------------------------------------------

static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<PooledBuffers<10, rs_matter::dm::IMBuffer>> = StaticCell::new();
static SUBSCRIPTIONS: StaticCell<Subscriptions> = StaticCell::new();
static KV_BUF: StaticCell<[u8; 4096]> = StaticCell::new();
static WEBRTC: StaticCell<WebRtc> = StaticCell::new();
static CAM_AV: StaticCell<CamAv> = StaticCell::new();
static CAM_AV_SETTINGS: StaticCell<
    CamAvSettingsHandler<StubCamAvSettingsHooks, CAM_AV_SETTINGS_NP, CAM_AV_SETTINGS_NS>,
> = StaticCell::new();
static ZONE_MGMT: StaticCell<ZoneMgmtHandler<StubZoneHooks, ZONE_NZ, ZONE_NV, ZONE_NT>> =
    StaticCell::new();
static PUSH_AV: StaticCell<PushAvStreamHandler<'static, StubPushHooks, PUSH_NC>> =
    StaticCell::new();

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Error> {
    std::env::set_var("RUST_BACKTRACE", "1");

    env_logger::builder()
        .format(|buf, record| {
            use std::io::Write;
            writeln!(buf, "{}: {}", record.level(), record.args())
        })
        .target(env_logger::Target::Stdout)
        .filter_level(::log::LevelFilter::Debug)
        .init();

    let matter = MATTER.uninit().init_with(Matter::init(
        &BASIC_INFO,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        rs_matter::utils::epoch::sys_epoch,
        MATTER_PORT,
    ));

    let kv_buf = KV_BUF.uninit().init_zeroed().as_mut_slice();
    let mut kv = FileKvBlobStore::new_default();
    futures_lite::future::block_on(matter.load_persist(&mut kv, kv_buf))?;

    let buffers = BUFFERS.uninit().init_with(PooledBuffers::init(0));
    let subscriptions = SUBSCRIPTIONS.uninit().init_with(Subscriptions::init());

    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);
    let mut rand = crypto.rand()?;

    const CAM_AV_STREAM_USAGES: &[StreamUsageEnum] = &[StreamUsageEnum::LiveView];
    const CAM_AV_RATE_DISTORTION: &[RateDistortionPoint] = &[RateDistortionPoint {
        codec: VideoCodecEnum::H264,
        min_resolution: (640, 360),
        min_bit_rate: 500_000,
    }];

    let cam_av_settings = CAM_AV_SETTINGS.init(CamAvSettingsHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        CLUSTER_DPTZ_ONLY,
        CamAvSettingsConfig {
            pan_range: (0, 0),
            tilt_range: (0, 0),
            zoom_max: 1,
            default_position: rs_matter::dm::clusters::app::cam_av_settings::Mptz {
                pan: None,
                tilt: None,
                zoom: None,
            },
            max_presets: 0,
        },
        StubCamAvSettingsHooks,
    ));

    const CAM_AV_SUPPORTED_CODECS: &[AudioCodecEnum] = &[AudioCodecEnum::OPUS];
    const CAM_AV_SAMPLE_RATES: &[u32] = &[48_000];
    const CAM_AV_BIT_DEPTHS: &[u8] = &[16];

    let cam_av = CAM_AV.init(CameraAvStreamHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        CameraAvStreamConfig {
            max_concurrent_encoders: 1,
            max_encoded_pixel_rate: 1920 * 1080 * 30,
            sensor: VideoSensorParams {
                sensor_width: 1920,
                sensor_height: 1080,
                max_fps: 30,
                max_hdrfps: None,
            },
            min_viewport: (640, 360),
            max_content_buffer_size: 1_048_576,
            max_network_bandwidth: 10_000,
            supported_stream_usages: CAM_AV_STREAM_USAGES,
            default_stream_usage_priorities: CAM_AV_STREAM_USAGES,
            rate_distortion_points: CAM_AV_RATE_DISTORTION,
            mic_capabilities: Some(AudioCapabilitiesConfig {
                max_channels: 1,
                supported_codecs: CAM_AV_SUPPORTED_CODECS,
                supported_sample_rates: CAM_AV_SAMPLE_RATES,
                supported_bit_depths: CAM_AV_BIT_DEPTHS,
            }),
        },
        rs_matter::dm::clusters::app::cam_av_stream::Feature::VIDEO.bits()
            | rs_matter::dm::clusters::app::cam_av_stream::Feature::AUDIO.bits(),
        StubCamHooks { cam_av_settings },
    ));

    let video_stream_id = cam_av
        .add_preallocated_video(VideoStream {
            video_stream_id: 0,
            stream_usage: StreamUsageEnum::LiveView,
            video_codec: VideoCodecEnum::H264,
            min_frame_rate: 1,
            max_frame_rate: 30,
            min_width: 640,
            min_height: 360,
            max_width: 1920,
            max_height: 1080,
            min_bit_rate: 500_000,
            max_bit_rate: 4_000_000,
            key_frame_interval: 2000,
            watermark_enabled: None,
            osd_enabled: None,
            reference_count: 0,
        })
        .ok();
    if let Some(id) = video_stream_id {
        cam_av_settings
            .add_preallocated_dptz(DptzView {
                video_stream_id: id,
                x1: 0,
                y1: 0,
                x2: 1920,
                y2: 1080,
            })
            .ok();
    }

    cam_av
        .add_preallocated_audio(AudioStream {
            audio_stream_id: 0,
            stream_usage: StreamUsageEnum::LiveView,
            audio_codec: AudioCodecEnum::OPUS,
            channel_count: 1,
            sample_rate: 48_000,
            bit_rate: 64_000,
            bit_depth: 16,
            reference_count: 0,
        })
        .ok();

    let webrtc = WEBRTC.init(WebRtcProvHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        StubWebRtcHooks { cam_av },
    ));

    let zone_mgmt = ZONE_MGMT.init(ZoneMgmtHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        ZoneMgmtConfig {
            max_zones: ZONE_NZ as u8,
            max_user_defined_zones: ZONE_NZ as u8,
            sensitivity_max: 10,
            default_sensitivity: 5,
            two_d_cartesian_max: (1919, 1079),
        },
        rs_matter::dm::clusters::app::zone_mgmt::Feature::TWO_DIMENSIONAL_CARTESIAN_ZONE.bits()
            | rs_matter::dm::clusters::app::zone_mgmt::Feature::USER_DEFINED.bits(),
        StubZoneHooks,
    ));

    const PUSH_FORMATS: &[SupportedFormat] = &[SupportedFormat {
        container_format: ContainerFormatEnum::CMAF,
        ingest_method: IngestMethodsEnum::CMAFIngest,
    }];

    let push_av = PUSH_AV.init(PushAvStreamHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        PushAvStreamConfig {
            supported_formats: PUSH_FORMATS,
        },
        StubPushHooks,
    ));

    let chime = ChimeHandler::new(Dataver::new_rand(&mut rand));

    info!(
        "Matter memory: Matter (BSS)={}B, IM Buffers (BSS)={}B",
        core::mem::size_of::<Matter>(),
        core::mem::size_of::<PooledBuffers<10, rs_matter::dm::IMBuffer>>(),
    );

    let events = NoEvents::new_default();
    let dm = DataModel::new(
        matter,
        &crypto,
        buffers,
        subscriptions,
        &events,
        dm_handler(
            rand,
            webrtc,
            cam_av,
            cam_av_settings,
            zone_mgmt,
            push_av,
            chime,
        ),
        SharedKvBlobStore::new(kv, kv_buf),
        SharedNetworks::new(EthNetwork::new_default()),
    );

    let responder = DefaultResponder::new(&dm);
    let mut respond = pin!(responder.run::<4, 4>());
    let mut dm_job = pin!(dm.run());

    let udp_socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;
    let tcp_socket = async_io::Async::<TcpListener>::bind(MATTER_SOCKET_BIND_ADDR)?;
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

    if !matter.is_commissioned() {
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
        select3(&mut respond, &mut dm_job, &mut term).coalesce(),
    );

    futures_lite::future::block_on(all.coalesce())
}

// ---------------------------------------------------------------------------
// BasicInfo
// ---------------------------------------------------------------------------

const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    product_appearance: ProductAppearance {
        finish: ProductFinishEnum::Satin,
        color: Some(ColorEnum::Purple),
    },
    device_type: Some(DEV_TYPE_MATTER_CAMERA.dtype),
    pairing_hint: PairingHintFlags::PRESS_RESET_BUTTON,
    tcp_supported: true,
    ..TEST_DEV_DET
};

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_MATTER_CAMERA),
            clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                CamAv::CLUSTER_VIDEO_AUDIO,
                CLUSTER_DPTZ_ONLY,
                ZoneMgmtHandler::<StubZoneHooks, ZONE_NZ, ZONE_NV, ZONE_NT>::CLUSTER,
                PushAvStreamHandler::<StubPushHooks, PUSH_NC>::CLUSTER,
                WebRtc::CLUSTER,
                chime_decl::FULL_CLUSTER
            ),
        ),
    ],
};

// ---------------------------------------------------------------------------
// Handler wiring
// ---------------------------------------------------------------------------

fn dm_handler<'a>(
    mut rand: impl RngCore + Copy,
    webrtc: &'a WebRtc,
    cam_av: &'a CamAv,
    cam_av_settings: &'a CamAvSettingsHandler<
        StubCamAvSettingsHooks,
        CAM_AV_SETTINGS_NP,
        CAM_AV_SETTINGS_NS,
    >,
    zone_mgmt: &'a ZoneMgmtHandler<StubZoneHooks, ZONE_NZ, ZONE_NV, ZONE_NT>,
    push_av: &'a PushAvStreamHandler<'static, StubPushHooks, PUSH_NC>,
    chime: ChimeHandler,
) -> impl DataModelHandler + 'a {
    (
        NODE,
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
                    EpClMatcher::new(Some(1), Some(groups::GroupsHandler::CLUSTER.id)),
                    Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(CamAv::CLUSTER_VIDEO_AUDIO.id)),
                    rs_matter::dm::clusters::app::cam_av_stream::HandlerAsyncAdaptor(cam_av),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(CLUSTER_DPTZ_ONLY.id)),
                    rs_matter::dm::clusters::app::cam_av_settings::HandlerAsyncAdaptor(
                        cam_av_settings,
                    ),
                )
                .chain(
                    EpClMatcher::new(
                        Some(1),
                        Some(
                            ZoneMgmtHandler::<StubZoneHooks, ZONE_NZ, ZONE_NV, ZONE_NT>::CLUSTER.id,
                        ),
                    ),
                    ZoneMgmtAdaptor(zone_mgmt),
                )
                .chain(
                    EpClMatcher::new(
                        Some(1),
                        Some(PushAvStreamHandler::<StubPushHooks, PUSH_NC>::CLUSTER.id),
                    ),
                    rs_matter::dm::clusters::app::push_av_stream::HandlerAsyncAdaptor(push_av),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(WebRtc::CLUSTER.id)),
                    WebRtcAdaptor(webrtc),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(chime_decl::FULL_CLUSTER.id)),
                    Async(ChimeHandlerAdaptor(chime)),
                ),
        ),
    )
}
