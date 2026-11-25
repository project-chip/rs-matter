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

//! The node of the `clusters` target, which has most of the cluster handlers of rs-matter,
//! as the all-clusters app of CHIP has most of its clusters. It runs in the harness of the
//! `node` target, with the same sessions and the same input format.
//!
//! - Endpoint 0, the root node: the clusters of `clusters!(eth;)`, with the auxiliary ACL
//!   feature of Access Control, and Time Synchronization with time zones, Groups,
//!   Groupcast, User Label, Binding, OTA Provider, OTA Requestor, Diagnostic Logs,
//!   ICD Management and Power Source;
//! - Endpoint 1, an extended color light: Identify, Groups, On/Off, Level Control,
//!   Color Control, Scenes Management, Mode Select, Laundry Washer Mode, Fixed Label,
//!   Binding and Unit Testing;
//! - Endpoint 2, a room air conditioner: Identify, On/Off, Thermostat and Fan Control;
//! - Endpoint 3, a camera: Camera AV Stream Management, Camera AV Settings User Level
//!   Management, Zone Management, Push AV Stream Transport and WebRTC Transport Provider.
//!
//! The hooks of the clusters accept what they are asked to do. Where rs-matter has hooks
//! for tests, the node uses them.

use core::cell::Cell;
use core::mem::MaybeUninit;

use rs_matter::crypto::{test_only_crypto, Crypto};
use rs_matter::dm::clusters::app::cam_av_settings::{
    self, CamAvSettingsConfig, CamAvSettingsHandler, CamAvSettingsHooks, DptzView, Mptz,
    CLUSTER_DPTZ_ONLY,
};
use rs_matter::dm::clusters::app::cam_av_stream::{
    self, AudioCapabilitiesConfig, AudioCodecEnum, AudioStream, CamAvError, CameraAvStreamConfig,
    CameraAvStreamHandler, CameraAvStreamHooks, RateDistortionPoint, StreamUsageEnum,
    VideoCodecEnum, VideoSensorParams, VideoStream,
};
use rs_matter::dm::clusters::app::color_control::{
    self, test::TestColorControlDeviceLogic, ColorControlHandler, ColorControlHooks as _,
};
use rs_matter::dm::clusters::app::fan_control::{
    self, test::TestFanDeviceLogic, FanControlHandler, FanControlHooks as _,
};
use rs_matter::dm::clusters::app::level_control::{
    self, test::TestLevelControlDeviceLogic, LevelControlHandler, LevelControlHooks as _,
};
use rs_matter::dm::clusters::app::on_off::{
    self, test::TestOnOffDeviceLogic, NoLevelControl, OnOffHandler, OnOffHooks as _,
};
use rs_matter::dm::clusters::app::push_av_stream::{
    self, AllocatePushTransportRequest, ContainerFormatEnum, IngestMethodsEnum, PushAvError,
    PushAvStreamConfig, PushAvStreamHandler, PushAvStreamHooks, SupportedFormat,
};
use rs_matter::dm::clusters::app::thermostat::{
    self, test::TestThermostatDeviceLogic, ThermostatHandler, ThermostatHooks as _,
};
use rs_matter::dm::clusters::app::webrtc_prov::{
    self, AnswerOutcome, OfferParams, SolicitOutcome, WebRtcError, WebRtcHooks, WebRtcProvHandler,
};
use rs_matter::dm::clusters::app::zone_mgmt::{
    self, ZoneMgmtConfig, ZoneMgmtHandler, ZoneMgmtHooks,
};
use rs_matter::dm::clusters::binding::{self, BindingHandler, Bindings};
use rs_matter::dm::clusters::decl::globals::{ICECandidateStruct, WebRTCEndReasonEnum};
use rs_matter::dm::clusters::decl::scenes_management::FULL_CLUSTER as SCENES_CLUSTER;
use rs_matter::dm::clusters::desc::{ClusterHandler as _, DescHandler};
use rs_matter::dm::clusters::diag_logs::{self, DiagLogs, DiagLogsHandler, IntentEnum};
use rs_matter::dm::clusters::fixed_label::{self, FixedLabelEntry, FixedLabelHandler};
use rs_matter::dm::clusters::groupcast::{self, ClusterHandler as _, GroupcastHandler};
use rs_matter::dm::clusters::groups::{ClusterHandler as _, GroupsHandler};
use rs_matter::dm::clusters::icd_mgmt::{IcdModeConfig, LitIcd, LitIcdMgmtHandler};
use rs_matter::dm::clusters::identify::{self, IdentifyHandler};
use rs_matter::dm::clusters::mode::{
    self, laundry_washer_mode, ModeChangeError, ModeHandler, ModeHooks, ModeTag,
};
use rs_matter::dm::clusters::mode_select::{self, ModeSelectHandler, ModeSelectHooks};
use rs_matter::dm::clusters::ota_prov::{
    self, OtaImageMeta, OtaImagesRegistry, OtaProviderHandler, OtaQueryOutcome, OtaRequestorId,
};
use rs_matter::dm::clusters::ota_req::{
    ClusterHandler as _, OtaRequestorHandler, OtaState, Providers,
};
use rs_matter::dm::clusters::power_source::{self, PowerSourceConfig, PowerSourceHandler};
use rs_matter::dm::clusters::scenes::{ScenesHandler, ScenesState};
use rs_matter::dm::clusters::time_sync::{
    self, ClusterHandler as _, TimeSyncHandler, TimeZoneStore,
};
use rs_matter::dm::clusters::unit_testing::{
    ClusterHandler as _, UnitTestingHandler, UnitTestingHandlerData,
};
use rs_matter::dm::clusters::user_label::{self, UserLabelHandler, UserLabels};
use rs_matter::dm::devices::{
    DEV_TYPE_CAMERA, DEV_TYPE_EXTENDED_COLOR_LIGHT, DEV_TYPE_OTA_PROVIDER, DEV_TYPE_OTA_REQUESTOR,
    DEV_TYPE_POWER_SOURCE, DEV_TYPE_ROOM_AIR_CONDITIONER, DEV_TYPE_ROOT_NODE,
};
use rs_matter::dm::endpoints::EthSysHandlerBuilder;
use rs_matter::dm::{Async, Cluster, Dataver, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::im::FabricIndex;
use rs_matter::persist::VENDOR_KEYS_START;
use rs_matter::tlv::TLVArray;
use rs_matter::transport::MatterBuffers;
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::sync::blocking::Mutex;
use rs_matter::{clusters, devices, with};

use crate::harness;

/// How many scenes each fabric can have
const SCENES: usize = 8;
/// How many video and audio streams the camera can have
const STREAMS: usize = 2;
/// How many zones, vertices of a zone, and triggers the camera can have
const ZONES: usize = 4;
const ZONE_VERTICES: usize = 8;
const ZONE_TRIGGERS: usize = 4;
/// How many push transports the camera can have
const PUSH_TRANSPORTS: usize = 2;
/// How many WebRTC sessions the camera can have, and the sizes of their SDP and ICE
/// candidates
const WEBRTC_SESSIONS: usize = 2;
const SDP_LEN: usize = 1024;
const WEBRTC_OUT_LEN: usize = SDP_LEN + 512;
const CANDIDATE_LEN: usize = 128;
const CANDIDATES: usize = 4;

type CamAv<'a> = CameraAvStreamHandler<'a, CamHooks<'a>, STREAMS, STREAMS>;
type CamSettings = CamAvSettingsHandler<NoCamSettingsHooks, 0, STREAMS>;
type Zones = ZoneMgmtHandler<NoZoneHooks, ZONES, ZONE_VERTICES, ZONE_TRIGGERS>;
type PushAv<'a> = PushAvStreamHandler<'a, AcceptPush, PUSH_TRANSPORTS>;
type WebRtc<'a> = WebRtcProvHandler<
    'a,
    AcceptWebRtc,
    WEBRTC_SESSIONS,
    SDP_LEN,
    WEBRTC_OUT_LEN,
    CANDIDATE_LEN,
    CANDIDATES,
>;

const OTA_PROVIDER_CLUSTER: Cluster<'static> =
    <OtaProviderHandler<Images> as ota_prov::ClusterAsyncHandler>::CLUSTER;
const DIAG_LOGS_CLUSTER: Cluster<'static> =
    <DiagLogsHandler<&MatterBuffers<2>, Logs> as diag_logs::ClusterAsyncHandler>::CLUSTER;

const NODE: Node<'static> = Node {
    endpoints: &[
        Endpoint::new(
            0,
            devices!(
                DEV_TYPE_ROOT_NODE,
                DEV_TYPE_OTA_REQUESTOR,
                DEV_TYPE_OTA_PROVIDER,
                DEV_TYPE_POWER_SOURCE
            ),
            clusters!(
                eth,
                acl(aux),
                time_sync(time_zone, time_sync_client);
                GroupsHandler::CLUSTER,
                GroupcastHandler::CLUSTER,
                user_label::CLUSTER,
                binding::CLUSTER,
                OTA_PROVIDER_CLUSTER,
                OtaRequestorHandler::CLUSTER,
                DIAG_LOGS_CLUSTER,
                LitIcdMgmtHandler::CLUSTER_DSLS,
                power_source::CLUSTER
            ),
        ),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_EXTENDED_COLOR_LIGHT),
            clusters!(
                DescHandler::CLUSTER,
                identify::CLUSTER,
                GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                TestLevelControlDeviceLogic::CLUSTER,
                TestColorControlDeviceLogic::CLUSTER,
                SCENES_CLUSTER,
                Patterns::CLUSTER,
                WashCycles::CLUSTER,
                fixed_label::CLUSTER,
                binding::CLUSTER,
                UnitTestingHandler::CLUSTER
            ),
        ),
        Endpoint::new(
            2,
            devices!(DEV_TYPE_ROOM_AIR_CONDITIONER),
            clusters!(
                DescHandler::CLUSTER,
                identify::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                TestThermostatDeviceLogic::CLUSTER,
                TestFanDeviceLogic::CLUSTER
            ),
        ),
        Endpoint::new(
            3,
            devices!(DEV_TYPE_CAMERA),
            clusters!(
                DescHandler::CLUSTER,
                CamAv::CLUSTER_VIDEO_AUDIO,
                CLUSTER_DPTZ_ONLY,
                Zones::CLUSTER,
                PushAv::CLUSTER,
                WebRtc::CLUSTER
            ),
        ),
    ],
};

/// Runs the node of the `clusters` target with the messages in `data`. `observe` gets the
/// protocol ID, the opcode and the payload of each message that the node sends.
pub fn run(data: &[u8], observe: impl FnMut(u16, u8, &[u8])) {
    let crypto = test_only_crypto();
    let mut rand = crypto.rand().unwrap();

    let matter = harness::new_matter(&crypto);

    // Endpoint 0
    let user_labels = UserLabels::<1, 4>::new();
    let bindings = Bindings::<8>::new();
    let time_zones: TimeZoneStore = TimeZoneStore::new();
    let ota_providers = Providers::new();
    let ota_state = OtaState::new(0);
    let log_buffers: MatterBuffers<2> = MatterBuffers::new();
    let icd = LitIcd::new(
        100,
        IcdModeConfig {
            idle_mode_duration_s: 3600,
            active_mode_duration_ms: 10000,
            active_mode_threshold_ms: 5000,
            user_active_mode_trigger_hint: 0x111D,
            user_active_mode_trigger_instruction: "Press the button",
        },
        5000,
    );

    // Endpoint 1
    let mut unit_testing = MaybeUninit::uninit();
    let unit_testing =
        unit_testing.init_with(Mutex::init(RefCell::init(UnitTestingHandlerData::init())));
    let scenes: ScenesState<SCENES> = ScenesState::new();
    let identify_1 = IdentifyHandler::new(Dataver::new_rand(&mut rand));
    let patterns = ModeSelectHandler::new(
        Dataver::new_rand(&mut rand),
        VENDOR_KEYS_START + 0x13,
        Patterns(Mutex::new(Cell::new(0))),
    );
    let on_off_1 = OnOffHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        VENDOR_KEYS_START + 0x10,
        TestOnOffDeviceLogic::new(false),
    )
    .with_scene_invalidator(&scenes)
    .with_on_mode_applier(&patterns);
    let level = LevelControlHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        VENDOR_KEYS_START + 0x12,
        TestLevelControlDeviceLogic::new(),
    )
    .with_scene_invalidator(&scenes);
    let color = ColorControlHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        VENDOR_KEYS_START + 0x11,
        TestColorControlDeviceLogic::new(),
    )
    .with_scene_invalidator(&scenes);
    on_off_1.init(Some(&level));
    level.init(Some(&on_off_1));
    color.init(Some(&on_off_1));
    let scenes = ScenesHandler::new(
        Dataver::new_rand(&mut rand),
        &matter,
        &scenes,
        (&on_off_1, (&level, (&color, ()))),
    );

    // Endpoint 2
    let on_off_2: OnOffHandler<'_, _, NoLevelControl> = OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        2,
        VENDOR_KEYS_START + 0x15,
        TestOnOffDeviceLogic::new(false),
    );

    // Endpoint 3
    let cam_settings: CamSettings = CamAvSettingsHandler::new(
        Dataver::new_rand(&mut rand),
        3,
        CLUSTER_DPTZ_ONLY,
        CamAvSettingsConfig {
            pan_range: (0, 0),
            tilt_range: (0, 0),
            zoom_max: 1,
            default_position: Mptz {
                pan: None,
                tilt: None,
                zoom: None,
            },
            max_presets: 0,
        },
        NoCamSettingsHooks,
    );
    let cam_av: CamAv = CameraAvStreamHandler::new(
        Dataver::new_rand(&mut rand),
        3,
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
            supported_stream_usages: &[StreamUsageEnum::LiveView],
            default_stream_usage_priorities: &[StreamUsageEnum::LiveView],
            rate_distortion_points: &[RateDistortionPoint {
                codec: VideoCodecEnum::H264,
                min_resolution: (640, 360),
                min_bit_rate: 500_000,
            }],
            mic_capabilities: Some(AudioCapabilitiesConfig {
                max_channels: 1,
                supported_codecs: &[AudioCodecEnum::OPUS],
                supported_sample_rates: &[48_000],
                supported_bit_depths: &[16],
            }),
        },
        cam_av_stream::Feature::VIDEO.bits() | cam_av_stream::Feature::AUDIO.bits(),
        CamHooks(&cam_settings),
    );
    if let Ok(video_stream_id) = cam_av.add_preallocated_video(VideoStream {
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
    }) {
        cam_settings
            .add_preallocated_dptz(full_view(video_stream_id))
            .unwrap();
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
        .unwrap();
    let zones: Zones = ZoneMgmtHandler::new(
        Dataver::new_rand(&mut rand),
        3,
        ZoneMgmtConfig {
            max_zones: ZONES as u8,
            max_user_defined_zones: ZONES as u8,
            sensitivity_max: 10,
            default_sensitivity: 5,
            two_d_cartesian_max: (1919, 1079),
        },
        zone_mgmt::Feature::TWO_DIMENSIONAL_CARTESIAN_ZONE.bits()
            | zone_mgmt::Feature::USER_DEFINED.bits(),
        NoZoneHooks,
    );
    let push_av: PushAv = PushAvStreamHandler::new(
        Dataver::new_rand(&mut rand),
        3,
        PushAvStreamConfig {
            supported_formats: &[SupportedFormat {
                container_format: ContainerFormatEnum::CMAF,
                ingest_method: IngestMethodsEnum::CMAFIngest,
            }],
        },
        AcceptPush,
    );
    let webrtc: WebRtc =
        WebRtcProvHandler::new(Dataver::new_rand(&mut rand), &matter, 3, AcceptWebRtc);

    let handler = EthSysHandlerBuilder::new()
        .build(&matter, rand)
        // Endpoint 0
        .chain(
            |e, c| e == 0 && c == TimeSyncHandler::CLUSTER.id,
            Async(time_sync::HandlerAdaptor(
                TimeSyncHandler::new_with_time_zone(
                    Dataver::new_rand(&mut rand),
                    &matter,
                    &time_zones,
                ),
            )),
        )
        .chain(
            |e, c| e == 0 && c == GroupsHandler::CLUSTER.id,
            Async(GroupsHandler::new(Dataver::new_rand(&mut rand), &matter).adapt()),
        )
        .chain(
            |e, c| e == 0 && c == GroupcastHandler::CLUSTER.id,
            Async(
                GroupcastHandler::new(
                    Dataver::new_rand(&mut rand),
                    &matter,
                    groupcast::Feature::all(),
                )
                .adapt(),
            ),
        )
        .chain(
            |e, c| e == 0 && c == user_label::CLUSTER.id,
            Async(user_label::HandlerAdaptor(UserLabelHandler::new(
                Dataver::new_rand(&mut rand),
                0,
                &user_labels,
            ))),
        )
        .chain(
            |e, c| e == 0 && c == binding::CLUSTER.id,
            Async(binding::HandlerAdaptor(BindingHandler::new(
                Dataver::new_rand(&mut rand),
                0,
                &bindings,
            ))),
        )
        .chain(
            |e, c| e == 0 && c == OTA_PROVIDER_CLUSTER.id,
            OtaProviderHandler::new(Dataver::new_rand(&mut rand), &matter, Images).adapt(),
        )
        .chain(
            |e, c| e == 0 && c == OtaRequestorHandler::CLUSTER.id,
            Async(
                OtaRequestorHandler::new(
                    Dataver::new_rand(&mut rand),
                    &matter,
                    &ota_providers,
                    &ota_state,
                )
                .adapt(),
            ),
        )
        .chain(
            |e, c| e == 0 && c == DIAG_LOGS_CLUSTER.id,
            DiagLogsHandler::new(Dataver::new_rand(&mut rand), &matter, &log_buffers, Logs).adapt(),
        )
        .chain(
            |e, c| e == 0 && c == LitIcdMgmtHandler::CLUSTER_DSLS.id,
            Async(LitIcdMgmtHandler::new(Dataver::new_rand(&mut rand), &matter, &icd).adapt()),
        )
        .chain(
            |e, c| e == 0 && c == power_source::CLUSTER.id,
            Async(
                PowerSourceHandler::new(Dataver::new_rand(&mut rand), &PowerSourceConfig::MAINS)
                    .adapt(),
            ),
        )
        // Endpoint 1
        .chain(
            |e, c| e == 1 && c == DescHandler::CLUSTER.id,
            Async(DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
        )
        .chain(
            |e, c| e == 1 && c == identify::CLUSTER.id,
            Async(identify::HandlerAdaptor(&identify_1)),
        )
        .chain(
            |e, c| e == 1 && c == GroupsHandler::CLUSTER.id,
            Async(
                GroupsHandler::new_with_identify(
                    Dataver::new_rand(&mut rand),
                    &matter,
                    &identify_1,
                )
                .adapt(),
            ),
        )
        .chain(
            |e, c| e == 1 && c == TestOnOffDeviceLogic::CLUSTER.id,
            Async(on_off::HandlerAdaptor(&on_off_1)),
        )
        .chain(
            |e, c| e == 1 && c == TestLevelControlDeviceLogic::CLUSTER.id,
            Async(level_control::HandlerAdaptor(&level)),
        )
        .chain(
            |e, c| e == 1 && c == TestColorControlDeviceLogic::CLUSTER.id,
            Async(color_control::HandlerAdaptor(&color)),
        )
        .chain(|e, c| e == 1 && c == SCENES_CLUSTER.id, scenes.adapt())
        .chain(
            |e, c| e == 1 && c == Patterns::CLUSTER.id,
            Async(mode_select::HandlerAdaptor(&patterns)),
        )
        .chain(
            |e, c| e == 1 && c == WashCycles::CLUSTER.id,
            Async(laundry_washer_mode::HandlerAdaptor(ModeHandler::new(
                Dataver::new_rand(&mut rand),
                VENDOR_KEYS_START + 0x14,
                WashCycles(Mutex::new(Cell::new(0))),
            ))),
        )
        .chain(
            |e, c| e == 1 && c == fixed_label::CLUSTER.id,
            Async(FixedLabelHandler::new(Dataver::new_rand(&mut rand), FIXED_LABELS).adapt()),
        )
        .chain(
            |e, c| e == 1 && c == binding::CLUSTER.id,
            Async(binding::HandlerAdaptor(BindingHandler::new(
                Dataver::new_rand(&mut rand),
                1,
                &bindings,
            ))),
        )
        .chain(
            |e, c| e == 1 && c == UnitTestingHandler::CLUSTER.id,
            Async(UnitTestingHandler::new(Dataver::new_rand(&mut rand), unit_testing).adapt()),
        )
        // Endpoint 2
        .chain(
            |e, c| e == 2 && c == DescHandler::CLUSTER.id,
            Async(DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
        )
        .chain(
            |e, c| e == 2 && c == identify::CLUSTER.id,
            Async(IdentifyHandler::new(Dataver::new_rand(&mut rand)).adapt()),
        )
        .chain(
            |e, c| e == 2 && c == TestOnOffDeviceLogic::CLUSTER.id,
            Async(on_off::HandlerAdaptor(on_off_2)),
        )
        .chain(
            |e, c| e == 2 && c == TestThermostatDeviceLogic::CLUSTER.id,
            Async(thermostat::HandlerAdaptor(ThermostatHandler::new(
                Dataver::new_rand(&mut rand),
                2,
                VENDOR_KEYS_START + 0x16,
                TestThermostatDeviceLogic::new(),
            ))),
        )
        .chain(
            |e, c| e == 2 && c == TestFanDeviceLogic::CLUSTER.id,
            Async(fan_control::HandlerAdaptor(FanControlHandler::new(
                Dataver::new_rand(&mut rand),
                2,
                VENDOR_KEYS_START + 0x17,
                TestFanDeviceLogic::new(),
            ))),
        )
        // Endpoint 3
        .chain(
            |e, c| e == 3 && c == DescHandler::CLUSTER.id,
            Async(DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
        )
        .chain(
            |e, c| e == 3 && c == CamAv::CLUSTER_VIDEO_AUDIO.id,
            cam_av_stream::HandlerAsyncAdaptor(&cam_av),
        )
        .chain(
            |e, c| e == 3 && c == CLUSTER_DPTZ_ONLY.id,
            cam_av_settings::HandlerAsyncAdaptor(&cam_settings),
        )
        .chain(
            |e, c| e == 3 && c == Zones::CLUSTER.id,
            zone_mgmt::HandlerAsyncAdaptor(&zones),
        )
        .chain(
            |e, c| e == 3 && c == PushAv::CLUSTER.id,
            push_av_stream::HandlerAsyncAdaptor(&push_av),
        )
        .chain(
            |e, c| e == 3 && c == WebRtc::CLUSTER.id,
            webrtc_prov::HandlerAsyncAdaptor(&webrtc),
        );

    harness::drive(&matter, &crypto, (NODE, handler), data, observe);
}

const FIXED_LABELS: &[FixedLabelEntry<'static>] = &[
    FixedLabelEntry {
        label: "room",
        value: "kitchen",
    },
    FixedLabelEntry {
        label: "orientation",
        value: "north",
    },
];

/// The view of the whole sensor, for a video stream
const fn full_view(video_stream_id: u16) -> DptzView {
    DptzView {
        video_stream_id,
        x1: 0,
        y1: 0,
        x2: 1920,
        y2: 1080,
    }
}

/// The modes of Mode Select
struct Patterns(Mutex<Cell<mode_select::ModeId>>);

const PATTERNS: &[mode_select::Mode] = &[
    mode_select::Mode::new(
        0,
        "Steady",
        &[mode_select::SemanticTag::new(0xfff1, 0x8000)],
    ),
    mode_select::Mode::new(4, "Blink", &[mode_select::SemanticTag::new(0xfff1, 0x8001)]),
    mode_select::Mode::new(7, "Pulse", &[]),
];

impl ModeSelectHooks for Patterns {
    const CLUSTER: Cluster<'static> = mode_select::FULL_CLUSTER
        .with_features(mode_select::Feature::ON_OFF.bits())
        .with_attrs(with!(
            required;
            mode_select::AttributeId::StartUpMode | mode_select::AttributeId::OnMode
        ));

    const START_UP_MODE: Option<mode_select::ModeId> = Some(0);

    const PERSIST_DELAY_MS: u32 = 0;

    fn description(&self) -> &str {
        "Pattern"
    }

    fn supported_modes(&self) -> &[mode_select::Mode<'_>] {
        PATTERNS
    }

    fn change_to_mode(&self, mode: mode_select::ModeId) -> Result<(), Error> {
        self.0.lock(|current| current.set(mode));

        Ok(())
    }
}

/// The modes of Laundry Washer Mode, a cluster derived from Mode Base
struct WashCycles(Mutex<Cell<mode::ModeId>>);

const WASH_CYCLES: &[mode::Mode<laundry_washer_mode::ModeTag>] = &[
    mode::Mode::new(
        0,
        "Normal",
        &[ModeTag::Standard(laundry_washer_mode::ModeTag::Normal)],
    ),
    mode::Mode::new(
        2,
        "Delicate",
        &[
            ModeTag::Standard(laundry_washer_mode::ModeTag::Delicate),
            ModeTag::Standard(laundry_washer_mode::ModeTag::LowNoise),
        ],
    ),
    mode::Mode::new(
        3,
        "Heavy",
        &[ModeTag::Standard(laundry_washer_mode::ModeTag::Heavy)],
    ),
];

impl ModeHooks for WashCycles {
    const CLUSTER: Cluster<'static> = laundry_washer_mode::CLUSTER;

    type ModeTag = laundry_washer_mode::ModeTag;

    const PERSIST_DELAY_MS: u32 = 0;

    fn supported_modes(&self) -> &[mode::Mode<'_, Self::ModeTag>] {
        WASH_CYCLES
    }

    fn change_to_mode(&self, mode: mode::ModeId) -> Result<(), ModeChangeError> {
        self.0.lock(|current| current.set(mode));

        Ok(())
    }
}

/// An OTA image for every requestor, one version newer than what it runs
struct Images;

impl OtaImagesRegistry for Images {
    async fn query<'b>(
        &self,
        _requestor: OtaRequestorId,
        _vendor_id: u16,
        _product_id: u16,
        current_version: u32,
        requestor_can_consent: bool,
        _buf: &'b mut [u8],
    ) -> OtaQueryOutcome<'b> {
        OtaQueryOutcome::Available(OtaImageMeta {
            version: current_version.wrapping_add(1),
            version_str: "next",
            file_designator: "image.ota",
            update_token: &[0x10; 8],
            user_consent_needed: requestor_can_consent,
        })
    }
}

/// Logs for two of the intents: a long one, which is sent over BDX, and a short one
struct Logs;

const LONG_LOG: [u8; 2000] = [b'l'; 2000];
const SHORT_LOG: &[u8] = b"A short log";

impl Logs {
    fn log(intent: IntentEnum) -> Option<&'static [u8]> {
        match intent {
            IntentEnum::EndUserSupport => Some(&LONG_LOG),
            IntentEnum::NetworkDiag => Some(SHORT_LOG),
            _ => None,
        }
    }
}

impl DiagLogs for Logs {
    async fn size(&self, intent: IntentEnum) -> Option<u64> {
        Self::log(intent).map(|log| log.len() as u64)
    }

    async fn read(&self, intent: IntentEnum, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let log = Self::log(intent).unwrap_or_default();
        let rest = log.get(offset as usize..).unwrap_or_default();
        let len = rest.len().min(buf.len());
        buf[..len].copy_from_slice(&rest[..len]);

        Ok(len)
    }
}

/// The camera: each allocated video stream gets a view of the whole sensor
struct CamHooks<'a>(&'a CamSettings);

impl CameraAvStreamHooks for CamHooks<'_> {
    async fn allocate_video(&self, stream: &VideoStream) -> Result<(), CamAvError> {
        let _ = self
            .0
            .add_preallocated_dptz(full_view(stream.video_stream_id));

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
        let _ = self.0.remove_dptz_stream(id);

        Ok(())
    }
}

struct NoCamSettingsHooks;

impl CamAvSettingsHooks for NoCamSettingsHooks {}

struct NoZoneHooks;

impl<const NV: usize> ZoneMgmtHooks<NV> for NoZoneHooks {}

struct AcceptPush;

impl PushAvStreamHooks for AcceptPush {
    async fn on_allocate(
        &self,
        _connection_id: u16,
        _fabric_index: FabricIndex,
        _request: &AllocatePushTransportRequest<'_>,
    ) -> Result<(), PushAvError> {
        Ok(())
    }
}

struct AcceptWebRtc;

impl WebRtcHooks for AcceptWebRtc {
    async fn on_solicit_offer(
        &self,
        _session_id: u16,
        _params: &OfferParams,
    ) -> Result<SolicitOutcome, WebRtcError> {
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
        Ok(AnswerOutcome {
            video_stream_id: None,
            audio_stream_id: None,
        })
    }

    async fn on_answer(&self, _session_id: u16, _sdp: &str) -> Result<(), WebRtcError> {
        Ok(())
    }

    async fn on_ice_candidates(
        &self,
        _session_id: u16,
        _candidates: &TLVArray<'_, ICECandidateStruct<'_>>,
    ) -> Result<(), WebRtcError> {
        Ok(())
    }

    async fn on_end_session(
        &self,
        _session_id: u16,
        _reason: WebRTCEndReasonEnum,
    ) -> Result<(), WebRtcError> {
        Ok(())
    }
}
