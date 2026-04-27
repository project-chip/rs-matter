/*
 *
 *    Copyright (c) 2020-2026 Project CHIP Authors
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

//! Implementation of the Matter Camera AV Stream Management cluster (0x0551).
//!
//! Advertises the audio / video / snapshot streams a camera can produce and
//! supports dynamic allocation/modification/deallocation of those streams by
//! Matter controllers (notably SmartThings, Google Home, and the upstream
//! `chip-tool` test suites).
//!
//! # Architecture (Pattern B1 — "Hooks")
//!
//! [`CameraAvStreamHandler`] owns the spec-defined state — the stream
//! table, stable stream IDs, reference counts, and the mutable
//! `StreamUsagePriorities` attribute — and performs all spec validation
//! before delegating the side-effecting bits (open / close the encoder,
//! flip watermark/OSD overlays) to a user-supplied
//! [`CameraAvStreamHooks`] implementation.
//!
//! ```text
//! ┌──────────────────────┐  ClusterAsyncHandler   ┌───────────────────┐
//! │                      │◀── inbound commands ───│   rs-matter IM    │
//! │ CameraAvStreamHandler│                        │     dispatcher    │
//! └──────┬───────────────┘                        └───────────────────┘
//!        │ delegates encoder open/modify/close
//!        ▼
//! ┌──────────────────────┐
//! │ CameraAvStreamHooks  │  user-supplied (e.g. str0m / GStreamer)
//! └──────────────────────┘
//! ```
//!
//! # Cross-cluster reference counting
//!
//! `WebRTCTransportProvider` and `PushAvStreamTransport` both refer to
//! video streams by ID. When such a transport binds a stream the consumer
//! MUST call [`CameraAvStreamHandler::acquire_video`]; when it tears down,
//! [`CameraAvStreamHandler::release_video`]. The handler refuses to
//! deallocate any stream whose reference count is non-zero, mirroring the
//! Matter 1.5 spec requirement.
//!
//! # Const generics
//!
//! * `NV` — maximum number of allocated video streams the handler can
//!   hold at once. Spec MinLimit is 1 for any camera advertising the
//!   `VIDEO` feature; commercial devices typically expose 2..=4.
//!
//! # Scope of v1
//!
//! * `VIDEO` feature only.
//! * Full validation, allocation, modification, deallocation, priority
//!   negotiation.
//! * `WATERMARK` / `ON_SCREEN_DISPLAY` feature gating for the
//!   per-stream toggles (not yet exposed at cluster level — once the
//!   user sets those feature bits, modify accepts them).
//! * NOT in scope (return `INVALID_ACTION` / `UNSUPPORTED_ATTRIBUTE`):
//!   audio streams, snapshot streams, `CaptureSnapshot`, privacy modes,
//!   night vision, image control, speaker / microphone, status light.
//!   Each is a follow-up.

use core::cell::{Cell, RefCell};

use crate::dm::{ArrayAttributeRead, Cluster, Dataver, EndptId, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVArray, TLVBuilderParent, ToTLVArrayBuilder, ToTLVBuilder};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::with;

pub use crate::dm::clusters::decl::camera_av_stream_management::AudioCodecEnum;
#[allow(unused_imports)]
pub use crate::dm::clusters::decl::camera_av_stream_management::*;
pub use crate::dm::clusters::decl::globals::StreamUsageEnum;

use super::super::decl::camera_av_stream_management as decl;

/// Static description of the camera image sensor.
///
/// Reported via the `VideoSensorParams` attribute (spec §"VideoSensorParams").
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VideoSensorParams {
    pub sensor_width: u16,
    pub sensor_height: u16,
    pub max_fps: u16,
    pub max_hdrfps: Option<u16>,
}

/// One operating point exposed via `RateDistortionTradeOffPoints`.
///
/// Each entry tells controllers "for codec X at minimum resolution
/// (W,H), the encoder needs at least `min_bit_rate` bps." Controllers
/// then build `VideoStreamAllocate` requests around those constraints.
/// At least one entry is required by SmartThings to attempt a stream
/// allocation; the validation logic in [`CameraAvStreamHandler`] insists
/// every allocation references a codec present in this list.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RateDistortionPoint {
    pub codec: VideoCodecEnum,
    pub min_resolution: (u16, u16),
    pub min_bit_rate: u32,
}

/// One row in the `AllocatedAudioStreams` attribute.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AudioStream {
    pub audio_stream_id: u16,
    pub stream_usage: StreamUsageEnum,
    pub audio_codec: AudioCodecEnum,
    pub channel_count: u8,
    pub sample_rate: u32,
    pub bit_rate: u32,
    pub bit_depth: u8,
    pub reference_count: u8,
}

/// Static description of the microphone, reported via `MicrophoneCapabilities`.
#[derive(Debug, Clone, Copy)]
pub struct AudioCapabilitiesConfig<'a> {
    pub max_channels: u8,
    pub supported_codecs: &'a [AudioCodecEnum],
    pub supported_sample_rates: &'a [u32],
    pub supported_bit_depths: &'a [u8],
}

/// One row in the `AllocatedVideoStreams` attribute.
///
/// The `reference_count` field is fully managed by the handler — callers
/// of `allocate_video` / `modify_video` in [`CameraAvStreamHooks`] should
/// ignore it; cross-cluster consumers (WebRTC, PushAV) adjust it via
/// [`CameraAvStreamHandler::acquire_video`] /
/// [`CameraAvStreamHandler::release_video`].
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VideoStream {
    pub video_stream_id: u16,
    pub stream_usage: StreamUsageEnum,
    pub video_codec: VideoCodecEnum,
    pub min_frame_rate: u16,
    pub max_frame_rate: u16,
    pub min_width: u16,
    pub min_height: u16,
    pub max_width: u16,
    pub max_height: u16,
    pub min_bit_rate: u32,
    pub max_bit_rate: u32,
    pub key_frame_interval: u16,
    pub watermark_enabled: Option<bool>,
    pub osd_enabled: Option<bool>,
    pub reference_count: u8,
}

/// Errors a [`CameraAvStreamHooks`] implementation can surface back to
/// the cluster. Each maps to a Matter cluster-status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CamAvError {
    /// `RESOURCE_EXHAUSTED` — encoder cannot accept another concurrent stream.
    ResourceExhausted,
    /// `DYNAMIC_CONSTRAINT_ERROR` — combination of params is unsupported
    /// at runtime (e.g. requested bitrate exceeds what the codec can do
    /// for the requested resolution).
    DynamicConstraint,
    /// `NOT_FOUND` — referenced stream ID does not exist.
    NotFound,
    /// `FAILURE` — any other hooks-level failure.
    Failure,
}

impl From<CamAvError> for Error {
    fn from(e: CamAvError) -> Self {
        match e {
            CamAvError::ResourceExhausted => ErrorCode::ResourceExhausted.into(),
            CamAvError::DynamicConstraint => ErrorCode::ConstraintError.into(),
            CamAvError::NotFound => ErrorCode::NotFound.into(),
            CamAvError::Failure => ErrorCode::Failure.into(),
        }
    }
}

/// Application hooks for the side-effecting pieces of stream lifecycle.
///
/// All spec validation (priority membership, codec availability,
/// resolution/framerate/bitrate min<=max, viewport floor, sensor ceiling,
/// reference-count protection on deallocate) is done by
/// [`CameraAvStreamHandler`] before any of these methods run. Implementors
/// only need to interact with their actual encoder / camera.
pub trait CameraAvStreamHooks {
    /// Called when a new video stream has been validated and assigned a
    /// stable ID. The implementation should provision encoder resources;
    /// returning `Err` aborts the allocation (the stream is NOT added to
    /// the cluster's `AllocatedVideoStreams` attribute and no ID is
    /// returned to the controller).
    ///
    /// `stream` carries the just-assigned `video_stream_id` and the
    /// validated parameters. `reference_count` is always 0 here.
    fn allocate_video(
        &self,
        stream: &VideoStream,
    ) -> impl core::future::Future<Output = Result<(), CamAvError>>;

    /// Called when a controller requests `VideoStreamModify`.
    ///
    /// The handler has already verified the stream exists and that the
    /// requested toggles are legal under the advertised feature set.
    /// `watermark_enabled` / `osd_enabled` carry the requested new
    /// values (`None` = not changing). On success the cluster table is
    /// updated to match; on `Err` the table is left unchanged.
    fn modify_video(
        &self,
        video_stream_id: u16,
        watermark_enabled: Option<bool>,
        osd_enabled: Option<bool>,
    ) -> impl core::future::Future<Output = Result<(), CamAvError>>;

    /// Called when a controller requests `VideoStreamDeallocate` AND
    /// the handler has confirmed the stream's reference count is zero.
    fn deallocate_video(
        &self,
        video_stream_id: u16,
    ) -> impl core::future::Future<Output = Result<(), CamAvError>>;
}

/// Maximum number of `StreamUsageEnum` entries the handler will hold for
/// the (mutable) `StreamUsagePriorities` attribute. Spec defines six
/// usages today; eight is comfortable headroom.
const MAX_STREAM_USAGES: usize = 8;

/// Static (non-allocatable) configuration for a [`CameraAvStreamHandler`].
///
/// Everything that does not change at runtime: sensor description,
/// codec/resolution catalogue, supported usages, encoder limits.
#[derive(Debug, Clone, Copy)]
pub struct CameraAvStreamConfig<'a> {
    pub max_concurrent_encoders: u8,
    pub max_encoded_pixel_rate: u32,
    pub sensor: VideoSensorParams,
    /// Floor for both `MinViewportResolution` and any `min_resolution`
    /// supplied by `VideoStreamAllocate`. Stored as `(width, height)`.
    pub min_viewport: (u16, u16),
    /// Reported via `MaxContentBufferSize`. Spec recommends ≥ 1 MiB.
    pub max_content_buffer_size: u32,
    /// Reported via `MaxNetworkBandwidth` (kbps).
    pub max_network_bandwidth: u32,
    /// Stable, server-defined list of every usage this camera *could*
    /// expose. `StreamUsagePriorities` (mutable, see
    /// `default_stream_usage_priorities`) is always a subset/permutation.
    pub supported_stream_usages: &'a [StreamUsageEnum],
    /// Initial priority order at boot. Must be a permutation of (a
    /// subset of) `supported_stream_usages`.
    pub default_stream_usage_priorities: &'a [StreamUsageEnum],
    /// `RateDistortionTradeOffPoints` operating-points catalogue. At
    /// least one entry strongly recommended for interop.
    pub rate_distortion_points: &'a [RateDistortionPoint],
    /// If `Some`, the `AUDIO` feature is active and this describes the
    /// microphone via `MicrophoneCapabilities`. If `None`, only VIDEO is
    /// supported (the `CLUSTER` constant; the `CLUSTER_VIDEO_AUDIO`
    /// constant requires `Some`).
    pub mic_capabilities: Option<AudioCapabilitiesConfig<'a>>,
}

struct State<const NV: usize, const NA: usize> {
    videos: Vec<VideoStream, NV>,
    audios: Vec<AudioStream, NA>,
    stream_usage_priorities: Vec<StreamUsageEnum, MAX_STREAM_USAGES>,
}

impl<const NV: usize, const NA: usize> State<NV, NA> {
    const fn new() -> Self {
        Self {
            videos: Vec::new(),
            audios: Vec::new(),
            stream_usage_priorities: Vec::new(),
        }
    }

    fn find_video_mut(&mut self, id: u16) -> Result<&mut VideoStream, Error> {
        self.videos
            .iter_mut()
            .find(|s| s.video_stream_id == id)
            .ok_or_else(|| ErrorCode::NotFound.into())
    }
}

/// Handler for the Camera AV Stream Management cluster (0x0551).
///
/// See the [module documentation](self) for architecture and usage.
pub struct CameraAvStreamHandler<'a, H, const NV: usize, const NA: usize = 0>
where
    H: CameraAvStreamHooks,
{
    dataver: Dataver,
    endpoint_id: EndptId,
    config: CameraAvStreamConfig<'a>,
    /// Bitfield of advertised feature bits — must match the value
    /// returned by `Self::CLUSTER.feature_map`. Used only as a fast
    /// in-handler test for `WATERMARK` / `ON_SCREEN_DISPLAY`.
    features: u32,
    hooks: H,
    state: Mutex<RefCell<State<NV, NA>>>,
    next_id: Mutex<Cell<u16>>,
    next_audio_id: Mutex<Cell<u16>>,
}

impl<'a, H, const NV: usize, const NA: usize> CameraAvStreamHandler<'a, H, NV, NA>
where
    H: CameraAvStreamHooks,
{
    /// Cluster metadata advertising the `VIDEO` feature only and the
    /// minimal mandatory attribute set under that feature.
    ///
    /// Use this when the camera does not (yet) need watermark / OSD /
    /// audio / snapshot. For other combinations build a `Cluster` value
    /// directly via the generated `decl::FULL_CLUSTER.with_features(...)`.
    pub const CLUSTER: Cluster<'static> = decl::FULL_CLUSTER
        .with_revision(1)
        .with_features(decl::Feature::VIDEO.bits())
        .with_attrs(with!(
            required;
            AttributeId::MaxConcurrentEncoders
                | AttributeId::MaxEncodedPixelRate
                | AttributeId::VideoSensorParams
                | AttributeId::MinViewportResolution
                | AttributeId::RateDistortionTradeOffPoints
                | AttributeId::AllocatedVideoStreams
        ))
        .with_cmds(with!(
            decl::CommandId::VideoStreamAllocate
                | decl::CommandId::VideoStreamModify
                | decl::CommandId::VideoStreamDeallocate
                | decl::CommandId::SetStreamPriorities
        ));

    /// Cluster metadata advertising both `VIDEO` and `AUDIO` features.
    ///
    /// Use this (together with `CameraAvStreamConfig::mic_capabilities: Some(...)`)
    /// when the camera also exposes a microphone and pre-allocated audio streams.
    pub const CLUSTER_VIDEO_AUDIO: Cluster<'static> = decl::FULL_CLUSTER
        .with_revision(1)
        .with_features(decl::Feature::VIDEO.bits() | decl::Feature::AUDIO.bits())
        .with_attrs(with!(
            required;
            AttributeId::MaxConcurrentEncoders
                | AttributeId::MaxEncodedPixelRate
                | AttributeId::VideoSensorParams
                | AttributeId::MinViewportResolution
                | AttributeId::RateDistortionTradeOffPoints
                | AttributeId::AllocatedVideoStreams
                | AttributeId::MicrophoneCapabilities
                | AttributeId::AllocatedAudioStreams
        ))
        .with_cmds(with!(
            decl::CommandId::VideoStreamAllocate
                | decl::CommandId::VideoStreamModify
                | decl::CommandId::VideoStreamDeallocate
                | decl::CommandId::SetStreamPriorities
        ));

    /// Construct a new handler.
    ///
    /// `features` MUST equal the `feature_map` of the [`Cluster`] this
    /// handler is registered with; the handler uses it to decide
    /// whether `WATERMARK` / `ON_SCREEN_DISPLAY` toggles are legal in
    /// `VideoStreamAllocate` / `VideoStreamModify`.
    ///
    /// Panics if `features` advertises `AUDIO` but
    /// `config.mic_capabilities` is `None`. The `MicrophoneCapabilities`
    /// attribute is mandatory whenever `AUDIO` is enabled (Matter 1.5
    /// §1.16) and must be supplied at construction.
    pub const fn new(
        dataver: Dataver,
        endpoint_id: EndptId,
        config: CameraAvStreamConfig<'a>,
        features: u32,
        hooks: H,
    ) -> Self {
        // `core::assert!` is required here (not the crate-local `assert!`
        // shim) because `::defmt::assert!` is not const-callable.
        core::assert!(
            (features & decl::Feature::AUDIO.bits()) == 0 || config.mic_capabilities.is_some(),
            "CameraAvStreamHandler: AUDIO feature requires `config.mic_capabilities` to be Some",
        );
        Self {
            dataver,
            endpoint_id,
            config,
            features,
            hooks,
            state: Mutex::new(RefCell::new(State::new())),
            next_id: Mutex::new(Cell::new(1)),
            next_audio_id: Mutex::new(Cell::new(1)),
        }
    }

    /// Wrap in the generic async adaptor for registration with a
    /// `rs-matter` `Node`.
    pub const fn adapt(self) -> decl::HandlerAsyncAdaptor<Self> {
        decl::HandlerAsyncAdaptor(self)
    }

    /// Endpoint this handler is mounted on.
    pub const fn endpoint_id(&self) -> EndptId {
        self.endpoint_id
    }

    /// Increment the reference count of an allocated video stream so
    /// that [`Self::deallocate_video`] cannot remove it underneath the
    /// caller. Cross-cluster consumers (WebRTC, PushAV) MUST pair this
    /// with [`Self::release_video`] when their session ends.
    ///
    /// Returns `NOT_FOUND` if the stream does not exist.
    pub fn acquire_video(&self, video_stream_id: u16) -> Result<(), Error> {
        let changed = self.state.lock(|cell| -> Result<bool, Error> {
            let mut state = cell.borrow_mut();
            let row = state.find_video_mut(video_stream_id)?;
            row.reference_count = row.reference_count.saturating_add(1);
            Ok(true)
        })?;
        if changed {
            self.dataver.changed();
        }
        Ok(())
    }

    /// Decrement the reference count of an allocated video stream
    /// (saturating at 0). Best-effort: silently ignores unknown IDs so
    /// that callers can release in `Drop` without an extra existence
    /// check after a parallel deallocation.
    pub fn release_video(&self, video_stream_id: u16) {
        let changed = self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if let Some(row) = state
                .videos
                .iter_mut()
                .find(|s| s.video_stream_id == video_stream_id)
            {
                row.reference_count = row.reference_count.saturating_sub(1);
                true
            } else {
                false
            }
        });
        if changed {
            self.dataver.changed();
        }
    }

    /// Snapshot the current set of allocated video streams. Useful for
    /// applications that want to query state outside the data-model
    /// dispatch path (e.g. logging, diagnostics).
    pub fn video_streams(&self) -> Vec<VideoStream, NV> {
        self.state.lock(|cell| cell.borrow().videos.clone())
    }

    /// Pre-seed an entry into `AllocatedVideoStreams` at boot without
    /// invoking [`CameraAvStreamHooks::allocate_video`]. Suitable for
    /// devices that have a single fixed encoder configuration baked
    /// into the firmware and only need the cluster as a registry.
    ///
    /// The stream's `video_stream_id` field is overwritten with a
    /// freshly allocated ID; `reference_count` is reset to 0. No spec
    /// validation is performed — the caller is presumed to know what
    /// the device can do.
    ///
    /// Returns the assigned ID, or `RESOURCE_EXHAUSTED` if the table
    /// is full.
    pub fn add_preallocated_video(&self, mut stream: VideoStream) -> Result<u16, Error> {
        stream.reference_count = 0;
        stream.video_stream_id = self.alloc_video_id();
        let id = stream.video_stream_id;
        let pushed = self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.videos.push(stream).is_ok()
        });
        if !pushed {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        self.dataver.changed();
        Ok(id)
    }

    /// Snapshot the current set of allocated audio streams.
    pub fn audio_streams(&self) -> Vec<AudioStream, NA> {
        self.state.lock(|cell| cell.borrow().audios.clone())
    }

    /// Pre-seed an entry into `AllocatedAudioStreams` at boot without
    /// calling any hooks. Mirrors [`Self::add_preallocated_video`].
    ///
    /// Returns the assigned ID, or `RESOURCE_EXHAUSTED` if the table
    /// is full (or `NA = 0`).
    pub fn add_preallocated_audio(&self, mut stream: AudioStream) -> Result<u16, Error> {
        stream.reference_count = 0;
        stream.audio_stream_id = self.alloc_audio_id();
        let id = stream.audio_stream_id;
        let pushed = self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.audios.push(stream).is_ok()
        });
        if !pushed {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        self.dataver.changed();
        Ok(id)
    }

    // ----- internals -----

    /// Allocate the next free `video_stream_id`. Wraps to 1 if `next_id`
    /// rolls over `u16::MAX` (vanishingly unlikely on a real device but
    /// cheap to defend against).
    fn alloc_video_id(&self) -> u16 {
        self.next_id.lock(|cell| {
            let mut id = cell.get();
            if id == 0 {
                id = 1;
            }
            cell.set(id.wrapping_add(1).max(1));
            id
        })
    }

    fn alloc_audio_id(&self) -> u16 {
        self.next_audio_id.lock(|cell| {
            let mut id = cell.get();
            if id == 0 {
                id = 1;
            }
            cell.set(id.wrapping_add(1).max(1));
            id
        })
    }

    /// Initialise the mutable `StreamUsagePriorities` table from
    /// `config.default_stream_usage_priorities` exactly once.
    fn ensure_priorities_seeded(&self) {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if state.stream_usage_priorities.is_empty() {
                for u in self.config.default_stream_usage_priorities {
                    let _ = state.stream_usage_priorities.push(*u);
                }
            }
        });
    }

    fn has_feature(&self, bit: u32) -> bool {
        self.features & bit != 0
    }

    /// Validate a `VideoStreamAllocate` request against the spec and
    /// the static config. Returns a fresh [`VideoStream`] (without an
    /// ID) on success.
    fn validate_video_alloc(
        &self,
        request: &VideoStreamAllocateRequest<'_>,
    ) -> Result<VideoStream, Error> {
        let stream_usage = request.stream_usage()?;
        let video_codec = request.video_codec()?;
        let min_frame_rate = request.min_frame_rate()?;
        let max_frame_rate = request.max_frame_rate()?;
        let min_resolution = request.min_resolution()?;
        let max_resolution = request.max_resolution()?;
        let min_bit_rate = request.min_bit_rate()?;
        let max_bit_rate = request.max_bit_rate()?;
        let key_frame_interval = request.key_frame_interval()?;
        let watermark = request.watermark_enabled()?;
        let osd = request.osd_enabled()?;

        let min_w = min_resolution.width()?;
        let min_h = min_resolution.height()?;
        let max_w = max_resolution.width()?;
        let max_h = max_resolution.height()?;

        // CONSTRAINT: stream usage is reserved.
        if matches!(stream_usage, StreamUsageEnum::Internal) {
            return Err(ErrorCode::ConstraintError.into());
        }

        // CONSTRAINT: stream usage must be a known one.
        if !self.config.supported_stream_usages.contains(&stream_usage) {
            return Err(ErrorCode::ConstraintError.into());
        }

        // INVALID_IN_STATE: stream usage absent from the (mutable)
        // priority list — see TC_AVSM_2_7 step 18.
        let in_priorities = self.state.lock(|cell| {
            cell.borrow()
                .stream_usage_priorities
                .contains(&stream_usage)
        });
        if !in_priorities {
            return Err(ErrorCode::InvalidAction.into());
        }

        // CONSTRAINT: codec must appear in RateDistortionTradeOffPoints
        // (TC_AVSM_2_7 keys all subsequent steps off
        // aRateDistortionTradeOffPoints[0].codec).
        if !self
            .config
            .rate_distortion_points
            .iter()
            .any(|p| p.codec == video_codec)
        {
            return Err(ErrorCode::ConstraintError.into());
        }

        // CONSTRAINT: monotonic min ≤ max.
        if min_frame_rate == 0
            || min_frame_rate > max_frame_rate
            || min_bit_rate > max_bit_rate
            || min_w == 0
            || min_h == 0
            || min_w > max_w
            || min_h > max_h
        {
            return Err(ErrorCode::ConstraintError.into());
        }

        // CONSTRAINT: framerate within sensor capability.
        if max_frame_rate > self.config.sensor.max_fps {
            return Err(ErrorCode::ConstraintError.into());
        }

        // CONSTRAINT: resolution within sensor and viewport bounds.
        if max_w > self.config.sensor.sensor_width
            || max_h > self.config.sensor.sensor_height
            || min_w < self.config.min_viewport.0
            || min_h < self.config.min_viewport.1
        {
            return Err(ErrorCode::ConstraintError.into());
        }

        // CONSTRAINT: watermark / OSD only legal if the matching
        // feature is advertised.
        if watermark.is_some() && !self.has_feature(decl::Feature::WATERMARK.bits()) {
            return Err(ErrorCode::ConstraintError.into());
        }
        if osd.is_some() && !self.has_feature(decl::Feature::ON_SCREEN_DISPLAY.bits()) {
            return Err(ErrorCode::ConstraintError.into());
        }

        Ok(VideoStream {
            video_stream_id: 0, // assigned later by alloc_video_id
            stream_usage,
            video_codec,
            min_frame_rate,
            max_frame_rate,
            min_width: min_w,
            min_height: min_h,
            max_width: max_w,
            max_height: max_h,
            min_bit_rate,
            max_bit_rate,
            key_frame_interval,
            watermark_enabled: watermark,
            osd_enabled: osd,
            reference_count: 0,
        })
    }

    /// Idempotency: if an existing stream has byte-for-byte matching
    /// allocation params, return its ID instead of creating a new one
    /// (spec §"Allocation idempotency"). Compares everything except
    /// `video_stream_id` and `reference_count`.
    fn find_matching_existing(&self, candidate: &VideoStream) -> Option<u16> {
        self.state.lock(|cell| {
            cell.borrow().videos.iter().find_map(|s| {
                if s.stream_usage == candidate.stream_usage
                    && s.video_codec == candidate.video_codec
                    && s.min_frame_rate == candidate.min_frame_rate
                    && s.max_frame_rate == candidate.max_frame_rate
                    && s.min_width == candidate.min_width
                    && s.min_height == candidate.min_height
                    && s.max_width == candidate.max_width
                    && s.max_height == candidate.max_height
                    && s.min_bit_rate == candidate.min_bit_rate
                    && s.max_bit_rate == candidate.max_bit_rate
                    && s.key_frame_interval == candidate.key_frame_interval
                    && s.watermark_enabled == candidate.watermark_enabled
                    && s.osd_enabled == candidate.osd_enabled
                {
                    Some(s.video_stream_id)
                } else {
                    None
                }
            })
        })
    }
}

impl<'a, H, const NV: usize, const NA: usize> ClusterAsyncHandler
    for CameraAvStreamHandler<'a, H, NV, NA>
where
    H: CameraAvStreamHooks,
{
    const CLUSTER: Cluster<'static> = Self::CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn max_content_buffer_size(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.config.max_content_buffer_size)
    }

    async fn max_network_bandwidth(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.config.max_network_bandwidth)
    }

    async fn max_concurrent_encoders(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.config.max_concurrent_encoders)
    }

    async fn max_encoded_pixel_rate(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.config.max_encoded_pixel_rate)
    }

    async fn video_sensor_params<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: VideoSensorParamsStructBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .sensor_width(self.config.sensor.sensor_width)?
            .sensor_height(self.config.sensor.sensor_height)?
            .max_fps(self.config.sensor.max_fps)?
            .max_hdrfps(self.config.sensor.max_hdrfps)?
            .end()
    }

    async fn min_viewport_resolution<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: VideoResolutionStructBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .width(self.config.min_viewport.0)?
            .height(self.config.min_viewport.1)?
            .end()
    }

    async fn rate_distortion_trade_off_points<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            RateDistortionTradeOffPointsStructArrayBuilder<P>,
            RateDistortionTradeOffPointsStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(mut b) => {
                for p in self.config.rate_distortion_points {
                    b = write_rate_distortion(b.push()?, p)?;
                }
                b.end()
            }
            ArrayAttributeRead::ReadOne(idx, b) => {
                let Some(p) = self.config.rate_distortion_points.get(idx as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };
                write_rate_distortion(b, p)
            }
            ArrayAttributeRead::ReadNone(b) => b.end(),
        }
    }

    async fn supported_stream_usages<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            ToTLVArrayBuilder<P, StreamUsageEnum>,
            ToTLVBuilder<P, StreamUsageEnum>,
        >,
    ) -> Result<P, Error> {
        read_enum_array(builder, self.config.supported_stream_usages)
    }

    async fn stream_usage_priorities<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            ToTLVArrayBuilder<P, StreamUsageEnum>,
            ToTLVBuilder<P, StreamUsageEnum>,
        >,
    ) -> Result<P, Error> {
        self.ensure_priorities_seeded();
        let snapshot = self.state.lock(|cell| {
            let s = cell.borrow();
            // Avoid holding the lock across builder pushes.
            let mut out: Vec<StreamUsageEnum, MAX_STREAM_USAGES> = Vec::new();
            for u in s.stream_usage_priorities.iter() {
                let _ = out.push(*u);
            }
            out
        });
        read_enum_array(builder, &snapshot)
    }

    async fn allocated_video_streams<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<VideoStreamStructArrayBuilder<P>, VideoStreamStructBuilder<P>>,
    ) -> Result<P, Error> {
        // Snapshot to avoid holding the lock across writer calls.
        let snapshot = self.state.lock(|cell| cell.borrow().videos.clone());
        match builder {
            ArrayAttributeRead::ReadAll(mut b) => {
                for s in snapshot.iter() {
                    b = write_video_stream(b.push()?, s)?;
                }
                b.end()
            }
            ArrayAttributeRead::ReadOne(idx, b) => {
                let Some(s) = snapshot.get(idx as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };
                write_video_stream(b, s)
            }
            ArrayAttributeRead::ReadNone(b) => b.end(),
        }
    }

    // ----- Commands -----

    async fn handle_video_stream_allocate<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: VideoStreamAllocateRequest<'_>,
        response: VideoStreamAllocateResponseBuilder<P>,
    ) -> Result<P, Error> {
        self.ensure_priorities_seeded();
        let mut candidate = self.validate_video_alloc(&request)?;

        // Idempotency.
        if let Some(existing) = self.find_matching_existing(&candidate) {
            return response.video_stream_id(existing)?.end();
        }

        // Capacity. RESOURCE_EXHAUSTED per spec.
        let full = self.state.lock(|cell| cell.borrow().videos.len() >= NV);
        if full {
            return Err(ErrorCode::ResourceExhausted.into());
        }

        // Assign ID and let the application open the encoder.
        candidate.video_stream_id = self.alloc_video_id();
        self.hooks.allocate_video(&candidate).await?;

        // Commit. If push() fails (NV exhausted concurrently) the hooks
        // already returned Ok and we leak a half-open stream — call
        // deallocate to be tidy.
        let pushed = self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.videos.push(candidate).is_ok()
        });
        if !pushed {
            let _ = self.hooks.deallocate_video(candidate.video_stream_id).await;
            return Err(ErrorCode::ResourceExhausted.into());
        }
        ctx.notify_own_attr_changed(AttributeId::AllocatedVideoStreams as _);

        response.video_stream_id(candidate.video_stream_id)?.end()
    }

    async fn handle_video_stream_modify(
        &self,
        ctx: impl InvokeContext,
        request: VideoStreamModifyRequest<'_>,
    ) -> Result<(), Error> {
        let id = request.video_stream_id()?;
        let watermark = request.watermark_enabled()?;
        let osd = request.osd_enabled()?;

        if watermark.is_some() && !self.has_feature(decl::Feature::WATERMARK.bits()) {
            return Err(ErrorCode::ConstraintError.into());
        }
        if osd.is_some() && !self.has_feature(decl::Feature::ON_SCREEN_DISPLAY.bits()) {
            return Err(ErrorCode::ConstraintError.into());
        }

        // Existence check up-front so we can return NOT_FOUND without
        // bothering the hooks.
        let exists = self
            .state
            .lock(|cell| cell.borrow().videos.iter().any(|s| s.video_stream_id == id));
        if !exists {
            return Err(ErrorCode::NotFound.into());
        }

        self.hooks.modify_video(id, watermark, osd).await?;

        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if let Some(row) = state.videos.iter_mut().find(|s| s.video_stream_id == id) {
                if let Some(w) = watermark {
                    row.watermark_enabled = Some(w);
                }
                if let Some(o) = osd {
                    row.osd_enabled = Some(o);
                }
            }
        });
        ctx.notify_own_attr_changed(AttributeId::AllocatedVideoStreams as _);
        Ok(())
    }

    async fn handle_video_stream_deallocate(
        &self,
        ctx: impl InvokeContext,
        request: VideoStreamDeallocateRequest<'_>,
    ) -> Result<(), Error> {
        let id = request.video_stream_id()?;

        // Spec: cannot deallocate a stream still bound to a transport.
        // Map "in use" to INVALID_IN_STATE; "missing" to NOT_FOUND.
        let status = self.state.lock(|cell| {
            let state = cell.borrow();
            match state.videos.iter().find(|s| s.video_stream_id == id) {
                None => Err(ErrorCode::NotFound),
                Some(s) if s.reference_count > 0 => Err(ErrorCode::InvalidAction),
                Some(_) => Ok(()),
            }
        });
        status.map_err(Error::from)?;

        self.hooks.deallocate_video(id).await?;

        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.videos.retain(|s| s.video_stream_id != id);
        });
        ctx.notify_own_attr_changed(AttributeId::AllocatedVideoStreams as _);
        Ok(())
    }

    async fn handle_set_stream_priorities(
        &self,
        ctx: impl InvokeContext,
        request: SetStreamPrioritiesRequest<'_>,
    ) -> Result<(), Error> {
        let new_prio: TLVArray<'_, StreamUsageEnum> = request.stream_priorities()?;

        // Build the new list while validating (a) every entry is in
        // SupportedStreamUsages, (b) no duplicates, (c) it fits.
        let mut buffer: Vec<StreamUsageEnum, MAX_STREAM_USAGES> = Vec::new();
        for entry in new_prio.iter() {
            let usage = entry?;
            if !self.config.supported_stream_usages.contains(&usage) {
                return Err(ErrorCode::ConstraintError.into());
            }
            if buffer.contains(&usage) {
                return Err(ErrorCode::ConstraintError.into());
            }
            buffer
                .push(usage)
                .map_err(|_| Error::from(ErrorCode::ResourceExhausted))?;
        }

        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.stream_usage_priorities.clear();
            for u in buffer.iter() {
                let _ = state.stream_usage_priorities.push(*u);
            }
        });
        ctx.notify_own_attr_changed(AttributeId::StreamUsagePriorities as _);
        Ok(())
    }

    async fn microphone_capabilities<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: AudioCapabilitiesStructBuilder<P>,
    ) -> Result<P, Error> {
        let Some(cfg) = self.config.mic_capabilities else {
            return Err(ErrorCode::InvalidAction.into());
        };
        let b = builder.max_number_of_channels(cfg.max_channels)?;
        let mut codecs = b.supported_codecs()?;
        for codec in cfg.supported_codecs {
            codecs = codecs.push(codec)?;
        }
        let b = codecs.end()?;
        let mut rates = b.supported_sample_rates()?;
        for r in cfg.supported_sample_rates {
            rates = rates.push(r)?;
        }
        let b = rates.end()?;
        let mut depths = b.supported_bit_depths()?;
        for d in cfg.supported_bit_depths {
            depths = depths.push(d)?;
        }
        depths.end()?.end()
    }

    async fn allocated_audio_streams<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<AudioStreamStructArrayBuilder<P>, AudioStreamStructBuilder<P>>,
    ) -> Result<P, Error> {
        let snapshot = self.state.lock(|cell| cell.borrow().audios.clone());
        match builder {
            ArrayAttributeRead::ReadAll(mut b) => {
                for s in snapshot.iter() {
                    b = write_audio_stream(b.push()?, s)?;
                }
                b.end()
            }
            ArrayAttributeRead::ReadOne(idx, b) => {
                let Some(s) = snapshot.get(idx as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };
                write_audio_stream(b, s)
            }
            ArrayAttributeRead::ReadNone(b) => b.end(),
        }
    }

    // ----- Commands deferred to follow-up sessions -----

    async fn handle_audio_stream_allocate<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: AudioStreamAllocateRequest<'_>,
        _response: AudioStreamAllocateResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    async fn handle_audio_stream_deallocate(
        &self,
        _ctx: impl InvokeContext,
        _request: AudioStreamDeallocateRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    async fn handle_snapshot_stream_allocate<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: SnapshotStreamAllocateRequest<'_>,
        _response: SnapshotStreamAllocateResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    async fn handle_snapshot_stream_modify(
        &self,
        _ctx: impl InvokeContext,
        _request: SnapshotStreamModifyRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    async fn handle_snapshot_stream_deallocate(
        &self,
        _ctx: impl InvokeContext,
        _request: SnapshotStreamDeallocateRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    async fn handle_capture_snapshot<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: CaptureSnapshotRequest<'_>,
        _response: CaptureSnapshotResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
}

// -----------------------------------------------------------------------
// Local helpers
// -----------------------------------------------------------------------

fn read_enum_array<P: TLVBuilderParent>(
    builder: ArrayAttributeRead<
        ToTLVArrayBuilder<P, StreamUsageEnum>,
        ToTLVBuilder<P, StreamUsageEnum>,
    >,
    items: &[StreamUsageEnum],
) -> Result<P, Error> {
    match builder {
        ArrayAttributeRead::ReadAll(mut b) => {
            for item in items {
                b = b.push(item)?;
            }
            b.end()
        }
        ArrayAttributeRead::ReadOne(idx, b) => {
            let Some(item) = items.get(idx as usize) else {
                return Err(ErrorCode::ConstraintError.into());
            };
            b.set(item)
        }
        ArrayAttributeRead::ReadNone(b) => b.end(),
    }
}

fn write_video_stream<P: TLVBuilderParent>(
    builder: VideoStreamStructBuilder<P>,
    s: &VideoStream,
) -> Result<P, Error> {
    let b = builder
        .video_stream_id(s.video_stream_id)?
        .stream_usage(s.stream_usage)?
        .video_codec(s.video_codec)?
        .min_frame_rate(s.min_frame_rate)?
        .max_frame_rate(s.max_frame_rate)?;
    let b = b
        .min_resolution()?
        .width(s.min_width)?
        .height(s.min_height)?
        .end()?;
    let b = b
        .max_resolution()?
        .width(s.max_width)?
        .height(s.max_height)?
        .end()?;
    b.min_bit_rate(s.min_bit_rate)?
        .max_bit_rate(s.max_bit_rate)?
        .key_frame_interval(s.key_frame_interval)?
        .watermark_enabled(s.watermark_enabled)?
        .osd_enabled(s.osd_enabled)?
        .reference_count(s.reference_count)?
        .end()
}

fn write_audio_stream<P: TLVBuilderParent>(
    builder: AudioStreamStructBuilder<P>,
    s: &AudioStream,
) -> Result<P, Error> {
    builder
        .audio_stream_id(s.audio_stream_id)?
        .stream_usage(s.stream_usage)?
        .audio_codec(s.audio_codec)?
        .channel_count(s.channel_count)?
        .sample_rate(s.sample_rate)?
        .bit_rate(s.bit_rate)?
        .bit_depth(s.bit_depth)?
        .reference_count(s.reference_count)?
        .end()
}

fn write_rate_distortion<P: TLVBuilderParent>(
    builder: RateDistortionTradeOffPointsStructBuilder<P>,
    p: &RateDistortionPoint,
) -> Result<P, Error> {
    let b = builder.codec(p.codec)?;
    let b = b
        .resolution()?
        .width(p.min_resolution.0)?
        .height(p.min_resolution.1)?
        .end()?;
    b.min_bit_rate(p.min_bit_rate)?.end()
}
