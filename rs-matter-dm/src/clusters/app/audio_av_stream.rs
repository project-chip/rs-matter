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

//! Audio-only handler for the Matter 1.5 Camera AV Stream Management cluster (0x0551).
//!
//! Designed for `DEV_TYPE_AUDIO_DOORBELL` (`0x0141`) endpoints advertising
//! `Feature::AUDIO | Feature::SPEAKER` with zero video/snapshot state bloat.
//! Shares core data structures and serialization helpers with [`super::cam_av_stream`].

use core::cell::RefCell;
use core::future::Future;

use crate::dm::clusters::decl::camera_av_stream_management as decl;
use crate::dm::clusters::decl::globals::StreamUsageEnum;
use crate::dm::{
    ArrayAttributeRead, AttrChangeNotifier, Cluster, Dataver, EndptId, HandlerContext,
    InvokeContext, ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVBuilderParent, TlvError, ToTLVArrayBuilder, ToTLVBuilder};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::{MaybeSend, MaybeSendSync, Notification};
use crate::with;

use super::cam_av_common::{
    build_stream_priorities, read_enum_array, validate_audio_allocate, write_audio_capabilities,
    write_audio_stream, AudioStreamTable, StreamAllocation, MAX_STREAM_USAGES,
};
pub use super::cam_av_common::{
    AudioCapabilitiesConfig, AudioStream, AudioStreamParams, CamAvError,
};
pub use decl::{
    AudioCapabilitiesStructBuilder, AudioCodecEnum, AudioStreamAllocateRequest,
    AudioStreamAllocateResponseBuilder, AudioStreamDeallocateRequest,
    AudioStreamStructArrayBuilder, AudioStreamStructBuilder, ClusterAsyncHandler,
    HandlerAsyncAdaptor, SetStreamPrioritiesRequest, TwoWayTalkSupportTypeEnum,
};

const DEFAULT_OPUS_CODECS: &[AudioCodecEnum] = &[AudioCodecEnum::OPUS];
const DEFAULT_SAMPLE_RATES_HZ: &[u32] = &[16_000, 48_000];
const DEFAULT_BIT_DEPTHS: &[u8] = &[16];
const DEFAULT_USAGES: &[StreamUsageEnum] = &[StreamUsageEnum::LiveView];

/// Configuration for an audio channel's volume range and startup default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AudioLevelConfig {
    pub min_level: u8,
    pub max_level: u8,
    pub default_volume: u8,
}

impl AudioLevelConfig {
    /// Constructs a level configuration, asserting `min_level <= max_level` and
    /// `default_volume` is within bounds.
    pub const fn new(min_level: u8, max_level: u8, default_volume: u8) -> Self {
        core::assert!(min_level <= max_level, "min_level must be <= max_level");
        core::assert!(max_level <= 254, "max_level must be <= 254");
        core::assert!(
            default_volume >= min_level && default_volume <= max_level,
            "default_volume must be within [min_level, max_level]"
        );
        Self {
            min_level,
            max_level,
            default_volume,
        }
    }

    /// Checks whether `value` is within the inclusive `[min_level, max_level]` range.
    pub const fn is_valid(&self, value: u8) -> bool {
        value >= self.min_level && value <= self.max_level
    }
}

/// Static configuration for an [`AudioAvStreamHandler`].
///
/// Contains parameters that remain fixed across reboots: microphone and speaker
/// capabilities, two-way talk support, stream usages, network bandwidth, and
/// volume bounds.
#[derive(Debug, Clone, Copy)]
pub struct AudioAvStreamConfig<'a> {
    /// Reported via `MicrophoneCapabilities`. Describes supported audio codecs,
    /// sample rates, bit depths, and maximum channel count for the microphone.
    pub mic_capabilities: AudioCapabilitiesConfig<'a>,
    /// Reported via `SpeakerCapabilities`. Describes supported audio codecs,
    /// sample rates, bit depths, and maximum channel count for the speaker.
    pub speaker_capabilities: AudioCapabilitiesConfig<'a>,
    /// Reported via `MaxContentBufferSize`. Size in bytes of content buffering
    /// available on the server.
    pub max_content_buffer_size: u32,
    /// Reported via `MaxNetworkBandwidth` (bits per second). Maximum network
    /// bandwidth dedicated to streaming.
    pub max_network_bandwidth: u32,
    /// Reported via `TwoWayTalkSupportType`. Indicates half-duplex or full-duplex
    /// two-way audio talk support.
    pub two_way_talk: TwoWayTalkSupportTypeEnum,
    /// Stable, server-defined list of every stream usage this audio endpoint can
    /// expose. Reported via `SupportedStreamUsages`.
    pub supported_stream_usages: &'a [StreamUsageEnum],
    /// Initial stream usage priority order at boot. Reported via mutable attribute
    /// `StreamUsagePriorities`. Must be a subset or permutation of `supported_stream_usages`.
    pub default_stream_usage_priorities: &'a [StreamUsageEnum],
    /// Inclusive microphone volume range and initial startup volume.
    /// Reported via `MicrophoneMinLevel`, `MicrophoneMaxLevel`, and `MicrophoneVolumeLevel`.
    pub mic_level: AudioLevelConfig,
    /// Inclusive speaker volume range and initial startup volume.
    /// Reported via `SpeakerMinLevel`, `SpeakerMaxLevel`, and `SpeakerVolumeLevel`.
    pub speaker_level: AudioLevelConfig,
}

impl AudioAvStreamConfig<'static> {
    /// Default Matter 1.5 Audio Doorbell profile: mono Opus (`16 kHz` native / `48 kHz` RFC 7587), half-duplex.
    pub const fn opus_16khz_mono() -> Self {
        const CAPS: AudioCapabilitiesConfig<'static> = AudioCapabilitiesConfig {
            max_channels: 1,
            supported_codecs: DEFAULT_OPUS_CODECS,
            supported_sample_rates: DEFAULT_SAMPLE_RATES_HZ,
            supported_bit_depths: DEFAULT_BIT_DEPTHS,
        };
        Self {
            mic_capabilities: CAPS,
            speaker_capabilities: CAPS,
            max_content_buffer_size: 0,
            max_network_bandwidth: 64_000,
            two_way_talk: TwoWayTalkSupportTypeEnum::HalfDuplex,
            supported_stream_usages: DEFAULT_USAGES,
            default_stream_usage_priorities: DEFAULT_USAGES,
            mic_level: AudioLevelConfig::new(0, 100, 75),
            speaker_level: AudioLevelConfig::new(0, 100, 80),
        }
    }
}

/// Application lifecycle callbacks for audio stream allocation and volume changes.
pub trait AudioAvStreamHooks: MaybeSendSync {
    /// Called when a new audio stream entry has been reserved in `AllocatedAudioStreams`.
    ///
    /// Drivers should initialize hardware audio pipelines or codecs for `stream`.
    /// If this hook returns an error, the reserved stream entry is automatically
    /// rolled back from the stream table and the allocation command fails.
    fn on_audio_allocated(
        &self,
        stream: &AudioStream,
    ) -> impl Future<Output = Result<(), CamAvError>> + MaybeSend;

    /// Called when an audio stream has reached a reference count of zero, before removing it
    /// from `AllocatedAudioStreams`. If this hook returns an error, the stream remains allocated
    /// and the command fails.
    fn on_audio_deallocated(
        &self,
        stream_id: u16,
    ) -> impl Future<Output = Result<(), CamAvError>> + MaybeSend;

    /// Called when microphone or speaker volume or mute states change via Matter write attributes.
    fn on_volume_or_mute_changed(
        &self,
        _mic_muted: bool,
        _mic_volume_level: u8,
        _speaker_muted: bool,
        _speaker_volume_level: u8,
    ) -> impl Future<Output = Result<(), CamAvError>> + MaybeSend {
        core::future::ready(Ok(()))
    }
}

impl<T: AudioAvStreamHooks> AudioAvStreamHooks for &T {
    fn on_audio_allocated(
        &self,
        stream: &AudioStream,
    ) -> impl Future<Output = Result<(), CamAvError>> + MaybeSend {
        (*self).on_audio_allocated(stream)
    }

    fn on_audio_deallocated(
        &self,
        stream_id: u16,
    ) -> impl Future<Output = Result<(), CamAvError>> + MaybeSend {
        (*self).on_audio_deallocated(stream_id)
    }

    fn on_volume_or_mute_changed(
        &self,
        mic_muted: bool,
        mic_volume_level: u8,
        speaker_muted: bool,
        speaker_volume_level: u8,
    ) -> impl Future<Output = Result<(), CamAvError>> + MaybeSend {
        (*self).on_volume_or_mute_changed(
            mic_muted,
            mic_volume_level,
            speaker_muted,
            speaker_volume_level,
        )
    }
}

/// Audio-only handler for Cluster `0x0551` (`CameraAVStreamManagement`).
pub struct AudioAvStreamHandler<'a, H: AudioAvStreamHooks, const NA: usize> {
    dataver: Dataver,
    endpoint_id: EndptId,
    config: AudioAvStreamConfig<'a>,
    hooks: H,
    state: Mutex<RefCell<State<NA>>>,
    notify_change: Notification,
}

impl<'a, H: AudioAvStreamHooks, const NA: usize> AudioAvStreamHandler<'a, H, NA> {
    pub const CLUSTER: Cluster<'static> = decl::FULL_CLUSTER
        .with_revision(1)
        .with_features(decl::Feature::AUDIO.bits() | decl::Feature::SPEAKER.bits())
        .with_attrs(with!(system;
            decl::AttributeId::MaxContentBufferSize
                | decl::AttributeId::MicrophoneCapabilities
                | decl::AttributeId::SpeakerCapabilities
                | decl::AttributeId::TwoWayTalkSupport
                | decl::AttributeId::MaxNetworkBandwidth
                | decl::AttributeId::SupportedStreamUsages
                | decl::AttributeId::AllocatedAudioStreams
                | decl::AttributeId::StreamUsagePriorities
                | decl::AttributeId::SpeakerMuted
                | decl::AttributeId::SpeakerVolumeLevel
                | decl::AttributeId::SpeakerMaxLevel
                | decl::AttributeId::SpeakerMinLevel
                | decl::AttributeId::MicrophoneMuted
                | decl::AttributeId::MicrophoneVolumeLevel
                | decl::AttributeId::MicrophoneMaxLevel
                | decl::AttributeId::MicrophoneMinLevel
        ))
        .with_cmds(with!(
            decl::CommandId::AudioStreamAllocate
                | decl::CommandId::AudioStreamDeallocate
                | decl::CommandId::SetStreamPriorities
        ));

    pub const fn new(
        dataver: Dataver,
        endpoint_id: EndptId,
        config: AudioAvStreamConfig<'a>,
        hooks: H,
    ) -> Self {
        Self {
            dataver,
            endpoint_id,
            config,
            hooks,
            state: Mutex::new(RefCell::new(State::new(
                config.mic_level.default_volume,
                config.speaker_level.default_volume,
            ))),
            notify_change: Notification::new(),
        }
    }

    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }

    pub const fn endpoint_id(&self) -> EndptId {
        self.endpoint_id
    }

    pub async fn allocate_stream(&self, params: &AudioStreamParams) -> Result<u16, Error> {
        let priorities = self.get_seeded_priorities();
        validate_audio_allocate(params, &self.config.mic_capabilities, &priorities)?;

        let allocation = self.with_state_mut(|s| s.table.find_or_create(params))?;
        let stream = *allocation.stream();

        if let StreamAllocation::Created(_) = allocation {
            if let Err(e) = self.hooks.on_audio_allocated(&stream).await {
                self.with_state_mut(|s| {
                    s.table.remove(stream.audio_stream_id);
                });
                return Err(e.into());
            }
            self.dataver.changed();
            self.notify_change.notify();
        }

        Ok(stream.audio_stream_id)
    }

    pub async fn deallocate_stream(&self, audio_stream_id: u16) -> Result<(), Error> {
        self.with_state(|s| s.table.can_deallocate(audio_stream_id))?;
        self.hooks
            .on_audio_deallocated(audio_stream_id)
            .await
            .map_err(Error::from)?;
        self.with_state_mut(|s| s.table.deallocate(audio_stream_id))?;
        self.dataver.changed();
        self.notify_change.notify();
        Ok(())
    }

    pub fn acquire_audio(&self, audio_stream_id: u16) -> Result<(), Error> {
        self.with_state_mut(|s| s.table.acquire(audio_stream_id))?;
        self.dataver.changed();
        self.notify_change.notify();
        Ok(())
    }

    pub fn release_audio(&self, audio_stream_id: u16) -> Result<(), Error> {
        self.with_state_mut(|s| s.table.release(audio_stream_id))?;
        self.dataver.changed();
        self.notify_change.notify();
        Ok(())
    }

    /// Background notification loop forwarding out-of-band audio allocation changes to Matter subscribers.
    pub async fn run_notify(&self, notifier: impl AttrChangeNotifier) -> Result<(), Error> {
        loop {
            self.notify_change.wait().await;
            notifier.notify_attr_changed(
                self.endpoint_id,
                Self::CLUSTER.id,
                decl::AttributeId::AllocatedAudioStreams as _,
            );
        }
    }

    /// Pre-seeds an audio stream into `AllocatedAudioStreams` at boot without calling hooks.
    pub fn add_preallocated_audio(&self, stream: AudioStream) -> Result<u16, Error> {
        let id = self.with_state_mut(|s| s.table.add_preallocated(stream))?;
        self.dataver.changed();
        Ok(id)
    }

    /// Snapshot the current set of allocated audio streams.
    pub fn audio_streams(&self) -> Vec<AudioStream, NA> {
        self.with_state(|s| s.table.snapshot())
    }

    #[cfg(test)]
    pub const fn config(&self) -> &AudioAvStreamConfig<'a> {
        &self.config
    }

    #[cfg(test)]
    pub const fn hooks(&self) -> &H {
        &self.hooks
    }

    // --- Private helpers ---

    fn get_seeded_priorities(&self) -> Vec<StreamUsageEnum, MAX_STREAM_USAGES> {
        self.with_state_mut(|state| {
            if state.stream_usage_priorities.is_empty() {
                for u in self.config.default_stream_usage_priorities {
                    let _ = state.stream_usage_priorities.push(*u);
                }
            }
            state.stream_usage_priorities.clone()
        })
    }

    fn with_state<R>(&self, f: impl FnOnce(&State<NA>) -> R) -> R {
        self.state.lock(|cell| f(&cell.borrow()))
    }

    fn with_state_mut<R>(&self, f: impl FnOnce(&mut State<NA>) -> R) -> R {
        self.state.lock(|cell| f(&mut cell.borrow_mut()))
    }

    fn speaker_muted(&self) -> bool {
        self.with_state(|s| s.volume.speaker_muted)
    }

    fn speaker_volume(&self) -> u8 {
        self.with_state(|s| s.volume.speaker_volume)
    }

    fn mic_muted(&self) -> bool {
        self.with_state(|s| s.volume.mic_muted)
    }

    fn mic_volume(&self) -> u8 {
        self.with_state(|s| s.volume.mic_volume)
    }

    #[inline]
    fn validate<T>(&self, field: Result<T, TlvError>) -> Result<T, Error> {
        field.map_err(|_| ErrorCode::ConstraintError.into())
    }
}

impl<'a, H: AudioAvStreamHooks, const NA: usize> ClusterAsyncHandler
    for AudioAvStreamHandler<'a, H, NA>
{
    const CLUSTER: Cluster<'static> = Self::CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        self.run_notify(ctx).await
    }

    async fn max_content_buffer_size(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.config.max_content_buffer_size)
    }

    async fn max_network_bandwidth(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.config.max_network_bandwidth)
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
        let prios = self.get_seeded_priorities();
        read_enum_array(builder, &prios)
    }

    async fn microphone_capabilities<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: AudioCapabilitiesStructBuilder<P>,
    ) -> Result<P, Error> {
        write_audio_capabilities(builder, &self.config.mic_capabilities)
    }

    async fn speaker_capabilities<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: AudioCapabilitiesStructBuilder<P>,
    ) -> Result<P, Error> {
        write_audio_capabilities(builder, &self.config.speaker_capabilities)
    }

    async fn two_way_talk_support(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<TwoWayTalkSupportTypeEnum, Error> {
        Ok(self.config.two_way_talk)
    }

    async fn allocated_audio_streams<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<AudioStreamStructArrayBuilder<P>, AudioStreamStructBuilder<P>>,
    ) -> Result<P, Error> {
        let snapshot = self.with_state(|s| s.table.snapshot());
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

    async fn speaker_muted(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        Ok(self.speaker_muted())
    }

    async fn speaker_volume_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.speaker_volume())
    }

    async fn speaker_max_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.config.speaker_level.max_level)
    }

    async fn speaker_min_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.config.speaker_level.min_level)
    }

    async fn microphone_muted(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        Ok(self.mic_muted())
    }

    async fn microphone_volume_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.mic_volume())
    }

    async fn microphone_max_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.config.mic_level.max_level)
    }

    async fn microphone_min_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.config.mic_level.min_level)
    }

    async fn set_speaker_muted(&self, ctx: impl WriteContext, value: bool) -> Result<(), Error> {
        let v = self.with_state(|s| s.volume);
        self.hooks
            .on_volume_or_mute_changed(v.mic_muted, v.mic_volume, value, v.speaker_volume)
            .await?;
        self.with_state_mut(|s| s.volume.speaker_muted = value);
        self.dataver.changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn set_speaker_volume_level(
        &self,
        ctx: impl WriteContext,
        value: u8,
    ) -> Result<(), Error> {
        if !self.config.speaker_level.is_valid(value) {
            return Err(ErrorCode::ConstraintError.into());
        }
        let v = self.with_state(|s| s.volume);
        self.hooks
            .on_volume_or_mute_changed(v.mic_muted, v.mic_volume, v.speaker_muted, value)
            .await?;
        self.with_state_mut(|s| s.volume.speaker_volume = value);
        self.dataver.changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn set_microphone_muted(&self, ctx: impl WriteContext, value: bool) -> Result<(), Error> {
        let v = self.with_state(|s| s.volume);
        self.hooks
            .on_volume_or_mute_changed(value, v.mic_volume, v.speaker_muted, v.speaker_volume)
            .await?;
        self.with_state_mut(|s| s.volume.mic_muted = value);
        self.dataver.changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn set_microphone_volume_level(
        &self,
        ctx: impl WriteContext,
        value: u8,
    ) -> Result<(), Error> {
        if !self.config.mic_level.is_valid(value) {
            return Err(ErrorCode::ConstraintError.into());
        }
        let v = self.with_state(|s| s.volume);
        self.hooks
            .on_volume_or_mute_changed(v.mic_muted, value, v.speaker_muted, v.speaker_volume)
            .await?;
        self.with_state_mut(|s| s.volume.mic_volume = value);
        self.dataver.changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn handle_audio_stream_allocate<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        request: AudioStreamAllocateRequest<'_>,
        response: AudioStreamAllocateResponseBuilder<P>,
    ) -> Result<P, Error> {
        let params = AudioStreamParams::new(
            self.validate(request.stream_usage())?,
            self.validate(request.audio_codec())?,
            self.validate(request.channel_count())?,
            self.validate(request.sample_rate())?,
            self.validate(request.bit_rate())?,
            self.validate(request.bit_depth())?,
        );
        let stream_id = self.allocate_stream(&params).await?;
        response.audio_stream_id(stream_id)?.end()
    }

    async fn handle_audio_stream_deallocate(
        &self,
        _ctx: impl InvokeContext,
        request: AudioStreamDeallocateRequest<'_>,
    ) -> Result<(), Error> {
        let stream_id = self.validate(request.audio_stream_id())?;
        self.deallocate_stream(stream_id).await
    }

    async fn handle_video_stream_allocate<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: decl::VideoStreamAllocateRequest<'_>,
        _response: decl::VideoStreamAllocateResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_video_stream_modify(
        &self,
        _ctx: impl InvokeContext,
        _request: decl::VideoStreamModifyRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_video_stream_deallocate(
        &self,
        _ctx: impl InvokeContext,
        _request: decl::VideoStreamDeallocateRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_snapshot_stream_allocate<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: decl::SnapshotStreamAllocateRequest<'_>,
        _response: decl::SnapshotStreamAllocateResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_snapshot_stream_modify(
        &self,
        _ctx: impl InvokeContext,
        _request: decl::SnapshotStreamModifyRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_snapshot_stream_deallocate(
        &self,
        _ctx: impl InvokeContext,
        _request: decl::SnapshotStreamDeallocateRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_set_stream_priorities(
        &self,
        ctx: impl InvokeContext,
        request: SetStreamPrioritiesRequest<'_>,
    ) -> Result<(), Error> {
        let any_allocated = self.with_state(|s| !s.table.is_empty());
        if any_allocated {
            return Err(ErrorCode::InvalidInState.into());
        }
        let priorities = self.validate(request.stream_priorities())?;
        let new_prios = build_stream_priorities(
            priorities.iter().map(|item| self.validate(item)),
            self.config.supported_stream_usages,
        )?;
        self.with_state_mut(|s| {
            s.stream_usage_priorities = new_prios;
        });
        self.dataver.changed();
        ctx.notify_own_attr_changed(decl::AttributeId::StreamUsagePriorities as _);
        Ok(())
    }

    async fn handle_capture_snapshot<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: decl::CaptureSnapshotRequest<'_>,
        _response: decl::CaptureSnapshotResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::CommandNotFound.into())
    }
}

/// Internal volume and mute state bundle for microphone and speaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct VolumeState {
    mic_muted: bool,
    mic_volume: u8,
    speaker_muted: bool,
    speaker_volume: u8,
}

impl VolumeState {
    const fn new(mic_default_volume: u8, speaker_default_volume: u8) -> Self {
        Self {
            mic_muted: false,
            mic_volume: mic_default_volume,
            speaker_muted: false,
            speaker_volume: speaker_default_volume,
        }
    }
}

struct State<const NA: usize> {
    table: AudioStreamTable<NA>,
    stream_usage_priorities: Vec<StreamUsageEnum, MAX_STREAM_USAGES>,
    volume: VolumeState,
}

impl<const NA: usize> State<NA> {
    const fn new(mic_default_volume: u8, speaker_default_volume: u8) -> Self {
        Self {
            table: AudioStreamTable::new(),
            stream_usage_priorities: Vec::new(),
            volume: VolumeState::new(mic_default_volume, speaker_default_volume),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::*;

    struct AudioAvStreamHooksMock {
        allocated: Cell<u16>,
        deallocated: Cell<u16>,
        last_volumes: Cell<(bool, u8, bool, u8)>,
        should_fail_deallocate: Cell<bool>,
    }

    impl AudioAvStreamHooksMock {
        const fn new() -> Self {
            Self {
                allocated: Cell::new(0),
                deallocated: Cell::new(0),
                last_volumes: Cell::new((false, 0, false, 0)),
                should_fail_deallocate: Cell::new(false),
            }
        }
    }

    impl AudioAvStreamHooks for AudioAvStreamHooksMock {
        async fn on_audio_allocated(&self, stream: &AudioStream) -> Result<(), CamAvError> {
            self.allocated.set(stream.audio_stream_id);
            Ok(())
        }

        async fn on_audio_deallocated(&self, stream_id: u16) -> Result<(), CamAvError> {
            if self.should_fail_deallocate.get() {
                return Err(CamAvError::Failure);
            }
            self.deallocated.set(stream_id);
            Ok(())
        }

        async fn on_volume_or_mute_changed(
            &self,
            mic_muted: bool,
            mic_vol: u8,
            spk_muted: bool,
            spk_vol: u8,
        ) -> Result<(), CamAvError> {
            self.last_volumes
                .set((mic_muted, mic_vol, spk_muted, spk_vol));
            Ok(())
        }
    }

    #[test]
    fn cluster_preserves_system_attributes_and_audio_only_feature_bits() {
        // Arrange
        let cluster = AudioAvStreamHandler::<AudioAvStreamHooksMock, 2>::CLUSTER;

        // Act
        let features = cluster.feature_map;
        let has_feature_map_attr = cluster.attribute(0xFFFC).is_some();
        let has_attr_list = cluster.attribute(0xFFFB).is_some();
        let has_max_buf = cluster
            .attribute(decl::AttributeId::MaxContentBufferSize as _)
            .is_some();
        let has_bandwidth = cluster
            .attribute(decl::AttributeId::MaxNetworkBandwidth as _)
            .is_some();
        let has_usages = cluster
            .attribute(decl::AttributeId::SupportedStreamUsages as _)
            .is_some();
        let has_priorities = cluster
            .attribute(decl::AttributeId::StreamUsagePriorities as _)
            .is_some();
        let has_alloc_cmd = cluster
            .command(decl::CommandId::AudioStreamAllocate as _)
            .is_some();
        let has_dealloc_cmd = cluster
            .command(decl::CommandId::AudioStreamDeallocate as _)
            .is_some();
        let has_set_priorities_cmd = cluster
            .command(decl::CommandId::SetStreamPriorities as _)
            .is_some();

        // Assert
        assert!(has_feature_map_attr);
        assert!(has_attr_list);
        assert!(has_max_buf);
        assert!(has_bandwidth);
        assert!(has_usages);
        assert!(has_priorities);
        assert!(has_alloc_cmd);
        assert!(has_dealloc_cmd);
        assert!(has_set_priorities_cmd);
        assert_eq!(
            features,
            (decl::Feature::AUDIO | decl::Feature::SPEAKER).bits()
        );
    }

    fn test_params(
        usage: StreamUsageEnum,
        codec: AudioCodecEnum,
        bit_rate: u32,
    ) -> AudioStreamParams {
        AudioStreamParams::new(usage, codec, 1, 16_000, bit_rate, 16)
    }

    #[test]
    fn allocate_stream_rejects_non_opus_and_notifies_hooks_for_opus() {
        futures_lite::future::block_on(async {
            // Arrange
            let handler = AudioAvStreamHandler::<_, 2>::new(
                Dataver::new(1),
                1,
                AudioAvStreamConfig::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );

            // Act
            let rejected = handler
                .allocate_stream(&test_params(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::AACLC,
                    24_000,
                ))
                .await;
            let allocated_id = handler
                .allocate_stream(&test_params(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    24_000,
                ))
                .await
                .expect("Opus allocation succeeds");

            // Assert
            assert_eq!(
                rejected.unwrap_err().code(),
                ErrorCode::DynamicConstraintError
            );
            assert_eq!(allocated_id, 1);
            assert_eq!(handler.hooks().allocated.get(), 1);
        });
    }

    #[test]
    fn allocate_stream_wraps_after_counter_overflows() {
        futures_lite::future::block_on(async {
            // Arrange
            let handler = AudioAvStreamHandler::<_, 3>::new(
                Dataver::new(1),
                1,
                AudioAvStreamConfig::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );
            handler.with_state_mut(|s| s.table.set_next_id(u16::MAX));
            let max_id = handler
                .allocate_stream(&test_params(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    25_000,
                ))
                .await
                .expect("max ID allocation succeeds");
            handler
                .deallocate_stream(max_id)
                .await
                .expect("max ID deallocation succeeds");

            // Act
            let wrapped_id = handler
                .allocate_stream(&test_params(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    26_000,
                ))
                .await
                .expect("allocation after wrap succeeds");

            // Assert
            assert_eq!(max_id, u16::MAX);
            assert_eq!(wrapped_id, 1);
        });
    }

    #[test]
    fn acquire_audio_rejects_reference_count_overflow() {
        futures_lite::future::block_on(async {
            // Arrange
            let handler = AudioAvStreamHandler::<_, 1>::new(
                Dataver::new(1),
                1,
                AudioAvStreamConfig::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );
            let id = handler
                .allocate_stream(&test_params(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    24_000,
                ))
                .await
                .expect("allocation succeeds");
            for _ in 0..u8::MAX {
                handler
                    .acquire_audio(id)
                    .expect("reference count increments");
            }

            // Act
            let overflow = handler.acquire_audio(id);
            for _ in 0..(u8::MAX - 1) {
                handler
                    .release_audio(id)
                    .expect("reference count decrements");
            }
            let still_blocked = handler.deallocate_stream(id).await;
            handler.release_audio(id).expect("last reference releases");
            let freed = handler.deallocate_stream(id).await;

            // Assert
            assert_eq!(overflow.unwrap_err().code(), ErrorCode::ResourceExhausted);
            assert_eq!(still_blocked.unwrap_err().code(), ErrorCode::InvalidInState);
            assert!(freed.is_ok());
        });
    }

    #[test]
    fn ref_counted_audio_stream_blocks_deallocation_while_webrtc_session_bound() {
        futures_lite::future::block_on(async {
            // Arrange
            let handler = AudioAvStreamHandler::<_, 2>::new(
                Dataver::new(1),
                1,
                AudioAvStreamConfig::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );
            let id = handler
                .allocate_stream(&test_params(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    24_000,
                ))
                .await
                .expect("allocate succeeds");
            handler.acquire_audio(id).expect("acquire succeeds");

            // Act
            let blocked = handler.deallocate_stream(id).await;
            handler.release_audio(id).expect("release succeeds");
            let freed = handler.deallocate_stream(id).await;

            // Assert
            assert_eq!(blocked.unwrap_err().code(), ErrorCode::InvalidInState);
            assert!(freed.is_ok());
            assert_eq!(handler.hooks().deallocated.get(), id);
        });
    }

    #[test]
    fn allocate_stream_enforces_spec_usage_checks() {
        futures_lite::future::block_on(async {
            let handler = AudioAvStreamHandler::<_, 2>::new(
                Dataver::new(1),
                1,
                AudioAvStreamConfig::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );

            // 1. Internal usage must be rejected with ConstraintError
            let internal_err = handler
                .allocate_stream(&test_params(
                    StreamUsageEnum::Internal,
                    AudioCodecEnum::OPUS,
                    24_000,
                ))
                .await
                .unwrap_err();
            assert_eq!(internal_err.code(), ErrorCode::ConstraintError);

            // 2. Usage not in StreamUsagePriorities must be rejected with InvalidInState
            let not_in_prios = handler
                .allocate_stream(&test_params(
                    StreamUsageEnum::Recording,
                    AudioCodecEnum::OPUS,
                    24_000,
                ))
                .await
                .unwrap_err();
            assert_eq!(not_in_prios.code(), ErrorCode::InvalidInState);
        });
    }

    #[test]
    fn separate_mic_and_speaker_capabilities_and_volume_ranges() {
        futures_lite::future::block_on(async {
            const MIC_CAPS: AudioCapabilitiesConfig<'static> = AudioCapabilitiesConfig {
                max_channels: 1,
                supported_codecs: &[AudioCodecEnum::OPUS],
                supported_sample_rates: &[16_000],
                supported_bit_depths: &[16],
            };
            const SPK_CAPS: AudioCapabilitiesConfig<'static> = AudioCapabilitiesConfig {
                max_channels: 2,
                supported_codecs: &[AudioCodecEnum::OPUS, AudioCodecEnum::AACLC],
                supported_sample_rates: &[16_000, 48_000],
                supported_bit_depths: &[16, 24],
            };

            let config = AudioAvStreamConfig {
                mic_capabilities: MIC_CAPS,
                speaker_capabilities: SPK_CAPS,
                max_content_buffer_size: 4096,
                max_network_bandwidth: 128_000,
                two_way_talk: TwoWayTalkSupportTypeEnum::FullDuplex,
                supported_stream_usages: &[StreamUsageEnum::LiveView, StreamUsageEnum::Recording],
                default_stream_usage_priorities: &[StreamUsageEnum::LiveView],
                mic_level: AudioLevelConfig::new(10, 90, 50),
                speaker_level: AudioLevelConfig::new(20, 80, 60),
            };

            let handler = AudioAvStreamHandler::<_, 2>::new(
                Dataver::new(1),
                1,
                config,
                AudioAvStreamHooksMock::new(),
            );

            assert_eq!(handler.config().max_content_buffer_size, 4096);
            assert_eq!(handler.config().mic_capabilities.max_channels, 1);
            assert_eq!(handler.config().speaker_capabilities.max_channels, 2);
            assert_eq!(handler.config().mic_capabilities.supported_codecs.len(), 1);
            assert_eq!(
                handler.config().speaker_capabilities.supported_codecs.len(),
                2
            );
        });
    }

    #[test]
    fn out_of_band_audio_lifecycle_notifies_subscribers_via_run_notify() {
        use crate::dm::clusters::app::test_util::RecordingNotifier;
        use crate::dm::AttrId;

        futures_lite::future::block_on(async {
            let handler = AudioAvStreamHandler::<_, 2>::new(
                Dataver::new(1),
                1,
                AudioAvStreamConfig::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );

            let notifier = RecordingNotifier::default();
            let mut run_fut = core::pin::pin!(handler.run_notify(&notifier));

            let id = handler
                .allocate_stream(&test_params(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    24_000,
                ))
                .await
                .expect("allocate succeeds");

            let polled0 = futures_lite::future::poll_once(&mut run_fut).await;
            assert!(polled0.is_none());
            let notifs0 = notifier.take();
            assert_eq!(notifs0.len(), 1);
            assert_eq!(
                notifs0[0].2,
                decl::AttributeId::AllocatedAudioStreams as AttrId
            );

            handler.acquire_audio(id).expect("acquire succeeds");
            let polled = futures_lite::future::poll_once(&mut run_fut).await;
            assert!(polled.is_none(), "run loops indefinitely");

            let notifications = notifier.take();
            assert_eq!(notifications.len(), 1);
            assert_eq!(notifications[0].0, 1);
            assert_eq!(
                notifications[0].1,
                AudioAvStreamHandler::<AudioAvStreamHooksMock, 2>::CLUSTER.id
            );
            assert_eq!(
                notifications[0].2,
                decl::AttributeId::AllocatedAudioStreams as AttrId
            );

            handler.release_audio(id).expect("release succeeds");
            let polled2 = futures_lite::future::poll_once(&mut run_fut).await;
            assert!(polled2.is_none());

            let notifications2 = notifier.take();
            assert_eq!(notifications2.len(), 1);
            assert_eq!(
                notifications2[0].2,
                decl::AttributeId::AllocatedAudioStreams as AttrId
            );

            handler
                .deallocate_stream(id)
                .await
                .expect("deallocate succeeds");
            let polled3 = futures_lite::future::poll_once(&mut run_fut).await;
            assert!(polled3.is_none());

            let notifications3 = notifier.take();
            assert_eq!(notifications3.len(), 1);
            assert_eq!(
                notifications3[0].2,
                decl::AttributeId::AllocatedAudioStreams as AttrId
            );
        });
    }

    #[test]
    fn audio_level_config_valid_and_bounds_check() {
        let cfg = AudioLevelConfig::new(10, 90, 50);
        assert_eq!(cfg.min_level, 10);
        assert_eq!(cfg.max_level, 90);
        assert_eq!(cfg.default_volume, 50);

        assert!(!cfg.is_valid(9));
        assert!(cfg.is_valid(10));
        assert!(cfg.is_valid(50));
        assert!(cfg.is_valid(90));
        assert!(!cfg.is_valid(91));
    }

    #[test]
    #[should_panic(expected = "min_level must be <= max_level")]
    fn audio_level_config_rejects_inverted_range() {
        AudioLevelConfig::new(90, 10, 50);
    }

    #[test]
    #[should_panic(expected = "default_volume must be within [min_level, max_level]")]
    fn audio_level_config_rejects_default_below_min() {
        AudioLevelConfig::new(20, 80, 10);
    }

    #[test]
    #[should_panic(expected = "default_volume must be within [min_level, max_level]")]
    fn audio_level_config_rejects_default_above_max() {
        AudioLevelConfig::new(20, 80, 85);
    }

    #[test]
    #[should_panic(expected = "max_level must be <= 254")]
    fn audio_level_config_rejects_max_level_exceeding_254() {
        AudioLevelConfig::new(0, 255, 50);
    }

    #[test]
    fn audio_stream_table_encapsulation_and_get() {
        let mut table = AudioStreamTable::<2>::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert_eq!(table.as_slice().len(), 0);
        assert_eq!(table.snapshot().len(), 0);
        assert!(table.get(1).is_none());

        let params = AudioStreamParams::new(
            StreamUsageEnum::LiveView,
            AudioCodecEnum::OPUS,
            1,
            16_000,
            64_000,
            16,
        );
        assert!(table.find(&params).is_none());
        let allocated = table.create(&params).unwrap();
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.as_slice()[0].audio_stream_id,
            allocated.audio_stream_id
        );
        assert_eq!(
            table.snapshot()[0].audio_stream_id,
            allocated.audio_stream_id
        );
        assert_eq!(
            table
                .get(allocated.audio_stream_id)
                .unwrap()
                .audio_stream_id,
            allocated.audio_stream_id
        );
        assert!(table.get(999).is_none());

        // Finding matching params returns existing stream
        let found = table.find(&params).unwrap();
        assert_eq!(found.audio_stream_id, allocated.audio_stream_id);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn audio_stream_table_acquire_release_deallocate() {
        let mut table = AudioStreamTable::<2>::new();
        let params = AudioStreamParams::new(
            StreamUsageEnum::LiveView,
            AudioCodecEnum::OPUS,
            1,
            16_000,
            64_000,
            16,
        );
        let allocated = table.create(&params).unwrap();
        let id = allocated.audio_stream_id;

        table.acquire(id).unwrap();
        assert_eq!(table.get(id).unwrap().reference_count, 1);

        // Cannot deallocate referenced stream
        let err = table.deallocate(id).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInState);

        table.release(id).unwrap();
        assert_eq!(table.get(id).unwrap().reference_count, 0);

        table.deallocate(id).unwrap();
        assert!(table.is_empty());
        assert!(table.get(id).is_none());

        // Deallocating non-existent returns NotFound
        let err = table.deallocate(id).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[test]
    fn audio_stream_table_remove() {
        let mut table = AudioStreamTable::<2>::new();
        let params = AudioStreamParams::new(
            StreamUsageEnum::LiveView,
            AudioCodecEnum::OPUS,
            1,
            16_000,
            64_000,
            16,
        );
        let allocated = table.create(&params).unwrap();
        let id = allocated.audio_stream_id;
        assert_eq!(table.len(), 1);

        assert!(table.remove(id).is_some());
        assert!(table.is_empty());
        assert!(table.get(id).is_none());

        // Removal of unknown id returns None
        assert!(table.remove(999).is_none());
    }

    #[test]
    fn audio_stream_table_next_stream_id_skips_in_use_ids() {
        let mut table = AudioStreamTable::<4>::new();
        // Pre-allocate stream 1 explicitly
        let pre_stream = AudioStream {
            audio_stream_id: 1,
            stream_usage: StreamUsageEnum::Recording,
            audio_codec: AudioCodecEnum::OPUS,
            channel_count: 1,
            sample_rate: 16_000,
            bit_rate: 64_000,
            bit_depth: 16,
            reference_count: 0,
        };
        table.add_preallocated(pre_stream).unwrap();
        assert_eq!(table.len(), 1);

        // Next allocated stream should skip ID 1 and allocate ID 2
        let params = AudioStreamParams::new(
            StreamUsageEnum::LiveView,
            AudioCodecEnum::OPUS,
            1,
            16_000,
            64_000,
            16,
        );
        let allocated = table.create(&params).unwrap();
        assert_eq!(allocated.audio_stream_id, 2);

        // Wrapping counter also skips active streams
        table.set_next_id(u16::MAX);
        let params3 = AudioStreamParams::new(
            StreamUsageEnum::Analysis,
            AudioCodecEnum::OPUS,
            1,
            16_000,
            64_000,
            16,
        );
        let allocated3 = table.create(&params3).unwrap();
        assert_eq!(allocated3.audio_stream_id, u16::MAX);

        // Next allocation wraps past MAX: skips 1 (in use), skips 2 (in use), assigns 3
        let params4 = AudioStreamParams::new(
            StreamUsageEnum::LiveView,
            AudioCodecEnum::OPUS,
            2,
            16_000,
            64_000,
            16,
        );
        let allocated4 = table.create(&params4).unwrap();
        assert_eq!(allocated4.audio_stream_id, 3);
    }

    #[test]
    fn audio_stream_table_create_fails_when_full() {
        let mut table = AudioStreamTable::<1>::new();
        let params1 = AudioStreamParams::new(
            StreamUsageEnum::LiveView,
            AudioCodecEnum::OPUS,
            1,
            16_000,
            64_000,
            16,
        );
        let params2 = AudioStreamParams::new(
            StreamUsageEnum::Analysis,
            AudioCodecEnum::OPUS,
            1,
            16_000,
            64_000,
            16,
        );
        assert!(table.create(&params1).is_ok());
        let err = table.create(&params2).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceExhausted);
    }

    #[test]
    fn deallocate_stream_preserves_stream_when_hook_fails() {
        futures_lite::future::block_on(async {
            let handler = AudioAvStreamHandler::<_, 2>::new(
                Dataver::new(1),
                1,
                AudioAvStreamConfig::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );

            let id = handler
                .allocate_stream(&test_params(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    24_000,
                ))
                .await
                .expect("allocate succeeds");

            assert_eq!(handler.audio_streams().len(), 1);

            // Configure hook to fail on deallocation
            handler.hooks().should_fail_deallocate.set(true);

            let err = handler.deallocate_stream(id).await.unwrap_err();
            assert_eq!(err.code(), ErrorCode::Failure);

            // Stream must still be present in table because hook failed
            assert_eq!(handler.audio_streams().len(), 1);
            assert_eq!(handler.audio_streams()[0].audio_stream_id, id);

            // Now allow hook to succeed
            handler.hooks().should_fail_deallocate.set(false);
            handler
                .deallocate_stream(id)
                .await
                .expect("deallocate succeeds");
            assert!(handler.audio_streams().is_empty());
        });
    }

    #[test]
    fn deallocate_stream_rejects_internal_stream_with_dynamic_constraint_error() {
        futures_lite::future::block_on(async {
            let handler = AudioAvStreamHandler::<_, 2>::new(
                Dataver::new(1),
                1,
                AudioAvStreamConfig::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );

            let internal_stream = AudioStream {
                audio_stream_id: 10,
                stream_usage: StreamUsageEnum::Internal,
                audio_codec: AudioCodecEnum::OPUS,
                channel_count: 1,
                sample_rate: 16_000,
                bit_rate: 32_000,
                bit_depth: 16,
                reference_count: 0,
            };

            let id = handler
                .add_preallocated_audio(internal_stream)
                .expect("preallocate succeeds");
            assert_eq!(id, 10);

            let err = handler.deallocate_stream(id).await.unwrap_err();
            assert_eq!(err.code(), ErrorCode::DynamicConstraintError);

            // Stream must remain allocated
            assert_eq!(handler.audio_streams().len(), 1);
            assert_eq!(handler.audio_streams()[0].audio_stream_id, id);
        });
    }

    #[test]
    fn allocate_stream_concurrent_tasks_deduplicate_safely() {
        futures_lite::future::block_on(async {
            let handler = AudioAvStreamHandler::<_, 4>::new(
                Dataver::new(1),
                1,
                AudioAvStreamConfig::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );

            let params = test_params(StreamUsageEnum::LiveView, AudioCodecEnum::OPUS, 24_000);

            // Run 4 concurrent allocation requests for identical parameters
            let ((r1, r2), (r3, r4)) = futures_lite::future::zip(
                futures_lite::future::zip(
                    handler.allocate_stream(&params),
                    handler.allocate_stream(&params),
                ),
                futures_lite::future::zip(
                    handler.allocate_stream(&params),
                    handler.allocate_stream(&params),
                ),
            )
            .await;

            let (id1, id2) = (
                r1.expect("allocation 1 succeeds"),
                r2.expect("allocation 2 succeeds"),
            );
            let (id3, id4) = (
                r3.expect("allocation 3 succeeds"),
                r4.expect("allocation 4 succeeds"),
            );

            assert_eq!(
                id1, id2,
                "concurrent allocations must resolve to the same stream ID"
            );
            assert_eq!(id2, id3);
            assert_eq!(id3, id4);

            let streams = handler.audio_streams();
            assert_eq!(streams.len(), 1);
            assert_eq!(streams[0].audio_stream_id, id1);
            assert_eq!(
                streams[0].reference_count, 0,
                "reference count remains 0 until acquired by an active session"
            );
        });
    }

    #[test]
    fn allocate_stream_concurrent_tasks_multiple_distinct_no_collisions() {
        futures_lite::future::block_on(async {
            let handler = AudioAvStreamHandler::<_, 4>::new(
                Dataver::new(1),
                1,
                AudioAvStreamConfig::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );

            let params1 = test_params(StreamUsageEnum::LiveView, AudioCodecEnum::OPUS, 16_000);
            let params2 = test_params(StreamUsageEnum::LiveView, AudioCodecEnum::OPUS, 24_000);
            let params3 = test_params(StreamUsageEnum::LiveView, AudioCodecEnum::OPUS, 32_000);

            let (id1, (id2, id3)) = futures_lite::future::zip(
                handler.allocate_stream(&params1),
                futures_lite::future::zip(
                    handler.allocate_stream(&params2),
                    handler.allocate_stream(&params3),
                ),
            )
            .await;

            let id1 = id1.expect("allocation 1 succeeds");
            let id2 = id2.expect("allocation 2 succeeds");
            let id3 = id3.expect("allocation 3 succeeds");

            assert_ne!(id1, id2, "distinct streams must receive distinct IDs");
            assert_ne!(id2, id3, "distinct streams must receive distinct IDs");
            assert_ne!(id1, id3, "distinct streams must receive distinct IDs");

            let streams = handler.audio_streams();
            assert_eq!(streams.len(), 3);
        });
    }

    #[test]
    fn allocate_stream_concurrent_tasks_capacity_exhaustion() {
        futures_lite::future::block_on(async {
            // Capacity of 2
            let handler = AudioAvStreamHandler::<_, 2>::new(
                Dataver::new(1),
                1,
                AudioAvStreamConfig::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );

            let params1 = test_params(StreamUsageEnum::LiveView, AudioCodecEnum::OPUS, 16_000);
            let params2 = test_params(StreamUsageEnum::LiveView, AudioCodecEnum::OPUS, 24_000);
            let params3 = test_params(StreamUsageEnum::LiveView, AudioCodecEnum::OPUS, 32_000);

            let (r1, (r2, r3)) = futures_lite::future::zip(
                handler.allocate_stream(&params1),
                futures_lite::future::zip(
                    handler.allocate_stream(&params2),
                    handler.allocate_stream(&params3),
                ),
            )
            .await;

            let results = [r1, r2, r3];
            let successes = results.iter().filter(|r| r.is_ok()).count();
            let failures = results.iter().filter(|r| r.is_err()).count();

            assert_eq!(successes, 2, "exactly 2 streams must fit in capacity 2");
            assert_eq!(failures, 1, "excess allocation must fail");
            for err in results.iter().filter_map(|r| r.as_ref().err()) {
                assert_eq!(err.code(), ErrorCode::ResourceExhausted);
            }

            let streams = handler.audio_streams();
            assert_eq!(streams.len(), 2);
        });
    }
}
