/*
 *    Copyright (c) 2026 Project CHIP Authors
 *    Licensed under the Apache License, Version 2.0
 */

//! Audio-only handler for the Matter 1.5 Camera AV Stream Management cluster (0x0551).
//!
//! Designed for `DEV_TYPE_AUDIO_DOORBELL` (`0x0141`) endpoints advertising
//! `Feature::AUDIO | Feature::SPEAKER` with zero video/snapshot state bloat.
//! Shares core data structures and serialization helpers with [`super::cam_av_stream`].

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::dm::clusters::decl::camera_av_stream_management as decl;
use crate::dm::clusters::decl::globals::StreamUsageEnum;
use crate::dm::{ArrayAttributeRead, Cluster, Dataver, InvokeContext, ReadContext, WriteContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVArray, TLVBuilderParent, ToTLVArrayBuilder, ToTLVBuilder};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::{MaybeSend, MaybeSendSync};
use crate::with;

pub use super::cam_av_stream::{AudioStream, CamAvError};
pub use decl::{
    AudioCapabilitiesStructBuilder, AudioCodecEnum, AudioStreamAllocateRequest,
    AudioStreamAllocateResponseBuilder, AudioStreamDeallocateRequest,
    AudioStreamStructArrayBuilder, AudioStreamStructBuilder, CaptureSnapshotRequest,
    CaptureSnapshotResponseBuilder, ClusterAsyncHandler, HandlerAsyncAdaptor,
    RateDistortionTradeOffPointsStructArrayBuilder, RateDistortionTradeOffPointsStructBuilder,
    SetStreamPrioritiesRequest, SnapshotCapabilitiesStructArrayBuilder,
    SnapshotCapabilitiesStructBuilder, SnapshotStreamAllocateRequest,
    SnapshotStreamAllocateResponseBuilder, SnapshotStreamDeallocateRequest,
    SnapshotStreamModifyRequest, SnapshotStreamStructArrayBuilder, SnapshotStreamStructBuilder,
    TwoWayTalkSupportTypeEnum, VideoResolutionStructBuilder, VideoSensorParamsStructBuilder,
    VideoStreamAllocateRequest, VideoStreamAllocateResponseBuilder, VideoStreamDeallocateRequest,
    VideoStreamModifyRequest, VideoStreamStructArrayBuilder, VideoStreamStructBuilder,
};

const DEFAULT_MAX_STREAM_USAGES: usize = 4;
const DEFAULT_OPUS_CODECS: &[AudioCodecEnum] = &[AudioCodecEnum::OPUS];
const DEFAULT_SAMPLE_RATES_HZ: &[u32] = &[16_000, 48_000];
const DEFAULT_BIT_DEPTHS: &[u8] = &[16];
const DEFAULT_USAGES: &[StreamUsageEnum] = &[StreamUsageEnum::LiveView];

/// Static capabilities advertised for both microphone (`AUDIO`) and speaker (`SPEAKER`).
#[derive(Debug, Clone, Copy)]
pub struct AudioEndpointCapabilities<'a> {
    pub max_channels: u8,
    pub supported_codecs: &'a [AudioCodecEnum],
    pub supported_sample_rates: &'a [u32],
    pub supported_bit_depths: &'a [u8],
    pub max_network_bandwidth_kbps: u32,
    pub two_way_talk: TwoWayTalkSupportTypeEnum,
    pub supported_usages: &'a [StreamUsageEnum],
}

impl AudioEndpointCapabilities<'static> {
    /// Default Matter 1.5 Audio Doorbell profile: mono Opus (`16 kHz` native / `48 kHz` RFC 7587), half-duplex.
    pub const fn opus_16khz_mono() -> Self {
        Self {
            max_channels: 1,
            supported_codecs: DEFAULT_OPUS_CODECS,
            supported_sample_rates: DEFAULT_SAMPLE_RATES_HZ,
            supported_bit_depths: DEFAULT_BIT_DEPTHS,
            max_network_bandwidth_kbps: 64,
            two_way_talk: TwoWayTalkSupportTypeEnum::HalfDuplex,
            supported_usages: DEFAULT_USAGES,
        }
    }
}

/// Application callbacks for audio stream lifecycle and gain/mute updates.
pub trait AudioAvStreamHooks: MaybeSendSync {
    fn on_audio_allocated(
        &self,
        stream: &AudioStream,
    ) -> impl Future<Output = Result<(), CamAvError>> + MaybeSend;

    fn on_audio_deallocated(
        &self,
        stream_id: u16,
    ) -> impl Future<Output = Result<(), CamAvError>> + MaybeSend;

    fn on_volume_or_mute_changed(
        &self,
        _mic_muted: bool,
        _mic_volume_level: u8,
        _speaker_muted: bool,
        _speaker_volume_level: u8,
    ) -> impl Future<Output = Result<(), CamAvError>> + MaybeSend {
        async { Ok(()) }
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

struct State<const NA: usize> {
    streams: Vec<AudioStream, NA>,
    stream_usage_priorities: Vec<StreamUsageEnum, DEFAULT_MAX_STREAM_USAGES>,
}

/// Audio-only handler for Cluster `0x0551` (`CameraAVStreamManagement`).
pub struct AudioAvStreamHandler<H: AudioAvStreamHooks, const NA: usize> {
    dataver: Dataver,
    caps: AudioEndpointCapabilities<'static>,
    hooks: H,
    state: Mutex<RefCell<State<NA>>>,
    next_id: Mutex<Cell<u16>>,
    mic_muted: AtomicBool,
    mic_volume: AtomicU8,
    speaker_muted: AtomicBool,
    speaker_volume: AtomicU8,
}

impl<H: AudioAvStreamHooks, const NA: usize> AudioAvStreamHandler<H, NA> {
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
            decl::CommandId::AudioStreamAllocate | decl::CommandId::AudioStreamDeallocate
        ));

    pub fn new(dataver: Dataver, caps: AudioEndpointCapabilities<'static>, hooks: H) -> Self {
        let mut priorities = Vec::new();
        for usage in caps.supported_usages {
            let _ = priorities.push(*usage);
        }

        Self {
            dataver,
            caps,
            hooks,
            state: Mutex::new(RefCell::new(State {
                streams: Vec::new(),
                stream_usage_priorities: priorities,
            })),
            next_id: Mutex::new(Cell::new(1)),
            mic_muted: AtomicBool::new(false),
            mic_volume: AtomicU8::new(75),
            speaker_muted: AtomicBool::new(false),
            speaker_volume: AtomicU8::new(80),
        }
    }

    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }

    pub const fn hooks(&self) -> &H {
        &self.hooks
    }

    pub async fn allocate_stream(
        &self,
        stream_usage: StreamUsageEnum,
        audio_codec: AudioCodecEnum,
        channel_count: u8,
        sample_rate: u32,
        bit_rate: u32,
        bit_depth: u8,
    ) -> Result<u16, Error> {
        if !self.caps.supported_usages.contains(&stream_usage) {
            return Err(ErrorCode::ConstraintError.into());
        }
        if !self.caps.supported_codecs.contains(&audio_codec)
            || channel_count == 0
            || channel_count > self.caps.max_channels
            || !self.caps.supported_sample_rates.contains(&sample_rate)
            || !self.caps.supported_bit_depths.contains(&bit_depth)
            || bit_rate == 0
        {
            return Err(ErrorCode::DynamicConstraintError.into());
        }

        if let Some(existing_id) = self.state.lock(|cell| {
            cell.borrow().streams.iter().find_map(|s| {
                if s.stream_usage == stream_usage
                    && s.audio_codec == audio_codec
                    && s.channel_count == channel_count
                    && s.sample_rate == sample_rate
                    && s.bit_rate == bit_rate
                    && s.bit_depth == bit_depth
                {
                    Some(s.audio_stream_id)
                } else {
                    None
                }
            })
        }) {
            return Ok(existing_id);
        }

        let is_full = self.state.lock(|cell| cell.borrow().streams.len() >= NA);
        if is_full {
            return Err(ErrorCode::ResourceExhausted.into());
        }

        let id = self.next_stream_id()?;
        let candidate = AudioStream {
            audio_stream_id: id,
            stream_usage,
            audio_codec,
            channel_count,
            sample_rate,
            bit_rate,
            bit_depth,
            reference_count: 0,
        };

        self.hooks.on_audio_allocated(&candidate).await?;
        let pushed = self
            .state
            .lock(|cell| cell.borrow_mut().streams.push(candidate).is_ok());
        if !pushed {
            let _ = self.hooks.on_audio_deallocated(id).await;
            return Err(ErrorCode::ResourceExhausted.into());
        }
        self.dataver.changed();
        Ok(id)
    }

    pub async fn deallocate_stream(&self, audio_stream_id: u16) -> Result<(), Error> {
        let check = self.state.lock(|cell| {
            let list = cell.borrow();
            match list
                .streams
                .iter()
                .find(|s| s.audio_stream_id == audio_stream_id)
            {
                None => Err(ErrorCode::NotFound),
                Some(s) if s.reference_count > 0 => Err(ErrorCode::InvalidInState),
                Some(_) => Ok(()),
            }
        });
        check.map_err(Error::from)?;

        self.state.lock(|cell| {
            cell.borrow_mut()
                .streams
                .retain(|s| s.audio_stream_id != audio_stream_id);
        });
        let _ = self.hooks.on_audio_deallocated(audio_stream_id).await;
        self.dataver.changed();
        Ok(())
    }

    pub fn acquire_audio(&self, audio_stream_id: u16) -> Result<(), Error> {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            let row = state
                .streams
                .iter_mut()
                .find(|s| s.audio_stream_id == audio_stream_id)
                .ok_or_else(|| Error::from(ErrorCode::NotFound))?;
            if row.reference_count == u8::MAX {
                return Err(ErrorCode::ResourceExhausted.into());
            }
            row.reference_count += 1;
            Ok::<(), Error>(())
        })?;
        self.dataver.changed();
        Ok(())
    }

    pub fn release_audio(&self, audio_stream_id: u16) -> Result<(), Error> {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            let row = state
                .streams
                .iter_mut()
                .find(|s| s.audio_stream_id == audio_stream_id)
                .ok_or_else(|| Error::from(ErrorCode::NotFound))?;
            row.reference_count = row.reference_count.saturating_sub(1);
            Ok::<(), Error>(())
        })?;
        self.dataver.changed();
        Ok(())
    }

    async fn notify_hooks_audio_levels(&self) {
        let _ = self
            .hooks
            .on_volume_or_mute_changed(
                self.mic_muted.load(Ordering::Acquire),
                self.mic_volume.load(Ordering::Acquire),
                self.speaker_muted.load(Ordering::Acquire),
                self.speaker_volume.load(Ordering::Acquire),
            )
            .await;
    }

    fn next_stream_id(&self) -> Result<u16, Error> {
        self.state.lock(|cell| {
            self.next_id.lock(|next_cell| {
                let state = cell.borrow();
                for _ in 0..u16::MAX {
                    let current = next_cell.get().max(1);
                    let next = if current == u16::MAX { 1 } else { current + 1 };
                    next_cell.set(next);

                    if !state.streams.iter().any(|s| s.audio_stream_id == current) {
                        return Ok(current);
                    }
                }

                Err(ErrorCode::ResourceExhausted.into())
            })
        })
    }
}

impl<H: AudioAvStreamHooks, const NA: usize> ClusterAsyncHandler for AudioAvStreamHandler<H, NA> {
    const CLUSTER: Cluster<'static> = Self::CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn max_content_buffer_size(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(0)
    }

    async fn max_network_bandwidth(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.caps.max_network_bandwidth_kbps)
    }

    async fn supported_stream_usages<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            ToTLVArrayBuilder<P, StreamUsageEnum>,
            ToTLVBuilder<P, StreamUsageEnum>,
        >,
    ) -> Result<P, Error> {
        read_enum_array(builder, self.caps.supported_usages)
    }

    async fn stream_usage_priorities<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            ToTLVArrayBuilder<P, StreamUsageEnum>,
            ToTLVBuilder<P, StreamUsageEnum>,
        >,
    ) -> Result<P, Error> {
        let prios = self
            .state
            .lock(|cell| cell.borrow().stream_usage_priorities.clone());
        read_enum_array(builder, &prios)
    }

    async fn microphone_capabilities<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: AudioCapabilitiesStructBuilder<P>,
    ) -> Result<P, Error> {
        write_audio_capabilities(builder, &self.caps)
    }

    async fn speaker_capabilities<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: AudioCapabilitiesStructBuilder<P>,
    ) -> Result<P, Error> {
        write_audio_capabilities(builder, &self.caps)
    }

    async fn two_way_talk_support(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<TwoWayTalkSupportTypeEnum, Error> {
        Ok(self.caps.two_way_talk)
    }

    async fn allocated_audio_streams<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<AudioStreamStructArrayBuilder<P>, AudioStreamStructBuilder<P>>,
    ) -> Result<P, Error> {
        let snapshot = self.state.lock(|cell| cell.borrow().streams.clone());
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
        Ok(self.speaker_muted.load(Ordering::Acquire))
    }

    async fn speaker_volume_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.speaker_volume.load(Ordering::Acquire))
    }

    async fn speaker_max_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(100)
    }

    async fn speaker_min_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(0)
    }

    async fn microphone_muted(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        Ok(self.mic_muted.load(Ordering::Acquire))
    }

    async fn microphone_volume_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.mic_volume.load(Ordering::Acquire))
    }

    async fn microphone_max_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(100)
    }

    async fn microphone_min_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(0)
    }

    async fn set_speaker_muted(&self, ctx: impl WriteContext, value: bool) -> Result<(), Error> {
        self.speaker_muted.store(value, Ordering::Release);
        self.dataver.changed();
        ctx.notify_changed();
        self.notify_hooks_audio_levels().await;
        Ok(())
    }

    async fn set_speaker_volume_level(
        &self,
        ctx: impl WriteContext,
        value: u8,
    ) -> Result<(), Error> {
        if value > 100 {
            return Err(ErrorCode::ConstraintError.into());
        }
        self.speaker_volume.store(value, Ordering::Release);
        self.dataver.changed();
        ctx.notify_changed();
        self.notify_hooks_audio_levels().await;
        Ok(())
    }

    async fn set_microphone_muted(&self, ctx: impl WriteContext, value: bool) -> Result<(), Error> {
        self.mic_muted.store(value, Ordering::Release);
        self.dataver.changed();
        ctx.notify_changed();
        self.notify_hooks_audio_levels().await;
        Ok(())
    }

    async fn set_microphone_volume_level(
        &self,
        ctx: impl WriteContext,
        value: u8,
    ) -> Result<(), Error> {
        if value > 100 {
            return Err(ErrorCode::ConstraintError.into());
        }
        self.mic_volume.store(value, Ordering::Release);
        self.dataver.changed();
        ctx.notify_changed();
        self.notify_hooks_audio_levels().await;
        Ok(())
    }

    async fn handle_audio_stream_allocate<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: AudioStreamAllocateRequest<'_>,
        response: AudioStreamAllocateResponseBuilder<P>,
    ) -> Result<P, Error> {
        let id = self
            .allocate_stream(
                request.stream_usage()?,
                request.audio_codec()?,
                request.channel_count()?,
                request.sample_rate()?,
                request.bit_rate()?,
                request.bit_depth()?,
            )
            .await?;
        ctx.notify_own_attr_changed(decl::AttributeId::AllocatedAudioStreams as _);
        response.audio_stream_id(id)?.end()
    }

    async fn handle_audio_stream_deallocate(
        &self,
        ctx: impl InvokeContext,
        request: AudioStreamDeallocateRequest<'_>,
    ) -> Result<(), Error> {
        self.deallocate_stream(request.audio_stream_id()?).await?;
        ctx.notify_own_attr_changed(decl::AttributeId::AllocatedAudioStreams as _);
        Ok(())
    }

    async fn handle_video_stream_allocate<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: VideoStreamAllocateRequest<'_>,
        _response: VideoStreamAllocateResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    async fn handle_video_stream_modify(
        &self,
        _ctx: impl InvokeContext,
        _request: VideoStreamModifyRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    async fn handle_video_stream_deallocate(
        &self,
        _ctx: impl InvokeContext,
        _request: VideoStreamDeallocateRequest<'_>,
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

    async fn handle_set_stream_priorities(
        &self,
        _ctx: impl InvokeContext,
        request: SetStreamPrioritiesRequest<'_>,
    ) -> Result<(), Error> {
        let prios: TLVArray<'_, StreamUsageEnum> = request.stream_priorities()?;
        let mut new_prios = Vec::new();
        for entry in prios.iter() {
            let usage = entry?;
            if !self.caps.supported_usages.contains(&usage) {
                return Err(ErrorCode::ConstraintError.into());
            }
            if new_prios.push(usage).is_err() {
                return Err(ErrorCode::ResourceExhausted.into());
            }
        }
        self.state.lock(|cell| {
            cell.borrow_mut().stream_usage_priorities = new_prios;
        });
        self.dataver.changed();
        Ok(())
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

fn write_audio_capabilities<P: TLVBuilderParent>(
    builder: AudioCapabilitiesStructBuilder<P>,
    caps: &AudioEndpointCapabilities<'_>,
) -> Result<P, Error> {
    let b = builder.max_number_of_channels(caps.max_channels)?;
    let mut codecs = b.supported_codecs()?;
    for codec in caps.supported_codecs {
        codecs = codecs.push(codec)?;
    }
    let b = codecs.end()?;
    let mut rates = b.supported_sample_rates()?;
    for rate in caps.supported_sample_rates {
        rates = rates.push(rate)?;
    }
    let b = rates.end()?;
    let mut depths = b.supported_bit_depths()?;
    for depth in caps.supported_bit_depths {
        depths = depths.push(depth)?;
    }
    depths.end()?.end()
}

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

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::*;

    struct AudioAvStreamHooksMock {
        allocated: Cell<u16>,
        deallocated: Cell<u16>,
        last_volumes: Cell<(bool, u8, bool, u8)>,
    }

    impl AudioAvStreamHooksMock {
        const fn new() -> Self {
            Self {
                allocated: Cell::new(0),
                deallocated: Cell::new(0),
                last_volumes: Cell::new((false, 0, false, 0)),
            }
        }
    }

    impl AudioAvStreamHooks for AudioAvStreamHooksMock {
        async fn on_audio_allocated(&self, stream: &AudioStream) -> Result<(), CamAvError> {
            self.allocated.set(stream.audio_stream_id);
            Ok(())
        }

        async fn on_audio_deallocated(&self, stream_id: u16) -> Result<(), CamAvError> {
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

        // Assert
        assert!(has_feature_map_attr);
        assert!(has_attr_list);
        assert!(has_max_buf);
        assert!(has_bandwidth);
        assert!(has_usages);
        assert!(has_priorities);
        assert!(has_alloc_cmd);
        assert!(has_dealloc_cmd);
        assert_eq!(
            features,
            (decl::Feature::AUDIO | decl::Feature::SPEAKER).bits()
        );
    }

    #[test]
    fn allocate_stream_rejects_non_opus_and_notifies_hooks_for_opus() {
        futures_lite::future::block_on(async {
            // Arrange
            let handler = AudioAvStreamHandler::<_, 2>::new(
                Dataver::new(1),
                AudioEndpointCapabilities::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );

            // Act
            let rejected = handler
                .allocate_stream(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::AACLC,
                    1,
                    16_000,
                    24_000,
                    16,
                )
                .await;
            let allocated_id = handler
                .allocate_stream(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    1,
                    16_000,
                    24_000,
                    16,
                )
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
    fn allocate_stream_skips_active_id_after_counter_wraps() {
        futures_lite::future::block_on(async {
            // Arrange
            let handler = AudioAvStreamHandler::<_, 3>::new(
                Dataver::new(1),
                AudioEndpointCapabilities::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );
            let active_id = handler
                .allocate_stream(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    1,
                    16_000,
                    24_000,
                    16,
                )
                .await
                .expect("first allocation succeeds");
            handler.next_id.lock(|cell| cell.set(u16::MAX));
            let max_id = handler
                .allocate_stream(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    1,
                    16_000,
                    25_000,
                    16,
                )
                .await
                .expect("max ID allocation succeeds");
            handler
                .deallocate_stream(max_id)
                .await
                .expect("max ID deallocation succeeds");

            // Act
            let wrapped_id = handler
                .allocate_stream(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    1,
                    16_000,
                    26_000,
                    16,
                )
                .await
                .expect("allocation after wrap succeeds");

            // Assert
            assert_eq!(active_id, 1);
            assert_eq!(max_id, u16::MAX);
            assert_eq!(wrapped_id, 2);
        });
    }

    #[test]
    fn acquire_audio_rejects_reference_count_overflow() {
        futures_lite::future::block_on(async {
            // Arrange
            let handler = AudioAvStreamHandler::<_, 1>::new(
                Dataver::new(1),
                AudioEndpointCapabilities::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );
            let id = handler
                .allocate_stream(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    1,
                    16_000,
                    24_000,
                    16,
                )
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
                AudioEndpointCapabilities::opus_16khz_mono(),
                AudioAvStreamHooksMock::new(),
            );
            let id = handler
                .allocate_stream(
                    StreamUsageEnum::LiveView,
                    AudioCodecEnum::OPUS,
                    1,
                    16_000,
                    24_000,
                    16,
                )
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
}
