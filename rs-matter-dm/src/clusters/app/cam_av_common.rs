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

//! Shared primitives and serialization helpers for Camera and Audio AV Stream Management (Cluster 0x0551).

use crate::dm::clusters::decl::camera_av_stream_management::{
    AudioCapabilitiesStructBuilder, AudioCodecEnum, AudioStreamStructBuilder,
};
use crate::dm::clusters::decl::globals::StreamUsageEnum;
use crate::dm::ArrayAttributeRead;
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVBuilderParent, ToTLVArrayBuilder, ToTLVBuilder};
use crate::utils::storage::Vec;

/// Maximum number of distinct stream usages the priority table can hold.
pub const MAX_STREAM_USAGES: usize = 4;

/// Static description of audio capabilities, reported via `MicrophoneCapabilities`
/// and `SpeakerCapabilities`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioCapabilitiesConfig<'a> {
    pub max_channels: u8,
    pub supported_codecs: &'a [AudioCodecEnum],
    pub supported_sample_rates: &'a [u32],
    pub supported_bit_depths: &'a [u8],
}

/// One row in the `AllocatedAudioStreams` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl AudioStream {
    /// Returns the stream parameters without ID and reference count.
    pub fn params(&self) -> AudioStreamParams {
        AudioStreamParams {
            stream_usage: self.stream_usage,
            audio_codec: self.audio_codec,
            channel_count: self.channel_count,
            sample_rate: self.sample_rate,
            bit_rate: self.bit_rate,
            bit_depth: self.bit_depth,
        }
    }
}

/// Parameters describing an audio stream allocation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AudioStreamParams {
    pub stream_usage: StreamUsageEnum,
    pub audio_codec: AudioCodecEnum,
    pub channel_count: u8,
    pub sample_rate: u32,
    pub bit_rate: u32,
    pub bit_depth: u8,
}

impl AudioStreamParams {
    pub const fn new(
        stream_usage: StreamUsageEnum,
        audio_codec: AudioCodecEnum,
        channel_count: u8,
        sample_rate: u32,
        bit_rate: u32,
        bit_depth: u8,
    ) -> Self {
        Self {
            stream_usage,
            audio_codec,
            channel_count,
            sample_rate,
            bit_rate,
            bit_depth,
        }
    }
}

/// Errors an AV stream hooks implementation can surface back to the cluster.
/// Each maps to a Matter cluster-status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CamAvError {
    /// `RESOURCE_EXHAUSTED` — encoder cannot accept another concurrent stream.
    ResourceExhausted,
    /// `DYNAMIC_CONSTRAINT_ERROR` — combination of params is unsupported
    /// at runtime (e.g. requested bitrate exceeds what the codec can do
    /// for the requested resolution/audio parameters).
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
            CamAvError::DynamicConstraint => ErrorCode::DynamicConstraintError.into(),
            CamAvError::NotFound => ErrorCode::NotFound.into(),
            CamAvError::Failure => ErrorCode::Failure.into(),
        }
    }
}

/// Validates that a requested stream allocation conforms to the Matter spec.
pub fn validate_audio_allocate(
    params: &AudioStreamParams,
    capabilities: &AudioCapabilitiesConfig<'_>,
    current_priorities: &[StreamUsageEnum],
) -> Result<(), Error> {
    if params.channel_count == 0
        || params.channel_count > 8
        || params.sample_rate == 0
        || params.bit_rate == 0
        || !matches!(params.bit_depth, 8 | 16 | 24 | 32)
        || matches!(params.stream_usage, StreamUsageEnum::Internal)
    {
        return Err(ErrorCode::ConstraintError.into());
    }
    if !current_priorities.contains(&params.stream_usage) {
        return Err(ErrorCode::InvalidInState.into());
    }
    if !capabilities.supported_codecs.contains(&params.audio_codec)
        || params.channel_count > capabilities.max_channels
        || !capabilities
            .supported_sample_rates
            .contains(&params.sample_rate)
        || !capabilities
            .supported_bit_depths
            .contains(&params.bit_depth)
    {
        return Err(ErrorCode::DynamicConstraintError.into());
    }
    Ok(())
}

/// Builds a validated `StreamUsagePriorities` vector conforming to the Matter spec.
///
/// Verifies that each entry is present in `supported_usages`, rejects duplicates with
/// `ErrorCode::AlreadyExists`, and ensures the total count fits within capacity `N`.
pub fn build_stream_priorities<const N: usize>(
    new_priorities: impl IntoIterator<Item = Result<StreamUsageEnum, Error>>,
    supported_usages: &[StreamUsageEnum],
) -> Result<Vec<StreamUsageEnum, N>, Error> {
    let mut buffer = Vec::new();
    for entry in new_priorities {
        let usage = entry?;
        if !supported_usages.contains(&usage) {
            return Err(ErrorCode::DynamicConstraintError.into());
        }
        if buffer.contains(&usage) {
            return Err(ErrorCode::AlreadyExists.into());
        }
        if buffer.push(usage).is_err() {
            return Err(ErrorCode::ResourceExhausted.into());
        }
    }
    Ok(buffer)
}

// --- TLV serialization helpers ---

pub(crate) fn read_enum_array<P: TLVBuilderParent>(
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

pub(crate) fn write_audio_stream<P: TLVBuilderParent>(
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

pub(crate) fn write_audio_capabilities<P: TLVBuilderParent>(
    builder: AudioCapabilitiesStructBuilder<P>,
    caps: &AudioCapabilitiesConfig<'_>,
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

/// Result of an atomic stream allocation resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StreamAllocation {
    Found(AudioStream),
    Created(AudioStream),
}

impl StreamAllocation {
    pub const fn stream(&self) -> &AudioStream {
        match self {
            Self::Found(s) | Self::Created(s) => s,
        }
    }
}

/// Table of allocated audio streams with monotonic stream ID generation.
#[derive(Debug, Clone)]
pub struct AudioStreamTable<const NA: usize> {
    streams: Vec<AudioStream, NA>,
    next_id: u16,
}

impl<const NA: usize> Default for AudioStreamTable<NA> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const NA: usize> AudioStreamTable<NA> {
    pub const fn new() -> Self {
        Self {
            streams: Vec::new(),
            next_id: 1,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    pub fn get(&self, stream_id: u16) -> Option<&AudioStream> {
        let idx = self.find_index(stream_id)?;
        Some(&self.streams[idx])
    }

    pub fn snapshot(&self) -> Vec<AudioStream, NA> {
        self.streams.clone()
    }

    pub fn find(&self, params: &AudioStreamParams) -> Option<AudioStream> {
        self.streams.iter().find(|s| s.params() == *params).copied()
    }

    /// Atomically finds an existing matching stream or creates a new one.
    pub fn find_or_create(
        &mut self,
        params: &AudioStreamParams,
    ) -> Result<StreamAllocation, Error> {
        if let Some(existing) = self.find(params) {
            return Ok(StreamAllocation::Found(existing));
        }

        let stream = self.create(params)?;
        Ok(StreamAllocation::Created(stream))
    }

    /// Creates and inserts a new audio stream into the table.
    pub fn create(&mut self, params: &AudioStreamParams) -> Result<AudioStream, Error> {
        if self.streams.len() >= NA {
            return Err(ErrorCode::ResourceExhausted.into());
        }

        let stream = self.create_audio_stream(params);
        self.streams
            .push(stream)
            .map_err(|_| Error::from(ErrorCode::ResourceExhausted))?;
        Ok(stream)
    }

    pub fn add_preallocated(&mut self, mut stream: AudioStream) -> Result<u16, Error> {
        if self.streams.len() >= NA {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        if stream.audio_stream_id == 0 {
            stream.audio_stream_id = self.next_stream_id();
        }
        let id = stream.audio_stream_id;
        self.streams
            .push(stream)
            .map_err(|_| Error::from(ErrorCode::ResourceExhausted))?;
        Ok(id)
    }

    pub fn remove(&mut self, stream_id: u16) -> Option<AudioStream> {
        let idx = self.find_index(stream_id)?;
        Some(self.streams.remove(idx))
    }

    /// Validates that a stream can be deallocated: exists, refcount is 0, and not Internal.
    pub fn can_deallocate(&self, stream_id: u16) -> Result<(), Error> {
        let stream = self.get(stream_id).ok_or(ErrorCode::NotFound)?;
        if stream.reference_count > 0 {
            return Err(ErrorCode::InvalidInState.into());
        }
        if matches!(stream.stream_usage, StreamUsageEnum::Internal) {
            return Err(ErrorCode::DynamicConstraintError.into());
        }
        Ok(())
    }

    /// Deallocates a stream if it exists, has zero references, and is not Internal.
    pub fn deallocate(&mut self, stream_id: u16) -> Result<(), Error> {
        self.can_deallocate(stream_id)?;
        self.remove(stream_id);
        Ok(())
    }

    pub fn acquire(&mut self, stream_id: u16) -> Result<(), Error> {
        let stream = self.find_stream_mut(stream_id).ok_or(ErrorCode::NotFound)?;
        if stream.reference_count == u8::MAX {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        stream.reference_count += 1;
        Ok(())
    }

    pub fn release(&mut self, stream_id: u16) -> Result<(), Error> {
        let stream = self.find_stream_mut(stream_id).ok_or(ErrorCode::NotFound)?;
        stream.reference_count = stream.reference_count.saturating_sub(1);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.streams.len()
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[AudioStream] {
        &self.streams
    }

    #[cfg(test)]
    pub(crate) fn set_next_id(&mut self, id: u16) {
        self.next_id = id;
    }

    // --- Private helpers ---

    fn next_stream_id(&mut self) -> u16 {
        loop {
            let mut id = self.next_id;
            if id == 0 {
                id = 1;
            }
            self.next_id = id.wrapping_add(1).max(1);
            if self.find_index(id).is_none() {
                return id;
            }
        }
    }

    fn create_audio_stream(&mut self, params: &AudioStreamParams) -> AudioStream {
        let id = self.next_stream_id();
        AudioStream {
            audio_stream_id: id,
            stream_usage: params.stream_usage,
            audio_codec: params.audio_codec,
            channel_count: params.channel_count,
            sample_rate: params.sample_rate,
            bit_rate: params.bit_rate,
            bit_depth: params.bit_depth,
            reference_count: 0,
        }
    }

    fn find_index(&self, stream_id: u16) -> Option<usize> {
        self.streams
            .iter()
            .position(|s| s.audio_stream_id == stream_id)
    }

    fn find_stream_mut(&mut self, stream_id: u16) -> Option<&mut AudioStream> {
        let idx = self.find_index(stream_id)?;
        Some(&mut self.streams[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUPPORTED: &[StreamUsageEnum] = &[
        StreamUsageEnum::LiveView,
        StreamUsageEnum::Recording,
        StreamUsageEnum::Analysis,
    ];

    #[test]
    fn build_stream_priorities_succeeds_with_valid_subset_in_order() {
        let input = [
            Ok(StreamUsageEnum::Recording),
            Ok(StreamUsageEnum::LiveView),
        ];
        let result: Vec<StreamUsageEnum, 4> =
            build_stream_priorities(input, SUPPORTED).expect("priorities build succeeds");

        assert_eq!(result.len(), 2);
        assert_eq!(result[0], StreamUsageEnum::Recording);
        assert_eq!(result[1], StreamUsageEnum::LiveView);
    }

    #[test]
    fn build_stream_priorities_rejects_unsupported_usage() {
        let input = [Ok(StreamUsageEnum::LiveView), Ok(StreamUsageEnum::Internal)];
        let err = build_stream_priorities::<4>(input, SUPPORTED).unwrap_err();
        assert_eq!(err.code(), ErrorCode::DynamicConstraintError);
    }

    #[test]
    fn build_stream_priorities_rejects_duplicate_usage() {
        let input = [Ok(StreamUsageEnum::LiveView), Ok(StreamUsageEnum::LiveView)];
        let err = build_stream_priorities::<4>(input, SUPPORTED).unwrap_err();
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
    }

    #[test]
    fn build_stream_priorities_rejects_exceeding_capacity() {
        let input = [
            Ok(StreamUsageEnum::LiveView),
            Ok(StreamUsageEnum::Recording),
            Ok(StreamUsageEnum::Analysis),
        ];
        // Capacity of 2 but 3 items passed
        let err = build_stream_priorities::<2>(input, SUPPORTED).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceExhausted);
    }

    #[test]
    fn build_stream_priorities_propagates_iterator_error() {
        let input = [
            Ok(StreamUsageEnum::LiveView),
            Err(ErrorCode::InvalidDataType.into()),
        ];
        let err = build_stream_priorities::<4>(input, SUPPORTED).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidDataType);
    }

    const TEST_CAPABILITIES: AudioCapabilitiesConfig<'static> = AudioCapabilitiesConfig {
        max_channels: 2,
        supported_codecs: &[AudioCodecEnum::OPUS],
        supported_sample_rates: &[16_000, 48_000],
        supported_bit_depths: &[16],
    };

    fn valid_test_params() -> AudioStreamParams {
        AudioStreamParams {
            stream_usage: StreamUsageEnum::LiveView,
            audio_codec: AudioCodecEnum::OPUS,
            channel_count: 1,
            sample_rate: 16_000,
            bit_rate: 32_000,
            bit_depth: 16,
        }
    }

    #[test]
    fn validate_audio_allocate_succeeds_for_valid_params() {
        let params = valid_test_params();
        assert!(validate_audio_allocate(&params, &TEST_CAPABILITIES, SUPPORTED).is_ok());
    }

    #[test]
    fn validate_audio_allocate_rejects_zero_channel_count_with_constraint_error() {
        let mut params = valid_test_params();
        params.channel_count = 0;
        let err = validate_audio_allocate(&params, &TEST_CAPABILITIES, SUPPORTED).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConstraintError);
    }

    #[test]
    fn validate_audio_allocate_rejects_excess_channel_count_with_constraint_error() {
        let mut params = valid_test_params();
        params.channel_count = 9;
        let err = validate_audio_allocate(&params, &TEST_CAPABILITIES, SUPPORTED).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConstraintError);
    }

    #[test]
    fn validate_audio_allocate_rejects_zero_sample_rate_with_constraint_error() {
        let mut params = valid_test_params();
        params.sample_rate = 0;
        let err = validate_audio_allocate(&params, &TEST_CAPABILITIES, SUPPORTED).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConstraintError);
    }

    #[test]
    fn validate_audio_allocate_rejects_zero_bit_rate_with_constraint_error() {
        let mut params = valid_test_params();
        params.bit_rate = 0;
        let err = validate_audio_allocate(&params, &TEST_CAPABILITIES, SUPPORTED).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConstraintError);
    }

    #[test]
    fn validate_audio_allocate_rejects_invalid_bit_depth_with_constraint_error() {
        let mut params = valid_test_params();
        params.bit_depth = 12; // Valid schema bit depths are 8, 16, 24, 32
        let err = validate_audio_allocate(&params, &TEST_CAPABILITIES, SUPPORTED).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConstraintError);
    }

    #[test]
    fn validate_audio_allocate_rejects_internal_usage_with_constraint_error() {
        let mut params = valid_test_params();
        params.stream_usage = StreamUsageEnum::Internal;
        let err = validate_audio_allocate(&params, &TEST_CAPABILITIES, SUPPORTED).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConstraintError);
    }

    #[test]
    fn validate_audio_allocate_rejects_unsupported_priority_with_invalid_in_state() {
        let mut params = valid_test_params();
        params.stream_usage = StreamUsageEnum::Recording; // Not in active SUPPORTED priorities if we use a subset
        let priorities = &[StreamUsageEnum::LiveView];
        let err = validate_audio_allocate(&params, &TEST_CAPABILITIES, priorities).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInState);
    }

    #[test]
    fn validate_audio_allocate_rejects_unsupported_sample_rate_with_dynamic_constraint_error() {
        let mut params = valid_test_params();
        params.sample_rate = 8_000; // Schema valid (> 0), but not in TEST_CAPABILITIES
        let err = validate_audio_allocate(&params, &TEST_CAPABILITIES, SUPPORTED).unwrap_err();
        assert_eq!(err.code(), ErrorCode::DynamicConstraintError);
    }

    #[test]
    fn audio_stream_table_find_or_create_idempotency_preserves_zero_refcount() {
        let mut table = AudioStreamTable::<4>::new();
        let params = valid_test_params();

        // Initial allocation -> Created with reference_count == 0
        let alloc1 = table.find_or_create(&params).expect("create succeeds");
        assert!(matches!(alloc1, StreamAllocation::Created(_)));
        let stream1 = *alloc1.stream();
        assert_eq!(stream1.reference_count, 0);

        // Matching allocation -> Found with reference_count still 0
        let alloc2 = table.find_or_create(&params).expect("lookup succeeds");
        assert!(matches!(alloc2, StreamAllocation::Found(_)));
        let stream2 = *alloc2.stream();
        assert_eq!(stream2.audio_stream_id, stream1.audio_stream_id);
        assert_eq!(
            stream2.reference_count, 0,
            "idempotent lookup must not mutate reference count"
        );

        // find() returns the stream
        let found = table.find(&params).expect("find succeeds");
        assert_eq!(found.audio_stream_id, stream1.audio_stream_id);
    }
}
