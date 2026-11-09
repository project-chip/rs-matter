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

/// Validates that a requested stream allocation conforms to Matter spec §1.15.
pub fn validate_audio_allocate(
    params: &AudioStreamParams,
    capabilities: &AudioCapabilitiesConfig<'_>,
    current_priorities: &[StreamUsageEnum],
) -> Result<(), Error> {
    if matches!(params.stream_usage, StreamUsageEnum::Internal) {
        return Err(ErrorCode::ConstraintError.into());
    }
    if !current_priorities.contains(&params.stream_usage) {
        return Err(ErrorCode::InvalidInState.into());
    }
    if !capabilities.supported_codecs.contains(&params.audio_codec)
        || params.channel_count == 0
        || params.channel_count > capabilities.max_channels
        || !capabilities
            .supported_sample_rates
            .contains(&params.sample_rate)
        || !capabilities
            .supported_bit_depths
            .contains(&params.bit_depth)
        || params.bit_rate == 0
    {
        return Err(ErrorCode::DynamicConstraintError.into());
    }
    Ok(())
}

/// Builds a validated `StreamUsagePriorities` vector conforming to Matter spec §1.15.
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
}
