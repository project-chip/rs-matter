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

use crate::{
    error::{Error, ErrorCode},
    tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, TagType, ToTLV, TLV},
};

use super::{ClusterId, EndptId, GenericPath, IMStatusCode, Status};
use num_enum::TryFromPrimitive;

/// Event Filter
///
/// Corresponds to the `EventFilterIB` TLV structure in the Interaction Model.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EventFilter {
    pub node: Option<u64>,
    pub event_min: Option<u64>,
}

/// Event Path
///
/// Corresponds to the `EventPathIB` TLV structure in the Interaction Model.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(datatype = "list")]
pub struct EventPath {
    pub node: Option<u64>,
    pub endpoint: Option<EndptId>,
    pub cluster: Option<ClusterId>,
    pub event: Option<u32>,
    pub is_urgent: Option<bool>,
}

impl EventPath {
    /// Create a new `EventPath` from the provided `GenericPath`,
    /// filling all fields which are not provided with their default values.
    pub const fn from_gp(path: &GenericPath) -> Self {
        Self {
            node: None,
            endpoint: path.endpoint,
            cluster: path.cluster,
            event: path.leaf,
            is_urgent: None,
        }
    }

    /// Convert this `EventPath` to a `GenericPath`.
    pub const fn to_gp(&self) -> GenericPath {
        GenericPath::new(self.endpoint, self.cluster, self.event)
    }
}

/// Tags corresponding to the fields in the `EventReportIB` TLV structure.
///
/// Used when there is a need to perform low-level TLV serde on
/// `EventReportIB` structures.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum EventRespTag {
    Status = 0,
    Data = 1,
}

/// Tags corresponding to the fields in the `EventDataIB` TLV structure.
///
/// Used when there is a need to perform low-level TLV serde on
/// EventDataIB structures.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum EventDataTag {
    Path = 0,
    EventNumber = 1,
    Priority = 2,
    EpochTimestamp = 3,
    SystemTimestamp = 4,
    DeltaEpochTimestamp = 5,
    DeltaSystemTimestamp = 6,
    Data = 7,
}

/// A status response for an event in the Interaction Model.
///
/// Corresponds to the `EventStatusIB` TLV structure in the Interaction Model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EventStatus {
    /// The path to the event.
    pub path: EventPath,
    /// The status of the event operation.
    pub status: Status,
}

impl EventStatus {
    /// Create a new `EventStatus` with the given path, status code, and optional cluster status.
    pub const fn new(path: EventPath, status: IMStatusCode, cluster_status: Option<u16>) -> Self {
        Self {
            path,
            status: Status::new(status, cluster_status),
        }
    }

    /// Create a new `EventStatus` from a `GenericPath`, status code, and optional cluster status.
    ///
    /// ATTENTION: the actual reply `EventPath` will be filled with the `GenericPath` values,
    /// however these are not necessarily expressing the full path of the incoming data as `EventPath` does.
    ///
    /// Hence, this method is primarily useful for unit tests.
    pub const fn from_gp(
        path: &GenericPath,
        status: IMStatusCode,
        cluster_status: Option<u16>,
    ) -> Self {
        Self::new(EventPath::from_gp(path), status, cluster_status)
    }
}

/// Event Response
///
/// Corresponds to the `EventReportIB` TLV structure in the Interaction Model.
#[derive(Clone, FromTLV, ToTLV, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub enum EventResp<'a> {
    Status(EventStatus),
    Data(EventData<'a>),
}

/// A data response for an event in the Interaction Model.
///
/// Corresponds to the `EventDataIB` TLV structure in the Interaction Model.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EventData<'a> {
    /// The path to the event.
    pub path: EventPath,
    /// The event number counter for the node. While the node is running it is
    /// monotonically increasing, but the spec allows for (large) incremental jumps
    /// on node reboot
    pub event_number: u64,
    // Event priority, lower means higher priority
    pub priority: u8,
    // Event timestamp, one of multiple mutually exclusive options
    pub timestamp: EventDataTimestamp,
    /// The data for the event, represented as a TLV element.
    pub data: TLVElement<'a>,
}

impl<'a> EventData<'a> {
    /// Create a new `EventData` with the given data version, path, and data.
    pub const fn new(
        path: EventPath,
        event_number: u64,
        priority: u8,
        timestamp: EventDataTimestamp,
        data: TLVElement<'a>,
    ) -> Self {
        Self {
            path,
            event_number,
            priority,
            timestamp,
            data,
        }
    }
}

// Manually implemented because of the tagged union used for the timestamp
impl<'a> ToTLV for EventData<'a> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.start_struct(tag)?;
        self.path
            .to_tlv(&TagType::Context(EventDataTag::Path as _), &mut tw)?;
        tw.u64(
            &TagType::Context(EventDataTag::EventNumber as _),
            self.event_number,
        )?;
        tw.u8(
            &TagType::Context(EventDataTag::Priority as _),
            self.priority,
        )?;

        match self.timestamp {
            EventDataTimestamp::EpochTimestamp(ts) => {
                tw.u64(&TagType::Context(EventDataTag::EpochTimestamp as _), ts)?
            }
            EventDataTimestamp::SystemTimestamp(ts) => {
                tw.u64(&TagType::Context(EventDataTag::SystemTimestamp as _), ts)?
            }
            EventDataTimestamp::DeltaEpochTimestamp(ts) => tw.u64(
                &TagType::Context(EventDataTag::DeltaEpochTimestamp as _),
                ts,
            )?,
            EventDataTimestamp::DeltaSystemTimestamp(ts) => tw.u64(
                &TagType::Context(EventDataTag::DeltaSystemTimestamp as _),
                ts,
            )?,
        };

        self.data
            .to_tlv(&TagType::Context(EventDataTag::Data as _), &mut tw)?;

        tw.end_container()
    }

    fn tlv_iter(&self, tag: crate::tlv::TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        let (timestamp_tag, timestamp_val) = match self.timestamp {
            EventDataTimestamp::EpochTimestamp(ts) => (EventDataTag::EpochTimestamp, ts),
            EventDataTimestamp::SystemTimestamp(ts) => (EventDataTag::EpochTimestamp, ts),
            EventDataTimestamp::DeltaEpochTimestamp(ts) => (EventDataTag::EpochTimestamp, ts),
            EventDataTimestamp::DeltaSystemTimestamp(ts) => (EventDataTag::EpochTimestamp, ts),
        };

        let header = [Ok(TLV::structure(tag))].into_iter();
        let middle_fields = [
            Ok(TLV::u64(
                TLVTag::Context(EventDataTag::EventNumber as _),
                self.event_number,
            )),
            Ok(TLV::u8(
                TLVTag::Context(EventDataTag::Priority as _),
                self.priority,
            )),
            Ok(TLV::u64(TLVTag::Context(timestamp_tag as _), timestamp_val)),
        ]
        .into_iter();
        let trailer = [Ok(TLV::end_container())].into_iter();

        header
            .chain(self.path.tlv_iter(TLVTag::Context(EventDataTag::Path as _)))
            .chain(middle_fields)
            .chain(self.data.tlv_iter(TLVTag::Context(EventDataTag::Data as _)))
            .chain(trailer)
    }
}

impl<'a> FromTLV<'a> for EventData<'a> {
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        let mut path = None;
        let mut event_number = None;
        let mut priority = None;
        let mut timestamp = None;
        let mut data = None;
        for field in element.structure()?.iter() {
            let el = field?;
            match el.tag()? {
                TLVTag::Context(tag) => match EventDataTag::try_from(tag)? {
                    EventDataTag::Path => path = Some(EventPath::from_tlv(&el)?),
                    EventDataTag::EventNumber => event_number = Some(el.u64()?),
                    EventDataTag::Priority => priority = Some(el.u8()?),
                    EventDataTag::EpochTimestamp => {
                        timestamp = Some(EventDataTimestamp::EpochTimestamp(el.u64()?))
                    }
                    EventDataTag::SystemTimestamp => {
                        timestamp = Some(EventDataTimestamp::SystemTimestamp(el.u64()?))
                    }
                    EventDataTag::DeltaEpochTimestamp => {
                        timestamp = Some(EventDataTimestamp::DeltaEpochTimestamp(el.u64()?))
                    }
                    EventDataTag::DeltaSystemTimestamp => {
                        timestamp = Some(EventDataTimestamp::DeltaSystemTimestamp(el.u64()?))
                    }
                    EventDataTag::Data => data = Some(el),
                },
                _ => return Err(Error::new(ErrorCode::Invalid)),
            }
        }
        Ok(EventData::new(
            path.ok_or(Error::new(ErrorCode::Invalid))?,
            event_number.ok_or(Error::new(ErrorCode::Invalid))?,
            priority.ok_or(Error::new(ErrorCode::Invalid))?,
            timestamp.ok_or(Error::new(ErrorCode::Invalid))?,
            data.ok_or(Error::new(ErrorCode::Invalid))?,
        ))
    }
}

// Timestamp on an EventData, corresponds to the mutually exclusive timestamp
// options on EventDataIB in the Interaction Model
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EventDataTimestamp {
    // Posix milliseconds since the epoch, 1970-01-01 00:00:00 UTC
    EpochTimestamp(u64),
    // Milliseconds since booting
    SystemTimestamp(u64),
    // Delta-encoded version of EpochTimestamp. Same clock and unit, but value
    // is relative to most recently emitted event.
    DeltaEpochTimestamp(u64),
    // Delta-encoded version of SystemTimestamp. Same clock and unit, but value
    // is relative to most recently emitted event.
    DeltaSystemTimestamp(u64),
}
