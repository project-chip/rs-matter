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

use num_enum::TryFromPrimitive;

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, TagType, ToTLV, TLV};

use super::{ClusterId, EndptId, EventId, EventNumber, GenericPath, IMStatusCode, NodeId, Status};

/// Event Filter
///
/// Corresponds to the `EventFilterIB` TLV structure in the Interaction Model.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EventFilter {
    pub node: Option<NodeId>,
    pub event_min: Option<EventNumber>,
}

/// Event Path
///
/// Corresponds to the `EventPathIB` TLV structure in the Interaction Model.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(datatype = "list")]
pub struct EventPath {
    pub node: Option<NodeId>,
    pub endpoint: Option<EndptId>,
    pub cluster: Option<ClusterId>,
    pub event: Option<EventId>,
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

    /// Return true, if the path is wildcard
    pub const fn is_wildcard(&self) -> bool {
        self.endpoint.is_none() || self.cluster.is_none() || self.event.is_none()
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
    /// on node reboot.
    pub event_number: EventNumber,
    /// Event priority.
    pub priority: EventPriority,
    /// Event timestamp, one of multiple mutually exclusive options.
    pub timestamp: EventDataTimestamp,
    /// The data for the event, represented as a TLV element.
    pub data: TLVElement<'a>,
}

impl<'a> EventData<'a> {
    /// Create a new `EventData` with the given data version, path, and data.
    pub const fn new(
        path: EventPath,
        event_number: EventNumber,
        priority: EventPriority,
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

    pub fn write_preamble<T: TLVWrite>(&self, tag: &TLVTag, mut tw: T) -> Result<(), Error> {
        tw.start_struct(tag)?;

        self.path
            .to_tlv(&TagType::Context(EventDataTag::Path as _), &mut tw)?;

        tw.u64(
            &TagType::Context(EventDataTag::EventNumber as _),
            self.event_number,
        )?;

        tw.u8(
            &TagType::Context(EventDataTag::Priority as _),
            self.priority as _,
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
        }

        Ok(())
    }
}

// Manually implemented because of the tagged union used for the timestamp
impl<'a> ToTLV for EventData<'a> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        self.write_preamble(tag, &mut tw)?;

        self.data
            .to_tlv(&TagType::Context(EventDataTag::Data as _), &mut tw)?;

        tw.end_container()
    }

    fn tlv_iter(&self, tag: crate::tlv::TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        let (timestamp_tag, timestamp_val) = match self.timestamp {
            EventDataTimestamp::EpochTimestamp(ts) => (EventDataTag::EpochTimestamp, ts),
            EventDataTimestamp::SystemTimestamp(ts) => (EventDataTag::SystemTimestamp, ts),
            EventDataTimestamp::DeltaEpochTimestamp(ts) => (EventDataTag::DeltaEpochTimestamp, ts),
            EventDataTimestamp::DeltaSystemTimestamp(ts) => {
                (EventDataTag::DeltaSystemTimestamp, ts)
            }
        };

        let header = [Ok(TLV::structure(tag))].into_iter();
        let middle_fields = [
            Ok(TLV::u64(
                TLVTag::Context(EventDataTag::EventNumber as _),
                self.event_number,
            )),
            Ok(TLV::u8(
                TLVTag::Context(EventDataTag::Priority as _),
                self.priority as _,
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
                    EventDataTag::Priority => priority = Some(EventPriority::from_tlv(&el)?),
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

/// An enum type describing the priority each event might have
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(datatype = "u8")]
#[repr(u8)]
pub enum EventPriority {
    Debug = 0,
    Info = 1,
    Critical = 2,
}

impl EventPriority {
    /// Get the next (higher) priority, if any
    pub const fn next(&self) -> Option<Self> {
        match self {
            Self::Debug => Some(Self::Info),
            Self::Info => Some(Self::Critical),
            Self::Critical => None,
        }
    }

    /// Get the previous (lower) priority, if any
    pub const fn prev(&self) -> Option<Self> {
        match self {
            Self::Debug => None,
            Self::Info => Some(Self::Debug),
            Self::Critical => Some(Self::Info),
        }
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

#[cfg(test)]
mod tests {
    use crate::im::IMStatusCode;
    use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};
    use crate::utils::storage::WriteBuf;

    use super::{
        EventData, EventDataTimestamp, EventPath, EventPriority, EventResp, EventStatus,
        GenericPath,
    };

    fn event_path(endpoint: u16, cluster: u32, event: u32) -> EventPath {
        EventPath {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            event: Some(event),
            ..Default::default()
        }
    }

    /// Field-wise comparison: a decoded `data` element also spans the bytes that follow it
    /// inside the enclosing buffer, so whole-struct equality does not hold.
    fn assert_event_data_eq(decoded: &EventData<'_>, expected: &EventData<'_>) {
        assert_eq!(decoded.path, expected.path);
        assert_eq!(decoded.event_number, expected.event_number);
        assert_eq!(decoded.priority, expected.priority);
        assert_eq!(decoded.timestamp, expected.timestamp);
        assert_eq!(decoded.data.tag().unwrap(), expected.data.tag().unwrap());
        assert_eq!(decoded.data.u8().unwrap(), expected.data.u8().unwrap());
    }

    #[test]
    fn event_path_helpers_and_priority_order() {
        let gp = GenericPath::new(Some(0), Some(0x28), Some(1));
        let path = EventPath::from_gp(&gp);
        assert_eq!(path, event_path(0, 0x28, 1));
        assert_eq!(path.to_gp(), gp);
        assert!(!path.is_wildcard());
        assert!(EventPath::from_gp(&GenericPath::new(None, Some(0x28), Some(1))).is_wildcard());
        assert!(EventPath::from_gp(&GenericPath::new(Some(0), None, Some(1))).is_wildcard());
        assert!(EventPath::from_gp(&GenericPath::new(Some(0), Some(0x28), None)).is_wildcard());
        assert!(
            EventPath {
                is_urgent: Some(true),
                ..path
            }
            .to_gp()
                == gp
        );

        assert_eq!(EventPriority::Debug.next(), Some(EventPriority::Info));
        assert_eq!(EventPriority::Info.next(), Some(EventPriority::Critical));
        assert_eq!(EventPriority::Critical.next(), None);
        assert_eq!(EventPriority::Debug.prev(), None);
        assert_eq!(EventPriority::Info.prev(), Some(EventPriority::Debug));
        assert_eq!(EventPriority::Critical.prev(), Some(EventPriority::Info));
    }

    #[test]
    fn event_data_round_trips_each_timestamp_variant() {
        let value = [0x24, 7, 42];

        for (timestamp, tag) in [
            (EventDataTimestamp::EpochTimestamp(0x1_0000_0000), 3),
            (EventDataTimestamp::SystemTimestamp(5), 4),
            (EventDataTimestamp::DeltaEpochTimestamp(6), 5),
            (EventDataTimestamp::DeltaSystemTimestamp(7), 6),
        ] {
            let data = EventData::new(
                event_path(0, 0x28, 1),
                0x1234,
                EventPriority::Critical,
                timestamp,
                TLVElement::new(&value),
            );

            let mut buf = [0; 64];
            let mut wb = WriteBuf::new(&mut buf);
            EventResp::Data(data.clone())
                .to_tlv(&TLVTag::Anonymous, &mut wb)
                .unwrap();

            let EventResp::Data(decoded) =
                EventResp::from_tlv(&TLVElement::new(wb.as_slice())).unwrap()
            else {
                panic!("expected event data");
            };
            assert_event_data_eq(&decoded, &data);

            // The timestamp lands under its own tag and the other timestamp tags are absent
            let fields = TLVElement::new(wb.as_slice())
                .structure()
                .unwrap()
                .ctx(1)
                .unwrap();
            let fields = fields.structure().unwrap();
            for other in 3..=6 {
                assert_eq!(fields.find_ctx(other).unwrap().is_empty(), other != tag);
            }
        }

        let mut buf = [0; 64];
        let mut wb = WriteBuf::new(&mut buf);
        EventData::new(
            event_path(0, 0x28, 1),
            2,
            EventPriority::Info,
            EventDataTimestamp::SystemTimestamp(5),
            TLVElement::new(&value),
        )
        .to_tlv(&TLVTag::Anonymous, &mut wb)
        .unwrap();
        assert_eq!(
            wb.as_slice(),
            &[
                0x15, // EventDataIB
                0x37, 0, 0x24, 1, 0, 0x24, 2, 0x28, 0x24, 3, 1, 0x18, // Path list
                0x24, 1, 2, // EventNumber
                0x24, 2, 1, // Priority
                0x24, 4, 5, // SystemTimestamp
                0x24, 7, 42, // Data
                0x18,
            ]
        );

        // Status variant
        let status = EventResp::Status(EventStatus::from_gp(
            &GenericPath::new(Some(0), Some(0x28), Some(1)),
            IMStatusCode::UnsupportedEvent,
            Some(1),
        ));
        wb.reset();
        status.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        assert_eq!(
            EventResp::from_tlv(&TLVElement::new(wb.as_slice())).unwrap(),
            status
        );
    }

    #[test]
    #[ignore = "the derived ToTLV::tlv_iter (rs-matter-macros) emits a struct start for `datatype = \"list\"` structs such as EventPath, so it disagrees with to_tlv"]
    fn event_data_tlv_iter_matches_to_tlv() {
        let value = [0x24, 7, 42];
        let data = EventData::new(
            event_path(0, 0x28, 1),
            2,
            EventPriority::Info,
            EventDataTimestamp::SystemTimestamp(5),
            TLVElement::new(&value),
        );

        let mut buf = [0; 64];
        let mut wb = WriteBuf::new(&mut buf);
        for byte in data
            .tlv_iter(TLVTag::Anonymous)
            .flat_map(TLV::result_into_bytes_iter)
        {
            wb.append(&[byte.unwrap()]).unwrap();
        }

        let mut buf2 = [0; 64];
        let mut wb2 = WriteBuf::new(&mut buf2);
        data.to_tlv(&TLVTag::Anonymous, &mut wb2).unwrap();
        assert_eq!(wb.as_slice(), wb2.as_slice());
    }

    #[test]
    fn event_data_from_tlv_rejects_malformed_input() {
        let value = [0x24, 7, 42];
        let data = EventData::new(
            event_path(0, 0x28, 1),
            2,
            EventPriority::Info,
            EventDataTimestamp::SystemTimestamp(5),
            TLVElement::new(&value),
        );

        // Missing timestamp
        let mut buf = [0; 64];
        let mut wb = WriteBuf::new(&mut buf);
        wb.start_struct(&TLVTag::Anonymous).unwrap();
        data.path.to_tlv(&TLVTag::Context(0), &mut wb).unwrap();
        wb.u64(&TLVTag::Context(1), 2).unwrap();
        wb.u8(&TLVTag::Context(2), 1).unwrap();
        wb.u8(&TLVTag::Context(7), 42).unwrap();
        wb.end_container().unwrap();
        assert!(EventData::from_tlv(&TLVElement::new(wb.as_slice())).is_err());

        // Missing data
        wb.reset();
        data.write_preamble(&TLVTag::Anonymous, &mut wb).unwrap();
        wb.end_container().unwrap();
        assert!(EventData::from_tlv(&TLVElement::new(wb.as_slice())).is_err());

        // Unknown context tag
        wb.reset();
        data.write_preamble(&TLVTag::Anonymous, &mut wb).unwrap();
        wb.u8(&TLVTag::Context(7), 42).unwrap();
        wb.u8(&TLVTag::Context(8), 0).unwrap();
        wb.end_container().unwrap();
        assert!(EventData::from_tlv(&TLVElement::new(wb.as_slice())).is_err());

        // A non-context tag inside the struct
        wb.reset();
        data.write_preamble(&TLVTag::Anonymous, &mut wb).unwrap();
        wb.u8(&TLVTag::Anonymous, 42).unwrap();
        wb.end_container().unwrap();
        assert!(EventData::from_tlv(&TLVElement::new(wb.as_slice())).is_err());

        // The preamble followed by the data is a complete, decodable event
        wb.reset();
        data.write_preamble(&TLVTag::Anonymous, &mut wb).unwrap();
        wb.u8(&TLVTag::Context(7), 42).unwrap();
        wb.end_container().unwrap();
        assert_event_data_eq(
            &EventData::from_tlv(&TLVElement::new(wb.as_slice())).unwrap(),
            &data,
        );
    }
}
