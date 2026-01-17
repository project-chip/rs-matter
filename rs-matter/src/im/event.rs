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



use crate::tlv::{FromTLV, TLVElement, ToTLV};

use super::{ClusterId, EndptId, GenericPath, IMStatusCode, Status};



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
/// 1AttrDataIB` structures.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
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
    Data = 7
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
#[tlvargs(lifetime = "'a")] // TODO(events): What is this?
pub enum EventResp<'a> {
    Status(EventStatus),
    Data(EventData<'a>),
}


/// A data response for an event in the Interaction Model.
///
/// Corresponds to the `EventDataIB` TLV structure in the Interaction Model.
#[derive(Debug, Clone, PartialEq, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
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
    pub const fn new(path: EventPath, event_number: u64, priority: u8, timestamp: EventDataTimestamp, data: TLVElement<'a>) -> Self {
        Self {
            path,
            event_number,
            priority,
            timestamp,
            data,
        }
    }
}

// Timestamp on an EventData, corresponds to the mutually exclusive timestamp
// options on EventDataIB in the Interaction Model
#[derive(Debug, Clone, PartialEq, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EventDataTimestamp {
    // TODO(events) docstrings, see section 10.6.9.1->10.6.9.3
    // TODO(events) how do we ensure these get TLV-encoded correctly? They should have fields 3,4,5 or 6, see 10.6.9 in the spec
    EpochTimestamp(u64),
    SystemTimestamp(u64),
    DeltaEpochTimestamp(u64),
    DeltaSystemTimestamp(u64),
}