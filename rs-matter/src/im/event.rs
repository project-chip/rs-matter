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



use crate::error::Error;
use crate::tlv::{FromTLV, Nullable, TLVArray, TLVElement, ToTLV};

use super::{AttrId, EventId, ClusterId, EndptId, GenericPath, IMStatusCode, Status};

/// A path to an event in the Interaction Model.
///
/// Corresponds to the `EventPathIB` TLV structure in the Interaction Model.
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(datatype = "list")]
pub struct EventPath {
    pub node: Option<u64>,
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
            // TODO(events) validate that this is the correct way to map from GP
            endpoint: path.endpoint,
            cluster: path.cluster,
            event: path.leaf,
            node: None,
            is_urgent: None,
        }
    }

    /// Convert this `EventPath` to a `GenericPath`.
    pub const fn to_gp(&self) -> GenericPath {
        GenericPath::new(self.endpoint, self.cluster, self.attr)
    }
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