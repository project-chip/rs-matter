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

use super::{AttrId, ClusterId, EndptId, GenericPath, IMStatusCode, Status};

pub use read::*;
pub use subscribe::*;
pub use write::*;

mod read;
mod subscribe;
mod write;

/// A path to an attribute in the Interaction Model.
///
/// Corresponds to the `AttrPathIB` TLV structure in the Interaction Model.
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(datatype = "list")]
pub struct AttrPath {
    pub tag_compression: Option<bool>,
    pub node: Option<u64>,
    pub endpoint: Option<EndptId>,
    pub cluster: Option<ClusterId>,
    pub attr: Option<AttrId>,
    pub list_index: Option<Nullable<u16>>,
}

impl AttrPath {
    /// Create a new `AttrPath` from the provided `GenericPath`,
    /// filling all fields which are not provided with their default values.
    pub const fn from_gp(path: &GenericPath) -> Self {
        Self {
            endpoint: path.endpoint,
            cluster: path.cluster,
            attr: path.leaf,
            tag_compression: None,
            node: None,
            list_index: None,
        }
    }

    /// Convert this `AttrPath` to a `GenericPath`.
    pub const fn to_gp(&self) -> GenericPath {
        GenericPath::new(self.endpoint, self.cluster, self.attr)
    }
}

/// A status response for an attribute in the Interaction Model.
///
/// Corresponds to the `AttrStatusIB` TLV structure in the Interaction Model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttrStatus {
    /// The path to the attribute.
    pub path: AttrPath,
    /// The status of the attribute operation.
    pub status: Status,
}

impl AttrStatus {
    /// Create a new `AttrStatus` with the given path, status code, and optional cluster status.
    pub const fn new(path: AttrPath, status: IMStatusCode, cluster_status: Option<u16>) -> Self {
        Self {
            path,
            status: Status::new(status, cluster_status),
        }
    }

    /// Create a new `AttrStatus` from a `GenericPath`, status code, and optional cluster status.
    ///
    /// ATTENTION: the actual reply `AttrPath` will be filled with the `GenericPath` values,
    /// however these are not necessarily expressing the full path of the incoming data as `AttrPath` does.
    ///
    /// Hence, this method is primarily useful for unit tests.
    pub const fn from_gp(
        path: &GenericPath,
        status: IMStatusCode,
        cluster_status: Option<u16>,
    ) -> Self {
        Self::new(AttrPath::from_gp(path), status, cluster_status)
    }
}

/// A data response for an attribute in the Interaction Model.
///
/// Corresponds to the `AttrDataIB` TLV structure in the Interaction Model.
#[derive(Debug, Clone, PartialEq, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct AttrData<'a> {
    /// The cluster dataver
    pub data_ver: Option<u32>,
    /// The path to the attribute.
    pub path: AttrPath,
    /// The data for the attribute, represented as a TLV element.
    pub data: TLVElement<'a>,
}

impl<'a> AttrData<'a> {
    /// Create a new `AttrData` with the given data version, path, and data.
    pub const fn new(data_ver: Option<u32>, path: AttrPath, data: TLVElement<'a>) -> Self {
        Self {
            data_ver,
            path,
            data,
        }
    }
}

/// Tags corresponding to the fields in the `AttrDataIB` TLV structure.
///
/// Used when there is a need to perform low-level TLV serde on
/// 1AttrDataIB` structures.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum AttrDataTag {
    DataVer = 0,
    Path = 1,
    Data = 2,
}

/// Attribute Response
///
/// Corresponds to the `AttributeReportIB` TLV structure in the Interaction Model.
#[derive(Clone, FromTLV, ToTLV, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub enum AttrResp<'a> {
    Status(AttrStatus),
    Data(AttrData<'a>),
}

impl<'a> From<AttrData<'a>> for AttrResp<'a> {
    fn from(value: AttrData<'a>) -> Self {
        Self::Data(value)
    }
}

impl From<AttrStatus> for AttrResp<'_> {
    fn from(value: AttrStatus) -> Self {
        Self::Status(value)
    }
}

/// Tags corresponding to the fields in the `AttributeReportIB` TLV structure.
///
/// Used when there is a need to perform low-level TLV serde on
/// `AttributeReportIB` structures.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum AttrRespTag {
    Status = 0,
    Data = 1,
}

/// Cluster Path
///
/// Corresponds to the `ClusterPathIB` TLV structure in the Interaction Model.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[tlvargs(datatype = "list")]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClusterPath {
    pub node: Option<u64>,
    pub endpoint: EndptId,
    pub cluster: ClusterId,
}

/// Event Filter
///
/// Corresponds to the `EventFilterIB` TLV structure in the Interaction Model.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EventFilter {
    pub node: Option<u64>,
    pub event_min: Option<u64>,
}

/// Data Version Filter
///
/// Corresponds to the `DataVersionFilterIB` TLV structure in the Interaction Model.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DataVersionFilter {
    pub path: ClusterPath,
    pub data_ver: u32,
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

/// A wrapper enum for `ReadReq` and `SubscribeReq` that allows downstream code to
/// treat the two in a unified manner with regards to `OpCode::ReportDataResp` type responses.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReportDataReq<'a> {
    Read(&'a ReadReq<'a>),
    Subscribe(&'a SubscribeReq<'a>),
    SubscribeReport(&'a SubscribeReq<'a>),
}

impl<'a> ReportDataReq<'a> {
    pub fn attr_requests(&self) -> Result<Option<TLVArray<'a, AttrPath>>, Error> {
        match self {
            Self::Read(req) => req.attr_requests(),
            Self::Subscribe(req) | Self::SubscribeReport(req) => req.attr_requests(),
        }
    }

    pub fn dataver_filters(&self) -> Result<Option<TLVArray<'_, DataVersionFilter>>, Error> {
        match self {
            Self::Read(req) => req.dataver_filters(),
            Self::Subscribe(req) => req.dataver_filters(),
            Self::SubscribeReport(_) => Ok(None),
        }
    }

    pub fn fabric_filtered(&self) -> Result<bool, Error> {
        match self {
            Self::Read(req) => req.fabric_filtered(),
            Self::Subscribe(req) | Self::SubscribeReport(req) => req.fabric_filtered(),
        }
    }
}

/// Report Data Message
///
/// Corresponds to the `ReportDataMessage` TLV structure in the Interaction Model.
///
/// Only used in unitand integration tests. The Data Model layer in `rs-matter` does not
/// use this structure directly, utilizing on-the-fly serialization via `ReportDataTag` instead.
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct ReportDataResp<'a> {
    pub subscription_id: Option<u32>,
    pub attr_reports: Option<TLVArray<'a, AttrResp<'a>>>,
    pub event_reports: Option<bool>,
    pub more_chunks: Option<bool>,
    pub suppress_response: Option<bool>,
}

/// Tags corresponding to the fields in the `ReportDataMessage` TLV structure.
///
/// Used when there is a need to perform low-level TLV serde on
/// `ReportDataMessage` structures.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum ReportDataRespTag {
    SubscriptionId = 0,
    AttributeReports = 1,
    _EventReport = 2,
    MoreChunkedMsgs = 3,
    SupressResponse = 4,
}
