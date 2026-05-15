/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

use crate::error::{Error, ErrorCode};
use crate::im::{EventFilter, NodeId};
use crate::tlv::{FromTLV, Nullable, TLVArray, TLVElement, ToTLV};

use super::{AttrId, ClusterId, EndptId, EventPath, EventResp, GenericPath, IMStatusCode, Status};

pub use read::*;
pub use read_builder::*;
pub use subscribe::*;
pub use write::*;
pub use write_builder::*;

mod read;
mod read_builder;
mod subscribe;
mod write;
mod write_builder;

/// A path to an attribute in the Interaction Model.
///
/// Corresponds to the `AttrPathIB` TLV structure in the Interaction Model.
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(datatype = "list")]
pub struct AttrPath {
    pub tag_compression: Option<bool>,
    pub node: Option<NodeId>,
    pub endpoint: Option<EndptId>,
    pub cluster: Option<ClusterId>,
    pub attr: Option<AttrId>,
    pub list_index: Option<Nullable<u16>>,
}

/// Tags corresponding to the fields in the `AttributePathIB` TLV
/// structure (Matter Core spec §10.6.2). `AttrPath` is encoded as a
/// TLV *list* with positional context tags 0..5. Used by callers that
/// need to perform low-level TLV serde on `AttrPath` data.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum AttrPathTag {
    TagCompression = 0,
    Node = 1,
    Endpoint = 2,
    Cluster = 3,
    Attribute = 4,
    ListIndex = 5,
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

    /// Return true, if the path is wildcard
    pub const fn is_wildcard(&self) -> bool {
        self.endpoint.is_none() || self.cluster.is_none() || self.attr.is_none()
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

/// Data Version Filter
///
/// Corresponds to the `DataVersionFilterIB` TLV structure in the Interaction Model.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DataVersionFilter {
    pub path: ClusterPath,
    pub data_ver: u32,
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

    pub fn event_requests(&self) -> Result<Option<TLVArray<'a, EventPath>>, Error> {
        match self {
            Self::Read(req) => req.event_requests(),
            Self::Subscribe(req) | Self::SubscribeReport(req) => req.event_requests(),
        }
    }

    pub fn dataver_filters(&self) -> Result<Option<TLVArray<'_, DataVersionFilter>>, Error> {
        match self {
            Self::Read(req) => req.dataver_filters(),
            Self::Subscribe(req) => req.dataver_filters(),
            Self::SubscribeReport(_) => Ok(None),
        }
    }

    pub fn event_filters(&self) -> Result<Option<TLVArray<'_, EventFilter>>, Error> {
        match self {
            Self::Read(req) => req.event_filters(),
            Self::Subscribe(req) | Self::SubscribeReport(req) => req.event_filters(),
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
    pub event_reports: Option<TLVArray<'a, EventResp<'a>>>,
    pub more_chunks: Option<bool>,
    pub suppress_response: Option<bool>,
}

impl<'a> ReportDataResp<'a> {
    /// Iterate the entries in `attr_reports` whose path matches the
    /// given `(cluster, attr)` pair, in `(endpoint, result)` form.
    ///
    /// - **`Ok(T)`** — `AttrResp::Data` entry; the embedded `data` is
    ///   decoded via `FromTLV` into `T`.
    /// - **`Err(_)`** — `AttrResp::Status` entry; the `IMStatusCode`
    ///   becomes an [`Error`]. This catches access-check failures
    ///   (`UnsupportedAccess`, …) and `Unsupported{Endpoint,Cluster,Attribute}`
    ///   uniformly — the peer echoes the requested path on status, so
    ///   the filter still matches those entries.
    /// - Entries with non-matching cluster/attr are silently skipped.
    /// - Entries with an absent endpoint in the path are skipped
    ///   (would indicate a malformed report).
    ///
    /// Wildcard reads (path missing endpoint, cluster, or attr in the
    /// request) legally produce multiple matching reports — the
    /// iterator yields one per expanded path, in wire order.
    pub fn attrs<T>(
        &self,
        cluster: ClusterId,
        attr: AttrId,
    ) -> impl Iterator<Item = (EndptId, Result<T, Error>)> + use<'_, 'a, T>
    where
        T: FromTLV<'a> + 'a,
    {
        self.attr_reports
            .as_ref()
            .into_iter()
            .flat_map(|arr| arr.iter())
            .filter_map(move |resp| filter_attr_resp::<T>(resp.ok()?, cluster, attr))
    }
}

/// Helper for [`ReportDataResp::attrs`] — extracts `(endpoint,
/// Result<T, Error>)` from a single `AttrResp` if it matches the
/// requested `(cluster, attr)` filter.
fn filter_attr_resp<'a, T>(
    resp: AttrResp<'a>,
    cluster: ClusterId,
    attr: AttrId,
) -> Option<(EndptId, Result<T, Error>)>
where
    T: FromTLV<'a>,
{
    match resp {
        AttrResp::Data(data) => {
            if data.path.cluster != Some(cluster) || data.path.attr != Some(attr) {
                return None;
            }
            let endpoint = data.path.endpoint?;
            Some((endpoint, T::from_tlv(&data.data)))
        }
        AttrResp::Status(s) => {
            if s.path.cluster != Some(cluster) || s.path.attr != Some(attr) {
                return None;
            }
            let endpoint = s.path.endpoint?;
            let err: Error = s
                .status
                .status
                .to_error_code()
                .unwrap_or(ErrorCode::Failure)
                .into();
            Some((endpoint, Err(err)))
        }
    }
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
    EventReports = 2,
    MoreChunkedMsgs = 3,
    SupressResponse = 4,
}
