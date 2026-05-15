/*
 *
 *    Copyright (c) 2025 Project CHIP Authors
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

use core::fmt;

use crate::dm::{AttrId, ClusterId, EndptId};
use crate::error::{Error, ErrorCode};
use crate::im::{AttrData, AttrStatus};
use crate::tlv::{FromTLV, TLVArray, TLVElement, ToTLV};

/// A request to write attributes to a Matter device.
///
/// Corresponds to the `WriteRequestMessage` TLV structure in the Interaction Model.
#[derive(Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[tlvargs(lifetime = "'a")]
pub struct WriteReq<'a>(TLVElement<'a>);

impl<'a> WriteReq<'a> {
    /// Create a new `WriteReq` from a `TLVElement`.
    pub const fn new(element: TLVElement<'a>) -> Self {
        Self(element)
    }

    /// Return `Ok(true)` if this write request should suppress the response.
    pub fn supress_response(&self) -> Result<bool, Error> {
        self.0
            .r#struct()?
            .find_ctx(0)?
            .non_empty()
            .map(|t| t.bool())
            .unwrap_or(Ok(false))
    }

    /// Return `Ok(true)` if this write request is a timed request.
    pub fn timed_request(&self) -> Result<bool, Error> {
        self.0
            .r#struct()?
            .find_ctx(1)?
            .non_empty()
            .map(|t| t.bool())
            .unwrap_or(Ok(false))
    }

    /// Return the attribute data to write in this write request.
    pub fn write_requests(&self) -> Result<TLVArray<'a, AttrData<'_>>, Error> {
        TLVArray::new(self.0.r#struct()?.find_ctx(2)?)
    }

    /// Return `Ok(true)` if this write request has more chunks
    /// (i.e. more write requests coming after this one, which are for the same exchange/transaction).
    pub fn more_chunks(&self) -> Result<bool, Error> {
        self.0
            .r#struct()?
            .find_ctx(3)?
            .non_empty()
            .map(|t| t.bool())
            .unwrap_or(Ok(false))
    }
}

impl fmt::Debug for WriteReq<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteReqRef")
            .field("supress_response", &self.supress_response())
            .field("timed_request", &self.timed_request())
            .field("write_requests", &self.write_requests())
            .field("more_chunks", &self.more_chunks())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for WriteReq<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f,
            "WriteReqRef {{\n  supress_response: {:?},\n  timed_request: {:?},\n  write_requests: {:?},\n  more_chunks: {:?},\n}}",
            self.supress_response(),
            self.timed_request(),
            self.write_requests(),
            self.more_chunks(),
        )
    }
}

/// Tags corresponding to the fields in the `WriteReq` TLV structure.
///
/// Used when there is a need to perform low-level TLV serde on
/// `WriteReq` structures.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum WriteReqTag {
    SuppressResponse = 0,
    TimedRequest = 1,
    WriteRequests = 2,
    MoreChunked = 3,
}

/// A response to a write request.
///
/// Corresponds to the `WriteResponseMessage` TLV structure in the Interaction Model.
#[derive(ToTLV, FromTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct WriteResp<'a> {
    pub write_responses: TLVArray<'a, AttrStatus>,
}

impl<'a> WriteResp<'a> {
    /// Iterate the entries in `write_responses` whose path matches
    /// the given `(cluster, attr)` pair, in `(endpoint, result)` form.
    ///
    /// - **`Ok(())`** — the per-attribute write succeeded
    ///   (`IMStatusCode::Success`).
    /// - **`Err(_)`** — non-`Success` status; the `IMStatusCode`
    ///   becomes an [`Error`], covering access-check and
    ///   `Unsupported{Endpoint,Cluster,Attribute}` failures uniformly.
    /// - Entries with non-matching cluster/attr are skipped.
    /// - Entries with an absent endpoint in the path are skipped.
    ///
    /// Wildcard write requests (path missing endpoint, cluster, or
    /// attr) produce one status entry per expanded path; the
    /// iterator yields them in wire order.
    pub fn statuses(
        &self,
        cluster: ClusterId,
        attr: AttrId,
    ) -> impl Iterator<Item = (EndptId, Result<(), Error>)> + '_ {
        self.write_responses
            .iter()
            .filter_map(move |status| filter_attr_status(status.ok()?, cluster, attr))
    }
}

/// Helper for [`WriteResp::statuses`] — extracts `(endpoint, Result<(),
/// Error>)` from a single `AttrStatus` if it matches the requested
/// `(cluster, attr)` filter.
fn filter_attr_status(
    s: AttrStatus,
    cluster: ClusterId,
    attr: AttrId,
) -> Option<(EndptId, Result<(), Error>)> {
    if s.path.cluster != Some(cluster) || s.path.attr != Some(attr) {
        return None;
    }
    let endpoint = s.path.endpoint?;
    let result = if s.status.status == crate::im::IMStatusCode::Success {
        Ok(())
    } else {
        let err: Error = s
            .status
            .status
            .to_error_code()
            .unwrap_or(ErrorCode::Failure)
            .into();
        Err(err)
    };
    Some((endpoint, result))
}

/// Create a new `WriteResp` from a `TLVElement`.
///
/// Used when there is a need to perform low-level TLV serde on
/// `WriteResp` structures.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum WriteRespTag {
    WriteResponses = 0,
}
