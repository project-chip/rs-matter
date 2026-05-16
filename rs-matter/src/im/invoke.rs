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

//! This module contains types related to command invocations in the Interaction Model.

use core::fmt;

use crate::dm::GlobalElements;
use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVArray, TLVElement, ToTLV};

use super::{ClusterId, CmdId, EndptId, GenericPath, IMStatusCode, Status};

/// A path to a command in the Interaction Model.
///
/// Corresponds to the `CommandPathIB` block in the Matter Core spec.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[tlvargs(datatype = "list")]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CmdPath {
    /// The endpoint ID, if specified, otherwise `None` for wildcard
    pub endpoint: Option<EndptId>,
    /// The cluster ID, if specified, otherwise `None` for wildcard
    pub cluster: Option<ClusterId>,
    /// The command ID, if specified, otherwise `None` for wildcard
    pub cmd: Option<CmdId>,
}

/// Tags corresponding to the fields in the `CommandPathIB` TLV
/// structure (Matter Core spec §10.6.7). `CmdPath` is encoded as a
/// TLV *list* with positional context tags 0..2. Used by callers that
/// need to perform low-level TLV serde on `CmdPath` data.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum CmdPathTag {
    Endpoint = 0,
    Cluster = 1,
    Command = 2,
}

impl CmdPath {
    /// Create a new instance from the given IDs.
    pub const fn new(
        endpoint: Option<EndptId>,
        cluster: Option<ClusterId>,
        cmd: Option<CmdId>,
    ) -> Self {
        Self {
            endpoint,
            cluster,
            cmd,
        }
    }

    /// Create a new instance from the given `GenericPath`.
    pub const fn from_gp(path: &GenericPath) -> Self {
        Self {
            endpoint: path.endpoint,
            cluster: path.cluster,
            cmd: path.leaf,
        }
    }

    /// Convert this command path to a `GenericPath`.
    pub const fn to_gp(&self) -> GenericPath {
        GenericPath::new(self.endpoint, self.cluster, self.cmd)
    }

    /// Return true, if the path is wildcard
    pub const fn is_wildcard(&self) -> bool {
        self.endpoint.is_none() || self.cluster.is_none() || self.cmd.is_none()
    }
}

/// Status of a command invocation.
///
/// Returned when a command invocation does not have a specific generated-command
/// response.
///
/// Corresponds to the `CommandStatusIB` block in the Matter Core spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CmdStatus {
    /// The command path associated with this status.
    pub path: CmdPath,
    /// The status of the command invocation.
    pub status: Status,
    /// The CommandRef echoed from the corresponding `CommandDataIB`.
    /// Required when the request was part of a batched (multi-path) invoke.
    pub command_ref: Option<u16>,
}

impl CmdStatus {
    /// Create a new command status with the given path, status code, optional cluster status,
    /// and optional CommandRef (echoed from the request when batched).
    pub const fn new(
        path: CmdPath,
        status: IMStatusCode,
        cluster_status: Option<u16>,
        command_ref: Option<u16>,
    ) -> Self {
        Self {
            path,
            status: Status {
                status,
                cluster_status,
            },
            command_ref,
        }
    }
}

/// Data associated with a command invocation.
///
/// Corresponds to the `CommandDataIB` struct in the Matter Core spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct CmdData<'a> {
    pub path: CmdPath,
    pub data: TLVElement<'a>,
    /// CommandRef set by the requester to correlate batched invokes with their responses.
    /// Mandatory when the `InvokeRequestMessage` carries more than one `CommandDataIB`.
    pub command_ref: Option<u16>,
}

impl<'a> CmdData<'a> {
    /// Create a new command data instance with the specified path, data, and optional CommandRef.
    pub const fn new(path: CmdPath, data: TLVElement<'a>, command_ref: Option<u16>) -> Self {
        Self {
            path,
            data,
            command_ref,
        }
    }
}

/// Tags corresponding to the fields in the `CmdData` struct.
///
/// Used when there is a need to perform low-level TLV serde on
/// `CmdData` data.
pub enum CmdDataTag {
    Path = 0,
    Data = 1,
    CommandRef = 2,
}

/// Response to a command invocation.
///
/// Corresponds to the `InvokeResponseIB` struct in the Matter Core spec.
#[derive(Clone, FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub enum CmdResp<'a> {
    Cmd(CmdData<'a>),
    Status(CmdStatus),
}

impl CmdResp<'_> {
    /// Create the `Status` variant of a command response
    /// with the given command path, status code, optional cluster status, and optional CommandRef.
    pub const fn status_new(
        cmd_path: CmdPath,
        status: IMStatusCode,
        cluster_status: Option<u16>,
        command_ref: Option<u16>,
    ) -> Self {
        Self::Status(CmdStatus {
            path: cmd_path,
            status: Status::new(status, cluster_status),
            command_ref,
        })
    }
}

impl<'a> From<CmdData<'a>> for CmdResp<'a> {
    fn from(value: CmdData<'a>) -> Self {
        Self::Cmd(value)
    }
}

/// Tags corresponding to the fields in the `CmdResp` enum.
///
/// Used when there is a need to perform low-level TLV serde on
/// `CmdResp` data.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum CmdRespTag {
    Cmd = 0,
    Status = 1,
}

impl From<CmdStatus> for CmdResp<'_> {
    fn from(value: CmdStatus) -> Self {
        Self::Status(value)
    }
}

/// A request to invoke commands in the Interaction Model.
///
/// Corresponds to the `InvokeRequestMessage` struct in the Matter Core spec.
#[derive(Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[tlvargs(lifetime = "'a")]
pub struct InvReq<'a>(TLVElement<'a>);

impl<'a> InvReq<'a> {
    /// Create a new `InvReq` instance from the given TLV element.
    pub const fn new(element: TLVElement<'a>) -> Self {
        Self(element)
    }

    /// Return `true` if the request indicates that the response should be suppressed.
    pub fn suppress_response(&self) -> Result<bool, Error> {
        self.0
            .r#struct()?
            .find_ctx(0)?
            .non_empty()
            .map(|t| t.bool())
            .unwrap_or(Ok(false))
    }

    /// Return `true` if the request indicates that it is a timed request.
    pub fn timed_request(&self) -> Result<bool, Error> {
        self.0
            .r#struct()?
            .find_ctx(1)?
            .non_empty()
            .map(|t| t.bool())
            .unwrap_or(Ok(false))
    }

    /// Return the invocation requests contained in this request.
    pub fn inv_requests(&self) -> Result<Option<TLVArray<'a, CmdData<'a>>>, Error> {
        Option::from_tlv(&self.0.r#struct()?.find_ctx(2)?)
    }
}

impl fmt::Debug for InvReq<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InvReqRef")
            .field("suppress_response", &self.suppress_response())
            .field("timed_request", &self.timed_request())
            .field("inv_requests", &self.inv_requests())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for InvReq<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f,
            "InvReqRef {{\n  suppress_response: {:?},\n  timed_request: {:?},\n  inv_requests: {:?},\n}}",
            self.suppress_response(),
            self.timed_request(),
            self.inv_requests(),
        )
    }
}

/// Tags corresponding to the fields in the `InvReq` struct.
///
/// Used when there is a need to perform low-level TLV serde on
/// `InvReq` data.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum InvReqTag {
    SupressResponse = 0,
    TimedReq = 1,
    InvokeRequests = 2,
}

/// Tags corresponding to the fields in the `InvokeResponseMessage`
/// IM struct.
///
/// Used when there is a need to perform low-level TLV serde on
/// `InvokeResponseMessage` data.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum InvRespTag {
    SupressResponse = 0,
    InvokeResponses = 1,
}

/// A response to an invoke request in the Interaction Model.
///
/// Corresponds to the `InvokeResponseMessage` TLV structure in the Interaction Model.
/// Used by clients to parse invoke responses from devices.
#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct InvokeResp<'a> {
    /// Whether the response should be suppressed (echo from request)
    pub suppress_response: Option<bool>,
    /// The list of invoke responses
    pub invoke_responses: Option<TLVArray<'a, CmdResp<'a>>>,
    /// Whether there are more chunked messages coming
    pub more_chunks: Option<bool>,
    /// `interactionModelRevision` (TLV context tag `0xFF`). Mandatory in
    /// every IM message we send; modelled as `Option<u8>` so we tolerate
    /// peers that omit it (the C++ SDK is tolerant in practice).
    #[tagval(GlobalElements::InteractionModelRevision as u8)]
    pub interaction_model_revision: Option<u8>,
}

impl<'a> InvokeResp<'a> {
    /// Iterate the entries in `invoke_responses` whose path matches
    /// the given `(cluster, cmd)` pair, in `(endpoint, result)` form.
    ///
    /// - **`Ok(R)`** — `CmdResp::Cmd` entry; the embedded `data` is
    ///   decoded via `FromTLV` into `R`.
    /// - **`Err(_)`** — `CmdResp::Status` entry; the `IMStatusCode` is
    ///   converted to an [`Error`]. This covers access-check failures
    ///   (`UnsupportedAccess` etc.) and all `Unsupported*` cases
    ///   (`UnsupportedEndpoint`, `UnsupportedCluster`, `UnsupportedCommand`)
    ///   uniformly — the peer echoes the requested path on status, so
    ///   the filter still catches them.
    /// - Entries with a non-matching cluster/cmd are silently filtered
    ///   out (they belong to a *different* `.responses(...)` call).
    /// - Entries with an absent endpoint in the path are skipped
    ///   (the wire spec requires concrete paths on invoke responses;
    ///   a missing endpoint indicates a malformed response).
    ///
    /// `R = ()` for `DefaultSuccess` commands. Codegen-emitted
    /// response structs (e.g. `MoveToLevelResponse<'a>`) implement
    /// `FromTLV` over `'a` and plug in directly.
    ///
    /// Multi-response: single-command invokes per Matter Core spec
    /// §8.2.5 carry concrete paths only, but batched invokes
    /// (multiple `CommandDataIB`s in one `InvokeRequestMessage`) can
    /// produce multiple matching entries — the iterator yields one
    /// per match, in wire order.
    pub fn responses<R>(
        &self,
        cluster: ClusterId,
        cmd: CmdId,
    ) -> impl Iterator<Item = (EndptId, Result<R, Error>)> + use<'_, 'a, R>
    where
        R: FromTLV<'a> + 'a,
    {
        self.invoke_responses
            .as_ref()
            .into_iter()
            .flat_map(|arr| arr.iter())
            .filter_map(move |resp| filter_cmd_resp::<R>(resp.ok()?, cluster, cmd))
    }

    /// Counterpart of [`Self::responses`] for `DefaultSuccess`
    /// commands — the ones whose IDL `output` is `DefaultSuccess` and
    /// thus carry no per-command response payload. Filters the
    /// `invoke_responses` list by `(cluster, cmd)` and yields
    /// `(endpoint, Result<(), Error>)`:
    ///
    /// - **`Ok(())`** — a `CmdResp::Status(Success)` entry for the
    ///   given path (this is what a batched DefaultSuccess command
    ///   produces on the wire).
    /// - **`Err(_)`** — a non-`Success` `CmdResp::Status`, with the
    ///   same `IMStatusCode`-to-[`Error`] mapping as
    ///   [`Self::responses`].
    /// - `CmdResp::Cmd` entries (which would indicate the peer
    ///   replied with payload data for a command we asked to be
    ///   DefaultSuccess) are skipped silently.
    /// - Entries with non-matching cluster/cmd or absent endpoint
    ///   are skipped as in [`Self::responses`].
    ///
    /// Note: a *single-command* DefaultSuccess invoke produces a
    /// top-level `StatusResponse(Success)` instead of an
    /// `InvokeResponseMessage`, so the response array is absent
    /// entirely and this iterator yields nothing — use
    /// [`crate::im::client::InvokeRespChunk::is_status_only`] to
    /// detect that case. The iterator here is only useful for
    /// *batched* invokes that mix DefaultSuccess and response-bearing
    /// commands.
    pub fn statuses(
        &self,
        cluster: ClusterId,
        cmd: CmdId,
    ) -> impl Iterator<Item = (EndptId, Result<(), Error>)> + '_ {
        self.invoke_responses
            .as_ref()
            .into_iter()
            .flat_map(|arr| arr.iter())
            .filter_map(move |resp| match resp.ok()? {
                CmdResp::Status(s) => {
                    if s.path.cluster != Some(cluster) || s.path.cmd != Some(cmd) {
                        return None;
                    }
                    let endpoint = s.path.endpoint?;
                    let result = if s.status.status == IMStatusCode::Success {
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
                CmdResp::Cmd(_) => None,
            })
    }
}

/// Helper for [`InvokeResp::responses`] — extracts `(endpoint,
/// Result<R, Error>)` from a single `CmdResp` if it matches the
/// requested `(cluster, cmd)` filter.
fn filter_cmd_resp<'a, R>(
    resp: CmdResp<'a>,
    cluster: ClusterId,
    cmd: CmdId,
) -> Option<(EndptId, Result<R, Error>)>
where
    R: FromTLV<'a>,
{
    match resp {
        CmdResp::Cmd(data) => {
            if data.path.cluster != Some(cluster) || data.path.cmd != Some(cmd) {
                return None;
            }
            let endpoint = data.path.endpoint?;
            Some((endpoint, R::from_tlv(&data.data)))
        }
        CmdResp::Status(s) => {
            if s.path.cluster != Some(cluster) || s.path.cmd != Some(cmd) {
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
