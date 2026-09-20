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
/// structure (Matter Core spec). `CmdPath` is encoded as a
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
    #[tagval(crate::im::encoding::IM_REVISION_TAG)]
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
    /// carry concrete paths only, but batched invokes
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::error::ErrorCode;
    use crate::im::IM_REVISION;
    use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV};
    use crate::utils::storage::WriteBuf;

    use super::{
        CmdData, CmdPath, CmdResp, CmdStatus, GenericPath, IMStatusCode, InvRespTag, InvokeResp,
    };

    fn cmd_path(endpoint: u16, cluster: u32, cmd: u32) -> CmdPath {
        CmdPath::new(Some(endpoint), Some(cluster), Some(cmd))
    }

    #[test]
    fn cmd_path_helpers_and_cmd_resp_round_trip() {
        let gp = GenericPath::new(Some(1), Some(6), Some(2));
        let path = CmdPath::from_gp(&gp);
        assert_eq!(path, cmd_path(1, 6, 2));
        assert_eq!(path.to_gp(), gp);
        assert!(!path.is_wildcard());
        assert!(CmdPath::new(None, Some(6), Some(2)).is_wildcard());
        assert!(CmdPath::new(Some(1), None, Some(2)).is_wildcard());
        assert!(CmdPath::new(Some(1), Some(6), None).is_wildcard());

        let mut buf = [0; 64];
        let mut wb = WriteBuf::new(&mut buf);

        let status = CmdResp::status_new(
            cmd_path(1, 6, 2),
            IMStatusCode::InvalidCommand,
            Some(0x1234),
            Some(7),
        );
        status.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        assert_eq!(
            wb.as_slice(),
            &[
                0x15, // InvokeResponseIB
                0x35, 1, // Status
                0x37, 0, 0x24, 0, 1, 0x24, 1, 6, 0x24, 2, 2, 0x18, // Path list
                0x35, 1, 0x24, 0, 0x85, 0x25, 1, 0x34, 0x12, 0x18, // StatusIB
                0x24, 2, 7, // CommandRef
                0x18, 0x18,
            ]
        );
        let CmdResp::Status(decoded) = CmdResp::from_tlv(&TLVElement::new(wb.as_slice())).unwrap()
        else {
            panic!("expected a status");
        };
        assert_eq!(
            decoded,
            CmdStatus::new(
                cmd_path(1, 6, 2),
                IMStatusCode::InvalidCommand,
                Some(0x1234),
                Some(7)
            )
        );

        let payload = [0x35, 1, 0x24, 0, 9, 0x18];
        let data = CmdResp::from(CmdData::new(
            cmd_path(1, 6, 4),
            TLVElement::new(&payload),
            None,
        ));
        wb.reset();
        data.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        assert_eq!(
            wb.as_slice(),
            &[
                0x15, // InvokeResponseIB
                0x35, 0, // Cmd
                0x37, 0, 0x24, 0, 1, 0x24, 1, 6, 0x24, 2, 4, 0x18, // Path list
                0x35, 1, 0x24, 0, 9, 0x18, // Data
                0x18, 0x18,
            ]
        );
        let CmdResp::Cmd(decoded) = CmdResp::from_tlv(&TLVElement::new(wb.as_slice())).unwrap()
        else {
            panic!("expected command data");
        };
        assert_eq!(decoded.path, cmd_path(1, 6, 4));
        assert_eq!(decoded.command_ref, None);
        assert_eq!(
            decoded
                .data
                .structure()
                .unwrap()
                .ctx(0)
                .unwrap()
                .u8()
                .unwrap(),
            9
        );
    }

    #[test]
    fn invoke_resp_filters_responses_and_statuses() {
        let payload = [0x35, 1, 0x24, 0, 5, 0x18];

        let mut buf = [0; 256];
        let mut wb = WriteBuf::new(&mut buf);

        wb.start_struct(&TLVTag::Anonymous).unwrap();
        wb.bool(&TLVTag::Context(InvRespTag::SupressResponse as u8), false)
            .unwrap();
        wb.start_array(&TLVTag::Context(InvRespTag::InvokeResponses as u8))
            .unwrap();
        for resp in [
            CmdResp::from(CmdData::new(
                cmd_path(1, 6, 1),
                TLVElement::new(&payload),
                Some(1),
            )),
            CmdResp::status_new(cmd_path(1, 6, 2), IMStatusCode::Success, None, Some(2)),
            CmdResp::status_new(cmd_path(2, 6, 2), IMStatusCode::Busy, None, Some(3)),
            // Other command: filtered out of both iterators
            CmdResp::status_new(cmd_path(1, 6, 9), IMStatusCode::Failure, None, None),
            // No endpoint: filtered out
            CmdResp::from(CmdData::new(
                CmdPath::new(None, Some(6), Some(1)),
                TLVElement::new(&payload),
                None,
            )),
            // A status for the data-bearing command: an error in `responses`
            CmdResp::status_new(
                cmd_path(3, 6, 1),
                IMStatusCode::UnsupportedEndpoint,
                None,
                None,
            ),
        ] {
            resp.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        }
        wb.end_container().unwrap();
        wb.bool(&TLVTag::Context(2), true).unwrap();
        wb.u8(&TLVTag::Context(0xFF), IM_REVISION).unwrap();
        wb.end_container().unwrap();

        let resp = InvokeResp::from_tlv(&TLVElement::new(wb.as_slice())).unwrap();
        assert_eq!(resp.suppress_response, Some(false));
        assert_eq!(resp.more_chunks, Some(true));
        assert_eq!(resp.interaction_model_revision, Some(IM_REVISION));
        assert_eq!(resp.invoke_responses.as_ref().unwrap().iter().count(), 6);

        let mut responses = resp.responses::<TLVElement>(6, 1);
        let (endpoint, data) = responses.next().unwrap();
        assert_eq!(endpoint, 1);
        assert_eq!(
            data.unwrap()
                .structure()
                .unwrap()
                .ctx(0)
                .unwrap()
                .u8()
                .unwrap(),
            5
        );
        let (endpoint, data) = responses.next().unwrap();
        assert_eq!(endpoint, 3);
        assert_eq!(data.unwrap_err().code(), ErrorCode::EndpointNotFound);
        assert!(responses.next().is_none());

        let mut statuses = resp.statuses(6, 2);
        let (endpoint, result) = statuses.next().unwrap();
        assert_eq!(endpoint, 1);
        assert!(result.is_ok());
        let (endpoint, result) = statuses.next().unwrap();
        assert_eq!(endpoint, 2);
        assert_eq!(result.unwrap_err().code(), ErrorCode::Busy);
        assert!(statuses.next().is_none());

        // `statuses` ignores data-bearing entries even for a matching path
        assert_eq!(resp.statuses(6, 1).count(), 1);
    }
}
