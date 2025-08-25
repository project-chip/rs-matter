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

//! This module contains types related to command invocations in the Interaction Model.

use core::fmt;

use crate::error::Error;
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
}

impl CmdStatus {
    /// Create a new command status with the given path, status code, and optional cluster status.
    pub const fn new(path: CmdPath, status: IMStatusCode, cluster_status: Option<u16>) -> Self {
        Self {
            path,
            status: Status {
                status,
                cluster_status,
            },
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
}

impl<'a> CmdData<'a> {
    /// Create a new command data instance with the specified path and data.
    pub const fn new(path: CmdPath, data: TLVElement<'a>) -> Self {
        Self { path, data }
    }
}

/// Tags corresponding to the fields in the `CmdData` struct.
///
/// Used when there is a need to perform low-level TLV serde on
/// `CmdData` data.
pub enum CmdDataTag {
    Path = 0,
    Data = 1,
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
    /// with the given command path, status code, and optional cluster status.
    pub const fn status_new(
        cmd_path: CmdPath,
        status: IMStatusCode,
        cluster_status: Option<u16>,
    ) -> Self {
        Self::Status(CmdStatus {
            path: cmd_path,
            status: Status::new(status, cluster_status),
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
