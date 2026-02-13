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

//! This module contains the TLV-serde types as defined by the Interaction Model.
//!
//! Additionally, it contains a very simple IM implementation - busy - which always
//! returns a busy status code, to all incoming IM requests.

use num::FromPrimitive;
use num_derive::FromPrimitive;

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};
use crate::transport::exchange::MessageMeta;

pub use attr::*;
pub use event::*;
pub use invoke::*;
pub use status::*;
pub use timed::*;

pub mod busy;

mod attr;
mod event;
mod invoke;
mod status;
mod timed;

/// Interaction Model ID as per the Matter Core spec
pub const PROTO_ID_INTERACTION_MODEL: u16 = 0x01;

/// An enumeration of all possible error codes that can be returned by the Interaction Model.
#[derive(FromPrimitive, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum IMStatusCode {
    Success = 0,
    Failure = 1,
    InvalidSubscription = 0x7D,
    UnsupportedAccess = 0x7E,
    UnsupportedEndpoint = 0x7F,
    InvalidAction = 0x80,
    UnsupportedCommand = 0x81,
    InvalidCommand = 0x85,
    UnsupportedAttribute = 0x86,
    ConstraintError = 0x87,
    UnsupportedWrite = 0x88,
    ResourceExhausted = 0x89,
    NotFound = 0x8b,
    UnreportableAttribute = 0x8c,
    InvalidDataType = 0x8d,
    UnsupportedRead = 0x8f,
    DataVersionMismatch = 0x92,
    Timeout = 0x94,
    Busy = 0x9c,
    UnsupportedCluster = 0xc3,
    NoUpstreamSubscription = 0xc5,
    NeedsTimedInteraction = 0xc6,
    UnsupportedEvent = 0xc7,
    PathsExhausted = 0xc8,
    TimedRequestMisMatch = 0xc9,
    FailSafeRequired = 0xca,
}

impl From<ErrorCode> for IMStatusCode {
    fn from(e: ErrorCode) -> Self {
        match e {
            ErrorCode::EndpointNotFound => IMStatusCode::UnsupportedEndpoint,
            ErrorCode::ClusterNotFound => IMStatusCode::UnsupportedCluster,
            ErrorCode::AttributeNotFound => IMStatusCode::UnsupportedAttribute,
            ErrorCode::CommandNotFound => IMStatusCode::UnsupportedCommand,
            ErrorCode::InvalidAction => IMStatusCode::InvalidAction,
            ErrorCode::InvalidCommand => IMStatusCode::InvalidCommand,
            ErrorCode::InvalidDataType => IMStatusCode::InvalidDataType,
            ErrorCode::UnsupportedAccess => IMStatusCode::UnsupportedAccess,
            ErrorCode::Busy => IMStatusCode::Busy,
            ErrorCode::DataVersionMismatch => IMStatusCode::DataVersionMismatch,
            ErrorCode::ResourceExhausted => IMStatusCode::ResourceExhausted,
            ErrorCode::FailSafeRequired => IMStatusCode::FailSafeRequired,
            ErrorCode::ConstraintError => IMStatusCode::ConstraintError,
            ErrorCode::NotFound => IMStatusCode::NotFound,
            ErrorCode::Failure => IMStatusCode::Failure,
            _ => IMStatusCode::Failure,
        }
    }
}

impl From<Error> for IMStatusCode {
    fn from(value: Error) -> Self {
        Self::from(value.code())
    }
}

impl FromTLV<'_> for IMStatusCode {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error> {
        FromPrimitive::from_u16(t.u16()?).ok_or_else(|| ErrorCode::Invalid.into())
    }
}

impl ToTLV for IMStatusCode {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.u16(tag, *self as _)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        TLV::u16(tag, *self as _).into_tlv_iter()
    }
}

/// An enumeration of all possible opcodes used in the Interaction Model.
#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OpCode {
    Reserved = 0,
    StatusResponse = 1,
    ReadRequest = 2,
    SubscribeRequest = 3,
    SubscribeResponse = 4,
    ReportData = 5,
    WriteRequest = 6,
    WriteResponse = 7,
    InvokeRequest = 8,
    InvokeResponse = 9,
    TimedRequest = 10,
}

impl OpCode {
    /// Return the opcode as a `MessageMeta` structure, which contains
    /// the protocol ID, opcode, and reliability information.
    ///
    /// Reliability is set to `true` as all IM messages are reliable.
    pub const fn meta(&self) -> MessageMeta {
        MessageMeta {
            proto_id: PROTO_ID_INTERACTION_MODEL,
            proto_opcode: *self as u8,
            reliable: true,
        }
    }

    /// Return `true` if the opcode payload is in TLV format.
    ///
    /// Currently, the payload of all IM opcodes except `Reserved` is in TLV format.
    pub const fn is_tlv(&self) -> bool {
        !matches!(self, Self::Reserved)
    }
}

impl From<OpCode> for MessageMeta {
    fn from(opcode: OpCode) -> Self {
        opcode.meta()
    }
}

// Type aliases for first-class matter types
pub type EndptId = u16;
pub type ClusterId = u32;
pub type AttrId = u32;
pub type CmdId = u32;
pub type ActionId = u8;
pub type AttributeId = u32;
pub type ClusterStatus = u8;
pub type CommandRef = u16;
pub type CompressedFabricId = u64;
pub type DataVersion = u32;
pub type DeviceTypeId = u32;
pub type ElapsedS = u32;
pub type EventId = u32;
pub type EventNumber = u64;
pub type FabricId = u64;
pub type FabricIndex = u8;
pub type FieldId = u32;
pub type ListIndex = u16;
pub type LocalizedStringIdentifier = u16;
pub type TransactionId = u32;
pub type KeysetId = u16;
pub type InteractionModelRevision = u8;
pub type SubscriptionId = u32;
pub type SceneId = u8;
pub type Percent = u8;
pub type Percent100ths = u16;
pub type EnergyMilliWh = i64;
pub type EnergyMilliVAh = i64;
pub type EnergyMilliVARh = i64;
pub type AmperageMilliA = i64;
pub type PowerMilliW = i64;
pub type PowerMilliVA = i64;
pub type PowerMilliVAR = i64;
pub type VoltageMilliV = i64;
pub type Money = i64;

/// A generic (possibly a wildcard) path with endpoint, clusters, and a leaf
///
/// The leaf could be a command, an attribute, or an event
///
/// Note that this type does not implement `FromTLV` / `ToTLV` because it does not correspond
/// to a specific TLV structure in the Interaction Model.
///
/// Note also that it only captures a _subset_ of the fields of `AttrPath`, and as such, it should be used with care!
///
/// Look at `AttrPath`, `CmdPath`, and `EventPath` for specific TLV structures, which
/// can be turned into `GenericPath` using their `to_gp()` method.
#[derive(Default, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GenericPath {
    /// The endpoint ID, if specified, otherwise `None` for wildcard
    pub endpoint: Option<EndptId>,
    /// The cluster ID, if specified, otherwise `None` for wildcard
    pub cluster: Option<ClusterId>,
    /// The leaf ID, if specified, otherwise `None` for wildcard
    pub leaf: Option<u32>,
}

impl GenericPath {
    /// Create a new `GenericPath` with the given endpoint, cluster, and leaf.
    pub const fn new(
        endpoint: Option<EndptId>,
        cluster: Option<ClusterId>,
        leaf: Option<u32>,
    ) -> Self {
        Self {
            endpoint,
            cluster,
            leaf,
        }
    }

    /// Return Ok, if the path is non wildcard, otherwise returns an error
    pub fn not_wildcard(&self) -> Result<(EndptId, ClusterId, u32), Error> {
        match *self {
            GenericPath {
                endpoint: Some(e),
                cluster: Some(c),
                leaf: Some(l),
            } => Ok((e, c, l)),
            _ => Err(ErrorCode::Invalid.into()),
        }
    }

    /// Return true, if the path is wildcard
    pub const fn is_wildcard(&self) -> bool {
        !matches!(
            *self,
            GenericPath {
                endpoint: Some(_),
                cluster: Some(_),
                leaf: Some(_),
            }
        )
    }
}
