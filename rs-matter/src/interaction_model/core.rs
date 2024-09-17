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

use core::time::Duration;

use crate::{
    error::*,
    tlv::{FromTLV, TLVArray, TLVElement, TLVTag, TLVWrite, TagType, ToTLV, TLV},
    transport::exchange::MessageMeta,
    utils::{epoch::Epoch, storage::WriteBuf},
};
use num::FromPrimitive;
use num_derive::FromPrimitive;

use super::messages::ib::{AttrPath, DataVersionFilter};
use super::messages::msg::{ReadReqRef, StatusResp, SubscribeReqRef, SubscribeResp, TimedReq};

#[macro_export]
macro_rules! cmd_enter {
    ($e:expr) => {{
        use owo_colors::OwoColorize;
        info! {"{} {}", "Handling command".cyan(), $e.cyan()}
    }};
}

#[derive(FromPrimitive, Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
            ErrorCode::UnsupportedAccess => IMStatusCode::UnsupportedAccess,
            ErrorCode::Busy => IMStatusCode::Busy,
            ErrorCode::DataVersionMismatch => IMStatusCode::DataVersionMismatch,
            ErrorCode::ResourceExhausted => IMStatusCode::ResourceExhausted,
            ErrorCode::FailSafeRequired => IMStatusCode::FailSafeRequired,
            ErrorCode::ConstraintError => IMStatusCode::ConstraintError,
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

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>> {
        TLV::u16(tag, *self as _).into_tlv_iter()
    }
}

#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
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
    pub fn meta(&self) -> MessageMeta {
        MessageMeta {
            proto_id: PROTO_ID_INTERACTION_MODEL,
            proto_opcode: *self as u8,
            reliable: true,
        }
    }

    pub fn is_tlv(&self) -> bool {
        !matches!(self, Self::Reserved)
    }
}

impl From<OpCode> for MessageMeta {
    fn from(opcode: OpCode) -> Self {
        opcode.meta()
    }
}

/* Interaction Model ID as per the Matter Spec */
pub const PROTO_ID_INTERACTION_MODEL: u16 = 0x01;

/// A wrapper enum for `ReadReq` and `SubscribeReq` that allows downstream code to
/// treat the two in a unified manner with regards to `OpCode::ReportDataResp` type responses.
#[derive(Debug, Clone)]
pub enum ReportDataReq<'a> {
    Read(&'a ReadReqRef<'a>),
    Subscribe(&'a SubscribeReqRef<'a>),
    SubscribeReport(&'a SubscribeReqRef<'a>),
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

impl StatusResp {
    pub fn write(wb: &mut WriteBuf, status: IMStatusCode) -> Result<(), Error> {
        let status = Self { status };
        status.to_tlv(&TagType::Anonymous, wb)
    }
}

impl TimedReq {
    pub fn timeout_instant(&self, epoch: Epoch) -> Duration {
        epoch()
            .checked_add(Duration::from_millis(self.timeout as _))
            .unwrap()
    }
}

impl SubscribeResp {
    pub fn write<'a>(
        wb: &'a mut WriteBuf,
        subscription_id: u32,
        max_int: u16,
    ) -> Result<&'a [u8], Error> {
        let resp = Self::new(subscription_id, max_int);
        resp.to_tlv(&TagType::Anonymous, &mut *wb)?;

        Ok(wb.as_slice())
    }
}
