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

use num_derive::FromPrimitive;

use crate::error::Error;
use crate::transport::exchange::{Exchange, MessageMeta};
use crate::utils::storage::WriteBuf;

use super::status_report::{GeneralCode, StatusReport};

/* Interaction Model ID as per the Matter Spec */
pub const PROTO_ID_SECURE_CHANNEL: u16 = 0x00;

#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OpCode {
    MsgCounterSyncReq = 0x00,
    MsgCounterSyncResp = 0x01,
    MRPStandAloneAck = 0x10,
    PBKDFParamRequest = 0x20,
    PBKDFParamResponse = 0x21,
    PASEPake1 = 0x22,
    PASEPake2 = 0x23,
    PASEPake3 = 0x24,
    CASESigma1 = 0x30,
    CASESigma2 = 0x31,
    CASESigma3 = 0x32,
    CASESigma2Resume = 0x33,
    StatusReport = 0x40,
}

impl OpCode {
    pub fn meta(&self) -> MessageMeta {
        MessageMeta {
            proto_id: PROTO_ID_SECURE_CHANNEL,
            proto_opcode: *self as u8,
            reliable: !matches!(self, Self::MRPStandAloneAck),
        }
    }

    pub fn is_tlv(&self) -> bool {
        !matches!(
            self,
            Self::MRPStandAloneAck
                | Self::StatusReport
                | Self::MsgCounterSyncReq
                | Self::MsgCounterSyncResp
        )
    }
}

impl From<OpCode> for MessageMeta {
    fn from(op: OpCode) -> Self {
        op.meta()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SCStatusCodes {
    SessionEstablishmentSuccess = 0,
    NoSharedTrustRoots = 1,
    InvalidParameter = 2,
    CloseSession = 3,
    Busy = 4,
    SessionNotFound = 5,
}

impl SCStatusCodes {
    pub fn reliable(&self) -> bool {
        // CloseSession and Busy are sent without the R flag raised
        !matches!(self, SCStatusCodes::CloseSession | SCStatusCodes::Busy)
    }

    pub fn as_report<'a>(&self, payload: &'a [u8]) -> StatusReport<'a> {
        let general_code = match self {
            SCStatusCodes::SessionEstablishmentSuccess => GeneralCode::Success,
            SCStatusCodes::CloseSession => GeneralCode::Success,
            SCStatusCodes::Busy => GeneralCode::Busy,
            SCStatusCodes::InvalidParameter
            | SCStatusCodes::NoSharedTrustRoots
            | SCStatusCodes::SessionNotFound => GeneralCode::Failure,
        };

        StatusReport {
            general_code,
            proto_id: PROTO_ID_SECURE_CHANNEL as u32,
            proto_code: *self as u16,
            proto_data: payload,
        }
    }
}

pub async fn complete_with_status(
    exchange: &mut Exchange<'_>,
    status_code: SCStatusCodes,
    payload: &[u8],
) -> Result<(), Error> {
    exchange
        .send_with(|_, wb| sc_write(wb, status_code, payload))
        .await
}

pub fn sc_write(
    wb: &mut WriteBuf,
    status_code: SCStatusCodes,
    payload: &[u8],
) -> Result<Option<MessageMeta>, Error> {
    status_code.as_report(payload).write(wb)?;

    Ok(Some(
        OpCode::StatusReport.meta().reliable(status_code.reliable()),
    ))
}
