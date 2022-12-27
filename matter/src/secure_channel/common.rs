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

use crate::{error::Error, transport::packet::Packet};

use super::status_report::{create_status_report, GeneralCode};

/* Interaction Model ID as per the Matter Spec */
pub const PROTO_ID_SECURE_CHANNEL: usize = 0x00;

#[derive(FromPrimitive, Debug)]
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

#[derive(PartialEq)]
pub enum SCStatusCodes {
    SessionEstablishmentSuccess = 0,
    NoSharedTrustRoots = 1,
    InvalidParameter = 2,
    CloseSession = 3,
    Busy = 4,
    SessionNotFound = 5,
}

pub fn create_sc_status_report(
    proto_tx: &mut Packet,
    status_code: SCStatusCodes,
    proto_data: Option<&[u8]>,
) -> Result<(), Error> {
    let general_code = match status_code {
        SCStatusCodes::SessionEstablishmentSuccess => GeneralCode::Success,
        SCStatusCodes::CloseSession => {
            proto_tx.unset_reliable();
            // No time to manage reliable delivery for close session
            // the session will be closed soon
            GeneralCode::Success
        }
        SCStatusCodes::Busy
        | SCStatusCodes::InvalidParameter
        | SCStatusCodes::NoSharedTrustRoots
        | SCStatusCodes::SessionNotFound => GeneralCode::Failure,
    };
    create_status_report(
        proto_tx,
        general_code,
        PROTO_ID_SECURE_CHANNEL as u32,
        status_code as u16,
        proto_data,
    )
}

pub fn create_mrp_standalone_ack(proto_tx: &mut Packet) {
    proto_tx.set_proto_id(PROTO_ID_SECURE_CHANNEL as u16);
    proto_tx.set_proto_opcode(OpCode::MRPStandAloneAck as u8);
    proto_tx.unset_reliable();
}
