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

use std::sync::Arc;

use crate::{
    error::*,
    fabric::FabricMgr,
    secure_channel::common::*,
    tlv,
    transport::proto_demux::{self, ProtoCtx, ResponseRequired},
};
use log::{error, info};
use num;

use super::{case::Case, pake::PaseMgr};

/* Handle messages related to the Secure Channel
 */

pub struct SecureChannel {
    case: Case,
    pase: PaseMgr,
}

impl SecureChannel {
    pub fn new(pase: PaseMgr, fabric_mgr: Arc<FabricMgr>) -> SecureChannel {
        SecureChannel {
            pase,
            case: Case::new(fabric_mgr),
        }
    }
}

impl proto_demux::HandleProto for SecureChannel {
    fn handle_proto_id(&mut self, ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        let proto_opcode: OpCode =
            num::FromPrimitive::from_u8(ctx.rx.get_proto_opcode()).ok_or(Error::Invalid)?;
        ctx.tx.set_proto_id(PROTO_ID_SECURE_CHANNEL as u16);
        info!("Received Opcode: {:?}", proto_opcode);
        info!("Received Data:");
        tlv::print_tlv_list(ctx.rx.as_borrow_slice());
        let result = match proto_opcode {
            OpCode::MRPStandAloneAck => Ok(ResponseRequired::No),
            OpCode::PBKDFParamRequest => self.pase.pbkdfparamreq_handler(ctx),
            OpCode::PASEPake1 => self.pase.pasepake1_handler(ctx),
            OpCode::PASEPake3 => self.pase.pasepake3_handler(ctx),
            OpCode::CASESigma1 => self.case.casesigma1_handler(ctx),
            OpCode::CASESigma3 => self.case.casesigma3_handler(ctx),
            _ => {
                error!("OpCode Not Handled: {:?}", proto_opcode);
                Err(Error::InvalidOpcode)
            }
        };
        if result == Ok(ResponseRequired::Yes) {
            info!("Sending response");
            tlv::print_tlv_list(ctx.tx.as_borrow_slice());
        }
        result
    }

    fn get_proto_id(&self) -> usize {
        PROTO_ID_SECURE_CHANNEL
    }
}
