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

use core::cell::RefCell;

use crate::{
    error::*,
    fabric::FabricMgr,
    mdns::MdnsMgr,
    secure_channel::common::*,
    tlv,
    transport::proto_ctx::ProtoCtx,
    utils::{epoch::UtcCalendar, rand::Rand},
};
use log::{error, info};
use num;

use super::{case::Case, pake::PaseMgr};

/* Handle messages related to the Secure Channel
 */

pub struct SecureChannel<'a> {
    case: Case<'a>,
    pase: &'a RefCell<PaseMgr>,
    mdns: &'a RefCell<MdnsMgr<'a>>,
}

impl<'a> SecureChannel<'a> {
    pub fn new(
        pase: &'a RefCell<PaseMgr>,
        fabric_mgr: &'a RefCell<FabricMgr>,
        mdns: &'a RefCell<MdnsMgr<'a>>,
        rand: Rand,
        utc_calendar: UtcCalendar,
    ) -> Self {
        SecureChannel {
            case: Case::new(fabric_mgr, rand, utc_calendar),
            pase,
            mdns,
        }
    }

    pub fn handle(&mut self, ctx: &mut ProtoCtx) -> Result<bool, Error> {
        let proto_opcode: OpCode =
            num::FromPrimitive::from_u8(ctx.rx.get_proto_opcode()).ok_or(Error::Invalid)?;
        ctx.tx.set_proto_id(PROTO_ID_SECURE_CHANNEL);
        info!("Received Opcode: {:?}", proto_opcode);
        info!("Received Data:");
        tlv::print_tlv_list(ctx.rx.as_slice());
        let reply = match proto_opcode {
            OpCode::MRPStandAloneAck => Ok(true),
            OpCode::PBKDFParamRequest => self.pase.borrow_mut().pbkdfparamreq_handler(ctx),
            OpCode::PASEPake1 => self.pase.borrow_mut().pasepake1_handler(ctx),
            OpCode::PASEPake3 => self
                .pase
                .borrow_mut()
                .pasepake3_handler(ctx, &mut self.mdns.borrow_mut()),
            OpCode::CASESigma1 => self.case.casesigma1_handler(ctx),
            OpCode::CASESigma3 => self.case.casesigma3_handler(ctx),
            _ => {
                error!("OpCode Not Handled: {:?}", proto_opcode);
                Err(Error::InvalidOpcode)
            }
        }?;

        if reply {
            info!("Sending response");
            tlv::print_tlv_list(ctx.tx.as_mut_slice());
        }

        Ok(reply)
    }
}
