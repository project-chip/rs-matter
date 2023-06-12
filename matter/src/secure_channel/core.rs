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

use core::{borrow::Borrow, cell::RefCell};

use crate::{
    error::*,
    fabric::FabricMgr,
    mdns::Mdns,
    secure_channel::common::*,
    tlv,
    transport::{proto_ctx::ProtoCtx, session::CloneData},
    utils::{epoch::Epoch, rand::Rand},
};
use log::{error, info};

use super::{case::Case, pake::PaseMgr};

/* Handle messages related to the Secure Channel
 */

pub struct SecureChannel<'a> {
    case: Case<'a>,
    pase: &'a RefCell<PaseMgr>,
    mdns: &'a dyn Mdns,
}

impl<'a> SecureChannel<'a> {
    #[inline(always)]
    pub fn new<
        T: Borrow<RefCell<FabricMgr>>
            + Borrow<RefCell<PaseMgr>>
            + Borrow<dyn Mdns + 'a>
            + Borrow<Epoch>
            + Borrow<Rand>,
    >(
        matter: &'a T,
    ) -> Self {
        Self::wrap(
            matter.borrow(),
            matter.borrow(),
            matter.borrow(),
            *matter.borrow(),
        )
    }

    #[inline(always)]
    pub fn wrap(
        pase: &'a RefCell<PaseMgr>,
        fabric: &'a RefCell<FabricMgr>,
        mdns: &'a dyn Mdns,
        rand: Rand,
    ) -> Self {
        Self {
            case: Case::new(fabric, rand),
            pase,
            mdns,
        }
    }

    pub fn handle(&mut self, ctx: &mut ProtoCtx) -> Result<(bool, Option<CloneData>), Error> {
        let proto_opcode: OpCode = ctx.rx.get_proto_opcode()?;

        ctx.tx.set_proto_id(PROTO_ID_SECURE_CHANNEL);
        info!("Received Opcode: {:?}", proto_opcode);
        info!("Received Data:");
        tlv::print_tlv_list(ctx.rx.as_slice());
        let (reply, clone_data) = match proto_opcode {
            OpCode::MRPStandAloneAck => Ok((false, None)),
            OpCode::PBKDFParamRequest => self
                .pase
                .borrow_mut()
                .pbkdfparamreq_handler(ctx)
                .map(|reply| (reply, None)),
            OpCode::PASEPake1 => self
                .pase
                .borrow_mut()
                .pasepake1_handler(ctx)
                .map(|reply| (reply, None)),
            OpCode::PASEPake3 => self.pase.borrow_mut().pasepake3_handler(ctx, self.mdns),
            OpCode::CASESigma1 => self.case.casesigma1_handler(ctx).map(|reply| (reply, None)),
            OpCode::CASESigma3 => self.case.casesigma3_handler(ctx),
            _ => {
                error!("OpCode Not Handled: {:?}", proto_opcode);
                Err(ErrorCode::InvalidOpcode.into())
            }
        }?;

        if reply {
            info!("Sending response");
            tlv::print_tlv_list(ctx.tx.as_mut_slice());
        }

        Ok((reply, clone_data))
    }
}
