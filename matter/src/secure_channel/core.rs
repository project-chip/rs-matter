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

use core::borrow::Borrow;
use core::cell::RefCell;

use log::error;

use crate::{
    error::*,
    fabric::FabricMgr,
    mdns::Mdns,
    secure_channel::{common::*, pake::Pake},
    transport::{exchange::Exchange, packet::Packet},
    utils::{epoch::Epoch, rand::Rand},
};

use super::{case::Case, pake::PaseMgr};

/* Handle messages related to the Secure Channel
 */

pub struct SecureChannel<'a> {
    pase: &'a RefCell<PaseMgr>,
    fabric: &'a RefCell<FabricMgr>,
    mdns: &'a dyn Mdns,
    rand: Rand,
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
            fabric,
            pase,
            mdns,
            rand,
        }
    }

    pub async fn handle(
        &self,
        exchange: &mut Exchange<'_>,
        rx: &mut Packet<'_>,
        tx: &mut Packet<'_>,
    ) -> Result<(), Error> {
        match rx.get_proto_opcode()? {
            OpCode::PBKDFParamRequest => {
                Pake::new(self.pase)
                    .handle(exchange, rx, tx, self.mdns)
                    .await
            }
            OpCode::CASESigma1 => {
                Case::new(self.fabric, self.rand)
                    .handle(exchange, rx, tx)
                    .await
            }
            proto_opcode => {
                error!("OpCode not handled: {:?}", proto_opcode);
                Err(ErrorCode::InvalidOpcode.into())
            }
        }
    }
}
