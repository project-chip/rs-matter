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

use log::error;

use crate::{
    error::*,
    secure_channel::{common::*, pake::Pake},
    transport::{exchange::Exchange, packet::Packet},
};

use super::case::Case;

/* Handle messages related to the Secure Channel
 */

pub struct SecureChannel(());

impl SecureChannel {
    #[inline(always)]
    pub const fn new() -> Self {
        Self(())
    }

    pub async fn handle(
        &self,
        exchange: &mut Exchange<'_>,
        rx: &mut Packet<'_>,
        tx: &mut Packet<'_>,
    ) -> Result<(), Error> {
        match rx.get_proto_opcode()? {
            OpCode::PBKDFParamRequest => Pake::new().handle(exchange, rx, tx).await,
            OpCode::CASESigma1 => Case::new().handle(exchange, rx, tx).await,
            proto_opcode => {
                error!("OpCode not handled: {:?}", proto_opcode);
                Err(ErrorCode::InvalidOpcode.into())
            }
        }
    }
}

impl Default for SecureChannel {
    fn default() -> Self {
        Self::new()
    }
}
