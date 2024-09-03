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
    alloc,
    error::*,
    respond::ExchangeHandler,
    secure_channel::{common::*, pake::Pake},
    transport::exchange::Exchange,
};

use super::{
    case::{Case, CaseSession},
    spake2p::Spake2P,
};

/* Handle messages related to the Secure Channel
 */

pub struct SecureChannel(());

impl SecureChannel {
    #[inline(always)]
    pub const fn new() -> Self {
        Self(())
    }

    pub async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        if exchange.rx().is_err() {
            exchange.recv_fetch().await?;
        }

        let meta = exchange.rx()?.meta();
        if meta.proto_id != PROTO_ID_SECURE_CHANNEL {
            Err(ErrorCode::InvalidProto)?;
        }

        match meta.opcode()? {
            OpCode::PBKDFParamRequest => {
                let mut spake2p = alloc!(Spake2P::new()); // TODO LARGE BUFFER
                Pake::new().handle(exchange, &mut spake2p).await
            }
            OpCode::CASESigma1 => {
                let mut case_session = alloc!(CaseSession::new()); // TODO LARGE BUFFER
                Case::new().handle(exchange, &mut case_session).await
            }
            opcode => {
                error!("Invalid opcode: {:?}", opcode);
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

impl ExchangeHandler for SecureChannel {
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        SecureChannel::handle(self, exchange).await
    }
}
