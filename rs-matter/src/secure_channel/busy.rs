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

use crate::error::*;
use crate::respond::ExchangeHandler;
use crate::transport::exchange::Exchange;

use super::common::{sc_write, OpCode, SCStatusCodes, PROTO_ID_SECURE_CHANNEL};

/// A Secure Channel implementation that is only capable of sending Busy status codes
///
/// Use with e.g.
///
/// ```ignore
/// let matter = Matter::new(...);
///
/// // ...
///
/// let busy_responder = Responder::new("SC Busy Responder", BusySecureChannel::new(), &matter, 200/*ms*/);
/// busy_responder.run::<10>().await?;
/// ```
///
/// ... to respond with "I'm busy, please try later" status code to all incoming Secure Channel messages, which were
/// not accepted in time by the actual Secure Channel responder, due to all its handlers being occupied with work.
pub struct BusySecureChannel(());

impl BusySecureChannel {
    const BUSY_RETRY_DELAY_MS: u16 = 500;

    #[inline(always)]
    pub const fn new() -> Self {
        Self(())
    }

    pub async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let meta = exchange.recv().await?.meta();
        if meta.proto_id != PROTO_ID_SECURE_CHANNEL {
            Err(ErrorCode::InvalidProto)?;
        }

        match meta.opcode()? {
            OpCode::PBKDFParamRequest | OpCode::CASESigma1 => {
                exchange
                    .send_with(|_, wb| {
                        sc_write(
                            wb,
                            SCStatusCodes::Busy,
                            &u16::to_le_bytes(Self::BUSY_RETRY_DELAY_MS),
                        )
                    })
                    .await
            }
            proto_opcode => {
                error!("OpCode not handled: {:?}", proto_opcode);
                Err(ErrorCode::InvalidOpcode.into())
            }
        }
    }
}

impl ExchangeHandler for BusySecureChannel {
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        BusySecureChannel::handle(self, exchange).await
    }
}
