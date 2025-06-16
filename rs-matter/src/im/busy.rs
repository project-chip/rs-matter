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

use crate::error::*;
use crate::respond::ExchangeHandler;
use crate::transport::exchange::Exchange;

use super::{IMStatusCode, OpCode, StatusResp, PROTO_ID_INTERACTION_MODEL};

/// A Interaction Model implementation that is only capable of sending Busy status codes
///
/// Use with e.g.
///
/// ```ignore
/// let matter = Matter::new(...);
///
/// // ...
///
/// let busy_responder = Responder::new("IM Busy Responder", BusyInteractionModel::new(), &matter, 200/*ms*/);
/// busy_responder.run::<10>().await?;
/// ```
///
/// ... to respond with "I'm busy, please try later" or similar status codes to all incoming IM messages, which were
/// not accepted in time by the actual Interaction Model responder, due to all its handlers being occupied with work.
pub struct BusyInteractionModel(());

impl Default for BusyInteractionModel {
    fn default() -> Self {
        Self::new()
    }
}

impl BusyInteractionModel {
    #[inline(always)]
    pub const fn new() -> Self {
        Self(())
    }

    pub async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let meta = exchange.recv().await?.meta();
        if meta.proto_id != PROTO_ID_INTERACTION_MODEL {
            Err(ErrorCode::InvalidProto)?;
        }

        let status = match meta.opcode()? {
            OpCode::ReadRequest
            | OpCode::WriteRequest
            | OpCode::SubscribeRequest
            | OpCode::InvokeRequest => IMStatusCode::Busy,
            _ => IMStatusCode::Failure,
        };

        exchange
            .send_with(|_, wb| {
                StatusResp::write(wb, status)?;

                Ok(Some(OpCode::StatusResponse.meta()))
            })
            .await
    }
}

impl ExchangeHandler for BusyInteractionModel {
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        BusyInteractionModel::handle(self, exchange).await
    }
}
