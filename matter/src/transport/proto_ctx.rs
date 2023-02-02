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

use crate::error::Error;

use super::exchange::ExchangeCtx;
use super::packet::Packet;

/// This is the context in which a receive packet is being processed
pub struct ProtoCtx<'a, 'b> {
    /// This is the exchange context, that includes the exchange and the session
    pub exch_ctx: ExchangeCtx<'a>,
    /// This is the received buffer for this transaction
    pub rx: &'a Packet<'b>,
    /// This is the transmit buffer for this transaction
    pub tx: &'a mut Packet<'b>,
}

impl<'a, 'b> ProtoCtx<'a, 'b> {
    pub fn new(exch_ctx: ExchangeCtx<'a>, rx: &'a Packet<'b>, tx: &'a mut Packet<'b>) -> Self {
        Self { exch_ctx, rx, tx }
    }

    pub fn send(&mut self) -> Result<&[u8], Error> {
        self.exch_ctx.exch.send(self.tx, &mut self.exch_ctx.sess)?;

        Ok(self.tx.as_mut_slice())
    }
}
