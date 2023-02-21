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

use boxslab::BoxSlab;

use crate::error::*;

use super::exchange::ExchangeCtx;
use super::packet::PacketPool;

const MAX_PROTOCOLS: usize = 4;

#[derive(PartialEq, Debug)]
pub enum ResponseRequired {
    Yes,
    No,
}
pub struct ProtoDemux {
    proto_id_handlers: [Option<Box<dyn HandleProto>>; MAX_PROTOCOLS],
}

/// This is the context in which a receive packet is being processed
pub struct ProtoCtx<'a> {
    /// This is the exchange context, that includes the exchange and the session
    pub exch_ctx: ExchangeCtx<'a>,
    /// This is the received buffer for this transaction
    pub rx: BoxSlab<PacketPool>,
    /// This is the transmit buffer for this transaction
    pub tx: BoxSlab<PacketPool>,
}

impl<'a> ProtoCtx<'a> {
    pub fn new(
        exch_ctx: ExchangeCtx<'a>,
        rx: BoxSlab<PacketPool>,
        tx: BoxSlab<PacketPool>,
    ) -> Self {
        Self { exch_ctx, rx, tx }
    }
}

pub trait HandleProto {
    fn handle_proto_id(&mut self, proto_ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error>;

    fn get_proto_id(&self) -> usize;

    fn handle_session_event(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Default for ProtoDemux {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtoDemux {
    pub fn new() -> ProtoDemux {
        ProtoDemux {
            proto_id_handlers: [None, None, None, None],
        }
    }

    pub fn register(&mut self, proto_id_handle: Box<dyn HandleProto>) -> Result<(), Error> {
        let proto_id = proto_id_handle.get_proto_id();
        self.proto_id_handlers[proto_id] = Some(proto_id_handle);
        Ok(())
    }

    pub fn handle(&mut self, proto_ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        let proto_id = proto_ctx.rx.get_proto_id() as usize;
        if proto_id >= MAX_PROTOCOLS {
            return Err(Error::Invalid);
        }
        return self.proto_id_handlers[proto_id]
            .as_mut()
            .ok_or(Error::NoHandler)?
            .handle_proto_id(proto_ctx);
    }
}
