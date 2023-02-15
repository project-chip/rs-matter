/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
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

use std::sync::atomic::{AtomicU32, Ordering};

use crate::{
    error::Error,
    interaction_model::core::OpCode,
    tlv::{get_root_node_struct, FromTLV, TLVWriter, TagType, ToTLV},
    transport::{packet::Packet, proto_demux::ResponseRequired},
};

use log::error;

use super::{
    messages::msg::{self, SubscribeReq, SubscribeResp},
    InteractionModel, Transaction,
};

static SUBS_ID: AtomicU32 = AtomicU32::new(1);

impl InteractionModel {
    pub fn handle_subscribe_req(
        &mut self,
        trans: &mut Transaction,
        rx_buf: &[u8],
        proto_tx: &mut Packet,
    ) -> Result<ResponseRequired, Error> {
        proto_tx.set_proto_opcode(OpCode::ReportData as u8);

        let mut tw = TLVWriter::new(proto_tx.get_writebuf()?);
        let root = get_root_node_struct(rx_buf)?;
        let req = SubscribeReq::from_tlv(&root)?;

        let ctx = Box::new(SubsCtx {
            state: SubsState::Confirming,
            // TODO
            id: SUBS_ID.fetch_add(1, Ordering::SeqCst),
        });

        let read_req = req.to_read_req();
        tw.start_struct(TagType::Anonymous)?;
        tw.u32(
            TagType::Context(msg::ReportDataTag::SubscriptionId as u8),
            ctx.id,
        )?;
        self.consumer.consume_read_attr(&read_req, trans, &mut tw)?;
        tw.bool(
            TagType::Context(msg::ReportDataTag::SupressResponse as u8),
            false,
        )?;
        tw.end_container()?;

        if !trans.exch.is_data_none() {
            error!("Exchange data already set!");
            return Err(Error::InvalidState);
        }
        trans.exch.set_data_boxed(ctx);

        Ok(ResponseRequired::Yes)
    }

    pub fn handle_subscription_confirm(
        &mut self,
        trans: &mut Transaction,
        proto_tx: &mut Packet,
        request_handled: &mut bool,
    ) -> Result<ResponseRequired, Error> {
        *request_handled = false;
        if let Some(ctx) = trans.exch.get_data_boxed::<SubsCtx>() {
            if ctx.state != SubsState::Confirming {
                // Not relevant for us
                return Err(Error::Invalid);
            }
            *request_handled = true;
            ctx.state = SubsState::Confirmed;
            proto_tx.set_proto_opcode(OpCode::SubscriptResponse as u8);

            // TODO
            let resp = SubscribeResp::new(ctx.id, 40);
            let mut tw = TLVWriter::new(proto_tx.get_writebuf()?);
            resp.to_tlv(&mut tw, TagType::Anonymous)?;
            trans.complete();
            Ok(ResponseRequired::Yes)
        } else {
            trans.complete();
            Err(Error::Invalid)
        }
    }
}

#[derive(PartialEq)]
enum SubsState {
    Confirming,
    Confirmed,
}

struct SubsCtx {
    state: SubsState,
    id: u32,
}
