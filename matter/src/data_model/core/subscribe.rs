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
    interaction_model::{
        core::OpCode,
        messages::msg::{self, SubscribeReq, SubscribeResp},
    },
    tlv::{TLVWriter, TagType, ToTLV},
    transport::proto_demux::ResponseRequired,
};

use log::error;

use super::{DataModel, Transaction};

static SUBS_ID: AtomicU32 = AtomicU32::new(1);

impl DataModel {
    pub fn handle_subscribe_req(
        &self,
        req: &SubscribeReq,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
    ) -> Result<(OpCode, ResponseRequired), Error> {
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
        self.handle_read_attr_array(&read_req, trans, tw)?;
        tw.end_container()?;

        if !trans.exch.is_data_none() {
            error!("Exchange data already set!");
            return Err(Error::InvalidState);
        }
        trans.exch.set_data_boxed(ctx);

        Ok((OpCode::ReportData, ResponseRequired::Yes))
    }

    pub fn handle_subscription_confirm(
        &self,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
        request_handled: &mut bool,
    ) -> Result<(OpCode, ResponseRequired), Error> {
        *request_handled = false;
        if let Some(ctx) = trans.exch.get_data_boxed::<SubsCtx>() {
            if ctx.state != SubsState::Confirming {
                // Not relevant for us
                return Err(Error::Invalid);
            }
            *request_handled = true;
            ctx.state = SubsState::Confirmed;

            // TODO
            let resp = SubscribeResp::new(ctx.id, 40);
            resp.to_tlv(tw, TagType::Anonymous)?;
            trans.complete();
            Ok((OpCode::SubscriptResponse, ResponseRequired::Yes))
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
