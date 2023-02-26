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

use super::{DataModel, Transaction};

static SUBS_ID: AtomicU32 = AtomicU32::new(1);

impl DataModel {
    pub fn handle_subscribe_req(
        &self,
        req: &SubscribeReq,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
    ) -> Result<SubsCtx, Error> {
        let ctx = SubsCtx {
            state: SubsState::Confirming,
            // TODO
            id: SUBS_ID.fetch_add(1, Ordering::SeqCst),
        };

        let read_req = req.to_read_req();
        tw.start_struct(TagType::Anonymous)?;
        tw.u32(
            TagType::Context(msg::ReportDataTag::SubscriptionId as u8),
            ctx.id,
        )?;
        let mut resume_from = None;
        self.handle_read_attr_array(&read_req, trans, tw, &mut resume_from)?;
        tw.end_container()?;

        Ok(ctx)
    }

    pub fn handle_subscription_confirm(
        &self,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
        ctx: &mut SubsCtx,
    ) -> Result<(OpCode, ResponseRequired), Error> {
        if ctx.state != SubsState::Confirming {
            // Not relevant for us
            trans.complete();
            return Err(Error::Invalid);
        }
        ctx.state = SubsState::Confirmed;

        // TODO
        let resp = SubscribeResp::new(ctx.id, 40);
        resp.to_tlv(tw, TagType::Anonymous)?;
        trans.complete();
        Ok((OpCode::SubscriptResponse, ResponseRequired::Yes))
    }
}

#[derive(PartialEq, Clone, Copy)]
enum SubsState {
    Confirming,
    Confirmed,
}

#[derive(Clone, Copy)]
pub struct SubsCtx {
    state: SubsState,
    id: u32,
}
