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
        messages::{
            msg::{self, SubscribeReq, SubscribeResp},
            GenericPath,
        },
    },
    tlv::{self, get_root_node_struct, FromTLV, TLVWriter, TagType, ToTLV},
    transport::proto_demux::ResponseRequired,
};

use super::{read::ResumeReadReq, DataModel, Transaction};

static SUBS_ID: AtomicU32 = AtomicU32::new(1);

#[derive(PartialEq)]
enum SubsState {
    Confirming,
    Confirmed,
}

pub struct SubsCtx {
    state: SubsState,
    id: u32,
    resume_read_req: Option<ResumeReadReq>,
}

impl SubsCtx {
    pub fn new(
        rx_buf: &[u8],
        trans: &mut Transaction,
        tw: &mut TLVWriter,
        dm: &DataModel,
    ) -> Result<Self, Error> {
        let root = get_root_node_struct(rx_buf)?;
        let req = SubscribeReq::from_tlv(&root)?;

        let mut ctx = SubsCtx {
            state: SubsState::Confirming,
            // TODO
            id: SUBS_ID.fetch_add(1, Ordering::SeqCst),
            resume_read_req: None,
        };

        let mut resume_from = None;
        ctx.do_read(&req, trans, tw, dm, &mut resume_from)?;
        if resume_from.is_some() {
            // This is a multi-hop read transaction, remember this read request
            ctx.resume_read_req = Some(ResumeReadReq::new(rx_buf, &resume_from)?);
        }
        Ok(ctx)
    }

    pub fn handle_status_report(
        &mut self,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
        dm: &DataModel,
    ) -> Result<(OpCode, ResponseRequired), Error> {
        if self.state != SubsState::Confirming {
            // Not relevant for us
            trans.complete();
            return Err(Error::Invalid);
        }

        // Is there a previous resume read pending
        if self.resume_read_req.is_some() {
            let mut resume_read_req = self.resume_read_req.take().unwrap();
            if let Some(packet) = resume_read_req.pending_req.as_mut() {
                let rx_buf = packet.get_parsebuf()?.as_borrow_slice();
                let root = tlv::get_root_node(rx_buf)?;
                let req = SubscribeReq::from_tlv(&root)?;

                self.do_read(&req, trans, tw, dm, &mut resume_read_req.resume_from)?;
                if resume_read_req.resume_from.is_some() {
                    // More chunks are pending, setup resume_read_req again
                    self.resume_read_req = Some(resume_read_req);
                }

                return Ok((OpCode::ReportData, ResponseRequired::Yes));
            }
        }

        // We are here implies that the read is now complete
        self.confirm_subscription(trans, tw)
    }

    fn confirm_subscription(
        &mut self,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
    ) -> Result<(OpCode, ResponseRequired), Error> {
        self.state = SubsState::Confirmed;

        // TODO
        let resp = SubscribeResp::new(self.id, 40);
        resp.to_tlv(tw, TagType::Anonymous)?;
        trans.complete();
        Ok((OpCode::SubscriptResponse, ResponseRequired::Yes))
    }

    fn do_read(
        &mut self,
        req: &SubscribeReq,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
        dm: &DataModel,
        resume_from: &mut Option<GenericPath>,
    ) -> Result<(), Error> {
        let read_req = req.to_read_req();
        tw.start_struct(TagType::Anonymous)?;
        tw.u32(
            TagType::Context(msg::ReportDataTag::SubscriptionId as u8),
            self.id,
        )?;
        dm.handle_read_attr_array(&read_req, trans, tw, resume_from)?;
        tw.end_container()?;

        Ok(())
    }
}
