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

use std::time::{Duration, SystemTime};

use crate::{
    error::*,
    interaction_model::messages::msg::StatusResp,
    tlv::{self, get_root_node_struct, FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
    transport::{
        exchange::Exchange,
        packet::Packet,
        proto_demux::{self, ProtoCtx, ResponseRequired},
        session::Session,
    },
};
use colored::Colorize;
use log::{error, info};
use num;
use num_derive::FromPrimitive;

use super::InteractionModel;
use super::Transaction;
use super::TransactionState;
use super::{messages::msg::TimedReq, InteractionConsumer};

/* Handle messages related to the Interation Model
 */

/* Interaction Model ID as per the Matter Spec */
const PROTO_ID_INTERACTION_MODEL: usize = 0x01;

#[derive(FromPrimitive, Debug, Copy, Clone, PartialEq)]
pub enum OpCode {
    Reserved = 0,
    StatusResponse = 1,
    ReadRequest = 2,
    SubscribeRequest = 3,
    SubscriptResponse = 4,
    ReportData = 5,
    WriteRequest = 6,
    WriteResponse = 7,
    InvokeRequest = 8,
    InvokeResponse = 9,
    TimedRequest = 10,
}

impl<'a> Transaction<'a> {
    pub fn new(session: &'a mut Session, exch: &'a mut Exchange) -> Self {
        Self {
            state: TransactionState::Ongoing,
            session,
            exch,
        }
    }

    pub fn complete(&mut self) {
        self.state = TransactionState::Complete
    }

    pub fn is_complete(&self) -> bool {
        self.state == TransactionState::Complete
    }

    pub fn set_timeout(&mut self, timeout: u64) {
        self.exch
            .set_data_time(SystemTime::now().checked_add(Duration::from_millis(timeout)));
    }

    pub fn get_timeout(&mut self) -> Option<SystemTime> {
        self.exch.get_data_time()
    }

    pub fn has_timed_out(&self) -> bool {
        if let Some(timeout) = self.exch.get_data_time() {
            if SystemTime::now() > timeout {
                return true;
            }
        }
        false
    }
}

impl InteractionModel {
    pub fn new(consumer: Box<dyn InteractionConsumer>) -> InteractionModel {
        InteractionModel { consumer }
    }

    pub fn handle_timed_req(
        &mut self,
        trans: &mut Transaction,
        rx_buf: &[u8],
        proto_tx: &mut Packet,
    ) -> Result<ResponseRequired, Error> {
        proto_tx.set_proto_opcode(OpCode::StatusResponse as u8);

        let root = get_root_node_struct(rx_buf)?;
        let req = TimedReq::from_tlv(&root)?;
        trans.set_timeout(req.timeout.into());

        let status = StatusResp {
            status: IMStatusCode::Sucess,
        };
        let mut tw = TLVWriter::new(proto_tx.get_writebuf()?);
        let _ = status.to_tlv(&mut tw, TagType::Anonymous);
        Ok(ResponseRequired::Yes)
    }

    /// Handle Request Timeouts
    /// This API checks if a request was a timed request, and if so, and if the timeout has
    /// expired, it will generate the appropriate response as expected
    pub(super) fn req_timeout_handled(
        trans: &mut Transaction,
        proto_tx: &mut Packet,
    ) -> Result<bool, Error> {
        if trans.has_timed_out() {
            trans.complete();
            InteractionModel::create_status_response(proto_tx, IMStatusCode::Timeout)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(super) fn create_status_response(
        proto_tx: &mut Packet,
        status: IMStatusCode,
    ) -> Result<(), Error> {
        proto_tx.set_proto_opcode(OpCode::StatusResponse as u8);
        let mut tw = TLVWriter::new(proto_tx.get_writebuf()?);
        let status = StatusResp { status };
        status.to_tlv(&mut tw, TagType::Anonymous)
    }
}

impl proto_demux::HandleProto for InteractionModel {
    fn handle_proto_id(&mut self, ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        let mut trans = Transaction::new(&mut ctx.exch_ctx.sess, ctx.exch_ctx.exch);
        let proto_opcode: OpCode =
            num::FromPrimitive::from_u8(ctx.rx.get_proto_opcode()).ok_or(Error::Invalid)?;
        ctx.tx.set_proto_id(PROTO_ID_INTERACTION_MODEL as u16);

        let buf = ctx.rx.as_borrow_slice();
        info!("{} {:?}", "Received command".cyan(), proto_opcode);
        tlv::print_tlv_list(buf);
        let result = match proto_opcode {
            OpCode::InvokeRequest => self.handle_invoke_req(&mut trans, buf, &mut ctx.tx)?,
            OpCode::ReadRequest => self.handle_read_req(&mut trans, buf, &mut ctx.tx)?,
            OpCode::WriteRequest => self.handle_write_req(&mut trans, buf, &mut ctx.tx)?,
            OpCode::TimedRequest => self.handle_timed_req(&mut trans, buf, &mut ctx.tx)?,
            _ => {
                error!("Opcode Not Handled: {:?}", proto_opcode);
                return Err(Error::InvalidOpcode);
            }
        };

        if result == ResponseRequired::Yes {
            info!("Sending response");
            tlv::print_tlv_list(ctx.tx.as_borrow_slice());
        }
        if trans.is_complete() {
            ctx.exch_ctx.exch.close();
        }
        Ok(result)
    }

    fn get_proto_id(&self) -> usize {
        PROTO_ID_INTERACTION_MODEL as usize
    }
}

#[derive(FromPrimitive, Debug, Clone, Copy, PartialEq)]
pub enum IMStatusCode {
    Sucess = 0,
    Failure = 1,
    InvalidSubscription = 0x7D,
    UnsupportedAccess = 0x7E,
    UnsupportedEndpoint = 0x7F,
    InvalidAction = 0x80,
    UnsupportedCommand = 0x81,
    InvalidCommand = 0x85,
    UnsupportedAttribute = 0x86,
    ConstraintError = 0x87,
    UnsupportedWrite = 0x88,
    ResourceExhausted = 0x89,
    NotFound = 0x8b,
    UnreportableAttribute = 0x8c,
    InvalidDataType = 0x8d,
    UnsupportedRead = 0x8f,
    DataVersionMismatch = 0x92,
    Timeout = 0x94,
    Busy = 0x9c,
    UnsupportedCluster = 0xc3,
    NoUpstreamSubscription = 0xc5,
    NeedsTimedInteraction = 0xc6,
    UnsupportedEvent = 0xc7,
    PathsExhausted = 0xc8,
    TimedRequestMisMatch = 0xc9,
    FailSafeRequired = 0xca,
}

impl From<Error> for IMStatusCode {
    fn from(e: Error) -> Self {
        match e {
            Error::EndpointNotFound => IMStatusCode::UnsupportedEndpoint,
            Error::ClusterNotFound => IMStatusCode::UnsupportedCluster,
            Error::AttributeNotFound => IMStatusCode::UnsupportedAttribute,
            Error::CommandNotFound => IMStatusCode::UnsupportedCommand,
            _ => IMStatusCode::Failure,
        }
    }
}

impl FromTLV<'_> for IMStatusCode {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error> {
        num::FromPrimitive::from_u16(t.u16()?).ok_or(Error::Invalid)
    }
}

impl ToTLV for IMStatusCode {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        tw.u16(tag_type, *self as u16)
    }
}
