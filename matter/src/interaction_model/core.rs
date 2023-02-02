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

use core::time::Duration;

use crate::{
    data_model::core::DataHandler,
    error::*,
    tlv::{get_root_node_struct, print_tlv_list, FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
    transport::{exchange::ExchangeCtx, packet::Packet, proto_ctx::ProtoCtx, session::Session},
};
use colored::Colorize;
use log::{error, info};
use num;
use num_derive::FromPrimitive;

use super::messages::msg::{self, InvReq, ReadReq, StatusResp, TimedReq, WriteReq};

#[macro_export]
macro_rules! cmd_enter {
    ($e:expr) => {{
        use colored::Colorize;
        info! {"{} {}", "Handling Command".cyan(), $e.cyan()}
    }};
}

#[derive(FromPrimitive, Debug, Clone, Copy, PartialEq)]
pub enum IMStatusCode {
    Success = 0,
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
            Error::InvalidAction => IMStatusCode::InvalidAction,
            Error::InvalidCommand => IMStatusCode::InvalidCommand,
            Error::UnsupportedAccess => IMStatusCode::UnsupportedAccess,
            Error::Busy => IMStatusCode::Busy,
            Error::DataVersionMismatch => IMStatusCode::DataVersionMismatch,
            Error::ResourceExhausted => IMStatusCode::ResourceExhausted,
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

#[derive(PartialEq)]
pub enum TransactionState {
    Ongoing,
    Complete,
    Terminate,
}
pub struct Transaction<'a, 'b> {
    state: TransactionState,
    ctx: &'a mut ExchangeCtx<'b>,
}

impl<'a, 'b> Transaction<'a, 'b> {
    pub fn new(ctx: &'a mut ExchangeCtx<'b>) -> Self {
        Self {
            state: TransactionState::Ongoing,
            ctx,
        }
    }

    pub fn session(&self) -> &Session {
        self.ctx.sess.session()
    }

    pub fn session_mut(&mut self) -> &mut Session {
        self.ctx.sess.session_mut()
    }

    /// Terminates the transaction, no communication (even ACKs) happens hence forth
    pub fn terminate(&mut self) {
        self.state = TransactionState::Terminate
    }

    pub fn is_terminate(&self) -> bool {
        self.state == TransactionState::Terminate
    }
    /// Marks the transaction as completed from the application's perspective
    pub fn complete(&mut self) {
        self.state = TransactionState::Complete
    }

    pub fn is_complete(&self) -> bool {
        self.state == TransactionState::Complete
    }

    pub fn set_timeout(&mut self, timeout: u64) {
        let now = (self.ctx.epoch)();

        self.ctx
            .exch
            .set_data_time(now.checked_add(Duration::from_millis(timeout)));
    }

    pub fn get_timeout(&mut self) -> Option<Duration> {
        self.ctx.exch.get_data_time()
    }

    pub fn has_timed_out(&self) -> bool {
        if let Some(timeout) = self.ctx.exch.get_data_time() {
            if (self.ctx.epoch)() > timeout {
                return true;
            }
        }
        false
    }
}

/* Interaction Model ID as per the Matter Spec */
const PROTO_ID_INTERACTION_MODEL: usize = 0x01;

pub enum Interaction<'a> {
    Read(ReadReq<'a>),
    Write(WriteReq<'a>),
    Invoke(InvReq<'a>),
    Timed(TimedReq),
}

impl<'a> Interaction<'a> {
    pub fn new(rx: &'a Packet) -> Result<Self, Error> {
        let opcode: OpCode =
            num::FromPrimitive::from_u8(rx.get_proto_opcode()).ok_or(Error::Invalid)?;

        let rx_data = rx.as_slice();

        info!("{} {:?}", "Received command".cyan(), opcode);
        print_tlv_list(rx_data);

        match opcode {
            OpCode::ReadRequest => Ok(Self::Read(ReadReq::from_tlv(&get_root_node_struct(
                rx_data,
            )?)?)),
            OpCode::WriteRequest => Ok(Self::Write(WriteReq::from_tlv(&get_root_node_struct(
                rx_data,
            )?)?)),
            OpCode::InvokeRequest => Ok(Self::Invoke(InvReq::from_tlv(&get_root_node_struct(
                rx_data,
            )?)?)),
            OpCode::TimedRequest => Ok(Self::Timed(TimedReq::from_tlv(&get_root_node_struct(
                rx_data,
            )?)?)),
            // TODO
            // OpCode::SubscribeRequest => self.handle_subscribe_req(&mut trans, buf, &mut ctx.tx)?,
            // OpCode::StatusResponse => self.handle_status_resp(&mut trans, buf, &mut ctx.tx)?,
            _ => {
                error!("Opcode Not Handled: {:?}", opcode);
                Err(Error::InvalidOpcode)
            }
        }
    }

    pub fn initiate_tx(
        &self,
        tx: &mut Packet,
        transaction: &mut Transaction,
    ) -> Result<bool, Error> {
        let reply = match self {
            Self::Read(request) => {
                tx.set_proto_id(PROTO_ID_INTERACTION_MODEL as u16);
                tx.set_proto_opcode(OpCode::ReportData as u8);

                let mut tw = TLVWriter::new(tx.get_writebuf()?);

                tw.start_struct(TagType::Anonymous)?;

                if request.attr_requests.is_some() {
                    tw.start_array(TagType::Context(msg::ReportDataTag::AttributeReports as u8))?;
                }

                false
            }
            Interaction::Write(_) => {
                if transaction.has_timed_out() {
                    Self::create_status_response(tx, IMStatusCode::Timeout)?;

                    transaction.complete();
                    transaction.ctx.exch.close();

                    true
                } else {
                    tx.set_proto_id(PROTO_ID_INTERACTION_MODEL as u16);
                    tx.set_proto_opcode(OpCode::WriteResponse as u8);

                    let mut tw = TLVWriter::new(tx.get_writebuf()?);

                    tw.start_struct(TagType::Anonymous)?;
                    tw.start_array(TagType::Context(msg::WriteRespTag::WriteResponses as u8))?;

                    false
                }
            }
            Interaction::Invoke(request) => {
                if transaction.has_timed_out() {
                    Self::create_status_response(tx, IMStatusCode::Timeout)?;

                    transaction.complete();
                    transaction.ctx.exch.close();

                    true
                } else {
                    let timed_tx = transaction.get_timeout().map(|_| true);
                    let timed_request = request.timed_request.filter(|a| *a);

                    // Either both should be None, or both should be Some(true)
                    if timed_tx != timed_request {
                        Self::create_status_response(tx, IMStatusCode::TimedRequestMisMatch)?;

                        true
                    } else {
                        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL as u16);
                        tx.set_proto_opcode(OpCode::InvokeResponse as u8);

                        let mut tw = TLVWriter::new(tx.get_writebuf()?);

                        tw.start_struct(TagType::Anonymous)?;

                        // Suppress Response -> TODO: Need to revisit this for cases where we send a command back
                        tw.bool(
                            TagType::Context(msg::InvRespTag::SupressResponse as u8),
                            false,
                        )?;

                        if request.inv_requests.is_some() {
                            tw.start_array(TagType::Context(
                                msg::InvRespTag::InvokeResponses as u8,
                            ))?;
                        }

                        false
                    }
                }
            }
            Interaction::Timed(request) => {
                tx.set_proto_id(PROTO_ID_INTERACTION_MODEL as u16);
                tx.set_proto_opcode(OpCode::StatusResponse as u8);

                let mut tw = TLVWriter::new(tx.get_writebuf()?);

                transaction.set_timeout(request.timeout.into());

                let status = StatusResp {
                    status: IMStatusCode::Success,
                };

                status.to_tlv(&mut tw, TagType::Anonymous)?;

                true
            }
        };

        Ok(!reply)
    }

    pub fn complete_tx(
        &self,
        tx: &mut Packet,
        transaction: &mut Transaction,
    ) -> Result<bool, Error> {
        let reply = match self {
            Self::Read(request) => {
                let mut tw = TLVWriter::new(tx.get_writebuf()?);

                if request.attr_requests.is_some() {
                    tw.end_container()?;
                }

                // Suppress response always true for read interaction
                tw.bool(
                    TagType::Context(msg::ReportDataTag::SupressResponse as u8),
                    true,
                )?;

                tw.end_container()?;

                transaction.complete();

                true
            }
            Self::Write(request) => {
                let suppress = request.supress_response.unwrap_or_default();

                let mut tw = TLVWriter::new(tx.get_writebuf()?);

                tw.end_container()?;
                tw.end_container()?;

                transaction.complete();

                if suppress {
                    error!("Supress response is set, is this the expected handling?");
                    false
                } else {
                    true
                }
            }
            Self::Invoke(request) => {
                let mut tw = TLVWriter::new(tx.get_writebuf()?);

                if request.inv_requests.is_some() {
                    tw.end_container()?;
                }

                tw.end_container()?;

                true
            }
            Self::Timed(_) => false,
        };

        if reply {
            info!("Sending response");
            print_tlv_list(tx.as_slice());
        }

        if transaction.is_terminate() {
            transaction.ctx.exch.terminate();
        } else if transaction.is_complete() {
            transaction.ctx.exch.close();
        }

        Ok(true)
    }

    fn create_status_response(tx: &mut Packet, status: IMStatusCode) -> Result<(), Error> {
        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL as u16);
        tx.set_proto_opcode(OpCode::StatusResponse as u8);

        let mut tw = TLVWriter::new(tx.get_writebuf()?);

        let status = StatusResp { status };
        status.to_tlv(&mut tw, TagType::Anonymous)
    }
}

pub trait InteractionHandler {
    fn handle<'a>(&mut self, ctx: &'a mut ProtoCtx) -> Result<Option<&'a [u8]>, Error>;
}

impl<T> InteractionHandler for &mut T
where
    T: InteractionHandler,
{
    fn handle<'a>(&mut self, ctx: &'a mut ProtoCtx) -> Result<Option<&'a [u8]>, Error> {
        (**self).handle(ctx)
    }
}

pub struct InteractionModel<T>(pub T);

impl<T> InteractionModel<T>
where
    T: DataHandler,
{
    pub fn handle<'a>(&mut self, ctx: &'a mut ProtoCtx) -> Result<Option<&'a [u8]>, Error> {
        let interaction = Interaction::new(ctx.rx)?;
        let mut transaction = Transaction::new(&mut ctx.exch_ctx);

        let reply = if interaction.initiate_tx(ctx.tx, &mut transaction)? {
            self.0.handle(&interaction, ctx.tx, &mut transaction)?;
            interaction.complete_tx(ctx.tx, &mut transaction)?
        } else {
            true
        };

        Ok(reply.then_some(ctx.tx.as_slice()))
    }
}

#[cfg(feature = "nightly")]
impl<T> InteractionModel<T>
where
    T: crate::data_model::core::asynch::AsyncDataHandler,
{
    pub async fn handle_async<'a>(
        &mut self,
        ctx: &'a mut ProtoCtx<'_, '_>,
    ) -> Result<Option<&'a [u8]>, Error> {
        let interaction = Interaction::new(ctx.rx)?;
        let mut transaction = Transaction::new(&mut ctx.exch_ctx);

        let reply = if interaction.initiate_tx(ctx.tx, &mut transaction)? {
            self.0
                .handle(&interaction, ctx.tx, &mut transaction)
                .await?;
            interaction.complete_tx(ctx.tx, &mut transaction)?
        } else {
            true
        };

        Ok(reply.then_some(ctx.tx.as_slice()))
    }
}

impl<T> InteractionHandler for InteractionModel<T>
where
    T: DataHandler,
{
    fn handle<'a>(&mut self, ctx: &'a mut ProtoCtx) -> Result<Option<&'a [u8]>, Error> {
        InteractionModel::handle(self, ctx)
    }
}

#[cfg(feature = "nightly")]
pub mod asynch {
    use crate::{
        data_model::core::asynch::AsyncDataHandler, error::Error, transport::proto_ctx::ProtoCtx,
    };

    use super::InteractionModel;

    pub trait AsyncInteractionHandler {
        async fn handle<'a>(
            &mut self,
            ctx: &'a mut ProtoCtx<'_, '_>,
        ) -> Result<Option<&'a [u8]>, Error>;
    }

    impl<T> AsyncInteractionHandler for &mut T
    where
        T: AsyncInteractionHandler,
    {
        async fn handle<'a>(
            &mut self,
            ctx: &'a mut ProtoCtx<'_, '_>,
        ) -> Result<Option<&'a [u8]>, Error> {
            (**self).handle(ctx).await
        }
    }

    impl<T> AsyncInteractionHandler for InteractionModel<T>
    where
        T: AsyncDataHandler,
    {
        async fn handle<'a>(
            &mut self,
            ctx: &'a mut ProtoCtx<'_, '_>,
        ) -> Result<Option<&'a [u8]>, Error> {
            InteractionModel::handle_async(self, ctx).await
        }
    }
}
