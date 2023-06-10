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

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

use crate::{
    data_model::core::DataHandler,
    error::*,
    tlv::{get_root_node_struct, print_tlv_list, FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
    transport::{
        exchange::{Exchange, ExchangeCtx},
        packet::Packet,
        proto_ctx::ProtoCtx,
        session::Session,
    },
};
use log::{error, info};
use num;
use num_derive::FromPrimitive;
use owo_colors::OwoColorize;

use super::messages::{
    ib::{AttrPath, DataVersionFilter},
    msg::{self, InvReq, ReadReq, StatusResp, SubscribeReq, SubscribeResp, TimedReq, WriteReq},
    GenericPath,
};

#[macro_export]
macro_rules! cmd_enter {
    ($e:expr) => {{
        use owo_colors::OwoColorize;
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

impl From<ErrorCode> for IMStatusCode {
    fn from(e: ErrorCode) -> Self {
        match e {
            ErrorCode::EndpointNotFound => IMStatusCode::UnsupportedEndpoint,
            ErrorCode::ClusterNotFound => IMStatusCode::UnsupportedCluster,
            ErrorCode::AttributeNotFound => IMStatusCode::UnsupportedAttribute,
            ErrorCode::CommandNotFound => IMStatusCode::UnsupportedCommand,
            ErrorCode::InvalidAction => IMStatusCode::InvalidAction,
            ErrorCode::InvalidCommand => IMStatusCode::InvalidCommand,
            ErrorCode::UnsupportedAccess => IMStatusCode::UnsupportedAccess,
            ErrorCode::Busy => IMStatusCode::Busy,
            ErrorCode::DataVersionMismatch => IMStatusCode::DataVersionMismatch,
            ErrorCode::ResourceExhausted => IMStatusCode::ResourceExhausted,
            _ => IMStatusCode::Failure,
        }
    }
}

impl From<Error> for IMStatusCode {
    fn from(value: Error) -> Self {
        Self::from(value.code())
    }
}

impl FromTLV<'_> for IMStatusCode {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error> {
        num::FromPrimitive::from_u16(t.u16()?).ok_or_else(|| ErrorCode::Invalid.into())
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
    SubscribeResponse = 4,
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

    pub fn exch(&self) -> &Exchange {
        self.ctx.exch
    }

    pub fn exch_mut(&mut self) -> &mut Exchange {
        self.ctx.exch
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
pub const PROTO_ID_INTERACTION_MODEL: u16 = 0x01;

const MAX_RESUME_PATHS: usize = 32;
const MAX_RESUME_DATAVER_FILTERS: usize = 32;

// This is the amount of space we reserve for other things to be attached towards
// the end of long reads.
const LONG_READS_TLV_RESERVE_SIZE: usize = 24;

// TODO: For now...
static SUBS_ID: AtomicU32 = AtomicU32::new(1);

pub enum Interaction<'a> {
    Read(ReadReq<'a>),
    Write(WriteReq<'a>),
    Invoke(InvReq<'a>),
    Subscribe(SubscribeReq<'a>),
    Timed(TimedReq),
    ResumeRead(ResumeReadReq),
    ResumeSubscribe(ResumeSubscribeReq),
}

impl<'a> Interaction<'a> {
    fn new(rx: &'a Packet, transaction: &mut Transaction) -> Result<Option<Self>, Error> {
        let opcode: OpCode = rx.get_proto_opcode()?;

        let rx_data = rx.as_slice();

        info!("{} {:?}", "Received command".cyan(), opcode);
        print_tlv_list(rx_data);

        match opcode {
            OpCode::ReadRequest => Ok(Some(Self::Read(ReadReq::from_tlv(&get_root_node_struct(
                rx_data,
            )?)?))),
            OpCode::WriteRequest => Ok(Some(Self::Write(WriteReq::from_tlv(
                &get_root_node_struct(rx_data)?,
            )?))),
            OpCode::InvokeRequest => Ok(Some(Self::Invoke(InvReq::from_tlv(
                &get_root_node_struct(rx_data)?,
            )?))),
            OpCode::SubscribeRequest => Ok(Some(Self::Subscribe(SubscribeReq::from_tlv(
                &get_root_node_struct(rx_data)?,
            )?))),
            OpCode::StatusResponse => {
                let resp = StatusResp::from_tlv(&get_root_node_struct(rx_data)?)?;

                if resp.status == IMStatusCode::Success {
                    if let Some(req) = transaction.exch_mut().take_suspended_read_req() {
                        Ok(Some(Self::ResumeRead(req)))
                    } else if let Some(req) = transaction.exch_mut().take_suspended_subscribe_req()
                    {
                        Ok(Some(Self::ResumeSubscribe(req)))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            }
            OpCode::TimedRequest => Ok(Some(Self::Timed(TimedReq::from_tlv(
                &get_root_node_struct(rx_data)?,
            )?))),
            _ => {
                error!("Opcode not handled: {:?}", opcode);
                Err(ErrorCode::InvalidOpcode.into())
            }
        }
    }

    pub fn initiate(
        rx: &'a Packet,
        tx: &mut Packet,
        transaction: &mut Transaction,
    ) -> Result<Option<Self>, Error> {
        if let Some(interaction) = Self::new(rx, transaction)? {
            tx.reset();

            let initiated = match &interaction {
                Interaction::Read(req) => req.initiate(tx, transaction)?,
                Interaction::Write(req) => req.initiate(tx, transaction)?,
                Interaction::Invoke(req) => req.initiate(tx, transaction)?,
                Interaction::Subscribe(req) => req.initiate(tx, transaction)?,
                Interaction::Timed(req) => {
                    req.process(tx, transaction)?;
                    false
                }
                Interaction::ResumeRead(req) => req.initiate(tx, transaction)?,
                Interaction::ResumeSubscribe(req) => req.initiate(tx, transaction)?,
            };

            Ok(initiated.then_some(interaction))
        } else {
            Ok(None)
        }
    }

    fn create_status_response(tx: &mut Packet, status: IMStatusCode) -> Result<(), Error> {
        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
        tx.set_proto_opcode(OpCode::StatusResponse as u8);

        let mut tw = TLVWriter::new(tx.get_writebuf()?);

        let status = StatusResp { status };
        status.to_tlv(&mut tw, TagType::Anonymous)
    }
}

impl<'a> ReadReq<'a> {
    fn suspend(self, resume_path: GenericPath) -> ResumeReadReq {
        ResumeReadReq {
            paths: self
                .attr_requests
                .iter()
                .flat_map(|attr_requests| attr_requests.iter())
                .collect(),
            filters: self
                .dataver_filters
                .iter()
                .flat_map(|filters| filters.iter())
                .collect(),
            fabric_filtered: self.fabric_filtered,
            resume_path,
        }
    }

    fn initiate(&self, tx: &mut Packet, _transaction: &mut Transaction) -> Result<bool, Error> {
        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
        tx.set_proto_opcode(OpCode::ReportData as u8);

        let mut tw = Self::reserve_long_read_space(tx)?;

        tw.start_struct(TagType::Anonymous)?;

        if self.attr_requests.is_some() {
            tw.start_array(TagType::Context(msg::ReportDataTag::AttributeReports as u8))?;
        }

        Ok(true)
    }

    pub fn complete(
        self,
        tx: &mut Packet,
        transaction: &mut Transaction,
        resume_path: Option<GenericPath>,
    ) -> Result<bool, Error> {
        let mut tw = Self::restore_long_read_space(tx)?;

        if self.attr_requests.is_some() {
            tw.end_container()?;
        }

        let more_chunks = if let Some(resume_path) = resume_path {
            tw.bool(
                TagType::Context(msg::ReportDataTag::MoreChunkedMsgs as u8),
                true,
            )?;

            transaction
                .exch_mut()
                .set_suspended_read_req(self.suspend(resume_path));
            true
        } else {
            false
        };

        tw.bool(
            TagType::Context(msg::ReportDataTag::SupressResponse as u8),
            !more_chunks,
        )?;

        tw.end_container()?;

        if !more_chunks {
            transaction.complete();
        }

        Ok(true)
    }

    fn reserve_long_read_space<'p, 'b>(tx: &'p mut Packet<'b>) -> Result<TLVWriter<'p, 'b>, Error> {
        let wb = tx.get_writebuf()?;
        wb.shrink(LONG_READS_TLV_RESERVE_SIZE)?;

        Ok(TLVWriter::new(wb))
    }

    fn restore_long_read_space<'p, 'b>(tx: &'p mut Packet<'b>) -> Result<TLVWriter<'p, 'b>, Error> {
        let wb = tx.get_writebuf()?;
        wb.expand(LONG_READS_TLV_RESERVE_SIZE)?;

        Ok(TLVWriter::new(wb))
    }
}

impl<'a> WriteReq<'a> {
    fn initiate(&self, tx: &mut Packet, transaction: &mut Transaction) -> Result<bool, Error> {
        if transaction.has_timed_out() {
            Interaction::create_status_response(tx, IMStatusCode::Timeout)?;

            transaction.complete();

            Ok(false)
        } else {
            tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
            tx.set_proto_opcode(OpCode::WriteResponse as u8);

            let mut tw = TLVWriter::new(tx.get_writebuf()?);

            tw.start_struct(TagType::Anonymous)?;
            tw.start_array(TagType::Context(msg::WriteRespTag::WriteResponses as u8))?;

            Ok(true)
        }
    }

    pub fn complete(self, tx: &mut Packet, transaction: &mut Transaction) -> Result<bool, Error> {
        let suppress = self.supress_response.unwrap_or_default();

        let mut tw = TLVWriter::new(tx.get_writebuf()?);

        tw.end_container()?;
        tw.end_container()?;

        transaction.complete();

        Ok(if suppress {
            error!("Supress response is set, is this the expected handling?");
            false
        } else {
            true
        })
    }
}

impl<'a> InvReq<'a> {
    fn initiate(&self, tx: &mut Packet, transaction: &mut Transaction) -> Result<bool, Error> {
        if transaction.has_timed_out() {
            Interaction::create_status_response(tx, IMStatusCode::Timeout)?;

            transaction.complete();

            Ok(false)
        } else {
            let timed_tx = transaction.get_timeout().map(|_| true);
            let timed_request = self.timed_request.filter(|a| *a);

            // Either both should be None, or both should be Some(true)
            if timed_tx != timed_request {
                Interaction::create_status_response(tx, IMStatusCode::TimedRequestMisMatch)?;

                Ok(false)
            } else {
                tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
                tx.set_proto_opcode(OpCode::InvokeResponse as u8);

                let mut tw = TLVWriter::new(tx.get_writebuf()?);

                tw.start_struct(TagType::Anonymous)?;

                // Suppress Response -> TODO: Need to revisit this for cases where we send a command back
                tw.bool(
                    TagType::Context(msg::InvRespTag::SupressResponse as u8),
                    false,
                )?;

                if self.inv_requests.is_some() {
                    tw.start_array(TagType::Context(msg::InvRespTag::InvokeResponses as u8))?;
                }

                Ok(true)
            }
        }
    }

    pub fn complete(self, tx: &mut Packet, _transaction: &mut Transaction) -> Result<bool, Error> {
        let suppress = self.suppress_response.unwrap_or_default();

        let mut tw = TLVWriter::new(tx.get_writebuf()?);

        if self.inv_requests.is_some() {
            tw.end_container()?;
        }

        tw.end_container()?;

        Ok(if suppress {
            error!("Supress response is set, is this the expected handling?");
            false
        } else {
            true
        })
    }
}

impl TimedReq {
    pub fn process(&self, tx: &mut Packet, transaction: &mut Transaction) -> Result<(), Error> {
        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
        tx.set_proto_opcode(OpCode::StatusResponse as u8);

        let mut tw = TLVWriter::new(tx.get_writebuf()?);

        transaction.set_timeout(self.timeout.into());

        let status = StatusResp {
            status: IMStatusCode::Success,
        };

        status.to_tlv(&mut tw, TagType::Anonymous)?;

        Ok(())
    }
}

impl<'a> SubscribeReq<'a> {
    fn suspend(
        &self,
        resume_path: Option<GenericPath>,
        subscription_id: u32,
    ) -> ResumeSubscribeReq {
        ResumeSubscribeReq {
            subscription_id,
            paths: self
                .attr_requests
                .iter()
                .flat_map(|attr_requests| attr_requests.iter())
                .collect(),
            filters: self
                .dataver_filters
                .iter()
                .flat_map(|filters| filters.iter())
                .collect(),
            fabric_filtered: self.fabric_filtered,
            resume_path,
            keep_subs: self.keep_subs,
            min_int_floor: self.min_int_floor,
            max_int_ceil: self.max_int_ceil,
        }
    }

    fn initiate(&self, tx: &mut Packet, transaction: &mut Transaction) -> Result<bool, Error> {
        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
        tx.set_proto_opcode(OpCode::ReportData as u8);

        let mut tw = ReadReq::reserve_long_read_space(tx)?;

        tw.start_struct(TagType::Anonymous)?;

        let subscription_id = SUBS_ID.fetch_add(1, Ordering::SeqCst);
        transaction.exch_mut().set_subscription_id(subscription_id);

        tw.u32(
            TagType::Context(msg::ReportDataTag::SubscriptionId as u8),
            subscription_id,
        )?;

        if self.attr_requests.is_some() {
            tw.start_array(TagType::Context(msg::ReportDataTag::AttributeReports as u8))?;
        }

        Ok(true)
    }

    pub fn complete(
        self,
        tx: &mut Packet,
        transaction: &mut Transaction,
        resume_path: Option<GenericPath>,
    ) -> Result<bool, Error> {
        let mut tw = ReadReq::restore_long_read_space(tx)?;

        if self.attr_requests.is_some() {
            tw.end_container()?;
        }

        if resume_path.is_some() {
            tw.bool(
                TagType::Context(msg::ReportDataTag::MoreChunkedMsgs as u8),
                true,
            )?;
        }

        let subscription_id = transaction.exch_mut().take_subscription_id().unwrap();

        transaction
            .exch_mut()
            .set_suspended_subscribe_req(self.suspend(resume_path, subscription_id));

        tw.bool(
            TagType::Context(msg::ReportDataTag::SupressResponse as u8),
            false,
        )?;

        tw.end_container()?;

        Ok(true)
    }
}

#[derive(Debug)]
pub struct ResumeReadReq {
    pub paths: heapless::Vec<AttrPath, MAX_RESUME_PATHS>,
    pub filters: heapless::Vec<DataVersionFilter, MAX_RESUME_DATAVER_FILTERS>,
    pub fabric_filtered: bool,
    pub resume_path: GenericPath,
}

impl ResumeReadReq {
    fn initiate(&self, tx: &mut Packet, _transaction: &mut Transaction) -> Result<bool, Error> {
        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
        tx.set_proto_opcode(OpCode::ReportData as u8);

        let mut tw = ReadReq::reserve_long_read_space(tx)?;

        tw.start_struct(TagType::Anonymous)?;

        tw.start_array(TagType::Context(msg::ReportDataTag::AttributeReports as u8))?;

        Ok(true)
    }

    pub fn complete(
        mut self,
        tx: &mut Packet,
        transaction: &mut Transaction,
        resume_path: Option<GenericPath>,
    ) -> Result<bool, Error> {
        let mut tw = ReadReq::restore_long_read_space(tx)?;

        tw.end_container()?;

        let continue_interaction = if let Some(resume_path) = resume_path {
            tw.bool(
                TagType::Context(msg::ReportDataTag::MoreChunkedMsgs as u8),
                true,
            )?;

            self.resume_path = resume_path;
            transaction.exch_mut().set_suspended_read_req(self);
            true
        } else {
            false
        };

        tw.bool(
            TagType::Context(msg::ReportDataTag::SupressResponse as u8),
            !continue_interaction,
        )?;

        tw.end_container()?;

        if !continue_interaction {
            transaction.complete();
        }

        Ok(true)
    }
}

#[derive(Debug)]
pub struct ResumeSubscribeReq {
    pub subscription_id: u32,
    pub paths: heapless::Vec<AttrPath, MAX_RESUME_PATHS>,
    pub filters: heapless::Vec<DataVersionFilter, MAX_RESUME_DATAVER_FILTERS>,
    pub fabric_filtered: bool,
    pub resume_path: Option<GenericPath>,
    pub keep_subs: bool,
    pub min_int_floor: u16,
    pub max_int_ceil: u16,
}

impl ResumeSubscribeReq {
    fn initiate(&self, tx: &mut Packet, _transaction: &mut Transaction) -> Result<bool, Error> {
        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);

        if self.resume_path.is_some() {
            tx.set_proto_opcode(OpCode::ReportData as u8);

            let mut tw = ReadReq::reserve_long_read_space(tx)?;

            tw.start_struct(TagType::Anonymous)?;

            tw.u32(
                TagType::Context(msg::ReportDataTag::SubscriptionId as u8),
                self.subscription_id,
            )?;

            tw.start_array(TagType::Context(msg::ReportDataTag::AttributeReports as u8))?;

            Ok(true)
        } else {
            tx.set_proto_opcode(OpCode::SubscribeResponse as u8);

            let mut tw = TLVWriter::new(tx.get_writebuf()?);

            let resp = SubscribeResp::new(self.subscription_id, 40);
            resp.to_tlv(&mut tw, TagType::Anonymous)?;

            Ok(false)
        }
    }

    pub fn complete(
        mut self,
        tx: &mut Packet,
        transaction: &mut Transaction,
        resume_path: Option<GenericPath>,
    ) -> Result<bool, Error> {
        if self.resume_path.is_none() {
            // Should not get here as initiate() should've sent the subscribe response already
            panic!("Subscription was already processed");
        }

        // Completing a ReportData message

        let mut tw = ReadReq::restore_long_read_space(tx)?;

        tw.end_container()?;

        if resume_path.is_some() {
            tw.bool(
                TagType::Context(msg::ReportDataTag::MoreChunkedMsgs as u8),
                true,
            )?;
        }

        tw.bool(
            TagType::Context(msg::ReportDataTag::SupressResponse as u8),
            false,
        )?;

        tw.end_container()?;

        self.resume_path = resume_path;
        transaction.exch_mut().set_suspended_subscribe_req(self);

        Ok(true)
    }
}

pub trait InteractionHandler {
    fn handle(&mut self, ctx: &mut ProtoCtx) -> Result<bool, Error>;
}

impl<T> InteractionHandler for &mut T
where
    T: InteractionHandler,
{
    fn handle(&mut self, ctx: &mut ProtoCtx) -> Result<bool, Error> {
        (**self).handle(ctx)
    }
}

pub struct InteractionModel<T>(pub T);

impl<T> InteractionModel<T>
where
    T: DataHandler,
{
    pub fn handle(&mut self, ctx: &mut ProtoCtx) -> Result<bool, Error> {
        let mut transaction = Transaction::new(&mut ctx.exch_ctx);

        let reply =
            if let Some(interaction) = Interaction::initiate(ctx.rx, ctx.tx, &mut transaction)? {
                self.0.handle(interaction, ctx.tx, &mut transaction)?
            } else {
                true
            };

        if transaction.is_complete() {
            transaction.exch_mut().close();
        }

        Ok(reply)
    }
}

#[cfg(feature = "nightly")]
impl<T> InteractionModel<T>
where
    T: crate::data_model::core::asynch::AsyncDataHandler,
{
    pub async fn handle_async<'a>(&mut self, ctx: &mut ProtoCtx<'_, '_>) -> Result<bool, Error> {
        let mut transaction = Transaction::new(&mut ctx.exch_ctx);

        let reply =
            if let Some(interaction) = Interaction::initiate(ctx.rx, ctx.tx, &mut transaction)? {
                self.0.handle(interaction, ctx.tx, &mut transaction).await?
            } else {
                true
            };

        if transaction.is_complete() {
            transaction.exch_mut().close();
        }

        Ok(reply)
    }
}

impl<T> InteractionHandler for InteractionModel<T>
where
    T: DataHandler,
{
    fn handle(&mut self, ctx: &mut ProtoCtx) -> Result<bool, Error> {
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
        async fn handle(&mut self, ctx: &mut ProtoCtx<'_, '_>) -> Result<bool, Error>;
    }

    impl<T> AsyncInteractionHandler for &mut T
    where
        T: AsyncInteractionHandler,
    {
        async fn handle(&mut self, ctx: &mut ProtoCtx<'_, '_>) -> Result<bool, Error> {
            (**self).handle(ctx).await
        }
    }

    impl<T> AsyncInteractionHandler for InteractionModel<T>
    where
        T: AsyncDataHandler,
    {
        async fn handle(&mut self, ctx: &mut ProtoCtx<'_, '_>) -> Result<bool, Error> {
            InteractionModel::handle_async(self, ctx).await
        }
    }
}
