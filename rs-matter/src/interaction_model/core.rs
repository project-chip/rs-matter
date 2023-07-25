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
    acl::Accessor,
    error::*,
    tlv::{get_root_node_struct, FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
    transport::{exchange::Exchange, packet::Packet},
    utils::epoch::Epoch,
};
use log::error;
use num::{self, FromPrimitive};
use num_derive::FromPrimitive;

use super::messages::msg::{
    self, InvReq, ReadReq, StatusResp, SubscribeReq, SubscribeResp, TimedReq, WriteReq,
};

#[macro_export]
macro_rules! cmd_enter {
    ($e:expr) => {{
        use owo_colors::OwoColorize;
        info! {"{} {}", "Handling command".cyan(), $e.cyan()}
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
        FromPrimitive::from_u16(t.u16()?).ok_or_else(|| ErrorCode::Invalid.into())
    }
}

impl ToTLV for IMStatusCode {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        tw.u16(tag_type, *self as u16)
    }
}

#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
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

/* Interaction Model ID as per the Matter Spec */
pub const PROTO_ID_INTERACTION_MODEL: u16 = 0x01;

// This is the amount of space we reserve for other things to be attached towards
// the end of long reads.
const LONG_READS_TLV_RESERVE_SIZE: usize = 24;

impl<'a> ReadReq<'a> {
    pub fn tx_start<'r, 'p>(&self, tx: &'r mut Packet<'p>) -> Result<TLVWriter<'r, 'p>, Error> {
        tx.reset();
        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
        tx.set_proto_opcode(OpCode::ReportData as u8);

        let mut tw = Self::reserve_long_read_space(tx)?;

        tw.start_struct(TagType::Anonymous)?;

        if self.attr_requests.is_some() {
            tw.start_array(TagType::Context(msg::ReportDataTag::AttributeReports as u8))?;
        }

        Ok(tw)
    }

    pub fn tx_finish_chunk(&self, tx: &mut Packet) -> Result<(), Error> {
        self.complete(tx, true)
    }

    pub fn tx_finish(&self, tx: &mut Packet) -> Result<(), Error> {
        self.complete(tx, false)
    }

    fn complete(&self, tx: &mut Packet<'_>, more_chunks: bool) -> Result<(), Error> {
        let mut tw = Self::restore_long_read_space(tx)?;

        if self.attr_requests.is_some() {
            tw.end_container()?;
        }

        if more_chunks {
            tw.bool(
                TagType::Context(msg::ReportDataTag::MoreChunkedMsgs as u8),
                true,
            )?;
        }

        tw.bool(
            TagType::Context(msg::ReportDataTag::SupressResponse as u8),
            !more_chunks,
        )?;

        tw.end_container()
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
    pub fn tx_start<'r, 'p>(
        &self,
        tx: &'r mut Packet<'p>,
        epoch: Epoch,
        timeout: Option<Duration>,
    ) -> Result<Option<TLVWriter<'r, 'p>>, Error> {
        if has_timed_out(epoch, timeout) {
            Interaction::status_response(tx, IMStatusCode::Timeout)?;

            Ok(None)
        } else {
            tx.reset();
            tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
            tx.set_proto_opcode(OpCode::WriteResponse as u8);

            let mut tw = TLVWriter::new(tx.get_writebuf()?);

            tw.start_struct(TagType::Anonymous)?;
            tw.start_array(TagType::Context(msg::WriteRespTag::WriteResponses as u8))?;

            Ok(Some(tw))
        }
    }

    pub fn tx_finish(&self, tx: &mut Packet<'_>) -> Result<(), Error> {
        let mut tw = TLVWriter::new(tx.get_writebuf()?);

        tw.end_container()?;
        tw.end_container()
    }
}

impl<'a> InvReq<'a> {
    pub fn tx_start<'r, 'p>(
        &self,
        tx: &'r mut Packet<'p>,
        epoch: Epoch,
        timeout: Option<Duration>,
    ) -> Result<Option<TLVWriter<'r, 'p>>, Error> {
        if has_timed_out(epoch, timeout) {
            Interaction::status_response(tx, IMStatusCode::Timeout)?;

            Ok(None)
        } else {
            let timed_tx = timeout.map(|_| true);
            let timed_request = self.timed_request.filter(|a| *a);

            // Either both should be None, or both should be Some(true)
            if timed_tx != timed_request {
                Interaction::status_response(tx, IMStatusCode::TimedRequestMisMatch)?;

                Ok(None)
            } else {
                tx.reset();
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

                Ok(Some(tw))
            }
        }
    }

    pub fn tx_finish(&self, tx: &mut Packet<'_>) -> Result<(), Error> {
        let mut tw = TLVWriter::new(tx.get_writebuf()?);

        if self.inv_requests.is_some() {
            tw.end_container()?;
        }

        tw.end_container()
    }
}

impl TimedReq {
    pub fn timeout(&self, epoch: Epoch) -> Duration {
        epoch()
            .checked_add(Duration::from_millis(self.timeout as _))
            .unwrap()
    }

    pub fn tx_process(self, tx: &mut Packet<'_>, epoch: Epoch) -> Result<Duration, Error> {
        Interaction::status_response(tx, IMStatusCode::Success)?;

        Ok(epoch()
            .checked_add(Duration::from_millis(self.timeout as _))
            .unwrap())
    }
}

impl<'a> SubscribeReq<'a> {
    pub fn tx_start<'r, 'p>(
        &self,
        tx: &'r mut Packet<'p>,
        subscription_id: u32,
    ) -> Result<TLVWriter<'r, 'p>, Error> {
        tx.reset();
        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
        tx.set_proto_opcode(OpCode::ReportData as u8);

        let mut tw = ReadReq::reserve_long_read_space(tx)?;

        tw.start_struct(TagType::Anonymous)?;

        tw.u32(
            TagType::Context(msg::ReportDataTag::SubscriptionId as u8),
            subscription_id,
        )?;

        if self.attr_requests.is_some() {
            tw.start_array(TagType::Context(msg::ReportDataTag::AttributeReports as u8))?;
        }

        Ok(tw)
    }

    pub fn tx_finish_chunk(&self, tx: &mut Packet<'_>, more_chunks: bool) -> Result<(), Error> {
        let mut tw = ReadReq::restore_long_read_space(tx)?;

        if self.attr_requests.is_some() {
            tw.end_container()?;
        }

        if more_chunks {
            tw.bool(
                TagType::Context(msg::ReportDataTag::MoreChunkedMsgs as u8),
                true,
            )?;
        }

        tw.bool(
            TagType::Context(msg::ReportDataTag::SupressResponse as u8),
            false,
        )?;

        tw.end_container()
    }

    pub fn tx_process_final(&self, tx: &mut Packet, subscription_id: u32) -> Result<(), Error> {
        tx.reset();
        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
        tx.set_proto_opcode(OpCode::SubscribeResponse as u8);

        let mut tw = TLVWriter::new(tx.get_writebuf()?);

        let resp = SubscribeResp::new(subscription_id, 40);
        resp.to_tlv(&mut tw, TagType::Anonymous)
    }
}

pub struct ReadDriver<'a, 'r, 'p> {
    exchange: &'r mut Exchange<'a>,
    tx: &'r mut Packet<'p>,
    rx: &'r mut Packet<'p>,
    completed: bool,
}

impl<'a, 'r, 'p> ReadDriver<'a, 'r, 'p> {
    fn new(exchange: &'r mut Exchange<'a>, tx: &'r mut Packet<'p>, rx: &'r mut Packet<'p>) -> Self {
        Self {
            exchange,
            tx,
            rx,
            completed: false,
        }
    }

    fn start(&mut self, req: &ReadReq) -> Result<(), Error> {
        req.tx_start(self.tx)?;

        Ok(())
    }

    pub fn accessor(&self) -> Result<Accessor<'a>, Error> {
        self.exchange.accessor()
    }

    pub fn writer(&mut self) -> Result<TLVWriter<'_, 'p>, Error> {
        if self.completed {
            Err(ErrorCode::Invalid.into()) // TODO
        } else {
            Ok(TLVWriter::new(self.tx.get_writebuf()?))
        }
    }

    pub async fn send_chunk(&mut self, req: &ReadReq<'_>) -> Result<bool, Error> {
        req.tx_finish_chunk(self.tx)?;

        if exchange_confirm(self.exchange, self.tx, self.rx).await? != IMStatusCode::Success {
            self.completed = true;
            Ok(false)
        } else {
            req.tx_start(self.tx)?;

            Ok(true)
        }
    }

    pub async fn complete(&mut self, req: &ReadReq<'_>) -> Result<(), Error> {
        req.tx_finish(self.tx)?;

        self.exchange.send_complete(self.tx).await
    }
}

pub struct WriteDriver<'a, 'r, 'p> {
    exchange: &'r mut Exchange<'a>,
    tx: &'r mut Packet<'p>,
    epoch: Epoch,
    timeout: Option<Duration>,
}

impl<'a, 'r, 'p> WriteDriver<'a, 'r, 'p> {
    fn new(
        exchange: &'r mut Exchange<'a>,
        epoch: Epoch,
        timeout: Option<Duration>,
        tx: &'r mut Packet<'p>,
    ) -> Self {
        Self {
            exchange,
            tx,
            epoch,
            timeout,
        }
    }

    async fn start(&mut self, req: &WriteReq<'_>) -> Result<bool, Error> {
        if req.tx_start(self.tx, self.epoch, self.timeout)?.is_some() {
            Ok(true)
        } else {
            self.exchange.send_complete(self.tx).await?;

            Ok(false)
        }
    }

    pub fn accessor(&self) -> Result<Accessor<'a>, Error> {
        self.exchange.accessor()
    }

    pub fn writer(&mut self) -> Result<TLVWriter<'_, 'p>, Error> {
        Ok(TLVWriter::new(self.tx.get_writebuf()?))
    }

    pub async fn complete(&mut self, req: &WriteReq<'_>) -> Result<(), Error> {
        if !req.supress_response.unwrap_or_default() {
            req.tx_finish(self.tx)?;
            self.exchange.send_complete(self.tx).await?;
        }

        Ok(())
    }
}

pub struct InvokeDriver<'a, 'r, 'p> {
    exchange: &'r mut Exchange<'a>,
    tx: &'r mut Packet<'p>,
    epoch: Epoch,
    timeout: Option<Duration>,
}

impl<'a, 'r, 'p> InvokeDriver<'a, 'r, 'p> {
    fn new(
        exchange: &'r mut Exchange<'a>,
        epoch: Epoch,
        timeout: Option<Duration>,
        tx: &'r mut Packet<'p>,
    ) -> Self {
        Self {
            exchange,
            tx,
            epoch,
            timeout,
        }
    }

    async fn start(&mut self, req: &InvReq<'_>) -> Result<bool, Error> {
        if req.tx_start(self.tx, self.epoch, self.timeout)?.is_some() {
            Ok(true)
        } else {
            self.exchange.send_complete(self.tx).await?;

            Ok(false)
        }
    }

    pub fn accessor(&self) -> Result<Accessor<'a>, Error> {
        self.exchange.accessor()
    }

    pub fn writer(&mut self) -> Result<TLVWriter<'_, 'p>, Error> {
        Ok(TLVWriter::new(self.tx.get_writebuf()?))
    }

    pub fn writer_exchange(&mut self) -> Result<(TLVWriter<'_, 'p>, &Exchange<'a>), Error> {
        Ok((TLVWriter::new(self.tx.get_writebuf()?), (self.exchange)))
    }

    pub async fn complete(&mut self, req: &InvReq<'_>) -> Result<(), Error> {
        if !req.suppress_response.unwrap_or_default() {
            req.tx_finish(self.tx)?;
            self.exchange.send_complete(self.tx).await?;
        }

        Ok(())
    }
}

pub struct SubscribeDriver<'a, 'r, 'p> {
    exchange: &'r mut Exchange<'a>,
    tx: &'r mut Packet<'p>,
    rx: &'r mut Packet<'p>,
    subscription_id: u32,
    completed: bool,
}

impl<'a, 'r, 'p> SubscribeDriver<'a, 'r, 'p> {
    fn new(
        exchange: &'r mut Exchange<'a>,
        subscription_id: u32,
        tx: &'r mut Packet<'p>,
        rx: &'r mut Packet<'p>,
    ) -> Self {
        Self {
            exchange,
            tx,
            rx,
            subscription_id,
            completed: false,
        }
    }

    fn start(&mut self, req: &SubscribeReq) -> Result<(), Error> {
        req.tx_start(self.tx, self.subscription_id)?;

        Ok(())
    }

    pub fn accessor(&self) -> Result<Accessor<'a>, Error> {
        self.exchange.accessor()
    }

    pub fn writer(&mut self) -> Result<TLVWriter<'_, 'p>, Error> {
        if self.completed {
            Err(ErrorCode::Invalid.into()) // TODO
        } else {
            Ok(TLVWriter::new(self.tx.get_writebuf()?))
        }
    }

    pub async fn send_chunk(&mut self, req: &SubscribeReq<'_>) -> Result<bool, Error> {
        req.tx_finish_chunk(self.tx, true)?;

        if exchange_confirm(self.exchange, self.tx, self.rx).await? != IMStatusCode::Success {
            self.completed = true;
            Ok(false)
        } else {
            req.tx_start(self.tx, self.subscription_id)?;

            Ok(true)
        }
    }

    pub async fn complete(&mut self, req: &SubscribeReq<'_>) -> Result<(), Error> {
        if !self.completed {
            req.tx_finish_chunk(self.tx, false)?;

            if exchange_confirm(self.exchange, self.tx, self.rx).await? != IMStatusCode::Success {
                self.completed = true;
            } else {
                req.tx_process_final(self.tx, self.subscription_id)?;
                self.exchange.send_complete(self.tx).await?;
            }
        }

        Ok(())
    }
}

pub enum Interaction<'a, 'r, 'p> {
    Read {
        req: ReadReq<'r>,
        driver: ReadDriver<'a, 'r, 'p>,
    },
    Write {
        req: WriteReq<'r>,
        driver: WriteDriver<'a, 'r, 'p>,
    },
    Invoke {
        req: InvReq<'r>,
        driver: InvokeDriver<'a, 'r, 'p>,
    },
    Subscribe {
        req: SubscribeReq<'r>,
        driver: SubscribeDriver<'a, 'r, 'p>,
    },
}

impl<'a, 'r, 'p> Interaction<'a, 'r, 'p> {
    pub async fn timeout(
        exchange: &mut Exchange<'_>,
        rx: &mut Packet<'_>,
        tx: &mut Packet<'_>,
    ) -> Result<Option<Duration>, Error> {
        let epoch = exchange.matter.epoch;

        let mut opcode: OpCode = rx.get_proto_opcode()?;

        let mut timeout = None;

        while opcode == OpCode::TimedRequest {
            let rx_data = rx.as_slice();
            let req = TimedReq::from_tlv(&get_root_node_struct(rx_data)?)?;

            timeout = Some(req.tx_process(tx, epoch)?);

            exchange.exchange(tx, rx).await?;

            opcode = rx.get_proto_opcode()?;
        }

        Ok(timeout)
    }

    #[inline(always)]
    pub fn new<S>(
        exchange: &'r mut Exchange<'a>,
        rx: &'r Packet<'p>,
        tx: &'r mut Packet<'p>,
        rx_status: &'r mut Packet<'p>,
        subscription_id: S,
        timeout: Option<Duration>,
    ) -> Result<Interaction<'a, 'r, 'p>, Error>
    where
        S: FnOnce() -> u32,
    {
        let epoch = exchange.matter.epoch;

        let opcode = rx.get_proto_opcode()?;
        let rx_data = rx.as_slice();

        match opcode {
            OpCode::ReadRequest => {
                let req = ReadReq::from_tlv(&get_root_node_struct(rx_data)?)?;
                let driver = ReadDriver::new(exchange, tx, rx_status);

                Ok(Self::Read { req, driver })
            }
            OpCode::WriteRequest => {
                let req = WriteReq::from_tlv(&get_root_node_struct(rx_data)?)?;
                let driver = WriteDriver::new(exchange, epoch, timeout, tx);

                Ok(Self::Write { req, driver })
            }
            OpCode::InvokeRequest => {
                let req = InvReq::from_tlv(&get_root_node_struct(rx_data)?)?;
                let driver = InvokeDriver::new(exchange, epoch, timeout, tx);

                Ok(Self::Invoke { req, driver })
            }
            OpCode::SubscribeRequest => {
                let req = SubscribeReq::from_tlv(&get_root_node_struct(rx_data)?)?;
                let driver = SubscribeDriver::new(exchange, subscription_id(), tx, rx_status);

                Ok(Self::Subscribe { req, driver })
            }
            _ => {
                error!("Opcode not handled: {:?}", opcode);
                Err(ErrorCode::InvalidOpcode.into())
            }
        }
    }

    pub async fn start(&mut self) -> Result<bool, Error> {
        let started = match self {
            Self::Read { req, driver } => {
                driver.start(req)?;
                true
            }
            Self::Write { req, driver } => driver.start(req).await?,
            Self::Invoke { req, driver } => driver.start(req).await?,
            Self::Subscribe { req, driver } => {
                driver.start(req)?;
                true
            }
        };

        Ok(started)
    }

    fn status_response(tx: &mut Packet, status: IMStatusCode) -> Result<(), Error> {
        tx.reset();
        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
        tx.set_proto_opcode(OpCode::StatusResponse as u8);

        let mut tw = TLVWriter::new(tx.get_writebuf()?);

        let status = StatusResp { status };
        status.to_tlv(&mut tw, TagType::Anonymous)
    }
}

async fn exchange_confirm(
    exchange: &mut Exchange<'_>,
    tx: &mut Packet<'_>,
    rx: &mut Packet<'_>,
) -> Result<IMStatusCode, Error> {
    exchange.exchange(tx, rx).await?;

    let opcode: OpCode = rx.get_proto_opcode()?;

    if opcode == OpCode::StatusResponse {
        let resp = StatusResp::from_tlv(&get_root_node_struct(rx.as_slice())?)?;
        Ok(resp.status)
    } else {
        Interaction::status_response(tx, IMStatusCode::Busy)?; // TODO

        exchange.send_complete(tx).await?;

        Err(ErrorCode::Invalid.into()) // TODO
    }
}

fn has_timed_out(epoch: Epoch, timeout: Option<Duration>) -> bool {
    timeout.map(|timeout| epoch() > timeout).unwrap_or(false)
}
