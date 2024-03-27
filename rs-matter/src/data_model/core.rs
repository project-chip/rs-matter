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

use core::cell::{Cell, RefCell};
use core::iter::Peekable;
use core::pin::pin;
use core::time::Duration;

use embassy_futures::select::{select, Either};
use embassy_time::{Instant, Timer};
use log::{debug, error, info, warn};

use crate::acl::Accessor;
use crate::interaction_model::messages::ib::AttrStatus;
use crate::utils::buf::BufferAccess;
use crate::{error::*, Matter};

use crate::interaction_model::core::{
    IMStatusCode, OpCode, ReportDataReq, PROTO_ID_INTERACTION_MODEL,
};
use crate::interaction_model::messages::msg::{
    InvReq, InvRespTag, ReadReq, ReportDataTag, StatusResp, SubscribeReq, SubscribeResp, TimedReq,
    WriteReq, WriteRespTag,
};
use crate::respond::ExchangeHandler;
use crate::tlv::{get_root_node_struct, FromTLV, TLVWriter, TagType};
use crate::transport::exchange::{Exchange, MAX_EXCHANGE_RX_BUF_SIZE, MAX_EXCHANGE_TX_BUF_SIZE};
use crate::utils::writebuf::WriteBuf;

use super::objects::*;
use super::subscriptions::Subscriptions;

/// The Maximum number of expanded writer request per transaction
///
/// The write requests are first wildcard-expanded, and these many number of
/// write requests per-transaction will be supported.
const MAX_WRITE_ATTRS_IN_ONE_TRANS: usize = 7;

pub type IMBuffer = heapless::Vec<u8, MAX_EXCHANGE_RX_BUF_SIZE>;

struct SubscriptionBuffer<B> {
    node_id: u64,
    id: u32,
    buffer: B,
}

/// An `ExchangeHandler` implementation capable of handling responder exchanges for the Interaction Model protocol.
/// The implementation needs a `DataModelHandler` instance to interact with the underlying clusters of the data model.
pub struct DataModel<'a, const N: usize, B, T>
where
    B: BufferAccess<IMBuffer>,
{
    handler: T,
    subscriptions: &'a Subscriptions<N>,
    subscriptions_buffers: RefCell<heapless::Vec<SubscriptionBuffer<B::Buffer<'a>>, N>>,
    buffers: &'a B,
}

impl<'a, const N: usize, B, T> DataModel<'a, N, B, T>
where
    B: BufferAccess<IMBuffer>,
    T: DataModelHandler,
{
    /// Create the handler.
    #[inline(always)]
    pub const fn new(buffers: &'a B, subscriptions: &'a Subscriptions<N>, handler: T) -> Self {
        Self {
            handler,
            subscriptions,
            subscriptions_buffers: RefCell::new(heapless::Vec::new()),
            buffers,
        }
    }

    /// Answer a responding exchange using the `DataModelHandler` instance wrapped by this exchange handler.
    pub async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let mut timeout_instant = None;

        loop {
            let mut repeat = false;

            if exchange.rx().is_err() {
                exchange.recv_fetch().await?;
            }

            let meta = exchange.rx()?.meta();
            if meta.proto_id != PROTO_ID_INTERACTION_MODEL {
                Err(ErrorCode::InvalidProto)?;
            }

            match meta.opcode::<OpCode>()? {
                OpCode::ReadRequest => self.read(exchange).await?,
                OpCode::WriteRequest => {
                    repeat = self.write(exchange, timeout_instant.take()).await?;
                }
                OpCode::InvokeRequest => self.invoke(exchange, timeout_instant.take()).await?,
                OpCode::SubscribeRequest => self.subscribe(exchange).await?,
                OpCode::TimedRequest => {
                    timeout_instant = Some(self.timed(exchange).await?);
                    repeat = true;
                }
                opcode => {
                    error!("Invalid opcode: {:?}", opcode);
                    Err(ErrorCode::InvalidOpcode)?
                }
            }

            if !repeat {
                break;
            }
        }

        exchange.acknowledge().await?;
        exchange.matter().notify_changed();

        Ok(())
    }

    async fn read(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let Some(mut tx) = self.tx_buffer(exchange).await? else {
            return Ok(());
        };

        let mut wb = WriteBuf::new(&mut tx);

        let metadata = self.handler.lock().await;

        let req = ReadReq::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;
        debug!("IM: Read request: {:?}", req);

        let req = ReportDataReq::Read(&req);

        let accessor = exchange.accessor()?;

        // Will the clusters that are to be invoked await?
        let awaits = metadata.node().read(&req, None, &accessor).any(|item| {
            item.map(|attr| self.handler.read_awaits(&attr))
                .unwrap_or(false)
        });

        if !awaits {
            // No, they won't. Answer the request by directly using the RX packet
            // of the transport layer, as the operation won't await.

            let node = metadata.node();
            let mut attrs = node.read(&req, None, &accessor).peekable();

            if !req
                .respond(&self.handler, None, &mut attrs, &mut wb, true)
                .await?
            {
                drop(attrs);

                exchange.send(OpCode::ReportData, wb.as_slice()).await?;

                // TODO: We are unconditionally using `suppress_resp = true` here.
                // However, the spec is a bit unclear when `suppress_resp = true` is allowed.
                //
                // At one place, it says this is a decision of the caller (i.e. what we do)
                // At another place, it says it is a decision of the caller, but _only_ if the
                // sets of attributes and events to be reported are both empty.
                //
                // I've also noticed the other peer (Google Controller) to reply with a status code
                // (that we don't expect due to `suppress_resp = true`) in the case of malformed response...
                //
                // Resolve this discrepancy in future.
                // Self::recv_status(exchange).await?;

                return Ok(());
            }
        }

        // The clusters will await.
        // Allocate a separate RX buffer then and copy the RX packet into this buffer,
        // so as not to hold on to the transport layer (single) RX packet for too long
        // and block send / receive for everybody

        let Some(rx) = self.rx_buffer(exchange).await? else {
            return Ok(());
        };

        let req = ReadReq::from_tlv(&get_root_node_struct(&rx)?)?;
        let req = ReportDataReq::Read(&req);

        let node = metadata.node();
        let mut attrs = node.read(&req, None, &accessor).peekable();

        loop {
            let more_chunks = req
                .respond(&self.handler, None, &mut attrs, &mut wb, true)
                .await?;

            exchange.send(OpCode::ReportData, wb.as_slice()).await?;

            if more_chunks && !Self::recv_status(exchange).await? {
                break;
            }

            if !more_chunks {
                break;
            }
        }

        Ok(())
    }

    async fn write(
        &self,
        exchange: &mut Exchange<'_>,
        timeout_instant: Option<Duration>,
    ) -> Result<bool, Error> {
        let req = WriteReq::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;
        debug!("IM: Write request: {:?}", req);

        let timed = req.timed_request.unwrap_or(false);

        if self.timed_out(exchange, timeout_instant, timed).await? {
            return Ok(false);
        }

        let Some(mut tx) = self.tx_buffer(exchange).await? else {
            return Ok(false);
        };

        let mut wb = WriteBuf::new(&mut tx);

        let metadata = self.handler.lock().await;

        let req = WriteReq::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;

        // Will the clusters that are to be invoked await?
        let awaits = metadata
            .node()
            .write(&req, &exchange.accessor()?)
            .any(|item| {
                item.map(|(attr, _)| self.handler.write_awaits(&attr))
                    .unwrap_or(false)
            });

        let more_chunks = if awaits {
            // Yes, they will
            // Allocate a separate RX buffer then and copy the RX packet into this buffer,
            // so as not to hold on to the transport layer (single) RX packet for too long
            // and block send / receive for everybody

            let Some(rx) = self.rx_buffer(exchange).await? else {
                return Ok(false);
            };

            let req = WriteReq::from_tlv(&get_root_node_struct(&rx)?)?;

            req.respond(
                &self.handler,
                &exchange.accessor()?,
                &metadata.node(),
                &mut wb,
            )
            .await?
        } else {
            // No, they won't. Answer the request by directly using the RX packet
            // of the transport layer, as the operation won't await.

            req.respond(
                &self.handler,
                &exchange.accessor()?,
                &metadata.node(),
                &mut wb,
            )
            .await?
        };

        exchange.send(OpCode::WriteResponse, wb.as_slice()).await?;

        Ok(more_chunks)
    }

    async fn invoke(
        &self,
        exchange: &mut Exchange<'_>,
        timeout_instant: Option<Duration>,
    ) -> Result<(), Error> {
        let req = InvReq::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;
        debug!("IM: Invoke request: {:?}", req);

        let timed = req.timed_request.unwrap_or(false);

        if self.timed_out(exchange, timeout_instant, timed).await? {
            return Ok(());
        }

        let Some(mut tx) = self.tx_buffer(exchange).await? else {
            return Ok(());
        };

        let mut wb = WriteBuf::new(&mut tx);

        let metadata = self.handler.lock().await;

        let req = InvReq::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;

        // Will the clusters that are to be invoked await?
        let awaits = metadata
            .node()
            .invoke(&req, &exchange.accessor()?)
            .any(|item| {
                item.map(|(cmd, _)| self.handler.invoke_awaits(&cmd))
                    .unwrap_or(false)
            });

        if awaits {
            // Yes, they will
            // Allocate a separate RX buffer then and copy the RX packet into this buffer,
            // so as not to hold on to the transport layer (single) RX packet for too long
            // and block send / receive for everybody

            let Some(rx) = self.rx_buffer(exchange).await? else {
                return Ok(());
            };

            let req = InvReq::from_tlv(&get_root_node_struct(&rx)?)?;

            req.respond(&self.handler, exchange, &metadata.node(), &mut wb)
                .await?;
        } else {
            // No, they won't. Answer the request by directly using the RX packet
            // of the transport layer, as the operation won't await.

            req.respond(&self.handler, exchange, &metadata.node(), &mut wb)
                .await?;
        }

        exchange.send(OpCode::InvokeResponse, wb.as_slice()).await?;

        Ok(())
    }

    async fn subscribe(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let Some(rx) = self.rx_buffer(exchange).await? else {
            return Ok(());
        };

        let Some(mut tx) = self.tx_buffer(exchange).await? else {
            return Ok(());
        };

        let req = SubscribeReq::from_tlv(&get_root_node_struct(&rx)?)?;
        debug!("IM: Subscribe request: {:?}", req);

        let node_id = exchange
            .with_session(|sess| sess.get_peer_node_id().ok_or(ErrorCode::Invalid.into()))?;

        if !req.keep_subs {
            self.subscriptions.remove(Some(node_id), None);
            self.subscriptions_buffers
                .borrow_mut()
                .retain(|sb| sb.node_id != node_id);

            info!("All subscriptions for node {node_id:x} removed");
        }

        let max_int_secs = core::cmp::max(req.max_int_ceil, 40); // Say we need at least 4 secs for potential latencies
        let min_int_secs = req.min_int_floor;

        if let Some(id) = self.subscriptions.add(node_id, min_int_secs, max_int_secs) {
            let subscribed = Cell::new(false);

            let _guard = scopeguard::guard((), |_| {
                if !subscribed.get() {
                    self.subscriptions.remove(None, Some(id));
                }
            });

            let primed = self
                .report_data(id, node_id, &rx, &mut tx, exchange)
                .await?;

            if primed {
                exchange
                    .send_with(|_, wb| {
                        SubscribeResp::write(wb, id, max_int_secs)?;
                        Ok(Some(OpCode::SubscribeResponse.into()))
                    })
                    .await?;

                info!("Subscription {node_id:x}::{id} created");

                if self.subscriptions.update(id, node_id) {
                    let _ = self
                        .subscriptions_buffers
                        .borrow_mut()
                        .push(SubscriptionBuffer {
                            node_id,
                            id,
                            buffer: rx,
                        });

                    subscribed.set(true);
                }
            }
        } else {
            Self::send_status(exchange, IMStatusCode::ResourceExhausted).await?;
        }

        Ok(())
    }

    pub async fn process_subscriptions(&self, matter: &Matter<'_>) -> Result<(), Error> {
        loop {
            let mut timeout = pin!(Timer::after(embassy_time::Duration::from_secs(4)));
            let mut notification = pin!(self.subscriptions.notification.wait());

            let result = select(&mut notification, &mut timeout).await;
            let _changed = matches!(result, Either::First(_));

            let now = Instant::now();

            {
                while let Some((node_id, id)) = self.subscriptions.find_expired(now) {
                    self.subscriptions.remove(None, Some(id));
                    self.subscriptions_buffers
                        .borrow_mut()
                        .retain(|sb| sb.id != id);

                    info!("Subscription {node_id:x}::{id} removed due to inactivity");
                }
            }

            loop {
                let sub = self.subscriptions.fetch_report_due(now);

                if let Some((node_id, id)) = sub {
                    info!("About to report data for subscription {node_id:x}::{id}");

                    let subscribed = Cell::new(false);

                    let _guard = scopeguard::guard((), |_| {
                        if !subscribed.get() {
                            self.subscriptions.remove(None, Some(id));
                        }
                    });

                    // TODO: Do a more sophisticated check whether something had actually changed w.r.t. this subscription

                    let index = self
                        .subscriptions_buffers
                        .borrow()
                        .iter()
                        .position(|sb| sb.id == id)
                        .unwrap();
                    let rx = self.subscriptions_buffers.borrow_mut().remove(index).buffer;

                    let mut req = SubscribeReq::from_tlv(&get_root_node_struct(&rx)?)?;

                    // Only used when priming the subscription
                    req.dataver_filters = None;

                    let mut exchange = Exchange::initiate(matter, node_id, true).await?;

                    if let Some(mut tx) = self.buffers.get().await {
                        let primed = self
                            .report_data(id, node_id, &rx, &mut tx, &mut exchange)
                            .await?;

                        exchange.acknowledge().await?;

                        if primed && self.subscriptions.update(id, node_id) {
                            let _ =
                                self.subscriptions_buffers
                                    .borrow_mut()
                                    .push(SubscriptionBuffer {
                                        node_id,
                                        id,
                                        buffer: rx,
                                    });
                            subscribed.set(true);
                        }
                    }
                } else {
                    break;
                }
            }
        }
    }

    async fn timed(&self, exchange: &mut Exchange<'_>) -> Result<Duration, Error> {
        let req = TimedReq::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;
        debug!("IM: Timed request: {:?}", req);

        let timeout_instant = req.timeout_instant(exchange.matter().epoch);

        Self::send_status(exchange, IMStatusCode::Success).await?;

        Ok(timeout_instant)
    }

    async fn timed_out(
        &self,
        exchange: &mut Exchange<'_>,
        timeout_instant: Option<Duration>,
        timed_req: bool,
    ) -> Result<bool, Error> {
        let status = {
            if timed_req != timeout_instant.is_some() {
                Some(IMStatusCode::TimedRequestMisMatch)
            } else if timeout_instant
                .map(|timeout_instant| (exchange.matter().epoch)() > timeout_instant)
                .unwrap_or(false)
            {
                Some(IMStatusCode::Timeout)
            } else {
                None
            }
        };

        if let Some(status) = status {
            Self::send_status(exchange, status).await?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn report_data(
        &self,
        id: u32,
        node_id: u64,
        rx: &[u8],
        tx: &mut [u8],
        exchange: &mut Exchange<'_>,
    ) -> Result<bool, Error>
    where
        T: DataModelHandler,
    {
        let mut wb = WriteBuf::new(tx);

        let req = SubscribeReq::from_tlv(&get_root_node_struct(rx)?)?;
        let req = ReportDataReq::Subscribe(&req);

        let metadata = self.handler.lock().await;

        let accessor = exchange.accessor()?;

        {
            let node = metadata.node();
            let mut attrs = node.read(&req, None, &accessor).peekable();

            loop {
                let more_chunks = req
                    .respond(&self.handler, Some(id), &mut attrs, &mut wb, false)
                    .await?;

                exchange.send(OpCode::ReportData, wb.as_slice()).await?;

                if !Self::recv_status(exchange).await? {
                    info!("Subscription {node_id:x}::{id} removed during reporting");
                    return Ok(false);
                }

                if !more_chunks {
                    break;
                }
            }
        }

        Ok(true)
    }

    async fn rx_buffer(&self, exchange: &mut Exchange<'_>) -> Result<Option<B::Buffer<'a>>, Error> {
        let buffer = self.tx_buffer(exchange).await?;

        if let Some(mut buffer) = buffer {
            let rx = exchange.rx()?;

            buffer.clear();
            buffer.extend_from_slice(rx.payload()).unwrap();

            exchange.rx_done()?;

            Ok(Some(buffer))
        } else {
            Ok(None)
        }
    }

    async fn tx_buffer(&self, exchange: &mut Exchange<'_>) -> Result<Option<B::Buffer<'a>>, Error> {
        if let Some(mut buffer) = self.buffers.get().await {
            buffer.resize_default(MAX_EXCHANGE_TX_BUF_SIZE).unwrap();

            Ok(Some(buffer))
        } else {
            Self::send_status(exchange, IMStatusCode::Busy).await?;

            Ok(None)
        }
    }

    async fn recv_status(exchange: &mut Exchange<'_>) -> Result<bool, Error> {
        let rx = exchange.recv().await?;
        let opcode = rx.meta().proto_opcode;

        if opcode == OpCode::StatusResponse as u8 {
            let resp = StatusResp::from_tlv(&get_root_node_struct(rx.payload())?)?;

            if resp.status == IMStatusCode::Success {
                Ok(true)
            } else {
                warn!(
                    "Got status response {:?}, aborting interaction",
                    resp.status
                );

                drop(rx);
                exchange.acknowledge().await?;

                Ok(false)
            }
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }

    async fn send_status(exchange: &mut Exchange<'_>, status: IMStatusCode) -> Result<(), Error> {
        exchange
            .send_with(|_, wb| {
                StatusResp::write(wb, status)?;

                Ok(Some(OpCode::StatusResponse.into()))
            })
            .await
    }
}

impl<'a, const N: usize, B, T> ExchangeHandler for DataModel<'a, N, B, T>
where
    T: DataModelHandler,
    B: BufferAccess<IMBuffer>,
{
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        DataModel::handle(self, exchange).await
    }
}

impl<'a> ReportDataReq<'a> {
    // This is the amount of space we reserve for other things to be attached towards
    // the end of long reads.
    const LONG_READS_TLV_RESERVE_SIZE: usize = 24;

    pub(crate) async fn respond<T, I>(
        &self,
        handler: T,
        subscription_id: Option<u32>,
        attrs: &mut Peekable<I>,
        wb: &mut WriteBuf<'_>,
        suppress_resp: bool,
    ) -> Result<bool, Error>
    where
        T: DataModelHandler,
        I: Iterator<Item = Result<AttrDetails<'a>, AttrStatus>>,
    {
        wb.reset();
        wb.shrink(Self::LONG_READS_TLV_RESERVE_SIZE)?;

        let mut tw = TLVWriter::new(wb);

        tw.start_struct(TagType::Anonymous)?;

        if let Some(subscription_id) = subscription_id {
            assert!(matches!(self, ReportDataReq::Subscribe(_)));
            tw.u32(
                TagType::Context(ReportDataTag::SubscriptionId as u8),
                subscription_id,
            )?;
        } else {
            assert!(matches!(self, ReportDataReq::Read(_)));
        }

        let has_requests = self.attr_requests().is_some();

        if has_requests {
            tw.start_array(TagType::Context(ReportDataTag::AttributeReports as u8))?;
        }

        while let Some(item) = attrs.peek() {
            if AttrDataEncoder::handle_read(item, &handler, &mut tw).await? {
                attrs.next();
            } else {
                break;
            }
        }

        wb.expand(Self::LONG_READS_TLV_RESERVE_SIZE)?;
        let mut tw = TLVWriter::new(wb);

        if has_requests {
            tw.end_container()?;
        }

        let more_chunks = attrs.peek().is_some();

        if more_chunks {
            tw.bool(TagType::Context(ReportDataTag::MoreChunkedMsgs as u8), true)?;
        }

        if !more_chunks && suppress_resp {
            tw.bool(TagType::Context(ReportDataTag::SupressResponse as u8), true)?;
        }

        tw.end_container()?;

        Ok(more_chunks)
    }
}

impl<'a> WriteReq<'a> {
    async fn respond<T>(
        &self,
        handler: T,
        accessor: &Accessor<'_>,
        node: &Node<'_>,
        wb: &mut WriteBuf<'_>,
    ) -> Result<bool, Error>
    where
        T: DataModelHandler,
    {
        wb.reset();

        let mut tw = TLVWriter::new(wb);

        tw.start_struct(TagType::Anonymous)?;
        tw.start_array(TagType::Context(WriteRespTag::WriteResponses as u8))?;

        // The spec expects that a single write request like DeleteList + AddItem
        // should cause all ACLs of that fabric to be deleted and the new one to be added (Case 1).
        //
        // This is in conflict with the immediate-effect expectation of ACL: an ACL
        // write should instantaneously update the ACL so that immediate next WriteAttribute
        // *in the same WriteRequest* should see that effect (Case 2).
        //
        // As with the C++ SDK, here we do all the ACLs checks first, before any write begins.
        // Thus we support the Case1 by doing this. It does come at the cost of maintaining an
        // additional list of expanded write requests as we start processing those.
        let write_attrs: heapless::Vec<_, MAX_WRITE_ATTRS_IN_ONE_TRANS> =
            node.write(self, accessor).collect();

        for item in write_attrs {
            AttrDataEncoder::handle_write(&item, &handler, &mut tw).await?;
        }

        tw.end_container()?;
        tw.end_container()?;

        Ok(self.more_chunked.unwrap_or(false))
    }
}

impl<'a> InvReq<'a> {
    async fn respond<T>(
        &self,
        handler: T,
        exchange: &Exchange<'_>,
        node: &Node<'_>,
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error>
    where
        T: DataModelHandler,
    {
        wb.reset();

        let mut tw = TLVWriter::new(wb);

        tw.start_struct(TagType::Anonymous)?;

        // Suppress Response -> TODO: Need to revisit this for cases where we send a command back
        tw.bool(TagType::Context(InvRespTag::SupressResponse as u8), false)?;

        let has_requests = self.inv_requests.is_some();

        if has_requests {
            tw.start_array(TagType::Context(InvRespTag::InvokeResponses as u8))?;
        }

        let accessor = exchange.accessor()?;

        for item in node.invoke(self, &accessor) {
            CmdDataEncoder::handle(&item, &handler, &mut tw, exchange).await?;
        }

        if has_requests {
            tw.end_container()?;
        }

        tw.end_container()?;

        Ok(())
    }
}
