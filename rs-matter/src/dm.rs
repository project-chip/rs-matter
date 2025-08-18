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
use core::num::NonZeroU8;
use core::pin::pin;
use core::time::Duration;

use embassy_futures::select::select3;
use embassy_time::{Instant, Timer};

use crate::error::*;
use crate::im::{
    AttrStatus, IMStatusCode, InvReqRef, InvRespTag, OpCode, ReadReqRef, ReportDataReq,
    ReportDataTag, StatusResp, SubscribeReqRef, SubscribeResp, TimedReq, WriteReqRef, WriteRespTag,
    PROTO_ID_INTERACTION_MODEL,
};
use crate::respond::ExchangeHandler;
use crate::tlv::{get_root_node_struct, FromTLV, TLVElement, TLVTag, TLVWrite, TLVWriter};
use crate::transport::exchange::{Exchange, MAX_EXCHANGE_RX_BUF_SIZE, MAX_EXCHANGE_TX_BUF_SIZE};
use crate::utils::storage::pooled::BufferAccess;
use crate::utils::storage::WriteBuf;
use crate::Matter;

use subscriptions::Subscriptions;

pub use types::*;

pub mod clusters;
pub mod devices;
pub mod endpoints;
pub mod networks;
pub mod subscriptions;

mod types;

/// The Maximum number of expanded writer request per transaction
///
/// The write requests are first wildcard-expanded, and these many number of
/// write requests per-transaction will be supported.
const MAX_WRITE_ATTRS_IN_ONE_TRANS: usize = 7;

pub type IMBuffer = heapless::Vec<u8, MAX_EXCHANGE_RX_BUF_SIZE>;

struct SubscriptionBuffer<B> {
    fabric_idx: NonZeroU8,
    peer_node_id: u64,
    subscription_id: u32,
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
    /// Create the data model.
    ///
    /// The parameters are as follows:
    /// * `buffers` - a reference to an implementation of `BufferAccess<IMBuffer>` which is used for allocating RX and TX buffers on the fly, when necessary
    /// * `subscriptions` - a reference to a `Subscriptions<N>` struct which is used for managing subscriptions. `N` designates the maximum
    ///   number of subscriptions that can be managed by this handler.
    /// * `handler` - an instance of type `T` which implements the `DataModelHandler` trait. This instance is used for interacting with the underlying
    ///   clusters of the data model. Note that the expectations is for the user to provide a handler that handles the Matter system clusters
    ///   as well (Endpoint 0), possibly by decorating her own clusters with the `rs_matter::dm::root_endpoint::with_` methods
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
        exchange.matter().notify_persist();

        Ok(())
    }

    async fn read(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let Some(mut tx) = self.tx_buffer(exchange).await? else {
            return Ok(());
        };

        let mut wb = WriteBuf::new(&mut tx);

        let metadata = self.handler.lock().await;

        let req = ReadReqRef::new(TLVElement::new(exchange.rx()?.payload()));
        debug!("IM: Read request: {:?}", req);

        let req = ReportDataReq::Read(&req);

        let accessor = exchange.accessor()?;

        // Will the clusters that are to be invoked await?
        let mut awaits = false;

        for item in metadata.node().read(&req, &exchange.accessor()?)? {
            if item?
                .map(|attr| {
                    self.handler.read_awaits(ReadContextInstance::new(
                        exchange,
                        &self.handler,
                        &self.buffers,
                        &attr,
                    ))
                })
                .unwrap_or(false)
            {
                awaits = true;
                break;
            }
        }

        if !awaits {
            // No, they won't. Answer the request by directly using the RX packet
            // of the transport layer, as the operation won't await.

            let node = metadata.node();
            let mut attrs = node.read(&req, &accessor)?.peekable();

            if !req
                .respond(
                    &self.handler,
                    &self.buffers,
                    exchange,
                    None,
                    &mut attrs,
                    &mut wb,
                    true,
                )
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

        let req = ReadReqRef::new(TLVElement::new(&rx));
        let req = ReportDataReq::Read(&req);

        let node = metadata.node();
        let mut attrs = node.read(&req, &accessor)?.peekable();

        loop {
            let more_chunks = req
                .respond(
                    &self.handler,
                    &self.buffers,
                    exchange,
                    None,
                    &mut attrs,
                    &mut wb,
                    true,
                )
                .await?;

            exchange.send(OpCode::ReportData, wb.as_slice()).await?;

            if more_chunks && !Self::recv_status_success(exchange).await? {
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
        let req = WriteReqRef::new(TLVElement::new(exchange.rx()?.payload()));
        debug!("IM: Write request: {:?}", req);

        let timed = req.timed_request()?;

        if self.timed_out(exchange, timeout_instant, timed).await? {
            return Ok(false);
        }

        let Some(mut tx) = self.tx_buffer(exchange).await? else {
            return Ok(false);
        };

        let mut wb = WriteBuf::new(&mut tx);

        let metadata = self.handler.lock().await;

        let req = WriteReqRef::new(TLVElement::new(exchange.rx()?.payload()));

        // Will the clusters that are to be invoked await?
        let mut awaits = false;

        for item in metadata.node().write(&req, &exchange.accessor()?)? {
            if item?
                .map(|(attr, _)| {
                    self.handler.write_awaits(WriteContextInstance::new(
                        exchange,
                        &self.handler,
                        &self.buffers,
                        &attr,
                        &TLVElement::new(&[]),
                        &(),
                    ))
                })
                .unwrap_or(false)
            {
                awaits = true;
                break;
            }
        }

        let more_chunks = if awaits {
            // Yes, they will
            // Allocate a separate RX buffer then and copy the RX packet into this buffer,
            // so as not to hold on to the transport layer (single) RX packet for too long
            // and block send / receive for everybody

            let Some(rx) = self.rx_buffer(exchange).await? else {
                return Ok(false);
            };

            let req = WriteReqRef::new(TLVElement::new(&rx));

            req.respond(
                &self.handler,
                &self.buffers,
                exchange,
                &metadata.node(),
                self,
                &mut wb,
            )
            .await?
        } else {
            // No, they won't. Answer the request by directly using the RX packet
            // of the transport layer, as the operation won't await.

            req.respond(
                &self.handler,
                &self.buffers,
                exchange,
                &metadata.node(),
                self,
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
        let req = InvReqRef::new(TLVElement::new(exchange.rx()?.payload()));
        debug!("IM: Invoke request: {:?}", req);

        let timed = req.timed_request()?;

        if self.timed_out(exchange, timeout_instant, timed).await? {
            return Ok(());
        }

        let Some(mut tx) = self.tx_buffer(exchange).await? else {
            return Ok(());
        };

        let mut wb = WriteBuf::new(&mut tx);

        let metadata = self.handler.lock().await;

        let req = InvReqRef::new(TLVElement::new(exchange.rx()?.payload()));

        // Will the clusters that are to be invoked await?
        let mut awaits = false;

        for item in metadata.node().invoke(&req, &exchange.accessor()?)? {
            if item?
                .map(|(cmd, _)| {
                    self.handler.invoke_awaits(InvokeContextInstance::new(
                        exchange,
                        &self.handler,
                        &self.buffers,
                        &cmd,
                        &TLVElement::new(&[]),
                        &(),
                    ))
                })
                .unwrap_or(false)
            {
                awaits = true;
                break;
            }
        }

        if awaits {
            // Yes, they will
            // Allocate a separate RX buffer then and copy the RX packet into this buffer,
            // so as not to hold on to the transport layer (single) RX packet for too long
            // and block send / receive for everybody

            let Some(rx) = self.rx_buffer(exchange).await? else {
                return Ok(());
            };

            let req = InvReqRef::new(TLVElement::new(&rx));

            req.respond(
                &self.handler,
                &self.buffers,
                exchange,
                &metadata.node(),
                self,
                &mut wb,
                false,
            )
            .await?;
        } else {
            // No, they won't. Answer the request by directly using the RX packet
            // of the transport layer, as the operation won't await.

            req.respond(
                &self.handler,
                &self.buffers,
                exchange,
                &metadata.node(),
                self,
                &mut wb,
                false,
            )
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

        let req = SubscribeReqRef::new(TLVElement::new(&rx));
        debug!("IM: Subscribe request: {:?}", req);

        let (fabric_idx, peer_node_id) = exchange.with_session(|sess| {
            let fabric_idx =
                NonZeroU8::new(sess.get_local_fabric_idx()).ok_or(ErrorCode::Invalid)?;
            let peer_node_id = sess.get_peer_node_id().ok_or(ErrorCode::Invalid)?;

            Ok((fabric_idx, peer_node_id))
        })?;

        if !req.keep_subs()? {
            self.subscriptions
                .remove(Some(fabric_idx), Some(peer_node_id), None);
            self.subscriptions_buffers
                .borrow_mut()
                .retain(|sb| sb.fabric_idx != fabric_idx || sb.peer_node_id != peer_node_id);

            debug!(
                "All subscriptions for [F:{:x},P:{:x}] removed",
                fabric_idx, peer_node_id
            );
        }

        let max_int_secs = core::cmp::max(req.max_int_ceil()?, 40); // Say we need at least 4 secs for potential latencies
        let min_int_secs = req.min_int_floor()?;

        let Some(id) = self.subscriptions.add(
            fabric_idx,
            peer_node_id,
            exchange.id().session_id(),
            min_int_secs,
            max_int_secs,
        ) else {
            return Self::send_status(exchange, IMStatusCode::ResourceExhausted).await;
        };

        let subscribed = Cell::new(false);

        let _guard = scopeguard::guard((), |_| {
            if !subscribed.get() {
                self.subscriptions.remove(None, None, Some(id));
            }
        });

        let primed = self
            .report_data(
                id,
                fabric_idx.get(),
                peer_node_id,
                &rx,
                &mut tx,
                exchange,
                true,
            )
            .await?;

        if primed {
            exchange
                .send_with(|_, wb| {
                    SubscribeResp::write(wb, id, max_int_secs)?;
                    Ok(Some(OpCode::SubscribeResponse.into()))
                })
                .await?;

            debug!(
                "Subscription [F:{:x},P:{:x}]::{} created",
                fabric_idx, peer_node_id, id
            );

            if self.subscriptions.mark_reported(id) {
                let _ = self
                    .subscriptions_buffers
                    .borrow_mut()
                    .push(SubscriptionBuffer {
                        fabric_idx,
                        peer_node_id,
                        subscription_id: id,
                        buffer: rx,
                    });

                subscribed.set(true);
            }
        }

        Ok(())
    }

    pub async fn process_subscriptions(&self, matter: &Matter<'_>) -> Result<(), Error> {
        loop {
            // TODO: Un-hardcode these 4 seconds of waiting when the more precise change detection logic is implemented
            let mut timeout = pin!(Timer::after(embassy_time::Duration::from_secs(4)));
            let mut notification = pin!(self.subscriptions.notification.wait());
            let mut session_removed = pin!(matter.transport_mgr.session_removed.wait());

            select3(&mut notification, &mut timeout, &mut session_removed).await;

            while let Some((fabric_idx, peer_node_id, session_id, id)) =
                self.subscriptions.find_removed_session(|session_id| {
                    matter
                        .transport_mgr
                        .session_mgr
                        .borrow_mut()
                        .get(session_id)
                        .is_none()
                })
            {
                self.subscriptions.remove(None, None, Some(id));
                self.subscriptions_buffers
                    .borrow_mut()
                    .retain(|sb| sb.subscription_id != id);

                debug!(
                    "Subscription [F:{:x},P:{:x}]::{} removed since its session ({}) had been removed too",
                    fabric_idx,
                    peer_node_id,
                    id,
                    session_id
                );
            }

            let now = Instant::now();

            while let Some((fabric_idx, peer_node_id, _, id)) = self.subscriptions.find_expired(now)
            {
                self.subscriptions.remove(None, None, Some(id));
                self.subscriptions_buffers
                    .borrow_mut()
                    .retain(|sb| sb.subscription_id != id);

                warn!(
                    "Subscription [F:{:x},P:{:x}]::{} removed due to inactivity",
                    fabric_idx, peer_node_id, id
                );
            }

            loop {
                let sub = self.subscriptions.find_report_due(now);

                if let Some((fabric_idx, peer_node_id, session_id, id)) = sub {
                    debug!(
                        "About to report data for subscription [F:{:x},P:{:x}]::{}",
                        fabric_idx, peer_node_id, id
                    );

                    let subscribed = Cell::new(false);

                    let _guard = scopeguard::guard((), |_| {
                        if !subscribed.get() {
                            self.subscriptions.remove(None, None, Some(id));
                        }
                    });

                    // TODO: Do a more sophisticated check whether something had actually changed w.r.t. this subscription

                    let index = unwrap!(self
                        .subscriptions_buffers
                        .borrow()
                        .iter()
                        .position(|sb| sb.subscription_id == id));
                    let rx = self.subscriptions_buffers.borrow_mut().remove(index).buffer;

                    let result = self
                        .process_subscription(matter, fabric_idx, peer_node_id, session_id, id, &rx)
                        .await;

                    match result {
                        Ok(primed) => {
                            if primed && self.subscriptions.mark_reported(id) {
                                let _ = self.subscriptions_buffers.borrow_mut().push(
                                    SubscriptionBuffer {
                                        fabric_idx,
                                        peer_node_id,
                                        subscription_id: id,
                                        buffer: rx,
                                    },
                                );
                                subscribed.set(true);
                            }
                        }
                        Err(e) => {
                            error!("Error while processing subscription: {:?}", e);
                        }
                    }
                } else {
                    break;
                }
            }
        }
    }

    async fn process_subscription(
        &self,
        matter: &Matter<'_>,
        fabric_idx: NonZeroU8,
        peer_node_id: u64,
        session_id: Option<u32>,
        id: u32,
        rx: &[u8],
    ) -> Result<bool, Error> {
        let mut exchange = if let Some(session_id) = session_id {
            Exchange::initiate_for_session(matter, session_id)?
        } else {
            // Commented out as we have issues on HomeKit with that:
            // https://github.com/ivmarkov/esp-idf-matter/issues/3
            // Exchange::initiate(matter, fabric_idx, peer_node_id, true).await?
            Err(ErrorCode::NoSession)?
        };

        if let Some(mut tx) = self.buffers.get().await {
            // Always safe as `IMBuffer` is defined to be `MAX_EXCHANGE_RX_BUF_SIZE`, which is bigger than `MAX_EXCHANGE_TX_BUF_SIZE`
            unwrap!(tx.resize_default(MAX_EXCHANGE_TX_BUF_SIZE));

            let primed = self
                .report_data(
                    id,
                    fabric_idx.get(),
                    peer_node_id,
                    rx,
                    &mut tx,
                    &mut exchange,
                    false,
                )
                .await?;

            exchange.acknowledge().await?;

            Ok(primed)
        } else {
            error!(
                "No TX buffer available for processing subscription [F:{:x},P:{:x}]::{}",
                fabric_idx, peer_node_id, id
            );

            Ok(false)
        }
    }

    async fn timed(&self, exchange: &mut Exchange<'_>) -> Result<Duration, Error> {
        let req = TimedReq::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;
        debug!("IM: Timed request: {:?}", req);

        let timeout_instant = req.timeout_instant(exchange.matter().epoch());

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
                .map(|timeout_instant| (exchange.matter().epoch())() > timeout_instant)
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

    #[allow(clippy::too_many_arguments)]
    async fn report_data(
        &self,
        id: u32,
        fabric_idx: u8,
        peer_node_id: u64,
        rx: &[u8],
        tx: &mut [u8],
        exchange: &mut Exchange<'_>,
        with_dataver: bool,
    ) -> Result<bool, Error>
    where
        T: DataModelHandler,
    {
        let mut wb = WriteBuf::new(tx);

        let req = SubscribeReqRef::new(TLVElement::new(rx));
        let req = if with_dataver {
            ReportDataReq::Subscribe(&req)
        } else {
            ReportDataReq::SubscribeReport(&req)
        };

        let metadata = self.handler.lock().await;

        let accessor = exchange.accessor()?;

        {
            let node = metadata.node();
            let mut attrs = node.read(&req, &accessor)?.peekable();

            loop {
                let more_chunks = req
                    .respond(
                        &self.handler,
                        &self.buffers,
                        exchange,
                        Some(id),
                        &mut attrs,
                        &mut wb,
                        false,
                    )
                    .await?;

                exchange.send(OpCode::ReportData, wb.as_slice()).await?;

                if !Self::recv_status_success(exchange).await? {
                    debug!(
                        "Subscription [F:{:x},P:{:x}]::{} removed during reporting",
                        fabric_idx, peer_node_id, id
                    );
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
        if let Some(mut buffer) = self.buffer(exchange).await? {
            let rx = exchange.rx()?;

            buffer.clear();

            // Safe to unwrap, as `IMBuffer` is defined to be `MAX_EXCHANGE_RX_BUF_SIZE`, i.e. it cannot be overflown
            // by the payload of the received exchange.
            unwrap!(buffer.extend_from_slice(rx.payload()));

            exchange.rx_done()?;

            Ok(Some(buffer))
        } else {
            Ok(None)
        }
    }

    async fn tx_buffer(&self, exchange: &mut Exchange<'_>) -> Result<Option<B::Buffer<'a>>, Error> {
        if let Some(mut buffer) = self.buffer(exchange).await? {
            // Always safe as `IMBuffer` is defined to be `MAX_EXCHANGE_RX_BUF_SIZE`, which is bigger than `MAX_EXCHANGE_TX_BUF_SIZE`
            unwrap!(buffer.resize_default(MAX_EXCHANGE_TX_BUF_SIZE));

            Ok(Some(buffer))
        } else {
            Self::send_status(exchange, IMStatusCode::Busy).await?;

            Ok(None)
        }
    }

    async fn buffer(&self, exchange: &mut Exchange<'_>) -> Result<Option<B::Buffer<'a>>, Error> {
        if let Some(buffer) = self.buffers.get().await {
            Ok(Some(buffer))
        } else {
            Self::send_status(exchange, IMStatusCode::Busy).await?;

            Ok(None)
        }
    }

    async fn recv_status_success(exchange: &mut Exchange<'_>) -> Result<bool, Error> {
        let rx = exchange.recv().await?;
        let opcode = rx.meta().proto_opcode;

        if opcode != OpCode::StatusResponse as u8 {
            warn!(
                "Got opcode {:02x}, while expecting status code {:02x}",
                opcode,
                OpCode::StatusResponse as u8
            );

            return Err(ErrorCode::Invalid.into());
        }

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

impl<const N: usize, B, T> ExchangeHandler for DataModel<'_, N, B, T>
where
    T: DataModelHandler,
    B: BufferAccess<IMBuffer>,
{
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        DataModel::handle(self, exchange).await
    }
}

impl<const N: usize, B, T> ChangeNotify for DataModel<'_, N, B, T>
where
    T: DataModelHandler,
    B: BufferAccess<IMBuffer>,
{
    fn notify(&self, _endpt: EndptId, _clust: ClusterId) {
        // TODO: Make use of endpt and clust
        self.subscriptions.notify_changed();
    }
}

impl<'a> ReportDataReq<'a> {
    // This is the amount of space we reserve for other things to be attached towards
    // the end of long reads.
    const LONG_READS_TLV_RESERVE_SIZE: usize = 24;

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn respond<T, B, I>(
        &self,
        handler: T,
        buffers: B,
        exchange: &Exchange<'_>,
        subscription_id: Option<u32>,
        attrs: &mut Peekable<I>,
        wb: &mut WriteBuf<'_>,
        suppress_resp: bool,
    ) -> Result<bool, Error>
    where
        T: DataModelHandler,
        B: BufferAccess<IMBuffer>,
        I: Iterator<Item = Result<Result<AttrDetails<'a>, AttrStatus>, Error>>,
    {
        wb.reset();
        wb.shrink(Self::LONG_READS_TLV_RESERVE_SIZE)?;

        let mut tw = TLVWriter::new(wb);

        tw.start_struct(&TLVTag::Anonymous)?;

        if let Some(subscription_id) = subscription_id {
            assert!(matches!(
                self,
                ReportDataReq::Subscribe(_) | ReportDataReq::SubscribeReport(_)
            ));
            tw.u32(
                &TLVTag::Context(ReportDataTag::SubscriptionId as u8),
                subscription_id,
            )?;
        } else {
            assert!(matches!(self, ReportDataReq::Read(_)));
        }

        let has_requests = self.attr_requests()?.is_some();

        if has_requests {
            tw.start_array(&TLVTag::Context(ReportDataTag::AttributeReports as u8))?;
        }

        while let Some(item) = attrs.peek() {
            match item {
                Ok(item) => {
                    if ReadReplyInstance::handle_read(exchange, item, &handler, &buffers, &mut tw)
                        .await?
                    {
                        attrs.next();
                    } else {
                        break;
                    }
                }
                Err(_) => {
                    attrs.next().transpose()?;
                }
            }
        }

        wb.expand(Self::LONG_READS_TLV_RESERVE_SIZE)?;
        let tw = wb;

        if has_requests {
            tw.end_container()?;
        }

        let more_chunks = attrs.peek().is_some();

        if more_chunks {
            tw.bool(&TLVTag::Context(ReportDataTag::MoreChunkedMsgs as u8), true)?;
        }

        if !more_chunks && suppress_resp {
            tw.bool(&TLVTag::Context(ReportDataTag::SupressResponse as u8), true)?;
        }

        tw.end_container()?;

        Ok(more_chunks)
    }
}

impl WriteReqRef<'_> {
    async fn respond<T, B>(
        &self,
        handler: T,
        buffers: B,
        exchange: &Exchange<'_>,
        node: &Node<'_>,
        notify: &dyn ChangeNotify,
        wb: &mut WriteBuf<'_>,
    ) -> Result<bool, Error>
    where
        T: DataModelHandler,
        B: BufferAccess<IMBuffer>,
    {
        let accessor = exchange.accessor()?;

        wb.reset();

        let mut tw = TLVWriter::new(wb);

        tw.start_struct(&TLVTag::Anonymous)?;
        tw.start_array(&TLVTag::Context(WriteRespTag::WriteResponses as u8))?;

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
            node.write(self, &accessor)?.collect();

        for item in write_attrs {
            ReadReplyInstance::handle_write(exchange, &item?, &handler, &buffers, &mut tw, notify)
                .await?;
        }

        tw.end_container()?;
        tw.end_container()?;

        self.more_chunked()
    }
}

impl InvReqRef<'_> {
    #[allow(clippy::too_many_arguments)]
    async fn respond<T, B>(
        &self,
        handler: T,
        buffers: B,
        exchange: &Exchange<'_>,
        node: &Node<'_>,
        notify: &dyn ChangeNotify,
        wb: &mut WriteBuf<'_>,
        suppress_resp: bool,
    ) -> Result<(), Error>
    where
        T: DataModelHandler,
        B: BufferAccess<IMBuffer>,
    {
        wb.reset();

        let mut tw = TLVWriter::new(wb);

        tw.start_struct(&TLVTag::Anonymous)?;

        // Suppress Response -> TODO: Need to revisit this for cases where we send a command back
        tw.bool(
            &TLVTag::Context(InvRespTag::SupressResponse as u8),
            suppress_resp,
        )?;

        let has_requests = self.inv_requests()?.is_some();

        if has_requests {
            tw.start_array(&TLVTag::Context(InvRespTag::InvokeResponses as u8))?;
        }

        let accessor = exchange.accessor()?;

        for item in node.invoke(self, &accessor)? {
            InvokeReplyInstance::handle(&item?, &handler, &buffers, &mut tw, exchange, notify)
                .await?;
        }

        if has_requests {
            tw.end_container()?;
        }

        tw.end_container()?;

        Ok(())
    }
}
