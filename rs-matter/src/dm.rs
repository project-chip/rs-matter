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
use core::future::Future;
use core::num::NonZeroU8;
use core::pin::pin;
use core::time::Duration;

use embassy_futures::select::select3;
use embassy_time::{Instant, Timer};

use crate::error::{Error, ErrorCode};
use crate::im::{
    IMStatusCode, InvReq, InvRespTag, OpCode, ReadReq, ReportDataReq, ReportDataRespTag,
    StatusResp, SubscribeReq, SubscribeResp, TimedReq, WriteReq, WriteRespTag,
    PROTO_ID_INTERACTION_MODEL,
};
use crate::respond::ExchangeHandler;
use crate::tlv::{get_root_node_struct, FromTLV, Nullable, TLVElement, TLVTag, TLVWrite};
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
        let fetch_meta = |exchange: &mut Exchange| {
            let meta = exchange.rx()?.meta();
            if meta.proto_id != PROTO_ID_INTERACTION_MODEL {
                Err(ErrorCode::InvalidProto)?;
            }

            Result::<_, Error>::Ok(meta)
        };

        if exchange.rx().is_err() {
            exchange.recv_fetch().await?;
        }

        let mut meta = fetch_meta(exchange)?;

        let timeout_instant = if meta.opcode::<OpCode>()? == OpCode::TimedRequest {
            let timeout = self.timed(exchange).await?;

            exchange.recv_fetch().await?;
            meta = fetch_meta(exchange)?;

            Some(timeout)
        } else {
            None
        };

        // TODO: Handle the cases where we receive a timeout request
        // before read and subscribe. This is probably not allowed.

        match meta.opcode::<OpCode>()? {
            OpCode::ReadRequest => self.read(exchange).await?,
            OpCode::WriteRequest => self.write(exchange, timeout_instant).await?,
            OpCode::InvokeRequest => self.invoke(exchange, timeout_instant).await?,
            OpCode::SubscribeRequest => self.subscribe(exchange).await?,
            OpCode::TimedRequest => {
                Self::send_status(exchange, IMStatusCode::InvalidAction).await?
            }
            opcode => {
                error!("Invalid opcode: {:?}", opcode);
                Err(ErrorCode::InvalidOpcode)?
            }
        }

        exchange.acknowledge().await?;
        exchange.matter().notify_persist();

        Ok(())
    }

    /// Respond to a `ReadReq` request.
    async fn read(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let Some((mut tx, rx)) = self.buffers(exchange).await? else {
            return Ok(());
        };

        let read_req = ReadReq::new(TLVElement::new(&rx));
        debug!("IM: Read request: {:?}", read_req);

        let req = ReportDataReq::Read(&read_req);

        let mut wb = WriteBuf::new(&mut tx);

        let metadata = self.handler.lock().await;
        let node = metadata.node();

        let mut resp = ReportDataResponder::new(
            &req,
            &node,
            None,
            HandlerInvoker::new(exchange, &self.handler, &self.buffers),
        );

        resp.respond(&mut wb, true).await?;

        Ok(())
    }

    /// Respond to a `WriteReq` request.
    ///
    /// Arguments:
    /// - `exchange` - the exchange to respond to
    /// - `timeout_instant` - an optional timeout instant, if the request is a timed request
    async fn write(
        &self,
        exchange: &mut Exchange<'_>,
        timeout_instant: Option<Duration>,
    ) -> Result<(), Error> {
        while exchange.rx().is_ok() {
            // Loop while there are more write request chunks to process

            let Some((mut tx, rx)) = self.buffers(exchange).await? else {
                break;
            };

            let req = WriteReq::new(TLVElement::new(&rx));
            debug!("IM: Write request: {:?}", req);

            let timed = req.timed_request()?;

            if self.timed_out(exchange, timeout_instant, timed).await? {
                break;
            }

            let mut wb = WriteBuf::new(&mut tx);

            let metadata = self.handler.lock().await;
            let node = metadata.node();

            let mut resp = WriteResponder::new(
                &req,
                &node,
                HandlerInvoker::new(exchange, &self.handler, &self.buffers),
            );

            resp.respond(self, &mut wb).await?;

            if req.more_chunks()? {
                // This write request is just one of the chunks, so we need to wait and process
                // the next chunk as well
                exchange.recv_fetch().await?;
            }
        }

        Ok(())
    }

    /// Respond to an `InvokeReq` request.
    ///
    /// Arguments:
    /// - `exchange` - the exchange to respond to
    /// - `timeout_instant` - an optional timeout instant, if the request is a timed request
    async fn invoke(
        &self,
        exchange: &mut Exchange<'_>,
        timeout_instant: Option<Duration>,
    ) -> Result<(), Error> {
        let Some((mut tx, rx)) = self.buffers(exchange).await? else {
            return Ok(());
        };

        let req = InvReq::new(TLVElement::new(&rx));
        debug!("IM: Invoke request: {:?}", req);

        let timed = req.timed_request()?;

        if self.timed_out(exchange, timeout_instant, timed).await? {
            return Ok(());
        }

        let mut wb = WriteBuf::new(&mut tx);

        let metadata = self.handler.lock().await;
        let node = metadata.node();

        let mut resp = InvokeResponder::new(
            &req,
            &node,
            HandlerInvoker::new(exchange, &self.handler, &self.buffers),
        );

        resp.respond(self, &mut wb, false).await
    }

    /// Respond to a `SubscribeReq` request by priming the subscription (i.e. doing an initial data report)
    /// and if the priming is successful, sending a `SubscribeResp` response to the peer and registering
    /// the subscription details in the `Subscriptions` instance.
    async fn subscribe(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let Some((mut tx, rx)) = self.buffers(exchange).await? else {
            return Ok(());
        };

        let req = SubscribeReq::new(TLVElement::new(&rx));
        debug!("IM: Subscribe request: {:?}", req);

        if let Err(err) = self.validate_subscribe(&req).await {
            error!("Invalid subscribe request: {:?}", err);
            return Self::send_status(exchange, err.code().into()).await;
        }

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

    /// Validates the subscription request
    async fn validate_subscribe(&self, req: &SubscribeReq<'_>) -> Result<(), Error> {
        // As per spec, we need to validate that the subscription request
        // contains existing endpoints, clusters and attributes, and if not
        // we should (a bit surprisingly) return InvalidAction

        let metadata = self.handler.lock().await;

        if let Some(attr_requests) = req.attr_requests()? {
            let node = metadata.node();

            for attr_req in attr_requests {
                let attr_req = attr_req?;

                if let Some(endpt) = attr_req.endpoint {
                    let endpoint = node.endpoint(endpt).ok_or(ErrorCode::InvalidAction)?;

                    if let Some(clst) = attr_req.cluster {
                        let cluster = endpoint.cluster(clst).ok_or(ErrorCode::InvalidAction)?;

                        if let Some(attr) = attr_req.attr {
                            let _ = cluster.attribute(attr).ok_or(ErrorCode::InvalidAction)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Process all valid subscriptions in an endless loop, checking for changes
    /// and reporting them to the peers.
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

    /// Process one valid subscription, reporting the data to the peer.
    ///
    /// Arguments:
    /// - `matter` - a reference to the `Matter` instance
    /// - `fabric_idx` - the fabric index of the peer
    /// - `peer_node_id` - the node ID of the peer
    /// - `session_id` - the session ID of the peer, if any
    /// - `id` - the subscription ID
    /// - `rx` - the received and saved data for the subscription, when the subscription was primed
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

    /// Process a `TimedReq` request, which is used to set a timeout for the following Write/Invoke request.
    async fn timed(&self, exchange: &mut Exchange<'_>) -> Result<Duration, Error> {
        let req = TimedReq::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;
        debug!("IM: Timed request: {:?}", req);

        let timeout_instant = req.timeout_instant(exchange.matter().epoch());

        Self::send_status(exchange, IMStatusCode::Success).await?;

        Ok(timeout_instant)
    }

    /// A utility to check whether a timed request has timed out, and if so, send a timout status response
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
                Some(IMStatusCode::UnsupportedAccess)
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

    /// A utility to respond with a `ReportData` response to a subscription request, which is used to report data to the peer.
    ///
    /// Arguments:
    /// - `id` - the subscription ID
    /// - `fabric_idx` - the fabric index of the peer
    /// - `peer_node_id` - the node ID of the peer
    /// - `rx` - the received data for the subscription, when the subscription was primed
    /// - `tx` - the TX buffer to write the response to
    /// - `exchange` - the exchange to respond to
    /// - `with_dataver` - whether to include the data version in the response
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

        let sub_req = SubscribeReq::new(TLVElement::new(rx));
        let req = if with_dataver {
            ReportDataReq::Subscribe(&sub_req)
        } else {
            ReportDataReq::SubscribeReport(&sub_req)
        };

        let metadata = self.handler.lock().await;
        let node = metadata.node();

        let mut resp = ReportDataResponder::new(
            &req,
            &node,
            Some(id),
            HandlerInvoker::new(exchange, &self.handler, &self.buffers),
        );

        let sub_valid = resp.respond(&mut wb, false).await?;

        if !sub_valid {
            debug!(
                "Subscription [F:{:x},P:{:x}]::{} removed during reporting",
                fabric_idx, peer_node_id, id
            );
        }

        Ok(sub_valid)
    }

    /// A utility to fetch a pair of TX/RX buffers for processing an Interaction Model request.
    ///
    /// If there are no free buffers available, this method will send a `Busy` status response to the peer.
    ///
    /// Upon returning:
    /// - The RX buffer will contain the payload of the received Interaction Model request
    /// - The TX buffer will be resized to `MAX_EXCHANGE_TX_BUF_SIZE` and will be ready to be written to
    ///
    /// Returns:
    /// - `Ok(Some((tx, rx)))` - if both TX and RX buffers are available
    /// - `Ok(None)` - if no buffers are available, and a `Busy` status response has been sent
    /// - `Err(Error)` - if an error occurred while fetching the buffers or sending the status response
    async fn buffers(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> Result<Option<(B::Buffer<'a>, B::Buffer<'a>)>, Error> {
        if let Some(tx) = self.tx_buffer(exchange).await? {
            if let Some(rx) = self.rx_buffer(exchange).await? {
                return Ok(Some((tx, rx)));
            }
        }

        Ok(None)
    }

    /// A utility to fetch a RX buffer for processing an Interaction Model request.
    ///
    /// If there are no free buffers available, this method will send a `Busy` status response to the peer.
    ///
    /// Upon returning, the RX buffer will contain the payload of the received Interaction Model request.
    ///
    /// Returns:
    /// - `Ok(Some(rx))` - if a RX buffer is available
    /// - `Ok(None)` - if no RX buffer is available, and a `Busy` status response has been sent
    /// - `Err(Error)` - if an error occurred while fetching the buffer or sending the status response
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

    /// A utility to fetch a TX buffer for processing an Interaction Model request.
    ///
    /// If there are no free buffers available, this method will send a `Busy` status response to the peer.
    ///
    /// Upon returning, the TX buffer will be resized to `MAX_EXCHANGE_TX_BUF_SIZE` and will be ready to be written to.
    ///
    /// Returns:
    /// - `Ok(Some(tx))` - if a TX buffer is available
    /// - `Ok(None)` - if no TX buffer is available, and a `Busy` status response has been sent
    /// - `Err(Error)` - if an error occurred while fetching the buffer or sending the status response
    async fn tx_buffer(&self, exchange: &mut Exchange<'_>) -> Result<Option<B::Buffer<'a>>, Error> {
        if let Some(mut buffer) = self.buffer(exchange).await? {
            // Always safe as `IMBuffer` is defined to be `MAX_EXCHANGE_RX_BUF_SIZE`, which is bigger than `MAX_EXCHANGE_TX_BUF_SIZE`
            unwrap!(buffer.resize_default(MAX_EXCHANGE_TX_BUF_SIZE));

            Ok(Some(buffer))
        } else {
            Ok(None)
        }
    }

    /// A utility to fetch a buffer for processing an Interaction Model request.
    ///
    /// If there are no free buffers available, this method will send a `Busy` status response to the peer.
    ///
    /// Upon returning, the buffer will be UNINITIALIZED. I.e. it is up to the user to resize it appropriately
    /// if it is to be used for sending a response, or to fill it with data, if it is to be used for receiving data.
    ///
    /// Returns:
    /// - `Ok(Some(buffer))` - if a buffer is available
    /// - `Ok(None)` - if no buffer is available, and a `Busy` status response has been sent
    /// - `Err(Error)` - if an error occurred while fetching the buffer or sending the status response
    async fn buffer(&self, exchange: &mut Exchange<'_>) -> Result<Option<B::Buffer<'a>>, Error> {
        if let Some(buffer) = self.buffers.get().await {
            Ok(Some(buffer))
        } else {
            Self::send_status(exchange, IMStatusCode::Busy).await?;

            Ok(None)
        }
    }

    /// A utility to send a status response to the peer.
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
    fn handle(&self, exchange: &mut Exchange<'_>) -> impl Future<Output = Result<(), Error>> {
        DataModel::handle(self, exchange)
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

/// This type responds with a `ReportData` response to all of:
/// - A `ReadReq`
/// - A `SubscribeReq`
/// - A `SubscribeReportReq` (i.e. once a valid recorded subscription is detected as in a need to be reported on)
///
/// The responder handles chunking as needed. I.e. if reported data is too large to fit into a single
/// Matter message, it will send the data in multiple chunks (i.e. with multiple Matter messages), waiting for
/// a `Success` response from the peer after each chunk, and then continuing to send the next chunk until all data is sent.
struct ReportDataResponder<'a, 'b, 'c, D, B> {
    req: &'a ReportDataReq<'a>,
    node: &'a Node<'a>,
    subscription_id: Option<u32>,
    invoker: HandlerInvoker<'b, 'c, D, B>,
}

impl<'a, 'b, 'c, D, B> ReportDataResponder<'a, 'b, 'c, D, B>
where
    D: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    // This is the amount of space we reserve for the structure/array closing TLVs
    // to be attached towards the end of long reads
    const LONG_READS_TLV_RESERVE_SIZE: usize = 24;

    /// Create a new `ReportDataResponder`.
    const fn new(
        req: &'a ReportDataReq<'a>,
        node: &'a Node<'a>,
        subscription_id: Option<u32>,
        invoker: HandlerInvoker<'b, 'c, D, B>,
    ) -> Self {
        Self {
            req,
            node,
            subscription_id,
            invoker,
        }
    }

    /// Respond to the request with a `ReportData` response, possibly with more than one
    /// chunk if the data is too large to fit into a single Matter message.
    ///
    /// Arguments:
    /// - `wb` - the buffer to use while sending the response
    /// - `suppress_last_resp` - whether to suppress the response from the peer. When multiple Matter messages are
    ///   being sent due to chunking, this is valid for the last chunk only, as the others - by necessity need to have a
    ///   status response by the other peer
    async fn respond(
        &mut self,
        wb: &mut WriteBuf<'_>,
        suppress_last_resp: bool,
    ) -> Result<bool, Error> {
        let accessor = self.invoker.exchange().accessor()?;

        self.start_reply(wb)?;

        for item in self.node.read(self.req, &accessor)? {
            let item = item?;

            loop {
                let result = self.invoker.process_read(&item, &mut *wb).await;

                match result {
                    Ok(()) => break,
                    Err(err) if err.code() == ErrorCode::NoSpace => {
                        let array_attr = item.as_ref().ok().filter(|attr| {
                            attr.list_index.is_none()
                                // The whole attribute is requested
                                // Check if it is an array, and if so, send it as individual items instead
                                && self
                                    .node
                                    .endpoint(attr.endpoint_id)
                                    .and_then(|e| e.cluster(attr.cluster_id))
                                    .and_then(|c| c.attribute(attr.attr_id))
                                    .map(|a| a.quality.contains(Quality::ARRAY))
                                    .unwrap_or(false)
                        });

                        if let Some(array_attr) = array_attr {
                            if self.send_array_items(array_attr, wb).await? {
                                break;
                            } else {
                                return Ok(false);
                            }
                        } else {
                            debug!("<<< No TX space, chunking >>>");
                            if !self.send(true, false, wb).await? {
                                return Ok(false);
                            }
                        }
                    }
                    Err(err) => Err(err)?,
                }
            }
        }

        self.send(false, suppress_last_resp, wb).await
    }

    /// Send the items of an array attribute one by one, until the end of the array is reached.
    ///
    /// The data is potentially sent in multiple chunks if it cannot fit into a single Matter message.
    ///
    /// Arguments:
    /// - `attr` - the array attribute to send the items of
    /// - `wb` - the buffer to use while sending the items
    async fn send_array_items(
        &mut self,
        attr: &AttrDetails<'_>,
        wb: &mut WriteBuf<'_>,
    ) -> Result<bool, Error> {
        let mut attr = attr.clone();

        // First generate an empty array
        let mut list_index = None;
        attr.list_chunked = true;
        attr.list_index = Some(Nullable::new(list_index));

        loop {
            let pos = wb.get_tail();

            let result = self.invoker.read(&attr, &mut *wb).await;

            if result.is_err() {
                // If we got an error, we rewind to the position before the read
                // and handle it accordingly
                wb.rewind_to(pos);
            }

            match result {
                Ok(()) => {
                    // The empty array payload was sent
                    // Now iterate over the array and send each item one by one as separate payload

                    let new_list_index = if let Some(list_index) = list_index {
                        list_index + 1
                    } else {
                        0
                    };

                    list_index = Some(new_list_index);
                    attr.list_index = Some(Nullable::some(new_list_index));
                }
                Err(err) if err.code() == ErrorCode::NoSpace => {
                    debug!("<<< No TX space, chunking >>>");
                    if !self.send(true, false, wb).await? {
                        return Ok(false);
                    }
                }
                Err(err) if err.code() == ErrorCode::ConstraintError => break, // Got to the end of the array
                Err(err) => Err(err)?,
            }
        }

        Ok(true)
    }

    /// Send the reply to the peer, potentially opening another reply.
    ///
    /// Arguments:
    /// - `more_chunks`: whether there are more chunks to send. If `true`, this will initiate another reply in `wb`
    /// - `suppress_last_resp`: whether to suppress the response from the peer. Note that if `more_chunks` is `true`,
    ///   `suppress_last_resp` MUST be true and therefore it is set unconditionally
    /// - `wb`: the buffer containing the reply. Once the reply is sent, the buffer is re-initialized for a new reply if `more_chunks` is `true`
    async fn send(
        &mut self,
        more_chunks: bool,
        suppress_last_resp: bool,
        wb: &mut WriteBuf<'_>,
    ) -> Result<bool, Error> {
        self.end_reply(more_chunks, suppress_last_resp, wb)?;

        self.invoker
            .exchange()
            .send(OpCode::ReportData, wb.as_slice())
            .await?;

        let cont: bool = if more_chunks || !suppress_last_resp {
            self.recv_status_success().await?
        } else {
            false
        };

        if more_chunks {
            self.start_reply(wb)?;
        }

        Ok(cont)
    }

    /// Receive a status response from the peer
    ///
    /// If the response is not a status response, the method will fail with an `Invalid` error.
    ///
    /// Return `Ok(true)` if the response is a success response, `Ok(false)` if the response is not a success response.
    async fn recv_status_success(&mut self) -> Result<bool, Error> {
        let rx = self.invoker.exchange().recv().await?;
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

            self.invoker.exchange().acknowledge().await?;

            Ok(false)
        }
    }

    /// Start a reply by initializing the `WriteBuf` and writing the initial TLVs.
    fn start_reply(&self, wb: &mut WriteBuf<'_>) -> Result<(), Error> {
        wb.reset();
        wb.shrink(Self::LONG_READS_TLV_RESERVE_SIZE)?;

        wb.start_struct(&TLVTag::Anonymous)?;

        if let Some(subscription_id) = self.subscription_id {
            assert!(matches!(
                self.req,
                ReportDataReq::Subscribe(_) | ReportDataReq::SubscribeReport(_)
            ));
            wb.u32(
                &TLVTag::Context(ReportDataRespTag::SubscriptionId as u8),
                subscription_id,
            )?;
        } else {
            assert!(matches!(self.req, ReportDataReq::Read(_)));
        }

        let has_requests = self.req.attr_requests()?.is_some();

        if has_requests {
            wb.start_array(&TLVTag::Context(ReportDataRespTag::AttributeReports as u8))?;
        }

        Ok(())
    }

    /// End a reply by writing the closing TLVs and potentially indicating that there are more chunks to send.
    fn end_reply(
        &self,
        more_chunks: bool,
        suppress_resp: bool,
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        wb.expand(Self::LONG_READS_TLV_RESERVE_SIZE)?;

        let has_requests = self.req.attr_requests()?.is_some();

        if has_requests {
            wb.end_container()?;
        }

        if more_chunks {
            wb.bool(
                &TLVTag::Context(ReportDataRespTag::MoreChunkedMsgs as u8),
                true,
            )?;
        }

        if !more_chunks && suppress_resp {
            wb.bool(
                &TLVTag::Context(ReportDataRespTag::SupressResponse as u8),
                true,
            )?;
        }

        wb.end_container()?;

        Ok(())
    }
}

/// This type responds to a `WriteReq` by invoking the
/// corresponding handlers for each write attribute in the request.
///
/// The responser assumes that all response data can fit in a single Matter message,
/// which is a fair assumption and as per the Matter spec, in that the response of a
/// write request is always shorter than the write request itself, so given that the
/// write request fits in a single Matter message, the write reponse should as well.
///
/// With that said, the write request might itself be just one out of many chunks that
/// the other peers is sending, but processing all of those chunks is not done here,
/// but is rather - a responsibility of the caller who should call in a loop `WriteResponder::respond`
/// for all the chunks of the write request, until the `WriteReq::more_chunks()` returns `false`.
struct WriteResponder<'a, 'b, 'c, D, B> {
    req: &'a WriteReq<'a>,
    node: &'a Node<'a>,
    invoker: HandlerInvoker<'b, 'c, D, B>,
}

impl<'a, 'b, 'c, D, B> WriteResponder<'a, 'b, 'c, D, B>
where
    D: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    /// Create a new `WriteResponder`.
    const fn new(
        req: &'a WriteReq<'a>,
        node: &'a Node<'a>,
        invoker: HandlerInvoker<'b, 'c, D, B>,
    ) -> Self {
        Self { req, node, invoker }
    }

    /// Respond to the write request by processing each write attribute in the request
    /// and sending a response back.
    async fn respond(
        &mut self,
        notify: &dyn ChangeNotify,
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let accessor = self.invoker.exchange().accessor()?;

        wb.reset();

        wb.start_struct(&TLVTag::Anonymous)?;
        wb.start_array(&TLVTag::Context(WriteRespTag::WriteResponses as u8))?;

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
            self.node.write(self.req, &accessor)?.collect();

        for item in write_attrs {
            self.invoker.process_write(&item?, &mut *wb, notify).await?;
        }

        wb.end_container()?;
        wb.end_container()?;

        self.invoker
            .exchange()
            .send(OpCode::WriteResponse, wb.as_slice())
            .await
    }
}

/// This type responds to an `InvRequest` by invoking the
/// corresponding handlers for each command in the invoke request.
///
/// NOTE: In future, this responder should support chunking in that
/// if the reply to all the commands in the invoke request is too large to fit
/// into a single Matter message, it should send the response in multiple chunks.
///
/// The simplest strategy for chunking would be to simply - and unconditionally - send each individual
/// command response in a separate Matter message, i.e. if the invoke request contains 3 commands,
/// the responder will send 3 Matter messages, each containing a single command response.
struct InvokeResponder<'a, 'b, 'c, D, B> {
    req: &'a InvReq<'a>,
    node: &'a Node<'a>,
    invoker: HandlerInvoker<'b, 'c, D, B>,
}

impl<'a, 'b, 'c, D, B> InvokeResponder<'a, 'b, 'c, D, B>
where
    D: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    /// Create a new `InvokeResponder`.
    const fn new(
        req: &'a InvReq<'a>,
        node: &'a Node<'a>,
        invoker: HandlerInvoker<'b, 'c, D, B>,
    ) -> Self {
        Self { req, node, invoker }
    }

    /// Respond to the invoke request by processing each command in the request
    /// and sending one or more reponses back.
    async fn respond(
        &mut self,
        notify: &dyn ChangeNotify,
        wb: &mut WriteBuf<'_>,
        suppress_resp: bool,
    ) -> Result<(), Error> {
        wb.reset();

        wb.start_struct(&TLVTag::Anonymous)?;

        // Suppress Response -> TODO: Need to revisit this for cases where we send a command back
        wb.bool(
            &TLVTag::Context(InvRespTag::SupressResponse as u8),
            suppress_resp,
        )?;

        let has_requests = self.req.inv_requests()?.is_some();

        if has_requests {
            wb.start_array(&TLVTag::Context(InvRespTag::InvokeResponses as u8))?;
        }

        let accessor = self.invoker.exchange().accessor()?;

        for item in self.node.invoke(self.req, &accessor)? {
            self.invoker
                .process_invoke(&item?, &mut *wb, notify)
                .await?;
        }

        if has_requests {
            wb.end_container()?;
        }

        wb.end_container()?;

        self.invoker
            .exchange()
            .send(OpCode::InvokeResponse, wb.as_slice())
            .await?;

        Ok(())
    }
}
