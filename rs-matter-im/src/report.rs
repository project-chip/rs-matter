/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! The controller side of subscriptions: handling the `ReportData` messages
//! that a publisher sends for an established subscription.

use core::future::Future;
use core::num::NonZeroU8;

use crate::crypto::Crypto;
use crate::dm::{
    AsyncHandler, AttrChangeNotifier, AttrId, ClusterId, EndptId, EventEmitter, EventId,
    EventNumber, HandlerContext, LifecycleOp, Metadata,
};
use crate::dm::{EventTLVWrite, IMBuffer, ImStats};
use crate::encoding::{EventPriority, IMStatusCode, NodeId, ReportDataResp};
use crate::error::Error;
use crate::persist::KvBlobStoreAccess;
use crate::transport::exchange::Exchange;
use crate::utils::epoch::UtcTime;
use crate::utils::storage::pooled::Buffers;
use crate::utils::sync::{MaybeSend, MaybeSendSync};

/// The identity of the subscription (and the peer that owns it) that a
/// server-initiated `ReportData` message belongs to.
///
/// Reachable from a [`ReportContext`] via [`ReportContext::subscription`] and
/// handed (indirectly) to a [`ReportDataHandler`] so it can route the report to
/// the right in-flight subscription. The `(fabric_idx, peer_node_id,
/// subscription_id)` triple is exactly the key a controller records when it
/// establishes a subscription (see the IM client's `SubscribeEstablished`), and
/// mirrors how the C++ SDK matches an unsolicited `ReportData` to its
/// `ReadClient`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SubscriptionCtx {
    /// The local fabric index the report arrived on.
    pub fabric_idx: NonZeroU8,
    /// The node ID of the peer (publisher) that sent the report.
    pub peer_node_id: NodeId,
    /// The subscription ID carried in the report, if any. `None` for an
    /// unsolicited (subscription-less) `ReportData` — legal on the wire but not
    /// expected in the controller subscription flow.
    pub subscription_id: Option<u32>,
}

/// A context type passed to a [`ReportDataHandler`] when it processes a
/// server-initiated `ReportData` message (the controller / subscriber role).
///
/// Like [`ReadContext`] / [`InvokeContext`], it is a [`HandlerContext`] — so the
/// report handler has the same ambient access to the [`Matter`] stack, crypto,
/// KV store, networks, node metadata and buffer pool as any cluster handler —
/// plus the originating [`Exchange`] and the [`SubscriptionCtx`] identifying the
/// subscription the report belongs to.
pub trait ReportContext: HandlerContext {
    /// The exchange the report arrived on.
    fn exchange(&self) -> &Exchange<'_>;

    /// The `(fabric, peer, subscription-id)` identity of the report.
    fn subscription(&self) -> SubscriptionCtx;
}

impl<T> ReportContext for &T
where
    T: ReportContext,
{
    fn exchange(&self) -> &Exchange<'_> {
        (**self).exchange()
    }

    fn subscription(&self) -> SubscriptionCtx {
        (**self).subscription()
    }
}

/// A handler for consuming server-initiated `ReportData` messages — the
/// controller/subscriber side of the Interaction Model.
///
/// After a controller establishes a subscription (via the IM client), the
/// publisher pushes `ReportData` messages on fresh inbound exchanges
/// throughout the subscription's lifetime. The
/// [`InteractionModel`](crate::InteractionModel) accepts those exchanges
/// (it already owns all inbound IM traffic), parses each `ReportData` chunk,
/// ACKs it at the IM layer, and hands the parsed chunk to this trait via
/// [`handle_report`](Self::handle_report).
///
/// The report handler is a **separate, peer capability** of the
/// [`InteractionModel`], alongside the [`DataModel`] cluster handler — not a
/// supertrait of `DataModel`. A pure accessory does not supply one: the
/// `InteractionModel`'s report handler defaults to `()`, whose
/// implementation disowns every inbound report with
/// [`IMStatusCode::InvalidSubscription`] (the same status the C++ SDK returns
/// for an unmatched report, which the publisher uses to tear a stale
/// subscription down). A controller injects a real one via
/// [`InteractionModel::new_with_reports`](crate::InteractionModel::new_with_reports).
///
/// `handle_report` is invoked **once per received chunk** with a
/// [`ReportContext`] (a [`HandlerContext`] carrying the originating exchange
/// and the subscription identity) plus the parsed [`ReportDataResp`]
/// (borrowing the exchange RX buffer). The `InteractionModel` owns the
/// multi-chunk loop and the inter-chunk `StatusResponse(Success)` acks; a
/// handler that cares about chunk boundaries reads `report.more_chunks` and
/// reassembles across calls itself.
pub trait ReportDataHandler: MaybeSendSync {
    /// Handle a single received `ReportData` chunk.
    ///
    /// Returning `Ok(())` makes the `InteractionModel` reply
    /// `StatusResponse(Success)`; returning `Err(code)` makes it reply
    /// `StatusResponse(code)` (e.g. [`IMStatusCode::InvalidSubscription`] to
    /// disown a subscription the controller no longer tracks).
    fn handle_report(
        &self,
        ctx: impl ReportContext,
        report: &ReportDataResp<'_>,
    ) -> impl Future<Output = Result<(), IMStatusCode>> + MaybeSend;
}

impl<T> ReportDataHandler for &T
where
    T: ReportDataHandler,
{
    fn handle_report(
        &self,
        ctx: impl ReportContext,
        report: &ReportDataResp<'_>,
    ) -> impl Future<Output = Result<(), IMStatusCode>> {
        (**self).handle_report(ctx, report)
    }
}

impl<T> ReportDataHandler for &mut T
where
    T: ReportDataHandler,
{
    fn handle_report(
        &self,
        ctx: impl ReportContext,
        report: &ReportDataResp<'_>,
    ) -> impl Future<Output = Result<(), IMStatusCode>> {
        (**self).handle_report(ctx, report)
    }
}

/// The accessory-role default report handler: a device that never subscribes
/// to anything disowns every inbound report with
/// [`IMStatusCode::InvalidSubscription`]. This is the default type of the
/// `InteractionModel`'s report-handler generic, so existing accessory call
/// sites are unaffected.
impl ReportDataHandler for () {
    async fn handle_report(
        &self,
        _ctx: impl ReportContext,
        _report: &ReportDataResp<'_>,
    ) -> Result<(), IMStatusCode> {
        Err(IMStatusCode::InvalidSubscription)
    }
}

/// A concrete implementation of the [`ReportContext`] trait.
pub(crate) struct ReportContextInstance<'a, C> {
    exchange: &'a Exchange<'a>,
    context: C,
    subscription: SubscriptionCtx,
}

impl<'a, C> ReportContextInstance<'a, C>
where
    C: HandlerContext,
{
    /// Construct a new instance.
    #[inline(always)]
    pub(crate) const fn new(
        exchange: &'a Exchange<'a>,
        context: C,
        subscription: SubscriptionCtx,
    ) -> Self {
        Self {
            exchange,
            context,
            subscription,
        }
    }
}

impl<C> HandlerContext for ReportContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn utc_time(&self) -> UtcTime {
        self.context.utc_time()
    }

    fn crypto(&self) -> impl Crypto + '_ {
        self.context.crypto()
    }

    fn kv(&self) -> impl KvBlobStoreAccess + '_ {
        self.context.kv()
    }

    fn metadata(&self) -> impl Metadata + '_ {
        self.context.metadata()
    }

    fn handler(&self) -> impl AsyncHandler + '_ {
        self.context.handler()
    }

    fn buffers(&self) -> impl Buffers<IMBuffer> + '_ {
        self.context.buffers()
    }

    fn im_stats(&self) -> impl ImStats + '_ {
        self.context.im_stats()
    }

    fn notify_fabric_removed(&self, fab_idx: NonZeroU8) {
        self.context.notify_fabric_removed(fab_idx);
    }

    fn broadcast_lifecycle(&self, op: LifecycleOp) -> Result<(), Error> {
        self.context.broadcast_lifecycle(op)
    }
}

impl<C> AttrChangeNotifier for ReportContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn notify_attr_changed(&self, endpoint_id: EndptId, cluster_id: ClusterId, attr_id: AttrId) {
        self.context
            .notify_attr_changed(endpoint_id, cluster_id, attr_id);
    }

    fn notify_cluster_changed(&self, endpoint_id: EndptId, cluster_id: ClusterId) {
        self.context.notify_cluster_changed(endpoint_id, cluster_id);
    }

    fn notify_endpoint_changed(&self, endpoint_id: EndptId) {
        self.context.notify_endpoint_changed(endpoint_id);
    }

    fn notify_all_changed(&self) {
        self.context.notify_all_changed();
    }
}

impl<C> EventEmitter for ReportContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn emit_event<F>(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        event_id: EventId,
        priority: EventPriority,
        f: F,
    ) -> Result<EventNumber, Error>
    where
        F: FnOnce(EventTLVWrite<'_>) -> Result<(), Error>,
    {
        self.context
            .emit_event(endpoint_id, cluster_id, event_id, priority, f)
    }

    fn emit_u32_event(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        event_id: EventId,
        priority: EventPriority,
        value: u32,
    ) -> Result<EventNumber, Error> {
        self.context
            .emit_u32_event(endpoint_id, cluster_id, event_id, priority, value)
    }
}

impl<C> ReportContext for ReportContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn exchange(&self) -> &Exchange<'_> {
        self.exchange
    }

    fn subscription(&self) -> SubscriptionCtx {
        self.subscription
    }
}
