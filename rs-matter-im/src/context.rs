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

//! The implementations of the operation contexts that the Interaction Model
//! engine hands to the handlers.

use core::num::NonZeroU8;

use crate::crypto::Crypto;
use crate::dm::ImStats;
use crate::dm::{
    AsyncHandler, AttrChangeNotifier, AttrDetails, AttrId, ClusterId, CmdDetails, EndptId,
    EventEmitter, EventId, EventNumber, HandlerContext, InvokeContext, LifecycleOp, MatchContext,
    Metadata, OperationContext, OwnAttrChangeNotifier, OwnEventEmitter, ReadContext, TransactionId,
    WriteContext,
};
use crate::dm::{EventTLVWrite, IMBuffer};
use crate::encoding::EventPriority;
use crate::error::Error;
use crate::persist::KvBlobStoreAccess;
use crate::tlv::TLVElement;
use crate::utils::epoch::UtcTime;
use crate::utils::storage::pooled::Buffers;

/// A concrete implementation of the `ReadContext` trait
pub(crate) struct ReadContextInstance<'a, C> {
    transaction_id: TransactionId,
    context: C,
    attr: &'a AttrDetails,
}

impl<'a, C> ReadContextInstance<'a, C>
where
    C: HandlerContext,
{
    /// Construct a new instance.
    #[inline(always)]
    pub(crate) const fn new(
        transaction_id: TransactionId,
        context: C,
        attr: &'a AttrDetails,
    ) -> Self {
        Self {
            transaction_id,
            context,
            attr,
        }
    }
}

impl<C> HandlerContext for ReadContextInstance<'_, C>
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

impl<C> AttrChangeNotifier for ReadContextInstance<'_, C>
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

impl<C> EventEmitter for ReadContextInstance<'_, C>
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

impl<C> MatchContext for ReadContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn endpt(&self) -> Option<EndptId> {
        Some(self.attr.endpoint_id)
    }

    fn cluster(&self) -> Option<ClusterId> {
        Some(self.attr.cluster_id)
    }
}

impl<C> OperationContext for ReadContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }
}

impl<C> OwnAttrChangeNotifier for ReadContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn notify_own_attr_changed(&self, attr_id: AttrId) {
        self.notify_attr_changed(self.attr.endpoint_id, self.attr.cluster_id, attr_id);
    }

    fn notify_own_cluster_changed(&self) {
        self.notify_cluster_changed(self.attr.endpoint_id, self.attr.cluster_id);
    }

    fn notify_own_endpoint_changed(&self) {
        self.notify_endpoint_changed(self.attr.endpoint_id);
    }
}

impl<C> OwnEventEmitter for ReadContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn emit_own_event<F>(
        &self,
        event_id: EventId,
        priority: EventPriority,
        f: F,
    ) -> Result<EventNumber, Error>
    where
        F: FnOnce(EventTLVWrite<'_>) -> Result<(), Error>,
    {
        self.context.emit_event(
            self.attr.endpoint_id,
            self.attr.cluster_id,
            event_id,
            priority,
            f,
        )
    }
}

impl<C> ReadContext for ReadContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn attr(&self) -> &AttrDetails {
        self.attr
    }
}

/// A context implementation of the `WriteContext` trait
pub(crate) struct WriteContextInstance<'a, C> {
    transaction_id: TransactionId,
    context: C,
    attr: &'a AttrDetails,
    data: &'a TLVElement<'a>,
}

impl<'a, C> WriteContextInstance<'a, C>
where
    C: HandlerContext,
{
    /// Create a new instance.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        transaction_id: TransactionId,
        context: C,
        attr: &'a AttrDetails,
        data: &'a TLVElement<'a>,
    ) -> Self {
        Self {
            transaction_id,
            context,
            attr,
            data,
        }
    }
}

impl<C> HandlerContext for WriteContextInstance<'_, C>
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

impl<C> AttrChangeNotifier for WriteContextInstance<'_, C>
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

impl<C> EventEmitter for WriteContextInstance<'_, C>
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

impl<C> MatchContext for WriteContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn endpt(&self) -> Option<EndptId> {
        Some(self.attr.endpoint_id)
    }

    fn cluster(&self) -> Option<ClusterId> {
        Some(self.attr.cluster_id)
    }
}

impl<C> OperationContext for WriteContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }
}

impl<C> OwnAttrChangeNotifier for WriteContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn notify_own_attr_changed(&self, attr_id: AttrId) {
        self.notify_attr_changed(self.attr.endpoint_id, self.attr.cluster_id, attr_id);
    }

    fn notify_own_cluster_changed(&self) {
        self.notify_cluster_changed(self.attr.endpoint_id, self.attr.cluster_id);
    }

    fn notify_own_endpoint_changed(&self) {
        self.notify_endpoint_changed(self.attr.endpoint_id);
    }
}

impl<C> OwnEventEmitter for WriteContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn emit_own_event<F>(
        &self,
        event_id: EventId,
        priority: EventPriority,
        f: F,
    ) -> Result<EventNumber, Error>
    where
        F: FnOnce(EventTLVWrite<'_>) -> Result<(), Error>,
    {
        self.context.emit_event(
            self.attr.endpoint_id,
            self.attr.cluster_id,
            event_id,
            priority,
            f,
        )
    }
}

impl<C> WriteContext for WriteContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn attr(&self) -> &AttrDetails {
        self.attr
    }

    fn data(&self) -> &TLVElement<'_> {
        self.data
    }
}

/// A concrete implementation of the `InvokeContext` trait
pub(crate) struct InvokeContextInstance<'a, C> {
    transaction_id: TransactionId,
    context: C,
    cmd: &'a CmdDetails,
    data: &'a TLVElement<'a>,
}

impl<'a, C> InvokeContextInstance<'a, C>
where
    C: HandlerContext,
{
    /// Construct a new instance.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        transaction_id: TransactionId,
        context: C,
        cmd: &'a CmdDetails,
        data: &'a TLVElement<'a>,
    ) -> Self {
        Self {
            transaction_id,
            context,
            cmd,
            data,
        }
    }
}

impl<C> HandlerContext for InvokeContextInstance<'_, C>
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

impl<C> AttrChangeNotifier for InvokeContextInstance<'_, C>
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

impl<C> EventEmitter for InvokeContextInstance<'_, C>
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

impl<C> MatchContext for InvokeContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn endpt(&self) -> Option<EndptId> {
        Some(self.cmd.endpoint_id)
    }

    fn cluster(&self) -> Option<ClusterId> {
        Some(self.cmd.cluster_id)
    }
}

impl<C> OperationContext for InvokeContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }
}

impl<C> OwnAttrChangeNotifier for InvokeContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn notify_own_attr_changed(&self, attr_id: AttrId) {
        self.notify_attr_changed(self.cmd.endpoint_id, self.cmd.cluster_id, attr_id);
    }

    fn notify_own_cluster_changed(&self) {
        self.notify_cluster_changed(self.cmd.endpoint_id, self.cmd.cluster_id);
    }

    fn notify_own_endpoint_changed(&self) {
        self.notify_endpoint_changed(self.cmd.endpoint_id);
    }
}

impl<C> OwnEventEmitter for InvokeContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn emit_own_event<F>(
        &self,
        event_id: EventId,
        priority: EventPriority,
        f: F,
    ) -> Result<EventNumber, Error>
    where
        F: FnOnce(EventTLVWrite<'_>) -> Result<(), Error>,
    {
        self.context.emit_event(
            self.cmd.endpoint_id,
            self.cmd.cluster_id,
            event_id,
            priority,
            f,
        )
    }
}

impl<C> InvokeContext for InvokeContextInstance<'_, C>
where
    C: HandlerContext,
{
    fn cmd(&self) -> &CmdDetails {
        self.cmd
    }

    fn data(&self) -> &TLVElement<'_> {
        self.data
    }
}
