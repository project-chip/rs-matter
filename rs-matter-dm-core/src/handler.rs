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

use core::future::Future;
use core::num::NonZeroU8;
use core::pin::pin;

use crate::crypto::Crypto;
use crate::error::{Error, ErrorCode};
use crate::im::EventPriority;
use crate::persist::KvBlobStoreAccess;
use crate::tlv::{TLVElement, TLVTag, TLVWrite};
use crate::utils::epoch::UtcTime;
use crate::utils::futures::{select, Coalesce};
use crate::utils::storage::pooled::Buffers;
use crate::utils::sync::{MaybeSend, MaybeSendSync};
use crate::{EventId, EventNumber, EventTLVWrite, IMBuffer, ImStats, Metadata, EVENT_DATA_TAG};

use super::{
    AttrDetails, AttrId, ClusterId, CmdDetails, EndptId, InvokeReply, ReadReply, TransactionId,
};

pub use asynch::*;

pub trait DynAttrChangeNotifier: MaybeSendSync + AttrChangeNotifier {}

impl<T> DynAttrChangeNotifier for T where T: MaybeSendSync + AttrChangeNotifier {}

/// A trait for notifying the data model that the state of an attribute has changed.
pub trait AttrChangeNotifier {
    /// Notify that the state of an attribute has changed.
    ///
    /// # Arguments
    /// - `endpoint_id`: The endpoint ID of the cluster that has changed.
    /// - `cluster_id`: The cluster ID of the cluster that has changed.
    /// - `attr_id`: The attribute ID of the attribute that has changed.
    fn notify_attr_changed(&self, endpoint_id: EndptId, cluster_id: ClusterId, attr_id: AttrId);

    /// Notify that every attribute of the given cluster may have changed.
    ///
    /// Use this when a single operation mutates many attributes of the same
    /// cluster and enumerating them would be cumbersome or error-prone (e.g.
    /// commissioning-window transitions, cluster-wide resets).
    ///
    /// Subscriptions whose interest paths intersect `(endpoint_id, cluster_id)`
    /// at any attribute will be re-reported.
    fn notify_cluster_changed(&self, endpoint_id: EndptId, cluster_id: ClusterId);

    /// Notify that every attribute on every cluster of the given endpoint may
    /// have changed.
    ///
    /// Typically used when the endpoint's composition changes (dynamic
    /// endpoints being enabled/disabled, bridge device add/remove, etc.).
    fn notify_endpoint_changed(&self, endpoint_id: EndptId);

    /// Notify that every attribute on every cluster on every endpoint may
    /// have changed.
    ///
    /// This is the coarsest possible notification and should be used sparingly
    /// (e.g. global resets, factory reset, etc.). Every active subscription
    /// will be flagged for re-report.
    fn notify_all_changed(&self);
}

impl<T> AttrChangeNotifier for &T
where
    T: AttrChangeNotifier,
{
    fn notify_attr_changed(&self, endpoint_id: EndptId, cluster_id: ClusterId, attr_id: AttrId) {
        (**self).notify_attr_changed(endpoint_id, cluster_id, attr_id)
    }

    fn notify_cluster_changed(&self, endpoint_id: EndptId, cluster_id: ClusterId) {
        (**self).notify_cluster_changed(endpoint_id, cluster_id)
    }

    fn notify_endpoint_changed(&self, endpoint_id: EndptId) {
        (**self).notify_endpoint_changed(endpoint_id)
    }

    fn notify_all_changed(&self) {
        (**self).notify_all_changed()
    }
}

impl AttrChangeNotifier for () {
    fn notify_attr_changed(&self, _endpt: EndptId, _clust: ClusterId, _attr: AttrId) {
        // No-op
    }

    fn notify_cluster_changed(&self, _endpt: EndptId, _clust: ClusterId) {
        // No-op
    }

    fn notify_endpoint_changed(&self, _endpt: EndptId) {
        // No-op
    }

    fn notify_all_changed(&self) {
        // No-op
    }
}

/// A trait for notifying the data model that the state of an attribute has changed.
/// Typically implemented on types that have a notion of a "current" endpoint and a "current" cluster, so that the caller doesn't have to specify them again.
pub trait OwnAttrChangeNotifier {
    /// Notify that the state of an attribute has changed.
    ///
    /// # Arguments
    /// - `attr_id`: The attribute ID of the attribute that has changed.
    fn notify_own_attr_changed(&self, attr_id: AttrId);

    /// Notify that every attribute of our own cluster may have changed.
    ///
    /// Use this when a single operation mutates many attributes of the same
    /// cluster and enumerating them would be cumbersome or error-prone (e.g.
    /// commissioning-window transitions, cluster-wide resets).
    ///
    /// Subscriptions whose interest paths intersect `(endpoint_id, cluster_id)`
    /// at any attribute will be re-reported.
    fn notify_own_cluster_changed(&self);

    /// Notify that every attribute on every cluster of our own endpoint may
    /// have changed.
    ///
    /// Typically used when the endpoint's composition changes (dynamic
    /// endpoints being enabled/disabled, bridge device add/remove, etc.).
    fn notify_own_endpoint_changed(&self);
}

impl<T> OwnAttrChangeNotifier for &T
where
    T: OwnAttrChangeNotifier,
{
    fn notify_own_attr_changed(&self, attr_id: AttrId) {
        (**self).notify_own_attr_changed(attr_id)
    }

    fn notify_own_cluster_changed(&self) {
        (**self).notify_own_cluster_changed()
    }

    fn notify_own_endpoint_changed(&self) {
        (**self).notify_own_endpoint_changed()
    }
}

/// A trait for emitting events.
pub trait EventEmitter {
    /// Emit an event.
    ///
    /// # Arguments
    /// - `endpoint_id`: The endpoint ID of the cluster that emits the event.
    /// - `cluster_id`: The cluster ID of the cluster that emits the event.
    /// - `event_id`: The event ID of the event being emitted.
    /// - `priority`: The priority of the event.
    /// - `f`: A closure that takes an `EventTLVWrite` and writes the event data into it using TLV encoding.
    ///
    /// # Returns
    /// - `Ok(EventNumber)`: The sequence number of the emitted event, if the event was successfully emitted.
    /// - `Err(Error)`: An error if the event could not be emitted.
    fn emit_event<F>(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        event_id: EventId,
        priority: EventPriority,
        f: F,
    ) -> Result<EventNumber, Error>
    where
        F: FnOnce(EventTLVWrite<'_>) -> Result<(), Error>;

    /// Emit an event whose data is a single unsigned integer field, with context tag 0.
    ///
    /// Same as `emit_event` with such data, but not generic, so that an implementation
    /// can share one copy of its events queue code among all such events.
    fn emit_u32_event(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        event_id: EventId,
        priority: EventPriority,
        value: u32,
    ) -> Result<EventNumber, Error> {
        self.emit_event(endpoint_id, cluster_id, event_id, priority, |mut tw| {
            tw.start_struct(&EVENT_DATA_TAG)?;
            tw.u32(&TLVTag::Context(0), value)?;
            tw.end_container()
        })
    }
}

impl<T> EventEmitter for &T
where
    T: EventEmitter,
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
        (**self).emit_event(endpoint_id, cluster_id, event_id, priority, f)
    }

    fn emit_u32_event(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        event_id: EventId,
        priority: EventPriority,
        value: u32,
    ) -> Result<EventNumber, Error> {
        (**self).emit_u32_event(endpoint_id, cluster_id, event_id, priority, value)
    }
}

/// A trait for emitting events typically implemented on types that have a notion of a "current" endpoint and a "current" cluster.
pub trait OwnEventEmitter {
    /// Emit an event with the same endpoint ID and cluster ID as the current operation.
    ///
    /// This is a convenience method that calls `emit_event` with the endpoint ID and cluster ID of the current operation, so that the caller doesn't have to specify them again.
    ///
    /// # Arguments
    /// - `event_id`: The event ID of the event being emitted.
    /// - `priority`: The priority of the event.
    /// - `f`: A closure that takes an `EventTLVWrite` and writes the event data into it using TLV encoding.
    ///
    /// # Returns
    /// - `Ok(EventNumber)`: The sequence number of the emitted event, if the event was successfully emitted.
    /// - `Err(Error)`: An error if the event could not be emitted.
    fn emit_own_event<F>(
        &self,
        event_id: EventId,
        priority: EventPriority,
        f: F,
    ) -> Result<EventNumber, Error>
    where
        F: FnOnce(EventTLVWrite<'_>) -> Result<(), Error>;
}

impl<T> OwnEventEmitter for &T
where
    T: OwnEventEmitter,
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
        (**self).emit_own_event(event_id, priority, f)
    }
}

/// A context super-type that is also passed to the `(Async)Handler::run` method.
///
/// It provides access to the Matter instance and to Data Model-related objects,
/// which could be useful in the context of executing background tasks specific for the concrete handler.
pub trait HandlerContext: AttrChangeNotifier + EventEmitter + MaybeSendSync {
    /// Return the current UTC time of the node.
    fn utc_time(&self) -> UtcTime;

    /// Return the crypto object that is associated with this operation.
    fn crypto(&self) -> impl Crypto + '_;

    /// Return a blob store that can be used to persist data across reboots.
    fn kv(&self) -> impl KvBlobStoreAccess + '_;

    /// Return the metadata of the node that is associated with this handler.
    fn metadata(&self) -> impl Metadata + '_;

    /// Return the global handler that this handler is part of.
    ///
    /// Useful in case a concrete cluster handler (say, the Scenes one) needs to
    /// access the global handler so as to invoke read/write/invoke operations on other clusters.
    fn handler(&self) -> impl AsyncHandler + '_;

    /// Return the buffer pool of the Data Model.
    ///
    /// Useful in case e.g. a concrete cluster handler needs to invoke read/write/invoke operations on
    /// other clusters, and the TLV input/output data for those operations is non-trivial in size.
    fn buffers(&self) -> impl Buffers<IMBuffer> + '_;

    /// Return the Interaction Model statistics of the node.
    ///
    /// Lets a handler read IM-internal figures it cannot otherwise reach - the
    /// General Diagnostics handler uses it for `DeviceLoadStatus`.
    fn im_stats(&self) -> impl ImStats + '_;

    /// Notify that the fabric with the given local index has been removed
    /// from the fabric table, by synchronously broadcasting
    /// [`LifecycleOp::FabricRemoval`] to every handler in the data model.
    ///
    /// Two caveats for callers:
    /// - The broadcast runs the handlers' `lifecycle` methods inline, so this
    ///   must NOT be called while holding the Matter state lock (i.e. from
    ///   within a `with_state` closure) - handlers are free to access the
    ///   Matter instance themselves.
    /// - For the same reason, a handler must not call this from its own
    ///   `lifecycle` implementation (infinite recursion).
    fn notify_fabric_removed(&self, fab_idx: NonZeroU8);

    /// Broadcast a lifecycle operation to every handler in the data model.
    ///
    /// The same caveats as for `notify_fabric_removed` apply.
    fn broadcast_lifecycle(&self, op: LifecycleOp) -> Result<(), Error>;
}

impl<T> HandlerContext for &T
where
    T: HandlerContext,
{
    fn utc_time(&self) -> UtcTime {
        (**self).utc_time()
    }

    fn crypto(&self) -> impl Crypto + '_ {
        (**self).crypto()
    }

    fn kv(&self) -> impl KvBlobStoreAccess + '_ {
        (**self).kv()
    }

    fn metadata(&self) -> impl Metadata + '_ {
        (**self).metadata()
    }

    fn handler(&self) -> impl AsyncHandler + '_ {
        (**self).handler()
    }

    fn buffers(&self) -> impl Buffers<IMBuffer> + '_ {
        (**self).buffers()
    }

    fn im_stats(&self) -> impl ImStats + '_ {
        (**self).im_stats()
    }

    fn notify_fabric_removed(&self, fab_idx: NonZeroU8) {
        (**self).notify_fabric_removed(fab_idx);
    }

    fn broadcast_lifecycle(&self, op: LifecycleOp) -> Result<(), Error> {
        (**self).broadcast_lifecycle(op)
    }
}

/// A context super-type that is passed to the handler when bumping a dataver
pub trait MatchContext: MaybeSendSync {
    /// Return the endpoint ID that is associated with context.
    /// `None` if the context is not associated with a specific endpoint (e.g. a global handler's dataver bump).
    fn endpt(&self) -> Option<EndptId>;

    /// Return the cluster ID that is associated with this operation.
    /// `None` if the context is not associated with a specific cluster (e.g. a global handler's dataver bump).
    fn cluster(&self) -> Option<ClusterId>;
}

impl<T> MatchContext for &T
where
    T: MatchContext,
{
    fn endpt(&self) -> Option<EndptId> {
        (**self).endpt()
    }

    fn cluster(&self) -> Option<ClusterId> {
        (**self).cluster()
    }
}

/// A concrete implementation of the `MatchContext` trait
pub struct MatchContextInstance {
    endpt: Option<EndptId>,
    cluster: Option<ClusterId>,
}

impl MatchContextInstance {
    pub const fn new(endpt: Option<EndptId>, cluster: Option<ClusterId>) -> Self {
        Self { endpt, cluster }
    }
}

impl MatchContext for MatchContextInstance {
    fn endpt(&self) -> Option<EndptId> {
        self.endpt
    }

    fn cluster(&self) -> Option<ClusterId> {
        self.cluster
    }
}

/// A context super-type that is passed to the handler when processing an attribute read/write or a command invoke operation.
pub trait OperationContext:
    MatchContext + HandlerContext + OwnAttrChangeNotifier + OwnEventEmitter
{
    /// Return the ID of the transaction this operation arrived on.
    fn transaction_id(&self) -> TransactionId;
}

impl<T> OperationContext for &T
where
    T: OperationContext,
{
    fn transaction_id(&self) -> TransactionId {
        (**self).transaction_id()
    }
}

/// A context type that is passed to the handler when processing an attribute Read operation.
pub trait ReadContext: OperationContext {
    /// Return the attribute object that is associated with this read operation.
    fn attr(&self) -> &AttrDetails;
}

impl<T> ReadContext for &T
where
    T: ReadContext,
{
    fn attr(&self) -> &AttrDetails {
        (**self).attr()
    }
}

/// A context type that is passed to the handler when processing an attribute Write operation.
pub trait WriteContext: OperationContext {
    /// Return the attribute object that is associated with this write operation.
    fn attr(&self) -> &AttrDetails;

    /// Return the attribute data that is associated with this write operation.
    fn data(&self) -> &TLVElement<'_>;

    /// Notify that the state of the attribute whose write operation is processed has changed.
    fn notify_changed(&self) {
        self.notify_attr_changed(
            self.attr().endpoint_id,
            self.attr().cluster_id,
            self.attr().attr_id,
        );
    }
}

impl<T> WriteContext for &T
where
    T: WriteContext,
{
    fn attr(&self) -> &AttrDetails {
        (**self).attr()
    }

    fn data(&self) -> &TLVElement<'_> {
        (**self).data()
    }

    fn notify_changed(&self) {
        (**self).notify_changed()
    }
}

pub trait InvokeContext: OperationContext {
    /// Return the command object that is associated with this invoke operation.
    fn cmd(&self) -> &CmdDetails;

    /// Return the command data that is associated with this invoke operation.
    fn data(&self) -> &TLVElement<'_>;
}

impl<T> InvokeContext for &T
where
    T: InvokeContext,
{
    fn cmd(&self) -> &CmdDetails {
        (**self).cmd()
    }

    fn data(&self) -> &TLVElement<'_> {
        (**self).data()
    }
}

pub trait DataModel: Metadata + AsyncHandler {
    /// Bump the dataver of every cluster on the endpoint `endpoint_id` - as listed
    /// in the node metadata - by invoking `bump_dataver` once per cluster, with a
    /// fully-specified (endpoint, cluster) context.
    ///
    /// Matchers are functions of both IDs, so a single bump with the cluster left out
    /// could not be routed to just this endpoint's handlers.
    ///
    /// The metadata is not held while the handlers are invoked.
    fn bump_endpoint_dataver(&self, endpoint_id: EndptId) {
        let mut index = 0;

        while let Some(cluster_id) = self.access(|node| {
            node.endpoints
                .iter()
                .find(|endpoint| endpoint.id == endpoint_id)
                .and_then(|endpoint| endpoint.clusters.get(index))
                .map(|cluster| cluster.id)
        }) {
            self.bump_dataver(MatchContextInstance::new(
                Some(endpoint_id),
                Some(cluster_id),
            ));

            index += 1;
        }
    }
}

impl<T> DataModel for T where T: Metadata + AsyncHandler {}

/// A lifecycle operation delivered to a handler via [`Handler::lifecycle`] /
/// [`AsyncHandler::lifecycle`].
///
/// Unlike read/write/invoke - which are routed to the single handler matching the
/// operation path - lifecycle operations are broadcast to every handler in the
/// handler chain.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LifecycleOp {
    /// The node is starting up.
    ///
    /// Delivered once, after the Data Model is constructed and before it starts
    /// serving operations.
    ///
    /// The typical reaction is to populate the handler's in-memory state from
    /// persisted storage ([`HandlerContext::kv`]) - the mirror image of the
    /// on-the-fly persistence the handler does while serving operations.
    Startup,
    /// The node is being factory-reset.
    ///
    /// The typical reaction is to reset the handler's in-memory state to factory
    /// defaults and remove the handler's persisted data from [`HandlerContext::kv`].
    FactoryReset,
    /// The fabric with the given local index has been removed from the node.
    ///
    /// Delivered synchronously (via [`HandlerContext::notify_fabric_removed`])
    /// right after the fabric is gone from the fabric table - via the
    /// `RemoveFabric` command, an `AddNOC` rollback, or a fail-safe expiry
    /// that did not resurrect a persisted (pre-`UpdateNOC`) copy of the
    /// fabric. NOT delivered when a fail-safe expiry reverts an in-progress
    /// `UpdateNOC` - the fabric is still commissioned in that case.
    ///
    /// The typical reaction is to drop the removed fabric's entries from any
    /// fabric-scoped state the handler owns *outside* the fabric table (a
    /// bindings registry, a scene table, provider lists, ...) and re-persist.
    /// State stored inside the `Fabric` object itself (ACLs, group keys)
    /// needs no reaction - it is dropped with the fabric.
    ///
    /// Like every lifecycle operation this is a broadcast, so multiple
    /// handler instances borrowing one shared registry each receive it -
    /// reactions must be idempotent (a `retain`-style purge naturally is).
    FabricRemoval {
        /// The local index the removed fabric had
        fab_idx: NonZeroU8,
    },
    /// The armed fail-safe has been committed by a successful
    /// `CommissioningComplete`, whatever the fail-safe was armed for.
    ///
    /// The typical reaction is to persist the state the handler staged while
    /// the fail-safe was armed. Delivered before the command responds.
    FailSafeCommit,
    /// The armed fail-safe has expired: it timed out, or `ArmFailSafe(0)` or
    /// `RevokeCommissioning` force-expired it.
    ///
    /// The typical reaction is to drop the state the handler staged while the
    /// fail-safe was armed, reloading the committed one from
    /// [`HandlerContext::kv`].
    FailSafeExpiry,
}

/// A version of the `AsyncHandler` trait that never awaits any operation.
///
/// Prefer this trait when implementing handlers that are known to be non-blocking and additionally,
/// mark those with `NonBlockingHandler`.
pub trait Handler: MaybeSendSync {
    /// Read from the requested attribute and encode the result using the provided reply type.
    fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error>;

    /// Write into the requested attribute using the provided data.
    fn write(&self, _ctx: impl WriteContext) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    /// Invoke the requested command with the provided data and encode the result using the provided reply type.
    fn invoke(&self, _ctx: impl InvokeContext, _reply: impl InvokeReply) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    /// Bump the per-cluster `Dataver` for the cluster handler matching
    /// the supplied context `endpoint_id` / `cluster_id`.
    fn bump_dataver(&self, ctx: impl MatchContext);

    /// Process a lifecycle operation ([`LifecycleOp`]).
    ///
    /// Unlike read/write/invoke - which are routed to the single handler matching the
    /// operation path - this method is invoked on every handler in the handler chain.
    ///
    /// The default implementation does nothing.
    fn lifecycle(&self, _ctx: impl HandlerContext, _op: LifecycleOp) -> Result<(), Error> {
        Ok(())
    }

    /// A hook (a scheduling facility) for placing handler-impl-specific code that needs to run
    /// asynchronously - forever and in the "background".
    fn run(
        &self,
        _ctx: impl HandlerContext,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        // Default implementation pends forever.
        // This is useful for handlers that do not need to run any async operations in the background.
        core::future::pending::<Result<(), Error>>()
    }
}

impl<T> Handler for &T
where
    T: Handler,
{
    fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error> {
        (**self).read(ctx, reply)
    }

    fn write(&self, ctx: impl WriteContext) -> Result<(), Error> {
        (**self).write(ctx)
    }

    fn invoke(&self, ctx: impl InvokeContext, reply: impl InvokeReply) -> Result<(), Error> {
        (**self).invoke(ctx, reply)
    }

    fn bump_dataver(&self, ctx: impl MatchContext) {
        (**self).bump_dataver(ctx)
    }

    fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        (**self).lifecycle(ctx, op)
    }

    fn run(&self, ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>> {
        (**self).run(ctx)
    }
}

impl<T> Handler for &mut T
where
    T: Handler,
{
    fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error> {
        (**self).read(ctx, reply)
    }

    fn write(&self, ctx: impl WriteContext) -> Result<(), Error> {
        (**self).write(ctx)
    }

    fn invoke(&self, ctx: impl InvokeContext, reply: impl InvokeReply) -> Result<(), Error> {
        (**self).invoke(ctx, reply)
    }

    fn bump_dataver(&self, ctx: impl MatchContext) {
        (**self).bump_dataver(ctx)
    }

    fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        (**self).lifecycle(ctx, op)
    }

    fn run(&self, ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>> {
        (**self).run(ctx)
    }
}

/// A marker trait that indicates that the handler is non-blocking.
// TODO: Re-assess the need for this trait.
pub trait NonBlockingHandler: Handler {}

impl<T> NonBlockingHandler for &T where T: NonBlockingHandler {}

impl<T> NonBlockingHandler for &mut T where T: NonBlockingHandler {}

impl<M, H> Handler for (M, H)
where
    M: MaybeSendSync,
    H: Handler,
{
    fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error> {
        self.1.read(ctx, reply)
    }

    fn write(&self, ctx: impl WriteContext) -> Result<(), Error> {
        self.1.write(ctx)
    }

    fn invoke(&self, ctx: impl InvokeContext, reply: impl InvokeReply) -> Result<(), Error> {
        self.1.invoke(ctx, reply)
    }

    fn bump_dataver(&self, ctx: impl MatchContext) {
        self.1.bump_dataver(ctx)
    }

    fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        self.1.lifecycle(ctx, op)
    }

    fn run(&self, ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>> {
        self.1.run(ctx)
    }
}

impl<M, H> NonBlockingHandler for (M, H)
where
    M: MaybeSendSync,
    H: NonBlockingHandler,
{
}

/// A trait that defines a matcher for determining whether a handler - member of a handler-chain (`ChainedHandler`)
/// should be invoked for a specific operation.
pub trait Matcher: MaybeSendSync {
    /// Return `true` if the corresponding handler should be invoked for the provided context.
    fn matches(&self, ctx: impl MatchContext) -> bool;
}

/// The default matcher: a plain function of the endpoint ID and the cluster ID of the operation.
///
/// A function pointer rather than a closure type, so that handler chains built with it are
/// nameable (see `handler_chain_type!`). Non-capturing closures coerce to it, and constants
/// (endpoint IDs, `CLUSTER.id`) are not captures:
///
/// ```ignore
/// EmptyHandler.chain(|e, c| e == LIGHT_ENDPOINT_ID && c == OnOffHandler::CLUSTER.id, handler)
/// ```
///
/// A closure that does capture (e.g. an endpoint ID computed at runtime) is a `Matcher` too,
/// via `ChainedHandler::new_with_matcher`; the resulting chain is just not nameable.
pub type FnMatcher = fn(EndptId, ClusterId) -> bool;

impl<F> Matcher for F
where
    F: Fn(EndptId, ClusterId) -> bool + MaybeSendSync,
{
    fn matches(&self, ctx: impl MatchContext) -> bool {
        // A matcher is a function of both IDs, so a context that lacks one cannot be
        // routed by it and is let through as a global one. The Interaction Model only
        // ever produces a fully-specified context or a fully-unspecified one: an
        // endpoint-scoped dataver bump is expanded to one bump per cluster of that
        // endpoint (see `DataModel::bump_endpoint_dataver`) rather than sent with the cluster
        // left out, as the latter would reach every handler on every endpoint.
        let (Some(endpt_id), Some(cluster_id)) = (ctx.endpt(), ctx.cluster()) else {
            return true;
        };

        self(endpt_id, cluster_id)
    }
}

/// A handler that always fails with attribute / command not found.
///
/// Useful when chaining multiple handlers together as the end of the chain.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EmptyHandler;

impl EmptyHandler {
    /// Chain the empty handler with another handler thus providing an "end of handler chain"
    /// fallback that errors out.
    ///
    /// The returned chained handler works as follows:
    /// - It will call the provided `handler` instance if the provided matcher returns `true`
    ///   for the `ReadContext`/`WriteContext`/`InvokeContext` of the incoming operation
    /// - Otherwise, the empty handler would be invoked, causing the operation to error out.
    ///
    /// Arguments:
    /// - `matcher`: A matcher that determines whether the handler should be invoked for the incoming operation.
    /// - `handler`: The handler to be invoked if the matcher returns `true`.
    pub const fn chain<H>(
        self,
        matcher: FnMatcher,
        handler: H,
    ) -> ChainedHandler<FnMatcher, H, Self> {
        ChainedHandler {
            matcher,
            handler,
            next: self,
        }
    }
}

impl Handler for EmptyHandler {
    fn read(&self, _ctx: impl ReadContext, _reply: impl ReadReply) -> Result<(), Error> {
        // The empty handler sits at the end of every `ChainedHandler`
        // chain; reaching it means no matcher in the chain claimed
        // the requested `(endpoint, cluster)`. That can happen either
        // because the handler genuinely doesn't service the endpoint,
        // or because the handler shape changed between path expansion
        // (under the metadata lock) and dispatch (lock released). In
        // both cases the safest, most informative IM status is
        // `UnsupportedEndpoint`.
        Err(ErrorCode::EndpointNotFound.into())
    }

    fn write(&self, _ctx: impl WriteContext) -> Result<(), Error> {
        Err(ErrorCode::EndpointNotFound.into())
    }

    fn invoke(&self, _ctx: impl InvokeContext, _reply: impl InvokeReply) -> Result<(), Error> {
        Err(ErrorCode::EndpointNotFound.into())
    }

    fn bump_dataver(&self, _ctx: impl MatchContext) {
        // No-op since this handler doesn't actually handle any cluster.
    }
}

impl NonBlockingHandler for EmptyHandler {}

/// A handler that chains two handlers together in a composite handler.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChainedHandler<M, H, T> {
    /// The matcher that determines whether the handler should be invoked for the incoming operation.
    pub matcher: M,
    /// The handler to be invoked if the matcher returns `true`.
    pub handler: H,
    /// The next handler to be invoked if the matcher returns `false`.
    pub next: T,
}

impl<H, T> ChainedHandler<FnMatcher, H, T> {
    /// Construct a chained handler with the default `FnMatcher` matcher that works as follows:
    /// - It will call the provided `handler` instance if the provided matcher returns `true`
    ///   for the `ReadContext`/`WriteContext`/`InvokeContext` of the incoming operation
    /// - Otherwise, it will call the `next` handler
    ///
    /// Arguments:
    /// - `matcher`: A matcher that determines whether the handler should be invoked for the incoming operation.
    /// - `handler`: The handler to be invoked if the matcher returns `true`.
    /// - `next`: The next handler to be invoked if the matcher returns `false`.
    pub const fn new(matcher: FnMatcher, handler: H, next: T) -> Self {
        Self::new_with_matcher(matcher, handler, next)
    }
}

impl<M, H, T> ChainedHandler<M, H, T> {
    /// Construct a chained handler with a custom matcher that works as follows:
    /// - It will call the provided `handler` instance if the provided matcher returns `true`
    ///   for the `ReadContext`/`WriteContext`/`InvokeContext` of the incoming operation
    /// - Otherwise, it will call the `next` handler
    ///
    /// Arguments:
    /// - `matcher`: A matcher that determines whether the handler should be invoked for the incoming operation.
    /// - `handler`: The handler to be invoked if the matcher returns `true`.
    /// - `next`: The next handler to be invoked if the matcher returns `false`.
    pub const fn new_with_matcher(matcher: M, handler: H, next: T) -> Self {
        Self {
            matcher,
            handler,
            next,
        }
    }

    /// Chain itself with another handler.
    ///
    /// The returned chained handler works as follows:
    /// - It will call the provided `handler` instance if the provided matcher returns `true`
    ///   for the `ReadContext`/`WriteContext`/`InvokeContext` of the incoming operation
    /// - Otherwise, it will call the `self` handler
    ///
    /// Arguments:
    /// - `matcher`: A matcher that determines whether the handler should be invoked for the incoming operation.
    /// - `handler`: The handler to be invoked if the matcher returns `true`.
    pub const fn chain<H2>(
        self,
        matcher: FnMatcher,
        handler: H2,
    ) -> ChainedHandler<FnMatcher, H2, Self> {
        ChainedHandler::new(matcher, handler, self)
    }
}

impl<M, H, T> Handler for ChainedHandler<M, H, T>
where
    M: Matcher,
    H: Handler,
    T: Handler,
{
    fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error> {
        if self.matcher.matches(&ctx) {
            self.handler.read(ctx, reply)
        } else {
            self.next.read(ctx, reply)
        }
    }

    fn write(&self, ctx: impl WriteContext) -> Result<(), Error> {
        if self.matcher.matches(&ctx) {
            self.handler.write(ctx)
        } else {
            self.next.write(ctx)
        }
    }

    fn invoke(&self, ctx: impl InvokeContext, reply: impl InvokeReply) -> Result<(), Error> {
        if self.matcher.matches(&ctx) {
            self.handler.invoke(ctx, reply)
        } else {
            self.next.invoke(ctx, reply)
        }
    }

    fn bump_dataver(&self, ctx: impl MatchContext) {
        if self.matcher.matches(&ctx) {
            self.handler.bump_dataver(&ctx)
        }

        // Fall-through to the next handler in the chain since multiple handlers might need to bump dataver for the same operation
        self.next.bump_dataver(ctx)
    }

    fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        // Lifecycle ops are a broadcast: every handler in the chain gets them,
        // regardless of the matcher, and even if one fails (the first error wins)
        let result = self.handler.lifecycle(&ctx, op);

        result.and(self.next.lifecycle(ctx, op))
    }

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        let mut handler = pin!(self.handler.run(&ctx));
        let mut next = pin!(self.next.run(&ctx));

        select(&mut handler, &mut next).coalesce().await
    }
}

impl<M, H, T> NonBlockingHandler for ChainedHandler<M, H, T>
where
    M: Matcher,
    H: NonBlockingHandler,
    T: NonBlockingHandler,
{
}

/// A helper macro that makes it easier to specify the full type of a `ChainedHandler` instantiation,
/// which can be quite annoying in the case of long chains of handlers.
///
/// Use with type aliases:
/// ```ignore
/// pub type RootEndpointHandler<'a> = handler_chain_type!(
///     FnMatcher => DescriptorCluster<'static>,
///     FnMatcher => BasicInfoCluster<'a>,
///     FnMatcher => GenCommCluster<'a>,
///     FnMatcher => NwCommCluster,
///     FnMatcher => AdminCommCluster<'a>,
///     FnMatcher => NocCluster<'a>,
///     FnMatcher => AccessControlCluster<'a>,
///     FnMatcher => GenDiagCluster,
///     FnMatcher => EthNwDiagCluster,
///     FnMatcher => GrpKeyMgmtCluster
/// );
/// ```
#[allow(unused_macros)]
#[macro_export]
macro_rules! handler_chain_type {
    ($m:ty => $h:ty) => {
        $crate::ChainedHandler<$m, $h, $crate::EmptyHandler>
    };
    ($m1:ty => $h1:ty, $($m:ty => $h:ty),+) => {
        $crate::ChainedHandler<$m1, $h1, handler_chain_type!($($m => $h),+)>
    };
    ($m:ty => $h:ty | $f:ty) => {
        $crate::ChainedHandler<$m, $h, $f>
    };
    ($m1:ty => $h1:ty, $($m:ty => $h:ty),+ | $f:ty) => {
        $crate::ChainedHandler<$m1, $h1, handler_chain_type!($($m => $h),+ | $f)>
    };
}

mod asynch {
    use core::future::{ready, Future};
    use core::pin::pin;

    use either::Either;

    use crate::error::{Error, ErrorCode};
    use crate::utils::futures::{select, Coalesce};
    use crate::{HandlerContext, InvokeReply, MatchContext, Matcher, ReadReply};

    use crate::utils::sync::{MaybeSend, MaybeSendSync};

    use super::{
        ChainedHandler, EmptyHandler, Handler, InvokeContext, LifecycleOp, NonBlockingHandler,
        ReadContext, WriteContext,
    };

    /// A handler for processing a single IM operation:
    /// read an attribute, write an attribute, or invoke a command.
    ///
    /// Handlers are typically implemented by user-defined clusters, but there is no 1:1 correspondence between
    /// a handler and a cluster, as a single handler can handle multiple clusters and even multiple endpoints.
    ///
    /// Moreover, the `InteractionModel` implementation expects a single `AsyncHandler` instance, so the expectation
    /// is that the user will compose multiple handlers into a single `AsyncHandler` instance, using `ChainedHandler`
    /// or other means.
    pub trait AsyncHandler: MaybeSendSync {
        /// Read from the requested attribute and encode the result using the provided reply type.
        fn read(
            &self,
            ctx: impl ReadContext,
            reply: impl ReadReply,
        ) -> impl Future<Output = Result<(), Error>> + MaybeSend;

        /// Write into the requested attribute using the provided data.
        ///
        /// The default implementation errors out with `ErrorCode::AttributeNotFound`.
        fn write(
            &self,
            _ctx: impl WriteContext,
        ) -> impl Future<Output = Result<(), Error>> + MaybeSend {
            core::future::ready(Err(ErrorCode::AttributeNotFound.into()))
        }

        /// Invoke the requested command with the provided data and encode the result using the provided reply type.
        ///
        /// The default implementation errors out with `ErrorCode::CommandNotFound`.
        fn invoke(
            &self,
            _ctx: impl InvokeContext,
            _reply: impl InvokeReply,
        ) -> impl Future<Output = Result<(), Error>> + MaybeSend {
            core::future::ready(Err(ErrorCode::CommandNotFound.into()))
        }

        /// Bump the per-cluster `Dataver` for the cluster handler matching
        /// the supplied context `endpoint_id` / `cluster_id`.
        fn bump_dataver(&self, ctx: impl MatchContext);

        /// Process a lifecycle operation ([`LifecycleOp`]).
        ///
        /// Unlike read/write/invoke - which are routed to the single handler matching the
        /// operation path - this method is invoked on every handler in the handler chain.
        ///
        /// Deliberately synchronous - like [`AsyncHandler::bump_dataver`] -
        /// even on the async handler trait, so that lifecycle broadcasts can
        /// be dispatched eagerly from synchronous call sites (see
        /// [`HandlerContext::notify_fabric_removed`]).
        ///
        /// The default implementation does nothing.
        fn lifecycle(&self, _ctx: impl HandlerContext, _op: LifecycleOp) -> Result<(), Error> {
            Ok(())
        }

        /// A hook (a scheduling facility) for placing handler-impl-specific code that needs to run
        /// asynchronously - forever and in the "background".
        fn run(
            &self,
            _ctx: impl HandlerContext,
        ) -> impl Future<Output = Result<(), Error>> + MaybeSend {
            // Default implementation pends forever.
            // This is useful for handlers that do not need to run any async operations in the background.
            core::future::pending::<Result<(), Error>>()
        }
    }

    impl<T> AsyncHandler for &mut T
    where
        T: AsyncHandler,
    {
        fn read(
            &self,
            ctx: impl ReadContext,
            reply: impl ReadReply,
        ) -> impl Future<Output = Result<(), Error>> {
            (**self).read(ctx, reply)
        }

        fn write(&self, ctx: impl WriteContext) -> impl Future<Output = Result<(), Error>> {
            (**self).write(ctx)
        }

        fn invoke(
            &self,
            ctx: impl InvokeContext,
            reply: impl InvokeReply,
        ) -> impl Future<Output = Result<(), Error>> {
            (**self).invoke(ctx, reply)
        }

        fn bump_dataver(&self, ctx: impl MatchContext) {
            (**self).bump_dataver(ctx)
        }

        fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
            (**self).lifecycle(ctx, op)
        }

        fn run(&self, ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>> {
            (**self).run(ctx)
        }
    }

    impl<T> AsyncHandler for &T
    where
        T: AsyncHandler,
    {
        fn read(
            &self,
            ctx: impl ReadContext,
            reply: impl ReadReply,
        ) -> impl Future<Output = Result<(), Error>> {
            (**self).read(ctx, reply)
        }

        fn write(&self, ctx: impl WriteContext) -> impl Future<Output = Result<(), Error>> {
            (**self).write(ctx)
        }

        fn invoke(
            &self,
            ctx: impl InvokeContext,
            reply: impl InvokeReply,
        ) -> impl Future<Output = Result<(), Error>> {
            (**self).invoke(ctx, reply)
        }

        fn bump_dataver(&self, ctx: impl MatchContext) {
            (**self).bump_dataver(ctx)
        }

        fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
            (**self).lifecycle(ctx, op)
        }

        fn run(&self, ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>> {
            (**self).run(ctx)
        }
    }

    impl<M, H> AsyncHandler for (M, H)
    where
        M: MaybeSendSync,
        H: AsyncHandler,
    {
        fn read(
            &self,
            ctx: impl ReadContext,
            reply: impl ReadReply,
        ) -> impl Future<Output = Result<(), Error>> {
            self.1.read(ctx, reply)
        }

        fn write(&self, ctx: impl WriteContext) -> impl Future<Output = Result<(), Error>> {
            self.1.write(ctx)
        }

        fn invoke(
            &self,
            ctx: impl InvokeContext,
            reply: impl InvokeReply,
        ) -> impl Future<Output = Result<(), Error>> {
            self.1.invoke(ctx, reply)
        }

        fn bump_dataver(&self, ctx: impl MatchContext) {
            self.1.bump_dataver(ctx)
        }

        fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
            self.1.lifecycle(ctx, op)
        }

        fn run(&self, ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>> {
            self.1.run(ctx)
        }
    }

    impl<T> AsyncHandler for Async<T>
    where
        T: NonBlockingHandler,
    {
        fn read(
            &self,
            ctx: impl ReadContext,
            reply: impl ReadReply,
        ) -> impl Future<Output = Result<(), Error>> {
            ready(Handler::read(&self.0, ctx, reply))
        }

        fn write(&self, ctx: impl WriteContext) -> impl Future<Output = Result<(), Error>> {
            ready(Handler::write(&self.0, ctx))
        }

        fn invoke(
            &self,
            ctx: impl InvokeContext,
            reply: impl InvokeReply,
        ) -> impl Future<Output = Result<(), Error>> {
            ready(Handler::invoke(&self.0, ctx, reply))
        }

        fn bump_dataver(&self, ctx: impl MatchContext) {
            Handler::bump_dataver(&self.0, ctx)
        }

        fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
            Handler::lifecycle(&self.0, ctx, op)
        }

        fn run(&self, ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>> {
            Handler::run(&self.0, ctx)
        }
    }

    impl AsyncHandler for EmptyHandler {
        fn read(
            &self,
            _ctx: impl ReadContext,
            _reply: impl ReadReply,
        ) -> impl Future<Output = Result<(), Error>> {
            // See the blocking-`Handler` impl for the rationale on
            // returning `EndpointNotFound` rather than
            // `AttributeNotFound` here.
            core::future::ready(Err(ErrorCode::EndpointNotFound.into()))
        }

        fn write(&self, _ctx: impl WriteContext) -> impl Future<Output = Result<(), Error>> {
            core::future::ready(Err(ErrorCode::EndpointNotFound.into()))
        }

        fn invoke(
            &self,
            _ctx: impl InvokeContext,
            _reply: impl InvokeReply,
        ) -> impl Future<Output = Result<(), Error>> {
            core::future::ready(Err(ErrorCode::EndpointNotFound.into()))
        }

        fn bump_dataver(&self, _ctx: impl MatchContext) {
            // No-op since this handler doesn't actually handle any cluster.
        }
    }

    impl<M, H, T> AsyncHandler for ChainedHandler<M, H, T>
    where
        M: Matcher,
        H: AsyncHandler,
        T: AsyncHandler,
    {
        fn read(
            &self,
            ctx: impl ReadContext,
            reply: impl ReadReply,
        ) -> impl Future<Output = Result<(), Error>> {
            if self.matcher.matches(&ctx) {
                Either::Left(self.handler.read(ctx, reply))
            } else {
                Either::Right(self.next.read(ctx, reply))
            }
        }

        fn write(&self, ctx: impl WriteContext) -> impl Future<Output = Result<(), Error>> {
            if self.matcher.matches(&ctx) {
                Either::Left(self.handler.write(ctx))
            } else {
                Either::Right(self.next.write(ctx))
            }
        }

        fn invoke(
            &self,
            ctx: impl InvokeContext,
            reply: impl InvokeReply,
        ) -> impl Future<Output = Result<(), Error>> {
            if self.matcher.matches(&ctx) {
                Either::Left(self.handler.invoke(ctx, reply))
            } else {
                Either::Right(self.next.invoke(ctx, reply))
            }
        }

        fn bump_dataver(&self, ctx: impl MatchContext) {
            if self.matcher.matches(&ctx) {
                self.handler.bump_dataver(&ctx)
            }

            // Fall-through to the next handler in the chain since multiple handlers might need to bump dataver for the same operation
            self.next.bump_dataver(ctx)
        }

        fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
            // Lifecycle ops are a broadcast: every handler in the chain gets them,
            // regardless of the matcher, and even if one fails (the first error wins)
            let result = self.handler.lifecycle(&ctx, op);

            result.and(self.next.lifecycle(ctx, op))
        }

        async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
            let mut handler = pin!(self.handler.run(&ctx));
            let mut next = pin!(self.next.run(&ctx));

            select(&mut handler, &mut next).coalesce().await
        }
    }

    /// An adaptor that adapts a `NonBlockingHandler` trait implementation to the `AsyncHandler` trait contract.
    ///
    /// The adaptor also implements `NonBlockingHandler` so that the adapted handler can be used in any context.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Async<T>(pub T);

    impl<T> Handler for Async<T>
    where
        T: Handler,
    {
        fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error> {
            self.0.read(ctx, reply)
        }

        fn write(&self, ctx: impl WriteContext) -> Result<(), Error> {
            self.0.write(ctx)
        }

        fn invoke(&self, ctx: impl InvokeContext, reply: impl InvokeReply) -> Result<(), Error> {
            self.0.invoke(ctx, reply)
        }

        fn bump_dataver(&self, ctx: impl MatchContext) {
            self.0.bump_dataver(ctx)
        }

        fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
            self.0.lifecycle(ctx, op)
        }

        fn run(&self, ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>> {
            self.0.run(ctx)
        }
    }

    impl<T> NonBlockingHandler for Async<T> where T: NonBlockingHandler {}
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use core::cell::Cell;

    use crate::error::{Error, ErrorCode};
    use crate::{Async, Cluster, Endpoint, Node};

    use super::{
        DataModel, EmptyHandler, Handler, MatchContext, NonBlockingHandler, ReadContext, ReadReply,
    };

    /// A handler that only counts its dataver bumps.
    struct Counting(Cell<u32>);

    impl Handler for Counting {
        fn read(&self, _ctx: impl ReadContext, _reply: impl ReadReply) -> Result<(), Error> {
            Err(ErrorCode::AttributeNotFound.into())
        }

        fn bump_dataver(&self, _ctx: impl MatchContext) {
            self.0.set(self.0.get() + 1);
        }
    }

    impl NonBlockingHandler for Counting {}

    /// A cluster with no attributes, commands or events.
    const fn cluster(id: u32) -> Cluster<'static> {
        Cluster::new(
            id,
            1,
            0,
            &[],
            &[],
            &[],
            |_, _, _| true,
            |_, _, _| true,
            |_, _, _| true,
        )
    }

    /// The Descriptor and the Basic Information clusters.
    const DESC: Cluster<'static> = cluster(0x001D);
    const BASIC_INFO: Cluster<'static> = cluster(0x0028);

    const NODE: Node<'static> = Node {
        endpoints: &[
            Endpoint::new(0, &[], &[DESC, BASIC_INFO]),
            Endpoint::new(1, &[], &[DESC]),
        ],
    };

    #[test]
    fn endpoint_bump_reaches_only_the_clusters_of_that_endpoint() {
        let ep0_desc = Counting(Cell::new(0));
        let ep0_basic_info = Counting(Cell::new(0));
        let ep1_desc = Counting(Cell::new(0));

        let dm = (
            NODE,
            Async(
                EmptyHandler
                    .chain(|e, c| e == 0 && c == DESC.id, &ep0_desc)
                    .chain(|e, c| e == 0 && c == BASIC_INFO.id, &ep0_basic_info)
                    .chain(|e, c| e == 1 && c == DESC.id, &ep1_desc),
            ),
        );

        let counts = || (ep0_desc.0.get(), ep0_basic_info.0.get(), ep1_desc.0.get());

        dm.bump_endpoint_dataver(0);
        assert_eq!(counts(), (1, 1, 0));

        dm.bump_endpoint_dataver(1);
        assert_eq!(counts(), (1, 1, 1));

        // An endpoint that is not in the metadata bumps nothing
        dm.bump_endpoint_dataver(2);
        assert_eq!(counts(), (1, 1, 1));
    }
}
