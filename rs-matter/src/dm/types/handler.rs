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

use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use crate::dm::IMBuffer;
use crate::error::{Error, ErrorCode};
use crate::tlv::TLVElement;
use crate::transport::exchange::Exchange;
use crate::utils::storage::pooled::{BufferAccess, PooledBuffers};

use super::{AttrDetails, ClusterId, CmdDetails, EndptId, InvokeReply, ReadReply};

pub use asynch::*;

pub trait ChangeNotify {
    fn notify(&self, endpt: EndptId, clust: ClusterId);
}

impl<T> ChangeNotify for &T
where
    T: ChangeNotify,
{
    fn notify(&self, endpt: EndptId, clust: ClusterId) {
        (**self).notify(endpt, clust)
    }
}

impl ChangeNotify for () {
    fn notify(&self, _endpt: EndptId, _clust: ClusterId) {
        // No-op
    }
}

/// A context super-type that is passed to the handler when processing an attribute read/write or a command invoke operation.
pub trait Context {
    /// Return the exchange object that is associated with this operation.
    fn exchange(&self) -> &Exchange<'_>;

    /// Return the global handler that is associated with this operation.
    ///
    /// Useful in case a concrete cluster handler (say, the Scenes one) needs to
    /// access the global handler so as to invoke read/write/invoke operations on other clusters.
    fn handler(&self) -> impl AsyncHandler + '_;

    /// Return the buffer pool of the Data Model, in of the that are associated with this operation.
    ///
    /// Useful in case a concrete cluster handler needs to invoke read/write/invoke operations on
    /// other clusters, and the TLV input/output data for those operations is non-trivial in size.
    fn buffers(&self) -> impl BufferAccess<IMBuffer> + '_;

    /// Notify that the state of the cluster has changed.
    fn notify_changed(&self);

    /// Try to upcast the context to a read context.
    /// The operation will return `Some` only if the underlying context represents a read operation.
    fn as_read_ctx(&self) -> Option<impl ReadContext> {
        Option::<ReadContextInstance<EmptyHandler, PooledBuffers<0, NoopRawMutex, IMBuffer>>>::None
    }

    /// Try to upcast the context to a write context.
    /// The operation will return `Some` only if the underlying context represents a write operation.
    fn as_write_ctx(&self) -> Option<impl WriteContext> {
        Option::<WriteContextInstance<EmptyHandler, PooledBuffers<0, NoopRawMutex, IMBuffer>>>::None
    }

    /// Try to upcast the context to an invoke context.
    /// The operation will return `Some` only if the underlying context represents an invoke operation.
    fn as_invoke_ctx(&self) -> Option<impl InvokeContext> {
        Option::<InvokeContextInstance<EmptyHandler, PooledBuffers<0, NoopRawMutex, IMBuffer>>>::None
    }
}

impl<T> Context for &T
where
    T: Context,
{
    fn exchange(&self) -> &Exchange<'_> {
        (**self).exchange()
    }

    fn handler(&self) -> impl AsyncHandler + '_ {
        (**self).handler()
    }

    fn buffers(&self) -> impl BufferAccess<IMBuffer> + '_ {
        (**self).buffers()
    }

    fn notify_changed(&self) {
        (**self).notify_changed();
    }

    fn as_read_ctx(&self) -> Option<impl ReadContext> {
        (**self).as_read_ctx()
    }

    fn as_write_ctx(&self) -> Option<impl WriteContext> {
        (**self).as_write_ctx()
    }

    fn as_invoke_ctx(&self) -> Option<impl InvokeContext> {
        (**self).as_invoke_ctx()
    }
}

/// A context type that is passed to the handler when processing an attribute Read operation.
pub trait ReadContext: Context {
    /// Return the attribute object that is associated with this read operation.
    fn attr(&self) -> &AttrDetails<'_>;
}

impl<T> ReadContext for &T
where
    T: ReadContext,
{
    fn attr(&self) -> &AttrDetails<'_> {
        (**self).attr()
    }
}

/// A context type that is passed to the handler when processing an attribute Write operation.
pub trait WriteContext: Context {
    /// Return the attribute object that is associated with this read operation.
    fn attr(&self) -> &AttrDetails<'_>;

    /// Return the attribute data that is associated with this write operation.
    fn data(&self) -> &TLVElement<'_>;
}

impl<T> WriteContext for &T
where
    T: WriteContext,
{
    fn attr(&self) -> &AttrDetails<'_> {
        (**self).attr()
    }

    fn data(&self) -> &TLVElement<'_> {
        (**self).data()
    }
}

pub trait InvokeContext: Context {
    /// Return the command object that is associated with this invoke operation.
    fn cmd(&self) -> &CmdDetails<'_>;

    /// Return the command data that is associated with this invoke operation.
    fn data(&self) -> &TLVElement<'_>;
}

impl<T> InvokeContext for &T
where
    T: InvokeContext,
{
    fn cmd(&self) -> &CmdDetails<'_> {
        (**self).cmd()
    }

    fn data(&self) -> &TLVElement<'_> {
        (**self).data()
    }
}

/// A concrete implementation of the `ReadContext` trait
pub(crate) struct ReadContextInstance<'a, T, B> {
    exchange: &'a Exchange<'a>,
    handler: T,
    buffers: B,
    attr: &'a AttrDetails<'a>,
}

impl<'a, T, B> ReadContextInstance<'a, T, B>
where
    T: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    /// Construct a new instance.
    #[inline(always)]
    pub(crate) const fn new(
        exchange: &'a Exchange<'a>,
        handler: T,
        buffers: B,
        attr: &'a AttrDetails<'a>,
    ) -> Self {
        Self {
            exchange,
            handler,
            buffers,
            attr,
        }
    }
}

impl<T, B> Context for ReadContextInstance<'_, T, B>
where
    T: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    fn exchange(&self) -> &Exchange<'_> {
        self.exchange
    }

    fn handler(&self) -> impl AsyncHandler + '_ {
        &self.handler
    }

    fn buffers(&self) -> impl BufferAccess<IMBuffer> + '_ {
        &self.buffers
    }

    fn notify_changed(&self) {
        // no-op
    }

    fn as_read_ctx(&self) -> Option<impl ReadContext> {
        Some(self)
    }
}

impl<T, B> ReadContext for ReadContextInstance<'_, T, B>
where
    T: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    fn attr(&self) -> &AttrDetails<'_> {
        self.attr
    }
}

/// A context implementation of the `WriteContext` trait
pub(crate) struct WriteContextInstance<'a, T, B> {
    exchange: &'a Exchange<'a>,
    handler: T,
    buffers: B,
    attr: &'a AttrDetails<'a>,
    data: &'a TLVElement<'a>,
    pub(crate) notify: &'a dyn ChangeNotify,
}

impl<'a, T, B> WriteContextInstance<'a, T, B>
where
    T: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    /// Create a new instance.
    #[inline(always)]
    pub(crate) const fn new(
        exchange: &'a Exchange<'a>,
        handler: T,
        buffers: B,
        attr: &'a AttrDetails<'a>,
        data: &'a TLVElement<'a>,
        notify: &'a dyn ChangeNotify,
    ) -> Self {
        Self {
            exchange,
            handler,
            buffers,
            attr,
            data,
            notify,
        }
    }
}

impl<T, B> Context for WriteContextInstance<'_, T, B>
where
    T: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    fn exchange(&self) -> &Exchange<'_> {
        self.exchange
    }

    fn handler(&self) -> impl AsyncHandler + '_ {
        &self.handler
    }

    fn buffers(&self) -> impl BufferAccess<IMBuffer> + '_ {
        &self.buffers
    }

    fn notify_changed(&self) {
        self.notify
            .notify(self.attr.endpoint_id, self.attr.cluster_id);
    }

    fn as_write_ctx(&self) -> Option<impl WriteContext> {
        Some(self)
    }
}

impl<T, B> WriteContext for WriteContextInstance<'_, T, B>
where
    T: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    fn attr(&self) -> &AttrDetails<'_> {
        self.attr
    }

    fn data(&self) -> &TLVElement<'_> {
        self.data
    }
}

/// A concrete implementation of the `InvokeContext` trait
pub(crate) struct InvokeContextInstance<'a, T, B> {
    exchange: &'a Exchange<'a>,
    handler: T,
    buffers: B,
    cmd: &'a CmdDetails<'a>,
    data: &'a TLVElement<'a>,
    notify: &'a dyn ChangeNotify,
}

impl<'a, T, B> InvokeContextInstance<'a, T, B>
where
    T: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    /// Construct a new instance.
    #[inline(always)]
    pub(crate) const fn new(
        exchange: &'a Exchange<'a>,
        handler: T,
        buffers: B,
        cmd: &'a CmdDetails<'a>,
        data: &'a TLVElement<'a>,
        notify: &'a dyn ChangeNotify,
    ) -> Self {
        Self {
            exchange,
            handler,
            buffers,
            cmd,
            data,
            notify,
        }
    }
}

impl<T, B> Context for InvokeContextInstance<'_, T, B>
where
    T: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    fn exchange(&self) -> &Exchange<'_> {
        self.exchange
    }

    fn handler(&self) -> impl AsyncHandler + '_ {
        &self.handler
    }

    fn buffers(&self) -> impl BufferAccess<IMBuffer> + '_ {
        &self.buffers
    }

    fn notify_changed(&self) {
        self.notify
            .notify(self.cmd.endpoint_id, self.cmd.cluster_id);
    }

    fn as_invoke_ctx(&self) -> Option<impl InvokeContext> {
        Some(self)
    }
}

impl<T, B> InvokeContext for InvokeContextInstance<'_, T, B>
where
    T: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    fn cmd(&self) -> &CmdDetails<'_> {
        self.cmd
    }

    fn data(&self) -> &TLVElement<'_> {
        self.data
    }
}

pub trait DataModelHandler: super::AsyncMetadata + AsyncHandler {}
impl<T> DataModelHandler for T where T: super::AsyncMetadata + AsyncHandler {}

/// A version of the `AsyncHandler` trait that never awaits any operation.
///
/// Prefer this trait when implementing handlers that are known to be non-blocking and additionally,
/// mark those with `NonBlockingHandler`.
pub trait Handler {
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
}

/// A marker trait that indicates that the handler is non-blocking.
// TODO: Re-assess the need for this trait.
pub trait NonBlockingHandler: Handler {}

impl<T> NonBlockingHandler for &T where T: NonBlockingHandler {}

impl<T> NonBlockingHandler for &mut T where T: NonBlockingHandler {}

impl<M, H> Handler for (M, H)
where
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
}

impl<M, H> NonBlockingHandler for (M, H) where H: NonBlockingHandler {}

/// A trait that defines a matcher for determining whether a handler - member of a handler-chain (`ChainedHandler`)
/// should be invoked for a specific operation.
pub trait Matcher {
    /// Return `true` if the corresponding handler should be invoked for the provided context.
    fn matches(&self, ctx: impl Context) -> bool;
}

impl<T> Matcher for &T
where
    T: Matcher,
{
    fn matches(&self, ctx: impl Context) -> bool {
        T::matches(self, ctx)
    }
}

/// A matcher that matches a specific endpoint ID and cluster ID.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EpClMatcher {
    endpoint_id: Option<EndptId>,
    cluster_id: Option<ClusterId>,
}

impl EpClMatcher {
    /// Create a new `EpClMatcher` instance.
    ///
    /// # Arguments:
    /// - `endpoint_id`: The endpoint ID to match. If `None`, matches any endpoint ID.
    /// - `cluster_id`: The cluster ID to match. If `None`, matches any cluster ID.
    pub const fn new(endpoint_id: Option<EndptId>, cluster_id: Option<ClusterId>) -> Self {
        Self {
            endpoint_id,
            cluster_id,
        }
    }
}

impl Matcher for EpClMatcher {
    fn matches(&self, ctx: impl Context) -> bool {
        if let Some(ctx) = ctx.as_read_ctx() {
            self.endpoint_id
                .map(|endpoint_id| ctx.attr().endpoint_id == endpoint_id)
                .unwrap_or(true)
                && self
                    .cluster_id
                    .map(|cluster_id| cluster_id == ctx.attr().cluster_id)
                    .unwrap_or(true)
        } else if let Some(ctx) = ctx.as_write_ctx() {
            self.endpoint_id
                .map(|endpoint_id| ctx.attr().endpoint_id == endpoint_id)
                .unwrap_or(true)
                && self
                    .cluster_id
                    .map(|cluster_id| cluster_id == ctx.attr().cluster_id)
                    .unwrap_or(true)
        } else {
            let Some(ctx) = ctx.as_invoke_ctx() else {
                unreachable!()
            };

            self.endpoint_id
                .map(|endpoint_id| ctx.cmd().endpoint_id == endpoint_id)
                .unwrap_or(true)
                && self
                    .cluster_id
                    .map(|cluster_id| cluster_id == ctx.cmd().cluster_id)
                    .unwrap_or(true)
        }
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
    pub const fn chain<M, H>(self, matcher: M, handler: H) -> ChainedHandler<M, H, Self> {
        ChainedHandler {
            matcher,
            handler,
            next: self,
        }
    }
}

impl Handler for EmptyHandler {
    fn read(&self, _ctx: impl ReadContext, _reply: impl ReadReply) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
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

impl<M, H, T> ChainedHandler<M, H, T> {
    /// Construct a chained handler that works as follows:
    /// - It will call the provided `handler` instance if the provided matcher returns `true`
    ///   for the `ReadContext`/`WriteContext`/`InvokeContext` of the incoming operation
    /// - Otherwise, it will call the `next` handler
    ///
    /// Arguments:
    /// - `matcher`: A matcher that determines whether the handler should be invoked for the incoming operation.
    /// - `handler`: The handler to be invoked if the matcher returns `true`.
    /// - `next`: The next handler to be invoked if the matcher returns `false`.
    pub const fn new(matcher: M, handler: H, next: T) -> Self {
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
    pub const fn chain<M2, H2>(self, matcher: M2, handler: H2) -> ChainedHandler<M2, H2, Self> {
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
///     EpClMatcher => DescriptorCluster<'static>,
///     EpClMatcher => BasicInfoCluster<'a>,
///     EpClMatcher => GenCommCluster<'a>,
///     EpClMatcher => NwCommCluster,
///     EpClMatcher => AdminCommCluster<'a>,
///     EpClMatcher => NocCluster<'a>,
///     EpClMatcher => AccessControlCluster<'a>,
///     EpClMatcher => GenDiagCluster,
///     EpClMatcher => EthNwDiagCluster,
///     EpClMatcher => GrpKeyMgmtCluster
/// );
/// ```
#[allow(unused_macros)]
#[macro_export]
macro_rules! handler_chain_type {
    ($m:ty => $h:ty) => {
        $crate::dm::ChainedHandler<$m, $h, $crate::dm::EmptyHandler>
    };
    ($m1:ty => $h1:ty, $($m:ty => $h:ty),+) => {
        $crate::dm::ChainedHandler<$m1, $h1, handler_chain_type!($($m => $h),+)>
    };
    ($m:ty => $h:ty | $f:ty) => {
        $crate::dm::ChainedHandler<$m, $h, $f>
    };
    ($m1:ty => $h1:ty, $($m:ty => $h:ty),+ | $f:ty) => {
        $crate::dm::ChainedHandler<$m1, $h1, handler_chain_type!($($m => $h),+ | $f)>
    };
}

mod asynch {
    use embassy_futures::select::select;

    use crate::dm::{InvokeReply, Matcher, ReadReply};
    use crate::error::{Error, ErrorCode};
    use crate::utils::select::Coalesce;

    use super::{
        ChainedHandler, EmptyHandler, Handler, InvokeContext, NonBlockingHandler, ReadContext,
        WriteContext,
    };

    /// A handler for processing a single IM operation:
    /// read an attribute, write an attribute, or invoke a command.
    ///
    /// Handlers are typically implemented by user-defined clusters, but there is no 1:1 correspondence between
    /// a handler and a cluster, as a single handler can handle multiple clusters and even multiple endpoints.
    ///
    /// Moreover, the `DataModel` implementation expects a single `AsyncHandler` instance, so the expectation
    /// is that the user will compose multiple handlers into a single `AsyncHandler` instance, using `ChainedHandler`
    /// or other means.
    pub trait AsyncHandler {
        /// Provide information whether the handler will internally await while reading
        /// the current value of the provided attribute.
        ///
        /// Handlers which report `false` via this method provide an opportunity
        /// for the Data Model processing to use less memory by not storing the incoming request
        /// in an intermediate buffer.
        ///
        /// The default implementation unconditionally returns `true` i.e. the handler is assumed to
        /// await while reading any attribute.
        fn read_awaits(&self, _ctx: impl ReadContext) -> bool {
            true
        }

        /// Provide information whether the handler will internally await while updating
        /// the value of the provided attribute.
        ///
        /// Handlers which report `false` via this method provide an opportunity
        /// for the Data Model processing to use less memory by not storing the incoming request
        /// in an intermediate buffer.
        ///
        /// The default implementation unconditionally returns `true` i.e. the handler is assumed to
        /// await while writing any attribute.
        fn write_awaits(&self, _ctx: impl WriteContext) -> bool {
            true
        }

        /// Provide information whether the handler will internally await while invoking
        /// the provided command.
        ///
        /// Handlers which report `false` via this method provide an opportunity
        /// for the Data Model processing to use less memory by not storing the incoming request
        /// in an intermediate buffer.
        ///
        /// The default implementation unconditionally returns `true` i.e. the handler is assumed to
        /// await while invoking any command.
        fn invoke_awaits(&self, _ctx: impl InvokeContext) -> bool {
            true
        }

        /// Read from the requested attribute and encode the result using the provided reply type.
        async fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error>;

        /// Write into the requested attribute using the provided data.
        ///
        /// The default implementation errors out with `ErrorCode::AttributeNotFound`.
        async fn write(&self, _ctx: impl WriteContext) -> Result<(), Error> {
            Err(ErrorCode::AttributeNotFound.into())
        }

        /// Invoke the requested command with the provided data and encode the result using the provided reply type.
        ///
        /// The default implementation errors out with `ErrorCode::CommandNotFound`.
        async fn invoke(
            &self,
            _ctx: impl InvokeContext,
            _reply: impl InvokeReply,
        ) -> Result<(), Error> {
            Err(ErrorCode::CommandNotFound.into())
        }

        /// A hook (a scheduling facility) for placing handler-impl-specific code that needs to run
        /// asynchronously - forever and in the "background".
        async fn run(&self) -> Result<(), Error> {
            // Default implementation pends forever.
            // This is useful for handlers that do not need to run any async operations in the background.
            core::future::pending::<Result<(), Error>>().await
        }
    }

    impl<T> AsyncHandler for &mut T
    where
        T: AsyncHandler,
    {
        fn read_awaits(&self, ctx: impl ReadContext) -> bool {
            (**self).read_awaits(ctx)
        }

        fn write_awaits(&self, ctx: impl WriteContext) -> bool {
            (**self).write_awaits(ctx)
        }

        fn invoke_awaits(&self, ctx: impl InvokeContext) -> bool {
            (**self).invoke_awaits(ctx)
        }

        async fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error> {
            (**self).read(ctx, reply).await
        }

        async fn write(&self, ctx: impl WriteContext) -> Result<(), Error> {
            (**self).write(ctx).await
        }

        async fn invoke(
            &self,
            ctx: impl InvokeContext,
            reply: impl InvokeReply,
        ) -> Result<(), Error> {
            (**self).invoke(ctx, reply).await
        }

        async fn run(&self) -> Result<(), Error> {
            (**self).run().await
        }
    }

    impl<T> AsyncHandler for &T
    where
        T: AsyncHandler,
    {
        fn read_awaits(&self, ctx: impl ReadContext) -> bool {
            (**self).read_awaits(ctx)
        }

        fn write_awaits(&self, ctx: impl WriteContext) -> bool {
            (**self).write_awaits(ctx)
        }

        fn invoke_awaits(&self, ctx: impl InvokeContext) -> bool {
            (**self).invoke_awaits(ctx)
        }

        async fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error> {
            (**self).read(ctx, reply).await
        }

        async fn write(&self, ctx: impl WriteContext) -> Result<(), Error> {
            (**self).write(ctx).await
        }

        async fn invoke(
            &self,
            ctx: impl InvokeContext,
            reply: impl InvokeReply,
        ) -> Result<(), Error> {
            (**self).invoke(ctx, reply).await
        }

        async fn run(&self) -> Result<(), Error> {
            (**self).run().await
        }
    }

    impl<M, H> AsyncHandler for (M, H)
    where
        H: AsyncHandler,
    {
        fn read_awaits(&self, ctx: impl ReadContext) -> bool {
            self.1.read_awaits(ctx)
        }

        fn write_awaits(&self, ctx: impl WriteContext) -> bool {
            self.1.write_awaits(ctx)
        }

        fn invoke_awaits(&self, ctx: impl InvokeContext) -> bool {
            self.1.invoke_awaits(ctx)
        }

        async fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error> {
            self.1.read(ctx, reply).await
        }

        async fn write(&self, ctx: impl WriteContext) -> Result<(), Error> {
            self.1.write(ctx).await
        }

        async fn invoke(
            &self,
            ctx: impl InvokeContext,
            reply: impl InvokeReply,
        ) -> Result<(), Error> {
            self.1.invoke(ctx, reply).await
        }
    }

    impl<T> AsyncHandler for Async<T>
    where
        T: NonBlockingHandler,
    {
        fn read_awaits(&self, _ctx: impl ReadContext) -> bool {
            false
        }

        fn write_awaits(&self, _ctx: impl WriteContext) -> bool {
            false
        }

        fn invoke_awaits(&self, _ctx: impl InvokeContext) -> bool {
            false
        }

        async fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error> {
            Handler::read(&self.0, ctx, reply)
        }

        async fn write(&self, ctx: impl WriteContext) -> Result<(), Error> {
            Handler::write(&self.0, ctx)
        }

        async fn invoke(
            &self,
            ctx: impl InvokeContext,
            reply: impl InvokeReply,
        ) -> Result<(), Error> {
            Handler::invoke(&self.0, ctx, reply)
        }
    }

    impl AsyncHandler for EmptyHandler {
        fn read_awaits(&self, _ctx: impl ReadContext) -> bool {
            false
        }

        fn write_awaits(&self, _ctx: impl WriteContext) -> bool {
            false
        }

        fn invoke_awaits(&self, _ctx: impl InvokeContext) -> bool {
            false
        }

        async fn read(&self, _ctx: impl ReadContext, _reply: impl ReadReply) -> Result<(), Error> {
            Err(ErrorCode::AttributeNotFound.into())
        }
    }

    impl<M, H, T> AsyncHandler for ChainedHandler<M, H, T>
    where
        M: Matcher,
        H: AsyncHandler,
        T: AsyncHandler,
    {
        fn read_awaits(&self, ctx: impl ReadContext) -> bool {
            if self.matcher.matches(&ctx) {
                self.handler.read_awaits(ctx)
            } else {
                self.next.read_awaits(ctx)
            }
        }

        fn write_awaits(&self, ctx: impl WriteContext) -> bool {
            if self.matcher.matches(&ctx) {
                self.handler.write_awaits(ctx)
            } else {
                self.next.write_awaits(ctx)
            }
        }

        fn invoke_awaits(&self, ctx: impl InvokeContext) -> bool {
            if self.matcher.matches(&ctx) {
                self.handler.invoke_awaits(ctx)
            } else {
                self.next.invoke_awaits(ctx)
            }
        }

        async fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error> {
            if self.matcher.matches(&ctx) {
                self.handler.read(ctx, reply).await
            } else {
                self.next.read(ctx, reply).await
            }
        }

        async fn write(&self, ctx: impl WriteContext) -> Result<(), Error> {
            if self.matcher.matches(&ctx) {
                self.handler.write(ctx).await
            } else {
                self.next.write(ctx).await
            }
        }

        async fn invoke(
            &self,
            ctx: impl InvokeContext,
            reply: impl InvokeReply,
        ) -> Result<(), Error> {
            if self.matcher.matches(&ctx) {
                self.handler.invoke(ctx, reply).await
            } else {
                self.next.invoke(ctx, reply).await
            }
        }

        async fn run(&self) -> Result<(), Error> {
            select(self.handler.run(), self.next.run()).coalesce().await
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
    }

    impl<T> NonBlockingHandler for Async<T> where T: NonBlockingHandler {}
}
