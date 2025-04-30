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

use crate::{
    error::{Error, ErrorCode},
    tlv::TLVElement,
    transport::exchange::Exchange,
};

use super::{AttrDataEncoder, AttrDetails, ClusterId, CmdDataEncoder, CmdDetails, EndptId};

pub use asynch::*;

pub(crate) trait ChangeNotify {
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

/// A context object that is passed to the handler when processing an attribute Read operation.
pub struct ReadContext<'a> {
    exchange: &'a Exchange<'a>,
    attr: &'a AttrDetails<'a>,
}

impl<'a> ReadContext<'a> {
    /// Construct a new `ReadContext` instance.
    #[inline(always)]
    pub(crate) const fn new(exchange: &'a Exchange<'a>, attr: &'a AttrDetails<'a>) -> Self {
        Self { exchange, attr }
    }

    /// Return the exchange object that is associated with this read operation.
    #[inline(always)]
    pub fn exchange(&self) -> &Exchange<'_> {
        self.exchange
    }

    /// Return the attribute object that is associated with this read operation.
    #[inline(always)]
    pub fn attr(&self) -> &AttrDetails<'_> {
        self.attr
    }
}

/// A context object that is passed to the handler when processing an attribute Write operation.
pub struct WriteContext<'a> {
    exchange: &'a Exchange<'a>,
    attr: &'a AttrDetails<'a>,
    data: &'a TLVElement<'a>,
    notify: &'a dyn ChangeNotify,
}

impl<'a> WriteContext<'a> {
    /// Create a new `WriteContext` instance.
    #[inline(always)]
    pub(crate) const fn new(
        exchange: &'a Exchange<'a>,
        attr: &'a AttrDetails<'a>,
        data: &'a TLVElement<'a>,
        notify: &'a dyn ChangeNotify,
    ) -> Self {
        Self {
            exchange,
            attr,
            data,
            notify,
        }
    }

    /// Return the exchange object that is associated with this write operation.
    #[inline(always)]
    pub fn exchange(&self) -> &Exchange<'_> {
        self.exchange
    }

    /// Return the attribute object that is associated with this read operation.
    #[inline(always)]
    pub fn attr(&self) -> &AttrDetails<'_> {
        self.attr
    }

    /// Return the attribute data that is associated with this write operation.
    #[inline(always)]
    pub fn data(&self) -> &TLVElement<'_> {
        self.data
    }

    /// Notify that the attribute has changed.
    #[inline(always)]
    pub fn notify_changed(&self) {
        self.notify
            .notify(self.attr.endpoint_id, self.attr.cluster_id);
    }
}

/// A context object that is passed to the handler when processing a command Invoke operation.
pub struct InvokeContext<'a> {
    exchange: &'a Exchange<'a>,
    cmd: &'a CmdDetails<'a>,
    data: &'a TLVElement<'a>,
    notify: &'a dyn ChangeNotify,
}

impl<'a> InvokeContext<'a> {
    /// Construct a new `InvokeContext` instance.
    #[inline(always)]
    pub(crate) const fn new(
        exchange: &'a Exchange<'a>,
        cmd: &'a CmdDetails<'a>,
        data: &'a TLVElement<'a>,
        notify: &'a dyn ChangeNotify,
    ) -> Self {
        Self {
            exchange,
            cmd,
            data,
            notify,
        }
    }

    /// Return the exchange object that is associated with this invoke operation.
    #[inline(always)]
    pub fn exchange(&self) -> &Exchange<'_> {
        self.exchange
    }

    /// Return the command object that is associated with this invoke operation.
    #[inline(always)]
    pub fn cmd(&self) -> &CmdDetails<'_> {
        self.cmd
    }

    /// Return the command data that is associated with this invoke operation.
    #[inline(always)]
    pub fn data(&self) -> &TLVElement<'_> {
        self.data
    }

    /// Notify that the cluster has changed.
    #[inline(always)]
    pub fn notify_changed(&self) {
        self.notify
            .notify(self.cmd.endpoint_id, self.cmd.cluster_id);
    }
}

pub trait DataModelHandler: super::AsyncMetadata + AsyncHandler {}
impl<T> DataModelHandler for T where T: super::AsyncMetadata + AsyncHandler {}

/// A version of the `AsyncHandler` trait that never awaits any operation.
///
/// Prefer this trait when implementing handlers that are known to be non-blocking.
pub trait Handler {
    fn read(
        &self,
        ctx: &ReadContext<'_>,
        encoder: AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error>;

    fn write(&self, _ctx: &WriteContext<'_>) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    fn invoke(&self, _ctx: &InvokeContext<'_>, _encoder: CmdDataEncoder) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }
}

impl<T> Handler for &T
where
    T: Handler,
{
    fn read(&self, ctx: &ReadContext<'_>, encoder: AttrDataEncoder) -> Result<(), Error> {
        (**self).read(ctx, encoder)
    }

    fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
        (**self).write(ctx)
    }

    fn invoke(
        &self,
        ctx: &InvokeContext<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        (**self).invoke(ctx, encoder)
    }
}

impl<T> Handler for &mut T
where
    T: Handler,
{
    fn read(&self, ctx: &ReadContext<'_>, encoder: AttrDataEncoder) -> Result<(), Error> {
        (**self).read(ctx, encoder)
    }

    fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
        (**self).write(ctx)
    }

    fn invoke(
        &self,
        ctx: &InvokeContext<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        (**self).invoke(ctx, encoder)
    }
}

// TODO: Re-assess the need for this trait.
pub trait NonBlockingHandler: Handler {}

impl<T> NonBlockingHandler for &T where T: NonBlockingHandler {}

impl<T> NonBlockingHandler for &mut T where T: NonBlockingHandler {}

impl<M, H> Handler for (M, H)
where
    H: Handler,
{
    fn read(
        &self,
        ctx: &ReadContext<'_>,
        encoder: AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        self.1.read(ctx, encoder)
    }

    fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
        self.1.write(ctx)
    }

    fn invoke(&self, ctx: &InvokeContext<'_>, encoder: CmdDataEncoder) -> Result<(), Error> {
        self.1.invoke(ctx, encoder)
    }
}

impl<M, H> NonBlockingHandler for (M, H) where H: NonBlockingHandler {}

/// A handler that always fails with attribute / command not found.
///
/// Useful when chaining multiple handlers together as the end of the chain.
pub struct EmptyHandler;

impl EmptyHandler {
    /// Chain the empty handler with another handler thus providing an "end of handler chain"
    /// fallback that errors out.
    ///
    /// The returned chained handler works as follows:
    /// - It will call the provided `handler` instance if the endpoint and cluster
    ///   of the incoming request do match the `handler_endpoint` and `handler_cluster` provided here.
    /// - Otherwise, the empty handler would be invoked, causing the operation to error out.
    pub const fn chain<H>(
        self,
        handler_endpoint: u16,
        handler_cluster: u32,
        handler: H,
    ) -> ChainedHandler<H, Self> {
        ChainedHandler {
            handler_endpoint,
            handler_cluster,
            handler,
            next: self,
        }
    }
}

impl Handler for EmptyHandler {
    fn read(
        &self,
        _ctx: &ReadContext<'_>,
        _encoder: AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }
}

impl NonBlockingHandler for EmptyHandler {}

/// A handler that chains two handlers together in a composite handler.
pub struct ChainedHandler<H, T> {
    pub handler_endpoint: u16,
    pub handler_cluster: u32,
    pub handler: H,
    pub next: T,
}

impl<H, T> ChainedHandler<H, T> {
    /// Construct a chained handler that works as follows:
    /// - It will call the provided `handler` instance if the endpoint and cluster
    ///   of the incoming request do match the `handler_endpoint` and `handler_cluster` provided here.
    /// - Otherwise, it will call the `next` handler
    pub const fn new(handler_endpoint: u16, handler_cluster: u32, handler: H, next: T) -> Self {
        Self {
            handler_endpoint,
            handler_cluster,
            handler,
            next,
        }
    }

    /// Chain itself with another handler.
    ///
    /// The returned chained handler works as follows:
    /// - It will call the provided `handler` instance if the endpoint and cluster
    ///   of the incoming request do match the `handler_endpoint` and `handler_cluster` provided here.
    /// - Otherwise, it will call the `self` handler
    pub const fn chain<H2>(
        self,
        handler_endpoint: u16,
        handler_cluster: u32,
        handler: H2,
    ) -> ChainedHandler<H2, Self> {
        ChainedHandler::new(handler_endpoint, handler_cluster, handler, self)
    }
}

impl<H, T> Handler for ChainedHandler<H, T>
where
    H: Handler,
    T: Handler,
{
    fn read(
        &self,
        ctx: &ReadContext<'_>,
        encoder: AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        if self.handler_endpoint == ctx.attr().endpoint_id
            && self.handler_cluster == ctx.attr().cluster_id
        {
            self.handler.read(ctx, encoder)
        } else {
            self.next.read(ctx, encoder)
        }
    }

    fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
        if self.handler_endpoint == ctx.attr().endpoint_id
            && self.handler_cluster == ctx.attr().cluster_id
        {
            self.handler.write(ctx)
        } else {
            self.next.write(ctx)
        }
    }

    fn invoke(
        &self,
        ctx: &InvokeContext<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        if self.handler_endpoint == ctx.cmd().endpoint_id
            && self.handler_cluster == ctx.cmd().cluster_id
        {
            self.handler.invoke(ctx, encoder)
        } else {
            self.next.invoke(ctx, encoder)
        }
    }
}

impl<H, T> NonBlockingHandler for ChainedHandler<H, T>
where
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
///     DescriptorCluster<'static>,
///     BasicInfoCluster<'a>,
///     GenCommCluster<'a>,
///     NwCommCluster,
///     AdminCommCluster<'a>,
///     NocCluster<'a>,
///     AccessControlCluster<'a>,
///     GenDiagCluster,
///     EthNwDiagCluster,
///     GrpKeyMgmtCluster
/// );
/// ```
#[allow(unused_macros)]
#[macro_export]
macro_rules! handler_chain_type {
    ($h:ty) => {
        $crate::data_model::objects::ChainedHandler<$h, $crate::data_model::objects::EmptyHandler>
    };
    ($h1:ty $(, $rest:ty)+) => {
        $crate::data_model::objects::ChainedHandler<$h1, handler_chain_type!($($rest),+)>
    };

    ($h:ty | $f:ty) => {
        $crate::data_model::objects::ChainedHandler<$h, $f>
    };
    ($h1:ty $(, $rest:ty)+ | $f:ty) => {
        $crate::data_model::objects::ChainedHandler<$h1, handler_chain_type!($($rest),+ | $f)>
    };
}

mod asynch {
    use crate::data_model::objects::{AttrDataEncoder, CmdDataEncoder};
    use crate::error::{Error, ErrorCode};

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
        /// Provides information whether the handler will internally await while reading
        /// the current value of the provided attribute.
        ///
        /// Handlers which report `false` via this method provide an opportunity
        /// for the Data Model processing to use less memory by not storing the incoming request
        /// in an intermediate buffer.
        ///
        /// The default implementation unconditionally returns `true` i.e. the handler is assumed to
        /// await while reading any attribute.
        fn read_awaits(&self, _ctx: &ReadContext<'_>) -> bool {
            true
        }

        /// Provides information whether the handler will internally await while updating
        /// the value of the provided attribute.
        ///
        /// Handlers which report `false` via this method provide an opportunity
        /// for the Data Model processing to use less memory by not storing the incoming request
        /// in an intermediate buffer.
        ///
        /// The default implementation unconditionally returns `true` i.e. the handler is assumed to
        /// await while writing any attribute.
        fn write_awaits(&self, _ctx: &WriteContext<'_>) -> bool {
            true
        }

        /// Provides information whether the handler will internally await while invoking
        /// the provided command.
        ///
        /// Handlers which report `false` via this method provide an opportunity
        /// for the Data Model processing to use less memory by not storing the incoming request
        /// in an intermediate buffer.
        ///
        /// The default implementation unconditionally returns `true` i.e. the handler is assumed to
        /// await while invoking any command.
        fn invoke_awaits(&self, _ctx: &InvokeContext<'_>) -> bool {
            true
        }

        /// Reads from the requested attribute and encodes the result using the provided encoder.
        async fn read(
            &self,
            ctx: &ReadContext<'_>,
            encoder: AttrDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error>;

        /// Writes into the requested attribute using the provided data.
        ///
        /// The default implementation errors out with `ErrorCode::AttributeNotFound`.
        async fn write(&self, _ctx: &WriteContext<'_>) -> Result<(), Error> {
            Err(ErrorCode::AttributeNotFound.into())
        }

        /// Invokes the requested command with the provided data and encodes the result using the provided encoder.
        ///
        /// The default implementation errors out with `ErrorCode::CommandNotFound`.
        async fn invoke(
            &self,
            _ctx: &InvokeContext<'_>,
            _encoder: CmdDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            Err(ErrorCode::CommandNotFound.into())
        }
    }

    impl<T> AsyncHandler for &mut T
    where
        T: AsyncHandler,
    {
        fn read_awaits(&self, ctx: &ReadContext<'_>) -> bool {
            (**self).read_awaits(ctx)
        }

        fn write_awaits(&self, ctx: &WriteContext<'_>) -> bool {
            (**self).write_awaits(ctx)
        }

        fn invoke_awaits(&self, ctx: &InvokeContext<'_>) -> bool {
            (**self).invoke_awaits(ctx)
        }

        async fn read(
            &self,
            ctx: &ReadContext<'_>,
            encoder: AttrDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            (**self).read(ctx, encoder).await
        }

        async fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
            (**self).write(ctx).await
        }

        async fn invoke(
            &self,
            ctx: &InvokeContext<'_>,
            encoder: CmdDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            (**self).invoke(ctx, encoder).await
        }
    }

    impl<T> AsyncHandler for &T
    where
        T: AsyncHandler,
    {
        fn read_awaits(&self, ctx: &ReadContext<'_>) -> bool {
            (**self).read_awaits(ctx)
        }

        fn write_awaits(&self, ctx: &WriteContext<'_>) -> bool {
            (**self).write_awaits(ctx)
        }

        fn invoke_awaits(&self, ctx: &InvokeContext<'_>) -> bool {
            (**self).invoke_awaits(ctx)
        }

        async fn read(
            &self,
            ctx: &ReadContext<'_>,
            encoder: AttrDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            (**self).read(ctx, encoder).await
        }

        async fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
            (**self).write(ctx).await
        }

        async fn invoke(
            &self,
            ctx: &InvokeContext<'_>,
            encoder: CmdDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            (**self).invoke(ctx, encoder).await
        }
    }

    impl<M, H> AsyncHandler for (M, H)
    where
        H: AsyncHandler,
    {
        fn read_awaits(&self, ctx: &ReadContext<'_>) -> bool {
            self.1.read_awaits(ctx)
        }

        fn write_awaits(&self, ctx: &WriteContext<'_>) -> bool {
            self.1.write_awaits(ctx)
        }

        fn invoke_awaits(&self, ctx: &InvokeContext<'_>) -> bool {
            self.1.invoke_awaits(ctx)
        }

        async fn read(
            &self,
            ctx: &ReadContext<'_>,
            encoder: AttrDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            self.1.read(ctx, encoder).await
        }

        async fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
            self.1.write(ctx).await
        }

        async fn invoke(
            &self,
            ctx: &InvokeContext<'_>,
            encoder: CmdDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            self.1.invoke(ctx, encoder).await
        }
    }

    impl<T> AsyncHandler for Async<T>
    where
        T: NonBlockingHandler,
    {
        fn read_awaits(&self, _ctx: &ReadContext<'_>) -> bool {
            false
        }

        fn write_awaits(&self, _ctx: &WriteContext<'_>) -> bool {
            false
        }

        fn invoke_awaits(&self, _ctx: &InvokeContext<'_>) -> bool {
            false
        }

        async fn read(
            &self,
            ctx: &ReadContext<'_>,
            encoder: AttrDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            Handler::read(&self.0, ctx, encoder)
        }

        async fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
            Handler::write(&self.0, ctx)
        }

        async fn invoke(
            &self,
            ctx: &InvokeContext<'_>,
            encoder: CmdDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            Handler::invoke(&self.0, ctx, encoder)
        }
    }

    impl AsyncHandler for EmptyHandler {
        fn read_awaits(&self, _ctx: &ReadContext<'_>) -> bool {
            false
        }

        fn write_awaits(&self, _ctx: &WriteContext<'_>) -> bool {
            false
        }

        fn invoke_awaits(&self, _ctx: &InvokeContext<'_>) -> bool {
            false
        }

        async fn read(
            &self,
            _ctx: &ReadContext<'_>,
            _encoder: AttrDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            Err(ErrorCode::AttributeNotFound.into())
        }
    }

    impl<H, T> AsyncHandler for ChainedHandler<H, T>
    where
        H: AsyncHandler,
        T: AsyncHandler,
    {
        fn read_awaits(&self, ctx: &ReadContext<'_>) -> bool {
            if self.handler_endpoint == ctx.attr().endpoint_id
                && self.handler_cluster == ctx.attr().cluster_id
            {
                self.handler.read_awaits(ctx)
            } else {
                self.next.read_awaits(ctx)
            }
        }

        fn write_awaits(&self, ctx: &WriteContext<'_>) -> bool {
            if self.handler_endpoint == ctx.attr().endpoint_id
                && self.handler_cluster == ctx.attr().cluster_id
            {
                self.handler.write_awaits(ctx)
            } else {
                self.next.write_awaits(ctx)
            }
        }

        fn invoke_awaits(&self, ctx: &InvokeContext<'_>) -> bool {
            if self.handler_endpoint == ctx.cmd().endpoint_id
                && self.handler_cluster == ctx.cmd().cluster_id
            {
                self.handler.invoke_awaits(ctx)
            } else {
                self.next.invoke_awaits(ctx)
            }
        }

        async fn read(
            &self,
            ctx: &ReadContext<'_>,
            encoder: AttrDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            if self.handler_endpoint == ctx.attr().endpoint_id
                && self.handler_cluster == ctx.attr().cluster_id
            {
                self.handler.read(ctx, encoder).await
            } else {
                self.next.read(ctx, encoder).await
            }
        }

        async fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
            if self.handler_endpoint == ctx.attr().endpoint_id
                && self.handler_cluster == ctx.attr().cluster_id
            {
                self.handler.write(ctx).await
            } else {
                self.next.write(ctx).await
            }
        }

        async fn invoke(
            &self,
            ctx: &InvokeContext<'_>,
            encoder: CmdDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            if self.handler_endpoint == ctx.cmd().endpoint_id
                && self.handler_cluster == ctx.cmd().cluster_id
            {
                self.handler.invoke(ctx, encoder).await
            } else {
                self.next.invoke(ctx, encoder).await
            }
        }
    }

    /// An adaptor that adapts a `NonBlockingHandler` trait implementation to the `AsyncHandler` trait contract.
    ///
    /// The adaptor also implements `NonBlockingHandler` so that the adapted handler can be used in any context.
    pub struct Async<T>(pub T);

    impl<T> Handler for Async<T>
    where
        T: Handler,
    {
        fn read(
            &self,
            ctx: &ReadContext<'_>,
            encoder: AttrDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            self.0.read(ctx, encoder)
        }

        fn write(&self, ctx: &WriteContext<'_>) -> Result<(), Error> {
            self.0.write(ctx)
        }

        fn invoke(
            &self,
            ctx: &InvokeContext<'_>,
            encoder: CmdDataEncoder<'_, '_, '_>,
        ) -> Result<(), Error> {
            self.0.invoke(ctx, encoder)
        }
    }

    impl<T> NonBlockingHandler for Async<T> where T: NonBlockingHandler {}
}
