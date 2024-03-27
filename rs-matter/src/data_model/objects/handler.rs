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

use super::{AttrData, AttrDataEncoder, AttrDetails, CmdDataEncoder, CmdDetails};

pub use asynch::*;

pub trait DataModelHandler: super::asynch::AsyncMetadata + asynch::AsyncHandler {}
impl<T> DataModelHandler for T where T: super::asynch::AsyncMetadata + asynch::AsyncHandler {}

// TODO: Re-assess once once proper cluster change notifications are implemented.
pub trait ChangeNotifier<T> {
    fn consume_change(&mut self) -> Option<T>;
}

/// A version of the `AsyncHandler` trait that never awaits any operation.
///
/// Prefer this trait when implementing handlers that are known to be non-blocking.
pub trait Handler {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error>;

    fn write(&self, _attr: &AttrDetails, _data: AttrData) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    fn invoke(
        &self,
        _exchange: &Exchange,
        _cmd: &CmdDetails,
        _data: &TLVElement,
        _encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }
}

impl<T> Handler for &T
where
    T: Handler,
{
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        (**self).read(attr, encoder)
    }

    fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        (**self).write(attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        (**self).invoke(exchange, cmd, data, encoder)
    }
}

impl<T> Handler for &mut T
where
    T: Handler,
{
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        (**self).read(attr, encoder)
    }

    fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        (**self).write(attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        (**self).invoke(exchange, cmd, data, encoder)
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
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        self.1.read(attr, encoder)
    }

    fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        self.1.write(attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        self.1.invoke(exchange, cmd, data, encoder)
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
    /// of the incoming request do match the `handler_endpoint` and `handler_cluster` provided here.
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
    fn read(&self, _attr: &AttrDetails, _encoder: AttrDataEncoder) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }
}

impl NonBlockingHandler for EmptyHandler {}

impl ChangeNotifier<(u16, u32)> for EmptyHandler {
    fn consume_change(&mut self) -> Option<(u16, u32)> {
        None
    }
}

/// A handler that chains two handlers together in a composite handler.
pub struct ChainedHandler<H, T> {
    pub handler_endpoint: u16,
    pub handler_cluster: u32,
    pub handler: H,
    pub next: T,
}

impl<H, T> ChainedHandler<H, T> {
    /// Chain itself with another handler.
    ///
    /// The returned chained handler works as follows:
    /// - It will call the provided `handler` instance if the endpoint and cluster
    /// of the incoming request do match the `handler_endpoint` and `handler_cluster` provided here.
    /// - Otherwise, it will call the `self` handler
    pub const fn chain<H2>(
        self,
        handler_endpoint: u16,
        handler_cluster: u32,
        handler: H2,
    ) -> ChainedHandler<H2, Self> {
        ChainedHandler {
            handler_endpoint,
            handler_cluster,
            handler,
            next: self,
        }
    }
}

impl<H, T> Handler for ChainedHandler<H, T>
where
    H: Handler,
    T: Handler,
{
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if self.handler_endpoint == attr.endpoint_id && self.handler_cluster == attr.cluster_id {
            self.handler.read(attr, encoder)
        } else {
            self.next.read(attr, encoder)
        }
    }

    fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        if self.handler_endpoint == attr.endpoint_id && self.handler_cluster == attr.cluster_id {
            self.handler.write(attr, data)
        } else {
            self.next.write(attr, data)
        }
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        if self.handler_endpoint == cmd.endpoint_id && self.handler_cluster == cmd.cluster_id {
            self.handler.invoke(exchange, cmd, data, encoder)
        } else {
            self.next.invoke(exchange, cmd, data, encoder)
        }
    }
}

impl<H, T> NonBlockingHandler for ChainedHandler<H, T>
where
    H: NonBlockingHandler,
    T: NonBlockingHandler,
{
}

impl<H, T> ChangeNotifier<(u16, u32)> for ChainedHandler<H, T>
where
    H: ChangeNotifier<()>,
    T: ChangeNotifier<(u16, u32)>,
{
    fn consume_change(&mut self) -> Option<(u16, u32)> {
        if self.handler.consume_change().is_some() {
            Some((self.handler_endpoint, self.handler_cluster))
        } else {
            self.next.consume_change()
        }
    }
}

/// Wrap your `NonBlockingHandler` or `AsyncHandler` implementation in this struct
/// to get your code compilable with and without the `nightly` feature
///
/// TODO: Re-assess the need for this struct now that we no longer use a nightly compiler.
pub struct HandlerCompat<T>(pub T);

impl<T> Handler for HandlerCompat<T>
where
    T: Handler,
{
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        self.0.read(attr, encoder)
    }

    fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        self.0.write(attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        self.0.invoke(exchange, cmd, data, encoder)
    }
}

impl<T> NonBlockingHandler for HandlerCompat<T> where T: NonBlockingHandler {}

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
    use crate::{
        data_model::objects::{AttrData, AttrDataEncoder, AttrDetails, CmdDataEncoder, CmdDetails},
        error::{Error, ErrorCode},
        tlv::TLVElement,
        transport::exchange::Exchange,
    };

    use super::{ChainedHandler, EmptyHandler, Handler, HandlerCompat, NonBlockingHandler};

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
        /// in an inbtermediate buffer.
        ///
        /// The default implementation unconditionally returns `true` i.e. the handler is assumed to
        /// await while reading any attribute.
        fn read_awaits(&self, _attr: &AttrDetails) -> bool {
            true
        }

        /// Provides information whether the handler will internally await while updating
        /// the value of the provided attribute.
        ///
        /// Handlers which report `false` via this method provide an opportunity
        /// for the Data Model processing to use less memory by not storing the incoming request
        /// in an inbtermediate buffer.
        ///
        /// The default implementation unconditionally returns `true` i.e. the handler is assumed to
        /// await while writing any attribute.
        fn write_awaits(&self, _attr: &AttrDetails) -> bool {
            true
        }

        /// Provides information whether the handler will internally await while invoking
        /// the provided command.
        ///
        /// Handlers which report `false` via this method provide an opportunity
        /// for the Data Model processing to use less memory by not storing the incoming request
        /// in an inbtermediate buffer.
        ///
        /// The default implementation unconditionally returns `true` i.e. the handler is assumed to
        /// await while invoking any command.
        fn invoke_awaits(&self, _cmd: &CmdDetails) -> bool {
            true
        }

        /// Reads from the requested attribute and encodes the result using the provided encoder.
        async fn read<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            encoder: AttrDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error>;

        /// Writes into the requested attribute using the provided data.
        ///
        /// The default implementation errors out with `ErrorCode::AttributeNotFound`.
        async fn write<'a>(
            &'a self,
            _attr: &'a AttrDetails<'_>,
            _data: AttrData<'a>,
        ) -> Result<(), Error> {
            Err(ErrorCode::AttributeNotFound.into())
        }

        /// Invokes the requested command with the provided data and encodes the result using the provided encoder.
        ///
        /// The default implementation errors out with `ErrorCode::CommandNotFound`.
        async fn invoke<'a>(
            &'a self,
            _exchange: &'a Exchange<'_>,
            _cmd: &'a CmdDetails<'_>,
            _data: &'a TLVElement<'_>,
            _encoder: CmdDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            Err(ErrorCode::CommandNotFound.into())
        }
    }

    impl<T> AsyncHandler for &mut T
    where
        T: AsyncHandler,
    {
        fn read_awaits(&self, attr: &AttrDetails) -> bool {
            (**self).read_awaits(attr)
        }

        fn write_awaits(&self, attr: &AttrDetails) -> bool {
            (**self).write_awaits(attr)
        }

        fn invoke_awaits(&self, cmd: &CmdDetails) -> bool {
            (**self).invoke_awaits(cmd)
        }

        async fn read<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            encoder: AttrDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            (**self).read(attr, encoder).await
        }

        async fn write<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            data: AttrData<'a>,
        ) -> Result<(), Error> {
            (**self).write(attr, data).await
        }

        async fn invoke<'a>(
            &'a self,
            exchange: &'a Exchange<'_>,
            cmd: &'a CmdDetails<'_>,
            data: &'a TLVElement<'_>,
            encoder: CmdDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            (**self).invoke(exchange, cmd, data, encoder).await
        }
    }

    impl<T> AsyncHandler for &T
    where
        T: AsyncHandler,
    {
        fn read_awaits(&self, attr: &AttrDetails) -> bool {
            (**self).read_awaits(attr)
        }

        fn write_awaits(&self, attr: &AttrDetails) -> bool {
            (**self).write_awaits(attr)
        }

        fn invoke_awaits(&self, cmd: &CmdDetails) -> bool {
            (**self).invoke_awaits(cmd)
        }

        async fn read<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            encoder: AttrDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            (**self).read(attr, encoder).await
        }

        async fn write<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            data: AttrData<'a>,
        ) -> Result<(), Error> {
            (**self).write(attr, data).await
        }

        async fn invoke<'a>(
            &'a self,
            exchange: &'a Exchange<'_>,
            cmd: &'a CmdDetails<'_>,
            data: &'a TLVElement<'_>,
            encoder: CmdDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            (**self).invoke(exchange, cmd, data, encoder).await
        }
    }

    impl<M, H> AsyncHandler for (M, H)
    where
        H: AsyncHandler,
    {
        fn read_awaits(&self, attr: &AttrDetails) -> bool {
            self.1.read_awaits(attr)
        }

        fn write_awaits(&self, attr: &AttrDetails) -> bool {
            self.1.write_awaits(attr)
        }

        fn invoke_awaits(&self, cmd: &CmdDetails) -> bool {
            self.1.invoke_awaits(cmd)
        }

        async fn read<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            encoder: AttrDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            self.1.read(attr, encoder).await
        }

        async fn write<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            data: AttrData<'a>,
        ) -> Result<(), Error> {
            self.1.write(attr, data).await
        }

        async fn invoke<'a>(
            &'a self,
            exchange: &'a Exchange<'_>,
            cmd: &'a CmdDetails<'_>,
            data: &'a TLVElement<'_>,
            encoder: CmdDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            self.1.invoke(exchange, cmd, data, encoder).await
        }
    }

    impl<T> AsyncHandler for HandlerCompat<T>
    where
        T: NonBlockingHandler,
    {
        fn read_awaits(&self, _attr: &AttrDetails) -> bool {
            false
        }

        fn write_awaits(&self, _attr: &AttrDetails) -> bool {
            false
        }

        fn invoke_awaits(&self, _cmd: &CmdDetails) -> bool {
            false
        }

        async fn read<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            encoder: AttrDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            Handler::read(&self.0, attr, encoder)
        }

        async fn write<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            data: AttrData<'a>,
        ) -> Result<(), Error> {
            Handler::write(&self.0, attr, data)
        }

        async fn invoke<'a>(
            &'a self,
            exchange: &'a Exchange<'_>,
            cmd: &'a CmdDetails<'_>,
            data: &'a TLVElement<'_>,
            encoder: CmdDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            Handler::invoke(&self.0, exchange, cmd, data, encoder)
        }
    }

    impl AsyncHandler for EmptyHandler {
        fn read_awaits(&self, _attr: &AttrDetails) -> bool {
            false
        }

        fn write_awaits(&self, _attr: &AttrDetails) -> bool {
            false
        }

        fn invoke_awaits(&self, _cmd: &CmdDetails) -> bool {
            false
        }

        async fn read<'a>(
            &'a self,
            _attr: &'a AttrDetails<'_>,
            _encoder: AttrDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            Err(ErrorCode::AttributeNotFound.into())
        }
    }

    impl<H, T> AsyncHandler for ChainedHandler<H, T>
    where
        H: AsyncHandler,
        T: AsyncHandler,
    {
        fn read_awaits(&self, attr: &AttrDetails) -> bool {
            if self.handler_endpoint == attr.endpoint_id && self.handler_cluster == attr.cluster_id
            {
                self.handler.read_awaits(attr)
            } else {
                self.next.read_awaits(attr)
            }
        }

        fn write_awaits(&self, attr: &AttrDetails) -> bool {
            if self.handler_endpoint == attr.endpoint_id && self.handler_cluster == attr.cluster_id
            {
                self.handler.write_awaits(attr)
            } else {
                self.next.write_awaits(attr)
            }
        }

        fn invoke_awaits(&self, cmd: &CmdDetails) -> bool {
            if self.handler_endpoint == cmd.endpoint_id && self.handler_cluster == cmd.cluster_id {
                self.handler.invoke_awaits(cmd)
            } else {
                self.next.invoke_awaits(cmd)
            }
        }

        async fn read<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            encoder: AttrDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            if self.handler_endpoint == attr.endpoint_id && self.handler_cluster == attr.cluster_id
            {
                self.handler.read(attr, encoder).await
            } else {
                self.next.read(attr, encoder).await
            }
        }

        async fn write<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            data: AttrData<'a>,
        ) -> Result<(), Error> {
            if self.handler_endpoint == attr.endpoint_id && self.handler_cluster == attr.cluster_id
            {
                self.handler.write(attr, data).await
            } else {
                self.next.write(attr, data).await
            }
        }

        async fn invoke<'a>(
            &'a self,
            exchange: &'a Exchange<'_>,
            cmd: &'a CmdDetails<'_>,
            data: &'a TLVElement<'_>,
            encoder: CmdDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            if self.handler_endpoint == cmd.endpoint_id && self.handler_cluster == cmd.cluster_id {
                self.handler.invoke(exchange, cmd, data, encoder).await
            } else {
                self.next.invoke(exchange, cmd, data, encoder).await
            }
        }
    }
}
