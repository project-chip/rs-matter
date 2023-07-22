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

#[cfg(feature = "nightly")]
pub use asynch::*;

#[cfg(not(feature = "nightly"))]
pub trait DataModelHandler: super::Metadata + Handler {}
#[cfg(not(feature = "nightly"))]
impl<T> DataModelHandler for T where T: super::Metadata + Handler {}

#[cfg(feature = "nightly")]
pub trait DataModelHandler: super::asynch::AsyncMetadata + asynch::AsyncHandler {}
#[cfg(feature = "nightly")]
impl<T> DataModelHandler for T where T: super::asynch::AsyncMetadata + asynch::AsyncHandler {}

pub trait ChangeNotifier<T> {
    fn consume_change(&mut self) -> Option<T>;
}

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

pub struct EmptyHandler;

impl EmptyHandler {
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

pub struct ChainedHandler<H, T> {
    pub handler_endpoint: u16,
    pub handler_cluster: u32,
    pub handler: H,
    pub next: T,
}

impl<H, T> ChainedHandler<H, T> {
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

#[cfg(feature = "nightly")]
mod asynch {
    use crate::{
        data_model::objects::{AttrData, AttrDataEncoder, AttrDetails, CmdDataEncoder, CmdDetails},
        error::{Error, ErrorCode},
        tlv::TLVElement,
        transport::exchange::Exchange,
    };

    use super::{ChainedHandler, EmptyHandler, Handler, HandlerCompat, NonBlockingHandler};

    pub trait AsyncHandler {
        async fn read<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            encoder: AttrDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error>;

        async fn write<'a>(
            &'a self,
            _attr: &'a AttrDetails<'_>,
            _data: AttrData<'a>,
        ) -> Result<(), Error> {
            Err(ErrorCode::AttributeNotFound.into())
        }

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
