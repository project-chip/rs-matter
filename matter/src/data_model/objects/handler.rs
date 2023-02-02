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

use crate::{error::Error, interaction_model::core::Transaction, tlv::TLVElement};

use super::{AttrData, AttrDataEncoder, AttrDetails, CmdDataEncoder, CmdDetails};

pub trait ChangeNotifier<T> {
    fn consume_change(&mut self) -> Option<T>;
}

pub trait Handler {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error>;

    fn write(&mut self, _attr: &AttrDetails, _data: AttrData) -> Result<(), Error> {
        Err(Error::AttributeNotFound)
    }

    fn invoke(
        &mut self,
        _transaction: &mut Transaction,
        _cmd: &CmdDetails,
        _data: &TLVElement,
        _encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        Err(Error::CommandNotFound)
    }
}

impl<T> Handler for &mut T
where
    T: Handler,
{
    fn read<'a>(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        (**self).read(attr, encoder)
    }

    fn write(&mut self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        (**self).write(attr, data)
    }

    fn invoke(
        &mut self,
        transaction: &mut Transaction,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        (**self).invoke(transaction, cmd, data, encoder)
    }
}

pub trait NonBlockingHandler: Handler {}

impl<T> NonBlockingHandler for &mut T where T: NonBlockingHandler {}

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
        Err(Error::AttributeNotFound)
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

    fn write(&mut self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        if self.handler_endpoint == attr.endpoint_id && self.handler_cluster == attr.cluster_id {
            self.handler.write(attr, data)
        } else {
            self.next.write(attr, data)
        }
    }

    fn invoke(
        &mut self,
        transaction: &mut Transaction,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        if self.handler_endpoint == cmd.endpoint_id && self.handler_cluster == cmd.cluster_id {
            self.handler.invoke(transaction, cmd, data, encoder)
        } else {
            self.next.invoke(transaction, cmd, data, encoder)
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

#[allow(unused_macros)]
#[macro_export]
macro_rules! handler_chain_type {
    ($h:ty) => {
        $crate::data_model::objects::ChainedHandler<$h, $crate::data_model::objects::EmptyHandler>
    };
    ($h1:ty, $($rest:ty),+) => {
        $crate::data_model::objects::ChainedHandler<$h1, handler_chain_type!($($rest),+)>
    };
}

#[cfg(feature = "nightly")]
pub mod asynch {
    use crate::{
        data_model::objects::{AttrData, AttrDataEncoder, AttrDetails, CmdDataEncoder, CmdDetails},
        error::Error,
        interaction_model::core::Transaction,
        tlv::TLVElement,
    };

    use super::{ChainedHandler, EmptyHandler, Handler, NonBlockingHandler};

    pub trait AsyncHandler {
        async fn read<'a>(
            &'a self,
            attr: &'a AttrDetails<'_>,
            encoder: AttrDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error>;

        async fn write<'a>(
            &'a mut self,
            _attr: &'a AttrDetails<'_>,
            _data: AttrData<'a>,
        ) -> Result<(), Error> {
            Err(Error::AttributeNotFound)
        }

        async fn invoke<'a>(
            &'a mut self,
            _transaction: &'a mut Transaction<'_, '_>,
            _cmd: &'a CmdDetails<'_>,
            _data: &'a TLVElement<'_>,
            _encoder: CmdDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            Err(Error::CommandNotFound)
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
            &'a mut self,
            attr: &'a AttrDetails<'_>,
            data: AttrData<'a>,
        ) -> Result<(), Error> {
            (**self).write(attr, data).await
        }

        async fn invoke<'a>(
            &'a mut self,
            transaction: &'a mut Transaction<'_, '_>,
            cmd: &'a CmdDetails<'_>,
            data: &'a TLVElement<'_>,
            encoder: CmdDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            (**self).invoke(transaction, cmd, data, encoder).await
        }
    }

    pub struct Asyncify<T>(pub T);

    impl<T> AsyncHandler for Asyncify<T>
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
            &'a mut self,
            attr: &'a AttrDetails<'_>,
            data: AttrData<'a>,
        ) -> Result<(), Error> {
            Handler::write(&mut self.0, attr, data)
        }

        async fn invoke<'a>(
            &'a mut self,
            transaction: &'a mut Transaction<'_, '_>,
            cmd: &'a CmdDetails<'_>,
            data: &'a TLVElement<'_>,
            encoder: CmdDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            Handler::invoke(&mut self.0, transaction, cmd, data, encoder)
        }
    }

    impl AsyncHandler for EmptyHandler {
        async fn read<'a>(
            &'a self,
            _attr: &'a AttrDetails<'_>,
            _encoder: AttrDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            Err(Error::AttributeNotFound)
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
            &'a mut self,
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
            &'a mut self,
            transaction: &'a mut Transaction<'_, '_>,
            cmd: &'a CmdDetails<'_>,
            data: &'a TLVElement<'_>,
            encoder: CmdDataEncoder<'a, '_, '_>,
        ) -> Result<(), Error> {
            if self.handler_endpoint == cmd.endpoint_id && self.handler_cluster == cmd.cluster_id {
                self.handler.invoke(transaction, cmd, data, encoder).await
            } else {
                self.next.invoke(transaction, cmd, data, encoder).await
            }
        }
    }
}
