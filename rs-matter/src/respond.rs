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

use core::fmt::Display;
use core::pin::pin;

use embassy_futures::select::{select3, select_slice};

use log::{error, info};

use crate::data_model::core::{DataModel, IMBuffer};
use crate::data_model::objects::DataModelHandler;
use crate::data_model::subscriptions::Subscriptions;
use crate::error::{Error, ErrorCode};
use crate::interaction_model::busy::BusyInteractionModel;
use crate::secure_channel::busy::BusySecureChannel;
use crate::secure_channel::core::SecureChannel;
use crate::transport::exchange::Exchange;
use crate::utils::buf::BufferAccess;
use crate::utils::select::Coalesce;
use crate::Matter;

/// A trait modeling a generic handler for an exchange.
pub trait ExchangeHandler {
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error>;

    fn compose<T>(self, other: T) -> CompositeExchangeHandler<Self, T>
    where
        T: ExchangeHandler,
        Self: Sized,
    {
        CompositeExchangeHandler(self, other)
    }
}

impl<T> ExchangeHandler for &T
where
    T: ExchangeHandler,
{
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        (*self).handle(exchange).await
    }
}

/// A struct for composing two exchange handlers into a single one, where each handler is handling one specific protocol (i.e. SC vs IM).
pub struct CompositeExchangeHandler<F, S>(pub F, pub S);

impl<F, S> ExchangeHandler for CompositeExchangeHandler<F, S>
where
    F: ExchangeHandler,
    S: ExchangeHandler,
{
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let result = self.0.handle(exchange).await;

        match result {
            Err(e) if e.code() == ErrorCode::InvalidProto => self.1.handle(exchange).await,
            other => other,
        }
    }
}

/// A generic responder utility for accepting and handling exchanges received by the provided `Matter` stack,
/// by applying the provided `ExchangeHandler` instance to each accepted exchange.
///
/// This responder uses an intra-task concurrency model - without an external executor - where all handling is done as a single future.
pub struct Responder<'a, T> {
    name: &'a str,
    handler: T,
    matter: &'a Matter<'a>,
    respond_after_ms: u64,
}

impl<'a, T> Responder<'a, T>
where
    T: ExchangeHandler,
{
    /// Create a new responder.
    ///
    /// The `respond_after_ms` parameter instructs the responder how much time to wait before accepting an exchange.
    ///
    /// This is useful when utilizing multiple responders on a single `Matter` instance, where e.g. the first (main) responder is the actual one,
    /// responsible for handling the incoming exchanges, while e.g. another one - with a non-zero `respond_after_ms` - is answerring all exchanges
    /// not accepted in time by the main responder with a simple "I'm busy, try again later" handling.
    #[inline(always)]
    pub const fn new(
        name: &'a str,
        handler: T,
        matter: &'a Matter<'a>,
        respond_after_ms: u64,
    ) -> Self {
        Self {
            name,
            handler,
            matter,
            respond_after_ms,
        }
    }

    /// Get a reference to the `ExchangeHandler` instance used by this responder
    pub fn handler(&self) -> &T {
        &self.handler
    }

    /// Run the responder with a given number of handlers.
    pub async fn run<const N: usize>(&self) -> Result<(), Error> {
        info!("{}: Creating {N} handlers", self.name);

        let mut handlers = heapless::Vec::<_, N>::new();
        info!(
            "{}: Handlers size: {}B",
            self.name,
            core::mem::size_of_val(&handlers)
        );

        for index in 0..N {
            let handler_id = (index as u8) + 2;

            handlers
                .push(self.handle(handler_id))
                .map_err(|_| ())
                .unwrap();
        }

        select_slice(&mut handlers).await.0
    }

    #[inline(always)]
    async fn handle(&self, handler_id: impl Display) -> Result<(), Error> {
        loop {
            let _ = self.respond_once(&handler_id).await;
        }
    }

    /// Respond to a single exchange.
    /// Useful in e.g. integration tests, where we know that we are expecting to respond to a single exchange within the run of the test.
    #[inline(always)]
    pub async fn respond_once(&self, handler_id: impl Display) -> Result<(), Error> {
        let mut exchange = Exchange::accept_after(self.matter, self.respond_after_ms).await?;

        info!(
            "{}: Handler {handler_id} / exchange {}: Starting",
            self.name,
            exchange.id()
        );

        let result = self.handler.handle(&mut exchange).await;

        if let Err(err) = &result {
            error!(
                "{}: Handler {handler_id} / exchange {}: Abandoned because of error {err:?}",
                self.name,
                exchange.id()
            );
        } else {
            info!(
                "{}: Handler {handler_id} / exchange {}: Completed",
                self.name,
                exchange.id()
            );
        }

        result
    }
}

impl<'a, const N: usize, B, T>
    Responder<'a, CompositeExchangeHandler<DataModel<'a, N, B, T>, SecureChannel>>
where
    B: BufferAccess<IMBuffer>,
{
    /// Creates a "default" responder. This is a responder that composes and uses the `rs-matter`-provided `ExchangeHandler` implementations
    /// (`SecureChannel` and `DataModel`) for handling the Secure Channel protocol and the Interaction Model protocol.
    #[inline(always)]
    pub const fn new_default(
        matter: &'a Matter<'a>,
        buffers: &'a B,
        subscriptions: &'a Subscriptions<N>,
        dm_handler: T,
    ) -> Self
    where
        T: DataModelHandler,
    {
        Self::new(
            "Responder",
            CompositeExchangeHandler(
                DataModel::new(buffers, subscriptions, dm_handler),
                SecureChannel::new(),
            ),
            matter,
            0,
        )
    }
}

impl<'a> Responder<'a, CompositeExchangeHandler<BusyInteractionModel, BusySecureChannel>> {
    /// Creates a simple "busy" responder, which is answering all exchanges with a simple "I'm busy, try again later" handling.
    /// The resonder is using the `rs-matter`-provided `ExchangeHandler` instances (`BusySecureChannel` and `BusyInteractionModel`)
    /// capable of answering with "busy" messages the SC and IM protocols, respectively.
    ///
    /// Exchanges which are not accepted after 200ms are answered by this responder, as the assumption is that the main responder is
    /// busy and cannot answer these right now.
    #[inline(always)]
    pub const fn new_busy(matter: &'a Matter<'a>) -> Self {
        Self::new(
            "Busy Responder",
            CompositeExchangeHandler(BusyInteractionModel::new(), BusySecureChannel::new()),
            matter,
            200,
        )
    }
}

/// A composition of the `Responder::new_default` and `Responder::new_busy` responders.
pub struct DefaultResponder<'a, const N: usize, B, T>
where
    B: BufferAccess<IMBuffer>,
{
    responder: Responder<'a, CompositeExchangeHandler<DataModel<'a, N, B, T>, SecureChannel>>,
    busy_responder:
        Responder<'a, CompositeExchangeHandler<BusyInteractionModel, BusySecureChannel>>,
}

impl<'a, const N: usize, B, T> DefaultResponder<'a, N, B, T>
where
    B: BufferAccess<IMBuffer>,
    T: DataModelHandler,
{
    /// Creates the responder composition.
    #[inline(always)]
    pub const fn new(
        matter: &'a Matter<'a>,
        buffers: &'a B,
        subscriptions: &'a Subscriptions<N>,
        dm_handler: T,
    ) -> Self {
        Self {
            responder: Responder::new_default(matter, buffers, subscriptions, dm_handler),
            busy_responder: Responder::new_busy(matter),
        }
    }

    /// Run the responder.
    pub async fn run<const A: usize, const O: usize>(&self) -> Result<(), Error> {
        let mut actual = pin!(self.responder.run::<A>());
        let mut busy = pin!(self.busy_responder.run::<O>());
        let mut sub = pin!(self
            .responder
            .handler()
            .0
            .process_subscriptions(self.responder.matter));

        select3(&mut actual, &mut busy, &mut sub).coalesce().await
    }
}
