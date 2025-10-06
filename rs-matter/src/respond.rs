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
use core::future::Future;
use core::pin::pin;

use embassy_futures::select::{select3, select_slice};

use crate::dm::DataModelHandler;
use crate::dm::{DataModel, IMBuffer};
use crate::error::Error;
use crate::im::busy::BusyInteractionModel;
use crate::im::PROTO_ID_INTERACTION_MODEL;
use crate::sc::busy::BusySecureChannel;
use crate::sc::SecureChannel;
use crate::transport::exchange::Exchange;
use crate::utils::select::Coalesce;
use crate::utils::storage::pooled::BufferAccess;
use crate::Matter;

/// Send a busy response if - after that many ms - the exchange
/// is still not accepted by the regular handlers.
const RESPOND_BUSY_MS: u32 = 500;

/// A trait modeling a generic handler for an exchange.
pub trait ExchangeHandler {
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error>;
}

impl<T> ExchangeHandler for &T
where
    T: ExchangeHandler,
{
    fn handle(&self, exchange: &mut Exchange<'_>) -> impl Future<Output = Result<(), Error>> {
        (*self).handle(exchange)
    }
}

/// A struct for chaining two exchange handlers into a single one,
/// where each handler is handling one specific protocol (i.e. SC vs IM) in a sequential fashion.
/// I.e. if the first exchange handler refuses to handle the exchange, the second one is tried.
pub struct ChainedExchangeHandler<H, T> {
    pub handler_proto: u16,
    pub handler: H,
    pub next: T,
}

impl<H, T> ChainedExchangeHandler<H, T> {
    /// Construct a chained handler that works as follows:
    /// - It will call the provided `handler` instance if the protocol ID of the incoming message does match the supplied `handler_proto` value.
    /// - Otherwise, it will call the `next` handler
    pub const fn new(handler_proto: u16, handler: H, next: T) -> Self {
        Self {
            handler_proto,
            handler,
            next,
        }
    }

    /// Chain itself with another exchange handler.
    ///
    /// The returned chained handler works as follows:
    /// - It will call the provided `handler` instance if the protocol ID of the incoming message does match the supplied `handler_proto` value.
    /// - Otherwise, it will call the `self` handler
    pub const fn chain<H2>(
        self,
        handler_proto: u16,
        handler: H2,
    ) -> ChainedExchangeHandler<H2, Self> {
        ChainedExchangeHandler::new(handler_proto, handler, self)
    }
}

impl<H, T> ExchangeHandler for ChainedExchangeHandler<H, T>
where
    H: ExchangeHandler,
    T: ExchangeHandler,
{
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let rx = exchange.recv_fetch().await?;

        if rx.meta().proto_id == self.handler_proto {
            self.handler.handle(exchange).await
        } else {
            self.next.handle(exchange).await
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
    respond_after_ms: u32,
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
        respond_after_ms: u32,
    ) -> Self {
        Self {
            name,
            handler,
            matter,
            respond_after_ms,
        }
    }

    /// Get the name of this responder
    pub const fn name(&self) -> &str {
        self.name
    }

    /// Get a reference to the `ExchangeHandler` instance used by this responder
    pub fn handler(&self) -> &T {
        &self.handler
    }

    /// Run the responder with a given number of handlers.
    pub async fn run<const N: usize>(&self) -> Result<(), Error> {
        info!("{}: Creating {} handlers", self.name, N);

        let mut handlers = heapless::Vec::<_, N>::new();
        debug!(
            "{}: Handlers size: {}B",
            self.name,
            core::mem::size_of_val(&handlers)
        );

        for handler_id in 0..N {
            unwrap!(handlers.push(self.handle(handler_id)).map_err(|_| ())); // Cannot fail because the vector has size N
        }

        let handlers = pin!(handlers);
        let handlers = unsafe { handlers.map_unchecked_mut(|handlers| handlers.as_mut_slice()) };

        select_slice(handlers).await.0
    }

    /// A handler for one exchange.
    #[inline(always)]
    pub async fn handle(&self, handler_id: impl Display) -> Result<(), Error> {
        loop {
            // Ignore the error as it had been logged already
            let _ = self.respond_once(&handler_id).await;
        }
    }

    /// Respond to a single exchange.
    /// Useful in e.g. integration tests, where we know that we are expecting to respond to a single exchange within the run of the test.
    #[inline(always)]
    pub async fn respond_once(&self, handler_id: impl Display) -> Result<(), Error> {
        let mut exchange = Exchange::accept_after(self.matter, self.respond_after_ms).await?;

        if self.log_warn() {
            warn!(
                "{}: Handler {} / exchange {}: Starting",
                self.name,
                display2format!(&handler_id),
                exchange.id()
            );
        } else {
            debug!(
                "{}: Handler {} / exchange {}: Starting",
                self.name,
                display2format!(&handler_id),
                exchange.id()
            );
        }

        let result = self.handler.handle(&mut exchange).await;

        if let Err(err) = &result {
            error!(
                "{}: Handler {} / exchange {}: Abandoned because of error {:?}",
                self.name,
                display2format!(&handler_id),
                exchange.id(),
                err
            );
        } else if self.log_warn() {
            warn!(
                "{}: Handler {} / exchange {}: Completed",
                self.name,
                display2format!(&handler_id),
                exchange.id()
            );
        } else {
            debug!(
                "{}: Handler {} / exchange {}: Completed",
                self.name,
                display2format!(&handler_id),
                exchange.id()
            );
        }

        result
    }

    fn log_warn(&self) -> bool {
        self.respond_after_ms > 0
    }
}

/// A type alias for the "default" responder handler, which is a chained handler of the `DataModel` and `SecureChannel` handlers.
pub type DefaultExchangeHandler<'d, 'a, const N: usize, B, T> =
    ChainedExchangeHandler<&'d DataModel<'a, N, B, T>, SecureChannel>;

impl<'d, 'a, const N: usize, B, T> Responder<'a, DefaultExchangeHandler<'d, 'a, N, B, T>>
where
    B: BufferAccess<IMBuffer>,
{
    /// Creates a "default" responder. This is a responder that composes and uses the `rs-matter`-provided `ExchangeHandler` implementations
    /// (`SecureChannel` and `DataModel`) for handling the Secure Channel protocol and the Interaction Model protocol.
    #[inline(always)]
    pub const fn new_default(data_model: &'d DataModel<'a, N, B, T>) -> Self
    where
        T: DataModelHandler,
    {
        Self::new(
            "Responder",
            ChainedExchangeHandler::new(
                PROTO_ID_INTERACTION_MODEL,
                data_model,
                SecureChannel::new(),
            ),
            data_model.matter(),
            0,
        )
    }
}

/// A type alias for the "busy" responder handler, which is a chained handler of the `BusyInteractionModel` and `BusySecureChannel` handlers.
pub type BusyExchangeHandler = ChainedExchangeHandler<BusyInteractionModel, BusySecureChannel>;

impl<'a> Responder<'a, BusyExchangeHandler> {
    /// Creates a simple "busy" responder, which is answering all exchanges with a simple "I'm busy, try again later" handling.
    /// The resonder is using the `rs-matter`-provided `ExchangeHandler` instances (`BusySecureChannel` and `BusyInteractionModel`)
    /// capable of answering with "busy" messages the SC and IM protocols, respectively.
    ///
    /// Exchanges which are not accepted after the specified milliseconds are answered by this responder,
    /// as the assumption is that the main responder is busy and cannot answer these right now.
    #[inline(always)]
    pub const fn new_busy(matter: &'a Matter<'a>, respond_after_ms: u32) -> Self {
        Self::new(
            "Busy Responder",
            ChainedExchangeHandler::new(
                PROTO_ID_INTERACTION_MODEL,
                BusyInteractionModel::new(),
                BusySecureChannel::new(),
            ),
            matter,
            respond_after_ms,
        )
    }
}

/// A composition of the `Responder::new_default` and `Responder::new_busy` responders.
pub struct DefaultResponder<'d, 'a, const N: usize, B, T>
where
    B: BufferAccess<IMBuffer>,
{
    responder: Responder<'a, DefaultExchangeHandler<'d, 'a, N, B, T>>,
    busy_responder: Responder<'a, BusyExchangeHandler>,
}

impl<'d, 'a, const N: usize, B, T> DefaultResponder<'d, 'a, N, B, T>
where
    B: BufferAccess<IMBuffer>,
    T: DataModelHandler,
{
    /// Creates the responder composition.
    #[inline(always)]
    pub const fn new(data_model: &'d DataModel<'a, N, B, T>) -> Self {
        Self {
            responder: Responder::new_default(data_model),
            busy_responder: Responder::new_busy(data_model.matter(), RESPOND_BUSY_MS),
        }
    }

    /// Run the responder.
    pub async fn run<const A: usize, const O: usize>(&self) -> Result<(), Error> {
        let mut actual = pin!(self.responder.run::<A>());
        let mut busy = pin!(self.busy_responder.run::<O>());
        let mut sub = pin!(self.process_subscriptions());

        select3(&mut actual, &mut busy, &mut sub).coalesce().await
    }

    /// Get a reference to the main responder.
    ///
    /// Useful when the user would like to organize its own herd of responders rather than using the `run` method.
    pub const fn responder(
        &self,
    ) -> &Responder<'a, ChainedExchangeHandler<&'d DataModel<'a, N, B, T>, SecureChannel>> {
        &self.responder
    }

    /// Get a reference to the busy responder.
    ///
    /// Useful when the user would like to organize its own herd of busy responders rather than using the `run` method.
    pub const fn busy_responder(
        &self,
    ) -> &Responder<'a, ChainedExchangeHandler<BusyInteractionModel, BusySecureChannel>> {
        &self.busy_responder
    }

    /// Process subscriptions.
    ///
    /// Useful when the user would like to call `process_subscriptions` manually rather than using the `run` method.
    pub async fn process_subscriptions(&self) -> Result<(), Error> {
        let mut process = pin!(self
            .responder
            .handler()
            .handler
            .process_subscriptions(self.responder.matter));

        (&mut process).await
    }
}
