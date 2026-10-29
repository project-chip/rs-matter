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

//! The responders: what accepts the incoming exchanges of a `Matter` instance and
//! hands each of them to the handler of its protocol.
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(async_fn_in_trait)]
#![allow(unknown_lints)]
#![allow(clippy::uninlined_format_args)]
// `cargo llvm-cov` sets `coverage_nightly` when it runs on a nightly toolchain;
// the test modules are then excluded from the coverage report
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use core::fmt::Display;
use core::future::Future;
use core::pin::{pin, Pin};

use rs_matter_bdx::{Bdx, BdxHandler};
use rs_matter_crypto::Crypto;
use rs_matter_dm_core::persist::KvBlobStoreAccess;
use rs_matter_dm_core::{AttrChangeNotifier, DataModel, IMBuffer};
use rs_matter_im::busy::BusyInteractionModel;
use rs_matter_im::events::DEFAULT_MAX_EVENTS_BUF_SIZE;
use rs_matter_im::subscriptions::DEFAULT_MAX_SUBSCRIPTIONS;
use rs_matter_im::{InteractionModel, ReportDataHandler, PROTO_ID_INTERACTION_MODEL};
use rs_matter_node::transport::exchange::Exchange;
use rs_matter_node::Matter;
use rs_matter_sc::busy::BusySecureChannel;
use rs_matter_sc::{AsyncScHandler, ScHost, SecureChannel};
use rs_matter_utils::error::Error;
use rs_matter_utils::futures::{select, select_slice, Coalesce};
use rs_matter_utils::storage::pooled::Buffers;
use rs_matter_utils::storage::Vec;
use rs_matter_utils::sync::{MaybeSend, MaybeSendSync};

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

/// Send a busy response if - after that many ms - the exchange
/// is still not accepted by the regular handlers.
const RESPOND_BUSY_MS: u32 = 500;

/// A trait modeling a generic handler for an exchange.
///
/// The handler takes ownership of the exchange: once handling is done, the only
/// thing left to do with the exchange is to drop it (which ends it).
pub trait ExchangeHandler: MaybeSendSync {
    fn handle(&self, exchange: Exchange<'_>)
        -> impl Future<Output = Result<(), Error>> + MaybeSend;
}

impl<T> ExchangeHandler for &T
where
    T: ExchangeHandler,
{
    fn handle(&self, exchange: Exchange<'_>) -> impl Future<Output = Result<(), Error>> {
        (*self).handle(exchange)
    }
}

impl<C, B, T, K, R, const NS: usize, const NE: usize> ExchangeHandler
    for InteractionModel<'_, C, B, T, K, R, NS, NE>
where
    C: Crypto,
    B: Buffers<IMBuffer>,
    T: DataModel,
    K: KvBlobStoreAccess,
    R: ReportDataHandler,
{
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        InteractionModel::handle(self, &mut exchange).await
    }
}

impl ExchangeHandler for BusyInteractionModel {
    fn handle(&self, exchange: Exchange<'_>) -> impl Future<Output = Result<(), Error>> {
        BusyInteractionModel::handle(self, exchange)
    }
}

impl<M: ScHost, C: Crypto, N: AttrChangeNotifier + MaybeSendSync, H: AsyncScHandler> ExchangeHandler
    for SecureChannel<'_, M, C, N, H>
{
    fn handle(
        &self,
        exchange: Exchange<'_>,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        SecureChannel::handle(self, exchange)
    }
}

impl ExchangeHandler for BusySecureChannel {
    fn handle(&self, exchange: Exchange<'_>) -> impl Future<Output = Result<(), Error>> {
        BusySecureChannel::handle(self, exchange)
    }
}

impl<T: BdxHandler> ExchangeHandler for Bdx<T> {
    fn handle(&self, exchange: Exchange<'_>) -> impl Future<Output = Result<(), Error>> {
        Bdx::handle(self, exchange)
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
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        // Peek the protocol id of the incoming message, then hand the exchange
        // (by value) to the matching handler.
        exchange.recv_fetch().await?;
        let proto_id = exchange.rx()?.meta().proto_id;

        if proto_id == self.handler_proto {
            self.handler.handle(exchange).await
        } else {
            self.next.handle(exchange).await
        }
    }
}

/// An [`ExchangeHandler`] that handles nothing - a convenient terminator for a
/// [`ChainedExchangeHandler`].
///
/// By the time the chain reaches it, no handler matched the incoming protocol, so
/// it simply drops the exchange (sending no reply); the peer will time out and
/// retry as it would against any unsupported protocol.
pub struct EmptyExchangeHandler;

impl ExchangeHandler for EmptyExchangeHandler {
    async fn handle(&self, _exchange: Exchange<'_>) -> Result<(), Error> {
        Ok(())
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

        let mut handlers = Vec::<_, N>::new();
        debug!(
            "{}: Handlers size: {}B",
            self.name,
            core::mem::size_of_val(&handlers)
        );

        for handler_id in 0..N {
            unwrap!(handlers.push(self.handle(handler_id)).map_err(|_| ())); // Cannot fail because the vector has size N
        }

        // Pin the vector in place rather than via `pin!(handlers)`: `pin!` moves its argument
        // into a fresh temporary, and since `handlers` was already mutated (by the `push` loop
        // above) the compiler keeps both the moved-from local and the temporary alive in the
        // generated future - i.e. the handlers, which dominate the size of this future, would
        // be stored twice. The shadowing is load-bearing: it makes the original vector
        // unnameable, so nothing can move it before it is dropped in place at scope end.
        let handlers = unsafe { Pin::new_unchecked(handlers.as_mut_slice()) };

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
        let exchange =
            Exchange::accept_after(self.matter.transport(), self.respond_after_ms).await?;
        // Capture the id up front: the handler takes the exchange by value.
        let exchange_id = exchange.id();

        if self.log_warn() {
            warn!(
                "{}: Handler {} / exchange {}: Starting",
                self.name,
                display2format!(&handler_id),
                exchange_id
            );
        } else {
            debug!(
                "{}: Handler {} / exchange {}: Starting",
                self.name,
                display2format!(&handler_id),
                exchange_id
            );
        }

        let result = self.handler.handle(exchange).await;

        if let Err(err) = &result {
            error!(
                "{}: Handler {} / exchange {}: Abandoned because of error {:?}",
                self.name,
                display2format!(&handler_id),
                exchange_id,
                err
            );
        } else if self.log_warn() {
            warn!(
                "{}: Handler {} / exchange {}: Completed",
                self.name,
                display2format!(&handler_id),
                exchange_id
            );
        } else {
            debug!(
                "{}: Handler {} / exchange {}: Completed",
                self.name,
                display2format!(&handler_id),
                exchange_id
            );
        }

        result
    }

    fn log_warn(&self) -> bool {
        self.respond_after_ms > 0
    }
}

/// A type alias for the "default" responder handler, which is a chained handler of the `InteractionModel` and `SecureChannel` handlers.
pub type DefaultExchangeHandler<
    'd,
    'a,
    C,
    B,
    T,
    K,
    R = (),
    const NS: usize = DEFAULT_MAX_SUBSCRIPTIONS,
    const NE: usize = DEFAULT_MAX_EVENTS_BUF_SIZE,
> = ChainedExchangeHandler<
    &'d InteractionModel<'a, C, B, T, K, R, NS, NE>,
    SecureChannel<'a, Matter<'a>, &'d C, &'d InteractionModel<'a, C, B, T, K, R, NS, NE>>,
>;

impl<'d, 'a, C, B, T, K, R, const NS: usize, const NE: usize>
    Responder<'a, DefaultExchangeHandler<'d, 'a, C, B, T, K, R, NS, NE>>
where
    B: Buffers<IMBuffer>,
{
    /// Creates a "default" responder. This is a responder that composes and uses the `rs-matter`-provided `ExchangeHandler` implementations
    /// (`SecureChannel` and `InteractionModel`) for handling the Secure Channel protocol and the Interaction Model protocol.
    #[inline(always)]
    pub const fn new_default(data_model: &'d InteractionModel<'a, C, B, T, K, R, NS, NE>) -> Self
    where
        C: Crypto,
        T: DataModel,
        K: KvBlobStoreAccess,
        R: ReportDataHandler,
    {
        Self::new(
            "Responder",
            ChainedExchangeHandler::new(
                PROTO_ID_INTERACTION_MODEL,
                data_model,
                SecureChannel::new(data_model.matter(), data_model.crypto(), data_model),
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
pub struct DefaultResponder<
    'd,
    'a,
    C,
    B,
    T,
    K,
    R = (),
    const NS: usize = DEFAULT_MAX_SUBSCRIPTIONS,
    const NE: usize = DEFAULT_MAX_EVENTS_BUF_SIZE,
> where
    B: Buffers<IMBuffer>,
{
    responder: Responder<'a, DefaultExchangeHandler<'d, 'a, C, B, T, K, R, NS, NE>>,
    busy_responder: Responder<'a, BusyExchangeHandler>,
}

impl<'d, 'a, C, B, T, K, R, const NS: usize, const NE: usize>
    DefaultResponder<'d, 'a, C, B, T, K, R, NS, NE>
where
    C: Crypto,
    B: Buffers<IMBuffer>,
    T: DataModel,
    K: KvBlobStoreAccess,
    R: ReportDataHandler,
{
    /// Creates the responder composition.
    #[inline(always)]
    pub const fn new(data_model: &'d InteractionModel<'a, C, B, T, K, R, NS, NE>) -> Self {
        Self {
            responder: Responder::new_default(data_model),
            busy_responder: Responder::new_busy(data_model.matter(), RESPOND_BUSY_MS),
        }
    }

    /// Run the responder.
    pub async fn run<const A: usize, const O: usize>(&self) -> Result<(), Error> {
        let mut actual = pin!(self.responder.run::<A>());
        let mut busy = pin!(self.busy_responder.run::<O>());

        select(&mut actual, &mut busy).coalesce().await
    }

    /// Get a reference to the main responder.
    ///
    /// Useful when the user would like to organize its own herd of responders rather than using the `run` method.
    #[allow(clippy::type_complexity)]
    pub const fn responder(
        &self,
    ) -> &Responder<
        'a,
        ChainedExchangeHandler<
            &'d InteractionModel<'a, C, B, T, K, R, NS, NE>,
            SecureChannel<'a, Matter<'a>, &'d C, &'d InteractionModel<'a, C, B, T, K, R, NS, NE>>,
        >,
    > {
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
}
