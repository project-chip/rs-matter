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

//! Composing BDX handlers behind a single `PROTO_ID_BDX` exchange handler.
//!
//! [`Bdx`] is the [`ExchangeHandler`] that owns the BDX protocol in a responder's
//! handler chain. For each incoming transfer it accepts the opening `*Init` into a
//! [`BdxResponder`] (a download or an upload) and dispatches it to a
//! [`BdxHandler`].
//!
//! Multiple handlers are composed by nesting [`ChainedBdxHandler`]s (terminated by
//! [`EmptyBdxHandler`]), so several can share `PROTO_ID_BDX` while owning disjoint
//! file-designator namespaces - e.g. an OTA Provider serving images alongside a
//! Diagnostic Logs client receiving logs.

use crate::respond::ExchangeHandler;

use super::nego::abort;
use super::*;

/// An accepted, not-yet-answered BDX transfer, in one of the two directions:
/// `Download` (a peer wants to download from us - we send) or `Upload` (a peer
/// wants to upload to us - we receive).
pub enum BdxResponder<'a> {
    /// A peer's download request; reply to send the data via a [`BdxWriter`].
    Download(BdxDownloadResponder<'a>),
    /// A peer's upload request; reply to receive the data via a [`BdxReader`].
    Upload(BdxUploadResponder<'a>),
}

impl BdxResponder<'_> {
    /// The file designator the peer named (borrowed from the held `*Init`).
    pub fn fd(&self) -> &[u8] {
        match self {
            Self::Download(responder) => responder.fd(),
            Self::Upload(responder) => responder.fd(),
        }
    }

    /// Reject the transfer with the given status.
    pub async fn reject(self, status: BdxStatus) -> Result<(), Error> {
        match self {
            Self::Download(responder) => responder.reject(status).await,
            Self::Upload(responder) => responder.reject(status).await,
        }
    }
}

/// A device-specific BDX handler: one or more "files" - identified by their BDX
/// file designator and direction - that this node serves (a download) or
/// processes (an upload).
///
/// [`handles`](Self::handles) selects which transfers this handler owns; only a
/// [`BdxResponder`] it claims is passed to [`handle`](Self::handle). The default
/// `handle` rejects with `FileDesignatorUnknown`.
pub trait BdxHandler {
    /// Whether this handler owns the transfer described by `responder` (by its
    /// direction and file designator). Consulted before [`handle`](Self::handle),
    /// so it must not consume the responder.
    async fn handles(&self, _responder: &BdxResponder<'_>) -> bool {
        false
    }

    /// Handle a transfer this handler [`handles`](Self::handles): reply on (and
    /// drive) the [`BdxResponder`], or [`reject`](BdxResponder::reject) it.
    async fn handle(&self, responder: BdxResponder<'_>) -> Result<(), Error> {
        responder.reject(BdxStatus::FileDesignatorUnknown).await
    }
}

/// `&T` is a [`BdxHandler`] whenever `T` is, so a handler can be composed (into a
/// [`ChainedBdxHandler`]) or wrapped (in [`Bdx`]) by shared reference, without
/// giving up ownership of it.
impl<T> BdxHandler for &T
where
    T: BdxHandler,
{
    async fn handles(&self, responder: &BdxResponder<'_>) -> bool {
        T::handles(self, responder).await
    }

    async fn handle(&self, responder: BdxResponder<'_>) -> Result<(), Error> {
        T::handle(self, responder).await
    }
}

/// A [`BdxHandler`] that handles nothing - the terminator of a
/// [`ChainedBdxHandler`]. Every transfer routed to it is rejected with
/// `FileDesignatorUnknown`.
pub struct EmptyBdxHandler;

impl BdxHandler for EmptyBdxHandler {}

/// Two [`BdxHandler`]s composed into one: `handler` is consulted first (via
/// [`handles`](BdxHandler::handles)), then `next`. Nest these (terminated by
/// [`EmptyBdxHandler`]) to compose more than two.
pub struct ChainedBdxHandler<H, T> {
    /// The handler consulted first.
    pub handler: H,
    /// The handler consulted if `handler` does not match.
    pub next: T,
}

impl<H, T> ChainedBdxHandler<H, T> {
    /// Create a chained handler consulting `handler` before `next`.
    pub const fn new(handler: H, next: T) -> Self {
        Self { handler, next }
    }
}

impl<H, T> BdxHandler for ChainedBdxHandler<H, T>
where
    H: BdxHandler,
    T: BdxHandler,
{
    async fn handles(&self, responder: &BdxResponder<'_>) -> bool {
        self.handler.handles(responder).await || self.next.handles(responder).await
    }

    async fn handle(&self, responder: BdxResponder<'_>) -> Result<(), Error> {
        if self.handler.handles(&responder).await {
            self.handler.handle(responder).await
        } else {
            self.next.handle(responder).await
        }
    }
}

/// An [`ExchangeHandler`] for the BDX protocol ([`PROTO_ID_BDX`]) that accepts each
/// incoming transfer into a [`BdxResponder`] and dispatches it to the wrapped
/// [`BdxHandler`].
///
/// Chain it into your responder's handler for `PROTO_ID_BDX`:
///
/// ```ignore
/// use rs_matter::bdx::{Bdx, PROTO_ID_BDX};
///
/// let bdx = Bdx::new(OtaBdxHandler::new(&images));
/// let handler = im_and_sc_handler.chain(PROTO_ID_BDX, bdx);
/// ```
///
/// Serve several BDX handlers at once by nesting [`ChainedBdxHandler`]s
/// (terminated by [`EmptyBdxHandler`]):
///
/// ```ignore
/// let bdx = Bdx::new(ChainedBdxHandler::new(
///     ota_server,
///     ChainedBdxHandler::new(logs_sink, EmptyBdxHandler),
/// ));
/// ```
pub struct Bdx<T>(T);

impl<T> Bdx<T> {
    /// Wrap a [`BdxHandler`] (often a [`ChainedBdxHandler`]) as a BDX
    /// [`ExchangeHandler`].
    pub const fn new(handler: T) -> Self {
        Self(handler)
    }

    /// A reference to the wrapped handler.
    pub fn handler(&self) -> &T {
        &self.0
    }
}

impl<T: BdxHandler> ExchangeHandler for Bdx<T> {
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        // Peek the opening `*Init` to learn the transfer's direction, then accept
        // it into the matching responder (which keeps the `*Init` held).
        exchange.recv_fetch().await?;
        let meta = exchange.rx()?.meta();

        let responder = match opcode(&meta) {
            // A peer wants to download a file from us: we are the Sender.
            Some(OpCode::ReceiveInit) => {
                BdxResponder::Download(BdxDownloadResponder::accept(exchange).await?)
            }
            // A peer wants to upload a file to us: we are the Receiver.
            Some(OpCode::SendInit) => {
                BdxResponder::Upload(BdxUploadResponder::accept(exchange).await?)
            }
            // Any other opcode cannot open a transfer.
            _ => {
                exchange.rx_done()?;

                return abort(&mut exchange, BdxStatus::UnexpectedMessage).await;
            }
        };

        if self.0.handles(&responder).await {
            self.0.handle(responder).await
        } else {
            responder.reject(BdxStatus::FileDesignatorUnknown).await
        }
    }
}
