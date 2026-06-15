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

//! Composing BDX services behind a single `PROTO_ID_BDX` exchange handler.
//!
//! [`Bdx`] is the [`ExchangeHandler`] that owns the BDX protocol in a responder's
//! handler chain. For each incoming transfer it looks at the opening `*Init`
//! (its direction and file designator) and dispatches to a [`BdxServer`] - which
//! either *serves* a download (we send) or *processes* an upload (we receive).
//!
//! Multiple services are composed by nesting [`ChainedBdxServer`]s (terminated by
//! [`EmptyBdxServer`]), so several of them can share `PROTO_ID_BDX` while owning
//! disjoint file-designator namespaces - e.g. an OTA Provider serving images
//! alongside a Diagnostic Logs client receiving logs.

use crate::respond::ExchangeHandler;

use super::nego::abort;
use super::*;

/// A device-specific BDX service: one or more "files" - identified by their BDX
/// file designators - that this node either *serves* (sends, when a peer requests
/// a download) or *processes* (receives, when a peer requests an upload).
///
/// Implement only the direction(s) the service supports; the other one defaults
/// to rejecting the transfer with `FileDesignatorUnknown`.
pub trait BdxServer {
    /// Whether this server serves (can send) the file designated by `fd` when a
    /// peer requests to download it.
    async fn serves(&self, _fd: &[u8]) -> bool {
        false
    }

    /// Serve a download: a peer sent a `ReceiveInit` for a designator this server
    /// [`serves`](Self::serves), so this node is the Sender. Use `responder` to
    /// [`reply`](BdxDownloadResponder::reply) (then stream via the returned
    /// [`BdxWriter`]) or [`reject`](BdxDownloadResponder::reject) it.
    async fn serve(&self, responder: BdxDownloadResponder<'_>) -> Result<(), Error> {
        responder.reject(BdxStatus::FileDesignatorUnknown).await
    }

    /// Whether this server processes (can receive) the file designated by `fd`
    /// when a peer requests to upload it.
    async fn processes(&self, _fd: &[u8]) -> bool {
        false
    }

    /// Process an upload: a peer sent a `SendInit` for a designator this server
    /// [`processes`](Self::processes), so this node is the Receiver. Use
    /// `responder` to [`reply`](BdxUploadResponder::reply) (then drain the returned
    /// [`BdxReader`]) or [`reject`](BdxUploadResponder::reject) it.
    async fn process(&self, responder: BdxUploadResponder<'_>) -> Result<(), Error> {
        responder.reject(BdxStatus::FileDesignatorUnknown).await
    }
}

/// `&T` is a [`BdxServer`] whenever `T` is, so a server can be composed (into a
/// [`ChainedBdxServer`]) or wrapped (in [`Bdx`]) by shared reference, without
/// giving up ownership of it.
impl<T> BdxServer for &T
where
    T: BdxServer,
{
    async fn serves(&self, fd: &[u8]) -> bool {
        T::serves(self, fd).await
    }

    async fn serve(&self, responder: BdxDownloadResponder<'_>) -> Result<(), Error> {
        T::serve(self, responder).await
    }

    async fn processes(&self, fd: &[u8]) -> bool {
        T::processes(self, fd).await
    }

    async fn process(&self, responder: BdxUploadResponder<'_>) -> Result<(), Error> {
        T::process(self, responder).await
    }
}

/// A [`BdxServer`] that serves and processes nothing - the terminator of a
/// [`ChainedBdxServer`]. Every transfer routed to it is rejected with
/// `FileDesignatorUnknown`.
pub struct EmptyBdxServer;

impl BdxServer for EmptyBdxServer {}

/// Two [`BdxServer`]s composed into one: `handler` is consulted first (by file
/// designator), then `next`. Nest these (terminated by [`EmptyBdxServer`]) to
/// compose more than two.
pub struct ChainedBdxServer<H, T> {
    /// The server consulted first.
    pub handler: H,
    /// The server consulted if `handler` does not match.
    pub next: T,
}

impl<H, T> ChainedBdxServer<H, T> {
    /// Create a chained server consulting `handler` before `next`.
    pub const fn new(handler: H, next: T) -> Self {
        Self { handler, next }
    }
}

impl<H, T> BdxServer for ChainedBdxServer<H, T>
where
    H: BdxServer,
    T: BdxServer,
{
    async fn serves(&self, fd: &[u8]) -> bool {
        self.handler.serves(fd).await || self.next.serves(fd).await
    }

    async fn serve(&self, responder: BdxDownloadResponder<'_>) -> Result<(), Error> {
        if self.handler.serves(responder.fd()).await {
            self.handler.serve(responder).await
        } else {
            self.next.serve(responder).await
        }
    }

    async fn processes(&self, fd: &[u8]) -> bool {
        self.handler.processes(fd).await || self.next.processes(fd).await
    }

    async fn process(&self, responder: BdxUploadResponder<'_>) -> Result<(), Error> {
        if self.handler.processes(responder.fd()).await {
            self.handler.process(responder).await
        } else {
            self.next.process(responder).await
        }
    }
}

/// An [`ExchangeHandler`] for the BDX protocol ([`PROTO_ID_BDX`]) that dispatches
/// each incoming transfer to the wrapped [`BdxServer`], by the transfer's file
/// designator and direction.
///
/// Chain it into your responder's handler for `PROTO_ID_BDX`:
///
/// ```ignore
/// use rs_matter::bdx::{Bdx, PROTO_ID_BDX};
///
/// let bdx = Bdx::new(OtaBdxServer::new(&images));
/// let handler = im_and_sc_handler.chain(PROTO_ID_BDX, bdx);
/// ```
///
/// Serve several BDX services at once by nesting [`ChainedBdxServer`]s
/// (terminated by [`EmptyBdxServer`]):
///
/// ```ignore
/// let bdx = Bdx::new(ChainedBdxServer::new(
///     ota_server,
///     ChainedBdxServer::new(logs_sink, EmptyBdxServer),
/// ));
/// ```
pub struct Bdx<T>(T);

impl<T> Bdx<T> {
    /// Wrap a [`BdxServer`] (often a [`ChainedBdxServer`]) as a BDX
    /// [`ExchangeHandler`].
    pub const fn new(server: T) -> Self {
        Self(server)
    }

    /// A reference to the wrapped server.
    pub fn server(&self) -> &T {
        &self.0
    }
}

impl<T: BdxServer> ExchangeHandler for Bdx<T> {
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        // Peek the opening `*Init` to learn the transfer's direction. The held
        // message is re-read (and kept held) by the responder's `accept` below.
        exchange.recv_fetch().await?;
        let meta = exchange.rx()?.meta();

        match opcode(&meta) {
            // A peer wants to download a file from us: we are the Sender.
            Some(OpCode::ReceiveInit) => {
                let responder = BdxDownloadResponder::accept(exchange).await?;

                if self.0.serves(responder.fd()).await {
                    self.0.serve(responder).await
                } else {
                    responder.reject(BdxStatus::FileDesignatorUnknown).await
                }
            }
            // A peer wants to upload a file to us: we are the Receiver.
            Some(OpCode::SendInit) => {
                let responder = BdxUploadResponder::accept(exchange).await?;

                if self.0.processes(responder.fd()).await {
                    self.0.process(responder).await
                } else {
                    responder.reject(BdxStatus::FileDesignatorUnknown).await
                }
            }
            // Any other opcode cannot open a transfer.
            _ => {
                exchange.rx_done()?;

                abort(&mut exchange, BdxStatus::UnexpectedMessage).await
            }
        }
    }
}
