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

//! The Diagnostic Logs cluster *client* side (the controller fetching logs).
//!
//! The client sends `RetrieveLogsRequest` via the generated `DiagnosticLogsClient`
//! proxy on an [`Exchange`](crate::transport::exchange::Exchange); when the server
//! answers a `BDX` request by pushing the log over BDX, the client receives it
//! with [`DiagLogsBdxHandler`] - a [`BdxHandler`] it chains into its responder,
//! the mirror of the server-side
//! [`OtaBdxHandler`](crate::dm::clusters::ota_prov::OtaBdxHandler).

use crate::bdx::{BdxHandler, BdxReader, BdxResponder, BdxStatus};
use crate::error::Error;

use super::MAX_FILE_DESIGNATOR;

/// A destination for diagnostic logs received over BDX - the *client* side.
///
/// Implemented by an application that collects logs from devices (e.g. a small
/// management controller that fetches logs and forwards them to a cloud). The
/// [`DiagLogsBdxHandler`] calls [`receive`](Self::receive) once per incoming BDX
/// log transfer; pull the bytes from `reader` yourself and store them however you
/// like - there is no per-chunk callback.
pub trait DiagLogsReceiver {
    /// Receive one diagnostic-log transfer. `file_designator` is the one the
    /// client named in its `RetrieveLogsRequest` (use it to correlate the
    /// transfer with that request). Read from `reader` until it returns `0`; the
    /// transfer is abandoned if the reader is dropped before end-of-stream.
    async fn receive(
        &self,
        file_designator: &[u8],
        reader: &mut BdxReader<'_>,
    ) -> Result<(), Error>;
}

impl<T> DiagLogsReceiver for &T
where
    T: DiagLogsReceiver,
{
    async fn receive(
        &self,
        file_designator: &[u8],
        reader: &mut BdxReader<'_>,
    ) -> Result<(), Error> {
        T::receive(self, file_designator, reader).await
    }
}

/// The client side of Diagnostic Logs over BDX: a [`BdxHandler`] that accepts a
/// log a device *pushes* over BDX and hands it to a [`DiagLogsReceiver`].
///
/// This mirrors [`OtaBdxHandler`](crate::dm::clusters::ota_prov::OtaBdxHandler) on
/// the server side. Wrap it in a [`Bdx`](crate::bdx::Bdx) handler and chain that
/// into your responder: after you send a `RetrieveLogsRequest` with
/// `RequestedProtocol = BDX` (via the generated `DiagnosticLogsClient` proxy on an
/// [`Exchange`](crate::transport::exchange::Exchange)), the device opens a BDX
/// transfer back to you, and the responder routes it here - concurrently with the
/// still-in-flight request, so no explicit `accept`/`select` is needed.
pub struct DiagLogsBdxHandler<R> {
    receiver: R,
}

impl<R> DiagLogsBdxHandler<R> {
    /// Create a new handler that delivers each received log to `receiver`.
    pub const fn new(receiver: R) -> Self {
        Self { receiver }
    }
}

impl<R: DiagLogsReceiver> BdxHandler for DiagLogsBdxHandler<R> {
    async fn handles(&self, responder: &BdxResponder<'_>) -> bool {
        // We only accept logs being pushed to us (uploads), never downloads.
        matches!(responder, BdxResponder::Upload(_))
    }

    async fn handle(&self, responder: BdxResponder<'_>) -> Result<(), Error> {
        let responder = match responder {
            BdxResponder::Upload(responder) => responder,
            other => return other.reject(BdxStatus::TransferMethodNotSupported).await,
        };

        // Copy the file designator out before `reply` releases the held init.
        let mut fd = heapless::Vec::<u8, MAX_FILE_DESIGNATOR>::new();
        if fd.extend_from_slice(responder.fd()).is_err() {
            return responder.reject(BdxStatus::FileDesignatorUnknown).await;
        }

        let mut reader = responder.reply().await?;

        self.receiver.receive(&fd, &mut reader).await
    }
}
