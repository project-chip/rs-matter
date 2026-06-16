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

//! The Diagnostic Logs cluster (server role): it answers `RetrieveLogsRequest`
//! by handing back a device log - either *inline* in the response payload, or,
//! for larger logs, *streamed over BDX*.
//!
//! Unlike the OTA Provider (which serves an image as the BDX *responder* once a
//! requestor opens the transfer), the Diagnostic Logs server is the BDX
//! *initiator and sender*: on a `RetrieveLogsRequest` with `RequestedProtocol =
//! BDX`, the node opens a fresh BDX exchange back to the requestor and uploads
//! the log to it (see [`Exchange::upload`](crate::bdx::BdxUploadInitiator::upload)).
//!
//! # Inline vs BDX, and the response timing
//!
//! A log that fits in the response (up to [`MAX_INLINE_LOG`] bytes) is returned
//! inline. A larger one is streamed over BDX when the requestor asks for it.
//!
//! Per the Matter spec the command response is sent the moment the BDX transfer
//! is *accepted* (the `SendAccept`), not when it completes - so the requestor
//! learns the outcome (`Success` once accepted, `Denied` if the receiver refuses
//! the `SendInit`) while the blocks are still being streamed, and a *second*
//! request arriving mid-transfer is told `Busy`. To honor that, the handshake is
//! done inline (so the response can reflect it) but the block streaming runs in
//! the background, driven by this handler's [`run`](DiagnosticLogsHandler::run)
//! task (the same `run` hook the data model already polls). At most one BDX
//! transfer is in flight at a time.
//!
//! The log bytes themselves come from a user-supplied [`DiagnosticLogsProvider`]
//! (one log per [`IntentEnum`]).

use core::num::NonZeroU8;

use crate::bdx::{BdxBuffer, BdxUploadInitiator};
use crate::dm::{Cluster, Dataver, HandlerContext, InvokeContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::{Octets, TLVBuilderParent};
use crate::transport::exchange::{Exchange, MAX_EXCHANGE_RX_BUF_SIZE};
use crate::utils::cell::RefCell;
use crate::utils::storage::pooled::BufferAccess;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::{Notification, Signal};
use crate::with;

pub use crate::dm::clusters::decl::diagnostic_logs::*;

/// The maximum number of bytes a log may have to be returned *inline* (in the
/// `RetrieveLogsResponse` `LogContent` field). A larger log is streamed over BDX
/// (when requested) or truncated to this size (when an inline response is
/// requested). Matches the `LogContent` field's max length, per the Matter spec.
pub const MAX_INLINE_LOG: usize = 1024;

/// The maximum supported BDX file designator length, per the Matter spec.
const MAX_FILE_DESIGNATOR: usize = 32;

/// The log bytes a [`DiagnosticLogsHandler`] hands back, addressed by
/// [`IntentEnum`]. The same source feeds both the inline response and the BDX
/// stream, so a single implementation covers both delivery paths.
pub trait DiagnosticLogsProvider {
    /// The total size, in bytes, of the log for `intent`, or `None` if the node
    /// has no such log (the cluster answers `NoLogs`).
    ///
    /// The size decides the delivery path: a log up to [`MAX_INLINE_LOG`] bytes
    /// is returned inline; a larger one is streamed over BDX when the requestor
    /// asks for it (and is otherwise truncated to an inline response).
    async fn size(&self, intent: IntentEnum) -> Option<u64>;

    /// Read up to `buf.len()` bytes of the log for `intent` starting at `offset`,
    /// returning the number of bytes read (`0` marks the end of the log). Used
    /// for both the inline response and BDX streaming.
    async fn read(&self, intent: IntentEnum, offset: u64, buf: &mut [u8]) -> Result<usize, Error>;
}

impl<T> DiagnosticLogsProvider for &T
where
    T: DiagnosticLogsProvider,
{
    async fn size(&self, intent: IntentEnum) -> Option<u64> {
        T::size(self, intent).await
    }

    async fn read(&self, intent: IntentEnum, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        T::read(self, intent, offset, buf).await
    }
}

/// A pending (or in-flight) BDX log upload, handed from the command handler to
/// the background [`run`](DiagnosticLogsHandler::run) task.
struct Job {
    /// The accessing fabric, and the requestor node on it to upload to.
    fab_idx: NonZeroU8,
    node_id: u64,
    /// The BDX file designator the requestor named for the transfer.
    fd: heapless::String<MAX_FILE_DESIGNATOR>,
    /// Which log to stream.
    intent: IntentEnum,
}

/// The single-slot state machine coordinating the command handler with the
/// background BDX streamer. At most one transfer is in flight.
enum Bdx {
    /// No transfer; a new request may start one.
    Idle,
    /// A request posted a job that `run` has not yet picked up.
    Requested(Job),
    /// `run` is doing the handshake / streaming the blocks.
    InProgress,
}

/// The server-side handler for the Diagnostic Logs cluster.
///
/// It answers `RetrieveLogsRequest` from the [`DiagnosticLogsProvider`] it is
/// given, returning small logs inline and - when the requestor asks for `BDX` -
/// streaming larger logs over a BDX transfer it initiates back to the requestor.
///
/// `buffers` is a [`BufferAccess`] pool ([`BdxBuffer`]-sized): one buffer is
/// leased to stage the inline read, and one for the duration of a BDX transfer,
/// so the pool needs at least two buffers to serve an inline request while a BDX
/// transfer is in flight. When no buffer is free, the request is answered with
/// `Busy`.
///
/// The handler's [`run`](Self::run) hook must be polled (the data model does this
/// for the handler tree it is given) for BDX streaming to make progress.
pub struct DiagnosticLogsHandler<B, P> {
    dataver: Dataver,
    buffers: B,
    logs: P,
    /// The BDX transfer slot.
    bdx: Mutex<RefCell<Bdx>>,
    /// Wakes [`run`](Self::run) when a job is posted.
    job_posted: Notification,
    /// Carries the handshake outcome (`true` = accepted) from `run` back to the
    /// command handler awaiting it, atomically with the wakeup.
    handshake: Signal<Option<bool>>,
}

impl<B, P> DiagnosticLogsHandler<B, P> {
    /// Create a new handler backed by the given staging-buffer pool and log
    /// provider.
    pub const fn new(dataver: Dataver, buffers: B, logs: P) -> Self {
        Self {
            dataver,
            buffers,
            logs,
            bdx: Mutex::new(RefCell::new(Bdx::Idle)),
            job_posted: Notification::new(),
            handshake: Signal::new(None),
        }
    }

    /// Adapt this handler to the generic `rs-matter` `AsyncHandler` trait.
    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }
}

impl<B, P> DiagnosticLogsHandler<B, P>
where
    B: BufferAccess<BdxBuffer>,
    P: DiagnosticLogsProvider,
{
    /// Fill `buf` from the `intent` log starting at `offset`, looping until it is
    /// full or the log ends, so only the final read of a transfer is ever short.
    /// Returns the number of bytes read (`< buf.len()` only at end-of-log).
    async fn fill(&self, intent: IntentEnum, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let mut filled = 0;

        while filled < buf.len() {
            // `checked_add`: a buggy `size`/`read` could push the running offset
            // near `u64::MAX`, where `offset + filled` would overflow.
            let read_offset = offset
                .checked_add(filled as u64)
                .ok_or(ErrorCode::Invalid)?;
            let n = self
                .logs
                .read(intent, read_offset, &mut buf[filled..])
                .await?;
            if n == 0 {
                break;
            }
            // Guard a misbehaving `read` that reports more than the slice it was
            // handed - otherwise `filled` overruns `buf` and the next slice panics.
            if n > buf.len() - filled {
                return Err(ErrorCode::Invalid.into());
            }

            filled += n;
        }

        Ok(filled)
    }

    /// Return the `intent` log inline (truncated to [`MAX_INLINE_LOG`]) with the
    /// given `status`.
    async fn reply_inline<Q: TLVBuilderParent>(
        &self,
        intent: IntentEnum,
        status: StatusEnum,
        response: RetrieveLogsResponseBuilder<Q>,
    ) -> Result<Q, Error> {
        let Some(mut buf) = self.buffers.get().await else {
            return reply_status(response, StatusEnum::Busy);
        };
        unwrap!(buf.resize_default(MAX_INLINE_LOG));

        let n = self.fill(intent, 0, buf.as_mut_slice()).await?;

        response
            .status(status)?
            .log_content(Octets(&buf[..n]))?
            .utc_time_stamp(None)?
            .time_since_boot(None)?
            .end()
    }

    /// Perform one background BDX transfer for `job`: open the exchange, do the
    /// handshake (reporting its outcome to the waiting command handler via
    /// [`handshake`](Self::handshake)), then stream the log to completion.
    async fn run_transfer(&self, ctx: &impl HandlerContext, job: &Job) -> Result<(), Error> {
        let Some(mut buf) = self.buffers.get().await else {
            self.handshake.signal(false);
            return Err(ErrorCode::NoSpace.into());
        };
        unwrap!(buf.resize_default(MAX_EXCHANGE_RX_BUF_SIZE));

        let exchange =
            match Exchange::initiate(ctx.matter(), ctx.crypto(), job.fab_idx, job.node_id).await {
                Ok(exchange) => exchange,
                Err(e) => {
                    self.handshake.signal(false);
                    return Err(e);
                }
            };

        let mut writer = match exchange
            .upload(buf.as_mut_slice(), job.fd.as_bytes(), None)
            .await
        {
            Ok(writer) => writer,
            // The requestor refused the transfer (or it could not be set up): the
            // command handler turns this into `Denied`.
            Err(e) => {
                self.handshake.signal(false);
                return Err(e);
            }
        };

        // Handshake accepted: the command handler can now answer `Success`.
        self.handshake.signal(true);

        let mut offset = 0;

        loop {
            let n = self.fill(job.intent, offset, writer.block_buf()).await?;
            if n == 0 {
                break;
            }

            writer.commit(n).await?;

            offset += n as u64;
        }

        writer.finish().await
    }
}

impl<B, P> ClusterAsyncHandler for DiagnosticLogsHandler<B, P>
where
    B: BufferAccess<BdxBuffer>,
    P: DiagnosticLogsProvider,
{
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn handle_retrieve_logs_request<Q: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: RetrieveLogsRequestRequest<'_>,
        response: RetrieveLogsResponseBuilder<Q>,
    ) -> Result<Q, Error> {
        // An unknown enum in a command field is a malformed command.
        let intent = request.intent().map_err(|_| ErrorCode::InvalidCommand)?;
        let protocol = request
            .requested_protocol()
            .map_err(|_| ErrorCode::InvalidCommand)?;
        let file_designator = request.transfer_file_designator()?;

        // A BDX request must carry a file designator within the length limit;
        // reject a malformed one up front (regardless of whether a log exists).
        if matches!(protocol, TransferProtocolEnum::BDX) {
            match file_designator {
                None => return Err(ErrorCode::InvalidCommand.into()),
                Some(fd) if fd.len() > MAX_FILE_DESIGNATOR => {
                    return Err(ErrorCode::ConstraintError.into());
                }
                _ => {}
            }
        }

        // No log for this intent: nothing to return.
        let Some(size) = self.logs.size(intent).await else {
            return reply_status(response, StatusEnum::NoLogs);
        };

        // Stream over BDX only when the requestor asked for it and the log is too
        // big to fit in the response. A log that fits is delivered inline even when
        // BDX was requested (cheaper for both sides) - reported as `Exhausted`.
        if !matches!(protocol, TransferProtocolEnum::BDX) || size <= MAX_INLINE_LOG as u64 {
            let status = if matches!(protocol, TransferProtocolEnum::ResponsePayload) {
                // An inline request always succeeds (the content is truncated to fit).
                StatusEnum::Success
            } else {
                // The whole log fit in the response, so no transfer was needed.
                StatusEnum::Exhausted
            };
            return self.reply_inline(intent, status, response).await;
        }

        // BDX. Validated above to be present and within the length limit.
        let fd = unwrap!(file_designator);

        // The requestor is the peer of the exchange the command arrived on;
        // capture it so the background streamer can open an exchange back to it.
        let fab_idx = NonZeroU8::new(ctx.cmd().fab_idx).ok_or(ErrorCode::Invalid)?;
        let exchange = ctx.exchange();
        let node_id = exchange
            .with_state(|state| {
                Ok(exchange
                    .id()
                    .session(&mut state.sessions)
                    .get_peer_node_id())
            })?
            .ok_or(ErrorCode::Invalid)?;

        let mut fd_str = heapless::String::new();
        // Length already bounded to `MAX_FILE_DESIGNATOR` above.
        unwrap!(fd_str.push_str(fd));

        let job = Job {
            fab_idx,
            node_id,
            fd: fd_str,
            intent,
        };

        // Claim the single transfer slot; if one is already in flight, we are busy.
        let claimed = self.bdx.lock(|cell| {
            let mut state = cell.borrow_mut();
            if matches!(&*state, Bdx::Idle) {
                *state = Bdx::Requested(job);
                true
            } else {
                false
            }
        });

        if !claimed {
            return reply_status(response, StatusEnum::Busy);
        }

        self.job_posted.notify();

        // Wait for `run` to perform the handshake and report its outcome; the
        // blocks stream in the background afterwards.
        let status = if self.handshake.wait_signalled().await {
            StatusEnum::Success
        } else {
            StatusEnum::Denied
        };

        reply_status(response, status)
    }

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        loop {
            self.job_posted.wait().await;

            // Take the posted job and mark the slot in-flight (so concurrent
            // requests get `Busy` until the transfer finishes).
            let job = self.bdx.lock(|cell| {
                let mut state = cell.borrow_mut();
                match core::mem::replace(&mut *state, Bdx::InProgress) {
                    Bdx::Requested(job) => Some(job),
                    // Spurious wakeup: restore and keep waiting.
                    other => {
                        *state = other;
                        None
                    }
                }
            });

            let Some(job) = job else {
                continue;
            };

            let result = self.run_transfer(&ctx, &job).await;

            // Free the slot for the next request.
            self.bdx.lock(|cell| *cell.borrow_mut() = Bdx::Idle);

            // A failed transfer is, in practice, the requestor aborting it with a
            // Secure Channel `StatusReport` (mid-handshake or mid-data); mirror the
            // "StatusReport Error" wording CHIP uses, with the concrete error
            // appended for diagnostics.
            match result {
                Ok(()) => info!("Diagnostic logs transfer: Success"),
                Err(e) => warn!("Diagnostic logs transfer: StatusReport Error: {:?}", e),
            }
        }
    }
}

/// Build a `RetrieveLogsResponse` carrying just `status` and an empty
/// `LogContent` (used for `NoLogs`/`Busy`/`Denied` and for accepted BDX
/// transfers, where the bytes travel out-of-band).
fn reply_status<Q: TLVBuilderParent>(
    response: RetrieveLogsResponseBuilder<Q>,
    status: StatusEnum,
) -> Result<Q, Error> {
    response
        .status(status)?
        .log_content(Octets(&[]))?
        .utc_time_stamp(None)?
        .time_since_boot(None)?
        .end()
}
