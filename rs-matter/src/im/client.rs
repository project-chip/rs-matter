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

//! Interaction Model Client implementation.
//!
//! This module provides client-side functionality for sending IM requests
//! (Read, Write, Invoke) to Matter devices and processing their responses.

pub use super::{AttrId, ClusterId, EndptId};

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWriteParent, TagType, ToTLV};
use crate::transport::exchange::Exchange;
use crate::utils::storage::WriteBuf;

/// Root [`TLVBuilderParent`] type the IM client builders run against.
/// The user's `*_with` closure receives a message builder
/// parameterised by this parent type and must return it (via `.end()`
/// on the message builder) as proof that the TLV write is complete
/// and well-formed.
///
/// The HRTB on the two lifetimes is what lets the same closure work
/// for whichever TX buffer the transport hands us on each call —
/// neither lifetime is observable in user code.
pub type ImBuildRootParent<'wb, 'buf> = TLVWriteParent<&'static str, &'wb mut WriteBuf<'buf>>;

use super::{
    AttrData, AttrDataTag, AttrPath, AttrResp, CmdData, CmdDataTag, CmdPath, CmdResp,
    DataVersionFilter, EventFilter, EventPath, IMStatusCode, InvReqBuilder, InvokeResp, OpCode,
    ReadReqBuilder, ReportDataResp, StatusResp, TimedReq, WriteReqBuilder, WriteResp,
};

/// Builder for constructing ReadRequest messages.
///
/// Corresponds to the `ReadRequestMessage` TLV structure in the Interaction Model.
#[derive(Debug, Clone, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct ReadRequestBuilder<'a> {
    /// Attribute paths to read
    pub attr_requests: Option<&'a [AttrPath]>,
    /// Event paths to read
    pub event_requests: Option<&'a [EventPath]>,
    /// Event filters
    pub event_filters: Option<&'a [EventFilter]>,
    /// Whether to filter by fabric
    pub fabric_filtered: bool,
    /// Data version filters for conditional reads
    pub dataver_filters: Option<&'a [DataVersionFilter]>,
}

impl<'a> ReadRequestBuilder<'a> {
    /// Create a new ReadRequestBuilder for reading attributes
    pub const fn attributes(attr_requests: &'a [AttrPath], fabric_filtered: bool) -> Self {
        Self {
            attr_requests: Some(attr_requests),
            event_requests: None,
            event_filters: None,
            fabric_filtered,
            dataver_filters: None,
        }
    }
}

/// Builder for constructing WriteRequest messages.
///
/// Corresponds to the `WriteRequestMessage` TLV structure in the Interaction Model.
#[derive(Debug, Clone, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct WriteRequestBuilder<'a> {
    /// Whether to suppress the response
    pub suppress_response: Option<bool>,
    /// Whether this is a timed request
    pub timed_request: Option<bool>,
    /// Attribute data to write
    pub write_requests: &'a [AttrData<'a>],
    /// Whether there are more chunks coming
    pub more_chunks: Option<bool>,
}

impl<'a> WriteRequestBuilder<'a> {
    /// Create a new WriteRequestBuilder
    pub const fn new(write_requests: &'a [AttrData<'a>], timed: bool) -> Self {
        Self {
            suppress_response: None,
            timed_request: if timed { Some(true) } else { None },
            write_requests,
            more_chunks: None,
        }
    }
}

/// Builder for constructing InvokeRequest messages.
///
/// Corresponds to the `InvokeRequestMessage` TLV structure in the Interaction Model.
#[derive(Debug, Clone, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct InvokeRequestBuilder<'a> {
    /// Whether to suppress the response
    pub suppress_response: Option<bool>,
    /// Whether this is a timed request
    pub timed_request: Option<bool>,
    /// Command invocations
    pub invoke_requests: &'a [CmdData<'a>],
}

impl<'a> InvokeRequestBuilder<'a> {
    /// Create a new InvokeRequestBuilder
    pub const fn new(invoke_requests: &'a [CmdData<'a>], timed: bool) -> Self {
        Self {
            // Matter 1.5 Core spec §8.8.5: `SuppressResponse` and
            // `TimedRequest` are mandatory fields of `InvokeRequestMessage`
            // and MUST be present on the wire. Encode them explicitly so
            // strictly-validating peers (e.g. SmartThings) accept the
            // request instead of rejecting it with `INVALID_ACTION`.
            suppress_response: Some(false),
            timed_request: Some(timed),
            invoke_requests,
        }
    }
}

/// IM Client for sending requests to Matter devices.
///
/// This struct provides methods for sending Read, Write, and Invoke requests
/// over an established exchange (either PASE or CASE session).
///
/// # Lifecycle
///
/// Every method **consumes** its `Exchange` by value — one exchange is
/// one IM transaction, end of story. After the method returns, the
/// exchange is closed and the slot is released; callers wanting to
/// issue another transaction must initiate a fresh exchange. Methods
/// that need to surface zero-copy response data (`write`,
/// `read_single_attr`, `invoke_single_cmd`) take an `FnOnce(Resp<'_>)`
/// callback so the borrowed response can be inspected before the
/// exchange is dropped; the callback's return value is propagated as
/// owned `T`.
///
/// # Example
///
/// ```ignore
/// // Read an attribute
/// let attr_path = AttrPath {
///     endpoint: Some(1),
///     cluster: Some(0x0006), // OnOff cluster
///     attr: Some(0x0000),    // OnOff attribute
///     ..Default::default()
/// };
/// ImClient::read(exchange, &[attr_path], true, |report| {
///     // Process each chunk's attribute reports here
///     Ok(())
/// }).await?;
/// ```
pub struct ImClient;

impl ImClient {
    /// Read attributes from a device with full chunking support.
    ///
    /// This is the lowest-level read API. It supports wildcard paths and
    /// handles chunked responses automatically, invoking the callback once
    /// per chunk.
    ///
    /// # Callback lifetime constraints
    ///
    /// The callback receives `&ReportDataResp<'_>` where the lifetime is
    /// tied to the exchange's RX buffer for the current chunk. Because the
    /// buffer is invalidated between chunks, **only owned/`Copy` data can
    /// be extracted** from the callback. Borrowed data (e.g., `TLVElement`,
    /// byte slices from `AttrData`) cannot escape the callback.
    ///
    /// For single-attribute reads where you need zero-copy access to
    /// borrowed response data, use [`read_single_attr`](Self::read_single_attr)
    /// instead.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `attr_paths` - Attribute paths to read
    /// - `fabric_filtered` - Whether to filter results by fabric
    /// - `on_report` - Callback invoked for each ReportData chunk
    pub async fn read<F>(
        exchange: Exchange<'_>,
        attr_paths: &[AttrPath],
        fabric_filtered: bool,
        mut on_report: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&ReportDataResp<'_>) -> Result<(), Error>,
    {
        Self::read_with(
            exchange,
            |msg| {
                // Bridge the snapshot-style API onto the streaming
                // builder: one TLV encoding path for both call shapes.
                msg.attr_requests_from(attr_paths)?
                    .fabric_filtered(fabric_filtered)?
                    .end()
            },
            // Adapt the caller's sync FnMut callback into the
            // `AsyncFnMut` surface `read_with` expects: run the user
            // closure synchronously, return a trivially-ready
            // future. Zero runtime cost — `ready` does not box.
            async |resp| on_report(resp),
        )
        .await
    }

    /// Streaming counterpart to [`read`](Self::read).
    ///
    /// `build` is invoked with a typed
    /// [`ReadReqBuilder`] already opened on the outbound
    /// TX buffer; the closure must return the [`ImBuildRootParent`]
    /// produced by `ReadReqBuilder::end()` as the
    /// type-system proof that every container the builder opened has
    /// been closed. No intermediate `Vec<AttrPath>` is allocated.
    /// `on_report` is then invoked for each `ReportData` chunk the
    /// server returns; chunking flow control (ACK each chunk with
    /// `StatusResponse(SUCCESS)`, abort on callback error) is handled
    /// internally.
    ///
    /// `build` is `FnMut` and must be idempotent — the MRP layer may
    /// retransmit the request and re-invoke the closure with a fresh
    /// builder on each attempt. See
    /// [`write_with`](Self::write_with) for the rationale.
    ///
    /// `on_report` is `AsyncFnMut` so callers can `.await` while
    /// processing each chunk (e.g. forwarding values to an async
    /// sink, persisting them to KV, awaiting backpressure on a
    /// channel). The borrow of the chunk data is held across the
    /// await, but the rx buffer remains valid until the next chunk
    /// request, so this is safe.
    pub async fn read_with<B, F>(
        mut exchange: Exchange<'_>,
        mut build: B,
        on_report: F,
    ) -> Result<(), Error>
    where
        B: for<'wb, 'buf> FnMut(
            ReadReqBuilder<ImBuildRootParent<'wb, 'buf>, 0>,
        ) -> Result<ImBuildRootParent<'wb, 'buf>, Error>,
        F: AsyncFnMut(&ReportDataResp<'_>) -> Result<(), Error>,
    {
        debug!(
            "ImClient::read - Sending ReadRequest on exchange {}",
            exchange.id()
        );

        exchange
            .send_with(|_, wb| {
                let parent = TLVWriteParent::new("ReadRequest", wb);
                let builder = ReadReqBuilder::new(parent, &TLVTag::Anonymous)?;
                let _root = build(builder)?;
                Ok(Some(OpCode::ReadRequest.into()))
            })
            .await?;

        Self::recv_read_chunks(&mut exchange, on_report).await
    }

    /// Async-build counterpart to [`read_with`](Self::read_with).
    /// See [`write_with_async`](Self::write_with_async) for the
    /// TX-slot-lifetime caveat and the strengthened idempotency
    /// contract that apply to any async-build IM client path.
    pub async fn read_with_async<B, F>(
        mut exchange: Exchange<'_>,
        mut build: B,
        on_report: F,
    ) -> Result<(), Error>
    where
        B: for<'wb, 'buf> AsyncFnMut(
            ReadReqBuilder<ImBuildRootParent<'wb, 'buf>, 0>,
        ) -> Result<ImBuildRootParent<'wb, 'buf>, Error>,
        F: AsyncFnMut(&ReportDataResp<'_>) -> Result<(), Error>,
    {
        debug!(
            "ImClient::read - Sending ReadRequest (async build) on exchange {}",
            exchange.id()
        );

        exchange
            .send_with_async(async |_, wb| {
                let parent = TLVWriteParent::new("ReadRequest", wb);
                let builder = ReadReqBuilder::new(parent, &TLVTag::Anonymous)?;
                let _root = build(builder).await?;
                Ok(Some(OpCode::ReadRequest.into()))
            })
            .await?;

        Self::recv_read_chunks(&mut exchange, on_report).await
    }

    /// Shared chunked-response loop for the read APIs. Both the
    /// sync-build and async-build variants enter this loop after
    /// the initial `ReadRequest` is on the wire.
    async fn recv_read_chunks<F>(exchange: &mut Exchange<'_>, mut on_report: F) -> Result<(), Error>
    where
        F: AsyncFnMut(&ReportDataResp<'_>) -> Result<(), Error>,
    {
        loop {
            exchange.recv_fetch().await?;

            // Capture top-level fields first so the `rx` borrow can be
            // released before the async callback runs — that lets the
            // callback freely access `exchange`-unrelated async
            // resources without lifetime conflicts.
            let (more_chunks, suppress_response) = {
                let rx = exchange.rx()?;
                Self::check_opcode(rx.meta().proto_opcode, OpCode::ReportData)?;
                let element = TLVElement::new(rx.payload());
                let resp = ReportDataResp::from_tlv(&element)?;
                (
                    resp.more_chunks.unwrap_or(false),
                    resp.suppress_response.unwrap_or(false),
                )
            };

            // Re-parse and run the async callback in a separate scope.
            // The rx buffer stays valid until we send the next message,
            // so re-parsing here is essentially free (the TLV decoder
            // is a thin lazy iterator over the bytes).
            let cb_result = {
                let rx = exchange.rx()?;
                let element = TLVElement::new(rx.payload());
                let resp = ReportDataResp::from_tlv(&element)?;
                on_report(&resp).await
            };

            if more_chunks {
                // If the callback failed, abort the chunked transaction by
                // sending StatusResponse(Failure) so the server stops sending.
                if let Err(e) = cb_result {
                    Self::send_abort(exchange).await?;
                    return Err(e);
                }

                // Send StatusResponse to request the next chunk.
                // This clears the rx buffer.
                debug!("ImClient::read - more_chunks=true, sending StatusResponse for next chunk");
                exchange
                    .send_with(|_, wb| {
                        StatusResp::write(wb, IMStatusCode::Success)?;
                        Ok(Some(OpCode::StatusResponse.into()))
                    })
                    .await?;
            } else {
                // Final chunk — propagate callback error after completing the exchange.
                cb_result?;

                if !suppress_response {
                    debug!("ImClient::read - final chunk, sending StatusResponse");
                    exchange
                        .send_with(|_, wb| {
                            StatusResp::write(wb, IMStatusCode::Success)?;
                            Ok(Some(OpCode::StatusResponse.into()))
                        })
                        .await?;
                } else {
                    debug!("ImClient::read - final chunk, sending standalone ACK");
                    exchange.acknowledge().await?;
                }
                break;
            }
        }

        Ok(())
    }

    /// Invoke one or more commands on a device with full chunking support.
    ///
    /// This is the lowest-level invoke API. It supports multiple commands per
    /// request and handles chunked responses automatically, invoking the
    /// callback once per chunk.
    ///
    /// # Callback lifetime constraints
    ///
    /// The callback receives `&InvokeResp<'_>` where the lifetime is tied to
    /// the exchange's RX buffer for the current chunk. Because the buffer is
    /// invalidated between chunks, **only owned/`Copy` data can be extracted**
    /// from the callback. Borrowed data (e.g., `TLVElement`, byte slices)
    /// cannot escape the callback.
    ///
    /// For single-command invocations where you need zero-copy access to
    /// borrowed response data, use [`invoke_single_cmd`](Self::invoke_single_cmd)
    /// instead.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `cmd_data` - One or more commands to invoke
    /// - `timed_timeout_ms` - Optional timeout for timed invoke (required for some commands)
    /// - `on_response` - Callback invoked for each InvokeResponse chunk
    pub async fn invoke<F>(
        exchange: Exchange<'_>,
        cmd_data: &[CmdData<'_>],
        timed_timeout_ms: Option<u16>,
        mut on_response: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&InvokeResp<'_>) -> Result<(), Error>,
    {
        Self::invoke_with(
            exchange,
            timed_timeout_ms,
            |msg| {
                // Bridge: re-emit the pre-built `&[CmdData]` through
                // the streaming builder so both call shapes share one
                // TLV encoding path.
                let mut entries = msg
                    .suppress_response(false)?
                    .timed_request(timed_timeout_ms.is_some())?
                    .invoke_requests()?;
                for cd in cmd_data {
                    let entry = entries
                        .push()?
                        .path_from(&cd.path)?
                        .data(|w| cd.data.to_tlv(&TLVTag::Context(CmdDataTag::Data as u8), w))?;
                    entries = match cd.command_ref {
                        Some(r) => entry.command_ref(r)?.end()?,
                        None => entry.end()?,
                    };
                }
                entries.end()?.end()
            },
            // Sync→async adapter for the caller's `FnMut` callback;
            // see `read`'s mirror site for the rationale.
            async |resp| on_response(resp),
        )
        .await
    }

    /// Streaming counterpart to [`invoke`](Self::invoke).
    ///
    /// Where [`invoke`](Self::invoke) takes a pre-built `&[CmdData]`
    /// (each entry carrying a `TLVElement` for the command request
    /// body — meaning the body had to be serialised into a sibling
    /// buffer first), `invoke_with` hands the caller a typed
    /// [`InvReqBuilder`] already opened on the outbound
    /// TX buffer and lets them stream the `InvokeRequestMessage`
    /// directly. The closure must return the [`ImBuildRootParent`]
    /// produced by `InvReqBuilder::end()` as the
    /// type-system proof of completeness. This is the MCU-friendly
    /// path for client clusters that send commands — the typed
    /// request-builder writes straight into the TX buffer, no
    /// out-of-band payload buffer needed.
    ///
    /// `build` is `FnMut` and must be idempotent — the MRP layer may
    /// retransmit the request and re-invoke the closure with a fresh
    /// builder on each attempt.
    ///
    /// `on_response` is invoked per `InvokeResponseMessage` chunk
    /// (see Matter Core spec §10.7.10 for when invoke responses
    /// chunk); chunking flow control is handled internally.
    /// `on_response` is `AsyncFnMut` — see [`read_with`](Self::read_with)
    /// for the rationale.
    pub async fn invoke_with<B, F>(
        mut exchange: Exchange<'_>,
        timed_timeout_ms: Option<u16>,
        mut build: B,
        on_response: F,
    ) -> Result<(), Error>
    where
        B: for<'wb, 'buf> FnMut(
            InvReqBuilder<ImBuildRootParent<'wb, 'buf>, 0>,
        ) -> Result<ImBuildRootParent<'wb, 'buf>, Error>,
        F: AsyncFnMut(&InvokeResp<'_>) -> Result<(), Error>,
    {
        debug!(
            "ImClient::invoke - Starting invoke on exchange {}",
            exchange.id()
        );

        if let Some(timeout_ms) = timed_timeout_ms {
            Self::send_timed_request(&mut exchange, timeout_ms).await?;
        }

        exchange
            .send_with(|_, wb| {
                let parent = TLVWriteParent::new("InvokeRequest", wb);
                let builder = InvReqBuilder::new(parent, &TLVTag::Anonymous)?;
                let _root = build(builder)?;
                Ok(Some(OpCode::InvokeRequest.into()))
            })
            .await?;

        Self::recv_invoke_chunks(&mut exchange, on_response).await
    }

    /// Async-build counterpart to [`invoke_with`](Self::invoke_with).
    /// The genuine MCU win for client clusters: a command-request
    /// build that needs to await (binding lookup, async telemetry,
    /// crypto sign) can do so directly into the TX buffer without
    /// a sibling buffer. See [`write_with_async`](Self::write_with_async)
    /// for the slot-lifetime and idempotency caveats.
    pub async fn invoke_with_async<B, F>(
        mut exchange: Exchange<'_>,
        timed_timeout_ms: Option<u16>,
        mut build: B,
        on_response: F,
    ) -> Result<(), Error>
    where
        B: for<'wb, 'buf> AsyncFnMut(
            InvReqBuilder<ImBuildRootParent<'wb, 'buf>, 0>,
        ) -> Result<ImBuildRootParent<'wb, 'buf>, Error>,
        F: AsyncFnMut(&InvokeResp<'_>) -> Result<(), Error>,
    {
        debug!(
            "ImClient::invoke - Starting invoke (async build) on exchange {}",
            exchange.id()
        );

        if let Some(timeout_ms) = timed_timeout_ms {
            Self::send_timed_request(&mut exchange, timeout_ms).await?;
        }

        exchange
            .send_with_async(async |_, wb| {
                let parent = TLVWriteParent::new("InvokeRequest", wb);
                let builder = InvReqBuilder::new(parent, &TLVTag::Anonymous)?;
                let _root = build(builder).await?;
                Ok(Some(OpCode::InvokeRequest.into()))
            })
            .await?;

        Self::recv_invoke_chunks(&mut exchange, on_response).await
    }

    /// Shared chunked-response loop for the invoke APIs. Both the
    /// sync-build and async-build variants enter this loop after
    /// the initial `InvokeRequest` is on the wire.
    async fn recv_invoke_chunks<F>(
        exchange: &mut Exchange<'_>,
        mut on_response: F,
    ) -> Result<(), Error>
    where
        F: AsyncFnMut(&InvokeResp<'_>) -> Result<(), Error>,
    {
        loop {
            exchange.recv_fetch().await?;

            // Top-level fields first (no borrows held past this scope),
            // then re-parse and run the async callback. See
            // `read_with`'s loop for the rationale.
            let (more_chunks, suppress_response) = {
                let rx = exchange.rx()?;
                Self::check_opcode(rx.meta().proto_opcode, OpCode::InvokeResponse)?;
                let element = TLVElement::new(rx.payload());
                let resp = InvokeResp::from_tlv(&element)?;
                (
                    resp.more_chunks.unwrap_or(false),
                    resp.suppress_response.unwrap_or(false),
                )
            };

            let cb_result = {
                let rx = exchange.rx()?;
                let element = TLVElement::new(rx.payload());
                let resp = InvokeResp::from_tlv(&element)?;
                on_response(&resp).await
            };

            if more_chunks {
                // Spec forbids suppress_response=true with more_chunks=true
                if suppress_response {
                    Self::send_abort(exchange).await?;
                    return Err(ErrorCode::InvalidData.into());
                }

                // If the callback failed, abort the chunked transaction by
                // sending StatusResponse(Failure) so the server stops sending.
                if let Err(e) = cb_result {
                    Self::send_abort(exchange).await?;
                    return Err(e);
                }

                // Send StatusResponse to request the next chunk.
                // This clears the rx buffer.
                debug!(
                    "ImClient::invoke - more_chunks=true, sending StatusResponse for next chunk"
                );
                exchange
                    .send_with(|_, wb| {
                        StatusResp::write(wb, IMStatusCode::Success)?;
                        Ok(Some(OpCode::StatusResponse.into()))
                    })
                    .await?;
            } else {
                // Final chunk — propagate callback error after completing the exchange.
                cb_result?;

                if !suppress_response {
                    debug!("ImClient::invoke - final chunk, sending StatusResponse");
                    exchange
                        .send_with(|_, wb| {
                            StatusResp::write(wb, IMStatusCode::Success)?;
                            Ok(Some(OpCode::StatusResponse.into()))
                        })
                        .await?;
                } else {
                    debug!("ImClient::invoke - final chunk, sending standalone ACK");
                    exchange.acknowledge().await?;
                }
                break;
            }
        }

        Ok(())
    }

    /// Write attributes to a device.
    ///
    /// Sends a WriteRequest, then invokes `on_resp` with the parsed
    /// WriteResponse (which borrows from the exchange's RX buffer).
    /// The callback's return value is propagated; the exchange is
    /// consumed and dropped at the end of the call.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session) —
    ///   consumed by the call (one exchange = one IM transaction)
    /// - `attr_data` - Attribute data to write
    /// - `timed_timeout_ms` - Optional timeout for timed write (required for some attributes)
    /// - `on_resp` - Callback invoked with the parsed `WriteResp` so
    ///   the caller can inspect per-attribute statuses with zero-copy
    ///   access and extract an owned result.
    pub async fn write<F, T>(
        exchange: Exchange<'_>,
        attr_data: &[AttrData<'_>],
        timed_timeout_ms: Option<u16>,
        on_resp: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(WriteResp<'_>) -> Result<T, Error>,
    {
        Self::write_with(
            exchange,
            timed_timeout_ms,
            |msg| {
                // Bridge the snapshot-style API to the streaming one: the
                // pre-collected `&[AttrData]` is re-emitted entry-by-entry
                // through the streaming builder, so both code paths share
                // exactly one TLV encoding implementation.
                //
                // `SuppressResponse` is implicitly omitted (the legacy
                // snapshot did the same — `None` for that field). The
                // legacy snapshot also wrote `TimedRequest` only when
                // `timed=true`, so mirror that here.
                let mut entries = if timed_timeout_ms.is_some() {
                    msg.timed_request(true)?.write_requests()?
                } else {
                    msg.write_requests()?
                };
                for ad in attr_data {
                    // Each `AttrDataBuilder<_, N>` is a different type per
                    // typestate `N`; an if-else over `ad.data_ver` lets
                    // both arms land at state 2 (via implicit
                    // data_version skip on the None arm) and continue
                    // uniformly.
                    let entry = entries.push()?;
                    entries = match ad.data_ver {
                        Some(dv) => entry.data_version(dv)?.path_from(&ad.path)?,
                        None => entry.path_from(&ad.path)?,
                    }
                    .data(|w| ad.data.to_tlv(&TLVTag::Context(AttrDataTag::Data as u8), w))?
                    .end()?;
                }
                // `.end()` on the array closes it; the next `.end()` on
                // the message implicitly skips `MoreChunkedMessages` and
                // yields the root parent — proof that the message is
                // well-formed.
                entries.end()?.end()
            },
            on_resp,
        )
        .await
    }

    /// Streaming counterpart to [`write`](Self::write).
    ///
    /// Where [`write`](Self::write) takes a pre-built `&[AttrData]`
    /// slice (which means every attribute value had to be serialised
    /// into a sibling buffer first), `write_with` hands the caller a
    /// typed [`WriteReqBuilder`] already opened on the
    /// outgoing TX buffer and lets them stream the
    /// `WriteRequestMessage` directly. No intermediate `Vec`, no
    /// out-of-band payload buffer — every byte ends up in the TX
    /// buffer exactly once. This is what the "Tier-2" / power-user
    /// streaming client APIs use.
    ///
    /// The closure receives the message builder at typestate `0` and
    /// must return the [`ImBuildRootParent`] that
    /// `WriteReqBuilder::end()` produces — this is the
    /// type-system proof that the caller closed every container the
    /// builder opened (`.end()` on the array, then `.end()` on the
    /// message). Forgetting to close one is a compile error, not a
    /// runtime malformed-TLV bug.
    ///
    /// When `timed_timeout_ms` is `Some`, this method sends the
    /// `TimedRequest` handshake before the write — the caller's
    /// builder body should set `timed_request(true)` accordingly.
    ///
    /// # Idempotency requirement
    ///
    /// `build` is `FnMut` because Matter's reliable-messaging layer
    /// (MRP) may retransmit the request multiple times — each
    /// retransmit invokes the closure again on a fresh builder over
    /// a fresh TX buffer. The closure **must** produce the same TLV
    /// output on every call (i.e. its writes must be a pure function
    /// of any captured state, and that state must not be moved out /
    /// consumed by the first invocation). The typical idiomatic
    /// shape — build through the streaming
    /// `WriteReqBuilder` from values captured by
    /// reference — is naturally idempotent.
    pub async fn write_with<B, F, T>(
        mut exchange: Exchange<'_>,
        timed_timeout_ms: Option<u16>,
        mut build: B,
        on_resp: F,
    ) -> Result<T, Error>
    where
        B: for<'wb, 'buf> FnMut(
            WriteReqBuilder<ImBuildRootParent<'wb, 'buf>, 0>,
        ) -> Result<ImBuildRootParent<'wb, 'buf>, Error>,
        F: FnOnce(WriteResp<'_>) -> Result<T, Error>,
    {
        if let Some(timeout_ms) = timed_timeout_ms {
            Self::send_timed_request(&mut exchange, timeout_ms).await?;
        }

        exchange
            .send_with(|_, wb| {
                let parent = TLVWriteParent::new("WriteRequest", wb);
                let builder = WriteReqBuilder::new(parent, &TLVTag::Anonymous)?;
                let _root = build(builder)?;
                Ok(Some(OpCode::WriteRequest.into()))
            })
            .await?;

        Self::recv_write_response(&mut exchange, on_resp).await
    }

    /// Async-build counterpart to [`write_with`](Self::write_with).
    ///
    /// The `build` closure is `AsyncFnMut` and may `.await` while
    /// holding the typed [`WriteReqBuilder`] — useful when
    /// the attribute values must themselves be fetched asynchronously
    /// (KV lookup, sensor read, async crypto, …). Returns the
    /// [`ImBuildRootParent`] as the same proof-of-completeness as
    /// [`write_with`](Self::write_with).
    ///
    /// **TX-slot lifetime caveat**: the underlying transport's TX
    /// buffer slot stays reserved for the entire duration of one
    /// closure invocation, including the time spent inside any
    /// `.await`. With a small TX-buffer pool, a slow-awaiting build
    /// can starve other concurrent exchanges. See
    /// [`Exchange::send_with_async`] for the full discussion. Prefer
    /// the sync [`write_with`](Self::write_with) when the build is
    /// already a pure TLV serialisation.
    ///
    /// **Idempotency**: same contract as [`write_with`]'s sync
    /// version — strengthened because the closure can now suspend
    /// and observe possibly-different external state on retransmit.
    /// Output must remain identical across retransmits.
    pub async fn write_with_async<B, F, T>(
        mut exchange: Exchange<'_>,
        timed_timeout_ms: Option<u16>,
        mut build: B,
        on_resp: F,
    ) -> Result<T, Error>
    where
        B: for<'wb, 'buf> AsyncFnMut(
            WriteReqBuilder<ImBuildRootParent<'wb, 'buf>, 0>,
        ) -> Result<ImBuildRootParent<'wb, 'buf>, Error>,
        F: FnOnce(WriteResp<'_>) -> Result<T, Error>,
    {
        if let Some(timeout_ms) = timed_timeout_ms {
            Self::send_timed_request(&mut exchange, timeout_ms).await?;
        }

        exchange
            .send_with_async(async |_, wb| {
                let parent = TLVWriteParent::new("WriteRequest", wb);
                let builder = WriteReqBuilder::new(parent, &TLVTag::Anonymous)?;
                let _root = build(builder).await?;
                Ok(Some(OpCode::WriteRequest.into()))
            })
            .await?;

        Self::recv_write_response(&mut exchange, on_resp).await
    }

    /// Shared response-handling tail for [`write_with`] and
    /// [`write_with_async`] — extracted so both call sites stay
    /// identical and any future fix lands once.
    async fn recv_write_response<F, T>(exchange: &mut Exchange<'_>, on_resp: F) -> Result<T, Error>
    where
        F: FnOnce(WriteResp<'_>) -> Result<T, Error>,
    {
        exchange.recv_fetch().await?;

        {
            let rx = exchange.rx()?;
            Self::check_opcode(rx.meta().proto_opcode, OpCode::WriteResponse)?;
        }

        exchange.acknowledge().await?;

        let rx = exchange.rx()?;
        let resp = WriteResp::from_tlv(&TLVElement::new(rx.payload()))?;

        on_resp(resp)
    }

    /// Send a timed request and wait for the status response.
    ///
    /// This is used before timed write or invoke operations.
    async fn send_timed_request(exchange: &mut Exchange<'_>, timeout_ms: u16) -> Result<(), Error> {
        let req = TimedReq {
            timeout: timeout_ms,
        };

        exchange
            .send_with(|_, wb| {
                req.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::TimedRequest.into()))
            })
            .await?;

        exchange.recv_fetch().await?;

        let rx = exchange.rx()?;
        Self::check_opcode(rx.meta().proto_opcode, OpCode::StatusResponse)?;

        let status_resp = StatusResp::from_tlv(&TLVElement::new(rx.payload()))?;
        if status_resp.status != IMStatusCode::Success {
            error!("TimedRequest failed with status: {:?}", status_resp.status);
            return Err(status_resp
                .status
                .to_error_code()
                .unwrap_or(ErrorCode::Failure)
                .into());
        }

        Ok(())
    }

    /// Check that the received opcode matches the expected one.
    fn check_opcode(received: u8, expected: OpCode) -> Result<(), Error> {
        if received != expected as u8 {
            error!(
                "Unexpected IM opcode: received {}, expected {:?}",
                received, expected
            );
            Err(ErrorCode::InvalidOpcode.into())
        } else {
            Ok(())
        }
    }

    /// Abort a chunked transaction by sending `StatusResponse(Failure)`.
    ///
    /// This tells the server we are not continuing the transaction, preventing
    /// it from waiting indefinitely for the next `StatusResponse(Success)`.
    async fn send_abort(exchange: &mut Exchange<'_>) -> Result<(), Error> {
        exchange
            .send_with(|_, wb| {
                StatusResp::write(wb, IMStatusCode::Failure)?;
                Ok(Some(OpCode::StatusResponse.into()))
            })
            .await
    }
}

/// Extension methods for easier single-item operations
impl ImClient {
    /// Read a single attribute and extract an owned value via callback.
    ///
    /// Convenience wrapper around [`read`](Self::read) for the common case
    /// of reading one attribute and extracting a single value from the
    /// response. The callback receives the first `AttrResp` and should
    /// return the extracted data.
    ///
    /// # Callback lifetime constraints
    ///
    /// The same lifetime constraints as [`read`](Self::read) apply: the
    /// callback's `AttrResp<'_>` borrows from a transient RX buffer, so
    /// only owned/`Copy` types can be returned as `T`. Returning borrowed
    /// types like `TLVElement<'_>` will not compile.
    ///
    /// For single-attribute reads where you need zero-copy access to the
    /// response's `TLVElement` data, use
    /// [`read_single_attr`](Self::read_single_attr) instead.
    ///
    /// # Returns
    /// The value returned by the callback, or an error if no attribute
    /// response was found or the read failed.
    pub async fn read_single<T, F>(
        exchange: Exchange<'_>,
        endpoint: EndptId,
        cluster: ClusterId,
        attr: AttrId,
        fabric_filtered: bool,
        on_attr: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(&AttrResp<'_>) -> Result<T, Error>,
    {
        let path = AttrPath {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attr: Some(attr),
            ..Default::default()
        };

        let mut result: Option<Result<T, Error>> = None;
        let mut on_attr = Some(on_attr);

        Self::read(exchange, &[path], fabric_filtered, |report| {
            if result.is_none() {
                if let Some(attr_reports) = &report.attr_reports {
                    if let Some(attr_resp) = attr_reports.iter().next() {
                        if let Some(cb) = on_attr.take() {
                            match attr_resp {
                                Ok(resp) => result = Some(cb(&resp)),
                                Err(_) => {
                                    result = Some(Err(ErrorCode::InvalidData.into()));
                                }
                            }
                        }
                    }
                }
            }
            Ok(())
        })
        .await?;

        result.unwrap_or(Err(ErrorCode::InvalidData.into()))
    }

    /// Read a single attribute and return the response with zero-copy access.
    ///
    /// Unlike [`read_single`](Self::read_single), this method does not use a
    /// callback. Instead, it returns the `AttrResp` directly, with its
    /// `TLVElement` data borrowing from the exchange's RX buffer. This enables
    /// zero-copy access to attribute data without the lifetime constraints
    /// imposed by the callback pattern.
    ///
    /// This method follows the same pattern as [`write`](Self::write) and
    /// [`invoke_single_cmd`](Self::invoke_single_cmd): after receiving the
    /// response, it sends a standalone ACK (which preserves the RX buffer)
    /// and then parses the response from the still-valid buffer.
    ///
    /// # Limitations
    ///
    /// This method does **not** support chunked responses. If the server
    /// responds with `more_chunks=true`, an error is returned. For wildcard
    /// reads or large responses that may be chunked, use
    /// [`read`](Self::read) directly.
    ///
    /// This method requires the server to set `suppress_response=true` on
    /// the final ReportData chunk. This is standard behavior for
    /// non-subscription reads per the Matter specification. If the server
    /// sets `suppress_response=false`, the exchange is completed with
    /// `StatusResponse(Success)` and an error is returned; use
    /// [`read_single`](Self::read_single) with a callback for that case.
    ///
    /// `on_resp` is invoked synchronously with the borrowed
    /// `AttrResp` while the RX buffer is still valid; its return
    /// value is propagated as an owned `T`. The exchange is consumed
    /// and dropped on return.
    ///
    /// # Returns
    /// The value `on_resp` produced, or an error if no attribute
    /// response was found, the read failed, chunking was encountered,
    /// or `suppress_response` was false.
    pub async fn read_single_attr<F, T>(
        mut exchange: Exchange<'_>,
        endpoint: EndptId,
        cluster: ClusterId,
        attr: AttrId,
        fabric_filtered: bool,
        on_resp: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(&AttrResp<'_>) -> Result<T, Error>,
    {
        let path = AttrPath {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attr: Some(attr),
            ..Default::default()
        };

        let paths = [path];
        let req = ReadRequestBuilder::attributes(&paths, fabric_filtered);

        exchange
            .send_with(|_, wb| {
                req.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::ReadRequest.into()))
            })
            .await?;

        exchange.recv_fetch().await?;

        // Check opcode and response flags before acknowledging
        let suppress_response = {
            let rx = exchange.rx()?;
            Self::check_opcode(rx.meta().proto_opcode, OpCode::ReportData)?;

            let element = TLVElement::new(rx.payload());
            let resp = ReportDataResp::from_tlv(&element)?;

            if resp.more_chunks.unwrap_or(false) {
                Self::send_abort(&mut exchange).await?;
                return Err(ErrorCode::InvalidData.into());
            }

            resp.suppress_response.unwrap_or(false)
        };

        if !suppress_response {
            // suppress_response=false means the server expects a StatusResponse,
            // which requires send_with() and clears the RX buffer, making
            // zero-copy access impossible. Complete the exchange properly,
            // then return an error. Use read_single() with a callback for
            // the suppress_response=false case.
            exchange
                .send_with(|_, wb| {
                    StatusResp::write(wb, IMStatusCode::Success)?;
                    Ok(Some(OpCode::StatusResponse.into()))
                })
                .await?;
            return Err(ErrorCode::InvalidData.into());
        }

        // suppress_response=true: send standalone ACK (preserves RX buffer)
        exchange.acknowledge().await?;

        // Parse response from the still-valid RX buffer
        let rx = exchange.rx()?;
        let element = TLVElement::new(rx.payload());
        let resp = ReportDataResp::from_tlv(&element)?;

        let attr_resp = resp
            .attr_reports
            .as_ref()
            .and_then(|reports| reports.iter().next())
            .ok_or(Error::from(ErrorCode::InvalidData))?
            .map_err(|_| Error::from(ErrorCode::InvalidData))?;

        on_resp(&attr_resp)
    }

    /// Invoke a single command and extract an owned value via callback.
    ///
    /// Convenience wrapper around [`invoke`](Self::invoke) for the common case
    /// of sending one command and extracting a single value from the response.
    /// The callback receives the first `CmdResp` and should return the
    /// extracted data.
    ///
    /// # Callback lifetime constraints
    ///
    /// The same lifetime constraints as [`invoke`](Self::invoke) apply: the
    /// callback's `CmdResp<'_>` borrows from a transient RX buffer, so
    /// only owned/`Copy` types can be returned as `T`. Returning borrowed
    /// types like `TLVElement<'_>` will not compile.
    ///
    /// For single-command invocations where you need zero-copy access to
    /// the response's `TLVElement` data, use
    /// [`invoke_single_cmd`](Self::invoke_single_cmd) instead.
    ///
    /// # Returns
    /// The value returned by the callback, or an error if no command
    /// response was found or the invoke failed.
    pub async fn invoke_single<T, F>(
        exchange: Exchange<'_>,
        endpoint: EndptId,
        cluster: ClusterId,
        cmd: u32,
        cmd_data: TLVElement<'_>,
        timed_timeout_ms: Option<u16>,
        on_resp: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(CmdResp<'_>) -> Result<T, Error>,
    {
        let path = CmdPath {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            cmd: Some(cmd),
        };

        let data = CmdData {
            path,
            data: cmd_data,
            command_ref: None,
        };

        let mut result: Option<Result<T, Error>> = None;
        let mut on_resp = Some(on_resp);

        Self::invoke(exchange, &[data], timed_timeout_ms, |resp| {
            if result.is_none() {
                if let Some(invoke_responses) = &resp.invoke_responses {
                    if let Some(cmd_resp) = invoke_responses.iter().next() {
                        if let Some(cb) = on_resp.take() {
                            match cmd_resp {
                                Ok(resp) => result = Some(cb(resp)),
                                Err(_) => {
                                    result = Some(Err(ErrorCode::InvalidData.into()));
                                }
                            }
                        }
                    }
                }
            }
            Ok(())
        })
        .await?;

        result.unwrap_or(Err(ErrorCode::InvalidData.into()))
    }

    /// Invoke a single command and return the response with zero-copy access.
    ///
    /// Unlike [`invoke_single`](Self::invoke_single), this method does not use
    /// a callback. Instead, it returns the `CmdResp` directly, with its
    /// `TLVElement` data borrowing from the exchange's RX buffer. This enables
    /// zero-copy access to response fields without the lifetime constraints
    /// imposed by the callback pattern.
    ///
    /// This method follows the same pattern as [`write`](Self::write):
    /// after receiving the response, it sends a standalone ACK (which preserves
    /// the RX buffer) and then parses the response from the still-valid buffer.
    ///
    /// # Limitations
    ///
    /// This method does **not** support chunked responses. If the server
    /// responds with `more_chunks=true`, an error is returned. In practice
    /// this does not occur for single-command requests; if you need chunked
    /// response handling, use [`invoke`](Self::invoke) directly.
    ///
    /// **Note:** When the server sets `suppress_response=false` (the default
    /// for InvokeResponse), the spec requires the client to send
    /// `StatusResponse(Success)`. However, sending a StatusResponse clears
    /// the RX buffer, which would break zero-copy access. This method
    /// sends a standalone ACK instead, which completes the MRP-layer
    /// exchange but deviates from the IM-layer spec requirement. In
    /// practice this works because servers clean up the exchange on timeout.
    /// If strict spec compliance is required, use
    /// [`invoke_single`](Self::invoke_single) with a callback.
    ///
    /// The exchange remains borrowed for the lifetime of the returned
    /// `CmdResp`, since the response data points into the exchange's RX
    /// buffer.
    ///
    /// `on_resp` is invoked synchronously with the borrowed `CmdResp`
    /// while the RX buffer is still valid; its return value is
    /// propagated as an owned `T`. The exchange is consumed and
    /// dropped on return.
    ///
    /// # Returns
    /// The value `on_resp` produced, or an error if no response was
    /// found, the invoke failed, or chunking was encountered.
    pub async fn invoke_single_cmd<F, T>(
        mut exchange: Exchange<'_>,
        endpoint: EndptId,
        cluster: ClusterId,
        cmd: u32,
        cmd_data: TLVElement<'_>,
        timed_timeout_ms: Option<u16>,
        on_resp: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(CmdResp<'_>) -> Result<T, Error>,
    {
        // If timed, send TimedRequest first
        if let Some(timeout_ms) = timed_timeout_ms {
            Self::send_timed_request(&mut exchange, timeout_ms).await?;
        }

        let path = CmdPath {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            cmd: Some(cmd),
        };

        let cmd_data = [CmdData {
            path,
            data: cmd_data,
            command_ref: None,
        }];

        let req = InvokeRequestBuilder::new(&cmd_data, timed_timeout_ms.is_some());

        exchange
            .send_with(|_, wb| {
                req.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::InvokeRequest.into()))
            })
            .await?;

        exchange.recv_fetch().await?;

        // Servers MAY reply with a plain `StatusResponse` instead of a full
        // `InvokeResponse` for commands whose return is `DefaultSuccess`
        // (empty response body). Accept both.
        let opcode = exchange.rx()?.meta().proto_opcode;

        if opcode == OpCode::StatusResponse as u8 {
            // Parse status from the RX buffer, then ACK.
            let status = {
                let rx = exchange.rx()?;
                let element = TLVElement::new(rx.payload());
                StatusResp::from_tlv(&element)?.status
            };

            exchange.acknowledge().await?;

            if status == IMStatusCode::Success {
                let synth = CmdResp::status_new(
                    CmdPath {
                        endpoint: Some(endpoint),
                        cluster: Some(cluster),
                        cmd: Some(cmd),
                    },
                    IMStatusCode::Success,
                    None,
                    None,
                );
                return on_resp(synth);
            } else {
                error!("Invoke reply: StatusResponse({:?})", status);
                return Err(status
                    .to_error_code()
                    .unwrap_or(ErrorCode::InvalidData)
                    .into());
            }
        }

        // Check opcode and more_chunks before acknowledging
        {
            let rx = exchange.rx()?;
            Self::check_opcode(rx.meta().proto_opcode, OpCode::InvokeResponse)?;

            let element = TLVElement::new(rx.payload());
            let resp = InvokeResp::from_tlv(&element)?;

            if resp.more_chunks.unwrap_or(false) {
                Self::send_abort(&mut exchange).await?;
                return Err(ErrorCode::InvalidData.into());
            }
        }

        // Send ACK — this preserves the RX buffer (unlike send_with which clears it).
        // See doc comment on suppress_response handling above.
        exchange.acknowledge().await?;

        // Parse response from the still-valid RX buffer
        let rx = exchange.rx()?;
        let element = TLVElement::new(rx.payload());
        let resp = InvokeResp::from_tlv(&element)?;

        let cmd_resp = resp
            .invoke_responses
            .as_ref()
            .and_then(|responses| responses.iter().next())
            .ok_or(Error::from(ErrorCode::InvalidData))?
            .map_err(|_| Error::from(ErrorCode::InvalidData))?;

        on_resp(cmd_resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::storage::WriteBuf;

    #[test]
    fn test_read_request_encoding() {
        let path = AttrPath {
            endpoint: Some(1),
            cluster: Some(0x0006),
            attr: Some(0x0000),
            ..Default::default()
        };

        let paths = [path];
        let req = ReadRequestBuilder::attributes(&paths, true);

        let mut buf = [0u8; 128];
        let mut wb = WriteBuf::new(&mut buf);
        req.to_tlv(&TagType::Anonymous, &mut wb).unwrap();

        assert!(!wb.as_slice().is_empty());
    }

    #[test]
    fn test_invoke_request_encoding() {
        let path = CmdPath {
            endpoint: Some(1),
            cluster: Some(0x0006),
            cmd: Some(0x02), // Toggle
        };

        let data = CmdData {
            path,
            data: TLVElement::new(&[]),
            command_ref: None,
        };

        let cmds = [data];
        let req = InvokeRequestBuilder::new(&cmds, false);

        let mut buf = [0u8; 128];
        let mut wb = WriteBuf::new(&mut buf);
        req.to_tlv(&TagType::Anonymous, &mut wb).unwrap();

        assert!(!wb.as_slice().is_empty());
    }

    #[test]
    fn test_write_request_encoding() {
        let path = AttrPath {
            endpoint: Some(1),
            cluster: Some(0x0006),
            attr: Some(0x0000),
            ..Default::default()
        };

        let data = AttrData {
            data_ver: None,
            path,
            data: TLVElement::new(&[]),
        };

        let attrs = [data];
        let req = WriteRequestBuilder::new(&attrs, false);

        let mut buf = [0u8; 128];
        let mut wb = WriteBuf::new(&mut buf);
        req.to_tlv(&TagType::Anonymous, &mut wb).unwrap();

        assert!(!wb.as_slice().is_empty());
    }
}
