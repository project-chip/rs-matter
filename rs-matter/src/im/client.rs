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

//! Interaction Model Client implementation.
//!
//! This module provides client-side functionality for sending IM requests
//! (Read, Write, Invoke) to Matter devices and processing their responses.

pub use super::{AttrId, ClusterId, EndptId};

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVElement, TagType, ToTLV};
use crate::transport::exchange::Exchange;

use super::{
    AttrData, AttrPath, AttrResp, CmdData, CmdPath, CmdResp, DataVersionFilter, EventFilter,
    EventPath, IMStatusCode, InvokeResp, OpCode, ReportDataResp, StatusResp, TimedReq, WriteResp,
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
        exchange: &mut Exchange<'_>,
        attr_paths: &[AttrPath],
        fabric_filtered: bool,
        mut on_report: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&ReportDataResp<'_>) -> Result<(), Error>,
    {
        let req = ReadRequestBuilder::attributes(attr_paths, fabric_filtered);

        debug!(
            "ImClient::read - Sending ReadRequest on exchange {}",
            exchange.id()
        );

        exchange
            .send_with(|_, wb| {
                req.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::ReadRequest.into()))
            })
            .await?;

        loop {
            exchange.recv_fetch().await?;

            let (more_chunks, suppress_response, cb_result) = {
                let rx = exchange.rx()?;
                Self::check_opcode(rx.meta().proto_opcode, OpCode::ReportData)?;

                let element = TLVElement::new(rx.payload());
                let resp = ReportDataResp::from_tlv(&element)?;

                let more = resp.more_chunks.unwrap_or(false);
                let suppress = resp.suppress_response.unwrap_or(false);

                // Invoke callback while the rx buffer is still valid
                let cb_result = on_report(&resp);

                (more, suppress, cb_result)
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
        exchange: &mut Exchange<'_>,
        cmd_data: &[CmdData<'_>],
        timed_timeout_ms: Option<u16>,
        mut on_response: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&InvokeResp<'_>) -> Result<(), Error>,
    {
        debug!(
            "ImClient::invoke - Starting invoke on exchange {}",
            exchange.id()
        );

        // If timed, send TimedRequest first
        if let Some(timeout_ms) = timed_timeout_ms {
            Self::send_timed_request(exchange, timeout_ms).await?;
        }

        let req = InvokeRequestBuilder::new(cmd_data, timed_timeout_ms.is_some());

        exchange
            .send_with(|_, wb| {
                req.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::InvokeRequest.into()))
            })
            .await?;

        loop {
            exchange.recv_fetch().await?;

            let (more_chunks, suppress_response, cb_result) = {
                let rx = exchange.rx()?;
                Self::check_opcode(rx.meta().proto_opcode, OpCode::InvokeResponse)?;

                let element = TLVElement::new(rx.payload());
                let resp = InvokeResp::from_tlv(&element)?;

                let more = resp.more_chunks.unwrap_or(false);
                let suppress = resp.suppress_response.unwrap_or(false);

                // Invoke callback while the rx buffer is still valid
                let cb_result = on_response(&resp);

                (more, suppress, cb_result)
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
    /// Sends a WriteRequest and returns the WriteResponse containing
    /// the status of each write operation.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `attr_data` - Attribute data to write
    /// - `timed_timeout_ms` - Optional timeout for timed write (required for some attributes)
    ///
    /// # Returns
    /// The parsed WriteResponse, or an error if the request failed.
    pub async fn write<'a>(
        exchange: &'a mut Exchange<'_>,
        attr_data: &[AttrData<'_>],
        timed_timeout_ms: Option<u16>,
    ) -> Result<WriteResp<'a>, Error> {
        // If timed, send TimedRequest first
        if let Some(timeout_ms) = timed_timeout_ms {
            Self::send_timed_request(exchange, timeout_ms).await?;
        }

        let req = WriteRequestBuilder::new(attr_data, timed_timeout_ms.is_some());

        exchange
            .send_with(|_, wb| {
                req.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::WriteRequest.into()))
            })
            .await?;

        exchange.recv_fetch().await?;

        // Check opcode before acknowledging
        {
            let rx = exchange.rx()?;
            Self::check_opcode(rx.meta().proto_opcode, OpCode::WriteResponse)?;
        }

        // Send ACK for the WriteResponse so there's no pending ACK when the exchange is dropped.
        // This prevents race conditions with subsequent exchanges.
        exchange.acknowledge().await?;

        // Parse response (rx buffer is still valid after acknowledge)
        let rx = exchange.rx()?;
        let resp = WriteResp::from_tlv(&TLVElement::new(rx.payload()))?;

        Ok(resp)
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
        exchange: &mut Exchange<'_>,
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
    /// The exchange remains borrowed for the lifetime of the returned
    /// `AttrResp`, since the response data points into the exchange's RX
    /// buffer.
    ///
    /// # Returns
    /// The first `AttrResp` from the report data, or an error if no
    /// attribute response was found, the read failed, chunking was
    /// encountered, or `suppress_response` was false.
    pub async fn read_single_attr<'a>(
        exchange: &'a mut Exchange<'_>,
        endpoint: EndptId,
        cluster: ClusterId,
        attr: AttrId,
        fabric_filtered: bool,
    ) -> Result<AttrResp<'a>, Error> {
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
                Self::send_abort(exchange).await?;
                return Err(ErrorCode::InvalidData.into());
            }

            resp.suppress_response.unwrap_or(false)
        };

        if !suppress_response {
            // suppress_response=false means the server expects a StatusResponse,
            // which requires send_with() and clears the RX buffer, making
            // zero-copy return impossible. Complete the exchange properly,
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

        resp.attr_reports
            .as_ref()
            .and_then(|reports| reports.iter().next())
            .ok_or(Error::from(ErrorCode::InvalidData))?
            .map_err(|_| Error::from(ErrorCode::InvalidData))
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
        exchange: &mut Exchange<'_>,
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
    /// # Returns
    /// The first `CmdResp` from the invoke response, or an error if no
    /// response was found, the invoke failed, or chunking was encountered.
    pub async fn invoke_single_cmd<'a>(
        exchange: &'a mut Exchange<'_>,
        endpoint: EndptId,
        cluster: ClusterId,
        cmd: u32,
        cmd_data: TLVElement<'_>,
        timed_timeout_ms: Option<u16>,
    ) -> Result<CmdResp<'a>, Error> {
        // If timed, send TimedRequest first
        if let Some(timeout_ms) = timed_timeout_ms {
            Self::send_timed_request(exchange, timeout_ms).await?;
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
                return Ok(CmdResp::status_new(
                    CmdPath {
                        endpoint: Some(endpoint),
                        cluster: Some(cluster),
                        cmd: Some(cmd),
                    },
                    IMStatusCode::Success,
                    None,
                    None,
                ));
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
                Self::send_abort(exchange).await?;
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

        resp.invoke_responses
            .as_ref()
            .and_then(|responses| responses.iter().next())
            .ok_or(Error::from(ErrorCode::InvalidData))?
            .map_err(|_| Error::from(ErrorCode::InvalidData))
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
