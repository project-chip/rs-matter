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

//! Streaming TLV builders for `InvokeRequestMessage` and its
//! sub-structures.
//!
//! This is the analog of [`crate::im::attr::write_builder`] for
//! command invokes — and the genuine MCU win for client clusters: a
//! switch wanting to send `OnOff::Toggle` to a bound bulb constructs
//! the command-request payload directly into the TX `WriteBuf` via
//! [`CmdDataBuilder::data`], no sibling buffer needed.
//!
//! # Layout
//!
//! Per Matter Core spec §10.7.9 `InvokeRequestMessage` is an
//! anonymous-tagged struct with three fields:
//!
//! | Tag | Field            | Type           | Required |
//! |-----|------------------|----------------|----------|
//! | 0   | SuppressResponse | bool           | **yes**  |
//! | 1   | TimedRequest     | bool           | **yes**  |
//! | 2   | InvokeRequests   | array[CmdData] | **yes**  |
//!
//! All three are mandatory per the spec (and Matter 1.5
//! strictly-validating peers like SmartThings reject requests with
//! either bool field absent). The typestate machine therefore
//! requires `suppress_response()`, `timed_request()`, and
//! `invoke_requests()` to be called in order — there's no
//! implicit-skip on this builder for the first two fields.
//!
//! `CmdData` (`CommandDataIB`) is a struct with:
//!
//! | Tag | Field      | Type        | Required |
//! |-----|------------|-------------|----------|
//! | 0   | Path       | CmdPath     | yes      |
//! | 1   | Data       | any TLV     | yes      |
//! | 2   | CommandRef | u16         | conditional (mandatory when invoke is batched) |
//!
//! `CmdPath` (`CommandPathIB`) is a TLV *list* with optional fields
//! at tags 0,1,2 (endpoint, cluster, cmd). For client-cluster sends
//! the path is always concrete `(endpoint, cluster, cmd)`; the
//! builder requires all three.
//!
//! # Usage
//!
//! ```ignore
//! exchange.send_with(|_, wb| {
//!     let parent = TLVWriteParent::new("InvokeRequest", wb);
//!     InvokeRequestMessageBuilder::new(parent)?
//!         .suppress_response(false)?
//!         .timed_request(false)?
//!         .invoke_requests()?
//!             .push()?
//!                 .path(1, 0x0006 /* OnOff */, 0x02 /* Toggle */)?
//!                 .data(|w| {
//!                     // Toggle's request body is empty:
//!                     w.start_struct(&TLVTag::Context(CmdDataTag::Data as u8))?;
//!                     w.end_container()
//!                 })?
//!             .end()?
//!         .end()?
//!         .end()?;
//!     Ok(Some(OpCode::InvokeRequest.into()))
//! }).await
//! ```

use core::marker::PhantomData;

use crate::dm::{ClusterId, CmdId, EndptId};
use crate::error::Error;
use crate::im::CmdDataTag;
use crate::tlv::{TLVBuilderParent, TLVTag, TLVWrite, ToTLV};

/// Context tags for the three top-level fields of
/// `InvokeRequestMessage`. The crate doesn't yet export a public
/// `InvokeReqTag` enum because the snapshot-style
/// `InvokeRequestBuilder` writes via `derive(ToTLV)` and never names
/// the tags directly; defining them here mirrors the same field
/// positions the derive emits.
#[repr(u8)]
enum InvokeReqTag {
    SuppressResponse = 0,
    TimedRequest = 1,
    InvokeRequests = 2,
}

/// Context tags for the fields of `CommandPathIB` (Matter Core spec
/// §10.6.7). `CmdPath` is encoded as a TLV *list* with positional
/// context tags 0..2 — module-local mirror of [`crate::im::CmdPath`].
#[repr(u8)]
enum CmdPathTag {
    Endpoint = 0,
    Cluster = 1,
    Command = 2,
}

/// Streaming builder for an `InvokeRequestMessage`. Type-state-tagged
/// so the compiler enforces in-order field writes.
///
/// **No implicit-skip on the top-level fields** — Matter Core spec
/// §8.8.5 makes `SuppressResponse`, `TimedRequest`, and
/// `InvokeRequests` all mandatory, so the user must call each
/// setter. The CmdData entries inside the array do have an
/// optional `CommandRef`, which is implicitly skipped per the
/// `write_builder` convention.
///
/// Field-state values:
/// - `0`: nothing written yet
/// - `1`: past `SuppressResponse`
/// - `2`: past `TimedRequest`
/// - `3`: past `InvokeRequests` array
pub struct InvokeRequestMessageBuilder<P, const F: usize> {
    p: P,
}

impl<P> InvokeRequestMessageBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Begin a new `InvokeRequestMessage` — opens an anonymous struct
    /// on the parent's writer.
    pub fn new(mut p: P) -> Result<Self, Error> {
        p.writer().start_struct(&TLVTag::Anonymous)?;
        Ok(Self { p })
    }

    /// Write the mandatory `SuppressResponse` field. `false` is the
    /// typical value — most commands have a response and the client
    /// wants to receive it.
    pub fn suppress_response(
        mut self,
        value: bool,
    ) -> Result<InvokeRequestMessageBuilder<P, 1>, Error> {
        self.p.writer().bool(
            &TLVTag::Context(InvokeReqTag::SuppressResponse as u8),
            value,
        )?;
        Ok(InvokeRequestMessageBuilder { p: self.p })
    }
}

impl<P> InvokeRequestMessageBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    /// Write the mandatory `TimedRequest` field. Set to `true` only
    /// when the surrounding flow sent a `TimedRequest` IM message
    /// first (some commands like ACL writes require this).
    pub fn timed_request(
        mut self,
        value: bool,
    ) -> Result<InvokeRequestMessageBuilder<P, 2>, Error> {
        self.p
            .writer()
            .bool(&TLVTag::Context(InvokeReqTag::TimedRequest as u8), value)?;
        Ok(InvokeRequestMessageBuilder { p: self.p })
    }
}

impl<P> InvokeRequestMessageBuilder<P, 2>
where
    P: TLVBuilderParent,
{
    /// Open the mandatory `InvokeRequests` array. Each `.push()`
    /// starts one [`CmdDataBuilder`]; close with `.end()` to return
    /// to the message builder.
    pub fn invoke_requests(
        mut self,
    ) -> Result<CmdDataArrayBuilder<InvokeRequestMessageBuilder<P, 3>>, Error> {
        self.p
            .writer()
            .start_array(&TLVTag::Context(InvokeReqTag::InvokeRequests as u8))?;
        Ok(CmdDataArrayBuilder {
            p: InvokeRequestMessageBuilder { p: self.p },
        })
    }
}

impl<P> InvokeRequestMessageBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    /// Close the message struct and return the parent.
    pub fn end(mut self) -> Result<P, Error> {
        self.p.writer().end_container()?;
        Ok(self.p)
    }
}

impl<P, const F: usize> TLVBuilderParent for InvokeRequestMessageBuilder<P, F>
where
    P: TLVBuilderParent,
{
    type Write = P::Write;

    fn writer(&mut self) -> &mut Self::Write {
        self.p.writer()
    }
}

impl<P, const F: usize> core::fmt::Debug for InvokeRequestMessageBuilder<P, F>
where
    P: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}::InvokeRequestMessage<{}>", self.p, F)
    }
}

#[cfg(feature = "defmt")]
impl<P, const F: usize> defmt::Format for InvokeRequestMessageBuilder<P, F>
where
    P: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{:?}::InvokeRequestMessage<{}>", self.p, F);
    }
}

// =====================================================================
// CmdData array sub-builder
// =====================================================================

/// Array builder for the `InvokeRequests` field. Opened by
/// [`InvokeRequestMessageBuilder::invoke_requests`]; close with
/// `.end()` to return to the message builder.
pub struct CmdDataArrayBuilder<P> {
    p: P,
}

impl<P> CmdDataArrayBuilder<P>
where
    P: TLVBuilderParent,
{
    /// Start a new `CmdData` entry. The returned [`CmdDataBuilder`]
    /// terminates with `.end()` which returns this array builder.
    pub fn push(mut self) -> Result<CmdDataBuilder<Self, 0>, Error> {
        self.p.writer().start_struct(&TLVTag::Anonymous)?;
        Ok(CmdDataBuilder {
            p: self,
            _f: PhantomData,
        })
    }

    /// Close the array and return the message builder.
    pub fn end(mut self) -> Result<P, Error> {
        self.p.writer().end_container()?;
        Ok(self.p)
    }
}

impl<P> TLVBuilderParent for CmdDataArrayBuilder<P>
where
    P: TLVBuilderParent,
{
    type Write = P::Write;

    fn writer(&mut self) -> &mut Self::Write {
        self.p.writer()
    }
}

impl<P> core::fmt::Debug for CmdDataArrayBuilder<P>
where
    P: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}[]", self.p)
    }
}

#[cfg(feature = "defmt")]
impl<P> defmt::Format for CmdDataArrayBuilder<P>
where
    P: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{:?}[]", self.p);
    }
}

// =====================================================================
// CmdData entry builder
// =====================================================================

/// Streaming builder for one `CmdData` entry inside the
/// `InvokeRequests` array.
///
/// Field-state values:
/// - `0`: nothing written yet
/// - `1`: past `Path`
/// - `2`: past `Data` (struct can be closed)
/// - `3`: past `CommandRef`
pub struct CmdDataBuilder<P, const F: usize> {
    p: P,
    _f: PhantomData<[(); F]>,
}

// ---- path ------------------------------------------------------------
impl<P> CmdDataBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Write the concrete `(endpoint, cluster, command)` path.
    /// Wildcards aren't meaningful for invokes — every send targets a
    /// concrete `(endpoint, cluster, command)` triple. The path is
    /// encoded as a *list* per spec §10.6.7 `CommandPathIB`.
    pub fn path(
        mut self,
        endpoint: EndptId,
        cluster: ClusterId,
        cmd: CmdId,
    ) -> Result<CmdDataBuilder<P, 1>, Error> {
        let w = self.p.writer();
        w.start_list(&TLVTag::Context(CmdDataTag::Path as u8))?;
        w.u16(&TLVTag::Context(CmdPathTag::Endpoint as u8), endpoint)?;
        w.u32(&TLVTag::Context(CmdPathTag::Cluster as u8), cluster)?;
        w.u32(&TLVTag::Context(CmdPathTag::Command as u8), cmd)?;
        w.end_container()?;
        Ok(CmdDataBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }

    /// Write the path from an existing [`crate::im::CmdPath`]. Used
    /// by the snapshot→streaming bridge in `ImClient::invoke`.
    pub fn path_from(mut self, path: &crate::im::CmdPath) -> Result<CmdDataBuilder<P, 1>, Error> {
        path.to_tlv(&TLVTag::Context(CmdDataTag::Path as u8), self.p.writer())?;
        Ok(CmdDataBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }
}

// ---- data ------------------------------------------------------------
impl<P> CmdDataBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    /// Write the command request body into the `Data` slot.
    ///
    /// Per Matter Core spec §10.6.8 `CommandDataIB.Data` is the
    /// command's request payload — any TLV element tagged
    /// `TLVTag::Context(1)` (= `CmdDataTag::Data`). For commands
    /// with no request fields (e.g. `OnOff::On`, `OnOff::Toggle`)
    /// the data slot is still required: write an empty struct.
    ///
    /// Idiomatic call patterns:
    ///
    /// ```ignore
    /// // No-payload command (e.g. OnOff::Toggle):
    /// .data(|w| {
    ///     w.start_struct(&TLVTag::Context(CmdDataTag::Data as u8))?;
    ///     w.end_container()
    /// })?
    ///
    /// // Any `T: ToTLV` request body:
    /// .data(|w| req.to_tlv(&TLVTag::Context(CmdDataTag::Data as u8), w))?
    ///
    /// // Via a codegen-emitted typed request builder:
    /// .data(|w| MoveToHueRequestBuilder::new(w, ...)?
    ///             .hue(180)? .direction(...)? .end())?
    /// ```
    pub fn data<F>(mut self, f: F) -> Result<CmdDataBuilder<P, 2>, Error>
    where
        F: FnOnce(&mut P::Write) -> Result<(), Error>,
    {
        f(self.p.writer())?;
        Ok(CmdDataBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }
}

// ---- command_ref -----------------------------------------------------
impl<P> CmdDataBuilder<P, 2>
where
    P: TLVBuilderParent,
{
    /// Write the optional `CommandRef` field. **Mandatory** when the
    /// `InvokeRequests` array carries more than one entry (per spec
    /// §8.8.5 — the server echoes this back so the client can
    /// correlate responses to requests). For single-command invokes,
    /// omit (go straight to `.end()`).
    pub fn command_ref(mut self, value: u16) -> Result<CmdDataBuilder<P, 3>, Error> {
        self.p
            .writer()
            .u16(&TLVTag::Context(CmdDataTag::CommandRef as u8), value)?;
        Ok(CmdDataBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }
}

// ---- end -------------------------------------------------------------
// Closable from state 2 (CommandRef implicitly skipped) or state 3.
impl<P> CmdDataBuilder<P, 2>
where
    P: TLVBuilderParent,
{
    /// Close the `CmdData` struct, implicitly skipping `CommandRef`.
    /// Returns the array builder so the caller can `.push()` another
    /// entry or `.end()` the array.
    pub fn end(self) -> Result<P, Error> {
        CmdDataBuilder::<P, 3> {
            p: self.p,
            _f: PhantomData,
        }
        .end()
    }
}

impl<P> CmdDataBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    /// Close the `CmdData` struct and return the array builder.
    pub fn end(mut self) -> Result<P, Error> {
        self.p.writer().end_container()?;
        Ok(self.p)
    }
}

impl<P, const F: usize> TLVBuilderParent for CmdDataBuilder<P, F>
where
    P: TLVBuilderParent,
{
    type Write = P::Write;

    fn writer(&mut self) -> &mut Self::Write {
        self.p.writer()
    }
}

impl<P, const F: usize> core::fmt::Debug for CmdDataBuilder<P, F>
where
    P: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}::CmdData<{}>", self.p, F)
    }
}

#[cfg(feature = "defmt")]
impl<P, const F: usize> defmt::Format for CmdDataBuilder<P, F>
where
    P: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{:?}::CmdData<{}>", self.p, F);
    }
}
