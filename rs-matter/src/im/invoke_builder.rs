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
//! All three are mandatory on the wire per the spec — and Matter 1.5
//! strictly-validating peers like SmartThings reject requests with
//! either bool field absent — so the builder always emits all three.
//! At the API level, however, the two booleans are *optional*: the
//! caller may skip `suppress_response()` and/or `timed_request()` and
//! the builder will fill them in with their default value (`false`)
//! automatically. The default matches what every normal client
//! wants — receive a response, no timed-request handshake — so the
//! common-case ceremony collapses to just `invoke_requests()?`.
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
//!     // `suppress_response` and `timed_request` are skipped here —
//!     // the builder fills them in as `false` on the wire.
//!     InvReqBuilder::new(parent)?
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

use crate::dm::{ClusterId, CmdId, EndptId, GlobalElements};
use crate::error::Error;
use crate::im::{CmdDataTag, CmdPathTag, InvReqTag, IM_REVISION};
use crate::tlv::{TLVBuilder, TLVBuilderParent, TLVTag, TLVWrite, ToTLV};

/// Streaming builder for an `InvokeRequestMessage`. Type-state-tagged
/// so the compiler enforces in-order field writes.
///
/// All three top-level fields (`SuppressResponse`, `TimedRequest`,
/// `InvokeRequests`) are mandatory on the wire per Matter Core spec
/// §8.8.5, and the builder always emits all three. The two booleans
/// are *optional at the API level* though — skipping either setter
/// causes the builder to write the field with its default value
/// (`false`) before opening the next state. This matches the
/// `write_builder` ergonomics and keeps the common-case ceremony to
/// `invoke_requests()?` only. The CmdData entries inside the array
/// have an optional `CommandRef`, also implicitly skippable.
///
/// Field-state values:
/// - `0`: nothing written yet
/// - `1`: past `SuppressResponse`
/// - `2`: past `TimedRequest`
/// - `3`: past `InvokeRequests` array
/// - `4`: past `InteractionModelRevision` (auto-injected at default
///   value [`IM_REVISION`] by `end()` if the optional setter wasn't
///   called)
pub struct InvReqBuilder<P, const F: usize = 0> {
    p: P,
}

impl<P> InvReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Begin a new `InvokeRequestMessage` — opens a struct at the
    /// given tag. For top-level use (the usual case) pass
    /// `&TLVTag::Anonymous`.
    pub fn new(mut p: P, tag: &TLVTag) -> Result<Self, Error> {
        p.writer().start_struct(tag)?;
        Ok(Self { p })
    }
}

impl<P> TLVBuilder<P> for InvReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    fn new(parent: P, tag: &TLVTag) -> Result<Self, Error> {
        Self::new(parent, tag)
    }

    fn unchecked_into_parent(self) -> P {
        self.p
    }
}

// ---------------------------------------------------------------------
// `suppress_response` — optional in the *API* but mandatory on the
// *wire*. Settable from state 0 (advances to state 1). Skipping —
// going straight to `timed_request` or `invoke_requests` — causes the
// builder to emit the field with its default value (`false`)
// automatically, so strictly-validating peers (e.g. Matter 1.5
// SmartThings) still see all three top-level fields present.
// ---------------------------------------------------------------------
impl<P> InvReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Write the `SuppressResponse` field. Omitting this call is
    /// equivalent to `suppress_response(false)` (i.e. the typical
    /// case — most clients want a response); the builder emits the
    /// default automatically when `timed_request` or
    /// `invoke_requests` is called from state 0. Set to `true` only
    /// for fire-and-forget commands.
    pub fn suppress_response(mut self, value: bool) -> Result<InvReqBuilder<P, 1>, Error> {
        self.p
            .writer()
            .bool(&TLVTag::Context(InvReqTag::SupressResponse as u8), value)?;
        Ok(InvReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `timed_request` — same shape: optional in the API (defaults to
// `false`), mandatory on the wire. Settable from state 0 or 1.
// ---------------------------------------------------------------------
impl<P> InvReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Write the `TimedRequest` field, implicitly emitting
    /// `SuppressResponse(false)` first (the common-case default).
    pub fn timed_request(self, value: bool) -> Result<InvReqBuilder<P, 2>, Error> {
        self.suppress_response(false)?.timed_request(value)
    }
}

impl<P> InvReqBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    /// Write the `TimedRequest` field. Omitting this call is
    /// equivalent to `timed_request(false)`; the builder emits the
    /// default automatically when `invoke_requests` is called from
    /// state 1. Set to `true` only when the surrounding flow sent a
    /// `TimedRequest` IM message first (some commands like ACL
    /// writes require this).
    pub fn timed_request(mut self, value: bool) -> Result<InvReqBuilder<P, 2>, Error> {
        self.p
            .writer()
            .bool(&TLVTag::Context(InvReqTag::TimedReq as u8), value)?;
        Ok(InvReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `invoke_requests` — required; openable from state 0, 1, or 2.
// Calling from 0 or 1 fills in the missing default fields first so
// the wire layout always contains all three top-level fields.
// ---------------------------------------------------------------------
impl<P> InvReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Open the `InvokeRequests` array, implicitly emitting
    /// `SuppressResponse(false)` and `TimedRequest(false)` first.
    pub fn invoke_requests(self) -> Result<CmdDataArrayBuilder<InvReqBuilder<P, 3>>, Error> {
        self.suppress_response(false)?.invoke_requests()
    }
}

impl<P> InvReqBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    /// Open the `InvokeRequests` array, implicitly emitting
    /// `TimedRequest(false)` first.
    pub fn invoke_requests(self) -> Result<CmdDataArrayBuilder<InvReqBuilder<P, 3>>, Error> {
        self.timed_request(false)?.invoke_requests()
    }
}

impl<P> InvReqBuilder<P, 2>
where
    P: TLVBuilderParent,
{
    /// Open the `InvokeRequests` array. Each `.push()` starts one
    /// [`CmdDataBuilder`]; close with `.end()` to return to the
    /// message builder.
    pub fn invoke_requests(self) -> Result<CmdDataArrayBuilder<InvReqBuilder<P, 3>>, Error> {
        CmdDataArrayBuilder::new(
            InvReqBuilder { p: self.p },
            &TLVTag::Context(InvReqTag::InvokeRequests as u8),
        )
    }
}

impl<P> InvReqBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    /// Write the mandatory-on-the-wire `InteractionModelRevision`
    /// field (Matter Core §8.1.1, p. 545: value is `13` since Matter
    /// 1.3, unchanged in 1.4 and 1.5). Optional at the API level —
    /// omit and `end()` injects [`IM_REVISION`] automatically.
    pub fn interaction_model_revision(mut self, value: u8) -> Result<InvReqBuilder<P, 4>, Error> {
        self.p.writer().u8(
            &TLVTag::Context(GlobalElements::InteractionModelRevision as u8),
            value,
        )?;
        Ok(InvReqBuilder { p: self.p })
    }

    /// Close the message struct, auto-injecting
    /// `InteractionModelRevision` at its default value
    /// [`IM_REVISION`]. Returns the parent.
    pub fn end(self) -> Result<P, Error> {
        self.interaction_model_revision(IM_REVISION)?.end()
    }
}

impl<P> InvReqBuilder<P, 4>
where
    P: TLVBuilderParent,
{
    /// Close the message struct and return the parent.
    pub fn end(mut self) -> Result<P, Error> {
        self.p.writer().end_container()?;
        Ok(self.p)
    }
}

impl<P, const F: usize> TLVBuilderParent for InvReqBuilder<P, F>
where
    P: TLVBuilderParent,
{
    type Write = P::Write;

    fn writer(&mut self) -> &mut Self::Write {
        self.p.writer()
    }
}

impl<P, const F: usize> core::fmt::Debug for InvReqBuilder<P, F>
where
    P: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}::InvokeRequestMessage<{}>", self.p, F)
    }
}

#[cfg(feature = "defmt")]
impl<P, const F: usize> defmt::Format for InvReqBuilder<P, F>
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
/// [`InvReqBuilder::invoke_requests`]; close with
/// `.end()` to return to the message builder.
pub struct CmdDataArrayBuilder<P> {
    p: P,
}

impl<P> CmdDataArrayBuilder<P>
where
    P: TLVBuilderParent,
{
    /// Begin a new `CmdData` array — opens an array at the given tag.
    pub fn new(mut p: P, tag: &TLVTag) -> Result<Self, Error> {
        p.writer().start_array(tag)?;
        Ok(Self { p })
    }

    /// Start a new `CmdData` entry. The returned [`CmdDataBuilder`]
    /// terminates with `.end()` which returns this array builder.
    pub fn push(self) -> Result<CmdDataBuilder<Self, 0>, Error> {
        CmdDataBuilder::new(self, &TLVTag::Anonymous)
    }

    /// Close the array and return the message builder.
    pub fn end(mut self) -> Result<P, Error> {
        self.p.writer().end_container()?;
        Ok(self.p)
    }
}

impl<P> TLVBuilder<P> for CmdDataArrayBuilder<P>
where
    P: TLVBuilderParent,
{
    fn new(parent: P, tag: &TLVTag) -> Result<Self, Error> {
        Self::new(parent, tag)
    }

    fn unchecked_into_parent(self) -> P {
        self.p
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
pub struct CmdDataBuilder<P, const F: usize = 0> {
    p: P,
    _f: PhantomData<[(); F]>,
}

impl<P> CmdDataBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Begin a new `CmdData` entry — opens a struct at the given tag.
    /// Use `&TLVTag::Anonymous` when pushed into an `InvokeRequests`
    /// array (the typical case).
    pub fn new(mut p: P, tag: &TLVTag) -> Result<Self, Error> {
        p.writer().start_struct(tag)?;
        Ok(Self { p, _f: PhantomData })
    }
}

impl<P> TLVBuilder<P> for CmdDataBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    fn new(parent: P, tag: &TLVTag) -> Result<Self, Error> {
        Self::new(parent, tag)
    }

    fn unchecked_into_parent(self) -> P {
        self.p
    }
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

    /// Open the `Data` slot as a typed sub-builder.
    ///
    /// Closure-free counterpart to [`data`](Self::data) — hand back
    /// the codegen-emitted request builder for the command, already
    /// opened at `CmdDataTag::Data`. The caller fills the request
    /// fields, then calls `.end()` on the sub-builder; that close
    /// writes `Data`'s closing tag and yields a
    /// [`CmdDataBuilder<P, 2>`]. The caller then `.end()`s once more
    /// to close the `CmdData` entry struct itself (the "double-end"
    /// pattern of the IM-client glue).
    ///
    /// Soundness of the phantom typestate advance: `B::new` is
    /// contractually required (by [`TLVBuilder`]) to open exactly one
    /// container at the supplied tag, and `B`'s terminal `.end()`
    /// closes it. So by the time the caller observes the returned
    /// `CmdDataBuilder<P, 2>`, the `Data` field has been fully written
    /// and the typestate matches the wire state.
    pub fn data_builder<B>(self) -> Result<B, Error>
    where
        B: TLVBuilder<CmdDataBuilder<P, 2>>,
    {
        let advanced = CmdDataBuilder {
            p: self.p,
            _f: PhantomData,
        };
        B::new(advanced, &TLVTag::Context(CmdDataTag::Data as u8))
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
