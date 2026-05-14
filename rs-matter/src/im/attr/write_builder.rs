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

//! Streaming TLV builders for `WriteRequestMessage` and its sub-structures.
//!
//! Contrast with the snapshot-style `WriteRequestBuilder` in
//! `crate::im::client`: that one is a plain data struct that holds a
//! pre-built `&[AttrData]` and serialises it via `ToTLV` after the
//! caller has assembled all paths and payloads in some other buffer.
//!
//! The builders in *this* module write **directly** into the outbound
//! `TLVWrite` (typically the exchange's TX `WriteBuf`), field by field,
//! in the same typestate style the codegen emits for cluster structs.
//! No intermediate `Vec` of `AttrData`, no separate buffer for the
//! attribute payload — every byte ends up in the TX buffer exactly
//! once.
//!
//! # Layout
//!
//! Per Matter Core spec §10.7.5 `WriteRequestMessage` is an
//! anonymous-tagged struct with four fields:
//!
//! | Tag | Field             | Type                |
//! |-----|-------------------|---------------------|
//! | 0   | SuppressResponse  | bool? (omit = false)|
//! | 1   | TimedRequest      | bool? (omit = false)|
//! | 2   | WriteRequests     | array[AttrData]     |
//! | 3   | MoreChunkedMessages | bool?             |
//!
//! `AttrData` (`AttributeDataIB`) is itself a struct with:
//!
//! | Tag | Field      | Type        |
//! |-----|------------|-------------|
//! | 0   | DataVersion | u32?       |
//! | 1   | Path        | AttrPath   |
//! | 2   | Data        | any TLV    |
//!
//! `AttrPath` (`AttributePathIB`) is a *list* (not a struct, per IM
//! spec) with optional fields at tags 0..5 (tag_compression, node,
//! endpoint, cluster, attr, list_index). For attribute writes the
//! common shape is concrete `(endpoint, cluster, attr)`; the builder
//! below exposes those three as required, leaving the wildcard /
//! list-index variants out of the first-cut surface — they can be
//! added via additional setters when a real use case appears.
//!
//! # Usage
//!
//! Optional fields are **implicitly skipped** — just don't call their
//! setter. Later-field methods are available on earlier states, so a
//! minimal call writes only the mandatory `WriteRequests` array:
//!
//! ```ignore
//! exchange.send_with(|_, wb| {
//!     let parent = TLVWriteParent::new("WriteRequest", wb);
//!     WriteReqBuilder::new(parent)?
//!         // SuppressResponse + TimedRequest implicitly skipped:
//!         .write_requests()?
//!             .push()?
//!                 // DataVersion implicitly skipped:
//!                 .path(1, 0x0006 /* OnOff */, 0x4001 /* OnTime */)?
//!                 .data(|w| 60u16.to_tlv(&TLVTag::Context(2), w))?
//!             .end()?
//!         .end()?
//!         // MoreChunkedMessages implicitly skipped:
//!         .end()?;
//!     Ok(Some(OpCode::WriteRequest.into()))
//! }).await
//! ```
//!
//! To include an optional field, just call its setter — that locks
//! out earlier-state alternatives via the typestate, so call order
//! still matches the spec field order:
//!
//! ```ignore
//! WriteReqBuilder::new(parent)?
//!     .timed_request(true)?            // SuppressResponse skipped
//!     .write_requests()?
//!         .push()?
//!             .data_version(42)?       // optimistic-concurrency write
//!             .path(1, 0x001F /* ACL */, 0x0000 /* ACL */)?
//!             .data(|w| acl_value.to_tlv(&TLVTag::Context(2), w))?
//!         .end()?
//!     .end()?
//!     .more_chunks(true)?              // explicit chunked write
//!     .end()?
//! ```

use core::marker::PhantomData;

use crate::dm::{AttrId, ClusterId, EndptId};
use crate::error::Error;
use crate::im::{AttrDataTag, AttrPathTag, WriteReqTag};
use crate::tlv::{TLVBuilder, TLVBuilderParent, TLVTag, TLVWrite};

/// Streaming builder for a `WriteRequestMessage`. Type-state-tagged
/// so the compiler enforces in-order field writes. Optional fields
/// are **implicitly skipped** by simply not calling their setter —
/// later-field setters are available on all earlier states.
///
/// Field-state values (the state *after* each named field has been
/// written or implicitly skipped):
/// - `0`: nothing written yet
/// - `1`: past `SuppressResponse` (written or skipped)
/// - `2`: past `TimedRequest`
/// - `3`: past `WriteRequests` array (closed)
/// - `4`: past `MoreChunkedMessages`
///
/// In practice almost every call is `WriteReqBuilder::new(p)?
/// .write_requests()? … .end()?` — `SuppressResponse` and
/// `MoreChunkedMessages` default to absent (= false on the wire),
/// `TimedRequest` is only set when issuing a timed write.
pub struct WriteReqBuilder<P, const F: usize = 0> {
    p: P,
}

impl<P> WriteReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Begin a new `WriteRequestMessage` — opens a struct at the
    /// given tag on the parent's writer. For top-level use (the
    /// usual case) pass `&TLVTag::Anonymous`.
    pub fn new(mut p: P, tag: &TLVTag) -> Result<Self, Error> {
        p.writer().start_struct(tag)?;
        Ok(Self { p })
    }
}

impl<P> TLVBuilder<P> for WriteReqBuilder<P, 0>
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
// `suppress_response` — settable from state 0; advances to state 1.
// ---------------------------------------------------------------------
impl<P> WriteReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Write the optional `SuppressResponse` field. Omit (don't call)
    /// to leave the field absent on the wire.
    pub fn suppress_response(mut self, value: bool) -> Result<WriteReqBuilder<P, 1>, Error> {
        self.p
            .writer()
            .bool(&TLVTag::Context(WriteReqTag::SuppressResponse as u8), value)?;
        Ok(WriteReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `timed_request` — settable from state 0 or 1; advances to state 2.
// ---------------------------------------------------------------------
impl<P> WriteReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Write the optional `TimedRequest` field. Calling this from
    /// state 0 implicitly skips `SuppressResponse`.
    pub fn timed_request(self, value: bool) -> Result<WriteReqBuilder<P, 2>, Error> {
        WriteReqBuilder::<P, 1> { p: self.p }.timed_request(value)
    }
}

impl<P> WriteReqBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    /// Write the optional `TimedRequest` field.
    pub fn timed_request(mut self, value: bool) -> Result<WriteReqBuilder<P, 2>, Error> {
        self.p
            .writer()
            .bool(&TLVTag::Context(WriteReqTag::TimedRequest as u8), value)?;
        Ok(WriteReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `write_requests` — required; openable from state 0, 1, or 2.
// ---------------------------------------------------------------------
impl<P> WriteReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Open the `WriteRequests` array. Calling from state 0
    /// implicitly skips both `SuppressResponse` and `TimedRequest`.
    pub fn write_requests(self) -> Result<AttrDataArrayBuilder<WriteReqBuilder<P, 3>>, Error> {
        WriteReqBuilder::<P, 2> { p: self.p }.write_requests()
    }
}

impl<P> WriteReqBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    /// Open the `WriteRequests` array, implicitly skipping `TimedRequest`.
    pub fn write_requests(self) -> Result<AttrDataArrayBuilder<WriteReqBuilder<P, 3>>, Error> {
        WriteReqBuilder::<P, 2> { p: self.p }.write_requests()
    }
}

impl<P> WriteReqBuilder<P, 2>
where
    P: TLVBuilderParent,
{
    /// Open the `WriteRequests` array. Each `.push()` on the returned
    /// builder starts one `AttrData` entry; close with `.end()` to
    /// return to the message builder.
    pub fn write_requests(self) -> Result<AttrDataArrayBuilder<WriteReqBuilder<P, 3>>, Error> {
        AttrDataArrayBuilder::new(
            WriteReqBuilder { p: self.p },
            &TLVTag::Context(WriteReqTag::WriteRequests as u8),
        )
    }
}

// ---------------------------------------------------------------------
// `more_chunks` — settable from state 3; advances to state 4.
// ---------------------------------------------------------------------
impl<P> WriteReqBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    /// Write the optional `MoreChunkedMessages` field. Omit (don't
    /// call — go straight to `.end()`) for single-chunk writes.
    pub fn more_chunks(mut self, value: bool) -> Result<WriteReqBuilder<P, 4>, Error> {
        self.p
            .writer()
            .bool(&TLVTag::Context(WriteReqTag::MoreChunked as u8), value)?;
        Ok(WriteReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `end` — closable from state 3 or 4.
// ---------------------------------------------------------------------
impl<P> WriteReqBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    /// Close the message struct, implicitly skipping
    /// `MoreChunkedMessages`. Returns the parent.
    pub fn end(self) -> Result<P, Error> {
        WriteReqBuilder::<P, 4> { p: self.p }.end()
    }
}

impl<P> WriteReqBuilder<P, 4>
where
    P: TLVBuilderParent,
{
    /// Close the message struct and return the parent.
    pub fn end(mut self) -> Result<P, Error> {
        self.p.writer().end_container()?;
        Ok(self.p)
    }
}

// Bridge: the `WriteReqBuilder<P, F>` is itself a parent
// for sub-builders (the array of AttrData). Forward `writer()` to the
// inner parent.
impl<P, const F: usize> TLVBuilderParent for WriteReqBuilder<P, F>
where
    P: TLVBuilderParent,
{
    type Write = P::Write;

    fn writer(&mut self) -> &mut Self::Write {
        self.p.writer()
    }
}

impl<P, const F: usize> core::fmt::Debug for WriteReqBuilder<P, F>
where
    P: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}::WriteRequestMessage<{}>", self.p, F)
    }
}

#[cfg(feature = "defmt")]
impl<P, const F: usize> defmt::Format for WriteReqBuilder<P, F>
where
    P: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{:?}::WriteRequestMessage<{}>", self.p, F);
    }
}

/// Array builder for the `WriteRequests` field. The array is opened
/// in `write_requests()`; this type provides `.push()` (start one
/// entry) and `.end()` (close the array, return to the message
/// builder).
pub struct AttrDataArrayBuilder<P> {
    p: P,
}

impl<P> AttrDataArrayBuilder<P>
where
    P: TLVBuilderParent,
{
    /// Begin a new `AttrData` array — opens an array at the given
    /// tag on the parent's writer. Use the [`TLVBuilder`] trait
    /// constructor for the standard call.
    pub fn new(mut p: P, tag: &TLVTag) -> Result<Self, Error> {
        p.writer().start_array(tag)?;
        Ok(Self { p })
    }

    /// Start a new `AttrData` entry. The returned [`AttrDataBuilder`]
    /// terminates with `.end()` which returns this array builder.
    pub fn push(self) -> Result<AttrDataBuilder<Self, 0>, Error> {
        // Each AttrData is an anonymous-tagged struct (we're inside an array).
        AttrDataBuilder::new(self, &TLVTag::Anonymous)
    }

    /// Close the array and return the message builder.
    pub fn end(mut self) -> Result<P, Error> {
        self.p.writer().end_container()?;
        Ok(self.p)
    }
}

impl<P> TLVBuilder<P> for AttrDataArrayBuilder<P>
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

impl<P> TLVBuilderParent for AttrDataArrayBuilder<P>
where
    P: TLVBuilderParent,
{
    type Write = P::Write;

    fn writer(&mut self) -> &mut Self::Write {
        self.p.writer()
    }
}

impl<P> core::fmt::Debug for AttrDataArrayBuilder<P>
where
    P: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}[]", self.p)
    }
}

#[cfg(feature = "defmt")]
impl<P> defmt::Format for AttrDataArrayBuilder<P>
where
    P: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{:?}[]", self.p);
    }
}

/// Streaming builder for a single `AttrData` entry inside the
/// `WriteRequests` array.
///
/// Field-state values:
/// - `0`: nothing written yet
/// - `1`: `DataVersion` decided
/// - `2`: `Path` written
/// - `3`: `Data` written (struct can be closed)
pub struct AttrDataBuilder<P, const F: usize = 0> {
    p: P,
    _f: PhantomData<[(); F]>,
}

impl<P> AttrDataBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Begin a new `AttrData` entry — opens a struct at the given
    /// tag. Use `&TLVTag::Anonymous` when pushed into the
    /// `WriteRequests` array (the typical case).
    pub fn new(mut p: P, tag: &TLVTag) -> Result<Self, Error> {
        p.writer().start_struct(tag)?;
        Ok(Self { p, _f: PhantomData })
    }
}

impl<P> TLVBuilder<P> for AttrDataBuilder<P, 0>
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
// `data_version` — settable from state 0; advances to state 1.
// ---------------------------------------------------------------------
impl<P> AttrDataBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Write the optional `DataVersion` field — used for
    /// optimistic-concurrency writes that should fail on stale data.
    /// Omit (don't call) for unconditional writes; subsequent `path*`
    /// methods are also available on state 0 and implicitly skip
    /// this field.
    pub fn data_version(mut self, value: u32) -> Result<AttrDataBuilder<P, 1>, Error> {
        self.p
            .writer()
            .u32(&TLVTag::Context(AttrDataTag::DataVer as u8), value)?;
        Ok(AttrDataBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }
}

// ---------------------------------------------------------------------
// `path` / `path_from` — required; available from state 0 or 1.
// ---------------------------------------------------------------------
impl<P> AttrDataBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Write the concrete `(endpoint, cluster, attribute)` path,
    /// implicitly skipping `DataVersion`.
    pub fn path(
        self,
        endpoint: EndptId,
        cluster: ClusterId,
        attr: AttrId,
    ) -> Result<AttrDataBuilder<P, 2>, Error> {
        AttrDataBuilder::<P, 1> {
            p: self.p,
            _f: PhantomData,
        }
        .path(endpoint, cluster, attr)
    }

    /// Write the path from an existing [`crate::im::AttrPath`],
    /// implicitly skipping `DataVersion`. Used by the
    /// snapshot→streaming bridge in `ImClient::write`.
    pub fn path_from(self, path: &crate::im::AttrPath) -> Result<AttrDataBuilder<P, 2>, Error> {
        AttrDataBuilder::<P, 1> {
            p: self.p,
            _f: PhantomData,
        }
        .path_from(path)
    }
}

impl<P> AttrDataBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    /// Write the concrete `(endpoint, cluster, attribute)` path. This
    /// is the typical shape for attribute writes; wildcards aren't
    /// generally meaningful for writes and aren't exposed here. The
    /// path is encoded as a *list* (per spec §10.6.2 `AttributePathIB`).
    pub fn path(
        mut self,
        endpoint: EndptId,
        cluster: ClusterId,
        attr: AttrId,
    ) -> Result<AttrDataBuilder<P, 2>, Error> {
        let w = self.p.writer();
        w.start_list(&TLVTag::Context(AttrDataTag::Path as u8))?;
        w.u16(&TLVTag::Context(AttrPathTag::Endpoint as u8), endpoint)?;
        w.u32(&TLVTag::Context(AttrPathTag::Cluster as u8), cluster)?;
        w.u32(&TLVTag::Context(AttrPathTag::Attribute as u8), attr)?;
        w.end_container()?;
        Ok(AttrDataBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }

    /// Write the path from an existing [`crate::im::AttrPath`]. Used
    /// by the snapshot→streaming bridge in `ImClient::write` so the
    /// pre-built `AttrPath` (which may carry wildcards or
    /// `list_index`) is re-emitted faithfully. New call sites should
    /// prefer [`Self::path`].
    pub fn path_from(mut self, path: &crate::im::AttrPath) -> Result<AttrDataBuilder<P, 2>, Error> {
        use crate::tlv::ToTLV;
        path.to_tlv(&TLVTag::Context(AttrDataTag::Path as u8), self.p.writer())?;
        Ok(AttrDataBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }
}

impl<P> AttrDataBuilder<P, 2>
where
    P: TLVBuilderParent,
{
    /// Write the attribute value into the `Data` slot.
    ///
    /// Per Matter Core spec §10.6.2 `AttributeDataIB.Data` is "any
    /// TLV value." The closure receives the parent's `TLVWrite` and
    /// **must** emit exactly one TLV element tagged
    /// `TLVTag::Context(2)` (i.e. `AttrDataTag::Data`). The IM-level
    /// builder can't enforce the inner type because the schema lives
    /// in the attribute the path named, not the IM message; the
    /// closure body is where the caller asserts the schema match
    /// (typically by calling a codegen-emitted typed writer).
    ///
    /// Idiomatic call patterns:
    ///
    /// ```ignore
    /// // Any `T: ToTLV`:
    /// .data(|w| 60u16.to_tlv(&TLVTag::Context(AttrDataTag::Data as u8), w))?
    ///
    /// // A bool, raw:
    /// .data(|w| w.bool(&TLVTag::Context(AttrDataTag::Data as u8), true))?
    ///
    /// // A codegen-emitted typed helper that already knows the tag:
    /// .data(|w| on_off::write_on_time_value(60u16, w))?
    /// ```
    pub fn data<F>(mut self, f: F) -> Result<AttrDataBuilder<P, 3>, Error>
    where
        F: FnOnce(&mut P::Write) -> Result<(), Error>,
    {
        f(self.p.writer())?;
        Ok(AttrDataBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }

    /// Open the `Data` slot as a typed sub-builder.
    ///
    /// Closure-free counterpart to [`data`](Self::data) — hand back
    /// the codegen-emitted typed value builder for the attribute,
    /// already opened at `AttrDataTag::Data`. The caller fills the
    /// value, then calls `.end()` on the sub-builder; that close
    /// writes `Data`'s closing tag (for struct/array-valued attrs)
    /// and yields an [`AttrDataBuilder<P, 3>`]. The caller then
    /// `.end()`s once more to close the `AttrData` entry struct
    /// (the "double-end" pattern of the IM-client glue).
    ///
    /// Useful for struct- or array-valued attributes (e.g. ACL
    /// entries). For scalars prefer the closure-based [`data`].
    ///
    /// Soundness of the phantom typestate advance: see
    /// [`CmdDataBuilder::data_builder`].
    pub fn data_builder<B>(self) -> Result<B, Error>
    where
        B: TLVBuilder<AttrDataBuilder<P, 3>>,
    {
        let advanced = AttrDataBuilder {
            p: self.p,
            _f: PhantomData,
        };
        B::new(advanced, &TLVTag::Context(AttrDataTag::Data as u8))
    }
}

impl<P> AttrDataBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    /// Close the `AttrData` struct and return the array builder so
    /// the caller can `.push()` another entry or `.end()` the array.
    pub fn end(mut self) -> Result<P, Error> {
        self.p.writer().end_container()?;
        Ok(self.p)
    }
}

impl<P, const F: usize> TLVBuilderParent for AttrDataBuilder<P, F>
where
    P: TLVBuilderParent,
{
    type Write = P::Write;

    fn writer(&mut self) -> &mut Self::Write {
        self.p.writer()
    }
}

impl<P, const F: usize> core::fmt::Debug for AttrDataBuilder<P, F>
where
    P: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}::AttrData<{}>", self.p, F)
    }
}

#[cfg(feature = "defmt")]
impl<P, const F: usize> defmt::Format for AttrDataBuilder<P, F>
where
    P: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{:?}::AttrData<{}>", self.p, F);
    }
}
