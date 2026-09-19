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

//! Streaming TLV builders for `ReadRequestMessage` and its sub-structures.
//!
//! Compare with `WriteReqBuilder` in
//! [`crate::im::encoding::attr::write_builder`]: same typestate-machine shape,
//! same implicit-skip convention (optional fields are omitted by not
//! calling their setter; later-field setters are available on
//! earlier states so the user can write a minimal request in one
//! straight chain). The Read variant carries no payload per entry —
//! every entry is just an `AttrPath` list — so the path sub-builder
//! is much simpler than its `AttrData` counterpart.
//!
//! # Layout
//!
//! Per Matter Core spec `ReadRequestMessage` is an
//! anonymous-tagged struct with five fields:
//!
//! | Tag | Field             | Type             | Required |
//! |-----|-------------------|------------------|----------|
//! | 0   | AttributeRequests | array[AttrPath]? | no       |
//! | 1   | EventRequests     | array[EventPath]?| no       |
//! | 2   | EventFilters      | array[EventFilter]?| no     |
//! | 3   | FabricFiltered    | bool             | **yes**  |
//! | 4   | DataVersionFilters| array[DataVersionFilter]?| no |
//!
//! First-cut surface here covers the common case: attribute reads
//! plus the mandatory `fabric_filtered` toggle. Event-side fields and
//! dataver filters can be passed as pre-built slices via the
//! `*_from(...)` helpers, or added as proper streaming sub-builders
//! when a real use case appears.
//!
//! # Usage
//!
//! ```ignore
//! exchange.send_with(|_, wb| {
//!     let parent = TLVWriteParent::new("ReadRequest", wb);
//!     ReadReqBuilder::new(parent)?
//!         .attr_requests()?
//!             .push()?.endpoint(1).cluster(0x0006).attr(0x0000).end()?
//!             .push()?.endpoint(1).cluster(0x0008).attr(0x0000).end()?
//!         .end()?
//!         .fabric_filtered(true)?
//!         .end()?;
//!     Ok(Some(OpCode::ReadRequest.into()))
//! }).await
//! ```

use core::marker::PhantomData;

use crate::error::Error;
use crate::im::encoding::{AttrId, ClusterId, EndptId};
use crate::im::{
    AttrPath, AttrPathTag, DataVersionFilter, EventFilter, EventPath, NodeId, ReadReqTag,
    IM_REVISION,
};
use crate::tlv::{TLVBuilder, TLVBuilderParent, TLVTag, TLVWrite, ToTLV};

/// Streaming builder for a `ReadRequestMessage`. Type-state-tagged
/// so the compiler enforces in-order field writes; optional fields
/// are implicitly skipped by not calling their setter.
///
/// Field-state values (state *after* each named field has been
/// written or implicitly skipped):
/// - `0`: nothing written yet
/// - `1`: past `AttributeRequests`
/// - `2`: past `EventRequests`
/// - `3`: past `EventFilters`
/// - `4`: past `FabricFiltered` (mandatory; no implicit-skip path
///   from state 0/1/2/3 to here)
/// - `5`: past `DataVersionFilters`
/// - `6`: past `InteractionModelRevision` (auto-injected at default
///   value [`IM_REVISION`] by `end()` if the optional setter wasn't
///   called)
pub struct ReadReqBuilder<P, const F: usize = 0> {
    p: P,
}

impl<P> ReadReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Begin a new `ReadRequestMessage` — opens a struct at the given
    /// tag on the parent's writer. For top-level use (the usual case)
    /// pass `&TLVTag::Anonymous`.
    pub fn new(mut p: P, tag: &TLVTag) -> Result<Self, Error> {
        p.writer().start_struct(tag)?;
        Ok(Self { p })
    }
}

impl<P> TLVBuilder<P> for ReadReqBuilder<P, 0>
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
// `attr_requests` — openable from state 0; advances to state 1.
// ---------------------------------------------------------------------
impl<P> ReadReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Open the optional `AttributeRequests` array. Each `.push()`
    /// yields an [`AttrPathBuilder`]; close with `.end()` to advance
    /// to the next message field.
    pub fn attr_requests(self) -> Result<AttrPathArrayBuilder<ReadReqBuilder<P, 1>>, Error> {
        AttrPathArrayBuilder::new(
            ReadReqBuilder { p: self.p },
            &TLVTag::Context(ReadReqTag::AttrRequests as u8),
        )
    }

    /// Write `AttributeRequests` from a pre-built slice. Convenience
    /// for callers that already have an `&[AttrPath]` on hand.
    pub fn attr_requests_from(mut self, paths: &[AttrPath]) -> Result<ReadReqBuilder<P, 1>, Error> {
        let w = self.p.writer();
        w.start_array(&TLVTag::Context(ReadReqTag::AttrRequests as u8))?;
        for p in paths {
            p.to_tlv(&TLVTag::Anonymous, &mut *w)?;
        }
        w.end_container()?;
        Ok(ReadReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `event_requests` — openable from state 0 or 1; advances to state 2.
// ---------------------------------------------------------------------
impl<P> ReadReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Write `EventRequests` from a pre-built slice, implicitly
    /// skipping `AttributeRequests`.
    pub fn event_requests_from(self, paths: &[EventPath]) -> Result<ReadReqBuilder<P, 2>, Error> {
        ReadReqBuilder::<P, 1> { p: self.p }.event_requests_from(paths)
    }
}

impl<P> ReadReqBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    /// Write `EventRequests` from a pre-built slice. A streaming
    /// sub-builder for `EventPath` is on the to-do list for when an
    /// MCU client actually subscribes to events directly.
    pub fn event_requests_from(
        mut self,
        paths: &[EventPath],
    ) -> Result<ReadReqBuilder<P, 2>, Error> {
        let w = self.p.writer();
        w.start_array(&TLVTag::Context(ReadReqTag::EventRequests as u8))?;
        for p in paths {
            p.to_tlv(&TLVTag::Anonymous, &mut *w)?;
        }
        w.end_container()?;
        Ok(ReadReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `event_filters` — settable from state 0, 1, or 2; advances to 3.
// ---------------------------------------------------------------------
impl<P> ReadReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    pub fn event_filters_from(
        self,
        filters: &[EventFilter],
    ) -> Result<ReadReqBuilder<P, 3>, Error> {
        ReadReqBuilder::<P, 2> { p: self.p }.event_filters_from(filters)
    }
}

impl<P> ReadReqBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    pub fn event_filters_from(
        self,
        filters: &[EventFilter],
    ) -> Result<ReadReqBuilder<P, 3>, Error> {
        ReadReqBuilder::<P, 2> { p: self.p }.event_filters_from(filters)
    }
}

impl<P> ReadReqBuilder<P, 2>
where
    P: TLVBuilderParent,
{
    /// Write `EventFilters` from a pre-built slice.
    pub fn event_filters_from(
        mut self,
        filters: &[EventFilter],
    ) -> Result<ReadReqBuilder<P, 3>, Error> {
        let w = self.p.writer();
        w.start_array(&TLVTag::Context(ReadReqTag::EventFilters as u8))?;
        for ef in filters {
            ef.to_tlv(&TLVTag::Anonymous, &mut *w)?;
        }
        w.end_container()?;
        Ok(ReadReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `fabric_filtered` — *mandatory*; settable from state 0, 1, 2, or 3.
// ---------------------------------------------------------------------
impl<P> ReadReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Write the mandatory `FabricFiltered` field, implicitly
    /// skipping `AttributeRequests`, `EventRequests`, and
    /// `EventFilters`.
    pub fn fabric_filtered(self, value: bool) -> Result<ReadReqBuilder<P, 4>, Error> {
        ReadReqBuilder::<P, 3> { p: self.p }.fabric_filtered(value)
    }
}

impl<P> ReadReqBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    pub fn fabric_filtered(self, value: bool) -> Result<ReadReqBuilder<P, 4>, Error> {
        ReadReqBuilder::<P, 3> { p: self.p }.fabric_filtered(value)
    }
}

impl<P> ReadReqBuilder<P, 2>
where
    P: TLVBuilderParent,
{
    pub fn fabric_filtered(self, value: bool) -> Result<ReadReqBuilder<P, 4>, Error> {
        ReadReqBuilder::<P, 3> { p: self.p }.fabric_filtered(value)
    }
}

impl<P> ReadReqBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    /// Write the mandatory `FabricFiltered` field. `true` constrains
    /// reads of fabric-scoped attributes to the accessing fabric;
    /// `false` returns entries for every fabric the accessor has
    /// access to.
    pub fn fabric_filtered(mut self, value: bool) -> Result<ReadReqBuilder<P, 4>, Error> {
        self.p
            .writer()
            .bool(&TLVTag::Context(ReadReqTag::FabricFiltered as u8), value)?;
        Ok(ReadReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `dataver_filters` — settable from state 4; advances to state 5.
// ---------------------------------------------------------------------
impl<P> ReadReqBuilder<P, 4>
where
    P: TLVBuilderParent,
{
    /// Write `DataVersionFilters` from a pre-built slice. Used by
    /// caching clients to avoid re-reading attributes that haven't
    /// changed since the last data version they observed.
    pub fn dataver_filters_from(
        mut self,
        filters: &[DataVersionFilter],
    ) -> Result<ReadReqBuilder<P, 5>, Error> {
        let w = self.p.writer();
        w.start_array(&TLVTag::Context(ReadReqTag::DataVersionFilters as u8))?;
        for f in filters {
            f.to_tlv(&TLVTag::Anonymous, &mut *w)?;
        }
        w.end_container()?;
        Ok(ReadReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `end` — closable from state 4 or 5.
// ---------------------------------------------------------------------
impl<P> ReadReqBuilder<P, 4>
where
    P: TLVBuilderParent,
{
    /// Close the message struct, implicitly skipping
    /// `DataVersionFilters`. Returns the parent.
    pub fn end(self) -> Result<P, Error> {
        ReadReqBuilder::<P, 5> { p: self.p }.end()
    }
}

impl<P> ReadReqBuilder<P, 4>
where
    P: TLVBuilderParent,
{
    /// Write `InteractionModelRevision`, implicitly skipping
    /// `DataVersionFilters`. This is a typestate skip-shim mirroring
    /// the pattern PR #447 established for `SuppressResponse` /
    /// `TimedRequest` on `InvReqBuilder`: callers who don't populate
    /// the optional preceding field can advance straight to setting
    /// (or auto-injecting) `InteractionModelRevision` without an
    /// explicit no-op transition.
    pub fn interaction_model_revision(self, value: u8) -> Result<ReadReqBuilder<P, 6>, Error> {
        ReadReqBuilder::<P, 5> { p: self.p }.interaction_model_revision(value)
    }
}

impl<P> ReadReqBuilder<P, 5>
where
    P: TLVBuilderParent,
{
    /// Write the mandatory-on-the-wire `InteractionModelRevision`
    /// field (Matter Core: value is `13` since Matter
    /// 1.3, unchanged in 1.4 and 1.5). Optional at the API level —
    /// omit and `end()` injects [`IM_REVISION`] automatically. Set
    /// explicitly only when speaking a non-default revision is
    /// required (e.g. interop testing against a peer pinned to an
    /// older revision).
    pub fn interaction_model_revision(mut self, value: u8) -> Result<ReadReqBuilder<P, 6>, Error> {
        self.p.writer().u8(
            &TLVTag::Context(crate::im::encoding::IM_REVISION_TAG),
            value,
        )?;
        Ok(ReadReqBuilder { p: self.p })
    }

    /// Close the message struct, auto-injecting
    /// `InteractionModelRevision` at its default value
    /// [`IM_REVISION`]. Returns the parent.
    pub fn end(self) -> Result<P, Error> {
        self.interaction_model_revision(IM_REVISION)?.end()
    }
}

impl<P> ReadReqBuilder<P, 6>
where
    P: TLVBuilderParent,
{
    /// Close the message struct and return the parent.
    pub fn end(mut self) -> Result<P, Error> {
        self.p.writer().end_container()?;
        Ok(self.p)
    }
}

impl<P, const F: usize> TLVBuilderParent for ReadReqBuilder<P, F>
where
    P: TLVBuilderParent,
{
    type Write = P::Write;

    fn writer(&mut self) -> &mut Self::Write {
        self.p.writer()
    }
}

impl<P, const F: usize> core::fmt::Debug for ReadReqBuilder<P, F>
where
    P: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}::ReadRequestMessage<{}>", self.p, F)
    }
}

#[cfg(feature = "defmt")]
impl<P, const F: usize> defmt::Format for ReadReqBuilder<P, F>
where
    P: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{:?}::ReadRequestMessage<{}>", self.p, F);
    }
}

// =====================================================================
// AttrPath array sub-builder
// =====================================================================

/// Array builder for the `AttributeRequests` field. Opened by
/// [`ReadReqBuilder::attr_requests`]; close with `.end()`
/// to return to the message builder.
pub struct AttrPathArrayBuilder<P> {
    p: P,
}

impl<P> AttrPathArrayBuilder<P>
where
    P: TLVBuilderParent,
{
    /// Begin a new `AttrPath` array — opens an array at the given
    /// tag on the parent's writer.
    pub fn new(mut p: P, tag: &TLVTag) -> Result<Self, Error> {
        p.writer().start_array(tag)?;
        Ok(Self { p })
    }

    /// Start a new `AttrPath` entry. The returned [`AttrPathBuilder`]
    /// terminates with `.end()` which returns this array builder.
    pub fn push(self) -> Result<AttrPathBuilder<Self, 0>, Error> {
        AttrPathBuilder::new(self, &TLVTag::Anonymous)
    }

    /// Close the array and return the message builder.
    pub fn end(mut self) -> Result<P, Error> {
        self.p.writer().end_container()?;
        Ok(self.p)
    }
}

impl<P> TLVBuilder<P> for AttrPathArrayBuilder<P>
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

impl<P> TLVBuilderParent for AttrPathArrayBuilder<P>
where
    P: TLVBuilderParent,
{
    type Write = P::Write;

    fn writer(&mut self) -> &mut Self::Write {
        self.p.writer()
    }
}

impl<P> core::fmt::Debug for AttrPathArrayBuilder<P>
where
    P: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}[]", self.p)
    }
}

#[cfg(feature = "defmt")]
impl<P> defmt::Format for AttrPathArrayBuilder<P>
where
    P: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{:?}[]", self.p);
    }
}

// =====================================================================
// AttrPath builder (one entry in the array)
// =====================================================================

/// Streaming builder for one `AttrPath` (`AttributePathIB`) entry.
///
/// Field-state values:
/// - `0`: nothing written yet
/// - `1`: past `Node`
/// - `2`: past `Endpoint`
/// - `3`: past `Cluster`
/// - `4`: past `Attribute`
/// - `5`: past `ListIndex`
///
/// Every field is optional — wildcards are common on the read side
/// (e.g. "all attributes of cluster X on endpoint 1" omits
/// `Attribute`; "every endpoint that has cluster X" omits both
/// `Endpoint` and `Attribute`). Each setter advances directly to its
/// own state; later-field setters on earlier states implicitly skip
/// the ones in between.
pub struct AttrPathBuilder<P, const F: usize = 0> {
    p: P,
    _f: PhantomData<[(); F]>,
}

impl<P> AttrPathBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Begin a new `AttrPath` entry — opens a TLV list at the given
    /// tag. Use `&TLVTag::Anonymous` when pushed into an
    /// `AttributeRequests` array (the typical case).
    pub fn new(mut p: P, tag: &TLVTag) -> Result<Self, Error> {
        p.writer().start_list(tag)?;
        Ok(Self { p, _f: PhantomData })
    }
}

impl<P> TLVBuilder<P> for AttrPathBuilder<P, 0>
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

// ---- node ------------------------------------------------------------
impl<P> AttrPathBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Write the optional `Node` field. Rarely used on writes/reads
    /// to "self" — exists for proxied reads against other nodes.
    pub fn node(mut self, value: NodeId) -> Result<AttrPathBuilder<P, 1>, Error> {
        self.p
            .writer()
            .u64(&TLVTag::Context(AttrPathTag::Node as u8), value)?;
        Ok(AttrPathBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }
}

// ---- endpoint --------------------------------------------------------
impl<P> AttrPathBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Write the optional `Endpoint` field, implicitly skipping
    /// `Node`. Omit (call `.cluster(...)` instead) for a
    /// wildcard-endpoint read.
    pub fn endpoint(self, value: EndptId) -> Result<AttrPathBuilder<P, 2>, Error> {
        AttrPathBuilder::<P, 1> {
            p: self.p,
            _f: PhantomData,
        }
        .endpoint(value)
    }
}

impl<P> AttrPathBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    pub fn endpoint(mut self, value: EndptId) -> Result<AttrPathBuilder<P, 2>, Error> {
        self.p
            .writer()
            .u16(&TLVTag::Context(AttrPathTag::Endpoint as u8), value)?;
        Ok(AttrPathBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }
}

// ---- cluster ---------------------------------------------------------
impl<P> AttrPathBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    pub fn cluster(self, value: ClusterId) -> Result<AttrPathBuilder<P, 3>, Error> {
        AttrPathBuilder::<P, 2> {
            p: self.p,
            _f: PhantomData,
        }
        .cluster(value)
    }
}

impl<P> AttrPathBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    pub fn cluster(self, value: ClusterId) -> Result<AttrPathBuilder<P, 3>, Error> {
        AttrPathBuilder::<P, 2> {
            p: self.p,
            _f: PhantomData,
        }
        .cluster(value)
    }
}

impl<P> AttrPathBuilder<P, 2>
where
    P: TLVBuilderParent,
{
    pub fn cluster(mut self, value: ClusterId) -> Result<AttrPathBuilder<P, 3>, Error> {
        self.p
            .writer()
            .u32(&TLVTag::Context(AttrPathTag::Cluster as u8), value)?;
        Ok(AttrPathBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }
}

// ---- attr ------------------------------------------------------------
impl<P> AttrPathBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    pub fn attr(self, value: AttrId) -> Result<AttrPathBuilder<P, 4>, Error> {
        AttrPathBuilder::<P, 3> {
            p: self.p,
            _f: PhantomData,
        }
        .attr(value)
    }
}

impl<P> AttrPathBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    pub fn attr(self, value: AttrId) -> Result<AttrPathBuilder<P, 4>, Error> {
        AttrPathBuilder::<P, 3> {
            p: self.p,
            _f: PhantomData,
        }
        .attr(value)
    }
}

impl<P> AttrPathBuilder<P, 2>
where
    P: TLVBuilderParent,
{
    pub fn attr(self, value: AttrId) -> Result<AttrPathBuilder<P, 4>, Error> {
        AttrPathBuilder::<P, 3> {
            p: self.p,
            _f: PhantomData,
        }
        .attr(value)
    }
}

impl<P> AttrPathBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    pub fn attr(mut self, value: AttrId) -> Result<AttrPathBuilder<P, 4>, Error> {
        self.p
            .writer()
            .u32(&TLVTag::Context(AttrPathTag::Attribute as u8), value)?;
        Ok(AttrPathBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }
}

// ---- list_index ------------------------------------------------------
impl<P> AttrPathBuilder<P, 4>
where
    P: TLVBuilderParent,
{
    /// Write the optional `ListIndex` field — used to read a specific
    /// index within a list-typed attribute.
    pub fn list_index(mut self, value: Option<u16>) -> Result<AttrPathBuilder<P, 5>, Error> {
        // Nullable<u16> = Option<u16> with `None` encoded as TLV null.
        // Encode via the regular `to_tlv` of `Nullable`.
        let n: crate::tlv::Nullable<u16> = match value {
            Some(v) => crate::tlv::Nullable::some(v),
            None => crate::tlv::Nullable::none(),
        };
        n.to_tlv(
            &TLVTag::Context(AttrPathTag::ListIndex as u8),
            self.p.writer(),
        )?;
        Ok(AttrPathBuilder {
            p: self.p,
            _f: PhantomData,
        })
    }
}

// ---- end -------------------------------------------------------------
// Allowed from any state past 0 (each implicit-skip via forwarders).
impl<P> AttrPathBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    pub fn end(self) -> Result<P, Error> {
        AttrPathBuilder::<P, 5> {
            p: self.p,
            _f: PhantomData,
        }
        .end()
    }
}
impl<P> AttrPathBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    pub fn end(self) -> Result<P, Error> {
        AttrPathBuilder::<P, 5> {
            p: self.p,
            _f: PhantomData,
        }
        .end()
    }
}
impl<P> AttrPathBuilder<P, 2>
where
    P: TLVBuilderParent,
{
    pub fn end(self) -> Result<P, Error> {
        AttrPathBuilder::<P, 5> {
            p: self.p,
            _f: PhantomData,
        }
        .end()
    }
}
impl<P> AttrPathBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    pub fn end(self) -> Result<P, Error> {
        AttrPathBuilder::<P, 5> {
            p: self.p,
            _f: PhantomData,
        }
        .end()
    }
}
impl<P> AttrPathBuilder<P, 4>
where
    P: TLVBuilderParent,
{
    pub fn end(self) -> Result<P, Error> {
        AttrPathBuilder::<P, 5> {
            p: self.p,
            _f: PhantomData,
        }
        .end()
    }
}
impl<P> AttrPathBuilder<P, 5>
where
    P: TLVBuilderParent,
{
    /// Close the `AttrPath` list and return the array builder so the
    /// caller can `.push()` another entry or `.end()` the array.
    pub fn end(mut self) -> Result<P, Error> {
        self.p.writer().end_container()?;
        Ok(self.p)
    }
}

impl<P, const F: usize> TLVBuilderParent for AttrPathBuilder<P, F>
where
    P: TLVBuilderParent,
{
    type Write = P::Write;

    fn writer(&mut self) -> &mut Self::Write {
        self.p.writer()
    }
}

impl<P, const F: usize> core::fmt::Debug for AttrPathBuilder<P, F>
where
    P: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}::AttrPath<{}>", self.p, F)
    }
}

#[cfg(feature = "defmt")]
impl<P, const F: usize> defmt::Format for AttrPathBuilder<P, F>
where
    P: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{:?}::AttrPath<{}>", self.p, F);
    }
}

#[cfg(test)]
mod tests {
    use crate::error::{Error, ErrorCode};
    use crate::im::{
        AttrPath, ClusterPath, DataVersionFilter, EventFilter, EventPath, ReadReq, IM_REVISION,
    };
    use crate::tlv::{Nullable, TLVBuilderParent, TLVElement, TLVTag, TLVWriteParent};
    use crate::utils::storage::WriteBuf;

    use super::{AttrPathArrayBuilder, ReadReqBuilder};

    type Root<'a, 'b> = TLVWriteParent<(), &'a mut WriteBuf<'b>>;

    fn root<'a, 'b>(wb: &'a mut WriteBuf<'b>) -> Root<'a, 'b> {
        TLVWriteParent::new((), wb)
    }

    fn attr_path(endpoint: u16, cluster: u32, attr: u32) -> AttrPath {
        AttrPath {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attr: Some(attr),
            ..Default::default()
        }
    }

    #[test]
    fn single_path_read_round_trips() {
        let mut buf = [0; 64];
        let mut wb = WriteBuf::new(&mut buf);

        ReadReqBuilder::new(root(&mut wb), &TLVTag::Anonymous)
            .unwrap()
            .attr_requests()
            .unwrap()
            .push()
            .unwrap()
            .endpoint(1)
            .unwrap()
            .cluster(6)
            .unwrap()
            .attr(0)
            .unwrap()
            .end()
            .unwrap()
            .end()
            .unwrap()
            .fabric_filtered(true)
            .unwrap()
            .end()
            .unwrap();

        assert_eq!(
            wb.as_slice(),
            &[
                0x15, // ReadRequestMessage
                0x36,
                0, // AttributeRequests[]
                0x17,
                0x24,
                2,
                1,
                0x24,
                3,
                6,
                0x24,
                4,
                0,
                0x18, // AttrPath list
                0x18, // end AttributeRequests
                0x29,
                3, // FabricFiltered = true
                0x24,
                0xFF,
                IM_REVISION, // InteractionModelRevision
                0x18,
            ]
        );

        let req = ReadReq::new(TLVElement::new(wb.as_slice()));
        assert!(req
            .attr_requests()
            .unwrap()
            .unwrap()
            .iter()
            .map(Result::unwrap)
            .eq([attr_path(1, 6, 0)]));
        assert!(req.event_requests().unwrap().is_none());
        assert!(req.event_filters().unwrap().is_none());
        assert!(req.fabric_filtered().unwrap());
        assert!(req.dataver_filters().unwrap().is_none());
    }

    #[test]
    fn paths_with_wildcards_node_and_list_index() {
        let mut buf = [0; 128];
        let mut wb = WriteBuf::new(&mut buf);

        ReadReqBuilder::new(root(&mut wb), &TLVTag::Anonymous)
            .unwrap()
            .attr_requests()
            .unwrap()
            // every field present
            .push()
            .unwrap()
            .node(0x1122)
            .unwrap()
            .endpoint(2)
            .unwrap()
            .cluster(3)
            .unwrap()
            .attr(4)
            .unwrap()
            .list_index(Some(5))
            .unwrap()
            .end()
            .unwrap()
            // wildcard endpoint and attribute
            .push()
            .unwrap()
            .cluster(6)
            .unwrap()
            .end()
            .unwrap()
            // wildcard cluster
            .push()
            .unwrap()
            .endpoint(1)
            .unwrap()
            .attr(2)
            .unwrap()
            .end()
            .unwrap()
            // node followed by a skip straight to cluster / attribute
            .push()
            .unwrap()
            .node(9)
            .unwrap()
            .cluster(3)
            .unwrap()
            .end()
            .unwrap()
            .push()
            .unwrap()
            .node(9)
            .unwrap()
            .attr(1)
            .unwrap()
            .end()
            .unwrap()
            // null list index
            .push()
            .unwrap()
            .attr(7)
            .unwrap()
            .list_index(None)
            .unwrap()
            .end()
            .unwrap()
            // fully wildcard path
            .push()
            .unwrap()
            .end()
            .unwrap()
            .end()
            .unwrap()
            .fabric_filtered(false)
            .unwrap()
            .end()
            .unwrap();

        let req = ReadReq::new(TLVElement::new(wb.as_slice()));
        assert!(req
            .attr_requests()
            .unwrap()
            .unwrap()
            .iter()
            .map(Result::unwrap)
            .eq([
                AttrPath {
                    tag_compression: None,
                    node: Some(0x1122),
                    endpoint: Some(2),
                    cluster: Some(3),
                    attr: Some(4),
                    list_index: Some(Nullable::some(5)),
                },
                AttrPath {
                    cluster: Some(6),
                    ..Default::default()
                },
                AttrPath {
                    endpoint: Some(1),
                    attr: Some(2),
                    ..Default::default()
                },
                AttrPath {
                    node: Some(9),
                    cluster: Some(3),
                    ..Default::default()
                },
                AttrPath {
                    node: Some(9),
                    attr: Some(1),
                    ..Default::default()
                },
                AttrPath {
                    attr: Some(7),
                    list_index: Some(Nullable::none()),
                    ..Default::default()
                },
                AttrPath::default(),
            ]));
        assert!(!req.fabric_filtered().unwrap());
    }

    #[test]
    fn slice_helpers_and_forwarders_write_every_field() {
        let paths = [attr_path(1, 6, 0), attr_path(2, 8, 0)];
        let events = [EventPath {
            endpoint: Some(0),
            cluster: Some(0x28),
            event: Some(0),
            ..Default::default()
        }];
        let filters = [EventFilter {
            node: None,
            event_min: Some(42),
        }];
        let datavers = [DataVersionFilter {
            path: ClusterPath {
                node: None,
                endpoint: 1,
                cluster: 6,
            },
            data_ver: 0x1234_5678,
        }];

        let mut buf = [0; 256];
        let mut wb = WriteBuf::new(&mut buf);

        ReadReqBuilder::new(root(&mut wb), &TLVTag::Anonymous)
            .unwrap()
            .attr_requests_from(&paths)
            .unwrap()
            .event_requests_from(&events)
            .unwrap()
            .event_filters_from(&filters)
            .unwrap()
            .fabric_filtered(false)
            .unwrap()
            .dataver_filters_from(&datavers)
            .unwrap()
            .interaction_model_revision(7)
            .unwrap()
            .end()
            .unwrap();

        let req = ReadReq::new(TLVElement::new(wb.as_slice()));
        assert!(req
            .attr_requests()
            .unwrap()
            .unwrap()
            .iter()
            .map(Result::unwrap)
            .eq(paths.iter().cloned()));
        assert!(req
            .event_requests()
            .unwrap()
            .unwrap()
            .iter()
            .map(Result::unwrap)
            .eq(events.iter().cloned()));
        assert!(req
            .event_filters()
            .unwrap()
            .unwrap()
            .iter()
            .map(Result::unwrap)
            .eq(filters.iter().cloned()));
        assert!(!req.fabric_filtered().unwrap());
        assert!(req
            .dataver_filters()
            .unwrap()
            .unwrap()
            .iter()
            .map(Result::unwrap)
            .eq(datavers.iter().cloned()));
        assert_eq!(
            TLVElement::new(wb.as_slice())
                .structure()
                .unwrap()
                .find_ctx(0xFF)
                .unwrap()
                .u8()
                .unwrap(),
            7
        );

        // Skipping straight from state 0 to `EventRequests`
        wb.reset();
        ReadReqBuilder::new(root(&mut wb), &TLVTag::Anonymous)
            .unwrap()
            .event_requests_from(&events)
            .unwrap()
            .fabric_filtered(true)
            .unwrap()
            .end()
            .unwrap();
        let req = ReadReq::new(TLVElement::new(wb.as_slice()));
        assert!(req.attr_requests().unwrap().is_none());
        assert_eq!(req.event_requests().unwrap().unwrap().iter().count(), 1);
        assert!(req.event_filters().unwrap().is_none());
        assert!(req.fabric_filtered().unwrap());

        // Skipping from state 0 to `EventFilters`, and from state 1 to `EventFilters`
        wb.reset();
        ReadReqBuilder::new(root(&mut wb), &TLVTag::Anonymous)
            .unwrap()
            .event_filters_from(&filters)
            .unwrap()
            .fabric_filtered(true)
            .unwrap()
            .end()
            .unwrap();
        let req = ReadReq::new(TLVElement::new(wb.as_slice()));
        assert!(req.attr_requests().unwrap().is_none());
        assert!(req.event_requests().unwrap().is_none());
        assert_eq!(req.event_filters().unwrap().unwrap().iter().count(), 1);

        wb.reset();
        ReadReqBuilder::new(root(&mut wb), &TLVTag::Anonymous)
            .unwrap()
            .attr_requests_from(&paths)
            .unwrap()
            .event_filters_from(&filters)
            .unwrap()
            .fabric_filtered(true)
            .unwrap()
            .interaction_model_revision(7)
            .unwrap()
            .end()
            .unwrap();
        let req = ReadReq::new(TLVElement::new(wb.as_slice()));
        assert_eq!(req.attr_requests().unwrap().unwrap().iter().count(), 2);
        assert!(req.event_requests().unwrap().is_none());
        assert_eq!(req.event_filters().unwrap().unwrap().iter().count(), 1);
        assert!(req.dataver_filters().unwrap().is_none());

        // The minimal request is just the mandatory flag plus the revision
        wb.reset();
        ReadReqBuilder::new(root(&mut wb), &TLVTag::Anonymous)
            .unwrap()
            .fabric_filtered(false)
            .unwrap()
            .end()
            .unwrap();
        assert_eq!(
            wb.as_slice(),
            &[0x15, 0x28, 3, 0x24, 0xFF, IM_REVISION, 0x18]
        );
    }

    /// Pushes one concrete `(1, 6, attr)` path into the open array.
    fn push_path<P: TLVBuilderParent>(
        arr: AttrPathArrayBuilder<P>,
        attr: u32,
    ) -> Result<AttrPathArrayBuilder<P>, Error> {
        arr.push()?.endpoint(1)?.cluster(6)?.attr(attr)?.end()
    }

    #[test]
    fn paths_that_overflow_the_buffer_leave_a_decodable_prefix() {
        // Room for the array end, `FabricFiltered`, the revision and the message end
        const TRAILER: usize = 1 + 2 + 3 + 1;

        let mut buf = [0; 48];
        let buf_len = buf.len();
        let mut wb = WriteBuf::new(&mut buf);
        wb.shrink(TRAILER).unwrap();

        let mut arr = ReadReqBuilder::new(root(&mut wb), &TLVTag::Anonymous)
            .unwrap()
            .attr_requests()
            .unwrap();

        // Push paths until one does not fit; remember where the last complete one ended
        let mut written = 0;
        let last_complete = loop {
            let tail = arr.writer().get_tail();

            match push_path(arr, written) {
                Ok(a) => {
                    arr = a;
                    written += 1;
                }
                Err(e) => {
                    assert_eq!(e.code(), ErrorCode::NoSpace);
                    break tail;
                }
            }
        };

        assert!(written > 0);
        assert!(
            wb.get_tail() > last_complete,
            "the failed push wrote nothing"
        );

        // Drop the partially written path, then close the message in the reserved space
        wb.rewind_tail_to(last_complete);
        wb.expand(TRAILER).unwrap();

        AttrPathArrayBuilder {
            p: ReadReqBuilder::<_, 1> { p: root(&mut wb) },
        }
        .end()
        .unwrap()
        .fabric_filtered(true)
        .unwrap()
        .end()
        .unwrap();

        assert!(wb.as_slice().len() <= buf_len);

        let req = ReadReq::new(TLVElement::new(wb.as_slice()));
        assert!(req
            .attr_requests()
            .unwrap()
            .unwrap()
            .iter()
            .map(Result::unwrap)
            .eq((0..written).map(|attr| attr_path(1, 6, attr))));
        assert!(req.fabric_filtered().unwrap());
    }
}
