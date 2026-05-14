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
//! [`crate::im::attr::write_builder`]: same typestate-machine shape,
//! same implicit-skip convention (optional fields are omitted by not
//! calling their setter; later-field setters are available on
//! earlier states so the user can write a minimal request in one
//! straight chain). The Read variant carries no payload per entry —
//! every entry is just an `AttrPath` list — so the path sub-builder
//! is much simpler than its `AttrData` counterpart.
//!
//! # Layout
//!
//! Per Matter Core spec §10.7.2 `ReadRequestMessage` is an
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

use crate::dm::{AttrId, ClusterId, EndptId};
use crate::error::Error;
use crate::im::{
    AttrPath, AttrPathTag, DataVersionFilter, EventFilter, EventPath, NodeId, ReadReqTag,
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

impl<P> ReadReqBuilder<P, 5>
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
