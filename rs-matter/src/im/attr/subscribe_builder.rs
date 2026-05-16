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

//! Streaming TLV builder for `SubscribeRequestMessage`.
//!
//! Same typestate-machine + implicit-skip convention as
//! [`crate::im::attr::read_builder::ReadReqBuilder`]: mandatory
//! fields must be written in order (`keep_subs`, `min_int_floor`,
//! `max_int_ceil`, `fabric_filtered`); optional intermediate fields
//! (`AttributeRequests`, `EventRequests`, `EventFilters`,
//! `DataVersionFilters`) are skipped simply by not calling their
//! setter — later-field setters are available on earlier states so
//! the user can write a minimal request in one straight chain. The
//! `AttrPath` array sub-builder is re-used from
//! [`crate::im::attr::read_builder`] since the wire shape is
//! identical to the read variant.
//!
//! # Layout
//!
//! Per Matter Core spec §10.7.8 `SubscribeRequestMessage` is an
//! anonymous-tagged struct with seven fields plus a reserved gap at
//! tag 6:
//!
//! | Tag | Field             | Type                   | Required |
//! |-----|-------------------|------------------------|----------|
//! | 0   | KeepSubs          | bool                   | **yes**  |
//! | 1   | MinIntFloor       | u16                    | **yes**  |
//! | 2   | MaxIntCeil        | u16                    | **yes**  |
//! | 3   | AttributeRequests | array[AttrPath]?       | no       |
//! | 4   | EventRequests     | array[EventPath]?      | no       |
//! | 5   | EventFilters      | array[EventFilter]?    | no       |
//! | 6   | *(reserved)*      | —                      | —        |
//! | 7   | FabricFiltered    | bool                   | **yes**  |
//! | 8   | DataVersionFilters| array[DataVersionFilter]? | no    |
//!
//! Event-side fields and dataver filters can be passed as pre-built
//! slices via the `*_from(...)` helpers, matching what the
//! `ReadReqBuilder` exposes.
//!
//! # Usage
//!
//! ```ignore
//! exchange.send_with(|_, wb| {
//!     let parent = TLVWriteParent::new("SubscribeRequest", wb);
//!     SubscribeReqBuilder::new(parent)?
//!         .keep_subs(true)?
//!         .min_int_floor(0)?
//!         .max_int_ceil(60)?
//!         .attr_requests()?
//!             .push()?.endpoint(1).cluster(0x0006).attr(0x0000).end()?
//!         .end()?
//!         .fabric_filtered(true)?
//!         .end()?;
//!     Ok(Some(OpCode::SubscribeRequest.into()))
//! }).await
//! ```

use crate::dm::GlobalElements;
use crate::error::Error;
use crate::im::{
    AttrPath, AttrPathArrayBuilder, DataVersionFilter, EventFilter, EventPath, SubscribeReqTag,
    IM_REVISION,
};
use crate::tlv::{TLVBuilder, TLVBuilderParent, TLVTag, TLVWrite, ToTLV};

/// Streaming builder for a `SubscribeRequestMessage`. Type-state-tagged
/// so the compiler enforces in-order field writes; optional fields
/// are implicitly skipped by not calling their setter.
///
/// Field-state values (state *after* each named field has been
/// written or implicitly skipped):
/// - `0`: nothing written yet
/// - `1`: past `KeepSubs`
/// - `2`: past `MinIntFloor`
/// - `3`: past `MaxIntCeil`
/// - `4`: past `AttributeRequests`
/// - `5`: past `EventRequests`
/// - `6`: past `EventFilters`
/// - `7`: past `FabricFiltered` (mandatory; no implicit-skip from
///   states 3-6 to `end()` — caller must invoke `fabric_filtered`)
/// - `8`: past `DataVersionFilters`
/// - `9`: past `InteractionModelRevision` (auto-injected at default
///   value [`IM_REVISION`] by `end()` if the optional setter wasn't
///   called)
pub struct SubscribeReqBuilder<P, const F: usize = 0> {
    p: P,
}

impl<P> SubscribeReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Begin a new `SubscribeRequestMessage` — opens a struct at the
    /// given tag on the parent's writer. For top-level use (the usual
    /// case) pass `&TLVTag::Anonymous`.
    pub fn new(mut p: P, tag: &TLVTag) -> Result<Self, Error> {
        p.writer().start_struct(tag)?;
        Ok(Self { p })
    }
}

impl<P> TLVBuilder<P> for SubscribeReqBuilder<P, 0>
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
// `keep_subs` — mandatory; settable from state 0 only.
// ---------------------------------------------------------------------
impl<P> SubscribeReqBuilder<P, 0>
where
    P: TLVBuilderParent,
{
    /// Write the mandatory `KeepSubs` field. `true` (the typical
    /// value) instructs the peer to keep any existing subscriptions
    /// for this fabric+peer pair alongside the new one; `false`
    /// terminates them before establishing this subscription.
    pub fn keep_subs(mut self, value: bool) -> Result<SubscribeReqBuilder<P, 1>, Error> {
        self.p
            .writer()
            .bool(&TLVTag::Context(SubscribeReqTag::KeepSubs as u8), value)?;
        Ok(SubscribeReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `min_int_floor` — mandatory; settable from state 1 only.
// ---------------------------------------------------------------------
impl<P> SubscribeReqBuilder<P, 1>
where
    P: TLVBuilderParent,
{
    /// Write the mandatory `MinIntervalFloor` field (seconds). The
    /// minimum reporting interval the peer is allowed to use; the
    /// server may pick any interval at or above this floor.
    pub fn min_int_floor(mut self, value: u16) -> Result<SubscribeReqBuilder<P, 2>, Error> {
        self.p
            .writer()
            .u16(&TLVTag::Context(SubscribeReqTag::MinIntFloor as u8), value)?;
        Ok(SubscribeReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `max_int_ceil` — mandatory; settable from state 2 only.
// ---------------------------------------------------------------------
impl<P> SubscribeReqBuilder<P, 2>
where
    P: TLVBuilderParent,
{
    /// Write the mandatory `MaxIntervalCeiling` field (seconds). The
    /// peer MUST report no less frequently than this even if nothing
    /// has changed (heartbeat). The server may pick any interval at
    /// or below this ceiling — see Matter Core spec §8.5.3.
    pub fn max_int_ceil(mut self, value: u16) -> Result<SubscribeReqBuilder<P, 3>, Error> {
        self.p
            .writer()
            .u16(&TLVTag::Context(SubscribeReqTag::MaxIntCeil as u8), value)?;
        Ok(SubscribeReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `attr_requests` — openable from state 3; advances to state 4.
// ---------------------------------------------------------------------
impl<P> SubscribeReqBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    /// Open the optional `AttributeRequests` array. Each `.push()`
    /// yields an [`AttrPathBuilder`]; close with `.end()` to advance
    /// to the next message field.
    pub fn attr_requests(self) -> Result<AttrPathArrayBuilder<SubscribeReqBuilder<P, 4>>, Error> {
        AttrPathArrayBuilder::new(
            SubscribeReqBuilder { p: self.p },
            &TLVTag::Context(SubscribeReqTag::AttrRequests as u8),
        )
    }

    /// Write `AttributeRequests` from a pre-built slice. Convenience
    /// for callers that already have an `&[AttrPath]` on hand.
    pub fn attr_requests_from(
        mut self,
        paths: &[AttrPath],
    ) -> Result<SubscribeReqBuilder<P, 4>, Error> {
        let w = self.p.writer();
        w.start_array(&TLVTag::Context(SubscribeReqTag::AttrRequests as u8))?;
        for p in paths {
            p.to_tlv(&TLVTag::Anonymous, &mut *w)?;
        }
        w.end_container()?;
        Ok(SubscribeReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `event_requests` — openable from state 3 or 4; advances to state 5.
// ---------------------------------------------------------------------
impl<P> SubscribeReqBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    /// Write `EventRequests` from a pre-built slice, implicitly
    /// skipping `AttributeRequests`.
    pub fn event_requests_from(
        self,
        paths: &[EventPath],
    ) -> Result<SubscribeReqBuilder<P, 5>, Error> {
        SubscribeReqBuilder::<P, 4> { p: self.p }.event_requests_from(paths)
    }
}

impl<P> SubscribeReqBuilder<P, 4>
where
    P: TLVBuilderParent,
{
    /// Write `EventRequests` from a pre-built slice.
    pub fn event_requests_from(
        mut self,
        paths: &[EventPath],
    ) -> Result<SubscribeReqBuilder<P, 5>, Error> {
        let w = self.p.writer();
        w.start_array(&TLVTag::Context(SubscribeReqTag::EventRequests as u8))?;
        for p in paths {
            p.to_tlv(&TLVTag::Anonymous, &mut *w)?;
        }
        w.end_container()?;
        Ok(SubscribeReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `event_filters` — settable from state 3, 4, or 5; advances to 6.
// ---------------------------------------------------------------------
impl<P> SubscribeReqBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    pub fn event_filters_from(
        self,
        filters: &[EventFilter],
    ) -> Result<SubscribeReqBuilder<P, 6>, Error> {
        SubscribeReqBuilder::<P, 5> { p: self.p }.event_filters_from(filters)
    }
}

impl<P> SubscribeReqBuilder<P, 4>
where
    P: TLVBuilderParent,
{
    pub fn event_filters_from(
        self,
        filters: &[EventFilter],
    ) -> Result<SubscribeReqBuilder<P, 6>, Error> {
        SubscribeReqBuilder::<P, 5> { p: self.p }.event_filters_from(filters)
    }
}

impl<P> SubscribeReqBuilder<P, 5>
where
    P: TLVBuilderParent,
{
    /// Write `EventFilters` from a pre-built slice.
    pub fn event_filters_from(
        mut self,
        filters: &[EventFilter],
    ) -> Result<SubscribeReqBuilder<P, 6>, Error> {
        let w = self.p.writer();
        w.start_array(&TLVTag::Context(SubscribeReqTag::EventFilters as u8))?;
        for ef in filters {
            ef.to_tlv(&TLVTag::Anonymous, &mut *w)?;
        }
        w.end_container()?;
        Ok(SubscribeReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `fabric_filtered` — *mandatory*; settable from state 3, 4, 5, or 6.
// ---------------------------------------------------------------------
impl<P> SubscribeReqBuilder<P, 3>
where
    P: TLVBuilderParent,
{
    /// Write the mandatory `FabricFiltered` field, implicitly
    /// skipping `AttributeRequests`, `EventRequests`, and
    /// `EventFilters`.
    pub fn fabric_filtered(self, value: bool) -> Result<SubscribeReqBuilder<P, 7>, Error> {
        SubscribeReqBuilder::<P, 6> { p: self.p }.fabric_filtered(value)
    }
}

impl<P> SubscribeReqBuilder<P, 4>
where
    P: TLVBuilderParent,
{
    pub fn fabric_filtered(self, value: bool) -> Result<SubscribeReqBuilder<P, 7>, Error> {
        SubscribeReqBuilder::<P, 6> { p: self.p }.fabric_filtered(value)
    }
}

impl<P> SubscribeReqBuilder<P, 5>
where
    P: TLVBuilderParent,
{
    pub fn fabric_filtered(self, value: bool) -> Result<SubscribeReqBuilder<P, 7>, Error> {
        SubscribeReqBuilder::<P, 6> { p: self.p }.fabric_filtered(value)
    }
}

impl<P> SubscribeReqBuilder<P, 6>
where
    P: TLVBuilderParent,
{
    /// Write the mandatory `FabricFiltered` field. `true` (the
    /// typical value) constrains the subscription to attribute /
    /// event reports for the accessing fabric only.
    pub fn fabric_filtered(mut self, value: bool) -> Result<SubscribeReqBuilder<P, 7>, Error> {
        self.p.writer().bool(
            &TLVTag::Context(SubscribeReqTag::FabricFiltered as u8),
            value,
        )?;
        Ok(SubscribeReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `dataver_filters` — settable from state 7; advances to state 8.
// ---------------------------------------------------------------------
impl<P> SubscribeReqBuilder<P, 7>
where
    P: TLVBuilderParent,
{
    /// Write `DataVersionFilters` from a pre-built slice. Used by
    /// caching clients to skip attributes whose data version hasn't
    /// advanced since the last cached read.
    pub fn dataver_filters_from(
        mut self,
        filters: &[DataVersionFilter],
    ) -> Result<SubscribeReqBuilder<P, 8>, Error> {
        let w = self.p.writer();
        w.start_array(&TLVTag::Context(SubscribeReqTag::DataVersionFilters as u8))?;
        for f in filters {
            f.to_tlv(&TLVTag::Anonymous, &mut *w)?;
        }
        w.end_container()?;
        Ok(SubscribeReqBuilder { p: self.p })
    }
}

// ---------------------------------------------------------------------
// `end` — closable from state 7 or 8.
// ---------------------------------------------------------------------
impl<P> SubscribeReqBuilder<P, 7>
where
    P: TLVBuilderParent,
{
    /// Close the message struct, implicitly skipping
    /// `DataVersionFilters`. Returns the parent.
    pub fn end(self) -> Result<P, Error> {
        SubscribeReqBuilder::<P, 8> { p: self.p }.end()
    }
}

impl<P> SubscribeReqBuilder<P, 7>
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
    pub fn interaction_model_revision(self, value: u8) -> Result<SubscribeReqBuilder<P, 9>, Error> {
        SubscribeReqBuilder::<P, 8> { p: self.p }.interaction_model_revision(value)
    }
}

impl<P> SubscribeReqBuilder<P, 8>
where
    P: TLVBuilderParent,
{
    /// Write the mandatory-on-the-wire `InteractionModelRevision`
    /// field (Matter Core §8.1.1, p. 545: value is `13` since Matter
    /// 1.3, unchanged in 1.4 and 1.5). Optional at the API level —
    /// omit and `end()` injects [`IM_REVISION`] automatically.
    pub fn interaction_model_revision(
        mut self,
        value: u8,
    ) -> Result<SubscribeReqBuilder<P, 9>, Error> {
        self.p.writer().u8(
            &TLVTag::Context(GlobalElements::InteractionModelRevision as u8),
            value,
        )?;
        Ok(SubscribeReqBuilder { p: self.p })
    }

    /// Close the message struct, auto-injecting
    /// `InteractionModelRevision` at its default value
    /// [`IM_REVISION`]. Returns the parent.
    pub fn end(self) -> Result<P, Error> {
        self.interaction_model_revision(IM_REVISION)?.end()
    }
}

impl<P> SubscribeReqBuilder<P, 9>
where
    P: TLVBuilderParent,
{
    /// Close the message struct and return the parent.
    pub fn end(mut self) -> Result<P, Error> {
        self.p.writer().end_container()?;
        Ok(self.p)
    }
}

impl<P, const F: usize> TLVBuilderParent for SubscribeReqBuilder<P, F>
where
    P: TLVBuilderParent,
{
    type Write = P::Write;

    fn writer(&mut self) -> &mut Self::Write {
        self.p.writer()
    }
}

impl<P, const F: usize> core::fmt::Debug for SubscribeReqBuilder<P, F>
where
    P: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}::SubscribeRequestMessage<{}>", self.p, F)
    }
}

#[cfg(feature = "defmt")]
impl<P, const F: usize> defmt::Format for SubscribeReqBuilder<P, F>
where
    P: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{:?}::SubscribeRequestMessage<{}>", self.p, F);
    }
}
