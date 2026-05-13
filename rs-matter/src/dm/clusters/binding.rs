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

//! Binding cluster handler (Matter Core spec §9.6).
//!
//! Per-endpoint, fabric-scoped, **persistent** list of `TargetStruct`
//! entries each describing a unicast `(node, endpoint, cluster?)` or
//! a groupcast `(group, cluster?)` destination. The Binding cluster
//! is the *device-side address book* a client cluster reads when it
//! wants to send a command somewhere: a wall switch with `OnOff` in
//! its client list, for instance, reads its Binding list to find the
//! bulb(s) it's been paired with.
//!
//! See the spec's [`9.6` summary][spec], or the in-tree write-up in
//! `super::user_label` for the analogous (per-endpoint, persistent,
//! shared-registry) shape.
//!
//! # Persistence
//!
//! Spec §9.6.6.1 marks the `Binding` attribute with the `N` quality
//! bit (Non-Volatile, Matter Core §7.13.2) — values **SHALL** survive
//! reboots. We re-serialise the whole registry under [`BINDINGS_KEY`]
//! after every successful write, and re-hydrate on startup via
//! [`Bindings::load_persist`].
//!
//! # Fabric scoping
//!
//! `TargetStruct` carries an implicit `FabricIndex` field (id 254)
//! that the IM dispatch auto-injects from the writing accessor. On
//! reads, `attr.fab_filter` + `attr.fab_idx` constrain results to the
//! reading fabric. We store `fab_idx` alongside each entry and apply
//! the same filter manually on read paths.
//!
//! # Validation
//!
//! Per spec §9.6.5.1:
//! - `Group` and `Endpoint` are mutually exclusive (one of the two
//!   identifies the target).
//! - `Node` is required when `Endpoint` is present.
//! - `Cluster` is optional.
//!
//! We reject malformed entries with `ConstraintError`.

use core::num::NonZeroU8;

use crate::dm::{
    ArrayAttributeRead, ArrayAttributeWrite, Cluster, ClusterId, Dataver, EndptId, ReadContext,
    WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::persist::{KvBlobStore, Persist};
use crate::tlv::{FromTLV, TLVArray, TLVBuilderParent, TLVElement, ToTLV};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::with;

pub use crate::dm::clusters::decl::binding::*;
pub use crate::persist::BINDINGS_KEY;

/// Cluster metadata exposed by [`BindingHandler`].
///
/// Exposed as a free constant so callers can spell out
/// `EpClMatcher::new(Some(ep), Some(binding::CLUSTER.id))` without
/// reaching for the lifetime-parameterised handler type.
pub const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

/// One stored binding entry.
///
/// Wire layout follows the standard `derive(FromTLV, ToTLV)` shape —
/// a TLV struct with positional context-tagged fields (0 = first
/// declared field, 1 = second, …). `Option<T>` fields are
/// omit-if-`None`. The encoding is decoupled from the wire-level
/// `TargetStruct` (which puts `FabricIndex` at ctx 254): we own the
/// persisted layout and only need it to be self-consistent.
#[derive(Debug, Clone, FromTLV, ToTLV)]
struct StoredBinding {
    endpoint_id: EndptId,
    fab_idx: NonZeroU8,
    node: Option<u64>,
    group: Option<u16>,
    endpoint: Option<EndptId>,
    cluster: Option<ClusterId>,
}

/// Shared registry of Binding entries across every endpoint and
/// fabric. Persisted as a single TLV blob under [`BINDINGS_KEY`].
///
/// `N` bounds the total number of entries the device can hold. Per
/// Matter Core spec §9.6.1, device-type definitions may prescribe a
/// minimum-per-fabric; the spec also says the total must be
/// `min_per_fabric × supported_fabrics` — pick `N` accordingly.
pub struct Bindings<const N: usize> {
    state: Mutex<RefCell<Vec<StoredBinding, N>>>,
}

impl<const N: usize> Bindings<N> {
    /// Create an empty registry. Prefer [`Self::init`] for non-trivial
    /// `N` so the storage is initialised in BSS.
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(Vec::new())),
        }
    }

    /// Return an in-place initialiser for an empty registry.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            state <- Mutex::init(RefCell::init(Vec::init())),
        })
    }

    /// Re-hydrate the registry from `store` under [`BINDINGS_KEY`].
    /// Call once at startup, before exposing the data model.
    pub async fn load_persist<S: KvBlobStore>(
        &self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let Some(data) = store.load(BINDINGS_KEY, buf)? else {
            self.state.lock(|cell| cell.borrow_mut().clear());
            return Ok(());
        };

        let loaded = Vec::<StoredBinding, N>::from_tlv(&TLVElement::new(data))?;
        self.state.lock(|cell| *cell.borrow_mut() = loaded);

        info!("Loaded Binding entries for all endpoints from storage");
        Ok(())
    }

    /// Serialise the registry to `ctx.kv()` under [`BINDINGS_KEY`].
    fn store_persist<C: WriteContext>(&self, ctx: &C) -> Result<(), Error> {
        let mut persist = Persist::new(ctx.kv());

        self.state.lock(|cell| {
            let state = cell.borrow();
            persist.store_tlv(BINDINGS_KEY, &*state)
        })?;

        persist.run()
    }

    /// Validate a `TargetStruct` against spec §9.6.5.1 and return a
    /// fully-built `StoredBinding`. `endpoint_id` and `fab_idx` come
    /// from the dispatch context (they are not on the wire entry for
    /// this attribute write — the framework auto-injects fab_idx).
    fn parse_target(
        endpoint_id: EndptId,
        fab_idx: NonZeroU8,
        t: &TargetStruct<'_>,
    ) -> Result<StoredBinding, Error> {
        let node = t.node()?;
        let group = t.group()?;
        let endpoint = t.endpoint()?;
        let cluster = t.cluster()?;

        // Spec §9.6.5.1:
        // - Group and Endpoint MUST NOT both be present.
        // - Node SHALL be present when Endpoint is present.
        // - At least one of (Node+Endpoint) or Group must identify a target.
        if group.is_some() && endpoint.is_some() {
            return Err(ErrorCode::ConstraintError.into());
        }
        if endpoint.is_some() && node.is_none() {
            return Err(ErrorCode::ConstraintError.into());
        }
        if group.is_none() && node.is_none() && endpoint.is_none() {
            return Err(ErrorCode::ConstraintError.into());
        }

        Ok(StoredBinding {
            endpoint_id,
            fab_idx,
            node,
            group,
            endpoint,
            cluster,
        })
    }

    /// Replace every entry on `(endpoint_id, fab_idx)` with the
    /// supplied list. Other endpoints / fabrics are untouched.
    fn replace_entries<'a, C: WriteContext>(
        &self,
        ctx: &C,
        endpoint_id: EndptId,
        fab_idx: NonZeroU8,
        list: &TLVArray<'a, TargetStruct<'a>>,
    ) -> Result<(), Error> {
        // Two-pass validation: parse every supplied target *before*
        // mutating state so a malformed input never partially clears
        // the existing entries on this fabric.
        let mut parsed: Vec<StoredBinding, N> = Vec::new();
        for t in list {
            let t = t?;
            let sb = Self::parse_target(endpoint_id, fab_idx, &t)?;
            parsed.push(sb).map_err(|_| ErrorCode::ResourceExhausted)?;
        }

        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            // Drop every existing entry on this (endpoint, fabric).
            // Iterate-by-index because `retain` doesn't compose with
            // our bounded Vec API the same way.
            let mut i = 0;
            while i < state.len() {
                let e = &state[i];
                if e.endpoint_id == endpoint_id && e.fab_idx == fab_idx {
                    state.remove(i);
                } else {
                    i += 1;
                }
            }
            // Now bulk-insert the validated list. Capacity-exhausted
            // here means the *combined* fabric counts exceeded `N`.
            for sb in parsed {
                state.push(sb).map_err(|_| ErrorCode::ResourceExhausted)?;
            }
            Ok::<_, Error>(())
        })?;

        self.store_persist(ctx)
    }

    /// Append one entry for `(endpoint_id, fab_idx)`.
    fn add_entry<'a, C: WriteContext>(
        &self,
        ctx: &C,
        endpoint_id: EndptId,
        fab_idx: NonZeroU8,
        entry: &TargetStruct<'a>,
    ) -> Result<(), Error> {
        let sb = Self::parse_target(endpoint_id, fab_idx, entry)?;

        self.state.lock(|cell| {
            cell.borrow_mut()
                .push(sb)
                .map_err(|_| -> Error { ErrorCode::ResourceExhausted.into() })?;
            Ok::<_, Error>(())
        })?;

        self.store_persist(ctx)
    }

    /// Render every entry on `endpoint_id` matching the read filter
    /// into the provided builder. `fab_filter = Some(idx)` constrains
    /// the output to one fabric; `None` returns every fabric's
    /// entries (used when the reading accessor opted out of fabric
    /// filtering via `attr.fab_filter == false`).
    fn render<P: TLVBuilderParent>(
        &self,
        endpoint_id: EndptId,
        fab_filter: Option<NonZeroU8>,
        builder: ArrayAttributeRead<TargetStructArrayBuilder<P>, TargetStructBuilder<P>>,
    ) -> Result<P, Error> {
        self.state.lock(|cell| {
            let state = cell.borrow();
            let mut iter = state
                .iter()
                .filter(|e| e.endpoint_id == endpoint_id)
                .filter(|e| fab_filter.is_none_or(|f| e.fab_idx == f));

            match builder {
                ArrayAttributeRead::ReadAll(mut array) => {
                    for e in iter {
                        let item = array.push()?;
                        let item = item.node(e.node)?;
                        let item = item.group(e.group)?;
                        let item = item.endpoint(e.endpoint)?;
                        let item = item.cluster(e.cluster)?;
                        array = item.fabric_index(Some(e.fab_idx.get()))?.end()?;
                    }
                    array.end()
                }
                ArrayAttributeRead::ReadOne(index, item) => {
                    let Some(e) = iter.nth(index as usize) else {
                        return Err(ErrorCode::ConstraintError.into());
                    };
                    let item = item.node(e.node)?;
                    let item = item.group(e.group)?;
                    let item = item.endpoint(e.endpoint)?;
                    let item = item.cluster(e.cluster)?;
                    item.fabric_index(Some(e.fab_idx.get()))?.end()
                }
                ArrayAttributeRead::ReadNone(array) => array.end(),
            }
        })
    }
}

impl<const N: usize> Default for Bindings<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-`(endpoint, Binding)`-instance handler facade. Holds only a
/// `Dataver`, the endpoint id it serves, and a borrow of the shared
/// [`Bindings`] registry. All persisted state lives in the registry.
pub struct BindingHandler<'a, const N: usize> {
    dataver: Dataver,
    endpoint_id: EndptId,
    bindings: &'a Bindings<N>,
}

impl<'a, const N: usize> BindingHandler<'a, N> {
    /// Construct a facade for `(endpoint_id, Binding)` backed by the
    /// shared `bindings` registry.
    pub const fn new(dataver: Dataver, endpoint_id: EndptId, bindings: &'a Bindings<N>) -> Self {
        Self {
            dataver,
            endpoint_id,
            bindings,
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl<const N: usize> ClusterHandler for BindingHandler<'_, N> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn binding<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<TargetStructArrayBuilder<P>, TargetStructBuilder<P>>,
    ) -> Result<P, Error> {
        let attr = ctx.attr();
        // Translate the framework's `(fab_filter: bool, fab_idx: u8)` pair
        // into `Option<NonZeroU8>`. A reader that opted into fabric
        // filtering but presents an unaccredited fab_idx of 0 gets the
        // empty list — that's how the spec describes the "no accessing
        // fabric" state for fabric-scoped attrs.
        let fab_filter = if attr.fab_filter {
            Some(NonZeroU8::new(attr.fab_idx).ok_or(ErrorCode::UnsupportedAccess)?)
        } else {
            None
        };
        self.bindings.render(self.endpoint_id, fab_filter, builder)
    }

    fn set_binding(
        &self,
        ctx: impl WriteContext,
        value: ArrayAttributeWrite<TLVArray<'_, TargetStruct<'_>>, TargetStruct<'_>>,
    ) -> Result<(), Error> {
        // Fabric-scoped writes require a valid accessor fabric — the
        // `NonZeroU8::new` conversion is the type-system encoding of
        // that requirement.
        let fab_idx = NonZeroU8::new(ctx.attr().fab_idx).ok_or(ErrorCode::UnsupportedAccess)?;

        match value {
            ArrayAttributeWrite::Replace(list) => {
                self.bindings
                    .replace_entries(&ctx, self.endpoint_id, fab_idx, &list)
            }
            ArrayAttributeWrite::Add(entry) => {
                self.bindings
                    .add_entry(&ctx, self.endpoint_id, fab_idx, &entry)
            }
            // Per-element list update / remove on fabric-scoped attrs:
            // the framework converts these to InvalidAction before
            // reaching us, but match exhaustively to be safe.
            ArrayAttributeWrite::Update(_, _) | ArrayAttributeWrite::Remove(_) => {
                Err(ErrorCode::InvalidAction.into())
            }
        }
    }
}
