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

//! Scenes Management cluster (Matter Application Cluster Specification).
//!
//! # Overview
//!
//! A scene is a named snapshot of a chosen subset of cluster attributes
//! on one endpoint, stored on the device and recallable on demand. The
//! Scenes Management cluster owns the scene table and exposes commands
//! to add, view, remove, snapshot (`StoreScene`) and apply
//! (`RecallScene`) scenes.
//!
//! # Implementation status (v1)
//!
//! - All 8 commands have entry points.
//! - The 6 **data-only** commands are fully implemented:
//!   `AddScene`, `ViewScene`, `RemoveScene`, `RemoveAllScenes`,
//!   `GetSceneMembership`, `CopyScene`.
//! - **`StoreScene` / `RecallScene` are stubs** that return
//!   `IMStatusCode::Failure` — they need cross-cluster attribute
//!   read/write plumbing (via `ctx.handler()` on the global handler),
//!   which is the v2 workstream. The handler is wired as
//!   [`ClusterAsyncHandler`] so v2 can `.await` cross-cluster calls
//!   without a trait-shape migration.
//! - **`ExtensionFieldSetStructs` payloads from `AddScene` are
//!   discarded** in v1; `ViewScene` always echoes the field as absent.
//!   v2 will keep the wire bytes in a per-scene blob and replay them.
//! - **In-RAM storage only**: scenes are not persisted across reboots
//!   (also v2).
//! - The `SceneNames` feature is **disabled** by default; scene names
//!   sent by the controller are accepted on the wire but discarded.
//!
//! # Storage model
//!
//! Scenes are fabric-scoped (each fabric has its own scene table) and
//! per-endpoint (scenes on EP1 don't affect EP2). The state is a
//! single flat [`heapless::Vec`] of [`SceneEntry`] entries keyed by
//! `(fab_idx, endpoint_id, group_id, scene_id)`.
//!
//! The caller owns the [`ScenesState`] and shares it via reference
//! with one [`ScenesHandler`] per endpoint where the cluster is
//! exposed.
//!
//! # Async-trait shape note
//!
//! [`ClusterAsyncHandler`] methods that don't actually need to
//! `.await` anything (i.e. all of them in v1) are written as
//! `fn foo(...) -> impl Future<...> { ready(self.foo_sync(...)) }`
//! delegating to a plain `fn foo_sync(...) -> Result<...>` helper.
//! This compiles to a much smaller image than `async fn` — no
//! state-machine generator, no closure. Matters on flash-constrained
//! MCUs.

use core::future::{ready, Future};
use core::num::NonZeroU8;

use crate::dm::{
    ArrayAttributeRead, Cluster, Dataver, EndptId, InvokeContext, ReadContext, SceneId,
};
use crate::error::{Error, ErrorCode};
use crate::im::IMStatusCode;
use crate::tlv::TLVBuilderParent;
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;

pub use crate::dm::clusters::decl::scenes_management::*;

/// IM status codes specific to the Scenes Management cluster (see
/// "Generic Usage Notes" in the Matter Application Cluster spec).
const SC_NOT_FOUND: u8 = 0x8B;
const SC_INSUFFICIENT_SPACE: u8 = 0x89;

/// One scene record. v1 stores metadata only — the wire-form
/// `ExtensionFieldSetStructs` payload supplied by `AddScene` is
/// discarded (echo'd as absent on `ViewScene`). v2 will add a blob
/// field carrying that payload for `RecallScene`.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SceneEntry {
    /// Fabric index that owns this scene (spec reserves `0` for
    /// "no fabric" / PASE; an installed fabric is always non-zero).
    fab_idx: NonZeroU8,
    /// Endpoint this scene lives on.
    endpoint_id: EndptId,
    /// Group ID (0 ⇒ "no group" / per-endpoint).
    group_id: u16,
    /// Scene ID within the group.
    scene_id: SceneId,
    /// Transition time encoded per spec (1/10 s units).
    transition_time: u32,
}

impl SceneEntry {
    fn matches(
        &self,
        fab_idx: NonZeroU8,
        endpoint_id: EndptId,
        group_id: u16,
        scene_id: SceneId,
    ) -> bool {
        self.fab_idx == fab_idx
            && self.endpoint_id == endpoint_id
            && self.group_id == group_id
            && self.scene_id == scene_id
    }
}

/// Per-fabric "last recalled scene" pointer feeding
/// `FabricSceneInfo.CurrentScene` / `CurrentGroup` / `SceneValid`.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct CurrentScene {
    fab_idx: NonZeroU8,
    group_id: u16,
    scene_id: SceneId,
}

/// All mutable Scenes state, held behind a single mutex via
/// [`ScenesState`]. Grouped so the cluster handler takes exactly one
/// lock per operation — mirrors the `OnOffState` / `Mutex<RefCell<…>>`
/// shape used elsewhere in `rs-matter`.
struct ScenesStateInner<const N: usize> {
    /// The scene table, keyed by `(fab_idx, endpoint_id, group_id, scene_id)`.
    table: Vec<SceneEntry, N>,
    /// Bounded by `N` for storage symmetry; in practice one slot per
    /// fabric. Absent for a given `fab_idx` ⇒ `SceneValid = false`.
    current_per_fabric: Vec<CurrentScene, N>,
    /// Bookkeeping bump for the `FabricSceneInfo` reader.
    info_dataver: u32,
}

impl<const N: usize> ScenesStateInner<N> {
    const fn new() -> Self {
        Self {
            table: Vec::new(),
            current_per_fabric: Vec::new(),
            info_dataver: 0,
        }
    }

    /// In-place initializer — preferred when stamping into uninit
    /// memory (e.g. `StaticCell::uninit().init_with(...)`). Mirrors
    /// the same pattern used by `Fabrics`, `MatterState`, etc.
    fn init() -> impl Init<Self> {
        init!(Self {
            table <- Vec::init(),
            current_per_fabric <- Vec::init(),
            info_dataver: 0,
        })
    }

    fn bump_info_dataver(&mut self) {
        self.info_dataver = self.info_dataver.wrapping_add(1);
    }
}

/// Caller-owned per-device Scenes state. Capacity is the const
/// generic `N`. Shared across all endpoints that expose the cluster.
///
/// Internally a single [`Mutex`] over a [`RefCell`] — every handler
/// operation takes one lock and mutates the inner table directly.
pub struct ScenesState<const N: usize> {
    inner: Mutex<RefCell<ScenesStateInner<N>>>,
}

impl<const N: usize> ScenesState<N> {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(RefCell::new(ScenesStateInner::new())),
        }
    }

    /// In-place initializer.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            inner <- Mutex::init(RefCell::init(ScenesStateInner::init())),
        })
    }

    /// Take the lock and run `f` against the mutable inner state.
    fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut ScenesStateInner<N>) -> R,
    {
        self.inner.lock(|cell| {
            let mut inner = cell.borrow_mut();
            f(&mut inner)
        })
    }
}

impl<const N: usize> Default for ScenesState<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Scenes Management cluster handler. Implements the **async**
/// codegen trait so the v2 store/recall paths can `.await`
/// cross-cluster reads/writes via `ctx.handler()` without a trait-
/// shape migration.
pub struct ScenesHandler<'a, const N: usize> {
    dataver: Dataver,
    state: &'a ScenesState<N>,
}

impl<'a, const N: usize> ScenesHandler<'a, N> {
    pub const fn new(dataver: Dataver, state: &'a ScenesState<N>) -> Self {
        Self { dataver, state }
    }

    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }

    fn fab_idx<C: InvokeContext>(ctx: &C) -> Result<NonZeroU8, Error> {
        ctx.exchange().accessor()?.fab_idx()
    }

    /// Stamp `(group, scene)` as the current recalled scene for this
    /// fabric. Bumps `FabricSceneInfo` dataver. Operates on already-
    /// locked inner state.
    fn remember_current(
        inner: &mut ScenesStateInner<N>,
        fab_idx: NonZeroU8,
        group_id: u16,
        scene_id: SceneId,
    ) {
        if let Some(slot) = inner
            .current_per_fabric
            .iter_mut()
            .find(|c| c.fab_idx == fab_idx)
        {
            slot.group_id = group_id;
            slot.scene_id = scene_id;
        } else {
            // Best-effort push; if the slab is full we silently stop
            // tracking CurrentScene for this fabric (the spec permits
            // SceneValid=false in such cases).
            let _ = inner.current_per_fabric.push(CurrentScene {
                fab_idx,
                group_id,
                scene_id,
            });
        }
        inner.bump_info_dataver();
    }

    /// Drop the recalled-scene tracker for this fabric — called after
    /// operations that change the scene table in ways that may make
    /// the previously-recalled scene no longer represent the current
    /// attribute state (per the `SceneValid` field rules in the spec).
    /// Operates on already-locked inner state.
    fn invalidate_current(inner: &mut ScenesStateInner<N>, fab_idx: NonZeroU8) {
        inner.current_per_fabric.retain(|c| c.fab_idx != fab_idx);
        inner.bump_info_dataver();
    }

    /// Internal copy helper — runs against an already-locked
    /// [`ScenesStateInner`]. Returns the IM status code (0 on success).
    ///
    /// In-place index-walk: no scratch buffer. `heapless::Vec::push`
    /// always appends at the end, so an upsert that has to push a new
    /// destination row lands at an index strictly greater than the
    /// current source index — earlier-index iteration stays valid.
    /// Pushed rows live in `group_to`, never match the `group_from`
    /// filter, so the loop converges. Worst case is O(N²) on the
    /// inner `position` lookup, which is fine for the small `N` this
    /// cluster carries.
    #[allow(clippy::too_many_arguments)]
    fn copy_scenes_inner(
        inner: &mut ScenesStateInner<N>,
        fab_idx: NonZeroU8,
        endpoint_id: EndptId,
        group_from: u16,
        scene_from: SceneId,
        group_to: u16,
        scene_to: SceneId,
        copy_all: bool,
    ) -> u8 {
        let mut found_source = false;
        let mut idx = 0;
        while idx < inner.table.len() {
            let src = &inner.table[idx];
            let src_matches = src.fab_idx == fab_idx
                && src.endpoint_id == endpoint_id
                && src.group_id == group_from
                && (copy_all || src.scene_id == scene_from);
            if src_matches {
                found_source = true;
                // Copy the scalars out so we can re-borrow the table
                // mutably for the upsert.
                let src_scene_id = src.scene_id;
                let src_transition_time = src.transition_time;
                let target_scene_id = if copy_all { src_scene_id } else { scene_to };

                // Upsert into (fab, ep, group_to, target_scene_id).
                if let Some(pos) = inner
                    .table
                    .iter()
                    .position(|e| e.matches(fab_idx, endpoint_id, group_to, target_scene_id))
                {
                    inner.table[pos].transition_time = src_transition_time;
                } else if inner
                    .table
                    .push(SceneEntry {
                        fab_idx,
                        endpoint_id,
                        group_id: group_to,
                        scene_id: target_scene_id,
                        transition_time: src_transition_time,
                    })
                    .is_err()
                {
                    return SC_INSUFFICIENT_SPACE;
                }

                // Single-scene mode copies exactly one entry — bail
                // out before we walk the rest of the table.
                if !copy_all {
                    break;
                }
            }
            idx += 1;
        }

        // Source must exist for the operation to succeed (per the
        // `CopyScene` command's effect-on-receipt).
        if !found_source {
            return SC_NOT_FOUND;
        }

        Self::invalidate_current(inner, fab_idx);
        0
    }

    // -----------------------------------------------------------------
    // Synchronous handler bodies.
    //
    // The trait-required methods in the `ClusterAsyncHandler` impl
    // below are tiny `fn -> impl Future` wrappers that delegate here
    // via `ready(self.foo_sync(...))`. Keeping the real logic
    // synchronous (a) lets us use `?` freely, (b) skips the
    // `async fn` state-machine codegen, and (c) avoids closure
    // captures in the wrappers. Three small wins that add up on
    // flash-constrained targets.
    // -----------------------------------------------------------------

    fn fabric_scene_info_sync<P: TLVBuilderParent>(
        &self,
        ctx: &impl ReadContext,
        builder: ArrayAttributeRead<SceneInfoStructArrayBuilder<P>, SceneInfoStructBuilder<P>>,
    ) -> Result<P, Error> {
        let endpoint_id = ctx.attr().endpoint_id;
        let accessor_fab_idx = ctx.exchange().accessor()?.fab_idx()?;

        // Snapshot the relevant scalars under a single lock, then build
        // the response outside the lock.
        let (scene_count, cur_group, cur_scene, valid, remaining) = self.state.with(|inner| {
            let count = inner
                .table
                .iter()
                .filter(|e| e.fab_idx == accessor_fab_idx && e.endpoint_id == endpoint_id)
                .count();
            let current = inner
                .current_per_fabric
                .iter()
                .find(|c| c.fab_idx == accessor_fab_idx)
                .copied();
            let (g, s, v) = match current {
                Some(c) => (Some(c.group_id), Some(c.scene_id), true),
                None => (None, None, false),
            };
            let rem = (N.saturating_sub(inner.table.len())).min(0xFF) as u8;
            (count.min(0xFF) as u8, g, s, v, rem)
        });

        match builder {
            ArrayAttributeRead::ReadAll(arr) => {
                let arr = arr
                    .push()?
                    .scene_count(scene_count)?
                    .current_scene(cur_scene)?
                    .current_group(cur_group)?
                    .scene_valid(Some(valid))?
                    .remaining_capacity(remaining)?
                    .fabric_index(Some(accessor_fab_idx.get()))?
                    .end()?;

                arr.end()
            }
            ArrayAttributeRead::ReadNone(arr) => arr.end(),
            ArrayAttributeRead::ReadOne(_idx, _entry) => {
                // Indexed single-row reads aren't useful here (we only
                // emit one row); reject as not found.
                Err(ErrorCode::AttributeNotFound.into())
            }
        }
    }

    fn handle_add_scene_sync<P: TLVBuilderParent>(
        &self,
        ctx: &impl InvokeContext,
        request: &AddSceneRequest<'_>,
        response: AddSceneResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;
        let scene_id = request.scene_id()?;
        let transition_time = request.transition_time()?;

        // v1 discards the `ExtensionFieldSetStructs` payload; v2 will
        // capture it so `RecallScene` can replay it. Scene names are
        // accepted on the wire (codegen parses them) but not stored.

        // Insert / replace + invalidate SceneValid for this fabric — all
        // under a single lock. Per the `SceneValid` field rules,
        // adding/storing a scene that doesn't match the current
        // attribute state invalidates SceneValid.
        let status_code: u8 = self.state.with(|inner| {
            if let Some(pos) = inner
                .table
                .iter()
                .position(|e| e.matches(fab_idx, endpoint_id, group_id, scene_id))
            {
                inner.table[pos].transition_time = transition_time;
                Self::invalidate_current(inner, fab_idx);
                0
            } else if inner.table.len() >= N {
                SC_INSUFFICIENT_SPACE
            } else {
                let _ = inner.table.push(SceneEntry {
                    fab_idx,
                    endpoint_id,
                    group_id,
                    scene_id,
                    transition_time,
                });
                Self::invalidate_current(inner, fab_idx);
                0
            }
        });

        if status_code == 0 {
            self.dataver_changed();
        }

        response
            .status(status_code)?
            .group_id(group_id)?
            .scene_id(scene_id)?
            .end()
    }

    fn handle_view_scene_sync<P: TLVBuilderParent>(
        &self,
        ctx: &impl InvokeContext,
        request: &ViewSceneRequest<'_>,
        response: ViewSceneResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;
        let scene_id = request.scene_id()?;

        let transition_time = self.state.with(|inner| {
            inner
                .table
                .iter()
                .find(|e| e.matches(fab_idx, endpoint_id, group_id, scene_id))
                .map(|e| e.transition_time)
        });

        // The wire shape is (status, group_id, scene_id, optional
        // transition_time, optional scene_name, optional extension
        // fields). All three optional fields are emitted as absent on
        // NotFound; on Success, transition_time is populated, scene
        // name is empty (SceneNames disabled), extension fields are
        // absent (v2 will fill these from a stored blob).
        match transition_time {
            Some(tt) => response
                .status(0)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .transition_time(Some(tt))?
                .scene_name(Some(""))?
                .extension_field_set_structs()?
                .none()
                .end(),
            None => response
                .status(SC_NOT_FOUND)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .transition_time(None)?
                .scene_name(None)?
                .extension_field_set_structs()?
                .none()
                .end(),
        }
    }

    fn handle_remove_scene_sync<P: TLVBuilderParent>(
        &self,
        ctx: &impl InvokeContext,
        request: &RemoveSceneRequest<'_>,
        response: RemoveSceneResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;
        let scene_id = request.scene_id()?;

        let status: u8 = self.state.with(|inner| {
            if let Some(pos) = inner
                .table
                .iter()
                .position(|e| e.matches(fab_idx, endpoint_id, group_id, scene_id))
            {
                inner.table.swap_remove(pos);
                Self::invalidate_current(inner, fab_idx);
                0
            } else {
                SC_NOT_FOUND
            }
        });

        if status == 0 {
            self.dataver_changed();
        }

        response
            .status(status)?
            .group_id(group_id)?
            .scene_id(scene_id)?
            .end()
    }

    fn handle_remove_all_scenes_sync<P: TLVBuilderParent>(
        &self,
        ctx: &impl InvokeContext,
        request: &RemoveAllScenesRequest<'_>,
        response: RemoveAllScenesResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;

        let removed = self.state.with(|inner| {
            let before = inner.table.len();
            inner.table.retain(|e| {
                !(e.fab_idx == fab_idx && e.endpoint_id == endpoint_id && e.group_id == group_id)
            });
            let changed = before != inner.table.len();
            if changed {
                Self::invalidate_current(inner, fab_idx);
            }
            changed
        });

        if removed {
            self.dataver_changed();
        }

        response.status(0)?.group_id(group_id)?.end()
    }

    fn handle_store_scene_sync<P: TLVBuilderParent>(
        &self,
        request: &StoreSceneRequest<'_>,
        response: StoreSceneResponseBuilder<P>,
    ) -> Result<P, Error> {
        // v2: snapshot scene-able attributes on this endpoint via
        // `ctx.handler()` and store as ExtensionFieldSetStructs.
        let group_id = request.group_id()?;
        let scene_id = request.scene_id()?;
        response
            .status(IMStatusCode::Failure as u8)?
            .group_id(group_id)?
            .scene_id(scene_id)?
            .end()
    }

    fn handle_recall_scene_sync(
        &self,
        ctx: &impl InvokeContext,
        request: &RecallSceneRequest<'_>,
    ) -> Result<(), Error> {
        // v1 stub: succeeds for known (group, scene) — bumps
        // CurrentScene — but doesn't actually apply attribute writes.
        // v2 will parse the stored ExtensionFieldSetStructs and apply
        // each attribute write via `ctx.handler()`.
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;
        let scene_id = request.scene_id()?;

        let found = self.state.with(|inner| {
            let f = inner
                .table
                .iter()
                .any(|e| e.matches(fab_idx, endpoint_id, group_id, scene_id));
            if f {
                Self::remember_current(inner, fab_idx, group_id, scene_id);
            }
            f
        });

        if !found {
            return Err(ErrorCode::Failure.into());
        }

        self.dataver_changed();
        Ok(())
    }

    fn handle_get_scene_membership_sync<P: TLVBuilderParent>(
        &self,
        ctx: &impl InvokeContext,
        request: &GetSceneMembershipRequest<'_>,
        response: GetSceneMembershipResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;

        // Build the response directly inside the lock — the TLV
        // builder is purely synchronous (no `.await`), so holding the
        // lock for the write is cheap. This avoids snapshotting scene
        // IDs into a stack `Vec<SceneId, N>` (could be ~N bytes;
        // matters on small-stack MCUs).
        self.state.with(|inner| -> Result<P, Error> {
            let remaining = (N.saturating_sub(inner.table.len())).min(0xFF) as u8;
            let group_has_scenes = inner.table.iter().any(|e| {
                e.fab_idx == fab_idx && e.endpoint_id == endpoint_id && e.group_id == group_id
            });

            let resp = response
                .status(0)?
                .capacity(crate::tlv::Nullable::some(remaining))?
                .group_id(group_id)?;

            // Per the `GetSceneMembership` command spec: when GroupID
            // has no scenes on this device, SceneList SHALL be
            // omitted (None).
            if !group_has_scenes {
                return resp.scene_list()?.none().end();
            }

            let list = resp.scene_list()?.some()?;
            let list = inner
                .table
                .iter()
                .filter(|e| {
                    e.fab_idx == fab_idx && e.endpoint_id == endpoint_id && e.group_id == group_id
                })
                .try_fold(list, |list, e| list.push(&e.scene_id))?;
            list.end()?.end()
        })
    }

    fn handle_copy_scene_sync<P: TLVBuilderParent>(
        &self,
        ctx: &impl InvokeContext,
        request: &CopySceneRequest<'_>,
        response: CopySceneResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let mode = request.mode()?;
        let group_from = request.group_identifier_from()?;
        let scene_from = request.scene_identifier_from()?;
        let group_to = request.group_identifier_to()?;
        let scene_to = request.scene_identifier_to()?;

        // Per the `CopyModeBitmap` spec: bit 0 of Mode = COPY_ALL_SCENES
        // (copy all scenes from the source group; the From/To SceneIDs
        // are ignored when set).
        let copy_all = (mode.bits() & 0x01) != 0;

        // The whole "look up source + copy entries" operation runs
        // under one lock so the table can't change mid-copy.
        let status = self.state.with(|inner| {
            Self::copy_scenes_inner(
                inner,
                fab_idx,
                endpoint_id,
                group_from,
                scene_from,
                group_to,
                scene_to,
                copy_all,
            )
        });

        if status == 0 {
            self.dataver_changed();
        }

        response
            .status(status)?
            .group_identifier_from(group_from)?
            .scene_identifier_from(scene_from)?
            .end()
    }
}

impl<const N: usize> ClusterAsyncHandler for ScenesHandler<'_, N> {
    /// FULL_CLUSTER minus the SceneNames feature (we accept the field
    /// on the wire but don't persist it — see module docs).
    const CLUSTER: Cluster<'static> = FULL_CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn scene_table_size(&self, _ctx: impl ReadContext) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(N as u16))
    }

    fn fabric_scene_info<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<SceneInfoStructArrayBuilder<P>, SceneInfoStructBuilder<P>>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.fabric_scene_info_sync(&ctx, builder))
    }

    fn handle_add_scene<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: AddSceneRequest<'_>,
        response: AddSceneResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.handle_add_scene_sync(&ctx, &request, response))
    }

    fn handle_view_scene<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: ViewSceneRequest<'_>,
        response: ViewSceneResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.handle_view_scene_sync(&ctx, &request, response))
    }

    fn handle_remove_scene<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: RemoveSceneRequest<'_>,
        response: RemoveSceneResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.handle_remove_scene_sync(&ctx, &request, response))
    }

    fn handle_remove_all_scenes<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: RemoveAllScenesRequest<'_>,
        response: RemoveAllScenesResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.handle_remove_all_scenes_sync(&ctx, &request, response))
    }

    fn handle_store_scene<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        request: StoreSceneRequest<'_>,
        response: StoreSceneResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.handle_store_scene_sync(&request, response))
    }

    fn handle_recall_scene(
        &self,
        ctx: impl InvokeContext,
        request: RecallSceneRequest<'_>,
    ) -> impl Future<Output = Result<(), Error>> {
        ready(self.handle_recall_scene_sync(&ctx, &request))
    }

    fn handle_get_scene_membership<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: GetSceneMembershipRequest<'_>,
        response: GetSceneMembershipResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.handle_get_scene_membership_sync(&ctx, &request, response))
    }

    fn handle_copy_scene<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: CopySceneRequest<'_>,
        response: CopySceneResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.handle_copy_scene_sync(&ctx, &request, response))
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the more intricate Scenes Management logic.
    //!
    //! Focus is on [`ScenesHandler::copy_scenes_inner`] (in-place
    //! upsert loop on a shared `inner.table`) and the `CurrentScene`
    //! invalidation rules — the pieces with the easiest-to-introduce
    //! bugs.
    //!
    //! Tests run against [`ScenesStateInner`] directly (the
    //! handler-visible storage), so we don't have to spin up a full
    //! `Matter`/`Exchange`/`InvokeContext` to exercise the algorithm.

    use super::*;

    fn fab(n: u8) -> NonZeroU8 {
        NonZeroU8::new(n).unwrap()
    }

    fn entry(
        fab_idx: NonZeroU8,
        endpoint_id: EndptId,
        group_id: u16,
        scene_id: SceneId,
        transition_time: u32,
    ) -> SceneEntry {
        SceneEntry {
            fab_idx,
            endpoint_id,
            group_id,
            scene_id,
            transition_time,
        }
    }

    fn push(inner: &mut ScenesStateInner<8>, e: SceneEntry) {
        inner.table.push(e).expect("test table overflow");
    }

    /// Count entries in `inner.table` matching the given filter.
    fn count(inner: &ScenesStateInner<8>, fab_idx: NonZeroU8, ep: EndptId, group: u16) -> usize {
        inner
            .table
            .iter()
            .filter(|e| e.fab_idx == fab_idx && e.endpoint_id == ep && e.group_id == group)
            .count()
    }

    fn find_tt(
        inner: &ScenesStateInner<8>,
        fab_idx: NonZeroU8,
        ep: EndptId,
        group: u16,
        scene: SceneId,
    ) -> Option<u32> {
        inner
            .table
            .iter()
            .find(|e| e.matches(fab_idx, ep, group, scene))
            .map(|e| e.transition_time)
    }

    // ---- copy_scenes_inner: specific-scene mode ----

    #[test]
    fn copy_single_scene_to_new_dest() {
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry(fab(1), 1, 10, 5, 100));

        let status = ScenesHandler::<8>::copy_scenes_inner(
            &mut inner,
            fab(1),
            1,
            /*from*/ 10,
            5,
            /*to*/ 20,
            7,
            /*copy_all*/ false,
        );

        assert_eq!(status, 0);
        // Source still there.
        assert_eq!(find_tt(&inner, fab(1), 1, 10, 5), Some(100));
        // Dest got a new entry with the source's transition_time but
        // the requested target scene_id.
        assert_eq!(find_tt(&inner, fab(1), 1, 20, 7), Some(100));
        assert_eq!(inner.table.len(), 2);
    }

    #[test]
    fn copy_single_scene_replaces_existing_dest() {
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry(fab(1), 1, 10, 5, 100));
        push(&mut inner, entry(fab(1), 1, 20, 7, 999));

        let status =
            ScenesHandler::<8>::copy_scenes_inner(&mut inner, fab(1), 1, 10, 5, 20, 7, false);

        assert_eq!(status, 0);
        // Dest's transition_time was overwritten — no new row pushed.
        assert_eq!(find_tt(&inner, fab(1), 1, 20, 7), Some(100));
        assert_eq!(inner.table.len(), 2);
    }

    #[test]
    fn copy_single_scene_missing_source_returns_not_found() {
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry(fab(1), 1, 10, 5, 100));

        let status = ScenesHandler::<8>::copy_scenes_inner(
            &mut inner,
            fab(1),
            1,
            /*from*/ 99, // group doesn't exist
            5,
            20,
            7,
            false,
        );

        assert_eq!(status, SC_NOT_FOUND);
        // No side effects on the table.
        assert_eq!(inner.table.len(), 1);
        assert_eq!(find_tt(&inner, fab(1), 1, 20, 7), None);
    }

    // ---- copy_scenes_inner: copy-all mode ----

    #[test]
    fn copy_all_copies_every_source_scene() {
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry(fab(1), 1, 10, 1, 100));
        push(&mut inner, entry(fab(1), 1, 10, 2, 200));
        push(&mut inner, entry(fab(1), 1, 10, 3, 300));

        let status = ScenesHandler::<8>::copy_scenes_inner(
            &mut inner,
            fab(1),
            1,
            10,
            /*scene_from*/ 0, // ignored in copy_all
            20,
            /*scene_to*/ 0, // ignored in copy_all
            true,
        );

        assert_eq!(status, 0);
        // All three source scene IDs replicated under group 20 with
        // the same scene IDs and transition_times.
        assert_eq!(count(&inner, fab(1), 1, 20), 3);
        assert_eq!(find_tt(&inner, fab(1), 1, 20, 1), Some(100));
        assert_eq!(find_tt(&inner, fab(1), 1, 20, 2), Some(200));
        assert_eq!(find_tt(&inner, fab(1), 1, 20, 3), Some(300));
        // Sources untouched.
        assert_eq!(count(&inner, fab(1), 1, 10), 3);
    }

    #[test]
    fn copy_all_to_same_group_is_noop() {
        // Edge case: group_from == group_to. Each "copy" lands on the
        // existing source row → in-place replace of transition_time
        // with itself. Loop must terminate (pushes never occur) and
        // not infinite-loop on newly-pushed rows.
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry(fab(1), 1, 10, 1, 100));
        push(&mut inner, entry(fab(1), 1, 10, 2, 200));

        let status = ScenesHandler::<8>::copy_scenes_inner(
            &mut inner,
            fab(1),
            1,
            /*from*/ 10,
            0,
            /*to*/ 10, // SAME as from
            0,
            true,
        );

        assert_eq!(status, 0);
        assert_eq!(inner.table.len(), 2);
    }

    #[test]
    fn copy_all_missing_source_returns_not_found() {
        let mut inner = ScenesStateInner::<8>::new();
        // Some unrelated scenes — should not interfere.
        push(&mut inner, entry(fab(1), 1, 99, 1, 100));

        let status = ScenesHandler::<8>::copy_scenes_inner(
            &mut inner,
            fab(1),
            1,
            10, // empty group
            0,
            20,
            0,
            true,
        );

        assert_eq!(status, SC_NOT_FOUND);
        assert_eq!(inner.table.len(), 1);
        assert_eq!(count(&inner, fab(1), 1, 20), 0);
    }

    #[test]
    fn copy_all_capacity_exhaustion_returns_insufficient_space() {
        // N=3 capacity. Fill with 3 scenes in group 10. Copying all
        // to a new group 20 needs 3 more slots → fail mid-copy.
        let mut inner = ScenesStateInner::<3>::new();
        inner.table.push(entry(fab(1), 1, 10, 1, 100)).unwrap();
        inner.table.push(entry(fab(1), 1, 10, 2, 200)).unwrap();
        inner.table.push(entry(fab(1), 1, 10, 3, 300)).unwrap();

        let status =
            ScenesHandler::<3>::copy_scenes_inner(&mut inner, fab(1), 1, 10, 0, 20, 0, true);

        assert_eq!(status, SC_INSUFFICIENT_SPACE);
        // Table is at capacity, partial copies are NOT rolled back
        // (matches the original Vec-based implementation's behaviour);
        // just assert we didn't lose the sources.
        assert_eq!(inner.table.len(), 3);
    }

    // ---- isolation: don't touch other fabrics or endpoints ----

    #[test]
    fn copy_does_not_cross_fabric_boundary() {
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry(fab(1), 1, 10, 5, 100));

        let status = ScenesHandler::<8>::copy_scenes_inner(
            &mut inner,
            fab(2), // different fabric
            1,
            10,
            5,
            20,
            7,
            false,
        );

        assert_eq!(status, SC_NOT_FOUND);
        // fab(2) didn't gain a row.
        assert_eq!(count(&inner, fab(2), 1, 20), 0);
        // fab(1)'s row is untouched.
        assert_eq!(find_tt(&inner, fab(1), 1, 10, 5), Some(100));
    }

    #[test]
    fn copy_does_not_cross_endpoint_boundary() {
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry(fab(1), 1, 10, 5, 100));

        let status = ScenesHandler::<8>::copy_scenes_inner(
            &mut inner,
            fab(1),
            2, // different endpoint
            10,
            5,
            20,
            7,
            false,
        );

        assert_eq!(status, SC_NOT_FOUND);
        assert_eq!(count(&inner, fab(1), 2, 20), 0);
    }

    // ---- side effect: SceneValid invalidation ----

    #[test]
    fn successful_copy_invalidates_current_scene() {
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry(fab(1), 1, 10, 5, 100));
        // Stamp a "current scene" for fab 1, then assert it gets
        // cleared after the copy.
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 99, 99);
        assert_eq!(inner.current_per_fabric.len(), 1);

        let status =
            ScenesHandler::<8>::copy_scenes_inner(&mut inner, fab(1), 1, 10, 5, 20, 7, false);

        assert_eq!(status, 0);
        // current_per_fabric for fab(1) was cleared.
        assert!(inner.current_per_fabric.iter().all(|c| c.fab_idx != fab(1)));
    }

    #[test]
    fn failed_copy_does_not_invalidate_current_scene() {
        let mut inner = ScenesStateInner::<8>::new();
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 99, 99);
        let dv_before = inner.info_dataver;

        let status = ScenesHandler::<8>::copy_scenes_inner(
            &mut inner,
            fab(1),
            1,
            10, // empty group
            5,
            20,
            7,
            false,
        );

        assert_eq!(status, SC_NOT_FOUND);
        // current_per_fabric untouched.
        assert_eq!(inner.current_per_fabric.len(), 1);
        assert_eq!(inner.current_per_fabric[0].fab_idx, fab(1));
        assert_eq!(inner.current_per_fabric[0].group_id, 99);
        assert_eq!(inner.current_per_fabric[0].scene_id, 99);
        // info_dataver not bumped on failure.
        assert_eq!(inner.info_dataver, dv_before);
    }

    // ---- remember_current / invalidate_current helpers ----

    #[test]
    fn remember_current_replaces_existing_slot_in_place() {
        let mut inner = ScenesStateInner::<8>::new();
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 10, 1);
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 20, 2);

        // Same fabric ⇒ slot is updated, not duplicated.
        assert_eq!(inner.current_per_fabric.len(), 1);
        assert_eq!(inner.current_per_fabric[0].group_id, 20);
        assert_eq!(inner.current_per_fabric[0].scene_id, 2);
    }

    #[test]
    fn remember_current_keeps_fabrics_independent() {
        let mut inner = ScenesStateInner::<8>::new();
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 10, 1);
        ScenesHandler::<8>::remember_current(&mut inner, fab(2), 20, 2);

        assert_eq!(inner.current_per_fabric.len(), 2);
    }

    #[test]
    fn invalidate_current_only_clears_target_fabric() {
        let mut inner = ScenesStateInner::<8>::new();
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 10, 1);
        ScenesHandler::<8>::remember_current(&mut inner, fab(2), 20, 2);

        ScenesHandler::<8>::invalidate_current(&mut inner, fab(1));

        // fab(2)'s entry survives.
        assert_eq!(inner.current_per_fabric.len(), 1);
        assert_eq!(inner.current_per_fabric[0].fab_idx, fab(2));
    }
}
