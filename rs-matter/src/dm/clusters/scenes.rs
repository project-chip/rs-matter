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
//! # Implementation status
//!
//! - All 8 commands have entry points.
//! - The 6 **data-only** commands are fully implemented:
//!   `AddScene`, `ViewScene`, `RemoveScene`, `RemoveAllScenes`,
//!   `GetSceneMembership`, `CopyScene`.
//! - **`StoreScene`** is fully implemented: it reads the scene-able
//!   attributes of the registered clusters (OnOff + LevelControl —
//!   see [`SCENEABLE_CLUSTERS`]) on the host endpoint via
//!   `ctx.handler().read()` and stores the result as a wire-form
//!   `ExtensionFieldSetStructs` blob keyed by `(group, scene)`.
//! - **`RecallScene`** is fully implemented: it parses the stored
//!   `ExtensionFieldSetStructs` blob and re-applies each cluster's
//!   captured state by invoking the spec'd cluster command (OnOff:
//!   `On` / `Off`; LevelControl: `MoveToLevel`) via
//!   `ctx.handler().invoke()`. Apply is intentionally per-cluster (not
//!   a generic attribute write) because both spec'd scene-able
//!   attributes are read-only.
//! - **In-RAM storage only**: scenes are not persisted across reboots.
//! - The `SceneNames` feature is **disabled** by default; scene names
//!   sent by the controller are accepted on the wire but discarded.
//!
//! # Storage model
//!
//! Scenes are fabric-scoped (each fabric has its own scene table) and
//! per-endpoint (scenes on EP1 don't affect EP2). The state is a
//! single flat [`Vec`] of [`SceneEntry`] entries keyed by
//! `(fab_idx, endpoint_id, group_id, scene_id)`.
//!
//! The caller owns the [`ScenesState`] and shares it via reference
//! with one [`ScenesHandler`] per endpoint where the cluster is
//! exposed.
//!
//! # Async-trait shape note
//!
//! [`ClusterAsyncHandler`] methods that don't actually need to
//! `.await` anything (every one except `handle_store_scene`) are
//! written as
//! `fn foo(...) -> impl Future<...> { ready(self.foo(...)) }`
//! delegating to a plain `fn foo(...) -> Result<...>` helper. This
//! compiles to a much smaller image than `async fn` — no state-machine
//! generator, no closure. Matters on flash-constrained MCUs.
//! `handle_store_scene` and `handle_recall_scene` *do* await
//! (cross-cluster reads + invokes), so their wrappers are real
//! `async fn`s that call [`Self::store_scene`] / [`Self::recall_scene`].

use core::future::{ready, Future};
use core::num::NonZeroU8;

use crate::dm::{
    ArrayAttributeRead, AttrId, Cluster, ClusterId, Dataver, EndptId, HandlerContext,
    InvokeContext, ReadContext, SceneId,
};
use crate::error::{Error, ErrorCode};
use crate::persist::{KvBlobStore, Persist};
use crate::tlv::{
    FromTLV, Nullable, OptionalBuilder, TLVArray, TLVBuilder, TLVBuilderParent, TLVElement,
    TLVSequence, TLVTag, TLVWrite, TLVWriteParent, ToTLV, TLV,
};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::{Vec, WriteBuf};
use crate::utils::sync::blocking::Mutex;

pub use crate::dm::clusters::decl::scenes_management::*;
pub use crate::persist::SCENES_KEY;

/// IM status codes specific to the Scenes Management cluster (see
/// "Generic Usage Notes" in the Matter Application Cluster spec).
const SC_NOT_FOUND: u8 = 0x8B;
const SC_INSUFFICIENT_SPACE: u8 = 0x89;
/// IM-level `INVALID_COMMAND` (0x85). Returned by every group-aware
/// Scenes command when `GroupID != 0` is not present in the Groups
/// cluster's Group Table for `(fab_idx, endpoint_id)` — per Matter
/// Application Cluster spec §1.4.9 "Common per-command behavior".
const SC_INVALID_COMMAND: u8 = 0x85;
/// IM-level `CONSTRAINT_ERROR` (0x87). Returned by every Scenes
/// command that takes a `SceneID` when the value is `0xFF`, which the
/// spec reserves as invalid (valid range is `0x00 – 0xFE`).
const SC_CONSTRAINT_ERROR: u8 = 0x87;
/// Reserved (invalid) `SceneID` value per Matter App Cluster spec.
const RESERVED_SCENE_ID: SceneId = 0xFF;
/// Maximum legal `TransitionTime` value on `AddScene`, per Matter App
/// Cluster spec §1.4.7.1 "AddScene Command":
/// The maximum value SHALL be 60 000 000 (1000 minutes).
/// Anything larger MUST be rejected with `CONSTRAINT_ERROR`.
const MAX_TRANSITION_TIME_MS: u32 = 60_000_000;

/// Max length of the serialized `ExtensionFieldSetStructs` payload
/// carried on a single scene record. Per chip's notes a Color Control
/// scene is the largest realistic case at ~99 B; OnOff + LevelControl
/// scenes are ~16 B. `128` covers the realistic worst case for the
/// clusters Phase B.2 / C will register, with the cost paid per scene
/// (so `N * MAX_EXT_FIELDS_LEN` RAM total).
pub const MAX_EXT_FIELDS_LEN: usize = 128;

/// Per-cluster scene capture + apply trait.
///
/// Implemented **directly on the cluster's normal handler type** —
/// e.g. `impl SceneClusterHandler for OnOffHandler<'_, H, LH>`. The
/// same `&handler` value the application registers in the data-model
/// chain doubles as a scenes registry entry, so cross-cluster reads
/// and writes during `StoreScene` / `RecallScene` are direct typed
/// method calls on the handler — no IM-layer round-trip, no TLV
/// serde, no recursion-limit games.
///
/// The application composes a tuple-recursive registry
/// (`(&on_off, (&level_control, ()))`, etc.) and passes it to
/// [`ScenesHandler::new`]; the blanket impl
/// `impl<T: SceneClusterHandler + ?Sized> SceneClusterHandler for &T`
/// makes the references flow through transparently.
///
/// Back-direction notifications (a scenable attribute mutated, so
/// `SceneValid` may need to flip) flow through
/// [`SceneInvalidator`], implemented by [`ScenesState`].
pub trait SceneClusterHandler {
    /// The Matter cluster ID this impl handles. Used by [`SceneClusters`]
    /// to route apply dispatch.
    const CLUSTER_ID: ClusterId;

    /// Endpoint this handler instance is installed on. The Scenes
    /// handler uses this to skip clusters that don't live on the
    /// `StoreScene` / `RecallScene` target endpoint.
    fn endpoint_id(&self) -> EndptId;

    /// Return `true` if `attribute_id` is a scenable attribute of this
    /// cluster per the Matter Application Cluster spec. Walked by
    /// [`SceneClusters::check_scenable`] during `AddScene` to reject
    /// `ExtensionFieldSetStructs` referencing non-scenable attributes
    /// (the spec requires `INVALID_COMMAND` in that case;
    /// `Test_TC_S_2_2` step 8g exercises it).
    ///
    /// Default impl rejects every attribute — concrete cluster
    /// handlers MUST override.
    fn is_scenable_attribute(_attribute_id: AttrId) -> bool {
        false
    }

    /// Emit zero-or-more `AttributeValuePairStruct` elements for this
    /// cluster's scenable state into `avp_array`, reading directly
    /// from the handler's internal state (no IM round-trip). Returns
    /// the (advanced) builder so the caller can close the array.
    ///
    /// Synchronous — internal state reads don't block. Use
    /// [`AttributeValuePairStructArrayBuilder::push_u8`] /
    /// [`AttributeValuePairStructArrayBuilder::push_u16`] / etc. for
    /// a one-line per-attribute API.
    fn capture<P: TLVBuilderParent>(
        &self,
        avp_array: AttributeValuePairStructArrayBuilder<P>,
    ) -> Result<AttributeValuePairStructArrayBuilder<P>, Error>;

    /// Apply captured `avp_list` entries to the handler's internal
    /// state directly (e.g. by calling the same private helpers that
    /// the cluster's own command bodies use). `transition_time_ms` is
    /// the effective transition for this recall (either the
    /// `RecallScene` request override or the stored value).
    ///
    /// `ctx` is a [`HandlerContext`] — the same shape the cluster's
    /// own long-running `run()` task receives. It gives the impl
    /// access to `notify_attr_changed` (for subscribers) and
    /// `kv()` (for persisting state mutated by the recall), without
    /// exposing the IM-routed `ctx.handler()` recursion path that
    /// led to the trait's earlier `T: AsyncHandler` design problem
    /// — calling `ctx.handler()` from inside `apply` re-creates that
    /// recursion-limit pathology, so impls MUST NOT do that. Clusters
    /// whose state mutation runs on a long-running task
    /// (signal-driven OnOff / LevelControl) can ignore `ctx` entirely:
    /// the task carries its own context and fires its own
    /// `notify_attr_changed` when the mutation lands. Clusters that
    /// mutate state synchronously inside `apply` use `ctx` to notify
    /// subscribers and persist as needed.
    ///
    /// Async because some clusters (LevelControl) kick off transition
    /// tasks; sync-only impls can return [`core::future::ready`].
    fn apply<C: HandlerContext>(
        &self,
        ctx: &C,
        avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
        transition_time_ms: u32,
    ) -> impl Future<Output = Result<(), Error>>;
}

/// Lets the application pass `&on_off_handler` (which it also keeps
/// for the normal data-model handler chain) into the scenes registry
/// without moving it. The trait's associated const + static
/// `is_scenable_attribute` delegate cleanly through the reference.
impl<T: SceneClusterHandler + ?Sized> SceneClusterHandler for &T {
    const CLUSTER_ID: ClusterId = T::CLUSTER_ID;

    fn endpoint_id(&self) -> EndptId {
        T::endpoint_id(*self)
    }

    fn is_scenable_attribute(attribute_id: AttrId) -> bool {
        T::is_scenable_attribute(attribute_id)
    }

    fn capture<P: TLVBuilderParent>(
        &self,
        avp_array: AttributeValuePairStructArrayBuilder<P>,
    ) -> Result<AttributeValuePairStructArrayBuilder<P>, Error> {
        T::capture(*self, avp_array)
    }

    async fn apply<C: HandlerContext>(
        &self,
        ctx: &C,
        avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
        transition_time_ms: u32,
    ) -> Result<(), Error> {
        T::apply(*self, ctx, avp_list, transition_time_ms).await
    }
}

/// A tuple-recursive composition of [`SceneClusterHandler`]s, mirroring
/// the convention used by [`crate::dm::ChainedHandler`].
///
/// Terminated by `()`; one cluster registers as `(impl, ())`; multiple
/// register as `(a, (b, (c, ())))`. The macro-free spelling is
/// intentionally verbose for now — a `scene_clusters!` macro can be
/// layered on later.
pub trait SceneClusters {
    /// Walk the registry, emitting one `ExtensionFieldSetStruct` per
    /// cluster whose handler reports `endpoint_id() == endpoint_id`.
    ///
    /// `parent` is a raw [`TLVBuilderParent`] (e.g. wrapping a
    /// [`crate::utils::storage::WriteBuf`] over the destination
    /// buffer) — *not* an `ExtensionFieldSetStructArrayBuilder`. Each
    /// cluster's EFS struct is emitted directly into the parent
    /// (`start_struct(Anonymous) … end_container`), with no outer
    /// `start_array` byte written. The caller is responsible for
    /// writing the trailing `0x18` array terminator after this
    /// returns. This keeps the captured wire form aligned with
    /// [`SceneEntry::extension_fields`]'s "contents + 0x18" storage
    /// shape without needing an extra `+ 1` byte to absorb a leading
    /// control byte.
    fn capture<P: TLVBuilderParent>(&self, endpoint_id: EndptId, parent: P) -> Result<P, Error>;

    /// Walk the registry looking for `cluster_id`. Returns:
    ///
    /// - `Some(true)`  — `cluster_id` is registered and
    ///   `attribute_id` is scenable on that cluster (per
    ///   [`SceneClusterHandler::is_scenable_attribute`]).
    /// - `Some(false)` — `cluster_id` is registered but
    ///   `attribute_id` is **not** scenable (`AddScene` MUST
    ///   reject with `INVALID_COMMAND`).
    /// - `None`        — `cluster_id` is not registered with the
    ///   Scenes handler. `AddScene` treats this as lenient (store
    ///   the bytes; `RecallScene` will silently skip them on
    ///   replay), matching chip's behaviour on a firmware
    ///   downgrade that drops a previously-scenable cluster.
    fn check_scenable(&self, cluster_id: ClusterId, attribute_id: AttrId) -> Option<bool>;

    /// Find the registered cluster matching `(cluster_id, endpoint_id)`
    /// and let it apply `avp_list`. Returns `Ok(true)` if a cluster
    /// handled it, `Ok(false)` if no registered cluster matches (the
    /// entry is silently skipped, matching chip's behavior).
    fn apply<C: HandlerContext>(
        &self,
        ctx: &C,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
        transition_time_ms: u32,
    ) -> impl Future<Output = Result<bool, Error>>;
}

impl SceneClusters for () {
    fn capture<P: TLVBuilderParent>(&self, _endpoint_id: EndptId, parent: P) -> Result<P, Error> {
        Ok(parent)
    }

    fn check_scenable(&self, _cluster_id: ClusterId, _attribute_id: AttrId) -> Option<bool> {
        None
    }

    fn apply<C: HandlerContext>(
        &self,
        _ctx: &C,
        _endpoint_id: EndptId,
        _cluster_id: ClusterId,
        _avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
        _transition_time_ms: u32,
    ) -> impl Future<Output = Result<bool, Error>> {
        ready(Ok(false))
    }
}

impl<H, T> SceneClusters for (H, T)
where
    H: SceneClusterHandler,
    T: SceneClusters,
{
    fn check_scenable(&self, cluster_id: ClusterId, attribute_id: AttrId) -> Option<bool> {
        if cluster_id == H::CLUSTER_ID {
            Some(H::is_scenable_attribute(attribute_id))
        } else {
            self.1.check_scenable(cluster_id, attribute_id)
        }
    }

    fn capture<P: TLVBuilderParent>(&self, endpoint_id: EndptId, parent: P) -> Result<P, Error> {
        let parent = if self.0.endpoint_id() == endpoint_id {
            // Open this cluster's ExtensionFieldSetStruct directly on
            // the parent (no outer array wrapper), hand the inner
            // AVP-array builder to the cluster impl, then close both
            // containers and continue down the chain.
            let efs = ExtensionFieldSetStructBuilder::new(parent, &TLVTag::Anonymous)?;
            let efs = efs.cluster_id(H::CLUSTER_ID)?;
            let avp_array = efs.attribute_value_list()?;
            let avp_array = self.0.capture(avp_array)?;
            let efs = avp_array.end()?;
            efs.end()?
        } else {
            parent
        };
        self.1.capture(endpoint_id, parent)
    }

    async fn apply<C: HandlerContext>(
        &self,
        ctx: &C,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
        transition_time_ms: u32,
    ) -> Result<bool, Error> {
        if H::CLUSTER_ID == cluster_id && self.0.endpoint_id() == endpoint_id {
            self.0.apply(ctx, avp_list, transition_time_ms).await?;
            Ok(true)
        } else {
            self.1
                .apply(ctx, endpoint_id, cluster_id, avp_list, transition_time_ms)
                .await
        }
    }
}

// `SceneContext` and `CaptureReply` (the IM-routed cross-cluster
// read/invoke shim) were removed in favour of direct method calls on
// the typed cluster handler — see the module-level doc comment.

// ---------------------------------------------------------------------
// Builder ergonomics — push_u8 / push_u16 etc. on the codegen'd AVP
// array builder so capture impls read as
// `avp_array.push_u8(attr_id, v)?` instead of carrying an external
// helper. Inherent impls are legal cross-module because the type is in
// the same crate (rs-matter), generated from the Scenes IDL.
// ---------------------------------------------------------------------

impl<P> AttributeValuePairStructArrayBuilder<P>
where
    P: TLVBuilderParent,
{
    /// Push one `AttributeValuePairStruct { attributeID,
    /// valueUnsigned8 }` element. Wraps the codegen builder's 9-state
    /// push chain so callers don't have to spell out 8
    /// `value_*(None)?` hops manually.
    pub fn push_u8(self, attr_id: AttrId, value: u8) -> Result<Self, Error> {
        self.push()?
            .attribute_id(attr_id)?
            .value_unsigned_8(Some(value))?
            .value_signed_8(None)?
            .value_unsigned_16(None)?
            .value_signed_16(None)?
            .value_unsigned_32(None)?
            .value_signed_32(None)?
            .value_unsigned_64(None)?
            .value_signed_64(None)?
            .end()
    }

    /// Push one `AttributeValuePairStruct { attributeID,
    /// valueUnsigned16 }` element.
    pub fn push_u16(self, attr_id: AttrId, value: u16) -> Result<Self, Error> {
        self.push()?
            .attribute_id(attr_id)?
            .value_unsigned_8(None)?
            .value_signed_8(None)?
            .value_unsigned_16(Some(value))?
            .value_signed_16(None)?
            .value_unsigned_32(None)?
            .value_signed_32(None)?
            .value_unsigned_64(None)?
            .value_signed_64(None)?
            .end()
    }
}

/// One scene record. Stores both the metadata (group/scene/transition)
/// and the wire-form `ExtensionFieldSetStructs` blob captured on
/// `AddScene` / `StoreScene` and replayed on `ViewScene` /
/// `RecallScene` / `CopyScene`.
///
/// `M` is the per-scene blob capacity (see [`MAX_EXT_FIELDS_LEN`] for
/// the default rationale).
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SceneEntry<const M: usize = MAX_EXT_FIELDS_LEN> {
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
    /// Serialized `ExtensionFieldSetStructs` array payload — what the
    /// controller passed on `AddScene` (or what `StoreScene`
    /// captured). Stored as the array container's *value* bytes (the
    /// TLV element payload between the start-array control byte and
    /// the end-of-container terminator; see
    /// [`crate::tlv::TLVElement::raw_value`]). On `ViewScene` we
    /// splice it back out at the response tag. Empty ⇒ no captured
    /// fields (echoed as absent).
    extension_fields: Vec<u8, M>,
}

impl<const M: usize> SceneEntry<M> {
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

    /// In-place initializer used by [`super::ScenesHandler::upsert_scene`] to
    /// stamp a fresh row directly into the slot inside the scene
    /// table — avoiding the `M`-byte stack copy that
    /// `extension_fields: Vec<u8, M>` would otherwise incur if
    /// `SceneEntry` were constructed by value first.
    ///
    /// The `extension_fields` Vec is initialized empty; the caller of
    /// [`super::ScenesHandler::upsert_scene`] supplies a closure that
    /// fills it in place (typically by `extend_from_slice` from a
    /// caller-owned slice).
    fn init(
        fab_idx: NonZeroU8,
        endpoint_id: EndptId,
        group_id: u16,
        scene_id: SceneId,
        transition_time: u32,
    ) -> impl Init<Self> {
        init!(Self {
            fab_idx,
            endpoint_id,
            group_id,
            scene_id,
            transition_time,
            extension_fields <- Vec::init(),
        })
    }
}

/// Per-fabric "last recalled scene" pointer feeding
/// `FabricSceneInfo.CurrentScene` / `CurrentGroup` / `SceneValid`.
///
/// The entry persists once a fabric has interacted with scenes (so
/// `FabricSceneInfo` keeps emitting a row for it even after its only
/// scene is removed) — `valid` carries `SceneValid` directly.
/// `TestScenesMultiFabric` step 36 asserts this lifecycle: TH2 removes
/// its only scene and then reads `FabricSceneInfo`, expecting
/// `SceneCount=0` with `CurrentScene`/`CurrentGroup` preserved and
/// `SceneValid=false`.
///
/// `endpoint_id` records the endpoint the scene was recalled on so the
/// [`SceneInvalidator`] callback (fired by scenable cluster handlers
/// when their state changes) can flip `valid → false` per-endpoint
/// without touching other endpoints' recalled scenes.
///
/// `FromTLV` / `ToTLV` are derived (the type has no const generics,
/// unlike [`SceneEntry`]) — the persisted shape is a struct with
/// context-tagged fields auto-numbered 0..4 in source order.
#[derive(Debug, Clone, Copy, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct CurrentScene {
    fab_idx: NonZeroU8,
    endpoint_id: EndptId,
    group_id: u16,
    scene_id: SceneId,
    valid: bool,
}

/// All mutable Scenes state, held behind a single mutex via
/// [`ScenesState`]. Grouped so the cluster handler takes exactly one
/// lock per operation — mirrors the `OnOffState` / `Mutex<RefCell<…>>`
/// shape used elsewhere in `rs-matter`.
struct ScenesStateInner<const N: usize, const M: usize = MAX_EXT_FIELDS_LEN> {
    /// The scene table, keyed by `(fab_idx, endpoint_id, group_id, scene_id)`.
    table: Vec<SceneEntry<M>, N>,
    /// Bounded by `N` for storage symmetry; in practice one slot per
    /// fabric. Absent for a given `fab_idx` ⇒ `SceneValid = false`.
    current_per_fabric: Vec<CurrentScene, N>,
    /// Bookkeeping bump for the `FabricSceneInfo` reader.
    info_dataver: u32,
}

impl<const N: usize, const M: usize> ScenesStateInner<N, M> {
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

/// Caller-owned per-device Scenes state.
///
/// Const generics:
/// - `N` — scene-table capacity (rows across all fabrics + endpoints).
/// - `M` — per-scene `ExtensionFieldSetStructs` blob capacity in
///   bytes. Defaults to [`MAX_EXT_FIELDS_LEN`] (128). Bump it when
///   you wire ColorControl into a multi-feature deployment whose
///   captured EFS exceeds the default budget. Total static RAM for
///   the scene table is `N * (M + small overhead)`.
///
/// Shared across all endpoints that expose the cluster. Internally
/// a single [`Mutex`] over a [`RefCell`] — every handler operation
/// takes one lock and mutates the inner table directly.
pub struct ScenesState<const N: usize, const M: usize = MAX_EXT_FIELDS_LEN> {
    inner: Mutex<RefCell<ScenesStateInner<N, M>>>,
}

impl<const N: usize, const M: usize> ScenesState<N, M> {
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
        F: FnOnce(&mut ScenesStateInner<N, M>) -> R,
    {
        self.inner.lock(|cell| {
            let mut inner = cell.borrow_mut();
            f(&mut inner)
        })
    }
}

impl<const N: usize, const M: usize> Default for ScenesState<N, M> {
    fn default() -> Self {
        Self::new()
    }
}

/// Notified by scenable cluster handlers (OnOff, LevelControl,
/// ColorControl, …) when a scenable attribute on an endpoint changes
/// out from under a previously-recalled scene. Per Matter App Cluster
/// spec §1.4.6.5, that mutation invalidates `SceneValid` for every
/// fabric whose recalled scene lives on that endpoint.
///
/// `ScenesState` implements this trait directly. Wire the
/// implementation into a scene-able cluster handler at construction
/// (e.g. `OnOffHandler::with_scene_invalidator(&scenes_state)`); the
/// handler then calls
/// [`Self::scenable_attribute_changed`] at every internal mutation
/// site for the cluster's scenable attribute set.
///
/// Implementations MUST be cheap and re-entrant — they run inline on
/// the command-handler path.
pub trait SceneInvalidator {
    /// Flip `SceneValid → false` for every recalled scene that lives
    /// on `endpoint_id`, across all fabrics. No-op when no fabric has
    /// a scene recalled on that endpoint.
    fn scenable_attribute_changed(&self, endpoint_id: EndptId);
}

impl<T: SceneInvalidator + ?Sized> SceneInvalidator for &T {
    fn scenable_attribute_changed(&self, endpoint_id: EndptId) {
        (**self).scenable_attribute_changed(endpoint_id);
    }
}

impl<const N: usize, const M: usize> SceneInvalidator for ScenesState<N, M> {
    fn scenable_attribute_changed(&self, endpoint_id: EndptId) {
        self.with(|inner| {
            let mut bumped = false;
            for c in inner.current_per_fabric.iter_mut() {
                if c.valid && c.endpoint_id == endpoint_id {
                    c.valid = false;
                    bumped = true;
                }
            }
            if bumped {
                inner.bump_info_dataver();
            }
        });
    }
}

// ---------------------------------------------------------------------
// TLV round-trip used by the persistence layer.
//
// The whole [`ScenesStateInner`] is persisted as a single TLV struct
// under [`SCENES_KEY`] — the cross-fabric scene table plus the
// per-fabric `CurrentScene` bookkeeping. `info_dataver` is *not*
// persisted: the public `Dataver` on the handler is re-randomized at
// boot anyway, so any client cache will already see a new dataver and
// re-fetch.
//
// Hand-rolled rather than `#[derive(FromTLV, ToTLV)]` because the inner
// types are const-generic and the macro doesn't yet support that
// (same reason `EndpointLabels<N>` in `user_label.rs` is hand-rolled).
// The persisted wire shape is private to this module; it only needs to
// round-trip between successive runs of the same firmware.

impl<const M: usize> ToTLV for SceneEntry<M> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.start_struct(tag)?;
        self.fab_idx.to_tlv(&TLVTag::Context(0), &mut tw)?;
        self.endpoint_id.to_tlv(&TLVTag::Context(1), &mut tw)?;
        self.group_id.to_tlv(&TLVTag::Context(2), &mut tw)?;
        self.scene_id.to_tlv(&TLVTag::Context(3), &mut tw)?;
        self.transition_time.to_tlv(&TLVTag::Context(4), &mut tw)?;
        // The captured EFS bytes go on the wire as a single octet
        // string, rather than as an array-of-u8 (which is what the
        // blanket `Vec<u8, M>: ToTLV` would emit).
        tw.str(&TLVTag::Context(5), &self.extension_fields)?;
        tw.end_container()
    }

    fn tlv_iter(&self, _tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        // Only `Persist::store_tlv` exercises persistence and it goes
        // through `to_tlv` above. Leave `tlv_iter` empty to satisfy the
        // trait bound without dragging extra machinery in.
        core::iter::empty()
    }
}

impl<'a, const M: usize> FromTLV<'a> for SceneEntry<M> {
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        let s = element.structure()?;
        let mut extension_fields = Vec::<u8, M>::new();
        extension_fields
            .extend_from_slice(s.ctx(5)?.str()?)
            .map_err(|_| ErrorCode::NoSpace)?;
        Ok(Self {
            fab_idx: NonZeroU8::from_tlv(&s.ctx(0)?)?,
            endpoint_id: EndptId::from_tlv(&s.ctx(1)?)?,
            group_id: u16::from_tlv(&s.ctx(2)?)?,
            scene_id: SceneId::from_tlv(&s.ctx(3)?)?,
            transition_time: u32::from_tlv(&s.ctx(4)?)?,
            extension_fields,
        })
    }
}

impl<const N: usize, const M: usize> ToTLV for ScenesStateInner<N, M> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.start_struct(tag)?;
        self.table.to_tlv(&TLVTag::Context(0), &mut tw)?;
        self.current_per_fabric
            .to_tlv(&TLVTag::Context(1), &mut tw)?;
        tw.end_container()
    }

    fn tlv_iter(&self, _tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        core::iter::empty()
    }
}

impl<'a, const N: usize, const M: usize> FromTLV<'a> for ScenesStateInner<N, M> {
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        let s = element.structure()?;
        Ok(Self {
            table: Vec::<SceneEntry<M>, N>::from_tlv(&s.ctx(0)?)?,
            current_per_fabric: Vec::<CurrentScene, N>::from_tlv(&s.ctx(1)?)?,
            // Always boot at 0 — see the persistence note above.
            info_dataver: 0,
        })
    }
}

impl<const N: usize, const M: usize> ScenesState<N, M> {
    /// Re-hydrate the scene table and per-fabric `CurrentScene`
    /// bookkeeping from `store` under [`SCENES_KEY`]. Call once at
    /// application startup, before exposing the data model to
    /// commissioners, so subsequent `RecallScene` / `GetSceneMembership`
    /// commands see scenes that were stored before the last reboot.
    ///
    /// Missing key (first boot, or persistence cleared) is not an
    /// error — the registry stays empty.
    pub async fn load_persist<S: KvBlobStore>(
        &self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let Some(data) = store.load(SCENES_KEY, buf)? else {
            // No prior persistence — reset to empty so re-calling
            // `load_persist` after a `remove` of the key behaves
            // deterministically.
            self.with(|inner| {
                inner.table.clear();
                inner.current_per_fabric.clear();
            });
            return Ok(());
        };

        let loaded = ScenesStateInner::<N, M>::from_tlv(&TLVElement::new(data))?;
        let entries = loaded.table.len();

        self.with(|inner| {
            inner.table = loaded.table;
            inner.current_per_fabric = loaded.current_per_fabric;
            inner.bump_info_dataver();
        });

        info!("Loaded Scenes state from storage ({} entries)", entries);

        Ok(())
    }

    /// Serialise the current state to `ctx.kv()` under [`SCENES_KEY`].
    /// Called from every mutating handler path after the in-memory
    /// change is committed.
    fn store_persist<C: HandlerContext>(&self, ctx: &C) -> Result<(), Error> {
        let mut persist = Persist::new(ctx.kv());

        self.inner.lock(|cell| {
            let inner = cell.borrow();
            persist.store_tlv(SCENES_KEY, &*inner)
        })?;

        persist.run()
    }
}

/// Scenes Management cluster handler.
///
/// Generic over a tuple-recursive registry `R: SceneClusters` that
/// names which application-level clusters participate in scene
/// capture / recall on this device. Construct as:
///
/// ```ignore
/// use rs_matter::dm::clusters::app::on_off::OnOffSceneClusterHandler;
/// use rs_matter::dm::clusters::app::level_control::LevelControlSceneClusterHandler;
///
/// let scenes = ScenesHandler::new(
///     dataver,
///     &scenes_state,
///     (OnOffSceneClusterHandler, (LevelControlSceneClusterHandler, ())),
/// );
/// ```
///
/// The default `R = ()` constructs a Scenes handler with **no**
/// scene-able clusters — useful for tests / certification of the
/// table-management commands (Add/View/Remove/RemoveAll/GetSceneMembership/
/// CopyScene) in isolation. `M` mirrors the same parameter on
/// [`ScenesState`] (per-scene blob capacity, defaults to
/// [`MAX_EXT_FIELDS_LEN`]).
pub struct ScenesHandler<'a, const N: usize, R = (), const M: usize = MAX_EXT_FIELDS_LEN>
where
    R: SceneClusters,
{
    dataver: Dataver,
    state: &'a ScenesState<N, M>,
    clusters: R,
}

impl<'a, const N: usize, R, const M: usize> ScenesHandler<'a, N, R, M>
where
    R: SceneClusters,
{
    pub const fn new(dataver: Dataver, state: &'a ScenesState<N, M>, clusters: R) -> Self {
        Self {
            dataver,
            state,
            clusters,
        }
    }

    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }

    fn fab_idx<C: InvokeContext>(ctx: &C) -> Result<NonZeroU8, Error> {
        ctx.exchange().accessor()?.fab_idx()
    }

    /// Per-fabric remaining-capacity estimate used by both
    /// `GetSceneMembership::Capacity` and
    /// `FabricSceneInfo::RemainingCapacity`. Per chip's reference
    /// implementation (and the `Test_TC_S_*` certification suites),
    /// the formula is **`(N - 1) / 2 − scenes_in_this_fabric`**:
    /// `N - 1` slack reserves one row for inter-fabric arbitration,
    /// `/ 2` splits the remaining budget evenly across the
    /// (typically two) fabrics the spec expects to share the table.
    ///
    /// Result is then clamped by the *total free slots* across all
    /// fabrics — once fab A and B have consumed their shares, fab C's
    /// remaining must drop below its `(N-1)/2` allotment as the global
    /// budget shrinks. `TestScenesMaxCapacity` step that asserts
    /// `RemainingCapacity == 1` after fabs 1+2 fill 14 of 16 slots
    /// catches the unclamped version. Final value is clamped to
    /// `0xFF` to fit the u8 wire field.
    fn remaining_capacity_for_fab(inner: &ScenesStateInner<N, M>, fab_idx: NonZeroU8) -> u8 {
        let per_fab_budget = N.saturating_sub(1) / 2;
        let used = inner.table.iter().filter(|e| e.fab_idx == fab_idx).count();
        let per_fab_remaining = per_fab_budget.saturating_sub(used);
        let global_remaining = N.saturating_sub(inner.table.len());
        per_fab_remaining.min(global_remaining).min(0xFF) as u8
    }

    /// Check whether `group_id` is present in the Groups cluster's
    /// Group Table for `(fab_idx, endpoint_id)`. Every group-aware
    /// Scenes command must reject with `SC_INVALID_COMMAND` when this
    /// returns `false`. `group_id == 0` is treated as "always valid"
    /// matching the spec's special handling of the reserved no-group
    /// ID.
    fn group_in_table<C: InvokeContext>(
        ctx: &C,
        fab_idx: NonZeroU8,
        endpoint_id: EndptId,
        group_id: u16,
    ) -> Result<bool, Error> {
        if group_id == 0 {
            return Ok(true);
        }
        ctx.exchange().with_state(|state| {
            let fabric = state.fabrics.fabric(fab_idx)?;
            Ok(fabric
                .groups()
                .get(group_id)
                .map(|g| g.endpoints.contains(&endpoint_id))
                .unwrap_or(false))
        })
    }

    /// Stamp `(endpoint, group, scene)` as the current recalled scene
    /// for this fabric with `SceneValid = true`. Bumps
    /// `FabricSceneInfo` dataver. Operates on already-locked inner
    /// state. The `endpoint_id` lets the [`SceneInvalidator`] flip
    /// `valid → false` per-endpoint when scenable attributes change
    /// on that endpoint (see `TestScenesFabricSceneInfo` step 25).
    fn remember_current(
        inner: &mut ScenesStateInner<N, M>,
        fab_idx: NonZeroU8,
        endpoint_id: EndptId,
        group_id: u16,
        scene_id: SceneId,
    ) {
        if let Some(slot) = inner
            .current_per_fabric
            .iter_mut()
            .find(|c| c.fab_idx == fab_idx)
        {
            slot.endpoint_id = endpoint_id;
            slot.group_id = group_id;
            slot.scene_id = scene_id;
            slot.valid = true;
        } else {
            // Best-effort push; if the slab is full we silently stop
            // tracking CurrentScene for this fabric (the spec permits
            // SceneValid=false in such cases).
            let _ = inner.current_per_fabric.push(CurrentScene {
                fab_idx,
                endpoint_id,
                group_id,
                scene_id,
                valid: true,
            });
        }
        inner.bump_info_dataver();
    }

    /// Drop the recalled-scene tracker for `fab_idx` **only** when its
    /// stored `(group_id, scene_id)` matches the one passed in — i.e.
    /// when the operation that just happened (`AddScene` /
    /// `StoreScene` / `RemoveScene` / `CopyScene` single-target case)
    /// actually targeted the currently-recalled scene. Other scenes
    /// changing leaves `SceneValid` alone, per Matter App Cluster
    /// spec §1.4.6.5:
    /// > Successful `CopyScene` or `AddScene` operations SHALL
    /// > preserve the `SceneValid` attribute when the affected scene
    /// > is not the currently recalled scene.
    ///
    /// Operates on already-locked inner state.
    fn invalidate_current_if_match_scene(
        inner: &mut ScenesStateInner<N, M>,
        fab_idx: NonZeroU8,
        group_id: u16,
        scene_id: SceneId,
    ) {
        let mut bumped = false;
        for c in inner.current_per_fabric.iter_mut() {
            if c.valid && c.fab_idx == fab_idx && c.group_id == group_id && c.scene_id == scene_id {
                c.valid = false;
                bumped = true;
            }
        }
        if bumped {
            inner.bump_info_dataver();
        }
    }

    /// Flip `SceneValid → false` for `fab_idx` when its remembered
    /// `group_id` matches — used by `RemoveAllScenes(group_id)` and
    /// the `COPY_ALL` mode of `CopyScene` (both of which can affect
    /// any scene in the group). The slot keeps `CurrentScene` /
    /// `CurrentGroup` populated for the next read so the fabric stays
    /// "known" in `FabricSceneInfo`.
    fn invalidate_current_if_match_group(
        inner: &mut ScenesStateInner<N, M>,
        fab_idx: NonZeroU8,
        group_id: u16,
    ) {
        let mut bumped = false;
        for c in inner.current_per_fabric.iter_mut() {
            if c.valid && c.fab_idx == fab_idx && c.group_id == group_id {
                c.valid = false;
                bumped = true;
            }
        }
        if bumped {
            inner.bump_info_dataver();
        }
    }

    /// Internal copy helper — runs against an already-locked
    /// [`ScenesStateInner`]. Returns the IM status code (0 on success).
    ///
    /// In-place index-walk: no scratch buffer. `Vec::push`
    /// always appends at the end, so an upsert that has to push a new
    /// destination row lands at an index strictly greater than the
    /// current source index — earlier-index iteration stays valid.
    /// Pushed rows live in `group_to`, never match the `group_from`
    /// filter, so the loop converges. Worst case is O(N²) on the
    /// inner `position` lookup, which is fine for the small `N` this
    /// cluster carries.
    #[allow(clippy::too_many_arguments)]
    fn copy_scenes_inner(
        inner: &mut ScenesStateInner<N, M>,
        fab_idx: NonZeroU8,
        endpoint_id: EndptId,
        group_from: u16,
        scene_from: SceneId,
        group_to: u16,
        scene_to: SceneId,
        copy_all: bool,
    ) -> u8 {
        // Per-fab capacity gate up front: when the originating fabric
        // is already at its `(N-1)/2` allotment (or the global table
        // is full), the copy MUST be rejected with `INSUFFICIENT_SPACE`
        // even when the destination scene already exists and would
        // otherwise be a no-growth overwrite. Mirrors chip's reference
        // handler (`TestScenesMaxCapacity` step 56 asserts this: TH2
        // is at-cap and copies onto an already-existing destination,
        // but the test expects `0x89` regardless).
        if Self::remaining_capacity_for_fab(inner, fab_idx) == 0 {
            return SC_INSUFFICIENT_SPACE;
        }

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
                // Copy the scalars + clone the extension-fields blob
                // out so we can re-borrow the table mutably for the
                // upsert. The clone is a `MAX_EXT_FIELDS_LEN`-sized
                // stack value (~128 B), released after each iteration.
                let src_scene_id = src.scene_id;
                let src_transition_time = src.transition_time;
                let src_extension_fields = src.extension_fields.clone();
                let target_scene_id = if copy_all { src_scene_id } else { scene_to };

                // Upsert into (fab, ep, group_to, target_scene_id).
                if let Some(pos) = inner
                    .table
                    .iter()
                    .position(|e| e.matches(fab_idx, endpoint_id, group_to, target_scene_id))
                {
                    inner.table[pos].transition_time = src_transition_time;
                    inner.table[pos].extension_fields = src_extension_fields;
                } else {
                    if Self::remaining_capacity_for_fab(inner, fab_idx) == 0 {
                        // Reject when the originating fabric
                        // has reached its per-fab budget ((N-1)/2 entries.
                        return SC_INSUFFICIENT_SPACE;
                    }

                    if inner
                        .table
                        .push(SceneEntry {
                            fab_idx,
                            endpoint_id,
                            group_id: group_to,
                            scene_id: target_scene_id,
                            transition_time: src_transition_time,
                            extension_fields: src_extension_fields,
                        })
                        .is_err()
                    {
                        return SC_INSUFFICIENT_SPACE;
                    }
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

        // Only invalidate `CurrentScene` if this copy actually touched
        // the currently-recalled scene. Single-target mode targets
        // exactly `(group_to, scene_to)`; `COPY_ALL` mode targets the
        // whole destination group.
        if copy_all {
            Self::invalidate_current_if_match_group(inner, fab_idx, group_to);
        } else {
            Self::invalidate_current_if_match_scene(inner, fab_idx, group_to, scene_to);
        }
        0
    }

    // -----------------------------------------------------------------
    // Handler bodies.
    //
    // The trait-required methods in the `ClusterAsyncHandler` impl
    // below are tiny `fn -> impl Future` wrappers that delegate to
    // these via `ready(self.foo(...))`. Keeping the real logic
    // synchronous (a) lets us use `?` freely, (b) skips the
    // `async fn` state-machine codegen, and (c) avoids closure
    // captures in the wrappers. Three small wins that add up on
    // flash-constrained targets.
    //
    // `store_scene` is the one exception — it actually `.await`s
    // because it issues cross-cluster attribute reads through
    // `ctx.handler().read()`. The wrapper for that one just `.await`s
    // this method directly.
    // -----------------------------------------------------------------

    fn read_fabric_scene_info<P: TLVBuilderParent>(
        &self,
        ctx: &impl ReadContext,
        builder: ArrayAttributeRead<SceneInfoStructArrayBuilder<P>, SceneInfoStructBuilder<P>>,
    ) -> Result<P, Error> {
        let endpoint_id = ctx.attr().endpoint_id;
        let accessor_fab_idx = ctx.exchange().accessor()?.fab_idx()?;

        // Snapshot the relevant scalars under a single lock, then build
        // the response outside the lock.
        let (has_state, scene_count, cur_group, cur_scene, valid, remaining) =
            self.state.with(|inner| {
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
                // A fabric is "known" to the cluster — i.e. gets a
                // `FabricSceneInfo` row — once it owns at least one
                // scene OR has ever recalled one. `current_per_fabric`
                // entries persist past invalidation (carrying
                // `valid=false`) so the row stays present after the
                // last scene is removed (`TestScenesMultiFabric`
                // step 36).
                let has_state = count > 0 || current.is_some();
                // When a row IS emitted, `CurrentScene` /
                // `CurrentGroup` are always populated — set to 0 when
                // the fabric has never recalled a scene (i.e. no
                // `current` slot at all).
                let (g, s, v) = match current {
                    Some(c) => (Some(c.group_id), Some(c.scene_id), c.valid),
                    None => (Some(0u16), Some(0u8), false),
                };
                let rem = Self::remaining_capacity_for_fab(inner, accessor_fab_idx);
                (has_state, count.min(0xFF) as u8, g, s, v, rem)
            });

        match builder {
            ArrayAttributeRead::ReadAll(arr) => {
                if !has_state {
                    return arr.end();
                }

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

    fn add_scene<P: TLVBuilderParent>(
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

        // Spec: `CONSTRAINT_ERROR` for the reserved `SceneID = 0xFF`,
        // and also for `TransitionTime` exceeding the spec maximum
        // (`Test_TC_S_2_2` steps 8d/8e). Both are checked before the
        // group-table existence check so a bad request shape is
        // rejected even if the target group is absent.
        if scene_id == RESERVED_SCENE_ID || transition_time > MAX_TRANSITION_TIME_MS {
            return response
                .status(SC_CONSTRAINT_ERROR)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .end();
        }

        // Spec: `INVALID_COMMAND` when `group_id != 0` is absent from
        // the Groups cluster's Group Table for this endpoint.
        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_id)? {
            return response
                .status(SC_INVALID_COMMAND)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .end();
        }

        // Capture the `ExtensionFieldSetStructs` array payload from the
        // request — store the *value* bytes (contents-plus-terminator
        // of the array container), which is what `ViewScene` and
        // `CopyScene` will splice back out at the relevant response
        // tag. The codegen parser at context-tag 4 errors if the field
        // is missing; tolerate that by treating it as an empty blob.
        // Scene names are accepted on the wire (codegen parses them)
        // but not stored — see the SceneNames feature note in the
        // module docs.
        //
        // `upsert_scene`'s fill closure copies the request's raw EFS
        // bytes directly into the table slot's `extension_fields`
        // Vec, skipping an intermediate stack-allocated Vec.
        let efs_array_opt = request.extension_field_set_structs().ok();
        let raw = match efs_array_opt {
            Some(ref array) => array.element().raw_value()?,
            None => &[],
        };

        // Spec-conformance check: every AVP in the EFS payload whose
        // `cluster_id` is registered with this Scenes handler must
        // reference a scenable attribute on that cluster. Mixing in an
        // unscenable attribute MUST be rejected with `INVALID_COMMAND`
        // (Matter App Cluster spec §1.4.7.1; exercised by
        // `Test_TC_S_2_2` step 8g).
        //
        // For unregistered clusters we stay lenient (silently store the
        // bytes) — matches chip's behaviour on firmware downgrades
        // where a previously-scenable cluster is dropped from the
        // registry.
        if let Some(ref efs_array) = efs_array_opt {
            for efs in efs_array.iter() {
                let efs = efs?;
                let cid = efs.cluster_id()?;
                for avp in efs.attribute_value_list()?.iter() {
                    let avp = avp?;
                    let aid = avp.attribute_id()?;
                    if let Some(false) = self.clusters.check_scenable(cid, aid) {
                        return response
                            .status(SC_INVALID_COMMAND)?
                            .group_id(group_id)?
                            .scene_id(scene_id)?
                            .end();
                    }
                }
            }
        }

        // Insert / replace + invalidate SceneValid for this fabric — all
        // under a single lock. Per the `SceneValid` field rules,
        // adding/storing a scene that doesn't match the current
        // attribute state invalidates SceneValid.
        let status_code = self.state.with(|inner| {
            Self::upsert_scene(
                inner,
                fab_idx,
                endpoint_id,
                group_id,
                scene_id,
                transition_time,
                |ext_fields| {
                    if !raw.is_empty() {
                        ext_fields
                            .extend_from_slice(raw)
                            .map_err(|_| ErrorCode::NoSpace)?;
                    }
                    Ok(())
                },
            )
        })?;

        if status_code == 0 {
            self.state.store_persist(ctx)?;
            ctx.notify_own_attr_changed(AttributeId::FabricSceneInfo as _);
        }

        response
            .status(status_code)?
            .group_id(group_id)?
            .scene_id(scene_id)?
            .end()
    }

    /// Insert (or replace) one scene record and invalidate the fabric's
    /// `CurrentScene` slot. Returns `Ok(0)` on success, or
    /// `Ok(SC_INSUFFICIENT_SPACE)` when adding a *new* record would
    /// overflow `N`. Errors from `fill` propagate to the caller.
    ///
    /// `fill` is handed a `&mut` reference to the **in-place**
    /// `extension_fields` `Vec` inside the (newly-created or
    /// to-be-replaced) `SceneEntry`. This lets callers populate the
    /// blob directly into the table slot, skipping the 128 B stack
    /// `Vec` an intermediate by-value parameter would have required.
    ///
    /// Used by both `AddScene` (closure copies the controller-provided
    /// EFS payload) and `StoreScene` (closure copies the
    /// just-captured-from-attributes EFS payload).
    ///
    /// **Atomicity caveat**: on the replace-existing path, the slot's
    /// previous `extension_fields` are cleared *before* `fill` runs.
    /// If `fill` then errors, the slot is left with an empty blob.
    /// Spec doesn't mandate atomicity here, and in-tree callers' fill
    /// closures are `extend_from_slice` calls — all-or-nothing per
    /// [`Vec::extend_from_slice`] — so partial state never
    /// occurs in practice.
    fn upsert_scene<F>(
        inner: &mut ScenesStateInner<N, M>,
        fab_idx: NonZeroU8,
        endpoint_id: EndptId,
        group_id: u16,
        scene_id: SceneId,
        transition_time: u32,
        fill: F,
    ) -> Result<u8, Error>
    where
        F: FnOnce(&mut Vec<u8, M>) -> Result<(), Error>,
    {
        if let Some(pos) = inner
            .table
            .iter()
            .position(|e| e.matches(fab_idx, endpoint_id, group_id, scene_id))
        {
            // Mutate the existing slot in place.
            inner.table[pos].transition_time = transition_time;
            inner.table[pos].extension_fields.clear();
            fill(&mut inner.table[pos].extension_fields)?;
            Self::invalidate_current_if_match_scene(inner, fab_idx, group_id, scene_id);
            Ok(0)
        } else if inner.table.len() >= N {
            Ok(SC_INSUFFICIENT_SPACE)
        } else {
            // Push an empty entry in place, then let the closure fill
            // its `extension_fields` directly. `push_init_unchecked`
            // is safe (it only panics when full, and we just checked
            // `len < N`); the `Result<(), Infallible>` always
            // unwraps.
            inner
                .table
                .push_init_unchecked(SceneEntry::init(
                    fab_idx,
                    endpoint_id,
                    group_id,
                    scene_id,
                    transition_time,
                ))
                .unwrap();
            let pos = inner.table.len() - 1;
            if let Err(e) = fill(&mut inner.table[pos].extension_fields) {
                // Roll back the just-pushed entry so the table is
                // pre-call state.
                let _ = inner.table.pop();
                return Err(e);
            }
            Self::invalidate_current_if_match_scene(inner, fab_idx, group_id, scene_id);
            Ok(0)
        }
    }

    fn view_scene<P: TLVBuilderParent>(
        &self,
        ctx: &impl InvokeContext,
        request: &ViewSceneRequest<'_>,
        response: ViewSceneResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;
        let scene_id = request.scene_id()?;

        // Spec: `CONSTRAINT_ERROR` for the reserved `SceneID = 0xFF`.
        if scene_id == RESERVED_SCENE_ID {
            return response
                .status(SC_CONSTRAINT_ERROR)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .transition_time(None)?
                .scene_name(None)?
                .extension_field_set_structs()?
                .none()
                .end();
        }

        // Spec: `INVALID_COMMAND` when `group_id != 0` is absent from
        // the Groups cluster's Group Table for this endpoint.
        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_id)? {
            return response
                .status(SC_INVALID_COMMAND)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .transition_time(None)?
                .scene_name(None)?
                .extension_field_set_structs()?
                .none()
                .end();
        }

        // Build the response *inside* the lock so we can splice the
        // stored `extension_fields` blob (a `&[u8]` borrow into the
        // table) without cloning it onto the stack. The TLV builder
        // chain is purely synchronous (no `.await`), so holding the
        // mutex across the write is fine.
        //
        // Wire shape is (status, group_id, scene_id, optional
        // transition_time, optional scene_name, optional extension
        // fields). On NotFound all three optionals are absent; on
        // Success transition_time is populated, scene name is empty
        // (SceneNames feature disabled), and extension_field_set_structs
        // gets the stored blob (or absent if none was supplied).
        self.state.with(|inner| -> Result<P, Error> {
            let entry = inner
                .table
                .iter()
                .find(|e| e.matches(fab_idx, endpoint_id, group_id, scene_id));

            let Some(e) = entry else {
                return response
                    .status(SC_NOT_FOUND)?
                    .group_id(group_id)?
                    .scene_id(scene_id)?
                    .transition_time(None)?
                    .scene_name(None)?
                    .extension_field_set_structs()?
                    .none()
                    .end();
            };

            let opt = response
                .status(0)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .transition_time(Some(e.transition_time))?
                .scene_name(Some(""))?
                .extension_field_set_structs()?;

            Self::write_blob_or_none(opt, &e.extension_fields)?.end()
        })
    }

    /// Splice the stored extension-fields blob into the response at
    /// the optional field's tag (context 5 for both `ViewScene` and
    /// `AddScene` request — same tag number, different wire role).
    ///
    /// The blob is the array container's *value* bytes
    /// (contents-plus-terminator). We emit a fresh `start_array` at
    /// the destination tag and then write the stored bytes via
    /// `TLVWrite::write_raw_data`. Empty blob ⇒ skip the field
    /// entirely via `OptionalBuilder::none`.
    fn write_blob_or_none<P, Q>(mut opt: OptionalBuilder<P, Q>, blob: &[u8]) -> Result<P, Error>
    where
        P: TLVBuilderParent,
        Q: TLVBuilder<P>,
    {
        if !blob.is_empty() {
            // Tag is hard-coded as the spec field number for both
            // `ViewSceneResponse.ExtensionFieldSetStructs` and other
            // current call sites; if other tag positions reuse this
            // helper, take the tag as an explicit argument.
            let writer = opt.writer();
            writer.start_array(&TLVTag::Context(5))?;
            writer.write_raw_data(blob.iter().copied())?;
        }
        // `none()` returns the parent without further writes. When the
        // blob was non-empty we already emitted the field via the
        // writer; when empty we skip the field entirely. Either way
        // the surrounding response is well-formed.
        Ok(opt.none())
    }

    fn remove_scene<P: TLVBuilderParent>(
        &self,
        ctx: &impl InvokeContext,
        request: &RemoveSceneRequest<'_>,
        response: RemoveSceneResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;
        let scene_id = request.scene_id()?;

        // Spec: `CONSTRAINT_ERROR` for the reserved `SceneID = 0xFF`.
        if scene_id == RESERVED_SCENE_ID {
            return response
                .status(SC_CONSTRAINT_ERROR)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .end();
        }

        // Spec: `INVALID_COMMAND` when `group_id != 0` is absent from
        // the Groups cluster's Group Table for this endpoint.
        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_id)? {
            return response
                .status(SC_INVALID_COMMAND)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .end();
        }

        let status: u8 = self.state.with(|inner| {
            if let Some(pos) = inner
                .table
                .iter()
                .position(|e| e.matches(fab_idx, endpoint_id, group_id, scene_id))
            {
                inner.table.swap_remove(pos);
                Self::invalidate_current_if_match_scene(inner, fab_idx, group_id, scene_id);
                0
            } else {
                SC_NOT_FOUND
            }
        });

        if status == 0 {
            self.state.store_persist(ctx)?;
            ctx.notify_own_attr_changed(AttributeId::FabricSceneInfo as _);
        }

        response
            .status(status)?
            .group_id(group_id)?
            .scene_id(scene_id)?
            .end()
    }

    fn remove_all_scenes<P: TLVBuilderParent>(
        &self,
        ctx: &impl InvokeContext,
        request: &RemoveAllScenesRequest<'_>,
        response: RemoveAllScenesResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;

        // Spec: `INVALID_COMMAND` if `group_id != 0` is absent from
        // the Groups cluster's Group Table for this endpoint.
        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_id)? {
            return response
                .status(SC_INVALID_COMMAND)?
                .group_id(group_id)?
                .end();
        }

        let removed = self.state.with(|inner| {
            let before = inner.table.len();
            inner.table.retain(|e| {
                !(e.fab_idx == fab_idx && e.endpoint_id == endpoint_id && e.group_id == group_id)
            });
            let changed = before != inner.table.len();
            if changed {
                Self::invalidate_current_if_match_group(inner, fab_idx, group_id);
            }
            changed
        });

        if removed {
            self.state.store_persist(ctx)?;
            ctx.notify_own_attr_changed(AttributeId::FabricSceneInfo as _);
        }

        response.status(0)?.group_id(group_id)?.end()
    }

    /// `StoreScene` capture + commit.
    ///
    /// One of two [`ClusterAsyncHandler`] entry points that actually
    /// `.await` — it issues cross-cluster attribute reads through
    /// `ctx.handler().read()` for every registered
    /// [`SceneClusterHandler`] that is present on the host endpoint.
    /// The captured `ExtensionFieldSetStructs` blob is built up on a
    /// stack buffer (no per-attribute heap allocation, and no IO while
    /// the scene-table mutex is held). Only the final upsert briefly
    /// acquires the mutex.
    async fn store_scene<P: TLVBuilderParent>(
        &self,
        ctx: &impl InvokeContext,
        request: &StoreSceneRequest<'_>,
        response: StoreSceneResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;
        let scene_id = request.scene_id()?;

        // Spec: `CONSTRAINT_ERROR` for the reserved `SceneID = 0xFF`.
        if scene_id == RESERVED_SCENE_ID {
            return response
                .status(SC_CONSTRAINT_ERROR)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .end();
        }

        // Spec: `INVALID_COMMAND` when `group_id != 0` is absent from
        // the Groups cluster's Group Table for this endpoint.
        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_id)? {
            return response
                .status(SC_INVALID_COMMAND)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .end();
        }

        // Capture the EFS blob on the stack via the cluster registry.
        // Doing this *before* the mutex acquire keeps async IO
        // (`ctx.handler().read()`) out of the critical section.
        //
        // [`SceneClusters::capture`] writes EFS struct entries
        // directly into the parent (no outer `start_array` byte); we
        // append the trailing `0x18` ourselves. The result is exactly
        // the "contents + 0x18 terminator" shape that
        // [`SceneEntry::extension_fields`] stores — no leading byte
        // to strip, no `MAX_EXT_FIELDS_LEN + 1` slack needed.
        // Capture is now synchronous: each scene-aware cluster reads
        // its own internal state via its `SceneClusterHandler::capture`
        // impl. No IM-layer round-trip.
        let mut scratch = [0u8; M];
        let total_len = {
            let mut wb = WriteBuf::new(&mut scratch);
            let parent = TLVWriteParent::new("StoreScene EFS", &mut wb);
            let _ = self.clusters.capture(endpoint_id, parent)?;
            wb.end_container()?;
            wb.get_tail()
        };
        let stored_bytes = &scratch[..total_len];

        // StoreScene reuses AddScene's transition time when overwriting
        // an existing record (spec: "If a Scene Table entry with the
        // same Scene ID exists, all the fields of the entry shall be
        // updated…"). For a fresh record the transition time defaults
        // to 0 — the spec leaves the field implementation-defined for
        // StoreScene, and chip's reference handler does the same.
        let prior_tt = self.state.with(|inner| {
            inner
                .table
                .iter()
                .find(|e| e.matches(fab_idx, endpoint_id, group_id, scene_id))
                .map(|e| e.transition_time)
        });
        let transition_time = prior_tt.unwrap_or(0);

        let status_code = self.state.with(|inner| {
            let status = Self::upsert_scene(
                inner,
                fab_idx,
                endpoint_id,
                group_id,
                scene_id,
                transition_time,
                |ext_fields| {
                    if !stored_bytes.is_empty() {
                        ext_fields
                            .extend_from_slice(stored_bytes)
                            .map_err(|_| ErrorCode::NoSpace)?;
                    }
                    Ok(())
                },
            )?;
            // StoreScene captures the device's *current* attribute
            // state into the table, so the stored scene by definition
            // matches the current state. Per Matter App Cluster spec
            // §1.4.6.5 / chip's reference, that promotes
            // `(group, scene)` to the recalled scene with
            // `SceneValid=true` — `TestScenesMultiFabric` /
            // `TestScenesMaxCapacity` / `TestScenesFabricSceneInfo`
            // all assert this behaviour. `upsert_scene` may have just
            // flipped the slot invalid (when overwriting the previously
            // recalled entry); the `remember_current` below stamps it
            // back to valid with the freshly-stored ID.
            if status == 0 {
                Self::remember_current(inner, fab_idx, endpoint_id, group_id, scene_id);
            }
            Ok::<_, Error>(status)
        })?;

        if status_code == 0 {
            self.state.store_persist(ctx)?;
            ctx.notify_own_attr_changed(AttributeId::FabricSceneInfo as _);
        }

        response
            .status(status_code)?
            .group_id(group_id)?
            .scene_id(scene_id)?
            .end()
    }

    /// `RecallScene` parse + apply.
    ///
    /// Flow:
    /// 1. Look up the stored `(transition_time, ext_fields)` snapshot
    ///    under the mutex; release the mutex.
    /// 2. Walk the EFS blob and let the cluster registry apply each
    ///    `ExtensionFieldSetStruct` entry (see
    ///    [`SceneClusters::apply`]).
    /// 3. Only after apply succeeds, commit `CurrentScene` for this
    ///    fabric (acquiring the mutex again briefly).
    async fn recall_scene(
        &self,
        ctx: &impl InvokeContext,
        request: &RecallSceneRequest<'_>,
    ) -> Result<(), Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;
        let scene_id = request.scene_id()?;

        // `RecallScene` has no response struct (returns `()`), so the
        // status must be surfaced as an IM-level `CommandStatusIB.status`
        // — i.e. returned via `Err(ErrorCode::*)`. The
        // [`ErrorCode`] → [`IMStatusCode`] mapping in `im.rs` turns
        // these into the spec-mandated wire codes
        // (`ConstraintError = 0x87`, `InvalidCommand = 0x85`,
        // `NotFound = 0x8b`). Surfacing them via `set_cluster_status`
        // would produce `FAILURE` with a cluster-status side-channel,
        // which chip-tool's certification suites correctly reject
        // (see `Test_TC_S_2_2` step 4e).

        // Spec: `CONSTRAINT_ERROR` for the reserved `SceneID = 0xFF`.
        if scene_id == RESERVED_SCENE_ID {
            return Err(ErrorCode::ConstraintError.into());
        }

        // Spec: `INVALID_COMMAND` when `group_id != 0` is absent from
        // the Groups cluster's Group Table for this endpoint.
        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_id)? {
            return Err(ErrorCode::InvalidCommand.into());
        }

        // RecallScene's request carries an optional+nullable
        // transition-time override (ms). Present-and-non-null wins
        // over the stored record's transition time; otherwise fall
        // back to the stored value.
        let override_tt_ms: Option<u32> = request.transition_time()?.and_then(|n| n.into_option());

        // Copy the stored EFS blob into a stack buffer under the lock,
        // then drop the lock so the cross-cluster invokes below don't
        // run while it's held.
        //
        // The stored form is "ExtensionFieldSetStruct elements + 0x18
        // terminator" (i.e. what `TLVElement::array().raw_value()`
        // returns — see [`SceneEntry`] and `view_scene`). We iterate
        // it via [`TLVSequence`] rather than re-attaching the missing
        // `start_array(Anonymous)` byte: `TLVSequence` walks raw TLV
        // bytes directly and terminates cleanly on the trailing
        // `0x18`, so no framing buffer is needed.
        let mut blob = [0u8; M];
        let (blob_len, stored_tt_ms) = self.state.with(|inner| -> Result<_, Error> {
            let Some(e) = inner
                .table
                .iter()
                .find(|e| e.matches(fab_idx, endpoint_id, group_id, scene_id))
            else {
                return Ok((None, None));
            };
            let len = e.extension_fields.len();
            blob[..len].copy_from_slice(&e.extension_fields);
            Ok((Some(len), Some(e.transition_time)))
        })?;
        let (Some(blob_len), Some(stored_tt_ms)) = (blob_len, stored_tt_ms) else {
            // Spec: `NOT_FOUND` when no matching scene exists. Surfaced
            // at IM level (see the comment above on `ConstraintError`
            // / `InvalidCommand`).
            return Err(ErrorCode::NotFound.into());
        };

        let effective_tt_ms = override_tt_ms.unwrap_or(stored_tt_ms);

        for efs_element in TLVSequence(&blob[..blob_len]).iter() {
            let efs = ExtensionFieldSetStruct::new(efs_element?);
            let cluster_id = efs.cluster_id()?;
            let avp_list = efs.attribute_value_list()?;
            // `apply` returns `false` for unknown cluster IDs — match
            // chip's behaviour and silently skip them (the blob may
            // have been written by a previous firmware version with a
            // different scene-able cluster set).
            let _ = self
                .clusters
                .apply(ctx, endpoint_id, cluster_id, &avp_list, effective_tt_ms)
                .await?;
        }

        self.state
            .with(|inner| Self::remember_current(inner, fab_idx, endpoint_id, group_id, scene_id));

        self.state.store_persist(ctx)?;
        ctx.notify_own_attr_changed(AttributeId::FabricSceneInfo as _);
        Ok(())
    }

    fn get_scene_membership<P: TLVBuilderParent>(
        &self,
        ctx: &impl InvokeContext,
        request: &GetSceneMembershipRequest<'_>,
        response: GetSceneMembershipResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;

        // Spec: `INVALID_COMMAND` when `group_id != 0` isn't in the
        // Groups cluster's Group Table on this endpoint. Capacity is
        // reported as `null` in that case (per the
        // `Test_TC_S_2_2` spec table — `anyOf [fabricCapacity, 0xfe,
        // null]`, we pick `null`).
        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_id)? {
            return response
                .status(SC_INVALID_COMMAND)?
                .capacity(Nullable::none())?
                .group_id(group_id)?
                .scene_list()?
                .none()
                .end();
        }

        // Build the response directly inside the lock — the TLV
        // builder is purely synchronous (no `.await`), so holding the
        // lock for the write is cheap. This avoids snapshotting scene
        // IDs into a stack `Vec<SceneId, N>` (could be ~N bytes;
        // matters on small-stack MCUs).
        self.state.with(|inner| -> Result<P, Error> {
            let remaining = Self::remaining_capacity_for_fab(inner, fab_idx);

            let resp = response
                .status(0)?
                .capacity(Nullable::some(remaining))?
                .group_id(group_id)?;

            // The `SceneList` optional field is *always present* on
            // the success path — empty when the group has no scenes
            // on this device, populated otherwise. The chip-tool
            // certification suites (`Test_TC_S_2_3` step 1f) assert
            // the field exists rather than being omitted.
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

    fn copy_scene<P: TLVBuilderParent>(
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

        // Spec: `CONSTRAINT_ERROR` for the reserved `SceneID = 0xFF`
        // on either `scene_from` or `scene_to` — but only when the
        // single-scene mode actually uses them.
        if !copy_all && (scene_from == RESERVED_SCENE_ID || scene_to == RESERVED_SCENE_ID) {
            return response
                .status(SC_CONSTRAINT_ERROR)?
                .group_identifier_from(group_from)?
                .scene_identifier_from(scene_from)?
                .end();
        }

        // Spec: `INVALID_COMMAND` when EITHER `group_from` or
        // `group_to` (when non-zero) is absent from the Groups
        // cluster's Group Table for this endpoint.
        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_from)?
            || !Self::group_in_table(ctx, fab_idx, endpoint_id, group_to)?
        {
            return response
                .status(SC_INVALID_COMMAND)?
                .group_identifier_from(group_from)?
                .scene_identifier_from(scene_from)?
                .end();
        }

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
            self.state.store_persist(ctx)?;
            ctx.notify_own_attr_changed(AttributeId::FabricSceneInfo as _);
        }

        response
            .status(status)?
            .group_identifier_from(group_from)?
            .scene_identifier_from(scene_from)?
            .end()
    }
}

impl<const N: usize, R, const M: usize> ClusterAsyncHandler for ScenesHandler<'_, N, R, M>
where
    R: SceneClusters,
{
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
        ready(self.read_fabric_scene_info(&ctx, builder))
    }

    fn handle_add_scene<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: AddSceneRequest<'_>,
        response: AddSceneResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.add_scene(&ctx, &request, response))
    }

    fn handle_view_scene<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: ViewSceneRequest<'_>,
        response: ViewSceneResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.view_scene(&ctx, &request, response))
    }

    fn handle_remove_scene<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: RemoveSceneRequest<'_>,
        response: RemoveSceneResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.remove_scene(&ctx, &request, response))
    }

    fn handle_remove_all_scenes<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: RemoveAllScenesRequest<'_>,
        response: RemoveAllScenesResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.remove_all_scenes(&ctx, &request, response))
    }

    // `handle_store_scene` actually `.await`s (unlike the other
    // ClusterAsyncHandler methods on this handler) because StoreScene
    // captures the current values of scene-able attributes on other
    // clusters via `ctx.handler().read()` — see [`Self::store_scene`].
    async fn handle_store_scene<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: StoreSceneRequest<'_>,
        response: StoreSceneResponseBuilder<P>,
    ) -> Result<P, Error> {
        self.store_scene(&ctx, &request, response).await
    }

    // Like `handle_store_scene`, `handle_recall_scene` `.await`s —
    // apply is cluster-specific business logic that goes through
    // `ctx.handler().invoke()` (see [`Self::recall_scene`]).
    async fn handle_recall_scene(
        &self,
        ctx: impl InvokeContext,
        request: RecallSceneRequest<'_>,
    ) -> Result<(), Error> {
        self.recall_scene(&ctx, &request).await
    }

    fn handle_get_scene_membership<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: GetSceneMembershipRequest<'_>,
        response: GetSceneMembershipResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.get_scene_membership(&ctx, &request, response))
    }

    fn handle_copy_scene<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: CopySceneRequest<'_>,
        response: CopySceneResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        ready(self.copy_scene(&ctx, &request, response))
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
            extension_fields: Vec::new(),
        }
    }

    /// Variant of [`entry`] that stamps an arbitrary extension-fields
    /// blob — used by the Phase B.1 copy-preserves-blob test.
    fn entry_with_blob(
        fab_idx: NonZeroU8,
        endpoint_id: EndptId,
        group_id: u16,
        scene_id: SceneId,
        transition_time: u32,
        blob: &[u8],
    ) -> SceneEntry {
        let mut ext: Vec<u8, MAX_EXT_FIELDS_LEN> = Vec::new();
        ext.extend_from_slice(blob)
            .expect("blob too large for test");
        SceneEntry {
            fab_idx,
            endpoint_id,
            group_id,
            scene_id,
            transition_time,
            extension_fields: ext,
        }
    }

    fn push<const N: usize>(inner: &mut ScenesStateInner<N>, e: SceneEntry) {
        inner.table.push(e).expect("test table overflow");
    }

    /// Count entries in `inner.table` matching the given filter.
    fn count<const N: usize>(
        inner: &ScenesStateInner<N>,
        fab_idx: NonZeroU8,
        ep: EndptId,
        group: u16,
    ) -> usize {
        inner
            .table
            .iter()
            .filter(|e| e.fab_idx == fab_idx && e.endpoint_id == ep && e.group_id == group)
            .count()
    }

    fn find_tt<const N: usize>(
        inner: &ScenesStateInner<N>,
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

    /// Helper: look up the extension-fields blob for one entry.
    fn find_blob<const N: usize>(
        inner: &ScenesStateInner<N>,
        fab_idx: NonZeroU8,
        ep: EndptId,
        group: u16,
        scene: SceneId,
    ) -> Option<&[u8]> {
        inner
            .table
            .iter()
            .find(|e| e.matches(fab_idx, ep, group, scene))
            .map(|e| e.extension_fields.as_slice())
    }

    // ---- Phase B.1: extension-fields blob preservation ----

    #[test]
    fn copy_single_scene_preserves_extension_fields_blob() {
        // Source carries an opaque blob; the copy must replicate the
        // bytes byte-for-byte at the destination row.
        let blob = &[0xDE, 0xAD, 0xBE, 0xEF, 0x18];
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry_with_blob(fab(1), 1, 10, 5, 100, blob));

        let status =
            ScenesHandler::<8>::copy_scenes_inner(&mut inner, fab(1), 1, 10, 5, 20, 7, false);
        assert_eq!(status, 0);

        assert_eq!(find_blob(&inner, fab(1), 1, 20, 7), Some(&blob[..]));
        // Source row keeps its blob too.
        assert_eq!(find_blob(&inner, fab(1), 1, 10, 5), Some(&blob[..]));
    }

    #[test]
    fn copy_all_preserves_each_source_blob() {
        // `N=16` so per-fab cap `(N-1)/2 = 7` comfortably absorbs the
        // 2-source + 2-copy = 4 rows for fab(1).
        let blob_a = &[0xAA, 0xBB, 0x18];
        let blob_b = &[0xCC, 0x18];
        let mut inner = ScenesStateInner::<16>::new();
        push(&mut inner, entry_with_blob(fab(1), 1, 10, 1, 100, blob_a));
        push(&mut inner, entry_with_blob(fab(1), 1, 10, 2, 200, blob_b));

        let status =
            ScenesHandler::<16>::copy_scenes_inner(&mut inner, fab(1), 1, 10, 0, 20, 0, true);
        assert_eq!(status, 0);

        assert_eq!(find_blob(&inner, fab(1), 1, 20, 1), Some(&blob_a[..]));
        assert_eq!(find_blob(&inner, fab(1), 1, 20, 2), Some(&blob_b[..]));
    }

    #[test]
    fn copy_overwrites_existing_dest_blob() {
        let old_blob = &[0x11, 0x18];
        let new_blob = &[0x22, 0x33, 0x18];
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry_with_blob(fab(1), 1, 10, 5, 100, new_blob));
        push(&mut inner, entry_with_blob(fab(1), 1, 20, 7, 999, old_blob));

        let status =
            ScenesHandler::<8>::copy_scenes_inner(&mut inner, fab(1), 1, 10, 5, 20, 7, false);
        assert_eq!(status, 0);

        // Dest row's blob got replaced with the source's blob (not
        // appended to / mixed with the old).
        assert_eq!(find_blob(&inner, fab(1), 1, 20, 7), Some(&new_blob[..]));
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
        // `N=16` so per-fab cap `(N-1)/2 = 7` comfortably absorbs the
        // 3-source + 3-copy = 6 rows for fab(1).
        let mut inner = ScenesStateInner::<16>::new();
        push(&mut inner, entry(fab(1), 1, 10, 1, 100));
        push(&mut inner, entry(fab(1), 1, 10, 2, 200));
        push(&mut inner, entry(fab(1), 1, 10, 3, 300));

        let status = ScenesHandler::<16>::copy_scenes_inner(
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
    fn successful_copy_invalidates_current_scene_on_match() {
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry(fab(1), 1, 10, 5, 100));
        // Stamp "current scene" at the copy's TARGET (20, 7). After
        // the copy overwrites that slot, `SceneValid` MUST become
        // false because the recalled-scene data just changed
        // underneath the recall.
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 1, 20, 7);
        assert_eq!(inner.current_per_fabric.len(), 1);

        let status =
            ScenesHandler::<8>::copy_scenes_inner(&mut inner, fab(1), 1, 10, 5, 20, 7, false);

        assert_eq!(status, 0);
        // The slot persists (so `FabricSceneInfo` keeps emitting a row
        // for this fabric) but `valid` flips to false.
        let slot = inner
            .current_per_fabric
            .iter()
            .find(|c| c.fab_idx == fab(1))
            .expect("slot kept");
        assert!(!slot.valid);
    }

    #[test]
    fn successful_copy_preserves_current_scene_when_target_doesnt_match() {
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry(fab(1), 1, 10, 5, 100));
        // Stamp "current scene" at (99, 99) — disjoint from the
        // copy's target (20, 7). Per Matter spec §1.4.6.5,
        // `SceneValid` must be preserved when the copy doesn't touch
        // the currently-recalled scene.
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 1, 99, 99);

        let status =
            ScenesHandler::<8>::copy_scenes_inner(&mut inner, fab(1), 1, 10, 5, 20, 7, false);

        assert_eq!(status, 0);
        assert_eq!(inner.current_per_fabric.len(), 1);
        assert_eq!(inner.current_per_fabric[0].group_id, 99);
        assert_eq!(inner.current_per_fabric[0].scene_id, 99);
        assert!(inner.current_per_fabric[0].valid);
    }

    #[test]
    fn failed_copy_does_not_invalidate_current_scene() {
        let mut inner = ScenesStateInner::<8>::new();
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 1, 99, 99);
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
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 1, 10, 1);
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 1, 20, 2);

        // Same fabric ⇒ slot is updated, not duplicated.
        assert_eq!(inner.current_per_fabric.len(), 1);
        assert_eq!(inner.current_per_fabric[0].group_id, 20);
        assert_eq!(inner.current_per_fabric[0].scene_id, 2);
    }

    #[test]
    fn remember_current_keeps_fabrics_independent() {
        let mut inner = ScenesStateInner::<8>::new();
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 1, 10, 1);
        ScenesHandler::<8>::remember_current(&mut inner, fab(2), 1, 20, 2);

        assert_eq!(inner.current_per_fabric.len(), 2);
    }

    #[test]
    fn invalidate_match_scene_only_clears_exact_match() {
        let mut inner = ScenesStateInner::<8>::new();
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 1, 10, 1);
        ScenesHandler::<8>::remember_current(&mut inner, fab(2), 1, 20, 2);

        // Non-matching (group, scene) leaves the entry alone — this is
        // the spec-preserve-SceneValid path used by `AddScene` /
        // `RemoveScene` / `CopyScene` when they target a non-current
        // scene.
        ScenesHandler::<8>::invalidate_current_if_match_scene(&mut inner, fab(1), 99, 99);
        assert_eq!(inner.current_per_fabric.len(), 2);
        assert!(inner.current_per_fabric.iter().all(|c| c.valid));

        // Matching (group, scene) on fab(1) flips just fab(1)'s valid
        // bit — entries always persist so `FabricSceneInfo` still
        // emits a row for the fabric.
        ScenesHandler::<8>::invalidate_current_if_match_scene(&mut inner, fab(1), 10, 1);
        assert_eq!(inner.current_per_fabric.len(), 2);
        let f1 = inner
            .current_per_fabric
            .iter()
            .find(|c| c.fab_idx == fab(1))
            .unwrap();
        assert!(!f1.valid);
        let f2 = inner
            .current_per_fabric
            .iter()
            .find(|c| c.fab_idx == fab(2))
            .unwrap();
        assert!(f2.valid);
    }

    #[test]
    fn invalidate_match_group_clears_any_scene_in_group() {
        let mut inner = ScenesStateInner::<8>::new();
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 1, 10, 7);
        ScenesHandler::<8>::remember_current(&mut inner, fab(2), 1, 20, 2);

        // Wrong group: no-op.
        ScenesHandler::<8>::invalidate_current_if_match_group(&mut inner, fab(1), 99);
        assert!(inner.current_per_fabric.iter().all(|c| c.valid));

        // Right group on fab(1), regardless of scene id, flips fab(1)'s
        // valid bit — exercising the `RemoveAllScenes(group)` /
        // `CopyScene COPY_ALL` path.
        ScenesHandler::<8>::invalidate_current_if_match_group(&mut inner, fab(1), 10);
        let f1 = inner
            .current_per_fabric
            .iter()
            .find(|c| c.fab_idx == fab(1))
            .unwrap();
        assert!(!f1.valid);
        let f2 = inner
            .current_per_fabric
            .iter()
            .find(|c| c.fab_idx == fab(2))
            .unwrap();
        assert!(f2.valid);
    }

    // ---- Phase D: AddScene / StoreScene shared `upsert_scene` path ----
    //
    // `AddScene` and `StoreScene` differ only in *where* the EFS blob
    // comes from (request payload vs cross-cluster capture) — both
    // commit through `upsert_scene` with a fill closure that
    // `extend_from_slice`s into the slot's `Vec`. These tests
    // exercise the upsert state-machine directly (no async handler
    // harness needed).

    /// Fill closure that copies a fixed slice into the slot Vec.
    /// Used by `upsert_scene` tests where the contents don't matter.
    fn fill_with<'a>(blob: &'a [u8]) -> impl FnOnce(&mut Vec<u8, 128>) -> Result<(), Error> + 'a {
        move |ext| {
            ext.extend_from_slice(blob)
                .map_err(|_| ErrorCode::NoSpace.into())
        }
    }

    #[test]
    fn upsert_inserts_new_record_with_status_zero() {
        let mut inner = ScenesStateInner::<8>::new();
        let status = ScenesHandler::<8>::upsert_scene(
            &mut inner,
            fab(1),
            1,
            10,
            5,
            100,
            fill_with(&[0xAA, 0x18]),
        )
        .unwrap();

        assert_eq!(status, 0);
        assert_eq!(inner.table.len(), 1);
        assert_eq!(find_tt(&inner, fab(1), 1, 10, 5), Some(100));
        assert_eq!(find_blob(&inner, fab(1), 1, 10, 5), Some(&[0xAA, 0x18][..]));
    }

    #[test]
    fn upsert_replaces_existing_record_in_place_no_growth() {
        let mut inner = ScenesStateInner::<8>::new();
        push(
            &mut inner,
            entry_with_blob(fab(1), 1, 10, 5, 100, &[0xAA, 0x18]),
        );

        let status = ScenesHandler::<8>::upsert_scene(
            &mut inner,
            fab(1),
            1,
            10,
            5,
            999,
            fill_with(&[0xBB, 0xCC, 0x18]),
        )
        .unwrap();

        assert_eq!(status, 0);
        assert_eq!(inner.table.len(), 1, "replace must not grow the table");
        assert_eq!(find_tt(&inner, fab(1), 1, 10, 5), Some(999));
        assert_eq!(
            find_blob(&inner, fab(1), 1, 10, 5),
            Some(&[0xBB, 0xCC, 0x18][..])
        );
    }

    #[test]
    fn upsert_returns_insufficient_space_when_table_is_full() {
        // Fill the table to capacity, then try to insert a NEW key.
        let mut inner = ScenesStateInner::<3>::new();
        inner.table.push(entry(fab(1), 1, 10, 1, 100)).unwrap();
        inner.table.push(entry(fab(1), 1, 10, 2, 100)).unwrap();
        inner.table.push(entry(fab(1), 1, 10, 3, 100)).unwrap();

        let status = ScenesHandler::<3>::upsert_scene(
            &mut inner,
            fab(1),
            1,
            10,
            99, // new scene_id
            200,
            fill_with(&[0x18]),
        )
        .unwrap();

        assert_eq!(status, SC_INSUFFICIENT_SPACE);
        assert_eq!(inner.table.len(), 3, "table size unchanged on rejection");
    }

    #[test]
    fn upsert_replace_at_full_capacity_still_succeeds() {
        // Replacing an EXISTING entry doesn't need a new slot, so it
        // should succeed even when the table is at capacity.
        let mut inner = ScenesStateInner::<3>::new();
        inner.table.push(entry(fab(1), 1, 10, 1, 100)).unwrap();
        inner.table.push(entry(fab(1), 1, 10, 2, 100)).unwrap();
        inner.table.push(entry(fab(1), 1, 10, 3, 100)).unwrap();

        let status = ScenesHandler::<3>::upsert_scene(
            &mut inner,
            fab(1),
            1,
            10,
            2, // existing scene_id
            999,
            fill_with(&[0x18]),
        )
        .unwrap();

        assert_eq!(status, 0);
        assert_eq!(inner.table.len(), 3);
        assert_eq!(find_tt(&inner, fab(1), 1, 10, 2), Some(999));
    }

    #[test]
    fn upsert_invalidates_current_scene_when_upsert_targets_it() {
        // Per Matter App Cluster spec §1.4.6.5, `SceneValid` is only
        // invalidated when the upsert (`AddScene` / `StoreScene`)
        // overwrites the currently-recalled scene. Stamp the current
        // scene at the same `(group, scene)` the upsert targets and
        // verify it gets dropped.
        let mut inner = ScenesStateInner::<8>::new();
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 1, 10, 5);

        let _ =
            ScenesHandler::<8>::upsert_scene(&mut inner, fab(1), 1, 10, 5, 100, fill_with(&[0x18]))
                .unwrap();

        // The slot stays — the fabric is still "known" to the cluster
        // — but `valid` flips false.
        let f1 = inner
            .current_per_fabric
            .iter()
            .find(|c| c.fab_idx == fab(1))
            .expect("slot kept");
        assert!(!f1.valid);
    }

    #[test]
    fn upsert_preserves_current_scene_when_upsert_targets_a_different_scene() {
        // Non-matching upsert MUST leave `SceneValid` intact (the
        // spec-conformance regression that `TestScenesFabricSceneInfo`
        // step 21 catches when violated).
        let mut inner = ScenesStateInner::<8>::new();
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 1, 1, 1);

        let _ =
            // Upsert in a *different* group/scene than the current one.
            ScenesHandler::<8>::upsert_scene(&mut inner, fab(1), 1, 2, 1, 100, fill_with(&[0x18]))
                .unwrap();

        assert_eq!(inner.current_per_fabric.len(), 1);
        assert_eq!(inner.current_per_fabric[0].group_id, 1);
        assert_eq!(inner.current_per_fabric[0].scene_id, 1);
        assert!(inner.current_per_fabric[0].valid);
    }

    #[test]
    fn upsert_keeps_other_fabrics_current_scene_intact() {
        let mut inner = ScenesStateInner::<8>::new();
        // Both fabrics have a current scene matching what we're about
        // to upsert in fab(1) — only fab(1)'s entry should drop.
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 1, 10, 5);
        ScenesHandler::<8>::remember_current(&mut inner, fab(2), 1, 10, 5);

        let _ =
            ScenesHandler::<8>::upsert_scene(&mut inner, fab(1), 1, 10, 5, 100, fill_with(&[0x18]))
                .unwrap();

        // fab(1) is invalidated (valid=false) but the slot stays.
        // fab(2) is untouched.
        let f1 = inner
            .current_per_fabric
            .iter()
            .find(|c| c.fab_idx == fab(1))
            .expect("fab(1) slot kept");
        assert!(!f1.valid);
        let f2 = inner
            .current_per_fabric
            .iter()
            .find(|c| c.fab_idx == fab(2))
            .expect("fab(2) slot kept");
        assert!(f2.valid, "fab(2)'s CurrentScene must not be touched");
    }

    #[test]
    fn upsert_at_full_capacity_does_not_invalidate_current() {
        // When the new-entry path errors with SC_INSUFFICIENT_SPACE,
        // the table state is unchanged — CurrentScene must stay too.
        let mut inner = ScenesStateInner::<3>::new();
        inner.table.push(entry(fab(1), 1, 10, 1, 100)).unwrap();
        inner.table.push(entry(fab(1), 1, 10, 2, 100)).unwrap();
        inner.table.push(entry(fab(1), 1, 10, 3, 100)).unwrap();
        ScenesHandler::<3>::remember_current(&mut inner, fab(1), 1, 99, 99);

        let status = ScenesHandler::<3>::upsert_scene(
            &mut inner,
            fab(1),
            1,
            10,
            99,
            200,
            fill_with(&[0x18]),
        )
        .unwrap();

        assert_eq!(status, SC_INSUFFICIENT_SPACE);
        assert!(inner.current_per_fabric.iter().any(|c| c.fab_idx == fab(1)));
    }

    #[test]
    fn upsert_fill_failure_on_new_entry_rolls_back_the_push() {
        // If the fill closure errors *after* `push_init` has stamped
        // an empty SceneEntry into the slot, that slot must be popped
        // so the table returns to its pre-call state.
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry(fab(1), 1, 10, 1, 100));

        let result = ScenesHandler::<8>::upsert_scene(
            &mut inner,
            fab(1),
            1,
            10,
            42, // brand new
            200,
            |_| Err(ErrorCode::NoSpace.into()),
        );

        assert!(result.is_err());
        assert_eq!(
            inner.table.len(),
            1,
            "rolled-back push leaves count untouched"
        );
        assert!(find_tt(&inner, fab(1), 1, 10, 42).is_none());
    }
}
