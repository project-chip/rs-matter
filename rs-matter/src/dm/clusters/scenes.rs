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

use core::cell::Cell;
use core::future::{ready, Future};
use core::num::NonZeroU8;

use crate::dm::{
    ArrayAttributeRead, AsyncHandler, AttrDetails, AttrId, Cluster, ClusterId, CmdDetails, CmdId,
    Dataver, EndptId, InvokeContext, InvokeContextInstance, InvokeReplyInstance, Metadata,
    ReadContext, ReadContextInstance, ReadReply, Reply, SceneId,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{
    FromTLV, TLVArray, TLVBuilderParent, TLVElement, TLVTag, TLVWrite, TLVWriteParent, TagType,
    ToTLV,
};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::{Vec, WriteBuf};
use crate::utils::sync::blocking::Mutex;

pub use crate::dm::clusters::decl::scenes_management::*;

/// IM status codes specific to the Scenes Management cluster (see
/// "Generic Usage Notes" in the Matter Application Cluster spec).
const SC_NOT_FOUND: u8 = 0x8B;
const SC_INSUFFICIENT_SPACE: u8 = 0x89;

/// Max length of the serialized `ExtensionFieldSetStructs` payload
/// carried on a single scene record. Per chip's notes a Color Control
/// scene is the largest realistic case at ~99 B; OnOff + LevelControl
/// scenes are ~16 B. `128` covers the realistic worst case for the
/// clusters Phase B.2 / C will register, with the cost paid per scene
/// (so `N * MAX_EXT_FIELDS_LEN` RAM total).
pub const MAX_EXT_FIELDS_LEN: usize = 128;

/// Per-cluster scene capture + apply trait.
///
/// Implemented (typically as a zero-sized type) alongside each
/// scene-able cluster's handler — see
/// [`crate::dm::clusters::app::on_off::OnOffSceneClusterHandler`] etc.
/// The user composes a tuple of these and registers it with
/// [`ScenesHandler::new`]; the Scenes handler delegates the per-cluster
/// work via the [`SceneClusters`] tuple-recursive dispatch.
///
/// **Invariant**: all cross-cluster I/O goes through
/// `ctx.handler().{read, write, invoke}` — the Scenes handler has no
/// direct reference to other cluster handlers, only the routing layer
/// does.
pub trait SceneClusterHandler {
    /// The Matter cluster ID this impl handles. Used by [`SceneClusters`]
    /// to route apply dispatch.
    const CLUSTER_ID: ClusterId;

    /// Read this cluster's scene-able attributes via
    /// `sctx.read(...)` and emit zero-or-more
    /// `AttributeValuePairStruct` elements into `avp_array` (use
    /// [`AttributeValuePairStructArrayBuilder::push_u8`] /
    /// [`AttributeValuePairStructArrayBuilder::push_u16`] / etc. for a
    /// one-line per-attribute API).
    ///
    /// Returns the (advanced) builder so the caller can close the array.
    fn capture<C, P>(
        &self,
        sctx: &SceneContext<C>,
        endpoint_id: EndptId,
        avp_array: AttributeValuePairStructArrayBuilder<P>,
    ) -> impl Future<Output = Result<AttributeValuePairStructArrayBuilder<P>, Error>>
    where
        C: InvokeContext,
        P: TLVBuilderParent;

    /// Apply the captured attribute values by invoking the right
    /// cluster commands (via `sctx.invoke(...)`) — or, for clusters
    /// with writable scene-able attrs, by attribute writes.
    /// `transition_time_ms` is the effective transition for this
    /// recall (either the `RecallScene` request override or the stored
    /// value).
    fn apply<C>(
        &self,
        sctx: &SceneContext<C>,
        endpoint_id: EndptId,
        transition_time_ms: u32,
        avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
    ) -> impl Future<Output = Result<(), Error>>
    where
        C: InvokeContext;
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
    /// cluster that is actually present on `endpoint_id`.
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
    fn capture<C, P>(
        &self,
        sctx: &SceneContext<C>,
        endpoint_id: EndptId,
        parent: P,
    ) -> impl Future<Output = Result<P, Error>>
    where
        C: InvokeContext,
        P: TLVBuilderParent;

    /// Find the registered cluster matching `cluster_id` and let it
    /// apply `avp_list`. Returns `Ok(true)` if a cluster handled it,
    /// `Ok(false)` if no registered cluster matches (the entry is
    /// silently skipped, matching chip's behavior).
    fn apply<C>(
        &self,
        sctx: &SceneContext<C>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        transition_time_ms: u32,
        avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
    ) -> impl Future<Output = Result<bool, Error>>
    where
        C: InvokeContext;
}

impl SceneClusters for () {
    fn capture<C, P>(
        &self,
        _sctx: &SceneContext<C>,
        _endpoint_id: EndptId,
        parent: P,
    ) -> impl Future<Output = Result<P, Error>>
    where
        C: InvokeContext,
        P: TLVBuilderParent,
    {
        ready(Ok(parent))
    }

    fn apply<C>(
        &self,
        _sctx: &SceneContext<C>,
        _endpoint_id: EndptId,
        _cluster_id: ClusterId,
        _transition_time_ms: u32,
        _avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
    ) -> impl Future<Output = Result<bool, Error>>
    where
        C: InvokeContext,
    {
        ready(Ok(false))
    }
}

impl<H, T> SceneClusters for (H, T)
where
    H: SceneClusterHandler,
    T: SceneClusters,
{
    async fn capture<C, P>(
        &self,
        sctx: &SceneContext<C>,
        endpoint_id: EndptId,
        parent: P,
    ) -> Result<P, Error>
    where
        C: InvokeContext,
        P: TLVBuilderParent,
    {
        let parent = if sctx.cluster_present(endpoint_id, H::CLUSTER_ID) {
            // Open this cluster's ExtensionFieldSetStruct directly on
            // the parent (no outer array wrapper), hand the inner
            // AVP-array builder to the cluster impl, then close both
            // containers and continue down the chain.
            let efs = ExtensionFieldSetStructBuilder::new(parent, &TLVTag::Anonymous)?;
            let efs = efs.cluster_id(H::CLUSTER_ID)?;
            let avp_array = efs.attribute_value_list()?;
            let avp_array = self.0.capture(sctx, endpoint_id, avp_array).await?;
            let efs = avp_array.end()?;
            efs.end()?
        } else {
            parent
        };
        self.1.capture(sctx, endpoint_id, parent).await
    }

    async fn apply<C>(
        &self,
        sctx: &SceneContext<C>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        transition_time_ms: u32,
        avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
    ) -> Result<bool, Error>
    where
        C: InvokeContext,
    {
        if H::CLUSTER_ID == cluster_id {
            self.0
                .apply(sctx, endpoint_id, transition_time_ms, avp_list)
                .await?;
            Ok(true)
        } else {
            self.1
                .apply(sctx, endpoint_id, cluster_id, transition_time_ms, avp_list)
                .await
        }
    }
}

// ---------------------------------------------------------------------
// SceneContext — wraps the active InvokeContext and gives per-cluster
// scene impls a small, focused API (`read`, `invoke`, `cluster_present`)
// instead of bare `ctx.handler().{read,invoke}` + raw
// `ReadContextInstance` / `InvokeContextInstance` plumbing.
// ---------------------------------------------------------------------

/// Per-call context handed to [`SceneClusterHandler::capture`] and
/// [`SceneClusterHandler::apply`].
///
/// Wraps the live [`InvokeContext`] for the in-flight `StoreScene` /
/// `RecallScene` command and surfaces the operations a scene-able
/// cluster impl actually needs:
///
/// - [`SceneContext::read`] — cross-cluster attribute read, decoded
///   as a `FromTLV` type.
/// - [`SceneContext::invoke`] — cross-cluster command dispatch with
///   the response discarded.
/// - [`SceneContext::cluster_present`] — metadata-driven check used
///   by the tuple recursion to skip clusters not installed on the
///   host endpoint.
///
/// All three go through the global handler (`ctx.handler()`), matching
/// the invariant noted on [`SceneClusterHandler`].
pub struct SceneContext<C: InvokeContext>(C);

impl<C: InvokeContext> SceneContext<C> {
    pub const fn new(ctx: C) -> Self {
        Self(ctx)
    }

    /// The wrapped [`InvokeContext`]. Useful when a cluster impl needs
    /// something outside the small scene-focused surface (e.g.
    /// `notify_attr_changed`, `set_cluster_status`).
    ///
    /// Construction takes `C` by value; callers typically pass a
    /// reference (e.g. `SceneContext::new(ctx)` where `ctx: &impl
    /// InvokeContext`) — `&InvokeContext: InvokeContext` via the
    /// blanket impl, so the `'a` lifetime is folded into `C` itself.
    pub const fn ctx(&self) -> &C {
        &self.0
    }

    /// Read one attribute via the global handler and decode it as
    /// `T`.
    ///
    /// Drives [`AsyncHandler::read`] with a custom reply that
    /// captures the value bytes (TLV-encoded with anonymous tag) into
    /// a stack buffer, then decodes them as `T` via `FromTLV`. The
    /// `T: for<'b> FromTLV<'b>` bound restricts use to types that
    /// don't borrow from the TLV bytes (primitives, `Nullable<u8>`,
    /// enums, …) — which covers all scalar-valued attributes scene
    /// capture cares about.
    pub async fn read<T>(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        attr_id: AttrId,
    ) -> Result<T, Error>
    where
        T: for<'b> FromTLV<'b>,
    {
        let mut buf = [0u8; 16];
        let mut wb = WriteBuf::new(&mut buf);

        let attr = AttrDetails {
            endpoint_id,
            cluster_id,
            attr_id,
            list_index: None,
            list_chunked: false,
            // Fabric-scoped attrs are not in the spec'd scene-able set,
            // but pass the accessor's fabric in case a future scene-able
            // attribute is fabric-scoped.
            fab_idx: self.0.exchange().accessor()?.fab_idx()?.get(),
            fab_filter: false,
            dataver: None,
            wildcard: false,
            array: false,
            cluster_status: Cell::new(0),
        };

        let handler = self.0.handler();
        let read_ctx = ReadContextInstance::new(self.0.exchange(), &self.0, &attr);
        let reply = CaptureReply { wb: &mut wb };
        handler.read(read_ctx, reply).await?;

        T::from_tlv(&TLVElement::new(wb.as_slice()))
    }

    /// Dispatch a cross-cluster command through `ctx.handler().invoke()`.
    /// The command reply is captured into a small stack buffer and
    /// discarded — most cluster-apply paths only care about
    /// success/failure, not the echoed `DefaultSuccess` payload.
    ///
    /// `data` must be a complete TLV-encoded command request struct
    /// (anonymous-tagged), or empty for commands with no payload
    /// (`On`, `Off`, `Toggle`).
    pub async fn invoke(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        cmd_id: CmdId,
        data: &[u8],
    ) -> Result<(), Error> {
        let fab_idx = self.0.exchange().accessor()?.fab_idx()?.get();
        let cmd = CmdDetails::new(endpoint_id, cluster_id, cmd_id, fab_idx, false, None);
        let data_elem = TLVElement::new(data);

        // 64 B is plenty for a `DefaultSuccess` reply (anonymous outer
        // struct + cmd-resp struct + path).
        let mut response_buf = [0u8; 64];
        let mut response_wb = WriteBuf::new(&mut response_buf);
        let reply = InvokeReplyInstance::new(&cmd, &mut response_wb);

        let handler = self.0.handler();
        let inv_ctx = InvokeContextInstance::new(self.0.exchange(), &self.0, &cmd, &data_elem);
        handler.invoke(inv_ctx, reply).await
    }

    /// Check whether `cluster_id` is exposed on `endpoint_id` per the
    /// node metadata. Used by the [`SceneClusters`] tuple recursion
    /// to skip scene-able cluster impls that the host endpoint
    /// doesn't actually install — and available to cluster impls that
    /// want to do the same check (e.g. for sibling-cluster
    /// dependencies).
    pub fn cluster_present(&self, endpoint_id: EndptId, cluster_id: ClusterId) -> bool {
        self.0.metadata().access(|node| {
            node.endpoint(endpoint_id)
                .and_then(|ep| ep.cluster(cluster_id))
                .is_some()
        })
    }
}

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

    /// Stamp `(group, scene)` as the current recalled scene for this
    /// fabric. Bumps `FabricSceneInfo` dataver. Operates on already-
    /// locked inner state.
    fn remember_current(
        inner: &mut ScenesStateInner<N, M>,
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
    fn invalidate_current(inner: &mut ScenesStateInner<N, M>, fab_idx: NonZeroU8) {
        inner.current_per_fabric.retain(|c| c.fab_idx != fab_idx);
        inner.bump_info_dataver();
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
                } else if inner
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
        let raw = match request.extension_field_set_structs() {
            Ok(array) => array.element().raw_value()?,
            Err(_) => &[],
        };

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
            Self::invalidate_current(inner, fab_idx);
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
            Self::invalidate_current(inner, fab_idx);
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
    fn write_blob_or_none<P, T>(
        mut opt: crate::tlv::OptionalBuilder<P, T>,
        blob: &[u8],
    ) -> Result<P, Error>
    where
        P: TLVBuilderParent,
        T: crate::tlv::TLVBuilder<P>,
    {
        use crate::tlv::{TLVTag, TLVWrite};
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
        let sctx = SceneContext::new(ctx);
        let mut scratch = [0u8; M];
        let total_len = {
            let mut wb = WriteBuf::new(&mut scratch);
            let parent = TLVWriteParent::new("StoreScene EFS", &mut wb);
            let _ = self.clusters.capture(&sctx, endpoint_id, parent).await?;
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
            Self::upsert_scene(
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
            )
        })?;

        if status_code == 0 {
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
            // Spec: NotFound when no matching scene exists. The codegen
            // turns the IM error into a NotFound status response.
            ctx.cmd().set_cluster_status(SC_NOT_FOUND);
            return Err(ErrorCode::Failure.into());
        };

        let effective_tt_ms = override_tt_ms.unwrap_or(stored_tt_ms);

        let sctx = SceneContext::new(ctx);
        for efs_element in crate::tlv::TLVSequence(&blob[..blob_len]).iter() {
            let efs = ExtensionFieldSetStruct::new(efs_element?);
            let cluster_id = efs.cluster_id()?;
            let avp_list = efs.attribute_value_list()?;
            // `apply` returns `false` for unknown cluster IDs — match
            // chip's behaviour and silently skip them (the blob may
            // have been written by a previous firmware version with a
            // different scene-able cluster set).
            let _ = self
                .clusters
                .apply(&sctx, endpoint_id, cluster_id, effective_tt_ms, &avp_list)
                .await?;
        }

        self.state
            .with(|inner| Self::remember_current(inner, fab_idx, group_id, scene_id));

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
            ctx.notify_own_attr_changed(AttributeId::FabricSceneInfo as _);
        }

        response
            .status(status)?
            .group_identifier_from(group_from)?
            .scene_identifier_from(scene_from)?
            .end()
    }
}

// ---------------------------------------------------------------------
// Cross-cluster read plumbing for StoreScene.
//
// `CaptureReply` is a minimal [`ReadReply`] that *only* records the
// attribute value bytes (TLV-encoded with [`TagType::Anonymous`]) into
// a caller-provided [`WriteBuf`]. We deliberately bypass the standard
// `AttrResp::Data` framing (dataver + path + data) used by
// `ReadReplyInstance`, because StoreScene's capture path doesn't need
// any of it — it would just have to be re-parsed back out.
//
// The codegen for an attribute read produces:
//     reply.with_dataver(self.dataver())?
//          .and_then(|writer| Reply::set(writer, value))
// `with_dataver` here ignores the dataver entirely (we always want the
// current value) and `Reply::set` writes the value at TAG = Anonymous.
// ---------------------------------------------------------------------

/// See module-level comment block above.
struct CaptureReply<'b, 'wb> {
    wb: &'b mut WriteBuf<'wb>,
}

impl<'b, 'wb> ReadReply for CaptureReply<'b, 'wb> {
    fn with_dataver(self, _dataver: u32) -> Result<Option<impl Reply>, Error> {
        Ok(Some(CaptureReplyWriter { wb: self.wb }))
    }
}

struct CaptureReplyWriter<'b, 'wb> {
    wb: &'b mut WriteBuf<'wb>,
}

impl Reply for CaptureReplyWriter<'_, '_> {
    const TAG: TagType = TagType::Anonymous;

    fn set<T: ToTLV>(self, value: T) -> Result<(), Error> {
        value.to_tlv(&Self::TAG, self.wb)
    }

    fn reset(&mut self) {
        // No-op: the codegen-driven attribute read path calls
        // `Reply::set` exactly once per attribute, so a partial-write
        // rewind is never needed here.
    }

    fn writer(&mut self) -> impl TLVWrite + Send + '_ {
        &mut *self.wb
    }

    fn complete(self) -> Result<(), Error> {
        Ok(())
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
        let blob_a = &[0xAA, 0xBB, 0x18];
        let blob_b = &[0xCC, 0x18];
        let mut inner = ScenesStateInner::<8>::new();
        push(&mut inner, entry_with_blob(fab(1), 1, 10, 1, 100, blob_a));
        push(&mut inner, entry_with_blob(fab(1), 1, 10, 2, 200, blob_b));

        let status =
            ScenesHandler::<8>::copy_scenes_inner(&mut inner, fab(1), 1, 10, 0, 20, 0, true);
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
    fn upsert_invalidates_current_scene_for_target_fabric() {
        // Per `SceneValid` rules: any AddScene/StoreScene mutates
        // table state in a way that may no longer match the recalled
        // attributes, so CurrentScene gets cleared for the originating
        // fabric.
        let mut inner = ScenesStateInner::<8>::new();
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 99, 99);

        let _ =
            ScenesHandler::<8>::upsert_scene(&mut inner, fab(1), 1, 10, 5, 100, fill_with(&[0x18]))
                .unwrap();

        assert!(!inner.current_per_fabric.iter().any(|c| c.fab_idx == fab(1)));
    }

    #[test]
    fn upsert_keeps_other_fabrics_current_scene_intact() {
        let mut inner = ScenesStateInner::<8>::new();
        ScenesHandler::<8>::remember_current(&mut inner, fab(1), 99, 99);
        ScenesHandler::<8>::remember_current(&mut inner, fab(2), 88, 88);

        let _ =
            ScenesHandler::<8>::upsert_scene(&mut inner, fab(1), 1, 10, 5, 100, fill_with(&[0x18]))
                .unwrap();

        assert!(!inner.current_per_fabric.iter().any(|c| c.fab_idx == fab(1)));
        assert!(
            inner.current_per_fabric.iter().any(|c| c.fab_idx == fab(2)),
            "fab(2)'s CurrentScene must not be touched"
        );
    }

    #[test]
    fn upsert_at_full_capacity_does_not_invalidate_current() {
        // When the new-entry path errors with SC_INSUFFICIENT_SPACE,
        // the table state is unchanged — CurrentScene must stay too.
        let mut inner = ScenesStateInner::<3>::new();
        inner.table.push(entry(fab(1), 1, 10, 1, 100)).unwrap();
        inner.table.push(entry(fab(1), 1, 10, 2, 100)).unwrap();
        inner.table.push(entry(fab(1), 1, 10, 3, 100)).unwrap();
        ScenesHandler::<3>::remember_current(&mut inner, fab(1), 99, 99);

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
