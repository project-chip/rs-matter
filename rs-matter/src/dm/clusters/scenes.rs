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

//! Scenes Management cluster handler.
//!
//! A scene is a named snapshot of a chosen subset of cluster
//! attributes on one endpoint, recallable on demand. Scene capture
//! and apply talk to scene-aware clusters via the
//! [`SceneClusterHandler`] trait, which the cluster's normal handler
//! type implements directly — `&on_off_handler` doubles as both a
//! data-model chain entry and a scenes-registry entry.
//!
//! [`ScenesState`] holds the per-device scene table and per-fabric
//! `CurrentScene` bookkeeping; the table is persisted as a single
//! TLV blob under [`SCENES_KEY`] on every successful mutation, and
//! re-hydrated on startup via [`ScenesState::load_persist`].
//!
//! The `SceneNames` feature is not supported — scene names sent on
//! the wire are accepted and discarded.

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

// IM status codes used by Scenes Management response structs and
// command-level `Err(...)` returns.
const SC_NOT_FOUND: u8 = 0x8B;
const SC_INSUFFICIENT_SPACE: u8 = 0x89;
const SC_INVALID_COMMAND: u8 = 0x85;
const SC_CONSTRAINT_ERROR: u8 = 0x87;

/// Reserved (invalid) `SceneID` value per Matter Core Spec.
const RESERVED_SCENE_ID: SceneId = 0xFF;

/// `SceneID` 0 is reserved for the Global Scene; never valid in
/// add/view/remove/store/recall/copy.
const GLOBAL_SCENE_ID: SceneId = 0;

/// Maximum legal `AddScene.TransitionTime` in milliseconds
/// (60 000 seconds / 1000 minutes per Matter Core Spec).
const MAX_TRANSITION_TIME_MS: u32 = 60_000_000;

/// Default max length of the serialized `ExtensionFieldSetStructs`
/// payload on a single scene record. ColorControl scenes are the
/// largest realistic case at ~100 B; OnOff + LevelControl scenes are
/// ~16 B. Bumpable via the `M` const generic on [`ScenesState`] /
/// [`ScenesHandler`]; total RAM cost is `N * M`.
pub const MAX_EXT_FIELDS_LEN: usize = 128;

/// Per-cluster scene capture + apply trait. Implemented directly on
/// the cluster's handler type (e.g. `OnOffHandler`) so the same
/// `&handler` the application registers in the data-model chain can
/// also be registered in the scenes registry — no separate wrapper,
/// no IM round-trip, no TLV serde.
///
/// Back-direction (a scenable attribute mutated, so `SceneValid` may
/// need to flip) goes through [`SceneInvalidator`], implemented by
/// [`ScenesState`].
pub trait SceneClusterHandler {
    /// The Matter cluster ID this impl handles.
    const CLUSTER_ID: ClusterId;

    /// Endpoint this handler instance is installed on. Used to skip
    /// clusters not on the `StoreScene` / `RecallScene` target endpoint.
    fn endpoint_id(&self) -> EndptId;

    /// True if `attribute_id` is a scenable attribute of this cluster
    /// per the Matter Core Spec. `AddScene` rejects EFS payloads that
    /// reference non-scenable attributes.
    fn is_scenable_attribute(_attribute_id: AttrId) -> bool {
        false
    }

    /// Emit AVP entries for this cluster's scenable state into
    /// `avp_array`. Use [`AttributeValuePairStructArrayBuilder::push_u8`]
    /// / [`AttributeValuePairStructArrayBuilder::push_u16`] for a
    /// one-line per-attribute API.
    fn capture<P: TLVBuilderParent>(
        &self,
        avp_array: AttributeValuePairStructArrayBuilder<P>,
    ) -> Result<AttributeValuePairStructArrayBuilder<P>, Error>;

    /// Apply captured AVPs to the cluster's internal state. Async
    /// because some clusters (LevelControl) kick off transition
    /// tasks; sync-only impls can return [`core::future::ready`].
    ///
    /// # Arguments
    /// - `ctx` — [`HandlerContext`] for subscriber notification
    ///   ([`crate::dm::AttrChangeNotifier::notify_attr_changed`]) and
    ///   persistence ([`HandlerContext::kv`]). Impls MUST NOT call
    ///   `ctx.handler()` from inside `apply` — recursion-limit
    ///   pathology, by design.
    /// - `avp_list` — the captured scenable AVPs from `AddScene` /
    ///   `StoreScene`.
    /// - `transition_time_ms` — effective transition time
    ///   (`RecallScene` request override, falling back to the stored
    ///   per-scene value).
    fn apply<C: HandlerContext>(
        &self,
        ctx: &C,
        avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
        transition_time_ms: u32,
    ) -> impl Future<Output = Result<(), Error>>;
}

/// Lets the application pass `&handler` into the scenes registry
/// without moving it (the same `&handler` is also kept in the
/// data-model chain). Delegates every method through the reference.
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

/// Tuple-recursive composition of [`SceneClusterHandler`]s. Mirrors
/// [`crate::dm::ChainedHandler`]: terminated by `()`, one cluster
/// registers as `(impl, ())`, multiple as `(a, (b, (c, ())))`.
pub trait SceneClusters {
    /// Emit one EFS struct per registered cluster whose
    /// `endpoint_id()` matches `endpoint_id`. EFS structs are written
    /// directly into the parent without an outer array wrapper; the
    /// caller is responsible for the trailing array terminator.
    fn capture<P: TLVBuilderParent>(&self, endpoint_id: EndptId, parent: P) -> Result<P, Error>;

    /// `Some(true)` if `cluster_id` is registered and `attribute_id`
    /// is scenable on it; `Some(false)` if registered but
    /// non-scenable (`AddScene` returns `INVALID_COMMAND`); `None`
    /// if `cluster_id` is not registered (lenient — store the bytes,
    /// silently skip on recall; matches chip's firmware-downgrade
    /// behaviour).
    fn check_scenable(&self, cluster_id: ClusterId, attribute_id: AttrId) -> Option<bool>;

    /// Find the registered cluster matching `(cluster_id, endpoint_id)`
    /// and let it apply `avp_list`. Returns `Ok(true)` if handled,
    /// `Ok(false)` if no registered cluster matches.
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

/// Ergonomics shims on the codegen'd AVP array builder so `capture`
/// impls can write `avp_array.push_u8(attr_id, v)?` instead of
/// spelling out the codegen builder's 9-state push chain.
impl<P> AttributeValuePairStructArrayBuilder<P>
where
    P: TLVBuilderParent,
{
    /// Push one AVP element with a `valueUnsigned8` value.
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

    /// Push one AVP element with a `valueUnsigned16` value.
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

/// One scene record. Holds the metadata (fabric / endpoint / group
/// / scene / transition) plus the wire-form `ExtensionFieldSetStructs`
/// blob captured on `AddScene` / `StoreScene` and replayed on
/// `ViewScene` / `RecallScene` / `CopyScene`. `M` is the per-scene
/// blob capacity — see [`MAX_EXT_FIELDS_LEN`].
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SceneEntry<const M: usize = MAX_EXT_FIELDS_LEN> {
    fab_idx: NonZeroU8,
    endpoint_id: EndptId,
    group_id: u16,
    scene_id: SceneId,
    /// Transition time in milliseconds (1..=`MAX_TRANSITION_TIME_MS`).
    transition_time: u32,
    /// EFS array contents (between the array-control byte and the
    /// terminator — what [`crate::tlv::TLVElement::raw_value`]
    /// returns). Spliced back at the response tag by `ViewScene` /
    /// `CopyScene`. Empty ⇒ no captured fields.
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

    /// In-place initializer that avoids the `M`-byte stack copy a
    /// by-value `SceneEntry` would otherwise incur. The `extension_fields`
    /// `Vec` is initialized empty; the caller fills it in place via
    /// [`super::ScenesHandler::upsert_scene`]'s closure.
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

/// Per-fabric "last recalled scene" pointer backing
/// `FabricSceneInfo.CurrentScene` / `CurrentGroup` / `SceneValid`.
///
/// The slot persists once a fabric has interacted with scenes — so
/// `FabricSceneInfo` keeps emitting a row for it even after the only
/// scene is removed — and `valid` carries `SceneValid` directly.
/// `endpoint_id` lets [`SceneInvalidator`] flip `valid → false`
/// per-endpoint without touching other endpoints' recalled scenes.
#[derive(Debug, Clone, Copy, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct CurrentScene {
    fab_idx: NonZeroU8,
    endpoint_id: EndptId,
    group_id: u16,
    scene_id: SceneId,
    valid: bool,
}

/// All mutable Scenes state, held behind a single mutex inside
/// [`ScenesState`].
struct ScenesStateInner<const N: usize, const M: usize = MAX_EXT_FIELDS_LEN> {
    /// Scene table keyed by `(fab_idx, endpoint_id, group_id, scene_id)`.
    table: Vec<SceneEntry<M>, N>,
    /// One slot per fabric that has touched scenes.
    current_per_fabric: Vec<CurrentScene, N>,
    /// Bumped on every state mutation that affects `FabricSceneInfo`.
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

/// Caller-owned per-device Scenes state — the scene table plus
/// per-fabric `CurrentScene` bookkeeping. Shared across all endpoints
/// exposing the cluster.
///
/// Const generics:
/// - `N` — total scene-table capacity (rows across all fabrics +
///   endpoints).
/// - `M` — per-scene EFS blob capacity in bytes. Bump it when
///   wiring ColorControl into a multi-feature deployment whose
///   captured EFS exceeds [`MAX_EXT_FIELDS_LEN`]. Total static RAM
///   is roughly `N * (M + overhead)`.
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

/// Notified by scene-aware cluster handlers when a scenable
/// attribute on an endpoint changes outside a scene recall. Per
/// Matter Core Spec, such a mutation invalidates `SceneValid` for
/// every fabric whose recalled scene lives on that endpoint.
///
/// [`ScenesState`] implements this trait. Wire the impl into a
/// scene-aware cluster handler via its `with_scene_invalidator`
/// builder; the handler then calls
/// [`Self::scenable_attribute_changed`] from every command-driven
/// mutation site (scene-driven mutations skip the call so SceneValid
/// stays true through the recall).
///
/// Implementations MUST be cheap and re-entrant — they run inline on
/// the command-handler path.
pub trait SceneInvalidator {
    /// Flip `SceneValid → false` for every recalled scene on
    /// `endpoint_id`, across all fabrics. No-op when no fabric has a
    /// scene recalled there.
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

// TLV round-trip used by the persistence layer. The whole
// `ScenesStateInner` is persisted as a single TLV struct under
// `SCENES_KEY`. `info_dataver` is not persisted (the public `Dataver`
// is re-randomized at boot anyway).
//
// Hand-rolled because the inner types are const-generic and the
// derive macro doesn't yet support that. The on-disk shape is
// private to this module and only needs to round-trip across
// successive runs of the same firmware.

impl<const M: usize> ToTLV for SceneEntry<M> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.start_struct(tag)?;
        self.fab_idx.to_tlv(&TLVTag::Context(0), &mut tw)?;
        self.endpoint_id.to_tlv(&TLVTag::Context(1), &mut tw)?;
        self.group_id.to_tlv(&TLVTag::Context(2), &mut tw)?;
        self.scene_id.to_tlv(&TLVTag::Context(3), &mut tw)?;
        self.transition_time.to_tlv(&TLVTag::Context(4), &mut tw)?;
        // EFS bytes go on the wire as one octet string — not an
        // array-of-u8 (which is what the blanket `Vec<u8, M>: ToTLV`
        // would emit).
        tw.str(&TLVTag::Context(5), &self.extension_fields)?;
        tw.end_container()
    }

    fn tlv_iter(&self, _tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        // Persistence goes through `to_tlv`; this is just here to
        // satisfy the trait bound.
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
            info_dataver: 0,
        })
    }
}

impl<const N: usize, const M: usize> ScenesState<N, M> {
    /// Re-hydrate the scene table and per-fabric `CurrentScene`
    /// bookkeeping from `store` under [`SCENES_KEY`]. Call once at
    /// application startup, before exposing the data model to
    /// commissioners. A missing key (first boot or cleared
    /// persistence) leaves the registry empty.
    pub async fn load_persist<S: KvBlobStore>(
        &self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let Some(data) = store.load(SCENES_KEY, buf)? else {
            // Reset to empty so a `load_persist` after a key
            // `remove` is deterministic.
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

    /// Persist the current state under [`SCENES_KEY`]. Called from
    /// every mutating handler path after the in-memory change is
    /// committed.
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
/// Generic over a tuple-recursive registry `R: SceneClusters` of the
/// scene-aware cluster handlers that participate in scene capture /
/// recall on this device:
///
/// ```ignore
/// let scenes = ScenesHandler::new(
///     dataver,
///     &scenes_state,
///     (&on_off_handler, (&level_control_handler, ())),
/// );
/// ```
///
/// The default `R = ()` builds a Scenes handler with no scene-aware
/// clusters — useful for testing the table-management commands in
/// isolation. `M` matches the same const generic on [`ScenesState`].
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

    /// Per-fabric `RemainingCapacity` for `GetSceneMembership` and
    /// `FabricSceneInfo`. Formula matches chip's reference:
    /// `(N - 1) / 2 - scenes_in_fab`, clamped by the total free
    /// slots across all fabrics, then clamped to `u8`.
    fn remaining_capacity_for_fab(inner: &ScenesStateInner<N, M>, fab_idx: NonZeroU8) -> u8 {
        let per_fab_budget = N.saturating_sub(1) / 2;
        let used = inner.table.iter().filter(|e| e.fab_idx == fab_idx).count();
        let per_fab_remaining = per_fab_budget.saturating_sub(used);
        let global_remaining = N.saturating_sub(inner.table.len());
        per_fab_remaining.min(global_remaining).min(0xFF) as u8
    }

    /// `true` if `group_id` is present in the Groups cluster's Group
    /// Table for `(fab_idx, endpoint_id)`. `group_id == 0` ("no
    /// group") is always valid. Group-aware Scenes commands return
    /// `INVALID_COMMAND` on `false`.
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

    /// Stamp `(endpoint, group, scene)` as the recalled scene for
    /// `fab_idx` with `SceneValid = true`. Bumps `FabricSceneInfo`
    /// dataver. Operates on already-locked inner state.
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

    /// Flip `SceneValid → false` for `fab_idx` only when the
    /// recalled scene's `(group, scene)` matches the operation's
    /// target — i.e. an `AddScene` / `StoreScene` / `RemoveScene` /
    /// single-target `CopyScene` that actually touches the recalled
    /// scene. Other-scene operations leave `SceneValid` alone, per
    /// Matter Core Spec. Operates on already-locked inner state.
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

    /// Flip `SceneValid → false` for `fab_idx` when the recalled
    /// scene's group matches the operation's group — used by
    /// `RemoveAllScenes` and `COPY_ALL` `CopyScene`. The slot keeps
    /// `CurrentScene` / `CurrentGroup` populated so the fabric stays
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

    /// Body of `CopyScene` against an already-locked
    /// [`ScenesStateInner`]. Returns the IM status code (0 on
    /// success). In-place index walk: pushes destination rows go to
    /// `group_to`, never match the `group_from` filter, so the loop
    /// converges. Worst case is O(N²) on the inner `position` lookup,
    /// which is fine for the small `N` this cluster carries.
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
        // Per-fab capacity gate up front: at-cap rejects the copy
        // even when the destination already exists and would
        // otherwise be a no-growth overwrite. Matches chip's
        // reference.
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
                // Clone the source row's scalars + EFS blob so the
                // table can be re-borrowed mutably for the upsert.
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
                    // Re-check per-fab capacity for each new push —
                    // earlier pushes in this loop may have exhausted
                    // the fabric's budget.
                    if Self::remaining_capacity_for_fab(inner, fab_idx) == 0 {
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

                // Single-scene mode copies exactly one entry.
                if !copy_all {
                    break;
                }
            }
            idx += 1;
        }

        if !found_source {
            return SC_NOT_FOUND;
        }

        // Invalidate `CurrentScene` only if the copy actually
        // touched the recalled scene.
        if copy_all {
            Self::invalidate_current_if_match_group(inner, fab_idx, group_to);
        } else {
            Self::invalidate_current_if_match_scene(inner, fab_idx, group_to, scene_to);
        }
        0
    }

    // Handler bodies. The `ClusterAsyncHandler` impl below wraps
    // these in `fn -> impl Future { ready(self.foo(...)) }` to keep
    // the real logic synchronous — saves the `async fn` state-machine
    // codegen, matters on flash-constrained targets. `store_scene`
    // is the exception (cross-cluster attribute reads need `.await`).

    fn read_fabric_scene_info<P: TLVBuilderParent>(
        &self,
        ctx: &impl ReadContext,
        builder: ArrayAttributeRead<SceneInfoStructArrayBuilder<P>, SceneInfoStructBuilder<P>>,
    ) -> Result<P, Error> {
        let endpoint_id = ctx.attr().endpoint_id;
        let accessor_fab_idx = ctx.exchange().accessor()?.fab_idx()?;

        // Snapshot the relevant scalars under a single lock, then
        // build the response outside the lock. A fabric gets a row
        // once it has at least one scene OR has ever recalled one
        // (the `current_per_fabric` slot persists past invalidation
        // so the row stays present after the last scene is removed).
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
                let has_state = count > 0 || current.is_some();
                // `CurrentScene` / `CurrentGroup` are always
                // populated when a row is emitted — 0 when the
                // fabric has never recalled a scene.
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

        // Bad request shape (reserved scene id or oversized
        // transition) takes precedence over the group-table check.
        if scene_id == GLOBAL_SCENE_ID
            || scene_id == RESERVED_SCENE_ID
            || transition_time > MAX_TRANSITION_TIME_MS
        {
            return response
                .status(SC_CONSTRAINT_ERROR)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .end();
        }

        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_id)? {
            return response
                .status(SC_INVALID_COMMAND)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .end();
        }

        // EFS array payload — stored as the array's value bytes
        // (between control byte and terminator) so `ViewScene` /
        // `CopyScene` can splice it back at the response tag. A
        // missing field is treated as empty. Scene names are
        // accepted on the wire but not stored.
        let efs_array_opt = request.extension_field_set_structs().ok();
        let raw = match efs_array_opt {
            Some(ref array) => array.element().raw_value()?,
            None => &[],
        };

        // Every AVP referencing a registered cluster must be
        // scenable on that cluster — otherwise `INVALID_COMMAND`.
        // Unregistered clusters are lenient: store the bytes,
        // silently skip on recall (matches chip on firmware
        // downgrade).
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

        // An oversized EFS payload is a per-scene capacity failure,
        // surfaced via `SC_INSUFFICIENT_SPACE` (not a transaction error).
        if raw.len() > M {
            return response
                .status(SC_INSUFFICIENT_SPACE)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .end();
        }

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

    /// Insert (or replace) one scene record. `fill` populates the
    /// slot's `extension_fields` `Vec` directly (avoiding an
    /// intermediate stack copy of up to `M` bytes). Returns `Ok(0)`
    /// on success, `Ok(SC_INSUFFICIENT_SPACE)` when a *new* record
    /// would overflow `N`. Errors from `fill` propagate.
    ///
    /// On the replace-existing path the previous `extension_fields`
    /// are cleared before `fill` runs — a `fill` failure leaves the
    /// slot with an empty blob (acceptable; in-tree callers use
    /// `extend_from_slice` which is all-or-nothing).
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
            // `push_init_unchecked` only panics when full, and the
            // `else if` above just checked `len < N`.
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

        // `SceneID = 0x00` (Global Scene) and `0xFF` are reserved.
        if scene_id == GLOBAL_SCENE_ID || scene_id == RESERVED_SCENE_ID {
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

        // Build the response inside the lock so the stored
        // `extension_fields` slice can be spliced without cloning.
        // The builder chain is sync; holding the mutex is fine.
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

    /// Splice the stored EFS blob into the response at context tag 5
    /// (the `ExtensionFieldSetStructs` field). The blob is the array
    /// container's value bytes (contents + terminator). Empty blob
    /// ⇒ skip the field via `OptionalBuilder::none`.
    fn write_blob_or_none<P, Q>(mut opt: OptionalBuilder<P, Q>, blob: &[u8]) -> Result<P, Error>
    where
        P: TLVBuilderParent,
        Q: TLVBuilder<P>,
    {
        if !blob.is_empty() {
            let writer = opt.writer();
            writer.start_array(&TLVTag::Context(5))?;
            writer.write_raw_data(blob.iter().copied())?;
        }
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

        // `SceneID = 0x00` (Global Scene) and `0xFF` are reserved.
        if scene_id == GLOBAL_SCENE_ID || scene_id == RESERVED_SCENE_ID {
            return response
                .status(SC_CONSTRAINT_ERROR)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .end();
        }

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

    /// `StoreScene` capture + commit. Walks the
    /// [`SceneClusters`] registry, builds an EFS blob on a stack
    /// buffer, and upserts the result into the table.
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

        // `SceneID = 0x00` (Global Scene) and `0xFF` are reserved.
        if scene_id == GLOBAL_SCENE_ID || scene_id == RESERVED_SCENE_ID {
            return response
                .status(SC_CONSTRAINT_ERROR)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .end();
        }

        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_id)? {
            return response
                .status(SC_INVALID_COMMAND)?
                .group_id(group_id)?
                .scene_id(scene_id)?
                .end();
        }

        // Capture each scene-aware cluster's EFS struct into the
        // scratch buffer. `SceneClusters::capture` writes each struct
        // directly (no outer `start_array` byte); we append the
        // trailing array terminator ourselves so the result matches
        // `SceneEntry::extension_fields`'s "contents + 0x18" shape.
        let mut scratch = [0u8; M];
        let total_len = {
            let mut wb = WriteBuf::new(&mut scratch);
            let parent = TLVWriteParent::new("StoreScene EFS", &mut wb);
            let _ = self.clusters.capture(endpoint_id, parent)?;
            wb.end_container()?;
            wb.get_tail()
        };
        let stored_bytes = &scratch[..total_len];

        // Reuse the prior record's transition_time when overwriting;
        // 0 for a fresh record (spec leaves it implementation-defined).
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
            // The stored scene by definition matches current state,
            // so promote `(group, scene)` to the recalled scene with
            // `SceneValid=true` — overriding any invalidation
            // `upsert_scene` may have just performed on a re-store
            // of the previously-recalled entry.
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

    /// `RecallScene` parse + apply: snapshot the stored EFS under
    /// the mutex, drop the mutex, walk the EFS blob and let the
    /// cluster registry apply each entry, then commit `CurrentScene`
    /// for this fabric.
    async fn recall_scene(
        &self,
        ctx: &impl InvokeContext,
        request: &RecallSceneRequest<'_>,
    ) -> Result<(), Error> {
        let fab_idx = Self::fab_idx(ctx)?;
        let endpoint_id = ctx.cmd().endpoint_id;
        let group_id = request.group_id()?;
        let scene_id = request.scene_id()?;

        // `RecallScene` has no response struct (returns `()`), so
        // the spec status comes out as an IM-level
        // `CommandStatusIB.status` via `Err(ErrorCode::*)`. The
        // `ErrorCode → IMStatusCode` map in `im.rs` produces the
        // right wire codes; `set_cluster_status` would wrap as
        // `FAILURE` and chip-tool's certification suites reject that
        // shape.

        // `SceneID = 0x00` (Global Scene) and `0xFF` are reserved.
        if scene_id == GLOBAL_SCENE_ID || scene_id == RESERVED_SCENE_ID {
            return Err(ErrorCode::ConstraintError.into());
        }

        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_id)? {
            return Err(ErrorCode::InvalidCommand.into());
        }

        // The request's optional+nullable `transition_time` override
        // wins when present; otherwise fall back to the stored value.
        let override_tt_ms: Option<u32> = request.transition_time()?.and_then(|n| n.into_option());

        // Copy the stored EFS blob into a stack buffer under the
        // lock, then drop the lock so cross-cluster work below
        // doesn't run with it held. `TLVSequence` walks the stored
        // "EFS structs + 0x18 terminator" shape directly — no need
        // to re-attach the missing `start_array(Anonymous)` byte.
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
            return Err(ErrorCode::NotFound.into());
        };

        let effective_tt_ms = override_tt_ms.unwrap_or(stored_tt_ms);

        for efs_element in TLVSequence(&blob[..blob_len]).iter() {
            let efs = ExtensionFieldSetStruct::new(efs_element?);
            let cluster_id = efs.cluster_id()?;
            let avp_list = efs.attribute_value_list()?;
            // Unknown cluster IDs (firmware downgrade that dropped a
            // scenable cluster) are silently skipped by `apply`.
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

        // Reject unknown group with `INVALID_COMMAND`; spec allows
        // `null` for `Capacity` on this failure path.
        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_id)? {
            return response
                .status(SC_INVALID_COMMAND)?
                .capacity(Nullable::none())?
                .group_id(group_id)?
                .scene_list()?
                .none()
                .end();
        }

        // Build the response inside the lock so scene IDs can be
        // streamed directly without snapshotting into a stack `Vec`.
        // `SceneList` is always emitted on the success path (empty
        // when the group has no scenes on this endpoint).
        self.state.with(|inner| -> Result<P, Error> {
            let remaining = Self::remaining_capacity_for_fab(inner, fab_idx);

            let resp = response
                .status(0)?
                .capacity(Nullable::some(remaining))?
                .group_id(group_id)?;

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

        // `CopyModeBitmap` bit 0 = COPY_ALL_SCENES (From/To
        // SceneIDs are ignored in this mode).
        let copy_all = (mode.bits() & 0x01) != 0;

        // Reserved `SceneID`s (Global Scene `0x00`, `0xFF`) are only
        // invalid in single-scene mode (COPY_ALL ignores those fields).
        if !copy_all
            && (scene_from == GLOBAL_SCENE_ID
                || scene_from == RESERVED_SCENE_ID
                || scene_to == GLOBAL_SCENE_ID
                || scene_to == RESERVED_SCENE_ID)
        {
            return response
                .status(SC_CONSTRAINT_ERROR)?
                .group_identifier_from(group_from)?
                .scene_identifier_from(scene_from)?
                .end();
        }

        if !Self::group_in_table(ctx, fab_idx, endpoint_id, group_from)?
            || !Self::group_in_table(ctx, fab_idx, endpoint_id, group_to)?
        {
            return response
                .status(SC_INVALID_COMMAND)?
                .group_identifier_from(group_from)?
                .scene_identifier_from(scene_from)?
                .end();
        }

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

    async fn handle_store_scene<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: StoreSceneRequest<'_>,
        response: StoreSceneResponseBuilder<P>,
    ) -> Result<P, Error> {
        self.store_scene(&ctx, &request, response).await
    }

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
    //! Unit tests for the Scenes Management internals — primarily
    //! [`ScenesHandler::copy_scenes_inner`] (in-place upsert loop
    //! over a shared table) and the `CurrentScene` invalidation
    //! rules. Tests operate on [`ScenesStateInner`] directly, no
    //! `Matter` / `InvokeContext` setup needed.

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

    /// Variant of [`entry`] that stamps an arbitrary EFS blob.
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

    // ---- extension-fields blob preservation ----

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
        // copy's target (20, 7). Per Matter spec,
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

    // ---- AddScene / StoreScene shared `upsert_scene` path ----

    /// Fill closure that copies a fixed slice into the slot Vec.
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
        // Per Matter App Cluster spec, `SceneValid` is only
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
        // Non-matching upsert MUST leave `SceneValid` intact.
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
