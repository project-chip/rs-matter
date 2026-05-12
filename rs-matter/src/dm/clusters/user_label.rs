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

//! UserLabel cluster handler (Matter Application Cluster spec §9.7).
//!
//! The UserLabel cluster lets a commissioner persist a free-form list of
//! `(label, value)` string pairs on an endpoint — typical use is the
//! commissioner letting the user tag a device with metadata such as
//! `"room"` → `"living room"` or `"orientation"` → `"east"`. The list is
//! per-endpoint and *not* fabric-scoped: every fabric that has access
//! sees the same list (subject to the usual ACL rules — `LabelList` reads
//! at view-privilege, writes at manage-privilege).
//!
//! Spec §9.7.5 requires the `LabelList` to persist across reboots.
//! Persistence is implemented by [`UserLabels`], a registry that holds
//! every endpoint's `LabelList` and serialises the lot under a single
//! KV key ([`USER_LABELS_KEY`]) on every mutation. Each endpoint that
//! advertises the UserLabel cluster gets its own [`UserLabelHandler`]
//! facade (so the per-cluster-instance `Dataver` stays granular per
//! Matter Core spec §7.13.2.1), and all facades share one `UserLabels`
//! by reference.
//!
//! Application wiring:
//!
//! ```ignore
//! // One registry, sized for up to `E` endpoints, each holding up to `N` labels.
//! let labels = UserLabels::<2, 4>::new();
//! labels.load_persist(&mut kv, kv_buf).await?;
//!
//! let ep0_handler = UserLabelHandler::new(Dataver::new_rand(rand), 0, &labels);
//! let ep1_handler = UserLabelHandler::new(Dataver::new_rand(rand), 1, &labels);
//! ```

use crate::dm::{
    ArrayAttributeRead, ArrayAttributeWrite, Cluster, Dataver, EndptId, ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::persist::{KvBlobStore, Persist};
use crate::tlv::{FromTLV, TLVArray, TLVBuilderParent, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::with;

pub use crate::dm::clusters::decl::globals::{
    LabelStruct, LabelStructArrayBuilder, LabelStructBuilder,
};
pub use crate::dm::clusters::decl::user_label::*;
pub use crate::persist::USER_LABELS_KEY;

/// Cluster metadata exposed by [`UserLabelHandler`] regardless of the
/// const-generic parameters.
///
/// Exposed as a free constant so callers don't have to spell out the
/// generic parameters of [`UserLabelHandler`] when they just want the
/// cluster ID for an `EpClMatcher` or a `clusters!(...)` literal.
pub const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

/// Maximum length of a single `label` string, in characters.
/// Per Matter Application Cluster spec §9.6.4 (`LabelStruct`): 16 chars.
pub const MAX_LABEL_LEN: usize = 16;

/// Maximum length of a single `value` string, in characters.
/// Per Matter Application Cluster spec §9.6.4 (`LabelStruct`): 16 chars.
pub const MAX_VALUE_LEN: usize = 16;

/// One entry in a `LabelList`.
///
/// Named struct (rather than a tuple) so the `derive(FromTLV, ToTLV)`
/// pair gives us a stable persisted shape for free — the on-disk
/// representation matches the Matter spec's `LabelStruct` field layout
/// (`label` at tag 0, `value` at tag 1).
#[derive(Debug, Clone, PartialEq, Eq, FromTLV, ToTLV)]
pub struct LabelEntry {
    pub label: heapless::String<MAX_LABEL_LEN>,
    pub value: heapless::String<MAX_VALUE_LEN>,
}

/// One slot in the persisted [`UserLabels`] blob: the `LabelList` for a
/// specific endpoint. The TLV impls are hand-rolled (rather than
/// `#[derive(FromTLV, ToTLV)]`) because the derive macro doesn't yet
/// support const-generic structs. Wire format is a struct with two
/// context-tagged fields:
/// - `0`: `endpoint_id` (`u16`)
/// - `1`: `entries` (TLV array of `LabelEntry`)
///
/// No spec dictates this layout; it just needs to be internally
/// consistent between [`Self::to_tlv`] and [`Self::from_tlv`].
#[derive(Debug, Clone)]
struct EndpointLabels<const N: usize> {
    endpoint_id: EndptId,
    entries: Vec<LabelEntry, N>,
}

impl<const N: usize> ToTLV for EndpointLabels<N> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.start_struct(tag)?;
        self.endpoint_id.to_tlv(&TLVTag::Context(0), &mut tw)?;
        self.entries.to_tlv(&TLVTag::Context(1), &mut tw)?;
        tw.end_container()
    }

    fn tlv_iter(&self, _tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        // Not used by `Persist::store_tlv` — that goes through
        // `to_tlv` above. Returning an empty iterator keeps the trait
        // bound satisfied without dragging in extra machinery.
        core::iter::empty()
    }
}

impl<'a, const N: usize> FromTLV<'a> for EndpointLabels<N> {
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        let s = element.structure()?;
        Ok(Self {
            endpoint_id: EndptId::from_tlv(&s.ctx(0)?)?,
            entries: Vec::<LabelEntry, N>::from_tlv(&s.ctx(1)?)?,
        })
    }
}

/// Shared registry of every endpoint's UserLabel `LabelList`.
///
/// Persisted as a single TLV blob under [`USER_LABELS_KEY`] — every
/// successful write to any [`UserLabelHandler`] re-serialises the whole
/// registry and stores it. Read paths take the lock briefly to copy
/// labels into the TLV builder.
///
/// Const generics:
/// - `E` — max number of endpoints that may have a `LabelList`. Bound
///   on the in-memory `Vec` of per-endpoint slots.
/// - `N` — max number of `LabelEntry` rows per endpoint. Bound on each
///   slot's inner `Vec`. Defaults to 4.
///
/// Lock holds are bounded — the `Mutex<RefCell<_>>` is never held
/// across an `.await`, so the registry is sound under a work-stealing
/// executor.
pub struct UserLabels<const E: usize, const N: usize = 4> {
    state: Mutex<RefCell<Vec<EndpointLabels<N>, E>>>,
}

impl<const E: usize, const N: usize> UserLabels<E, N> {
    /// Create an empty registry. Call [`Self::load_persist`] at
    /// application startup to populate it from KV.
    ///
    /// Prefer [`Self::init`] for non-trivial `E` * `N` so the
    /// registry's storage can be initialised in-place (typically in a
    /// `StaticCell`) instead of being constructed on the stack and
    /// moved. The two paths produce structurally identical instances.
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(Vec::new())),
        }
    }

    /// Return an in-place initialiser for an empty registry. Use this
    /// when `E` * `N` * `size_of::<LabelEntry>` is large enough that
    /// stack-constructing a [`Self::new`] instance and moving it into
    /// long-lived storage would overflow the stack or bloat
    /// `.rodata`. Typical usage:
    ///
    /// ```ignore
    /// static USER_LABELS: StaticCell<UserLabels<8, 4>> = StaticCell::new();
    /// let user_labels = USER_LABELS.uninit().init_with(UserLabels::init());
    /// ```
    pub fn init() -> impl Init<Self> {
        init!(Self {
            state <- Mutex::init(RefCell::init(Vec::init())),
        })
    }

    /// Re-hydrate the registry from `store` under [`USER_LABELS_KEY`].
    /// Call once at application startup, before exposing the data
    /// model to commissioners, so subsequent reads see the labels
    /// written before the last reboot.
    ///
    /// Missing key (first boot, or persistence cleared) is not an
    /// error — the registry simply stays empty.
    pub async fn load_persist<S: KvBlobStore>(
        &self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let Some(data) = store.load(USER_LABELS_KEY, buf)? else {
            // No prior persistence — reset to empty so re-calling
            // `load_persist` after a `remove` of the key behaves
            // deterministically.
            self.state.lock(|cell| cell.borrow_mut().clear());
            return Ok(());
        };

        let loaded = Vec::<EndpointLabels<N>, E>::from_tlv(&TLVElement::new(data))?;

        self.state.lock(|cell| *cell.borrow_mut() = loaded);

        info!("Loaded UserLabel entries for all endpoints from storage");

        Ok(())
    }

    /// Serialise the current registry to `ctx.kv()` under
    /// [`USER_LABELS_KEY`]. Called from every mutating handler path
    /// after the in-memory change is committed.
    fn store_persist<C: WriteContext>(&self, ctx: &C) -> Result<(), Error> {
        let mut persist = Persist::new(ctx.kv());

        self.state.lock(|cell| {
            let state = cell.borrow();
            persist.store_tlv(USER_LABELS_KEY, &*state)
        })?;

        persist.run()
    }

    /// Run a closure with read-only access to the `LabelList` for
    /// `endpoint_id`. The closure receives an empty slice if the
    /// endpoint has no entries (or isn't registered yet).
    fn with_entries<R>(
        &self,
        endpoint_id: EndptId,
        f: impl FnOnce(&[LabelEntry]) -> Result<R, Error>,
    ) -> Result<R, Error> {
        self.state.lock(|cell| {
            let state = cell.borrow();
            match state.iter().find(|slot| slot.endpoint_id == endpoint_id) {
                Some(slot) => f(slot.entries.as_slice()),
                None => f(&[]),
            }
        })
    }

    /// Replace this endpoint's entire `LabelList` with the entries
    /// produced by the provided iterator. The new list is validated
    /// up front (each entry against the spec length limits) before
    /// any in-memory state changes; on success the whole registry is
    /// re-persisted.
    fn replace_entries<'a, C: WriteContext>(
        &self,
        ctx: &C,
        endpoint_id: EndptId,
        list: &TLVArray<'a, LabelStruct<'a>>,
    ) -> Result<(), Error> {
        // Two-pass validation: count + spec checks first, so a
        // malformed input never partially mutates the registry.
        let mut count = 0usize;
        for entry in list {
            let entry = entry?;
            Self::validate_entry(&entry)?;
            count += 1;
            if count > N {
                return Err(ErrorCode::ResourceExhausted.into());
            }
        }

        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            let slot = Self::slot_mut(&mut state, endpoint_id)?;
            slot.entries.clear();
            for entry in list {
                let entry = entry?;
                let (label, value) = Self::validate_entry(&entry)?;
                Self::push_into(&mut slot.entries, label, value)?;
            }
            Ok::<_, Error>(())
        })?;

        self.store_persist(ctx)
    }

    /// Append one entry to this endpoint's `LabelList`. Validates the
    /// spec length limits, then persists.
    fn add_entry<'a, C: WriteContext>(
        &self,
        ctx: &C,
        endpoint_id: EndptId,
        entry: &LabelStruct<'a>,
    ) -> Result<(), Error> {
        let (label, value) = Self::validate_entry(entry)?;

        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            let slot = Self::slot_mut(&mut state, endpoint_id)?;
            Self::push_into(&mut slot.entries, label, value)
        })?;

        self.store_persist(ctx)
    }

    /// Return a mutable reference to the slot for `endpoint_id`,
    /// inserting an empty slot if necessary.
    fn slot_mut(
        state: &mut Vec<EndpointLabels<N>, E>,
        endpoint_id: EndptId,
    ) -> Result<&mut EndpointLabels<N>, Error> {
        if let Some(idx) = state.iter().position(|s| s.endpoint_id == endpoint_id) {
            return Ok(&mut state[idx]);
        }
        state
            .push(EndpointLabels {
                endpoint_id,
                entries: Vec::new(),
            })
            .map_err(|_| ErrorCode::ResourceExhausted)?;
        // `push` succeeded → the new slot is the last element.
        Ok(state.last_mut().expect("just pushed"))
    }

    /// Validate a single `LabelStruct` against the spec length limits.
    /// Returns `ConstraintError` when the entry violates the limits —
    /// `TestUserLabelClusterConstraints` writes oversized entries and
    /// expects this exact failure mode.
    fn validate_entry<'a>(entry: &'a LabelStruct<'a>) -> Result<(&'a str, &'a str), Error> {
        let label = entry.label()?;
        let value = entry.value()?;
        if label.len() > MAX_LABEL_LEN || value.len() > MAX_VALUE_LEN {
            return Err(ErrorCode::ConstraintError.into());
        }
        Ok((label, value))
    }

    /// Push a `(label, value)` pair into a bounded vec. Returns
    /// `ResourceExhausted` when the vec is full.
    fn push_into(list: &mut Vec<LabelEntry, N>, label: &str, value: &str) -> Result<(), Error> {
        let label = heapless::String::try_from(label).map_err(|_| ErrorCode::ConstraintError)?;
        let value = heapless::String::try_from(value).map_err(|_| ErrorCode::ConstraintError)?;
        list.push(LabelEntry { label, value })
            .map_err(|_| ErrorCode::ResourceExhausted)?;
        Ok(())
    }
}

impl<const E: usize, const N: usize> Default for UserLabels<E, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-`(endpoint, UserLabel)`-instance handler facade. Owns the
/// cluster's `Dataver` and is bound to one `endpoint_id`; the actual
/// state lives in the shared [`UserLabels`] registry the facade points
/// at. Multiple facades may reference the same registry — that's how
/// a multi-endpoint device shares one persisted blob.
pub struct UserLabelHandler<'a, const E: usize, const N: usize = 4> {
    dataver: Dataver,
    endpoint_id: EndptId,
    labels: &'a UserLabels<E, N>,
}

impl<'a, const E: usize, const N: usize> UserLabelHandler<'a, E, N> {
    /// Construct a facade for `(endpoint_id, UserLabel)` backed by the
    /// shared `labels` registry.
    pub const fn new(dataver: Dataver, endpoint_id: EndptId, labels: &'a UserLabels<E, N>) -> Self {
        Self {
            dataver,
            endpoint_id,
            labels,
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl<const E: usize, const N: usize> ClusterHandler for UserLabelHandler<'_, E, N> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn label_list<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<LabelStructArrayBuilder<P>, LabelStructBuilder<P>>,
    ) -> Result<P, Error> {
        self.labels
            .with_entries(self.endpoint_id, |entries| match builder {
                ArrayAttributeRead::ReadAll(mut array) => {
                    for entry in entries {
                        array = array
                            .push()?
                            .label(entry.label.as_str())?
                            .value(entry.value.as_str())?
                            .end()?;
                    }
                    array.end()
                }
                ArrayAttributeRead::ReadOne(index, item) => {
                    let Some(entry) = entries.get(index as usize) else {
                        return Err(ErrorCode::ConstraintError.into());
                    };
                    item.label(entry.label.as_str())?
                        .value(entry.value.as_str())?
                        .end()
                }
                ArrayAttributeRead::ReadNone(array) => array.end(),
            })
    }

    fn set_label_list(
        &self,
        ctx: impl WriteContext,
        value: ArrayAttributeWrite<TLVArray<'_, LabelStruct<'_>>, LabelStruct<'_>>,
    ) -> Result<(), Error> {
        match value {
            ArrayAttributeWrite::Replace(list) => {
                self.labels.replace_entries(&ctx, self.endpoint_id, &list)
            }
            ArrayAttributeWrite::Add(entry) => {
                self.labels.add_entry(&ctx, self.endpoint_id, &entry)
            }
            // The Matter Core spec (V1.4.2 §10.6.4.3.1) does not yet
            // support per-element list update / remove writes — the
            // framework already converts these to `InvalidAction` before
            // the value reaches us, but match exhaustively to be safe.
            ArrayAttributeWrite::Update(_, _) | ArrayAttributeWrite::Remove(_) => {
                Err(ErrorCode::InvalidAction.into())
            }
        }
    }
}
