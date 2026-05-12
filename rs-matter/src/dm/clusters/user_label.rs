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
//! [`UserLabelHandler`] ships with bounded in-memory storage. Persistence
//! across reboots — which the spec requires (§9.7.5) — is not yet wired:
//! applications that need the labels to survive restart need to subscribe
//! to writes via `Matter::subscribe_changes` and store the values in
//! their own KV blob, or extend this handler with an explicit storage
//! hook trait. The CI test
//! [`TestUserLabelClusterConstraints`](`https://github.com/project-chip/connectedhomeip/blob/master/src/app/tests/suites/TestUserLabelClusterConstraints.yaml`)
//! exercises only the in-session length-constraint behaviour and passes
//! against this implementation; the `TestUserLabelCluster` YAML — which
//! includes a Reboot-and-read-back step — does not yet pass and remains
//! commented out in `xtask/src/itest.rs`.

use core::cell::RefCell;

use crate::dm::{
    ArrayAttributeRead, ArrayAttributeWrite, Cluster, Dataver, ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVArray, TLVBuilderParent};
use crate::utils::sync::blocking::Mutex;
use crate::with;

pub use crate::dm::clusters::decl::globals::{
    LabelStruct, LabelStructArrayBuilder, LabelStructBuilder,
};
pub use crate::dm::clusters::decl::user_label::*;

/// Cluster metadata exposed by [`UserLabelHandler`] regardless of the
/// `N` capacity parameter.
///
/// Equivalent to `<UserLabelHandler<N> as ClusterHandler>::CLUSTER` for
/// any `N`, exposed here as a free constant so callers don't have to
/// spell out the generic parameter when they just want the cluster ID
/// for an `EpClMatcher` or a `clusters!(...)` literal.
pub const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

/// Maximum length of a single `label` string, in characters.
/// Per Matter Application Cluster spec §9.6.4 (`LabelStruct`): 16 chars.
pub const MAX_LABEL_LEN: usize = 16;

/// Maximum length of a single `value` string, in characters.
/// Per Matter Application Cluster spec §9.6.4 (`LabelStruct`): 16 chars.
pub const MAX_VALUE_LEN: usize = 16;

/// One entry in a `LabelList`.
type LabelEntry = (
    heapless::String<MAX_LABEL_LEN>,
    heapless::String<MAX_VALUE_LEN>,
);

/// The handler for the UserLabel Matter cluster.
///
/// Per-endpoint instance: each endpoint that advertises the UserLabel
/// cluster must own a separate `UserLabelHandler` so the per-endpoint
/// `LabelList` stays segregated.
///
/// `N` (default 4) sets the maximum number of entries the list can hold;
/// writes that exceed it are rejected with `ErrorCode::ResourceExhausted`,
/// which the framework maps to the IM `ResourceExhausted` status. This
/// matches the `TestUserLabelClusterConstraints` test's expectation of
/// rejecting an oversized list.
///
/// Concurrency: the entry list is wrapped in a blocking [`Mutex`] +
/// `RefCell` so the handler is sound under a future work-stealing executor
/// configuration of rs-matter. Lock holds are bounded — the lock is
/// *never* held across `.await` points (this is a sync `ClusterHandler`
/// in the first place, so there are no `.await`s).
///
/// Dataver is bumped automatically by the framework after each write/invoke
/// and on every `notify_attr_changed`; this handler never calls
/// `dataver_changed()` directly.
pub struct UserLabelHandler<const N: usize = 4> {
    dataver: Dataver,
    entries: Mutex<RefCell<heapless::Vec<LabelEntry, N>>>,
}

impl<const N: usize> UserLabelHandler<N> {
    /// Creates a new `UserLabelHandler` with an empty `LabelList`.
    pub const fn new(dataver: Dataver) -> Self {
        Self {
            dataver,
            entries: Mutex::new(RefCell::new(heapless::Vec::new())),
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
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

    /// Push a `(label, value)` pair into a `Vec`. Returns
    /// `ResourceExhausted` when the bounded vec is full.
    fn push_into(
        list: &mut heapless::Vec<LabelEntry, N>,
        label: &str,
        value: &str,
    ) -> Result<(), Error> {
        let mut entry = (
            heapless::String::<MAX_LABEL_LEN>::new(),
            heapless::String::<MAX_VALUE_LEN>::new(),
        );
        // `push_str` on `heapless::String` returns `Err(())` on overflow.
        // We've already validated lengths above, so this can only fail if
        // the bounds change without `validate_entry` being updated.
        entry
            .0
            .push_str(label)
            .map_err(|_| ErrorCode::ConstraintError)?;
        entry
            .1
            .push_str(value)
            .map_err(|_| ErrorCode::ConstraintError)?;
        list.push(entry).map_err(|_| ErrorCode::ResourceExhausted)?;
        Ok(())
    }
}

impl<const N: usize> ClusterHandler for UserLabelHandler<N> {
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
        self.entries.lock(|cell| {
            let entries = cell.borrow();
            match builder {
                ArrayAttributeRead::ReadAll(mut array) => {
                    for (label, value) in entries.iter() {
                        array = array
                            .push()?
                            .label(label.as_str())?
                            .value(value.as_str())?
                            .end()?;
                    }
                    array.end()
                }
                ArrayAttributeRead::ReadOne(index, item) => {
                    let Some((label, value)) = entries.get(index as usize) else {
                        return Err(ErrorCode::ConstraintError.into());
                    };
                    item.label(label.as_str())?.value(value.as_str())?.end()
                }
                ArrayAttributeRead::ReadNone(array) => array.end(),
            }
        })
    }

    fn set_label_list(
        &self,
        _ctx: impl WriteContext,
        value: ArrayAttributeWrite<TLVArray<'_, LabelStruct<'_>>, LabelStruct<'_>>,
    ) -> Result<(), Error> {
        match value {
            ArrayAttributeWrite::Replace(list) => {
                // Two-pass: validate every entry first so we never end up
                // with a partially-applied list on a malformed input. If
                // validation passes we know `push_into` will succeed for
                // every entry up to the capacity bound. Mirrors
                // `acl::AclHandler::set_acl`'s validate-then-commit shape.
                let mut count = 0usize;
                for entry in &list {
                    let entry = entry?;
                    Self::validate_entry(&entry)?;
                    count += 1;
                    if count > N {
                        return Err(ErrorCode::ResourceExhausted.into());
                    }
                }

                self.entries.lock(|cell| {
                    let mut entries = cell.borrow_mut();
                    entries.clear();
                    for entry in &list {
                        // unwrap-equivalent is safe: we validated each
                        // entry above and the count is within capacity.
                        let entry = entry?;
                        let (label, value) = Self::validate_entry(&entry)?;
                        Self::push_into(&mut entries, label, value)?;
                    }
                    Ok(())
                })
            }
            ArrayAttributeWrite::Add(entry) => {
                let (label, value) = Self::validate_entry(&entry)?;
                self.entries
                    .lock(|cell| Self::push_into(&mut cell.borrow_mut(), label, value))
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
