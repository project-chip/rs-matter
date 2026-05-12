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

//! FixedLabel cluster handler (Matter Application Cluster spec §9.8).
//!
//! Per-endpoint **read-only** list of `(label, value)` string pairs
//! that the manufacturer bakes into the device firmware — typical use
//! is exposing immutable tags such as `"serial"` → `"abc123"` or
//! `"hwrev"` → `"B"`. Compare with [`super::user_label`], the
//! writable counterpart used by commissioners.
//!
//! The list is **fixed** in the F-quality sense (Matter Core spec
//! §7.13.2): it never changes for the lifetime of the device firmware,
//! so we don't need a persistence layer, a mutex, or any per-entry
//! storage. [`FixedLabelHandler`] just borrows a static slice of
//! [`FixedLabelEntry`] from the application and iterates it on read.
//! Writes are rejected by the framework before they reach the handler
//! because the cluster metadata declares `LabelList` as read-only
//! (`Access::READ`), which the IM dispatch maps to `UnsupportedWrite`
//! — exactly the behaviour `TC_FLABEL_2_1` step 3 expects.
//!
//! Application wiring:
//!
//! ```ignore
//! const LABELS: &[FixedLabelEntry] = &[
//!     FixedLabelEntry { label: "room", value: "kitchen" },
//!     FixedLabelEntry { label: "hwrev", value: "B" },
//! ];
//!
//! let handler = FixedLabelHandler::new(Dataver::new_rand(rand), LABELS);
//! ```

use crate::dm::{ArrayAttributeRead, Cluster, Dataver, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::TLVBuilderParent;
use crate::with;

pub use crate::dm::clusters::decl::fixed_label::*;
pub use crate::dm::clusters::decl::globals::{
    LabelStruct, LabelStructArrayBuilder, LabelStructBuilder,
};

/// Cluster metadata exposed by [`FixedLabelHandler`].
///
/// Exposed as a free constant so callers can spell out
/// `EpClMatcher::new(Some(ep), Some(fixed_label::CLUSTER.id))` without
/// reaching for the lifetime-parameterised handler type.
pub const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

/// One entry in a `LabelList`.
///
/// Per Matter Application Cluster spec §9.6.4 (`LabelStruct`), each
/// field is at most 16 characters. We don't enforce this here — the
/// application is responsible for supplying spec-compliant data, and
/// `TC_FLABEL_2_1` step 2 sanity-checks the lengths on the read path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedLabelEntry<'a> {
    pub label: &'a str,
    pub value: &'a str,
}

/// The handler for the FixedLabel Matter cluster.
///
/// Per-endpoint instance: each endpoint that advertises FixedLabel
/// must own its own handler so the per-cluster-instance `Dataver`
/// stays granular (Matter Core spec §7.13.2.1). The entries slice is
/// borrowed — typically a `&'static [FixedLabelEntry<'static>]` —
/// because the list is part of the device's firmware identity and
/// doesn't change at runtime.
pub struct FixedLabelHandler<'a> {
    dataver: Dataver,
    entries: &'a [FixedLabelEntry<'a>],
}

impl<'a> FixedLabelHandler<'a> {
    /// Construct a handler exposing `entries` as the cluster's
    /// `LabelList` attribute.
    pub const fn new(dataver: Dataver, entries: &'a [FixedLabelEntry<'a>]) -> Self {
        Self { dataver, entries }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for FixedLabelHandler<'_> {
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
        match builder {
            ArrayAttributeRead::ReadAll(mut array) => {
                for entry in self.entries {
                    array = array
                        .push()?
                        .label(entry.label)?
                        .value(entry.value)?
                        .end()?;
                }
                array.end()
            }
            ArrayAttributeRead::ReadOne(index, item) => {
                let Some(entry) = self.entries.get(index as usize) else {
                    // List-element index out of bounds — IM convention
                    // is `ConstraintError`; mirrors `UserLabelHandler`'s
                    // out-of-range behaviour.
                    return Err(ErrorCode::ConstraintError.into());
                };
                item.label(entry.label)?.value(entry.value)?.end()
            }
            ArrayAttributeRead::ReadNone(array) => array.end(),
        }
    }
}
