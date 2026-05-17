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

//! Implementation of the Software Diagnostics cluster.
//!
//! # Cluster-shape selection — endpoint-side, via [`Options`]
//!
//! Matter features (`WATERMARKS`) and spec-independent-optional
//! attribute toggles (`HEAP` for the heap counters, `THREAD` for the
//! `ThreadMetrics` list) are unified into a single [`Options`]
//! bitflags type, consumed by the [`cluster`] `const fn` which
//! returns the matching `Cluster<'static>` metadata.
//!
//! The shape is picked **endpoint-side**, on the `clusters!` /
//! `root_endpoint!` macros — e.g. `clusters!(sys, sw_diag(heap,
//! watermarks); …)` — not on the handler. [`SwDiagHandler`] itself
//! is non-generic and its [`Self::CLUSTER`](ClusterHandler::CLUSTER)
//! is pinned to the empty-options shape; only `CLUSTER.id` is
//! actually consulted by the dispatcher, and the per-attribute /
//! per-command dispatch is driven by what the endpoint advertises.
//!
//! This decoupling means a single handler instance can be installed
//! against any cluster shape — what gets dispatched to it is decided
//! by the endpoint metadata, and the [`SwDiag`] trait carries methods
//! for every option. Methods corresponding to un-advertised options
//! are simply never called.
//!
//! # Pluggable data source — [`SwDiag`]
//!
//! [`SwDiagHandler`] borrows a `&dyn SwDiag` data provider and
//! forwards every attribute read / command invoke to it. The trait
//! is intentionally abstract (no default methods) — the implementor
//! is forced to make an explicit choice for each method, paired
//! with the [`Feature`] set they've picked.
//!
//! [`impl SwDiag for ()`] is the canonical "we don't track
//! anything" provider (heap counters return `0`, thread iteration
//! emits nothing, `ResetWatermarks` refuses with `UnsupportedAccess`).
//! Pass `&()` when no real telemetry is available.
//!
//! Thread metrics use a visitor-style callback
//! ([`SwDiag::thread_metrics`]) rather than returning an allocated
//! `Vec` so MCU implementations can stream the list straight out of
//! their internal thread table.

use bitflags::bitflags;

use crate::dm::{ArrayAttributeRead, Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::TLVBuilderParent;
use crate::with;

pub use crate::dm::clusters::decl::software_diagnostics::*;

bitflags! {
    /// Cluster-shape selectors for the [`SwDiagHandler`]. Each bit
    /// turns on one orthogonal piece of the cluster surface — Matter
    /// `Feature` bits (`WATERMARKS`) and spec-independent-optional
    /// attribute toggles (`HEAP`, `THREAD`) are unified into a single
    /// enumset so the user picks the whole shape with one literal.
    ///
    /// Used as the argument to [`cluster`] to compute the matching
    /// `Cluster<'static>` metadata, which is then installed onto the
    /// endpoint via the `clusters!` / `root_endpoint!` macros (e.g.
    /// `clusters!(sys, sw_diag(heap, watermarks); …)`).
    ///
    /// `WATERMARKS` is the Matter `WATERMARKS` feature — it exposes
    /// `CurrentHeapHighWatermark` + the `ResetWatermarks` command and
    /// implies `HEAP` (the watermark tracks heap usage).
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct Options: u8 {
        /// Advertise the heap counters `CurrentHeapFree` and
        /// `CurrentHeapUsed`. Independently optional per Matter Core
        /// spec §11.13.
        const HEAP = 0x1;
        /// Claim the Matter `WATERMARKS` feature — adds
        /// `CurrentHeapHighWatermark` + the `ResetWatermarks`
        /// command, and surfaces the `WATERMARKS` bit in `FeatureMap`.
        /// Implies [`Options::HEAP`].
        const WATERMARKS = 0x2;
        /// Advertise the `ThreadMetrics` list attribute. Set only on
        /// devices that actually run multiple threads; a single-task
        /// Wi-Fi MCU should leave this off so the cluster doesn't
        /// misadvertise non-existent threads.
        const THREAD = 0x4;
    }
}

/// One thread's snapshot for the `ThreadMetrics` attribute. Yielded
/// by the implementor of [`SwDiag::thread_metrics`] via a visitor
/// closure; the lifetime `'a` is the borrow of the implementor's
/// internal storage for the duration of the visit, so `name` can
/// point straight into the implementor's thread-control-block
/// without copying.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ThreadMetric<'a> {
    /// OS-assigned identifier for this thread. Mandatory per spec.
    pub id: u64,
    /// Human-readable thread name. `None` if the runtime doesn't
    /// name threads.
    pub name: Option<&'a str>,
    /// Free stack bytes right now.
    pub stack_free_current: Option<u32>,
    /// Lowest free-stack value observed since boot (or since the
    /// last `ResetWatermarks` if the `WATERMARKS` feature is claimed).
    pub stack_free_minimum: Option<u32>,
    /// Total stack size in bytes.
    pub stack_size: Option<u32>,
}

/// Pluggable data source for the Software Diagnostics cluster
/// handler. All methods have sensible defaults so an implementor
/// can opt in to just the bits the device can actually report;
/// `impl SwDiag for ()` lets `&()` stand in as the no-op provider.
pub trait SwDiag {
    /// Free bytes on the device's heap right now. Default `0` for
    /// "not tracked".
    fn current_heap_free(&self) -> Result<u64, Error>;

    /// Used bytes on the device's heap right now. Default `0`.
    fn current_heap_used(&self) -> Result<u64, Error>;

    /// Maximum used bytes observed since boot or since the last
    /// `ResetWatermarks` invocation. Default `0`. Only meaningful
    /// when the handler is configured to claim the `WATERMARKS` feature.
    fn current_heap_high_watermark(&self) -> Result<u64, Error>;

    /// Stream per-thread metrics into `visit`. The implementor calls
    /// `visit(&ThreadMetric { … })` once per thread it wants to
    /// report; the handler relays each call into the on-wire
    /// `ThreadMetrics` array.
    ///
    /// `&ThreadMetric<'_>` is borrowed per-call: the implementor can
    /// build the metric from references into its own thread-control
    /// blocks (no `Vec` / `String` allocation needed).
    ///
    /// Default: emit nothing (no threads tracked) — the wire-side
    /// `ThreadMetrics` attribute reads as an empty list.
    fn thread_metrics(
        &self,
        _visit: &mut dyn FnMut(&ThreadMetric<'_>) -> Result<(), Error>,
    ) -> Result<(), Error>;

    /// Reset the high-watermark tracker. Default refuses with
    /// `UnsupportedAccess` — `ResetWatermarks` is gated on the
    /// `WATERMARKS` feature, which the current handler doesn't claim.
    fn reset_watermarks(&self) -> Result<(), Error>;
}

impl<T> SwDiag for &T
where
    T: SwDiag,
{
    fn current_heap_free(&self) -> Result<u64, Error> {
        (*self).current_heap_free()
    }
    fn current_heap_used(&self) -> Result<u64, Error> {
        (*self).current_heap_used()
    }
    fn current_heap_high_watermark(&self) -> Result<u64, Error> {
        (*self).current_heap_high_watermark()
    }
    fn thread_metrics(
        &self,
        visit: &mut dyn FnMut(&ThreadMetric<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        (*self).thread_metrics(visit)
    }
    fn reset_watermarks(&self) -> Result<(), Error> {
        (*self).reset_watermarks()
    }
}

/// No-op `SwDiag` provider used as `&()` for "no heap / thread
/// telemetry" — matches the convention used by [`crate::dm::clusters::wifi_diag::WifiDiag`].
impl SwDiag for () {
    fn current_heap_free(&self) -> Result<u64, Error> {
        Ok(0)
    }

    fn current_heap_used(&self) -> Result<u64, Error> {
        Ok(0)
    }

    fn current_heap_high_watermark(&self) -> Result<u64, Error> {
        Ok(0)
    }

    fn thread_metrics(
        &self,
        _visit: &mut dyn FnMut(&ThreadMetric<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn reset_watermarks(&self) -> Result<(), Error> {
        Err(ErrorCode::UnsupportedAccess.into())
    }
}

/// Compute the `Cluster<'static>` metadata for a SwDiag handler
/// whose advertised surface is described by `options`. See the
/// [`Options`] flags for the per-bit detail.
///
/// `Options::WATERMARKS` implies `Options::HEAP` — the watermark
/// tracks heap usage, so requesting a watermark without claiming
/// the heap counters is meaningless and the implication is folded
/// in here. Pair the returned shape with a [`SwDiag`]
/// implementation whose corresponding methods return real values
/// for the chosen options; the handler forwards every trait method
/// unconditionally, and methods for un-advertised attributes /
/// commands are simply never dispatched by the DM.
pub const fn cluster(options: Options) -> Cluster<'static> {
    let heap = options.bits() & Options::HEAP.bits() != 0
        || options.bits() & Options::WATERMARKS.bits() != 0;
    let watermarks = options.bits() & Options::WATERMARKS.bits() != 0;
    let thread = options.bits() & Options::THREAD.bits() != 0;

    let matter_features = if watermarks {
        Feature::WATERMARKS.bits()
    } else {
        0
    };
    let cluster = FULL_CLUSTER.with_features(matter_features);

    match (heap, watermarks, thread) {
        (false, _, false) => cluster.with_attrs(with!(required)).with_cmds(with!()),
        (false, _, true) => cluster
            .with_attrs(with!(required; AttributeId::ThreadMetrics))
            .with_cmds(with!()),
        (true, false, false) => cluster
            .with_attrs(with!(required;
                AttributeId::CurrentHeapFree | AttributeId::CurrentHeapUsed))
            .with_cmds(with!()),
        (true, false, true) => cluster
            .with_attrs(with!(required;
                AttributeId::ThreadMetrics
                    | AttributeId::CurrentHeapFree
                    | AttributeId::CurrentHeapUsed))
            .with_cmds(with!()),
        (true, true, false) => cluster
            .with_attrs(with!(required;
                AttributeId::CurrentHeapFree
                    | AttributeId::CurrentHeapUsed
                    | AttributeId::CurrentHeapHighWatermark))
            .with_cmds(with!(CommandId::ResetWatermarks)),
        (true, true, true) => cluster
            .with_attrs(with!(required;
                AttributeId::ThreadMetrics
                    | AttributeId::CurrentHeapFree
                    | AttributeId::CurrentHeapUsed
                    | AttributeId::CurrentHeapHighWatermark))
            .with_cmds(with!(CommandId::ResetWatermarks)),
    }
}

/// Handler for the Software Diagnostics Matter cluster.
///
/// Borrows a `&dyn SwDiag` data provider for the lifetime `'a` and
/// forwards every attribute read / command invoke to it.
///
/// The handler is **not** parameterized by cluster shape:
/// [`Self::CLUSTER`](ClusterHandler::CLUSTER) is pinned to the
/// empty-options form and only its `id` is consulted by the
/// dispatcher. The on-wire shape — which optional attributes /
/// commands / features are advertised — is decided by the cluster
/// metadata supplied on the endpoint side (e.g. `clusters!(sys,
/// sw_diag(heap, watermarks); …)`); per-attribute dispatch follows
/// the endpoint's metadata, so the handler answers exactly what
/// the endpoint exposes.
#[derive(Clone)]
pub struct SwDiagHandler<'a> {
    dataver: Dataver,
    sw_diag: &'a dyn SwDiag,
}

impl<'a> SwDiagHandler<'a> {
    /// Create a new handler bound to `sw_diag` for its lifetime.
    /// Pass `&()` (the no-op [`SwDiag`] impl) when no real telemetry
    /// source is available.
    pub const fn new(dataver: Dataver, sw_diag: &'a dyn SwDiag) -> Self {
        Self { dataver, sw_diag }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for SwDiagHandler<'_> {
    const CLUSTER: Cluster<'static> = cluster(Options::empty());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn current_heap_free(&self, _ctx: impl ReadContext) -> Result<u64, Error> {
        self.sw_diag.current_heap_free()
    }

    fn current_heap_used(&self, _ctx: impl ReadContext) -> Result<u64, Error> {
        self.sw_diag.current_heap_used()
    }

    fn current_heap_high_watermark(&self, _ctx: impl ReadContext) -> Result<u64, Error> {
        self.sw_diag.current_heap_high_watermark()
    }

    fn thread_metrics<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            ThreadMetricsStructArrayBuilder<P>,
            ThreadMetricsStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(array) => {
                // Stream the implementor's thread metrics into the
                // wire-side array via the visitor closure. The
                // `Option` dance is the same pattern used by
                // `WifiDiagHandler::bssid` to thread the moved-by-value
                // typestate builder through a `&mut dyn FnMut` closure.
                let mut array_opt = Some(array);
                self.sw_diag.thread_metrics(&mut |m| {
                    let array = unwrap!(array_opt.take());
                    let next = array
                        .push()?
                        .id(m.id)?
                        .name(m.name)?
                        .stack_free_current(m.stack_free_current)?
                        .stack_free_minimum(m.stack_free_minimum)?
                        .stack_size(m.stack_size)?
                        .end()?;
                    array_opt = Some(next);
                    Ok(())
                })?;
                unwrap!(array_opt.take()).end()
            }
            ArrayAttributeRead::ReadOne(index, item_builder) => {
                // Walk the implementor's thread list looking for the
                // requested index; on hit, emit that one entry into
                // the per-element builder. Consume `item_builder` at
                // most once; if the index is out of range, return
                // `ConstraintError` (same convention as
                // `desc::DescHandler::device_type_list`).
                let mut item_opt = Some(item_builder);
                let mut returned: Option<P> = None;
                let mut current = 0u16;
                self.sw_diag.thread_metrics(&mut |m| {
                    if returned.is_none() && current == index {
                        let b = unwrap!(item_opt.take());
                        returned = Some(
                            b.id(m.id)?
                                .name(m.name)?
                                .stack_free_current(m.stack_free_current)?
                                .stack_free_minimum(m.stack_free_minimum)?
                                .stack_size(m.stack_size)?
                                .end()?,
                        );
                    }
                    current = current.saturating_add(1);
                    Ok(())
                })?;
                returned.ok_or_else(|| ErrorCode::ConstraintError.into())
            }
            ArrayAttributeRead::ReadNone(array) => array.end(),
        }
    }

    fn handle_reset_watermarks(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        self.sw_diag.reset_watermarks()
    }
}

impl core::fmt::Debug for SwDiagHandler<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SwDiagHandler")
            .field("dataver", &self.dataver)
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for SwDiagHandler<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "SwDiagHandler {{ dataver: {} }}", self.dataver.get());
    }
}
