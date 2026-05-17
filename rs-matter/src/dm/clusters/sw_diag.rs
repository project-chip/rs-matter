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
//! The cluster is advertised on the root endpoint with **no feature
//! bits claimed** (so `CurrentHeapHighWatermark` and the
//! `ResetWatermarks` command stay off), but the three feature-free
//! optional attributes — `ThreadMetrics`, `CurrentHeapFree`,
//! `CurrentHeapUsed` — are opted in. All three are independently
//! optional per Matter Core spec §11.13, and exposing them lets a
//! real implementation surface useful telemetry without further
//! plumbing.
//!
//! # Pluggable data source — [`SwDiag`]
//!
//! [`SwDiagHandler`] borrows a `&dyn SwDiag` data provider and
//! forwards each attribute read to it. The no-op default — `impl
//! SwDiag for ()`, used via `&()` — returns `0` for every scalar
//! counter and emits an empty thread list (spec-legal; both mean
//! "not tracked"). A real implementation backed by the device's
//! allocator and threading runtime surfaces real numbers on the
//! wire without any further plumbing.
//!
//! Thread metrics use a visitor-style callback
//! ([`SwDiag::thread_metrics`]) rather than returning an
//! allocated `Vec` so MCU implementations can stream the list
//! straight out of their internal thread table.
//!
//! The `ResetWatermarks` command is gated by the `WTRMRK` feature
//! we don't claim, so the trait method has a default of "refuse
//! cleanly". An implementor that wants real watermarks would
//! override both the cluster's feature mask (a future variant of
//! this handler) and the trait method.

use crate::dm::{ArrayAttributeRead, Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::TLVBuilderParent;
use crate::with;

pub use crate::dm::clusters::decl::software_diagnostics::*;

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
    /// last `ResetWatermarks` if the `WTRMRK` feature is claimed).
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
    /// when the handler is configured to claim the `WTRMRK` feature.
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
    /// `WTRMRK` feature, which the current handler doesn't claim.
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

/// Handler for the Software Diagnostics Matter cluster.
///
/// Borrows a `&dyn SwDiag` data provider for the lifetime `'a` and
/// forwards each attribute read to it. Cluster metadata: required
/// globals + `CurrentHeapFree` + `CurrentHeapUsed`, no features,
/// no commands.
#[derive(Clone)]
pub struct SwDiagHandler<'a> {
    dataver: Dataver,
    sw_diag: &'a dyn SwDiag,
}

impl<'a> SwDiagHandler<'a> {
    /// Create a new handler bound to `sw_diag` for its lifetime.
    /// Pass `&()` (the no-op [`SwDiag`] impl) when no real
    /// heap-telemetry source is available.
    pub const fn new(dataver: Dataver, sw_diag: &'a dyn SwDiag) -> Self {
        Self { dataver, sw_diag }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for SwDiagHandler<'_> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_attrs(with!(required;
            AttributeId::ThreadMetrics
                | AttributeId::CurrentHeapFree
                | AttributeId::CurrentHeapUsed
        ))
        .with_cmds(with!());

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
        // Optional command (gated by the `WTRMRK` feature, which we
        // don't claim). The DM should never dispatch to us here;
        // refuse cleanly regardless.
        Err(ErrorCode::CommandNotFound.into())
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
