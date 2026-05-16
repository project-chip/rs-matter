/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

//! Stub implementation of the Software Diagnostics cluster.
//!
//! All attributes in this cluster are feature-gated (HeapStats / HW
//! watermarks / Thread metrics), and rs-matter does not currently
//! sample any of them — so this handler advertises the bare-minimum
//! shape: no features, no optional commands, just the required global
//! attributes (`FeatureMap`, `ClusterRevision`, `AttributeList`,
//! `AcceptedCommandList`, `GeneratedCommandList`). That is
//! spec-conformant per Matter Core spec §11.13 (every conditional
//! is gated on a feature this cluster doesn't claim).
//!
//! This makes `TC_DGSW_2_1` / `TC_DGSW_2_2` pass by establishing
//! cluster presence on the root endpoint and serving the required
//! globals. Adding real heap/thread sampling is a follow-up that
//! flips the appropriate `Feature` bits on `CLUSTER` and overrides
//! the corresponding attribute reads.

use crate::dm::{Cluster, Dataver, InvokeContext};
use crate::error::{Error, ErrorCode};
use crate::with;

pub use crate::dm::clusters::decl::software_diagnostics::*;

/// The system implementation of a handler for the Software Diagnostics Matter cluster.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SwDiagHandler {
    dataver: Dataver,
}

impl SwDiagHandler {
    /// Create a new instance of `SwDiagHandler` with the given `Dataver`.
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for SwDiagHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required)).with_cmds(with!());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn handle_reset_watermarks(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        // Optional command (gated by the `WTRMRK` feature, which we
        // don't claim). The DM should never dispatch to us here; if
        // it does — likely a peer probing — refuse cleanly.
        Err(ErrorCode::CommandNotFound.into())
    }
}
