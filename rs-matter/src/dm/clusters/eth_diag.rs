/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
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

//! This module contains the implementation of the Ethernet Network Diagnostics cluster and its handler.

use crate::dm::{Cluster, Dataver, InvokeContext};
use crate::error::{Error, ErrorCode};
use crate::with;

pub use crate::dm::clusters::decl::ethernet_network_diagnostics::*;

/// The system implementation of a handler for the Ethernet Network Diagnostics Matter cluster.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EthDiagHandler {
    dataver: Dataver,
}

impl EthDiagHandler {
    /// Create a new instance of `EthDiagHandler` with the given `Dataver`.
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for EthDiagHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required)).with_cmds(with!());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn handle_reset_counts(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }
}
