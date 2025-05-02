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

use crate::data_model::objects::{Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::Error;
use crate::with;

pub use crate::data_model::clusters::ethernet_network_diagnostics::*;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EthNwDiagHandler {
    dataver: Dataver,
}

impl EthNwDiagHandler {
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for EthNwDiagHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_revision(1)
        .with_attrs(with!(required; AttributeId::PacketRxCount | AttributeId::PacketTxCount))
        .with_cmds(with!(CommandId::ResetCounts));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn packet_rx_count(&self, _ctx: &ReadContext) -> Result<u64, Error> {
        Ok(1) // TODO
    }

    fn packet_tx_count(&self, _ctx: &ReadContext) -> Result<u64, Error> {
        Ok(1) // TODO
    }

    fn handle_reset_counts(&self, _ctx: &InvokeContext) -> Result<(), Error> {
        Ok(()) // TODO
    }
}
