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

//! Implementation of the Matter Power Topology cluster (`0x009C`),
//! `ClusterRevision` 1.
//!
//! The cluster answers one question: *what* do the electrical measurements on
//! this endpoint actually describe? It is mandatory for the Electrical Sensor
//! device type ([`crate::dm::devices::DEV_TYPE_ELECTRICAL_SENSOR`]), which
//! pairs it with [`super::elec_pwr_meas`] and/or [`super::elec_energy_meas`].
//!
//! This handler implements the `NODE` (NodeTopology) answer: the measurements
//! cover the whole node. That is the right answer for a single-purpose device —
//! a thermostat driving one heating element, a smart plug, a water heater — and
//! it is also the cheapest, because `NODE` makes both of the cluster's
//! attributes non-conformant, leaving only the global ones. There is
//! consequently nothing to configure and nothing for a consumer to implement:
//! construct [`PowerTopologyHandler`] and chain it.
//!
//! The `TREE` and `SET` topologies, which describe measurements covering a
//! subset of the node's endpoints, would need `AvailableEndpoints` and (with
//! `DYPF`) `ActiveEndpoints`, and a handler that can enumerate them. They are
//! not implemented.
//!
//! Note that the IDL we generate from also carries an `ELECTRICAL_CIRCUIT`
//! feature and an `ElectricalCircuitNodes` attribute. Neither is defined by the
//! Matter 1.6 data model, so the generated accessors are deliberately left at
//! their `AttributeNotFound` default.

use crate::dm::{Cluster, Dataver};
use crate::with;

pub use crate::dm::clusters::decl::power_topology::*;

/// The `ClusterRevision` this handler implements (Matter 1.6).
const CLUSTER_REVISION: u16 = 1;

/// Cluster metadata exposed by [`PowerTopologyHandler`].
///
/// Equivalent to `<PowerTopologyHandler as ClusterHandler>::CLUSTER`, exposed
/// here as a free constant so callers can name it in a handler-chain matcher or
/// a `clusters!(...)` literal, as [`crate::dm::clusters::identify`] does.
pub const CLUSTER: Cluster<'static> = FULL_CLUSTER
    .with_revision(CLUSTER_REVISION)
    .with_features(Feature::NODE_TOPOLOGY.bits())
    .with_attrs(with!(required))
    .with_cmds(with!());

/// A Power Topology cluster handler declaring node-wide topology.
pub struct PowerTopologyHandler {
    dataver: Dataver,
}

impl PowerTopologyHandler {
    /// Create a new `PowerTopologyHandler`.
    ///
    /// # Arguments
    /// - `dataver` - the cluster data version.
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for PowerTopologyHandler {
    const CLUSTER: Cluster<'static> = CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }
}
