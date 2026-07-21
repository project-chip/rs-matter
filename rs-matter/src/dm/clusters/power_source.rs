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

//! PowerSource cluster handler.
//!
//! Describes *one* source of power feeding the node - mains, a battery, or
//! PoE - and which endpoints it powers. A node with two sources (say, mains
//! plus a backup battery) hosts two instances on two endpoints, ordered by
//! [`PowerSourceConfig::order`].
//!
//! This handler implements the minimal conformant *wired* shape of the
//! cluster: the four attributes that are mandatory regardless of features
//! (`Status`, `Order`, `Description`, `EndpointList`), plus the `WIRED`
//! feature and its single mandatory attribute, `WiredCurrentType`.
//!
//! `WIRED` is not optional decoration: the `WIRED` / `BAT` features form an
//! at-least-one-of choice conformance (`O.a` in the spec), so a `FeatureMap`
//! of zero is non-conformant - `TC_DeviceConformance` flags it as
//! "choice conformance .a - 0 selected". The battery-side features
//! (`BAT` / `RECHG` / `REPLC`) are not implemented; the generated trait
//! defaults answer `AttributeNotFound` for their attributes.
//!
//! That featureless shape is deliberately useful on its own: test harnesses
//! and ecosystems probe `PowerSource` to decide whether a device is
//! battery-powered (`FeatureMap & BATTERY`), and a device with no PowerSource
//! at all makes that probe *fail* rather than answer "no". Hosting this
//! handler turns that into a clean negative answer.
//!
//! The cluster is optional in Matter - nothing requires a node to host it.
//!
//! Application wiring:
//!
//! ```ignore
//! const POWER: PowerSourceConfig = PowerSourceConfig {
//!     status: PowerSourceStatusEnum::Active,
//!     order: 0,
//!     description: "Mains",
//!     endpoint_list: &[1],
//! };
//!
//! let handler = PowerSourceHandler::new(Dataver::new_rand(rand), &POWER);
//! ```

use crate::dm::{ArrayAttributeRead, Cluster, Dataver, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::im::EndptId;
use crate::tlv::{TLVBuilderParent, ToTLVArrayBuilder, ToTLVBuilder, Utf8StrBuilder};
use crate::with;

pub use crate::dm::clusters::decl::power_source::*;

/// Cluster metadata exposed by [`PowerSourceHandler`].
///
/// Exposed as a free constant so callers can spell out
/// `EpClMatcher::new(Some(ep), Some(power_source::CLUSTER.id))` without
/// naming the lifetime-parameterised handler type.
pub const CLUSTER: Cluster<'static> = FULL_CLUSTER
    .with_features(Feature::WIRED.bits())
    .with_attrs(with!(required; AttributeId::WiredCurrentType))
    .with_cmds(with!());

/// The application-supplied description of one power source.
///
/// Borrowed rather than owned, and expected to be a `'static` constant: these
/// are firmware identity, in the same spirit as
/// [`super::fixed_label::FixedLabelEntry`]. A source whose *status* genuinely
/// changes at runtime is better served by a bespoke [`ClusterHandler`] impl
/// than by making this struct mutable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PowerSourceConfig<'a> {
    /// Whether this source is currently supplying power.
    pub status: PowerSourceStatusEnum,
    /// Relative preference, 0 being the most preferred. Per the spec, the
    /// values across a node's sources SHALL be distinct.
    pub order: u8,
    /// Human-readable name of the source, e.g. `"Mains"`. At most 60
    /// characters; not enforced here, as with the other config-carrying
    /// clusters.
    pub description: &'a str,
    /// The endpoints this source powers. May be empty, which per the spec
    /// means the source powers the node as a whole.
    pub endpoint_list: &'a [EndptId],
    /// The current type delivered by this wired source (mandatory under the
    /// `WIRED` feature, which this handler always claims - see the module
    /// docs on the `WIRED`/`BAT` choice conformance).
    pub wired_current_type: WiredCurrentTypeEnum,
}

impl PowerSourceConfig<'_> {
    /// A mains-powered source that powers the whole node.
    ///
    /// The common case for a wired accessory, and the one that makes
    /// "is this device battery powered?" answerable with a plain no.
    pub const MAINS: Self = Self {
        status: PowerSourceStatusEnum::Active,
        order: 0,
        description: "Mains",
        endpoint_list: &[],
        wired_current_type: WiredCurrentTypeEnum::AC,
    };
}

/// The system implementation of a handler for the PowerSource Matter cluster.
///
/// Per-endpoint instance: a node with several power sources hosts one handler
/// per source, each on its own endpoint with its own `Dataver`.
pub struct PowerSourceHandler<'a> {
    dataver: Dataver,
    config: &'a PowerSourceConfig<'a>,
}

impl<'a> PowerSourceHandler<'a> {
    /// Create a new handler describing `config`.
    pub const fn new(dataver: Dataver, config: &'a PowerSourceConfig<'a>) -> Self {
        Self { dataver, config }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for PowerSourceHandler<'_> {
    const CLUSTER: Cluster<'static> = CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn status(&self, _ctx: impl ReadContext) -> Result<PowerSourceStatusEnum, Error> {
        Ok(self.config.status)
    }

    fn order(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.config.order)
    }

    fn description<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(self.config.description)
    }

    fn wired_current_type(&self, _ctx: impl ReadContext) -> Result<WiredCurrentTypeEnum, Error> {
        Ok(self.config.wired_current_type)
    }

    fn endpoint_list<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<ToTLVArrayBuilder<P, EndptId>, ToTLVBuilder<P, EndptId>>,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(mut builder) => {
                for endpoint in self.config.endpoint_list {
                    builder = builder.push(endpoint)?;
                }

                builder.end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let Some(endpoint) = self.config.endpoint_list.get(index as usize) else {
                    // List-element index out of bounds - IM convention is
                    // `ConstraintError`, as in `FixedLabelHandler`.
                    return Err(ErrorCode::ConstraintError.into());
                };

                builder.set(endpoint)
            }
            ArrayAttributeRead::ReadNone(builder) => builder.end(),
        }
    }
}
