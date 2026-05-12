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

//! Implementation of the Matter Zone Management cluster (0x0550).
//!
//! Manages 2-D Cartesian detection regions ("zones") on a camera and
//! the duration triggers that turn those zones into `ZoneTriggered` /
//! `ZoneStopped` events. Zones are referenced by ID from
//! `ZoneTriggered` / `ZoneStopped` events and from the
//! `PushAvStreamTransport` cluster, so once a zone is created its ID
//! must remain stable until explicitly removed.
//!
//! # Architecture (Pattern B1 — "Hooks")
//!
//! [`ZoneMgmtHandler`] owns all spec-defined state (zone table, trigger
//! table, global sensitivity) and performs all spec validation. The
//! application provides a [`ZoneMgmtHooks`] implementation that hears
//! about lifecycle changes and feeds them into the camera's actual
//! motion-detection pipeline.
//!
//! # Const generics
//!
//! * `NZ` — maximum number of zones (manufacturer + user-defined).
//! * `NV` — maximum number of vertices per zone polygon.
//! * `NT` — maximum number of triggers (typically equals `NZ`).
//!
//! # Feature support in this revision
//!
//! * `TWO_DIMENSIONAL_CARTESIAN_ZONE` — fully supported.
//! * `USER_DEFINED` — fully supported (Create / Update / Remove).
//! * `PER_ZONE_SENSITIVITY` — not yet (per-zone `sensitivity` field on
//!   triggers is accepted but not enforced).
//! * `FOCUS_ZONES` — not yet.

use core::cell::{Cell, RefCell};
use core::future::Future;

use heapless::String as HString;

use crate::dm::{
    ArrayAttributeRead, Cluster, Dataver, EndptId, InvokeContext, ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVBuilderParent, Utf8Str};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::with;

#[allow(unused_imports)]
pub use crate::dm::clusters::decl::zone_management::*;

use super::super::decl::zone_management as decl;

/// Maximum length, in bytes, of a zone `name` string (Matter spec cap).
pub const MAX_ZONE_NAME_LEN: usize = 16;

/// Maximum length, in bytes, of a zone `color` string (`#RRGGBB`).
pub const MAX_ZONE_COLOR_LEN: usize = 7;

/// Errors a [`ZoneMgmtHooks`] implementation can surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ZoneError {
    ResourceExhausted,
    DynamicConstraint,
    NotFound,
    Failure,
}

impl From<ZoneError> for Error {
    fn from(e: ZoneError) -> Self {
        match e {
            ZoneError::ResourceExhausted => ErrorCode::ResourceExhausted.into(),
            ZoneError::DynamicConstraint => ErrorCode::ConstraintError.into(),
            ZoneError::NotFound => ErrorCode::NotFound.into(),
            ZoneError::Failure => ErrorCode::Failure.into(),
        }
    }
}

/// One row in the `Zones` attribute. Vertices are stored inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone<const NV: usize> {
    pub zone_id: u16,
    pub zone_type: ZoneTypeEnum,
    pub zone_source: ZoneSourceEnum,
    pub name: HString<MAX_ZONE_NAME_LEN>,
    pub zone_use: ZoneUseEnum,
    pub vertices: Vec<(u16, u16), NV>,
    pub color: Option<HString<MAX_ZONE_COLOR_LEN>>,
}

/// One row in the `Triggers` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Trigger {
    pub zone_id: u16,
    pub initial_duration: u32,
    pub augmentation_duration: u32,
    pub max_duration: u32,
    pub blind_duration: u32,
    pub sensitivity: Option<u8>,
}

/// Application hooks for the side-effecting pieces of zone-management
/// lifecycle. Each method has a no-op default body — implementors only
/// need to override the events they actually care about.
#[allow(unused_variables)]
pub trait ZoneMgmtHooks<const NV: usize> {
    fn zone_created(&self, zone: &Zone<NV>) -> impl Future<Output = Result<(), ZoneError>> {
        async { Ok(()) }
    }

    fn zone_updated(&self, zone: &Zone<NV>) -> impl Future<Output = Result<(), ZoneError>> {
        async { Ok(()) }
    }

    fn zone_removed(&self, zone_id: u16) -> impl Future<Output = Result<(), ZoneError>> {
        async { Ok(()) }
    }

    fn trigger_set(&self, trigger: &Trigger) -> impl Future<Output = Result<(), ZoneError>> {
        async { Ok(()) }
    }

    fn trigger_removed(&self, zone_id: u16) -> impl Future<Output = Result<(), ZoneError>> {
        async { Ok(()) }
    }

    fn set_sensitivity(&self, value: u8) -> impl Future<Output = Result<(), ZoneError>> {
        async { Ok(()) }
    }
}

impl<const NV: usize, T> ZoneMgmtHooks<NV> for &T
where
    T: ZoneMgmtHooks<NV>,
{
    fn zone_created(&self, zone: &Zone<NV>) -> impl Future<Output = Result<(), ZoneError>> {
        (*self).zone_created(zone)
    }

    fn zone_updated(&self, zone: &Zone<NV>) -> impl Future<Output = Result<(), ZoneError>> {
        (*self).zone_updated(zone)
    }

    fn zone_removed(&self, zone_id: u16) -> impl Future<Output = Result<(), ZoneError>> {
        (*self).zone_removed(zone_id)
    }

    fn trigger_set(&self, trigger: &Trigger) -> impl Future<Output = Result<(), ZoneError>> {
        (*self).trigger_set(trigger)
    }

    fn trigger_removed(&self, zone_id: u16) -> impl Future<Output = Result<(), ZoneError>> {
        (*self).trigger_removed(zone_id)
    }

    fn set_sensitivity(&self, value: u8) -> impl Future<Output = Result<(), ZoneError>> {
        (*self).set_sensitivity(value)
    }
}

/// Static configuration for a [`ZoneMgmtHandler`].
#[derive(Debug, Clone, Copy)]
pub struct ZoneMgmtConfig {
    pub max_zones: u8,
    pub max_user_defined_zones: u8,
    /// 0 disables the global `Sensitivity` attribute.
    pub sensitivity_max: u8,
    pub default_sensitivity: u8,
    /// Maximum vertex coordinates accepted by `CreateTwoDCartesianZone`
    /// / `UpdateTwoDCartesianZone` (advertised via `TwoDCartesianMax`).
    pub two_d_cartesian_max: (u16, u16),
}

struct State<const NZ: usize, const NV: usize, const NT: usize> {
    zones: Vec<Zone<NV>, NZ>,
    triggers: Vec<Trigger, NT>,
    sensitivity: u8,
    seeded: bool,
}

impl<const NZ: usize, const NV: usize, const NT: usize> State<NZ, NV, NT> {
    const fn new() -> Self {
        Self {
            zones: Vec::new(),
            triggers: Vec::new(),
            sensitivity: 0,
            seeded: false,
        }
    }
}

/// Handler for the Zone Management cluster (0x0550).
pub struct ZoneMgmtHandler<H, const NZ: usize, const NV: usize, const NT: usize>
where
    H: ZoneMgmtHooks<NV>,
{
    dataver: Dataver,
    endpoint_id: EndptId,
    config: ZoneMgmtConfig,
    features: u32,
    hooks: H,
    state: Mutex<RefCell<State<NZ, NV, NT>>>,
    next_id: Mutex<Cell<u16>>,
}

impl<H, const NZ: usize, const NV: usize, const NT: usize> ZoneMgmtHandler<H, NZ, NV, NT>
where
    H: ZoneMgmtHooks<NV>,
{
    /// Cluster metadata advertising `TWO_DIMENSIONAL_CARTESIAN_ZONE` +
    /// `USER_DEFINED`.
    pub const CLUSTER: Cluster<'static> = decl::FULL_CLUSTER
        .with_revision(1)
        .with_features(
            decl::Feature::TWO_DIMENSIONAL_CARTESIAN_ZONE.bits()
                | decl::Feature::USER_DEFINED.bits(),
        )
        .with_attrs(with!(
            required;
            AttributeId::MaxUserDefinedZones
                | AttributeId::MaxZones
                | AttributeId::Zones
                | AttributeId::Triggers
                | AttributeId::SensitivityMax
                | AttributeId::Sensitivity
                | AttributeId::TwoDCartesianMax
        ))
        .with_cmds(with!(
            decl::CommandId::CreateTwoDCartesianZone
                | decl::CommandId::UpdateTwoDCartesianZone
                | decl::CommandId::RemoveZone
                | decl::CommandId::CreateOrUpdateTrigger
                | decl::CommandId::RemoveTrigger
        ));

    pub const fn new(
        dataver: Dataver,
        endpoint_id: EndptId,
        config: ZoneMgmtConfig,
        features: u32,
        hooks: H,
    ) -> Self {
        Self {
            dataver,
            endpoint_id,
            config,
            features,
            hooks,
            state: Mutex::new(RefCell::new(State::new())),
            next_id: Mutex::new(Cell::new(1)),
        }
    }

    pub const fn adapt(self) -> decl::HandlerAsyncAdaptor<Self> {
        decl::HandlerAsyncAdaptor(self)
    }

    pub const fn endpoint_id(&self) -> EndptId {
        self.endpoint_id
    }

    /// Pre-seed a manufacturer zone at boot. The supplied zone gets a
    /// fresh ID and `zone_source` is forced to `Mfg`. Such zones cannot
    /// be removed via `RemoveZone`. Returns the assigned ID.
    pub fn add_mfg_zone(&self, mut zone: Zone<NV>) -> Result<u16, Error> {
        zone.zone_source = ZoneSourceEnum::Mfg;
        zone.zone_id = self.alloc_zone_id();
        let id = zone.zone_id;
        let pushed = self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            s.zones.push(zone).is_ok()
        });
        if !pushed {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        self.dataver.changed();
        Ok(id)
    }

    fn alloc_zone_id(&self) -> u16 {
        self.next_id.lock(|cell| {
            let mut id = cell.get();
            if id == 0 {
                id = 1;
            }
            cell.set(id.wrapping_add(1).max(1));
            id
        })
    }

    fn ensure_seeded(&self) {
        self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            if !s.seeded {
                s.sensitivity = self.config.default_sensitivity;
                s.seeded = true;
            }
        });
    }

    fn has_feature(&self, bit: u32) -> bool {
        self.features & bit != 0
    }

    fn user_defined_zone_count(&self) -> usize {
        self.state.lock(|cell| {
            cell.borrow()
                .zones
                .iter()
                .filter(|z| z.zone_source == ZoneSourceEnum::User)
                .count()
        })
    }

    /// Validate-and-extract a `TwoDCartesianZoneStruct` payload.
    #[allow(clippy::type_complexity)]
    fn parse_zone_payload(
        &self,
        s: &TwoDCartesianZoneStruct<'_>,
    ) -> Result<
        (
            HString<MAX_ZONE_NAME_LEN>,
            ZoneUseEnum,
            Vec<(u16, u16), NV>,
            Option<HString<MAX_ZONE_COLOR_LEN>>,
        ),
        Error,
    > {
        let name_str: Utf8Str<'_> = s.name()?;
        let mut name: HString<MAX_ZONE_NAME_LEN> = HString::new();
        if name_str.len() > MAX_ZONE_NAME_LEN || name.push_str(name_str).is_err() {
            return Err(ErrorCode::ConstraintError.into());
        }

        let zone_use = s.r#use()?;

        let verts_arr = s.vertices()?;
        let mut vertices: Vec<(u16, u16), NV> = Vec::new();
        for v in verts_arr.iter() {
            let v = v?;
            let x = v.x()?;
            let y = v.y()?;
            if x > self.config.two_d_cartesian_max.0 || y > self.config.two_d_cartesian_max.1 {
                return Err(ErrorCode::ConstraintError.into());
            }
            vertices
                .push((x, y))
                .map_err(|_| Error::from(ErrorCode::ResourceExhausted))?;
        }
        // Spec: a polygon needs at least 3 vertices.
        if vertices.len() < 3 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let color = match s.color()? {
            Some(c) => {
                let mut h: HString<MAX_ZONE_COLOR_LEN> = HString::new();
                if c.len() > MAX_ZONE_COLOR_LEN || h.push_str(c).is_err() {
                    return Err(ErrorCode::ConstraintError.into());
                }
                Some(h)
            }
            None => None,
        };

        Ok((name, zone_use, vertices, color))
    }
}

impl<H, const NZ: usize, const NV: usize, const NT: usize> ClusterAsyncHandler
    for ZoneMgmtHandler<H, NZ, NV, NT>
where
    H: ZoneMgmtHooks<NV>,
{
    const CLUSTER: Cluster<'static> = Self::CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn max_user_defined_zones(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.config.max_user_defined_zones)
    }

    async fn max_zones(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.config.max_zones)
    }

    async fn sensitivity_max(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(self.config.sensitivity_max)
    }

    async fn sensitivity(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        if self.config.sensitivity_max == 0 {
            return Err(ErrorCode::AttributeNotFound.into());
        }
        self.ensure_seeded();
        Ok(self.state.lock(|cell| cell.borrow().sensitivity))
    }

    async fn set_sensitivity(&self, _ctx: impl WriteContext, value: u8) -> Result<(), Error> {
        if self.config.sensitivity_max == 0 {
            return Err(ErrorCode::AttributeNotFound.into());
        }
        if value < 1 || value > self.config.sensitivity_max {
            return Err(ErrorCode::ConstraintError.into());
        }
        self.hooks.set_sensitivity(value).await?;
        self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            s.sensitivity = value;
            s.seeded = true;
        });
        Ok(())
    }

    async fn two_d_cartesian_max<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: TwoDCartesianVertexStructBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .x(self.config.two_d_cartesian_max.0)?
            .y(self.config.two_d_cartesian_max.1)?
            .end()
    }

    async fn zones<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            ZoneInformationStructArrayBuilder<P>,
            ZoneInformationStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        let snapshot = self.state.lock(|cell| cell.borrow().zones.clone());
        match builder {
            ArrayAttributeRead::ReadAll(mut b) => {
                for z in snapshot.iter() {
                    b = write_zone_info(b.push()?, z)?;
                }
                b.end()
            }
            ArrayAttributeRead::ReadOne(idx, b) => {
                let Some(z) = snapshot.get(idx as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };
                write_zone_info(b, z)
            }
            ArrayAttributeRead::ReadNone(b) => b.end(),
        }
    }

    async fn triggers<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            ZoneTriggerControlStructArrayBuilder<P>,
            ZoneTriggerControlStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        let snapshot = self.state.lock(|cell| cell.borrow().triggers.clone());
        match builder {
            ArrayAttributeRead::ReadAll(mut b) => {
                for t in snapshot.iter() {
                    b = write_trigger(b.push()?, t)?;
                }
                b.end()
            }
            ArrayAttributeRead::ReadOne(idx, b) => {
                let Some(t) = snapshot.get(idx as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };
                write_trigger(b, t)
            }
            ArrayAttributeRead::ReadNone(b) => b.end(),
        }
    }

    async fn handle_create_two_d_cartesian_zone<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: CreateTwoDCartesianZoneRequest<'_>,
        response: CreateTwoDCartesianZoneResponseBuilder<P>,
    ) -> Result<P, Error> {
        if !self.has_feature(decl::Feature::USER_DEFINED.bits()) {
            return Err(ErrorCode::InvalidAction.into());
        }

        let payload = request.zone()?;
        let (name, zone_use, vertices, color) = self.parse_zone_payload(&payload)?;

        if self.user_defined_zone_count() >= self.config.max_user_defined_zones as usize {
            return Err(ErrorCode::ResourceExhausted.into());
        }

        let zone = Zone {
            zone_id: self.alloc_zone_id(),
            zone_type: ZoneTypeEnum::TwoDCARTZone,
            zone_source: ZoneSourceEnum::User,
            name,
            zone_use,
            vertices,
            color,
        };
        let id = zone.zone_id;

        let pushed = self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            s.zones.push(zone.clone()).is_ok()
        });
        if !pushed {
            return Err(ErrorCode::ResourceExhausted.into());
        }

        if let Err(e) = self.hooks.zone_created(&zone).await {
            self.state.lock(|cell| {
                let mut s = cell.borrow_mut();
                s.zones.retain(|z| z.zone_id != id);
            });
            return Err(e.into());
        }
        ctx.notify_own_attr_changed(AttributeId::Zones as _);

        response.zone_id(id)?.end()
    }

    async fn handle_update_two_d_cartesian_zone(
        &self,
        ctx: impl InvokeContext,
        request: UpdateTwoDCartesianZoneRequest<'_>,
    ) -> Result<(), Error> {
        if !self.has_feature(decl::Feature::USER_DEFINED.bits()) {
            return Err(ErrorCode::InvalidAction.into());
        }

        let id = request.zone_id()?;
        let payload = request.zone()?;
        let (name, zone_use, vertices, color) = self.parse_zone_payload(&payload)?;

        let prior = self.state.lock(|cell| {
            cell.borrow()
                .zones
                .iter()
                .find(|z| z.zone_id == id)
                .cloned()
        });
        let Some(prior) = prior else {
            return Err(ErrorCode::NotFound.into());
        };
        if prior.zone_source != ZoneSourceEnum::User {
            return Err(ErrorCode::InvalidAction.into());
        }

        let updated = Zone {
            zone_id: id,
            zone_type: prior.zone_type,
            zone_source: ZoneSourceEnum::User,
            name,
            zone_use,
            vertices,
            color,
        };

        let prev = self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            s.zones.iter().position(|z| z.zone_id == id).map(|i| {
                let prev = s.zones[i].clone();
                s.zones[i] = updated.clone();
                prev
            })
        });
        let Some(prev) = prev else {
            return Err(ErrorCode::NotFound.into());
        };

        if let Err(e) = self.hooks.zone_updated(&updated).await {
            self.state.lock(|cell| {
                let mut s = cell.borrow_mut();
                if let Some(i) = s.zones.iter().position(|z| z.zone_id == id) {
                    s.zones[i] = prev;
                }
            });
            return Err(e.into());
        }
        ctx.notify_own_attr_changed(AttributeId::Zones as _);
        Ok(())
    }

    async fn handle_remove_zone(
        &self,
        ctx: impl InvokeContext,
        request: RemoveZoneRequest<'_>,
    ) -> Result<(), Error> {
        let id = request.zone_id()?;

        let outcome = self.state.lock(|cell| {
            let s = cell.borrow();
            match s.zones.iter().find(|z| z.zone_id == id) {
                None => Err(ErrorCode::NotFound),
                Some(z) if z.zone_source != ZoneSourceEnum::User => Err(ErrorCode::InvalidAction),
                _ => Ok(()),
            }
        });
        outcome.map_err(Error::from)?;

        self.hooks.zone_removed(id).await?;

        let triggers_changed = self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            s.zones.retain(|z| z.zone_id != id);
            let before = s.triggers.len();
            s.triggers.retain(|t| t.zone_id != id);
            s.triggers.len() != before
        });
        ctx.notify_own_attr_changed(AttributeId::Zones as _);
        if triggers_changed {
            ctx.notify_own_attr_changed(AttributeId::Triggers as _);
        }
        Ok(())
    }

    async fn handle_create_or_update_trigger(
        &self,
        ctx: impl InvokeContext,
        request: CreateOrUpdateTriggerRequest<'_>,
    ) -> Result<(), Error> {
        let payload = request.trigger()?;
        let zone_id = payload.zone_id()?;
        let initial_duration = payload.initial_duration()?;
        let augmentation_duration = payload.augmentation_duration()?;
        let max_duration = payload.max_duration()?;
        let blind_duration = payload.blind_duration()?;
        let sensitivity = payload.sensitivity()?;

        let zone_exists = self
            .state
            .lock(|cell| cell.borrow().zones.iter().any(|z| z.zone_id == zone_id));
        if !zone_exists {
            return Err(ErrorCode::NotFound.into());
        }

        if max_duration < initial_duration
            || (augmentation_duration > 0 && initial_duration >= max_duration)
        {
            return Err(ErrorCode::ConstraintError.into());
        }
        if let Some(s) = sensitivity {
            if s < 1 || s > self.config.sensitivity_max {
                return Err(ErrorCode::ConstraintError.into());
            }
        }

        let trigger = Trigger {
            zone_id,
            initial_duration,
            augmentation_duration,
            max_duration,
            blind_duration,
            sensitivity,
        };

        let pushed = self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            if let Some(t) = s.triggers.iter_mut().find(|t| t.zone_id == zone_id) {
                *t = trigger;
                true
            } else {
                s.triggers.push(trigger).is_ok()
            }
        });
        if !pushed {
            return Err(ErrorCode::ResourceExhausted.into());
        }

        if let Err(e) = self.hooks.trigger_set(&trigger).await {
            self.state.lock(|cell| {
                let mut s = cell.borrow_mut();
                s.triggers.retain(|t| t.zone_id != zone_id);
            });
            return Err(e.into());
        }
        ctx.notify_own_attr_changed(AttributeId::Triggers as _);
        Ok(())
    }

    async fn handle_remove_trigger(
        &self,
        ctx: impl InvokeContext,
        request: RemoveTriggerRequest<'_>,
    ) -> Result<(), Error> {
        let zone_id = request.zone_id()?;
        let existed = self
            .state
            .lock(|cell| cell.borrow().triggers.iter().any(|t| t.zone_id == zone_id));
        if !existed {
            return Err(ErrorCode::NotFound.into());
        }
        self.hooks.trigger_removed(zone_id).await?;
        self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            s.triggers.retain(|t| t.zone_id != zone_id);
        });
        ctx.notify_own_attr_changed(AttributeId::Triggers as _);
        Ok(())
    }
}

// -----------------------------------------------------------------------
// Local helpers
// -----------------------------------------------------------------------

fn write_zone_info<P: TLVBuilderParent, const NV: usize>(
    builder: ZoneInformationStructBuilder<P>,
    z: &Zone<NV>,
) -> Result<P, Error> {
    let b = builder
        .zone_id(z.zone_id)?
        .zone_type(z.zone_type)?
        .zone_source(z.zone_source)?;
    // The 2-D Cartesian zone payload is an OptionalBuilder; for
    // ZoneTypeEnum::TwoDCARTZone we always emit it.
    b.two_d_cartesian_zone()?
        .with_some_if(z.zone_type == ZoneTypeEnum::TwoDCARTZone, |zone_b| {
            let zone_b = zone_b.name(z.name.as_str())?.r#use(z.zone_use)?;
            let mut va = zone_b.vertices()?;
            for (x, y) in z.vertices.iter().copied() {
                va = va.push()?.x(x)?.y(y)?.end()?;
            }
            let zone_b = va.end()?;
            zone_b.color(z.color.as_ref().map(|c| c.as_str()))?.end()
        })?
        .end()
}

fn write_trigger<P: TLVBuilderParent>(
    builder: ZoneTriggerControlStructBuilder<P>,
    t: &Trigger,
) -> Result<P, Error> {
    builder
        .zone_id(t.zone_id)?
        .initial_duration(t.initial_duration)?
        .augmentation_duration(t.augmentation_duration)?
        .max_duration(t.max_duration)?
        .blind_duration(t.blind_duration)?
        .sensitivity(t.sensitivity)?
        .end()
}
