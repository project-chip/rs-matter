/*
 *
 *    Copyright (c) 2020-2026 Project CHIP Authors
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

//! Implementation of the Matter Camera AV Settings User-Level Management
//! cluster (0x0552).
//!
//! Exposes the user-tunable side of the camera: mechanical pan/tilt/zoom
//! (MPTZ) position, named MPTZ presets, and per-stream digital
//! pan/tilt/zoom (DPTZ) viewports. Controllers (SmartThings, Google
//! Home, Apple Home, `chip-tool`) drive this cluster directly to move
//! the camera or pan a viewport inside an already-allocated video
//! stream.
//!
//! # Architecture (Pattern B1 — "Hooks")
//!
//! [`CamAvSettingsHandler`] owns the spec-defined state — the current
//! MPTZ position, the preset table, the DPTZ viewport table — and
//! performs all spec validation. The application supplies a
//! [`CamAvSettingsHooks`] implementation that translates accepted
//! commands into actuator / encoder calls.
//!
//! ```text
//! ┌──────────────────────┐  ClusterAsyncHandler   ┌───────────────────┐
//! │                      │◀── inbound commands ───│   rs-matter IM    │
//! │ CamAvSettingsHandler │                        │     dispatcher    │
//! └──────┬───────────────┘                        └───────────────────┘
//!        │ delegates apply / move
//!        ▼
//! ┌──────────────────────┐
//! │ CamAvSettingsHooks   │  user-supplied (PTZ motors / GPU crop)
//! └──────────────────────┘
//! ```
//!
//! # Const generics
//!
//! * `NP` — maximum number of MPTZ presets stored at once.
//! * `NS` — maximum number of `DPTZStreams` rows.
//!
//! # Feature support
//!
//! All five spec features are implemented:
//!
//! | Feature             | Bit | Effect                                       |
//! |---------------------|-----|----------------------------------------------|
//! | `DIGITAL_PTZ`       | 0x1 | DPTZStreams attribute + DPTZSet/RelativeMove |
//! | `MECHANICAL_PAN`    | 0x2 | Pan range + pan field on MPTZPosition        |
//! | `MECHANICAL_TILT`   | 0x4 | Tilt range + tilt field on MPTZPosition      |
//! | `MECHANICAL_ZOOM`   | 0x8 | ZoomMax + zoom field on MPTZPosition         |
//! | `MECHANICAL_PRESETS`| 0x10| MaxPresets/MPTZPresets + 3 preset commands   |
//!
//! Any subset is valid; the handler refuses commands and rejects
//! attribute reads for features that aren't enabled. Three convenience
//! `CLUSTER_*` constants ([`CLUSTER_FULL`], [`CLUSTER_DPTZ_ONLY`],
//! [`CLUSTER_MPTZ_ALL`]) advertise the matching attribute and command
//! lists.

use core::cell::RefCell;

use heapless::String as HString;

use crate::dm::{ArrayAttributeRead, Cluster, Dataver, EndptId, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVBuilderParent, Utf8Str};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::with;

#[allow(unused_imports)]
pub use crate::dm::clusters::decl::camera_av_settings_user_level_management::*;

use super::super::decl::camera_av_settings_user_level_management as decl;

/// Maximum length, in bytes, of an MPTZ preset name (Matter spec cap).
pub const MAX_PRESET_NAME_LEN: usize = 32;

// -----------------------------------------------------------------------
// Public domain types
// -----------------------------------------------------------------------

/// Errors that a [`CamAvSettingsHooks`] implementation can surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CamAvSettingsError {
    /// The hardware refused the request (e.g. motor stalled).
    Failure,
    /// The preset / stream id does not exist.
    NotFound,
    /// The application's storage for presets / streams is full.
    ResourceExhausted,
    /// The request is well-formed but currently impossible (e.g.
    /// camera locked by privacy mode).
    DynamicConstraint,
}

impl From<CamAvSettingsError> for Error {
    fn from(e: CamAvSettingsError) -> Self {
        match e {
            CamAvSettingsError::Failure => ErrorCode::Failure.into(),
            CamAvSettingsError::NotFound => ErrorCode::NotFound.into(),
            CamAvSettingsError::ResourceExhausted => ErrorCode::ResourceExhausted.into(),
            CamAvSettingsError::DynamicConstraint => ErrorCode::ConstraintError.into(),
        }
    }
}

/// Mechanical pan/tilt/zoom triple. Each axis is `None` when the
/// corresponding feature bit is disabled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Mptz {
    pub pan: Option<i16>,
    pub tilt: Option<i16>,
    pub zoom: Option<u8>,
}

/// One row in the `MPTZPresets` attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MptzPreset {
    pub preset_id: u8,
    pub name: HString<MAX_PRESET_NAME_LEN>,
    pub settings: Mptz,
}

/// One row in the `DPTZStreams` attribute. Coordinates are interpreted
/// in the underlying video stream's full sensor coordinate space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DptzView {
    pub video_stream_id: u16,
    pub x1: u16,
    pub y1: u16,
    pub x2: u16,
    pub y2: u16,
}

impl DptzView {
    fn validate(&self) -> Result<(), Error> {
        if self.x2 <= self.x1 || self.y2 <= self.y1 {
            return Err(ErrorCode::ConstraintError.into());
        }
        Ok(())
    }
}

/// Static configuration for a [`CamAvSettingsHandler`].
///
/// Range fields are honoured only when the matching feature bit is
/// enabled. `default_position` is the boot-time `MPTZPosition` value
/// reported before the first `MPTZSetPosition` command — fields for
/// disabled features are ignored.
#[derive(Debug, Clone, Copy)]
pub struct CamAvSettingsConfig {
    /// Inclusive pan limits in hundredths of degrees, used when
    /// `MECHANICAL_PAN` is enabled. Spec range: -18000..=17999.
    pub pan_range: (i16, i16),
    /// Inclusive tilt limits in hundredths of degrees, used when
    /// `MECHANICAL_TILT` is enabled. Spec range: -9000..=9000.
    pub tilt_range: (i16, i16),
    /// Maximum zoom factor (1 = no zoom), used when `MECHANICAL_ZOOM`
    /// is enabled. Spec range: 1..=100.
    pub zoom_max: u8,
    /// Boot-time MPTZ position. Disabled-feature fields are ignored.
    pub default_position: Mptz,
    /// Maximum number of presets the device exposes. Capped to `NP`
    /// at construction. Required when `MECHANICAL_PRESETS` is enabled.
    pub max_presets: u8,
}

/// Application hooks for the side-effecting pieces of the cluster.
/// All hooks have a no-op default implementation.
#[allow(unused_variables)]
pub trait CamAvSettingsHooks {
    /// Apply a mechanical pan/tilt/zoom target. Called after the
    /// handler has validated bounds against the configured ranges and
    /// the enabled feature set.
    ///
    /// On `Err` the handler rolls back its internal `MPTZPosition`
    /// snapshot to the prior value.
    fn mptz_apply(
        &self,
        target: &Mptz,
    ) -> impl core::future::Future<Output = Result<(), CamAvSettingsError>> {
        async { Ok(()) }
    }

    /// Apply a digital viewport for a video stream. Called after the
    /// handler has validated `x1<x2`, `y1<y2`. Hardware-specific
    /// per-stream bounds (resolution caps, aspect-ratio constraints)
    /// are the implementation's responsibility.
    fn dptz_apply(
        &self,
        view: &DptzView,
    ) -> impl core::future::Future<Output = Result<(), CamAvSettingsError>> {
        async { Ok(()) }
    }

    /// Notify that a preset was saved or overwritten. The handler has
    /// already updated its `MPTZPresets` table; this hook is purely
    /// informational so the application can persist the preset across
    /// reboots if it wishes. Returning `Err` rolls back the save.
    fn preset_saved(
        &self,
        preset: &MptzPreset,
    ) -> impl core::future::Future<Output = Result<(), CamAvSettingsError>> {
        async { Ok(()) }
    }

    /// Notify that a preset was removed. Returning `Err` rolls back.
    fn preset_removed(
        &self,
        preset_id: u8,
    ) -> impl core::future::Future<Output = Result<(), CamAvSettingsError>> {
        async { Ok(()) }
    }
}

// -----------------------------------------------------------------------
// Internal state
// -----------------------------------------------------------------------

struct State<const NP: usize, const NS: usize> {
    mptz: Mptz,
    presets: Vec<MptzPreset, NP>,
    dptz: Vec<DptzView, NS>,
    seeded: bool,
}

impl<const NP: usize, const NS: usize> State<NP, NS> {
    const fn new() -> Self {
        Self {
            mptz: Mptz {
                pan: None,
                tilt: None,
                zoom: None,
            },
            presets: Vec::new(),
            dptz: Vec::new(),
            seeded: false,
        }
    }
}

// -----------------------------------------------------------------------
// CLUSTER constants
// -----------------------------------------------------------------------

/// `CLUSTER` advertising every feature: full MPTZ + presets + DPTZ.
pub const CLUSTER_FULL: Cluster<'static> = decl::FULL_CLUSTER
    .with_revision(1)
    .with_features(
        decl::Feature::DIGITAL_PTZ.bits()
            | decl::Feature::MECHANICAL_PAN.bits()
            | decl::Feature::MECHANICAL_TILT.bits()
            | decl::Feature::MECHANICAL_ZOOM.bits()
            | decl::Feature::MECHANICAL_PRESETS.bits(),
    )
    .with_attrs(with!(
        required;
        AttributeId::MPTZPosition
            | AttributeId::MaxPresets
            | AttributeId::MPTZPresets
            | AttributeId::DPTZStreams
            | AttributeId::ZoomMax
            | AttributeId::TiltMin
            | AttributeId::TiltMax
            | AttributeId::PanMin
            | AttributeId::PanMax
            | AttributeId::MovementState
    ))
    .with_cmds(with!(
        decl::CommandId::MPTZSetPosition
            | decl::CommandId::MPTZRelativeMove
            | decl::CommandId::MPTZMoveToPreset
            | decl::CommandId::MPTZSavePreset
            | decl::CommandId::MPTZRemovePreset
            | decl::CommandId::DPTZSetViewport
            | decl::CommandId::DPTZRelativeMove
    ));

/// `CLUSTER` advertising only `DIGITAL_PTZ` — fixed lens, software pan
/// inside the encoded frame.
pub const CLUSTER_DPTZ_ONLY: Cluster<'static> = decl::FULL_CLUSTER
    .with_revision(1)
    .with_features(decl::Feature::DIGITAL_PTZ.bits())
    .with_attrs(with!(required; AttributeId::DPTZStreams))
    .with_cmds(with!(
        decl::CommandId::DPTZSetViewport | decl::CommandId::DPTZRelativeMove
    ));

/// `CLUSTER` advertising the full mechanical PTZ surface (`PAN | TILT |
/// ZOOM | PRESETS`), but no `DIGITAL_PTZ`.
pub const CLUSTER_MPTZ_ALL: Cluster<'static> = decl::FULL_CLUSTER
    .with_revision(1)
    .with_features(
        decl::Feature::MECHANICAL_PAN.bits()
            | decl::Feature::MECHANICAL_TILT.bits()
            | decl::Feature::MECHANICAL_ZOOM.bits()
            | decl::Feature::MECHANICAL_PRESETS.bits(),
    )
    .with_attrs(with!(
        required;
        AttributeId::MPTZPosition
            | AttributeId::MaxPresets
            | AttributeId::MPTZPresets
            | AttributeId::ZoomMax
            | AttributeId::TiltMin
            | AttributeId::TiltMax
            | AttributeId::PanMin
            | AttributeId::PanMax
            | AttributeId::MovementState
    ))
    .with_cmds(with!(
        decl::CommandId::MPTZSetPosition
            | decl::CommandId::MPTZRelativeMove
            | decl::CommandId::MPTZMoveToPreset
            | decl::CommandId::MPTZSavePreset
            | decl::CommandId::MPTZRemovePreset
    ));

// -----------------------------------------------------------------------
// Handler
// -----------------------------------------------------------------------

/// Handler for the Camera AV Settings User-Level Management cluster
/// (0x0552). Pattern B1 ("Hooks").
pub struct CamAvSettingsHandler<H, const NP: usize, const NS: usize>
where
    H: CamAvSettingsHooks,
{
    dataver: Dataver,
    endpoint_id: EndptId,
    cluster: Cluster<'static>,
    config: CamAvSettingsConfig,
    hooks: H,
    state: Mutex<RefCell<State<NP, NS>>>,
}

impl<H, const NP: usize, const NS: usize> CamAvSettingsHandler<H, NP, NS>
where
    H: CamAvSettingsHooks,
{
    /// Construct a new handler.
    ///
    /// `cluster` must be one of [`CLUSTER_FULL`], [`CLUSTER_DPTZ_ONLY`],
    /// [`CLUSTER_MPTZ_ALL`], or any user-built [`Cluster`] derived from
    /// [`FULL_CLUSTER`]. Its `feature_map` drives runtime gating.
    pub const fn new(
        dataver: Dataver,
        endpoint_id: EndptId,
        cluster: Cluster<'static>,
        config: CamAvSettingsConfig,
        hooks: H,
    ) -> Self {
        Self {
            dataver,
            endpoint_id,
            cluster,
            config,
            hooks,
            state: Mutex::new(RefCell::new(State::new())),
        }
    }

    /// Wrap in the async dispatcher adaptor for registration on an
    /// async-handler chain.
    pub const fn adapt(self) -> decl::HandlerAsyncAdaptor<Self> {
        decl::HandlerAsyncAdaptor(self)
    }

    /// Endpoint id this handler was constructed against.
    pub const fn endpoint_id(&self) -> EndptId {
        self.endpoint_id
    }

    /// Feature bits advertised on this handler's [`Cluster`].
    pub fn features(&self) -> u32 {
        self.cluster.feature_map
    }

    fn has_feature(&self, bit: u32) -> bool {
        self.features() & bit != 0
    }

    /// Pre-seed a DPTZ stream entry at boot. Useful when the camera has
    /// a fixed default viewport per video stream that controllers
    /// should see immediately on subscription.
    pub fn add_preallocated_dptz(&self, view: DptzView) -> Result<(), Error> {
        view.validate()?;
        self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            if s.dptz
                .iter()
                .any(|v| v.video_stream_id == view.video_stream_id)
            {
                return Err(Error::from(ErrorCode::ConstraintError));
            }
            s.dptz
                .push(view)
                .map_err(|_| Error::from(ErrorCode::ResourceExhausted))
        })?;
        self.dataver.changed();
        Ok(())
    }

    /// Remove a DPTZ stream entry by video stream ID.
    /// Returns `NotFound` if no entry with that ID exists.
    pub fn remove_dptz_stream(&self, video_stream_id: u16) -> Result<(), Error> {
        self.state.lock(|cell| -> Result<(), Error> {
            let mut s = cell.borrow_mut();
            let pos = s
                .dptz
                .iter()
                .position(|v| v.video_stream_id == video_stream_id)
                .ok_or(Error::from(ErrorCode::NotFound))?;
            s.dptz.swap_remove(pos);
            Ok(())
        })?;
        self.dataver.changed();
        Ok(())
    }

    /// Pre-seed an MPTZ preset at boot. Returns `ConstraintError` if
    /// the id is out of range, `ResourceExhausted` if the table is full.
    pub fn add_preallocated_preset(&self, preset: MptzPreset) -> Result<(), Error> {
        self.validate_preset_id(preset.preset_id)?;
        self.validate_mptz(&preset.settings)?;
        if preset.name.is_empty() {
            return Err(ErrorCode::ConstraintError.into());
        }
        self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            if s.presets.iter().any(|p| p.preset_id == preset.preset_id) {
                return Err(Error::from(ErrorCode::ConstraintError));
            }
            s.presets
                .push(preset)
                .map_err(|_| Error::from(ErrorCode::ResourceExhausted))
        })?;
        self.dataver.changed();
        Ok(())
    }

    /// Snapshot of the current MPTZ position. Useful for tests and
    /// example wiring.
    pub fn current_mptz(&self) -> Mptz {
        self.ensure_seeded();
        self.state.lock(|cell| cell.borrow().mptz)
    }

    /// Snapshot of the DPTZ viewport list.
    pub fn dptz_streams(&self) -> Vec<DptzView, NS> {
        self.state.lock(|cell| cell.borrow().dptz.clone())
    }

    /// Snapshot of the preset list.
    pub fn presets(&self) -> Vec<MptzPreset, NP> {
        self.state.lock(|cell| cell.borrow().presets.clone())
    }

    fn ensure_seeded(&self) {
        self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            if !s.seeded {
                s.mptz = self.masked_default_position();
                s.seeded = true;
            }
        });
    }

    /// Filter `default_position` against the enabled feature set so
    /// disabled axes are reported as `None`.
    fn masked_default_position(&self) -> Mptz {
        Mptz {
            pan: if self.has_feature(decl::Feature::MECHANICAL_PAN.bits()) {
                self.config.default_position.pan
            } else {
                None
            },
            tilt: if self.has_feature(decl::Feature::MECHANICAL_TILT.bits()) {
                self.config.default_position.tilt
            } else {
                None
            },
            zoom: if self.has_feature(decl::Feature::MECHANICAL_ZOOM.bits()) {
                self.config.default_position.zoom
            } else {
                None
            },
        }
    }

    fn any_mptz_axis(&self) -> bool {
        self.has_feature(decl::Feature::MECHANICAL_PAN.bits())
            || self.has_feature(decl::Feature::MECHANICAL_TILT.bits())
            || self.has_feature(decl::Feature::MECHANICAL_ZOOM.bits())
    }

    fn validate_preset_id(&self, id: u8) -> Result<(), Error> {
        if id == 0 || id > self.config.max_presets {
            return Err(ErrorCode::ConstraintError.into());
        }
        Ok(())
    }

    /// Validate an MPTZ target against the enabled feature set and the
    /// configured ranges. Disabled axes must be `None`; enabled axes
    /// must be `Some` and in range.
    fn validate_mptz(&self, m: &Mptz) -> Result<(), Error> {
        let pan_en = self.has_feature(decl::Feature::MECHANICAL_PAN.bits());
        let tilt_en = self.has_feature(decl::Feature::MECHANICAL_TILT.bits());
        let zoom_en = self.has_feature(decl::Feature::MECHANICAL_ZOOM.bits());

        match (pan_en, m.pan) {
            (true, Some(v)) if v < self.config.pan_range.0 || v > self.config.pan_range.1 => {
                return Err(ErrorCode::ConstraintError.into());
            }
            (true, None) | (true, Some(_)) => {}
            (false, Some(_)) => return Err(ErrorCode::ConstraintError.into()),
            (false, None) => {}
        }
        match (tilt_en, m.tilt) {
            (true, Some(v)) if v < self.config.tilt_range.0 || v > self.config.tilt_range.1 => {
                return Err(ErrorCode::ConstraintError.into());
            }
            (true, None) | (true, Some(_)) => {}
            (false, Some(_)) => return Err(ErrorCode::ConstraintError.into()),
            (false, None) => {}
        }
        match (zoom_en, m.zoom) {
            (true, Some(v)) if v < 1 || v > self.config.zoom_max => {
                return Err(ErrorCode::ConstraintError.into());
            }
            (true, None) | (true, Some(_)) => {}
            (false, Some(_)) => return Err(ErrorCode::ConstraintError.into()),
            (false, None) => {}
        }
        Ok(())
    }

    fn clamp_axis_i16(&self, lo: i16, hi: i16, v: i32) -> i16 {
        v.max(lo as i32).min(hi as i32) as i16
    }

    fn clamp_zoom(&self, v: i32) -> u8 {
        v.max(1).min(self.config.zoom_max as i32) as u8
    }
}

// -----------------------------------------------------------------------
// ClusterAsyncHandler impl
// -----------------------------------------------------------------------

impl<H, const NP: usize, const NS: usize> ClusterAsyncHandler for CamAvSettingsHandler<H, NP, NS>
where
    H: CamAvSettingsHooks,
{
    const CLUSTER: Cluster<'static> = CLUSTER_FULL;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    // ---- attributes ----

    async fn mptz_position<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: MPTZStructBuilder<P>,
    ) -> Result<P, Error> {
        if !self.any_mptz_axis() {
            return Err(ErrorCode::AttributeNotFound.into());
        }
        self.ensure_seeded();
        let m = self.state.lock(|cell| cell.borrow().mptz);
        builder.pan(m.pan)?.tilt(m.tilt)?.zoom(m.zoom)?.end()
    }

    async fn max_presets(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        if !self.has_feature(decl::Feature::MECHANICAL_PRESETS.bits()) {
            return Err(ErrorCode::AttributeNotFound.into());
        }
        Ok(self.config.max_presets.min(NP as u8))
    }

    async fn mptz_presets<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<MPTZPresetStructArrayBuilder<P>, MPTZPresetStructBuilder<P>>,
    ) -> Result<P, Error> {
        if !self.has_feature(decl::Feature::MECHANICAL_PRESETS.bits()) {
            return Err(ErrorCode::AttributeNotFound.into());
        }
        let snapshot = self.state.lock(|cell| cell.borrow().presets.clone());
        match builder {
            ArrayAttributeRead::ReadAll(mut b) => {
                for p in snapshot.iter() {
                    b = write_preset(b.push()?, p)?;
                }
                b.end()
            }
            ArrayAttributeRead::ReadOne(idx, b) => {
                let Some(p) = snapshot.get(idx as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };
                write_preset(b, p)
            }
            ArrayAttributeRead::ReadNone(b) => b.end(),
        }
    }

    async fn dptz_streams<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<DPTZStructArrayBuilder<P>, DPTZStructBuilder<P>>,
    ) -> Result<P, Error> {
        if !self.has_feature(decl::Feature::DIGITAL_PTZ.bits()) {
            return Err(ErrorCode::AttributeNotFound.into());
        }
        let snapshot = self.state.lock(|cell| cell.borrow().dptz.clone());
        match builder {
            ArrayAttributeRead::ReadAll(mut b) => {
                for v in snapshot.iter() {
                    b = write_dptz(b.push()?, v)?;
                }
                b.end()
            }
            ArrayAttributeRead::ReadOne(idx, b) => {
                let Some(v) = snapshot.get(idx as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };
                write_dptz(b, v)
            }
            ArrayAttributeRead::ReadNone(b) => b.end(),
        }
    }

    async fn zoom_max(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        if !self.has_feature(decl::Feature::MECHANICAL_ZOOM.bits()) {
            return Err(ErrorCode::AttributeNotFound.into());
        }
        Ok(self.config.zoom_max)
    }

    async fn tilt_min(&self, _ctx: impl ReadContext) -> Result<i16, Error> {
        if !self.has_feature(decl::Feature::MECHANICAL_TILT.bits()) {
            return Err(ErrorCode::AttributeNotFound.into());
        }
        Ok(self.config.tilt_range.0)
    }

    async fn tilt_max(&self, _ctx: impl ReadContext) -> Result<i16, Error> {
        if !self.has_feature(decl::Feature::MECHANICAL_TILT.bits()) {
            return Err(ErrorCode::AttributeNotFound.into());
        }
        Ok(self.config.tilt_range.1)
    }

    async fn pan_min(&self, _ctx: impl ReadContext) -> Result<i16, Error> {
        if !self.has_feature(decl::Feature::MECHANICAL_PAN.bits()) {
            return Err(ErrorCode::AttributeNotFound.into());
        }
        Ok(self.config.pan_range.0)
    }

    async fn pan_max(&self, _ctx: impl ReadContext) -> Result<i16, Error> {
        if !self.has_feature(decl::Feature::MECHANICAL_PAN.bits()) {
            return Err(ErrorCode::AttributeNotFound.into());
        }
        Ok(self.config.pan_range.1)
    }

    async fn movement_state(&self, _ctx: impl ReadContext) -> Result<PhysicalMovementEnum, Error> {
        if !self.any_mptz_axis() {
            return Err(ErrorCode::AttributeNotFound.into());
        }
        // Commands complete synchronously from the data-model's
        // perspective, so we always report Idle outside of an in-flight
        // invocation.
        Ok(PhysicalMovementEnum::Idle)
    }

    // ---- commands ----

    async fn handle_mptz_set_position(
        &self,
        ctx: impl InvokeContext,
        request: MPTZSetPositionRequest<'_>,
    ) -> Result<(), Error> {
        if !self.any_mptz_axis() {
            return Err(ErrorCode::InvalidAction.into());
        }
        self.ensure_seeded();

        let req_pan = request.pan()?;
        let req_tilt = request.tilt()?;
        let req_zoom = request.zoom()?;

        let prior = self.state.lock(|cell| cell.borrow().mptz);
        let target = Mptz {
            pan: if self.has_feature(decl::Feature::MECHANICAL_PAN.bits()) {
                req_pan.or(prior.pan)
            } else {
                None
            },
            tilt: if self.has_feature(decl::Feature::MECHANICAL_TILT.bits()) {
                req_tilt.or(prior.tilt)
            } else {
                None
            },
            zoom: if self.has_feature(decl::Feature::MECHANICAL_ZOOM.bits()) {
                req_zoom.or(prior.zoom)
            } else {
                None
            },
        };
        // Reject sets touching disabled axes outright.
        if (!self.has_feature(decl::Feature::MECHANICAL_PAN.bits()) && req_pan.is_some())
            || (!self.has_feature(decl::Feature::MECHANICAL_TILT.bits()) && req_tilt.is_some())
            || (!self.has_feature(decl::Feature::MECHANICAL_ZOOM.bits()) && req_zoom.is_some())
        {
            return Err(ErrorCode::ConstraintError.into());
        }
        self.validate_mptz(&target)?;

        self.state.lock(|cell| cell.borrow_mut().mptz = target);
        if let Err(e) = self.hooks.mptz_apply(&target).await {
            self.state.lock(|cell| cell.borrow_mut().mptz = prior);
            return Err(e.into());
        }
        ctx.notify_own_attr_changed(AttributeId::MPTZPosition as _);
        Ok(())
    }

    async fn handle_mptz_relative_move(
        &self,
        ctx: impl InvokeContext,
        request: MPTZRelativeMoveRequest<'_>,
    ) -> Result<(), Error> {
        if !self.any_mptz_axis() {
            return Err(ErrorCode::InvalidAction.into());
        }
        self.ensure_seeded();

        let pan_delta = request.pan_delta()?;
        let tilt_delta = request.tilt_delta()?;
        let zoom_delta = request.zoom_delta()?;

        if (!self.has_feature(decl::Feature::MECHANICAL_PAN.bits()) && pan_delta.is_some())
            || (!self.has_feature(decl::Feature::MECHANICAL_TILT.bits()) && tilt_delta.is_some())
            || (!self.has_feature(decl::Feature::MECHANICAL_ZOOM.bits()) && zoom_delta.is_some())
        {
            return Err(ErrorCode::ConstraintError.into());
        }

        let prior = self.state.lock(|cell| cell.borrow().mptz);
        let mut target = prior;
        if let (true, Some(d)) = (
            self.has_feature(decl::Feature::MECHANICAL_PAN.bits()),
            pan_delta,
        ) {
            let cur = prior.pan.unwrap_or(0) as i32 + d as i32;
            target.pan =
                Some(self.clamp_axis_i16(self.config.pan_range.0, self.config.pan_range.1, cur));
        }
        if let (true, Some(d)) = (
            self.has_feature(decl::Feature::MECHANICAL_TILT.bits()),
            tilt_delta,
        ) {
            let cur = prior.tilt.unwrap_or(0) as i32 + d as i32;
            target.tilt =
                Some(self.clamp_axis_i16(self.config.tilt_range.0, self.config.tilt_range.1, cur));
        }
        if let (true, Some(d)) = (
            self.has_feature(decl::Feature::MECHANICAL_ZOOM.bits()),
            zoom_delta,
        ) {
            let cur = prior.zoom.unwrap_or(1) as i32 + d as i32;
            target.zoom = Some(self.clamp_zoom(cur));
        }

        self.state.lock(|cell| cell.borrow_mut().mptz = target);
        if let Err(e) = self.hooks.mptz_apply(&target).await {
            self.state.lock(|cell| cell.borrow_mut().mptz = prior);
            return Err(e.into());
        }
        ctx.notify_own_attr_changed(AttributeId::MPTZPosition as _);
        Ok(())
    }

    async fn handle_mptz_move_to_preset(
        &self,
        ctx: impl InvokeContext,
        request: MPTZMoveToPresetRequest<'_>,
    ) -> Result<(), Error> {
        if !self.has_feature(decl::Feature::MECHANICAL_PRESETS.bits()) {
            return Err(ErrorCode::InvalidAction.into());
        }
        let id = request.preset_id()?;
        self.validate_preset_id(id)?;
        let preset = self.state.lock(|cell| {
            cell.borrow()
                .presets
                .iter()
                .find(|p| p.preset_id == id)
                .cloned()
        });
        let Some(preset) = preset else {
            return Err(ErrorCode::NotFound.into());
        };
        // Apply via the same path as set_position, with rollback.
        self.ensure_seeded();
        let prior = self.state.lock(|cell| cell.borrow().mptz);
        self.state
            .lock(|cell| cell.borrow_mut().mptz = preset.settings);
        if let Err(e) = self.hooks.mptz_apply(&preset.settings).await {
            self.state.lock(|cell| cell.borrow_mut().mptz = prior);
            return Err(e.into());
        }
        ctx.notify_own_attr_changed(AttributeId::MPTZPosition as _);
        Ok(())
    }

    async fn handle_mptz_save_preset(
        &self,
        ctx: impl InvokeContext,
        request: MPTZSavePresetRequest<'_>,
    ) -> Result<(), Error> {
        if !self.has_feature(decl::Feature::MECHANICAL_PRESETS.bits()) {
            return Err(ErrorCode::InvalidAction.into());
        }
        self.ensure_seeded();

        let req_id = request.preset_id()?;
        let name_str: Utf8Str<'_> = request.name()?;
        let mut name: HString<MAX_PRESET_NAME_LEN> = HString::new();
        if name_str.is_empty()
            || name_str.len() > MAX_PRESET_NAME_LEN
            || name.push_str(name_str).is_err()
        {
            return Err(ErrorCode::ConstraintError.into());
        }

        let id = match req_id {
            Some(i) => {
                self.validate_preset_id(i)?;
                i
            }
            None => {
                // Allocate the lowest free id within
                // 1..=max_presets.
                let max_id = self.config.max_presets.min(NP as u8);
                let used: heapless::Vec<u8, NP> = self.state.lock(|cell| {
                    let mut v: heapless::Vec<u8, NP> = heapless::Vec::new();
                    for p in cell.borrow().presets.iter() {
                        let _ = v.push(p.preset_id);
                    }
                    v
                });
                let mut chosen: Option<u8> = None;
                for cand in 1..=max_id {
                    if !used.contains(&cand) {
                        chosen = Some(cand);
                        break;
                    }
                }
                chosen.ok_or_else(|| Error::from(ErrorCode::ResourceExhausted))?
            }
        };

        let settings = self.state.lock(|cell| cell.borrow().mptz);
        self.validate_mptz(&settings)?;
        let preset = MptzPreset {
            preset_id: id,
            name,
            settings,
        };

        // Replace or insert; remember prior for rollback.
        let prior = self.state.lock(|cell| {
            cell.borrow()
                .presets
                .iter()
                .find(|p| p.preset_id == id)
                .cloned()
        });
        let pushed = self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            if let Some(p) = s.presets.iter_mut().find(|p| p.preset_id == id) {
                *p = preset.clone();
                true
            } else {
                s.presets.push(preset.clone()).is_ok()
            }
        });
        if !pushed {
            return Err(ErrorCode::ResourceExhausted.into());
        }

        if let Err(e) = self.hooks.preset_saved(&preset).await {
            self.state.lock(|cell| {
                let mut s = cell.borrow_mut();
                match prior {
                    Some(p) => {
                        if let Some(slot) = s.presets.iter_mut().find(|x| x.preset_id == id) {
                            *slot = p;
                        }
                    }
                    None => s.presets.retain(|x| x.preset_id != id),
                }
            });
            return Err(e.into());
        }
        ctx.notify_own_attr_changed(AttributeId::MPTZPresets as _);
        Ok(())
    }

    async fn handle_mptz_remove_preset(
        &self,
        ctx: impl InvokeContext,
        request: MPTZRemovePresetRequest<'_>,
    ) -> Result<(), Error> {
        if !self.has_feature(decl::Feature::MECHANICAL_PRESETS.bits()) {
            return Err(ErrorCode::InvalidAction.into());
        }
        let id = request.preset_id()?;
        self.validate_preset_id(id)?;
        let existed = self
            .state
            .lock(|cell| cell.borrow().presets.iter().any(|p| p.preset_id == id));
        if !existed {
            return Err(ErrorCode::NotFound.into());
        }
        self.hooks.preset_removed(id).await?;
        self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            s.presets.retain(|p| p.preset_id != id);
        });
        ctx.notify_own_attr_changed(AttributeId::MPTZPresets as _);
        Ok(())
    }

    async fn handle_dptz_set_viewport(
        &self,
        ctx: impl InvokeContext,
        request: DPTZSetViewportRequest<'_>,
    ) -> Result<(), Error> {
        if !self.has_feature(decl::Feature::DIGITAL_PTZ.bits()) {
            return Err(ErrorCode::InvalidAction.into());
        }
        let stream_id = request.video_stream_id()?;
        let vp = request.viewport()?;
        let view = DptzView {
            video_stream_id: stream_id,
            x1: vp.x_1()?,
            y1: vp.y_1()?,
            x2: vp.x_2()?,
            y2: vp.y_2()?,
        };
        view.validate()?;

        let prior = self.state.lock(|cell| {
            cell.borrow()
                .dptz
                .iter()
                .find(|v| v.video_stream_id == stream_id)
                .copied()
        });
        let pushed = self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            if let Some(slot) = s.dptz.iter_mut().find(|v| v.video_stream_id == stream_id) {
                *slot = view;
                true
            } else {
                s.dptz.push(view).is_ok()
            }
        });
        if !pushed {
            return Err(ErrorCode::ResourceExhausted.into());
        }

        if let Err(e) = self.hooks.dptz_apply(&view).await {
            self.state.lock(|cell| {
                let mut s = cell.borrow_mut();
                match prior {
                    Some(p) => {
                        if let Some(slot) =
                            s.dptz.iter_mut().find(|v| v.video_stream_id == stream_id)
                        {
                            *slot = p;
                        }
                    }
                    None => s.dptz.retain(|v| v.video_stream_id != stream_id),
                }
            });
            return Err(e.into());
        }
        ctx.notify_own_attr_changed(AttributeId::DPTZStreams as _);
        Ok(())
    }

    async fn handle_dptz_relative_move(
        &self,
        ctx: impl InvokeContext,
        request: DPTZRelativeMoveRequest<'_>,
    ) -> Result<(), Error> {
        if !self.has_feature(decl::Feature::DIGITAL_PTZ.bits()) {
            return Err(ErrorCode::InvalidAction.into());
        }
        let stream_id = request.video_stream_id()?;
        let dx = request.delta_x()?.unwrap_or(0) as i32;
        let dy = request.delta_y()?.unwrap_or(0) as i32;
        let dz = request.zoom_delta()?.unwrap_or(0) as i32;

        let prior = self.state.lock(|cell| {
            cell.borrow()
                .dptz
                .iter()
                .find(|v| v.video_stream_id == stream_id)
                .copied()
        });
        let Some(prior) = prior else {
            return Err(ErrorCode::NotFound.into());
        };

        // Translate. Zoom delta is interpreted as a pixel shrink/expand
        // applied symmetrically — clamps prevent inversion. The actual
        // pixel-perfect math is the application's job; the handler
        // only enforces ordering invariants.
        let mut x1 = prior.x1 as i32 + dx;
        let mut x2 = prior.x2 as i32 + dx;
        let mut y1 = prior.y1 as i32 + dy;
        let mut y2 = prior.y2 as i32 + dy;
        x1 = x1.max(0);
        y1 = y1.max(0);
        x2 = x2.max(x1 + 1);
        y2 = y2.max(y1 + 1);
        if dz != 0 {
            let half = dz / 2;
            x1 = (x1 - half).max(0);
            y1 = (y1 - half).max(0);
            x2 = (x2 + half).max(x1 + 1);
            y2 = (y2 + half).max(y1 + 1);
        }
        let view = DptzView {
            video_stream_id: stream_id,
            x1: x1.min(u16::MAX as i32) as u16,
            y1: y1.min(u16::MAX as i32) as u16,
            x2: x2.min(u16::MAX as i32) as u16,
            y2: y2.min(u16::MAX as i32) as u16,
        };
        view.validate()?;

        self.state.lock(|cell| {
            let mut s = cell.borrow_mut();
            if let Some(slot) = s.dptz.iter_mut().find(|v| v.video_stream_id == stream_id) {
                *slot = view;
            }
        });
        if let Err(e) = self.hooks.dptz_apply(&view).await {
            self.state.lock(|cell| {
                let mut s = cell.borrow_mut();
                if let Some(slot) = s.dptz.iter_mut().find(|v| v.video_stream_id == stream_id) {
                    *slot = prior;
                }
            });
            return Err(e.into());
        }
        ctx.notify_own_attr_changed(AttributeId::DPTZStreams as _);
        Ok(())
    }
}

// -----------------------------------------------------------------------
// Local helpers
// -----------------------------------------------------------------------

fn write_preset<P: TLVBuilderParent>(
    builder: MPTZPresetStructBuilder<P>,
    p: &MptzPreset,
) -> Result<P, Error> {
    let b = builder.preset_id(p.preset_id)?.name(p.name.as_str())?;
    let s = b.settings()?;
    s.pan(p.settings.pan)?
        .tilt(p.settings.tilt)?
        .zoom(p.settings.zoom)?
        .end()?
        .end()
}

fn write_dptz<P: TLVBuilderParent>(
    builder: DPTZStructBuilder<P>,
    v: &DptzView,
) -> Result<P, Error> {
    let b = builder.video_stream_id(v.video_stream_id)?;
    b.viewport()?
        .x_1(v.x1)?
        .y_1(v.y1)?
        .x_2(v.x2)?
        .y_2(v.y2)?
        .end()?
        .end()
}
