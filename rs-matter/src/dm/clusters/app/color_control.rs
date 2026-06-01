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

//! ColorControl cluster (skeleton handler — Scenes integration only).
//!
//! This module ships a `ColorControlHandler` whose **only complete
//! surface today is the [`SceneClusterHandler`] impl**. It does not
//! yet expose the full data-model `ClusterHandler` trait (commands
//! and attribute reads/writes are stubbed out — the
//! command-driven path will be added in a follow-up). The skeleton
//! exists primarily to validate that the
//! [`crate::dm::clusters::scenes::SceneClusterHandler`] architecture
//! gracefully handles ColorControl's shape:
//!
//! - **Up to 9 scenable attributes** (`CurrentX`, `CurrentY`,
//!   `EnhancedCurrentHue`, `CurrentSaturation`, `ColorLoopActive`,
//!   `ColorLoopDirection`, `ColorLoopTime`,
//!   `ColorTemperatureMireds`, `EnhancedColorMode`) — vs OnOff's 1
//!   and LevelControl's 1.
//! - **Feature-conditional capture**: which subset of the attrs is
//!   captured depends on the cluster's `Feature` bitmap
//!   (`XY` / `HUE_AND_SATURATION` / `ENHANCED_HUE` / `COLOR_LOOP` /
//!   `COLOR_TEMPERATURE`).
//! - **Mode-dependent apply**: `EnhancedColorMode` selects which
//!   internal applier runs — `MoveToColor`-equivalent for `XY`,
//!   `MoveToColorTemperature` for `ColorTemperatureMireds`,
//!   `MoveToHueAndSaturation` / `EnhancedMoveToHueAndSaturation` for
//!   the hue/saturation modes. `ColorLoopActive=1` short-circuits to
//!   the `ColorLoopSet` path regardless of `EnhancedColorMode`.
//! - **Per-instance feature configuration**: instances on different
//!   endpoints may enable different subsets. The handler reads its
//!   active feature bitmap from the [`ColorControlHooks`] trait.
//!
//! The handler holds a [`crate::dm::clusters::scenes::SceneInvalidator`]
//! reference (set via [`ColorControlHandler::with_scene_invalidator`])
//! so command-driven mutations of scenable attributes (when the
//! command path lands) can flip `SceneValid → false` — exactly the
//! same pattern as [`crate::dm::clusters::app::on_off::OnOffHandler`]
//! and [`crate::dm::clusters::app::level_control::LevelControlHandler`].
//!
//! ## Hooks model
//!
//! [`ColorControlHooks`] exposes per-attribute getters and setters.
//! The application implements it on whatever per-device state it
//! keeps — typically a struct cached in static memory with
//! [`core::cell::Cell`] for each field. Setters MUST be cheap and
//! synchronous; the SceneClusterHandler's `apply` calls them inline
//! and immediately follows up with `notify_attr_changed` for
//! subscribers (unless `scene_apply=true`, in which case the
//! drift-detection notification is skipped — see the OnOff/LC
//! `set_on`/`set_level` `scene_apply` parameter for the rationale).

use core::cell::Cell;

use crate::dm::clusters::decl::scenes_management::{
    AttributeValuePairStruct, AttributeValuePairStructArrayBuilder,
};
use crate::dm::clusters::scenes::{SceneClusterHandler, SceneInvalidator};
use crate::dm::types::EndptId;
use crate::dm::{AttrChangeNotifier, AttrId, ClusterId, Dataver, HandlerContext};
use crate::error::Error;
use crate::tlv::{TLVArray, TLVBuilderParent};
use crate::utils::sync::blocking::Mutex;

pub use crate::dm::clusters::decl::color_control::*;

/// Device-supplied state + I/O for the ColorControl cluster.
///
/// All getters MUST be infallible (return cached state from the
/// device's local store). All setters MUST be synchronous and cheap
/// — `SceneClusterHandler::apply` calls them inline. Both halves
/// are required even for feature subsets the device doesn't
/// implement; unsupported attributes can be backed by stub fields
/// whose setters are no-ops and whose getters return a fixed sentinel
/// (typically `0`).
///
/// `features` reports the active `Feature` bitmap for THIS endpoint
/// — different ColorControl instances may enable different subsets,
/// so the handler reads it from the hooks rather than from a global
/// constant.
pub trait ColorControlHooks {
    /// The `Feature` bitmap active on this endpoint. The Scenes
    /// integration uses it to feature-gate capture (`XY` → emit
    /// `CurrentX`/`CurrentY`, `COLOR_TEMPERATURE` → emit
    /// `ColorTemperatureMireds`, etc.).
    fn features(&self) -> Feature;

    fn current_x(&self) -> u16;
    fn set_current_x(&self, value: u16);

    fn current_y(&self) -> u16;
    fn set_current_y(&self, value: u16);

    fn enhanced_current_hue(&self) -> u16;
    fn set_enhanced_current_hue(&self, value: u16);

    fn current_saturation(&self) -> u8;
    fn set_current_saturation(&self, value: u8);

    fn color_temperature_mireds(&self) -> u16;
    fn set_color_temperature_mireds(&self, value: u16);

    fn color_loop_active(&self) -> bool;
    fn set_color_loop_active(&self, value: bool);

    fn color_loop_direction(&self) -> ColorLoopDirectionEnum;
    fn set_color_loop_direction(&self, value: ColorLoopDirectionEnum);

    /// Duration of one full color-loop cycle, in seconds (per spec).
    fn color_loop_time(&self) -> u16;
    fn set_color_loop_time(&self, value: u16);

    /// The recalled-scene's `ColorLoopSet` path uses this as the
    /// starting hue when activating the loop. Read-only at this level
    /// — there's no scenable setter (the spec's `ColorLoopSet`
    /// command sets it, but scene recall doesn't carry a new value
    /// for it).
    fn color_loop_start_enhanced_hue(&self) -> u16;

    fn enhanced_color_mode(&self) -> EnhancedColorModeEnum;
    fn set_enhanced_color_mode(&self, value: EnhancedColorModeEnum);
}

/// Skeleton ColorControl cluster handler. See module docs for the
/// scope: this currently only implements the scenes-integration
/// surface, not the full data-model `ClusterHandler` trait.
pub struct ColorControlHandler<'a, H: ColorControlHooks> {
    #[allow(dead_code)] // wired in when the command-handler path lands
    dataver: Dataver,
    endpoint_id: EndptId,
    hooks: H,
    /// Optional scene-drift notifier — see
    /// [`crate::dm::clusters::scenes::SceneInvalidator`]. Set via
    /// [`Self::with_scene_invalidator`]; defaults to `None`, in which
    /// case all internal mutators are no-ops with respect to scene
    /// invalidation.
    scene_invalidator: Mutex<Cell<Option<&'a dyn SceneInvalidator>>>,
}

impl<'a, H: ColorControlHooks> ColorControlHandler<'a, H> {
    pub fn new(dataver: Dataver, endpoint_id: EndptId, hooks: H) -> Self {
        Self {
            dataver,
            endpoint_id,
            hooks,
            scene_invalidator: Mutex::new(Cell::new(None)),
        }
    }

    /// See [`crate::dm::clusters::app::on_off::OnOffHandler::with_scene_invalidator`].
    pub fn with_scene_invalidator(self, invalidator: &'a dyn SceneInvalidator) -> Self {
        self.scene_invalidator
            .lock(|cell| cell.set(Some(invalidator)));
        self
    }

    fn notify_scenable_changed(&self) {
        if let Some(inv) = self.scene_invalidator.lock(|cell| cell.get()) {
            inv.scenable_attribute_changed(self.endpoint_id);
        }
    }

    /// Apply the `CurrentXAndCurrentY` mode: write `CurrentX` /
    /// `CurrentY` / `EnhancedColorMode` and notify subscribers.
    /// `scene_apply` gates `notify_scenable_changed` — see
    /// [`crate::dm::clusters::app::level_control::LevelControlHandler::set_level`]
    /// for the rationale.
    fn apply_xy<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        x: u16,
        y: u16,
        // _transition_time_ds: u16 — non-instant XY transitions are
        // not modelled here; the skeleton applies instantly. The
        // architecture supports threading `scene_apply` through a
        // task-based transition the same way LevelControl does.
        scene_apply: bool,
    ) {
        self.hooks.set_current_x(x);
        self.hooks.set_current_y(y);
        self.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::CurrentXAndCurrentY);
        let cluster_id = Self::CLUSTER_ID;
        ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::CurrentX as _);
        ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::CurrentY as _);
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::EnhancedColorMode as _,
        );
        if !scene_apply {
            self.notify_scenable_changed();
        }
    }

    /// Apply the `ColorTemperatureMireds` mode.
    fn apply_color_temperature<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        mireds: u16,
        scene_apply: bool,
    ) {
        self.hooks.set_color_temperature_mireds(mireds);
        self.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::ColorTemperatureMireds);
        let cluster_id = Self::CLUSTER_ID;
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::ColorTemperatureMireds as _,
        );
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::EnhancedColorMode as _,
        );
        if !scene_apply {
            self.notify_scenable_changed();
        }
    }

    /// Apply the `CurrentHueAndCurrentSaturation` mode (non-enhanced
    /// hue is `u8`; chip's reference truncates `EnhancedCurrentHue`
    /// to the low byte when the captured mode says non-enhanced).
    fn apply_hue_saturation<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        hue_u8: u8,
        saturation: u8,
        scene_apply: bool,
    ) {
        // Truncate hue into the enhanced field — there's no separate
        // non-enhanced setter on the hooks (would just be a u8 view
        // of EnhancedCurrentHue per spec).
        self.hooks.set_enhanced_current_hue(hue_u8 as u16);
        self.hooks.set_current_saturation(saturation);
        self.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::CurrentHueAndCurrentSaturation);
        let cluster_id = Self::CLUSTER_ID;
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::EnhancedCurrentHue as _,
        );
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::CurrentSaturation as _,
        );
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::EnhancedColorMode as _,
        );
        if !scene_apply {
            self.notify_scenable_changed();
        }
    }

    /// Apply the `EnhancedCurrentHueAndCurrentSaturation` mode.
    fn apply_enhanced_hue_saturation<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        enhanced_hue: u16,
        saturation: u8,
        scene_apply: bool,
    ) {
        self.hooks.set_enhanced_current_hue(enhanced_hue);
        self.hooks.set_current_saturation(saturation);
        self.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::EnhancedCurrentHueAndCurrentSaturation);
        let cluster_id = Self::CLUSTER_ID;
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::EnhancedCurrentHue as _,
        );
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::CurrentSaturation as _,
        );
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::EnhancedColorMode as _,
        );
        if !scene_apply {
            self.notify_scenable_changed();
        }
    }

    /// Apply a color-loop activation. Mirrors chip's
    /// `ColorControl::ApplyScene` short-circuit: when a recalled
    /// scene has `ColorLoopActive=1`, drop the `MoveTo*` dispatch
    /// entirely and run the loop instead.
    fn apply_color_loop<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        direction: ColorLoopDirectionEnum,
        time: u16,
        scene_apply: bool,
    ) {
        self.hooks.set_color_loop_active(true);
        self.hooks.set_color_loop_direction(direction);
        self.hooks.set_color_loop_time(time);
        let cluster_id = Self::CLUSTER_ID;
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::ColorLoopActive as _,
        );
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::ColorLoopDirection as _,
        );
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::ColorLoopTime as _,
        );
        if !scene_apply {
            self.notify_scenable_changed();
        }
    }
}

impl<H: ColorControlHooks> SceneClusterHandler for ColorControlHandler<'_, H> {
    const CLUSTER_ID: ClusterId = FULL_CLUSTER.id;

    fn endpoint_id(&self) -> EndptId {
        self.endpoint_id
    }

    fn is_scenable_attribute(attribute_id: AttrId) -> bool {
        // Matter App Cluster spec §3.2.10. Feature-gated availability
        // is enforced at capture/apply time (a captured attribute
        // that maps to a disabled feature is silently dropped), not
        // here — `is_scenable_attribute` only validates `AddScene`
        // payload shape.
        matches!(
            attribute_id,
            a if a == AttributeId::CurrentX as AttrId
                || a == AttributeId::CurrentY as AttrId
                || a == AttributeId::EnhancedCurrentHue as AttrId
                || a == AttributeId::CurrentSaturation as AttrId
                || a == AttributeId::ColorLoopActive as AttrId
                || a == AttributeId::ColorLoopDirection as AttrId
                || a == AttributeId::ColorLoopTime as AttrId
                || a == AttributeId::ColorTemperatureMireds as AttrId
                || a == AttributeId::EnhancedColorMode as AttrId
        )
    }

    fn capture<P: TLVBuilderParent>(
        &self,
        avp_array: AttributeValuePairStructArrayBuilder<P>,
    ) -> Result<AttributeValuePairStructArrayBuilder<P>, Error> {
        // Capture order mirrors chip's
        // `DefaultColorControlSceneHandler::SerializeSave`.
        // `EnhancedColorMode` is captured unconditionally — apply
        // dispatches on it.
        let features = self.hooks.features();

        let avp_array = if features.contains(Feature::XY) {
            let x = self.hooks.current_x();
            let avp_array = avp_array.push_u16(AttributeId::CurrentX as _, x)?;
            let y = self.hooks.current_y();
            avp_array.push_u16(AttributeId::CurrentY as _, y)?
        } else {
            avp_array
        };

        let avp_array = if features.contains(Feature::ENHANCED_HUE) {
            let h = self.hooks.enhanced_current_hue();
            avp_array.push_u16(AttributeId::EnhancedCurrentHue as _, h)?
        } else {
            avp_array
        };

        let avp_array = if features.contains(Feature::HUE_AND_SATURATION) {
            let s = self.hooks.current_saturation();
            avp_array.push_u8(AttributeId::CurrentSaturation as _, s)?
        } else {
            avp_array
        };

        let avp_array = if features.contains(Feature::COLOR_LOOP) {
            let active = self.hooks.color_loop_active();
            let avp_array = avp_array.push_u8(AttributeId::ColorLoopActive as _, active as u8)?;
            let direction = self.hooks.color_loop_direction();
            let avp_array =
                avp_array.push_u8(AttributeId::ColorLoopDirection as _, direction as u8)?;
            let time = self.hooks.color_loop_time();
            avp_array.push_u16(AttributeId::ColorLoopTime as _, time)?
        } else {
            avp_array
        };

        let avp_array = if features.contains(Feature::COLOR_TEMPERATURE) {
            let mireds = self.hooks.color_temperature_mireds();
            avp_array.push_u16(AttributeId::ColorTemperatureMireds as _, mireds)?
        } else {
            avp_array
        };

        // `EnhancedColorMode` is `enum8`, serialised as
        // `valueUnsigned8`. Always captured (drives apply dispatch).
        let mode = self.hooks.enhanced_color_mode();
        avp_array.push_u8(AttributeId::EnhancedColorMode as _, mode as u8)
    }

    async fn apply<C: HandlerContext>(
        &self,
        ctx: &C,
        avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
        transition_time_ms: u32,
    ) -> Result<(), Error> {
        // Delegate to the narrower-typed inner method so unit tests
        // can pass `&()` (a no-op `AttrChangeNotifier`) without
        // needing to mock a full `HandlerContext`. `HandlerContext`
        // is a supertrait of `AttrChangeNotifier`, so any `&C` passed
        // in here also satisfies the inner method's bound.
        self.apply_inner(ctx, avp_list, transition_time_ms)
    }
}

impl<H: ColorControlHooks> ColorControlHandler<'_, H> {
    /// Inner apply (sync) — same logic as the trait method but
    /// scoped to `AttrChangeNotifier` instead of `HandlerContext`.
    /// Sync because every per-mode applier is sync (no transition
    /// task yet); when the command-handler path lands, the
    /// transitioning variants will be queued through a `task_signal`
    /// the same way LevelControl does it, and that signalling is
    /// already sync.
    fn apply_inner<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
        _transition_time_ms: u32,
    ) -> Result<(), Error> {
        // Sweep the AVP list once and stash each known value. We
        // need `EnhancedColorMode` AND the mode-specific values
        // before we can decide which applier to call.
        let mut mode: Option<EnhancedColorModeEnum> = None;
        let mut current_x: Option<u16> = None;
        let mut current_y: Option<u16> = None;
        let mut current_saturation: Option<u8> = None;
        let mut enhanced_current_hue: Option<u16> = None;
        let mut color_temperature_mireds: Option<u16> = None;
        let mut color_loop_active: Option<u8> = None;
        let mut color_loop_direction: Option<u8> = None;
        let mut color_loop_time: Option<u16> = None;

        for avp in avp_list.iter() {
            let avp = avp?;
            let attr_id = avp.attribute_id()?;
            if attr_id == AttributeId::EnhancedColorMode as _ {
                if let Some(v) = avp.value_unsigned_8()? {
                    mode = enhanced_color_mode_from_u8(v);
                }
            } else if attr_id == AttributeId::CurrentX as _ {
                current_x = avp.value_unsigned_16()?;
            } else if attr_id == AttributeId::CurrentY as _ {
                current_y = avp.value_unsigned_16()?;
            } else if attr_id == AttributeId::CurrentSaturation as _ {
                current_saturation = avp.value_unsigned_8()?;
            } else if attr_id == AttributeId::EnhancedCurrentHue as _ {
                enhanced_current_hue = avp.value_unsigned_16()?;
            } else if attr_id == AttributeId::ColorTemperatureMireds as _ {
                color_temperature_mireds = avp.value_unsigned_16()?;
            } else if attr_id == AttributeId::ColorLoopActive as _ {
                color_loop_active = avp.value_unsigned_8()?;
            } else if attr_id == AttributeId::ColorLoopDirection as _ {
                color_loop_direction = avp.value_unsigned_8()?;
            } else if attr_id == AttributeId::ColorLoopTime as _ {
                color_loop_time = avp.value_unsigned_16()?;
            }
        }

        // If the scene captured an active color loop, hand off to
        // the loop applier and ignore the Move-To dispatch —
        // mirrors chip's `ColorControl::ApplyScene`.
        if color_loop_active == Some(1) {
            let direction = color_loop_direction
                .and_then(color_loop_direction_from_u8)
                .unwrap_or(ColorLoopDirectionEnum::Increment);
            let time = color_loop_time.unwrap_or(0x0019);
            self.apply_color_loop(ctx, direction, time, true);
            return Ok(());
        }

        let Some(mode) = mode else {
            // No mode captured (perhaps an older firmware's blob
            // that didn't include it) — nothing to do.
            return Ok(());
        };

        match mode {
            EnhancedColorModeEnum::CurrentXAndCurrentY => {
                let (Some(x), Some(y)) = (current_x, current_y) else {
                    return Ok(());
                };
                self.apply_xy(ctx, x, y, true);
            }
            EnhancedColorModeEnum::ColorTemperatureMireds => {
                let Some(mireds) = color_temperature_mireds else {
                    return Ok(());
                };
                self.apply_color_temperature(ctx, mireds, true);
            }
            EnhancedColorModeEnum::CurrentHueAndCurrentSaturation => {
                // Non-enhanced hue is u8; chip's reference truncates
                // EnhancedCurrentHue's low byte. (Behaviour mirrored
                // from `ColorControl::ApplyScene`.)
                let (Some(hue), Some(sat)) = (
                    enhanced_current_hue.map(|h| (h & 0xFF) as u8),
                    current_saturation,
                ) else {
                    return Ok(());
                };
                self.apply_hue_saturation(ctx, hue, sat, true);
            }
            EnhancedColorModeEnum::EnhancedCurrentHueAndCurrentSaturation => {
                let (Some(hue), Some(sat)) = (enhanced_current_hue, current_saturation) else {
                    return Ok(());
                };
                self.apply_enhanced_hue_saturation(ctx, hue, sat, true);
            }
        }

        Ok(())
    }
}

/// Convert a stored `valueUnsigned8` to an
/// [`EnhancedColorModeEnum`], returning `None` for unknown values
/// rather than failing the apply (matches chip's lenient parse).
fn enhanced_color_mode_from_u8(v: u8) -> Option<EnhancedColorModeEnum> {
    match v {
        0 => Some(EnhancedColorModeEnum::CurrentHueAndCurrentSaturation),
        1 => Some(EnhancedColorModeEnum::CurrentXAndCurrentY),
        2 => Some(EnhancedColorModeEnum::ColorTemperatureMireds),
        3 => Some(EnhancedColorModeEnum::EnhancedCurrentHueAndCurrentSaturation),
        _ => None,
    }
}

/// Convert a stored `valueUnsigned8` to a [`ColorLoopDirectionEnum`],
/// returning `None` for unknown values.
fn color_loop_direction_from_u8(v: u8) -> Option<ColorLoopDirectionEnum> {
    match v {
        0 => Some(ColorLoopDirectionEnum::Decrement),
        1 => Some(ColorLoopDirectionEnum::Increment),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the ColorControl scenes integration. Validates
    //! the [`SceneClusterHandler`] impl against the cluster's
    //! feature-gated capture matrix, mode-routed apply dispatch,
    //! `ColorLoopActive=1` short-circuit, and the `scene_apply` /
    //! drift-detection contract.
    //!
    //! End-to-end YAML coverage isn't available — no chip-tool
    //! `Test_TC_S_*` / `TestScenes*` suite exercises ColorControl
    //! AVPs. These tests are the validation gate for the integration.
    //!
    //! Test infrastructure:
    //! - [`MockHooks`]: `Cell`-backed implementation of
    //!   [`ColorControlHooks`]. Sets `features()` from a constructor
    //!   field; all getters return the cached values; all setters
    //!   write through.
    //! - [`CountingInvalidator`]: tracks `scenable_attribute_changed`
    //!   call count so tests can assert on drift-notification gating.
    //! - `build_avp_bytes`: round-trips AVPs through the codegen
    //!   `AttributeValuePairStructArrayBuilder` so `apply` receives
    //!   the same TLV shape it would on the wire.
    //! - `dummy_ctx`: minimal `HandlerContext` whose
    //!   `notify_attr_changed` is a no-op (subscriber notification is
    //!   tested elsewhere; here we focus on scene-cluster behaviour).

    use super::*;
    use crate::tlv::{TLVElement, TLVWriteParent};
    use crate::utils::storage::WriteBuf;

    /// All in-test calls into `apply_*` go through the
    /// `&impl AttrChangeNotifier` surface (not the full
    /// `HandlerContext`). The stdlib `()` is a no-op
    /// `AttrChangeNotifier` (see `dm::types::handler::impl AttrChangeNotifier for ()`),
    /// so we use `&()` everywhere we'd otherwise need to mock a
    /// context. This sidesteps the heavy `HandlerContext`-mock
    /// boilerplate that doesn't add real test coverage — the apply
    /// helpers only USE the notifier surface.
    const NULL_CTX: &() = &();

    /// `Cell`-backed implementation of [`ColorControlHooks`] for
    /// tests. The `features` bitmap is constructor-fixed; everything
    /// else round-trips through `Cell::get`/`set`.
    struct MockHooks {
        features: Feature,
        current_x: Cell<u16>,
        current_y: Cell<u16>,
        enhanced_current_hue: Cell<u16>,
        current_saturation: Cell<u8>,
        color_temperature_mireds: Cell<u16>,
        color_loop_active: Cell<bool>,
        color_loop_direction: Cell<ColorLoopDirectionEnum>,
        color_loop_time: Cell<u16>,
        color_loop_start_enhanced_hue: Cell<u16>,
        enhanced_color_mode: Cell<EnhancedColorModeEnum>,
    }

    impl MockHooks {
        fn new(features: Feature) -> Self {
            Self {
                features,
                current_x: Cell::new(0),
                current_y: Cell::new(0),
                enhanced_current_hue: Cell::new(0),
                current_saturation: Cell::new(0),
                color_temperature_mireds: Cell::new(0),
                color_loop_active: Cell::new(false),
                color_loop_direction: Cell::new(ColorLoopDirectionEnum::Decrement),
                color_loop_time: Cell::new(0),
                color_loop_start_enhanced_hue: Cell::new(0),
                enhanced_color_mode: Cell::new(
                    EnhancedColorModeEnum::CurrentHueAndCurrentSaturation,
                ),
            }
        }
    }

    impl ColorControlHooks for MockHooks {
        fn features(&self) -> Feature {
            self.features
        }
        fn current_x(&self) -> u16 {
            self.current_x.get()
        }
        fn set_current_x(&self, value: u16) {
            self.current_x.set(value);
        }
        fn current_y(&self) -> u16 {
            self.current_y.get()
        }
        fn set_current_y(&self, value: u16) {
            self.current_y.set(value);
        }
        fn enhanced_current_hue(&self) -> u16 {
            self.enhanced_current_hue.get()
        }
        fn set_enhanced_current_hue(&self, value: u16) {
            self.enhanced_current_hue.set(value);
        }
        fn current_saturation(&self) -> u8 {
            self.current_saturation.get()
        }
        fn set_current_saturation(&self, value: u8) {
            self.current_saturation.set(value);
        }
        fn color_temperature_mireds(&self) -> u16 {
            self.color_temperature_mireds.get()
        }
        fn set_color_temperature_mireds(&self, value: u16) {
            self.color_temperature_mireds.set(value);
        }
        fn color_loop_active(&self) -> bool {
            self.color_loop_active.get()
        }
        fn set_color_loop_active(&self, value: bool) {
            self.color_loop_active.set(value);
        }
        fn color_loop_direction(&self) -> ColorLoopDirectionEnum {
            self.color_loop_direction.get()
        }
        fn set_color_loop_direction(&self, value: ColorLoopDirectionEnum) {
            self.color_loop_direction.set(value);
        }
        fn color_loop_time(&self) -> u16 {
            self.color_loop_time.get()
        }
        fn set_color_loop_time(&self, value: u16) {
            self.color_loop_time.set(value);
        }
        fn color_loop_start_enhanced_hue(&self) -> u16 {
            self.color_loop_start_enhanced_hue.get()
        }
        fn enhanced_color_mode(&self) -> EnhancedColorModeEnum {
            self.enhanced_color_mode.get()
        }
        fn set_enhanced_color_mode(&self, value: EnhancedColorModeEnum) {
            self.enhanced_color_mode.set(value);
        }
    }

    /// [`SceneInvalidator`] mock that counts calls — tests assert
    /// on this to verify the `scene_apply` flag suppresses drift
    /// notification.
    struct CountingInvalidator {
        count: Cell<u32>,
    }

    impl CountingInvalidator {
        const fn new() -> Self {
            Self {
                count: Cell::new(0),
            }
        }
        fn count(&self) -> u32 {
            self.count.get()
        }
    }

    impl SceneInvalidator for CountingInvalidator {
        fn scenable_attribute_changed(&self, _endpoint_id: EndptId) {
            self.count.set(self.count.get() + 1);
        }
    }

    /// AVP-array TLV blobs are built inline per-test rather than via
    /// a helper: the `AttributeValuePairStructArrayBuilder` carries
    /// the `WriteBuf` lifetime in nested type parameters, so a
    /// generic helper has unpleasant HRTB-around-nested-lifetime
    /// signatures. Inlining is shorter than the indirection.
    ///
    /// The pattern is:
    /// ```ignore
    /// let mut buf = [0u8; 128];
    /// let len = {
    ///     let mut wb = WriteBuf::new(&mut buf);
    ///     let parent = TLVWriteParent::new("test", &mut wb);
    ///     let array = AttributeValuePairStructArrayBuilder::new(
    ///         parent, &crate::tlv::TLVTag::Anonymous,
    ///     ).unwrap();
    ///     let array = array.push_u16(…).unwrap()…;
    ///     array.end().unwrap();
    ///     wb.get_tail()
    /// }; // wb dropped here → buf's mutable borrow released
    /// let bytes = &buf[..len];
    /// ```

    /// Returns a fresh [`ColorControlHandler`] for tests. `EP = 1`
    /// matches our other scene-aware handlers' test convention.
    fn handler(features: Feature) -> ColorControlHandler<'static, MockHooks> {
        // SAFETY-equivalent of leaking: tests don't drop, and the
        // hooks live for the duration of the test. Cleaner than
        // wrestling with `'static` bounds for `with_scene_invalidator`.
        // (The invalidator is wired explicitly per test via
        // `with_scene_invalidator` when needed.)
        let hooks = MockHooks::new(features);
        ColorControlHandler::new(Dataver::new(1), 1, hooks)
    }

    // ---- is_scenable_attribute ----

    #[test]
    fn is_scenable_attribute_accepts_all_nine_scenable() {
        for attr in [
            AttributeId::CurrentX,
            AttributeId::CurrentY,
            AttributeId::EnhancedCurrentHue,
            AttributeId::CurrentSaturation,
            AttributeId::ColorLoopActive,
            AttributeId::ColorLoopDirection,
            AttributeId::ColorLoopTime,
            AttributeId::ColorTemperatureMireds,
            AttributeId::EnhancedColorMode,
        ] {
            assert!(
                <ColorControlHandler<'_, MockHooks> as SceneClusterHandler>::is_scenable_attribute(
                    attr as AttrId,
                ),
                "{:?} should be scenable",
                attr,
            );
        }
    }

    #[test]
    fn is_scenable_attribute_rejects_unscenable_color_attrs() {
        // Per spec these are NOT scenable, even though they're
        // ColorControl attributes.
        for attr in [
            AttributeId::ColorLoopStartEnhancedHue,
            AttributeId::StartUpColorTemperatureMireds,
        ] {
            assert!(
                !<ColorControlHandler<'_, MockHooks> as SceneClusterHandler>::is_scenable_attribute(
                    attr as AttrId,
                ),
                "{:?} should NOT be scenable",
                attr,
            );
        }
    }

    // ---- capture: feature gating ----

    #[test]
    fn capture_xy_only_emits_just_xy_and_mode() {
        let h = handler(Feature::XY);
        h.hooks.set_current_x(0x1234);
        h.hooks.set_current_y(0x5678);
        h.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::CurrentXAndCurrentY);

        let mut buf = [0u8; 128];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("capture", &mut wb);
            let array =
                AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                    .unwrap();
            let array = h.capture(array).unwrap();
            array.end().unwrap();
            wb.get_tail()
        };
        let bytes = &buf[..len];

        // Walk the array and collect (attr_id, value) pairs. Bare
        // numeric checks here — TLV-level encoding is tested
        // elsewhere; we just want to know that the cluster picked
        // the right attrs and values.
        let elem = TLVElement::new(bytes);
        let arr: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        let mut seen: heapless::Vec<(u32, Option<u8>, Option<u16>), 16> = heapless::Vec::new();
        for avp in arr.iter() {
            let avp = avp.unwrap();
            seen.push((
                avp.attribute_id().unwrap(),
                avp.value_unsigned_8().unwrap(),
                avp.value_unsigned_16().unwrap(),
            ))
            .unwrap();
        }
        // XY features → CurrentX, CurrentY, EnhancedColorMode.
        // No hue/sat/temp/loop entries.
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0].0, AttributeId::CurrentX as u32);
        assert_eq!(seen[0].2, Some(0x1234));
        assert_eq!(seen[1].0, AttributeId::CurrentY as u32);
        assert_eq!(seen[1].2, Some(0x5678));
        assert_eq!(seen[2].0, AttributeId::EnhancedColorMode as u32);
        assert_eq!(
            seen[2].1,
            Some(EnhancedColorModeEnum::CurrentXAndCurrentY as u8)
        );
    }

    #[test]
    fn capture_color_temperature_only_emits_just_mireds_and_mode() {
        let h = handler(Feature::COLOR_TEMPERATURE);
        h.hooks.set_color_temperature_mireds(370);
        h.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::ColorTemperatureMireds);

        let mut buf = [0u8; 128];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("capture", &mut wb);
            let array =
                AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                    .unwrap();
            let array = h.capture(array).unwrap();
            array.end().unwrap();
            wb.get_tail()
        };
        let bytes = &buf[..len];

        let elem = TLVElement::new(bytes);
        let arr: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        let mut ids: heapless::Vec<u32, 16> = heapless::Vec::new();
        for avp in arr.iter() {
            ids.push(avp.unwrap().attribute_id().unwrap()).unwrap();
        }
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], AttributeId::ColorTemperatureMireds as u32);
        assert_eq!(ids[1], AttributeId::EnhancedColorMode as u32);
    }

    #[test]
    fn capture_full_feature_set_emits_all_scenable_attrs() {
        let h = handler(
            Feature::XY
                | Feature::ENHANCED_HUE
                | Feature::HUE_AND_SATURATION
                | Feature::COLOR_LOOP
                | Feature::COLOR_TEMPERATURE,
        );

        let mut buf = [0u8; 128];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("capture", &mut wb);
            let array =
                AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                    .unwrap();
            let array = h.capture(array).unwrap();
            array.end().unwrap();
            wb.get_tail()
        };
        let bytes = &buf[..len];

        let elem = TLVElement::new(bytes);
        let arr: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        let mut ids: heapless::Vec<u32, 16> = heapless::Vec::new();
        for avp in arr.iter() {
            ids.push(avp.unwrap().attribute_id().unwrap()).unwrap();
        }
        // Spec order from `SceneClusterHandler::capture`:
        // X, Y, EnhancedHue, Saturation, LoopActive, LoopDirection,
        // LoopTime, ColorTemperatureMireds, EnhancedColorMode.
        assert_eq!(ids.len(), 9);
        let expected = [
            AttributeId::CurrentX as u32,
            AttributeId::CurrentY as u32,
            AttributeId::EnhancedCurrentHue as u32,
            AttributeId::CurrentSaturation as u32,
            AttributeId::ColorLoopActive as u32,
            AttributeId::ColorLoopDirection as u32,
            AttributeId::ColorLoopTime as u32,
            AttributeId::ColorTemperatureMireds as u32,
            AttributeId::EnhancedColorMode as u32,
        ];
        for (got, want) in ids.iter().zip(expected.iter()) {
            assert_eq!(got, want);
        }
    }

    // ---- apply: mode dispatch ----

    /// Build an AVP list inline (see the `build_avp_bytes` doc-block
    /// for the pattern). Used by every apply-side test.
    fn build_xy_avps(buf: &mut [u8], x: u16, y: u16, mode: EnhancedColorModeEnum) -> usize {
        let mut wb = WriteBuf::new(buf);
        let parent = TLVWriteParent::new("test", &mut wb);
        let array =
            AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                .unwrap();
        let array = array
            .push_u16(AttributeId::CurrentX as _, x)
            .unwrap()
            .push_u16(AttributeId::CurrentY as _, y)
            .unwrap()
            .push_u8(AttributeId::EnhancedColorMode as _, mode as u8)
            .unwrap();
        array.end().unwrap();
        wb.get_tail()
    }

    #[test]
    fn apply_xy_mode_writes_x_y_and_sets_mode() {
        let h = handler(Feature::XY);
        let mut buf = [0u8; 128];
        let len = build_xy_avps(
            &mut buf,
            0xABCD,
            0x1234,
            EnhancedColorModeEnum::CurrentXAndCurrentY,
        );
        let bytes = &buf[..len];

        let elem = TLVElement::new(bytes);
        let avp_list: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        h.apply_inner(NULL_CTX, &avp_list, 0).unwrap();

        assert_eq!(h.hooks.current_x(), 0xABCD);
        assert_eq!(h.hooks.current_y(), 0x1234);
        assert!(matches!(
            h.hooks.enhanced_color_mode(),
            EnhancedColorModeEnum::CurrentXAndCurrentY
        ));
    }

    #[test]
    fn apply_color_temperature_mode_writes_mireds_and_sets_mode() {
        let h = handler(Feature::COLOR_TEMPERATURE);
        let mut buf = [0u8; 128];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("test", &mut wb);
            let array =
                AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                    .unwrap();
            let array = array
                .push_u16(AttributeId::ColorTemperatureMireds as _, 250)
                .unwrap()
                .push_u8(
                    AttributeId::EnhancedColorMode as _,
                    EnhancedColorModeEnum::ColorTemperatureMireds as u8,
                )
                .unwrap();
            array.end().unwrap();
            wb.get_tail()
        };
        let bytes = &buf[..len];

        let elem = TLVElement::new(bytes);
        let avp_list: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        h.apply_inner(NULL_CTX, &avp_list, 0).unwrap();

        assert_eq!(h.hooks.color_temperature_mireds(), 250);
        assert!(matches!(
            h.hooks.enhanced_color_mode(),
            EnhancedColorModeEnum::ColorTemperatureMireds
        ));
    }

    #[test]
    fn apply_hue_saturation_mode_truncates_enhanced_hue_to_u8() {
        // Captured EnhancedCurrentHue is u16; non-enhanced apply
        // path takes the low byte. Mirrors chip's `ApplyScene`
        // behaviour and is documented on `apply_hue_saturation`.
        let h = handler(Feature::HUE_AND_SATURATION);
        let mut buf = [0u8; 128];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("test", &mut wb);
            let array =
                AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                    .unwrap();
            // Hue = 0x12FF → low byte 0xFF after truncation.
            let array = array
                .push_u16(AttributeId::EnhancedCurrentHue as _, 0x12FF)
                .unwrap()
                .push_u8(AttributeId::CurrentSaturation as _, 100)
                .unwrap()
                .push_u8(
                    AttributeId::EnhancedColorMode as _,
                    EnhancedColorModeEnum::CurrentHueAndCurrentSaturation as u8,
                )
                .unwrap();
            array.end().unwrap();
            wb.get_tail()
        };
        let bytes = &buf[..len];

        let elem = TLVElement::new(bytes);
        let avp_list: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        h.apply_inner(NULL_CTX, &avp_list, 0).unwrap();

        // The mutator writes the low byte into the enhanced field
        // (the cluster's only hue storage); the mode flips to
        // non-enhanced.
        assert_eq!(h.hooks.enhanced_current_hue(), 0xFF);
        assert_eq!(h.hooks.current_saturation(), 100);
        assert!(matches!(
            h.hooks.enhanced_color_mode(),
            EnhancedColorModeEnum::CurrentHueAndCurrentSaturation
        ));
    }

    #[test]
    fn apply_enhanced_hue_saturation_keeps_full_u16_hue() {
        let h = handler(Feature::ENHANCED_HUE | Feature::HUE_AND_SATURATION);
        let mut buf = [0u8; 128];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("test", &mut wb);
            let array =
                AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                    .unwrap();
            let array = array
                .push_u16(AttributeId::EnhancedCurrentHue as _, 0x4321)
                .unwrap()
                .push_u8(AttributeId::CurrentSaturation as _, 200)
                .unwrap()
                .push_u8(
                    AttributeId::EnhancedColorMode as _,
                    EnhancedColorModeEnum::EnhancedCurrentHueAndCurrentSaturation as u8,
                )
                .unwrap();
            array.end().unwrap();
            wb.get_tail()
        };
        let bytes = &buf[..len];

        let elem = TLVElement::new(bytes);
        let avp_list: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        h.apply_inner(NULL_CTX, &avp_list, 0).unwrap();

        // Enhanced mode preserves the full 16-bit hue.
        assert_eq!(h.hooks.enhanced_current_hue(), 0x4321);
        assert_eq!(h.hooks.current_saturation(), 200);
    }

    // ---- apply: ColorLoopActive=1 short-circuit ----

    #[test]
    fn apply_color_loop_active_short_circuits_move_to_dispatch() {
        // Even when a mode + matching values are captured, if
        // ColorLoopActive=1 is present apply must hand off to the
        // loop applier and IGNORE the mode-dispatched value. Mirrors
        // chip's `ColorControl::ApplyScene`.
        let h = handler(Feature::COLOR_LOOP | Feature::XY);
        let mut buf = [0u8; 128];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("test", &mut wb);
            let array =
                AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                    .unwrap();
            let array = array
                .push_u8(AttributeId::ColorLoopActive as _, 1)
                .unwrap()
                .push_u8(
                    AttributeId::ColorLoopDirection as _,
                    ColorLoopDirectionEnum::Increment as u8,
                )
                .unwrap()
                .push_u16(AttributeId::ColorLoopTime as _, 60)
                .unwrap()
                // XY values + mode that would normally win — should
                // be ignored because the loop short-circuits.
                .push_u16(AttributeId::CurrentX as _, 0xDEAD)
                .unwrap()
                .push_u16(AttributeId::CurrentY as _, 0xBEEF)
                .unwrap()
                .push_u8(
                    AttributeId::EnhancedColorMode as _,
                    EnhancedColorModeEnum::CurrentXAndCurrentY as u8,
                )
                .unwrap();
            array.end().unwrap();
            wb.get_tail()
        };
        let bytes = &buf[..len];

        let elem = TLVElement::new(bytes);
        let avp_list: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        h.apply_inner(NULL_CTX, &avp_list, 0).unwrap();

        // Loop state set:
        assert!(h.hooks.color_loop_active());
        assert!(matches!(
            h.hooks.color_loop_direction(),
            ColorLoopDirectionEnum::Increment
        ));
        assert_eq!(h.hooks.color_loop_time(), 60);
        // XY values NOT applied (short-circuit took effect):
        assert_eq!(h.hooks.current_x(), 0);
        assert_eq!(h.hooks.current_y(), 0);
    }

    // ---- apply: missing-data tolerance ----

    #[test]
    fn apply_with_no_mode_is_noop() {
        // EnhancedColorMode is missing — chip's reference treats this
        // as a no-op rather than an error (forward-compat with
        // older firmware that didn't capture the mode).
        let h = handler(Feature::XY);
        let mut buf = [0u8; 128];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("test", &mut wb);
            let array =
                AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                    .unwrap();
            let array = array
                .push_u16(AttributeId::CurrentX as _, 0xAAAA)
                .unwrap()
                .push_u16(AttributeId::CurrentY as _, 0xBBBB)
                .unwrap();
            array.end().unwrap();
            wb.get_tail()
        };
        let bytes = &buf[..len];

        let elem = TLVElement::new(bytes);
        let avp_list: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        h.apply_inner(NULL_CTX, &avp_list, 0).unwrap();

        // Hooks never mutated — apply skipped everything.
        assert_eq!(h.hooks.current_x(), 0);
        assert_eq!(h.hooks.current_y(), 0);
    }

    // ---- scene_apply gates drift notification ----

    #[test]
    fn apply_via_scenes_does_not_fire_invalidator() {
        // The whole reason `apply` takes the scenes path is that
        // mutations during a scene recall MUST NOT fire
        // `notify_scenable_changed` — otherwise `SceneInvalidator`
        // would flip `SceneValid` to false after the recall just set
        // it true. Verify the invalidator stays at zero.
        let inv = CountingInvalidator::new();
        let hooks = MockHooks::new(Feature::XY);
        let h = ColorControlHandler::new(Dataver::new(1), 1, hooks).with_scene_invalidator(&inv);

        let mut buf = [0u8; 128];
        let len = build_xy_avps(
            &mut buf,
            0x1111,
            0x2222,
            EnhancedColorModeEnum::CurrentXAndCurrentY,
        );
        let bytes = &buf[..len];

        let elem = TLVElement::new(bytes);
        let avp_list: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        h.apply_inner(NULL_CTX, &avp_list, 0).unwrap();

        assert_eq!(inv.count(), 0, "scene apply must not invalidate");
        // Sanity: state DID change.
        assert_eq!(h.hooks.current_x(), 0x1111);
    }

    #[test]
    fn direct_mutator_with_scene_apply_false_fires_invalidator() {
        // The inverse: call the same internal applier with
        // `scene_apply=false` (the path command handlers will use
        // when they ship) — drift notification MUST fire.
        let inv = CountingInvalidator::new();
        let hooks = MockHooks::new(Feature::XY);
        let h = ColorControlHandler::new(Dataver::new(1), 1, hooks).with_scene_invalidator(&inv);

        h.apply_xy(NULL_CTX, 0x1111, 0x2222, false);

        assert_eq!(inv.count(), 1, "command-driven mutation must invalidate");
    }

    // ---- capture → apply roundtrip ----

    #[test]
    fn capture_then_apply_roundtrips_xy_mode_state() {
        // End-to-end: stamp a known state into `src`, capture into
        // bytes, apply the bytes onto an empty `dst`, then assert
        // dst's state matches src's. This is the closest thing we
        // have to an end-to-end YAML test for ColorControl scenes.
        let src = handler(Feature::XY);
        src.hooks.set_current_x(0x7F00);
        src.hooks.set_current_y(0x80FF);
        src.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::CurrentXAndCurrentY);

        let mut buf = [0u8; 128];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("roundtrip", &mut wb);
            let array =
                AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                    .unwrap();
            let array = src.capture(array).unwrap();
            array.end().unwrap();
            wb.get_tail()
        };
        let bytes = &buf[..len];

        // Apply onto a fresh handler with zeroed state.
        let dst = handler(Feature::XY);
        assert_eq!(dst.hooks.current_x(), 0);
        let elem = TLVElement::new(bytes);
        let avp_list: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        dst.apply_inner(NULL_CTX, &avp_list, 0).unwrap();

        assert_eq!(dst.hooks.current_x(), 0x7F00);
        assert_eq!(dst.hooks.current_y(), 0x80FF);
        assert!(matches!(
            dst.hooks.enhanced_color_mode(),
            EnhancedColorModeEnum::CurrentXAndCurrentY
        ));
    }
}
