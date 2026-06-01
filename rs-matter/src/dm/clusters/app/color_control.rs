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

//! Implementation of the Matter Color Control cluster.

use core::cell::Cell;
use core::future::{pending, ready, Future};
use core::pin::pin;

use embassy_futures::select::{select, Either};

use crate::dm::clusters::app::level_control::{LevelControlHooks, NoOnOff};
use crate::dm::clusters::app::on_off::{NoLevelControl, OnOffHandler, OnOffHooks};
use crate::dm::clusters::decl::scenes_management::{
    AttributeValuePairStruct, AttributeValuePairStructArrayBuilder,
};
use crate::dm::clusters::scenes::{SceneClusterHandler, SceneInvalidator};
use crate::dm::{
    AttrChangeNotifier, AttrId, Cluster, ClusterId, Dataver, EndptId, HandlerContext,
    InvokeContext, ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{Nullable, TLVArray, TLVBuilderParent};
use crate::utils::cell::RefCell;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Signal;

pub use crate::dm::clusters::decl::color_control::*;

/// Messages passed to the `notify` closure in `ColorControlHooks::run()`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OutOfBandMessage {
    /// Out-of-band physical-state update — Matter attributes should
    /// be re-read from the hooks.
    Update,
}

/// Default values for the handler-internal attribute state seeded at
/// `init` time. Currently only `options` and `start_up_color_temperature_mireds`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct AttributeDefaults {
    pub options: OptionsBitmap,
}

impl AttributeDefaults {
    pub const fn new() -> Self {
        Self {
            options: OptionsBitmap::from_bits_retain(0),
        }
    }
}

/// Device-supplied state + I/O for the Color Control cluster.
///
/// Implementers expose the device's persisted color attributes,
/// physical color-temperature limits, and three actuator hooks (XY,
/// hue+saturation, color-temperature). Getters return cached state;
/// setters are synchronous and cheap.
pub trait ColorControlHooks {
    /// Cluster metadata for this device — typically `FULL_CLUSTER`
    /// passed through `.with_features(...).with_attrs(...).with_cmds(...)`.
    const CLUSTER: Cluster<'static>;

    /// `ColorCapabilities` bitmap as reported via the attribute of
    /// the same name. Should mirror the `Feature` bits enabled in
    /// `Self::CLUSTER.feature_map`.
    const COLOR_CAPABILITIES: ColorCapabilitiesBitmap;

    /// Physical color-temperature lower bound, in mireds.
    const COLOR_TEMP_PHYSICAL_MIN_MIREDS: u16;

    /// Physical color-temperature upper bound, in mireds.
    const COLOR_TEMP_PHYSICAL_MAX_MIREDS: u16;

    /// Mireds threshold above which `CoupleColorTempToLevel` keeps
    /// the colour temperature synchronised with the current level.
    /// Unused unless the device opts into that coupling.
    const COUPLE_COLOR_TEMP_TO_LEVEL_MIN_MIREDS: u16 = 0;

    // ---- Persisted device state (getters + setters) ----

    /// `EnhancedCurrentHue` (uint16). The non-enhanced `CurrentHue`
    /// is the high byte.
    fn enhanced_current_hue(&self) -> u16;
    fn set_enhanced_current_hue(&self, value: u16);

    fn current_saturation(&self) -> u8;
    fn set_current_saturation(&self, value: u8);

    fn current_x(&self) -> u16;
    fn set_current_x(&self, value: u16);

    fn current_y(&self) -> u16;
    fn set_current_y(&self, value: u16);

    fn color_temperature_mireds(&self) -> u16;
    fn set_color_temperature_mireds(&self, value: u16);

    fn color_mode(&self) -> ColorModeEnum;
    fn set_color_mode(&self, value: ColorModeEnum);

    fn enhanced_color_mode(&self) -> EnhancedColorModeEnum;
    fn set_enhanced_color_mode(&self, value: EnhancedColorModeEnum);

    fn color_loop_active(&self) -> bool;
    fn set_color_loop_active(&self, value: bool);

    fn color_loop_direction(&self) -> ColorLoopDirectionEnum;
    fn set_color_loop_direction(&self, value: ColorLoopDirectionEnum);

    /// Duration of one full colour-loop cycle, in seconds.
    fn color_loop_time(&self) -> u16;
    fn set_color_loop_time(&self, value: u16);

    fn color_loop_start_enhanced_hue(&self) -> u16;
    fn set_color_loop_start_enhanced_hue(&self, value: u16);

    fn color_loop_stored_enhanced_hue(&self) -> u16;
    fn set_color_loop_stored_enhanced_hue(&self, value: u16);

    fn start_up_color_temperature_mireds(&self) -> Result<Nullable<u16>, Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    fn set_start_up_color_temperature_mireds(&self, _value: Nullable<u16>) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    // ---- Device actuators ----

    /// Drive the device to the given xy chromaticity.
    /// Returns the values the device was actually set to (clamped if
    /// needed), or `Err(())` on failure (surfaced as `Failure`).
    #[allow(clippy::result_unit_err)]
    fn set_device_xy(&self, x: u16, y: u16) -> Result<(u16, u16), ()>;

    /// Drive the device to the given hue (full 16-bit enhanced
    /// resolution) and saturation. Returns the actual values.
    #[allow(clippy::result_unit_err)]
    fn set_device_hue_saturation(&self, enhanced_hue: u16, saturation: u8)
        -> Result<(u16, u8), ()>;

    /// Drive the device to the given color temperature, in mireds.
    /// Returns the actual value (clamped to physical bounds if needed).
    #[allow(clippy::result_unit_err)]
    fn set_device_color_temperature_mireds(&self, mireds: u16) -> Result<u16, ()>;

    /// Background task for out-of-band notifications. The future MUST
    /// NOT return — implementers should loop or `pending::<()>().await`.
    fn run<F: Fn(OutOfBandMessage)>(&self, _notify: F) -> impl Future<Output = ()> {
        pending::<()>()
    }
}

impl<T> ColorControlHooks for &T
where
    T: ColorControlHooks,
{
    const CLUSTER: Cluster<'static> = T::CLUSTER;
    const COLOR_CAPABILITIES: ColorCapabilitiesBitmap = T::COLOR_CAPABILITIES;
    const COLOR_TEMP_PHYSICAL_MIN_MIREDS: u16 = T::COLOR_TEMP_PHYSICAL_MIN_MIREDS;
    const COLOR_TEMP_PHYSICAL_MAX_MIREDS: u16 = T::COLOR_TEMP_PHYSICAL_MAX_MIREDS;
    const COUPLE_COLOR_TEMP_TO_LEVEL_MIN_MIREDS: u16 = T::COUPLE_COLOR_TEMP_TO_LEVEL_MIN_MIREDS;

    fn enhanced_current_hue(&self) -> u16 {
        (*self).enhanced_current_hue()
    }
    fn set_enhanced_current_hue(&self, value: u16) {
        (*self).set_enhanced_current_hue(value)
    }
    fn current_saturation(&self) -> u8 {
        (*self).current_saturation()
    }
    fn set_current_saturation(&self, value: u8) {
        (*self).set_current_saturation(value)
    }
    fn current_x(&self) -> u16 {
        (*self).current_x()
    }
    fn set_current_x(&self, value: u16) {
        (*self).set_current_x(value)
    }
    fn current_y(&self) -> u16 {
        (*self).current_y()
    }
    fn set_current_y(&self, value: u16) {
        (*self).set_current_y(value)
    }
    fn color_temperature_mireds(&self) -> u16 {
        (*self).color_temperature_mireds()
    }
    fn set_color_temperature_mireds(&self, value: u16) {
        (*self).set_color_temperature_mireds(value)
    }
    fn color_mode(&self) -> ColorModeEnum {
        (*self).color_mode()
    }
    fn set_color_mode(&self, value: ColorModeEnum) {
        (*self).set_color_mode(value)
    }
    fn enhanced_color_mode(&self) -> EnhancedColorModeEnum {
        (*self).enhanced_color_mode()
    }
    fn set_enhanced_color_mode(&self, value: EnhancedColorModeEnum) {
        (*self).set_enhanced_color_mode(value)
    }
    fn color_loop_active(&self) -> bool {
        (*self).color_loop_active()
    }
    fn set_color_loop_active(&self, value: bool) {
        (*self).set_color_loop_active(value)
    }
    fn color_loop_direction(&self) -> ColorLoopDirectionEnum {
        (*self).color_loop_direction()
    }
    fn set_color_loop_direction(&self, value: ColorLoopDirectionEnum) {
        (*self).set_color_loop_direction(value)
    }
    fn color_loop_time(&self) -> u16 {
        (*self).color_loop_time()
    }
    fn set_color_loop_time(&self, value: u16) {
        (*self).set_color_loop_time(value)
    }
    fn color_loop_start_enhanced_hue(&self) -> u16 {
        (*self).color_loop_start_enhanced_hue()
    }
    fn set_color_loop_start_enhanced_hue(&self, value: u16) {
        (*self).set_color_loop_start_enhanced_hue(value)
    }
    fn color_loop_stored_enhanced_hue(&self) -> u16 {
        (*self).color_loop_stored_enhanced_hue()
    }
    fn set_color_loop_stored_enhanced_hue(&self, value: u16) {
        (*self).set_color_loop_stored_enhanced_hue(value)
    }
    fn start_up_color_temperature_mireds(&self) -> Result<Nullable<u16>, Error> {
        (*self).start_up_color_temperature_mireds()
    }
    fn set_start_up_color_temperature_mireds(&self, value: Nullable<u16>) -> Result<(), Error> {
        (*self).set_start_up_color_temperature_mireds(value)
    }
    fn set_device_xy(&self, x: u16, y: u16) -> Result<(u16, u16), ()> {
        (*self).set_device_xy(x, y)
    }
    fn set_device_hue_saturation(
        &self,
        enhanced_hue: u16,
        saturation: u8,
    ) -> Result<(u16, u8), ()> {
        (*self).set_device_hue_saturation(enhanced_hue, saturation)
    }
    fn set_device_color_temperature_mireds(&self, mireds: u16) -> Result<u16, ()> {
        (*self).set_device_color_temperature_mireds(mireds)
    }
    fn run<F: Fn(OutOfBandMessage)>(&self, notify: F) -> impl Future<Output = ()> {
        (*self).run(notify)
    }
}

/// Internal task placeholder. Populated in subsequent steps when the
/// transition pipeline is implemented.
enum Task {
    // No transition tasks yet — Step 3 introduces hue/saturation moves,
    // Step 4 adds XY and colour-temperature moves, Step 5 adds the
    // colour-loop tick. For now this enum is uninhabited.
}

/// Handler-internal cluster state. Device-persisted attributes live
/// in the hooks.
struct ColorControlState {
    options: OptionsBitmap,
    remaining_time: u16,
}

impl ColorControlState {
    fn new(defaults: AttributeDefaults) -> Self {
        Self {
            options: defaults.options,
            remaining_time: 0,
        }
    }
}

/// Implementation of the Matter Color Control cluster handler.
///
/// Step 1 surface: full hooks, attribute-read routing, and stubbed
/// command handlers. Transitions, command-driven mutations and the
/// `run()` task pipeline are wired in subsequent steps.
///
/// # Type Parameters
/// - `'a`: lifetime of borrowed coupled-handler references.
/// - `H`: device-specific [`ColorControlHooks`] implementation.
/// - `OH`: [`OnOffHooks`] of the coupled OnOff cluster (used for the
///   `Options.EXECUTE_IF_OFF` check). Use [`NoOnOff`] when standalone.
/// - `LH`: [`LevelControlHooks`] of the LevelControl cluster the
///   coupled OnOff handler is parameterised over.
pub struct ColorControlHandler<'a, H: ColorControlHooks, OH: OnOffHooks, LH: LevelControlHooks> {
    dataver: Dataver,
    endpoint_id: EndptId,
    hooks: H,
    on_off_handler: Mutex<Cell<Option<&'a OnOffHandler<'a, OH, LH>>>>,
    scene_invalidator: Mutex<Cell<Option<&'a dyn SceneInvalidator>>>,
    state: Mutex<RefCell<ColorControlState>>,
    #[allow(dead_code)]
    task_signal: Signal<Option<Task>>,
}

impl<H: ColorControlHooks> ColorControlHandler<'_, H, NoOnOff, NoLevelControl> {
    /// Standalone ColorControl handler — not coupled to OnOff. Calls
    /// `init(None)` automatically.
    pub fn new_standalone(
        dataver: Dataver,
        endpoint_id: EndptId,
        hooks: H,
        attribute_defaults: AttributeDefaults,
    ) -> Self {
        let this = Self::new_internal(dataver, endpoint_id, hooks, attribute_defaults);
        this.init(None);
        this
    }
}

impl<'a, H: ColorControlHooks, OH: OnOffHooks, LH: LevelControlHooks>
    ColorControlHandler<'a, H, OH, LH>
{
    fn new_internal(
        dataver: Dataver,
        endpoint_id: EndptId,
        hooks: H,
        attribute_defaults: AttributeDefaults,
    ) -> Self {
        Self {
            dataver,
            endpoint_id,
            hooks,
            on_off_handler: Mutex::new(Cell::new(None)),
            scene_invalidator: Mutex::new(Cell::new(None)),
            state: Mutex::new(RefCell::new(ColorControlState::new(attribute_defaults))),
            task_signal: Signal::new(None),
        }
    }

    /// Construct a handler without driving `init` (no validation, no
    /// startup behaviour). Useful for unit tests and for the
    /// scenes-integration-only skeleton path.
    pub fn new(
        dataver: Dataver,
        endpoint_id: EndptId,
        hooks: H,
        attribute_defaults: AttributeDefaults,
    ) -> Self {
        Self::new_internal(dataver, endpoint_id, hooks, attribute_defaults)
    }

    /// Wire the optional coupled OnOff handler, validate the cluster
    /// configuration, and apply `StartUpColorTemperatureMireds` if set.
    pub fn init(&self, on_off_handler: Option<&'a OnOffHandler<'a, OH, LH>>) {
        self.on_off_handler.lock(|h| h.set(on_off_handler));
        self.validate();

        // StartUpColorTemperatureMireds: if non-null, force the
        // cluster's ColorTemperatureMireds to the supplied value on
        // power-up — but only when the feature is enabled and the
        // attribute is reachable from the hooks.
        if H::CLUSTER.feature_map & Feature::COLOR_TEMPERATURE.bits() != 0 {
            if let Ok(value) = self.hooks.start_up_color_temperature_mireds() {
                if let Some(mireds) = value.into_option() {
                    let clamped = mireds.clamp(
                        H::COLOR_TEMP_PHYSICAL_MIN_MIREDS,
                        H::COLOR_TEMP_PHYSICAL_MAX_MIREDS,
                    );
                    if let Ok(actual) = self.hooks.set_device_color_temperature_mireds(clamped) {
                        self.hooks.set_color_temperature_mireds(actual);
                        self.hooks
                            .set_color_mode(ColorModeEnum::ColorTemperatureMireds);
                        self.hooks
                            .set_enhanced_color_mode(EnhancedColorModeEnum::ColorTemperatureMireds);
                    }
                }
            }
        }
    }

    fn validate(&self) {
        if H::CLUSTER.revision != 7 {
            panic!(
                "ColorControl validation: incorrect version number: expected 7 got {}",
                H::CLUSTER.revision
            );
        }

        // Mandatory attributes (always required regardless of features).
        if H::CLUSTER.attribute(AttributeId::ColorMode as _).is_none()
            || H::CLUSTER.attribute(AttributeId::Options as _).is_none()
            || H::CLUSTER
                .attribute(AttributeId::NumberOfPrimaries as _)
                .is_none()
            || H::CLUSTER
                .attribute(AttributeId::EnhancedColorMode as _)
                .is_none()
            || H::CLUSTER
                .attribute(AttributeId::ColorCapabilities as _)
                .is_none()
        {
            panic!("ColorControl validation: missing required attributes: ColorMode, Options, NumberOfPrimaries, EnhancedColorMode, or ColorCapabilities");
        }

        // StopMoveStep is required whenever any of the move/step
        // feature families is enabled.
        let features = H::CLUSTER.feature_map;
        let any_move_feature = features
            & (Feature::HUE_AND_SATURATION.bits()
                | Feature::XY.bits()
                | Feature::COLOR_TEMPERATURE.bits())
            != 0;
        if any_move_feature && H::CLUSTER.command(CommandId::StopMoveStep as _).is_none() {
            panic!(
                "ColorControl validation: missing required command StopMoveStep (mandatory when any of HUE_AND_SATURATION/XY/COLOR_TEMPERATURE is enabled)"
            );
        }

        // HUE_AND_SATURATION feature: attribute + command requirements.
        if features & Feature::HUE_AND_SATURATION.bits() != 0 {
            if H::CLUSTER.attribute(AttributeId::CurrentHue as _).is_none()
                || H::CLUSTER
                    .attribute(AttributeId::CurrentSaturation as _)
                    .is_none()
            {
                panic!("ColorControl validation: HUE_AND_SATURATION requires CurrentHue and CurrentSaturation attributes");
            }
            if H::CLUSTER.command(CommandId::MoveToHue as _).is_none()
                || H::CLUSTER.command(CommandId::MoveHue as _).is_none()
                || H::CLUSTER.command(CommandId::StepHue as _).is_none()
                || H::CLUSTER
                    .command(CommandId::MoveToSaturation as _)
                    .is_none()
                || H::CLUSTER.command(CommandId::MoveSaturation as _).is_none()
                || H::CLUSTER.command(CommandId::StepSaturation as _).is_none()
                || H::CLUSTER
                    .command(CommandId::MoveToHueAndSaturation as _)
                    .is_none()
            {
                panic!("ColorControl validation: HUE_AND_SATURATION requires MoveToHue, MoveHue, StepHue, MoveToSaturation, MoveSaturation, StepSaturation and MoveToHueAndSaturation commands");
            }
        }

        // ENHANCED_HUE feature requires HUE_AND_SATURATION.
        if features & Feature::ENHANCED_HUE.bits() != 0 {
            if features & Feature::HUE_AND_SATURATION.bits() == 0 {
                panic!("ColorControl validation: ENHANCED_HUE requires HUE_AND_SATURATION to also be enabled");
            }
            if H::CLUSTER
                .attribute(AttributeId::EnhancedCurrentHue as _)
                .is_none()
            {
                panic!(
                    "ColorControl validation: ENHANCED_HUE requires EnhancedCurrentHue attribute"
                );
            }
            if H::CLUSTER
                .command(CommandId::EnhancedMoveToHue as _)
                .is_none()
                || H::CLUSTER
                    .command(CommandId::EnhancedMoveHue as _)
                    .is_none()
                || H::CLUSTER
                    .command(CommandId::EnhancedStepHue as _)
                    .is_none()
                || H::CLUSTER
                    .command(CommandId::EnhancedMoveToHueAndSaturation as _)
                    .is_none()
            {
                panic!("ColorControl validation: ENHANCED_HUE requires EnhancedMoveToHue, EnhancedMoveHue, EnhancedStepHue and EnhancedMoveToHueAndSaturation commands");
            }
        }

        // XY feature.
        if features & Feature::XY.bits() != 0 {
            if H::CLUSTER.attribute(AttributeId::CurrentX as _).is_none()
                || H::CLUSTER.attribute(AttributeId::CurrentY as _).is_none()
            {
                panic!("ColorControl validation: XY requires CurrentX and CurrentY attributes");
            }
            if H::CLUSTER.command(CommandId::MoveToColor as _).is_none()
                || H::CLUSTER.command(CommandId::MoveColor as _).is_none()
                || H::CLUSTER.command(CommandId::StepColor as _).is_none()
            {
                panic!("ColorControl validation: XY requires MoveToColor, MoveColor and StepColor commands");
            }
        }

        // COLOR_TEMPERATURE feature.
        if features & Feature::COLOR_TEMPERATURE.bits() != 0 {
            if H::CLUSTER
                .attribute(AttributeId::ColorTemperatureMireds as _)
                .is_none()
                || H::CLUSTER
                    .attribute(AttributeId::ColorTempPhysicalMinMireds as _)
                    .is_none()
                || H::CLUSTER
                    .attribute(AttributeId::ColorTempPhysicalMaxMireds as _)
                    .is_none()
            {
                panic!("ColorControl validation: COLOR_TEMPERATURE requires ColorTemperatureMireds, ColorTempPhysicalMinMireds and ColorTempPhysicalMaxMireds attributes");
            }
            if H::CLUSTER
                .command(CommandId::MoveToColorTemperature as _)
                .is_none()
                || H::CLUSTER
                    .command(CommandId::MoveColorTemperature as _)
                    .is_none()
                || H::CLUSTER
                    .command(CommandId::StepColorTemperature as _)
                    .is_none()
            {
                panic!("ColorControl validation: COLOR_TEMPERATURE requires MoveToColorTemperature, MoveColorTemperature and StepColorTemperature commands");
            }
            if H::COLOR_TEMP_PHYSICAL_MIN_MIREDS >= H::COLOR_TEMP_PHYSICAL_MAX_MIREDS {
                panic!(
                    "ColorControl validation: COLOR_TEMP_PHYSICAL_MIN_MIREDS must be < COLOR_TEMP_PHYSICAL_MAX_MIREDS"
                );
            }
        }

        // COLOR_LOOP feature requires ENHANCED_HUE.
        if features & Feature::COLOR_LOOP.bits() != 0 {
            if features & Feature::ENHANCED_HUE.bits() == 0 {
                panic!(
                    "ColorControl validation: COLOR_LOOP requires ENHANCED_HUE to also be enabled"
                );
            }
            if H::CLUSTER
                .attribute(AttributeId::ColorLoopActive as _)
                .is_none()
                || H::CLUSTER
                    .attribute(AttributeId::ColorLoopDirection as _)
                    .is_none()
                || H::CLUSTER
                    .attribute(AttributeId::ColorLoopTime as _)
                    .is_none()
                || H::CLUSTER
                    .attribute(AttributeId::ColorLoopStartEnhancedHue as _)
                    .is_none()
                || H::CLUSTER
                    .attribute(AttributeId::ColorLoopStoredEnhancedHue as _)
                    .is_none()
            {
                panic!("ColorControl validation: COLOR_LOOP requires ColorLoopActive, ColorLoopDirection, ColorLoopTime, ColorLoopStartEnhancedHue and ColorLoopStoredEnhancedHue attributes");
            }
            if H::CLUSTER.command(CommandId::ColorLoopSet as _).is_none() {
                panic!("ColorControl validation: COLOR_LOOP requires the ColorLoopSet command");
            }
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }

    /// Attach a [`SceneInvalidator`] — typically the
    /// [`crate::dm::clusters::scenes::ScenesState`] backing Scenes
    /// Management on the same endpoint. No-op when unset.
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

    fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut ColorControlState) -> R,
    {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            f(&mut state)
        })
    }

    fn with_state_notify<F, R>(&self, ctx: impl WriteContext, f: F) -> R
    where
        F: FnOnce(&mut ColorControlState) -> R,
    {
        let result = self.with_state(f);
        ctx.notify_changed();
        result
    }

    // ---- Scene-recall apply helpers (used by SceneClusterHandler) ----

    /// Apply the `CurrentXAndCurrentY` mode.
    fn apply_xy<N: AttrChangeNotifier>(&self, ctx: &N, x: u16, y: u16, scene_apply: bool) {
        self.hooks.set_current_x(x);
        self.hooks.set_current_y(y);
        self.hooks
            .set_color_mode(ColorModeEnum::CurrentXAndCurrentY);
        self.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::CurrentXAndCurrentY);
        let cluster_id = <Self as SceneClusterHandler>::CLUSTER_ID;
        ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::CurrentX as _);
        ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::CurrentY as _);
        ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::ColorMode as _);
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
            .set_color_mode(ColorModeEnum::ColorTemperatureMireds);
        self.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::ColorTemperatureMireds);
        let cluster_id = <Self as SceneClusterHandler>::CLUSTER_ID;
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::ColorTemperatureMireds as _,
        );
        ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::ColorMode as _);
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::EnhancedColorMode as _,
        );
        if !scene_apply {
            self.notify_scenable_changed();
        }
    }

    /// Apply the `CurrentHueAndCurrentSaturation` mode. `CurrentHue`
    /// is the high byte of `EnhancedCurrentHue`.
    fn apply_hue_saturation<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        hue_u8: u8,
        saturation: u8,
        scene_apply: bool,
    ) {
        self.hooks.set_enhanced_current_hue((hue_u8 as u16) << 8);
        self.hooks.set_current_saturation(saturation);
        self.hooks
            .set_color_mode(ColorModeEnum::CurrentHueAndCurrentSaturation);
        self.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::CurrentHueAndCurrentSaturation);
        let cluster_id = <Self as SceneClusterHandler>::CLUSTER_ID;
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
        ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::ColorMode as _);
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
        // Non-enhanced ColorMode mirrors to the closest non-enhanced equivalent.
        self.hooks
            .set_color_mode(ColorModeEnum::CurrentHueAndCurrentSaturation);
        self.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::EnhancedCurrentHueAndCurrentSaturation);
        let cluster_id = <Self as SceneClusterHandler>::CLUSTER_ID;
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
        ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::ColorMode as _);
        ctx.notify_attr_changed(
            self.endpoint_id,
            cluster_id,
            AttributeId::EnhancedColorMode as _,
        );
        if !scene_apply {
            self.notify_scenable_changed();
        }
    }

    /// Apply a colour-loop activation — short-circuits `MoveTo*`
    /// dispatch when the recalled scene has `ColorLoopActive=1`.
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
        let cluster_id = <Self as SceneClusterHandler>::CLUSTER_ID;
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

// ---- ClusterAsyncHandler implementation ----

impl<H: ColorControlHooks, OH: OnOffHooks, LH: LevelControlHooks> ClusterAsyncHandler
    for ColorControlHandler<'_, H, OH, LH>
{
    const CLUSTER: Cluster<'static> = H::CLUSTER;

    async fn run(&self, _ctx: impl HandlerContext) -> Result<(), Error> {
        // Step 1: just keep the hooks' background task alive. The
        // task_manager loop is wired in Step 3+ when transitions land.
        let mut hooks_fut = pin!(self.hooks.run(|_message| {
            // No out-of-band handling yet.
        }));
        loop {
            match select(&mut hooks_fut, self.task_signal.wait_signalled()).await {
                Either::First(_) => panic!(
                    "ColorControlHooks::run returned; implementers MUST not return. Use loop {{}} or core::future::pending::<()>().await."
                ),
                Either::Second(_task) => {
                    // No tasks defined yet — drop and resume waiting.
                }
            }
        }
    }

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    // ---- Attribute reads ----

    fn current_hue(&self, _ctx: impl ReadContext) -> impl Future<Output = Result<u8, Error>> {
        ready(Ok((self.hooks.enhanced_current_hue() >> 8) as u8))
    }

    fn current_saturation(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u8, Error>> {
        ready(Ok(self.hooks.current_saturation()))
    }

    fn remaining_time(&self, _ctx: impl ReadContext) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.with_state(|s| s.remaining_time)))
    }

    fn current_x(&self, _ctx: impl ReadContext) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.hooks.current_x()))
    }

    fn current_y(&self, _ctx: impl ReadContext) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.hooks.current_y()))
    }

    fn color_temperature_mireds(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.hooks.color_temperature_mireds()))
    }

    async fn color_mode(&self, _ctx: impl ReadContext) -> Result<ColorModeEnum, Error> {
        Ok(self.hooks.color_mode())
    }

    async fn options(&self, _ctx: impl ReadContext) -> Result<OptionsBitmap, Error> {
        Ok(self.with_state(|s| s.options))
    }

    async fn number_of_primaries(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        // Devices that don't enumerate primaries report null.
        Ok(Nullable::none())
    }

    fn enhanced_current_hue(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.hooks.enhanced_current_hue()))
    }

    async fn enhanced_color_mode(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<EnhancedColorModeEnum, Error> {
        Ok(self.hooks.enhanced_color_mode())
    }

    fn color_loop_active(&self, _ctx: impl ReadContext) -> impl Future<Output = Result<u8, Error>> {
        ready(Ok(self.hooks.color_loop_active() as u8))
    }

    fn color_loop_direction(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u8, Error>> {
        ready(Ok(self.hooks.color_loop_direction() as u8))
    }

    fn color_loop_time(&self, _ctx: impl ReadContext) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.hooks.color_loop_time()))
    }

    fn color_loop_start_enhanced_hue(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.hooks.color_loop_start_enhanced_hue()))
    }

    fn color_loop_stored_enhanced_hue(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.hooks.color_loop_stored_enhanced_hue()))
    }

    async fn color_capabilities(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<ColorCapabilitiesBitmap, Error> {
        Ok(H::COLOR_CAPABILITIES)
    }

    fn color_temp_physical_min_mireds(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(H::COLOR_TEMP_PHYSICAL_MIN_MIREDS))
    }

    fn color_temp_physical_max_mireds(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(H::COLOR_TEMP_PHYSICAL_MAX_MIREDS))
    }

    fn couple_color_temp_to_level_min_mireds(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(H::COUPLE_COLOR_TEMP_TO_LEVEL_MIN_MIREDS))
    }

    fn start_up_color_temperature_mireds(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<Nullable<u16>, Error>> {
        ready(self.hooks.start_up_color_temperature_mireds())
    }

    // ---- Attribute writes ----

    async fn set_options(&self, ctx: impl WriteContext, value: OptionsBitmap) -> Result<(), Error> {
        // Only `EXECUTE_IF_OFF` (bit 0) is defined; other bits are reserved.
        if value.bits() & !OptionsBitmap::EXECUTE_IF_OFF.bits() != 0 {
            return Err(ErrorCode::ConstraintError.into());
        }
        self.with_state_notify(ctx, |s| {
            s.options = value;
        });
        Ok(())
    }

    fn set_start_up_color_temperature_mireds(
        &self,
        ctx: impl WriteContext,
        value: Nullable<u16>,
    ) -> impl Future<Output = Result<(), Error>> {
        ready('a: {
            // Non-null values must lie in 1..=65279 (the spec's
            // `temperatureMireds` reserves 0 and 65280..=65535).
            if let Some(v) = value.clone().into_option() {
                if v == 0 || v > 0xFEFF {
                    break 'a Err(ErrorCode::ConstraintError.into());
                }
            }
            let res = self.hooks.set_start_up_color_temperature_mireds(value);
            if res.is_ok() {
                ctx.notify_changed();
            }
            res
        })
    }

    // ---- Command handlers (Step 1: all stubbed as `CommandNotFound`) ----

    async fn handle_move_to_hue(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveToHueRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_move_hue(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveHueRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_step_hue(
        &self,
        _ctx: impl InvokeContext,
        _request: StepHueRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_move_to_saturation(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveToSaturationRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_move_saturation(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveSaturationRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_step_saturation(
        &self,
        _ctx: impl InvokeContext,
        _request: StepSaturationRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_move_to_hue_and_saturation(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveToHueAndSaturationRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_move_to_color(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveToColorRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_move_color(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveColorRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_step_color(
        &self,
        _ctx: impl InvokeContext,
        _request: StepColorRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_move_to_color_temperature(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveToColorTemperatureRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_enhanced_move_to_hue(
        &self,
        _ctx: impl InvokeContext,
        _request: EnhancedMoveToHueRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_enhanced_move_hue(
        &self,
        _ctx: impl InvokeContext,
        _request: EnhancedMoveHueRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_enhanced_step_hue(
        &self,
        _ctx: impl InvokeContext,
        _request: EnhancedStepHueRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_enhanced_move_to_hue_and_saturation(
        &self,
        _ctx: impl InvokeContext,
        _request: EnhancedMoveToHueAndSaturationRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_color_loop_set(
        &self,
        _ctx: impl InvokeContext,
        _request: ColorLoopSetRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_stop_move_step(
        &self,
        _ctx: impl InvokeContext,
        _request: StopMoveStepRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_move_color_temperature(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveColorTemperatureRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_step_color_temperature(
        &self,
        _ctx: impl InvokeContext,
        _request: StepColorTemperatureRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }
}

// ---- Scenes integration ----

impl<H, OH, LH> SceneClusterHandler for ColorControlHandler<'_, H, OH, LH>
where
    H: ColorControlHooks,
    OH: OnOffHooks,
    LH: LevelControlHooks,
{
    const CLUSTER_ID: ClusterId = FULL_CLUSTER.id;

    fn endpoint_id(&self) -> EndptId {
        self.endpoint_id
    }

    fn is_scenable_attribute(attribute_id: AttrId) -> bool {
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
        // `EnhancedColorMode` is captured unconditionally — apply
        // dispatches on it.
        let features = Feature::from_bits_truncate(H::CLUSTER.feature_map);

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

        let mode = self.hooks.enhanced_color_mode();
        avp_array.push_u8(AttributeId::EnhancedColorMode as _, mode as u8)
    }

    async fn apply<C: HandlerContext>(
        &self,
        ctx: &C,
        avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
        transition_time_ms: u32,
    ) -> Result<(), Error> {
        // Inner method takes `AttrChangeNotifier` (a `HandlerContext`
        // supertrait) so unit tests can pass `&()` without mocking.
        self.apply_inner(ctx, avp_list, transition_time_ms)
    }
}

impl<H: ColorControlHooks, OH: OnOffHooks, LH: LevelControlHooks>
    ColorControlHandler<'_, H, OH, LH>
{
    /// Sync apply, scoped to `AttrChangeNotifier` for testability.
    fn apply_inner<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
        _transition_time_ms: u32,
    ) -> Result<(), Error> {
        // We need `EnhancedColorMode` plus the mode-specific values
        // before dispatching, so collect them all in one pass.
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

        // An active colour loop short-circuits the MoveTo dispatch.
        if color_loop_active == Some(1) {
            let direction = color_loop_direction
                .and_then(color_loop_direction_from_u8)
                .unwrap_or(ColorLoopDirectionEnum::Increment);
            let time = color_loop_time.unwrap_or(0x0019);
            self.apply_color_loop(ctx, direction, time, true);
            return Ok(());
        }

        let Some(mode) = mode else {
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
                // `CurrentHue` is the high byte of `EnhancedCurrentHue`.
                let (Some(hue), Some(sat)) = (
                    enhanced_current_hue.map(|h| (h >> 8) as u8),
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
/// [`EnhancedColorModeEnum`], `None` for unknown values.
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
/// `None` for unknown values.
fn color_loop_direction_from_u8(v: u8) -> Option<ColorLoopDirectionEnum> {
    match v {
        0 => Some(ColorLoopDirectionEnum::Decrement),
        1 => Some(ColorLoopDirectionEnum::Increment),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the ColorControl scenes integration — no
    //! chip-tool YAML suite covers it.

    use super::*;
    use crate::tlv::{TLVElement, TLVWriteParent};
    use crate::utils::storage::WriteBuf;
    use crate::with;

    /// `()` is a no-op `AttrChangeNotifier`, which is all the apply
    /// helpers use — avoids mocking a full `HandlerContext`.
    const NULL_CTX: &() = &();

    /// `MockHooks<F>` carries its feature bitmap at the type level so
    /// the cluster's `H::CLUSTER` const is feature-gated per
    /// instantiation. Use `MockHooks::<{Feature::XY.bits()}>::new()`.
    struct MockHooks<const F: u32> {
        current_x: Cell<u16>,
        current_y: Cell<u16>,
        enhanced_current_hue: Cell<u16>,
        current_saturation: Cell<u8>,
        color_temperature_mireds: Cell<u16>,
        color_loop_active: Cell<bool>,
        color_loop_direction: Cell<ColorLoopDirectionEnum>,
        color_loop_time: Cell<u16>,
        color_loop_start_enhanced_hue: Cell<u16>,
        color_loop_stored_enhanced_hue: Cell<u16>,
        enhanced_color_mode: Cell<EnhancedColorModeEnum>,
        color_mode: Cell<ColorModeEnum>,
    }

    impl<const F: u32> MockHooks<F> {
        fn new() -> Self {
            Self {
                current_x: Cell::new(0),
                current_y: Cell::new(0),
                enhanced_current_hue: Cell::new(0),
                current_saturation: Cell::new(0),
                color_temperature_mireds: Cell::new(0),
                color_loop_active: Cell::new(false),
                color_loop_direction: Cell::new(ColorLoopDirectionEnum::Decrement),
                color_loop_time: Cell::new(0),
                color_loop_start_enhanced_hue: Cell::new(0),
                color_loop_stored_enhanced_hue: Cell::new(0),
                enhanced_color_mode: Cell::new(
                    EnhancedColorModeEnum::CurrentHueAndCurrentSaturation,
                ),
                color_mode: Cell::new(ColorModeEnum::CurrentHueAndCurrentSaturation),
            }
        }
    }

    impl<const F: u32> ColorControlHooks for MockHooks<F> {
        const CLUSTER: Cluster<'static> = FULL_CLUSTER
            .with_features(F)
            .with_attrs(with!(required))
            .with_cmds(with!());
        const COLOR_CAPABILITIES: ColorCapabilitiesBitmap =
            ColorCapabilitiesBitmap::from_bits_retain(F as u16);
        const COLOR_TEMP_PHYSICAL_MIN_MIREDS: u16 = 153;
        const COLOR_TEMP_PHYSICAL_MAX_MIREDS: u16 = 500;

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
        fn color_temperature_mireds(&self) -> u16 {
            self.color_temperature_mireds.get()
        }
        fn set_color_temperature_mireds(&self, value: u16) {
            self.color_temperature_mireds.set(value);
        }
        fn color_mode(&self) -> ColorModeEnum {
            self.color_mode.get()
        }
        fn set_color_mode(&self, value: ColorModeEnum) {
            self.color_mode.set(value);
        }
        fn enhanced_color_mode(&self) -> EnhancedColorModeEnum {
            self.enhanced_color_mode.get()
        }
        fn set_enhanced_color_mode(&self, value: EnhancedColorModeEnum) {
            self.enhanced_color_mode.set(value);
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
        fn set_color_loop_start_enhanced_hue(&self, value: u16) {
            self.color_loop_start_enhanced_hue.set(value);
        }
        fn color_loop_stored_enhanced_hue(&self) -> u16 {
            self.color_loop_stored_enhanced_hue.get()
        }
        fn set_color_loop_stored_enhanced_hue(&self, value: u16) {
            self.color_loop_stored_enhanced_hue.set(value);
        }
        fn set_device_xy(&self, x: u16, y: u16) -> Result<(u16, u16), ()> {
            Ok((x, y))
        }
        fn set_device_hue_saturation(
            &self,
            enhanced_hue: u16,
            saturation: u8,
        ) -> Result<(u16, u8), ()> {
            Ok((enhanced_hue, saturation))
        }
        fn set_device_color_temperature_mireds(&self, mireds: u16) -> Result<u16, ()> {
            Ok(mireds)
        }
    }

    /// [`SceneInvalidator`] mock that counts calls.
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

    fn handler<const F: u32>() -> ColorControlHandler<'static, MockHooks<F>, NoOnOff, NoLevelControl>
    {
        let hooks = MockHooks::<F>::new();
        ColorControlHandler::new(Dataver::new(1), 1, hooks, AttributeDefaults::default())
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
            type H<'a> =
                ColorControlHandler<'a, MockHooks<{ Feature::XY.bits() }>, NoOnOff, NoLevelControl>;
            assert!(
                <H as SceneClusterHandler>::is_scenable_attribute(attr as AttrId),
                "expected {:?} to be scenable",
                attr
            );
        }
    }

    #[test]
    fn is_scenable_attribute_rejects_unscenable_color_attrs() {
        for attr in [
            AttributeId::CurrentHue,
            AttributeId::ColorMode,
            AttributeId::Options,
            AttributeId::NumberOfPrimaries,
            AttributeId::ColorCapabilities,
        ] {
            type H<'a> =
                ColorControlHandler<'a, MockHooks<{ Feature::XY.bits() }>, NoOnOff, NoLevelControl>;
            assert!(
                !<H as SceneClusterHandler>::is_scenable_attribute(attr as AttrId),
                "expected {:?} to NOT be scenable",
                attr
            );
        }
    }

    // ---- capture: feature gating ----

    #[test]
    fn capture_xy_only_emits_just_xy_and_mode() {
        let h = handler::<{ Feature::XY.bits() }>();
        h.hooks.set_current_x(0x1234);
        h.hooks.set_current_y(0x5678);
        h.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::CurrentXAndCurrentY);

        let mut buf = [0u8; 256];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("test", &mut wb);
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
        let mut count = 0;
        let mut seen_mode = false;
        let mut seen_x = false;
        let mut seen_y = false;
        for avp in arr.iter() {
            let avp = avp.unwrap();
            count += 1;
            let aid = avp.attribute_id().unwrap();
            if aid == AttributeId::CurrentX as u32 {
                seen_x = true;
            } else if aid == AttributeId::CurrentY as u32 {
                seen_y = true;
            } else if aid == AttributeId::EnhancedColorMode as u32 {
                seen_mode = true;
            }
        }
        assert_eq!(count, 3);
        assert!(seen_x && seen_y && seen_mode);
    }

    #[test]
    fn capture_color_temperature_only_emits_just_mireds_and_mode() {
        let h = handler::<{ Feature::COLOR_TEMPERATURE.bits() }>();
        h.hooks.set_color_temperature_mireds(250);
        h.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::ColorTemperatureMireds);

        let mut buf = [0u8; 256];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("test", &mut wb);
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
        let count = arr.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn capture_full_feature_set_emits_all_scenable_attrs() {
        const F: u32 = Feature::XY.bits()
            | Feature::HUE_AND_SATURATION.bits()
            | Feature::ENHANCED_HUE.bits()
            | Feature::COLOR_LOOP.bits()
            | Feature::COLOR_TEMPERATURE.bits();
        let h = handler::<F>();

        let mut buf = [0u8; 512];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("test", &mut wb);
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
        // 2 (xy) + 1 (enh hue) + 1 (sat) + 3 (color loop active/dir/time) + 1 (mireds) + 1 (mode)
        assert_eq!(arr.iter().count(), 9);
    }

    // ---- apply: mode dispatch ----

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
        let h = handler::<{ Feature::XY.bits() }>();
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
        assert!(matches!(
            h.hooks.color_mode(),
            ColorModeEnum::CurrentXAndCurrentY
        ));
    }

    #[test]
    fn apply_hue_saturation_mode_truncates_enhanced_hue_to_u8() {
        // `CurrentHue` (u8) is the high byte of `EnhancedCurrentHue`
        // (u16). Captured EnhancedHue=0x12FF → CurrentHue=0x12 →
        // round-trip stored as 0x1200.
        let h = handler::<{ Feature::HUE_AND_SATURATION.bits() }>();
        let mut buf = [0u8; 128];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("test", &mut wb);
            let array =
                AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                    .unwrap();
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

        assert_eq!(h.hooks.enhanced_current_hue(), 0x1200);
        assert_eq!(h.hooks.current_saturation(), 100);
        assert!(matches!(
            h.hooks.enhanced_color_mode(),
            EnhancedColorModeEnum::CurrentHueAndCurrentSaturation
        ));
    }

    #[test]
    fn apply_enhanced_hue_saturation_keeps_full_u16_hue() {
        const F: u32 = Feature::HUE_AND_SATURATION.bits() | Feature::ENHANCED_HUE.bits();
        let h = handler::<F>();
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

        assert_eq!(h.hooks.enhanced_current_hue(), 0x4321);
        assert_eq!(h.hooks.current_saturation(), 200);
    }

    // ---- apply: ColorLoopActive=1 short-circuit ----

    #[test]
    fn apply_with_color_loop_active_skips_mode_dispatch() {
        const F: u32 = Feature::COLOR_LOOP.bits()
            | Feature::ENHANCED_HUE.bits()
            | Feature::HUE_AND_SATURATION.bits()
            | Feature::XY.bits();
        let h = handler::<F>();
        // Pre-set XY so we can detect if the mode-dispatch path ran.
        h.hooks.set_current_x(1);
        h.hooks.set_current_y(2);
        let mut buf = [0u8; 256];
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
                .push_u16(AttributeId::ColorLoopTime as _, 30)
                .unwrap()
                .push_u16(AttributeId::CurrentX as _, 0xABCD)
                .unwrap()
                .push_u16(AttributeId::CurrentY as _, 0xDCBA)
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

        assert!(h.hooks.color_loop_active());
        assert_eq!(h.hooks.color_loop_time(), 30);
        // XY mode-dispatch must NOT have run.
        assert_eq!(h.hooks.current_x(), 1);
        assert_eq!(h.hooks.current_y(), 2);
    }

    // ---- apply: missing-data tolerance ----

    #[test]
    fn apply_with_no_mode_is_noop() {
        // Missing EnhancedColorMode → no-op rather than error.
        let h = handler::<{ Feature::XY.bits() }>();
        let mut buf = [0u8; 128];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new("test", &mut wb);
            let array =
                AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                    .unwrap();
            let array = array
                .push_u16(AttributeId::CurrentX as _, 1)
                .unwrap()
                .push_u16(AttributeId::CurrentY as _, 2)
                .unwrap();
            array.end().unwrap();
            wb.get_tail()
        };
        let bytes = &buf[..len];
        let elem = TLVElement::new(bytes);
        let avp_list: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        h.apply_inner(NULL_CTX, &avp_list, 0).unwrap();

        // current_x/y unchanged (still 0 from new()).
        assert_eq!(h.hooks.current_x(), 0);
        assert_eq!(h.hooks.current_y(), 0);
    }

    // ---- scene_apply gates drift notification ----

    #[test]
    fn scene_apply_true_suppresses_invalidator() {
        let inv = CountingInvalidator::new();
        let hooks = MockHooks::<{ Feature::XY.bits() }>::new();
        let h: ColorControlHandler<'_, _, NoOnOff, NoLevelControl> =
            ColorControlHandler::new(Dataver::new(1), 1, hooks, AttributeDefaults::default());
        let h = h.with_scene_invalidator(&inv);

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

        assert_eq!(inv.count(), 0, "scene apply must NOT invalidate");
    }

    #[test]
    fn direct_mutator_with_scene_apply_false_fires_invalidator() {
        let inv = CountingInvalidator::new();
        let hooks = MockHooks::<{ Feature::XY.bits() }>::new();
        let h: ColorControlHandler<'_, _, NoOnOff, NoLevelControl> =
            ColorControlHandler::new(Dataver::new(1), 1, hooks, AttributeDefaults::default());
        let h = h.with_scene_invalidator(&inv);

        h.apply_xy(NULL_CTX, 0x1111, 0x2222, false);

        assert_eq!(inv.count(), 1, "command-driven mutation must invalidate");
    }

    // ---- capture → apply roundtrip ----

    #[test]
    fn capture_then_apply_roundtrips_xy_mode_state() {
        let h = handler::<{ Feature::XY.bits() }>();
        h.hooks.set_current_x(0xAAAA);
        h.hooks.set_current_y(0x5555);
        h.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::CurrentXAndCurrentY);

        let mut cap_buf = [0u8; 256];
        let cap_len = {
            let mut wb = WriteBuf::new(&mut cap_buf);
            let parent = TLVWriteParent::new("test", &mut wb);
            let array =
                AttributeValuePairStructArrayBuilder::new(parent, &crate::tlv::TLVTag::Anonymous)
                    .unwrap();
            let array = h.capture(array).unwrap();
            array.end().unwrap();
            wb.get_tail()
        };

        // Reset hooks
        h.hooks.set_current_x(0);
        h.hooks.set_current_y(0);
        h.hooks
            .set_enhanced_color_mode(EnhancedColorModeEnum::CurrentHueAndCurrentSaturation);

        // Apply the captured blob
        let elem = TLVElement::new(&cap_buf[..cap_len]);
        let avp_list: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        h.apply_inner(NULL_CTX, &avp_list, 0).unwrap();

        assert_eq!(h.hooks.current_x(), 0xAAAA);
        assert_eq!(h.hooks.current_y(), 0x5555);
        assert!(matches!(
            h.hooks.enhanced_color_mode(),
            EnhancedColorModeEnum::CurrentXAndCurrentY
        ));
    }
}
