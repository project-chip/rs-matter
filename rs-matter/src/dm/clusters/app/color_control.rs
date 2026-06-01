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

//! ColorControl cluster — skeleton handler exposing only the
//! [`SceneClusterHandler`] impl. The full data-model `ClusterHandler`
//! (commands, attribute reads/writes) will be added in a follow-up.

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

/// Device-supplied state + I/O for the ColorControl cluster. Getters
/// return cached device state; setters are synchronous and cheap
/// (called inline from scene apply). Attributes outside the active
/// feature subset may be backed by no-op stubs.
pub trait ColorControlHooks {
    /// Active `Feature` bitmap on this endpoint. Used to feature-gate
    /// scene capture.
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

    /// Duration of one full color-loop cycle, in seconds.
    fn color_loop_time(&self) -> u16;
    fn set_color_loop_time(&self, value: u16);

    /// Starting hue used when scene recall activates the color loop.
    fn color_loop_start_enhanced_hue(&self) -> u16;

    fn enhanced_color_mode(&self) -> EnhancedColorModeEnum;
    fn set_enhanced_color_mode(&self, value: EnhancedColorModeEnum);
}

/// Skeleton ColorControl cluster handler — currently exposes only
/// the scenes-integration surface, not the full `ClusterHandler`.
pub struct ColorControlHandler<'a, H: ColorControlHooks> {
    #[allow(dead_code)]
    dataver: Dataver,
    endpoint_id: EndptId,
    hooks: H,
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

    /// Apply the `CurrentXAndCurrentY` mode.
    fn apply_xy<N: AttrChangeNotifier>(&self, ctx: &N, x: u16, y: u16, scene_apply: bool) {
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

    /// Apply the `CurrentHueAndCurrentSaturation` mode. Hue is
    /// stored in `EnhancedCurrentHue` as the low byte.
    fn apply_hue_saturation<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        hue_u8: u8,
        saturation: u8,
        scene_apply: bool,
    ) {
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

    /// Apply a color-loop activation — short-circuits `MoveTo*`
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
        // Feature-gated availability is enforced at capture/apply,
        // not here — this only validates `AddScene` payload shape.
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

impl<H: ColorControlHooks> ColorControlHandler<'_, H> {
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

        // An active color loop short-circuits the MoveTo dispatch.
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
                // Non-enhanced hue is the low byte of EnhancedCurrentHue.
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

    /// `()` is a no-op `AttrChangeNotifier`, which is all the apply
    /// helpers use — avoids mocking a full `HandlerContext`.
    const NULL_CTX: &() = &();

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

    fn handler(features: Feature) -> ColorControlHandler<'static, MockHooks> {
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
        // Missing EnhancedColorMode → no-op rather than error.
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
