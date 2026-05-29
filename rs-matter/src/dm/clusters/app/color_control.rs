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

//! ColorControl cluster (placeholder).
//!
//! A full ColorControl cluster handler is not yet shipped — this
//! module currently only provides the [`scenes`] submodule, which
//! lets ColorControl participate in scene capture / recall via
//! Scenes Management. Downstream apps that ship their own
//! ColorControl handler can register the [`scenes::ColorControlSceneClusterHandler`]
//! alongside it with `ScenesHandler::new`.

/// Scenes Management integration for the ColorControl cluster.
///
/// # Why ColorControl needs special wiring
///
/// Unlike OnOff / LevelControl (each one read-only scene-able
/// attribute, one apply command), ColorControl has:
///
/// - **Up to 9 scene-able attributes** (`CurrentX`, `CurrentY`,
///   `EnhancedCurrentHue`, `CurrentSaturation`, `ColorLoopActive`,
///   `ColorLoopDirection`, `ColorLoopTime`, `ColorTemperatureMireds`,
///   `EnhancedColorMode`). All are read-only at the attribute level.
/// - **Feature-conditional capture**: which attributes are stored
///   depends on the device's `FeatureMap` (`XY`, `HUE_AND_SATURATION`,
///   `ENHANCED_HUE`, `COLOR_LOOP`, `COLOR_TEMPERATURE`).
/// - **Mode-dependent apply**: the captured `EnhancedColorMode`
///   selects which `MoveTo*` command to invoke (`MoveToColor` for XY,
///   `MoveToColorTemperature` for `ColorTemperatureMireds`, etc.). If
///   `ColorLoopActive` is captured as `1`, apply instead starts a
///   color loop via `ColorLoopSet`.
///
/// Reading the FeatureMap attribute at runtime is possible but adds
/// one cross-cluster read per scene operation. Instead we let the
/// application inject a [`ColorControlFeatureLookup`] that maps
/// `EndptId` → `Feature` bits — the app knows which ColorControl
/// features it enabled on which endpoints, so this is free.
pub mod scenes {
    use crate::dm::clusters::decl::color_control::{
        AttributeId, ColorLoopActionEnum, ColorLoopDirectionEnum, ColorLoopSetRequestBuilder,
        CommandId, EnhancedColorModeEnum, EnhancedMoveToHueAndSaturationRequestBuilder, Feature,
        MoveToColorRequestBuilder, MoveToColorTemperatureRequestBuilder,
        MoveToHueAndSaturationRequestBuilder, OptionsBitmap, UpdateFlagsBitmap, FULL_CLUSTER,
    };
    use crate::dm::clusters::decl::scenes_management::{
        AttributeValuePairStruct, AttributeValuePairStructArrayBuilder,
    };
    use crate::dm::clusters::scenes::{SceneClusterHandler, SceneContext};
    use crate::dm::{AsyncHandler, ClusterId, EndptId, InvokeContext};
    use crate::error::Error;
    use crate::tlv::{TLVArray, TLVBuilderParent, TLVTag, TLVWriteParent};
    use crate::utils::storage::WriteBuf;

    /// Worst-case TLV-encoded size of any command this scene impl
    /// sends. The largest is `ColorLoopSet` (7 fields):
    ///
    /// ```text
    /// 0x15                              (struct start, anon)        1 B
    ///   updateFlags    bitmap8 @ Ctx 0                              3 B
    ///   action         enum8   @ Ctx 1                              3 B
    ///   direction      enum8   @ Ctx 2                              3 B
    ///   time           u16     @ Ctx 3                              4 B
    ///   startHue       u16     @ Ctx 4                              4 B
    ///   optionsMask    bitmap8 @ Ctx 5                              3 B
    ///   optionsOverride bitmap8 @ Ctx 6                             3 B
    /// 0x18                              (end_container)             1 B
    /// ----------------------------------------------------------- 25 B
    /// ```
    ///
    /// The 4 Move-To commands all fit in ≤ 20 B. 32 leaves a
    /// comfortable margin without over-committing.
    const MAX_REQUEST_BUF: usize = 32;

    /// Application-supplied feature lookup for ColorControl.
    ///
    /// The Matter spec lets ColorControl be deployed with any subset
    /// of {`XY`, `HUE_AND_SATURATION`, `ENHANCED_HUE`, `COLOR_LOOP`,
    /// `COLOR_TEMPERATURE`}. The Scenes integration needs to know
    /// which features are active on each endpoint so it can decide
    /// which attributes to capture and which `MoveTo*` /
    /// `ColorLoopSet` command to invoke on recall.
    ///
    /// The application implements this on whatever per-endpoint
    /// state it already has (often a static lookup), and passes a
    /// reference into [`ColorControlSceneClusterHandler::new`].
    pub trait ColorControlFeatureLookup {
        /// Return the `Feature` bitmap enabled for `endpoint_id`.
        /// Empty for endpoints where ColorControl is not installed
        /// (callers should not invoke this for endpoints without
        /// ColorControl).
        fn features(&self, endpoint_id: EndptId) -> Feature;
    }

    impl<T: ColorControlFeatureLookup + ?Sized> ColorControlFeatureLookup for &T {
        fn features(&self, endpoint_id: EndptId) -> Feature {
            (**self).features(endpoint_id)
        }
    }

    /// [`SceneClusterHandler`] for ColorControl.
    ///
    /// Holds a reference to a [`ColorControlFeatureLookup`]; not a
    /// ZST because the cluster's behaviour is feature-conditional.
    ///
    /// ```ignore
    /// let cc_lookup = MyFeatureLookup;
    /// let scenes = ScenesHandler::new(
    ///     dataver, &scenes_state,
    ///     (OnOffSceneClusterHandler,
    ///      (LevelControlSceneClusterHandler,
    ///       (ColorControlSceneClusterHandler::new(&cc_lookup), ()))),
    /// );
    /// ```
    #[derive(Copy, Clone)]
    pub struct ColorControlSceneClusterHandler<'a> {
        features: &'a dyn ColorControlFeatureLookup,
    }

    impl<'a> ColorControlSceneClusterHandler<'a> {
        pub const fn new(features: &'a dyn ColorControlFeatureLookup) -> Self {
            Self { features }
        }
    }

    impl SceneClusterHandler for ColorControlSceneClusterHandler<'_> {
        const CLUSTER_ID: ClusterId = FULL_CLUSTER.id;

        async fn capture<C, T, P>(
            &self,
            sctx: &SceneContext<C, T>,
            endpoint_id: EndptId,
            avp_array: AttributeValuePairStructArrayBuilder<P>,
        ) -> Result<AttributeValuePairStructArrayBuilder<P>, Error>
        where
            C: InvokeContext,
            T: AsyncHandler,
            P: TLVBuilderParent,
        {
            let features = self.features.features(endpoint_id);

            // Capture order mirrors chip's
            // `DefaultColorControlSceneHandler::SerializeSave`.
            // `EnhancedColorMode` is captured unconditionally — apply
            // dispatches on it.
            let avp_array = if features.contains(Feature::XY) {
                let x: u16 = sctx
                    .read(endpoint_id, FULL_CLUSTER.id, AttributeId::CurrentX as _)
                    .await?;
                let avp_array = avp_array.push_u16(AttributeId::CurrentX as _, x)?;
                let y: u16 = sctx
                    .read(endpoint_id, FULL_CLUSTER.id, AttributeId::CurrentY as _)
                    .await?;
                avp_array.push_u16(AttributeId::CurrentY as _, y)?
            } else {
                avp_array
            };

            let avp_array = if features.contains(Feature::ENHANCED_HUE) {
                let h: u16 = sctx
                    .read(
                        endpoint_id,
                        FULL_CLUSTER.id,
                        AttributeId::EnhancedCurrentHue as _,
                    )
                    .await?;
                avp_array.push_u16(AttributeId::EnhancedCurrentHue as _, h)?
            } else {
                avp_array
            };

            let avp_array = if features.contains(Feature::HUE_AND_SATURATION) {
                let s: u8 = sctx
                    .read(
                        endpoint_id,
                        FULL_CLUSTER.id,
                        AttributeId::CurrentSaturation as _,
                    )
                    .await?;
                avp_array.push_u8(AttributeId::CurrentSaturation as _, s)?
            } else {
                avp_array
            };

            let avp_array = if features.contains(Feature::COLOR_LOOP) {
                let active: u8 = sctx
                    .read(
                        endpoint_id,
                        FULL_CLUSTER.id,
                        AttributeId::ColorLoopActive as _,
                    )
                    .await?;
                let avp_array = avp_array.push_u8(AttributeId::ColorLoopActive as _, active)?;
                let direction: u8 = sctx
                    .read(
                        endpoint_id,
                        FULL_CLUSTER.id,
                        AttributeId::ColorLoopDirection as _,
                    )
                    .await?;
                let avp_array =
                    avp_array.push_u8(AttributeId::ColorLoopDirection as _, direction)?;
                let time: u16 = sctx
                    .read(
                        endpoint_id,
                        FULL_CLUSTER.id,
                        AttributeId::ColorLoopTime as _,
                    )
                    .await?;
                avp_array.push_u16(AttributeId::ColorLoopTime as _, time)?
            } else {
                avp_array
            };

            let avp_array = if features.contains(Feature::COLOR_TEMPERATURE) {
                let mireds: u16 = sctx
                    .read(
                        endpoint_id,
                        FULL_CLUSTER.id,
                        AttributeId::ColorTemperatureMireds as _,
                    )
                    .await?;
                avp_array.push_u16(AttributeId::ColorTemperatureMireds as _, mireds)?
            } else {
                avp_array
            };

            // `EnhancedColorMode` is always captured. The enum is
            // `enum8`, so serialized as `valueUnsigned8`.
            let mode_u8: u8 = sctx
                .read(
                    endpoint_id,
                    FULL_CLUSTER.id,
                    AttributeId::EnhancedColorMode as _,
                )
                .await?;
            avp_array.push_u8(AttributeId::EnhancedColorMode as _, mode_u8)
        }

        async fn apply<C, T>(
            &self,
            sctx: &SceneContext<C, T>,
            endpoint_id: EndptId,
            transition_time_ms: u32,
            avp_list: &TLVArray<'_, AttributeValuePairStruct<'_>>,
        ) -> Result<(), Error>
        where
            C: InvokeContext,
            T: AsyncHandler,
        {
            // Sweep the AVP list once and stash each known value. We
            // need EnhancedColorMode *and* the mode-specific values
            // before we can decide which command to invoke.
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

            // `MoveTo*` and `ColorLoopSet` carry `transitionTime` /
            // `time` as `int16u`. Recall passes `int32u` milliseconds
            // — convert with saturation. (`ColorLoopSet.time` is
            // already in seconds in the spec; we pass through the
            // captured `ColorLoopTime` value unchanged because that
            // attribute is already in seconds per the spec.)
            let transition_ds = (transition_time_ms / 100).min(u16::MAX as u32) as u16;

            // If the scene captured an active color loop, hand off to
            // ColorLoopSet and ignore the Move-To dispatch — mirrors
            // chip's behavior in `ColorControl::ApplyScene`.
            if color_loop_active == Some(1) {
                let direction = color_loop_direction
                    .and_then(color_loop_direction_from_u8)
                    .unwrap_or(ColorLoopDirectionEnum::Increment);
                let time = color_loop_time.unwrap_or(0x0019);

                let mut data_buf = [0u8; MAX_REQUEST_BUF];
                let data_len = {
                    let mut wb = WriteBuf::new(&mut data_buf);
                    let parent = TLVWriteParent::new("Scene/ColorLoopSet", &mut wb);
                    ColorLoopSetRequestBuilder::new(parent, &TLVTag::Anonymous)?
                        .update_flags(
                            UpdateFlagsBitmap::UPDATE_ACTION
                                | UpdateFlagsBitmap::UPDATE_DIRECTION
                                | UpdateFlagsBitmap::UPDATE_TIME,
                        )?
                        .action(ColorLoopActionEnum::ActivateFromColorLoopStartEnhancedHue)?
                        .direction(direction)?
                        .time(time)?
                        // `StartHue` isn't updated here (no
                        // UPDATE_START_HUE flag set) but the field is
                        // mandatory on the wire — pass 0.
                        .start_hue(0)?
                        .options_mask(OptionsBitmap::empty())?
                        .options_override(OptionsBitmap::empty())?
                        .end()?;
                    wb.get_tail()
                };
                return sctx
                    .invoke(
                        endpoint_id,
                        FULL_CLUSTER.id,
                        CommandId::ColorLoopSet as _,
                        &data_buf[..data_len],
                    )
                    .await;
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
                    let mut data_buf = [0u8; MAX_REQUEST_BUF];
                    let data_len = {
                        let mut wb = WriteBuf::new(&mut data_buf);
                        let parent = TLVWriteParent::new("Scene/MoveToColor", &mut wb);
                        MoveToColorRequestBuilder::new(parent, &TLVTag::Anonymous)?
                            .color_x(x)?
                            .color_y(y)?
                            .transition_time(transition_ds)?
                            .options_mask(OptionsBitmap::empty())?
                            .options_override(OptionsBitmap::empty())?
                            .end()?;
                        wb.get_tail()
                    };
                    sctx.invoke(
                        endpoint_id,
                        FULL_CLUSTER.id,
                        CommandId::MoveToColor as _,
                        &data_buf[..data_len],
                    )
                    .await
                }
                EnhancedColorModeEnum::ColorTemperatureMireds => {
                    let Some(mireds) = color_temperature_mireds else {
                        return Ok(());
                    };
                    let mut data_buf = [0u8; MAX_REQUEST_BUF];
                    let data_len = {
                        let mut wb = WriteBuf::new(&mut data_buf);
                        let parent = TLVWriteParent::new("Scene/MoveToColorTemperature", &mut wb);
                        MoveToColorTemperatureRequestBuilder::new(parent, &TLVTag::Anonymous)?
                            .color_temperature_mireds(mireds)?
                            .transition_time(transition_ds)?
                            .options_mask(OptionsBitmap::empty())?
                            .options_override(OptionsBitmap::empty())?
                            .end()?;
                        wb.get_tail()
                    };
                    sctx.invoke(
                        endpoint_id,
                        FULL_CLUSTER.id,
                        CommandId::MoveToColorTemperature as _,
                        &data_buf[..data_len],
                    )
                    .await
                }
                EnhancedColorModeEnum::CurrentHueAndCurrentSaturation => {
                    // Non-enhanced hue is u8; if only EnhancedHue was
                    // captured but the mode says non-enhanced, take the
                    // low byte. (Chip's behavior is similar — it stashes
                    // into `colorHueTransitionState->finalEnhancedHue`
                    // which is then truncated on apply.)
                    let (Some(hue), Some(sat)) = (
                        enhanced_current_hue.map(|h| (h & 0xFF) as u8),
                        current_saturation,
                    ) else {
                        return Ok(());
                    };
                    let mut data_buf = [0u8; MAX_REQUEST_BUF];
                    let data_len = {
                        let mut wb = WriteBuf::new(&mut data_buf);
                        let parent = TLVWriteParent::new("Scene/MoveToHueAndSaturation", &mut wb);
                        MoveToHueAndSaturationRequestBuilder::new(parent, &TLVTag::Anonymous)?
                            .hue(hue)?
                            .saturation(sat)?
                            .transition_time(transition_ds)?
                            .options_mask(OptionsBitmap::empty())?
                            .options_override(OptionsBitmap::empty())?
                            .end()?;
                        wb.get_tail()
                    };
                    sctx.invoke(
                        endpoint_id,
                        FULL_CLUSTER.id,
                        CommandId::MoveToHueAndSaturation as _,
                        &data_buf[..data_len],
                    )
                    .await
                }
                EnhancedColorModeEnum::EnhancedCurrentHueAndCurrentSaturation => {
                    let (Some(hue), Some(sat)) = (enhanced_current_hue, current_saturation) else {
                        return Ok(());
                    };
                    let mut data_buf = [0u8; MAX_REQUEST_BUF];
                    let data_len = {
                        let mut wb = WriteBuf::new(&mut data_buf);
                        let parent =
                            TLVWriteParent::new("Scene/EnhancedMoveToHueAndSaturation", &mut wb);
                        EnhancedMoveToHueAndSaturationRequestBuilder::new(
                            parent,
                            &TLVTag::Anonymous,
                        )?
                        .enhanced_hue(hue)?
                        .saturation(sat)?
                        .transition_time(transition_ds)?
                        .options_mask(OptionsBitmap::empty())?
                        .options_override(OptionsBitmap::empty())?
                        .end()?;
                        wb.get_tail()
                    };
                    sctx.invoke(
                        endpoint_id,
                        FULL_CLUSTER.id,
                        CommandId::EnhancedMoveToHueAndSaturation as _,
                        &data_buf[..data_len],
                    )
                    .await
                }
            }
        }
    }

    /// Convert a stored `valueUnsigned8` to an
    /// `EnhancedColorModeEnum`, returning `None` for unknown values
    /// rather than failing the apply.
    fn enhanced_color_mode_from_u8(v: u8) -> Option<EnhancedColorModeEnum> {
        match v {
            0 => Some(EnhancedColorModeEnum::CurrentHueAndCurrentSaturation),
            1 => Some(EnhancedColorModeEnum::CurrentXAndCurrentY),
            2 => Some(EnhancedColorModeEnum::ColorTemperatureMireds),
            3 => Some(EnhancedColorModeEnum::EnhancedCurrentHueAndCurrentSaturation),
            _ => None,
        }
    }

    /// Convert a stored `valueUnsigned8` to a `ColorLoopDirectionEnum`,
    /// returning `None` for unknown values.
    fn color_loop_direction_from_u8(v: u8) -> Option<ColorLoopDirectionEnum> {
        match v {
            0 => Some(ColorLoopDirectionEnum::Decrement),
            1 => Some(ColorLoopDirectionEnum::Increment),
            _ => None,
        }
    }
}
