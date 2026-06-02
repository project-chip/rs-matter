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

use embassy_futures::select::{select, select3, Either, Either3};
use embassy_time::{Duration, Instant, Timer};

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
            options: OptionsBitmap::from_bits_truncate(0),
        }
    }
}

/// Device-supplied state + I/O for the Color Control cluster.
///
/// Implementers expose the device's persisted color attributes,
/// physical color-temperature limits, and three actuator hooks (XY,
/// hue+saturation, color-temperature). Getters return cached state;
/// setters are synchronous and cheap.
/// Colour-set command passed to [`ColorControlHooks::set_device_color`].
/// The variant carried by the command identifies the colour space the
/// cluster has decided to drive the device in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SetDeviceColor {
    /// CIE xy chromaticity. `x` and `y` are in `0..=0xFEFF`.
    Xy { x: u16, y: u16 },
    /// Hue + saturation. `enhanced_hue` is the full 16-bit hue
    /// (`CurrentHue` is its high byte). `saturation` is `0..=254`.
    HueSaturation { enhanced_hue: u16, saturation: u8 },
    /// Colour temperature in mireds, clamped by the cluster to
    /// `[COLOR_TEMP_PHYSICAL_MIN_MIREDS, COLOR_TEMP_PHYSICAL_MAX_MIREDS]`.
    ColorTemperature { mireds: u16 },
}

/// Gamma encoding for the RGB output of [`SetDeviceColor::to_rgb`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RgbGamma {
    /// Linear-light RGB. Each channel is proportional to luminous
    /// intensity. Use for PWM duty cycles and additive LED mixing.
    Linear,
    /// sRGB gamma (IEC 61966-2-1). Use when the consumer expects a
    /// display-ready value.
    SRgb,
}

/// sRGB encoding LUT — maps linear `0..=255` to sRGB-encoded `0..=255`
/// per IEC 61966-2-1. Avoids needing `libm::powf` for the gamma curve
/// at the cost of one bit of precision at the bottom end.
const SRGB_GAMMA_LUT: [u8; 256] = [
    0, 13, 22, 28, 34, 38, 42, 46, 50, 53, 56, 59, 61, 64, 66, 69, //
    71, 73, 75, 77, 79, 81, 83, 85, 86, 88, 90, 92, 93, 95, 96, 98, //
    99, 101, 102, 104, 105, 106, 108, 109, 110, 112, 113, 114, 115, 117, 118, 119, //
    120, 121, 122, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, //
    137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 148, 149, 150, 151, //
    152, 153, 154, 155, 155, 156, 157, 158, 159, 159, 160, 161, 162, 163, 163, 164, //
    165, 166, 167, 167, 168, 169, 170, 170, 171, 172, 173, 173, 174, 175, 175, 176, //
    177, 178, 178, 179, 180, 180, 181, 182, 182, 183, 184, 185, 185, 186, 187, 187, //
    188, 189, 189, 190, 190, 191, 192, 192, 193, 194, 194, 195, 196, 196, 197, 197, //
    198, 199, 199, 200, 200, 201, 202, 202, 203, 203, 204, 205, 205, 206, 206, 207, //
    208, 208, 209, 209, 210, 210, 211, 212, 212, 213, 213, 214, 214, 215, 215, 216, //
    216, 217, 218, 218, 219, 219, 220, 220, 221, 221, 222, 222, 223, 223, 224, 224, //
    225, 226, 226, 227, 227, 228, 228, 229, 229, 230, 230, 231, 231, 232, 232, 233, //
    233, 234, 234, 235, 235, 236, 236, 237, 237, 238, 238, 238, 239, 239, 240, 240, //
    241, 241, 242, 242, 243, 243, 244, 244, 245, 245, 246, 246, 246, 247, 247, 248, //
    248, 249, 249, 250, 250, 251, 251, 251, 252, 252, 253, 253, 254, 254, 255, 255, //
];

impl SetDeviceColor {
    /// Convert to an sRGB-primaries RGB triplet, each channel
    /// `0..=255`, with the requested `gamma` encoding. Brightness is
    /// assumed full (the brightest channel of the result hits 255),
    /// since this colour command carries no separate luminance.
    ///
    /// Suitable for driving an RGB LED — use [`RgbGamma::Linear`] for
    /// PWM duty cycles and [`RgbGamma::SRgb`] when the consumer
    /// expects a display-encoded value.
    pub fn to_rgb(self, gamma: RgbGamma) -> (u8, u8, u8) {
        let (r, g, b) = self.to_linear_rgb_f32();
        let to_u8 = |c: f32| (c.clamp(0.0, 1.0) * 255.0 + 0.5) as u8;
        let (rl, gl, bl) = (to_u8(r), to_u8(g), to_u8(b));
        match gamma {
            RgbGamma::Linear => (rl, gl, bl),
            RgbGamma::SRgb => (
                SRGB_GAMMA_LUT[rl as usize],
                SRGB_GAMMA_LUT[gl as usize],
                SRGB_GAMMA_LUT[bl as usize],
            ),
        }
    }

    /// Convert to CIE 1931 xy chromaticity (each value `0..=0xFEFF`).
    /// Idempotent on the `Xy` variant.
    pub fn to_xy(self) -> (u16, u16) {
        match self {
            SetDeviceColor::Xy { x, y } => (x, y),
            SetDeviceColor::HueSaturation {
                enhanced_hue,
                saturation,
            } => {
                let (r, g, b) = hsv_to_linear_rgb_f32(enhanced_hue, saturation);
                linear_rgb_to_xy(r, g, b)
            }
            SetDeviceColor::ColorTemperature { mireds } => ct_mireds_to_xy_f32_pair(mireds),
        }
    }

    /// Convert to enhanced-hue + saturation. Idempotent on the
    /// `HueSaturation` variant. Brightness is assumed full.
    pub fn to_hue_saturation(self) -> (u16, u8) {
        let (r, g, b) = match self {
            SetDeviceColor::HueSaturation {
                enhanced_hue,
                saturation,
            } => return (enhanced_hue, saturation),
            SetDeviceColor::Xy { x, y } => xy_to_linear_rgb_f32(x, y),
            SetDeviceColor::ColorTemperature { mireds } => {
                let (x, y) = ct_mireds_to_xy_f32_pair(mireds);
                xy_to_linear_rgb_f32(x, y)
            }
        };
        linear_rgb_to_hue_saturation(r, g, b)
    }

    /// Internal: dispatch to the per-variant linear-RGB converter.
    fn to_linear_rgb_f32(self) -> (f32, f32, f32) {
        match self {
            SetDeviceColor::Xy { x, y } => xy_to_linear_rgb_f32(x, y),
            SetDeviceColor::HueSaturation {
                enhanced_hue,
                saturation,
            } => hsv_to_linear_rgb_f32(enhanced_hue, saturation),
            SetDeviceColor::ColorTemperature { mireds } => {
                let (x, y) = ct_mireds_to_xy_f32_pair(mireds);
                xy_to_linear_rgb_f32(x, y)
            }
        }
    }
}

/// HSV (V=1) → linear sRGB, each channel `0.0..=1.0`.
fn hsv_to_linear_rgb_f32(enhanced_hue: u16, saturation: u8) -> (f32, f32, f32) {
    let h_deg = enhanced_hue as f32 * 360.0 / 65536.0;
    let s = saturation as f32 / 254.0;
    let v = 1.0_f32;
    let c = v * s;
    let h6 = h_deg / 60.0;
    // h6 ∈ [0, 6); fold to [0, 2) without f32 `%` (needs `__fmodf` on
    // soft-float targets like riscv32imc).
    let h6_mod2 = if h6 < 2.0 {
        h6
    } else if h6 < 4.0 {
        h6 - 2.0
    } else {
        h6 - 4.0
    };
    let x = c * (1.0 - (h6_mod2 - 1.0).abs());
    let m = v - c;
    let (r, g, b) = match h6 as i32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    (r + m, g + m, b + m)
}

/// CIE xy chromaticity → linear sRGB, normalised so the brightest
/// channel is `1.0` (full brightness at the given chromaticity).
/// Out-of-gamut inputs are clamped per-channel.
fn xy_to_linear_rgb_f32(x_u16: u16, y_u16: u16) -> (f32, f32, f32) {
    let x = x_u16 as f32 / 0xFEFF as f32;
    let y = y_u16 as f32 / 0xFEFF as f32;
    if y < 1e-4 {
        return (0.0, 0.0, 0.0);
    }
    // Y=1.0 (we normalise at the end), so X=x/y, Z=(1-x-y)/y.
    let x_xyz = x / y;
    let y_xyz = 1.0;
    let z_xyz = (1.0 - x - y) / y;
    // sRGB D65 inverse matrix (XYZ → linear sRGB).
    let r = 3.2406 * x_xyz - 1.5372 * y_xyz - 0.4986 * z_xyz;
    let g = -0.9689 * x_xyz + 1.8758 * y_xyz + 0.0415 * z_xyz;
    let b = 0.0557 * x_xyz - 0.2040 * y_xyz + 1.0570 * z_xyz;
    let r = r.max(0.0);
    let g = g.max(0.0);
    let b = b.max(0.0);
    let max_c = r.max(g).max(b);
    if max_c <= 1e-6 {
        (0.0, 0.0, 0.0)
    } else {
        (r / max_c, g / max_c, b / max_c)
    }
}

/// Linear sRGB → CIE xy chromaticity (each `0..=0xFEFF`).
fn linear_rgb_to_xy(r: f32, g: f32, b: f32) -> (u16, u16) {
    // sRGB D65 forward matrix (linear sRGB → XYZ).
    let x_xyz = 0.4124 * r + 0.3576 * g + 0.1805 * b;
    let y_xyz = 0.2126 * r + 0.7152 * g + 0.0722 * b;
    let z_xyz = 0.0193 * r + 0.1192 * g + 0.9505 * b;
    let sum = x_xyz + y_xyz + z_xyz;
    if sum < 1e-6 {
        return (0, 0);
    }
    let x = (x_xyz / sum) * 0xFEFF as f32;
    let y = (y_xyz / sum) * 0xFEFF as f32;
    (
        x.clamp(0.0, 0xFEFF as f32) as u16,
        y.clamp(0.0, 0xFEFF as f32) as u16,
    )
}

/// Linear sRGB → enhanced hue + saturation (V is discarded — the
/// returned values describe the chromaticity at full brightness).
fn linear_rgb_to_hue_saturation(r: f32, g: f32, b: f32) -> (u16, u8) {
    let max_c = r.max(g).max(b);
    let min_c = r.min(g).min(b);
    let delta = max_c - min_c;
    if delta < 1e-6 {
        return (0, 0);
    }
    // (g-b)/delta ∈ [-1, 1] when r is the max channel; fold the
    // negative half into [0, 6) without f32 `%`.
    let h6 = if (max_c - r).abs() < 1e-6 {
        let v = (g - b) / delta;
        if v < 0.0 {
            v + 6.0
        } else {
            v
        }
    } else if (max_c - g).abs() < 1e-6 {
        (b - r) / delta + 2.0
    } else {
        (r - g) / delta + 4.0
    };
    // h6 ∈ [0, 6]; only the boundary h6 == 6.0 needs wrapping.
    let h_deg = if h6 >= 6.0 { 0.0 } else { h6 * 60.0 };
    let s = if max_c > 0.0 { delta / max_c } else { 0.0 };
    let enhanced_hue = (h_deg * 65536.0 / 360.0).clamp(0.0, 65535.0) as u16;
    let saturation = (s * 254.0 + 0.5).clamp(0.0, 254.0) as u8;
    (enhanced_hue, saturation)
}

/// Colour temperature in mireds → CIE xy on the Planckian locus
/// (Krystek 1985 approximation via CIE 1960 UCS).
#[allow(clippy::excessive_precision)]
fn ct_mireds_to_xy_f32_pair(mireds: u16) -> (u16, u16) {
    if mireds == 0 {
        return (0, 0);
    }
    let t = 1_000_000.0_f32 / mireds as f32;
    let t2 = t * t;
    let u = (0.860117757 + 1.54118254e-4 * t + 1.28641212e-7 * t2)
        / (1.0 + 8.42420235e-4 * t + 7.08145163e-7 * t2);
    let v = (0.317398726 + 4.22806245e-5 * t + 4.20481691e-8 * t2)
        / (1.0 - 2.89741816e-5 * t + 1.61456053e-7 * t2);
    let denom = 2.0 * u - 8.0 * v + 4.0;
    if denom.abs() < 1e-6 {
        return (0, 0);
    }
    let x = (3.0 * u / denom) * 0xFEFF as f32;
    let y = (2.0 * v / denom) * 0xFEFF as f32;
    (
        x.clamp(0.0, 0xFEFF as f32) as u16,
        y.clamp(0.0, 0xFEFF as f32) as u16,
    )
}

/// Device-supplied bindings for the Color Control cluster.
///
/// The cluster owns and persists all attribute state internally; the
/// hooks only need to (a) describe the device's static capabilities
/// (features + physical CT bounds) and (b) push the current colour
/// onto the hardware via [`Self::set_device_color`]. Optionally,
/// devices that persist `StartUpColorTemperatureMireds` across
/// reboots can override the two persistence hooks.
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

    /// Drive the device to the requested colour. Called by the
    /// cluster on every colour-mutation step (commands, transitions,
    /// the colour loop, and scene recall). `Err(())` surfaces as
    /// `Failure`.
    #[allow(clippy::result_unit_err)]
    fn set_device_color(&self, target: SetDeviceColor) -> Result<(), ()>;

    /// Optional read for the spec-mandated non-volatile
    /// `StartUpColorTemperatureMireds`. Devices that don't persist
    /// it leave the default which reports `AttributeNotFound`.
    fn start_up_color_temperature_mireds(&self) -> Result<Nullable<u16>, Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    fn set_start_up_color_temperature_mireds(&self, _value: Nullable<u16>) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

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

    fn set_device_color(&self, target: SetDeviceColor) -> Result<(), ()> {
        (*self).set_device_color(target)
    }

    fn start_up_color_temperature_mireds(&self) -> Result<Nullable<u16>, Error> {
        (*self).start_up_color_temperature_mireds()
    }

    fn set_start_up_color_temperature_mireds(&self, value: Nullable<u16>) -> Result<(), Error> {
        (*self).set_start_up_color_temperature_mireds(value)
    }

    fn run<F: Fn(OutOfBandMessage)>(&self, notify: F) -> impl Future<Output = ()> {
        (*self).run(notify)
    }
}

/// Internal task variants driving the transition pipeline.
enum Task {
    /// Linear interpolation to a target. Either or both axes may be
    /// set. `is_enhanced` controls which attributes are notified
    /// (CurrentHue only vs CurrentHue + EnhancedCurrentHue).
    ///
    /// Hue is carried as a *signed* enhanced-units delta from the
    /// transition's start so paths like `Direction::Longest` (which
    /// walk the long way round the colour wheel) interpolate
    /// correctly — collapsing to a `target_enhanced_hue` would lose
    /// the path information after `wrapping_add`.
    HueSaturationMoveTo {
        hue_delta: Option<i32>,
        target_saturation: Option<u8>,
        transition_ms: u32,
        is_enhanced: bool,
    },
    /// Continuous hue move at a given enhanced-units/sec rate.
    HueMove {
        direction: MoveModeEnum,
        rate_enhanced_per_sec: u32,
        is_enhanced: bool,
    },
    /// Continuous saturation move at a given units/sec rate.
    SaturationMove {
        direction: MoveModeEnum,
        rate_per_sec: u32,
    },
    /// Linear interpolation to a target xy point.
    XyMoveTo {
        target_x: u16,
        target_y: u16,
        transition_ms: u32,
    },
    /// Continuous xy move at the given signed per-second rates.
    XyMove {
        rate_x_per_sec: i32,
        rate_y_per_sec: i32,
    },
    /// Linear interpolation to a target colour temperature in mireds.
    ColorTemperatureMoveTo {
        target_mireds: u16,
        transition_ms: u32,
    },
    /// Continuous colour-temperature move at the given signed
    /// mireds/sec rate, bounded by `[min_mireds, max_mireds]`.
    ColorTemperatureMove {
        rate_mireds_per_sec: i32,
        min_mireds: u16,
        max_mireds: u16,
    },
    /// Run the colour loop: rotate `EnhancedCurrentHue` around the
    /// full u16 wheel, completing one revolution every `time_secs`.
    ColorLoop {
        direction: ColorLoopDirectionEnum,
        time_secs: u16,
    },
    /// Cancel any active transition.
    Stop,
}

/// Tick interval for transition loops. Trades smoothness against
/// subscription churn — 100 ms gives ≤ 10 notifies/sec which the
/// quiet-report logic further throttles.
const TRANSITION_TICK: Duration = Duration::from_millis(100);

/// Spec maximum for `CurrentHue` (u8) and the high byte of
/// `EnhancedCurrentHue`. Values above this saturate at this cap.
const HUE_U8_MAX: u8 = 254;

/// Spec maximum for `CurrentSaturation`.
const SATURATION_MAX: u8 = 254;

/// Spec maximum for `CurrentX` / `CurrentY` (i.e., 0xFEFF).
const XY_MAX: u16 = 0xFEFF;

/// Handler-internal cluster state. Device-persisted attributes live
/// in the hooks.
/// Cluster-internal state. Owns every Matter Color Control attribute
/// value (previously exposed via hook getter/setter pairs) plus
/// transition bookkeeping. Devices only see the abstracted
/// [`SetDeviceColor`] actuator.
struct ColorControlState {
    options: OptionsBitmap,
    remaining_time: u16,
    last_hue_notification: Instant,
    last_saturation_notification: Instant,
    last_xy_notification: Instant,
    last_color_temperature_notification: Instant,
    // Current-colour attributes (mod-tracked alongside the actuator).
    enhanced_current_hue: u16,
    current_saturation: u8,
    current_x: u16,
    current_y: u16,
    color_temperature_mireds: u16,
    color_mode: ColorModeEnum,
    enhanced_color_mode: EnhancedColorModeEnum,
    // Colour-loop bookkeeping — purely cluster-internal.
    color_loop_active: bool,
    color_loop_direction: ColorLoopDirectionEnum,
    color_loop_time: u16,
    color_loop_start_enhanced_hue: u16,
    color_loop_stored_enhanced_hue: u16,
}

impl ColorControlState {
    const fn new(defaults: AttributeDefaults) -> Self {
        Self {
            options: defaults.options,
            remaining_time: 0,
            last_hue_notification: Instant::from_millis(0),
            last_saturation_notification: Instant::from_millis(0),
            last_xy_notification: Instant::from_millis(0),
            last_color_temperature_notification: Instant::from_millis(0),
            enhanced_current_hue: 0,
            current_saturation: 0,
            // Default xy chromaticity (warm-white-ish).
            current_x: 0x616B,
            current_y: 0x607D,
            color_temperature_mireds: 250,
            color_mode: ColorModeEnum::ColorTemperatureMireds,
            enhanced_color_mode: EnhancedColorModeEnum::ColorTemperatureMireds,
            color_loop_active: false,
            color_loop_direction: ColorLoopDirectionEnum::Increment,
            color_loop_time: 25,
            color_loop_start_enhanced_hue: 0x2300,
            color_loop_stored_enhanced_hue: 0,
        }
    }

    /// Mirrors LevelControl's quiet-reporting rule: notify when
    /// transitioning to/from zero, or once per second, or on a large
    /// delta at the start of a transition.
    fn write_remaining_time_quietly(
        &mut self,
        remaining: Duration,
        is_start_of_transition: bool,
    ) -> bool {
        let new_ds = remaining.as_millis().div_ceil(100) as u16;
        let prev = self.remaining_time;
        let changed_to_zero = new_ds == 0 && prev != 0;
        let changed_from_zero_gt_10 = prev == 0 && new_ds > 10;
        let changed_by_gt_10 = new_ds.abs_diff(prev) > 10 && is_start_of_transition;
        self.remaining_time = new_ds;
        changed_to_zero || changed_from_zero_gt_10 || changed_by_gt_10
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
    const fn new_internal(
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
    pub const fn new(
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
                    if self
                        .hooks
                        .set_device_color(SetDeviceColor::ColorTemperature { mireds: clamped })
                        .is_ok()
                    {
                        self.with_state(|s| {
                            s.color_temperature_mireds = clamped;
                            s.color_mode = ColorModeEnum::ColorTemperatureMireds;
                            s.enhanced_color_mode = EnhancedColorModeEnum::ColorTemperatureMireds;
                        });
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
        self.with_state(|s| s.current_x = x);
        self.with_state(|s| s.current_y = y);
        self.with_state(|s| s.color_mode = ColorModeEnum::CurrentXAndCurrentY);
        self.with_state(|s| s.enhanced_color_mode = EnhancedColorModeEnum::CurrentXAndCurrentY);

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
        self.with_state(|s| s.color_temperature_mireds = mireds);
        self.with_state(|s| s.color_mode = ColorModeEnum::ColorTemperatureMireds);
        self.with_state(|s| s.enhanced_color_mode = EnhancedColorModeEnum::ColorTemperatureMireds);

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
        self.with_state(|s| s.enhanced_current_hue = (hue_u8 as u16) << 8);
        self.with_state(|s| s.current_saturation = saturation);
        self.with_state(|s| s.color_mode = ColorModeEnum::CurrentHueAndCurrentSaturation);
        self.with_state(|s| {
            s.enhanced_color_mode = EnhancedColorModeEnum::CurrentHueAndCurrentSaturation
        });

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
        self.with_state(|s| s.enhanced_current_hue = enhanced_hue);
        self.with_state(|s| s.current_saturation = saturation);
        // Non-enhanced ColorMode mirrors to the closest non-enhanced equivalent.
        self.with_state(|s| s.color_mode = ColorModeEnum::CurrentHueAndCurrentSaturation);
        self.with_state(|s| {
            s.enhanced_color_mode = EnhancedColorModeEnum::EnhancedCurrentHueAndCurrentSaturation
        });

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
        self.with_state(|s| s.color_loop_active = true);
        self.with_state(|s| s.color_loop_direction = direction);
        self.with_state(|s| s.color_loop_time = time);

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

// ---- Command-driven mutation helpers + transition pipeline ----

impl<'a, H: ColorControlHooks, OH: OnOffHooks, LH: LevelControlHooks>
    ColorControlHandler<'a, H, OH, LH>
{
    fn cluster_id() -> ClusterId {
        H::CLUSTER.id
    }

    /// Apply Options/OptionsMask/OptionsOverride to decide whether a
    /// command should execute when the coupled OnOff cluster is off.
    fn should_continue(
        &self,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> bool {
        let Some(on_off_handler) = self.on_off_handler.lock(|h| h.get()) else {
            return true;
        };

        if on_off_handler.on_off() {
            return true;
        }

        // OptionsMask bit set → consult OptionsOverride; else consult Options attribute.
        if options_mask.contains(OptionsBitmap::EXECUTE_IF_OFF) {
            options_override.contains(OptionsBitmap::EXECUTE_IF_OFF)
        } else {
            self.with_state(|s| s.options.contains(OptionsBitmap::EXECUTE_IF_OFF))
        }
    }

    /// Compute the signed delta required to walk from `current` to
    /// `target` on the u16 colour wheel honouring `direction`.
    /// Returns total enhanced-units delta as a signed i32 so the
    /// transition loop can integer-step.
    fn hue_path_delta(current: u16, target: u16, direction: DirectionEnum) -> i32 {
        let cur = current as i32;
        let tgt = target as i32;
        let up_distance = ((tgt - cur).rem_euclid(0x10000)) as u32; // 0..65535
        let down_distance = ((cur - tgt).rem_euclid(0x10000)) as u32;

        match direction {
            DirectionEnum::Up => up_distance as i32,
            DirectionEnum::Down => -(down_distance as i32),
            DirectionEnum::Shortest => {
                if up_distance <= down_distance {
                    up_distance as i32
                } else {
                    -(down_distance as i32)
                }
            }
            DirectionEnum::Longest => {
                if up_distance > down_distance {
                    up_distance as i32
                } else {
                    -(down_distance as i32)
                }
            }
        }
    }

    /// Update `EnhancedCurrentHue` and notify, with quiet reporting.
    /// `is_enhanced=true` notifies both `EnhancedCurrentHue` and
    /// `CurrentHue`; false notifies only `CurrentHue`.
    fn set_hue<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        new_eh: u16,
        is_end_of_transition: bool,
        is_enhanced: bool,
    ) {
        let prev_eh = self.with_state(|s| s.enhanced_current_hue);
        if prev_eh == new_eh && !is_end_of_transition {
            return;
        }

        self.with_state(|s| s.enhanced_current_hue = new_eh);
        self.with_state(|s| s.color_mode = ColorModeEnum::CurrentHueAndCurrentSaturation);
        let enhanced_mode = if is_enhanced {
            EnhancedColorModeEnum::EnhancedCurrentHueAndCurrentSaturation
        } else {
            EnhancedColorModeEnum::CurrentHueAndCurrentSaturation
        };
        self.with_state(|s| s.enhanced_color_mode = enhanced_mode);

        let should_notify = self.with_state(|s| {
            let now = Instant::now();
            let elapsed = now - s.last_hue_notification;
            if is_end_of_transition || elapsed >= Duration::from_secs(1) {
                s.last_hue_notification = now;
                true
            } else {
                false
            }
        });

        if should_notify {
            let cluster_id = Self::cluster_id();

            ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::CurrentHue as _);
            if is_enhanced {
                ctx.notify_attr_changed(
                    self.endpoint_id,
                    cluster_id,
                    AttributeId::EnhancedCurrentHue as _,
                );
            }
            ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::ColorMode as _);
            ctx.notify_attr_changed(
                self.endpoint_id,
                cluster_id,
                AttributeId::EnhancedColorMode as _,
            );
        }

        self.notify_scenable_changed();
    }

    /// Update `CurrentSaturation` and notify, with quiet reporting.
    fn set_saturation<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        new_sat: u8,
        is_end_of_transition: bool,
    ) {
        let prev = self.with_state(|s| s.current_saturation);
        if prev == new_sat && !is_end_of_transition {
            return;
        }

        self.with_state(|s| s.current_saturation = new_sat);
        self.with_state(|s| s.color_mode = ColorModeEnum::CurrentHueAndCurrentSaturation);

        // EnhancedColorMode: keep enhanced variant if already enhanced.
        let current_emode = self.with_state(|s| s.enhanced_color_mode);
        if !matches!(
            current_emode,
            EnhancedColorModeEnum::CurrentHueAndCurrentSaturation
                | EnhancedColorModeEnum::EnhancedCurrentHueAndCurrentSaturation
        ) {
            self.with_state(|s| {
                s.enhanced_color_mode = EnhancedColorModeEnum::CurrentHueAndCurrentSaturation
            });
        }

        let should_notify = self.with_state(|s| {
            let now = Instant::now();
            let elapsed = now - s.last_saturation_notification;
            if is_end_of_transition || elapsed >= Duration::from_secs(1) {
                s.last_saturation_notification = now;
                true
            } else {
                false
            }
        });

        if should_notify {
            let cluster_id = Self::cluster_id();

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
        }

        self.notify_scenable_changed();
    }

    /// Push the latest enhanced hue + saturation values to the device.
    /// Logs but does not propagate errors.
    fn drive_device_hue_saturation(&self) {
        let (enhanced_hue, saturation) =
            self.with_state(|s| (s.enhanced_current_hue, s.current_saturation));
        if self
            .hooks
            .set_device_color(SetDeviceColor::HueSaturation {
                enhanced_hue,
                saturation,
            })
            .is_err()
        {
            warn!("set_device_color (hue/saturation) failed");
        }
    }

    /// Linear interpolation along a signed hue delta and/or to a
    /// saturation target over `transition_ms`. The hue path is
    /// `start + delta * progress`, mod u16 — preserving long-way-
    /// round travel for `Direction::Longest`.
    async fn move_to_hue_saturation_transition(
        &self,
        ctx: &impl HandlerContext,
        hue_delta: Option<i32>,
        target_saturation: Option<u8>,
        transition_ms: u32,
        is_enhanced: bool,
    ) -> Result<(), Error> {
        let start_eh = self.with_state(|s| s.enhanced_current_hue);
        let start_sat = self.with_state(|s| s.current_saturation);

        let hue_delta_total: i32 = hue_delta.unwrap_or(0);
        let sat_delta_total: i32 = target_saturation
            .map(|t| t as i32 - start_sat as i32)
            .unwrap_or(0);

        // Initial RemainingTime (deciseconds).
        let total = Duration::from_millis(transition_ms as u64);
        let start_time = Instant::now();

        if self.with_state(|s| s.write_remaining_time_quietly(total, true)) {
            ctx.notify_attr_changed(
                self.endpoint_id,
                Self::cluster_id(),
                AttributeId::RemainingTime as _,
            );
        }

        let final_eh = ((start_eh as i64 + hue_delta_total as i64).rem_euclid(0x10000)) as u16;

        if transition_ms == 0 || (hue_delta_total == 0 && sat_delta_total == 0) {
            if hue_delta.is_some() {
                self.set_hue(ctx, final_eh, true, is_enhanced);
            }

            if let Some(t) = target_saturation {
                self.set_saturation(ctx, t, true);
            }

            self.drive_device_hue_saturation();

            let notify_rt = self
                .with_state(|s| s.write_remaining_time_quietly(Duration::from_millis(0), false));
            if notify_rt {
                ctx.notify_attr_changed(
                    self.endpoint_id,
                    Self::cluster_id(),
                    AttributeId::RemainingTime as _,
                );
            }

            return Ok(());
        }

        loop {
            let elapsed_ms = (Instant::now() - start_time).as_millis();
            let progress_milli = (elapsed_ms.saturating_mul(1000) / transition_ms as u64).min(1000);
            let is_end = progress_milli >= 1000;

            if hue_delta.is_some() {
                let delta_now = (hue_delta_total as i64) * progress_milli as i64 / 1000;
                let new_eh = ((start_eh as i64 + delta_now).rem_euclid(0x10000)) as u16;
                let cur_eh = if is_end { final_eh } else { new_eh };
                self.set_hue(ctx, cur_eh, is_end, is_enhanced);
            }

            if let Some(t) = target_saturation {
                let delta_now = ((sat_delta_total as i64) * progress_milli as i64 / 1000) as i32;
                let new_sat = (start_sat as i32 + delta_now).clamp(0, SATURATION_MAX as i32) as u8;
                let final_sat = if is_end { t } else { new_sat };
                self.set_saturation(ctx, final_sat, is_end);
            }

            self.drive_device_hue_saturation();

            // Update RemainingTime.
            let remaining = if is_end {
                Duration::from_millis(0)
            } else {
                Duration::from_millis(transition_ms as u64 - elapsed_ms)
            };

            let notify_rt = self.with_state(|s| s.write_remaining_time_quietly(remaining, false));
            if notify_rt {
                ctx.notify_attr_changed(
                    self.endpoint_id,
                    Self::cluster_id(),
                    AttributeId::RemainingTime as _,
                );
            }

            if is_end {
                return Ok(());
            }

            // Sleep at most until the transition's end so the final
            // tick fires at `transition_ms` exactly. Without this cap
            // the loop would overshoot by up to `TRANSITION_TICK` and
            // a read that lands during the slop sees a pre-final value.
            let remaining_ms = (transition_ms as u64).saturating_sub(elapsed_ms);
            let wait = TRANSITION_TICK.min(Duration::from_millis(remaining_ms));

            Timer::after(wait).await;
        }
    }

    /// Continuous hue move at the given enhanced-units/sec rate.
    /// Wraps around the u16 colour wheel and stops only on a `Stop`
    /// task (or natural cancellation by a new signal).
    async fn hue_move_transition(
        &self,
        ctx: &impl HandlerContext,
        direction: MoveModeEnum,
        rate_enhanced_per_sec: u32,
        is_enhanced: bool,
    ) -> Result<(), Error> {
        if rate_enhanced_per_sec == 0 {
            return Ok(());
        }

        // Position is derived from elapsed time (rather than
        // accumulating per-tick deltas) so the effective rate matches
        // the requested `rate_per_sec` regardless of tick granularity.
        let start_eh = self.with_state(|s| s.enhanced_current_hue);
        let start_time = Instant::now();
        let signed_rate: i64 = match direction {
            MoveModeEnum::Up => rate_enhanced_per_sec as i64,
            MoveModeEnum::Down => -(rate_enhanced_per_sec as i64),
            _ => return Ok(()),
        };

        loop {
            let elapsed_ms = (Instant::now() - start_time).as_millis() as i64;
            let delta = signed_rate * elapsed_ms / 1000;
            let new_eh = ((start_eh as i64 + delta).rem_euclid(0x10000)) as u16;

            self.set_hue(ctx, new_eh, false, is_enhanced);
            self.drive_device_hue_saturation();

            Timer::after(TRANSITION_TICK).await;
        }
    }

    /// Continuous saturation move at the given units/sec rate.
    /// Saturates at `[0, 254]` and terminates when the bound is hit.
    async fn saturation_move_transition(
        &self,
        ctx: &impl HandlerContext,
        direction: MoveModeEnum,
        rate_per_sec: u32,
    ) -> Result<(), Error> {
        if rate_per_sec == 0 {
            return Ok(());
        }

        let start_sat = self.with_state(|s| s.current_saturation);
        let start_time = Instant::now();
        let signed_rate: i64 = match direction {
            MoveModeEnum::Up => rate_per_sec as i64,
            MoveModeEnum::Down => -(rate_per_sec as i64),
            _ => return Ok(()),
        };

        loop {
            let elapsed_ms = (Instant::now() - start_time).as_millis() as i64;
            let delta = signed_rate * elapsed_ms / 1000;
            let new_sat = (start_sat as i64 + delta).clamp(0, SATURATION_MAX as i64) as u8;
            let is_end =
                (signed_rate > 0 && new_sat == SATURATION_MAX) || (signed_rate < 0 && new_sat == 0);

            self.set_saturation(ctx, new_sat, is_end);
            self.drive_device_hue_saturation();

            if is_end {
                return Ok(());
            }

            Timer::after(TRANSITION_TICK).await;
        }
    }

    /// Update `CurrentX` / `CurrentY` and the colour-mode mirror,
    /// then notify with quiet reporting.
    fn set_xy<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        new_x: u16,
        new_y: u16,
        is_end_of_transition: bool,
    ) {
        let prev_x = self.with_state(|s| s.current_x);
        let prev_y = self.with_state(|s| s.current_y);

        if prev_x == new_x && prev_y == new_y && !is_end_of_transition {
            return;
        }

        self.with_state(|s| s.current_x = new_x);
        self.with_state(|s| s.current_y = new_y);
        self.with_state(|s| s.color_mode = ColorModeEnum::CurrentXAndCurrentY);
        self.with_state(|s| s.enhanced_color_mode = EnhancedColorModeEnum::CurrentXAndCurrentY);

        let should_notify = self.with_state(|s| {
            let now = Instant::now();
            let elapsed = now - s.last_xy_notification;

            if is_end_of_transition || elapsed >= Duration::from_secs(1) {
                s.last_xy_notification = now;
                true
            } else {
                false
            }
        });

        if should_notify {
            let cluster_id = Self::cluster_id();

            ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::CurrentX as _);
            ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::CurrentY as _);
            ctx.notify_attr_changed(self.endpoint_id, cluster_id, AttributeId::ColorMode as _);
            ctx.notify_attr_changed(
                self.endpoint_id,
                cluster_id,
                AttributeId::EnhancedColorMode as _,
            );
        }

        self.notify_scenable_changed();
    }

    /// Drive the device with the latest xy values.
    fn drive_device_xy(&self) {
        let (x, y) = self.with_state(|s| (s.current_x, s.current_y));

        if self
            .hooks
            .set_device_color(SetDeviceColor::Xy { x, y })
            .is_err()
        {
            warn!("set_device_color (xy) failed");
        }
    }

    /// Update `ColorTemperatureMireds` and the colour-mode mirror,
    /// then notify with quiet reporting.
    fn set_color_temperature<N: AttrChangeNotifier>(
        &self,
        ctx: &N,
        new_mireds: u16,
        is_end_of_transition: bool,
    ) {
        let prev = self.with_state(|s| s.color_temperature_mireds);

        if prev == new_mireds && !is_end_of_transition {
            return;
        }

        self.with_state(|s| s.color_temperature_mireds = new_mireds);
        self.with_state(|s| s.color_mode = ColorModeEnum::ColorTemperatureMireds);
        self.with_state(|s| s.enhanced_color_mode = EnhancedColorModeEnum::ColorTemperatureMireds);

        let should_notify = self.with_state(|s| {
            let now = Instant::now();
            let elapsed = now - s.last_color_temperature_notification;
            if is_end_of_transition || elapsed >= Duration::from_secs(1) {
                s.last_color_temperature_notification = now;
                true
            } else {
                false
            }
        });

        if should_notify {
            let cluster_id = Self::cluster_id();

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
        }

        self.notify_scenable_changed();
    }

    /// Drive the device with the latest colour-temperature value.
    fn drive_device_color_temperature(&self) {
        let mireds = self.with_state(|s| s.color_temperature_mireds);

        if self
            .hooks
            .set_device_color(SetDeviceColor::ColorTemperature { mireds })
            .is_err()
        {
            warn!("set_device_color (mireds) failed");
        }
    }

    /// Linear interpolation to a target xy point.
    async fn move_to_xy_transition(
        &self,
        ctx: &impl HandlerContext,
        target_x: u16,
        target_y: u16,
        transition_ms: u32,
    ) -> Result<(), Error> {
        let start_x = self.with_state(|s| s.current_x) as i32;
        let start_y = self.with_state(|s| s.current_y) as i32;
        let dx = target_x as i32 - start_x;
        let dy = target_y as i32 - start_y;

        let total = Duration::from_millis(transition_ms as u64);
        let start_time = Instant::now();

        if self.with_state(|s| s.write_remaining_time_quietly(total, true)) {
            ctx.notify_attr_changed(
                self.endpoint_id,
                Self::cluster_id(),
                AttributeId::RemainingTime as _,
            );
        }

        if transition_ms == 0 || (dx == 0 && dy == 0) {
            self.set_xy(ctx, target_x, target_y, true);

            self.drive_device_xy();

            let notify_rt = self
                .with_state(|s| s.write_remaining_time_quietly(Duration::from_millis(0), false));
            if notify_rt {
                ctx.notify_attr_changed(
                    self.endpoint_id,
                    Self::cluster_id(),
                    AttributeId::RemainingTime as _,
                );
            }

            return Ok(());
        }

        loop {
            let elapsed_ms = (Instant::now() - start_time).as_millis();
            let progress = (elapsed_ms.saturating_mul(1000) / transition_ms as u64).min(1000);
            let is_end = progress >= 1000;

            let cur_x = if is_end {
                target_x
            } else {
                (start_x + (dx as i64 * progress as i64 / 1000) as i32).clamp(0, XY_MAX as i32)
                    as u16
            };

            let cur_y = if is_end {
                target_y
            } else {
                (start_y + (dy as i64 * progress as i64 / 1000) as i32).clamp(0, XY_MAX as i32)
                    as u16
            };

            self.set_xy(ctx, cur_x, cur_y, is_end);

            self.drive_device_xy();

            let remaining = if is_end {
                Duration::from_millis(0)
            } else {
                Duration::from_millis(transition_ms as u64 - elapsed_ms)
            };

            let notify_rt = self.with_state(|s| s.write_remaining_time_quietly(remaining, false));
            if notify_rt {
                ctx.notify_attr_changed(
                    self.endpoint_id,
                    Self::cluster_id(),
                    AttributeId::RemainingTime as _,
                );
            }

            if is_end {
                return Ok(());
            }

            let remaining_ms = (transition_ms as u64).saturating_sub(elapsed_ms);
            let wait = TRANSITION_TICK.min(Duration::from_millis(remaining_ms));

            Timer::after(wait).await;
        }
    }

    /// Continuous xy move at signed per-second rates. Stops naturally
    /// when both axes hit their bounds (or stay clamped against them).
    async fn xy_move_transition(
        &self,
        ctx: &impl HandlerContext,
        rate_x: i32,
        rate_y: i32,
    ) -> Result<(), Error> {
        if rate_x == 0 && rate_y == 0 {
            return Ok(());
        }

        let start_x = self.with_state(|s| s.current_x) as i64;
        let start_y = self.with_state(|s| s.current_y) as i64;
        let start_time = Instant::now();

        loop {
            let elapsed_ms = (Instant::now() - start_time).as_millis() as i64;

            let delta_x = rate_x as i64 * elapsed_ms / 1000;
            let delta_y = rate_y as i64 * elapsed_ms / 1000;

            let new_x = (start_x + delta_x).clamp(0, XY_MAX as i64) as u16;
            let new_y = (start_y + delta_y).clamp(0, XY_MAX as i64) as u16;

            let x_pinned = (rate_x > 0 && new_x == XY_MAX) || (rate_x < 0 && new_x == 0);
            let y_pinned = (rate_y > 0 && new_y == XY_MAX) || (rate_y < 0 && new_y == 0);

            let x_done = rate_x == 0 || x_pinned;
            let y_done = rate_y == 0 || y_pinned;

            let is_end = x_done && y_done;

            self.set_xy(ctx, new_x, new_y, is_end);

            self.drive_device_xy();

            if is_end {
                return Ok(());
            }

            Timer::after(TRANSITION_TICK).await;
        }
    }

    /// Linear interpolation to a target colour temperature in mireds.
    async fn move_to_color_temperature_transition(
        &self,
        ctx: &impl HandlerContext,
        target_mireds: u16,
        transition_ms: u32,
    ) -> Result<(), Error> {
        let target = target_mireds.clamp(
            H::COLOR_TEMP_PHYSICAL_MIN_MIREDS,
            H::COLOR_TEMP_PHYSICAL_MAX_MIREDS,
        );

        let start = self.with_state(|s| s.color_temperature_mireds) as i32;
        let delta = target as i32 - start;

        let total = Duration::from_millis(transition_ms as u64);
        let start_time = Instant::now();

        if self.with_state(|s| s.write_remaining_time_quietly(total, true)) {
            ctx.notify_attr_changed(
                self.endpoint_id,
                Self::cluster_id(),
                AttributeId::RemainingTime as _,
            );
        }

        if transition_ms == 0 || delta == 0 {
            self.set_color_temperature(ctx, target, true);
            self.drive_device_color_temperature();

            let notify_rt = self
                .with_state(|s| s.write_remaining_time_quietly(Duration::from_millis(0), false));
            if notify_rt {
                ctx.notify_attr_changed(
                    self.endpoint_id,
                    Self::cluster_id(),
                    AttributeId::RemainingTime as _,
                );
            }

            return Ok(());
        }

        loop {
            let elapsed_ms = (Instant::now() - start_time).as_millis();
            let progress = (elapsed_ms.saturating_mul(1000) / transition_ms as u64).min(1000);
            let is_end = progress >= 1000;

            let value = if is_end {
                target
            } else {
                (start + (delta as i64 * progress as i64 / 1000) as i32).clamp(
                    H::COLOR_TEMP_PHYSICAL_MIN_MIREDS as i32,
                    H::COLOR_TEMP_PHYSICAL_MAX_MIREDS as i32,
                ) as u16
            };

            self.set_color_temperature(ctx, value, is_end);
            self.drive_device_color_temperature();

            let remaining = if is_end {
                Duration::from_millis(0)
            } else {
                Duration::from_millis(transition_ms as u64 - elapsed_ms)
            };

            let notify_rt = self.with_state(|s| s.write_remaining_time_quietly(remaining, false));
            if notify_rt {
                ctx.notify_attr_changed(
                    self.endpoint_id,
                    Self::cluster_id(),
                    AttributeId::RemainingTime as _,
                );
            }

            if is_end {
                return Ok(());
            }

            let remaining_ms = (transition_ms as u64).saturating_sub(elapsed_ms);
            let wait = TRANSITION_TICK.min(Duration::from_millis(remaining_ms));

            Timer::after(wait).await;
        }
    }

    /// Continuous colour-temperature move, bounded by command-supplied
    /// `[min_mireds, max_mireds]` (further clamped by the device's
    /// physical bounds).
    async fn color_temperature_move_transition(
        &self,
        ctx: &impl HandlerContext,
        rate_per_sec: i32,
        min_mireds: u16,
        max_mireds: u16,
    ) -> Result<(), Error> {
        if rate_per_sec == 0 {
            return Ok(());
        }

        let lo = min_mireds.max(H::COLOR_TEMP_PHYSICAL_MIN_MIREDS);
        let hi = max_mireds.min(H::COLOR_TEMP_PHYSICAL_MAX_MIREDS);

        if lo >= hi {
            return Ok(());
        }

        let start_mireds = self.with_state(|s| s.color_temperature_mireds) as i64;
        let start_time = Instant::now();

        loop {
            let elapsed_ms = (Instant::now() - start_time).as_millis() as i64;
            let delta = rate_per_sec as i64 * elapsed_ms / 1000;
            let new_mireds = (start_mireds + delta).clamp(lo as i64, hi as i64) as u16;
            let pinned =
                (rate_per_sec > 0 && new_mireds == hi) || (rate_per_sec < 0 && new_mireds == lo);

            self.set_color_temperature(ctx, new_mireds, pinned);
            self.drive_device_color_temperature();

            if pinned {
                return Ok(());
            }

            Timer::after(TRANSITION_TICK).await;
        }
    }

    /// Colour-loop tick: rotate `EnhancedCurrentHue` around the
    /// full u16 wheel, completing exactly one revolution per
    /// `time_secs` seconds. Position is derived from elapsed time
    /// with a "snap" when within `SNAP_HUE_UNITS` of the wrap (so
    /// timer jitter near the wrap moment can't show a value just
    /// shy of the start hue). Runs forever; cancelled by a new
    /// task signal.
    async fn color_loop_transition(
        &self,
        ctx: &impl HandlerContext,
        direction: ColorLoopDirectionEnum,
        time_secs: u16,
    ) -> Result<(), Error> {
        // Snap zone (hue units) around each revolution boundary —
        // chip-tool tests use 15% tolerance on intra-revolution
        // reads, so ~0.5% near the wrap is well within the test
        // budget and large enough to absorb scheduling jitter.
        const SNAP_HUE_UNITS: i64 = 384;

        let time_secs = if time_secs == 0 { 25 } else { time_secs };
        let total_ms = time_secs as u64 * 1000;

        let start_eh = self.with_state(|s| s.enhanced_current_hue);
        let start_time = Instant::now();

        let signed_rate: i64 = match direction {
            ColorLoopDirectionEnum::Increment => 0x10000,
            ColorLoopDirectionEnum::Decrement => -0x10000,
        };

        loop {
            let elapsed_ms = (Instant::now() - start_time).as_millis();
            let raw_delta = signed_rate * elapsed_ms as i64 / total_ms as i64;

            // Snap to the nearest revolution boundary when within
            // SNAP_HUE_UNITS of it (either side).
            let abs = raw_delta.unsigned_abs() as i64;
            let rem_mod = abs % 0x10000;

            let snapped_delta = if rem_mod >= 0x10000 - SNAP_HUE_UNITS {
                raw_delta + signed_rate.signum() * (0x10000 - rem_mod)
            } else if rem_mod <= SNAP_HUE_UNITS && abs >= 0x10000 {
                raw_delta - signed_rate.signum() * rem_mod
            } else {
                raw_delta
            };

            let new_eh = ((start_eh as i64 + snapped_delta).rem_euclid(0x10000)) as u16;

            self.set_hue(ctx, new_eh, false, true);
            self.drive_device_hue_saturation();

            // Sleep until either the next periodic tick or the next
            // revolution boundary, whichever comes sooner.
            let revs = elapsed_ms / total_ms;
            let next_boundary_ms = (revs + 1) * total_ms;
            let to_boundary = next_boundary_ms.saturating_sub(elapsed_ms);
            let wait = TRANSITION_TICK.min(Duration::from_millis(to_boundary));

            Timer::after(wait).await;
        }
    }

    async fn task_manager(&self, ctx: &impl HandlerContext, task: Task) {
        match task {
            Task::HueSaturationMoveTo {
                hue_delta,
                target_saturation,
                transition_ms,
                is_enhanced,
            } => {
                if let Err(e) = self
                    .move_to_hue_saturation_transition(
                        ctx,
                        hue_delta,
                        target_saturation,
                        transition_ms,
                        is_enhanced,
                    )
                    .await
                {
                    error!("HueSaturationMoveTo: {:?}", e);
                }
            }
            Task::HueMove {
                direction,
                rate_enhanced_per_sec,
                is_enhanced,
            } => {
                if let Err(e) = self
                    .hue_move_transition(ctx, direction, rate_enhanced_per_sec, is_enhanced)
                    .await
                {
                    error!("HueMove: {:?}", e);
                }
            }
            Task::SaturationMove {
                direction,
                rate_per_sec,
            } => {
                if let Err(e) = self
                    .saturation_move_transition(ctx, direction, rate_per_sec)
                    .await
                {
                    error!("SaturationMove: {:?}", e);
                }
            }
            Task::XyMoveTo {
                target_x,
                target_y,
                transition_ms,
            } => {
                if let Err(e) = self
                    .move_to_xy_transition(ctx, target_x, target_y, transition_ms)
                    .await
                {
                    error!("XyMoveTo: {:?}", e);
                }
            }
            Task::XyMove {
                rate_x_per_sec,
                rate_y_per_sec,
            } => {
                if let Err(e) = self
                    .xy_move_transition(ctx, rate_x_per_sec, rate_y_per_sec)
                    .await
                {
                    error!("XyMove: {:?}", e);
                }
            }
            Task::ColorTemperatureMoveTo {
                target_mireds,
                transition_ms,
            } => {
                if let Err(e) = self
                    .move_to_color_temperature_transition(ctx, target_mireds, transition_ms)
                    .await
                {
                    error!("ColorTemperatureMoveTo: {:?}", e);
                }
            }
            Task::ColorTemperatureMove {
                rate_mireds_per_sec,
                min_mireds,
                max_mireds,
            } => {
                if let Err(e) = self
                    .color_temperature_move_transition(
                        ctx,
                        rate_mireds_per_sec,
                        min_mireds,
                        max_mireds,
                    )
                    .await
                {
                    error!("ColorTemperatureMove: {:?}", e);
                }
            }
            Task::ColorLoop {
                direction,
                time_secs,
            } => {
                if let Err(e) = self.color_loop_transition(ctx, direction, time_secs).await {
                    error!("ColorLoop: {:?}", e);
                }
            }
            Task::Stop => {
                let notify_rt = self.with_state(|s| {
                    s.write_remaining_time_quietly(Duration::from_millis(0), false)
                });
                if notify_rt {
                    ctx.notify_attr_changed(
                        self.endpoint_id,
                        Self::cluster_id(),
                        AttributeId::RemainingTime as _,
                    );
                }
            }
        }
    }

    // ---- Command entry points (validation + task signalling) ----

    fn cmd_move_to_hue(
        &self,
        hue: u8,
        direction: DirectionEnum,
        transition_time_ds: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if hue > HUE_U8_MAX {
            return Err(ErrorCode::ConstraintError.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        let current_eh = self.with_state(|s| s.enhanced_current_hue);
        let target_eh = (hue as u16) << 8;
        let delta = Self::hue_path_delta(current_eh, target_eh, direction);

        self.task_signal.signal(Task::HueSaturationMoveTo {
            hue_delta: Some(delta),
            target_saturation: None,
            transition_ms: transition_time_ds as u32 * 100,
            is_enhanced: false,
        });

        Ok(())
    }

    fn cmd_enhanced_move_to_hue(
        &self,
        enhanced_hue: u16,
        direction: DirectionEnum,
        transition_time_ds: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        let current_eh = self.with_state(|s| s.enhanced_current_hue);
        let delta = Self::hue_path_delta(current_eh, enhanced_hue, direction);

        self.task_signal.signal(Task::HueSaturationMoveTo {
            hue_delta: Some(delta),
            target_saturation: None,
            transition_ms: transition_time_ds as u32 * 100,
            is_enhanced: true,
        });

        Ok(())
    }

    fn cmd_move_hue(
        &self,
        move_mode: MoveModeEnum,
        rate: u8,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
        is_enhanced: bool,
    ) -> Result<(), Error> {
        if matches!(move_mode, MoveModeEnum::Stop) {
            self.task_signal.signal(Task::Stop);
            return Ok(());
        }

        if rate == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        // For the non-enhanced command, `rate` is in u8 hue units/sec
        // — multiply by 256 to land in enhanced units/sec.
        let rate_eh_per_sec = if is_enhanced {
            rate as u32
        } else {
            (rate as u32) * 256
        };

        self.task_signal.signal(Task::HueMove {
            direction: move_mode,
            rate_enhanced_per_sec: rate_eh_per_sec,
            is_enhanced,
        });

        Ok(())
    }

    fn cmd_enhanced_move_hue(
        &self,
        move_mode: MoveModeEnum,
        rate: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if matches!(move_mode, MoveModeEnum::Stop) {
            self.task_signal.signal(Task::Stop);
            return Ok(());
        }

        if rate == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        self.task_signal.signal(Task::HueMove {
            direction: move_mode,
            rate_enhanced_per_sec: rate as u32,
            is_enhanced: true,
        });

        Ok(())
    }

    fn cmd_step_hue(
        &self,
        step_mode: StepModeEnum,
        step_size: u8,
        transition_time_ds: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if step_size == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        let _ = self.with_state(|s| s.enhanced_current_hue);

        let signed_step: i32 = match step_mode {
            StepModeEnum::Up => (step_size as i32) << 8,
            StepModeEnum::Down => -((step_size as i32) << 8),
        };

        self.task_signal.signal(Task::HueSaturationMoveTo {
            hue_delta: Some(signed_step),
            target_saturation: None,
            transition_ms: transition_time_ds as u32 * 100,
            is_enhanced: false,
        });

        Ok(())
    }

    fn cmd_enhanced_step_hue(
        &self,
        step_mode: StepModeEnum,
        step_size: u16,
        transition_time_ds: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if step_size == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        let signed_step: i32 = match step_mode {
            StepModeEnum::Up => step_size as i32,
            StepModeEnum::Down => -(step_size as i32),
        };

        self.task_signal.signal(Task::HueSaturationMoveTo {
            hue_delta: Some(signed_step),
            target_saturation: None,
            transition_ms: transition_time_ds as u32 * 100,
            is_enhanced: true,
        });

        Ok(())
    }

    fn cmd_move_to_saturation(
        &self,
        saturation: u8,
        transition_time_ds: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if saturation > SATURATION_MAX {
            return Err(ErrorCode::ConstraintError.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        self.task_signal.signal(Task::HueSaturationMoveTo {
            hue_delta: None,
            target_saturation: Some(saturation),
            transition_ms: transition_time_ds as u32 * 100,
            is_enhanced: false,
        });

        Ok(())
    }

    fn cmd_move_saturation(
        &self,
        move_mode: MoveModeEnum,
        rate: u8,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if matches!(move_mode, MoveModeEnum::Stop) {
            self.task_signal.signal(Task::Stop);
            return Ok(());
        }

        if rate == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        self.task_signal.signal(Task::SaturationMove {
            direction: move_mode,
            rate_per_sec: rate as u32,
        });

        Ok(())
    }

    fn cmd_step_saturation(
        &self,
        step_mode: StepModeEnum,
        step_size: u8,
        transition_time_ds: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if step_size == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        let current = self.with_state(|s| s.current_saturation);
        let new_sat = match step_mode {
            StepModeEnum::Up => current.saturating_add(step_size).min(SATURATION_MAX),
            StepModeEnum::Down => current.saturating_sub(step_size),
        };

        self.task_signal.signal(Task::HueSaturationMoveTo {
            hue_delta: None,
            target_saturation: Some(new_sat),
            transition_ms: transition_time_ds as u32 * 100,
            is_enhanced: false,
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn cmd_move_to_hue_and_saturation(
        &self,
        hue: u8,
        saturation: u8,
        transition_time_ds: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
        is_enhanced: bool,
        enhanced_hue: u16,
    ) -> Result<(), Error> {
        if (!is_enhanced && hue > HUE_U8_MAX) || saturation > SATURATION_MAX {
            return Err(ErrorCode::ConstraintError.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        // MoveToHueAndSaturation uses Shortest direction implicitly.
        let target_eh = if is_enhanced {
            enhanced_hue
        } else {
            (hue as u16) << 8
        };

        let current_eh = self.with_state(|s| s.enhanced_current_hue);
        let delta = Self::hue_path_delta(current_eh, target_eh, DirectionEnum::Shortest);

        self.task_signal.signal(Task::HueSaturationMoveTo {
            hue_delta: Some(delta),
            target_saturation: Some(saturation),
            transition_ms: transition_time_ds as u32 * 100,
            is_enhanced,
        });

        Ok(())
    }

    fn cmd_stop_move_step(
        &self,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        self.task_signal.signal(Task::Stop);

        Ok(())
    }

    fn cmd_move_to_color(
        &self,
        color_x: u16,
        color_y: u16,
        transition_time_ds: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if color_x > XY_MAX || color_y > XY_MAX {
            return Err(ErrorCode::ConstraintError.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        self.task_signal.signal(Task::XyMoveTo {
            target_x: color_x,
            target_y: color_y,
            transition_ms: transition_time_ds as u32 * 100,
        });

        Ok(())
    }

    fn cmd_move_color(
        &self,
        rate_x: i16,
        rate_y: i16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        // Both rates zero → Stop per spec.
        if rate_x == 0 && rate_y == 0 {
            self.task_signal.signal(Task::Stop);
            return Ok(());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        self.task_signal.signal(Task::XyMove {
            rate_x_per_sec: rate_x as i32,
            rate_y_per_sec: rate_y as i32,
        });

        Ok(())
    }

    fn cmd_step_color(
        &self,
        step_x: i16,
        step_y: i16,
        transition_time_ds: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        // Spec: both StepX=0 and StepY=0 is invalid.
        if step_x == 0 && step_y == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        let cur_x = self.with_state(|s| s.current_x) as i32;
        let cur_y = self.with_state(|s| s.current_y) as i32;

        let target_x = (cur_x + step_x as i32).clamp(0, XY_MAX as i32) as u16;
        let target_y = (cur_y + step_y as i32).clamp(0, XY_MAX as i32) as u16;

        self.task_signal.signal(Task::XyMoveTo {
            target_x,
            target_y,
            transition_ms: transition_time_ds as u32 * 100,
        });

        Ok(())
    }

    fn cmd_move_to_color_temperature(
        &self,
        mireds: u16,
        transition_time_ds: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        // 0 is reserved per spec; the physical bound clamp is the
        // safety net for any out-of-range non-zero values.
        if mireds == 0 {
            return Err(ErrorCode::ConstraintError.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        let clamped = mireds.clamp(
            H::COLOR_TEMP_PHYSICAL_MIN_MIREDS,
            H::COLOR_TEMP_PHYSICAL_MAX_MIREDS,
        );

        self.task_signal.signal(Task::ColorTemperatureMoveTo {
            target_mireds: clamped,
            transition_ms: transition_time_ds as u32 * 100,
        });

        Ok(())
    }

    fn cmd_move_color_temperature(
        &self,
        move_mode: MoveModeEnum,
        rate: u16,
        color_temperature_minimum_mireds: u16,
        color_temperature_maximum_mireds: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if matches!(move_mode, MoveModeEnum::Stop) {
            self.task_signal.signal(Task::Stop);
            return Ok(());
        }

        if rate == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        let signed_rate: i32 = match move_mode {
            MoveModeEnum::Up => rate as i32,
            MoveModeEnum::Down => -(rate as i32),
            MoveModeEnum::Stop => return Ok(()),
        };

        // Treat 0 as "no caller-supplied bound" — fall back to the
        // physical bound so the move runs to that edge.
        let min_mireds = if color_temperature_minimum_mireds == 0 {
            H::COLOR_TEMP_PHYSICAL_MIN_MIREDS
        } else {
            color_temperature_minimum_mireds
        };

        let max_mireds = if color_temperature_maximum_mireds == 0 {
            H::COLOR_TEMP_PHYSICAL_MAX_MIREDS
        } else {
            color_temperature_maximum_mireds
        };

        self.task_signal.signal(Task::ColorTemperatureMove {
            rate_mireds_per_sec: signed_rate,
            min_mireds,
            max_mireds,
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn cmd_step_color_temperature(
        &self,
        step_mode: StepModeEnum,
        step_size: u16,
        transition_time_ds: u16,
        color_temperature_minimum_mireds: u16,
        color_temperature_maximum_mireds: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if step_size == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        let signed_step: i32 = match step_mode {
            StepModeEnum::Up => step_size as i32,
            StepModeEnum::Down => -(step_size as i32),
        };

        let min_mireds = if color_temperature_minimum_mireds == 0 {
            H::COLOR_TEMP_PHYSICAL_MIN_MIREDS
        } else {
            color_temperature_minimum_mireds
        };

        let max_mireds = if color_temperature_maximum_mireds == 0 {
            H::COLOR_TEMP_PHYSICAL_MAX_MIREDS
        } else {
            color_temperature_maximum_mireds
        };

        let lo = min_mireds.max(H::COLOR_TEMP_PHYSICAL_MIN_MIREDS);
        let hi = max_mireds.min(H::COLOR_TEMP_PHYSICAL_MAX_MIREDS);

        let cur = self.with_state(|s| s.color_temperature_mireds) as i32;
        let target = (cur + signed_step).clamp(lo as i32, hi as i32) as u16;

        self.task_signal.signal(Task::ColorTemperatureMoveTo {
            target_mireds: target,
            transition_ms: transition_time_ds as u32 * 100,
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn cmd_color_loop_set(
        &self,
        ctx: impl InvokeContext,
        update_flags: UpdateFlagsBitmap,
        action: ColorLoopActionEnum,
        direction: ColorLoopDirectionEnum,
        time: u16,
        start_hue: u16,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        // 1. Apply config updates (direction, time, start hue) up front.
        let cluster_id = Self::cluster_id();

        if update_flags.contains(UpdateFlagsBitmap::UPDATE_DIRECTION) {
            self.with_state(|s| s.color_loop_direction = direction);
            ctx.notify_attr_changed(
                self.endpoint_id,
                cluster_id,
                AttributeId::ColorLoopDirection as _,
            );
        }

        if update_flags.contains(UpdateFlagsBitmap::UPDATE_TIME) {
            self.with_state(|s| s.color_loop_time = time);
            ctx.notify_attr_changed(
                self.endpoint_id,
                cluster_id,
                AttributeId::ColorLoopTime as _,
            );
        }

        if update_flags.contains(UpdateFlagsBitmap::UPDATE_START_HUE) {
            self.with_state(|s| s.color_loop_start_enhanced_hue = start_hue);
            ctx.notify_attr_changed(
                self.endpoint_id,
                cluster_id,
                AttributeId::ColorLoopStartEnhancedHue as _,
            );
        }

        // 2. Process the action.
        if !update_flags.contains(UpdateFlagsBitmap::UPDATE_ACTION) {
            return Ok(());
        }

        let was_active = self.with_state(|s| s.color_loop_active);
        match action {
            ColorLoopActionEnum::Deactivate => {
                if was_active {
                    // Restore the saved hue before stopping the loop.
                    let restore = self.with_state(|s| s.color_loop_stored_enhanced_hue);

                    self.task_signal.signal(Task::Stop);

                    self.with_state(|s| s.color_loop_active = false);

                    ctx.notify_attr_changed(
                        self.endpoint_id,
                        cluster_id,
                        AttributeId::ColorLoopActive as _,
                    );

                    // Set hue directly so the restored value shows up
                    // immediately rather than waiting on the next tick.
                    self.set_hue(&ctx, restore, true, true);
                    self.drive_device_hue_saturation();
                }
            }
            ColorLoopActionEnum::ActivateFromColorLoopStartEnhancedHue
            | ColorLoopActionEnum::ActivateFromEnhancedCurrentHue => {
                // Save the current EnhancedCurrentHue before activating
                // (only if not already active — otherwise we'd overwrite
                // the pre-loop value with a mid-loop value).
                if !was_active {
                    let cur = self.with_state(|s| s.enhanced_current_hue);

                    self.with_state(|s| s.color_loop_stored_enhanced_hue = cur);

                    ctx.notify_attr_changed(
                        self.endpoint_id,
                        cluster_id,
                        AttributeId::ColorLoopStoredEnhancedHue as _,
                    );

                    self.with_state(|s| s.color_loop_active = true);

                    ctx.notify_attr_changed(
                        self.endpoint_id,
                        cluster_id,
                        AttributeId::ColorLoopActive as _,
                    );
                }

                // Seed EnhancedCurrentHue per the action.
                let seed = match action {
                    ColorLoopActionEnum::ActivateFromColorLoopStartEnhancedHue => {
                        self.with_state(|s| s.color_loop_start_enhanced_hue)
                    }
                    // ActivateFromEnhancedCurrentHue keeps current value.
                    _ => self.with_state(|s| s.enhanced_current_hue),
                };

                self.set_hue(&ctx, seed, true, true);
                self.drive_device_hue_saturation();

                // Start (or restart) the loop task with the latest config.
                self.task_signal.signal(Task::ColorLoop {
                    direction: self.with_state(|s| s.color_loop_direction),
                    time_secs: self.with_state(|s| s.color_loop_time),
                });
            }
        }

        Ok(())
    }
}

// ---- ClusterAsyncHandler implementation ----

impl<H: ColorControlHooks, OH: OnOffHooks, LH: LevelControlHooks> ClusterAsyncHandler
    for ColorControlHandler<'_, H, OH, LH>
{
    const CLUSTER: Cluster<'static> = H::CLUSTER;

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        let mut hooks_fut = pin!(self.hooks.run(|_message| {
            // No out-of-band handling yet.
        }));

        loop {
            let result = select(&mut hooks_fut, self.task_signal.wait_signalled()).await;

            let mut task = match result {
                Either::First(_) => {
                    panic!("ColorControlHooks::run returned; implementers MUST not return.")
                }
                Either::Second(task) => task,
            };

            loop {
                let result = select3(
                    &mut hooks_fut,
                    self.task_manager(&ctx, task),
                    self.task_signal.wait_signalled(),
                )
                .await;

                match result {
                    Either3::First(_) => {
                        panic!("ColorControlHooks::run returned; implementers MUST not return.")
                    }
                    Either3::Second(_) => break,
                    Either3::Third(new_task) => task = new_task,
                };
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
        ready(Ok((self.with_state(|s| s.enhanced_current_hue) >> 8) as u8))
    }

    fn current_saturation(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u8, Error>> {
        ready(Ok(self.with_state(|s| s.current_saturation)))
    }

    fn remaining_time(&self, _ctx: impl ReadContext) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.with_state(|s| s.remaining_time)))
    }

    fn current_x(&self, _ctx: impl ReadContext) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.with_state(|s| s.current_x)))
    }

    fn current_y(&self, _ctx: impl ReadContext) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.with_state(|s| s.current_y)))
    }

    fn color_temperature_mireds(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.with_state(|s| s.color_temperature_mireds)))
    }

    async fn color_mode(&self, _ctx: impl ReadContext) -> Result<ColorModeEnum, Error> {
        Ok(self.with_state(|s| s.color_mode))
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
        ready(Ok(self.with_state(|s| s.enhanced_current_hue)))
    }

    async fn enhanced_color_mode(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<EnhancedColorModeEnum, Error> {
        Ok(self.with_state(|s| s.enhanced_color_mode))
    }

    fn color_loop_active(&self, _ctx: impl ReadContext) -> impl Future<Output = Result<u8, Error>> {
        ready(Ok(self.with_state(|s| s.color_loop_active) as u8))
    }

    fn color_loop_direction(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u8, Error>> {
        ready(Ok(self.with_state(|s| s.color_loop_direction) as u8))
    }

    fn color_loop_time(&self, _ctx: impl ReadContext) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.with_state(|s| s.color_loop_time)))
    }

    fn color_loop_start_enhanced_hue(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.with_state(|s| s.color_loop_start_enhanced_hue)))
    }

    fn color_loop_stored_enhanced_hue(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<u16, Error>> {
        ready(Ok(self.with_state(|s| s.color_loop_stored_enhanced_hue)))
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

    // ---- Command handlers ----

    async fn handle_move_to_hue(
        &self,
        _ctx: impl InvokeContext,
        request: MoveToHueRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_move_to_hue(
            request.hue()?,
            request.direction()?,
            request.transition_time()?,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_move_hue(
        &self,
        _ctx: impl InvokeContext,
        request: MoveHueRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_move_hue(
            request.move_mode()?,
            request.rate()?,
            request.options_mask()?,
            request.options_override()?,
            false,
        )
    }

    async fn handle_step_hue(
        &self,
        _ctx: impl InvokeContext,
        request: StepHueRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_step_hue(
            request.step_mode()?,
            request.step_size()?,
            request.transition_time()? as u16,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_move_to_saturation(
        &self,
        _ctx: impl InvokeContext,
        request: MoveToSaturationRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_move_to_saturation(
            request.saturation()?,
            request.transition_time()?,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_move_saturation(
        &self,
        _ctx: impl InvokeContext,
        request: MoveSaturationRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_move_saturation(
            request.move_mode()?,
            request.rate()?,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_step_saturation(
        &self,
        _ctx: impl InvokeContext,
        request: StepSaturationRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_step_saturation(
            request.step_mode()?,
            request.step_size()?,
            request.transition_time()? as u16,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_move_to_hue_and_saturation(
        &self,
        _ctx: impl InvokeContext,
        request: MoveToHueAndSaturationRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_move_to_hue_and_saturation(
            request.hue()?,
            request.saturation()?,
            request.transition_time()?,
            request.options_mask()?,
            request.options_override()?,
            false,
            0,
        )
    }

    async fn handle_move_to_color(
        &self,
        _ctx: impl InvokeContext,
        request: MoveToColorRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_move_to_color(
            request.color_x()?,
            request.color_y()?,
            request.transition_time()?,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_move_color(
        &self,
        _ctx: impl InvokeContext,
        request: MoveColorRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_move_color(
            request.rate_x()?,
            request.rate_y()?,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_step_color(
        &self,
        _ctx: impl InvokeContext,
        request: StepColorRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_step_color(
            request.step_x()?,
            request.step_y()?,
            request.transition_time()?,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_move_to_color_temperature(
        &self,
        _ctx: impl InvokeContext,
        request: MoveToColorTemperatureRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_move_to_color_temperature(
            request.color_temperature_mireds()?,
            request.transition_time()?,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_enhanced_move_to_hue(
        &self,
        _ctx: impl InvokeContext,
        request: EnhancedMoveToHueRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_enhanced_move_to_hue(
            request.enhanced_hue()?,
            request.direction()?,
            request.transition_time()?,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_enhanced_move_hue(
        &self,
        _ctx: impl InvokeContext,
        request: EnhancedMoveHueRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_enhanced_move_hue(
            request.move_mode()?,
            request.rate()?,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_enhanced_step_hue(
        &self,
        _ctx: impl InvokeContext,
        request: EnhancedStepHueRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_enhanced_step_hue(
            request.step_mode()?,
            request.step_size()?,
            request.transition_time()?,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_enhanced_move_to_hue_and_saturation(
        &self,
        _ctx: impl InvokeContext,
        request: EnhancedMoveToHueAndSaturationRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_move_to_hue_and_saturation(
            0, // unused when is_enhanced=true
            request.saturation()?,
            request.transition_time()?,
            request.options_mask()?,
            request.options_override()?,
            true,
            request.enhanced_hue()?,
        )
    }

    async fn handle_color_loop_set(
        &self,
        ctx: impl InvokeContext,
        request: ColorLoopSetRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_color_loop_set(
            ctx,
            request.update_flags()?,
            request.action()?,
            request.direction()?,
            request.time()?,
            request.start_hue()?,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_stop_move_step(
        &self,
        _ctx: impl InvokeContext,
        request: StopMoveStepRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_stop_move_step(request.options_mask()?, request.options_override()?)
    }

    async fn handle_move_color_temperature(
        &self,
        _ctx: impl InvokeContext,
        request: MoveColorTemperatureRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_move_color_temperature(
            request.move_mode()?,
            request.rate()?,
            request.color_temperature_minimum_mireds()?,
            request.color_temperature_maximum_mireds()?,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_step_color_temperature(
        &self,
        _ctx: impl InvokeContext,
        request: StepColorTemperatureRequest<'_>,
    ) -> Result<(), Error> {
        self.cmd_step_color_temperature(
            request.step_mode()?,
            request.step_size()?,
            request.transition_time()?,
            request.color_temperature_minimum_mireds()?,
            request.color_temperature_maximum_mireds()?,
            request.options_mask()?,
            request.options_override()?,
        )
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
            let x = self.with_state(|s| s.current_x);
            let avp_array = avp_array.push_u16(AttributeId::CurrentX as _, x)?;
            let y = self.with_state(|s| s.current_y);
            avp_array.push_u16(AttributeId::CurrentY as _, y)?
        } else {
            avp_array
        };

        let avp_array = if features.contains(Feature::ENHANCED_HUE) {
            let h = self.with_state(|s| s.enhanced_current_hue);
            avp_array.push_u16(AttributeId::EnhancedCurrentHue as _, h)?
        } else {
            avp_array
        };

        let avp_array = if features.contains(Feature::HUE_AND_SATURATION) {
            let s = self.with_state(|s| s.current_saturation);
            avp_array.push_u8(AttributeId::CurrentSaturation as _, s)?
        } else {
            avp_array
        };

        let avp_array = if features.contains(Feature::COLOR_LOOP) {
            let active = self.with_state(|s| s.color_loop_active);
            let avp_array = avp_array.push_u8(AttributeId::ColorLoopActive as _, active as u8)?;
            let direction = self.with_state(|s| s.color_loop_direction);
            let avp_array =
                avp_array.push_u8(AttributeId::ColorLoopDirection as _, direction as u8)?;
            let time = self.with_state(|s| s.color_loop_time);
            avp_array.push_u16(AttributeId::ColorLoopTime as _, time)?
        } else {
            avp_array
        };

        let avp_array = if features.contains(Feature::COLOR_TEMPERATURE) {
            let mireds = self.with_state(|s| s.color_temperature_mireds);
            avp_array.push_u16(AttributeId::ColorTemperatureMireds as _, mireds)?
        } else {
            avp_array
        };

        let mode = self.with_state(|s| s.enhanced_color_mode);
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

/// Re-usable test/demo `ColorControlHooks` implementation. Mirrors
/// the shape of [`crate::dm::clusters::app::on_off::test`] and
/// [`crate::dm::clusters::app::level_control::test`] — application
/// integration tests and examples can use this without writing their
/// own hooks scaffolding.
pub mod test {
    use core::cell::Cell;

    use crate::dm::clusters::app::color_control::{
        ColorCapabilitiesBitmap, ColorControlHooks, SetDeviceColor,
    };
    use crate::dm::clusters::decl::color_control::{AttributeId, CommandId, Feature, FULL_CLUSTER};
    use crate::dm::Cluster;
    use crate::error::Error;
    use crate::tlv::Nullable;
    use crate::with;

    /// All-features-enabled [`ColorControlHooks`] for tests, demos
    /// and the bundled `light_tests` example. The cluster owns every
    /// piece of state internally; this stub only persists
    /// `StartUpColorTemperatureMireds` in RAM (lost on reboot — real
    /// devices would wire flash here) and discards actuator writes.
    pub struct TestColorControlDeviceLogic {
        start_up_color_temperature_mireds: Cell<Option<u16>>,
    }

    impl TestColorControlDeviceLogic {
        pub const fn new() -> Self {
            Self {
                start_up_color_temperature_mireds: Cell::new(None),
            }
        }
    }

    impl Default for TestColorControlDeviceLogic {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ColorControlHooks for TestColorControlDeviceLogic {
        const CLUSTER: Cluster<'static> = FULL_CLUSTER
            .with_features(
                Feature::HUE_AND_SATURATION.bits()
                    | Feature::ENHANCED_HUE.bits()
                    | Feature::COLOR_LOOP.bits()
                    | Feature::XY.bits()
                    | Feature::COLOR_TEMPERATURE.bits(),
            )
            .with_attrs(with!(
                required;
                AttributeId::CurrentHue
                    | AttributeId::CurrentSaturation
                    | AttributeId::RemainingTime
                    | AttributeId::CurrentX
                    | AttributeId::CurrentY
                    | AttributeId::ColorTemperatureMireds
                    | AttributeId::ColorMode
                    | AttributeId::Options
                    | AttributeId::NumberOfPrimaries
                    | AttributeId::EnhancedCurrentHue
                    | AttributeId::EnhancedColorMode
                    | AttributeId::ColorLoopActive
                    | AttributeId::ColorLoopDirection
                    | AttributeId::ColorLoopTime
                    | AttributeId::ColorLoopStartEnhancedHue
                    | AttributeId::ColorLoopStoredEnhancedHue
                    | AttributeId::ColorCapabilities
                    | AttributeId::ColorTempPhysicalMinMireds
                    | AttributeId::ColorTempPhysicalMaxMireds
                    | AttributeId::CoupleColorTempToLevelMinMireds
                    | AttributeId::StartUpColorTemperatureMireds
            ))
            .with_cmds(with!(
                CommandId::MoveToHue
                    | CommandId::MoveHue
                    | CommandId::StepHue
                    | CommandId::MoveToSaturation
                    | CommandId::MoveSaturation
                    | CommandId::StepSaturation
                    | CommandId::MoveToHueAndSaturation
                    | CommandId::MoveToColor
                    | CommandId::MoveColor
                    | CommandId::StepColor
                    | CommandId::MoveToColorTemperature
                    | CommandId::EnhancedMoveToHue
                    | CommandId::EnhancedMoveHue
                    | CommandId::EnhancedStepHue
                    | CommandId::EnhancedMoveToHueAndSaturation
                    | CommandId::ColorLoopSet
                    | CommandId::StopMoveStep
                    | CommandId::MoveColorTemperature
                    | CommandId::StepColorTemperature
            ));

        const COLOR_CAPABILITIES: ColorCapabilitiesBitmap =
            ColorCapabilitiesBitmap::from_bits_truncate(
                ColorCapabilitiesBitmap::HUE_SATURATION.bits()
                    | ColorCapabilitiesBitmap::ENHANCED_HUE.bits()
                    | ColorCapabilitiesBitmap::COLOR_LOOP.bits()
                    | ColorCapabilitiesBitmap::XY.bits()
                    | ColorCapabilitiesBitmap::COLOR_TEMPERATURE.bits(),
            );

        const COLOR_TEMP_PHYSICAL_MIN_MIREDS: u16 = 153;
        const COLOR_TEMP_PHYSICAL_MAX_MIREDS: u16 = 500;
        const COUPLE_COLOR_TEMP_TO_LEVEL_MIN_MIREDS: u16 = Self::COLOR_TEMP_PHYSICAL_MIN_MIREDS;

        fn set_device_color(&self, _target: SetDeviceColor) -> Result<(), ()> {
            // No-op actuator: real devices would drive their LED here.
            Ok(())
        }

        fn start_up_color_temperature_mireds(&self) -> Result<Nullable<u16>, Error> {
            Ok(match self.start_up_color_temperature_mireds.get() {
                Some(v) => Nullable::some(v),
                None => Nullable::none(),
            })
        }

        fn set_start_up_color_temperature_mireds(&self, value: Nullable<u16>) -> Result<(), Error> {
            self.start_up_color_temperature_mireds
                .set(value.into_option());
            Ok(())
        }
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
    struct MockHooks<const F: u32>;

    impl<const F: u32> MockHooks<F> {
        fn new() -> Self {
            Self
        }
    }

    impl<const F: u32> ColorControlHooks for MockHooks<F> {
        const CLUSTER: Cluster<'static> = FULL_CLUSTER
            .with_features(F)
            .with_attrs(with!(required))
            .with_cmds(with!());

        const COLOR_CAPABILITIES: ColorCapabilitiesBitmap =
            ColorCapabilitiesBitmap::from_bits_truncate(F as u16);

        const COLOR_TEMP_PHYSICAL_MIN_MIREDS: u16 = 153;
        const COLOR_TEMP_PHYSICAL_MAX_MIREDS: u16 = 500;

        fn set_device_color(&self, _target: SetDeviceColor) -> Result<(), ()> {
            Ok(())
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
        h.with_state(|s| s.current_x = 0x1234);
        h.with_state(|s| s.current_y = 0x5678);
        h.with_state(|s| s.enhanced_color_mode = EnhancedColorModeEnum::CurrentXAndCurrentY);

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
        h.with_state(|s| s.color_temperature_mireds = 250);
        h.with_state(|s| s.enhanced_color_mode = EnhancedColorModeEnum::ColorTemperatureMireds);

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

        assert_eq!(h.with_state(|s| s.current_x), 0xABCD);
        assert_eq!(h.with_state(|s| s.current_y), 0x1234);
        assert!(matches!(
            h.with_state(|s| s.enhanced_color_mode),
            EnhancedColorModeEnum::CurrentXAndCurrentY
        ));
        assert!(matches!(
            h.with_state(|s| s.color_mode),
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

        assert_eq!(h.with_state(|s| s.enhanced_current_hue), 0x1200);
        assert_eq!(h.with_state(|s| s.current_saturation), 100);
        assert!(matches!(
            h.with_state(|s| s.enhanced_color_mode),
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

        assert_eq!(h.with_state(|s| s.enhanced_current_hue), 0x4321);
        assert_eq!(h.with_state(|s| s.current_saturation), 200);
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
        h.with_state(|s| s.current_x = 1);
        h.with_state(|s| s.current_y = 2);
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

        assert!(h.with_state(|s| s.color_loop_active));
        assert_eq!(h.with_state(|s| s.color_loop_time), 30);
        // XY mode-dispatch must NOT have run.
        assert_eq!(h.with_state(|s| s.current_x), 1);
        assert_eq!(h.with_state(|s| s.current_y), 2);
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

        // current_x/y unchanged (still at the ColorControlState defaults).
        assert_eq!(h.with_state(|s| s.current_x), 0x616B);
        assert_eq!(h.with_state(|s| s.current_y), 0x607D);
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
        h.with_state(|s| s.current_x = 0xAAAA);
        h.with_state(|s| s.current_y = 0x5555);
        h.with_state(|s| s.enhanced_color_mode = EnhancedColorModeEnum::CurrentXAndCurrentY);

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
        h.with_state(|s| s.current_x = 0);
        h.with_state(|s| s.current_y = 0);
        h.with_state(|s| {
            s.enhanced_color_mode = EnhancedColorModeEnum::CurrentHueAndCurrentSaturation
        });

        // Apply the captured blob
        let elem = TLVElement::new(&cap_buf[..cap_len]);
        let avp_list: TLVArray<'_, AttributeValuePairStruct<'_>> = TLVArray::new(elem).unwrap();
        h.apply_inner(NULL_CTX, &avp_list, 0).unwrap();

        assert_eq!(h.with_state(|s| s.current_x), 0xAAAA);
        assert_eq!(h.with_state(|s| s.current_y), 0x5555);
        assert!(matches!(
            h.with_state(|s| s.enhanced_color_mode),
            EnhancedColorModeEnum::CurrentXAndCurrentY
        ));
    }

    // ---- SetDeviceColor conversion utilities ----

    #[test]
    fn hsv_to_rgb_primary_colours() {
        // Pure red: hue=0, full sat.
        let (r, g, b) = SetDeviceColor::HueSaturation {
            enhanced_hue: 0,
            saturation: 254,
        }
        .to_rgb(RgbGamma::Linear);
        assert_eq!((r, g, b), (255, 0, 0));

        // Pure green: hue=120° → enhanced 65536/3 (≈ 21845).
        let (r, g, b) = SetDeviceColor::HueSaturation {
            enhanced_hue: 21845,
            saturation: 254,
        }
        .to_rgb(RgbGamma::Linear);
        // Allow 1-unit jitter on the 0 channels due to f32 rounding.
        assert!(r <= 1 && g == 255 && b <= 1, "got ({r}, {g}, {b})");

        // Pure blue: hue=240° → enhanced 2*65536/3 (≈ 43690).
        let (r, g, b) = SetDeviceColor::HueSaturation {
            enhanced_hue: 43690,
            saturation: 254,
        }
        .to_rgb(RgbGamma::Linear);
        assert!(r <= 1 && g <= 1 && b == 255, "got ({r}, {g}, {b})");

        // Zero saturation: any hue → white.
        let (r, g, b) = SetDeviceColor::HueSaturation {
            enhanced_hue: 12345,
            saturation: 0,
        }
        .to_rgb(RgbGamma::Linear);
        assert_eq!((r, g, b), (255, 255, 255));
    }

    #[test]
    fn srgb_gamma_brighter_than_linear_in_mid_range() {
        // At hue=0 (red), saturation 127 gives linear (255, 128, 128)
        // — the brightest channel is always full at full brightness,
        // so the mid-tone reveal happens on the off-channels.
        let src = SetDeviceColor::HueSaturation {
            enhanced_hue: 0,
            saturation: 127,
        };
        let (_, g_lin, _) = src.to_rgb(RgbGamma::Linear);
        let (_, g_srgb, _) = src.to_rgb(RgbGamma::SRgb);
        assert!(
            g_srgb > g_lin,
            "sRGB should brighten mid-tones; lin={g_lin} srgb={g_srgb}"
        );
        // The bright channel is at the curve's endpoint, where the
        // two encodings agree.
        let (r_full, _, _) = SetDeviceColor::HueSaturation {
            enhanced_hue: 0,
            saturation: 254,
        }
        .to_rgb(RgbGamma::SRgb);
        assert_eq!(r_full, 255);
    }

    #[test]
    fn to_xy_idempotent_on_xy_variant() {
        assert_eq!(
            SetDeviceColor::Xy {
                x: 0x1234,
                y: 0x5678
            }
            .to_xy(),
            (0x1234, 0x5678)
        );
    }

    #[test]
    fn to_hue_saturation_idempotent_on_hs_variant() {
        let src = SetDeviceColor::HueSaturation {
            enhanced_hue: 0x4000,
            saturation: 200,
        };
        assert_eq!(src.to_hue_saturation(), (0x4000, 200));
    }

    #[test]
    fn ct_to_xy_planckian_locus_4000k() {
        // 4000 K ≈ 250 mireds. Planckian locus at 4000K sits at
        // approximately (0.381, 0.377). The Krystek approximation
        // should land within ±0.005 in xy-space.
        let (x, y) = SetDeviceColor::ColorTemperature { mireds: 250 }.to_xy();
        let x_f = x as f32 / 0xFEFF as f32;
        let y_f = y as f32 / 0xFEFF as f32;
        assert!((x_f - 0.381).abs() < 0.005, "expected x ≈ 0.381, got {x_f}");
        assert!((y_f - 0.377).abs() < 0.005, "expected y ≈ 0.377, got {y_f}");
    }

    #[test]
    fn xy_red_roundtrips_through_hue() {
        // Pure red in xy (sRGB-ish: 0.64, 0.33) should map to hue ≈ 0°.
        let red = SetDeviceColor::Xy {
            x: (0.64 * 0xFEFF as f32) as u16,
            y: (0.33 * 0xFEFF as f32) as u16,
        };
        let (hue, sat) = red.to_hue_saturation();
        // hue near 0 (or near 65535 due to the circular wrap).
        assert!(
            !(1000..=64500).contains(&hue),
            "expected hue near 0°, got {hue}"
        );
        // Should be very saturated.
        assert!(sat > 240, "expected high saturation, got {sat}");
    }
}
