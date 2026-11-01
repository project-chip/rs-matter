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

//! An example Matter device that implements the On/Off, LevelControl and
//! ColorControl clusters over Ethernet - i.e. an RGB light.
//!
//! The ColorControl cluster offers hue + saturation, CIE xy and colour
//! temperature; `set_device_color` turns whichever of those the cluster
//! decides to drive into an RGB triplet for the "hardware".
#![allow(clippy::uninlined_format_args)]

use core::pin::pin;

use async_signal::{Signal, Signals};

use log::info;

use futures_lite::StreamExt;

use rand::Rng;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::color_control::{
    self, ColorCapabilitiesBitmap, ColorControlHooks, RgbGamma, SetDeviceColor,
};
use rs_matter::dm::clusters::app::level_control::{self, LevelControlHooks};
use rs_matter::dm::clusters::app::on_off::{self, OnOffHooks};
use rs_matter::dm::clusters::decl::color_control as color_control_cluster;
use rs_matter::dm::clusters::decl::level_control::{
    AttributeId, CommandId, OptionsBitmap, FULL_CLUSTER as LEVEL_CONTROL_FULL_CLUSTER,
};
use rs_matter::dm::clusters::decl::on_off as on_off_cluster;
use rs_matter::dm::clusters::decl::scenes_management::FULL_CLUSTER as SCENES_FULL_CLUSTER;
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::identify::{self, IdentifyHandler};
use rs_matter::dm::clusters::scenes::{SceneClusters, ScenesHandler, ScenesState};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_EXTENDED_COLOR_LIGHT;
use rs_matter::dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, Cluster, DataModel, Dataver, EmptyHandler, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::utils::futures::{select, Coalesce};
use rs_matter::{clusters, devices, root_endpoint, with, Matter};

use rs_matter::stack::eth::EthMatterStack;
use rs_matter::stack::net::std::StdNetStack;
use rs_matter::utils::init::InitMaybeUninit;

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

/// How many scenes the scene table can hold, across all fabrics.
const SCENES_CAPACITY: usize = 16;

/// The bump allocator size of the stack, in bytes.
///
/// If it is not enough, the stack panics while it starts. The futures of an
/// unoptimized build are much bigger than those of an optimized one.
const BUMP_SIZE: usize = 32 * 1024;

/// The stack is allocated statically to avoid program stack blowups.
static MATTER_STACK: StaticCell<EthMatterStack<BUMP_SIZE, ()>> = StaticCell::new();

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let stack = MATTER_STACK.uninit().init_with(EthMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));

    // Persistence
    let mut store = rs_matter::persist::DirKvBlobStore::new_default();

    // Create the crypto instance
    let crypto = default_crypto(rand::rng(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // Re-hydrate the persisted state. If the device is not commissioned yet, this also
    // prints the QR text and code to the console and enables basic commissioning.
    futures_lite::future::block_on(stack.startup(&crypto, &mut store))?;

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = stack.kv(store);

    // The scene table, shared by the Scenes Management cluster and by the
    // three scene-aware handlers below, which flip `SceneValid` through it
    // whenever a command changes a captured attribute. It persists itself
    // under `rs_matter::persist::SCENES_KEY`.
    let scenes_state = ScenesState::<SCENES_CAPACITY>::new();

    // OnOff cluster setup
    let on_off_handler = on_off::OnOffHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x10,
        OnOffDeviceLogic::new(),
    )
    .with_scene_invalidator(&scenes_state);

    // LevelControl cluster setup
    let level_control_handler = level_control::LevelControlHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x11,
        LevelControlDeviceLogic::new(),
    )
    .with_scene_invalidator(&scenes_state);

    // ColorControl cluster setup
    let color_control_handler = color_control::ColorControlHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x12,
        ColorControlDeviceLogic::new(),
    )
    .with_scene_invalidator(&scenes_state);

    // Cluster wiring, validation and initialisation.
    // ColorControl is coupled to the same OnOff handler, so that the
    // `Options.EXECUTE_IF_OFF` gating of the colour commands works.
    on_off_handler.init(Some(&level_control_handler));
    level_control_handler.init(Some(&on_off_handler));
    color_control_handler.init(Some(&on_off_handler));

    // Scenes Management cluster setup - mandatory for the Extended Color
    // Light device type. The registry lists the handlers whose attributes
    // a scene captures and recalls.
    let scenes_handler = ScenesHandler::new(
        Dataver::new_rand(&mut rand),
        stack.matter(),
        &scenes_state,
        (
            &on_off_handler,
            (&level_control_handler, (&color_control_handler, ())),
        ),
    );

    // Listen to SIGTERM (or Ctrl-C on Windows, where SIGTERM is not
    // supported by `async-signal`) because at the end of the test we'll
    // receive it.
    #[cfg(not(windows))]
    let mut term_signal = Signals::new([Signal::Term])?;
    #[cfg(windows)]
    let mut term_signal = Signals::new([Signal::Int])?;
    let mut term = pin!(async {
        term_signal.next().await;
        Ok(())
    });

    // Run the stack until it fails, or until we are asked to terminate
    let mut matter = pin!(stack.run_preex(
        // The UDP sockets of the node
        StdNetStack::new(),
        // The network interfaces of the host
        SysNetifs,
        // No Ethernet diagnostics to report
        &(),
        mdns::create_mdns(),
        &crypto,
        data_model(
            stack.matter(),
            rand,
            &on_off_handler,
            &level_control_handler,
            &color_control_handler,
            scenes_handler,
        ),
        kv,
        // No user task to run
        (),
    ));

    let all = select(&mut matter, &mut term).coalesce();

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all)
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_EXTENDED_COLOR_LIGHT),
            clusters!(
                desc::DescHandler::CLUSTER,
                identify::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                OnOffDeviceLogic::CLUSTER,
                LevelControlDeviceLogic::CLUSTER,
                ColorControlDeviceLogic::CLUSTER,
                SCENES_FULL_CLUSTER,
            ),
        ),
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the light endpoint handlers.
fn data_model<'a, LH: LevelControlHooks, OH: OnOffHooks, CH: ColorControlHooks, R>(
    matter: &'a Matter<'a>,
    mut rand: impl Rng + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
    level_control: &'a level_control::LevelControlHandler<'a, LH, OH>,
    color_control: &'a color_control::ColorControlHandler<'a, CH, OH, LH>,
    scenes: ScenesHandler<'a, SCENES_CAPACITY, R>,
) -> impl DataModel + 'a
where
    R: SceneClusters + 'a,
{
    (
        NODE,
        EmptyHandler
            .chain(
                |e, _| e == ROOT_ENDPOINT_ID,
                Async(EthMatterStack::<0, ()>::root_handler(matter, &(), rand)),
            )
            .chain(
                |e, c| e == 1 && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == identify::CLUSTER.id,
                Async(IdentifyHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == groups::GroupsHandler::CLUSTER.id,
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand), matter).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == OnOffDeviceLogic::CLUSTER.id,
                Async(on_off::HandlerAdaptor(on_off)),
            )
            .chain(
                |e, c| e == 1 && c == LevelControlDeviceLogic::CLUSTER.id,
                Async(level_control::HandlerAdaptor(level_control)),
            )
            .chain(
                |e, c| e == 1 && c == ColorControlDeviceLogic::CLUSTER.id,
                Async(color_control::HandlerAdaptor(color_control)),
            )
            .chain(|e, c| e == 1 && c == SCENES_FULL_CLUSTER.id, scenes.adapt()),
    )
}

// Implementing the ColorControl business logic
//
// The cluster handler owns and persists every colour attribute, runs the
// transitions and picks the colour space to drive the device in; the device
// logic only has to push the colour onto the hardware.
#[derive(Default)]
pub struct ColorControlDeviceLogic;

impl ColorControlDeviceLogic {
    pub const fn new() -> Self {
        Self
    }
}

impl ColorControlHooks for ColorControlDeviceLogic {
    // An RGB LED has no dedicated white channel, so colour temperature looks
    // like a feature to leave out - but it seems a colour light cannot be
    // modelled without it: `Extended Color Light` makes `COLOR_TEMPERATURE`
    // mandatory, and some ecosystems (Google Home, for one) appear to go by
    // the device type rather than by `FeatureMap`, sending
    // `MoveToColorTemperature` regardless. Enabling it is free anyway: the
    // cluster converts the mireds into a colour `set_device_color` can drive.
    const CLUSTER: Cluster<'static> = color_control_cluster::FULL_CLUSTER
        .with_features(
            color_control_cluster::Feature::HUE_AND_SATURATION.bits()
                | color_control_cluster::Feature::XY.bits()
                | color_control_cluster::Feature::COLOR_TEMPERATURE.bits(),
        )
        .with_attrs(with!(
            required;
            color_control_cluster::AttributeId::CurrentHue
                | color_control_cluster::AttributeId::CurrentSaturation
                | color_control_cluster::AttributeId::CurrentX
                | color_control_cluster::AttributeId::CurrentY
                | color_control_cluster::AttributeId::RemainingTime
                | color_control_cluster::AttributeId::ColorTemperatureMireds
                | color_control_cluster::AttributeId::ColorTempPhysicalMinMireds
                | color_control_cluster::AttributeId::ColorTempPhysicalMaxMireds
                | color_control_cluster::AttributeId::StartUpColorTemperatureMireds
        ))
        .with_cmds(with!(
            color_control_cluster::CommandId::MoveToHue
                | color_control_cluster::CommandId::MoveHue
                | color_control_cluster::CommandId::StepHue
                | color_control_cluster::CommandId::MoveToSaturation
                | color_control_cluster::CommandId::MoveSaturation
                | color_control_cluster::CommandId::StepSaturation
                | color_control_cluster::CommandId::MoveToHueAndSaturation
                | color_control_cluster::CommandId::MoveToColor
                | color_control_cluster::CommandId::MoveColor
                | color_control_cluster::CommandId::StepColor
                | color_control_cluster::CommandId::MoveToColorTemperature
                | color_control_cluster::CommandId::MoveColorTemperature
                | color_control_cluster::CommandId::StepColorTemperature
                | color_control_cluster::CommandId::StopMoveStep
        ));

    // Mirrors the features enabled above.
    const COLOR_CAPABILITIES: ColorCapabilitiesBitmap = ColorCapabilitiesBitmap::from_bits_truncate(
        ColorCapabilitiesBitmap::HUE_SATURATION.bits()
            | ColorCapabilitiesBitmap::XY.bits()
            | ColorCapabilitiesBitmap::COLOR_TEMPERATURE.bits(),
    );

    // The colour-temperature range we accept, i.e. 6535K to 2000K.
    const COLOR_TEMP_PHYSICAL_MIN_MIREDS: u16 = 153;
    const COLOR_TEMP_PHYSICAL_MAX_MIREDS: u16 = 500;

    // Come up in saturated red until the handler has persisted a colour.
    const COLOR: Option<SetDeviceColor> = Some(SetDeviceColor::HueSaturation {
        enhanced_hue: 0,
        saturation: 254,
    });

    fn set_device_color(&self, target: SetDeviceColor) -> Result<(), ()> {
        // This is where business logic is implemented to physically change
        // the colour of the device. The level (brightness) comes separately,
        // from LevelControl. A colour temperature arrives here as its point
        // on the Planckian locus, i.e. the LED approximates white the way
        // RGB-only bulbs do.
        //
        // The two triplets below are the same colour in two encodings, and
        // they are far apart at the dim end - 2000K is linear (255, 66, 2)
        // but sRGB (255, 139, 22) - so never read one as if it were the
        // other. `linear` is proportional to light output and is what drives
        // a PWM duty cycle, i.e. what a real device would use here. `srgb` is
        // display-encoded, and is the one to compare against a colour picker
        // or a screenshot of a controller's UI.
        let linear = target.to_rgb(RgbGamma::Linear);
        let srgb = target.to_rgb(RgbGamma::SRgb);

        info!(
            "ColorControlDeviceLogic: setting color to {:?} (linear RGB {}, {}, {} / sRGB {}, {}, {})",
            target, linear.0, linear.1, linear.2, srgb.0, srgb.1, srgb.2
        );

        Ok(())
    }
}

// Implementing the LevelControl business logic
//
// The cluster handler owns and persists every attribute, including `CurrentLevel`;
// the device logic only drives the hardware.
pub struct LevelControlDeviceLogic;

impl Default for LevelControlDeviceLogic {
    fn default() -> Self {
        Self::new()
    }
}

impl LevelControlDeviceLogic {
    pub const fn new() -> Self {
        Self
    }
}

impl LevelControlHooks for LevelControlDeviceLogic {
    const MIN_LEVEL: u8 = 1;
    const MAX_LEVEL: u8 = 254;
    const FASTEST_RATE: u8 = 50;
    const ON_LEVEL: Option<u8> = Some(42);
    const OPTIONS: OptionsBitmap = OptionsBitmap::EXECUTE_IF_OFF;
    const CURRENT_LEVEL: Option<u8> = Some(1);
    const CLUSTER: Cluster<'static> = LEVEL_CONTROL_FULL_CLUSTER
        .with_features(
            level_control::Feature::LIGHTING.bits() | level_control::Feature::ON_OFF.bits(),
        )
        .with_attrs(with!(
            required;
            AttributeId::CurrentLevel
            | AttributeId::RemainingTime
            | AttributeId::MinLevel
            | AttributeId::MaxLevel
            | AttributeId::OnOffTransitionTime
            | AttributeId::OnLevel
            | AttributeId::OnTransitionTime
            | AttributeId::OffTransitionTime
            | AttributeId::DefaultMoveRate
            | AttributeId::Options
            | AttributeId::StartUpCurrentLevel
        ))
        .with_cmds(with!(
            CommandId::MoveToLevel
                | CommandId::Move
                | CommandId::Step
                | CommandId::Stop
                | CommandId::MoveToLevelWithOnOff
                | CommandId::MoveWithOnOff
                | CommandId::StepWithOnOff
                | CommandId::StopWithOnOff
        ));

    fn set_device_level(&self, level: u8) -> Result<Option<u8>, ()> {
        // This is where business logic is implemented to physically change the level of the device.
        info!("LevelControlDeviceLogic: setting level to {}", level);
        Ok(Some(level))
    }
}

// Implementing the OnOff business logic
//
// The cluster handler owns and persists the `OnOff` attribute; the device logic
// only drives the hardware.
#[derive(Default)]
pub struct OnOffDeviceLogic;

impl OnOffDeviceLogic {
    pub const fn new() -> Self {
        Self
    }
}

impl OnOffHooks for OnOffDeviceLogic {
    const CLUSTER: Cluster<'static> = on_off_cluster::FULL_CLUSTER
        .with_revision(6)
        .with_features(on_off_cluster::Feature::LIGHTING.bits())
        .with_attrs(with!(
            required;
            on_off_cluster::AttributeId::OnOff
            | on_off_cluster::AttributeId::GlobalSceneControl
            | on_off_cluster::AttributeId::OnTime
            | on_off_cluster::AttributeId::OffWaitTime
            | on_off_cluster::AttributeId::StartUpOnOff
        ))
        .with_cmds(with!(
            on_off_cluster::CommandId::Off
                | on_off_cluster::CommandId::On
                | on_off_cluster::CommandId::Toggle
                | on_off_cluster::CommandId::OffWithEffect
                | on_off_cluster::CommandId::OnWithRecallGlobalScene
                | on_off_cluster::CommandId::OnWithTimedOff
        ));

    fn set_on_off(&self, on: bool) {
        // This is where business logic is implemented to physically switch the device.
        info!("OnOff state set to: {}", on);
    }

    async fn handle_off_with_effect(&self, _effect: on_off::EffectVariantEnum) {
        // no effect
    }
}
