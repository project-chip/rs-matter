/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

//! This module contains the implementation of the On/Off cluster and its handler.
//!
//! While this cluster is not necessary for the operation of `rs-matter`, this
//! implementation is useful in examples and tests.

use core::cell::Cell;

use crate::dm::clusters::decl::on_off;
use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext, WriteContext};
use crate::error::{Error, ErrorCode};

pub use crate::dm::clusters::decl::on_off::*;

use crate::tlv::Nullable;

pub struct OnOffHandler<'a, H: OnOffHooks> {
    dataver: Dataver,
    state: &'a OnOffState<'a, H>,
}

impl<'a, H: OnOffHooks> OnOffHandler<'a, H> {
    /// Creates a new instance of `OnOffHandler` with the given `Dataver`.
    pub fn new(dataver: Dataver, on_off_state: &'a OnOffState<'a, H>) -> Self {
        let this = Self {
            dataver,
            state: on_off_state,
        };

        this.validate();

        this
    }

    fn validate(&self) {
        if Self::CLUSTER.revision != 6 {
            panic!("OnOff validation: incorrect version number: expected 6 got {}", Self::CLUSTER.revision);
        }

        // Check for mandatory attributes
        if Self::CLUSTER.attribute(AttributeId::OnOff as _).is_none() {
            panic!("OnOff validation: missing required attribute: OnOff");
        }

        // Check for mandatory commands
        if Self::CLUSTER.command(CommandId::Off as _).is_none() {
            panic!("OnOff validation: missing required command: Off");
        }

        // Check LIGHTING feature requirements
        if Self::CLUSTER.feature_map & on_off::Feature::LIGHTING.bits() != 0 {
            if Self::CLUSTER.attribute(AttributeId::GlobalSceneControl as _).is_none()
            || Self::CLUSTER.attribute(AttributeId::OnTime as _).is_none()
            || Self::CLUSTER.attribute(AttributeId::OffWaitTime as _).is_none()
            || Self::CLUSTER.attribute(AttributeId::StartUpOnOff as _).is_none() {
                panic!("OnOff validation: missing attributes required by LIGHTING feature: GlobalSceneControl, OnTime, OffWaitTime, StartUpOnOff")
            }

            if Self::CLUSTER.command(CommandId::OffWithEffect as _).is_none() 
            || Self::CLUSTER.command(CommandId::OnWithRecallGlobalScene as _).is_none() 
            || Self::CLUSTER.command(CommandId::OnWithTimedOff as _).is_none() 
            {
                panic!("OnOff validation: missing commands required by LIGHTING feature: OffWithEffect, OnWithRecallGlobalScene, OnWithTimedOff")
            }
        }

        // Check OFFONLY feature requirements
        if Self::CLUSTER.feature_map & on_off::Feature::OFF_ONLY.bits() != 0 {
            if Self::CLUSTER.command(CommandId::On as _).is_some()
            || Self::CLUSTER.command(CommandId::Toggle as _).is_some()
            {
                panic!("OnOff validation: extra commands while using OFFONLY feature: On, Toggle")
            }
        }
    }

    /// Initialise the cluster on startup.
    fn init(&self) {
        // 1.5.6.6. StartUpOnOff Attribute
        // This attribute SHALL define the desired startup behavior of a device when it is supplied with power
        // and this state SHALL be reflected in the OnOff attribute. If the value is null, the OnOff attribute is
        // set to its previous value. Otherwise, the behavior is defined in the table defining StartUpOnOffEnum.
        // todo: Implement checking the reason for reboot.
        // This behavior does not apply to reboots associated with OTA. After an OTA restart, the OnOff
        // attribute SHALL return to its value prior to the restart.
        //
        // Note: We assume that since the on_off state is persisted by the user and it is entangled with the 
        // actual state of the device, if start_up_on_off == null we don't need to do anything.
        if let Some(start_up_state) = self.state.hooks.start_up_on_off().into_option() {
            match start_up_state {
                StartUpOnOffEnum::Off => self.state.hooks.set_on_off(false),
                StartUpOnOffEnum::On => self.state.hooks.set_on_off(true),
                StartUpOnOffEnum::Toggle => self.state.hooks.set_on_off(!self.state.hooks.on_off()),
            }
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    // todo Move into OnOffState?
    // The method that should be used by coupled clusters to update the on_off state.
    pub(crate) fn coupled_cluster_set_on_off(&self, on: bool) {
        info!(
            "OnOffCluster: coupled_cluster_set_on_off: Setting on_off to {}",
            on
        );

        if Self::CLUSTER.feature_map & on_off::Feature::LIGHTING.bits() != 0 {
            // From section 1.5.4.1. Lighting Feature
            match on {
                // On receipt of a Level Control cluster command that causes the OnOff attribute to be set to TRUE, if
                // the value of the OnTime attribute is equal to 0, the server SHALL set the OffWaitTime attribute to 0.
                true => {
                    if self.state.on_time.get() == 0 {
                        self.state.off_wait_time.set(0)
                    }
                },
                // On receipt of a Level Control cluster command that causes the OnOff attribute to be set to FALSE,
                // the OnTime attribute SHALL be set to 0.
                false => self.state.on_time.set(0),
            }
        }

        self.state.hooks.set_on_off(on);
    }
}

impl<'a, H: OnOffHooks> ClusterAsyncHandler for OnOffHandler<'a, H> {
    #[doc = "The cluster-metadata corresponding to this handler trait."]
    const CLUSTER: Cluster<'static> = H::CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn run(&self) -> Result<(), Error>{
        core::future::pending:: <Result:: <(), Error>>().await
    }
    
    // Attribute accessors
    async fn on_off(&self, _ctx:impl ReadContext) -> Result<bool, Error>  {
        Ok(self.state.hooks.on_off())
    }

    async fn global_scene_control(&self, _ctx:impl ReadContext) -> Result<bool, Error>{
        Ok(self.state.global_scene_control.get())
    }
    
    async fn on_time(&self, _ctx:impl ReadContext) -> Result<u16, Error>{
        Ok(self.state.on_time.get())
    }
    
    async fn off_wait_time(&self, _ctx:impl ReadContext) -> Result<u16, Error>{
        Ok(self.state.off_wait_time.get())
    }
    
    async fn start_up_on_off(&self, _ctx:impl ReadContext) -> Result<Nullable<StartUpOnOffEnum> , Error>{
        Ok(self.state.hooks.start_up_on_off())
    }

    async fn set_on_time(&self, _ctx:impl WriteContext, value:u16) -> Result<(), Error>{
        // todo check the spec for any required checks/error states
        self.state.on_time.set(value);
        Ok(())
    }
    
    async fn set_off_wait_time(&self, _ctx:impl WriteContext, value:u16) -> Result<(), Error>{
        // todo check the spec for any required checks/error states
        self.state.off_wait_time.set(value);
        Ok(())
    }
    
    async fn set_start_up_on_off(&self, _ctx:impl WriteContext, value: Nullable<StartUpOnOffEnum>) -> Result<(), Error>{
        // todo check the spec for any required checks/error states
        self.state.hooks.set_start_up_on_off(value)
    }
    
    // Commands
    async fn handle_off(&self, _ctx:impl InvokeContext,) -> Result<(), Error>  {
        // 1.5.7.1. Off Command
        // On receipt of the Off command, a server SHALL set the OnOff attribute to FALSE.
        self.state.hooks.set_on_off(false);

        // Additionally, when the OnTime attribute is supported, the server SHALL set the OnTime attribute to 0.
        if Self::CLUSTER.attribute(AttributeId::OnTime as _).is_some() {
            self.state.on_time.set(0);
        }

        // if LevelControl is coupled
        // LevelControl coupling logic defined in section 1.6.4.1.1
        // todo Call LevelControl coupled_on_off_cluster_on_off_state_change

        Ok(())
    }

    async fn handle_on(&self, _ctx:impl InvokeContext,) -> Result<(), Error>  {
        // 1.5.7.2. On Command
        // If the OffOnly feature is supported, on receipt of the On command, an UNSUPPORTED_COMMAND
        // failure status response SHALL be sent. 
        // Note: The validate method ensures the above statement.

        // Otherwise, on receipt of the On command, a server SHALL set the OnOff attribute to TRUE.
        self.state.hooks.set_on_off(true);

        // Additionally, when the OnTime and OffWaitTime attributes are both supported, if the value of the
        // OnTime attribute is equal to 0, the server SHALL set the OffWaitTime attribute to 0.
        if Self::CLUSTER.attribute(AttributeId::OnTime as _).is_some()
        && Self::CLUSTER.attribute(AttributeId::OffWaitTime as _).is_some()
        {
            if self.state.on_time.get() == 0 {
                self.state.off_wait_time.set(0)
            }
        }

        // if LevelControl is coupled
        // LevelControl coupling logic defined in section 1.6.4.1.1
        // todo Call LevelControl coupled_on_off_cluster_on_off_state_change

        Ok(())
    }

    async fn handle_toggle(&self, ctx:impl InvokeContext,) -> Result<(), Error>  {
        // 1.5.7.3. Toggle Command
        // If the OffOnly feature is supported, on receipt of the Toggle command, an
        // UNSUPPORTED_COMMAND failure status response SHALL be sent. 
        // Note: The validate method ensures the above statement.

        // Otherwise, on receipt of the
        // Toggle command, if the value of the OnOff attribute is equal to FALSE, the server SHALL set the
        // OnOff attribute to TRUE, otherwise, the server SHALL set the OnOff attribute to FALSE.
        // Additionally, when the OnTime and OffWaitTime attributes are both supported, if the value of the
        // OnOff attribute is equal to FALSE and if the value of the OnTime attribute is equal to 0, the server
        // SHALL set the OffWaitTime attribute to 0. If the value of the OnOff attribute is equal to TRUE, the
        // server SHALL set the OnTime attribute to 0.
        match !self.state.hooks.on_off() {
            true => self.handle_on(ctx).await,
            false => self.handle_off(ctx).await,
        }
    }

    async fn handle_off_with_effect(&self, _ctx:impl InvokeContext, request:OffWithEffectRequest<'_> ,) -> Result<(), Error>  {
        // 1.5.7.4.3. Effect on Receipt
        // On receipt of the OffWithEffect command the server SHALL check the value of the
        // GlobalSceneControl attribute.
        match self.state.global_scene_control.get() {
            // If the GlobalSceneControl attribute is equal to TRUE, the server SHALL store its settings in its global
            // scene then set the GlobalSceneControl attribute to FALSE, then set the OnOff attribute to FALSE and
            // if the OnTime attribute is supported set the OnTime attribute to 0.
            true => {
                // todo: store the GlobalSceneControl setting (true) in the global scene.

                self.state.global_scene_control.set(false);

                // todo this logic is repeated. Should we consolidate it?
                self.state.hooks.set_on_off(false);

                if Self::CLUSTER.attribute(AttributeId::OnTime as _).is_some() {
                    self.state.on_time.set(0);
                }
            },
            // If the GlobalSceneControl attribute is equal to FALSE, the server SHALL only set the OnOff attribute
            // to FALSE.
            false => {
                self.state.hooks.set_on_off(false);
            },
        }
        
        let effect_variant = match request.effect_identifier()? {
            EffectIdentifierEnum::DelayedAllOff => {
                match request.effect_variant()? {
                    // todo Impl TryFrom for DelayedAllOffEffectVariantEnum and remove this match.
                    0 => EffectVariantEnum::DelayedAllOff(DelayedAllOffEffectVariantEnum::DelayedOffFastFade),
                    1 => EffectVariantEnum::DelayedAllOff(DelayedAllOffEffectVariantEnum::NoFade),
                    2 => EffectVariantEnum::DelayedAllOff(DelayedAllOffEffectVariantEnum::DelayedOffSlowFade),
                    _ => return Err(ErrorCode::Failure.into()),
                }
            },
            EffectIdentifierEnum::DyingLight => {
                match request.effect_variant()? {
                    // todo Impl TryFrom for DyingLightEffectVariantEnum and remove this match.
                    0 => EffectVariantEnum::DyingLight(DyingLightEffectVariantEnum::DyingLightFadeOff),
                    _ => return Err(ErrorCode::Failure.into()),
                }
            },
        };

        // todo This needs to be executed in a thread.
        self.state.hooks.handle_off_with_effect(effect_variant);

        Ok(())
    }

    async fn handle_on_with_recall_global_scene(&self, _ctx:impl InvokeContext,) -> Result<(), Error>  {
        todo!()
    }

    async fn handle_on_with_timed_off(&self, _ctx:impl InvokeContext, _request:OnWithTimedOffRequest<'_> ,) -> Result<(), Error>  {
        todo!()
    }
}

enum OnOffClusterState {
    On,
    Off,
    TimedOn,
    TimedOff,
    DelayedOff,
}

/// Hold the state of the OnOff handler.
pub struct OnOffState<'a, H: OnOffHooks> {
    hooks: &'a H,
    state: OnOffClusterState,
    global_scene_control: Cell<bool>,
    on_time: Cell<u16>,
    off_wait_time: Cell<u16>,
    start_up_on_off: Cell<Nullable<StartUpOnOffEnum>>,
}

impl<'a, H: OnOffHooks> OnOffState<'a, H> {
    pub fn new(hooks: &'a H, default_startup_on_off: Nullable<StartUpOnOffEnum>) -> Self {
        let state = match hooks.on_off() {
            true => OnOffClusterState::On,
            false => OnOffClusterState::Off,
        };

        Self {
            hooks,
            state,
            global_scene_control: Cell::new(true),
            on_time: Cell::new(0),
            off_wait_time: Cell::new(0),
            start_up_on_off: Cell::new(default_startup_on_off),
        }
    }

    pub fn set_on_off(&self, on: bool, command_id: Option<CommandId>) {
        self.hooks.set_on_off(on);

        // todo unsure if this is correct.
        // 1.5.6.3. GlobalSceneControl Attribute
        // This attribute SHALL be set to TRUE after the reception of a command which causes the OnOff
        // attribute to be set to TRUE, such as a standard On command, a MoveToLevel(WithOnOff) command,
        // a RecallScene command or a OnWithRecallGlobalScene command.
        // This attribute is set to FALSE after reception of a OffWithEffect command
        if H::CLUSTER.attribute(AttributeId::GlobalSceneControl as _).is_some() {
            if command_id == Some(CommandId::OffWithEffect) {
                self.global_scene_control.set(false)
            }

            if on == true && command_id != Some(CommandId::OnWithRecallGlobalScene) {
                self.global_scene_control.set(true)
            }
        }
    }
}

pub enum EffectVariantEnum {
    DelayedAllOff(DelayedAllOffEffectVariantEnum),
    DyingLight(DyingLightEffectVariantEnum),
}

pub trait OnOffHooks {
    const CLUSTER: Cluster<'static>;

    // Get the current device on/off state. This value SHALL be persisted across reboots.
    fn on_off(&self) -> bool;
    // Switch the device to the `on`` value and persist this setting.
    fn set_on_off(&self, on: bool);

    // Get the start_up_on_off attribute. This value SHALL be persisted across reboots.
    fn start_up_on_off(&self) -> Nullable<StartUpOnOffEnum>;
    // Set the start_up_on_off attribute. This value SHALL be persisted across reboots.
    fn set_start_up_on_off(&self, value: Nullable<StartUpOnOffEnum>) -> Result<(), Error>;

    fn handle_off_with_effect(&self, effect: EffectVariantEnum);
}