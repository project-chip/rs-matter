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

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::Duration;

use crate::dm::clusters::decl::on_off;
use crate::dm::clusters::level_control::{LevelControlHandler, LevelControlHooks};
use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext, WriteContext};
use crate::error::{Error, ErrorCode};

pub use crate::dm::clusters::decl::on_off::*;

use crate::tlv::Nullable;

#[derive(Clone, Copy, PartialEq)]
enum OnOffClusterState {
    On,
    Off,
    TimedOn,
    DelayedOff,
}

#[derive(Clone, Copy)]
pub enum EffectVariantEnum {
    DelayedAllOff(DelayedAllOffEffectVariantEnum),
    DyingLight(DyingLightEffectVariantEnum),
}

// Internal enum for managing sending commands to the state machine.
enum OnOffCommand {
    Off,
    On,
    Toggle,
    OffWithEffect(EffectVariantEnum),
    OnWithTimedOff,
    CoupledClusterOn,
    CoupledClusterOff,
}

pub struct OnOffHandler<'a, H: OnOffHooks, LH: LevelControlHooks> {
    dataver: Dataver,
    hooks: &'a H,
    level_control_handler: Cell<Option<&'a LevelControlHandler<'a, LH, H>>>,
    state_change_signal: Signal<NoopRawMutex, OnOffCommand>,
    state: Cell<OnOffClusterState>,
    global_scene_control: Cell<bool>,
    on_time: Cell<u16>,
    off_wait_time: Cell<u16>,
}

impl<'a, H: OnOffHooks, LH: LevelControlHooks> OnOffHandler<'a, H, LH> {
    /// Creates a new instance of `OnOffHandler` with the given `Dataver`.
    pub fn new(dataver: Dataver, on_off_hooks: &'a H) -> Self {
        let state = match on_off_hooks.on_off() {
            true => OnOffClusterState::On,
            false => OnOffClusterState::Off,
        };

        Self {
            dataver,
            hooks: on_off_hooks,
            level_control_handler: Cell::new(None),
            state_change_signal: Signal::new(),
            state: Cell::new(state),
            global_scene_control: Cell::new(true),
            on_time: Cell::new(0),
            off_wait_time: Cell::new(0),
        }
    }

    /// Checks that the cluster is correctly configured, including required attributes, commands, and feature dependencies.
    ///
    /// # Panics
    ///
    /// panics with error message if the `state`'s `CLUSTER` is misconfigured.
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
        if self.supports_feature(on_off::Feature::LIGHTING.bits()) {
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
        if self.supports_feature(on_off::Feature::OFF_ONLY.bits()) {
            if Self::CLUSTER.command(CommandId::On as _).is_some()
            || Self::CLUSTER.command(CommandId::Toggle as _).is_some()
            {
                panic!("OnOff validation: extra commands while using OFFONLY feature: On, Toggle")
            }
        }
    }

    /// Initialise the cluster on startup.
    /// - wire coupled handlers
    /// - validate the handler setup with the configuration
    /// - update the OnOff state based on the StartUpOnOff attribute
    /// 
    /// # Parameters
    /// *level_control_handler: the LevelControlHandler instance coupled with this OnOffHandler, i.e. the LevelControl cluster on the same endpoint.
    ///
    /// # Panics
    ///
    /// panics if the `state`'s `CLUSTER` is misconfigured.
    pub fn init(&self, level_control_handler: Option<&'a LevelControlHandler<'a, LH, H>>) {

        // Wire any coupled clusters
        self.level_control_handler.set(level_control_handler);

        self.validate();

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
        if let Some(start_up_state) = self.hooks.start_up_on_off().into_option() {
            match start_up_state {
                StartUpOnOffEnum::Off => self.hooks.set_on_off(false),
                StartUpOnOffEnum::On => self.hooks.set_on_off(true),
                StartUpOnOffEnum::Toggle => self.hooks.set_on_off(!self.hooks.on_off()),
            }
        }
    }

    // todo is this needed given that this is Async?
    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    // todo Do we need similar accessors for all the attributes the user might want to access?
    pub(crate) fn on_off(&self) -> Result<bool, Error> {
        Ok(self.hooks.on_off())
    }

    fn set_on(&self, level_control_initiated: bool) {
        if self.hooks.on_off() == true {
            return;
        }

        // 1.5.7.2. On Command
        // ... on receipt of the On command, a server SHALL set the OnOff attribute to TRUE.
        self.hooks.set_on_off(true);

        // Note: The OnTime, OffWaitTime and GlobalScenesControl attributes are only supported and must 
        // be supported when the LIGHTING feature is enabled.
        // This configuration is ensured by the validate method upon initialisation.
        if self.supports_feature(on_off::Feature::LIGHTING.bits()) {
            // 1.5.7.2. On Command
            // ... when the OnTime and OffWaitTime attributes are both supported, if the value of the
            // OnTime attribute is equal to 0, the server SHALL set the OffWaitTime attribute to 0.
            if self.on_time.get() == 0 {
                self.off_wait_time.set(0)
            }

            // 1.5.6.3. GlobalSceneControl Attribute
            // This attribute SHALL be set to TRUE after the reception of a command which causes the OnOff
            // attribute to be set to TRUE, such as a standard On command, a MoveToLevel(WithOnOff) command,
            // a RecallScene command or a OnWithRecallGlobalScene command.
            self.global_scene_control.set(true)
        }

        // LevelControl coupling logic defined in section 1.6.4.1.1
        if !level_control_initiated {
            if let Some(level_control_handler) = self.level_control_handler.get() {
                level_control_handler.coupled_on_off_cluster_on_off_state_change(true);
            }
        }
    }

    /// Sets the on_off state to false.
    /// If a LevelControl cluster is coupled with this OnOff cluster and this command was not initiated by the 
    /// LevelControl cluster, the coupled flow is initiated.
    /// In this case, the method will not set the on_off state to false and returns false.
    /// Otherwise, we set the on_off state to false and return true.
    /// The return boolean indicates if the on_off state has been set.
    fn set_off(&self, level_control_initiated: bool) -> bool {
        if self.hooks.on_off() == false {
            return true;
        }

        if self.supports_feature(on_off::Feature::LIGHTING.bits()) {
            // 1.5.7.1. Off Command
            // ... when the OnTime attribute is supported, the server SHALL set the OnTime attribute to 0.
            self.on_time.set(0);
        }

        // LevelControl coupling logic defined in section 1.6.4.1.1
        if self.level_control_handler.get().is_some() & !level_control_initiated {
            // Use of unwrap is safe due to the previous check.
            self.level_control_handler.get().unwrap().coupled_on_off_cluster_on_off_state_change(false);
            // When calling the LevelControl with false (off), the levelControl cluster will call
            // back into the OnOff cluster to set the OnOff attribute to false when it is done.
            // Hence, we return without setting the on_off attribute.
            return false;
        }

        // 1.5.7.1. Off Command
        // On receipt of the Off command, a server SHALL set the OnOff attribute to FALSE.
        self.hooks.set_on_off(false);

        true
    }

    fn supports_feature(&self, features: u32) -> bool {
        H::CLUSTER.feature_map & features != 0
    }

    async fn handle_off_with_effect(&self, effect_variant: EffectVariantEnum)  {
        // 1.5.7.4.3. Effect on Receipt
        // On receipt of the OffWithEffect command the server SHALL check the value of the
        // GlobalSceneControl attribute.
        // If the GlobalSceneControl attribute is equal to TRUE, the server SHALL store its settings in its global
        // scene then set the GlobalSceneControl attribute to FALSE...
        if self.global_scene_control.get() {
            // todo: store the GlobalSceneControl setting (true) in the global scene.

            self.global_scene_control.set(false);
        }
        
        self.hooks.handle_off_with_effect(effect_variant).await;

        // This is set to true because in this case we do not want to also run the effects from the LevelControl cluster.
        let _ = self.set_off(true);
    }

    async fn state_machine(&self, command: OnOffCommand) {
        let start_time = embassy_time::Instant::now();

        // todo we should probably call Stop on the LevelControl cluster ??and similar from LevelControl to OnOff??.
        // if let Some(level_control_handler) = self.level_control_handler.get() {
        //     level_control_handler.stop();
        // }

        loop {
            match self.state.get() {
                OnOffClusterState::On => {
                    match command {
                        OnOffCommand::Off 
                        | OnOffCommand::Toggle => {
                            if self.set_off(false) {
                                self.state.set(OnOffClusterState::Off);
                            }
                            break;
                        },
                        OnOffCommand::CoupledClusterOff => {
                            self.set_off(true);
                            self.state.set(OnOffClusterState::Off);
                            break;
                        }
                        OnOffCommand::On
                        | OnOffCommand::CoupledClusterOn => break,
                        OnOffCommand::OffWithEffect(effect) => {
                            self.handle_off_with_effect(effect).await;
                            self.state.set(OnOffClusterState::Off);
                            break;
                        },
                        OnOffCommand::OnWithTimedOff => self.state.set(OnOffClusterState::TimedOn),
                    }
                },
                OnOffClusterState::Off => {
                    match command {
                        OnOffCommand::Off 
                        | OnOffCommand::OffWithEffect(_) 
                        | OnOffCommand::CoupledClusterOff => break,
                        OnOffCommand::On 
                        | OnOffCommand::Toggle => {
                            self.state.set(OnOffClusterState::On);
                            self.set_on(false);
                            break;
                        },
                        OnOffCommand::CoupledClusterOn => {
                            self.state.set(OnOffClusterState::On);
                            self.set_on(true);
                            break;
                        }
                        OnOffCommand::OnWithTimedOff => self.state.set(OnOffClusterState::TimedOn),
                    }
                },
                OnOffClusterState::TimedOn => {
                    match command {
                        OnOffCommand::Off 
                        | OnOffCommand::Toggle => {
                            info!("Got Off command from TimedOn state");
                            if self.set_off(false) {
                                self.state.set(OnOffClusterState::DelayedOff);
                            } else {
                                // If set_off returns false, we brake and expect to be called again by the CoupledClusterOff command.
                                break;
                            }
                        },
                        OnOffCommand::CoupledClusterOff => {
                            self.set_off(true);
                            self.state.set(OnOffClusterState::DelayedOff);
                        }
                        OnOffCommand::OffWithEffect(effect) => {
                            self.handle_off_with_effect(effect).await;
                            self.state.set(OnOffClusterState::DelayedOff);
                        },
                        // 1.5.7.6.4. Effect on Receipt
                        // If the value of the OnOff attribute is equal to TRUE and the value of the OnTime attribute is
                        // greater than zero, the server SHALL decrement the value of the OnTime attribute. If the value of
                        // the OnTime attribute reaches 0, the server SHALL set the OffWaitTime and OnOff attributes to 0
                        // and FALSE, respectively.
                        OnOffCommand::On 
                        | OnOffCommand::OnWithTimedOff => {
                            let mut next_tick = start_time + Duration::from_millis(100);
                            while self.on_time.get() > 0 {
                                let now = embassy_time::Instant::now();
                                if next_tick > now {
                                    embassy_time::Timer::after(next_tick - now).await;
                                }
                                self.on_time.set(self.on_time.get() - 1);
                                next_tick += Duration::from_millis(100);
                            }

                            self.off_wait_time.set(0);
                            if self.set_off(false) {
                                self.state.set(OnOffClusterState::Off);
                            }
                            break;
                        },
                        OnOffCommand::CoupledClusterOn => {
                            // This should not be reachable as the device would already be on so a change in the LevelControl cluster cannot cause the OnOff cluster to switch to On.
                        }
                    }
                },
                OnOffClusterState::DelayedOff => {
                    match command {
                        // 1.5.6.5. OffWaitTime Attribute
                        // This attribute specifies the length of time (in 1/10ths second) that the Off state SHALL be guarded to
                        // prevent another OnWithTimedOff command turning the server back to its On state.
                        OnOffCommand::On
                        | OnOffCommand::Toggle => {
                            self.state.set(OnOffClusterState::On);
                            self.set_on(false);
                            break;
                        },
                        OnOffCommand::CoupledClusterOn => {
                            self.state.set(OnOffClusterState::On);
                            self.set_on(true);
                            break;
                        },
                        OnOffCommand::Off
                        | OnOffCommand::OffWithEffect(_)
                        | OnOffCommand::OnWithTimedOff
                        | OnOffCommand::CoupledClusterOff => (),
                    }

                    // 1.5.7.6.4. Effect on Receipt
                    // If the value of the OnOff attribute is equal to FALSE and the value of the OffWaitTime attribute
                    // is greater than zero, the server SHALL decrement the value of the OffWaitTime attribute. If the
                    // value of the OffWaitTime attribute reaches 0, the server SHALL terminate the update.
                    let mut next_tick = embassy_time::Instant::now() + Duration::from_millis(100);
                    while self.off_wait_time.get() > 0 {
                        let now = embassy_time::Instant::now();
                        if next_tick > now {
                            embassy_time::Timer::after(next_tick - now).await;
                        }
                        self.off_wait_time.set(self.off_wait_time.get() - 1);
                        next_tick += Duration::from_millis(100);
                    }

                    self.state.set(OnOffClusterState::Off);
                    break;
                },
            }
        }
    }

    // The method that should be used by coupled clusters to update the on_off state.
    pub(crate) fn coupled_cluster_set_on_off(&self, on: bool) {
        info!(
            "OnOffCluster: coupled_cluster_set_on_off: Setting on_off to {}",
            on
        );

        match on {
            true => {
                if self.state.get() == OnOffClusterState::DelayedOff {
                    warn!("LevelControl is trying to set OnOff to true while the OnOff cluster is in the guarded 'Delayed Off' state");
                    return;
                }

                self.state_change_signal.signal(OnOffCommand::CoupledClusterOn);
            },
            false => self.state_change_signal.signal(OnOffCommand::CoupledClusterOff),
        }
    }
}

impl<'a, H: OnOffHooks, LH: LevelControlHooks> ClusterAsyncHandler for OnOffHandler<'a, H, LH> {
    #[doc = "The cluster-metadata corresponding to this handler trait."]
    const CLUSTER: Cluster<'static> = H::CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn run(&self) -> Result<(), Error>{
        loop {
            let mut command = self.state_change_signal.wait().await;

            loop {
                match embassy_futures::select::select(
                    self.state_machine(command),
                    self.state_change_signal.wait(),
                ).await {
                    embassy_futures::select::Either::First(_) => break,
                    embassy_futures::select::Either::Second(new_command) => command = new_command,
                }
            }
        }
    }
    
    // Attribute accessors
    async fn on_off(&self, _ctx:impl ReadContext) -> Result<bool, Error>  {
        Ok(self.hooks.on_off())
    }

    async fn global_scene_control(&self, _ctx:impl ReadContext) -> Result<bool, Error>{
        Ok(self.global_scene_control.get())
    }
    
    async fn on_time(&self, _ctx:impl ReadContext) -> Result<u16, Error>{
        Ok(self.on_time.get())
    }
    
    async fn off_wait_time(&self, _ctx:impl ReadContext) -> Result<u16, Error>{
        Ok(self.off_wait_time.get())
    }
    
    async fn start_up_on_off(&self, _ctx:impl ReadContext) -> Result<Nullable<StartUpOnOffEnum> , Error>{
        Ok(self.hooks.start_up_on_off())
    }

    async fn set_on_time(&self, _ctx:impl WriteContext, value:u16) -> Result<(), Error>{
        // todo check the spec for any required checks/error states
        self.on_time.set(value);
        Ok(())
    }
    
    async fn set_off_wait_time(&self, _ctx:impl WriteContext, value:u16) -> Result<(), Error>{
        // todo check the spec for any required checks/error states
        self.off_wait_time.set(value);
        Ok(())
    }
    
    async fn set_start_up_on_off(&self, _ctx:impl WriteContext, value: Nullable<StartUpOnOffEnum>) -> Result<(), Error>{
        // todo check the spec for any required checks/error states
        self.hooks.set_start_up_on_off(value)
    }
    
    // Commands
    async fn handle_off(&self, _ctx:impl InvokeContext,) -> Result<(), Error>  {
        self.state_change_signal.signal(OnOffCommand::Off);

        Ok(())
    }

    async fn handle_on(&self, _ctx:impl InvokeContext,) -> Result<(), Error>  {
        self.state_change_signal.signal(OnOffCommand::On);

        Ok(())
    }

    async fn handle_toggle(&self, _ctx:impl InvokeContext,) -> Result<(), Error>  {
        self.state_change_signal.signal(OnOffCommand::Toggle);

        Ok(())
    }

    async fn handle_off_with_effect(&self, _ctx:impl InvokeContext, request:OffWithEffectRequest<'_> ,) -> Result<(), Error>  {
        if !self.supports_feature(on_off::Feature::LIGHTING.bits()) {
            // This error is currently mapped to the IM status UnsupportedCommand.
            return Err(ErrorCode::CommandNotFound.into());
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

        // todo pass effect_variant 
        self.state_change_signal.signal(OnOffCommand::OffWithEffect(effect_variant));

        Ok(())
    }

    async fn handle_on_with_recall_global_scene(&self, _ctx:impl InvokeContext,) -> Result<(), Error>  {
        // 1.5.7.5.1. Effect on Receipt
        // On receipt of the OnWithRecallGlobalScene command, if the GlobalSceneControl attribute is equal
        // to TRUE, the server SHALL discard the command.
        if self.global_scene_control.get() == true {
            return Ok(());
        }

        // If the GlobalSceneControl attribute is equal to FALSE, the Scene cluster server on the same endpoint
        // SHALL recall its global scene, updating the OnOff attribute accordingly. The OnOff server SHALL
        // then set the GlobalSceneControl attribute to TRUE.
        // Additionally, when the OnTime and OffWaitTime attributes are both supported, if the value of the
        // OnTime attribute is equal to 0, the server SHALL set the OffWaitTime attribute to 0.
        // todo Implement the above statement once the Scene cluster is implemented.
        // self.set_on(false);

        // This error is currently mapped to the IM status UnsupportedCommand.
        Err(ErrorCode::CommandNotFound.into())
    }

    async fn handle_on_with_timed_off(&self, _ctx:impl InvokeContext, request:OnWithTimedOffRequest<'_> ,) -> Result<(), Error>  {
        // 1.5.7.6.4. Effect on Receipt
        // On receipt of this command, if the AcceptOnlyWhenOn sub-field of the OnOffControl field is set to 1,
        // and the value of the OnOff attribute is equal to FALSE, the command SHALL be discarded.
        // todo It's unclear if this command should be ignored if the OnOff attribute is FALSE or if the state,
        // according to section 1.5.8, is "Off". It is possible for the device to get the OnWithTimedOff command 
        // while it is in the "delayed Off" state. In this case, should the OffWaitTime be update as describe below,
        // or should it be ignored? If it should be ignored, do we remain in the "Delayed Off" state, decrementing
        // the OffWaitTime?
        if request.on_off_control()?.contains(OnOffControlBitmap::ACCEPT_ONLY_WHEN_ON) 
        && self.state.get() == OnOffClusterState::Off
        {
            return Ok(());
        }

        // If the value of the OffWaitTime attribute is greater than zero and the value of the OnOff attribute is
        // equal to FALSE, then the server SHALL set the OffWaitTime attribute to the minimum of the
        // OffWaitTime attribute and the value specified in the OffWaitTime field.
        if self.off_wait_time.get() > 0 && self.hooks.on_off() == false {
            self.off_wait_time.set(self.off_wait_time.get().min(request.off_wait_time()?));
        }
        // In all other cases, the server SHALL set the OnTime attribute to the maximum of the OnTime
        // attribute and the value specified in the OnTime field, set the OffWaitTime attribute to the value
        // specified in the OffWaitTime field and set the OnOff attribute to TRUE.
        else {
            self.on_time.set(self.on_time.get().max(request.on_time()?));
            self.off_wait_time.set(request.off_wait_time()?);
            self.set_on(false);
        }

        // If the values of the OnTime and OffWaitTime attributes are both not equal to 0xFFFF, the server
        // SHALL then update these attributes every 1/10th second until both the OnTime and OffWaitTime
        // attributes are equal to 0, as follows:
        if self.on_time.get() == 0xFFFF && self.off_wait_time.get() == 0xFFFF {
            return Ok(());
        }

        self.state_change_signal.signal(OnOffCommand::OnWithTimedOff);

        Ok(())
    }
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

    async fn handle_off_with_effect(&self, effect: EffectVariantEnum);
}