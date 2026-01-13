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

//! Implementation of the Matter Level Control cluster.
//!
//! This module provides the core logic and state management for the LevelControl cluster as defined by the Matter specification v1.3.
//! It handles commands and attributes related to device level control, such as dimming lights or adjusting motor positions.
//! The implementation supports asynchronous transitions, step and move operations, and integration with the OnOff cluster.
//!
//! Key features:
//! - Validates cluster configuration and feature dependencies.
//! - Manages level transitions with optional timing and rate control.
//! - Supports quiet reporting of attribute changes according to specification rules.
//! - Provides hooks for device-specific logic via the `LevelControlHooks` trait.
//! - Designed for extensibility and integration with other clusters (e.g., OnOff).

use core::cell::Cell;
use core::future::{pending, Future};
use core::ops::Mul;
use core::pin::pin;

use embassy_futures::select::{select, select3, Either, Either3};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant};

pub use crate::dm::clusters::decl::level_control::*;
use crate::dm::clusters::on_off::{OnOffHooks, FULL_CLUSTER as ON_OFF_FULL_CLUSTER};
use crate::dm::clusters::{level_control, on_off::OnOffHandler};
use crate::dm::{
    Cluster, Dataver, EndptId, HandlerContext, InvokeContext, ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::Nullable;

/// Messages passed to the `notify` closure in `LevelControlHooks::run()` method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OutOfBandMessage {
    /// Indicates to the handler that the value of the current level has change and it should update the Matter state accordingly.
    /// Takes the new value of the CurrentLevel.
    Update(u8),
    /// Initiates a MoveToLevel command.
    /// This will change the state of the device if and when appropriate according to Matter logic.
    /// See Matter Application Clusters specification section 1.6.7.1.
    MoveToLevel {
        with_on_off: bool,
        level: u8,
        transition_time: Option<u16>,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    },
    /// Initiates a Move command.
    /// This will change the state of the device if and when appropriate according to Matter logic.
    /// See Matter Application Clusters specification section 1.6.7.2.
    Move {
        with_on_off: bool,
        move_mode: MoveModeEnum,
        rate: Option<u8>,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    },
    /// Initiates a Step command.
    /// This will change the state of the device if and when appropriate according to Matter logic.
    /// See Matter Application Clusters specification section 1.6.7.3.
    Step {
        with_on_off: bool,
        step_mode: StepModeEnum,
        step_size: u8,
        transition_time: Option<u16>,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    },
    /// Stop any running LevelControl transitions.
    Stop,
}

enum Task {
    MoveToLevel {
        with_on_off: bool,
        target: u8,
        transition_time: u16,
    },
    Move {
        with_on_off: bool,
        move_mode: MoveModeEnum,
        event_duration: Duration,
    },
    Stop,
    OnOffStateChange {
        on: bool,
    },
}

/// Implementation of the LevelControlHandler, providing functionality for the Matter Level Control cluster.
///
/// # Type Parameters
/// - `'a`: Lifetime for references held by the cluster.
/// - `H`: Handler implementing the LevelControlHooks trait, providing cluster-specific configuration and logic.
/// - `OH` : Handler implementing the OnOffHooks trait.
///
/// # Constants
/// - `MAXIMUM_LEVEL`: The maximum allowed level value (254).
///
/// # Panics
/// - Initialisation panics if the cluster configuration is invalid or required attributes/commands are missing.
///
/// # Notes
/// - This implementation follows version 1.3 of the Matter specification.
pub struct LevelControlHandler<'a, H: LevelControlHooks, OH: OnOffHooks> {
    dataver: Dataver,
    endpoint_id: EndptId,
    hooks: H,
    on_off_handler: Cell<Option<&'a OnOffHandler<'a, OH, H>>>,
    task_signal: Signal<NoopRawMutex, Task>,
    on_level: Cell<Nullable<u8>>,
    options: Cell<OptionsBitmap>,
    remaining_time: Cell<u16>,
    on_off_transition_time: Cell<u16>,
    on_transition_time: Cell<Nullable<u16>>,
    off_transition_time: Cell<Nullable<u16>>,
    default_move_rate: Cell<Nullable<u8>>,
    previous_current_level: Cell<Option<u8>>,
    last_current_level_notification: Cell<Instant>,
}

/// Default values for the attributes with manufacturer specific defaults.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttributeDefaults {
    pub on_level: Nullable<u8>,
    pub options: OptionsBitmap,
    pub on_off_transition_time: u16,
    pub on_transition_time: Nullable<u16>,
    pub off_transition_time: Nullable<u16>,
    pub default_move_rate: Nullable<u8>,
}

impl AttributeDefaults {
    /// Creates an `AttributeDefaults` instance with default values.
    ///
    /// # Default Values
    /// - `on_level`: `Nullable::none()` (not set)
    /// - `options`: 0 (no options set)
    /// - `on_off_transition_time`: 0 (no transition delay by default)
    /// - `on_transition_time`: `Nullable::none()` (not set)
    /// - `off_transition_time`: `Nullable::none()` (not set)
    /// - `default_move_rate`: `Nullable::none()` (not set)
    pub const fn new() -> Self {
        Self {
            on_level: Nullable::none(),
            options: OptionsBitmap::from_bits(0).unwrap(),
            on_off_transition_time: 0,
            on_transition_time: Nullable::none(),
            off_transition_time: Nullable::none(),
            default_move_rate: Nullable::none(),
        }
    }
}

impl Default for AttributeDefaults {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: LevelControlHooks> LevelControlHandler<'_, H, NoOnOff> {
    /// Creates a new `LevelControlHandler` with the given hooks which is **not** coupled to an OnOff cluster.
    ///
    /// NOTE: This constructor automatically calls `init` with no coupled `OnOff` handler.
    ///
    /// # Arguments
    /// - `hooks` - A reference to the struct implementing the device-specific level control logic.
    pub fn new_standalone(
        dataver: Dataver,
        endpoint_id: EndptId,
        hooks: H,
        attribute_defaults: AttributeDefaults,
    ) -> Self {
        let this = Self::new(dataver, endpoint_id, hooks, attribute_defaults);

        this.init(None);

        this
    }
}

impl<'a, H: LevelControlHooks, OH: OnOffHooks> LevelControlHandler<'a, H, OH> {
    const MAXIMUM_LEVEL: u8 = 254;

    /// Creates a new `LevelControlHandler` with the given hooks.
    ///
    /// # Arguments
    /// - `hooks` - A reference to the struct implementing the device-specific level control logic.
    ///
    /// # Usage
    /// - Initialise and optionally couple with an OnOff handler via `init`.
    pub fn new(
        dataver: Dataver,
        endpoint_id: EndptId,
        hooks: H,
        attribute_defaults: AttributeDefaults,
    ) -> Self {
        Self {
            dataver,
            endpoint_id,
            hooks,
            on_off_handler: Cell::new(None),
            task_signal: Signal::new(),
            on_level: Cell::new(attribute_defaults.on_level),
            options: Cell::new(attribute_defaults.options),
            remaining_time: Cell::new(0),
            on_off_transition_time: Cell::new(attribute_defaults.on_off_transition_time),
            on_transition_time: Cell::new(attribute_defaults.on_transition_time),
            off_transition_time: Cell::new(attribute_defaults.off_transition_time),
            default_move_rate: Cell::new(attribute_defaults.default_move_rate),
            previous_current_level: Cell::new(None),
            last_current_level_notification: Cell::new(Instant::from_millis(0)),
        }
    }

    /// Checks that the cluster is correctly configured, including required attributes, commands, and feature dependencies.
    ///
    /// # Panics
    ///
    /// panics with error message if the `state`'s `CLUSTER` is misconfigured.
    fn validate(&self) {
        if H::CLUSTER.revision != 6 {
            panic!(
                "LevelControl validation: incorrect version number: expected 5 got {}",
                H::CLUSTER.revision
            );
        }

        // Check for mandatory attributes
        if H::CLUSTER
            .attribute(AttributeId::CurrentLevel as _)
            .is_none()
            || H::CLUSTER.attribute(AttributeId::OnLevel as _).is_none()
            || H::CLUSTER.attribute(AttributeId::Options as _).is_none()
        {
            panic!("LevelControl validation: missing required attributes: CurrentLevel, OnLevel, or Options");
        }

        // Check for mandatory commands
        if H::CLUSTER.command(CommandId::MoveToLevel as _).is_none()
            || H::CLUSTER.command(CommandId::Move as _).is_none()
            || H::CLUSTER.command(CommandId::Step as _).is_none()
            || H::CLUSTER.command(CommandId::Stop as _).is_none()
            || H::CLUSTER
                .command(CommandId::MoveToLevelWithOnOff as _)
                .is_none()
            || H::CLUSTER.command(CommandId::MoveWithOnOff as _).is_none()
            || H::CLUSTER.command(CommandId::StepWithOnOff as _).is_none()
            || H::CLUSTER.command(CommandId::StopWithOnOff as _).is_none()
        {
            panic!("LevelControl validation: missing required commands: MoveToLevel, Move, Step, Stop, MoveToLevelWithOnOff, MoveWithOnOff, StepWithOnOff or StopWithOnOff");
        }

        // If the ON_OFF feature in enabled, check that an OnOff cluster is coupled.
        if H::CLUSTER.feature_map & level_control::Feature::ON_OFF.bits() != 0 {
            // Ideally we should confirm that they are on the same endpoint.
            if self.on_off_handler.get().is_none() {
                panic!("LevelControl validation: a reference to the OnOff cluster must be set when the ON_OFF feature is enabled");
            }
        }

        if H::MAX_LEVEL > Self::MAXIMUM_LEVEL {
            panic!(
                "LevelControl validation: the MAX_LEVEL cannot be higher than {}",
                Self::MAXIMUM_LEVEL
            );
        }

        if H::CLUSTER.feature_map & level_control::Feature::LIGHTING.bits() != 0 {
            // From section 1.6.4.2
            // A value of 0x00 SHALL NOT be used.
            // A value of 0x01 SHALL indicate the minimum level that can be attained on a device.
            // A value of 0xFE SHALL indicate the maximum level that can be attained on a device.
            if H::MIN_LEVEL == 0 {
                panic!("LevelControl validation: MIN_LEVEL cannot be 0 when the LIGHTING feature is enabled");
            }

            // Check for required attributes when using this feature
            if H::CLUSTER
                .attribute(AttributeId::RemainingTime as _)
                .is_none()
                || H::CLUSTER
                    .attribute(AttributeId::StartUpCurrentLevel as _)
                    .is_none()
            {
                panic!("LevelControl validation: the RemainingTime and StartUpCurrentLevel attributes are required by the LIGHTING feature");
            }
        }
    }

    /// Initializes the cluster on startup;
    /// - wire coupled handlers
    /// - validate the handler setup with the configuration
    /// - set the CurrentLevel attribute according to the StartUpCurrentLevel attribute.
    ///
    /// # Parameters
    /// *on_off_handler: the OnOffHandler instance coupled with this LevelControlHandler, i.e. the OnOff cluster on the same endpoint. This should be set if the OnOff feature is set.
    ///
    /// # Panics
    ///
    /// panics if the `state`'s `CLUSTER` is misconfigured.
    pub fn init(&self, on_off_handler: Option<&'a OnOffHandler<'a, OH, H>>) {
        // 1.6.6.15. StartUpCurrentLevel Attribute
        // This attribute SHALL indicate the desired startup level for a device when it is supplied with power
        // and this level SHALL be reflected in the CurrentLevel attribute. The values of the
        // StartUpCurrentLevel attribute are listed below:
        // | Value        | Action on power up |
        // |--------------| -------------------|
        // | 0            | Set the CurrentLevel attribute to the minimum value permitted on the device |
        // | null         | Set the CurrentLevel attribute to its previous value |
        // | other values | Set the CurrentLevel attribute to this value |
        // todo: Implement checking the reason for reboot.
        // This behavior does not apply to reboots associated with OTA. After an OTA restart, the CurrentLevel
        // attribute SHALL return to its value prior to the restart.

        // Wire any coupled clusters
        self.on_off_handler.set(on_off_handler);

        self.validate();

        // `self.hooks` holds the previous current level as supplied by the SDK consumer.
        // Hence, if this process errors, we quietly abort resulting in the previous current level.
        if let Ok(Some(startup_current_level)) = self.hooks.start_up_current_level() {
            // The spec fails to mention the need for this bounding.
            let level = if startup_current_level < H::MIN_LEVEL {
                H::MIN_LEVEL
            } else if startup_current_level > H::MAX_LEVEL {
                H::MAX_LEVEL
            } else {
                startup_current_level
            };

            match self.hooks.set_device_level(level) {
                Ok(current_level) => self.hooks.set_current_level(current_level),
                Err(_) => error!("Failed to set Current Level to Start Up Current Level."),
            }
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }

    // Helper accessors for `Nullable` attributes.
    fn on_level(&self) -> Nullable<u8> {
        let val = self.on_level.take();
        self.on_level.set(val.clone());
        val
    }

    fn on_transition_time(&self) -> Nullable<u16> {
        let val = self.on_transition_time.take();
        self.on_transition_time.set(val.clone());
        val
    }

    fn off_transition_time(&self) -> Nullable<u16> {
        let val = self.off_transition_time.take();
        self.off_transition_time.set(val.clone());
        val
    }

    fn default_move_rate(&self) -> Nullable<u8> {
        let val = self.default_move_rate.take();
        self.default_move_rate.set(val.clone());
        val
    }

    /// Updates the RemainingTime attribute and returns true if a Matter notification is required.
    /// Matter notifications, reporting changes to this attribute, are only required under specific conditions.
    ///
    /// # Arguments
    /// - `remaining_time` - The new remaining time.
    /// - `is_start_of_transition` - Indicates if this is the start of a transition.
    fn write_remaining_time_quietly(
        &self,
        remaining_time: Duration,
        is_start_of_transition: bool,
    ) -> bool {
        let remaining_time_ds = remaining_time.as_millis().div_ceil(100) as u16;

        // RemainingTime Quiet report conditions:
        // - When it changes to 0, or
        // - When it changes from 0 to any value higher than 10, or
        // - When it changes, with a delta larger than 10, caused by the invoke of a command.
        let previous_remaining_time = self.remaining_time.get();
        let changed_to_zero = remaining_time_ds == 0 && previous_remaining_time != 0;
        let changed_from_zero_gt_10 = previous_remaining_time == 0 && remaining_time_ds > 10;
        let changed_by_gt_10 =
            remaining_time_ds.abs_diff(previous_remaining_time) > 10 && is_start_of_transition;

        self.remaining_time.set(remaining_time_ds);

        if changed_to_zero || changed_from_zero_gt_10 || changed_by_gt_10 {
            return true;
        }

        false
    }

    /// Sets the CurrentLevel attribute.
    /// If `set_device` is true, this method sets the level of the device, via the `set_level` hook.
    /// This method calculates if a Matter notification is required according to the quiet reporting conditions described in the spec.
    ///
    /// # Arguments
    /// - `level` - The new current level.
    /// - `is_end_of_transition` - Indicates if this is the end of a transition.
    /// - `set_device` - Indicates if the state of the physical device should be changed.
    ///
    /// # Returns
    /// A tuple with the current level of the device, and a boolean signifying if a Matter notification is required.
    fn set_level(
        &self,
        level: u8,
        is_end_of_transition: bool,
        set_device: bool,
    ) -> Result<(Option<u8>, bool), Error> {
        // Store the previous current level before updating, for quiet reporting logic.
        self.previous_current_level.set(self.hooks.current_level());
        let current_level = match set_device {
            true => self
                .hooks
                .set_device_level(level)
                .map_err(|_| ErrorCode::Failure)?,
            false => Some(level),
        };
        self.hooks.set_current_level(current_level);
        let last_notification = Instant::now() - self.last_current_level_notification.get();

        // CurrentLevel Quiet report conditions:
        // - At most once per second, or
        // - At the end of the movement/transition, or
        // - When it changes from null to any other value and vice versa.
        if last_notification.ge(&Duration::from_secs(1))
            || is_end_of_transition
            || self.previous_current_level.get().is_none()
            || current_level.is_none()
        {
            self.last_current_level_notification.set(Instant::now());
            return Ok((current_level, true));
        }

        Ok((current_level, false))
    }

    /// Checks if a command should proceed beyond the Options processing.
    /// Returns true if execution of the command should continue, false otherwise.
    //
    // From section 1.6.6.9
    // Command execution SHALL NOT continue beyond the Options processing if all of these criteria are true:
    // - The command is one of the ‘without On/Off’ commands: Move, Move to Level, Step, or Stop.
    // - The On/Off cluster exists on the same endpoint as this cluster.
    // - The OnOff attribute of the On/Off cluster, on this endpoint, is FALSE.
    // - The value of the ExecuteIfOff bit is 0.
    fn should_continue(
        &self,
        with_on_off: bool,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<bool, Error> {
        if with_on_off {
            return Ok(true);
        }

        let on_off_state = match self.on_off_handler.get() {
            Some(on_off_state) => on_off_state,
            None => {
                // This should be sufficient to satisfy "The On/Off cluster exists on the same endpoint as this cluster"
                // if we can check the NODE configuration in validate.
                return Ok(true);
            }
        };

        if on_off_state.on_off() {
            return Ok(true);
        }

        // The OptionsMask and OptionsOverride fields SHALL both be present. Default values are provided
        // to interpret missing fields from legacy devices. A temporary Options bitmap SHALL be created from
        // the Options attribute, using the OptionsMask and OptionsOverride fields. Each bit of the temporary
        // Options bitmap SHALL be determined as follows:
        // Each bit in the Options attribute SHALL determine the corresponding bit in the temporary Options
        // bitmap, unless the OptionsMask field is present and has the corresponding bit set to 1, in which
        // case the corresponding bit in the OptionsOverride field SHALL determine the corresponding bit in
        // the temporary Options bitmap.
        if options_mask.contains(level_control::OptionsBitmap::EXECUTE_IF_OFF) {
            return Ok(options_override.contains(level_control::OptionsBitmap::EXECUTE_IF_OFF));
        }

        Ok(self
            .options
            .get()
            .contains(level_control::OptionsBitmap::EXECUTE_IF_OFF))
    }

    /// Handles asynchronous tasks for level transitions and moves.
    async fn task_manager(&self, ctx: impl HandlerContext, task: Task) {
        match task {
            Task::MoveToLevel {
                with_on_off,
                target,
                transition_time,
            } => {
                if let Err(e) = self
                    .move_to_level_transition(ctx, with_on_off, target, transition_time)
                    .await
                {
                    error!("Task::MoveToLevel: {:?}", e);
                }
            }
            Task::Move {
                with_on_off,
                move_mode,
                event_duration,
            } => {
                if let Err(e) = self
                    .move_transition(ctx, with_on_off, move_mode, event_duration)
                    .await
                {
                    error!("Task::Move: {:?}", e);
                }
            }
            Task::Stop => (),
            Task::OnOffStateChange { on } => {
                if let Err(e) = self.handle_on_off_state_change(ctx, on).await {
                    error!("Task::OnOffStateChange: {:?}", e);
                }
            }
        }
    }

    /// This method is called by an OnOff cluster that is coupled with this LevelControl cluster.
    /// This method updates the CurrentLevel of the device when the state of the OnOff cluster changes.
    pub(crate) fn coupled_on_off_cluster_on_off_state_change(&self, on: bool) {
        self.task_signal.signal(Task::OnOffStateChange { on });
    }

    // From section 1.6.4.1.1
    // ## On
    // Temporarily store CurrentLevel.
    // Set CurrentLevel to the minimum level allowed for the device.
    // Change CurrentLevel to OnLevel, or to the stored level if OnLevel is not defined, over the time period OnOffTransitionTime.
    // ## off
    // Temporarily store CurrentLevel.
    // Change CurrentLevel to the minimum level allowed for the device over the time period OnOffTransitionTime.
    // If OnLevel is not defined, set the CurrentLevel to the stored level.
    async fn handle_on_off_state_change(
        &self,
        ctx: impl HandlerContext,
        on: bool,
    ) -> Result<(), Error> {
        info!("handle_on_off_state_change");

        let temp_current_level = self.hooks.current_level();

        // use of unwrap is justified since this will option is always valid.
        let bitmap = OptionsBitmap::from_bits(0).unwrap();

        // 1.6.6.10. OnOffTransitionTime Attribute
        // This attribute SHALL indicate the time taken to move to or from the target level when On or Off
        // commands are received by an On/Off cluster on the same endpoint.
        let mut transition_time = self.on_off_transition_time.get();

        match on {
            true => {
                let (level, should_notify) = self.set_level(H::MIN_LEVEL, false, true)?;
                if should_notify {
                    self.dataver_changed();
                    ctx.notify_attribute_changed(
                        self.endpoint_id,
                        Self::CLUSTER.id,
                        AttributeId::CurrentLevel as _,
                    );
                }
                if level.is_none() {
                    return Err(ErrorCode::Failure.into());
                }

                let target_level = match self.on_level().into_option() {
                    Some(on_level) => on_level,
                    None => temp_current_level.ok_or(ErrorCode::Failure)?,
                };

                // 1.6.6.12. OnTransitionTime Attribute
                // This attribute SHALL indicate the time taken to move the current level from the minimum level to
                // the maximum level when an On command is received by an On/Off cluster on the same endpoint.
                // If this attribute is not implemented, or contains a null value, the
                // OnOffTransitionTime SHALL be used instead.
                if let Some(tt) = self.on_transition_time().into_option() {
                    transition_time = tt;
                }

                self.move_to_level_blocking(
                    ctx,
                    true,
                    target_level,
                    Some(transition_time),
                    bitmap,
                    bitmap,
                )
                .await?;
            }
            false => {
                // 1.6.6.13. OffTransitionTime Attribute
                // This attribute SHALL indicate the time taken to move the current level from the maximum level to
                // the minimum level when an Off command is received by an On/Off cluster on the same endpoint.
                // If this attribute is not implemented, or contains a null value, the
                // OnOffTransitionTime SHALL be used instead.
                if let Some(tt) = self.off_transition_time().into_option() {
                    transition_time = tt;
                }

                self.move_to_level_blocking(
                    ctx,
                    true,
                    H::MIN_LEVEL,
                    Some(transition_time),
                    bitmap,
                    bitmap,
                )
                .await?;

                if self.on_level().is_none() {
                    self.hooks.set_current_level(temp_current_level);
                }
            }
        };

        Ok(())
    }

    /// Updates the OnOff attribute of the coupled OnOff cluster based on the current level and command type.
    //
    // From section 1.6.4.1.2
    // When the level is reduced to its minimum the OnOff attribute is automatically turned to FALSE,
    // and when the level is increased above its minimum the OnOff attribute is automatically turned to TRUE.
    fn update_coupled_on_off(&self, current_level: u8, with_on_off: bool) -> Result<(), Error> {
        // From section 1.6.4.1.2.
        // There are two sets of commands provided in the Level Control cluster. These are identical, except
        // that the first set (MoveToLevel, Move and Step commands) SHALL NOT affect the OnOff attribute,
        // whereas the second set ('with On/Off' variants) SHALL.
        if !with_on_off {
            return Ok(());
        }

        let new_on_off_value = current_level > H::MIN_LEVEL;

        // The `validate` method ensures that the on_off_handler is set if this function is called.
        if let Some(on_off) = self.on_off_handler.get() {
            let current_on_off = on_off.on_off();
            if current_on_off != new_on_off_value {
                info!(
                    "Updating the OnOff cluster with on_off = {}",
                    new_on_off_value
                );
                on_off.coupled_cluster_set_on_off(new_on_off_value);
            }
        }

        Ok(())
    }

    // Helper method performing initial validation for the move-to-level command.
    // Used by move_to_level and move_to_level_blocking.
    // Return true if processing should continue. False otherwise.
    fn move_to_level_validation(
        &self,
        level: &mut u8,
        with_on_off: bool,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<bool, Error> {
        if *level > Self::MAXIMUM_LEVEL {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if !self.should_continue(with_on_off, options_mask, options_override)? {
            return Ok(false);
        }

        if *level > H::MAX_LEVEL {
            *level = H::MAX_LEVEL;
            debug!("target level > MAX_LEVEL. level set to MAX_LEVEL")
        } else if *level < H::MIN_LEVEL {
            *level = H::MIN_LEVEL;
            debug!("target level < MIN_LEVEL. level set to MIN_LEVEL")
        }

        Ok(true)
    }

    /// Handles MoveToLevel commands, including validation, bounding, and transition logic.
    /// Note: This will try to update the OnOff cluster's OnOff attribute at the start and end of the transition.
    /// Note: If calling this from another Task, use the blocking version `move_to_level_blocking`, otherwise the calling Task will be halted.
    ///
    /// # Parameters
    ///
    /// * with_on_off: Is the LevelControl command calling this method one of the "WithOnOff" variant?
    /// * level: The target level to move to.
    /// * transition_time: The time for the transition in 1/10ts of a second.
    /// * options_mask: The options mask in the command attributes.
    /// * options_override: The options override in the command attributes.
    fn move_to_level(
        &self,
        with_on_off: bool,
        mut level: u8,
        transition_time: Option<u16>,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if let Ok(false) =
            self.move_to_level_validation(&mut level, with_on_off, options_mask, options_override)
        {
            return Ok(());
        }

        info!(
            "setting level to {} with transition time {:?}",
            level, transition_time
        );

        // Stop any ongoing transitions and check if we happen to be where we need to be.
        // If so, there is nothing to do.
        self.task_signal.signal(Task::Stop);
        if self.hooks.current_level() == Some(level) {
            self.update_coupled_on_off(level, with_on_off)?;
            return Ok(());
        }

        let t_time = transition_time.unwrap_or(0);

        self.task_signal.signal(Task::MoveToLevel {
            with_on_off,
            target: level,
            transition_time: t_time,
        });

        Ok(())
    }

    // This version does not call Task::Stop. If we are called from another Task, we shouldn't stop it.
    /// Handles MoveToLevel commands, including validation, bounding, and transition logic.
    /// Note: This will try to update the OnOff cluster's OnOff attribute at the start and end of the transition.
    /// Note: This will block until the transition completes.
    ///
    /// # Parameters
    ///
    /// * with_on_off: Is the LevelControl command calling this method one of the "WithOnOff" variant?
    /// * level: The target level to move to.
    /// * transition_time: The time for the transition in 1/10ts of a second.
    /// * options_mask: The options mask in the command attributes.
    /// * options_override: The options override in the command attributes.
    async fn move_to_level_blocking(
        &self,
        ctx: impl HandlerContext,
        with_on_off: bool,
        mut level: u8,
        transition_time: Option<u16>,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if let Ok(false) =
            self.move_to_level_validation(&mut level, with_on_off, options_mask, options_override)
        {
            return Ok(());
        }

        info!(
            "setting level to {} with transition time {:?}",
            level, transition_time
        );

        if self.hooks.current_level() == Some(level) {
            self.update_coupled_on_off(level, with_on_off)?;
            return Ok(());
        }

        let t_time = transition_time.unwrap_or(0);

        self.move_to_level_transition(ctx, with_on_off, level, t_time)
            .await?;

        Ok(())
    }

    /// Asynchronously transitions the current level to a target level over a specified time.
    /// Note: This will try to update the OnOff cluster's OnOff attribute at the start and end of the transition.
    async fn move_to_level_transition(
        &self,
        ctx: impl HandlerContext,
        with_on_off: bool,
        target_level: u8,
        transition_time: u16,
    ) -> Result<(), Error> {
        let event_start_time = Instant::now();

        // Check if current_level is null. If so, return error.
        let mut current_level = match self.hooks.current_level() {
            Some(cl) => cl,
            None => return Err(ErrorCode::Failure.into()),
        };

        let increasing = current_level < target_level;

        let steps = target_level.abs_diff(current_level);

        if steps == 0 {
            return Ok(());
        }

        let mut remaining_time = Duration::from_millis(transition_time as u64 * 100);
        let event_duration = Duration::from_millis_floor(remaining_time.as_millis() / steps as u64);

        let startup_latency = Instant::now() - event_start_time;
        loop {
            let event_start_time = Instant::now();

            if transition_time == 0 {
                current_level = target_level;
            } else {
                match increasing {
                    true => current_level += 1,
                    false => current_level -= 1,
                }
            }

            let is_transition_start = remaining_time.as_millis() == (transition_time as u64 * 100);
            let is_transition_end = current_level == target_level;

            debug!(
                "move_to_level_transition: Setting current level: {}",
                current_level
            );
            let (current_level, should_notify) =
                self.set_level(current_level, is_transition_end, true)?;
            let current_level = match current_level {
                Some(level) => level,
                None => return Err(ErrorCode::Failure.into()),
            };

            if is_transition_start || is_transition_end {
                self.update_coupled_on_off(current_level, with_on_off)?;
            }

            if is_transition_end {
                if should_notify
                    || self
                        .write_remaining_time_quietly(Duration::from_millis(0), is_transition_start)
                {
                    self.dataver_changed();
                    ctx.notify_attribute_changed(
                        self.endpoint_id,
                        Self::CLUSTER.id,
                        AttributeId::CurrentLevel as _,
                    );
                }
                return Ok(());
            }

            match remaining_time > event_duration {
                true => remaining_time -= event_duration,
                false => {
                    warn!("remaining time is 0 before level reached target");
                    remaining_time = Duration::from_millis(0)
                }
            }

            if should_notify
                || self.write_remaining_time_quietly(remaining_time, is_transition_start)
            {
                self.dataver_changed();
                ctx.notify_attribute_changed(
                    self.endpoint_id,
                    Self::CLUSTER.id,
                    AttributeId::CurrentLevel as _,
                );
            }

            let latency = match is_transition_start {
                false => embassy_time::Instant::now() - event_start_time,
                true => (embassy_time::Instant::now() - event_start_time) + startup_latency,
            };
            match event_duration.checked_sub(latency) {
                Some(wait_time) => embassy_time::Timer::after(wait_time).await,
                None => warn!("no wait time. Consider dynamically adjusting the step size?"),
            }
        }
    }

    /// Handles Move commands, determining the rate and initiating transitions.
    fn move_command(
        &self,
        with_on_off: bool,
        move_mode: MoveModeEnum,
        rate: Option<u8>,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        // From Section 1.6.7.2.2
        //
        // If the Rate field is null, then the value of the
        // DefaultMoveRate attribute SHALL be used if that attribute is supported and its value is not null. If
        // the Rate field is null and the DefaultMoveRate attribute is either not supported or set to null, then
        // the device SHOULD move as fast as it is able.
        let rate = match rate {
            // Move at a rate of zero is no move at all. Immediately succeed without touching anything.
            Some(0) => return Ok(()),
            Some(val) => val,
            None => match self.default_move_rate().into_option() {
                Some(val) => val,
                None => H::FASTEST_RATE,
            },
        };

        // This will catch the case where H::FASTEST_RATE is 0.
        // The spec is not explicit about what should be done if this happens.
        // For now we error out if DefaultMoveRate is equal to 0 as this is invalid
        // until spec defines a behaviour.
        if rate == 0 {
            return Err(Error::new(ErrorCode::InvalidCommand));
        }

        if !self.should_continue(with_on_off, options_mask, options_override)? {
            return Ok(());
        }

        // Exit if we are already at the limit in the direct of movement.
        if let Some(current_level) = self.hooks.current_level() {
            if (current_level == H::MIN_LEVEL && move_mode == MoveModeEnum::Down)
                || (current_level == H::MAX_LEVEL && move_mode == MoveModeEnum::Up)
            {
                return Ok(());
            }
        }

        let event_duration = Duration::from_hz(rate as u64);

        info!("moving with rate {}", rate);

        self.task_signal.signal(Task::Move {
            with_on_off,
            move_mode,
            event_duration,
        });

        Ok(())
    }

    /// Asynchronously moves the current level up or down at a specified rate.
    async fn move_transition(
        &self,
        ctx: impl HandlerContext,
        with_on_off: bool,
        move_mode: MoveModeEnum,
        event_duration: Duration,
    ) -> Result<(), Error> {
        loop {
            let event_start_time = Instant::now();

            let current_level = match self.hooks.current_level() {
                Some(cl) => cl,
                None => return Err(ErrorCode::InvalidState.into()),
            };

            let new_level = match move_mode {
                MoveModeEnum::Up => current_level.checked_add(1),
                MoveModeEnum::Down => current_level.checked_sub(1),
            };

            let new_level = match new_level {
                Some(nl) => nl,
                None => return Ok(()),
            };

            // If we start at min and go up, we need to update the onoff cluster immediately in case this method is halted.
            if current_level == H::MIN_LEVEL && new_level > H::MIN_LEVEL {
                self.update_coupled_on_off(new_level, with_on_off)?;
            }

            let is_end_of_transition = (new_level == H::MAX_LEVEL) || (new_level == H::MIN_LEVEL);

            let (new_level, should_notify) =
                self.set_level(new_level, is_end_of_transition, true)?;
            if should_notify {
                self.dataver_changed();
                ctx.notify_attribute_changed(
                    self.endpoint_id,
                    Self::CLUSTER.id,
                    AttributeId::CurrentLevel as _,
                );
            }
            let new_level = match new_level {
                Some(level) => level,
                None => return Err(ErrorCode::Failure.into()),
            };

            if is_end_of_transition {
                self.update_coupled_on_off(new_level, with_on_off)?;
                return Ok(());
            }

            let latency = embassy_time::Instant::now() - event_start_time;
            match event_duration.checked_sub(latency) {
                Some(wait_time) => embassy_time::Timer::after(wait_time).await,
                None => warn!("no wait time. Consider dynamically adjusting the step size?"),
            }
        }
    }

    /// Handles Step commands, adjusting the level by a step size and managing transition time proportionally.
    fn step(
        &self,
        with_on_off: bool,
        step_mode: StepModeEnum,
        step_size: u8,
        transition_time: Option<u16>,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        // From section 1.6.7.3.4
        //
        // if the StepSize field has a value of zero, the command has no effect and
        // a response SHALL be returned with the status code set to INVALID_COMMAND.
        if step_size == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if !self.should_continue(with_on_off, options_mask, options_override)? {
            return Ok(());
        }

        let current_level = match self.hooks.current_level() {
            Some(val) => val,
            None => return Err(ErrorCode::InvalidState.into()),
        };

        let new_level = match step_mode {
            StepModeEnum::Up => current_level.saturating_add(step_size).min(H::MAX_LEVEL),
            StepModeEnum::Down => current_level.saturating_sub(step_size).max(H::MIN_LEVEL),
        };

        // From section 1.6.7.3.4. Effect on Receipt
        // Increase/Decrease CurrentLevel by StepSize units, or until
        // it reaches the maximum/minimum level allowed for the
        // device if this reached in the process. In the latter
        // case, the transition time SHALL be
        // proportionally reduced.
        let transition_time = match transition_time {
            Some(val) => {
                if current_level.abs_diff(new_level) != step_size {
                    let new_step_size = current_level.abs_diff(new_level);
                    val.mul(new_step_size as u16).div_euclid(step_size as u16)
                } else {
                    val
                }
            }
            None => 0,
        };

        // This will run some extra unnecessary checks, they will all pass, but benefits
        // of code reuse and a single source of truth for this logic outweigh the minor
        // performance cost of a few extra checks.
        self.move_to_level(
            with_on_off,
            new_level,
            Some(transition_time),
            options_mask,
            options_override,
        )
    }

    /// Stops any ongoing transitions and resets the remaining time.
    fn stop(
        &self,
        ctx: impl HandlerContext,
        with_on_off: bool,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if !self.should_continue(with_on_off, options_mask, options_override)? {
            return Ok(());
        }
        self.task_signal.signal(Task::Stop);
        if self.write_remaining_time_quietly(Duration::from_millis(0), false) {
            self.dataver_changed();
            ctx.notify_attribute_changed(
                self.endpoint_id,
                Self::CLUSTER.id,
                AttributeId::RemainingTime as _,
            );
        }

        Ok(())
    }

    fn handle_out_of_band_message(&self, ctx: impl HandlerContext, message: OutOfBandMessage) {
        match message {
            OutOfBandMessage::Update(current_level) => {
                self.task_signal.signal(Task::Stop);

                match self.set_level(current_level, true, false) {
                    Ok((_, should_notify)) => {
                        if should_notify
                            || self.write_remaining_time_quietly(Duration::from_millis(0), false)
                        {
                            self.dataver_changed();
                            ctx.notify_attribute_changed(
                                self.endpoint_id,
                                Self::CLUSTER.id,
                                AttributeId::CurrentLevel as _,
                            );
                        }
                    }
                    Err(e) => {
                        error!("OutOfBandMessage::Update failed: set_level failed unexpectedly with set_device == false: {}", e);
                    }
                }
            }
            OutOfBandMessage::MoveToLevel {
                with_on_off,
                level,
                transition_time,
                options_mask,
                options_override,
            } => {
                if let Err(e) = self.move_to_level(
                    with_on_off,
                    level,
                    transition_time,
                    options_mask,
                    options_override,
                ) {
                    error!(
                        "Device initiated MoveToLevel failed: {} | with_on_off: {}, level: {}, transition_time: {:?}, options_mask: {:?}, options_override: {:?}",
                        e, with_on_off, level, transition_time, options_mask, options_override
                    );
                }
            }
            OutOfBandMessage::Move {
                with_on_off,
                move_mode,
                rate,
                options_mask,
                options_override,
            } => {
                if let Err(e) =
                    self.move_command(with_on_off, move_mode, rate, options_mask, options_override)
                {
                    error!(
                        "Device initiated Move failed: {} | with_on_off: {}, move_mode: {:?}, rate: {:?}, options_mask: {:?}, options_override: {:?}",
                        e, with_on_off, move_mode, rate, options_mask, options_override
                    );
                }
            }
            OutOfBandMessage::Step {
                with_on_off,
                step_mode,
                step_size,
                transition_time,
                options_mask,
                options_override,
            } => {
                if let Err(e) = self.step(
                    with_on_off,
                    step_mode,
                    step_size,
                    transition_time,
                    options_mask,
                    options_override,
                ) {
                    error!(
                        "Device initiated Step failed: {} | with_on_off: {}, step_mode: {:?}, step_size: {}, transition_time: {:?}, options_mask: {:?}, options_override: {:?}",
                        e, with_on_off, step_mode, step_size, transition_time, options_mask, options_override
                    );
                }
            }
            OutOfBandMessage::Stop => {
                self.task_signal.signal(Task::Stop);
                if self.write_remaining_time_quietly(Duration::from_millis(0), false) {
                    self.dataver_changed();
                    ctx.notify_attribute_changed(
                        self.endpoint_id,
                        Self::CLUSTER.id,
                        AttributeId::RemainingTime as _,
                    );
                }
            }
        }
    }
}

impl<H: LevelControlHooks, OH: OnOffHooks> ClusterAsyncHandler for LevelControlHandler<'_, H, OH> {
    const CLUSTER: Cluster<'static> = H::CLUSTER;

    // Runs an async task manager for the cluster handler.
    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        let mut hooks_fut = pin!(self
            .hooks
            .run(|message| self.handle_out_of_band_message(&ctx, message)));

        loop {
            let mut task = match select(
                &mut hooks_fut,
                self.task_signal.wait(),
            ).await {
                Either::First(_) => panic!("LevelControlHooks::run returned; implementers MUST not return. Implementations should loop forever or await core::future::pending::<()>()."),
                Either::Second(task) => task,
            };

            loop {
                match select3(
                    &mut hooks_fut,
                    self.task_manager(&ctx, task),
                    self.task_signal.wait(),
                )
                .await
                {
                    Either3::First(_) => panic!("LevelControlHooks::run returned; implementers MUST not return. Implementations should loop forever or await core::future::pending::<()>()."),
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

    async fn current_level(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        match self.hooks.current_level() {
            Some(level) => Ok(Nullable::some(level)),
            None => Ok(Nullable::none()),
        }
    }

    async fn on_level(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        Ok(self.on_level())
    }

    async fn set_on_level(&self, ctx: impl WriteContext, value: Nullable<u8>) -> Result<(), Error> {
        if let Some(level) = value.clone().into_option() {
            if level > H::MAX_LEVEL || level < H::MIN_LEVEL {
                return Err(ErrorCode::ConstraintError.into());
            }
        }

        self.on_level.set(value);
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn options(&self, _ctx: impl ReadContext) -> Result<OptionsBitmap, Error> {
        Ok(self.options.get())
    }

    async fn set_options(&self, ctx: impl WriteContext, value: OptionsBitmap) -> Result<(), Error> {
        self.options.set(value);
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn remaining_time(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(self.remaining_time.get())
    }

    async fn max_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(H::MAX_LEVEL)
    }

    async fn min_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(H::MIN_LEVEL)
    }

    async fn on_off_transition_time(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(self.on_off_transition_time.get())
    }

    async fn set_on_off_transition_time(
        &self,
        ctx: impl WriteContext,
        value: u16,
    ) -> Result<(), Error> {
        self.on_off_transition_time.set(value);
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn on_transition_time(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        Ok(self.on_transition_time())
    }

    async fn set_on_transition_time(
        &self,
        ctx: impl WriteContext,
        value: Nullable<u16>,
    ) -> Result<(), Error> {
        self.on_transition_time.set(value);
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn off_transition_time(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        Ok(self.off_transition_time())
    }

    async fn set_off_transition_time(
        &self,
        ctx: impl WriteContext,
        value: Nullable<u16>,
    ) -> Result<(), Error> {
        self.off_transition_time.set(value);
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn default_move_rate(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        Ok(self.default_move_rate())
    }

    async fn set_default_move_rate(
        &self,
        ctx: impl WriteContext,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        // The spec is not explicit about what should be done if this happens.
        // For now we error out if DefaultMoveRate is equal to 0 as this is invalid
        // until spec defines a behaviour.
        if Some(0) == value.clone().into_option() {
            return Err(ErrorCode::InvalidData.into());
        }
        self.default_move_rate.set(value);
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn start_up_current_level(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        match self.hooks.start_up_current_level()? {
            Some(val) => Ok(Nullable::some(val)),
            None => Ok(Nullable::none()),
        }
    }

    async fn set_start_up_current_level(
        &self,
        ctx: impl WriteContext,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        // According to the current spec, this attribute does not have any constraints at this stage.
        // However, it's usage is bounded by min/max hence it makes sense to restrict the settable values to this range.
        if let Some(level) = value.clone().into_option() {
            if level > H::MAX_LEVEL || level < H::MIN_LEVEL {
                return Err(ErrorCode::ConstraintError.into());
            }
        }

        self.hooks.set_start_up_current_level(value.into_option())?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn handle_move_to_level(
        &self,
        _ctx: impl InvokeContext,
        request: MoveToLevelRequest<'_>,
    ) -> Result<(), Error> {
        self.move_to_level(
            false,
            request.level()?,
            request.transition_time()?.into_option(),
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_move(
        &self,
        _ctx: impl InvokeContext,
        request: MoveRequest<'_>,
    ) -> Result<(), Error> {
        self.move_command(
            false,
            request.move_mode()?,
            request.rate()?.into_option(),
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_step(
        &self,
        _ctx: impl InvokeContext,
        request: StepRequest<'_>,
    ) -> Result<(), Error> {
        self.step(
            false,
            request.step_mode()?,
            request.step_size()?,
            request.transition_time()?.into_option(),
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_stop(
        &self,
        ctx: impl InvokeContext,
        request: StopRequest<'_>,
    ) -> Result<(), Error> {
        self.stop(
            &ctx,
            false,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_move_to_level_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        request: MoveToLevelWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        self.move_to_level(
            true,
            request.level()?,
            request.transition_time()?.into_option(),
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_move_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        request: MoveWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        self.move_command(
            true,
            request.move_mode()?,
            request.rate()?.into_option(),
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_step_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        request: StepWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        self.step(
            true,
            request.step_mode()?,
            request.step_size()?,
            request.transition_time()?.into_option(),
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_stop_with_on_off(
        &self,
        ctx: impl InvokeContext,
        request: StopWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        self.stop(
            &ctx,
            true,
            request.options_mask()?,
            request.options_override()?,
        )
    }

    async fn handle_move_to_closest_frequency(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveToClosestFrequencyRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::InvalidCommand.into())
    }
}

pub trait LevelControlHooks {
    const MIN_LEVEL: u8;
    const MAX_LEVEL: u8;
    const FASTEST_RATE: u8;
    const CLUSTER: Cluster<'static>;

    /// Implements the business logic for setting the level of the device.
    /// Returns the level the device was set to.
    /// If this method returns Err, the `LevelControlHandler` will represent this as an error with `ImStatusCode` of `Failure`.
    /// Note: The above is the only responsibility of this method. There is no need to update Matter attributes.
    #[allow(clippy::result_unit_err)]
    fn set_device_level(&self, level: u8) -> Result<Option<u8>, ()>;

    // Raw accessors
    //  These methods should not perform any checks.
    //  They should simply get or set values.
    //  They should not error.

    /// Raw current_level getter.
    /// This value should persist across reboots.
    fn current_level(&self) -> Option<u8>;

    /// Raw current_level setter.
    /// This value should persist across reboots.
    fn set_current_level(&self, level: Option<u8>);

    /// Raw start_up_current_level getter.
    /// This value should persist across reboots.
    fn start_up_current_level(&self) -> Result<Option<u8>, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    /// Raw start_up_current_level setter.
    /// This value should persist across reboots.
    fn set_start_up_current_level(&self, _value: Option<u8>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    /// Background task for out-of-band notifications to the handler.
    ///
    /// This future MUST NOT return. Implementers should either loop forever or await
    /// core::future::pending::<()>(), so the SDK's task does not observe a completed future.
    ///
    /// # Panics
    /// The SDK will panic if this method returns.
    async fn run<F: Fn(OutOfBandMessage)>(&self, _notify: F) {
        pending::<()>().await
    }
}

impl<T> LevelControlHooks for &T
where
    T: LevelControlHooks,
{
    const MIN_LEVEL: u8 = T::MIN_LEVEL;
    const MAX_LEVEL: u8 = T::MAX_LEVEL;
    const FASTEST_RATE: u8 = T::FASTEST_RATE;
    const CLUSTER: Cluster<'static> = T::CLUSTER;

    fn set_device_level(&self, level: u8) -> Result<Option<u8>, ()> {
        (*self).set_device_level(level)
    }

    fn current_level(&self) -> Option<u8> {
        (*self).current_level()
    }

    fn set_current_level(&self, level: Option<u8>) {
        (*self).set_current_level(level)
    }

    fn start_up_current_level(&self) -> Result<Option<u8>, Error> {
        (*self).start_up_current_level()
    }

    fn set_start_up_current_level(&self, value: Option<u8>) -> Result<(), Error> {
        (*self).set_start_up_current_level(value)
    }

    fn run<F: Fn(OutOfBandMessage)>(&self, notify: F) -> impl Future<Output = ()> {
        (*self).run(notify)
    }
}

/// This is a phantom type for when the LevelControl cluster is not coupled with an OnOff cluster.
/// This type should only be used for annotations and not for actual OnOff functionality.
/// All methods will panic.
pub struct NoOnOff;

impl OnOffHooks for NoOnOff {
    const CLUSTER: Cluster<'static> = ON_OFF_FULL_CLUSTER;

    fn on_off(&self) -> bool {
        panic!("NoOnOff: on_off called unexpectedly - this phantom type should not be used for OnOff functionality")
    }

    fn set_on_off(&self, _on: bool) {
        panic!("NoOnOff: set_on_off called unexpectedly - this phantom type should not be used for OnOff functionality")
    }

    fn start_up_on_off(&self) -> Nullable<super::on_off::StartUpOnOffEnum> {
        panic!("NoOnOff: start_up_on_off called unexpectedly - this phantom type should not be used for OnOff functionality")
    }

    fn set_start_up_on_off(
        &self,
        _value: Nullable<super::on_off::StartUpOnOffEnum>,
    ) -> Result<(), Error> {
        panic!("NoOnOff: set_start_up_on_off called unexpectedly - this method should not be called when LevelControl is not coupled with OnOff")
    }

    async fn handle_off_with_effect(&self, _effect: super::on_off::EffectVariantEnum) {
        panic!("NoOnOff: handle_off_with_effect called unexpectedly - this phantom type should not be used for OnOff functionality")
    }
}

pub mod test {
    use core::cell::Cell;

    use crate::dm::clusters::level_control::{
        AttributeId, CommandId, Feature, LevelControlHooks, FULL_CLUSTER,
    };
    use crate::dm::Cluster;
    use crate::error::Error;
    use crate::with;

    pub struct LevelControlDeviceLogic {
        current_level: Cell<Option<u8>>,
        start_up_current_level: Cell<Option<u8>>,
    }

    impl Default for LevelControlDeviceLogic {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LevelControlDeviceLogic {
        pub const fn new() -> Self {
            Self {
                current_level: Cell::new(Some(1)),
                start_up_current_level: Cell::new(None),
            }
        }
    }

    impl LevelControlHooks for LevelControlDeviceLogic {
        const MIN_LEVEL: u8 = 1;
        const MAX_LEVEL: u8 = 254;
        const FASTEST_RATE: u8 = 50;
        const CLUSTER: Cluster<'static> = FULL_CLUSTER
            .with_revision(5)
            .with_features(Feature::ON_OFF.bits())
            .with_attrs(with!(
                required;
                AttributeId::CurrentLevel
                | AttributeId::MinLevel
                | AttributeId::MaxLevel
                | AttributeId::OnLevel
                | AttributeId::Options
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
            Ok(Some(level))
        }

        fn current_level(&self) -> Option<u8> {
            self.current_level.get()
        }

        fn set_current_level(&self, level: Option<u8>) {
            info!(
                "LevelControlDeviceLogic::set_current_level: setting level to {:?}",
                level
            );
            self.current_level.set(level);
        }

        fn start_up_current_level(&self) -> Result<Option<u8>, Error> {
            Ok(self.start_up_current_level.get())
        }

        fn set_start_up_current_level(&self, value: Option<u8>) -> Result<(), Error> {
            self.start_up_current_level.set(value);
            Ok(())
        }
    }
}
