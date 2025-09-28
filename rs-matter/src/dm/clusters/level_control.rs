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
use core::ops::Mul;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant};

pub use crate::dm::clusters::decl::level_control::*;
use crate::dm::clusters::on_off::OnOffHooks;
use crate::dm::clusters::{level_control, on_off::OnOffHandler};
use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext, WriteContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::Nullable;

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
    hooks: &'a H,
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
pub struct AttributeDefaults {
    pub on_level: Nullable<u8>,
    pub options: OptionsBitmap,
    pub on_off_transition_time: u16,
    pub on_transition_time: Nullable<u16>,
    pub off_transition_time: Nullable<u16>,
    pub default_move_rate: Nullable<u8>,
}

impl<'a, H: LevelControlHooks, OH: OnOffHooks> LevelControlHandler<'a, H, OH> {
    const MAXIMUM_LEVEL: u8 = 254;

    /// Creates a new `LevelControlHandler` with the given hooks.
    ///
    /// # Arguments
    /// - `level_control_hooks` - A reference to the struct implementing the device-specific level control logic.
    pub fn new(
        dataver: Dataver,
        level_control_hooks: &'a H,
        attribute_defaults: AttributeDefaults,
    ) -> Self {
        Self {
            dataver,
            hooks: level_control_hooks,
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
        if H::CLUSTER.revision != 5 {
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
        if let Ok(startup_current_level) = self.hooks.start_up_current_level() {
            if let Some(startup_current_level) = startup_current_level.into_option() {
                // The spec fails to mention the need for this bounding.
                let level = if startup_current_level < H::MIN_LEVEL {
                    H::MIN_LEVEL
                } else if startup_current_level > H::MAX_LEVEL {
                    H::MAX_LEVEL
                } else {
                    startup_current_level
                };

                let _ = self.hooks.set_level(level);
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

    /// Updates the RemainingTime attribute quietly, reporting changes only under specific conditions.
    ///
    /// # Arguments
    /// - `remaining_time` - The new remaining time.
    /// - `is_start_of_transition` - Indicates if this is the start of a transition.
    fn write_remaining_time_quietly(
        &self,
        remaining_time: Duration,
        is_start_of_transition: bool,
    ) -> Result<(), Error> {
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
            // todo notify.changed();
        }

        Ok(())
    }

    /// Sets the level of the device, via the `set_level` hook, and notifies Matter of a change in the current level.
    /// Notification depends on the quiet reporting conditions set in the spec.
    ///
    /// # Arguments
    /// - `level` - The new current level.
    /// - `is_end_of_transition` - Indicates if this is the end of a transition.
    ///
    /// # Returns
    /// The current level of the device.
    fn set_level_and_notify(&self, level: u8, is_end_of_transition: bool) -> Option<u8> {
        self.previous_current_level.set(self.hooks.get_level());
        let current_level = self.hooks.set_level(level);
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
            // todo notify.changed();
        }

        current_level
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

        if on_off_state.on_off()? {
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
    async fn task_manager(&self, task: Task) {
        match task {
            Task::MoveToLevel {
                with_on_off,
                target,
                transition_time,
            } => {
                if let Err(e) = self
                    .move_to_level_transition(with_on_off, target, transition_time)
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
                    .move_transition(with_on_off, move_mode, event_duration)
                    .await
                {
                    error!("Task::Move: {:?}", e);
                }
            }
            Task::Stop => (),
            Task::OnOffStateChange { on } => {
                if let Err(e) = self.handle_on_off_state_change(on).await {
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
    async fn handle_on_off_state_change(&self, on: bool) -> Result<(), Error> {
        info!("handle_on_off_state_change");

        let temp_current_level = self.hooks.get_level().ok_or(ErrorCode::Failure)?;

        // use of unwrap is justified since this will option is always valid.
        let bitmap = OptionsBitmap::from_bits(0).unwrap();

        // 1.6.6.10. OnOffTransitionTime Attribute
        // This attribute SHALL indicate the time taken to move to or from the target level when On or Off
        // commands are received by an On/Off cluster on the same endpoint.
        let mut transition_time = self.on_off_transition_time.get();

        match on {
            true => {
                let _ = self
                    .set_level_and_notify(H::MIN_LEVEL, false)
                    .ok_or(ErrorCode::Failure)?;

                let target_level = match self.on_level().into_option() {
                    Some(on_level) => on_level,
                    None => temp_current_level,
                };

                // 1.6.6.12. OnTransitionTime Attribute
                // This attribute SHALL indicate the time taken to move the current level from the minimum level to
                // the maximum level when an On command is received by an On/Off cluster on the same endpoint.
                // If this attribute is not implemented, or contains a null value, the
                // OnOffTransitionTime SHALL be used instead.
                if let Some(tt) = self.on_transition_time().into_option() {
                    transition_time = tt;
                }

                self.move_to_level(
                    true,
                    target_level,
                    Some(transition_time),
                    bitmap,
                    bitmap,
                    true,
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

                self.move_to_level(
                    true,
                    H::MIN_LEVEL,
                    Some(transition_time),
                    bitmap,
                    bitmap,
                    true,
                )
                .await?;

                // todo we may need to separate the device logic from attribute storage as users will implement the set_level to both set and store the level. Hence, calling `set_level` here will probably switch the device on again.
                if self.on_level().is_none() {
                    let _ = self.hooks.set_level(temp_current_level);
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
            let current_on_off = on_off.on_off()?;
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

    /// Handles MoveToLevel commands, including validation, bounding, and transition logic.
    /// Note: This will try to update the OnOff cluster's OnOff attribute at the start and end of the transition.
    ///
    /// # Parameters
    ///
    /// * with_on_off: Is the LevelControl command calling this method one of the "WithOnOff" variant?
    /// * level: The target level to move to.
    /// * transition_time: The time for the transition in 1/10ts of a second.
    /// * options_mask: The options mask in the command attributes.
    /// * options_override: The options override in the command attributes.
    /// * block: Should we wait for the transition to finish before returning? Set this if the call is made from another Task, otherwise the calling Task will be halted.
    async fn move_to_level(
        &self,
        with_on_off: bool,
        mut level: u8,
        transition_time: Option<u16>,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
        block: bool,
    ) -> Result<(), Error> {
        if level > Self::MAXIMUM_LEVEL {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if !self.should_continue(with_on_off, options_mask, options_override)? {
            return Ok(());
        }

        if level > H::MAX_LEVEL {
            level = H::MAX_LEVEL;
            debug!("target level > MAX_LEVEL. level set to MAX_LEVEL")
        } else if level < H::MIN_LEVEL {
            level = H::MIN_LEVEL;
            debug!("target level < MIN_LEVEL. level set to MIN_LEVEL")
        }

        info!(
            "setting level to {} with transition time {:?}",
            level, transition_time
        );

        // Stop any ongoing transitions and check if we happen to be where we need to be.
        // If so, there is nothing to do.
        // If we are called from another Task, we shouldn't stop it.
        if !block {
            self.task_signal.signal(Task::Stop);
        }
        if self.hooks.get_level() == Some(level) {
            self.update_coupled_on_off(level, with_on_off)?;
            return Ok(());
        }

        match transition_time {
            None | Some(0) => {
                let level = self
                    .set_level_and_notify(level, true)
                    .ok_or(ErrorCode::Failure)?;
                self.write_remaining_time_quietly(Duration::from_millis(0), true)?;

                self.update_coupled_on_off(level, with_on_off)?;
            }
            Some(t_time) => {
                if block {
                    self.move_to_level_transition(with_on_off, level, t_time)
                        .await?;
                } else {
                    self.task_signal.signal(Task::MoveToLevel {
                        with_on_off,
                        target: level,
                        transition_time: t_time,
                    });
                }
            }
        }

        Ok(())
    }

    /// Asynchronously transitions the current level to a target level over a specified time.
    /// Note: This will try to update the OnOff cluster's OnOff attribute at the start and end of the transition.
    async fn move_to_level_transition(
        &self,
        with_on_off: bool,
        target_level: u8,
        transition_time: u16,
    ) -> Result<(), Error> {
        let event_start_time = Instant::now();

        // Check if current_level is null. If so, return error.
        let mut current_level = match self.hooks.get_level() {
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

            match increasing {
                true => current_level += 1,
                false => current_level -= 1,
            }

            let is_transition_start = remaining_time.as_millis() == (transition_time as u64 * 100);
            let is_transition_end = current_level == target_level;

            debug!(
                "move_to_level_transition: Setting current level: {}",
                current_level
            );
            let current_level = self
                .set_level_and_notify(current_level, is_transition_end)
                .ok_or(ErrorCode::Failure)?;

            if is_transition_start || is_transition_end {
                self.update_coupled_on_off(current_level, with_on_off)?;
            }

            if is_transition_end {
                self.write_remaining_time_quietly(Duration::from_millis(0), is_transition_start)?;
                return Ok(());
            }

            match remaining_time > event_duration {
                true => remaining_time -= event_duration,
                false => {
                    warn!("remaining time is 0 before level reached target");
                    remaining_time = Duration::from_millis(0)
                }
            }

            self.write_remaining_time_quietly(remaining_time, is_transition_start)?;

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
        if let Some(current_level) = self.hooks.get_level() {
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
        with_on_off: bool,
        move_mode: MoveModeEnum,
        event_duration: Duration,
    ) -> Result<(), Error> {
        loop {
            let event_start_time = Instant::now();

            let current_level = match self.hooks.get_level() {
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
            let new_level = self
                .set_level_and_notify(new_level, is_end_of_transition)
                .ok_or(ErrorCode::Failure)?;

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
    async fn step(
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

        let current_level = match self.hooks.get_level() {
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
            false,
        )
        .await
    }

    /// Stops any ongoing transitions and resets the remaining time.
    fn stop(
        &self,
        with_on_off: bool,
        options_mask: OptionsBitmap,
        options_override: OptionsBitmap,
    ) -> Result<(), Error> {
        if !self.should_continue(with_on_off, options_mask, options_override)? {
            return Ok(());
        }
        self.task_signal.signal(Task::Stop);
        self.write_remaining_time_quietly(Duration::from_millis(0), false)?;

        Ok(())
    }
}

impl<'a, H: LevelControlHooks, OH: OnOffHooks> ClusterAsyncHandler
    for LevelControlHandler<'a, H, OH>
{
    const CLUSTER: Cluster<'static> = H::CLUSTER;

    // Runs an async task manager for the cluster handler.
    async fn run(&self) -> Result<(), Error> {
        loop {
            let mut task = self.task_signal.wait().await;

            loop {
                match embassy_futures::select::select(
                    self.task_manager(task),
                    self.task_signal.wait(),
                )
                .await
                {
                    embassy_futures::select::Either::First(_) => break,
                    embassy_futures::select::Either::Second(new_task) => task = new_task,
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
        match self.hooks.get_level() {
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
        self.hooks.start_up_current_level()
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

        self.hooks.set_start_up_current_level(value)?;
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
            false,
        )
        .await
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
        .await
    }

    async fn handle_stop(
        &self,
        _ctx: impl InvokeContext,
        request: StopRequest<'_>,
    ) -> Result<(), Error> {
        self.stop(false, request.options_mask()?, request.options_override()?)
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
            false,
        )
        .await
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
        .await
    }

    async fn handle_stop_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        request: StopWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        self.stop(true, request.options_mask()?, request.options_override()?)
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
    /// The new level of the device must be persistently stored, as required by the spec, and accessible via `get_level`.
    /// Returns the new level of the device.
    /// If this method returns None, the `LevelControlHandler` will represent this as an error with `ImStatusCode` of `Failure`.
    fn set_level(&self, level: u8) -> Option<u8>;

    /// Get the current level of the device.
    fn get_level(&self) -> Option<u8>;

    // Raw accessors
    //  These methods should not perform any checks.
    //  They should simply get or set values.

    /// Raw start_up_current_level getter.
    /// This value should persist across reboots.
    fn start_up_current_level(&self) -> Result<Nullable<u8>, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    /// Raw start_up_current_level setter.
    /// This value should persist across reboots.
    fn set_start_up_current_level(&self, _value: Nullable<u8>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }
}
