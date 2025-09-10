use core::cell::Cell;
use core::ops::Mul;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant};

use crate::tlv::Nullable;
use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext, WriteContext};
use crate::dm::clusters::{level_control, on_off::OnOffHandler};
pub use crate::dm::clusters::decl::level_control::*;
use crate::utils::maybe::Maybe;
use crate::error::{Error, ErrorCode};

use delegate::delegate;

enum Task {
    MoveToLevel{with_on_off: bool, target: u8, transition_time: u16},
    Move{with_on_off: bool, move_mode: MoveModeEnum, event_duration: Duration},
    Stop,
}

pub struct LevelControlCluster<'a, H: LevelControlHooks> {
    dataver: Dataver,
    state: &'a LevelControlState<'a, H>,
    task_signal: Signal<NoopRawMutex, Task>,
    // todo: Replace with OnOffState when OnOff in re-implemented.
    on_off: Cell<Option<&'a OnOffHandler>>,
}

impl<'a, H: LevelControlHooks> LevelControlCluster<'a, H> {
    const MAXIMUM_LEVEL: u8 = 254;

    // todo: add `on_off_state: Option<&'a OnOffState>` when OnOff in re-implemented.
    // Creates a new instance of the LevelControlCluster.
    //
    // ## Panic
    //
    // panics if the `handler`'s `CLUSTER`` is misconfigured.
    pub fn new(dataver: Dataver,handler: &'a LevelControlState<'a, H>) -> Self {
        let cluster = Self {
            dataver,
            state: handler,
            task_signal: Signal::new(),
            on_off: Cell::new(None),
        };

        cluster.validate();

        // todo: call a pub(crate) method in OnOffCluster setting up `&cluster` as a LevelControlCluster
        // accessor so it can call `coupled_on_off_cluster_on_off_state_change`

        cluster.init();

        cluster
    }

    // Validate that the LevelControlCluster has been set up correctly for given cluster configuration.
    //
    // ## Panic
    //
    // panics with error message if the `handler`'s `CLUSTER` is misconfigured.
    fn validate(&self) {
        if H::CLUSTER.revision != 5 {
            panic!("LevelControl validation: incorrect version number: expected 5 got {}", H::CLUSTER.revision);
        }

        // Check for mandatory attributes
        if H::CLUSTER.attribute(AttributeId::CurrentLevel as _).is_none()
        || H::CLUSTER.attribute(AttributeId::OnLevel as _).is_none()
        || H::CLUSTER.attribute(AttributeId::Options as _).is_none()
        {
            panic!("LevelControl validation: one or more of the following required attributes are missing:
            - CurrentLevel
            - OnLevel
            - Options");
        }

        // Check for mandatory commands
        if H::CLUSTER.command(CommandId::MoveToLevel as _).is_none()
        || H::CLUSTER.command(CommandId::Move as _).is_none()
        || H::CLUSTER.command(CommandId::Step as _).is_none()
        || H::CLUSTER.command(CommandId::Stop as _).is_none()
        || H::CLUSTER.command(CommandId::MoveToLevelWithOnOff as _).is_none()
        || H::CLUSTER.command(CommandId::MoveWithOnOff as _).is_none()
        || H::CLUSTER.command(CommandId::StepWithOnOff as _).is_none()
        || H::CLUSTER.command(CommandId::StopWithOnOff as _).is_none()
        {
            panic!("LevelControl validation: one or more of the following required commands are missing:
            - MoveToLevel
            - Move
            - Step
            - Stop
            - MoveToLevelWithOnOff
            - MoveWithOnOff
            - StepWithOnOff
            - StopWithOnOff")
        }

        // todo: uncomment after implementing the OnOff cluster.
        // If the ON_OFF feature in enabled or any of the "WithOnOff" commands are supported,
        // check that an OnOff cluster exists on the same endpoint.
        // if H::CLUSTER.feature_map & level_control::Feature::ON_OFF.bits() != 0
        // {
        //     match self.on_off.get() {
        //         Some(_on_off_state) => {
        //             // todo can we check the endpoint?
        //         },
        //         None => {
        //             panic!("LevelControl validation: a reference to the OnOff cluster must be set when the ON_OFF feature is enabled");
        //         },
        //     }
        // }

        if H::MAX_LEVEL > Self::MAXIMUM_LEVEL {
            panic!("LevelControl validation: the MAX_LEVEL cannot be higher than {}", Self::MAXIMUM_LEVEL);
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
            if H::CLUSTER.attribute(AttributeId::RemainingTime as _).is_none()
            || H::CLUSTER.attribute(AttributeId::StartUpCurrentLevel as _).is_none()
            {
                panic!("LevelControl validation: the RemainingTime and StartUpCurrentLevel attributes are required by the LIGHTING feature");
            }
        }
    }

    // Initialise the cluster on startup
    fn init(&self) {
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

        // `self.state` holds the previous current level as supplied by the SDK consumer.
        // Hence, if this process errors, we quietly abort resulting in the previous current level.
        if let Ok(startup_current_level) = self.state.start_up_current_level() {
            if let Some(startup_current_level) = startup_current_level.into_option() {
                // The spec fails to mention the need for this bounding.
                let level = if startup_current_level < H::MIN_LEVEL {
                    H::MIN_LEVEL
                } else if startup_current_level > H::MAX_LEVEL {
                    H::MAX_LEVEL
                } else {
                    startup_current_level
                };

                let _ = self.state.set_current_level(Maybe::some(level));
            }
        }
    }
    
    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }

    // todo Remove once OnOff is re-implemented.
    // Set the OnOff cluster instance coupled with this LevelControl cluster, i.e. the OnOff cluster on the same endpoint.
    // Note: The OnOff cluster on the same endpoint SHALL be set if any of the following is true
    //   - The OnOff feature is set
    //   - The `WithOnOff` commands are supported
    pub fn set_on_off_cluster(&self, cluster: &'a OnOffHandler) {
        self.on_off.set(Some(cluster))
    }

    // Checks if a command should continue beyond the Options processing.
    // Returns true if execution of the command should continue, false otherwise.
    //
    // From section 1.6.6.9
    // Command execution SHALL NOT continue beyond the Options processing if all of these criteria are true:
    // - The command is one of the ‘without On/Off’ commands: Move, Move to Level, Step, or Stop.
    // - The On/Off cluster exists on the same endpoint as this cluster.
    // - The OnOff attribute of the On/Off cluster, on this endpoint, is FALSE.
    // - The value of the ExecuteIfOff bit is 0.
    fn should_continue(&self, with_on_off: bool, options_mask: OptionsBitmap, options_override: OptionsBitmap) -> Result<bool, Error> {
        if with_on_off {
            return Ok(true);
        }

        let on_off_state = match self.on_off.get() {
            Some(on_off_state) => on_off_state,
            None => {
                // This should be sufficient to satisfy "The On/Off cluster exists on the same endpoint as this cluster" 
                // if we can check the NODE configuration in validate.
                return Ok(true)
            },
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

        return Ok(self.state.options()?.contains(level_control::OptionsBitmap::EXECUTE_IF_OFF));
    }

    async fn task_manager(&self, task: Task) {
        match task {
            Task::MoveToLevel{with_on_off, target, transition_time} => {
                if let Err(e) = self.move_to_level_transition(with_on_off, target, transition_time).await {
                    error!("{}", e.to_string());
                }
            },
            Task::Move { with_on_off, move_mode, event_duration } => {
                if let Err(e) = self.move_transition(with_on_off, move_mode, event_duration).await {
                    error!("{}", e.to_string());
                }

            }
            Task::Stop => return,
        }
    }

    // This method is called by an OnOff cluster that is coupled with this LevelControl cluster.
    // This method updates the CurrentLevel of the device when the state of the OnOff cluster changes.
    //
    // From section 1.6.4.1.1
    // ## On
    // Temporarily store CurrentLevel.
    // Set CurrentLevel to the minimum level allowed
    // for the device.
    // Change CurrentLevel to OnLevel, or to the
    // stored level if OnLevel is not defined, over the
    // time period OnOffTransitionTime.
    // ## off
    // Temporarily store CurrentLevel.
    // Change CurrentLevel to the minimum level
    // allowed for the device over the time period
    // OnOffTransitionTime.
    // If OnLevel is not defined, set the CurrentLevel to
    // the stored level.
    pub(crate) fn coupled_on_off_cluster_on_off_state_change(&self, on: bool) -> Result<(), Error> {
        self.task_signal.signal(Task::Stop);

        let temp_current_level = match self.state.current_level()?.into_option() {
            Some(current_level) => current_level,
            None => return Err(ErrorCode::Failure.into()),
        };

        // use of unwrap is justified since this will option is always valid.
        let bitmap = OptionsBitmap::from_bits(0).unwrap();

        // 1.6.6.10. OnOffTransitionTime Attribute
        // This attribute SHALL indicate the time taken to move to or from the target level when On or Off
        // commands are received by an On/Off cluster on the same endpoint.
        let mut transition_time = self.state.on_off_transition_time().unwrap_or(0);

        match on {
            true => {
                let level = self.state.set_level(H::MIN_LEVEL).map_err(|_| ErrorCode::Failure)?;
                self.state.write_current_level_quietly(Nullable::some(level), false)?;

                let on_level = match self.state.on_level()?.into_option() {
                    Some(on_level) => on_level,
                    None => temp_current_level,
                };

                // 1.6.6.12. OnTransitionTime Attribute
                // This attribute SHALL indicate the time taken to move the current level from the minimum level to
                // the maximum level when an On command is received by an On/Off cluster on the same endpoint.
                // If this attribute is not implemented, or contains a null value, the
                // OnOffTransitionTime SHALL be used instead.
                if let Ok(tt) = self.state.on_transition_time() {
                    if let Some(tt) = tt.into_option() {
                        // todo I'm unsure from the reading of the spec if this time should be proportional
                        transition_time = tt
                    }
                };
                
                self.move_to_level(false, on_level, Some(transition_time), bitmap, bitmap)?;
            },
            false => {
                // 1.6.6.13. OffTransitionTime Attribute
                // This attribute SHALL indicate the time taken to move the current level from the maximum level to
                // the minimum level when an Off command is received by an On/Off cluster on the same endpoint.
                // If this attribute is not implemented, or contains a null value, the
                // OnOffTransitionTime SHALL be used instead.
                if let Ok(tt) = self.state.off_transition_time() {
                    if let Some(tt) = tt.into_option() {
                        // todo I'm unsure from the reading of the spec if this time should be proportional
                        transition_time = tt
                    }
                };

                if let Some(tt) = self.state.off_transition_time()?.into_option() {
                    transition_time = tt
                }

                self.move_to_level(false, H::MIN_LEVEL, Some(transition_time), bitmap, bitmap)?;

                if self.state.on_level()?.is_none() {
                    self.state.set_current_level(Nullable::some(temp_current_level))?;
                }
            },
        };

        Ok(())
    }

    // Update the on_off attribute of the OnOff cluster.
    // 
    // From section 1.6.4.1.2
    // When the level is reduced to its minimum the OnOff attribute is automatically turned to FALSE, 
    // and when the level is increased above its minimum the OnOff attribute is automatically turned to TRUE.
    fn update_coupled_on_off(&self, current_level: u8, with_on_off: bool) -> Result<(), Error>{
        // From section 1.6.4.1.2.
        // There are two sets of commands provided in the Level Control cluster. These are identical, except
        // that the first set (MoveToLevel, Move and Step commands) SHALL NOT affect the OnOff attribute,
        // whereas the second set ('with On/Off' variants) SHALL.
        if !with_on_off {
            return Ok(());
        }

        let new_on_off_value = current_level > H::MIN_LEVEL;

        match self.on_off.get() {
            Some(on_off) => {
                let current_on_off = on_off.get();
                if current_on_off != new_on_off_value {
                    on_off.coupled_cluster_set_on_off(new_on_off_value);
                }
            },
            None => {
                error!("LevelControlCluster: expected OnOffCluster is missing.\n
                help: use set_on_off_cluster() to couple the OnOffCluster on the same endpoint with this LevelControlCluster")
            },
        }

        Ok(())
    }

    // A single move-to-level command handler for both with and without on off.
    fn move_to_level(&self, with_on_off: bool,mut level: u8, transition_time: Option<u16>, options_mask: OptionsBitmap, options_override: OptionsBitmap) -> Result<(), Error> {

        if level > Self::MAXIMUM_LEVEL {
            return Err(ErrorCode::InvalidCommand.into())
        }

        if !self.should_continue(with_on_off, options_mask, options_override)? {
            return Ok(());
        }

        if level > H::MAX_LEVEL {
            level = H::MAX_LEVEL;
            debug!("target level > MAX_LEVEL. level set to MAX_LEVEL")
        }
        else if level < H::MIN_LEVEL {
            level = H::MIN_LEVEL;
            debug!("target level < MIN_LEVEL. level set to MIN_LEVEL")
        }

        info!("setting level to {} with transition time {:?}", level, transition_time);

        match transition_time {
            None | Some(0) => {
                self.task_signal.signal(Task::Stop);
                let level = self.state.set_level(level).map_err(|_| ErrorCode::Failure)?;
                self.state.write_current_level_quietly(Nullable::some(level), true)?;
                self.state.write_remaining_time_quietly(Duration::from_millis(0), true)?;

                self.update_coupled_on_off(level, with_on_off)?;

            }
            Some(t_time) => {
                self.task_signal.signal(Task::MoveToLevel { with_on_off: with_on_off, target: level, transition_time: t_time});
            }
        }

        Ok(())

    }

    // Transition the current_level to target_level in the transition_time.
    async fn move_to_level_transition(&self, with_on_off: bool, target_level: u8, transition_time: u16) -> Result<(), Error> {
        let event_start_time = Instant::now();

        // Check if current_level is null. If so, return error.
        let mut current_level = match self.state.current_level()?.into_option() {
            Some(cl) => cl,
            None => return Err(ErrorCode::Failure.into()),
        };

        let increasing = current_level < target_level;

        let steps = target_level.abs_diff(current_level);

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

            debug!("move_to_level_transition: Setting current level: {}", current_level);
            let current_level = self.state.set_level(current_level).map_err(|_| ErrorCode::Failure)?;
            self.state.write_current_level_quietly(Nullable::some(current_level), is_transition_end)?;


            if is_transition_start || is_transition_end {
                self.update_coupled_on_off(current_level, with_on_off)?;
            }

            if is_transition_end{
                self.state.write_remaining_time_quietly(Duration::from_millis(0), is_transition_start)?;
                return Ok(());
            }

            match remaining_time > event_duration {
                true => remaining_time -= event_duration,
                false => {
                    warn!("remaining time is 0 before level reached target");
                    remaining_time = Duration::from_millis(0)
                },
            }

            self.state.write_remaining_time_quietly(remaining_time, is_transition_start)?;

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

    // A single move command handler for both with and without on off.
    fn move_command(&self, with_on_off: bool, move_mode: MoveModeEnum, rate: Option<u8>, options_mask: OptionsBitmap, options_override: OptionsBitmap) -> Result<(), Error> {
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
            None => {
                match self.state.default_move_rate() {
                    Ok(default_move_rate) => {
                        match default_move_rate.into_option() {
                            Some(val) => val,
                            None => H::FASTEST_RATE,
                        }
                    }
                    Err(_) => H::FASTEST_RATE,
                }
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
        if let Some(current_level) = self.state.current_level()?.into_option() {
            if (current_level == H::MIN_LEVEL && move_mode == MoveModeEnum::Down) ||
               (current_level == H::MAX_LEVEL && move_mode == MoveModeEnum::Up) {
                return Ok(());
            }
        }

        let event_duration = Duration::from_hz(rate as u64);

        info!("moving with rate {}", rate);

        self.task_signal.signal(Task::Move { with_on_off: with_on_off, move_mode: move_mode, event_duration: event_duration });

        Ok(())
    }

    async fn move_transition(&self, with_on_off: bool, move_mode: MoveModeEnum, event_duration: Duration) -> Result<(), Error> {
        loop {
            let event_start_time = Instant::now();

            let current_level = match self.state.current_level()?.into_option() {
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
            let new_level = self.state.set_level(new_level).map_err(|_| ErrorCode::Failure)?;
            self.state.write_current_level_quietly(Maybe::some(new_level), is_end_of_transition)?;

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

    fn step(&self, with_on_off: bool, step_mode: StepModeEnum, step_size: u8, transition_time: Option<u16>, options_mask: OptionsBitmap, options_override: OptionsBitmap) -> Result<(), Error> {

        // From section 1.6.7.3.4
        // 
        // if the StepSize field has a value of zero, the command has no effect and 
        // a response SHALL be returned with the status code set to INVALID_COMMAND.
        if step_size == 0 {
            return Err(ErrorCode::InvalidCommand.into())
        }

        if !self.should_continue(with_on_off, options_mask, options_override)? {
            return Ok(());
        }

        let current_level = match self.state.current_level()?.into_option() {
            Some(val) => val,
            None => return Err(ErrorCode::InvalidState.into()),
        };

        let new_level = match step_mode {
            StepModeEnum::Up => current_level.saturating_add(step_size).min(H::MAX_LEVEL),
            StepModeEnum::Down => current_level.saturating_sub(step_size).max(H::MIN_LEVEL),
        };

        let transition_time = match transition_time {
            Some(val) => {
                if current_level.abs_diff(new_level) != step_size {
                    let new_step_size = current_level.abs_diff(new_level);
                    val.mul(new_step_size as u16).div_euclid(step_size as u16)
                } else {
                    val
                }              
            },
            None => 0,
        };

        // Could call `self.move_to_level(with_on_off, new_level, Some(transition_time), options_mask, options_override)`
        // But this will run some extra checks which would be unnecessary.
        match transition_time {
            0 => {
                self.task_signal.signal(Task::Stop);
                let new_level = self.state.set_level(new_level).map_err(|_| ErrorCode::Failure)?;
                self.state.write_current_level_quietly(Nullable::some(new_level), true)?;
                self.state.write_remaining_time_quietly(Duration::from_millis(0), true)?;

                self.update_coupled_on_off(new_level, with_on_off)?;
            }
            t_time => {
                self.task_signal.signal(Task::MoveToLevel { with_on_off: with_on_off, target: new_level, transition_time: t_time});
            }
        }

        Ok(())
    }

    fn stop(&self, with_on_off: bool, options_mask: OptionsBitmap, options_override: OptionsBitmap) -> Result<(), Error> {
        if !self.should_continue(with_on_off, options_mask, options_override)? {
            return Ok(());
        }
        self.task_signal.signal(Task::Stop);
        self.state.write_remaining_time_quietly(Duration::from_millis(0), false)?;

        Ok(())
    }
}

impl<'a, H: LevelControlHooks> ClusterAsyncHandler for LevelControlCluster<'a, H> {
    const CLUSTER: Cluster<'static> = H::CLUSTER;

    // Runs an async task manager for the cluster.
    async fn run(&self) -> Result<(), Error> {
        loop {
            let mut task = self.task_signal.wait().await;

            loop {
                match embassy_futures::select::select(self.task_manager(task), self.task_signal.wait()).await {
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

    async fn current_level(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<Nullable<u8>, Error> {
        self.state.current_level()
    }

    async fn on_level(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<Nullable<u8>, Error> {
        self.state.on_level()
    }

    async fn set_on_level(
        &self,
        ctx: impl WriteContext,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        if let Some(level) = value.clone().into_option() {
            if level > H::MAX_LEVEL || level < H::MIN_LEVEL {
                return Err(ErrorCode::ConstraintError.into())
            }
        }

        self.state.set_on_level(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn options(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<OptionsBitmap, Error> {
        self.state.options()
    }

    async fn set_options(
        &self,
        ctx: impl WriteContext,
        value: OptionsBitmap,
    ) -> Result<(), Error> {
        self.state.set_options(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn remaining_time(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        self.state.remaining_time()
    }

    async fn max_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(H::MAX_LEVEL)
    }

    async fn min_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(H::MIN_LEVEL)
    }

    async fn on_off_transition_time(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        self.state.on_off_transition_time()
    }

    async fn set_on_off_transition_time(&self, ctx: impl WriteContext, value:u16) -> Result<(), Error> {
        self.state.set_on_off_transition_time(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn on_transition_time(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        self.state.on_transition_time()
    }

    async fn set_on_transition_time(&self, ctx: impl WriteContext, value:Nullable<u16>) -> Result<(), Error> {
        self.state.set_on_transition_time(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn off_transition_time(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        self.state.off_transition_time()
    }

    async fn set_off_transition_time(&self, ctx: impl WriteContext, value:Nullable<u16>) -> Result<(), Error> {
        self.state.set_off_transition_time(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn default_move_rate(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        self.state.default_move_rate()
    }

    async fn set_default_move_rate(&self, ctx: impl WriteContext, value:Nullable<u8>) -> Result<(), Error> {
        // The spec is not explicit about what should be done if this happens.
        // For now we error out if DefaultMoveRate is equal to 0 as this is invalid
        // until spec defines a behaviour.
        if Some(0) == value.clone().into_option() {
            return Err(ErrorCode::InvalidData.into());
        }
        self.state.set_default_move_rate(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn start_up_current_level(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        self.state.startup_current_level()
    }

    async fn set_start_up_current_level(&self, ctx: impl WriteContext, value:Nullable<u8>) -> Result<(), Error> {
        // According to the current spec, this attribute dose not have any constraints at this stage.
        // However, it's usage is bounded by min/max hence it makes sense to restrict the settable values to this range.
        if let Some(level) = value.clone().into_option() {
            if level > H::MAX_LEVEL || level < H::MIN_LEVEL {
                return Err(ErrorCode::ConstraintError.into())
            }
        }

        self.state.set_startup_current_level(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn handle_move_to_level(
        &self,
        _ctx: impl InvokeContext,
        request: MoveToLevelRequest<'_>,
    ) -> Result<(), Error> {

        self.move_to_level(false, request.level()?, request.transition_time()?.into_option(), request.options_mask()?, request.options_override()?)

    }

    async fn handle_move(
        &self,
        _ctx: impl InvokeContext,
        request: MoveRequest<'_>,
    ) -> Result<(), Error> {

        self.move_command(false, request.move_mode()?, request.rate()?.into_option(), request.options_mask()?, request.options_override()?)

    }

    async fn handle_step(
        &self,
        _ctx: impl InvokeContext,
        request: StepRequest<'_>,
    ) -> Result<(), Error> {

        self.step(false, request.step_mode()?, request.step_size()?, request.transition_time()?.into_option(), request.options_mask()?, request.options_override()?)
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

        self.move_to_level(true, request.level()?, request.transition_time()?.into_option(), request.options_mask()?, request.options_override()?)

    }

    async fn handle_move_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        request: MoveWithOnOffRequest<'_>,
    ) -> Result<(), Error> {

        self.move_command(true, request.move_mode()?, request.rate()?.into_option(), request.options_mask()?, request.options_override()?)
    }

    async fn handle_step_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        request: StepWithOnOffRequest<'_>,
    ) -> Result<(), Error> {

        self.step(true, request.step_mode()?, request.step_size()?, request.transition_time()?.into_option(), request.options_mask()?, request.options_override()?)
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


pub struct LevelControlState<'a, H: LevelControlHooks> {
    handler: &'a H,
    last_current_level_notification: Cell<Instant>,
}

impl<'a, H: LevelControlHooks> LevelControlState<'a, H> {
    pub fn new(handler: &'a H) -> Self {
        Self {
            handler,
            last_current_level_notification: Cell::new(Instant::from_millis(0)),
        }
    }

    fn write_remaining_time_quietly(&self, remaining_time: Duration, is_start_of_transition: bool) -> Result<(), Error> {
        let remaining_time_ds = remaining_time.as_millis().div_ceil(100) as u16;

        self.handler.set_remaining_time(remaining_time_ds as u16)?;

        // RemainingTime Quiet report conditions:
        // - When it changes to 0, or
        // - When it changes from 0 to any value higher than 10, or
        // - When it changes, with a delta larger than 10, caused by the invoke of a command.
        let previous_remaining_time = self.handler.remaining_time()?;
        let changed_to_zero = remaining_time_ds == 0 && previous_remaining_time != 0;
        let changed_from_zero_gt_10 = previous_remaining_time == 0 && remaining_time_ds > 10;
        let changed_by_gt_10 = remaining_time_ds.abs_diff(previous_remaining_time) > 10 && is_start_of_transition;

        if changed_to_zero || changed_from_zero_gt_10 || changed_by_gt_10 {
            // todo notify.changed();
        }

        Ok(())
    }

    fn write_current_level_quietly(&self, current_level: Nullable<u8>, is_end_of_transition: bool) -> Result<(), Error> {
        let previous_value = self.handler.current_level()?;
        let last_notification = Instant::now() - self.last_current_level_notification.get();
        self.handler.set_current_level(current_level.clone())?;

        // CurrentLevel Quiet report conditions:
        // - At most once per second, or
        // - At the end of the movement/transition, or
        // - When it changes from null to any other value and vice versa.
        if last_notification.ge(&Duration::from_secs(1)) || is_end_of_transition || previous_value.is_none() || current_level.is_none() {
            self.last_current_level_notification.set(Instant::now());
            // todo notify.changed();
        }

        Ok(())
    }

}

impl<'a, H: LevelControlHooks> LevelControlHooks for LevelControlState<'a, H> {
    const MIN_LEVEL: u8 = H::MIN_LEVEL;
    const MAX_LEVEL: u8 = H::MAX_LEVEL;
    const FASTEST_RATE: u8 = H::FASTEST_RATE;
    const CLUSTER: Cluster<'static> = H::CLUSTER;

    delegate!{
        to self.handler {
            fn set_level(&self, level: u8) -> Result<u8, ()>;
            fn current_level(&self) -> Result<Nullable<u8>, Error>;
            fn set_current_level(&self, value: Nullable<u8>) -> Result<(), Error>;
            fn on_level(&self) -> Result<Nullable<u8>, Error>;
            fn set_on_level(&self, value: Nullable<u8>) -> Result<(), Error>;
            fn options(&self) -> Result<OptionsBitmap, Error>;
            fn set_options(&self, value: OptionsBitmap) -> Result<(), Error>;
            fn startup_current_level(&self) -> Result<Nullable<u8>, Error>;
            fn set_startup_current_level(&self, _value: Nullable<u8>) -> Result<(), Error>;
            fn remaining_time(&self) -> Result<u16, Error>;
            fn set_remaining_time(&self, value: u16) -> Result<(), Error>;
            fn on_off_transition_time(&self) -> Result<u16, Error>;
            fn set_on_off_transition_time(&self, _value: u16) -> Result<(), Error>;
            fn on_transition_time(&self) -> Result<Nullable<u16>, Error>;
            fn set_on_transition_time(&self, _value: Nullable<u16>) -> Result<(), Error>;
            fn off_transition_time(&self) -> Result<Nullable<u16>, Error>;
            fn set_off_transition_time(&self, _value: Nullable<u16>) -> Result<(), Error>;
            fn default_move_rate(&self) -> Result<Nullable<u8>, Error>;
            fn set_default_move_rate(&self, _value: Nullable<u8>) -> Result<(), Error>;
            fn start_up_current_level(&self) -> Result<Nullable<u8>, Error>;
            fn set_start_up_current_level(&self, _value: Nullable<u8>) -> Result<(), Error>;
        }
    }
}


pub trait LevelControlHooks {
    const MIN_LEVEL: u8;
    const MAX_LEVEL: u8;
    const FASTEST_RATE: u8;
    const CLUSTER: Cluster<'static>;

    // Implements the business logic for setting the level of the device.
    // Returns the new level of the device.
    // If this method errors, the `LevelControlCluster` will represent this with an `ImStatusCode` of `Failure`.
    //
    // ## Implementation notes
    //
    // - DO NOT update attribute states, this is handled by the `LevelControlCluster`.
    fn set_level(&self, level: u8) -> Result<u8, ()>;

    // Raw accessors
    //  These methods should not perform any checks.
    //  They should simply set or get values.
    fn current_level(&self) -> Result<Nullable<u8>, Error>;
    fn set_current_level(&self, value: Nullable<u8>) -> Result<(), Error>;

    fn on_level(&self) -> Result<Nullable<u8>, Error>;
    fn set_on_level(&self, value: Nullable<u8>) -> Result<(), Error>;

    fn options(&self) -> Result<OptionsBitmap, Error>;
    fn set_options(&self, value: OptionsBitmap) -> Result<(), Error>;

    fn startup_current_level(&self) -> Result<Nullable<u8>, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn set_startup_current_level(&self, _value: Nullable<u8>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn remaining_time(&self) -> Result<u16, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn set_remaining_time(&self, value: u16) -> Result<(), Error>;

    fn on_off_transition_time(&self) -> Result<u16, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn set_on_off_transition_time(&self, _value: u16) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn on_transition_time(&self) -> Result<Nullable<u16>, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn set_on_transition_time(&self, _value: Nullable<u16>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn off_transition_time(&self) -> Result<Nullable<u16>, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn set_off_transition_time(&self, _value: Nullable<u16>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn default_move_rate(&self) -> Result<Nullable<u8>, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn set_default_move_rate(&self, _value: Nullable<u8>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn start_up_current_level(&self) -> Result<Nullable<u8>, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn set_start_up_current_level(&self, _value: Nullable<u8>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }    

}
