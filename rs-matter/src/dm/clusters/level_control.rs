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
use crate::with;
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
    pub fn new(dataver: Dataver, handler: &'a LevelControlState<'a, H>) -> Self {
        Self {
            dataver,
            state: handler,
            task_signal: Signal::new(),
            on_off: Cell::new(None),
        }

        // todo call self.validate
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


    // Validate that the LevelControlCluster has been set up correctly for given cluster configuration.
    //
    // ## Panic
    //
    // panics with error message if the cluster setup is not valid according to the given cluster configuration.
    fn validate(&self, cluster: Cluster<'static>) {
        if cluster.revision != 5 {
            panic!("incorrect version number: expected 5 got {}", cluster.revision);
        }

        // todo check for mandatory Attributes and Commands

        // If the ON_OFF feature in enabled or any of the "WithOnOff" commands are supported,
        // check that an OnOff cluster exists on the same endpoint.
        if cluster.feature_map & level_control::Feature::ON_OFF.bits() != 0
        {
            match self.on_off.get() {
                Some(_on_off_state) => {
                    // todo can we check the endpoint?
                },
                None => {
                    panic!("a reference to the OnOff cluster must be set when the ON_OFF feature is enabled");
                },
            }
        }

        if H::MAX_LEVEL > Self::MAXIMUM_LEVEL {
            panic!("the MAX_LEVEL cannot be higher than {}", Self::MAXIMUM_LEVEL);
        }

        if cluster.feature_map & level_control::Feature::LIGHTING.bits() != 0 {
            // From section 1.6.4.2
            // A value of 0x00 SHALL NOT be used.
            // A value of 0x01 SHALL indicate the minimum level that can be attained on a device.
            // A value of 0xFE SHALL indicate the maximum level that can be attained on a device.
            if H::MIN_LEVEL == 0 {
                panic!("the MIN_LEVEL cannot be 0 when the LIGHTING feature is enabled");
            }

            // Check for required attributes when using this feature
            // if !cluster.attributes.contains(AttributeId::RemainingTime)
            // || !cluster.attributes.contains(AttributeId::StartUpCurrentLevel) {
            //     panic!("the RemainingTime and StartUpCurrentLevel attributes are required by the LIGHTING feature");
            // }
        }
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

        if on_off_state.raw_get_on_off()? {
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

        return Ok(self.state.raw_get_options()?.contains(level_control::OptionsBitmap::EXECUTE_IF_OFF));
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
    fn move_to_level(&self, with_on_off: bool, level: u8, transition_time: Option<u16>, options_mask: OptionsBitmap, options_override: OptionsBitmap) -> Result<(), Error> {

        if level > Self::MAXIMUM_LEVEL {
            return Err(ErrorCode::InvalidCommand.into())
        }

        if !self.should_continue(with_on_off, options_mask, options_override)? {
            return Ok(());
        }

        info!("setting level to {} with transition time {:?}", level, transition_time);

        match transition_time {
            None | Some(0) => {
                self.task_signal.signal(Task::Stop);
                // todo find suitable error.
                let level = self.state.set_level(level).map_err(|_| ErrorCode::Invalid)?;
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
        //  todo: currently returning an incorrect error. `Failure` is used in the cpp impl
        //  Equivalent code in cpp impl: https://github.com/project-chip/connectedhomeip/blob/8adaf97c152e478200784629499756e81c53fd15/src/app/clusters/level-control/level-control.cpp#L904
        let mut current_level = match self.state.raw_get_current_level()?.into_option() {
            Some(cl) => cl,
            None => return Err(ErrorCode::InvalidState.into()),
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
            // todo find suitable error.
            let current_level = self.state.set_level(current_level).map_err(|_| ErrorCode::Invalid)?;
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
                match self.state.raw_get_default_move_rate() {
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
        if let Some(current_level) = self.state.raw_get_current_level()?.into_option() {
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

            let current_level = match self.state.raw_get_current_level()?.into_option() {
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
            // todo find suitable error.
            let new_level = self.state.set_level(new_level).map_err(|_| ErrorCode::Invalid)?;
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

        let current_level = match self.state.raw_get_current_level()?.into_option() {
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
                // todo find suitable error.
                let new_level = self.state.set_level(new_level).map_err(|_| ErrorCode::Invalid)?;
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
    // todo Because this is const, we can't populated it by `set` methods in LevelControlCluster to ensure the cluster is setup correctly.
    // Hence, we should move this to the LevelControlHooks or take it as an input during initialisation.
    #[doc = "The cluster-metadata corresponding to this handler trait."]
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_revision(5)
        .with_features(level_control::Feature::LIGHTING.bits() | level_control::Feature::ON_OFF.bits())
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
        self.state.raw_get_current_level()
    }

    async fn on_level(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<Nullable<u8>, Error> {
        self.state.raw_get_on_level()
    }

    async fn set_on_level(
        &self,
        ctx: impl WriteContext,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        if let Some(level) = value.clone().into_option() {
            if level > H::MAX_LEVEL || level < H::MIN_LEVEL {
                // todo not sure if this is the correct error
                return Err(ErrorCode::InvalidData.into())
            }
        }

        self.state.raw_set_on_level(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn options(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<OptionsBitmap, Error> {
        self.state.raw_get_options()
    }

    async fn set_options(
        &self,
        ctx: impl WriteContext,
        value: OptionsBitmap,
    ) -> Result<(), Error> {
        self.state.raw_set_options(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn remaining_time(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        self.state.raw_get_remaining_time()
    }

    async fn max_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(H::MAX_LEVEL)
    }

    async fn min_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        Ok(H::MIN_LEVEL)
    }

    // todo uncomment when the FQ feature is no longer provisional
    // async fn current_frequency(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
    //     self.handler.raw_get_current_frequency()
    // }
    // async fn min_frequency(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
    //     self.handler.raw_get_min_frequency()
    // }
    // async fn max_frequency(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
    //     self.handler.raw_get_max_frequency()
    // }

    async fn on_off_transition_time(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        self.state.raw_get_on_off_transition_time()
    }

    async fn set_on_off_transition_time(&self, ctx: impl WriteContext, value:u16) -> Result<(), Error> {
        self.state.raw_set_on_off_transition_time(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn on_transition_time(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        self.state.raw_get_on_transition_time()
    }

    async fn set_on_transition_time(&self, ctx: impl WriteContext, value:Nullable<u16>) -> Result<(), Error> {
        self.state.raw_set_on_transition_time(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn off_transition_time(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        self.state.raw_get_off_transition_time()
    }

    async fn set_off_transition_time(&self, ctx: impl WriteContext, value:Nullable<u16>) -> Result<(), Error> {
        self.state.raw_set_off_transition_time(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn default_move_rate(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        self.state.raw_get_default_move_rate()
    }

    async fn set_default_move_rate(&self, ctx: impl WriteContext, value:Nullable<u8>) -> Result<(), Error> {
        // The spec is not explicit about what should be done if this happens.
        // For now we error out if DefaultMoveRate is equal to 0 as this is invalid
        // until spec defines a behaviour.
        if Some(0) == value.clone().into_option() {
            return Err(ErrorCode::InvalidData.into());
        }
        self.state.raw_set_default_move_rate(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn start_up_current_level(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        self.state.raw_get_startup_current_level()
    }

    async fn set_start_up_current_level(&self, ctx: impl WriteContext, value:Nullable<u8>) -> Result<(), Error> {
        if let Some(level) = value.clone().into_option() {
            if level > H::MAX_LEVEL || level < H::MIN_LEVEL {
                // todo not sure if this is the correct error
                return Err(ErrorCode::InvalidData.into())
            }
        }

        self.state.raw_set_startup_current_level(value)?;
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
        // todo replace the error with the comments when the FQ feature is no longer provisional
        Err(ErrorCode::InvalidCommand.into())

        // let new_frequency = self.handler.set_frequency(request.frequency()?)?;
        // self.write_current_frequency_quietly(new_frequency, true)
    }

}


pub struct LevelControlState<'a, H: LevelControlHooks> {
    handler: &'a H,
    last_current_level_notification: Cell<Instant>,
    // todo uncomment when the FQ feature is no longer provisional
    // last_current_frequency_notification: Cell<Instant>,
}

impl<'a, H: LevelControlHooks> LevelControlState<'a, H> {
    pub fn new(handler: &'a H) -> Self {
        Self {
            handler,
            last_current_level_notification: Cell::new(Instant::from_millis(0)),
            // todo uncomment when the FQ feature is no longer provisional
            // last_current_frequency_notification: Cell::new(Instant::from_millis(0)),
        }
    }

    fn write_remaining_time_quietly(&self, remaining_time: Duration, is_start_of_transition: bool) -> Result<(), Error> {
        let remaining_time_ds = remaining_time.as_millis().div_ceil(100) as u16;

        self.handler.raw_set_remaining_time(remaining_time_ds as u16)?;

        // RemainingTime Quiet report conditions:
        // - When it changes to 0, or
        // - When it changes from 0 to any value higher than 10, or
        // - When it changes, with a delta larger than 10, caused by the invoke of a command.
        let previous_remaining_time = self.handler.raw_get_remaining_time()?;
        let changed_to_zero = remaining_time_ds == 0 && previous_remaining_time != 0;
        let changed_from_zero_gt_10 = previous_remaining_time == 0 && remaining_time_ds > 10;
        let changed_by_gt_10 = remaining_time_ds.abs_diff(previous_remaining_time) > 10 && is_start_of_transition;

        if changed_to_zero || changed_from_zero_gt_10 || changed_by_gt_10 {
            // todo notify.changed();
        }

        Ok(())
    }

    fn write_current_level_quietly(&self, current_level: Nullable<u8>, is_end_of_transition: bool) -> Result<(), Error> {
        let previous_value = self.handler.raw_get_current_level()?;
        let last_notification = Instant::now() - self.last_current_level_notification.get();
        self.handler.raw_set_current_level(current_level.clone())?;

        // CurrentLevel Quiet report conditions:
        // - At most once per second, or
        // - At the end of the movement/transition, or
        // - When it changes from null to any other value and vice versa.
        if last_notification.ge(&Duration::from_secs(1)) || is_end_of_transition || previous_value.is_none() || current_level.is_none() {
            self.last_current_level_notification.set(Instant::now());
            // todo notify.changed();
        }

        // todo uncomment when the FQ feature is no longer provisional
        // // Update the current frequency according to the current level value
        // if (H::CLUSTER.feature_map & level_control::Feature::FREQUENCY.bits()) != 0 {
        //     self.write_current_frequency_quietly(self.handler.get_frequency_at_current_level()?, true)?;
        // }

        Ok(())
    }

    // todo uncomment when the FQ feature is no longer provisional
    // fn write_current_frequency_quietly(&self, current_frequency: u16, is_transition_end_start: bool) -> Result<(), Error> {
    //     let last_notification = Instant::now() - self.last_current_frequency_notification.get();
    //     self.handler.raw_set_current_frequency(current_frequency)?;

    //     // Changes to this attribute SHALL only be marked as reportable in the following cases:
    //     // - At most once per second, or
    //     // - At the start of the movement/transition, or
    //     // - At the end of the movement/transition.
    //     if last_notification.ge(&Duration::from_secs(1)) || is_transition_end_start {
    //         self.last_current_frequency_notification.set(Instant::now());
    //         // todo notify.changed()
    //     }

    //     Ok(())
    // }

}

impl<'a, H: LevelControlHooks> LevelControlHooks for LevelControlState<'a, H> {
    const MIN_LEVEL: u8 = H::MIN_LEVEL;
    const MAX_LEVEL: u8 = H::MAX_LEVEL;
    const FASTEST_RATE: u8 = H::FASTEST_RATE;

    delegate!{
        to self.handler {
            fn set_level(&self, level: u8) -> Result<u8, ()>;
            // fn set_frequency(&self, frequency: u16) -> Result<u16, Error>;
            // fn get_frequency_at_current_level(&self) -> Result<u16, Error>;
            fn raw_get_current_level(&self) -> Result<Nullable<u8>, Error>;
            fn raw_set_current_level(&self, value: Nullable<u8>) -> Result<(), Error>;
            fn raw_get_on_level(&self) -> Result<Nullable<u8>, Error>;
            fn raw_set_on_level(&self, value: Nullable<u8>) -> Result<(), Error>;
            fn raw_get_options(&self) -> Result<OptionsBitmap, Error>;
            fn raw_set_options(&self, value: OptionsBitmap) -> Result<(), Error>;
            fn raw_get_startup_current_level(&self) -> Result<Nullable<u8>, Error>;
            fn raw_set_startup_current_level(&self, _value: Nullable<u8>) -> Result<(), Error>;
            fn raw_get_remaining_time(&self) -> Result<u16, Error>;
            fn raw_set_remaining_time(&self, value: u16) -> Result<(), Error>;
            // fn raw_get_current_frequency(&self) -> Result<u16, Error>;
            // fn raw_set_current_frequency(&self, _value: u16) -> Result<(), Error>;
            // fn raw_get_min_frequency(&self) -> Result<u16, Error>;
            // fn raw_get_max_frequency(&self) -> Result<u16, Error>;
            fn raw_get_on_off_transition_time(&self) -> Result<u16, Error>;
            fn raw_set_on_off_transition_time(&self, _value: u16) -> Result<(), Error>;
            fn raw_get_on_transition_time(&self) -> Result<Nullable<u16>, Error>;
            fn raw_set_on_transition_time(&self, _value: Nullable<u16>) -> Result<(), Error>;
            fn raw_get_off_transition_time(&self) -> Result<Nullable<u16>, Error>;
            fn raw_set_off_transition_time(&self, _value: Nullable<u16>) -> Result<(), Error>;
            fn raw_get_default_move_rate(&self) -> Result<Nullable<u8>, Error>;
            fn raw_set_default_move_rate(&self, _value: Nullable<u8>) -> Result<(), Error>;
            fn raw_get_start_up_current_level(&self) -> Result<Nullable<u8>, Error>;
            fn raw_set_start_up_current_level(&self, _value: Nullable<u8>) -> Result<(), Error>;
        }
    }
}


pub trait LevelControlHooks {
    const MIN_LEVEL: u8;
    const MAX_LEVEL: u8;
    const FASTEST_RATE: u8;

    // Implements the business logic for setting the level.
    // DO NOT update attribute states.
    // Returns the value to which the device was set.
    //
    // todo Should this be allowed to error? 
    // If so, the error could be `()` and the SDK maps it to a suitable error signifying that something went wrong with the device.
    fn set_level(&self, level: u8) -> Result<u8, ()>;

    // todo uncomment when the FQ feature is no longer provisional
    // // If the device cannot approximate the frequency, then it SHALL 
    // // return a default response with an error code of CONSTRAINT_ERROR.
    // // If Ok, return the value of the new frequency.
    // fn set_frequency(&self, frequency: u16) -> Result<u16, Error>;
    // // If the FREQUENCY feature is supported, this method should return the 
    // // value of the device frequency at the current level.
    // fn get_frequency_at_current_level(&self) -> Result<u16, Error> {
    //     Err(ErrorCode::InvalidAction.into())
    // }

    // Raw accessors
    //  These methods should not perform any checks.
    //  They should simply set or get values.
    fn raw_get_current_level(&self) -> Result<Nullable<u8>, Error>;
    fn raw_set_current_level(&self, value: Nullable<u8>) -> Result<(), Error>;

    fn raw_get_on_level(&self) -> Result<Nullable<u8>, Error>;
    fn raw_set_on_level(&self, value: Nullable<u8>) -> Result<(), Error>;

    fn raw_get_options(&self) -> Result<OptionsBitmap, Error>;
    fn raw_set_options(&self, value: OptionsBitmap) -> Result<(), Error>;

    fn raw_get_startup_current_level(&self) -> Result<Nullable<u8>, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn raw_set_startup_current_level(&self, _value: Nullable<u8>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn raw_get_remaining_time(&self) -> Result<u16, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn raw_set_remaining_time(&self, value: u16) -> Result<(), Error>;

    // todo uncomment when the FQ feature is no longer provisional
    // fn raw_get_current_frequency(&self) -> Result<u16, Error> {
    //     Err(ErrorCode::InvalidAction.into())
    // }
    // fn raw_set_current_frequency(&self, _value: u16) -> Result<(), Error> {
    //     Err(ErrorCode::InvalidAction.into())
    // }
    // fn raw_get_min_frequency(&self) -> Result<u16, Error> {
    //     Err(ErrorCode::InvalidAction.into())
    // }    
    // fn raw_get_max_frequency(&self) -> Result<u16, Error> {
    //     Err(ErrorCode::InvalidAction.into())
    // }

    fn raw_get_on_off_transition_time(&self) -> Result<u16, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn raw_set_on_off_transition_time(&self, _value: u16) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn raw_get_on_transition_time(&self) -> Result<Nullable<u16>, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn raw_set_on_transition_time(&self, _value: Nullable<u16>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn raw_get_off_transition_time(&self) -> Result<Nullable<u16>, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn raw_set_off_transition_time(&self, _value: Nullable<u16>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn raw_get_default_move_rate(&self) -> Result<Nullable<u8>, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn raw_set_default_move_rate(&self, _value: Nullable<u8>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn raw_get_start_up_current_level(&self) -> Result<Nullable<u8>, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    fn raw_set_start_up_current_level(&self, _value: Nullable<u8>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }    

}
