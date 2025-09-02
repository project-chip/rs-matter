use core::cell::Cell;
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

enum Task {
    MoveToLevel{with_on_off: bool, target: u8, transition_time: u16},
    Move{with_on_off: bool, move_mode: MoveModeEnum, event_duration: Duration},
    // Step{with_on_off: bool},
    Stop,
}

pub struct LevelControlCluster<'lh, 'oc, T: LevelControlHooks> {
    dataver: Dataver,
    handler: &'lh T,
    task_signal: Signal<NoopRawMutex, Task>,
    last_current_level_update: Cell<Instant>,
    on_off: Cell<Option<&'oc OnOffHandler>>,
}

impl<'lh, 'oc, T: LevelControlHooks> LevelControlCluster<'lh, 'oc, T> {

    pub fn new(dataver: Dataver, handler: &'lh T) -> Self {
        Self {
            dataver,
            handler,
            task_signal: Signal::new(),
            last_current_level_update: Cell::new(Instant::from_millis(0)),
            on_off: Cell::new(None),
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }

    // Set the OnOff cluster instance that in coupled with this LevelControl cluster, i.e. the OnOff cluster on the same endpoint.
    // Note: The OnOff cluster on the same endpoint SHALL be set if any of the following is true
    //   - The OnOff feature is set
    //   - The `WithOnOff` commands are supported
    pub fn set_on_off_cluster(&self, cluster: &'oc OnOffHandler) {
        self.on_off.set(Some(cluster))
    }


    // todo Such a method might be useful to inform the user of any misconfigurations at start-up rather than during operation.
    // Similar checks are carried out by the Matter certification, however, this would also pick up if the on_off cluster was set when needed.
    // Validate that the LevelControlCluster has been set up correctly for the desired cluster configuration.
    // todo decide the type of the errors
    pub fn validate(&self, cluster: Cluster<'static>) -> Result<(), Error> {
        if cluster.revision != 7 {
            // "incorrect version number: expected 7 got {}", cluster.revision
            return Err(ErrorCode::Invalid.into());
        }

        if cluster.feature_map & level_control::Feature::ON_OFF.bits() != 0 {
            if let None = self.on_off.get() {
                // "a reference to the OnOff cluster must be set when the LIGHTING feature is enabled"
                return Err(ErrorCode::Invalid.into());
            }

            // // This is an example. Needs PartialEq derived on AttributeId
            // if cluster.attributes.contains(AttributeId::MaxLevel) {
            //     return Err(ErrorCode::Invalid.into());
            // }
        }

        if cluster.feature_map & level_control::Feature::LIGHTING.bits() != 0 {
            // From section 1.6.4.2
            // A value of 0x00 SHALL NOT be used.
            // A value of 0x01 SHALL indicate the minimum level that can be attained on a device.
            // A value of 0xFE SHALL indicate the maximum level that can be attained on a device.
            if T::MIN_LEVEL == 0 || T::MAX_LEVEL > 0xFE {
                return Err(ErrorCode::Invalid.into());
            }
        }

        Ok(())
    }

    // Processes the options of commands 'without On/Off'.
    // Returns true if execution of the command should continue, false otherwise.
    fn should_continue(&self, options_mask: OptionsBitmap, options_override: OptionsBitmap) -> Result<bool, Error> {
        let temporary_options = (options_mask & options_override) | self.handler.raw_get_options()?;

        Ok(temporary_options.contains(level_control::OptionsBitmap::EXECUTE_IF_OFF))
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
            // Task::Step { with_on_off } => return, // todo
            Task::Stop => return,
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
        let last_update = Instant::now() - self.last_current_level_update.get();
        self.last_current_level_update.set(Instant::now());
        self.handler.raw_set_current_level(current_level.clone())?;

        // CurrentLevel Quiet report conditions:
        // - At most once per second, or
        // - At the end of the movement/transition, or
        // - When it changes from null to any other value and vice versa.
        if last_update.ge(&Duration::from_secs(1)) || is_end_of_transition || previous_value.is_none() || current_level.is_none() {
            // todo notify.changed();
        }

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
        info!("update_coupled_onoff: 1");
        if !with_on_off {
            return Ok(());
        }

        info!("update_coupled_onoff: 2");
        let new_on_off_value = current_level > T::MIN_LEVEL;
        
        match self.on_off.get() {
            Some(on_off) => {
                info!("update_coupled_onoff: 3");
                let current_on_off = on_off.get();
                if current_on_off != new_on_off_value {
                    info!("update_coupled_onoff: 4");
                    on_off.coupled_cluster_set_on_off(true);
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

        // todo should this be corrected? Check the cpp impl
        if level > T::MAX_LEVEL || level < T::MIN_LEVEL {
            return Err(ErrorCode::InvalidCommand.into())
        }

        if with_on_off && !self.should_continue(options_mask, options_override)? {
            return Ok(());
        }

        info!("setting level to {} with transition time {:?}", level, transition_time);

        match transition_time {
            None | Some(0) => {
                self.task_signal.signal(Task::Stop);
                self.handler.set_level(level)?;
                self.write_current_level_quietly(Nullable::some(level), true)?;
                self.write_remaining_time_quietly(Duration::from_millis(0), true)?;

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
        //  todo: currently returning an incorrect error.
        //  Equivalent code in cpp impl: https://github.com/project-chip/connectedhomeip/blob/8adaf97c152e478200784629499756e81c53fd15/src/app/clusters/level-control/level-control.cpp#L904
        let mut current_level = match self.handler.raw_get_current_level()?.into_option() {
            Some(cl) => cl,
            None => return Err(ErrorCode::InvalidState.into()),
        };

        let increasing = current_level < target_level;

        let steps = match increasing {
            true => {target_level - current_level},
            false => {current_level - target_level},
        };

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
            self.handler.set_level(current_level)?;
            self.write_current_level_quietly(Nullable::some(current_level), is_transition_end)?;

            if is_transition_end {
                self.write_remaining_time_quietly(Duration::from_millis(0), is_transition_start)?;

                self.update_coupled_on_off(current_level, with_on_off)?;

                return Ok(());
            }
            else {
                match remaining_time > event_duration {
                    true => remaining_time -= event_duration,
                    false => {
                        warn!("remaining time is 0 before level reached target");
                        remaining_time = Duration::from_millis(0)
                    },
                }

                self.write_remaining_time_quietly(remaining_time, is_transition_start)?;
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

    // A single move command handler for both with and without on off.
    fn move_command(&self, with_on_off: bool, move_mode: MoveModeEnum, rate: Option<u8>, options_mask: OptionsBitmap, options_override: OptionsBitmap) -> Result<(), Error> {
        // From Section 1.6.7.2.2
        // 
        // If the Rate field is null, then the value of the
        // DefaultMoveRate attribute SHALL be used if that attribute is supported and its value is not null. If
        // the Rate field is null and the DefaultMoveRate attribute is either not supported or set to null, then
        // the device SHOULD move as fast as it is able.
        let rate = match rate {
            Some(val) => val,
            None => {
                match self.handler.raw_get_default_move_rate() {
                    Ok(default_move_rate) => {
                        match default_move_rate.into_option() {
                            Some(val) => val,
                            None => T::FASTEST_RATE,
                        }
                    }
                    Err(_) => T::FASTEST_RATE,
                }
            },
        };

        // This will catch the case where T::FASTEST_RATE is 0.
        // The spec is not explicit about what should be done if this happens.
        // For now we error out if DefaultMoveRate is equal to 0 as this is invalid
        // until spec defines a behaviour.
        if rate == 0 {
            return Err(Error::new(ErrorCode::InvalidCommand));
        }

        if with_on_off && !self.should_continue(options_mask, options_override)? {
            return Ok(());
        }

        let event_duration = Duration::from_hz(rate as u64);
        
        info!("moving with rate {}", rate);

        self.task_signal.signal(Task::Move { with_on_off: with_on_off, move_mode: move_mode, event_duration: event_duration });

        Ok(())
    }

    async fn move_transition(&self, with_on_off: bool, move_mode: MoveModeEnum, event_duration: Duration) -> Result<(), Error> {
        loop {
            let event_start_time = Instant::now();

            let current_level = match self.handler.raw_get_current_level()?.into_option() {
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
            if current_level == T::MIN_LEVEL && new_level > T::MAX_LEVEL {
                self.update_coupled_on_off(new_level, with_on_off)?;
            }

            let is_end_of_transition = (new_level == T::MAX_LEVEL) || (new_level == T::MIN_LEVEL);
            self.handler.set_level(new_level)?;
            self.write_current_level_quietly(Maybe::some(new_level), is_end_of_transition)?;

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
}

impl<'lh, 'oc, T: LevelControlHooks> ClusterAsyncHandler for LevelControlCluster<'lh, 'oc, T> {
    // todo Because this is const, I don't think that we can populated it by `set` methods in LevelControlCluster to ensure the cluster is setup correctly.
    // Hence, we should move this to the LevelControlHooks of take it as an input during initialisation.
    #[doc = "The cluster-metadata corresponding to this handler trait."]
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_revision(7)
        .with_features(level_control::Feature::LIGHTING.bits() | level_control::Feature::ON_OFF.bits())
        .with_attrs(with!(
            required;
            AttributeId::CurrentLevel 
            | AttributeId::RemainingTime
            | AttributeId::OnLevel
            | AttributeId::MaxLevel
            | AttributeId::MinLevel
            | AttributeId::Options
            | AttributeId::StartUpCurrentLevel
        )) // todo add missing attributes needed for a dimmable light AttributeId::MinLevel
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
        info!("LevelControl: Called current_level()");
        self.handler.raw_get_current_level()
    }

    async fn on_level(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<Nullable<u8>, Error> {
        info!("LevelControl: Called on_level()");
        self.handler.raw_get_on_level()
    }

    async fn set_on_level(
        &self,
        ctx: impl WriteContext,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        info!("set_on_level called");
        if let Some(level) = value.clone().into_option() {
            if level > T::MAX_LEVEL || level < T::MIN_LEVEL {
                // todo not sure if this is the correct error
                return Err(ErrorCode::InvalidData.into())
            }
        }

        self.handler.raw_set_on_level(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn options(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<OptionsBitmap, Error> {
        info!("LevelControl: Called options()");
        self.handler.raw_get_options()
    }

    async fn set_options(
        &self,
        ctx: impl WriteContext,
        value: OptionsBitmap,
    ) -> Result<(), Error> {
        info!("set_options called");
        self.handler.raw_set_options(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn remaining_time(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        info!("LevelControl: Called remaining_time()");
        self.handler.raw_get_remaining_time()
    }

    async fn max_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        info!("LevelControl: Called max_level()");
        Ok(T::MAX_LEVEL)
    }

    async fn min_level(&self, _ctx: impl ReadContext) -> Result<u8, Error> {
        info!("LevelControl: Called min_level()");
        Ok(T::MIN_LEVEL)
    }

    async fn current_frequency(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        self.handler.raw_get_current_frequency()
    }

    async fn min_frequency(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        self.handler.raw_get_min_frequency()
    }

    async fn max_frequency(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        self.handler.raw_get_max_frequency()
    }

    async fn on_off_transition_time(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        self.handler.raw_get_on_off_transition_time()
    }

    async fn set_on_off_transition_time(&self, ctx: impl WriteContext, value:u16) -> Result<(), Error> {
        self.handler.raw_set_on_off_transition_time(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn on_transition_time(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        self.handler.raw_get_on_transition_time()
    }

    async fn set_on_transition_time(&self, ctx: impl WriteContext, value:Nullable<u16>) -> Result<(), Error> {
        self.handler.raw_set_on_transition_time(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn off_transition_time(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        self.handler.raw_get_off_transition_time()
    }

    async fn set_off_transition_time(&self, ctx: impl WriteContext, value:Nullable<u16>) -> Result<(), Error> {
        self.handler.raw_set_off_transition_time(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn default_move_rate(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        self.handler.raw_get_default_move_rate()
    }

    async fn set_default_move_rate(&self, ctx: impl WriteContext, value:Nullable<u8>) -> Result<(), Error> {
        // The spec is not explicit about what should be done if this happens.
        // For now we error out if DefaultMoveRate is equal to 0 as this is invalid
        // until spec defines a behaviour.
        if Some(0) == value.clone().into_option() {
            return Err(ErrorCode::InvalidData.into());
        }
        self.handler.raw_set_default_move_rate(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn start_up_current_level(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        info!("LevelControl: Called start_up_current_level()");
        self.handler.raw_get_startup_current_level()
    }

    async fn set_start_up_current_level(&self, ctx: impl WriteContext, value:Nullable<u8>) -> Result<(), Error> {
        info!("LevelControl: Called set_start_up_current_level()");
        if let Some(level) = value.clone().into_option() {
            if level > T::MAX_LEVEL || level < T::MIN_LEVEL {
                // todo not sure if this is the correct error
                return Err(ErrorCode::InvalidData.into())
            }
        }

        self.handler.raw_set_startup_current_level(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn handle_move_to_level(
        &self,
        _ctx: impl InvokeContext,
        request: MoveToLevelRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_move_to_level()");

        self.move_to_level(false, request.level()?, request.transition_time()?.into_option(), request.options_mask()?, request.options_override()?)

    }

    async fn handle_move(
        &self,
        _ctx: impl InvokeContext,
        request: MoveRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_move()");

        self.move_command(false, request.move_mode()?, request.rate()?.into_option(), request.options_mask()?, request.options_override()?)

    }

    async fn handle_step(
        &self,
        _ctx: impl InvokeContext,
        request: StepRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_step()");
        if !self.should_continue(request.options_mask()?, request.options_override()?)? {
            // todo Should this return an error?
            info!("Ignoring command due to options settings");
            return Ok(());
        }

        Ok(())
    }

    async fn handle_stop(
        &self,
        _ctx: impl InvokeContext,
        request: StopRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_stop()");
        if !self.should_continue(request.options_mask()?, request.options_override()?)? {
            // todo Should this return an error?
            info!("Ignoring command due to options settings");
            return Ok(());
        }

        Ok(())
    }

    async fn handle_move_to_level_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        request: MoveToLevelWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_move_to_level_with_on_off()");

        self.move_to_level(true, request.level()?, request.transition_time()?.into_option(), request.options_mask()?, request.options_override()?)

    }

    async fn handle_move_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        request: MoveWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_move_with_on_off()");

        self.move_command(true, request.move_mode()?, request.rate()?.into_option(), request.options_mask()?, request.options_override()?)
    }

    async fn handle_step_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        _request: StepWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_step_with_on_off()");
        Ok(())
    }

    async fn handle_stop_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        _request: StopWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_stop_with_on_off()");
        Ok(())
    }

    async fn handle_move_to_closest_frequency(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveToClosestFrequencyRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_move_to_closest_frequency()");
        Ok(())
    }

}


pub trait LevelControlHooks {
    const MIN_LEVEL: u8;
    const MAX_LEVEL: u8;
    const FASTEST_RATE: u8;

    // Implements the business logic for setting the level.
    // Do not update attribute states.
    fn set_level(&self, level: u8) -> Result<(), Error>;

    // Raw accessors
    //  These methods should not perform any checks.
    //  They should simply set of get values.
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
    
    fn raw_get_current_frequency(&self) -> Result<u16, Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn raw_set_current_frequency(&self, _value: u16) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    
    fn raw_get_min_frequency(&self) -> Result<u16, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
    
    fn raw_get_max_frequency(&self) -> Result<u16, Error> {
        Err(ErrorCode::InvalidAction.into())
    }

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
