use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
// use log::{warn, info}; // todo there seems to be a conflict
use crate::dm::{Dataver, InvokeContext, ReadContext, WriteContext, Cluster};
use crate::tlv::Nullable;

use crate::dm::clusters::level_control;
pub use crate::dm::clusters::decl::level_control::*;
use crate::with;
use crate::error::{Error, ErrorCode};

enum Task {
    Stop,
    Fade{target: u8, transition_time: u16},
}

pub struct LevelControlCluster<'a, T: LevelControlHooks> {
    dataver: Dataver,
    handler: &'a T,
    task_signal: Signal<NoopRawMutex, Task>,
}

impl<'a, T: LevelControlHooks> LevelControlCluster<'a, T> {

    pub fn new(dataver: Dataver, handler: &'a T) -> Self {
        Self {
            dataver,
            handler,
            task_signal: Signal::new()
        }
    }

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

    async fn task_manager(&self, task: Task) {
        match task {
            Task::Stop => return,
            Task::Fade{ target, transition_time} => {
                self.fade(target, transition_time).await;
            },
        }
    }

    async fn fade(&self, target_level: u8, transition_time: u16) {
        let current_level = self.handler.raw_get_current_level();
        // todo: current_level should be Nullabel. If null, return status failure? Or log error?
        //  see here for equivalent code in cpp impl: https://github.com/project-chip/connectedhomeip/blob/8adaf97c152e478200784629499756e81c53fd15/src/app/clusters/level-control/level-control.cpp#L904

        let increasing = current_level < target_level;

        loop {
            // todo cluster logic
            let steps = match increasing {
                true => {target_level - current_level},
                false => {current_level - target_level},
            };

            let step_size: u8 = 1;
            let duration = transition_time / (steps as u16 / step_size as u16);
            let new_level = current_level + step_size;

            // todo: Handle errors.
            self.handler.raw_set_current_level(new_level).unwrap();
            self.handler.set_level(new_level).unwrap();
            if new_level == target_level {
                return;
            }

            // todo if withOnOff command, update the OnOff cluster accordingly
            //  This is going to require passing the context through the signal

            embassy_time::Timer::after(embassy_time::Duration::from_millis(duration as u64)).await;
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    // Processes the options of commands 'without On/Off'.
    // Returns true if execution of the command should continue, false otherwise.
    fn should_continue(&self, options_mask: OptionsBitmap, options_override: OptionsBitmap) -> bool {
        let temporary_options = (options_mask & options_override) | self.handler.raw_get_options();

        temporary_options.contains(level_control::OptionsBitmap::EXECUTE_IF_OFF)
    }

    // A single method for dealing with the MoveToLevel and MoveToLevelWithOnOff logic.
    fn move_to_level(&self, ctx: impl InvokeContext, level: u8, transition_time: Option<u16>, options_mask: OptionsBitmap, options_override: OptionsBitmap) -> Result<(), Error>{
        // todo should this be corrected? Check the cpp impl
        if level > T::MAX_LEVEL || level < T::MIN_LEVEL {
            return Err(Error::new(ErrorCode::InvalidCommand))
        }

        let with_on_off = ctx.cmd().cmd_id == level_control::CommandId::MoveToLevelWithOnOff as u32;
        if with_on_off && !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        info!("setting level to {}", level);

        match transition_time {
            None | Some(0) => {
                self.task_signal.signal(Task::Stop);
                self.handler.set_level(level)?;
                self.handler.raw_set_current_level(level)?;
                ctx.notify_changed();

                // todo: possibly update the OnOff cluster
            }
            Some(t_time) => {
                self.task_signal.signal(Task::Fade { target: level, transition_time: t_time});
                ctx.notify_changed();
            }
        }

        Ok(())
    }
}

impl<'a, T: LevelControlHooks> ClusterHandler for LevelControlCluster<'a, T> {
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

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    // fn current_frequency(&self,ctx:impl crate::dm::ReadContext) -> Result<u16,crate::error::Error>{

    fn current_level(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<Nullable<u8>, Error> {
        info!("LevelControl: Called current_level()");
        Ok(Nullable::some(self.handler.raw_get_current_level()))
    }

    fn options(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<OptionsBitmap, Error> {
        info!("LevelControl: Called options()");
        Ok(self.handler.raw_get_options())
    }

    fn on_level(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<Nullable<u8>, Error> {
        info!("LevelControl: Called on_level()");
        Ok(self.handler.raw_get_on_level())
    }

    fn set_options(
        &self,
        _ctx: impl WriteContext,
        value: OptionsBitmap,
    ) -> Result<(), Error> {
        info!("set_options called");
        self.handler.raw_set_options(value)
    }

    fn set_on_level(
        &self,
        ctx: impl WriteContext,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        info!("set_on_level called");
        self.handler.raw_set_on_level(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    fn remaining_time(&self, _ctx: impl ReadContext) -> Result<u16,Error> {
        info!("LevelControl: Called remaining_time()");
        Ok(self.handler.raw_get_remaining_time())
    }

    fn max_level(&self, _ctx: impl ReadContext) -> Result<u8,Error> {
        info!("LevelControl: Called max_level()");
        Ok(T::MAX_LEVEL)
    }

    fn min_level(&self, _ctx: impl ReadContext) -> Result<u8,Error> {
        info!("LevelControl: Called min_level()");
        Ok(T::MIN_LEVEL)
    }

    fn start_up_current_level(&self, _ctx: impl ReadContext) -> Result<Nullable<u8> ,Error> {
        info!("LevelControl: Called start_up_current_level()");
        Ok(self.handler.raw_get_startup_current_level())
    }

    fn set_start_up_current_level(&self, ctx: impl WriteContext, value:Nullable<u8>) -> Result<(),Error> {
        info!("LevelControl: Called set_start_up_current_level()");
        self.handler.raw_set_startup_current_level(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    fn handle_move_to_level(
        &self,
        ctx: impl InvokeContext,
        request: MoveToLevelRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_move_to_level()");

        self.move_to_level(ctx, request.level()?, request.transition_time()?.into_option(), request.options_mask()?, request.options_override()?)
    }

    fn handle_move(
        &self,
        _ctx: impl InvokeContext,
        request: MoveRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_move()");

        if !self.should_continue(request.options_mask()?, request.options_override()?) {
            // todo Should this return an error?
            info!("Ignoring command due to options settings");
            return Ok(());
        }

        let rate = request.rate()?.into_option();

        let rate = match rate {
            Some(0) | None => { return Err(Error::new(ErrorCode::InvalidCommand)); },
            Some(val) => val,
        };

        info!("moving with rate {}", rate);
        // todo implement move
        Ok(())
    }

    fn handle_step(
        &self,
        _ctx: impl InvokeContext,
        request: StepRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_step()");
        if !self.should_continue(request.options_mask()?, request.options_override()?) {
            // todo Should this return an error?
            info!("Ignoring command due to options settings");
            return Ok(());
        }

        Ok(())
    }

    fn handle_stop(
        &self,
        _ctx: impl InvokeContext,
        request: StopRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_stop()");
        if !self.should_continue(request.options_mask()?, request.options_override()?) {
            // todo Should this return an error?
            info!("Ignoring command due to options settings");
            return Ok(());
        }

        Ok(())
    }

    fn handle_move_to_level_with_on_off(
        &self,
        ctx: impl InvokeContext,
        request: MoveToLevelWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_move_to_level_with_on_off()");

        self.move_to_level(ctx, request.level()?, request.transition_time()?.into_option(), request.options_mask()?, request.options_override()?)
    }

    fn handle_move_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_move_with_on_off()");
        Ok(())
    }

    fn handle_step_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        _request: StepWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_step_with_on_off()");
        Ok(())
    }

    fn handle_stop_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        _request: StopWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_stop_with_on_off()");
        Ok(())
    }

    fn handle_move_to_closest_frequency(
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

    // Raw accessors
    //  These methods should not perform any checks.
    //  They should simply set of get values.
    fn raw_get_options(&self) -> OptionsBitmap;
    fn raw_set_options(&self, value: OptionsBitmap) -> Result<(), Error>;
    fn raw_get_on_level(&self) -> Nullable<u8>;
    fn raw_set_on_level(&self, value: Nullable<u8>) -> Result<(), Error>;
    fn raw_get_current_level(&self) -> u8;
    fn raw_set_current_level(&self, value: u8) -> Result<(), Error>;
    fn raw_get_startup_current_level(&self) -> Nullable<u8>;
    fn raw_set_startup_current_level(&self, value: Nullable<u8>) -> Result<(), Error>;
    fn raw_get_remaining_time(&self) -> u16;
    fn raw_set_remaining_time(&self, value: u16) -> Result<(), Error>;

    // Implements the business logic for setting the level.
    // Do not update attribute states.
    fn set_level(&self, level: u8) -> Result<(), Error>;
}


