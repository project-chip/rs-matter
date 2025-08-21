use core::cell::Cell;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant};

use crate::im::AttrResp;
use crate::utils::storage::WriteBuf;
use crate::tlv::{FromTLV, Nullable, TLVElement};
use crate::dm::{AsyncHandler, AttrDetails, Cluster, CmdDetails, Dataver, InvokeContext, InvokeContextInstance, InvokeReplyInstance, ReadContext, ReadContextInstance, CmdDataTracker, ReadReplyInstance, WriteContext};
use crate::dm::clusters::{decl, level_control};
pub use crate::dm::clusters::decl::level_control::*;
use crate::with;
use crate::error::{Error, ErrorCode};

enum Task {
    Stop,
    MoveToLevel{target: u8, transition_time: u16},
}

pub struct LevelControlCluster<'a, T: LevelControlHooks> {
    dataver: Dataver,
    handler: &'a T,
    task_signal: Signal<NoopRawMutex, Task>,
    last_current_level_update: Cell<Instant>,
}

impl<'a, T: LevelControlHooks> LevelControlCluster<'a, T> {

    pub fn new(dataver: Dataver, handler: &'a T) -> Self {
        Self {
            dataver,
            handler,
            task_signal: Signal::new(),
            last_current_level_update: Cell::new(Instant::from_millis(0)),
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }

    // Processes the options of commands 'without On/Off'.
    // Returns true if execution of the command should continue, false otherwise.
    fn should_continue(&self, options_mask: OptionsBitmap, options_override: OptionsBitmap) -> bool {
        let temporary_options = (options_mask & options_override) | self.handler.raw_get_options();

        temporary_options.contains(level_control::OptionsBitmap::EXECUTE_IF_OFF)
    }

    async fn task_manager(&self, task: Task) {
        match task {
            Task::Stop => return,
            Task::MoveToLevel{ target, transition_time} => {
                if let Err(e) = self.move_to_level_transition(target, transition_time).await {
                    error!("{}", e.to_string());
                }
            },
        }
    }

    fn write_remaining_time_quietly(&self, remaining_time: Duration, is_start_of_transition: bool) -> Result<(), Error> {
        let remaining_time_ds = remaining_time.as_millis().div_ceil(100) as u16;

        self.handler.raw_set_remaining_time(remaining_time_ds as u16)?;

        // RemainingTime Quiet report conditions:
        // - When it changes to 0, or
        // - When it changes from 0 to any value higher than 10, or
        // - When it changes, with a delta larger than 10, caused by the invoke of a command.
        let previous_remaining_time = self.handler.raw_get_remaining_time();
        let changed_to_zero = remaining_time_ds == 0 && previous_remaining_time != 0;
        let changed_from_zero_gt_10 = previous_remaining_time == 0 && remaining_time_ds > 10;
        let changed_by_gt_10 = remaining_time_ds.abs_diff(previous_remaining_time) > 10 && is_start_of_transition;

        if changed_to_zero || changed_from_zero_gt_10 || changed_by_gt_10 {
            // todo notify.changed();
        }

        Ok(())
    }

    fn write_current_level_quietly(&self, current_level: Nullable<u8>, is_end_of_transition: bool) -> Result<(), Error> {
        let previous_value = self.handler.raw_get_current_level();
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
    async fn update_coupled_onoff(&self, ctx: impl InvokeContext, current_level: u8) -> Result<(), Error>{
        // From section 1.6.4.1.2.
        // There are two sets of commands provided in the Level Control cluster. These are identical, except
        // that the first set (MoveToLevel, Move and Step commands) SHALL NOT affect the OnOff attribute,
        // whereas the second set ('with On/Off' variants) SHALL.
        let with_on_off_commands: u32 = 
            CommandId::MoveToLevelWithOnOff as u32 |
            CommandId::MoveWithOnOff as u32 |
            CommandId::StepWithOnOff as u32 | 
            CommandId::StopWithOnOff as u32;
        if ctx.cmd().cmd_id & with_on_off_commands == 0 {
            return Ok(());
        }
        
        // step1 : get the current on_off value. Probably not needed.
        let attr = AttrDetails{
            node: ctx.cmd().node,
            endpoint_id: ctx.cmd().endpoint_id,
            cluster_id: crate::dm::clusters::decl::on_off::FULL_CLUSTER.id,
            attr_id: crate::dm::clusters::decl::on_off::AttributeId::OnOff as u32,
            list_index: None,
            fab_idx: 0,
            fab_filter: false,
            dataver: None,
            wildcard: false,
        };
        let read_context = ReadContextInstance::new(
            ctx.exchange(),
            ctx.handler(),
            ctx.buffers(),
            &attr,
        );
        let mut buf = [0u8; 1024]; // todo get accurate size?
        let mut wb = WriteBuf::new(&mut buf);
        let mut tw = crate::tlv::TLVWriter::new(&mut wb);
        let reply = ReadReplyInstance::new(&attr, &mut tw);
        ctx.handler().read(read_context, reply).await?;

        let attr_response = AttrResp::from_tlv(&TLVElement::new(&buf))?;
        let on_off = match attr_response {
            AttrResp::Status(_attr_status) => {
                // todo not the correct error
                return Err(ErrorCode::AttributeNotFound.into())
            },
            AttrResp::Data(attr_data) => {
                attr_data.data.bool()?
            },
        };

        // step 2: set the on_off value based on the current level.
        let new_on_off_value = current_level > T::MIN_LEVEL;

        if on_off != new_on_off_value {
            let mut buf = [0u8; 1024]; // todo get accurate size?
            let mut wb = WriteBuf::new(&mut buf);
            let mut tw = crate::tlv::TLVWriter::new(&mut wb);
            let tlv_element = &TLVElement::new(&[]);
            let mut tracker = CmdDataTracker::new();

            match new_on_off_value {
                true => {
                    let cmd_details = CmdDetails{
                        node: ctx.cmd().node,
                        endpoint_id: ctx.cmd().endpoint_id,
                        cluster_id: decl::on_off::FULL_CLUSTER.id,
                        cmd_id: decl::on_off::CommandId::On as u32,
                        wildcard: false,
                    };

                    let on_invoke_context = InvokeContextInstance::new(
                        ctx.exchange(),
                        ctx.handler(),
                        ctx.buffers(),
                        &cmd_details,
                        &tlv_element,
                        &(),
                    );

                    let reply = InvokeReplyInstance::new(&cmd_details, &mut tracker, &mut tw);
                    // COMPILATION ERROR overflow depth limit
                    ctx.handler().invoke(on_invoke_context, reply).await?;
                    // todo read reply for success
                },
                false => {
                    let cmd_details = CmdDetails{
                        node: ctx.cmd().node,
                        endpoint_id: ctx.cmd().endpoint_id,
                        cluster_id: decl::on_off::FULL_CLUSTER.id,
                        cmd_id: decl::on_off::CommandId::Off as u32,
                        wildcard: false,
                    };

                    let off_invoke_context = InvokeContextInstance::new(
                        ctx.exchange(),
                        ctx.handler(),
                        ctx.buffers(),
                        &cmd_details,
                        &tlv_element,
                        &(),
                    );

                    let reply = InvokeReplyInstance::new(&cmd_details, &mut tracker, &mut tw);
                    // COMPILATION ERROR overflow depth limit
                    ctx.handler().invoke(off_invoke_context, reply).await?;
                    // todo read reply for success
                },
            }
        }

        Ok(())
    }

    async fn move_to_level_transition(&self, target_level: u8, transition_time: u16) -> Result<(), Error> {
        let event_start_time = Instant::now();

        // Check if current_level is null. If so, return error.
        //  todo: currently returning an incorrect error.
        //  Equivalent code in cpp impl: https://github.com/project-chip/connectedhomeip/blob/8adaf97c152e478200784629499756e81c53fd15/src/app/clusters/level-control/level-control.cpp#L904
        let mut current_level = match self.handler.raw_get_current_level().into_option() {
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

                // todo if withOnOff command, update the OnOff cluster accordingly.
                //  This is going to require passing the context through the signal
                // self.update_coupled_onoff(ctx, current_level).await?;
                

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

    // A single method for dealing with the MoveToLevel and MoveToLevelWithOnOff logic.
    async fn move_to_level(&self, ctx: impl InvokeContext, level: u8, transition_time: Option<u16>, options_mask: OptionsBitmap, options_override: OptionsBitmap) -> Result<(), Error>{
        // todo should this be corrected? Check the cpp impl
        if level > T::MAX_LEVEL || level < T::MIN_LEVEL {
            return Err(Error::new(ErrorCode::InvalidCommand))
        }

        let with_on_off = ctx.cmd().cmd_id == level_control::CommandId::MoveToLevelWithOnOff as u32;
        if with_on_off && !self.should_continue(options_mask, options_override) {
            return Ok(());
        }

        info!("setting level to {} with transition time {:?}", level, transition_time);

        match transition_time {
            None | Some(0) => {
                self.task_signal.signal(Task::Stop);
                self.handler.set_level(level)?;
                self.write_current_level_quietly(Nullable::some(level), true)?;
                self.write_remaining_time_quietly(Duration::from_millis(0), true)?;

                self.update_coupled_onoff(ctx, level).await?;

            }
            Some(t_time) => {
                self.task_signal.signal(Task::MoveToLevel { target: level, transition_time: t_time});
            }
        }

        Ok(())
    }
}

impl<'a, T: LevelControlHooks> ClusterAsyncHandler for LevelControlCluster<'a, T> {
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

    // fn current_frequency(&self,ctx:impl crate::dm::ReadContext) -> Result<u16,crate::error::Error>{

    async fn current_level(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<Nullable<u8>, Error> {
        info!("LevelControl: Called current_level()");
        Ok(self.handler.raw_get_current_level())
    }

    async fn options(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<OptionsBitmap, Error> {
        info!("LevelControl: Called options()");
        Ok(self.handler.raw_get_options())
    }

    async fn on_level(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<Nullable<u8>, Error> {
        info!("LevelControl: Called on_level()");
        Ok(self.handler.raw_get_on_level())
    }

    async fn set_options(
        &self,
        _ctx: impl WriteContext,
        value: OptionsBitmap,
    ) -> Result<(), Error> {
        info!("set_options called");
        self.handler.raw_set_options(value)
    }

    async fn set_on_level(
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

    async fn remaining_time(&self, _ctx: impl ReadContext) -> Result<u16,Error> {
        info!("LevelControl: Called remaining_time()");
        Ok(self.handler.raw_get_remaining_time())
    }

    async fn max_level(&self, _ctx: impl ReadContext) -> Result<u8,Error> {
        info!("LevelControl: Called max_level()");
        Ok(T::MAX_LEVEL)
    }

    async fn min_level(&self, _ctx: impl ReadContext) -> Result<u8,Error> {
        info!("LevelControl: Called min_level()");
        Ok(T::MIN_LEVEL)
    }

    async fn start_up_current_level(&self, _ctx: impl ReadContext) -> Result<Nullable<u8> ,Error> {
        info!("LevelControl: Called start_up_current_level()");
        Ok(self.handler.raw_get_startup_current_level())
    }

    async fn set_start_up_current_level(&self, ctx: impl WriteContext, value:Nullable<u8>) -> Result<(),Error> {
        info!("LevelControl: Called set_start_up_current_level()");
        self.handler.raw_set_startup_current_level(value)?;
        self.dataver_changed();
        ctx.notify_changed();
        Ok(())
    }

    async fn handle_move_to_level(
        &self,
        ctx: impl InvokeContext,
        request: MoveToLevelRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_move_to_level()");

        self.move_to_level(ctx, request.level()?, request.transition_time()?.into_option(), request.options_mask()?, request.options_override()?).await
    }

    async fn handle_move(
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

    async fn handle_step(
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

    async fn handle_stop(
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

    async fn handle_move_to_level_with_on_off(
        &self,
        ctx: impl InvokeContext,
        request: MoveToLevelWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_move_to_level_with_on_off()");

        self.move_to_level(ctx, request.level()?, request.transition_time()?.into_option(), request.options_mask()?, request.options_override()?).await
    }

    async fn handle_move_with_on_off(
        &self,
        _ctx: impl InvokeContext,
        _request: MoveWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("LevelControl: Called handle_move_with_on_off()");
        Ok(())
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

    // Raw accessors
    //  These methods should not perform any checks.
    //  They should simply set of get values.
    fn raw_get_options(&self) -> OptionsBitmap;
    fn raw_set_options(&self, value: OptionsBitmap) -> Result<(), Error>;
    fn raw_get_on_level(&self) -> Nullable<u8>;
    fn raw_set_on_level(&self, value: Nullable<u8>) -> Result<(), Error>;
    fn raw_get_current_level(&self) -> Nullable<u8>;
    fn raw_set_current_level(&self, value: Nullable<u8>) -> Result<(), Error>;
    fn raw_get_startup_current_level(&self) -> Nullable<u8>;
    fn raw_set_startup_current_level(&self, value: Nullable<u8>) -> Result<(), Error>;
    fn raw_get_remaining_time(&self) -> u16;
    fn raw_set_remaining_time(&self, value: u16) -> Result<(), Error>;

    // Implements the business logic for setting the level.
    // Do not update attribute states.
    fn set_level(&self, level: u8) -> Result<(), Error>;
}
