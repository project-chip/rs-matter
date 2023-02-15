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

use super::objects::*;
use crate::{
    error::*,
    interaction_model::{command::CommandReq, core::IMStatusCode},
};
use log::info;
use num_derive::FromPrimitive;
use std::sync::{Arc, Mutex};
use std::{thread, time};

// ID of base cluster for level control, other specifics are defined for lighting - might need an update in next release
pub const ID: u32 = 0x0008;

const MIN_LVL_DEFAULT: u8 = 0;
const MAX_LVL_DEFAULT: u8 = 254;

#[derive(FromPrimitive)]
pub enum Attributes {
    CurrentLevel = 0x0000,
    RemainingTime = 0x0001,
    MinLevel = 0x0002,
    MaxLevel = 0x0003,
    OnLevel = 0x0011,
    Options = 0x000F,
    StartUpCurrentLevel = 0x4000,
}

struct DataCallback<T, U> {
    name: Commands,
    callback: Box<dyn FnMut(T, U, T)>,
}

impl<T, U> DataCallback<T, U> {
    fn call(&mut self, arg1: T, arg2: U, arg3: T) {
        (self.callback)(arg1, arg2, arg3);
    }
}

struct Callback {
    name: Commands,
    callback: Box<dyn FnMut()>,
}

impl Callback {
    fn call(&mut self) {
        (self.callback)()
    }
}

enum MoveMode {
    Up = 0x00,
    Down = 0x01,
}

impl MoveMode {
    pub fn from_u8(src: u8) -> MoveMode {
        if src == 0x00 {
            MoveMode::Up
        } else {
            MoveMode::Down
        }
    }
}
enum StepMode {
    Up = 0x00,
    Down = 0x01,
}

impl StepMode {
    pub fn from_u8(src: u8) -> StepMode {
        if src == 0x00 {
            StepMode::Up
        } else {
            StepMode::Down
        }
    }
}

#[derive(FromPrimitive, PartialEq)]
pub enum Commands {
    MoveToLevel = 0x00,
    Move = 0x01,
    Step = 0x02,
    Stop = 0x03,
    MoveToLevelWithOnOff = 0x04,
    MoveWithOnOff = 0x05,
    StepWithOnOff = 0x06,
    StopWithOnOff = 0x07,
    MoveToClosestFrequency = 0x08,
}

pub struct UpdateDataStore {
    level: u8,
    remaining_time: u16,
    current_command: Option<Commands>,
    is_running: bool,
    is_fresh: bool,
}

impl UpdateDataStore {
    fn tick_time(&mut self) -> bool {
        self.remaining_time = match self.remaining_time.checked_sub(1) {
            Some(t) => t,
            None => {
                self.current_command = None;
                self.is_running = false;
                0
            }
        };

        self.is_running
    }

    // Prepare a command to run
    fn prepare_command(&mut self, time: Option<u16>, cmd: Option<Commands>) {
        self.remaining_time = match time {
            Some(t) => t,
            None => self.remaining_time,
        };
        self.current_command = cmd;
        self.is_running = true;
    }

    fn stop_current_command(&mut self) {
        self.is_running = false;
        self.current_command = Some(Commands::Stop);
        self.remaining_time = 0;
        self.is_fresh = false;
    }

    pub fn update_level(&mut self, level: u8) {
        self.level = level;
        self.is_fresh = true;
    }
}

// Each 1/10th of a second wake up and update current volume and remaining time
fn move_to_lvl(event_loop: &Arc<Mutex<UpdateDataStore>>, time: u16, new_level: u8, cur_level: u8) {
    let update_interval = time::Duration::from_millis(100);

    let dir;
    let steps: u16 = time;
    let mut delta;

    if new_level > cur_level {
        delta = match new_level.checked_sub(cur_level) {
            Some(t) => t as u16,
            None => 0,
        };

        delta = match delta.checked_div(steps) {
            Some(t) => t,
            None => 1,
        };
        dir = MoveMode::Up;
    } else {
        delta = match cur_level.checked_sub(new_level) {
            Some(t) => t as u16,
            None => 0,
        };
        delta = match delta.checked_div(steps) {
            Some(t) => {
                if t == 0 {
                    1
                } else {
                    t
                }
            }
            None => 1,
        };
        dir = MoveMode::Down;
    }

    loop {
        thread::sleep(update_interval);
        let mut loop_data = event_loop.lock().unwrap();
        if !loop_data.is_running {
            info!("Command finished or cancelled.");
            break;
        }

        match dir {
            MoveMode::Up => {
                loop_data.level = match loop_data.level.checked_add(delta as u8) {
                    Some(t) => {
                        if t >= new_level {
                            // Exit early if we hit the level we are looking for
                            loop_data.remaining_time = 0;
                            new_level
                        } else {
                            t
                        }
                    }
                    None => loop_data.level,
                };
            }
            MoveMode::Down => {
                loop_data.level = match loop_data.level.checked_sub(delta as u8) {
                    Some(t) => {
                        if t <= new_level {
                            // Exit early if we hit the level we are looking for
                            loop_data.remaining_time = 0;
                            new_level
                        } else {
                            t
                        }
                    }
                    None => loop_data.level,
                };
            }
        }
        loop_data.is_fresh = true;
        if !loop_data.tick_time() {
            loop_data.level = new_level;
            break;
        }
    }
}

// Each 1/10th of a second wake up and update current volume and remaining time
fn move_lvl_down(event_loop: &Arc<Mutex<UpdateDataStore>>, rate: u8, min_level: u8, cur_level: u8) {
    let update_interval = time::Duration::from_millis(100);
    let mut new_level = cur_level;
    loop {
        thread::sleep(update_interval);
        new_level = match new_level.checked_sub(rate) {
            Some(t) => t,
            None => min_level,
        };
        let mut loop_data = event_loop.lock().unwrap();
        if !loop_data.is_running {
            info!("Command stoppped, finished or cancelled.");
            break;
        }
        if new_level <= min_level {
            loop_data.level = min_level;
            break;
        } else {
            loop_data.level = new_level;
        }
    }
}

// Each 1/10th of a second wake up and update current volume and remaining time
fn move_lvl_up(event_loop: &Arc<Mutex<UpdateDataStore>>, rate: u8, max_level: u8, cur_level: u8) {
    let update_interval = time::Duration::from_millis(100);
    let mut new_level = cur_level;
    loop {
        thread::sleep(update_interval);
        new_level = match new_level.checked_add(rate) {
            Some(t) => t,
            None => max_level,
        };
        let mut loop_data = event_loop.lock().unwrap();
        if !loop_data.is_running {
            info!("Command stoppped, finished or cancelled.");
            break;
        }
        if new_level >= max_level {
            loop_data.level = max_level;
            break;
        } else {
            loop_data.level = new_level;
        }
        loop_data.is_fresh = true;
    }
}

pub struct LevelControlCluster {
    base: Cluster,
    event_loop: Arc<Mutex<UpdateDataStore>>,

    callbacks: Vec<Callback>,
    d_callbacks: Vec<DataCallback<u8, u16>>,
}

// Callbacks
impl LevelControlCluster {
    pub fn add_callback(&mut self, name: Commands, cb: Box<dyn FnMut()>) {
        self.callbacks.push(Callback {
            name: name,
            callback: cb,
        });
    }
    pub fn add_data_callback<T, U>(&mut self, name: Commands, cb: Box<dyn FnMut(u8, u16, u8)>) {
        self.d_callbacks.push(DataCallback {
            name: name,
            callback: cb,
        });
    }
    pub fn run_data_callback(&mut self, cmd: Commands, level: u8, time: u16, mode: u8) {
        for cb in self.d_callbacks.iter_mut() {
            if cb.name == cmd {
                cb.call(level, time, mode);
                break;
            }
        }
    }
    pub fn run_callback(&mut self, cmd: Commands) {
        for cb in self.callbacks.iter_mut() {
            if cb.name == cmd {
                cb.call();
                break;
            }
        }
    }

    pub fn get_event_loop_ref(&self) -> &Arc<Mutex<UpdateDataStore>> {
        &self.event_loop
    }
}

impl LevelControlCluster {
    fn get_current_level_u8(&mut self) -> Result<u8, IMStatusCode> {
        let level = self
            .base
            .read_attribute_raw(Attributes::CurrentLevel as u16)?;

        if let AttrValue::Uint8(t) = level {
            Ok(*t)
        } else {
            Err(IMStatusCode::NotFound)
        }
    }

    fn get_max_level_u8(&mut self) -> u8 {
        let max_level = self.base.read_attribute_raw(Attributes::MaxLevel as u16);

        match max_level {
            Ok(t) => match *t {
                AttrValue::Uint8(t) => t,
                _ => MAX_LVL_DEFAULT,
            },
            Err(_) => MAX_LVL_DEFAULT,
        }
    }

    fn get_min_level_u8(&mut self) -> u8 {
        let min_level = self.base.read_attribute_raw(Attributes::MinLevel as u16);

        match min_level {
            Ok(t) => match *t {
                AttrValue::Uint8(t) => t,
                _ => MIN_LVL_DEFAULT,
            },
            Err(_) => MIN_LVL_DEFAULT,
        }
    }

    // Flag data as not a fresh update anymore everytime we do commands
    fn update_from_loop(&mut self) {
        let mut loop_data = self.event_loop.lock().unwrap();

        let new_level: u8 = loop_data.level;
        let time_left: u16 = loop_data.remaining_time;

        match self
            .base
            .write_attribute_raw(Attributes::CurrentLevel as u16, AttrValue::Uint8(new_level))
        {
            Ok(_) => (),
            Err(e) => {
                log::error!("Failed to update CurrentLevel: {e}");
            }
        }
        match self.base.write_attribute_raw(
            Attributes::RemainingTime as u16,
            AttrValue::Uint16(time_left),
        ) {
            Ok(_) => (),
            Err(e) => {
                log::error!("Failed to update RemainingTime: {e}");
            }
        }
        loop_data.is_fresh = false;
    }

    fn prepare_command(
        &mut self,
        time: Option<u16>,
        cmd: Option<Commands>,
        cmd_req: &mut CommandReq,
    ) -> Result<(), IMStatusCode> {
        match self.event_loop.lock() {
            Ok(mut t) => {
                t.prepare_command(time, cmd);
                drop(t);
            }
            Err(e) => {
                log::error!("Failed to aqcuire lock: {e}");
                cmd_req.trans.complete();
                return Err(IMStatusCode::Failure);
            }
        };

        Ok(())
    }
}

impl LevelControlCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        let mut cluster = Box::new(LevelControlCluster {
            base: Cluster::new(ID)?,
            event_loop: Arc::new(Mutex::new(UpdateDataStore {
                level: 0,
                remaining_time: 0,
                current_command: None,
                is_running: false,
                is_fresh: false,
            })),
            callbacks: vec![],
            d_callbacks: vec![],
        });

        let attrs = [
            Attribute::new(
                Attributes::CurrentLevel as u16,
                AttrValue::Uint8(0),
                Access::RV,
                Quality::PERSISTENT,
            )?,
            Attribute::new(
                Attributes::RemainingTime as u16,
                AttrValue::Uint16(0),
                Access::RV,
                Quality::PERSISTENT,
            )?,
            Attribute::new(
                Attributes::MinLevel as u16,
                AttrValue::Uint8(0),
                Access::RV,
                Quality::PERSISTENT,
            )?,
            Attribute::new(
                Attributes::MaxLevel as u16,
                AttrValue::Uint8(254),
                Access::RV,
                Quality::PERSISTENT,
            )?,
            Attribute::new(
                Attributes::OnLevel as u16,
                AttrValue::Uint8(0),
                Access::RV,
                Quality::PERSISTENT,
            )?,
            Attribute::new(
                Attributes::StartUpCurrentLevel as u16,
                AttrValue::Uint8(0x00),
                Access::RV,
                Quality::PERSISTENT,
            )?,
        ];
        cluster.base.add_attributes(&attrs)?;
        Ok(cluster)
    }

    fn handle_move_to_lvl(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd_data = cmd_req.data;
        let mut tlv_iterator = cmd_data.enter().ok_or(Error::Invalid)?;

        let mut new_level = tlv_iterator
            .next()
            .ok_or(IMStatusCode::InvalidDataType)?
            .u8()?;
        let trans_time = tlv_iterator
            .next()
            .ok_or(IMStatusCode::InvalidDataType)?
            .u16()?;

        // TODO: Process these before updating level
        let _options_mask = tlv_iterator.next().ok_or(IMStatusCode::InvalidDataType)?;
        let _options_override = tlv_iterator.next().ok_or(IMStatusCode::InvalidDataType)?;

        let cur_level = self.get_current_level_u8()?;
        let min_level = self.get_min_level_u8();
        let max_level = self.get_max_level_u8();

        if cur_level == new_level {
            cmd_req.trans.complete();
            return Err(IMStatusCode::Sucess);
        } else if cur_level > new_level && min_level >= new_level {
            new_level = min_level;
        } else if cur_level < new_level && new_level >= max_level {
            new_level = max_level;
        }

        self.prepare_command(Some(trans_time), Some(Commands::MoveToLevel), cmd_req)?;
        let event_loop = self.event_loop.clone();
        thread::spawn(move || {
            move_to_lvl(&event_loop, trans_time, new_level, cur_level);
        });

        self.run_data_callback(Commands::MoveToLevel, new_level, trans_time, 0);
        cmd_req.trans.complete();
        Err(IMStatusCode::Sucess)
    }

    fn handle_move(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd_data = cmd_req.data;
        let mut tlv_iterator = cmd_data.enter().ok_or(Error::Invalid)?;

        let move_mode = tlv_iterator.next().ok_or(Error::Invalid)?.u8()?;
        let rate = tlv_iterator.next().ok_or(Error::Invalid)?.u8()?;

        let max_level = self.get_max_level_u8();
        let min_level = self.get_min_level_u8();
        let cur_level = self.get_current_level_u8()?;

        // TODO: Process these first
        let _options_mask = tlv_iterator.next().ok_or(Error::Invalid)?;
        let _options_override = tlv_iterator.next().ok_or(Error::Invalid)?;

        self.prepare_command(None, Some(Commands::Move), cmd_req)?;
        let event_loop = self.event_loop.clone();
        match MoveMode::from_u8(move_mode) {
            MoveMode::Up => {
                thread::spawn(move || {
                    move_lvl_up(&event_loop, rate, max_level, cur_level);
                });
            }
            MoveMode::Down => {
                thread::spawn(move || {
                    move_lvl_down(&event_loop, rate, min_level, cur_level);
                });
            }
        };

        self.run_data_callback(Commands::Move, rate, 0, move_mode);
        cmd_req.trans.complete();
        Err(IMStatusCode::Sucess)
    }

    fn handle_stop(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd_data = cmd_req.data;
        let mut tlv_iterator = cmd_data.enter().ok_or(Error::Invalid)?;

        let _options_mask = tlv_iterator.next().ok_or(Error::Invalid)?;
        let _options_override = tlv_iterator.next().ok_or(Error::Invalid)?;

        match self.event_loop.lock() {
            Ok(mut t) => {
                t.stop_current_command();
                drop(t);
            }
            Err(e) => {
                log::error!("Failed to aqcuire lock: {e}");
                cmd_req.trans.complete();
                return Err(IMStatusCode::Failure);
            }
        };

        self.base
            .write_attribute_raw(Attributes::RemainingTime as u16, AttrValue::Uint16(0))?;
        self.run_callback(Commands::Stop);
        cmd_req.trans.complete();
        Err(IMStatusCode::Sucess)
    }

    fn handle_step(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd_data = cmd_req.data;
        let mut tlv_iterator = cmd_data.enter().ok_or(Error::Invalid)?;

        let step_mode = tlv_iterator.next().ok_or(Error::Invalid)?.u8()?;
        let step_size = tlv_iterator.next().ok_or(Error::Invalid)?.u8()?;
        let _options_mask = tlv_iterator.next().ok_or(Error::Invalid)?;
        let _options_override = tlv_iterator.next().ok_or(Error::Invalid)?;

        let transition_time = match tlv_iterator.next().ok_or(Error::Invalid)?.u16() {
            Ok(t) => t,
            Err(_) => 0,
        };

        let cur_level = self.get_current_level_u8()?;
        let min_level = self.get_min_level_u8();
        let max_level = self.get_max_level_u8();

        self.prepare_command(Some(transition_time), Some(Commands::Step), cmd_req)?;
        let event_loop = self.event_loop.clone();
        match StepMode::from_u8(step_mode) {
            StepMode::Up => {
                let new_lvl = match cur_level.checked_add(step_size) {
                    Some(t) => t,
                    None => max_level,
                };
                thread::spawn(move || {
                    // Wait transition time before executing the step?
                    let wait_period = 100 * transition_time;
                    thread::sleep(time::Duration::from_millis(wait_period as u64));
                    move_to_lvl(&event_loop, transition_time, new_lvl, cur_level);
                });
            }
            StepMode::Down => {
                let new_lvl = match cur_level.checked_sub(step_size) {
                    Some(t) => t,
                    None => min_level,
                };
                thread::spawn(move || {
                    // Wait transition time before executing the step?
                    let wait_period = 100 * transition_time;
                    thread::sleep(time::Duration::from_millis(wait_period as u64));
                    move_to_lvl(&event_loop, transition_time, new_lvl, cur_level);
                });
            }
        };

        self.run_data_callback(Commands::Step, step_size, transition_time, step_mode);
        cmd_req.trans.complete();
        Err(IMStatusCode::Sucess)
    }

    fn handle_move_to_lvl_with_onoff(
        &mut self,
        cmd_req: &mut CommandReq,
    ) -> Result<(), IMStatusCode> {
        let _cmd_data = cmd_req.data;
        cmd_req.trans.complete();
        Err(IMStatusCode::UnsupportedCommand)
    }

    fn handle_move_with_onoff(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let _cmd_data = cmd_req.data;
        cmd_req.trans.complete();
        Err(IMStatusCode::UnsupportedCommand)
    }

    fn handle_step_with_onoff(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let _cmd_data = cmd_req.data;
        cmd_req.trans.complete();
        Err(IMStatusCode::UnsupportedCommand)
    }

    fn handle_stop_with_onoff(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let _cmd_data = cmd_req.data;
        cmd_req.trans.complete();
        Err(IMStatusCode::UnsupportedCommand)
    }

    fn move_to_closest_freq(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let _cmd_data = cmd_req.data;
        cmd_req.trans.complete();
        Err(IMStatusCode::UnsupportedCommand)
    }
}

impl ClusterType for LevelControlCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }

    fn read_attribute(
        &self,
        access_req: &mut crate::acl::AccessReq,
        encoder: &mut dyn Encoder,
        attr: &AttrDetails,
    ) {
        let mut error = IMStatusCode::Sucess;
        let base = self.base();
        let loop_data = self.event_loop.lock().unwrap();
        let a = if let Ok(a) = base.get_attribute(attr.attr_id) {
            a
        } else {
            encoder.encode_status(IMStatusCode::UnsupportedAttribute, 0);
            return;
        };

        if !a.access.contains(Access::READ) {
            error = IMStatusCode::UnsupportedRead;
        }
        access_req.set_target_perms(a.access);
        if !access_req.allow() {
            error = IMStatusCode::UnsupportedAccess;
        }
        if error != IMStatusCode::Sucess {
            encoder.encode_status(error, 0);
        } else if Attribute::is_system_attr(attr.attr_id) {
            self.base().read_system_attribute(encoder, a)
        } else if a.value != AttrValue::Custom {
            if loop_data.is_fresh && attr.attr_id == Attributes::CurrentLevel as u16 {
                let val = AttrValue::Uint8(loop_data.level);
                encoder.encode(EncodeValue::Value(&val))
            } else {
                encoder.encode(EncodeValue::Value(&a.value))
            }
        } else {
            self.read_custom_attribute(encoder, attr)
        }
    }

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req
            .cmd
            .path
            .leaf
            .map(num::FromPrimitive::from_u32)
            .ok_or(IMStatusCode::UnsupportedCommand)?
            .ok_or(IMStatusCode::UnsupportedCommand)?;

        // Update from the event loop before we do anyhting
        self.update_from_loop();

        match cmd {
            Commands::MoveToLevel => self.handle_move_to_lvl(cmd_req),
            Commands::Move => self.handle_move(cmd_req),
            Commands::Step => self.handle_step(cmd_req),
            Commands::Stop => self.handle_stop(cmd_req),
            Commands::MoveToLevelWithOnOff => self.handle_move_to_lvl_with_onoff(cmd_req),
            Commands::MoveWithOnOff => self.handle_move_with_onoff(cmd_req),
            Commands::StepWithOnOff => self.handle_step_with_onoff(cmd_req),
            Commands::StopWithOnOff => self.handle_stop_with_onoff(cmd_req),
            Commands::MoveToClosestFrequency => self.move_to_closest_freq(cmd_req),
        }
    }
}
