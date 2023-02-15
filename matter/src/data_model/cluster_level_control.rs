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
    tlv::TLVElement,
};
use log::{info, debug};
use num_derive::FromPrimitive;
use std::sync::{Arc, Mutex};
use std::{thread, time};

// ID of base cluster for level control, other specifics are defined for lighting - might need an update in next release
pub const ID: u32 = 0x0008;

// IDs of attributes
pub enum Attributes {
    CurrentLevel = 0x0000,
    RemainingTime = 0x0001,
    MinLevel = 0x0002,
    MaxLevel = 0x0003,
    OnLevel = 0x0011,
    Options = 0x000F,
    StartUpCurrentLevel = 0x4000,
}

const MAX_LVL: u8 = 254;
const MIN_LVL_DEFAULT: u8 = 0;
const MAX_LVL_DEFAULT: u8 = 254;
const STARTUP_CURRENT_LVL_DEFAULT: u8 = 0;

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

#[derive(FromPrimitive)]
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

struct UpdateData {
    level: u8,
    remaining_time: u16,
    current_command: Option<Commands>,
    is_running: bool,
}

impl UpdateData {
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
    fn update_from_command(&mut self, new_level: u8, remaining_time: u16, cmd: Option<Commands>) {
        self.level = new_level;
        self.remaining_time = remaining_time;
        self.current_command = match cmd {
            Some(t) => {
                self.is_running = true;
                Some(t)
            }
            None => {
                self.is_running = false;
                None
            }
        };
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
        info!("Running [stop current command]");
        self.is_running = false;
        self.current_command = Some(Commands::Stop);
        self.remaining_time = 0;
    }
}

// fn dispatch_commands(&mut self, new_level: u8, remaining_time: u16, cmd: Option<Commands>)

// };
// let mut time_left = time;

fn move_lvl_down(event_loop: &Arc<Mutex<UpdateData>>, rate: u8, min_level: u8, cur_level: u8) {
    let update_interval = time::Duration::from_millis(100);

    // Each 1/10th of a second wake up and update current volume and remaining time
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

        info!("Moving device level down by: {rate} to {new_level}");
        // End of command if we hit min level
        if new_level <= min_level {
            loop_data.level = min_level;
            info!("Device reached min level: {min_level}");
            break;
        } else {
            loop_data.level = new_level;
        }
    }
}

fn move_lvl_up(event_loop: &Arc<Mutex<UpdateData>>, rate: u8, max_level: u8, cur_level: u8) {
    let update_interval = time::Duration::from_millis(100);
    let mut new_level = cur_level;
    // Each 1/10th of a second wake up and update current volume and remaining time
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
        // loop_data.tick_time();
        info!("Moving device level up by: {rate} to {new_level}");

        // End of command if we hit max level
        if new_level >= max_level {
            loop_data.level = max_level;
            info!("Device reached min level: {max_level}");
            break;
        } else {
            loop_data.level = new_level;
        }
    }
}

pub struct LevelControlCluster {
    base: Cluster,
    event_loop: Arc<Mutex<UpdateData>>,
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
            Err(e) => MAX_LVL_DEFAULT,
        }
    }

    fn get_min_level_u8(&mut self) -> u8 {
        let min_level = self.base.read_attribute_raw(Attributes::MinLevel as u16);

        match min_level {
            Ok(t) => match *t {
                AttrValue::Uint8(t) => t,
                _ => 0,
            },
            Err(_) => 0,
        }
    }

    fn set_current_level(&mut self, new_level: u8) -> Result<(), IMStatusCode> {
        self.base
            .write_attribute_raw(Attributes::CurrentLevel as u16, AttrValue::Uint8(new_level))
            .map_err(|_| IMStatusCode::Failure)
    }

    // fn set_remaining_time(&mut self, time_left: u16) -> Result<(), IMStatusCode> {
    //     self.base
    //         .write_attribute_raw(
    //             Attributes::RemainingTime as u16,
    //             AttrValue::Uint16(time_left),
    //         )
    //         .map_err(|_| IMStatusCode::Failure)
    // }

    fn step_level(&mut self, step_mode: StepMode, step_size: u8) -> Result<(), IMStatusCode> {
        let current_level = self.get_current_level_u8()?;
        let max_level = self.get_max_level_u8();
        let min_level = self.get_min_level_u8();

        match step_mode {
            StepMode::Up => {
                let new_level = match current_level.checked_add(step_size) {
                    Some(t) => t,
                    None => current_level,
                };

                debug!("[STEP_UP] CurrentLevel: {current_level} + {step_size} = {new_level}");

                if new_level >= max_level {
                    self.set_current_level(max_level)?;
                } else {
                    self.set_current_level(new_level)?;
                }
            }
            StepMode::Down => {
                let new_level = match current_level.checked_sub(step_size) {
                    Some(t) => t,
                    None => current_level,
                };

                debug!("[STEP_DOWN] CurrentLevel: {current_level} - {step_size} = {new_level}");
                if new_level <= min_level {
                    self.set_current_level(min_level)?;
                    debug!("Set level to: {min_level}")
                } else {
                    debug!("[STEP_DOWN] new_level: {new_level} > min_level: {min_level}");
                    self.set_current_level(new_level)?;
                }
            }
        }

        // TODO: Remove unwraps
        // Update the loop
        let current_level = self.get_current_level_u8()?;
        let mut loop_data = self.event_loop.lock().unwrap();
        loop_data.update_from_command(current_level, 0, None);

        debug!("Step command update level to: {current_level}");
        Err(IMStatusCode::Sucess)
    }
}

impl LevelControlCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        let mut cluster = Box::new(LevelControlCluster {
            base: Cluster::new(ID)?,
            event_loop: Arc::new(Mutex::new(UpdateData {
                level: 0,
                remaining_time: 0,
                current_command: None,
                is_running: false,
            })),
        });

        let attrs = [
            Attribute::new(
                Attributes::CurrentLevel as u16,
                AttrValue::Uint8(0),
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
                Attributes::StartUpCurrentLevel as u16,
                AttrValue::Uint8(0x00),
                Access::RV,
                Quality::PERSISTENT,
            )?,
            // Options - probably want a custom type here for mapping cluster options to TLV bitmask
        ];
        cluster.base.add_attributes(&attrs)?;
        Ok(cluster)
    }

    fn update_from_loop(&mut self) {
        let loop_data = self.event_loop.lock().unwrap();

        let new_level: u8 = loop_data.level;
        let time_left: u16 = loop_data.remaining_time;

        self.base
            .write_attribute_raw(Attributes::CurrentLevel as u16, AttrValue::Uint8(new_level));
        self.base.write_attribute_raw(
            Attributes::RemainingTime as u16,
            AttrValue::Uint16(time_left),
        );

        debug!("Reading loop data: level: {new_level} time left: {time_left} before processing new command!");
        // let q = self.
        // info!("Device updated to new level: {f}");
    }

    fn handle_move_to_lvl(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        let mut tlv_iterator = cmd_data.enter().ok_or(Error::Invalid)?;
        let mut new_level = tlv_iterator
            .next()
            .ok_or(IMStatusCode::InvalidDataType)?
            .u8()?;
        let trans_time = tlv_iterator
            .next()
            .ok_or(IMStatusCode::InvalidDataType)?
            .u16()?;

        let cur_level = self.get_current_level_u8()?;
        let min_level = self.get_max_level_u8();
        let max_level = self.get_max_level_u8();

        // TODO: Process these before updating level
        // let _options_mask = tlv_iterator.next().ok_or(IMStatusCode::InvalidDataType)?;
        // let _options_override = tlv_iterator.next().ok_or(IMStatusCode::InvalidDataType)?;

        // Update level in data model
        if cur_level > new_level && new_level <= min_level {
            new_level = min_level;
        } else if cur_level < new_level && new_level >= max_level {
            new_level = max_level;
        }
        self.set_current_level(new_level)?;

        let mut data_loop = self.event_loop.lock().unwrap();
        data_loop.update_from_command(new_level, trans_time, Some(Commands::MoveToLevel));

        // Run moveToLevel in background

        // TODO: implement this in background as well
        Err(IMStatusCode::Sucess)
    }

    fn handle_move(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        let mut tlv_iterator = cmd_data.enter().ok_or(Error::Invalid)?;
        let move_mode = tlv_iterator.next().ok_or(Error::Invalid)?.u8()?;
        let rate = tlv_iterator.next().ok_or(Error::Invalid)?.u8()?;

        let max_level = self.get_max_level_u8();
        let min_level = self.get_min_level_u8();
        let cur_level = self.get_current_level_u8()?;

        // TODO: Process these first
        // let _options_mask = tlv_iterator.next().ok_or(Error::Invalid)?;
        // let _options_override = tlv_iterator.next().ok_or(Error::Invalid)?;

        // Setup command for running
        // Prepare command
        let event_loop = self.event_loop.clone();
        let mut loop_data = event_loop.lock().unwrap();
        loop_data.prepare_command(None, Some(Commands::Move));
        // Drop mutex explicitly
        drop(loop_data);

        // Actually run command
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

        Err(IMStatusCode::Sucess)
    }

    fn handle_stop(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        let mut tlv_iterator = cmd_data.enter().ok_or(Error::Invalid)?;
        let _options_mask = tlv_iterator.next().ok_or(Error::Invalid)?;
        let _options_override = tlv_iterator.next().ok_or(Error::Invalid)?;

        // self.base
        //     .write_attribute_raw(Attributes::RemainingTime as u16, AttrValue::Uint16(0))
        // .map_err(|_| IMStatusCode::Failure)?;

        debug!("Stopping command.");
        // Stop the loop from running
        let mut data_loop = self.event_loop.lock().map_err(|_| IMStatusCode::Busy)?;
        data_loop.stop_current_command();

        Err(IMStatusCode::Sucess)
    }

    // TODO: Actually handle transition time
    fn handle_step(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        let mut tlv_iterator = cmd_data.enter().ok_or(Error::Invalid)?;

        let step_mode = tlv_iterator.next().ok_or(Error::Invalid)?.u8()?;
        let step_size = tlv_iterator.next().ok_or(Error::Invalid)?.u8()?;
        let _options_mask = tlv_iterator.next().ok_or(Error::Invalid)?;
        let _options_override = tlv_iterator.next().ok_or(Error::Invalid)?;

        let transition_time = match tlv_iterator.next().ok_or(Error::Invalid)?.u16() {
            Ok(t) => t,
            Err(_) => 0,
        };

        self.step_level(StepMode::from_u8(step_mode), step_size)?;

        let new_level = self.get_current_level_u8()?;

        // TODO: Make this update happen in the back ground
        let mut data_loop = self.event_loop.lock().unwrap();
        data_loop.update_from_command(new_level, transition_time, Some(Commands::Step));
        drop(data_loop);

        // Queue in actual command?

        Err(IMStatusCode::Sucess)
    }

    fn handle_move_to_lvl_with_onoff(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        // todo!();
        Err(IMStatusCode::Sucess)
    }

    fn handle_move_with_onoff(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        // todo!();
        Err(IMStatusCode::Sucess)
    }

    fn handle_step_with_onoff(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        // todo!();
        Err(IMStatusCode::Sucess)
    }

    fn handle_stop_with_onoff(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        // todo!();
        Err(IMStatusCode::Sucess)
    }

    fn move_to_closest_freq(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        // todo!();
        Err(IMStatusCode::Sucess)
    }
}

impl ClusterType for LevelControlCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
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
            Commands::MoveToLevel => self.handle_move_to_lvl(&cmd_req.data),
            Commands::Move => self.handle_move(&cmd_req.data),
            Commands::Step => self.handle_step(&cmd_req.data),
            Commands::Stop => self.handle_stop(&cmd_req.data),
            Commands::MoveToLevelWithOnOff => self.handle_move_to_lvl_with_onoff(&cmd_req.data),
            Commands::MoveWithOnOff => self.handle_move_with_onoff(&cmd_req.data),
            Commands::StepWithOnOff => self.handle_step_with_onoff(&cmd_req.data),
            Commands::StopWithOnOff => self.handle_stop_with_onoff(&cmd_req.data),
            Commands::MoveToClosestFrequency => self.move_to_closest_freq(&cmd_req.data),
        }
    }
}
