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
use log::{info, Level};
use num_derive::FromPrimitive;
use std::{thread, time};
use std::sync::{Arc, Mutex};

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
    pub fn from_tlv(src: TLVElement) -> MoveMode {
        let res = src.u8()?;
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
    is_running: bool
}

// let mut time_left = time;
   
fn move_lvl_down(event_loop: Arc<Mutex<UpdateData>>, rate: u8, min_level: u8, cur_level: u8) {
    let update_interval = time::Duration::from_millis(100);
    let loop_data = event_loop.lock().unwrap();

    // Each 1/10th of a second wake up and update current volume and remaining time
    loop {
        thread::sleep(update_interval);
        cur_level = match cur_level.checked_sub(rate) {
            Some(t) => t,
            None => min_level,
        };

        info!("Moving device level down by: {rate} to {cur_level}");
        // End of command if we hit min level
        if cur_level <= min_level {
            loop_data.level = min_level;
            info!("Device reached min level: {min_level}");
            break;
        } else {
            loop_data.level = cur_level;
        }
    }
}

fn move_lvl_up(event_loop: Arc<Mutex<UpdateData>>, rate: u8, max_level: u8, cur_level: u8) {
    let update_interval = time::Duration::from_millis(100);

    let loop_data = event_loop.lock().unwrap();
    // Each 1/10th of a second wake up and update current volume and remaining time
    loop {
        thread::sleep(update_interval);
        cur_level = match cur_level.checked_sub(rate) {
            Some(t) => t,
            None => max_level,
        };

        info!("Moving device level up by: {rate} to {cur_level}");

        // End of command if we hit max level
        if cur_level >= max_level {
            loop_data.level = max_level;
            info!("Device reached min level: {max_level}");
            break;
        } else {
            loop_data.level = cur_level;
        }
    }
}


pub struct LevelControlCluster {
    base: Cluster,
    event_loop: <Arc<Mutex<UpdateData>>>
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
        let max_level = self.base.read_attribute_raw(Attributes::MaxLevel as u16);

        match max_level {
            Ok(t) => match *t {
                AttrValue::Uint8(t) => t,
                _ => MIN_LVL_DEFAULT,
            },
            Err(e) => MIN_LVL_DEFAULT,
        }
    }

    fn set_current_level(&mut self, new_level: u8) -> Result<(), IMStatusCode> {
        self.base
            .write_attribute_raw(Attributes::CurrentLevel as u16, AttrValue::Uint8(new_level))
            .map_err(|_| IMStatusCode::Failure)
    }

    fn set_remaining_time(&mut self, time_left: u16) -> Result<(), IMStatusCode> {
        self.base
            .write_attribute_raw(
                Attributes::RemainingTime as u16,
                AttrValue::Uint16(time_left),
            )
            .map_err(|_| IMStatusCode::Failure)
    }

    fn step_level(&mut self, step_mode: StepMode, step_size: u8) -> Result<(), IMStatusCode> {
        let current_level = self.get_current_level_u8()?;
        match step_mode {
            StepMode::Up => {
                let new_level = current_level.checked_add(step_size);
                let new_level = match new_level {
                    Some(t) => t,
                    None => u8::MIN,
                };

                let max_level = self.get_max_level_u8();
                if new_level > max_level {
                    self.set_current_level(max_level)?;
                } else {
                    self.set_current_level(new_level)?;
                }
                let update_level = self.get_current_level_u8()?;
            }
            StepMode::Down => {
                let new_level = current_level.checked_sub(step_size);
                let new_level = match new_level {
                    Some(t) => t,
                    None => u8::MIN,
                };

                let min_level = self.get_min_level_u8();
                if new_level < min_level {
                    self.set_current_level(min_level)?;
                } else {
                    self.set_current_level(new_level)?;
                }
            }
        }

        Err(IMStatusCode::Sucess)
    }
}

impl LevelControlCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        let mut cluster = Box::new(LevelControlCluster {
            base: Cluster::new(ID)?,
            event_loop: Arc::new(Mutex::new(UpdateData{}))
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

        self.set_current_level(loop_data.level);
        self.set_remaining_time(loop_data.remaining_time);
    }

    fn handle_move_to_lvl(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        let mut tlv_iterator = cmd_data.enter().ok_or(Error::Invalid)?;
        let new_level = tlv_iterator.next().ok_or(IMStatusCode::InvalidDataType)?.u8()?;
        let _trans_time =  tlv_iterator.next().ok_or(IMStatusCode::InvalidDataType)?.u16()?;

        let cur_level = self.get_current_level_u8()?;
        let min_level = self.get_max_level_u8();
        let max_level = self.get_max_level_u8();

        // TODO: Process these before updating level
        // let _options_mask = tlv_iterator.next().ok_or(IMStatusCode::InvalidDataType)?;
        // let _options_override = tlv_iterator.next().ok_or(IMStatusCode::InvalidDataType)?;

        // TODO: Check if we are not above min/max level
        if cur_level > new_level && new_level > min_level{
            self.set_current_level(new_level);
        } else if cur_level > new_level {
            self.set_current_level(min_level);
        } else if cur_level < new_level && new_level < max_level{
            self.set_current_level(new_level);
        } else if cur_level < new_level{
            self.set_current_level(max_level);
        }

        // Do it in the background
        Err(IMStatusCode::Sucess)
    }

    fn handle_move(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        let mut tlv_iterator = cmd_data.enter().ok_or(Error::Invalid)?;
        let move_mode = tlv_iterator.next().ok_or(Error::Invalid)?.u8()?;
        let rate = tlv_iterator.next().ok_or(Error::Invalid)?.u8()?;

        let max_level = self.get_max_level_u8();
        let min_level = self.get_min_level_u8();
        let cur_level = self.get_current_level_u8();

        // TODO: Process these first
        // let _options_mask = tlv_iterator.next().ok_or(Error::Invalid)?;
        // let _options_override = tlv_iterator.next().ok_or(Error::Invalid)?;
        
        match MoveMode::from_u8(move_mode) {
            MoveMode::Up => {
                // let new_level: u8 = match cur_level.checked_add(rate) {
                //     Some(t) => t,
                //     None => max_level
                // };        
                // self.set_current_level(new_level);
                thread::spawn(move || {
                    move_lvl_up(self.event_loop, rate, max_level, cur_level);
                });
            },
            MoveMode::Down => {
                // let new_level: u8 = match cur_level.checked_sub(rate) {
                //     Some(t) => t,
                //     None => min_level
                // };
                // self.set_current_level(new_level);

                thread::spawn(move || {
                    move_lvl_down(self.event_loop, rate, min_level, cur_level);
                });
            }
        };


        Err(IMStatusCode::Sucess)
    }

    // TODO: Stop any command in progress - implement when we implement progress for commands
    fn handle_stop(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        let mut tlv_iterator = cmd_data.enter().ok_or(Error::Invalid)?;
        let _options_mask = tlv_iterator.next().ok_or(Error::Invalid)?;
        let _options_override = tlv_iterator.next().ok_or(Error::Invalid)?;
        self.base
            .write_attribute_raw(Attributes::RemainingTime as u16, AttrValue::Uint16(0))
            .map_err(|_| IMStatusCode::Failure)?;

        Err(IMStatusCode::Sucess)
    }

    // TODO: Actually handle transition time
    fn handle_step(&mut self, cmd_data: &TLVElement) -> Result<(), IMStatusCode> {
        let mut tlv_iterator = cmd_data.enter().ok_or(Error::Invalid)?;

        let step_mode = tlv_iterator.next().ok_or(Error::Invalid)?.u8()?;
        let step_size = tlv_iterator.next().ok_or(Error::Invalid)?.u8()?;
        let _options_mask = tlv_iterator.next().ok_or(Error::Invalid)?;
        let _options_override = tlv_iterator.next().ok_or(Error::Invalid)?;
        let _transition_time = tlv_iterator.next().ok_or(Error::Invalid)?;

        self.step_level(StepMode::from_u8(step_mode), step_size)?;
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
