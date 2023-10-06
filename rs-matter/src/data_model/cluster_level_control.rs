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

use core::{cell::Cell, convert::TryInto};

use super::objects::*;
use crate::{
    attribute_enum, cmd_enter, command_enum,
    error::Error,
    tlv::{FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
    transport::exchange::Exchange,
    utils::rand::Rand,
};

use log::{error, info, warn};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use strum::{EnumDiscriminants, FromRepr};

pub const ID: u32 = 0x008;

#[repr(u8)]
pub enum Features {
    /// Dependency with the On/Off cluster
    OO = 1 << 0, // Bit 0
    /// Behavior that supports lighting applications
    LT = 1 << 1, // Bit 1
    /// Frequency
    FQ = 1 << 2, // Bit 2
}

#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive)]
#[repr(u8)]
pub enum Options {
    /// Dependency on On/Off cluster
    ExecuteIfOff = 1 << 0, // Bit 0
    /// Dependency on Color Control cluster
    CoupleColorTempToLevel = 1 << 1, // Bit 1
}

impl From<u8> for Options {
    fn from(val: u8) -> Self {
        Options::from_u8(val).unwrap_or(Options::ExecuteIfOff)
    }
}

impl FromTLV<'_> for Options {
    fn from_tlv(tlv: &TLVElement) -> Result<Self, Error> {
        let val = u8::from_tlv(tlv)?;
        Ok(Options::from(val))
    }
}

impl From<Options> for u8 {
    fn from(val: Options) -> Self {
        val as u8
    }
}

impl ToTLV for Options {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        let val: u8 = (*self).into();
        tw.u8(tag_type, val)
    }
}

#[derive(FromRepr, EnumDiscriminants, Debug)]
#[repr(u16)]
pub enum Attributes {
    /// Constraint : MinLevel to MaxLevel
    /// Quality : SNX
    /// Default : null
    /// Access : RV
    /// Conformance : M
    CurrentLevel(AttrType<u8>) = 0x0000,
    /// Constraint : all
    /// Quality :
    /// Default : 0
    /// Access : RV
    /// Conformance : LT
    RemainingTime(AttrType<u16>) = 0x0001,
    /// Constraint : !LT : 0 to MaxLevel, LT : 1 to MaxLevel
    /// Quality :
    /// Default : !LT : 0, LT : 1
    /// Access : RV
    /// Conformance : O
    MinLevel(AttrType<u8>) = 0x0002,
    /// Constraint : MinLevel to 254
    /// Quality :
    /// Default : 254
    /// Access : RV
    /// Conformance O
    MaxLevel(AttrType<u8>) = 0x0003,
    /// Constraint : MinFrequency to MaxFrequency
    /// Quality : PS
    /// Default : 0
    /// Access : RV
    /// Conformance : FQ
    CurrentFrequency(AttrType<u16>) = 0x0004,
    /// Constraint : 0 to MaxFrequency
    /// Quality :
    /// Default : 0
    /// Access : RV
    /// Conformance : FQ
    MinFrequency(AttrType<u16>) = 0x0005,
    /// Constraint : MinFrequency to max
    /// Quality :
    /// Default : 0
    /// Access : RV
    /// Conformance : FQ
    MaxFrequency(AttrType<u16>) = 0x0006,
    /// Constraint : all
    /// Quality :
    /// Default : 0
    /// Access : RW VO
    /// Conformance : O
    OnOffTransitionTime(AttrType<u16>) = 0x0010,
    /// Constraint : MinLevel to MaxLevel
    /// Quality : X
    /// Default : null
    /// Access : RW VO
    /// Conformance : M
    OnLevel(AttrType<u8>) = 0x0011,
    /// Constraint : all
    /// Quality : X
    /// Default : null
    /// Access : RW VO
    /// Conformance : O
    OnTransitionTime(AttrType<u16>) = 0x0012,
    /// Constraint : all
    /// Quality : X
    /// Default : null
    /// Access : RW VO
    /// Conformance : O
    OffTransitionTime(AttrType<u16>) = 0x0013,
    /// Constraint : all
    /// Quality : X
    /// Default : MS
    /// Access : RW VO
    /// Conformance : O
    DefaultMoveRate(AttrType<u8>) = 0x0014,
    /// Constraint : desc
    /// Quality :
    /// Default : 0
    /// Access : RW VO
    /// Conformance : M
    Options(AttrType<Options>) = 0x000F,
    /// Constraint : desc
    /// Quality : XN
    /// Default : MS
    /// Access : RW VM
    /// Conformance : LT
    StartUpCurrentLevel(AttrType<u8>) = 0x4000,
}

attribute_enum!(Attributes);

#[derive(FromRepr, EnumDiscriminants, Debug)]
#[repr(u32)]
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

command_enum!(Commands);

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    feature_map: Features::LT as u32 | Features::OO as u32,
    attributes: &[
        FEATURE_MAP,
        ATTRIBUTE_LIST,
        Attribute::new(
            AttributesDiscriminants::CurrentLevel as u16,
            Access::RV,
            Quality::SNX,
        ),
        Attribute::new(
            AttributesDiscriminants::RemainingTime as u16,
            Access::RV,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::OnLevel as u16,
            Access::RWVO,
            Quality::X,
        ),
        Attribute::new(
            AttributesDiscriminants::Options as u16,
            Access::RWVO,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::StartUpCurrentLevel as u16,
            Access::RWVM,
            Quality::XN,
        ),
    ],
    commands: &[
        CommandsDiscriminants::MoveToLevel as _,
        CommandsDiscriminants::Move as _,
        CommandsDiscriminants::Step as _,
        CommandsDiscriminants::Stop as _,
        CommandsDiscriminants::MoveToLevelWithOnOff as _,
        CommandsDiscriminants::MoveWithOnOff as _,
        CommandsDiscriminants::StepWithOnOff as _,
        CommandsDiscriminants::StopWithOnOff as _,
    ],
};

/// Warning : passing invalid values to the builder will panic
#[derive(Default)]
pub struct LevelControlClusterBuilder {
    pub data_ver: Option<Dataver>,
    pub current_level: u8,
    pub remaining_time: Option<u16>,         // Feature LT
    pub min_level: Option<u8>,               // Optional
    pub max_level: Option<u8>,               // Optional
    pub current_frequency: Option<u8>,       // Feature FQ
    pub min_frequency: Option<u8>,           // Feature FQ
    pub max_frequency: Option<u8>,           // Feature FQ
    pub on_off_transition_time: Option<u16>, // Optional
    pub on_level: u8,
    pub on_transition_time: Option<u16>,  // Optional
    pub off_transition_time: Option<u16>, // Optional
    pub default_move_rate: Option<u8>,    // Optional
    pub options: u8,
    pub start_up_current_level: Option<u8>, // Feature LT
}

impl LevelControlClusterBuilder {
    pub fn new(rand: Rand) -> Self {
        Self {
            data_ver: Some(Dataver::new(rand)),
            ..Default::default()
        }
    }

    pub fn build(self) -> LevelControlCluster {
        LevelControlCluster {
            data_ver: self.data_ver.unwrap(),
            current_level: Cell::new(self.current_level),
            remaining_time: Cell::new(self.remaining_time.unwrap_or(0)),
            on_level: Cell::new(self.on_level),
            options: Cell::new(self.options),
            start_up_current_level: Cell::new(self.start_up_current_level.unwrap_or(0)),
        }
    }

    pub fn data_ver(mut self, rand: Rand) -> Self {
        self.data_ver = Some(Dataver::new(rand));
        self
    }

    pub fn feature_lighting(mut self, remaining_time: u16, startup_current_level: u8) -> Self {
        self.remaining_time = Some(remaining_time);
        self.start_up_current_level = Some(startup_current_level);
        self
    }

    pub fn feature_frequency(
        mut self,
        min_frequency: u16,
        max_frequency: u16,
        current_frequency: u16,
    ) -> Self {
        if min_frequency > max_frequency {
            panic!("min_frequency > max_frequency");
        }
        if current_frequency < min_frequency || current_frequency > max_frequency {
            panic!("current_frequency < min_frequency || current_frequency > max_frequency");
        }
        self.min_frequency = Some(min_frequency as u8);
        self.max_frequency = Some(max_frequency as u8);
        self.current_frequency = Some(current_frequency as u8);
        self
    }

    pub fn min_level(mut self, min_level: u8) -> Self {
        if min_level > self.max_level.unwrap_or(254) {
            panic!("min_level > max_level");
        }
        self.min_level = Some(min_level);
        self
    }

    pub fn max_level(mut self, max_level: u8) -> Self {
        if max_level < self.min_level.unwrap_or(0) {
            panic!("max_level < min_level");
        }
        if max_level > 254 {
            panic!("max_level > 254");
        }
        self.max_level = Some(max_level);
        self
    }

    pub fn on_off_transition_time(mut self, on_off_transition_time: u16) -> Self {
        self.on_off_transition_time = Some(on_off_transition_time);
        self
    }

    pub fn on_transition_time(mut self, on_transition_time: u16) -> Self {
        self.on_transition_time = Some(on_transition_time);
        self
    }

    pub fn off_transition_time(mut self, off_transition_time: u16) -> Self {
        self.off_transition_time = Some(off_transition_time);
        self
    }

    pub fn default_move_rate(mut self, default_move_rate: u8) -> Self {
        self.default_move_rate = Some(default_move_rate);
        self
    }

    /// TODO: check options are correct
    pub fn options(mut self, options: u8) -> Self {
        self.options = options;
        self
    }
}

/// TODO: implement remaining attributes
pub struct LevelControlCluster {
    pub data_ver: Dataver,
    pub current_level: Cell<u8>,
    pub remaining_time: Cell<u16>,
    pub on_level: Cell<u8>,
    pub options: Cell<u8>,
    pub start_up_current_level: Cell<u8>,
}

impl LevelControlCluster {
    pub fn new(rand: Rand) -> Self {
        Self {
            data_ver: Dataver::new(rand),
            current_level: Cell::new(1),
            remaining_time: Cell::new(0),
            on_level: Cell::new(1),
            options: Cell::new(Options::ExecuteIfOff as u8),
            start_up_current_level: Cell::new(1),
        }
    }

    pub fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                println!("Level Control read attr id: {:?}", attr.attr_id);
                let attr = match attr.attr_id.try_into() {
                    Ok(attr) => attr,
                    Err(e) => {
                        error!(
                            "Level Control read attr error: {:?} on: {:?} , aka {:08b}",
                            e, attr.attr_id, attr.attr_id
                        );
                        return Err(e);
                    }
                };
                info!("Level Control read : {:?}", &attr);
                match attr {
                    Attributes::CurrentLevel(codec) => {
                        codec.encode(writer, self.current_level.get())
                    }
                    Attributes::RemainingTime(codec) => {
                        codec.encode(writer, self.remaining_time.get())
                    }
                    Attributes::OnLevel(codec) => codec.encode(writer, self.on_level.get()),
                    Attributes::Options(codec) => codec.encode(writer, self.options.get().into()),
                    Attributes::StartUpCurrentLevel(codec) => {
                        codec.encode(writer, self.start_up_current_level.get())
                    }
                    Attributes::MaxLevel(codec) => {
                        // TODO: implement
                        codec.encode(writer, 254) // default max value
                    }
                    Attributes::MinLevel(codec) => {
                        // TODO: implement
                        codec.encode(writer, 1) // default min value for LT feature
                    }
                    _ => {
                        warn!(
                            "read {:?} : remaining attribute ids not implemented yet, skipping",
                            attr
                        );
                        Ok(())
                    }
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        let data = data.with_dataver(self.data_ver.get())?;

        let attr = attr.attr_id.try_into();
        dbg!("Write", &attr);
        let attr = attr?;

        match attr {
            Attributes::CurrentLevel(codec) => self.current_level.set(codec.decode(data)?),
            _ => {
                warn!(
                    "write {:?} : remaining attribute ids not implemented yet, skipping",
                    attr
                );
            }
        }
        self.data_ver.changed();
        Ok(())
    }

    pub fn invoke(
        &self,
        _exchange: &Exchange,
        cmd: &CmdDetails,
        _data: &TLVElement,
        _encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        dbg!("Move To Level cmd {:?}, data {:?}", &cmd, &_data);
        let cmd = cmd.cmd_id.try_into()?;
        match cmd {
            Commands::MoveToLevel => {
                cmd_enter!("Move To Level");
                self.current_level.set(50);
            }
            Commands::MoveToLevelWithOnOff => {
                cmd_enter!("Move To Level With On Off");
                self.current_level.set(50);
            }

            _ => {
                warn!(
                    "invoke {:?} : remaining command ids not implemented yet, skipping",
                    cmd
                );
            } // TODO : implement remaining commands
        }
        self.data_ver.changed();
        Ok(())
    }
}

impl Handler for LevelControlCluster {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        LevelControlCluster::read(self, attr, encoder)
    }

    fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        LevelControlCluster::write(self, attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        LevelControlCluster::invoke(self, exchange, cmd, data, encoder)
    }
}

impl NonBlockingHandler for LevelControlCluster {}

impl ChangeNotifier<()> for LevelControlCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
