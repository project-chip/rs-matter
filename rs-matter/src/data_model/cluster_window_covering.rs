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
    error::{Error, ErrorCode},
    tlv::{FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
    transport::exchange::Exchange,
    utils::rand::Rand,
};
use domain::rdata::A;
use log::info;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use strum::{EnumDiscriminants, FromRepr};

pub const ID: u32 = 0x0102;

#[repr(u8)]
pub enum Features {
    /// Lift Control and behavior for lift­ing/sliding win­dow coverings
    LiftControl = 0b0000_0001,
    /// Tilt Control and behavior for tilt­ing window cover­ings
    TiltControl = 0b0000_0010,
    /// Position Aware lift control is sup­ported.
    PositionAwareLiftControl = 0b0000_0100,
    /// Absolute position­ ing is supported.
    AbsolutePosition = 0b0000_1000,
    /// Position Aware tilt control is sup­ported.
    PositionAwareTiltControl = 0b0001_0000,
}

#[derive(FromRepr, EnumDiscriminants, FromPrimitive, Copy, Clone, PartialEq, Default)]
#[repr(u8)]
pub enum TypeAttribute {
    /// Lift
    #[default]
    Rollershade = 0x00,
    /// Lift
    Rollershade2Motor = 0x01,
    /// Lift
    RollershadeExterior = 0x02,
    /// Lift
    RollershadeExterior2Motor = 0x03,
    /// Lift
    Drapery = 0x04,
    /// Lift
    Awning = 0x05,
    /// Tilt, Lift
    Shutter = 0x06,
    /// Tilt
    TiltBlindTiltOnly = 0x07,
    /// Lift, Tilt
    TiltBlindLiftAndTilt = 0x08,
    /// Lift
    ProjectorScreen = 0x09,
    /// Reserved
    Unknown = 0xFF,
}

impl FromTLV<'_> for TypeAttribute {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error> {
        FromPrimitive::from_u8(t.u8()?).ok_or_else(|| ErrorCode::Invalid.into())
    }
}

impl ToTLV for TypeAttribute {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        tw.u8(tag_type, *self as u8)
    }
}

#[derive( Copy, Clone, PartialEq, Default)]
pub struct ConfigStatus {
    /// Conformance Mandatory
    operational: bool,

    /// Conformance LF
    lift_movement_reversed: bool,

    /// Conformance LF
    lift_control_position_aware : bool,

    /// Conformance TL
    tilt_control_position_aware : bool,

    // Conformance LF & PA_LF
    lift_controller_uses_encoder : bool,
    
    // Conformance TL & PA_TL
    tilt_controller_uses_encoder : bool,
}

impl From<u8> for ConfigStatus {
    fn from(v: u8) -> ConfigStatus {
        ConfigStatus {
            operational: v & 0b0000_0001 == 0b0000_0001,
            lift_movement_reversed: v & 0b0000_0100 == 0b0000_0100,
            lift_control_position_aware: v & 0b0000_1000 == 0b0000_1000,
            tilt_control_position_aware: v & 0b0001_0000 == 0b0001_0000,
            lift_controller_uses_encoder: v & 0b0010_0000 == 0b0010_0000,
            tilt_controller_uses_encoder: v & 0b0100_0000 == 0b0100_0000,
        }
    }
}

impl FromTLV<'_> for ConfigStatus {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error> {
        Ok(ConfigStatus::from(t.u8()?))
    }
}

impl Into<u8> for ConfigStatus {
    fn into(self) -> u8 {
        let mut v = 0u8;
        if self.operational {
            v |= 0b0000_0001;
        }
        if self.lift_movement_reversed {
            v |= 0b0000_0100;
        }
        if self.lift_control_position_aware {
            v |= 0b0000_1000;
        }
        if self.tilt_control_position_aware {
            v |= 0b0001_0000;
        }
        if self.lift_controller_uses_encoder {
            v |= 0b0010_0000;
        }
        if self.tilt_controller_uses_encoder {
            v |= 0b0100_0000;
        }
        v
    }
}

impl ToTLV for ConfigStatus {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        tw.u8(tag_type, self.clone().into())
    }
}

#[derive(FromRepr, EnumDiscriminants, FromPrimitive, Copy, Clone, PartialEq, Default)]
#[repr(u8)]
pub enum CoveringStatus {
    #[default]
    NotMoving = 0b00,
    Opening = 0b01,
    Closing = 0b10,
    Reserved = 0b11,
}

impl From<u8> for CoveringStatus {
    fn from(v: u8) -> CoveringStatus {
        match v {
            0b00 => CoveringStatus::NotMoving,
            0b01 => CoveringStatus::Opening,
            0b10 => CoveringStatus::Closing,
            _ => CoveringStatus::Reserved,
        }
    }
}

impl Into<u8> for CoveringStatus {
    fn into(self) -> u8 {
        self as u8
    }
}

/// The OperationalStatus attribute keeps track of currently ongoing operations and applies to all type of devices. See below for details about the meaning of individual bits.
#[derive(Copy, Clone, PartialEq, Default)]
pub struct OperationalStatus {
    /// Indicates in which direction the covering is cur­ rently moving or if it has stopped. 
    /// Bit : 0..1
    status: CoveringStatus,
    /// Indicates in which direction the covering’s Lift is currently moving or if it has stopped. 
    /// Bit : 2..3
    status_lift : CoveringStatus,
    /// Indicates in which direction the covering’s Tilt is currently moving or if it has stopped.
    /// Bit : 4..5
    status_tilt : CoveringStatus,
}

impl From<u8> for OperationalStatus {
    fn from(v: u8) -> Self {
        OperationalStatus {
            status: CoveringStatus::from(v & 0b11),
            status_lift: CoveringStatus::from((v >> 2) & 0b11),
            status_tilt: CoveringStatus::from((v >> 4) & 0b11),
        }
    }
}

impl FromTLV<'_> for OperationalStatus {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error> {
        Ok(OperationalStatus::from(t.u8()?))
    }
}

impl Into<u8> for OperationalStatus {
    fn into(self) -> u8 {
        let mut v = 0u8;
        v |= self.status as u8;
        v |= (self.status_lift as u8) << 2;
        v |= (self.status_tilt as u8) << 4;
        v
    }
}

impl ToTLV for OperationalStatus {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        tw.u8(tag_type, self.clone().into())
    }
}

#[derive(FromRepr, EnumDiscriminants, FromPrimitive, Copy, Clone, PartialEq, Default)]
#[repr(u8)]
pub enum EndProductType {
    #[default]
    Rollershade = 0x00,
    RomanShade = 0x01,
    BalloonShade = 0x02,
    WovenWood = 0x03,
    PleatedShade = 0x04,
    CellularShade = 0x05,
    LayeredShade = 0x06,
    LayeredShade2D = 0x07,
    SheerShader = 0x08,
    TiltOnlyInteriorBlind = 0x09,
    InteriorBlind = 0x0A,
    VerticalBlindStripCurtain = 0x0B,
    InteriorVenetianBlind = 0x0C,
    ExteriorVenetianBlind = 0x0D,
    LateralLeftCurtain = 0x0E,
    LateralRightCurtain = 0x0F,
    CentralCurtain = 0x10,
    RollerShutter = 0x11,
    ExteriorVerticalScreen = 0x12,
    AwningTerracePatio = 0x13,
    AwningVerticalScreen = 0x14,
    TiltOnlyPergola = 0x15,
    SwingingShutter = 0x16,
    SlidingShutter = 0x17,
    Unknown = 0xFF,
}

impl From<u8> for EndProductType {
    fn from(v: u8) -> EndProductType {
        match v {
            0x00 => EndProductType::Rollershade,
            0x01 => EndProductType::RomanShade,
            0x02 => EndProductType::BalloonShade,
            0x03 => EndProductType::WovenWood,
            0x04 => EndProductType::PleatedShade,
            0x05 => EndProductType::CellularShade,
            0x06 => EndProductType::LayeredShade,
            0x07 => EndProductType::LayeredShade2D,
            0x08 => EndProductType::SheerShader,
            0x09 => EndProductType::TiltOnlyInteriorBlind,
            0x0A => EndProductType::InteriorBlind,
            0x0B => EndProductType::VerticalBlindStripCurtain,
            0x0C => EndProductType::InteriorVenetianBlind,
            0x0D => EndProductType::ExteriorVenetianBlind,
            0x0E => EndProductType::LateralLeftCurtain,
            0x0F => EndProductType::LateralRightCurtain,
            0x10 => EndProductType::CentralCurtain,
            0x11 => EndProductType::RollerShutter,
            0x12 => EndProductType::ExteriorVerticalScreen,
            0x13 => EndProductType::AwningTerracePatio,
            0x14 => EndProductType::AwningVerticalScreen,
            0x15 => EndProductType::TiltOnlyPergola,
            0x16 => EndProductType::SwingingShutter,
            0x17 => EndProductType::SlidingShutter,
            _ => EndProductType::Unknown,
        }
    }
}

impl FromTLV<'_> for EndProductType {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error> {
        Ok(EndProductType::from(t.u8()?))
    }
}

impl Into<u8> for EndProductType {
    fn into(self) -> u8 {
        self as u8
    }
}

impl ToTLV for EndProductType {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        tw.u8(tag_type, self.clone().into())
    }
}

#[derive(Copy, Clone, PartialEq, Default)]
pub struct Mode {
    lift_movement_reverse : bool,
    calibrating : bool,
    maintenance : bool,
    led_feedback : bool,
}

impl From<u8> for Mode {
    fn from(value: u8) -> Self {
        Mode {
            lift_movement_reverse: (value & 0b0000_0001) != 0,
            calibrating: (value & 0b0000_0010) != 0,
            maintenance: (value & 0b0000_0100) != 0,
            led_feedback: (value & 0b0000_1000) != 0,
        }
    }
}

impl FromTLV<'_> for Mode {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error> {
        Ok(Mode::from(t.u8()?))
    }
}

impl Into<u8> for Mode {
    fn into(self) -> u8 {
        let mut value = 0;
        if self.lift_movement_reverse {
            value |= 0b0000_0001;
        }
        if self.calibrating {
            value |= 0b0000_0010;
        }
        if self.maintenance {
            value |= 0b0000_0100;
        }
        if self.led_feedback {
            value |= 0b0000_1000;
        }
        value
    }
}

impl ToTLV for Mode {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        tw.u8(tag_type, self.clone().into())
    }
}

#[derive(Copy, Clone, PartialEq, Default)]
struct Safety {
    /// Movement commands are ignored (locked out). e.g. not granted authorization, outside some time/date range.
    /// Bit : 0
    remote_lockout : bool,
    /// Tampering detected on sensors or any other safety equip­ ment. Ex: a device has been forcedly moved without its actuator(s).
    /// Bit : 1
    tamper_detected : bool,
    /// Communication failure to sensors or other safety equip­ ment.
    /// Bit : 2
    communication_failure : bool,
    /// Device has failed to reach the desired position. e.g. with Position Aware device, time expired before TargetPosition is reached.
    /// Bit : 3
    position_failure : bool,
    /// Motor(s) and/or electric circuit thermal protection acti­ vated.
    /// Bit : 4
    thermal_protection : bool,
    /// An obstacle is preventing actuator movement.
    /// Bit : 5
    obstacle_detected : bool,
    /// Device has power related issue or limitation e.g. device is running w/ the help of a backup battery or power might not be fully available at the moment.
    /// Bit : 6
    power_source_failure : bool,
    /// Local safety sensor (not a direct obstacle) is preventing movements (e.g. Safety EU Standard EN60335).
    /// Bit : 7
    stop_input : bool,
    /// Mechanical problem related to the motor(s) detected.
    /// Bit : 8
    motor_jammed : bool,
    /// PCB, fuse and other electrics problems.
    /// Bit : 9
    hardware_failure : bool,
    /// Actuator is manually operated and is preventing actuator movement (e.g. actuator is disengaged/decoupled).
    /// Bit : 10
    manual_operation : bool,
    /// Protection is activated.
    /// Bit : 11
    protection_activated : bool,
}

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u16)]
pub enum Attributes {
    /// Conformance Mandatory
    Type(AttrType<TypeAttribute>) = 0x0000,
    /// Conformance [LF & PA_LF & ABS]
    /// unit : cm
    PhysicalClosedLimitLift(AttrType<u16>) = 0x0001,
    /// Conformance [TL & PA_TL & ABS]
    /// unit : 0.1°
    PhysicalClosedLimitTilt(AttrType<u16>) = 0x0002,
    /// Conformance [LF & PA_LF & ABS]
    /// unit : cm
    CurrentPositionLift(AttrType<u16>) = 0x0003,
    /// Conformance [TL & PA_TL & ABS]
    /// unit : 0.1°
    CurrentPositionTilt(AttrType<u16>) = 0x0004,
    /// Conformance [LF]
    /// #
    NumberOfActuationsLift(AttrType<u16>) = 0x0005,
    /// Conformance [TL]
    /// #
    NumberOfActuationsTilt(AttrType<u16>) = 0x0006,
    /// Conformance Mandatory
    /// map
    ConfigStatus(AttrType<ConfigStatus>) = 0x0007,
    /// Conformance [LF & PA_LF]
    /// unit : 1% | 1-100%
    CurrentPositionLiftPercentage(AttrType<u8>) = 0x0008,
    /// Conformance [TL & PA_TL]
    /// unit : 1% | 1-100%
    CurrentPositionTiltPercentage(AttrType<u8>) = 0x0009,
    /// Conformance Mandatory
    /// map
    OperationalStatus(AttrType<OperationalStatus>) = 0x000A,
    /// Conformance [LF & PA_LF]
    /// unit : 0.01% | 0 to 10000
    TargetPositionLiftPercent100ths(AttrType<u16>) = 0x000B,
    /// Conformance [TL & PA_TL]
    /// unit : 0.01% | 0 to 10000
    TargetPositionTiltPercent100ths(AttrType<u16>) = 0x000C,
    /// Conformance Mandatory
    /// enum
    EndProductType(AttrType<EndProductType>) = 0x000D,
    /// Conformance [LF & PA_LF]
    /// unit : 0.01% | 0 to 10000
    CurrentPositionLiftPercent100ths(AttrType<u16>) = 0x000E,
    /// Conformance [TL & PA_TL]
    /// unit : 0.01% | 0 to 10000
    CurrentPositionTiltPercent100ths(AttrType<u16>) = 0x000F,
    /// Conformance [LF & PA_LF & ABS]
    /// unit : cm
    InstalledOpenLimitLift(AttrType<u16>) = 0x0010,
    /// Conformance [LF & PA_LF & ABS]
    /// unit : cm
    InstalledClosedLimitLift(AttrType<u16>) = 0x0011,
    /// Conformance [TL & PA_TL & ABS]
    /// unit : 0.1°
    InstalledOpenLimitTilt(AttrType<u16>) = 0x0012,
    /// Conformance [TL & PA_TL & ABS]
    /// unit : 0.1°
    InstalledClosedLimitTilt(AttrType<u16>) = 0x0013,

    // .. 0x0014 - 0x0016 Attributes with conformance D : Deleted
    /// Conformance Mandatory
    /// map
    Mode(AttrType<Mode>) = 0x0017,

    // .. 0x0018 - 0x0019 Attributes with conformance D : Deleted
    /// Conformance Optional
    /// map
    SafetyStatus(AttrType<u16>) = 0x001A,
}

attribute_enum!(Attributes);

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u32)]
pub enum Commands {
    /// Conformance Mandatory
    UpOrOpen = 0x00,
    /// Conformance Mandatory
    DownOrClose = 0x01,
    /// Conformance Mandatory
    StopMotion = 0x02,
    /// Conformance [LF & ABS]
    GoToLiftValue = 0x04,
    /// Conformance LF & PA_LF, [LF]
    GoToLiftPercentage = 0x05,
    /// Conformance [TL & ABS]
    GoToTiltValue = 0x07,
    /// Conformance TL & PA_TL, [TL]
    GoToTiltPercentage = 0x08,
}

command_enum!(Commands);

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    feature_map: 0,
    attributes: &[
        FEATURE_MAP,
        ATTRIBUTE_LIST,
        Attribute::new(AttributesDiscriminants::Type as u16, Access::RV, Quality::F),
        Attribute::new(AttributesDiscriminants::ConfigStatus as u16, Access::RV, Quality::N),
        Attribute::new(AttributesDiscriminants::OperationalStatus as u16, Access::RV, Quality::P),
        Attribute::new(AttributesDiscriminants::EndProductType as u16, Access::RV, Quality::F),
        Attribute::new(AttributesDiscriminants::Mode as u16, Access::RWVM, Quality::N),
    ],
    commands: &[
        CommandsDiscriminants::UpOrOpen as _,
        CommandsDiscriminants::DownOrClose as _,
        CommandsDiscriminants::StopMotion as _,
        CommandsDiscriminants::GoToLiftValue as _,
        CommandsDiscriminants::GoToLiftPercentage as _,
        CommandsDiscriminants::GoToTiltValue as _,
        CommandsDiscriminants::GoToTiltPercentage as _,
    ],
};

pub struct WindowCoveringCluster {
    data_ver: Dataver,
    type_attribute: Cell<TypeAttribute>,
    config_status : Cell<ConfigStatus>,
    operational_status : Cell<OperationalStatus>,
    end_product_type : Cell<EndProductType>,
    mode : Cell<Mode>
}

impl WindowCoveringCluster {
    pub fn new(rand: Rand) -> Self {
        Self {
            data_ver: Dataver::new(rand),
            type_attribute: Cell::new(TypeAttribute::default()),
            config_status : Cell::new(ConfigStatus::default()),
            operational_status : Cell::new(OperationalStatus::default()),
            end_product_type : Cell::new(EndProductType::default()),
            mode : Cell::new(Mode::default())
        }
    }

    pub fn set_type(&self, device_type: TypeAttribute) {
        if self.type_attribute.get() != device_type {
            self.type_attribute.set(device_type);
            self.data_ver.changed();
        }
    }

    pub fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::Type(codec) => codec.encode(writer, self.type_attribute.get()),
                    Attributes::ConfigStatus(codec) => codec.encode(writer, self.config_status.get()),
                    Attributes::OperationalStatus(codec) => codec.encode(writer, self.operational_status.get()),
                    Attributes::EndProductType(codec) => codec.encode(writer, self.end_product_type.get()),
                    Attributes::Mode(codec) => codec.encode(writer, self.mode.get()),                
                    _ => todo!("read {:?}", attr.attr_id),
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        let data = data.with_dataver(self.data_ver.get())?;

        match attr.attr_id.try_into()? {
            Attributes::Type(codec) => self.set_type(codec.decode(data)?),
            _ => todo!("write {:?}", attr.attr_id),
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
        match cmd.cmd_id.try_into()? {
            Commands::DownOrClose => {
                cmd_enter!("DownOrClose");
                todo!("DownOrClose");
            }
            _ => todo!("invoke {:?}", cmd.cmd_id),
        }

        #[allow(unreachable_code)]
        {
            self.data_ver.changed();
        }

        Ok(())
    }
}

impl Handler for WindowCoveringCluster {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        WindowCoveringCluster::read(self, attr, encoder)
    }

    fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        WindowCoveringCluster::write(self, attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        WindowCoveringCluster::invoke(self, exchange, cmd, data, encoder)
    }
}

// TODO: Might be removed once the `on` member is externalized
impl NonBlockingHandler for WindowCoveringCluster {}

impl ChangeNotifier<()> for WindowCoveringCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
