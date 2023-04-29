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

use core::cell::RefCell;
use core::convert::TryInto;

use crate::data_model::objects::*;
use crate::data_model::sdm::failsafe::FailSafe;
use crate::interaction_model::core::Transaction;
use crate::tlv::{FromTLV, TLVElement, TLVWriter, TagType, ToTLV, UtfStr};
use crate::utils::rand::Rand;
use crate::{attribute_enum, cmd_enter};
use crate::{command_enum, error::*};
use log::info;
use strum::{EnumDiscriminants, FromRepr};

#[derive(Clone, Copy)]
#[allow(dead_code)]
enum CommissioningError {
    Ok = 0,
    ErrValueOutsideRange = 1,
    ErrInvalidAuth = 2,
    ErrNotCommissioning = 3,
    ErrBusyWithOtherAdmin = 4,
}

pub const ID: u32 = 0x0030;

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u16)]
pub enum Attributes {
    BreadCrumb(AttrType<u64>) = 0,
    BasicCommissioningInfo(()) = 1,
    RegConfig(AttrType<u8>) = 2,
    LocationCapability(AttrType<u8>) = 3,
}

attribute_enum!(Attributes);

#[derive(FromRepr)]
#[repr(u32)]
pub enum Commands {
    ArmFailsafe = 0x00,
    SetRegulatoryConfig = 0x02,
    CommissioningComplete = 0x04,
}

command_enum!(Commands);

#[repr(u16)]
pub enum RespCommands {
    ArmFailsafeResp = 0x01,
    SetRegulatoryConfigResp = 0x03,
    CommissioningCompleteResp = 0x05,
}

#[derive(FromTLV, ToTLV)]
#[tlvargs(lifetime = "'a")]
struct CommonResponse<'a> {
    error_code: u8,
    debug_txt: UtfStr<'a>,
}

pub enum RegLocationType {
    Indoor = 0,
    Outdoor = 1,
    IndoorOutdoor = 2,
}

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    feature_map: 0,
    attributes: &[
        FEATURE_MAP,
        ATTRIBUTE_LIST,
        Attribute::new(
            AttributesDiscriminants::BreadCrumb as u16,
            Access::READ.union(Access::WRITE).union(Access::NEED_ADMIN),
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::RegConfig as u16,
            Access::RV,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::LocationCapability as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::BasicCommissioningInfo as u16,
            Access::RV,
            Quality::FIXED,
        ),
    ],
    commands: &[
        Commands::ArmFailsafe as _,
        Commands::SetRegulatoryConfig as _,
        Commands::CommissioningComplete as _,
    ],
};

#[derive(FromTLV, ToTLV)]
struct FailSafeParams {
    expiry_len: u8,
    bread_crumb: u8,
}

pub struct GenCommCluster<'a> {
    data_ver: Dataver,
    expiry_len: u16,
    failsafe: &'a RefCell<FailSafe>,
}

impl<'a> GenCommCluster<'a> {
    pub fn new(failsafe: &'a RefCell<FailSafe>, rand: Rand) -> Self {
        Self {
            data_ver: Dataver::new(rand),
            failsafe,
            // TODO: Arch-Specific
            expiry_len: 120,
        }
    }

    pub fn failsafe(&self) -> &RefCell<FailSafe> {
        &self.failsafe
    }

    pub fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::BreadCrumb(codec) => codec.encode(writer, 0),
                    // TODO: Arch-Specific
                    Attributes::RegConfig(codec) => {
                        codec.encode(writer, RegLocationType::IndoorOutdoor as _)
                    }
                    // TODO: Arch-Specific
                    Attributes::LocationCapability(codec) => {
                        codec.encode(writer, RegLocationType::IndoorOutdoor as _)
                    }
                    Attributes::BasicCommissioningInfo(_) => {
                        writer.start_struct(AttrDataWriter::TAG)?;
                        writer.u16(TagType::Context(0), self.expiry_len)?;
                        writer.end_container()?;

                        writer.complete()
                    }
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn invoke(
        &mut self,
        transaction: &mut Transaction,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        match cmd.cmd_id.try_into()? {
            Commands::ArmFailsafe => self.handle_command_armfailsafe(transaction, data, encoder)?,
            Commands::SetRegulatoryConfig => {
                self.handle_command_setregulatoryconfig(transaction, data, encoder)?
            }
            Commands::CommissioningComplete => {
                self.handle_command_commissioningcomplete(transaction, encoder)?;
            }
        }

        self.data_ver.changed();

        Ok(())
    }

    fn handle_command_armfailsafe(
        &mut self,
        transaction: &mut Transaction,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("ARM Fail Safe");

        let p = FailSafeParams::from_tlv(data)?;

        let status = if self
            .failsafe
            .borrow_mut()
            .arm(p.expiry_len, transaction.session().get_session_mode())
            .is_err()
        {
            CommissioningError::ErrBusyWithOtherAdmin as u8
        } else {
            CommissioningError::Ok as u8
        };

        let cmd_data = CommonResponse {
            error_code: status,
            debug_txt: UtfStr::new(b""),
        };

        encoder
            .with_command(RespCommands::ArmFailsafeResp as _)?
            .set(cmd_data)?;

        transaction.complete();
        Ok(())
    }

    fn handle_command_setregulatoryconfig(
        &mut self,
        transaction: &mut Transaction,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("Set Regulatory Config");
        let country_code = data
            .find_tag(1)
            .map_err(|_| ErrorCode::InvalidCommand)?
            .slice()
            .map_err(|_| ErrorCode::InvalidCommand)?;
        info!("Received country code: {:?}", country_code);

        let cmd_data = CommonResponse {
            error_code: 0,
            debug_txt: UtfStr::new(b""),
        };

        encoder
            .with_command(RespCommands::SetRegulatoryConfigResp as _)?
            .set(cmd_data)?;

        transaction.complete();
        Ok(())
    }

    fn handle_command_commissioningcomplete(
        &mut self,
        transaction: &mut Transaction,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("Commissioning Complete");
        let mut status: u8 = CommissioningError::Ok as u8;

        // Has to be a Case Session
        if transaction.session().get_local_fabric_idx().is_none() {
            status = CommissioningError::ErrInvalidAuth as u8;
        }

        // AddNOC or UpdateNOC must have happened, and that too for the same fabric
        // scope that is for this session
        if self
            .failsafe
            .borrow_mut()
            .disarm(transaction.session().get_session_mode())
            .is_err()
        {
            status = CommissioningError::ErrInvalidAuth as u8;
        }

        let cmd_data = CommonResponse {
            error_code: status,
            debug_txt: UtfStr::new(b""),
        };

        encoder
            .with_command(RespCommands::CommissioningCompleteResp as _)?
            .set(cmd_data)?;

        transaction.complete();
        Ok(())
    }
}

impl<'a> Handler for GenCommCluster<'a> {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        GenCommCluster::read(self, attr, encoder)
    }

    fn invoke(
        &mut self,
        transaction: &mut Transaction,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        GenCommCluster::invoke(self, transaction, cmd, data, encoder)
    }
}

impl<'a> NonBlockingHandler for GenCommCluster<'a> {}

impl<'a> ChangeNotifier<()> for GenCommCluster<'a> {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
