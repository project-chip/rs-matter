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

use log::info;

use rs_matter_macros::idl_import;

use strum::{EnumDiscriminants, FromRepr};

use crate::data_model::objects::*;
use crate::tlv::{FromTLV, TLVElement, ToTLV, Utf8Str};
use crate::transport::exchange::Exchange;
use crate::{attribute_enum, cmd_enter};
use crate::{command_enum, error::*};

idl_import!(clusters = ["GeneralCommissioning"]);

pub use general_commissioning::Commands;
pub use general_commissioning::CommissioningErrorEnum;
pub use general_commissioning::RegulatoryLocationTypeEnum;
pub use general_commissioning::ID;

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u16)]
pub enum Attributes {
    BreadCrumb(AttrType<u64>) = 0,
    BasicCommissioningInfo(()) = 1,
    RegConfig(AttrType<u8>) = 2,
    LocationCapability(AttrType<u8>) = 3,
    SupportsConcurrentConnection(AttrType<bool>) = 4,
}

attribute_enum!(Attributes);

command_enum!(Commands);

#[repr(u16)]
pub enum RespCommands {
    ArmFailsafeResp = 0x01,
    SetRegulatoryConfigResp = 0x03,
    CommissioningCompleteResp = 0x05,
}

#[derive(Debug, Clone, FromTLV, ToTLV, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
struct CommonResponse<'a> {
    error_code: u8,
    debug_txt: Utf8Str<'a>,
}

impl CommissioningErrorEnum {
    fn map(result: Result<(), Error>) -> Result<Self, Error> {
        match result {
            Ok(()) => Ok(CommissioningErrorEnum::OK),
            Err(err) => match err.code() {
                ErrorCode::Busy | ErrorCode::NocInvalidFabricIndex => {
                    Ok(CommissioningErrorEnum::BusyWithOtherAdmin)
                }
                ErrorCode::GennCommInvalidAuthentication => {
                    Ok(CommissioningErrorEnum::InvalidAuthentication)
                }
                ErrorCode::FailSafeRequired => Ok(CommissioningErrorEnum::NoFailSafe),
                _ => Err(err),
            },
        }
    }
}

#[derive(Debug, FromTLV, ToTLV, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct FailSafeParams {
    expiry_len: u16,
    bread_crumb: u64,
}

#[derive(Debug, Clone, FromTLV, ToTLV, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BasicCommissioningInfo {
    pub expiry_len: u16,
    pub max_cmltv_failsafe_secs: u16,
}

impl BasicCommissioningInfo {
    pub const fn new() -> Self {
        // TODO: Arch-Specific
        Self {
            expiry_len: 120,
            max_cmltv_failsafe_secs: 120,
        }
    }
}

impl Default for BasicCommissioningInfo {
    fn default() -> Self {
        BasicCommissioningInfo::new()
    }
}

#[derive(Debug, Clone, FromTLV, ToTLV, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
struct RegulatoryConfig<'a> {
    #[tagval(1)]
    country_code: Utf8Str<'a>,
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
        Attribute::new(
            AttributesDiscriminants::SupportsConcurrentConnection as u16,
            Access::RV,
            Quality::FIXED,
        ),
    ],
    commands: &[
        Commands::ArmFailSafe as _,
        Commands::SetRegulatoryConfig as _,
        Commands::CommissioningComplete as _,
    ],
};

/// A trait indicating whether the device supports concurrent connection
/// (i.e. co-existence of the BLE/BTP network and the operational network during commissioning).
pub trait ConcurrentConnectionPolicy {
    /// Return true if the device supports concurrent connection.
    fn concurrent_connection_supported(&self) -> bool;
}

impl<T> ConcurrentConnectionPolicy for &T
where
    T: ConcurrentConnectionPolicy,
{
    fn concurrent_connection_supported(&self) -> bool {
        (*self).concurrent_connection_supported()
    }
}

impl ConcurrentConnectionPolicy for bool {
    fn concurrent_connection_supported(&self) -> bool {
        *self
    }
}

#[derive(Clone)]
pub struct GenCommCluster<'a> {
    data_ver: Dataver,
    basic_comm_info: BasicCommissioningInfo,
    concurrent_connection_policy: &'a dyn ConcurrentConnectionPolicy,
}

impl<'a> GenCommCluster<'a> {
    pub const fn new(
        data_ver: Dataver,
        basic_comm_info: BasicCommissioningInfo,
        concurrent_connection_policy: &'a dyn ConcurrentConnectionPolicy,
    ) -> Self {
        Self {
            data_ver,
            basic_comm_info,
            concurrent_connection_policy,
        }
    }

    pub fn read(
        &self,
        _exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        if let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::BreadCrumb(codec) => codec.encode(writer, 0),
                    // TODO: Arch-Specific
                    Attributes::RegConfig(codec) => {
                        codec.encode(writer, RegulatoryLocationTypeEnum::IndoorOutdoor as _)
                    }
                    // TODO: Arch-Specific
                    Attributes::LocationCapability(codec) => {
                        codec.encode(writer, RegulatoryLocationTypeEnum::IndoorOutdoor as _)
                    }
                    Attributes::BasicCommissioningInfo(_) => {
                        self.basic_comm_info
                            .to_tlv(&AttrDataWriter::TAG, &mut *writer)?;
                        writer.complete()
                    }
                    Attributes::SupportsConcurrentConnection(codec) => codec.encode(
                        writer,
                        self.concurrent_connection_policy
                            .concurrent_connection_supported(),
                    ),
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        match cmd.cmd_id.try_into()? {
            Commands::ArmFailSafe => self.handle_command_armfailsafe(exchange, data, encoder)?,
            Commands::SetRegulatoryConfig => {
                self.handle_command_setregulatoryconfig(exchange, data, encoder)?
            }
            Commands::CommissioningComplete => {
                self.handle_command_commissioningcomplete(exchange, encoder)?;
            }
        }

        self.data_ver.changed();

        Ok(())
    }

    fn handle_command_armfailsafe(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("ARM Fail Safe");

        let p = FailSafeParams::from_tlv(data).map_err(Error::map_invalid_command)?;
        info!("Received fail safe params: {:?}", p);

        let status = CommissioningErrorEnum::map(exchange.with_session(|sess| {
            exchange
                .matter()
                .failsafe
                .borrow_mut()
                .arm(p.expiry_len, sess.get_session_mode())
        }))?;

        let cmd_data = CommonResponse {
            error_code: status as _,
            debug_txt: "",
        };

        encoder
            .with_command(RespCommands::ArmFailsafeResp as _)?
            .set(cmd_data)?;

        Ok(())
    }

    fn handle_command_setregulatoryconfig(
        &self,
        _exchange: &Exchange,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("Set Regulatory Config");

        let cfg = RegulatoryConfig::from_tlv(data).map_err(Error::map_invalid_command)?;
        info!("Received reg cfg: {:?}", cfg);

        let cmd_data = CommonResponse {
            error_code: 0,
            debug_txt: "",
        };

        encoder
            .with_command(RespCommands::SetRegulatoryConfigResp as _)?
            .set(cmd_data)?;

        Ok(())
    }

    fn handle_command_commissioningcomplete(
        &self,
        exchange: &Exchange,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("Commissioning Complete");

        let status = CommissioningErrorEnum::map(exchange.with_session(|sess| {
            exchange
                .matter()
                .failsafe
                .borrow_mut()
                .disarm(sess.get_session_mode())
        }))?;

        if matches!(status, CommissioningErrorEnum::OK) {
            // As per section 5.5 of the Matter Core Spec V1.3 we have to teriminate the PASE session
            // upon completion of commissioning
            exchange
                .matter()
                .pase_mgr
                .borrow_mut()
                .disable_pase_session(&exchange.matter().transport_mgr.mdns)?;
        }

        let cmd_data = CommonResponse {
            error_code: status as _,
            debug_txt: "",
        };

        encoder
            .with_command(RespCommands::CommissioningCompleteResp as _)?
            .set(cmd_data)?;

        Ok(())
    }
}

impl Handler for GenCommCluster<'_> {
    fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        GenCommCluster::read(self, exchange, attr, encoder)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        GenCommCluster::invoke(self, exchange, cmd, data, encoder)
    }
}

impl NonBlockingHandler for GenCommCluster<'_> {}

impl ChangeNotifier<()> for GenCommCluster<'_> {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
