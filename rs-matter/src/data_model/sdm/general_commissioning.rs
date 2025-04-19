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

use rs_matter_macros::idl_import;

use crate::data_model::objects::Dataver;
use crate::error::{Error, ErrorCode};
use crate::tlv::TLVBuilderParent;
use crate::transport::exchange::Exchange;

idl_import!(clusters = ["GeneralCommissioning"]);

impl CommissioningErrorEnum {
    fn map(result: Result<(), Error>) -> Result<Self, Error> {
        match result {
            Ok(()) => Ok(Self::OK),
            Err(err) => match err.code() {
                ErrorCode::Busy | ErrorCode::NocInvalidFabricIndex => Ok(Self::BusyWithOtherAdmin),
                ErrorCode::GennCommInvalidAuthentication => Ok(Self::InvalidAuthentication),
                ErrorCode::FailSafeRequired => Ok(Self::NoFailSafe),
                _ => Err(err),
            },
        }
    }
}

// impl BasicCommissioningInfo {
//     pub const fn new() -> Self {
//         // TODO: Arch-Specific
//         Self {
//             expiry_len: 120,
//             max_cmltv_failsafe_secs: 120,
//         }
//     }
// }

/// A trait indicating whether the device supports concurrent connection
/// (i.e. co-existence of the BLE/BTP network and the operational network during commissioning).
pub trait CommissioningPolicy {
    /// Return true if the device supports concurrent connection.
    fn concurrent_connection_supported(&self) -> bool;

    fn failsafe_expiry_len_secs(&self) -> u16;

    fn failsafe_max_cml_secs(&self) -> u16;

    fn regulatory_config(&self) -> RegulatoryLocationTypeEnum;

    fn location_cap(&self) -> RegulatoryLocationTypeEnum;
}

impl<T> CommissioningPolicy for &T
where
    T: CommissioningPolicy,
{
    fn concurrent_connection_supported(&self) -> bool {
        (*self).concurrent_connection_supported()
    }

    fn failsafe_expiry_len_secs(&self) -> u16 {
        (*self).failsafe_expiry_len_secs()
    }

    fn failsafe_max_cml_secs(&self) -> u16 {
        (*self).failsafe_max_cml_secs()
    }

    fn regulatory_config(&self) -> RegulatoryLocationTypeEnum {
        (*self).regulatory_config()
    }

    fn location_cap(&self) -> RegulatoryLocationTypeEnum {
        (*self).location_cap()
    }
}

impl CommissioningPolicy for bool {
    fn concurrent_connection_supported(&self) -> bool {
        *self
    }

    fn failsafe_expiry_len_secs(&self) -> u16 {
        120
    }

    fn failsafe_max_cml_secs(&self) -> u16 {
        120
    }

    fn regulatory_config(&self) -> RegulatoryLocationTypeEnum {
        RegulatoryLocationTypeEnum::IndoorOutdoor
    }

    fn location_cap(&self) -> RegulatoryLocationTypeEnum {
        RegulatoryLocationTypeEnum::IndoorOutdoor
    }
}

#[derive(Clone)]
pub struct GenCommCluster<'a> {
    dataver: Dataver,
    commissioning_policy: &'a dyn CommissioningPolicy,
}

impl<'a> GenCommCluster<'a> {
    pub const fn new(dataver: Dataver, commissioning_policy: &'a dyn CommissioningPolicy) -> Self {
        Self {
            dataver,
            commissioning_policy,
        }
    }
}

impl GeneralCommissioningHandler for GenCommCluster<'_> {
    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn breadcrumb(&self, _exchange: &Exchange<'_>) -> Result<u64, Error> {
        Ok(0) // TODO
    }

    fn set_breadcrumb(&self, _exchange: &Exchange<'_>, _value: u64) -> Result<(), Error> {
        Ok(()) // TODO
    }

    fn basic_commissioning_info<P: TLVBuilderParent>(
        &self,
        _exchange: &Exchange<'_>,
        builder: BasicCommissioningInfoBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .fail_safe_expiry_length_seconds(self.commissioning_policy.failsafe_expiry_len_secs())?
            .max_cumulative_failsafe_seconds(self.commissioning_policy.failsafe_max_cml_secs())?
            .finish()
    }

    fn regulatory_config(
        &self,
        _exchange: &Exchange<'_>,
    ) -> Result<RegulatoryLocationTypeEnum, Error> {
        Ok(RegulatoryLocationTypeEnum::IndoorOutdoor)
    }

    fn location_capability(
        &self,
        _exchange: &Exchange<'_>,
    ) -> Result<RegulatoryLocationTypeEnum, Error> {
        Ok(self.commissioning_policy.location_cap())
    }

    fn supports_concurrent_connection(&self, _exchange: &Exchange<'_>) -> Result<bool, Error> {
        Ok(self.commissioning_policy.concurrent_connection_supported())
    }

    fn handle_arm_fail_safe<P: TLVBuilderParent>(
        &self,
        exchange: &Exchange<'_>,
        request: ArmFailSafeRequest,
        response: ArmFailSafeResponseBuilder<P>,
    ) -> Result<P, Error> {
        let status = CommissioningErrorEnum::map(exchange.with_session(|sess| {
            exchange
                .matter()
                .failsafe
                .borrow_mut()
                .arm(request.expiry_length_seconds()?, sess.get_session_mode())
        }))?;

        response.error_code(status)?.debug_text("")?.finish()
    }

    fn handle_set_regulatory_config<P: TLVBuilderParent>(
        &self,
        _exchange: &Exchange<'_>,
        _request: SetRegulatoryConfigRequest,
        response: SetRegulatoryConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        // TODO
        response
            .error_code(CommissioningErrorEnum::OK)?
            .debug_text("")?
            .finish()
    }

    fn handle_commissioning_complete<P: TLVBuilderParent>(
        &self,
        exchange: &Exchange<'_>,
        response: CommissioningCompleteResponseBuilder<P>,
    ) -> Result<P, Error> {
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

        response.error_code(status)?.debug_text("")?.finish()
    }
}
