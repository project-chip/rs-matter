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

//! This module contains the implementation of the General Commissioning cluster and its handler.

use crate::data_model::objects::{Cluster, Dataver, InvokeContext, ReadContext, WriteContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::TLVBuilderParent;

pub use crate::data_model::clusters::general_commissioning::*;
use crate::with;

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

/// A trait indicating the commissioning policy supported by `rs-matter`.
/// (i.e. co-existence of the BLE/BTP network and the operational network during commissioning).
pub trait CommPolicy {
    /// Return true if the device supports concurrent connection
    /// (i.e. co-existence of the BLE/BTP network and the operational network during commissioning).
    fn concurrent_connection_supported(&self) -> bool;

    /// Return the expiry length of the fail-safe in seconds.
    fn failsafe_expiry_len_secs(&self) -> u16;

    /// Return the maximum cumulative fail-safe time in seconds.
    fn failsafe_max_cml_secs(&self) -> u16;

    /// Return the regulatory configuration of the device.
    // TODO: Needs to be persisted
    fn regulatory_config(&self) -> RegulatoryLocationTypeEnum;

    /// Return the location capability of the device.
    fn location_cap(&self) -> RegulatoryLocationTypeEnum;
}

impl<T> CommPolicy for &T
where
    T: CommPolicy,
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

impl CommPolicy for bool {
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

/// The system implementation of a handler for the General Commissioning Matter cluster.
#[derive(Clone)]
pub struct GenCommHandler<'a> {
    dataver: Dataver,
    commissioning_policy: &'a dyn CommPolicy,
}

impl<'a> GenCommHandler<'a> {
    /// Create a new instance of `GenCommHandler` with the given `Dataver` and `CommissioningPolicy`.
    pub const fn new(dataver: Dataver, commissioning_policy: &'a dyn CommPolicy) -> Self {
        Self {
            dataver,
            commissioning_policy,
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for GenCommHandler<'_> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_revision(1).with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn breadcrumb(&self, _ctx: &ReadContext) -> Result<u64, Error> {
        Ok(0) // TODO
    }

    fn set_breadcrumb(&self, _ctx: &WriteContext, _value: u64) -> Result<(), Error> {
        Ok(()) // TODO
    }

    fn basic_commissioning_info<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext,
        builder: BasicCommissioningInfoBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .fail_safe_expiry_length_seconds(self.commissioning_policy.failsafe_expiry_len_secs())?
            .max_cumulative_failsafe_seconds(self.commissioning_policy.failsafe_max_cml_secs())?
            .end()
    }

    fn regulatory_config(&self, _ctx: &ReadContext) -> Result<RegulatoryLocationTypeEnum, Error> {
        Ok(RegulatoryLocationTypeEnum::IndoorOutdoor)
    }

    fn location_capability(&self, _ctx: &ReadContext) -> Result<RegulatoryLocationTypeEnum, Error> {
        Ok(self.commissioning_policy.location_cap())
    }

    fn supports_concurrent_connection(&self, _ctx: &ReadContext) -> Result<bool, Error> {
        Ok(self.commissioning_policy.concurrent_connection_supported())
    }

    fn handle_arm_fail_safe<P: TLVBuilderParent>(
        &self,
        ctx: &InvokeContext,
        request: ArmFailSafeRequest,
        response: ArmFailSafeResponseBuilder<P>,
    ) -> Result<P, Error> {
        let status = CommissioningErrorEnum::map(ctx.exchange().with_session(|sess| {
            ctx.exchange()
                .matter()
                .failsafe
                .borrow_mut()
                .arm(request.expiry_length_seconds()?, sess.get_session_mode())
        }))?;

        response.error_code(status)?.debug_text("")?.end()
    }

    fn handle_set_regulatory_config<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext,
        _request: SetRegulatoryConfigRequest,
        response: SetRegulatoryConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        // TODO
        response
            .error_code(CommissioningErrorEnum::OK)?
            .debug_text("")?
            .end()
    }

    fn handle_commissioning_complete<P: TLVBuilderParent>(
        &self,
        ctx: &InvokeContext,
        response: CommissioningCompleteResponseBuilder<P>,
    ) -> Result<P, Error> {
        let status = CommissioningErrorEnum::map(ctx.exchange().with_session(|sess| {
            ctx.exchange()
                .matter()
                .failsafe
                .borrow_mut()
                .disarm(sess.get_session_mode())
        }))?;

        if matches!(status, CommissioningErrorEnum::OK) {
            // As per section 5.5 of the Matter Core Spec V1.3 we have to teriminate the PASE session
            // upon completion of commissioning
            ctx.exchange()
                .matter()
                .pase_mgr
                .borrow_mut()
                .disable_pase_session(&ctx.exchange().matter().transport_mgr.mdns)?;
        }

        response.error_code(status)?.debug_text("")?.end()
    }
}
