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

use core::fmt::Debug;

use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext, WriteContext};
use crate::error::{Error, ErrorCode};
use crate::persist::{Persist, BASIC_INFO_KEY};
use crate::tlv::TLVBuilderParent;
use crate::utils::sync::DynBase;
use crate::with;

pub use crate::dm::clusters::decl::general_commissioning::*;

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
pub trait CommPolicy: DynBase {
    /// Return true if the device supports concurrent connection
    /// (i.e. co-existence of the BLE/BTP network and the operational network during commissioning).
    fn concurrent_connection_supported(&self) -> bool;

    /// Return the expiry length of the fail-safe in seconds.
    fn failsafe_expiry_len_secs(&self) -> u16;

    /// Return the maximum cumulative fail-safe time in seconds.
    fn failsafe_max_cml_secs(&self) -> u16;

    /// Return the regulatory configuration of the device.
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

impl DynBase for bool {}

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
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn breadcrumb(&self, ctx: impl ReadContext) -> Result<u64, Error> {
        ctx.exchange()
            .with_state(|state| Ok(state.failsafe.breadcrumb()))
    }

    fn set_breadcrumb(&self, ctx: impl WriteContext, value: u64) -> Result<(), Error> {
        ctx.exchange().with_state(|state| {
            state.failsafe.set_breadcrumb(value);

            Ok(())
        })
    }

    fn basic_commissioning_info<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: BasicCommissioningInfoBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .fail_safe_expiry_length_seconds(self.commissioning_policy.failsafe_expiry_len_secs())?
            .max_cumulative_failsafe_seconds(self.commissioning_policy.failsafe_max_cml_secs())?
            .end()
    }

    fn regulatory_config(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<RegulatoryLocationTypeEnum, Error> {
        Ok(RegulatoryLocationTypeEnum::IndoorOutdoor)
    }

    fn location_capability(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<RegulatoryLocationTypeEnum, Error> {
        Ok(self.commissioning_policy.location_cap())
    }

    fn supports_concurrent_connection(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        Ok(self.commissioning_policy.concurrent_connection_supported())
    }

    fn handle_arm_fail_safe<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: ArmFailSafeRequest<'_>,
        response: ArmFailSafeResponseBuilder<P>,
    ) -> Result<P, Error> {
        let notify_mdns = || ctx.exchange().matter().notify_mdns();
        let notify_change =
            |endpt_id, clust_id, attr_id| ctx.notify_attribute_changed(endpt_id, clust_id, attr_id);

        ctx.exchange().with_state(|state| {
            let sess = ctx.exchange().id().session(&mut state.sessions);

            let status = CommissioningErrorEnum::map(state.failsafe.arm(
                request.expiry_length_seconds()?,
                request.breadcrumb()?,
                sess.get_session_mode(),
                &mut state.pase,
                notify_mdns,
                notify_change,
            ))?;

            response.error_code(status)?.debug_text("")?.end()
        })
    }

    fn handle_set_regulatory_config<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: SetRegulatoryConfigRequest<'_>,
        response: SetRegulatoryConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        let country_code = request.country_code()?;
        if country_code.len() != 2 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let location_type = request.new_regulatory_config()?;
        let breadcrumb = request.breadcrumb()?;

        let mut persist = Persist::new(ctx.kv());

        ctx.exchange().with_state(|state| {
            state.basic_info_settings.set_location(country_code);
            state.basic_info_settings.location_type = location_type;

            state.failsafe.set_breadcrumb(breadcrumb);

            persist.store_tlv(BASIC_INFO_KEY, &state.basic_info_settings)
        })?;

        persist.run()?;

        response
            .error_code(CommissioningErrorEnum::OK)?
            .debug_text("")?
            .end()
    }

    fn handle_commissioning_complete<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        response: CommissioningCompleteResponseBuilder<P>,
    ) -> Result<P, Error> {
        let notify_mdns = || ctx.exchange().matter().notify_mdns();
        let notify_change =
            |endpt_id, clust_id, attr_id| ctx.notify_attribute_changed(endpt_id, clust_id, attr_id);

        ctx.exchange().with_state(|state| {
            let sess = ctx.exchange().id().session(&mut state.sessions);

            let status = CommissioningErrorEnum::map(
                state
                    .failsafe
                    .disarm(sess.get_session_mode())
                    .map_err(|err| match err.code() {
                        ErrorCode::NocInvalidFabricIndex => {
                            Error::new(ErrorCode::GennCommInvalidAuthentication)
                        }
                        _ => err,
                    }),
            )?;

            if matches!(status, CommissioningErrorEnum::OK) {
                // As per section 5.5 of the Matter Core Spec V1.3 we have to terminate the PASE session
                // upon completion of commissioning
                state.pase.close_comm_window(notify_mdns, notify_change)?;
            }

            response.error_code(status)?.debug_text("")?.end()
        })
    }

    fn handle_set_tc_acknowledgements<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: SetTCAcknowledgementsRequest<'_>,
        response: SetTCAcknowledgementsResponseBuilder<P>,
    ) -> Result<P, Error> {
        // TODO
        response.error_code(CommissioningErrorEnum::OK)?.end()
    }
}

impl Debug for GenCommHandler<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GenCommHandler")
            .field("dataver", &self.dataver)
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for GenCommHandler<'_> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "GenCommHandler {{ dataver: {} }}", self.dataver);
    }
}
