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

use either::Either;

use crate::dm::clusters::net_comm::NetworksAccess;
use crate::dm::{Cluster, Context, Dataver, InvokeContext, ReadContext, WriteContext};
use crate::error::{Error, ErrorCode};
use crate::fabric::FabricPersist;
use crate::persist::{Persist, BASIC_INFO_KEY, NETWORKS_KEY};
use crate::tlv::TLVBuilderParent;
use crate::utils::sync::DynBase;
use crate::{with, MatterState};

pub use crate::dm::clusters::decl::general_commissioning::*;

impl CommissioningErrorEnum {
    fn map(result: Result<(), Error>) -> Result<Self, Error> {
        Self::map_result(result).map(Self::ok)
    }

    fn map_result<T>(result: Result<T, Error>) -> Result<Either<T, Self>, Error> {
        match result {
            Ok(value) => Ok(Either::Left(value)),
            Err(err) => match err.code() {
                ErrorCode::Busy | ErrorCode::NocInvalidFabricIndex => {
                    Ok(Either::Right(Self::BusyWithOtherAdmin))
                }
                ErrorCode::GennCommInvalidAuthentication => {
                    Ok(Either::Right(Self::InvalidAuthentication))
                }
                ErrorCode::FailSafeRequired => Ok(Either::Right(Self::NoFailSafe)),
                _ => Err(err),
            },
        }
    }

    fn ok<T>(value: Either<T, Self>) -> Self {
        match value {
            Either::Left(_) => Self::OK,
            Either::Right(code) => code,
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

    /// Execute the provided closure after checking that the failsafe is armed for the
    /// fabric of this session.
    ///
    /// If the check fail, an appropriate error is returned.
    pub(crate) fn with_armed_failsafe<F, T>(ctx: impl Context, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut MatterState, &mut dyn FnMut()) -> Result<T, Error>,
    {
        Self::with_armed_failsafe_ex(ctx, f)
    }

    /// Execute the provided closure after checking that the failsafe is armed for the
    /// fabric of this session.
    ///
    /// If the check fail, an appropriate error is returned.
    pub(crate) fn with_armed_failsafe_ex<F, T, E>(ctx: impl Context, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut MatterState, &mut dyn FnMut()) -> Result<T, E>,
        E: From<Error>,
    {
        let mut notify_mdns = || ctx.exchange().matter().notify_mdns();

        ctx.exchange().with_state_ex(|state| {
            let sess = ctx.exchange().id().session(&mut state.sessions);

            state
                .failsafe
                .check_armed(sess.get_session_mode())
                .map_err(|err| match err.code() {
                    ErrorCode::NocInvalidFabricIndex => {
                        Error::new(ErrorCode::GennCommInvalidAuthentication)
                    }
                    _ => err,
                })?;

            f(state, &mut notify_mdns)
        })
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
        ctx: impl ReadContext,
    ) -> Result<RegulatoryLocationTypeEnum, Error> {
        ctx.exchange()
            .with_state(|state| Ok(state.basic_info_settings.location_type))
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
        let status = CommissioningErrorEnum::map(ctx.exchange().with_state(|state| {
            let sess = ctx.exchange().id().session(&mut state.sessions);

            state.failsafe.arm(
                request.expiry_length_seconds()?,
                request.breadcrumb()?,
                sess.get_session_mode(),
                &mut state.pase,
            )
        }))?;

        response.error_code(status)?.debug_text("")?.end()
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

        let status = CommissioningErrorEnum::map(ctx.exchange().with_state(|state| {
            state.basic_info_settings.set_location(country_code);
            state.basic_info_settings.location_type = location_type;

            state.failsafe.set_breadcrumb(breadcrumb);

            persist.store_tlv(BASIC_INFO_KEY, &state.basic_info_settings)?;

            Ok(())
        }))?;

        persist.run()?;

        response.error_code(status)?.debug_text("")?.end()
    }

    fn handle_commissioning_complete<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        response: CommissioningCompleteResponseBuilder<P>,
    ) -> Result<P, Error> {
        let notify_change =
            |endpt_id, clust_id, attr_id| ctx.notify_attribute_changed(endpt_id, clust_id, attr_id);

        let mut persist = FabricPersist::new(ctx.kv());

        let status =
            CommissioningErrorEnum::map(Self::with_armed_failsafe(&ctx, |state, notify_mdns| {
                let sess = ctx.exchange().id().session(&mut state.sessions);

                let fabric = state
                    .failsafe
                    .disarm(sess.get_session_mode(), &mut state.fabrics)?;

                // As per section 5.5 of the Matter Core Spec V1.3 we have to terminate the PASE session
                // upon completion of commissioning
                state.pase.close_comm_window(notify_mdns, notify_change)?;

                // Finally, persist the fabric and the network settings, prior to sending the other party a "success" status
                persist.store(fabric)?;
                ctx.networks().access(|networks| {
                    persist
                        .persist_mut()
                        .store(NETWORKS_KEY, |buf| networks.save(buf))
                })?;

                info!("Commissioning complete, fabric and network settings persisted");

                Ok(())
            }))?;

        persist.run()?;

        response.error_code(status)?.debug_text("")?.end()
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
