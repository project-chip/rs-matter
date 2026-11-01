/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! The Secure Channel protocol: PASE and CASE, as initiator and responder,
//! Check-In and the Message Counter Synchronization Protocol.
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(async_fn_in_trait)]
#![allow(unknown_lints)]
#![allow(clippy::uninlined_format_args)]
#![recursion_limit = "1024"]
// `cargo llvm-cov` sets `coverage_nightly` when it runs on a nightly toolchain;
// the test modules are then excluded from the coverage report
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use core::future::Future;
use core::mem::MaybeUninit;

use crate::crypto::Crypto;
use crate::dm::AttrChangeNotifier;
use crate::error::{Error, ErrorCode};
use crate::im::IM_REVISION;
use crate::transport::exchange::Exchange;
use crate::transport::mrp;
use crate::utils::init::InitMaybeUninit;
use crate::utils::storage::ReadBuf;
use crate::utils::sync::{MaybeSend, MaybeSendSync};
use case::CaseResponder;
use pase::PaseResponder;

#[cfg(feature = "alloc")]
extern crate alloc;

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

pub mod busy;
pub mod case;
pub mod checkin;
mod host;
mod initiate;
#[cfg(feature = "groups")]
pub mod mcsp;
pub mod pase;

// The dependencies, under the names the code uses for them
use rs_matter_cert as cert;
use rs_matter_crypto as crypto;
use rs_matter_dm_core as dm;
#[cfg(feature = "case-resumption")]
use rs_matter_dm_core::persist;
use rs_matter_node_core::{fabric, failsafe};
use rs_matter_pairing as pairing;
use rs_matter_tlv as tlv;
use rs_matter_transport as transport;
use rs_matter_transport::proto::im;
use rs_matter_utils as utils;
use rs_matter_utils::error;

pub use host::{ScHost, ScState};
pub use initiate::ExchangeInitiator;
pub use rs_matter_transport::proto::sc::*;

#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! alloc {
    ($val:expr) => {
        alloc::boxed::Box::new($val)
    };
}

#[cfg(not(feature = "alloc"))]
#[macro_export]
macro_rules! alloc {
    ($val:expr) => {
        $val
    };
}

pub async fn complete_with_status(
    exchange: &mut Exchange<'_>,
    status_code: SCStatusCodes,
    payload: &[u8],
) -> Result<(), Error> {
    exchange
        .send_with(|_, wb| sc_write(wb, status_code, payload))
        .await
}

/// The session parameters this node advertises in the CASE / PASE handshake
/// messages it sends, as initiator or responder.
///
/// Must not be called with the Matter state borrowed, as it reads the ICD
/// advertisement from it.
pub(crate) fn local_session_parameters(matter: &impl ScHost) -> SessionParameters {
    let dev_det = matter.dev_det();
    let icd = matter.icd_advertisement();

    SessionParameters {
        sii: mrp::advertised_sii(dev_det, icd),
        sai: Some(mrp::advertised_sai(dev_det)),
        sat: icd.map(|icd| icd.active_threshold_ms),
        dm_revision: Some(dev_det.data_model_revision),
        im_revision: Some(IM_REVISION as u16),
        spec_version: Some(dev_det.specification_version),
        max_paths_per_invoke: Some(dev_det.max_paths_per_invoke),
    }
}

/// An extension point for the [`SecureChannel`] handler, letting a controller
/// react to the Secure Channel messages that the accessory role only drops:
/// incoming Check-In notifications and unsolicited Message Counter Sync
/// responses.
///
/// Both methods default to dropping the message (matching the accessory role),
/// so `()` is a valid no-op handler. A controller overrides the verb(s) it cares
/// about; the handler receives the [`Exchange`] to read the message from.
pub trait AsyncScHandler: MaybeSendSync {
    /// Handle an incoming Check-In message (Secure Channel opcode `CheckIn`).
    fn check_in(
        &self,
        _exchange: Exchange<'_>,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        warn!("Check-In: Unexpected Check-In message received; dropping");

        core::future::ready(Ok(()))
    }

    /// Handle an unsolicited Message Counter Sync response
    /// (opcode `MsgCounterSyncResp`).
    fn mcsp_resp(
        &self,
        _exchange: Exchange<'_>,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        warn!("MCSP: Unsolicited MsgCounterSyncResp received; dropping");

        core::future::ready(Ok(()))
    }
}

impl AsyncScHandler for () {}

impl<T> AsyncScHandler for &T
where
    T: AsyncScHandler,
{
    async fn check_in(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        T::check_in(self, exchange).await
    }

    async fn mcsp_resp(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        T::mcsp_resp(self, exchange).await
    }
}

/// Handle messages related to the Secure Channel
pub struct SecureChannel<'a, M, C, N, H = ()> {
    matter: &'a M,
    crypto: C,
    notify: N,
    handler: H,
}

impl<'a, M: ScHost, C: Crypto, N: AttrChangeNotifier> SecureChannel<'a, M, C, N, ()> {
    #[inline(always)]
    pub const fn new(matter: &'a M, crypto: C, notify: N) -> Self {
        Self {
            matter,
            crypto,
            notify,
            handler: (),
        }
    }
}

impl<'a, M: ScHost, C: Crypto, N: AttrChangeNotifier, H: AsyncScHandler>
    SecureChannel<'a, M, C, N, H>
{
    /// Like [`new`](Self::new) but with a controller-side [`AsyncScHandler`] that
    /// receives incoming Check-In / MCSP-response messages instead of dropping them.
    #[inline(always)]
    pub const fn new_with_handler(matter: &'a M, crypto: C, notify: N, handler: H) -> Self {
        Self {
            matter,
            crypto,
            notify,
            handler,
        }
    }

    pub async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        if exchange.rx().is_err() {
            exchange.recv_fetch().await?;
        }

        let meta = exchange.rx()?.meta();
        if meta.proto_id != PROTO_ID_SECURE_CHANNEL {
            Err(ErrorCode::InvalidProto)?;
        }

        match meta.opcode()? {
            OpCode::PBKDFParamRequest => {
                let mut pase = MaybeUninit::uninit(); // TODO LARGE BUFFER
                pase.init_with(PaseResponder::init(self.matter, &self.crypto, &self.notify))
                    .handle(exchange)
                    .await
            }
            OpCode::CASESigma1 => {
                let mut case = MaybeUninit::uninit(); // TODO LARGE BUFFER
                case.init_with(CaseResponder::init(self.matter, &self.crypto))
                    .handle(exchange)
                    .await
            }
            #[cfg(feature = "groups")]
            OpCode::MsgCounterSyncReq => {
                // The receive path has already checked this landed on a
                // group session with a destination matching one of our
                // fabric node ids.
                mcsp::respond(self.matter, &self.crypto, exchange).await
            }
            OpCode::MsgCounterSyncResp => {
                // Unsolicited in the accessory role; a controller may hook it.
                self.handler.mcsp_resp(exchange).await
            }
            OpCode::CheckIn => {
                // Unexpected in the accessory role (we are a Check-In *server*);
                // a controller may hook it to receive Check-In notifications.
                self.handler.check_in(exchange).await
            }
            opcode => {
                error!("Invalid opcode: {:?}", opcode);
                Err(ErrorCode::InvalidOpcode.into())
            }
        }
    }
}

/// Check the opcode of the received message like [`check_opcode`], additionally
/// reporting a mismatch to the peer with a `StatusReport(FAILURE, INVALID_PARAMETER)`
/// before bailing out with an error.
async fn expect_opcode(exchange: &mut Exchange<'_>, opcode: OpCode) -> Result<(), Error> {
    let result = check_opcode(exchange, opcode);

    if let Err(err) = result {
        if !exchange.rx()?.meta().is_sc_status() {
            // Best-effort: the handshake has failed regardless of whether the
            // report makes it to the peer, and the opcode mismatch is the more
            // informative error to propagate.
            let _ = complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await;
        }

        Err(err)
    } else {
        Ok(())
    }
}

/// Check that the opcode of the received message matches the expected one.
/// Logs an error if that's not the case, and if the opcode is `StatusReport`,
/// it also logs the details of the status report.
fn check_opcode(exchange: &Exchange<'_>, opcode: OpCode) -> Result<(), Error> {
    let meta = exchange.rx()?.meta();
    let their_opcode = meta.opcode::<OpCode>()?;

    if their_opcode == opcode {
        Ok(())
    } else {
        error!("Invalid opcode: {:?}, expected: {:?}", their_opcode, opcode);

        if matches!(their_opcode, OpCode::StatusReport) {
            let mut rb = ReadBuf::new(exchange.rx()?.payload());

            // Show the status code details in the log
            match StatusReport::read(&mut rb) {
                Ok(status_report) => error!("Status Report: {:?}", status_report),
                Err(e) => error!("Failed to parse Status Report: {:?}", e),
            }
        }

        Err(ErrorCode::Invalid.into())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::im::IM_REVISION;
    use crate::transport::mrp::MRP_BASE_RETRY_INTERVAL_MS;
    use crate::transport::{Transport, TransportHost};
    use crate::ScHost;
    use rs_matter_node_core::basic_info::{
        BasicInfoConfig, DEFAULT_DATA_MODEL_REVISION, DEFAULT_MATTER_SPEC_VERSION,
        DEFAULT_MAX_PATHS_PER_INVOKE,
    };
    use rs_matter_node_core::icd::{IcdAdvertisement, IcdOperatingMode};
    use rs_matter_node_core::test_device::TEST_DEV_DET;

    /// A node with what `local_session_parameters` reads from it.
    struct TestHost {
        transport: Transport,
        dev_det: &'static BasicInfoConfig<'static>,
        icd: Option<IcdAdvertisement>,
    }

    impl TestHost {
        fn new(dev_det: &'static BasicInfoConfig<'static>, icd: Option<IcdAdvertisement>) -> Self {
            Self {
                transport: Transport::new(None),
                dev_det,
                icd,
            }
        }
    }

    impl TransportHost for TestHost {
        fn transport(&self) -> &Transport {
            &self.transport
        }

        fn with_fabrics(
            &self,
            _f: &mut dyn FnMut(&mut crate::transport::session::Sessions, &crate::fabric::Fabrics),
        ) {
            unimplemented!()
        }

        fn mdns_services(
            &self,
            _f: &mut dyn FnMut(
                crate::transport::network::MatterLocalService,
            ) -> Result<(), crate::error::Error>,
        ) -> Result<(), crate::error::Error> {
            unimplemented!()
        }

        fn dev_det(&self) -> &BasicInfoConfig<'_> {
            self.dev_det
        }

        fn port(&self) -> u16 {
            0
        }

        fn icd_advertisement(&self) -> Option<IcdAdvertisement> {
            self.icd
        }

        #[cfg(feature = "groups")]
        fn groupcast_testing(&self) -> &crate::transport::groupcast::TestingBridge {
            unimplemented!()
        }
    }

    impl ScHost for TestHost {
        fn with_sc_state<F, R>(&self, _f: F) -> R
        where
            F: FnOnce(&mut crate::ScState) -> R,
        {
            unimplemented!()
        }
    }

    /// The session parameters a node sends always carry the fields the spec
    /// requires: the revisions, the max paths per invoke and - because those
    /// follow it - the active interval, defaulted when none is configured.
    #[test]
    fn local_session_parameters_carry_the_required_fields() {
        let params = crate::local_session_parameters(&TestHost::new(&TEST_DEV_DET, None));

        assert_eq!(params.sii, None);
        assert_eq!(params.sai, Some(MRP_BASE_RETRY_INTERVAL_MS));
        assert_eq!(params.sat, None);
        assert_eq!(params.dm_revision, Some(DEFAULT_DATA_MODEL_REVISION));
        assert_eq!(params.im_revision, Some(IM_REVISION as u16));
        assert_eq!(params.spec_version, Some(DEFAULT_MATTER_SPEC_VERSION));
        assert_eq!(
            params.max_paths_per_invoke,
            Some(DEFAULT_MAX_PATHS_PER_INVOKE)
        );
    }

    /// An ICD advertises the same intervals as over mDNS - the SII capped while
    /// a LIT-capable device operates as a SIT, its slow poll when none is
    /// configured - and its Active Mode Threshold as the SAT.
    #[test]
    fn local_session_parameters_of_an_icd() {
        const DEV_DET: BasicInfoConfig<'static> = BasicInfoConfig {
            sai: Some(700),
            sii: Some(300_000),
            ..TEST_DEV_DET
        };

        let adv = |operating_mode, slow_poll_ms| IcdAdvertisement {
            active_threshold_ms: 5000,
            slow_poll_ms,
            fast_poll_ms: 700,
            operating_mode,
            idle_mode_duration_s: 300,
        };

        let params = crate::local_session_parameters(&TestHost::new(
            &DEV_DET,
            Some(adv(Some(IcdOperatingMode::Sit), 15_000)),
        ));
        assert_eq!(
            (params.sai, params.sii, params.sat),
            (Some(700), Some(15_000), Some(5000))
        );

        let params = crate::local_session_parameters(&TestHost::new(
            &DEV_DET,
            Some(adv(Some(IcdOperatingMode::Lit), 300_000)),
        ));
        assert_eq!((params.sii, params.sat), (Some(300_000), Some(5000)));

        // A SIT-only ICD advertises its configured SII.
        let params =
            crate::local_session_parameters(&TestHost::new(&DEV_DET, Some(adv(None, 15_000))));
        assert_eq!((params.sii, params.sat), (Some(300_000), Some(5000)));

        // An ICD with no configured SII advertises its slow poll.
        let params =
            crate::local_session_parameters(&TestHost::new(&TEST_DEV_DET, Some(adv(None, 15_000))));
        assert_eq!(params.sii, Some(15_000));
    }
}
