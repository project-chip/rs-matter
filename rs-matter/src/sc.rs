/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

use core::borrow::Borrow;
use core::future::Future;
use core::mem::MaybeUninit;

use num_derive::FromPrimitive;

use crate::crypto::Crypto;
use crate::dm::AttrChangeNotifier;
use crate::error::{Error, ErrorCode};
use crate::respond::ExchangeHandler;
use crate::tlv::{FromTLV, ToTLV};
use crate::transport::exchange::{Exchange, MessageMeta};
use crate::utils::init::InitMaybeUninit;
use crate::utils::storage::{ReadBuf, WriteBuf};

use case::CaseResponder;
use pase::PaseResponder;

pub mod busy;
pub mod case;
pub mod checkin;
#[cfg(feature = "groups")]
pub mod mcsp;
pub mod pase;

/* Interaction Model ID as per the Matter Spec */
pub const PROTO_ID_SECURE_CHANNEL: u16 = 0x00;

#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OpCode {
    MsgCounterSyncReq = 0x00,
    MsgCounterSyncResp = 0x01,
    MRPStandAloneAck = 0x10,
    PBKDFParamRequest = 0x20,
    PBKDFParamResponse = 0x21,
    PASEPake1 = 0x22,
    PASEPake2 = 0x23,
    PASEPake3 = 0x24,
    CASESigma1 = 0x30,
    CASESigma2 = 0x31,
    CASESigma3 = 0x32,
    CASESigma2Resume = 0x33,
    StatusReport = 0x40,
    CheckIn = 0x50,
}

impl OpCode {
    pub fn meta(&self) -> MessageMeta {
        MessageMeta {
            proto_id: PROTO_ID_SECURE_CHANNEL,
            proto_opcode: *self as u8,
            // Check-In is a fire-and-forget notification sent without MRP, like
            // the standalone ack.
            reliable: !matches!(self, Self::MRPStandAloneAck | Self::CheckIn),
        }
    }

    pub fn is_tlv(&self) -> bool {
        !matches!(
            self,
            Self::MRPStandAloneAck
                | Self::StatusReport
                | Self::MsgCounterSyncReq
                | Self::MsgCounterSyncResp
                | Self::CheckIn
        )
    }
}

impl From<OpCode> for MessageMeta {
    fn from(op: OpCode) -> Self {
        op.meta()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SCStatusCodes {
    SessionEstablishmentSuccess = 0,
    NoSharedTrustRoots = 1,
    InvalidParameter = 2,
    CloseSession = 3,
    Busy = 4,
    SessionNotFound = 5,
}

impl SCStatusCodes {
    pub fn reliable(&self) -> bool {
        // CloseSession, Busy and SessionNotFound are sent without the R flag raised
        !matches!(
            self,
            SCStatusCodes::CloseSession | SCStatusCodes::Busy | SCStatusCodes::SessionNotFound
        )
    }

    pub fn as_report<'a>(&self, payload: &'a [u8]) -> StatusReport<'a> {
        let general_code = match self {
            SCStatusCodes::SessionEstablishmentSuccess => GeneralCode::Success,
            SCStatusCodes::CloseSession => GeneralCode::Success,
            SCStatusCodes::Busy => GeneralCode::Busy,
            SCStatusCodes::InvalidParameter
            | SCStatusCodes::NoSharedTrustRoots
            | SCStatusCodes::SessionNotFound => GeneralCode::Failure,
        };

        StatusReport {
            general_code,
            proto_id: PROTO_ID_SECURE_CHANNEL as u32,
            proto_code: *self as u16,
            proto_data: payload,
        }
    }
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

pub fn sc_write(
    wb: &mut WriteBuf,
    status_code: SCStatusCodes,
    payload: &[u8],
) -> Result<Option<MessageMeta>, Error> {
    status_code.as_report(payload).write(wb)?;

    Ok(Some(
        OpCode::StatusReport.meta().reliable(status_code.reliable()),
    ))
}

#[allow(dead_code)]
#[derive(FromPrimitive, PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GeneralCode {
    Success = 0,
    Failure = 1,
    BadPrecondition = 2,
    OutOfRange = 3,
    BadRequest = 4,
    Unsupported = 5,
    Unexpected = 6,
    ResourceExhausted = 7,
    Busy = 8,
    Timeout = 9,
    Continue = 10,
    Aborted = 11,
    InvalidArgument = 12,
    NotFound = 13,
    AlreadyExists = 14,
    PermissionDenied = 15,
    DataLoss = 16,
}

/// Represents the session parameters
/// that might present in a "PBKDFParamRequest"/"PBKDFParamResponse" or "CASE-Sigma1"/"CASE-Sigma2" message
#[derive(Default, Clone, FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1)]
pub(crate) struct SessionParameters {
    /// Session Idle Interval
    pub(crate) sii: Option<u32>,
    /// Session Active Interval
    pub(crate) sai: Option<u32>,
    /// Session Active Threshold
    pub(crate) sat: Option<u16>,
    /// Data Model Revision
    pub(crate) dm_revision: Option<u16>,
    /// Interaction Model Revision
    pub(crate) im_revision: Option<u16>,
    /// Specification Version
    pub(crate) spec_version: Option<u32>,
    /// Maximum number of paths per invoke
    pub(crate) max_paths_per_invoke: Option<u16>,
}

/// Represents a Status Report message, as per "Appendix D: Status Report Messages" of the Matter Spec.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StatusReport<'a> {
    pub general_code: GeneralCode,
    pub proto_id: u32,
    pub proto_code: u16,
    pub proto_data: &'a [u8],
}

impl<'a> StatusReport<'a> {
    pub fn read<T>(pb: &'a mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        Ok(Self {
            general_code: num::FromPrimitive::from_u16(pb.le_u16()?)
                .ok_or(ErrorCode::InvalidOpcode)?,
            proto_id: pb.le_u32()?,
            proto_code: pb.le_u16()?,
            proto_data: pb.as_slice(),
        })
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        wb.le_u16(self.general_code as u16)?;
        wb.le_u32(self.proto_id)?;
        wb.le_u16(self.proto_code)?;
        wb.copy_from_slice(self.proto_data)?;

        Ok(())
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
pub trait AsyncScHandler {
    /// Handle an incoming Check-In message (Secure Channel opcode `CheckIn`).
    async fn check_in(&self, _exchange: Exchange<'_>) -> Result<(), Error> {
        warn!("Check-In: Unexpected Check-In message received; dropping");
        Ok(())
    }

    /// Handle an unsolicited Message Counter Sync response
    /// (opcode `MsgCounterSyncResp`).
    async fn mcsp_resp(&self, _exchange: Exchange<'_>) -> Result<(), Error> {
        warn!("MCSP: Unsolicited MsgCounterSyncResp received; dropping");
        Ok(())
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
pub struct SecureChannel<'a, C, H = ()> {
    crypto: C,
    notify: &'a dyn AttrChangeNotifier,
    handler: H,
}

impl<'a, C: Crypto> SecureChannel<'a, C, ()> {
    #[inline(always)]
    pub const fn new(crypto: C, notify: &'a dyn AttrChangeNotifier) -> Self {
        Self {
            crypto,
            notify,
            handler: (),
        }
    }
}

impl<'a, C: Crypto, H: AsyncScHandler> SecureChannel<'a, C, H> {
    /// Like [`new`](Self::new) but with a controller-side [`AsyncScHandler`] that
    /// receives incoming Check-In / MCSP-response messages instead of dropping them.
    #[inline(always)]
    pub const fn new_with_handler(
        crypto: C,
        notify: &'a dyn AttrChangeNotifier,
        handler: H,
    ) -> Self {
        Self {
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
                pase.init_with(PaseResponder::init(&self.crypto, self.notify))
                    .handle(exchange)
                    .await
            }
            OpCode::CASESigma1 => {
                let mut case = MaybeUninit::uninit(); // TODO LARGE BUFFER
                case.init_with(CaseResponder::init(&self.crypto))
                    .handle(exchange)
                    .await
            }
            #[cfg(feature = "groups")]
            OpCode::MsgCounterSyncReq => {
                // The receive path has already checked this landed on a
                // group session with a destination matching one of our
                // fabric node ids.
                mcsp::respond(&self.crypto, exchange).await
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

impl<C: Crypto, H: AsyncScHandler> ExchangeHandler for SecureChannel<'_, C, H> {
    fn handle(&self, exchange: Exchange<'_>) -> impl Future<Output = Result<(), Error>> {
        SecureChannel::handle(self, exchange)
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
