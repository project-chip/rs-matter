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

//! PASE (Passcode-Authenticated Session Establishment) protocol implementation.
//!
//! This module provides both the initiator (commissioner) and responder (device) sides
//! of the PASE protocol for establishing secure sessions using a shared passcode.

use core::num::NonZeroU8;
use core::ops::Add;
use core::time::Duration;

use spake2p::Spake2pVerifierData;

use crate::dm::clusters::adm_comm::{self};
use crate::dm::endpoints::ROOT_ENDPOINT_ID;
use crate::error::{Error, ErrorCode};
use crate::im::{AttrId, ClusterId, EndptId};
use crate::sc::pase::spake2p::{
    Spake2pVerifierPasswordRef, Spake2pVerifierSaltRef, Spake2pVerifierStrRef,
};
use crate::sc::SessionParameters;
use crate::tlv::{FromTLV, OctetStr, ToTLV};
use crate::transport::exchange::{Exchange, ExchangeId};
use crate::utils::epoch::Epoch;
use crate::utils::init::{init, Init};
use crate::utils::maybe::Maybe;
use crate::MatterMdnsService;

mod initiator;
mod responder;
pub(crate) mod spake2p;

pub use initiator::PaseInitiator;
pub use responder::PaseResponder;

/// Minimal commissioning window timeout in seconds, as per the Matter Core Spec
pub const MIN_COMM_WINDOW_TIMEOUT_SECS: u16 = 3 * 60;
/// Maximal commissioning window timeout in seconds, as per the Matter Core Spec
pub const MAX_COMM_WINDOW_TIMEOUT_SECS: u16 = 15 * 60;

/// The type of commissioning window
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommWindowType {
    /// Basic commissioning window (using passcode)
    Basic,
    /// Enhanced commissioning window (using verifier)
    Enhanced,
}

/// The fabric index of the fabric administrator that opened the commissioning window
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CommWindowOpener {
    /// The fabric index
    pub fab_idx: NonZeroU8,
    /// The vendor ID
    pub vendor_id: u16,
}

/// A PASE commissioning window
pub struct CommWindow {
    /// The mDNS identifier
    mdns_id: u64,
    /// The discriminator
    discriminator: u16,
    /// The verifier data
    pub(crate) verifier: Spake2pVerifierData,
    /// The opener info
    opener: Option<CommWindowOpener>,
    /// The window expiry instant
    window_expiry: Duration,
}

impl CommWindow {
    /// Initialize a commissioning window with a passcode
    ///
    /// # Arguments
    /// - `mdns_id` - The mDNS identifier
    /// - `password` - The passcode
    /// - `discriminator` - The discriminator
    /// - `opener` - The opener info
    /// - `window_expiry` - The window expiry instant
    /// - `rand` - The random number generator
    fn init_with_pw<'a>(
        mdns_id: u64,
        password: Spake2pVerifierPasswordRef<'a>,
        salt: Spake2pVerifierSaltRef<'a>,
        discriminator: u16,
        opener: Option<CommWindowOpener>,
        window_expiry: Duration,
    ) -> impl Init<Self> + 'a {
        init!(Self {
            mdns_id,
            discriminator,
            verifier <- Spake2pVerifierData::init_with_pw(password, salt),
            opener,
            window_expiry,
        })
    }

    /// Initialize a commissioning window with a verifier
    ///
    /// # Arguments
    /// - `verifier` - The verifier bytes
    /// - `salt` - The salt bytes
    /// - `count` - The iteration count
    /// - `discriminator` - The discriminator
    /// - `opener` - The opener info
    /// - `window_expiry` - The window expiry instant
    fn init<'a>(
        mdns_id: u64,
        verifier: Spake2pVerifierStrRef<'a>,
        salt: Spake2pVerifierSaltRef<'a>,
        count: u32,
        discriminator: u16,
        opener: Option<CommWindowOpener>,
        window_expiry: Duration,
    ) -> impl Init<Self> + 'a {
        init!(Self {
            mdns_id,
            discriminator,
            verifier <- Spake2pVerifierData::init(verifier, salt, count),
            opener,
            window_expiry,
        })
    }

    /// Get the type of commissioning window
    pub fn comm_window_type(&self) -> CommWindowType {
        if self.verifier.password.is_some() {
            CommWindowType::Basic
        } else {
            CommWindowType::Enhanced
        }
    }

    /// Get the opener info, if any
    pub fn opener(&self) -> Option<CommWindowOpener> {
        self.opener
    }

    /// Get the mDNS service info
    pub fn mdns_service(&self) -> MatterMdnsService {
        MatterMdnsService::Commissionable {
            id: self.mdns_id,
            discriminator: self.discriminator,
        }
    }
}

/// The PASE state
pub struct Pase {
    /// The opened commissioning window, if any
    comm_window: Maybe<CommWindow>,
    /// The (one and only) PASE session timeout tracker
    /// If there is no active PASE session, this is `None`
    pub(crate) session_timeout: Option<SessionEstTimeout>,
    /// The epoch function
    pub(crate) epoch: Epoch,
}

impl Pase {
    /// Create a new PASE state
    ///
    /// # Arguments
    /// - `epoch` - The epoch function
    #[inline(always)]
    pub const fn new(epoch: Epoch) -> Self {
        Self {
            comm_window: Maybe::none(),
            session_timeout: None,
            epoch,
        }
    }

    /// Return an in-place initializer for the PASE manager
    ///
    /// # Arguments
    /// - `epoch` - The epoch function
    /// - `rand` - The random number generator
    pub fn init(epoch: Epoch) -> impl Init<Self> {
        init!(Self {
            comm_window <- Maybe::init_none(),
            session_timeout: None,
            epoch,
        })
    }

    /// Check if the opened commissioning window has expired, and close it if so.
    ///
    /// This should be called periodically to ensure that the commissioning window state is updated in a timely manner.
    /// Ideally, it should also be called at the beginning of any API that requires the commissioning window to be opened to ensure that the state is up to date.
    pub fn check_comm_window_timeout(
        &mut self,
        notify_mdns: impl FnMut(),
        notify_change: impl FnMut(EndptId, ClusterId, AttrId),
    ) -> Result<bool, Error> {
        let expired = self
            .comm_window
            .as_opt_ref()
            .map(|comm_window| (self.epoch)() > comm_window.window_expiry)
            .unwrap_or(false);

        if expired {
            warn!("PASE Commissioning Window expired, closing");

            self.close_comm_window(notify_mdns, notify_change)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get the opened commissioning window, if any
    pub fn comm_window(&self) -> Option<&CommWindow> {
        self.comm_window.as_opt_ref()
    }

    /// Open a basic commissioning window using a passcode
    ///
    /// # Arguments
    /// - `password` - The passcode
    /// - `discriminator` - The discriminator
    /// - `timeout_secs` - The timeout in seconds of the validity of the window
    /// - `opener` - The opener info
    /// - `mdns_notif` - The mDNS notification callback
    ///
    /// # Returns
    /// - `Ok(())` if the window was opened successfully
    /// - `Err(Error)` if an error occurred
    ///   (i.e. there is another non-expired commissioning window already opened
    ///   or the timeout is invalid)
    #[allow(clippy::too_many_arguments)]
    pub fn open_basic_comm_window(
        &mut self,
        mdns_id: u64,
        salt: Spake2pVerifierSaltRef<'_>,
        password: Spake2pVerifierPasswordRef<'_>,
        discriminator: u16,
        timeout_secs: u16,
        opener: Option<CommWindowOpener>,
        mut notify_mdns: impl FnMut(),
        mut notify_change: impl FnMut(EndptId, ClusterId, AttrId),
    ) -> Result<(), Error> {
        if self.comm_window.is_some() {
            Err(ErrorCode::Busy)?;
        }

        if !(MIN_COMM_WINDOW_TIMEOUT_SECS..=MAX_COMM_WINDOW_TIMEOUT_SECS).contains(&timeout_secs) {
            Err(ErrorCode::InvalidCommand)?;
        }

        let window_expiry = (self.epoch)().add(Duration::from_secs(timeout_secs as _));

        self.comm_window
            .reinit(Maybe::init_some(CommWindow::init_with_pw(
                mdns_id,
                password,
                salt,
                discriminator,
                opener,
                window_expiry,
            )));

        notify_mdns();
        notify_change(
            ROOT_ENDPOINT_ID,
            adm_comm::FULL_CLUSTER.id,
            adm_comm::AttributeId::WindowStatus as _,
        );

        info!("PASE Basic Commissioning Window opened");

        Ok(())
    }

    /// Open an enhanced commissioning window using a verifier
    ///
    /// # Arguments
    /// - `verifier` - The verifier bytes
    /// - `salt` - The salt bytes
    /// - `count` - The iteration count
    /// - `discriminator` - The discriminator
    /// - `timeout_secs` - The timeout in seconds of the validity of the window
    /// - `opener` - The opener info
    /// - `mdns_notif` - The mDNS notification callback
    ///
    /// # Returns
    /// - `Ok(())` if the window was opened successfully
    /// - `Err(Error)` if an error occurred
    ///   (i.e. there is another non-expired commissioning window already opened
    ///   or the timeout is invalid)
    #[allow(clippy::too_many_arguments)]
    pub fn open_comm_window(
        &mut self,
        mdns_id: u64,
        verifier: Spake2pVerifierStrRef<'_>,
        salt: Spake2pVerifierSaltRef<'_>,
        count: u32,
        discriminator: u16,
        timeout_secs: u16,
        opener: Option<CommWindowOpener>,
        mut notify_mdns: impl FnMut(),
        mut notify_change: impl FnMut(EndptId, ClusterId, AttrId),
    ) -> Result<(), Error> {
        if self.comm_window.is_some() {
            Err(ErrorCode::Busy)?;
        }

        if !(MIN_COMM_WINDOW_TIMEOUT_SECS..=MAX_COMM_WINDOW_TIMEOUT_SECS).contains(&timeout_secs) {
            Err(ErrorCode::InvalidCommand)?;
        }

        let window_expiry = (self.epoch)().add(Duration::from_secs(timeout_secs as _));

        self.comm_window.reinit(Maybe::init_some(CommWindow::init(
            mdns_id,
            verifier,
            salt,
            count,
            discriminator,
            opener,
            window_expiry,
        )));

        notify_mdns();
        notify_change(
            ROOT_ENDPOINT_ID,
            adm_comm::FULL_CLUSTER.id,
            adm_comm::AttributeId::WindowStatus as _,
        );

        info!("PASE Commissioning Window opened");

        Ok(())
    }

    /// Close the opened commissioning window, if any
    ///
    /// # Arguments
    /// - `ctx` - The handler context
    ///
    /// # Returns
    /// - `Ok(true)` if a commissioning window was closed
    /// - `Ok(false)` if there was no commissioning window to close
    pub fn close_comm_window(
        &mut self,
        mut notify_mdns: impl FnMut(),
        mut notify_change: impl FnMut(EndptId, ClusterId, AttrId),
    ) -> Result<bool, Error> {
        if self.comm_window.is_some() {
            self.comm_window.clear();

            notify_mdns();
            notify_change(
                ROOT_ENDPOINT_ID,
                adm_comm::FULL_CLUSTER.id,
                adm_comm::AttributeId::WindowStatus as _,
            );

            info!("PASE Commissioning Window closed");

            Ok(true)
        } else {
            warn!("No PASE Commissioning Window to close");

            Ok(false)
        }
    }
}

/// The timeout tracker for a PASE session establishment
const PASE_SESSION_EST_TIMEOUT_SECS: Duration = Duration::from_secs(60);

/// The info string for SPAKE2 session key derivation
pub(crate) const SPAKE2_SESSION_KEYS_INFO: &[u8] = b"SessionKeys";

/// The PASE session establishment timeout tracker
pub(crate) struct SessionEstTimeout {
    /// The session expiry instant
    session_est_expiry: Duration,
    /// The exchange identifier
    pub(crate) exch_id: ExchangeId,
}

impl SessionEstTimeout {
    /// Create a new session establishment timeout tracker
    ///
    /// # Arguments
    /// - `exchange` - The exchange
    /// - `epoch` - The epoch function
    pub(crate) fn new(exchange: &Exchange, epoch: Epoch) -> Self {
        Self {
            session_est_expiry: epoch().add(PASE_SESSION_EST_TIMEOUT_SECS),
            exch_id: exchange.id(),
        }
    }

    /// Check if the session establishment has expired
    ///
    /// # Arguments
    /// - `epoch` - The current epoch
    pub(crate) fn is_sess_expired(&self, epoch: Epoch) -> bool {
        epoch() > self.session_est_expiry
    }
}

/// The PBKDFParamRequest structure
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub(crate) struct PBKDFParamReq<'a> {
    /// The initiator random bytes
    pub initiator_random: OctetStr<'a>,
    /// The initiator session identifier
    pub initiator_ssid: u16,
    /// The passcode identifier
    pub passcode_id: u16,
    /// Whether parameters are included
    pub has_params: bool,
    /// The session parameters, if any
    pub session_parameters: Option<SessionParameters>,
}

/// The PBKDFParamResponse structure
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub(crate) struct PBKDFParamResp<'a> {
    /// The initiator random bytes (echoed back)
    pub initiator_random: OctetStr<'a>,
    /// The responder random bytes
    pub responder_random: OctetStr<'a>,
    /// The responder session identifier
    pub responder_ssid: u16,
    /// The PBKDF2 parameters, if any
    pub params: Option<PBKDFParamRespParams<'a>>,
}

/// The PBKDFParamResponse parameters structure
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub(crate) struct PBKDFParamRespParams<'a> {
    /// The iteration count
    pub iterations: u32,
    /// The salt bytes
    pub salt: OctetStr<'a>,
}

/// TLV structure for Pake1 (sent by initiator)
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub(crate) struct Pake1<'a> {
    /// The pA point (65 bytes, uncompressed P-256)
    pub pa: OctetStr<'a>,
}

/// The Pake1Resp structure (Pake2 message from responder)
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub(crate) struct Pake2<'a> {
    /// The pB bytes
    pub pb: OctetStr<'a>,
    /// The cB bytes
    pub cb: OctetStr<'a>,
}

/// TLV structure for Pake3 (sent by initiator)
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub(crate) struct Pake3<'a> {
    /// The cA confirmation (32 bytes HMAC)
    pub ca: OctetStr<'a>,
}
