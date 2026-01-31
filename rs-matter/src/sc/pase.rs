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

use core::num::NonZeroU8;
use core::ops::Add;
use core::time::Duration;

use spake2p::{Spake2P, VerifierData, VERIFIER_SALT_LEN};

use crate::crypto::{
    CanonEcPointRef, Crypto, CryptoSensitive, HmacHashRef, Kdf, AEAD_CANON_KEY_LEN,
    EC_POINT_ZEROED, HMAC_HASH_ZEROED,
};
use crate::dm::clusters::adm_comm::{self};
use crate::dm::endpoints::ROOT_ENDPOINT_ID;
use crate::dm::{BasicContext, BasicContextInstance};
use crate::error::{Error, ErrorCode};
use crate::sc::pase::spake2p::{VerifierPasswordRef, VerifierSalt, VerifierStrRef};
use crate::sc::{check_opcode, complete_with_status, OpCode, SessionParameters};
use crate::tlv::{get_root_node_struct, FromTLV, OctetStr, TLVElement, TagType, ToTLV};
use crate::transport::exchange::{Exchange, ExchangeId};
use crate::transport::session::{ReservedSession, SessionMode};
use crate::utils::epoch::Epoch;
use crate::utils::init::{init, Init};
use crate::utils::maybe::Maybe;
use crate::utils::rand::Rand;
use crate::MatterMdnsService;

use super::SCStatusCodes;

pub(crate) mod spake2p;

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
    verifier: VerifierData,
    /// The opener info
    opener: Option<CommWindowOpener>,
    /// The window expiry instant
    window_expiry: Duration,
}

impl CommWindow {
    /// Initialize a commissioning window with a passcode
    ///
    /// # Arguments
    /// - `password` - The passcode
    /// - `discriminator` - The discriminator
    /// - `opener` - The opener info
    /// - `window_expiry` - The window expiry instant
    /// - `rand` - The random number generator
    fn init_with_pw<'a>(
        password: VerifierPasswordRef<'a>,
        discriminator: u16,
        opener: Option<CommWindowOpener>,
        window_expiry: Duration,
        rand: Rand,
    ) -> impl Init<Self> + 'a {
        init!(Self {
            mdns_id: Self::mdns_id(rand),
            discriminator,
            verifier <- VerifierData::init_with_pw(password, rand),
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
        verifier: VerifierStrRef<'a>,
        salt: &'a VerifierSalt,
        count: u32,
        discriminator: u16,
        opener: Option<CommWindowOpener>,
        window_expiry: Duration,
        rand: Rand,
    ) -> impl Init<Self> + 'a {
        init!(Self {
            mdns_id: Self::mdns_id(rand),
            discriminator,
            verifier <- VerifierData::init(verifier, salt, count),
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

    /// Generate a random mDNS identifier
    ///
    /// # Arguments
    /// - `rand` - The random number generator
    /// - Returns - A random u64 identifier
    fn mdns_id(rand: Rand) -> u64 {
        let mut buf = [0; 8];
        (rand)(&mut buf);
        u64::from_ne_bytes(buf)
    }
}

/// The PASE manager
pub struct PaseMgr {
    /// The opened commissioning window, if any
    comm_window: Maybe<CommWindow>,
    /// The (one and only) PASE session timeout tracker
    /// If there is no active PASE session, this is `None`
    session_timeout: Option<SessionEstTimeout>,
    /// The epoch function
    epoch: Epoch,
    /// The random number generator
    rand: Rand,
}

impl PaseMgr {
    /// Create a new PASE manager
    ///
    /// # Arguments
    /// - `epoch` - The epoch function
    /// - `rand` - The random number generator
    #[inline(always)]
    pub const fn new(epoch: Epoch, rand: Rand) -> Self {
        Self {
            comm_window: Maybe::none(),
            session_timeout: None,
            epoch,
            rand,
        }
    }

    /// Return an in-place initializer for the PASE manager
    ///
    /// # Arguments
    /// - `epoch` - The epoch function
    /// - `rand` - The random number generator
    pub fn init(epoch: Epoch, rand: Rand) -> impl Init<Self> {
        init!(Self {
            comm_window <- Maybe::init_none(),
            session_timeout: None,
            epoch,
            rand,
        })
    }

    pub fn comm_window(&mut self, ctx: impl BasicContext) -> Result<Option<&CommWindow>, Error> {
        let expired = self
            .comm_window
            .as_opt_ref()
            .map(|comm_window| (self.epoch)() > comm_window.window_expiry)
            .unwrap_or(false);

        if expired {
            warn!("PASE Commissioning Window expired, closing");

            self.close_comm_window(ctx)?;

            Ok(None)
        } else {
            Ok(self.comm_window.as_opt_ref())
        }
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
    pub fn open_basic_comm_window(
        &mut self,
        password: VerifierPasswordRef<'_>,
        discriminator: u16,
        timeout_secs: u16,
        opener: Option<CommWindowOpener>,
        ctx: impl BasicContext,
    ) -> Result<(), Error> {
        if self.comm_window(&ctx)?.is_some() {
            Err(ErrorCode::Busy)?;
        }

        if !(MIN_COMM_WINDOW_TIMEOUT_SECS..=MAX_COMM_WINDOW_TIMEOUT_SECS).contains(&timeout_secs) {
            Err(ErrorCode::InvalidCommand)?;
        }

        let window_expiry = (self.epoch)().add(Duration::from_secs(timeout_secs as _));

        self.comm_window
            .reinit(Maybe::init_some(CommWindow::init_with_pw(
                password,
                discriminator,
                opener,
                window_expiry,
                self.rand,
            )));

        ctx.matter().notify_mdns();

        ctx.notify_attribute_changed(
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
        verifier: VerifierStrRef<'_>,
        salt: &VerifierSalt,
        count: u32,
        discriminator: u16,
        timeout_secs: u16,
        opener: Option<CommWindowOpener>,
        ctx: impl BasicContext,
    ) -> Result<(), Error> {
        if self.comm_window(&ctx)?.is_some() {
            Err(ErrorCode::Busy)?;
        }

        if !(MIN_COMM_WINDOW_TIMEOUT_SECS..=MAX_COMM_WINDOW_TIMEOUT_SECS).contains(&timeout_secs) {
            Err(ErrorCode::InvalidCommand)?;
        }

        let window_expiry = (self.epoch)().add(Duration::from_secs(timeout_secs as _));

        self.comm_window.reinit(Maybe::init_some(CommWindow::init(
            verifier,
            salt,
            count,
            discriminator,
            opener,
            window_expiry,
            self.rand,
        )));

        ctx.matter().notify_mdns();

        ctx.notify_attribute_changed(
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
    pub fn close_comm_window(&mut self, ctx: impl BasicContext) -> Result<bool, Error> {
        if self.comm_window.is_some() {
            self.comm_window.clear();
            ctx.matter().notify_mdns();

            ctx.notify_attribute_changed(
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
const SPAKE2_SESSION_KEYS_INFO: &[u8] = b"SessionKeys";

/// The PASE session establishment timeout tracker
struct SessionEstTimeout {
    /// The session expiry instant
    session_est_expiry: Duration,
    /// The exchange identifier
    exch_id: ExchangeId,
}

impl SessionEstTimeout {
    /// Create a new session establishment timeout tracker
    ///
    /// # Arguments
    /// - `exchange` - The exchange
    /// - `epoch` - The epoch function
    fn new(exchange: &Exchange, epoch: Epoch) -> Self {
        Self {
            session_est_expiry: epoch().add(PASE_SESSION_EST_TIMEOUT_SECS),
            exch_id: exchange.id(),
        }
    }

    /// Check if the session establishment has expired
    ///
    /// # Arguments
    /// - `epoch` - The current epoch
    fn is_sess_expired(&self, epoch: Epoch) -> bool {
        epoch() > self.session_est_expiry
    }
}

/// The PBKDFParamRequest structure
#[derive(FromTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
struct PBKDFParamReq<'a> {
    /// The initiator random bytes
    initiator_random: OctetStr<'a>,
    /// The initiator session identifier
    initiator_ssid: u16,
    /// The passcode identifier
    passcode_id: u16,
    /// Whether parameters are included
    has_params: bool,
    /// The session parameters, if any
    session_parameters: Option<SessionParameters>,
}

/// The PBKDFParamResponse structure
#[derive(ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1)]
struct PBKDFParamResp<'a> {
    /// The initiator random bytes
    init_random: OctetStr<'a>,
    /// Our random bytes
    our_random: OctetStr<'a>,
    /// Our local session identifier
    local_sessid: u16,
    /// The PBKDF2 parameters, if any
    params: Option<PBKDFParamRespParams<'a>>,
}

/// The PBKDFParamResponse parameters structure
#[derive(ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1)]
struct PBKDFParamRespParams<'a> {
    /// The iteration count
    count: u32,
    /// The salt bytes
    salt: OctetStr<'a>,
}

/// The Pake1Resp structure
#[derive(ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1)]
struct Pake1Resp<'a> {
    /// The pB bytes
    pb: OctetStr<'a>,
    /// The cB bytes
    cb: OctetStr<'a>,
}

/// The PASE PAKE handler
pub struct Pase<'a, C: Crypto> {
    spake2p: Spake2P<'a, C>,
}

impl<'a, C: Crypto> Pase<'a, C> {
    /// Create a new PASE PAKE handler
    pub const fn new(crypto: &'a C) -> Self {
        // TODO: Can any PBKDF2 calculation be pre-computed here
        Self {
            spake2p: Spake2P::new(crypto),
        }
    }

    pub fn init(crypto: &'a C) -> impl Init<Self> {
        init!(Self {
            spake2p <- Spake2P::init(crypto),
        })
    }

    /// Handle a PASE PAKE exchange, where the other peer is the exchange initiator
    ///
    /// # Arguments
    /// - `exchange` - The exchange
    pub async fn handle(&mut self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let session = ReservedSession::reserve(self.spake2p.crypto, exchange.matter()).await?;

        if !self.update_session_timeout(exchange, true).await? {
            return Ok(());
        }

        self.handle_pbkdfparamrequest(exchange).await?;

        exchange.recv_fetch().await?;

        if !self.update_session_timeout(exchange, false).await? {
            return Ok(());
        }

        self.handle_pasepake1(exchange).await?;

        exchange.recv_fetch().await?;

        if !self.update_session_timeout(exchange, false).await? {
            return Ok(());
        }

        self.handle_pasepake3(exchange, session).await?;

        exchange.acknowledge().await?;
        exchange.matter().notify_persist();

        self.clear_session_timeout(exchange);

        Ok(())
    }

    /// Handle a PBKDFParamRequest message
    ///
    /// # Arguments
    /// - `exchange` - The exchange
    async fn handle_pbkdfparamrequest(&mut self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        check_opcode(exchange, OpCode::PBKDFParamRequest)?;

        let rx = exchange.rx()?;

        let mut salt = [0; VERIFIER_SALT_LEN];
        let mut count = 0;

        let ctx = BasicContextInstance::new(exchange.matter(), exchange.matter());
        let has_comm_window = {
            let matter = exchange.matter();
            let mut pase = matter.pase_mgr.borrow_mut();

            if let Some(comm_window) = pase.comm_window(&ctx)? {
                salt.copy_from_slice(&comm_window.verifier.salt);
                count = comm_window.verifier.count;

                true
            } else {
                false
            }
        };

        if has_comm_window {
            let mut our_random = [0; 32];
            let mut initiator_random = [0; 32];

            let resp = {
                let a = PBKDFParamReq::from_tlv(&TLVElement::new(rx.payload()))?;
                if a.passcode_id != 0 {
                    error!("Can't yet handle passcode_id != 0");
                    Err(ErrorCode::Invalid)?;
                }

                (exchange.matter().pase_mgr.borrow().rand)(&mut our_random);

                let local_sessid = exchange
                    .matter()
                    .transport_mgr
                    .session_mgr
                    .borrow_mut()
                    .get_next_sess_id();
                let spake2p_data: u32 = ((local_sessid as u32) << 16) | a.initiator_ssid as u32;
                self.spake2p.set_app_data(spake2p_data);

                initiator_random[..a.initiator_random.0.len()]
                    .copy_from_slice(a.initiator_random.0);
                let initiator_random = &initiator_random[..a.initiator_random.0.len()];

                // Generate response
                let mut resp = PBKDFParamResp {
                    init_random: OctetStr::new(initiator_random),
                    our_random: OctetStr::new(&our_random),
                    local_sessid,
                    params: None,
                };
                if !a.has_params {
                    let params_resp = PBKDFParamRespParams {
                        count,
                        salt: OctetStr::new(&salt),
                    };
                    resp.params = Some(params_resp);
                }

                resp
            };

            self.spake2p.set_context()?;
            self.spake2p.update_context(rx.payload())?;

            let mut context_set = false;
            exchange
                .send_with(|_, wb| {
                    resp.to_tlv(&TagType::Anonymous, &mut *wb)?;

                    if !context_set {
                        self.spake2p.update_context(wb.as_slice())?;
                        context_set = true;
                    }

                    Ok(Some(OpCode::PBKDFParamResponse.into()))
                })
                .await
        } else {
            complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await
        }
    }

    /// Handle a PASEPake1 message
    ///
    /// # Arguments
    /// - `exchange` - The exchange
    #[allow(non_snake_case)]
    async fn handle_pasepake1(&mut self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        check_opcode(exchange, OpCode::PASEPake1)?;

        let root = get_root_node_struct(exchange.rx()?.payload())?;

        let pA: CanonEcPointRef<'_> = root.structure()?.ctx(1)?.str()?.try_into()?;
        let mut pB = EC_POINT_ZEROED;
        let mut cB = HMAC_HASH_ZEROED;

        let has_comm_window = {
            let matter = exchange.matter();
            let mut pase = matter.pase_mgr.borrow_mut();
            let ctx = BasicContextInstance::new(matter, matter);

            if let Some(comm_window) = pase.comm_window(&ctx)? {
                self.spake2p.start_verifier(&comm_window.verifier)?;
                self.spake2p.handle_pA(pA, &mut pB, &mut cB)?;

                true
            } else {
                false
            }
        };

        if has_comm_window {
            exchange
                .send_with(|_, wb| {
                    let resp = Pake1Resp {
                        pb: OctetStr::new(pB.access()),
                        cb: OctetStr::new(cB.access()),
                    };
                    resp.to_tlv(&TagType::Anonymous, wb)?;

                    Ok(Some(OpCode::PASEPake2.into()))
                })
                .await
        } else {
            complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await
        }
    }

    /// Handle a PASEPake3 message
    ///
    /// # Arguments
    /// - `exchange` - The exchange
    /// - `session` - The reserved session
    #[allow(non_snake_case)]
    async fn handle_pasepake3(
        &mut self,
        exchange: &mut Exchange<'_>,
        mut session: ReservedSession<'_>,
    ) -> Result<(), Error> {
        check_opcode(exchange, OpCode::PASEPake3)?;

        let root = get_root_node_struct(exchange.rx()?.payload())?;

        let cA: HmacHashRef<'_> = root.structure()?.ctx(1)?.str()?.try_into()?;
        let result = self.spake2p.handle_cA(cA);

        if result.is_ok() {
            // Get the keys
            let mut session_keys = CryptoSensitive::<{ AEAD_CANON_KEY_LEN * 3 }>::new(); // TODO: MEDIUM BUFFER
            self.spake2p
                .crypto
                .kdf()?
                .expand(
                    &[],
                    self.spake2p.ke(),
                    SPAKE2_SESSION_KEYS_INFO,
                    &mut session_keys,
                )
                .map_err(|_x| ErrorCode::InvalidData)?;

            // Create a session
            let data = self.spake2p.get_app_data();
            let peer_sessid: u16 = (data & 0xffff) as u16;
            let local_sessid: u16 = ((data >> 16) & 0xffff) as u16;
            let peer_addr = exchange.with_session(|sess| Ok(sess.get_peer_addr()))?;

            let (dec_key, remaining) = session_keys
                .reference()
                .split::<AEAD_CANON_KEY_LEN, { AEAD_CANON_KEY_LEN * 2 }>();
            let (enc_key, att_challenge) =
                remaining.split::<AEAD_CANON_KEY_LEN, AEAD_CANON_KEY_LEN>();

            session.update(
                0,
                0,
                peer_sessid,
                local_sessid,
                peer_addr,
                SessionMode::Pase { fab_idx: 0 },
                Some(dec_key),
                Some(enc_key),
                Some(att_challenge),
            )?;
        }

        let status = match result {
            Ok(()) => {
                // Complete the reserved session and thus make the `Session` instance
                // immediately available for use by the system.
                //
                // We need to do this _before_ we send the response to the peer, or else we risk missing
                // (dropping) the first messages the peer would send us on the newly-established session,
                // as it might start using it right after it receives the response, while it is still marked
                // as reserved.
                session.complete();

                SCStatusCodes::SessionEstablishmentSuccess
            }
            Err(status) => status,
        };

        complete_with_status(exchange, status, &[]).await
    }

    /// Update the PASE session timeout tracker
    ///
    /// # Arguments
    /// - `exchange` - The exchange
    /// - `new` - Whether this is for a new session
    ///
    /// # Returns
    /// - `Ok(true)` if the session timeout was updated successfully
    /// - `Ok(false)` if the session timeout could not be updated
    ///   (e.g. another session is in progress, there is no active PASE session establishment, or the session has expired)
    async fn update_session_timeout(
        &mut self,
        exchange: &mut Exchange<'_>,
        new: bool,
    ) -> Result<bool, Error> {
        let status = {
            let mut pase = exchange.matter().pase_mgr.borrow_mut();

            if pase
                .session_timeout
                .as_ref()
                .map(|sd| sd.is_sess_expired(pase.epoch))
                .unwrap_or(false)
            {
                pase.session_timeout = None;
            }

            if let Some(sd) = pase.session_timeout.as_mut() {
                if sd.exch_id != exchange.id() {
                    debug!("Another PAKE session in progress");
                    Some(SCStatusCodes::Busy)
                } else {
                    None
                }
            } else if new {
                None
            } else {
                error!("PAKE session not found or expired");
                Some(SCStatusCodes::SessionNotFound)
            }
        };

        if let Some(status) = status {
            complete_with_status(exchange, status, &[]).await?;

            Ok(false)
        } else {
            let mut pase = exchange.matter().pase_mgr.borrow_mut();
            pase.session_timeout = Some(SessionEstTimeout::new(exchange, pase.epoch));

            Ok(true)
        }
    }

    /// Clear the PASE session timeout tracker
    fn clear_session_timeout(&mut self, exchange: &Exchange) {
        let mut pase = exchange.matter().pase_mgr.borrow_mut();

        pase.session_timeout = None;
    }
}
