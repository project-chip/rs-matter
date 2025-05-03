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

use core::{fmt::Write, time::Duration};

use crate::crypto;
use crate::error::{Error, ErrorCode};
use crate::mdns::{Mdns, ServiceMode};
use crate::secure_channel::common::{complete_with_status, OpCode};
use crate::tlv::{get_root_node_struct, FromTLV, OctetStr, TLVElement, TagType, ToTLV};
use crate::transport::exchange::{Exchange, ExchangeId};
use crate::transport::session::{ReservedSession, SessionMode};
use crate::utils::epoch::Epoch;
use crate::utils::init::{init, try_init, Init};
use crate::utils::maybe::Maybe;
use crate::utils::rand::Rand;

use super::common::SCStatusCodes;
use super::spake2p::{Spake2P, VerifierData, MAX_SALT_SIZE_BYTES};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PaseSessionType {
    Basic,
    Enhanced,
}

struct PaseSession {
    mdns_service_name: heapless::String<16>,
    verifier: VerifierData,
}

impl PaseSession {
    fn init_with_pw(password: u32, rand: Rand) -> impl Init<Self> {
        init!(Self {
            mdns_service_name: heapless::String::new(),
            verifier <- VerifierData::init_with_pw(password, rand),
        })
    }

    fn init<'a>(verifier: &'a [u8], salt: &'a [u8], count: u32) -> impl Init<Self, Error> + 'a {
        try_init!(Self {
            mdns_service_name: heapless::String::new(),
            verifier <- VerifierData::init(verifier, salt, count),
        }? Error)
    }

    fn session_type(&self) -> PaseSessionType {
        if self.verifier.password.is_some() {
            PaseSessionType::Basic
        } else {
            PaseSessionType::Enhanced
        }
    }

    fn add_mdns(&mut self, discriminator: u16, rand: Rand, mdns: &dyn Mdns) -> Result<(), Error> {
        let mut buf = [0; 8];
        (rand)(&mut buf);
        let num = u64::from_be_bytes(buf);

        self.mdns_service_name.clear();
        write_unwrap!(&mut self.mdns_service_name, "{:016X}", num);

        mdns.add(
            &self.mdns_service_name,
            ServiceMode::Commissionable(discriminator),
        )?;

        Ok(())
    }
}

pub struct PaseMgr {
    session: Maybe<PaseSession>,
    timeout: Option<Timeout>,
    epoch: Epoch,
    rand: Rand,
}

impl PaseMgr {
    #[inline(always)]
    pub const fn new(epoch: Epoch, rand: Rand) -> Self {
        Self {
            session: Maybe::none(),
            timeout: None,
            epoch,
            rand,
        }
    }

    pub fn init(epoch: Epoch, rand: Rand) -> impl Init<Self> {
        init!(Self {
            session <- Maybe::init_none(),
            timeout: None,
            epoch,
            rand,
        })
    }

    pub fn session_type(&self) -> Option<PaseSessionType> {
        self.session
            .as_opt_ref()
            .map(|session| session.session_type())
    }

    pub fn enable_basic_pase_session(
        &mut self,
        password: u32,
        discriminator: u16,
        _timeout_secs: u16,
        mdns: &dyn Mdns,
    ) -> Result<(), Error> {
        if self.session.is_some() {
            Err(ErrorCode::Invalid)?;
        }

        self.session
            .reinit(Maybe::init_some(PaseSession::init_with_pw(
                password, self.rand,
            )));

        // Can't fail as we just initialized the session
        let session = unwrap!(self.session.as_opt_mut());

        session.add_mdns(discriminator, self.rand, mdns)
    }

    pub fn enable_pase_session(
        &mut self,
        verifier: &[u8],
        salt: &[u8],
        count: u32,
        discriminator: u16,
        _timeout_secs: u16,
        mdns: &dyn Mdns,
    ) -> Result<(), Error> {
        if self.session.is_some() {
            Err(ErrorCode::Invalid)?;
        }

        self.session
            .try_reinit(Maybe::init_some(PaseSession::init(verifier, salt, count)))?;

        // Can't fail as we just initialized the session
        let session = unwrap!(self.session.as_opt_mut());

        session.add_mdns(discriminator, self.rand, mdns)
    }

    pub fn disable_pase_session(&mut self, mdns: &dyn Mdns) -> Result<bool, Error> {
        let disabled = if let Some(session) = self.session.as_opt_ref() {
            mdns.remove(&session.mdns_service_name)?;

            true
        } else {
            false
        };

        self.session.clear();

        Ok(disabled)
    }
}

// This file basically deals with the handlers for the PASE secure channel protocol
// TLV extraction and encoding is done in this file.
// We create a Spake2p object and set it up in the exchange-data. This object then
// handles Spake2+ specific stuff.

const PASE_DISCARD_TIMEOUT_SECS: Duration = Duration::from_secs(60);
const SPAKE2_SESSION_KEYS_INFO: &[u8] = b"SessionKeys";

struct Timeout {
    start_time: Duration,
    exch_id: ExchangeId,
}

impl Timeout {
    fn new(exchange: &Exchange, epoch: Epoch) -> Self {
        Self {
            start_time: epoch(),
            exch_id: exchange.id(),
        }
    }

    fn is_sess_expired(&self, epoch: Epoch) -> bool {
        epoch() - self.start_time > PASE_DISCARD_TIMEOUT_SECS
    }
}

pub struct Pake(());

impl Pake {
    pub const fn new() -> Self {
        // TODO: Can any PBKDF2 calculation be pre-computed here
        Self(())
    }

    pub async fn handle(
        &mut self,
        exchange: &mut Exchange<'_>,
        spake2p: &mut Spake2P,
    ) -> Result<(), Error> {
        let session = ReservedSession::reserve(exchange.matter()).await?;

        if !self.update_timeout(exchange, true).await? {
            return Ok(());
        }

        self.handle_pbkdfparamrequest(exchange, spake2p).await?;

        exchange.recv_fetch().await?;

        if !self.update_timeout(exchange, false).await? {
            return Ok(());
        }

        self.handle_pasepake1(exchange, spake2p).await?;

        exchange.recv_fetch().await?;

        if !self.update_timeout(exchange, false).await? {
            return Ok(());
        }

        self.handle_pasepake3(exchange, session, spake2p).await?;

        exchange.acknowledge().await?;
        exchange.matter().notify_persist();

        self.clear_timeout(exchange);

        Ok(())
    }

    #[allow(non_snake_case)]
    async fn handle_pasepake3(
        &mut self,
        exchange: &mut Exchange<'_>,
        mut session: ReservedSession<'_>,
        spake2p: &mut Spake2P,
    ) -> Result<(), Error> {
        exchange.rx()?.meta().check_opcode(OpCode::PASEPake3)?;

        let cA = extract_pasepake_1_or_3_params(exchange.rx()?.payload())?;
        let (status, ke) = spake2p.handle_cA(cA);

        let result = if status == SCStatusCodes::SessionEstablishmentSuccess {
            // Get the keys
            let ke = ke.ok_or(ErrorCode::Invalid)?;
            let mut session_keys: [u8; 48] = [0; 48];
            crypto::hkdf_sha256(&[], ke, SPAKE2_SESSION_KEYS_INFO, &mut session_keys)
                .map_err(|_x| ErrorCode::NoSpace)?;

            // Create a session
            let data = spake2p.get_app_data();
            let peer_sessid: u16 = (data & 0xffff) as u16;
            let local_sessid: u16 = ((data >> 16) & 0xffff) as u16;
            let peer_addr = exchange.with_session(|sess| Ok(sess.get_peer_addr()))?;

            session.update(
                0,
                0,
                peer_sessid,
                local_sessid,
                peer_addr,
                SessionMode::Pase { fab_idx: 0 },
                Some(&session_keys[0..16]),
                Some(&session_keys[16..32]),
                Some(&session_keys[32..48]),
            )?;

            Ok(())
        } else {
            Err(status)
        };

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

    #[allow(non_snake_case)]
    async fn handle_pasepake1(
        &mut self,
        exchange: &mut Exchange<'_>,
        spake2p: &mut Spake2P,
    ) -> Result<(), Error> {
        exchange.rx()?.meta().check_opcode(OpCode::PASEPake1)?;

        let pA = extract_pasepake_1_or_3_params(exchange.rx()?.payload())?;
        let mut pB: [u8; 65] = [0; 65];
        let mut cB: [u8; 32] = [0; 32];

        {
            let pase = exchange.matter().pase_mgr.borrow();
            let session = pase.session.as_opt_ref().ok_or(ErrorCode::NoSession)?;

            spake2p.start_verifier(&session.verifier)?;
            spake2p.handle_pA(pA, &mut pB, &mut cB, pase.rand)?;
        }

        exchange
            .send_with(|_, wb| {
                let resp = Pake1Resp {
                    pb: OctetStr::new(&pB),
                    cb: OctetStr::new(&cB),
                };
                resp.to_tlv(&TagType::Anonymous, wb)?;

                Ok(Some(OpCode::PASEPake2.into()))
            })
            .await
    }

    async fn handle_pbkdfparamrequest(
        &mut self,
        exchange: &mut Exchange<'_>,
        spake2p: &mut Spake2P,
    ) -> Result<(), Error> {
        let rx = exchange.rx()?;
        rx.meta().check_opcode(OpCode::PBKDFParamRequest)?;

        let mut our_random = [0; 32];
        let mut initiator_random = [0; 32];
        let mut salt = [0; MAX_SALT_SIZE_BYTES];

        let resp = {
            let pase = exchange.matter().pase_mgr.borrow();
            let session = pase.session.as_opt_ref().ok_or(ErrorCode::NoSession)?;

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
            spake2p.set_app_data(spake2p_data);

            initiator_random[..a.initiator_random.0.len()].copy_from_slice(a.initiator_random.0);
            let initiator_random = &initiator_random[..a.initiator_random.0.len()];

            salt.copy_from_slice(&session.verifier.salt);

            // Generate response
            let mut resp = PBKDFParamResp {
                init_random: OctetStr::new(initiator_random),
                our_random: OctetStr::new(&our_random),
                local_sessid,
                params: None,
            };
            if !a.has_params {
                let params_resp = PBKDFParamRespParams {
                    count: session.verifier.count,
                    salt: OctetStr::new(&salt),
                };
                resp.params = Some(params_resp);
            }

            resp
        };

        spake2p.set_context()?;
        spake2p.update_context(rx.payload())?;

        let mut context_set = false;
        exchange
            .send_with(|_, wb| {
                resp.to_tlv(&TagType::Anonymous, &mut *wb)?;

                if !context_set {
                    spake2p.update_context(wb.as_slice())?;
                    context_set = true;
                }

                Ok(Some(OpCode::PBKDFParamResponse.into()))
            })
            .await
    }

    fn clear_timeout(&mut self, exchange: &Exchange) {
        let mut pase = exchange.matter().pase_mgr.borrow_mut();

        pase.timeout = None;
    }

    async fn update_timeout(
        &mut self,
        exchange: &mut Exchange<'_>,
        new: bool,
    ) -> Result<bool, Error> {
        if !self.check_session(exchange).await? {
            return Ok(false);
        }

        let status = {
            let mut pase = exchange.matter().pase_mgr.borrow_mut();

            if pase
                .timeout
                .as_ref()
                .map(|sd| sd.is_sess_expired(pase.epoch))
                .unwrap_or(false)
            {
                pase.timeout = None;
            }

            if let Some(sd) = pase.timeout.as_mut() {
                if sd.exch_id != exchange.id() {
                    debug!("Other PAKE session in progress");
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
            pase.timeout = Some(Timeout::new(exchange, pase.epoch));

            Ok(true)
        }
    }

    async fn check_session(&mut self, exchange: &mut Exchange<'_>) -> Result<bool, Error> {
        if exchange.matter().pase_mgr.borrow().session.is_none() {
            error!("PASE not enabled");
            complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await?;

            Ok(false)
        } else {
            Ok(true)
        }
    }
}

impl Default for Pake {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1)]
struct Pake1Resp<'a> {
    pb: OctetStr<'a>,
    cb: OctetStr<'a>,
}

#[derive(ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1)]
struct PBKDFParamRespParams<'a> {
    count: u32,
    salt: OctetStr<'a>,
}

#[derive(ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1)]
struct PBKDFParamResp<'a> {
    init_random: OctetStr<'a>,
    our_random: OctetStr<'a>,
    local_sessid: u16,
    params: Option<PBKDFParamRespParams<'a>>,
}

#[allow(non_snake_case)]
fn extract_pasepake_1_or_3_params(buf: &[u8]) -> Result<&[u8], Error> {
    let root = get_root_node_struct(buf)?;
    let pA = root.structure()?.ctx(1)?.str()?;
    Ok(pA)
}

#[derive(FromTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
struct PBKDFParamReq<'a> {
    initiator_random: OctetStr<'a>,
    initiator_ssid: u16,
    passcode_id: u16,
    has_params: bool,
}
