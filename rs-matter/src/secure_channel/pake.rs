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

use core::{cell::RefCell, fmt::Write, time::Duration};

use super::{
    common::{SCStatusCodes, PROTO_ID_SECURE_CHANNEL},
    spake2p::{Spake2P, VerifierData},
};
use crate::{
    alloc, crypto,
    error::{Error, ErrorCode},
    mdns::{Mdns, ServiceMode},
    secure_channel::common::{complete_with_status, OpCode},
    tlv::{self, get_root_node_struct, FromTLV, OctetStr, TLVWriter, TagType, ToTLV},
    transport::{
        exchange::{Exchange, ExchangeId},
        packet::Packet,
        session::{CloneData, SessionMode},
    },
    utils::{epoch::Epoch, rand::Rand},
};
use log::{error, info};

struct PaseSession {
    mdns_service_name: heapless::String<16>,
    verifier: VerifierData,
}

pub struct PaseMgr {
    session: Option<PaseSession>,
    timeout: Option<Timeout>,
    epoch: Epoch,
    rand: Rand,
}

impl PaseMgr {
    #[inline(always)]
    pub fn new(epoch: Epoch, rand: Rand) -> Self {
        Self {
            session: None,
            timeout: None,
            epoch,
            rand,
        }
    }

    pub fn is_pase_session_enabled(&self) -> bool {
        self.session.is_some()
    }

    pub fn enable_pase_session(
        &mut self,
        verifier: VerifierData,
        discriminator: u16,
        mdns: &dyn Mdns,
    ) -> Result<(), Error> {
        let mut buf = [0; 8];
        (self.rand)(&mut buf);
        let num = u64::from_be_bytes(buf);

        let mut mdns_service_name = heapless::String::<16>::new();
        write!(&mut mdns_service_name, "{:016X}", num).unwrap();

        mdns.add(
            &mdns_service_name,
            ServiceMode::Commissionable(discriminator),
        )?;

        self.session = Some(PaseSession {
            mdns_service_name,
            verifier,
        });

        Ok(())
    }

    pub fn disable_pase_session(&mut self, mdns: &dyn Mdns) -> Result<(), Error> {
        if let Some(session) = self.session.as_ref() {
            mdns.remove(&session.mdns_service_name)?;
        }

        self.session = None;

        Ok(())
    }
}

// This file basically deals with the handlers for the PASE secure channel protocol
// TLV extraction and encoding is done in this file.
// We create a Spake2p object and set it up in the exchange-data. This object then
// handles Spake2+ specific stuff.

const PASE_DISCARD_TIMEOUT_SECS: Duration = Duration::from_secs(60);

const SPAKE2_SESSION_KEYS_INFO: [u8; 11] = *b"SessionKeys";

struct Timeout {
    start_time: Duration,
    exch_id: ExchangeId,
}

impl Timeout {
    fn new(exchange: &Exchange, epoch: Epoch) -> Self {
        Self {
            start_time: epoch(),
            exch_id: exchange.id().clone(),
        }
    }

    fn is_sess_expired(&self, epoch: Epoch) -> bool {
        epoch() - self.start_time > PASE_DISCARD_TIMEOUT_SECS
    }
}

pub struct Pake<'a> {
    pase: &'a RefCell<PaseMgr>,
}

impl<'a> Pake<'a> {
    pub const fn new(pase: &'a RefCell<PaseMgr>) -> Self {
        // TODO: Can any PBKDF2 calculation be pre-computed here
        Self { pase }
    }

    pub async fn handle(
        &mut self,
        exchange: &mut Exchange<'_>,
        rx: &mut Packet<'_>,
        tx: &mut Packet<'_>,
        mdns: &dyn Mdns,
    ) -> Result<(), Error> {
        let mut spake2p = alloc!(Spake2P::new());

        self.handle_pbkdfparamrequest(exchange, rx, tx, &mut spake2p)
            .await?;
        self.handle_pasepake1(exchange, rx, tx, &mut spake2p)
            .await?;
        self.handle_pasepake3(exchange, rx, tx, mdns, &mut spake2p)
            .await
    }

    #[allow(non_snake_case)]
    async fn handle_pasepake3(
        &mut self,
        exchange: &mut Exchange<'_>,
        rx: &Packet<'_>,
        tx: &mut Packet<'_>,
        mdns: &dyn Mdns,
        spake2p: &mut Spake2P,
    ) -> Result<(), Error> {
        rx.check_proto_opcode(OpCode::PASEPake3 as _)?;
        self.update_timeout(exchange, tx, true).await?;

        let cA = extract_pasepake_1_or_3_params(rx.as_slice())?;
        let (status_code, ke) = spake2p.handle_cA(cA);

        let clone_data = if status_code == SCStatusCodes::SessionEstablishmentSuccess {
            // Get the keys
            let ke = ke.ok_or(ErrorCode::Invalid)?;
            let mut session_keys: [u8; 48] = [0; 48];
            crypto::hkdf_sha256(&[], ke, &SPAKE2_SESSION_KEYS_INFO, &mut session_keys)
                .map_err(|_x| ErrorCode::NoSpace)?;

            // Create a session
            let data = spake2p.get_app_data();
            let peer_sessid: u16 = (data & 0xffff) as u16;
            let local_sessid: u16 = ((data >> 16) & 0xffff) as u16;
            let mut clone_data = CloneData::new(
                0,
                0,
                peer_sessid,
                local_sessid,
                exchange.with_session(|sess| Ok(sess.get_peer_addr()))?,
                SessionMode::Pase,
            );
            clone_data.dec_key.copy_from_slice(&session_keys[0..16]);
            clone_data.enc_key.copy_from_slice(&session_keys[16..32]);
            clone_data
                .att_challenge
                .copy_from_slice(&session_keys[32..48]);

            // Queue a transport mgr request to add a new session
            Some(clone_data)
        } else {
            None
        };

        if let Some(clone_data) = clone_data {
            // TODO: Handle NoSpace
            exchange.with_session_mgr_mut(|sess_mgr| sess_mgr.clone_session(&clone_data))?;

            self.pase.borrow_mut().disable_pase_session(mdns)?;
        }

        complete_with_status(exchange, tx, status_code, None).await?;

        Ok(())
    }

    #[allow(non_snake_case)]
    async fn handle_pasepake1(
        &mut self,
        exchange: &mut Exchange<'_>,
        rx: &mut Packet<'_>,
        tx: &mut Packet<'_>,
        spake2p: &mut Spake2P,
    ) -> Result<(), Error> {
        rx.check_proto_opcode(OpCode::PASEPake1 as _)?;
        self.update_timeout(exchange, tx, false).await?;

        {
            let pase = self.pase.borrow();
            let session = pase.session.as_ref().ok_or(ErrorCode::NoSession)?;

            let pA = extract_pasepake_1_or_3_params(rx.as_slice())?;
            let mut pB: [u8; 65] = [0; 65];
            let mut cB: [u8; 32] = [0; 32];
            spake2p.start_verifier(&session.verifier)?;
            spake2p.handle_pA(pA, &mut pB, &mut cB, pase.rand)?;

            // Generate response
            tx.reset();
            tx.set_proto_id(PROTO_ID_SECURE_CHANNEL);
            tx.set_proto_opcode(OpCode::PASEPake2 as u8);

            let mut tw = TLVWriter::new(tx.get_writebuf()?);
            let resp = Pake1Resp {
                pb: OctetStr(&pB),
                cb: OctetStr(&cB),
            };
            resp.to_tlv(&mut tw, TagType::Anonymous)?;
        }

        exchange.exchange(tx, rx).await
    }

    async fn handle_pbkdfparamrequest(
        &mut self,
        exchange: &mut Exchange<'_>,
        rx: &mut Packet<'_>,
        tx: &mut Packet<'_>,
        spake2p: &mut Spake2P,
    ) -> Result<(), Error> {
        rx.check_proto_opcode(OpCode::PBKDFParamRequest as _)?;
        self.update_timeout(exchange, tx, true).await?;

        {
            let pase = self.pase.borrow();
            let session = pase.session.as_ref().ok_or(ErrorCode::NoSession)?;

            let root = tlv::get_root_node(rx.as_slice())?;
            let a = PBKDFParamReq::from_tlv(&root)?;
            if a.passcode_id != 0 {
                error!("Can't yet handle passcode_id != 0");
                Err(ErrorCode::Invalid)?;
            }

            let mut our_random: [u8; 32] = [0; 32];
            (self.pase.borrow().rand)(&mut our_random);

            let local_sessid = exchange.with_session_mgr_mut(|mgr| Ok(mgr.get_next_sess_id()))?;
            let spake2p_data: u32 = ((local_sessid as u32) << 16) | a.initiator_ssid as u32;
            spake2p.set_app_data(spake2p_data);

            // Generate response
            tx.reset();
            tx.set_proto_id(PROTO_ID_SECURE_CHANNEL);
            tx.set_proto_opcode(OpCode::PBKDFParamResponse as u8);

            let mut tw = TLVWriter::new(tx.get_writebuf()?);
            let mut resp = PBKDFParamResp {
                init_random: a.initiator_random,
                our_random: OctetStr(&our_random),
                local_sessid,
                params: None,
            };
            if !a.has_params {
                let params_resp = PBKDFParamRespParams {
                    count: session.verifier.count,
                    salt: OctetStr(&session.verifier.salt),
                };
                resp.params = Some(params_resp);
            }
            resp.to_tlv(&mut tw, TagType::Anonymous)?;

            spake2p.set_context(rx.as_slice(), tx.as_mut_slice())?;
        }

        exchange.exchange(tx, rx).await
    }

    async fn update_timeout(
        &mut self,
        exchange: &mut Exchange<'_>,
        tx: &mut Packet<'_>,
        new: bool,
    ) -> Result<(), Error> {
        self.check_session(exchange, tx).await?;

        let status = {
            let mut pase = self.pase.borrow_mut();

            if pase
                .timeout
                .as_ref()
                .map(|sd| sd.is_sess_expired(pase.epoch))
                .unwrap_or(false)
            {
                pase.timeout = None;
            }

            if let Some(sd) = pase.timeout.as_mut() {
                if &sd.exch_id != exchange.id() {
                    info!("Other PAKE session in progress");
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
            complete_with_status(exchange, tx, status, None).await
        } else {
            let mut pase = self.pase.borrow_mut();

            pase.timeout = Some(Timeout::new(exchange, pase.epoch));

            Ok(())
        }
    }

    async fn check_session(
        &mut self,
        exchange: &mut Exchange<'_>,
        tx: &mut Packet<'_>,
    ) -> Result<(), Error> {
        if self.pase.borrow().session.is_none() {
            error!("PASE not enabled");
            complete_with_status(exchange, tx, SCStatusCodes::InvalidParameter, None).await
        } else {
            Ok(())
        }
    }
}

#[derive(ToTLV)]
#[tlvargs(start = 1)]
struct Pake1Resp<'a> {
    pb: OctetStr<'a>,
    cb: OctetStr<'a>,
}

#[derive(ToTLV)]
#[tlvargs(start = 1)]
struct PBKDFParamRespParams<'a> {
    count: u32,
    salt: OctetStr<'a>,
}

#[derive(ToTLV)]
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
    let pA = root.find_tag(1)?.slice()?;
    Ok(pA)
}

#[derive(FromTLV)]
#[tlvargs(lifetime = "'a", start = 1)]
struct PBKDFParamReq<'a> {
    initiator_random: OctetStr<'a>,
    initiator_ssid: u16,
    passcode_id: u16,
    has_params: bool,
}
