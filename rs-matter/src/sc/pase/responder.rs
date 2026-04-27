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

//! PASE Responder (Device side) implementation.
//!
//! This module implements the responder side of the PASE (Passcode-Authenticated Session Establishment)
//! protocol, used by Matter devices to accept secure session establishment from commissioners.

use rand_core::RngCore;

use crate::crypto::{
    CanonEcPointRef, Crypto, HmacHashRef, Kdf, AEAD_CANON_KEY_LEN, EC_POINT_ZEROED,
    HMAC_HASH_ZEROED,
};
use crate::dm::AttrChangeNotifier;
use crate::error::{Error, ErrorCode};
use crate::sc::pase::spake2p::{Spake2P, Spake2pRandom, Spake2pRandomRef, Spake2pSessionKeys};
use crate::sc::{check_opcode, complete_with_status, OpCode, SCStatusCodes};
use crate::tlv::{get_root_node_struct, FromTLV, OctetStr, TLVElement, TagType, ToTLV};
use crate::transport::exchange::Exchange;
use crate::transport::session::{ReservedSession, SessionMode};
use crate::utils::init::{init, Init};

use super::{
    PBKDFParamReq, PBKDFParamResp, PBKDFParamRespParams, Pake1, Pake2, Pake3,
    SPAKE2_SESSION_KEYS_INFO,
};

/// The PASE Responder (device side) handler
pub struct PaseResponder<'a, C: Crypto> {
    crypto: C,
    notify: &'a dyn AttrChangeNotifier,
    spake2p: Spake2P,
}

impl<'a, C: Crypto> PaseResponder<'a, C> {
    /// Create a new PASE Responder handler
    pub const fn new(crypto: C, notify: &'a dyn AttrChangeNotifier) -> Self {
        // TODO: Can any PBKDF2 calculation be pre-computed here
        Self {
            crypto,
            notify,
            spake2p: Spake2P::new(),
        }
    }

    pub fn init(crypto: C, notify: &'a dyn AttrChangeNotifier) -> impl Init<Self> {
        init!(Self {
            crypto,
            notify,
            spake2p <- Spake2P::init(),
        })
    }

    /// Handle a PASE PAKE exchange, where the other peer is the exchange initiator
    ///
    /// # Arguments
    /// - `exchange` - The exchange
    pub async fn handle(&mut self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let result = self.handle_inner(exchange).await;

        // Per Matter Core spec section 11.18.6.1.5, every unsuccessful PAKE
        // handshake within the open commissioning window must be counted; the
        // window SHALL be revoked after 20. We charge a failure for any path
        // that errored mid-handshake or returned `Ok(false)` from
        // `handle_inner` (PAKE3 verify failed). Successful handshakes and
        // protocol-level rejections (e.g. "another PAKE session in progress",
        // which is not a wrong-passcode attempt) return `Ok(true)` and
        // therefore are not counted.
        //
        // We also unconditionally clear `session_timeout` so the next inbound
        // PBKDFParamRequest isn't blocked by a stale "session in progress"
        // marker left behind by an aborted handshake.
        let pake_failed = matches!(result, Ok(false) | Err(_));

        if pake_failed {
            let notify_mdns = || exchange.matter().notify_mdns_changed();
            let notify_change =
                |endpt_id, cluster_id| self.notify.notify_cluster_changed(endpt_id, cluster_id);

            let _ = exchange
                .with_state(|state| state.pase.record_pake_failure(notify_mdns, notify_change));
        }

        result.map(|_| ())
    }

    async fn handle_inner(&mut self, exchange: &mut Exchange<'_>) -> Result<bool, Error> {
        let session = ReservedSession::reserve(exchange.matter(), &self.crypto).await?;

        if !self.update_session_timeout(exchange, true).await? {
            return Ok(true);
        }

        self.handle_pbkdfparamrequest(exchange).await?;

        exchange.recv_fetch().await?;

        if !self.update_session_timeout(exchange, false).await? {
            return Ok(true);
        }

        self.handle_pasepake1(exchange).await?;

        exchange.recv_fetch().await?;

        if !self.update_session_timeout(exchange, false).await? {
            return Ok(true);
        }

        let success = self.handle_pasepake3(exchange, session).await?;

        exchange.acknowledge().await?;

        self.clear_session_timeout(exchange)?;

        Ok(success)
    }

    /// Handle a PBKDFParamRequest message
    ///
    /// # Arguments
    /// - `exchange` - The exchange
    async fn handle_pbkdfparamrequest(&mut self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        check_opcode(exchange, OpCode::PBKDFParamRequest)?;

        let rx = exchange.rx()?;

        let mut salt = super::spake2p::SPAKE2P_VERIFIER_SALT_ZEROED;
        let mut count = 0;

        let notify_mdns = || exchange.matter().notify_mdns_changed();
        let notify_change =
            |endpt_id, cluster_id| self.notify.notify_cluster_changed(endpt_id, cluster_id);

        let has_comm_window = {
            exchange.with_state(|state| {
                state
                    .pase
                    .check_comm_window_timeout(notify_mdns, notify_change)?;

                if let Some(comm_window) = state.pase.comm_window() {
                    salt.load(comm_window.verifier.salt.reference());
                    count = comm_window.verifier.count;

                    Ok(true)
                } else {
                    Ok(false)
                }
            })?
        };

        if has_comm_window {
            let mut our_random = Spake2pRandom::new();
            let mut initiator_random = Spake2pRandom::new();

            let (local_sessid, peer_sessid, resp) = {
                let req = PBKDFParamReq::from_tlv(&TLVElement::new(rx.payload()))?;
                if req.passcode_id != 0 {
                    error!("Can't yet handle passcode_id != 0");
                    Err(ErrorCode::Invalid)?;
                }

                let mut rand = self.crypto.rand()?;
                rand.fill_bytes(our_random.access_mut());

                let local_sessid =
                    exchange.with_state(|state| Ok(state.sessions.get_next_sess_id()))?;

                initiator_random.load(Spake2pRandomRef::try_new(req.initiator_random.0)?);

                // Generate response
                let max_paths = exchange.matter().dev_det().max_paths_per_invoke;
                let resp = PBKDFParamResp {
                    initiator_random: OctetStr::new(initiator_random.access()),
                    responder_random: OctetStr::new(our_random.access()),
                    responder_ssid: local_sessid,
                    params: (!req.has_params).then(|| PBKDFParamRespParams {
                        iterations: count,
                        salt: OctetStr::new(salt.access()),
                    }),
                    session_parameters: Some(crate::sc::SessionParameters {
                        max_paths_per_invoke: Some(max_paths),
                        ..Default::default()
                    }),
                };

                (local_sessid, req.initiator_ssid, resp)
            };

            let mut context = Some(self.spake2p.start_context(
                &self.crypto,
                local_sessid,
                peer_sessid,
                rx.payload(),
            )?);

            exchange
                .send_with(|_, wb| {
                    resp.to_tlv(&TagType::Anonymous, &mut *wb)?;

                    if let Some(context) = context.take() {
                        self.spake2p.finish_context::<&C>(context, wb.as_slice())?;
                    }

                    Ok(Some(OpCode::PBKDFParamResponse.into()))
                })
                .await?;

            Ok(())
        } else {
            complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await
        }
    }

    /// Handle a PASEPake1 message
    ///
    /// # Arguments
    /// - `exchange` - The exchange
    async fn handle_pasepake1(&mut self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        check_opcode(exchange, OpCode::PASEPake1)?;

        let req = get_root_node_struct(exchange.rx()?.payload())?;
        let pake1 = Pake1::from_tlv(&req)?;
        let a_pt: CanonEcPointRef<'_> = pake1.pa.0.try_into()?;

        let mut b_pt = EC_POINT_ZEROED;
        let mut cb = HMAC_HASH_ZEROED;

        let notify_mdns = || exchange.matter().notify_mdns_changed();
        let notify_change =
            |endpt_id, cluster_id| self.notify.notify_cluster_changed(endpt_id, cluster_id);

        let has_comm_window = {
            exchange.with_state(|state| {
                state
                    .pase
                    .check_comm_window_timeout(notify_mdns, notify_change)?;

                if let Some(comm_window) = state.pase.comm_window() {
                    self.spake2p.setup_verifier(
                        &self.crypto,
                        &comm_window.verifier,
                        a_pt,
                        &mut b_pt,
                        &mut cb,
                    )?;

                    Ok(true)
                } else {
                    Ok(false)
                }
            })?
        };

        if has_comm_window {
            exchange
                .send_with(|_, wb| {
                    let resp = Pake2 {
                        pb: OctetStr::new(b_pt.access()),
                        cb: OctetStr::new(cb.access()),
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
    async fn handle_pasepake3(
        &mut self,
        exchange: &mut Exchange<'_>,
        mut session: ReservedSession<'_>,
    ) -> Result<bool, Error> {
        check_opcode(exchange, OpCode::PASEPake3)?;

        let req = get_root_node_struct(exchange.rx()?.payload())?;
        let pake3 = Pake3::from_tlv(&req)?;
        let ca: HmacHashRef<'_> = pake3.ca.0.try_into()?;

        let verify_result = self.spake2p.verify(ca);
        let success = verify_result.is_ok();

        let status = match verify_result {
            Ok((local_sessid, peer_sessid, ke)) => {
                // Get the keys
                let mut session_keys = Spake2pSessionKeys::new(); // TODO: MEDIUM BUFFER
                self.crypto
                    .kdf()?
                    .expand(&[], ke, SPAKE2_SESSION_KEYS_INFO, &mut session_keys)
                    .map_err(|_x| ErrorCode::InvalidData)?;

                // Create a session
                let peer_addr = exchange.with_state(|state| {
                    let sess = exchange.id().session(&mut state.sessions);
                    Ok(sess.get_peer_addr())
                })?;

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

                // Complete the reserved session and thus make the `Session` instance
                // immediately available for use by the system.
                //
                // We need to do this _before_ we send the response to the peer, or else we risk missing
                // (dropping) the first messages the peer would send us on the newly-established session,
                // as it might start using it right after it receives the response, while it is still marked
                // as reserved.
                session.complete();

                // Per CHIP `CommissioningWindowManager::OnSessionEstablished`,
                // arm the fail-safe automatically once a PASE session is up so
                // the commissioner can issue `AddTrustedRootCertificate` and
                // friends without first sending `ArmFailSafe` itself. Mirrors
                // `CHIP_DEVICE_CONFIG_FAILSAFE_EXPIRY_LENGTH_SEC` (60s default).
                exchange.with_state(|state| {
                    if !state.failsafe.is_armed() {
                        let session_mode = SessionMode::Pase { fab_idx: 0 };
                        let _ = state.failsafe.arm(
                            crate::failsafe::DEFAULT_FAILSAFE_EXPIRY_SECS,
                            0,
                            &session_mode,
                            &mut state.pase,
                        );
                    }

                    Ok(())
                })?;

                SCStatusCodes::SessionEstablishmentSuccess
            }
            Err(status) => status,
        };

        complete_with_status(exchange, status, &[]).await?;

        Ok(success)
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
        let status = exchange.with_state(|state| {
            if state
                .pase
                .session_timeout
                .as_ref()
                .map(|sd| sd.is_sess_expired(state.pase.epoch))
                .unwrap_or(false)
            {
                state.pase.session_timeout = None;
            }

            if let Some(sd) = state.pase.session_timeout.as_mut() {
                if sd.exch_id != exchange.id() {
                    debug!("Another PAKE session in progress");
                    Ok(Some(SCStatusCodes::Busy))
                } else {
                    state.pase.session_timeout =
                        Some(super::SessionEstTimeout::new(exchange, state.pase.epoch));

                    Ok(None)
                }
            } else if new {
                state.pase.session_timeout =
                    Some(super::SessionEstTimeout::new(exchange, state.pase.epoch));

                Ok(None)
            } else {
                error!("PAKE session not found or expired");
                Ok(Some(SCStatusCodes::SessionNotFound))
            }
        })?;

        if let Some(status) = status {
            complete_with_status(exchange, status, &[]).await?;

            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// Clear the PASE session timeout tracker
    fn clear_session_timeout(&mut self, exchange: &Exchange) -> Result<(), Error> {
        exchange.with_state(|state| {
            state.pase.session_timeout = None;
            Ok(())
        })
    }
}
