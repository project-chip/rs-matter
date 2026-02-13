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

//! PASE Initiator (Commissioner/Controller side) implementation.
//!
//! This module implements the initiator side of the PASE (Passcode-Authenticated Session Establishment)
//! protocol, used by commissioners to establish secure sessions with Matter devices.

use rand_core::RngCore;

use crate::crypto::{
    CanonEcPointRef, Crypto, HmacHash, HmacHashRef, Kdf, AEAD_CANON_KEY_LEN, EC_POINT_ZEROED,
    HMAC_HASH_ZEROED,
};
use crate::error::{Error, ErrorCode};
use crate::sc::pase::spake2p::{
    ProverContext, Spake2P, Spake2pRandom, Spake2pSessionKeys, Spake2pVerifierPasswordRef,
    SPAKE2P_VERIFIER_SALT_LEN,
};
use crate::sc::{complete_with_status, GeneralCode, OpCode, SCStatusCodes, StatusReport};
use crate::tlv::{FromTLV, OctetStr, TLVElement, TagType, ToTLV};
use crate::transport::exchange::Exchange;
use crate::transport::session::{ReservedSession, SessionMode};
use crate::utils::storage::ReadBuf;

use super::{PBKDFParamReq, PBKDFParamResp, Pake1, Pake2, Pake3, SPAKE2_SESSION_KEYS_INFO};

/// PASE Initiator for establishing secure sessions with Matter devices.
///
/// This implements the commissioner/controller side of the PASE protocol.
/// The typical flow is:
///
/// 1. Create an unsecured exchange to the target device
/// 2. Call `PaseInitiator::initiate()` with the setup passcode
/// 3. On success, the exchange's session is upgraded to a secure PASE session
#[allow(unused)]
pub struct PaseInitiator<C: Crypto> {
    crypto: C,
    spake2p: Spake2P,
    initiator_random: Spake2pRandom,
    local_sessid: u16,
    peer_sessid: u16,
    prover_context: Option<ProverContext>,
    ca: HmacHash,
}

impl<C: Crypto> PaseInitiator<C> {
    /// Create a new PASE initiator
    fn new(crypto: C) -> Result<Self, Error> {
        Ok(Self {
            crypto,
            spake2p: Spake2P::new(),
            initiator_random: Spake2pRandom::new(),
            local_sessid: 0,
            peer_sessid: 0,
            prover_context: None,
            ca: HMAC_HASH_ZEROED,
        })
    }

    /// Initiate a PASE handshake with a Matter device.
    ///
    /// This performs the complete PASE handshake:
    /// 1. Send PBKDFParamRequest
    /// 2. Receive PBKDFParamResponse
    /// 3. Send Pake1 (with pA)
    /// 4. Receive Pake2 (with pB, cB)
    /// 5. Send Pake3 (with cA)
    /// 6. Receive StatusReport
    ///
    /// On success, the session is upgraded to a secure PASE session.
    ///
    /// # Arguments
    /// - `exchange` - An unsecured exchange to the target device
    /// - `crypto` - The crypto implementation
    /// - `password` - The setup passcode (typically 8 digits, e.g., 20202021)
    ///
    /// # Returns
    /// - `Ok(())` on successful session establishment
    /// - `Err(Error)` on failure
    #[allow(unused)]
    pub async fn initiate(
        exchange: &mut Exchange<'_>,
        crypto: C,
        password: u32,
    ) -> Result<(), Error> {
        let session = ReservedSession::reserve(exchange.matter(), &crypto).await?;

        let mut initiator = Self::new(crypto)?;

        // Step 1: Send PBKDFParamRequest, receive PBKDFParamResponse
        let (salt, iterations) = match initiator.exchange_pbkdf_params(exchange).await {
            Ok(result) => result,
            Err(e) => {
                // Send status report to notify responder of failure
                let _ = complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await;
                return Err(e);
            }
        };

        // Step 2: Send Pake1, receive Pake2
        if let Err(e) = initiator
            .exchange_pake1_pake2(exchange, password, &salt, iterations)
            .await
        {
            // Send status report to notify responder of failure (e.g., wrong password)
            let _ = complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await;
            return Err(e);
        }

        // Step 3: Send Pake3, receive StatusReport
        // Note: No need to send status report here since we're just receiving one
        initiator.exchange_pake3_status(exchange).await?;

        // Step 4: Complete session establishment
        initiator.complete_session(exchange, session).await
    }

    /// Exchange PBKDFParamRequest/Response
    ///
    /// Returns (salt, iterations) on success
    async fn exchange_pbkdf_params(
        &mut self,
        exchange: &mut Exchange<'_>,
    ) -> Result<([u8; SPAKE2P_VERIFIER_SALT_LEN], u32), Error> {
        // Generate random and session ID
        let mut rand = self.crypto.rand()?;
        rand.fill_bytes(self.initiator_random.access_mut());

        self.local_sessid = exchange
            .matter()
            .transport_mgr
            .session_mgr
            .borrow_mut()
            .get_next_sess_id();

        // Build and send request
        let req = PBKDFParamReq {
            initiator_random: OctetStr::new(self.initiator_random.access()),
            initiator_ssid: self.local_sessid,
            passcode_id: 0,
            has_params: false,
            session_parameters: None,
        };

        // Start context hash with request payload
        let context = {
            let mut context = None;
            exchange
                .send_with(|_, wb| {
                    req.to_tlv(&TagType::Anonymous, &mut *wb)?;

                    context = Some(self.spake2p.start_context(
                        &self.crypto,
                        self.local_sessid,
                        0, // peer_sessid not known yet
                        wb.as_slice(),
                    )?);

                    Ok(Some(OpCode::PBKDFParamRequest.into()))
                })
                .await?;
            context.ok_or(ErrorCode::Invalid)?
        };

        // Receive response
        exchange.recv_fetch().await?;

        let rx = exchange.rx()?;
        let meta = rx.meta();

        // Check for StatusReport (error case)
        if meta.proto_opcode == OpCode::StatusReport as u8 {
            let mut rb = ReadBuf::new(rx.payload());
            let status = StatusReport::read(&mut rb)?;
            error!(
                "PASE failed: general={:?}, proto_code={}",
                status.general_code, status.proto_code
            );
            return Err(ErrorCode::Invalid.into());
        }

        // Verify opcode
        if meta.proto_opcode != OpCode::PBKDFParamResponse as u8 {
            error!(
                "Unexpected opcode: expected PBKDFParamResponse, got {}",
                meta.proto_opcode
            );
            return Err(ErrorCode::InvalidOpcode.into());
        }

        // Parse response
        let resp = PBKDFParamResp::from_tlv(&TLVElement::new(rx.payload()))?;

        // Verify echoed random matches
        if resp.initiator_random.0 != self.initiator_random.access() {
            error!("PBKDFParamResponse: initiator_random mismatch");
            return Err(ErrorCode::Invalid.into());
        }

        // Extract peer session ID
        self.peer_sessid = resp.responder_ssid;

        // Extract PBKDF parameters
        let params = resp.params.ok_or_else(|| {
            error!("PBKDFParamResponse: missing PBKDF params");
            ErrorCode::Invalid
        })?;

        let mut salt = [0u8; SPAKE2P_VERIFIER_SALT_LEN];
        if params.salt.0.len() != SPAKE2P_VERIFIER_SALT_LEN {
            error!(
                "PBKDFParamResponse: invalid salt length {}",
                params.salt.0.len()
            );
            return Err(ErrorCode::Invalid.into());
        }
        salt.copy_from_slice(params.salt.0);

        // Finish context hash with response payload
        self.spake2p.finish_context::<&C>(context, rx.payload())?;

        Ok((salt, params.iterations))
    }

    /// Exchange Pake1/Pake2
    async fn exchange_pake1_pake2(
        &mut self,
        exchange: &mut Exchange<'_>,
        password: u32,
        salt: &[u8],
        iterations: u32,
    ) -> Result<(), Error> {
        // Setup prover and generate pA
        let mut pa = EC_POINT_ZEROED;
        let password_bytes = password.to_le_bytes();
        let password_ref = Spake2pVerifierPasswordRef::new(&password_bytes);

        let prover_ctx =
            self.spake2p
                .setup_prover(&self.crypto, password_ref, salt, iterations, &mut pa)?;

        // Send Pake1
        let pake1 = Pake1 {
            pa: OctetStr::new(pa.access()),
        };

        exchange
            .send_with(|_, wb| {
                pake1.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::PASEPake1.into()))
            })
            .await?;

        // Receive Pake2
        exchange.recv_fetch().await?;

        let rx = exchange.rx()?;
        let meta = rx.meta();

        // Check for StatusReport (error case)
        if meta.proto_opcode == OpCode::StatusReport as u8 {
            let mut rb = ReadBuf::new(rx.payload());
            let status = StatusReport::read(&mut rb)?;
            error!(
                "PASE Pake1 failed: general={:?}, proto_code={}",
                status.general_code, status.proto_code
            );
            return Err(ErrorCode::Invalid.into());
        }

        // Verify opcode
        if meta.proto_opcode != OpCode::PASEPake2 as u8 {
            error!(
                "Unexpected opcode: expected PASEPake2, got {}",
                meta.proto_opcode
            );
            return Err(ErrorCode::InvalidOpcode.into());
        }

        // Parse Pake2
        let pake2 = Pake2::from_tlv(&TLVElement::new(rx.payload()))?;

        // Extract pB and cB
        let pb: CanonEcPointRef<'_> = pake2.pb.0.try_into()?;
        let cb: HmacHashRef<'_> = pake2.cb.0.try_into()?;

        // Complete prover - this verifies cB and computes cA
        let mut ca = HMAC_HASH_ZEROED;
        self.spake2p
            .complete_prover(&self.crypto, &prover_ctx, pa.reference(), pb, cb, &mut ca)
            .map_err(|_| {
                error!("PASE: cB verification failed (wrong password?)");
                ErrorCode::Invalid
            })?;

        // Store cA for Pake3
        self.ca = ca;
        self.prover_context = Some(prover_ctx);

        Ok(())
    }

    /// Exchange Pake3/StatusReport
    async fn exchange_pake3_status(&mut self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        // Send Pake3
        let pake3 = Pake3 {
            ca: OctetStr::new(self.ca.access()),
        };

        exchange
            .send_with(|_, wb| {
                pake3.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::PASEPake3.into()))
            })
            .await?;

        // Receive StatusReport
        exchange.recv_fetch().await?;

        let rx = exchange.rx()?;
        let meta = rx.meta();

        // Verify opcode
        if meta.proto_opcode != OpCode::StatusReport as u8 {
            error!(
                "Unexpected opcode: expected StatusReport, got {}",
                meta.proto_opcode
            );
            return Err(ErrorCode::InvalidOpcode.into());
        }

        // Parse StatusReport
        let mut rb = ReadBuf::new(rx.payload());
        let status = StatusReport::read(&mut rb)?;

        // Check for success
        if status.general_code != GeneralCode::Success
            || status.proto_code != SCStatusCodes::SessionEstablishmentSuccess as u16
        {
            error!(
                "PASE failed: general={:?}, proto_code={}",
                status.general_code, status.proto_code
            );
            return Err(ErrorCode::Invalid.into());
        }

        Ok(())
    }

    /// Complete session establishment
    async fn complete_session(
        &mut self,
        exchange: &mut Exchange<'_>,
        mut session: ReservedSession<'_>,
    ) -> Result<(), Error> {
        // Derive session keys from Ke
        let ke = self.spake2p.ke();

        let mut session_keys = Spake2pSessionKeys::new();
        self.crypto
            .kdf()?
            .expand(&[], ke, SPAKE2_SESSION_KEYS_INFO, &mut session_keys)
            .map_err(|_| ErrorCode::InvalidData)?;

        // Get peer address
        let peer_addr = exchange.with_session(|sess| Ok(sess.get_peer_addr()))?;

        // Split session keys into dec_key, enc_key, att_challenge
        // Note: For initiator, the key order is swapped compared to responder
        // because what we encrypt, they decrypt and vice versa
        let (enc_key, remaining) = session_keys
            .reference()
            .split::<AEAD_CANON_KEY_LEN, { AEAD_CANON_KEY_LEN * 2 }>();
        let (dec_key, att_challenge) = remaining.split::<AEAD_CANON_KEY_LEN, AEAD_CANON_KEY_LEN>();

        // Update session
        session.update(
            0,
            0,
            self.peer_sessid,
            self.local_sessid,
            peer_addr,
            SessionMode::Pase { fab_idx: 0 },
            Some(dec_key),
            Some(enc_key),
            Some(att_challenge),
        )?;

        // Complete the reserved session
        session.complete();

        // Acknowledge the final message
        exchange.acknowledge().await?;

        info!(
            "PASE session established: local_sessid={}, peer_sessid={}",
            self.local_sessid, self.peer_sessid
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf_param_req_encoding() {
        // Basic test that the TLV encoding compiles and works
        let random = [0u8; 32];
        let req = PBKDFParamReq {
            initiator_random: OctetStr::new(&random),
            initiator_ssid: 1234,
            passcode_id: 0,
            has_params: false,
            session_parameters: None,
        };

        let mut buf = [0u8; 128];
        let mut wb = crate::utils::storage::WriteBuf::new(&mut buf);
        req.to_tlv(&TagType::Anonymous, &mut wb).unwrap();

        assert!(wb.as_slice().len() > 0);
    }

    #[test]
    fn test_pake1_encoding() {
        let pa = [0u8; 65];
        let pake1 = Pake1 {
            pa: OctetStr::new(&pa),
        };

        let mut buf = [0u8; 128];
        let mut wb = crate::utils::storage::WriteBuf::new(&mut buf);
        pake1.to_tlv(&TagType::Anonymous, &mut wb).unwrap();

        assert!(wb.as_slice().len() > 0);
    }

    #[test]
    fn test_pake3_encoding() {
        let ca = [0u8; 32];
        let pake3 = Pake3 {
            ca: OctetStr::new(&ca),
        };

        let mut buf = [0u8; 128];
        let mut wb = crate::utils::storage::WriteBuf::new(&mut buf);
        pake3.to_tlv(&TagType::Anonymous, &mut wb).unwrap();

        assert!(wb.as_slice().len() > 0);
    }
}
