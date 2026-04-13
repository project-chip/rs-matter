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

//! CASE Initiator (Controller side) implementation.
//!
//! This module implements the initiator side of the CASE (Certificate Authenticated Session
//! Establishment) protocol, used by controllers to establish secure sessions with Matter devices.

use core::mem::MaybeUninit;
use core::num::NonZeroU8;

use crate::alloc;
use crate::cert::CertRef;
use crate::crypto::{
    CanonPkcPublicKeyRef, CanonPkcSignature, CanonPkcSignatureRef, Crypto, Hash, AEAD_CANON_KEY_LEN,
};
use crate::error::{Error, ErrorCode};
use crate::sc::{complete_with_status, GeneralCode, OpCode, SCStatusCodes, StatusReport};
use crate::tlv::{get_root_node_struct, FromTLV, OctetStr, TLVElement, TLVTag, TLVWrite};
use crate::transport::exchange::Exchange;
use crate::transport::session::{NocCatIds, ReservedSession, SessionMode};
use crate::utils::init::InitMaybeUninit;
use crate::utils::storage::ReadBuf;

use super::casep::{CaseP, CaseRandom, CaseRandomRef, CaseSessionKeys, CASE_RESUMPTION_ID_ZEROED};
use super::CASE_LARGE_BUF_SIZE;

/// Sigma2 Response structure, parsed from the responder's Sigma2 message.
#[derive(FromTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1, lifetime = "'a")]
struct Sigma2Resp<'a> {
    /// The responder's random value
    responder_random: OctetStr<'a>,
    /// The responder's session ID
    responder_sessid: u16,
    /// The responder's ephemeral public key
    responder_eph_pub_key: OctetStr<'a>,
    /// The encrypted TBE2 payload
    encrypted2: OctetStr<'a>,
}

/// Decrypted TBE data from Sigma2
#[derive(FromTLV)]
#[tlvargs(start = 1, lifetime = "'a")]
struct TBEData2Decrypt<'a> {
    responder_noc: OctetStr<'a>,
    responder_icac: Option<OctetStr<'a>>,
    signature: OctetStr<'a>,
    resumption_id: OctetStr<'a>,
}

/// CASE Initiator for establishing secure sessions with Matter devices using operational
/// certificates.
///
/// This implements the controller side of the CASE protocol.
/// The typical flow is:
///
/// 1. Create an exchange to the target device
/// 2. Call `CaseInitiator::initiate()` with the fabric index and peer node ID
/// 3. On success, the exchange's session is upgraded to a secure CASE session
pub struct CaseInitiator<'a, C: Crypto + 'a> {
    casep: CaseP<'a, C>,
    /// The peer's node ID (used to verify responder NOC in process_sigma2)
    peer_node_id: u64,
    /// Our ephemeral secret key (retained from start_initiator for ECDH in process_sigma2)
    secret_key: Option<C::SecretKey<'a>>,
}

impl<'a, C: Crypto + 'a> CaseInitiator<'a, C> {
    /// Initiate a CASE handshake with a Matter device.
    ///
    /// This performs the complete CASE handshake:
    /// 1. Send Sigma1 (initiator_random, session_id, destination_id, eph_pub_key)
    /// 2. Receive Sigma2 (responder_random, session_id, eph_pub_key, encrypted TBE2)
    /// 3. Send Sigma3 (encrypted TBE3)
    /// 4. Receive StatusReport
    ///
    /// On success, the session is upgraded to a secure CASE session.
    ///
    /// # Arguments
    /// - `exchange` - An exchange to the target device
    /// - `crypto` - The crypto implementation
    /// - `fab_idx` - The fabric index to use for the handshake
    /// - `peer_node_id` - The node ID of the target device
    pub async fn initiate(
        exchange: &mut Exchange<'_>,
        crypto: &'a C,
        fab_idx: NonZeroU8,
        peer_node_id: u64,
    ) -> Result<(), Error> {
        // Step 1: Reserve a session slot
        let mut session = ReservedSession::reserve(exchange.matter(), crypto).await?;

        let mut initiator = CaseInitiator {
            casep: CaseP::new(),
            peer_node_id,
            secret_key: None,
        };

        let mut random = MaybeUninit::<CaseRandom>::uninit();
        let random = random.init_with(CaseRandom::init());

        let mut dest_id = MaybeUninit::<Hash>::uninit();
        let dest_id = dest_id.init_with(Hash::init());

        // Step 2: Prepare Sigma1 parameters
        let local_sessid = exchange.with_state(|state| {
            let local_sessid = state.sessions.get_next_sess_id();

            let fabric = state.fabrics.fabric(fab_idx)?;

            let secret_key = initiator.casep.start_initiator(
                crypto,
                fabric,
                peer_node_id,
                local_sessid,
                random,
                dest_id,
            )?;

            initiator.secret_key = Some(secret_key);

            Ok(local_sessid)
        })?;

        // Step 3: Build and send Sigma1
        let mut tt_updated = false;
        exchange
            .send_with(|_, tw| {
                tw.start_struct(&TLVTag::Anonymous)?;
                tw.str(&TLVTag::Context(1), random.access())?;
                tw.u16(&TLVTag::Context(2), local_sessid)?;
                tw.str(&TLVTag::Context(3), dest_id.access())?;
                tw.str(&TLVTag::Context(4), initiator.casep.our_pub_key().access())?;
                tw.end_container()?;

                if !tt_updated {
                    initiator.casep.update_tt(tw.as_slice())?;
                    tt_updated = true;
                }

                Ok(Some(OpCode::CASESigma1.into()))
            })
            .await?;

        // Step 4: Receive Sigma2
        exchange.recv_fetch().await?;

        {
            let rx = exchange.rx()?;
            let meta = rx.meta();

            // Check for StatusReport error first
            if meta.proto_opcode == OpCode::StatusReport as u8 {
                let mut rb = ReadBuf::new(rx.payload());
                let status = StatusReport::read(&mut rb)?;
                error!(
                    "CASE Sigma1 failed: general={:?}, proto_code={}",
                    status.general_code, status.proto_code
                );
                return Err(ErrorCode::Invalid.into());
            }

            // Verify opcode is CASESigma2
            if meta.proto_opcode != OpCode::CASESigma2 as u8 {
                error!(
                    "Unexpected opcode: expected CASESigma2, got {}",
                    meta.proto_opcode
                );
                return Err(ErrorCode::InvalidOpcode.into());
            }
        }

        // Step 5: Decrypt Sigma2 TBE and validate
        let (peer_catids, _resumption_id) = {
            let rx = exchange.rx()?;
            let raw_sigma2_payload = rx.payload();

            let sigma2 = Sigma2Resp::from_tlv(&get_root_node_struct(raw_sigma2_payload)?)?;

            // Copy encrypted2 to a mutable stack buffer for in-place decryption
            let mut encrypted2_buf = alloc!([0u8; CASE_LARGE_BUF_SIZE]);

            let result = exchange.with_state(|state| {
                if sigma2.encrypted2.0.len() > encrypted2_buf.len() {
                    error!("Sigma2 encrypted data too large");
                    return Err(ErrorCode::BufferTooSmall.into());
                }

                let encrypted2 = &mut encrypted2_buf[..sigma2.encrypted2.0.len()];
                encrypted2.copy_from_slice(sigma2.encrypted2.0);

                let peer_random = CaseRandomRef::try_new(sigma2.responder_random.0)?;
                let peer_sessid = sigma2.responder_sessid;
                let peer_eph_pub_key =
                    CanonPkcPublicKeyRef::try_new(sigma2.responder_eph_pub_key.0)?;

                let fabric = state.fabrics.fabric(fab_idx)?;

                let secret_key = initiator
                    .secret_key
                    .as_ref()
                    .ok_or(ErrorCode::InvalidState)?;

                // Decrypt TBE2 (symmetric with sigma3_decrypt on the responder side)
                let len = initiator
                    .casep
                    .sigma2_decrypt(
                        crypto,
                        fabric,
                        secret_key,
                        raw_sigma2_payload,
                        peer_random,
                        peer_sessid,
                        peer_eph_pub_key,
                        encrypted2,
                    )
                    .inspect_err(|e| {
                        error!("Failed to decrypt Sigma2 TBE: {}", e);
                    })?;

                // Clear the secret key after ECDH
                initiator.secret_key = None;

                let decrypted = &encrypted2[..len];
                let decrypted_data = TBEData2Decrypt::from_tlv(&get_root_node_struct(decrypted)?)?;

                // Validate certificate chain
                let responder_noc = CertRef::new(TLVElement::new(decrypted_data.responder_noc.0));
                let icac_cert = decrypted_data
                    .responder_icac
                    .as_ref()
                    .map(|icac| CertRef::new(TLVElement::new(icac.0)));

                let mut tmp_buf = alloc!([0u8; CASE_LARGE_BUF_SIZE]);
                initiator
                    .casep
                    .validate_certs(
                        crypto,
                        fabric,
                        &responder_noc,
                        icac_cert.as_ref(),
                        &mut tmp_buf[..],
                    )
                    .inspect_err(|e| {
                        error!("Certificate chain doesn't match: {}", e);
                    })?;

                // Verify the responder's node ID matches the expected peer
                if responder_noc.get_node_id()? != initiator.peer_node_id {
                    error!(
                        "Responder node ID doesn't match expected peer: expected {}, got {}",
                        initiator.peer_node_id,
                        responder_noc.get_node_id()?
                    );

                    Err(ErrorCode::Invalid)?;
                }

                // Verify signature
                initiator
                    .casep
                    .validate_peer_tbs_signature(
                        crypto,
                        decrypted_data.responder_noc.0,
                        decrypted_data.responder_icac.map(|a| a.0),
                        &responder_noc,
                        CanonPkcSignatureRef::try_new(decrypted_data.signature.0)?,
                        &mut tmp_buf[..],
                    )
                    .inspect_err(|e| {
                        error!("Sigma2 signature doesn't match: {}", e);
                    })?;

                // Extract CAT IDs
                let mut peer_catids: NocCatIds = Default::default();
                responder_noc.get_cat_ids(&mut peer_catids)?;

                // Capture resumption ID
                let mut resumption_id = CASE_RESUMPTION_ID_ZEROED;
                resumption_id
                    .access_mut()
                    .copy_from_slice(decrypted_data.resumption_id.0);

                Ok((peer_catids, resumption_id))
            });

            if result.is_err() {
                complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await?;
            }

            result
        }?;

        // Step 6: Compute Sigma3 signature (needs fabric borrow, must drop before await)
        let mut signature = MaybeUninit::<CanonPkcSignature>::uninit();
        let signature = signature.init_with(CanonPkcSignature::init());

        exchange.with_state(|state| {
            let fabric = state.fabrics.fabric(fab_idx)?;

            // Use a temporary buffer for the TBS data
            let mut tmp_buf = alloc!([0u8; CASE_LARGE_BUF_SIZE]);
            initiator
                .casep
                .compute_sigma3_signature(crypto, fabric, &mut tmp_buf[..], signature)
        })?;

        // Step 7: Build and send Sigma3
        let mut tt_updated = false;
        exchange
            .send_with(|exchange_ref, tw| {
                exchange_ref.with_state(|state| {
                    let fabric = state.fabrics.fabric(fab_idx)?;

                    tw.start_struct(&TLVTag::Anonymous)?;
                    tw.str_cb(&TLVTag::Context(1), |buf| {
                        initiator
                            .casep
                            .sigma3_encrypt(crypto, fabric, signature.reference(), buf)
                    })?;
                    tw.end_container()?;

                    if !tt_updated {
                        initiator.casep.update_tt(tw.as_slice())?;
                        tt_updated = true;
                    }

                    Ok(Some(OpCode::CASESigma3.into()))
                })
            })
            .await?;

        // Step 8: Receive StatusReport
        exchange.recv_fetch().await?;

        {
            let rx = exchange.rx()?;
            let meta = rx.meta();

            if meta.proto_opcode != OpCode::StatusReport as u8 {
                error!(
                    "Unexpected opcode: expected StatusReport, got {}",
                    meta.proto_opcode
                );
                return Err(ErrorCode::InvalidOpcode.into());
            }

            let mut rb = ReadBuf::new(rx.payload());
            let status = StatusReport::read(&mut rb)?;

            if status.general_code != GeneralCode::Success
                || status.proto_code != SCStatusCodes::SessionEstablishmentSuccess as u16
            {
                error!(
                    "CASE failed: general={:?}, proto_code={}",
                    status.general_code, status.proto_code
                );
                return Err(ErrorCode::Invalid.into());
            }
        }

        // Step 9: Derive session keys and complete the session
        {
            let mut session_keys = MaybeUninit::<CaseSessionKeys>::uninit();
            let session_keys = session_keys.init_with(CaseSessionKeys::init());

            let (peer_addr, local_node_id) = exchange.with_state(|state| {
                let sess = exchange.id().session(&mut state.sessions);

                let fabric = state.fabrics.fabric(fab_idx)?;

                initiator.casep.compute_session_keys(
                    crypto,
                    fabric.ipk().op_key(),
                    session_keys,
                )?;

                Ok((sess.get_peer_addr(), fabric.node_id()))
            })?;

            // For initiator: first key = I2R (enc_key), second = R2I (dec_key)
            let (enc_key, remaining) = session_keys
                .reference()
                .split::<AEAD_CANON_KEY_LEN, { AEAD_CANON_KEY_LEN * 2 }>();
            let (dec_key, att_challenge) =
                remaining.split::<AEAD_CANON_KEY_LEN, AEAD_CANON_KEY_LEN>();

            session.update(
                local_node_id,
                peer_node_id,
                initiator.casep.peer_sessid(),
                initiator.casep.local_sessid(),
                peer_addr,
                SessionMode::Case {
                    fab_idx,
                    cat_ids: peer_catids,
                },
                Some(dec_key),
                Some(enc_key),
                Some(att_challenge),
            )?;
        }

        session.complete();

        exchange.acknowledge().await?;

        info!(
            "CASE session established: local_sessid={}, peer_sessid={}",
            initiator.casep.local_sessid(),
            initiator.casep.peer_sessid()
        );

        Ok(())
    }
}
