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

//! CASE Initiator (Controller side) implementation.
//!
//! This module implements the initiator side of the CASE (Certificate Authenticated Session
//! Establishment) protocol, used by controllers to establish secure sessions with Matter devices.

use core::mem::MaybeUninit;
use core::num::NonZeroU8;

use crate::alloc;
use crate::cert::CertRef;
#[cfg(feature = "case-resumption")]
use crate::crypto::CanonAeadKey;
use crate::crypto::{
    CanonPkcPublicKeyRef, CanonPkcSignature, CanonPkcSignatureRef, Crypto, Hash,
    AEAD_CANON_KEY_LEN, AEAD_TAG_LEN,
};
use crate::error::{Error, ErrorCode};
use crate::sc::{complete_with_status, GeneralCode, OpCode, SCStatusCodes, StatusReport};
use crate::tlv::{get_root_node_struct, FromTLV, OctetStr, TLVElement, TLVTag, TLVWrite};
use crate::transport::exchange::Exchange;
use crate::transport::session::{NocCatIds, ReservedSession, SessionMode};
use crate::utils::init::InitMaybeUninit;
use crate::utils::storage::ReadBuf;

#[cfg(feature = "case-resumption")]
use super::casep::{
    compute_resume_mic, compute_resumption_session_keys, derive_resume_key, verify_resume_mic,
    ResumeKeyKind, RESUME1_MIC_NONCE, RESUME2_MIC_NONCE,
};
use super::casep::{
    CaseP, CaseRandom, CaseRandomRef, CaseSessionKeys, CASE_RESUMPTION_ID_LEN,
    CASE_RESUMPTION_ID_ZEROED,
};
#[cfg(feature = "case-resumption")]
use super::resumption::ResumableSession;
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

/// Sigma2_Resume response, parsed from the responder's message when it
/// accepts a Sigma1-with-Resumption.
#[cfg(feature = "case-resumption")]
#[derive(FromTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1, lifetime = "'a")]
struct Sigma2ResumeMsg<'a> {
    /// The new `ResumptionID` minted by the responder.
    resumption_id: OctetStr<'a>,
    /// The 16-byte AEAD tag over empty plaintext with `S2RK`.
    sigma2_resume_mic: OctetStr<'a>,
    /// The responder's session ID.
    responder_sessid: u16,
    /// Optional responder MRP session parameters. Currently ignored
    /// by rs-matter's initiator side (parity with the non-resumption
    /// Sigma2 path).
    _session_parameters: Option<crate::sc::SessionParameters>,
}

/// CASE Initiator for establishing secure sessions with Matter devices using operational
/// certificates.
///
/// This implements the controller side of the CASE protocol.
/// The typical flow is:
///
/// 1. Create an exchange to the target device over a plaintext session
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
    /// Create a new CASE initiator
    const fn new(peer_node_id: u64) -> Self {
        Self {
            casep: CaseP::new(),
            peer_node_id,
            secret_key: None,
        }
    }

    /// Perform a CASE handshake with a Matter device.
    ///
    /// This performs the complete CASE handshake:
    /// 1. Send Sigma1 (initiator_random, session_id, destination_id, eph_pub_key)
    /// 2. Receive Sigma2 (responder_random, session_id, eph_pub_key, encrypted TBE2)
    /// 3. Send Sigma3 (encrypted TBE3)
    /// 4. Receive StatusReport
    ///
    /// On success, a new secure CASE session is established with the target device.
    ///
    /// # Arguments
    /// - `exchange` - An exchange to the target device over a plaintext session
    /// - `crypto` - The crypto implementation
    /// - `fab_idx` - The fabric index to use for the handshake
    /// - `peer_node_id` - The node ID of the target device
    pub async fn perform(
        mut exchange: Exchange<'_>,
        crypto: &'a C,
        fab_idx: NonZeroU8,
        peer_node_id: u64,
    ) -> Result<(), Error> {
        // Step 1: Reserve a session slot
        let mut session = ReservedSession::reserve(exchange.matter(), crypto).await?;

        let mut initiator = Self::new(peer_node_id);

        // Step 1a: Look up any cached CASE session resumption record for
        // this peer. If present, we'll ask the responder for resumption
        // by populating tags 6 and 7 on Sigma1; the responder either
        // returns Sigma2_Resume (accepted) or Sigma2 (fell back to the
        // full handshake) — both are handled below.
        //
        // Without the `case-resumption` feature there is no cache, so we
        // never offer resumption and always run the full handshake.
        #[cfg(feature = "case-resumption")]
        let cached_record: Option<ResumableSession> = exchange.with_state(|state| {
            Ok(state
                .resumption
                .find_by_peer(fab_idx, peer_node_id)
                .cloned())
        })?;

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

        // Step 2a: If we have a cached resumption record, precompute
        // `Resume1MIC` so it can be spliced into Sigma1 below.
        // `initiator_random` is available now (produced by
        // `start_initiator`), so we can already derive `S1RK`.
        //
        // Without `case-resumption` these are always `(None, None)`, so the
        // Sigma1 built below carries no resumption fields.
        #[allow(clippy::type_complexity)]
        let (resume_rid_bytes, resume_mic_bytes): (
            Option<[u8; CASE_RESUMPTION_ID_LEN]>,
            Option<[u8; AEAD_TAG_LEN]>,
        );
        #[cfg(feature = "case-resumption")]
        {
            (resume_rid_bytes, resume_mic_bytes) = if let Some(ref record) = cached_record {
                let mut s1rk = CanonAeadKey::new();
                derive_resume_key(
                    crypto,
                    ResumeKeyKind::S1rk,
                    record.shared_secret.reference(),
                    random.reference(),
                    record.resumption_id.reference(),
                    &mut s1rk,
                )?;

                let mut mic = [0u8; AEAD_TAG_LEN];
                compute_resume_mic(crypto, s1rk.reference(), RESUME1_MIC_NONCE, &mut mic)?;

                (Some(*record.resumption_id.reference().access()), Some(mic))
            } else {
                (None, None)
            };
        }
        #[cfg(not(feature = "case-resumption"))]
        {
            (resume_rid_bytes, resume_mic_bytes) = (None, None);
        }

        // Step 3: Build and send Sigma1
        let mut tt_updated = false;
        exchange
            .send_with(|_, tw| {
                tw.start_struct(&TLVTag::Anonymous)?;
                tw.str(&TLVTag::Context(1), random.access())?;
                tw.u16(&TLVTag::Context(2), local_sessid)?;
                tw.str(&TLVTag::Context(3), dest_id.access())?;
                tw.str(&TLVTag::Context(4), initiator.casep.our_pub_key().access())?;

                // Sigma1 with Resumption: attach the cached `resumptionID`
                // (tag 6) and the freshly-computed `Resume1MIC` (tag 7).
                if let (Some(rid), Some(mic)) =
                    (resume_rid_bytes.as_ref(), resume_mic_bytes.as_ref())
                {
                    tw.str(&TLVTag::Context(6), rid)?;
                    tw.str(&TLVTag::Context(7), mic)?;
                }

                tw.end_container()?;

                if !tt_updated {
                    initiator.casep.update_tt(tw.as_slice())?;
                    tt_updated = true;
                }

                Ok(Some(OpCode::CASESigma1.into()))
            })
            .await?;

        // Step 4: Receive Sigma2, Sigma2_Resume, or an error StatusReport
        exchange.recv_fetch().await?;

        let response_opcode = exchange.rx()?.meta().proto_opcode;

        if response_opcode == OpCode::StatusReport as u8 {
            let rx = exchange.rx()?;
            let mut rb = ReadBuf::new(rx.payload());
            let status = StatusReport::read(&mut rb)?;
            error!(
                "CASE Sigma1 failed: general={:?}, proto_code={}",
                status.general_code, status.proto_code
            );
            return Err(ErrorCode::Invalid.into());
        }

        // We only ever offer resumption when `case-resumption` is on, so a
        // spec-compliant responder never sends Sigma2_Resume otherwise; the
        // branch (and its `finalize_sigma2_resume`) is compiled out.
        #[cfg(feature = "case-resumption")]
        if response_opcode == OpCode::CASESigma2Resume as u8 {
            // Responder accepted our resumption request. Complete it
            // via `finalize_sigma2_resume`. If we didn't request
            // resumption, this response is a spec violation and we
            // reject with `InvalidParameter`.
            let Some(record) = cached_record else {
                error!("Responder sent Sigma2_Resume but we did not request resumption");
                complete_with_status(&mut exchange, SCStatusCodes::InvalidParameter, &[]).await?;
                return Err(ErrorCode::Invalid.into());
            };

            return Self::finalize_sigma2_resume(
                &mut exchange,
                crypto,
                session,
                fab_idx,
                local_sessid,
                record,
                random,
            )
            .await;
        }

        if response_opcode != OpCode::CASESigma2 as u8 {
            error!(
                "Unexpected opcode: expected CASESigma2 or CASESigma2Resume, got {}",
                response_opcode
            );
            return Err(ErrorCode::InvalidOpcode.into());
        }

        // Step 5: Decrypt Sigma2 TBE and validate
        // `peer_resumption_id` (the responder's ResumptionID from TBEData2,
        // spec-mandated in full CASE) is only consumed to seed the resumption
        // cache, so it is unused when `case-resumption` is off.
        #[cfg_attr(not(feature = "case-resumption"), allow(unused_variables))]
        let (peer_catids, peer_resumption_id) = {
            let rx = exchange.rx()?;
            let raw_sigma2_payload = rx.payload();

            let sigma2 = Sigma2Resp::from_tlv(&get_root_node_struct(raw_sigma2_payload)?)?;

            let result = exchange.with_state(|state| {
                // Copy encrypted2 to a mutable stack buffer for in-place decryption
                let mut encrypted2_buf = alloc!([0u8; CASE_LARGE_BUF_SIZE]); // TODO LARGE BUFFER

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

                let mut tmp_buf = alloc!([0u8; CASE_LARGE_BUF_SIZE]); // TODO LARGE BUFFER
                initiator
                    .casep
                    .validate_certs(
                        crypto,
                        state.rtc.utc_time(),
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
                complete_with_status(&mut exchange, SCStatusCodes::InvalidParameter, &[]).await?;
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
                Some(initiator.casep.shared_secret()),
            )?;
        }

        session.complete();

        exchange.acknowledge().await?;

        // Seed the resumption cache with this freshly-established full
        // CASE session so a subsequent handshake with the same peer can
        // attempt resumption. The `resumption_id` came from `TBEData2`
        // in Sigma2 (`peer_resumption_id`); `SharedSecret`, peer id and
        // peer CATs are what we just committed to the `Session`.
        #[cfg(feature = "case-resumption")]
        {
            exchange.with_state(|state| {
                state.resumption.insert_or_update(ResumableSession {
                    fab_idx,
                    peer_nodeid: peer_node_id,
                    peer_cat_ids: peer_catids,
                    resumption_id: peer_resumption_id,
                    shared_secret: crate::crypto::CanonPkcSharedSecret::new_from_ref(
                        initiator.casep.shared_secret(),
                    ),
                });
                Ok::<_, Error>(())
            })?;
            exchange.matter().transport().notify_resumption_dirty();
        }

        info!(
            "CASE session established: local_sessid={}, peer_sessid={}",
            initiator.casep.local_sessid(),
            initiator.casep.peer_sessid()
        );

        Ok(())
    }

    /// Complete a CASE resumption from the initiator side, given that
    /// we have just received a `Sigma2_Resume` in response to a Sigma1
    /// that carried the resumption fields.
    ///
    /// On success:
    /// - Derives the resumption session keys.
    /// - Populates the reserved session (rotating the `SharedSecret`
    ///   into place along with the new keys).
    /// - Marks the session live via `session.complete()`.
    /// - Sends `SigmaFinished` (a StatusReport with
    ///   `SessionEstablishmentSuccess`) which piggybacks the MRP ack
    ///   for `Sigma2_Resume`, concluding the exchange.
    /// - Rotates the cache entry: same peer, same `SharedSecret`, new
    ///   `resumption_id`.
    ///
    /// On `Resume2MIC` verification failure the initiator sends
    /// `InvalidParameter` per Matter spec and returns an error; the
    /// reserved session is dropped uncomitted.
    ///
    /// Compiled only with the `case-resumption` feature.
    #[cfg(feature = "case-resumption")]
    #[allow(clippy::too_many_arguments)]
    async fn finalize_sigma2_resume(
        exchange: &mut Exchange<'_>,
        crypto: &'a C,
        mut session: ReservedSession<'_>,
        fab_idx: NonZeroU8,
        local_sessid: u16,
        record: ResumableSession,
        initiator_random: &CaseRandom,
    ) -> Result<(), Error> {
        // ---- Parse Sigma2_Resume, copy out fields. ---------------------
        //
        // Same borrow-scoping pattern as the responder path: the parsed
        // message borrows from the RX buffer, so we copy the small
        // pieces out into stack storage and let the borrow drop before
        // we send the SigmaFinished status report.
        let (new_rid, resume2_mic, peer_sessid) = {
            let payload = exchange.rx()?.payload();
            let msg = Sigma2ResumeMsg::from_tlv(&get_root_node_struct(payload)?)?;

            if msg.resumption_id.0.len() != CASE_RESUMPTION_ID_LEN
                || msg.sigma2_resume_mic.0.len() != AEAD_TAG_LEN
            {
                error!(
                    "Sigma2_Resume: bad field length \
                     (resumption_id={}, sigma2_resume_mic={})",
                    msg.resumption_id.0.len(),
                    msg.sigma2_resume_mic.0.len()
                );
                complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await?;
                return Err(ErrorCode::Invalid.into());
            }

            let rid_bytes: &[u8; CASE_RESUMPTION_ID_LEN] = msg
                .resumption_id
                .0
                .try_into()
                .map_err(|_| ErrorCode::InvalidData)?;
            let mut new_rid = CASE_RESUMPTION_ID_ZEROED;
            new_rid.load_from_array(rid_bytes);

            let mut mic = [0u8; AEAD_TAG_LEN];
            mic.copy_from_slice(msg.sigma2_resume_mic.0);

            (new_rid, mic, msg.responder_sessid)
        };

        // ---- Derive S2RK and verify Resume2MIC. -----------------------
        let mut s2rk = CanonAeadKey::new();
        derive_resume_key(
            crypto,
            ResumeKeyKind::S2rk,
            record.shared_secret.reference(),
            initiator_random.reference(),
            new_rid.reference(),
            &mut s2rk,
        )?;

        if verify_resume_mic(crypto, s2rk.reference(), RESUME2_MIC_NONCE, &resume2_mic).is_err() {
            error!("Sigma2_Resume: Resume2MIC verify failed");
            complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await?;
            return Err(ErrorCode::Invalid.into());
        }

        // ---- Derive resumption session keys. --------------------------
        let mut session_keys = MaybeUninit::<CaseSessionKeys>::uninit();
        let session_keys = session_keys.init_with(CaseSessionKeys::init());
        // Derive session traffic keys from the resumption ID we sent in
        // Sigma1 (the current ID), not from Sigma2_Resume's rotated ID.
        compute_resumption_session_keys(
            crypto,
            record.shared_secret.reference(),
            initiator_random.reference(),
            record.resumption_id.reference(),
            session_keys,
        )?;

        // As initiator: enc_key = I2R, dec_key = R2I (mirror of the
        // Sigma3 path — see the fall-through branch above).
        let (enc_key, remaining) = session_keys
            .reference()
            .split::<AEAD_CANON_KEY_LEN, { AEAD_CANON_KEY_LEN * 2 }>();
        let (dec_key, att_challenge) = remaining.split::<AEAD_CANON_KEY_LEN, AEAD_CANON_KEY_LEN>();

        // ---- Populate the reserved session with new keys + secret. ----
        let (peer_addr, local_nodeid) = exchange.with_state(|state| {
            let sess = exchange.id().session(&mut state.sessions);
            let fabric = state.fabrics.fabric(fab_idx)?;
            Ok((sess.get_peer_addr(), fabric.node_id()))
        })?;

        session.update(
            local_nodeid,
            record.peer_nodeid,
            peer_sessid,
            local_sessid,
            peer_addr,
            SessionMode::Case {
                fab_idx: record.fab_idx,
                cat_ids: record.peer_cat_ids,
            },
            Some(dec_key),
            Some(enc_key),
            Some(att_challenge),
            Some(record.shared_secret.reference()),
        )?;

        // Mark the session live *before* sending SigmaFinished so that
        // if the responder immediately reuses the session for an
        // application message, our receive path can already route it
        // (the responder considers the session live as soon as it
        // receives SigmaFinished).
        session.complete();

        // ---- Send SigmaFinished (piggybacks MRP ack for Sigma2_Resume).
        complete_with_status(exchange, SCStatusCodes::SessionEstablishmentSuccess, &[]).await?;

        // ---- Rotate the cache entry. ----------------------------------
        //
        // `SharedSecret` and peer identity are unchanged; only
        // `resumption_id` rotates. `insert_or_update` refreshes the
        // existing record for this peer and moves it to the tail (MRU).
        exchange.with_state(|state| {
            state.resumption.insert_or_update(ResumableSession {
                fab_idx: record.fab_idx,
                peer_nodeid: record.peer_nodeid,
                peer_cat_ids: record.peer_cat_ids,
                resumption_id: new_rid,
                shared_secret: record.shared_secret.clone(),
            });
            Ok::<_, Error>(())
        })?;
        exchange.matter().transport().notify_resumption_dirty();

        info!(
            "CASE session resumed (initiator): local_sessid={}, peer_sessid={}, \
             fabric={}, peer_nodeid=0x{:x}",
            local_sessid,
            peer_sessid,
            record.fab_idx.get(),
            record.peer_nodeid,
        );

        Ok(())
    }
}
