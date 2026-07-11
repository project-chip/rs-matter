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

use core::{mem::MaybeUninit, num::NonZeroU8};

use rand_core::RngCore;

use super::casep::{
    compute_resume_mic, compute_resumption_session_keys, derive_resume_key, verify_resume_mic,
    CaseP, CaseRandom, CaseResumptionId, CaseSessionKeys, ResumeKeyKind, CASE_RANDOM_LEN,
    CASE_RESUMPTION_ID_LEN, RESUME1_MIC_NONCE, RESUME2_MIC_NONCE,
};
use super::resumption::ResumableSession;
use super::CASE_LARGE_BUF_SIZE;
use crate::alloc;
use crate::cert::CertRef;
use crate::crypto::{
    CanonAeadKey, CanonPkcSignature, CanonPkcSignatureRef, Crypto, Hash, AEAD_CANON_KEY_LEN,
    AEAD_TAG_LEN,
};
use crate::error::{Error, ErrorCode};
use crate::sc::{
    check_opcode, complete_with_status, sc_write, GeneralCode, OpCode, SCStatusCodes,
    SessionParameters, StatusReport,
};
use crate::tlv::{get_root_node_struct, FromTLV, OctetStr, TLVElement, TLVTag, TLVWrite, ToTLV};
use crate::transport::exchange::Exchange;
use crate::transport::session::{NocCatIds, ReservedSession, SessionMode};
use crate::utils::init::{init, Init, InitMaybeUninit};
use crate::utils::storage::ReadBuf;

/// Sigma1 Request structure
#[derive(FromTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1, lifetime = "'a")]
struct Sigma1Req<'a> {
    /// The initiator's random value
    initiator_random: OctetStr<'a>,
    /// The initiator's session ID
    initiator_sessid: u16,
    /// The destination ID
    dest_id: OctetStr<'a>,
    /// The peer's public key
    peer_pub_key: OctetStr<'a>,
    /// Session parameters (optional)
    session_parameters: Option<SessionParameters>,
    /// Resumption ID (optional)
    resumption_id: Option<OctetStr<'a>>,
    /// Initiator Resume MIC (optional)
    initiator_resume_mic: Option<OctetStr<'a>>,
}

/// Sigma3 Decrypt structure
#[derive(FromTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1, lifetime = "'a")]
struct Sigma3Decrypt<'a> {
    /// The initiator's Node Operational Certificate
    initiator_noc: OctetStr<'a>,
    /// The initiator's Intermediate Certificate Authority Certificate (optional)
    initiator_icac: Option<OctetStr<'a>>,
    /// The signature
    signature: OctetStr<'a>,
}

/// The CASE Responder (device side) handler
pub struct CaseResponder<'a, C: Crypto> {
    crypto: &'a C,
    /// The CASE session state
    casep: CaseP<'a, C>,
}

impl<'a, C: Crypto> CaseResponder<'a, C> {
    /// Create a new `CaseResponder` instance
    #[inline(always)]
    pub const fn new(crypto: &'a C) -> Self {
        Self {
            crypto,
            casep: CaseP::new(),
        }
    }

    /// Return an in-place initializer for `CaseResponder`
    pub fn init(crypto: &'a C) -> impl Init<Self> {
        init!(Self {
            crypto,
            casep <- CaseP::init(),
        })
    }

    /// Handle the CASE protocol exchange, where the other peer is the exchange initiator.
    ///
    /// Consumes the exchange: on return the CASE handshake has either
    /// completed, been rejected, or aborted, and the exchange is dropped.
    pub async fn handle(&mut self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        let mut session = ReservedSession::reserve(exchange.matter(), self.crypto).await?;

        // Attempt session resumption first. If the peer's Sigma1 carries
        // both `resumptionID` and `initiatorResumeMIC`, we have a cached
        // record for that resumption id, and the MIC checks out, this
        // shortcuts to Sigma2_Resume + SigmaFinished. Any other case
        // (fields absent, unknown id, MIC mismatch) falls through to the
        // full Sigma1/2/3 flow.
        if self
            .try_handle_sigma1_resume(&mut exchange, &mut session)
            .await?
        {
            return Ok(());
        }

        self.handle_casesigma1(&mut exchange, &mut session).await?;

        exchange.recv_fetch().await?;

        self.handle_casesigma3(&mut exchange, session).await?;

        exchange.acknowledge().await?;

        Ok(())
    }

    /// Handle the CASE Sigma1 message
    ///
    /// # Arguments
    /// - `exchange` - The exchange to handle the CASE Sigma1 message on
    /// - `session` - The reserved CASE session slot that receives the
    ///   peer's MRP `session_parameters` from Sigma1 so they're in place
    ///   before it transitions to the established CASE session.
    async fn handle_casesigma1(
        &mut self,
        exchange: &mut Exchange<'_>,
        session: &mut ReservedSession<'_>,
    ) -> Result<(), Error> {
        check_opcode(exchange, OpCode::CASESigma1)?;

        let req = Sigma1Req::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;

        // Per Matter spec, `resumptionID` and `initiatorResumeMIC` must
        // either both be present or both be absent. A mismatched pair
        // is malformed and the responder rejects it with
        // `INVALID_PARAMETER`.
        if req.resumption_id.is_some() != req.initiator_resume_mic.is_some() {
            error!("Sigma1 has mismatched resumptionID/initiatorResumeMIC presence; rejecting");
            complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await?;

            return Ok(());
        }

        let local_fabric_idx = exchange.with_state(|state| {
            Ok(state
                .fabrics
                .get_by_dest_id(self.crypto, req.initiator_random.0, req.dest_id.0)
                .map(|fabric| fabric.fab_idx()))
        })?;

        if local_fabric_idx.is_none() {
            error!("Fabric Index mismatch");
            complete_with_status(exchange, SCStatusCodes::NoSharedTrustRoots, &[]).await?;

            return Ok(());
        }

        let local_sessid = exchange.with_state(|state| Ok(state.sessions.get_next_sess_id()))?;

        let mut our_random = MaybeUninit::<CaseRandom>::uninit(); // TODO MEDIUM BUFFER
        let our_random = our_random.init_with(CaseRandom::init());

        let mut resumption_id = MaybeUninit::<CaseResumptionId>::uninit(); // TODO MEDIUM BUFFER
        let resumption_id = resumption_id.init_with(CaseResumptionId::init());

        let mut tt_hash = MaybeUninit::<Hash>::uninit(); // TODO MEDIUM BUFFER
        let tt_hash = tt_hash.init_with(Hash::init());

        self.casep.start(
            self.crypto,
            req.initiator_sessid,
            local_sessid,
            unwrap!(local_fabric_idx).get(),
            req.peer_pub_key.0.try_into()?,
            exchange.rx()?.payload(),
            our_random,
            resumption_id,
            tt_hash,
        )?;

        // Stash the initiator's advertised MRP `session_parameters`
        // so the responder uses the peer's SAI as the retransmission
        // base interval for Sigma2 and any post-handshake traffic. We
        // apply them both to the unsecured session that the handshake
        // currently rides on (so Sigma2 retransmits use them) and to
        // the reserved CASE session that takes over after Sigma3.
        if let Some(params) = req.session_parameters.as_ref() {
            exchange.with_state(|state| {
                exchange
                    .id()
                    .session(&mut state.sessions)
                    .set_peer_session_params(params);
                Ok(())
            })?;
            session.set_peer_session_params(params)?;
        }

        trace!(
            "Destination ID matched to fabric index {}",
            self.casep.local_fabric_idx()
        );

        let mut tt_updated = false;
        exchange
            .send_with(|exchange, tw| {
                exchange.with_state(|state| {
                    let fabric = NonZeroU8::new(self.casep.local_fabric_idx())
                        .and_then(|fabric_idx| state.fabrics.get(fabric_idx));

                    let Some(fabric) = fabric else {
                        return sc_write(tw, SCStatusCodes::NoSharedTrustRoots, &[]);
                    };

                    let mut signature = MaybeUninit::<CanonPkcSignature>::uninit(); // TODO MEDIUM BUFFER
                    let signature = signature.init_with(CanonPkcSignature::init());

                    // Use the remainder of the TX buffer as scratch space for computing the signature
                    let sign_buf = tw.empty_as_mut_slice();

                    self.casep.compute_sigma2_signature(
                        self.crypto,
                        fabric,
                        sign_buf,
                        signature,
                    )?;

                    tw.start_struct(&TLVTag::Anonymous)?;
                    tw.str(&TLVTag::Context(1), our_random.access())?;
                    tw.u16(&TLVTag::Context(2), local_sessid)?;
                    tw.str(&TLVTag::Context(3), self.casep.our_pub_key().access())?;

                    tw.str_cb(&TLVTag::Context(4), |buf| {
                        self.casep.sigma2_encrypt(
                            self.crypto,
                            fabric,
                            our_random.reference(),
                            tt_hash.reference(),
                            signature.reference(),
                            resumption_id.reference(),
                            buf,
                        )
                    })?;

                    // Responder session parameters (tag 5)
                    let session_params = crate::sc::SessionParameters {
                        max_paths_per_invoke: Some(
                            exchange.matter().dev_det().max_paths_per_invoke,
                        ),
                        ..Default::default()
                    };
                    session_params.to_tlv(&TLVTag::Context(5), &mut *tw)?;

                    tw.end_container()?;

                    if !tt_updated {
                        self.casep.update_tt(tw.as_slice())?;
                        tt_updated = true;
                    }

                    Ok(Some(OpCode::CASESigma2.into()))
                })
            })
            .await
    }

    /// Handle the CASE Sigma3 message
    ///
    /// # Arguments
    /// - `exchange` - The exchange to handle the CASE Sigma3 message on
    /// - `session` - The reserved session to complete upon successful CASE handshake
    async fn handle_casesigma3(
        &mut self,
        exchange: &mut Exchange<'_>,
        mut session: ReservedSession<'_>,
    ) -> Result<(), Error> {
        check_opcode(exchange, OpCode::CASESigma3)?;

        let status = exchange.with_state(|state| {
            let sess = exchange.id().session(&mut state.sessions);

            let fabric = NonZeroU8::new(self.casep.local_fabric_idx())
                .and_then(|fabric_idx| state.fabrics.get(fabric_idx));
            if let Some(fabric) = fabric {
                // A malformed or corrupted Sigma3 — bad TLV at the outer
                // wrapper, an oversized `TBEData3Encrypted` field, AEAD auth
                // failure, or a decrypted payload that doesn't parse — must
                // be reported back to the peer with `INVALID_PARAMETER`
                // rather than silently abandoning the exchange (TC-SC-3.4
                // step 5 covers this).
                let req = match get_root_node_struct(exchange.rx()?.payload()) {
                    Ok(req) => req,
                    Err(e) => {
                        error!("Sigma3 outer TLV parse failed: {}", e);
                        return Ok(SCStatusCodes::InvalidParameter);
                    }
                };
                let encrypted = match req.structure().and_then(|s| s.ctx(1)).and_then(|c| c.str()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Sigma3 encrypted field parse failed: {}", e);
                        return Ok(SCStatusCodes::InvalidParameter);
                    }
                };

                let mut decrypted = alloc!([0; CASE_LARGE_BUF_SIZE]); // TODO LARGE BUFFER
                if encrypted.len() > decrypted.len() {
                    error!(
                        "Encrypted Sigma3 data too large ({} bytes)",
                        encrypted.len()
                    );
                    return Ok(SCStatusCodes::InvalidParameter);
                }

                let decrypted = &mut decrypted[..encrypted.len()];
                decrypted.copy_from_slice(encrypted);

                let len =
                    match self
                        .casep
                        .sigma3_decrypt(self.crypto, fabric.ipk().op_key(), decrypted)
                    {
                        Ok(len) => len,
                        Err(e) => {
                            error!("Sigma3 AEAD decrypt failed: {}", e);
                            return Ok(SCStatusCodes::InvalidParameter);
                        }
                    };
                let decrypted = &decrypted[..len];
                let decrypted_req: Sigma3Decrypt<'_> = match get_root_node_struct(decrypted)
                    .and_then(|n| Sigma3Decrypt::from_tlv(&n))
                {
                    Ok(req) => req,
                    Err(e) => {
                        error!("Sigma3 decrypted TLV parse failed: {}", e);
                        return Ok(SCStatusCodes::InvalidParameter);
                    }
                };

                let initiator_noc = CertRef::new(TLVElement::new(decrypted_req.initiator_noc.0));
                let initiator_icac = decrypted_req
                    .initiator_icac
                    .map(|icac| CertRef::new(TLVElement::new(icac.0)));

                let mut buf = alloc!([0; CASE_LARGE_BUF_SIZE]); // TODO LARGE BUFFER
                let buf = &mut buf[..];
                if let Err(e) = self.casep.validate_certs(
                    self.crypto,
                    state.rtc.utc_time(),
                    fabric,
                    &initiator_noc,
                    initiator_icac.as_ref(),
                    buf,
                ) {
                    error!("Certificate Chain doesn't match: {}", e);
                    Ok(SCStatusCodes::InvalidParameter)
                } else if let Err(e) = self.casep.validate_peer_tbs_signature(
                    self.crypto,
                    decrypted_req.initiator_noc.0,
                    decrypted_req.initiator_icac.map(|a| a.0),
                    &initiator_noc,
                    CanonPkcSignatureRef::try_new(decrypted_req.signature.0)?,
                    buf,
                ) {
                    error!("Sigma3 Signature doesn't match: {}", e);
                    Ok(SCStatusCodes::InvalidParameter)
                } else {
                    // Only now do we add this message to the TT Hash
                    let mut peer_catids: NocCatIds = Default::default();
                    initiator_noc.get_cat_ids(&mut peer_catids)?;
                    self.casep.update_tt(exchange.rx()?.payload())?;

                    let mut session_keys = MaybeUninit::<CaseSessionKeys>::uninit(); // TODO MEDIM BUFFER
                    let session_keys = session_keys.init_with(CaseSessionKeys::init());
                    self.casep.compute_session_keys(
                        self.crypto,
                        fabric.ipk().op_key(),
                        session_keys,
                    )?;

                    let peer_addr = sess.get_peer_addr();

                    let (dec_key, remaining) = session_keys
                        .reference()
                        .split::<AEAD_CANON_KEY_LEN, { AEAD_CANON_KEY_LEN * 2 }>();
                    let (enc_key, att_challenge) =
                        remaining.split::<AEAD_CANON_KEY_LEN, AEAD_CANON_KEY_LEN>();

                    session.update_with_state(
                        state,
                        fabric.node_id(),
                        initiator_noc.get_node_id()?,
                        self.casep.peer_sessid(),
                        self.casep.local_sessid(),
                        peer_addr,
                        SessionMode::Case {
                            // Unwrapping is safe, because if the fabric index was 0, we would not be in here
                            fab_idx: unwrap!(NonZeroU8::new(self.casep.local_fabric_idx())),
                            cat_ids: peer_catids,
                        },
                        Some(dec_key),
                        Some(enc_key),
                        Some(att_challenge),
                        Some(self.casep.shared_secret()),
                    )?;

                    // Seed the resumption cache with this freshly-established
                    // full CASE session so a subsequent handshake with the
                    // same peer can attempt resumption. `SharedSecret`,
                    // fab_idx, peer_nodeid and peer CATs are the same as
                    // what we just loaded into the `Session`; the
                    // `resumption_id` was minted by the responder in
                    // `casep.start` and is still held on `self.casep`.
                    state.resumption.insert_or_update(ResumableSession {
                        // Unwrap is safe: we are inside the `fabric` branch.
                        fab_idx: unwrap!(NonZeroU8::new(self.casep.local_fabric_idx())),
                        peer_nodeid: initiator_noc.get_node_id()?,
                        peer_cat_ids: peer_catids,
                        resumption_id: super::casep::CaseResumptionId::new_from_ref(
                            self.casep.resumption_id(),
                        ),
                        shared_secret: crate::crypto::CanonPkcSharedSecret::new_from_ref(
                            self.casep.shared_secret(),
                        ),
                    });

                    Ok(SCStatusCodes::SessionEstablishmentSuccess)
                }
            } else {
                Ok(SCStatusCodes::NoSharedTrustRoots)
            }
        })?;

        if matches!(status, SCStatusCodes::SessionEstablishmentSuccess) {
            // Complete the reserved session and thus make the `Session` instance
            // immediately available for use by the system.
            //
            // We need to do this _before_ we send the response to the peer, or else we risk missing
            // (dropping) the first messages the peer would send us on the newly-established session,
            // as it might start using it right after it receives the response, while it is still marked
            // as reserved.
            session.complete();

            // The `state.resumption.insert_or_update` call above dirties
            // the cache; wake the background persist task.
            exchange.matter().transport().notify_resumption_dirty();
        }

        complete_with_status(exchange, status, &[]).await
    }

    /// Try to handle the received Sigma1 as a session-resumption
    /// request. Returns:
    ///
    /// - `Ok(true)` — the resumption path fully handled the exchange
    ///   (whether successfully or with the initiator rejecting the
    ///   resumption). The caller must not fall through to the normal
    ///   Sigma1/2/3 flow.
    /// - `Ok(false)` — the Sigma1 does not carry resumption fields, or
    ///   we could not honour the resumption (unknown `resumptionID`,
    ///   MIC verify failed, malformed fields). The caller must continue
    ///   with the full handshake, treating this Sigma1 as if it had no
    ///   resumption fields (per Matter spec's fall-through rule).
    /// - `Err(_)` — a hard error unrelated to resumption (I/O,
    ///   cryptographic backend failure). The exchange is aborted.
    async fn try_handle_sigma1_resume(
        &mut self,
        exchange: &mut Exchange<'_>,
        session: &mut ReservedSession<'_>,
    ) -> Result<bool, Error> {
        check_opcode(exchange, OpCode::CASESigma1)?;

        // ---- Parse Sigma1 and copy out everything we need. -------------
        //
        // The parsed `Sigma1Req` borrows from the RX buffer, and we later
        // need mutable access to the exchange (`send_with`) so we cannot
        // hold that borrow across the send. Copy the small pieces into
        // owned stack storage and let `req` drop before we send.
        let (init_random, init_sessid, incoming_rid, incoming_mic, peer_params) = {
            let payload = exchange.rx()?.payload();
            let req = Sigma1Req::from_tlv(&get_root_node_struct(payload)?)?;

            // Spec: both `resumptionID` and `initiatorResumeMIC` are
            // present, or neither is. If only one is present the outer
            // `handle_casesigma1` will produce INVALID_PARAMETER; we just
            // decline resumption here.
            let (Some(rid), Some(mic)) = (
                req.resumption_id.as_ref(),
                req.initiator_resume_mic.as_ref(),
            ) else {
                return Ok(false);
            };

            if rid.0.len() != CASE_RESUMPTION_ID_LEN || mic.0.len() != AEAD_TAG_LEN {
                // Bad shape — let the full-handshake path reject it.
                return Ok(false);
            }

            let random_bytes: &[u8; CASE_RANDOM_LEN] = req
                .initiator_random
                .0
                .try_into()
                .map_err(|_| ErrorCode::InvalidData)?;
            let mut init_random = CaseRandom::new();
            init_random.load_from_array(random_bytes);

            let rid_bytes: &[u8; CASE_RESUMPTION_ID_LEN] =
                rid.0.try_into().map_err(|_| ErrorCode::InvalidData)?;
            let mut incoming_rid = CaseResumptionId::new();
            incoming_rid.load_from_array(rid_bytes);

            let mut incoming_mic = [0u8; AEAD_TAG_LEN];
            incoming_mic.copy_from_slice(mic.0);

            (
                init_random,
                req.initiator_sessid,
                incoming_rid,
                incoming_mic,
                req.session_parameters.clone(),
            )
        };

        // ---- Look up the cached resumption record. ---------------------
        let record = exchange.with_state(|state| {
            Ok::<_, Error>(
                state
                    .resumption
                    .find_by_resumption_id(incoming_rid.reference().access())
                    .cloned(),
            )
        })?;

        let Some(record) = record else {
            debug!(
                "CASE Sigma1 resumption: no cached record for the requested resumption id; \
                 falling back to full handshake"
            );
            return Ok(false);
        };

        // ---- Derive S1RK and verify Resume1MIC. ------------------------
        let mut s1rk = CanonAeadKey::new();
        derive_resume_key(
            self.crypto,
            ResumeKeyKind::S1rk,
            record.shared_secret.reference(),
            init_random.reference(),
            record.resumption_id.reference(),
            &mut s1rk,
        )?;

        if verify_resume_mic(
            self.crypto,
            s1rk.reference(),
            RESUME1_MIC_NONCE,
            &incoming_mic,
        )
        .is_err()
        {
            debug!(
                "CASE Sigma1 resumption: Resume1MIC verify failed for peer node id \
                 0x{:x} on fabric {}; falling back to full handshake",
                record.peer_nodeid,
                record.fab_idx.get()
            );
            return Ok(false);
        }

        // ---- Mint a new resumption id + derive S2RK + Resume2MIC. ------
        let mut new_rid = CaseResumptionId::new();
        self.crypto.rand()?.fill_bytes(new_rid.access_mut());

        let mut s2rk = CanonAeadKey::new();
        derive_resume_key(
            self.crypto,
            ResumeKeyKind::S2rk,
            record.shared_secret.reference(),
            init_random.reference(),
            new_rid.reference(),
            &mut s2rk,
        )?;

        let mut resume2_mic = [0u8; AEAD_TAG_LEN];
        compute_resume_mic(
            self.crypto,
            s2rk.reference(),
            RESUME2_MIC_NONCE,
            &mut resume2_mic,
        )?;

        // ---- Prepare session context (peer id, IDs, MRP params). -------
        let local_sessid = exchange.with_state(|state| Ok(state.sessions.get_next_sess_id()))?;

        // Apply peer's Sigma1 MRP `session_parameters` to both the
        // unsecured session that carries the handshake (so Sigma2_Resume
        // retransmits use them) and to the reserved session that takes
        // over after SigmaFinished. Mirrors the equivalent block in
        // `handle_casesigma1`.
        if let Some(ref params) = peer_params {
            exchange.with_state(|state| {
                exchange
                    .id()
                    .session(&mut state.sessions)
                    .set_peer_session_params(params);
                Ok::<_, Error>(())
            })?;
            session.set_peer_session_params(params)?;
        }

        // ---- Send Sigma2_Resume. --------------------------------------
        let responder_session_params = SessionParameters {
            max_paths_per_invoke: Some(exchange.matter().dev_det().max_paths_per_invoke),
            ..Default::default()
        };
        let new_rid_bytes: [u8; CASE_RESUMPTION_ID_LEN] = *new_rid.reference().access();

        exchange
            .send_with(|_, tw| {
                tw.start_struct(&TLVTag::Anonymous)?;
                tw.str(&TLVTag::Context(1), &new_rid_bytes)?;
                tw.str(&TLVTag::Context(2), &resume2_mic)?;
                tw.u16(&TLVTag::Context(3), local_sessid)?;
                responder_session_params.to_tlv(&TLVTag::Context(4), &mut *tw)?;
                tw.end_container()?;

                Ok(Some(OpCode::CASESigma2Resume.into()))
            })
            .await?;

        // ---- Derive resumption session keys. --------------------------
        let mut session_keys = MaybeUninit::<CaseSessionKeys>::uninit();
        let session_keys = session_keys.init_with(CaseSessionKeys::init());
        // Derive session traffic keys from the resumption ID carried in
        // Sigma1 (the current ID), not the rotated `new_rid` from
        // Sigma2_Resume.
        compute_resumption_session_keys(
            self.crypto,
            record.shared_secret.reference(),
            init_random.reference(),
            record.resumption_id.reference(),
            session_keys,
        )?;

        // As a responder: dec_key = I2R, enc_key = R2I (mirror of the
        // Sigma3 path in `handle_casesigma3`).
        let (dec_key, remaining) = session_keys
            .reference()
            .split::<AEAD_CANON_KEY_LEN, { AEAD_CANON_KEY_LEN * 2 }>();
        let (enc_key, att_challenge) = remaining.split::<AEAD_CANON_KEY_LEN, AEAD_CANON_KEY_LEN>();

        // ---- Load keys + identity into the reserved session. -----------
        exchange.with_state(|state| {
            let local_nodeid = state
                .fabrics
                .get(record.fab_idx)
                .map(|f| f.node_id())
                .ok_or(ErrorCode::Invalid)?;
            let peer_addr = exchange.id().session(&mut state.sessions).get_peer_addr();

            session.update_with_state(
                state,
                local_nodeid,
                record.peer_nodeid,
                init_sessid,
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
            )
        })?;

        // ---- Wait for SigmaFinished (StatusReport). --------------------
        exchange.recv_fetch().await?;

        let ok = {
            let rx = exchange.rx()?;
            let meta = rx.meta();
            if meta.proto_opcode != OpCode::StatusReport as u8 {
                warn!(
                    "CASE resumption: expected StatusReport after Sigma2_Resume, got {}",
                    meta.proto_opcode
                );
                false
            } else {
                let mut rb = ReadBuf::new(rx.payload());
                match StatusReport::read(&mut rb) {
                    Ok(status)
                        if status.general_code == GeneralCode::Success
                            && status.proto_code
                                == SCStatusCodes::SessionEstablishmentSuccess as u16 =>
                    {
                        true
                    }
                    Ok(status) => {
                        warn!(
                            "CASE resumption: SigmaFinished failed: general={:?}, proto_code={}",
                            status.general_code, status.proto_code
                        );
                        false
                    }
                    Err(e) => {
                        warn!("CASE resumption: failed to parse SigmaFinished: {}", e);
                        false
                    }
                }
            }
        };

        if !ok {
            // Initiator rejected the resumption (or sent a malformed
            // SigmaFinished). The reserved session is dropped by
            // `ReservedSession::drop` since we never call
            // `session.complete()`. Do not fall through to the full
            // handshake: this exchange has already produced Sigma2_Resume.
            exchange.acknowledge().await?;
            return Ok(true);
        }

        // Mark the session live *before* acknowledging SigmaFinished, so
        // that if the initiator races an application-layer message right
        // after its SigmaFinished, the receive path can already route it
        // (mirrors the ordering in `handle_casesigma3`).
        session.complete();
        exchange.acknowledge().await?;

        // ---- Update the cache with the rotated resumption id. ----------
        //
        // `SharedSecret` and peer identity are unchanged; only the
        // `resumption_id` is rotated. `insert_or_update` refreshes the
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
            "CASE session resumed: local_sessid={}, peer_sessid={}, fabric={}, peer_nodeid=0x{:x}",
            local_sessid,
            init_sessid,
            record.fab_idx.get(),
            record.peer_nodeid,
        );

        Ok(true)
    }
}
