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
//! This module implements the initiator side of the CASE (Certificate Authenticated
//! Session Establishment) protocol, used by controllers to establish secure sessions
//! with commissioned Matter devices using fabric credentials.

use core::mem::MaybeUninit;
use core::num::NonZeroU8;

use rand_core::RngCore;

use crate::alloc;
use crate::cert::{CertRef, MAX_CERT_TLV_LEN};
use crate::crypto::{
    Aead, AeadNonceRef, CanonAeadKey, CanonAeadKeyRef, CanonPkcPublicKeyRef, CanonPkcSecretKeyRef,
    CanonPkcSignature, CanonPkcSignatureRef, Crypto, CryptoSensitive, Digest, Kdf, PublicKey,
    SecretKey, SigningSecretKey, AEAD_CANON_KEY_LEN, AEAD_KEY_ZEROED, AEAD_TAG_LEN,
    AEAD_TAG_ZEROED, HASH_LEN, HASH_ZEROED, PKC_CANON_PUBLIC_KEY_LEN, PKC_PUBLIC_KEY_ZEROED,
    PKC_SHARED_SECRET_ZEROED,
};
use crate::error::{Error, ErrorCode};
use crate::fabric::Fabric;
use crate::sc::{complete_with_status, GeneralCode, OpCode, SCStatusCodes, StatusReport};
use crate::tlv::{get_root_node_struct, FromTLV, OctetStr, TLVElement, TLVTag, TLVWrite};
use crate::transport::exchange::Exchange;
use crate::transport::session::{NocCatIds, ReservedSession, SessionMode};
use crate::utils::init::InitMaybeUninit;
use crate::utils::storage::{ReadBuf, WriteBuf};

use super::casep::{CaseSessionKeys, CASE_RANDOM_LEN};

/// Buffer size for TBE (to-be-encrypted) and TBS (to-be-signed) data.
const CASE_LARGE_BUF_SIZE: usize = MAX_CERT_TLV_LEN * 2 + 224;

/// Sigma2 nonce: "NCASE_Sigma2N" (13 bytes)
const SIGMA2_NONCE: AeadNonceRef = AeadNonceRef::new(&[
    0x4e, 0x43, 0x41, 0x53, 0x45, 0x5f, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x32, 0x4e,
]);

/// Sigma3 nonce: "NCASE_Sigma3N" (13 bytes)
const SIGMA3_NONCE: AeadNonceRef = AeadNonceRef::new(&[
    0x4e, 0x43, 0x41, 0x53, 0x45, 0x5f, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x33, 0x4e,
]);

/// Sigma2 key info: "Sigma2"
const S2K_INFO: [u8; 6] = [0x53, 0x69, 0x67, 0x6d, 0x61, 0x32];

/// Sigma3 key info: "Sigma3"
const S3K_INFO: [u8; 6] = [0x53, 0x69, 0x67, 0x6d, 0x61, 0x33];

/// Session keys info: "SessionKeys"
const SEKEYS_INFO: [u8; 11] = [
    0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x73,
];

/// Sigma2 Response structure (received by initiator)
#[derive(FromTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1, lifetime = "'a")]
struct Sigma2Resp<'a> {
    responder_random: OctetStr<'a>,
    responder_sessid: u16,
    responder_pub_key: OctetStr<'a>,
    encrypted2: OctetStr<'a>,
}

/// Sigma2 decrypted payload structure
#[derive(FromTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1, lifetime = "'a")]
struct Sigma2Decrypt<'a> {
    responder_noc: OctetStr<'a>,
    responder_icac: Option<OctetStr<'a>>,
    signature: OctetStr<'a>,
    resumption_id: OctetStr<'a>,
}

/// Controller credentials needed for CASE session establishment.
///
/// This contains the controller's own fabric identity, used to authenticate
/// to commissioned devices via CASE.
pub struct ControllerCredentials<'a> {
    /// Controller's Node Operational Certificate (TLV encoded)
    pub noc: &'a [u8],
    /// Controller's Intermediate CA Certificate (TLV encoded, optional)
    pub icac: Option<&'a [u8]>,
    /// Root CA certificate (TLV encoded, shared with the device)
    pub root_ca: &'a [u8],
    /// Controller's operational private key
    pub secret_key: CanonPkcSecretKeyRef<'a>,
    /// Identity Protection Key (operational key)
    pub ipk: CanonAeadKeyRef<'a>,
    /// Fabric ID
    pub fabric_id: u64,
    /// Controller's node ID in the fabric
    pub node_id: u64,
    /// Local fabric index (1-based, identifies the fabric in local storage)
    pub fab_idx: NonZeroU8,
}

/// CASE Initiator for establishing secure sessions with commissioned Matter devices.
///
/// This implements the controller side of the CASE protocol. The typical flow is:
///
/// 1. Create an unsecured exchange to the target device
/// 2. Call `CaseInitiator::initiate()` with the controller credentials and peer node ID
/// 3. On success, a secure CASE session is established
///
/// # Example
///
/// ```ignore
/// let creds = ControllerCredentials {
///     noc: &controller_noc,
///     icac: None,
///     root_ca: &root_cert,
///     secret_key: secret_key_ref,
///     ipk: ipk_ref,
///     fabric_id: 1,
///     node_id: 2,
///     fab_idx: NonZeroU8::new(1).unwrap(),
/// };
///
/// CaseInitiator::initiate(&mut exchange, &crypto, &creds, peer_node_id).await?;
/// // Exchange now has a secure CASE session
/// ```
pub struct CaseInitiator;

impl CaseInitiator {
    /// Initiate a CASE handshake with a commissioned Matter device.
    ///
    /// This performs the complete CASE handshake:
    /// 1. Send Sigma1 (with dest_id and ephemeral public key)
    /// 2. Receive Sigma2 (decrypt and verify responder's credentials)
    /// 3. Send Sigma3 (with encrypted controller credentials)
    /// 4. Receive StatusReport
    ///
    /// On success, the session is upgraded to a secure CASE session.
    ///
    /// # Arguments
    /// - `exchange` - An unsecured exchange to the target device
    /// - `crypto` - The crypto implementation
    /// - `creds` - The controller's fabric credentials
    /// - `peer_node_id` - The target device's node ID in the fabric
    pub async fn initiate<C: Crypto>(
        exchange: &mut Exchange<'_>,
        crypto: &C,
        creds: &ControllerCredentials<'_>,
        peer_node_id: u64,
    ) -> Result<(), Error> {
        let mut session = ReservedSession::reserve(exchange.matter(), crypto).await?;

        let local_sessid = exchange.with_state(|state| Ok(state.sessions.get_next_sess_id()))?;

        // Derive the IPK operational key from epoch key + compressed fabric ID.
        // The responder uses the operational key (not the raw epoch key) for
        // dest_id verification and all CASE key derivations (S2K, S3K, session keys).
        let root_tlv = TLVElement::new(creds.root_ca);
        let root_cert = CertRef::new(root_tlv);
        let root_pubkey: CanonPkcPublicKeyRef<'_> = root_cert.pubkey()?.try_into()?;
        let compressed_fabric_id =
            Fabric::compute_compressed_fabric_id(crypto, root_pubkey, creds.fabric_id);

        const GRP_KEY_INFO: &[u8] = &[
            0x47, 0x72, 0x6f, 0x75, 0x70, 0x4b, 0x65, 0x79, 0x20, 0x76, 0x31, 0x2e, 0x30,
        ];
        let mut op_key = MaybeUninit::<CanonAeadKey>::uninit();
        let op_key = op_key.init_with(CanonAeadKey::init());
        crypto
            .kdf()?
            .expand(
                &compressed_fabric_id.to_be_bytes(),
                creds.ipk,
                GRP_KEY_INFO,
                op_key,
            )
            .map_err(|_| ErrorCode::InvalidData)?;

        // Generate ephemeral keypair
        let ephemeral_key = crypto.generate_secret_key()?;
        let mut our_pub_key = PKC_PUBLIC_KEY_ZEROED;
        ephemeral_key.pub_key()?.write_canon(&mut our_pub_key)?;

        // Generate initiator random
        let mut initiator_random = [0u8; CASE_RANDOM_LEN];
        crypto.rand()?.fill_bytes(&mut initiator_random);

        // Compute destination ID: HMAC(IPK_op_key, random || root_pubkey || fabric_id || peer_node_id)
        let mut dest_id = HASH_ZEROED;
        {
            let mut mac = crypto.hmac(op_key.reference())?;
            mac.update(&initiator_random)?;
            mac.update(root_pubkey.access())?;
            mac.update(&creds.fabric_id.to_le_bytes())?;
            mac.update(&peer_node_id.to_le_bytes())?;
            mac.finish(&mut dest_id)?;
        }

        // Start transcript hash
        let mut tt = crypto.hash()?;

        // === Sigma1: Build and send ===
        exchange
            .send_with(|_, wb| {
                wb.start_struct(&TLVTag::Anonymous)?;
                wb.str(&TLVTag::Context(1), &initiator_random)?;
                wb.u16(&TLVTag::Context(2), local_sessid)?;
                wb.str(&TLVTag::Context(3), dest_id.access())?;
                wb.str(&TLVTag::Context(4), our_pub_key.access())?;
                wb.end_container()?;

                // TT = Hash(Sigma1_payload)
                tt.update(wb.as_slice())?;

                Ok(Some(OpCode::CASESigma1.into()))
            })
            .await?;

        // TT hash after Sigma1 — needed for S2K derivation
        let mut tt_hash_after_sigma1 = HASH_ZEROED;
        tt.finish_current(&mut tt_hash_after_sigma1)?;

        // === Sigma2: Receive and process ===
        exchange.recv_fetch().await?;

        {
            let rx = exchange.rx()?;
            let meta = rx.meta();

            if meta.proto_opcode == OpCode::StatusReport as u8 {
                let mut rb = ReadBuf::new(rx.payload());
                let status = StatusReport::read(&mut rb)?;
                error!(
                    "CASE Sigma1 rejected: general={:?}, proto_code={}",
                    status.general_code, status.proto_code
                );
                return Err(ErrorCode::Invalid.into());
            }

            if meta.proto_opcode != OpCode::CASESigma2 as u8 {
                error!("Expected CASESigma2, got opcode {}", meta.proto_opcode);
                return Err(ErrorCode::InvalidOpcode.into());
            }
        }

        let sigma2_payload = exchange.rx()?.payload();
        let resp = Sigma2Resp::from_tlv(&get_root_node_struct(sigma2_payload)?)?;
        let peer_sessid = resp.responder_sessid;

        // Load responder's ephemeral public key
        let mut peer_pub_key = PKC_PUBLIC_KEY_ZEROED;
        peer_pub_key.load(CanonPkcPublicKeyRef::try_new(resp.responder_pub_key.0)?);

        // Derive ECDH shared secret
        let peer_pub = crypto.pub_key(peer_pub_key.reference())?;
        let mut shared_secret = PKC_SHARED_SECRET_ZEROED;
        ephemeral_key.derive_shared_secret(&peer_pub, &mut shared_secret)?;

        // Derive Sigma2 key
        // S2K_salt = IPK || responder_random || responder_pub_key || TT_hash(after Sigma1)
        let mut sigma2_key = AEAD_KEY_ZEROED;
        {
            let mut salt = CryptoSensitive::<
                { AEAD_CANON_KEY_LEN + CASE_RANDOM_LEN + PKC_CANON_PUBLIC_KEY_LEN + HASH_LEN },
            >::new();
            let s = salt.access_mut();
            let mut off = 0;
            s[off..off + AEAD_CANON_KEY_LEN].copy_from_slice(op_key.access());
            off += AEAD_CANON_KEY_LEN;
            s[off..off + resp.responder_random.0.len()].copy_from_slice(resp.responder_random.0);
            off += CASE_RANDOM_LEN;
            s[off..off + PKC_CANON_PUBLIC_KEY_LEN].copy_from_slice(peer_pub_key.access());
            off += PKC_CANON_PUBLIC_KEY_LEN;
            s[off..off + HASH_LEN].copy_from_slice(tt_hash_after_sigma1.access());

            crypto
                .kdf()?
                .expand(
                    salt.access(),
                    shared_secret.reference(),
                    &S2K_INFO,
                    &mut sigma2_key,
                )
                .map_err(|_| ErrorCode::InvalidData)?;
        }

        // Decrypt Sigma2 encrypted payload
        let mut decrypted = alloc!([0; CASE_LARGE_BUF_SIZE]);
        let encrypted = resp.encrypted2.0;
        if encrypted.len() > decrypted.len() {
            error!("Sigma2 encrypted data too large");
            return Err(ErrorCode::BufferTooSmall.into());
        }
        let decrypted = &mut decrypted[..encrypted.len()];
        decrypted.copy_from_slice(encrypted);

        let mut cipher = crypto.aead()?;
        cipher.decrypt_in_place(sigma2_key.reference(), SIGMA2_NONCE, &[], decrypted)?;
        let decrypted_len = decrypted.len() - AEAD_TAG_LEN;
        let decrypted = &decrypted[..decrypted_len];

        let sigma2_inner = Sigma2Decrypt::from_tlv(&get_root_node_struct(decrypted)?)?;

        // Validate responder's certificate chain against our root CA
        let responder_noc = CertRef::new(TLVElement::new(sigma2_inner.responder_noc.0));
        let responder_icac = sigma2_inner
            .responder_icac
            .map(|icac| CertRef::new(TLVElement::new(icac.0)));

        // Check fabric ID matches
        if creds.fabric_id != responder_noc.get_fabric_id()? {
            error!("Responder NOC fabric ID mismatch");
            let _ = complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await;
            return Err(ErrorCode::Invalid.into());
        }

        // Verify certificate chain: NOC -> (ICAC) -> Root CA
        {
            let mut verify_buf = alloc!([0; CASE_LARGE_BUF_SIZE]);
            let verify_buf = &mut verify_buf[..];

            let mut verifier = responder_noc.verify_chain_start(crypto);
            if let Some(ref icac) = responder_icac {
                if let Ok(fid) = icac.get_fabric_id() {
                    if fid != creds.fabric_id {
                        error!("Responder ICAC fabric ID mismatch");
                        let _ =
                            complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[])
                                .await;
                        return Err(ErrorCode::Invalid.into());
                    }
                }
                verifier = verifier.add_cert(icac, verify_buf)?;
            }
            verifier
                .add_cert(&CertRef::new(TLVElement::new(creds.root_ca)), verify_buf)?
                .finalise(verify_buf)?;
        }

        // Verify Sigma2 signature
        // TBS2 = { responder_noc, responder_icac?, responder_pub_key, our_pub_key }
        {
            let mut tbs_buf = alloc!([0; CASE_LARGE_BUF_SIZE]);
            let mut tw = WriteBuf::new(&mut tbs_buf[..]);

            tw.start_struct(&TLVTag::Anonymous)?;
            tw.str(&TLVTag::Context(1), sigma2_inner.responder_noc.0)?;
            if let Some(icac) = sigma2_inner.responder_icac {
                tw.str(&TLVTag::Context(2), icac.0)?;
            }
            tw.str(&TLVTag::Context(3), peer_pub_key.access())?;
            tw.str(&TLVTag::Context(4), our_pub_key.access())?;
            tw.end_container()?;

            let responder_pubkey =
                crypto.pub_key(CanonPkcPublicKeyRef::try_new(responder_noc.pubkey()?)?)?;
            let signature = CanonPkcSignatureRef::try_new(sigma2_inner.signature.0)?;
            if !responder_pubkey.verify(tw.as_slice(), signature)? {
                error!("Sigma2 signature verification failed");
                let _ = complete_with_status(exchange, SCStatusCodes::InvalidParameter, &[]).await;
                return Err(ErrorCode::Invalid.into());
            }
        }

        // Update TT with Sigma2
        tt.update(sigma2_payload)?;

        // === Sigma3: Build and send ===

        // Derive Sigma3 key
        // S3K_salt = IPK || TT_hash(after Sigma1 + Sigma2)
        let mut sigma3_key = AEAD_KEY_ZEROED;
        {
            let mut tt_hash = HASH_ZEROED;
            tt.finish_current(&mut tt_hash)?;

            let mut salt = CryptoSensitive::<{ AEAD_CANON_KEY_LEN + HASH_LEN }>::new();
            let s = salt.access_mut();
            s[..AEAD_CANON_KEY_LEN].copy_from_slice(op_key.access());
            s[AEAD_CANON_KEY_LEN..].copy_from_slice(tt_hash.access());

            crypto
                .kdf()?
                .expand(
                    salt.access(),
                    shared_secret.reference(),
                    &S3K_INFO,
                    &mut sigma3_key,
                )
                .map_err(|_| ErrorCode::InvalidData)?;
        }

        // Compute Sigma3 signature
        // TBS3 = { our_noc, our_icac?, our_pub_key, peer_pub_key }
        let mut signature = MaybeUninit::<CanonPkcSignature>::uninit();
        let signature = signature.init_with(CanonPkcSignature::init());
        {
            let mut tbs_buf = alloc!([0; CASE_LARGE_BUF_SIZE]);
            let mut tw = WriteBuf::new(&mut tbs_buf[..]);

            tw.start_struct(&TLVTag::Anonymous)?;
            tw.str(&TLVTag::Context(1), creds.noc)?;
            if let Some(icac) = creds.icac {
                tw.str(&TLVTag::Context(2), icac)?;
            }
            tw.str(&TLVTag::Context(3), our_pub_key.access())?;
            tw.str(&TLVTag::Context(4), peer_pub_key.access())?;
            tw.end_container()?;

            let our_secret = crypto.secret_key(creds.secret_key)?;
            our_secret.sign(tw.as_slice(), signature)?;
        }

        // Build and encrypt Sigma3 TBE, then send
        exchange
            .send_with(|_, wb| {
                // Build the encrypted inner payload in the send buffer
                wb.start_struct(&TLVTag::Anonymous)?;

                // The encrypted payload will go in tag 1
                wb.str_cb(&TLVTag::Context(1), |buf| {
                    let mut tw = WriteBuf::new(buf);

                    tw.start_struct(&TLVTag::Anonymous)?;
                    tw.str(&TLVTag::Context(1), creds.noc)?;
                    if let Some(icac) = creds.icac {
                        tw.str(&TLVTag::Context(2), icac)?;
                    }
                    tw.str(&TLVTag::Context(3), signature.access())?;
                    tw.end_container()?;

                    // Append space for AEAD tag
                    tw.append(AEAD_TAG_ZEROED.access())?;
                    let cipher_text = tw.as_mut_slice();

                    let mut cipher = crypto.aead()?;
                    cipher.encrypt_in_place(
                        sigma3_key.reference(),
                        SIGMA3_NONCE,
                        &[],
                        cipher_text,
                        cipher_text.len() - AEAD_TAG_LEN,
                    )?;

                    Ok(tw.as_slice().len())
                })?;

                wb.end_container()?;

                // Update TT with Sigma3
                tt.update(wb.as_slice())?;

                Ok(Some(OpCode::CASESigma3.into()))
            })
            .await?;

        // === StatusReport: Receive ===
        exchange.recv_fetch().await?;

        {
            let rx = exchange.rx()?;
            let meta = rx.meta();

            if meta.proto_opcode != OpCode::StatusReport as u8 {
                error!("Expected StatusReport, got opcode {}", meta.proto_opcode);
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

        // === Derive session keys and complete ===
        let mut session_keys = MaybeUninit::<CaseSessionKeys>::uninit();
        let session_keys = session_keys.init_with(CaseSessionKeys::init());
        {
            let mut tt_hash = HASH_ZEROED;
            tt.finish_current(&mut tt_hash)?;

            let mut salt = CryptoSensitive::<{ AEAD_CANON_KEY_LEN + HASH_LEN }>::new();
            let s = salt.access_mut();
            s[..AEAD_CANON_KEY_LEN].copy_from_slice(op_key.access());
            s[AEAD_CANON_KEY_LEN..].copy_from_slice(tt_hash.access());

            crypto
                .kdf()?
                .expand(
                    salt.access(),
                    shared_secret.reference(),
                    &SEKEYS_INFO,
                    session_keys,
                )
                .map_err(|_| ErrorCode::InvalidData)?;
        }

        // Get peer address from the exchange
        let peer_addr = exchange.with_state(|state| {
            let sess = exchange.id().session(&mut state.sessions);
            Ok(sess.get_peer_addr())
        })?;

        // Split session keys: for initiator, first key = enc, second = dec
        // (reversed from responder perspective)
        let (enc_key, remaining) = session_keys
            .reference()
            .split::<AEAD_CANON_KEY_LEN, { AEAD_CANON_KEY_LEN * 2 }>();
        let (dec_key, att_challenge) = remaining.split::<AEAD_CANON_KEY_LEN, AEAD_CANON_KEY_LEN>();

        let mut peer_catids: NocCatIds = Default::default();
        responder_noc.get_cat_ids(&mut peer_catids)?;

        session.update(
            creds.node_id,
            peer_node_id,
            peer_sessid,
            local_sessid,
            peer_addr,
            SessionMode::Case {
                fab_idx: creds.fab_idx,
                cat_ids: peer_catids,
            },
            Some(dec_key),
            Some(enc_key),
            Some(att_challenge),
        )?;

        session.complete();

        exchange.acknowledge().await?;

        info!(
            "CASE session established: local_sessid={}, peer_sessid={}, peer_node_id={}",
            local_sessid, peer_sessid, peer_node_id
        );

        Ok(())
    }
}
