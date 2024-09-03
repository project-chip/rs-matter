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

use core::{mem::MaybeUninit, num::NonZeroU8};

use log::{error, trace};

use crate::{
    alloc,
    cert::CertRef,
    crypto::{self, KeyPair, Sha256},
    error::{Error, ErrorCode},
    fabric::Fabric,
    secure_channel::common::{complete_with_status, sc_write, OpCode, SCStatusCodes},
    tlv::{get_root_node_struct, FromTLV, OctetStr, TLVElement, TLVTag, TLVWrite},
    transport::{
        exchange::Exchange,
        session::{NocCatIds, ReservedSession, SessionMode},
    },
    utils::{init::InitMaybeUninit, rand::Rand, storage::WriteBuf},
};

#[derive(Debug, Clone)]
pub struct CaseSession {
    peer_sessid: u16,
    local_sessid: u16,
    tt_hash: Option<Sha256>,
    shared_secret: [u8; crypto::ECDH_SHARED_SECRET_LEN_BYTES],
    our_pub_key: [u8; crypto::EC_POINT_LEN_BYTES],
    peer_pub_key: [u8; crypto::EC_POINT_LEN_BYTES],
    local_fabric_idx: u8,
}

impl Default for CaseSession {
    fn default() -> Self {
        Self::new()
    }
}

impl CaseSession {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            peer_sessid: 0,
            local_sessid: 0,
            tt_hash: None,
            shared_secret: [0; crypto::ECDH_SHARED_SECRET_LEN_BYTES],
            our_pub_key: [0; crypto::EC_POINT_LEN_BYTES],
            peer_pub_key: [0; crypto::EC_POINT_LEN_BYTES],
            local_fabric_idx: 0,
        }
    }
}

pub struct Case(());

impl Case {
    #[inline(always)]
    pub const fn new() -> Self {
        Self(())
    }

    pub async fn handle(
        &mut self,
        exchange: &mut Exchange<'_>,
        case_session: &mut CaseSession,
    ) -> Result<(), Error> {
        let session = ReservedSession::reserve(exchange.matter()).await?;

        self.handle_casesigma1(exchange, case_session).await?;

        exchange.recv_fetch().await?;

        self.handle_casesigma3(exchange, case_session, session)
            .await?;

        exchange.acknowledge().await?;
        exchange.matter().notify_changed();

        Ok(())
    }

    async fn handle_casesigma3(
        &mut self,
        exchange: &mut Exchange<'_>,
        case_session: &mut CaseSession,
        mut session: ReservedSession<'_>,
    ) -> Result<(), Error> {
        exchange.rx()?.meta().check_opcode(OpCode::CASESigma3)?;

        let status = {
            let fabric_mgr = exchange.matter().fabric_mgr.borrow();

            let fabric = NonZeroU8::new(case_session.local_fabric_idx)
                .and_then(|fabric_idx| fabric_mgr.get_fabric(fabric_idx));
            if let Some(fabric) = fabric {
                let root = get_root_node_struct(exchange.rx()?.payload())?;
                let encrypted = root.structure()?.ctx(1)?.str()?;

                let mut decrypted = alloc!([0; 800]); // TODO LARGE BUFFER
                if encrypted.len() > decrypted.len() {
                    error!("Data too large");
                    Err(ErrorCode::NoSpace)?;
                }
                let decrypted = &mut decrypted[..encrypted.len()];
                decrypted.copy_from_slice(encrypted);

                let len =
                    Case::get_sigma3_decryption(fabric.ipk.op_key(), case_session, decrypted)?;
                let decrypted = &decrypted[..len];

                let root = get_root_node_struct(decrypted)?;
                let d = Sigma3Decrypt::from_tlv(&root)?;

                let initiator_noc = CertRef::new(TLVElement::new(d.initiator_noc.0));
                let initiator_icac = d
                    .initiator_icac
                    .map(|icac| CertRef::new(TLVElement::new(icac.0)));

                let mut validate_certs_buf = alloc!([0; 800]); // TODO LARGE BUFFER
                let validate_certs_buf = &mut validate_certs_buf[..];
                if let Err(e) = Case::validate_certs(
                    fabric,
                    &initiator_noc,
                    initiator_icac.as_ref(),
                    validate_certs_buf,
                ) {
                    error!("Certificate Chain doesn't match: {}", e);
                    SCStatusCodes::InvalidParameter
                } else if let Err(e) = Case::validate_sigma3_sign(
                    d.initiator_noc.0,
                    d.initiator_icac.map(|a| a.0),
                    &initiator_noc,
                    d.signature.0,
                    case_session,
                ) {
                    error!("Sigma3 Signature doesn't match: {}", e);
                    SCStatusCodes::InvalidParameter
                } else {
                    // Only now do we add this message to the TT Hash
                    let mut peer_catids: NocCatIds = Default::default();
                    initiator_noc.get_cat_ids(&mut peer_catids)?;
                    case_session
                        .tt_hash
                        .as_mut()
                        .unwrap()
                        .update(exchange.rx()?.payload())?;

                    let mut session_keys =
                        MaybeUninit::<[u8; 3 * crypto::SYMM_KEY_LEN_BYTES]>::uninit(); // TODO MEDIM BUFFER
                    let session_keys = session_keys.init_zeroed();
                    Case::get_session_keys(
                        fabric.ipk.op_key(),
                        case_session.tt_hash.as_ref().unwrap(),
                        &case_session.shared_secret,
                        session_keys,
                    )?;

                    let peer_addr = exchange.with_session(|sess| Ok(sess.get_peer_addr()))?;

                    session.update(
                        fabric.get_node_id(),
                        initiator_noc.get_node_id()?,
                        case_session.peer_sessid,
                        case_session.local_sessid,
                        peer_addr,
                        SessionMode::Case {
                            // Unwrapping is safe, because if the fabric index was 0, we would not be in here
                            fab_idx: NonZeroU8::new(case_session.local_fabric_idx).unwrap(),
                            cat_ids: peer_catids,
                        },
                        Some(&session_keys[0..16]),
                        Some(&session_keys[16..32]),
                        Some(&session_keys[32..48]),
                    )?;

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
            } else {
                SCStatusCodes::NoSharedTrustRoots
            }
        };

        complete_with_status(exchange, status, &[]).await
    }

    async fn handle_casesigma1(
        &mut self,
        exchange: &mut Exchange<'_>,
        case_session: &mut CaseSession,
    ) -> Result<(), Error> {
        exchange.rx()?.meta().check_opcode(OpCode::CASESigma1)?;

        let root = get_root_node_struct(exchange.rx()?.payload())?;
        let r = Sigma1Req::from_tlv(&root)?;

        let local_fabric_idx = exchange
            .matter()
            .fabric_mgr
            .borrow_mut()
            .match_dest_id(r.initiator_random.0, r.dest_id.0);
        if local_fabric_idx.is_err() {
            error!("Fabric Index mismatch");
            complete_with_status(exchange, SCStatusCodes::NoSharedTrustRoots, &[]).await?;

            return Ok(());
        }

        let local_sessid = exchange
            .matter()
            .transport_mgr
            .session_mgr
            .borrow_mut()
            .get_next_sess_id();
        case_session.peer_sessid = r.initiator_sessid;
        case_session.local_sessid = local_sessid;
        case_session.tt_hash = Some(Sha256::new()?);
        case_session
            .tt_hash
            .as_mut()
            .unwrap()
            .update(exchange.rx()?.payload())?;
        case_session.local_fabric_idx = local_fabric_idx?.get();
        if r.peer_pub_key.0.len() != crypto::EC_POINT_LEN_BYTES {
            error!("Invalid public key length");
            Err(ErrorCode::Invalid)?;
        }
        case_session.peer_pub_key.copy_from_slice(r.peer_pub_key.0);
        trace!(
            "Destination ID matched to fabric index {}",
            case_session.local_fabric_idx
        );

        // Create an ephemeral Key Pair
        let key_pair = KeyPair::new(exchange.matter().rand())?;
        let _ = key_pair.get_public_key(&mut case_session.our_pub_key)?;

        // Derive the Shared Secret
        let len = key_pair.derive_secret(r.peer_pub_key.0, &mut case_session.shared_secret)?;
        if len != 32 {
            error!("Derived secret length incorrect");
            Err(ErrorCode::Invalid)?;
        }
        //        println!("Derived secret: {:x?} len: {}", secret, len);

        let mut our_random = MaybeUninit::<[u8; 32]>::uninit(); // TODO MEDIUM BUFFER
        let our_random = our_random.init_zeroed();
        (exchange.matter().rand())(our_random);

        let mut hash_updated = false;
        exchange
            .send_with(|exchange, tw| {
                let fabric_mgr = exchange.matter().fabric_mgr.borrow();

                let fabric = NonZeroU8::new(case_session.local_fabric_idx)
                    .and_then(|fabric_idx| fabric_mgr.get_fabric(fabric_idx));

                let Some(fabric) = fabric else {
                    return sc_write(tw, SCStatusCodes::NoSharedTrustRoots, &[]);
                };

                tw.start_struct(&TLVTag::Anonymous)?;
                tw.str(&TLVTag::Context(1), &*our_random)?;
                tw.u16(&TLVTag::Context(2), local_sessid)?;
                tw.str(&TLVTag::Context(3), &case_session.our_pub_key)?;

                // Use the remainder of the TX buffer as scratch space for performing signature
                let sign_buf = tw.empty_as_mut_slice();

                let mut signature = MaybeUninit::<[u8; crypto::EC_SIGNATURE_LEN_BYTES]>::uninit(); // TODO MEDIUM BUFFER
                let signature = signature.init_zeroed();

                let sign_len = Case::get_sigma2_sign(
                    fabric,
                    &case_session.our_pub_key,
                    &case_session.peer_pub_key,
                    sign_buf,
                    signature,
                )?;

                let signature = &signature[..sign_len];

                tw.str_cb(&TLVTag::Context(4), |buf| {
                    Case::get_sigma2_encryption(
                        fabric,
                        exchange.matter().rand(),
                        &*our_random,
                        case_session,
                        signature,
                        buf,
                    )
                })?;
                tw.end_container()?;

                if !hash_updated {
                    case_session
                        .tt_hash
                        .as_mut()
                        .unwrap()
                        .update(tw.as_slice())?;
                    hash_updated = true;
                }

                Ok(Some(OpCode::CASESigma2.into()))
            })
            .await
    }

    fn validate_sigma3_sign(
        initiator_noc: &[u8],
        initiator_icac: Option<&[u8]>,
        initiator_noc_cert: &CertRef,
        sign: &[u8],
        case_session: &CaseSession,
    ) -> Result<(), Error> {
        const MAX_TBS_SIZE: usize = 800;
        let mut buf = [0; MAX_TBS_SIZE];
        let mut write_buf = WriteBuf::new(&mut buf);
        let tw = &mut write_buf;
        tw.start_struct(&TLVTag::Anonymous)?;
        tw.str(&TLVTag::Context(1), initiator_noc)?;
        if let Some(icac) = initiator_icac {
            tw.str(&TLVTag::Context(2), icac)?;
        }
        tw.str(&TLVTag::Context(3), &case_session.peer_pub_key)?;
        tw.str(&TLVTag::Context(4), &case_session.our_pub_key)?;
        tw.end_container()?;

        let key = KeyPair::new_from_public(initiator_noc_cert.pubkey()?)?;
        key.verify_msg(write_buf.as_slice(), sign)?;
        Ok(())
    }

    fn validate_certs(
        fabric: &Fabric,
        noc: &CertRef,
        icac: Option<&CertRef>,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let mut verifier = noc.verify_chain_start();

        if fabric.get_fabric_id() != noc.get_fabric_id()? {
            Err(ErrorCode::Invalid)?;
        }

        if let Some(icac) = icac {
            // If ICAC is present handle it
            if let Ok(fid) = icac.get_fabric_id() {
                if fid != fabric.get_fabric_id() {
                    Err(ErrorCode::Invalid)?;
                }
            }
            verifier = verifier.add_cert(icac, buf)?;
        }

        verifier
            .add_cert(&CertRef::new(TLVElement::new(&fabric.root_ca)), buf)?
            .finalise(buf)?;
        Ok(())
    }

    fn get_session_keys(
        ipk: &[u8],
        tt: &Sha256,
        shared_secret: &[u8],
        key: &mut [u8],
    ) -> Result<(), Error> {
        const SEKEYS_INFO: [u8; 11] = [
            0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x73,
        ];
        if key.len() < 48 {
            Err(ErrorCode::NoSpace)?;
        }
        let mut salt = heapless::Vec::<u8, 256>::new();
        salt.extend_from_slice(ipk).unwrap();
        let tt = tt.clone();
        let mut tt_hash = [0u8; crypto::SHA256_HASH_LEN_BYTES];
        tt.finish(&mut tt_hash)?;
        salt.extend_from_slice(&tt_hash).unwrap();
        //        println!("Session Key: salt: {:x?}, len: {}", salt, salt.len());

        crypto::hkdf_sha256(salt.as_slice(), shared_secret, &SEKEYS_INFO, key)
            .map_err(|_x| ErrorCode::NoSpace)?;
        //        println!("Session Key: key: {:x?}", key);

        Ok(())
    }

    fn get_sigma3_decryption(
        ipk: &[u8],
        case_session: &CaseSession,
        encrypted: &mut [u8],
    ) -> Result<usize, Error> {
        let mut sigma3_key = [0_u8; crypto::SYMM_KEY_LEN_BYTES];
        Case::get_sigma3_key(
            ipk,
            case_session.tt_hash.as_ref().unwrap(),
            &case_session.shared_secret,
            &mut sigma3_key,
        )?;
        // println!("Sigma3 Key: {:x?}", sigma3_key);

        let nonce: [u8; 13] = [
            0x4e, 0x43, 0x41, 0x53, 0x45, 0x5f, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x33, 0x4e,
        ];

        let encrypted_len = encrypted.len();
        crypto::decrypt_in_place(&sigma3_key, &nonce, &[], encrypted)?;
        Ok(encrypted_len - crypto::AEAD_MIC_LEN_BYTES)
    }

    fn get_sigma3_key(
        ipk: &[u8],
        tt: &Sha256,
        shared_secret: &[u8],
        key: &mut [u8],
    ) -> Result<(), Error> {
        const S3K_INFO: [u8; 6] = [0x53, 0x69, 0x67, 0x6d, 0x61, 0x33];
        if key.len() < 16 {
            Err(ErrorCode::NoSpace)?;
        }
        let mut salt = heapless::Vec::<u8, 256>::new();
        salt.extend_from_slice(ipk).unwrap();

        let tt = tt.clone();

        let mut tt_hash = [0u8; crypto::SHA256_HASH_LEN_BYTES];
        tt.finish(&mut tt_hash)?;
        salt.extend_from_slice(&tt_hash).unwrap();
        //        println!("Sigma3Key: salt: {:x?}, len: {}", salt, salt.len());

        crypto::hkdf_sha256(salt.as_slice(), shared_secret, &S3K_INFO, key)
            .map_err(|_x| ErrorCode::NoSpace)?;
        //        println!("Sigma3Key: key: {:x?}", key);

        Ok(())
    }

    fn get_sigma2_key(
        ipk: &[u8],
        our_random: &[u8],
        case_session: &CaseSession,
        key: &mut [u8],
    ) -> Result<(), Error> {
        const S2K_INFO: [u8; 6] = [0x53, 0x69, 0x67, 0x6d, 0x61, 0x32];
        if key.len() < 16 {
            Err(ErrorCode::NoSpace)?;
        }
        let mut salt = heapless::Vec::<u8, 256>::new();
        salt.extend_from_slice(ipk).unwrap();
        salt.extend_from_slice(our_random).unwrap();
        salt.extend_from_slice(&case_session.our_pub_key).unwrap();

        let tt = case_session.tt_hash.as_ref().unwrap().clone();

        let mut tt_hash = [0u8; crypto::SHA256_HASH_LEN_BYTES];
        tt.finish(&mut tt_hash)?;
        salt.extend_from_slice(&tt_hash).unwrap();
        //        println!("Sigma2Key: salt: {:x?}, len: {}", salt, salt.len());

        crypto::hkdf_sha256(salt.as_slice(), &case_session.shared_secret, &S2K_INFO, key)
            .map_err(|_x| ErrorCode::NoSpace)?;
        //        println!("Sigma2Key: key: {:x?}", key);

        Ok(())
    }

    fn get_sigma2_encryption(
        fabric: &Fabric,
        rand: Rand,
        our_random: &[u8],
        case_session: &CaseSession,
        signature: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut resumption_id: [u8; 16] = [0; 16];
        rand(&mut resumption_id);

        let mut sigma2_key = [0_u8; crypto::SYMM_KEY_LEN_BYTES];
        Case::get_sigma2_key(
            fabric.ipk.op_key(),
            our_random,
            case_session,
            &mut sigma2_key,
        )?;

        let mut write_buf = WriteBuf::new(out);
        let tw = &mut write_buf;
        tw.start_struct(&TLVTag::Anonymous)?;
        tw.str(&TLVTag::Context(1), &fabric.noc)?;
        if let Some(icac_cert) = fabric.icac.as_ref() {
            tw.str(&TLVTag::Context(2), icac_cert)?
        };

        tw.str(&TLVTag::Context(3), signature)?;
        tw.str(&TLVTag::Context(4), &resumption_id)?;
        tw.end_container()?;
        //println!("TBE is {:x?}", write_buf.as_borrow_slice());
        let nonce: [u8; crypto::AEAD_NONCE_LEN_BYTES] = [
            0x4e, 0x43, 0x41, 0x53, 0x45, 0x5f, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x32, 0x4e,
        ];
        //        let nonce = GenericArray::from_slice(&nonce);
        //        type AesCcm = Ccm<Aes128, U16, U13>;
        //        let cipher = AesCcm::new(GenericArray::from_slice(key));
        const TAG_LEN: usize = 16;
        let tag = [0u8; TAG_LEN];
        write_buf.append(&tag)?;
        let cipher_text = write_buf.as_mut_slice();

        crypto::encrypt_in_place(
            &sigma2_key,
            &nonce,
            &[],
            cipher_text,
            cipher_text.len() - TAG_LEN,
        )?;
        Ok(write_buf.as_slice().len())
    }

    fn get_sigma2_sign(
        fabric: &Fabric,
        our_pub_key: &[u8],
        peer_pub_key: &[u8],
        buf: &mut [u8],
        signature: &mut [u8],
    ) -> Result<usize, Error> {
        let mut write_buf = WriteBuf::new(buf);
        let tw = &mut write_buf;
        tw.start_struct(&TLVTag::Anonymous)?;
        tw.str(&TLVTag::Context(1), &fabric.noc)?;
        if let Some(icac_cert) = fabric.icac.as_deref() {
            tw.str(&TLVTag::Context(2), icac_cert)?;
        }
        tw.str(&TLVTag::Context(3), our_pub_key)?;
        tw.str(&TLVTag::Context(4), peer_pub_key)?;
        tw.end_container()?;
        //println!("TBS is {:x?}", write_buf.as_borrow_slice());
        fabric.sign_msg(write_buf.as_slice(), signature)
    }
}

impl Default for Case {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(FromTLV)]
#[tlvargs(start = 1, lifetime = "'a")]
struct Sigma1Req<'a> {
    initiator_random: OctetStr<'a>,
    initiator_sessid: u16,
    dest_id: OctetStr<'a>,
    peer_pub_key: OctetStr<'a>,
}

#[derive(FromTLV)]
#[tlvargs(start = 1, lifetime = "'a")]
struct Sigma3Decrypt<'a> {
    initiator_noc: OctetStr<'a>,
    initiator_icac: Option<OctetStr<'a>>,
    signature: OctetStr<'a>,
}
