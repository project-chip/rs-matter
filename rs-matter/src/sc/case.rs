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

use crate::alloc;
use crate::cert::CertRef;
use crate::crypto::{
    self, as_canon, Aead, Aes128Nonce, CanonAes128Key, CanonSecp256r1EcdhSharedSecret,
    CanonSecp256r1PublicKey, CanonSecp256r1Signature, Crypto, Digest, Hkdf, PublicKey, SecretKey,
    Sha256Hash, SigningSecretKey, AES128_CANON_KEY_LEN, AES128_KEY_ZEROED, AES128_TAG_LEN,
    AES128_TAG_ZEROED, SECP256R1_ECDH_SHARED_SECRET_ZEROED, SECP256R1_PUBLIC_KEY_ZEROED,
    SHA256_HASH_ZEROED,
};
use crate::error::{Error, ErrorCode};
use crate::fabric::Fabric;
use crate::sc::{
    check_opcode, complete_with_status, sc_write, OpCode, SCStatusCodes, SessionParameters,
};
use crate::tlv::{get_root_node_struct, FromTLV, OctetStr, Optional, TLVElement, TLVTag, TLVWrite};
use crate::transport::exchange::Exchange;
use crate::transport::session::{NocCatIds, ReservedSession, SessionMode};
use crate::utils::init::{init, init_zeroed, Init, InitMaybeUninit};
use crate::utils::storage::WriteBuf;

/// The CASE Session type used during the CASE handshake
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct CaseSession<'a, C: Crypto + 'a> {
    /// The peer's session ID
    peer_sessid: u16,
    /// The local session ID
    local_sessid: u16,
    /// The Transcript Hash
    tt_hash: Optional<C::Sha256<'a>>,
    /// The ECDH Shared Secret
    shared_secret: CanonSecp256r1EcdhSharedSecret,
    /// Our ephemeral public key
    our_pub_key: CanonSecp256r1PublicKey,
    /// The peer's ephemeral public key
    peer_pub_key: CanonSecp256r1PublicKey,
    /// The local fabric index for this session
    local_fabric_idx: u8,
    crypto: &'a C,
}

impl<'a, C: Crypto + 'a> CaseSession<'a, C> {
    /// Create a new `CaseSession` instance
    #[inline(always)]
    pub const fn new(crypto: &'a C) -> Self {
        Self {
            peer_sessid: 0,
            local_sessid: 0,
            tt_hash: Optional::none(),
            shared_secret: SECP256R1_ECDH_SHARED_SECRET_ZEROED,
            our_pub_key: SECP256R1_PUBLIC_KEY_ZEROED,
            peer_pub_key: SECP256R1_PUBLIC_KEY_ZEROED,
            local_fabric_idx: 0,
            crypto,
        }
    }

    /// Return an in-place initializer for `CaseSession`
    pub fn init(crypto: &'a C) -> impl Init<Self> {
        init!(Self {
            peer_sessid: 0,
            local_sessid: 0,
            tt_hash <- Optional::init_none(),
            shared_secret <- init_zeroed(),
            our_pub_key <- init_zeroed(),
            peer_pub_key <- init_zeroed(),
            local_fabric_idx: 0,
            crypto,
        })
    }

    /// Get the Sigma2 encrypted data
    ///
    /// # Arguments
    /// - `fabric` - The local fabric
    /// - `our_random` - Our random value
    /// - `our_hash` - Our transcript hash
    /// - `signature` - Our signature
    /// - `resumption_id` - The resumption ID
    /// - `out` - The output buffer to write the encrypted data to
    ///
    /// # Returns
    /// - `Ok(usize)` - The length of the encrypted data written to `out`
    /// - `Err(Error)` - If an error occurred during the process
    #[allow(clippy::too_many_arguments)]
    fn get_sigma2_encryption(
        &self,
        fabric: &Fabric,
        our_random: &[u8],
        our_hash: &Sha256Hash,
        signature: &CanonSecp256r1Signature,
        resumption_id: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut sigma2_key = AES128_KEY_ZEROED;
        self.get_sigma2_key(fabric.ipk().op_key(), our_random, our_hash, &mut sigma2_key)?;

        let mut write_buf = WriteBuf::new(out);
        let tw = &mut write_buf;
        tw.start_struct(&TLVTag::Anonymous)?;
        tw.str(&TLVTag::Context(1), fabric.noc())?;
        if !fabric.icac().is_empty() {
            tw.str(&TLVTag::Context(2), fabric.icac())?
        };

        tw.str(&TLVTag::Context(3), signature)?;
        tw.str(&TLVTag::Context(4), resumption_id)?;
        tw.end_container()?;
        //println!("TBE is {:x?}", write_buf.as_borrow_slice());
        const NONCE: &Aes128Nonce = &[
            0x4e, 0x43, 0x41, 0x53, 0x45, 0x5f, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x32, 0x4e,
        ];
        //        let nonce = GenericArray::from_slice(&nonce);
        //        type AesCcm = Ccm<Aes128, U16, U13>;
        //        let cipher = AesCcm::new(GenericArray::from_slice(key));
        write_buf.append(&AES128_TAG_ZEROED)?;
        let cipher_text = write_buf.as_mut_slice();

        let mut cypher = self.crypto.aes_ccm_16_64_128()?;

        cypher.encrypt_in_place(
            &sigma2_key,
            NONCE,
            &[],
            cipher_text,
            cipher_text.len() - AES128_TAG_LEN,
        )?;
        Ok(write_buf.as_slice().len())
    }

    /// Get the Sigma2 signature
    ///
    /// # Arguments
    /// - `fabric` - The local fabric
    /// - `tmp_buf` - A temporary buffer for constructing the signature
    /// - `signature` - The output buffer to write the signature to
    ///
    /// # Returns
    /// - `Ok(())` - If the signature was successfully generated
    /// - `Err(Error)` - If an error occurred during the process
    fn get_sigma2_sign(
        &self,
        fabric: &Fabric,
        tmp_buf: &mut [u8],
        signature: &mut CanonSecp256r1Signature,
    ) -> Result<(), Error> {
        let mut write_buf = WriteBuf::new(tmp_buf);
        let tw = &mut write_buf;
        tw.start_struct(&TLVTag::Anonymous)?;
        tw.str(&TLVTag::Context(1), fabric.noc())?;
        if !fabric.icac().is_empty() {
            tw.str(&TLVTag::Context(2), fabric.icac())?;
        }
        tw.str(&TLVTag::Context(3), &self.our_pub_key)?;
        tw.str(&TLVTag::Context(4), &self.peer_pub_key)?;
        tw.end_container()?;
        //println!("TBS is {:x?}", write_buf.as_borrow_slice());

        let fabric_secret = self.crypto.secp256r1_secret_key(fabric.secret_key())?;
        fabric_secret.sign(write_buf.as_slice(), signature);

        Ok(())
    }

    /// Get the Sigma2 key
    ///
    /// # Arguments
    /// - `ipk` - The IPK
    /// - `our_random` - Our random value
    /// - `our_pub_key` - Our public key
    /// - `our_hash` - Our transcript hash
    /// - `key` - The output buffer to write the Sigma2 key to
    ///
    /// # Returns
    /// - `Ok(())` - If the Sigma2 key was successfully derived
    /// - `Err(Error)` - If an error occurred during the process
    fn get_sigma2_key(
        &self,
        ipk: &[u8],
        our_random: &[u8],
        our_hash: &Sha256Hash,
        key: &mut CanonAes128Key,
    ) -> Result<(), Error> {
        const S2K_INFO: [u8; 6] = [0x53, 0x69, 0x67, 0x6d, 0x61, 0x32];
        let mut salt = heapless::Vec::<u8, 256>::new();
        unwrap!(salt.extend_from_slice(ipk));
        unwrap!(salt.extend_from_slice(our_random));
        unwrap!(salt.extend_from_slice(&self.our_pub_key));
        unwrap!(salt.extend_from_slice(our_hash));

        self.crypto
            .hkdf_sha256()?
            .expand(salt.as_slice(), &self.shared_secret, &S2K_INFO, key)
            .map_err(|_x| ErrorCode::InvalidData)?;
        //        println!("Sigma2Key: key: {:x?}", key);

        Ok(())
    }

    /// Validate the certificate chain
    ///
    /// # Arguments
    /// - `fabric` - The local fabric
    /// - `noc` - The Node Operational Certificate
    /// - `icac` - The Intermediate Certificate Authority Certificate (optional)
    /// - `tmp_buf` - A temporary buffer for certificate validation
    ///
    /// # Returns
    /// - `Ok(())` - If the certificate chain is valid
    /// - `Err(Error)` - If the certificate chain is invalid
    fn validate_certs(
        &self,
        fabric: &Fabric,
        noc: &CertRef,
        icac: Option<&CertRef>,
        tmp_buf: &mut [u8],
    ) -> Result<(), Error> {
        let mut verifier = noc.verify_chain_start(self.crypto);

        if fabric.fabric_id() != noc.get_fabric_id()? {
            Err(ErrorCode::Invalid)?;
        }

        if let Some(icac) = icac {
            // If ICAC is present handle it
            if let Ok(fid) = icac.get_fabric_id() {
                if fid != fabric.fabric_id() {
                    Err(ErrorCode::Invalid)?;
                }
            }
            verifier = verifier.add_cert(icac, tmp_buf)?;
        }

        verifier
            .add_cert(&CertRef::new(TLVElement::new(fabric.root_ca())), tmp_buf)?
            .finalise(tmp_buf)?;
        Ok(())
    }

    /// Validate the Sigma3 signature
    ///
    /// # Arguments
    /// - `initiator_noc` - The initiator's Node Operational Certificate
    /// - `initiator_icac` - The initiator's Intermediate Certificate Authority Certificate (optional)
    /// - `initiator_noc_cert` - The initiator's Node Operational Certificate reference
    /// - `sign` - The signature to validate
    /// - `tmp_buf` - A temporary buffer for signature validation
    ///
    /// # Returns
    /// - `Ok(())` - If the signature is valid
    /// - `Err(Error)` - If the signature is invalid
    fn validate_sigma3_sign(
        &self,
        initiator_noc: &[u8],
        initiator_icac: Option<&[u8]>,
        initiator_noc_cert: &CertRef,
        signature: &[u8],
        tmp_buf: &mut [u8],
    ) -> Result<(), Error> {
        let signature = as_canon(signature)?;

        let mut write_buf = WriteBuf::new(tmp_buf);
        let tw = &mut write_buf;
        tw.start_struct(&TLVTag::Anonymous)?;
        tw.str(&TLVTag::Context(1), initiator_noc)?;
        if let Some(icac) = initiator_icac {
            tw.str(&TLVTag::Context(2), icac)?;
        }
        tw.str(&TLVTag::Context(3), &self.peer_pub_key)?;
        tw.str(&TLVTag::Context(4), &self.our_pub_key)?;
        tw.end_container()?;

        let pub_key = self
            .crypto
            .secp256r1_pub_key(as_canon(initiator_noc_cert.pubkey()?)?)?;
        if !pub_key.verify(write_buf.as_slice(), signature) {
            Err(ErrorCode::Invalid)?;
        }

        Ok(())
    }

    /// Get the session keys
    ///
    /// # Arguments
    /// - `ipk` - The IPK
    /// - `key` - The output buffer to write the session keys to
    ///
    /// # Returns
    /// - `Ok(())` - If the session keys were successfully derived
    /// - `Err(Error)` - If an error occurred during the process
    fn get_session_keys(
        &self,
        ipk: &[u8],
        keys: &mut [u8; AES128_CANON_KEY_LEN * 3],
    ) -> Result<(), Error> {
        let tt = unwrap!(self.tt_hash.as_opt_ref());
        let shared_secret = &self.shared_secret;

        const SEKEYS_INFO: [u8; 11] = [
            0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x73,
        ];

        let mut salt = heapless::Vec::<u8, 256>::new();
        unwrap!(salt.extend_from_slice(ipk));
        let tt = tt.clone();
        let mut tt_hash = SHA256_HASH_ZEROED;
        tt.finish(&mut tt_hash);
        unwrap!(salt.extend_from_slice(&tt_hash));
        //        println!("Session Key: salt: {:x?}, len: {}", salt, salt.len());

        self.crypto
            .hkdf_sha256()?
            .expand(salt.as_slice(), shared_secret, &SEKEYS_INFO, keys)
            .map_err(|_x| ErrorCode::InvalidData)?;
        //        println!("Session Key: key: {:x?}", key);

        Ok(())
    }

    /// Get the Sigma3 decrypted data
    ///
    /// # Arguments
    /// - `ipk` - The IPK
    /// - `encrypted` - The encrypted data to decrypt
    ///
    /// # Returns
    /// - `Ok(usize)` - The length of the decrypted data
    /// - `Err(Error)` - If an error occurred during the process
    fn get_sigma3_decryption(&self, ipk: &[u8], encrypted: &mut [u8]) -> Result<usize, Error> {
        let mut sigma3_key = AES128_KEY_ZEROED;
        self.get_sigma3_key(ipk, &mut sigma3_key)?;
        // println!("Sigma3 Key: {:x?}", sigma3_key);

        const NONCE: &Aes128Nonce = &[
            0x4e, 0x43, 0x41, 0x53, 0x45, 0x5f, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x33, 0x4e,
        ];

        let encrypted_len = encrypted.len();

        let mut cypher = self.crypto.aes_ccm_16_64_128()?;

        cypher.decrypt_in_place(&sigma3_key, NONCE, &[], encrypted)?;
        Ok(encrypted_len - crypto::AES128_TAG_LEN)
    }

    /// Get the Sigma3 key
    ///
    /// # Arguments
    /// - `ipk` - The IPK
    /// - `key` - The output buffer to write the Sigma3 key to
    ///
    /// # Returns
    /// - `Ok(())` - If the Sigma3 key was successfully derived
    /// - `Err(Error)` - If an error occurred during the process
    fn get_sigma3_key(&self, ipk: &[u8], key: &mut [u8]) -> Result<(), Error> {
        let tt = unwrap!(self.tt_hash.as_opt_ref());
        let shared_secret = &self.shared_secret;

        const S3K_INFO: [u8; 6] = [0x53, 0x69, 0x67, 0x6d, 0x61, 0x33];
        if key.len() < 16 {
            Err(ErrorCode::InvalidData)?;
        }
        let mut salt = heapless::Vec::<u8, 256>::new();
        unwrap!(salt.extend_from_slice(ipk));

        let tt = tt.clone();

        let mut tt_hash = SHA256_HASH_ZEROED;
        tt.finish(&mut tt_hash);
        unwrap!(salt.extend_from_slice(&tt_hash));
        //        println!("Sigma3Key: salt: {:x?}, len: {}", salt, salt.len());

        self.crypto
            .hkdf_sha256()?
            .expand(salt.as_slice(), shared_secret, &S3K_INFO, key)
            .map_err(|_x| ErrorCode::InvalidData)?;
        //        println!("Sigma3Key: key: {:x?}", key);

        Ok(())
    }
}

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

/// The CASE protocol handler
pub struct Case<'a, C: Crypto + 'a> {
    /// The CASE session state
    session: CaseSession<'a, C>,
}

impl<'a, C: Crypto + 'a> Case<'a, C> {
    /// Create a new `Case` instance
    #[inline(always)]
    pub const fn new(crypto: &'a C) -> Self {
        Self {
            session: CaseSession::new(crypto),
        }
    }

    /// Return an in-place initializer for `Case`
    pub fn init(crypto: &'a C) -> impl Init<Self> {
        init!(Self {
            session <- CaseSession::init(crypto),
        })
    }

    /// Handle the CASE protocol exchange, where the other peer is the exchange initiator
    ///
    /// # Arguments
    /// - `exchange` - The exchange to handle the CASE protocol on
    pub async fn handle(&mut self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let session = ReservedSession::reserve(exchange.matter(), self.session.crypto).await?;

        self.handle_casesigma1(exchange).await?;

        exchange.recv_fetch().await?;

        self.handle_casesigma3(exchange, session).await?;

        exchange.acknowledge().await?;
        exchange.matter().notify_persist();

        Ok(())
    }

    /// Handle the CASE Sigma1 message
    ///
    /// # Arguments
    /// - `exchange` - The exchange to handle the CASE Sigma1 message on
    async fn handle_casesigma1(&mut self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        check_opcode(exchange, OpCode::CASESigma1)?;

        let root = get_root_node_struct(exchange.rx()?.payload())?;
        let r = Sigma1Req::from_tlv(&root)?;

        let local_fabric_idx = exchange
            .matter()
            .fabric_mgr
            .borrow()
            .get_by_dest_id(r.initiator_random.0, r.dest_id.0, self.session.crypto)
            .map(|fabric| fabric.fab_idx());
        if local_fabric_idx.is_none() {
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
        self.session.peer_sessid = r.initiator_sessid;
        self.session.local_sessid = local_sessid;
        self.session.tt_hash = Optional::some(self.session.crypto.sha256()?);
        unwrap!(self.session.tt_hash.as_opt_mut()).update(exchange.rx()?.payload());
        self.session.local_fabric_idx = unwrap!(local_fabric_idx).get();
        let peer_pub_key: &CanonSecp256r1PublicKey = as_canon(r.peer_pub_key.0)?;
        self.session.peer_pub_key.copy_from_slice(peer_pub_key);
        trace!(
            "Destination ID matched to fabric index {}",
            self.session.local_fabric_idx
        );

        let peer_pub_key = self
            .session
            .crypto
            .secp256r1_pub_key(&self.session.peer_pub_key)?;

        // Create an ephemeral EC secret key
        let secret_key = self.session.crypto.secp256r1_secret_key_random()?;

        secret_key
            .pub_key()
            .canon_into(&mut self.session.our_pub_key);

        // Derive the Shared Secret
        secret_key.derive_shared_secret(&peer_pub_key, &mut self.session.shared_secret);
        //        println!("Derived secret: {:x?} len: {}", secret, len);

        let mut our_random = MaybeUninit::<[u8; 32]>::uninit(); // TODO MEDIUM BUFFER
        let our_random = our_random.init_zeroed();
        (exchange.matter().rand())(our_random);

        let mut resumption_id = MaybeUninit::<[u8; 16]>::uninit(); // TODO MEDIUM BUFFER
        let resumption_id = resumption_id.init_zeroed();
        (exchange.matter().rand())(resumption_id);

        let mut tt_hash = MaybeUninit::<Sha256Hash>::uninit(); // TODO MEDIUM BUFFER
        let tt_hash = tt_hash.init_zeroed();
        unwrap!(self.session.tt_hash.as_opt_ref())
            .clone()
            .finish(tt_hash);

        let mut hash_updated = false;
        exchange
            .send_with(|exchange, tw| {
                let fabric_mgr = exchange.matter().fabric_mgr.borrow();

                let fabric = NonZeroU8::new(self.session.local_fabric_idx)
                    .and_then(|fabric_idx| fabric_mgr.get(fabric_idx));

                let Some(fabric) = fabric else {
                    return sc_write(tw, SCStatusCodes::NoSharedTrustRoots, &[]);
                };

                let mut signature = MaybeUninit::<CanonSecp256r1Signature>::uninit(); // TODO MEDIUM BUFFER
                let signature = signature.init_zeroed();

                // Use the remainder of the TX buffer as scratch space for computing the signature
                let sign_buf = tw.empty_as_mut_slice();

                self.session.get_sigma2_sign(fabric, sign_buf, signature)?;

                tw.start_struct(&TLVTag::Anonymous)?;
                tw.str(&TLVTag::Context(1), &*our_random)?;
                tw.u16(&TLVTag::Context(2), local_sessid)?;
                tw.str(&TLVTag::Context(3), &self.session.our_pub_key)?;

                tw.str_cb(&TLVTag::Context(4), |buf| {
                    self.session.get_sigma2_encryption(
                        fabric,
                        &*our_random,
                        &*tt_hash,
                        signature,
                        resumption_id,
                        buf,
                    )
                })?;
                tw.end_container()?;

                if !hash_updated {
                    unwrap!(self.session.tt_hash.as_opt_mut()).update(tw.as_slice());
                    hash_updated = true;
                }

                Ok(Some(OpCode::CASESigma2.into()))
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

        let status = {
            let fabric_mgr = exchange.matter().fabric_mgr.borrow();

            let fabric = NonZeroU8::new(self.session.local_fabric_idx)
                .and_then(|fabric_idx| fabric_mgr.get(fabric_idx));
            if let Some(fabric) = fabric {
                let root = get_root_node_struct(exchange.rx()?.payload())?;
                let encrypted = root.structure()?.ctx(1)?.str()?;

                let mut decrypted = alloc!([0; 800]); // TODO LARGE BUFFER
                if encrypted.len() > decrypted.len() {
                    error!("Encrypted data too large");
                    Err(ErrorCode::BufferTooSmall)?;
                }
                let decrypted = &mut decrypted[..encrypted.len()];
                decrypted.copy_from_slice(encrypted);

                let len = self
                    .session
                    .get_sigma3_decryption(fabric.ipk().op_key(), decrypted)?;
                let decrypted = &decrypted[..len];

                let root = get_root_node_struct(decrypted)?;
                let d = Sigma3Decrypt::from_tlv(&root)?;

                let initiator_noc = CertRef::new(TLVElement::new(d.initiator_noc.0));
                let initiator_icac = d
                    .initiator_icac
                    .map(|icac| CertRef::new(TLVElement::new(icac.0)));

                let mut buf = alloc!([0; 800]); // TODO LARGE BUFFER
                let buf = &mut buf[..];
                if let Err(e) = self.session.validate_certs(
                    fabric,
                    &initiator_noc,
                    initiator_icac.as_ref(),
                    buf,
                ) {
                    error!("Certificate Chain doesn't match: {}", e);
                    SCStatusCodes::InvalidParameter
                } else if let Err(e) = self.session.validate_sigma3_sign(
                    d.initiator_noc.0,
                    d.initiator_icac.map(|a| a.0),
                    &initiator_noc,
                    d.signature.0,
                    buf,
                ) {
                    error!("Sigma3 Signature doesn't match: {}", e);
                    SCStatusCodes::InvalidParameter
                } else {
                    // Only now do we add this message to the TT Hash
                    let mut peer_catids: NocCatIds = Default::default();
                    initiator_noc.get_cat_ids(&mut peer_catids)?;
                    unwrap!(self.session.tt_hash.as_opt_mut()).update(exchange.rx()?.payload());

                    let mut session_keys = MaybeUninit::<[u8; 3 * AES128_CANON_KEY_LEN]>::uninit(); // TODO MEDIM BUFFER
                    let session_keys = session_keys.init_zeroed();
                    self.session
                        .get_session_keys(fabric.ipk().op_key(), session_keys)?;

                    let peer_addr = exchange.with_session(|sess| Ok(sess.get_peer_addr()))?;

                    session.update(
                        fabric.node_id(),
                        initiator_noc.get_node_id()?,
                        self.session.peer_sessid,
                        self.session.local_sessid,
                        peer_addr,
                        SessionMode::Case {
                            // Unwrapping is safe, because if the fabric index was 0, we would not be in here
                            fab_idx: unwrap!(NonZeroU8::new(self.session.local_fabric_idx)),
                            cat_ids: peer_catids,
                        },
                        Some(&session_keys[..AES128_CANON_KEY_LEN]),
                        Some(&session_keys[AES128_CANON_KEY_LEN..AES128_CANON_KEY_LEN * 2]),
                        Some(&session_keys[AES128_CANON_KEY_LEN * 2..]),
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
}
