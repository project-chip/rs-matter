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

use rand_core::RngCore;

use crate::cert::CertRef;
use crate::crypto::{
    self, canon, Aead, AeadNonceRef, CanonAeadKey, CanonAeadKeyRef, CanonPkcPublicKey,
    CanonPkcPublicKeyRef, CanonPkcSharedSecret, CanonPkcSignature, CanonPkcSignatureRef, Crypto,
    CryptoSensitive, Digest, Hash, HashRef, Kdf, PublicKey, SecretKey, SigningSecretKey,
    AEAD_CANON_KEY_LEN, AEAD_KEY_ZEROED, AEAD_TAG_LEN, AEAD_TAG_ZEROED, HASH_LEN, HASH_ZEROED,
    PKC_CANON_PUBLIC_KEY_LEN, PKC_PUBLIC_KEY_ZEROED, PKC_SHARED_SECRET_ZEROED,
};
use crate::error::{Error, ErrorCode};
use crate::fabric::Fabric;
use crate::tlv::{Optional, TLVElement, TLVTag, TLVWrite};
use crate::utils::init::{init, Init};
use crate::utils::storage::WriteBuf;

pub const CASE_RANDOM_LEN: usize = 32;

pub const CASE_RESUMPTION_ID_LEN: usize = 16;

pub const CASE_SESSION_KEYS_LEN: usize = AEAD_CANON_KEY_LEN * 3;

canon!(
    CASE_RANDOM_LEN,
    CASE_RANDOM_ZEROED,
    CaseRandom,
    CaseRandomRef
);
canon!(
    CASE_RESUMPTION_ID_LEN,
    CASE_RESUMPTION_ID_ZEROED,
    CaseResumptionId,
    CaseResumptionIdRef
);
canon!(
    CASE_SESSION_KEYS_LEN,
    CASE_SESSION_KEYS_ZEROED,
    CaseSessionKeys,
    CaseSessionKeysRef
);

/// The CASE protocol handler type used during the CASE handshake
pub struct CaseP<'a, C: Crypto + 'a> {
    /// The peer's session ID
    peer_sessid: u16,
    /// The local session ID
    local_sessid: u16,
    /// The local fabric index for this session
    local_fabric_idx: u8,
    /// The ECDH Shared Secret
    shared_secret: CanonPkcSharedSecret,
    /// Our ephemeral public key
    our_pub_key: CanonPkcPublicKey,
    /// The peer's ephemeral public key
    peer_pub_key: CanonPkcPublicKey,
    /// The Transcript Hash
    tt: Optional<C::Hash<'a>>,
}

impl<'a, C: Crypto + 'a> CaseP<'a, C> {
    /// Create a new `CaseSession` instance
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            peer_sessid: 0,
            local_sessid: 0,
            local_fabric_idx: 0,
            shared_secret: PKC_SHARED_SECRET_ZEROED,
            our_pub_key: PKC_PUBLIC_KEY_ZEROED,
            peer_pub_key: PKC_PUBLIC_KEY_ZEROED,
            tt: Optional::none(),
        }
    }

    /// Return an in-place initializer for `CaseSession`
    pub fn init() -> impl Init<Self> {
        init!(Self {
            peer_sessid: 0,
            local_sessid: 0,
            local_fabric_idx: 0,
            shared_secret <- CanonPkcSharedSecret::init(),
            our_pub_key <- CanonPkcPublicKey::init(),
            peer_pub_key <- CanonPkcPublicKey::init(),
            tt <- Optional::init_none(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &mut self,
        crypto: &'a C,
        peer_sessid: u16,
        local_sessid: u16,
        local_fabric_idx: u8,
        peer_pub_key: CanonPkcPublicKeyRef<'_>,
        request: &[u8],
        our_random_out: &mut CaseRandom,
        resumption_id_out: &mut CaseResumptionId,
        tt_hash_out: &mut Hash,
    ) -> Result<(), Error> {
        self.peer_sessid = peer_sessid;
        self.local_sessid = local_sessid;
        self.local_fabric_idx = local_fabric_idx;

        self.peer_pub_key.load(peer_pub_key);

        let peer_pub_key = crypto.pub_key(peer_pub_key)?;

        // Create an ephemeral EC secret key
        let secret_key = crypto.generate_secret_key()?;

        secret_key.pub_key()?.write_canon(&mut self.our_pub_key)?;

        // Derive the Shared Secret
        secret_key.derive_shared_secret(&peer_pub_key, &mut self.shared_secret)?;
        //        println!("Derived secret: {:x?} len: {}", secret, len);

        let mut rand = crypto.rand()?;

        rand.fill_bytes(our_random_out.access_mut());
        rand.fill_bytes(resumption_id_out.access_mut());

        self.tt = Optional::some(crypto.hash()?);
        self.update_tt(request)?;

        self.current_tt_hash(tt_hash_out)?;

        Ok(())
    }

    pub fn local_fabric_idx(&self) -> u8 {
        self.local_fabric_idx
    }

    pub fn peer_sessid(&self) -> u16 {
        self.peer_sessid
    }

    pub fn local_sessid(&self) -> u16 {
        self.local_sessid
    }

    pub fn our_pub_key(&self) -> CanonPkcPublicKeyRef<'_> {
        self.our_pub_key.reference()
    }

    pub fn update_tt(&mut self, data: &[u8]) -> Result<(), Error> {
        unwrap!(self.tt.as_opt_mut()).update(data)
    }

    pub fn current_tt_hash(&mut self, out: &mut Hash) -> Result<(), Error> {
        unwrap!(self.tt.as_opt_mut()).finish_current(out)
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
    pub fn sigma2_encrypt(
        &self,
        crypto: &C,
        fabric: &Fabric,
        our_random: CaseRandomRef<'_>,
        our_hash: HashRef<'_>,
        signature: CanonPkcSignatureRef<'_>,
        resumption_id: CaseResumptionIdRef<'_>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut sigma2_key = AEAD_KEY_ZEROED;
        self.compute_sigma2_key(
            crypto,
            fabric.ipk().op_key(),
            our_random,
            our_hash,
            &mut sigma2_key,
        )?;

        let mut tw = WriteBuf::new(out);

        tw.start_struct(&TLVTag::Anonymous)?;
        tw.str(&TLVTag::Context(1), fabric.noc())?;
        if !fabric.icac().is_empty() {
            tw.str(&TLVTag::Context(2), fabric.icac())?
        };
        tw.str(&TLVTag::Context(3), signature.access())?;
        tw.str(&TLVTag::Context(4), resumption_id.access())?;
        tw.end_container()?;

        //println!("TBE is {:x?}", write_buf.as_borrow_slice());
        const NONCE: AeadNonceRef = AeadNonceRef::new(&[
            0x4e, 0x43, 0x41, 0x53, 0x45, 0x5f, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x32, 0x4e,
        ]);
        //        let nonce = GenericArray::from_slice(&nonce);
        //        type AesCcm = Ccm<Aes128, U16, U13>;
        //        let cipher = AesCcm::new(GenericArray::from_slice(key));

        tw.append(AEAD_TAG_ZEROED.access())?;
        let cipher_text = tw.as_mut_slice();

        let mut cypher = crypto.aead()?;

        cypher.encrypt_in_place(
            sigma2_key.reference(),
            NONCE,
            &[],
            cipher_text,
            cipher_text.len() - AEAD_TAG_LEN,
        )?;

        Ok(tw.as_slice().len())
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
    pub fn compute_sigma2_signature(
        &self,
        crypto: &C,
        fabric: &Fabric,
        tmp_buf: &mut [u8],
        signature: &mut CanonPkcSignature,
    ) -> Result<(), Error> {
        let mut tw = WriteBuf::new(tmp_buf);

        tw.start_struct(&TLVTag::Anonymous)?;
        tw.str(&TLVTag::Context(1), fabric.noc())?;
        if !fabric.icac().is_empty() {
            tw.str(&TLVTag::Context(2), fabric.icac())?;
        }
        tw.str(&TLVTag::Context(3), self.our_pub_key.access())?;
        tw.str(&TLVTag::Context(4), self.peer_pub_key.access())?;
        tw.end_container()?;
        //println!("TBS is {:x?}", write_buf.as_borrow_slice());

        let fabric_secret = crypto.secret_key(fabric.secret_key())?;
        fabric_secret.sign(tw.as_slice(), signature)?;

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
    fn compute_sigma2_key(
        &self,
        crypto: &C,
        ipk: CanonAeadKeyRef<'_>,
        our_random: CaseRandomRef<'_>,
        our_hash: HashRef<'_>,
        key: &mut CanonAeadKey,
    ) -> Result<(), Error> {
        const S2K_INFO: [u8; 6] = [0x53, 0x69, 0x67, 0x6d, 0x61, 0x32];

        let mut salt = CryptoSensitive::<
            { AEAD_CANON_KEY_LEN + 32 + PKC_CANON_PUBLIC_KEY_LEN + HASH_LEN },
        >::new();

        let salt_access: &mut [u8] = salt.access_mut();
        salt_access[..AEAD_CANON_KEY_LEN].copy_from_slice(ipk.access());
        salt_access[AEAD_CANON_KEY_LEN..][..32].copy_from_slice(our_random.access());
        salt_access[AEAD_CANON_KEY_LEN..][32..][..PKC_CANON_PUBLIC_KEY_LEN]
            .copy_from_slice(self.our_pub_key.access());
        salt_access[AEAD_CANON_KEY_LEN..][32..][PKC_CANON_PUBLIC_KEY_LEN..]
            .copy_from_slice(our_hash.access());

        crypto
            .kdf()?
            .expand(
                salt.access(),
                self.shared_secret.reference(),
                &S2K_INFO,
                key,
            )
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
    pub fn validate_certs(
        &self,
        crypto: &C,
        fabric: &Fabric,
        noc: &CertRef,
        icac: Option<&CertRef>,
        tmp_buf: &mut [u8],
    ) -> Result<(), Error> {
        let mut verifier = noc.verify_chain_start(crypto);

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
    pub fn validate_sigma3_signature(
        &self,
        crypto: &C,
        initiator_noc: &[u8],
        initiator_icac: Option<&[u8]>,
        initiator_noc_cert: &CertRef,
        signature: CanonPkcSignatureRef<'_>,
        tmp_buf: &mut [u8],
    ) -> Result<(), Error> {
        let mut tw = WriteBuf::new(tmp_buf);

        tw.start_struct(&TLVTag::Anonymous)?;
        tw.str(&TLVTag::Context(1), initiator_noc)?;
        if let Some(icac) = initiator_icac {
            tw.str(&TLVTag::Context(2), icac)?;
        }
        tw.str(&TLVTag::Context(3), self.peer_pub_key.access())?;
        tw.str(&TLVTag::Context(4), self.our_pub_key.access())?;
        tw.end_container()?;

        let pub_key =
            crypto.pub_key(CanonPkcPublicKeyRef::try_new(initiator_noc_cert.pubkey()?)?)?;
        if !pub_key.verify(tw.as_slice(), signature)? {
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
    pub fn compute_session_keys(
        &mut self,
        crypto: &C,
        ipk: CanonAeadKeyRef<'_>,
        keys: &mut CaseSessionKeys,
    ) -> Result<(), Error> {
        const SEKEYS_INFO: [u8; 11] = [
            0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x73,
        ];

        let mut tt_hash = HASH_ZEROED;
        self.current_tt_hash(&mut tt_hash)?;

        let mut salt = CryptoSensitive::<{ AEAD_CANON_KEY_LEN + HASH_LEN }>::new();

        let salt_access: &mut [u8] = salt.access_mut();
        salt_access[..AEAD_CANON_KEY_LEN].copy_from_slice(ipk.access());
        salt_access[AEAD_CANON_KEY_LEN..].copy_from_slice(tt_hash.access());

        //        println!("Session Key: salt: {:x?}, len: {}", salt, salt.len());

        crypto
            .kdf()?
            .expand(
                salt.access(),
                self.shared_secret.reference(),
                &SEKEYS_INFO,
                keys,
            )
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
    pub fn sigma3_decrypt(
        &mut self,
        crypto: &C,
        ipk: CanonAeadKeyRef<'_>,
        encrypted: &mut [u8],
    ) -> Result<usize, Error> {
        let mut sigma3_key = AEAD_KEY_ZEROED;
        self.compute_sigma3_key(crypto, ipk, &mut sigma3_key)?;
        // println!("Sigma3 Key: {:x?}", sigma3_key);

        const NONCE: AeadNonceRef = AeadNonceRef::new(&[
            0x4e, 0x43, 0x41, 0x53, 0x45, 0x5f, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x33, 0x4e,
        ]);

        let encrypted_len = encrypted.len();

        let mut cypher = crypto.aead()?;

        cypher.decrypt_in_place(sigma3_key.reference(), NONCE, &[], encrypted)?;
        Ok(encrypted_len - crypto::AEAD_TAG_LEN)
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
    fn compute_sigma3_key(
        &mut self,
        crypto: &C,
        ipk: CanonAeadKeyRef<'_>,
        key: &mut CanonAeadKey,
    ) -> Result<(), Error> {
        const S3K_INFO: [u8; 6] = [0x53, 0x69, 0x67, 0x6d, 0x61, 0x33];

        let mut tt_hash = HASH_ZEROED;
        self.current_tt_hash(&mut tt_hash)?;

        let mut salt = CryptoSensitive::<{ AEAD_CANON_KEY_LEN + HASH_LEN }>::new();

        let salt_access: &mut [u8] = salt.access_mut();
        salt_access[..AEAD_CANON_KEY_LEN].copy_from_slice(ipk.access());
        salt_access[AEAD_CANON_KEY_LEN..].copy_from_slice(tt_hash.access());

        //        println!("Sigma3Key: salt: {:x?}, len: {}", salt, salt.len());

        crypto
            .kdf()?
            .expand(
                salt.access(),
                self.shared_secret.reference(),
                &S3K_INFO,
                key,
            )
            .map_err(|_x| ErrorCode::InvalidData)?;
        //        println!("Sigma3Key: key: {:x?}", key);

        Ok(())
    }
}
