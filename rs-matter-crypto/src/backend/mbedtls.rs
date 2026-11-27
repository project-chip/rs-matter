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

//! MbedTLS-based crypto backend for Matter.
//!
//! The backend is only propagating errors originating from incorrect input data, such as invalid keys.
//! All other errors (including out of memory - for now) are considered unrecoverable and will cause a panic.
//! This is done so that programming errors are caught early-on, with meaningful location and backtraces,
//! even in `no_std` environments where backtrace capturing during error propagation does not work.
//!
//! The MbedTLS backend might or might not use hardware acceleration under the hood depending on the target platform.
//! For example, on ESP32 chips it uses HW acceleration for the SHA algorithms, and might use HW acceleration for the
//! ECC operations and AEAD-CCM in the near future.
//!
//! In any case, the hardware acceleration is encapsulated by the MbedTLS crate and is transparent to the users of
//! this crypto backend. This is unlike the RustCrypto backend, where users are expected to provide their own variations
//! of the crypto backend where certain primitives are replaced by hardware-accelerated implementations.

/// Check the result of an MbedTLS call: an allocation failure is reported as
/// `NoMemory`, an invalid key, point or scalar as `InvalidInput`, and any other
/// error is a bug, so it panics.
macro_rules! merr_check {
    ($expr:expr) => {{
        let result = $expr;
        match mbedtls_rs_sys::merr!(result) {
            Ok(val) => Ok::<_, $crate::error::CryptoError>(val),
            Err(err) => Err(error_or_panic(err)),
        }
    }};
}

use core::ffi::{c_int, c_uchar, c_void};

use mbedtls_rs_sys::{merr, MbedtlsError};

use rand_core::{CryptoRng, Rng, TryCryptoRng, TryRng};

use crate::error::{CryptoError, CryptoErrorCode};
use crate::utils::cell::RefCell;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::MaybeSend;
use crate::{CanonPkcSecretKeyRef, CryptoSensitive, CryptoSensitiveRef, SharedRand};

/// MbedTLS-based crypto backend for Matter.
pub struct MbedtlsCrypto<'s, T> {
    /// Elliptic curve group (secp256r1)
    ec_group: SharedECGroup<{ crate::EC_CANON_POINT_LEN }, { crate::EC_CANON_SCALAR_LEN }>,
    /// A shared cryptographic random number generator
    rng: SharedRand<T>,
    /// The singleton secret key to be returned by `Crypto::singleton_singing_secret_key`
    singleton_secret_key: CanonPkcSecretKeyRef<'s>,
}

impl<'s, T> MbedtlsCrypto<'s, T> {
    /// Create a new MbedTLS crypto backend.
    ///
    /// # Arguments
    /// - `rng` - A cryptographic random number generator
    /// - `singleton_secret_key` - A singleton secret key to be returned by `Crypto::singleton_singing_secret_key`
    ///   The primary use-case for this secret key is to be used as the secret key for the Device Attestation credentials
    pub fn new(rng: T, singleton_secret_key: CanonPkcSecretKeyRef<'s>) -> Self {
        let mut ec_group = ECGroup::new();
        unwrap!(unsafe {
            ec_group.set(mbedtls_rs_sys::mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1)
        });

        Self {
            ec_group: SharedECGroup::new(ec_group),
            rng: SharedRand::new(rng),
            singleton_secret_key,
        }
    }
}

impl<T> crate::Crypto for MbedtlsCrypto<'_, T>
where
    T: CryptoRng + MaybeSend,
{
    type Rand<'a>
        = &'a SharedRand<T>
    where
        Self: 'a;

    type WeakRand<'a>
        = &'a SharedRand<T>
    where
        Self: 'a;

    type Hash<'a>
        = Sha256
    where
        Self: 'a;

    type Hash1<'a>
        = Sha1
    where
        Self: 'a;

    type Hmac<'a>
        = Hmac<{ crate::HASH_LEN }>
    where
        Self: 'a;

    type Kdf<'a>
        = Hkdf
    where
        Self: 'a;

    type PbKdf<'a>
        = Pbkdf2Hmac
    where
        Self: 'a;

    type Aead<'a>
        = AeadCcm<{ crate::AEAD_CANON_KEY_LEN }, { crate::AEAD_NONCE_LEN }, { crate::AEAD_TAG_LEN }>
    where
        Self: 'a;

    type PublicKey<'a>
        = ECPoint<'a, { crate::EC_CANON_POINT_LEN }, { crate::EC_CANON_SCALAR_LEN }, SharedRand<T>>
    where
        Self: 'a;

    type SecretKey<'a>
        = ECScalar<'a, { crate::EC_CANON_SCALAR_LEN }, { crate::EC_CANON_POINT_LEN }, SharedRand<T>>
    where
        Self: 'a;

    type SigningSecretKey<'a>
        = ECScalar<'a, { crate::EC_CANON_SCALAR_LEN }, { crate::EC_CANON_POINT_LEN }, SharedRand<T>>
    where
        Self: 'a;

    type EcScalar<'a>
        = ECScalar<'a, { crate::EC_CANON_SCALAR_LEN }, { crate::EC_CANON_POINT_LEN }, SharedRand<T>>
    where
        Self: 'a;

    type EcPoint<'a>
        = ECPoint<'a, { crate::EC_CANON_POINT_LEN }, { crate::EC_CANON_SCALAR_LEN }, SharedRand<T>>
    where
        Self: 'a;

    fn rand(&self) -> Result<Self::Rand<'_>, CryptoError> {
        Ok(&self.rng)
    }

    fn weak_rand(&self) -> Result<Self::WeakRand<'_>, CryptoError> {
        Ok(&self.rng)
    }

    fn hash(&self) -> Result<Self::Hash<'_>, CryptoError> {
        Ok(Sha256::new())
    }

    fn hash1(&self) -> Result<Self::Hash1<'_>, CryptoError> {
        Ok(Sha1::new())
    }

    fn hmac<const KEY_LEN: usize>(
        &self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
    ) -> Result<Self::Hmac<'_>, CryptoError> {
        unsafe {
            Hmac::new(
                mbedtls_rs_sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
                key.access(),
            )
        }
    }

    fn kdf(&self) -> Result<Self::Kdf<'_>, CryptoError> {
        Ok(Hkdf::new(
            mbedtls_rs_sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
        ))
    }

    fn pbkdf(&self) -> Result<Self::PbKdf<'_>, CryptoError> {
        Ok(Pbkdf2Hmac::new(
            mbedtls_rs_sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
        ))
    }

    fn aead(&self) -> Result<Self::Aead<'_>, CryptoError> {
        Ok(unsafe { AeadCcm::new(mbedtls_rs_sys::mbedtls_cipher_id_t_MBEDTLS_CIPHER_ID_AES) })
    }

    fn pub_key(
        &self,
        key: crate::CanonPkcPublicKeyRef<'_>,
    ) -> Result<Self::PublicKey<'_>, CryptoError> {
        self.ec_point(key)
    }

    fn generate_secret_key(&self) -> Result<Self::SecretKey<'_>, CryptoError> {
        self.generate_ec_scalar()
    }

    fn secret_key(
        &self,
        key: crate::CanonPkcSecretKeyRef<'_>,
    ) -> Result<Self::SecretKey<'_>, CryptoError> {
        let result = self.ec_scalar(key)?;

        // A secret key must not be zero either
        self.ec_group.access(|group| {
            merr_check!(unsafe {
                mbedtls_rs_sys::mbedtls_ecp_check_privkey(&group.raw, &result.mpi.raw)
            })
        })?;

        Ok(result)
    }

    fn singleton_singing_secret_key(&self) -> Result<Self::SigningSecretKey<'_>, CryptoError> {
        self.secret_key(self.singleton_secret_key)
    }

    fn ec_scalar(
        &self,
        scalar: crate::CanonEcScalarRef<'_>,
    ) -> Result<Self::EcScalar<'_>, CryptoError> {
        let mut result = ECScalar::new(&self.ec_group, &self.rng);
        unsafe {
            result.set(scalar)?;
        }

        // The scalar must be below the group order
        let valid = self.ec_group.access(|group| unsafe {
            mbedtls_rs_sys::mbedtls_mpi_cmp_mpi(&result.mpi.raw, &group.raw.N) < 0
        });

        if !valid {
            Err(CryptoErrorCode::InvalidInput)?;
        }

        Ok(result)
    }

    fn ec_scalar_mod_p(
        &self,
        uint: crate::CanonUint320Ref<'_>,
    ) -> Result<Self::EcScalar<'_>, CryptoError> {
        let mut result = ECScalar::new(&self.ec_group, &self.rng);

        let mut mpi = Mpi::new();
        mpi.set(uint.access())?;

        self.ec_group.access(|group| {
            merr_check!(unsafe {
                mbedtls_rs_sys::mbedtls_mpi_mod_mpi(&mut result.mpi.raw, &mpi.raw, &group.raw.N)
            })
        })?;

        Ok(result)
    }

    fn generate_ec_scalar(&self) -> Result<Self::EcScalar<'_>, CryptoError> {
        let mut result = ECScalar::new(&self.ec_group, &self.rng);

        self.ec_group.access(|group| {
            merr_check!(unsafe {
                mbedtls_rs_sys::mbedtls_ecp_gen_privkey(
                    &group.raw,
                    &mut result.mpi.raw,
                    Some(mbedtls_platform_rng::<SharedRand<T>>),
                    &self.rng as *const _ as *const _ as *mut _,
                )
            })
        })?;

        Ok(result)
    }

    fn ec_point(
        &self,
        point: crate::CanonEcPointRef<'_>,
    ) -> Result<Self::EcPoint<'_>, CryptoError> {
        let mut result = ECPoint::new(&self.ec_group, &self.rng);
        unsafe {
            result.set(point)?;
        }

        // `mbedtls_ecp_point_read_binary` only parses the coordinates; the
        // point must be on the curve (and not the identity) to be usable
        if !crate::EcPoint::is_valid_pubkey(&result)? {
            Err(CryptoErrorCode::InvalidInput)?;
        }

        Ok(result)
    }

    fn ec_generator_point(&self) -> Result<Self::EcPoint<'_>, CryptoError> {
        let mut result = ECPoint::new(&self.ec_group, &self.rng);

        self.ec_group.access(|group| {
            merr_check!(unsafe { mbedtls_rs_sys::mbedtls_ecp_copy(&mut result.raw, &group.raw.G) })
        })?;

        Ok(result)
    }
}

/// SHA-256 hash implementation using MbedTLS.
pub struct Sha256 {
    /// Raw MbedTLS SHA-256 context
    raw: mbedtls_rs_sys::mbedtls_sha256_context,
}

impl Sha256 {
    /// Create a new SHA-256 hash instance.
    fn new() -> Self {
        let mut raw = Default::default();

        unsafe {
            mbedtls_rs_sys::mbedtls_sha256_init(&mut raw);
            mbedtls_rs_sys::mbedtls_sha256_starts(&mut raw, 0);
        }

        Self { raw }
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        unsafe {
            mbedtls_rs_sys::mbedtls_sha256_free(&mut self.raw);
        }
    }
}

impl Clone for Sha256 {
    fn clone(&self) -> Self {
        let mut raw = Default::default();

        unsafe {
            mbedtls_rs_sys::mbedtls_sha256_init(&mut raw);
            mbedtls_rs_sys::mbedtls_sha256_clone(&mut raw, &self.raw);
        }

        Self { raw }
    }
}

impl crate::Digest<{ crate::HASH_LEN }> for Sha256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_sha256_update(&mut self.raw, data.as_ptr(), data.len())
        })?;

        Ok(())
    }

    fn finish_current(
        &mut self,
        hash: &mut CryptoSensitive<{ crate::HASH_LEN }>,
    ) -> Result<(), CryptoError> {
        let copy = self.clone();

        copy.finish(hash)
    }

    fn finish(mut self, out: &mut CryptoSensitive<{ crate::HASH_LEN }>) -> Result<(), CryptoError> {
        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_sha256_finish(&mut self.raw, out.access_mut().as_mut_ptr())
        })?;

        Ok(())
    }
}

/// SHA-1 hash implementation using MbedTLS.
pub struct Sha1 {
    /// Raw MbedTLS SHA-1 context
    raw: mbedtls_rs_sys::mbedtls_sha1_context,
}

impl Sha1 {
    /// Create a new SHA-1 hash instance.
    fn new() -> Self {
        let mut raw = Default::default();

        unsafe {
            mbedtls_rs_sys::mbedtls_sha1_init(&mut raw);
            mbedtls_rs_sys::mbedtls_sha1_starts(&mut raw);
        }

        Self { raw }
    }
}

impl Drop for Sha1 {
    fn drop(&mut self) {
        unsafe {
            mbedtls_rs_sys::mbedtls_sha1_free(&mut self.raw);
        }
    }
}

impl Clone for Sha1 {
    fn clone(&self) -> Self {
        let mut raw = Default::default();

        unsafe {
            mbedtls_rs_sys::mbedtls_sha1_init(&mut raw);
            mbedtls_rs_sys::mbedtls_sha1_clone(&mut raw, &self.raw);
        }

        Self { raw }
    }
}

impl crate::Digest<{ crate::SHA1_HASH_LEN }> for Sha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_sha1_update(&mut self.raw, data.as_ptr(), data.len())
        })?;

        Ok(())
    }

    fn finish_current(
        &mut self,
        hash: &mut CryptoSensitive<{ crate::SHA1_HASH_LEN }>,
    ) -> Result<(), CryptoError> {
        let copy = self.clone();

        copy.finish(hash)
    }

    fn finish(
        mut self,
        out: &mut CryptoSensitive<{ crate::SHA1_HASH_LEN }>,
    ) -> Result<(), CryptoError> {
        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_sha1_finish(&mut self.raw, out.access_mut().as_mut_ptr())
        })?;

        Ok(())
    }
}

/// HMAC implementation using MbedTLS.
pub struct Hmac<const HASH_LEN: usize> {
    /// Raw MbedTLS MD context
    raw: mbedtls_rs_sys::mbedtls_md_context_t,
}

impl<const HASH_LEN: usize> Hmac<HASH_LEN> {
    /// Create a new HMAC instance with the given key.
    ///
    /// # Safety
    /// The caller must ensure that the provided `md_type` corresponds to the `HASH_LEN`
    /// generic parameter.
    unsafe fn new(
        md_type: mbedtls_rs_sys::mbedtls_md_type_t,
        key: &[u8],
    ) -> Result<Self, CryptoError> {
        let mut this = Self {
            raw: Default::default(),
        };

        unsafe {
            mbedtls_rs_sys::mbedtls_md_init(&mut this.raw);
        }

        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_md_setup(
                &mut this.raw,
                mbedtls_rs_sys::mbedtls_md_info_from_type(md_type),
                1,
            )
        })?;

        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_md_hmac_starts(&mut this.raw, key.as_ptr(), key.len())
        })?;

        Ok(this)
    }
}

impl<const HASH_LEN: usize> Drop for Hmac<HASH_LEN> {
    fn drop(&mut self) {
        unsafe {
            mbedtls_rs_sys::mbedtls_md_free(&mut self.raw);
        }
    }
}

// SAFETY: The pointers of the MbedTLS context refer to memory owned by the context, or to
// static tables, and MbedTLS keeps no per-thread state for it.
unsafe impl<const HASH_LEN: usize> Send for Hmac<HASH_LEN> {}

impl<const HASH_LEN: usize> Clone for Hmac<HASH_LEN> {
    fn clone(&self) -> Self {
        let mut raw = Default::default();

        unsafe {
            mbedtls_rs_sys::mbedtls_md_init(&mut raw);
            mbedtls_rs_sys::mbedtls_md_clone(&mut raw, &self.raw);
        }

        Self { raw }
    }
}

impl<const HASH_LEN: usize> crate::Digest<HASH_LEN> for Hmac<HASH_LEN> {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_md_hmac_update(&mut self.raw, data.as_ptr(), data.len())
        })?;

        Ok(())
    }

    fn finish_current(&mut self, hash: &mut CryptoSensitive<HASH_LEN>) -> Result<(), CryptoError> {
        let copy = self.clone();

        copy.finish(hash)
    }

    fn finish(mut self, out: &mut CryptoSensitive<HASH_LEN>) -> Result<(), CryptoError> {
        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_md_hmac_finish(&mut self.raw, out.access_mut().as_mut_ptr())
        })?;

        Ok(())
    }
}

/// HKDF implementation using MbedTLS.
pub struct Hkdf {
    /// Message digest type
    md_type: mbedtls_rs_sys::mbedtls_md_type_t,
}

impl Hkdf {
    /// Create a new HKDF instance.
    fn new(md_type: mbedtls_rs_sys::mbedtls_md_type_t) -> Self {
        Self { md_type }
    }
}

impl crate::Kdf for Hkdf {
    fn expand<const IKM_LEN: usize, const KEY_LEN: usize>(
        self,
        salt: &[u8],
        ikm: CryptoSensitiveRef<'_, IKM_LEN>,
        info: &[u8],
        key: &mut CryptoSensitive<KEY_LEN>,
    ) -> Result<(), CryptoError> {
        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_hkdf(
                mbedtls_rs_sys::mbedtls_md_info_from_type(self.md_type),
                salt.as_ptr(),
                salt.len(),
                ikm.access().as_ptr(),
                IKM_LEN,
                info.as_ptr(),
                info.len(),
                key.access_mut().as_mut_ptr(),
                KEY_LEN,
            )
        })?;

        Ok(())
    }
}

/// PBKDF2-HMAC implementation using MbedTLS.
pub struct Pbkdf2Hmac {
    /// Message digest type
    md_type: mbedtls_rs_sys::mbedtls_md_type_t,
}

impl Pbkdf2Hmac {
    /// Create a new PBKDF2-HMAC instance.
    fn new(md_type: mbedtls_rs_sys::mbedtls_md_type_t) -> Self {
        Self { md_type }
    }
}

impl crate::PbKdf for Pbkdf2Hmac {
    fn derive<const PASS_LEN: usize, const KEY_LEN: usize>(
        self,
        password: CryptoSensitiveRef<'_, PASS_LEN>,
        iter: usize,
        salt: &[u8],
        out: &mut CryptoSensitive<KEY_LEN>,
    ) -> Result<(), CryptoError> {
        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_pkcs5_pbkdf2_hmac_ext(
                self.md_type,
                password.access().as_ptr(),
                PASS_LEN,
                salt.as_ptr(),
                salt.len(),
                iter as u32,
                KEY_LEN as _,
                out.access_mut().as_mut_ptr(),
            )
        })?;

        Ok(())
    }
}

/// AEAD-CCM implementation using MbedTLS.
pub struct AeadCcm<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize> {
    /// Cipher type
    cipher_id: mbedtls_rs_sys::mbedtls_cipher_id_t,
}

impl<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>
    AeadCcm<KEY_LEN, NONCE_LEN, TAG_LEN>
{
    /// Create a new AEAD-CCM instance.
    ///
    /// # Safety
    /// The caller must ensure that the provided `cipher_type` corresponds to the
    /// `KEY_LEN`, `NONCE_LEN`, and `TAG_LEN` generic parameters.
    unsafe fn new(cipher_id: mbedtls_rs_sys::mbedtls_cipher_id_t) -> Self {
        Self { cipher_id }
    }
}

impl<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>
    crate::Aead<KEY_LEN, NONCE_LEN> for AeadCcm<KEY_LEN, NONCE_LEN, TAG_LEN>
{
    fn encrypt_in_place<'a>(
        &mut self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
        nonce: CryptoSensitiveRef<'_, NONCE_LEN>,
        aad: &[u8],
        data: &'a mut [u8],
        data_len: usize,
    ) -> Result<&'a [u8], CryptoError> {
        if data.len() < data_len + TAG_LEN {
            Err(CryptoErrorCode::BufferTooSmall)?;
        }

        let mut ctx = Default::default();

        unsafe {
            mbedtls_rs_sys::mbedtls_ccm_init(&mut ctx);
        }

        let result = merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_ccm_setkey(
                &mut ctx,
                self.cipher_id,
                key.access().as_ptr(),
                (KEY_LEN * 8) as u32,
            )
        })
        .and_then(|_| {
            merr_check!(unsafe {
                mbedtls_rs_sys::mbedtls_ccm_encrypt_and_tag(
                    &mut ctx,
                    data_len,
                    nonce.access().as_ptr(),
                    NONCE_LEN,
                    aad.as_ptr(),
                    aad.len(),
                    data.as_ptr(),
                    data.as_mut_ptr(),
                    data.as_mut_ptr().add(data_len),
                    TAG_LEN,
                )
            })
        });

        unsafe {
            mbedtls_rs_sys::mbedtls_ccm_free(&mut ctx);
        }

        result?;

        Ok(&data[..data_len + TAG_LEN])
    }

    fn decrypt_in_place<'a>(
        &mut self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
        nonce: CryptoSensitiveRef<'_, NONCE_LEN>,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        if data.len() < TAG_LEN {
            // Nothing to authenticate
            Err(CryptoErrorCode::InvalidInput)?;
        }

        let mut ctx = Default::default();

        unsafe {
            mbedtls_rs_sys::mbedtls_ccm_init(&mut ctx);
        }

        let ret = merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_ccm_setkey(
                &mut ctx,
                self.cipher_id,
                key.access().as_ptr(),
                (KEY_LEN * 8) as u32,
            )
        })
        .map(|_| unsafe {
            mbedtls_rs_sys::mbedtls_ccm_auth_decrypt(
                &mut ctx,
                data.len() - TAG_LEN,
                nonce.access().as_ptr(),
                NONCE_LEN,
                aad.as_ptr(),
                aad.len(),
                data.as_ptr(),
                data.as_mut_ptr(),
                data.as_mut_ptr().add(data.len() - TAG_LEN),
                TAG_LEN,
            )
        });

        unsafe {
            mbedtls_rs_sys::mbedtls_ccm_free(&mut ctx);
        }

        let ret = ret?;

        // A failed tag means a corrupted, replayed or foreign message; any other
        // error is a bug, as `merr_check!` treats it
        if ret == mbedtls_rs_sys::MBEDTLS_ERR_CCM_AUTH_FAILED {
            Err(CryptoErrorCode::InvalidInput)?;
        }
        merr_check!(ret)?;

        Ok(&data[..data.len() - TAG_LEN])
    }
}

/// Multi-precision integer (MPI) implementation using MbedTLS.
pub struct Mpi {
    /// Raw MbedTLS MPI
    raw: mbedtls_rs_sys::mbedtls_mpi,
}

impl Mpi {
    /// Create a new MPI instance.
    fn new() -> Self {
        let mut raw = Default::default();

        unsafe {
            mbedtls_rs_sys::mbedtls_mpi_init(&mut raw);
        }

        Self { raw }
    }

    /// Set the MPI from the given BE byte representation.
    fn set(&mut self, uint: &[u8]) -> Result<(), CryptoError> {
        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_mpi_read_binary(&mut self.raw, uint.as_ptr(), uint.len())
        })?;

        Ok(())
    }

    /// Write the MPI to the given BE byte array.
    ///
    /// The method will panic if the provided buffer is not large enough.
    fn write(&self, uint: &mut [u8]) -> Result<(), CryptoError> {
        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_mpi_write_binary(&self.raw, uint.as_mut_ptr(), uint.len())
        })?;

        Ok(())
    }
}

impl Drop for Mpi {
    fn drop(&mut self) {
        unsafe {
            mbedtls_rs_sys::mbedtls_mpi_free(&mut self.raw);
        }
    }
}

// SAFETY: The pointers of the MbedTLS context refer to memory owned by the context, or to
// static tables, and MbedTLS keeps no per-thread state for it.
unsafe impl Send for Mpi {}

/// A shareable elliptic curve group protected by a mutex.
///
/// Necessary because a lot of MbedTLS EC functions require a mutable reference to the group,
/// even for read-only operations.
pub struct SharedECGroup<const LEN: usize, const SCALAR_LEN: usize> {
    inner: Mutex<RefCell<ECGroup<LEN, SCALAR_LEN>>>,
}

impl<const LEN: usize, const SCALAR_LEN: usize> SharedECGroup<LEN, SCALAR_LEN> {
    /// Create a new shared EC group instance.
    pub const fn new(group: ECGroup<LEN, SCALAR_LEN>) -> Self {
        Self {
            inner: Mutex::new(RefCell::new(group)),
        }
    }

    /// Access the inner EC group with a closure.
    ///
    /// The closure receives a mutable reference to the EC group.
    pub fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut ECGroup<LEN, SCALAR_LEN>) -> R,
    {
        self.inner.lock(|group| f(&mut group.borrow_mut()))
    }
}

/// Elliptic curve group implementation using MbedTLS.
pub struct ECGroup<const LEN: usize, const SCALAR_LEN: usize> {
    /// Raw MbedTLS EC group
    raw: mbedtls_rs_sys::mbedtls_ecp_group,
}

impl<const LEN: usize, const SCALAR_LEN: usize> ECGroup<LEN, SCALAR_LEN> {
    /// Create a new EC group instance.
    fn new() -> Self {
        let mut raw = Default::default();

        unsafe {
            mbedtls_rs_sys::mbedtls_ecp_group_init(&mut raw);
        }

        Self { raw }
    }

    /// Set the EC group to the specified group ID.
    ///
    /// # Safety
    /// The caller must ensure that the provided `group_id` matches the
    /// `LEN` and `SCALAR_LEN` generic parameters.
    unsafe fn set(
        &mut self,
        group_id: mbedtls_rs_sys::mbedtls_ecp_group_id,
    ) -> Result<(), CryptoError> {
        merr_check!(unsafe { mbedtls_rs_sys::mbedtls_ecp_group_load(&mut self.raw, group_id) })?;

        Ok(())
    }
}

impl<const LEN: usize, const SCALAR_LEN: usize> Drop for ECGroup<LEN, SCALAR_LEN> {
    fn drop(&mut self) {
        unsafe {
            mbedtls_rs_sys::mbedtls_ecp_group_free(&mut self.raw);
        }
    }
}

// SAFETY: The pointers of the MbedTLS context refer to memory owned by the context, or to
// static tables, and MbedTLS keeps no per-thread state for it.
unsafe impl<const LEN: usize, const SCALAR_LEN: usize> Send for ECGroup<LEN, SCALAR_LEN> {}

/// Elliptic curve point implementation using MbedTLS.
pub struct ECPoint<'a, const LEN: usize, const SCALAR_LEN: usize, R> {
    /// Associated EC group
    group: &'a SharedECGroup<LEN, SCALAR_LEN>,
    /// The random number generator
    rng: &'a R,
    /// Raw MbedTLS EC point
    raw: mbedtls_rs_sys::mbedtls_ecp_point,
}

impl<'a, const LEN: usize, const SCALAR_LEN: usize, R> ECPoint<'a, LEN, SCALAR_LEN, R> {
    /// Create a new EC point instance with an empty point.
    ///
    /// The point MUST be initialized post-creation using `set()`.
    ///
    /// # Arguments
    /// - `group`: Reference to the associated EC group.
    ///
    /// # Returns
    /// - New EC point instance.
    fn new(group: &'a SharedECGroup<LEN, SCALAR_LEN>, rng: &'a R) -> Self {
        let mut raw = Default::default();

        unsafe {
            mbedtls_rs_sys::mbedtls_ecp_point_init(&mut raw);
        }

        Self { group, rng, raw }
    }

    /// Set the EC point from the given byte representation.
    unsafe fn set(&mut self, point: CryptoSensitiveRef<LEN>) -> Result<(), CryptoError> {
        self.group
            .access(|group| {
                merr!(unsafe {
                    mbedtls_rs_sys::mbedtls_ecp_point_read_binary(
                        &group.raw,
                        &mut self.raw,
                        point.access().as_ptr(),
                        LEN,
                    )
                })
            })
            .map_err(|e| {
                error!("Failed to read EC point: {}", e);

                no_memory_or(e, CryptoErrorCode::InvalidInput)
            })?;

        Ok(())
    }

    /// Write the EC point to the given byte array in uncompressed format.
    fn write(&self, point: &mut CryptoSensitive<LEN>) -> Result<(), CryptoError> {
        let mut olen = 0;

        self.group.access(|group| {
            merr_check!(unsafe {
                mbedtls_rs_sys::mbedtls_ecp_point_write_binary(
                    &group.raw,
                    &self.raw,
                    mbedtls_rs_sys::MBEDTLS_ECP_PF_UNCOMPRESSED as _,
                    &mut olen,
                    point.access_mut().as_mut_ptr(),
                    LEN,
                )
            })
        })?;

        // Only the point at infinity is shorter, and it has no canonical form
        if olen != LEN {
            Err(CryptoErrorCode::InvalidInput)?;
        }

        Ok(())
    }
}

impl<const LEN: usize, const SCALAR_LEN: usize, R> Drop for ECPoint<'_, LEN, SCALAR_LEN, R> {
    fn drop(&mut self) {
        unsafe {
            mbedtls_rs_sys::mbedtls_ecp_point_free(&mut self.raw);
        }
    }
}

// SAFETY: The pointers of the MbedTLS context refer to memory owned by the context, or to
// static tables, and MbedTLS keeps no per-thread state for it.
unsafe impl<const LEN: usize, const SCALAR_LEN: usize, R> Send for ECPoint<'_, LEN, SCALAR_LEN, R>
where
    SharedECGroup<LEN, SCALAR_LEN>: Sync,
    R: Sync,
{
}

impl<'a, const LEN: usize, const SCALAR_LEN: usize, R> crate::EcPoint<'a, LEN, SCALAR_LEN>
    for ECPoint<'a, LEN, SCALAR_LEN, R>
where
    for<'r> &'r R: CryptoRng,
{
    type Scalar<'s>
        = ECScalar<'s, SCALAR_LEN, LEN, R>
    where
        Self: 'a + 's;

    fn is_valid_pubkey(&self) -> Result<bool, CryptoError> {
        // `mbedtls_ecp_check_pubkey` performs the full RFC-9383 public-key
        // validation: the point is on the curve, its coordinates are in range,
        // and it is not the identity (zero) point. It returns `0` for a valid
        // key, `MBEDTLS_ERR_ECP_INVALID_KEY` for an invalid point, or *another*
        // negative error code on an internal failure. Map the first two to the
        // boolean verdict and let `merr_check!` panic on any other failure, as
        // the rest of this backend does for unrecoverable internal errors.
        let rc = self.group.access(|group| unsafe {
            mbedtls_rs_sys::mbedtls_ecp_check_pubkey(&group.raw, &self.raw)
        });

        match rc {
            0 => Ok(true),
            mbedtls_rs_sys::MBEDTLS_ERR_ECP_INVALID_KEY => Ok(false),
            other => {
                // Not a validity verdict — an internal failure. Surface it the
                // same way as every other call in this backend (panic).
                merr_check!(other)?;
                unreachable!()
            }
        }
    }

    fn neg(&self) -> Result<Self, CryptoError> {
        assert!(unsafe { mbedtls_rs_sys::mbedtls_mpi_cmp_int(&self.raw.private_Z, 1) } == 0);

        let mut result = ECPoint::new(self.group, self.rng);

        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_mpi_copy(&mut result.raw.private_X, &self.raw.private_X)
        })?;

        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_mpi_lset(&mut result.raw.private_Z, 1)
            //mbedtls_rs_sys::mbedtls_mpi_copy(&mut result.raw.private_Z, &self.raw.private_Z)
        })?;

        if unsafe { mbedtls_rs_sys::mbedtls_mpi_cmp_int(&self.raw.private_Y, 0) } != 0 {
            self.group.access(|group| {
                merr_check!(unsafe {
                    mbedtls_rs_sys::mbedtls_mpi_sub_mpi(
                        &mut result.raw.private_Y,
                        &group.raw.P,
                        &self.raw.private_Y,
                    )
                })
            })?;
        } else {
            merr_check!(unsafe {
                mbedtls_rs_sys::mbedtls_mpi_copy(&mut result.raw.private_Y, &self.raw.private_Y)
            })?;
        }

        Ok(result)
    }

    fn mul(&self, scalar: &Self::Scalar<'a>) -> Result<Self, CryptoError> {
        let mut result = ECPoint::new(self.group, self.rng);

        self.group.access(|group| {
            merr_check!(unsafe {
                mbedtls_rs_sys::mbedtls_ecp_mul(
                    &mut group.raw,
                    &mut result.raw,
                    &scalar.mpi.raw,
                    &self.raw,
                    Some(mbedtls_platform_rng::<R>),
                    self.rng as *const _ as *const _ as *mut _,
                )
            })
        })?;

        Ok(result)
    }

    fn add_mul(
        &self,
        s1: &Self::Scalar<'a>,
        p2: &Self,
        s2: &Self::Scalar<'a>,
    ) -> Result<Self, CryptoError> {
        let mut result = ECPoint::new(self.group, self.rng);

        self.group.access(|group| {
            merr_check!(unsafe {
                mbedtls_rs_sys::mbedtls_ecp_muladd(
                    &mut group.raw,
                    &mut result.raw,
                    &s1.mpi.raw,
                    &self.raw,
                    &s2.mpi.raw,
                    &p2.raw,
                )
            })
        })?;

        Ok(result)
    }

    fn write_canon(&self, point: &mut CryptoSensitive<LEN>) -> Result<(), CryptoError> {
        self.write(point)
    }
}

impl<'a, const KEY_LEN: usize, const SECRET_KEY_LEN: usize, const SIGNATURE_LEN: usize, R>
    crate::PublicKey<'a, KEY_LEN, SIGNATURE_LEN> for ECPoint<'a, KEY_LEN, SECRET_KEY_LEN, R>
{
    fn verify(
        &self,
        data: &[u8],
        signature: CryptoSensitiveRef<'_, SIGNATURE_LEN>,
    ) -> Result<bool, CryptoError> {
        let mut r = Mpi::new();
        let mut s = Mpi::new();

        let (r_signature, s_signature) = signature.access().split_at(SIGNATURE_LEN / 2);

        r.set(r_signature)?;
        s.set(s_signature)?;

        use crate::Digest;

        let mut sha256 = Sha256::new();
        sha256.update(data)?;

        let mut hash = crate::HASH_ZEROED;
        sha256.finish(&mut hash)?;

        let result = self.group.access(|group| unsafe {
            mbedtls_rs_sys::mbedtls_ecdsa_verify(
                &mut group.raw,
                hash.access_mut().as_ptr(),
                crate::HASH_LEN,
                &self.raw,
                &r.raw,
                &s.raw,
            )
        });

        Ok(result == 0)
    }

    fn write_canon(&self, key: &mut CryptoSensitive<KEY_LEN>) -> Result<(), CryptoError> {
        self.write(key)
    }
}

/// Elliptic curve scalar implementation using MbedTLS.
pub struct ECScalar<'a, const LEN: usize, const POINT_LEN: usize, R> {
    /// Associated EC group
    group: &'a SharedECGroup<POINT_LEN, LEN>,
    /// The random number generator
    rng: &'a R,
    /// Scalar
    mpi: Mpi,
}

impl<'a, const LEN: usize, const POINT_LEN: usize, R> ECScalar<'a, LEN, POINT_LEN, R> {
    /// Create a new, empty EC scalar instance.
    ///
    /// The scalar value MUST be initialized post-creation
    /// using `set()`.
    fn new(group: &'a SharedECGroup<POINT_LEN, LEN>, rng: &'a R) -> Self {
        Self {
            group,
            rng,
            mpi: Mpi::new(),
        }
    }

    /// Set the EC scalar from the given byte representation.
    unsafe fn set(&mut self, scalar: CryptoSensitiveRef<LEN>) -> Result<(), CryptoError> {
        self.mpi.set(scalar.access())
    }

    /// Write the EC scalar to the given byte array.
    fn write(&self, scalar: &mut CryptoSensitive<LEN>) -> Result<(), CryptoError> {
        self.mpi.write(scalar.access_mut())
    }
}

impl<'a, const LEN: usize, const POINT_LEN: usize, R> crate::EcScalar<'a, LEN>
    for ECScalar<'a, LEN, POINT_LEN, R>
where
    for<'r> &'r R: CryptoRng,
{
    fn mul(&self, other: &Self) -> Result<Self, CryptoError> {
        let mut result = ECScalar::new(self.group, self.rng);

        let mut mpi = Mpi::new();

        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_mpi_mul_mpi(&mut mpi.raw, &self.mpi.raw, &other.mpi.raw)
        })?;

        // TODO: Can this be done faster?
        // See the `ecp_modp` function which is unfortunately not a public API in `ecp.h`
        self.group.access(|group| {
            merr_check!(unsafe {
                mbedtls_rs_sys::mbedtls_mpi_mod_mpi(&mut result.mpi.raw, &mpi.raw, &group.raw.N)
            })
        })?;

        Ok(result)
    }

    fn write_canon(&self, scalar: &mut CryptoSensitive<LEN>) -> Result<(), CryptoError> {
        self.write(scalar)
    }
}

impl<'a, const KEY_LEN: usize, const PUB_KEY_LEN: usize, const SIGNATURE_LEN: usize, R>
    crate::SigningSecretKey<'a, PUB_KEY_LEN, SIGNATURE_LEN>
    for ECScalar<'a, KEY_LEN, PUB_KEY_LEN, R>
where
    for<'r> &'r R: CryptoRng,
{
    type PublicKey<'s>
        = ECPoint<'s, PUB_KEY_LEN, KEY_LEN, R>
    where
        Self: 's;

    fn pub_key(&self) -> Result<Self::PublicKey<'a>, CryptoError> {
        let mut pub_key = ECPoint::new(self.group, self.rng);

        self.group.access(|group| {
            merr_check!(unsafe {
                mbedtls_rs_sys::mbedtls_ecp_mul(
                    &mut group.raw,
                    &mut pub_key.raw,
                    &self.mpi.raw,
                    &group.raw.G,
                    Some(mbedtls_platform_rng::<R>),
                    self.rng as *const _ as *const _ as *mut _,
                )
            })
        })?;

        Ok(pub_key)
    }

    fn sign(
        &self,
        data: &[u8],
        signature: &mut CryptoSensitive<SIGNATURE_LEN>,
    ) -> Result<(), CryptoError> {
        use crate::Digest;

        let mut sha256 = Sha256::new();
        sha256.update(data)?;

        let mut hash = crate::HASH_ZEROED;
        sha256.finish(&mut hash)?;

        let mut r = Mpi::new();
        let mut s = Mpi::new();

        self.group.access(|group| {
            merr_check!(unsafe {
                mbedtls_rs_sys::mbedtls_ecdsa_sign(
                    &mut group.raw,
                    &mut r.raw,
                    &mut s.raw,
                    &self.mpi.raw,
                    hash.access().as_ptr(),
                    crate::HASH_LEN,
                    Some(mbedtls_platform_rng::<R>),
                    self.rng as *const _ as *const _ as *mut _,
                )
            })
        })?;

        let (r_signature, s_signature) = signature
            .access_mut()
            .split_at_mut(crate::PKC_SIGNATURE_LEN / 2);

        r.write(r_signature)?;
        s.write(s_signature)?;

        Ok(())
    }
}

impl<
        'a,
        const KEY_LEN: usize,
        const PUB_KEY_LEN: usize,
        const SIGNATURE_LEN: usize,
        const SHARED_SECRET_LEN: usize,
        R,
    > crate::SecretKey<'a, KEY_LEN, PUB_KEY_LEN, SIGNATURE_LEN, SHARED_SECRET_LEN>
    for ECScalar<'a, KEY_LEN, PUB_KEY_LEN, R>
where
    for<'r> &'r R: CryptoRng,
{
    fn derive_shared_secret(
        &self,
        peer_pub_key: &Self::PublicKey<'a>,
        shared_secret: &mut CryptoSensitive<SHARED_SECRET_LEN>,
    ) -> Result<(), CryptoError> {
        let mut z = Mpi::new();

        self.group.access(|group| {
            merr_check!(unsafe {
                mbedtls_rs_sys::mbedtls_ecdh_compute_shared(
                    &mut group.raw,
                    &mut z.raw,
                    &peer_pub_key.raw,
                    &self.mpi.raw,
                    Some(mbedtls_platform_rng::<R>),
                    self.rng as *const _ as *const _ as *mut _,
                )
            })
        })?;

        z.write(shared_secret.access_mut())
    }

    fn write_canon(&self, key: &mut CryptoSensitive<KEY_LEN>) -> Result<(), CryptoError> {
        self.write(key)
    }
}

/// MbedTLS platform CSPRNG function adapter used by `ECPoint` and `ECScalar`.`
unsafe extern "C" fn mbedtls_platform_rng<T>(
    ctx: *mut c_void,
    buf: *mut c_uchar,
    buf_len: usize,
) -> c_int
where
    for<'a> &'a T: CryptoRng,
{
    let mut drbg = unwrap!(unsafe { (ctx as *const _ as *const T).as_ref() });

    drbg.fill_bytes(unsafe { core::slice::from_raw_parts_mut(buf, buf_len) });

    0
}

/// A type-safe wrapper around the MbedTLS DRBG cryptographically secure random number generator.
///
/// Implements the `CryptoRng` trait.
pub struct MbedtlsDrbg<'a, T> {
    /// Reference to the entropy source
    _entropy: &'a mut T,
    /// Raw MbedTLS CTR-DRBG context
    raw: mbedtls_rs_sys::mbedtls_ctr_drbg_context,
}

impl<'a, T: CryptoRng> MbedtlsDrbg<'a, T> {
    /// Create a new MbedTLS DRBG instance.
    ///
    /// # Arguments
    /// - `entropy`: Reference to the entropy source.
    /// - `personality`: Optional personality string.
    pub fn new(entropy: &'a mut T, personality: Option<&[u8]>) -> Result<Self, CryptoError> {
        let mut raw = Default::default();

        unsafe {
            mbedtls_rs_sys::mbedtls_ctr_drbg_init(&mut raw);
        }

        let pers_ptr = personality.map(|p| p.as_ptr()).unwrap_or(core::ptr::null());

        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_ctr_drbg_seed(
                &mut raw,
                Some(mbedtls_platform_entropy::<T>),
                entropy as *mut _ as *mut _,
                pers_ptr,
                personality.map(|p| p.len()).unwrap_or(0),
            )
        })?;

        Ok(Self {
            _entropy: entropy,
            raw,
        })
    }
}

impl<T> Drop for MbedtlsDrbg<'_, T> {
    fn drop(&mut self) {
        unsafe {
            mbedtls_rs_sys::mbedtls_ctr_drbg_free(&mut self.raw);
        }
    }
}

impl<T: CryptoRng> TryRng for MbedtlsDrbg<'_, T> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        rand_core::utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        rand_core::utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        unwrap!(merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_ctr_drbg_random(
                &mut self.raw as *mut _ as *mut _,
                buf.as_mut_ptr(),
                buf.len(),
            )
        }));

        Ok(())
    }
}

impl<T: CryptoRng> TryCryptoRng for MbedtlsDrbg<'_, T> {}

/// A type-safe wrapper around the MbedTLS entropy provider.
///
/// Implements the `CryptoRng` trait and can then be used by the MbedTLS DRBG impl - `MbedtlsDrbg`.
/// or any other CSPRNG needing entropy.
pub struct MbedtlsEntropy<T> {
    /// Raw MbedTLS entropy context
    raw: Option<mbedtls_rs_sys::mbedtls_entropy_context>,
    /// Registered entropy sources
    entropy_sources: Option<T>,
}

impl MbedtlsEntropy<()> {
    /// Create a new MbedTLS entropy instance.
    ///
    /// NOTE: At least one non-weak entropy source should be registered
    /// using `add()` or else `MbedtlsEntropy` would panic at runtime.
    pub fn new() -> Self {
        let mut raw = Default::default();

        unsafe {
            mbedtls_rs_sys::mbedtls_entropy_init(&mut raw);
        }

        Self {
            raw: Some(raw),
            entropy_sources: Some(()),
        }
    }
}

impl<T> MbedtlsEntropy<T> {
    /// Add an entropy source to the MbedTLS entropy instance.
    ///
    /// # Arguments
    /// - `entropy_source`: Reference to the entropy source.
    /// - `threshold`: Minimum number of bytes that should be provided by the source.
    ///
    /// # Returns
    /// - New MbedTLS entropy instance with the added source.
    ///
    /// NOTE: At least one non-weak entropy source should be registered
    /// or else `MbedtlsEntropy` would panic at runtime.
    pub fn add<E: CryptoRng>(
        self,
        entropy_source: &mut E,
        threshold: usize,
    ) -> Result<MbedtlsEntropy<(T, &mut E)>, CryptoError> {
        self.internal_add(entropy_source, true, threshold)
    }

    /// Add a weak entropy source to the MbedTLS entropy instance.
    ///
    /// # Arguments
    /// - `entropy_source`: Reference to the entropy source.
    /// - `threshold`: Minimum number of bytes that should be provided by the source.
    ///
    /// # Returns
    /// - New MbedTLS entropy instance with the added weak source.
    ///
    /// NOTE: At least one non-weak entropy source should be registered
    /// using `add()` or else `MbedtlsEntropy` would panic at runtime.
    pub fn add_weak<E: Rng>(
        self,
        entropy_source: &mut E,
        threshold: usize,
    ) -> Result<MbedtlsEntropy<(T, &mut E)>, CryptoError> {
        self.internal_add(entropy_source, false, threshold)
    }

    fn internal_add<E: Rng>(
        mut self,
        entropy_source: &mut E,
        strong: bool,
        threshold: usize,
    ) -> Result<MbedtlsEntropy<(T, &mut E)>, CryptoError> {
        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_entropy_add_source(
                &mut unwrap!(self.raw),
                Some(mbedtls_platform_entropy_source::<E>),
                entropy_source as *mut _ as *mut _,
                threshold,
                if strong {
                    mbedtls_rs_sys::MBEDTLS_ENTROPY_SOURCE_STRONG
                } else {
                    mbedtls_rs_sys::MBEDTLS_ENTROPY_SOURCE_WEAK
                } as _,
            )
        })?;

        Ok(MbedtlsEntropy {
            raw: self.raw.take(),
            entropy_sources: Some((unwrap!(self.entropy_sources.take()), entropy_source)),
        })
    }

    /// Manually seed the entropy pool with the provided data.
    ///
    /// # Arguments
    /// - `data`: The seed data.
    pub fn seed(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_entropy_update_manual(
                unwrap!(self.raw.as_mut()),
                data.as_ptr(),
                data.len(),
            )
        })?;

        Ok(())
    }
}

impl<T> Drop for MbedtlsEntropy<T> {
    fn drop(&mut self) {
        if let Some(mut raw) = self.raw.take() {
            unsafe {
                mbedtls_rs_sys::mbedtls_entropy_free(&mut raw);
            }
        }
    }
}

impl Default for MbedtlsEntropy<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> TryRng for MbedtlsEntropy<T> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        rand_core::utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        rand_core::utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        unwrap!(merr_check!(unsafe {
            mbedtls_rs_sys::mbedtls_entropy_func(
                unwrap!(self.raw.as_mut()) as *mut _ as *mut _,
                buf.as_mut_ptr(),
                buf.len(),
            )
        }));

        Ok(())
    }
}

impl<T> TryCryptoRng for MbedtlsEntropy<T> {}

/// MbedTLS platform entropy function adapter.
unsafe extern "C" fn mbedtls_platform_entropy<T: Rng>(
    ctx: *mut c_void,
    buf: *mut c_uchar,
    buf_len: usize,
) -> c_int {
    let entropy = unwrap!(unsafe { (ctx as *mut T).as_mut() });

    entropy.fill_bytes(unsafe { core::slice::from_raw_parts_mut(buf, buf_len) });

    0
}

/// MbedTLS platform entropy source function adapter.
unsafe extern "C" fn mbedtls_platform_entropy_source<T: Rng>(
    ctx: *mut c_void,
    buf: *mut c_uchar,
    buf_len: usize,
    olen: *mut usize,
) -> c_int {
    let entropy_source = unwrap!(unsafe { (ctx as *mut T).as_mut() });

    entropy_source.fill_bytes(unsafe { core::slice::from_raw_parts_mut(buf, buf_len) });

    unsafe {
        olen.write(buf_len);
    }

    0
}

/// Map an MbedTLS error to `NoMemory` if it is an allocation failure and to
/// `InvalidInput` if it is an invalid key, point or scalar, and panic otherwise:
/// any other error is a bug in how the backend calls MbedTLS.
#[cold]
#[inline(never)]
fn error_or_panic(err: MbedtlsError) -> CryptoError {
    if is_alloc_failure(&err) {
        error!("MbedTLS is out of memory: {}", err);

        CryptoErrorCode::NoMemory.into()
    } else if is_invalid_key(&err) {
        error!("MbedTLS: invalid key, point or scalar: {}", err);

        CryptoErrorCode::InvalidInput.into()
    } else {
        panic!("{}", err);
    }
}

/// Map an MbedTLS error to `NoMemory` if it is an allocation failure, and to `code` otherwise.
#[cold]
#[inline(never)]
fn no_memory_or(err: MbedtlsError, code: CryptoErrorCode) -> CryptoError {
    if is_alloc_failure(&err) {
        CryptoErrorCode::NoMemory.into()
    } else {
        code.into()
    }
}

/// Whether an MbedTLS error is an allocation failure of any MbedTLS module.
///
/// The memory might be allocated by any module, also behind the pointers of a
/// context that lives in place.
fn is_alloc_failure(err: &MbedtlsError) -> bool {
    let (high, low) = split(err);

    matches!(
        low,
        mbedtls_rs_sys::MBEDTLS_ERR_MPI_ALLOC_FAILED
            | mbedtls_rs_sys::MBEDTLS_ERR_ASN1_ALLOC_FAILED
    ) || matches!(
        high,
        mbedtls_rs_sys::MBEDTLS_ERR_ECP_ALLOC_FAILED
            | mbedtls_rs_sys::MBEDTLS_ERR_MD_ALLOC_FAILED
            | mbedtls_rs_sys::MBEDTLS_ERR_CIPHER_ALLOC_FAILED
            | mbedtls_rs_sys::MBEDTLS_ERR_PK_ALLOC_FAILED
            | mbedtls_rs_sys::MBEDTLS_ERR_X509_ALLOC_FAILED
    )
}

/// Whether an MbedTLS error says that a key, point or scalar is not valid.
fn is_invalid_key(err: &MbedtlsError) -> bool {
    split(err).0 == mbedtls_rs_sys::MBEDTLS_ERR_ECP_INVALID_KEY
}

/// Split an MbedTLS error into its high-level and low-level code.
///
/// A code is the negated sum of a high-level code (bits 7 to 14) and a
/// low-level one (bits 0 to 6).
fn split(err: &MbedtlsError) -> (i32, i32) {
    let code = err.code_normalized().unwrap_or(0);

    (-((code & !0x7f) as i32), -((code & 0x7f) as i32))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use mbedtls_rs_sys::MbedtlsError;

    use super::{is_alloc_failure, is_invalid_key};

    #[test]
    fn alloc_failures_are_detected() {
        let alloc = |code| is_alloc_failure(&MbedtlsError::new(code));

        // Low-level and high-level codes alone
        assert!(alloc(mbedtls_rs_sys::MBEDTLS_ERR_MPI_ALLOC_FAILED));
        assert!(alloc(mbedtls_rs_sys::MBEDTLS_ERR_PK_ALLOC_FAILED));

        // An allocation failure in either part of a combined code
        assert!(alloc(
            mbedtls_rs_sys::MBEDTLS_ERR_X509_INVALID_FORMAT
                + mbedtls_rs_sys::MBEDTLS_ERR_ASN1_ALLOC_FAILED
        ));
        assert!(alloc(
            mbedtls_rs_sys::MBEDTLS_ERR_ECP_ALLOC_FAILED
                + mbedtls_rs_sys::MBEDTLS_ERR_MPI_BAD_INPUT_DATA
        ));

        assert!(!alloc(mbedtls_rs_sys::MBEDTLS_ERR_CCM_AUTH_FAILED));
        assert!(!alloc(mbedtls_rs_sys::MBEDTLS_ERR_ECP_INVALID_KEY));
        assert!(!alloc(
            mbedtls_rs_sys::MBEDTLS_ERR_X509_INVALID_FORMAT
                + mbedtls_rs_sys::MBEDTLS_ERR_ASN1_OUT_OF_DATA
        ));
        assert!(!alloc(0));
    }

    #[test]
    fn invalid_keys_are_detected() {
        let invalid = |code| is_invalid_key(&MbedtlsError::new(code));

        assert!(invalid(mbedtls_rs_sys::MBEDTLS_ERR_ECP_INVALID_KEY));
        assert!(invalid(
            mbedtls_rs_sys::MBEDTLS_ERR_ECP_INVALID_KEY
                + mbedtls_rs_sys::MBEDTLS_ERR_MPI_BAD_INPUT_DATA
        ));

        assert!(!invalid(mbedtls_rs_sys::MBEDTLS_ERR_ECP_BAD_INPUT_DATA));
        assert!(!invalid(mbedtls_rs_sys::MBEDTLS_ERR_ECP_ALLOC_FAILED));
        assert!(!invalid(0));
    }
}
