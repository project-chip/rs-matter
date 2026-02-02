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

//! MbedTLS-based crypto backend for Matter.

macro_rules! merr_unwrap {
    ($expr:expr) => {{
        let result = $expr;
        match esp_mbedtls_sys::merr!(result) {
            Ok(val) => val,
            Err(err) => panic!("{}", err),
        }
    }};
}

use core::ffi::{c_int, c_uchar, c_void};

use embassy_sync::blocking_mutex::raw::RawMutex;

use esp_mbedtls_sys::merr;

use rand_core::{CryptoRng, CryptoRngCore, RngCore};

use crate::crypto::{CanonPkcSecretKeyRef, CryptoSensitive, CryptoSensitiveRef, SharedRand};
use crate::error::Error;

/// MbedTLS-based crypto backend for Matter.
pub struct MbedtlsCrypto<'s, M: RawMutex, T> {
    /// Elliptic curve group (secp256r1)
    ec_group: ECGroup<{ super::EC_CANON_POINT_LEN }, { super::EC_CANON_SCALAR_LEN }>,
    /// A shared cryptographic random number generator
    rng: SharedRand<M, T>,
    /// The singleton secret key to be returned by `Crypto::singleton_singing_secret_key`
    singleton_secret_key: CanonPkcSecretKeyRef<'s>,
}

impl<'s, M: RawMutex, T> MbedtlsCrypto<'s, M, T> {
    /// Create a new MbedTLS crypto backend.
    ///
    /// # Arguments
    /// - `rng` - A cryptographic random number generator
    /// - `singleton_secret_key` - A singleton secret key to be returned by `Crypto::singleton_singing_secret_key`
    ///   The primary use-case for this secret key is to be used as the secret key for the Device Attestation credentials
    pub fn new(rng: T, singleton_secret_key: CanonPkcSecretKeyRef<'s>) -> Self {
        let mut ec_group = ECGroup::new();
        unsafe { ec_group.set(esp_mbedtls_sys::mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1) };

        Self {
            ec_group,
            rng: SharedRand::new(rng),
            singleton_secret_key,
        }
    }
}

impl<M: RawMutex, T> super::Crypto for MbedtlsCrypto<'_, M, T>
where
    T: CryptoRngCore,
{
    type Rand<'a>
        = &'a SharedRand<M, T>
    where
        Self: 'a;

    type WeakRand<'a>
        = &'a SharedRand<M, T>
    where
        Self: 'a;

    type Hash<'a>
        = Sha256
    where
        Self: 'a;

    type Hmac<'a>
        = Hmac<{ super::HASH_LEN }>
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
        = AeadCcm<{ super::AEAD_CANON_KEY_LEN }, { super::AEAD_NONCE_LEN }, { super::AEAD_TAG_LEN }>
    where
        Self: 'a;

    type PublicKey<'a>
        =
        ECPoint<'a, { super::EC_CANON_POINT_LEN }, { super::EC_CANON_SCALAR_LEN }, SharedRand<M, T>>
    where
        Self: 'a;

    type SecretKey<'a>
        = ECScalar<
        'a,
        { super::EC_CANON_SCALAR_LEN },
        { super::EC_CANON_POINT_LEN },
        SharedRand<M, T>,
    >
    where
        Self: 'a;

    type SigningSecretKey<'a>
        = ECScalar<
        'a,
        { super::EC_CANON_SCALAR_LEN },
        { super::EC_CANON_POINT_LEN },
        SharedRand<M, T>,
    >
    where
        Self: 'a;

    type UInt320<'a>
        = Mpi
    where
        Self: 'a;

    type EcScalar<'a>
        = ECScalar<
        'a,
        { super::EC_CANON_SCALAR_LEN },
        { super::EC_CANON_POINT_LEN },
        SharedRand<M, T>,
    >
    where
        Self: 'a;

    type EcPoint<'a>
        =
        ECPoint<'a, { super::EC_CANON_POINT_LEN }, { super::EC_CANON_SCALAR_LEN }, SharedRand<M, T>>
    where
        Self: 'a;

    fn rand(&self) -> Result<Self::Rand<'_>, Error> {
        Ok(&self.rng)
    }

    fn weak_rand(&self) -> Result<Self::WeakRand<'_>, Error> {
        Ok(&self.rng)
    }

    fn hash(&self) -> Result<Self::Hash<'_>, Error> {
        Ok(Sha256::new())
    }

    fn hmac<const KEY_LEN: usize>(
        &self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
    ) -> Result<Self::Hmac<'_>, Error> {
        Ok(unsafe {
            Hmac::new(
                esp_mbedtls_sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
                key.access(),
            )
        })
    }

    fn kdf(&self) -> Result<Self::Kdf<'_>, Error> {
        Ok(Hkdf::new(
            esp_mbedtls_sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
        ))
    }

    fn pbkdf(&self) -> Result<Self::PbKdf<'_>, Error> {
        Ok(Pbkdf2Hmac::new(
            esp_mbedtls_sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
        ))
    }

    fn aead(&self) -> Result<Self::Aead<'_>, Error> {
        Ok(unsafe { AeadCcm::new(esp_mbedtls_sys::mbedtls_cipher_id_t_MBEDTLS_CIPHER_ID_AES) })
    }

    fn pub_key(&self, key: super::CanonPkcPublicKeyRef<'_>) -> Result<Self::PublicKey<'_>, Error> {
        self.ec_point(key)
    }

    fn generate_secret_key(&self) -> Result<Self::SecretKey<'_>, Error> {
        self.generate_ec_scalar()
    }

    fn secret_key(
        &self,
        key: super::CanonPkcSecretKeyRef<'_>,
    ) -> Result<Self::SecretKey<'_>, Error> {
        self.ec_scalar(key)
    }

    fn singleton_singing_secret_key(&self) -> Result<Self::SigningSecretKey<'_>, Error> {
        self.ec_scalar(self.singleton_secret_key)
    }

    fn uint320(&self, uint: super::CanonUint320Ref<'_>) -> Result<Self::UInt320<'_>, Error> {
        let mut result = Mpi::new();

        result.set(uint.access());

        Ok(result)
    }

    fn ec_scalar(&self, scalar: super::CanonEcScalarRef<'_>) -> Result<Self::EcScalar<'_>, Error> {
        let mut result = ECScalar::new(&self.ec_group, &self.rng);
        unsafe {
            result.set(scalar);
        }

        Ok(result)
    }

    fn generate_ec_scalar(&self) -> Result<Self::EcScalar<'_>, Error> {
        unimplemented!()
    }

    fn ec_point(&self, point: super::CanonEcPointRef<'_>) -> Result<Self::EcPoint<'_>, Error> {
        let mut result = ECPoint::new(&self.ec_group, &self.rng);
        unsafe {
            result.set(point);
        }

        Ok(result)
    }

    fn ec_generator_point(&self) -> Result<Self::EcPoint<'_>, Error> {
        let mut result = ECPoint::new(&self.ec_group, &self.rng);

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_copy(&mut result.raw, &self.ec_group.raw.G)
        });

        Ok(result)
    }
}

/// SHA-256 hash implementation using MbedTLS.
pub struct Sha256 {
    /// Raw MbedTLS SHA-256 context
    raw: esp_mbedtls_sys::mbedtls_sha256_context,
}

impl Sha256 {
    /// Create a new SHA-256 hash instance.
    fn new() -> Self {
        let mut raw = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_sha256_init(&mut raw);
            esp_mbedtls_sys::mbedtls_sha256_starts(&mut raw, 0);
        }

        Self { raw }
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        unsafe {
            esp_mbedtls_sys::mbedtls_sha256_free(&mut self.raw);
        }
    }
}

impl Clone for Sha256 {
    fn clone(&self) -> Self {
        let mut raw = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_sha256_init(&mut raw);
            esp_mbedtls_sys::mbedtls_sha256_clone(&mut raw, &self.raw);
        }

        Self { raw }
    }
}

impl super::Digest<{ super::HASH_LEN }> for Sha256 {
    fn update(&mut self, data: &[u8]) {
        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_sha256_update(&mut self.raw, data.as_ptr(), data.len())
        });
    }

    fn finish(mut self, out: &mut CryptoSensitive<{ super::HASH_LEN }>) {
        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_sha256_finish(&mut self.raw, out.access_mut().as_mut_ptr())
        });
    }
}

/// HMAC implementation using MbedTLS.
pub struct Hmac<const HASH_LEN: usize> {
    /// Raw MbedTLS MD context
    raw: esp_mbedtls_sys::mbedtls_md_context_t,
}

impl<const HASH_LEN: usize> Hmac<HASH_LEN> {
    /// Create a new HMAC instance with the given key.
    ///
    /// # Safety
    /// The caller must ensure that the provided `md_type` corresponds to the `HASH_LEN`
    /// generic parameter.
    unsafe fn new(md_type: esp_mbedtls_sys::mbedtls_md_type_t, key: &[u8]) -> Self {
        let mut raw = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_md_init(&mut raw);
        }

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_md_setup(
                &mut raw,
                esp_mbedtls_sys::mbedtls_md_info_from_type(md_type),
                1,
            )
        });

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_md_hmac_starts(&mut raw, key.as_ptr(), key.len())
        });

        Self { raw }
    }
}

impl<const HASH_LEN: usize> Drop for Hmac<HASH_LEN> {
    fn drop(&mut self) {
        unsafe {
            esp_mbedtls_sys::mbedtls_md_free(&mut self.raw);
        }
    }
}

impl<const HASH_LEN: usize> Clone for Hmac<HASH_LEN> {
    fn clone(&self) -> Self {
        let mut raw = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_md_init(&mut raw);
            esp_mbedtls_sys::mbedtls_md_clone(&mut raw, &self.raw);
        }

        Self { raw }
    }
}

impl<const HASH_LEN: usize> super::Digest<HASH_LEN> for Hmac<HASH_LEN> {
    fn update(&mut self, data: &[u8]) {
        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_md_hmac_update(&mut self.raw, data.as_ptr(), data.len())
        });
    }

    fn finish(mut self, out: &mut CryptoSensitive<HASH_LEN>) {
        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_md_hmac_finish(&mut self.raw, out.access_mut().as_mut_ptr())
        });
    }
}

/// HKDF implementation using MbedTLS.
pub struct Hkdf {
    /// Message digest type
    md_type: esp_mbedtls_sys::mbedtls_md_type_t,
}

impl Hkdf {
    /// Create a new HKDF instance.
    fn new(md_type: esp_mbedtls_sys::mbedtls_md_type_t) -> Self {
        Self { md_type }
    }
}

impl super::Kdf for Hkdf {
    fn expand<const IKM_LEN: usize, const KEY_LEN: usize>(
        self,
        salt: &[u8],
        ikm: CryptoSensitiveRef<'_, IKM_LEN>,
        info: &[u8],
        key: &mut CryptoSensitive<KEY_LEN>,
    ) -> Result<(), Error> {
        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_hkdf(
                esp_mbedtls_sys::mbedtls_md_info_from_type(self.md_type),
                salt.as_ptr(),
                salt.len(),
                ikm.access().as_ptr(),
                IKM_LEN,
                info.as_ptr(),
                info.len(),
                key.access_mut().as_mut_ptr(),
                KEY_LEN,
            )
        });

        Ok(())
    }
}

/// PBKDF2-HMAC implementation using MbedTLS.
pub struct Pbkdf2Hmac {
    /// Message digest type
    md_type: esp_mbedtls_sys::mbedtls_md_type_t,
}

impl Pbkdf2Hmac {
    /// Create a new PBKDF2-HMAC instance.
    fn new(md_type: esp_mbedtls_sys::mbedtls_md_type_t) -> Self {
        Self { md_type }
    }
}

impl super::PbKdf for Pbkdf2Hmac {
    fn derive<const PASS_LEN: usize, const KEY_LEN: usize>(
        self,
        password: CryptoSensitiveRef<'_, PASS_LEN>,
        iter: usize,
        salt: &[u8],
        out: &mut CryptoSensitive<KEY_LEN>,
    ) {
        unsafe {
            esp_mbedtls_sys::mbedtls_pkcs5_pbkdf2_hmac_ext(
                self.md_type,
                password.access().as_ptr(),
                PASS_LEN,
                salt.as_ptr(),
                salt.len(),
                iter as u32,
                KEY_LEN as _,
                out.access_mut().as_mut_ptr(),
            );
        }
    }
}

/// AEAD-CCM implementation using MbedTLS.
pub struct AeadCcm<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize> {
    /// Cipher type
    cipher_id: esp_mbedtls_sys::mbedtls_cipher_id_t,
}

impl<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>
    AeadCcm<KEY_LEN, NONCE_LEN, TAG_LEN>
{
    /// Create a new AEAD-CCM instance.
    ///
    /// # Safety
    /// The caller must ensure that the provided `cipher_type` corresponds to the
    /// `KEY_LEN`, `NONCE_LEN`, and `TAG_LEN` generic parameters.
    unsafe fn new(cipher_id: esp_mbedtls_sys::mbedtls_cipher_id_t) -> Self {
        Self { cipher_id }
    }
}

impl<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>
    super::Aead<KEY_LEN, NONCE_LEN> for AeadCcm<KEY_LEN, NONCE_LEN, TAG_LEN>
{
    fn encrypt_in_place<'a>(
        &mut self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
        nonce: CryptoSensitiveRef<'_, NONCE_LEN>,
        aad: &[u8],
        data: &'a mut [u8],
        data_len: usize,
    ) -> Result<&'a [u8], Error> {
        assert!(data.len() >= data_len + TAG_LEN);

        let mut ctx = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_ccm_init(&mut ctx);
        }

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ccm_setkey(
                &mut ctx,
                self.cipher_id,
                key.access().as_ptr(),
                (KEY_LEN * 8) as u32,
            )
        });

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ccm_encrypt_and_tag(
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
        });

        unsafe {
            esp_mbedtls_sys::mbedtls_ccm_free(&mut ctx);
        }

        Ok(&data[..data_len + TAG_LEN])
    }

    fn decrypt_in_place<'a>(
        &mut self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
        nonce: CryptoSensitiveRef<'_, NONCE_LEN>,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        assert!(data.len() >= TAG_LEN);

        let mut ctx = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_ccm_init(&mut ctx);
        }

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ccm_setkey(
                &mut ctx,
                self.cipher_id,
                key.access().as_ptr(),
                (KEY_LEN * 8) as u32,
            )
        });

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ccm_auth_decrypt(
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
            esp_mbedtls_sys::mbedtls_ccm_free(&mut ctx);
        }

        Ok(&data[..data.len() - TAG_LEN])
    }
}

/// Multi-precision integer (MPI) implementation using MbedTLS.
pub struct Mpi {
    /// Raw MbedTLS MPI
    raw: esp_mbedtls_sys::mbedtls_mpi,
}

impl Mpi {
    /// Create a new MPI instance.
    fn new() -> Self {
        let mut raw = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_mpi_init(&mut raw);
        }

        Self { raw }
    }

    /// Set the MPI from the given BE byte representation.
    fn set(&mut self, uint: &[u8]) {
        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_read_binary(&mut self.raw, uint.as_ptr(), uint.len())
        });
    }

    /// Write the MPI to the given BE byte array.
    ///
    /// The method will panic if the provided buffer is not large enough.
    fn write(&self, uint: &mut [u8]) {
        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_write_binary(&self.raw, uint.as_mut_ptr(), uint.len())
        });
    }
}

impl Drop for Mpi {
    fn drop(&mut self) {
        unsafe {
            esp_mbedtls_sys::mbedtls_mpi_free(&mut self.raw);
        }
    }
}

impl<const LEN: usize> super::UInt<'_, LEN> for Mpi {
    fn rem(&self, other: &Self) -> Option<Self> {
        let mut result = Mpi::new();

        let result_code = merr!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_mod_mpi(&mut result.raw, &self.raw, &other.raw)
        });

        if result_code.is_ok() {
            Some(result)
        } else {
            None
        }
    }

    fn write_canon(&self, buf: &mut CryptoSensitive<LEN>) {
        self.write(buf.access_mut());
    }
}

/// Elliptic curve group implementation using MbedTLS.
pub struct ECGroup<const LEN: usize, const SCALAR_LEN: usize> {
    /// Raw MbedTLS EC group
    raw: esp_mbedtls_sys::mbedtls_ecp_group,
}

impl<const LEN: usize, const SCALAR_LEN: usize> ECGroup<LEN, SCALAR_LEN> {
    /// Create a new EC group instance.
    fn new() -> Self {
        let mut raw = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_ecp_group_init(&mut raw);
        }

        Self { raw }
    }

    /// Set the EC group to the specified group ID.
    ///
    /// # Safety
    /// The caller must ensure that the provided `group_id` matches the
    /// `LEN` and `SCALAR_LEN` generic parameters.
    unsafe fn set(&mut self, group_id: esp_mbedtls_sys::mbedtls_ecp_group_id) {
        merr_unwrap!(unsafe { esp_mbedtls_sys::mbedtls_ecp_group_load(&mut self.raw, group_id) });
    }
}

impl<const LEN: usize, const SCALAR_LEN: usize> Drop for ECGroup<LEN, SCALAR_LEN> {
    fn drop(&mut self) {
        unsafe {
            esp_mbedtls_sys::mbedtls_ecp_group_free(&mut self.raw);
        }
    }
}

/// Elliptic curve point implementation using MbedTLS.
pub struct ECPoint<'a, const LEN: usize, const SCALAR_LEN: usize, R> {
    /// Associated EC group
    group: &'a ECGroup<LEN, SCALAR_LEN>,
    /// The random number generator
    rng: &'a R,
    /// Raw MbedTLS EC point
    raw: esp_mbedtls_sys::mbedtls_ecp_point,
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
    fn new(group: &'a ECGroup<LEN, SCALAR_LEN>, rng: &'a R) -> Self {
        let mut raw = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_ecp_point_init(&mut raw);
        }

        Self { group, rng, raw }
    }

    /// Set the EC point from the given byte representation.
    unsafe fn set(&mut self, point: CryptoSensitiveRef<LEN>) {
        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_point_read_binary(
                &self.group.raw,
                &mut self.raw,
                point.access().as_ptr(),
                LEN,
            )
        });
    }

    /// Write the EC point to the given byte array in uncompressed format.
    fn write(&self, point: &mut CryptoSensitive<LEN>) {
        let mut olen = 0;

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_point_write_binary(
                &self.group.raw,
                &self.raw,
                esp_mbedtls_sys::MBEDTLS_ECP_PF_UNCOMPRESSED as _,
                &mut olen,
                point.access_mut().as_mut_ptr(),
                LEN,
            )
        });

        assert_eq!(olen, LEN);
    }
}

impl<const LEN: usize, const SCALAR_LEN: usize, R> Drop for ECPoint<'_, LEN, SCALAR_LEN, R> {
    fn drop(&mut self) {
        unsafe {
            esp_mbedtls_sys::mbedtls_ecp_point_free(&mut self.raw);
        }
    }
}

impl<'a, const LEN: usize, const SCALAR_LEN: usize, R> super::EcPoint<'a, LEN, SCALAR_LEN>
    for ECPoint<'a, LEN, SCALAR_LEN, R>
where
    for<'r> &'r R: CryptoRngCore,
{
    type Scalar<'s>
        = ECScalar<'s, SCALAR_LEN, LEN, R>
    where
        Self: 'a + 's;

    fn neg(&self) -> Self {
        assert!(unsafe { esp_mbedtls_sys::mbedtls_mpi_cmp_int(&self.raw.private_Z, 1) } == 0);

        let mut result = ECPoint::new(self.group, self.rng);

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_copy(&mut result.raw.private_X, &self.raw.private_X)
        });

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_lset(&mut result.raw.private_Z, 1)
            //esp_mbedtls_sys::mbedtls_mpi_copy(&mut result.raw.private_Z, &self.raw.private_Z)
        });

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_sub_mpi(
                &mut result.raw.private_Y,
                &self.group.raw.P,
                &self.raw.private_Y,
            )
        });

        result
    }

    fn mul(&self, scalar: &Self::Scalar<'a>) -> Self {
        let mut result = ECPoint::new(self.group, self.rng);

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_mul(
                &self.group.raw as *const _ as *mut _,
                &mut result.raw,
                &scalar.mpi.raw,
                &self.raw,
                Some(mbedtls_platform_rng::<R>),
                self.rng as *const _ as *const _ as *mut _,
            )
        });

        result
    }

    fn add_mul(&self, s1: &Self::Scalar<'a>, p2: &Self, s2: &Self::Scalar<'a>) -> Self {
        let mut result = ECPoint::new(self.group, self.rng);

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_muladd(
                &self.group.raw as *const _ as *mut _,
                &mut result.raw,
                &s1.mpi.raw,
                &self.raw,
                &s2.mpi.raw,
                &p2.raw,
            )
        });

        result
    }

    fn write_canon(&self, point: &mut CryptoSensitive<LEN>) {
        self.write(point);
    }
}

impl<'a, const KEY_LEN: usize, const SECRET_KEY_LEN: usize, const SIGNATURE_LEN: usize, R>
    super::PublicKey<'a, KEY_LEN, SIGNATURE_LEN> for ECPoint<'a, KEY_LEN, SECRET_KEY_LEN, R>
{
    fn verify(&self, data: &[u8], signature: CryptoSensitiveRef<'_, SIGNATURE_LEN>) -> bool {
        let mut r = Mpi::new();
        let mut s = Mpi::new();

        let (r_signature, s_signature) = signature.access().split_at(SIGNATURE_LEN / 2);

        r.set(r_signature);
        s.set(s_signature);

        use super::Digest;

        let mut sha256 = Sha256::new();
        sha256.update(data);

        let mut hash = super::HASH_ZEROED;
        sha256.finish(&mut hash);

        let result = unsafe {
            esp_mbedtls_sys::mbedtls_ecdsa_verify(
                &self.group.raw as *const _ as *mut _,
                hash.access_mut().as_ptr(),
                super::HASH_LEN,
                &self.raw,
                &r.raw,
                &s.raw,
            )
        };

        result == 0
    }

    fn write_canon(&self, key: &mut CryptoSensitive<KEY_LEN>) {
        self.write(key);
    }
}

/// Elliptic curve scalar implementation using MbedTLS.
pub struct ECScalar<'a, const LEN: usize, const POINT_LEN: usize, R> {
    /// Associated EC group
    group: &'a ECGroup<POINT_LEN, LEN>,
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
    fn new(group: &'a ECGroup<POINT_LEN, LEN>, rng: &'a R) -> Self {
        Self {
            group,
            rng,
            mpi: Mpi::new(),
        }
    }

    /// Set the EC scalar from the given byte representation.
    unsafe fn set(&mut self, scalar: CryptoSensitiveRef<LEN>) {
        self.mpi.set(scalar.access());
    }

    /// Write the EC scalar to the given byte array.
    fn write(&self, scalar: &mut CryptoSensitive<LEN>) {
        self.mpi.write(scalar.access_mut());
    }
}

impl<'a, const LEN: usize, const POINT_LEN: usize, R> super::EcScalar<'a, LEN>
    for ECScalar<'a, LEN, POINT_LEN, R>
where
    for<'r> &'r R: CryptoRngCore,
{
    fn mul(&self, other: &Self) -> Self {
        let mut result = ECScalar::new(self.group, self.rng);

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_mul_mpi(&mut result.mpi.raw, &self.mpi.raw, &other.mpi.raw)
        });

        result
    }

    fn write_canon(&self, scalar: &mut CryptoSensitive<LEN>) {
        self.write(scalar);
    }
}

impl<'a, const KEY_LEN: usize, const PUB_KEY_LEN: usize, const SIGNATURE_LEN: usize, R>
    super::SigningSecretKey<'a, PUB_KEY_LEN, SIGNATURE_LEN>
    for ECScalar<'a, KEY_LEN, PUB_KEY_LEN, R>
where
    for<'r> &'r R: CryptoRngCore,
{
    type PublicKey<'s>
        = ECPoint<'s, PUB_KEY_LEN, KEY_LEN, R>
    where
        Self: 's;

    fn csr<'s>(&self, buf: &'s mut [u8]) -> Result<&'s [u8], Error> {
        let mut csr = Default::default();
        let mut pk = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_x509write_csr_init(&mut csr);
            esp_mbedtls_sys::mbedtls_pk_init(&mut pk);
        }

        unsafe {
            esp_mbedtls_sys::mbedtls_x509write_csr_set_md_alg(
                &mut csr,
                esp_mbedtls_sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
            );
        }

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_pk_setup(
                &mut pk,
                esp_mbedtls_sys::mbedtls_pk_info_from_type(
                    esp_mbedtls_sys::mbedtls_pk_type_t_MBEDTLS_PK_ECKEY,
                ),
            )
        });

        let ec_ctx = unwrap!(unsafe {
            (pk.private_pk_ctx as *mut esp_mbedtls_sys::mbedtls_ecp_keypair).as_mut()
        });

        unsafe {
            esp_mbedtls_sys::mbedtls_ecp_point_init(&mut ec_ctx.private_Q);
        }

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_mul(
                &self.group.raw as *const _ as *mut _,
                &mut ec_ctx.private_Q,
                &self.mpi.raw,
                &self.group.raw.G,
                Some(mbedtls_platform_rng::<R>),
                self.rng as *const _ as *const _ as *mut _,
            )
        });

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_group_copy(&mut ec_ctx.private_grp, &self.group.raw)
        });

        unsafe {
            esp_mbedtls_sys::mbedtls_x509write_csr_set_key(&mut csr, &mut pk);
        }

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_x509write_csr_set_subject_name(&mut csr, c"O=CSR".as_ptr())
        });

        let len = merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_x509write_csr_der(
                &mut csr,
                buf.as_mut_ptr(),
                buf.len(),
                None,
                core::ptr::null_mut(),
            )
        });

        unsafe {
            esp_mbedtls_sys::mbedtls_x509write_csr_free(&mut csr);
            esp_mbedtls_sys::mbedtls_pk_free(&mut pk);
        }

        Ok(&buf[..len as usize])
    }

    fn pub_key(&self) -> Self::PublicKey<'a> {
        let mut pub_key = ECPoint::new(self.group, self.rng);

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_mul(
                &self.group.raw as *const _ as *mut _,
                &mut pub_key.raw,
                &self.mpi.raw,
                &self.group.raw.G,
                Some(mbedtls_platform_rng::<R>),
                self.rng as *const _ as *const _ as *mut _,
            )
        });

        pub_key
    }

    fn sign(&self, data: &[u8], signature: &mut CryptoSensitive<SIGNATURE_LEN>) {
        use super::Digest;

        let mut sha256 = Sha256::new();
        sha256.update(data);

        let mut hash = super::HASH_ZEROED;
        sha256.finish(&mut hash);

        let mut r = Mpi::new();
        let mut s = Mpi::new();

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ecdsa_sign(
                &self.group.raw as *const _ as *mut _,
                &mut r.raw,
                &mut s.raw,
                &self.mpi.raw,
                hash.access().as_ptr(),
                super::HASH_LEN,
                Some(mbedtls_platform_rng::<R>),
                self.rng as *const _ as *const _ as *mut _,
            )
        });

        let (r_signature, s_signature) = signature
            .access_mut()
            .split_at_mut(super::PKC_SIGNATURE_LEN / 2);

        r.write(r_signature);
        s.write(s_signature);
    }
}

impl<
        'a,
        const KEY_LEN: usize,
        const PUB_KEY_LEN: usize,
        const SIGNATURE_LEN: usize,
        const SHARED_SECRET_LEN: usize,
        R,
    > super::SecretKey<'a, KEY_LEN, PUB_KEY_LEN, SIGNATURE_LEN, SHARED_SECRET_LEN>
    for ECScalar<'a, KEY_LEN, PUB_KEY_LEN, R>
where
    for<'r> &'r R: CryptoRngCore,
{
    fn derive_shared_secret(
        &self,
        peer_pub_key: &Self::PublicKey<'a>,
        shared_secret: &mut CryptoSensitive<SHARED_SECRET_LEN>,
    ) {
        let mut z = Mpi::new();

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ecdh_compute_shared(
                &self.group.raw as *const _ as *mut _,
                &mut z.raw,
                &peer_pub_key.raw,
                &self.mpi.raw,
                Some(mbedtls_platform_rng::<R>),
                self.rng as *const _ as *const _ as *mut _,
            )
        });

        z.write(shared_secret.access_mut());
    }

    fn write_canon(&self, key: &mut CryptoSensitive<KEY_LEN>) {
        self.write(key);
    }
}

/// MbedTLS platform CSPRNG function adapter used by `ECPoint` and `ECScalar`.`
unsafe extern "C" fn mbedtls_platform_rng<T>(
    ctx: *mut c_void,
    buf: *mut c_uchar,
    buf_len: usize,
) -> c_int
where
    for<'a> &'a T: CryptoRngCore,
{
    let mut drbg = unwrap!(unsafe { (ctx as *const _ as *const T).as_ref() });

    drbg.fill_bytes(unsafe { core::slice::from_raw_parts_mut(buf, buf_len) });

    0
}

/// A type-safe wrapper around the MbedTLS DRBG cryptographically secure random number generator.
///
/// Implements the `CryptoRngCore` trait.
pub struct MbedtlsDrbg<'a, T> {
    /// Reference to the entropy source
    _entropy: &'a mut T,
    /// Raw MbedTLS CTR-DRBG context
    raw: esp_mbedtls_sys::mbedtls_ctr_drbg_context,
}

impl<'a, T: CryptoRngCore> MbedtlsDrbg<'a, T> {
    /// Create a new MbedTLS DRBG instance.
    ///
    /// # Arguments
    /// - `entropy`: Reference to the entropy source.
    /// - `personality`: Optional personality string.
    pub fn new(entropy: &'a mut T, personality: Option<&[u8]>) -> Self {
        let mut raw = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_ctr_drbg_init(&mut raw);
        }

        let pers_ptr = personality.map(|p| p.as_ptr()).unwrap_or(core::ptr::null());

        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ctr_drbg_seed(
                &mut raw,
                Some(mbedtls_platform_entropy::<T>),
                entropy as *const _ as *const _ as *mut _,
                pers_ptr,
                personality.map(|p| p.len()).unwrap_or(0),
            )
        });

        Self {
            _entropy: entropy,
            raw,
        }
    }
}

impl<T> Drop for MbedtlsDrbg<'_, T> {
    fn drop(&mut self) {
        unsafe {
            esp_mbedtls_sys::mbedtls_ctr_drbg_free(&mut self.raw);
        }
    }
}

impl<T: CryptoRngCore> RngCore for MbedtlsDrbg<'_, T> {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_ctr_drbg_random(
                &mut self.raw as *mut _ as *mut _,
                buf.as_mut_ptr(),
                buf.len(),
            )
        });
    }

    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);

        Ok(())
    }
}

impl<T: CryptoRngCore> CryptoRng for MbedtlsDrbg<'_, T> {}

/// A type-safe wrapper around the MbedTLS entropy provider.
///
/// Implements the `CryptoRngCore` trait and can then be used by the MbedTLS DRBG impl - `MbedtlsDrbg`.
/// or any other CSPRNG needing entropy.
pub struct MbedtlsEntropy<T> {
    /// Raw MbedTLS entropy context
    raw: Option<esp_mbedtls_sys::mbedtls_entropy_context>,
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
            esp_mbedtls_sys::mbedtls_entropy_init(&mut raw);
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
    pub fn add<E: CryptoRngCore>(
        self,
        entropy_source: &mut E,
        threshold: usize,
    ) -> MbedtlsEntropy<(T, &mut E)> {
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
    pub fn add_weak<E: RngCore>(
        self,
        entropy_source: &mut E,
        threshold: usize,
    ) -> MbedtlsEntropy<(T, &mut E)> {
        self.internal_add(entropy_source, false, threshold)
    }

    fn internal_add<E: RngCore>(
        mut self,
        entropy_source: &mut E,
        strong: bool,
        threshold: usize,
    ) -> MbedtlsEntropy<(T, &mut E)> {
        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_entropy_add_source(
                &mut unwrap!(self.raw),
                Some(mbedtls_platform_entropy_source::<E>),
                entropy_source as *const _ as *const _ as *mut _,
                threshold,
                if strong {
                    esp_mbedtls_sys::MBEDTLS_ENTROPY_SOURCE_STRONG
                } else {
                    esp_mbedtls_sys::MBEDTLS_ENTROPY_SOURCE_WEAK
                } as _,
            )
        });

        MbedtlsEntropy {
            raw: self.raw.take(),
            entropy_sources: Some((unwrap!(self.entropy_sources.take()), entropy_source)),
        }
    }

    /// Manually seed the entropy pool with the provided data.
    ///
    /// # Arguments
    /// - `data`: The seed data.
    pub fn seed(&mut self, data: &[u8]) {
        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_entropy_update_manual(
                unwrap!(self.raw.as_mut()),
                data.as_ptr(),
                data.len(),
            )
        });
    }
}

impl<T> Drop for MbedtlsEntropy<T> {
    fn drop(&mut self) {
        if let Some(mut raw) = self.raw.take() {
            unsafe {
                esp_mbedtls_sys::mbedtls_entropy_free(&mut raw);
            }
        }
    }
}

impl Default for MbedtlsEntropy<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> RngCore for &MbedtlsEntropy<T> {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        merr_unwrap!(unsafe {
            esp_mbedtls_sys::mbedtls_entropy_func(
                unwrap!(self.raw.as_ref()) as *const _ as *mut _,
                buf.as_mut_ptr(),
                buf.len(),
            )
        });
    }

    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);

        Ok(())
    }
}

impl<T> CryptoRng for &MbedtlsEntropy<T> {}

/// MbedTLS platform entropy function adapter.
unsafe extern "C" fn mbedtls_platform_entropy<T: RngCore>(
    ctx: *mut c_void,
    buf: *mut c_uchar,
    buf_len: usize,
) -> c_int {
    let entropy = unwrap!(unsafe { (ctx as *mut T).as_mut() });

    entropy.fill_bytes(unsafe { core::slice::from_raw_parts_mut(buf, buf_len) });

    0
}

/// MbedTLS platform entropy source function adapter.
unsafe extern "C" fn mbedtls_platform_entropy_source<T: RngCore>(
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

/// MbedTLS platform zeroize function.
// TODO: Make it user-provided
#[cfg(not(target_os = "espidf"))]
#[no_mangle]
unsafe extern "C" fn mbedtls_platform_zeroize(dst: *mut c_uchar, len: u32) {
    for i in 0..len as isize {
        dst.offset(i).write_volatile(0);
    }
}
