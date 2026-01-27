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

use esp_mbedtls_sys::merr;

use crate::error::Error;

pub struct MbedtlsCrypto {
    secp256r1_group:
        ECGroup<{ super::SECP256R1_CANON_POINT_LEN }, { super::SECP256R1_CANON_SCALAR_LEN }>,
}

impl MbedtlsCrypto {
    pub fn new() -> Self {
        let mut ec_group = unsafe { ECGroup::new() };
        ec_group.set(esp_mbedtls_sys::mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1);

        Self {
            secp256r1_group: ec_group,
        }
    }
}

impl super::Crypto for MbedtlsCrypto {
    type Sha256<'a>
        = Sha256
    where
        Self: 'a;

    type HmacSha256<'a>
        = Hmac<{ super::SHA256_HASH_LEN }>
    where
        Self: 'a;

    type HkdfSha256<'a>
        = Hkdf
    where
        Self: 'a;

    type Pbkdf2HmacSha256<'a>
        = Pbkdf2Hmac
    where
        Self: 'a;

    type AesCcm16p64p128<'a>
        = AeadCcm<
        { super::AES128_CANON_KEY_LEN },
        { super::AES128_NONCE_LEN },
        { super::AES128_TAG_LEN },
    >
    where
        Self: 'a;

    type Secp256r1PublicKey<'a>
        = ECPoint<'a, { super::SECP256R1_CANON_POINT_LEN }, { super::SECP256R1_CANON_SCALAR_LEN }>
    where
        Self: 'a;

    type Secp256r1SecretKey<'a>
        = ECScalar<'a, { super::SECP256R1_CANON_SCALAR_LEN }, { super::SECP256R1_CANON_POINT_LEN }>
    where
        Self: 'a;

    type UInt384<'a>
        = Mpi
    where
        Self: 'a;

    type Secp256r1Scalar<'a>
        = ECScalar<'a, { super::SECP256R1_CANON_SCALAR_LEN }, { super::SECP256R1_CANON_POINT_LEN }>
    where
        Self: 'a;

    type Secp256r1Point<'a>
        = ECPoint<'a, { super::SECP256R1_CANON_POINT_LEN }, { super::SECP256R1_CANON_SCALAR_LEN }>
    where
        Self: 'a;

    fn sha256(&self) -> Result<Self::Sha256<'_>, Error> {
        Ok(Sha256::new())
    }

    fn hmac_sha256(&self, key: &[u8]) -> Result<Self::HmacSha256<'_>, Error> {
        Ok(unsafe { Hmac::new(esp_mbedtls_sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256, key) })
    }

    fn hkdf_sha256(&self) -> Result<Self::HkdfSha256<'_>, Error> {
        Ok(Hkdf::new(
            esp_mbedtls_sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
        ))
    }

    fn pbkdf2_hmac_sha256(&self) -> Result<Self::Pbkdf2HmacSha256<'_>, Error> {
        Ok(Pbkdf2Hmac::new(
            esp_mbedtls_sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
        ))
    }

    fn aes_ccm_16_64_128(&self) -> Result<Self::AesCcm16p64p128<'_>, Error> {
        Ok(unsafe {
            AeadCcm::new(esp_mbedtls_sys::mbedtls_cipher_type_t_MBEDTLS_CIPHER_AES_128_CCM)
        })
    }

    fn secp256r1_pub_key(
        &self,
        key: &super::CanonSecp256r1PublicKey,
    ) -> Result<Self::Secp256r1PublicKey<'_>, Error> {
        self.secp256r1_point(key)
    }

    fn secp256r1_secret_key_random(&self) -> Result<Self::Secp256r1SecretKey<'_>, Error> {
        self.secp256r1_scalar_random()
    }

    fn secp256r1_secret_key(
        &self,
        key: &super::CanonSecp256r1SecretKey,
    ) -> Result<Self::Secp256r1SecretKey<'_>, Error> {
        self.secp256r1_scalar(key)
    }

    fn uint384(&self, uint: &super::CanonUint384) -> Result<Self::UInt384<'_>, Error> {
        let mut result = Mpi::new();

        result.set(uint);

        Ok(result)
    }

    fn secp256r1_scalar(
        &self,
        scalar: &super::CanonSecp256r1Scalar,
    ) -> Result<Self::Secp256r1Scalar<'_>, Error> {
        let mut result = ECScalar::new(&self.secp256r1_group);
        result.set(scalar);

        Ok(result)
    }

    fn secp256r1_scalar_random(&self) -> Result<Self::Secp256r1Scalar<'_>, Error> {
        unimplemented!()
    }

    fn secp256r1_point(
        &self,
        point: &super::CanonSecp256r1Point,
    ) -> Result<Self::Secp256r1Point<'_>, Error> {
        let mut result = ECPoint::new(&self.secp256r1_group);
        result.set(point);

        Ok(result)
    }

    fn secp256r1_generator(&self) -> Result<Self::Secp256r1Point<'_>, Error> {
        let mut result = ECPoint::new(&self.secp256r1_group);

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_copy(&mut result.raw, &self.secp256r1_group.raw.G)
        })
        .unwrap();

        Ok(result)
    }
}

pub struct Sha256 {
    raw: esp_mbedtls_sys::mbedtls_sha256_context,
}

impl Sha256 {
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

impl super::Digest<{ super::SHA256_HASH_LEN }> for Sha256 {
    fn update(&mut self, data: &[u8]) {
        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_sha256_update(&mut self.raw, data.as_ptr(), data.len())
        })
        .unwrap();
    }

    fn finish(mut self, out: &mut [u8; super::SHA256_HASH_LEN]) {
        merr!(unsafe { esp_mbedtls_sys::mbedtls_sha256_finish(&mut self.raw, out.as_mut_ptr()) })
            .unwrap();
    }
}

pub struct Hmac<const HASH_LEN: usize> {
    raw: esp_mbedtls_sys::mbedtls_md_context_t,
}

impl<const HASH_LEN: usize> Hmac<HASH_LEN> {
    unsafe fn new(md_type: esp_mbedtls_sys::mbedtls_md_type_t, key: &[u8]) -> Self {
        let mut raw = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_md_init(&mut raw);
        }

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_md_setup(
                &mut raw,
                esp_mbedtls_sys::mbedtls_md_info_from_type(md_type),
                1,
            )
        })
        .unwrap();

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_md_hmac_starts(&mut raw, key.as_ptr(), key.len())
        })
        .unwrap();

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
        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_md_update(&mut self.raw, data.as_ptr(), data.len())
        })
        .unwrap();
    }

    fn finish(mut self, out: &mut [u8; HASH_LEN]) {
        merr!(unsafe { esp_mbedtls_sys::mbedtls_md_finish(&mut self.raw, out.as_mut_ptr()) })
            .unwrap();
    }
}

pub struct Hkdf {
    md_type: esp_mbedtls_sys::mbedtls_md_type_t,
}

impl Hkdf {
    fn new(md_type: esp_mbedtls_sys::mbedtls_md_type_t) -> Self {
        Self { md_type }
    }
}

impl super::Hkdf for Hkdf {
    fn expand(self, salt: &[u8], ikm: &[u8], info: &[u8], key: &mut [u8]) -> Result<(), ()> {
        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_hkdf(
                esp_mbedtls_sys::mbedtls_md_info_from_type(self.md_type),
                salt.as_ptr(),
                salt.len(),
                ikm.as_ptr(),
                ikm.len(),
                info.as_ptr(),
                info.len(),
                key.as_mut_ptr(),
                key.len(),
            )
        })
        .unwrap();

        Ok(())
    }
}

pub struct Pbkdf2Hmac {
    md_type: esp_mbedtls_sys::mbedtls_md_type_t,
}

impl Pbkdf2Hmac {
    fn new(md_type: esp_mbedtls_sys::mbedtls_md_type_t) -> Self {
        Self { md_type }
    }
}

impl super::Pbkdf2Hmac for Pbkdf2Hmac {
    fn derive(self, password: &[u8], iter: usize, salt: &[u8], out: &mut [u8]) {
        unsafe {
            esp_mbedtls_sys::mbedtls_pkcs5_pbkdf2_hmac_ext(
                self.md_type,
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                iter as u32,
                out.len() as _,
                out.as_mut_ptr(),
            );
        }
    }
}

pub struct AeadCcm<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize> {
    cipher_type: esp_mbedtls_sys::mbedtls_cipher_type_t,
}

impl<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>
    AeadCcm<KEY_LEN, NONCE_LEN, TAG_LEN>
{
    unsafe fn new(cipher_type: esp_mbedtls_sys::mbedtls_cipher_type_t) -> Self {
        Self { cipher_type }
    }
}

impl<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>
    super::Aead<KEY_LEN, NONCE_LEN> for AeadCcm<KEY_LEN, NONCE_LEN, TAG_LEN>
{
    fn encrypt_in_place<'a>(
        &mut self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        data: &'a mut [u8],
        data_len: usize,
    ) -> Result<&'a [u8], Error> {
        assert!(data.len() >= data_len + TAG_LEN);

        let mut ctx = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_ccm_init(&mut ctx);
        }

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ccm_setkey(
                &mut ctx,
                self.cipher_type,
                key.as_ptr(),
                (KEY_LEN * 8) as u32,
            )
        })
        .unwrap();

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ccm_encrypt_and_tag(
                &mut ctx,
                data_len,
                nonce.as_ptr(),
                nonce.len(),
                ad.as_ptr(),
                ad.len(),
                data.as_ptr(),
                data.as_mut_ptr(),
                data.as_mut_ptr().add(data_len),
                TAG_LEN,
            )
        })
        .unwrap();

        unsafe {
            esp_mbedtls_sys::mbedtls_ccm_free(&mut ctx);
        }

        Ok(&data[..data_len + TAG_LEN])
    }

    fn decrypt_in_place<'a>(
        &mut self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        assert!(data.len() >= TAG_LEN);

        let mut ctx = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_ccm_init(&mut ctx);
        }

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ccm_setkey(
                &mut ctx,
                self.cipher_type,
                key.as_ptr(),
                (KEY_LEN * 8) as u32,
            )
        })
        .unwrap();

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ccm_auth_decrypt(
                &mut ctx,
                data.len() - TAG_LEN,
                nonce.as_ptr(),
                nonce.len(),
                ad.as_ptr(),
                ad.len(),
                data.as_ptr(),
                data.as_mut_ptr(),
                data.as_mut_ptr().add(data.len() - TAG_LEN),
                TAG_LEN,
            )
        })
        .unwrap();

        unsafe {
            esp_mbedtls_sys::mbedtls_ccm_free(&mut ctx);
        }

        Ok(&data[..data.len() - TAG_LEN])
    }
}

pub struct Mpi {
    raw: esp_mbedtls_sys::mbedtls_mpi,
}

impl Mpi {
    fn new() -> Self {
        let mut raw = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_mpi_init(&mut raw);
        }

        Self { raw }
    }

    fn set(&mut self, uint: &[u8]) {
        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_read_binary(&mut self.raw, uint.as_ptr(), uint.len())
        })
        .unwrap();
    }

    fn write(&self, uint: &mut [u8]) {
        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_write_binary(&self.raw, uint.as_mut_ptr(), uint.len())
        })
        .unwrap();
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

    fn canon_into(&self, buf: &mut [u8; LEN]) {
        self.write(buf);
    }
}

pub struct ECGroup<const LEN: usize, const SCALAR_LEN: usize> {
    raw: esp_mbedtls_sys::mbedtls_ecp_group,
}

impl<const LEN: usize, const SCALAR_LEN: usize> ECGroup<LEN, SCALAR_LEN> {
    unsafe fn new() -> Self {
        let mut raw = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_ecp_group_init(&mut raw);
        }

        Self { raw }
    }

    fn set(&mut self, group_id: esp_mbedtls_sys::mbedtls_ecp_group_id) {
        merr!(unsafe { esp_mbedtls_sys::mbedtls_ecp_group_load(&mut self.raw, group_id) }).unwrap();
    }
}

impl<const LEN: usize, const SCALAR_LEN: usize> Drop for ECGroup<LEN, SCALAR_LEN> {
    fn drop(&mut self) {
        unsafe {
            esp_mbedtls_sys::mbedtls_ecp_group_free(&mut self.raw);
        }
    }
}

pub struct ECPoint<'a, const LEN: usize, const SCALAR_LEN: usize> {
    group: &'a ECGroup<LEN, SCALAR_LEN>,
    raw: esp_mbedtls_sys::mbedtls_ecp_point,
}

impl<'a, const LEN: usize, const SCALAR_LEN: usize> ECPoint<'a, LEN, SCALAR_LEN> {
    fn new(group: &'a ECGroup<LEN, SCALAR_LEN>) -> Self {
        let mut raw = Default::default();

        unsafe {
            esp_mbedtls_sys::mbedtls_ecp_point_init(&mut raw);
        }

        Self { group, raw }
    }

    fn set(&mut self, point: &[u8]) {
        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_point_read_binary(
                &self.group.raw,
                &mut self.raw,
                point.as_ptr(),
                point.len(),
            )
        })
        .unwrap();
    }

    fn write(&self, point: &mut [u8; LEN]) {
        let mut olen = 0;

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_point_write_binary(
                &self.group.raw,
                &self.raw,
                esp_mbedtls_sys::MBEDTLS_ECP_PF_UNCOMPRESSED as _,
                &mut olen,
                point.as_mut_ptr(),
                point.len(),
            )
        })
        .unwrap();

        assert_eq!(olen, LEN);
    }
}

impl<const LEN: usize, const SCALAR_LEN: usize> Drop for ECPoint<'_, LEN, SCALAR_LEN> {
    fn drop(&mut self) {
        unsafe {
            esp_mbedtls_sys::mbedtls_ecp_point_free(&mut self.raw);
        }
    }
}

impl<'a, const LEN: usize, const SCALAR_LEN: usize> super::CurvePoint<'a, LEN, SCALAR_LEN>
    for ECPoint<'a, LEN, SCALAR_LEN>
{
    type Scalar<'s>
        = ECScalar<'s, SCALAR_LEN, LEN>
    where
        Self: 'a + 's;

    fn neg(&self) -> Self {
        let mut result = ECPoint::new(self.group);

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_copy(&mut result.raw.private_X, &self.raw.private_X)
        })
        .unwrap();

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_copy(&mut result.raw.private_Z, &self.raw.private_Z)
        })
        .unwrap();

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_sub_mpi(
                &mut result.raw.private_Y,
                &self.group.raw.P,
                &self.raw.private_Y,
            )
        })
        .unwrap();

        result
    }

    fn mul(&self, scalar: &Self::Scalar<'a>) -> Self {
        let mut result = ECPoint::new(self.group);

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_mul(
                self.group as *const _ as *mut _,
                &mut result.raw,
                &scalar.mpi.raw,
                &self.raw,
                None, // TODO
                core::ptr::null_mut(),
            )
        })
        .unwrap();

        result
    }

    fn add_mul(&self, s1: &Self::Scalar<'a>, p2: &Self, s2: &Self::Scalar<'a>) -> Self {
        let mut result = ECPoint::new(self.group);

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_muladd(
                self.group as *const _ as *mut _,
                &mut result.raw,
                &s1.mpi.raw,
                &self.raw,
                &s2.mpi.raw,
                &p2.raw,
            )
        })
        .unwrap();

        result
    }

    fn canon_into(&self, point: &mut [u8; LEN]) {
        self.write(point);
    }
}

impl<'a, const KEY_LEN: usize, const SECRET_KEY_LEN: usize, const SIGNATURE_LEN: usize>
    super::PublicKey<'a, KEY_LEN, SIGNATURE_LEN> for ECPoint<'a, KEY_LEN, SECRET_KEY_LEN>
{
    fn verify(&self, data: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
        let mut r = Mpi::new();
        let mut s = Mpi::new();

        let (r_signature, s_signature) = signature.split_at(super::SECP256R1_SIGNATURE_LEN / 2);

        r.set(r_signature);
        s.set(s_signature);

        use super::Digest;

        let mut sha256 = Sha256::new();
        sha256.update(data);

        let mut hash = super::SHA256_HASH_ZEROED;
        sha256.finish(&mut hash);

        let result = unsafe {
            esp_mbedtls_sys::mbedtls_ecdsa_verify(
                self.group as *const _ as *mut _,
                hash.as_ptr(),
                hash.len(),
                &self.raw,
                &r.raw,
                &s.raw,
            )
        };

        result == 0
    }

    fn canon_into(&self, key: &mut [u8; KEY_LEN]) {
        self.write(key);
    }
}

pub struct ECScalar<'a, const LEN: usize, const POINT_LEN: usize> {
    group: &'a ECGroup<POINT_LEN, LEN>,
    mpi: Mpi,
}

impl<'a, const LEN: usize, const POINT_LEN: usize> ECScalar<'a, LEN, POINT_LEN> {
    fn new(group: &'a ECGroup<POINT_LEN, LEN>) -> Self {
        Self {
            group,
            mpi: Mpi::new(),
        }
    }

    fn set(&mut self, scalar: &[u8]) {
        self.mpi.set(scalar);
    }

    fn write(&self, scalar: &mut [u8; LEN]) {
        self.mpi.write(scalar);
    }
}

impl<'a, const LEN: usize, const POINT_LEN: usize> super::Scalar<'a, LEN>
    for ECScalar<'a, LEN, POINT_LEN>
{
    fn mul(&self, other: &Self) -> Self {
        let mut result = ECScalar::new(self.group);

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_mpi_mul_mpi(&mut result.mpi.raw, &self.mpi.raw, &other.mpi.raw)
        })
        .unwrap();

        result
    }

    fn canon_into(&self, scalar: &mut [u8; LEN]) {
        self.write(scalar);
    }
}

impl<
        'a,
        const KEY_LEN: usize,
        const PUB_KEY_LEN: usize,
        const SIGNATURE_LEN: usize,
        const SHARED_SECRET_LEN: usize,
    > super::SecretKey<'a, KEY_LEN, PUB_KEY_LEN, SIGNATURE_LEN, SHARED_SECRET_LEN>
    for ECScalar<'a, KEY_LEN, PUB_KEY_LEN>
{
    type PublicKey<'s>
        = ECPoint<'s, PUB_KEY_LEN, KEY_LEN>
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

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_pk_setup(
                &mut pk,
                esp_mbedtls_sys::mbedtls_pk_info_from_type(
                    esp_mbedtls_sys::mbedtls_pk_type_t_MBEDTLS_PK_ECKEY,
                ),
            )
        })
        .unwrap();

        let ec_ctx =
            unsafe { (pk.private_pk_ctx as *mut esp_mbedtls_sys::mbedtls_ecp_keypair).as_mut() }
                .unwrap();

        unsafe {
            esp_mbedtls_sys::mbedtls_ecp_point_init(&mut ec_ctx.private_Q);
        }

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_mul(
                &self.group as *const _ as *mut _,
                &mut ec_ctx.private_Q,
                &self.mpi.raw,
                &self.group.raw.G,
                None, // TODO
                core::ptr::null_mut(),
            )
        })
        .unwrap();

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_group_copy(&mut ec_ctx.private_grp, &self.group.raw)
        })
        .unwrap();

        unsafe {
            esp_mbedtls_sys::mbedtls_x509write_csr_set_key(&mut csr, &mut pk);
        }

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_x509write_csr_set_subject_name(&mut csr, c"O=CSR".as_ptr())
        })
        .unwrap();

        let len = merr!(unsafe {
            esp_mbedtls_sys::mbedtls_x509write_csr_der(
                &mut csr,
                buf.as_mut_ptr(),
                buf.len(),
                None,
                core::ptr::null_mut(),
            )
        })
        .unwrap();

        unsafe {
            esp_mbedtls_sys::mbedtls_x509write_csr_free(&mut csr);
            esp_mbedtls_sys::mbedtls_pk_free(&mut pk);
        }

        Ok(&buf[..len as usize])
    }

    fn pub_key(&self) -> Self::PublicKey<'a> {
        let mut pub_key = ECPoint::new(self.group);

        merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ecp_mul(
                self.group as *const _ as *mut _,
                &mut pub_key.raw,
                &self.mpi.raw,
                &self.group.raw.G,
                None, // TODO
                core::ptr::null_mut(),
            )
        })
        .unwrap();

        pub_key
    }

    fn canon_into(&self, key: &mut [u8; KEY_LEN]) {
        self.write(key);
    }

    fn derive_shared_secret(
        &self,
        peer_pub_key: &Self::PublicKey<'a>,
        shared_secret: &mut [u8; SHARED_SECRET_LEN],
    ) {
        let mut z = Mpi::new();

        let result = merr!(unsafe {
            esp_mbedtls_sys::mbedtls_ecdh_compute_shared(
                self.group as *const _ as *mut _,
                &mut z.raw,
                &peer_pub_key.raw,
                &self.mpi.raw,
                None, // TODO
                core::ptr::null_mut(),
            )
        });

        z.write(shared_secret);

        result.unwrap();
    }

    fn sign(&self, data: &[u8], signature: &mut [u8; SIGNATURE_LEN]) {
        use super::Digest;

        let mut sha256 = Sha256::new();
        sha256.update(data);

        let mut hash = super::SHA256_HASH_ZEROED;
        sha256.finish(&mut hash);

        let mut r = Mpi::new();
        let mut s = Mpi::new();

        let result = unsafe {
            esp_mbedtls_sys::mbedtls_ecdsa_sign(
                &self.group as *const _ as *mut _,
                &mut r.raw,
                &mut s.raw,
                &self.mpi.raw,
                hash.as_ptr(),
                hash.len(),
                None, // TODO
                core::ptr::null_mut(),
            )
        };

        merr!(result).unwrap();

        let (r_signature, s_signature) = signature.split_at_mut(super::SECP256R1_SIGNATURE_LEN / 2);

        r.write(r_signature);
        s.write(s_signature);
    }
}

#[no_mangle]
unsafe extern "C" fn mbedtls_platform_zeroize(dst: *mut core::ffi::c_uchar, len: u32) {
    for i in 0..len as isize {
        dst.offset(i).write_volatile(0);
    }
}
