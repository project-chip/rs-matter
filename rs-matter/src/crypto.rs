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

use crate::error::Error;

#[cfg(not(any(feature = "rustcrypto", feature = "mbedtls", feature = "openssl")))]
pub use self::dummy::*;
#[cfg(all(feature = "mbedtls", not(feature = "rustcrypto")))]
pub use self::mbedtls::*;
#[cfg(all(
    feature = "openssl",
    not(any(feature = "rustcrypto", feature = "mbedtls"))
))]
pub use self::openssl::*;
#[cfg(feature = "rustcrypto")]
pub use self::rustcrypto::*;

// pub const SYMM_KEY_LEN_BITS: usize = 128;
// pub const SYMM_KEY_LEN_BYTES: usize = SYMM_KEY_LEN_BITS / 8;

// pub const AEAD_MIC_LEN_BITS: usize = 128;
// pub const AEAD_MIC_LEN_BYTES: usize = AEAD_MIC_LEN_BITS / 8;

// pub const AEAD_NONCE_LEN_BYTES: usize = 13;
// pub const AEAD_AAD_LEN_BYTES: usize = 8;

// pub const SHA256_HASH_LEN_BYTES: usize = 256 / 8;

// pub const BIGNUM_LEN_BYTES: usize = 32;
// pub const EC_POINT_LEN_BYTES: usize = 65;

// pub const ECDH_SHARED_SECRET_LEN_BYTES: usize = 32;

// pub const EC_SIGNATURE_LEN_BYTES: usize = 64;

#[cfg(not(any(feature = "rustcrypto", feature = "mbedtls", feature = "openssl")))]
mod dummy;
#[cfg(all(feature = "mbedtls", not(feature = "rustcrypto")))]
mod mbedtls;
#[cfg(all(
    feature = "openssl",
    not(any(feature = "rustcrypto", feature = "mbedtls"))
))]
mod openssl;
#[cfg(feature = "rustcrypto")]
mod rustcrypto;

pub const SHA256_HASH_LEN: usize = 32;

pub const SECP256R1_SCALAR_LEN: usize = 32;
pub const SECP256R1_POINT_LEN: usize = 65;
pub const SECP256R1_SECRET_KEY_LEN: usize = 95;
pub const SECP256R1_SIGNATURE_LEN: usize = 64;
pub const SECP256R1_ECDH_SHARED_SECRET_LEN: usize = 32;

pub const UINT384_LEN: usize = 48;

pub const AES128_KEY_LEN: usize = 16;
pub const AES128_NONCE_LEN: usize = 13;
pub const AES128_TAG_LEN: usize = 16;
pub const AES128_AAD_LEN: usize = 8;

pub type Sha256Hash = [u8; SHA256_HASH_LEN];
pub const SHA256_HASH_ZEROED: Sha256Hash = [0u8; SHA256_HASH_LEN];

pub type Uint384 = [u8; UINT384_LEN];
pub const UINT384_ZEROED: Uint384 = [0u8; UINT384_LEN];

pub type Aes128Key = [u8; AES128_KEY_LEN];
pub const AES128_ZEROED: Aes128Key = [0u8; AES128_KEY_LEN];

pub type Aes128Nonce = [u8; AES128_NONCE_LEN];
pub const AES128_NONCE_ZEROED: Aes128Nonce = [0u8; AES128_NONCE_LEN];

pub type Aes128Tag = [u8; AES128_TAG_LEN];
pub const AES128_TAG_ZEROED: Aes128Tag = [0u8; AES128_TAG_LEN];

pub type Aes128Aad = [u8; AES128_AAD_LEN];
pub const AES128_AAD_ZEROED: Aes128Aad = [0u8; AES128_AAD_LEN];

pub type Secp256r1Scalar = [u8; SECP256R1_SCALAR_LEN];
pub const SECP256R1_SCALAR_ZEROED: Secp256r1Scalar = [0u8; SECP256R1_SCALAR_LEN];

pub type Secp256r1Point = [u8; SECP256R1_POINT_LEN];
pub const SECP256R1_POINT_ZEROED: Secp256r1Point = [0u8; SECP256R1_POINT_LEN];

pub type Secp256r1SecretKey = [u8; SECP256R1_SECRET_KEY_LEN];
pub const SECP256R1_SECRET_KEY_ZEROED: Secp256r1SecretKey = [0u8; SECP256R1_SECRET_KEY_LEN];

pub type Secp256r1PublicKey = Secp256r1Point;
pub const SECP256R1_PUBLIC_KEY_ZEROED: Secp256r1PublicKey = SECP256R1_POINT_ZEROED;

pub type Secp256r1Signature = [u8; SECP256R1_SIGNATURE_LEN];
pub const SECP256R1_SIGNATURE_ZEROED: Secp256r1Signature = [0u8; SECP256R1_SIGNATURE_LEN];

pub type Secp256r1EcdhSharedSecret = [u8; SECP256R1_ECDH_SHARED_SECRET_LEN];
pub const SECP256R1_ECDH_SHARED_SECRET_ZEROED: Secp256r1EcdhSharedSecret =
    [0u8; SECP256R1_ECDH_SHARED_SECRET_LEN];

pub type FabricSecretKey = Secp256r1SecretKey;
pub const FABRIC_SECRET_KEY_ZEROED: FabricSecretKey = SECP256R1_SECRET_KEY_ZEROED;

pub type FabricPublicKey = Secp256r1PublicKey;
pub const FABRIC_PUBLIC_KEY_ZEROED: FabricPublicKey = SECP256R1_PUBLIC_KEY_ZEROED;

pub type SessionKey = Aes128Key;
pub const SESSION_KEY_ZEROED: SessionKey = AES128_ZEROED;

pub trait Crypto {
    type Sha256<'a>: Digest<SHA256_HASH_LEN>
    where
        Self: 'a;
    type HmacSha256<'a>: Digest<SHA256_HASH_LEN>
    where
        Self: 'a;
    type HkdfSha256<'a>: Hkdf<SHA256_HASH_LEN>
    where
        Self: 'a;
    type Pbkdf2HmacSha256<'a>: Pbkdf2Hmac<SHA256_HASH_LEN>
    where
        Self: 'a;
    type AesCcm16p64p128<'a>: Aead<AES128_NONCE_LEN>
    where
        Self: 'a;
    type PublicKeySecp256r1<'a>: PublicKey<SECP256R1_POINT_LEN, SECP256R1_SIGNATURE_LEN>
    where
        Self: 'a;
    type SecretKeySecp256r1<'a>: SecretKey<
        SECP256R1_SECRET_KEY_LEN,
        SECP256R1_POINT_LEN,
        SECP256R1_SIGNATURE_LEN,
        SECP256R1_ECDH_SHARED_SECRET_LEN,
        PublicKey<'a> = Self::PublicKeySecp256r1<'a>,
    >
    where
        Self: 'a;
    type UInt384<'a>: UInt<'a, UINT384_LEN>
    where
        Self: 'a;
    type Secp256r1Scalar<'a>: Scalar<'a, SECP256R1_SCALAR_LEN>
    where
        Self: 'a;
    type Secp256r1Point<'a>: CurvePoint<
        'a,
        SECP256R1_POINT_LEN,
        SECP256R1_SCALAR_LEN,
        Scalar<'a> = Self::Secp256r1Scalar<'a>,
    >
    where
        Self: 'a;

    fn sha256(&self) -> Result<Self::Sha256<'_>, Error>;

    fn hmac_sha256(&self, key: &[u8]) -> Result<Self::HmacSha256<'_>, Error>;

    fn hkdf_sha256(&self) -> Result<Self::HkdfSha256<'_>, Error>;

    fn pbkdf2_hmac_sha256(&self) -> Result<Self::Pbkdf2HmacSha256<'_>, Error>;

    fn aes_ccm_16_64_128(&self, key: &Aes128Key) -> Result<Self::AesCcm16p64p128<'_>, Error>;

    fn public_key_secp256r1_hydrate(
        &self,
        dehydrated_public_key: &Secp256r1PublicKey,
    ) -> Result<Self::PublicKeySecp256r1<'_>, Error>;

    fn secret_key_secp256r1(&self) -> Result<Self::SecretKeySecp256r1<'_>, Error>;

    fn secret_key_secp256r1_hydrate(
        &self,
        dehydrated_secret_key: &Secp256r1SecretKey,
    ) -> Result<Self::SecretKeySecp256r1<'_>, Error>;

    fn uint384(&self, scalar: &Uint384) -> Result<Self::UInt384<'_>, Error>;

    fn secp256r1_scalar(
        &self,
        scalar: &Secp256r1Scalar,
    ) -> Result<Self::Secp256r1Scalar<'_>, Error>;

    fn secp256r1_scalar_random(&self) -> Result<Self::Secp256r1Scalar<'_>, Error>;

    fn secpp256r1_point(&self, point: &Secp256r1Point) -> Result<Self::Secp256r1Point<'_>, Error>;

    fn secpp256r1_generator(&self) -> Result<Self::Secp256r1Point<'_>, Error>;
}

impl<T> Crypto for &T
where
    T: Crypto,
{
    type Sha256<'a>
        = T::Sha256<'a>
    where
        Self: 'a;
    type HmacSha256<'a>
        = T::HmacSha256<'a>
    where
        Self: 'a;
    type HkdfSha256<'a>
        = T::HkdfSha256<'a>
    where
        Self: 'a;
    type Pbkdf2HmacSha256<'a>
        = T::Pbkdf2HmacSha256<'a>
    where
        Self: 'a;
    type AesCcm16p64p128<'a>
        = T::AesCcm16p64p128<'a>
    where
        Self: 'a;
    type PublicKeySecp256r1<'a>
        = T::PublicKeySecp256r1<'a>
    where
        Self: 'a;
    type SecretKeySecp256r1<'a>
        = T::SecretKeySecp256r1<'a>
    where
        Self: 'a;
    type UInt384<'a>
        = T::UInt384<'a>
    where
        Self: 'a;
    type Secp256r1Scalar<'a>
        = T::Secp256r1Scalar<'a>
    where
        Self: 'a;
    type Secp256r1Point<'a>
        = T::Secp256r1Point<'a>
    where
        Self: 'a;

    fn sha256(&self) -> Result<Self::Sha256<'_>, Error> {
        (*self).sha256()
    }

    fn hmac_sha256(&self, key: &[u8]) -> Result<Self::HmacSha256<'_>, Error> {
        (*self).hmac_sha256(key)
    }

    fn hkdf_sha256(&self) -> Result<Self::HkdfSha256<'_>, Error> {
        (*self).hkdf_sha256()
    }

    fn pbkdf2_hmac_sha256(&self) -> Result<Self::Pbkdf2HmacSha256<'_>, Error> {
        (*self).pbkdf2_hmac_sha256()
    }

    fn aes_ccm_16_64_128(&self, key: &Aes128Key) -> Result<Self::AesCcm16p64p128<'_>, Error> {
        (*self).aes_ccm_16_64_128(key)
    }

    fn public_key_secp256r1_hydrate(
        &self,
        dehydrated_public_key: &Secp256r1PublicKey,
    ) -> Result<Self::PublicKeySecp256r1<'_>, Error> {
        (*self).public_key_secp256r1_hydrate(dehydrated_public_key)
    }

    fn secret_key_secp256r1(&self) -> Result<Self::SecretKeySecp256r1<'_>, Error> {
        (*self).secret_key_secp256r1()
    }

    fn secret_key_secp256r1_hydrate(
        &self,
        dehydrated_secret_key: &Secp256r1SecretKey,
    ) -> Result<Self::SecretKeySecp256r1<'_>, Error> {
        (*self).secret_key_secp256r1_hydrate(dehydrated_secret_key)
    }

    fn uint384(&self, scalar: &Uint384) -> Result<Self::UInt384<'_>, Error> {
        (*self).uint384(scalar)
    }

    fn secp256r1_scalar(
        &self,
        scalar: &Secp256r1Scalar,
    ) -> Result<Self::Secp256r1Scalar<'_>, Error> {
        (*self).secp256r1_scalar(scalar)
    }

    fn secp256r1_scalar_random(&self) -> Result<Self::Secp256r1Scalar<'_>, Error> {
        (*self).secp256r1_scalar_random()
    }

    fn secpp256r1_point(&self, point: &Secp256r1Point) -> Result<Self::Secp256r1Point<'_>, Error> {
        (*self).secpp256r1_point(point)
    }

    fn secpp256r1_generator(&self) -> Result<Self::Secp256r1Point<'_>, Error> {
        (*self).secpp256r1_generator()
    }
}

pub trait Digest<const HASH_LEN: usize> {
    fn update(&mut self, data: &[u8]);

    fn finish(self, hash: &mut [u8; HASH_LEN]);
}

pub trait Hkdf<const IKM_LEN: usize> {
    fn expand(self, salt: &[u8], ikm: &[u8; IKM_LEN], info: &[u8], key: &mut [u8]);
}

pub trait Pbkdf2Hmac<const KEY_LEN: usize> {
    fn derive(self, pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8; KEY_LEN]);
}

pub trait Aead<const NONCE_LEN: usize> {
    fn encrypt_in_place<'a>(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        data: &'a mut [u8],
        data_len: usize,
    ) -> Result<&'a [u8], Error>;

    fn decrypt_in_place<'a>(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], Error>;
}

impl<const NONCE_LEN: usize, T> Aead<NONCE_LEN> for &mut T
where
    T: Aead<NONCE_LEN>,
{
    fn encrypt_in_place<'a>(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        data: &'a mut [u8],
        data_len: usize,
    ) -> Result<&'a [u8], Error> {
        (*self).encrypt_in_place(nonce, ad, data, data_len)
    }

    fn decrypt_in_place<'a>(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        (*self).decrypt_in_place(nonce, ad, data)
    }
}

pub trait SecretKey<
    const KEY_LEN: usize,
    const PUB_KEY_LEN: usize,
    const SIGNATURE_LEN: usize,
    const SHARED_SECRET_LEN: usize,
>
{
    type PublicKey<'a>: PublicKey<PUB_KEY_LEN, SIGNATURE_LEN>
    where
        Self: 'a;

    fn csr<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Error>;

    fn pub_key(&self) -> Result<Self::PublicKey<'_>, Error>;

    fn dehydrate(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error>;

    fn derive_shared_secret(
        &self,
        peer_pub_key: &Self::PublicKey<'_>,
        shared_secret: &mut [u8; SHARED_SECRET_LEN],
    ) -> Result<(), Error>;

    fn sign(&self, data: &[u8], signature: &mut [u8; SIGNATURE_LEN]) -> Result<(), Error>;
}

// TODO
// impl<'t, T> SecretKey for &'t T
// where
//     T: SecretKey + 't,
// {
//     type PublicKey<'a>
//         = T::PublicKey<'a>
//     where
//         Self: 'a;

//     fn csr<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
//         (*self).csr(buf)
//     }

//     fn pub_key(&self) -> Result<Self::PublicKey<'_>, Error> {
//         (*self).pub_key()
//     }

//     fn dehydrate<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
//         (*self).dehydrate(buf)
//     }

//     fn derive_shared_secret<'a>(
//         &self,
//         peer_pub_key: &Self::PublicKey<'_>,
//         buf: &'a mut [u8],
//     ) -> Result<&'a [u8], Error> {
//         (*self).derive_shared_secret(peer_pub_key, buf)
//     }

//     fn sign<'a>(&self, data: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
//         (*self).sign(data, buf)
//     }
// }

pub trait PublicKey<const KEY_LEN: usize, const SIGNATURE_LEN: usize> {
    fn dehydrate(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error>;

    fn verify(&self, signature: &[u8; SIGNATURE_LEN], data: &[u8]) -> Result<(), Error>;
}

impl<const KEY_LEN: usize, const SIGNATURE_LEN: usize, T> PublicKey<KEY_LEN, SIGNATURE_LEN> for &T
where
    T: PublicKey<KEY_LEN, SIGNATURE_LEN>,
{
    fn dehydrate(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        (*self).dehydrate(key)
    }

    fn verify(&self, signature: &[u8; SIGNATURE_LEN], data: &[u8]) -> Result<(), Error> {
        (*self).verify(signature, data)
    }
}

pub trait UInt<'a, const LEN: usize> {
    fn rem(&self, other: &Self) -> Self;

    fn dehydrate(&self, key: &mut [u8; LEN]) -> Result<(), Error>;
}

pub trait Scalar<'a, const LEN: usize> {
    fn mul(&self, other: &Self) -> Self;

    fn dehydrate(&self, buf: &mut [u8; LEN]) -> Result<(), Error>;
}

pub trait CurvePoint<'a, const LEN: usize, const SCALAR_LEN: usize> {
    type Scalar<'s>: Scalar<'s, SCALAR_LEN>;

    fn neg(&self) -> Self;

    fn mul(&self, scalar: &Self::Scalar<'a>) -> Self;

    fn add(&self, other: &Self) -> Self;

    fn dehydrate(&self, buf: &mut [u8; LEN]) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use crate::error::ErrorCode;

    #[test]
    fn test_verify_msg_success() {
        let key = unwrap!(KeyPair::new_from_public(&test_vectors::PUB_KEY1));
        unwrap!(key.verify_msg(&test_vectors::MSG1_SUCCESS, &test_vectors::SIGNATURE1));
    }

    #[test]
    fn test_verify_msg_fail() {
        let key = unwrap!(KeyPair::new_from_public(&test_vectors::PUB_KEY1));
        assert_eq!(
            key.verify_msg(&test_vectors::MSG1_FAIL, &test_vectors::SIGNATURE1)
                .map_err(|e| e.code()),
            Err(ErrorCode::InvalidSignature)
        );
    }

    mod test_vectors {
        pub const PUB_KEY1: [u8; 65] = [
            0x4, 0x56, 0x19, 0x77, 0x18, 0x3f, 0xd4, 0xff, 0x2b, 0x58, 0x3d, 0xe9, 0x79, 0x34,
            0x66, 0xdf, 0xe9, 0x0, 0xfb, 0x6d, 0xa1, 0xef, 0xe0, 0xcc, 0xdc, 0x77, 0x30, 0xc0,
            0x6f, 0xb6, 0x2d, 0xff, 0xbe, 0x54, 0xa0, 0x95, 0x75, 0xb, 0x8b, 0x7, 0xbc, 0x55, 0xdb,
            0x9c, 0xb6, 0x55, 0x13, 0x8, 0xb8, 0xdf, 0x2, 0xe3, 0x40, 0x6b, 0xae, 0x34, 0xf5, 0xc,
            0xba, 0xc9, 0xf2, 0xbf, 0xf1, 0xe7, 0x50,
        ];
        pub const MSG1_SUCCESS: [u8; 421] = [
            0x30, 0x82, 0x1, 0xa1, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2, 0x1, 0x1, 0x30, 0xa, 0x6, 0x8,
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x30, 0x44, 0x31, 0x20, 0x30, 0x1e, 0x6,
            0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x1, 0x3, 0xc, 0x10, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x31,
            0x20, 0x30, 0x1e, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x1, 0x5, 0xc,
            0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x31, 0x30, 0x1e, 0x17, 0xd, 0x32, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0xd, 0x33, 0x30, 0x31, 0x32, 0x33, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x44, 0x31, 0x20, 0x30, 0x1e, 0x6, 0xa,
            0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x1, 0x1, 0xc, 0x10, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x42, 0x43, 0x35, 0x43, 0x30, 0x32, 0x31,
            0x20, 0x30, 0x1e, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x1, 0x5, 0xc,
            0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x31, 0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2,
            0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x6,
            0x47, 0xf2, 0x86, 0x4d, 0x27, 0x25, 0xdc, 0x1, 0xa, 0x87, 0xde, 0x8d, 0xca, 0x88, 0x37,
            0xcb, 0x3b, 0xd0, 0xea, 0x93, 0xa6, 0x24, 0x65, 0x8, 0x8f, 0xa1, 0x75, 0xc2, 0xd4,
            0x41, 0xfa, 0xca, 0x96, 0x54, 0xa3, 0xd8, 0x10, 0x85, 0x73, 0xce, 0x15, 0xa5, 0x38,
            0xc1, 0xe3, 0xb5, 0x6b, 0x61, 0x1, 0xd3, 0xc4, 0xb7, 0x6b, 0x61, 0x16, 0xc3, 0x77,
            0x8d, 0xe9, 0xb5, 0x44, 0xac, 0x14, 0xa3, 0x81, 0x83, 0x30, 0x81, 0x80, 0x30, 0xc, 0x6,
            0x3, 0x55, 0x1d, 0x13, 0x1, 0x1, 0xff, 0x4, 0x2, 0x30, 0x0, 0x30, 0xe, 0x6, 0x3, 0x55,
            0x1d, 0xf, 0x1, 0x1, 0xff, 0x4, 0x4, 0x3, 0x2, 0x7, 0x80, 0x30, 0x20, 0x6, 0x3, 0x55,
            0x1d, 0x25, 0x1, 0x1, 0xff, 0x4, 0x16, 0x30, 0x14, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5,
            0x7, 0x3, 0x2, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3, 0x1, 0x30, 0x1d, 0x6, 0x3,
            0x55, 0x1d, 0xe, 0x4, 0x16, 0x4, 0x14, 0xbd, 0xfd, 0x11, 0xac, 0x89, 0xb6, 0xe0, 0x90,
            0x7a, 0xf6, 0x12, 0x61, 0x78, 0x4d, 0x3d, 0x79, 0x56, 0xeb, 0xc2, 0xdc, 0x30, 0x1f,
            0x6, 0x3, 0x55, 0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0xce, 0x60, 0xb4, 0x28,
            0x96, 0x72, 0x27, 0x64, 0x81, 0xbc, 0x4f, 0x0, 0x78, 0xa3, 0x30, 0x48, 0xfe, 0x6e,
            0x65, 0x86,
        ];
        pub const MSG1_FAIL: [u8; 421] = [
            0x30, 0x82, 0x1, 0xa1, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2, 0x1, 0x1, 0x30, 0xa, 0x6, 0x8,
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x30, 0x44, 0x31, 0x20, 0x30, 0x1e, 0x6,
            0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x1, 0x3, 0xc, 0x10, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x31,
            0x20, 0x30, 0x1e, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x1, 0x5, 0xc,
            0x10, 0x30, 0x30, 0x30, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x31, 0x30, 0x1e, 0x17, 0xd, 0x32, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0xd, 0x33, 0x30, 0x31, 0x32, 0x33, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x44, 0x31, 0x20, 0x30, 0x1e, 0x6, 0xa,
            0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x1, 0x1, 0xc, 0x10, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x42, 0x43, 0x35, 0x43, 0x30, 0x32, 0x31,
            0x20, 0x30, 0x1e, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x1, 0x5, 0xc,
            0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x31, 0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2,
            0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x6,
            0x47, 0xf2, 0x86, 0x4d, 0x27, 0x25, 0xdc, 0x1, 0xa, 0x87, 0xde, 0x8d, 0xca, 0x88, 0x37,
            0xcb, 0x3b, 0xd0, 0xea, 0x93, 0xa6, 0x24, 0x65, 0x8, 0x8f, 0xa1, 0x75, 0xc2, 0xd4,
            0x41, 0xfa, 0xca, 0x96, 0x54, 0xa3, 0xd8, 0x10, 0x85, 0x73, 0xce, 0x15, 0xa5, 0x38,
            0xc1, 0xe3, 0xb5, 0x6b, 0x61, 0x1, 0xd3, 0xc4, 0xb7, 0x6b, 0x61, 0x16, 0xc3, 0x77,
            0x8d, 0xe9, 0xb5, 0x44, 0xac, 0x14, 0xa3, 0x81, 0x83, 0x30, 0x81, 0x80, 0x30, 0xc, 0x6,
            0x3, 0x55, 0x1d, 0x13, 0x1, 0x1, 0xff, 0x4, 0x2, 0x30, 0x0, 0x30, 0xe, 0x6, 0x3, 0x55,
            0x1d, 0xf, 0x1, 0x1, 0xff, 0x4, 0x4, 0x3, 0x2, 0x7, 0x80, 0x30, 0x20, 0x6, 0x3, 0x55,
            0x1d, 0x25, 0x1, 0x1, 0xff, 0x4, 0x16, 0x30, 0x14, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5,
            0x7, 0x3, 0x2, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3, 0x1, 0x30, 0x1d, 0x6, 0x3,
            0x55, 0x1d, 0xe, 0x4, 0x16, 0x4, 0x14, 0xbd, 0xfd, 0x11, 0xac, 0x89, 0xb6, 0xe0, 0x90,
            0x7a, 0xf6, 0x12, 0x61, 0x78, 0x4d, 0x3d, 0x79, 0x56, 0xeb, 0xc2, 0xdc, 0x30, 0x1f,
            0x6, 0x3, 0x55, 0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0xce, 0x60, 0xb4, 0x28,
            0x96, 0x72, 0x27, 0x64, 0x81, 0xbc, 0x4f, 0x0, 0x78, 0xa3, 0x30, 0x48, 0xfe, 0x6e,
            0x65, 0x86,
        ];
        pub const SIGNATURE1: [u8; 64] = [
            0x20, 0x16, 0xd0, 0x13, 0x1e, 0xd0, 0xb3, 0x9d, 0x44, 0x25, 0x16, 0xea, 0x9c, 0xf2,
            0x72, 0x44, 0xd7, 0xb0, 0xf4, 0xae, 0x4a, 0xa4, 0x37, 0x32, 0xcd, 0x6a, 0x79, 0x7a,
            0x4c, 0x48, 0x3, 0x6d, 0xef, 0xe6, 0x26, 0x82, 0x39, 0x28, 0x9, 0x22, 0xc8, 0x9a, 0xde,
            0xd5, 0x13, 0x9f, 0xc5, 0x40, 0x25, 0x85, 0x2c, 0x69, 0xe0, 0xdb, 0x6a, 0x79, 0x5b,
            0x21, 0x82, 0x13, 0xb0, 0x20, 0xb9, 0x69,
        ];
    }
}
