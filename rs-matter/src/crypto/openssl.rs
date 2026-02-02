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

//! An OpenSSL-based crypto backend

#![allow(deprecated)] // Remove this once `hmac` updates to `generic-array` 1.x

use core::ops::Mul;

use openssl::asn1::Asn1Type;
use openssl::bn::{BigNum, BigNumContext};
use openssl::cipher::CipherRef;
use openssl::cipher_ctx::CipherCtx;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{Hasher, MessageDigest};
use openssl::md::{Md, MdRef};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl::x509::{X509NameBuilder, X509ReqBuilder};

// We directly use the hmac crate here, there was a self-referential structure
// problem while using OpenSSL's Signer
// TODO: Use proper OpenSSL method for this
use hmac::{Hmac, Mac};

use rand_core::{CryptoRng, RngCore};

use crate::crypto::{CanonPkcSecretKeyRef, CryptoSensitive, CryptoSensitiveRef};
use crate::error::{Error, ErrorCode};

macro_rules! openssl_unwrap {
    ($expr:expr) => {{
        let result = $expr;
        match result {
            Ok(val) => val,
            Err(err) => {
                #[cfg(not(feature = "defmt"))]
                {
                    panic!("{:?}", err);
                }

                #[cfg(feature = "defmt")]
                {
                    extern crate alloc;
                    panic!("{}", alloc::format!("{err:?}"));
                }
            }
        }
    }};
}

/// An OpenSSL-based crypto backend
pub struct OpenSslCrypto<'s> {
    /// Elliptic curve group (secp256r1)
    ec_group: ECGroup<{ super::EC_CANON_POINT_LEN }, { super::EC_CANON_SCALAR_LEN }>,
    /// The singleton secret key to be returned by `Crypto::singleton_singing_secret_key`
    singleton_secret_key: CanonPkcSecretKeyRef<'s>,
}

impl<'s> OpenSslCrypto<'s> {
    /// Create a new OpenSSL crypto backend
    ///
    /// # Arguments
    /// - `singleton_secret_key` - A singleton secret key to be returned by `Crypto::singleton_singing_secret_key`
    ///   The primary use-case for this secret key is to be used as the secret key for the Device Attestation credentials
    pub fn new(singleton_secret_key: CanonPkcSecretKeyRef<'s>) -> Self {
        Self {
            ec_group: unsafe { ECGroup::new(Nid::X9_62_PRIME256V1).unwrap() },
            singleton_secret_key,
        }
    }
}

impl super::Crypto for OpenSslCrypto<'_> {
    type Rand<'a>
        = Rand
    where
        Self: 'a;

    type WeakRand<'a>
        = Rand
    where
        Self: 'a;

    type Hash<'a>
        = Hash<{ super::HASH_LEN }>
    where
        Self: 'a;

    type Hmac<'a>
        = HmacSha256
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
        = Aead<{ super::AEAD_CANON_KEY_LEN }, { super::AEAD_NONCE_LEN }, { super::AEAD_TAG_LEN }>
    where
        Self: 'a;

    type PublicKey<'a>
        = ECPoint<'a, { super::EC_CANON_POINT_LEN }, { super::EC_CANON_SCALAR_LEN }>
    where
        Self: 'a;

    type SecretKey<'a>
        = ECScalar<'a, { super::EC_CANON_SCALAR_LEN }, { super::EC_CANON_POINT_LEN }>
    where
        Self: 'a;

    type SigningSecretKey<'a>
        = ECScalar<'a, { super::EC_CANON_SCALAR_LEN }, { super::EC_CANON_POINT_LEN }>
    where
        Self: 'a;

    type UInt320<'a>
        = BigNum
    where
        Self: 'a;

    type EcScalar<'a>
        = ECScalar<'a, { super::EC_CANON_SCALAR_LEN }, { super::EC_CANON_POINT_LEN }>
    where
        Self: 'a;

    type EcPoint<'a>
        = ECPoint<'a, { super::EC_CANON_POINT_LEN }, { super::EC_CANON_SCALAR_LEN }>
    where
        Self: 'a;

    fn rand(&self) -> Result<Self::Rand<'_>, Error> {
        Ok(Rand(()))
    }

    fn weak_rand(&self) -> Result<Self::WeakRand<'_>, Error> {
        Ok(Rand(()))
    }

    fn hash(&self) -> Result<Self::Hash<'_>, Error> {
        unsafe { Hash::new(MessageDigest::sha256()) }
    }

    fn hmac<const KEY_LEN: usize>(
        &self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
    ) -> Result<Self::Hmac<'_>, Error> {
        Ok(HmacSha256::new(key.access()))
    }

    fn kdf(&self) -> Result<Self::Kdf<'_>, Error> {
        Ok(Hkdf::new(Md::sha256()))
    }

    fn pbkdf(&self) -> Result<Self::PbKdf<'_>, Error> {
        Ok(Pbkdf2Hmac::new(MessageDigest::sha256()))
    }

    fn aead(&self) -> Result<Self::Aead<'_>, Error> {
        Ok(unsafe { Aead::new(openssl::cipher::Cipher::aes_128_ccm()) })
    }

    fn pub_key(&self, key: super::CanonPkcPublicKeyRef<'_>) -> Result<Self::PublicKey<'_>, Error> {
        self.ec_point(key)
    }

    fn generate_secret_key(&self) -> Result<Self::SecretKey<'_>, Error> {
        self.generate_ec_scalar() // TODO: Should be non-zero
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
        let uint = openssl_unwrap!(BigNum::from_slice(uint.access()));

        Ok(uint)
    }

    fn ec_scalar(&self, scalar: super::CanonEcScalarRef<'_>) -> Result<Self::EcScalar<'_>, Error> {
        let scalar = openssl_unwrap!(BigNum::from_slice(scalar.access()));

        Ok(Self::EcScalar {
            group: &self.ec_group,
            scalar,
        })
    }

    fn generate_ec_scalar(&self) -> Result<Self::EcScalar<'_>, Error> {
        let mut ctx = openssl_unwrap!(BigNumContext::new());
        let mut order = openssl_unwrap!(BigNum::new());
        openssl_unwrap!(self.ec_group.group.order(&mut order, &mut ctx));

        let mut scalar = openssl_unwrap!(BigNum::new());
        openssl_unwrap!(order.rand_range(&mut scalar));

        Ok(Self::EcScalar {
            group: &self.ec_group,
            scalar,
        })
    }

    fn ec_point(&self, point: super::CanonEcPointRef<'_>) -> Result<Self::EcPoint<'_>, Error> {
        let mut ctx = openssl_unwrap!(BigNumContext::new());

        let point = openssl_unwrap!(EcPoint::from_bytes(
            &self.ec_group.group,
            point.access(),
            &mut ctx
        ));

        Ok(Self::EcPoint {
            group: &self.ec_group,
            point,
        })
    }

    fn ec_generator_point(&self) -> Result<Self::EcPoint<'_>, Error> {
        let point = openssl_unwrap!(self
            .ec_group
            .group
            .generator()
            .to_owned(&self.ec_group.group));

        Ok(Self::EcPoint {
            group: &self.ec_group,
            point,
        })
    }
}

/// A cryptographically secure random number generator using OpenSSL
#[derive(Copy, Clone)]
pub struct Rand(());

impl RngCore for Rand {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        openssl::rand::rand_bytes(dest).unwrap();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);

        Ok(())
    }
}

impl CryptoRng for Rand {}

/// A hash implementation
#[derive(Clone)]
pub struct Hash<const HASH_LEN: usize>(Hasher);

impl<const HASH_LEN: usize> Hash<HASH_LEN> {
    /// Create a new hash instance
    ///
    /// # Arguments
    /// - `md`: The message digest algorithm to use
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that the
    /// `md` parameter corresponds to the `HASH_LEN` generic parameter.
    unsafe fn new(md: MessageDigest) -> Result<Self, Error> {
        Ok(Self(openssl_unwrap!(Hasher::new(md))))
    }
}

impl<const HASH_LEN: usize> super::Digest<HASH_LEN> for Hash<HASH_LEN> {
    fn update(&mut self, data: &[u8]) {
        openssl_unwrap!(self.0.update(data));
    }

    fn finish(mut self, hash: &mut CryptoSensitive<HASH_LEN>) {
        let digest = openssl_unwrap!(self.0.finish());
        hash.access_mut().copy_from_slice(digest.as_ref());
    }
}

/// An HMAC-SHA256 implementation
#[derive(Clone)]
pub struct HmacSha256(Hmac<sha2::Sha256>);

impl HmacSha256 {
    /// Create a new HMAC-SHA256 instance
    fn new(key: &[u8]) -> Self {
        Self(openssl_unwrap!(Hmac::<sha2::Sha256>::new_from_slice(key)))
    }
}

impl super::Digest<{ super::HASH_LEN }> for HmacSha256 {
    fn update(&mut self, data: &[u8]) {
        Mac::update(&mut self.0, data);
    }

    fn finish(self, hash: &mut CryptoSensitive<{ super::HASH_LEN }>) {
        hash.access_mut()
            .copy_from_slice(self.0.finalize().into_bytes().as_slice());
    }
}

/// An HKDF implementation
pub struct Hkdf(&'static MdRef);

impl Hkdf {
    /// Create a new HKDF instance
    fn new(md: &'static MdRef) -> Self {
        Self(md)
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
        let mut ctx = openssl_unwrap!(PkeyCtx::new_id(Id::HKDF));

        openssl_unwrap!(ctx.derive_init());

        openssl_unwrap!(ctx.set_hkdf_md(self.0));
        openssl_unwrap!(ctx.set_hkdf_key(ikm.access()));

        if !salt.is_empty() {
            openssl_unwrap!(ctx.set_hkdf_salt(salt));
        }

        openssl_unwrap!(ctx.add_hkdf_info(info));
        openssl_unwrap!(ctx.derive(Some(key.access_mut())));

        Ok(())
    }
}

/// A PBKDF2-HMAC implementation
pub struct Pbkdf2Hmac(MessageDigest);

impl Pbkdf2Hmac {
    /// Create a new PBKDF2-HMAC instance
    fn new(md: MessageDigest) -> Self {
        Self(md)
    }
}

impl super::PbKdf for Pbkdf2Hmac {
    fn derive<const PASS_LEN: usize, const KEY_LEN: usize>(
        self,
        pass: CryptoSensitiveRef<'_, PASS_LEN>,
        iter: usize,
        salt: &[u8],
        key: &mut CryptoSensitive<KEY_LEN>,
    ) {
        openssl_unwrap!(openssl::pkcs5::pbkdf2_hmac(
            pass.access(),
            salt,
            iter,
            self.0,
            key.access_mut()
        ));
    }
}

/// An AEAD implementation
pub struct Aead<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>(
    &'static CipherRef,
);

impl<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>
    Aead<KEY_LEN, NONCE_LEN, TAG_LEN>
{
    /// Create a new AEAD instance
    ///
    /// # Arguments
    /// - `cipher`: The cipher to use
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that the
    /// `cipher` parameter corresponds to the `KEY_LEN`, `NONCE_LEN` and `TAG_LEN` generic parameters.
    unsafe fn new(cipher: &'static CipherRef) -> Self {
        Self(cipher)
    }
}

impl<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>
    super::Aead<KEY_LEN, NONCE_LEN> for Aead<KEY_LEN, NONCE_LEN, TAG_LEN>
{
    fn encrypt_in_place<'a>(
        &mut self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
        nonce: CryptoSensitiveRef<'_, NONCE_LEN>,
        aad: &[u8],
        data: &'a mut [u8],
        data_len: usize,
    ) -> Result<&'a [u8], Error> {
        // Most of the initialization stuff adapted from here:
        // https://wiki.openssl.org/images/e/e1/Evp-ccm-encrypt.c

        assert!(data_len + TAG_LEN <= data.len());

        let mut ctx = openssl_unwrap!(CipherCtx::new());

        openssl_unwrap!(ctx.encrypt_init(Some(self.0), None, None));
        openssl_unwrap!(ctx.set_key_length(KEY_LEN));
        openssl_unwrap!(ctx.set_iv_length(NONCE_LEN));
        openssl_unwrap!(ctx.set_tag_length(TAG_LEN));
        openssl_unwrap!(ctx.encrypt_init(None, Some(key.access()), Some(nonce.access())));

        openssl_unwrap!(ctx.set_data_len(data_len));

        openssl_unwrap!(ctx.cipher_update(aad, None));

        let mut encrypted_data_len = openssl_unwrap!(ctx.cipher_update_inplace(data, data_len));
        encrypted_data_len += openssl_unwrap!(ctx.cipher_final(&mut data[encrypted_data_len..]));

        openssl_unwrap!(ctx.tag(&mut data[encrypted_data_len..encrypted_data_len + TAG_LEN]));

        Ok(&data[..encrypted_data_len + TAG_LEN])
    }

    fn decrypt_in_place<'a>(
        &mut self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
        nonce: CryptoSensitiveRef<'_, NONCE_LEN>,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        // Most of the initialization stuff adapted from here:
        // https://wiki.openssl.org/images/e/e1/Evp-ccm-encrypt.c

        assert!(data.len() >= TAG_LEN);

        let (data, tag) = data.split_at_mut(data.len() - TAG_LEN);

        let mut ctx = openssl_unwrap!(CipherCtx::new());

        openssl_unwrap!(ctx.decrypt_init(Some(self.0), None, None));
        openssl_unwrap!(ctx.set_key_length(KEY_LEN));
        openssl_unwrap!(ctx.set_iv_length(NONCE_LEN));
        openssl_unwrap!(ctx.set_tag_length(TAG_LEN));
        openssl_unwrap!(ctx.set_tag(tag));

        openssl_unwrap!(ctx.decrypt_init(None, Some(key.access()), Some(nonce.access())));

        openssl_unwrap!(ctx.set_data_len(data.len()));

        openssl_unwrap!(ctx.cipher_update(aad, None));

        let mut decrypted_data_len = openssl_unwrap!(ctx.cipher_update_inplace(data, data.len()));
        decrypted_data_len += openssl_unwrap!(ctx.cipher_final(&mut data[decrypted_data_len..]));

        Ok(&data[..decrypted_data_len])
    }
}

impl<'a, const LEN: usize> super::UInt<'a, LEN> for BigNum {
    fn rem(&self, other: &Self) -> Option<Self> {
        let mut ctx = openssl_unwrap!(BigNumContext::new());

        let mut result = openssl_unwrap!(BigNum::new());

        if result.checked_rem(self, other, &mut ctx).is_ok() {
            Some(result)
        } else {
            None
        }
    }

    fn write_canon(&self, uint: &mut CryptoSensitive<LEN>) {
        uint.access_mut()
            .copy_from_slice(openssl_unwrap!(self.to_vec_padded(LEN as _)).as_slice());
    }
}

/// Elliptic curve group implementation using OpenSSL
pub struct ECGroup<const LEN: usize, const SCALAR_LEN: usize> {
    /// The underlying OpenSSL EC group
    group: EcGroup,
}

impl<const LEN: usize, const SCALAR_LEN: usize> ECGroup<LEN, SCALAR_LEN> {
    /// Create a new EC group instance
    ///
    /// # Arguments
    /// - `nid`: The OpenSSL NID of the curve to use
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that the
    /// `nid` parameter corresponds to the `LEN` and `SCALAR_LEN` generic parameters.
    unsafe fn new(nid: Nid) -> Result<Self, Error> {
        let group = openssl_unwrap!(EcGroup::from_curve_name(nid));

        Ok(Self { group })
    }
}

/// An EC point implementation using OpenSSL
pub struct ECPoint<'a, const LEN: usize, const SCALAR_LEN: usize> {
    /// The associated EC group
    group: &'a ECGroup<LEN, SCALAR_LEN>,
    /// The underlying OpenSSL EC point
    point: EcPoint,
}

impl<const LEN: usize, const SCALAR_LEN: usize> ECPoint<'_, LEN, SCALAR_LEN> {
    /// Compute the OpenSSL EC key corresponding to this point
    fn ec_key(&self) -> EcKey<Public> {
        openssl_unwrap!(EcKey::from_public_key(&self.group.group, &self.point))
    }

    /// Write the point in canonical form
    fn write(&self, point: &mut CryptoSensitive<LEN>) {
        let mut ctx = openssl_unwrap!(BigNumContext::new());

        let tmp = openssl_unwrap!(self.point.to_bytes(
            &self.group.group,
            PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        ));

        point.access_mut().copy_from_slice(tmp.as_slice());
    }
}

impl<'a, const LEN: usize, const SCALAR_LEN: usize> super::EcPoint<'a, LEN, SCALAR_LEN>
    for ECPoint<'a, LEN, SCALAR_LEN>
{
    type Scalar<'s>
        = ECScalar<'s, SCALAR_LEN, LEN>
    where
        Self: 'a + 's;

    fn neg(&self) -> Self {
        let mut result = openssl_unwrap!(self.point.to_owned(&self.group.group));

        let ctx = openssl_unwrap!(BigNumContext::new());
        openssl_unwrap!(result.invert(&self.group.group, &ctx));

        Self {
            group: self.group,
            point: result,
        }
    }

    fn mul(&self, scalar: &Self::Scalar<'a>) -> Self {
        let mut result = openssl_unwrap!(EcPoint::new(&self.group.group));

        let ctx = openssl_unwrap!(BigNumContext::new());

        openssl_unwrap!(result.mul(&self.group.group, &self.point, &scalar.scalar, &ctx));

        Self {
            group: self.group,
            point: result,
        }
    }

    fn add_mul(&self, s1: &Self::Scalar<'a>, p2: &Self, s2: &Self::Scalar<'a>) -> Self {
        let a = self.mul(s1);
        let b = p2.mul(s2);

        let mut ctx = openssl_unwrap!(BigNumContext::new());

        let mut result = openssl_unwrap!(EcPoint::new(&self.group.group));

        openssl_unwrap!(result.add(&self.group.group, &a.point, &b.point, &mut ctx));

        Self {
            group: self.group,
            point: result,
        }
    }

    fn write_canon(&self, point: &mut CryptoSensitive<LEN>) {
        self.write(point);
    }
}

impl<'a, const KEY_LEN: usize, const SECRET_KEY_LEN: usize, const SIGNATURE_LEN: usize>
    super::PublicKey<'a, KEY_LEN, SIGNATURE_LEN> for ECPoint<'a, KEY_LEN, SECRET_KEY_LEN>
{
    fn verify(&self, data: &[u8], signature: CryptoSensitiveRef<'_, SIGNATURE_LEN>) -> bool {
        // First get the SHA256 of the message
        let mut hasher = openssl_unwrap!(Hasher::new(MessageDigest::sha256()));
        openssl_unwrap!(hasher.update(data));
        let digest = openssl_unwrap!(hasher.finish());

        let r = openssl_unwrap!(BigNum::from_slice(&signature.access()[..SIGNATURE_LEN / 2]));
        let s = openssl_unwrap!(BigNum::from_slice(&signature.access()[SIGNATURE_LEN / 2..]));
        let sig = openssl_unwrap!(EcdsaSig::from_private_components(r, s));

        let ec_key = openssl_unwrap!(EcKey::from_public_key(&self.group.group, &self.point));

        openssl_unwrap!(sig.verify(&digest, &ec_key))
    }

    fn write_canon(&self, key: &mut CryptoSensitive<KEY_LEN>) {
        self.write(key);
    }
}

/// An EC scalar implementation using OpenSSL
pub struct ECScalar<'a, const LEN: usize, const POINT_LEN: usize> {
    /// The associated EC group
    group: &'a ECGroup<POINT_LEN, LEN>,
    /// The underlying OpenSSL big number scalar
    scalar: BigNum,
}

impl<const LEN: usize, const POINT_LEN: usize> ECScalar<'_, LEN, POINT_LEN> {
    /// Compute the OpenSSL EC point corresponding to this scalar
    fn ec_pub_key_point(&self) -> EcPoint {
        let ctx = openssl_unwrap!(BigNumContext::new());

        let mut point = openssl_unwrap!(EcPoint::new(&self.group.group));

        openssl_unwrap!(point.mul(
            &self.group.group,
            self.group.group.generator(),
            &self.scalar,
            &ctx,
        ));

        point
    }

    /// Compute the OpenSSL EC key corresponding to this scalar
    fn ec_key(&self) -> EcKey<Private> {
        openssl_unwrap!(EcKey::from_private_components(
            &self.group.group,
            &self.scalar,
            &self.ec_pub_key_point()
        ))
    }

    /// Write the scalar in canonical form
    fn write(&self, scalar: &mut CryptoSensitive<LEN>) {
        scalar
            .access_mut()
            .copy_from_slice(openssl_unwrap!(self.scalar.to_vec_padded(LEN as _)).as_slice());
    }
}

impl<'a, const LEN: usize, const POINT_LEN: usize> super::EcScalar<'a, LEN>
    for ECScalar<'a, LEN, POINT_LEN>
{
    fn mul(&self, other: &Self) -> Self {
        Self {
            group: self.group,
            scalar: self.scalar.mul(&other.scalar),
        }
    }

    fn write_canon(&self, scalar: &mut CryptoSensitive<LEN>) {
        self.write(scalar);
    }
}

impl<'a, const LEN: usize, const POINT_LEN: usize, const SIGNATURE_LEN: usize>
    super::SigningSecretKey<'a, POINT_LEN, SIGNATURE_LEN> for ECScalar<'a, LEN, POINT_LEN>
{
    type PublicKey<'s>
        = ECPoint<'s, POINT_LEN, LEN>
    where
        Self: 's;

    fn csr<'s>(&self, buf: &'s mut [u8]) -> Result<&'s [u8], Error> {
        let mut builder = openssl_unwrap!(X509ReqBuilder::new());
        openssl_unwrap!(builder.set_version(0));

        let pkey = openssl_unwrap!(PKey::from_ec_key(self.ec_key()));
        openssl_unwrap!(builder.set_pubkey(&pkey));

        let mut name_builder = openssl_unwrap!(X509NameBuilder::new());
        openssl_unwrap!(name_builder.append_entry_by_text_with_type(
            "O",
            "CSR",
            Asn1Type::IA5STRING
        ));
        let subject_name = name_builder.build();
        openssl_unwrap!(builder.set_subject_name(&subject_name));

        openssl_unwrap!(builder.sign(&pkey, MessageDigest::sha256()));

        let csr = openssl_unwrap!(builder.build().to_der());
        if buf.len() <= csr.len() {
            buf[..csr.len()].copy_from_slice(csr.as_slice());

            Ok(&buf[..csr.len()])
        } else {
            Err(ErrorCode::NoSpace.into())
        }
    }

    fn pub_key(&self) -> Self::PublicKey<'a> {
        let ctx = openssl_unwrap!(BigNumContext::new());

        let mut pub_key = Self::PublicKey {
            group: self.group,
            point: openssl_unwrap!(EcPoint::new(&self.group.group)),
        };

        openssl_unwrap!(pub_key.point.mul(
            &self.group.group,
            self.group.group.generator(),
            &self.scalar,
            &ctx,
        ));

        pub_key
    }

    fn sign(&self, data: &[u8], signature: &mut CryptoSensitive<SIGNATURE_LEN>) {
        // First get the SHA256 of the message
        let mut hasher = openssl_unwrap!(Hasher::new(MessageDigest::sha256()));
        openssl_unwrap!(hasher.update(data));
        let digest = openssl_unwrap!(hasher.finish());

        let our_ec_key = self.ec_key();

        let sig = openssl_unwrap!(EcdsaSig::sign(&digest, &our_ec_key));

        signature.access_mut()[..super::PKC_SHARED_SECRET_LEN / 2]
            .copy_from_slice(sig.r().to_vec().as_slice());
        signature.access_mut()[super::PKC_SHARED_SECRET_LEN / 2..]
            .copy_from_slice(sig.s().to_vec().as_slice());
    }
}

impl<
        'a,
        const LEN: usize,
        const POINT_LEN: usize,
        const SIGNATURE_LEN: usize,
        const SHARED_SECRET_LEN: usize,
    > super::SecretKey<'a, LEN, POINT_LEN, SIGNATURE_LEN, SHARED_SECRET_LEN>
    for ECScalar<'a, LEN, POINT_LEN>
{
    fn derive_shared_secret(
        &self,
        peer_pub_key: &Self::PublicKey<'a>,
        shared_secret: &mut CryptoSensitive<SHARED_SECRET_LEN>,
    ) {
        let our_priv_key = openssl_unwrap!(PKey::from_ec_key(self.ec_key()));
        let peer_pub_key = openssl_unwrap!(PKey::from_ec_key(peer_pub_key.ec_key()));

        let mut deriver = openssl_unwrap!(Deriver::new(&our_priv_key));

        openssl_unwrap!(deriver.set_peer(&peer_pub_key));
        openssl_unwrap!(deriver.derive(shared_secret.access_mut()));
    }

    fn write_canon(&self, key: &mut CryptoSensitive<LEN>) {
        self.write(key);
    }
}

// const P256_KEY_LEN: usize = 256 / 8;
// pub fn pubkey_from_der(der: &[u8], out_key: &mut [u8]) -> Result<(), Error> {
//     if out_key.len() != P256_KEY_LEN {
//         error!("Insufficient length");
//         Err(ErrorCode::NoSpace.into())
//     } else {
//         let key = X509::from_der(der)?.public_key()?.public_key_to_der()?;
//         let len = key.len();
//         let out_key = &mut out_key[..len];
//         out_key.copy_from_slice(key.as_slice());
//         Ok(())
//     }
// }
