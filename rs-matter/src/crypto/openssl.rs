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

use core::borrow::Borrow;
use core::ops::Mul;

use crate::crypto::CanonPkcSecretKey;
use crate::error::{Error, ErrorCode};

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

/// An OpenSSL-based crypto backend
pub struct OpenSslCrypto<S> {
    /// Elliptic curve group (secp256r1)
    ec_group: ECGroup<{ super::EC_CANON_POINT_LEN }, { super::EC_CANON_SCALAR_LEN }>,
    /// The singleton secret key to be returned by `Crypto::singleton_singing_secret_key`
    singleton_secret_key: S,
}

impl<S> OpenSslCrypto<S> {
    /// Create a new OpenSSL crypto backend
    ///
    /// # Arguments
    /// - `singleton_secret_key` - A singleton secret key to be returned by `Crypto::singleton_singing_secret_key`
    ///   The primary use-case for this secret key is to be used as the secret key for the Device Attestation credentials
    pub fn new(singleton_secret_key: S) -> Self {
        Self {
            ec_group: unsafe { ECGroup::new(Nid::X9_62_PRIME256V1).unwrap() },
            singleton_secret_key,
        }
    }
}

impl<S> super::Crypto for OpenSslCrypto<S>
where
    S: Borrow<CanonPkcSecretKey>,
{
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

    type UInt384<'a>
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

    fn hash(&self) -> Result<Self::Hash<'_>, Error> {
        unsafe { Hash::new(MessageDigest::sha256()) }
    }

    fn hmac(&self, key: &[u8]) -> Result<Self::Hmac<'_>, Error> {
        Ok(HmacSha256::new(key))
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

    fn pub_key(&self, key: &super::CanonPkcPublicKey) -> Result<Self::PublicKey<'_>, Error> {
        self.ec_point(key)
    }

    fn generate_secret_key(&self) -> Result<Self::SecretKey<'_>, Error> {
        self.generate_ec_scalar() // TODO: Should be non-zero
    }

    fn secret_key(&self, key: &super::CanonPkcSecretKey) -> Result<Self::SecretKey<'_>, Error> {
        self.ec_scalar(key)
    }

    fn singleton_singing_secret_key(&self) -> Result<Self::SigningSecretKey<'_>, Error> {
        self.ec_scalar(self.singleton_secret_key.borrow())
    }

    fn uint384(&self, uint: &super::CanonUint384) -> Result<Self::UInt384<'_>, Error> {
        let uint = BigNum::from_slice(uint)?;

        Ok(uint)
    }

    fn ec_scalar(&self, scalar: &super::CanonEcScalar) -> Result<Self::EcScalar<'_>, Error> {
        let scalar = BigNum::from_slice(scalar)?;

        Ok(Self::EcScalar {
            group: &self.ec_group,
            scalar,
        })
    }

    fn generate_ec_scalar(&self) -> Result<Self::EcScalar<'_>, Error> {
        let mut ctx = BigNumContext::new()?;
        let mut order = BigNum::new()?;
        self.ec_group.group.order(&mut order, &mut ctx)?;

        let mut scalar = BigNum::new()?;
        order.rand_range(&mut scalar)?;

        Ok(Self::EcScalar {
            group: &self.ec_group,
            scalar,
        })
    }

    fn ec_point(&self, point: &super::CanonEcPoint) -> Result<Self::EcPoint<'_>, Error> {
        let mut ctx = BigNumContext::new()?;

        let point = EcPoint::from_bytes(&self.ec_group.group, point, &mut ctx)?;

        Ok(Self::EcPoint {
            group: &self.ec_group,
            point,
        })
    }

    fn ec_generator_point(&self) -> Result<Self::EcPoint<'_>, Error> {
        Ok(Self::EcPoint {
            group: &self.ec_group,
            point: self
                .ec_group
                .group
                .generator()
                .to_owned(&self.ec_group.group)?,
        })
    }
}

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
        Ok(Self(Hasher::new(md)?))
    }
}

impl<const HASH_LEN: usize> super::Digest<HASH_LEN> for Hash<HASH_LEN> {
    fn update(&mut self, data: &[u8]) {
        unwrap!(self.0.update(data));
    }

    fn finish(mut self, hash: &mut [u8; HASH_LEN]) {
        let digest = unwrap!(self.0.finish());
        hash.copy_from_slice(digest.as_ref());
    }
}

/// An HMAC-SHA256 implementation
#[derive(Clone)]
pub struct HmacSha256(Hmac<sha2::Sha256>);

impl HmacSha256 {
    /// Create a new HMAC-SHA256 instance
    fn new(key: &[u8]) -> Self {
        Self(Hmac::<sha2::Sha256>::new_from_slice(key).unwrap())
    }
}

impl super::Digest<{ super::HASH_LEN }> for HmacSha256 {
    fn update(&mut self, data: &[u8]) {
        Mac::update(&mut self.0, data);
    }

    fn finish(self, hash: &mut [u8; super::HASH_LEN]) {
        hash.copy_from_slice(self.0.finalize().into_bytes().as_slice());
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
    fn expand(self, salt: &[u8], ikm: &[u8], info: &[u8], key: &mut [u8]) -> Result<(), ()> {
        let mut ctx = PkeyCtx::new_id(Id::HKDF).unwrap();

        ctx.derive_init().unwrap();

        ctx.set_hkdf_md(self.0).unwrap();
        ctx.set_hkdf_key(ikm).unwrap();

        if !salt.is_empty() {
            ctx.set_hkdf_salt(salt).unwrap();
        }

        ctx.add_hkdf_info(info).unwrap();

        ctx.derive(Some(key)).unwrap();

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
    fn derive(self, pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) {
        openssl::pkcs5::pbkdf2_hmac(pass, salt, iter, self.0, key).unwrap();
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
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &'a mut [u8],
        data_len: usize,
    ) -> Result<&'a [u8], Error> {
        assert!(data_len + TAG_LEN <= data.len());

        let mut ctx = CipherCtx::new()?;

        ctx.encrypt_init(Some(self.0), Some(key), Some(nonce))?;
        //ctx.set_key_length(KEY_LEN)?;
        //ctx.set_iv_length(NONCE_LEN)?;
        ctx.set_tag_length(TAG_LEN)?;
        ctx.set_data_len(data_len)?;

        let mut encrypted_data_len = ctx.cipher_update(aad, None)?;

        encrypted_data_len += ctx.cipher_update_inplace(data, data_len)?;
        encrypted_data_len += ctx.cipher_final(&mut data[encrypted_data_len..])?;

        ctx.tag(&mut data[encrypted_data_len..])?;

        Ok(&data[..encrypted_data_len + TAG_LEN])
    }

    fn decrypt_in_place<'a>(
        &mut self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        assert!(data.len() >= TAG_LEN);

        let (data, tag) = data.split_at_mut(data.len() - TAG_LEN);

        let mut ctx = CipherCtx::new()?;

        ctx.decrypt_init(Some(self.0), Some(key), Some(nonce))?;
        //ctx.set_key_length(KEY_LEN)?;
        //ctx.set_iv_length(NONCE_LEN)?;
        ctx.set_tag(tag)?;
        ctx.set_data_len(data.len())?;

        let mut decrypted_data_len = ctx.cipher_update(aad, None)?;

        decrypted_data_len += ctx.cipher_update_inplace(data, data.len())?;
        decrypted_data_len += ctx.cipher_final(&mut data[decrypted_data_len..])?;

        Ok(&data[..decrypted_data_len])
    }
}

impl<'a, const LEN: usize> super::UInt<'a, LEN> for BigNum {
    fn rem(&self, other: &Self) -> Option<Self> {
        let mut ctx = BigNumContext::new().unwrap();

        let mut result = BigNum::new().unwrap();

        if result.checked_rem(self, other, &mut ctx).is_ok() {
            Some(result)
        } else {
            None
        }
    }

    fn write_canon(&self, uint: &mut [u8; LEN]) {
        uint.copy_from_slice(self.to_vec_padded(LEN as _).unwrap().as_slice());
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
        let group = EcGroup::from_curve_name(nid)?;

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
        EcKey::from_public_key(&self.group.group, &self.point).unwrap()
    }

    /// Write the point in canonical form
    fn write(&self, point: &mut [u8; LEN]) {
        let mut ctx = BigNumContext::new().unwrap();

        let tmp = self
            .point
            .to_bytes(
                &self.group.group,
                PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap();

        point.copy_from_slice(tmp.as_slice());
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
        let mut result = self.point.to_owned(&self.group.group).unwrap();

        let ctx = BigNumContext::new().unwrap();
        result.invert(&self.group.group, &ctx).unwrap();

        Self {
            group: self.group,
            point: result,
        }
    }

    fn mul(&self, scalar: &Self::Scalar<'a>) -> Self {
        let mut result = EcPoint::new(&self.group.group).unwrap();

        let ctx = BigNumContext::new().unwrap();

        result
            .mul(&self.group.group, &self.point, &scalar.scalar, &ctx)
            .unwrap();

        Self {
            group: self.group,
            point: result,
        }
    }

    fn add_mul(&self, s1: &Self::Scalar<'a>, p2: &Self, s2: &Self::Scalar<'a>) -> Self {
        let a = self.mul(s1);
        let b = p2.mul(s2);

        let mut ctx = BigNumContext::new().unwrap();

        let mut result = EcPoint::new(&self.group.group).unwrap();

        result
            .add(&self.group.group, &a.point, &b.point, &mut ctx)
            .unwrap();

        Self {
            group: self.group,
            point: result,
        }
    }

    fn write_canon(&self, point: &mut [u8; LEN]) {
        self.write(point);
    }
}

impl<'a, const KEY_LEN: usize, const SECRET_KEY_LEN: usize, const SIGNATURE_LEN: usize>
    super::PublicKey<'a, KEY_LEN, SIGNATURE_LEN> for ECPoint<'a, KEY_LEN, SECRET_KEY_LEN>
{
    fn verify(&self, data: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
        // First get the SHA256 of the message
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        hasher.update(data).unwrap();
        let digest = hasher.finish().unwrap();

        let r = BigNum::from_slice(&signature[..SIGNATURE_LEN / 2]).unwrap();
        let s = BigNum::from_slice(&signature[SIGNATURE_LEN / 2..]).unwrap();
        let sig = EcdsaSig::from_private_components(r, s).unwrap();

        let ec_key = EcKey::from_public_key(&self.group.group, &self.point).unwrap();

        sig.verify(&digest, &ec_key).unwrap()
    }

    fn write_canon(&self, key: &mut [u8; KEY_LEN]) {
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
        let ctx = BigNumContext::new().unwrap();

        let mut point = EcPoint::new(&self.group.group).unwrap();

        point
            .mul(
                &self.group.group,
                self.group.group.generator(),
                &self.scalar,
                &ctx,
            )
            .unwrap();

        point
    }

    /// Compute the OpenSSL EC key corresponding to this scalar
    fn ec_key(&self) -> EcKey<Private> {
        EcKey::from_private_components(&self.group.group, &self.scalar, &self.ec_pub_key_point())
            .unwrap()
    }

    /// Write the scalar in canonical form
    fn write(&self, scalar: &mut [u8; LEN]) {
        scalar.copy_from_slice(self.scalar.to_vec_padded(LEN as _).unwrap().as_slice());
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

    fn write_canon(&self, scalar: &mut [u8; LEN]) {
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
        let mut builder = X509ReqBuilder::new()?;
        builder.set_version(0)?;

        let pkey = PKey::from_ec_key(self.ec_key())?;
        builder.set_pubkey(&pkey)?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text_with_type("O", "CSR", Asn1Type::IA5STRING)?;
        let subject_name = name_builder.build();
        builder.set_subject_name(&subject_name)?;

        builder.sign(&pkey, MessageDigest::sha256())?;

        let csr = builder.build().to_der()?;
        if buf.len() <= csr.len() {
            buf[..csr.len()].copy_from_slice(csr.as_slice());

            Ok(&buf[..csr.len()])
        } else {
            Err(ErrorCode::NoSpace.into())
        }
    }

    fn pub_key(&self) -> Self::PublicKey<'a> {
        let ctx = BigNumContext::new().unwrap();

        let mut pub_key = Self::PublicKey {
            group: self.group,
            point: EcPoint::new(&self.group.group).unwrap(),
        };

        pub_key
            .point
            .mul(
                &self.group.group,
                self.group.group.generator(),
                &self.scalar,
                &ctx,
            )
            .unwrap();

        pub_key
    }

    fn sign(&self, data: &[u8], signature: &mut [u8; SIGNATURE_LEN]) {
        // First get the SHA256 of the message
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        hasher.update(data).unwrap();
        let digest = hasher.finish().unwrap();

        let our_ec_key = self.ec_key();

        let sig = EcdsaSig::sign(&digest, &our_ec_key).unwrap();

        signature[..super::PKC_SHARED_SECRET_LEN / 2].copy_from_slice(sig.r().to_vec().as_slice());
        signature[super::PKC_SHARED_SECRET_LEN / 2..].copy_from_slice(sig.s().to_vec().as_slice());
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
    fn write_canon(&self, key: &mut [u8; LEN]) {
        self.write(key);
    }

    fn derive_shared_secret(
        &self,
        peer_pub_key: &Self::PublicKey<'a>,
        shared_secret: &mut [u8; SHARED_SECRET_LEN],
    ) {
        let our_priv_key = PKey::from_ec_key(self.ec_key()).unwrap();
        let peer_pub_key = PKey::from_ec_key(peer_pub_key.ec_key()).unwrap();

        let mut deriver = Deriver::new(&our_priv_key).unwrap();

        deriver.set_peer(&peer_pub_key).unwrap();
        deriver.derive(shared_secret).unwrap();
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
