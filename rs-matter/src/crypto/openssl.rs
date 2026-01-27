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

#![allow(deprecated)] // Remove this once `hmac` updates to `generic-array` 1.x

use core::ops::Mul;

use crate::error::{Error, ErrorCode};

use openssl::asn1::Asn1Type;
use openssl::bn::{BigNum, BigNumContext};
use openssl::cipher_ctx::CipherCtx;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{Hasher, MessageDigest};
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::{self, Id, PKey};
use openssl::pkey_ctx::PkeyCtx;
use openssl::x509::{X509NameBuilder, X509ReqBuilder};

// We directly use the hmac crate here, there was a self-referential structure
// problem while using OpenSSL's Signer
// TODO: Use proper OpenSSL method for this
use hmac::{Hmac, Mac};

extern crate alloc;

pub struct OpenSslCrypto {
    ec_group: EcGroup,
}

impl OpenSslCrypto {
    pub fn new() -> Self {
        Self {
            ec_group: EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(),
        }
    }
}

impl super::Crypto for OpenSslCrypto {
    type Sha256<'a>
        = Sha256
    where
        Self: 'a;

    type HmacSha256<'a>
        = HmacSha256
    where
        Self: 'a;

    type HkdfSha256<'a>
        = HkdfFactory
    where
        Self: 'a;

    type Pbkdf2HmacSha256<'a>
        = Pbkdf2HmacFactory
    where
        Self: 'a;

    type AesCcm16p64p128<'a>
        = Aes128Ccm1613
    where
        Self: 'a;

    type Secp256r1PublicKey<'a>
        = ECPublicKey<'a>
    where
        Self: 'a;

    type Secp256r1SecretKey<'a>
        = ECPrivateKey<'a>
    where
        Self: 'a;

    type UInt384<'a>
        = BigNum
    where
        Self: 'a;

    type Secp256r1Scalar<'a>
        = ECScalar
    where
        Self: 'a;

    type Secp256r1Point<'a>
        = ECPoint<'a>
    where
        Self: 'a;

    fn sha256(&self) -> Result<Self::Sha256<'_>, Error> {
        Ok(Sha256(Hasher::new(MessageDigest::sha256())?))
    }

    fn hmac_sha256(&self, key: &[u8]) -> Result<Self::HmacSha256<'_>, Error> {
        Ok(HmacSha256 {
            ctx: Hmac::<sha2::Sha256>::new_from_slice(key)
                .map_err(|_x| ErrorCode::InvalidKeyLength)?,
        })
    }

    fn hkdf_sha256(&self) -> Result<Self::HkdfSha256<'_>, Error> {
        Ok(HkdfFactory(()))
    }

    fn pbkdf2_hmac_sha256(&self) -> Result<Self::Pbkdf2HmacSha256<'_>, Error> {
        Ok(Pbkdf2HmacFactory(()))
    }

    fn aes_ccm_16_64_128(&self) -> Result<Self::AesCcm16p64p128<'_>, Error> {
        Ok(Aes128Ccm1613)
    }

    fn secp256r1_pub_key(
        &self,
        key: &super::CanonSecp256r1PublicKey,
    ) -> Result<Self::Secp256r1PublicKey<'_>, Error> {
        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&self.ec_group, key, &mut ctx)?;
        let key = EcKey::from_public_key(&self.ec_group, &point)?;
        Ok(Self::Secp256r1PublicKey { crypto: self, key })
    }

    fn secp256r1_secret_key_random(&self) -> Result<Self::Secp256r1SecretKey<'_>, Error> {
        let key = EcKey::generate(&self.ec_group)?;
        Ok(Self::Secp256r1SecretKey { crypto: self, key })
    }

    fn secp256r1_secret_key(
        &self,
        key: &super::CanonSecp256r1SecretKey,
    ) -> Result<Self::Secp256r1SecretKey<'_>, Error> {
        let priv_key = BigNum::from_slice(key)?;

        let mut ctx = BigNumContext::new()?;
        let mut pub_key = EcPoint::new(&self.ec_group)?;
        pub_key.mul(
            &self.ec_group,
            self.ec_group.generator(),
            &priv_key,
            &mut ctx,
        )?;

        let ec_key = EcKey::from_private_components(&self.ec_group, &priv_key, &pub_key)?;
        Ok(Self::Secp256r1SecretKey {
            crypto: self,
            key: ec_key,
        })
    }

    fn uint384(&self, uint: &super::CanonUint384) -> Result<Self::UInt384<'_>, Error> {
        let bn = BigNum::from_slice(uint)?;
        Ok(bn)
    }

    fn secp256r1_scalar(
        &self,
        scalar: &super::CanonSecp256r1Scalar,
    ) -> Result<Self::Secp256r1Scalar<'_>, Error> {
        let bn = BigNum::from_slice(scalar)?;
        Ok(ECScalar(bn))
    }

    fn secp256r1_scalar_random(&self) -> Result<Self::Secp256r1Scalar<'_>, Error> {
        let mut ctx = BigNumContext::new()?;
        let mut order = BigNum::new()?;
        self.ec_group.order(&mut order, &mut ctx)?;
        let mut bn = BigNum::new()?;
        order.rand_range(&mut bn)?;
        Ok(ECScalar(bn))
    }

    fn secp256r1_point(
        &self,
        point: &super::CanonSecp256r1Point,
    ) -> Result<Self::Secp256r1Point<'_>, Error> {
        let mut ctx = BigNumContext::new()?;
        let ec_point = EcPoint::from_bytes(&self.ec_group, point, &mut ctx)?;
        Ok(Self::Secp256r1Point {
            crypto: self,
            point: ec_point,
        })
    }

    fn secp256r1_generator(&self) -> Result<Self::Secp256r1Point<'_>, Error> {
        Ok(Self::Secp256r1Point {
            crypto: self,
            point: self.ec_group.generator().to_owned(&self.ec_group)?,
        })
    }
}

#[derive(Clone)]
pub struct Sha256(Hasher);

impl super::Digest<{ super::SHA256_HASH_LEN }> for Sha256 {
    fn update(&mut self, data: &[u8]) {
        unwrap!(self.0.update(data));
    }

    fn finish(mut self, hash: &mut [u8; super::SHA256_HASH_LEN]) {
        let digest = unwrap!(self.0.finish());
        hash.copy_from_slice(digest.as_ref());
    }
}

#[derive(Clone)]
pub struct HmacSha256 {
    ctx: Hmac<sha2::Sha256>,
}

impl super::Digest<{ super::SHA256_HASH_LEN }> for HmacSha256 {
    fn update(&mut self, data: &[u8]) {
        Mac::update(&mut self.ctx, data);
    }

    fn finish(self, hash: &mut [u8; super::SHA256_HASH_LEN]) {
        hash.copy_from_slice(self.ctx.finalize().into_bytes().as_slice());
    }
}

// TODO: Generalize for more than Sha256
pub struct HkdfFactory(());

impl super::Hkdf for HkdfFactory {
    fn expand(self, salt: &[u8], ikm: &[u8], info: &[u8], key: &mut [u8]) -> Result<(), ()> {
        let mut ctx = PkeyCtx::new_id(Id::HKDF).unwrap();
        ctx.derive_init().unwrap();
        ctx.set_hkdf_md(Md::sha256()).unwrap();
        ctx.set_hkdf_key(ikm).unwrap();
        if !salt.is_empty() {
            ctx.set_hkdf_salt(salt).unwrap();
        }
        ctx.add_hkdf_info(info).unwrap();
        ctx.derive(Some(key)).unwrap();

        Ok(())
    }
}

// TODO: Generalize for more than Sha256
pub struct Pbkdf2HmacFactory(());

impl super::Pbkdf2Hmac for Pbkdf2HmacFactory {
    fn derive(self, pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) {
        openssl::pkcs5::pbkdf2_hmac(pass, salt, iter, MessageDigest::sha256(), key).unwrap();
    }
}

pub struct Aes128Ccm1613;

impl super::Aead<{ super::AES128_CANON_KEY_LEN }, { super::AES128_NONCE_LEN }> for Aes128Ccm1613 {
    fn encrypt_in_place<'a>(
        &mut self,
        key: &[u8; super::AES128_CANON_KEY_LEN],
        nonce: &[u8; super::AES128_NONCE_LEN],
        aad: &[u8],
        data: &'a mut [u8],
        data_len: usize,
    ) -> Result<&'a [u8], Error> {
        assert!(data_len + super::AES128_TAG_LEN <= data.len());

        let mut ctx = CipherCtx::new()?;

        ctx.encrypt_init(
            Some(openssl::cipher::Cipher::aes_128_ccm()),
            Some(key),
            Some(nonce),
        )?;
        //ctx.set_key_length(super::AES128_CANON_KEY_LEN)?;
        //ctx.set_iv_length(super::AES128_NONCE_LEN)?;
        ctx.set_tag_length(super::AES128_TAG_LEN)?;
        ctx.set_data_len(data_len)?;

        let mut encrypted_data_len = ctx.cipher_update(aad, None)?;

        encrypted_data_len += ctx.cipher_update_inplace(data, data_len)?;
        encrypted_data_len += ctx.cipher_final(&mut data[encrypted_data_len..])?;

        ctx.tag(&mut data[encrypted_data_len..])?;

        Ok(&data[..encrypted_data_len + super::AES128_TAG_LEN])
    }

    fn decrypt_in_place<'a>(
        &mut self,
        key: &[u8; super::AES128_CANON_KEY_LEN],
        nonce: &[u8; super::AES128_NONCE_LEN],
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        assert!(data.len() >= super::AES128_TAG_LEN);

        let (data, tag) = data.split_at_mut(data.len() - super::AES128_TAG_LEN);

        let mut ctx = CipherCtx::new()?;

        ctx.decrypt_init(
            Some(openssl::cipher::Cipher::aes_128_ccm()),
            Some(key),
            Some(nonce),
        )?;
        //ctx.set_key_length(super::AES128_CANON_KEY_LEN)?;
        //ctx.set_iv_length(super::AES128_NONCE_LEN)?;
        ctx.set_tag(tag)?;
        ctx.set_data_len(data.len())?;

        let mut decrypted_data_len = ctx.cipher_update(aad, None)?;

        decrypted_data_len += ctx.cipher_update_inplace(data, data.len())?;
        decrypted_data_len += ctx.cipher_final(&mut data[decrypted_data_len..])?;

        Ok(&data[..decrypted_data_len])
    }
}

pub struct ECPublicKey<'a> {
    crypto: &'a OpenSslCrypto,
    key: EcKey<pkey::Public>,
}

impl<'a>
    super::PublicKey<'a, { super::SECP256R1_CANON_POINT_LEN }, { super::SECP256R1_SIGNATURE_LEN }>
    for ECPublicKey<'a>
{
    fn canon_into(&self, key: &mut [u8; super::SECP256R1_CANON_POINT_LEN]) {
        let mut bn_ctx = BigNumContext::new().unwrap();
        let s = self
            .key
            .public_key()
            .to_bytes(
                &self.crypto.ec_group,
                PointConversionForm::UNCOMPRESSED,
                &mut bn_ctx,
            )
            .unwrap();
        key.copy_from_slice(s.as_slice());
    }

    fn verify(&self, data: &[u8], signature: &[u8; super::SECP256R1_SIGNATURE_LEN]) -> bool {
        // First get the SHA256 of the message
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        hasher.update(data).unwrap();
        let digest = hasher.finish().unwrap();

        let r = BigNum::from_slice(&signature[..super::SECP256R1_SIGNATURE_LEN / 2]).unwrap();
        let s = BigNum::from_slice(&signature[super::SECP256R1_SIGNATURE_LEN / 2..]).unwrap();
        let sig = EcdsaSig::from_private_components(r, s).unwrap();

        sig.verify(&digest, &self.key).unwrap()
    }
}

pub struct ECPrivateKey<'a> {
    crypto: &'a OpenSslCrypto,
    key: EcKey<pkey::Private>,
}

impl<'a>
    super::SecretKey<
        'a,
        { super::SECP256R1_CANON_SECRET_KEY_LEN },
        { super::SECP256R1_CANON_POINT_LEN },
        { super::SECP256R1_SIGNATURE_LEN },
        { super::SECP256R1_ECDH_SHARED_SECRET_LEN },
    > for ECPrivateKey<'a>
{
    type PublicKey<'s>
        = ECPublicKey<'s>
    where
        Self: 's;

    fn csr<'s>(&self, buf: &'s mut [u8]) -> Result<&'s [u8], Error> {
        let mut builder = X509ReqBuilder::new()?;
        builder.set_version(0)?;

        let pkey = PKey::from_ec_key(self.key.clone())?;
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
        Self::PublicKey {
            crypto: self.crypto,
            key: EcKey::from_public_key(&self.crypto.ec_group, self.key.public_key()).unwrap(),
        }
    }

    fn canon_into(&self, key: &mut [u8; super::SECP256R1_CANON_SECRET_KEY_LEN]) {
        key.copy_from_slice(self.key.private_key().to_vec().as_slice());
    }

    fn derive_shared_secret(
        &self,
        peer_pub_key: &Self::PublicKey<'a>,
        shared_secret: &mut [u8; super::SECP256R1_ECDH_SHARED_SECRET_LEN],
    ) {
        let our_priv_key = PKey::from_ec_key(self.key.clone()).unwrap();
        let peer_pub_key = PKey::from_ec_key(peer_pub_key.key.clone()).unwrap();

        let mut deriver = Deriver::new(&our_priv_key).unwrap();

        deriver.set_peer(&peer_pub_key).unwrap();
        deriver.derive(shared_secret).unwrap();
    }

    fn sign(&self, data: &[u8], signature: &mut [u8; super::SECP256R1_SIGNATURE_LEN]) {
        // First get the SHA256 of the message
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        hasher.update(data).unwrap();
        let digest = hasher.finish().unwrap();

        let sig = EcdsaSig::sign(&digest, &self.key).unwrap();

        signature[..super::SECP256R1_ECDH_SHARED_SECRET_LEN / 2]
            .copy_from_slice(sig.r().to_vec().as_slice());
        signature[super::SECP256R1_ECDH_SHARED_SECRET_LEN / 2..]
            .copy_from_slice(sig.s().to_vec().as_slice());
    }
}

impl<'a> super::UInt<'a, { super::UINT384_CANON_LEN }> for BigNum {
    fn rem(&self, other: &Self) -> Option<Self> {
        let mut ctx = BigNumContext::new().unwrap();
        let mut r = BigNum::new().unwrap();
        if r.checked_rem(self, other, &mut ctx).is_ok() {
            Some(r)
        } else {
            None
        }
    }

    fn canon_into(&self, uint: &mut [u8; super::UINT384_CANON_LEN]) {
        uint.copy_from_slice(
            self.to_vec_padded(super::SECP256R1_CANON_SCALAR_LEN as _)
                .unwrap()
                .as_slice(),
        );
    }
}

pub struct ECScalar(BigNum);

impl<'a> super::Scalar<'a, { super::SECP256R1_CANON_SCALAR_LEN }> for ECScalar {
    fn mul(&self, other: &Self) -> Self {
        Self(self.0.mul(&other.0))
    }

    fn canon_into(&self, scalar: &mut [u8; super::SECP256R1_CANON_SCALAR_LEN]) {
        scalar.copy_from_slice(
            self.0
                .to_vec_padded(super::SECP256R1_CANON_SCALAR_LEN as _)
                .unwrap()
                .as_slice(),
        );
    }
}

pub struct ECPoint<'a> {
    crypto: &'a OpenSslCrypto,
    point: EcPoint,
}

impl<'a>
    super::CurvePoint<
        'a,
        { super::SECP256R1_CANON_POINT_LEN },
        { super::SECP256R1_CANON_SCALAR_LEN },
    > for ECPoint<'a>
{
    type Scalar<'s>
        = ECScalar
    where
        Self: 'a + 's;

    fn neg(&self) -> Self {
        let mut result = self.point.to_owned(&self.crypto.ec_group).unwrap();

        let ctx = BigNumContext::new().unwrap();
        result.invert(&self.crypto.ec_group, &ctx).unwrap();

        Self {
            crypto: self.crypto,
            point: result,
        }
    }

    fn mul(&self, scalar: &Self::Scalar<'a>) -> Self {
        let mut result = EcPoint::new(&self.crypto.ec_group).unwrap();

        let ctx = BigNumContext::new().unwrap();

        result
            .mul(&self.crypto.ec_group, &self.point, &scalar.0, &ctx)
            .unwrap();

        Self {
            crypto: self.crypto,
            point: result,
        }
    }

    fn add_mul(&self, s1: &Self::Scalar<'a>, p2: &Self, s2: &Self::Scalar<'a>) -> Self {
        let a = self.mul(s1);
        let b = p2.mul(s2);

        let mut ctx = BigNumContext::new().unwrap();

        let mut result = EcPoint::new(&self.crypto.ec_group).unwrap();

        result
            .add(&self.crypto.ec_group, &a.point, &b.point, &mut ctx)
            .unwrap();

        Self {
            crypto: self.crypto,
            point: result,
        }
    }

    fn canon_into(&self, point: &mut [u8; super::SECP256R1_CANON_POINT_LEN]) {
        let mut ctx = BigNumContext::new().unwrap();

        let tmp = self
            .point
            .to_bytes(
                &self.crypto.ec_group,
                PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap();

        point.copy_from_slice(tmp.as_slice());
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
