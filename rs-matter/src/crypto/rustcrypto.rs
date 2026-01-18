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

#![allow(deprecated)] // Remove this once `ccm` and `elliptic_curve` update to `generic-array` 1.x

use core::convert::TryInto;
use core::mem::MaybeUninit;
use core::ops::{Add, Mul, Neg, Rem};

use aes::Aes128;
use alloc::vec;
use ccm::aead::generic_array::GenericArray;
use ccm::consts::{U13, U16};
use ccm::Ccm;

use digest::OutputSizeUser;

use elliptic_curve::bigint::U384;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::{AffinePoint, CurveArithmetic, ProjectivePoint, Scalar};

use embassy_sync::blocking_mutex::raw::RawMutex;

use hkdf::HmacImpl;

use hmac::Mac;

use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::{EncodedPoint, NistP256, PublicKey, SecretKey};

use rand_core::{CryptoRng, CryptoRngCore, RngCore};

use sha2::Digest;

use x509_cert::attr::AttributeType;
use x509_cert::der::{asn1::BitString, Any, Encode, Writer};
use x509_cert::name::RdnSequence;
use x509_cert::request::CertReq;
use x509_cert::spki::{AlgorithmIdentifier, SubjectPublicKeyInfoOwned};

use crate::crypto::{
    Aes128Key, Crypto, Secp256r1Point, Secp256r1PublicKey, Secp256r1Scalar, Secp256r1SecretKey,
    Uint384, SECP256R1_ECDH_SHARED_SECRET_LEN, SECP256R1_POINT_LEN, SECP256R1_SECRET_KEY_LEN,
    SECP256R1_SIGNATURE_LEN,
};
use crate::error::{Error, ErrorCode};
use crate::utils::cell::RefCell;
use crate::utils::init::InitMaybeUninit;
use crate::utils::sync::blocking::Mutex;

extern crate alloc;

pub struct RustCrypto<M: RawMutex, T>(Mutex<M, RefCell<T>>);

impl<M: RawMutex, T> RustCrypto<M, T> {}

impl<M: RawMutex, T> Crypto for RustCrypto<M, T>
where
    T: CryptoRngCore,
{
    type Sha256<'a>
        = sha2::Sha256
    where
        Self: 'a;
    type HmacSha256<'a>
        = hmac::Hmac<sha2::Sha256>
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
        = Ccm<Aes128, U16, U13>
    where
        Self: 'a;
    type PublicKeySecp256r1<'a>
        = p256::PublicKey
    where
        Self: 'a;
    type SecretKeySecp256r1<'a>
        = p256::SecretKey
    where
        Self: 'a;
    type UInt384<'a>
        = RUInt<crypto_bigint::U384>
    where
        Self: 'a;
    type Secp256r1Scalar<'a>
        = RCurveScalar<NistP256>
    where
        Self: 'a;
    type Secp256r1Point<'a>
        = RCurvePoint<NistP256>
    where
        Self: 'a;

    fn sha256(&self) -> Result<Self::Sha256<'_>, Error> {
        Ok(Self::Sha256::new())
    }

    fn hmac_sha256(&self, key: &[u8]) -> Result<Self::HmacSha256<'_>, Error> {
        hmac::Hmac::<sha2::Sha256>::new_from_slice(key).map_err(|e| {
            error!("Error creating HmacSha256 {:?}", display2format!(&e));
            ErrorCode::TLSStack.into()
        })
    }

    fn hkdf_sha256(&self) -> Result<Self::HkdfSha256<'_>, Error> {
        Ok(HkdfFactory(()))
    }

    fn pbkdf2_hmac_sha256(&self) -> Result<Self::Pbkdf2HmacSha256<'_>, Error> {
        Ok(Pbkdf2HmacFactory(()))
    }

    fn aes_ccm_16_64_128(&self, key: &Aes128Key) -> Result<Self::AesCcm16p64p128<'_>, Error> {
        use ccm::KeyInit;

        Ok(Ccm::<Aes128, U16, U13>::new(GenericArray::from_slice(key)))
    }

    fn public_key_secp256r1_hydrate(
        &self,
        dehydrated_public_key: &Secp256r1PublicKey,
    ) -> Result<Self::PublicKeySecp256r1<'_>, Error> {
        let encoded_point = EncodedPoint::from_bytes(dehydrated_public_key)?;
        Ok(PublicKey::from_encoded_point(&encoded_point).ok_or(ErrorCode::InvalidData)?)
    }

    fn secret_key_secp256r1(&self) -> Result<Self::SecretKeySecp256r1<'_>, Error> {
        Ok(self.0.lock(|rng| SecretKey::random(&mut *rng.borrow_mut())))
    }

    fn secret_key_secp256r1_hydrate(
        &self,
        dehydrated_secret_key: &Secp256r1SecretKey,
    ) -> Result<Self::SecretKeySecp256r1<'_>, Error> {
        Ok(SecretKey::from_slice(dehydrated_secret_key)?)
    }

    fn uint384(&self, scalar: &Uint384) -> Result<Self::UInt384<'_>, Error> {
        todo!()
    }

    fn secp256r1_scalar(
        &self,
        scalar: &Secp256r1Scalar,
    ) -> Result<Self::Secp256r1Scalar<'_>, Error> {
        todo!()
    }

    fn secp256r1_scalar_random(&self) -> Result<Self::Secp256r1Scalar<'_>, Error> {
        todo!()
    }

    fn secpp256r1_point(&self, point: &Secp256r1Point) -> Result<Self::Secp256r1Point<'_>, Error> {
        todo!()
    }

    fn secpp256r1_generator(&self) -> Result<Self::Secp256r1Point<'_>, Error> {
        todo!()
    }
}

impl<const HASH_LEN: usize, T> super::Digest<HASH_LEN> for T
where
    T: digest::Update + digest::FixedOutput,
{
    fn update(&mut self, data: &[u8]) {
        digest::Update::update(self, data);
    }

    fn finish(self, hash: &mut [u8; HASH_LEN]) {
        let output = digest::FixedOutput::finalize_fixed(self);
        hash.copy_from_slice(output.as_slice());
    }
}

// TODO: Generalize for more than Sha256
pub struct HkdfFactory(());

impl<const IKM_LEN: usize> super::Hkdf<IKM_LEN> for HkdfFactory {
    fn expand(self, salt: &[u8], ikm: &[u8; IKM_LEN], info: &[u8], key: &mut [u8]) {
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);

        unwrap!(hkdf.expand(info, key));
    }
}

// TODO: Generalize for more than Sha256
pub struct Pbkdf2HmacFactory(());

impl<const KEY_LEN: usize> super::Pbkdf2Hmac<KEY_LEN> for Pbkdf2HmacFactory {
    fn derive(self, pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8; KEY_LEN]) {
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(pass, salt, iter as u32, key);
    }
}

// TODO: Generalize for more than Aes128
impl super::Aead<{ super::AES128_NONCE_LEN }> for Ccm<Aes128, U16, U13> {
    fn encrypt_in_place<'a>(
        &mut self,
        nonce: &[u8; super::AES128_NONCE_LEN],
        ad: &[u8],
        data: &'a mut [u8],
        data_len: usize,
    ) -> Result<&'a [u8], Error> {
        let mut buffer = SliceBuffer::new(data, data_len);
        ccm::AeadInPlace::encrypt_in_place(self, GenericArray::from_slice(nonce), ad, &mut buffer)?;

        let len = buffer.len();

        Ok(&data[..len])
    }

    fn decrypt_in_place<'a>(
        &mut self,
        nonce: &[u8; super::AES128_NONCE_LEN],
        ad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let mut buffer = SliceBuffer::new(data, data.len());
        ccm::AeadInPlace::decrypt_in_place(self, GenericArray::from_slice(nonce), ad, &mut buffer)?;

        let len = buffer.len();

        Ok(&data[..len])
    }
}

impl super::PublicKey<{ SECP256R1_POINT_LEN }, { SECP256R1_SIGNATURE_LEN }> for p256::PublicKey {
    fn dehydrate(&self, key: &mut [u8; SECP256R1_POINT_LEN]) -> Result<(), Error> {
        let point = self.as_affine().to_encoded_point(false);
        let slice = point.as_bytes();

        assert_eq!(slice.len(), SECP256R1_POINT_LEN);
        key[..slice.len()].copy_from_slice(slice);

        Ok(())
    }

    fn verify(&self, signature: &[u8; SECP256R1_SIGNATURE_LEN], data: &[u8]) -> Result<(), Error> {
        use p256::ecdsa::signature::Verifier;

        let verifying_key = VerifyingKey::from_affine(*self.as_affine())?;
        let signature = Signature::from_slice(signature)?;

        verifying_key
            .verify(data, &signature)
            .map_err(|_| ErrorCode::InvalidSignature)?;

        Ok(())
    }
}

impl
    super::SecretKey<
        { SECP256R1_SECRET_KEY_LEN },
        { SECP256R1_POINT_LEN },
        { SECP256R1_SIGNATURE_LEN },
        { SECP256R1_ECDH_SHARED_SECRET_LEN },
    > for p256::SecretKey
{
    type PublicKey<'a>
        = p256::PublicKey
    where
        Self: 'a;

    fn csr<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        use p256::ecdsa::signature::Signer;

        fn attr_type(value: &str) -> AttributeType {
            unwrap!(
                AttributeType::new(value),
                "x509 AttributeType creation failed"
            )
        }

        let subject = RdnSequence(vec![x509_cert::name::RelativeDistinguishedName(unwrap!(
            vec![x509_cert::attr::AttributeTypeAndValue {
                // Organization name: http://www.oid-info.com/get/2.5.4.10
                oid: attr_type("2.5.4.10"),
                value: unwrap!(
                    x509_cert::attr::AttributeValue::new(
                        x509_cert::der::Tag::Utf8String,
                        "CSR".as_bytes(),
                    ),
                    "x509 AttrValue creation failed"
                ),
            }]
            .try_into(),
            "x509 AttrValue creation failed"
        ))]);

        let mut public_key = MaybeUninit::<[u8; SECP256R1_POINT_LEN]>::uninit(); // TODO MEDIUM BUFFER
        let public_key = public_key.init_zeroed();

        super::PublicKey::dehydrate(&self.public_key(), public_key)?;

        let info = x509_cert::request::CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject,
            public_key: SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifier {
                    // ecPublicKey(1) http://www.oid-info.com/get/1.2.840.10045.2.1
                    oid: attr_type("1.2.840.10045.2.1"),
                    parameters: Some(unwrap!(
                        Any::new(
                            x509_cert::der::Tag::ObjectIdentifier,
                            // prime256v1 http://www.oid-info.com/get/1.2.840.10045.3.1.7
                            attr_type("1.2.840.10045.3.1.7").as_bytes(),
                        ),
                        "x509 OID creation failed"
                    )),
                },
                subject_public_key: BitString::from_bytes(&*public_key)?,
            },
            attributes: Default::default(),
        };

        let mut encoded_info = SliceBuffer::new(buf, 0);
        info.encode(&mut encoded_info)?;

        // Can't use self.sign_msg as the signature has to be in DER format
        let signing_key = SigningKey::from(self);
        let signature: Signature = signing_key.sign(encoded_info.as_ref());

        let signature_der = signature.to_der();
        let signature_der_bytes = signature_der.as_bytes();

        let csr = CertReq {
            info,
            algorithm: AlgorithmIdentifier {
                // ecdsa-with-SHA256(2) http://www.oid-info.com/get/1.2.840.10045.4.3.2
                oid: attr_type("1.2.840.10045.4.3.2"),
                parameters: None,
            },
            signature: BitString::from_bytes(signature_der_bytes)?,
        };

        Ok(csr.encode_to_slice(buf)?)
    }

    fn pub_key(&self) -> Result<Self::PublicKey<'_>, Error> {
        Ok(self.public_key())
    }

    fn dehydrate(&self, key: &mut [u8; SECP256R1_SECRET_KEY_LEN]) -> Result<(), Error> {
        let bytes = self.to_bytes();
        let slice = bytes.as_slice();

        assert_eq!(slice.len(), SECP256R1_SECRET_KEY_LEN);
        key[..slice.len()].copy_from_slice(slice);

        Ok(())
    }

    fn derive_shared_secret(
        &self,
        peer_pub_key: &Self::PublicKey<'_>,
        shared_secret: &mut [u8; SECP256R1_ECDH_SHARED_SECRET_LEN],
    ) -> Result<(), Error> {
        // let encoded_point = EncodedPoint::from_bytes(peer_pub_key)?;
        // let peer_pubkey = PublicKey::from_encoded_point(&encoded_point).unwrap(); // TODO: defmt
        let secret = elliptic_curve::ecdh::diffie_hellman(
            self.to_nonzero_scalar(),
            peer_pub_key.as_affine(),
        );

        let bytes = secret.raw_secret_bytes();
        let slice = bytes.as_slice();

        assert_eq!(slice.len(), SECP256R1_ECDH_SHARED_SECRET_LEN);
        shared_secret[..slice.len()].copy_from_slice(slice);

        Ok(())
    }

    fn sign(&self, msg: &[u8], signature: &mut [u8; SECP256R1_SIGNATURE_LEN]) -> Result<(), Error> {
        use p256::ecdsa::signature::Signer;

        let signing_key = SigningKey::from(self);
        let sign: Signature = signing_key.sign(msg);
        let sign_bytes = sign.to_bytes();

        assert_eq!(sign_bytes.len(), SECP256R1_SIGNATURE_LEN);
        signature[..sign_bytes.len()].copy_from_slice(&sign_bytes);

        Ok(())
    }
}

pub struct RUInt<T>(T);

impl<'a, T> super::UInt<'a, { super::UINT384_LEN }> for RUInt<T>
where
    T: Rem<Output = T> + Clone,
{
    fn rem(&self, other: &Self) -> Self {
        Self(self.0.clone().rem(other.0.clone()))
    }

    fn dehydrate(&self, buf: &mut [u8; super::UINT384_LEN]) -> Result<(), Error> {
        todo!()
    }
}

pub struct RCurveScalar<C: CurveArithmetic>(Scalar<C>);

impl<'a, C: CurveArithmetic> super::Scalar<'a, { super::SECP256R1_SCALAR_LEN }> for RCurveScalar<C>
where
    C::Scalar: Mul<Output = C::Scalar> + Clone,
{
    fn mul(&self, other: &Self) -> Self {
        Self(self.0.mul(other.0.clone()))
    }

    fn dehydrate(&self, buf: &mut [u8; super::SECP256R1_SCALAR_LEN]) -> Result<(), Error> {
        todo!()
    }
}

pub struct RCurvePoint<C: CurveArithmetic>(ProjectivePoint<C>);

impl<'a, C: CurveArithmetic>
    super::CurvePoint<'a, { super::SECP256R1_POINT_LEN }, { super::SECP256R1_SCALAR_LEN }>
    for RCurvePoint<C>
where
    C::Scalar: Mul<Output = C::Scalar> + Clone,
    C::ProjectivePoint: Neg<Output = C::ProjectivePoint>
        + Mul<C::Scalar, Output = C::ProjectivePoint>
        + Add<Output = C::ProjectivePoint>
        + Clone,
{
    type Scalar<'s> = RCurveScalar<C>;

    fn neg(&self) -> Self {
        Self(self.0.neg())
    }

    fn mul(&self, scalar: &Self::Scalar<'a>) -> Self {
        Self(self.0.mul(scalar.0.clone()))
    }

    fn add(&self, other: &Self) -> Self {
        Self(self.0.add(other.0.clone()))
    }

    fn dehydrate(&self, buf: &mut [u8; super::SECP256R1_POINT_LEN]) -> Result<(), Error> {
        todo!()
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct SliceBuffer<'a> {
    slice: &'a mut [u8],
    len: usize,
}

impl<'a> SliceBuffer<'a> {
    const fn new(slice: &'a mut [u8], len: usize) -> Self {
        Self { slice, len }
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl AsMut<[u8]> for SliceBuffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.slice[..self.len]
    }
}

impl AsRef<[u8]> for SliceBuffer<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.slice[..self.len]
    }
}

impl ccm::aead::Buffer for SliceBuffer<'_> {
    fn extend_from_slice(&mut self, slice: &[u8]) -> ccm::aead::Result<()> {
        if self.len + slice.len() > self.slice.len() {
            error!("Buffer overflow");
            return Err(ccm::aead::Error);
        }

        self.slice[self.len..][..slice.len()].copy_from_slice(slice);
        self.len += slice.len();

        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.len = len;
    }
}

impl Writer for SliceBuffer<'_> {
    fn write(&mut self, slice: &[u8]) -> x509_cert::der::Result<()> {
        if self.len + slice.len() > self.slice.len() {
            error!("Buffer overflow");
            Err(x509_cert::der::ErrorKind::Failed)?;
        }

        self.slice[self.len..][..slice.len()].copy_from_slice(slice);
        self.len += slice.len();

        Ok(())
    }
}
