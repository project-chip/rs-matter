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

//! A RustCrypto backend for the crypto traits
//!
//! Besides implementation of the main `Crypto` trait, this module also provides
//! implementations for various other crypto traits defined in the `crypto` module,
//! where those implementations are as generic as possible (i.e., not tied to a specific
//! RustCrypto curve or algorithm) but rather - **coded against the generic RustCrypto traits**
//! describing the notions of ciphers, digests, AEAD, elliptic-curves and so on.
//!
//! This is a deliberate decision which - while increasing a bit the implementation complexity -
//! allows the user to more easily implement hardware acceleration for specific algorithms/curves
//! **IF** the hardware-accelerated algorithm implementation already implements the corresponding
//! RustCrypto traits, because in that case the HW-accelerated algorithm should be piossible to reuse
//! as-is, without additional adaptation.

#![allow(deprecated)] // Remove this once `ccm` and `elliptic_curve` update to `generic-array` 1.x

use core::convert::TryInto;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::{Add, Mul, Neg};

use alloc::vec;

use ccm::{Ccm, NonceSize, TagSize};

use crypto_bigint::{Limb, NonZero};

use digest::Digest as _;

use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
use ecdsa::{der, PrimeCurve, Signature, SignatureSize, SigningKey, VerifyingKey};

use elliptic_curve::generic_array::{ArrayLength, GenericArray};
use elliptic_curve::group::Curve;
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::{
    AffinePoint, CurveArithmetic, Field, FieldBytesSize, PrimeField, ProjectivePoint, PublicKey,
    Scalar, SecretKey,
};

use embassy_sync::blocking_mutex::raw::RawMutex;

use primeorder::PrimeCurveParams;

use rand_core::CryptoRngCore;

use sec1::point::ModulusSize;

use x509_cert::attr::AttributeType;
use x509_cert::der::{asn1::BitString, Any, Encode, Writer};
use x509_cert::name::RdnSequence;
use x509_cert::request::CertReq;
use x509_cert::spki::{AlgorithmIdentifier, SubjectPublicKeyInfoOwned};

use crate::crypto::{
    CanonEcPoint, CanonEcScalar, CanonPkcPublicKey, CanonPkcSecretKey, CanonUint384, Crypto,
};
use crate::error::Error;
use crate::utils::cell::RefCell;
use crate::utils::init::InitMaybeUninit;
use crate::utils::sync::blocking::Mutex;

extern crate alloc;

/// A RustCrypto backend for the crypto traits
pub struct RustCrypto<M: RawMutex, T>(Mutex<M, RefCell<T>>);

impl<M: RawMutex, T> RustCrypto<M, T> {
    /// Create a new RustCrypto backend
    ///
    /// # Arguments
    /// * `rng` - A cryptographic random number generator
    pub const fn new(rng: T) -> Self {
        Self(Mutex::new(RefCell::new(rng)))
    }
}

impl<M: RawMutex, T> Crypto for RustCrypto<M, T>
where
    T: CryptoRngCore,
{
    type Hash<'a>
        = Digest<{ super::HASH_LEN }, sha2::Sha256>
    where
        Self: 'a;

    type Hmac<'a>
        = Digest<{ super::HMAC_HASH_LEN }, hmac::Hmac<sha2::Sha256>>
    where
        Self: 'a;

    type Kdf<'a>
        = HkdfSha256
    where
        Self: 'a;

    type PbKdf<'a>
        = Pbkdf2<hmac::Hmac<sha2::Sha256>>
    where
        Self: 'a;

    type Aead<'a>
        = AeadCcm<
        { super::AEAD_CANON_KEY_LEN },
        { super::AEAD_NONCE_LEN },
        { super::AEAD_TAG_LEN },
        aes::Aes128,
        ccm::consts::U16,
        ccm::consts::U13,
    >
    where
        Self: 'a;

    type PublicKey<'a>
        = ECPublicKey<
        { super::PKC_CANON_PUBLIC_KEY_LEN },
        { super::PKC_SIGNATURE_LEN },
        p256::NistP256,
    >
    where
        Self: 'a;

    type SigningSecretKey<'a>
        = ECSecretKey<
        { super::PKC_CANON_SECRET_KEY_LEN },
        { super::PKC_CANON_PUBLIC_KEY_LEN },
        { super::PKC_SIGNATURE_LEN },
        { super::PKC_SHARED_SECRET_LEN },
        p256::NistP256,
    >
    where
        Self: 'a;

    type SecretKey<'a>
        = ECSecretKey<
        { super::PKC_CANON_SECRET_KEY_LEN },
        { super::PKC_CANON_PUBLIC_KEY_LEN },
        { super::PKC_SIGNATURE_LEN },
        { super::PKC_SHARED_SECRET_LEN },
        p256::NistP256,
    >
    where
        Self: 'a;

    type UInt384<'a>
        = Uint<{ super::UINT384_CANON_LEN }, 384>
    where
        Self: 'a;

    type EcScalar<'a>
        = ECScalar<{ super::EC_CANON_SCALAR_LEN }, p256::NistP256>
    where
        Self: 'a;

    type EcPoint<'a>
        = ECPoint<{ super::EC_CANON_POINT_LEN }, { super::EC_CANON_SCALAR_LEN }, p256::NistP256>
    where
        Self: 'a;

    fn hash(&self) -> Result<Self::Hash<'_>, Error> {
        Ok(unsafe { Digest::new(sha2::Sha256::new()) })
    }

    fn hmac(&self, key: &[u8]) -> Result<Self::Hmac<'_>, Error> {
        pub use hmac::Mac;

        Ok(unsafe { Digest::new(hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap()) })
    }

    fn kdf(&self) -> Result<Self::Kdf<'_>, Error> {
        Ok(HkdfSha256(()))
    }

    fn pbkdf(&self) -> Result<Self::PbKdf<'_>, Error> {
        Ok(Pbkdf2::new())
    }

    fn aead(&self) -> Result<Self::Aead<'_>, Error> {
        Ok(unsafe { AeadCcm::new() })
    }

    fn pub_key(&self, pub_key: &CanonPkcPublicKey) -> Result<Self::PublicKey<'_>, Error> {
        Ok(unsafe { ECPublicKey::new(pub_key) })
    }

    fn secret_key(&self, secret_key: &CanonPkcSecretKey) -> Result<Self::SecretKey<'_>, Error> {
        Ok(unsafe { ECSecretKey::new(secret_key) })
    }

    fn generate_secret_key(&self) -> Result<Self::SecretKey<'_>, Error> {
        Ok(self
            .0
            .lock(|rng| unsafe { ECSecretKey::new_random(&mut *rng.borrow_mut()) }))
    }

    fn singleton_singing_secret_key(&self) -> Result<Self::SigningSecretKey<'_>, Error> {
        todo!()
    }

    fn uint384(&self, uint: &CanonUint384) -> Result<Self::UInt384<'_>, Error> {
        Ok(unsafe { Uint::new(uint) })
    }

    fn ec_scalar(&self, scalar: &CanonEcScalar) -> Result<Self::EcScalar<'_>, Error> {
        Ok(unsafe { ECScalar::new(scalar) })
    }

    fn generate_ec_scalar(&self) -> Result<Self::EcScalar<'_>, Error> {
        Ok(self
            .0
            .lock(|rng| unsafe { ECScalar::new_random(&mut *rng.borrow_mut()) }))
    }

    fn ec_point(&self, point: &CanonEcPoint) -> Result<Self::EcPoint<'_>, Error> {
        Ok(unsafe { ECPoint::new(point) })
    }

    fn ec_generator_point(&self) -> Result<Self::EcPoint<'_>, Error> {
        Ok(unsafe { ECPoint::generator() })
    }
}

/// A digest implementation using RustCrypto
///
/// The implementation is parameterized with the generic RustCrypto `digest` traits, so
/// it can be used with any hasher implementing those traits (including hardware-accelerated ones).
#[derive(Clone)]
pub struct Digest<const HASH_LEN: usize, T>(T);

impl<const HASH_LEN: usize, T> Digest<HASH_LEN, T> {
    /// Create a new Digest
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that the hasher
    /// produces a hash of length `HASH_LEN`.
    unsafe fn new(hasher: T) -> Self {
        Self(hasher)
    }
}

impl<const HASH_LEN: usize, T> super::Digest<HASH_LEN> for Digest<HASH_LEN, T>
where
    T: digest::Update + digest::FixedOutput + Clone,
{
    fn update(&mut self, data: &[u8]) {
        digest::Update::update(&mut self.0, data);
    }

    fn finish(self, hash: &mut [u8; HASH_LEN]) {
        let output = digest::FixedOutput::finalize_fixed(self.0);
        hash.copy_from_slice(output.as_slice());
    }
}

/// A HKDF implementation using SHA-256
// TODO: Generalize for more than Sha256
pub struct HkdfSha256(());

impl super::Kdf for HkdfSha256 {
    fn expand(self, salt: &[u8], ikm: &[u8], info: &[u8], key: &mut [u8]) -> Result<(), ()> {
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);

        hkdf.expand(info, key).map_err(|_| ())
    }
}

/// A PBKDF2 implementation using RustCrypto
///
/// The implementation is parameterized with the generic RustCrypto `digest` traits, so
/// it can be used with any hasher implementing those traits (including hardware-accelerated ones).
pub struct Pbkdf2<T>(PhantomData<T>);

impl<T> Pbkdf2<T> {
    /// Create a new PBKDF2 instance
    fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T> super::PbKdf for Pbkdf2<T>
where
    T: digest::KeyInit + digest::Update + digest::FixedOutput + Clone + Sync,
{
    fn derive(self, pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) {
        unwrap!(pbkdf2::pbkdf2::<T>(pass, salt, iter as u32, key));
    }
}

/// An AEAD-CCM implementation using RustCrypto
///
/// The implementation is parameterized with the generic RustCrypto `cipher` traits, so
/// it can be used with any cipher implementing those traits (including hardware-accelerated ones).
pub struct AeadCcm<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize, C, M, N>(
    PhantomData<(C, M, N)>,
);

impl<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize, C, M, N>
    AeadCcm<KEY_LEN, NONCE_LEN, TAG_LEN, C, M, N>
{
    /// Create a new AEAD-CCM instance
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that the
    /// generic parameters C, M, and N correspond to the KEY_LEN, NONCE_LEN,
    /// and TAG_LEN const generics.
    const unsafe fn new() -> Self {
        Self(PhantomData)
    }
}

impl<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize, C, M, N>
    super::Aead<KEY_LEN, NONCE_LEN> for AeadCcm<KEY_LEN, NONCE_LEN, TAG_LEN, C, M, N>
where
    C: cipher::BlockCipher
        + cipher::BlockSizeUser<BlockSize = ccm::consts::U16 /* TODO */>
        + cipher::BlockEncrypt
        + cipher::KeyInit,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    fn encrypt_in_place<'a>(
        &mut self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &'a mut [u8],
        data_len: usize,
    ) -> Result<&'a [u8], Error> {
        use ccm::{AeadInPlace, KeyInit};

        let cipher = Ccm::<C, M, N>::new(GenericArray::from_slice(key));

        let mut buffer = SliceBuffer::new(data, data_len);
        cipher.encrypt_in_place(GenericArray::from_slice(nonce), aad, &mut buffer)?;

        let len = buffer.len();

        Ok(&data[..len])
    }

    fn decrypt_in_place<'a>(
        &mut self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        use ccm::{AeadInPlace, KeyInit};

        let cipher = Ccm::<C, M, N>::new(GenericArray::from_slice(key));

        let mut buffer = SliceBuffer::new(data, data.len());
        cipher.decrypt_in_place(GenericArray::from_slice(nonce), aad, &mut buffer)?;

        let len = buffer.len();

        Ok(&data[..len])
    }
}

/// An elliptic-curve based public key implementation using RustCrypto
///
/// The implementation is parameterized with the generic RustCrypto `elliptic_curve` traits, so
/// it can be used with any curve implementing those traits (including hardware-accelerated ones).
pub struct ECPublicKey<const KEY_LEN: usize, const SIGNATURE_LEN: usize, C: CurveArithmetic>(
    PublicKey<C>,
);

impl<const KEY_LEN: usize, const SIGNATURE_LEN: usize, C> ECPublicKey<KEY_LEN, SIGNATURE_LEN, C>
where
    C: CurveArithmetic + PrimeCurve + DigestPrimitive,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: ModulusSize,
    <FieldBytesSize<C> as Add>::Output: ArrayLength<u8>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Create a new EC public key from its canonical representation
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that
    /// the curve `C` corresponds to the `KEY_LEN` and `SIGNATURE_LEN` const generics.
    unsafe fn new(pub_key: &[u8; KEY_LEN]) -> Self {
        let encoded_point = EncodedPoint::<C>::from_bytes(pub_key).unwrap();

        Self(
            PublicKey::<C>::from_encoded_point(&encoded_point)
                .into_option()
                .unwrap(),
        )
    }
}

impl<const KEY_LEN: usize, const SIGNATURE_LEN: usize, C>
    super::PublicKey<'_, KEY_LEN, SIGNATURE_LEN> for ECPublicKey<KEY_LEN, SIGNATURE_LEN, C>
where
    C: CurveArithmetic + PrimeCurve + DigestPrimitive,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: ModulusSize,
    <FieldBytesSize<C> as Add>::Output: ArrayLength<u8>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn verify(&self, data: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
        let verifying_key = unwrap!(VerifyingKey::<C>::from_affine(*self.0.as_affine()));
        let signature = unwrap!(Signature::<C>::from_slice(signature));

        ecdsa::signature::Verifier::verify(&verifying_key, data, &signature).is_ok()
    }

    fn write_canon(&self, key: &mut [u8; KEY_LEN]) {
        let point = self.0.as_affine().to_encoded_point(false);
        let slice = point.as_bytes();

        assert_eq!(slice.len(), KEY_LEN);
        key[..slice.len()].copy_from_slice(slice);
    }
}

/// An elliptic-curve based secret key implementation using RustCrypto
///
/// The implementation is parameterized with the generic RustCrypto `elliptic_curve` traits, so
/// it can be used with any curve implementing those traits (including hardware-accelerated ones).
pub struct ECSecretKey<
    const KEY_LEN: usize,
    const PUB_KEY_LEN: usize,
    const SIGNATURE_LEN: usize,
    const SHARED_SECRET_LEN: usize,
    C: CurveArithmetic,
>(SecretKey<C>);

impl<
        const KEY_LEN: usize,
        const PUB_KEY_LEN: usize,
        const SIGNATURE_LEN: usize,
        const SHARED_SECRET_LEN: usize,
        C,
    > ECSecretKey<KEY_LEN, PUB_KEY_LEN, SIGNATURE_LEN, SHARED_SECRET_LEN, C>
where
    C: CurveArithmetic + PrimeCurve + DigestPrimitive,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    Scalar<C>: SignPrimitive<C>,
    FieldBytesSize<C>: ModulusSize,
    <FieldBytesSize<C> as Add>::Output: ArrayLength<u8>,
    SignatureSize<C>: ArrayLength<u8>,
    der::MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<der::MaxOverhead> + ArrayLength<u8>,
{
    /// Create a new EC secret key from its canonical representation
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that
    /// the curve `C` corresponds to the `KEY_LEN`, `PUB_KEY_LEN`,
    /// `SIGNATURE_LEN`, and `SHARED_SECRET_LEN` const generics.
    unsafe fn new(secret_key: &[u8; KEY_LEN]) -> Self {
        Self(SecretKey::<C>::from_slice(secret_key).unwrap())
    }

    /// Create a new random EC secret key
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that
    /// the curve `C` corresponds to the `KEY_LEN`, `PUB_KEY_LEN`,
    /// `SIGNATURE_LEN`, and `SHARED_SECRET_LEN` const generics.
    unsafe fn new_random<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self(SecretKey::<C>::random(rng))
    }
}

impl<
        'a,
        const KEY_LEN: usize,
        const PUB_KEY_LEN: usize,
        const SIGNATURE_LEN: usize,
        const SHARED_SECRET_LEN: usize,
        C,
    > super::SigningSecretKey<'a, PUB_KEY_LEN, SIGNATURE_LEN>
    for ECSecretKey<KEY_LEN, PUB_KEY_LEN, SIGNATURE_LEN, SHARED_SECRET_LEN, C>
where
    C: CurveArithmetic + PrimeCurve + DigestPrimitive,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    Scalar<C>: SignPrimitive<C>,
    FieldBytesSize<C>: ModulusSize,
    <FieldBytesSize<C> as Add>::Output: ArrayLength<u8>,
    SignatureSize<C>: ArrayLength<u8>,
    der::MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<der::MaxOverhead> + ArrayLength<u8>,
{
    type PublicKey<'s>
        = ECPublicKey<PUB_KEY_LEN, SIGNATURE_LEN, C>
    where
        Self: 's;

    fn csr<'s>(&self, buf: &'s mut [u8]) -> Result<&'s [u8], Error> {
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

        let mut public_key = MaybeUninit::<[u8; PUB_KEY_LEN]>::uninit(); // TODO MEDIUM BUFFER
        let public_key = public_key.init_zeroed();
        super::PublicKey::write_canon(&self.pub_key(), public_key);

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
        let signing_key = SigningKey::<C>::from(&self.0);
        let signature: Signature<C> =
            ecdsa::signature::Signer::sign(&signing_key, encoded_info.as_ref());

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

    fn pub_key(&self) -> Self::PublicKey<'a> {
        ECPublicKey(self.0.public_key())
    }

    fn sign(&self, data: &[u8], signature: &mut [u8; SIGNATURE_LEN]) {
        use ecdsa::signature::Signer;

        let signing_key = SigningKey::<C>::from(&self.0);
        let sign: Signature<C> = signing_key.sign(data);
        let sign_bytes = sign.to_bytes();

        assert_eq!(sign_bytes.len(), SIGNATURE_LEN);
        signature[..sign_bytes.len()].copy_from_slice(&sign_bytes);
    }
}

impl<
        'a,
        const KEY_LEN: usize,
        const PUB_KEY_LEN: usize,
        const SIGNATURE_LEN: usize,
        const SHARED_SECRET_LEN: usize,
        C,
    > super::SecretKey<'a, KEY_LEN, PUB_KEY_LEN, SIGNATURE_LEN, SHARED_SECRET_LEN>
    for ECSecretKey<KEY_LEN, PUB_KEY_LEN, SIGNATURE_LEN, SHARED_SECRET_LEN, C>
where
    C: CurveArithmetic + PrimeCurve + DigestPrimitive,
    Scalar<C>: SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: ModulusSize,
    <FieldBytesSize<C> as Add>::Output: ArrayLength<u8>,
    der::MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<der::MaxOverhead> + ArrayLength<u8>,
{
    fn derive_shared_secret(
        &self,
        peer_pub_key: &Self::PublicKey<'_>,
        shared_secret: &mut [u8; SHARED_SECRET_LEN],
    ) {
        // let encoded_point = EncodedPoint::from_bytes(peer_pub_key)?;
        // let peer_pubkey = PublicKey::from_encoded_point(&encoded_point).unwrap(); // TODO: defmt
        let secret = elliptic_curve::ecdh::diffie_hellman(
            self.0.to_nonzero_scalar(),
            peer_pub_key.0.as_affine(),
        );

        let bytes = secret.raw_secret_bytes();
        let slice = bytes.as_slice();

        assert_eq!(slice.len(), super::PKC_SHARED_SECRET_LEN);
        shared_secret[..slice.len()].copy_from_slice(slice);
    }

    fn write_canon(&self, key: &mut [u8; KEY_LEN]) {
        let bytes = self.0.to_bytes();
        let slice = bytes.as_slice();

        assert_eq!(slice.len(), KEY_LEN);
        key[..slice.len()].copy_from_slice(slice);
    }
}

/// A unsigned integer implementation using RustCrypto
/// based on the `crypto-bigint` crate.
///
/// When using hardware acceleration, this type needs to be
/// replaced with a custom one.
pub struct Uint<const LEN: usize, const LIMBS: usize>(crypto_bigint::Uint<LIMBS>);

impl<const LEN: usize, const LIMBS: usize> Uint<LEN, LIMBS> {
    /// Create a new Uint from its canonical representation (BE bytes)
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that
    /// the `LIMBS` const generic corresponds to the `LEN` const generic.
    unsafe fn new(uint: &[u8; LEN]) -> Self {
        Self(crypto_bigint::Uint::from_be_slice(uint))
    }
}

impl<const LEN: usize, const LIMBS: usize> super::UInt<'_, LEN> for Uint<LEN, LIMBS> {
    fn rem(&self, other: &Self) -> Option<Self> {
        let other = NonZero::new(other.0).into_option();
        other.map(|other| Self(self.0.rem(&other)))
    }

    fn write_canon(&self, uint: &mut [u8; LEN]) {
        for (src, dst) in self
            .0
            .as_limbs()
            .iter()
            .rev()
            .cloned()
            .zip(uint.chunks_exact_mut(Limb::BYTES))
        {
            dst.copy_from_slice(&src.0.to_be_bytes());
        }
    }
}

/// An elliptic-curve based scalar implementation using RustCrypto
///
/// The implementation is parameterized with the generic RustCrypto `elliptic_curve` traits, so
/// it can be used with any curve implementing those traits (including hardware-accelerated ones).
pub struct ECScalar<const LEN: usize, C: CurveArithmetic>(Scalar<C>);

impl<const LEN: usize, C> ECScalar<LEN, C>
where
    C: CurveArithmetic,
    Scalar<C>: PrimeField + Mul<Output = C::Scalar> + Clone,
{
    /// Create a new EC scalar from its canonical representation
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that
    /// the curve `C` corresponds to the `LEN` const generic (i.e. its scalar length in SEC-1 representation is exactly `LEN` bytes).
    unsafe fn new(scalar: &[u8; LEN]) -> Self {
        Self(Scalar::<C>::from_repr(GenericArray::from_slice(scalar).clone()).unwrap())
    }

    /// Create a new random EC scalar
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that
    /// the curve `C` corresponds to the `LEN` const generic (i.e. its scalar length in SEC-1 representation is exactly `LEN` bytes).
    unsafe fn new_random<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self(Scalar::<C>::random(rng))
    }
}

impl<'a, const LEN: usize, C> super::EcScalar<'a, LEN> for ECScalar<LEN, C>
where
    C: CurveArithmetic,
    Scalar<C>: Mul<Output = C::Scalar> + Clone,
{
    fn mul(&self, other: &Self) -> Self {
        Self(self.0.mul(other.0))
    }

    fn write_canon(&self, _scalar: &mut [u8; LEN]) {
        todo!()
    }
}

/// An elliptic-curve based point implementation using RustCrypto
///
/// The implementation is parameterized with the generic RustCrypto `elliptic_curve` traits, so
/// it can be used with any curve implementing those traits (including hardware-accelerated ones).
pub struct ECPoint<const LEN: usize, const SCALAR_LEN: usize, C: CurveArithmetic>(
    ProjectivePoint<C>,
);

impl<const LEN: usize, const SCALAR_LEN: usize, C> ECPoint<LEN, SCALAR_LEN, C>
where
    C: CurveArithmetic + PrimeCurveParams,
    FieldBytesSize<C>: ModulusSize,
    Scalar<C>: Mul<Output = C::Scalar> + Clone,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    ProjectivePoint<C>: Neg<Output = C::ProjectivePoint>
        + Mul<C::Scalar, Output = C::ProjectivePoint>
        + Add<Output = C::ProjectivePoint>
        + Clone,
{
    /// Create a new EC point from its canonical representation
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that
    /// the curve `C` corresponds to the `LEN` and `SCALAR_LEN` const generics.
    /// I.e. the point length in SEC-1 representation is exactly `LEN` bytes,
    /// and the scalar length in SEC-1 representation is exactly `SCALAR_LEN` bytes.
    unsafe fn new(point: &[u8; LEN]) -> Self {
        let affine_point =
            AffinePoint::<C>::from_encoded_point(&EncodedPoint::<C>::from_bytes(point).unwrap())
                .unwrap();

        Self(affine_point.into())
    }

    /// Create the EC generator point
    ///
    /// # Safety
    /// This function is unsafe because the caller must ensure that
    /// the curve `C` corresponds to the `LEN` and `SCALAR_LEN` const generics.
    /// I.e. the point length in SEC-1 representation is exactly `LEN` bytes,
    /// and the scalar length in SEC-1 representation is exactly `SCALAR_LEN` bytes.
    unsafe fn generator() -> Self {
        Self(AffinePoint::<C>::GENERATOR.into())
    }
}

impl<'a, const LEN: usize, const SCALAR_LEN: usize, C> super::EcPoint<'a, LEN, SCALAR_LEN>
    for ECPoint<LEN, SCALAR_LEN, C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    Scalar<C>: Mul<Output = C::Scalar> + Clone,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    ProjectivePoint<C>: Neg<Output = C::ProjectivePoint>
        + Mul<C::Scalar, Output = C::ProjectivePoint>
        + Add<Output = C::ProjectivePoint>
        + Clone,
{
    type Scalar<'s> = ECScalar<SCALAR_LEN, C>;

    fn neg(&self) -> Self {
        Self(self.0.neg())
    }

    fn mul(&self, scalar: &Self::Scalar<'a>) -> Self {
        Self(self.0.mul(scalar.0))
    }

    fn add_mul(&self, s1: &Self::Scalar<'a>, p2: &Self, s2: &Self::Scalar<'a>) -> Self {
        let a = self.0.mul(s1.0);
        let b = p2.0.mul(s2.0);
        Self(a.add(b))
    }

    fn write_canon(&self, point: &mut [u8; LEN]) {
        let encoded_point = self.0.to_affine().to_encoded_point(false);
        let slice = encoded_point.as_bytes();

        assert_eq!(slice.len(), LEN);
        point[..slice.len()].copy_from_slice(slice);
    }
}

/// A helper buffer for the AEAD cipher implementing the `ccm::aead::Buffer` trait
///
/// The helper is also used in the X509 CSR generation to provide a buffer implementing
/// the `x509_cert::der::Writer` trait.
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
