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

use core::convert::{TryFrom, TryInto};
use core::marker::PhantomData;
use core::mem::MaybeUninit;

use aes::Aes128;
use alloc::vec;
use ccm::{
    aead::generic_array::GenericArray,
    consts::{U13, U16},
    Ccm,
};
use digest::OutputSizeUser;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use hkdf::HmacImpl;
use hmac::Mac;
use p256::NistP256;
use p256::{
    ecdsa::{Signature, SigningKey, VerifyingKey},
    AffinePoint, EncodedPoint, PublicKey, SecretKey,
};
use rand_core::{CryptoRng, CryptoRngCore, RngCore};
use sha2::Digest;
use x509_cert::{
    attr::AttributeType,
    der::{asn1::BitString, Any, Encode, Writer},
    name::RdnSequence,
    request::CertReq,
    spki::{AlgorithmIdentifier, SubjectPublicKeyInfoOwned},
};

use crate::crypto::Crypto;
use crate::{
    error::{Error, ErrorCode},
    utils::{init::InitMaybeUninit, rand::Rand},
};

type HmacSha256I = hmac::Hmac<sha2::Sha256>;
type AesCcm = Ccm<Aes128, U16, U13>;

extern crate alloc;

pub struct RandRngCore(pub Rand);

impl RngCore for RandRngCore {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0; 4];
        self.fill_bytes(&mut buf);

        u32::from_be_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0; 8];
        self.fill_bytes(&mut buf);

        u64::from_be_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        (self.0)(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for RandRngCore {}

pub struct RustCrypto(());

impl RustCrypto {}

impl Crypto for RustCrypto {
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
    type AeadAesCcm16p64p128<'a>
        = AesCcm
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

    fn aead_aes_ccm_16_64_128(&self, key: &[u8]) -> Result<Self::AeadAesCcm16p64p128<'_>, Error> {
        use ccm::KeyInit;

        Ok(AesCcm::new(GenericArray::from_slice(key)))
    }

    fn public_key_secp256r1_hydrate(
        &self,
        dehydrated_public_key: &[u8],
    ) -> Result<Self::PublicKeySecp256r1<'_>, Error> {
        let encoded_point = EncodedPoint::from_bytes(dehydrated_public_key)?;
        Ok(PublicKey::from_encoded_point(&encoded_point).ok_or(ErrorCode::InvalidData)?)
    }

    fn secret_key_secp256r1(&self, mut rng: R) -> Result<Self::SecretKeySecp256r1<'_>, Error> {
        Ok(SecretKey::random(&mut rng))
    }

    fn secret_key_secp256r1_hydrate(
        &self,
        dehydrated_secret_key: &[u8],
    ) -> Result<Self::SecretKeySecp256r1<'_>, Error> {
        Ok(SecretKey::from_slice(dehydrated_secret_key)?)
    }
}

impl<const HASH_LEN: usize, T> super::Digest<HASH_LEN> for T
where
    T: digest::Update + digest::FixedOutput,
{
    fn update(&mut self, data: &[u8]) {
        digest::Update::update(self, data);
    }

    fn finish(self, buf: &mut [u8; HASH_LEN]) {
        let output = digest::FixedOutput::finalize_fixed(self);
        buf.copy_from_slice(output.as_slice());
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
impl super::Aead for Ccm<Aes128, U16, U13> {
    fn encrypt_in_place<'a>(
        &mut self,
        nonce: &[u8],
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
        nonce: &[u8],
        ad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let mut buffer = SliceBuffer::new(data, data.len());
        ccm::AeadInPlace::decrypt_in_place(self, GenericArray::from_slice(nonce), ad, &mut buffer)?;

        let len = buffer.len();

        Ok(&data[..len])
    }
}

impl super::PublicKey for p256::PublicKey {
    fn dehydrate<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let point = self.as_affine().to_encoded_point(false);

        let slice = point.as_bytes();
        buf[..slice.len()].copy_from_slice(slice);

        Ok(&buf[..slice.len()])
    }

    fn verify(&self, signature: &[u8], data: &[u8]) -> Result<(), Error> {
        use p256::ecdsa::signature::Verifier;

        let verifying_key = VerifyingKey::from_affine(*self.as_affine())?;
        let signature = Signature::try_from(signature)?;

        verifying_key
            .verify(data, &signature)
            .map_err(|_| ErrorCode::InvalidSignature)?;

        Ok(())
    }
}

impl super::SecretKey for p256::SecretKey {
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

        let mut public_key = MaybeUninit::<[u8; 65]>::uninit(); // TODO MEDIUM BUFFER
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

    fn dehydrate<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let bytes = self.to_bytes();
        let slice = bytes.as_slice();

        buf[..slice.len()].copy_from_slice(slice);

        Ok(&buf[..slice.len()])
    }

    fn derive_shared_secret<'a>(
        self,
        peer_pub_key: &Self::PublicKey<'_>,
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        // let encoded_point = EncodedPoint::from_bytes(peer_pub_key)?;
        // let peer_pubkey = PublicKey::from_encoded_point(&encoded_point).unwrap(); // TODO: defmt
        let shared_secret = elliptic_curve::ecdh::diffie_hellman(
            self.to_nonzero_scalar(),
            peer_pub_key.as_affine(),
        );

        let bytes = shared_secret.raw_secret_bytes();
        let slice = bytes.as_slice();
        assert_eq!(buf.len(), slice.len());

        buf.copy_from_slice(slice);

        Ok(&buf[..slice.len()])
    }

    fn sign<'a>(&self, msg: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        use p256::ecdsa::signature::Signer;

        if buf.len() < super::EC_SIGNATURE_LEN_BYTES {
            return Err(ErrorCode::InvalidData.into());
        }

        let signing_key = SigningKey::from(self);
        let signature: Signature = signing_key.sign(msg);
        let signature_bytes = signature.to_bytes();

        buf[..signature_bytes.len()].copy_from_slice(&signature_bytes);

        Ok(&buf[..signature_bytes.len()])
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
