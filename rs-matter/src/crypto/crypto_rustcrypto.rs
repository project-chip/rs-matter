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

use core::convert::{TryFrom, TryInto};
use core::mem::MaybeUninit;

use aes::Aes128;
use alloc::vec;
use ccm::{
    aead::generic_array::GenericArray,
    consts::{U13, U16},
    Ccm,
};
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use hmac::Mac;
use p256::{
    ecdsa::{Signature, SigningKey, VerifyingKey},
    AffinePoint, EncodedPoint, PublicKey, SecretKey,
};
use sha2::Digest;
use x509_cert::{
    attr::AttributeType,
    der::{asn1::BitString, Any, Encode, Writer},
    name::RdnSequence,
    request::CertReq,
    spki::{AlgorithmIdentifier, SubjectPublicKeyInfoOwned},
};

use crate::{
    error::{Error, ErrorCode},
    secure_channel::crypto_rustcrypto::RandRngCore,
    utils::{init::InitMaybeUninit, rand::Rand},
};

type HmacSha256I = hmac::Hmac<sha2::Sha256>;
type AesCcm = Ccm<Aes128, U16, U13>;

extern crate alloc;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Sha256 {
    #[cfg_attr(feature = "defmt", defmt(Debug2Format))]
    hasher: sha2::Sha256,
}

impl Sha256 {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            hasher: sha2::Sha256::new(),
        })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.hasher.update(data);
        Ok(())
    }

    pub fn finish(self, digest: &mut [u8]) -> Result<(), Error> {
        let output = self.hasher.finalize();
        digest.copy_from_slice(output.as_slice());
        Ok(())
    }
}

pub struct HmacSha256 {
    inner: HmacSha256I,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            inner: HmacSha256I::new_from_slice(key).map_err(|e| {
                error!("Error creating HmacSha256 {:?}", display2format!(&e));
                ErrorCode::TLSStack
            })?,
        })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.inner.update(data);
        Ok(())
    }

    pub fn finish(self, out: &mut [u8]) -> Result<(), Error> {
        let result = &self.inner.finalize().into_bytes()[..];
        out.clone_from_slice(result);
        Ok(())
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeyType {
    Private(#[cfg_attr(feature = "defmt", defmt(Debug2Format))] SecretKey),
    Public(#[cfg_attr(feature = "defmt", defmt(Debug2Format))] PublicKey),
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyPair {
    #[cfg_attr(feature = "defmt", defmt(Debug2Format))]
    key: KeyType,
}

impl KeyPair {
    pub fn new(rand: Rand) -> Result<Self, Error> {
        let mut rng = RandRngCore(rand);
        let secret_key = SecretKey::random(&mut rng);

        Ok(Self {
            key: KeyType::Private(secret_key),
        })
    }

    pub fn new_from_components(pub_key: &[u8], priv_key: &[u8]) -> Result<Self, Error> {
        let secret_key = SecretKey::from_slice(priv_key)?;
        let encoded_point = EncodedPoint::from_bytes(pub_key)?;
        let public_key = PublicKey::from_encoded_point(&encoded_point).unwrap(); // TODO: defmt
        assert!(
            public_key == secret_key.public_key(),
            "Public key {:?} is not equal to ours {:?}",
            debug2format!(public_key),
            debug2format!(secret_key.public_key())
        );

        Ok(Self {
            key: KeyType::Private(secret_key),
        })
    }

    pub fn new_from_public(pub_key: &[u8]) -> Result<Self, Error> {
        let encoded_point = EncodedPoint::from_bytes(pub_key)?;
        Ok(Self {
            key: KeyType::Public(PublicKey::from_encoded_point(&encoded_point).unwrap()), // TODO: defmt
        })
    }

    fn public_key_point(&self) -> AffinePoint {
        match &self.key {
            KeyType::Private(k) => *(k.public_key().as_affine()),
            KeyType::Public(k) => *(k.as_affine()),
        }
    }

    fn private_key(&self) -> Result<&SecretKey, Error> {
        match &self.key {
            KeyType::Private(key) => Ok(key),
            KeyType::Public(_) => Err(ErrorCode::Crypto.into()),
        }
    }

    pub fn get_private_key(&self, priv_key: &mut [u8]) -> Result<usize, Error> {
        match &self.key {
            KeyType::Private(key) => {
                let bytes = key.to_bytes();
                let slice = bytes.as_slice();
                let len = slice.len();
                priv_key[..slice.len()].copy_from_slice(slice);
                Ok(len)
            }
            KeyType::Public(_) => Err(ErrorCode::Crypto.into()),
        }
    }
    pub fn get_csr<'a>(&self, out_csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
        use p256::ecdsa::signature::Signer;

        let subject = RdnSequence(vec![x509_cert::name::RelativeDistinguishedName(unwrap!(
            vec![x509_cert::attr::AttributeTypeAndValue {
                // Organization name: http://www.oid-info.com/get/2.5.4.10
                oid: Self::attr_type("2.5.4.10"),
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
        let mut pubkey = MaybeUninit::<[u8; 65]>::uninit(); // TODO MEDIUM BUFFER
        let pubkey = pubkey.init_zeroed();
        self.get_public_key(pubkey)?;
        let info = x509_cert::request::CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject,
            public_key: SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifier {
                    // ecPublicKey(1) http://www.oid-info.com/get/1.2.840.10045.2.1
                    oid: Self::attr_type("1.2.840.10045.2.1"),
                    parameters: Some(unwrap!(
                        Any::new(
                            x509_cert::der::Tag::ObjectIdentifier,
                            // prime256v1 http://www.oid-info.com/get/1.2.840.10045.3.1.7
                            Self::attr_type("1.2.840.10045.3.1.7").as_bytes(),
                        ),
                        "x509 OID creation failed"
                    )),
                },
                subject_public_key: BitString::from_bytes(&*pubkey)?,
            },
            attributes: Default::default(),
        };
        let mut encoded_info = SliceBuffer::new(out_csr, 0);
        info.encode(&mut encoded_info)?;

        // Can't use self.sign_msg as the signature has to be in DER format
        let private_key = self.private_key()?;
        let signing_key = SigningKey::from(private_key);
        let sig: Signature = signing_key.sign(encoded_info.as_ref());
        let to_der = sig.to_der();
        let signature = to_der.as_bytes();

        let cert = CertReq {
            info,
            algorithm: AlgorithmIdentifier {
                // ecdsa-with-SHA256(2) http://www.oid-info.com/get/1.2.840.10045.4.3.2
                oid: Self::attr_type("1.2.840.10045.4.3.2"),
                parameters: None,
            },
            signature: BitString::from_bytes(signature)?,
        };
        Ok(cert.encode_to_slice(out_csr)?)
    }
    pub fn get_public_key(&self, pub_key: &mut [u8]) -> Result<usize, Error> {
        let point = self.public_key_point().to_encoded_point(false);
        let bytes = point.as_bytes();
        let len = bytes.len();
        pub_key[..len].copy_from_slice(bytes);
        Ok(len)
    }
    pub fn derive_secret(self, peer_pub_key: &[u8], secret: &mut [u8]) -> Result<usize, Error> {
        let encoded_point = EncodedPoint::from_bytes(peer_pub_key)?;
        let peer_pubkey = PublicKey::from_encoded_point(&encoded_point).unwrap(); // TODO: defmt
        let private_key = self.private_key()?;
        let shared_secret = elliptic_curve::ecdh::diffie_hellman(
            private_key.to_nonzero_scalar(),
            peer_pubkey.as_affine(),
        );
        let bytes = shared_secret.raw_secret_bytes();
        let bytes = bytes.as_slice();
        let len = bytes.len();
        assert_eq!(secret.len(), len);
        secret.copy_from_slice(bytes);

        Ok(len)
    }
    pub fn sign_msg(&self, msg: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        use p256::ecdsa::signature::Signer;

        if signature.len() < super::EC_SIGNATURE_LEN_BYTES {
            return Err(ErrorCode::NoSpace.into());
        }

        match &self.key {
            KeyType::Private(k) => {
                let signing_key = SigningKey::from(k);
                let sig: Signature = signing_key.sign(msg);
                let bytes = sig.to_bytes();
                let len = bytes.len();
                signature[..len].copy_from_slice(&bytes);
                Ok(len)
            }
            KeyType::Public(_) => todo!(),
        }
    }
    pub fn verify_msg(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error> {
        use p256::ecdsa::signature::Verifier;

        let verifying_key = VerifyingKey::from_affine(self.public_key_point())?;
        let signature = Signature::try_from(signature)?;

        verifying_key
            .verify(msg, &signature)
            .map_err(|_| ErrorCode::InvalidSignature)?;

        Ok(())
    }

    fn attr_type(value: &str) -> AttributeType {
        unwrap!(
            AttributeType::new(value),
            "x509 AttributeType creation failed"
        )
    }
}

pub fn pbkdf2_hmac(pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) -> Result<(), Error> {
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(pass, salt, iter as u32, key)?;

    Ok(())
}

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], key: &mut [u8]) -> Result<(), Error> {
    hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm)
        .expand(info, key)
        .map_err(|e| {
            error!("Error with hkdf_sha256 {:?}", display2format!(&e));
            ErrorCode::TLSStack.into()
        })
}

// TODO: add tests and check against mbedtls and openssl
pub fn encrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    data: &mut [u8],
    data_len: usize,
) -> Result<usize, Error> {
    use ccm::{AeadInPlace, KeyInit};

    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let cipher = AesCcm::new(key);

    let mut buffer = SliceBuffer::new(data, data_len);
    cipher.encrypt_in_place(nonce, ad, &mut buffer)?;
    Ok(buffer.len())
}

pub fn decrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    data: &mut [u8],
) -> Result<usize, Error> {
    use ccm::{AeadInPlace, KeyInit};

    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let cipher = AesCcm::new(key);

    let mut buffer = SliceBuffer::new(data, data.len());
    cipher.decrypt_in_place(nonce, ad, &mut buffer)?;
    Ok(buffer.len())
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
            Err(ccm::aead::Error)?;
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
