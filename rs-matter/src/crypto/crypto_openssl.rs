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

use core::fmt::{self, Debug};

use crate::error::{Error, ErrorCode};
use crate::utils::rand::Rand;

use alloc::vec;
use foreign_types::ForeignTypeRef;
use openssl::asn1::Asn1Type;
use openssl::bn::{BigNum, BigNumContext};
use openssl::cipher::CipherRef;
use openssl::cipher_ctx::{CipherCtx, CipherCtxRef};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, EcPointRef, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::{Hasher, MessageDigest};
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::{self, Id, PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use openssl::symm::{self};
use openssl::x509::{X509NameBuilder, X509ReqBuilder, X509};

// We directly use the hmac crate here, there was a self-referential structure
// problem while using OpenSSL's Signer
// TODO: Use proper OpenSSL method for this
use hmac::{Hmac, Mac};

extern crate alloc;

pub struct HmacSha256 {
    ctx: Hmac<sha2::Sha256>,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            ctx: Hmac::<sha2::Sha256>::new_from_slice(key)
                .map_err(|_x| ErrorCode::InvalidKeyLength)?,
        })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.ctx.update(data);
        Ok(())
    }

    pub fn finish(self, out: &mut [u8]) -> Result<(), Error> {
        let a = self.ctx.finalize().into_bytes();
        out.copy_from_slice(a.as_slice());
        Ok(())
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeyType {
    Public(#[cfg_attr(feature = "defmt", defmt(Debug2Format))] EcKey<pkey::Public>),
    Private(#[cfg_attr(feature = "defmt", defmt(Debug2Format))] EcKey<pkey::Private>),
}
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyPair {
    key: KeyType,
}

impl KeyPair {
    pub fn new(_rand: Rand) -> Result<Self, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = EcKey::generate(&group)?;
        Ok(Self {
            key: KeyType::Private(key),
        })
    }

    pub fn new_from_components(pub_key: &[u8], priv_key: &[u8]) -> Result<Self, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let priv_key = BigNum::from_slice(priv_key)?;
        let pub_key = EcPoint::from_bytes(&group, pub_key, &mut ctx)?;
        Ok(Self {
            key: KeyType::Private(EcKey::from_private_components(&group, &priv_key, &pub_key)?),
        })
    }

    pub fn new_from_public(pub_key: &[u8]) -> Result<Self, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let pub_key = EcPoint::from_bytes(&group, pub_key, &mut ctx)?;

        Ok(Self {
            key: KeyType::Public(EcKey::from_public_key(&group, &pub_key)?),
        })
    }

    fn public_key_point(&self) -> &EcPointRef {
        match &self.key {
            KeyType::Public(k) => k.public_key(),
            KeyType::Private(k) => k.public_key(),
        }
    }

    fn private_key(&self) -> Result<&EcKey<Private>, Error> {
        match &self.key {
            KeyType::Public(_) => Err(ErrorCode::Invalid.into()),
            KeyType::Private(k) => Ok(k),
        }
    }

    pub fn get_public_key(&self, pub_key: &mut [u8]) -> Result<usize, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut bn_ctx = BigNumContext::new()?;
        let s = self.public_key_point().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut bn_ctx,
        )?;
        let len = s.len();
        pub_key[..len].copy_from_slice(s.as_slice());
        Ok(len)
    }

    pub fn get_private_key(&self, priv_key: &mut [u8]) -> Result<usize, Error> {
        let s = self.private_key()?.private_key().to_vec();
        let len = s.len();
        priv_key[..len].copy_from_slice(s.as_slice());
        Ok(len)
    }

    pub fn derive_secret(self, peer_pub_key: &[u8], secret: &mut [u8]) -> Result<usize, Error> {
        let self_pkey = PKey::from_ec_key(self.private_key()?.clone())?;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, peer_pub_key, &mut ctx)?;
        let peer_key = EcKey::from_public_key(&group, &point)?;
        let peer_pkey = PKey::from_ec_key(peer_key)?;

        let mut deriver = Deriver::new(&self_pkey)?;
        deriver.set_peer(&peer_pkey)?;
        Ok(deriver.derive(secret)?)
    }

    pub fn get_csr<'a>(&self, out_csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let mut builder = X509ReqBuilder::new()?;
        builder.set_version(0)?;

        let pkey = PKey::from_ec_key(self.private_key()?.clone())?;
        builder.set_pubkey(&pkey)?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text_with_type("O", "CSR", Asn1Type::IA5STRING)?;
        let subject_name = name_builder.build();
        builder.set_subject_name(&subject_name)?;

        builder.sign(&pkey, MessageDigest::sha256())?;

        let csr_vec = builder.build().to_der()?;
        let csr = csr_vec.as_slice();
        if csr.len() < out_csr.len() {
            let a = &mut out_csr[0..csr.len()];
            a.copy_from_slice(csr);
            Ok(a)
        } else {
            Err(ErrorCode::NoSpace.into())
        }
    }

    pub fn sign_msg(&self, msg: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        // First get the SHA256 of the message
        let mut h = Hasher::new(MessageDigest::sha256())?;
        h.update(msg)?;
        let msg = h.finish()?;

        if signature.len() < super::EC_SIGNATURE_LEN_BYTES {
            Err(ErrorCode::NoSpace)?;
        }
        safemem::write_bytes(signature, 0);

        let sig = EcdsaSig::sign(&msg, self.private_key()?)?;
        let r = sig.r().to_vec();
        signature[0..r.len()].copy_from_slice(r.as_slice());
        let s = sig.s().to_vec();
        signature[32..(32 + s.len())].copy_from_slice(s.as_slice());
        Ok(64)
    }

    pub fn verify_msg(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error> {
        // First get the SHA256 of the message
        let mut h = Hasher::new(MessageDigest::sha256())?;
        h.update(msg)?;
        let msg = h.finish()?;

        let r = BigNum::from_slice(&signature[0..super::BIGNUM_LEN_BYTES])?;
        let s =
            BigNum::from_slice(&signature[super::BIGNUM_LEN_BYTES..(2 * super::BIGNUM_LEN_BYTES)])?;
        let sig = EcdsaSig::from_private_components(r, s)?;

        let k = match &self.key {
            KeyType::Public(key) => key,
            _ => {
                error!("Not yet supported");
                return Err(ErrorCode::Invalid.into());
            }
        };
        if !sig.verify(&msg, k)? {
            Err(ErrorCode::InvalidSignature.into())
        } else {
            Ok(())
        }
    }
}

const P256_KEY_LEN: usize = 256 / 8;
pub fn pubkey_from_der(der: &[u8], out_key: &mut [u8]) -> Result<(), Error> {
    if out_key.len() != P256_KEY_LEN {
        error!("Insufficient length");
        Err(ErrorCode::NoSpace.into())
    } else {
        let key = X509::from_der(der)?.public_key()?.public_key_to_der()?;
        let len = key.len();
        let out_key = &mut out_key[..len];
        out_key.copy_from_slice(key.as_slice());
        Ok(())
    }
}

pub fn pbkdf2_hmac(pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) -> Result<(), Error> {
    openssl::pkcs5::pbkdf2_hmac(pass, salt, iter, MessageDigest::sha256(), key)
        .map_err(|_e| ErrorCode::TLSStack.into())
}

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], key: &mut [u8]) -> Result<(), Error> {
    let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(Md::sha256())?;
    ctx.set_hkdf_key(ikm)?;
    if !salt.is_empty() {
        ctx.set_hkdf_salt(salt)?;
    }
    ctx.add_hkdf_info(info)?;
    ctx.derive(Some(key))?;
    Ok(())
}

pub fn encrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    data: &mut [u8],
    data_len: usize,
) -> Result<usize, Error> {
    let (plain_text, tag) = data.split_at_mut(data_len);

    let result = lowlevel_encrypt_aead(
        key,
        Some(nonce),
        ad,
        plain_text,
        &mut tag[..super::AEAD_MIC_LEN_BYTES],
    )?;
    data[..data_len].copy_from_slice(result.as_slice());
    Ok(result.len() + super::AEAD_MIC_LEN_BYTES)
}

pub fn decrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    data: &mut [u8],
) -> Result<usize, Error> {
    let tag_start = data.len() - super::AEAD_MIC_LEN_BYTES;
    let (data, tag) = data.split_at_mut(tag_start);
    let result = lowlevel_decrypt_aead(key, Some(nonce), ad, data, tag)?;
    data[..result.len()].copy_from_slice(result.as_slice());
    Ok(result.len())
}

// The default encrypt/decrypt routines in rust-mbedtls have a problem in the ordering of
// set-tag-length. This causes the CCM tag-length to be use incorrectly.
// Instead we use the low-level CipherCtx APIs here to get the desired behaviour.
// More details available here: https://github.com/sfackler/rust-openssl/pull/1594/
//   Need to pursue this PR when I get a chance
pub fn lowlevel_encrypt_aead(
    key: &[u8],
    iv: Option<&[u8]>,
    aad: &[u8],
    data: &[u8],
    tag: &mut [u8],
) -> Result<alloc::vec::Vec<u8>, ErrorStack> {
    let t = symm::Cipher::aes_128_ccm();
    let mut ctx = CipherCtx::new()?;
    CipherCtxRef::encrypt_init(
        &mut ctx,
        Some(unsafe { CipherRef::from_ptr(t.as_ptr() as *mut _) }),
        None,
        None,
    )?;

    ctx.set_tag_length(tag.len())?;
    ctx.set_key_length(key.len())?;
    if let (Some(iv), Some(iv_len)) = (iv, t.iv_len()) {
        if iv.len() != iv_len {
            ctx.set_iv_length(iv.len())?;
        }
    }
    CipherCtxRef::encrypt_init(&mut ctx, None, Some(key), iv)?;

    let mut out = vec![0; data.len() + t.block_size()];
    ctx.set_data_len(data.len())?;

    ctx.cipher_update(aad, None)?;
    let count = ctx.cipher_update(data, Some(&mut out))?;
    let rest = ctx.cipher_final(&mut out[count..])?;
    ctx.tag(tag)?;
    out.truncate(count + rest);
    Ok(out)
}

pub fn lowlevel_decrypt_aead(
    key: &[u8],
    iv: Option<&[u8]>,
    aad: &[u8],
    data: &[u8],
    tag: &[u8],
) -> Result<alloc::vec::Vec<u8>, ErrorStack> {
    let t = symm::Cipher::aes_128_ccm();
    let mut ctx = CipherCtx::new()?;
    CipherCtxRef::decrypt_init(
        &mut ctx,
        Some(unsafe { CipherRef::from_ptr(t.as_ptr() as *mut _) }),
        None,
        None,
    )?;

    ctx.set_tag_length(tag.len())?;
    ctx.set_key_length(key.len())?;
    if let (Some(iv), Some(iv_len)) = (iv, t.iv_len()) {
        if iv.len() != iv_len {
            ctx.set_iv_length(iv.len())?;
        }
    }
    CipherCtxRef::decrypt_init(&mut ctx, None, Some(key), iv)?;

    let mut out = vec![0; data.len() + t.block_size()];

    ctx.set_tag(tag)?;
    ctx.set_data_len(data.len())?;

    ctx.cipher_update(aad, None)?;
    let count = ctx.cipher_update(data, Some(&mut out))?;

    out.truncate(count);
    Ok(out)
}

#[derive(Clone)]
pub struct Sha256 {
    hasher: Hasher,
}

impl Sha256 {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            hasher: Hasher::new(MessageDigest::sha256())?,
        })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.hasher
            .update(data)
            .map_err(|_| ErrorCode::TLSStack.into())
    }

    pub fn finish(mut self, data: &mut [u8]) -> Result<(), Error> {
        let h = self.hasher.finish()?;
        data.copy_from_slice(h.as_ref());
        Ok(())
    }
}

impl Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Sha256")
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Sha256 {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Sha256")
    }
}
