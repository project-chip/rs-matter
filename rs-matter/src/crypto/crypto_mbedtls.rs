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

extern crate alloc;

use core::fmt::{self, Debug};

use alloc::sync::Arc;

use log::{error, info};
use mbedtls::{
    bignum::Mpi,
    cipher::{Authenticated, Cipher},
    ecp::EcPoint,
    hash::{self, Hkdf, Hmac, Md, Type},
    pk::{EcGroup, EcGroupId, Pk},
    rng::{CtrDrbg, OsEntropy},
    x509,
};

use crate::{
    // TODO: We should move ASN1Writer out of Cert,
    // so Crypto doesn't have to depend on Cert
    cert::{ASN1Writer, CertConsumer},
    error::{Error, ErrorCode},
    utils::rand::Rand,
};

pub struct HmacSha256 {
    inner: Hmac,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            inner: Hmac::new(Type::Sha256, key)?,
        })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.inner
            .update(data)
            .map_err(|_| ErrorCode::TLSStack.into())
    }

    pub fn finish(self, out: &mut [u8]) -> Result<(), Error> {
        self.inner.finish(out).map_err(|_| ErrorCode::TLSStack)?;
        Ok(())
    }
}

pub struct KeyPair {
    key: Pk,
}

impl KeyPair {
    pub fn new(_rand: Rand) -> Result<Self, Error> {
        let mut ctr_drbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;
        Ok(Self {
            key: Pk::generate_ec(&mut ctr_drbg, EcGroupId::SecP256R1)?,
        })
    }

    pub fn new_from_components(_pub_key: &[u8], priv_key: &[u8]) -> Result<Self, Error> {
        // No rust-mbedtls API yet for creating keypair from both public and private key
        let mut ctr_drbg: CtrDrbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;
        let priv_key = Mpi::from_binary(priv_key)?;
        Ok(Self {
            key: Pk::private_from_ec_scalar_with_rng(
                EcGroup::new(EcGroupId::SecP256R1)?,
                priv_key,
                &mut ctr_drbg,
            )?,
        })
    }

    pub fn new_from_public(pub_key: &[u8]) -> Result<Self, Error> {
        let group = EcGroup::new(EcGroupId::SecP256R1)?;
        let pub_key = EcPoint::from_binary(&group, pub_key)?;

        Ok(Self {
            key: Pk::public_from_ec_components(group, pub_key)?,
        })
    }

    pub fn get_csr<'a>(&self, out_csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let mut ctr_drbg: CtrDrbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;
        let tmp_priv = self.key.ec_private()?;
        let mut tmp_key = Pk::private_from_ec_scalar_with_rng(
            EcGroup::new(EcGroupId::SecP256R1)?,
            tmp_priv,
            &mut ctr_drbg,
        )?;

        let mut builder = x509::csr::Builder::new();
        builder.key(&mut tmp_key);
        builder.signature_hash(mbedtls::hash::Type::Sha256);
        builder.subject("O=CSR")?;

        let mut ctr_drbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;
        match builder.write_der(out_csr, &mut ctr_drbg) {
            Ok(Some(a)) => Ok(a),
            Ok(None) => {
                error!("Error in writing CSR: None received");
                Err(ErrorCode::Invalid.into())
            }
            Err(e) => {
                error!("Error in writing CSR {}", e);
                Err(ErrorCode::TLSStack.into())
            }
        }
    }

    pub fn get_public_key(&self, pub_key: &mut [u8]) -> Result<usize, Error> {
        let public_key = self.key.ec_public()?;
        let group = EcGroup::new(EcGroupId::SecP256R1)?;
        let vec = public_key.to_binary(&group, false)?;

        let len = vec.len();
        pub_key[..len].copy_from_slice(vec.as_slice());
        Ok(len)
    }

    pub fn get_private_key(&self, priv_key: &mut [u8]) -> Result<usize, Error> {
        let priv_key_mpi = self.key.ec_private()?;
        let vec = priv_key_mpi.to_binary()?;

        let len = vec.len();
        priv_key[..len].copy_from_slice(vec.as_slice());
        Ok(len)
    }

    pub fn derive_secret(self, peer_pub_key: &[u8], secret: &mut [u8]) -> Result<usize, Error> {
        // mbedtls requires a 'mut' key. Instead of making a change in our Trait,
        // we just clone the key this way

        let mut ctr_drbg: CtrDrbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;
        let tmp_key = self.key.ec_private()?;
        let mut tmp_key = Pk::private_from_ec_scalar_with_rng(
            EcGroup::new(EcGroupId::SecP256R1)?,
            tmp_key,
            &mut ctr_drbg,
        )?;

        let group = EcGroup::new(EcGroupId::SecP256R1)?;
        let other = EcPoint::from_binary(&group, peer_pub_key)?;
        let other = Pk::public_from_ec_components(group, other)?;

        let mut ctr_drbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;

        let len = tmp_key.agree(&other, secret, &mut ctr_drbg)?;
        Ok(len)
    }

    pub fn sign_msg(&self, msg: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        // mbedtls requires a 'mut' key. Instead of making a change in our Trait,
        // we just clone the key this way
        let mut ctr_drbg: CtrDrbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;
        let tmp_key = self.key.ec_private()?;
        let mut tmp_key = Pk::private_from_ec_scalar_with_rng(
            EcGroup::new(EcGroupId::SecP256R1)?,
            tmp_key,
            &mut ctr_drbg,
        )?;

        // First get the SHA256 of the message
        let mut msg_hash = [0_u8; super::SHA256_HASH_LEN_BYTES];
        Md::hash(hash::Type::Sha256, msg, &mut msg_hash)?;
        let mut ctr_drbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;

        if signature.len() < super::EC_SIGNATURE_LEN_BYTES {
            Err(ErrorCode::NoSpace)?;
        }
        safemem::write_bytes(signature, 0);

        // mbedTLS writes the DER signature first
        // TODO: Update rust-mbedtls to provide raw level APIs to get r and s values
        let mut tmp_sign = [0u8; super::EC_SIGNATURE_LEN_BYTES * 3];
        tmp_key.sign(hash::Type::Sha256, &msg_hash, &mut tmp_sign, &mut ctr_drbg)?;
        let len = convert_asn1_sign_to_r_s(&mut tmp_sign)?;
        signature[..len].copy_from_slice(&tmp_sign[..len]);
        Ok(len)
    }

    pub fn verify_msg(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error> {
        // mbedtls requires a 'mut' key. Instead of making a change in our Trait,
        // we just clone the key this way
        let tmp_key = self.key.ec_public()?;
        let mut tmp_key =
            Pk::public_from_ec_components(EcGroup::new(EcGroupId::SecP256R1)?, tmp_key)?;

        // First get the SHA256 of the message
        let mut msg_hash = [0_u8; super::SHA256_HASH_LEN_BYTES];
        Md::hash(hash::Type::Sha256, msg, &mut msg_hash)?;

        // current rust-mbedTLS APIs the signature to be in DER format
        let mut mbedtls_sign = [0u8; super::EC_SIGNATURE_LEN_BYTES * 3];
        let len = convert_r_s_to_asn1_sign(signature, &mut mbedtls_sign)?;
        let mbedtls_sign = &mbedtls_sign[..len];

        if let Err(e) = tmp_key.verify(hash::Type::Sha256, &msg_hash, mbedtls_sign) {
            info!("The error is {}", e);
            Err(ErrorCode::InvalidSignature.into())
        } else {
            Ok(())
        }
    }
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair").finish()
    }
}

fn convert_r_s_to_asn1_sign(signature: &[u8], mbedtls_sign: &mut [u8]) -> Result<usize, Error> {
    let r = &signature[0..32];
    let s = &signature[32..64];

    let mut wr = ASN1Writer::new(mbedtls_sign);
    wr.start_seq("")?;
    wr.integer("r", r)?;
    wr.integer("s", s)?;
    wr.end_seq()?;
    Ok(wr.as_slice().len())
}

// mbedTLS sign() function directly encodes the signature in ASN1. The lower level function
// is not yet exposed to us through the Rust crate. So here, I am crudely extracting the 'r'
// and 's' values from the ASN1 encoding and writing 'r' and 's' back sequentially as is expected
// per the Matter spec.
fn convert_asn1_sign_to_r_s(signature: &mut [u8]) -> Result<usize, Error> {
    if signature[0] == 0x30 {
        // Type 0x30 ASN1 Sequence
        // Length: Skip
        let mut offset: usize = 2;

        // Type 0x2 is Integer (first integer is r)
        if signature[offset] != 2 {
            Err(ErrorCode::Invalid)?;
        }
        offset += 1;

        // Length
        let len = signature[offset];
        offset += 1;
        // XXX Once, I have seen a crash in this conversion, need to dig
        if len < 32 {
            error!(
                "Cannot deal with this: this will crash: the slice is: {:x?}",
                signature
            );
        }

        // Sometimes length is more than 32 with a 0 prefix-padded, skip over that
        offset += (len - 32) as usize;

        // Extract the 32 bytes of 'r'
        let mut r = [0_u8; super::BIGNUM_LEN_BYTES];
        r.copy_from_slice(&signature[offset..(offset + 32)]);
        offset += 32;

        // Type 0x2 is Integer (this integer is s)
        if signature[offset] != 2 {
            Err(ErrorCode::Invalid)?;
        }
        offset += 1;

        // Length
        let len = signature[offset];
        offset += 1;
        // Sometimes length is more than 32 with a 0 prefix-padded, skip over that
        offset += (len - 32) as usize;

        // Extract the 32 bytes of 's'
        let mut s = [0_u8; super::BIGNUM_LEN_BYTES];
        s.copy_from_slice(&signature[offset..(offset + 32)]);

        signature[0..32].copy_from_slice(&r);
        signature[32..64].copy_from_slice(&s);

        Ok(64)
    } else {
        Err(ErrorCode::Invalid.into())
    }
}

pub fn pbkdf2_hmac(pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) -> Result<(), Error> {
    mbedtls::hash::pbkdf2_hmac(Type::Sha256, pass, salt, iter as u32, key)
        .map_err(|_e| ErrorCode::TLSStack.into())
}

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], key: &mut [u8]) -> Result<(), Error> {
    Hkdf::hkdf(Type::Sha256, salt, ikm, info, key).map_err(|_e| ErrorCode::TLSStack.into())
}

pub fn encrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    data: &mut [u8],
    data_len: usize,
) -> Result<usize, Error> {
    let cipher = Cipher::<_, Authenticated, _>::new(
        mbedtls::cipher::raw::CipherId::Aes,
        mbedtls::cipher::raw::CipherMode::CCM,
        (key.len() * 8) as u32,
    )?;
    let cipher = cipher.set_key_iv(key, nonce)?;
    let (data, tag) = data.split_at_mut(data_len);
    let tag = &mut tag[..super::AEAD_MIC_LEN_BYTES];
    cipher
        .encrypt_auth_inplace(ad, data, tag)
        .map(|(len, _)| len)
        .map_err(|_e| ErrorCode::TLSStack.into())
}

pub fn decrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    data: &mut [u8],
) -> Result<usize, Error> {
    let cipher = Cipher::<_, Authenticated, _>::new(
        mbedtls::cipher::raw::CipherId::Aes,
        mbedtls::cipher::raw::CipherMode::CCM,
        (key.len() * 8) as u32,
    )?;
    let cipher = cipher.set_key_iv(key, nonce)?;
    let data_len = data.len() - super::AEAD_MIC_LEN_BYTES;
    let (data, tag) = data.split_at_mut(data_len);
    cipher
        .decrypt_auth_inplace(ad, data, tag)
        .map(|(len, _)| len)
        .map_err(|e| {
            error!("Error during decryption: {:?}", e);
            ErrorCode::TLSStack.into()
        })
}

#[derive(Clone)]
pub struct Sha256 {
    ctx: Md,
}

impl Sha256 {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            ctx: Md::new(Type::Sha256)?,
        })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.ctx.update(data).map_err(|_| ErrorCode::TLSStack)?;
        Ok(())
    }

    pub fn finish(self, digest: &mut [u8]) -> Result<(), Error> {
        self.ctx.finish(digest).map_err(|_| ErrorCode::TLSStack)?;
        Ok(())
    }
}

impl Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Sha256")
    }
}
