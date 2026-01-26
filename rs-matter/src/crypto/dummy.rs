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

//! A dummy crypto backend
//!
//! NOTE: The dummy backend _cannot_ be used for running `rs-matter`, even in test mode.
//! The moment any crypto operation is invoked, it will panic.
//!
//! The module has a limited use for measuring `rs-matter` flash and RAM footprint without
//! pulling in any crypto dependencies. Note that this module might be retired in future
//! and `rustcrypto` might be used as the default backend.

use crate::{crypto::Crypto, error::Error};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DummyCrypto;

impl Crypto for DummyCrypto {
    type Sha256<'a>
        = DummyCrypto
    where
        Self: 'a;

    type HmacSha256<'a>
        = DummyCrypto
    where
        Self: 'a;

    type HkdfSha256<'a>
        = DummyCrypto
    where
        Self: 'a;

    type Pbkdf2HmacSha256<'a>
        = DummyCrypto
    where
        Self: 'a;

    type AesCcm16p64p128<'a>
        = DummyCrypto
    where
        Self: 'a;

    type Secp256r1PublicKey<'a>
        = DummyCrypto
    where
        Self: 'a;

    type Secp256r1SecretKey<'a>
        = DummyCrypto
    where
        Self: 'a;

    type UInt384<'a>
        = DummyCrypto
    where
        Self: 'a;

    type Secp256r1Scalar<'a>
        = DummyCrypto
    where
        Self: 'a;

    type Secp256r1Point<'a>
        = DummyCrypto
    where
        Self: 'a;

    fn sha256(&self) -> Result<Self::Sha256<'_>, Error> {
        unimplemented!()
    }

    fn hmac_sha256(&self, _key: &[u8]) -> Result<Self::HmacSha256<'_>, Error> {
        unimplemented!()
    }

    fn hkdf_sha256(&self) -> Result<Self::HkdfSha256<'_>, Error> {
        unimplemented!()
    }

    fn pbkdf2_hmac_sha256(&self) -> Result<Self::Pbkdf2HmacSha256<'_>, Error> {
        unimplemented!()
    }

    fn aes_ccm_16_64_128(&self) -> Result<Self::AesCcm16p64p128<'_>, Error> {
        unimplemented!()
    }

    fn secp256r1_pub_key(
        &self,
        _key: &super::CanonSecp256r1PublicKey,
    ) -> Result<Self::Secp256r1PublicKey<'_>, Error> {
        unimplemented!()
    }

    fn secp256r1_secret_key_random(&self) -> Result<Self::Secp256r1SecretKey<'_>, Error> {
        unimplemented!()
    }

    fn secp256r1_secret_key(
        &self,
        _key: &super::CanonSecp256r1SecretKey,
    ) -> Result<Self::Secp256r1SecretKey<'_>, Error> {
        unimplemented!()
    }

    fn uint384(&self, _uint: &super::CanonUint384) -> Result<Self::UInt384<'_>, Error> {
        unimplemented!()
    }

    fn secp256r1_scalar(
        &self,
        _scalar: &super::CanonSecp256r1Scalar,
    ) -> Result<Self::Secp256r1Scalar<'_>, Error> {
        unimplemented!()
    }

    fn secp256r1_scalar_random(&self) -> Result<Self::Secp256r1Scalar<'_>, Error> {
        unimplemented!()
    }

    fn secp256r1_point(
        &self,
        _point: &super::CanonSecp256r1Point,
    ) -> Result<Self::Secp256r1Point<'_>, Error> {
        unimplemented!()
    }

    fn secp256r1_generator(&self) -> Result<Self::Secp256r1Point<'_>, Error> {
        unimplemented!()
    }
}

impl<const HASH_LEN: usize> super::Digest<HASH_LEN> for DummyCrypto {
    fn update(&mut self, _data: &[u8]) {
        unimplemented!()
    }

    fn finish(self, _out: &mut [u8; HASH_LEN]) {
        unimplemented!()
    }
}

impl super::Hkdf for DummyCrypto {
    fn expand(self, _salt: &[u8], _ikm: &[u8], _info: &[u8], _key: &mut [u8]) -> Result<(), ()> {
        unimplemented!()
    }
}

impl super::Pbkdf2Hmac for DummyCrypto {
    fn derive(self, _password: &[u8], _iter: usize, _salt: &[u8], _out: &mut [u8]) {
        unimplemented!()
    }
}

impl<const KEY_LEN: usize, const NONCE_LEN: usize> super::Aead<KEY_LEN, NONCE_LEN> for DummyCrypto {
    fn encrypt_in_place<'a>(
        &mut self,
        _key: &[u8; KEY_LEN],
        _nonce: &[u8; NONCE_LEN],
        _ad: &[u8],
        _data: &'a mut [u8],
        _data_len: usize,
    ) -> Result<&'a [u8], Error> {
        unimplemented!()
    }

    fn decrypt_in_place<'a>(
        &mut self,
        _key: &[u8; KEY_LEN],
        _nonce: &[u8; NONCE_LEN],
        _ad: &[u8],
        _data: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        unimplemented!()
    }
}

impl<const KEY_LEN: usize, const SIGNATURE_LEN: usize> super::PublicKey<'_, KEY_LEN, SIGNATURE_LEN>
    for DummyCrypto
{
    fn verify(&self, _msg: &[u8], _signature: &[u8; SIGNATURE_LEN]) -> bool {
        unimplemented!()
    }

    fn canon_into(&self, _key: &mut [u8; KEY_LEN]) {
        unimplemented!()
    }
}

impl<
        const KEY_LEN: usize,
        const PUB_KEY_LEN: usize,
        const SIGNATURE_LEN: usize,
        const SHARED_SECRET_LEN: usize,
    > super::SecretKey<'_, KEY_LEN, PUB_KEY_LEN, SIGNATURE_LEN, SHARED_SECRET_LEN> for DummyCrypto
{
    type PublicKey<'s>
        = DummyCrypto
    where
        Self: 's;

    fn csr<'s>(&self, _buf: &'s mut [u8]) -> Result<&'s [u8], Error> {
        unimplemented!()
    }

    fn pub_key(&self) -> Self::PublicKey<'_> {
        unimplemented!()
    }

    fn canon_into(&self, _key: &mut [u8; KEY_LEN]) {
        unimplemented!()
    }

    fn derive_shared_secret(
        &self,
        _peer_pub_key: &Self::PublicKey<'_>,
        _shared_secret: &mut [u8; SHARED_SECRET_LEN],
    ) {
        unimplemented!()
    }

    fn sign(&self, _data: &[u8], _signature: &mut [u8; SIGNATURE_LEN]) {
        unimplemented!()
    }
}

impl<const LEN: usize> super::UInt<'_, LEN> for DummyCrypto {
    fn rem(&self, _other: &Self) -> Option<Self> {
        unimplemented!()
    }

    fn canon_into(&self, _buf: &mut [u8; LEN]) {
        unimplemented!()
    }
}

impl<const LEN: usize> super::Scalar<'_, LEN> for DummyCrypto {
    fn mul(&self, _other: &Self) -> Self {
        unimplemented!()
    }

    fn canon_into(&self, _scalar: &mut [u8; LEN]) {
        unimplemented!()
    }
}

impl<'a, const LEN: usize, const SCALAR_LEN: usize> super::CurvePoint<'a, LEN, SCALAR_LEN>
    for DummyCrypto
{
    type Scalar<'s> = DummyCrypto;

    fn neg(&self) -> Self {
        unimplemented!()
    }

    fn mul(&self, _scalar: &Self::Scalar<'a>) -> Self {
        unimplemented!()
    }

    fn add_mul(&self, _s1: &Self::Scalar<'a>, _p2: &Self, _s2: &Self::Scalar<'a>) -> Self {
        unimplemented!()
    }

    fn canon_into(&self, _point: &mut [u8; LEN]) {
        unimplemented!()
    }
}
