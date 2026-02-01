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

use rand_core::{CryptoRng, RngCore};

use crate::crypto::{Crypto, CryptoSensitive, CryptoSensitiveRef};
use crate::error::Error;

/// A dummy crypto backend that panics on any operation.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DummyCrypto;

impl Crypto for DummyCrypto {
    type Rand<'a>
        = DummyCrypto
    where
        Self: 'a;

    type WeakRand<'a>
        = DummyCrypto
    where
        Self: 'a;

    type Hash<'a>
        = DummyCrypto
    where
        Self: 'a;

    type Hmac<'a>
        = DummyCrypto
    where
        Self: 'a;

    type Kdf<'a>
        = DummyCrypto
    where
        Self: 'a;

    type PbKdf<'a>
        = DummyCrypto
    where
        Self: 'a;

    type Aead<'a>
        = DummyCrypto
    where
        Self: 'a;

    type PublicKey<'a>
        = DummyCrypto
    where
        Self: 'a;

    type SecretKey<'a>
        = DummyCrypto
    where
        Self: 'a;

    type SigningSecretKey<'a>
        = DummyCrypto
    where
        Self: 'a;

    type UInt320<'a>
        = DummyCrypto
    where
        Self: 'a;

    type EcScalar<'a>
        = DummyCrypto
    where
        Self: 'a;

    type EcPoint<'a>
        = DummyCrypto
    where
        Self: 'a;

    fn rand(&self) -> Result<Self::Rand<'_>, Error> {
        unimplemented!()
    }

    fn weak_rand(&self) -> Result<Self::WeakRand<'_>, Error> {
        unimplemented!()
    }

    fn hash(&self) -> Result<Self::Hash<'_>, Error> {
        unimplemented!()
    }

    fn hmac<const KEY_LEN: usize>(
        &self,
        _key: CryptoSensitiveRef<'_, KEY_LEN>,
    ) -> Result<Self::Hmac<'_>, Error> {
        unimplemented!()
    }

    fn kdf(&self) -> Result<Self::Kdf<'_>, Error> {
        unimplemented!()
    }

    fn pbkdf(&self) -> Result<Self::PbKdf<'_>, Error> {
        unimplemented!()
    }

    fn aead(&self) -> Result<Self::Aead<'_>, Error> {
        unimplemented!()
    }

    fn pub_key(&self, _key: super::CanonPkcPublicKeyRef<'_>) -> Result<Self::PublicKey<'_>, Error> {
        unimplemented!()
    }

    fn generate_secret_key(&self) -> Result<Self::SecretKey<'_>, Error> {
        unimplemented!()
    }

    fn secret_key(
        &self,
        _key: super::CanonPkcSecretKeyRef<'_>,
    ) -> Result<Self::SecretKey<'_>, Error> {
        unimplemented!()
    }

    fn singleton_singing_secret_key(&self) -> Result<Self::SigningSecretKey<'_>, Error> {
        unimplemented!()
    }

    fn uint320(&self, _uint: super::CanonUint320Ref<'_>) -> Result<Self::UInt320<'_>, Error> {
        unimplemented!()
    }

    fn ec_scalar(&self, _scalar: super::CanonEcScalarRef<'_>) -> Result<Self::EcScalar<'_>, Error> {
        unimplemented!()
    }

    fn generate_ec_scalar(&self) -> Result<Self::EcScalar<'_>, Error> {
        unimplemented!()
    }

    fn ec_point(&self, _point: super::CanonEcPointRef<'_>) -> Result<Self::EcPoint<'_>, Error> {
        unimplemented!()
    }

    fn ec_generator_point(&self) -> Result<Self::EcPoint<'_>, Error> {
        unimplemented!()
    }
}

impl<const HASH_LEN: usize> super::Digest<HASH_LEN> for DummyCrypto {
    fn update(&mut self, _data: &[u8]) {
        unimplemented!()
    }

    fn finish(self, _out: &mut CryptoSensitive<HASH_LEN>) {
        unimplemented!()
    }
}

impl super::Kdf for DummyCrypto {
    fn expand<const IKM_LEN: usize, const KEY_LEN: usize>(
        self,
        _salt: &[u8],
        _ikm: CryptoSensitiveRef<'_, IKM_LEN>,
        _info: &[u8],
        _key: &mut CryptoSensitive<KEY_LEN>,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

impl super::PbKdf for DummyCrypto {
    fn derive<const PASS_LEN: usize, const KEY_LEN: usize>(
        self,
        _password: CryptoSensitiveRef<'_, PASS_LEN>,
        _iter: usize,
        _salt: &[u8],
        _out: &mut CryptoSensitive<KEY_LEN>,
    ) {
        unimplemented!()
    }
}

impl<const KEY_LEN: usize, const NONCE_LEN: usize> super::Aead<KEY_LEN, NONCE_LEN> for DummyCrypto {
    fn encrypt_in_place<'a>(
        &mut self,
        _key: CryptoSensitiveRef<'_, KEY_LEN>,
        _nonce: CryptoSensitiveRef<'_, NONCE_LEN>,
        _aad: &[u8],
        _data: &'a mut [u8],
        _data_len: usize,
    ) -> Result<&'a [u8], Error> {
        unimplemented!()
    }

    fn decrypt_in_place<'a>(
        &mut self,
        _key: CryptoSensitiveRef<'_, KEY_LEN>,
        _nonce: CryptoSensitiveRef<'_, NONCE_LEN>,
        _aad: &[u8],
        _data: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        unimplemented!()
    }
}

impl<const KEY_LEN: usize, const SIGNATURE_LEN: usize> super::PublicKey<'_, KEY_LEN, SIGNATURE_LEN>
    for DummyCrypto
{
    fn verify(&self, _msg: &[u8], _signature: CryptoSensitiveRef<SIGNATURE_LEN>) -> bool {
        unimplemented!()
    }

    fn write_canon(&self, _key: &mut CryptoSensitive<KEY_LEN>) {
        unimplemented!()
    }
}

impl<const PUB_KEY_LEN: usize, const SIGNATURE_LEN: usize>
    super::SigningSecretKey<'_, PUB_KEY_LEN, SIGNATURE_LEN> for DummyCrypto
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

    fn sign(&self, _data: &[u8], _signature: &mut CryptoSensitive<SIGNATURE_LEN>) {
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
    fn derive_shared_secret(
        &self,
        _peer_pub_key: &Self::PublicKey<'_>,
        _shared_secret: &mut CryptoSensitive<SHARED_SECRET_LEN>,
    ) {
        unimplemented!()
    }

    fn write_canon(&self, _key: &mut CryptoSensitive<KEY_LEN>) {
        unimplemented!()
    }
}

impl<const LEN: usize> super::UInt<'_, LEN> for DummyCrypto {
    fn rem(&self, _other: &Self) -> Option<Self> {
        unimplemented!()
    }

    fn write_canon(&self, _buf: &mut CryptoSensitive<LEN>) {
        unimplemented!()
    }
}

impl<const LEN: usize> super::EcScalar<'_, LEN> for DummyCrypto {
    fn mul(&self, _other: &Self) -> Self {
        unimplemented!()
    }

    fn write_canon(&self, _scalar: &mut CryptoSensitive<LEN>) {
        unimplemented!()
    }
}

impl<'a, const LEN: usize, const SCALAR_LEN: usize> super::EcPoint<'a, LEN, SCALAR_LEN>
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

    fn write_canon(&self, _point: &mut CryptoSensitive<LEN>) {
        unimplemented!()
    }
}

impl RngCore for DummyCrypto {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        unimplemented!()
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        unimplemented!()
    }
}

impl CryptoRng for DummyCrypto {}
