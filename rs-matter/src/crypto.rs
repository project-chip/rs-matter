/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

//! Cryptographic abstractions and backend.

use crate::error::Error;

pub use rand_core::{CryptoRng, Rng, TryCryptoRng, TryRng};

pub use canon::*;
pub use rand::*;

pub mod backend;
mod canon;
mod rand;

/// Trait representing a cryptographic backend.
///
/// The backend should provide all the cryptographic primitives required by the Matter spec.
///
/// The trait is designed in a way where it allows customizing a concrete implementation by
/// swapping out its out of the box algorithms with custom (potentially HW-accelerated) ones,
/// by decorating the original implementation and replacing only the required types and methods.
pub trait Crypto {
    type Rand<'a>: CryptoRng + Copy
    where
        Self: 'a;

    type WeakRand<'a>: Rng + Copy
    where
        Self: 'a;

    /// Hasher type returned by `Crypto::hash`.
    ///
    /// As per the Matter spec, the hasher should be SHA-256.
    type Hash<'a>: Digest<HASH_LEN>
    where
        Self: 'a;

    /// SHA-1 hasher type returned by `Crypto::hash1`.
    type Hash1<'a>: Digest<SHA1_HASH_LEN>
    where
        Self: 'a;

    /// HMAC hasher type returned by `Crypto::hmac`.
    ///
    /// As per the Matter spec, the HMAC hasher should be HMAC-SHA-256.
    type Hmac<'a>: Digest<HASH_LEN>
    where
        Self: 'a;

    /// KDF type returned by `Crypto::kdf`.
    ///
    /// As per the Matter spec, the KDF should be HKDF-SHA256.
    type Kdf<'a>: Kdf
    where
        Self: 'a;

    /// PBKDF type returned by `Crypto::pbkdf`.
    ///
    /// As per the Matter spec, the PBKDF should be PBKDF2-HMAC-SHA256.
    type PbKdf<'a>: PbKdf
    where
        Self: 'a;

    /// AEAD type returned by `Crypto::aead`.
    ///
    /// As per the Matter spec, the AEAD algorithm used is AES-CCM with 128-bit keys, 13-byte nonces
    /// and 16-byte tags.
    type Aead<'a>: Aead<AEAD_CANON_KEY_LEN, AEAD_NONCE_LEN>
    where
        Self: 'a;

    /// Public key type returned by `Crypto::pub_key`.
    ///
    /// As per the Matter spec, the used Public Key Cryptograqphy should be
    /// Elliptic-Curve based, and specifically secp256r1 (NIST P-256).
    ///
    /// In other words, the public key is a point on the secp256r1 curve.
    ///
    /// With that said, the implementation is free to choose a different internal
    /// representation of the public key type as compared to the `EcPoint` type.
    /// The only requirement is that both should be possible to convert from/to
    /// the same canonical representation.
    type PublicKey<'a>: PublicKey<'a, PKC_CANON_PUBLIC_KEY_LEN, PKC_SIGNATURE_LEN>
    where
        Self: 'a;

    /// Signing secret key type returned by `Crypto::singleton_singing_secret_key`.
    ///
    /// As per the Matter spec, the used Public Key Cryptograqphy should be
    /// Elliptic-Curve based, and specifically secp256r1 (NIST P-256).
    ///
    /// In other words, the signing secret key is a scalar on the secp256r1 curve.
    ///
    /// With that said, the implementation is free to choose a different internal
    /// representation of the signing secret key type as compared to the `EcScalar` type.
    /// The only requirement is that both should be possible to convert from/to
    /// the same canonical representation.
    type SigningSecretKey<'a>: SigningSecretKey<
        'a,
        PKC_CANON_PUBLIC_KEY_LEN,
        PKC_SIGNATURE_LEN,
        PublicKey<'a> = Self::PublicKey<'a>,
    >
    where
        Self: 'a;

    /// Secret key type returned by `Crypto::secret_key` and `Crypto::generate_secret_key`.
    ///
    /// As per the Matter spec, the used Public Key Cryptograqphy should be
    /// Elliptic-Curve based, and specifically secp256r1 (NIST P-256).
    ///
    /// In other words, the secret key is a scalar on the secp256r1 curve.
    ///
    /// With that said, the implementation is free to choose a different internal
    /// representation of the secret key type as compared to the `EcScalar` type.
    /// The only requirement is that both should be possible to convert from/to
    /// the same canonical representation.
    type SecretKey<'a>: SecretKey<
        'a,
        PKC_CANON_SECRET_KEY_LEN,
        PKC_CANON_PUBLIC_KEY_LEN,
        PKC_SIGNATURE_LEN,
        PKC_SHARED_SECRET_LEN,
        PublicKey<'a> = Self::PublicKey<'a>,
    >
    where
        Self: 'a;

    /// EC scalar type returned by `Crypto::ec_scalar` and `Crypto::generate_ec_scalar`.
    ///
    /// As per the Matter spec, the curve used is secp256r1 (NIST P-256).
    ///
    /// In other words, the EC scalar is a scalar on the secp256r1 curve.
    type EcScalar<'a>: EcScalar<'a, EC_CANON_SCALAR_LEN>
    where
        Self: 'a;

    /// EC point type returned by `Crypto::ec_point` and `Crypto::ec_generator_point`.
    ///
    /// As per the Matter spec, the curve used is secp256r1 (NIST P-256).
    ///
    /// In other words, the EC point is a point on the secp256r1 curve.
    type EcPoint<'a>: EcPoint<
        'a,
        EC_CANON_POINT_LEN,
        EC_CANON_SCALAR_LEN,
        Scalar<'a> = Self::EcScalar<'a>,
    >
    where
        Self: 'a;

    /// Create a new, cryptographically secure, random number generator instance.
    fn rand(&self) -> Result<Self::Rand<'_>, Error>;

    /// Create a new NON-cryptographically secure (but potentially faster), random number generator instance.
    fn weak_rand(&self) -> Result<Self::WeakRand<'_>, Error>;

    /// Create a new hasher instance.
    fn hash(&self) -> Result<Self::Hash<'_>, Error>;

    /// Create a new SHA-1 hasher instance.
    fn hash1(&self) -> Result<Self::Hash1<'_>, Error>;

    /// Create a new HMAC hasher instance with the given key.
    fn hmac<const KEY_LEN: usize>(
        &self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
    ) -> Result<Self::Hmac<'_>, Error>;

    /// Create a new KDF instance.
    fn kdf(&self) -> Result<Self::Kdf<'_>, Error>;

    /// Create a new PBKDF instance.
    fn pbkdf(&self) -> Result<Self::PbKdf<'_>, Error>;

    /// Create a new AEAD instance.
    fn aead(&self) -> Result<Self::Aead<'_>, Error>;

    /// Create a public key instance from its canonical representation.
    fn pub_key(&self, key: CanonPkcPublicKeyRef<'_>) -> Result<Self::PublicKey<'_>, Error>;

    /// Create a secret key instance from its canonical representation.
    fn secret_key(&self, key: CanonPkcSecretKeyRef<'_>) -> Result<Self::SecretKey<'_>, Error>;

    /// Generate a new secret key instance.
    fn generate_secret_key(&self) -> Result<Self::SecretKey<'_>, Error>;

    /// Get the singleton signing secret key instance.
    ///
    /// This is used for device attestation.
    fn singleton_singing_secret_key(&self) -> Result<Self::SigningSecretKey<'_>, Error>;

    /// Create an EC scalar instance from its canonical representation.
    fn ec_scalar(&self, scalar: CanonEcScalarRef<'_>) -> Result<Self::EcScalar<'_>, Error>;

    /// Create an EC scalar instance from a 320-bit unsigned integer modulo the EC prime modulus.
    fn ec_scalar_mod_p(&self, uint: CanonUint320Ref<'_>) -> Result<Self::EcScalar<'_>, Error>;

    /// Generate a new random EC scalar instance.
    fn generate_ec_scalar(&self) -> Result<Self::EcScalar<'_>, Error>;

    /// Create an EC point instance from its canonical representation.
    fn ec_point(&self, point: CanonEcPointRef<'_>) -> Result<Self::EcPoint<'_>, Error>;

    /// Get the EC Generator point.
    fn ec_generator_point(&self) -> Result<Self::EcPoint<'_>, Error>;
}

impl<T> Crypto for &T
where
    T: Crypto,
{
    type Rand<'a>
        = T::Rand<'a>
    where
        Self: 'a;

    type WeakRand<'a>
        = T::WeakRand<'a>
    where
        Self: 'a;

    type Hash<'a>
        = T::Hash<'a>
    where
        Self: 'a;

    type Hash1<'a>
        = T::Hash1<'a>
    where
        Self: 'a;

    type Hmac<'a>
        = T::Hmac<'a>
    where
        Self: 'a;

    type Kdf<'a>
        = T::Kdf<'a>
    where
        Self: 'a;

    type PbKdf<'a>
        = T::PbKdf<'a>
    where
        Self: 'a;

    type Aead<'a>
        = T::Aead<'a>
    where
        Self: 'a;

    type PublicKey<'a>
        = T::PublicKey<'a>
    where
        Self: 'a;

    type SecretKey<'a>
        = T::SecretKey<'a>
    where
        Self: 'a;

    type SigningSecretKey<'a>
        = T::SigningSecretKey<'a>
    where
        Self: 'a;

    type EcScalar<'a>
        = T::EcScalar<'a>
    where
        Self: 'a;

    type EcPoint<'a>
        = T::EcPoint<'a>
    where
        Self: 'a;

    fn rand(&self) -> Result<Self::Rand<'_>, Error> {
        (*self).rand()
    }

    fn weak_rand(&self) -> Result<Self::WeakRand<'_>, Error> {
        (*self).weak_rand()
    }

    fn hash(&self) -> Result<Self::Hash<'_>, Error> {
        (*self).hash()
    }

    fn hash1(&self) -> Result<Self::Hash1<'_>, Error> {
        (*self).hash1()
    }

    fn hmac<const KEY_LEN: usize>(
        &self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
    ) -> Result<Self::Hmac<'_>, Error> {
        (*self).hmac(key)
    }

    fn kdf(&self) -> Result<Self::Kdf<'_>, Error> {
        (*self).kdf()
    }

    fn pbkdf(&self) -> Result<Self::PbKdf<'_>, Error> {
        (*self).pbkdf()
    }

    fn aead(&self) -> Result<Self::Aead<'_>, Error> {
        (*self).aead()
    }

    fn pub_key(&self, key: CanonPkcPublicKeyRef<'_>) -> Result<Self::PublicKey<'_>, Error> {
        (*self).pub_key(key)
    }

    fn generate_secret_key(&self) -> Result<Self::SecretKey<'_>, Error> {
        (*self).generate_secret_key()
    }

    fn secret_key(&self, key: CanonPkcSecretKeyRef<'_>) -> Result<Self::SecretKey<'_>, Error> {
        (*self).secret_key(key)
    }

    fn singleton_singing_secret_key(&self) -> Result<Self::SigningSecretKey<'_>, Error> {
        (*self).singleton_singing_secret_key()
    }

    fn ec_scalar(&self, scalar: CanonEcScalarRef<'_>) -> Result<Self::EcScalar<'_>, Error> {
        (*self).ec_scalar(scalar)
    }

    fn ec_scalar_mod_p(&self, uint: CanonUint320Ref<'_>) -> Result<Self::EcScalar<'_>, Error> {
        (*self).ec_scalar_mod_p(uint)
    }

    fn generate_ec_scalar(&self) -> Result<Self::EcScalar<'_>, Error> {
        (*self).generate_ec_scalar()
    }

    fn ec_point(&self, point: CanonEcPointRef<'_>) -> Result<Self::EcPoint<'_>, Error> {
        (*self).ec_point(point)
    }

    fn ec_generator_point(&self) -> Result<Self::EcPoint<'_>, Error> {
        (*self).ec_generator_point()
    }
}

/// Trait representing a generic digest (hash) algorithm.
///
/// The digest algorithm should support incremental updates and finalization.
///
/// Used for both hashing and HMAC.
pub trait Digest<const HASH_LEN: usize> {
    /// Update the digest with the given data.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Finish the digest and write the result into the given buffer,
    /// without consuming the hasher instance, allowing for further updates and finalizations.
    fn finish_current(&mut self, hash: &mut CryptoSensitive<HASH_LEN>) -> Result<(), Error>;

    /// Finish the digest and write the result into the given buffer.
    fn finish(self, hash: &mut CryptoSensitive<HASH_LEN>) -> Result<(), Error>;
}

/// Trait representing a Key Derivation Function (KDF).
pub trait Kdf {
    /// Expand the given input keying material (IKM) with the given salt and info
    /// to produce the output keying material (OKM) written into `key`.
    fn expand<const IKM_LEN: usize, const KEY_LEN: usize>(
        self,
        salt: &[u8],
        ikm: CryptoSensitiveRef<'_, IKM_LEN>,
        info: &[u8],
        key: &mut CryptoSensitive<KEY_LEN>,
    ) -> Result<(), Error>;
}

/// Trait representing a Password-Based Key Derivation Function (PBKDF).
pub trait PbKdf {
    /// Derive a key from the given password, salt and iteration count,
    /// writing the result into `key`.
    fn derive<const PASS_LEN: usize, const KEY_LEN: usize>(
        self,
        pass: CryptoSensitiveRef<'_, PASS_LEN>,
        iter: usize,
        salt: &[u8],
        key: &mut CryptoSensitive<KEY_LEN>,
    ) -> Result<(), Error>;
}

/// Trait representing an Authenticated Encryption with Associated Data (AEAD) algorithm.
pub trait Aead<const KEY_LEN: usize, const NONCE_LEN: usize> {
    /// Encrypt the given data in place, using the given key, nonce and additional authenticated data (AAD).
    ///
    /// # Arguments
    /// - `key`: The AEAD key.
    /// - `nonce`: The AEAD nonce.
    /// - `aad`: The additional authenticated data.
    /// - `data`: The data to encrypt, which will be modified in place to contain the ciphertext and tag.
    /// - `data_len`: The length of the plaintext data in `data`.
    ///
    /// # Returns
    /// - On success, returns a slice containing the ciphertext and tag.
    /// - On failure, returns an `Error`.
    fn encrypt_in_place<'a>(
        &mut self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
        nonce: CryptoSensitiveRef<'_, NONCE_LEN>,
        aad: &[u8],
        data: &'a mut [u8],
        data_len: usize,
    ) -> Result<&'a [u8], Error>;

    /// Decrypt the given data in place, using the given key, nonce and additional authenticated data (AAD).
    ///
    /// # Arguments
    /// - `key`: The AEAD key.
    /// - `nonce`: The AEAD nonce.
    /// - `aad`: The additional authenticated data.
    /// - `data`: The data to decrypt, which will be modified in place to contain the plaintext.
    ///
    /// # Returns
    /// - On success, returns a slice containing the plaintext.
    /// - On failure, returns an `Error`.
    fn decrypt_in_place<'a>(
        &mut self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
        nonce: CryptoSensitiveRef<'_, NONCE_LEN>,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], Error>;
}

impl<const KEY_LEN: usize, const NONCE_LEN: usize, T> Aead<KEY_LEN, NONCE_LEN> for &mut T
where
    T: Aead<KEY_LEN, NONCE_LEN>,
{
    fn encrypt_in_place<'a>(
        &mut self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
        nonce: CryptoSensitiveRef<'_, NONCE_LEN>,
        aad: &[u8],
        data: &'a mut [u8],
        data_len: usize,
    ) -> Result<&'a [u8], Error> {
        (*self).encrypt_in_place(key, nonce, aad, data, data_len)
    }

    fn decrypt_in_place<'a>(
        &mut self,
        key: CryptoSensitiveRef<'_, KEY_LEN>,
        nonce: CryptoSensitiveRef<'_, NONCE_LEN>,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        (*self).decrypt_in_place(key, nonce, aad, data)
    }
}

/// Trait representing a signing secret key.
///
/// A signing secret key is a weaker variant of a secret key. Namely:
/// - It can only be used for signing operations.
/// - It cannot be used for deriving shared secrets.
/// - It cannot be written to its canonical representation (exported).
///
/// Suitable in use-cases requiring static yet strongly protected secret key (i.e. device attestation),
/// where the secret key of the device might be offloaded to a special storage and crypto-engine
/// and thus might not be directly accessible.
pub trait SigningSecretKey<'a, const PUB_KEY_LEN: usize, const SIGNATURE_LEN: usize> {
    /// Public key type associated with this secret key.
    type PublicKey<'s>: PublicKey<'s, PUB_KEY_LEN, SIGNATURE_LEN>
    where
        Self: 's;

    /// Get the public key corresponding to this secret key.
    fn pub_key(&self) -> Result<Self::PublicKey<'a>, Error>;

    /// Generate a Certificate Signing Request (CSR) using this secret key,
    ///
    /// # Arguments
    /// - `buf`: Buffer to write the CSR into.
    ///
    /// # Returns
    /// - On success, returns a slice containing the CSR, in DER format.
    /// - On failure, returns an `Error`.
    fn csr<'s>(&self, buf: &'s mut [u8]) -> Result<&'s [u8], Error>;

    /// Sign the given data using this secret key,
    ///
    /// # Arguments
    /// - `data`: Data to sign.
    /// - `signature`: Buffer to write the signature into.
    fn sign(
        &self,
        data: &[u8],
        signature: &mut CryptoSensitive<SIGNATURE_LEN>,
    ) -> Result<(), Error>;
}

/// Trait representing a secret key.
///
/// A secret key can be used for signing operations, deriving shared secrets,
/// and can be written to its canonical representation (exported).
pub trait SecretKey<
    'a,
    const KEY_LEN: usize,
    const PUB_KEY_LEN: usize,
    const SIGNATURE_LEN: usize,
    const SHARED_SECRET_LEN: usize,
>: SigningSecretKey<'a, PUB_KEY_LEN, SIGNATURE_LEN>
{
    /// Derive a shared secret with the given peer public key,
    ///
    /// # Arguments
    /// - `peer_pub_key`: Peer public key to derive the shared secret with.
    /// - `shared_secret`: Buffer to write the shared secret into.
    fn derive_shared_secret(
        &self,
        peer_pub_key: &Self::PublicKey<'a>,
        shared_secret: &mut CryptoSensitive<SHARED_SECRET_LEN>,
    ) -> Result<(), Error>;

    /// Write the canonical representation of this secret key into the given buffer.
    fn write_canon(&self, key: &mut CryptoSensitive<KEY_LEN>) -> Result<(), Error>;
}

/// Trait representing a public key.
pub trait PublicKey<'a, const KEY_LEN: usize, const SIGNATURE_LEN: usize> {
    /// Verify the given signature over the given data using this public key.
    ///
    /// # Arguments
    /// - `data`: Data to verify the signature over.
    /// - `signature`: Signature to verify.
    ///
    /// # Returns
    /// - `true` if the signature is valid.
    fn verify(
        &self,
        data: &[u8],
        signature: CryptoSensitiveRef<SIGNATURE_LEN>,
    ) -> Result<bool, Error>;

    /// Write the canonical representation of this public key into the given buffer.
    fn write_canon(&self, key: &mut CryptoSensitive<KEY_LEN>) -> Result<(), Error>;
}

impl<'a, const KEY_LEN: usize, const SIGNATURE_LEN: usize, T> PublicKey<'a, KEY_LEN, SIGNATURE_LEN>
    for &T
where
    T: PublicKey<'a, KEY_LEN, SIGNATURE_LEN>,
{
    fn verify(
        &self,
        data: &[u8],
        signature: CryptoSensitiveRef<SIGNATURE_LEN>,
    ) -> Result<bool, Error> {
        (*self).verify(data, signature)
    }

    fn write_canon(&self, key: &mut CryptoSensitive<KEY_LEN>) -> Result<(), Error> {
        (*self).write_canon(key)
    }
}

/// Trait representing an Elliptic Curve (EC) scalar value.
pub trait EcScalar<'a, const LEN: usize> {
    /// Multiply this scalar by another scalar.
    ///
    /// # Arguments
    /// - `other`: The other scalar to multiply with.
    ///
    /// # Returns
    /// - The result of the multiplication.
    fn mul(&self, other: &Self) -> Result<Self, Error>
    where
        Self: Sized;

    /// Write the canonical representation of this scalar into the given buffer.
    fn write_canon(&self, scalar: &mut CryptoSensitive<LEN>) -> Result<(), Error>;
}

/// Trait representing an Elliptic Curve (EC) point.
pub trait EcPoint<'a, const LEN: usize, const SCALAR_LEN: usize> {
    /// Scalar type associated with this EC point.
    type Scalar<'s>: EcScalar<'s, SCALAR_LEN>
    where
        Self: 'a + 's;

    /// Return `true` if this point is a valid public key on the curve, i.e. it
    /// is on the curve, its coordinates are in range, and it is **not** the
    /// identity (point at infinity) — equivalently, per RFC 9383 §4, that the
    /// cofactor multiple `h*P` is not the identity element.
    ///
    /// SPAKE2+ requires this validation on the peer's public share (`X` on the
    /// verifier side, `Y` on the prover side); an unchecked identity/invalid
    /// point lets a peer force the shared secret and break the protocol's
    /// guarantees.
    fn is_valid_pubkey(&self) -> Result<bool, Error>;

    /// Negate this EC point.
    fn neg(&self) -> Result<Self, Error>
    where
        Self: Sized;

    /// Multiply this EC point by the given scalar.
    fn mul(&self, scalar: &Self::Scalar<'a>) -> Result<Self, Error>
    where
        Self: Sized;

    /// Perform an addition-multiplication operation,
    /// i.e. compute P1 * s1 + P2 * s2, where P1 is `self`.
    ///
    /// # Arguments
    /// - `s1`: Scalar to multiply `self` with.
    /// - `p2`: Second EC point to multiply with `s2`.
    /// - `s2`: Scalar to multiply `p2` with.
    ///
    /// # Returns
    /// - The result of the addition-multiplication.
    fn add_mul(
        &self,
        s1: &Self::Scalar<'a>,
        p2: &Self,
        s2: &Self::Scalar<'a>,
    ) -> Result<Self, Error>
    where
        Self: Sized;

    /// Write the canonical representation of this EC point into the given buffer.
    fn write_canon(&self, point: &mut CryptoSensitive<LEN>) -> Result<(), Error>;
}

#[allow(unused)]
pub fn default_crypto<'s, R>(
    rand: R,
    singleton_secret_key: CanonPkcSecretKeyRef<'s>,
) -> impl Crypto + 's
where
    R: CryptoRng + 's,
{
    #[cfg(feature = "openssl")]
    let crypto = backend::openssl::OpenSslCrypto::new(singleton_secret_key);

    #[cfg(all(feature = "mbedtls", not(feature = "openssl")))]
    let crypto = backend::mbedtls::MbedtlsCrypto::new(rand, singleton_secret_key);

    #[cfg(all(
        feature = "rustcrypto",
        not(any(feature = "openssl", feature = "mbedtls"))
    ))]
    let crypto = backend::rustcrypto::RustCrypto::new(rand, singleton_secret_key);

    #[cfg(not(any(feature = "openssl", feature = "mbedtls", feature = "rustcrypto")))]
    let crypto = backend::dummy::DummyCrypto;

    crypto
}

pub fn test_only_crypto() -> impl Crypto {
    default_crypto(
        WeakTestOnlyRand::new_default(),
        crate::dm::devices::test::DAC_PRIVKEY,
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::crypto::{
        test_only_crypto, Aead, CanonPkcPublicKey, CanonPkcPublicKeyRef, CanonPkcSecretKey,
        CanonPkcSecretKeyRef, CanonPkcSharedSecret, CanonPkcSignature, CanonPkcSignatureRef,
        Crypto, CryptoSensitive, CryptoSensitiveRef, Digest, Kdf, PbKdf, PublicKey, Rng, SecretKey,
        SigningSecretKey, AEAD_TAG_LEN, HASH_LEN, PKC_CANON_PUBLIC_KEY_LEN, SHA1_HASH_LEN,
    };

    /// One-shot SHA-256 over `data` via the `Crypto` trait.
    fn sha256(data: &[u8]) -> [u8; HASH_LEN] {
        let crypto = test_only_crypto();

        let mut hasher = unwrap!(crypto.hash());
        unwrap!(hasher.update(data));

        let mut out = CryptoSensitive::new();
        unwrap!(hasher.finish(&mut out));

        *out.access()
    }

    /// HMAC-SHA-256 of `msg` under `key` via the `Crypto` trait.
    fn hmac_sha256<const KEY_LEN: usize>(key: &[u8; KEY_LEN], msg: &[u8]) -> [u8; HASH_LEN] {
        let crypto = test_only_crypto();

        let mut hmac = unwrap!(crypto.hmac(CryptoSensitiveRef::new(key)));
        unwrap!(hmac.update(msg));

        let mut out = CryptoSensitive::new();
        unwrap!(hmac.finish(&mut out));

        *out.access()
    }

    /// HKDF-SHA-256 extract+expand via the `Crypto` trait.
    fn hkdf_sha256<const IKM_LEN: usize, const KEY_LEN: usize>(
        salt: &[u8],
        ikm: &[u8; IKM_LEN],
        info: &[u8],
    ) -> [u8; KEY_LEN] {
        let crypto = test_only_crypto();

        let mut out = CryptoSensitive::new();
        unwrap!(unwrap!(crypto.kdf()).expand(salt, CryptoSensitiveRef::new(ikm), info, &mut out));

        *out.access()
    }

    /// PBKDF2-HMAC-SHA-256 via the `Crypto` trait.
    fn pbkdf2_sha256<const PASS_LEN: usize, const KEY_LEN: usize>(
        pass: &[u8; PASS_LEN],
        iter: usize,
        salt: &[u8],
    ) -> [u8; KEY_LEN] {
        let crypto = test_only_crypto();

        let mut out = CryptoSensitive::new();
        unwrap!(unwrap!(crypto.pbkdf()).derive(
            CryptoSensitiveRef::new(pass),
            iter,
            salt,
            &mut out
        ));

        *out.access()
    }

    /// AES-128-CCM encrypt: returns `ciphertext || tag`.
    fn ccm_encrypt(key: &[u8; 16], nonce: &[u8; 13], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let crypto = test_only_crypto();
        let mut aead = unwrap!(crypto.aead());

        let mut buf = vec![0u8; pt.len() + AEAD_TAG_LEN];
        buf[..pt.len()].copy_from_slice(pt);

        let out = unwrap!(aead.encrypt_in_place(
            CryptoSensitiveRef::new(key),
            CryptoSensitiveRef::new(nonce),
            aad,
            &mut buf,
            pt.len(),
        ));

        out.to_vec()
    }

    /// AES-128-CCM decrypt of `ciphertext || tag`: returns the plaintext, or `None`
    /// if authentication failed.
    fn ccm_decrypt(key: &[u8; 16], nonce: &[u8; 13], aad: &[u8], ct_tag: &[u8]) -> Option<Vec<u8>> {
        let crypto = test_only_crypto();
        let mut aead = unwrap!(crypto.aead());

        let mut buf = ct_tag.to_vec();

        aead.decrypt_in_place(
            CryptoSensitiveRef::new(key),
            CryptoSensitiveRef::new(nonce),
            aad,
            &mut buf,
        )
        .ok()
        .map(|pt| pt.to_vec())
    }

    // Vectors from connectedhomeip src/crypto/tests/Hash_SHA256_test_vectors.h (v01, v02, v07, v08)
    #[test]
    fn sha256_kat() {
        assert_eq!(
            sha256(&[]),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );

        assert_eq!(
            sha256(&[0xd3]),
            [
                0x28, 0x96, 0x9c, 0xdf, 0xa7, 0x4a, 0x12, 0xc8, 0x2f, 0x3b, 0xad, 0x96, 0x0b, 0x0b,
                0x00, 0x0a, 0xca, 0x2a, 0xc3, 0x29, 0xde, 0xea, 0x5c, 0x23, 0x28, 0xeb, 0xc6, 0xf2,
                0xba, 0x98, 0x02, 0xc1
            ]
        );

        assert_eq!(
            sha256(&[
                0x1b, 0x50, 0x3f, 0xb9, 0xa7, 0x3b, 0x16, 0xad, 0xa3, 0xfc, 0xf1, 0x04, 0x26, 0x23,
                0xae, 0x76, 0x10
            ]),
            [
                0xd5, 0xc3, 0x03, 0x15, 0xf7, 0x2e, 0xd0, 0x5f, 0xe5, 0x19, 0xa1, 0xbf, 0x75, 0xab,
                0x5f, 0xd0, 0xff, 0xec, 0x5a, 0xc1, 0xac, 0xb0, 0xda, 0xf6, 0x6b, 0x6b, 0x76, 0x95,
                0x98, 0x59, 0x45, 0x09
            ]
        );

        assert_eq!(sha256(SHA256_DATA08), SHA256_HASH08);
    }

    /// Feeding the input in chunks gives the same digest as one shot, and
    /// `finish_current` is a non-consuming snapshot of the data seen so far.
    #[test]
    fn sha256_incremental() {
        let crypto = test_only_crypto();

        let mut hasher = unwrap!(crypto.hash());
        unwrap!(hasher.update(&SHA256_DATA08[..7]));
        unwrap!(hasher.update(&SHA256_DATA08[7..20]));

        let mut mid = CryptoSensitive::new();
        unwrap!(hasher.finish_current(&mut mid));
        assert_eq!(*mid.access(), sha256(&SHA256_DATA08[..20]));

        unwrap!(hasher.update(&SHA256_DATA08[20..]));
        unwrap!(hasher.update(&[]));

        let mut full = CryptoSensitive::new();
        unwrap!(hasher.finish(&mut full));
        assert_eq!(*full.access(), SHA256_HASH08);
    }

    // FIPS 180-4 example: SHA-1("abc")
    #[test]
    fn sha1_kat() {
        let crypto = test_only_crypto();

        let mut hasher = unwrap!(crypto.hash1());
        unwrap!(hasher.update(b"abc"));

        let mut out = CryptoSensitive::<SHA1_HASH_LEN>::new();
        unwrap!(hasher.finish(&mut out));

        assert_eq!(
            *out.access(),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    // Vectors from connectedhomeip src/crypto/tests/HMAC_SHA256_test_vectors.h
    // (kHmacSha256TestCase1 with a 131-byte key, kHmacKeyHandleSha256TestCase1 with a 16-byte key)
    #[test]
    fn hmac_sha256_kat() {
        let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";

        assert_eq!(
            hmac_sha256(&[0xaa; 131], msg),
            [
                0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
                0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
                0x0e, 0xe3, 0x7f, 0x54
            ]
        );

        assert_eq!(
            hmac_sha256(&[0xba; 16], msg),
            [
                0xc0, 0xcd, 0x77, 0x23, 0xdc, 0xf1, 0x57, 0xa5, 0xfe, 0x53, 0xc5, 0x6b, 0x2d, 0x86,
                0xd4, 0x1c, 0x78, 0x61, 0xb4, 0x20, 0x67, 0xca, 0x7c, 0xae, 0x44, 0x13, 0x57, 0x4d,
                0x25, 0xda, 0x84, 0x1e
            ]
        );

        // A different key must give a different MAC
        assert_ne!(hmac_sha256(&[0xbb; 16], msg), hmac_sha256(&[0xba; 16], msg));
    }

    // Vectors from connectedhomeip src/crypto/tests/HKDF_SHA256_test_vectors.h (v1, v2, v3)
    #[test]
    fn hkdf_sha256_kat() {
        // v1: 22-byte IKM, 13-byte salt, 10-byte info, 42-byte OKM
        let okm: [u8; 42] = hkdf_sha256(
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            ],
            &[0x0b; 22],
            &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
        );
        assert_eq!(
            okm,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
            ]
        );

        // v2: 80-byte IKM/salt/info, 82-byte OKM (spans multiple HMAC blocks)
        let mut ikm = [0u8; 80];
        let mut salt = [0u8; 80];
        let mut info = [0u8; 80];
        for i in 0..80 {
            ikm[i] = i as u8;
            salt[i] = 0x60 + i as u8;
            info[i] = 0xb0 + i as u8;
        }
        let okm: [u8; 82] = hkdf_sha256(&salt, &ikm, &info);
        assert_eq!(
            okm,
            [
                0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a,
                0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c,
                0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb,
                0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
                0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec,
                0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87
            ]
        );

        // v3: empty salt, 80-byte info, 42-byte OKM
        let okm: [u8; 42] = hkdf_sha256(&[], &[0x0b; 22], &info);
        assert_eq!(
            okm,
            [
                0x7a, 0xc3, 0xc1, 0xb4, 0x18, 0xd0, 0xc3, 0xad, 0x19, 0x7a, 0x8f, 0x6d, 0x69, 0x29,
                0x8a, 0x04, 0x0b, 0x51, 0x23, 0x82, 0x32, 0xd1, 0xf6, 0xbd, 0xa9, 0xe7, 0x69, 0x90,
                0x5a, 0x09, 0xb6, 0xba, 0x79, 0x81, 0x1d, 0xbe, 0xb3, 0x3a, 0x46, 0xfb, 0x1b, 0x8b
            ]
        );
    }

    // Vectors from connectedhomeip src/crypto/tests/PBKDF2_SHA256_test_vectors.h (tcId 1, 2, 5)
    #[test]
    fn pbkdf2_sha256_kat() {
        let key: [u8; 20] = pbkdf2_sha256(b"password", 1, b"saltSALTsaltSALT");
        assert_eq!(
            key,
            [
                0xf2, 0xe3, 0x4b, 0xd9, 0x50, 0xe9, 0x1c, 0xf3, 0x7d, 0x22, 0xe1, 0x13, 0x5a, 0x39,
                0x9b, 0x02, 0xa1, 0x7c, 0xb1, 0x93
            ]
        );

        let key: [u8; 20] = pbkdf2_sha256(b"password", 2, b"saltSALTsaltSALT");
        assert_eq!(
            key,
            [
                0x2b, 0x77, 0x27, 0x5c, 0xc3, 0x12, 0x0b, 0x15, 0x13, 0xf6, 0xf3, 0xe0, 0x36, 0x49,
                0xfd, 0x49, 0x33, 0x76, 0x52, 0x60
            ]
        );

        let key: [u8; 25] = pbkdf2_sha256(
            b"passwordPASSWORDpassword",
            10,
            b"saltSALTsaltSALTsaltSALTsaltSALT",
        );
        assert_eq!(
            key,
            [
                0x0d, 0xbf, 0x87, 0x38, 0xd2, 0x30, 0xbf, 0x28, 0xba, 0xe0, 0xfb, 0x4d, 0x8f, 0x07,
                0x34, 0x98, 0x24, 0xb5, 0xe0, 0xb1, 0xa7, 0x0b, 0xa2, 0x19, 0x3b
            ]
        );
    }

    // Vectors from connectedhomeip src/crypto/tests/AES_CCM_128_test_vectors.h
    // (aesccm128_matter_*_test_vector_0, _10 and _11: 13-byte nonce, 16-byte tag)
    struct CcmVector {
        key: [u8; 16],
        nonce: [u8; 13],
        aad: &'static [u8],
        pt: &'static [u8],
        ct: &'static [u8],
        tag: [u8; 16],
    }

    const CCM_VECTORS: &[CcmVector] = &[
        // tcId 0: 13-byte plaintext, no AAD
        CcmVector {
            key: [
                0x09, 0x53, 0xfa, 0x93, 0xe7, 0xca, 0xac, 0x96, 0x38, 0xf5, 0x88, 0x20, 0x22, 0x0a,
                0x39, 0x8e,
            ],
            nonce: [
                0x00, 0x80, 0x00, 0x00, 0x01, 0x12, 0x01, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
            ],
            aad: &[],
            pt: &[
                0xff, 0xfd, 0x03, 0x4b, 0x50, 0x05, 0x7e, 0x40, 0x00, 0x00, 0x01, 0x00, 0x00,
            ],
            ct: &[
                0xb5, 0xe5, 0xbf, 0xda, 0xcb, 0xaf, 0x6c, 0xb7, 0xfb, 0x6b, 0xff, 0x87, 0x1f,
            ],
            tag: [
                0xb0, 0xd6, 0xdd, 0x82, 0x7d, 0x35, 0xbf, 0x37, 0x2f, 0xa6, 0x42, 0x5d, 0xcd, 0x17,
                0xd3, 0x56,
            ],
        },
        // tcId 10: 8-byte plaintext, 16-byte AAD
        CcmVector {
            key: [
                0x63, 0x96, 0x47, 0x71, 0x73, 0x4f, 0xbd, 0x76, 0xe3, 0xb4, 0x05, 0x19, 0xd1, 0xd9,
                0x4a, 0x48,
            ],
            nonce: [
                0x01, 0x00, 0x07, 0x08, 0x0d, 0x12, 0x34, 0x97, 0x36, 0x12, 0x34, 0x56, 0x77,
            ],
            aad: &[
                0xf4, 0xa0, 0x02, 0xc7, 0xfb, 0x1e, 0x4c, 0xa0, 0xa4, 0x69, 0xa0, 0x21, 0xde, 0x0d,
                0xb8, 0x75,
            ],
            pt: &[0xea, 0x0a, 0x00, 0x57, 0x6f, 0x72, 0x6c, 0x64],
            ct: &[0xde, 0x15, 0x47, 0x11, 0x84, 0x63, 0x12, 0x3e],
            tag: [
                0x14, 0x60, 0x4c, 0x1d, 0xdb, 0x4f, 0x59, 0x87, 0x06, 0x4b, 0x17, 0x36, 0xf3, 0x92,
                0x39, 0x62,
            ],
        },
        // tcId 11: empty plaintext, 1-byte AAD
        CcmVector {
            key: [
                0x08, 0xb0, 0xda, 0x25, 0x5d, 0x20, 0x83, 0x80, 0x8a, 0x1b, 0x4d, 0x36, 0x70, 0x90,
                0xba, 0xcc,
            ],
            nonce: [
                0x77, 0x78, 0x28, 0xb1, 0x36, 0x79, 0xa9, 0xe2, 0xca, 0x89, 0x56, 0x82, 0x33,
            ],
            aad: &[0xc5],
            pt: &[],
            ct: &[],
            tag: [
                0x0a, 0x93, 0xec, 0x4a, 0x8f, 0xf3, 0x39, 0x64, 0xf5, 0x80, 0x05, 0x86, 0x8a, 0x86,
                0x88, 0x56,
            ],
        },
    ];

    #[test]
    fn aes_ccm_encrypt_kat() {
        for v in CCM_VECTORS {
            let out = ccm_encrypt(&v.key, &v.nonce, v.aad, v.pt);

            assert_eq!(out.len(), v.ct.len() + AEAD_TAG_LEN);
            assert_eq!(&out[..v.ct.len()], v.ct);
            assert_eq!(&out[v.ct.len()..], &v.tag);
        }
    }

    #[test]
    fn aes_ccm_decrypt_kat() {
        for v in CCM_VECTORS {
            let mut ct_tag = v.ct.to_vec();
            ct_tag.extend_from_slice(&v.tag);

            assert_eq!(
                ccm_decrypt(&v.key, &v.nonce, v.aad, &ct_tag).as_deref(),
                Some(v.pt)
            );
        }
    }

    #[test]
    fn aes_ccm_decrypt_tampered_tag_fails() {
        let v = &CCM_VECTORS[1];

        let mut ct_tag = v.ct.to_vec();
        ct_tag.extend_from_slice(&v.tag);
        let last = ct_tag.len() - 1;
        ct_tag[last] ^= 0x01;

        assert!(ccm_decrypt(&v.key, &v.nonce, v.aad, &ct_tag).is_none());
    }

    #[test]
    fn aes_ccm_decrypt_tampered_ciphertext_fails() {
        let v = &CCM_VECTORS[1];

        let mut ct_tag = v.ct.to_vec();
        ct_tag.extend_from_slice(&v.tag);
        ct_tag[0] ^= 0x80;

        assert!(ccm_decrypt(&v.key, &v.nonce, v.aad, &ct_tag).is_none());
    }

    #[test]
    fn aes_ccm_decrypt_wrong_aad_or_nonce_fails() {
        let v = &CCM_VECTORS[1];

        let mut ct_tag = v.ct.to_vec();
        ct_tag.extend_from_slice(&v.tag);

        let mut aad = v.aad.to_vec();
        aad[3] ^= 0x01;
        assert!(ccm_decrypt(&v.key, &v.nonce, &aad, &ct_tag).is_none());

        // Dropping the AAD entirely must also fail
        assert!(ccm_decrypt(&v.key, &v.nonce, &[], &ct_tag).is_none());

        let mut nonce = v.nonce;
        nonce[12] ^= 0x01;
        assert!(ccm_decrypt(&v.key, &nonce, v.aad, &ct_tag).is_none());

        // Sanity: the untouched inputs still decrypt
        assert!(ccm_decrypt(&v.key, &v.nonce, v.aad, &ct_tag).is_some());
    }

    /// A ciphertext shorter than the tag cannot be authenticated.
    #[test]
    fn aes_ccm_decrypt_too_short_fails() {
        let v = &CCM_VECTORS[0];

        assert!(ccm_decrypt(&v.key, &v.nonce, v.aad, &v.tag[..AEAD_TAG_LEN - 1]).is_none());
    }

    /// The RFC 6979 P-256 key shared by all vectors in
    /// connectedhomeip src/crypto/tests/ECDSA_det_test_vectors.h
    const ECDSA_DET_PRIV_KEY: CanonPkcSecretKeyRef = CanonPkcSecretKeyRef::new(&[
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6,
        0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F,
        0x67, 0x21,
    ]);

    /// The uncompressed SEC1 encoding (`0x04 || X || Y`) of the public key above.
    const ECDSA_DET_PUB_KEY: CanonPkcPublicKeyRef = CanonPkcPublicKeyRef::new(&[
        0x04, 0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31, 0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35,
        0x6D, 0x68, 0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C, 0xE6, 0x69, 0x62, 0x2E, 0x60,
        0xF2, 0x9F, 0xB6, 0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99, 0xA4, 0x1A, 0xE9, 0xE9,
        0x56, 0x28, 0xBC, 0x64, 0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51, 0x77, 0xA3, 0xC2,
        0x94, 0xD4, 0x46, 0x22, 0x99,
    ]);

    /// (message, r || s) pairs from connectedhomeip src/crypto/tests/ECDSA_det_test_vectors.h
    const ECDSA_DET_VECTORS: &[(&[u8], [u8; 64])] = &[
        (
            b"sample",
            [
                0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD, 0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E,
                0x81, 0xD6, 0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91, 0xC3, 0x4D, 0x0E, 0xA8,
                0x4E, 0xAF, 0x37, 0x16, 0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41, 0xD4, 0x36,
                0xC7, 0xA1, 0xB6, 0xE2, 0x9F, 0x65, 0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06,
                0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8,
            ],
        ),
        (
            b"test",
            [
                0xF1, 0xAB, 0xB0, 0x23, 0x51, 0x83, 0x51, 0xCD, 0x71, 0xD8, 0x81, 0x56, 0x7B, 0x1E,
                0xA6, 0x63, 0xED, 0x3E, 0xFC, 0xF6, 0xC5, 0x13, 0x2B, 0x35, 0x4F, 0x28, 0xD3, 0xB0,
                0xB7, 0xD3, 0x83, 0x67, 0x01, 0x9F, 0x41, 0x13, 0x74, 0x2A, 0x2B, 0x14, 0xBD, 0x25,
                0x92, 0x6B, 0x49, 0xC6, 0x49, 0x15, 0x5F, 0x26, 0x7E, 0x60, 0xD3, 0x81, 0x4B, 0x4C,
                0x0C, 0xC8, 0x42, 0x50, 0xE4, 0x6F, 0x00, 0x83,
            ],
        ),
        // SHA-256(message) >= curve order
        (
            b"\xca\xb5\x89\x7a\x2d\xa7\x3c\x33",
            [
                0x24, 0x9E, 0x5A, 0x94, 0xCE, 0x56, 0x7B, 0x42, 0xC0, 0xCB, 0xFC, 0xF5, 0x59, 0xCE,
                0x5F, 0x95, 0x1D, 0x5A, 0xA1, 0xF5, 0xC5, 0x4A, 0x10, 0x0C, 0x17, 0x00, 0xA9, 0x91,
                0x39, 0xDB, 0x93, 0x59, 0x33, 0x71, 0xC6, 0x28, 0x79, 0x75, 0x54, 0x9A, 0x34, 0x81,
                0xD9, 0xFB, 0x5E, 0x10, 0xDB, 0x17, 0xFF, 0x7C, 0x90, 0xE1, 0xA6, 0x73, 0xB7, 0x9A,
                0xC0, 0x58, 0x9A, 0x53, 0x78, 0x7B, 0x1E, 0x38,
            ],
        ),
        // First deterministic k candidate >= curve order
        (
            b"\x0a\x1c\x40\xa8\xcd\x85\x44\x01",
            [
                0xAD, 0xC7, 0xBE, 0x41, 0x40, 0x8E, 0x47, 0x17, 0x6C, 0x47, 0x0D, 0x95, 0x78, 0xCE,
                0x5D, 0x1A, 0xF7, 0x78, 0xA2, 0x7F, 0x4B, 0x63, 0x7D, 0x1A, 0x7C, 0x3F, 0xA6, 0x7B,
                0xD6, 0xDD, 0xDE, 0x74, 0xB3, 0x42, 0x50, 0x59, 0xB4, 0xD0, 0x6F, 0xF8, 0x0B, 0x4B,
                0xE8, 0x75, 0x49, 0x07, 0xE4, 0x9D, 0x17, 0x12, 0x14, 0x74, 0xCE, 0xE3, 0x8D, 0x1F,
                0xFB, 0x30, 0x75, 0x6C, 0x39, 0xD6, 0x4C, 0xD3,
            ],
        ),
    ];

    /// Verification of the RFC 6979 deterministic signatures. Only verification
    /// is exercised, since signing is randomized on some backends.
    #[test]
    fn ecdsa_det_vectors_verify() {
        let crypto = test_only_crypto();
        let key = unwrap!(crypto.pub_key(ECDSA_DET_PUB_KEY));

        for (msg, sig) in ECDSA_DET_VECTORS {
            assert!(unwrap!(key.verify(msg, CryptoSensitiveRef::new(sig))));
        }

        // A signature over one message does not verify over another
        assert!(!unwrap!(key.verify(
            ECDSA_DET_VECTORS[1].0,
            CryptoSensitiveRef::new(&ECDSA_DET_VECTORS[0].1)
        )));
    }

    /// The public key derived from a canonical secret key matches the known point,
    /// and the secret key exports back to the same canonical bytes.
    #[test]
    fn ecdsa_secret_key_canon_roundtrip() {
        let crypto = test_only_crypto();
        let key = unwrap!(crypto.secret_key(ECDSA_DET_PRIV_KEY));

        let mut canon_priv = CanonPkcSecretKey::new();
        unwrap!(key.write_canon(&mut canon_priv));
        assert_eq!(canon_priv.access(), ECDSA_DET_PRIV_KEY.access());

        let mut canon_pub = CanonPkcPublicKey::new();
        unwrap!(unwrap!(key.pub_key()).write_canon(&mut canon_pub));
        assert_eq!(canon_pub.access(), ECDSA_DET_PUB_KEY.access());
    }

    #[test]
    fn ecdsa_sign_then_verify() {
        let crypto = test_only_crypto();
        let key = unwrap!(crypto.secret_key(ECDSA_DET_PRIV_KEY));
        let msg = b"The quick brown fox jumps over the lazy dog";

        let mut sig = CanonPkcSignature::new();
        unwrap!(key.sign(msg, &mut sig));
        assert_ne!(sig.access(), &[0u8; 64]);

        // Verifies with the matching public key (imported from canon bytes as well)
        assert!(unwrap!(unwrap!(key.pub_key()).verify(msg, sig.reference())));
        let imported = unwrap!(crypto.pub_key(ECDSA_DET_PUB_KEY));
        assert!(unwrap!(imported.verify(msg, sig.reference())));

        // Fails with a different key
        let other = unwrap!(crypto.pub_key(PUB_KEY1));
        assert!(!unwrap!(other.verify(msg, sig.reference())));

        // Fails over a tampered message
        let mut tampered = *msg;
        tampered[0] ^= 0x20;
        assert!(!unwrap!(imported.verify(&tampered, sig.reference())));

        // Fails with a tampered signature
        let mut bad_sig = sig.clone();
        bad_sig.access_mut()[63] ^= 0x01;
        assert!(!unwrap!(imported.verify(msg, bad_sig.reference())));
    }

    /// A freshly generated key is non-trivial and signs/verifies.
    #[test]
    fn ecdsa_generated_key_signs() {
        let crypto = test_only_crypto();
        let key = unwrap!(crypto.generate_secret_key());

        let mut canon = CanonPkcSecretKey::new();
        unwrap!(key.write_canon(&mut canon));
        assert_ne!(canon.access(), &[0u8; 32]);

        let mut canon_pub = CanonPkcPublicKey::new();
        unwrap!(unwrap!(key.pub_key()).write_canon(&mut canon_pub));
        assert_eq!(canon_pub.access()[0], 0x04);

        let mut sig = CanonPkcSignature::new();
        unwrap!(key.sign(b"hello", &mut sig));
        assert!(unwrap!(
            unwrap!(key.pub_key()).verify(b"hello", sig.reference())
        ));

        // Re-importing the exported canon bytes gives the same public key
        let reimported = unwrap!(crypto.secret_key(canon.reference()));
        let mut canon_pub2 = CanonPkcPublicKey::new();
        unwrap!(unwrap!(reimported.pub_key()).write_canon(&mut canon_pub2));
        assert_eq!(canon_pub.access(), canon_pub2.access());
    }

    /// The singleton signing key is the one `test_only_crypto` was built with.
    #[test]
    fn singleton_signing_key_matches_dac() {
        let crypto = test_only_crypto();

        let singleton = unwrap!(crypto.singleton_singing_secret_key());
        let mut singleton_pub = CanonPkcPublicKey::new();
        unwrap!(unwrap!(singleton.pub_key()).write_canon(&mut singleton_pub));

        let dac = unwrap!(crypto.secret_key(crate::dm::devices::test::DAC_PRIVKEY));
        let mut dac_pub = CanonPkcPublicKey::new();
        unwrap!(unwrap!(dac.pub_key()).write_canon(&mut dac_pub));

        assert_eq!(singleton_pub.access(), dac_pub.access());

        let mut sig = CanonPkcSignature::new();
        unwrap!(singleton.sign(b"attest", &mut sig));
        assert!(unwrap!(
            unwrap!(dac.pub_key()).verify(b"attest", sig.reference())
        ));

        let mut csr_buf = [0u8; 512];
        let csr = unwrap!(singleton.csr(&mut csr_buf));
        // DER SEQUENCE
        assert_eq!(csr[0], 0x30);
        assert!(csr.len() > PKC_CANON_PUBLIC_KEY_LEN);
    }

    // Vectors from connectedhomeip src/crypto/tests/ECDH_P256_test_vectors.h (ecdh_v1..v3)
    #[test]
    fn ecdh_kat() {
        const VECTORS: &[([u8; 32], [u8; 65], [u8; 32])] = &[
            (
                [
                    0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda, 0xf8, 0x0d, 0x62, 0x14, 0x63,
                    0x2e, 0xea, 0xe0, 0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e, 0xd8, 0x0b,
                    0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34,
                ],
                [
                    0x04, 0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32, 0xca,
                    0x65, 0x64, 0x0d, 0xb9, 0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4, 0x2c,
                    0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87, 0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd,
                    0x9b, 0x06, 0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5, 0x94, 0x8d, 0x46,
                    0xfb, 0xf6, 0x40, 0xdf, 0xe0, 0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac,
                ],
                [
                    0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01, 0x2e, 0x54, 0xa4, 0x34, 0xfb,
                    0xdd, 0x2d, 0x25, 0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68, 0x04, 0x0d,
                    0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b,
                ],
            ),
            (
                [
                    0xf5, 0xf8, 0xe0, 0x17, 0x46, 0x10, 0xa6, 0x61, 0x27, 0x79, 0x79, 0xb5, 0x8c,
                    0xe5, 0xc9, 0x0f, 0xee, 0x6c, 0x9b, 0x3b, 0xb3, 0x46, 0xa9, 0x0a, 0x71, 0x96,
                    0x25, 0x5e, 0x40, 0xb1, 0x32, 0xef,
                ],
                [
                    0x04, 0x33, 0xe8, 0x20, 0x92, 0xa0, 0xf1, 0xfb, 0x38, 0xf5, 0x64, 0x9d, 0x58,
                    0x67, 0xfb, 0xa2, 0x8b, 0x50, 0x31, 0x72, 0xb7, 0x03, 0x55, 0x74, 0xbf, 0x8e,
                    0x5b, 0x71, 0x00, 0xa3, 0x05, 0x27, 0x92, 0xf2, 0xcf, 0x6b, 0x60, 0x1e, 0x0a,
                    0x05, 0x94, 0x5e, 0x33, 0x55, 0x50, 0xbf, 0x64, 0x8d, 0x78, 0x2f, 0x46, 0x18,
                    0x6c, 0x77, 0x2c, 0x0f, 0x20, 0xd3, 0xcd, 0x0d, 0x6b, 0x8c, 0xa1, 0x4b, 0x2f,
                ],
                [
                    0x66, 0x4e, 0x45, 0xd5, 0xbb, 0xa4, 0xac, 0x93, 0x1c, 0xd6, 0x5d, 0x52, 0x01,
                    0x7e, 0x4b, 0xe9, 0xb1, 0x9a, 0x51, 0x5f, 0x66, 0x9b, 0xea, 0x47, 0x03, 0x54,
                    0x2a, 0x2c, 0x52, 0x5c, 0xd3, 0xd3,
                ],
            ),
            // Shared secret with a leading zero byte
            (
                [
                    0x7A, 0xE6, 0x7A, 0xFC, 0xF2, 0x50, 0x5C, 0x12, 0xB7, 0x60, 0x0F, 0xA2, 0x25,
                    0x85, 0x9A, 0xFE, 0x36, 0xFA, 0x01, 0xE7, 0xB0, 0x78, 0x9C, 0xF5, 0x9B, 0x06,
                    0xA1, 0xC9, 0xB8, 0xEF, 0x90, 0xD2,
                ],
                [
                    0x04, 0x19, 0x6C, 0x32, 0xA9, 0x90, 0x1B, 0xDC, 0x81, 0x70, 0x28, 0x0C, 0x78,
                    0x94, 0x71, 0x32, 0xB9, 0x2C, 0x9A, 0x7B, 0x8D, 0x4F, 0x59, 0x7A, 0x18, 0x33,
                    0x71, 0x25, 0x45, 0x8C, 0xCF, 0x92, 0x56, 0x1B, 0xA3, 0x80, 0x9E, 0xC1, 0xB9,
                    0x66, 0x8A, 0x29, 0x03, 0x68, 0x66, 0xE6, 0xD8, 0x45, 0x89, 0x11, 0x01, 0x3E,
                    0x2E, 0x78, 0xF9, 0x29, 0x6E, 0x86, 0xD6, 0x81, 0x7F, 0x7A, 0xE6, 0xF3, 0x09,
                ],
                [
                    0x00, 0x13, 0xB5, 0x76, 0xC6, 0xC0, 0x27, 0x02, 0xB1, 0xB6, 0x6C, 0x67, 0xFA,
                    0xB4, 0x6D, 0xA8, 0x54, 0x88, 0x0A, 0x39, 0xD7, 0x5F, 0xA7, 0x44, 0x64, 0x1F,
                    0xFA, 0x61, 0x11, 0x82, 0x3A, 0x4E,
                ],
            ),
        ];

        let crypto = test_only_crypto();

        for (priv_key, peer_pub, expected) in VECTORS {
            let key = unwrap!(crypto.secret_key(CryptoSensitiveRef::new(priv_key)));
            let peer = unwrap!(crypto.pub_key(CryptoSensitiveRef::new(peer_pub)));

            let mut shared = CanonPkcSharedSecret::new();
            unwrap!(key.derive_shared_secret(&peer, &mut shared));

            assert_eq!(shared.access(), expected);
        }
    }

    /// ECDH is symmetric: both sides derive the same secret, and a third
    /// key derives something else.
    #[test]
    fn ecdh_symmetric() {
        let crypto = test_only_crypto();

        let a = unwrap!(crypto.generate_secret_key());
        let b = unwrap!(crypto.generate_secret_key());
        let c = unwrap!(crypto.generate_secret_key());

        let mut ab = CanonPkcSharedSecret::new();
        unwrap!(a.derive_shared_secret(&unwrap!(b.pub_key()), &mut ab));

        let mut ba = CanonPkcSharedSecret::new();
        unwrap!(b.derive_shared_secret(&unwrap!(a.pub_key()), &mut ba));

        let mut cb = CanonPkcSharedSecret::new();
        unwrap!(c.derive_shared_secret(&unwrap!(b.pub_key()), &mut cb));

        assert_eq!(ab.access(), ba.access());
        assert_ne!(ab.access(), cb.access());
        assert_ne!(ab.access(), &[0u8; 32]);
    }

    /// Importing a byte string that is not a point on the curve fails.
    #[test]
    fn pub_key_import_rejects_invalid_point() {
        let crypto = test_only_crypto();

        let mut bad = *PUB_KEY1.access();
        bad[64] ^= 0x01;

        assert!(crypto.pub_key(CryptoSensitiveRef::new(&bad)).is_err());
    }

    #[test]
    fn rand_draws_differ() {
        let crypto = test_only_crypto();

        let mut rng = unwrap!(crypto.rand());
        let a = rng.next_u32();
        let b = rng.next_u32();
        let c = rng.next_u64();
        assert!(a != b || c != a as u64);

        let mut x = [0u8; 16];
        let mut y = [0u8; 16];
        rng.fill_bytes(&mut x);
        rng.fill_bytes(&mut y);
        assert_ne!(x, y);

        let mut weak = unwrap!(crypto.weak_rand());
        let mut wx = [0u8; 16];
        let mut wy = [0u8; 16];
        weak.fill_bytes(&mut wx);
        weak.fill_bytes(&mut wy);
        assert_ne!(wx, wy);
    }

    #[test]
    fn rand_fill_large_buffer_is_nonzero() {
        let crypto = test_only_crypto();

        let mut rng = unwrap!(crypto.rand());
        let mut buf = [0u8; 1024];
        rng.fill_bytes(&mut buf);

        assert!(buf.iter().any(|b| *b != 0));
        // Every 64-byte window should have some entropy in it
        assert!(buf.chunks(64).all(|c| c.iter().any(|b| *b != 0)));

        // An odd-length fill also works
        let mut odd = [0u8; 33];
        rng.fill_bytes(&mut odd);
        assert!(odd.iter().any(|b| *b != 0));
    }

    // Vector v08 from connectedhomeip src/crypto/tests/Hash_SHA256_test_vectors.h (59 bytes)
    const SHA256_DATA08: &[u8] = &[
        0xd1, 0xbe, 0x3f, 0x13, 0xfe, 0xba, 0xfe, 0xfc, 0x14, 0x41, 0x4d, 0x9f, 0xb7, 0xf6, 0x93,
        0xdb, 0x16, 0xdc, 0x1a, 0xe2, 0x70, 0xc5, 0xb6, 0x47, 0xd8, 0x0d, 0xa8, 0x58, 0x35, 0x87,
        0xc1, 0xad, 0x8c, 0xb8, 0xcb, 0x01, 0x82, 0x43, 0x24, 0x41, 0x1c, 0xa5, 0xac, 0xe3, 0xca,
        0x22, 0xe1, 0x79, 0xa4, 0xff, 0x49, 0x86, 0xf3, 0xf2, 0x11, 0x90, 0xf3, 0xd7, 0xf3,
    ];

    const SHA256_HASH08: [u8; HASH_LEN] = [
        0x02, 0x80, 0x49, 0x78, 0xeb, 0xa6, 0xe1, 0xde, 0x65, 0xaf, 0xdb, 0xc6, 0xa6, 0x09, 0x1e,
        0xd6, 0xb1, 0xec, 0xee, 0x51, 0xe8, 0xbf, 0xf4, 0x06, 0x46, 0xa2, 0x51, 0xde, 0x66, 0x78,
        0xb7, 0xef,
    ];

    #[test]
    fn test_verify_msg_success() {
        let crypto = test_only_crypto();

        let key = unwrap!(crypto.pub_key(PUB_KEY1));
        assert_eq!(unwrap!(key.verify(MSG1_SUCCESS, SIGNATURE1)), true);
    }

    #[test]
    fn test_verify_msg_fail() {
        let crypto = test_only_crypto();

        let key = unwrap!(crypto.pub_key(PUB_KEY1));
        assert_eq!(unwrap!(key.verify(MSG1_FAIL, SIGNATURE1)), false);
    }

    const PUB_KEY1: CanonPkcPublicKeyRef = CanonPkcPublicKeyRef::new(&[
        0x4, 0x56, 0x19, 0x77, 0x18, 0x3f, 0xd4, 0xff, 0x2b, 0x58, 0x3d, 0xe9, 0x79, 0x34, 0x66,
        0xdf, 0xe9, 0x0, 0xfb, 0x6d, 0xa1, 0xef, 0xe0, 0xcc, 0xdc, 0x77, 0x30, 0xc0, 0x6f, 0xb6,
        0x2d, 0xff, 0xbe, 0x54, 0xa0, 0x95, 0x75, 0xb, 0x8b, 0x7, 0xbc, 0x55, 0xdb, 0x9c, 0xb6,
        0x55, 0x13, 0x8, 0xb8, 0xdf, 0x2, 0xe3, 0x40, 0x6b, 0xae, 0x34, 0xf5, 0xc, 0xba, 0xc9,
        0xf2, 0xbf, 0xf1, 0xe7, 0x50,
    ]);

    const MSG1_SUCCESS: &[u8] = &[
        0x30, 0x82, 0x1, 0xa1, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2, 0x1, 0x1, 0x30, 0xa, 0x6, 0x8, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x30, 0x44, 0x31, 0x20, 0x30, 0x1e, 0x6, 0xa, 0x2b,
        0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x1, 0x3, 0xc, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x31, 0x20, 0x30, 0x1e,
        0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x1, 0x5, 0xc, 0x10, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x30,
        0x1e, 0x17, 0xd, 0x32, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5a, 0x17, 0xd, 0x33, 0x30, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5a, 0x30, 0x44, 0x31, 0x20, 0x30, 0x1e, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2,
        0x7c, 0x1, 0x1, 0xc, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x42, 0x43, 0x35, 0x43, 0x30, 0x32, 0x31, 0x20, 0x30, 0x1e, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4,
        0x1, 0x82, 0xa2, 0x7c, 0x1, 0x5, 0xc, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7,
        0x3, 0x42, 0x0, 0x4, 0x6, 0x47, 0xf2, 0x86, 0x4d, 0x27, 0x25, 0xdc, 0x1, 0xa, 0x87, 0xde,
        0x8d, 0xca, 0x88, 0x37, 0xcb, 0x3b, 0xd0, 0xea, 0x93, 0xa6, 0x24, 0x65, 0x8, 0x8f, 0xa1,
        0x75, 0xc2, 0xd4, 0x41, 0xfa, 0xca, 0x96, 0x54, 0xa3, 0xd8, 0x10, 0x85, 0x73, 0xce, 0x15,
        0xa5, 0x38, 0xc1, 0xe3, 0xb5, 0x6b, 0x61, 0x1, 0xd3, 0xc4, 0xb7, 0x6b, 0x61, 0x16, 0xc3,
        0x77, 0x8d, 0xe9, 0xb5, 0x44, 0xac, 0x14, 0xa3, 0x81, 0x83, 0x30, 0x81, 0x80, 0x30, 0xc,
        0x6, 0x3, 0x55, 0x1d, 0x13, 0x1, 0x1, 0xff, 0x4, 0x2, 0x30, 0x0, 0x30, 0xe, 0x6, 0x3, 0x55,
        0x1d, 0xf, 0x1, 0x1, 0xff, 0x4, 0x4, 0x3, 0x2, 0x7, 0x80, 0x30, 0x20, 0x6, 0x3, 0x55, 0x1d,
        0x25, 0x1, 0x1, 0xff, 0x4, 0x16, 0x30, 0x14, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3,
        0x2, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3, 0x1, 0x30, 0x1d, 0x6, 0x3, 0x55, 0x1d,
        0xe, 0x4, 0x16, 0x4, 0x14, 0xbd, 0xfd, 0x11, 0xac, 0x89, 0xb6, 0xe0, 0x90, 0x7a, 0xf6,
        0x12, 0x61, 0x78, 0x4d, 0x3d, 0x79, 0x56, 0xeb, 0xc2, 0xdc, 0x30, 0x1f, 0x6, 0x3, 0x55,
        0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0xce, 0x60, 0xb4, 0x28, 0x96, 0x72, 0x27,
        0x64, 0x81, 0xbc, 0x4f, 0x0, 0x78, 0xa3, 0x30, 0x48, 0xfe, 0x6e, 0x65, 0x86,
    ];

    const MSG1_FAIL: &[u8] = &[
        0x30, 0x82, 0x1, 0xa1, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2, 0x1, 0x1, 0x30, 0xa, 0x6, 0x8, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x30, 0x44, 0x31, 0x20, 0x30, 0x1e, 0x6, 0xa, 0x2b,
        0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x1, 0x3, 0xc, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x31, 0x20, 0x30, 0x1e,
        0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x1, 0x5, 0xc, 0x10, 0x30, 0x30,
        0x30, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x30,
        0x1e, 0x17, 0xd, 0x32, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5a, 0x17, 0xd, 0x33, 0x30, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5a, 0x30, 0x44, 0x31, 0x20, 0x30, 0x1e, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2,
        0x7c, 0x1, 0x1, 0xc, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x42, 0x43, 0x35, 0x43, 0x30, 0x32, 0x31, 0x20, 0x30, 0x1e, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4,
        0x1, 0x82, 0xa2, 0x7c, 0x1, 0x5, 0xc, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7,
        0x3, 0x42, 0x0, 0x4, 0x6, 0x47, 0xf2, 0x86, 0x4d, 0x27, 0x25, 0xdc, 0x1, 0xa, 0x87, 0xde,
        0x8d, 0xca, 0x88, 0x37, 0xcb, 0x3b, 0xd0, 0xea, 0x93, 0xa6, 0x24, 0x65, 0x8, 0x8f, 0xa1,
        0x75, 0xc2, 0xd4, 0x41, 0xfa, 0xca, 0x96, 0x54, 0xa3, 0xd8, 0x10, 0x85, 0x73, 0xce, 0x15,
        0xa5, 0x38, 0xc1, 0xe3, 0xb5, 0x6b, 0x61, 0x1, 0xd3, 0xc4, 0xb7, 0x6b, 0x61, 0x16, 0xc3,
        0x77, 0x8d, 0xe9, 0xb5, 0x44, 0xac, 0x14, 0xa3, 0x81, 0x83, 0x30, 0x81, 0x80, 0x30, 0xc,
        0x6, 0x3, 0x55, 0x1d, 0x13, 0x1, 0x1, 0xff, 0x4, 0x2, 0x30, 0x0, 0x30, 0xe, 0x6, 0x3, 0x55,
        0x1d, 0xf, 0x1, 0x1, 0xff, 0x4, 0x4, 0x3, 0x2, 0x7, 0x80, 0x30, 0x20, 0x6, 0x3, 0x55, 0x1d,
        0x25, 0x1, 0x1, 0xff, 0x4, 0x16, 0x30, 0x14, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3,
        0x2, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3, 0x1, 0x30, 0x1d, 0x6, 0x3, 0x55, 0x1d,
        0xe, 0x4, 0x16, 0x4, 0x14, 0xbd, 0xfd, 0x11, 0xac, 0x89, 0xb6, 0xe0, 0x90, 0x7a, 0xf6,
        0x12, 0x61, 0x78, 0x4d, 0x3d, 0x79, 0x56, 0xeb, 0xc2, 0xdc, 0x30, 0x1f, 0x6, 0x3, 0x55,
        0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0xce, 0x60, 0xb4, 0x28, 0x96, 0x72, 0x27,
        0x64, 0x81, 0xbc, 0x4f, 0x0, 0x78, 0xa3, 0x30, 0x48, 0xfe, 0x6e, 0x65, 0x86,
    ];

    const SIGNATURE1: CanonPkcSignatureRef = CanonPkcSignatureRef::new(&[
        0x20, 0x16, 0xd0, 0x13, 0x1e, 0xd0, 0xb3, 0x9d, 0x44, 0x25, 0x16, 0xea, 0x9c, 0xf2, 0x72,
        0x44, 0xd7, 0xb0, 0xf4, 0xae, 0x4a, 0xa4, 0x37, 0x32, 0xcd, 0x6a, 0x79, 0x7a, 0x4c, 0x48,
        0x3, 0x6d, 0xef, 0xe6, 0x26, 0x82, 0x39, 0x28, 0x9, 0x22, 0xc8, 0x9a, 0xde, 0xd5, 0x13,
        0x9f, 0xc5, 0x40, 0x25, 0x85, 0x2c, 0x69, 0xe0, 0xdb, 0x6a, 0x79, 0x5b, 0x21, 0x82, 0x13,
        0xb0, 0x20, 0xb9, 0x69,
    ]);
}
