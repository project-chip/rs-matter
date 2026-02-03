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

//! Cryptographic abstractions and backend.

use core::fmt::Debug;

use embassy_sync::blocking_mutex::raw::RawMutex;

pub use rand_core::{CryptoRng, CryptoRngCore, RngCore};

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, zeroed, Init, IntoFallibleInit};
use crate::utils::sync::blocking::Mutex;

pub mod dummy;
#[cfg(feature = "mbedtls")]
pub mod mbedtls;
#[cfg(feature = "openssl")]
pub mod openssl;
#[cfg(feature = "rustcrypto")]
pub mod rustcrypto;

/// Length of the hash returned by the hasher (`Crypto::hash`) in bytes.
///
/// As per the Matter spec, the hasher should be SHA-256.
pub const HASH_LEN: usize = 32;

/// Length of the HMAC hash returned by the HMAC hasher (`Crypto::hmac`) in bytes.
///
/// As per the Matter spec, the HMAC hasher should be HMAC-SHA-256.
pub const HMAC_HASH_LEN: usize = HASH_LEN;

/// Length of the canonical representation of an EC scalar in bytes.
///
/// As per the Matter spec, the curve used is secp256r1 (NIST P-256).
pub const EC_CANON_SCALAR_LEN: usize = 32;

/// Length of the canonical representation of an EC point in bytes.
///
/// As per the Matter spec, the curve used is secp256r1 (NIST P-256).
pub const EC_CANON_POINT_LEN: usize = EC_CANON_SCALAR_LEN * 2 + 1;

/// Length of the canonical representation of a public key in bytes.
///
/// As per the Matter spec, the used Public Key Cryptograqphy should be
/// Elliptic-Curve based, and specifically secp256r1 (NIST P-256).
///
/// Note that this is the same as `EC_CANON_POINT_LEN`.
pub const PKC_CANON_PUBLIC_KEY_LEN: usize = EC_CANON_POINT_LEN;

/// Length of the canonical representation of a secret key in bytes.
///
/// As per the Matter spec, the used Public Key Cryptograqphy should be
/// Elliptic-Curve based, and specifically secp256r1 (NIST P-256).
///
/// Note that this is the same as `EC_CANON_SCALAR_LEN`.
pub const PKC_CANON_SECRET_KEY_LEN: usize = EC_CANON_SCALAR_LEN;

/// Length of the canonical representation of a signature in bytes.
///
/// As per the Matter spec, the used Public Key Cryptograqphy should be
/// Elliptic-Curve based, and specifically secp256r1 (NIST P-256).
///
/// Note that this is `2 * EC_CANON_SCALAR_LEN`, as the signature contains
/// the (r, s) scalars computed using ECDSA.
pub const PKC_SIGNATURE_LEN: usize = PKC_CANON_SECRET_KEY_LEN * 2;

/// Length of the canonical representation of a shared secret in bytes.
///
/// As per the Matter spec, the used Public Key Cryptograqphy should be
/// Elliptic-Curve based, and specifically secp256r1 (NIST P-256).
///
/// The shared secret is the ECDH computed value.
pub const PKC_SHARED_SECRET_LEN: usize = 32;

/// Length of the canonical representation of a 320-bit unsigned integer in bytes.
///
/// As per the Matter spec, this is used in the SPAKE2+ protocol.
pub const UINT320_CANON_LEN: usize = 40;

/// Length of the canonical representation of an AEAD key in bytes.
///
/// As per the Matter spec, the AEAD algorithm used is AES-CCM with 128-bit keys.
pub const AEAD_CANON_KEY_LEN: usize = 16;

/// Length of the nonce used in AEAD operations in bytes.
///
/// As per the Matter spec, the AEAD algorithm used is AES-CCM with a 13-byte nonce.
pub const AEAD_NONCE_LEN: usize = 13;

/// Length of the tag produced by AEAD operations in bytes.
///
/// As per the Matter spec, the AEAD algorithm used is AES-CCM with a 16-byte tag.
pub const AEAD_TAG_LEN: usize = 16;

/// Canonical representation of a hash value.
///
/// As per the Matter spec, the hasher should be SHA-256.
pub type Hash = CryptoSensitive<HASH_LEN>;

pub type HashRef<'a> = CryptoSensitiveRef<'a, HASH_LEN>;

/// Zeroed hash value.
pub const HASH_ZEROED: Hash = Hash::new();

/// Canonical representation of an HMAC hash value.
///
/// As per the Matter spec, the HMAC hasher should be HMAC-SHA-256.
pub type HmacHash = CryptoSensitive<HMAC_HASH_LEN>;

pub type HmacHashRef<'a> = CryptoSensitiveRef<'a, HMAC_HASH_LEN>;

/// Zeroed HMAC hash value.
pub const HMAC_HASH_ZEROED: Hash = HmacHash::new();

/// Canonical representation of a 320-bit unsigned integer (BE format).
pub type CanonUint320 = CryptoSensitive<UINT320_CANON_LEN>;

pub type CanonUint320Ref<'a> = CryptoSensitiveRef<'a, UINT320_CANON_LEN>;

/// Zeroed 320-bit unsigned integer.
pub const UINT320_ZEROED: CanonUint320 = CanonUint320::new();

/// Canonical representation of an AEAD key.
///
/// As per the Matter spec, the AEAD algorithm used is AES-CCM with 128-bit keys.
pub type CanonAeadKey = CryptoSensitive<AEAD_CANON_KEY_LEN>;

pub type CanonAeadKeyRef<'a> = CryptoSensitiveRef<'a, AEAD_CANON_KEY_LEN>;

/// Zeroed AEAD key.
pub const AEAD_KEY_ZEROED: CanonAeadKey = CanonAeadKey::new();

/// Canonical representation of an AEAD nonce.
///
/// As per the Matter spec, the AEAD algorithm used is AES-CCM with a 13-byte nonce.
pub type AeadNonce = CryptoSensitive<AEAD_NONCE_LEN>;

pub type AeadNonceRef<'a> = CryptoSensitiveRef<'a, AEAD_NONCE_LEN>;

/// Zeroed AEAD nonce.
pub const AEAD_NONCE_ZEROED: AeadNonce = AeadNonce::new();

/// Canonical representation of an AEAD tag.
///
/// As per the Matter spec, the AEAD algorithm used is AES-CCM with a 16-byte tag.
pub type AeadTag = CryptoSensitive<AEAD_TAG_LEN>;

pub type AeadTagRef<'a> = CryptoSensitiveRef<'a, AEAD_TAG_LEN>;

/// Zeroed AEAD tag.
pub const AEAD_TAG_ZEROED: AeadTag = AeadTag::new();

/// Canonical representation of an EC scalar.
///
/// As per the Matter spec, the curve used is secp256r1 (NIST P-256).
pub type CanonEcScalar = CryptoSensitive<EC_CANON_SCALAR_LEN>;

pub type CanonEcScalarRef<'a> = CryptoSensitiveRef<'a, EC_CANON_SCALAR_LEN>;

/// Zeroed EC scalar.
pub const EC_SCALAR_ZEROED: CanonEcScalar = CanonEcScalar::new();

/// Canonical representation of an EC point (one byte prefix and then two affine scalar coordinates),
/// uncompressed.
///
/// As per the Matter spec, the curve used is secp256r1 (NIST P-256).
pub type CanonEcPoint = CryptoSensitive<EC_CANON_POINT_LEN>;

pub type CanonEcPointRef<'a> = CryptoSensitiveRef<'a, EC_CANON_POINT_LEN>;

/// Zeroed EC point.
pub const EC_POINT_ZEROED: CanonEcPoint = CanonEcPoint::new();

/// Canonical representation of a Public Key Cryptography secret key.
///
/// As per the Matter spec, the used Public Key Cryptograqphy should be
/// Elliptic-Curve based, and specifically secp256r1 (NIST P-256).
///
/// Note that this is the same as `CanonEcScalar`.
pub type CanonPkcSecretKey = CanonEcScalar;

pub type CanonPkcSecretKeyRef<'a> = CanonEcScalarRef<'a>;

/// Zeroed PKC secret key.
pub const PKC_SECRET_KEY_ZEROED: CanonPkcSecretKey = EC_SCALAR_ZEROED;

/// Canonical representation of a Public Key Cryptography public key.
///
/// As per the Matter spec, the used Public Key Cryptograqphy should be
/// Elliptic-Curve based, and specifically secp256r1 (NIST P-256).
///
/// Note that this is the same as `CanonEcPoint`.
pub type CanonPkcPublicKey = CanonEcPoint;

pub type CanonPkcPublicKeyRef<'a> = CanonEcPointRef<'a>;

/// Zeroed PKC public key.
pub const PKC_PUBLIC_KEY_ZEROED: CanonPkcPublicKey = EC_POINT_ZEROED;

/// Canonical representation of a Public Key Cryptography signature.
///
/// As per the Matter spec, the used Public Key Cryptograqphy should be
/// Elliptic-Curve based, and specifically secp256r1 (NIST P-256).
///
/// Note that this is `2 * EC_CANON_SCALAR_LEN`, as the signature contains
/// the (r, s) scalars computed using ECDSA.
pub type CanonPkcSignature = CryptoSensitive<PKC_SIGNATURE_LEN>;

pub type CanonPkcSignatureRef<'a> = CryptoSensitiveRef<'a, PKC_SIGNATURE_LEN>;

/// Zeroed PKC signature.
pub const EC_SIGNATURE_ZEROED: CanonPkcSignature = CryptoSensitive::new();

/// Canonical representation of a Public Key Cryptography shared secret.
///
/// As per the Matter spec, the used Public Key Cryptograqphy should be
/// Elliptic-Curve based, and specifically secp256r1 (NIST P-256).
///
/// The shared secret is the ECDH computed value.
pub type CanonPkcSharedSecret = CryptoSensitive<PKC_SHARED_SECRET_LEN>;

pub type CanonPkcSharedSecretRef<'a> = CryptoSensitiveRef<'a, PKC_SHARED_SECRET_LEN>;

/// Zeroed PKC shared secret.
pub const PKC_SHARED_SECRET_ZEROED: CanonPkcSharedSecret = CryptoSensitive::new();

#[derive(Clone)]
pub struct CryptoSensitive<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> CryptoSensitive<N> {
    #[inline(always)]
    pub const fn new() -> Self {
        Self { data: [0u8; N] }
    }

    pub const fn new_from_ref(other: CryptoSensitiveRef<'_, N>) -> Self {
        let mut this = Self::new();

        this.load(other);

        this
    }

    #[inline(always)]
    pub fn init() -> impl Init<Self> {
        init!(Self {
            data <- zeroed(),
        })
    }

    pub fn zeroize(&mut self) {
        for b in &mut self.data {
            *b = 0;
        }
    }

    pub const fn reference(&self) -> CryptoSensitiveRef<'_, N> {
        CryptoSensitiveRef::new(&self.data)
    }

    pub const fn load(&mut self, other: CryptoSensitiveRef<'_, N>) {
        self.load_from_array(other.access());
    }

    pub const fn load_from_array(&mut self, data: &[u8; N]) {
        self.data.copy_from_slice(data);
    }

    pub fn try_load_from_slice(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() != N {
            return Err(ErrorCode::InvalidData.into());
        }

        self.data.copy_from_slice(data);

        Ok(())
    }

    pub const fn access(&self) -> &[u8; N] {
        &self.data
    }

    pub const fn access_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }
}

impl<const N: usize> Drop for CryptoSensitive<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> Default for CryptoSensitive<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Debug for CryptoSensitive<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CryptoSensitive<{}>(**hidden**)", N)
    }
}

#[cfg(feature = "defmt")]
impl<const N: usize> defmt::Format for CryptoSensitive<N> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "CryptoSensitive<{}>(**hidden**)", N);
    }
}

impl<const N: usize> From<CryptoSensitiveRef<'_, N>> for CryptoSensitive<N> {
    fn from(other: CryptoSensitiveRef<'_, N>) -> Self {
        let mut material = CryptoSensitive::new();

        material.load(other);

        material
    }
}

impl<const N: usize> From<&[u8; N]> for CryptoSensitive<N> {
    fn from(data: &[u8; N]) -> Self {
        let mut material = CryptoSensitive::new();

        material.load_from_array(data);

        material
    }
}

impl<const N: usize> From<[u8; N]> for CryptoSensitive<N> {
    fn from(data: [u8; N]) -> Self {
        let mut material = CryptoSensitive::new();

        material.load_from_array(&data);

        material
    }
}

impl<const N: usize> TryFrom<&[u8]> for CryptoSensitive<N> {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut material = CryptoSensitive::new();

        material.try_load_from_slice(data)?;

        Ok(material)
    }
}

impl<'a, const N: usize> FromTLV<'a> for CryptoSensitive<N> {
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, crate::error::Error> {
        Ok(Self {
            data: element
                .str()?
                .try_into()
                .map_err(|_| ErrorCode::ConstraintError)?,
        })
    }

    fn init_from_tlv(element: TLVElement<'a>) -> impl Init<Self, Error> {
        Init::chain(Self::init().into_fallible(), move |this| {
            let data = element.str()?;
            if data.len() != N {
                Err(ErrorCode::ConstraintError)?;
            }

            this.access_mut().copy_from_slice(data);

            Ok(())
        })
    }
}

impl<const N: usize> ToTLV for CryptoSensitive<N> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.str(tag, &self.data)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        TLV::str(tag, self.data.as_slice()).into_tlv_iter()
    }
}

#[derive(Copy, Clone)]
pub struct CryptoSensitiveRef<'a, const N: usize> {
    data: &'a [u8; N],
}

impl<'a, const N: usize> CryptoSensitiveRef<'a, N> {
    #[inline(always)]
    pub const fn new(material: &'a [u8; N]) -> Self {
        Self { data: material }
    }

    #[inline(always)]
    pub fn new_from_slice(material: &'a [u8]) -> Self {
        assert_eq!(material.len(), N);

        Self::new(Self::as_array(material).unwrap()) // TODO
    }

    #[inline(always)]
    pub fn try_new(material: &'a [u8]) -> Result<Self, Error> {
        if material.len() != N {
            Err(ErrorCode::InvalidData)?;
        }

        Ok(Self::new(Self::as_array(material).unwrap())) // TODO
    }

    pub fn split<const M1: usize, const M2: usize>(
        &self,
    ) -> (CryptoSensitiveRef<'a, M1>, CryptoSensitiveRef<'a, M2>) {
        let (left, right) = self.data.split_at(M1);

        (
            CryptoSensitiveRef::new_from_slice(left),
            CryptoSensitiveRef::new_from_slice(right),
        )
    }

    pub const fn access(&self) -> &'a [u8; N] {
        self.data
    }

    // TODO: `as_array` is not yet const fn in Rust core
    const fn as_array<const L: usize>(slice: &'a [u8]) -> Option<&'a [u8; L]> {
        if slice.len() == L {
            let ptr = slice.as_ptr() as *const [u8; L];

            // SAFETY: The underlying array of a slice can be reinterpreted as an actual array `[T; N]` if `N` is not greater than the slice's length.
            let me = unsafe { &*ptr };
            Some(me)
        } else {
            None
        }
    }
}

impl<const N: usize> Debug for CryptoSensitiveRef<'_, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CryptoSensitiveRef<{}>(**hidden**)", N)
    }
}

#[cfg(feature = "defmt")]
impl<const N: usize> defmt::Format for CryptoSensitiveRef<'_, N> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "CryptoSensitiveRef<{}>(**hidden**)", N);
    }
}

impl<'a, const N: usize> From<&'a CryptoSensitive<N>> for CryptoSensitiveRef<'a, N> {
    fn from(cs: &'a CryptoSensitive<N>) -> Self {
        cs.reference()
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for CryptoSensitiveRef<'a, N> {
    fn from(data: &'a [u8; N]) -> Self {
        Self::new(data)
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8]> for CryptoSensitiveRef<'a, N> {
    type Error = Error;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_new(data)
    }
}

/// Trait representing a cryptographic backend.
///
/// The backend should provide all the cryptographic primitives required by the Matter spec.
///
/// The trait is designed in a way where it allows customizing a concrete implementation by
/// swapping out its out of the box algorithms with custom (potentially HW-accelerated) ones,
/// by decorating the original implementation and replacing only the required types and methods.
pub trait Crypto {
    type Rand<'a>: CryptoRngCore + Copy
    where
        Self: 'a;

    type WeakRand<'a>: RngCore + Copy
    where
        Self: 'a;

    /// Hasher type returned by `Crypto::hash`.
    ///
    /// As per the Matter spec, the hasher should be SHA-256.
    type Hash<'a>: Digest<HASH_LEN>
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

    /// 320-bit unsigned integer type returned by `Crypto::uint320`.
    type UInt320<'a>: UInt<'a, UINT320_CANON_LEN>
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

    /// Create a 320-bit unsigned integer instance from its canonical representation.
    fn uint320(&self, uint: CanonUint320Ref<'_>) -> Result<Self::UInt320<'_>, Error>;

    /// Create an EC scalar instance from its canonical representation.
    fn ec_scalar(&self, scalar: CanonEcScalarRef<'_>) -> Result<Self::EcScalar<'_>, Error>;

    /// Generate a new random EC scalar instance.
    fn generate_ec_scalar(&self) -> Result<Self::EcScalar<'_>, Error>;

    /// Create an EC point instance from its canonical representation.
    fn ec_point(&self, point: CanonEcPointRef<'_>) -> Result<Self::EcPoint<'_>, Error>;

    /// Get the EC Generator point.
    fn ec_generator_point(&self) -> Result<Self::EcPoint<'_>, Error>;

    /// Get the EC prime modulus as an EC scalar.
    fn ec_prime_modulus(&self) -> Result<Self::EcScalar<'_>, Error>;
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

    type UInt320<'a>
        = T::UInt320<'a>
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

    fn uint320(&self, uint: CanonUint320Ref<'_>) -> Result<Self::UInt320<'_>, Error> {
        (*self).uint320(uint)
    }

    fn ec_scalar(&self, scalar: CanonEcScalarRef<'_>) -> Result<Self::EcScalar<'_>, Error> {
        (*self).ec_scalar(scalar)
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

    fn ec_prime_modulus(&self) -> Result<Self::EcScalar<'_>, Error> {
        (*self).ec_prime_modulus()
    }
}

/// Trait representing a generic digest (hash) algorithm.
///
/// The digest algorithm should support incremental updates and finalization.
///
/// Used for both hashing and HMAC.
pub trait Digest<const HASH_LEN: usize>: Clone {
    /// Update the digest with the given data.
    fn update(&mut self, data: &[u8]);

    /// Finish the digest and write the result into the given buffer.
    fn finish(self, hash: &mut CryptoSensitive<HASH_LEN>);
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
    );
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
    fn pub_key(&self) -> Self::PublicKey<'a>;

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
    fn sign(&self, data: &[u8], signature: &mut CryptoSensitive<SIGNATURE_LEN>);
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
    );

    /// Write the canonical representation of this secret key into the given buffer.
    fn write_canon(&self, key: &mut CryptoSensitive<KEY_LEN>);
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
    fn verify(&self, data: &[u8], signature: CryptoSensitiveRef<SIGNATURE_LEN>) -> bool;

    /// Write the canonical representation of this public key into the given buffer.
    fn write_canon(&self, key: &mut CryptoSensitive<KEY_LEN>);
}

impl<'a, const KEY_LEN: usize, const SIGNATURE_LEN: usize, T> PublicKey<'a, KEY_LEN, SIGNATURE_LEN>
    for &T
where
    T: PublicKey<'a, KEY_LEN, SIGNATURE_LEN>,
{
    fn verify(&self, data: &[u8], signature: CryptoSensitiveRef<SIGNATURE_LEN>) -> bool {
        (*self).verify(data, signature)
    }

    fn write_canon(&self, key: &mut CryptoSensitive<KEY_LEN>) {
        (*self).write_canon(key)
    }
}

/// Trait representing a generic unsigned integer of fixed length in BE format.
pub trait UInt<'a, const LEN: usize>: Sized {
    /// Compute the remainder of this integer divided by another integer.
    ///
    /// # Arguments
    /// - `other`: The divisor integer.
    ///
    /// # Returns
    /// - On success, returns `Some(result)` where `result` is the remainder.
    /// - If division by zero is attempted, returns `None`.
    fn rem(&self, other: &Self) -> Option<Self>;

    /// Write the canonical representation of this integer into the given buffer.
    fn write_canon(&self, uint: &mut CryptoSensitive<LEN>);
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
    fn mul(&self, other: &Self) -> Self;

    /// Write the canonical representation of this scalar into the given buffer.
    fn write_canon(&self, scalar: &mut CryptoSensitive<LEN>);
}

/// Trait representing an Elliptic Curve (EC) point.
pub trait EcPoint<'a, const LEN: usize, const SCALAR_LEN: usize> {
    /// Scalar type associated with this EC point.
    type Scalar<'s>: EcScalar<'s, SCALAR_LEN>
    where
        Self: 'a + 's;

    /// Negate this EC point.
    fn neg(&self) -> Self;

    /// Multiply this EC point by the given scalar.
    fn mul(&self, scalar: &Self::Scalar<'a>) -> Self;

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
    fn add_mul(&self, s1: &Self::Scalar<'a>, p2: &Self, s2: &Self::Scalar<'a>) -> Self;

    /// Write the canonical representation of this EC point into the given buffer.
    fn write_canon(&self, point: &mut CryptoSensitive<LEN>);
}

pub struct SharedRand<M: RawMutex, T> {
    shared: Mutex<M, RefCell<T>>,
}

impl<M: RawMutex, T> SharedRand<M, T> {
    pub const fn new(rand: T) -> Self {
        Self {
            shared: Mutex::new(RefCell::new(rand)),
        }
    }

    pub fn init(rand: impl Init<T>) -> impl Init<Self> {
        init!(Self {
            shared <- Mutex::init(RefCell::init(rand)),
        })
    }
}

impl<M: RawMutex, T> rand_core::RngCore for &SharedRand<M, T>
where
    T: rand_core::RngCore,
{
    fn next_u32(&mut self) -> u32 {
        self.shared.lock(|rand| rand.borrow_mut().next_u32())
    }

    fn next_u64(&mut self) -> u64 {
        self.shared.lock(|rand| rand.borrow_mut().next_u64())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.shared.lock(|rand| rand.borrow_mut().fill_bytes(dest))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.shared
            .lock(|rand| rand.borrow_mut().try_fill_bytes(dest))
    }
}

impl<M: RawMutex, T> CryptoRng for &SharedRand<M, T> where T: CryptoRng {}

pub struct WeakTestOnlyRand(u32);

impl WeakTestOnlyRand {
    const SEED: u32 = 2463534242;

    pub const fn new_default() -> Self {
        Self(Self::SEED)
    }

    pub const fn new(seed: u32) -> Self {
        Self(seed)
    }
}

impl RngCore for WeakTestOnlyRand {
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0 ^ (self.0 << 13);
        self.0 = self.0 ^ (self.0 >> 17);
        self.0 = self.0 ^ (self.0 << 5);

        self.0
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        rand_core::impls::fill_bytes_via_next(self, dest);

        Ok(())
    }
}

impl CryptoRng for WeakTestOnlyRand {}

#[allow(unused)]
pub fn default_crypto<'s, M, R>(
    rand: R,
    singleton_secret_key: CanonPkcSecretKeyRef<'s>,
) -> impl Crypto + 's
where
    M: RawMutex + 's,
    R: CryptoRngCore + 's,
{
    #[cfg(feature = "openssl")]
    let crypto = openssl::OpenSslCrypto::new(singleton_secret_key);

    #[cfg(all(feature = "mbedtls", not(feature = "openssl")))]
    let crypto = mbedtls::MbedtlsCrypto::<M, _>::new(rand, singleton_secret_key);

    #[cfg(all(
        feature = "rustcrypto",
        not(any(feature = "openssl", feature = "mbedtls"))
    ))]
    let crypto = rustcrypto::RustCrypto::<M, _>::new(rand, singleton_secret_key);

    #[cfg(not(any(feature = "openssl", feature = "mbedtls", feature = "rustcrypto")))]
    let crypto = dummy::DummyCrypto;

    crypto
}

pub fn test_only_crypto() -> impl Crypto {
    default_crypto::<embassy_sync::blocking_mutex::raw::NoopRawMutex, _>(
        WeakTestOnlyRand::new_default(),
        crate::dm::devices::test::DAC_PRIVKEY,
    )
}

#[cfg(test)]
mod tests {
    use crate::crypto::{
        test_only_crypto, CanonPkcPublicKeyRef, CanonPkcSignatureRef, Crypto, PublicKey,
    };

    #[test]
    fn test_verify_msg_success() {
        let crypto = test_only_crypto();

        let key = unwrap!(crypto.pub_key(PUB_KEY1));
        assert_eq!(key.verify(MSG1_SUCCESS, SIGNATURE1), true);
    }

    #[test]
    fn test_verify_msg_fail() {
        let crypto = test_only_crypto();

        let key = unwrap!(crypto.pub_key(PUB_KEY1));
        assert_eq!(key.verify(MSG1_FAIL, SIGNATURE1), false);
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
