/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! Canonical representations of cryptographic material as per the Matter spec.

use core::fmt::Debug;

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};
use crate::utils::init::{init, zeroed, Init, IntoFallibleInit};

/// Length of the hash returned by the hasher (`Crypto::hash`) in bytes.
///
/// As per the Matter spec, the hasher should be SHA-256.
pub const HASH_LEN: usize = 32;

/// Length of the SHA-1 hash returned by `Crypto::hash1` in bytes.
pub const SHA1_HASH_LEN: usize = 20;

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

macro_rules! canon {
    ($len:expr, $zero: ident, $name:ident, $name_ref:ident) => {
        /// Canonical representation of a $name.
        #[allow(unused)]
        pub type $name = $crate::crypto::CryptoSensitive<$len>;

        /// Reference to a canonical $name.
        #[allow(unused)]
        pub type $name_ref<'a> = $crate::crypto::CryptoSensitiveRef<'a, $len>;

        /// Zeroed $name.
        #[allow(unused)]
        pub const $zero: $name = $name::new();
    };
}

pub(crate) use canon;

canon!(HASH_LEN, HASH_ZEROED, Hash, HashRef);
canon!(HMAC_HASH_LEN, HMAC_HASH_ZEROED, HmacHash, HmacHashRef);

canon!(
    UINT320_CANON_LEN,
    UINT320_ZEROED,
    CanonUint320,
    CanonUint320Ref
);

canon!(
    AEAD_CANON_KEY_LEN,
    AEAD_KEY_ZEROED,
    CanonAeadKey,
    CanonAeadKeyRef
);
canon!(AEAD_NONCE_LEN, AEAD_NONCE_ZEROED, AeadNonce, AeadNonceRef);
canon!(AEAD_TAG_LEN, AEAD_TAG_ZEROED, AeadTag, AeadTagRef);

canon!(
    PKC_CANON_PUBLIC_KEY_LEN,
    PKC_PUBLIC_KEY_ZEROED,
    CanonPkcPublicKey,
    CanonPkcPublicKeyRef
);
canon!(
    PKC_CANON_SECRET_KEY_LEN,
    PKC_SECRET_KEY_ZEROED,
    CanonPkcSecretKey,
    CanonPkcSecretKeyRef
);
canon!(
    PKC_SIGNATURE_LEN,
    PKC_SIGNATURE_ZEROED,
    CanonPkcSignature,
    CanonPkcSignatureRef
);
canon!(
    PKC_SHARED_SECRET_LEN,
    PKC_SHARED_SECRET_ZEROED,
    CanonPkcSharedSecret,
    CanonPkcSharedSecretRef
);

canon!(
    EC_CANON_SCALAR_LEN,
    EC_SCALAR_ZEROED,
    CanonEcScalar,
    CanonEcScalarRef
);
canon!(
    EC_CANON_POINT_LEN,
    EC_POINT_ZEROED,
    CanonEcPoint,
    CanonEcPointRef
);

/// A cryptographic material represented in a cross-platform way,
/// as a fixed-length array in a well-defined format.
///
/// Thus, it can be imported into any `Crypto` provider and exported from it without
/// worrying about endianness or other platform-specific representation issues.
///
/// The reason for wrapping the array with a newtype is so that the following
/// protection measures are taken:
/// - The material is not accidentally printed in logs or debug output.
/// - The material has a single `access` / `access_mut` method and deliberately
///   does not implement `Deref` or `AsRef` traits to avoid accidental leakage.
/// - The material is zeroed out when dropped; note however that this has a limited use case,
///   in Rust, because of the Rust move semantics.
///
/// Regarding sensitivity, `rs-matter` takes a radical approach and assumes that
/// *all* cryptographic material is sensitive. Including, but not limited to:
/// - Secret keys (obviously)
/// - Signatures (because they can leak information about the secret key)
/// - Hashes (because they can be pre-images of sensitive data)
/// - Public keys (just in case)
#[derive(Clone)]
pub struct CryptoSensitive<const N: usize> {
    /// The underlying data array that needs to be protected.
    data: [u8; N],
}

impl<const N: usize> CryptoSensitive<N> {
    /// Create a new zeroed `CryptoSensitive` instance.
    #[inline(always)]
    pub const fn new() -> Self {
        Self { data: [0u8; N] }
    }

    /// Create a new `CryptoSensitive` instance by loading data from the provided reference.
    pub const fn new_from_ref(other: CryptoSensitiveRef<'_, N>) -> Self {
        let mut this = Self::new();

        this.load(other);

        this
    }

    /// Return an in-place initializer for a zeroed `CryptoSensitive` instance.
    #[inline(always)]
    pub fn init() -> impl Init<Self> {
        init!(Self {
            data <- zeroed(),
        })
    }

    /// Zeroizes the cryptographic material held by this instance.
    pub fn zeroize(&mut self) {
        // TODO: Depend on the `zeroize` crate to ensure that the compiler does not optimize this out.
        // TODO: Implement some sort of pinning to ensure that the compiler does move this type when on-stack.
        self.data.fill(0);
    }

    /// Get a reference to this cryptographic material.
    pub const fn reference(&self) -> CryptoSensitiveRef<'_, N> {
        CryptoSensitiveRef::new(&self.data)
    }

    /// Load data from another cryptographic material reference.
    pub const fn load(&mut self, other: CryptoSensitiveRef<'_, N>) {
        self.load_from_array(other.access());
    }

    /// Load data from a byte array.
    pub const fn load_from_array(&mut self, data: &[u8; N]) {
        self.data.copy_from_slice(data);
    }

    /// Try to load data from a byte slice.
    ///
    /// Returns an error if the slice length does not match the expected length.
    pub fn try_load_from_slice(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() != N {
            return Err(ErrorCode::InvalidData.into());
        }

        self.data.copy_from_slice(data);

        Ok(())
    }

    /// Access the underlying data as a byte array reference.
    ///
    /// NOTE: care should be taken when using this method, as it exposes the sensitive data.
    pub const fn access(&self) -> &[u8; N] {
        &self.data
    }

    /// Access the underlying data as a mutable byte array reference.
    ///
    /// NOTE: care should be taken when using this method, as it exposes the sensitive data.
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

/// A reference to cryptographic material.
/// The non-owned equivalent of `CryptoSensitive<N>`.
#[derive(Copy, Clone)]
pub struct CryptoSensitiveRef<'a, const N: usize> {
    data: &'a [u8; N],
}

impl<'a, const N: usize> CryptoSensitiveRef<'a, N> {
    /// Create a new `CryptoSensitiveRef` instance from a byte array reference.
    #[inline(always)]
    pub const fn new(material: &'a [u8; N]) -> Self {
        Self { data: material }
    }

    /// Create a new `CryptoSensitiveRef` instance from a byte slice.
    ///
    /// Panics if the slice length does not match the expected length.
    #[inline(always)]
    pub fn new_from_slice(material: &'a [u8]) -> Self {
        assert_eq!(material.len(), N);

        Self::new(Self::as_array(material).unwrap()) // TODO
    }

    /// Try to create a new `CryptoSensitiveRef` instance from a byte slice.
    ///
    /// Returns an error if the slice length does not match the expected length.
    #[inline(always)]
    pub fn try_new(material: &'a [u8]) -> Result<Self, Error> {
        if material.len() != N {
            Err(ErrorCode::InvalidData)?;
        }

        Ok(Self::new(Self::as_array(material).unwrap())) // TODO
    }

    /// Split this reference into two references of the specified lengths.
    ///
    /// Panics if the sum of the specified lengths does not match the length of this reference.
    pub fn split<const M1: usize, const M2: usize>(
        &self,
    ) -> (CryptoSensitiveRef<'a, M1>, CryptoSensitiveRef<'a, M2>) {
        let (left, right) = self.data.split_at(M1);

        (
            CryptoSensitiveRef::new_from_slice(left),
            CryptoSensitiveRef::new_from_slice(right),
        )
    }

    /// Access the underlying data as a byte array reference.
    ///
    /// NOTE: care should be taken when using this method, as it exposes the sensitive data.
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

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;

    use crate::error::ErrorCode;
    use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVValue, ToTLV};
    use crate::utils::init::InitMaybeUninit;
    use crate::utils::storage::WriteBuf;

    use super::{CryptoSensitive, CryptoSensitiveRef};

    #[test]
    fn new_and_default_are_zeroed() {
        let a = CryptoSensitive::<8>::new();
        assert_eq!(a.access(), &[0u8; 8]);

        let b: CryptoSensitive<8> = Default::default();
        assert_eq!(b.access(), &[0u8; 8]);

        // The zero-length instantiation is legal too
        let z = CryptoSensitive::<0>::new();
        assert_eq!(z.access().len(), 0);
    }

    #[test]
    fn init_is_zeroed() {
        let mut slot = MaybeUninit::<CryptoSensitive<16>>::uninit();
        // Poison the slot so a zeroed result cannot be an accident
        unsafe { slot.as_mut_ptr().cast::<u8>().write_bytes(0xff, 16) };

        let value = slot.init_with(CryptoSensitive::<16>::init());
        assert_eq!(value.access(), &[0u8; 16]);
    }

    #[test]
    fn load_from_array_and_ref() {
        let mut a = CryptoSensitive::<4>::new();
        a.load_from_array(&[1, 2, 3, 4]);
        assert_eq!(a.access(), &[1, 2, 3, 4]);

        let mut b = CryptoSensitive::<4>::new();
        b.load(a.reference());
        assert_eq!(b.access(), a.access());

        let c = CryptoSensitive::new_from_ref(a.reference());
        assert_eq!(c.access(), &[1, 2, 3, 4]);

        let d: CryptoSensitive<4> = a.reference().into();
        assert_eq!(d.access(), &[1, 2, 3, 4]);

        let e: CryptoSensitive<4> = (&[9u8, 8, 7, 6]).into();
        assert_eq!(e.access(), &[9, 8, 7, 6]);

        let f: CryptoSensitive<4> = [5u8, 5, 5, 5].into();
        assert_eq!(f.access(), &[5, 5, 5, 5]);
    }

    #[test]
    fn try_load_from_slice_checks_length() {
        let mut a = CryptoSensitive::<4>::new();

        assert!(a.try_load_from_slice(&[1, 2, 3, 4]).is_ok());
        assert_eq!(a.access(), &[1, 2, 3, 4]);

        // Too short and too long both fail and leave the contents untouched
        assert_eq!(
            a.try_load_from_slice(&[7, 7, 7]).unwrap_err().code(),
            ErrorCode::InvalidData
        );
        assert_eq!(
            a.try_load_from_slice(&[7, 7, 7, 7, 7]).unwrap_err().code(),
            ErrorCode::InvalidData
        );
        assert_eq!(a.access(), &[1, 2, 3, 4]);

        assert!(CryptoSensitive::<4>::try_from(&[1u8, 2, 3][..]).is_err());
        let ok = CryptoSensitive::<3>::try_from(&[1u8, 2, 3][..]).unwrap();
        assert_eq!(ok.access(), &[1, 2, 3]);
    }

    #[test]
    fn access_mut_and_zeroize() {
        let mut a = CryptoSensitive::<6>::from([1u8, 2, 3, 4, 5, 6]);

        a.access_mut()[0] = 0xaa;
        a.access_mut()[5] = 0xbb;
        assert_eq!(a.access(), &[0xaa, 2, 3, 4, 5, 0xbb]);

        a.zeroize();
        assert_eq!(a.access(), &[0u8; 6]);

        // Clone is an independent copy
        let mut b = CryptoSensitive::<2>::from([1u8, 2]);
        let c = b.clone();
        b.zeroize();
        assert_eq!(c.access(), &[1, 2]);
        assert_eq!(b.access(), &[0, 0]);
    }

    #[test]
    fn debug_hides_contents() {
        let a = CryptoSensitive::<3>::from([0xde, 0xad, 0xbe]);
        let s = format!("{a:?}");
        assert_eq!(s, "CryptoSensitive<3>(**hidden**)");
        assert!(!s.contains("de") && !s.contains("222"));

        let r = a.reference();
        assert_eq!(format!("{r:?}"), "CryptoSensitiveRef<3>(**hidden**)");
    }

    #[test]
    fn reference_new_and_access() {
        let data = [1u8, 2, 3, 4, 5];

        let r = CryptoSensitiveRef::<5>::new(&data);
        assert_eq!(r.access(), &data);

        let r2: CryptoSensitiveRef<5> = (&data).into();
        assert_eq!(r2.access(), &data);

        let owned = CryptoSensitive::<5>::from(&data);
        let r3: CryptoSensitiveRef<5> = (&owned).into();
        assert_eq!(r3.access(), &data);

        // Copy semantics: both copies see the same bytes
        let r4 = r;
        assert_eq!(r4.access(), r.access());
    }

    #[test]
    fn reference_try_new_checks_length() {
        let data = [1u8, 2, 3, 4, 5];

        let ok = CryptoSensitiveRef::<5>::try_new(&data).unwrap();
        assert_eq!(ok.access(), &data);

        assert_eq!(
            CryptoSensitiveRef::<4>::try_new(&data).unwrap_err().code(),
            ErrorCode::InvalidData
        );
        assert_eq!(
            CryptoSensitiveRef::<6>::try_new(&data).unwrap_err().code(),
            ErrorCode::InvalidData
        );

        assert!(CryptoSensitiveRef::<2>::try_from(&data[..]).is_err());
        assert!(CryptoSensitiveRef::<5>::try_from(&data[..]).is_ok());

        let r = CryptoSensitiveRef::<3>::new_from_slice(&data[1..4]);
        assert_eq!(r.access(), &[2, 3, 4]);
    }

    #[test]
    #[should_panic]
    fn reference_new_from_slice_wrong_length_panics() {
        let data = [1u8, 2, 3];
        let _ = CryptoSensitiveRef::<2>::new_from_slice(&data);
    }

    #[test]
    fn reference_split() {
        let data = [1u8, 2, 3, 4, 5, 6, 7];
        let r = CryptoSensitiveRef::<7>::new(&data);

        let (l, rt) = r.split::<3, 4>();
        assert_eq!(l.access(), &[1, 2, 3]);
        assert_eq!(rt.access(), &[4, 5, 6, 7]);

        let (l, rt) = r.split::<0, 7>();
        assert_eq!(l.access().len(), 0);
        assert_eq!(rt.access(), &data);

        let (l, rt) = r.split::<7, 0>();
        assert_eq!(l.access(), &data);
        assert_eq!(rt.access().len(), 0);
    }

    #[test]
    #[should_panic]
    fn reference_split_wrong_lengths_panics() {
        let data = [1u8, 2, 3, 4];
        let r = CryptoSensitiveRef::<4>::new(&data);
        let _ = r.split::<1, 2>();
    }

    #[test]
    fn tlv_roundtrip() {
        let orig = CryptoSensitive::<5>::from([0x10, 0x20, 0x30, 0x40, 0x50]);

        let mut buf = [0u8; 32];
        let mut wb = WriteBuf::new(&mut buf);
        orig.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        let len = wb.get_tail();

        // Anonymous octet string with a 1-byte length: 0x10, len, payload
        assert_eq!(&buf[..len], &[0x10, 5, 0x10, 0x20, 0x30, 0x40, 0x50]);

        let parsed = CryptoSensitive::<5>::from_tlv(&TLVElement::new(&buf[..len])).unwrap();
        assert_eq!(parsed.access(), orig.access());

        // Same via the in-place initializer
        let mut slot = MaybeUninit::<CryptoSensitive<5>>::uninit();
        let parsed = slot
            .try_init_with(CryptoSensitive::<5>::init_from_tlv(TLVElement::new(
                &buf[..len],
            )))
            .unwrap();
        assert_eq!(parsed.access(), orig.access());

        // The iterator form yields the same single element
        let mut it = orig.tlv_iter(TLVTag::Anonymous);
        let tlv = it.next().unwrap().unwrap();
        assert!(matches!(tlv.tag, TLVTag::Anonymous));
        assert!(matches!(tlv.value, TLVValue::Str8l(s) if s == orig.access()));
        assert!(it.next().is_none());
    }

    #[test]
    fn tlv_wrong_length_is_constraint_error() {
        let orig = CryptoSensitive::<5>::from([1, 2, 3, 4, 5]);

        let mut buf = [0u8; 32];
        let mut wb = WriteBuf::new(&mut buf);
        orig.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        let len = wb.get_tail();

        let err = CryptoSensitive::<8>::from_tlv(&TLVElement::new(&buf[..len])).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConstraintError);

        let mut slot = MaybeUninit::<CryptoSensitive<8>>::uninit();
        let err = slot
            .try_init_with(CryptoSensitive::<8>::init_from_tlv(TLVElement::new(
                &buf[..len],
            )))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConstraintError);

        // A non-string element is a type error rather than a length error
        let u8_elem = [0x04, 42];
        assert!(CryptoSensitive::<1>::from_tlv(&TLVElement::new(&u8_elem)).is_err());
    }
}
