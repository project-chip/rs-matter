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

//! Certificate Signing Request (CSR) parsing utilities.
//!
//! This module provides a parser for DER-encoded PKCS#10 Certificate Signing Requests.
//! It extracts the public key needed for NOC generation and can verify the CSR's
//! self-signature.

use der::asn1::{BitStringRef, UintRef};
use der::oid::ObjectIdentifier;
use der::{
    AnyRef, Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence,
    SliceReader, Tag, Writer,
};

use crate::cert::der_utils;
use crate::crypto::{
    CanonPkcPublicKey, CanonPkcPublicKeyRef, Crypto, PublicKey, PKC_CANON_PUBLIC_KEY_LEN,
    PKC_SIGNATURE_LEN,
};
use crate::error::{Error, ErrorCode};

/// OID for ECDSA-with-SHA256: 1.2.840.10045.4.3.2
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// OID for id-ecPublicKey: 1.2.840.10045.2.1
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// OID for prime256v1 (secp256r1): 1.2.840.10045.3.1.7
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// Matter uses the P-256 uncompressed public key length
/// (0x04 || X || Y = 65 bytes)
const P256_PUBLIC_KEY_LEN: usize = PKC_CANON_PUBLIC_KEY_LEN;

/// ECDSA signature length (r || s = 64 bytes)
const ECDSA_SIGNATURE_LEN: usize = PKC_SIGNATURE_LEN;

#[allow(unused)]
struct CertificationRequest<'a> {
    pub certification_request_info: CertificationRequestInfo<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature: BitStringRef<'a>,
}

#[derive(Sequence)]
struct AlgorithmIdentifier<'a> {
    oid: ObjectIdentifier,
    parameters: Option<AnyRef<'a>>,
}

impl<'a> DecodeValue<'a> for CertificationRequest<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        // Decode SEQUENCE
        reader.read_nested(header.length, |reader| {
            let certification_request_info = CertificationRequestInfo::decode(reader)?;
            // Decode algorithm identifier
            let signature_algorithm = AlgorithmIdentifier::decode(reader)?;

            // Validate it's ECDSA-SHA256
            if signature_algorithm.oid != OID_ECDSA_SHA256 {
                return Err(der::Tag::Sequence.value_error());
            }

            // Decode the signature bit string
            let signature = BitStringRef::decode(reader)?;

            Ok(Self {
                certification_request_info,
                signature_algorithm,
                signature,
            })
        })
    }
}
impl<'a> der::FixedTag for CertificationRequest<'a> {
    const TAG: Tag = Tag::Sequence;
}

// TODO Remove when upgrading to der 0.8+ which separates Encode/Decode traits.
impl<'a> EncodeValue for CertificationRequest<'a> {
    fn value_len(&self) -> der::Result<Length> {
        unimplemented!("CertificationRequest encoding is not supported")
    }
    fn encode_value(&self, _writer: &mut impl Writer) -> der::Result<()> {
        unimplemented!("CertificationRequest encoding is not supported")
    }
}

#[derive(Sequence)]
struct CertificationRequestInfo<'a> {
    pub version: UintRef<'a>,
    pub subject: AnyRef<'a>,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    pub attributes: AnyRef<'a>,
}

#[allow(unused)]
struct SubjectPublicKeyInfo<'a> {
    /// Algorithm oid verified id-ecPublicKey with prime256v1 curve oid
    pub algorithm: AlgorithmIdentifier<'a>,
    /// SubjectPublicKey verified for size
    pub subject_public_key: BitStringRef<'a>,
}

impl<'a> DecodeValue<'a> for SubjectPublicKeyInfo<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        // Decode SEQUENCE
        reader.read_nested(header.length, |reader| {
            // Decode algorithm identifier
            let algorithm = AlgorithmIdentifier::decode(reader)?;

            // Validate it's id-ecPublicKey
            if algorithm.oid != OID_EC_PUBLIC_KEY {
                return Err(der::Tag::Sequence.value_error());
            }

            // Validate parameters contain prime256v1 OID
            if let Some(params) = &algorithm.parameters {
                // Parameters should be an OID for the curve
                let curve_oid = ObjectIdentifier::from_der(params.to_der()?.as_slice())
                    .map_err(|_| der::Tag::ObjectIdentifier.value_error())?;

                if curve_oid != OID_PRIME256V1 {
                    return Err(der::Tag::ObjectIdentifier.value_error());
                }
            } else {
                // Parameters must be present for EC public keys
                return Err(der::Tag::ObjectIdentifier.value_error());
            }

            // Decode the public key bit string
            let subject_public_key = BitStringRef::decode(reader)?;

            // Validate the public key is 65 bytes (0x04 || X || Y)
            let key_bytes = subject_public_key
                .as_bytes()
                .ok_or_else(|| der::Tag::BitString.value_error())?;

            // The as_bytes() method returns the actual key bytes without the unused bits count
            // So we expect exactly 65 bytes (0x04 || X || Y)
            if key_bytes.len() != P256_PUBLIC_KEY_LEN {
                return Err(der::Tag::BitString.value_error());
            }

            // Verify it's an uncompressed point (starts with 0x04)
            if key_bytes[0] != 0x04 {
                return Err(der::Tag::BitString.value_error());
            }

            Ok(Self {
                algorithm,
                subject_public_key,
            })
        })
    }
}

impl<'a> der::FixedTag for SubjectPublicKeyInfo<'a> {
    const TAG: Tag = Tag::Sequence;
}

// TODO Remove when upgrading to der 0.8+ which separates Encode/Decode traits.
impl<'a> EncodeValue for SubjectPublicKeyInfo<'a> {
    fn value_len(&self) -> der::Result<Length> {
        unimplemented!("SubjectPublicKeyInfo encoding is not supported")
        // self.algorithm.encoded_len()? + self.subject_public_key.encoded_len()?
    }
    fn encode_value(&self, _writer: &mut impl Writer) -> der::Result<()> {
        unimplemented!("SubjectPublicKeyInfo encoding is not supported")
        // self.algorithm.encode(writer)?;
        // self.subject_public_key.encode(writer)?;
        // Ok(())
    }
}

/// A reference to a DER-encoded PKCS#10 Certificate Signing Request.
///
/// CSR structure (RFC 2986):
/// ```text
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo CertificationRequestInfo,
///     signatureAlgorithm       AlgorithmIdentifier,
///     signature                BIT STRING
/// }
///
/// CertificationRequestInfo ::= SEQUENCE {
///     version       INTEGER { v1(0) },
///     subject       Name,
///     subjectPKInfo SubjectPublicKeyInfo,
///     attributes    [0] IMPLICIT Attributes
/// }
///
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm        AlgorithmIdentifier,
///     subjectPublicKey BIT STRING
/// }
/// ```
pub struct CsrRef<'a> {
    csr: CertificationRequest<'a>,
    cert_req_info: &'a [u8],
}

impl<'a> CsrRef<'a> {
    /// Create a new CsrRef from a DER-encoded CSR byte slice.
    ///
    /// Validates that the outer structure is a SEQUENCE tag but does not
    /// parse the full CSR.
    pub fn new(der: &'a [u8]) -> Result<Self, Error> {
        let csr = CertificationRequest::from_der(der).map_err(|_| ErrorCode::InvalidData)?;

        // Also store the raw bytes of certificationRequestInfo for `crypto` crate verification
        let mut reader = SliceReader::new(der).map_err(|_| ErrorCode::InvalidData)?;

        // Decode the outer SEQUENCE header (CertificationRequest)
        Header::decode(&mut reader).map_err(|_| ErrorCode::InvalidData)?;

        // Now positioned at certificationRequestInfo
        let start = usize::try_from(reader.position()).map_err(|_| ErrorCode::InvalidData)?;

        // Decode and skip certificationRequestInfo to find its end
        let _info =
            CertificationRequestInfo::decode(&mut reader).map_err(|_| ErrorCode::InvalidData)?;

        let end = usize::try_from(reader.position()).map_err(|_| ErrorCode::InvalidData)?;

        Ok(Self {
            csr,
            cert_req_info: &der[start..end],
        })
    }

    /// Get the raw certificationRequestInfo bytes (the TBS portion).
    ///
    /// This is the data that is signed.
    fn certification_request_info_raw(&self) -> Result<&'a [u8], Error> {
        Ok(self.cert_req_info)
    }

    /// Extract the uncompressed P-256 public key from the CSR.
    ///
    /// Returns a 65-byte array containing the uncompressed public key
    /// (0x04 || X || Y).
    pub fn pubkey(&self) -> Result<[u8; P256_PUBLIC_KEY_LEN], Error> {
        // Access the subject_public_key from the parsed structure
        let subject_pk = &self
            .csr
            .certification_request_info
            .subject_public_key_info
            .subject_public_key;

        // as_bytes() returns the actual key bytes (already excludes unused bits count)
        let key_bytes = subject_pk.as_bytes().ok_or(ErrorCode::InvalidData)?;

        // Verify it's the correct length (65 bytes for uncompressed P-256)
        if key_bytes.len() != P256_PUBLIC_KEY_LEN {
            return Err(ErrorCode::InvalidData.into());
        }

        // Convert to fixed-size array
        let mut result = [0u8; P256_PUBLIC_KEY_LEN];
        result.copy_from_slice(key_bytes);
        Ok(result)
    }

    /// Extract the public key as a canonical type.
    pub fn pubkey_canon(&self) -> Result<CanonPkcPublicKey, Error> {
        let key_bytes = self.pubkey()?;
        let mut canon = CanonPkcPublicKey::new();
        canon.load(CanonPkcPublicKeyRef::try_new(&key_bytes)?);
        Ok(canon)
    }

    /// Extract the signature from the CSR.
    ///
    /// Returns the raw ECDSA signature bytes (r || s, 64 bytes).
    fn signature(&self) -> Result<[u8; ECDSA_SIGNATURE_LEN], Error> {
        der_utils::ecdsa_der_to_raw(self.csr.signature.raw_bytes())
    }

    /// Verify the CSR's self-signature.
    ///
    /// The CSR is signed by the private key corresponding to the public key
    /// contained within the CSR itself.
    pub fn verify<C: Crypto>(&self, crypto: &C) -> Result<(), Error> {
        let pubkey_bytes = self.pubkey()?;
        let pubkey = crypto.pub_key(CanonPkcPublicKeyRef::try_new(&pubkey_bytes)?)?;

        let tbs_data = self.certification_request_info_raw()?;
        let signature = self.signature()?;

        let mut sig_canon = crate::crypto::CanonPkcSignature::new();
        sig_canon.load(crate::crypto::CanonPkcSignatureRef::try_new(&signature)?);

        if pubkey.verify(tbs_data, sig_canon.reference())? {
            Ok(())
        } else {
            Err(ErrorCode::InvalidSignature.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{test_only_crypto, PublicKey, SigningSecretKey};

    // Test vectors are from connectedhomeip/src/crypto/tests/TestChipCryptoPAL.cpp

    /// Valid CSR with known public key
    const GOOD_CSR: &[u8] = &[
        0x30, 0x81, 0xca, 0x30, 0x70, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06,
        0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 0x43, 0x53, 0x52, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
        0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa3, 0xbe, 0xa1, 0xf5, 0x42, 0x01, 0x07, 0x3c, 0x4b,
        0x75, 0x85, 0xd8, 0xe2, 0x98, 0xac, 0x2f, 0xf6, 0x98, 0xdb, 0xd9, 0x5b, 0xe0, 0x7e, 0xc1,
        0x04, 0xd5, 0x73, 0xc5, 0xb0, 0x90, 0x77, 0x27, 0x00, 0x1e, 0x22, 0xc7, 0x89, 0x5e, 0x4d,
        0x75, 0x07, 0x89, 0x82, 0x0f, 0x49, 0xb6, 0x59, 0xd5, 0xc5, 0x15, 0x7d, 0x93, 0xe6, 0x80,
        0x5c, 0x70, 0x89, 0x0a, 0x43, 0x10, 0x3d, 0xeb, 0x3d, 0x4a, 0xa0, 0x00, 0x30, 0x0c, 0x06,
        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x00, 0x03, 0x48, 0x00, 0x30,
        0x45, 0x02, 0x20, 0x1d, 0x86, 0x21, 0xb4, 0xc2, 0xe1, 0xa9, 0xf3, 0xbc, 0xc8, 0x7c, 0xda,
        0xb4, 0xb9, 0xc6, 0x8c, 0xd0, 0xe4, 0x9a, 0x9c, 0xef, 0x02, 0x93, 0x98, 0x27, 0x7e, 0x81,
        0x21, 0x5d, 0x20, 0x9d, 0x32, 0x02, 0x21, 0x00, 0x8b, 0x6b, 0x49, 0xb6, 0x7d, 0x3e, 0x67,
        0x9e, 0xb1, 0x22, 0xd3, 0x63, 0x82, 0x40, 0x4f, 0x49, 0xa4, 0xdc, 0x17, 0x35, 0xac, 0x4b,
        0x7a, 0xbf, 0x52, 0x05, 0x58, 0x68, 0xe0, 0xaa, 0xd2, 0x8e,
    ];

    /// Expected public key from GOOD_CSR
    const GOOD_CSR_PUBLIC_KEY: &[u8] = &[
        0x04, 0xa3, 0xbe, 0xa1, 0xf5, 0x42, 0x01, 0x07, 0x3c, 0x4b, 0x75, 0x85, 0xd8, 0xe2, 0x98,
        0xac, 0x2f, 0xf6, 0x98, 0xdb, 0xd9, 0x5b, 0xe0, 0x7e, 0xc1, 0x04, 0xd5, 0x73, 0xc5, 0xb0,
        0x90, 0x77, 0x27, 0x00, 0x1e, 0x22, 0xc7, 0x89, 0x5e, 0x4d, 0x75, 0x07, 0x89, 0x82, 0x0f,
        0x49, 0xb6, 0x59, 0xd5, 0xc5, 0x15, 0x7d, 0x93, 0xe6, 0x80, 0x5c, 0x70, 0x89, 0x0a, 0x43,
        0x10, 0x3d, 0xeb, 0x3d, 0x4a,
    ];

    /// CSR with trailing garbage (should fail parsing)
    const BAD_TRAILING_GARBAGE_CSR: &[u8] = &[
        0x30, 0x81, 0xda, 0x30, 0x81, 0x81, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a,
        0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x43, 0x53, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06,
        0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x72, 0x48, 0xc0, 0x36, 0xf0, 0x12, 0x5f, 0xd1,
        0x68, 0x92, 0x2d, 0xee, 0x57, 0x2b, 0x8e, 0x20, 0x9d, 0x97, 0xfa, 0x73, 0x92, 0xf1, 0xa0,
        0x91, 0x0e, 0xfd, 0x04, 0x93, 0x66, 0x47, 0x3c, 0xa3, 0xf0, 0xa8, 0x47, 0xa1, 0xa3, 0x1e,
        0x13, 0x3b, 0x67, 0x3b, 0x18, 0xca, 0x77, 0xd1, 0xea, 0xe3, 0x74, 0x93, 0x49, 0x8b, 0x9d,
        0xdc, 0xef, 0xf9, 0xd5, 0x9b, 0x27, 0x19, 0xad, 0x6e, 0x90, 0xd2, 0xa0, 0x11, 0x30, 0x0f,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e, 0x31, 0x02, 0x30, 0x00,
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00,
        0x30, 0x45, 0x02, 0x20, 0x6a, 0x2e, 0x15, 0x34, 0x1b, 0xde, 0xcb, 0x8f, 0xd2, 0xfd, 0x35,
        0x03, 0x89, 0x0e, 0xed, 0x23, 0x54, 0xff, 0xcb, 0x79, 0xf9, 0xcb, 0x40, 0x33, 0x59, 0xb4,
        0x27, 0x69, 0xeb, 0x07, 0x3b, 0xd5, 0x02, 0x21, 0x00, 0xb0, 0x25, 0xc9, 0xc2, 0x21, 0xe8,
        0x54, 0xcc, 0x08, 0x12, 0xf5, 0x10, 0x3a, 0x0b, 0x25, 0x20, 0x0a, 0x61, 0x38, 0xc8, 0x6f,
        0x82, 0xa7, 0x51, 0x84, 0x61, 0xae, 0x93, 0x69, 0xe4, 0x74, 0x84, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// CSR with bad signature (should fail verification)
    /// One byte changed in signature (0xb1, 0x21 instead of 0xb1, 0x22)
    const BAD_SIGNATURE_CSR: &[u8] = &[
        0x30, 0x81, 0xca, 0x30, 0x70, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06,
        0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 0x43, 0x53, 0x52, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
        0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa3, 0xbe, 0xa1, 0xf5, 0x42, 0x01, 0x07, 0x3c, 0x4b,
        0x75, 0x85, 0xd8, 0xe2, 0x98, 0xac, 0x2f, 0xf6, 0x98, 0xdb, 0xd9, 0x5b, 0xe0, 0x7e, 0xc1,
        0x04, 0xd5, 0x73, 0xc5, 0xb0, 0x90, 0x77, 0x27, 0x00, 0x1e, 0x22, 0xc7, 0x89, 0x5e, 0x4d,
        0x75, 0x07, 0x89, 0x82, 0x0f, 0x49, 0xb6, 0x59, 0xd5, 0xc5, 0x15, 0x7d, 0x93, 0xe6, 0x80,
        0x5c, 0x70, 0x89, 0x0a, 0x43, 0x10, 0x3d, 0xeb, 0x3d, 0x4a, 0xa0, 0x00, 0x30, 0x0c, 0x06,
        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x00, 0x03, 0x48, 0x00, 0x30,
        0x45, 0x02, 0x20, 0x1d, 0x86, 0x21, 0xb4, 0xc2, 0xe1, 0xa9, 0xf3, 0xbc, 0xc8, 0x7c, 0xda,
        0xb4, 0xb9, 0xc6, 0x8c, 0xd0, 0xe4, 0x9a, 0x9c, 0xef, 0x02, 0x93, 0x98, 0x27, 0x7e, 0x81,
        0x21, 0x5d, 0x20, 0x9d, 0x32, 0x02, 0x21, 0x00, 0x8b, 0x6b, 0x49, 0xb6, 0x7d, 0x3e, 0x67,
        0x9e, 0xb1, 0x21, 0xd3, 0x63, 0x82, 0x40, 0x4f, 0x49, 0xa4, 0xdc, 0x17, 0x35, 0xac, 0x4b,
        0x7a, 0xbf, 0x52, 0x05, 0x58, 0x68, 0xe0, 0xaa, 0xd2, 0x8e,
    ];

    /// CSR that's too big (has extra byte at the end)
    const BAD_TOO_BIG_CSR: &[u8] = &[
        0x30, 0x81, 0xda, 0x30, 0x81, 0x81, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a,
        0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x43, 0x53, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06,
        0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x72, 0x48, 0xc0, 0x36, 0xf0, 0x12, 0x5f, 0xd1,
        0x68, 0x92, 0x2d, 0xee, 0x57, 0x2b, 0x8e, 0x20, 0x9d, 0x97, 0xfa, 0x73, 0x92, 0xf1, 0xa0,
        0x91, 0x0e, 0xfd, 0x04, 0x93, 0x66, 0x47, 0x3c, 0xa3, 0xf0, 0xa8, 0x47, 0xa1, 0xa3, 0x1e,
        0x13, 0x3b, 0x67, 0x3b, 0x18, 0xca, 0x77, 0xd1, 0xea, 0xe3, 0x74, 0x93, 0x49, 0x8b, 0x9d,
        0xdc, 0xef, 0xf9, 0xd5, 0x9b, 0x27, 0x19, 0xad, 0x6e, 0x90, 0xd2, 0xa0, 0x11, 0x30, 0x0f,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e, 0x31, 0x02, 0x30, 0x00,
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00,
        0x30, 0x45, 0x02, 0x20, 0x6a, 0x2e, 0x15, 0x34, 0x1b, 0xde, 0xcb, 0x8f, 0xd2, 0xfd, 0x35,
        0x03, 0x89, 0x0e, 0xed, 0x23, 0x54, 0xff, 0xcb, 0x79, 0xf9, 0xcb, 0x40, 0x33, 0x59, 0xb4,
        0x27, 0x69, 0xeb, 0x07, 0x3b, 0xd5, 0x02, 0x21, 0x00, 0xb0, 0x25, 0xc9, 0xc2, 0x21, 0xe8,
        0x54, 0xcc, 0x08, 0x12, 0xf5, 0x10, 0x3a, 0x0b, 0x25, 0x20, 0x0a, 0x61, 0x38, 0xc8, 0x6f,
        0x82, 0xa7, 0x51, 0x84, 0x61, 0xae, 0x93, 0x69, 0xe4, 0x74, 0x84, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];

    /// Truncated CSR (too small to be valid)
    const TOO_SMALL_CSR: &[u8] = &[0x30, 0x81, 0xda, 0x30, 0x81, 0x81, 0x02, 0x01, 0x00, 0x30];

    /// CSR with wrong ASN.1 tag (0x31 SET instead of 0x30 SEQUENCE)
    const NOT_SEQUENCE_CSR: &[u8] = &[
        0x31, 0x81, 0xca, 0x30, 0x70, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06,
        0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 0x43, 0x53, 0x52, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
        0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa3, 0xbe, 0xa1, 0xf5, 0x42, 0x01, 0x07, 0x3c, 0x4b,
        0x75, 0x85, 0xd8, 0xe2, 0x98, 0xac, 0x2f, 0xf6, 0x98, 0xdb, 0xd9, 0x5b, 0xe0, 0x7e, 0xc1,
        0x04, 0xd5, 0x73, 0xc5, 0xb0, 0x90, 0x77, 0x27, 0x00, 0x1e, 0x22, 0xc7, 0x89, 0x5e, 0x4d,
        0x75, 0x07, 0x89, 0x82, 0x0f, 0x49, 0xb6, 0x59, 0xd5, 0xc5, 0x15, 0x7d, 0x93, 0xe6, 0x80,
        0x5c, 0x70, 0x89, 0x0a, 0x43, 0x10, 0x3d, 0xeb, 0x3d, 0x4a, 0xa0, 0x00, 0x30, 0x0c, 0x06,
        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x00, 0x03, 0x48, 0x00, 0x30,
        0x45, 0x02, 0x20, 0x1d, 0x86, 0x21, 0xb4, 0xc2, 0xe1, 0xa9, 0xf3, 0xbc, 0xc8, 0x7c, 0xda,
        0xb4, 0xb9, 0xc6, 0x8c, 0xd0, 0xe4, 0x9a, 0x9c, 0xef, 0x02, 0x93, 0x98, 0x27, 0x7e, 0x81,
        0x21, 0x5d, 0x20, 0x9d, 0x32, 0x02, 0x21, 0x00, 0x8b, 0x6b, 0x49, 0xb6, 0x7d, 0x3e, 0x67,
        0x9e, 0xb1, 0x22, 0xd3, 0x63, 0x82, 0x40, 0x4f, 0x49, 0xa4, 0xdc, 0x17, 0x35, 0xac, 0x4b,
        0x7a, 0xbf, 0x52, 0x05, 0x58, 0x68, 0xe0, 0xaa, 0xd2, 0x8e,
    ];

    #[test]
    fn test_parse_valid_csr() {
        let csr = unwrap!(CsrRef::new(GOOD_CSR));
        let pubkey = unwrap!(csr.pubkey());
        assert_eq!(&pubkey[..], GOOD_CSR_PUBLIC_KEY);
    }

    #[test]
    fn test_parse_valid_csr_pubkey_canon() {
        let csr = unwrap!(CsrRef::new(GOOD_CSR));
        let pubkey = unwrap!(csr.pubkey_canon());
        assert_eq!(pubkey.access(), GOOD_CSR_PUBLIC_KEY);
    }

    #[test]
    fn test_verify_valid_csr_signature() {
        let crypto = test_only_crypto();
        let csr = unwrap!(CsrRef::new(GOOD_CSR));
        unwrap!(csr.verify(&crypto));
    }

    #[test]
    fn test_csr_with_trailing_garbage_fails() {
        assert!(CsrRef::new(BAD_TRAILING_GARBAGE_CSR).is_err());
    }

    #[test]
    fn test_csr_with_bad_signature_fails_verification() {
        let crypto = test_only_crypto();
        // Should parse successfully
        let csr = unwrap!(CsrRef::new(BAD_SIGNATURE_CSR));
        // signature verification should fail
        assert!(csr.verify(&crypto).is_err());
    }

    #[test]
    fn test_oversized_csr_fails() {
        assert!(CsrRef::new(BAD_TOO_BIG_CSR).is_err());
    }

    #[test]
    fn test_truncated_csr_fails() {
        assert!(CsrRef::new(TOO_SMALL_CSR).is_err());
    }

    #[test]
    fn test_wrong_asn1_tag_fails() {
        // CSR with wrong ASN.1 tag should fail parsing
        assert!(CsrRef::new(NOT_SEQUENCE_CSR).is_err());
    }

    #[test]
    fn test_extract_pubkey_matches_expected() {
        let csr = unwrap!(CsrRef::new(GOOD_CSR));
        let pubkey = unwrap!(csr.pubkey());

        // Verify it's 65 bytes (uncompressed P-256)
        assert_eq!(pubkey.len(), P256_PUBLIC_KEY_LEN);

        // Verify it starts with 0x04 (uncompressed point marker)
        assert_eq!(pubkey[0], 0x04);

        // Verify it matches expected value
        assert_eq!(&pubkey[..], GOOD_CSR_PUBLIC_KEY);
    }

    #[test]
    fn test_pubkey_canon_format() {
        let csr = unwrap!(CsrRef::new(GOOD_CSR));
        let pubkey_canon = unwrap!(csr.pubkey_canon());
        let pubkey_raw = unwrap!(csr.pubkey());

        // Canonical and raw should match
        assert_eq!(pubkey_canon.access(), &pubkey_raw[..]);
    }

    #[test]
    fn test_valid_signature_verifies() {
        let crypto = test_only_crypto();
        let csr = unwrap!(CsrRef::new(GOOD_CSR));

        // Should verify successfully
        assert!(csr.verify(&crypto).is_ok());
    }

    #[test]
    fn test_corrupted_signature_fails() {
        let crypto = test_only_crypto();
        let csr = unwrap!(CsrRef::new(BAD_SIGNATURE_CSR));

        // Should fail verification
        assert!(csr.verify(&crypto).is_err());
    }

    #[test]
    fn test_manual_signature_corruption_fails() {
        let crypto = test_only_crypto();

        // Create a mutable copy of the good CSR
        let mut csr_bytes = GOOD_CSR.to_vec();

        // Corrupt the last byte of the signature
        let len = csr_bytes.len();
        csr_bytes[len - 1] ^= 0xFF;

        let csr = unwrap!(CsrRef::new(&csr_bytes));

        // Should fail verification
        assert!(csr.verify(&crypto).is_err());
    }

    #[test]
    fn test_generated_csr_round_trip() {
        let crypto = test_only_crypto();

        // Generate a new keypair
        let secret_key = unwrap!(crypto.generate_secret_key());

        // Generate CSR
        let mut csr_buf = [0u8; 512];
        let csr_der = unwrap!(secret_key.csr(&mut csr_buf));

        // Parse the generated CSR
        let csr = unwrap!(CsrRef::new(csr_der));

        // Verify the signature
        unwrap!(csr.verify(&crypto));

        // Extract public key and verify it matches
        let csr_pubkey = unwrap!(csr.pubkey_canon());
        let mut expected_pubkey = CanonPkcPublicKey::new();
        unwrap!(secret_key
            .pub_key()
            .unwrap()
            .write_canon(&mut expected_pubkey));

        assert_eq!(csr_pubkey.access(), expected_pubkey.access());
    }

    #[test]
    fn test_multiple_generated_csrs_are_different() {
        let crypto = test_only_crypto();

        // Generate first CSR
        let secret_key1 = unwrap!(crypto.generate_secret_key());
        let mut csr_buf1 = [0u8; 512];
        let csr_der1 = unwrap!(secret_key1.csr(&mut csr_buf1));

        // Generate second CSR
        let secret_key2 = unwrap!(crypto.generate_secret_key());
        let mut csr_buf2 = [0u8; 512];
        let csr_der2 = unwrap!(secret_key2.csr(&mut csr_buf2));

        // CSRs should be different (different keypairs)
        assert_ne!(csr_der1, csr_der2);

        // Parse both
        let csr1 = unwrap!(CsrRef::new(csr_der1));
        let csr2 = unwrap!(CsrRef::new(csr_der2));

        // Public keys should be different
        let pubkey1 = unwrap!(csr1.pubkey());
        let pubkey2 = unwrap!(csr2.pubkey());
        assert_ne!(pubkey1, pubkey2);
    }

    #[test]
    fn test_generated_csr_corrupted_fails() {
        let crypto = test_only_crypto();

        // Generate a CSR
        let secret_key = unwrap!(crypto.generate_secret_key());
        let mut csr_buf = [0u8; 512];
        let csr_der = unwrap!(secret_key.csr(&mut csr_buf));

        // Corrupt a copy of it
        let mut corrupted = csr_der.to_vec();
        let len = corrupted.len();
        corrupted[len - 1] ^= 0xFF;

        let csr = unwrap!(CsrRef::new(&corrupted));

        // Should fail verification
        assert!(csr.verify(&crypto).is_err());
    }
}
