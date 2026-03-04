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
    SliceReader, Tag, Tagged, Writer,
};
use x509_cert::spki::AlgorithmIdentifier;

use crate::crypto::{
    CanonPkcPublicKey, CanonPkcPublicKeyRef, Crypto, PublicKey, PKC_CANON_PUBLIC_KEY_LEN,
    PKC_CANON_SECRET_KEY_LEN, PKC_SIGNATURE_LEN,
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

/// P-256 field element length in bytes (ECDSA signature r and s values).
const P256_FE_LEN: usize = PKC_CANON_SECRET_KEY_LEN;

struct CertificationRequest<'a> {
    pub certification_request_info: CertificationRequestInfo<'a>,
    pub signature_algorithm: AlgorithmIdentifier<()>,
    pub signature: BitStringRef<'a>,
}

impl<'a> DecodeValue<'a> for CertificationRequest<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        // Decode SEQUENCE
        reader.read_nested(header.length, |reader| {
            let certification_request_info =
                CertificationRequestInfo::decode_value(reader, header)?;
            // Decode algorithm identifier
            let signature_algorithm: AlgorithmIdentifier<()> = AlgorithmIdentifier::decode(reader)?;

            // Validate it's id-ecPublicKey
            if signature_algorithm.oid != OID_ECDSA_SHA256 {
                return Err(der::Tag::Sequence.value_error());
            }

            // Decode the public key bit string
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

struct SubjectPublicKeyInfo<'a> {
    /// Algorithm oid verified id-ecPublicKey with prime256v1 curve oid
    pub algorithm: AlgorithmIdentifier<()>,
    /// SubjectPublicKey verified for size
    pub subject_public_key: BitStringRef<'a>,
}

impl<'a> DecodeValue<'a> for SubjectPublicKeyInfo<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        // Decode SEQUENCE
        reader.read_nested(header.length, |reader| {
            // Decode algorithm identifier
            let algorithm: AlgorithmIdentifier<()> = AlgorithmIdentifier::decode(reader)?;

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

            // First byte is unused bits (should be 0), then 65 bytes of key
            if key_bytes.len() != P256_PUBLIC_KEY_LEN + 1 || key_bytes[0] != 0 {
                return Err(der::Tag::BitString.value_error());
            }

            // Verify it's an uncompressed point (starts with 0x04)
            if key_bytes[1] != 0x04 {
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
    pub csr: CertificationRequest<'a>,
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

        // BitStringRef includes the unused bits count in its encoding
        // Get the raw bytes (this should be the public key with 0x04 prefix)
        let key_bytes = subject_pk.as_bytes().ok_or(ErrorCode::InvalidData)?;

        // The first byte should be 0 (unused bits count), skip it
        let key = if key_bytes.len() > 0 && key_bytes[0] == 0 {
            &key_bytes[1..]
        } else {
            return Err(ErrorCode::InvalidData.into());
        };

        // // Verify it's the correct length
        // if key.len() != P256_PUBLIC_KEY_LEN {
        //     return Err(ErrorCode::InvalidData.into());
        // }

        // Convert to fixed-size array
        let mut result = [0u8; P256_PUBLIC_KEY_LEN];
        result.copy_from_slice(key);
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
        Self::ecdsa_der_to_raw(self.csr.signature.raw_bytes())
    }

    /// Parse a DER-encoded ECDSA signature into raw (r || s) format.
    ///
    /// DER format: SEQUENCE { INTEGER r, INTEGER s }
    /// Raw format: r (32 bytes, big-endian, zero-padded) || s (32 bytes)
    fn ecdsa_der_to_raw(der: &[u8]) -> Result<[u8; ECDSA_SIGNATURE_LEN], Error> {
        let mut reader =
            SliceReader::new(der).map_err(|_| Error::from(ErrorCode::CdInvalidSignature))?;

        // Read the SEQUENCE header
        let seq_header =
            Header::decode(&mut reader).map_err(|_| Error::from(ErrorCode::CdInvalidSignature))?;

        if seq_header.tag != Tag::Sequence {
            return Err(ErrorCode::CdInvalidSignature.into());
        }

        // Read INTEGER r
        let r_any =
            AnyRef::decode(&mut reader).map_err(|_| Error::from(ErrorCode::CdInvalidSignature))?;
        if r_any.tag() != Tag::Integer {
            return Err(ErrorCode::CdInvalidSignature.into());
        }

        // Read INTEGER s
        let s_any =
            AnyRef::decode(&mut reader).map_err(|_| Error::from(ErrorCode::CdInvalidSignature))?;
        if s_any.tag() != Tag::Integer {
            return Err(ErrorCode::CdInvalidSignature.into());
        }

        // Convert to fixed-length raw format
        let mut raw = [0u8; ECDSA_SIGNATURE_LEN];
        Self::copy_integer_to_fixed(&mut raw[..P256_FE_LEN], r_any.value())?;
        Self::copy_integer_to_fixed(&mut raw[P256_FE_LEN..], s_any.value())?;

        Ok(raw)
    }

    /// Copy a DER INTEGER value to a fixed-size buffer, handling leading zeros.
    fn copy_integer_to_fixed(dest: &mut [u8], src: &[u8]) -> Result<(), Error> {
        let dest_len = dest.len();

        // Skip leading zero byte if present (used for positive sign in DER)
        let src = if !src.is_empty() && src[0] == 0x00 && src.len() > dest_len {
            &src[1..]
        } else {
            src
        };

        if src.len() > dest_len {
            return Err(ErrorCode::InvalidData.into());
        }

        // Zero-pad on the left if src is shorter
        let pad_len = dest_len - src.len();
        dest[..pad_len].fill(0);
        dest[pad_len..].copy_from_slice(src);

        Ok(())
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

    #[test]
    fn test_invalid_empty_input() {
        assert!(CsrRef::new(&[]).is_err());
    }

    #[test]
    fn test_invalid_not_sequence() {
        assert!(CsrRef::new(&[0x01, 0x02, 0x03]).is_err());
    }

    #[test]
    fn test_invalid_empty_sequence() {
        assert!(CsrRef::new(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn test_copy_integer_to_fixed() {
        // Test with exact size
        let mut dest = [0u8; 4];
        CsrRef::copy_integer_to_fixed(&mut dest, &[0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(dest, [0x01, 0x02, 0x03, 0x04]);

        // Test with leading zero (sign byte) that needs to be stripped
        let mut dest = [0u8; 4];
        CsrRef::copy_integer_to_fixed(&mut dest, &[0x00, 0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(dest, [0x01, 0x02, 0x03, 0x04]);

        // Test with shorter input (needs padding)
        let mut dest = [0u8; 4];
        CsrRef::copy_integer_to_fixed(&mut dest, &[0x01, 0x02]).unwrap();
        assert_eq!(dest, [0x00, 0x00, 0x01, 0x02]);
    }
}
