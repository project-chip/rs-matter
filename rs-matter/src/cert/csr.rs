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

use crate::crypto::{
    CanonPkcPublicKey, CanonPkcPublicKeyRef, Crypto, PublicKey, PKC_CANON_PUBLIC_KEY_LEN,
    PKC_SIGNATURE_LEN,
};
use crate::error::{Error, ErrorCode};

// ASN.1 DER tag constants
const TAG_BIT_STRING: u8 = 0x03;
const TAG_SEQUENCE: u8 = 0x30;

/// OID for ECDSA-with-SHA256: 1.2.840.10045.4.3.2
const OID_ECDSA_SHA256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

/// OID tag for ASN.1
const TAG_OID: u8 = 0x06;

// ASN.1 DER length encoding constants
const LEN_SHORT_FORM_MAX: u8 = 0x7F;
const LEN_LONG_FORM_1BYTE: u8 = 0x81;
const LEN_LONG_FORM_2BYTE: u8 = 0x82;

/// Matter uses the P-256 uncompressed public key length
/// (0x04 || X || Y = 65 bytes)
const P256_PUBLIC_KEY_LEN: usize = PKC_CANON_PUBLIC_KEY_LEN;

/// ECDSA signature length (r || s = 64 bytes)
const ECDSA_SIGNATURE_LEN: usize = PKC_SIGNATURE_LEN;

/// DER reader that operates on a borrowed byte slice.
///
/// Navigates the hierarchical structure of a DER-encoded CSR.
#[derive(Clone, Copy)]
struct DerReader<'a> {
    data: &'a [u8],
}

impl<'a> DerReader<'a> {
    /// Create a new DerReader from a byte slice.
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Read a DER length from the given byte slice.
    ///
    /// Returns `(length_value, rest_after_length)`.
    fn read_length(data: &'a [u8]) -> Result<(usize, &'a [u8]), Error> {
        if data.is_empty() {
            return Err(ErrorCode::InvalidData.into());
        }

        let first = data[0];
        if first <= LEN_SHORT_FORM_MAX {
            Ok((first as usize, &data[1..]))
        } else if first == LEN_LONG_FORM_1BYTE {
            if data.len() < 2 {
                return Err(ErrorCode::InvalidData.into());
            }
            Ok((data[1] as usize, &data[2..]))
        } else if first == LEN_LONG_FORM_2BYTE {
            if data.len() < 3 {
                return Err(ErrorCode::InvalidData.into());
            }
            let len = ((data[1] as usize) << 8) | (data[2] as usize);
            Ok((len, &data[3..]))
        } else {
            Err(ErrorCode::InvalidData.into())
        }
    }

    /// Read a complete TLV (tag, length, value) from the current position.
    ///
    /// Returns `(tag, value_bytes, rest_after_this_tlv)`.
    fn read_tlv(&self) -> Result<(u8, &'a [u8], &'a [u8]), Error> {
        if self.data.is_empty() {
            return Err(ErrorCode::InvalidData.into());
        }

        let tag = self.data[0];
        let (len, after_len) = Self::read_length(&self.data[1..])?;

        if after_len.len() < len {
            return Err(ErrorCode::InvalidData.into());
        }

        let value = &after_len[..len];
        let rest = &after_len[len..];
        Ok((tag, value, rest))
    }

    /// Enter a constructed type (SEQUENCE, SET, etc.).
    ///
    /// Returns `(tag, inner_reader_over_value_bytes, rest_after_this_tlv)`.
    fn enter(&self) -> Result<(u8, DerReader<'a>, &'a [u8]), Error> {
        let (tag, value, rest) = self.read_tlv()?;
        Ok((tag, DerReader::new(value), rest))
    }

    /// Skip the current TLV and return a reader positioned at the next element.
    fn skip(&self) -> Result<DerReader<'a>, Error> {
        let (_, _, rest) = self.read_tlv()?;
        Ok(DerReader::new(rest))
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
    data: &'a [u8],
}

impl<'a> CsrRef<'a> {
    /// Create a new CsrRef from a DER-encoded CSR byte slice.
    ///
    /// Validates that the outer structure is a SEQUENCE tag but does not
    /// parse the full CSR.
    pub fn new(der: &'a [u8]) -> Result<Self, Error> {
        if der.len() < 2 {
            return Err(ErrorCode::InvalidData.into());
        }
        // Outer structure must be a SEQUENCE
        if der[0] != TAG_SEQUENCE {
            return Err(ErrorCode::InvalidData.into());
        }
        // Validate that the length is consistent
        let reader = DerReader::new(der);
        let (_, value, _) = reader.read_tlv()?;
        if value.is_empty() {
            return Err(ErrorCode::InvalidData.into());
        }
        Ok(Self { data: der })
    }

    /// Get the raw certificationRequestInfo bytes (the TBS portion).
    ///
    /// This is the data that is signed.
    fn certification_request_info_raw(&self) -> Result<&'a [u8], Error> {
        let outer = DerReader::new(self.data);
        let (_, outer_content, _) = outer.enter()?;

        // The certificationRequestInfo is the first child SEQUENCE
        let (tag, _value, _) = outer_content.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return Err(ErrorCode::InvalidData.into());
        }

        // Return the full TLV (tag + length + value) for signature verification
        // Calculate the length of the TLV header
        let value_start = self.data.len() - outer_content.data.len();
        let value_end = value_start
            + (outer_content.data.len() - DerReader::new(outer_content.data).skip()?.data.len());

        Ok(&self.data[value_start..value_end])
    }

    /// Get a DerReader over the certificationRequestInfo SEQUENCE contents.
    fn certification_request_info(&self) -> Result<DerReader<'a>, Error> {
        let outer = DerReader::new(self.data);
        let (_, outer_content, _) = outer.enter()?;

        // First child is certificationRequestInfo SEQUENCE
        let (tag, cri_reader, _) = outer_content.enter()?;
        if tag != TAG_SEQUENCE {
            return Err(ErrorCode::InvalidData.into());
        }
        Ok(cri_reader)
    }

    /// Extract the uncompressed P-256 public key from the CSR.
    ///
    /// Returns a 65-byte array containing the uncompressed public key
    /// (0x04 || X || Y).
    pub fn pubkey(&self) -> Result<[u8; P256_PUBLIC_KEY_LEN], Error> {
        let mut cri_reader = self.certification_request_info()?;

        // Skip version (INTEGER)
        cri_reader = cri_reader.skip()?;

        // Skip subject (Name/SEQUENCE)
        cri_reader = cri_reader.skip()?;

        // subjectPKInfo is next (SEQUENCE)
        let (tag, spki_value, _) = cri_reader.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return Err(ErrorCode::InvalidData.into());
        }

        // SubjectPublicKeyInfo = SEQUENCE { algorithm, subjectPublicKey }
        let mut spki_reader = DerReader::new(spki_value);

        // Skip algorithm SEQUENCE
        spki_reader = spki_reader.skip()?;

        // subjectPublicKey is a BIT STRING
        let (tag, bs_value, _) = spki_reader.read_tlv()?;
        if tag != TAG_BIT_STRING {
            return Err(ErrorCode::InvalidData.into());
        }

        // BIT STRING: first byte is unused bits count (must be 0)
        if bs_value.is_empty() || bs_value[0] != 0x00 {
            return Err(ErrorCode::InvalidData.into());
        }

        let key = &bs_value[1..];
        if key.len() != P256_PUBLIC_KEY_LEN {
            return Err(ErrorCode::InvalidData.into());
        }

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
        let outer = DerReader::new(self.data);
        let (_, outer_content, _) = outer.enter()?;

        // Skip certificationRequestInfo
        let reader = outer_content.skip()?;

        // Skip signatureAlgorithm
        let reader = reader.skip()?;

        // signature is a BIT STRING
        let (tag, bs_value, _) = reader.read_tlv()?;
        if tag != TAG_BIT_STRING {
            return Err(ErrorCode::InvalidData.into());
        }

        // BIT STRING: first byte is unused bits count (must be 0)
        if bs_value.is_empty() || bs_value[0] != 0x00 {
            return Err(ErrorCode::InvalidData.into());
        }

        let sig_der = &bs_value[1..];

        // The signature is DER-encoded as SEQUENCE { INTEGER r, INTEGER s }
        // We need to extract the raw r and s values (32 bytes each)
        Self::parse_ecdsa_signature_der(sig_der)
    }

    /// Parse a DER-encoded ECDSA signature into raw (r || s) format.
    ///
    /// DER format: SEQUENCE { INTEGER r, INTEGER s }
    /// Raw format: r (32 bytes, big-endian, zero-padded) || s (32 bytes)
    fn parse_ecdsa_signature_der(der: &[u8]) -> Result<[u8; ECDSA_SIGNATURE_LEN], Error> {
        let reader = DerReader::new(der);
        let (tag, seq_value, _) = reader.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return Err(ErrorCode::InvalidData.into());
        }

        let mut seq_reader = DerReader::new(seq_value);

        // Read r INTEGER
        let (tag, r_value, _) = seq_reader.read_tlv()?;
        if tag != 0x02 {
            // INTEGER tag
            return Err(ErrorCode::InvalidData.into());
        }

        seq_reader = seq_reader.skip()?;

        // Read s INTEGER
        let (tag, s_value, _) = seq_reader.read_tlv()?;
        if tag != 0x02 {
            return Err(ErrorCode::InvalidData.into());
        }

        let mut result = [0u8; ECDSA_SIGNATURE_LEN];

        // Copy r value (may have leading zero for sign, or be shorter than 32 bytes)
        Self::copy_integer_to_fixed(&mut result[..32], r_value)?;

        // Copy s value
        Self::copy_integer_to_fixed(&mut result[32..], s_value)?;

        Ok(result)
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

    /// Validate that the CSR uses ECDSA-with-SHA256 signature algorithm.
    ///
    /// Matter only supports ECDSA-with-SHA256 for CSR signatures.
    pub fn validate_signature_algorithm(&self) -> Result<(), Error> {
        let outer = DerReader::new(self.data);
        let (_, outer_content, _) = outer.enter()?;

        // Skip certificationRequestInfo
        let reader = outer_content.skip()?;

        // signatureAlgorithm is a SEQUENCE containing the algorithm OID
        let (tag, alg_value, _) = reader.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return Err(ErrorCode::InvalidData.into());
        }

        // First element should be the OID
        let alg_reader = DerReader::new(alg_value);
        let (tag, oid_value, _) = alg_reader.read_tlv()?;
        if tag != TAG_OID {
            return Err(ErrorCode::InvalidData.into());
        }

        // Verify it matches ECDSA-with-SHA256
        if oid_value != OID_ECDSA_SHA256 {
            return Err(ErrorCode::InvalidData.into());
        }

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
    fn test_der_reader_read_length() {
        // Short form length
        let (len, rest) = DerReader::read_length(&[0x05, 0xAA, 0xBB]).unwrap();
        assert_eq!(len, 5);
        assert_eq!(rest, &[0xAA, 0xBB]);

        // Long form 1-byte length
        let (len, rest) = DerReader::read_length(&[0x81, 0x80, 0xAA]).unwrap();
        assert_eq!(len, 128);
        assert_eq!(rest, &[0xAA]);

        // Long form 2-byte length
        let (len, rest) = DerReader::read_length(&[0x82, 0x01, 0x00, 0xAA]).unwrap();
        assert_eq!(len, 256);
        assert_eq!(rest, &[0xAA]);
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

    #[test]
    fn test_signature_algorithm_constants() {
        // Verify OID constant is correct (1.2.840.10045.4.3.2)
        assert_eq!(OID_ECDSA_SHA256.len(), 8);
        assert_eq!(OID_ECDSA_SHA256[0], 0x2A); // 1.2
        assert_eq!(OID_ECDSA_SHA256[1], 0x86); // 840 (part 1)
    }
}
