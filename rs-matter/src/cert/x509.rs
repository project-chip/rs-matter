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

//! X.509 DER certificate parsing utilities for extracting Matter-specific data.
//!
//! This module provides a zero-copy, no-alloc parser for DER-encoded X.509
//! certificates. It extracts fields needed for Matter device attestation
//! verification: Subject Key Identifier (SKID), Authority Key Identifier (AKID),
//! public key, Matter Vendor ID, Matter Product ID, and validity periods.

use crate::error::{Error, ErrorCode};

use time::{Date, Month, PrimitiveDateTime, Time};

// ASN.1 DER tag constants
const TAG_BOOLEAN: u8 = 0x01;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;

// Context specific tags for tbsCertificate
const TAG_CONTEXT_0: u8 = 0xA0;
const TAG_CONTEXT_3: u8 = 0xA3;

// Context specific tag for AuthorityKeyIdentifier
const TAG_CONTEXT_0_PRIM: u8 = 0x80;

// X.509 extension OIDs
const OID_SUBJECT_KEY_ID: [u8; 3] = [0x55, 0x1D, 0x0E]; // OID 2.5.29.14
const OID_AUTHORITY_KEY_ID: [u8; 3] = [0x55, 0x1D, 0x23]; // OID 2.5.29.35

// Matter-specific OIDs for Subject DN attributes
// 1.3.6.1.4.1.37244.2.1 (Vendor ID)
const OID_MATTER_VENDOR_ID: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x02, 0x01];
// 1.3.6.1.4.1.37244.2.2 (Product ID)
const OID_MATTER_PRODUCT_ID: [u8; 10] =
    [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x02, 0x02];

/// Matter uses the P-256 uncompressed public key length
/// (0x04 || X || Y = 65 bytes)
const P256_PUBLIC_KEY_LEN: usize = 65;

/// DER reader that operates on a borrowed byte slice.
///
/// Navigates the hierarchical structure of a DER-encoded X.509 certificate.
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
    ///
    /// Supports:
    /// - Short form: single byte < 128
    /// - Long form 0x81: next 1 byte is the length
    /// - Long form 0x82: next 2 bytes are the length (big-endian)
    fn read_length(data: &'a [u8]) -> Result<(usize, &'a [u8]), Error> {
        if data.is_empty() {
            return Err(ErrorCode::InvalidData.into());
        }

        let first = data[0];
        if first < 0x80 {
            // Short form: length is directly encoded
            Ok((first as usize, &data[1..]))
        } else if first == 0x81 {
            // Long form: 1 byte of length follows
            if data.len() < 2 {
                return Err(ErrorCode::InvalidData.into());
            }
            Ok((data[1] as usize, &data[2..]))
        } else if first == 0x82 {
            // Long form: 2 bytes of length follow (big-endian)
            if data.len() < 3 {
                return Err(ErrorCode::InvalidData.into());
            }
            let len = ((data[1] as usize) << 8) | (data[2] as usize);
            Ok((len, &data[3..]))
        } else {
            // Lengths requiring 3+ bytes are not expected in certificates
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

    /// Check if all bytes have been consumed.
    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Parse a hex character (0-9, A-F, a-f) into its numeric value.
fn hex_digit(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(ErrorCode::InvalidData.into()),
    }
}

/// Parse a hex string into a u16.
///
/// Used for Vendor ID and Product ID which are stored as UTF8String
/// hex values in the Subject DN.
fn parse_hex_u16(s: &[u8]) -> Result<u16, Error> {
    if s.len() != 4 {
        return Err(ErrorCode::InvalidData.into());
    }

    let mut val: u16 = 0;
    // build hex number
    for &b in s {
        val = val << 4 | hex_digit(b)? as u16;
    }
    Ok(val)
}

/// Parse two ASCII decimal digits from a byte slice into a u8.
fn parse_2digits(s: &[u8]) -> Result<u8, Error> {
    if s.len() < 2 {
        return Err(ErrorCode::InvalidData.into());
    }
    let d1 = s[0].wrapping_sub(b'0');
    let d2 = s[1].wrapping_sub(b'0');
    if d1 > 9 || d2 > 9 {
        return Err(ErrorCode::InvalidData.into());
    }
    Ok(d1 * 10 + d2)
}

/// Parse four ASCII decimal digits from a byte slice into a u16.
fn parse_4digits(s: &[u8]) -> Result<u16, Error> {
    if s.len() < 4 {
        return Err(ErrorCode::InvalidData.into());
    }
    let hi = parse_2digits(&s[0..2])? as u16;
    let lo = parse_2digits(&s[2..4])? as u16;
    Ok(hi * 100 + lo)
}

/// Parse a DER time value (UTCTime or GeneralizedTime) into Unix epoch seconds.
///
/// UTCTime format: "YYMMDDHHMMSSZ" (13 bytes).
/// Two digit year is ambiguous. Deciding:
///   - Year 00-49 maps to 2000-2049
///   - Year 50-99 maps to 1950-1999
///
/// GeneralizedTime format: "YYYYMMDDHHMMSSZ" (15 bytes)
///   - "99991231235959Z" is treated as no-expiry (returns `u64::MAX`)
fn parse_asn1_time(tag: u8, value: &[u8]) -> Result<u64, Error> {
    let (year, rest) = if tag == TAG_UTC_TIME {
        // UTCTime: "YYMMDDHHMMSSZ"
        if value.len() != 13 || value[12] != b'Z' {
            return Err(ErrorCode::InvalidData.into());
        }
        let yy = parse_2digits(&value[0..2])? as i32;
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (year, &value[2..])
    } else if tag == TAG_GENERALIZED_TIME {
        // GeneralizedTime: "YYYYMMDDHHMMSSZ"
        if value.len() != 15 || value[14] != b'Z' {
            return Err(ErrorCode::InvalidData.into());
        }
        let year = parse_4digits(&value[0..4])? as i32;
        // "99991231235959Z" => no expiry
        if year == 9999 {
            return Ok(u64::MAX);
        }
        (year, &value[4..])
    } else {
        return Err(ErrorCode::InvalidData.into());
    };

    let month = parse_2digits(&rest[0..2])?;
    let day = parse_2digits(&rest[2..4])?;
    let hour = parse_2digits(&rest[4..6])?;
    let minute = parse_2digits(&rest[6..8])?;
    let second = parse_2digits(&rest[8..10])?;

    let month = Month::try_from(month).map_err(|_| Error::from(ErrorCode::InvalidData))?;
    let date = Date::from_calendar_date(year, month, day)
        .map_err(|_| Error::from(ErrorCode::InvalidData))?;
    let time =
        Time::from_hms(hour, minute, second).map_err(|_| Error::from(ErrorCode::InvalidData))?;
    let dt = PrimitiveDateTime::new(date, time).assume_utc();

    Ok(dt.unix_timestamp() as u64)
}

/// A reference to a DER-encoded X.509 certificate.
///
/// Provides methods to extract specific fields needed for Matter device
/// attestation verification. Each method lazily walks the DER structure
/// to find the requested field, with no upfront allocation.
///
/// # Example
///
/// ```
/// let cert = X509CertRef::new(der_bytes)?;
/// let skid = cert.subject_key_id()?;
/// let pubkey = cert.public_key()?;
/// let vid = cert.vendor_id()?;
/// ```
pub struct X509CertRef<'a> {
    data: &'a [u8],
}

impl<'a> X509CertRef<'a> {
    /// Create a new X509CertRef from a DER-encoded certificate byte slice.
    ///
    /// Validates that the outer structure is a SEQUENCE tag but does not
    /// parse the full certificate.
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

    /// Get a DerReader over the tbsCertificate SEQUENCE contents.
    ///
    /// The tbsCertificate is the first child SEQUENCE inside the outer
    /// Certificate SEQUENCE.
    fn tbs_certificate(&self) -> Result<DerReader<'a>, Error> {
        let outer = DerReader::new(self.data);
        let (_, outer_content, _) = outer.enter()?;
        // First child of outer Certificate SEQUENCE is tbsCertificate SEQUENCE
        let (tag, tbs_reader, _) = outer_content.enter()?;
        if tag != TAG_SEQUENCE {
            return Err(ErrorCode::InvalidData.into());
        }
        Ok(tbs_reader)
    }

    /// Navigate to the nth field of tbsCertificate (0-indexed), accounting
    /// for the optional [0] EXPLICIT version tag.
    ///
    /// Field indices (within tbsCertificate):
    ///   0 = version [0] EXPLICIT (optional, but always present in v3)
    ///   1 = serialNumber
    ///   2 = signature (AlgorithmIdentifier)
    ///   3 = issuer (Name)
    ///   4 = validity
    ///   5 = subject (Name)
    ///   6 = subjectPublicKeyInfo
    ///   7 = extensions [3] EXPLICIT
    ///
    /// https://www.rfc-editor.org/rfc/rfc5280#section-4.1
    fn tbs_field(&self, index: usize) -> Result<DerReader<'a>, Error> {
        let mut reader = self.tbs_certificate()?;

        // Check if the first element is the [0] EXPLICIT version tag
        let (first_tag, _, _) = reader.read_tlv()?;
        let has_version = first_tag == TAG_CONTEXT_0;

        // If index 0 is requested and version is present, return it directly
        if index == 0 && has_version {
            return Ok(reader);
        }

        // Skip elements to reach the desired index
        // If version is present, we start counting from 0 (version)
        // If version is absent, field index 1 (serialNumber) is at position 0
        let skip_count = if has_version { index } else { index - 1 };

        for _ in 0..skip_count {
            reader = reader.skip()?;
        }

        Ok(reader)
    }

    /// Get a DerReader positioned at the extensions [3] EXPLICIT wrapper.
    ///
    /// Walks to the end of tbsCertificate looking for a extensions (tag of 0xA3).
    fn extensions(&self) -> Result<DerReader<'a>, Error> {
        let mut reader = self.tbs_certificate()?;

        // Walk all children of tbsCertificate looking for [3] EXPLICIT
        while !reader.is_empty() {
            let (tag, value, rest) = reader.read_tlv()?;
            if tag == TAG_CONTEXT_3 {
                // Enter the [3] wrapper to get the SEQUENCE OF Extension
                let inner = DerReader::new(value);
                let (seq_tag, seq_value, _) = inner.read_tlv()?;
                if seq_tag != TAG_SEQUENCE {
                    return Err(ErrorCode::InvalidData.into());
                }
                return Ok(DerReader::new(seq_value));
            }
            reader = DerReader::new(rest);
        }

        Err(ErrorCode::NotFound.into())
    }

    /// Search extensions for a specific OID.
    ///
    /// Returns the extnValue OCTET STRING contents (the inner DER-encoded
    /// extension value), or `None` if the extension is not found.
    ///
    /// Extension structure:
    /// ```text
    /// SEQUENCE {
    ///   OID,
    ///   BOOLEAN (critical, optional, DEFAULT FALSE),
    ///   OCTET STRING (extnValue)
    /// }
    /// https://www.rfc-editor.org/rfc/rfc5280#section-4.2
    /// ```
    fn find_extension(&self, oid: &[u8]) -> Result<Option<&'a [u8]>, Error> {
        let mut reader = self.extensions()?;

        while !reader.is_empty() {
            let (tag, ext_value, rest) = reader.read_tlv()?;
            if tag != TAG_SEQUENCE {
                reader = DerReader::new(rest);
                continue;
            }

            // Parse the extension SEQUENCE
            let mut ext_reader = DerReader::new(ext_value);

            // First element: OID
            let (oid_tag, oid_value, _) = ext_reader.read_tlv()?;
            if oid_tag != TAG_OID {
                reader = DerReader::new(rest);
                continue;
            }

            if oid_value == oid {
                // Skip optional BOOLEAN (critical flag)
                ext_reader = ext_reader.skip()?;
                let (next_tag, next_value, after_next) = ext_reader.read_tlv()?;

                if next_tag == TAG_BOOLEAN {
                    // The BOOLEAN was critical flag; the OCTET STRING follows
                    let ext_reader2 = DerReader::new(after_next);
                    let (ostr_tag, ostr_value, _) = ext_reader2.read_tlv()?;
                    if ostr_tag != TAG_OCTET_STRING {
                        return Err(ErrorCode::InvalidData.into());
                    }
                    return Ok(Some(ostr_value));
                } else if next_tag == TAG_OCTET_STRING {
                    // No critical flag; this is already the extnValue
                    return Ok(Some(next_value));
                } else {
                    return Err(ErrorCode::InvalidData.into());
                }
            }

            reader = DerReader::new(rest);
        }

        Ok(None)
    }

    /// Search Subject DN SET OF entries for a specific attribute OID.
    ///
    /// Returns the attribute value bytes (from a UTF8String or PrintableString).
    ///
    /// Subject DN structure:
    /// ```text
    /// SEQUENCE OF SET {
    ///   SEQUENCE {
    ///     OID (attribute type),
    ///     UTF8String | PrintableString (attribute value)
    ///   }
    /// }
    /// ```
    fn find_subject_attr(&self, oid: &[u8]) -> Result<Option<&'a [u8]>, Error> {
        // Navigate to Subject DN (field index 5 in tbsCertificate)
        // https://www.rfc-editor.org/rfc/rfc5280#section-4.1
        let field_reader = self.tbs_field(5)?;
        let (tag, subject_value, _) = field_reader.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return Err(ErrorCode::InvalidData.into());
        }

        let mut set_reader = DerReader::new(subject_value);

        while !set_reader.is_empty() {
            let (set_tag, set_value, rest) = set_reader.read_tlv()?;
            if set_tag != TAG_SET {
                set_reader = DerReader::new(rest);
                continue;
            }

            // Each SET contains one SEQUENCE { OID, value }
            let seq_reader = DerReader::new(set_value);
            let (seq_tag, seq_value, _) = seq_reader.read_tlv()?;
            if seq_tag != TAG_SEQUENCE {
                set_reader = DerReader::new(rest);
                continue;
            }

            let mut attr_reader = DerReader::new(seq_value);

            // OID
            let (oid_tag, oid_value, _) = attr_reader.read_tlv()?;
            if oid_tag == TAG_OID && oid_value == oid {
                // Value (UTF8String or PrintableString)
                attr_reader = attr_reader.skip()?;
                let (_, attr_value, _) = attr_reader.read_tlv()?;
                return Ok(Some(attr_value));
            }

            set_reader = DerReader::new(rest);
        }

        Ok(None)
    }

    /// Extract the Subject Key Identifier (SKID) from the SKID extension.
    ///
    /// The SKID extension contains an OCTET STRING with a 20 byte key
    /// identifier.
    ///
    /// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2
    ///
    /// Returns `ErrorCode::NotFound` if the extension is not present.
    pub fn subject_key_id(&self) -> Result<&'a [u8], Error> {
        let ext_value = self
            .find_extension(&OID_SUBJECT_KEY_ID)?
            .ok_or(Error::from(ErrorCode::NotFound))?;

        // extnValue contains: OCTET STRING (the raw 20-byte SKID)
        let reader = DerReader::new(ext_value);
        let (tag, value, _) = reader.read_tlv()?;
        if tag != TAG_OCTET_STRING {
            return Err(ErrorCode::InvalidData.into());
        }

        Ok(value)
    }

    /// Extract the Authority Key Identifier (AKID) from the AKID extension.
    ///
    /// The AKID extension contains:
    /// ```text
    /// SEQUENCE {
    ///   [0] IMPLICIT keyIdentifier (20 bytes)
    /// }
    /// ```
    /// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1
    ///
    /// Returns `ErrorCode::NotFound` if the extension is not present.
    pub fn authority_key_id(&self) -> Result<&'a [u8], Error> {
        let ext_value = self
            .find_extension(&OID_AUTHORITY_KEY_ID)?
            .ok_or(Error::from(ErrorCode::NotFound))?;

        // extnValue contains: SEQUENCE { [0] IMPLICIT keyIdentifier }
        let reader = DerReader::new(ext_value);
        let (tag, seq_value, _) = reader.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return Err(ErrorCode::InvalidData.into());
        }

        // First element should be [0] IMPLICIT (tag 0x80)
        // Implicit Context specific tag for AuthorityKeyIdentifier
        let inner = DerReader::new(seq_value);
        let (tag, value, _) = inner.read_tlv()?;
        if tag != TAG_CONTEXT_0_PRIM {
            return Err(ErrorCode::InvalidData.into());
        }

        Ok(value)
    }

    /// Extract the uncompressed P-256 public key (65 bytes: 0x04 || X || Y).
    ///
    /// Navigates to subjectPublicKeyInfo (tbsCertificate field 6), then
    /// extracts the public key from the BIT STRING.
    ///
    /// Returns `ErrorCode::InvalidData` if the key is not 65 bytes or the
    /// BIT STRING unused-bits byte is not 0x00.
    pub fn public_key(&self) -> Result<&'a [u8], Error> {
        // Navigate to subjectPublicKeyInfo (field 6)
        let field_reader = self.tbs_field(6)?;
        let (tag, spki_value, _) = field_reader.read_tlv()?;
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

        Ok(key)
    }

    /// Extract the Matter Vendor ID from the Subject DN.
    ///
    /// Searches for OID 1.3.6.1.4.1.37244.2.1 in the Subject distinguished
    /// name. The value is a UTF8String containing the hex representation
    /// (e.g., "FFF1"), which is parsed to a `u16`.
    ///
    /// Returns `ErrorCode::NotFound` if not present in the Subject DN.
    pub fn vendor_id(&self) -> Result<u16, Error> {
        let attr = self
            .find_subject_attr(&OID_MATTER_VENDOR_ID)?
            .ok_or(Error::from(ErrorCode::NotFound))?;

        parse_hex_u16(attr)
    }

    /// Extract the Matter Product ID from the Subject DN.
    ///
    /// Searches for OID 1.3.6.1.4.1.37244.2.2 in the Subject distinguished
    /// name. The value is a UTF8String containing the hex representation
    /// (e.g., "8000"), which is parsed to a `u16`.
    ///
    /// Returns `ErrorCode::NotFound` if not present in the Subject DN.
    pub fn product_id(&self) -> Result<u16, Error> {
        let attr = self
            .find_subject_attr(&OID_MATTER_PRODUCT_ID)?
            .ok_or(Error::from(ErrorCode::NotFound))?;

        parse_hex_u16(attr)
    }

    /// Extract the NotBefore time as Unix epoch seconds.
    ///
    /// Parses UTCTime ("YYMMDDHHMMSSZ") or GeneralizedTime ("YYYYMMDDHHMMSSZ")
    /// from the validity field of the tbsCertificate.
    pub fn not_before_unix(&self) -> Result<u64, Error> {
        let field_reader = self.tbs_field(4)?;
        let (tag, validity_value, _) = field_reader.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return Err(ErrorCode::InvalidData.into());
        }

        let reader = DerReader::new(validity_value);
        let (tag, value, _) = reader.read_tlv()?;
        parse_asn1_time(tag, value)
    }

    /// Extract the NotAfter time as Unix epoch seconds.
    ///
    /// Parses UTCTime or GeneralizedTime. For GeneralizedTime
    /// "99991231235959Z", returns `u64::MAX` to indicate no expiry.
    pub fn not_after_unix(&self) -> Result<u64, Error> {
        let field_reader = self.tbs_field(4)?;
        let (tag, validity_value, _) = field_reader.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return Err(ErrorCode::InvalidData.into());
        }

        // Skip NotBefore, read NotAfter
        let reader = DerReader::new(validity_value);
        let reader = reader.skip()?;
        let (tag, value, _) = reader.read_tlv()?;
        parse_asn1_time(tag, value)
    }

    /// Check if the certificate is valid at the given Unix epoch time (seconds).
    ///
    /// Returns `true` if `not_before <= now_unix_secs <= not_after`.
    /// A `not_after` of `u64::MAX` (from "99991231235959Z") is always
    /// considered valid (no expiry).
    pub fn is_valid_at(&self, now_unix_secs: u64) -> Result<bool, Error> {
        let not_before = self.not_before_unix()?;
        let not_after = self.not_after_unix()?;

        Ok(now_unix_secs >= not_before && now_unix_secs <= not_after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Matter Development PAA certificate (self-signed, no VID/PID)
    // From connectedhomeip/credentials/development/attestation/Chip-Development-PAA-Cert.der
    const PAA_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0xa0, 0x30, 0x82, 0x01, 0x46, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08,
        0x57, 0xd3, 0xa2, 0xd0, 0x1e, 0x31, 0x81, 0x90, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x21, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x16, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x44, 0x65, 0x76, 0x65, 0x6c,
        0x6f, 0x70, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x50, 0x41, 0x41, 0x30, 0x20, 0x17, 0x0d, 0x32,
        0x31, 0x30, 0x36, 0x32, 0x38, 0x31, 0x34, 0x32, 0x33, 0x34, 0x33, 0x5a, 0x18, 0x0f, 0x39,
        0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30,
        0x21, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16, 0x4d, 0x61, 0x74,
        0x74, 0x65, 0x72, 0x20, 0x44, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x6d, 0x65, 0x6e, 0x74,
        0x20, 0x50, 0x41, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        0x04, 0x1b, 0x0f, 0x25, 0x94, 0x2e, 0x3d, 0x92, 0xab, 0xd6, 0x70, 0x4c, 0x1a, 0x27, 0x81,
        0xa0, 0x38, 0xec, 0x53, 0x21, 0x2c, 0x4d, 0xab, 0x58, 0xb0, 0xbe, 0x3c, 0x40, 0xbd, 0xfb,
        0x49, 0x23, 0x23, 0x42, 0x1c, 0x79, 0xdc, 0xc7, 0xad, 0x70, 0x18, 0x10, 0x07, 0x12, 0x0d,
        0xc8, 0x6f, 0x0a, 0x89, 0x25, 0x3d, 0x89, 0x93, 0xeb, 0x37, 0xab, 0x65, 0x2e, 0xf8, 0xdb,
        0x13, 0x75, 0xe5, 0xb1, 0x45, 0xa3, 0x66, 0x30, 0x64, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d,
        0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01, 0x30,
        0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06,
        0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xfa, 0x92, 0xcf, 0x09,
        0x5e, 0xfa, 0x42, 0xe1, 0x14, 0x30, 0x65, 0x16, 0x32, 0xfe, 0xfe, 0x1b, 0x2c, 0x77, 0xa7,
        0xc8, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xfa,
        0x92, 0xcf, 0x09, 0x5e, 0xfa, 0x42, 0xe1, 0x14, 0x30, 0x65, 0x16, 0x32, 0xfe, 0xfe, 0x1b,
        0x2c, 0x77, 0xa7, 0xc8, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
        0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x50, 0xa7, 0x90, 0x33, 0x64, 0xb6, 0x53,
        0xff, 0x0e, 0xa4, 0x63, 0xdc, 0x68, 0x4a, 0x86, 0xdd, 0x25, 0xc7, 0x31, 0xa3, 0x9e, 0xfe,
        0xb3, 0xc2, 0x0c, 0xd2, 0xde, 0xd1, 0xb6, 0x60, 0x7e, 0x2f, 0x02, 0x21, 0x00, 0xaf, 0xd4,
        0xed, 0x4b, 0x6a, 0x99, 0xe5, 0xf8, 0xc5, 0x52, 0x1d, 0x70, 0x1e, 0xbc, 0xf9, 0xfd, 0x53,
        0xb9, 0x39, 0x4f, 0xd8, 0x0f, 0xc5, 0x99, 0x92, 0xff, 0x3e, 0x5b, 0xbb, 0xb6, 0x0a, 0x35,
    ];

    // Matter Development PAI certificate (VID=FFF1, no PID)
    // From connectedhomeip/credentials/development/attestation/Matter-Development-PAI-FFF1-noPID-Cert.der
    const PAI_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0xcb, 0x30, 0x82, 0x01, 0x71, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08,
        0x56, 0xad, 0x82, 0x22, 0xad, 0x94, 0x5b, 0x64, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x30, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x0f, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20,
        0x50, 0x41, 0x41, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
        0xa2, 0x7c, 0x02, 0x01, 0x0c, 0x04, 0x46, 0x46, 0x46, 0x31, 0x30, 0x20, 0x17, 0x0d, 0x32,
        0x32, 0x30, 0x32, 0x30, 0x35, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x39,
        0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30,
        0x3d, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1c, 0x4d, 0x61, 0x74,
        0x74, 0x65, 0x72, 0x20, 0x44, 0x65, 0x76, 0x20, 0x50, 0x41, 0x49, 0x20, 0x30, 0x78, 0x46,
        0x46, 0x46, 0x31, 0x20, 0x6e, 0x6f, 0x20, 0x50, 0x49, 0x44, 0x31, 0x14, 0x30, 0x12, 0x06,
        0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02, 0x01, 0x0c, 0x04, 0x46, 0x46,
        0x46, 0x31, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x41,
        0x9a, 0x93, 0x15, 0xc2, 0x17, 0x3e, 0x0c, 0x8c, 0x87, 0x6d, 0x03, 0xcc, 0xfc, 0x94, 0x48,
        0x52, 0x64, 0x7f, 0x7f, 0xec, 0x5e, 0x50, 0x82, 0xf4, 0x05, 0x99, 0x28, 0xec, 0xa8, 0x94,
        0xc5, 0x94, 0x15, 0x13, 0x09, 0xac, 0x63, 0x1e, 0x4c, 0xb0, 0x33, 0x92, 0xaf, 0x68, 0x4b,
        0x0b, 0xaf, 0xb7, 0xe6, 0x5b, 0x3b, 0x81, 0x62, 0xc2, 0xf5, 0x2b, 0xf9, 0x31, 0xb8, 0xe7,
        0x7a, 0xaa, 0x82, 0xa3, 0x66, 0x30, 0x64, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
        0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x06,
        0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x1d,
        0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x63, 0x54, 0x0e, 0x47, 0xf6, 0x4b,
        0x1c, 0x38, 0xd1, 0x38, 0x84, 0xa4, 0x62, 0xd1, 0x6c, 0x19, 0x5d, 0x8f, 0xfb, 0x3c, 0x30,
        0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6a, 0xfd, 0x22,
        0x77, 0x1f, 0x51, 0x1f, 0xec, 0xbf, 0x16, 0x41, 0x97, 0x67, 0x10, 0xdc, 0xdc, 0x31, 0xa1,
        0x71, 0x7e, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
        0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xb2, 0xef, 0x27, 0xf4, 0x9a, 0xe9, 0xb5, 0x0f,
        0xb9, 0x1e, 0xea, 0xc9, 0x4c, 0x4d, 0x0b, 0xdb, 0xb8, 0xd7, 0x92, 0x9c, 0x6c, 0xb8, 0x8f,
        0xac, 0xe5, 0x29, 0x36, 0x8d, 0x12, 0x05, 0x4c, 0x0c, 0x02, 0x20, 0x65, 0x5d, 0xc9, 0x2b,
        0x86, 0xbd, 0x90, 0x98, 0x82, 0xa6, 0xc6, 0x21, 0x77, 0xb8, 0x25, 0xd7, 0xd0, 0x5e, 0xdb,
        0xe7, 0xc2, 0x2f, 0x9f, 0xea, 0x71, 0x22, 0x0e, 0x7e, 0xa7, 0x03, 0xf8, 0x91,
    ];

    // Matter Development DAC certificate (VID=FFF1, PID=8000)
    // From connectedhomeip/credentials/development/attestation/Matter-Development-DAC-FFF1-8000-Cert.der
    const DAC_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0xe9, 0x30, 0x82, 0x01, 0x8e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08,
        0x23, 0x8a, 0x64, 0x7b, 0xbc, 0x4c, 0x30, 0xdd, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x3d, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x1c, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x44, 0x65, 0x76, 0x20, 0x50,
        0x41, 0x49, 0x20, 0x30, 0x78, 0x46, 0x46, 0x46, 0x31, 0x20, 0x6e, 0x6f, 0x20, 0x50, 0x49,
        0x44, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c,
        0x02, 0x01, 0x0c, 0x04, 0x46, 0x46, 0x46, 0x31, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x32, 0x30,
        0x32, 0x30, 0x35, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39,
        0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x53, 0x31,
        0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1c, 0x4d, 0x61, 0x74, 0x74, 0x65,
        0x72, 0x20, 0x44, 0x65, 0x76, 0x20, 0x44, 0x41, 0x43, 0x20, 0x30, 0x78, 0x46, 0x46, 0x46,
        0x31, 0x2f, 0x30, 0x78, 0x38, 0x30, 0x30, 0x30, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b,
        0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02, 0x01, 0x0c, 0x04, 0x46, 0x46, 0x46, 0x31,
        0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02,
        0x02, 0x0c, 0x04, 0x38, 0x30, 0x30, 0x30, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00, 0x04, 0x62, 0xdb, 0x16, 0xba, 0xde, 0xa3, 0x26, 0xa6, 0xdb, 0x84, 0x81,
        0x4a, 0x06, 0x3f, 0xc6, 0xc7, 0xe9, 0xe2, 0xb1, 0x01, 0xb7, 0x21, 0x64, 0x8e, 0xba, 0x4e,
        0x5a, 0xc8, 0x40, 0xf5, 0xda, 0x30, 0x1e, 0xe6, 0x18, 0x12, 0x4e, 0xb4, 0x18, 0x0e, 0x2f,
        0xc3, 0xa2, 0x04, 0x7a, 0x56, 0x4b, 0xa9, 0xbc, 0xfa, 0x0b, 0xf7, 0x1f, 0x60, 0xce, 0x89,
        0x30, 0xf1, 0xe7, 0xf6, 0x6e, 0xc8, 0xd7, 0x28, 0xa3, 0x60, 0x30, 0x5e, 0x30, 0x0c, 0x06,
        0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03,
        0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x1d, 0x06,
        0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xbc, 0xf7, 0xb0, 0x07, 0x49, 0x70, 0x63,
        0x60, 0x6a, 0x26, 0xbe, 0x4e, 0x08, 0x7c, 0x59, 0x56, 0x87, 0x74, 0x5a, 0x5a, 0x30, 0x1f,
        0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x63, 0x54, 0x0e, 0x47,
        0xf6, 0x4b, 0x1c, 0x38, 0xd1, 0x38, 0x84, 0xa4, 0x62, 0xd1, 0x6c, 0x19, 0x5d, 0x8f, 0xfb,
        0x3c, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49,
        0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0x97, 0x97, 0x11, 0xec, 0x9e, 0x76, 0x18, 0xce, 0x41,
        0x80, 0x11, 0x32, 0xc2, 0x50, 0xdb, 0x70, 0x76, 0x74, 0x63, 0x0c, 0xd5, 0x8c, 0x12, 0xc6,
        0xe2, 0x31, 0x5f, 0x08, 0xd0, 0x1e, 0xe1, 0x78, 0x02, 0x21, 0x00, 0xec, 0xfc, 0x13, 0x06,
        0xbd, 0x2a, 0x13, 0x3d, 0x12, 0x2a, 0x27, 0x86, 0x10, 0xea, 0x3d, 0xca, 0x47, 0xf0, 0x5c,
        0x7a, 0x8b, 0x80, 0x5f, 0xa7, 0x1c, 0x6f, 0xf4, 0x15, 0x38, 0xa8, 0x64, 0xc8,
    ];

    #[test]
    fn test_paa_skid() {
        let cert = X509CertRef::new(PAA_DER).unwrap();
        let skid = cert.subject_key_id().unwrap();
        assert_eq!(
            skid,
            &[
                0xFA, 0x92, 0xCF, 0x09, 0x5E, 0xFA, 0x42, 0xE1, 0x14, 0x30, 0x65, 0x16, 0x32, 0xFE,
                0xFE, 0x1B, 0x2C, 0x77, 0xA7, 0xC8
            ]
        );
    }

    #[test]
    fn test_paa_self_signed_akid_equals_skid() {
        let cert = X509CertRef::new(PAA_DER).unwrap();
        let skid = cert.subject_key_id().unwrap();
        let akid = cert.authority_key_id().unwrap();
        assert_eq!(skid, akid);
    }

    #[test]
    fn test_pai_skid() {
        let cert = X509CertRef::new(PAI_DER).unwrap();
        let skid = cert.subject_key_id().unwrap();
        assert_eq!(
            skid,
            &[
                0x63, 0x54, 0x0E, 0x47, 0xF6, 0x4B, 0x1C, 0x38, 0xD1, 0x38, 0x84, 0xA4, 0x62, 0xD1,
                0x6C, 0x19, 0x5D, 0x8F, 0xFB, 0x3C
            ]
        );
    }

    #[test]
    fn test_dac_skid() {
        let cert = X509CertRef::new(DAC_DER).unwrap();
        let skid = cert.subject_key_id().unwrap();
        assert_eq!(
            skid,
            &[
                0xBC, 0xF7, 0xB0, 0x07, 0x49, 0x70, 0x63, 0x60, 0x6A, 0x26, 0xBE, 0x4E, 0x08, 0x7C,
                0x59, 0x56, 0x87, 0x74, 0x5A, 0x5A
            ]
        );
    }

    #[test]
    fn test_dac_akid_matches_pai_skid() {
        let dac = X509CertRef::new(DAC_DER).unwrap();
        let pai = X509CertRef::new(PAI_DER).unwrap();
        assert_eq!(
            dac.authority_key_id().unwrap(),
            pai.subject_key_id().unwrap()
        );
    }

    #[test]
    fn test_paa_public_key() {
        let cert = X509CertRef::new(PAA_DER).unwrap();
        let pk = cert.public_key().unwrap();
        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04); // uncompressed point marker
        assert_eq!(
            pk,
            &[
                0x04, 0x1b, 0x0f, 0x25, 0x94, 0x2e, 0x3d, 0x92, 0xab, 0xd6, 0x70, 0x4c, 0x1a, 0x27,
                0x81, 0xa0, 0x38, 0xec, 0x53, 0x21, 0x2c, 0x4d, 0xab, 0x58, 0xb0, 0xbe, 0x3c, 0x40,
                0xbd, 0xfb, 0x49, 0x23, 0x23, 0x42, 0x1c, 0x79, 0xdc, 0xc7, 0xad, 0x70, 0x18, 0x10,
                0x07, 0x12, 0x0d, 0xc8, 0x6f, 0x0a, 0x89, 0x25, 0x3d, 0x89, 0x93, 0xeb, 0x37, 0xab,
                0x65, 0x2e, 0xf8, 0xdb, 0x13, 0x75, 0xe5, 0xb1, 0x45,
            ]
        );
    }

    #[test]
    fn test_dac_public_key() {
        let cert = X509CertRef::new(DAC_DER).unwrap();
        let pk = cert.public_key().unwrap();
        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04);
        assert_eq!(
            pk,
            &[
                0x04, 0x62, 0xdb, 0x16, 0xba, 0xde, 0xa3, 0x26, 0xa6, 0xdb, 0x84, 0x81, 0x4a, 0x06,
                0x3f, 0xc6, 0xc7, 0xe9, 0xe2, 0xb1, 0x01, 0xb7, 0x21, 0x64, 0x8e, 0xba, 0x4e, 0x5a,
                0xc8, 0x40, 0xf5, 0xda, 0x30, 0x1e, 0xe6, 0x18, 0x12, 0x4e, 0xb4, 0x18, 0x0e, 0x2f,
                0xc3, 0xa2, 0x04, 0x7a, 0x56, 0x4b, 0xa9, 0xbc, 0xfa, 0x0b, 0xf7, 0x1f, 0x60, 0xce,
                0x89, 0x30, 0xf1, 0xe7, 0xf6, 0x6e, 0xc8, 0xd7, 0x28,
            ]
        );
    }

    #[test]
    fn test_dac_vendor_id() {
        let cert = X509CertRef::new(DAC_DER).unwrap();
        assert_eq!(cert.vendor_id().unwrap(), 0xFFF1);
    }

    #[test]
    fn test_dac_product_id() {
        let cert = X509CertRef::new(DAC_DER).unwrap();
        assert_eq!(cert.product_id().unwrap(), 0x8000);
    }

    #[test]
    fn test_pai_vendor_id() {
        let cert = X509CertRef::new(PAI_DER).unwrap();
        assert_eq!(cert.vendor_id().unwrap(), 0xFFF1);
    }

    #[test]
    fn test_pai_no_product_id() {
        let cert = X509CertRef::new(PAI_DER).unwrap();
        assert_eq!(
            cert.product_id().map_err(|e| e.code()),
            Err(ErrorCode::NotFound)
        );
    }

    #[test]
    fn test_paa_no_vendor_id() {
        let cert = X509CertRef::new(PAA_DER).unwrap();
        assert_eq!(
            cert.vendor_id().map_err(|e| e.code()),
            Err(ErrorCode::NotFound)
        );
    }

    #[test]
    fn test_paa_no_product_id() {
        let cert = X509CertRef::new(PAA_DER).unwrap();
        assert_eq!(
            cert.product_id().map_err(|e| e.code()),
            Err(ErrorCode::NotFound)
        );
    }

    #[test]
    fn test_dac_not_before() {
        let cert = X509CertRef::new(DAC_DER).unwrap();
        let nb = cert.not_before_unix().unwrap();
        // 2022-02-05 00:00:00 UTC = 1644019200
        assert_eq!(nb, 1644019200);
    }

    #[test]
    fn test_dac_not_after_no_expiry() {
        let cert = X509CertRef::new(DAC_DER).unwrap();
        let na = cert.not_after_unix().unwrap();
        // 99991231235959Z => u64::MAX (no expiry)
        assert_eq!(na, u64::MAX);
    }

    #[test]
    fn test_paa_not_before() {
        let cert = X509CertRef::new(PAA_DER).unwrap();
        let nb = cert.not_before_unix().unwrap();
        // 2021-06-28 14:23:43 UTC = 1624890223
        assert_eq!(nb, 1624890223);
    }

    #[test]
    fn test_dac_is_valid_at() {
        let cert = X509CertRef::new(DAC_DER).unwrap();
        // A time well after NotBefore (2023-11-14)
        assert!(cert.is_valid_at(1700000000).unwrap());
        // A time before NotBefore (2021-09-13)
        assert!(!cert.is_valid_at(1600000000).unwrap());
    }

    #[test]
    fn test_invalid_empty_input() {
        assert!(X509CertRef::new(&[]).is_err());
    }

    #[test]
    fn test_invalid_not_sequence() {
        assert!(X509CertRef::new(&[0x01, 0x02, 0x03]).is_err());
    }

    #[test]
    fn test_invalid_empty_sequence() {
        assert!(X509CertRef::new(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn test_parse_hex_u16() {
        assert_eq!(parse_hex_u16(b"FFF1").unwrap(), 0xFFF1);
        assert_eq!(parse_hex_u16(b"8000").unwrap(), 0x8000);
        assert_eq!(parse_hex_u16(b"0000").unwrap(), 0x0000);
        assert_eq!(parse_hex_u16(b"FFFF").unwrap(), 0xFFFF);
        assert_eq!(parse_hex_u16(b"abcd").unwrap(), 0xABCD);
        assert!(parse_hex_u16(b"FFF").is_err()); // too short
        assert!(parse_hex_u16(b"FFFFF").is_err()); // too long
        assert!(parse_hex_u16(b"GHIJ").is_err()); // invalid chars
    }
}
