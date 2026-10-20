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

//! The OTA Software Image file format: a fixed-width prefix, an
//! [`OtaImageHeader`] and the payload.
//!
//! The caller streams the payload and checks its digest. Used by
//! [`ota_prov`](crate::dm::clusters::ota_prov) and
//! [`ota_req`](crate::dm::clusters::ota_req).

use embedded_io_async::{Read, ReadExactError};

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, OctetStr, TLVElement, TLVTag, ToTLV, Utf8Str};
use crate::utils::storage::WriteBuf;

/// The `ImageDigestType` of SHA-256 (its IANA hash algorithm ID).
pub const OTA_IMAGE_DIGEST_SHA256: u8 = 1;

/// The `FileIdentifier` starting every OTA image file.
const FILE_ID: u32 = 0x1BEE_F11E;

/// The prefix length: `FileIdentifier`, `TotalSize` and `HeaderSize`.
const PREFIX_LEN: usize = 16;

/// The maximum length of [`OtaImageHeader::software_version_str`].
pub(crate) const MAX_SOFTWARE_VERSION_STR_LEN: usize = 64;

/// The maximum length of [`OtaImageHeader::release_notes_url`].
const MAX_RELEASE_NOTES_URL_LEN: usize = 256;

/// The maximum length of [`OtaImageHeader::image_digest`].
const MAX_DIGEST_LEN: usize = 64;

/// The fixed-width prefix of an OTA image file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OtaImagePrefix {
    /// The size of the whole file: prefix, header and payload.
    total_size: u64,
    /// The size of the TLV-encoded header following the prefix.
    header_size: u32,
}

impl OtaImagePrefix {
    /// Decode the prefix from the start of `data`.
    fn decode(data: &[u8]) -> Result<Self, Error> {
        let prefix: &[u8; PREFIX_LEN] = data
            .get(..PREFIX_LEN)
            .and_then(|prefix| prefix.try_into().ok())
            .ok_or(ErrorCode::InvalidData)?;

        let file_id = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
        if file_id != FILE_ID {
            return Err(ErrorCode::InvalidData.into());
        }

        let mut total_size = [0; 8];
        total_size.copy_from_slice(&prefix[4..12]);

        Ok(Self {
            total_size: u64::from_le_bytes(total_size),
            header_size: u32::from_le_bytes([prefix[12], prefix[13], prefix[14], prefix[15]]),
        })
    }

    /// Encode the prefix.
    fn encode(&self) -> [u8; PREFIX_LEN] {
        let mut prefix = [0; PREFIX_LEN];

        prefix[..4].copy_from_slice(&FILE_ID.to_le_bytes());
        prefix[4..12].copy_from_slice(&self.total_size.to_le_bytes());
        prefix[12..].copy_from_slice(&self.header_size.to_le_bytes());

        prefix
    }

    /// The payload offset (prefix plus header length), saturating.
    fn payload_offset(&self) -> usize {
        PREFIX_LEN.saturating_add(self.header_size as usize)
    }
}

/// The header of an OTA image file. Field order gives the TLV tags.
#[derive(Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct OtaImageHeader<'a> {
    /// The Vendor ID the image is for; zero for any vendor.
    pub vendor_id: u16,
    /// The Product ID the image is for; zero for any product.
    pub product_id: u16,
    /// The payload's software version, as reported in Basic Information.
    pub software_version: u32,
    /// The displayable version (1 to 64 characters), as reported in Basic
    /// Information.
    pub software_version_str: Utf8Str<'a>,
    /// The length of the payload following the header.
    pub payload_size: u64,
    /// The lowest software version the image can be applied on top of.
    pub min_applicable_software_version: Option<u32>,
    /// The highest software version the image can be applied on top of.
    pub max_applicable_software_version: Option<u32>,
    /// An `https` link to the release notes (1 to 256 characters).
    pub release_notes_url: Option<Utf8Str<'a>>,
    /// The IANA hash algorithm ID of `image_digest`, e.g.
    /// [`OTA_IMAGE_DIGEST_SHA256`].
    pub image_digest_type: u8,
    /// The digest of the whole payload (up to 64 bytes).
    pub image_digest: OctetStr<'a>,
}

impl<'a> OtaImageHeader<'a> {
    /// Decode the prefix and header from the start of `data`, returning the
    /// header and the payload offset. The payload may follow, or not.
    pub fn decode(data: &'a [u8]) -> Result<(Self, usize), Error> {
        let prefix = OtaImagePrefix::decode(data)?;
        let payload_offset = prefix.payload_offset();

        let header = data
            .get(PREFIX_LEN..payload_offset)
            .ok_or(ErrorCode::InvalidData)?;
        let header = Self::from_tlv(&TLVElement::new(header))?;

        header.check()?;

        if (payload_offset as u64).checked_add(header.payload_size) != Some(prefix.total_size) {
            return Err(ErrorCode::InvalidData.into());
        }

        Ok((header, payload_offset))
    }

    /// Read the prefix and header from `reader` (e.g. a
    /// [`BdxReader`](crate::bdx::BdxReader)) into `buf`, leaving `reader` at the
    /// payload. 512 bytes of `buf` fit any valid header.
    pub async fn load<R>(mut reader: R, buf: &'a mut [u8]) -> Result<Self, Error>
    where
        R: Read,
        R::Error: Into<Error>,
    {
        let prefix = buf.get_mut(..PREFIX_LEN).ok_or(ErrorCode::NoSpace)?;
        read_exact(&mut reader, prefix).await?;

        let payload_offset = OtaImagePrefix::decode(prefix)?.payload_offset();

        let header = buf
            .get_mut(PREFIX_LEN..payload_offset)
            .ok_or(ErrorCode::NoSpace)?;
        read_exact(&mut reader, header).await?;

        let buf: &'a [u8] = buf;

        Self::decode(&buf[..payload_offset]).map(|(header, _)| header)
    }

    /// Whether the image is for `vendor_id` and `product_id`; a zero ID in the
    /// header matches any.
    pub fn is_for_product(&self, vendor_id: u16, product_id: u16) -> bool {
        (self.vendor_id == 0 || self.vendor_id == vendor_id)
            && (self.product_id == 0 || self.product_id == product_id)
    }

    /// Whether a node running `software_version` can update to the image: it is
    /// newer, and `software_version` is within the min/max applicable versions.
    pub fn is_update_for(&self, software_version: u32) -> bool {
        self.software_version > software_version
            && self
                .min_applicable_software_version
                .is_none_or(|min| software_version >= min)
            && self
                .max_applicable_software_version
                .is_none_or(|max| software_version <= max)
    }

    /// Encode the prefix and header into `buf`, returning the payload offset.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
        self.check()?;

        let (prefix, header) = buf
            .split_at_mut_checked(PREFIX_LEN)
            .ok_or(ErrorCode::NoSpace)?;

        let mut wb = WriteBuf::new(header);
        self.to_tlv(&TLVTag::Anonymous, &mut wb)?;
        let header_size = wb.get_tail();

        let payload_offset = PREFIX_LEN + header_size;
        let total_size = (payload_offset as u64)
            .checked_add(self.payload_size)
            .ok_or(ErrorCode::InvalidData)?;

        prefix.copy_from_slice(
            &OtaImagePrefix {
                total_size,
                header_size: header_size as u32,
            }
            .encode(),
        );

        Ok(payload_offset)
    }

    /// Check the length constraints of the header fields.
    fn check(&self) -> Result<(), Error> {
        let version_len = self.software_version_str.len();
        let url_ok = self
            .release_notes_url
            .is_none_or(|url| (1..=MAX_RELEASE_NOTES_URL_LEN).contains(&url.len()));

        if (1..=MAX_SOFTWARE_VERSION_STR_LEN).contains(&version_len)
            && url_ok
            && self.image_digest.0.len() <= MAX_DIGEST_LEN
        {
            Ok(())
        } else {
            Err(ErrorCode::ConstraintError.into())
        }
    }
}

/// Fill `buf` from `reader`; a stream ending early is malformed.
async fn read_exact<R>(reader: &mut R, buf: &mut [u8]) -> Result<(), Error>
where
    R: Read,
    R::Error: Into<Error>,
{
    reader.read_exact(buf).await.map_err(|e| match e {
        ReadExactError::UnexpectedEof => ErrorCode::InvalidData.into(),
        ReadExactError::Other(e) => e.into(),
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    use futures_lite::future::block_on;

    use crate::crypto::{test_only_crypto, Crypto, CryptoSensitive, Digest, HASH_LEN};
    use crate::tlv::Octets;

    /// The payload of both reference images.
    const PAYLOAD: &[u8] = b"rs-matter OTA image test payload\n";

    /// SHA-256 of [`PAYLOAD`].
    const PAYLOAD_DIGEST: [u8; HASH_LEN] = [
        0xc1, 0x21, 0x9a, 0x04, 0x0e, 0xa3, 0x65, 0x31, 0x53, 0xb6, 0x21, 0xca, 0xda, 0x63, 0x58,
        0xdf, 0xb4, 0x9a, 0x8c, 0xbd, 0xb8, 0x07, 0xe4, 0xd7, 0x62, 0xd2, 0x26, 0x2c, 0x6e, 0xe8,
        0x07, 0x91,
    ];

    /// The prefix and header connectedhomeip's `ota_image_tool.py` writes for
    /// `create -v 0xFFF1 -p 0x8000 -vn 2 -vs "2.0" -da sha256`.
    const MINIMAL_HEADER: &[u8] = &[
        0x1e, 0xf1, 0xee, 0x1b, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00,
        0x00, 0x15, 0x25, 0x00, 0xf1, 0xff, 0x25, 0x01, 0x00, 0x80, 0x24, 0x02, 0x02, 0x2c, 0x03,
        0x03, 0x32, 0x2e, 0x30, 0x24, 0x04, 0x21, 0x24, 0x08, 0x01, 0x30, 0x09, 0x20, 0xc1, 0x21,
        0x9a, 0x04, 0x0e, 0xa3, 0x65, 0x31, 0x53, 0xb6, 0x21, 0xca, 0xda, 0x63, 0x58, 0xdf, 0xb4,
        0x9a, 0x8c, 0xbd, 0xb8, 0x07, 0xe4, 0xd7, 0x62, 0xd2, 0x26, 0x2c, 0x6e, 0xe8, 0x07, 0x91,
        0x18,
    ];

    /// The same, with every optional field: `create -v 0xFFF1 -p 0x8000
    /// -vn 0x10203 -vs "1.2.3-rc1" -da sha256 -mi 1 -ma 0x10202
    /// -rn "https://example.com/notes"`.
    const FULL_HEADER: &[u8] = &[
        0x1e, 0xf1, 0xee, 0x1b, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x00, 0x00,
        0x00, 0x15, 0x25, 0x00, 0xf1, 0xff, 0x25, 0x01, 0x00, 0x80, 0x26, 0x02, 0x03, 0x02, 0x01,
        0x00, 0x2c, 0x03, 0x09, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2d, 0x72, 0x63, 0x31, 0x24, 0x04,
        0x21, 0x24, 0x05, 0x01, 0x26, 0x06, 0x02, 0x02, 0x01, 0x00, 0x2c, 0x07, 0x19, 0x68, 0x74,
        0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63,
        0x6f, 0x6d, 0x2f, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x24, 0x08, 0x01, 0x30, 0x09, 0x20, 0xc1,
        0x21, 0x9a, 0x04, 0x0e, 0xa3, 0x65, 0x31, 0x53, 0xb6, 0x21, 0xca, 0xda, 0x63, 0x58, 0xdf,
        0xb4, 0x9a, 0x8c, 0xbd, 0xb8, 0x07, 0xe4, 0xd7, 0x62, 0xd2, 0x26, 0x2c, 0x6e, 0xe8, 0x07,
        0x91, 0x18,
    ];

    /// A reader returning at most `chunk` bytes per read.
    struct ChunkedReader<'a> {
        data: &'a [u8],
        chunk: usize,
    }

    impl embedded_io_async::ErrorType for ChunkedReader<'_> {
        type Error = Error;
    }

    impl Read for ChunkedReader<'_> {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            let n = buf.len().min(self.chunk).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];

            Ok(n)
        }
    }

    fn minimal() -> OtaImageHeader<'static> {
        OtaImageHeader {
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            software_version: 2,
            software_version_str: "2.0",
            payload_size: PAYLOAD.len() as u64,
            min_applicable_software_version: None,
            max_applicable_software_version: None,
            release_notes_url: None,
            image_digest_type: OTA_IMAGE_DIGEST_SHA256,
            image_digest: Octets(&PAYLOAD_DIGEST),
        }
    }

    fn full() -> OtaImageHeader<'static> {
        OtaImageHeader {
            software_version: 0x10203,
            software_version_str: "1.2.3-rc1",
            min_applicable_software_version: Some(1),
            max_applicable_software_version: Some(0x10202),
            release_notes_url: Some("https://example.com/notes"),
            ..minimal()
        }
    }

    fn image(header: &[u8]) -> Vec<u8> {
        [header, PAYLOAD].concat()
    }

    #[test]
    fn payload_digest_is_sha256() {
        let crypto = test_only_crypto();

        let mut hasher = crypto.hash().unwrap();
        hasher.update(PAYLOAD).unwrap();

        let mut digest = CryptoSensitive::new();
        hasher.finish(&mut digest).unwrap();

        assert_eq!(*digest.access(), PAYLOAD_DIGEST);
    }

    #[test]
    fn encode_matches_reference() {
        for (header, expected) in [(minimal(), MINIMAL_HEADER), (full(), FULL_HEADER)] {
            let mut buf = [0; 256];
            let len = header.encode(&mut buf).unwrap();

            assert_eq!(&buf[..len], expected);
        }
    }

    #[test]
    fn decode_reference() {
        for (expected, header) in [(minimal(), MINIMAL_HEADER), (full(), FULL_HEADER)] {
            let image = image(header);
            let (decoded, payload_offset) = OtaImageHeader::decode(&image).unwrap();

            assert_eq!(decoded, expected);
            assert_eq!(payload_offset, header.len());
            assert_eq!(&image[payload_offset..], PAYLOAD);

            let prefix = OtaImagePrefix::decode(&image).unwrap();
            assert_eq!(prefix.total_size, image.len() as u64);
            assert_eq!(prefix.payload_offset(), payload_offset);
        }
    }

    #[test]
    fn decode_without_payload() {
        let (decoded, payload_offset) = OtaImageHeader::decode(MINIMAL_HEADER).unwrap();

        assert_eq!(decoded, minimal());
        assert_eq!(payload_offset, MINIMAL_HEADER.len());
    }

    #[test]
    fn load_stops_at_payload() {
        for (expected, header) in [(minimal(), MINIMAL_HEADER), (full(), FULL_HEADER)] {
            let image = image(header);

            for chunk in [1, 7, usize::MAX] {
                let mut reader = ChunkedReader {
                    data: &image,
                    chunk,
                };
                let mut buf = [0; 512];

                let loaded = block_on(OtaImageHeader::load(&mut reader, &mut buf)).unwrap();

                assert_eq!(loaded, expected);
                assert_eq!(reader.data, PAYLOAD);
            }
        }
    }

    #[test]
    fn load_rejects_malformed() {
        let load = |data: &[u8], buf: &mut [u8]| {
            let reader = ChunkedReader { data, chunk: 7 };
            block_on(OtaImageHeader::load(reader, buf)).map(|_| ())
        };

        let image = image(MINIMAL_HEADER);
        let mut buf = [0; 512];

        // No room for the prefix, or for the header
        let err = load(&image, &mut buf[..PREFIX_LEN - 1]).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NoSpace);
        let err = load(&image, &mut buf[..MINIMAL_HEADER.len() - 1]).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NoSpace);

        // A `HeaderSize` no buffer can hold
        let mut bad = image.clone();
        bad[12..16].fill(0xff);
        let err = load(&bad, &mut buf).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NoSpace);

        // The stream ending inside the prefix, or inside the header
        let err = load(&image[..PREFIX_LEN - 1], &mut buf).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidData);
        let err = load(&image[..MINIMAL_HEADER.len() - 1], &mut buf).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidData);

        // Wrong file identifier
        let mut bad = image.clone();
        bad[0] ^= 1;
        let err = load(&bad, &mut buf).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidData);
    }

    #[test]
    fn product_match() {
        let header = minimal();

        assert!(header.is_for_product(0xFFF1, 0x8000));
        assert!(!header.is_for_product(0xFFF2, 0x8000));
        assert!(!header.is_for_product(0xFFF1, 0x8001));

        let any = OtaImageHeader {
            vendor_id: 0,
            product_id: 0,
            ..minimal()
        };
        assert!(any.is_for_product(0x1234, 0x5678));
    }

    #[test]
    fn update_applicability() {
        // Version 2, applicable on top of any older version
        let header = minimal();
        assert!(header.is_update_for(0));
        assert!(header.is_update_for(1));
        assert!(!header.is_update_for(2));
        assert!(!header.is_update_for(3));

        // Version 10, applicable on top of versions 4 to 6
        let header = OtaImageHeader {
            software_version: 10,
            min_applicable_software_version: Some(4),
            max_applicable_software_version: Some(6),
            ..minimal()
        };
        assert!(!header.is_update_for(3));
        assert!(header.is_update_for(4));
        assert!(header.is_update_for(6));
        assert!(!header.is_update_for(7));
    }

    #[test]
    fn prefix_roundtrip() {
        let prefix = OtaImagePrefix {
            total_size: 0x0102_0304_0506_0708,
            header_size: 0x0a0b_0c0d,
        };

        assert_eq!(OtaImagePrefix::decode(&prefix.encode()).unwrap(), prefix);
    }

    #[test]
    fn decode_rejects_malformed() {
        // Wrong file identifier
        let mut bad = image(MINIMAL_HEADER);
        bad[0] ^= 1;
        assert!(OtaImageHeader::decode(&bad).is_err());

        // Shorter than the prefix
        assert!(OtaImagePrefix::decode(&MINIMAL_HEADER[..PREFIX_LEN - 1]).is_err());

        // Header cut short
        assert!(OtaImageHeader::decode(&MINIMAL_HEADER[..MINIMAL_HEADER.len() - 1]).is_err());

        // `TotalSize` disagreeing with the header and the payload size
        let mut bad = image(MINIMAL_HEADER);
        bad[4] += 1;
        assert!(OtaImageHeader::decode(&bad).is_err());
    }

    #[test]
    fn length_constraints() {
        let long_version = "1".repeat(MAX_SOFTWARE_VERSION_STR_LEN + 1);
        let long_url = "u".repeat(MAX_RELEASE_NOTES_URL_LEN + 1);
        let long_digest = [0; MAX_DIGEST_LEN + 1];

        let bad = [
            OtaImageHeader {
                software_version_str: "",
                ..minimal()
            },
            OtaImageHeader {
                software_version_str: &long_version,
                ..minimal()
            },
            OtaImageHeader {
                release_notes_url: Some(""),
                ..minimal()
            },
            OtaImageHeader {
                release_notes_url: Some(&long_url),
                ..minimal()
            },
            OtaImageHeader {
                image_digest: Octets(&long_digest),
                ..minimal()
            },
        ];

        for header in bad {
            let mut buf = [0; 512];
            assert!(header.encode(&mut buf).is_err());
        }
    }

    #[test]
    fn longest_header_fits_512() {
        let version = "1".repeat(MAX_SOFTWARE_VERSION_STR_LEN);
        let url = "u".repeat(MAX_RELEASE_NOTES_URL_LEN);
        let digest = [0; MAX_DIGEST_LEN];

        let header = OtaImageHeader {
            vendor_id: u16::MAX,
            product_id: u16::MAX,
            software_version: u32::MAX,
            software_version_str: &version,
            payload_size: u64::MAX / 2,
            min_applicable_software_version: Some(u32::MAX),
            max_applicable_software_version: Some(u32::MAX),
            release_notes_url: Some(&url),
            image_digest_type: u8::MAX,
            image_digest: Octets(&digest),
        };

        let mut buf = [0; 512];
        header.encode(&mut buf).unwrap();
    }

    #[test]
    fn encode_needs_room() {
        let mut buf = [0; 20];
        assert!(minimal().encode(&mut buf).is_err());
    }
}
