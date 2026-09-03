/*
 *
 *    Copyright (c) 2023-2026 Project CHIP Authors
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

use core::iter::Empty;

use qrcodegen_no_heap::{QrCode, QrCodeEcc, Version};

use verhoeff::Verhoeff;

use crate::error::ErrorCode;
use crate::tlv::{EitherIter, TLVElement, TLVTag, TLV};
use crate::transport::network::mdns::CommissionableFilter;
use crate::utils::codec::base38;
use crate::utils::storage::WriteBuf;

use super::*;

#[cfg(feature = "qr-scan")]
pub mod scan;

/// The prefix of a Matter onboarding QR-code text payload.
pub const QR_PREFIX: &str = "MT:";

// See the spec. QR Code in the Matter specification
const LONG_BITS: usize = 12;
const VERSION_FIELD_LENGTH_IN_BITS: usize = 3;
const VENDOR_IDFIELD_LENGTH_IN_BITS: usize = 16;
const PRODUCT_IDFIELD_LENGTH_IN_BITS: usize = 16;
const COMMISSIONING_FLOW_FIELD_LENGTH_IN_BITS: usize = 2;
const RENDEZVOUS_INFO_FIELD_LENGTH_IN_BITS: usize = 8;
const PAYLOAD_DISCRIMINATOR_FIELD_LENGTH_IN_BITS: usize = LONG_BITS;
const SETUP_PINCODE_FIELD_LENGTH_IN_BITS: usize = 27;
const PADDING_FIELD_LENGTH_IN_BITS: usize = 4;
const TOTAL_PAYLOAD_DATA_SIZE_IN_BITS: usize = VERSION_FIELD_LENGTH_IN_BITS
    + VENDOR_IDFIELD_LENGTH_IN_BITS
    + PRODUCT_IDFIELD_LENGTH_IN_BITS
    + COMMISSIONING_FLOW_FIELD_LENGTH_IN_BITS
    + RENDEZVOUS_INFO_FIELD_LENGTH_IN_BITS
    + PAYLOAD_DISCRIMINATOR_FIELD_LENGTH_IN_BITS
    + SETUP_PINCODE_FIELD_LENGTH_IN_BITS
    + PADDING_FIELD_LENGTH_IN_BITS;

pub const TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES: usize = TOTAL_PAYLOAD_DATA_SIZE_IN_BITS / 8;

// Spec CHIP-Common Reserved Tags
pub const SERIAL_NUMBER_TAG: u8 = 0x00;
pub const PBKDFITERATIONS_TAG: u8 = 0x01;
pub const BPKFSALT_TAG: u8 = 0x02;
pub const NUMBER_OFDEVICES_TAG: u8 = 0x03;
pub const COMMISSIONING_TIMEOUT_TAG: u8 = 0x04;

/// Commissioning flow type as per the Matter Core spec
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommFlowType {
    /// Standard commissioning flow
    Standard = 0,
    /// Enhanced commissioning flow with user intent
    UserIntent = 1,
    /// Custom commissioning flow
    Custom = 2,
}

/// Type alias for no optional data function for the QR payload
pub type NoOptionalData = fn() -> Empty<Result<u8, Error>>;

/// Function that provides no optional data for the QR payload
pub fn no_optional_data() -> Empty<Result<u8, Error>> {
    core::iter::empty()
}

/// QR Code payload type
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct QrPayload<'a, T> {
    /// Payload version. Always 0
    version: u8,
    /// Discovery capabilities of the device
    discovery_capabilities: DiscoveryCapabilities,
    /// Commissioning flow type
    comm_flow: CommFlowType,
    /// Basic commissioning data
    comm_data: BasicCommData,
    /// Vendor ID
    vid: u16,
    /// Product ID
    pid: u16,
    /// Serial number of the device
    serial_no: &'a str,
    /// Optional extra data
    /// The data must be ordered by the tag of each TLV element in ascending order.
    optional_data: T,
}

impl<'a, T, I> QrPayload<'a, T>
where
    T: Fn() -> I,
    I: Iterator<Item = Result<u8, Error>> + 'a,
{
    /// Create a new QR payload from the device basic info config
    ///
    /// # Arguments
    /// - `discovery_capabilities` - Discovery capabilities of the device
    /// - `comm_flow` - Commissioning flow type
    /// - `comm_data` - Basic commissioning data
    /// - `dev_det` - Device basic info config
    /// - `optional_data` - Function that provides an iterator over optional TLV data bytes.
    ///   NOTE: Should be ordered by tag number in ascending order.
    pub const fn new_from_basic_info(
        discovery_capabilities: DiscoveryCapabilities,
        comm_flow: CommFlowType,
        comm_data: BasicCommData,
        dev_det: &'a BasicInfoConfig,
        optional_data: T,
    ) -> Self {
        Self::new(
            discovery_capabilities,
            comm_flow,
            comm_data,
            dev_det.vid,
            dev_det.pid,
            dev_det.serial_no,
            optional_data,
        )
    }

    /// Create a new QR payload
    ///
    /// # Arguments
    /// - `discovery_capabilities` - Discovery capabilities of the device
    /// - `comm_flow` - Commissioning flow type
    /// - `comm_data` - Basic commissioning data
    /// - `vid` - Vendor ID
    /// - `pid` - Product ID
    /// - `serial_no` - Serial number of the device
    /// - `optional_data` - Function that provides an iterator over optional TLV data bytes.
    ///   NOTE: Should be ordered by tag number in ascending order.
    pub const fn new(
        discovery_capabilities: DiscoveryCapabilities,
        comm_flow: CommFlowType,
        comm_data: BasicCommData,
        vid: u16,
        pid: u16,
        serial_no: &'a str,
        optional_data: T,
    ) -> Self {
        const DEFAULT_VERSION: u8 = 0;

        Self {
            version: DEFAULT_VERSION,
            discovery_capabilities,
            comm_flow,
            comm_data,
            vid,
            pid,
            serial_no,
            optional_data,
        }
    }

    /// Check if the QR payload is valid
    ///
    /// # Returns
    /// - `true` if the payload is valid
    /// - `false` otherwise
    pub fn is_valid(&self) -> bool {
        // 3-bit value specifying the QR code payload version.
        if self.version >= 1 << VERSION_FIELD_LENGTH_IN_BITS {
            return false;
        }

        if self.discovery_capabilities.is_empty() {
            return false;
        }

        let password = u32::from_le_bytes(*self.comm_data.password.access());
        if password >= 1 << SETUP_PINCODE_FIELD_LENGTH_IN_BITS {
            return false;
        }

        self.check_payload_common_constraints()
    }

    fn check_payload_common_constraints(&self) -> bool {
        #[repr(u16)]
        enum VendorId {
            CommonOrUnspecified = 0x0000,
            TestVendor4 = 0xFFF4,
        }

        impl VendorId {
            fn is_valid_operationally(vendor_id: u16) -> bool {
                (vendor_id != Self::CommonOrUnspecified as u16)
                    && (vendor_id <= Self::TestVendor4 as u16)
            }
        }

        // A version not equal to 0 would be invalid for v1 and would indicate new format (e.g. version 2)
        if self.version != 0 {
            return false;
        }

        if !Self::is_valid_setup_pin(u32::from_le_bytes(*self.comm_data.password.access())) {
            return false;
        }

        // VendorID must be unspecified (0) or in valid range expected.
        if VendorId::is_valid_operationally(self.vid)
            && (self.vid != VendorId::CommonOrUnspecified as u16)
        {
            return false;
        }

        // A value of 0x0000 SHALL NOT be assigned to a product since Product ID = 0x0000 is used for these specific cases:
        //  * To announce an anonymized Product ID as part of device discovery
        //  * To indicate an OTA software update file applies to multiple Product IDs equally.
        //  * To avoid confusion when presenting the Onboarding Payload for ECM with multiple nodes
        if self.pid == 0 && self.vid != VendorId::CommonOrUnspecified as u16 {
            return false;
        }

        true
    }

    fn is_valid_setup_pin(setup_pin: u32) -> bool {
        const SETUP_PINCODE_MAXIMUM_VALUE: u32 = 99999998;
        const SETUP_PINCODE_UNDEFINED_VALUE: u32 = 0;

        // SHALL be restricted to the values 0x0000001 to 0x5F5E0FE (00000001 to 99999998 in decimal), excluding the invalid Passcode
        // values.
        !(setup_pin == SETUP_PINCODE_UNDEFINED_VALUE
            || setup_pin > SETUP_PINCODE_MAXIMUM_VALUE
            || setup_pin == 11111111
            || setup_pin == 22222222
            || setup_pin == 33333333
            || setup_pin == 44444444
            || setup_pin == 55555555
            || setup_pin == 66666666
            || setup_pin == 77777777
            || setup_pin == 88888888
            || setup_pin == 12345678
            || setup_pin == 87654321)
    }

    /// Encode the QR text of this payload as a string into the provided buffer
    ///
    /// # Arguments
    /// - `buf` - Buffer to store the QR code string
    ///
    /// # Returns
    /// - On success, returns a tuple containing the QR code string and the remaining buffer
    /// - On failure, returns an error
    pub fn as_str<'b>(&self, buf: &'b mut [u8]) -> Result<(&'b str, &'b mut [u8]), Error> {
        let str_len = self.emit_chars().count();

        let (str_buf, remaining_buf) = buf.split_at_mut(str_len);

        let mut wb = WriteBuf::new(str_buf);
        for ch in self.emit_chars() {
            wb.le_u8(ch? as u8)?;
        }

        // Can't fail as `emit_chars` generates a valid UTF-8 string
        let str = unwrap!(core::str::from_utf8(str_buf).map_err(|_| ErrorCode::InvalidData));

        Ok((str, remaining_buf))
    }

    /// Encode this payload as the NDEF message an NFC tag carries, into the
    /// provided buffer.
    ///
    /// An NFC tag is an alternative carrier for the *same* onboarding payload
    /// as the QR code - "The data contained in the NFC tag SHALL be formatted
    /// as specified in QR Code Format" - wrapped in a single NDEF URI record.
    /// This is passive-tag onboarding only: it says nothing about the NFC
    /// Transport Layer (PASE over NFC), which rs-matter does not implement and
    /// which needs no payload of this kind.
    ///
    /// The record layout is fixed by the Matter Core spec:
    ///
    /// ```text
    /// 0: 0xD1   TNF=0x01 (well-known), SR=1, MB=1, ME=1
    /// 1: 0x01   length of the record type
    /// 2: <len>  URI payload size in bytes
    /// 3: 0x55   record name, "U"
    /// 4: 0x00   URI identifier code: no abbreviation
    /// 5: MT:<base-38 content>
    /// ```
    ///
    /// # Arguments
    /// - `buf` - Buffer to store the NDEF message
    ///
    /// # Returns
    /// - On success, a tuple of the NDEF message and the remaining buffer
    /// - On failure, an error
    pub fn as_ndef<'b>(&self, buf: &'b mut [u8]) -> Result<(&'b [u8], &'b mut [u8]), Error> {
        /// `0xD1`, `0x01`, payload length, `0x55`, `0x00`.
        const HEADER_LEN: usize = 5;

        let uri_len = self.emit_chars().count();

        // `SR=1` in the header byte makes this a Short Record, whose payload
        // length is a single byte. The payload is the URI identifier code plus
        // the text, and `MT:` has no NFC Forum abbreviation, so all of it
        // counts.
        let payload_len = uri_len + 1;
        if payload_len > u8::MAX as usize {
            Err(ErrorCode::NoSpace)?;
        }

        if buf.len() < HEADER_LEN + uri_len {
            Err(ErrorCode::BufferTooSmall)?;
        }

        let (ndef_buf, remaining_buf) = buf.split_at_mut(HEADER_LEN + uri_len);
        let (header, uri_buf) = ndef_buf.split_at_mut(HEADER_LEN);

        header.copy_from_slice(&[0xd1, 0x01, payload_len as u8, 0x55, 0x00]);

        let mut wb = WriteBuf::new(uri_buf);
        for ch in self.emit_chars() {
            wb.le_u8(ch? as u8)?;
        }

        Ok((ndef_buf, remaining_buf))
    }

    /// Emit the QR text of this payload as an iterator of characters
    pub fn emit_chars(&self) -> impl Iterator<Item = Result<char, Error>> + '_ {
        struct PackedBitsIterator<I>(I);

        impl<I> Iterator for PackedBitsIterator<I>
        where
            I: Iterator<Item = Result<bool, Error>>,
        {
            type Item = Result<(u32, u8), Error>;

            fn next(&mut self) -> Option<Self::Item> {
                let mut chunk = 0;
                let mut packed_bits = 0;

                for index in 0..24 {
                    // Up to 24 bits as we are enclding with Base38, which means up to 3 bytes at once
                    if let Some(bit) = self.0.next() {
                        let bit = match bit {
                            Ok(bit) => bit,
                            Err(err) => return Some(Err(err)),
                        };

                        chunk |= (bit as u32) << index;
                        packed_bits += 1;
                    } else {
                        break;
                    }
                }

                if packed_bits > 0 {
                    assert!(packed_bits % 8 == 0);

                    Some(Ok((chunk, packed_bits)))
                } else {
                    None
                }
            }
        }

        "MT:"
            .chars()
            .map(Result::Ok)
            .chain(
                PackedBitsIterator(self.emit_all_bits()).flat_map(|bits| match bits {
                    Ok((bits, bits_count)) => {
                        EitherIter::First(base38::encode_bits(bits, bits_count).map(Result::Ok))
                    }
                    Err(err) => EitherIter::Second(core::iter::once(Err(err))),
                }),
            )
    }

    fn emit_all_bits(&self) -> impl Iterator<Item = Result<bool, Error>> + '_ {
        Self::emit_bits(self.version as _, VERSION_FIELD_LENGTH_IN_BITS)
            .chain(Self::emit_bits(
                self.vid as _,
                VENDOR_IDFIELD_LENGTH_IN_BITS,
            ))
            .chain(Self::emit_bits(
                self.pid as _,
                PRODUCT_IDFIELD_LENGTH_IN_BITS,
            ))
            .chain(Self::emit_bits(
                self.comm_flow as _,
                COMMISSIONING_FLOW_FIELD_LENGTH_IN_BITS,
            ))
            .chain(Self::emit_bits(
                self.discovery_capabilities.bits() as _,
                RENDEZVOUS_INFO_FIELD_LENGTH_IN_BITS,
            ))
            .chain(Self::emit_bits(
                self.comm_data.discriminator as _,
                PAYLOAD_DISCRIMINATOR_FIELD_LENGTH_IN_BITS,
            ))
            .chain(Self::emit_bits(
                u32::from_le_bytes(*self.comm_data.password.access()),
                SETUP_PINCODE_FIELD_LENGTH_IN_BITS,
            ))
            .chain(Self::emit_bits(0, PADDING_FIELD_LENGTH_IN_BITS))
            .chain(
                self.emit_optional_tlv_data()
                    .flat_map(|bits| Self::emit_maybe_bits(bits.map(|bits| (bits as _, 8)))),
            )
    }

    fn emit_bits(input: u32, len: usize) -> impl Iterator<Item = Result<bool, Error>> {
        (0..len).map(move |i| Ok((input >> i) & 1 == 1))
    }

    fn emit_maybe_bits(
        bits: Result<(u32, usize), Error>,
    ) -> impl Iterator<Item = Result<bool, Error>> {
        match bits {
            Ok((input, len)) => EitherIter::First(Self::emit_bits(input, len)),
            Err(err) => EitherIter::Second(core::iter::once(Err(err))),
        }
    }

    fn emit_optional_tlv_data(&self) -> impl Iterator<Item = Result<u8, Error>> + '_ {
        if self.serial_no.is_empty() && (self.optional_data)().next().is_none() {
            return EitherIter::First(core::iter::empty());
        }

        let serial_no = if self.serial_no.is_empty() {
            EitherIter::First(core::iter::empty())
        } else {
            EitherIter::Second(
                TLV::utf8(TLVTag::Context(SERIAL_NUMBER_TAG), self.serial_no).into_tlv_iter(),
            )
        };

        EitherIter::Second(
            TLV::structure(TLVTag::Anonymous)
                .into_tlv_iter()
                .chain(serial_no)
                .flat_map(TLV::result_into_bytes_iter)
                .chain((self.optional_data)())
                .chain(
                    TLV::end_container()
                        .into_tlv_iter()
                        .flat_map(TLV::result_into_bytes_iter),
                ),
        )
    }
}

impl<'a> QrPayload<'a, &'a [u8]> {
    /// Parse a Matter onboarding QR-code text (an `MT:` payload) into a [`QrPayload`].
    ///
    /// This is the inverse of the [`QrPayload::as_str`] / [`QrPayload::emit_chars`]
    /// encoding path, and the entry point a commissioner uses to turn a scanned QR
    /// string into the discriminator, passcode, VID/PID etc. it needs to commission
    /// the device.
    ///
    /// `buf` is a scratch buffer that the parsed payload borrows from: the trailing
    /// optional-TLV data (and hence any serial number decoded out of it) points into
    /// it, so `buf` must outlive the returned payload. A buffer of
    /// [`TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES`] plus the optional-data length is enough;
    /// the base38 body never decodes to more bytes than the input string.
    ///
    /// The returned payload's `optional_data` is the raw optional-TLV byte slice (an
    /// anonymous TLV structure), which is empty when the QR carries no optional data.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidData`] if the string is not a well-formed `MT:`
    /// payload (missing prefix, invalid base38, too short, or an out-of-range field).
    pub fn parse(qr: &str, buf: &'a mut [u8]) -> Result<Self, Error> {
        // Strip the `MT:` prefix.
        let body = qr.strip_prefix(QR_PREFIX).ok_or(ErrorCode::InvalidData)?;

        // Base38-decode the body into `buf`.
        let mut len = 0;
        for byte in base38::decode(body) {
            let byte = byte?;
            *buf.get_mut(len).ok_or(ErrorCode::BufferTooSmall)? = byte;
            len += 1;
        }
        let decoded = &buf[..len];

        // The fixed part of the payload is `TOTAL_PAYLOAD_DATA_SIZE_IN_BITS` bits
        // (`TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES` bytes); anything beyond it is the
        // optional-TLV data.
        if decoded.len() < TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES {
            return Err(ErrorCode::InvalidData.into());
        }

        let mut reader = BitReader::new(decoded);

        // Read the fixed fields in the same order (and LSB-first bit order) as
        // `emit_all_bits` writes them.
        let version = reader.read(VERSION_FIELD_LENGTH_IN_BITS)? as u8;
        let vid = reader.read(VENDOR_IDFIELD_LENGTH_IN_BITS)? as u16;
        let pid = reader.read(PRODUCT_IDFIELD_LENGTH_IN_BITS)? as u16;
        let comm_flow =
            CommFlowType::from_bits(reader.read(COMMISSIONING_FLOW_FIELD_LENGTH_IN_BITS)? as u8)?;
        let discovery_capabilities = DiscoveryCapabilities::from_bits_truncate(
            reader.read(RENDEZVOUS_INFO_FIELD_LENGTH_IN_BITS)? as u8,
        );
        let discriminator = reader.read(PAYLOAD_DISCRIMINATOR_FIELD_LENGTH_IN_BITS)? as u16;
        let passcode = reader.read(SETUP_PINCODE_FIELD_LENGTH_IN_BITS)?;
        // Padding bits (must be present but are ignored).
        let _ = reader.read(PADDING_FIELD_LENGTH_IN_BITS)?;

        // The remaining whole bytes are the optional-TLV data.
        let optional_data = &decoded[TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES..];

        // If present, the serial number is a context-`SERIAL_NUMBER_TAG` UTF-8 string
        // in the anonymous optional-TLV structure. Borrow it out of the blob.
        let serial_no = Self::parse_serial_no(optional_data).unwrap_or("");

        let payload = Self {
            version,
            discovery_capabilities,
            comm_flow,
            comm_data: BasicCommData {
                password: passcode.to_le_bytes().into(),
                discriminator,
            },
            vid,
            pid,
            serial_no,
            optional_data,
        };

        Ok(payload)
    }

    /// Extract the serial number (context tag [`SERIAL_NUMBER_TAG`]) from the
    /// optional-TLV structure, if present.
    fn parse_serial_no(optional_data: &'a [u8]) -> Option<&'a str> {
        if optional_data.is_empty() {
            return None;
        }

        let root = TLVElement::new(optional_data);
        let serial = root.structure().ok()?.find_ctx(SERIAL_NUMBER_TAG).ok()?;

        serial.utf8().ok()
    }

    /// The payload version (always 0 for v1 QR codes).
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// The device's advertised discovery capabilities.
    pub const fn discovery_capabilities(&self) -> DiscoveryCapabilities {
        self.discovery_capabilities
    }

    /// The commissioning flow type.
    pub const fn comm_flow(&self) -> CommFlowType {
        self.comm_flow
    }

    /// The 12-bit discriminator.
    pub const fn discriminator(&self) -> u16 {
        self.comm_data.discriminator
    }

    /// The setup passcode (PIN).
    pub fn passcode(&self) -> u32 {
        u32::from_le_bytes(*self.comm_data.password.access())
    }

    /// The Vendor ID.
    pub const fn vid(&self) -> u16 {
        self.vid
    }

    /// The Product ID.
    pub const fn pid(&self) -> u16 {
        self.pid
    }

    /// The serial number, or an empty string if the QR carries none.
    pub const fn serial_no(&self) -> &'a str {
        self.serial_no
    }

    /// The raw optional-TLV data (an anonymous TLV structure), empty if absent.
    pub const fn optional_data(&self) -> &'a [u8] {
        self.optional_data
    }

    /// A [`CommissionableFilter`] that discovers the device this QR code describes.
    ///
    /// A QR code carries the **full 12-bit** discriminator, so this filters on
    /// `discriminator` and can narrow discovery to a single device. (Contrast
    /// [`QrPayload::<()>::commissionable_filter`], built from a manual pairing code,
    /// which can only filter on the short discriminator.)
    ///
    /// Only the discriminator is set. The vendor and product IDs are deliberately
    /// *not* included even though the QR carries them: per the Matter Core spec a
    /// device may advertise an **anonymized** Product ID of 0 during discovery, so
    /// filtering on the QR's PID would fail to find such a device. Add them to the
    /// returned filter if the extra selectivity is wanted and the device is known
    /// not to anonymize.
    pub fn commissionable_filter(&self) -> CommissionableFilter {
        CommissionableFilter {
            discriminator: Some(self.discriminator()),
            ..Default::default()
        }
    }
}

impl<'a> QrPayload<'a, ()> {
    /// Parse a Matter **manual pairing code** (the 11- or 21-digit decimal string
    /// printed on a device, e.g. `34970112332` / `3497-0112-332`) into a
    /// [`QrPayload`].
    ///
    /// This is the "typed by a human" onboarding format, and it is the counterpart
    /// of [`BasicCommData::compute_pairing_code`]. It is deliberately a *different*
    /// `T` from [`QrPayload::parse`] (`()` rather than `&[u8]`), because a manual
    /// pairing code carries strictly less information than a QR code, and the
    /// resulting payload must not be mistaken for one:
    ///
    /// - Only the **upper 4 bits** of the discriminator are carried (the "short
    ///   discriminator"). Per the Matter Core spec: *"For machine-readable formats,
    ///   the full 12-bit Discriminator is used. For the Manual Pairing Code, only
    ///   the upper 4 bits out of the 12-bit Discriminator are used."* Read it via
    ///   [`Self::short_discriminator`] - there is deliberately no `discriminator()`
    ///   accessor on this `T`, so a 4-bit value can never be mistaken for a 12-bit
    ///   one.
    /// - **No discovery capabilities** are carried, so a commissioner cannot know
    ///   whether to look for the device over BLE, SoftAP or IP, and must try all of
    ///   them.
    /// - **No serial number and no optional TLV data** are carried (hence `T = ()`).
    /// - The commissioning flow is only *implied* - see [`Self::comm_flow`].
    ///
    /// The Verhoeff check digit is verified. Separators (`-` and spaces) are
    /// ignored, so both the compact and the "pretty" printed forms are accepted.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidData`] if the code is not a well-formed v1 manual
    /// pairing code: wrong length, a non-digit, a bad check digit, a first digit of
    /// 8 or 9 (which per spec indicates a future format version), a VID/PID-present
    /// flag inconsistent with the length, or an out-of-range digit group.
    pub fn parse_pairing_code(code: &str) -> Result<Self, Error> {
        /// Length of the manual pairing code without vendor/product IDs.
        const SHORT_CODE_LEN: usize = 11;
        /// Length of the manual pairing code with vendor/product IDs.
        const LONG_CODE_LEN: usize = 21;

        // Strip the separators of the "pretty" form (e.g. `3497-0112-332`).
        let mut digits: heapless::String<LONG_CODE_LEN> = heapless::String::new();
        for ch in code.chars() {
            if matches!(ch, '-' | ' ') {
                continue;
            }

            if !ch.is_ascii_digit() {
                return Err(ErrorCode::InvalidData.into());
            }

            digits
                .push(ch)
                .map_err(|_| Error::from(ErrorCode::InvalidData))?;
        }

        let long_form = match digits.len() {
            SHORT_CODE_LEN => false,
            LONG_CODE_LEN => true,
            _ => return Err(ErrorCode::InvalidData.into()),
        };

        // The trailing check digit protects against typos and transpositions.
        if !digits.validate_verhoeff_check_digit() {
            return Err(ErrorCode::InvalidData.into());
        }

        // DIGIT[1] := (VID_PID_PRESENT << 2) | (DISCRIMINATOR >> 10)
        //
        // A leading digit of 8 or 9 is invalid for v1 and would indicate a future
        // payload version.
        let digit1 = Self::digits_at(&digits, 0, 1)?;
        if digit1 > 7 {
            return Err(ErrorCode::InvalidData.into());
        }

        let vid_pid_present = digit1 >> 2 == 1;
        // The flag and the code length must agree.
        if vid_pid_present != long_form {
            return Err(ErrorCode::InvalidData.into());
        }

        // The two most significant bits (11..10) of the discriminator.
        let disc_bits_11_10 = (digit1 & 0x3) as u16;

        // DIGIT[2..6] := ((DISCRIMINATOR & 0x300) << 6) | (PASSCODE & 0x3FFF)
        let group = Self::digits_at(&digits, 1, 5)?;
        if group > 0xFFFF {
            return Err(ErrorCode::InvalidData.into());
        }

        // Bits 9..8 of the discriminator, and the low 14 bits of the passcode.
        let disc_bits_9_8 = ((group >> 14) & 0x3) as u16;
        let passcode_low = group & 0x3FFF;

        // DIGIT[7..10] := (PASSCODE >> 14)
        let passcode_high = Self::digits_at(&digits, 6, 4)?;
        if passcode_high > 0x1FFF {
            return Err(ErrorCode::InvalidData.into());
        }

        let passcode = (passcode_high << 14) | passcode_low;

        // The short discriminator is exactly the upper 4 bits (11..8) of the full
        // 12-bit discriminator.
        let short_discriminator = (disc_bits_11_10 << 2) | disc_bits_9_8;

        // DIGIT[11..15] := VENDOR_ID, DIGIT[16..20] := PRODUCT_ID (long form only)
        let (vid, pid) = if long_form {
            let vid = Self::digits_at(&digits, 10, 5)?;
            let pid = Self::digits_at(&digits, 15, 5)?;

            if vid > 0xFFFF || pid > 0xFFFF {
                return Err(ErrorCode::InvalidData.into());
            }

            (vid as u16, pid as u16)
        } else {
            (0, 0)
        };

        Ok(Self {
            // Not carried; a valid v1 code is version 0 by construction (a leading
            // digit of 8 or 9 - i.e. a future version - is rejected above).
            version: 0,
            // Not carried at all. Empty means "unknown - try every transport",
            // rather than "the device supports none".
            discovery_capabilities: DiscoveryCapabilities::empty(),
            // Not carried directly; per spec the *variant* implies it, and doubles as
            // our short/long-form discriminant. See `Self::comm_flow`.
            comm_flow: if long_form {
                CommFlowType::Custom
            } else {
                CommFlowType::Standard
            },
            comm_data: BasicCommData {
                password: passcode.to_le_bytes().into(),
                // NOTE: this 12-bit field holds the 4-bit *short* discriminator for a
                // manual pairing code. Only `short_discriminator()` exposes it.
                discriminator: short_discriminator,
            },
            vid,
            pid,
            // Not carried.
            serial_no: "",
            // A manual pairing code has no optional data - hence `T = ()`.
            optional_data: (),
        })
    }

    /// Parse `len` decimal digits starting at `offset`.
    fn digits_at(digits: &str, offset: usize, len: usize) -> Result<u32, Error> {
        digits
            .get(offset..offset + len)
            .ok_or(ErrorCode::InvalidData)?
            .parse()
            .map_err(|_| ErrorCode::InvalidData.into())
    }

    /// The **short** (4-bit) discriminator - the upper 4 bits of the device's full
    /// 12-bit discriminator.
    ///
    /// This is all a manual pairing code carries, so it can only narrow discovery to
    /// 1-in-16 devices. Feed it to
    /// [`CommissionableFilter::short_discriminator`](crate::transport::network::mdns::CommissionableFilter),
    /// *not* to the full-discriminator filter.
    pub const fn short_discriminator(&self) -> u8 {
        self.comm_data.discriminator as u8
    }

    /// The setup passcode (PIN). Carried in full (27 bits).
    pub fn passcode(&self) -> u32 {
        u32::from_le_bytes(*self.comm_data.password.access())
    }

    /// The Vendor and Product IDs, if this is the 21-digit variant that carries them
    /// (`None` for the 11-digit variant).
    pub fn vid_pid(&self) -> Option<(u16, u16)> {
        (!matches!(self.comm_flow, CommFlowType::Standard)).then_some((self.vid, self.pid))
    }

    /// The commissioning flow, as far as the code determines it.
    ///
    /// A manual pairing code has no dedicated commissioning-flow field; per the
    /// Matter Core spec the *variant* implies it:
    /// - The 11-digit variant (no VID/PID) means the commissioner *"SHALL assume it
    ///   is a standard flow device"* - so this returns `Some(CommFlowType::Standard)`.
    /// - The 21-digit variant (with VID/PID) is used for **both** the User-intent and
    ///   the Custom flow, and the code alone cannot distinguish them - so this
    ///   returns `None`. To resolve it, look the VID/PID up in the Distributed
    ///   Compliance Ledger (see [`Self::vid_pid`]).
    pub fn comm_flow(&self) -> Option<CommFlowType> {
        matches!(self.comm_flow, CommFlowType::Standard).then_some(CommFlowType::Standard)
    }

    /// A [`CommissionableFilter`] that discovers the device this manual pairing code
    /// describes.
    ///
    /// A manual pairing code only carries the **short** (4-bit) discriminator, so
    /// this necessarily filters on `short_discriminator` - which narrows discovery
    /// to 1-in-16 devices rather than to exactly one. Getting this right is the
    /// whole point of the method: the short value must not end up in the filter's
    /// full-discriminator field, where it would match nothing.
    ///
    /// The vendor and product IDs are not included even when the 21-digit variant
    /// carries them, since a device may advertise an anonymized Product ID of 0
    /// during discovery.
    pub fn commissionable_filter(&self) -> CommissionableFilter {
        CommissionableFilter {
            short_discriminator: Some(self.short_discriminator()),
            ..Default::default()
        }
    }
}

impl CommFlowType {
    /// Decode a 2-bit commissioning-flow field.
    fn from_bits(bits: u8) -> Result<Self, Error> {
        match bits {
            0 => Ok(Self::Standard),
            1 => Ok(Self::UserIntent),
            2 => Ok(Self::Custom),
            _ => Err(ErrorCode::InvalidData.into()),
        }
    }
}

/// A little-endian, LSB-first bit reader over a byte slice - the inverse of the
/// `emit_bits` bit order used by the QR encoder (`(input >> i) & 1`).
struct BitReader<'a> {
    data: &'a [u8],
    /// Absolute bit position of the next bit to read.
    pos: usize,
}

impl<'a> BitReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Read `len` bits (0..=32) as a little-endian value, LSB-first.
    fn read(&mut self, len: usize) -> Result<u32, Error> {
        debug_assert!(len <= 32);

        if self.pos + len > self.data.len() * 8 {
            return Err(ErrorCode::InvalidData.into());
        }

        let mut value = 0u32;
        for i in 0..len {
            let bit_pos = self.pos + i;
            let byte = self.data[bit_pos / 8];
            let bit = (byte >> (bit_pos % 8)) & 1;
            value |= (bit as u32) << i;
        }

        self.pos += len;

        Ok(value)
    }
}

/// QR Code text type
///
/// Used when emitting the QR code in different text formats
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum QrTextType {
    /// Pure ASCII text
    /// Compatible with all consoles
    Ascii,
    /// ANSI
    Ansi,
    /// Unicode
    Unicode,
}

/// QR Code representation
pub struct Qr<'a>(QrCode<'a>);

impl<'a> Qr<'a> {
    /// Create a new QR code from the given text
    ///
    /// # Arguments
    /// - `text` - Text to encode in the QR code
    /// - `tmp_buf` - Temporary buffer for QR code generation
    /// - `out_buf` - Output buffer for the QR code
    ///
    /// # Returns
    /// - On success, returns the generated QR code
    /// - On failure, returns an error
    pub fn compute(text: &str, tmp_buf: &mut [u8], out_buf: &'a mut [u8]) -> Result<Self, Error> {
        let needed_version = Version::new(Self::version(text));

        let qr = QrCode::encode_text(
            text,
            tmp_buf,
            out_buf,
            QrCodeEcc::Medium,
            needed_version,
            needed_version,
            None,
            false,
        )
        .map_err(|_| ErrorCode::BufferTooSmall)?;

        Ok(Self(qr))
    }

    /// Get the size of the QR code
    pub fn size(&self) -> u32 {
        self.0.size() as _
    }

    /// Get the module value at the given coordinates
    pub fn get_module(&self, x: i32, y: i32) -> bool {
        self.0.get_module(x, y)
    }

    /// Encode the QR as a string into the provided buffer
    ///
    /// # Arguments
    /// - `text_type` - Type of text to return (ASCII, ANSI, Unicode)
    /// - `border` - Border size
    /// - `invert` - Whether to invert the colors (black on a white background)
    /// - `out_buf` - Output buffer for the rendered string
    ///
    /// # Returns
    /// - On success, returns a tuple containing the rendered string and the remaining buffer
    /// - On failure, returns an error
    pub fn as_str<'b>(
        &self,
        text_type: QrTextType,
        border: u8,
        invert: bool,
        out_buf: &'b mut [u8],
    ) -> Result<(&'b str, &'b mut [u8]), Error> {
        let mut offset = 0;

        for c in self.emit_chars(text_type, border, invert) {
            let mut dst = [0; 4];
            let bytes = c.encode_utf8(&mut dst).as_bytes();

            if offset + bytes.len() > out_buf.len() {
                return Err(ErrorCode::BufferTooSmall.into());
            } else {
                out_buf[offset..offset + bytes.len()].copy_from_slice(bytes);
                offset += bytes.len();
            }
        }

        let (str_buf, remaining_buf) = out_buf.split_at_mut(offset);

        // Can't fail as `emit_chars` generates a valid UTF-8 string
        let str = unwrap!(core::str::from_utf8(str_buf).map_err(|_| ErrorCode::InvalidData));

        Ok((str, remaining_buf))
    }

    /// Encode a single line of the QR as a string into the provided buffer
    ///
    /// # Arguments
    /// - `text_type` - Type of text to return (ASCII, ANSI, Unicode)
    /// - `border` - Border size
    /// - `invert` - Whether to invert the colors (black on a white background)
    /// - `nl` - Whether to add a newline at the end of the line
    /// - `y` - Y coordinate of the line to render
    /// - `out_buf` - Output buffer for the rendered string
    ///
    /// # Returns
    /// - On success, returns a tuple containing the rendered string and the remaining buffer
    /// - On failure, returns an error
    pub fn line_as_str<'b>(
        &self,
        text_type: QrTextType,
        border: u8,
        invert: bool,
        nl: bool,
        y: i32,
        out_buf: &'b mut [u8],
    ) -> Result<(&'b str, &'b mut [u8]), Error> {
        let mut offset = 0;

        for c in self.emit_line_chars(text_type, border, invert, nl, y) {
            let mut dst = [0; 4];
            let bytes = c.encode_utf8(&mut dst).as_bytes();

            if offset + bytes.len() > out_buf.len() {
                return Err(ErrorCode::BufferTooSmall.into());
            } else {
                out_buf[offset..offset + bytes.len()].copy_from_slice(bytes);
                offset += bytes.len();
            }
        }

        let (str_buf, remaining_buf) = out_buf.split_at_mut(offset);

        // Can't fail as `emit_chars` generates a valid UTF-8 string
        let str = unwrap!(core::str::from_utf8(str_buf).map_err(|_| ErrorCode::InvalidData));

        Ok((str, remaining_buf))
    }

    /// Get an iterator over the indexes of the lines of the QR code including borders
    ///
    /// # Arguments
    /// - `text_type` - Type of text to return (ASCII, ANSI, Unicode)
    /// - `border` - Border size
    pub fn lines_range(
        &self,
        text_type: QrTextType,
        border: u8,
    ) -> impl Iterator<Item = i32> + '_ + 'a {
        let iborder: i32 = border as _;

        (-iborder..self.size() as i32 + iborder)
            .filter(move |y| !matches!(text_type, QrTextType::Unicode) || (*y - -iborder) % 2 == 0)
    }

    /// Get an iterator over the characters of the rendered QR code
    ///
    /// # Arguments
    /// - `text_type` - Type of text to return (ASCII, ANSI, Unicode)
    /// - `border` - Border size
    /// - `invert` - Whether to invert the colors (black on a white background)
    ///
    /// # Returns
    /// - An iterator over the characters of the rendered QR code
    pub fn emit_chars(
        &self,
        text_type: QrTextType,
        border: u8,
        invert: bool,
    ) -> impl Iterator<Item = char> + use<'_, 'a> {
        self.lines_range(text_type, border)
            .flat_map(move |y| self.emit_line_chars(text_type, border, invert, true, y))
    }

    /// Get an iterator over the characters of a single line of the rendered QR code
    ///
    /// # Arguments
    /// - `text_type` - Type of text to return (ASCII, ANSI, Unicode)
    /// - `border` - Border size
    /// - `invert` - Whether to invert the colors (black on a white background)
    /// - `nl` - Whether to add a newline at the end of the line
    /// - `y` - Y coordinate of the line to render
    ///
    /// # Returns
    /// - An iterator over the characters of the rendered line
    pub fn emit_line_chars(
        &self,
        text_type: QrTextType,
        border: u8,
        invert: bool,
        nl: bool,
        y: i32,
    ) -> impl Iterator<Item = char> + use<'_, 'a> {
        let border: i32 = border as _;

        (-border..self.size() as i32 + border + 1)
            .map(move |x| (x, y))
            .map(move |(x, y)| {
                if x < self.size() as i32 + border {
                    let white = !self.get_module(x, y) ^ invert;

                    match text_type {
                        QrTextType::Ascii => {
                            if white {
                                "#"
                            } else {
                                " "
                            }
                        }
                        QrTextType::Ansi => {
                            let prev_white = if x > -border {
                                Some(self.get_module(x - 1, y))
                            } else {
                                None
                            }
                            .map(|prev_white| !prev_white ^ invert);

                            if prev_white != Some(white) {
                                if white {
                                    "\x1b[47m "
                                } else {
                                    "\x1b[40m "
                                }
                            } else {
                                " "
                            }
                        }
                        QrTextType::Unicode => {
                            if white == !self.get_module(x, y + 1) ^ invert {
                                if white {
                                    "\u{2588}"
                                } else {
                                    " "
                                }
                            } else if white {
                                "\u{2580}"
                            } else {
                                "\u{2584}"
                            }
                        }
                    }
                } else {
                    match text_type {
                        QrTextType::Ascii => {
                            if nl {
                                "\n"
                            } else {
                                ""
                            }
                        }
                        _ => {
                            if nl {
                                "\x1b[0m\n"
                            } else {
                                "\x1b[0m"
                            }
                        }
                    }
                }
            })
            .flat_map(str::chars)
    }

    fn version(qr_code_text: &str) -> u8 {
        match qr_code_text.len() {
            0..=38 => 2,
            39..=61 => 3,
            62..=90 => 4,
            _ => 5,
        }
    }
}

/// QR Code text renderer
pub enum QrTextRenderer<'a> {
    /// ASCII renderer
    Ascii(Qr<'a>),
    /// ANSI renderer
    Ansi(Qr<'a>),
    /// Unicode renderer
    Unicode(Qr<'a>),
}

impl<'a> QrTextRenderer<'a> {
    /// Render the complete QR code as a string into the provided buffer
    ///
    /// # Arguments
    /// - `border` - Border size
    /// - `invert` - Whether to invert the colors (black on a white background)
    /// - `out_buf` - Output buffer for the rendered string
    ///
    /// # Returns
    /// - On success, returns a tuple containing the rendered string and the remaining buffer
    /// - On failure, returns an error
    pub fn render<'b>(
        &self,
        border: u8,
        invert: bool,
        out_buf: &'b mut [u8],
    ) -> Result<(&'b str, &'b mut [u8]), Error> {
        let mut offset = 0;

        for c in self.render_iter(border, invert) {
            let mut dst = [0; 4];
            let bytes = c.encode_utf8(&mut dst).as_bytes();

            if offset + bytes.len() > out_buf.len() {
                return Err(ErrorCode::BufferTooSmall.into());
            } else {
                out_buf[offset..offset + bytes.len()].copy_from_slice(bytes);
                offset += bytes.len();
            }
        }

        let (str_buf, remaining_buf) = out_buf.split_at_mut(offset);

        // Can't fail as `emit_chars` generates a valid UTF-8 string
        let str = unwrap!(core::str::from_utf8(str_buf).map_err(|_| ErrorCode::InvalidData));

        Ok((str, remaining_buf))
    }

    /// Render a single line of the QR code as a string into the provided buffer
    ///
    /// # Arguments
    /// - `border` - Border size
    /// - `invert` - Whether to invert the colors (black on a white background)
    /// - `nl` - Whether to add a newline at the end of the line
    /// - `y` - Y coordinate of the line to render
    /// - `out_buf` - Output buffer for the rendered string
    ///
    /// # Returns
    /// - On success, returns a tuple containing the rendered string and the remaining buffer
    /// - On failure, returns an error
    pub fn render_line<'b>(
        &self,
        border: u8,
        invert: bool,
        nl: bool,
        y: i32,
        out_buf: &'b mut [u8],
    ) -> Result<(&'b str, &'b mut [u8]), Error> {
        let mut offset = 0;

        for c in self.render_line_iter(border, invert, nl, y) {
            let mut dst = [0; 4];
            let bytes = c.encode_utf8(&mut dst).as_bytes();

            if offset + bytes.len() > out_buf.len() {
                return Err(ErrorCode::BufferTooSmall.into());
            } else {
                out_buf[offset..offset + bytes.len()].copy_from_slice(bytes);
                offset += bytes.len();
            }
        }

        let (str_buf, remaining_buf) = out_buf.split_at_mut(offset);

        // Can't fail as `emit_chars` generates a valid UTF-8 string
        let str = unwrap!(core::str::from_utf8(str_buf).map_err(|_| ErrorCode::InvalidData));

        Ok((str, remaining_buf))
    }

    /// Get an iterator over the indexes of the lines of the QR code including borders
    ///
    /// # Arguments
    /// - `border` - Border size
    pub fn lines_range(&self, border: u8) -> impl Iterator<Item = i32> + '_ + 'a {
        let unicode = matches!(self, Self::Unicode(_));
        let iborder: i32 = border as _;

        (-iborder..self.qr().size() as i32 + iborder)
            .filter(move |y| !unicode || (*y - -iborder) % 2 == 0)
    }

    /// Get an iterator over the characters of the rendered QR code
    ///
    /// # Arguments
    /// - `border` - Border size
    /// - `invert` - Whether to invert the colors (black on a white background)
    ///
    /// # Returns
    /// - An iterator over the characters of the rendered QR code
    pub fn render_iter(
        &self,
        border: u8,
        invert: bool,
    ) -> impl Iterator<Item = char> + use<'_, 'a> {
        self.lines_range(border)
            .flat_map(move |y| self.render_line_iter(border, invert, true, y))
    }

    /// Get an iterator over the characters of a single line of the rendered QR code
    ///
    /// # Arguments
    /// - `border` - Border size
    /// - `invert` - Whether to invert the colors (black on a white background)
    /// - `nl` - Whether to add a newline at the end of the line
    /// - `y` - Y coordinate of the line to render
    ///
    /// # Returns
    /// - An iterator over the characters of the rendered line
    pub fn render_line_iter(
        &self,
        border: u8,
        invert: bool,
        nl: bool,
        y: i32,
    ) -> impl Iterator<Item = char> + use<'_, 'a> {
        let border: i32 = border as _;

        (-border..self.qr().size() as i32 + border + 1)
            .map(move |x| (x, y))
            .map(move |(x, y)| {
                if x < self.qr().size() as i32 + border {
                    let white = !self.qr().get_module(x, y) ^ invert;

                    match self {
                        Self::Ascii(_) => {
                            if white {
                                "#"
                            } else {
                                " "
                            }
                        }
                        Self::Ansi(_) => {
                            let prev_white = if x > -border {
                                Some(self.qr().get_module(x - 1, y))
                            } else {
                                None
                            }
                            .map(|prev_white| !prev_white ^ invert);

                            if prev_white != Some(white) {
                                if white {
                                    "\x1b[47m "
                                } else {
                                    "\x1b[40m "
                                }
                            } else {
                                " "
                            }
                        }
                        Self::Unicode(_) => {
                            if white == !self.qr().get_module(x, y + 1) ^ invert {
                                if white {
                                    "\u{2588}"
                                } else {
                                    " "
                                }
                            } else if white {
                                "\u{2580}"
                            } else {
                                "\u{2584}"
                            }
                        }
                    }
                } else {
                    match self {
                        Self::Ascii(_) => {
                            if nl {
                                "\n"
                            } else {
                                ""
                            }
                        }
                        _ => {
                            if nl {
                                "\x1b[0m\n"
                            } else {
                                "\x1b[0m"
                            }
                        }
                    }
                }
            })
            .flat_map(str::chars)
    }

    #[inline(always)]
    pub fn qr(&self) -> &Qr<'a> {
        match self {
            Self::Ascii(qr) => qr,
            Self::Ansi(qr) => qr,
            Self::Unicode(qr) => qr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_base38_encode() {
        const QR_CODE: &str = "MT:YNJV7VSC00CMVH7SR00";

        let comm_data = BasicCommData {
            password: 34567890_u32.to_le_bytes().into(),
            discriminator: 2976,
        };
        let dev_det = BasicInfoConfig {
            vid: 9050,
            pid: 65279,
            ..Default::default()
        };

        let disc_cap = DiscoveryCapabilities::BLE;
        let qr_code_data = QrPayload::new_from_basic_info(
            disc_cap,
            CommFlowType::Standard,
            comm_data,
            &dev_det,
            no_optional_data,
        );
        let mut buf = [0; 1024];
        let data_str = unwrap!(qr_code_data.as_str(&mut buf), "Failed to encode").0;
        assert_eq!(data_str, QR_CODE)
    }

    /// The bit positions are fixed by the Matter Core spec's Discovery
    /// Capabilities Bitmask, and a payload carrying PAF or NTL has to survive a
    /// round-trip: `parse` uses `from_bits_truncate`, so any bit the type does
    /// not define is silently dropped off a peer's payload.
    #[test]
    fn discovery_capability_bits_round_trip() {
        assert_eq!(DiscoveryCapabilities::BLE.bits(), 1 << 1);
        assert_eq!(DiscoveryCapabilities::IP.bits(), 1 << 2);
        assert_eq!(DiscoveryCapabilities::PAF.bits(), 1 << 3);
        assert_eq!(DiscoveryCapabilities::NTL.bits(), 1 << 4);

        let comm_data = BasicCommData {
            password: 20202021_u32.to_le_bytes().into(),
            discriminator: 3840,
        };
        let dev_det = BasicInfoConfig {
            vid: 65521,
            pid: 32769,
            ..Default::default()
        };

        let caps = DiscoveryCapabilities::BLE | DiscoveryCapabilities::NTL;

        let payload = QrPayload::new_from_basic_info(
            caps,
            CommFlowType::Standard,
            comm_data,
            &dev_det,
            no_optional_data,
        );

        let mut buf = [0; 1024];
        let (text, buf) = unwrap!(payload.as_str(&mut buf), "Failed to encode");

        let mut parse_buf = [0; 1024];
        let parsed = unwrap!(QrPayload::parse(text, &mut parse_buf), "Failed to parse");

        assert_eq!(parsed.discovery_capabilities, caps);

        let _ = buf;
    }

    /// The NFC tag carries the same onboarding payload as the QR code, wrapped
    /// in the single NDEF URI record the Matter Core spec fixes byte for byte.
    #[test]
    fn encodes_the_nfc_ndef_record() {
        const QR_CODE: &str = "MT:YNJV7VSC00CMVH7SR00";

        let comm_data = BasicCommData {
            password: 34567890_u32.to_le_bytes().into(),
            discriminator: 2976,
        };
        let dev_det = BasicInfoConfig {
            vid: 9050,
            pid: 65279,
            ..Default::default()
        };

        let qr_code_data = QrPayload::new_from_basic_info(
            DiscoveryCapabilities::BLE,
            CommFlowType::Standard,
            comm_data,
            &dev_det,
            no_optional_data,
        );

        let mut buf = [0; 1024];
        let ndef = unwrap!(qr_code_data.as_ndef(&mut buf), "Failed to encode").0;

        // Header, then the URI text verbatim.
        assert_eq!(
            ndef,
            [
                &[0xd1, 0x01, (QR_CODE.len() + 1) as u8, 0x55, 0x00][..],
                QR_CODE.as_bytes(),
            ]
            .concat()
        );

        // The URI data is exactly what the QR code carries: one payload, two
        // carriers.
        assert_eq!(&ndef[5..], QR_CODE.as_bytes());
    }

    #[test]
    fn can_base38_encode_with_vendor_data() {
        const QR_CODE: &str = "MT:-24J0AFN00KA064IJ3P0IXZB0DK5N1K8SQ1RYCU1-A40";

        let comm_data = BasicCommData {
            password: 20202021_u32.to_le_bytes().into(),
            discriminator: 3840,
        };
        let dev_det = BasicInfoConfig {
            vid: 65521,
            pid: 32769,
            serial_no: "1234567890",
            ..Default::default()
        };

        let disc_cap = DiscoveryCapabilities::IP;
        let qr_code_data = QrPayload::new_from_basic_info(
            disc_cap,
            CommFlowType::Standard,
            comm_data,
            &dev_det,
            no_optional_data,
        );
        let mut buf = [0; 1024];
        let data_str = unwrap!(qr_code_data.as_str(&mut buf), "Failed to encode").0;
        assert_eq!(data_str, QR_CODE)
    }

    #[test]
    fn can_base38_encode_with_optional_data() {
        const QR_CODE: &str =
            "MT:-24J0AFN00KA064IJ3P0IXZB0DK5N1K8SQ1RYCU1UXH34YY0V3KY.O3DKN440F710Q940";
        const OPTIONAL_DEFAULT_STRING_TAG: u8 = 0x82; // Vendor "test" tag
        const OPTIONAL_DEFAULT_STRING_VALUE: &str = "myData";

        const OPTIONAL_DEFAULT_INT_TAG: u8 = 0x83; // Vendor "test" tag
        const OPTIONAL_DEFAULT_INT_VALUE: i32 = 65550;

        let comm_data = BasicCommData {
            password: 20202021_u32.to_le_bytes().into(),
            discriminator: 3840,
        };
        let dev_det = BasicInfoConfig {
            vid: 65521,
            pid: 32769,
            serial_no: "1234567890",
            ..Default::default()
        };

        let disc_cap = DiscoveryCapabilities::IP;
        let optional_data = || {
            TLV::utf8(
                TLVTag::Context(OPTIONAL_DEFAULT_STRING_TAG),
                OPTIONAL_DEFAULT_STRING_VALUE,
            )
            .into_tlv_iter()
            .chain(
                TLV::i32(
                    TLVTag::Context(OPTIONAL_DEFAULT_INT_TAG),
                    OPTIONAL_DEFAULT_INT_VALUE,
                )
                .into_tlv_iter(),
            )
            .flat_map(TLV::result_into_bytes_iter)
        };

        let qr_code_data = QrPayload::new_from_basic_info(
            disc_cap,
            CommFlowType::Standard,
            comm_data,
            &dev_det,
            optional_data,
        );

        let mut buf = [0; 1024];
        let data_str = unwrap!(qr_code_data.as_str(&mut buf), "Failed to encode").0;
        assert_eq!(data_str, QR_CODE)
    }

    #[test]
    fn parse_qr_basic() {
        // Same vector as `can_base38_encode` (BLE, no optional data).
        const QR_CODE: &str = "MT:YNJV7VSC00CMVH7SR00";

        let mut buf = [0; 128];
        let payload = unwrap!(QrPayload::parse(QR_CODE, &mut buf), "Failed to parse");

        assert_eq!(payload.version(), 0);
        assert_eq!(payload.vid(), 9050);
        assert_eq!(payload.pid(), 65279);
        assert_eq!(payload.comm_flow(), CommFlowType::Standard);
        assert_eq!(payload.discovery_capabilities(), DiscoveryCapabilities::BLE);
        assert_eq!(payload.discriminator(), 2976);
        assert_eq!(payload.passcode(), 34567890);
        assert_eq!(payload.serial_no(), "");
        assert!(payload.optional_data().is_empty());
    }

    #[test]
    fn parse_qr_with_serial_no() {
        // Same vector as `can_base38_encode_with_vendor_data` (IP, serial number).
        const QR_CODE: &str = "MT:-24J0AFN00KA064IJ3P0IXZB0DK5N1K8SQ1RYCU1-A40";

        let mut buf = [0; 128];
        let payload = unwrap!(QrPayload::parse(QR_CODE, &mut buf), "Failed to parse");

        assert_eq!(payload.vid(), 65521);
        assert_eq!(payload.pid(), 32769);
        assert_eq!(payload.discovery_capabilities(), DiscoveryCapabilities::IP);
        assert_eq!(payload.discriminator(), 3840);
        assert_eq!(payload.passcode(), 20202021);
        assert_eq!(payload.serial_no(), "1234567890");
        assert!(!payload.optional_data().is_empty());
    }

    #[test]
    fn parse_qr_round_trips_through_encode() {
        // Parse a QR, then re-encode from the parsed *fields* and expect the same
        // string. (We rebuild via the fields rather than replaying the raw optional
        // blob, since the encoder re-wraps the serial number into the optional-TLV
        // structure itself - here the serial is the only optional content.)
        const QR_CODE: &str = "MT:-24J0AFN00KA064IJ3P0IXZB0DK5N1K8SQ1RYCU1-A40";

        let mut buf = [0; 128];
        let payload = unwrap!(QrPayload::parse(QR_CODE, &mut buf), "Failed to parse");

        let reencoded = QrPayload::new(
            payload.discovery_capabilities(),
            payload.comm_flow(),
            payload.comm_data.clone(),
            payload.vid(),
            payload.pid(),
            payload.serial_no(),
            no_optional_data,
        );

        let mut out = [0; 256];
        let s = unwrap!(reencoded.as_str(&mut out), "Failed to encode").0;
        assert_eq!(s, QR_CODE);
    }

    #[test]
    fn parse_pairing_code_round_trips_with_encoder() {
        // The two vectors from `code.rs`'s `can_compute_pairing_code`, parsed back.
        for (code, passcode, discriminator) in [
            ("00876800071", 123456_u32, 250_u16),
            ("26318621095", 34567890, 2976),
        ] {
            let payload = unwrap!(QrPayload::parse_pairing_code(code), "Failed to parse");

            assert_eq!(payload.passcode(), passcode);
            // Only the upper 4 bits of the discriminator survive a manual code.
            assert_eq!(payload.short_discriminator(), (discriminator >> 8) as u8);
            // The 11-digit variant implies the standard flow and carries no VID/PID.
            assert_eq!(payload.comm_flow(), Some(CommFlowType::Standard));
            assert_eq!(payload.vid_pid(), None);
            // Nothing tells us how to reach the device.
            assert!(payload.discovery_capabilities.is_empty());

            // And the code we parsed re-computes from the parsed passcode + a
            // discriminator whose upper 4 bits match.
            let comm_data = BasicCommData {
                password: payload.passcode().to_le_bytes().into(),
                discriminator,
            };
            assert_eq!(comm_data.compute_pairing_code(), code);
        }
    }

    #[test]
    fn commissionable_filter_uses_the_right_discriminator_field() {
        // A QR carries the full 12-bit discriminator...
        let mut buf = [0; 128];
        let qr = unwrap!(
            QrPayload::parse("MT:-24J0AFN00KA064IJ3P0IXZB0DK5N1K8SQ1RYCU1-A40", &mut buf),
            "Failed to parse"
        );
        let filter = qr.commissionable_filter();

        assert_eq!(filter.discriminator, Some(3840));
        assert_eq!(filter.short_discriminator, None);

        // ... while a manual pairing code only carries the upper 4 bits, which must
        // land in `short_discriminator` (0xF00 >> 8 == 15) and *not* in the
        // full-discriminator field, where it would match nothing.
        let manual = unwrap!(QrPayload::parse_pairing_code("34970112332"), "Failed");
        let filter = manual.commissionable_filter();

        assert_eq!(filter.short_discriminator, Some(15));
        assert_eq!(filter.discriminator, None);

        // Neither constrains vendor/product: a device may advertise an anonymized
        // Product ID of 0 during discovery.
        assert_eq!(filter.vendor_id, None);
        assert_eq!(filter.product_id, None);
    }

    #[test]
    fn parse_pairing_code_accepts_pretty_form() {
        // The canonical CHIP test device: discriminator 3840, passcode 20202021.
        let compact = unwrap!(QrPayload::parse_pairing_code("34970112332"), "compact");
        let pretty = unwrap!(QrPayload::parse_pairing_code("3497-0112-332"), "pretty");

        assert_eq!(compact.passcode(), 20202021);
        assert_eq!(compact.short_discriminator(), 15); // 3840 >> 8
        assert_eq!(pretty.passcode(), compact.passcode());
        assert_eq!(pretty.short_discriminator(), compact.short_discriminator());
    }

    #[test]
    fn parse_pairing_code_rejects_bad_input() {
        // Bad Verhoeff check digit (last digit of the valid code bumped).
        assert!(QrPayload::parse_pairing_code("34970112333").is_err());
        // Not a digit.
        assert!(QrPayload::parse_pairing_code("3497011233X").is_err());
        // Wrong length (neither 11 nor 21).
        assert!(QrPayload::parse_pairing_code("3497011233").is_err());
        // A leading digit of 8/9 indicates a future payload version, not v1.
        assert!(QrPayload::parse_pairing_code("94970112332").is_err());
        // VID/PID-present flag set (leading digit >= 4) but only 11 digits.
        assert!(QrPayload::parse_pairing_code("74970112332").is_err());
    }

    #[test]
    fn parse_qr_rejects_bad_input() {
        let mut buf = [0; 128];

        // Missing `MT:` prefix.
        assert!(QrPayload::parse("YNJV7VSC00CMVH7SR00", &mut buf).is_err());
        // Invalid base38 character (`!`).
        assert!(QrPayload::parse("MT:YNJV7VSC00CMVH7SR0!", &mut buf).is_err());
        // Too short to hold the fixed payload.
        assert!(QrPayload::parse("MT:00", &mut buf).is_err());
    }
}
