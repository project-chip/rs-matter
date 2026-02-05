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

use core::iter::Empty;

use qrcodegen_no_heap::{QrCode, QrCodeEcc, Version};

use crate::error::ErrorCode;
use crate::tlv::{EitherIter, TLVTag, TLV};
use crate::utils::codec::base38;
use crate::utils::storage::WriteBuf;

use super::*;

// See section 5.1.2. QR Code in the Matter specification
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

// Spec 5.1.4.2 CHIP-Common Reserved Tags
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
        if setup_pin == SETUP_PINCODE_UNDEFINED_VALUE
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
            || setup_pin == 87654321
        {
            return false;
        }

        true
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
                return Err(ErrorCode::BufferTooSmall)?;
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
                return Err(ErrorCode::BufferTooSmall)?;
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
                return Err(ErrorCode::BufferTooSmall)?;
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
                return Err(ErrorCode::BufferTooSmall)?;
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
}
