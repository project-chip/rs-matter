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

use qrcodegen_no_heap::{QrCode, QrCodeEcc, Version};

use crate::{
    error::ErrorCode,
    tlv::{ElementType, TLVElement, TLVWriter, TagType, ToTLV},
    utils::writebuf::WriteBuf,
};

use super::{
    vendor_identifiers::{is_vendor_id_valid_operationally, VendorId},
    *,
};

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

pub struct QrSetupPayload<'data> {
    version: u8,
    flow_type: CommissionningFlowType,
    discovery_capabilities: DiscoveryCapabilities,
    dev_det: &'data BasicInfoConfig<'data>,
    comm_data: &'data CommissioningData,
    // The slice must be ordered by the tag of each `TLVElement` in ascending order.
    optional_data: &'data [TLVElement<'data>],
}

impl<'data> QrSetupPayload<'data> {
    /// `optional_data` should be ordered by tag number in ascending order.
    pub fn new(
        dev_det: &'data BasicInfoConfig,
        comm_data: &'data CommissioningData,
        discovery_capabilities: DiscoveryCapabilities,
        optional_data: &'data [TLVElement<'data>],
    ) -> Self {
        const DEFAULT_VERSION: u8 = 0;

        Self {
            version: DEFAULT_VERSION,
            flow_type: CommissionningFlowType::Standard,
            discovery_capabilities,
            dev_det,
            comm_data,
            optional_data,
        }
    }

    pub fn is_valid(&self) -> bool {
        let passwd = passwd_from_comm_data(self.comm_data);

        // 3-bit value specifying the QR code payload version.
        if self.version >= 1 << VERSION_FIELD_LENGTH_IN_BITS {
            return false;
        }

        if !self.discovery_capabilities.has_value() {
            return false;
        }

        if passwd >= 1 << SETUP_PINCODE_FIELD_LENGTH_IN_BITS {
            return false;
        }

        self.check_payload_common_constraints()
    }

    fn check_payload_common_constraints(&self) -> bool {
        // A version not equal to 0 would be invalid for v1 and would indicate new format (e.g. version 2)
        if self.version != 0 {
            return false;
        }

        let passwd = passwd_from_comm_data(self.comm_data);

        if !Self::is_valid_setup_pin(passwd) {
            return false;
        }

        // VendorID must be unspecified (0) or in valid range expected.
        if !is_vendor_id_valid_operationally(self.dev_det.vid)
            && (self.dev_det.vid != VendorId::CommonOrUnspecified as u16)
        {
            return false;
        }

        // A value of 0x0000 SHALL NOT be assigned to a product since Product ID = 0x0000 is used for these specific cases:
        //  * To announce an anonymized Product ID as part of device discovery
        //  * To indicate an OTA software update file applies to multiple Product IDs equally.
        //  * To avoid confusion when presenting the Onboarding Payload for ECM with multiple nodes
        if self.dev_det.pid == 0 && self.dev_det.vid != VendorId::CommonOrUnspecified as u16 {
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

    pub fn try_as_str<'a>(&self, buf: &'a mut [u8]) -> Result<(&'a str, &'a mut [u8]), Error> {
        let str_len = self.try_iter(buf)?.count();

        let (str_buf, remaining_buf) = buf.split_at_mut(str_len);

        let mut wb = WriteBuf::new(str_buf);
        for ch in self.try_iter(remaining_buf)? {
            wb.le_u8(ch as u8)?;
        }

        let str = unsafe { core::str::from_utf8_unchecked(str_buf) };
        Ok((str, remaining_buf))
    }

    pub fn try_iter<'a>(
        &'a self,
        tlv_buf: &'a mut [u8],
    ) -> Result<impl Iterator<Item = char> + 'a, Error> {
        let iter = self.emit_chars(self.optional_data_to_tlv(tlv_buf)?.iter().copied());

        Ok(iter)
    }

    pub fn estimate_optional_data_tlv(&self) -> Result<usize, Error> {
        let mut estimate = 0;

        let data_item_size_estimate = |info: &TLVElement| {
            // Each data item needs a control byte and a context tag.
            let mut size: usize = 2;

            if let &ElementType::Utf8l(data) = info.get_element_type() {
                // We'll need to encode the string length and then the string data.
                // Length is at most 8 bytes.
                size += 8;
                size += data.len()
            } else {
                // Integer.  Assume it might need up to 8 bytes, for simplicity.
                size += 8;
            }

            size
        };

        for data in self.optional_data {
            estimate += data_item_size_estimate(data);
        }

        // Estimate 4 bytes of overhead per field.  This can happen for a large
        // octet string field: 1 byte control, 1 byte context tag, 2 bytes
        // length.
        //
        // The struct itself has a control byte and an end-of-struct marker.
        estimate += 4 + 2;

        if estimate > u32::MAX as usize {
            Err(ErrorCode::NoMemory)?;
        }

        Ok(estimate)
    }

    pub fn optional_data_to_tlv<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        if self.optional_data.is_empty() && self.dev_det.serial_no.is_empty() {
            Ok(&[])
        } else {
            let mut wb = WriteBuf::new(buf);
            let mut tw = TLVWriter::new(&mut wb);

            tw.start_struct(TagType::Anonymous)?;

            if !self.dev_det.serial_no.is_empty() {
                tw.utf8(
                    TagType::Context(SERIAL_NUMBER_TAG),
                    self.dev_det.serial_no.as_bytes(),
                )?;
            }

            for elem in self.optional_data {
                elem.to_tlv(&mut tw, TagType::Anonymous)?;
            }

            tw.end_container()?;

            let end = wb.get_tail();
            Ok(&buf[..end])
        }
    }

    fn emit_chars<'a, T>(&'a self, tlv_data: T) -> impl Iterator<Item = char> + 'a
    where
        T: Iterator<Item = u8> + 'a,
    {
        struct PackedBitsIterator<I>(I);

        impl<I> Iterator for PackedBitsIterator<I>
        where
            I: Iterator<Item = bool>,
        {
            type Item = (u32, u8);

            fn next(&mut self) -> Option<Self::Item> {
                let mut chunk = 0;
                let mut packed_bits = 0;

                for index in 0..24 {
                    // Up to 24 bits as we are enclding with Base38, which means up to 3 bytes at once
                    if let Some(bit) = self.0.next() {
                        chunk |= (bit as u32) << index;
                        packed_bits += 1;
                    } else {
                        break;
                    }
                }

                if packed_bits > 0 {
                    assert!(packed_bits % 8 == 0);

                    Some((chunk, packed_bits))
                } else {
                    None
                }
            }
        }

        "MT:".chars().chain(
            PackedBitsIterator(self.emit_all_bits(tlv_data))
                .flat_map(|(bits, bits_count)| base38::encode_bits(bits, bits_count)),
        )
    }

    fn emit_all_bits<'a, I>(&'a self, tlv_data: I) -> impl Iterator<Item = bool> + 'a
    where
        I: Iterator<Item = u8> + 'a,
    {
        let passwd = passwd_from_comm_data(self.comm_data);

        Self::emit_bits(self.version as _, VERSION_FIELD_LENGTH_IN_BITS)
            .chain(Self::emit_bits(
                self.dev_det.vid as _,
                VENDOR_IDFIELD_LENGTH_IN_BITS,
            ))
            .chain(Self::emit_bits(
                self.dev_det.pid as _,
                PRODUCT_IDFIELD_LENGTH_IN_BITS,
            ))
            .chain(Self::emit_bits(
                self.flow_type as _,
                COMMISSIONING_FLOW_FIELD_LENGTH_IN_BITS,
            ))
            .chain(Self::emit_bits(
                self.discovery_capabilities.as_bits() as _,
                RENDEZVOUS_INFO_FIELD_LENGTH_IN_BITS,
            ))
            .chain(Self::emit_bits(
                self.comm_data.discriminator as _,
                PAYLOAD_DISCRIMINATOR_FIELD_LENGTH_IN_BITS,
            ))
            .chain(Self::emit_bits(
                passwd as _,
                SETUP_PINCODE_FIELD_LENGTH_IN_BITS,
            ))
            .chain(Self::emit_bits(0, PADDING_FIELD_LENGTH_IN_BITS))
            .chain(tlv_data.flat_map(|b| Self::emit_bits(b as _, 8)))
    }

    fn emit_bits(input: u32, len: usize) -> impl Iterator<Item = bool> {
        (0..len).map(move |i| (input >> i) & 1 == 1)
    }
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum CommissionningFlowType {
    Standard = 0,
    UserIntent = 1,
    Custom = 2,
}

pub fn print_qr_code(qr_code_text: &str, buf: &mut [u8]) -> Result<(), Error> {
    info!("QR Code Text: {}", qr_code_text);

    let (tmp_buf, out_buf) = buf.split_at_mut(buf.len() / 2);

    let qr_code = compute_qr_code(qr_code_text, tmp_buf, out_buf)?;

    let text_image = TextImage::Unicode;

    for y in text_image.lines_range(&qr_code, 4) {
        info!(
            "{}",
            text_image.render_line(&qr_code, 4, false, false, y, tmp_buf)?
        );
    }

    Ok(())
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TextImage {
    Ascii,
    Ansi,
    Unicode,
}

impl TextImage {
    pub fn render<'a>(
        &self,
        qr_code: &QrCode,
        border: u8,
        invert: bool,
        out_buf: &'a mut [u8],
    ) -> Result<&'a str, Error> {
        let mut offset = 0;

        for c in self.render_iter(qr_code, border, invert) {
            let mut dst = [0; 4];
            let bytes = c.encode_utf8(&mut dst).as_bytes();

            if offset + bytes.len() > out_buf.len() {
                return Err(ErrorCode::BufferTooSmall)?;
            } else {
                out_buf[offset..offset + bytes.len()].copy_from_slice(bytes);
                offset += bytes.len();
            }
        }

        Ok(unsafe { core::str::from_utf8_unchecked(&out_buf[..offset]) })
    }

    pub fn render_line<'a>(
        &self,
        qr_code: &QrCode,
        border: u8,
        invert: bool,
        nl: bool,
        y: i32,
        out_buf: &'a mut [u8],
    ) -> Result<&'a str, Error> {
        let mut offset = 0;

        for c in self.render_line_iter(qr_code, border, invert, nl, y) {
            let mut dst = [0; 4];
            let bytes = c.encode_utf8(&mut dst).as_bytes();

            if offset + bytes.len() > out_buf.len() {
                return Err(ErrorCode::BufferTooSmall)?;
            } else {
                out_buf[offset..offset + bytes.len()].copy_from_slice(bytes);
                offset += bytes.len();
            }
        }

        Ok(unsafe { core::str::from_utf8_unchecked(&out_buf[..offset]) })
    }

    pub fn render_iter<'a>(
        &self,
        qr_code: &'a QrCode<'a>,
        border: u8,
        invert: bool,
    ) -> impl Iterator<Item = char> + 'a {
        let console_type = *self;

        self.lines_range(qr_code, border)
            .flat_map(move |y| console_type.render_line_iter(qr_code, border, invert, true, y))
    }

    pub fn lines_range(&self, qr_code: &QrCode, border: u8) -> impl Iterator<Item = i32> {
        let iborder: i32 = border as _;
        let console_type = *self;

        (-iborder..qr_code.size() + iborder)
            .filter(move |y| console_type != Self::Unicode || (y - -iborder) % 2 == 0)
    }

    pub fn render_line_iter<'a>(
        &self,
        qr_code: &'a QrCode<'a>,
        border: u8,
        invert: bool,
        nl: bool,
        y: i32,
    ) -> impl Iterator<Item = char> + 'a {
        let border: i32 = border as _;
        let console_type = *self;

        (-border..qr_code.size() + border + 1)
            .map(move |x| (x, y))
            .map(move |(x, y)| {
                if x < qr_code.size() + border {
                    let white = !qr_code.get_module(x, y) ^ invert;

                    match console_type {
                        Self::Ascii => {
                            if white {
                                "#"
                            } else {
                                " "
                            }
                        }
                        Self::Ansi => {
                            let prev_white = if x > -border {
                                Some(qr_code.get_module(x - 1, y))
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
                        Self::Unicode => {
                            if white == !qr_code.get_module(x, y + 1) ^ invert {
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
                    match console_type {
                        TextImage::Ascii => {
                            if nl {
                                "\n"
                            } else {
                                ""
                            }
                        }
                        TextImage::Ansi | TextImage::Unicode => {
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
}

pub fn compute_qr_code<'a>(
    qr_code_text: &str,
    tmp_buf: &mut [u8],
    out_buf: &'a mut [u8],
) -> Result<QrCode<'a>, Error> {
    let needed_version = Version::new(compute_qr_code_version(qr_code_text));

    QrCode::encode_text(
        qr_code_text,
        tmp_buf,
        out_buf,
        QrCodeEcc::Medium,
        needed_version,
        needed_version,
        None,
        false,
    )
    .map_err(|_| ErrorCode::BufferTooSmall.into())
}

pub fn compute_qr_code_version(qr_code_text: &str) -> u8 {
    match qr_code_text.len() {
        0..=38 => 2,
        39..=61 => 3,
        62..=90 => 4,
        _ => 5,
    }
}

pub fn compute_qr_code_text<'a>(
    dev_det: &BasicInfoConfig,
    comm_data: &CommissioningData,
    discovery_capabilities: DiscoveryCapabilities,
    optional_data: &[TLVElement],
    buf: &'a mut [u8],
) -> Result<(&'a str, &'a mut [u8]), Error> {
    let qr_code_data =
        QrSetupPayload::new(dev_det, comm_data, discovery_capabilities, optional_data);

    qr_code_data.try_as_str(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{secure_channel::spake2p::VerifierData, tlv::ElementType, utils::rand::dummy_rand};

    #[test]
    fn can_base38_encode() {
        const QR_CODE: &str = "MT:YNJV7VSC00CMVH7SR00";

        let comm_data = CommissioningData {
            verifier: VerifierData::new_with_pw(34567890, dummy_rand),
            discriminator: 2976,
        };
        let dev_det = BasicInfoConfig {
            vid: 9050,
            pid: 65279,
            ..Default::default()
        };

        let disc_cap = DiscoveryCapabilities::new(false, true, false);
        let qr_code_data = QrSetupPayload::new(&dev_det, &comm_data, disc_cap, &[]);
        let mut buf = [0; 1024];
        let data_str = qr_code_data
            .try_as_str(&mut buf)
            .expect("Failed to encode")
            .0;
        assert_eq!(data_str, QR_CODE)
    }

    #[test]
    fn can_base38_encode_with_vendor_data() {
        const QR_CODE: &str = "MT:-24J0AFN00KA064IJ3P0IXZB0DK5N1K8SQ1RYCU1-A40";

        let comm_data = CommissioningData {
            verifier: VerifierData::new_with_pw(20202021, dummy_rand),
            discriminator: 3840,
        };
        let dev_det = BasicInfoConfig {
            vid: 65521,
            pid: 32769,
            serial_no: "1234567890",
            ..Default::default()
        };

        let disc_cap = DiscoveryCapabilities::new(true, false, false);
        let qr_code_data = QrSetupPayload::new(&dev_det, &comm_data, disc_cap, &[]);
        let mut buf = [0; 1024];
        let data_str = qr_code_data
            .try_as_str(&mut buf)
            .expect("Failed to encode")
            .0;
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

        let comm_data = CommissioningData {
            verifier: VerifierData::new_with_pw(20202021, dummy_rand),
            discriminator: 3840,
        };
        let dev_det = BasicInfoConfig {
            vid: 65521,
            pid: 32769,
            serial_no: "1234567890",
            ..Default::default()
        };

        let disc_cap = DiscoveryCapabilities::new(true, false, false);
        let optional_data = [
            TLVElement::new(
                TagType::Context(OPTIONAL_DEFAULT_STRING_TAG),
                ElementType::Utf8l(OPTIONAL_DEFAULT_STRING_VALUE.as_bytes()),
            ),
            // todo: check why unsigned ints are not accepted by 'chip-tool payload parse-setup-payload'
            TLVElement::new(
                TagType::Context(OPTIONAL_DEFAULT_INT_TAG),
                ElementType::S32(OPTIONAL_DEFAULT_INT_VALUE),
            ),
        ];
        let qr_code_data = QrSetupPayload::new(&dev_det, &comm_data, disc_cap, &optional_data);

        let mut buf = [0; 1024];
        let data_str = qr_code_data
            .try_as_str(&mut buf)
            .expect("Failed to encode")
            .0;
        assert_eq!(data_str, QR_CODE)
    }
}
