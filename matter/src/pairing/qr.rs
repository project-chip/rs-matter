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

use crate::{
    tlv::{TLVWriter, TagType},
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

const TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES: usize = TOTAL_PAYLOAD_DATA_SIZE_IN_BITS / 8;

// Spec 5.1.4.2 CHIP-Common Reserved Tags
const SERIAL_NUMBER_TAG: u8 = 0x00;
// const PBKDFITERATIONS_TAG: u8 = 0x01;
// const BPKFSALT_TAG: u8 = 0x02;
// const NUMBER_OFDEVICES_TAG: u8 = 0x03;
// const COMMISSIONING_TIMEOUT_TAG: u8 = 0x04;

pub enum QRCodeInfoType {
    String(heapless::String<128>), // TODO: Big enough?
    Int32(i32),
    Int64(i64),
    UInt32(u32),
    UInt64(u64),
}

pub enum SerialNumber {
    String(heapless::String<128>),
    UInt32(u32),
}

pub struct OptionalQRCodeInfo {
    // the tag number of the optional info
    pub tag: u8,
    // the data of the optional info
    pub data: QRCodeInfoType,
}

pub struct QrSetupPayload<'data> {
    version: u8,
    flow_type: CommissionningFlowType,
    discovery_capabilities: DiscoveryCapabilities,
    dev_det: &'data BasicInfoConfig<'data>,
    comm_data: &'data CommissioningData,
    // The vec is ordered by the tag of OptionalQRCodeInfo
    optional_data: heapless::Vec<OptionalQRCodeInfo, 16>,
}

impl<'data> QrSetupPayload<'data> {
    pub fn new(
        dev_det: &'data BasicInfoConfig,
        comm_data: &'data CommissioningData,
        discovery_capabilities: DiscoveryCapabilities,
    ) -> Self {
        const DEFAULT_VERSION: u8 = 0;

        let mut result = QrSetupPayload {
            version: DEFAULT_VERSION,
            flow_type: CommissionningFlowType::Standard,
            discovery_capabilities,
            dev_det,
            comm_data,
            optional_data: heapless::Vec::new(),
        };

        if !dev_det.serial_no.is_empty() {
            result.add_serial_number(SerialNumber::String(dev_det.serial_no.into()));
        }

        result
    }

    fn is_valid(&self) -> bool {
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

    /// A function to add an optional vendor data
    /// # Arguments
    /// * `tag` - tag number in the [0x80-0xFF] range
    /// * `data` - Data to add
    pub fn add_optional_vendor_data(&mut self, tag: u8, data: QRCodeInfoType) -> Result<(), Error> {
        if is_vendor_tag(tag) {
            self.add_optional_data(tag, data)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    /// A function to add an optional QR Code info CHIP object
    /// # Arguments
    /// * `tag` - one of the CHIP-Common Reserved Tags
    /// * `data` - Data to add
    pub fn add_optional_extension_data(
        &mut self,
        tag: u8,
        data: QRCodeInfoType,
    ) -> Result<(), Error> {
        if is_common_tag(tag) {
            self.add_optional_data(tag, data)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    fn add_optional_data(&mut self, tag: u8, data: QRCodeInfoType) -> Result<(), Error> {
        let item = OptionalQRCodeInfo { tag, data };
        let index = self.optional_data.iter().position(|info| tag < info.tag);

        if let Some(index) = index {
            self.optional_data.insert(index, item)
        } else {
            self.optional_data.push(item)
        }
        .map_err(|_| Error::NoSpace)
    }

    pub fn get_all_optional_data(&self) -> &[OptionalQRCodeInfo] {
        &self.optional_data
    }

    pub fn add_serial_number(&mut self, serial_number: SerialNumber) {
        match serial_number {
            SerialNumber::String(serial_number) => self.add_optional_extension_data(
                SERIAL_NUMBER_TAG,
                QRCodeInfoType::String(serial_number),
            ),
            SerialNumber::UInt32(serial_number) => self.add_optional_extension_data(
                SERIAL_NUMBER_TAG,
                QRCodeInfoType::UInt32(serial_number),
            ),
        }
        .expect("can not add serial number");
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

    fn has_tlv(&self) -> bool {
        !self.optional_data.is_empty()
    }
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum CommissionningFlowType {
    Standard = 0,
    UserIntent = 1,
    Custom = 2,
}

pub(super) fn payload_base38_representation<const N: usize>(
    payload: &QrSetupPayload,
    buf: &mut [u8],
) -> Result<heapless::String<N>, Error> {
    if payload.is_valid() {
        let (bits_buf, tlv_buf) = if payload.has_tlv() {
            let (bits_buf, tlv_buf) = buf.split_at_mut(buf.len() / 2);

            (bits_buf, Some(tlv_buf))
        } else {
            (buf, None)
        };

        payload_base38_representation_with_tlv(payload, bits_buf, tlv_buf)
    } else {
        Err(Error::InvalidArgument)
    }
}

pub fn estimate_buffer_size(payload: &QrSetupPayload) -> Result<usize, Error> {
    // Estimate the size of the needed buffer; initialize with the size of the standard payload.
    let mut estimate = TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES;

    let data_item_size_estimate = |info: &QRCodeInfoType| {
        // Each data item needs a control byte and a context tag.
        let mut size: usize = 2;

        if let QRCodeInfoType::String(data) = info {
            // We'll need to encode the string length and then the string data.
            // Length is at most 8 bytes.
            size += 8;
            size += data.as_bytes().len()
        } else {
            // Integer.  Assume it might need up to 8 bytes, for simplicity.
            size += 8;
        }

        size
    };

    for data in payload.get_all_optional_data() {
        estimate += data_item_size_estimate(&data.data);
    }

    estimate = estimate_struct_overhead(estimate);

    if estimate > u32::MAX as usize {
        return Err(Error::NoMemory);
    }

    Ok(estimate)
}

fn estimate_struct_overhead(first_field_size: usize) -> usize {
    // Estimate 4 bytes of overhead per field.  This can happen for a large
    // octet string field: 1 byte control, 1 byte context tag, 2 bytes
    // length.
    //
    // The struct itself has a control byte and an end-of-struct marker.
    first_field_size + 4 + 2
}

pub(super) fn print_qr_code(qr_data: &str) {
    #[cfg(not(feature = "std"))]
    {
        info!("\n QR CODE DATA: {}", qr_data);
    }

    #[cfg(feature = "std")]
    {
        use qrcode::{render::unicode, QrCode, Version};

        let needed_version = compute_qr_version(qr_data);
        let code =
            QrCode::with_version(qr_data, Version::Normal(needed_version), qrcode::EcLevel::M)
                .unwrap();
        let image = code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .build();

        info!("\n{}", image);
    }
}

fn compute_qr_version(qr_data: &str) -> i16 {
    match qr_data.len() {
        0..=38 => 2,
        39..=61 => 3,
        62..=90 => 4,
        _ => 5,
    }
}

fn populate_bits(
    bits: &mut [u8],
    offset: &mut usize,
    mut input: u64,
    number_of_bits: usize,
    total_payload_data_size_in_bits: usize,
) -> Result<(), Error> {
    if *offset + number_of_bits > total_payload_data_size_in_bits {
        return Err(Error::InvalidArgument);
    }

    if input >= 1u64 << number_of_bits {
        return Err(Error::InvalidArgument);
    }

    let mut index = *offset;
    *offset += number_of_bits;

    while input != 0 {
        if input & 1 == 1 {
            let mask = (1 << (index % 8)) as u8;
            bits[index / 8] |= mask;
        }
        index += 1;
        input >>= 1;
    }

    Ok(())
}

fn payload_base38_representation_with_tlv<const N: usize>(
    payload: &QrSetupPayload,
    bits_buf: &mut [u8],
    tlv_buf: Option<&mut [u8]>,
) -> Result<heapless::String<N>, Error> {
    let tlv_data = if let Some(tlv_buf) = tlv_buf {
        Some(generate_tlv_from_optional_data(payload, tlv_buf)?)
    } else {
        None
    };

    let bits = generate_bit_set(payload, bits_buf, tlv_data)?;

    let mut base38_encoded: heapless::String<N> = "MT:".into();

    for c in base38::encode(bits) {
        base38_encoded.push(c).map_err(|_| Error::NoSpace)?;
    }

    Ok(base38_encoded)
}

fn generate_tlv_from_optional_data<'a>(
    payload: &QrSetupPayload,
    tlv_buf: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let mut wb = WriteBuf::new(tlv_buf);
    let mut tw = TLVWriter::new(&mut wb);

    tw.start_struct(TagType::Anonymous)?;

    for info in payload.get_all_optional_data() {
        match &info.data {
            QRCodeInfoType::String(data) => tw.utf8(TagType::Context(info.tag), data.as_bytes())?,
            QRCodeInfoType::Int32(data) => tw.i32(TagType::Context(info.tag), *data)?,
            QRCodeInfoType::Int64(data) => tw.i64(TagType::Context(info.tag), *data)?,
            QRCodeInfoType::UInt32(data) => tw.u32(TagType::Context(info.tag), *data)?,
            QRCodeInfoType::UInt64(data) => tw.u64(TagType::Context(info.tag), *data)?,
        }
    }

    tw.end_container()?;

    let tail = tw.get_tail();

    Ok(&tlv_buf[..tail])
}

fn generate_bit_set<'a>(
    payload: &QrSetupPayload,
    bits_buf: &'a mut [u8],
    tlv_data: Option<&[u8]>,
) -> Result<&'a [u8], Error> {
    let total_payload_size_in_bits =
        TOTAL_PAYLOAD_DATA_SIZE_IN_BITS + tlv_data.map(|tlv_data| tlv_data.len() * 8).unwrap_or(0);

    if bits_buf.len() * 8 < total_payload_size_in_bits {
        return Err(Error::BufferTooSmall);
    };

    let passwd = passwd_from_comm_data(payload.comm_data);

    let mut offset: usize = 0;

    populate_bits(
        bits_buf,
        &mut offset,
        payload.version as u64,
        VERSION_FIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits_buf,
        &mut offset,
        payload.dev_det.vid as u64,
        VENDOR_IDFIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits_buf,
        &mut offset,
        payload.dev_det.pid as u64,
        PRODUCT_IDFIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits_buf,
        &mut offset,
        payload.flow_type as u64,
        COMMISSIONING_FLOW_FIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits_buf,
        &mut offset,
        payload.discovery_capabilities.as_bits() as u64,
        RENDEZVOUS_INFO_FIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits_buf,
        &mut offset,
        payload.comm_data.discriminator as u64,
        PAYLOAD_DISCRIMINATOR_FIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits_buf,
        &mut offset,
        passwd as u64,
        SETUP_PINCODE_FIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits_buf,
        &mut offset,
        0,
        PADDING_FIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    if let Some(tlv_data) = tlv_data {
        populate_tlv_bits(bits_buf, &mut offset, tlv_data, total_payload_size_in_bits)?;
    }

    let bytes_written = (offset + 7) / 8;

    Ok(&bits_buf[..bytes_written])
}

fn populate_tlv_bits(
    bits_buf: &mut [u8],
    offset: &mut usize,
    tlv_data: &[u8],
    total_payload_size_in_bits: usize,
) -> Result<(), Error> {
    for b in tlv_data {
        populate_bits(bits_buf, offset, *b as u64, 8, total_payload_size_in_bits)?;
    }

    Ok(())
}

/// Spec 5.1.4.1 Manufacture-specific tag numbers are in the range [0x80, 0xFF]
fn is_vendor_tag(tag: u8) -> bool {
    !is_common_tag(tag)
}

/// Spec 5.1.4.2 CHIPCommon tag numbers are in the range [0x00, 0x7F]
fn is_common_tag(tag: u8) -> bool {
    tag < 0x80
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{secure_channel::spake2p::VerifierData, utils::rand::dummy_rand};

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
        let qr_code_data = QrSetupPayload::new(&dev_det, &comm_data, disc_cap);
        let mut buf = [0; 1024];
        let data_str = payload_base38_representation::<128>(&qr_code_data, &mut buf)
            .expect("Failed to encode");
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
        let qr_code_data = QrSetupPayload::new(&dev_det, &comm_data, disc_cap);
        let mut buf = [0; 1024];
        let data_str = payload_base38_representation::<128>(&qr_code_data, &mut buf)
            .expect("Failed to encode");
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
        let mut qr_code_data = QrSetupPayload::new(&dev_det, &comm_data, disc_cap);

        qr_code_data
            .add_optional_vendor_data(
                OPTIONAL_DEFAULT_STRING_TAG,
                QRCodeInfoType::String(OPTIONAL_DEFAULT_STRING_VALUE.into()),
            )
            .expect("Failed to add optional data");

        // todo: check why unsigned ints are not accepted by 'chip-tool payload parse-setup-payload'

        qr_code_data
            .add_optional_vendor_data(
                OPTIONAL_DEFAULT_INT_TAG,
                QRCodeInfoType::Int32(OPTIONAL_DEFAULT_INT_VALUE),
            )
            .expect("Failed to add optional data");

        let mut buf = [0; 1024];
        let data_str = payload_base38_representation::<{ QR_CODE.len() }>(&qr_code_data, &mut buf)
            .expect("Failed to encode");
        assert_eq!(data_str, QR_CODE)
    }
}
