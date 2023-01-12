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

use std::collections::BTreeMap;

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
    String(String),
    Int32(i32),
    Int64(i64),
    UInt32(u32),
    UInt64(u64),
}

pub enum SerialNumber {
    String(String),
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
    dev_det: &'data BasicInfoConfig,
    comm_data: &'data CommissioningData,
    // we use a BTreeMap to keep the order of the optional data stable
    optional_data: BTreeMap<u8, OptionalQRCodeInfo>,
}

impl<'data> QrSetupPayload<'data> {
    pub fn new(
        dev_det: &'data BasicInfoConfig,
        comm_data: &'data CommissioningData,
        discovery_capabilities: DiscoveryCapabilities,
    ) -> Self {
        const DEFAULT_VERSION: u8 = 0;

        QrSetupPayload {
            version: DEFAULT_VERSION,
            flow_type: CommissionningFlowType::Standard,
            discovery_capabilities,
            dev_det,
            comm_data,
            optional_data: BTreeMap::new(),
        }
    }

    fn is_valid(&self) -> bool {
        // 3-bit value specifying the QR code payload version.
        if self.version >= 1 << VERSION_FIELD_LENGTH_IN_BITS {
            return false;
        }

        if !self.discovery_capabilities.has_value() {
            return false;
        }

        if self.comm_data.passwd >= 1 << SETUP_PINCODE_FIELD_LENGTH_IN_BITS {
            return false;
        }

        self.check_payload_common_constraints()
    }

    /// A function to add an optional vendor data
    /// # Arguments
    /// * `tag` - tag number in the [0x80-0xFF] range
    /// * `data` - Data to add
    pub fn add_optional_vendor_data(&mut self, tag: u8, data: QRCodeInfoType) -> Result<(), Error> {
        if !is_vendor_tag(tag) {
            return Err(Error::InvalidArgument);
        }

        self.optional_data
            .insert(tag, OptionalQRCodeInfo { tag, data });
        Ok(())
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
        if !is_common_tag(tag) {
            return Err(Error::InvalidArgument);
        }

        self.optional_data
            .insert(tag, OptionalQRCodeInfo { tag, data });
        Ok(())
    }

    pub fn get_all_optional_data(&self) -> &BTreeMap<u8, OptionalQRCodeInfo> {
        &self.optional_data
    }

    pub fn add_serial_number(&mut self, serial_number: SerialNumber) -> Result<(), Error> {
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
    }

    fn check_payload_common_constraints(&self) -> bool {
        // A version not equal to 0 would be invalid for v1 and would indicate new format (e.g. version 2)
        if self.version != 0 {
            return false;
        }

        if !Self::is_valid_setup_pin(self.comm_data.passwd) {
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

struct TlvData {
    max_data_length_in_bytes: u32,
    data_length_in_bytes: Option<usize>,
    data: Option<Vec<u8>>,
}

pub(super) fn payload_base38_representation(payload: &QrSetupPayload) -> Result<String, Error> {
    let (mut bits, tlv_data) = if payload.has_tlv() {
        let buffer_size = estimate_buffer_size(payload)?;
        (
            vec![0; buffer_size],
            Some(TlvData {
                max_data_length_in_bytes: buffer_size as u32,
                data_length_in_bytes: None,
                data: None,
            }),
        )
    } else {
        (vec![0; TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES], None)
    };

    if !payload.is_valid() {
        return Err(Error::InvalidArgument);
    }

    payload_base38_representation_with_tlv(payload, &mut bits, tlv_data)
}

fn estimate_buffer_size(payload: &QrSetupPayload) -> Result<usize, Error> {
    // Estimate the size of the needed buffer.
    let mut estimate = 0;

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

    let vendor_data = payload.get_all_optional_data();
    vendor_data.values().for_each(|data| {
        estimate += data_item_size_estimate(&data.data);
    });

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
    first_field_size + 4
}

pub(super) fn print_qr_code(qr_data: &str) {
    let code = QrCode::with_version(qr_data, Version::Normal(2), qrcode::EcLevel::M).unwrap();
    let image = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    info!("\n{}", image);
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

fn payload_base38_representation_with_tlv(
    payload: &QrSetupPayload,
    bits: &mut [u8],
    mut tlv_data: Option<TlvData>,
) -> Result<String, Error> {
    if let Some(tlv_data) = tlv_data.as_mut() {
        generate_tlv_from_optional_data(payload, tlv_data)?;
    }

    let bytes_written = generate_bit_set(payload, bits, tlv_data)?;
    let base38_encoded = base38::encode(&*bits, bytes_written);
    Ok(format!("MT:{}", base38_encoded))
}

fn generate_tlv_from_optional_data(
    payload: &QrSetupPayload,
    tlv_data: &mut TlvData,
) -> Result<(), Error> {
    let size_needed = tlv_data.max_data_length_in_bytes as usize;
    let mut tlv_buffer = vec![0u8; size_needed];
    let mut wb = WriteBuf::new(&mut tlv_buffer, size_needed);
    let mut tw = TLVWriter::new(&mut wb);

    tw.start_struct(TagType::Anonymous)?;
    let data = payload.get_all_optional_data();

    for (tag, value) in data {
        match &value.data {
            QRCodeInfoType::String(data) => {
                if data.len() > 256 {
                    tw.str16(TagType::Context(*tag), data.as_bytes())?;
                } else {
                    tw.str8(TagType::Context(*tag), data.as_bytes())?;
                }
            }
            // todo: check i32 -> u32??
            QRCodeInfoType::Int32(data) => tw.u32(TagType::Context(*tag), *data as u32)?,
            // todo: check i64 -> u64??
            QRCodeInfoType::Int64(data) => tw.u64(TagType::Context(*tag), *data as u64)?,
            QRCodeInfoType::UInt32(data) => tw.u32(TagType::Context(*tag), *data)?,
            QRCodeInfoType::UInt64(data) => tw.u64(TagType::Context(*tag), *data)?,
        }
    }

    tw.end_container()?;
    tlv_data.data_length_in_bytes = Some(tw.get_tail());
    tlv_data.data = Some(tlv_buffer);

    Ok(())
}

fn generate_bit_set(
    payload: &QrSetupPayload,
    bits: &mut [u8],
    tlv_data: Option<TlvData>,
) -> Result<usize, Error> {
    let mut offset: usize = 0;

    let total_payload_size_in_bits = if let Some(tlv_data) = &tlv_data {
        TOTAL_PAYLOAD_DATA_SIZE_IN_BITS + (tlv_data.data_length_in_bytes.unwrap_or_default() * 8)
    } else {
        TOTAL_PAYLOAD_DATA_SIZE_IN_BITS
    };

    if bits.len() * 8 < total_payload_size_in_bits {
        return Err(Error::BufferTooSmall);
    };

    populate_bits(
        bits,
        &mut offset,
        payload.version as u64,
        VERSION_FIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits,
        &mut offset,
        payload.dev_det.vid as u64,
        VENDOR_IDFIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits,
        &mut offset,
        payload.dev_det.pid as u64,
        PRODUCT_IDFIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits,
        &mut offset,
        payload.flow_type as u64,
        COMMISSIONING_FLOW_FIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits,
        &mut offset,
        payload.discovery_capabilities.as_bits() as u64,
        RENDEZVOUS_INFO_FIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits,
        &mut offset,
        payload.comm_data.discriminator as u64,
        PAYLOAD_DISCRIMINATOR_FIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits,
        &mut offset,
        payload.comm_data.passwd as u64,
        SETUP_PINCODE_FIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    populate_bits(
        bits,
        &mut offset,
        0,
        PADDING_FIELD_LENGTH_IN_BITS,
        total_payload_size_in_bits,
    )?;

    if let Some(tlv_data) = tlv_data {
        populate_tlv_bits(bits, &mut offset, tlv_data, total_payload_size_in_bits)?;
    }

    let bytes_written = (offset + 7) / 8;
    Ok(bytes_written)
}

fn populate_tlv_bits(
    bits: &mut [u8],
    offset: &mut usize,
    tlv_data: TlvData,
    total_payload_size_in_bits: usize,
) -> Result<(), Error> {
    if let (Some(data), Some(data_length_in_bytes)) = (tlv_data.data, tlv_data.data_length_in_bytes)
    {
        for pos in 0..data_length_in_bytes {
            populate_bits(
                bits,
                offset,
                data[pos] as u64,
                8,
                total_payload_size_in_bits,
            )?;
        }
    } else {
        return Err(Error::InvalidArgument);
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

    #[test]
    fn can_base38_encode() {
        const QR_CODE: &str = "MT:YNJV7VSC00CMVH7SR00";

        let comm_data = CommissioningData {
            passwd: 34567890,
            discriminator: 2976,
            ..Default::default()
        };
        let dev_det = BasicInfoConfig {
            vid: 9050,
            pid: 65279,
            ..Default::default()
        };

        let disc_cap = DiscoveryCapabilities::new(false, true, false);
        let qr_code_data = QrSetupPayload::new(&dev_det, &comm_data, disc_cap);
        let data_str = payload_base38_representation(&qr_code_data).expect("Failed to encode");
        assert_eq!(data_str, QR_CODE)
    }

    #[test]
    fn can_base38_encode_with_optional_data() {
        // todo: this must be validated!
        const QR_CODE: &str = "MT:YNJV7VSC00CMVH70V3P0-ISA0DK5N1K8SQ1RYCU1WET70.QT52B.E232XZE0O0";
        const OPTIONAL_DEFAULT_STRING_TAG: u8 = 0x82; // Vendor "test" tag
        const OPTIONAL_DEFAULT_STRING_VALUE: &str = "myData";

        const OPTIONAL_DEFAULT_INT_TAG: u8 = 0x83; // Vendor "test" tag
        const OPTIONAL_DEFAULT_INT_VALUE: u32 = 12;

        let comm_data = CommissioningData {
            passwd: 34567890,
            discriminator: 2976,
            ..Default::default()
        };
        let dev_det = BasicInfoConfig {
            vid: 9050,
            pid: 65279,
            ..Default::default()
        };

        let disc_cap = DiscoveryCapabilities::new(false, true, false);
        let mut qr_code_data = QrSetupPayload::new(&dev_det, &comm_data, disc_cap);
        qr_code_data
            .add_serial_number(SerialNumber::String("123456789".to_string()))
            .expect("Failed to add serial number");

        qr_code_data
            .add_optional_vendor_data(
                OPTIONAL_DEFAULT_STRING_TAG,
                QRCodeInfoType::String(OPTIONAL_DEFAULT_STRING_VALUE.to_string()),
            )
            .expect("Failed to add optional data");

        qr_code_data
            .add_optional_vendor_data(
                OPTIONAL_DEFAULT_INT_TAG,
                QRCodeInfoType::UInt32(OPTIONAL_DEFAULT_INT_VALUE),
            )
            .expect("Failed to add optional data");

        let data_str = payload_base38_representation(&qr_code_data).expect("Failed to encode");
        assert_eq!(data_str, QR_CODE)
    }
}
