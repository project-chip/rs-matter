//! This module contains the logic for generating the pairing code and the QR code for easy pairing.

use log::info;
use qrcode::{render::unicode, QrCode, Version};
use verhoeff::Verhoeff;

use crate::{
    codec::base38, data_model::cluster_basic_information::BasicInfoConfig, error::Error,
    CommissioningData,
};

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

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum CommissionningFlowType {
    Standard = 0,
    UserIntent = 1,
    Custom = 2,
}

pub struct DiscoveryCapabilitiesSchema {
    on_ip_network: bool,
    ble: bool,
    soft_access_point: bool,
}

impl DiscoveryCapabilitiesSchema {
    pub fn new(on_ip_network: bool, ble: bool, soft_access_point: bool) -> Self {
        DiscoveryCapabilitiesSchema {
            on_ip_network,
            ble,
            soft_access_point,
        }
    }
}

impl DiscoveryCapabilitiesSchema {
    fn as_bits(&self) -> u8 {
        let mut bits = 0;
        if self.soft_access_point {
            bits |= 1 << 0;
        }
        if self.ble {
            bits |= 1 << 1;
        }
        if self.on_ip_network {
            bits |= 1 << 2;
        }
        bits
    }
}

pub struct QrCodeData<'data> {
    flow_type: CommissionningFlowType,
    discovery_capabilities: DiscoveryCapabilitiesSchema,
    dev_det: &'data BasicInfoConfig,
    comm_data: &'data CommissioningData,
}

impl<'data> QrCodeData<'data> {
    pub fn new(
        dev_det: &'data BasicInfoConfig,
        comm_data: &'data CommissioningData,
        discovery_capabilities: DiscoveryCapabilitiesSchema,
    ) -> Self {
        QrCodeData {
            flow_type: CommissionningFlowType::Standard,
            discovery_capabilities,
            dev_det,
            comm_data,
        }
    }
}

struct TlvData {
    data_length_in_bytes: u32,
}

/// Prepares and prints the pairing code and the QR code for easy pairing.
pub fn print_pairing_code_and_qr(dev_det: &BasicInfoConfig, comm_data: &CommissioningData) {
    let pairing_code = compute_pairing_code(comm_data);

    // todo: allow the discovery capabilities to be passed in
    let disc_cap = DiscoveryCapabilitiesSchema::new(true, false, false);
    let qr_code_data = QrCodeData::new(dev_det, comm_data, disc_cap);
    let data_str = payload_base38_representation(&qr_code_data).expect("Failed to encode");

    pretty_print_pairing_code(&pairing_code);
    print_qr_code(&data_str);
}

fn compute_pairing_code(comm_data: &CommissioningData) -> String {
    // 0: no Vendor ID and Product ID present in Manual Pairing Code
    const VID_PID_PRESENT: u8 = 0;

    let CommissioningData {
        discriminator,
        passwd,
        ..
    } = comm_data;

    let mut digits = String::new();
    digits.push_str(&((VID_PID_PRESENT << 2) | (discriminator >> 10) as u8).to_string());
    digits.push_str(&format!(
        "{:0>5}",
        ((discriminator & 0x300) << 6) | (passwd & 0x3FFF) as u16
    ));
    digits.push_str(&format!("{:0>4}", passwd >> 14));

    let check_digit = digits.calculate_verhoeff_check_digit();
    digits.push_str(&check_digit.to_string());

    digits
}

fn pretty_print_pairing_code(pairing_code: &str) {
    assert!(pairing_code.len() == 11);
    let mut pretty = String::new();
    pretty.push_str(&pairing_code[..4]);
    pretty.push('-');
    pretty.push_str(&pairing_code[4..8]);
    pretty.push('-');
    pretty.push_str(&pairing_code[8..]);
    info!("Pairing Code: {}", pretty);
}

fn print_qr_code(qr_data: &str) {
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
    payload: &QrCodeData,
    bits: &mut [u8; TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES],
    tlv_data: Option<&TlvData>,
) -> Result<String, Error> {
    generate_bit_set(payload, bits, tlv_data)?;
    let base38_encoded = base38::encode(&*bits);
    Ok(format!("MT:{}", base38_encoded))
}

fn payload_base38_representation(payload: &QrCodeData) -> Result<String, Error> {
    let mut bits: [u8; TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES] = [0; TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES];

    // VerifyOrReturnError(mPayload.isValidQRCodePayload(), CHIP_ERROR_INVALID_ARGUMENT);

    payload_base38_representation_with_tlv(payload, &mut bits, None)
}

fn generate_bit_set(
    payload: &QrCodeData,
    bits: &mut [u8; TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES],
    tlv_data: Option<&TlvData>,
) -> Result<(), Error> {
    let mut offset: usize = 0;
    let total_payload_size_in_bits = if let Some(tlv_data) = tlv_data {
        TOTAL_PAYLOAD_DATA_SIZE_IN_BITS + (tlv_data.data_length_in_bytes * 8) as usize
    } else {
        TOTAL_PAYLOAD_DATA_SIZE_IN_BITS
    };

    if bits.len() * 8 < total_payload_size_in_bits {
        return Err(Error::BufferTooSmall);
    };

    const VERSION: u64 = 0;
    populate_bits(
        bits,
        &mut offset,
        VERSION,
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

    // todo: add tlv data
    // ReturnErrorOnFailure(populateTLVBits(bits.data(), offset, tlvDataStart, tlvDataLengthInBytes, totalPayloadSizeInBits));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_compute_pairing_code() {
        let comm_data = CommissioningData {
            passwd: 123456,
            discriminator: 250,
            ..Default::default()
        };
        let pairing_code = compute_pairing_code(&comm_data);
        assert_eq!(pairing_code, "00876800071");

        let comm_data = CommissioningData {
            passwd: 34567890,
            discriminator: 2976,
            ..Default::default()
        };
        let pairing_code = compute_pairing_code(&comm_data);
        assert_eq!(pairing_code, "26318621095");
    }

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

        let disc_cap = DiscoveryCapabilitiesSchema::new(false, true, false);
        let qr_code_data = QrCodeData::new(&dev_det, &comm_data, disc_cap);
        let data_str = payload_base38_representation(&qr_code_data).expect("Failed to encode");
        assert_eq!(data_str, QR_CODE)
    }
}
