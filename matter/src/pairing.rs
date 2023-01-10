use log::info;
use packed_struct::prelude::*;
use qrcode::{render::unicode, QrCode, Version};
use verhoeff::Verhoeff;

use crate::{
    codec::base38, data_model::cluster_basic_information::BasicInfoConfig, CommissioningData,
};

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

#[derive(PackedStruct, Debug)]
#[packed_struct(bit_numbering = "msb0", size_bytes = "11", endian = "msb")]
pub struct PackedQrData {
    #[packed_field(bits = "0..3")]
    version: Integer<u8, packed_bits::Bits<3>>,
    #[packed_field(bits = "3..19")]
    vid: Integer<u16, packed_bits::Bits<16>>,
    #[packed_field(bits = "19..35")]
    pid: Integer<u16, packed_bits::Bits<16>>,
    #[packed_field(bits = "35..37")]
    commissionning_flow_type: Integer<u8, packed_bits::Bits<2>>,
    #[packed_field(bits = "37")]
    soft_access_point: bool,
    #[packed_field(bits = "38")]
    ble: bool,
    #[packed_field(bits = "39")]
    on_ip_network: bool,
    #[packed_field(bits = "40..45")]
    _reserved: Integer<u8, packed_bits::Bits<5>>,
    #[packed_field(bits = "45..57")]
    discriminator: Integer<u16, packed_bits::Bits<12>>,
    #[packed_field(bits = "57..84")]
    passcode: Integer<u32, packed_bits::Bits<27>>,
    #[packed_field(bits = "84..88")]
    _padding: Integer<u8, packed_bits::Bits<4>>,
}

pub fn compute_and_print_pairing_code(dev_det: &BasicInfoConfig, comm_data: &CommissioningData) {
    let pairing_code = compute_pairing_code(comm_data);
    pretty_print_pairing_code(&pairing_code);
    print_qr_code(&pairing_code, dev_det, comm_data);
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

pub fn pretty_print_pairing_code(pairing_code: &str) {
    assert!(pairing_code.len() == 11);
    let mut pretty = String::new();
    pretty.push_str(&pairing_code[..4]);
    pretty.push('-');
    pretty.push_str(&pairing_code[4..8]);
    pretty.push('-');
    pretty.push_str(&pairing_code[8..]);
    info!("Pairing Code: {}", pretty);
}

fn print_qr_code(pairing_code: &str, dev_det: &BasicInfoConfig, comm_data: &CommissioningData) {
    let code = QrCode::with_version(pairing_code, Version::Normal(2), qrcode::EcLevel::M).unwrap();
    let image = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{}", image);
}

fn base38_encode_qr(qr_data: &QrCodeData) -> String {
    let QrCodeData {
        flow_type,
        discovery_capabilities,
        dev_det,
        comm_data,
    } = &qr_data;

    let BasicInfoConfig { vid, pid, .. } = dev_det;
    const VERSION: u8 = 0; // 3-bit value specifying the QR code payload version. SHALL be 000.

    let packed_qr_data = PackedQrData {
        version: VERSION.into(),
        vid: (*vid).reverse_bits().into(),
        pid: (*pid).reverse_bits().into(),
        commissionning_flow_type: ((*flow_type) as u8).into(),
        soft_access_point: discovery_capabilities.soft_access_point,
        ble: discovery_capabilities.ble,
        on_ip_network: discovery_capabilities.on_ip_network,
        _reserved: 0u8.into(),
        discriminator: comm_data.discriminator.reverse_bits().into(),
        passcode: comm_data.passwd.reverse_bits().into(),
        _padding: 0u8.into(),
    };

    println!("{:?}", packed_qr_data);
    println!("{}", packed_qr_data);

    let data = packed_qr_data.pack().unwrap();
    let data = data
        .into_iter()
        .map(|b| b.reverse_bits())
        .collect::<Vec<u8>>();

    let base38 = base38::encode(&data);
    format!("MT:{}", base38)
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
        let disc_cap = DiscoveryCapabilitiesSchema {
            on_ip_network: false,
            ble: true,
            soft_access_point: false,
        };

        let qr_code_data = QrCodeData::new(&dev_det, &comm_data, disc_cap);
        let data_str = base38_encode_qr(&qr_code_data);
        assert_eq!(data_str, QR_CODE)
    }
}
