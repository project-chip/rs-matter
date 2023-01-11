use super::{
    vendor_identifiers::{is_vendor_id_valid_operationally, VendorId},
    *,
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

pub struct QrCodeData<'data> {
    version: u8,
    flow_type: CommissionningFlowType,
    discovery_capabilities: DiscoveryCapabilities,
    dev_det: &'data BasicInfoConfig,
    comm_data: &'data CommissioningData,
}

impl<'data> QrCodeData<'data> {
    pub fn new(
        dev_det: &'data BasicInfoConfig,
        comm_data: &'data CommissioningData,
        discovery_capabilities: DiscoveryCapabilities,
    ) -> Self {
        const DEFAULT_VERSION: u8 = 0;

        QrCodeData {
            version: DEFAULT_VERSION,
            flow_type: CommissionningFlowType::Standard,
            discovery_capabilities,
            dev_det,
            comm_data,
        }
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
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum CommissionningFlowType {
    Standard = 0,
    UserIntent = 1,
    Custom = 2,
}

struct TlvData {
    data_length_in_bytes: u32,
}

pub(super) fn payload_base38_representation(payload: &QrCodeData) -> Result<String, Error> {
    let mut bits: [u8; TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES] = [0; TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES];

    if !payload.is_valid() {
        return Err(Error::InvalidArgument);
    }

    payload_base38_representation_with_tlv(payload, &mut bits, None)
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
    payload: &QrCodeData,
    bits: &mut [u8; TOTAL_PAYLOAD_DATA_SIZE_IN_BYTES],
    tlv_data: Option<&TlvData>,
) -> Result<String, Error> {
    generate_bit_set(payload, bits, tlv_data)?;
    let base38_encoded = base38::encode(&*bits);
    Ok(format!("MT:{}", base38_encoded))
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

    let passwd = passwd_from_comm_data(payload.comm_data);

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
        passwd as u64,
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
    use crate::secure_channel::spake2p::VerifierData;

    #[test]
    fn can_base38_encode() {
        const QR_CODE: &str = "MT:YNJV7VSC00CMVH7SR00";

        let comm_data = CommissioningData {
            verifier: VerifierData::new_with_pw(34567890),
            discriminator: 2976,
        };
        let dev_det = BasicInfoConfig {
            vid: 9050,
            pid: 65279,
            ..Default::default()
        };

        let disc_cap = DiscoveryCapabilities::new(false, true, false);
        let qr_code_data = QrCodeData::new(&dev_det, &comm_data, disc_cap);
        let data_str = payload_base38_representation(&qr_code_data).expect("Failed to encode");
        assert_eq!(data_str, QR_CODE)
    }
}
