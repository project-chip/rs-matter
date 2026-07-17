/*
 *
 *    Copyright (c) 2024-2026 Project CHIP Authors
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

use core::iter::{empty, once};

use crate::dm::clusters::basic_info::BasicInfoConfig;
use crate::transport::network::mdns::CommissionableFilter;

use super::{GATT_HEADER_SIZE, MAX_BTP_SEGMENT_SIZE};

/// The AD structure type for "Service Data - 16-bit UUID" (AD2), as per the BLE Core spec.
const AD_TYPE_SERVICE_DATA_UUID16: u8 = 0x16;
/// The length, in bytes, of the Matter commissionable service-data payload
/// (the bytes _following_ the 2-byte service UUID16 in the AD2 record), as per
/// the Matter Core spec, section "5.4.2.5.6. Advertising Data".
const MATTER_SERVICE_DATA_PAYLOAD_LEN: usize = 8;
/// The Matter BLE advertisement OpCode designating a commissionable device.
const MATTER_ADV_OPCODE_COMMISSIONABLE: u8 = 0x00;

#[cfg(all(feature = "os", feature = "bluer", target_os = "linux"))]
pub mod bluer;
// BlueZ is Linux-only (it uses the Linux Bluetooth stack and Linux-specific
// socket flags such as `SOCK_CLOEXEC`).
#[cfg(all(feature = "zbus", target_os = "linux"))]
pub mod bluez;

// The 16-bit, registered Matter Service UUID, as per the Matter Core spec.
pub const MATTER_BLE_SERVICE_UUID16: u16 = 0xFFF6;
// A 128-bit expanded representation of the Matter Service UUID.
pub const MATTER_BLE_SERVICE_UUID: u128 = 0x0000FFF600001000800000805F9B34FB;

/// `C1` characteristic UUID, as per the Matter Core spec.
pub const C1_CHARACTERISTIC_UUID: u128 = 0x18EE2EF5263D4559959F4F9C429F9D11;
/// `C2` characteristic UUID, as per the Matter Core spec.
pub const C2_CHARACTERISTIC_UUID: u128 = 0x18EE2EF5263D4559959F4F9C429F9D12;
/// `C3` characteristic UUID, as per the Matter Core spec.
pub const C3_CHARACTERISTIC_UUID: u128 = 0x64630238877245F2B87D748A83218F04;

/// The maximum length of packet data written to the `C1` characteristic, as per the Matter Core spec, and as advertised in the GATT service.
pub const C1_MAX_LEN: usize = MAX_BTP_SEGMENT_SIZE + GATT_HEADER_SIZE;
/// The maximum length of packet data indicated via the `C2` characteristic, as per the Matter Core spec, and as advertised in the GATT service.
pub const C2_MAX_LEN: usize = MAX_BTP_SEGMENT_SIZE + GATT_HEADER_SIZE;
/// The maximum length of data read from the `C3` characteristic, as per the Matter Core spec, and as advertised in the GATT service.
pub const C3_MAX_LEN: usize = 512;

/// Encapsulates the advertising data for the Matter BTP protocol.
///
/// This type is used in two directions:
/// - By an Accessory (GATT Peripheral) to **serialize** the advertising data it
///   broadcasts while commissionable (see [`AdvData::iter`] and friends).
/// - By a Commissioner (GATT Central) to **parse** a scanned advertisement and
///   decide whether it designates the commissionable device it is looking for
///   (see [`AdvData::parse_adv`] / [`AdvData::parse_service_data`] and
///   [`AdvData::matches`]) - the BLE-side analogue of resolving a commissionable
///   node from an mDNS TXT record.
///
/// See section "5.4.2.5.6. Advertising Data" in the Core Matter spec
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AdvData {
    vid: u16,
    pid: u16,
    discriminator: u16,
    /// Whether the device signals that it carries additional (BLE) advertising
    /// data (bit 0 of the last byte of the Matter service-data payload).
    ///
    /// Always `false` for advertisements produced by this stack; decoded from
    /// the wire when parsing a peer's advertisement.
    additional_data: bool,
}

impl AdvData {
    /// Create a new instance by using the provided `BasicInfoConfig` and `CommissioningData`.
    pub const fn new(dev_det: &BasicInfoConfig, discriminator: u16) -> Self {
        Self {
            vid: dev_det.vid,
            pid: dev_det.pid,
            discriminator,
            additional_data: false,
        }
    }

    /// The Vendor ID carried by this advertising data.
    pub const fn vid(&self) -> u16 {
        self.vid
    }

    /// The Product ID carried by this advertising data.
    pub const fn pid(&self) -> u16 {
        self.pid
    }

    /// The 12-bit discriminator carried by this advertising data.
    pub const fn discriminator(&self) -> u16 {
        self.discriminator
    }

    /// Whether the advertised device signals that it carries additional (BLE)
    /// advertising data. See the field of the same name; commissioners do not
    /// usually need to inspect this.
    pub const fn additional_data(&self) -> bool {
        self.additional_data
    }

    /// Return an iterator over the binary representation of the advertising data.
    ///
    /// As per the Matter Core spec, the advertising data consists of
    /// an AD1 record which is of Flags type, and an AD2 record, which is of type UUID16+Service Data
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        self.flags_iter().chain(self.service_iter())
    }

    /// Return an iterator over the binary representation of the AD1 advertising data (Flags).
    /// Useful with GATT stacks that require the advertising data to be reported as separate AD records
    pub fn flags_iter(&self) -> impl Iterator<Item = u8> + '_ {
        empty()
            .chain(once(self.flags_payload_iter().count() as u8 + 1)) // 1-byte type
            .chain(once(self.flags_adv_type()))
            .chain(self.flags_payload_iter())
    }

    /// The AD1 advertising data type (Flags).
    pub const fn flags_adv_type(&self) -> u8 {
        0x01
    }

    /// Return an iterator over the binary representation of the AD1 advertising data _payload_.
    /// Useful with GATT stacks that require the advertising data to be reported as separate AD records
    pub fn flags_payload_iter(&self) -> impl Iterator<Item = u8> + '_ {
        once(0x06)
    }

    /// Return an iterator over the binary representation of the AD2 advertising data (UUID16+Service Data).
    pub fn service_iter(&self) -> impl Iterator<Item = u8> + '_ {
        empty()
            .chain(once(self.service_payload_iter().count() as u8 + 3)) // + 1-byte type and 2-bytes Matter UUID16 Service
            .chain(once(self.service_adv_type()))
            .chain(MATTER_BLE_SERVICE_UUID16.to_le_bytes())
            .chain(self.service_payload_iter())
    }

    /// The AD2 advertising data type (UUID16+Service Data).
    pub const fn service_adv_type(&self) -> u8 {
        0x16
    }

    /// Return an iterator over the binary representation of the AD2 advertising data _payload_.
    /// Useful with GATT stacks that require the advertising data to be reported as separate AD records
    pub fn service_payload_iter(&self) -> impl Iterator<Item = u8> + '_ {
        [
            0, // Always 0 = "Commissionable"
            self.discriminator.to_le_bytes()[0],
            self.discriminator.to_le_bytes()[1],
            self.vid.to_le_bytes()[0],
            self.vid.to_le_bytes()[1],
            self.pid.to_le_bytes()[0],
            self.pid.to_le_bytes()[1],
            self.additional_data as u8, // Additional-data flag (bit 0)
        ]
        .into_iter()
    }

    /// Parse the advertising data out of a full, raw BLE advertising-data blob
    /// (a sequence of `length`-prefixed AD structures, i.e. `[len, type, ..len-1 bytes..]*`).
    ///
    /// This walks the AD structures, looks for the "Service Data - 16-bit UUID"
    /// (`0x16`) structure whose UUID is the Matter service UUID (`0xFFF6`), and
    /// decodes its payload.
    ///
    /// Returns `None` if the blob contains no (valid) Matter commissionable
    /// service-data structure. Use this when the OS/GATT stack hands you the raw
    /// advertising bytes; if it instead de-multiplexes service data by UUID for
    /// you (as BlueZ and `bluer` do), use [`AdvData::parse_service_data`] with
    /// the `0xFFF6` service-data value directly.
    pub fn parse_adv(adv: &[u8]) -> Option<Self> {
        for (ad_type, ad_payload) in AdStructures::new(adv) {
            if ad_type != AD_TYPE_SERVICE_DATA_UUID16 {
                continue;
            }

            // The service-data payload starts with the 2-byte (LE) UUID16. A
            // structure too short to hold one is malformed - skip it and keep
            // looking, rather than giving up on the whole advertisement: the Matter
            // record may well be further along.
            let Some((uuid16, service_data)) = ad_payload.split_first_chunk::<2>() else {
                continue;
            };

            if u16::from_le_bytes(*uuid16) == MATTER_BLE_SERVICE_UUID16 {
                return Self::parse_service_data(service_data);
            }
        }

        None
    }

    /// Parse the advertising data out of the Matter service-data payload - i.e.
    /// the bytes of the `0xFFF6` "Service Data - 16-bit UUID" advertising
    /// structure that _follow_ the 2-byte service UUID.
    ///
    /// This is the layout produced by [`AdvData::service_payload_iter`] and is
    /// what most OS GATT stacks (BlueZ, `bluer`) hand back when they expose
    /// advertised service data as a `UUID -> bytes` map.
    ///
    /// Returns `None` if the payload is not a valid, commissionable Matter
    /// service-data payload.
    pub fn parse_service_data(payload: &[u8]) -> Option<Self> {
        // As per spec the payload is exactly 8 bytes. Be lenient and accept a
        // longer payload (future extensions), but never a shorter one.
        if payload.len() < MATTER_SERVICE_DATA_PAYLOAD_LEN {
            return None;
        }

        // Byte 0 is the Matter BLE OpCode; only "Commissionable" (0) is a
        // commissionable device.
        if payload[0] != MATTER_ADV_OPCODE_COMMISSIONABLE {
            return None;
        }

        // Bytes 1..=2 are a 16-bit LE field whose low 12 bits are the
        // discriminator and whose high 4 bits are the advertising version
        // (currently 0). Mask off the version so we get the plain discriminator.
        let discriminator = u16::from_le_bytes([payload[1], payload[2]]) & 0x0FFF;
        let vid = u16::from_le_bytes([payload[3], payload[4]]);
        let pid = u16::from_le_bytes([payload[5], payload[6]]);
        let additional_data = payload[7] & 0x01 != 0;

        Some(Self {
            vid,
            pid,
            discriminator,
            additional_data,
        })
    }

    /// Whether this advertised commissionable device matches **all** of the
    /// non-`None` fields of the provided [`CommissionableFilter`] (AND
    /// semantics); an empty filter matches every commissionable device.
    ///
    /// This mirrors [`CommissionableFilter::matches`] (the mDNS TXT-record path)
    /// over the subset of fields a BLE advertisement carries:
    /// - `discriminator` (full 12-bit) and `short_discriminator` (upper 4 bits)
    ///   are matched against the advertised discriminator;
    /// - `vendor_id` / `product_id` are matched against the advertised VID / PID.
    ///
    /// A BLE advertisement does not carry a device type, and being advertised at
    /// all already implies commissioning mode, so a filter that constrains
    /// `device_type` never matches a BLE advertisement, and
    /// `commissioning_mode_only` is always satisfied.
    pub fn matches(&self, filter: &CommissionableFilter) -> bool {
        if let Some(want) = filter.discriminator {
            if self.discriminator != want {
                return false;
            }
        }

        if let Some(want) = filter.short_discriminator {
            // Short discriminator is the upper 4 bits of the 12-bit discriminator.
            if (self.discriminator >> 8) as u8 != want {
                return false;
            }
        }

        if let Some(want) = filter.vendor_id {
            if self.vid != want {
                return false;
            }
        }

        if let Some(want) = filter.product_id {
            if self.pid != want {
                return false;
            }
        }

        // A BLE advertisement carries no device type; a filter that requires one
        // cannot be satisfied by BLE discovery.
        if filter.device_type.is_some() {
            return false;
        }

        // `commissioning_mode_only` is implicit: a commissionable advertisement
        // (OpCode 0) is, by definition, in commissioning mode.

        true
    }
}

/// An iterator over the individual AD structures of a raw BLE advertising-data
/// blob, yielding `(ad_type, ad_payload)` for each well-formed
/// `[length, type, ..payload..]` structure and stopping at the first malformed
/// or zero-length structure (as per the BLE Core spec, a zero-length structure
/// marks the end of significant data).
struct AdStructures<'a> {
    rem: &'a [u8],
}

impl<'a> AdStructures<'a> {
    const fn new(adv: &'a [u8]) -> Self {
        Self { rem: adv }
    }
}

impl<'a> Iterator for AdStructures<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let (&len, rest) = self.rem.split_first()?;

        // A zero-length structure marks the end of significant data.
        let len = len as usize;
        if len == 0 || len > rest.len() {
            self.rem = &[];
            return None;
        }

        let (structure, rest) = rest.split_at(len);
        self.rem = rest;

        // `len` counts the type byte plus the payload, so `structure` is
        // non-empty here.
        let (&ad_type, payload) = structure.split_first()?;

        Some((ad_type, payload))
    }
}

#[cfg(test)]
mod test {
    use crate::transport::network::mdns::CommissionableFilter;

    use super::AdvData;

    /// A sample `AdvData` with a 12-bit discriminator that exercises the
    /// version-nibble masking on parse.
    fn sample() -> AdvData {
        AdvData {
            vid: 0xFFF1,
            pid: 0x8000,
            discriminator: 0xF00,
            additional_data: false,
        }
    }

    /// The parsed form of [`sample`], via the service-data payload round-trip.
    fn sample_parsed() -> AdvData {
        let payload: heapless::Vec<u8, 16> = sample().service_payload_iter().collect();
        AdvData::parse_service_data(&payload).unwrap()
    }

    #[test]
    fn parse_service_data_round_trips_adv_data() {
        let adv = sample();
        let parsed = sample_parsed();

        assert_eq!(parsed, adv);
        assert_eq!(parsed.discriminator(), adv.discriminator());
        assert_eq!(parsed.vid(), adv.vid());
        assert_eq!(parsed.pid(), adv.pid());
        assert!(!parsed.additional_data());
    }

    #[test]
    fn parse_service_data_round_trips_additional_data_flag() {
        let adv = AdvData {
            additional_data: true,
            ..sample()
        };
        let payload: heapless::Vec<u8, 16> = adv.service_payload_iter().collect();
        let parsed = AdvData::parse_service_data(&payload).unwrap();

        assert!(parsed.additional_data());
        assert_eq!(parsed, adv);
    }

    #[test]
    fn parse_full_adv_round_trips_adv_data() {
        let adv = sample();

        // The full AD blob is the AD1 (Flags) record chained with the AD2
        // (UUID16 + Service Data) record.
        let blob: heapless::Vec<u8, 32> = adv.iter().collect();

        let parsed = AdvData::parse_adv(&blob).unwrap();

        assert_eq!(parsed, adv);
    }

    #[test]
    fn parse_adv_ignores_unrelated_records() {
        // A blob with a Flags record, an unrelated 16-bit service-data record,
        // and finally the Matter one - the parser must skip to the Matter one.
        let adv = sample();

        let mut blob: heapless::Vec<u8, 64> = heapless::Vec::new();
        // Flags
        blob.extend([0x02, 0x01, 0x06]);
        // Unrelated Service Data - UUID16 (0x1234), 3 payload bytes
        blob.extend([0x06, 0x16, 0x34, 0x12, 0xAA, 0xBB, 0xCC]);
        // The Matter one
        blob.extend(adv.service_iter());

        let parsed = AdvData::parse_adv(&blob).unwrap();
        assert_eq!(parsed.discriminator(), adv.discriminator());
    }

    #[test]
    fn parse_adv_skips_a_malformed_service_data_record() {
        // A service-data record too short to even hold its UUID16, *before* the
        // Matter one. It must be skipped rather than abandoning the whole scan.
        let adv = sample();

        let mut blob: heapless::Vec<u8, 64> = heapless::Vec::new();
        // Service Data - UUID16 with a 1-byte payload: not even a full UUID.
        blob.extend([0x02, 0x16, 0x34]);
        // The Matter one.
        blob.extend(adv.service_iter());

        let parsed = unwrap!(AdvData::parse_adv(&blob), "Failed to parse");
        assert_eq!(parsed.discriminator(), adv.discriminator());
    }

    #[test]
    fn parse_service_data_rejects_non_commissionable_opcode() {
        let mut payload: heapless::Vec<u8, 16> = sample().service_payload_iter().collect();
        payload[0] = 0x01; // Not "Commissionable"

        assert!(AdvData::parse_service_data(&payload).is_none());
    }

    #[test]
    fn parse_service_data_rejects_short_payload() {
        assert!(AdvData::parse_service_data(&[0, 1, 2, 3]).is_none());
    }

    #[test]
    fn parse_adv_returns_none_without_matter_service_data() {
        // Just a Flags record - no Matter service data.
        assert!(AdvData::parse_adv(&[0x02, 0x01, 0x06]).is_none());
    }

    #[test]
    fn parse_adv_tolerates_truncated_trailing_record() {
        let adv = sample();
        let mut blob: heapless::Vec<u8, 64> = adv.iter().collect();
        // Append a malformed record claiming more bytes than are present.
        blob.extend([0x05, 0x16, 0x00]);

        // The Matter record precedes the malformed one, so it's still found.
        assert!(AdvData::parse_adv(&blob).is_some());
    }

    #[test]
    fn matches_filter_by_full_and_short_discriminator() {
        let parsed = sample_parsed();

        // Exact discriminator 0xF00
        let mut filter = CommissionableFilter {
            discriminator: Some(0xF00),
            ..Default::default()
        };
        assert!(parsed.matches(&filter));

        filter.discriminator = Some(0xF01);
        assert!(!parsed.matches(&filter));

        // Short discriminator = upper 4 bits of 0xF00 = 0xF
        let filter = CommissionableFilter {
            short_discriminator: Some(0xF),
            ..Default::default()
        };
        assert!(parsed.matches(&filter));

        let filter = CommissionableFilter {
            short_discriminator: Some(0x0),
            ..Default::default()
        };
        assert!(!parsed.matches(&filter));
    }

    #[test]
    fn matches_filter_by_vid_pid() {
        let parsed = sample_parsed();

        let filter = CommissionableFilter {
            vendor_id: Some(0xFFF1),
            product_id: Some(0x8000),
            ..Default::default()
        };
        assert!(parsed.matches(&filter));

        let filter = CommissionableFilter {
            vendor_id: Some(0x1234),
            ..Default::default()
        };
        assert!(!parsed.matches(&filter));
    }

    #[test]
    fn empty_filter_matches_any_commissionable_adv() {
        assert!(sample_parsed().matches(&CommissionableFilter::default()));
    }

    #[test]
    fn device_type_filter_never_matches_ble() {
        let filter = CommissionableFilter {
            device_type: Some(0x0100),
            ..Default::default()
        };
        assert!(!sample_parsed().matches(&filter));
    }
}
