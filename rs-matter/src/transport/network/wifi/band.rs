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

//! A utility for converting a Wifi frequency to a Wifi band and channel

use crate::dm::clusters::net_comm::WiFiBandEnum;

/// Convert a Wifi frequency to a Wifi band and channel.
///
/// Return a tuple of `(WiFiBandEnum, u16)` where `WiFiBandEnum` is the band and `u16NonZeroU16` is the channel.
/// If the frequency is not valid, return `None`.
///
/// See https://github.com/project-chip/connectedhomeip/blob/cd5fec9ba9be0c39f3c11f67d57b18b6bb2b4289/src/platform/Linux/ConnectivityManagerImpl.cpp#L1937
pub fn band_and_channel(freq: u32) -> Option<(WiFiBandEnum, u16)> {
    let mut band = WiFiBandEnum::V2G4;

    let channel = if freq <= 931 {
        if freq >= 916 {
            ((freq - 916) * 2) - 1
        } else if freq >= 902 {
            (freq - 902) * 2
        } else if freq >= 863 {
            (freq - 863) * 2
        } else {
            1
        }
    } else if freq <= 2472 {
        (freq - 2412) / 5 + 1
    } else if freq == 2484 {
        14
    } else if (3600..=3700).contains(&freq) {
        // Note: There are not many devices supports this band, and this band contains rational frequency in MHz, need to figure out
        // the behavior of wpa_supplicant in this case.
        band = WiFiBandEnum::V3G65;
        0
    } else if (5035..=5945).contains(&freq) || freq == 5960 || freq == 5980 {
        band = WiFiBandEnum::V5G;
        (freq - 5000) / 5
    } else if (5955..58_000).contains(&freq) {
        band = WiFiBandEnum::V6G;
        (freq - 5950) / 5
    } else if freq >= 58_000 {
        band = WiFiBandEnum::V60G;

        // Note: Some channel has the same center frequency but different bandwidth. Should figure out wpa_supplicant's behavior in
        // this case. Also, wpa_supplicant's frequency property is uint16 infact.
        match freq {
            58_320 => 1,
            60_480 => 2,
            62_640 => 3,
            64_800 => 4,
            66_960 => 5,
            69_120 => 6,
            59_400 => 9,
            61_560 => 10,
            63_720 => 11,
            65_880 => 12,
            68_040 => 13,
            _ => 0,
        }
    } else {
        // Unknown channel
        0
    };

    (channel > 0).then_some((band, channel as _))
}

/// Convert a signal strength percentage (0-100) to an RSSI value in dBm.
///
/// Note that the conversion is a rough approximation:
/// - 0% corresponds to -100 dBm (no signal)
/// - 100% corresponds to -30 dBm (excellent signal)
pub fn signal_strength_to_rssi(strength_perc: u8) -> i8 {
    let strength_perc = strength_perc.clamp(0, 100);

    // Convert percentage to dBm
    // 0% -> -100 dBm, 100% -> -30 dBm
    (strength_perc / 2) as i8 - 100
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_band_and_channel() {
        // Not testing the 900MHz 802.11ah band, as it is country-specific and the likelyhood
        // of having a device operating there is near 0%
        //
        // Branches for 900MHz band kept in the code for completeness, but not tested.

        use super::band_and_channel;
        use crate::dm::clusters::net_comm::WiFiBandEnum::{V2G4, V5G, V60G, V6G};

        assert_eq!(Some((V2G4, 1)), band_and_channel(2412));
        assert_eq!(Some((V2G4, 6)), band_and_channel(2437));
        assert_eq!(Some((V2G4, 11)), band_and_channel(2462));
        assert_eq!(Some((V2G4, 14)), band_and_channel(2484));
        assert_eq!(None, band_and_channel(5000));

        assert_eq!(Some((V5G, 7)), band_and_channel(5035));
        assert_eq!(Some((V5G, 8)), band_and_channel(5040));
        assert_eq!(Some((V5G, 9)), band_and_channel(5048));
        assert_eq!(Some((V5G, 11)), band_and_channel(5055));
        assert_eq!(Some((V5G, 12)), band_and_channel(5060));
        assert_eq!(Some((V5G, 16)), band_and_channel(5080));

        assert_eq!(Some((V5G, 36)), band_and_channel(5180));
        assert_eq!(Some((V5G, 38)), band_and_channel(5190));
        assert_eq!(Some((V5G, 40)), band_and_channel(5200));
        assert_eq!(Some((V5G, 42)), band_and_channel(5210));
        assert_eq!(Some((V5G, 44)), band_and_channel(5220));
        assert_eq!(Some((V5G, 46)), band_and_channel(5230));
        assert_eq!(Some((V5G, 48)), band_and_channel(5240));
        assert_eq!(Some((V5G, 52)), band_and_channel(5260));
        assert_eq!(Some((V5G, 56)), band_and_channel(5280));
        assert_eq!(Some((V5G, 60)), band_and_channel(5300));
        assert_eq!(Some((V5G, 64)), band_and_channel(5320));
        assert_eq!(Some((V5G, 100)), band_and_channel(5500));
        assert_eq!(Some((V5G, 104)), band_and_channel(5520));
        assert_eq!(Some((V5G, 108)), band_and_channel(5540));
        assert_eq!(Some((V5G, 112)), band_and_channel(5560));
        assert_eq!(Some((V5G, 116)), band_and_channel(5580));
        assert_eq!(Some((V5G, 120)), band_and_channel(5600));
        assert_eq!(Some((V5G, 124)), band_and_channel(5620));
        assert_eq!(Some((V5G, 128)), band_and_channel(5640));
        assert_eq!(Some((V5G, 132)), band_and_channel(5660));
        assert_eq!(Some((V5G, 136)), band_and_channel(5680));
        assert_eq!(Some((V5G, 140)), band_and_channel(5700));
        assert_eq!(Some((V5G, 144)), band_and_channel(5720));
        assert_eq!(Some((V5G, 149)), band_and_channel(5745));
        assert_eq!(Some((V5G, 153)), band_and_channel(5765));
        assert_eq!(Some((V5G, 157)), band_and_channel(5785));
        assert_eq!(Some((V5G, 161)), band_and_channel(5805));
        assert_eq!(Some((V5G, 165)), band_and_channel(5825));

        assert_eq!(Some((V5G, 187)), band_and_channel(5935));
        assert_eq!(Some((V5G, 192)), band_and_channel(5960));
        assert_eq!(Some((V5G, 196)), band_and_channel(5980));

        assert_eq!(None, band_and_channel(5950));

        assert_eq!(Some((V6G, 1)), band_and_channel(5955));
        assert_eq!(Some((V6G, 5)), band_and_channel(5975));
        assert_eq!(Some((V6G, 9)), band_and_channel(5995));

        assert_eq!(Some((V60G, 1)), band_and_channel(58320));
        assert_eq!(Some((V60G, 2)), band_and_channel(60480));
        assert_eq!(Some((V60G, 3)), band_and_channel(62640));
        assert_eq!(Some((V60G, 4)), band_and_channel(64800));
        assert_eq!(Some((V60G, 5)), band_and_channel(66960));
        assert_eq!(Some((V60G, 9)), band_and_channel(59400));
        assert_eq!(Some((V60G, 10)), band_and_channel(61560));
    }

    #[test]
    fn test_signal_strength_to_rssi() {
        use super::signal_strength_to_rssi;

        assert_eq!(signal_strength_to_rssi(0), -100);
        assert_eq!(signal_strength_to_rssi(50), -75);
        assert_eq!(signal_strength_to_rssi(100), -50);
        assert_eq!(signal_strength_to_rssi(25), -88);
        assert_eq!(signal_strength_to_rssi(75), -63);
        assert_eq!(signal_strength_to_rssi(110), -50); // Clamped to 100%
        assert_eq!(signal_strength_to_rssi(150), -50); // Clamped to 100%
    }
}
