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

use core::fmt::Write;

use verhoeff::Verhoeff;

use crate::BasicCommData;

impl BasicCommData {
    /// Compute the 11-digit manual pairing code (no vendor/product IDs)
    ///
    /// Implies the standard commissioning flow; other flows need
    /// [`Self::compute_pairing_code_long`].
    pub fn compute_pairing_code(&self) -> heapless::String<11> {
        let mut digits = heapless::String::new();

        self.write_pairing_code_digits(&mut digits, None);

        digits
    }

    /// Compute the 21-digit manual pairing code, which carries the vendor and
    /// product IDs; required for non-standard commissioning flows
    pub fn compute_pairing_code_long(&self, vid: u16, pid: u16) -> heapless::String<21> {
        let mut digits = heapless::String::new();

        self.write_pairing_code_digits(&mut digits, Some((vid, pid)));

        digits
    }

    /// The 11-digit manual pairing code grouped for display: `XXXX-XXX-XXXX`
    pub fn compute_pretty_pairing_code(&self) -> heapless::String<13> {
        let pairing_code = self.compute_pairing_code();

        let mut pretty = heapless::String::new();
        Self::write_groups(&mut pretty, &pairing_code, &[4, 3, 4]);

        pretty
    }

    /// The 21-digit manual pairing code grouped for display:
    /// `XXXX-XXX-XXXX-XXXXX-XXXXX` (the spec prescribes no grouping)
    pub fn compute_pretty_pairing_code_long(&self, vid: u16, pid: u16) -> heapless::String<25> {
        let pairing_code = self.compute_pairing_code_long(vid, pid);

        let mut pretty = heapless::String::new();
        Self::write_groups(&mut pretty, &pairing_code, &[4, 3, 4, 5, 5]);

        pretty
    }

    /// Write the pairing code digits, check digit included; the 21-digit
    /// variant if `vid_pid` is present.
    fn write_pairing_code_digits<const N: usize>(
        &self,
        digits: &mut heapless::String<N>,
        vid_pid: Option<(u16, u16)>,
    ) {
        let BasicCommData {
            password,
            discriminator,
            ..
        } = self;

        let password = u32::from_le_bytes(*password.access());
        let vid_pid_present: u8 = vid_pid.is_some().into();

        // DIGIT[1]      := (VID_PID_PRESENT << 2) | (DISCRIMINATOR >> 10)
        // DIGIT[2..6]   := ((DISCRIMINATOR & 0x300) << 6) | (PASSCODE & 0x3FFF)
        // DIGIT[7..10]  := PASSCODE >> 14
        // DIGIT[11..15] := VID and DIGIT[16..20] := PID (21-digit variant only)
        // Last digit    := Verhoeff check digit over all of the above
        write_unwrap!(
            digits,
            "{}{:0>5}{:0>4}",
            (vid_pid_present << 2) | (discriminator >> 10) as u8,
            ((discriminator & 0x300) << 6) | (password & 0x3FFF) as u16,
            password >> 14
        );

        if let Some((vid, pid)) = vid_pid {
            write_unwrap!(digits, "{vid:0>5}{pid:0>5}");
        }

        let check_digit = digits.calculate_verhoeff_check_digit();
        write_unwrap!(digits, "{check_digit}");
    }

    /// Write `digits` into `pretty` in dash-separated groups of the given sizes.
    fn write_groups<const N: usize>(
        pretty: &mut heapless::String<N>,
        digits: &str,
        groups: &[usize],
    ) {
        let mut offset = 0;

        for (index, group) in groups.iter().enumerate() {
            if index > 0 {
                unwrap!(pretty.push('-'));
            }

            unwrap!(pretty.push_str(&digits[offset..offset + group]));
            offset += group;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pairing::qr::QrPayload;

    #[test]
    fn can_compute_pairing_code() {
        let comm_data = BasicCommData {
            password: 123456_u32.to_le_bytes().into(),
            discriminator: 250,
        };
        let pairing_code = comm_data.compute_pairing_code();
        assert_eq!(pairing_code, "00876800071");

        let comm_data = BasicCommData {
            password: 34567890_u32.to_le_bytes().into(),
            discriminator: 2976,
        };
        let pairing_code = comm_data.compute_pairing_code();
        assert_eq!(pairing_code, "26318621095");
        assert_eq!(comm_data.compute_pretty_pairing_code(), "2631-862-1095");
    }

    /// Vectors from the CHIP SDK's `TestManualCode` suite (given there without
    /// the check digit).
    #[test]
    fn can_compute_pairing_code_long() {
        let comm_data = BasicCommData {
            password: 12345679_u32.to_le_bytes().into(),
            discriminator: 2560,
        };

        let short = comm_data.compute_pairing_code();
        assert_eq!(&short[..10], "2412950753");
        assert!(short.validate_verhoeff_check_digit());

        let long = comm_data.compute_pairing_code_long(0, 0);
        assert_eq!(&long[..20], "64129507530000000000");
        assert!(long.validate_verhoeff_check_digit());

        let long = comm_data.compute_pairing_code_long(1, 1);
        assert_eq!(&long[..20], "64129507530000100001");
        assert!(long.validate_verhoeff_check_digit());

        let long = comm_data.compute_pairing_code_long(45367, 14526);
        assert_eq!(&long[..20], "64129507534536714526");
        assert!(long.validate_verhoeff_check_digit());

        let pretty = comm_data.compute_pretty_pairing_code_long(45367, 14526);
        assert_eq!(&pretty[..24], "6412-950-7534-53671-4526");
        assert_eq!(pretty.len(), 25);

        // Round-trip through the parser, dashes and all
        let parsed = QrPayload::parse_pairing_code(&pretty).unwrap();
        assert_eq!(parsed.passcode(), 12345679);
        assert_eq!(parsed.short_discriminator(), (2560 >> 8) as u8);
        assert_eq!(parsed.vid_pid(), Some((45367, 14526)));

        // The all-ones vector: every field at its maximum
        let comm_data = BasicCommData {
            password: 0x7FF_FFFF_u32.to_le_bytes().into(),
            discriminator: 0xFFF,
        };
        let long = comm_data.compute_pairing_code_long(65535, 65535);
        assert_eq!(&long[..20], "76553581916553565535");
        assert!(long.validate_verhoeff_check_digit());
    }
}
