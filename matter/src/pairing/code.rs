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

use super::*;

pub(super) fn compute_pairing_code(comm_data: &CommissioningData) -> String {
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

pub(super) fn pretty_print_pairing_code(pairing_code: &str) {
    assert!(pairing_code.len() == 11);
    let mut pretty = String::new();
    pretty.push_str(&pairing_code[..4]);
    pretty.push('-');
    pretty.push_str(&pairing_code[4..8]);
    pretty.push('-');
    pretty.push_str(&pairing_code[8..]);
    info!("Pairing Code: {}", pretty);
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
}
