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

//! Base38 encoding functions.

const BASE38_CHARS: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";

/// Encodes a byte array into a base38 string.
pub fn encode(bytes: &[u8], length: usize) -> String {
    let mut offset = 0;
    let mut result = String::new();

    while offset < length {
        let remaining = length - offset;
        match remaining.cmp(&2) {
            std::cmp::Ordering::Greater => {
                result.push_str(&encode_base38(
                    ((bytes[offset + 2] as u32) << 16)
                        | ((bytes[offset + 1] as u32) << 8)
                        | (bytes[offset] as u32),
                    5,
                ));
                offset += 3;
            }
            std::cmp::Ordering::Equal => {
                result.push_str(&encode_base38(
                    ((bytes[offset + 1] as u32) << 8) | (bytes[offset] as u32),
                    4,
                ));
                break;
            }
            std::cmp::Ordering::Less => {
                result.push_str(&encode_base38(bytes[offset] as u32, 2));
                break;
            }
        }
    }

    result
}

fn encode_base38(mut value: u32, char_count: u8) -> String {
    let mut result = String::new();
    let chars = BASE38_CHARS.chars();
    for _ in 0..char_count {
        let mut use_chars = chars.clone();
        let remainder = value % 38;
        result.push(use_chars.nth(remainder as usize).unwrap());
        value = (value - remainder) / 38;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_base38_encode() {
        const ENCODED: &str = "-MOA57ZU02IT2L2BJ00";
        const DECODED: [u8; 11] = [
            0x88, 0xff, 0xa7, 0x91, 0x50, 0x40, 0x00, 0x47, 0x51, 0xdd, 0x02,
        ];
        assert_eq!(encode(&DECODED, 11), ENCODED);
    }
}
