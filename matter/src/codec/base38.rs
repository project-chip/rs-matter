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

//! Base38 encoding and decoding functions.

extern crate alloc;

use alloc::{string::String, vec::Vec};

use crate::error::Error;

const BASE38_CHARS: [char; 38] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '-', '.',
];

const UNUSED: u8 = 255;

// map of base38 charater to numeric value
// subtract 45 from the character, then index into this array, if possible
const DECODE_BASE38: [u8; 46] = [
    36,     // '-', =45
    37,     // '.', =46
    UNUSED, // '/', =47
    0,      // '0', =48
    1,      // '1', =49
    2,      // '2', =50
    3,      // '3', =51
    4,      // '4', =52
    5,      // '5', =53
    6,      // '6', =54
    7,      // '7', =55
    8,      // '8', =56
    9,      // '9', =57
    UNUSED, // ':', =58
    UNUSED, // ';', =59
    UNUSED, // '<', =50
    UNUSED, // '=', =61
    UNUSED, // '>', =62
    UNUSED, // '?', =63
    UNUSED, // '@', =64
    10,     // 'A', =65
    11,     // 'B', =66
    12,     // 'C', =67
    13,     // 'D', =68
    14,     // 'E', =69
    15,     // 'F', =70
    16,     // 'G', =71
    17,     // 'H', =72
    18,     // 'I', =73
    19,     // 'J', =74
    20,     // 'K', =75
    21,     // 'L', =76
    22,     // 'M', =77
    23,     // 'N', =78
    24,     // 'O', =79
    25,     // 'P', =80
    26,     // 'Q', =81
    27,     // 'R', =82
    28,     // 'S', =83
    29,     // 'T', =84
    30,     // 'U', =85
    31,     // 'V', =86
    32,     // 'W', =87
    33,     // 'X', =88
    34,     // 'Y', =89
    35,     // 'Z', =90
];

const BASE38_CHARACTERS_NEEDED_IN_NBYTES_CHUNK: [u8; 3] = [2, 4, 5];
const RADIX: u32 = BASE38_CHARS.len() as u32;

/// Encode a byte array into a base38 string.
///
/// # Arguments
/// * `bytes` - byte array to encode
/// * `length` - optional length of the byte array to encode. If not specified, the entire byte array is encoded.
pub fn encode(bytes: &[u8], length: Option<usize>) -> String {
    let mut offset = 0;
    let mut result = String::new();

    // if length is specified, use it, otherwise use the length of the byte array
    // if length is specified but is greater than the length of the byte array, use the length of the byte array
    let b_len = bytes.len();
    let length = length.map(|l| l.min(b_len)).unwrap_or(b_len);

    while offset < length {
        let remaining = length - offset;
        match remaining.cmp(&2) {
            core::cmp::Ordering::Greater => {
                result.push_str(&encode_base38(
                    ((bytes[offset + 2] as u32) << 16)
                        | ((bytes[offset + 1] as u32) << 8)
                        | (bytes[offset] as u32),
                    5,
                ));
                offset += 3;
            }
            core::cmp::Ordering::Equal => {
                result.push_str(&encode_base38(
                    ((bytes[offset + 1] as u32) << 8) | (bytes[offset] as u32),
                    4,
                ));
                break;
            }
            core::cmp::Ordering::Less => {
                result.push_str(&encode_base38(bytes[offset] as u32, 2));
                break;
            }
        }
    }

    result
}

fn encode_base38(mut value: u32, char_count: u8) -> String {
    let mut result = String::new();
    for _ in 0..char_count {
        let remainder = value % 38;
        result.push(BASE38_CHARS[remainder as usize]);
        value = (value - remainder) / 38;
    }
    result
}

/// Decode a base38-encoded string into a byte slice
///
/// # Arguments
/// * `base38_str` - base38-encoded string to decode
///
/// Fails if the string contains invalid characters
pub fn decode(base38_str: &str) -> Result<Vec<u8>, Error> {
    let mut result = Vec::new();
    let mut base38_characters_number: usize = base38_str.len();
    let mut decoded_base38_characters: usize = 0;

    while base38_characters_number > 0 {
        let base38_characters_in_chunk: usize;
        let bytes_in_decoded_chunk: usize;

        if base38_characters_number >= BASE38_CHARACTERS_NEEDED_IN_NBYTES_CHUNK[2] as usize {
            base38_characters_in_chunk = BASE38_CHARACTERS_NEEDED_IN_NBYTES_CHUNK[2] as usize;
            bytes_in_decoded_chunk = 3;
        } else if base38_characters_number == BASE38_CHARACTERS_NEEDED_IN_NBYTES_CHUNK[1] as usize {
            base38_characters_in_chunk = BASE38_CHARACTERS_NEEDED_IN_NBYTES_CHUNK[1] as usize;
            bytes_in_decoded_chunk = 2;
        } else if base38_characters_number == BASE38_CHARACTERS_NEEDED_IN_NBYTES_CHUNK[0] as usize {
            base38_characters_in_chunk = BASE38_CHARACTERS_NEEDED_IN_NBYTES_CHUNK[0] as usize;
            bytes_in_decoded_chunk = 1;
        } else {
            return Err(Error::InvalidData);
        }

        let mut value = 0u32;

        for i in (1..=base38_characters_in_chunk).rev() {
            let mut base38_chars = base38_str.chars();
            let v = decode_char(base38_chars.nth(decoded_base38_characters + i - 1).unwrap())?;

            value = value * RADIX + v as u32;
        }

        decoded_base38_characters += base38_characters_in_chunk;
        base38_characters_number -= base38_characters_in_chunk;

        for _i in 0..bytes_in_decoded_chunk {
            result.push(value as u8);
            value >>= 8;
        }

        if value > 0 {
            // encoded value is too big to represent a correct chunk of size 1, 2 or 3 bytes
            return Err(Error::InvalidArgument);
        }
    }

    Ok(result)
}

fn decode_char(c: char) -> Result<u8, Error> {
    let c = c as u8;
    if !(45..=90).contains(&c) {
        return Err(Error::InvalidData);
    }

    let c = DECODE_BASE38[c as usize - 45];
    if c == UNUSED {
        return Err(Error::InvalidData);
    }

    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    const ENCODED: &str = "-MOA57ZU02IT2L2BJ00";
    const DECODED: [u8; 11] = [
        0x88, 0xff, 0xa7, 0x91, 0x50, 0x40, 0x00, 0x47, 0x51, 0xdd, 0x02,
    ];

    #[test]
    fn can_base38_encode() {
        assert_eq!(encode(&DECODED, None), ENCODED);
        assert_eq!(encode(&DECODED, Some(11)), ENCODED);

        // length is greater than the length of the byte array
        assert_eq!(encode(&DECODED, Some(12)), ENCODED);
    }

    #[test]
    fn can_base38_decode() {
        assert_eq!(decode(ENCODED).expect("can not decode base38"), DECODED);
    }
}
