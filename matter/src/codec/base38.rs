const BASE38_CHARS: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";

fn encode_base38(mut value: u32, char_count: u8) -> String {
    let mut result = String::new();
    for _ in 0..char_count {
        let mut chars = BASE38_CHARS.chars();
        let remainder = value % 38;
        result.push(chars.nth(remainder as usize).unwrap());
        value = (value - remainder) / 38;
    }
    result
}

pub fn encode(bytes: &[u8]) -> String {
    let length = bytes.len();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_base38_encode() {
        const ENCODED: &str = "-MOA57ZU02IT2L2BJ00";
        const DECODED: [u8; 11] = [
            0x88, 0xff, 0xa7, 0x91, 0x50, 0x40, 0x00, 0x47, 0x51, 0xdd, 0x02,
        ];
        assert_eq!(encode(&DECODED), ENCODED);
    }
}
