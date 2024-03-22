/*
 * Copyright (c) 2024 Project CHIP Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#[cfg(test)]
mod tlv_encoding_tests {
    use rs_matter::error::Error;
    use rs_matter::tlv::{get_root_node, FromTLV, TLVWriter, TagType, ToTLV};
    use rs_matter::utils::writebuf::WriteBuf;

    #[derive(PartialEq, Debug, ToTLV, FromTLV)]
    struct SimpleStruct {
        number1: u8,
        number2: u32,
    }

    #[derive(PartialEq, Debug, ToTLV, FromTLV)]
    #[allow(dead_code)]
    enum SimpleEnum {
        A,
        B,
        C,
    }

    #[derive(PartialEq, Debug, ToTLV, FromTLV)]
    struct SimpleStructWithEnum {
        enum1: SimpleEnum,
        number2: u32,
    }

    fn encode_to_tlv(what: &impl ToTLV) -> Result<Vec<u8>, Error> {
        const MAX_OUTPUT_SIZE: usize = 1024;

        let mut output_buffer = [0u8; MAX_OUTPUT_SIZE];
        let mut write_buf = WriteBuf::new(&mut output_buffer);
        let mut writer = TLVWriter::new(&mut write_buf);
        what.to_tlv(&mut writer, TagType::Anonymous)?;

        Ok(Vec::from(write_buf.as_slice()))
    }

    fn decode_from_tlv<'a, T: FromTLV<'a>>(data: &'a [u8]) -> Result<T, Error> {
        let node = get_root_node(data)?;
        T::from_tlv(&node)
    }

    macro_rules! asserted_ok {
        ($a:expr, $message: literal) => {
            match $a {
                Ok(value) => value,
                Err(e) => {
                    assert!(false, "{} failed with {:?}", $message, e);
                    return;
                }
            }
        };
    }

    #[test]
    fn encode_simple_struct() {
        let a = SimpleStruct {
            number1: 123,
            number2: 0x23456,
        };

        let encoded = asserted_ok!(encode_to_tlv(&a), "Encoding to TLV");
        let b = asserted_ok!(decode_from_tlv(&encoded), "Decoding of LTV");

        assert_eq!(a, b);
    }

    #[test]
    fn simple_enum_formats() {
        let with_enum = SimpleStructWithEnum {
            enum1: SimpleEnum::C,
            number2: 0x23456,
        };

        let without_enum = SimpleStruct {
            number1: 2,
            number2: 0x23456,
        };

        let encoded = asserted_ok!(encode_to_tlv(&with_enum), "Encoding to TLV");

        // check that enums are encoded as a simple u8
        let b = asserted_ok!(decode_from_tlv::<SimpleStruct>(&encoded), "Decoding of TLV");
        assert_eq!(b, without_enum);

        // check that enum decoding back works (i.e. encode/decode are idem-potent)
        let b = asserted_ok!(
            decode_from_tlv::<SimpleStructWithEnum>(&encoded),
            "Decoding of TLV"
        );
        assert_eq!(b, with_enum);
    }
}
