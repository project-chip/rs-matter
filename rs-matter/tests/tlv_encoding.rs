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
    use bitflags::bitflags;
    use rs_matter::bitflags_tlv;
    use rs_matter::error::Error;
    use rs_matter::tlv::{FromTLV, TLVElement, TLVTag, ToTLV};
    use rs_matter::utils::storage::WriteBuf;

    #[derive(PartialEq, Debug, ToTLV, FromTLV)]
    struct SimpleStruct {
        number1: u8,
        number2: u32,
    }

    #[derive(PartialEq, Debug, Copy, Clone, ToTLV, FromTLV)]
    #[tlvargs(datatype = "u8")]
    #[allow(dead_code)]
    #[repr(u8)]
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
        let mut writer = WriteBuf::new(&mut output_buffer);
        what.to_tlv(&TLVTag::Anonymous, &mut writer)?;

        Ok(Vec::from(writer.as_slice()))
    }

    fn decode_from_tlv<'a, T: FromTLV<'a>>(data: &'a [u8]) -> Result<T, Error> {
        T::from_tlv(&TLVElement::new(data))
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

    #[test]
    fn test_bitflags() {
        bitflags! {
            #[repr(transparent)]
            #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
            struct SampleBitmap : u16 {
                const A = 0x0010;
                const B = 0x0200;
                const C = 0x4000;
            }
        };

        bitflags_tlv!(SampleBitmap, u16);

        #[derive(Debug, PartialEq, ToTLV, FromTLV)]
        struct StructWithBitmap {
            number: u32,
            data: SampleBitmap,
        }

        let a = StructWithBitmap {
            number: 112233,
            data: SampleBitmap::A | SampleBitmap::C,
        };

        let encoded = asserted_ok!(encode_to_tlv(&a), "Encoding to TLV");
        let b = asserted_ok!(decode_from_tlv(&encoded), "Decode from tlv");

        assert_eq!(a, b);
    }
}
