/*
 * Copyright (c) 2024-2026 Project CHIP Authors
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
    use rs_matter::im::CmdPath;
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

    /// Regression test for the `CmdPath` decoder dropping the optional
    /// `endpointId` (context tag 0) when a peer writes the IB members in
    /// any order other than 0, 1, 2.
    ///
    /// Matter Core spec §10.6.1 ("Tag Rules", 1.5 / 1.5.1) requires
    /// context tags to be emitted in the order defined by the IB, so
    /// encoders that re-order are non-conformant. matter.js (and hence
    /// matterjs-server / Home Assistant Matter in beta mode) violates
    /// this rule for `CommandPathIB`: it writes `clusterId (tag 1),
    /// commandId (tag 2), endpointId (tag 0)`. See
    /// matter-js/matter.js#3747 for the upstream-side discussion. A
    /// `scan_ctx`-based linear decoder (the previous rs-matter default,
    /// now opt-in via `#[tlvargs(assume_ordered)]`) would pass tag 0
    /// before checking it and silently report `endpoint = None`, which
    /// then triggers wildcard endpoint expansion on the receiver. The
    /// new `find_ctx`-based decoder (the current default) tolerates any
    /// member order, matching the C++ SDK's status quo.
    #[test]
    fn cmd_path_decodes_with_out_of_order_tags() {
        // CommandPathIB list, members in matter.js order:
        //   0x37 0x00              // List, context tag 0 (commandPath field)
        //     0x24 0x01 0x06       // U8 ctx-tag 1: clusterId = 0x06 (OnOff)
        //     0x24 0x02 0x01       // U8 ctx-tag 2: commandId = 0x01 (On)
        //     0x24 0x00 0x01       // U8 ctx-tag 0: endpointId = 0x01
        //   0x18                   // End of List
        //
        // Decode as a bare list, anchored at the List opener.
        let bytes: [u8; 12] = [
            0x37, 0x00, 0x24, 0x01, 0x06, 0x24, 0x02, 0x01, 0x24, 0x00, 0x01, 0x18,
        ];

        let element = TLVElement::new(&bytes);
        let decoded = asserted_ok!(CmdPath::from_tlv(&element), "Decoding CmdPath from TLV");

        assert_eq!(decoded.endpoint, Some(1), "endpointId (tag 0) must decode");
        assert_eq!(decoded.cluster, Some(6), "clusterId (tag 1) must decode");
        assert_eq!(decoded.cmd, Some(1), "commandId (tag 2) must decode");
    }

    /// Sibling of the test above for another non-conformant ordering
    /// (tags 0, 2, 1 — `endpoint, command, cluster`). Spec-compliant
    /// encoders emit 0, 1, 2; this exercises the unordered scan from a
    /// different direction so a future "optimization" that re-introduces
    /// ordered scanning fails here too.
    #[test]
    fn cmd_path_decodes_with_tag_1_after_tag_2() {
        let bytes: [u8; 12] = [
            0x37, 0x00, 0x24, 0x00, 0x01, 0x24, 0x02, 0x01, 0x24, 0x01, 0x06, 0x18,
        ];

        let element = TLVElement::new(&bytes);
        let decoded = asserted_ok!(CmdPath::from_tlv(&element), "Decoding CmdPath from TLV");

        assert_eq!(decoded.endpoint, Some(1));
        assert_eq!(decoded.cluster, Some(6));
        assert_eq!(decoded.cmd, Some(1));
    }

    /// Wildcard endpoint (tag 0 omitted) must still decode cleanly as
    /// `endpoint = None`. This is the legitimate use of the option per spec.
    #[test]
    fn cmd_path_wildcard_endpoint_still_decodes() {
        // List with only cluster and command members.
        let bytes: [u8; 9] = [0x37, 0x00, 0x24, 0x01, 0x06, 0x24, 0x02, 0x01, 0x18];

        let element = TLVElement::new(&bytes);
        let decoded = asserted_ok!(CmdPath::from_tlv(&element), "Decoding CmdPath from TLV");

        assert_eq!(decoded.endpoint, None);
        assert_eq!(decoded.cluster, Some(6));
        assert_eq!(decoded.cmd, Some(1));
    }
}
