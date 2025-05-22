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

use core::fmt::Debug;

use rs_matter::error::Error;
use rs_matter::tlv::{TLVElement, TLVTag, TLVWriter, ToTLV};
use rs_matter::transport::exchange::MessageMeta;
use rs_matter::utils::storage::WriteBuf;

use super::test::E2eTest;

/// A `ToTLV` trait variant useful for testing.
///
/// Unlike `ToTLV`, `TestToTLV` is `dyn`-friendly, but therefore does
/// require a `TLVWriter` to be passed in.
pub trait TestToTLV: Debug + Sync {
    fn test_to_tlv(&self, tag: &TLVTag, tw: &mut TLVWriter) -> Result<(), Error>;
}

impl<T> TestToTLV for T
where
    T: ToTLV + Debug + Sync,
{
    fn test_to_tlv(&self, tag: &TLVTag, tw: &mut TLVWriter) -> Result<(), Error> {
        ToTLV::to_tlv(self, tag, tw)
    }
}

/// A concrete `E2eTest` implementation that assumes that the input and output payload
/// of the test are both TLV payloads.
///
/// It validates the differences between the output and the expected payload using a Diff
/// algorithm, which provides a human readable output.
pub struct TLVTest<I, E, F> {
    pub input_meta: MessageMeta,
    pub input_payload: I,
    pub expected_meta: MessageMeta,
    pub expected_payload: E,
    pub process_reply: F,
    pub delay_ms: Option<u64>,
}

impl<I, E, F> E2eTest for TLVTest<I, E, F>
where
    I: TestToTLV,
    E: TestToTLV,
    F: Fn(&TLVElement, &mut [u8]) -> Result<usize, Error>,
{
    fn fill_input(&self, message_buf: &mut WriteBuf) -> Result<MessageMeta, Error> {
        self.input_payload
            .test_to_tlv(&TLVTag::Anonymous, &mut TLVWriter::new(message_buf))?;

        Ok(self.input_meta)
    }

    fn validate_result(&self, meta: MessageMeta, message: &[u8]) -> Result<(), Error> {
        use core::fmt::Write;

        assert_eq!(self.expected_meta, meta);

        let mut buf = [0; 1500];
        let mut wb = WriteBuf::new(&mut buf);

        let mut tw = TLVWriter::new(&mut wb);

        self.expected_payload
            .test_to_tlv(&TLVTag::Anonymous, &mut tw)?;
        let expected_element = TLVElement::new(wb.as_slice());

        let element = TLVElement::new(message);

        let mut buf2 = [0; 1500];
        let len = (self.process_reply)(&element, &mut buf2)?;

        let element = TLVElement::new(&buf2[..len]);

        if expected_element != element {
            let expected_str = format!("{expected_element}");
            let actual_str = format!("{element}");

            let diff = similar::TextDiff::from_lines(&expected_str, &actual_str);

            let mut diff_str = String::new();

            // TODO: Color the diff output
            for change in diff.iter_all_changes() {
                let sign = match change.tag() {
                    similar::ChangeTag::Delete => "-",
                    similar::ChangeTag::Insert => "+",
                    similar::ChangeTag::Equal => " ",
                };

                write!(diff_str, "{sign}{change}").unwrap();
            }

            panic!("Expected does not match actual:\n== Diff:\n{diff_str}");
            //panic!("Expected does not match actual:\n== Diff:\n{diff_str}\n== Expected:\n{expected_str}\n== Actual:\n{actual_str}");
        }

        Ok(())
    }

    fn delay(&self) -> Option<u64> {
        self.delay_ms
    }
}
