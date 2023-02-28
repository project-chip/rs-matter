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

use matter::interaction_model::{messages::ib::AttrResp, messages::msg::ReportDataMsg};

/// Assert that the data received in the outbuf matches our expectations
pub fn assert_attr_report(received: &ReportDataMsg, expected: &[AttrResp]) {
    let mut index = 0;

    // We can't use assert_eq because it will also try to match data-version
    for inv_response in received.attr_reports.as_ref().unwrap().iter() {
        println!("Validating index {}", index);
        match expected[index] {
            AttrResp::Data(e_d) => match inv_response {
                AttrResp::Data(d) => {
                    // We don't match the data-version
                    assert_eq!(e_d.path, d.path);
                    assert_eq!(e_d.data, d.data);
                }
                _ => {
                    panic!("Invalid response, expected AttrRespIn::Data");
                }
            },
            AttrResp::Status(s) => assert_eq!(AttrResp::Status(s), inv_response),
        }
        println!("Index {} success", index);
        index += 1;
    }
    assert_eq!(index, expected.len());
}

// We have to hard-code this here, and it should match the tag
// of the 'data' part in AttrData
pub const ATTR_DATA_TAG_DATA: u8 = 2;

#[macro_export]
macro_rules! attr_data {
    ($endpoint:expr, $cluster:expr, $attr: expr, $data:expr) => {
        AttrResp::Data(AttrData {
            data_ver: None,
            path: AttrPath {
                endpoint: Some($endpoint),
                cluster: Some($cluster),
                attr: Some($attr as u16),
                ..Default::default()
            },
            data: EncodeValue::Tlv(TLVElement::new(TagType::Context(ATTR_DATA_TAG_DATA), $data)),
        })
    };
}

#[macro_export]
macro_rules! attr_data_path {
    ($path:expr, $data:expr) => {
        AttrResp::Data(AttrData {
            data_ver: None,
            path: AttrPath {
                endpoint: $path.endpoint,
                cluster: $path.cluster,
                attr: $path.leaf.map(|x| x as u16),
                ..Default::default()
            },
            data: EncodeValue::Tlv(TLVElement::new(TagType::Context(ATTR_DATA_TAG_DATA), $data)),
        })
    };
}

#[macro_export]
macro_rules! attr_status {
    ($path:expr, $status:expr) => {
        AttrResp::Status(AttrStatus::new($path, $status, 0))
    };
}
