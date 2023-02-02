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

use matter::{
    interaction_model::{messages::ib::AttrResp, messages::msg::ReportDataMsg},
    tlv::{TLVElement, TLVList, TLVWriter, TagType, ToTLV},
    utils::writebuf::WriteBuf,
};

/// Assert that the data received in the outbuf matches our expectations
pub fn __assert_attr_report(received: &ReportDataMsg, expected: &[AttrResp], skip_data: bool) {
    let mut index = 0;

    // We can't use assert_eq because it will also try to match data-version
    for inv_response in received.attr_reports.as_ref().unwrap().iter() {
        println!("Validating index {}", index);
        match expected[index] {
            AttrResp::Data(e_d) => match inv_response {
                AttrResp::Data(d) => {
                    // We don't match the data-version
                    assert_eq!(e_d.path, d.path);
                    if !skip_data {
                        assert_eq!(e_d.data, d.data);
                    }
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

pub fn assert_attr_report(received: &ReportDataMsg, expected: &[AttrResp]) {
    __assert_attr_report(received, expected, false)
}

pub fn assert_attr_report_skip_data(received: &ReportDataMsg, expected: &[AttrResp]) {
    __assert_attr_report(received, expected, true)
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

pub struct TLVHolder {
    buf: [u8; 100],
    used_len: usize,
}

impl TLVHolder {
    pub fn new_array<'a, T, I>(ctx_tag: u8, data: I) -> Self
    where
        T: ToTLV + 'a,
        I: IntoIterator<Item = &'a T>,
    {
        let mut s = Self {
            buf: [0; 100],
            used_len: 0,
        };
        let mut wb = WriteBuf::new(&mut s.buf);
        let mut tw = TLVWriter::new(&mut wb);
        let _ = tw.start_array(TagType::Context(ctx_tag));
        for e in data {
            let _ = e.to_tlv(&mut tw, TagType::Anonymous);
        }
        let _ = tw.end_container();

        s.used_len = wb.as_slice().len();
        s
    }

    pub fn to_tlv(&self) -> TLVElement {
        let s = &self.buf[..self.used_len];
        TLVList::new(s).iter().next().unwrap()
    }
}
