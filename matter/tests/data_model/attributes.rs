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
    data_model::{
        cluster_on_off,
        core::DataModel,
        objects::{AttrValue, EncodeValue, GlobalElements},
    },
    interaction_model::{
        core::{IMStatusCode, OpCode},
        messages::GenericPath,
        messages::{
            ib::{AttrData, AttrPath, AttrResp, AttrStatus},
            msg::{ReadReq, ReportDataMsg, WriteReq, WriteResp},
        },
    },
    tlv::{self, ElementType, FromTLV, TLVElement, TLVList, TLVWriter, TagType, ToTLV},
    utils::writebuf::WriteBuf,
};

use crate::{
    attr_data, attr_status,
    common::{attributes::*, echo_cluster, im_engine::im_engine},
};

fn handle_read_reqs(input: &[AttrPath], expected: &[AttrResp]) {
    let mut out_buf = [0u8; 400];
    let received = gen_read_reqs_output(input, &mut out_buf);
    assert_attr_report(&received, expected)
}

// Helper for handling Read Req sequences
fn gen_read_reqs_output<'a>(input: &[AttrPath], out_buf: &'a mut [u8]) -> ReportDataMsg<'a> {
    let mut buf = [0u8; 400];
    let buf_len = buf.len();
    let mut wb = WriteBuf::new(&mut buf, buf_len);
    let mut tw = TLVWriter::new(&mut wb);

    let read_req = ReadReq::new(true).set_attr_requests(input);
    read_req.to_tlv(&mut tw, TagType::Anonymous).unwrap();

    let (_, _, out_buf) = im_engine(OpCode::ReadRequest, wb.as_borrow_slice(), out_buf);
    tlv::print_tlv_list(out_buf);
    let root = tlv::get_root_node_struct(out_buf).unwrap();
    ReportDataMsg::from_tlv(&root).unwrap()
}

// Helper for handling Write Attribute sequences
fn handle_write_reqs(input: &[AttrData], expected: &[AttrStatus]) -> DataModel {
    let mut buf = [0u8; 400];
    let mut out_buf = [0u8; 400];

    let buf_len = buf.len();
    let mut wb = WriteBuf::new(&mut buf, buf_len);
    let mut tw = TLVWriter::new(&mut wb);

    let write_req = WriteReq::new(false, input);
    write_req.to_tlv(&mut tw, TagType::Anonymous).unwrap();

    let (dm, _, out_buf) = im_engine(OpCode::WriteRequest, wb.as_borrow_slice(), &mut out_buf);
    let root = tlv::get_root_node_struct(out_buf).unwrap();
    let response = WriteResp::from_tlv(&root).unwrap();
    assert_eq!(response.write_responses, expected);

    dm
}

#[test]
fn test_read_success() {
    // 3 Attr Read Requests
    // - first on endpoint 0, att1
    // - second on endpoint 1, att2
    // - third on endpoint 1, attcustom a custom attribute
    let _ = env_logger::try_init();

    let ep0_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let ep1_att2 = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att2 as u32),
    );
    let ep1_attcustom = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttCustom as u32),
    );
    let input = &[
        AttrPath::new(&ep0_att1),
        AttrPath::new(&ep1_att2),
        AttrPath::new(&ep1_attcustom),
    ];
    let expected = &[
        attr_data!(ep0_att1, ElementType::U16(0x1234)),
        attr_data!(ep1_att2, ElementType::U16(0x5678)),
        attr_data!(
            ep1_attcustom,
            ElementType::U32(echo_cluster::ATTR_CUSTOM_VALUE)
        ),
    ];
    handle_read_reqs(input, expected);
}

#[test]
fn test_read_unsupported_fields() {
    // 6 reads
    // - endpoint doesn't exist - UnsupportedEndpoint
    // - cluster doesn't exist - UnsupportedCluster
    // - cluster doesn't exist and endpoint is wildcard - Silently ignore
    // - attribute doesn't exist - UnsupportedAttribute
    // - attribute doesn't exist and endpoint is wildcard - Silently ignore
    // - attribute doesn't exist and cluster is wildcard - Silently ignore
    let _ = env_logger::try_init();

    let invalid_endpoint = GenericPath::new(
        Some(2),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let invalid_cluster = GenericPath::new(
        Some(0),
        Some(0x1234),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let invalid_cluster_wc_endpoint = GenericPath::new(
        None,
        Some(0x1234),
        Some(echo_cluster::Attributes::AttCustom as u32),
    );
    let invalid_attribute = GenericPath::new(Some(0), Some(echo_cluster::ID), Some(0x1234));
    let invalid_attribute_wc_endpoint =
        GenericPath::new(None, Some(echo_cluster::ID), Some(0x1234));
    let invalid_attribute_wc_cluster = GenericPath::new(Some(0), None, Some(0x1234));
    let input = &[
        AttrPath::new(&invalid_endpoint),
        AttrPath::new(&invalid_cluster),
        AttrPath::new(&invalid_cluster_wc_endpoint),
        AttrPath::new(&invalid_attribute),
        AttrPath::new(&invalid_attribute_wc_endpoint),
        AttrPath::new(&invalid_attribute_wc_cluster),
    ];

    let expected = &[
        attr_status!(&invalid_endpoint, IMStatusCode::UnsupportedEndpoint),
        attr_status!(&invalid_cluster, IMStatusCode::UnsupportedCluster),
        attr_status!(&invalid_attribute, IMStatusCode::UnsupportedAttribute),
    ];
    handle_read_reqs(input, expected);
}

#[test]
fn test_read_wc_endpoint_all_have_clusters() {
    // 1 Attr Read Requests
    // - wildcard endpoint, att1
    // - 2 responses are expected
    let _ = env_logger::try_init();

    let wc_ep_att1 = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let input = &[AttrPath::new(&wc_ep_att1)];

    let expected = &[
        attr_data!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::Att1 as u32)
            ),
            ElementType::U16(0x1234)
        ),
        attr_data!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::Att1 as u32)
            ),
            ElementType::U16(0x1234)
        ),
    ];
    handle_read_reqs(input, expected);
}

#[test]
fn test_read_wc_endpoint_only_1_has_cluster() {
    // 1 Attr Read Requests
    // - wildcard endpoint, on/off Cluster OnOff Attribute
    // - 1 response are expected
    let _ = env_logger::try_init();

    let wc_ep_onoff = GenericPath::new(
        None,
        Some(cluster_on_off::ID),
        Some(cluster_on_off::Attributes::OnOff as u32),
    );
    let input = &[AttrPath::new(&wc_ep_onoff)];

    let expected = &[attr_data!(
        GenericPath::new(
            Some(1),
            Some(cluster_on_off::ID),
            Some(cluster_on_off::Attributes::OnOff as u32)
        ),
        ElementType::False
    )];
    handle_read_reqs(input, expected);
}

fn get_tlvs<'a>(buf: &'a mut [u8], data: &[u16]) -> TLVElement<'a> {
    let buf_len = buf.len();
    let mut wb = WriteBuf::new(buf, buf_len);
    let mut tw = TLVWriter::new(&mut wb);
    let _ = tw.start_array(TagType::Context(2));
    for e in data {
        let _ = tw.u16(TagType::Anonymous, *e);
    }
    let _ = tw.end_container();
    let tlv_array = TLVList::new(wb.as_slice()).iter().next().unwrap();
    tlv_array
}

#[test]
fn test_read_wc_endpoint_wc_attribute() {
    // 1 Attr Read Request
    // - wildcard endpoint, wildcard attribute
    // - 8 responses are expected, 1+3 attributes on endpoint 0, 1+3 on endpoint 1
    let _ = env_logger::try_init();
    let wc_ep_wc_attr = GenericPath::new(None, Some(echo_cluster::ID), None);
    let input = &[AttrPath::new(&wc_ep_wc_attr)];

    let mut buf = [0u8; 100];
    let attr_list_tlvs = get_tlvs(
        &mut buf,
        &[
            GlobalElements::AttributeList as u16,
            echo_cluster::Attributes::Att1 as u16,
            echo_cluster::Attributes::Att2 as u16,
            echo_cluster::Attributes::AttWrite as u16,
            echo_cluster::Attributes::AttCustom as u16,
        ],
    );

    let expected = &[
        attr_data!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(GlobalElements::AttributeList as u32),
            ),
            attr_list_tlvs.get_element_type()
        ),
        attr_data!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::Att1 as u32),
            ),
            ElementType::U16(0x1234)
        ),
        attr_data!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::Att2 as u32),
            ),
            ElementType::U16(0x5678)
        ),
        attr_data!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::AttCustom as u32),
            ),
            ElementType::U32(echo_cluster::ATTR_CUSTOM_VALUE)
        ),
        attr_data!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(GlobalElements::AttributeList as u32),
            ),
            attr_list_tlvs.get_element_type()
        ),
        attr_data!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::Att1 as u32),
            ),
            ElementType::U16(0x1234)
        ),
        attr_data!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::Att2 as u32),
            ),
            ElementType::U16(0x5678)
        ),
        attr_data!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::AttCustom as u32),
            ),
            ElementType::U32(echo_cluster::ATTR_CUSTOM_VALUE)
        ),
    ];
    handle_read_reqs(input, expected);
}

#[test]
fn test_write_success() {
    // 2 Attr Write Request
    // - first on endpoint 0, AttWrite
    // - second on endpoint 1, AttWrite
    let val0 = 10;
    let val1 = 15;
    let _ = env_logger::try_init();
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };
    let attr_data1 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val1);
    };

    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
    let ep1_att = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );

    let input = &[
        AttrData::new(
            None,
            AttrPath::new(&ep0_att),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&ep1_att),
            EncodeValue::Closure(&attr_data1),
        ),
    ];
    let expected = &[
        AttrStatus::new(&ep0_att, IMStatusCode::Sucess, 0),
        AttrStatus::new(&ep1_att, IMStatusCode::Sucess, 0),
    ];

    let dm = handle_write_reqs(input, expected);
    let node = dm.node.read().unwrap();
    let echo = node.get_cluster(0, echo_cluster::ID).unwrap();
    assert_eq!(
        AttrValue::Uint16(val0),
        *echo
            .base()
            .read_attribute_raw(echo_cluster::Attributes::AttWrite as u16)
            .unwrap()
    );
    let echo = node.get_cluster(1, echo_cluster::ID).unwrap();
    assert_eq!(
        AttrValue::Uint16(val1),
        *echo
            .base()
            .read_attribute_raw(echo_cluster::Attributes::AttWrite as u16)
            .unwrap()
    );
}

#[test]
fn test_write_wc_endpoint() {
    // 1 Attr Write Request
    // - wildcard endpoint, AttWrite
    let val0 = 10;
    let _ = env_logger::try_init();
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };

    let ep_att = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
    let input = &[AttrData::new(
        None,
        AttrPath::new(&ep_att),
        EncodeValue::Closure(&attr_data0),
    )];

    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );

    let ep1_att = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
    let expected = &[
        AttrStatus::new(&ep0_att, IMStatusCode::Sucess, 0),
        AttrStatus::new(&ep1_att, IMStatusCode::Sucess, 0),
    ];

    let dm = handle_write_reqs(input, expected);
    assert_eq!(
        AttrValue::Uint16(val0),
        dm.read_attribute_raw(
            0,
            echo_cluster::ID,
            echo_cluster::Attributes::AttWrite as u16
        )
        .unwrap()
    );
    assert_eq!(
        AttrValue::Uint16(val0),
        dm.read_attribute_raw(
            0,
            echo_cluster::ID,
            echo_cluster::Attributes::AttWrite as u16
        )
        .unwrap()
    );
}

#[test]
fn test_write_unsupported_fields() {
    // 7 writes
    // - endpoint doesn't exist - UnsupportedEndpoint
    // - cluster doesn't exist - UnsupportedCluster
    // - attribute doesn't exist - UnsupportedAttribute
    // - cluster doesn't exist and endpoint is wildcard - Silently ignore
    // - attribute doesn't exist and endpoint is wildcard - Silently ignore
    // - cluster is wildcard - Cluster cannot be wildcard - UnsupportedCluster
    // - attribute is wildcard - Attribute cannot be wildcard - UnsupportedAttribute
    let _ = env_logger::try_init();

    let val0 = 50;
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };

    let invalid_endpoint = GenericPath::new(
        Some(4),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
    let invalid_cluster = GenericPath::new(
        Some(0),
        Some(0x1234),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
    let invalid_attribute = GenericPath::new(Some(0), Some(echo_cluster::ID), Some(0x1234));
    let wc_endpoint_invalid_cluster = GenericPath::new(
        None,
        Some(0x1234),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
    let wc_endpoint_invalid_attribute =
        GenericPath::new(None, Some(echo_cluster::ID), Some(0x1234));
    let wc_cluster = GenericPath::new(
        Some(0),
        None,
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
    let wc_attribute = GenericPath::new(Some(0), Some(echo_cluster::ID), None);

    let input = &[
        AttrData::new(
            None,
            AttrPath::new(&invalid_endpoint),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&invalid_cluster),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&invalid_attribute),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&wc_endpoint_invalid_cluster),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&wc_endpoint_invalid_attribute),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&wc_cluster),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&wc_attribute),
            EncodeValue::Closure(&attr_data0),
        ),
    ];
    let expected = &[
        AttrStatus::new(&invalid_endpoint, IMStatusCode::UnsupportedEndpoint, 0),
        AttrStatus::new(&invalid_cluster, IMStatusCode::UnsupportedCluster, 0),
        AttrStatus::new(&invalid_attribute, IMStatusCode::UnsupportedAttribute, 0),
        AttrStatus::new(&wc_cluster, IMStatusCode::UnsupportedCluster, 0),
        AttrStatus::new(&wc_attribute, IMStatusCode::UnsupportedAttribute, 0),
    ];
    let dm = handle_write_reqs(input, expected);
    assert_eq!(
        AttrValue::Uint16(echo_cluster::ATTR_WRITE_DEFAULT_VALUE),
        dm.read_attribute_raw(
            0,
            echo_cluster::ID,
            echo_cluster::Attributes::AttWrite as u16
        )
        .unwrap()
    );
}
