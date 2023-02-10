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
    acl::{gen_noc_cat, AclEntry, AuthMode, Target},
    data_model::{
        objects::{AttrValue, EncodeValue, Privilege},
        system_model::access_control,
    },
    interaction_model::{
        core::{IMStatusCode, OpCode},
        messages::{
            ib::{AttrData, AttrPath, AttrResp, AttrStatus, ClusterPath, DataVersionFilter},
            msg::{ReadReq, ReportDataMsg, WriteReq},
        },
        messages::{msg, GenericPath},
    },
    tlv::{self, ElementType, FromTLV, TLVArray, TLVElement, TLVWriter, TagType},
    transport::session::NocCatIds,
};

use crate::{
    attr_data, attr_status,
    common::{
        attributes::*,
        echo_cluster::{self, ATTR_WRITE_DEFAULT_VALUE},
        im_engine::{ImEngine, ImInput},
    },
};

// Helper for handling Read Req sequences for this file
fn handle_read_reqs(
    im: &mut ImEngine,
    peer_node_id: u64,
    input: &[AttrPath],
    expected: &[AttrResp],
) {
    let mut out_buf = [0u8; 400];
    let received = gen_read_reqs_output(im, peer_node_id, input, None, &mut out_buf);
    assert_attr_report(&received, expected)
}

fn gen_read_reqs_output<'a>(
    im: &mut ImEngine,
    peer_node_id: u64,
    input: &[AttrPath],
    dataver_filters: Option<TLVArray<'a, DataVersionFilter>>,
    out_buf: &'a mut [u8],
) -> ReportDataMsg<'a> {
    let mut read_req = ReadReq::new(true).set_attr_requests(input);
    read_req.dataver_filters = dataver_filters;

    let mut input = ImInput::new(OpCode::ReadRequest, &read_req);
    input.set_peer_node_id(peer_node_id);

    let (_, out_buf) = im.process(&input, out_buf);

    tlv::print_tlv_list(out_buf);
    let root = tlv::get_root_node_struct(out_buf).unwrap();
    ReportDataMsg::from_tlv(&root).unwrap()
}

// Helper for handling Write Attribute sequences
fn handle_write_reqs(
    im: &mut ImEngine,
    peer_node_id: u64,
    peer_cat_ids: Option<&NocCatIds>,
    input: &[AttrData],
    expected: &[AttrStatus],
) {
    let mut out_buf = [0u8; 400];
    let write_req = WriteReq::new(false, input);

    let mut input = ImInput::new(OpCode::WriteRequest, &write_req);
    input.set_peer_node_id(peer_node_id);
    if let Some(cat_ids) = peer_cat_ids {
        input.set_cat_ids(cat_ids);
    }
    let (_, out_buf) = im.process(&input, &mut out_buf);

    tlv::print_tlv_list(out_buf);
    let root = tlv::get_root_node_struct(out_buf).unwrap();

    let mut index = 0;
    let response_iter = root
        .find_tag(msg::WriteRespTag::WriteResponses as u32)
        .unwrap()
        .confirm_array()
        .unwrap()
        .enter()
        .unwrap();
    for response in response_iter {
        println!("Validating index {}", index);
        let status = AttrStatus::from_tlv(&response).unwrap();
        assert_eq!(expected[index], status);
        println!("Index {} success", index);
        index += 1;
    }
    assert_eq!(index, expected.len());
}

#[test]
/// Ensure that wildcard read attributes don't include error response
/// and silently drop the data when access is not granted
fn wc_read_attribute() {
    let _ = env_logger::try_init();

    let wc_att1 = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let ep0_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let ep1_att1 = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );

    let peer = 98765;
    let mut im = ImEngine::new();

    // Test1: Empty Response as no ACL matches
    let input = &[AttrPath::new(&wc_att1)];
    let expected = &[];
    handle_read_reqs(&mut im, peer, input, expected);

    // Add ACL to allow our peer to only access endpoint 0
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    acl.add_target(Target::new(Some(0), None, None)).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test2: Only Single response as only single endpoint is allowed
    let input = &[AttrPath::new(&wc_att1)];
    let expected = &[attr_data!(ep0_att1, ElementType::U16(0x1234))];
    handle_read_reqs(&mut im, peer, input, expected);

    // Add ACL to allow our peer to only access endpoint 1
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    acl.add_target(Target::new(Some(1), None, None)).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test3: Both responses are valid
    let input = &[AttrPath::new(&wc_att1)];
    let expected = &[
        attr_data!(ep0_att1, ElementType::U16(0x1234)),
        attr_data!(ep1_att1, ElementType::U16(0x1234)),
    ];
    handle_read_reqs(&mut im, peer, input, expected);
}

#[test]
/// Ensure that exact read attribute includes error response
/// when access is not granted
fn exact_read_attribute() {
    let _ = env_logger::try_init();

    let wc_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let ep0_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );

    let peer = 98765;
    let mut im = ImEngine::new();

    // Test1: Unsupported Access error as no ACL matches
    let input = &[AttrPath::new(&wc_att1)];
    let expected = &[attr_status!(&ep0_att1, IMStatusCode::UnsupportedAccess)];
    handle_read_reqs(&mut im, peer, input, expected);

    // Add ACL to allow our peer to access any endpoint
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test2: Only Single response as only single endpoint is allowed
    let input = &[AttrPath::new(&wc_att1)];
    let expected = &[attr_data!(ep0_att1, ElementType::U16(0x1234))];
    handle_read_reqs(&mut im, peer, input, expected);
}

fn read_cluster_id_write_attr(im: &ImEngine, endpoint: u16) -> AttrValue {
    let node = im.dm.node.read().unwrap();
    let echo = node.get_cluster(endpoint, echo_cluster::ID).unwrap();

    echo.base()
        .read_attribute_raw(echo_cluster::Attributes::AttWrite as u16)
        .unwrap()
        .clone()
}

fn read_cluster_id_data_ver(im: &ImEngine, endpoint: u16) -> u32 {
    let node = im.dm.node.read().unwrap();
    let echo = node.get_cluster(endpoint, echo_cluster::ID).unwrap();

    echo.base().get_dataver()
}

#[test]
/// Ensure that an write attribute with a wildcard either performs the operation,
/// if allowed, or silently drops the request
fn wc_write_attribute() {
    let _ = env_logger::try_init();
    let val0 = 10;
    let val1 = 20;
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };
    let attr_data1 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val1);
    };

    let wc_att = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
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

    let input0 = &[AttrData::new(
        None,
        AttrPath::new(&wc_att),
        EncodeValue::Closure(&attr_data0),
    )];
    let input1 = &[AttrData::new(
        None,
        AttrPath::new(&wc_att),
        EncodeValue::Closure(&attr_data1),
    )];

    let peer = 98765;
    let mut im = ImEngine::new();

    // Test 1: Wildcard write to an attribute without permission should return
    // no error
    handle_write_reqs(&mut im, peer, None, input0, &[]);
    {
        let node = im.dm.node.read().unwrap();
        let echo = node.get_cluster(0, echo_cluster::ID).unwrap();
        assert_eq!(
            AttrValue::Uint16(ATTR_WRITE_DEFAULT_VALUE),
            *echo
                .base()
                .read_attribute_raw(echo_cluster::Attributes::AttWrite as u16)
                .unwrap()
        );
    }

    // Add ACL to allow our peer to access one endpoint
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    acl.add_target(Target::new(Some(0), None, None)).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test 2: Wildcard write to attributes will only return attributes
    // where the writes were successful
    handle_write_reqs(
        &mut im,
        peer,
        None,
        input0,
        &[AttrStatus::new(&ep0_att, IMStatusCode::Sucess, 0)],
    );
    assert_eq!(AttrValue::Uint16(val0), read_cluster_id_write_attr(&im, 0));
    assert_eq!(
        AttrValue::Uint16(ATTR_WRITE_DEFAULT_VALUE),
        read_cluster_id_write_attr(&im, 1)
    );

    // Add ACL to allow our peer to access another endpoint
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    acl.add_target(Target::new(Some(1), None, None)).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test 3: Wildcard write to attributes will return multiple attributes
    // where the writes were successful
    handle_write_reqs(
        &mut im,
        peer,
        None,
        input1,
        &[
            AttrStatus::new(&ep0_att, IMStatusCode::Sucess, 0),
            AttrStatus::new(&ep1_att, IMStatusCode::Sucess, 0),
        ],
    );
    assert_eq!(AttrValue::Uint16(val1), read_cluster_id_write_attr(&im, 0));
    assert_eq!(AttrValue::Uint16(val1), read_cluster_id_write_attr(&im, 1));
}

#[test]
/// Ensure that an write attribute without a wildcard returns an error when the
/// ACL disallows the access, and returns success once access is granted
fn exact_write_attribute() {
    let _ = env_logger::try_init();
    let val0 = 10;
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };

    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );

    let input = &[AttrData::new(
        None,
        AttrPath::new(&ep0_att),
        EncodeValue::Closure(&attr_data0),
    )];
    let expected_fail = &[AttrStatus::new(
        &ep0_att,
        IMStatusCode::UnsupportedAccess,
        0,
    )];
    let expected_success = &[AttrStatus::new(&ep0_att, IMStatusCode::Sucess, 0)];

    let peer = 98765;
    let mut im = ImEngine::new();

    // Test 1: Exact write to an attribute without permission should return
    // Unsupported Access Error
    handle_write_reqs(&mut im, peer, None, input, expected_fail);
    assert_eq!(
        AttrValue::Uint16(ATTR_WRITE_DEFAULT_VALUE),
        read_cluster_id_write_attr(&im, 0)
    );

    // Add ACL to allow our peer to access any endpoint
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test 1: Exact write to an attribute with permission should grant
    // access
    handle_write_reqs(&mut im, peer, None, input, expected_success);
    assert_eq!(AttrValue::Uint16(val0), read_cluster_id_write_attr(&im, 0));
}

#[test]
/// Ensure that an write attribute without a wildcard returns an error when the
/// ACL disallows the access, and returns success once access is granted to the CAT ID
/// The Accessor CAT version is one more than that in the ACL
fn exact_write_attribute_noc_cat() {
    let _ = env_logger::try_init();
    let val0 = 10;
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };

    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );

    let input = &[AttrData::new(
        None,
        AttrPath::new(&ep0_att),
        EncodeValue::Closure(&attr_data0),
    )];
    let expected_fail = &[AttrStatus::new(
        &ep0_att,
        IMStatusCode::UnsupportedAccess,
        0,
    )];
    let expected_success = &[AttrStatus::new(&ep0_att, IMStatusCode::Sucess, 0)];

    let peer = 98765;
    /* CAT in NOC is 1 more, in version, than that in ACL */
    let noc_cat = gen_noc_cat(0xABCD, 2);
    let cat_in_acl = gen_noc_cat(0xABCD, 1);
    let cat_ids = [noc_cat, 0, 0];
    let mut im = ImEngine::new();

    // Test 1: Exact write to an attribute without permission should return
    // Unsupported Access Error
    handle_write_reqs(&mut im, peer, Some(&cat_ids), input, expected_fail);
    assert_eq!(
        AttrValue::Uint16(ATTR_WRITE_DEFAULT_VALUE),
        read_cluster_id_write_attr(&im, 0)
    );

    // Add ACL to allow our peer to access any endpoint
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(cat_in_acl).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test 1: Exact write to an attribute with permission should grant
    // access
    handle_write_reqs(&mut im, peer, Some(&cat_ids), input, expected_success);
    assert_eq!(AttrValue::Uint16(val0), read_cluster_id_write_attr(&im, 0));
}

#[test]
/// Ensure that a write attribute with insufficient permissions is rejected
fn insufficient_perms_write() {
    let _ = env_logger::try_init();
    let val0 = 10;
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };
    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
    let input0 = &[AttrData::new(
        None,
        AttrPath::new(&ep0_att),
        EncodeValue::Closure(&attr_data0),
    )];

    let peer = 98765;
    let mut im = ImEngine::new();

    // Add ACL to allow our peer with only OPERATE permission
    let mut acl = AclEntry::new(1, Privilege::OPERATE, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    acl.add_target(Target::new(Some(0), None, None)).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test: Not enough permission should return error
    handle_write_reqs(
        &mut im,
        peer,
        None,
        input0,
        &[AttrStatus::new(
            &ep0_att,
            IMStatusCode::UnsupportedAccess,
            0,
        )],
    );
    assert_eq!(
        AttrValue::Uint16(ATTR_WRITE_DEFAULT_VALUE),
        read_cluster_id_write_attr(&im, 0)
    );
}

#[test]
/// Ensure that a write to the ACL attribute instantaneously grants permission
/// Here we have 2 ACLs, the first (basic_acl) allows access only to the ACL cluster
/// Then we execute a write attribute with 3 writes
///    - Write Attr to Echo Cluster (permission denied)
///    - Write Attr to ACL Cluster (allowed, this ACL also grants universal access)
///    - Write Attr to Echo Cluster again (successful this time)
fn write_with_runtime_acl_add() {
    let _ = env_logger::try_init();
    let peer = 98765;
    let mut im = ImEngine::new();

    let val0 = 10;
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };
    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
    let input0 = AttrData::new(
        None,
        AttrPath::new(&ep0_att),
        EncodeValue::Closure(&attr_data0),
    );

    // Create ACL to allow our peer ADMIN on everything
    let mut allow_acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    allow_acl.add_subject(peer).unwrap();

    let acl_att = GenericPath::new(
        Some(0),
        Some(access_control::ID),
        Some(access_control::Attributes::Acl as u32),
    );
    let acl_input = AttrData::new(
        None,
        AttrPath::new(&acl_att),
        EncodeValue::Value(&allow_acl),
    );

    // Create ACL that only allows write to the ACL Cluster
    let mut basic_acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    basic_acl.add_subject(peer).unwrap();
    basic_acl
        .add_target(Target::new(Some(0), Some(access_control::ID), None))
        .unwrap();
    im.acl_mgr.add(basic_acl).unwrap();

    // Test: deny write (with error), then ACL is added, then allow write
    handle_write_reqs(
        &mut im,
        peer,
        None,
        // write to echo-cluster attribute, write to acl attribute, write to echo-cluster attribute
        &[input0, acl_input, input0],
        &[
            AttrStatus::new(&ep0_att, IMStatusCode::UnsupportedAccess, 0),
            AttrStatus::new(&acl_att, IMStatusCode::Sucess, 0),
            AttrStatus::new(&ep0_att, IMStatusCode::Sucess, 0),
        ],
    );
    assert_eq!(AttrValue::Uint16(val0), read_cluster_id_write_attr(&im, 0));
}

#[test]
/// Data Version filtering should ignore the attributes that are filtered
/// - in case of wildcard reads
/// - in case of exact read attribute
fn test_read_data_ver() {
    // 1 Attr Read Requests
    // - wildcard endpoint, att1
    // - 2 responses are expected
    let _ = env_logger::try_init();
    let peer = 98765;
    let mut im = ImEngine::new();

    // Add ACL to allow our peer with only OPERATE permission
    let acl = AclEntry::new(1, Privilege::OPERATE, AuthMode::Case);
    im.acl_mgr.add(acl).unwrap();

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
    let mut out_buf = [0u8; 400];

    // Test 1: Simple read to retrieve the current Data Version of Cluster at Endpoint 0
    let received = gen_read_reqs_output(&mut im, peer, input, None, &mut out_buf);
    assert_attr_report(&received, expected);

    let data_ver_cluster_at_0 = received
        .attr_reports
        .as_ref()
        .unwrap()
        .get_index(0)
        .unwrap_data()
        .data_ver
        .unwrap();

    let dataver_filter = [DataVersionFilter {
        path: ClusterPath {
            node: None,
            endpoint: 0,
            cluster: echo_cluster::ID,
        },
        data_ver: data_ver_cluster_at_0,
    }];

    // Test 2: Add Dataversion filter for cluster at endpoint 0 only single entry should be retrieved
    let received = gen_read_reqs_output(
        &mut im,
        peer,
        input,
        Some(TLVArray::Slice(&dataver_filter)),
        &mut out_buf,
    );
    let expected_only_one = &[attr_data!(
        GenericPath::new(
            Some(1),
            Some(echo_cluster::ID),
            Some(echo_cluster::Attributes::Att1 as u32)
        ),
        ElementType::U16(0x1234)
    )];

    assert_attr_report(&received, expected_only_one);

    // Test 3: Exact read attribute
    let ep0_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let input = &[AttrPath::new(&ep0_att1)];
    let received = gen_read_reqs_output(
        &mut im,
        peer,
        input,
        Some(TLVArray::Slice(&dataver_filter)),
        &mut out_buf,
    );
    let expected_error = &[];

    assert_attr_report(&received, expected_error);
}

#[test]
/// - Write with the correct data version should go through
/// - Write with incorrect data version should fail with error
/// - Wildcard write with incorrect data version should be ignored
fn test_write_data_ver() {
    // 1 Attr Read Requests
    // - wildcard endpoint, att1
    // - 2 responses are expected
    let _ = env_logger::try_init();
    let peer = 98765;
    let mut im = ImEngine::new();

    // Add ACL to allow our peer with only OPERATE permission
    let acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    im.acl_mgr.add(acl).unwrap();

    let wc_ep_attwrite = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
    let ep0_attwrite = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );

    let val0 = 10u16;
    let val1 = 11u16;
    let attr_data0 = EncodeValue::Value(&val0);
    let attr_data1 = EncodeValue::Value(&val1);

    let initial_data_ver = read_cluster_id_data_ver(&im, 0);

    // Test 1: Write with correct dataversion should succeed
    let input_correct_dataver = &[AttrData::new(
        Some(initial_data_ver),
        AttrPath::new(&ep0_attwrite),
        attr_data0,
    )];
    handle_write_reqs(
        &mut im,
        peer,
        None,
        input_correct_dataver,
        &[AttrStatus::new(&ep0_attwrite, IMStatusCode::Sucess, 0)],
    );
    assert_eq!(AttrValue::Uint16(val0), read_cluster_id_write_attr(&im, 0));

    // Test 2: Write with incorrect dataversion should fail
    // Now the data version would have incremented due to the previous write
    let input_correct_dataver = &[AttrData::new(
        Some(initial_data_ver),
        AttrPath::new(&ep0_attwrite),
        attr_data1,
    )];
    handle_write_reqs(
        &mut im,
        peer,
        None,
        input_correct_dataver,
        &[AttrStatus::new(
            &ep0_attwrite,
            IMStatusCode::DataVersionMismatch,
            0,
        )],
    );
    assert_eq!(AttrValue::Uint16(val0), read_cluster_id_write_attr(&im, 0));

    // Test 3: Wildcard write with incorrect dataversion should ignore that cluster
    //   In this case, while the data version is correct for endpoint 0, the endpoint 1's
    //   data version would not match
    let new_data_ver = read_cluster_id_data_ver(&im, 0);

    let input_correct_dataver = &[AttrData::new(
        Some(new_data_ver),
        AttrPath::new(&wc_ep_attwrite),
        attr_data1,
    )];
    handle_write_reqs(
        &mut im,
        peer,
        None,
        input_correct_dataver,
        &[AttrStatus::new(&ep0_attwrite, IMStatusCode::Sucess, 0)],
    );
    assert_eq!(AttrValue::Uint16(val1), read_cluster_id_write_attr(&im, 0));

    assert_eq!(initial_data_ver + 1, new_data_ver);
}
