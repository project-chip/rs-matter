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

use core::num::NonZeroU8;

use rs_matter::acl::{gen_noc_cat, AclEntry, AuthMode, Target};
use rs_matter::data_model::{objects::Privilege, system_model::access_control};
use rs_matter::interaction_model::core::IMStatusCode;
use rs_matter::interaction_model::messages::ib::{
    AttrPath, AttrStatus, ClusterPath, DataVersionFilter,
};
use rs_matter::interaction_model::messages::GenericPath;

use crate::common::e2e::im::attributes::{TestAttrData, TestAttrResp};
use crate::common::e2e::im::echo_cluster::ATTR_WRITE_DEFAULT_VALUE;
use crate::common::e2e::im::{echo_cluster, ReplyProcessor, TestReadReq, TestReportDataMsg};
use crate::common::e2e::tlv::TLVTest;
use crate::common::e2e::{ImEngine, IM_ENGINE_PEER_ID};
use crate::common::init_env_logger;
use crate::{attr_data, attr_data_path, attr_status};

const FAB_1: NonZeroU8 = match NonZeroU8::new(1) {
    Some(f) => f,
    None => unreachable!(),
};

#[test]
/// Ensure that wildcard read attributes don't include error response
/// and silently drop the data when access is not granted
fn wc_read_attribute() {
    init_env_logger();

    let wc_att1 = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );
    let ep0_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );
    let ep1_att1 = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );

    let im = ImEngine::new_default();
    let handler = im.handler();

    // Test1: Empty Response as no ACL matches
    im.handle_read_reqs(&handler, &[AttrPath::new(&wc_att1)], &[]);

    // Add ACL to allow our peer to only access endpoint 0
    let mut acl = AclEntry::new(FAB_1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(IM_ENGINE_PEER_ID).unwrap();
    acl.add_target(Target::new(Some(0), None, None)).unwrap();
    im.matter.acl_mgr.borrow_mut().add(acl).unwrap();

    // Test2: Only Single response as only single endpoint is allowed
    im.handle_read_reqs(
        &handler,
        &[AttrPath::new(&wc_att1)],
        &[TestAttrResp::data(&ep0_att1, &0x1234u16)],
    );

    // Add ACL to allow our peer to also access endpoint 1
    let mut acl = AclEntry::new(FAB_1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(IM_ENGINE_PEER_ID).unwrap();
    acl.add_target(Target::new(Some(1), None, None)).unwrap();
    im.matter.acl_mgr.borrow_mut().add(acl).unwrap();

    // Test3: Both responses are valid
    im.handle_read_reqs(
        &handler,
        &[AttrPath::new(&wc_att1)],
        &[
            TestAttrResp::data(&ep0_att1, &0x1234u16),
            TestAttrResp::data(&ep1_att1, &0x1234u16),
        ],
    );
}

#[test]
/// Ensure that exact read attribute includes error response
/// when access is not granted
fn exact_read_attribute() {
    init_env_logger();

    let wc_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );

    let im = ImEngine::new_default();
    let handler = im.handler();

    // Test1: Unsupported Access error as no ACL matches
    let input = &[AttrPath::new(&wc_att1)];
    let expected = &[attr_status!(&wc_att1, IMStatusCode::UnsupportedAccess)];
    im.handle_read_reqs(&handler, input, expected);

    // Add ACL to allow our peer to access any endpoint
    let mut acl = AclEntry::new(FAB_1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(IM_ENGINE_PEER_ID).unwrap();
    im.matter.acl_mgr.borrow_mut().add(acl).unwrap();

    // Test2: Only Single response as only single endpoint is allowed
    let input = &[AttrPath::new(&wc_att1)];
    let expected = &[attr_data_path!(wc_att1, Some(&0x1234u16))];
    im.handle_read_reqs(&handler, input, expected);
}

#[test]
/// Ensure that an write attribute with a wildcard either performs the operation,
/// if allowed, or silently drops the request
fn wc_write_attribute() {
    init_env_logger();
    let val0 = 10;
    let val1 = 20;

    let wc_att = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let ep1_att = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );

    let input0 = &[TestAttrData::new(None, AttrPath::new(&wc_att), &val0 as _)];
    let input1 = &[TestAttrData::new(None, AttrPath::new(&wc_att), &val1 as _)];

    let im = ImEngine::new_default();
    let handler = im.handler();

    // Test 1: Wildcard write to an attribute without permission should return
    // no error
    im.handle_write_reqs(&handler, input0, &[]);
    assert_eq!(
        ATTR_WRITE_DEFAULT_VALUE,
        handler.echo_cluster(0).att_write.get()
    );

    // Add ACL to allow our peer to access one endpoint
    let mut acl = AclEntry::new(FAB_1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(IM_ENGINE_PEER_ID).unwrap();
    acl.add_target(Target::new(Some(0), None, None)).unwrap();
    im.matter.acl_mgr.borrow_mut().add(acl).unwrap();

    // Test 2: Wildcard write to attributes will only return attributes
    // where the writes were successful
    im.handle_write_reqs(
        &handler,
        input0,
        &[AttrStatus::new(&ep0_att, IMStatusCode::Success, 0)],
    );
    assert_eq!(val0, handler.echo_cluster(0).att_write.get());
    assert_eq!(
        ATTR_WRITE_DEFAULT_VALUE,
        handler.echo_cluster(1).att_write.get()
    );

    // Add ACL to allow our peer to access another endpoint
    let mut acl = AclEntry::new(FAB_1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(IM_ENGINE_PEER_ID).unwrap();
    acl.add_target(Target::new(Some(1), None, None)).unwrap();
    im.matter.acl_mgr.borrow_mut().add(acl).unwrap();

    // Test 3: Wildcard write to attributes will return multiple attributes
    // where the writes were successful
    im.handle_write_reqs(
        &handler,
        input1,
        &[
            AttrStatus::new(&ep0_att, IMStatusCode::Success, 0),
            AttrStatus::new(&ep1_att, IMStatusCode::Success, 0),
        ],
    );
    assert_eq!(val1, handler.echo_cluster(0).att_write.get());
    assert_eq!(val1, handler.echo_cluster(1).att_write.get());
}

#[test]
/// Ensure that an write attribute without a wildcard returns an error when the
/// ACL disallows the access, and returns success once access is granted
fn exact_write_attribute() {
    init_env_logger();
    let val0 = 10;

    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );

    let input = &[TestAttrData::new(None, AttrPath::new(&ep0_att), &val0 as _)];
    let expected_fail = &[AttrStatus::new(
        &ep0_att,
        IMStatusCode::UnsupportedAccess,
        0,
    )];
    let expected_success = &[AttrStatus::new(&ep0_att, IMStatusCode::Success, 0)];

    let im = ImEngine::new_default();
    let handler = im.handler();

    // Test 1: Exact write to an attribute without permission should return
    // Unsupported Access Error
    im.handle_write_reqs(&handler, input, expected_fail);
    assert_eq!(
        ATTR_WRITE_DEFAULT_VALUE,
        handler.echo_cluster(0).att_write.get()
    );

    // Add ACL to allow our peer to access any endpoint
    let mut acl = AclEntry::new(FAB_1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(IM_ENGINE_PEER_ID).unwrap();
    im.matter.acl_mgr.borrow_mut().add(acl).unwrap();

    // Test 1: Exact write to an attribute with permission should grant
    // access
    im.handle_write_reqs(&handler, input, expected_success);
    assert_eq!(val0, handler.echo_cluster(0).att_write.get());
}

#[test]
/// Ensure that an write attribute without a wildcard returns an error when the
/// ACL disallows the access, and returns success once access is granted to the CAT ID
/// The Accessor CAT version is one more than that in the ACL
fn exact_write_attribute_noc_cat() {
    init_env_logger();
    let val0 = 10;

    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );

    let input = &[TestAttrData::new(None, AttrPath::new(&ep0_att), &val0 as _)];
    let expected_fail = &[AttrStatus::new(
        &ep0_att,
        IMStatusCode::UnsupportedAccess,
        0,
    )];
    let expected_success = &[AttrStatus::new(&ep0_att, IMStatusCode::Success, 0)];

    /* CAT in NOC is 1 more, in version, than that in ACL */
    let noc_cat = gen_noc_cat(0xABCD, 2);
    let cat_in_acl = gen_noc_cat(0xABCD, 1);
    let cat_ids = [noc_cat, 0, 0];
    let im = ImEngine::new(cat_ids);
    let handler = im.handler();

    // Test 1: Exact write to an attribute without permission should return
    // Unsupported Access Error
    im.handle_write_reqs(&handler, input, expected_fail);
    assert_eq!(
        ATTR_WRITE_DEFAULT_VALUE,
        handler.echo_cluster(0).att_write.get()
    );

    // Add ACL to allow our peer to access any endpoint
    let mut acl = AclEntry::new(FAB_1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject_catid(cat_in_acl).unwrap();
    im.matter.acl_mgr.borrow_mut().add(acl).unwrap();

    // Test 1: Exact write to an attribute with permission should grant
    // access
    im.handle_write_reqs(&handler, input, expected_success);
    assert_eq!(val0, handler.echo_cluster(0).att_write.get());
}

#[test]
/// Ensure that a write attribute with insufficient permissions is rejected
fn insufficient_perms_write() {
    init_env_logger();
    let val0 = 10;
    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let input0 = &[TestAttrData::new(None, AttrPath::new(&ep0_att), &val0 as _)];

    let im = ImEngine::new_default();
    let handler = im.handler();

    // Add ACL to allow our peer with only OPERATE permission
    let mut acl = AclEntry::new(FAB_1, Privilege::OPERATE, AuthMode::Case);
    acl.add_subject(IM_ENGINE_PEER_ID).unwrap();
    acl.add_target(Target::new(Some(0), None, None)).unwrap();
    im.matter.acl_mgr.borrow_mut().add(acl).unwrap();

    // Test: Not enough permission should return error
    im.handle_write_reqs(
        &handler,
        input0,
        &[AttrStatus::new(
            &ep0_att,
            IMStatusCode::UnsupportedAccess,
            0,
        )],
    );
    assert_eq!(
        ATTR_WRITE_DEFAULT_VALUE,
        handler.echo_cluster(0).att_write.get()
    );
}

/// Disabling this test as it conflicts with another part of the spec.
///
/// The spec expects that a single write request like DeleteList + AddItem
/// should cause all ACLs of that fabric to be deleted and the new one to be added
///
/// This is in conflict with the immediate-effect expectation of ACL: an ACL
/// write should instantaneously update the ACL so that immediate next WriteAttribute
/// *in the same WriteRequest* should see that effect.
///
/// This test validates the immediate effect expectation of ACL, but that is disabled
/// since ecosystems routinely send DeleteList+AddItem, so we support that over this.
#[ignore]
#[test]
/// Ensure that a write to the ACL attribute instantaneously grants permission
/// Here we have 2 ACLs, the first (basic_acl) allows access only to the ACL cluster
/// Then we execute a write attribute with 3 writes
///    - Write Attr to Echo Cluster (permission denied)
///    - Write Attr to ACL Cluster (allowed, this ACL also grants universal access)
///    - Write Attr to Echo Cluster again (successful this time)
fn write_with_runtime_acl_add() {
    init_env_logger();

    let im = ImEngine::new_default();
    let handler = im.handler();

    let val0 = 10;
    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let input0 = TestAttrData::new(None, AttrPath::new(&ep0_att), &val0 as _);

    // Create ACL to allow our peer ADMIN on everything
    let mut allow_acl = AclEntry::new(FAB_1, Privilege::ADMIN, AuthMode::Case);
    allow_acl.add_subject(IM_ENGINE_PEER_ID).unwrap();

    let acl_att = GenericPath::new(
        Some(0),
        Some(access_control::ID),
        Some(access_control::AttributesDiscriminants::Acl as u32),
    );
    let acl_input = TestAttrData::new(None, AttrPath::new(&acl_att), &allow_acl);

    // Create ACL that only allows write to the ACL Cluster
    let mut basic_acl = AclEntry::new(FAB_1, Privilege::ADMIN, AuthMode::Case);
    basic_acl.add_subject(IM_ENGINE_PEER_ID).unwrap();
    basic_acl
        .add_target(Target::new(Some(0), Some(access_control::ID), None))
        .unwrap();
    im.matter.acl_mgr.borrow_mut().add(basic_acl).unwrap();

    // Test: deny write (with error), then ACL is added, then allow write
    im.handle_write_reqs(
        &handler,
        // write to echo-cluster attribute, write to acl attribute, write to echo-cluster attribute
        &[input0.clone(), acl_input, input0],
        &[
            AttrStatus::new(&ep0_att, IMStatusCode::UnsupportedAccess, 0),
            AttrStatus::new(&acl_att, IMStatusCode::Success, 0),
            AttrStatus::new(&ep0_att, IMStatusCode::Success, 0),
        ],
    );
    assert_eq!(val0, handler.echo_cluster(0).att_write.get());
}

#[test]
/// Data Version filtering should ignore the attributes that are filtered
/// - in case of wildcard reads
/// - in case of exact read attribute
fn test_read_data_ver() {
    // 1 Attr Read Requests
    // - wildcard endpoint, att1
    // - 2 responses are expected
    init_env_logger();

    let im = ImEngine::new_default();
    let handler = im.handler();

    // Add ACL to allow our peer with only OPERATE permission
    let acl = AclEntry::new(FAB_1, Privilege::OPERATE, AuthMode::Case);
    im.matter.acl_mgr.borrow_mut().add(acl).unwrap();

    let wc_ep_att1 = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );
    let input = &[AttrPath::new(&wc_ep_att1)];

    let expected = &[
        attr_data!(
            0,
            echo_cluster::ID,
            echo_cluster::AttributesDiscriminants::Att1,
            Some(&0x1234u16)
        ),
        attr_data!(
            1,
            echo_cluster::ID,
            echo_cluster::AttributesDiscriminants::Att1,
            Some(&0x1234u16)
        ),
    ];

    // Test 1: Simple read without any data version filters
    im.test_one(&handler, TLVTest::read_attrs(input, expected));

    let data_ver_cluster_at_0 = handler.echo_cluster(0).data_ver.get();

    let dataver_filter = &[DataVersionFilter {
        path: ClusterPath {
            node: None,
            endpoint: 0,
            cluster: echo_cluster::ID,
        },
        data_ver: data_ver_cluster_at_0,
    }];

    // Test 2: Add Dataversion filter for cluster at endpoint 0 only single entry should be retrieved
    let expected_only_one = &[attr_data!(
        1,
        echo_cluster::ID,
        echo_cluster::AttributesDiscriminants::Att1,
        Some(&0x1234u16)
    )];

    im.test_one(
        &handler,
        TLVTest::read(
            TestReadReq {
                dataver_filters: Some(dataver_filter),
                ..TestReadReq::reqs(input)
            },
            TestReportDataMsg::reports(expected_only_one),
            ReplyProcessor::remove_attr_dataver,
        ),
    );

    // Test 3: Exact read attribute
    let ep0_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );
    let input = &[AttrPath::new(&ep0_att1)];
    im.test_one(
        &handler,
        TLVTest::read(
            TestReadReq {
                dataver_filters: Some(dataver_filter),
                ..TestReadReq::reqs(input)
            },
            TestReportDataMsg::reports(&[]),
            ReplyProcessor::none,
        ),
    );
}

#[test]
/// - Write with the correct data version should go through
/// - Write with incorrect data version should fail with error
/// - Wildcard write with incorrect data version should be ignored
fn test_write_data_ver() {
    // 1 Attr Read Requests
    // - wildcard endpoint, att1
    // - 2 responses are expected
    init_env_logger();

    let im = ImEngine::new_default();
    let handler = im.handler();

    // Add ACL to allow our peer with only OPERATE permission
    let acl = AclEntry::new(FAB_1, Privilege::ADMIN, AuthMode::Case);
    im.matter.acl_mgr.borrow_mut().add(acl).unwrap();

    let wc_ep_attwrite = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let ep0_attwrite = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );

    let val0 = 10u16;
    let val1 = 11u16;

    let initial_data_ver = handler.echo_cluster(0).data_ver.get();

    // Test 1: Write with correct dataversion should succeed
    let input_correct_dataver = &[TestAttrData::new(
        Some(initial_data_ver),
        AttrPath::new(&ep0_attwrite),
        &val0 as _,
    )];
    im.handle_write_reqs(
        &handler,
        input_correct_dataver,
        &[AttrStatus::new(&ep0_attwrite, IMStatusCode::Success, 0)],
    );
    assert_eq!(val0, handler.echo_cluster(0).att_write.get());

    // Test 2: Write with incorrect dataversion should fail
    // Now the data version would have incremented due to the previous write
    let input_correct_dataver = &[TestAttrData::new(
        Some(initial_data_ver),
        AttrPath::new(&ep0_attwrite),
        &val1 as _,
    )];
    im.handle_write_reqs(
        &handler,
        input_correct_dataver,
        &[AttrStatus::new(
            &ep0_attwrite,
            IMStatusCode::DataVersionMismatch,
            0,
        )],
    );
    assert_eq!(val0, handler.echo_cluster(0).att_write.get());

    // Test 3: Wildcard write with incorrect dataversion should ignore that cluster
    //   In this case, while the data version is correct for endpoint 0, the endpoint 1's
    //   data version would not match
    let new_data_ver = handler.echo_cluster(0).data_ver.get();

    let input_correct_dataver = &[TestAttrData::new(
        Some(new_data_ver),
        AttrPath::new(&wc_ep_attwrite),
        &val1 as _,
    )];
    im.handle_write_reqs(
        &handler,
        input_correct_dataver,
        &[AttrStatus::new(&ep0_attwrite, IMStatusCode::Success, 0)],
    );
    assert_eq!(val1, handler.echo_cluster(0).att_write.get());

    assert_eq!(initial_data_ver + 1, new_data_ver);
}
