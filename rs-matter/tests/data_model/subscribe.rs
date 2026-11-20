/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

use rs_matter::basic_info::SUBSCRIPTION_BUFFER_SIZE;
use rs_matter::dm::clusters::app::on_off;
use rs_matter::im::{AttrPath, AttrStatus, ClusterPath, DataVersionFilter, EventPath, GenericPath};
use rs_matter::im::{IMStatusCode, OpCode, PROTO_ID_INTERACTION_MODEL};
use rs_matter::im::{StatusResp, SubscribeResp};
use rs_matter::tlv::{TLVTag, ToTLV};
use rs_matter::transport::exchange::MessageMeta;
use rs_matter::utils::storage::WriteBuf;

use crate::common::e2e::im::attributes::TestAttrData;
use crate::common::e2e::im::{
    echo_cluster, ReplyProcessor, Setup, TestReportDataMsg, TestSubscribeReq,
};
use crate::common::e2e::new_default_runner;
use crate::common::e2e::test::{E2eTest, E2eTestDirection};
use crate::common::e2e::tlv::TLVTest;
use crate::common::init_env_logger;
use crate::{attr_data, attr_data_path, attr_read_status_resp};

const EP1_ON_TIME: GenericPath = GenericPath::new(
    Some(1),
    Some(on_off::FULL_CLUSTER.id),
    Some(on_off::AttributeId::OnTime as u32),
);
const INVALID_ENDPOINT: GenericPath = GenericPath::new(
    Some(2),
    Some(echo_cluster::ID),
    Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
);
const INVALID_CLUSTER: GenericPath = GenericPath::new(
    Some(0),
    Some(0x1234),
    Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
);
const INVALID_ATTRIBUTE: GenericPath =
    GenericPath::new(Some(0), Some(echo_cluster::ID), Some(0x1234));

#[test]
fn test_subscribe_mixed_paths() {
    // A subscription with both supported and unsupported concrete paths is accepted.
    // The priming report has data for the supported paths and an error status for each
    // unsupported one; the later reports cover the supported paths only.
    init_env_logger();

    let im = new_default_runner();
    let handler = im.handler();

    im.add_default_acl();

    let input = &[
        AttrPath::from_gp(&EP1_ON_TIME),
        AttrPath::from_gp(&INVALID_ENDPOINT),
        AttrPath::from_gp(&INVALID_CLUSTER),
        AttrPath::from_gp(&INVALID_ATTRIBUTE),
    ];

    let new_value = 5u16;

    im.test_all(
        &handler,
        [
            &TLVTest::subscribe(
                TestSubscribeReq {
                    min_int_floor: 0,
                    max_int_ceil: 1,
                    ..TestSubscribeReq::reqs(input)
                },
                TestReportDataMsg {
                    subscription_id: Some(1),
                    attr_reports: Some(&[
                        attr_data_path!(EP1_ON_TIME, Some(&0u16)),
                        attr_read_status_resp!(
                            &INVALID_ENDPOINT,
                            IMStatusCode::UnsupportedEndpoint
                        ),
                        attr_read_status_resp!(&INVALID_CLUSTER, IMStatusCode::UnsupportedCluster),
                        attr_read_status_resp!(
                            &INVALID_ATTRIBUTE,
                            IMStatusCode::UnsupportedAttribute
                        ),
                    ]),
                    ..Default::default()
                },
                ReplyProcessor::remove_attr_dataver,
            ) as &dyn E2eTest,
            &TLVTest {
                delay_ms: Some(1),
                ..TLVTest::subscribe_final(
                    StatusResp {
                        status: IMStatusCode::Success,
                        ..Default::default()
                    },
                    SubscribeResp::new(1, 40),
                    ReplyProcessor::none,
                )
            },
            &TLVTest::write_attrs(
                &[TestAttrData::new(
                    None,
                    AttrPath::from_gp(&EP1_ON_TIME),
                    &new_value as _,
                )],
                &[AttrStatus::from_gp(
                    &EP1_ON_TIME,
                    IMStatusCode::Success,
                    None,
                )],
            ),
            &TLVTest::subscription_report(
                Setup::none,
                TestReportDataMsg {
                    subscription_id: Some(1),
                    attr_reports: Some(&[attr_data_path!(EP1_ON_TIME, Some(&new_value))]),
                    ..Default::default()
                },
                ReplyProcessor::remove_attr_dataver,
                StatusResp {
                    status: IMStatusCode::Success,
                    ..Default::default()
                },
            ),
        ],
    );
}

#[test]
fn test_subscribe_large_req_dataver_filters() {
    // A subscription keeps a request too large for its buffer without its data
    // version filters. The priming report still honours them.
    init_env_logger();

    let im = new_default_runner();
    let handler = im.handler();

    im.add_default_acl();

    let wc_ep_att1 = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );
    let input = &[AttrPath::from_gp(&wc_ep_att1)];

    // The current version of the echo cluster on endpoint 0, and then the versions
    // of clusters the node does not have, as a controller with a stale cache sends
    let mut dataver_filters = vec![DataVersionFilter {
        path: ClusterPath {
            node: None,
            endpoint: 0,
            cluster: echo_cluster::ID,
        },
        data_ver: handler.echo_cluster(0).data_ver.get(),
    }];
    dataver_filters.extend((0x1000..0x1010).map(|cluster| DataVersionFilter {
        path: ClusterPath {
            node: None,
            endpoint: 0,
            cluster,
        },
        data_ver: 0x1234_5678,
    }));

    let req = TestSubscribeReq {
        min_int_floor: 0,
        max_int_ceil: 1,
        dataver_filters: Some(&dataver_filters),
        ..TestSubscribeReq::reqs(input)
    };

    let mut buf = [0; 1024];
    let mut wb = WriteBuf::new(&mut buf);
    req.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
    assert!(wb.as_slice().len() > SUBSCRIPTION_BUFFER_SIZE);

    im.test_all(
        &handler,
        [
            &TLVTest::subscribe(
                req,
                // The echo cluster on endpoint 0 is filtered out
                TestReportDataMsg {
                    subscription_id: Some(1),
                    attr_reports: Some(&[attr_data!(
                        1,
                        echo_cluster::ID,
                        echo_cluster::AttributesDiscriminants::Att1,
                        Some(&0x1234u16)
                    )]),
                    ..Default::default()
                },
                ReplyProcessor::remove_attr_dataver,
            ) as &dyn E2eTest,
            &TLVTest {
                delay_ms: Some(1),
                ..TLVTest::subscribe_final(
                    StatusResp {
                        status: IMStatusCode::Success,
                        ..Default::default()
                    },
                    SubscribeResp::new(1, 40),
                    ReplyProcessor::none,
                )
            },
        ],
    );
}

#[test]
fn test_subscribe_rejected() {
    // A subscription none of whose paths is valid, or whose min interval is
    // greater than its max interval, is rejected with `InvalidAction`
    init_env_logger();

    let im = new_default_runner();
    let handler = im.handler();

    im.add_default_acl();

    let attr_reqs = &[
        AttrPath::from_gp(&INVALID_ENDPOINT),
        AttrPath::from_gp(&INVALID_CLUSTER),
        AttrPath::from_gp(&INVALID_ATTRIBUTE),
    ];

    let event_reqs = &[EventPath::from_gp(&GenericPath::new(
        Some(0),
        Some(0x1234),
        Some(1),
    ))];

    // A wildcard event path that matches no event
    let wc_event_reqs = &[EventPath::from_gp(&GenericPath::new(Some(999), None, None))];

    let valid_attr_reqs = &[AttrPath::from_gp(&EP1_ON_TIME)];

    for req in [
        TestSubscribeReq {
            min_int_floor: 0,
            max_int_ceil: 1,
            ..TestSubscribeReq::reqs(attr_reqs)
        },
        TestSubscribeReq {
            min_int_floor: 0,
            max_int_ceil: 1,
            ..TestSubscribeReq::event_reqs(event_reqs)
        },
        TestSubscribeReq {
            min_int_floor: 0,
            max_int_ceil: 1,
            event_requests: Some(event_reqs),
            ..TestSubscribeReq::reqs(attr_reqs)
        },
        TestSubscribeReq {
            min_int_floor: 0,
            max_int_ceil: 1,
            ..TestSubscribeReq::event_reqs(wc_event_reqs)
        },
        TestSubscribeReq {
            min_int_floor: 10,
            max_int_ceil: 5,
            ..TestSubscribeReq::reqs(valid_attr_reqs)
        },
    ] {
        im.test_one(
            &handler,
            TLVTest {
                delay_ms: None,
                input_meta: MessageMeta {
                    proto_id: PROTO_ID_INTERACTION_MODEL,
                    proto_opcode: OpCode::SubscribeRequest as _,
                    reliable: true,
                },
                input_payload: req,
                expected_meta: MessageMeta {
                    proto_id: PROTO_ID_INTERACTION_MODEL,
                    proto_opcode: OpCode::StatusResponse as _,
                    reliable: true,
                },
                expected_payload: StatusResp {
                    status: IMStatusCode::InvalidAction,
                    ..Default::default()
                },
                process_reply: ReplyProcessor::none,
                setup: Setup::none,
                direction: E2eTestDirection::ClientInitiated,
            },
        );
    }
}
