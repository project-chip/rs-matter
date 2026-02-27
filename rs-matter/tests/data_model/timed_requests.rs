/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
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

use rs_matter::im::GenericPath;
use rs_matter::im::{AttrPath, AttrStatus};
use rs_matter::im::{IMStatusCode, OpCode, PROTO_ID_INTERACTION_MODEL};
use rs_matter::im::{StatusResp, TimedReq};
use rs_matter::transport::exchange::MessageMeta;

use crate::common::e2e::im::attributes::TestAttrData;
use crate::common::e2e::im::{
    echo_cluster, ReplyProcessor, Setup, TestInvReq, TestInvResp, TestWriteReq, TestWriteResp,
};
use crate::common::e2e::new_default_runner;
use crate::common::e2e::test::{E2eTest, E2eTestDirection};
use crate::common::e2e::tlv::TLVTest;
use crate::common::init_env_logger;
use crate::{echo_req, echo_resp};

#[test]
fn test_timed_write_fail_and_success() {
    // - 2 Timed Attr Write Transactions should fail due to timeout mismatch
    // - 1 Timed Attr Write Transaction should fail due to timeout
    // - 1 Timed Attr Write Transaction should succeed
    let val0 = 10;
    init_env_logger();

    let ep_att = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let input = &[TestAttrData::new(
        None,
        AttrPath::from_gp(&ep_att),
        &val0 as _,
    )];

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
    let expected = &[
        AttrStatus::from_gp(&ep0_att, IMStatusCode::Success, None),
        AttrStatus::from_gp(&ep1_att, IMStatusCode::Success, None),
    ];

    let im = new_default_runner();
    let handler = im.handler();
    im.add_default_acl();

    // Test with timeout mismatch (timeout not set, but the following write req is timed)
    im.test_one(
        &handler,
        TLVTest {
            delay_ms: None,
            input_meta: MessageMeta {
                proto_id: PROTO_ID_INTERACTION_MODEL,
                proto_opcode: OpCode::WriteRequest as _,
                reliable: true,
            },
            input_payload: TestWriteReq {
                timed_request: Some(true),
                ..TestWriteReq::reqs(input)
            },
            expected_meta: MessageMeta {
                proto_id: PROTO_ID_INTERACTION_MODEL,
                proto_opcode: OpCode::StatusResponse as _,
                reliable: true,
            },
            expected_payload: StatusResp {
                status: IMStatusCode::TimedRequestMisMatch,
            },
            process_reply: ReplyProcessor::none,
            setup: Setup::none,
            direction: E2eTestDirection::ClientInitiated,
        },
    );

    // Test with timeout mismatch (timeout set, but the write req is not timed)
    im.test_all(
        &handler,
        [
            &TLVTest {
                delay_ms: Some(100),
                ..TLVTest::timed(
                    TimedReq { timeout: 1 },
                    StatusResp {
                        status: IMStatusCode::Success,
                    },
                    ReplyProcessor::none,
                )
            } as &dyn E2eTest,
            &TLVTest {
                delay_ms: None,
                input_meta: MessageMeta {
                    proto_id: PROTO_ID_INTERACTION_MODEL,
                    proto_opcode: OpCode::WriteRequest as _,
                    reliable: true,
                },
                input_payload: TestWriteReq::reqs(input),
                expected_meta: MessageMeta {
                    proto_id: PROTO_ID_INTERACTION_MODEL,
                    proto_opcode: OpCode::StatusResponse as _,
                    reliable: true,
                },
                expected_payload: StatusResp {
                    status: IMStatusCode::TimedRequestMisMatch,
                },
                process_reply: ReplyProcessor::none,
                setup: Setup::none,
                direction: E2eTestDirection::ClientInitiated,
            },
        ],
    );

    // Test with incorrect handling
    im.test_all(
        &handler,
        [
            &TLVTest {
                delay_ms: Some(100),
                ..TLVTest::timed(
                    TimedReq { timeout: 1 },
                    StatusResp {
                        status: IMStatusCode::Success,
                    },
                    ReplyProcessor::none,
                )
            } as &dyn E2eTest,
            &TLVTest {
                delay_ms: None,
                input_meta: MessageMeta {
                    proto_id: PROTO_ID_INTERACTION_MODEL,
                    proto_opcode: OpCode::WriteRequest as _,
                    reliable: true,
                },
                input_payload: TestWriteReq {
                    timed_request: Some(true),
                    ..TestWriteReq::reqs(input)
                },
                expected_meta: MessageMeta {
                    proto_id: PROTO_ID_INTERACTION_MODEL,
                    proto_opcode: OpCode::StatusResponse as _,
                    reliable: true,
                },
                expected_payload: StatusResp {
                    status: IMStatusCode::Timeout,
                },
                process_reply: ReplyProcessor::none,
                setup: Setup::none,
                direction: E2eTestDirection::ClientInitiated,
            },
        ],
    );

    // Test with correct handling
    im.test_all(
        &handler,
        [
            &TLVTest {
                delay_ms: None,
                ..TLVTest::timed(
                    TimedReq { timeout: 500 },
                    StatusResp {
                        status: IMStatusCode::Success,
                    },
                    ReplyProcessor::none,
                )
            } as &dyn E2eTest,
            &TLVTest::write(
                TestWriteReq {
                    timed_request: Some(true),
                    ..TestWriteReq::reqs(input)
                },
                TestWriteResp::resp(expected),
                ReplyProcessor::none,
            ),
        ],
    );

    assert_eq!(val0, handler.echo_cluster(0).att_write.get());
}

#[test]
fn test_timed_cmd_success() {
    // A timed request that works
    init_env_logger();

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];
    let expected = &[echo_resp!(0, 10), echo_resp!(1, 30)];

    let im = new_default_runner();
    let handler = im.handler();
    im.add_default_acl();

    // Test with correct handling
    im.test_all(
        &handler,
        [
            &TLVTest {
                delay_ms: None,
                ..TLVTest::timed(
                    TimedReq { timeout: 2000 },
                    StatusResp {
                        status: IMStatusCode::Success,
                    },
                    ReplyProcessor::none,
                )
            } as &dyn E2eTest,
            &TLVTest::invoke(
                TestInvReq {
                    timed_request: Some(true),
                    ..TestInvReq::reqs(input)
                },
                TestInvResp::resp(expected),
                ReplyProcessor::none,
            ),
        ],
    );
}

#[test]
fn test_timed_cmd_timeout() {
    // A timed request that is executed after a timeout
    init_env_logger();

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];

    let im = new_default_runner();
    let handler = im.handler();
    im.add_default_acl();

    im.test_all(
        &handler,
        [
            &TLVTest {
                delay_ms: Some(500),
                ..TLVTest::timed(
                    TimedReq { timeout: 1 },
                    StatusResp {
                        status: IMStatusCode::Success,
                    },
                    ReplyProcessor::none,
                )
            } as &dyn E2eTest,
            &TLVTest {
                delay_ms: None,
                input_meta: MessageMeta {
                    proto_id: PROTO_ID_INTERACTION_MODEL,
                    proto_opcode: OpCode::InvokeRequest as _,
                    reliable: true,
                },
                input_payload: TestInvReq {
                    timed_request: Some(true),
                    ..TestInvReq::reqs(input)
                },
                expected_meta: MessageMeta {
                    proto_id: PROTO_ID_INTERACTION_MODEL,
                    proto_opcode: OpCode::StatusResponse as _,
                    reliable: true,
                },
                expected_payload: StatusResp {
                    status: IMStatusCode::Timeout,
                },
                process_reply: ReplyProcessor::none,
                setup: Setup::none,
                direction: E2eTestDirection::ClientInitiated,
            },
        ],
    );
}

#[test]
fn test_timed_cmd_timeout_mismatch() {
    // A timed request with timeout mismatch
    init_env_logger();

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];

    let im = new_default_runner();
    let handler = im.handler();
    im.add_default_acl();

    // Test with timeout mismatch (timeout not set, but the following write req is timed)
    im.test_one(
        &handler,
        TLVTest {
            delay_ms: None,
            input_meta: MessageMeta {
                proto_id: PROTO_ID_INTERACTION_MODEL,
                proto_opcode: OpCode::InvokeRequest as _,
                reliable: true,
            },
            input_payload: TestInvReq {
                timed_request: Some(true),
                ..TestInvReq::reqs(input)
            },
            expected_meta: MessageMeta {
                proto_id: PROTO_ID_INTERACTION_MODEL,
                proto_opcode: OpCode::StatusResponse as _,
                reliable: true,
            },
            expected_payload: StatusResp {
                status: IMStatusCode::TimedRequestMisMatch,
            },
            process_reply: ReplyProcessor::none,
            setup: Setup::none,
            direction: E2eTestDirection::ClientInitiated,
        },
    );

    // Test with timeout mismatch (timeout set, but the following write req is timed)
    im.test_all(
        &handler,
        [
            &TLVTest {
                delay_ms: None,
                ..TLVTest::timed(
                    TimedReq { timeout: 1 },
                    StatusResp {
                        status: IMStatusCode::Success,
                    },
                    ReplyProcessor::none,
                )
            } as &dyn E2eTest,
            &TLVTest {
                delay_ms: None,
                input_meta: MessageMeta {
                    proto_id: PROTO_ID_INTERACTION_MODEL,
                    proto_opcode: OpCode::InvokeRequest as _,
                    reliable: true,
                },
                input_payload: TestInvReq::reqs(input),
                expected_meta: MessageMeta {
                    proto_id: PROTO_ID_INTERACTION_MODEL,
                    proto_opcode: OpCode::StatusResponse as _,
                    reliable: true,
                },
                expected_payload: StatusResp {
                    status: IMStatusCode::TimedRequestMisMatch,
                },
                process_reply: ReplyProcessor::none,
                setup: Setup::none,
                direction: E2eTestDirection::ClientInitiated,
            },
        ],
    );
}
