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

use core::num::NonZeroU8;

use rs_matter::dm::clusters::adm_comm::{self, CommandId, StatusCode};
use rs_matter::im::{CmdPath, CmdStatus, IMStatusCode, StatusResp, TimedReq};
use rs_matter::tlv::ToTLV;
use rs_matter::transport::session::SessionMode;

use crate::common::e2e::im::commands::{TestCmdData, TestCmdResp};
use crate::common::e2e::im::{ReplyProcessor, TestInvReq, TestInvResp};
use crate::common::e2e::new_default_runner;
use crate::common::e2e::test::E2eTest;
use crate::common::e2e::tlv::TLVTest;
use crate::common::init_env_logger;

/// TLV mirror of `OpenBasicCommissioningWindowRequest`.
#[derive(Debug, Clone, PartialEq, ToTLV)]
struct TestOpenBasicWindowReq {
    commissioning_timeout: u16,
}

/// While a fail-safe is armed, another commissioner is likely about to
/// commission the node, so no commissioning window opens.
#[test]
fn no_window_opens_while_the_failsafe_is_armed() {
    init_env_logger();

    let path = CmdPath::new(
        Some(0),
        Some(adm_comm::FULL_CLUSTER.id),
        Some(CommandId::OpenBasicCommissioningWindow as u32),
    );
    let req = TestOpenBasicWindowReq {
        commissioning_timeout: 180,
    };
    let input = &[TestCmdData::new(path.clone(), &req)];
    let expected = &[TestCmdResp::Status(CmdStatus::new(
        path,
        IMStatusCode::Failure,
        NonZeroU8::new(StatusCode::Busy as u8),
        None,
    ))];

    let im = new_default_runner();
    let handler = im.handler();
    im.add_default_acl();

    im.matter.with_state(|state| {
        let case = SessionMode::Case {
            fab_idx: NonZeroU8::new(1).unwrap(),
            cat_ids: Default::default(),
        };

        state.failsafe.arm(60, 0, &case, false).unwrap();
    });

    im.test_all(
        &handler,
        [
            &TLVTest {
                delay_ms: None,
                ..TLVTest::timed(
                    TimedReq::new(2000),
                    StatusResp {
                        status: IMStatusCode::Success,
                        ..Default::default()
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

    assert!(!im.matter.comm_window_state().is_open());
}
