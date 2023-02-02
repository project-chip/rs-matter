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

use matter::{
    data_model::objects::EncodeValue,
    interaction_model::{
        core::IMStatusCode,
        messages::ib::{AttrData, AttrPath, AttrStatus},
        messages::{ib::CmdData, ib::CmdPath, GenericPath},
    },
    mdns::DummyMdns,
    tlv::TLVWriter,
};

use crate::{
    common::{
        commands::*,
        echo_cluster,
        handlers::{TimedInvResponse, WriteResponse},
        im_engine::{matter, ImEngine},
    },
    echo_req, echo_resp,
};

#[test]
fn test_timed_write_fail_and_success() {
    // - 1 Timed Attr Write Transaction should fail due to timeout
    // - 1 Timed Attr Write Transaction should succeed
    let val0 = 10;
    let _ = env_logger::try_init();
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };

    let ep_att = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let input = &[AttrData::new(
        None,
        AttrPath::new(&ep_att),
        EncodeValue::Closure(&attr_data0),
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
        AttrStatus::new(&ep0_att, IMStatusCode::Success, 0),
        AttrStatus::new(&ep1_att, IMStatusCode::Success, 0),
    ];

    // Test with incorrect handling
    ImEngine::new_with_timed_write_reqs(
        &matter(&mut DummyMdns),
        input,
        &WriteResponse::TransactionError,
        400,
        500,
    );

    // Test with correct handling
    let mut mdns = DummyMdns;
    let matter = matter(&mut mdns);
    let im = ImEngine::new_with_timed_write_reqs(
        &matter,
        input,
        &WriteResponse::TransactionSuccess(expected),
        400,
        0,
    );
    assert_eq!(val0, im.echo_cluster(0).att_write);
}

#[test]
fn test_timed_cmd_success() {
    // A timed request that works
    let _ = env_logger::try_init();

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];
    let expected = &[echo_resp!(0, 10), echo_resp!(1, 30)];
    ImEngine::new_with_timed_commands(
        &matter(&mut DummyMdns),
        input,
        &TimedInvResponse::TransactionSuccess(expected),
        400,
        0,
        true,
    );
}

#[test]
fn test_timed_cmd_timeout() {
    // A timed request that is executed after t imeout
    let _ = env_logger::try_init();

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];
    ImEngine::new_with_timed_commands(
        &matter(&mut DummyMdns),
        input,
        &TimedInvResponse::TransactionError(IMStatusCode::Timeout),
        400,
        500,
        true,
    );
}

#[test]
fn test_timed_cmd_timedout_mismatch() {
    // A timed request with timeout mismatch
    let _ = env_logger::try_init();

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];
    ImEngine::new_with_timed_commands(
        &matter(&mut DummyMdns),
        input,
        &TimedInvResponse::TransactionError(IMStatusCode::TimedRequestMisMatch),
        400,
        0,
        false,
    );

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];
    ImEngine::new_with_timed_commands(
        &matter(&mut DummyMdns),
        input,
        &TimedInvResponse::TransactionError(IMStatusCode::TimedRequestMisMatch),
        0,
        0,
        true,
    );
}
