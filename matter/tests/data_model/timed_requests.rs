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

use core::time;
use std::thread;

use matter::{
    data_model::{
        core::DataModel,
        objects::{AttrValue, EncodeValue},
    },
    interaction_model::{
        core::{IMStatusCode, OpCode},
        messages::{ib::CmdData, ib::CmdPath, msg::InvReq, GenericPath},
        messages::{
            ib::{AttrData, AttrPath, AttrStatus},
            msg::{self, StatusResp, TimedReq, WriteReq, WriteResp},
        },
    },
    tlv::{self, FromTLV, TLVArray, TLVWriter, ToTLV},
    transport::exchange::{self, Exchange},
};

use crate::{
    common::{
        commands::*,
        echo_cluster,
        im_engine::{ImEngine, ImInput},
    },
    echo_req, echo_resp,
};

fn handle_timed_reqs<'a>(
    opcode: OpCode,
    request: &dyn ToTLV,
    timeout: u16,
    delay: u16,
    output: &'a mut [u8],
) -> (u8, DataModel, &'a [u8]) {
    let mut im_engine = ImEngine::new();
    // Use the same exchange for all parts of the transaction
    im_engine.exch = Some(Exchange::new(1, 0, exchange::Role::Responder));

    if timeout != 0 {
        // Send Timed Req
        let mut tmp_buf = [0u8; 400];
        let timed_req = TimedReq { timeout };
        let im_input = ImInput::new(OpCode::TimedRequest, &timed_req);
        let (_, out_buf) = im_engine.process(&im_input, &mut tmp_buf);
        tlv::print_tlv_list(out_buf);
    } else {
        println!("Skipping timed request");
    }

    // Process any delays
    let delay = time::Duration::from_millis(delay.into());
    thread::sleep(delay);

    // Send Write Req
    let input = ImInput::new(opcode, request);
    let (resp_opcode, output) = im_engine.process(&input, output);
    (resp_opcode, im_engine.dm, output)
}
enum WriteResponse<'a> {
    TransactionError,
    TransactionSuccess(&'a [AttrStatus]),
}

// Helper for handling Write Attribute sequences
fn handle_timed_write_reqs(
    input: &[AttrData],
    expected: &WriteResponse,
    timeout: u16,
    delay: u16,
) -> DataModel {
    let mut out_buf = [0u8; 400];
    let write_req = WriteReq::new(false, input);

    let (resp_opcode, dm, out_buf) = handle_timed_reqs(
        OpCode::WriteRequest,
        &write_req,
        timeout,
        delay,
        &mut out_buf,
    );
    tlv::print_tlv_list(out_buf);
    let root = tlv::get_root_node_struct(out_buf).unwrap();

    match expected {
        WriteResponse::TransactionSuccess(t) => {
            assert_eq!(
                num::FromPrimitive::from_u8(resp_opcode),
                Some(OpCode::WriteResponse)
            );
            let resp = WriteResp::from_tlv(&root).unwrap();
            assert_eq!(resp.write_responses, t);
        }
        WriteResponse::TransactionError => {
            assert_eq!(
                num::FromPrimitive::from_u8(resp_opcode),
                Some(OpCode::StatusResponse)
            );
            let status_resp = StatusResp::from_tlv(&root).unwrap();
            assert_eq!(status_resp.status, IMStatusCode::Timeout);
        }
    }
    dm
}

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

    // Test with incorrect handling
    handle_timed_write_reqs(input, &WriteResponse::TransactionError, 400, 500);

    // Test with correct handling
    let dm = handle_timed_write_reqs(input, &WriteResponse::TransactionSuccess(expected), 400, 0);
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

enum TimedInvResponse<'a> {
    TransactionError(IMStatusCode),
    TransactionSuccess(&'a [ExpectedInvResp]),
}
// Helper for handling Invoke Command sequences
fn handle_timed_commands(
    input: &[CmdData],
    expected: &TimedInvResponse,
    timeout: u16,
    delay: u16,
    set_timed_request: bool,
) -> DataModel {
    let mut out_buf = [0u8; 400];
    let req = InvReq {
        suppress_response: Some(false),
        timed_request: Some(set_timed_request),
        inv_requests: Some(TLVArray::Slice(input)),
    };

    let (resp_opcode, dm, out_buf) =
        handle_timed_reqs(OpCode::InvokeRequest, &req, timeout, delay, &mut out_buf);
    tlv::print_tlv_list(out_buf);
    let root = tlv::get_root_node_struct(out_buf).unwrap();

    match expected {
        TimedInvResponse::TransactionSuccess(t) => {
            assert_eq!(
                num::FromPrimitive::from_u8(resp_opcode),
                Some(OpCode::InvokeResponse)
            );
            let resp = msg::InvResp::from_tlv(&root).unwrap();
            assert_inv_response(&resp, t)
        }
        TimedInvResponse::TransactionError(e) => {
            assert_eq!(
                num::FromPrimitive::from_u8(resp_opcode),
                Some(OpCode::StatusResponse)
            );
            let status_resp = StatusResp::from_tlv(&root).unwrap();
            assert_eq!(status_resp.status, *e);
        }
    }
    dm
}

#[test]
fn test_timed_cmd_success() {
    // A timed request that works
    let _ = env_logger::try_init();

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];
    let expected = &[echo_resp!(0, 10), echo_resp!(1, 30)];
    handle_timed_commands(
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
    handle_timed_commands(
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
    handle_timed_commands(
        input,
        &TimedInvResponse::TransactionError(IMStatusCode::TimedRequestMisMatch),
        400,
        0,
        false,
    );

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];
    handle_timed_commands(
        input,
        &TimedInvResponse::TransactionError(IMStatusCode::TimedRequestMisMatch),
        0,
        0,
        true,
    );
}
