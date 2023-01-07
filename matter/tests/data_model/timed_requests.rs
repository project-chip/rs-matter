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
        messages::GenericPath,
        messages::{
            ib::{AttrData, AttrPath, AttrStatus},
            msg::{StatusResp, TimedReq, WriteReq, WriteResp},
        },
    },
    tlv::{self, FromTLV, TLVWriter},
    transport::exchange::{self, Exchange},
};

use crate::common::{
    echo_cluster,
    im_engine::{ImEngine, ImInput},
};

enum WriteResponse<'a> {
    TransactionError,
    TransactionSuccess(&'a [AttrStatus]),
}

// Helper for handling Write Attribute sequences
fn handle_timed_write_reqs(
    input: &[AttrData],
    expected: WriteResponse,
    timeout: u16,
    delay: u16,
) -> DataModel {
    let mut im_engine = ImEngine::new();
    // Use the same exchange for all parts of the transaction
    im_engine.exch = Some(Exchange::new(1, 0, exchange::Role::Responder));

    // Send Timed Req
    let mut out_buf = [0u8; 400];
    let timed_req = TimedReq { timeout };
    let im_input = ImInput::new(OpCode::TimedRequest, &timed_req);
    let (_, out_buf) = im_engine.process(&im_input, &mut out_buf);
    tlv::print_tlv_list(out_buf);

    // Process any delays
    let delay = time::Duration::from_millis(delay.into());
    thread::sleep(delay);

    // Send Write Req
    let mut out_buf = [0u8; 400];
    let write_req = WriteReq::new(false, input);
    let input = ImInput::new(OpCode::WriteRequest, &write_req);
    let (resp_opcode, out_buf) = im_engine.process(&input, &mut out_buf);

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
    im_engine.dm
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
    handle_timed_write_reqs(input, WriteResponse::TransactionError, 400, 500);

    // Test with correct handling
    let dm = handle_timed_write_reqs(input, WriteResponse::TransactionSuccess(expected), 400, 0);
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
