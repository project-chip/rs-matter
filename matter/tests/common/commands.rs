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
        messages::ib::{CmdPath, CmdStatus, InvResp},
        messages::msg,
    },
};

pub enum ExpectedInvResp {
    Cmd(CmdPath, u8),
    Status(CmdStatus),
}

pub fn assert_inv_response(resp: &msg::InvResp, expected: &[ExpectedInvResp]) {
    let mut index = 0;
    for inv_response in resp.inv_responses.as_ref().unwrap().iter() {
        println!("Validating index {}", index);
        match &expected[index] {
            ExpectedInvResp::Cmd(e_c, e_d) => match inv_response {
                InvResp::Cmd(c) => {
                    assert_eq!(e_c, &c.path);
                    match c.data {
                        EncodeValue::Tlv(t) => {
                            assert_eq!(*e_d, t.find_tag(0).unwrap().u8().unwrap())
                        }
                        _ => panic!("Incorrect CmdDataType"),
                    }
                }
                _ => {
                    panic!("Invalid response, expected InvResponse::Cmd");
                }
            },
            ExpectedInvResp::Status(e_status) => match inv_response {
                InvResp::Status(status) => {
                    assert_eq!(e_status, &status);
                }
                _ => {
                    panic!("Invalid response, expected InvResponse::Status");
                }
            },
        }
        println!("Index {} success", index);
        index += 1;
    }
    assert_eq!(index, expected.len());
}

#[macro_export]
macro_rules! cmd_data {
    ($path:expr, $data:literal) => {
        CmdData::new($path, EncodeValue::Value(&($data as u32)))
    };
}

#[macro_export]
macro_rules! echo_req {
    ($endpoint:literal, $data:literal) => {
        CmdData::new(
            CmdPath::new(
                Some($endpoint),
                Some(echo_cluster::ID),
                Some(echo_cluster::Commands::EchoReq as u32),
            ),
            EncodeValue::Value(&($data as u32)),
        )
    };
}

#[macro_export]
macro_rules! echo_resp {
    ($endpoint:literal, $data:literal) => {
        ExpectedInvResp::Cmd(
            CmdPath::new(
                Some($endpoint),
                Some(echo_cluster::ID),
                Some(echo_cluster::RespCommands::EchoResp as u32),
            ),
            $data,
        )
    };
}
