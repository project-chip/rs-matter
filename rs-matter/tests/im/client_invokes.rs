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

//! Client-side invoke tests exercising `ImClient::invoke`, `ImClient::invoke_single`,
//! and `ImClient::invoke_single_cmd`.

use embassy_futures::block_on;
use embassy_futures::select::select;

use rs_matter::im::client::ImClient;
use rs_matter::im::{CmdData, CmdPath, CmdResp};
use rs_matter::tlv::TLVElement;
use rs_matter::utils::select::Coalesce;

use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

/// Test that a non-chunked invoke works correctly via `ImClient::invoke`.
#[test]
fn test_client_invoke_non_chunked() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let mut exchange = im.initiate_exchange().await?;

            let path = CmdPath {
                endpoint: Some(0),
                cluster: Some(echo_cluster::ID),
                cmd: Some(echo_cluster::Commands::EchoReq as u32),
            };

            // EchoReq takes a u8 value; encode as anonymous TLV u8
            let echo_data = [0x04, 5u8]; // TLV unsigned int tag=anonymous, value=5
            let cmd = CmdData {
                path,
                data: TLVElement::new(&echo_data),
                command_ref: None,
            };

            let mut chunk_count = 0u32;
            let mut got_response = false;

            ImClient::invoke(&mut exchange, &[cmd], None, |resp| {
                chunk_count += 1;

                if let Some(invoke_responses) = &resp.invoke_responses {
                    for cmd_resp in invoke_responses.iter() {
                        if cmd_resp.is_ok() {
                            got_response = true;
                        }
                    }
                }

                Ok(())
            })
            .await?;

            assert_eq!(
                chunk_count, 1,
                "Non-chunked invoke should have exactly 1 chunk"
            );
            assert!(got_response, "Should have received an invoke response");

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}

/// Test that `ImClient::invoke_single` works correctly with the callback-based `invoke`.
#[test]
fn test_client_invoke_single() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let mut exchange = im.initiate_exchange().await?;

            // EchoReq on endpoint 0 with value 5; multiplier is 2, so expect 10
            let echo_data = [0x04, 5u8]; // TLV unsigned int tag=anonymous, value=5

            let value = ImClient::invoke_single(
                &mut exchange,
                0,
                echo_cluster::ID,
                echo_cluster::Commands::EchoReq as u32,
                TLVElement::new(&echo_data),
                None,
                |resp| match resp {
                    CmdResp::Cmd(data) => Ok(data.data.u8()?),
                    CmdResp::Status(status) => {
                        panic!("Unexpected status response: {:?}", status.status);
                    }
                },
            )
            .await?;

            // EchoHandler on endpoint 0 has multiplier 2, so 5 * 2 = 10
            assert_eq!(value, 10, "EchoResp should return 5 * 2 = 10");

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}

/// Test that `ImClient::invoke_single_cmd` returns zero-copy response data.
#[test]
fn test_client_invoke_single_cmd() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let mut exchange = im.initiate_exchange().await?;

            // EchoReq on endpoint 0 with value 7; multiplier is 2, so expect 14
            let echo_data = [0x04, 7u8]; // TLV unsigned int tag=anonymous, value=7

            let resp = ImClient::invoke_single_cmd(
                &mut exchange,
                0,
                echo_cluster::ID,
                echo_cluster::Commands::EchoReq as u32,
                TLVElement::new(&echo_data),
                None,
            )
            .await?;

            match resp {
                CmdResp::Cmd(data) => {
                    let value = data.data.u8()?;
                    assert_eq!(value, 14, "EchoResp should return 7 * 2 = 14");
                }
                CmdResp::Status(status) => {
                    panic!("Unexpected status response: {:?}", status.status);
                }
            }

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}
