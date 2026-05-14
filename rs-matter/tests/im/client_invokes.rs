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

use either::Either;
use embassy_futures::block_on;
use embassy_futures::select::select;

use rs_matter::im::client::ImClient;
use rs_matter::im::{CmdData, CmdDataTag, CmdPath, CmdResp};
use rs_matter::tlv::{TLVElement, TLVTag, TLVWrite};
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
            let exchange = im.initiate_exchange().await?;

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

            ImClient::invoke(exchange, &[cmd], None, |resp| {
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
            let exchange = im.initiate_exchange().await?;

            // EchoReq on endpoint 0 with value 5; multiplier is 2, so expect 10
            let echo_data = [0x04, 5u8]; // TLV unsigned int tag=anonymous, value=5

            let value = ImClient::invoke_single(
                exchange,
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
            let exchange = im.initiate_exchange().await?;

            // EchoReq on endpoint 0 with value 7; multiplier is 2, so expect 14
            let echo_data = [0x04, 7u8]; // TLV unsigned int tag=anonymous, value=7

            let value = ImClient::invoke_single_cmd(
                exchange,
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

            assert_eq!(value, 14, "EchoResp should return 7 * 2 = 14");

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}

/// Tier-1 (closure-free, scratch-buffer-free) `invoke` via
/// `ImClient::invoke_txn` + `InvokeTxn::tx` + `InvokeRespChunk`.
///
/// Drives the retransmit-and-receive loop manually:
///   1. `invoke_txn().await?`  →  `InvokeTxn` (no I/O yet).
///   2. `txn.tx().await?`      →  on first call, returns `Left(builder)`.
///   3. Build the request via the typed builder; `.end()` hands the
///      `InvokeTxn` back.
///   4. `txn.tx().await?`      →  commits bytes, awaits the framework.
///                                Returns `Right(chunk)` once ACK-ed.
///   5. `chunk.response()?`    →  borrowed `InvokeResp` for inspection.
///   6. `chunk.complete().await?` → ACKs the chunk; returns the next
///                                  chunk if `more_chunks=true`, else `None`.
#[test]
fn test_client_invoke_txn_non_chunked() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let exchange = im.initiate_exchange().await?;
            let mut txn = exchange.invoke_txn(None).await?;

            // Drive the retransmit loop until the framework hands us
            // the first response chunk.
            let mut chunk = loop {
                match txn.tx().await? {
                    Either::Left(builder) => {
                        txn = builder
                            .suppress_response(false)?
                            .timed_request(false)?
                            .invoke_requests()?
                            .push()?
                            .path(0, echo_cluster::ID, echo_cluster::Commands::EchoReq as u32)?
                            .data(|w| {
                                // EchoReq body: anonymous TLV u8 retagged at
                                // CmdDataTag::Data — same on-wire form as the
                                // existing tier-2 invoke test (`[0x04, 5u8]`).
                                w.u8(&TLVTag::Context(CmdDataTag::Data as u8), 5)
                            })?
                            .end()? // close CmdData entry
                            .end()? // close InvokeRequests array
                            .end()?; // close InvokeRequestMessage → InvokeTxn
                    }
                    Either::Right(c) => break c,
                }
            };

            // Iterate the response-chunk loop. Non-chunked EchoReq
            // gives exactly one chunk before `complete()` returns None.
            let mut chunk_count = 0u32;
            let mut got_response = false;
            loop {
                chunk_count += 1;
                {
                    let resp = chunk.response()?;
                    if let Some(invoke_responses) = &resp.invoke_responses {
                        for cmd_resp in invoke_responses.iter() {
                            if cmd_resp.is_ok() {
                                got_response = true;
                            }
                        }
                    }
                }
                match chunk.complete().await? {
                    Some(next) => chunk = next,
                    None => break,
                }
            }

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
