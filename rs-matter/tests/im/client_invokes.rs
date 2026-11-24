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

//! Client-side invoke tests exercising the `InvokeSender` API.

use rs_matter::dm::clusters::app::on_off::OnOffClient as _;
use rs_matter::error::ErrorCode;
use rs_matter::im::CmdDataTag;
use rs_matter::im::{ImClient, TxOutcome};
use rs_matter::tlv::{TLVTag, TLVWrite};
use rs_matter::utils::futures::{block_on, select, Coalesce};

use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

#[test]
fn test_client_invoke_sender_non_chunked() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let exchange = im.initiate_exchange().await?;
            let mut sender = exchange.invoke_sender(None).await?;

            // Drive the retransmit loop until the framework hands us
            // the first response chunk.
            let mut chunk = loop {
                match sender.tx().await? {
                    TxOutcome::BuildRequest(builder) => {
                        sender = builder
                            .suppress_response(false)?
                            .timed_request(false)?
                            .invoke_requests()?
                            .push()?
                            .path(0, echo_cluster::ID, echo_cluster::Commands::EchoReq as u32)?
                            .data(|w| {
                                // EchoReq body: anonymous TLV u8 retagged at
                                // CmdDataTag::Data — same on-wire form as the
                                // existing invoke test (`[0x04, 5u8]`).
                                Ok(w.u8(&TLVTag::Context(CmdDataTag::Data as u8), 5)?)
                            })?
                            .end()? // close CmdData entry
                            .end()? // close InvokeRequests array
                            .end()?; // close InvokeRequestMessage → InvokeSender
                    }
                    TxOutcome::GotResponse(c) => break c,
                }
            };

            // Iterate the response-chunk loop. Non-chunked EchoReq
            // gives exactly one chunk before `complete()` returns None.
            let mut chunk_count = 0u32;
            let mut got_response = false;
            loop {
                chunk_count += 1;
                {
                    // `response()` returns `Option` — `None` for
                    // DefaultSuccess (status-only) commands; EchoReq
                    // is *not* DefaultSuccess so we expect `Some`.
                    let resp = chunk
                        .response()?
                        .expect("EchoReq has a real InvokeResponse");
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

/// A command without a response that the peer refuses, as it has no ACL entry for us:
/// the status of the command (`UnsupportedAccess`) is the error.
#[test]
fn test_client_no_data_command_refused() {
    init_env_logger();

    let im = new_default_runner();
    // No `add_default_acl()`
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let exchange = im.initiate_exchange().await?;
            let err = exchange
                .on_off()
                .on(1)
                .await
                .expect_err("a refused command should be an error");
            assert_eq!(err.code(), ErrorCode::UnsupportedAccess);

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}

/// A command without a response to an endpoint the peer does not have: the status of
/// the command (`UnsupportedEndpoint`, i.e. `EndpointNotFound`) is the error.
#[test]
fn test_client_no_data_command_missing_endpoint() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let exchange = im.initiate_exchange().await?;
            let err = exchange
                .on_off()
                .on(99)
                .await
                .expect_err("a command to a missing endpoint should be an error");
            assert_eq!(err.code(), ErrorCode::EndpointNotFound);

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}

/// Commands without a response that the peer succeeds are `Ok`.
#[test]
fn test_client_no_data_command_succeeded() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let exchange = im.initiate_exchange().await?;
            exchange.on_off().on(1).await?;

            let exchange = im.initiate_exchange().await?;
            exchange.on_off().off(1).await?;

            let exchange = im.initiate_exchange().await?;
            exchange.on_off().toggle(1).await?;

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}
