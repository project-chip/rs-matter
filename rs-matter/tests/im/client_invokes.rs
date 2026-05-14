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

//! Client-side invoke tests exercising the tier-1 `InvokeTxn` API.

use either::Either;
use embassy_futures::block_on;
use embassy_futures::select::select;

use rs_matter::im::client::ImClient;
use rs_matter::im::CmdDataTag;
use rs_matter::tlv::{TLVTag, TLVWrite};
use rs_matter::utils::select::Coalesce;

use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

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
