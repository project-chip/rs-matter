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

//! Client-side read tests exercising the `ReadSender` API.

use embassy_futures::block_on;
use embassy_futures::select::select;

use rs_matter::im::client::{ImClient, TxOutcome};
use rs_matter::im::{AttrPath, GenericPath};
use rs_matter::utils::select::Coalesce;

use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

/// `ReadSender::tx` + `ReadRespChunk`. Mirrors
/// `test_client_invoke_sender_non_chunked`.
#[test]
fn test_client_read_sender_non_chunked() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let exchange = im.initiate_exchange().await?;
            let mut sender = exchange.read_sender().await?;

            let path = AttrPath::from_gp(&GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
            ));
            let paths = [path];

            // Drive the retransmit loop.
            let mut chunk = loop {
                match sender.tx().await? {
                    TxOutcome::BuildRequest(builder) => {
                        sender = builder
                            .attr_requests_from(&paths)?
                            .fabric_filtered(false)?
                            .end()?;
                    }
                    TxOutcome::GotResponse(c) => break c,
                }
            };

            // Iterate response chunks. Non-chunked read → exactly one chunk.
            let mut chunk_count = 0u32;
            let mut attr_count = 0u32;
            loop {
                chunk_count += 1;
                {
                    let resp = chunk.response()?;
                    if let Some(attr_reports) = &resp.attr_reports {
                        for attr_resp in attr_reports.iter() {
                            if attr_resp.is_ok() {
                                attr_count += 1;
                            }
                        }
                    }
                }
                match chunk.complete().await? {
                    Some(next) => chunk = next,
                    None => break,
                }
            }

            assert_eq!(chunk_count, 1, "Non-chunked read should have 1 chunk");
            assert_eq!(attr_count, 1, "Should have received 1 attribute report");

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}

/// Chunked wildcard read — verifies the chunk loop on
/// `InvokeRespChunk` / `ReadRespChunk` correctly iterates multiple
/// chunks when the server signals `more_chunks=true`. Reading every
/// attribute on every endpoint should produce > 1 chunk and many
/// attribute reports.
#[test]
fn test_client_read_sender_chunked_wildcard() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let exchange = im.initiate_exchange().await?;
            let mut sender = exchange.read_sender().await?;

            // Wildcard path: every attribute on every endpoint.
            let path = AttrPath::from_gp(&GenericPath::new(None, None, None));
            let paths = [path];

            let mut chunk = loop {
                match sender.tx().await? {
                    TxOutcome::BuildRequest(builder) => {
                        sender = builder
                            .attr_requests_from(&paths)?
                            .fabric_filtered(false)?
                            .end()?;
                    }
                    TxOutcome::GotResponse(c) => break c,
                }
            };

            let mut chunk_count = 0u32;
            let mut total_attr_count = 0u32;
            loop {
                chunk_count += 1;
                {
                    let resp = chunk.response()?;
                    if let Some(attr_reports) = &resp.attr_reports {
                        for attr_resp in attr_reports.iter() {
                            if attr_resp.is_ok() {
                                total_attr_count += 1;
                            }
                        }
                    }
                }
                match chunk.complete().await? {
                    Some(next) => chunk = next,
                    None => break,
                }
            }

            assert!(
                chunk_count > 1,
                "Wildcard read should produce multiple chunks, got {}",
                chunk_count
            );
            assert!(
                total_attr_count > 100,
                "Wildcard read should return many attributes, got {}",
                total_attr_count
            );

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}
