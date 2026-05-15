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

//! Client-side subscribe tests exercising the `SubscribeSender` API
//! and the establishment-phase response handling
//! (`SubscribePrimingChunk::complete` →
//! [`SubscribeOutcome::Established`]).

use embassy_futures::block_on;
use embassy_futures::select::select;

use rs_matter::im::client::{ImClient, SubscribeOutcome, TxOutcome};
use rs_matter::im::{AttrPath, GenericPath};
use rs_matter::utils::select::Coalesce;

use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

/// `SubscribeSender::tx` + priming-chunk loop + terminal
/// `SubscribeEstablished`. Mirrors `test_client_read_sender_non_chunked`
/// but on the subscribe path: one priming `ReportData` chunk for the
/// single concrete attribute, followed by the `SubscribeResponse`
/// carrying `subscription_id` + `max_int`.
#[test]
fn test_client_subscribe_sender_non_chunked() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let exchange = im.initiate_exchange().await?;
            let mut sender = exchange.subscribe_sender().await?;

            let path = AttrPath::from_gp(&GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
            ));
            let paths = [path];

            // Drive the retransmit loop. `min_int_floor=0`,
            // `max_int_ceil=60` are bounds the test responder
            // accepts; `keep_subs=true` is the typical client value.
            let mut chunk = loop {
                match sender.tx().await? {
                    TxOutcome::BuildRequest(builder) => {
                        sender = builder
                            .keep_subs(true)?
                            .min_int_floor(0)?
                            .max_int_ceil(60)?
                            .attr_requests_from(&paths)?
                            .fabric_filtered(false)?
                            .end()?;
                    }
                    TxOutcome::GotResponse(c) => break c,
                }
            };

            // One concrete attribute → one priming ReportData chunk →
            // SubscribeResponse. Walk the outcome enum.
            let mut chunk_count = 0u32;
            let mut attr_count = 0u32;
            let established = loop {
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
                    SubscribeOutcome::NextChunk(next) => chunk = next,
                    SubscribeOutcome::Established(est) => break est,
                }
            };

            assert_eq!(
                chunk_count, 1,
                "Single-attr subscribe should have 1 priming chunk"
            );
            assert_eq!(attr_count, 1, "Should have received 1 attribute report");
            assert_ne!(
                established.subscription_id, 0,
                "Subscription id should be non-zero"
            );
            assert!(
                established.max_int >= 40,
                "Server should clamp max_int to at least 40s (saw {})",
                established.max_int
            );

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}

/// Chunked wildcard subscribe — mirrors
/// `test_client_read_sender_chunked_wildcard`. Subscribing to every
/// attribute on every endpoint forces the priming-read side of the
/// establishment to chunk; the test verifies the chunk loop on
/// [`SubscribePrimingChunk`] correctly iterates and lands on the
/// terminal [`SubscribeOutcome::Established`].
#[test]
fn test_client_subscribe_sender_chunked_wildcard() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let exchange = im.initiate_exchange().await?;
            let mut sender = exchange.subscribe_sender().await?;

            let path = AttrPath::from_gp(&GenericPath::new(None, None, None));
            let paths = [path];

            let mut chunk = loop {
                match sender.tx().await? {
                    TxOutcome::BuildRequest(builder) => {
                        sender = builder
                            .keep_subs(true)?
                            .min_int_floor(0)?
                            .max_int_ceil(60)?
                            .attr_requests_from(&paths)?
                            .fabric_filtered(false)?
                            .end()?;
                    }
                    TxOutcome::GotResponse(c) => break c,
                }
            };

            let mut chunk_count = 0u32;
            let mut attr_count = 0u32;
            let established = loop {
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
                    SubscribeOutcome::NextChunk(next) => chunk = next,
                    SubscribeOutcome::Established(est) => break est,
                }
            };

            assert!(
                chunk_count > 1,
                "Wildcard subscribe priming should chunk (got {})",
                chunk_count
            );
            assert!(
                attr_count > 1,
                "Wildcard subscribe should report many attributes (got {})",
                attr_count
            );
            assert_ne!(established.subscription_id, 0);

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}
