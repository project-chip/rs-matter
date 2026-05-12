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

//! Client-side read tests exercising `ImClient::read`, `ImClient::read_single`,
//! and `ImClient::read_single_attr`.
//!
//! These tests use the `E2eRunner` infrastructure to run a real server (with
//! the default E2eTestHandler) and then call `ImClient` methods directly on the
//! client-side exchange.

use embassy_futures::block_on;
use embassy_futures::select::select;

use rs_matter::im::client::ImClient;
use rs_matter::im::{AttrPath, AttrResp, GenericPath};
use rs_matter::utils::select::Coalesce;

use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

/// Test that a non-chunked read (single attribute) works correctly via `ImClient::read`.
#[test]
fn test_client_read_non_chunked() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let mut exchange = im.initiate_exchange().await?;

            let mut chunk_count = 0u32;
            let mut attr_count = 0u32;

            // Read a single attribute: echo cluster Att1 on endpoint 0
            let path = AttrPath::from_gp(&GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
            ));

            ImClient::read(&mut exchange, &[path], false, |report| {
                chunk_count += 1;

                if let Some(attr_reports) = &report.attr_reports {
                    for attr_resp in attr_reports.iter() {
                        if attr_resp.is_ok() {
                            attr_count += 1;
                        }
                    }
                }

                Ok(())
            })
            .await?;

            assert_eq!(
                chunk_count, 1,
                "Non-chunked read should have exactly 1 chunk"
            );
            assert_eq!(
                attr_count, 1,
                "Should have received exactly 1 attribute report"
            );

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}

/// Test that a chunked read (wildcard path reading all attributes) works correctly
/// via `ImClient::read`, receiving multiple chunks.
#[test]
fn test_client_read_chunked_wildcard() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let mut exchange = im.initiate_exchange().await?;

            let mut chunk_count = 0u32;
            let mut total_attr_count = 0u32;

            // Read all attributes on all endpoints — this will trigger chunking
            let path = AttrPath::from_gp(&GenericPath::new(None, None, None));

            ImClient::read(&mut exchange, &[path], false, |report| {
                chunk_count += 1;

                if let Some(attr_reports) = &report.attr_reports {
                    for attr_resp in attr_reports.iter() {
                        if attr_resp.is_ok() {
                            total_attr_count += 1;
                        }
                    }
                }

                Ok(())
            })
            .await?;

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

/// Test that `ImClient::read_single` works correctly with the callback-based `read`.
#[test]
fn test_client_read_single() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let mut exchange = im.initiate_exchange().await?;

            // Read echo cluster Att1 on endpoint 0
            let value = ImClient::read_single(
                &mut exchange,
                0,
                echo_cluster::ID,
                echo_cluster::AttributesDiscriminants::Att1 as u32,
                false,
                |resp| match resp {
                    AttrResp::Data(data) => Ok(data.data.u16()?),
                    AttrResp::Status(status) => {
                        panic!("Unexpected status response: {:?}", status.status);
                    }
                },
            )
            .await?;

            // EchoHandler returns 0x1234 for Att1 reads (see echo_cluster.rs)
            assert_eq!(value, 0x1234, "Att1 should return 0x1234");

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}

/// Test that `ImClient::read_single_attr` returns zero-copy response data.
#[test]
fn test_client_read_single_attr() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let mut exchange = im.initiate_exchange().await?;

            // Read echo cluster Att1 on endpoint 0
            let resp = ImClient::read_single_attr(
                &mut exchange,
                0,
                echo_cluster::ID,
                echo_cluster::AttributesDiscriminants::Att1 as u32,
                false,
            )
            .await?;

            match resp {
                AttrResp::Data(data) => {
                    let value = data.data.u16()?;
                    assert_eq!(value, 0x1234, "Att1 should return 0x1234");
                }
                AttrResp::Status(status) => {
                    panic!("Unexpected status response: {:?}", status.status);
                }
            }

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}
