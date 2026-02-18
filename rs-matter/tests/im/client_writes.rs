/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

//! Client-side write tests exercising `ImClient::write`.

use embassy_futures::block_on;
use embassy_futures::select::select;

use rs_matter::im::client::ImClient;
use rs_matter::im::{AttrData, AttrPath, IMStatusCode};
use rs_matter::tlv::TLVElement;
use rs_matter::utils::select::Coalesce;

use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

/// Test that `ImClient::write` can write an attribute and receive a success response.
#[test]
fn test_client_write() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let mut exchange = im.initiate_exchange().await?;

            let path = AttrPath {
                endpoint: Some(0),
                cluster: Some(echo_cluster::ID),
                attr: Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
                ..Default::default()
            };

            // Encode a u16 value as anonymous TLV
            let value_tlv = [0x05, 0x39, 0x05]; // TLV u16 tag=anonymous, value=0x0539
            let attr = AttrData {
                data_ver: None,
                path,
                data: TLVElement::new(&value_tlv),
            };

            let resp = ImClient::write(&mut exchange, &[attr], None).await?;

            // Check that we got exactly one write response with Success status
            let mut status_count = 0u32;
            for status in resp.write_responses.iter() {
                let status = status.unwrap();
                assert_eq!(
                    status.status.status,
                    IMStatusCode::Success,
                    "Write should succeed"
                );
                status_count += 1;
            }

            assert_eq!(
                status_count, 1,
                "Should have exactly 1 write response status"
            );

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}
