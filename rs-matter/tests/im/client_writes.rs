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

//! Client-side write tests exercising the tier-1 `WriteTxn` API.

use either::Either;
use embassy_futures::block_on;
use embassy_futures::select::select;

use rs_matter::im::client::ImClient;
use rs_matter::im::{AttrDataTag, IMStatusCode};
use rs_matter::tlv::{TLVElement, TLVTag, ToTLV};
use rs_matter::utils::select::Coalesce;

use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

#[test]
fn test_client_write_txn() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let handler = im.handler();

    block_on(
        select(im.run(handler), async {
            let exchange = im.initiate_exchange().await?;
            let mut txn = exchange.write_txn(None).await?;

            // Encode a u16 value (0x0539) as anonymous TLV. Same wire
            // form as the snapshot-API test above.
            let value_tlv = [0x05, 0x39, 0x05];
            let value = TLVElement::new(&value_tlv);

            // Drive the retransmit loop.
            let handle = loop {
                match txn.tx().await? {
                    Either::Left(builder) => {
                        // Skip SuppressResponse + TimedRequest (implicit).
                        let entries = builder.write_requests()?;
                        // One AttrData entry: write echo_cluster::AttWrite on endpoint 0.
                        let entry = entries
                            .push()?
                            // Skip DataVersion (implicit) → state 2 via path().
                            .path(
                                0,
                                echo_cluster::ID,
                                echo_cluster::AttributesDiscriminants::AttWrite as u32,
                            )?
                            .data(|w| value.to_tlv(&TLVTag::Context(AttrDataTag::Data as u8), w))?
                            .end()?; // close AttrData → AttrDataArrayBuilder
                        txn = entry.end()?.end()?; // close array, close msg
                    }
                    Either::Right(h) => break h,
                }
            };

            // Inspect the parsed WriteResp.
            {
                let resp = handle.response()?;
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
            }

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}
