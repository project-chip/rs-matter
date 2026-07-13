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

//! End-to-end proof of persistent subscriptions across a (simulated) reboot.
//!
//! A client subscribes to an attribute over CASE; the server persists the
//! subscription to a retained key-value store. The server is then torn down and
//! brought back up with a *fresh* subscription table but the *same* store — the
//! moral equivalent of the device rebooting with its flash intact. On the second
//! boot the server resumes the persisted subscription and, because a resumed
//! subscription is re-primed, promptly drives a `ReportData` back to the client
//! without the client having to re-subscribe.

use embassy_futures::block_on;
use embassy_futures::select::{select, Either};

use rs_matter::im::client::{ImClient, SubscribeOutcome, TxOutcome};
use rs_matter::im::{
    AttrPath, GenericPath, IMStatusCode, InteractionModelState, OpCode, StatusResp,
};
use rs_matter::persist::PERSISTENT_SUBSCRIPTIONS_START;
use rs_matter::transport::exchange::Exchange;
use rs_matter::utils::select::Coalesce;

use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::{new_default_runner, E2E_EVENTS_BUF_SIZE};
use crate::common::{init_env_logger, MemKvBlobStore};

use rs_matter::dm::clusters::net_comm::DummyNetworks;

/// Subscribe → persist → reboot the server (fresh table, same store) → resume →
/// the resumed subscription reports back to the still-connected client.
#[test]
fn test_subscription_survives_reboot() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();

    // A retained store, shared (via a cheap `Rc` clone) across both boots so that
    // what the first boot persists is what the second boot reads back.
    let kv = MemKvBlobStore::default();

    let path = AttrPath::from_gp(&GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    ));
    let paths = [path];

    // ---- Boot 1: subscribe and let the server persist the subscription. ----
    block_on(
        select(
            im.run_with(im.handler(), &im.state, kv.clone(), false),
            async {
                let exchange = im.initiate_exchange().await?;
                let mut sender = exchange.subscribe_sender().await?;

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

                let established = loop {
                    let _ = chunk.response()?;
                    match chunk.complete().await? {
                        SubscribeOutcome::NextChunk(next) => chunk = next,
                        SubscribeOutcome::Established(est) => break est,
                    }
                };

                assert_ne!(established.subscription_id, 0);

                // The client is `Established` the moment it receives the
                // `SubscribeResponse`, but the server persists the subscription
                // slightly *after* sending that response. Give the server task a
                // moment to run to completion before we tear boot 1 down.
                embassy_time::Timer::after(embassy_time::Duration::from_millis(200)).await;

                Ok(())
            },
        )
        .coalesce(),
    )
    .unwrap();

    // The subscription must now be on disk.
    assert!(
        kv.contains_key(PERSISTENT_SUBSCRIPTIONS_START),
        "boot 1 should have persisted the subscription"
    );

    // ---- Boot 2: a fresh subscription table, the same store. ----
    let state2: InteractionModelState<DummyNetworks, 3, E2E_EVENTS_BUF_SIZE> =
        InteractionModelState::new(DummyNetworks);

    // The resumed subscription is primed, so the server initiates a `ReportData`
    // to the client on its own. We accept that server-initiated exchange and
    // verify it is indeed a report — proof that the subscription survived the
    // reboot and delivered without the client re-subscribing.
    let got_report = block_on(async {
        let server = im.run_with(im.handler(), &state2, kv.clone(), true);
        let client = async {
            // The resumed subscription's report arrives on a server-initiated
            // exchange. Accept it, note the opcode, and answer with a
            // `StatusResponse(Success)` so the server sees the report delivered.
            let mut exchange = Exchange::accept(im.matter_client()).await?;
            exchange.recv_fetch().await?;
            let opcode = exchange.rx()?.meta().proto_opcode;
            exchange
                .send_with(|_, wb| {
                    StatusResp::write(wb, IMStatusCode::Success)?;
                    Ok(Some(OpCode::StatusResponse.into()))
                })
                .await?;
            Ok::<_, rs_matter::error::Error>(opcode)
        };

        match select(server, client).await {
            Either::First(r) => panic!("server exited before delivering a report: {r:?}"),
            Either::Second(result) => result.unwrap(),
        }
    });

    assert_eq!(
        got_report,
        OpCode::ReportData as u8,
        "the resumed subscription should have delivered a ReportData after reboot"
    );
}
