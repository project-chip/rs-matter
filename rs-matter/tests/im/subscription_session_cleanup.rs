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

//! A failed subscription report must not remove sessions to its subscriber:
//! the transport expires a session whose peer stopped acknowledging, and any
//! other session, such as a newer one the peer just established, stays usable.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use core::num::NonZeroU8;

use rs_matter::crypto::{test_only_crypto, Crypto};
use rs_matter::error::Error;
use rs_matter::im::client::{ImClient, SubscribeOutcome, TxOutcome};
use rs_matter::im::encoding::ReportDataResp;
use rs_matter::im::{AttrPath, GenericPath, InteractionModelState, OpCode};
use rs_matter::persist::PERSISTENT_SUBSCRIPTIONS_START;
use rs_matter::tlv::{FromTLV, TLVElement};
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::{Address, MatterRemoteService};
use rs_matter::transport::session::{NocCatIds, ReservedSession, SessionMode};
use rs_matter::utils::futures::{block_on, select, Either};
use rs_matter::utils::timers::{Duration, Timer};
use rs_matter::Matter;

use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::{new_default_runner, E2eRunner, E2E_EVENTS_BUF_SIZE, TEST_PEER_ID};
use crate::common::{init_env_logger, run_device_controller, MemKvBlobStore};

const FABRIC: NonZeroU8 = NonZeroU8::new(1).unwrap();
const SERVER_ID: u64 = 123456;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// The subscriber's address cannot be resolved, so no exchange is opened.
    Resolve,
    /// The subscriber answers the report with an unexpected message.
    BadResponse,
    /// The subscriber never acknowledges the report.
    Unacknowledged,
}

async fn persist_subscription(im: &E2eRunner<impl Crypto>, kv: &MemKvBlobStore) -> u32 {
    let mut subscription_id = 0;
    run_device_controller(
        im.run_with(im.handler(), &im.state, kv.clone(), false),
        async {
            let paths = [AttrPath::from_gp(&GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
            ))];
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
                    TxOutcome::GotResponse(chunk) => break chunk,
                }
            };
            loop {
                match chunk.complete().await? {
                    SubscribeOutcome::NextChunk(next) => chunk = next,
                    SubscribeOutcome::Established(established) => {
                        subscription_id = established.subscription_id;
                        break;
                    }
                }
            }
            // SubscribeResponse can precede the server's persistence commit.
            while !kv.contains_key(PERSISTENT_SUBSCRIPTIONS_START) {
                futures_lite::future::yield_now().await;
            }
            Ok(())
        },
    )
    .await
    .unwrap();
    subscription_id
}

fn add_case_session(
    matter: &Matter<'_>,
    local: u64,
    peer: u64,
    address: Address,
) -> Result<(), Error> {
    let mut session = ReservedSession::reserve_now(matter, test_only_crypto())?;
    session.update(
        local,
        peer,
        2,
        2,
        address,
        SessionMode::Case {
            fab_idx: FABRIC,
            cat_ids: NocCatIds::default(),
        },
        None,
        None,
        None,
        None,
    )?;
    session.complete();
    Ok(())
}

async fn receive_report<'a>(
    client: &'a Matter<'a>,
    subscription_id: u32,
) -> Result<Exchange<'a>, Error> {
    let mut exchange = Exchange::accept(client).await?;
    exchange.recv_fetch().await?;
    {
        let rx = exchange.rx()?;
        assert_eq!(rx.meta().proto_opcode, OpCode::ReportData as u8);
        let report = ReportDataResp::from_tlv(&TLVElement::new(rx.payload()))?;
        assert_eq!(report.subscription_id, Some(subscription_id));
        assert_eq!(
            report
                .attrs::<u16>(
                    echo_cluster::ID,
                    echo_cluster::AttributesDiscriminants::Att1 as u32
                )
                .map(|(endpoint, value)| (endpoint, value.unwrap()))
                .collect::<Vec<_>>(),
            [(0, 0x1234)]
        );
    }
    exchange.rx_done()?;
    Ok(exchange)
}

fn session_cleanup(failure: Failure) {
    init_env_logger();
    let im = new_default_runner();
    im.add_default_acl();
    let kv = MemKvBlobStore::default();

    block_on(async {
        let test = async {
            let subscription_id = persist_subscription(&im, &kv).await;
            let state: InteractionModelState<3, E2E_EVENTS_BUF_SIZE> = InteractionModelState::new();
            run_device_controller(
                im.run_with_setup(im.handler(), &state, kv.clone(), true, || match failure {
                    Failure::Resolve => im.matter.reset_transport(),
                    Failure::BadResponse => Ok(()),
                    Failure::Unacknowledged => {
                        im.lose_remote_tx(true);
                        Ok(())
                    }
                }),
                async {
                    let responder = im.matter.transport().mdns_responder();

                    let (old_session, mut old_report) = match failure {
                        Failure::Resolve => {
                            let service = responder.wait_resolve_request().await;
                            assert!(matches!(
                                service,
                                MatterRemoteService::Operational {
                                    node_id: TEST_PEER_ID,
                                    ..
                                }
                            ));
                            (None, None)
                        }
                        Failure::BadResponse => {
                            let probe = Exchange::initiate(
                                &im.matter,
                                test_only_crypto(),
                                FABRIC,
                                TEST_PEER_ID,
                            )
                            .await?;
                            let mut report =
                                receive_report(im.matter_client(), subscription_id).await?;
                            report.acknowledge().await?;
                            (Some(probe), Some(report))
                        }
                        Failure::Unacknowledged => {
                            let probe = Exchange::initiate(
                                &im.matter,
                                test_only_crypto(),
                                FABRIC,
                                TEST_PEER_ID,
                            )
                            .await?;
                            // Once the device has tried to send the report, its
                            // exchange is bound to the old session.
                            while im.lost_remote_tx() == 0 {
                                futures_lite::future::yield_now().await;
                            }
                            (Some(probe), None)
                        }
                    };

                    // Model an inbound CASE handshake completing while the
                    // restored subscription's resolve/report is still pending.
                    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
                    let address = match failure {
                        Failure::Resolve => Address::Udp(address),
                        // TCP wins a peer lookup even when the failing UDP
                        // exchange refreshes its session's last-use timestamp.
                        // The idle probe needs no TCP transport implementation.
                        Failure::BadResponse | Failure::Unacknowledged => Address::Tcp(address),
                    };
                    add_case_session(&im.matter, SERVER_ID, TEST_PEER_ID, address)?;
                    add_case_session(im.matter_client(), TEST_PEER_ID, SERVER_ID, address)?;
                    let new_session =
                        Exchange::initiate(&im.matter, test_only_crypto(), FABRIC, TEST_PEER_ID)
                            .await?;

                    match failure {
                        // No answer is deposited; the real resolver times out.
                        Failure::Resolve => assert!(im.matter.transport().mdns_resolve_in_flight()),
                        // Fail the old report with an unexpected answer. Whether
                        // the device acknowledges that answer does not matter here.
                        Failure::BadResponse => {
                            let report = old_report.as_mut().unwrap();
                            report
                                .init_send()
                                .await?
                                .complete(0, 0, OpCode::ReadRequest)?;
                        }
                        // The device runs out of MRP retransmissions on its own.
                        Failure::Unacknowledged => (),
                    }
                    // A resumed subscription is discarded after its first
                    // failed report. Wait for the normal persistence cleanup
                    // so the failed report and its session cleanup have finished.
                    while kv.contains_key(PERSISTENT_SUBSCRIPTIONS_START) {
                        futures_lite::future::yield_now().await;
                    }
                    assert!(!state
                        .subscriptions()
                        .has_subscription_for(FABRIC, TEST_PEER_ID));

                    assert!(
                        new_session.pending_retrans().is_ok(),
                        "failed subscription processing removed the new inbound CASE session"
                    );
                    if let Some(old_session) = old_session {
                        assert!(
                            old_session.pending_retrans().is_ok(),
                            "failed subscription processing removed the session it used"
                        );
                    }
                    // Only a session whose peer stopped acknowledging is expired.
                    let expired = im.matter.with_state(|state| {
                        state.sessions.iter().filter(|s| s.is_expired()).count()
                    });
                    assert_eq!(expired, usize::from(failure == Failure::Unacknowledged));
                    Ok(())
                },
            )
            .await
        };
        match select(test, Timer::after(Duration::from_secs(15))).await {
            Either::First(result) => result.unwrap(),
            Either::Second(()) => panic!("subscription session cleanup timed out"),
        }
    });
}

#[test]
fn resolve_failure_preserves_new_inbound_session() {
    session_cleanup(Failure::Resolve);
}

#[test]
fn bad_response_preserves_sessions() {
    session_cleanup(Failure::BadResponse);
}

#[test]
fn unacknowledged_report_only_expires_its_session() {
    session_cleanup(Failure::Unacknowledged);
}
