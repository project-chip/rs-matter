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

use embassy_futures::block_on;
use rs_matter::error::Error;
use rs_matter::im::EventDataTag;
use rs_matter::im::EventFilter;
use rs_matter::im::EventPath;
use rs_matter::im::GenericPath;
use rs_matter::im::IMStatusCode;
use rs_matter::im::StatusResp;
use rs_matter::im::SubscribeResp;
use rs_matter::tlv::{TLVTag, TLVWrite};
use rs_matter::utils::storage::WriteBuf;

use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::im::events::TestEventData;
use crate::common::e2e::im::ReplyProcessor;
use crate::common::e2e::im::TestReadReq;
use crate::common::e2e::im::TestReportDataMsg;
use crate::common::e2e::im::TestSubscribeReq;
use crate::common::e2e::new_default_runner;
use crate::common::e2e::test::E2eTest;
use crate::common::e2e::tlv::TLVTest;
use crate::common::init_env_logger;
use crate::{event_data_path, event_data_req};

const WILDCARD_PATH: EventPath = EventPath::from_gp(&GenericPath::new(None, None, None));

#[test]
fn test_read_event_filtered() {
    init_env_logger();

    let im = new_default_runner();
    let handler = im.handler();

    im.add_default_acl();

    let ep0_event1 = GenericPath::new(Some(0), Some(echo_cluster::ID), Some(1));
    let ep1_event1 = GenericPath::new(Some(1), Some(echo_cluster::ID), Some(1));
    let ep1_event2 = GenericPath::new(Some(1), Some(echo_cluster::ID), Some(2));
    let cl2_ep0_event1 = GenericPath::new(Some(0), Some(2), Some(1));

    // Given events
    push_events(
        &im,
        &[
            // Event no set to 0 on all, because Events will assign these, starting at zero
            event_data_req!(ep0_event1, 0, 2, Some(&0x41u8)),
            event_data_req!(ep0_event1, 0, 2, Some(&0x42u8)),
            event_data_req!(ep0_event1, 0, 2, Some(&0x43u8)),
            event_data_req!(ep1_event1, 0, 2, Some(&0x44u8)),
            event_data_req!(ep1_event2, 0, 2, Some(&0x45u8)),
            event_data_req!(cl2_ep0_event1, 0, 2, Some(&0x46u8)),
        ],
    );

    // Test 1: Simple read without any filters returns all events
    im.test_one(
        &handler,
        TLVTest::read_events(
            &[WILDCARD_PATH.clone()],
            &[
                event_data_path!(ep0_event1, 0, 2, Some(&0x41u8)),
                event_data_path!(ep0_event1, 1, 2, Some(&0x42u8)),
                event_data_path!(ep0_event1, 2, 2, Some(&0x43u8)),
                event_data_path!(ep1_event1, 3, 2, Some(&0x44u8)),
                event_data_path!(ep1_event2, 4, 2, Some(&0x45u8)),
                event_data_path!(cl2_ep0_event1, 5, 2, Some(&0x46u8)),
            ],
        ),
    );

    // Test 2: Event number filtering excludes all events below the filter
    im.test_one(
        &handler,
        TLVTest::read(
            TestReadReq {
                event_filters: Some(&[EventFilter {
                    node: None,
                    event_min: Some(2),
                }]),
                ..TestReadReq::event_reqs(&[WILDCARD_PATH.clone()])
            },
            TestReportDataMsg::event_reports(&[
                // n.b. first two events excluded
                event_data_path!(ep0_event1, 2, 2, Some(&0x43u8)),
                event_data_path!(ep1_event1, 3, 2, Some(&0x44u8)),
                event_data_path!(ep1_event2, 4, 2, Some(&0x45u8)),
                event_data_path!(cl2_ep0_event1, 5, 2, Some(&0x46u8)),
            ]),
            ReplyProcessor::none,
        ),
    );

    // Test 3: Path filtering by endpoint
    im.test_one(
        &handler,
        TLVTest::read(
            TestReadReq {
                ..TestReadReq::event_reqs(&[EventPath {
                    node: None,
                    endpoint: Some(0),
                    cluster: None,
                    event: None,
                    is_urgent: None,
                }])
            },
            TestReportDataMsg::event_reports(&[
                // n.b. events that aren't from endpoint 0 are excluded
                event_data_path!(ep0_event1, 0, 2, Some(&0x41u8)),
                event_data_path!(ep0_event1, 1, 2, Some(&0x42u8)),
                event_data_path!(ep0_event1, 2, 2, Some(&0x43u8)),
                event_data_path!(cl2_ep0_event1, 5, 2, Some(&0x46u8)),
            ]),
            ReplyProcessor::none,
        ),
    );

    // Test 4: Path filtering by event id
    im.test_one(
        &handler,
        TLVTest::read(
            TestReadReq {
                ..TestReadReq::event_reqs(&[EventPath {
                    node: None,
                    endpoint: None,
                    cluster: None,
                    event: Some(1),
                    is_urgent: None,
                }])
            },
            TestReportDataMsg::event_reports(&[
                // n.b. only events with id 1
                event_data_path!(ep0_event1, 0, 2, Some(&0x41u8)),
                event_data_path!(ep0_event1, 1, 2, Some(&0x42u8)),
                event_data_path!(ep0_event1, 2, 2, Some(&0x43u8)),
                event_data_path!(ep1_event1, 3, 2, Some(&0x44u8)),
                event_data_path!(cl2_ep0_event1, 5, 2, Some(&0x46u8)),
            ]),
            ReplyProcessor::none,
        ),
    );

    // Test 5: Path filtering by node id
    im.test_one(
        &handler,
        TLVTest::read(
            TestReadReq {
                ..TestReadReq::event_reqs(&[EventPath {
                    node: Some(1337),
                    endpoint: None,
                    cluster: None,
                    event: None,
                    is_urgent: None,
                }])
            },
            TestReportDataMsg::event_reports(&[
                // no events on node 1337
            ]),
            ReplyProcessor::none,
        ),
    );

    // Test 6: Path filtering by cluster
    im.test_one(
        &handler,
        TLVTest::read(
            TestReadReq {
                ..TestReadReq::event_reqs(&[EventPath {
                    node: None,
                    endpoint: None,
                    cluster: Some(2),
                    event: None,
                    is_urgent: None,
                }])
            },
            TestReportDataMsg::event_reports(&[event_data_path!(
                cl2_ep0_event1,
                5,
                2,
                Some(&0x46u8)
            )]),
            ReplyProcessor::none,
        ),
    );
}

#[test]
fn test_subscribe_events() {
    init_env_logger();

    let im = new_default_runner();
    let handler = im.handler();

    im.add_default_acl();

    let ep0_event1 = GenericPath::new(Some(0), Some(echo_cluster::ID), Some(1));

    // Given there is 1 event published so far
    push_events(&im, &[event_data_req!(ep0_event1, 0, 2, Some(&0x41u8))]);

    im.test_all(
        &handler,
        [
            // When we initially subscribe, we get the one already-stored event
            &TLVTest::subscribe(
                TestSubscribeReq {
                    min_int_floor: 0,
                    max_int_ceil: 1,
                    ..TestSubscribeReq::event_reqs(&[WILDCARD_PATH.clone()])
                },
                TestReportDataMsg {
                    subscription_id: Some(1),
                    event_reports: Some(&[event_data_path!(ep0_event1, 0, 2, Some(&0x41u8))]),
                    ..Default::default()
                },
                ReplyProcessor::none,
            ) as &dyn E2eTest,
            &TLVTest {
                delay_ms: Some(1),
                ..TLVTest::subscribe_final(
                    StatusResp {
                        status: IMStatusCode::Success,
                    },
                    SubscribeResp {
                        subs_id: 1,
                        max_int: 40,
                        ..Default::default()
                    },
                    ReplyProcessor::none,
                )
            },
            // Without this unrelated back-n-forth the test hangs, should investigate and fix at some point
            &TLVTest::read(
                TestReadReq {
                    ..TestReadReq::event_reqs(&[WILDCARD_PATH.clone()])
                },
                TestReportDataMsg::event_reports(&[event_data_path!(
                    ep0_event1,
                    0,
                    2,
                    Some(&0x41u8)
                )]),
                ReplyProcessor::none,
            ),
            &TLVTest::subscription_report(
                || -> Result<(), Error> {
                    push_events(&im, &[event_data_req!(ep0_event1, 0, 2, Some(&0x42u8))]);
                    im.subscriptions
                        .notify_event_emitted(0, echo_cluster::ID, 2);
                    Ok(())
                },
                // Holy crap y'all. All this ceremony is really about these few lines:
                // We should get notified of the new event and we should *only* get the new event, note that the
                // payload is 0x42, matching the new event we emitted, vs 0x41 for the first event that we already saw.
                TestReportDataMsg {
                    subscription_id: Some(1),
                    event_reports: Some(&[event_data_path!(ep0_event1, 1, 2, Some(&0x42u8))]),
                    ..Default::default()
                },
                ReplyProcessor::none,
                StatusResp {
                    status: IMStatusCode::Success,
                },
            ),
        ],
    );
}

#[test]
fn test_long_read_events() {
    init_env_logger();

    let im = new_default_runner();
    let handler = im.handler();

    im.add_default_acl();

    let ep0_event1 = GenericPath::new(Some(0), Some(echo_cluster::ID), Some(1));

    // Given there are some large-payload events available to read
    push_events(
        &im,
        &[
            event_data_req!(ep0_event1, 0, 2, Some(&[1u8; 256])),
            event_data_req!(ep0_event1, 0, 2, Some(&[2u8; 256])),
            event_data_req!(ep0_event1, 0, 2, Some(&[3u8; 256])),
        ],
    );

    im.test_all(
        &handler,
        [
            &TLVTest::read(
                TestReadReq::event_reqs(&[WILDCARD_PATH.clone()]),
                TestReportDataMsg {
                    event_reports: Some(&[
                        event_data_path!(ep0_event1, 0, 2, Some(&[1u8; 256])),
                        event_data_path!(ep0_event1, 1, 2, Some(&[2u8; 256])),
                    ]),
                    more_chunks: Some(true),
                    ..Default::default()
                },
                ReplyProcessor::none,
            ) as &dyn E2eTest,
            &TLVTest::continue_report(
                StatusResp {
                    status: IMStatusCode::Success,
                },
                TestReportDataMsg {
                    event_reports: Some(&[event_data_path!(ep0_event1, 2, 2, Some(&[3u8; 256]))]),
                    suppress_response: Some(true),
                    ..Default::default()
                },
                ReplyProcessor::none,
            ),
        ],
    );
}
fn push_events<C>(im: &crate::common::e2e::E2eRunner<C>, events: &[TestEventData])
where
    C: rs_matter::crypto::Crypto,
{
    for ev in events {
        block_on(
            im.events
                .push(ev.path.clone(), ev.priority, |tw| -> Result<(), Error> {
                    if let Some(data) = ev.data {
                        let mut b = [0u8; 2048];
                        let mut wb = WriteBuf::new(&mut b[0..]);
                        data.test_to_tlv(&TLVTag::Context(EventDataTag::Data as _), &mut wb)?;
                        let end = wb.get_tail();
                        tw.write_raw_data(b[..end].iter().copied())?;
                    }
                    Ok(())
                }),
        )
        .unwrap();
    }
}
