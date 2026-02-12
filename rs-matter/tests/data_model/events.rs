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
use crate::common::e2e::test::E2eTest;
use crate::common::e2e::tlv::TLVTest;
use crate::common::e2e::ImEngine;
use crate::common::init_env_logger;
use crate::{event_data_path, event_data_req};

const WILDCARD_PATH: EventPath = EventPath::from_gp(&GenericPath::new(None, None, None));

#[test]
/// Event number filtering should.. filter events by number
fn test_read_event_filtered() {
    init_env_logger();

    let im = ImEngine::new_default();
    let handler = im.handler();

    im.add_default_acl();

    let ep0_event1 = GenericPath::new(Some(0), Some(echo_cluster::ID), Some(1));

    // Given events
    push_events(
        &im,
        &[
            // Both set to 0 event-no, because Events will assign new event-nos
            event_data_req!(ep0_event1, 0, 2, Some(&0x41u8)),
            event_data_req!(ep0_event1, 0, 2, Some(&0x42u8)),
            event_data_req!(ep0_event1, 0, 2, Some(&0x43u8)),
        ],
    );

    // Test 1: Simple read without any event number filters
    let input = &[WILDCARD_PATH.clone()];
    let expected = &[
        event_data_path!(ep0_event1, 0, 2, Some(&0x41u8)),
        event_data_path!(ep0_event1, 1, 2, Some(&0x42u8)),
        event_data_path!(ep0_event1, 2, 2, Some(&0x43u8)),
    ];
    im.test_one(&handler, TLVTest::read_events(input, expected));

    // Test 2: Add event filter, only single entry should be retrieved
    let event_filter = &[EventFilter {
        node: None,
        event_min: Some(1),
    }];
    let expected_only_one = &[
        // n.b. first event is no longer included
        event_data_path!(ep0_event1, 1, 2, Some(&0x42u8)),
        event_data_path!(ep0_event1, 2, 2, Some(&0x43u8)),
    ];

    im.test_one(
        &handler,
        TLVTest::read(
            TestReadReq {
                event_filters: Some(event_filter),
                ..TestReadReq::event_reqs(input)
            },
            TestReportDataMsg::event_reports(expected_only_one),
            ReplyProcessor::none,
        ),
    );
}

#[test]
fn test_subscribe_events() {
    init_env_logger();

    let im = ImEngine::new_default();
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
            // TODO(events): Without this unrelated back-n-forth the test hangs, I think
            //               something-something acks?
            &TLVTest::read(
                TestReadReq {
                    ..TestReadReq::event_reqs(&[WILDCARD_PATH.clone()])
                },
                TestReportDataMsg::event_reports(&[event_data_path!(ep0_event1, 0, 2, Some(&0x41u8))]),
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

    let im = ImEngine::new_default();
    let handler = im.handler();

    im.add_default_acl();

    let ep0_event1 = GenericPath::new(Some(0), Some(echo_cluster::ID), Some(1));

    // Given there are some large-payload events available to read
    push_events(&im, &[
            event_data_req!(ep0_event1, 0, 2, Some(&[1u8;256])),
            event_data_req!(ep0_event1, 0, 2, Some(&[2u8;256])),
            event_data_req!(ep0_event1, 0, 2, Some(&[3u8;256])),
    ]);

    im.test_all(
        &handler,
        [
            &TLVTest::read(
                TestReadReq::event_reqs(&[WILDCARD_PATH.clone()]),
                TestReportDataMsg {
                    event_reports: Some(&[
                    event_data_path!(ep0_event1, 0, 2, Some(&[1u8;256])),
                    event_data_path!(ep0_event1, 1, 2, Some(&[2u8;256])),
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
                    event_reports: Some(&[
                        event_data_path!(ep0_event1, 2, 2, Some(&[3u8;256])),
                    ]),
                    suppress_response: Some(true),
                    ..Default::default()
                },
                ReplyProcessor::none,
            ),
        ],
    );
}
fn push_events(im: &ImEngine, events: &[TestEventData]) {
    for ev in events {
        block_on(im.events
            .push(ev.path.clone(), ev.priority, |tw| -> Result<(), Error> {
                if let Some(data) = ev.data {
                    // TODO(events) the public API shouldn't require knowing about the tag index here
                    let mut b = [0u8; 2048];
                    let mut wb = WriteBuf::new(&mut b[0..]);
                    data.test_to_tlv(&TLVTag::Context(EventDataTag::Data as _), &mut wb)?;
                    let end = wb.get_tail();
                    tw.write_raw_data(b[..end].iter().copied())?;
                }
                Ok(())
            })
        ).unwrap();
    }
}
