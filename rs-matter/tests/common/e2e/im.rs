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

use bitflags::bitflags;

use rs_matter::error::Error;
use rs_matter::interaction_model::core::{OpCode, PROTO_ID_INTERACTION_MODEL};
use rs_matter::interaction_model::messages::ib::{
    AttrPath, AttrResp, AttrStatus, DataVersionFilter, EventFilter, EventPath,
};
use rs_matter::interaction_model::messages::msg::{ReportDataMsg, WriteReqTag};
use rs_matter::tlv::{FromTLV, Slice, TLVElement, TLVTag, TLVWrite, TLVWriter, ToTLV};
use rs_matter::transport::exchange::MessageMeta;
use rs_matter::utils::storage::WriteBuf;

use super::tlv::{TLVTest, TestToTLV};

use attributes::{TestAttrData, TestAttrResp};
use commands::{TestCmdData, TestCmdResp};

pub mod attributes;
pub mod commands;
pub mod echo_cluster;
pub mod handler;

/// A `ReadReq` alternative more suitable for testing.
///
/// Unlike `ReadReq`, `TestReadReq` uses regular Rust slices where
/// `ReadReq` uses `TLVArray` instances.
#[derive(Debug, Default, Clone, ToTLV)]
pub struct TestReadReq<'a> {
    pub attr_requests: Option<&'a [AttrPath]>,
    pub event_requests: Option<&'a [EventPath]>,
    pub event_filters: Option<&'a [EventFilter]>,
    pub fabric_filtered: bool,
    pub dataver_filters: Option<&'a [DataVersionFilter]>,
}

impl<'a> TestReadReq<'a> {
    /// Create a new `TestReadReq` instance.
    pub const fn new() -> Self {
        Self {
            attr_requests: None,
            event_requests: None,
            event_filters: None,
            fabric_filtered: false,
            dataver_filters: None,
        }
    }

    /// Create a new `TestReadReq` instance with the provided attribute requests.
    pub const fn reqs(reqs: &'a [AttrPath]) -> Self {
        Self {
            attr_requests: Some(reqs),
            ..Self::new()
        }
    }
}

/// A `ReadResp` alternative more suitable for testing.
///
/// Unlike `ReadResp`, `TestReadResp` uses regular Rust slices where
/// `ReadResp` uses `TLVArray` instances. Also, it utilizes `TestReadData`
/// for the write requests, where `ReadResp` uses `AttrData` instances.
#[derive(Debug, Default, Clone)]
pub struct TestWriteReq<'a> {
    pub suppress_response: Option<bool>,
    pub timed_request: Option<bool>,
    pub write_requests: &'a [TestAttrData<'a>],
    pub more_chunked: Option<bool>,
}

impl<'a> TestWriteReq<'a> {
    /// Create a new `TestWriteReq` instance.
    pub const fn new() -> Self {
        Self {
            suppress_response: None,
            timed_request: None,
            write_requests: &[],
            more_chunked: None,
        }
    }

    /// Create a new `TestWriteReq` instance with the provided write requests.
    pub const fn reqs(reqs: &'a [TestAttrData<'a>]) -> Self {
        Self {
            write_requests: reqs,
            suppress_response: Some(true),
            ..Self::new()
        }
    }
}

impl TestToTLV for TestWriteReq<'_> {
    fn test_to_tlv(&self, tag: &TLVTag, tw: &mut TLVWriter) -> Result<(), Error> {
        tw.start_struct(tag)?;

        if let Some(supress_response) = self.suppress_response {
            tw.bool(
                &TLVTag::Context(WriteReqTag::SuppressResponse as _),
                supress_response,
            )?;
        }

        if let Some(timed_request) = self.timed_request {
            tw.bool(
                &TLVTag::Context(WriteReqTag::TimedRequest as _),
                timed_request,
            )?;
        }

        tw.start_array(&TLVTag::Context(WriteReqTag::WriteRequests as _))?;
        for write_request in self.write_requests {
            write_request.test_to_tlv(&TLVTag::Anonymous, tw)?;
        }
        tw.end_container()?;

        if let Some(more_chunked) = self.more_chunked {
            tw.bool(
                &TLVTag::Context(WriteReqTag::MoreChunked as _),
                more_chunked,
            )?;
        }

        tw.end_container()?;

        Ok(())
    }
}

/// A `WriteResp` alternative more suitable for testing.
///
/// Unlike `WriteResp`, `TestWriteResp` uses regular Rust slices where
/// `WriteResp` uses `TLVArray` instances.
#[derive(ToTLV, Debug, Default, Clone)]
#[tlvargs(lifetime = "'a")]
pub struct TestWriteResp<'a> {
    pub write_responses: Slice<'a, AttrStatus>,
}

impl<'a> TestWriteResp<'a> {
    /// Create a new `TestWriteResp` instance with the provided write responses.
    pub const fn resp(write_responses: &'a [AttrStatus]) -> Self {
        Self { write_responses }
    }
}

/// A `SubscribeResp` alternative more suitable for testing.
///
/// Unlike `SubscribeResp`, `TestSubscribeResp` uses regular Rust slices where
/// `SubscribeResp` uses `TLVArray` instances.
#[derive(Debug, Default, Clone, ToTLV)]
pub struct TestSubscribeReq<'a> {
    pub keep_subs: bool,
    pub min_int_floor: u16,
    pub max_int_ceil: u16,
    pub attr_requests: Option<&'a [AttrPath]>,
    pub event_requests: Option<&'a [EventPath]>,
    pub event_filters: Option<&'a [EventFilter]>,
    // The Context Tags are discontiguous for some reason
    pub _dummy: Option<bool>,
    pub fabric_filtered: bool,
    pub dataver_filters: Option<&'a [DataVersionFilter]>,
}

impl<'a> TestSubscribeReq<'a> {
    /// Create a new `TestSubscribeReq` instance.
    pub const fn new() -> Self {
        Self {
            keep_subs: false,
            min_int_floor: 0,
            max_int_ceil: 0,
            attr_requests: None,
            event_requests: None,
            event_filters: None,
            _dummy: None,
            fabric_filtered: false,
            dataver_filters: None,
        }
    }

    /// Create a new `TestSubscribeReq` instance with the provided attribute requests.
    pub const fn reqs(reqs: &'a [AttrPath]) -> Self {
        Self {
            attr_requests: Some(reqs),
            ..Self::new()
        }
    }
}

/// A `ReportDataMsg` alternative more suitable for testing.
///
/// Unlike `ReportDataMsg`, `TestReportDataMsg` uses regular Rust slices where
/// `ReportDataMsg` uses `TLVArray` instances. Also, it utilizes `TestAttrResp`
/// for the attribute reports, where `ReportDataMsg` uses `AttrResp` instances.
#[derive(Debug, Default, Clone)]
pub struct TestReportDataMsg<'a> {
    pub subscription_id: Option<u32>,
    pub attr_reports: Option<&'a [TestAttrResp<'a>]>,
    // TODO
    pub event_reports: Option<bool>,
    pub more_chunks: Option<bool>,
    pub suppress_response: Option<bool>,
}

impl<'a> TestReportDataMsg<'a> {
    /// Create a new `TestReportDataMsg` instance.
    pub const fn new() -> Self {
        Self {
            subscription_id: None,
            attr_reports: None,
            event_reports: None,
            more_chunks: None,
            suppress_response: None,
        }
    }

    /// Create a new `TestReportDataMsg` instance with the provided attribute reports.
    pub const fn reports(reports: &'a [TestAttrResp<'a>]) -> Self {
        Self {
            attr_reports: Some(reports),
            suppress_response: Some(true),
            ..Self::new()
        }
    }
}

impl<'a> TestToTLV for TestReportDataMsg<'a> {
    fn test_to_tlv(&self, tag: &TLVTag, tw: &mut TLVWriter) -> Result<(), Error> {
        tw.start_struct(tag)?;

        if let Some(subscription_id) = self.subscription_id {
            tw.u32(&TLVTag::Context(0), subscription_id)?;
        }

        if let Some(attr_reports) = self.attr_reports {
            tw.start_array(&TLVTag::Context(1))?;
            for attr_report in attr_reports {
                attr_report.test_to_tlv(&TLVTag::Anonymous, tw)?;
            }
            tw.end_container()?;
        }

        if let Some(event_reports) = self.event_reports {
            tw.bool(&TLVTag::Context(2), event_reports)?;
        }

        if let Some(more_chunks) = self.more_chunks {
            tw.bool(&TLVTag::Context(3), more_chunks)?;
        }

        if let Some(suppress_response) = self.suppress_response {
            tw.bool(&TLVTag::Context(4), suppress_response)?;
        }

        tw.end_container()?;

        Ok(())
    }
}

/// A `InvReq` alternative more suitable for testing.
///
/// Unlike `InvReq`, `TestInvReq` uses regular Rust slices where
/// `InvReq` uses `TLVArray` instances. Also, it utilizes `TestCmdData`
/// for the invocation requests, where `InvReq` uses `CmdData` instances.
#[derive(Debug, Default, Clone)]
pub struct TestInvReq<'a> {
    pub suppress_response: Option<bool>,
    pub timed_request: Option<bool>,
    pub inv_requests: Option<&'a [TestCmdData<'a>]>,
}

impl<'a> TestInvReq<'a> {
    /// Create a new `TestInvReq` instance.
    pub const fn new() -> Self {
        Self {
            suppress_response: None,
            timed_request: None,
            inv_requests: None,
        }
    }

    /// Create a new `TestInvReq` instance with the provided command requests.
    pub const fn reqs(reqs: &'a [TestCmdData<'a>]) -> Self {
        Self {
            inv_requests: Some(reqs),
            ..Self::new()
        }
    }
}

impl<'a> TestToTLV for TestInvReq<'a> {
    fn test_to_tlv(&self, tag: &TLVTag, tw: &mut TLVWriter) -> Result<(), Error> {
        tw.start_struct(tag)?;

        if let Some(suppress_response) = self.suppress_response {
            tw.bool(&TLVTag::Context(0), suppress_response)?;
        }

        if let Some(timed_request) = self.timed_request {
            tw.bool(&TLVTag::Context(1), timed_request)?;
        }

        if let Some(inv_requests) = self.inv_requests {
            tw.start_array(&TLVTag::Context(2))?;
            for inv_request in inv_requests {
                inv_request.test_to_tlv(&TLVTag::Anonymous, tw)?;
            }
            tw.end_container()?;
        }

        tw.end_container()?;

        Ok(())
    }
}

/// An `InvResp` alternative more suitable for testing.
///
/// Unlike `InvResp`, `TestInvResp` uses regular Rust slices where
/// `InvResp` uses `TLVArray` instances. Also, it utilizes `TestCmdResp`
/// for the invocation responses, where `InvResp` uses `CmdResp` instances.
#[derive(Debug, Default, Clone)]
pub struct TestInvResp<'a> {
    pub suppress_response: Option<bool>,
    pub inv_responses: Option<&'a [TestCmdResp<'a>]>,
}

impl<'a> TestInvResp<'a> {
    /// Create a new `TestInvResp` instance with the provided command responses.
    pub const fn resp(inv_responses: &'a [TestCmdResp<'a>]) -> Self {
        Self {
            suppress_response: Some(false),
            inv_responses: Some(inv_responses),
        }
    }
}

impl<'a> TestToTLV for TestInvResp<'a> {
    fn test_to_tlv(&self, tag: &TLVTag, tw: &mut TLVWriter) -> Result<(), Error> {
        tw.start_struct(tag)?;

        if let Some(suppress_response) = self.suppress_response {
            tw.bool(&TLVTag::Context(0), suppress_response)?;
        }

        if let Some(inv_responses) = self.inv_responses {
            tw.start_array(&TLVTag::Context(1))?;
            for inv_response in inv_responses {
                inv_response.test_to_tlv(&TLVTag::Anonymous, tw)?;
            }
            tw.end_container()?;
        }

        tw.end_container()?;

        Ok(())
    }
}

bitflags! {
    /// Flags for trimming data from reply payloads.
    ///
    /// Useful when the E2E tests do now want to assert on e.g.
    /// dataver, and/or concrete data returned by the Matter server.
    ///
    /// Currently, only trimming IM `ReportData` payloads is supported,
    /// but if the end-to-end tests grow, this could be expanded to other IM messages.
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ReplyProcessor: u8 {
        const REMOVE_ATTRDATA_DATAVER = 0b01;
        const REMOVE_ATTRDATA_VALUE = 0b10;
    }
}

impl ReplyProcessor {
    /// Remove the dataver and/or the data value from the `AttrData` payload, if so requested
    pub fn process(&self, element: &TLVElement, buf: &mut [u8]) -> Result<usize, Error> {
        let mut wb = WriteBuf::new(buf);
        let mut tw = TLVWriter::new(&mut wb);

        if self.is_empty() {
            element.to_tlv(&TLVTag::Anonymous, &mut tw)?;

            return Ok(wb.get_tail());
        }

        let report_data = ReportDataMsg::from_tlv(element)?;

        tw.start_struct(&TLVTag::Anonymous)?;

        if let Some(subscription_id) = report_data.subscription_id {
            tw.u32(&TLVTag::Context(0), subscription_id)?;
        }

        if let Some(attr_reports) = report_data.attr_reports {
            tw.start_array(&TLVTag::Context(1))?;

            for attr_report in attr_reports {
                let mut attr_report = attr_report?;

                if let AttrResp::Data(data) = &mut attr_report {
                    if self.contains(Self::REMOVE_ATTRDATA_DATAVER) {
                        data.data_ver = None;
                    }

                    if self.contains(Self::REMOVE_ATTRDATA_VALUE) {
                        data.data = TLVElement::new(&[]);
                    }
                }

                attr_report.to_tlv(&TLVTag::Anonymous, &mut tw)?;
            }

            tw.end_container()?;
        }

        if let Some(event_reports) = report_data.event_reports {
            tw.bool(&TLVTag::Context(2), event_reports)?;
        }

        if let Some(more_chunks) = report_data.more_chunks {
            tw.bool(&TLVTag::Context(3), more_chunks)?;
        }

        if let Some(suppress_response) = report_data.suppress_response {
            tw.bool(&TLVTag::Context(4), suppress_response)?;
        }

        tw.end_container()?;

        Ok(wb.get_tail())
    }

    /// Process the supplied element without removing any data
    pub fn none(element: &TLVElement, buf: &mut [u8]) -> Result<usize, Error> {
        Self::empty().process(element, buf)
    }

    /// Process the supplied element with removing the dataver from the `AttrData` payload
    pub fn remove_attr_dataver(element: &TLVElement, buf: &mut [u8]) -> Result<usize, Error> {
        Self::REMOVE_ATTRDATA_DATAVER.process(element, buf)
    }

    /// Process the supplied element with removing the data value from the `AttrData` payload
    pub fn remove_attr_data<'a>(element: &TLVElement, buf: &mut [u8]) -> Result<usize, Error> {
        (Self::REMOVE_ATTRDATA_VALUE | Self::REMOVE_ATTRDATA_DATAVER).process(element, buf)
    }
}

impl<I, E, F> TLVTest<I, E, F>
where
    F: Fn(&TLVElement, &mut [u8]) -> Result<usize, Error>,
{
    /// Create a new TLV test instance with input payload being the IM `ReadRequest` message
    /// and the expected payload being the IM `ReportData` message.
    pub const fn read(input_payload: I, expected_payload: E, process_reply: F) -> Self {
        Self {
            input_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::ReadRequest as _,
                true,
            ),
            input_payload,
            expected_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::ReportData as _,
                true,
            ),
            expected_payload,
            process_reply,
            delay_ms: None,
        }
    }

    /// Create a new TLV test instance with input payload being the IM `StatusResponse` message
    /// and the expected payload being the IM `ReportData` message.
    pub const fn continue_report(input_payload: I, expected_payload: E, process_reply: F) -> Self {
        Self {
            input_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::StatusResponse as _,
                true,
            ),
            input_payload,
            expected_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::ReportData as _,
                true,
            ),
            expected_payload,
            process_reply,
            delay_ms: None,
        }
    }

    /// Create a new TLV test instance with input payload being the IM `WriteRequest` message
    /// and the expected payload being the IM `WriteResponse` message.
    pub const fn write(input_payload: I, expected_payload: E, process_reply: F) -> Self {
        Self {
            input_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::WriteRequest as _,
                true,
            ),
            input_payload,
            expected_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::WriteResponse as _,
                true,
            ),
            expected_payload,
            process_reply,
            delay_ms: None,
        }
    }

    /// Create a new TLV test instance with input payload being the IM `SubscribeRequest` message
    /// and the expected payload being the IM `ReportData` message.
    pub const fn subscribe(input_payload: I, expected_payload: E, process_reply: F) -> Self {
        Self {
            input_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::SubscribeRequest as _,
                true,
            ),
            input_payload,
            expected_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::ReportData as _,
                true,
            ),
            expected_payload,
            process_reply,
            delay_ms: None,
        }
    }

    /// Create a new TLV test instance with input payload being the IM `StatusResponse` message
    /// and the expected payload being the IM `SubscribeResponse` message.
    pub const fn subscribe_final(input_payload: I, expected_payload: E, process_reply: F) -> Self {
        Self {
            input_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::StatusResponse as _,
                true,
            ),
            input_payload,
            expected_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::SubscribeResponse as _,
                true,
            ),
            expected_payload,
            process_reply,
            delay_ms: None,
        }
    }

    /// Create a new TLV test instance with input payload being the IM `InvokeRequest` message
    /// and the expected payload being the IM `InvokeResponse` message.
    pub const fn invoke(input_payload: I, expected_payload: E, process_reply: F) -> Self {
        Self {
            input_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::InvokeRequest as _,
                true,
            ),
            input_payload,
            expected_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::InvokeResponse as _,
                true,
            ),
            expected_payload,
            process_reply,
            delay_ms: None,
        }
    }

    /// Create a new TLV test instance with input payload being the IM `TimedRequest` message
    /// and the expected payload being the IM `StatusResponse` message.
    pub const fn timed(input_payload: I, expected_payload: E, process_reply: F) -> Self {
        Self {
            input_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::TimedRequest as _,
                true,
            ),
            input_payload,
            expected_meta: MessageMeta::new(
                PROTO_ID_INTERACTION_MODEL,
                OpCode::StatusResponse as _,
                true,
            ),
            expected_payload,
            process_reply,
            delay_ms: None,
        }
    }
}

impl<'a>
    TLVTest<
        TestReadReq<'a>,
        TestReportDataMsg<'a>,
        fn(&TLVElement, &mut [u8]) -> Result<usize, Error>,
    >
{
    /// Create a new TLV test instance with input payload being the IM `ReadRequest` message
    /// and the expected payload being the IM `ReportData` message and the input payload and the
    /// expected payload being the provided attribute requests and responses.
    ///
    /// The reply will be processed to remove the data version from the `AttrData` payload.
    pub const fn read_attrs(input: &'a [AttrPath], expected: &'a [TestAttrResp<'a>]) -> Self {
        Self::read(
            TestReadReq::reqs(input),
            TestReportDataMsg::reports(expected),
            ReplyProcessor::remove_attr_dataver,
        )
    }
}

impl<'a>
    TLVTest<TestWriteReq<'a>, TestWriteResp<'a>, fn(&TLVElement, &mut [u8]) -> Result<usize, Error>>
{
    /// Create a new TLV test instance with input payload being the IM `WriteRequest` message
    /// and the expected payload being the IM `WriteResponse` message and the input payload and the
    /// expected payload being the provided write requests and responses.
    pub const fn write_attrs(input: &'a [TestAttrData<'a>], expected: &'a [AttrStatus]) -> Self {
        Self::write(
            TestWriteReq::reqs(input),
            TestWriteResp::resp(expected),
            ReplyProcessor::none,
        )
    }
}

impl<'a>
    TLVTest<TestInvReq<'a>, TestInvResp<'a>, fn(&TLVElement, &mut [u8]) -> Result<usize, Error>>
{
    /// Create a new TLV test instance with input payload being the IM `InvokeRequest` message
    /// and the expected payload being the IM `InvokeResponse` message and the input payload and the
    /// expected payload being the provided command requests and responses.
    pub const fn inv_cmds(input: &'a [TestCmdData<'a>], expected: &'a [TestCmdResp<'a>]) -> Self {
        Self::invoke(
            TestInvReq::reqs(input),
            TestInvResp::resp(expected),
            ReplyProcessor::none,
        )
    }
}
