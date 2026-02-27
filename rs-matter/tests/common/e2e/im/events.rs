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

use rs_matter::error::Error;
use rs_matter::im::{EventDataTimestamp, EventPath, EventStatus};
use rs_matter::tlv::{TLVTag, TLVWrite};
use rs_matter::utils::storage::WriteBuf;

use crate::common::e2e::tlv::TestToTLV;

/// A macro for creating an `EventStatus` instance for the provided generic path and `IMStatusCode``
#[macro_export]
macro_rules! event_status {
    ($path:expr, $status:expr) => {
        rs_matter::im::EventStatus::from_gp($path, $status, None)
    };
}

/// A macro for creating a `TestEventResp` instance of variant `Status`.
#[macro_export]
macro_rules! event_read_status_resp {
    ($path:expr, $status:expr) => {
        $crate::common::e2e::im::attributes::TestEventResp::EventStatus($crate::attr_status!(
            $path, $status
        ))
    };
}

/// A macro for creating a `TestEventData` instance taking
/// `GenericPath` instance, prio, event_no and data.
#[macro_export]
macro_rules! event_data_req {
    ($path:expr, $event_no:expr, $prio:expr, $data:expr) => {
        $crate::common::e2e::im::events::TestEventData {
            path: rs_matter::im::EventPath::from_gp(&$path),
            event_number: $event_no,
            priority: $prio,
            // Test harness is hardcoded, for events, for the clock to stay at 1337ms past the epoch
            timestamp: rs_matter::im::EventDataTimestamp::EpochTimestamp(1337),
            data: $data,
        }
    };
}

/// A macro for creating a `TestEventResp` instance of variant `EventData` taking
/// a `GenericPath` instance and data.
#[macro_export]
macro_rules! event_data_path {
    ($path:expr, $event_no:expr, $prio:expr, $data:expr) => {
        $crate::common::e2e::im::events::TestEventResp::EventData($crate::event_data_req!(
            $path, $event_no, $prio, $data
        ))
    };
}

/// A macro for creating a `TestEventResp` instance of variant `EventData` taking
/// an endpoint, cluster, attribute, and data.
///
/// Unlike the `event_data_path` variant, this one does not support wildcards,
/// but has a shorter syntax.
#[macro_export]
macro_rules! event_data {
    ($endpoint:expr, $cluster:expr, $event: expr,$event_no:expr, $prio:expr, $data:expr) => {
        $crate::event_data_path!(
            rs_matter::im::GenericPath::new(
                Some($endpoint as u16),
                Some($cluster as u32),
                Some($event as u32)
            ),
            $event_no,
            $prio,
            $data
        )
    };
}

/// An `EventData` alternative more suitable for testing.
///
/// The main difference is that `TestEventData::data` implements `TestToTLV`, whereas
/// `EventData::data` is a `TLVElement`.
#[derive(Debug, Clone)]
pub struct TestEventData<'a> {
    /// The path to the event.
    pub path: EventPath,
    pub event_number: u64,
    pub priority: u8,
    pub timestamp: EventDataTimestamp,
    pub data: Option<&'a dyn TestToTLV>,
}

impl TestToTLV for TestEventData<'_> {
    fn test_to_tlv(&self, tag: &TLVTag, tw: &mut WriteBuf<'_>) -> Result<(), Error> {
        tw.start_struct(tag)?;

        self.path.test_to_tlv(&TLVTag::Context(0), tw)?;

        tw.u64(&TLVTag::Context(1), self.event_number)?;
        tw.u8(&TLVTag::Context(2), self.priority)?;

        match self.timestamp {
            EventDataTimestamp::EpochTimestamp(ts) => tw.u64(&TLVTag::Context(3), ts)?,
            EventDataTimestamp::SystemTimestamp(ts) => tw.u64(&TLVTag::Context(4), ts)?,
            EventDataTimestamp::DeltaEpochTimestamp(ts) => tw.u64(&TLVTag::Context(5), ts)?,
            EventDataTimestamp::DeltaSystemTimestamp(ts) => tw.u64(&TLVTag::Context(6), ts)?,
        }

        if let Some(data) = self.data {
            data.test_to_tlv(&TLVTag::Context(7), tw)?;
        }

        tw.end_container()?;

        Ok(())
    }
}

/// An `EventResp` alternative more suitable for testing, in that the
/// `TestEventResp::EventData` variant uses `TestEventData` instead of `EventData`.
#[derive(Debug)]
pub enum TestEventResp<'a> {
    #[allow(dead_code)]
    EventStatus(EventStatus),
    EventData(TestEventData<'a>),
}

impl TestToTLV for TestEventResp<'_> {
    fn test_to_tlv(&self, tag: &TLVTag, tw: &mut WriteBuf<'_>) -> Result<(), Error> {
        tw.start_struct(tag)?;

        match self {
            TestEventResp::EventStatus(status) => status.test_to_tlv(&TLVTag::Context(0), tw),
            TestEventResp::EventData(data) => data.test_to_tlv(&TLVTag::Context(1), tw),
        }?;

        tw.end_container()
    }
}
