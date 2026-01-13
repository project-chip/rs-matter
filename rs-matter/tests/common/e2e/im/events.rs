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

use rs_matter::dm::{AsyncHandler, AsyncMetadata};
use rs_matter::error::Error;
use rs_matter::im::{EventPath, GenericPath};
use rs_matter::im::{AttrPath, AttrStatus};
use rs_matter::tlv::{TLVTag, TLVWrite};
use rs_matter::utils::storage::WriteBuf;

use crate::common::e2e::tlv::{TLVTest, TestToTLV};
use crate::common::e2e::E2eRunner;

/// A macro for creating an `EventStatus` instance for the provided generic path and `IMStatusCode``
#[macro_export]
macro_rules! event_status {
    ($path:expr, $status:expr) => {
        rs_matter::im::EventStatus::from_gp($path, $status, None)
    };
}

/// A macro for creating an `EventStatus` instance for the provided generic path and `IMStatusCode``,
/// where the path is for one concrete array element in an array attribute
#[macro_export]
macro_rules! event_status_lel {
    ($path:expr, $status:expr) => {
        rs_matter::im::EventStatus::new(
            rs_matter::im::AttrPath {
                tag_compression: None,
                node: None,
                endpoint: $path.endpoint,
                cluster: $path.cluster,
                attr: $path.leaf,
                list_index: Some(rs_matter::tlv::Nullable::none()),
            },
            $status,
            None,
        )
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

/// A macro for creating a `TestEventData` instance of variant `EventData` taking
/// a `GenericPath` instance and data.
#[macro_export]
macro_rules! event_data_req {
    ($path:expr, $data:expr) => {
        $crate::common::e2e::im::events::TestEventData {
            data_ver: None,
            path: rs_matter::im::AttrPath::from_gp(&$path),
            data: $data,
        }
    };
}

/// Same as `attr_data_req!`, but generates a path for one concrete
/// array element in an array attribute
#[macro_export]
macro_rules! event_data_req_lel {
    ($path:expr, $data:expr) => {
        $crate::common::e2e::im::attributes::TestEventData {
            data_ver: None,
            path: rs_matter::im::AttrPath {
                tag_compression: None,
                node: None,
                endpoint: $path.endpoint,
                cluster: $path.cluster,
                attr: $path.leaf,
                list_index: Some(rs_matter::tlv::Nullable::none()),
            },
            data: $data,
        }
    };
}

/// A macro for creating a `TestEventResp` instance of variant `EventData` taking
/// a `GenericPath` instance and data.
#[macro_export]
macro_rules! event_data_path {
    ($path:expr, $data:expr) => {
        $crate::common::e2e::im::events::TestEventResp::EventData($crate::event_data_req!(
            $path, $data
        ))
    };
}

/// Same as `attr_data_path!`, but generates a path for one concrete
/// array element in an array attribute
#[macro_export]
macro_rules! event_data_lel_path {
    ($path:expr, $data:expr) => {
        $crate::common::e2e::im::attributes::TestEventResp::EventData($crate::attr_data_req_lel!(
            $path, $data
        ))
    };
}

/// A macro for creating a `TestEventResp` instance of variant `EventData` taking
/// an endpoint, cluster, attribute, and data.
///
/// Unlike the `attr_data_path` variant, this one does not support wildcards,
/// but has a shorter syntax.
#[macro_export]
macro_rules! event_data {
    ($endpoint:expr, $cluster:expr, $attr: expr, $data:expr) => {
        $crate::attr_data_path!(
            rs_matter::im::GenericPath::new(
                Some($endpoint as u16),
                Some($cluster as u32),
                Some($attr as u32)
            ),
            $data
        )
    };
}

/// Same as `attr_data!`, but generates data for one concrete
/// array element in an array attribute
#[macro_export]
macro_rules! event_data_lel {
    ($endpoint:expr, $cluster:expr, $attr: expr, $data:expr) => {
        $crate::attr_data_lel_path!(
            rs_matter::im::GenericPath::new(
                Some($endpoint as u16),
                Some($cluster as u32),
                Some($attr as u32)
            ),
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
    // TODO this is bogus
    pub data_ver: Option<u32>,
    pub path: AttrPath,
    pub data: Option<&'a dyn TestToTLV>,
}

impl<'a> TestEventData<'a> {
    /// Create a new `TestEventData` instance.
    pub const fn new(data_ver: Option<u32>, path: AttrPath, data: &'a dyn TestToTLV) -> Self {
        Self {
            data_ver,
            path,
            data: Some(data),
        }
    }
}

impl TestToTLV for TestEventData<'_> {
    fn test_to_tlv(&self, tag: &TLVTag, tw: &mut WriteBuf<'_>) -> Result<(), Error> {
        tw.start_struct(tag)?;

        if let Some(data_ver) = self.data_ver {
            tw.u32(&TLVTag::Context(0), data_ver)?;
        }

        self.path.test_to_tlv(&TLVTag::Context(1), tw)?;

        if let Some(data) = self.data {
            data.test_to_tlv(&TLVTag::Context(2), tw)?;
        }

        tw.end_container()?;

        Ok(())
    }
}

/// An `AttrResp` alternative more suitable for testing, in that the
/// `TestEventResp::EventData` variant uses `TestEventData` instead of `EventData`.
#[derive(Debug)]
pub enum TestEventResp<'a> {
    // TODO(events) these are from attr read stuff, check what the outcomes are for event reads
    EventStatus(AttrStatus),
    EventData(TestEventData<'a>),
}

impl<'a> TestEventResp<'a> {
    /// Create a new `TestEventResp` instance with an `EventData` value.
    pub fn data(path: &GenericPath, data: &'a dyn TestToTLV) -> Self {
        Self::EventData(TestEventData::new(None, AttrPath::from_gp(path), data))
    }
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

impl E2eRunner {
    /// For backwards compatibility.
    pub fn read_event_reqs<'a>(input: &'a [EventPath], expected: &'a [TestEventResp<'a>]) {
        let runner = Self::new_default();
        runner.add_default_acl();
        runner.handle_read_event_reqs(runner.handler(), input, expected)
    }

    /// For backwards compatibility.
    pub fn handle_read_event_reqs<'a, H>(
        &self,
        handler: H,
        input: &'a [EventPath],
        expected: &'a [TestEventResp<'a>],
    ) where
        H: AsyncHandler + AsyncMetadata,
    {
        self.test_one(handler, TLVTest::read_events(input, expected))
    }

}
