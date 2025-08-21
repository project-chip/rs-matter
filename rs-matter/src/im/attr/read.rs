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

use core::fmt;

use crate::error::Error;
use crate::im::{AttrPath, DataVersionFilter, EventFilter, EventPath};
use crate::tlv::{FromTLV, TLVArray, TLVElement, ToTLV};

/// A request to read attributes and events from a Matter device.
///
/// Corresponds to the `ReadRequestMessage` TLV structure in the Interaction Model.
#[derive(Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[tlvargs(lifetime = "'a")]
pub struct ReadReq<'a>(TLVElement<'a>);

impl<'a> ReadReq<'a> {
    /// Create a new `ReadReq` from a `TLVElement`.
    pub const fn new(element: TLVElement<'a>) -> Self {
        Self(element)
    }

    /// Return the attribute requests in this read request, if any.
    pub fn attr_requests(&self) -> Result<Option<TLVArray<'a, AttrPath>>, Error> {
        Option::from_tlv(&self.0.r#struct()?.find_ctx(0)?)
    }

    /// Return the event requests in this read request, if any.
    pub fn event_requests(&self) -> Result<Option<TLVArray<'a, EventPath>>, Error> {
        Option::from_tlv(&self.0.r#struct()?.find_ctx(1)?)
    }

    /// Return the event filters in this read request, if any.
    pub fn event_filters(&self) -> Result<Option<TLVArray<'a, EventFilter>>, Error> {
        Option::from_tlv(&self.0.r#struct()?.find_ctx(2)?)
    }

    /// Return Ok(`true`) if this read request is fabric-filtered.
    pub fn fabric_filtered(&self) -> Result<bool, Error> {
        self.0.r#struct()?.find_ctx(3)?.bool()
    }

    /// Return the data version filters in this read request, if any.
    pub fn dataver_filters(&self) -> Result<Option<TLVArray<'a, DataVersionFilter>>, Error> {
        Option::from_tlv(&self.0.r#struct()?.find_ctx(4)?)
    }
}

impl fmt::Debug for ReadReq<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadReqRef")
            .field("attr_requests", &self.attr_requests())
            .field("event_requests", &self.event_requests())
            .field("event_filters", &self.event_filters())
            .field("fabric_filtered", &self.fabric_filtered())
            .field("dataver_filters", &self.dataver_filters())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for ReadReq<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f,
            "ReadReqRef {{\n  attr_requests: {:?},\n  event_requests: {:?},\n  event_filters: {:?},\n  fabric_filtered: {:?},\n  dataver_filters: {:?},\n}}",
            self.attr_requests(),
            self.event_requests(),
            self.event_filters(),
            self.fabric_filtered(),
            self.dataver_filters(),
        )
    }
}

/// Tags corresponding to the fields in the `ReadReq` TLV structure.
///
/// Used when there is a need to perform low-level TLV serde on
/// `ReadReq` structures.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum ReadReqTag {
    AttrRequests = 0,
    EventRequests = 1,
    EventFilters = 2,
    FabricFiltered = 3,
    DataVersionFilters = 4,
}
