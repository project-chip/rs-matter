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
use crate::tlv::{FromTLV, TLVArray, TLVElement, TagType, ToTLV};
use crate::utils::storage::WriteBuf;

/// A request to subscribe to attributes and events from a Matter device.
///
/// Corresponds to the `SubscribeRequestMessage` TLV structure in the Interaction Model.
#[derive(Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[tlvargs(lifetime = "'a")]
pub struct SubscribeReq<'a>(TLVElement<'a>);

impl<'a> SubscribeReq<'a> {
    /// Create a new `SubscribeReq` from a `TLVElement`.
    pub const fn new(element: TLVElement<'a>) -> Self {
        Self(element)
    }

    /// Return `Ok(true)` if this subscription request should keep existing subscriptions.
    pub fn keep_subs(&self) -> Result<bool, Error> {
        self.0.r#struct()?.find_ctx(0)?.bool()
    }

    /// Return the minimum interval floor for this subscription request.
    pub fn min_int_floor(&self) -> Result<u16, Error> {
        self.0.r#struct()?.find_ctx(1)?.u16()
    }

    /// Return the maximum interval ceiling for this subscription request.
    pub fn max_int_ceil(&self) -> Result<u16, Error> {
        self.0.r#struct()?.find_ctx(2)?.u16()
    }

    /// Return the attribute requests in this subscription request, if any.
    pub fn attr_requests(&self) -> Result<Option<TLVArray<'a, AttrPath>>, Error> {
        Option::from_tlv(&self.0.r#struct()?.find_ctx(3)?)
    }

    /// Return the event requests in this subscription request, if any.
    pub fn event_requests(&self) -> Result<Option<TLVArray<'a, EventPath>>, Error> {
        Option::from_tlv(&self.0.r#struct()?.find_ctx(4)?)
    }

    /// Return the event filters in this subscription request, if any.
    pub fn event_filters(&self) -> Result<Option<TLVArray<'a, EventFilter>>, Error> {
        Option::from_tlv(&self.0.r#struct()?.find_ctx(5)?)
    }

    /// Return `Ok(true)` if this subscription request is fabric-filtered.
    pub fn fabric_filtered(&self) -> Result<bool, Error> {
        self.0.r#struct()?.find_ctx(7)?.bool()
    }

    /// Return the data version filters in this subscription request, if any.
    pub fn dataver_filters(&self) -> Result<Option<TLVArray<'a, DataVersionFilter>>, Error> {
        Option::from_tlv(&self.0.r#struct()?.find_ctx(8)?)
    }
}

impl fmt::Debug for SubscribeReq<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscribeReqRef")
            .field("keep_subs", &self.keep_subs())
            .field("min_int_floor", &self.min_int_floor())
            .field("max_int_ceil", &self.max_int_ceil())
            .field("attr_requests", &self.attr_requests())
            .field("event_requests", &self.event_requests())
            .field("event_filters", &self.event_filters())
            .field("fabric_filtered", &self.fabric_filtered())
            .field("dataver_filters", &self.dataver_filters())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for SubscribeReq<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f,
            "SubscribeReqRef {{\n  keep_subs: {:?},\n  min_int_floor: {:?},\n  max_int_ceil: {:?},\n  attr_requests: {:?},\n  event_requests: {:?},\n  event_filters: {:?},\n  fabric_filtered: {:?},\n  dataver_filters: {:?},\n}}",
            self.keep_subs(),
            self.min_int_floor(),
            self.max_int_ceil(),
            self.attr_requests(),
            self.event_requests(),
            self.event_filters(),
            self.fabric_filtered(),
            self.dataver_filters(),
        )
    }
}

/// A response to a subscription request.
///
/// Corresponds to the `SubscribeResponseMessage` TLV structure in the Interaction Model.
#[derive(Debug, Default, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SubscribeResp {
    pub subs_id: u32,
    // The Context Tags are discontiguous for some reason
    pub _dummy: Option<u32>,
    pub max_int: u16,
}

impl SubscribeResp {
    /// Create a new `SubscribeResp` with the given subscription ID and maximum interval.
    pub fn new(subs_id: u32, max_int: u16) -> Self {
        Self {
            subs_id,
            _dummy: None,
            max_int,
        }
    }

    /// Write a `SubscribeResp` message to the provided `WriteBuf`.
    ///
    /// Returns a slice of the buffer containing the serialized response.
    ///
    /// Arguments:
    /// - `wb`: A mutable reference to a `WriteBuf` where the response will be written.
    /// - `subscription_id`: The subscription ID to include in the response.
    /// - `max_int`: The maximum interval for the subscription to include in the response.
    pub fn write<'a>(
        wb: &'a mut WriteBuf,
        subscription_id: u32,
        max_int: u16,
    ) -> Result<&'a [u8], Error> {
        let resp = Self::new(subscription_id, max_int);
        resp.to_tlv(&TagType::Anonymous, &mut *wb)?;

        Ok(wb.as_slice())
    }
}
