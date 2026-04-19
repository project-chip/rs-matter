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

use super::{Access, EventId};

/// A type modeling the event meta-data in the Matter data model.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Event {
    /// The ID of the event
    pub id: EventId,
    /// The access control for the event
    pub access: Access,
}

impl Event {
    /// Creates a new event with the given ID and access control.
    pub const fn new(id: EventId, access: Access) -> Self {
        Self { id, access }
    }
}

impl core::fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// A macro to generate the events for a cluster.
#[allow(unused_macros)]
#[macro_export]
macro_rules! events {
    ($($event:expr $(,)?)*) => {
        &[
            $($event,)*
        ]
    }
}

/// A macro to generate a `TryFrom` implementation for an event enum.
#[allow(unused_macros)]
#[macro_export]
macro_rules! event_enum {
    ($en:ty) => {
        impl core::convert::TryFrom<$crate::dm::EventId> for $en {
            type Error = $crate::error::Error;

            fn try_from(id: $crate::dm::EventId) -> Result<Self, Self::Error> {
                <$en>::from_repr(id).ok_or_else(|| $crate::error::ErrorCode::EventNotFound.into())
            }
        }
    };
}
