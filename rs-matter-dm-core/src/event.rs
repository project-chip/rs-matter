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

use core::fmt;

use crate::error::Error;
use crate::im::EventDataTag;
use crate::tlv::{TLVBuilderParent, TLVTag, TLVWrite};
use crate::utils::sync::MaybeSendSync;

use super::{Access, EventId};

/// The context tag corresponding to the event data field in the Event Response TLV structure.
pub const EVENT_DATA_TAG: TLVTag = TLVTag::Context(EventDataTag::Data as _);

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
        impl core::convert::TryFrom<$crate::EventId> for $en {
            type Error = $crate::error::Error;

            fn try_from(id: $crate::EventId) -> Result<Self, Self::Error> {
                <$en>::from_repr(id).ok_or_else(|| $crate::error::ErrorCode::EventNotFound.into())
            }
        }
    };
}

/// A dyn-compatible writer for event data
/// Necessary so that we can implement `EventTLVWrite`, which is a `TLVWrite` with an erased `const N: usize` generic
pub trait DynEventWriter: MaybeSendSync {
    /// Write a byte.
    fn write(&mut self, byte: u8) -> Result<(), Error>;

    /// The position after the last written byte.
    fn get_tail(&self) -> usize;

    /// Drop the bytes written after `pos`.
    fn rewind_to(&mut self, pos: usize);
}

/// A `TLVWrite` wrapper around EventWriter that erases the const generic,
/// allowing it to be used in the closure passed to `Events::push()` and the various `emit_event` handler context methods.
pub struct EventTLVWrite<'a>(&'a mut dyn DynEventWriter);

impl<'a> EventTLVWrite<'a> {
    /// Create a new instance writing into `writer`.
    pub fn new(writer: &'a mut dyn DynEventWriter) -> Self {
        Self(writer)
    }
}

impl core::fmt::Debug for EventTLVWrite<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("EventTLVWrite").finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for EventTLVWrite<'_> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "EventTLVWrite")
    }
}

impl TLVWrite for EventTLVWrite<'_> {
    type Position = usize;

    fn write(&mut self, byte: u8) -> Result<(), Error> {
        self.0.write(byte)
    }

    fn get_tail(&self) -> Self::Position {
        self.0.get_tail()
    }

    fn rewind_to(&mut self, pos: Self::Position) {
        self.0.rewind_to(pos)
    }
}

impl TLVBuilderParent for EventTLVWrite<'_> {
    type Write = Self;

    fn writer(&mut self) -> &mut Self::Write {
        self
    }
}
