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

use core::fmt::{self, Display};

/// Identifies an Interaction Model transaction: the session it runs on, and the
/// exchange carrying it within that session.
///
/// The operation contexts give it to the handlers, so that they can find the
/// session an operation arrived on.
///
/// This is a handle local to the Matter stack, not the Transaction ID the peers
/// exchange in the message header.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TransactionId(u32);

impl TransactionId {
    /// Create an identifier from the raw value of the identifier of its exchange.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// The ID of the session of the transaction.
    pub const fn session_id(&self) -> u32 {
        self.0 & 0x0fff_ffff
    }

    /// The index of the exchange of the transaction within its session.
    pub const fn exchange_index(&self) -> usize {
        (self.0 >> 28) as _
    }
}

impl Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.session_id(), self.exchange_index())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for TransactionId {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "{}::{}", self.session_id(), self.exchange_index())
    }
}
