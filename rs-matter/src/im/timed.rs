/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

//! This module contains types related to the Timed Request feature in the Matter Interaction Model.

use core::time::Duration;

use crate::dm::GlobalElements;
use crate::im::IM_REVISION;
use crate::tlv::{FromTLV, ToTLV};
use crate::utils::epoch::Epoch;

/// A structure representing a timed request in the Interaction Model.
///
/// Corresponds to the `TimedRequestMessage` struct in the Interaction Model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TimedReq {
    /// The timeout duration in milliseconds for the request.
    pub timeout: u16,
    /// `interactionModelRevision` — mandatory in every IM message we send;
    /// modelled as `Option<u8>` so we tolerate peers that omit it (the C++
    /// SDK is tolerant in practice).
    #[tagval(GlobalElements::InteractionModelRevision as u8)]
    pub interaction_model_revision: Option<u8>,
}

impl TimedReq {
    /// Create a new `TimedReq` with the given timeout (in milliseconds).
    pub const fn new(timeout: u16) -> Self {
        Self {
            timeout,
            interaction_model_revision: Some(IM_REVISION),
        }
    }

    /// Returns the moment in time - since the system epoch - when the request
    /// following this timed request should be considered expired.
    pub fn timeout_instant(&self, epoch: Epoch) -> Duration {
        unwrap!(epoch().checked_add(Duration::from_millis(self.timeout as _)))
    }
}
