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

use embassy_time::{Duration, Instant};

use crate::im::IM_REVISION;
use crate::tlv::{FromTLV, ToTLV};

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
    #[tagval(crate::im::encoding::IM_REVISION_TAG)]
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

    /// Returns the monotonic [`Instant`] at which the request following this
    /// timed request should be considered expired.
    ///
    /// Saturates to [`Instant::MAX`] if the addition would overflow.
    pub fn timeout_instant(&self) -> Instant {
        Instant::now().saturating_add(Duration::from_millis(self.timeout as _))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::tlv::{FromTLV, TLVElement, TLVTag, ToTLV};
    use crate::utils::storage::WriteBuf;

    use super::{TimedReq, IM_REVISION};

    #[test]
    fn timed_req_round_trips() {
        let mut buf = [0; 16];
        let mut wb = WriteBuf::new(&mut buf);

        let req = TimedReq::new(500);
        req.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        assert_eq!(
            wb.as_slice(),
            &[0x15, 0x25, 0, 0xF4, 0x01, 0x24, 0xFF, IM_REVISION, 0x18]
        );
        assert_eq!(
            TimedReq::from_tlv(&TLVElement::new(wb.as_slice())).unwrap(),
            req
        );

        // A request without the revision field still decodes
        let bare = [0x15, 0x24, 0, 7, 0x18];
        let req = TimedReq::from_tlv(&TLVElement::new(&bare)).unwrap();
        assert_eq!(req.timeout, 7);
        assert_eq!(req.interaction_model_revision, None);
    }
}
