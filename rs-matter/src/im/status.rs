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

//! This module defines the `Status` and `StatusResp` structures used in the Interaction Model.

use crate::error::Error;
use crate::tlv::{FromTLV, TagType, ToTLV};
use crate::utils::storage::WriteBuf;

use super::IMStatusCode;

/// An IM status structure that contains an `IMStatusCode` and an optional cluster status code.
///
/// Corresponds to the `StatusIB` block in the Matter Interaction Model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Status {
    /// The status code of the IM operation.
    pub status: IMStatusCode,
    /// An optional cluster status code, which is used for cluster-specific status codes.
    pub cluster_status: Option<u16>,
}

impl Status {
    /// Create a new `Status` instance with the given `IMStatusCode` and an optional cluster status code.
    pub const fn new(status: IMStatusCode, cluster_status: Option<u16>) -> Status {
        Status {
            status,
            cluster_status,
        }
    }
}

/// An IM status response structure used for sending/receiving status responses in the Interaction Model.
///
/// Corresponds to the `StatusResponseMessage` struct in the Matter Interaction Model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StatusResp {
    pub status: IMStatusCode,
}

impl StatusResp {
    pub fn write(wb: &mut WriteBuf, status: IMStatusCode) -> Result<(), Error> {
        let status = Self { status };
        status.to_tlv(&TagType::Anonymous, wb)
    }
}
