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

//! This module contains the logic for generating the pairing code and the QR code for easy pairing.

use crate::dm::clusters::basic_info::BasicInfoConfig;
use crate::error::Error;
use crate::utils::bitflags::bitflags;
use crate::BasicCommData;

pub mod code;
pub mod qr;

bitflags! {
    #[repr(transparent)]
    #[cfg_attr(not(feature = "defmt"), derive(Debug, Copy, Clone, Eq, PartialEq, Hash))]
    pub struct DiscoveryCapabilities: u8 {
        const SOFT_AP = 0x01;
        const BLE = 0x02;
        const IP = 0x04;
    }
}

impl Default for DiscoveryCapabilities {
    fn default() -> Self {
        Self::IP
    }
}
