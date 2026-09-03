/*
 *
 *    Copyright (c) 2023-2026 Project CHIP Authors
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
    /// The Discovery Capabilities Bitmask carried in the machine-readable
    /// onboarding payloads (QR code, NFC tag).
    pub struct DiscoveryCapabilities: u8 {
        /// Soft Access Point (AP) discovery.
        ///
        /// Note bit 0 is reserved and SHALL be zero as of Matter 1.6;
        /// `SOFT_AP` predates that and is kept only for backwards
        /// compatibility - do not set it on a 1.6 device.
        const SOFT_AP = 0x01;
        /// BLE discovery
        const BLE = 0x02;
        /// IP-based discovery (e.g. mDNS or DNS-SD with Thread)
        const IP = 0x04;
        /// Wi-Fi Public Action Frame
        const PAF = 0x08;
        /// NFC Transport Layer (NTL) commissioning
        const NTL = 0x10;
    }
}

impl Default for DiscoveryCapabilities {
    fn default() -> Self {
        Self::IP
    }
}
