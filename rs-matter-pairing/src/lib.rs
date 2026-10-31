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

//! The onboarding payloads of Matter: the manual pairing code, the QR code and
//! its scanning, and the NFC payload.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unknown_lints)]
#![allow(clippy::uninlined_format_args)]
// `cargo llvm-cov` sets `coverage_nightly` when it runs on a nightly toolchain;
// the test modules are then excluded from the coverage report
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use crate::crypto::canon;
use crate::error::Error;
use crate::utils::bitflags::bitflags;

// The dependencies, under the names the code uses for them
use rs_matter_crypto as crypto;
use rs_matter_tlv as tlv;
use rs_matter_utils as utils;
use rs_matter_utils::error;

#[cfg(feature = "alloc")]
extern crate alloc;

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

pub mod code;
pub mod qr;

/// The length of the setup passcode, in bytes.
pub const SPAKE2P_VERIFIER_PASSWORD_LEN: usize = 4;

canon!(
    SPAKE2P_VERIFIER_PASSWORD_LEN,
    SPAKE2P_VERIFIER_PASSWORD_ZEROED,
    Spake2pVerifierPassword,
    Spake2pVerifierPasswordRef
);

/// Device basic commissioning data
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BasicCommData {
    /// The password which is necessary to authenticate the device in either
    /// initial commissioning, or when the basic commissioning window is opened
    pub password: Spake2pVerifierPassword,
    /// The 12-bit discriminator used to differentiate between multiple devices
    pub discriminator: u16,
}

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
