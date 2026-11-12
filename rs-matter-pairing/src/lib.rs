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
//! its scanning, and the NFC payload. And what a device authenticates
//! commissioners with: its passcode, or the verifier computed from it.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unknown_lints)]
#![allow(clippy::uninlined_format_args)]
// `cargo llvm-cov` sets `coverage_nightly` when it runs on a nightly toolchain;
// the test modules are then excluded from the coverage report
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use crate::crypto::{canon, EC_CANON_POINT_LEN, EC_CANON_SCALAR_LEN};
use crate::error::{Error, ErrorCode};
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

/// The length of a SPAKE2+ verifier: `w0`, then `L`.
pub const SPAKE2P_VERIFIER_STR_LEN: usize = EC_CANON_SCALAR_LEN + EC_CANON_POINT_LEN;

/// Maximum size of the PASE salt buffer, in bytes.
///
/// The Matter Core spec (Cryptographic Building Blocks) defines the
/// PASE salt as a variable-length octet string in **the range 16..=32**.
pub const SPAKE2P_VERIFIER_SALT_LEN: usize = 32;

/// Minimum PASE salt length per Matter Core spec.
pub const SPAKE2P_VERIFIER_SALT_MIN_LEN: usize = 16;

/// The smallest PBKDF2 iteration count of a verifier.
pub const SPAKE2P_ITERATIONS_MIN: u32 = 1000;

/// The largest PBKDF2 iteration count of a verifier.
pub const SPAKE2P_ITERATIONS_MAX: u32 = 100_000;

canon!(
    SPAKE2P_VERIFIER_PASSWORD_LEN,
    SPAKE2P_VERIFIER_PASSWORD_ZEROED,
    Spake2pVerifierPassword,
    Spake2pVerifierPasswordRef
);
canon!(
    SPAKE2P_VERIFIER_STR_LEN,
    SPAKE2P_VERIFIER_STR_ZEROED,
    Spake2pVerifierStr,
    Spake2pVerifierStrRef
);
canon!(
    SPAKE2P_VERIFIER_SALT_LEN,
    SPAKE2P_VERIFIER_SALT_ZEROED,
    Spake2pVerifierSalt,
    Spake2pVerifierSaltRef
);

/// The passcode and the discriminator: what the onboarding payloads carry.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BasicCommData {
    /// The passcode, which commissioners authenticate the device with
    pub password: Spake2pVerifierPassword,
    /// The 12-bit discriminator used to differentiate between multiple devices
    pub discriminator: u16,
}

/// What a device authenticates commissioners with in its basic commissioning
/// window.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DevCommData<'a> {
    /// The passcode itself: each window gets a verifier computed from it, and
    /// the device can show its pairing code and QR code. For development and
    /// tests, as the Core spec wants a device with a static passcode to be
    /// given the verifier, and the passcode kept out of its reach.
    Passcode(BasicCommData),
    /// The verifier computed from the passcode at manufacturing.
    Verifier(VerifierCommData<'a>),
}

impl DevCommData<'_> {
    /// The discriminator.
    pub const fn discriminator(&self) -> u16 {
        match self {
            Self::Passcode(data) => data.discriminator,
            Self::Verifier(data) => data.discriminator,
        }
    }

    /// The passcode and the discriminator, if the device has its passcode.
    pub const fn passcode(&self) -> Option<&BasicCommData> {
        match self {
            Self::Passcode(data) => Some(data),
            Self::Verifier(_) => None,
        }
    }
}

impl From<BasicCommData> for DevCommData<'_> {
    fn from(data: BasicCommData) -> Self {
        Self::Passcode(data)
    }
}

impl<'a> From<VerifierCommData<'a>> for DevCommData<'a> {
    fn from(data: VerifierCommData<'a>) -> Self {
        Self::Verifier(data)
    }
}

/// A SPAKE2+ verifier, with the salt and the iteration count it was computed
/// with, and the discriminator.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VerifierCommData<'a> {
    discriminator: u16,
    verifier: Spake2pVerifierStrRef<'a>,
    salt: &'a [u8],
    iterations: u32,
}

impl<'a> VerifierCommData<'a> {
    /// Fails unless the verifier is [`SPAKE2P_VERIFIER_STR_LEN`] bytes, the
    /// salt 16 to 32 bytes and the iteration count 1,000 to 100,000.
    pub fn new(
        discriminator: u16,
        verifier: &'a [u8],
        salt: &'a [u8],
        iterations: u32,
    ) -> Result<Self, Error> {
        if !(SPAKE2P_VERIFIER_SALT_MIN_LEN..=SPAKE2P_VERIFIER_SALT_LEN).contains(&salt.len())
            || !(SPAKE2P_ITERATIONS_MIN..=SPAKE2P_ITERATIONS_MAX).contains(&iterations)
        {
            Err(ErrorCode::InvalidData)?;
        }

        Ok(Self {
            discriminator,
            verifier: Spake2pVerifierStrRef::try_new(verifier)?,
            salt,
            iterations,
        })
    }

    /// The discriminator.
    pub const fn discriminator(&self) -> u16 {
        self.discriminator
    }

    /// The verifier: `w0`, then `L`.
    pub const fn verifier(&self) -> Spake2pVerifierStrRef<'a> {
        self.verifier
    }

    /// The salt.
    pub const fn salt(&self) -> &'a [u8] {
        self.salt
    }

    /// The PBKDF2 iteration count.
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }
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
