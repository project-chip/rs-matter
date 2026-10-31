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

//! The state of a Matter node, as far as it does not depend on how the node
//! talks to others: the fabrics, the ACL, the fail-safe, the basic information
//! settings, the networks, the clock and the ICD advertisement.
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(async_fn_in_trait)]
#![allow(unknown_lints)]
#![allow(clippy::uninlined_format_args)]
#![recursion_limit = "1024"]
// `cargo llvm-cov` sets `coverage_nightly` when it runs on a nightly toolchain;
// the test modules are then excluded from the coverage report
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

#[cfg(feature = "alloc")]
extern crate alloc;

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

pub mod acl;
pub mod basic_info;
pub mod fabric;
pub mod failsafe;
pub mod handover;
pub mod icd;
pub mod networks;
pub mod rtc;
pub mod session;
pub mod test_device;

// The dependencies, under the names the code uses for them
use rs_matter_cert as cert;
use rs_matter_cert::attest;
use rs_matter_crypto as crypto;
use rs_matter_crypto::group_keys;
use rs_matter_dm_core as dm;
use rs_matter_dm_core::persist;
use rs_matter_im_core as im;
use rs_matter_pairing as pairing;
use rs_matter_tlv as tlv;
use rs_matter_utils as utils;
use rs_matter_utils::error;

pub use crate::pairing::BasicCommData;

/// The Matter UDP port
pub const MATTER_PORT: u16 = 5540;
