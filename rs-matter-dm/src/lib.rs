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

//! The cluster handlers of `rs-matter`: the system clusters of the root
//! endpoint and the application clusters, the composition of the root
//! endpoint, and the network commissioning drivers.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(async_fn_in_trait)]
#![allow(unknown_lints)]
#![allow(clippy::uninlined_format_args)]
#![recursion_limit = "1024"]
// `cargo llvm-cov` sets `coverage_nightly` when it runs on a nightly toolchain;
// the test modules are then excluded from the coverage report
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

// The dependencies, under the names the code uses for them
use rs_matter_bdx as bdx;
use rs_matter_cert as cert;
use rs_matter_cert::attest;
use rs_matter_crypto as crypto;
#[cfg(feature = "groups")]
use rs_matter_crypto::group_keys;
use rs_matter_dm_core::persist;
use rs_matter_dm_core::{except, handler_chain_type, with};
#[cfg(feature = "groups")]
use rs_matter_node::groupcast;
use rs_matter_node::transport;
use rs_matter_node::{acl, im, BootReason, Matter, MatterState};
use rs_matter_node_core::{basic_info, fabric, icd, rtc};
use rs_matter_sc as sc;
use rs_matter_tlv as tlv;
use rs_matter_utils as utils;
use rs_matter_utils::error;

// For the exported macros
#[doc(hidden)]
pub use rs_matter_dm_core::devices;

/// The Data Model types, the test device and the modules of this crate, under
/// the paths the code and the exported macros use for them.
#[doc(hidden)]
pub mod dm {
    pub use rs_matter_dm_core::*;

    pub use crate::{clusters, endpoints, networks};
}

#[cfg(feature = "alloc")]
extern crate alloc;

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

pub mod clusters;
pub mod endpoints;
pub mod networks;
pub mod ota;
