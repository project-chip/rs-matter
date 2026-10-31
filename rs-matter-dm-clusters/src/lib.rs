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

//! The cluster types, metadata, handler traits and clients, generated from the
//! Matter IDL by `build.rs`.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(
    async_fn_in_trait,
    unknown_lints,
    unexpected_cfgs,
    clippy::all,
    dead_code,
    unused_variables,
    unused_mut,
    unreachable_patterns,
    noop_method_call,
    mismatched_lifetime_syntaxes
)]

// The crates, under the paths the generated code uses for them
use rs_matter_dm_core as dm;
use rs_matter_im_core as im;
use rs_matter_tlv as tlv;
use rs_matter_tlv::bitflags_tlv;
use rs_matter_utils as utils;
use rs_matter_utils::error;

/// The crates used by the generated code
mod reexport {
    // With `defmt`, the generated code uses the `bitflags!` of `defmt`
    #[allow(unused_imports)]
    pub use bitflags;
    #[cfg(feature = "defmt")]
    pub use defmt;
    pub use strum;
}

include!(concat!(env!("OUT_DIR"), "/clusters_generated.rs"));
