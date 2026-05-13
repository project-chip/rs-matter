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

//! This module imports all system clusters that are used by the `rs-matter` itself.
//!
//! Application-level clusters (OnOff, LevelControl, the camera / streaming
//! clusters, etc.) live under [`app`] and have to be opted into by the
//! application as needed.

pub mod acl;
pub mod adm_comm;
pub mod app;
pub mod basic_info;
pub mod binding;
pub mod desc;
pub mod dev_att;
pub mod eth_diag;
pub mod fixed_label;
pub mod gen_comm;
pub mod gen_diag;
pub mod groups;
pub mod grp_key_mgmt;
pub mod identify;
pub mod net_comm;
pub mod noc;
pub mod thread_diag;
pub mod unit_testing;
pub mod user_label;
pub mod wifi_diag;

/// Generated cluster declarations from Matter IDL (via build.rs).
#[allow(
    clippy::all,
    dead_code,
    unused_variables,
    unused_mut,
    unreachable_patterns,
    noop_method_call,
    mismatched_lifetime_syntaxes
)]
pub mod decl {
    include!(concat!(env!("OUT_DIR"), "/clusters_generated.rs"));
}
