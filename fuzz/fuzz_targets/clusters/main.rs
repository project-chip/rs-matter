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

//! Arbitrary messages into a whole node with most of the cluster handlers of rs-matter.
//! The node is in `all_clusters.rs`, and the format of the input is in
//! `../node/harness.rs`.
//!
//! With `RUST_LOG` set, the target logs what the node does, which helps to understand
//! a crash: `RUST_LOG=debug cargo +nightly fuzz run clusters <crash file>`.

#![no_main]
#![recursion_limit = "256"]

use libfuzzer_sys::fuzz_target;

mod all_clusters;
// The node of the `node` target in the harness is not used here
#[allow(dead_code)]
#[path = "../node/harness.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = env_logger::try_init();
    }

    all_clusters::run(data, |_, _, _| ());
});
