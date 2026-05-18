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

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Only re-run when build.rs itself changes.
    // Changes to the rs-matter-codegen build-dependency are tracked automatically by Cargo.
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    rs_matter_codegen::generate("crate", &out_dir);

    capture_build_time(&out_dir);
}

fn capture_build_time(out_dir: &Path) {
    /// Seconds between the UNIX epoch (1970-01-01) and the Matter epoch
    /// (2000-01-01). Mirrors `crate::utils::epoch::MATTER_EPOCH_SECS`.
    const MATTER_EPOCH_SECS: u64 = 946_684_800;

    println!("cargo:rerun-if-env-changed=RS_MATTER_BUILD_MATTER_SECS");

    // Capture the host wall clock at build time and emit it as a `const`
    // so the runtime can seed Matter Core spec §3.5.6.1 "Last Known Good
    // UTC Time" with the firmware build timestamp. Without a real-time
    // clock, this is the only lower-bound a freshly-flashed device can
    // rely on for cert validity checks.
    //
    // `RS_MATTER_BUILD_MATTER_SECS` (a u64 Matter-epoch seconds value)
    // can be set in the environment to pin a deterministic value, e.g.
    // for reproducible builds.
    let matter_secs = match std::env::var("RS_MATTER_BUILD_MATTER_SECS") {
        Ok(s) => s
            .parse::<u64>()
            .expect("RS_MATTER_BUILD_MATTER_SECS must be a u64 Matter-epoch seconds value"),
        Err(_) => {
            let now_unix_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is before UNIX epoch")
                .as_secs();
            // Saturate on hosts whose clock isn't set; `0` then means
            // "Matter epoch" which is harmless but earlier than any
            // plausible NOC validity. Devices in this state will reject
            // every NOC — the safe failure mode.
            now_unix_secs.saturating_sub(MATTER_EPOCH_SECS)
        }
    };
    let matter_us = matter_secs.saturating_mul(1_000_000);

    let dest = out_dir.join("build_time.rs");
    let contents = format!(
        "/// Firmware build time as Matter-epoch microseconds, captured by\n\
         /// `build.rs`. Seed value for the Last-Known-Good UTC Time on a\n\
         /// freshly-flashed device per Matter Core spec §3.5.6.1.\n\
         pub const FIRMWARE_BUILD_MATTER_US: u64 = {matter_us};\n"
    );

    std::fs::write(&dest, contents).expect("failed to write build_time.rs");
}
