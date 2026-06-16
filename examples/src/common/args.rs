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

//! Shared command-line argument parsing for the `*_tests` example binaries.
//!
//! The ConnectedHomeIP integration-test harness drives every test binary as a
//! device-under-test and may pass it commissioning/port/storage overrides (and
//! always appends `--interface-id <n>`, which we simply tolerate by ignoring
//! unknown flags). Centralizing the parsing here keeps every `*_tests` binary
//! consistently controllable by the harness.

// Each binary includes this module via `#[path = "../common/args.rs"]`, so not
// every parser is used by every binary.
#![allow(dead_code)]

use rs_matter::dm::devices::test::TEST_DEV_COMM;
use rs_matter::persist::FileKvBlobStore;
use rs_matter::sc::pase::{Spake2pVerifierPassword, Spake2pVerifierPasswordRef};
use rs_matter::{BasicCommData, MATTER_PORT};

/// Look up an optional `--<opt> <value>` CLI argument, converting its value with
/// `conv`. Returns `None` when the flag is absent. Unknown flags are ignored, so
/// harness-injected extras (e.g. `--interface-id`) are tolerated.
pub fn parse_arg_opt_override<T>(opt: &str, conv: impl FnOnce(&str) -> T) -> Option<T> {
    let args: Vec<String> = std::env::args().collect();

    let mut i = 1;
    while i < args.len() {
        if args[i] == opt && i + 1 < args.len() {
            return Some(conv(&args[i + 1]));
        }

        i += 1;
    }

    None
}

/// Whether a (valueless) flag is present on the command line.
pub fn arg_present(opt: &str) -> bool {
    std::env::args().any(|a| a == opt)
}

/// Commissioning data based on `TEST_DEV_COMM`, with optional `--discriminator
/// <u16>` / `--passcode <u32>` overrides. Used by tests (e.g. TC-SC-7.1) that
/// assert the device is *not* on the spec defaults, and by the OTA harness which
/// pins the provider's discriminator.
pub fn comm_overrides() -> BasicCommData {
    let mut data = TEST_DEV_COMM;

    if let Some(discriminator) =
        parse_arg_opt_override("--discriminator", |s| s.parse::<u16>().ok()).flatten()
    {
        data.discriminator = discriminator;
    }

    if let Some(passcode) =
        parse_arg_opt_override("--passcode", |s| s.parse::<u32>().ok()).flatten()
    {
        data.password = Spake2pVerifierPassword::new_from_ref(Spake2pVerifierPasswordRef::new(
            &passcode.to_le_bytes(),
        ));
    }

    data
}

/// The Matter UDP/TCP port to bind on. The CHIP harness starts apps with
/// `--secured-device-port`; our own tests use `--port`. Honor either (preferring
/// the CHIP spelling), defaulting to [`MATTER_PORT`] (5540).
pub fn port_override() -> u16 {
    parse_arg_opt_override("--secured-device-port", |s| s.parse::<u16>().ok())
        .flatten()
        .or_else(|| parse_arg_opt_override("--port", |s| s.parse::<u16>().ok()).flatten())
        .unwrap_or(MATTER_PORT)
}

/// The optional `--KVS <path>` key-value store path passed by the CHIP harness.
pub fn kvs_override() -> Option<String> {
    parse_arg_opt_override("--KVS", |s| s.to_string())
}

/// The IPv6 socket address to bind the Matter transport on, honoring
/// [`port_override`] (`[::]:<port>`, default `[::]:5540`).
pub fn bind_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        port_override(),
        0,
        0,
    ))
}

/// A [`FileKvBlobStore`] persisting at `--KVS <path>` when given, else the
/// default location. Honoring `--KVS` lets the harness's factory-reset (which
/// unlinks that path) actually clear our persisted state.
pub fn file_kv_store() -> FileKvBlobStore {
    match kvs_override() {
        Some(path) => FileKvBlobStore::new(path.into()),
        None => FileKvBlobStore::new_default(),
    }
}
