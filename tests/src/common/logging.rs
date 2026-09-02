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

//! Shared logging setup for the `*_tests` example binaries.

/// Initialise logging for a test binary.
///
/// Defaults to `Debug`, which is the level the integration tests are written
/// against: a failure is normally diagnosed by reading this log next to the
/// harness's own, message by message, and anything quieter drops the exchanges
/// that make that possible.
///
/// `RUST_LOG` overrides it when a run wants to be quieter or more targeted -
/// `RUST_LOG=info`, `RUST_LOG=rs_matter::transport=trace`. The default is
/// supplied through `Env::default_filter_or`, so the whole of `env_logger`'s
/// environment handling (`RUST_LOG_STYLE` included) keeps working.
///
/// Lines carry a millisecond timestamp. These logs are read alongside the Test
/// Harness's, which timestamps everything it prints, and lining the two up is
/// how a failure gets placed in the run.
pub fn init() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .format(|buf, record| {
            use std::io::Write;

            writeln!(
                buf,
                "[{} {}]: {}",
                buf.timestamp_millis(),
                record.level(),
                record.args()
            )
        })
        .target(env_logger::Target::Stdout)
        .init();

    // `rs_matter::error::Error` captures a `std::backtrace::Backtrace`, which
    // is only populated when `RUST_BACKTRACE` is set - otherwise it renders as
    // "disabled backtrace".
    //
    // Tie that to debug logging rather than turning it on unconditionally, so
    // that quietening a run with `RUST_LOG` also quietens the backtraces. Set
    // before the first `Error` is constructed, since `Backtrace` caches whether
    // capture is enabled on first use.
    if log::max_level() >= log::LevelFilter::Debug && std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
}
