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

//! The `--app-pipe <path>` out-of-band command channel shared by the `*_tests`
//! binaries.
//!
//! The CHIP Python test framework (`MatterBaseTest::write_to_app_pipe`) — and
//! the `xtask` itest orchestration — send JSON command lines to a named FIFO;
//! the device-under-test reads them and reacts out-of-band (outside the Matter
//! protocol), e.g. to simulate a physical switch press.

// Each binary includes this module via `#[path = "../common/pipe.rs"]`, so not
// every item is used by every binary.
#![allow(dead_code)]

use log::{info, warn};

use rs_matter::error::Error;

/// Read command lines from the `--app-pipe` FIFO (creating it if necessary)
/// and dispatch each to `action`. Pends forever when no pipe path is given.
///
/// `action` runs on the calling task — typically the main thread, so it's
/// free to touch `&Matter` / `&InteractionModel` directly (neither is `Sync`).
pub async fn run_app_pipe_actions(
    path: Option<String>,
    mut action: impl FnMut(String) -> Result<bool, Error>,
) -> Result<(), Error> {
    let Some(path) = path else {
        info!("No --app-pipe provided; out-of-band command channel disabled.");
        core::future::pending::<()>().await;
        unreachable!()
    };
    info!("App pipe enabled at {path}");

    use blocking::{unblock, Unblock};
    use futures_lite::io::{AsyncBufReadExt, BufReader};

    // Best-effort: create the FIFO if it doesn't already exist. Shell out to
    // `mkfifo` to avoid pulling in a `libc`/`nix` dep just for this. Errors
    // here are non-fatal: if the file already exists (or is a regular file
    // from a prior run) the reader open below will surface a useful error.
    let _ = std::process::Command::new("mkfifo").arg(&path).status();

    loop {
        let path_clone = path.clone();
        let file = match unblock(move || std::fs::File::open(&path_clone)).await {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to open app pipe {}: {}", path, e);
                embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
                continue;
            }
        };

        let mut reader = BufReader::new(Unblock::new(file));
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // writer closed; reopen
                Ok(_) => {
                    // Avoid a JSON dep: the framework sends one JSON dict per
                    // line and we only care about a single command name.

                    let line = line.trim_end();
                    info!("[app-pipe] received: {line}");

                    match action(line.to_string()) {
                        Ok(true) => info!("Processed"),
                        Ok(false) => info!("Skipped"),
                        Err(e) => warn!("Failed: {}", e),
                    }
                }
                Err(e) => {
                    warn!("Error reading from app pipe: {}", e);
                    break;
                }
            }
        }
    }
}
