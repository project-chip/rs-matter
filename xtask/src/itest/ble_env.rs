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

//! A mock Bluetooth stack for the BLE integration tests.
//!
//! `run_test_suite.py` can stand up CHIP's own BLE mocks (its `--ble-wifi`
//! flag), but `run_python_test.py` - which drives the `MatterBaseTest` scripts -
//! cannot. This module fills that gap: a private D-Bus daemon plus `bluezoo`
//! serving `org.bluez` with two virtual adapters, which both ends of the link
//! then bind. Neither the device nor the CHIP controller needs Bluetooth
//! hardware, or even a kernel Bluetooth stack.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use log::{info, warn};

/// The MAC addresses of the two virtual adapters. `bluezoo` publishes them as
/// `/org/bluez/hci0` and `/org/bluez/hci1`, which is what both `rs-matter`'s
/// BlueZ peripheral and CHIP's `BLEManagerImpl` select on. The device takes the
/// first and the commissioner the second, so the two ends of the link are
/// distinct adapters.
const ADAPTERS: [&str; 2] = ["00:00:00:11:11:11", "00:00:00:22:22:22"];

/// `bluezoo`, relative to the Chip checkout.
const BLUEZOO: &str = ".environment/pigweed-venv/bin/bluezoo";

/// A running mock Bluetooth stack. All processes are torn down on drop.
pub struct BleEnv {
    dbus_socket: PathBuf,
    /// The private `dbus-daemon` process (kept in the foreground so that it
    /// can be terminated on drop - a forked daemon would leak, one instance
    /// per suite start).
    dbus_daemon: Child,
    bluezoo: Child,
}

impl BleEnv {
    /// Start a private D-Bus daemon and `bluezoo` on top of it.
    ///
    /// Returns once both virtual adapters have been published, so that a device
    /// started afterwards is guaranteed to find them.
    pub fn start(chip_dir: &Path) -> anyhow::Result<Self> {
        let bluezoo_path = chip_dir.join(BLUEZOO);
        if !bluezoo_path.exists() {
            anyhow::bail!(
                "`bluezoo` not found at {}. It is declared in the Chip checkout's \
                 `scripts/tests/requirements.txt` and installed into the pigweed venv \
                 by `cargo xtask itest-setup`.",
                bluezoo_path.display(),
            );
        }

        // Deliberately short: a Unix socket path is capped at ~108 bytes, which
        // the usual scratch and build directories already exceed on their own.
        let dbus_socket = PathBuf::from(format!("/tmp/rs-matter-ble-{}", std::process::id()));
        let _ = std::fs::remove_file(&dbus_socket);

        // Foreground (`--nofork`), so the process handle survives and the
        // daemon can be terminated on drop. Readiness = the socket appearing.
        let mut dbus_daemon = Command::new("dbus-daemon")
            .arg("--session")
            .arg(format!("--address=unix:path={}", dbus_socket.display()))
            .arg("--nofork")
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn dbus-daemon: {e}"))?;

        let deadline = Instant::now() + Duration::from_secs(5);
        while !dbus_socket.exists() {
            if Instant::now() >= deadline {
                let _ = dbus_daemon.kill();
                let _ = dbus_daemon.wait();
                anyhow::bail!(
                    "dbus-daemon did not create its socket at {} within 5s",
                    dbus_socket.display()
                );
            }

            std::thread::sleep(Duration::from_millis(50));
        }

        info!("Mock Bluetooth bus at {}", dbus_socket.display());

        let mut bluezoo = Command::new(&bluezoo_path)
            .arg("--auto-enable")
            .args(ADAPTERS.iter().map(|mac| format!("--adapter={mac}")))
            .env("DBUS_SYSTEM_BUS_ADDRESS", Self::bus_address(&dbus_socket))
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn bluezoo: {e}"))?;

        // `bluezoo` logs one line per adapter as it registers it; once both are
        // up the bus is fully populated.
        let stderr = bluezoo.stderr.take().expect("piped");
        let mut seen = 0;
        let deadline = Instant::now() + Duration::from_secs(30);
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            info!("[bluezoo] {line}");

            if line.contains("Adding adapter") {
                seen += 1;
                if seen == ADAPTERS.len() {
                    break;
                }
            }

            if Instant::now() >= deadline {
                break;
            }
        }

        if seen != ADAPTERS.len() {
            let _ = bluezoo.kill();
            let _ = bluezoo.wait();
            let _ = dbus_daemon.kill();
            let _ = dbus_daemon.wait();
            let _ = std::fs::remove_file(&dbus_socket);
            anyhow::bail!("bluezoo did not publish both virtual adapters");
        }

        Ok(Self {
            dbus_socket,
            dbus_daemon,
            bluezoo,
        })
    }

    /// The value to put in `DBUS_SYSTEM_BUS_ADDRESS` so that a child talks to
    /// the mock bus rather than the real system one.
    pub fn dbus_address(&self) -> String {
        Self::bus_address(&self.dbus_socket)
    }

    fn bus_address(socket: &Path) -> String {
        format!("unix:path={}", socket.display())
    }
}

impl Drop for BleEnv {
    fn drop(&mut self) {
        if let Err(err) = self.bluezoo.kill() {
            warn!("Failed to stop bluezoo: {err}");
        }
        let _ = self.bluezoo.wait();

        if let Err(err) = self.dbus_daemon.kill() {
            warn!("Failed to stop dbus-daemon: {err}");
        }
        let _ = self.dbus_daemon.wait();

        let _ = std::fs::remove_file(&self.dbus_socket);
    }
}
