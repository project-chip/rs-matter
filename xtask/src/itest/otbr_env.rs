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

//! A real Thread stack for the Thread integration tests, minus the radio
//! hardware.
//!
//! The DUT side of the `thread` suite is `otbr-agent` — OpenThread's reference
//! Linux daemon — owning the radio and exposing the `io.openthread.BorderRouter`
//! D-Bus API that the rs-matter driver's `NetCtl` implementation talks to. This
//! module stands the daemon up on a *private* D-Bus bus (the same pattern as
//! `BleEnv`/`bluezoo`), with the radio defaulting to OpenThread's *simulated*
//! RCP: a host binary whose 802.15.4 "RF" is localhost UDP, so PANs form and
//! datasets switch for real without any hardware. Point
//! `RS_MATTER_THREAD_RADIO_URL` at e.g. `spinel+hdlc+uart:///dev/ttyACM0` to
//! run the very same suite against a physical RCP dongle instead.
//!
//! `otbr-agent` creates a TUN interface (`wpan0`) and therefore needs
//! `CAP_NET_ADMIN` (+`CAP_NET_RAW` for its ICMPv6 traffic). Rather than
//! running the daemon as root, the suite relies on *file capabilities* on the
//! binary — `setcap cap_net_admin,cap_net_raw+ep otbr-agent` — so the whole
//! process tree stays owned by the invoking user: teardown is a plain kill,
//! and the `ot-ctl` debug socket is user-accessible. The capabilities are
//! probed at startup (they vanish whenever the binary is rebuilt) and
//! re-applied via non-interactive `sudo` where available, falling back to an
//! actionable error message.

use std::env;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use log::{debug, info, warn};

/// Environment variable overriding the radio URL, for runs against a real RCP
/// dongle (e.g. `spinel+hdlc+uart:///dev/ttyACM0?uart-baudrate=460800`).
const RADIO_URL_ENV: &str = "RS_MATTER_THREAD_RADIO_URL";

/// The OpenThread simulation node id of the DUT's RCP. Every sim node on the
/// host meshes with the others over localhost UDP; upstream's test-harness
/// border router uses node 9, so staying low keeps the two composable later.
const SIM_NODE_ID: u32 = 1;

/// The TUN interface name the agent creates. The D-Bus service name is derived
/// from it (`io.openthread.BorderRouter.wpan0`), so the driver's `NetCtl` and
/// this fixture must agree.
const OTBR_IFNAME: &str = "wpan0";

/// A running otbr-agent on a private D-Bus bus. Torn down on drop.
pub struct OtbrEnv {
    dbus_socket: PathBuf,
    /// The private `dbus-daemon` process (kept in the foreground so that it
    /// can be terminated on drop - a forked daemon would leak, one instance
    /// per suite start).
    dbus_daemon: Child,
    /// The `otbr-agent` process (running as the invoking user, via file
    /// capabilities on the binary).
    agent: Child,
    /// Scratch cwd of the agent; `OT_POSIX_SETTINGS_PATH="tmp"` makes it store
    /// its Thread settings under `<cwd>/tmp`, so a fresh dir per start means a
    /// factory-new Thread stack.
    _settings_dir: tempfile::TempDir,
}

impl OtbrEnv {
    /// Start a private D-Bus daemon and `otbr-agent` on top of it.
    ///
    /// Returns once the agent has completed the spinel handshake with its RCP
    /// (real or simulated), so a driver started afterwards finds the D-Bus API
    /// live.
    pub fn start(otbr_agent: &Path, ot_rcp_sim: &Path) -> anyhow::Result<Self> {
        if !otbr_agent.exists() {
            anyhow::bail!(
                "`otbr-agent` not found at {} — it is built lazily by the thread suite; \
                 run `cargo xtask itest --suite thread` (or `itest-setup`) with network access",
                otbr_agent.display(),
            );
        }

        let radio_url = match env::var(RADIO_URL_ENV) {
            Ok(url) => {
                info!("Using {RADIO_URL_ENV} radio: {url}");
                url
            }
            Err(_) => {
                if !ot_rcp_sim.exists() {
                    anyhow::bail!(
                        "simulation `ot-rcp` not found at {} (and no {RADIO_URL_ENV} override)",
                        ot_rcp_sim.display(),
                    );
                }
                format!(
                    "spinel+hdlc+forkpty://{}?forkpty-arg={SIM_NODE_ID}",
                    ot_rcp_sim.display()
                )
            }
        };

        Self::ensure_agent_caps(otbr_agent)?;

        // Deliberately short: a Unix socket path is capped at ~108 bytes.
        let dbus_socket = PathBuf::from(format!("/tmp/rs-matter-otbr-{}", std::process::id()));
        let _ = std::fs::remove_file(&dbus_socket);

        let settings_dir = tempfile::TempDir::new()?;

        // A custom bus configuration rather than `--session`, because the bus
        // must ALSO accept `ANONYMOUS` auth: the chip-tool YAML runner spawns
        // the DUT app inside `unshare --map-root-user`, where the app's
        // announced euid (0) no longer matches the socket peer credential the
        // daemon sees (the real user), so the standard `EXTERNAL` mechanism
        // rejects it. `EXTERNAL` stays enabled for the (un-namespaced)
        // `otbr-agent`.
        let dbus_config = settings_dir.path().join("dbus.conf");
        std::fs::write(
            &dbus_config,
            format!(
                r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={}</listen>
  <auth>EXTERNAL</auth>
  <auth>ANONYMOUS</auth>
  <allow_anonymous/>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
                dbus_socket.display()
            ),
        )?;

        // Foreground (`--nofork`), so the process handle survives and the
        // daemon can be terminated on drop. Readiness = the socket appearing.
        let mut dbus_daemon = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", dbus_config.display()))
            .arg("--nofork")
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn dbus-daemon: {e}"))?;

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !dbus_socket.exists() {
            if std::time::Instant::now() >= deadline {
                let _ = dbus_daemon.kill();
                let _ = dbus_daemon.wait();
                anyhow::bail!(
                    "dbus-daemon did not create its socket at {} within 5s",
                    dbus_socket.display()
                );
            }

            thread::sleep(Duration::from_millis(50));
        }

        info!("Thread environment bus at {}", dbus_socket.display());

        let mut agent = Command::new(otbr_agent)
            .env("DBUS_SYSTEM_BUS_ADDRESS", Self::bus_address(&dbus_socket))
            .arg(format!("-I{OTBR_IFNAME}"))
            // A border-routing infra interface is mandatory on the command
            // line; the suite does not exercise border routing (the DUT is
            // dual-homed via the host LAN), so loopback is sufficient.
            .arg("-Blo")
            // `-d7`: the "Co-processor version:" readiness line below is not
            // emitted at lower levels. The output is drained at debug level,
            // so the verbosity only reaches the operator with `-v` runs.
            .arg("-d7")
            .arg("-v")
            .arg(&radio_url)
            .current_dir(settings_dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn otbr-agent: {e}"))?;

        // Readiness: the agent logs the RCP's version string once the spinel
        // handshake is done; the D-Bus name is registered before that. The
        // log lines go to *stderr* (that is what `-v` means), but match on
        // both streams rather than assume. Keep draining the output
        // afterwards so the pipes can't fill and stall the daemon.
        let stdout = agent.stdout.take().expect("piped");
        let stderr = agent.stderr.take().expect("piped");
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        for reader in [
            Box::new(BufReader::new(stdout)) as Box<dyn BufRead + Send>,
            Box::new(BufReader::new(stderr)) as Box<dyn BufRead + Send>,
        ] {
            let ready_tx = ready_tx.clone();
            thread::spawn(move || {
                let mut signalled = false;
                for line in reader.lines().map_while(Result::ok) {
                    debug!("[otbr-agent] {line}");
                    if !signalled && line.contains("Co-processor version:") {
                        let _ = ready_tx.send(());
                        signalled = true;
                    }
                }
            });
        }

        if ready_rx.recv_timeout(Duration::from_secs(20)).is_err() {
            let env = Self {
                dbus_socket,
                dbus_daemon,
                agent,
                _settings_dir: settings_dir,
            };
            drop(env); // kills the agent and the bus daemon, removes the socket
            anyhow::bail!(
                "otbr-agent did not complete the RCP handshake within 20s \
                 (radio URL: {radio_url}); re-run with `-v` for its output"
            );
        }

        info!("otbr-agent up on {OTBR_IFNAME} (radio: {radio_url})");

        Ok(Self {
            dbus_socket,
            dbus_daemon,
            agent,
            _settings_dir: settings_dir,
        })
    }

    /// The value to put in `DBUS_SYSTEM_BUS_ADDRESS` so that the driver (and
    /// anything else) talks to the private bus rather than the real system one.
    pub fn dbus_address(&self) -> String {
        Self::bus_address(&self.dbus_socket)
    }

    /// Make sure the agent binary carries the file capabilities it needs to
    /// run unprivileged (`cap_net_admin` for the TUN interface,
    /// `cap_net_raw` for its ICMPv6 traffic).
    ///
    /// A rebuild of the binary silently drops previously-granted
    /// capabilities, so this is probed on every start. Granting them needs
    /// root once per rebuild: attempted via non-interactive `sudo` (free in
    /// CI), with an actionable message when that is not available.
    fn ensure_agent_caps(otbr_agent: &Path) -> anyhow::Result<()> {
        let has_caps = Command::new("getcap")
            .arg(otbr_agent)
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("cap_net_admin"))
            .unwrap_or(false);
        if has_caps {
            return Ok(());
        }

        let granted = Command::new("sudo")
            .arg("-n")
            .arg("setcap")
            .arg("cap_net_admin,cap_net_raw+ep")
            .arg(otbr_agent)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if granted {
            info!(
                "Granted cap_net_admin,cap_net_raw to {}",
                otbr_agent.display()
            );
            return Ok(());
        }

        anyhow::bail!(
            "`otbr-agent` lacks the file capabilities it needs to run unprivileged \
             (they are dropped whenever the binary is rebuilt). Grant them once with:\n\n  \
             sudo setcap cap_net_admin,cap_net_raw+ep {}\n\nand re-run the suite.",
            otbr_agent.display(),
        )
    }

    fn bus_address(socket: &Path) -> String {
        format!("unix:path={}", socket.display())
    }
}

impl Drop for OtbrEnv {
    fn drop(&mut self) {
        // The agent runs as the invoking user (file capabilities, not root),
        // so a plain kill suffices.
        if let Err(err) = self.agent.kill() {
            warn!("Failed to stop otbr-agent: {err}");
        }
        let _ = self.agent.wait();

        if let Err(err) = self.dbus_daemon.kill() {
            warn!("Failed to stop dbus-daemon: {err}");
        }
        let _ = self.dbus_daemon.wait();

        let _ = std::fs::remove_file(&self.dbus_socket);
    }
}
