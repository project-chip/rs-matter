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

//! Runnable controller-side smoke test.
//!
//! Drives [`rs_matter::commissioner::Commissioner::commission`] (phase 1
//! — `ArmFailSafe` through `AddNOC`) against an externally-running
//! Matter accessory. Designed to exercise the rs-matter controller path
//! end-to-end against the canonical upstream
//! [`chip-all-clusters-app`](https://github.com/project-chip/connectedhomeip/tree/master/examples/all-clusters-app)
//! — see the `commissioner` suite in `xtask/src/itest.rs` for the
//! runner wiring.
//!
//! Phase 2 (CASE + `CommissioningComplete`) is not yet implemented in
//! the library, so the device's fail-safe will eventually expire and
//! the fabric rolls back. Until phase 2 lands, the goal of this binary
//! is to prove the post-PASE invoke chain works on the wire against an
//! upstream-compliant responder.
//!
//! Usage:
//! ```text
//! commissioner_test [PASSCODE] [PEER_ADDR]
//! ```
//! Defaults match the rs-matter test fixture
//! ([`TEST_DEV_COMM`](rs_matter::dm::devices::test::TEST_DEV_COMM)):
//! passcode `20202021`, peer `[::1]:5540`.
//!
//! Exits `0` on a successful phase-1 commissioning, non-zero (with a
//! diagnostic on stderr) otherwise. On success a single
//! machine-readable line is printed to stdout:
//! ```text
//! commissioner_test: ok fabric_index=<u8> device_node_id=0x<hex>
//! ```

use core::pin::pin;

use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use log::{error, info};

use rs_matter::cert::builder::VALID_FOREVER;
use rs_matter::commissioner::{CommissionOptions, Commissioner, FabricCredentials};
use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::sc::pase::PaseInitiator;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::{Address, NoNetwork};
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::Matter;

use static_cell::StaticCell;

/// Defaults match rs-matter's `TEST_DEV_COMM`. Override via CLI args
/// for chip-all-clusters-app or any other peer.
const DEFAULT_PASSCODE: u32 = 20202021;
const DEFAULT_PEER_ADDR: &str = "[::1]:5540";

const PASE_TIMEOUT_SECS: u64 = 30;
const COMMISSION_TIMEOUT_SECS: u64 = 60;

static CTRL_MATTER: StaticCell<Matter> = StaticCell::new();

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("commissioner_test: {msg}");
            eprintln!("usage: commissioner_test [PASSCODE] [PEER_ADDR]");
            return ExitCode::FAILURE;
        }
    };
    info!(
        "commissioner_test: passcode={} peer={}",
        args.passcode, args.peer_addr
    );

    match futures_lite::future::block_on(run(args)) {
        Ok(result) => {
            println!(
                "commissioner_test: ok fabric_index={} device_node_id=0x{:016x}",
                result.fabric_index, result.device_node_id
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("commissioner_test: FAILED — {e:?}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug)]
struct Args {
    passcode: u32,
    peer_addr: SocketAddr,
}

fn parse_args() -> Result<Args, String> {
    let mut iter = std::env::args().skip(1);
    let passcode = match iter.next() {
        Some(s) => s
            .parse::<u32>()
            .map_err(|e| format!("passcode must be u32: {e}"))?,
        None => DEFAULT_PASSCODE,
    };
    let peer_addr_str = iter.next().unwrap_or_else(|| DEFAULT_PEER_ADDR.to_string());
    let peer_addr = peer_addr_str
        .parse::<SocketAddr>()
        .map_err(|e| format!("peer addr must be SocketAddr (e.g. [::1]:5540): {e}"))?;
    Ok(Args {
        passcode,
        peer_addr,
    })
}

async fn run(args: Args) -> Result<CommissionResult, Error> {
    let bind_addr: SocketAddr = "[::]:0".parse().unwrap();
    let socket =
        async_io::Async::<UdpSocket>::bind(bind_addr).map_err(|_| ErrorCode::NoNetworkInterface)?;
    info!(
        "controller bound on {}",
        socket.get_ref().local_addr().unwrap()
    );

    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);
    let matter = CTRL_MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        // local port = 0 → kernel-picked, matches the ephemeral `socket`.
        0,
    ));

    // The transport pump must stay alive throughout the flow.
    let transport_fut = matter.run(&crypto, &socket, &socket, NoNetwork);
    let flow_fut = run_commission(matter, &crypto, args);

    let mut transport_fut = pin!(transport_fut);
    let mut flow_fut = pin!(flow_fut);

    match select(&mut transport_fut, &mut flow_fut).await {
        Either::First(r) => {
            error!("transport exited prematurely: {r:?}");
            Err(ErrorCode::NoExchange.into())
        }
        Either::Second(result) => result,
    }
}

/// Mirror of [`rs_matter::commissioner::CommissionResult`] — re-declared
/// here so the `main` print doesn't have to import the lifetime-bound
/// type through the public API just to format two scalars.
#[derive(Debug, Clone, Copy)]
struct CommissionResult {
    fabric_index: u8,
    device_node_id: u64,
}

async fn run_commission<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    args: Args,
) -> Result<CommissionResult, Error> {
    info!("=== PASE handshake against {} ===", args.peer_addr);
    establish_pase(matter, crypto, args.peer_addr, args.passcode).await?;
    info!("PASE established");

    info!("=== Commissioner::commission (phase 1) ===");
    let mut fabric_creds = FabricCredentials::new(crypto, /*fabric_id=*/ 1, VALID_FOREVER)?;
    let mut commissioner = Commissioner::new(matter, crypto, &mut fabric_creds);

    let opts = CommissionOptions {
        // chip-all-clusters-app ships with the canonical test DAC;
        // skip DCL verification until DAC work lands.
        allow_test_attestation: true,
        ..CommissionOptions::default()
    };

    let mut commission_fut = pin!(commissioner.commission(&opts));
    let mut timeout = pin!(Timer::after(Duration::from_secs(COMMISSION_TIMEOUT_SECS)));

    let result = match select(&mut commission_fut, &mut timeout).await {
        Either::First(r) => r?,
        Either::Second(_) => {
            error!("commission() timed out after {COMMISSION_TIMEOUT_SECS}s");
            return Err(ErrorCode::RxTimeout.into());
        }
    };

    Ok(CommissionResult {
        fabric_index: result.fabric_index,
        device_node_id: result.device_node_id,
    })
}

async fn establish_pase<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    peer_addr: SocketAddr,
    passcode: u32,
) -> Result<(), Error> {
    let peer = Address::Udp(peer_addr);

    let mut exchange = Exchange::initiate_unsecured(matter, crypto, peer).await?;
    let mut pase_fut = pin!(PaseInitiator::initiate(&mut exchange, crypto, passcode));
    let mut timeout = pin!(Timer::after(Duration::from_secs(PASE_TIMEOUT_SECS)));

    match select(&mut pase_fut, &mut timeout).await {
        Either::First(r) => r,
        Either::Second(_) => {
            error!("PASE timed out after {PASE_TIMEOUT_SECS}s");
            Err(ErrorCode::RxTimeout.into())
        }
    }
}
