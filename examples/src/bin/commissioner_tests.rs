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

//! Runnable controller-side tests.
//!
//! For now, drives [`rs_matter::onboard::Commissioner::commission`] against
//! an externally-running Matter accessory. Designed to exercise the rs-matter controller path
//! end-to-end against the canonical upstream
//! [`chip-all-clusters-app`](https://github.com/project-chip/connectedhomeip/tree/master/examples/all-clusters-app)
//! — see the `commissioner` suite in `xtask/src/itest.rs` for the
//! runner wiring.
//!
//! Usage:
//! ```text
//! commissioner_tests [PASSCODE] [PEER_ADDR]
//! ```
//! Defaults match the rs-matter test fixture
//! ([`TEST_DEV_COMM`](rs_matter::dm::devices::test::TEST_DEV_COMM)):
//! passcode `20202021`, peer `[::1]:5540`.
//!
//! Exits `0` on a successful commissioning, non-zero (with a
//! diagnostic on stderr) otherwise. On success a single
//! machine-readable line is printed to stdout:
//! ```text
//! commissioner_tests: ok fabric_index=<u8> device_node_id=0x<hex>
//! ```

use core::num::NonZeroU8;
use core::pin::pin;

use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use log::{error, info};

use rs_matter::cert::builder::VALID_FOREVER;
use rs_matter::cert::{MAX_CERT_TLV_AND_ASN1_LEN, MAX_CERT_TLV_LEN};
use rs_matter::crypto::{
    default_crypto, CanonAeadKey, CanonPkcSecretKey, Crypto, RngCore as _, SecretKey,
    SigningSecretKey,
};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::onboard::cac::{IcacGenerator, RcacGenerator};
use rs_matter::onboard::noc::NocGenerator;
use rs_matter::onboard::{CommissionOptions, Commissioner};
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
            eprintln!("commissioner_tests: {msg}");
            eprintln!("usage: commissioner_tests [PASSCODE] [PEER_ADDR]");
            return ExitCode::FAILURE;
        }
    };
    info!(
        "commissioner_tests: passcode={} peer={}",
        args.passcode, args.peer_addr
    );

    match futures_lite::future::block_on(run(args)) {
        Ok(result) => {
            println!(
                "commissioner_tests: ok fabric_index={} device_node_id=0x{:016x}",
                result.fabric_index, result.device_node_id
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("commissioner_tests: FAILED — {e:?}");
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

/// Mirror of [`rs_matter::onboard::CommissionResult`] — re-declared
/// here so the `main` print doesn't have to import the lifetime-bound
/// type through the public API just to format two scalars.
///
/// `fabric_index` is `NonZeroU8` because the device's `AddNOC` response
/// (spec §11.18.6.10) reserves `0` for "no fabric" / PASE — a real
/// commissioned fabric slot is always non-zero.
#[derive(Debug, Clone, Copy)]
struct CommissionResult {
    fabric_index: NonZeroU8,
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

    info!("=== Commissioner::commission (phase 1 — over PASE) ===");

    // chip-tool's conventional admin NodeID + test vendor — matches
    // what `chip-all-clusters-app` expects on the device-side ACL.
    const FABRIC_ID: u64 = 1;
    const CONTROLLER_NODE_ID: u64 = 112233;
    const DEVICE_NODE_ID: u64 = 112234;
    const ADMIN_VENDOR_ID: u16 = 0xFFF1;

    // Offline CA chain: RCAC then ICAC; RCAC priv key discarded
    // immediately afterwards (in a real deployment it would never
    // have been on the controller in the first place).
    let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut rcac_gen = RcacGenerator::new(&mut rcac_buf);
    let (rcac_priv, rcac) = rcac_gen.generate(crypto, FABRIC_ID, VALID_FOREVER)?;

    let mut icac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut icac_gen = IcacGenerator::new(&mut icac_buf);
    let (icac_priv, icac) =
        icac_gen.generate(crypto, rcac_priv.reference(), rcac, VALID_FOREVER)?;
    drop(rcac_priv);

    // Controller operational keypair + CSR.
    let controller_secret_key = crypto.generate_secret_key()?;
    let mut controller_csr_buf = [0u8; 256];
    let controller_csr = controller_secret_key.csr(&mut controller_csr_buf)?;
    let mut controller_secret_key_canon = CanonPkcSecretKey::new();
    controller_secret_key.write_canon(&mut controller_secret_key_canon)?;

    // NocGenerator: signs the controller NOC now, then the device
    // NOC during commissioning. The NOC serial is derived from the
    // NodeID internally.
    let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut noc_generator = NocGenerator::create(icac_priv.reference(), rcac, icac, &mut noc_buf)?;

    let controller_noc = noc_generator.generate(
        crypto,
        controller_csr,
        CONTROLLER_NODE_ID,
        &[],
        VALID_FOREVER,
    )?;

    // Fabric IPK: 16 random bytes, shared across the fabric.
    let mut ipk = CanonAeadKey::new();
    crypto.rand()?.fill_bytes(ipk.access_mut());

    // Install the fabric in `matter.state.fabrics`.
    let controller_fab_idx = matter.with_state(|state| {
        state
            .fabrics
            .add(
                crypto,
                controller_secret_key_canon.reference(),
                rcac,
                controller_noc,
                icac,
                Some(ipk.reference()),
                ADMIN_VENDOR_ID,
                CONTROLLER_NODE_ID,
            )
            .map(|f| f.fab_idx())
    })?;

    // Scratch buffer for Commissioner — used to stage the fabric's
    // RCAC / ICAC bytes across the async on-wire calls. See
    // `Commissioner::new` for the size requirement.
    let mut commissioner_buf = [0u8; MAX_CERT_TLV_LEN];
    let mut commissioner = Commissioner::new(
        matter,
        crypto,
        controller_fab_idx,
        &mut noc_generator,
        &mut commissioner_buf,
    );

    let opts = CommissionOptions {
        // chip-all-clusters-app ships with the canonical test DAC;
        // skip DCL verification until DAC work lands.
        allow_test_attestation: true,
        ..CommissionOptions::default()
    };

    let phase1 = {
        let mut commission_fut =
            pin!(commissioner.commission(&opts, DEVICE_NODE_ID, VALID_FOREVER));
        let mut timeout = pin!(Timer::after(Duration::from_secs(COMMISSION_TIMEOUT_SECS)));
        match select(&mut commission_fut, &mut timeout).await {
            Either::First(r) => r?,
            Either::Second(_) => {
                error!("commission() timed out after {COMMISSION_TIMEOUT_SECS}s");
                return Err(ErrorCode::RxTimeout.into());
            }
        }
    };
    info!(
        "phase 1 ok: device_fabric_index={}, device_node_id=0x{:016x}",
        phase1.fabric_index, phase1.device_node_id,
    );

    info!("=== complete_via_case (phase 2 — CASE + CommissioningComplete) ===");
    {
        let peer = Address::Udp(args.peer_addr);
        let mut case_fut = pin!(commissioner.complete_via_case(peer, &phase1));
        let mut timeout = pin!(Timer::after(Duration::from_secs(COMMISSION_TIMEOUT_SECS)));
        match select(&mut case_fut, &mut timeout).await {
            Either::First(r) => r?,
            Either::Second(_) => {
                error!("complete_via_case() timed out after {COMMISSION_TIMEOUT_SECS}s");
                return Err(ErrorCode::RxTimeout.into());
            }
        }
    }
    info!("phase 2 ok: CASE established, CommissioningComplete acknowledged");

    Ok(CommissionResult {
        fabric_index: phase1.fabric_index,
        device_node_id: phase1.device_node_id,
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
