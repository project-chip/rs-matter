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

//! Minimal end-to-end PASE smoke test.
//!
//! Usage:
//!   1. In one terminal: `cargo run --release --bin onoff_light`
//!      (or any rs-matter responder that opens a Basic Commissioning Window).
//!   2. In another terminal: `cargo run --release --bin pase_smoke_test`
//!
//! What it does:
//!   - Constructs a controller-side `Matter` bound to port 5541 (so it
//!     doesn't fight the responder for the standard 5540).
//!   - Opens an unsecured exchange to `127.0.0.1:5540` (the responder).
//!   - Drives `PaseInitiator::initiate` with passcode 20202021 (the
//!     canonical test passcode that onoff_light + chip_tool_tests use).
//!   - Reports whether PASE completed.
//!
//! Success = the responder's "PASE Basic Commissioning Window" picks up,
//! Spake2+ messages exchange, and `PaseInitiator::initiate` returns `Ok(())`.
//! Failure = first stage where the handshake broke down. The output of
//! both processes together identifies the offending step.
//!
//! This is the test the controller-side commissioner work has been
//! building toward — proves PASE *actually negotiates over the wire*
//! between rs-matter's responder and our `PaseInitiator` driver.

use std::net::{SocketAddr, UdpSocket};

use async_io::Async;
use log::{error, info};

use rs_matter::commissioner::FabricCredentials;
use rs_matter::controller::commissioner::{arm_fail_safe, commission_pase, csr_request};
use rs_matter::crypto::default_crypto;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::sc::pase::PaseInitiator;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::Address;
use rs_matter::{Matter, MATTER_PORT};

const SMOKE_TEST_PORT: u16 = 5541;
const RESPONDER_PORT: u16 = MATTER_PORT; // 5540
                                         // IPv6 localhost — matches the bind on [::]:SMOKE_TEST_PORT. Mixing v4
                                         // peer + v6 socket fails with EINVAL on macOS (and is iffy on Linux too
                                         // without IPV6_V6ONLY=0). rs-matter's whole transport is IPv6-native.
const RESPONDER_ADDR: &str = "[::1]";
const PASSCODE: u32 = 20202021;

fn main() {
    env_logger::init();
    info!("PASE smoke test starting (controller side)");

    // Run the whole thing on a stack-size-bumped thread — `Matter`'s
    // futures want ~550 KB of stack (matches what onoff_light does).
    let thread = std::thread::Builder::new()
        .stack_size(550 * 1024)
        .spawn(|| {
            if let Err(e) = run() {
                error!("smoke test thread error: {}", e);
                std::process::exit(1);
            }
        })
        .expect("spawn");
    thread.join().expect("join");
}

fn run() -> Result<(), String> {
    // 1. Controller-side Matter runtime. We use the same TEST_DEV_*
    //    fixtures the device side uses — the controller doesn't actually
    //    serve attestation to peers, but the constructor needs the refs.
    let matter = Box::leak(Box::new(Matter::new_default(
        &TEST_DEV_DET,
        TEST_DEV_COMM.clone(),
        &TEST_DEV_ATT,
        SMOKE_TEST_PORT,
    )));

    let bind_addr: SocketAddr = format!("[::]:{}", SMOKE_TEST_PORT)
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let socket = Async::<UdpSocket>::bind(bind_addr).map_err(|e| e.to_string())?;
    info!(
        "controller bound on UDP {} (responder at {}:{})",
        SMOKE_TEST_PORT, RESPONDER_ADDR, RESPONDER_PORT
    );

    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);

    let main = async move {
        let peer_addr: SocketAddr = format!("{}:{}", RESPONDER_ADDR, RESPONDER_PORT)
            .parse()
            .unwrap();
        let peer = Address::Udp(peer_addr);

        // Run the matter transport in parallel with the PASE handshake.
        // PASE needs the transport pump alive to send/receive.
        let transport_fut = matter.run(&crypto, &socket, &socket, &socket);
        let pase_fut = async {
            info!("opening unsecured exchange to {}", peer_addr);
            let mut exchange = Exchange::initiate_unsecured(matter, &crypto, peer).await?;
            info!(
                "unsecured exchange open — driving PASE with passcode {}",
                PASSCODE
            );
            PaseInitiator::initiate(&mut exchange, &crypto, PASSCODE).await?;
            info!("✓ PASE handshake completed");
            drop(exchange); // PASE session now cached; subsequent opens are secured

            // Stage 2: ArmFailSafe over the PASE-secured channel.
            //   - Opens a fresh exchange (fab=0, peer=0, secure=true)
            //   - Sends GeneralCommissioning::ArmFailSafe(60, 0)
            //   - Waits for the device's ArmFailSafeResponse
            info!("calling ArmFailSafe(60s, breadcrumb=0) over PASE...");
            arm_fail_safe(matter, 60, 0).await.map_err(|e| {
                error!("arm_fail_safe error: {:?}", e);
                rs_matter::error::Error::new(rs_matter::error::ErrorCode::NoExchange)
            })?;
            info!("✓ ArmFailSafe completed");

            // Stage 3: CSRRequest over PASE — exercises response-bearing
            // IM invoke (decode NOCSRElements from the device's reply).
            use rand::RngCore;
            let mut nonce = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut nonce);
            info!("calling CSRRequest(random 32B nonce) over PASE...");
            let csr = csr_request(matter, &nonce).await.map_err(|e| {
                error!("csr_request error: {:?}", e);
                rs_matter::error::Error::new(rs_matter::error::ErrorCode::NoExchange)
            })?;
            info!(
                "✓✓✓ CSRRequest completed — got {}B NOCSRElements + {}B AttestationSignature",
                csr.nocsr_elements.len(),
                csr.attestation_signature.len()
            );

            // Stage 4: full end-to-end commissioning. NOCSR decode →
            // controller issues a NOC against its own fabric → installs
            // RCAC → AddNOC → CommissioningComplete. After this the
            // device is part of our fabric and should respond on its
            // operational identity.
            info!("building controller-side FabricCredentials (fabric_id=1)...");
            let mut fabric_creds = FabricCredentials::new(&crypto, 1).map_err(|e| {
                error!("FabricCredentials::new error: {:?}", e);
                rs_matter::error::Error::new(rs_matter::error::ErrorCode::Invalid)
            })?;
            info!(
                "calling commission_pase(admin_subject=112233, admin_vendor_id=0xFFF1, fs=60s)..."
            );
            let result = commission_pase(matter, &crypto, &mut fabric_creds, 112233, 0xFFF1, 60)
                .await
                .map_err(|e| {
                    error!("commission_pase error: {:?}", e);
                    rs_matter::error::Error::new(rs_matter::error::ErrorCode::NoExchange)
                })?;
            info!(
                "✓✓✓✓ commission_pase done — fabric_index={} device_node_id=0x{:016x} \
                 noc={}B icac={}B",
                result.fabric_index,
                result.device_node_id,
                result.noc_der.len(),
                result.icac_der.len()
            );
            Ok::<(), rs_matter::error::Error>(())
        };

        match futures_lite::future::or(
            async {
                let r = pase_fut.await;
                match &r {
                    Ok(()) => info!("controller-side PASE flow returned Ok"),
                    Err(e) => error!("controller-side PASE flow returned Err: {:?}", e),
                }
                r
            },
            async {
                transport_fut.await.unwrap_or_else(|e| {
                    error!("transport future ended: {:?}", e);
                });
                Err(rs_matter::error::Error::new(
                    rs_matter::error::ErrorCode::NoExchange,
                ))
            },
        )
        .await
        {
            Ok(()) => info!("smoke test PASS"),
            Err(e) => error!("smoke test FAIL: {:?}", e),
        }
    };

    async_io::block_on(main);
    Ok(())
}
