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

//! End-to-end test for CASE session resumption.
//!
//! Establishes two CASE sessions back-to-back between two in-process
//! `Matter` instances that share a fabric, and verifies the second
//! handshake takes the resumption path rather than a fresh full
//! handshake.
//!
//! The distinguishing signal is the cached `SharedSecret`:
//! - Full handshake mints a fresh ECDH `SharedSecret` and replaces the
//!   cache entry with it.
//! - Successful resumption reuses the previous `SharedSecret` and
//!   only rotates the `ResumptionID`.
//!
//! So after handshake #2, if the `SharedSecret` in the cache is
//! unchanged from #1 (and the `ResumptionID` did change), we know
//! resumption happened on both sides.

#![cfg(all(feature = "std", feature = "async-io", feature = "case-resumption"))]

use core::num::NonZeroU8;
use core::pin::pin;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use log::info;

use rs_matter::cert::gen::VALID_FOREVER;
use rs_matter::cert::MAX_CERT_TLV_AND_ASN1_LEN;
use rs_matter::crypto::{
    test_only_crypto, CanonAeadKey, CanonAeadKeyRef, CanonPkcSecretKey, Crypto, Rng, SecretKey,
    SigningSecretKey, AEAD_CANON_KEY_LEN,
};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::Error;
use rs_matter::onboard::cac::RcacGenerator;
use rs_matter::onboard::noc::NocGenerator;
use rs_matter::respond::Responder;
use rs_matter::sc::case::CaseInitiator;
use rs_matter::sc::SecureChannel;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::{Address, NoNetwork};

use rs_matter::utils::select::Coalesce;
use rs_matter::Matter;

use crate::common::{create_localhost_socket_pair, init_env_logger, run_device_controller};

#[allow(dead_code)]
mod common;

const TEST_FABRIC_ID: u64 = 1;
const CONTROLLER_NODE_ID: u64 = 100;
const DEVICE_NODE_ID: u64 = 200;

/// Copy of a resumption record's identifying material, extracted from
/// the cache so we can compare pre- and post-handshake without holding
/// a borrow into `MatterState`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheSnapshot {
    shared_secret: [u8; 32],
    resumption_id: [u8; 16],
}

/// Pull the resumption record for `(fab_idx, peer_nodeid)` from
/// `matter`'s in-memory cache, if any. Returns `None` when no matching
/// record exists.
fn snapshot(matter: &Matter<'_>, fab_idx: NonZeroU8, peer_nodeid: u64) -> Option<CacheSnapshot> {
    matter.with_state(|state| {
        state
            .resumption
            .find_by_peer(fab_idx, peer_nodeid)
            .map(|rec| CacheSnapshot {
                shared_secret: *rec.shared_secret.reference().access(),
                resumption_id: *rec.resumption_id.reference().access(),
            })
    })
}

/// Two back-to-back CASE handshakes between two in-process Matter
/// instances that share a fabric. Handshake #2 must take the
/// resumption path.
///
/// See the module-level doc comment for the distinguishing-signal
/// rationale (`SharedSecret` unchanged, `ResumptionID` rotated).
#[test]
fn test_case_resumption_round_trip() {
    init_env_logger();

    futures_lite::future::block_on(async {
        let crypto = test_only_crypto();

        // ---- 1. Generate shared fabric material: RCAC + IPK + NOCs ----
        //
        // Same recipe as `tests/case.rs` — signing one RCAC and both
        // NOCs against it so controller and device end up on the same
        // fabric.

        let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut rcac_gen = RcacGenerator::new(&mut rcac_buf);
        let (rcac_privkey, rcac) = rcac_gen
            .generate(&crypto, TEST_FABRIC_ID, VALID_FOREVER)
            .unwrap();

        let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut noc_generator =
            NocGenerator::create(rcac_privkey.reference(), rcac, &[], &mut noc_buf).unwrap();

        // Shared fabric IPK (16 random bytes).
        let mut ipk = CanonAeadKey::new();
        let mut ipk_bytes = [0u8; AEAD_CANON_KEY_LEN];
        crypto.rand().unwrap().fill_bytes(&mut ipk_bytes);
        ipk.load_from_array(&ipk_bytes);
        let ipk_ref: CanonAeadKeyRef<'_> = ipk.reference();

        // Controller signing keypair + CSR.
        let controller_secret_key = crypto.generate_secret_key().unwrap();
        let mut controller_csr_buf = [0u8; 256];
        let controller_csr = controller_secret_key.csr(&mut controller_csr_buf).unwrap();
        let mut controller_secret_key_canon = CanonPkcSecretKey::new();
        controller_secret_key
            .write_canon(&mut controller_secret_key_canon)
            .unwrap();

        // Device signing keypair + CSR.
        let device_secret_key = crypto.generate_secret_key().unwrap();
        let mut device_csr_buf = [0u8; 256];
        let device_csr = device_secret_key.csr(&mut device_csr_buf).unwrap();
        let mut device_secret_key_canon = CanonPkcSecretKey::new();
        device_secret_key
            .write_canon(&mut device_secret_key_canon)
            .unwrap();

        // ---- 2. Set up two Matter instances ----

        let device_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
        let controller_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);

        // ---- 3. Install the same fabric in both fabric tables ----
        //
        // The NOC slice returned by `noc_generator.generate` borrows
        // `noc_buf`, so it must be consumed before the next
        // `generate` call overwrites the buffer.

        let controller_noc = noc_generator
            .generate(
                &crypto,
                controller_csr,
                CONTROLLER_NODE_ID,
                &[],
                VALID_FOREVER,
            )
            .unwrap();

        let controller_fab_idx = controller_matter.with_state(|state| {
            state
                .fabrics
                .add(
                    &crypto,
                    controller_secret_key_canon.reference(),
                    rcac,
                    controller_noc,
                    &[], // no ICAC
                    Some(ipk_ref),
                    0xFFF1,
                    CONTROLLER_NODE_ID,
                )
                .unwrap()
                .fab_idx()
        });

        let device_noc = noc_generator
            .generate(&crypto, device_csr, DEVICE_NODE_ID, &[], VALID_FOREVER)
            .unwrap();

        let device_fab_idx = device_matter.with_state(|state| {
            state
                .fabrics
                .add(
                    &crypto,
                    device_secret_key_canon.reference(),
                    rcac,
                    device_noc,
                    &[], // no ICAC
                    Some(ipk_ref),
                    0xFFF1,
                    CONTROLLER_NODE_ID,
                )
                .unwrap()
                .fab_idx()
        });

        // ---- 4. Bind UDP sockets ----

        let (device_socket, controller_socket) = create_localhost_socket_pair();
        let peer_addr = Address::Udp(device_socket.get_ref().local_addr().unwrap());

        // ---- 5. Device side: transport + SecureChannel responder ----

        let sc = SecureChannel::new(&crypto, &());
        let responder = Responder::new("device", sc, &device_matter, 0);

        let device_fut = async {
            select(
                device_matter.run(&crypto, &device_socket, &device_socket, NoNetwork),
                responder.run::<4>(),
            )
            .coalesce()
            .await
        };

        // ---- 6. Controller side: transport + two CASE handshakes ----

        let controller_fut = async {
            let mut transport = pin!(controller_matter.run(
                &crypto,
                &controller_socket,
                &controller_socket,
                NoNetwork,
            ));

            let mut test = pin!(async {
                // ---- Handshake #1 — full CASE ----
                info!("--- First CASE handshake (full) ---");
                run_case_handshake(
                    &controller_matter,
                    &crypto,
                    peer_addr,
                    controller_fab_idx,
                    DEVICE_NODE_ID,
                )
                .await?;

                // Both sides must have cached a record.
                let ctrl_after1 = snapshot(&controller_matter, controller_fab_idx, DEVICE_NODE_ID)
                    .expect("controller cache empty after handshake #1");
                let dev_after1 = snapshot(&device_matter, device_fab_idx, CONTROLLER_NODE_ID)
                    .expect("device cache empty after handshake #1");

                // Both sides must agree on the same (SharedSecret, ResumptionID).
                assert_eq!(
                    ctrl_after1, dev_after1,
                    "controller and device disagree on cache contents after handshake #1"
                );

                // ---- Handshake #2 — must resume ----
                info!("--- Second CASE handshake (resumption expected) ---");
                run_case_handshake(
                    &controller_matter,
                    &crypto,
                    peer_addr,
                    controller_fab_idx,
                    DEVICE_NODE_ID,
                )
                .await?;

                let ctrl_after2 = snapshot(&controller_matter, controller_fab_idx, DEVICE_NODE_ID)
                    .expect("controller cache empty after handshake #2");
                let dev_after2 = snapshot(&device_matter, device_fab_idx, CONTROLLER_NODE_ID)
                    .expect("device cache empty after handshake #2");

                // Distinguishing signal: SharedSecret is unchanged.
                // If handshake #2 had done a full CASE, this would have
                // rotated to a fresh ECDH result and the assertion
                // would fail.
                assert_eq!(
                    ctrl_after2.shared_secret, ctrl_after1.shared_secret,
                    "SharedSecret rotated on controller side — handshake #2 did NOT resume"
                );
                assert_eq!(
                    dev_after2.shared_secret, dev_after1.shared_secret,
                    "SharedSecret rotated on device side — handshake #2 did NOT resume"
                );

                // The `ResumptionID` must have rotated (responder mints
                // a fresh one in `Sigma2_Resume`).
                assert_ne!(
                    ctrl_after2.resumption_id, ctrl_after1.resumption_id,
                    "ResumptionID did not rotate on controller side"
                );
                assert_ne!(
                    dev_after2.resumption_id, dev_after1.resumption_id,
                    "ResumptionID did not rotate on device side"
                );

                // Sides must still agree.
                assert_eq!(
                    ctrl_after2, dev_after2,
                    "controller and device disagree on cache contents after handshake #2"
                );

                info!("CASE resumption verified end-to-end");
                Ok::<_, Error>(())
            });

            match select(&mut transport, &mut test).await {
                Either::First(transport_result) => {
                    panic!("Controller transport exited prematurely: {transport_result:?}");
                }
                Either::Second(test_result) => {
                    // Give transport a moment to flush final messages
                    let mut flush = pin!(Timer::after(Duration::from_millis(300)));
                    if let Either::First(transport_result) =
                        select(&mut transport, &mut flush).await
                    {
                        panic!("Controller transport error during flush: {transport_result:?}");
                    }
                    test_result
                }
            }
        };

        // ---- 7. Run device and controller concurrently ----

        run_device_controller(device_fut, controller_fut)
            .await
            .unwrap();
    });
}

async fn run_case_handshake<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    peer_addr: Address,
    fab_idx: NonZeroU8,
    peer_node_id: u64,
) -> Result<(), Error> {
    let exchange = Exchange::initiate_plaintext(matter, crypto, peer_addr).await?;

    let mut case_fut = pin!(CaseInitiator::perform(
        exchange,
        crypto,
        fab_idx,
        peer_node_id,
    ));
    let mut timeout = pin!(Timer::after(Duration::from_secs(30)));

    match select(&mut case_fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => panic!("CASE handshake timed out after 30 seconds"),
    }
}
