/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

#![cfg(all(feature = "std", feature = "async-io"))]

#[allow(dead_code)]
mod common;

use core::pin::pin;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};
use log::info;

use rs_matter::commissioner::fabric_credentials::FabricCredentials;
use rs_matter::crypto::{
    test_only_crypto, CanonAeadKeyRef, CanonPkcSecretKey, Crypto, SecretKey, SigningSecretKey,
};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::Error;
use rs_matter::respond::Responder;
use rs_matter::sc::case::CaseInitiator;
use rs_matter::sc::SecureChannel;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::Address;
use rs_matter::utils::epoch::sys_epoch;
use rs_matter::utils::select::Coalesce;
use rs_matter::Matter;

use crate::common::{create_localhost_socket_pair, init_env_logger, run_device_controller};

const TEST_FABRIC_ID: u64 = 1;
const CONTROLLER_NODE_ID: u64 = 100;
const DEVICE_NODE_ID: u64 = 200;

/// Test that a full CASE handshake succeeds between two in-process Matter instances.
///
/// The controller initiates a CASE session using `CaseInitiator`, while the device
/// runs a `SecureChannel` responder that handles the handshake. On success the
/// unsecured session is upgraded to a secure CASE session.
///
/// Uses `FabricCredentials` to generate all certs at runtime via the NOC generation
/// infrastructure — no raw cert builders or hardcoded test vectors.
#[test]
fn test_case_handshake() {
    init_env_logger();

    futures_lite::future::block_on(async {
        let crypto = test_only_crypto();

        // ---- 1. Generate credentials using FabricCredentials ----

        let mut fabric_creds = FabricCredentials::new(&crypto, TEST_FABRIC_ID).unwrap();

        // Generate controller credentials (keypair + CSR + NOC)
        let controller_secret_key = crypto.generate_secret_key().unwrap();
        let mut controller_csr_buf = [0u8; 256];
        let controller_csr = controller_secret_key.csr(&mut controller_csr_buf).unwrap();
        let controller_creds = fabric_creds
            .generate_device_credentials_with_node_id(
                &crypto,
                controller_csr,
                CONTROLLER_NODE_ID,
                &[],
            )
            .unwrap();

        let mut controller_secret_key_canon = CanonPkcSecretKey::new();
        controller_secret_key
            .write_canon(&mut controller_secret_key_canon)
            .unwrap();

        // Generate device credentials (keypair + CSR + NOC)
        let device_secret_key = crypto.generate_secret_key().unwrap();
        let mut device_csr_buf = [0u8; 256];
        let device_csr = device_secret_key.csr(&mut device_csr_buf).unwrap();
        let device_creds = fabric_creds
            .generate_device_credentials_with_node_id(&crypto, device_csr, DEVICE_NODE_ID, &[])
            .unwrap();

        let mut device_secret_key_canon = CanonPkcSecretKey::new();
        device_secret_key
            .write_canon(&mut device_secret_key_canon)
            .unwrap();

        // ---- 2. Set up two Matter instances ----

        let device_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, sys_epoch, 0);
        device_matter.initialize_transport_buffers().unwrap();

        let controller_matter =
            Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, sys_epoch, 0);
        controller_matter.initialize_transport_buffers().unwrap();

        // ---- 3. Populate both FabricMgrs with matching fabric ----

        let controller_fab_idx = controller_matter
            .fabric_mgr
            .borrow_mut()
            .add(
                &crypto,
                controller_secret_key_canon.reference(),
                &controller_creds.root_cert,
                &controller_creds.noc,
                controller_creds
                    .icac
                    .as_ref()
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]),
                Some(CanonAeadKeyRef::new(&controller_creds.ipk)),
                0xFFF1,
                CONTROLLER_NODE_ID,
                &mut || {},
            )
            .unwrap()
            .fab_idx();

        device_matter
            .fabric_mgr
            .borrow_mut()
            .add(
                &crypto,
                device_secret_key_canon.reference(),
                &device_creds.root_cert,
                &device_creds.noc,
                device_creds
                    .icac
                    .as_ref()
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]),
                Some(CanonAeadKeyRef::new(&device_creds.ipk)),
                0xFFF1,
                CONTROLLER_NODE_ID,
                &mut || {},
            )
            .unwrap();

        // ---- 4. Bind UDP sockets ----

        let (device_socket, controller_socket) = create_localhost_socket_pair();
        let peer_addr = Address::Udp(device_socket.get_ref().local_addr().unwrap());

        // ---- 5. Device side: transport + SecureChannel responder ----
        // No need to open commissioning window for CASE

        let sc = SecureChannel::new(&crypto, &());
        let responder = Responder::new("device", sc, &device_matter, 0);

        let device_fut = async {
            select(
                device_matter.run_transport(&crypto, &device_socket, &device_socket),
                responder.run::<4>(),
            )
            .coalesce()
            .await
        };

        // ---- 6. Controller side: transport + CASE handshake ----

        let controller_fut = async {
            let mut transport = pin!(controller_matter.run_transport(
                &crypto,
                &controller_socket,
                &controller_socket,
            ));
            let mut test = pin!(run_case_handshake(
                &controller_matter,
                &crypto,
                peer_addr,
                controller_fab_idx,
                DEVICE_NODE_ID,
            ));

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
    fab_idx: core::num::NonZeroU8,
    peer_node_id: u64,
) -> Result<(), Error> {
    info!("Creating unsecured session and initiating CASE handshake...");

    let mut exchange = Exchange::initiate_unsecured(matter, crypto, peer_addr).await?;
    info!("Exchange initiated: {}", exchange.id());

    info!("Starting CASE handshake...");

    let mut case_fut = pin!(CaseInitiator::initiate(
        &mut exchange,
        crypto,
        fab_idx,
        peer_node_id,
    ));
    let mut timeout = pin!(Timer::after(Duration::from_secs(30)));

    let result = match select(&mut case_fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => panic!("CASE handshake timed out after 30 seconds"),
    };

    result?;

    info!("CASE handshake completed successfully - secure session established");
    Ok(())
}
