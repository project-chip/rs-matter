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

use rs_matter::crypto::{test_only_crypto, Crypto};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::Error;
use rs_matter::respond::Responder;
use rs_matter::sc::pase::{PaseInitiator, MAX_COMM_WINDOW_TIMEOUT_SECS};
use rs_matter::sc::SecureChannel;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::{Address, NoNetwork};
use rs_matter::utils::epoch::sys_epoch;
use rs_matter::utils::select::Coalesce;
use rs_matter::Matter;

use crate::common::{
    create_localhost_socket_pair, init_env_logger, run_device_controller, run_with_transport,
};

/// Test that a full PASE handshake succeeds between two in-process Matter instances.
///
/// The controller initiates a PASE session using `PaseInitiator`, while the device
/// runs a `SecureChannel` responder that handles the handshake. On success the
/// unsecured session is upgraded to a secure PASE session.
#[test]
fn test_pase_handshake() {
    init_env_logger();

    futures_lite::future::block_on(async {
        let device_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, sys_epoch, 0);
        device_matter.initialize_transport_buffers().unwrap();

        let controller_matter =
            Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, sys_epoch, 0);
        controller_matter.initialize_transport_buffers().unwrap();

        let crypto = test_only_crypto();

        let (device_socket, controller_socket) = create_localhost_socket_pair();
        let peer_addr = Address::Udp(device_socket.get_ref().local_addr().unwrap());

        // Open commissioning window so the device accepts PBKDFParamRequest
        device_matter
            .open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())
            .unwrap();

        // Device side: transport + SecureChannel responder
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

        // Controller side: transport + PASE handshake
        let controller_fut = run_with_transport(
            controller_matter.run(&crypto, &controller_socket, &controller_socket, NoNetwork),
            run_pase_handshake(&controller_matter, &crypto, peer_addr),
        );

        run_device_controller(device_fut, controller_fut)
            .await
            .unwrap();
    });
}

async fn run_pase_handshake<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    peer_addr: Address,
) -> Result<(), Error> {
    info!("Creating unsecured session and initiating PASE handshake...");

    let mut exchange = Exchange::initiate_unsecured(matter, crypto, peer_addr).await?;
    info!("Exchange initiated: {}", exchange.id());

    info!("Starting PASE handshake...");

    let mut pase_fut = pin!(PaseInitiator::initiate(&mut exchange, crypto, 20202021));
    let mut timeout = pin!(Timer::after(Duration::from_secs(30)));

    let result = match select(&mut pase_fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => panic!("PASE handshake timed out after 30 seconds"),
    };

    result?;

    info!("PASE handshake completed successfully - secure session established");
    Ok(())
}
