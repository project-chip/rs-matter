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

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};
use log::info;

use rs_matter::crypto::{test_only_crypto, Crypto};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::Error;
use rs_matter::respond::Responder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::sc::{OpCode, SecureChannel, PROTO_ID_SECURE_CHANNEL};
use rs_matter::tlv::{OctetStr, TLVTag, TLVWrite, ToTLV};
use rs_matter::transport::exchange::{Exchange, MessageMeta};
use rs_matter::transport::network::{Address, NoNetwork};
use rs_matter::utils::epoch::sys_epoch;
use rs_matter::utils::select::Coalesce;
use rs_matter::Matter;

use crate::common::{
    create_localhost_socket_pair, init_env_logger, run_device_controller, run_with_transport,
};

/// Test that an unsecured exchange can be initiated between two rs-matter instances
/// over UDP sockets on localhost.
///
/// The controller opens an unsecured exchange, sends a PBKDFParamRequest, and
/// asserts that the device responds with a PBKDFParamResponse.
#[test]
fn test_unsecured_exchange_over_udp() {
    init_env_logger();

    futures_lite::future::block_on(async {
        // Create device-side and controller-side Matter instances
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

        // Device side: transport + SecureChannel responder (handles PBKDFParamRequest)
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

        // Controller side: transport + exchange test
        let controller_fut = run_with_transport(
            controller_matter.run(&crypto, &controller_socket, &controller_socket, NoNetwork),
            run_exchange_flow(&controller_matter, &crypto, peer_addr),
        );

        run_device_controller(device_fut, controller_fut)
            .await
            .unwrap();
    });
}

async fn run_exchange_flow<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    peer_addr: Address,
) -> Result<(), Error> {
    info!("Creating unsecured session and initiating exchange...");

    let mut exchange = Exchange::initiate_unsecured(matter, crypto, peer_addr).await?;

    info!("Exchange initiated: {}", exchange.id());
    info!("Sending PBKDFParamRequest...");

    let initiator_random = [0x42u8; 32];
    let initiator_ssid: u16 = 1234;
    let passcode_id: u16 = 0;
    let has_params = false;

    exchange
        .send_with(|_, wb| {
            wb.start_struct(&TLVTag::Anonymous)?;
            OctetStr::new(&initiator_random).to_tlv(&TLVTag::Context(1), &mut *wb)?;
            initiator_ssid.to_tlv(&TLVTag::Context(2), &mut *wb)?;
            passcode_id.to_tlv(&TLVTag::Context(3), &mut *wb)?;
            has_params.to_tlv(&TLVTag::Context(4), &mut *wb)?;
            wb.end_container()?;

            Ok(Some(MessageMeta::new(
                PROTO_ID_SECURE_CHANNEL,
                OpCode::PBKDFParamRequest as u8,
                true,
            )))
        })
        .await?;

    info!("PBKDFParamRequest sent, waiting for response...");

    let rx = match select(
        core::pin::pin!(exchange.recv()),
        core::pin::pin!(Timer::after(Duration::from_secs(10))),
    )
    .await
    {
        Either::First(Ok(rx)) => rx,
        Either::First(Err(e)) => return Err(e),
        Either::Second(_) => {
            panic!("Timeout waiting for response");
        }
    };

    let meta = rx.meta();
    info!(
        "Received response: proto_id=0x{:04x}, opcode=0x{:02x}",
        meta.proto_id, meta.proto_opcode
    );

    assert_eq!(meta.proto_id, PROTO_ID_SECURE_CHANNEL);
    assert_eq!(meta.proto_opcode, OpCode::PBKDFParamResponse as u8);
    info!("Got PBKDFParamResponse - exchange round-trip successful!");

    // Release rx's borrow on `exchange` so we can call `acknowledge()` below
    drop(rx);

    exchange.acknowledge().await
}
