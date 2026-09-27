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

#![cfg(all(feature = "std", feature = "async-io"))]

#[allow(dead_code)]
mod common;

use core::pin::pin;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Instant, Timer};
use log::info;

use rs_matter::crypto::test_only_crypto;
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::Error;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::sc::{OpCode, PROTO_ID_SECURE_CHANNEL};
use rs_matter::tlv::{OctetStr, TLVTag, TLVWrite, ToTLV};
use rs_matter::transport::exchange::{Exchange, MessageMeta};
use rs_matter::transport::network::{Address, NoNetwork};
use rs_matter::Matter;

use crate::common::{create_localhost_socket_pair, init_env_logger, run_with_transport};

/// Test that a received message whose exchange nobody accepts is dropped after the
/// accept timeout (1 second).
///
/// The device runs its transport with no responder, on its own thread so that only its
/// own events wake it. It acknowledges the controller's request only when it drops the
/// exchange, so the controller's send completes at the accept timeout.
#[test]
fn test_unaccepted_exchange_dropped_after_accept_timeout() {
    init_env_logger();

    let (device_socket, controller_socket) = create_localhost_socket_pair();
    let peer_addr = Address::Udp(device_socket.get_ref().local_addr().unwrap());

    let (stop_tx, stop_rx) = async_channel::bounded::<()>(1);

    let device = std::thread::spawn(move || {
        futures_lite::future::block_on(async {
            let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
            let crypto = test_only_crypto();

            matter
                .open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())
                .unwrap();

            // Transport only: nothing accepts the exchange
            let transport = matter.run(&crypto, &device_socket, &device_socket, NoNetwork);

            if let Either::First(r) = select(transport, stop_rx.recv()).await {
                panic!("Device exited: {r:?}");
            }
        });
    });

    futures_lite::future::block_on(async {
        let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
        let crypto = test_only_crypto();

        let controller = run_with_transport(
            matter.run(&crypto, &controller_socket, &controller_socket, NoNetwork),
            async {
                let mut exchange =
                    Exchange::initiate_plaintext(&matter, &crypto, peer_addr).await?;

                let start = Instant::now();

                let send = exchange.send_with(|_, wb| {
                    wb.start_struct(&TLVTag::Anonymous)?;

                    OctetStr::new(&[0x42u8; 32]).to_tlv(&TLVTag::Context(1), &mut *wb)?;
                    1234u16.to_tlv(&TLVTag::Context(2), &mut *wb)?;
                    0u16.to_tlv(&TLVTag::Context(3), &mut *wb)?;
                    false.to_tlv(&TLVTag::Context(4), &mut *wb)?;

                    wb.end_container()?;

                    Ok(Some(MessageMeta::new(
                        PROTO_ID_SECURE_CHANNEL,
                        OpCode::PBKDFParamRequest as u8,
                        true,
                    )))
                });

                match select(pin!(send), pin!(Timer::after(Duration::from_secs(5)))).await {
                    Either::First(r) => r?,
                    Either::Second(()) => panic!("the unaccepted request was never dropped"),
                }

                let elapsed = start.elapsed();
                info!("Request acknowledged after {} ms", elapsed.as_millis());

                assert!(
                    elapsed >= Duration::from_millis(1000),
                    "acknowledged before the accept timeout"
                );
                assert!(
                    elapsed < Duration::from_millis(1200),
                    "dropped late: the accept timeout isn't being polled"
                );

                Ok::<(), Error>(())
            },
        );

        controller.await.unwrap();
    });

    stop_tx.send_blocking(()).unwrap();
    device.join().unwrap();
}
