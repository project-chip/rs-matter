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

// Too annoying to create the tests without alloc
// (and STD - only needs `rand` and `RawMutex` implementations)
#![cfg(feature = "std")]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};

use embassy_futures::block_on;

use crate::utils::sync::blocking::raw::StdRawMutex;

use super::*;

extern crate alloc;

const PEER_ADDR: BtAddr = BtAddr([1, 2, 3, 4, 5, 6]);

const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    vid: 10,
    pid: 11,
    hw_ver: 12,
    sw_ver: 13,
    sw_ver_str: "13",
    serial_no: "aabbccdd",
    device_name: "Test Device",
    product_name: "TestProd",
    vendor_name: "TestVendor",
    sai: None,
    sii: None,
};

#[derive(Debug, Clone)]
enum PeripheralIncoming {
    Subscribed(BtAddr),
    Unsubscribed(BtAddr),
    Write {
        address: BtAddr,
        data: Vec<u8>,
        gatt_mtu: Option<u16>,
    },
}

#[derive(Debug, Eq, PartialEq)]
struct PeripheralOutgoing {
    data: Vec<u8>,
    address: BtAddr,
}

/// A utlity struct to send and receive data on behalf of the peer (the "peripheral").
struct Peripheral {
    peer_sender: async_channel::Sender<PeripheralIncoming>,
    peer_receiver: async_channel::Receiver<PeripheralOutgoing>,
}

impl Peripheral {
    /// Generate `GattPeripheralEvent::NotifySubscribed` event for the peer
    async fn subscribe(&self, addr: BtAddr) {
        self.peer_sender
            .send(PeripheralIncoming::Subscribed(addr))
            .await
            .unwrap();
    }

    /// Generate `GattPeripheralEvent::NotifyUnsubscribed` event for the peer
    async fn unsubscribe(&self, addr: BtAddr) {
        self.peer_sender
            .send(PeripheralIncoming::Unsubscribed(addr))
            .await
            .unwrap();
    }

    /// Generate `GattPeripheralEvent::Write` event for the peer
    async fn send(&self, data: &[u8], addr: BtAddr, gatt_mtu: Option<u16>) {
        self.peer_sender
            .send(PeripheralIncoming::Write {
                address: addr,
                data: data.to_vec(),
                gatt_mtu,
            })
            .await
            .unwrap();
    }

    /// Expect to receive the provided data from the peer as if the BTP protocol
    /// did call `indicate`
    async fn expect(&self, data: &[u8], addr: BtAddr) {
        let received = self.peer_receiver.recv().await.unwrap();

        assert_eq!(received.data, data);
        assert_eq!(received.address, addr);
    }
}

#[derive(Debug)]
struct IoPacket {
    data: Vec<u8>,
    address: BtAddr,
}

/// A utility struct so that we can send and receive data on behalf of the BTP protocol.
struct Io {
    send: async_channel::Sender<IoPacket>,
    recv: async_channel::Receiver<IoPacket>,
    context: Arc<BtpContext<StdRawMutex>>,
}

impl Io {
    /// Drive the BTP protocol by sending the provided data to the peer
    async fn send(&self, data: &[u8], addr: BtAddr) {
        let packet = IoPacket {
            data: data.to_vec(),
            address: addr,
        };

        self.send.send(packet).await.unwrap();
    }

    /// Drive the BTP protocol by expecting to receive the provided data from the peer
    async fn expect(&self, data: &[u8], addr: BtAddr) {
        let packet = self.recv.recv().await.unwrap();

        assert_eq!(packet.data, data);
        assert_eq!(packet.address, addr);
    }
}

/// A mocked peripheral that can be used to test the BTP protocol
///
/// It provides facilities to send data as if it is the peer (the "peripheral") which is sending it,
/// as well as facilities to assert what data is expected to be received by the peer.
///
/// Sending/receiving data on behalf of the peer (the "peripheral") is done using the `Peripheral` struct,
/// while sending/receiving data on behalf of us (the BTP protocol) is done using the `Io` struct.
struct GattPeriheralMock {
    sender: async_channel::Sender<PeripheralOutgoing>,
    receiver: async_channel::Receiver<PeripheralIncoming>,
}

impl GattPeriheralMock {
    /// Run the provided test closure using the mock peripheral
    ///
    /// The test closure may use the provided `Peripheral` instance
    /// to send and receive data on behalf of the peer ("peripheral").
    ///
    /// The test closure may use the provided `Io` instance to send
    /// and receive data on behalf of "us" (i.e. the BTP protocol).
    fn run<T, F>(test: T)
    where
        T: FnOnce(Peripheral, Io) -> F,
        F: Future<Output = ()> + Send + 'static,
    {
        Self::run_with_custom_timeouts(BTP_ACK_TIMEOUT_SECS, BTP_CONN_IDLE_TIMEOUT_SECS, test)
    }

    /// Same as run but provides the opportunity for custom ACK timeout.
    fn run_with_custom_timeouts<T, F>(ack_timeout_secs: u16, conn_idle_timeout_secs: u16, test: T)
    where
        T: FnOnce(Peripheral, Io) -> F,
        F: Future<Output = ()> + Send + 'static,
    {
        #[cfg(all(feature = "std", not(target_os = "espidf")))]
        {
            let _ = env_logger::try_init_from_env(
                env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
            );
        }

        // Pipe send/receive data between the mocked peripheral and the BTP protocol using channels.

        let (sender, peer_receiver) = async_channel::unbounded();
        let (peer_sender, receiver) = async_channel::unbounded();

        let mock = GattPeriheralMock { sender, receiver };

        let context = Arc::new(BtpContext::<StdRawMutex>::new());
        let btp = Arc::new(Btp::new_internal(
            mock,
            context.clone(),
            ack_timeout_secs,
            conn_idle_timeout_secs,
        ));

        let (io_sender, io_btp_receiver) = async_channel::unbounded();
        let (io_btp_sender, io_receiver) = async_channel::unbounded();

        let test_fut = Box::pin(test(
            Peripheral {
                peer_sender,
                peer_receiver,
            },
            Io {
                send: io_sender.clone(),
                recv: io_receiver.clone(),
                context,
            },
        ));

        block_on(
            select4(
                btp.run("test", &BASIC_INFO, 250),
                async {
                    loop {
                        let mut buf = vec![0; 1500];

                        let Ok((len, addr)) = btp.recv(&mut buf).await else {
                            break;
                        };

                        buf.truncate(len);

                        io_btp_sender
                            .send(IoPacket {
                                data: buf,
                                address: addr,
                            })
                            .await
                            .unwrap();
                    }

                    Ok(())
                },
                async {
                    while let Ok::<IoPacket, _>(packet) = io_btp_receiver.recv().await {
                        btp.send(&packet.data, packet.address).await.unwrap();
                    }

                    Ok(())
                },
                async {
                    test_fut.await;

                    Ok(())
                },
            )
            .coalesce(),
        )
        .unwrap();
    }
}

impl GattPeripheral for GattPeriheralMock {
    async fn indicate(&self, data: &[u8], address: BtAddr) -> Result<(), Error> {
        self.sender
            .send(PeripheralOutgoing {
                data: data.to_vec(),
                address,
            })
            .await
            .unwrap();

        Ok(())
    }

    async fn run<F>(
        &self,
        _service_name: &str,
        _adv_data: &AdvData,
        callback: F,
    ) -> Result<(), Error>
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + Clone + 'static,
    {
        while let Ok(msg) = self.receiver.recv().await {
            match msg {
                PeripheralIncoming::Subscribed(addr) => {
                    callback(GattPeripheralEvent::NotifySubscribed(addr));
                }
                PeripheralIncoming::Unsubscribed(addr) => {
                    callback(GattPeripheralEvent::NotifyUnsubscribed(addr));
                }
                PeripheralIncoming::Write {
                    address,
                    data,
                    gatt_mtu,
                } => {
                    callback(GattPeripheralEvent::Write {
                        address,
                        data: &data,
                        gatt_mtu,
                    });
                }
            }
        }

        Ok(())
    }
}

#[test]
fn test_mtu() {
    GattPeriheralMock::run(|peripheral, io| async move {
        peripheral
            .send(
                &[0x65, 0x6c, 0x54, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x05],
                PEER_ADDR,
                Some(0xc8),
            )
            .await;

        peripheral.subscribe(PEER_ADDR).await;

        // io.context.sessions.lock(|sessions| {
        //     assert!(sessions.borrow().len() == 1);
        // });

        // Expected MTU in response is 0xc8 - 3 = 0xc5
        peripheral
            .expect(&[0x65, 0x6c, 0x05, 0xc5, 0x00, 0x05], PEER_ADDR)
            .await;

        peripheral.unsubscribe(PEER_ADDR).await;

        Timer::after(Duration::from_secs(1)).await;

        io.context.sessions.lock(|sessions| {
            assert!(sessions.borrow().is_empty());
        });

        /////////////////////////////////

        peripheral
            .send(
                &[0x65, 0x6c, 0x54, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x05],
                PEER_ADDR,
                None, // GATT MTU is unknown
            )
            .await;

        peripheral.subscribe(PEER_ADDR).await;

        // io.context.sessions.lock(|sessions| {
        //     assert!(sessions.borrow().len() == 1);
        // });

        // Expected MTU is the minimum one (0x14)
        peripheral
            .expect(&[0x65, 0x6c, 0x05, 0x14, 0x00, 0x05], PEER_ADDR)
            .await;
    });
}

// Utility to do the negotiation phase with a minumum MTU
async fn nego_min_mtu(peripheral: &Peripheral) {
    peripheral
        .send(
            &[0x65, 0x6c, 0x54, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x05],
            PEER_ADDR,
            None,
        )
        .await;

    peripheral.subscribe(PEER_ADDR).await;

    // io.context.sessions.lock(|sessions| {
    //     assert!(sessions.borrow().len() == 1);
    // });

    // Peer window = 1 because of this handshake resp
    peripheral
        .expect(&[0x65, 0x6c, 0x05, 0x14, 0x00, 0x05], PEER_ADDR)
        .await;
}

#[test]
fn test_short_read() {
    GattPeriheralMock::run(|peripheral, io| async move {
        nego_min_mtu(&peripheral).await;

        io.send(&[0, 1, 2, 3], PEER_ADDR).await;

        peripheral
            .expect(&[5, 1, 4, 0, 0, 1, 2, 3], PEER_ADDR)
            .await;
    });
}

#[test]
fn test_short_write() {
    GattPeriheralMock::run(|peripheral, io| async move {
        nego_min_mtu(&peripheral).await;

        peripheral
            .send(&[5, 0, 3, 0, 1, 2, 3], PEER_ADDR, None)
            .await;

        io.expect(&[1, 2, 3], PEER_ADDR).await;
    });
}

#[test]
fn test_long_read() {
    GattPeriheralMock::run(|peripheral, io| async move {
        nego_min_mtu(&peripheral).await;

        io.send(&[0; 52], PEER_ADDR).await;

        // Long msg beginning
        peripheral
            .expect(
                &[1, 1, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                PEER_ADDR,
            )
            .await;

        // Long msg continue
        peripheral
            .expect(
                &[2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                PEER_ADDR,
            )
            .await;

        // Long msg end
        peripheral
            .expect(
                &[6, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                PEER_ADDR,
            )
            .await;

        peripheral.unsubscribe(PEER_ADDR).await;

        Timer::after(Duration::from_secs(1)).await;

        io.context.sessions.lock(|sessions| {
            assert!(sessions.borrow().is_empty());
        });
    });
}

#[test]
fn test_long_write() {
    GattPeriheralMock::run(|peripheral, io| async move {
        nego_min_mtu(&peripheral).await;

        // Beginning
        peripheral
            .send(
                &[
                    1, 0, 30, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                ],
                PEER_ADDR,
                None,
            )
            .await;

        // End
        peripheral
            .send(
                &[4, 1, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30],
                PEER_ADDR,
                None,
            )
            .await;

        io.expect(
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30,
            ],
            PEER_ADDR,
        )
        .await;
    });
}

#[test]
fn test_long_read_ack() {
    GattPeriheralMock::run(|peripheral, io| async move {
        nego_min_mtu(&peripheral).await;

        // A short message, to pump up the ack window
        io.send(&[0, 1, 2, 3], PEER_ADDR).await;

        // Peer window = 2
        peripheral
            .expect(&[5, 1, 4, 0, 0, 1, 2, 3], PEER_ADDR)
            .await;

        io.send(&[0; 100], PEER_ADDR).await;

        // Long msg beginning
        // Peer window = 3
        peripheral
            .expect(
                &[1, 2, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                PEER_ADDR,
            )
            .await;

        // Long msg continue
        // Peer window = 4
        peripheral
            .expect(
                &[2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                PEER_ADDR,
            )
            .await;

        // Send ACK from the peer as its window is full by now (5 - 1) = 4
        peripheral.send(&[8, 3, 0], PEER_ADDR, None).await;

        // Long msg end + ACK
        // Peer window = 0, final packet
        peripheral
            .expect(
                &[10, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                PEER_ADDR,
            )
            .await;

        peripheral.unsubscribe(PEER_ADDR).await;

        Timer::after(Duration::from_secs(1)).await;

        io.context.sessions.lock(|sessions| {
            assert!(sessions.borrow().is_empty());
        });
    });
}

#[test]
fn test_long_write_ack() {
    GattPeriheralMock::run(|peripheral, io| async move {
        nego_min_mtu(&peripheral).await;

        // Beginning
        peripheral
            .send(
                &[1, 0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                PEER_ADDR,
                None,
            )
            .await;

        // Continue
        peripheral
            .send(
                &[2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                PEER_ADDR,
                None,
            )
            .await;

        // End
        peripheral
            .send(&[4, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], PEER_ADDR, None)
            .await;

        io.expect(&[0; 44], PEER_ADDR).await;
    });
}

#[test]
fn test_idle_ping_pong() {
    GattPeriheralMock::run_with_custom_timeouts(
        0,
        BTP_CONN_IDLE_TIMEOUT_SECS,
        |peripheral, _io| async move {
            nego_min_mtu(&peripheral).await;

            // The peripheral should send the first ACK for the handshake response
            peripheral.send(&[8, 0, 0], PEER_ADDR, None).await;

            // BTP should - in X seconds - ACK our message so that the session does not timeout
            peripheral.expect(&[8, 0, 1], PEER_ADDR).await;

            // The peripheral should ACK it
            peripheral.send(&[8, 1, 1], PEER_ADDR, None).await;

            // BTP should - in X seconds - ACK again
            peripheral.expect(&[8, 1, 2], PEER_ADDR).await;

            // ... and so on. Stop here.
        },
    );
}

#[test]
fn test_idle_timeout() {
    GattPeriheralMock::run_with_custom_timeouts(
        BTP_ACK_TIMEOUT_SECS,
        1,
        |peripheral, io| async move {
            nego_min_mtu(&peripheral).await;

            Timer::after(Duration::from_secs(3)).await;

            // Session should be closed by now
            io.context.sessions.lock(|sessions| {
                assert!(sessions.borrow().is_empty());
            });
        },
    );
}
