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

//! An implementation of the Matter BTP protocol over BLE, using GATT as the underlying transport.

use core::future::Future;

use embassy_futures::select::select;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{Instant, Timer};

use session::{BTP_ACK_TIMEOUT_SECS, BTP_CONN_IDLE_TIMEOUT_SECS};

use crate::error::{Error, ErrorCode};
use crate::transport::network::btp::session::Session;
use crate::transport::network::{Address, BtAddr, NetworkReceive, NetworkSend, MAX_TX_PACKET_SIZE};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;

pub use gatt::*;

mod gatt;
mod session;

/// The maximum size of a BTP segment.
pub(crate) const MAX_BTP_SEGMENT_SIZE: usize = 244;
/// The size of the GATT header. `MAX_BTP_SEGMENT_SIZE` + `GATT_HEADER_SIZE` is 247 bytes, which is the maximum ATT MTU size supported by the BTP protocol.
pub(crate) const GATT_HEADER_SIZE: usize = 3;

/// The minimum MTU that can be used as per specification.
pub(crate) const MIN_MTU: u16 = (20 + GATT_HEADER_SIZE) as u16;
/// The maximum MTU that can be used as per specification.
pub(crate) const MAX_MTU: u16 = (MAX_BTP_SEGMENT_SIZE + GATT_HEADER_SIZE) as u16;

/// An implementation of the Matter BTP protocol.
/// This is a low-level protocol that is used to send and receive Matter messages over BLE.
///
/// For the BTP protocol to function, it is expected that a GATT Peripheral (or a GATT Central, when rs-matter plays the Controller role)
/// is setup in some OS-specific way by the user, where the GATT peripheral app is configured to contain the C1 and C2 characteristics
/// on a service with the the Matter Service UUID.
///
/// The OS-specific GATT Peripheral or Central is supposed to call the following two methods:
///
/// - For the case where we take the GATT Peripheral role (i.e. rs-matter is the Accessory/Device, and BTP is initialized with `Btp::set_initiator(false)`):
///   - `Btp::process_incoming` - when a GATT Write request is received on the C1 characteristic
///   - `Btp::process_outgoing` - periodically and when `Btp::wait_outgoing` is notified, to check if there is any data to send to the peer
///     The data is to be send via a GATT indication on the C2 characteristic.
///
/// - For the case where we take the GATT Central role (i.e. rs-matter is the Controller, and BTP is initialized with `Btp::set_initiator(true)`):
///   - `Btp::process_incoming` - when a GATT indication is received on the C2 characteristic
///   - `Btp::process_outgoing` - periodically and when `Btp::wait_outgoing` is notified, to check if there is any data to send to the peer
///     The data is to be send via a GATT Write request on the C1 characteristic.
pub struct Btp {
    /// The inner state of the BTP protocol, containing the session state, the outgoing SDU buffer, and the timeouts configuration.
    inner: Mutex<NoopRawMutex, RefCell<BtpInner>>,
    /// Notification triggered when (potentially!) a new Matter packet (BTP SDU) is assembled and available for processing.
    recv_notif: Notification<NoopRawMutex>,
    /// Notification triggered when (potentially!) there is now space for buffering a new outgoing Matter packet (BTP SDU).
    send_notif: Notification<NoopRawMutex>,
    /// Notification triggered when (potentially!) there is new outgoing data to be sent to the peer, which can be either a handshake packet or a BTP SDU segment.
    outg_notif: Notification<NoopRawMutex>,
}

impl Btp {
    /// Construct a new BTP instance.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(RefCell::new(BtpInner::new())),
            recv_notif: Notification::new(),
            send_notif: Notification::new(),
            outg_notif: Notification::new(),
        }
    }

    /// Create an in-place initializer for a BTP instance.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            inner <- Mutex::init(RefCell::init(BtpInner::init())),
            recv_notif: Notification::new(),
            send_notif: Notification::new(),
            outg_notif: Notification::new(),
        })
    }

    /// Reset the BTP state, by clearing all sessions and buffers, and resetting the timeouts to their default values.
    pub fn reset(&self) {
        self.inner.lock(|inner| {
            inner.borrow_mut().reset();

            self.recv_notif.notify();
            self.send_notif.notify();
            self.outg_notif.notify();
        });
    }

    /// Set the BTP timeouts, by configuring the ACK timeout and the connection idle timeout.
    ///
    /// Only used by the unit tests.
    #[allow(dead_code)]
    pub(crate) fn set_timeouts(&self, ack_timeout_secs: u8, conn_idle_timeout_secs: u8) {
        self.inner.lock(|inner| {
            inner
                .borrow_mut()
                .set_timeouts(ack_timeout_secs, conn_idle_timeout_secs);

            self.recv_notif.notify();
            self.send_notif.notify();
            self.outg_notif.notify();
        });
    }

    /// Check if the session has timed out due to inactivity (connection timeout).
    pub fn timeout(&self) -> bool {
        self.inner.lock(|inner| inner.borrow().timeout())
    }

    /// Wait until the session has timed out due to inactivity (connection timeout).
    pub async fn wait_timeout(&self) {
        while !self.timeout() {
            Timer::after_secs(2).await;
        }
    }

    /// Process an incoming BLE packet
    ///
    /// This method is expected to be called by the OS-specific GATT Peripheral or Central when a packet is received from the peer.
    ///
    /// # Arguments
    /// - `gatt_mtu`: the GATT MTU (if known) to be used for processing the incoming packet.
    ///   This is needed in order to properly process the BTP handshake packets, which contain the peer's supported MTU.
    ///   If `None` is provided, the processing will assume that the GATT MTU is unknown, and will use the minimum MTU for processing the handshake packets.
    /// - `addr`: the address of the peer from where the packet originates
    /// - `data`: the incoming packet data, which is expected to be the payload of a GATT Write request (when we are the Peripheral) or a GATT indication (when we are the Central)
    pub fn process_incoming(
        &self,
        gatt_mtu: Option<u16>,
        addr: BtAddr,
        data: &[u8],
    ) -> Result<(), Error> {
        self.inner.lock(|inner| {
            inner.borrow_mut().process_incoming(gatt_mtu, addr, data)?;

            self.recv_notif.notify();
            self.outg_notif.notify();

            Ok(())
        })
    }

    /// Process outgoing data and prepare it to be sent to the peer.
    ///
    /// This method is expected to be called by the OS-specific GATT Peripheral or Central periodically and when `Btp::wait_outgoing` is notified,
    /// in order to check if there is any data to send to the peer.
    ///
    /// The data to be sent is expected to be sent by the OS-specific GATT Peripheral or Central via a GATT indication (when we are the Peripheral)
    /// or a GATT Write request (when we are the Central).
    ///
    /// # Arguments
    /// - `gatt_mtu`: the GATT MTU (if known) to be used for processing the outgoing packet.
    ///   This is needed in order to properly process the BTP handshake packets, which require to know the MTU in order to properly segment the outgoing data.
    ///   If `None` is provided, the processing will assume that the GATT MTU is unknown, and will use the minimum MTU for processing the handshake packets.
    /// - `buf`: the buffer to be used for preparing the outgoing packet data, which is expected to be the payload of a GATT indication (when we are the Peripheral)
    ///   or a GATT Write request (when we are the Central). A size of 512 (max MTU) should be enough.
    ///
    /// # Returns
    /// - `Ok(len)` if there is data to be sent to the peer, where `len` is the size of the prepared packet data to be sent.
    ///   The prepared packet data will be written to the provided `buf` buffer.
    /// - `Ok(0)` if there is no data to be sent to the peer at the moment.
    /// - `Err` if there was an error during processing the outgoing data.
    pub fn process_outgoing(&self, gatt_mtu: Option<u16>, buf: &mut [u8]) -> Result<usize, Error> {
        self.inner.lock(|inner| {
            let mut inner = inner.borrow_mut();

            let len = inner.process_outgoing(gatt_mtu, buf)?;

            if inner.outgoing_sdu.buf.is_empty() {
                self.send_notif.notify();
            }

            Ok(len)
        })
    }

    /// Wait until there is at least one packet to be sent to the peer,
    /// by waiting for a notification that is triggered when there is new outgoing data to be sent.
    pub async fn wait_outgoing(&self) {
        select(self.outg_notif.wait(), Timer::after_secs(2)).await;
    }

    /// Wait until there is at least one Matter (a.k.a. BTP SDU) packet available for consumption.
    pub async fn wait_available(&self) -> Result<(), Error> {
        loop {
            let available = self.inner.lock(|inner| inner.borrow().available());

            if available {
                break;
            }

            self.recv_notif.wait().await;
        }

        Ok(())
    }

    /// Receive a Matter (a.k.a. BTP SDU) packet.
    ///
    /// If there is no packet available, this method will block asynchronously until a packet is available.
    /// Returns the size of the received packet, as well as the address of the BLE peer from where the packet originates.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, BtAddr), Error> {
        loop {
            let result = self.inner.lock(|inner| {
                let result = inner.borrow_mut().recv(buf)?;

                if result.is_some() {
                    self.outg_notif.notify();
                }

                Ok::<_, Error>(result)
            })?;

            if let Some(result) = result {
                break Ok(result);
            }

            self.recv_notif.wait().await;
        }
    }

    /// Send a Matter (a.k.a. BTP SDU) packet to the specified BLE peer.
    pub async fn send(&self, data: &[u8], addr: BtAddr) -> Result<(), Error> {
        loop {
            let sent = self.inner.lock(|inner| {
                let sent = inner.borrow_mut().send(data, addr)?;

                if sent {
                    self.outg_notif.notify();
                }

                Ok::<_, Error>(sent)
            })?;

            if sent {
                break Ok(());
            }

            self.send_notif.wait().await;
        }
    }
}

impl Default for Btp {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkSend for &Btp {
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        (*self)
            .send(data, addr.btp().ok_or(ErrorCode::NoNetworkInterface)?)
            .await
    }
}

impl NetworkReceive for &Btp {
    fn wait_available(&mut self) -> impl Future<Output = Result<(), Error>> {
        (*self).wait_available()
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        (*self)
            .recv(buffer)
            .await
            .map(|(len, addr)| (len, Address::Btp(addr)))
    }
}

impl NetworkSend for Btp {
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        (&*self).send_to(data, addr).await
    }
}

impl NetworkReceive for Btp {
    fn wait_available(&mut self) -> impl Future<Output = Result<(), Error>> {
        (*self).wait_available()
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        (&*self).recv_from(buffer).await
    }
}

/// The inner state of the BTP protocol, containing the session state, the outgoing SDU buffer, and the timeouts configuration.
struct BtpInner {
    session: Session,
    outgoing_sdu: OutgoingSdu,
    ack_timeout_secs: u8,
    conn_idle_timeout_secs: u8,
}

impl BtpInner {
    /// Construct a new BtpInner instance with default values.
    const fn new() -> Self {
        Self {
            session: Session::new(),
            outgoing_sdu: OutgoingSdu::new(),
            ack_timeout_secs: BTP_ACK_TIMEOUT_SECS,
            conn_idle_timeout_secs: BTP_CONN_IDLE_TIMEOUT_SECS,
        }
    }

    /// Create an in-place initializer for a BtpInner instance.
    fn init() -> impl Init<Self> {
        init!(Self {
            session <- Session::init(),
            outgoing_sdu <- OutgoingSdu::init(),
            ack_timeout_secs: BTP_ACK_TIMEOUT_SECS,
            conn_idle_timeout_secs: BTP_CONN_IDLE_TIMEOUT_SECS,
        })
    }

    /// Reset the BtpInner state, by resetting the session, clearing the outgoing SDU buffer, and resetting the timeouts to their default values.
    fn reset(&mut self) {
        self.session.reset();
        self.outgoing_sdu.reset();
        self.ack_timeout_secs = BTP_ACK_TIMEOUT_SECS;
        self.conn_idle_timeout_secs = BTP_CONN_IDLE_TIMEOUT_SECS;
    }

    /// Set the BTP timeouts, by configuring the ACK timeout and the connection idle timeout.
    /// Only used by the unit tests.
    fn set_timeouts(&mut self, ack_timeout_secs: u8, conn_idle_timeout_secs: u8) {
        self.ack_timeout_secs = ack_timeout_secs;
        self.conn_idle_timeout_secs = conn_idle_timeout_secs;
    }

    /// Process an incoming BLE packet
    fn process_incoming(
        &mut self,
        gatt_mtu: Option<u16>,
        addr: BtAddr,
        data: &[u8],
    ) -> Result<(), Error> {
        self.session.process_rx(addr, data, gatt_mtu)
    }

    /// Process outgoing data and prepare it to be sent to the peer.
    fn process_outgoing(&mut self, gatt_mtu: Option<u16>, buf: &mut [u8]) -> Result<usize, Error> {
        let len = self.session.prep_tx_handshake(gatt_mtu, buf)?;
        if len > 0 {
            return Ok(len);
        }

        if !self.outgoing_sdu.buf.is_empty() {
            if self.outgoing_sdu.address == self.session.address() {
                let len = self.session.prep_tx_data(
                    &self.outgoing_sdu.buf,
                    &mut self.outgoing_sdu.buf_offset,
                    buf,
                )?;
                if len > 0 {
                    if self.outgoing_sdu.buf_offset == self.outgoing_sdu.buf.len() {
                        self.outgoing_sdu.reset();
                    }

                    return Ok(len);
                }
            } else {
                self.outgoing_sdu.reset();
            }
        }

        if self
            .session
            .is_ack_due(Instant::now(), self.ack_timeout_secs as _)
        {
            let len = self.session.prep_tx_data(&[], &mut 0, buf)?;
            assert!(len > 0);

            return Ok(len);
        }

        Ok(0)
    }

    /// Check if there is at least one Matter (a.k.a. BTP SDU) packet available for consumption.
    fn available(&self) -> bool {
        self.session.message_available()
    }

    /// Receive a Matter (a.k.a. BTP SDU) packet.
    ///
    /// Returns the size of the received packet, as well as the address of the BLE peer from where the packet originates,
    /// or 0 if there is no packet available for reception.
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, BtAddr)>, Error> {
        if self.session.message_available() {
            let len = self.session.fetch_message(buf)?;

            Ok(Some((len, self.session.address())))
        } else {
            Ok(None)
        }
    }

    /// Send a Matter (a.k.a. BTP SDU) packet to the specified BLE peer.
    ///
    /// Returns `Ok(true)` if the packet was successfully buffered for sending,
    /// `Ok(false)` if there is already an outgoing packet being buffered (i.e. the caller should retry later),
    /// or an error if there was an error during buffering the packet for sending.
    fn send(&mut self, data: &[u8], addr: BtAddr) -> Result<bool, Error> {
        if data.is_empty() || data.len() > MAX_TX_PACKET_SIZE {
            Err(ErrorCode::InvalidArgument.into())
        } else if self.outgoing_sdu.buf.is_empty() {
            self.outgoing_sdu.address = addr;
            self.outgoing_sdu.buf_offset = 0;
            unwrap!(self.outgoing_sdu.buf.extend_from_slice(data));

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if the session has timed out due to inactivity (connection timeout).
    fn timeout(&self) -> bool {
        self.session
            .is_timed_out(Instant::now(), self.conn_idle_timeout_secs as _)
    }
}

/// The state of an outgoing BTP SDU, containing the peer address, the SDU data buffer, and the current offset in the buffer for sending.
struct OutgoingSdu {
    address: BtAddr,
    buf: Vec<u8, MAX_TX_PACKET_SIZE>,
    buf_offset: usize,
}

impl OutgoingSdu {
    const fn new() -> Self {
        Self {
            address: BtAddr([0; 6]),
            buf: Vec::new(),
            buf_offset: 0,
        }
    }

    fn init() -> impl Init<Self> {
        init!(Self {
            address: BtAddr([0; 6]),
            buf <- crate::utils::storage::Vec::init(),
            buf_offset: 0,
        })
    }

    fn reset(&mut self) {
        self.address = BtAddr([0; 6]);
        self.buf.clear();
        self.buf_offset = 0;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const PEER_ADDR: BtAddr = BtAddr([1, 2, 3, 4, 5, 6]);

    fn incoming(btp: &Btp, data: &[u8]) {
        incoming_mtu(btp, None, data)
    }

    fn expect_outgoing(btp: &Btp, data: &[u8]) {
        expect_outgoing_mtu(btp, None, data)
    }

    /// Generate `GattPeripheralEvent::Write` event for the peer
    fn incoming_mtu(btp: &Btp, gatt_mtu: Option<u16>, data: &[u8]) {
        btp.process_incoming(gatt_mtu, PEER_ADDR, data).unwrap();
    }

    /// Expect to receive the provided data from the peer as if the BTP protocol
    /// did call `indicate`
    fn expect_outgoing_mtu(btp: &Btp, gatt_mtu: Option<u16>, data: &[u8]) {
        let mut buf = [0; 512];

        let len = btp.process_outgoing(gatt_mtu, &mut buf).unwrap();

        assert_eq!(&buf[..len], data);
    }

    fn send(btp: &Btp, data: &[u8]) {
        embassy_futures::block_on(btp.send(data, PEER_ADDR)).unwrap();
    }

    fn expect_recv(btp: &Btp, data: &[u8]) {
        let mut buf = [0; 2048];

        let (len, addr) = embassy_futures::block_on(btp.recv(&mut buf)).unwrap();

        assert_eq!(addr, PEER_ADDR);
        assert_eq!(&buf[..len], data);
    }

    #[test]
    fn test_mtu_timeout() {
        #[cfg(all(feature = "std", not(target_os = "espidf")))]
        {
            let _ = env_logger::try_init_from_env(
                env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
            );
        }

        let btp = Btp::new();
        btp.set_timeouts(1, 2);

        incoming_mtu(
            &btp,
            Some(0xc8),
            &[0x65, 0x6c, 0x54, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x05],
        );

        // Expected MTU in response is 0xc8 - 3 = 0xc5
        expect_outgoing(&btp, &[0x65, 0x6c, 0x05, 0xc5, 0x00, 0x05]);

        embassy_futures::block_on(Timer::after_secs(3));

        assert!(btp.timeout());

        /////////////////////////////////

        btp.reset();

        // GATT MTU is unknown
        incoming_mtu(
            &btp,
            None,
            &[0x65, 0x6c, 0x54, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x05],
        );

        // Expected MTU is the minimum one (0x14)
        expect_outgoing(&btp, &[0x65, 0x6c, 0x05, 0x14, 0x00, 0x05]);
    }

    // Utility to do the negotiation phase with a minumum MTU
    fn nego_min_mtu() -> Btp {
        let btp = Btp::new();

        incoming(
            &btp,
            &[0x65, 0x6c, 0x54, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x05],
        );

        // Peer window = 1 because of this handshake resp
        expect_outgoing(&btp, &[0x65, 0x6c, 0x05, 0x14, 0x00, 0x05]);

        btp
    }

    #[test]
    fn test_short_read() {
        let btp = nego_min_mtu();

        send(&btp, &[0, 1, 2, 3]);

        expect_outgoing(&btp, &[5, 1, 4, 0, 0, 1, 2, 3]);
    }

    #[test]
    fn test_short_write() {
        let btp = nego_min_mtu();

        incoming(&btp, &[5, 0, 3, 0, 1, 2, 3]);

        expect_recv(&btp, &[1, 2, 3]);
    }

    #[test]
    fn test_long_read() {
        let btp = nego_min_mtu();

        send(&btp, &[0; 52]);

        // Long msg beginning
        expect_outgoing(
            &btp,
            &[1, 1, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        // Long msg continue
        expect_outgoing(
            &btp,
            &[2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        // Long msg end
        expect_outgoing(
            &btp,
            &[6, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
    }

    #[test]
    fn test_long_write() {
        let btp = nego_min_mtu();

        // Beginning
        incoming(
            &btp,
            &[
                1, 0, 30, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            ],
        );

        // End
        incoming(
            &btp,
            &[4, 1, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30],
        );

        expect_recv(
            &btp,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30,
            ],
        );
    }

    #[test]
    fn test_long_read_ack() {
        let btp = nego_min_mtu();

        // A short message, to pump up the ack window
        send(&btp, &[0, 1, 2, 3]);

        // Peer window = 2
        expect_outgoing(&btp, &[5, 1, 4, 0, 0, 1, 2, 3]);

        send(&btp, &[0; 100]);

        // Long msg beginning
        // Peer window = 3
        expect_outgoing(
            &btp,
            &[1, 2, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        // Long msg continue
        // Peer window = 4
        expect_outgoing(
            &btp,
            &[2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        // Send ACK from the peer as its window is full by now (5 - 1) = 4
        incoming(&btp, &[8, 3, 0]);

        // Long msg end + ACK
        // Peer window = 0, final packet
        expect_outgoing(
            &btp,
            &[10, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
    }

    #[test]
    fn test_long_write_ack() {
        let btp = nego_min_mtu();

        // Beginning
        incoming(
            &btp,
            &[1, 0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        // Continue
        incoming(
            &btp,
            &[2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        // End
        incoming(&btp, &[4, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        expect_recv(&btp, &[0; 44]);
    }

    #[test]
    fn test_idle_ping_pong() {
        let btp = nego_min_mtu();

        btp.set_timeouts(1, 10);

        // The peripheral should send the first ACK for the handshake response
        incoming(&btp, &[8, 0, 0]);

        embassy_futures::block_on(Timer::after_secs(1));

        // BTP should - in X seconds - ACK our message so that the session does not timeout
        expect_outgoing(&btp, &[8, 0, 1]);

        // The peripheral should ACK it
        incoming(&btp, &[8, 1, 1]);

        embassy_futures::block_on(Timer::after_secs(1));

        // BTP should - in X seconds - ACK again
        expect_outgoing(&btp, &[8, 1, 2]);
    }
}
