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

use core::{
    fmt::{self, Debug, Display},
    pin::pin,
};

pub use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use embassy_futures::select::{select, Either};

use crate::error::{Error, ErrorCode};

pub mod btp;
pub mod udp;

// Maximum UDP RX packet size per Matter spec
pub const MAX_RX_PACKET_SIZE: usize = 1583;

// Maximum UDP TX packet size per Matter spec
pub const MAX_TX_PACKET_SIZE: usize = 1280 - 40/*IPV6 header size*/ - 8/*UDP header size*/;

// Maximum TCP RX packet size per Matter spec
pub const MAX_RX_LARGE_PACKET_SIZE: usize = 1024 * 1024;

// Maximum TCP TX packet size per Matter spec
pub const MAX_TX_LARGE_PACKET_SIZE: usize = MAX_RX_LARGE_PACKET_SIZE;

/// A Bluetooth address.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct BtAddr(pub [u8; 6]);

impl Display for BtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for BtAddr {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5]
        )
    }
}

/// An enum representing a network address for all supported protocols by the Matter specification (UDP, TCP and BTP).
#[derive(Eq, PartialEq, Copy, Clone)]
pub enum Address {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Btp(BtAddr),
}

impl Address {
    pub const fn new() -> Self {
        Self::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    pub const fn is_reliable(&self) -> bool {
        matches!(self, Self::Tcp(_) | Self::Btp(_))
    }

    pub const fn is_udp(&self) -> bool {
        matches!(self, Self::Udp(_))
    }

    pub const fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }

    pub const fn is_btp(&self) -> bool {
        matches!(self, Self::Btp(_))
    }

    pub const fn udp(self) -> Option<SocketAddr> {
        match self {
            Self::Udp(addr) => Some(addr),
            _ => None,
        }
    }

    pub const fn tcp(self) -> Option<SocketAddr> {
        match self {
            Self::Tcp(addr) => Some(addr),
            _ => None,
        }
    }

    pub const fn btp(self) -> Option<BtAddr> {
        match self {
            Self::Btp(addr) => Some(addr),
            _ => None,
        }
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Udp(addr) => write!(f, "UDP {}", addr),
            Address::Tcp(addr) => write!(f, "TCP {}", addr),
            Address::Btp(addr) => write!(f, "BTP {}", addr),
        }
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Udp(addr) => writeln!(f, "{}", addr),
            Address::Tcp(addr) => writeln!(f, "{}", addr),
            Address::Btp(addr) => writeln!(f, "{:?}", addr),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Address {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Address::Udp(addr) => defmt::write!(f, "UDP {}", addr),
            Address::Tcp(addr) => defmt::write!(f, "TCP {}", addr),
            Address::Btp(addr) => defmt::write!(f, "BTP {}", addr),
        }
    }
}

/// A trait for sending data to a network address.
///
/// All network communication in the Matter transport is packetized (including via TCP and Bluetooth), hence
/// this trait models the sending of a single Matter packet of data to a network address.
///
/// Data packetization is expected to be handled by the implementation of this trait, and is trivial
/// for e.g. the UDP transport which is packetized by default, but more complex for e.g. the TCP transport and especially for BTP.
pub trait NetworkSend {
    /// Send a Matter packet represented as a sequence of bytes (`data`) to the specified address.
    ///
    /// Might return an error if the address is not supported, or if there is a general error on the network interface.
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error>;
}

impl<T> NetworkSend for &mut T
where
    T: NetworkSend,
{
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        (*self).send_to(data, addr).await
    }
}

/// A trait for receiving data from a network address.
///
/// All network communication in the Matter transport is packetized (including via TCP and Bluetooth), hence
/// this trait models the receiving of a single Matter packet of data from a network address.
///
/// Data packetization is expected to be handled by the implementation of this trait, and is trivial
/// for e.g. the UDP transport which is packetized by default, but more complex for e.g. the TCP transport and especially for BTP.
pub trait NetworkReceive {
    /// Wait until a data packet is available to be received.
    ///
    /// Allows the Matter transport layer to re-use a single RX buffer accross all network protocol implementatiins.
    ///
    /// Might return an error if there is a general error on the network interface.
    async fn wait_available(&mut self) -> Result<(), Error>;

    /// Receive a single data packet from the network.
    ///
    /// Might return an error if there is a general error on the network interface.
    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error>;
}

impl<T> NetworkReceive for &mut T
where
    T: NetworkReceive,
{
    async fn wait_available(&mut self) -> Result<(), Error> {
        (*self).wait_available().await
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        (*self).recv_from(buffer).await
    }
}

/// A network implementation that does not support any network communication:
/// - Trying to send a packet always results in a `ErrorCode::NoNetworkInterface` error.
/// - Trying to wait/receive a packet pends forever.
///
/// Useful when chaining multiple network interfaces together to serve as the last network interface in the chain.
pub struct NoNetwork;

impl NetworkSend for NoNetwork {
    async fn send_to(&mut self, _data: &[u8], _addr: Address) -> Result<(), Error> {
        Err(ErrorCode::NoNetworkInterface.into())
    }
}

impl NetworkReceive for NoNetwork {
    async fn wait_available(&mut self) -> Result<(), Error> {
        core::future::pending().await
    }

    async fn recv_from(&mut self, _buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        core::future::pending().await
    }
}

/// A network implementation that chains two network implementations together in a composite network interface.
///
/// This allows for e.g. a network implementation that can send/receive data to/from both a UDP and a TCP network interface - or -
/// with e.g. further chaining - from all of UDP, TCP and BTP network interfaces.
#[derive(Clone)]
pub struct ChainedNetwork<H, T, F> {
    pub handler_can_send: F,
    pub handler: H,
    pub next: T,
}

impl<H, T, F> ChainedNetwork<H, T, F> {
    /// Construct a chained handler that works as follows:
    /// - When a packet is about to be send, the `handler_can_send` function is called with the destination address.
    ///   If it returns `true`, the packet is sent via the `handler` network interface, otherwise it is sent via the `next` network interface.
    /// - When `wait_available` is called, the function waits until a packet is available on either network interface.
    /// - When `recv_from` is called, the function receives a packet from the first network interface that has a packet available.
    pub const fn new(handler_can_send: F, handler: H, next: T) -> Self {
        Self {
            handler_can_send,
            handler,
            next,
        }
    }

    /// Chain itself with another handler.
    ///
    /// The returned chained handler works as follows:
    /// - When a packet is about to be send, the `handler_can_send` function is called with the destination address.
    ///   If it returns `true`, the packet is sent via the `handler` network interface, otherwise it is sent via `self`.
    /// - When `wait_available` is called, the function waits until a packet is available on either network interface.
    /// - When `recv_from` is called, the function receives a packet from the first network interface that has a packet available.
    pub const fn chain<H2, F2>(
        self,
        handler_can_send: F2,
        handler: H2,
    ) -> ChainedNetwork<H2, Self, F2> {
        ChainedNetwork::new(handler_can_send, handler, self)
    }
}

impl<H, T, F> NetworkReceive for ChainedNetwork<H, T, F>
where
    H: NetworkReceive,
    T: NetworkReceive,
{
    async fn wait_available(&mut self) -> Result<(), Error> {
        let mut first = pin!(self.handler.wait_available());
        let mut second = pin!(self.next.wait_available());

        select(&mut first, &mut second).await;

        Ok(())
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        let first = {
            let mut first_available = pin!(self.handler.wait_available());
            let mut second_available = pin!(self.next.wait_available());

            matches!(
                select(&mut first_available, &mut second_available).await,
                Either::First(_)
            )
        };

        if first {
            self.handler.recv_from(buffer).await
        } else {
            self.next.recv_from(buffer).await
        }
    }
}

impl<H, T, F> NetworkSend for ChainedNetwork<H, T, F>
where
    H: NetworkSend,
    T: NetworkSend,
    F: Fn(&Address) -> bool,
{
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        if (self.handler_can_send)(&addr) {
            self.handler.send_to(data, addr).await
        } else {
            self.next.send_to(data, addr).await
        }
    }
}
