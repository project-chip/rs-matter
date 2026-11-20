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

//! The IP network stack, as far as the Matter stack needs one: UDP sockets
//! that speak the network traits of the transport.

use core::future::{pending, ready, Future};
use core::net::{Ipv4Addr, SocketAddr};

use rs_matter_transport::network::tcp::{NoTcp, TcpNetwork, TcpNetworkSockets};
use rs_matter_transport::network::{
    Address, ChainedNetwork, EitherNetwork, NetworkMulticast, NetworkReceive, NetworkSend,
    NoNetwork,
};
use rs_matter_utils::error::{Error, ErrorCode};
use rs_matter_utils::sync::{MaybeSend, MaybeSendSync};

#[cfg(all(feature = "std", feature = "async-io"))]
pub mod std;

/// An IP network stack.
pub trait NetStack: MaybeSendSync {
    /// The UDP socket of this network stack
    type Socket<'a>: NetSocket
    where
        Self: 'a;

    /// Bind a UDP socket.
    ///
    /// # Arguments
    /// - `addr`: The address to bind to. The unspecified IPv6 address also takes IPv4
    ///   traffic where the network stack has IPv4.
    /// - `ipv4_interface`: The address of the interface for joining IPv4 multicast groups.
    /// - `ipv6_interface`: The index of the interface for joining IPv6 multicast groups.
    fn bind(
        &self,
        addr: SocketAddr,
        ipv4_interface: Ipv4Addr,
        ipv6_interface: u32,
    ) -> impl Future<Output = Result<Self::Socket<'_>, Error>> + MaybeSend;

    /// Returns the operational TCP stack, or `None` if TCP is disabled or not supported.
    fn tcp(&self) -> Option<impl NetTcpStack + '_> {
        None::<NoTcp>
    }
}

impl<T> NetStack for &T
where
    T: NetStack,
{
    type Socket<'a>
        = T::Socket<'a>
    where
        Self: 'a;

    fn bind(
        &self,
        addr: SocketAddr,
        ipv4_interface: Ipv4Addr,
        ipv6_interface: u32,
    ) -> impl Future<Output = Result<Self::Socket<'_>, Error>> + MaybeSend {
        (*self).bind(addr, ipv4_interface, ipv6_interface)
    }

    fn tcp(&self) -> Option<impl NetTcpStack + '_> {
        (*self).tcp()
    }
}

/// An operational Matter-over-TCP network stack.
///
/// Implementations should hold a reference to caller-owned static [`TcpNetworkBuffers`](crate::tcp::TcpNetworkBuffers)
/// so [`Self::bind`] returns a lightweight [`NetTcp`] handle without placing multi-KiB
/// frame buffers inside async task futures.
pub trait NetTcpStack: MaybeSendSync {
    /// The bound operational TCP transport handle returned by [`Self::bind`].
    type Tcp<'a>: NetTcp
    where
        Self: 'a;

    /// Bind an operational TCP listener on `addr` and return a lightweight [`NetTcp`] handle.
    fn bind(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<Self::Tcp<'_>, Error>> + MaybeSend;

    /// Whether this TCP stack supports initiating outbound TCP connections
    /// (Matter Core Spec `T` TXT bit 1: `T=6` when `true`, `T=4` when `false`).
    fn supports_client(&self) -> bool {
        false
    }
}

impl<T: NetTcpStack> NetTcpStack for &T {
    type Tcp<'a>
        = T::Tcp<'a>
    where
        Self: 'a;

    fn bind(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<Self::Tcp<'_>, Error>> + MaybeSend {
        (*self).bind(addr)
    }

    fn supports_client(&self) -> bool {
        (*self).supports_client()
    }
}

/// A bound operational Matter-over-TCP transport handle.
pub trait NetTcp: MaybeSendSync {
    /// The sending half of the bound TCP transport.
    type Send<'a>: NetworkSend
    where
        Self: 'a;

    /// The receiving half of the bound TCP transport.
    type Receive<'a>: NetworkReceive
    where
        Self: 'a;

    /// Borrow the sending half of the bound TCP transport.
    fn send(&self) -> Self::Send<'_>;

    /// Borrow the receiving half of the bound TCP transport.
    fn recv(&self) -> Self::Receive<'_>;

    /// Drive TCP accept/connect and peer I/O loops until error or cancellation.
    fn run(&self) -> impl Future<Output = Result<(), Error>> + MaybeSend;

    /// Maximum Matter-over-TCP message size supported by this bound TCP transport.
    fn max_message_size(&self) -> usize {
        rs_matter_transport::MAX_RX_BUF_SIZE
    }

    /// Chain the sending half of `tcp`, if bound, with the sending half of the UDP socket.
    ///
    /// Only [`NoTcpNetwork`] overrides this, to keep the UDP half as it is.
    fn chain_send<'a, U>(tcp: Option<&'a Self>, udp: U) -> impl NetworkSend + 'a
    where
        U: NetworkSend + 'a,
    {
        match tcp {
            Some(tcp) => {
                EitherNetwork::First(ChainedNetwork::new(Address::is_tcp, tcp.send(), udp))
            }
            None => EitherNetwork::Second(udp),
        }
    }

    /// Chain the receiving half of `tcp`, if bound, with the receiving half of the UDP socket.
    ///
    /// Only [`NoTcpNetwork`] overrides this, to keep the UDP half as it is.
    fn chain_recv<'a, U>(tcp: Option<&'a Self>, udp: U) -> impl NetworkReceive + 'a
    where
        U: NetworkReceive + 'a,
    {
        match tcp {
            Some(tcp) => {
                EitherNetwork::First(ChainedNetwork::new(Address::is_tcp, tcp.recv(), udp))
            }
            None => EitherNetwork::Second(udp),
        }
    }
}

impl<T: NetTcp> NetTcp for &T {
    type Send<'a>
        = T::Send<'a>
    where
        Self: 'a;

    type Receive<'a>
        = T::Receive<'a>
    where
        Self: 'a;

    fn send(&self) -> Self::Send<'_> {
        (*self).send()
    }

    fn recv(&self) -> Self::Receive<'_> {
        (*self).recv()
    }

    fn run(&self) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        (*self).run()
    }

    fn max_message_size(&self) -> usize {
        (*self).max_message_size()
    }

    fn chain_send<'a, U>(tcp: Option<&'a Self>, udp: U) -> impl NetworkSend + 'a
    where
        U: NetworkSend + 'a,
    {
        T::chain_send(tcp.copied(), udp)
    }

    fn chain_recv<'a, U>(tcp: Option<&'a Self>, udp: U) -> impl NetworkReceive + 'a
    where
        U: NetworkReceive + 'a,
    {
        T::chain_recv(tcp.copied(), udp)
    }
}

impl<L, const N: usize, const SLOTS: usize, const TX_QUEUE: usize> NetTcp
    for TcpNetwork<'_, L, N, SLOTS, TX_QUEUE>
where
    L: TcpNetworkSockets,
    L::Socket: MaybeSendSync,
{
    type Send<'a>
        = &'a Self
    where
        Self: 'a;

    type Receive<'a>
        = &'a Self
    where
        Self: 'a;

    fn send(&self) -> Self::Send<'_> {
        self
    }

    fn recv(&self) -> Self::Receive<'_> {
        self
    }

    fn run(&self) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        TcpNetwork::run(self)
    }

    fn max_message_size(&self) -> usize {
        N
    }
}

impl NetTcp for NoTcp {
    type Send<'a> = NoNetwork;
    type Receive<'a> = NoNetwork;

    fn send(&self) -> Self::Send<'_> {
        NoNetwork
    }

    fn recv(&self) -> Self::Receive<'_> {
        NoNetwork
    }

    fn run(&self) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        pending()
    }
}

impl NetTcpStack for NoTcp {
    type Tcp<'a> = NoTcpNetwork;

    fn bind(
        &self,
        _addr: SocketAddr,
    ) -> impl Future<Output = Result<Self::Tcp<'_>, Error>> + MaybeSend {
        ready(Err(ErrorCode::NoNetworkInterface.into()))
    }
}

/// The bound TCP of [`NoTcp`], which has no values, as binding [`NoTcp`] always fails.
///
/// The stack then runs the operational transport over the UDP socket alone, without
/// the code for chaining TCP.
pub enum NoTcpNetwork {}

impl NetTcp for NoTcpNetwork {
    type Send<'a> = Self;
    type Receive<'a> = Self;

    fn send(&self) -> Self::Send<'_> {
        match *self {}
    }

    fn recv(&self) -> Self::Receive<'_> {
        match *self {}
    }

    async fn run(&self) -> Result<(), Error> {
        match *self {}
    }

    fn max_message_size(&self) -> usize {
        match *self {}
    }

    fn chain_send<'a, U>(_tcp: Option<&'a Self>, udp: U) -> impl NetworkSend + 'a
    where
        U: NetworkSend + 'a,
    {
        udp
    }

    fn chain_recv<'a, U>(_tcp: Option<&'a Self>, udp: U) -> impl NetworkReceive + 'a
    where
        U: NetworkReceive + 'a,
    {
        udp
    }
}

impl NetworkSend for NoTcpNetwork {
    async fn send_to(&mut self, _data: &[u8], _addr: Address) -> Result<(), Error> {
        match *self {}
    }
}

impl NetworkReceive for NoTcpNetwork {
    async fn wait_available(&mut self) -> Result<(), Error> {
        match *self {}
    }

    async fn recv_from(&mut self, _buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        match *self {}
    }
}

/// A bound UDP socket.
pub trait NetSocket: MaybeSend {
    /// The sending half of the socket
    type Send<'a>: NetworkSend
    where
        Self: 'a;

    /// The receiving half of the socket
    type Receive<'a>: NetworkReceive
    where
        Self: 'a;

    /// The multicast group membership of the socket
    type Multicast<'a>: NetworkMulticast
    where
        Self: 'a;

    /// Split the socket, so that it can send and receive at the same time.
    fn split(&mut self) -> (Self::Send<'_>, Self::Receive<'_>, Self::Multicast<'_>);
}
