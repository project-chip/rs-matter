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

use core::future::Future;
use core::net::{Ipv4Addr, SocketAddr};

use rs_matter_transport::network::{NetworkMulticast, NetworkReceive, NetworkSend};
use rs_matter_utils::error::Error;
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
