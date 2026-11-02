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

//! A `NetStack` over the standard UDP sockets and `async-io`.

use core::future::{ready, Future};
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use std::net::UdpSocket;

use async_io::Async;

use socket2::{Domain, Protocol, Socket, Type};

use rs_matter_transport::network::mdns::MDNS_PORT;
use rs_matter_transport::network::NetworkMulticast;
use rs_matter_utils::error::Error;
use rs_matter_utils::sync::MaybeSend;

use super::{NetSocket, NetStack};

/// A `NetStack` over the standard UDP sockets and `async-io`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdNetStack;

impl StdNetStack {
    /// Create a new instance of the `StdNetStack` type.
    pub const fn new() -> Self {
        Self
    }
}

impl NetStack for StdNetStack {
    type Socket<'a>
        = StdNetSocket
    where
        Self: 'a;

    fn bind(
        &self,
        addr: SocketAddr,
        ipv4_interface: Ipv4Addr,
        ipv6_interface: u32,
    ) -> impl Future<Output = Result<Self::Socket<'_>, Error>> + MaybeSend {
        ready(StdNetSocket::bind(addr, ipv4_interface, ipv6_interface))
    }
}

/// The UDP socket of `StdNetStack`.
#[derive(Debug)]
pub struct StdNetSocket {
    socket: Async<UdpSocket>,
    ipv4_interface: Ipv4Addr,
    ipv6_interface: u32,
}

impl StdNetSocket {
    fn bind(
        addr: SocketAddr,
        ipv4_interface: Ipv4Addr,
        ipv6_interface: u32,
    ) -> Result<Self, Error> {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;

        // The port is shared with the mDNS responder of the OS, if there is one
        if addr.port() == MDNS_PORT {
            socket.set_reuse_address(true)?;
        }

        if addr.is_ipv6() {
            socket.set_only_v6(false)?;
        }

        socket.bind(&addr.into())?;

        Ok(Self {
            socket: Async::new_nonblocking(socket.into())?,
            ipv4_interface,
            ipv6_interface,
        })
    }
}

impl NetSocket for StdNetSocket {
    type Send<'a>
        = &'a Async<UdpSocket>
    where
        Self: 'a;

    type Receive<'a>
        = &'a Async<UdpSocket>
    where
        Self: 'a;

    type Multicast<'a>
        = StdNetMulticast<'a>
    where
        Self: 'a;

    fn split(&mut self) -> (Self::Send<'_>, Self::Receive<'_>, Self::Multicast<'_>) {
        (&self.socket, &self.socket, StdNetMulticast(self))
    }
}

/// The multicast group membership of a `StdNetSocket`.
///
/// Unlike the adapter of the transport, it joins on the interfaces the socket was bound for.
#[derive(Debug)]
pub struct StdNetMulticast<'a>(&'a StdNetSocket);

impl NetworkMulticast for StdNetMulticast<'_> {
    async fn join(&mut self, addr: IpAddr) -> Result<(), Error> {
        let socket = self.0.socket.get_ref();

        match addr {
            IpAddr::V6(addr) => socket.join_multicast_v6(&addr, self.0.ipv6_interface)?,
            IpAddr::V4(addr) => socket.join_multicast_v4(&addr, &self.0.ipv4_interface)?,
        }

        Ok(())
    }

    async fn leave(&mut self, addr: IpAddr) -> Result<(), Error> {
        let socket = self.0.socket.get_ref();

        match addr {
            IpAddr::V6(addr) => socket.leave_multicast_v6(&addr, self.0.ipv6_interface)?,
            IpAddr::V4(addr) => socket.leave_multicast_v4(&addr, &self.0.ipv4_interface)?,
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use rs_matter_transport::network::{Address, NetworkReceive, NetworkSend};

    use super::*;

    fn any(port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))
    }

    #[test]
    fn an_ipv6_socket_exchanges_ipv6_and_ipv4_packets() {
        futures_lite::future::block_on(async {
            let mut socket = StdNetStack
                .bind(any(0), Ipv4Addr::UNSPECIFIED, 0)
                .await
                .unwrap();

            let port = socket.socket.get_ref().local_addr().unwrap().port();

            let (mut send, mut recv, _) = socket.split();

            for addr in [
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            ] {
                NetworkSend::send_to(&mut send, b"ping", Address::Udp(addr))
                    .await
                    .unwrap();

                NetworkReceive::wait_available(&mut recv).await.unwrap();

                let mut buf = [0; 8];
                let (len, _) = NetworkReceive::recv_from(&mut recv, &mut buf)
                    .await
                    .unwrap();

                assert_eq!(&buf[..len], b"ping");
            }
        });
    }

    #[test]
    fn only_the_mdns_port_is_shared() {
        futures_lite::future::block_on(async {
            let stack = StdNetStack;

            let _first = stack
                .bind(any(MDNS_PORT), Ipv4Addr::UNSPECIFIED, 0)
                .await
                .unwrap();
            assert!(stack
                .bind(any(MDNS_PORT), Ipv4Addr::UNSPECIFIED, 0)
                .await
                .is_ok());

            let first = stack.bind(any(0), Ipv4Addr::UNSPECIFIED, 0).await.unwrap();
            let port = first.socket.get_ref().local_addr().unwrap().port();
            assert!(stack
                .bind(any(port), Ipv4Addr::UNSPECIFIED, 0)
                .await
                .is_err());
        });
    }

    #[test]
    fn multicast_joins_and_leaves() {
        futures_lite::future::block_on(async {
            let mut socket = StdNetStack
                .bind(any(0), Ipv4Addr::UNSPECIFIED, 0)
                .await
                .unwrap();

            let (_, _, mut multicast) = socket.split();

            let group = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb));

            multicast.join(group).await.unwrap();
            multicast.leave(group).await.unwrap();
        });
    }
}
