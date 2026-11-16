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

//! A `NetStack` over standard UDP sockets and `async-io`.

use core::future::{ready, Future};
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use std::net::UdpSocket;

use async_io::Async;

use socket2::{Domain, Protocol, Socket, Type};

use rs_matter_transport::network::mdns::MDNS_PORT;
use rs_matter_transport::network::NetworkMulticast;
use rs_matter_utils::error::Error;
use rs_matter_utils::sync::MaybeSend;

use super::{NetSocket, NetStack, NetTcpStack};

/// A `NetStack` over standard UDP sockets and `async-io`, with optional operational TCP.
#[derive(Clone, Copy)]
pub struct StdNetStack<'a> {
    tcp: Option<&'a crate::tcp::TcpBuffers<StdTcpSocket>>,
}

impl core::fmt::Debug for StdNetStack<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StdNetStack")
            .field("tcp", &self.tcp.is_some())
            .finish()
    }
}

impl Default for StdNetStack<'static> {
    fn default() -> Self {
        Self::new()
    }
}

impl StdNetStack<'static> {
    /// Create a new UDP-only instance of the `StdNetStack` type.
    pub const fn new() -> Self {
        Self { tcp: None }
    }
}

impl<'a> StdNetStack<'a> {
    /// Create a new `StdNetStack` with operational TCP enabled over caller-owned buffers.
    pub const fn with_tcp(tcp: &'a crate::tcp::TcpBuffers<StdTcpSocket>) -> Self {
        Self { tcp: Some(tcp) }
    }
}

impl<'a> NetStack for StdNetStack<'a> {
    type Socket<'s>
        = StdNetSocket
    where
        Self: 's;

    fn bind(
        &self,
        addr: SocketAddr,
        ipv4_interface: Ipv4Addr,
        ipv6_interface: u32,
    ) -> impl Future<Output = Result<Self::Socket<'_>, Error>> + MaybeSend {
        ready(StdNetSocket::bind(addr, ipv4_interface, ipv6_interface))
    }

    fn tcp(&self) -> Option<impl NetTcpStack + '_> {
        self.tcp.map(StdTcpStack)
    }
}

mod tcp {
    use core::net::SocketAddr;
    use std::net::{TcpListener, TcpStream};

    use async_io::Async;
    use socket2::{Domain, Protocol, Socket, Type};

    use crate::net::NetTcpStack;
    use crate::tcp::{NetTcpListener, TcpBound, TcpBuffers};
    use rs_matter_utils::error::Error;

    /// An `async-io` TCP listener, usable with [`TcpNetwork`](crate::tcp::TcpNetwork)
    /// and [`TcpBound`].
    pub struct StdTcpListener(pub Async<TcpListener>);

    impl StdTcpListener {
        /// Bind an async TCP listener on the given socket address.
        pub fn bind(addr: SocketAddr) -> Result<Self, Error> {
            let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
            socket.set_reuse_address(true)?;
            if addr.is_ipv6() {
                socket.set_only_v6(false)?;
            }
            socket.bind(&addr.into())?;
            socket.listen(16)?;
            socket.set_nonblocking(true)?;
            Ok(Self(Async::new_nonblocking(socket.into())?))
        }
    }

    impl core::ops::Deref for StdTcpListener {
        type Target = Async<TcpListener>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl core::ops::DerefMut for StdTcpListener {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl NetTcpListener for StdTcpListener {
        type Socket = Async<TcpStream>;

        async fn accept(&mut self) -> Result<(SocketAddr, Self::Socket), Error> {
            NetTcpListener::accept(&mut self.0).await
        }

        async fn connect(&mut self, addr: SocketAddr) -> Result<Self::Socket, Error> {
            NetTcpListener::connect(&mut self.0, addr).await
        }
    }

    /// An owned, full-duplex `async-io` stream.
    pub type StdTcpSocket = Async<TcpStream>;

    /// Operational TCP stack for [`StdNetStack`](super::StdNetStack) backed by
    /// caller-owned [`TcpBuffers`].
    pub struct StdTcpStack<'a>(pub(super) &'a TcpBuffers<StdTcpSocket>);

    impl<'a> NetTcpStack for StdTcpStack<'a> {
        type Tcp<'s>
            = TcpBound<'a, StdTcpListener>
        where
            Self: 's;

        async fn bind(&self, addr: SocketAddr) -> Result<Self::Tcp<'_>, Error> {
            let listener = StdTcpListener::bind(addr)?;
            Ok(self.0.bind(listener))
        }

        fn supports_client(&self) -> bool {
            true
        }
    }
}

pub use tcp::*;

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
        socket.set_nonblocking(true)?;

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
    use std::net::TcpStream;

    fn any(port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn std_net_stack_binds_tcp_server() {
        use crate::net::NetTcpStack;
        use crate::tcp::TcpBuffers;
        use rs_matter_utils::init::InitMaybeUninit;

        futures_lite::future::block_on(async {
            let buffers = Box::leak(Box::new_uninit()).init_with(TcpBuffers::init());
            let stack = StdNetStack::with_tcp(buffers);
            let addr = "127.0.0.1:0".parse().unwrap();
            let tcp_stack = stack.tcp().unwrap();
            assert!(tcp_stack.supports_client());
            let server = tcp_stack.bind(addr).await;
            assert!(server.is_ok());
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn embedded_tcp_server_exchanges_framed_packets_over_real_sockets() {
        use crate::tcp::{TcpConfig, TcpNetwork};
        use rs_matter_utils::futures::{select3, Either3};
        use rs_matter_utils::timers::{with_timeout, Duration};

        futures_lite::future::block_on(async {
            let listener = StdTcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let address = listener.0.get_ref().local_addr().unwrap();
            let server = TcpNetwork::<_, 64>::with_config(
                listener,
                TcpConfig {
                    idle_timeout: Some(Duration::from_millis(500)),
                    ..Default::default()
                },
            );
            let service = async {
                let mut receiver = &server;
                let mut buffer = [0u8; 32];
                loop {
                    let (count, peer) = receiver.recv_from(&mut buffer).await.unwrap();
                    assert!(&buffer[..count] == b"ping" || &buffer[..count] == b"again");
                    receiver.send_to(b"pong", peer).await.unwrap();
                }
            };
            let client = async {
                let mut stream = Async::<TcpStream>::connect(address).await.unwrap();
                futures_lite::io::AsyncWriteExt::write_all(&mut stream, b"\x04\0\0\0ping")
                    .await
                    .unwrap();
                let mut reply = [0u8; 8];
                futures_lite::io::AsyncReadExt::read_exact(&mut stream, &mut reply)
                    .await
                    .unwrap();
                assert_eq!(&reply, b"\x04\0\0\0pong");

                // A second connection cannot disrupt or replace the active operational peer.
                let second = Async::<TcpStream>::connect(address).await.unwrap();
                futures_lite::io::AsyncWriteExt::write_all(&mut stream, b"\x04\0\0\0ping")
                    .await
                    .unwrap();
                futures_lite::io::AsyncReadExt::read_exact(&mut stream, &mut reply)
                    .await
                    .unwrap();
                assert_eq!(&reply, b"\x04\0\0\0pong");
                drop(second);

                // Idle teardown releases the socket; the listener stays usable.
                let mut eof = [0u8; 1];
                assert_eq!(
                    futures_lite::io::AsyncReadExt::read(&mut stream, &mut eof)
                        .await
                        .unwrap(),
                    0
                );
                let mut replacement = Async::<TcpStream>::connect(address).await.unwrap();
                futures_lite::io::AsyncWriteExt::write_all(&mut replacement, b"\x05\0\0\0again")
                    .await
                    .unwrap();
                futures_lite::io::AsyncReadExt::read_exact(&mut replacement, &mut reply)
                    .await
                    .unwrap();
                assert_eq!(&reply, b"\x04\0\0\0pong");
            };
            let result = with_timeout(
                Duration::from_secs(5),
                select3(server.run(), service, client),
            )
            .await
            .unwrap();
            assert!(matches!(result, Either3::Third(())));
        });
    }

    #[test]
    fn an_ipv6_socket_exchanges_ipv6_and_ipv4_packets() {
        futures_lite::future::block_on(async {
            let mut socket = StdNetStack::new()
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
            let stack = StdNetStack::new();

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
            let mut socket = StdNetStack::new()
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
