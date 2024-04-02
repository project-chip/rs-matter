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

use core::fmt::{Debug, Display};

#[cfg(not(feature = "std"))]
pub use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
#[cfg(feature = "std")]
pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::error::Error;

#[derive(Eq, PartialEq, Copy, Clone)]
pub enum Address {
    Udp(SocketAddr),
}

impl Address {
    pub const fn new() -> Self {
        Self::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    pub fn is_reliable(&self) -> bool {
        match self {
            Self::Udp(_) => false,
        }
    }

    pub fn unwrap_udp(self) -> SocketAddr {
        match self {
            Self::Udp(addr) => addr,
        }
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Address::Udp(addr) => write!(f, "UDP {}", addr),
        }
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Address::Udp(addr) => writeln!(f, "{}", addr),
        }
    }
}

pub trait NetworkSend {
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

pub trait NetworkReceive {
    async fn wait_available(&mut self) -> Result<(), Error>;

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

#[cfg(all(feature = "std", feature = "async-io"))]
mod async_io {
    use crate::error::*;

    use std::net::UdpSocket;

    use async_io::Async;

    use crate::transport::network::Address;

    use super::{NetworkReceive, NetworkSend};

    impl NetworkSend for &Async<UdpSocket> {
        async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
            Async::<UdpSocket>::send_to(self, data, addr.unwrap_udp()).await?;

            Ok(())
        }
    }

    impl NetworkReceive for &Async<UdpSocket> {
        async fn wait_available(&mut self) -> Result<(), Error> {
            let mut buf = [0];

            loop {
                let (len, _) = Async::<UdpSocket>::peek_from(self, &mut buf).await?;

                if len > 0 {
                    break;
                }
            }

            Ok(())
        }

        async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
            let (len, addr) = Async::<UdpSocket>::recv_from(self, buffer).await?;

            Ok((len, Address::Udp(addr)))
        }
    }
}
