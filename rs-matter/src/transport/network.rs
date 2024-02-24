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
use core::mem::MaybeUninit;

#[cfg(not(feature = "std"))]
pub use no_std_net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
#[cfg(feature = "std")]
pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::error::Error;

use super::packet::{MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE};

#[derive(Eq, PartialEq, Copy, Clone)]
pub enum Address {
    Udp(SocketAddr),
}

impl Address {
    pub fn unwrap_udp(self) -> SocketAddr {
        match self {
            Self::Udp(addr) => addr,
        }
    }
}

impl Default for Address {
    fn default() -> Self {
        Address::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Address::Udp(addr) => writeln!(f, "{}", addr),
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

pub trait UdpSend {
    async fn send_to(&mut self, data: &[u8], addr: SocketAddr) -> Result<(), Error>;
}

impl<T> UdpSend for &mut T
where
    T: UdpSend,
{
    async fn send_to(&mut self, data: &[u8], addr: SocketAddr) -> Result<(), Error> {
        (*self).send_to(data, addr).await
    }
}

pub trait UdpReceive {
    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Error>;
}

impl<T> UdpReceive for &mut T
where
    T: UdpReceive,
{
    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        (*self).recv_from(buffer).await
    }
}

pub struct UdpBuffers(MaybeUninit<([u8; MAX_TX_BUF_SIZE], [u8; MAX_RX_BUF_SIZE])>);

impl UdpBuffers {
    #[inline(always)]
    pub const fn new() -> Self {
        Self(MaybeUninit::uninit())
    }

    pub fn split(&mut self) -> (&mut [u8], &mut [u8]) {
        let init = unsafe { self.0.assume_init_mut() };

        (&mut init.0, &mut init.1)
    }
}

#[cfg(all(feature = "std", feature = "async-io"))]
mod async_io {
    use crate::error::*;

    use std::net::UdpSocket;

    use async_io::Async;

    use crate::transport::network::SocketAddr;

    use super::{UdpReceive, UdpSend};

    impl UdpSend for &Async<UdpSocket> {
        async fn send_to(&mut self, data: &[u8], addr: SocketAddr) -> Result<(), Error> {
            Async::<UdpSocket>::send_to(self, data, addr).await?;

            Ok(())
        }
    }

    impl UdpReceive for &Async<UdpSocket> {
        async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
            let (len, addr) = Async::<UdpSocket>::recv_from(self, buffer).await?;

            Ok((len, addr))
        }
    }
}
