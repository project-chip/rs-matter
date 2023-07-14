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
pub use no_std_net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(feature = "std")]
pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
        Address::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080))
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

#[cfg(all(feature = "std", not(feature = "embassy-net")))]
pub use std_stack::*;

#[cfg(feature = "embassy-net")]
pub use embassy_stack::*;

#[cfg(all(feature = "std", not(feature = "embassy-net")))]
mod std_stack {
    pub trait NetworkStackDriver {}

    impl NetworkStackDriver for () {}

    pub trait NetworkStackMulticastDriver {}

    impl NetworkStackMulticastDriver for () {}

    pub struct NetworkStack<D>(D);

    impl NetworkStack<()> {
        pub const fn new() -> Self {
            Self(())
        }
    }
}

#[cfg(feature = "embassy-net")]
mod embassy_stack {
    pub use embassy_net::Stack as NetworkStack;
    pub use embassy_net_driver::Driver as NetworkStackDriver;
    pub use smoltcp::phy::Device as NetworkStackMulticastDriver;
}
