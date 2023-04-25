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
use no_std_net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(feature = "std")]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(PartialEq, Copy, Clone)]
pub enum Address {
    Udp(SocketAddr),
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
