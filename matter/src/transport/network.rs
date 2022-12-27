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

use std::{
    fmt::{Debug, Display},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use crate::error::Error;

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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Udp(addr) => writeln!(f, "{}", addr),
        }
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Udp(addr) => writeln!(f, "{}", addr),
        }
    }
}

pub trait NetworkInterface {
    fn recv(&self, in_buf: &mut [u8]) -> Result<(usize, Address), Error>;
    fn send(&self, out_buf: &[u8], addr: Address) -> Result<usize, Error>;
}
