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

//! A module containing `NetifDiag` and `NetChangeNotif` implementations for Unix-like systems.

use core::net::{Ipv4Addr, Ipv6Addr};

use alloc::string::String;
use alloc::vec::Vec;

use nix::ifaddrs::InterfaceAddress;
use nix::net::if_::InterfaceFlags;

use crate::data_model::sdm::gen_diag::{InterfaceTypeEnum, NetifDiag, NetifInfo};
use crate::error::{Error, ErrorCode};

use super::NetChangeNotif;

/// UnixNetifs is a type for getting all network interfaces
///
/// A simple implementation of the `NetifDiag` trait.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UnixNetifs;

impl UnixNetifs {
    /// Get all network interfaces
    pub fn get(&self) -> Result<Vec<UnixNetif>, Error> {
        let mut netifs: Vec<UnixNetif> = Vec::new();

        for ia in nix::ifaddrs::getifaddrs().map_err(|_| ErrorCode::NoNetworkInterface)? {
            let netif_index =
                nix::net::if_::if_nametoindex(ia.interface_name.as_str()).unwrap_or(0);

            if let Some(netif) = netifs
                .iter_mut()
                .find(|netif| netif.name == ia.interface_name)
            {
                netif.load(&ia, netif_index)?;
            } else {
                let mut netif = UnixNetif {
                    name: String::new(),
                    hw_addr: [0; 8],
                    ipv4addrs: Vec::new(),
                    ipv6addrs: Vec::new(),
                    operational: false,
                    netif_index: 0,
                };

                netif.load(&ia, netif_index)?;

                netifs.push(netif);
            }
        }

        Ok(netifs)
    }
}

impl NetifDiag for UnixNetifs {
    fn netifs(&self, f: &mut dyn FnMut(&NetifInfo) -> Result<(), Error>) -> Result<(), Error> {
        for netif in self.get()? {
            f(&netif.to_netif_info())?;
        }

        Ok(())
    }
}

impl NetChangeNotif for UnixNetifs {
    async fn wait_changed(&self) {
        core::future::pending().await // TODO
    }
}

/// A type for representing one network interface
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UnixNetif {
    /// Interface name
    pub name: String,
    /// Hardware address
    pub hw_addr: [u8; 8],
    /// IPv4 addresses
    pub ipv4addrs: Vec<Ipv4Addr>,
    /// IPv6 addresses
    pub ipv6addrs: Vec<Ipv6Addr>,
    /// Operational status
    pub operational: bool,
    /// Interface index
    pub netif_index: u32,
}

impl UnixNetif {
    /// Convert to `NetifInfo`
    pub fn to_netif_info(&self) -> NetifInfo<'_> {
        NetifInfo {
            name: &self.name,
            operational: self.operational,
            offprem_svc_reachable_ipv4: None,
            offprem_svc_reachable_ipv6: None,
            hw_addr: &self.hw_addr,
            ipv4_addrs: &self.ipv4addrs,
            ipv6_addrs: &self.ipv6addrs,
            netif_type: InterfaceTypeEnum::Unspecified, // TODO
            netif_index: self.netif_index,
        }
    }

    /// Augment the information of the network interface with
    /// the provided `InterfaceAddress`.
    fn load(&mut self, ia: &InterfaceAddress, index: u32) -> Result<(), Error> {
        self.name = ia.interface_name.clone();
        self.operational |= ia.flags.contains(InterfaceFlags::IFF_RUNNING);
        self.netif_index = index;

        if let Some(address) = ia.address.as_ref() {
            if let Some(link_addr) = address.as_link_addr() {
                if let Some(addr) = link_addr.addr() {
                    self.hw_addr[..6].copy_from_slice(&addr);
                    self.hw_addr[6..].fill(0);
                }
            } else if let Some(ipv6_addr) = address.as_sockaddr_in6() {
                self.ipv6addrs.push(ipv6_addr.ip());
            } else if let Some(ipv4_addr) = address.as_sockaddr_in() {
                self.ipv4addrs.push(ipv4_addr.ip().into());
            }
        }

        Ok(())
    }
}
