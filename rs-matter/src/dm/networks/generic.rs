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

//! A cross-platform `NetifDiag` and `NetChangeNotif` implementation backed by
//! the `if-addrs` crate. Suitable as a fallback on platforms (notably
//! Windows) where the richer [`super::unix::UnixNetifs`] implementation is
//! not available. Unlike the `unix` module, this implementation does not
//! report a hardware address (MAC).

use core::net::{Ipv4Addr, Ipv6Addr};

use alloc::string::String;
use alloc::vec::Vec;

use crate::dm::clusters::gen_diag::{InterfaceTypeEnum, NetifDiag, NetifInfo};
use crate::error::{Error, ErrorCode};
use crate::utils::sync::DynBase;

use super::NetChangeNotif;

/// `GenericNetifs` enumerates all operational network interfaces in a
/// cross-platform way using the `if-addrs` crate.
///
/// It is a simple implementation of the [`NetifDiag`] trait suitable as a
/// fallback on platforms where the richer [`super::unix::UnixNetifs`]
/// implementation is not available (notably Windows). On Unix platforms,
/// prefer [`super::unix::UnixNetifs`], which additionally reports the
/// hardware (MAC) address.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GenericNetifs;

impl GenericNetifs {
    /// Get all network interfaces.
    pub fn get(&self) -> Result<Vec<GenericNetif>, Error> {
        let mut netifs: Vec<GenericNetif> = Vec::new();

        for ia in if_addrs::get_if_addrs().map_err(|_| ErrorCode::NoNetworkInterface)? {
            let netif_index = ia.index.unwrap_or(0);

            let entry = if let Some(entry) = netifs.iter_mut().find(|n| n.name == ia.name) {
                entry
            } else {
                netifs.push(GenericNetif {
                    name: ia.name.clone(),
                    hw_addr: [0; 8],
                    ipv4addrs: Vec::new(),
                    ipv6addrs: Vec::new(),
                    operational: true,
                    netif_index,
                });
                netifs.last_mut().unwrap()
            };

            if entry.netif_index == 0 {
                entry.netif_index = netif_index;
            }

            match ia.addr {
                if_addrs::IfAddr::V4(v4) => entry.ipv4addrs.push(v4.ip),
                if_addrs::IfAddr::V6(v6) => entry.ipv6addrs.push(v6.ip),
            }
        }

        Ok(netifs)
    }
}

impl DynBase for GenericNetifs {}

impl NetifDiag for GenericNetifs {
    fn netifs(&self, f: &mut dyn FnMut(&NetifInfo) -> Result<(), Error>) -> Result<(), Error> {
        for netif in self.get()? {
            f(&netif.to_netif_info())?;
        }

        Ok(())
    }
}

impl NetChangeNotif for GenericNetifs {
    /// Wait until the set of network interfaces (or their addresses) may have
    /// changed.
    ///
    /// NOTE: The `if-addrs` crate does not expose OS-specific change
    /// notifications, so this is a polling-based fallback that simply waits
    /// for [`super::NETIF_POLL_INTERVAL`] and then returns; it does not
    /// actually detect changes. Callers are expected to re-read the
    /// interface state after this returns and diff it against the previously
    /// observed one.
    async fn wait_changed(&self) {
        super::poll_netifs_changed().await;
    }
}

/// A single network interface as reported by [`GenericNetifs`].
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GenericNetif {
    /// Interface name
    pub name: String,
    /// Hardware address (always zero - not provided by `if-addrs`)
    pub hw_addr: [u8; 8],
    /// IPv4 addresses
    pub ipv4addrs: Vec<Ipv4Addr>,
    /// IPv6 addresses
    pub ipv6addrs: Vec<Ipv6Addr>,
    /// Operational status (always `true` - `if-addrs` only reports interfaces
    /// that have an address assigned, which we treat as operational).
    pub operational: bool,
    /// Interface index
    pub netif_index: u32,
}

impl GenericNetif {
    /// Convert to [`NetifInfo`].
    pub fn to_netif_info(&self) -> NetifInfo<'_> {
        NetifInfo {
            name: &self.name,
            operational: self.operational,
            offprem_svc_reachable_ipv4: None,
            offprem_svc_reachable_ipv6: None,
            hw_addr: &self.hw_addr,
            ipv4_addrs: &self.ipv4addrs,
            ipv6_addrs: &self.ipv6addrs,
            netif_type: InterfaceTypeEnum::Unspecified,
            netif_index: self.netif_index,
        }
    }
}
