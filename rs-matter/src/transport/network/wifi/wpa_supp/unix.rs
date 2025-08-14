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

//! Unix-specific implementation of `IpStackCtl` using the `dhclient` command-line utility.

use core::cell::RefCell;

use std::process::Command;

use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{Duration, Timer};

use crate::dm::clusters::net_comm::NetCtlError;
use crate::dm::networks::unix::{UnixNetif, UnixNetifs};
use crate::error::{Error, ErrorCode};
use crate::transport::network::wifi::wpa_supp::IpStackCtl;
use crate::utils::ipv6::create_link_local_ipv6;
use crate::utils::sync::blocking;

/// An `IpStackCtl` implementation for the linux `dhclient` command-line utility.
///
/// NOTE: Running `dhclient` might require certain privileges for the Unix user on behalf of which
/// `rs-matter` and thus this code is running. For development/testing, it is easiest to run the
/// application with `sudo`, but for production, it is recommended to make sure the user has appropriate permissions.
pub struct DhClientCtl {
    ifname: String,
    self_assign_link_local_ipv6: bool,
    netif: blocking::Mutex<NoopRawMutex, RefCell<Option<UnixNetif>>>,
}

impl DhClientCtl {
    /// Create a new `DhClientCtl` instance.
    ///
    /// # Arguments
    /// - `ifname` - The name of the network interface to control (e.g., "wlan0").
    /// - `self_assign_link_local_ipv6` - If true, self-assign a link-local IPv6 address derived from the MAC address of the interface.
    ///   Note that while `self_assign_link_local_ipv6` does generate a proper link-local Ipv6 address derived from the network interface
    ///   MAC, it does not really implement the SLAAC protocol in that it does not check whether the generated address is already in use.
    pub fn new(ifname: &str, self_assign_link_local_ipv6: bool) -> Self {
        Self {
            ifname: ifname.to_string(),
            self_assign_link_local_ipv6,
            netif: blocking::Mutex::new(RefCell::new(None)),
        }
    }

    /// Wait for the interface state as follows:
    /// - If `for_connection` is true, wait until the interface is connected.
    /// - If `for_connection` is false, wait until the interface state changes (e.g., connected, disconnected or other change).
    async fn wait(&self, for_connection: bool) {
        const WAIT_TIMEOUT_SECS: u64 = 1;

        loop {
            let (changed, connected) = self.update_netif(self.fetch_netif().ok());

            if for_connection && connected || !for_connection && changed {
                break;
            }

            Timer::after(Duration::from_secs(WAIT_TIMEOUT_SECS)).await;
        }
    }

    /// Update the cached network interface information and return whether it has changed and whether it has connected.
    fn update_netif(&self, new_netif: Option<UnixNetif>) -> (bool, bool) {
        self.netif.lock(|netif_ref| {
            let mut netif = netif_ref.borrow_mut();

            let changed = if *netif != new_netif {
                *netif = new_netif;
                true
            } else {
                false
            };

            let connected = Self::connected(netif.as_ref());

            (changed, connected)
        })
    }

    /// Fetch the current network interface information by name.
    fn fetch_netif(&self) -> Result<UnixNetif, Error> {
        UnixNetifs
            .get()?
            .into_iter()
            .find(|netif| netif.name == self.ifname)
            .ok_or_else(|| ErrorCode::NoNetworkInterface.into())
    }

    /// Check if the network interface is connected.
    fn connected(netif: Option<&UnixNetif>) -> bool {
        netif.is_some_and(|netif| {
            netif.operational && !netif.ipv4addrs.is_empty() && !netif.ipv6addrs.is_empty()
        })
    }
}

impl IpStackCtl for DhClientCtl {
    async fn connect(&self) -> Result<(), NetCtlError> {
        const CONNECT_TIMEOUT_SECS: u64 = 15;

        // 1) If the user requested, self-assign a MAC-derived link-local ipv6 addr
        // Necessary, because the `dhclient` coming with certain Linux distros (Ubunut + NetworkManager)
        // seems not to configure any Ipv6 addresses on the interface, even if SLAAC is enabled.

        let netif = self.fetch_netif().map_err(NetCtlError::Other)?;

        self.update_netif(Some(netif.clone()));

        if self.self_assign_link_local_ipv6 {
            let ipv6 = create_link_local_ipv6(&unwrap!(netif.hw_addr[..6].try_into()));

            let status = Command::new("ip")
                .arg("-6")
                .arg("addr")
                .arg("add")
                .arg(format!("{}/10", ipv6))
                .arg("dev")
                .arg(&self.ifname)
                .status()
                .map_err(|_| NetCtlError::IpBindFailed)?;

            if !status.success() {
                error!(
                    "Assigning link-local IPv6 address {} on interface {} failed with status: {}",
                    ipv6, self.ifname, status
                );

                return Err(NetCtlError::IpBindFailed);
            }
        }

        // 2) invoke `dhclient` on the interface. This will:
        // - Get a DHCP lease for an Ipv4 address
        // - Use SLAAC to configure an ipv6 address
        let result = Command::new("dhclient")
            .arg("-nw")
            .arg(&self.ifname)
            .status();

        // Do not hard-fail if we cannot run `dhclient`
        // It might fail if NetworkManager is around, and we just need a link-local ipv6 IP anyway
        // Also see this:
        // https://github.com/project-chip/connectedhomeip/blob/cd5fec9ba9be0c39f3c11f67d57b18b6bb2b4289/src/platform/Linux/ConnectivityManagerImpl.cpp#L1699

        match result {
            Ok(status) => {
                if !status.success() {
                    warn!(
                        "Running `dhclient` on interface {} failed with status: {}",
                        self.ifname, status
                    );
                }
            }
            Err(e) => warn!(
                "Running `dhclient` on interface {} failed with error: {}",
                self.ifname, e
            ),
        }

        let timeout = Timer::after(Duration::from_secs(CONNECT_TIMEOUT_SECS));
        let connected = self.wait(true);

        match select(connected, timeout).await {
            Either::First(_) => Ok(()),
            Either::Second(_) => Err(NetCtlError::IpBindFailed),
        }
    }

    async fn wait_changed(&self) {
        self.wait(false).await
    }

    fn is_connected(&self) -> Result<bool, NetCtlError> {
        self.netif
            .lock(|netif| Ok(Self::connected(netif.borrow().as_ref())))
    }
}
