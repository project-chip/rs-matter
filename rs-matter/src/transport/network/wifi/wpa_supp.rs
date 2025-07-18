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

//! Wifi network controller implementation based on the wpa-supplicant D-Bus service.

use core::cell::{Cell, RefCell};

use std::collections::HashMap;
use std::process::Command;

use embassy_futures::select::Either;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use futures_lite::StreamExt;

use zbus::zvariant::{ObjectPath, Value};
use zbus::Connection;

use crate::dm::clusters::net_comm::{
    NetCtl, NetCtlError, NetworkScanInfo, NetworkType, WiFiBandEnum, WiFiSecurityBitmap,
    WirelessCreds,
};
use crate::dm::clusters::wifi_diag::{WifiDiag, WirelessDiag};
use crate::dm::networks::NetChangeNotif;
use crate::error::{Error, ErrorCode};
use crate::utils::sync::blocking::Mutex;
use crate::utils::zbus_proxies::wpa_supp::bss::BSSProxy;
use crate::utils::zbus_proxies::wpa_supp::interface::InterfaceProxy;

/// A `NetCtl`, `WirelessDiag`, `WifiDiag` and `NetChangeNotif` implementation based on the `wpa-supplicant` service.
///
/// Suitable for use with embedded Linux devices that do have the `wpa-supplicant` service running over D-Bus
/// but don't have the `NetworkManager` service available.
pub struct WpaSuppCtl<'a, T> {
    interface: InterfaceProxy<'a>,
    connection: &'a Connection,
    ip_stack_ctl: T,
    ssid_info: Mutex<NoopRawMutex, RefCell<SSIDInfo>>,
}

impl<'a, T> WpaSuppCtl<'a, T>
where
    T: IpStackCtl,
{
    /// Create a new `WpaSuppCtl` instance.
    ///
    /// # Arguments
    /// * `connection` - A reference to the D-Bus connection.
    /// * `interface` - The D-Bus object path of Wifi interface object.
    /// * `ip_stack_ctl` - An instance of a type implementing the `IpStackCtl` trait, which is used to control the IP stack.
    ///
    /// # Returns
    /// A `zbus::Result<Self>` containing the new `WpaSuppCtl` instance on success.
    pub async fn new(
        connection: &'a Connection,
        interface: ObjectPath<'a>,
        ip_stack_ctl: T,
    ) -> zbus::Result<Self> {
        Ok(Self {
            interface: InterfaceProxy::builder(connection)
                .path(interface)?
                .build()
                .await?,
            connection,
            ip_stack_ctl,
            ssid_info: Mutex::new(RefCell::new(SSIDInfo::new())),
        })
    }

    /// Return a reference to the `InterfaceProxy`.
    pub const fn interface(&self) -> &InterfaceProxy<'_> {
        &self.interface
    }

    /// Return a reference to the D-Bus connection.
    pub const fn connection(&self) -> &Connection {
        self.connection
    }

    async fn wait_changed(&self) -> Result<bool, zbus::Error> {
        let mut authorized = self.interface.receive_sta_authorized().await?;
        let mut deauthorized = self.interface.receive_sta_deauthorized().await?;

        loop {
            let ip_stack_changed = self.ip_stack_ctl.wait_changed();

            embassy_futures::select::select3(
                authorized.next(),
                deauthorized.next(),
                ip_stack_changed,
            )
            .await;

            let bss = self.interface.current_bss().await?;

            let ssid = if !bss.is_empty() {
                let bss_info = BSSProxy::builder(self.connection)
                    .path(bss)?
                    .build()
                    .await?;

                Some(bss_info.ssid().await?)
            } else {
                None
            };

            let (changed, connected) = self.update_connected(ssid);

            if changed {
                break Ok(connected);
            }
        }
    }

    async fn wait_connected(&self) -> Result<(), zbus::Error> {
        loop {
            if self.wait_changed().await? {
                return Ok(());
            }
        }
    }

    fn update_connected(&self, ssid: Option<Vec<u8>>) -> (bool, bool) {
        self.ssid_info.lock(|ssid_info| {
            let mut ssid_info = ssid_info.borrow_mut();

            let was_connected =
                ssid_info.is_connected() && self.ip_stack_ctl.is_connected().unwrap_or(false);

            ssid_info.connected = ssid;

            (
                was_connected != ssid_info.is_connected()
                    && self.ip_stack_ctl.is_connected().unwrap_or(false),
                ssid_info.is_connected(),
            )
        })
    }
}

/// A trait for controlling the IP stack, allowing for connection management and change notifications.
///
/// This trait is necessary, because `wpa-supplicant` does not control the IP stack directly.
///
/// One possible implementation would be to just invoke the command line `dhclient` utility on the
/// wireless interface. Another possibility would be to use the DHCP client in the `edge-mdns` crate for Ipv4
/// and then additionally assign a pre-computed link-local IP address to the interface for Ipv6.
pub trait IpStackCtl {
    /// Connect the IP stack by e.g. configuring the network interface via DHCP (for IPv4) and SLAAC (for IPv6).
    async fn connect(&self) -> Result<(), NetCtlError>;

    /// Wait for changes in the IP stack, such as connection status changes or network configuration updates.
    async fn wait_changed(&self);

    /// Check if the IP stack is currently connected.
    fn is_connected(&self) -> Result<bool, NetCtlError>;
}

impl<T> IpStackCtl for &T
where
    T: IpStackCtl,
{
    async fn connect(&self) -> Result<(), NetCtlError> {
        T::connect(self).await
    }

    async fn wait_changed(&self) {
        T::wait_changed(self).await;
    }

    fn is_connected(&self) -> Result<bool, NetCtlError> {
        T::is_connected(self)
    }
}

/// An `IpStackCtl` implementation for the linux `dhclient` command-line utility.
pub struct DhClientCtl {
    ifname: String,
    connected: Mutex<NoopRawMutex, Cell<bool>>,
}

impl DhClientCtl {
    /// Create a new `DhClientCtl` instance.
    ///
    /// # Arguments
    /// * `ifname` - The name of the network interface to control (e.g., "wlan0").
    pub fn new(ifname: &str) -> Self {
        Self {
            ifname: ifname.to_string(),
            connected: Mutex::new(Cell::new(false)),
        }
    }
}

impl IpStackCtl for DhClientCtl {
    async fn connect(&self) -> Result<(), NetCtlError> {
        Command::new("dhclient")
            .arg("-nw")
            .arg(&self.ifname)
            .status()
            .map_err(|_| NetCtlError::Other(ErrorCode::NoNetworkInterface.into()))?;

        self.connected.lock(|connected| connected.set(true));

        Ok(())
    }

    async fn wait_changed(&self) {
        // Implement the logic to wait for changes in the IP stack.
        core::future::pending::<()>().await
    }

    fn is_connected(&self) -> Result<bool, NetCtlError> {
        Ok(self.connected.lock(|connected| connected.get()))
    }
}

impl<T> NetCtl for WpaSuppCtl<'_, T>
where
    T: IpStackCtl,
{
    fn net_type(&self) -> NetworkType {
        NetworkType::Wifi
    }

    async fn scan<F>(&self, network: Option<&[u8]>, mut f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error>,
    {
        let mut args = HashMap::new();

        let active = Value::from("active");
        args.insert("Type", &active);

        let ssids = network.map(|network| vec![network.to_vec()].into());
        if ssids.is_some() {
            #[allow(clippy::unnecessary_unwrap)]
            args.insert("SSIDs", ssids.as_ref().unwrap());
        }

        let mut scan_done = self.interface.receive_scan_done().await?;

        self.interface.scan(args).await?;

        while scan_done.next().await.is_none() {}

        let bsss = self.interface.bsss().await?;

        for bss in bsss {
            let bss_info = BSSProxy::builder(self.connection)
                .path(bss)?
                .build()
                .await?;

            // TODO: Only leave the infrastructure ones, remove the ad-hocs

            let mut security = WiFiSecurityBitmap::WEP;
            if !bss_info.wpa().await?.is_empty() {
                // TODO
                security |= WiFiSecurityBitmap::WPA_PERSONAL;
            }

            let network_scan_info = NetworkScanInfo::Wifi {
                security,
                ssid: &bss_info.ssid().await?,
                bssid: &bss_info.bssid().await?,
                channel: 11,              // TODO bss_info.frequency().await? as u8,
                band: WiFiBandEnum::V2G4, // TODO
                rssi: bss_info.signal().await? as i8,
            };

            f(&network_scan_info)?;
        }

        Ok(())
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        let WirelessCreds::Wifi { ssid, pass } = creds else {
            return Err(NetCtlError::Other(ErrorCode::InvalidAction.into()));
        };

        // TODO: Maybe just add our own network
        self.interface.remove_all_networks().await?;

        let mut args = HashMap::new();

        self.ssid_info.lock(|ssid_info| {
            let mut ssid_info = ssid_info.borrow_mut();
            ssid_info.requested = Some(ssid.to_vec());
        });

        let arg_ssid = (*ssid).into();
        args.insert("ssid", &arg_ssid);

        let arg_pass = (*pass).into();
        args.insert("psk", &arg_pass);

        let network = self.interface.add_network(args).await?;

        self.interface.select_network(&network).await?;

        let timer = embassy_time::Timer::after(embassy_time::Duration::from_secs(30));
        let connected = self.wait_connected();

        match embassy_futures::select::select(connected, timer).await {
            Either::First(result) => {
                result?;

                Ok(())
            }
            Either::Second(_) => {
                self.interface.remove_all_networks().await?;

                Err(NetCtlError::AuthFailure)
            }
        }
    }
}

impl<T> WirelessDiag for WpaSuppCtl<'_, T>
where
    T: IpStackCtl,
{
    fn connected(&self) -> Result<bool, Error> {
        Ok(self.ssid_info.lock(|ssid_info| {
            ssid_info.borrow().is_connected() && self.ip_stack_ctl.is_connected().unwrap_or(false)
        }))
    }
}

impl<T> WifiDiag for WpaSuppCtl<'_, T> where T: IpStackCtl {} // TODO

impl<T> NetChangeNotif for WpaSuppCtl<'_, T>
where
    T: IpStackCtl,
{
    async fn wait_changed(&self) {
        let _ = WpaSuppCtl::wait_changed(self).await;
    }
}

#[derive(Debug)]
struct SSIDInfo {
    requested: Option<Vec<u8>>,
    connected: Option<Vec<u8>>,
}

impl SSIDInfo {
    const fn new() -> Self {
        Self {
            requested: None,
            connected: None,
        }
    }

    fn is_connected(&self) -> bool {
        self.requested.is_some() && self.requested == self.connected
    }
}

impl From<zbus::Error> for Error {
    fn from(_: zbus::Error) -> Self {
        ErrorCode::NoNetworkInterface.into()
    }
}

impl From<zbus::Error> for NetCtlError {
    fn from(value: zbus::Error) -> Self {
        NetCtlError::Other(value.into())
    }
}
