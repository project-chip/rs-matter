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

use core::cell::RefCell;

use std::collections::HashMap;

use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use embassy_time::{Duration, Timer};
use futures_lite::StreamExt;

use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::Connection;

use crate::dm::clusters::net_comm::{
    NetCtl, NetCtlError, NetworkScanInfo, NetworkType, WiFiBandEnum, WiFiSecurityBitmap,
    WirelessCreds,
};
use crate::dm::clusters::wifi_diag::{SecurityTypeEnum, WiFiVersionEnum, WifiDiag, WirelessDiag};
use crate::dm::networks::NetChangeNotif;
use crate::error::{Error, ErrorCode};
use crate::tlv::Nullable;
use crate::utils::sync::{blocking, IfMutex};
use crate::utils::zbus_proxies::wpa_supp::bss::BSSProxy;
use crate::utils::zbus_proxies::wpa_supp::interface::InterfaceProxy;
use crate::utils::zbus_proxies::wpa_supp::wpa_supplicant::WPASupplicantProxy;

#[cfg(unix)]
pub mod unix;

/// A `NetCtl`, `WirelessDiag`, `WifiDiag` and `NetChangeNotif` implementation based on the `wpa-supplicant` service.
///
/// Suitable for use with embedded Linux devices that do have the `wpa-supplicant` service running over D-Bus
/// but don't have the `NetworkManager` service available.
pub struct WpaSuppCtl<'a, T>
where
    T: IpStackCtl,
{
    connection: &'a Connection,
    ifname: &'a str,
    ip_stack_ctl: T,
    network: IfMutex<NoopRawMutex, Option<OwnedObjectPath>>,
    wifi_conn_info: blocking::Mutex<NoopRawMutex, RefCell<Option<WifiConnInfo>>>,
}

impl<'a, T> WpaSuppCtl<'a, T>
where
    T: IpStackCtl,
{
    /// Create a new `WpaSuppCtl` instance.
    ///
    /// # Arguments
    /// * `connection` - A reference to the D-Bus connection.
    /// * `interface_path` - The D-Bus object path of Wifi interface object.
    /// * `ip_stack_ctl` - An instance of a type implementing the `IpStackCtl` trait, which is used to control the IP stack.
    ///
    /// # Returns
    /// The new `WpaSuppCtl` instance.
    pub const fn new(connection: &'a Connection, ifname: &'a str, ip_stack_ctl: T) -> Self {
        Self {
            connection,
            ifname,
            ip_stack_ctl,
            network: IfMutex::new(None),
            wifi_conn_info: blocking::Mutex::new(RefCell::new(None)),
        }
    }

    /// Return a reference to the D-Bus connection.
    pub const fn connection(&self) -> &Connection {
        self.connection
    }

    /// Create a wpa-supplicant interface proxy for out interface name
    async fn interface(&self) -> Result<InterfaceProxy<'a>, zbus::Error> {
        let wpas = WPASupplicantProxy::new(self.connection).await?;
        let interface_path = wpas.get_interface(self.ifname).await?;

        InterfaceProxy::builder(self.connection)
            .path(interface_path.clone())?
            .build()
            .await
    }

    /// Wait for the interface state as follows:
    /// - If `for_connection` is true, wait until the interface is connected to a network.
    /// - If `for_connection` is false, wait until the interface state changes (e.g., connected, disconnected or other change).
    async fn wait(&self, for_connection: bool) -> Result<(), Error> {
        let interface = self.interface().await?;

        let mut iface_state_changed = interface.receive_state_changed().await;

        loop {
            let bss = interface.current_bss().await?;

            let (changed, connected) = if bss.len() > 1 {
                self.network_scan_info(&bss, |info| {
                    let info = info.map(WifiConnInfo::new);

                    Ok(self.update_wifi_conn_info(info))
                })
                .await?
            } else {
                self.update_wifi_conn_info(None)
            };

            if for_connection && connected || !for_connection && changed {
                break Ok(());
            }

            let ip_stack_changed = self.ip_stack_ctl.wait_changed();

            select(iface_state_changed.next(), ip_stack_changed).await;
        }
    }

    /// Update the cached WiFi connection information and return whether it has changed and whether it has connected.
    fn update_wifi_conn_info(&self, new_wifi_conn_info: Option<WifiConnInfo>) -> (bool, bool) {
        self.wifi_conn_info.lock(|wifi_conn_info| {
            let mut wifi_conn_info = wifi_conn_info.borrow_mut();

            let changed = if *wifi_conn_info != new_wifi_conn_info {
                *wifi_conn_info = new_wifi_conn_info;
                true
            } else {
                false
            };

            let connected = Self::connected(wifi_conn_info.as_ref());

            (changed, connected)
        })
    }

    /// Check if the provided WiFi connecton info represents a connected network.
    fn connected(wifi_conn_info: Option<&WifiConnInfo>) -> bool {
        wifi_conn_info.is_some()
    }

    /// Remove the currently connected network, if any.
    async fn remove_network(&self, network: &mut Option<OwnedObjectPath>) -> zbus::Result<()> {
        let interface = self.interface().await?;

        if let Some(network_path) = network.clone() {
            if interface.remove_network(&network_path).await.is_ok() {
                network.take();
            }
        }

        Ok(())
    }

    /// Get the network scan information for a given BSS object path.
    async fn network_scan_info<F, R>(&self, bss: &ObjectPath<'_>, f: F) -> Result<R, Error>
    where
        F: FnOnce(Option<&NetworkScanInfo>) -> Result<R, Error>,
    {
        let bss_info = BSSProxy::builder(self.connection)
            .path(bss)?
            .build()
            .await?;

        if bss_info.mode().await? == "infrastructure" {
            let wpa = bss_info.wpa().await?;
            let rsn = bss_info.rsn().await?;

            let security = if wpa.is_empty() && rsn.is_empty() {
                WiFiSecurityBitmap::UNENCRYPTED
            } else {
                let str_list_val = |key, map: &HashMap<String, OwnedValue>| {
                    let str_list: Vec<String> = map
                        .get(key)
                        .cloned()
                        .and_then(|w| w.clone().try_into().ok())
                        .unwrap_or_default();

                    str_list
                };

                let mut security = WiFiSecurityBitmap::empty();

                let wpa_key_mgmt = str_list_val("KeyMgmt", &wpa);

                if wpa_key_mgmt.contains(&"wpa-none".to_string()) {
                    security |= WiFiSecurityBitmap::WEP;
                }

                if wpa_key_mgmt.contains(&"wpa-psk".to_string()) {
                    security |= WiFiSecurityBitmap::WPA_PERSONAL;
                }

                let rsn_key_mgmt = str_list_val("KeyMgmt", &rsn);

                if rsn_key_mgmt.contains(&"wpa-psk".to_string())
                    || rsn_key_mgmt.contains(&"wpa-ft-psk".to_string())
                    || rsn_key_mgmt.contains(&"wpa-psk-sha256".to_string())
                {
                    security |= WiFiSecurityBitmap::WPA_2_PERSONAL;
                }

                if rsn_key_mgmt.contains(&"sae".to_string()) {
                    security |= WiFiSecurityBitmap::WPA_3_PERSONAL
                }

                security
            };

            let (band, channel) = band_and_channel(bss_info.frequency().await? as u32);

            let network_scan_info = NetworkScanInfo::Wifi {
                security,
                ssid: &bss_info.ssid().await?,
                bssid: &bss_info.bssid().await?,
                band,
                channel,
                rssi: bss_info.signal().await?.min(i8::MIN as _).max(i8::MAX as _) as i8,
            };

            f(Some(&network_scan_info))
        } else {
            // Skip ad-hoc networks, we are only interested in infrastructure ones
            f(None)
        }
    }
}

impl<T> Drop for WpaSuppCtl<'_, T>
where
    T: IpStackCtl,
{
    fn drop(&mut self) {
        // Remove the network on drop
        let _ = futures_lite::future::block_on(async {
            let mut network = self.network.lock().await;

            self.remove_network(&mut network).await
        });
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
        const SCAN_RETRIES: usize = 3;
        const SCAN_RETRIES_SLEEP_SEC: u64 = 5;

        let _guard = self.network.lock().await;

        let mut args = HashMap::new();

        let active = Value::from("active");
        args.insert("Type", &active);

        let ssids = network.map(|network| vec![network.to_vec()].into());
        if ssids.is_some() {
            #[allow(clippy::unnecessary_unwrap)]
            args.insert("SSIDs", ssids.as_ref().unwrap());
        }

        let interface = self.interface().await?;

        let mut scan_done = interface.receive_scan_done().await?;

        for _ in 0..SCAN_RETRIES {
            // Sometimes we do get a "Scan Rejected error"
            // Therefore, try several times

            if interface.scan(args.clone()).await.is_ok() {
                // Scan started successfully

                // Wait for the scan to complete
                while scan_done.next().await.is_none() {}

                break;
            }

            Timer::after(Duration::from_secs(SCAN_RETRIES_SLEEP_SEC)).await;
        }

        let bsss = interface.bsss().await?;

        for bss in bsss {
            self.network_scan_info(&bss, |info| {
                if let Some(info) = info {
                    f(info)?;
                }

                Ok(())
            })
            .await?;
        }

        Ok(())
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        const CONNECT_TIMEOUT_SECS: u64 = 30;

        let mut network = self.network.lock().await;

        let WirelessCreds::Wifi { ssid, pass } = creds else {
            return Err(NetCtlError::Other(ErrorCode::InvalidAction.into()));
        };

        let interface = self.interface().await?;

        self.remove_network(&mut network).await?;

        let mut args = HashMap::new();

        // For some reason, `wpa_supplicant` really wants the SSID and PSK to be
        // strings, even if in theory they can be any byte array.

        let utf8_err = |_| NetCtlError::Other(ErrorCode::Invalid.into());

        let arg_ssid = core::str::from_utf8(ssid).map_err(utf8_err)?.into();
        args.insert("ssid", &arg_ssid);

        let arg_pass = core::str::from_utf8(pass).map_err(utf8_err)?.into();
        if !pass.is_empty() {
            args.insert("psk", &arg_pass);
        }

        let network_path = interface.add_network(args).await?;

        *network = Some(network_path.clone());

        interface.select_network(&network_path).await?;

        // First try to connect on the Wifi level

        let connected = self.wait(true);
        let timeout = Timer::after(Duration::from_secs(CONNECT_TIMEOUT_SECS));

        match select(connected, timeout).await {
            Either::First(_) => (),
            Either::Second(_) => {
                if let Err(e2) = self.remove_network(&mut network).await {
                    warn!(
                        "Failed to remove network after connection timeout: {:?}",
                        e2
                    );
                }
                return Err(NetCtlError::AuthFailure);
            }
        }

        // Then try to bring up the IP stack (e.g., via DHCP for IPv4 and SLAAC for IPv6)

        match self.ip_stack_ctl.connect().await {
            Ok(()) => Ok(()),
            Err(e) => {
                // If the IP stack connection failed, remove the network
                if let Err(e2) = self.remove_network(&mut network).await {
                    warn!(
                        "Failed to remove network after IP stack connection failure: {:?}",
                        e2
                    );
                }
                Err(e)
            }
        }
    }
}

impl<T> WirelessDiag for WpaSuppCtl<'_, T>
where
    T: IpStackCtl,
{
    fn connected(&self) -> Result<bool, Error> {
        Ok(self.wifi_conn_info.lock(|ssid_info| {
            Self::connected(ssid_info.borrow().as_ref())
                && self.ip_stack_ctl.is_connected().unwrap_or(false)
        }))
    }
}

impl<T> WifiDiag for WpaSuppCtl<'_, T>
where
    T: IpStackCtl,
{
    fn bssid(&self, f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>) -> Result<(), Error> {
        self.wifi_conn_info.lock(|wifi_conn_info| {
            let wifi_conn_info = wifi_conn_info.borrow();
            if let Some(wifi_conn_info) = wifi_conn_info.as_ref() {
                f(Some(&wifi_conn_info.bssid))
            } else {
                f(None)
            }
        })
    }

    fn security_type(&self) -> Result<Nullable<SecurityTypeEnum>, Error> {
        // TODO: Figure out how to get this
        Ok(Nullable::none())
    }

    fn wi_fi_version(&self) -> Result<Nullable<WiFiVersionEnum>, Error> {
        // TODO: Figure out how to get this
        Ok(Nullable::none())
    }

    fn channel_number(&self) -> Result<Nullable<u16>, Error> {
        Ok(self.wifi_conn_info.lock(|wifi_conn_info| {
            let wifi_conn_info = wifi_conn_info.borrow();
            if let Some(wifi_conn_info) = wifi_conn_info.as_ref() {
                Nullable::some(wifi_conn_info.channel)
            } else {
                Nullable::none()
            }
        }))
    }

    fn rssi(&self) -> Result<Nullable<i8>, Error> {
        Ok(self.wifi_conn_info.lock(|wifi_conn_info| {
            let wifi_conn_info = wifi_conn_info.borrow();
            if let Some(wifi_conn_info) = wifi_conn_info.as_ref() {
                Nullable::some(wifi_conn_info.rssi)
            } else {
                Nullable::none()
            }
        }))
    }
}

impl<T> NetChangeNotif for WpaSuppCtl<'_, T>
where
    T: IpStackCtl,
{
    async fn wait_changed(&self) {
        let wait_wifi = self.wait(false);
        let wait_ip = self.ip_stack_ctl.wait_changed();

        select(wait_wifi, wait_ip).await;
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

/// An owned variant of `NetworkScanInfo::Wifi`.
/// Used for caching the connected BSS so that it can be returned by the
/// non-async `WifiDiag` methods.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
struct WifiConnInfo {
    security: WiFiSecurityBitmap,
    ssid: Vec<u8>,
    bssid: Vec<u8>,
    band: WiFiBandEnum,
    channel: u16,
    rssi: i8,
}

impl WifiConnInfo {
    /// Create a new `WifiConnInfo` from the given `NetworkScanInfo::Wifi`.
    fn new(scan_info: &NetworkScanInfo) -> Self {
        let NetworkScanInfo::Wifi {
            security,
            ssid,
            bssid,
            channel,
            band,
            rssi,
        } = scan_info
        else {
            // Not possible, because `WpaSupp` only produces scan info of type `Wifi`
            unreachable!();
        };

        Self {
            security: *security,
            ssid: ssid.to_vec(),
            bssid: bssid.to_vec(),
            band: *band,
            channel: *channel,
            rssi: *rssi,
        }
    }
}

impl From<zbus::Error> for NetCtlError {
    fn from(value: zbus::Error) -> Self {
        NetCtlError::Other(value.into())
    }
}

// See https://github.com/project-chip/connectedhomeip/blob/cd5fec9ba9be0c39f3c11f67d57b18b6bb2b4289/src/platform/Linux/ConnectivityManagerImpl.cpp#L1937
fn band_and_channel(freq: u32) -> (WiFiBandEnum, u16) {
    let mut band = WiFiBandEnum::V2G4;

    let channel = if freq <= 931 {
        if freq >= 916 {
            ((freq - 916) * 2) - 1
        } else if freq >= 902 {
            (freq - 902) * 2
        } else if freq >= 863 {
            (freq - 863) * 2
        } else {
            1
        }
    } else if freq <= 2472 {
        (freq - 2412) / 5 + 1
    } else if freq == 2484 {
        14
    } else if (3600..=3700).contains(&freq) {
        // Note: There are not many devices supports this band, and this band contains rational frequency in MHz, need to figure out
        // the behavior of wpa_supplicant in this case.
        band = WiFiBandEnum::V3G65;
        0
    } else if (5035..=5945).contains(&freq) || freq == 5960 || freq == 5980 {
        band = WiFiBandEnum::V5G;
        (freq - 5000) / 5
    } else if freq >= 5955 {
        band = WiFiBandEnum::V6G;
        (freq - 5950) / 5
    } else if freq >= 58000 {
        band = WiFiBandEnum::V60G;

        // Note: Some channel has the same center frequency but different bandwidth. Should figure out wpa_supplicant's behavior in
        // this case. Also, wpa_supplicant's frequency property is uint16 infact.
        match freq {
            58_320 => 1,
            60_480 => 2,
            62_640 => 3,
            64_800 => 4,
            66_960 => 5,
            69_120 => 6,
            59_400 => 9,
            61_560 => 10,
            63_720 => 11,
            65_880 => 12,
            68_040 => 13,
            _ => 0,
        }
    } else {
        // Unknown channel
        0
    };

    (band, channel as u16)
}
