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

//! Wifi network controller implementation based on the NetworkManager D-Bus service.

// TODO: It is possible to get all Ipv4 and Ipv6 netifs via NetworkManager, so we can also implement
// the `NetifDiag` trait (with some caching, as it is non-async), thus getting rid of the `UnixNetifs` type
// when NM is used.

use core::cell::RefCell;

use std::collections::HashMap;

use embassy_futures::select::{select, select3, Either, Either3};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use embassy_time::{Duration, Timer};
use futures_lite::StreamExt;

use uuid::Uuid;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};
use zbus::Connection;

use crate::dm::clusters::net_comm::{
    NetCtl, NetCtlError, NetworkScanInfo, NetworkType, WiFiBandEnum, WiFiSecurityBitmap,
    WirelessCreds,
};
use crate::dm::clusters::wifi_diag::{SecurityTypeEnum, WiFiVersionEnum, WifiDiag, WirelessDiag};
use crate::dm::networks::NetChangeNotif;
use crate::error::{Error, ErrorCode};
use crate::tlv::Nullable;
use crate::transport::network::wifi::band::band_and_channel;
use crate::utils::sync::{blocking, IfMutex};
use crate::utils::zbus_proxies::nm::access_point::AccessPointProxy;
use crate::utils::zbus_proxies::nm::connection::ConnectionProxy;
use crate::utils::zbus_proxies::nm::device::wireless::WirelessProxy;
use crate::utils::zbus_proxies::nm::device::DeviceProxy;
use crate::utils::zbus_proxies::nm::network_manager::NetworkManagerProxy;
use crate::utils::zbus_proxies::nm::{NM80211ApSecurityFlags, NM80211Mode, NMDeviceState};

/// A `NetCtl`, `WirelessDiag`, `WifiDiag` and `NetChangeNotif` implementation based on the `NetworkManager` service.
///
/// Suitable for use with embedded Linux devices that do have the `NetworkManager` service running over D-Bus.
pub struct NetMgrCtl<'a> {
    connection: &'a Connection,
    ifname: &'a str,
    net_conn: IfMutex<NoopRawMutex, Option<OwnedObjectPath>>,
    wifi_conn_info: blocking::Mutex<NoopRawMutex, RefCell<Option<WifiConnInfo>>>,
}

impl<'a> NetMgrCtl<'a> {
    /// Create a new `NetMgrCtl` instance.
    ///
    /// # Arguments
    /// * `connection` - A reference to the D-Bus connection.
    /// * `interface_path` - The D-Bus object path of Wifi interface object.
    ///
    /// # Returns
    /// The new `NetMgrCtl` instance.
    pub const fn new(connection: &'a Connection, ifname: &'a str) -> Self {
        Self {
            connection,
            ifname,
            net_conn: IfMutex::new(None),
            wifi_conn_info: blocking::Mutex::new(RefCell::new(None)),
        }
    }

    /// Return a reference to the D-Bus connection.
    pub const fn connection(&self) -> &Connection {
        self.connection
    }

    /// Create a wpa-supplicant interface proxy for out interface name
    async fn mgr(&self) -> Result<NetworkManagerProxy<'a>, zbus::Error> {
        NetworkManagerProxy::new(self.connection).await
    }

    async fn device(&self) -> Result<OwnedObjectPath, zbus::Error> {
        self.mgr().await?.get_device_by_ip_iface(self.ifname).await
    }

    /// Wait for the interface state as follows:
    /// - If `for_connection` is true, wait until the interface is connected to a network.
    /// - If `for_connection` is false, wait until the interface state changes (e.g., connected, disconnected or other change).
    async fn wait(&self, for_connection: bool) -> Result<(), Error> {
        let device = self.device().await?;

        let interface = DeviceProxy::new(self.connection, &device).await?;
        let wifi = WirelessProxy::new(self.connection, &device).await?;

        let mut iface_state_changed = interface.receive_dev_state_changed().await;

        loop {
            let bss = wifi.active_access_point().await?;

            let (changed, connected) = if bss.len() > 1 {
                let connected = interface.dev_state().await? == NMDeviceState::Activated as _;

                self.network_scan_info(&bss, |info| {
                    let info = info.map(|info| WifiConnInfo::new(info, connected));

                    Ok(self.update_wifi_conn_info(info))
                })
                .await?
            } else {
                self.update_wifi_conn_info(None)
            };

            if for_connection && connected || !for_connection && changed {
                break Ok(());
            }

            iface_state_changed.next().await;
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
        wifi_conn_info.map(|info| info.connected).unwrap_or(false)
    }

    /// Remove our connection, if any.
    async fn remove_net_conn(&self, net_conn: &mut Option<OwnedObjectPath>) -> zbus::Result<()> {
        let interface = self.mgr().await?;

        if let Some(net_conn_path) = net_conn.clone() {
            if interface
                .deactivate_connection(&net_conn_path)
                .await
                .is_ok()
            {
                let net_conn_proxy = ConnectionProxy::new(self.connection, &net_conn_path).await?;
                net_conn_proxy.delete().await?;

                net_conn.take();
            }
        }

        Ok(())
    }

    /// Get the network scan information for a given BSS object path.
    async fn network_scan_info<F, R>(&self, bss: &ObjectPath<'_>, f: F) -> Result<R, Error>
    where
        F: FnOnce(Option<&NetworkScanInfo>) -> Result<R, Error>,
    {
        let bss_info = AccessPointProxy::new(self.connection, bss).await?;

        if bss_info.mode().await? == NM80211Mode::Infra as _ {
            let wpa = NM80211ApSecurityFlags::from_bits_truncate(bss_info.wpa_flags().await?);
            let rsn = NM80211ApSecurityFlags::from_bits_truncate(bss_info.rsn_flags().await?);

            let security = if wpa.is_empty() && rsn.is_empty() {
                WiFiSecurityBitmap::UNENCRYPTED
            } else {
                let mut security = WiFiSecurityBitmap::empty();

                if !wpa
                    .union(rsn)
                    .intersection(
                        NM80211ApSecurityFlags::PAIR_WEP40 | NM80211ApSecurityFlags::PAIR_WEP104,
                    )
                    .is_empty()
                {
                    security |= WiFiSecurityBitmap::WEP;
                }

                if wpa.contains(NM80211ApSecurityFlags::KEY_MGMT_PSK) {
                    security |= WiFiSecurityBitmap::WPA_PERSONAL;
                }

                if rsn.contains(NM80211ApSecurityFlags::KEY_MGMT_PSK) {
                    security |= WiFiSecurityBitmap::WPA_2_PERSONAL;
                }

                // TODO
                // if rsn_key_mgmt.contains(&"sae".to_string()) {
                //     security |= WiFiSecurityBitmap::WPA_3_PERSONAL
                // }

                security
            };

            // If we can't determine the band and channel we prefer to still report the network
            // even if with unknown band and channel.
            let (band, channel) =
                band_and_channel(bss_info.frequency().await?).unwrap_or((WiFiBandEnum::V2G4, 0));

            let bssid = {
                let bssid_str = bss_info.hw_address().await?;

                let result: Result<heapless::Vec<_, 8>, _> = bssid_str
                    .split(':')
                    .map(|s| u8::from_str_radix(s, 16))
                    .collect();

                result.map_err(|_| Error::from(ErrorCode::Invalid))?
            };

            let network_scan_info = NetworkScanInfo::Wifi {
                security,
                ssid: &bss_info.ssid().await?,
                bssid: &bssid,
                band,
                channel,
                rssi: bss_info
                    .strength()
                    .await?
                    .min(i8::MIN as _)
                    .max(i8::MAX as _) as i8,
            };

            f(Some(&network_scan_info))
        } else {
            // Skip ad-hoc networks, we are only interested in infrastructure ones
            f(None)
        }
    }
}

impl Drop for NetMgrCtl<'_> {
    fn drop(&mut self) {
        // Remove the network on drop
        let _ = futures_lite::future::block_on(async {
            let mut network = self.net_conn.lock().await;

            self.remove_net_conn(&mut network).await
        });
    }
}

impl NetCtl for NetMgrCtl<'_> {
    fn net_type(&self) -> NetworkType {
        NetworkType::Wifi
    }

    async fn scan<F>(&self, network: Option<&[u8]>, mut f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error>,
    {
        const SCAN_DONE_TIMEOUT_SEC: u64 = 3;

        let _guard = self.net_conn.lock().await;

        let mut args = HashMap::new();

        let active = Value::from("active");
        args.insert("Type", &active);

        let ssids = network.map(|network| vec![network.to_vec()].into());
        if ssids.is_some() {
            #[allow(clippy::unnecessary_unwrap)]
            args.insert("SSIDs", ssids.as_ref().unwrap());
        }

        let device_path = self.device().await?;

        let wifi = WirelessProxy::new(self.connection, &device_path).await?;

        let mut ap_added = wifi.receive_access_point_added().await?;
        let mut ap_removed = wifi.receive_access_point_added().await?;

        wifi.request_scan(args.clone()).await?;

        loop {
            // Wait for the scan to complete
            //
            // NOTE: It seems NetworkManager - unlike `wpa_supplicant` - does not provide a way to
            // to get a "Scan done" signal, so we just monitor the "access point added / removed"
            // signals and timeout if we don't see one incoming after a few seconds

            let ap_added = ap_added.next();
            let ap_removed = ap_removed.next();
            let timeout = Timer::after(Duration::from_secs(SCAN_DONE_TIMEOUT_SEC));

            if matches!(
                select3(ap_added, ap_removed, timeout).await,
                Either3::Third(_)
            ) {
                break;
            }
        }

        let bsss = wifi.access_points().await?;

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

        let mut net_conn = self.net_conn.lock().await;

        let WirelessCreds::Wifi { ssid, pass } = creds else {
            return Err(NetCtlError::Other(ErrorCode::InvalidAction.into()));
        };

        let mgr = self.mgr().await?;

        self.remove_net_conn(&mut net_conn).await?;

        let utf8_err = |_| NetCtlError::Other(ErrorCode::Invalid.into());

        let conn_uuid = Uuid::new_v4().hyphenated().to_string();

        let arg_conn_uuid = conn_uuid.as_str().into();
        let arg_conn_type = "802-11-wireless".into();
        let arg_security = "wpa-psk".into();
        let arg_ssid = (*ssid).into();
        // For some reason, `NetworkManager` wants the PSK to be a string
        let arg_pass = core::str::from_utf8(pass).map_err(utf8_err)?.into();
        let arg_ipv4_method = "auto".into();
        let arg_ipv6_method = "auto".into();

        let args: &[(_, &[_])] = &[
            (
                "connection",
                &[
                    ("id", &arg_conn_uuid),
                    ("uuid", &arg_conn_uuid),
                    ("type", &arg_conn_type),
                ],
            ),
            ("802-11-wireless", &[("ssid", &arg_ssid)]),
            (
                "802-11-wireless-security",
                if pass.is_empty() {
                    &[]
                } else {
                    &[("key-mgmt", &arg_security), ("psk", &arg_pass)]
                },
            ),
            ("ipv4", &[("method", &arg_ipv4_method)]),
            ("ipv6", &[("method", &arg_ipv6_method)]),
        ];

        let args = args
            .iter()
            .map(|(k, v)| (*k, (*v).iter().map(|(k, v)| (*k, *v)).collect()))
            .collect::<HashMap<&str, HashMap<&str, &Value<'_>>>>();

        let device_path = self.device().await?;
        let (_, net_conn_path) = mgr
            .add_and_activate_connection(
                args,
                &device_path,
                &OwnedObjectPath::try_from("/").unwrap(),
            )
            .await?;

        *net_conn = Some(net_conn_path.clone());

        let connected = self.wait(true);
        let timeout = Timer::after(Duration::from_secs(CONNECT_TIMEOUT_SECS));

        match select(connected, timeout).await {
            Either::First(_) => info!("Connected to Wifi network: {}", self.ifname),
            Either::Second(_) => {
                error!(
                    "Connection to Wifi network timed out: {}, assuming auth failure",
                    self.ifname
                );

                if let Err(e2) = self.remove_net_conn(&mut net_conn).await {
                    warn!(
                        "Failed to remove network after connection timeout: {:?}",
                        e2
                    );
                }
                return Err(NetCtlError::AuthFailure);
            }
        }

        Ok(())
    }
}

impl WirelessDiag for NetMgrCtl<'_> {
    fn connected(&self) -> Result<bool, Error> {
        Ok(self
            .wifi_conn_info
            .lock(|ssid_info| Self::connected(ssid_info.borrow().as_ref())))
    }
}

impl WifiDiag for NetMgrCtl<'_> {
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

impl NetChangeNotif for NetMgrCtl<'_> {
    async fn wait_changed(&self) {
        let _ = self.wait(false).await;
    }
}

/// An owned variant of `NetworkScanInfo::Wifi`.
/// Used for caching the connected BSS so that it can be returned by the
/// non-async `WifiDiag` methods.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
struct WifiConnInfo {
    connected: bool,
    security: WiFiSecurityBitmap,
    ssid: Vec<u8>,
    bssid: Vec<u8>,
    band: WiFiBandEnum,
    channel: u16,
    rssi: i8,
}

impl WifiConnInfo {
    /// Create a new `WifiConnInfo` from the given `NetworkScanInfo::Wifi`.
    fn new(scan_info: &NetworkScanInfo, connected: bool) -> Self {
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
            connected,
            security: *security,
            ssid: ssid.to_vec(),
            bssid: bssid.to_vec(),
            band: *band,
            channel: *channel,
            rssi: *rssi,
        }
    }
}
