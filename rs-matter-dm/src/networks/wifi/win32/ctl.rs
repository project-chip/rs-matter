/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

use core::cell::Cell;
use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use core::{ptr, slice};

use async_channel::{Receiver, Sender};

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BAD_PROFILE, ERROR_INVALID_DATA, ERROR_SUCCESS, HANDLE,
};
use windows::Win32::NetworkManagement::WiFi::{
    dot11_BSS_type_infrastructure, dot11_phy_type_dsss, dot11_phy_type_eht, dot11_phy_type_erp,
    dot11_phy_type_he, dot11_phy_type_hrdsss, dot11_phy_type_ht, dot11_phy_type_ofdm,
    dot11_phy_type_vht, wlan_connection_mode_temporary_profile, wlan_interface_state_connected,
    wlan_intf_opcode_channel_number, wlan_intf_opcode_current_connection,
    wlan_intf_opcode_interface_state, wlan_intf_opcode_rssi, wlan_intf_opcode_statistics,
    wlan_notification_acm_connection_complete, wlan_notification_acm_disconnected,
    wlan_notification_acm_interface_arrival, wlan_notification_acm_interface_removal,
    wlan_notification_acm_scan_complete, wlan_notification_acm_scan_fail, WlanCloseHandle,
    WlanConnect, WlanDisconnect, WlanEnumInterfaces, WlanFreeMemory, WlanGetAvailableNetworkList,
    WlanGetInterfaceCapability, WlanGetNetworkBssList, WlanOpenHandle, WlanQueryInterface,
    WlanRegisterNotification, WlanScan, DOT11_AUTH_ALGO_80211_OPEN,
    DOT11_AUTH_ALGO_80211_SHARED_KEY, DOT11_AUTH_ALGO_RSNA, DOT11_AUTH_ALGO_RSNA_PSK,
    DOT11_AUTH_ALGO_WPA, DOT11_AUTH_ALGO_WPA3_ENT, DOT11_AUTH_ALGO_WPA3_ENT_192,
    DOT11_AUTH_ALGO_WPA3_SAE, DOT11_AUTH_ALGO_WPA_PSK, DOT11_PHY_TYPE, DOT11_SSID,
    L2_NOTIFICATION_DATA, WLAN_API_VERSION_2_0, WLAN_AVAILABLE_NETWORK,
    WLAN_AVAILABLE_NETWORK_LIST, WLAN_BSS_ENTRY, WLAN_BSS_LIST, WLAN_CONNECTION_ATTRIBUTES,
    WLAN_CONNECTION_HIDDEN_NETWORK, WLAN_CONNECTION_NOTIFICATION_DATA, WLAN_CONNECTION_PARAMETERS,
    WLAN_INTERFACE_CAPABILITY, WLAN_INTERFACE_INFO, WLAN_INTERFACE_INFO_LIST, WLAN_INTERFACE_STATE,
    WLAN_INTF_OPCODE, WLAN_MAC_FRAME_STATISTICS, WLAN_NOTIFICATION_SOURCE_ACM,
    WLAN_REASON_CODE_MSMSEC_BASE, WLAN_REASON_CODE_MSMSEC_END,
    WLAN_REASON_CODE_NETWORK_NOT_AVAILABLE, WLAN_REASON_CODE_NOT_VISIBLE, WLAN_REASON_CODE_SUCCESS,
    WLAN_SECURITY_ATTRIBUTES, WLAN_STATISTICS,
};

use crate::dm::clusters::net_comm::{
    NetCtl, NetCtlError, NetworkScanInfo, NetworkType, WiFiBandEnum, WirelessCreds,
};
use crate::dm::clusters::wifi_diag::{SecurityTypeEnum, WiFiVersionEnum, WifiDiag, WirelessDiag};
use crate::dm::networks::wifi::band::band_and_channel;
use crate::dm::networks::{poll_netifs_changed, NetChangeNotif};
use crate::error::{Error, ErrorCode};
use crate::tlv::Nullable;
use crate::utils::futures::{select, Either};
use crate::utils::sync::{blocking, IfMultiMutex, MaybeSend};
use crate::utils::timers::{Duration, Timer};

use super::{is_raw_psk, profile_xml, security, Auth};

/// How long to wait for a scan to complete. Windows asks the drivers to
/// complete one within 4 seconds.
const SCAN_TIMEOUT_SECS: u64 = 10;

/// How long to wait for a connection, shared by the authentications tried.
const CONNECT_TIMEOUT_SECS: u64 = 30;

/// Notifications waiting for the operation that registered for them; more are
/// dropped.
const EVENTS_QUEUED: usize = 16;

/// The ACM notifications used here.
const SCAN_COMPLETE: u32 = wlan_notification_acm_scan_complete.0 as u32;
const SCAN_FAIL: u32 = wlan_notification_acm_scan_fail.0 as u32;
const CONNECTION_COMPLETE: u32 = wlan_notification_acm_connection_complete.0 as u32;
const DISCONNECTED: u32 = wlan_notification_acm_disconnected.0 as u32;
const INTERFACE_ARRIVAL: u32 = wlan_notification_acm_interface_arrival.0 as u32;
const INTERFACE_REMOVAL: u32 = wlan_notification_acm_interface_removal.0 as u32;

/// The privacy bit of the capability information of a BSS.
const CAPABILITY_PRIVACY: u16 = 0x0010;

/// A `NetCtl`, `WirelessDiag`, `WifiDiag` and `NetChangeNotif` implementation
/// over the Native Wifi API of Windows.
pub struct Win32WifiCtl {
    client: blocking::Mutex<Client>,
    interface: GUID,
    /// Serializes the scans and the connects
    op: IfMultiMutex<()>,
    /// What `connected` returned last, for `wait_changed` to compare with
    connected: blocking::Mutex<Cell<bool>>,
    /// The packet counts at the last `reset_counts`
    counts_base: blocking::Mutex<Cell<Counts>>,
}

impl Win32WifiCtl {
    /// Create an instance for the first Wi-Fi interface of the system.
    pub fn new() -> Result<Self, Error> {
        Self::open(None)
    }

    /// Create an instance for the Wi-Fi interface with GUID `interface`.
    pub fn with_interface(interface: u128) -> Result<Self, Error> {
        Self::open(Some(GUID::from_u128(interface)))
    }

    /// Return the GUID of the Wi-Fi interface.
    pub fn interface(&self) -> u128 {
        self.interface.to_u128()
    }

    fn open(interface: Option<GUID>) -> Result<Self, Error> {
        let client = Client::open()?;
        let interface = client.interface(interface)?;

        Ok(Self {
            client: blocking::Mutex::new(client),
            interface,
            op: IfMultiMutex::new(()),
            connected: blocking::Mutex::new(Cell::new(false)),
            counts_base: blocking::Mutex::new(Cell::new(Counts::default())),
        })
    }

    /// Connect with one authentication, and wait for the outcome at most
    /// `timeout_secs`.
    async fn connect_with(
        &self,
        notifications: &Notifications,
        ssid: &DOT11_SSID,
        pass: &[u8],
        auth: Auth,
        hidden: bool,
        timeout_secs: u64,
    ) -> Result<(), NetCtlError> {
        let Some(profile) = profile_xml(ssid_bytes(ssid), pass, auth) else {
            warn!("Wi-Fi: the key cannot be put in a profile");
            return Err(NetCtlError::Other(ErrorCode::Invalid.into()));
        };

        let profile = profile
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect::<Vec<_>>();

        let err = {
            let mut ssid = *ssid;
            let params = WLAN_CONNECTION_PARAMETERS {
                wlanConnectionMode: wlan_connection_mode_temporary_profile,
                strProfile: PCWSTR(profile.as_ptr()),
                pDot11Ssid: &mut ssid,
                pDesiredBssidList: ptr::null_mut(),
                dot11BssType: dot11_BSS_type_infrastructure,
                dwFlags: if hidden {
                    WLAN_CONNECTION_HIDDEN_NETWORK
                } else {
                    0
                },
            };

            notifications.with_handle(|handle| unsafe {
                WlanConnect(handle, &self.interface, &params, None)
            })
        };

        if err == ERROR_BAD_PROFILE.0 {
            warn!("Wi-Fi: Windows does not take a {:?} profile", auth);
            return Err(NetCtlError::UnsupportedSecurity);
        }

        check(err, "connect")?;

        let completed = async {
            loop {
                let event = notifications.next().await;

                if event.code == CONNECTION_COMPLETE
                    && event
                        .ssid
                        .is_some_and(|event_ssid| ssid_bytes(&event_ssid) == ssid_bytes(ssid))
                {
                    break event.reason;
                }
            }
        };

        match select(completed, Timer::after(Duration::from_secs(timeout_secs))).await {
            Either::First(WLAN_REASON_CODE_SUCCESS) => {
                info!("Wi-Fi: connected, with {:?}", auth);
                Ok(())
            }
            Either::First(reason) => {
                warn!(
                    "Wi-Fi: connecting with {:?} failed, reason code {}",
                    auth, reason
                );
                Err(connect_error(reason))
            }
            Either::Second(_) => {
                warn!("Wi-Fi: connecting with {:?} timed out", auth);

                notifications
                    .with_handle(|handle| unsafe { WlanDisconnect(handle, &self.interface, None) });

                Err(NetCtlError::OtherConnectionFailure)
            }
        }
    }

    /// Whether the interface is connected now.
    fn query_connected(&self) -> bool {
        self.query::<WLAN_INTERFACE_STATE>(wlan_intf_opcode_interface_state)
            .is_some_and(|state| state == wlan_interface_state_connected)
    }

    /// The attributes of the current connection.
    fn connection(&self) -> Option<WLAN_CONNECTION_ATTRIBUTES> {
        self.query::<WLAN_CONNECTION_ATTRIBUTES>(wlan_intf_opcode_current_connection)
            .filter(|connection| connection.isState == wlan_interface_state_connected)
    }

    /// The packet counts of the interface.
    fn counts(&self) -> Option<Counts> {
        self.client.lock(|client| {
            let (data, size) = client
                .query_raw(&self.interface, wlan_intf_opcode_statistics)
                .ok()?;

            // The MAC counters, before the counters of each PHY
            if size < offset_of!(WLAN_STATISTICS, dwNumberOfPhys) {
                return None;
            }

            let stats = data.0.cast::<WLAN_STATISTICS>();
            let (unicast, multicast) = unsafe {
                (
                    ptr::addr_of!((*stats).MacUcastCounters).read_unaligned(),
                    ptr::addr_of!((*stats).MacMcastCounters).read_unaligned(),
                )
            };

            Some(Counts::new(&unicast, &multicast))
        })
    }

    /// One of the packet counts, since the last `reset_counts`.
    fn count(&self, pick: fn(&Counts) -> u64) -> Nullable<u32> {
        Nullable::new(self.counts().map(|now| {
            let base = pick(&self.counts_base.lock(Cell::get));
            let now = pick(&now);

            // A count lower than at the reset has started over
            now.checked_sub(base).unwrap_or(now) as u32
        }))
    }

    fn query<T: Copy>(&self, opcode: WLAN_INTF_OPCODE) -> Option<T> {
        self.client
            .lock(|client| client.query(&self.interface, opcode))
            .ok()
    }
}

impl NetCtl for Win32WifiCtl {
    fn net_type(&self) -> NetworkType {
        NetworkType::Wifi
    }

    fn supported_wifi_bands<F>(&self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(WiFiBandEnum) -> Result<(), Error>,
    {
        let capability = self
            .client
            .lock(|client| client.capability(&self.interface));

        let phys = capability
            .as_ref()
            .map(|capability| {
                let count = (capability.dwNumberOfSupportedPhys as usize)
                    .min(capability.dot11PhyTypes.len());

                &capability.dot11PhyTypes[..count]
            })
            .unwrap_or(&[]);

        let has = |types: &[DOT11_PHY_TYPE]| phys.iter().any(|phy| types.contains(phy));

        // Without the capabilities, only 2.4 GHz, as by default
        if phys.is_empty()
            || has(&[
                dot11_phy_type_dsss,
                dot11_phy_type_hrdsss,
                dot11_phy_type_erp,
                dot11_phy_type_ht,
                dot11_phy_type_he,
                dot11_phy_type_eht,
            ])
        {
            f(WiFiBandEnum::V2G4)?;
        }

        if has(&[dot11_phy_type_ofdm, dot11_phy_type_vht]) {
            f(WiFiBandEnum::V5G)?;
        }

        Ok(())
    }

    async fn scan<F>(&self, network: Option<&[u8]>, mut f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error> + MaybeSend,
    {
        let _guard = self.op.lock().await;

        let ssid = network
            .map(|network| dot11_ssid(network).ok_or(NetCtlError::NetworkNotFound))
            .transpose()?;

        let notifications = Notifications::new(self.interface)?;

        check(
            notifications.with_handle(|handle| unsafe {
                WlanScan(
                    handle,
                    &self.interface,
                    ssid.as_ref().map(|ssid| ssid as *const _),
                    None,
                    None,
                )
            }),
            "scan",
        )?;

        let done = async {
            loop {
                let event = notifications.next().await;

                match event.code {
                    SCAN_COMPLETE => break Ok(()),
                    SCAN_FAIL => break Err(event.reason),
                    _ => (),
                }
            }
        };

        match select(done, Timer::after(Duration::from_secs(SCAN_TIMEOUT_SECS))).await {
            Either::First(Ok(())) => (),
            Either::First(Err(reason)) => warn!(
                "Wi-Fi: the scan failed, reason code {}; reporting the networks seen before",
                reason
            ),
            Either::Second(_) => {
                warn!("Wi-Fi: the scan timed out; reporting the networks seen so far")
            }
        }

        self.client.lock(|client| {
            client.bss_entries(&self.interface, |entry, ies| {
                let entry_ssid = ssid_bytes(&entry.dot11Ssid);

                if network.is_some_and(|network| network != entry_ssid) {
                    return Ok(());
                }

                // Report a network also when its band and channel are not known
                let (band, channel) = band_and_channel(entry.ulChCenterFrequency / 1000)
                    .unwrap_or((WiFiBandEnum::V2G4, 0));

                f(&NetworkScanInfo::Wifi {
                    security: security(
                        entry.usCapabilityInformation & CAPABILITY_PRIVACY != 0,
                        ies,
                    ),
                    ssid: entry_ssid,
                    bssid: &entry.dot11Bssid,
                    channel,
                    band,
                    rssi: rssi(entry.lRssi),
                })
            })
        })?;

        Ok(())
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        const OPEN: &[Auth] = &[Auth::Open];
        const PSK: &[Auth] = &[Auth::Wpa2Psk];
        const PSK_OR_SAE: &[Auth] = &[Auth::Wpa2Psk, Auth::Wpa3Sae];

        let WirelessCreds::Wifi { ssid, pass } = creds else {
            return Err(NetCtlError::Other(ErrorCode::InvalidAction.into()));
        };

        let Some(ssid) = dot11_ssid(ssid) else {
            return Err(NetCtlError::Other(ErrorCode::Invalid.into()));
        };

        let _guard = self.op.lock().await;

        let notifications = Notifications::new(self.interface)?;

        let seen = self
            .client
            .lock(|client| client.seen(&self.interface, &ssid));

        // A network Windows does not see may be hidden, or Windows may not show
        // the networks without the location permission. Then try WPA2 and WPA3.
        let (auths, hidden) = match &seen {
            Seen::Auth(auth) => (slice::from_ref(auth), false),
            Seen::Unsupported => {
                warn!("Wi-Fi: the security of the network is not supported");
                return Err(NetCtlError::UnsupportedSecurity);
            }
            Seen::Unseen if pass.is_empty() => (OPEN, true),
            Seen::Unseen if core::str::from_utf8(pass).is_ok_and(is_raw_psk) => (PSK, true),
            Seen::Unseen => (PSK_OR_SAE, true),
        };

        if pass.is_empty() && auths != OPEN {
            return Err(NetCtlError::AuthFailure);
        }

        let timeout_secs = CONNECT_TIMEOUT_SECS / auths.len() as u64;
        let mut failure = None;

        for auth in auths {
            match self
                .connect_with(&notifications, &ssid, pass, *auth, hidden, timeout_secs)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e @ (NetCtlError::NetworkNotFound | NetCtlError::Other(_))) => return Err(e),
                Err(e) => {
                    failure.get_or_insert(e);
                }
            }
        }

        Err(failure.unwrap_or(NetCtlError::OtherConnectionFailure))
    }
}

impl WirelessDiag for Win32WifiCtl {
    fn connected(&self) -> Result<bool, Error> {
        let connected = self.query_connected();

        self.connected.lock(|cell| cell.set(connected));

        Ok(connected)
    }
}

impl WifiDiag for Win32WifiCtl {
    fn bssid(&self, f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>) -> Result<(), Error> {
        match self.connection() {
            Some(connection) => f(Some(&connection.wlanAssociationAttributes.dot11Bssid)),
            None => f(None),
        }
    }

    fn security_type(&self) -> Result<Nullable<SecurityTypeEnum>, Error> {
        Ok(Nullable::new(self.connection().map(|connection| {
            security_type(&connection.wlanSecurityAttributes)
        })))
    }

    fn wi_fi_version(&self) -> Result<Nullable<WiFiVersionEnum>, Error> {
        Ok(Nullable::new(self.connection().and_then(|connection| {
            wifi_version(connection.wlanAssociationAttributes.dot11PhyType)
        })))
    }

    fn channel_number(&self) -> Result<Nullable<u16>, Error> {
        Ok(Nullable::new(
            self.query::<u32>(wlan_intf_opcode_channel_number)
                .and_then(|channel| u16::try_from(channel).ok()),
        ))
    }

    fn rssi(&self) -> Result<Nullable<i8>, Error> {
        Ok(Nullable::new(
            self.query::<i32>(wlan_intf_opcode_rssi).map(rssi),
        ))
    }

    fn packet_multicast_rx_count(&self) -> Result<Nullable<u32>, Error> {
        Ok(self.count(|counts| counts.multicast_rx))
    }

    fn packet_multicast_tx_count(&self) -> Result<Nullable<u32>, Error> {
        Ok(self.count(|counts| counts.multicast_tx))
    }

    fn packet_unicast_rx_count(&self) -> Result<Nullable<u32>, Error> {
        Ok(self.count(|counts| counts.unicast_rx))
    }

    fn packet_unicast_tx_count(&self) -> Result<Nullable<u32>, Error> {
        Ok(self.count(|counts| counts.unicast_tx))
    }

    fn current_max_rate(&self) -> Result<Nullable<u64>, Error> {
        // In kbit/s
        Ok(Nullable::new(self.connection().map(|connection| {
            connection.wlanAssociationAttributes.ulTxRate as u64 * 1000
        })))
    }

    fn reset_counts(&self) -> Result<(), Error> {
        if let Some(counts) = self.counts() {
            self.counts_base.lock(|base| base.set(counts));
        }

        Ok(())
    }
}

impl NetChangeNotif for Win32WifiCtl {
    async fn wait_changed(&self) {
        let notifications = match Notifications::new(self.interface) {
            Ok(notifications) => notifications,
            Err(_) => {
                poll_netifs_changed().await;
                return;
            }
        };

        // Registered before looking, so that no change is missed
        let connected = self.query_connected();
        if self.connected.lock(|cell| cell.get()) != connected {
            return;
        }

        loop {
            let event = notifications.next().await;

            if matches!(
                event.code,
                CONNECTION_COMPLETE | DISCONNECTED | INTERFACE_ARRIVAL | INTERFACE_REMOVAL
            ) {
                break;
            }
        }
    }
}

/// A Native Wifi client handle, closed on drop.
struct Client(HANDLE);

// The handle is not tied to the thread that opened it.
unsafe impl Send for Client {}

impl Client {
    fn open() -> Result<Self, Error> {
        let mut version = 0;
        let mut handle = HANDLE(ptr::null_mut());

        check(
            unsafe { WlanOpenHandle(WLAN_API_VERSION_2_0, None, &mut version, &mut handle) },
            "open a client handle",
        )?;

        Ok(Self(handle))
    }

    /// The interface with GUID `wanted`, or the first one if `None`.
    fn interface(&self, wanted: Option<GUID>) -> Result<GUID, Error> {
        let mut list = ptr::null_mut();
        let err = unsafe { WlanEnumInterfaces(self.0, None, &mut list) };
        let list = WlanMem::<WLAN_INTERFACE_INFO_LIST>(list);

        check(err, "list the Wi-Fi interfaces")?;

        let interfaces = unsafe {
            items(
                ptr::addr_of!((*list.0).InterfaceInfo).cast::<WLAN_INTERFACE_INFO>(),
                (*list.0).dwNumberOfItems,
            )
        };

        let Some(interface) = interfaces
            .iter()
            .find(|interface| wanted.is_none_or(|wanted| interface.InterfaceGuid == wanted))
        else {
            warn!("Wi-Fi: no such interface");
            return Err(ErrorCode::NoNetworkInterface.into());
        };

        let description = interface.strInterfaceDescription;
        let len = description
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(description.len());

        info!(
            "Wi-Fi: using interface {}",
            String::from_utf16_lossy(&description[..len]).as_str()
        );

        Ok(interface.InterfaceGuid)
    }

    /// The value of `opcode` for `interface`.
    fn query<T: Copy>(&self, interface: &GUID, opcode: WLAN_INTF_OPCODE) -> Result<T, u32> {
        let (data, size) = self.query_raw(interface, opcode)?;

        if size < size_of::<T>() {
            return Err(ERROR_INVALID_DATA.0);
        }

        Ok(unsafe { data.0.cast::<T>().read_unaligned() })
    }

    /// The value of `opcode` for `interface`, and its size.
    fn query_raw(
        &self,
        interface: &GUID,
        opcode: WLAN_INTF_OPCODE,
    ) -> Result<(WlanMem<c_void>, usize), u32> {
        let mut size = 0;
        let mut data = ptr::null_mut();
        let err = unsafe {
            WlanQueryInterface(self.0, interface, opcode, None, &mut size, &mut data, None)
        };
        let data = WlanMem(data);

        if err != ERROR_SUCCESS.0 {
            return Err(err);
        }

        if data.0.is_null() {
            return Err(ERROR_INVALID_DATA.0);
        }

        Ok((data, size as usize))
    }

    fn capability(&self, interface: &GUID) -> Option<WLAN_INTERFACE_CAPABILITY> {
        let mut capability = ptr::null_mut();
        let err = unsafe { WlanGetInterfaceCapability(self.0, interface, None, &mut capability) };
        let capability = WlanMem(capability);

        (err == ERROR_SUCCESS.0 && !capability.0.is_null())
            .then(|| unsafe { capability.0.read_unaligned() })
    }

    /// Call `f` with each BSS of the scan results, and its information elements.
    fn bss_entries<F>(&self, interface: &GUID, mut f: F) -> Result<(), Error>
    where
        F: FnMut(&WLAN_BSS_ENTRY, &[u8]) -> Result<(), Error>,
    {
        let mut list = ptr::null_mut();
        let err = unsafe {
            WlanGetNetworkBssList(
                self.0,
                interface,
                None,
                dot11_BSS_type_infrastructure,
                false,
                None,
                &mut list,
            )
        };
        let list = WlanMem::<WLAN_BSS_LIST>(list);

        check(err, "read the scan results")?;

        let (total, entries) = unsafe {
            (
                (*list.0).dwTotalSize as usize,
                items(
                    ptr::addr_of!((*list.0).wlanBssEntries).cast::<WLAN_BSS_ENTRY>(),
                    (*list.0).dwNumberOfItems,
                ),
            )
        };

        for entry in entries {
            // The elements are after the entry, at an offset from it
            let start = (entry as *const WLAN_BSS_ENTRY as usize - list.0 as usize)
                + entry.ulIeOffset as usize;
            let len = entry.ulIeSize as usize;

            let ies = if start + len <= total {
                unsafe { slice::from_raw_parts(list.0.cast::<u8>().add(start), len) }
            } else {
                &[]
            };

            f(entry, ies)?;
        }

        Ok(())
    }

    /// How network `ssid` authenticates, from the networks Windows sees.
    fn seen(&self, interface: &GUID, ssid: &DOT11_SSID) -> Seen {
        let mut list = ptr::null_mut();
        let err = unsafe { WlanGetAvailableNetworkList(self.0, interface, 0, None, &mut list) };
        let list = WlanMem::<WLAN_AVAILABLE_NETWORK_LIST>(list);

        if err != ERROR_SUCCESS.0 {
            debug!("Wi-Fi: cannot list the networks: error {}", err);
            return Seen::Unseen;
        }

        let networks = unsafe {
            items(
                ptr::addr_of!((*list.0).Network).cast::<WLAN_AVAILABLE_NETWORK>(),
                (*list.0).dwNumberOfItems,
            )
        };

        let Some(network) = networks.iter().find(|network| {
            network.dot11BssType == dot11_BSS_type_infrastructure
                && ssid_bytes(&network.dot11Ssid) == ssid_bytes(ssid)
        }) else {
            return Seen::Unseen;
        };

        if !network.bSecurityEnabled.as_bool() {
            return Seen::Auth(Auth::Open);
        }

        match network.dot11DefaultAuthAlgorithm {
            DOT11_AUTH_ALGO_RSNA_PSK => Seen::Auth(Auth::Wpa2Psk),
            DOT11_AUTH_ALGO_WPA3_SAE => Seen::Auth(Auth::Wpa3Sae),
            DOT11_AUTH_ALGO_WPA_PSK => Seen::Auth(Auth::WpaPsk),
            _ => Seen::Unsupported,
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // Also unregisters the notifications, after a callback that is running
        unsafe { WlanCloseHandle(self.0, None) };
    }
}

/// Memory allocated by Native Wifi, freed on drop.
struct WlanMem<T>(*mut T);

impl<T> Drop for WlanMem<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WlanFreeMemory(self.0 as *const c_void) };
        }
    }
}

/// A client handle receiving the ACM notifications of one interface, from
/// its creation until dropped.
struct Notifications {
    // Struct fields are dropped in declaration order, so closing the handle,
    // which waits for a running callback, comes before dropping the sender.
    // Keep this field first.
    client: blocking::Mutex<Client>,
    _sender: Box<Sender<Event>>,
    events: Receiver<Event>,
    interface: GUID,
}

impl Notifications {
    fn new(interface: GUID) -> Result<Self, Error> {
        let client = Client::open()?;
        let (sender, events) = async_channel::bounded(EVENTS_QUEUED);
        let sender = Box::new(sender);

        check(
            unsafe {
                WlanRegisterNotification(
                    client.0,
                    WLAN_NOTIFICATION_SOURCE_ACM,
                    true,
                    Some(on_notification),
                    Some(&*sender as *const Sender<Event> as *const c_void),
                    None,
                    None,
                )
            },
            "register for notifications",
        )?;

        Ok(Self {
            client: blocking::Mutex::new(client),
            _sender: sender,
            events,
            interface,
        })
    }

    /// Call `f` with the client handle.
    fn with_handle<R>(&self, f: impl FnOnce(HANDLE) -> R) -> R {
        self.client.lock(|client| f(client.0))
    }

    /// The next notification of the interface.
    async fn next(&self) -> Event {
        loop {
            // The sender lives as long as `self`
            if let Ok(event) = self.events.recv().await {
                if event.interface == self.interface {
                    break event;
                }
            }
        }
    }
}

/// An ACM notification: its code, and for a connection, its network and
/// reason code.
#[derive(Clone, Copy)]
struct Event {
    interface: GUID,
    code: u32,
    reason: u32,
    ssid: Option<DOT11_SSID>,
}

/// How a network authenticates, from the networks Windows sees.
enum Seen {
    Auth(Auth),
    Unsupported,
    Unseen,
}

/// The packet counts of the interface.
#[derive(Clone, Copy, Default)]
struct Counts {
    unicast_rx: u64,
    unicast_tx: u64,
    multicast_rx: u64,
    multicast_tx: u64,
}

impl Counts {
    fn new(unicast: &WLAN_MAC_FRAME_STATISTICS, multicast: &WLAN_MAC_FRAME_STATISTICS) -> Self {
        Self {
            unicast_rx: unicast.ullReceivedFrameCount,
            unicast_tx: unicast.ullTransmittedFrameCount,
            multicast_rx: multicast.ullReceivedFrameCount,
            multicast_tx: multicast.ullTransmittedFrameCount,
        }
    }
}

/// Pass the ACM notifications on to the `Sender<Event>` of `context`.
///
/// Native Wifi calls this on its own threads.
unsafe extern "system" fn on_notification(data: *mut L2_NOTIFICATION_DATA, context: *mut c_void) {
    let (Some(data), Some(sender)) = (unsafe { data.as_ref() }, unsafe {
        context.cast::<Sender<Event>>().as_ref()
    }) else {
        return;
    };

    if data.NotificationSource != WLAN_NOTIFICATION_SOURCE_ACM {
        return;
    }

    let mut event = Event {
        interface: data.InterfaceGuid,
        code: data.NotificationCode,
        reason: WLAN_REASON_CODE_SUCCESS,
        ssid: None,
    };

    let size = data.dwDataSize as usize;

    if !data.pData.is_null() {
        if event.code == CONNECTION_COMPLETE
            && size >= offset_of!(WLAN_CONNECTION_NOTIFICATION_DATA, dwFlags)
        {
            let connection = data.pData.cast::<WLAN_CONNECTION_NOTIFICATION_DATA>();

            unsafe {
                event.reason = ptr::addr_of!((*connection).wlanReasonCode).read_unaligned();
                event.ssid = Some(ptr::addr_of!((*connection).dot11Ssid).read_unaligned());
            }
        } else if event.code == SCAN_FAIL && size >= size_of::<u32>() {
            event.reason = unsafe { data.pData.cast::<u32>().read_unaligned() };
        }
    }

    // A full queue drops the notification
    let _ = sender.try_send(event);
}

/// The `count` items of a variable-length array allocated by Native Wifi.
///
/// # Safety
/// `first` must point to `count` items, which outlive `'a`.
unsafe fn items<'a, T>(first: *const T, count: u32) -> &'a [T] {
    if first.is_null() || count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(first, count as usize) }
    }
}

/// Fail, logging what failed, unless `err` is `ERROR_SUCCESS`.
fn check(err: u32, what: &str) -> Result<(), Error> {
    if err == ERROR_SUCCESS.0 {
        return Ok(());
    }

    if err == ERROR_ACCESS_DENIED.0 {
        warn!(
            "Wi-Fi: cannot {}: access denied; Windows 11 needs desktop apps to be allowed the location",
            what
        );
    } else {
        warn!("Wi-Fi: cannot {}: error {}", what, err);
    }

    Err(ErrorCode::NoNetworkInterface.into())
}

fn connect_error(reason: u32) -> NetCtlError {
    match reason {
        WLAN_REASON_CODE_NETWORK_NOT_AVAILABLE | WLAN_REASON_CODE_NOT_VISIBLE => {
            NetCtlError::NetworkNotFound
        }
        WLAN_REASON_CODE_MSMSEC_BASE..=WLAN_REASON_CODE_MSMSEC_END => NetCtlError::AuthFailure,
        _ => NetCtlError::OtherConnectionFailure,
    }
}

fn security_type(security: &WLAN_SECURITY_ATTRIBUTES) -> SecurityTypeEnum {
    if !security.bSecurityEnabled.as_bool() {
        return SecurityTypeEnum::None;
    }

    match security.dot11AuthAlgorithm {
        // Open or shared key, with encryption
        DOT11_AUTH_ALGO_80211_OPEN | DOT11_AUTH_ALGO_80211_SHARED_KEY => SecurityTypeEnum::WEP,
        DOT11_AUTH_ALGO_WPA | DOT11_AUTH_ALGO_WPA_PSK => SecurityTypeEnum::WPA,
        DOT11_AUTH_ALGO_RSNA | DOT11_AUTH_ALGO_RSNA_PSK => SecurityTypeEnum::WPA2,
        DOT11_AUTH_ALGO_WPA3_SAE | DOT11_AUTH_ALGO_WPA3_ENT | DOT11_AUTH_ALGO_WPA3_ENT_192 => {
            SecurityTypeEnum::WPA3
        }
        _ => SecurityTypeEnum::Unspecified,
    }
}

/// The Wi-Fi version of PHY type `phy`; none for 802.11be, which the cluster
/// has no value for.
fn wifi_version(phy: DOT11_PHY_TYPE) -> Option<WiFiVersionEnum> {
    const VERSIONS: &[(DOT11_PHY_TYPE, WiFiVersionEnum)] = &[
        (dot11_phy_type_ofdm, WiFiVersionEnum::A),
        (dot11_phy_type_dsss, WiFiVersionEnum::B),
        (dot11_phy_type_hrdsss, WiFiVersionEnum::B),
        (dot11_phy_type_erp, WiFiVersionEnum::G),
        (dot11_phy_type_ht, WiFiVersionEnum::N),
        (dot11_phy_type_vht, WiFiVersionEnum::Ac),
        (dot11_phy_type_he, WiFiVersionEnum::Ax),
    ];

    VERSIONS
        .iter()
        .find(|(version_phy, _)| *version_phy == phy)
        .map(|(_, version)| *version)
}

fn dot11_ssid(ssid: &[u8]) -> Option<DOT11_SSID> {
    let mut dot11 = DOT11_SSID {
        uSSIDLength: ssid.len() as u32,
        ucSSID: [0; 32],
    };

    dot11.ucSSID.get_mut(..ssid.len())?.copy_from_slice(ssid);

    Some(dot11)
}

fn ssid_bytes(ssid: &DOT11_SSID) -> &[u8] {
    &ssid.ucSSID[..(ssid.uSSIDLength as usize).min(ssid.ucSSID.len())]
}

fn rssi(dbm: i32) -> i8 {
    dbm.clamp(i8::MIN as i32, i8::MAX as i32) as i8
}
