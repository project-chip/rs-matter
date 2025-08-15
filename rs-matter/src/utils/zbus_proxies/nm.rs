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

//! zbus proxies for NetworkManager.
//!
//! All proxy traits are either generated using introspection (i.e. `zbus-xmlgen system org.freedesktop.NetworkManager /org/freedesktop/NetworkManager`)
//! or manually by consulting the NetworkManager D-Bus interface definitions
//! as documented here: https://networkmanager.dev/docs/api/latest/spec.html circa 2025-07-15

use crate::utils::bitflags::bitflags;

pub mod access_point;
pub mod active;
pub mod agent_manager;
pub mod checkpoint;
pub mod connection;
pub mod device;
pub mod dhcp4config;
pub mod dhcp6config;
pub mod dns_manager;
pub mod ip4config;
pub mod ip6config;
pub mod network_manager;
pub mod ppp;
pub mod settings;
pub mod vpn_connection;
pub mod wifi_p2ppeer;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum NMDeviceState {
    /// the device's state is unknown
    Unknown = 0,
    /// the device is recognized, but not managed by NetworkManager
    Unmanaged = 10,
    /// the device is managed by NetworkManager, but is not available for use.
    /// Reasons may include the wireless switched off, missing firmware, no ethernet carrier,
    /// missing supplicant or modem manager, etc.
    Unavailable = 20,
    /// the device can be activated, but is currently idle and not connected to a network.
    Disconnected = 30,
    /// the device is preparing the connection to the network.
    /// This may include operations like changing the MAC address, setting physical link properties,
    /// and anything else required to connect to the requested network.
    Prepare = 40,
    /// the device is connecting to the requested network.
    /// This may include operations like associating with the WiFi AP, dialing the modem,
    /// connecting to the remote Bluetooth device, etc.
    Config = 50,
    /// the device requires more information to continue connecting to the requested network.
    /// This includes secrets like WiFi passphrases, login passwords, PIN codes, etc.
    NeedAuth = 60,
    /// the device is requesting IPv4 and/or IPv6 addresses and routing information from the network.
    IpConfig = 70,
    /// the device is checking whether further action is required for the requested network connection.
    /// This may include checking whether only local network access is available, whether a captive portal is blocking access to the Internet, etc.
    IpCheck = 80,
    /// the device is waiting for a secondary connection (like a VPN) which must activated before the device can be activated
    Secondaries = 90,
    /// the device has a network connection, either local or global.
    Activated = 100,
    /// a disconnection from the current network connection was requested, and the device is cleaning up resources used
    /// for that connection. The network connection may still be valid.
    Deactivating = 110,
    /// the device failed to connect to the requested network and is cleaning up the connection request
    Failed = 120,
}

/// NMState values indicate the current overall networking state.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum NM80211Mode {
    /// the device or access point mode is unknown
    Unknown = 0,
    /// for both devices and access point objects, indicates the object
    /// is part of an Ad-Hoc 802.11 network without a central coordinating access point.
    Adhoc = 1,
    /// the device or access point is in infrastructure mode.
    /// For devices, this indicates the device is an 802.11 client/station.
    /// For access point objects, this indicates the object is an access point that provides connectivity to clients.
    Infra = 2,
    /// the device is an access point/hotspot.
    /// Not valid for access point objects; used only for hotspot mode on the local machine.
    Ap = 3,
}

bitflags! {
    /// 802.11 access point security and authentication flags.
    /// These flags describe the current security requirements of an access point as determined from the access point's beacon.
    #[repr(transparent)]
    #[derive(Default)]
    #[cfg_attr(not(feature = "defmt"), derive(Debug, Copy, Clone, Eq, PartialEq, Hash))]
    pub struct NM80211ApSecurityFlags: u32 {
        /// the access point has no special security requirements
        const NONE = 0x00;
        /// 40/64-bit WEP is supported for pairwise/unicast encryption
        const PAIR_WEP40 = 0x01;
        /// 104/128-bit WEP is supported for pairwise/unicast encryption
        const PAIR_WEP104 = 0x02;
        /// TKIP is supported for pairwise/unicast encryption
        const PAIR_TKIP = 0x04;
        /// AES/CCMP is supported for pairwise/unicast encryption
        const PAIR_CCMP = 0x08;
        /// 40/64-bit WEP is supported for group/broadcast encryption
        const GROUP_WEP40 = 0x10;
        /// 104/128-bit WEP is supported for group/broadcast encryption
        const GROUP_WEP104 = 0x20;
        /// TKIP is supported for group/broadcast encryption
        const GROUP_TKIP = 0x40;
        /// AES/CCMP is supported for group/broadcast encryption
        const GROUP_CCMP = 0x80;
        /// WPA/RSN Pre-Shared Key encryption is supported
        const KEY_MGMT_PSK = 0x100;
        /// 802.1x authentication and key management is supported
        const KEY_MGMT_802_1X = 0x200;
    }
}
