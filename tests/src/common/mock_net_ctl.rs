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

//! A `NetCtl` implementation that answers scans and connects from a canned set
//! of networks, without touching a radio.
//!
//! The Network Commissioning certification tests are mostly about the cluster's
//! own bookkeeping - failsafe interaction, `Networks` list ordering, the
//! `NetworkIDNotFound` / `NetworkNotFound` statuses, breadcrumb handling - which
//! they drive through `ScanNetworks` and `ConnectNetwork`. Answering just those
//! two from a fixed table lets the whole surface be exercised on a host with no
//! Wi-Fi or Thread hardware, while the node keeps carrying operational traffic
//! over whatever interface it was already reachable on.
//!
//! Note what this deliberately does *not* model: `connect` never changes which
//! network the node is reachable on. A test that verifies the DUT moved to a
//! second network and was re-discovered there (`TC_CNET_4_12`) would go green
//! against this without having tested anything, and belongs on real hardware.

use rs_matter::dm::clusters::net_comm::{
    NetCtl, NetCtlError, NetCtlStatus, NetworkCommissioningStatusEnum, NetworkScanInfo,
    NetworkType, WiFiBandEnum, WiFiSecurityBitmap, WirelessCreds,
};
use rs_matter::dm::clusters::thread_diag::{RoutingRoleEnum, ThreadDiag};
use rs_matter::dm::clusters::wifi_diag::{
    SecurityTypeEnum, WiFiVersionEnum, WifiDiag, WirelessDiag,
};
use rs_matter::dm::networks::NetChangeNotif;
use rs_matter::error::Error;
use rs_matter::tlv::Nullable;
use rs_matter::utils::sync::DynBase;

/// A canned Wi-Fi network, as reported by `ScanNetworks`.
pub struct MockWifiNetwork {
    pub ssid: &'static [u8],
    pub bssid: &'static [u8; 6],
    pub channel: u16,
    pub rssi: i8,
}

/// A canned Thread network, as reported by `ScanNetworks`.
pub struct MockThreadNetwork {
    pub pan_id: u16,
    pub ext_pan_id: u64,
    pub network_name: &'static str,
    pub channel: u16,
    pub ext_addr: &'static [u8; 8],
    pub rssi: i8,
    pub lqi: u8,
}

/// The Wi-Fi networks the mock reports. The first entry doubles as the network
/// the device is provisioned with, so a directed scan for the SSID found in the
/// `Networks` attribute matches - which is what `TC_CNET_4_4` checks.
pub const MOCK_WIFI_NETWORKS: &[MockWifiNetwork] = &[
    MockWifiNetwork {
        ssid: b"MatterAP",
        bssid: b"\x00\x11\x22\x33\x44\x55",
        channel: 6,
        rssi: -50,
    },
    MockWifiNetwork {
        ssid: b"MatterAP2",
        bssid: b"\x00\x11\x22\x33\x44\x66",
        channel: 11,
        rssi: -70,
    },
];

/// The Thread networks the mock reports; the first is the provisioned one.
pub const MOCK_THREAD_NETWORKS: &[MockThreadNetwork] = &[
    MockThreadNetwork {
        pan_id: 0x1234,
        // Deliberately not `1111111122222222`: `TC_CNET_4_16` hardcodes that
        // value as the *second*, deliberately-unknown network it expects a
        // `NetworkIDNotFound` for, so the provisioned one must differ.
        ext_pan_id: 0x1234_5678_9ABC_DEF0,
        network_name: "MatterThread",
        channel: 15,
        ext_addr: b"\x00\x11\x22\x33\x44\x55\x66\x77",
        rssi: -50,
        lqi: 200,
    },
    MockThreadNetwork {
        pan_id: 0x5678,
        ext_pan_id: 0x3333_3333_4444_4444,
        network_name: "MatterThread2",
        channel: 20,
        ext_addr: b"\x00\x11\x22\x33\x44\x55\x66\x88",
        rssi: -70,
        lqi: 150,
    },
];

/// The SSID of the Wi-Fi network the device reports itself provisioned with.
pub const MOCK_WIFI_SSID: &[u8] = MOCK_WIFI_NETWORKS[0].ssid;

/// The extended PAN ID of the Thread network the device reports itself
/// provisioned with, in the big-endian form the `Networks` attribute uses.
pub const MOCK_THREAD_EXT_PAN_ID: [u8; 8] = MOCK_THREAD_NETWORKS[0].ext_pan_id.to_be_bytes();

/// The passphrase of the provisioned Wi-Fi network. Never checked - the mock
/// accepts whatever it is handed.
pub const MOCK_WIFI_PASS: &[u8] = b"MatterAPPassword";

/// A minimal Thread operational dataset for the provisioned network: just the
/// Extended PAN ID TLV (type 2, length 8), which is all `Thread` needs in order
/// to derive the network ID.
pub const MOCK_THREAD_DATASET: [u8; 10] = [
    2,
    8,
    MOCK_THREAD_EXT_PAN_ID[0],
    MOCK_THREAD_EXT_PAN_ID[1],
    MOCK_THREAD_EXT_PAN_ID[2],
    MOCK_THREAD_EXT_PAN_ID[3],
    MOCK_THREAD_EXT_PAN_ID[4],
    MOCK_THREAD_EXT_PAN_ID[5],
    MOCK_THREAD_EXT_PAN_ID[6],
    MOCK_THREAD_EXT_PAN_ID[7],
];

/// A `NetCtl` serving [`MOCK_WIFI_NETWORKS`] / [`MOCK_THREAD_NETWORKS`].
pub struct MockNetCtl {
    net_type: NetworkType,
}

impl MockNetCtl {
    /// Create a mock controller for the given network type.
    ///
    /// `NetworkType::Ethernet` is rejected: it has no `ScanNetworks` or
    /// `ConnectNetwork` to answer, and `EthNetCtl` already covers it.
    pub const fn new(net_type: NetworkType) -> Self {
        assert!(
            !matches!(net_type, NetworkType::Ethernet),
            "MockNetCtl models the wireless network types only"
        );

        Self { net_type }
    }
}

impl NetCtl for MockNetCtl {
    fn net_type(&self) -> NetworkType {
        self.net_type
    }

    async fn scan<F>(&self, network: Option<&[u8]>, mut f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error>,
    {
        let mut found = false;

        match self.net_type {
            NetworkType::Wifi => {
                for net in MOCK_WIFI_NETWORKS {
                    // A directed scan reports only the requested SSID.
                    if matches!(network, Some(ssid) if ssid != net.ssid) {
                        continue;
                    }

                    found = true;

                    f(&NetworkScanInfo::Wifi {
                        security: WiFiSecurityBitmap::WPA_2_PERSONAL,
                        ssid: net.ssid,
                        bssid: net.bssid,
                        channel: net.channel,
                        band: WiFiBandEnum::V2G4,
                        rssi: net.rssi,
                    })?;
                }
            }
            NetworkType::Thread => {
                // Thread scans are not filtered by network ID.
                for net in MOCK_THREAD_NETWORKS {
                    found = true;

                    f(&NetworkScanInfo::Thread {
                        pan_id: net.pan_id,
                        ext_pan_id: net.ext_pan_id,
                        network_name: net.network_name,
                        channel: net.channel,
                        version: 4,
                        ext_addr: net.ext_addr,
                        rssi: net.rssi,
                        lqi: net.lqi,
                    })?;
                }
            }
            NetworkType::Ethernet => unreachable!("rejected by `MockNetCtl::new`"),
        }

        // A directed scan that matched nothing is a `NetworkNotFound`, which is
        // what the tests assert when scanning for a random SSID.
        if found {
            Ok(())
        } else {
            Err(NetCtlError::NetworkNotFound)
        }
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        // Only the credential type is checked; the node stays reachable on the
        // interface it was already reachable on.
        Ok(creds.check_match(self.net_type)?)
    }
}

impl NetCtlStatus for MockNetCtl {
    fn last_networking_status(&self) -> Result<Option<NetworkCommissioningStatusEnum>, Error> {
        Ok(Some(NetworkCommissioningStatusEnum::Success))
    }

    fn last_network_id<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(Option<&[u8]>) -> Result<R, Error>,
    {
        match self.net_type {
            NetworkType::Wifi => f(Some(MOCK_WIFI_SSID)),
            NetworkType::Thread => f(Some(&MOCK_THREAD_EXT_PAN_ID)),
            NetworkType::Ethernet => f(None),
        }
    }

    fn last_connect_error_value(&self) -> Result<Option<i32>, Error> {
        Ok(None)
    }
}

impl NetChangeNotif for MockNetCtl {
    async fn wait_changed(&self) {
        // The mock network never changes state.
        core::future::pending().await
    }
}

impl DynBase for MockNetCtl {}

impl WirelessDiag for MockNetCtl {
    fn connected(&self) -> Result<bool, Error> {
        Ok(true)
    }
}

// The diagnostics clusters report the provisioned network. Left at their
// defaults these would all read null, which the certification tests tolerate but
// learn nothing from - answering them from the same canned table the scans use
// is what gives `TC_DGWIFI_*` / `TC_DGTHREAD_*` something to check.
impl WifiDiag for MockNetCtl {
    fn bssid(&self, f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>) -> Result<(), Error> {
        f(Some(MOCK_WIFI_NETWORKS[0].bssid))
    }

    fn security_type(&self) -> Result<Nullable<SecurityTypeEnum>, Error> {
        Ok(Nullable::some(SecurityTypeEnum::WPA2))
    }

    fn wi_fi_version(&self) -> Result<Nullable<WiFiVersionEnum>, Error> {
        Ok(Nullable::some(WiFiVersionEnum::N))
    }

    fn channel_number(&self) -> Result<Nullable<u16>, Error> {
        Ok(Nullable::some(MOCK_WIFI_NETWORKS[0].channel))
    }

    fn rssi(&self) -> Result<Nullable<i8>, Error> {
        Ok(Nullable::some(MOCK_WIFI_NETWORKS[0].rssi))
    }
}

impl ThreadDiag for MockNetCtl {
    fn channel(&self) -> Result<Option<u16>, Error> {
        Ok(Some(MOCK_THREAD_NETWORKS[0].channel))
    }

    fn routing_role(&self) -> Result<Option<RoutingRoleEnum>, Error> {
        Ok(Some(RoutingRoleEnum::EndDevice))
    }

    fn network_name(
        &self,
        f: &mut dyn FnMut(Option<&str>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        f(Some(MOCK_THREAD_NETWORKS[0].network_name))
    }

    fn pan_id(&self) -> Result<Option<u16>, Error> {
        Ok(Some(MOCK_THREAD_NETWORKS[0].pan_id))
    }

    fn extended_pan_id(&self) -> Result<Option<u64>, Error> {
        Ok(Some(MOCK_THREAD_NETWORKS[0].ext_pan_id))
    }

    fn ext_address(&self) -> Result<Option<u64>, Error> {
        Ok(Some(u64::from_be_bytes(*MOCK_THREAD_NETWORKS[0].ext_addr)))
    }
}
