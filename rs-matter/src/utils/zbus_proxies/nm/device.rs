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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Device`

#![allow(clippy::type_complexity)]

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

pub mod adsl;
pub mod bluetooth;
pub mod bond;
pub mod bridge;
pub mod dummy;
pub mod generic;
pub mod hsr;
pub mod infiniband;
pub mod ip_tunnel;
pub mod ipvlan;
pub mod loopback;
pub mod lowpan;
pub mod macsec;
pub mod macvlan;
pub mod modem;
pub mod olpc_mesh;
pub mod ovs_bridge;
pub mod ovs_interface;
pub mod ovs_port;
pub mod ppp;
pub mod statistics;
pub mod team;
pub mod tun;
pub mod veth;
pub mod vlan;
pub mod vrf;
pub mod vxlan;
pub mod wifi_p2p;
pub mod wired;
pub mod wireguard;
pub mod wireless;
pub mod wpan;

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Device {
    /// Delete method
    fn delete(&self) -> zbus::Result<()>;

    /// Disconnect method
    fn disconnect(&self) -> zbus::Result<()>;

    /// GetAppliedConnection method
    fn get_applied_connection(
        &self,
        flags: u32,
    ) -> zbus::Result<(HashMap<String, HashMap<String, OwnedValue>>, u64)>;

    /// Reapply method
    fn reapply(
        &self,
        connection: HashMap<&str, HashMap<&str, &Value<'_>>>,
        version_id: u64,
        flags: u32,
    ) -> zbus::Result<()>;

    /// StateChanged signal
    #[zbus(signal, name = "StateChanged")]
    fn dev_state_changed_signal(
        &self,
        new_state: u32,
        old_state: u32,
        reason: u32,
    ) -> zbus::Result<()>;

    /// ActiveConnection property
    #[zbus(property)]
    fn active_connection(&self) -> zbus::Result<OwnedObjectPath>;

    /// Autoconnect property
    #[zbus(property)]
    fn autoconnect(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_autoconnect(&self, value: bool) -> zbus::Result<()>;

    /// AvailableConnections property
    #[zbus(property)]
    fn available_connections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Capabilities property
    #[zbus(property)]
    fn capabilities(&self) -> zbus::Result<u32>;

    /// DeviceType property
    #[zbus(property)]
    fn device_type(&self) -> zbus::Result<u32>;

    /// Dhcp4Config property
    #[zbus(property)]
    fn dhcp4_config(&self) -> zbus::Result<OwnedObjectPath>;

    /// Dhcp6Config property
    #[zbus(property)]
    fn dhcp6_config(&self) -> zbus::Result<OwnedObjectPath>;

    /// Driver property
    #[zbus(property)]
    fn driver(&self) -> zbus::Result<String>;

    /// DriverVersion property
    #[zbus(property)]
    fn driver_version(&self) -> zbus::Result<String>;

    /// FirmwareMissing property
    #[zbus(property)]
    fn firmware_missing(&self) -> zbus::Result<bool>;

    /// FirmwareVersion property
    #[zbus(property)]
    fn firmware_version(&self) -> zbus::Result<String>;

    /// HwAddress property
    #[zbus(property)]
    fn hw_address(&self) -> zbus::Result<String>;

    /// Interface property
    #[zbus(property)]
    fn interface(&self) -> zbus::Result<String>;

    /// InterfaceFlags property
    #[zbus(property)]
    fn interface_flags(&self) -> zbus::Result<u32>;

    /// Ip4Address property
    #[zbus(property)]
    fn ip4_address(&self) -> zbus::Result<u32>;

    /// Ip4Config property
    #[zbus(property)]
    fn ip4_config(&self) -> zbus::Result<OwnedObjectPath>;

    /// Ip4Connectivity property
    #[zbus(property)]
    fn ip4_connectivity(&self) -> zbus::Result<u32>;

    /// Ip6Config property
    #[zbus(property)]
    fn ip6_config(&self) -> zbus::Result<OwnedObjectPath>;

    /// Ip6Connectivity property
    #[zbus(property)]
    fn ip6_connectivity(&self) -> zbus::Result<u32>;

    /// IpInterface property
    #[zbus(property)]
    fn ip_interface(&self) -> zbus::Result<String>;

    /// LldpNeighbors property
    #[zbus(property)]
    fn lldp_neighbors(&self) -> zbus::Result<Vec<HashMap<String, OwnedValue>>>;

    /// Managed property
    #[zbus(property)]
    fn managed(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_managed(&self, value: bool) -> zbus::Result<()>;

    /// Metered property
    #[zbus(property)]
    fn metered(&self) -> zbus::Result<u32>;

    /// Mtu property
    #[zbus(property)]
    fn mtu(&self) -> zbus::Result<u32>;

    /// NmPluginMissing property
    #[zbus(property)]
    fn nm_plugin_missing(&self) -> zbus::Result<bool>;

    /// Path property
    #[zbus(property)]
    fn path(&self) -> zbus::Result<String>;

    /// PhysicalPortId property
    #[zbus(property)]
    fn physical_port_id(&self) -> zbus::Result<String>;

    /// Ports property
    #[zbus(property)]
    fn ports(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Real property
    #[zbus(property)]
    fn real(&self) -> zbus::Result<bool>;

    /// State property
    #[zbus(property, name = "State")]
    fn dev_state(&self) -> zbus::Result<u32>;

    /// StateReason property
    #[zbus(property)]
    fn state_reason(&self) -> zbus::Result<(u32, u32)>;

    /// Udi property
    #[zbus(property)]
    fn udi(&self) -> zbus::Result<String>;
}
