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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

#[proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
pub trait NetworkManager {
    /// ActivateConnection method
    fn activate_connection(
        &self,
        connection: &ObjectPath<'_>,
        device: &ObjectPath<'_>,
        specific_object: &ObjectPath<'_>,
    ) -> zbus::Result<OwnedObjectPath>;

    /// AddAndActivateConnection method
    fn add_and_activate_connection(
        &self,
        connection: HashMap<&str, HashMap<&str, &Value<'_>>>,
        device: &ObjectPath<'_>,
        specific_object: &ObjectPath<'_>,
    ) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;

    /// AddAndActivateConnection2 method
    #[allow(clippy::too_many_arguments)]
    fn add_and_activate_connection2(
        &self,
        connection: HashMap<&str, HashMap<&str, &Value<'_>>>,
        device: &ObjectPath<'_>,
        specific_object: &ObjectPath<'_>,
        options: HashMap<&str, &Value<'_>>,
    ) -> zbus::Result<(
        OwnedObjectPath,
        OwnedObjectPath,
        HashMap<String, OwnedValue>,
    )>;

    /// CheckConnectivity method
    fn check_connectivity(&self) -> zbus::Result<u32>;

    /// CheckpointAdjustRollbackTimeout method
    fn checkpoint_adjust_rollback_timeout(
        &self,
        checkpoint: &ObjectPath<'_>,
        add_timeout: u32,
    ) -> zbus::Result<()>;

    /// CheckpointCreate method
    fn checkpoint_create(
        &self,
        devices: &[&ObjectPath<'_>],
        rollback_timeout: u32,
        flags: u32,
    ) -> zbus::Result<OwnedObjectPath>;

    /// CheckpointDestroy method
    fn checkpoint_destroy(&self, checkpoint: &ObjectPath<'_>) -> zbus::Result<()>;

    /// CheckpointRollback method
    fn checkpoint_rollback(
        &self,
        checkpoint: &ObjectPath<'_>,
    ) -> zbus::Result<HashMap<String, u32>>;

    /// DeactivateConnection method
    fn deactivate_connection(&self, active_connection: &ObjectPath<'_>) -> zbus::Result<()>;

    /// Enable method
    fn enable(&self, enable: bool) -> zbus::Result<()>;

    /// GetAllDevices method
    fn get_all_devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// GetDeviceByIpIface method
    fn get_device_by_ip_iface(&self, iface: &str) -> zbus::Result<OwnedObjectPath>;

    /// GetDevices method
    fn get_devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// GetLogging method
    fn get_logging(&self) -> zbus::Result<(String, String)>;

    /// GetPermissions method
    fn get_permissions(&self) -> zbus::Result<HashMap<String, String>>;

    /// Reload method
    fn reload(&self, flags: u32) -> zbus::Result<()>;

    /// SetLogging method
    fn set_logging(&self, level: &str, domains: &str) -> zbus::Result<()>;

    /// Sleep method
    fn sleep(&self, sleep: bool) -> zbus::Result<()>;

    /// state method
    #[zbus(name = "state")]
    fn nm_state(&self) -> zbus::Result<u32>;

    /// CheckPermissions signal
    #[zbus(signal)]
    fn check_permissions(&self) -> zbus::Result<()>;

    /// DeviceAdded signal
    #[zbus(signal)]
    fn device_added(&self, device_path: ObjectPath<'_>) -> zbus::Result<()>;

    /// DeviceRemoved signal
    #[zbus(signal)]
    fn device_removed(&self, device_path: ObjectPath<'_>) -> zbus::Result<()>;

    /// StateChanged signal
    #[zbus(signal, name = "StateChanged")]
    fn nm_state_changed(&self, state: u32) -> zbus::Result<()>;

    /// ActivatingConnection property
    #[zbus(property)]
    fn activating_connection(&self) -> zbus::Result<OwnedObjectPath>;

    /// ActiveConnections property
    #[zbus(property)]
    fn active_connections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// AllDevices property
    #[zbus(property)]
    fn all_devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Capabilities property
    #[zbus(property)]
    fn capabilities(&self) -> zbus::Result<Vec<u32>>;

    /// Checkpoints property
    #[zbus(property)]
    fn checkpoints(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Connectivity property
    #[zbus(property)]
    fn connectivity(&self) -> zbus::Result<u32>;

    /// ConnectivityCheckAvailable property
    #[zbus(property)]
    fn connectivity_check_available(&self) -> zbus::Result<bool>;

    /// ConnectivityCheckEnabled property
    #[zbus(property)]
    fn connectivity_check_enabled(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_connectivity_check_enabled(&self, value: bool) -> zbus::Result<()>;

    /// ConnectivityCheckUri property
    #[zbus(property)]
    fn connectivity_check_uri(&self) -> zbus::Result<String>;

    /// Devices property
    #[zbus(property)]
    fn devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// GlobalDnsConfiguration property
    #[zbus(property)]
    fn global_dns_configuration(&self) -> zbus::Result<HashMap<String, OwnedValue>>;
    #[zbus(property)]
    fn set_global_dns_configuration(
        &self,
        // TODO value: HashMap<&str, &Value<'_>>,
        value: Value<'_>,
    ) -> zbus::Result<()>;

    /// Metered property
    #[zbus(property)]
    fn metered(&self) -> zbus::Result<u32>;

    /// NetworkingEnabled property
    #[zbus(property)]
    fn networking_enabled(&self) -> zbus::Result<bool>;

    /// PrimaryConnection property
    #[zbus(property)]
    fn primary_connection(&self) -> zbus::Result<OwnedObjectPath>;

    /// PrimaryConnectionType property
    #[zbus(property)]
    fn primary_connection_type(&self) -> zbus::Result<String>;

    /// RadioFlags property
    #[zbus(property)]
    fn radio_flags(&self) -> zbus::Result<u32>;

    /// Startup property
    #[zbus(property)]
    fn startup(&self) -> zbus::Result<bool>;

    /// State property
    #[zbus(property)]
    fn state(&self) -> zbus::Result<u32>;

    /// Version property
    #[zbus(property)]
    fn version(&self) -> zbus::Result<String>;

    /// VersionInfo property
    #[zbus(property)]
    fn version_info(&self) -> zbus::Result<Vec<u32>>;

    /// WimaxEnabled property
    #[zbus(property)]
    fn wimax_enabled(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_wimax_enabled(&self, value: bool) -> zbus::Result<()>;

    /// WimaxHardwareEnabled property
    #[zbus(property)]
    fn wimax_hardware_enabled(&self) -> zbus::Result<bool>;

    /// WirelessEnabled property
    #[zbus(property)]
    fn wireless_enabled(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_wireless_enabled(&self, value: bool) -> zbus::Result<()>;

    /// WirelessHardwareEnabled property
    #[zbus(property)]
    fn wireless_hardware_enabled(&self) -> zbus::Result<bool>;

    /// WwanEnabled property
    #[zbus(property)]
    fn wwan_enabled(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_wwan_enabled(&self, value: bool) -> zbus::Result<()>;

    /// WwanHardwareEnabled property
    #[zbus(property)]
    fn wwan_hardware_enabled(&self) -> zbus::Result<bool>;
}
