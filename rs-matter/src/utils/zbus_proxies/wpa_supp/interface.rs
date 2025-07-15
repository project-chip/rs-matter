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

//! # D-Bus interface proxy for: `fi.w1.wpa_supplicant1.Interface`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

#[proxy(interface = "fi.w1.wpa_supplicant1.Interface", assume_defaults = true)]
pub trait Interface {
    /// AddBlob method
    fn add_blob(&self, name: &str, data: &[u8]) -> zbus::Result<()>;

    /// AddNetwork method
    fn add_network(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<OwnedObjectPath>;

    /// AutoScan method
    fn auto_scan(&self, arg: &str) -> zbus::Result<()>;

    /// Disconnect method
    fn disconnect(&self) -> zbus::Result<()>;

    /// EAPLogoff method
    #[zbus(name = "EAPLogoff")]
    fn eaplogoff(&self) -> zbus::Result<()>;

    /// EAPLogon method
    #[zbus(name = "EAPLogon")]
    fn eaplogon(&self) -> zbus::Result<()>;

    /// FlushBSS method
    #[zbus(name = "FlushBSS")]
    fn flush_bss(&self, age: u32) -> zbus::Result<()>;

    /// GetBlob method
    fn get_blob(&self, name: &str) -> zbus::Result<Vec<u8>>;

    /// NetworkReply method
    fn network_reply(&self, network: &ObjectPath<'_>, field: &str, value: &str)
        -> zbus::Result<()>;

    /// Reassociate method
    fn reassociate(&self) -> zbus::Result<()>;

    /// Reattach method
    fn reattach(&self) -> zbus::Result<()>;

    /// Reconnect method
    fn reconnect(&self) -> zbus::Result<()>;

    /// RemoveAllNetworks method
    fn remove_all_networks(&self) -> zbus::Result<()>;

    /// RemoveBlob method
    fn remove_blob(&self, name: &str) -> zbus::Result<()>;

    /// RemoveNetwork method
    fn remove_network(&self, path: &ObjectPath<'_>) -> zbus::Result<()>;

    /// Scan method
    fn scan(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// SelectNetwork method
    fn select_network(&self, path: &ObjectPath<'_>) -> zbus::Result<()>;

    /// SetPKCS11EngineAndModulePath method
    #[zbus(name = "SetPKCS11EngineAndModulePath")]
    fn set_pkcs11engine_and_module_path(
        &self,
        pkcs11_engine_path: &str,
        pkcs11_module_path: &str,
    ) -> zbus::Result<()>;

    /// SignalPoll method
    fn signal_poll(&self) -> zbus::Result<HashMap<String, OwnedValue>>;

    /// SubscribeProbeReq method
    fn subscribe_probe_req(&self) -> zbus::Result<()>;

    /// TDLSDiscover method
    #[zbus(name = "TDLSDiscover")]
    fn tdlsdiscover(&self, peer_address: &str) -> zbus::Result<()>;

    /// TDLSSetup method
    #[zbus(name = "TDLSSetup")]
    fn tdlssetup(&self, peer_address: &str) -> zbus::Result<()>;

    /// TDLSStatus method
    #[zbus(name = "TDLSStatus")]
    fn tdlsstatus(&self, peer_address: &str) -> zbus::Result<String>;

    /// TDLSTeardown method
    #[zbus(name = "TDLSTeardown")]
    fn tdlsteardown(&self, peer_address: &str) -> zbus::Result<()>;

    /// UnsubscribeProbeReq method
    fn unsubscribe_probe_req(&self) -> zbus::Result<()>;

    /// BSSAdded signal
    #[zbus(signal, name = "BSSAdded")]
    fn bssadded(
        &self,
        path: ObjectPath<'_>,
        properties: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;

    /// BSSRemoved signal
    #[zbus(signal, name = "BSSRemoved")]
    fn bssremoved(&self, path: ObjectPath<'_>) -> zbus::Result<()>;

    /// BlobAdded signal
    #[zbus(signal)]
    fn blob_added(&self, name: &str) -> zbus::Result<()>;

    /// BlobRemoved signal
    #[zbus(signal)]
    fn blob_removed(&self, name: &str) -> zbus::Result<()>;

    /// Certification signal
    #[zbus(signal)]
    fn certification(&self, certification: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// EAP signal
    #[zbus(signal, name = "EAP")]
    fn eap(&self, status: &str, parameter: &str) -> zbus::Result<()>;

    /// NetworkRequest signal
    #[zbus(signal)]
    fn network_request(&self, network: ObjectPath<'_>, field: &str, txt: &str) -> zbus::Result<()>;

    /// NetworkAdded signal
    #[zbus(signal)]
    fn network_added(
        &self,
        path: ObjectPath<'_>,
        properties: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;

    /// NetworkRemoved signal
    #[zbus(signal)]
    fn network_removed(&self, path: ObjectPath<'_>) -> zbus::Result<()>;

    /// NetworkSelected signal
    #[zbus(signal)]
    fn network_selected(&self, path: ObjectPath<'_>) -> zbus::Result<()>;

    /// ProbeRequest signal
    #[zbus(signal)]
    fn probe_request(&self, args: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// PropertiesChanged signal
    #[zbus(signal)]
    fn properties_changed(&self, properties: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// ScanDone signal
    #[zbus(signal)]
    fn scan_done(&self, success: bool) -> zbus::Result<()>;

    /// StaAuthorized signal
    #[zbus(signal)]
    fn sta_authorized(&self, name: &str) -> zbus::Result<()>;

    /// StaDeauthorized signal
    #[zbus(signal)]
    fn sta_deauthorized(&self, name: &str) -> zbus::Result<()>;

    /// ApScan property
    #[zbus(property)]
    fn ap_scan(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn set_ap_scan(&self, value: u32) -> zbus::Result<()>;

    /// BSSExpireAge property
    #[zbus(property, name = "BSSExpireAge")]
    fn bssexpire_age(&self) -> zbus::Result<u32>;
    #[zbus(property, name = "BSSExpireAge")]
    fn set_bssexpire_age(&self, value: u32) -> zbus::Result<()>;

    /// BSSExpireCount property
    #[zbus(property, name = "BSSExpireCount")]
    fn bssexpire_count(&self) -> zbus::Result<u32>;
    #[zbus(property, name = "BSSExpireCount")]
    fn set_bssexpire_count(&self, value: u32) -> zbus::Result<()>;

    /// BSSs property
    #[zbus(property, name = "BSSs")]
    fn bsss(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Blobs property
    #[zbus(property)]
    // TODO fn blobs(&self) -> zbus::Result<std::collections::HashMap<String, Vec<u8>>>;
    fn blobs(&self) -> zbus::Result<Vec<String>>;

    /// BridgeIfname property
    #[zbus(property)]
    fn bridge_ifname(&self) -> zbus::Result<String>;

    /// Capabilities property
    #[zbus(property)]
    fn capabilities(&self) -> zbus::Result<HashMap<String, OwnedValue>>;

    /// Country property
    #[zbus(property)]
    fn country(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_country(&self, value: &str) -> zbus::Result<()>;

    /// CurrentAuthMode property
    #[zbus(property)]
    fn current_auth_mode(&self) -> zbus::Result<String>;

    /// CurrentBSS property
    #[zbus(property, name = "CurrentBSS")]
    fn current_bss(&self) -> zbus::Result<OwnedObjectPath>;

    /// CurrentNetwork property
    #[zbus(property)]
    fn current_network(&self) -> zbus::Result<OwnedObjectPath>;

    /// DisconnectReason property
    #[zbus(property)]
    fn disconnect_reason(&self) -> zbus::Result<i32>;

    /// Driver property
    #[zbus(property)]
    fn driver(&self) -> zbus::Result<String>;

    /// FastReauth property
    #[zbus(property)]
    fn fast_reauth(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_fast_reauth(&self, value: bool) -> zbus::Result<()>;

    /// Ifname property
    #[zbus(property)]
    fn ifname(&self) -> zbus::Result<String>;

    /// Networks property
    #[zbus(property)]
    fn networks(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// PKCS11EnginePath property
    #[zbus(property, name = "PKCS11EnginePath")]
    fn pkcs11engine_path(&self) -> zbus::Result<String>;

    /// PKCS11ModulePath property
    #[zbus(property, name = "PKCS11ModulePath")]
    fn pkcs11module_path(&self) -> zbus::Result<String>;

    /// ScanInterval property
    #[zbus(property)]
    fn scan_interval(&self) -> zbus::Result<i32>;
    #[zbus(property)]
    fn set_scan_interval(&self, value: i32) -> zbus::Result<()>;

    /// Scanning property
    #[zbus(property)]
    fn scanning(&self) -> zbus::Result<bool>;

    /// State property
    #[zbus(property)]
    fn state(&self) -> zbus::Result<String>;
}
