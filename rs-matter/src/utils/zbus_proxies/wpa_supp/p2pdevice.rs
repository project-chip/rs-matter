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

//! # D-Bus interface proxy for: `fi.w1.wpa_supplicant1.Interface.P2PDevice`

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

#[proxy(
    interface = "fi.w1.wpa_supplicant1.Interface.P2PDevice",
    assume_defaults = true
)]
pub trait P2PDevice {
    /// AddPersistentGroup method
    fn add_persistent_group(
        &self,
        args: HashMap<&str, &Value<'_>>,
    ) -> zbus::Result<OwnedObjectPath>;

    /// AddService method
    fn add_service(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// Connect method
    fn connect(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<String>;

    /// DeleteService method
    fn delete_service(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// Disconnect method
    fn disconnect(&self) -> zbus::Result<()>;

    /// ExtendedListen method
    fn extended_listen(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// Find method
    fn find(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// Flush method
    fn flush(&self) -> zbus::Result<()>;

    /// FlushService method
    fn flush_service(&self) -> zbus::Result<()>;

    /// GroupAdd method
    fn group_add(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// Cancel method
    fn cancel(&self) -> zbus::Result<()>;

    /// Invite method
    fn invite(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// Listen method
    fn listen(&self, timeout: i32) -> zbus::Result<()>;

    /// PresenceRequest method
    fn presence_request(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// ProvisionDiscoveryRequest method
    fn provision_discovery_request(
        &self,
        peer: &ObjectPath<'_>,
        config_method: &str,
    ) -> zbus::Result<()>;

    /// RejectPeer method
    fn reject_peer(&self, peer: &ObjectPath<'_>) -> zbus::Result<()>;

    /// RemoveClient method
    fn remove_client(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// RemoveAllPersistentGroups method
    fn remove_all_persistent_groups(&self) -> zbus::Result<()>;

    /// RemovePersistentGroup method
    fn remove_persistent_group(&self, path: &ObjectPath<'_>) -> zbus::Result<()>;

    /// ServiceDiscoveryCancelRequest method
    fn service_discovery_cancel_request(&self, args: u64) -> zbus::Result<()>;

    /// ServiceDiscoveryExternal method
    fn service_discovery_external(&self, arg: i32) -> zbus::Result<()>;

    /// ServiceDiscoveryRequest method
    fn service_discovery_request(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<u64>;

    /// ServiceDiscoveryResponse method
    fn service_discovery_response(&self, args: HashMap<&str, &Value<'_>>) -> zbus::Result<()>;

    /// ServiceUpdate method
    fn service_update(&self) -> zbus::Result<()>;

    /// StopFind method TODO: Isn't this `FindStopped`?
    fn stop_find(&self) -> zbus::Result<()>;

    /// DeviceFound signal
    #[zbus(signal)]
    fn device_found(&self, path: ObjectPath<'_>) -> zbus::Result<()>;

    /// DeviceLost signal
    #[zbus(signal)]
    fn device_lost(&self, path: ObjectPath<'_>) -> zbus::Result<()>;

    /// GONegotiationFailure signal
    #[zbus(signal, name = "GONegotiationFailure")]
    fn gonegotiation_failure(&self, properties: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// GONegotiationRequest signal
    #[zbus(signal, name = "GONegotiationRequest")]
    fn gonegotiation_request(
        &self,
        path: ObjectPath<'_>,
        dev_passwd_id: i32,
        dev_go_intent: u8, // TODO
    ) -> zbus::Result<()>;

    /// GONegotiationSuccess signal
    #[zbus(signal, name = "GONegotiationSuccess")]
    fn gonegotiation_success(&self, properties: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// GroupFinished signal
    #[zbus(signal)]
    fn group_finished(&self, properties: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// GroupStarted signal
    #[zbus(signal)]
    fn group_started(&self, properties: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// InvitationResult signal
    #[zbus(signal)]
    fn invitation_result(&self, invite_result: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// P2PStateChanged signal
    #[zbus(signal, name = "P2PStateChanged")]
    fn p2pstate_changed(&self, states: HashMap<&str, &str>) -> zbus::Result<()>;

    /// PersistentGroupAdded signal
    #[zbus(signal)]
    fn persistent_group_added(
        &self,
        path: ObjectPath<'_>,
        properties: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;

    /// PersistentGroupRemoved signal
    #[zbus(signal)]
    fn persistent_group_removed(&self, path: ObjectPath<'_>) -> zbus::Result<()>;

    /// ProvisionDiscoveryFailure signal
    #[zbus(signal)]
    fn provision_discovery_failure(
        &self,
        peer_object: ObjectPath<'_>,
        status: i32,
    ) -> zbus::Result<()>;

    /// ProvisionDiscoveryPBCRequest signal
    #[zbus(signal, name = "ProvisionDiscoveryPBCRequest")]
    fn provision_discovery_pbcrequest(&self, peer_object: ObjectPath<'_>) -> zbus::Result<()>;

    /// ProvisionDiscoveryPBCResponse signal
    #[zbus(signal, name = "ProvisionDiscoveryPBCResponse")]
    fn provision_discovery_pbcresponse(&self, peer_object: ObjectPath<'_>) -> zbus::Result<()>;

    /// ProvisionDiscoveryRequestDisplayPin signal
    #[zbus(signal)]
    fn provision_discovery_request_display_pin(
        &self,
        peer_object: ObjectPath<'_>,
        pin: &str,
    ) -> zbus::Result<()>;

    /// ProvisionDiscoveryRequestEnterPin signal
    #[zbus(signal)]
    fn provision_discovery_request_enter_pin(
        &self,
        peer_object: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    /// ProvisionDiscoveryResponseDisplayPin signal
    #[zbus(signal)]
    fn provision_discovery_response_display_pin(
        &self,
        peer_object: ObjectPath<'_>,
        pin: &str,
    ) -> zbus::Result<()>;

    /// ProvisionDiscoveryResponseEnterPin signal
    #[zbus(signal)]
    fn provision_discovery_response_enter_pin(
        &self,
        peer_object: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    /// ServiceDiscoveryRequest signal
    #[zbus(signal)]
    fn service_discovery_request(&self, sd_request: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// ServiceDiscoveryResponse signal
    #[zbus(signal)]
    fn service_discovery_response(&self, sd_response: HashMap<&str, Value<'_>>)
        -> zbus::Result<()>;

    /// WpsFailed signal
    #[zbus(signal)]
    fn wps_failed(&self, name: &str, args: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// InvitationReceived signal
    #[zbus(signal)]
    fn invitation_received(&self, args: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// GroupFormationFailure signal
    #[zbus(signal)]
    fn group_formation_failure(&self, reason: &str) -> zbus::Result<()>;

    /// Group property
    #[zbus(property)]
    fn group(&self) -> zbus::Result<OwnedObjectPath>;

    /// P2PDeviceConfig property
    #[zbus(property, name = "P2PDeviceConfig")]
    fn p2pdevice_config(&self) -> zbus::Result<HashMap<String, OwnedValue>>;
    #[zbus(property, name = "P2PDeviceConfig")]
    fn set_p2pdevice_config(
        &self,
        // TODO value: HashMap<&str, &Value<'_>>,
        value: Value<'_>,
    ) -> zbus::Result<()>;

    /// PeerGO property
    #[zbus(property, name = "PeerGO")]
    fn peer_go(&self) -> zbus::Result<OwnedObjectPath>;

    /// Peers property
    #[zbus(property)]
    fn peers(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// PersistentGroups property
    #[zbus(property)]
    fn persistent_groups(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Role property
    #[zbus(property)]
    fn role(&self) -> zbus::Result<String>;
}
