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

//! # D-Bus interface proxy for: `io.openthread.BorderRouter`
//!
//! Hand-written from the OpenThread sources at
//! <https://github.com/openthread/ot-br-posix/blob/main/src/dbus/server/introspect.xml>.
//!
//! Covers the full `io.openthread.BorderRouter` surface. D-Bus structs are
//! mapped onto named Rust structs that derive [`zvariant::Type`] + serde so
//! the wire encoding stays identical to a positional tuple while the Rust
//! side gets named fields and per-field documentation. See
//! [`MdnsTelemetryInfo`] for a note about one OTBR introspection-XML quirk.
//!
//! D-Bus property type `y` (`uint8`) sometimes carries signed values per
//! the OpenThread struct definitions (RSSI / TX-power fields). The wire
//! type is still `u8`; the caller is responsible for the `as i8`
//! reinterpretation. The relevant fields are marked in the per-struct doc
//! comments.

use serde::{Deserialize, Serialize};
use zbus::{
    proxy,
    zvariant::{OwnedValue, Type, Value},
};

// ---------- shared data types ----------

/// `(prefix_bytes, prefix_length)` — an IPv6 prefix as it appears on the
/// OTBR D-Bus surface. Used standalone (`RemoveExternalRoute`,
/// `RemoveOnMeshPrefix`) and as a sub-struct inside [`ExternalRoute`] and
/// [`OnMeshPrefix`].
#[derive(Debug, Clone, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct Ip6Prefix {
    pub prefix_bytes: Vec<u8>,
    pub prefix_length: u8,
}

/// Single entry returned by [`BorderRouterProxy::scan`].
#[derive(Debug, Clone, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct ScanResult {
    pub ext_address: u64,
    pub network_name: String,
    pub ext_panid: u64,
    pub steering_data: Vec<u8>,
    pub panid: u16,
    pub joiner_udp_port: u16,
    pub channel: u8,
    pub rssi: i16,
    pub lqi: u8,
    pub version: u8,
    pub is_native: bool,
    pub is_joinable: bool,
}

/// Single entry returned by [`BorderRouterProxy::energy_scan`].
///
/// `max_rssi` is signed semantically (`int8_t`); cast `as i8` at use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct EnergyScanResult {
    pub channel: u8,
    pub max_rssi: u8,
}

/// External-route rule — argument to
/// [`BorderRouterProxy::add_external_route`] and the (per the introspection
/// XML) single-struct return of [`BorderRouterProxy::external_routes`].
///
/// `rloc16` and `next_hop_is_self` are ignored by OTBR per the upstream
/// source comments.
#[derive(Debug, Clone, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct ExternalRoute {
    pub prefix: Ip6Prefix,
    pub rloc16: u16,
    pub preference: u8,
    pub stable: bool,
    pub next_hop_is_self: bool,
}

/// On-mesh prefix — argument to [`BorderRouterProxy::add_on_mesh_prefix`]
/// and element of [`BorderRouterProxy::on_mesh_prefixes`].
#[derive(Debug, Clone, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct OnMeshPrefix {
    pub prefix: Ip6Prefix,
    pub rloc16: u16,
    pub preference: u8,
    pub preferred: bool,
    pub slaac: bool,
    pub dhcp: bool,
    pub configure: bool,
    pub default_route: bool,
    pub on_mesh: bool,
    pub stable: bool,
    pub nd_dns: bool,
    pub dp: bool,
}

/// Network-leader data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct LeaderData {
    pub partition_id: u32,
    pub weighting: u8,
    pub data_version: u8,
    pub stable_data_version: u8,
    pub leader_router_id: u8,
}

/// Single entry of [`BorderRouterProxy::channel_monitor_channel_quality_map`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct ChannelQuality {
    pub channel: u8,
    pub occupancy: u16,
}

/// One row of [`BorderRouterProxy::child_table`].
///
/// `average_rssi` and `last_rssi` are signed semantically; cast `as i8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct ChildEntry {
    pub ext_address: u64,
    pub timeout: u32,
    pub age: u32,
    pub rloc16: u16,
    pub child_id: u16,
    pub network_data_version: u8,
    pub link_quality_in: u8,
    pub average_rssi: u8,
    pub last_rssi: u8,
    /// 0xFFFF → 100%. Requires error-tracking feature.
    pub frame_error_rate: u16,
    /// 0xFFFF → 100%. Requires error-tracking feature.
    pub message_error_rate: u16,
    pub rx_on_when_idle: bool,
    pub full_thread_device: bool,
    pub full_network_data: bool,
    pub is_state_restoring: bool,
}

/// One row of [`BorderRouterProxy::neighbor_table`].
///
/// `average_rssi` and `last_rssi` are signed semantically; cast `as i8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct NeighborEntry {
    pub ext_address: u64,
    pub age: u32,
    pub rloc16: u16,
    pub link_frame_counter: u32,
    pub mle_frame_counter: u32,
    pub link_quality_in: u8,
    pub average_rssi: u8,
    pub last_rssi: u8,
    /// 0xFFFF → 100%. Requires error-tracking feature.
    pub frame_error_rate: u16,
    /// 0xFFFF → 100%. Requires error-tracking feature.
    pub message_error_rate: u16,
    pub thread_version: u16,
    pub rx_on_when_idle: bool,
    pub full_thread_device: bool,
    pub full_network_data: bool,
    pub is_child: bool,
}

/// Link-layer statistic counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct LinkCounters {
    pub ip_tx_success: u32,
    pub ip_rx_success: u32,
    pub ip_tx_failure: u32,
    pub ip_rx_failure: u32,
}

/// Current link mode flags — getter / setter type for `LinkMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct LinkMode {
    /// Whether the radio receiver is on when the device is idle.
    pub rx_on_when_idle: bool,
    /// `true` = Full Thread Device, `false` = Minimal Thread Device.
    pub device_type_ftd: bool,
    /// `true` = full Network Data, `false` = stable only.
    pub network_data_full: bool,
}

/// Per-host / per-service SRP lease counters used inside [`SrpServerInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct SrpLeaseCounters {
    pub fresh_count: u32,
    pub deleted_count: u32,
    pub lease_time_total: u64,
    pub key_lease_time_total: u64,
    pub remaining_lease_time_total: u64,
    pub remaining_key_lease_time_total: u64,
}

/// SRP response counters used inside [`SrpServerInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct SrpResponseCounters {
    pub success: u32,
    pub server_failure: u32,
    pub format_error: u32,
    pub name_exists: u32,
    pub refused: u32,
    pub other: u32,
}

/// SRP server status & counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct SrpServerInfo {
    pub state: u8,
    pub port: u16,
    pub address_mode: u8,
    pub hosts: SrpLeaseCounters,
    pub services: SrpLeaseCounters,
    pub responses: SrpResponseCounters,
}

/// DNS-SD counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct DnssdCounters {
    pub success: u32,
    pub server_failure: u32,
    pub format_error: u32,
    pub name_error: u32,
    pub not_implemented: u32,
    pub other: u32,
    pub resolved_by_srp: u32,
}

/// Radio spinel metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct RadioSpinelMetrics {
    pub rcp_timeout_count: u32,
    pub rcp_unexpected_reset_count: u32,
    pub rcp_restoration_count: u32,
    pub spinel_parse_error_count: u32,
}

/// RCP interface metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct RcpInterfaceMetrics {
    pub rcp_interface_type: u8,
    pub transferred_frame_count: u64,
    pub transferred_valid_frame_count: u64,
    pub transferred_garbage_frame_count: u64,
    pub rx_frame_count: u64,
    pub rx_frame_byte_count: u64,
    pub tx_frame_count: u64,
    pub tx_frame_byte_count: u64,
}

/// Per-protocol NAT64 packet/byte counters, used inside
/// [`Nat64ProtocolCounters`] and [`Nat64Mapping`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct Nat64Counters {
    pub m_4to6_packets: u64,
    pub m_4to6_bytes: u64,
    pub m_6to4_packets: u64,
    pub m_6to4_bytes: u64,
}

/// NAT64 counters split by IP protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct Nat64ProtocolCounters {
    pub total: Nat64Counters,
    pub icmp: Nat64Counters,
    pub udp: Nat64Counters,
    pub tcp: Nat64Counters,
}

/// Per-direction NAT64 drop counters used inside [`Nat64ErrorCounters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct Nat64ErrorPair {
    pub m_4to6_packets: u64,
    pub m_6to4_packets: u64,
}

/// NAT64 drop counters by error class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct Nat64ErrorCounters {
    /// Packet drop for unknown reasons.
    pub unknown: Nat64ErrorPair,
    /// Packet drop due to failure to parse the datagram.
    pub illegal_packet: Nat64ErrorPair,
    /// Packet drop due to an unsupported IP protocol.
    pub unsupported_proto: Nat64ErrorPair,
    /// Packet drop due to no mapping found / mapping pool exhausted.
    pub no_mapping: Nat64ErrorPair,
}

/// Single entry of [`BorderRouterProxy::nat64_mappings`].
#[derive(Debug, Clone, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct Nat64Mapping {
    pub id: u64,
    pub ip4: Vec<u8>,
    pub ip6: Vec<u8>,
    pub remaining_time_ms: u32,
    pub counters: Nat64ProtocolCounters,
}

/// NAT64 state — `(prefix_manager_state, translator_state)`.
#[derive(Debug, Clone, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct Nat64State {
    pub prefix_manager_state: String,
    pub translator_state: String,
}

/// `(packets, bytes)` — used in [`BorderRoutingCounters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct PacketByteCounter {
    pub packets: u64,
    pub bytes: u64,
}

/// Border-routing counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct BorderRoutingCounters {
    pub inbound_unicast: PacketByteCounter,
    pub inbound_multicast: PacketByteCounter,
    pub outbound_unicast: PacketByteCounter,
    pub outbound_multicast: PacketByteCounter,
    /// Number of received Router Advertisement packets.
    pub ra_rx: u32,
    /// Number of RA packets successfully transmitted.
    pub ra_tx_success: u32,
    /// Number of RA packets that failed to transmit.
    pub ra_tx_failure: u32,
    /// Number of received Router Solicitation packets.
    pub rs_rx: u32,
    /// Number of RS packets successfully transmitted.
    pub rs_tx_success: u32,
    /// Number of RS packets that failed to transmit.
    pub rs_tx_failure: u32,
}

/// Information about the infrastructure-link interface (the network the
/// OTBR forwards Thread traffic onto).
#[derive(Debug, Clone, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct InfraLinkInfo {
    pub name: String,
    pub is_up: bool,
    pub is_running: bool,
    pub is_multicast: bool,
    pub link_local_addresses: u32,
    pub unique_local_addresses: u32,
    pub global_unicast_addresses: u32,
}

/// TREL packet statistics used inside [`TrelInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct TrelPacketStats {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_failure: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

/// TREL link information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct TrelInfo {
    pub enabled: bool,
    pub num_trel_peers: u16,
    pub stats: TrelPacketStats,
}

/// `(key, value)` row passed to
/// [`BorderRouterProxy::update_vendor_mesh_cop_txt_entries`].
#[derive(Debug, Clone, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct VendorTxtEntry {
    pub key: String,
    pub value: Vec<u8>,
}

/// MAC layer statistic counters — the [`BorderRouterProxy::mac_counters`]
/// property. Every counter is a `uint32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct MacCounters {
    pub tx_total: u32,
    pub tx_unicast: u32,
    pub tx_broadcast: u32,
    pub tx_ack_requested: u32,
    pub tx_acked: u32,
    pub tx_no_ack_requested: u32,
    pub tx_data: u32,
    pub tx_data_poll: u32,
    pub tx_beacon: u32,
    pub tx_beacon_request: u32,
    pub tx_other: u32,
    pub tx_retry: u32,
    pub tx_err_cca: u32,
    pub tx_err_abort: u32,
    pub tx_busy_channel: u32,
    pub rx_total: u32,
    pub rx_unicast: u32,
    pub rx_broadcast: u32,
    pub rx_data: u32,
    pub rx_data_poll: u32,
    pub rx_beacon: u32,
    pub rx_beacon_request: u32,
    pub rx_other: u32,
    pub rx_address_filtered: u32,
    pub rx_dest_address_filtered: u32,
    pub rx_duplicated: u32,
    pub rx_err_no_frame: u32,
    pub rx_err_unknown_neighbor: u32,
    pub rx_err_invalid_src_addr: u32,
    pub rx_err_sec: u32,
    pub rx_err_fcs: u32,
    pub rx_err_other: u32,
}

/// Radio coexistence metrics — the [`BorderRouterProxy::radio_coex_metrics`]
/// property.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct RadioCoexMetrics {
    /// Number of grant glitches.
    pub num_grant_glitch: u32,
    /// Number of tx requests.
    pub num_tx_request: u32,
    /// Number of tx requests while grant was active.
    pub num_tx_grant_immediate: u32,
    /// Number of tx requests while grant was inactive.
    pub num_tx_grant_wait: u32,
    /// Number of tx requests while grant was inactive that were ultimately granted.
    pub num_tx_grant_wait_activated: u32,
    /// Number of tx requests while grant was inactive that timed out.
    pub num_tx_grant_wait_timeout: u32,
    /// Number of tx that were in progress when grant was deactivated.
    pub num_tx_grant_deactivated_during_request: u32,
    /// Number of tx requests that were not granted within 50us.
    pub num_tx_delayed_grant: u32,
    /// Average time in usec from tx request to grant.
    pub avg_tx_request_to_grant_time: u32,
    /// Number of rx requests.
    pub num_rx_request: u32,
    /// Number of rx requests while grant was active.
    pub num_rx_grant_immediate: u32,
    /// Number of rx requests while grant was inactive.
    pub num_rx_grant_wait: u32,
    /// Number of rx requests while grant was inactive that were ultimately granted.
    pub num_rx_grant_wait_activated: u32,
    /// Number of rx requests while grant was inactive that timed out.
    pub num_rx_grant_wait_timeout: u32,
    /// Number of rx that were in progress when grant was deactivated.
    pub num_rx_grant_deactivated_during_request: u32,
    /// Number of rx requests that were not granted within 50us.
    pub num_rx_delayed_grant: u32,
    /// Average time in usec from rx request to grant.
    pub avg_rx_request_to_grant_time: u32,
    /// Number of rx requests that completed without receiving grant.
    pub num_rx_grant_none: u32,
    /// Stats collection stopped due to saturation.
    pub stopped: bool,
}

/// mDNS per-class response counters — used four times inside
/// [`MdnsTelemetryInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct MdnsResponseCounters {
    pub success: u32,
    pub not_found: u32,
    pub invalid_args: u32,
    pub duplicated: u32,
    pub not_implemented: u32,
    pub unknown_error: u32,
    pub aborted: u32,
    pub invalid_state: u32,
}

/// mDNS telemetry information — the
/// [`BorderRouterProxy::mdns_telemetry_info`] property.
///
/// **OTBR signature caveat:** OTBR's `introspect.xml` declares the property
/// type as `(uuuuuuuu)(uuuuuuuu)(uuuuuuuu)(uuuuuuuu)uuuu` (four 8-tuples
/// followed by four `u32`s, with no outer struct parentheses). That is not a
/// well-formed signature for a single D-Bus value; the wire emission is
/// almost certainly the natural outer struct (`((uuuuuuuu)…uuuu)`), which is
/// what this Rust struct maps to. If decoding fails against a live OTBR,
/// switch the property's return type to [`OwnedValue`] and decode ad-hoc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize, Value, OwnedValue)]
pub struct MdnsTelemetryInfo {
    pub host_registration: MdnsResponseCounters,
    pub service_registration: MdnsResponseCounters,
    pub host_resolution: MdnsResponseCounters,
    pub service_resolution: MdnsResponseCounters,
    pub host_registration_ema_latency: u32,
    pub service_registration_ema_latency: u32,
    pub host_resolution_ema_latency: u32,
    pub service_resolution_ema_latency: u32,
}

// ---------- proxy ----------

#[proxy(
    interface = "io.openthread.BorderRouter",
    default_service = "io.openthread.BorderRouter.wpan0",
    default_path = "/io/openthread/BorderRouter/wpan0"
)]
pub trait BorderRouter {
    // ---- Methods ----

    /// Perform a Thread network scan, returning one [`ScanResult`] per
    /// discovered network.
    fn scan(&self) -> zbus::Result<Vec<ScanResult>>;

    /// Perform a Thread energy scan.
    ///
    /// `scan_duration` is in milliseconds per channel.
    fn energy_scan(&self, scan_duration: u32) -> zbus::Result<Vec<EnergyScanResult>>;

    /// Attach the current device to a Thread network.
    ///
    /// Empty `network_key` / empty `pskc` / `panid == UINT16_MAX` /
    /// `ext_panid == UINT64_MAX` / `channel_mask == 0` request random
    /// selection. Call with all-defaults to attach using the current Active
    /// Operational Dataset.
    #[allow(clippy::too_many_arguments)]
    fn attach(
        &self,
        network_key: Vec<u8>,
        panid: u16,
        network_name: &str,
        ext_panid: u64,
        pskc: Vec<u8>,
        channel_mask: u32,
    ) -> zbus::Result<()>;

    /// Request that all nodes on the current network migrate to the network
    /// described by `dataset` (a full Operational Dataset, TLV-encoded).
    ///
    /// Returns the effective delay in milliseconds before the new dataset
    /// takes effect. `0` means the device has already attached to the new
    /// network by the time this call returns.
    fn attach_all_nodes_to(&self, dataset: Vec<u8>) -> zbus::Result<i64>;

    /// Detach from the current Thread network.
    fn detach(&self) -> zbus::Result<()>;

    /// Temporarily allow joining via unsecure traffic on `port` for
    /// `timeout` seconds.
    fn permit_unsecure_join(&self, port: u16, timeout: u32) -> zbus::Result<()>;

    /// Start Thread joining as a Joiner using the supplied pre-shared key
    /// for the device (`pskd`) and optional commissioning metadata.
    #[allow(clippy::too_many_arguments)]
    fn joiner_start(
        &self,
        pskd: &str,
        provision_url: &str,
        vendor_name: &str,
        vendor_model: &str,
        vendor_sw_version: &str,
        vendor_data: &str,
    ) -> zbus::Result<()>;

    /// Stop an in-progress Thread joining.
    fn joiner_stop(&self) -> zbus::Result<()>;

    /// Factory-reset the device — wipes all Thread persistent data.
    fn factory_reset(&self) -> zbus::Result<()>;

    /// Reset the OpenThread stack; the device will attempt to resume the
    /// network after reset.
    fn reset(&self) -> zbus::Result<()>;

    /// Add an external routing rule, advertising this device as the border
    /// router for `route.prefix`.
    fn add_external_route(&self, route: ExternalRoute) -> zbus::Result<()>;

    /// Remove a previously-added external routing rule.
    fn remove_external_route(&self, prefix: Ip6Prefix) -> zbus::Result<()>;

    /// Add an on-mesh prefix to the Thread network.
    fn add_on_mesh_prefix(&self, prefix: OnMeshPrefix) -> zbus::Result<()>;

    /// Remove a previously-added on-mesh prefix.
    fn remove_on_mesh_prefix(&self, prefix: Ip6Prefix) -> zbus::Result<()>;

    /// Enable or disable the Border Agent (the MeshCoP responder used by
    /// commissioners).
    fn set_border_agent_enabled(&self, enable: bool) -> zbus::Result<()>;

    /// Replace the vendor-specific MeshCoP TXT entries advertised by the
    /// Border Agent.
    fn update_vendor_mesh_cop_txt_entries(&self, update: Vec<VendorTxtEntry>) -> zbus::Result<()>;

    /// Subscribe to one or more OTBR properties for batched reads.
    ///
    /// The OTBR introspection declares no out-parameter for this method, so
    /// the proxy returns `()`. Results are delivered out-of-band via the
    /// standard properties interface.
    fn get_properties(&self, properties: Vec<String>) -> zbus::Result<()>;

    /// Detach and forget the network credentials.
    fn leave_network(&self) -> zbus::Result<()>;

    /// Enable or disable the NAT64 translator.
    fn set_nat64_enabled(&self, enable: bool) -> zbus::Result<()>;

    /// Activate ePSKc (ephemeral key) mode for `lifetime` ms (0 →
    /// `OT_BORDER_AGENT_DEFAULT_EPHEMERAL_KEY_TIMEOUT`, max 10 min).
    ///
    /// Returns the 9-digit ePSKc string (first 8 random, 9th is the
    /// Verhoeff checksum).
    fn activate_ephemeral_key_mode(&self, lifetime: u32) -> zbus::Result<String>;

    /// Deactivate ePSKc mode.
    ///
    /// `retain_active_session = false` tears down any active commissioner
    /// session immediately; `true` keeps an existing session but disables
    /// further ePSKc-based auth.
    fn deactivate_ephemeral_key_mode(&self, retain_active_session: bool) -> zbus::Result<()>;

    // ---- Properties (read-only) ----

    /// Current Thread device role. One of
    /// `"disabled" | "detached" | "child" | "router" | "leader"`.
    #[zbus(property)]
    fn device_role(&self) -> zbus::Result<String>;

    /// The Thread network name.
    #[zbus(property)]
    fn network_name(&self) -> zbus::Result<String>;

    /// The 16-bit PAN ID.
    #[zbus(property)]
    fn pan_id(&self) -> zbus::Result<u16>;

    /// The 64-bit extended PAN ID.
    #[zbus(property)]
    fn ext_pan_id(&self) -> zbus::Result<u64>;

    /// Current 2.4 GHz channel (11–26).
    #[zbus(property)]
    fn channel(&self) -> zbus::Result<u16>;

    /// Clear Channel Assessment failure rate.
    #[zbus(property)]
    fn cca_failure_rate(&self) -> zbus::Result<u16>;

    /// MAC layer statistics.
    #[zbus(property)]
    fn mac_counters(&self) -> zbus::Result<MacCounters>;

    /// Link counters.
    #[zbus(property)]
    fn link_counters(&self) -> zbus::Result<LinkCounters>;

    /// Bitmask of supported link channels.
    #[zbus(property)]
    fn link_supported_channel_mask(&self) -> zbus::Result<u32>;

    /// Bitmask of preferred link channels.
    #[zbus(property)]
    fn link_preferred_channel_mask(&self) -> zbus::Result<u32>;

    /// 16-bit Routing Locator.
    #[zbus(property)]
    fn rloc16(&self) -> zbus::Result<u16>;

    /// 64-bit IEEE EUI-64 of the Thread radio.
    #[zbus(property)]
    fn extended_address(&self) -> zbus::Result<u64>;

    /// Current router ID.
    #[zbus(property)]
    fn router_id(&self) -> zbus::Result<u8>;

    /// Network leader data.
    #[zbus(property)]
    fn leader_data(&self) -> zbus::Result<LeaderData>;

    /// Full Thread network data, raw bytes.
    #[zbus(property)]
    fn network_data(&self) -> zbus::Result<Vec<u8>>;

    /// Stable Thread network data, raw bytes.
    #[zbus(property)]
    fn stable_network_data(&self) -> zbus::Result<Vec<u8>>;

    /// Leader weight of the local node.
    #[zbus(property)]
    fn local_leader_weight(&self) -> zbus::Result<u8>;

    /// Number of samples collected by the channel monitor.
    #[zbus(property)]
    fn channel_monitor_sample_count(&self) -> zbus::Result<u32>;

    /// Channel monitor occupancy per channel.
    #[zbus(property)]
    fn channel_monitor_channel_quality_map(&self) -> zbus::Result<Vec<ChannelQuality>>;

    /// The node's child table.
    #[zbus(property)]
    fn child_table(&self) -> zbus::Result<Vec<ChildEntry>>;

    /// The node's neighbor table.
    #[zbus(property)]
    fn neighbor_table(&self) -> zbus::Result<Vec<NeighborEntry>>;

    /// Current network partition ID.
    #[zbus(property)]
    fn partition_id(&self) -> zbus::Result<u32>;

    /// RSSI of the last received packet (signed semantically, cast `as i8`).
    #[zbus(property)]
    fn instant_rssi(&self) -> zbus::Result<u8>;

    /// Radio transmit power in dBm (signed semantically, cast `as i8`).
    #[zbus(property)]
    fn radio_tx_power(&self) -> zbus::Result<u8>;

    /// Active external route rule. Per the OTBR introspection XML this is
    /// declared as a single struct (not an array); the doc comment in
    /// upstream describes it as a list, so OTBR's behaviour here may
    /// diverge from the static signature. The proxy mirrors the declared
    /// type verbatim.
    #[zbus(property)]
    fn external_routes(&self) -> zbus::Result<ExternalRoute>;

    /// On-mesh prefixes.
    #[zbus(property)]
    fn on_mesh_prefixes(&self) -> zbus::Result<Vec<OnMeshPrefix>>;

    /// Pending Thread Operational Dataset, TLV-encoded. Empty if there is
    /// no pending change.
    #[zbus(property)]
    fn pending_dataset_tlvs(&self) -> zbus::Result<Vec<u8>>;

    /// SRP server status & counters.
    #[zbus(property)]
    fn srp_server_info(&self) -> zbus::Result<SrpServerInfo>;

    /// DNS-SD counters.
    #[zbus(property)]
    fn dnssd_counters(&self) -> zbus::Result<DnssdCounters>;

    /// mDNS telemetry. See [`MdnsTelemetryInfo`] for the OTBR signature
    /// caveat — the introspect XML is missing the outer struct parentheses.
    #[zbus(property)]
    fn mdns_telemetry_info(&self) -> zbus::Result<MdnsTelemetryInfo>;

    /// Version string of the `otbr-agent` package.
    #[zbus(property)]
    fn otbr_version(&self) -> zbus::Result<String>;

    /// Version string of the host build.
    #[zbus(property)]
    fn ot_host_version(&self) -> zbus::Result<String>;

    /// Version string of the RCP firmware.
    #[zbus(property)]
    fn ot_rcp_version(&self) -> zbus::Result<String>;

    /// Thread protocol version.
    #[zbus(property)]
    fn thread_version(&self) -> zbus::Result<u16>;

    /// IEEE EUI-64 of this Thread interface.
    #[zbus(property)]
    fn eui64(&self) -> zbus::Result<u64>;

    /// 16-byte unique Border Agent ID advertised in `_meshcop._udp.`.
    #[zbus(property)]
    fn border_agent_id(&self) -> zbus::Result<Vec<u8>>;

    /// Radio spinel metrics.
    #[zbus(property)]
    fn radio_spinel_metrics(&self) -> zbus::Result<RadioSpinelMetrics>;

    /// RCP interface metrics.
    #[zbus(property)]
    fn rcp_interface_metrics(&self) -> zbus::Result<RcpInterfaceMetrics>;

    /// Number of milliseconds since the OpenThread instance was initialized.
    #[zbus(property)]
    fn uptime(&self) -> zbus::Result<u64>;

    /// Radio coexistence metrics.
    #[zbus(property)]
    fn radio_coex_metrics(&self) -> zbus::Result<RadioCoexMetrics>;

    /// NAT64 prefix-manager / translator state.
    #[zbus(property)]
    fn nat64_state(&self) -> zbus::Result<Nat64State>;

    /// Active NAT64 session mappings.
    #[zbus(property)]
    fn nat64_mappings(&self) -> zbus::Result<Vec<Nat64Mapping>>;

    /// NAT64 per-protocol counters.
    #[zbus(property)]
    fn nat64_protocol_counters(&self) -> zbus::Result<Nat64ProtocolCounters>;

    /// NAT64 drop counters by error class.
    #[zbus(property)]
    fn nat64_error_counters(&self) -> zbus::Result<Nat64ErrorCounters>;

    /// Border-routing counters.
    #[zbus(property)]
    fn border_routing_counters(&self) -> zbus::Result<BorderRoutingCounters>;

    /// Information about the infrastructure network interface.
    #[zbus(property)]
    fn infra_link_info(&self) -> zbus::Result<InfraLinkInfo>;

    /// TREL link info.
    #[zbus(property)]
    fn trel_info(&self) -> zbus::Result<TrelInfo>;

    /// `true` if multiple AILs (Adjacent IP Links) are detected on the
    /// Thread network.
    #[zbus(property)]
    fn multi_ail_detected(&self) -> zbus::Result<bool>;

    /// Thread telemetry, serialized `proto/thread_telemetry.proto`.
    #[zbus(property)]
    fn telemetry_data(&self) -> zbus::Result<Vec<u8>>;

    /// Thread capabilities, serialized `proto/capabilities.proto`.
    #[zbus(property)]
    fn capabilities(&self) -> zbus::Result<Vec<u8>>;

    // ---- Properties (read-write) ----

    /// Whether the ephemeral-key (ePSKc) Border Agent mode is enabled.
    #[zbus(property)]
    fn ephemeral_key_enabled(&self) -> zbus::Result<bool>;

    /// Set whether the ephemeral-key (ePSKc) Border Agent mode is enabled.
    #[zbus(property)]
    fn set_ephemeral_key_enabled(&self, value: bool) -> zbus::Result<()>;

    /// The /64 mesh-local prefix.
    #[zbus(property)]
    fn mesh_local_prefix(&self) -> zbus::Result<Vec<u8>>;

    /// Set the /64 mesh-local prefix.
    #[zbus(property)]
    fn set_mesh_local_prefix(&self, value: Vec<u8>) -> zbus::Result<()>;

    /// Current link mode.
    #[zbus(property)]
    fn link_mode(&self) -> zbus::Result<LinkMode>;

    /// Set the link mode.
    #[zbus(property)]
    fn set_link_mode(&self, value: LinkMode) -> zbus::Result<()>;

    /// Active Thread Operational Dataset, TLV-encoded. Empty if disabled
    /// or detached.
    #[zbus(property)]
    fn active_dataset_tlvs(&self) -> zbus::Result<Vec<u8>>;

    /// Set the Active Operational Dataset (TLV-encoded); triggers a
    /// re-attach.
    #[zbus(property)]
    fn set_active_dataset_tlvs(&self, value: Vec<u8>) -> zbus::Result<()>;

    /// Thread feature flags (`proto/feature_flag.proto`), raw bytes.
    #[zbus(property)]
    fn feature_flag_list_data(&self) -> zbus::Result<Vec<u8>>;

    /// Set the Thread feature flags (`proto/feature_flag.proto`).
    #[zbus(property)]
    fn set_feature_flag_list_data(&self, value: Vec<u8>) -> zbus::Result<()>;

    /// Radio region code (ISO 3166-1).
    #[zbus(property)]
    fn radio_region(&self) -> zbus::Result<String>;

    /// Set the radio region code (ISO 3166-1).
    #[zbus(property)]
    fn set_radio_region(&self, value: &str) -> zbus::Result<()>;

    /// CIDR used for NAT64.
    #[zbus(property)]
    fn nat64_cidr(&self) -> zbus::Result<String>;

    /// Set the CIDR used for NAT64.
    #[zbus(property)]
    fn set_nat64_cidr(&self, value: &str) -> zbus::Result<()>;

    /// Whether the server forwards DNS queries to the platform-configured
    /// upstream DNS servers.
    #[zbus(property)]
    fn dns_upstream_query_state(&self) -> zbus::Result<bool>;

    /// Set whether DNS queries are forwarded upstream.
    #[zbus(property)]
    fn set_dns_upstream_query_state(&self, value: bool) -> zbus::Result<()>;

    // ---- Signals ----

    /// Emitted once on startup, signalling that the Border Router is ready
    /// to accept requests.
    #[zbus(signal)]
    fn ready(&self) -> zbus::Result<()>;
}
