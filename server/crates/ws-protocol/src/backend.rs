//! The `Backend` trait (PLAN.md §3): everything HA-shaped lives in `server`, everything
//! Matter-stack-shaped lives behind this trait. `backend-mc` / `backend-rsm` implement it;
//! this crate ships `MockBackend` for protocol-layer tests.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::path::ConcretePath;
use crate::value::MValue;
use crate::wire::ServerError;

pub type BErr = ServerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_id: u64,
    pub fabric_id: u64,
    pub fabric_index: u8,
}

/// What `server_info` needs about our own (controller) fabric — WIRE_PROTOCOL.md §8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FabricSummary {
    pub fabric_id: u64,
    pub compressed_fabric_id: u64,
    pub fabric_index: u8,
    pub controller_node_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BackendEvent {
    AttributeChanged {
        node_id: u64,
        path: ConcretePath,
        value: MValue,
    },
    Event {
        node_id: u64,
        endpoint: u16,
        cluster: u32,
        event: u32,
        event_number: u64,
        priority: u8,
        timestamp_ms: Option<u64>,
        data: MValue,
    },
    NodeAvailability {
        node_id: u64,
        available: bool,
    },
    SubscriptionLost {
        node_id: u64,
    },
}

/// `commission_on_network` filter (WIRE_PROTOCOL.md §9). `filter_type` 4 (device type) is not
/// implemented upstream either and falls back to `None` at the server layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryFilter {
    None,
    ShortDiscriminator(u16),
    LongDiscriminator(u16),
    VendorId(u16),
}

/// `open_commissioning_window` result (WIRE_PROTOCOL.md §10 / `CommissioningParameters`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowCodes {
    pub setup_pin_code: u32,
    pub setup_manual_code: String,
    pub setup_qr_code: String,
}

/// One row of `get_matter_fabrics` (WIRE_PROTOCOL.md §12), minus `vendor_name` which the
/// server layer fills in from the static vendor-id table (backend has no vendor DB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceFabric {
    pub fabric_id: u64,
    pub vendor_id: u16,
    pub fabric_index: u8,
    pub fabric_label: String,
}

/// One ACL entry to write, `fabric_index` already resolved by the server (WIRE_PROTOCOL.md §13:
/// never client-supplied).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclEntry {
    pub privilege: u8,
    pub auth_mode: u8,
    pub subjects: Vec<u64>,
    pub targets: Option<Vec<AclTarget>>,
    pub fabric_index: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AclTarget {
    pub cluster: Option<u32>,
    pub endpoint: Option<u16>,
    pub device_type: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingTarget {
    pub node: Option<u64>,
    pub group: Option<u16>,
    pub endpoint: Option<u16>,
    pub cluster: Option<u32>,
}

/// `IcdStateData` (WIRE_PROTOCOL.md §14). Field names match the wire shape one-to-one; `Option`
/// fields serialize as `null` (never omitted — WIRE_PROTOCOL.md §14 shows them present-but-null).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct IcdState {
    pub supported: bool,
    pub lit_supported: bool,
    pub registered: bool,
    pub operating_mode: Option<String>,
    pub awake: Option<bool>,
    pub available: Option<bool>,
    pub next_expected_checkin: Option<u64>,
}

/// One `discover_commissionable_nodes` result element (WIRE_PROTOCOL.md §18). Field names match
/// the wire shape one-to-one, so the server layer serializes this directly.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize)]
pub struct CommissionableNode {
    pub instance_name: Option<String>,
    pub host_name: Option<String>,
    pub port: Option<u16>,
    pub long_discriminator: Option<u16>,
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    pub commissioning_mode: Option<u8>,
    pub device_type: Option<u32>,
    pub device_name: Option<String>,
    pub pairing_instruction: Option<String>,
    pub pairing_hint: Option<u16>,
    pub mrp_retry_interval_idle: Option<u32>,
    pub mrp_retry_interval_active: Option<u32>,
    pub supports_tcp: Option<bool>,
    pub addresses: Vec<String>,
    pub rotating_id: Option<String>,
}

/// Result of `invoke` (`device_command`): either response fields (tag-based, TLV-shaped — the
/// server layer name-decodes them via `CommandNames`) or a bare status for status-only commands
/// (WIRE_PROTOCOL.md §7: "Status-only success -> null").
#[derive(Debug, Clone, PartialEq)]
pub enum InvokeOutcome {
    Fields(MValue),
    Status(u8),
}

#[async_trait]
pub trait Backend: Send + Sync {
    async fn fabric_info(&self) -> FabricSummary;
    async fn nodes(&self) -> Vec<NodeIdentity>;
    async fn commission_with_code(
        &self,
        code: &str,
        network_only: bool,
    ) -> Result<NodeIdentity, BErr>;
    async fn commission_on_network(
        &self,
        pin: u32,
        filter: DiscoveryFilter,
        ip: Option<IpAddr>,
    ) -> Result<NodeIdentity, BErr>;
    async fn read(
        &self,
        node: u64,
        paths: &[crate::path::AttrPath],
    ) -> Result<Vec<(ConcretePath, MValue)>, BErr>;
    async fn write(
        &self,
        node: u64,
        path: ConcretePath,
        value: MValue,
        timed_ms: Option<u16>,
    ) -> Result<Vec<(ConcretePath, u8)>, BErr>;
    #[allow(clippy::too_many_arguments)]
    async fn invoke(
        &self,
        node: u64,
        endpoint: u16,
        cluster: u32,
        command: u32,
        fields: MValue,
        timed_ms: Option<u16>,
    ) -> Result<InvokeOutcome, BErr>;
    /// Whole-node subscription (attrs + events); backend keeps it alive and feeds `events()`.
    async fn subscribe_all(&self, node: u64) -> Result<(), BErr>;
    async fn unsubscribe(&self, node: u64);
    /// `RemoveFabric` on the device, then forget it locally.
    async fn remove_node(&self, node: u64) -> Result<(), BErr>;
    async fn open_commissioning_window(
        &self,
        node: u64,
        timeout_s: u16,
        discriminator: Option<u16>,
    ) -> Result<WindowCodes, BErr>;
    async fn device_fabrics(&self, node: u64) -> Result<Vec<DeviceFabric>, BErr>;
    async fn remove_device_fabric(&self, node: u64, fabric_index: u8) -> Result<(), BErr>;
    async fn update_fabric_label(&self, node: u64, label: &str) -> Result<(), BErr>;
    async fn set_acl(&self, node: u64, entries: Vec<AclEntry>) -> Result<(), BErr>;
    async fn set_bindings(
        &self,
        node: u64,
        endpoint: u16,
        targets: Vec<BindingTarget>,
    ) -> Result<(), BErr>;
    async fn node_addresses(&self, node: u64, prefer_cache: bool) -> Result<Vec<IpAddr>, BErr>;
    async fn discover_commissionable(&self, timeout: Duration) -> Vec<CommissionableNode>;
    async fn icd_register(&self, node: u64) -> Result<IcdState, BErr>;
    async fn icd_unregister(&self, node: u64, force: bool) -> Result<IcdState, BErr>;
    async fn icd_state(&self, node: u64) -> Result<IcdState, BErr>;
    fn events(&self) -> broadcast::Receiver<BackendEvent>;
}
