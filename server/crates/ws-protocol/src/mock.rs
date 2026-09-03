//! In-memory `Backend` for protocol-layer tests: configurable nodes/attributes, events fired
//! on demand via `push_attribute_change` / `push_availability`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{broadcast, RwLock};

use crate::backend::*;
use crate::path::{AttrPath, ConcretePath};
use crate::value::MValue;

#[derive(Debug, Clone)]
pub struct MockNode {
    pub identity: NodeIdentity,
    pub attrs: BTreeMap<ConcretePath, MValue>,
}

struct State {
    fabric: FabricSummary,
    nodes: HashMap<u64, MockNode>,
    subscribed: HashSet<u64>,
    next_node_id: u64,
    /// Records the most recent `invoke()` call so tests can assert what a `device_command`
    /// actually reached the backend as (cluster/command id/ctx-tagged fields), without needing a
    /// full fake device that echoes commands back over the wire.
    last_invoke: Option<(u16, u32, u32, MValue)>,
}

pub struct MockBackend {
    state: RwLock<State>,
    events_tx: broadcast::Sender<BackendEvent>,
}

impl MockBackend {
    pub fn new(fabric: FabricSummary) -> Self {
        let (events_tx, _) = broadcast::channel(256);
        Self {
            state: RwLock::new(State {
                fabric,
                nodes: HashMap::new(),
                subscribed: HashSet::new(),
                next_node_id: 1,
                last_invoke: None,
            }),
            events_tx,
        }
    }

    /// Test/setup helper: register a node with a starting attribute set.
    pub async fn add_node(&self, identity: NodeIdentity, attrs: Vec<(ConcretePath, MValue)>) {
        let mut state = self.state.write().await;
        state.nodes.insert(
            identity.node_id,
            MockNode {
                identity,
                attrs: attrs.into_iter().collect(),
            },
        );
    }

    /// Test helper: simulate a device-initiated report. Emits `AttributeChanged` unconditionally
    /// (a real backend would only report on an active subscription, but nothing here depends on
    /// that gate — `Server::start_listening` gates *delivery to a connection*, not backend fan-out).
    pub async fn push_attribute_change(&self, node: u64, path: ConcretePath, value: MValue) {
        {
            let mut state = self.state.write().await;
            if let Some(n) = state.nodes.get_mut(&node) {
                n.attrs.insert(path, value.clone());
            }
        }
        let _ = self.events_tx.send(BackendEvent::AttributeChanged {
            node_id: node,
            path,
            value,
        });
    }

    pub async fn push_availability(&self, node: u64, available: bool) {
        let _ = self.events_tx.send(BackendEvent::NodeAvailability {
            node_id: node,
            available,
        });
    }

    pub async fn is_subscribed(&self, node: u64) -> bool {
        self.state.read().await.subscribed.contains(&node)
    }

    /// Test helper: the `(endpoint, cluster, command, fields)` of the last `invoke()` call.
    pub async fn last_invoke(&self) -> Option<(u16, u32, u32, MValue)> {
        self.state.read().await.last_invoke.clone()
    }

    /// Test helper: simulate a device-originated event report (`node_event`, WIRE_PROTOCOL.md
    /// §3). Unlike `push_attribute_change` this has no cache to update — event history is a
    /// server-layer ring buffer, not backend state.
    #[allow(clippy::too_many_arguments)]
    pub async fn push_event(
        &self,
        node: u64,
        endpoint: u16,
        cluster: u32,
        event: u32,
        event_number: u64,
        priority: u8,
        timestamp_ms: Option<u64>,
        data: MValue,
    ) {
        let _ = self.events_tx.send(BackendEvent::Event {
            node_id: node,
            endpoint,
            cluster,
            event,
            event_number,
            priority,
            timestamp_ms,
            data,
        });
    }
}

#[async_trait]
impl Backend for MockBackend {
    async fn fabric_info(&self) -> FabricSummary {
        self.state.read().await.fabric
    }

    async fn nodes(&self) -> Vec<NodeIdentity> {
        self.state
            .read()
            .await
            .nodes
            .values()
            .map(|n| n.identity)
            .collect()
    }

    async fn commission_with_code(
        &self,
        _code: &str,
        _network_only: bool,
    ) -> Result<NodeIdentity, BErr> {
        let mut state = self.state.write().await;
        let node_id = state.next_node_id;
        state.next_node_id += 1;
        let fabric = state.fabric;
        let identity = NodeIdentity {
            node_id,
            fabric_id: fabric.fabric_id,
            fabric_index: fabric.fabric_index,
        };
        state.nodes.insert(
            node_id,
            MockNode {
                identity,
                attrs: BTreeMap::new(),
            },
        );
        Ok(identity)
    }

    async fn commission_on_network(
        &self,
        _pin: u32,
        _filter: DiscoveryFilter,
        _ip: Option<IpAddr>,
    ) -> Result<NodeIdentity, BErr> {
        self.commission_with_code("mock", true).await
    }

    async fn read(
        &self,
        node: u64,
        paths: &[AttrPath],
    ) -> Result<Vec<(ConcretePath, MValue)>, BErr> {
        let state = self.state.read().await;
        let n = state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        Ok(n.attrs
            .iter()
            .filter(|(p, _)| paths.iter().any(|ap| ap.matches(p)))
            .map(|(p, v)| (*p, v.clone()))
            .collect())
    }

    async fn write(
        &self,
        node: u64,
        path: ConcretePath,
        value: MValue,
        _timed_ms: Option<u16>,
    ) -> Result<Vec<(ConcretePath, u8)>, BErr> {
        {
            let mut state = self.state.write().await;
            let n = state
                .nodes
                .get_mut(&node)
                .ok_or_else(|| BErr::node_not_exists(node))?;
            n.attrs.insert(path, value.clone());
        }
        // There is no separate device process to echo the write back through a report: the mock
        // *is* the device state, so a write is observably the same as a device-originated change.
        // This is what lets a black-box WS test drive `attribute_updated` through nothing but the
        // public wire protocol (`write_attribute`), same as `push_attribute_change` for tests that
        // hold the `MockBackend` directly.
        let _ = self.events_tx.send(BackendEvent::AttributeChanged {
            node_id: node,
            path,
            value,
        });
        Ok(vec![(path, 0)])
    }

    async fn invoke(
        &self,
        node: u64,
        endpoint: u16,
        cluster: u32,
        command: u32,
        fields: MValue,
        _timed_ms: Option<u16>,
    ) -> Result<InvokeOutcome, BErr> {
        let mut state = self.state.write().await;
        state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        state.last_invoke = Some((endpoint, cluster, command, fields));
        Ok(InvokeOutcome::Status(0))
    }

    async fn subscribe_all(&self, node: u64) -> Result<(), BErr> {
        let mut state = self.state.write().await;
        state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        state.subscribed.insert(node);
        Ok(())
    }

    async fn unsubscribe(&self, node: u64) {
        self.state.write().await.subscribed.remove(&node);
    }

    async fn remove_node(&self, node: u64) -> Result<(), BErr> {
        let mut state = self.state.write().await;
        state
            .nodes
            .remove(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        state.subscribed.remove(&node);
        Ok(())
    }

    async fn open_commissioning_window(
        &self,
        node: u64,
        _timeout_s: u16,
        _discriminator: Option<u16>,
    ) -> Result<WindowCodes, BErr> {
        let state = self.state.read().await;
        state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        Ok(WindowCodes {
            setup_pin_code: 20202021,
            setup_manual_code: "34970112332".into(),
            setup_qr_code: "MT:Y.K9042C00KA0648G00".into(),
        })
    }

    async fn device_fabrics(&self, node: u64) -> Result<Vec<DeviceFabric>, BErr> {
        let state = self.state.read().await;
        let n = state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        Ok(vec![DeviceFabric {
            fabric_id: n.identity.fabric_id,
            vendor_id: 0xFFF1,
            fabric_index: n.identity.fabric_index,
            fabric_label: String::new(),
        }])
    }

    async fn remove_device_fabric(&self, node: u64, _fabric_index: u8) -> Result<(), BErr> {
        let state = self.state.read().await;
        state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        Ok(())
    }

    async fn update_fabric_label(&self, node: u64, _label: &str) -> Result<(), BErr> {
        let state = self.state.read().await;
        state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        Ok(())
    }

    async fn set_acl(&self, node: u64, _entries: Vec<AclEntry>) -> Result<(), BErr> {
        let state = self.state.read().await;
        state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        Ok(())
    }

    async fn set_bindings(
        &self,
        node: u64,
        _endpoint: u16,
        _targets: Vec<BindingTarget>,
    ) -> Result<(), BErr> {
        let state = self.state.read().await;
        state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        Ok(())
    }

    async fn node_addresses(&self, node: u64, _prefer_cache: bool) -> Result<Vec<IpAddr>, BErr> {
        let state = self.state.read().await;
        state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        Ok(vec!["127.0.0.1".parse().unwrap()])
    }

    async fn discover_commissionable(&self, _timeout: Duration) -> Vec<CommissionableNode> {
        Vec::new()
    }

    async fn icd_register(&self, node: u64) -> Result<IcdState, BErr> {
        let state = self.state.read().await;
        state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        Ok(IcdState::default())
    }

    async fn icd_unregister(&self, node: u64, _force: bool) -> Result<IcdState, BErr> {
        let state = self.state.read().await;
        state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        Ok(IcdState::default())
    }

    async fn icd_state(&self, node: u64) -> Result<IcdState, BErr> {
        let state = self.state.read().await;
        state
            .nodes
            .get(&node)
            .ok_or_else(|| BErr::node_not_exists(node))?;
        Ok(IcdState::default())
    }

    fn events(&self) -> broadcast::Receiver<BackendEvent> {
        self.events_tx.subscribe()
    }
}
