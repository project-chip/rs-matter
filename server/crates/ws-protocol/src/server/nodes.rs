//! `MatterNodeData` (WIRE_PROTOCOL.md §2): the interview cache and node-object JSON shape, plus
//! the commissioning/read/write/ping command handlers that operate on it.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use serde_json::{json, Value as Json};

use crate::backend::{DiscoveryFilter, NodeIdentity};
use crate::path::{AttrPath, ConcretePath};
use crate::value::MValue;
use crate::wire::{Event, ServerError};

use super::commands::{opt_bool, opt_str, opt_u16, opt_u64, req_str, req_u64};
use super::events::EventGate;
use super::Server;

#[derive(Debug, Clone)]
pub struct NodeRecord {
    pub node_id: u64,
    /// This node's index for *our* fabric, as reported by the device at commission time — needed
    /// to fill `fabric_index` on ACL entries we write (WIRE_PROTOCOL.md §13). Not part of the
    /// `MatterNodeData` wire shape itself (§2 has no `fabric_id`/`fabric_index` field).
    pub fabric_index: u8,
    pub date_commissioned: String,
    pub last_interview: String,
    pub attrs: BTreeMap<ConcretePath, MValue>,
    pub available: bool,
}

/// `getDateAsString` (Converters.ts:728-739): local wall-clock, millisecond precision, the
/// microsecond field always padded `000` (JS `Date` has no microseconds). We use UTC — only the
/// format, not the timezone, is part of the wire contract.
pub fn wire_timestamp_now() -> String {
    wire_timestamp(std::time::SystemTime::now())
}

pub fn wire_timestamp(t: std::time::SystemTime) -> String {
    let dur = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs() as i64;
    let millis = dur.subsec_millis();
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}000")
}

/// Howard Hinnant's `civil_from_days`, extended with the time-of-day split. Avoids pulling in a
/// full datetime crate for one formatting helper.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn civil_from_unix(unix_secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix_secs.div_euclid(86400);
    let secs_of_day = unix_secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let h = (secs_of_day / 3600) as u32;
    let mi = ((secs_of_day % 3600) / 60) as u32;
    let s = (secs_of_day % 60) as u32;
    (y, m, d, h, mi, s)
}

impl NodeRecord {
    /// Basic Information `SpecificationVersion` packing per the CSA core spec:
    /// `0xMMmmpp00` (major/minor/patch, one reserved byte).
    fn is_bridge(&self) -> bool {
        let path = ConcretePath {
            endpoint: 1,
            cluster: 29,
            attribute: 0,
        };
        match self.attrs.get(&path) {
            Some(MValue::Array(items)) => items.iter().any(|item| {
                matches!(item, MValue::Struct(members)
                    if members.iter().any(|(tag, v)| *tag == 0 && matches!(v, MValue::U(14))))
            }),
            _ => false,
        }
    }

    fn matter_version(&self) -> Option<String> {
        let spec_path = ConcretePath {
            endpoint: 0,
            cluster: 40,
            attribute: 21,
        };
        if let Some(MValue::U(v)) = self.attrs.get(&spec_path) {
            if *v > 0 {
                let major = (v >> 24) & 0xFF;
                let minor = (v >> 16) & 0xFF;
                let patch = (v >> 8) & 0xFF;
                return Some(format!("{major}.{minor}.{patch}"));
            }
        }
        let dmr_path = ConcretePath {
            endpoint: 0,
            cluster: 40,
            attribute: 0,
        };
        match self.attrs.get(&dmr_path) {
            Some(MValue::U(v)) if *v <= 16 => Some("<1.2.0".into()),
            Some(MValue::U(17)) => Some("1.2.0".into()),
            _ => None,
        }
    }

    /// The full `MatterNodeData` object (WIRE_PROTOCOL.md §2).
    pub fn to_json(&self) -> Json {
        let mut attributes = serde_json::Map::with_capacity(self.attrs.len());
        for (path, val) in &self.attrs {
            attributes.insert(path.to_string(), val.to_json());
        }
        let mut obj = json!({
            "node_id": self.node_id,
            "date_commissioned": self.date_commissioned,
            "last_interview": self.last_interview,
            "interview_version": 6,
            "available": self.available,
            "is_bridge": self.is_bridge(),
            "attributes": Json::Object(attributes),
            "attribute_subscriptions": [],
        });
        if let Some(v) = self.matter_version() {
            obj.as_object_mut()
                .unwrap()
                .insert("matter_version".into(), Json::String(v));
        }
        obj
    }
}

impl Server {
    pub(super) async fn ensure_node(&self, id: u64) -> Result<(), ServerError> {
        if self.nodes.read().await.contains_key(&id) {
            Ok(())
        } else {
            Err(ServerError::node_not_exists(id))
        }
    }

    /// This node's index for *our* fabric — needed to fill `fabric_index` on ACL entries
    /// (`commands::cmd_set_acl_entry`, WIRE_PROTOCOL.md §13).
    pub(super) async fn node_fabric_index(&self, id: u64) -> Result<u8, ServerError> {
        self.nodes
            .read()
            .await
            .get(&id)
            .map(|n| n.fabric_index)
            .ok_or_else(|| ServerError::node_not_exists(id))
    }

    pub(super) async fn get_nodes(&self, only_available: Option<bool>) -> Json {
        let nodes = self.nodes.read().await;
        let list: Vec<Json> = nodes
            .values()
            .filter(|n| only_available != Some(true) || n.available)
            .map(NodeRecord::to_json)
            .collect();
        Json::Array(list)
    }

    pub(super) async fn get_node(&self, id: u64) -> Result<Json, ServerError> {
        self.nodes
            .read()
            .await
            .get(&id)
            .map(NodeRecord::to_json)
            .ok_or_else(|| ServerError::node_not_exists(id))
    }

    pub(super) async fn emit_node_updated(&self, id: u64) {
        if let Some(json) = self.nodes.read().await.get(&id).map(NodeRecord::to_json) {
            self.broadcaster
                .send(Event::new("node_updated", json), EventGate::Listening);
        }
    }

    /// Populates/refreshes the interview cache for an already-registered node id.
    pub(super) async fn interview(&self, node_id: u64) -> Result<Json, ServerError> {
        let results = self.backend.read(node_id, &[AttrPath::default()]).await?;
        let mut nodes = self.nodes.write().await;
        let rec = nodes
            .get_mut(&node_id)
            .ok_or_else(|| ServerError::node_not_exists(node_id))?;
        rec.attrs = results.into_iter().collect();
        rec.last_interview = wire_timestamp_now();
        Ok(rec.to_json())
    }

    async fn commission_common(&self, identity: NodeIdentity) -> Result<Json, ServerError> {
        let now = wire_timestamp_now();
        {
            let mut nodes = self.nodes.write().await;
            nodes.insert(
                identity.node_id,
                NodeRecord {
                    node_id: identity.node_id,
                    fabric_index: identity.fabric_index,
                    date_commissioned: now.clone(),
                    last_interview: now,
                    attrs: Default::default(),
                    available: true,
                },
            );
        }
        let node_json = self.interview(identity.node_id).await?;
        if let Err(e) = self.backend.subscribe_all(identity.node_id).await {
            tracing::warn!(node_id = identity.node_id, error = %e, "post-commission subscribe failed");
        }
        self.broadcaster.send(
            Event::new("node_added", node_json.clone()),
            EventGate::Listening,
        );
        Ok(node_json)
    }

    pub(super) async fn cmd_commission_with_code(&self, args: &Json) -> Result<Json, ServerError> {
        let code = req_str(args, "code")?;
        let network_only = opt_bool(args, "network_only").unwrap_or(false);
        let identity = self
            .backend
            .commission_with_code(code, network_only)
            .await?;
        self.commission_common(identity).await
    }

    pub(super) async fn cmd_commission_on_network(&self, args: &Json) -> Result<Json, ServerError> {
        let pin = req_u64(args, "setup_pin_code")? as u32;
        let filter_type = opt_u64(args, "filter_type").unwrap_or(0);
        let filter_val = opt_u64(args, "filter");
        let filter = match filter_type {
            0 => DiscoveryFilter::None,
            1 => DiscoveryFilter::ShortDiscriminator(filter_val.ok_or_else(|| {
                ServerError::invalid_arguments("filter required for filter_type 1")
            })? as u16),
            2 => DiscoveryFilter::LongDiscriminator(filter_val.ok_or_else(|| {
                ServerError::invalid_arguments("filter required for filter_type 2")
            })? as u16),
            3 => DiscoveryFilter::VendorId(filter_val.ok_or_else(|| {
                ServerError::invalid_arguments("filter required for filter_type 3")
            })? as u16),
            4 => {
                tracing::warn!("filter_type 4 (device type) is not implemented upstream either; using unfiltered discovery");
                DiscoveryFilter::None
            }
            other => {
                return Err(ServerError::invalid_arguments(format!(
                    "unknown filter_type {other}"
                )))
            }
        };
        let ip = opt_str(args, "ip_addr").and_then(|s| {
            if s.starts_with("fe80") {
                None // link-local is ignored (WIRE_PROTOCOL.md §9)
            } else {
                s.parse::<IpAddr>().ok()
            }
        });
        let identity = self.backend.commission_on_network(pin, filter, ip).await?;
        self.commission_common(identity).await
    }

    pub(super) async fn cmd_open_commissioning_window(
        &self,
        args: &Json,
    ) -> Result<Json, ServerError> {
        let id = req_u64(args, "node_id")?;
        self.ensure_node(id).await?;
        let timeout = opt_u64(args, "timeout").unwrap_or(300) as u16;
        let discriminator = opt_u16(args, "discriminator");
        let codes = self
            .backend
            .open_commissioning_window(id, timeout, discriminator)
            .await?;
        Ok(json!({
            "setup_pin_code": codes.setup_pin_code,
            "setup_manual_code": codes.setup_manual_code,
            "setup_qr_code": codes.setup_qr_code,
        }))
    }

    /// `discover` and `discover_commissionable_nodes` share this: a 3s scan, only the last
    /// result returned as a one-element array (or `[]`) — WIRE_PROTOCOL.md §18.
    pub(super) async fn cmd_discover(&self) -> Json {
        let mut found = self
            .backend
            .discover_commissionable(Duration::from_secs(3))
            .await;
        match found.pop() {
            Some(n) => Json::Array(vec![serde_json::to_value(n).unwrap_or(Json::Null)]),
            None => Json::Array(vec![]),
        }
    }

    pub(super) async fn cmd_remove_node(&self, args: &Json) -> Result<Json, ServerError> {
        let id = req_u64(args, "node_id")?;
        self.ensure_node(id).await?;
        self.backend.remove_node(id).await?;
        self.backend.unsubscribe(id).await;
        self.nodes.write().await.remove(&id);
        self.broadcaster
            .send(Event::new("node_removed", json!(id)), EventGate::Listening);
        Ok(Json::Null)
    }

    pub(super) async fn cmd_read_attribute(&self, args: &Json) -> Result<Json, ServerError> {
        let node_id = req_u64(args, "node_id")?;
        self.ensure_node(node_id).await?;
        let paths = super::commands::parse_attribute_paths(args.get("attribute_path"))?;
        let results = self.backend.read(node_id, &paths).await?;
        let mut out = serde_json::Map::new();
        for (p, v) in results {
            out.insert(p.to_string(), v.to_json());
        }
        if out.is_empty() {
            return Err(ServerError::sdk_stack(
                "Failed to read attribute: no values returned",
            ));
        }
        Ok(Json::Object(out))
    }

    pub(super) async fn cmd_write_attribute(&self, args: &Json) -> Result<Json, ServerError> {
        let node_id = req_u64(args, "node_id")?;
        // matterjs-server validates the path (wildcards rejected) *before* resolving the node
        // handler (`WebSocketControllerHandler.ts#handleWriteAttribute`, WIRE_PROTOCOL.md §6):
        // an unknown node with a wildcard path still gets error 8, not 5. Keep this check first.
        let path = AttrPath::parse(req_str(args, "attribute_path")?);
        let concrete = path.as_concrete().ok_or_else(|| {
            ServerError::invalid_arguments("write_attribute requires a concrete attribute_path")
        })?;
        let value = MValue::from_json(args.get("value").unwrap_or(&Json::Null))
            .map_err(|e| ServerError::invalid_arguments(e.to_string()))?;
        self.ensure_node(node_id).await?;
        let results = self.backend.write(node_id, concrete, value, None).await?;
        let arr: Vec<Json> = results
            .into_iter()
            .map(|(p, status)| {
                json!({
                    "Path": {"EndpointId": p.endpoint, "ClusterId": p.cluster, "AttributeId": p.attribute},
                    "Status": status,
                })
            })
            .collect();
        Ok(Json::Array(arr))
    }

    pub(super) async fn cmd_ping_node(&self, args: &Json) -> Result<Json, ServerError> {
        let node_id = req_u64(args, "node_id")?;
        self.ensure_node(node_id).await?;
        let addrs = self.backend.node_addresses(node_id, false).await?;
        let mut out = serde_json::Map::with_capacity(addrs.len());
        for addr in addrs {
            let reachable = ping_ip(addr).await;
            out.insert(addr.to_string(), Json::Bool(reachable));
        }
        Ok(Json::Object(out))
    }

    pub(super) async fn cmd_get_node_ip_addresses(&self, args: &Json) -> Result<Json, ServerError> {
        let node_id = req_u64(args, "node_id")?;
        self.ensure_node(node_id).await?;
        let prefer_cache = opt_bool(args, "prefer_cache").unwrap_or(true);
        let scoped = opt_bool(args, "scoped").unwrap_or(false);
        let addrs = self.backend.node_addresses(node_id, prefer_cache).await?;
        let list: Vec<Json> = addrs
            .into_iter()
            .map(|a| {
                let s = a.to_string();
                let s = if scoped {
                    s
                } else {
                    s.split('%').next().unwrap_or(&s).to_string()
                };
                Json::String(s)
            })
            .collect();
        Ok(Json::Array(list))
    }
}

async fn ping_ip(addr: IpAddr) -> bool {
    tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", "2"])
        .arg(addr.to_string())
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(epoch_ms: u64) -> String {
        wire_timestamp(std::time::UNIX_EPOCH + std::time::Duration::from_millis(epoch_ms))
    }

    #[test]
    fn format_matches_spec_pattern() {
        // 2026-09-03T00:00:00.000 UTC == 1788393600000 ms
        let s = ts(1_788_393_600_000);
        assert_eq!(s, "2026-09-03T00:00:00.000000");
    }

    #[test]
    fn is_bridge_detects_aggregator_device_type() {
        let mut attrs = BTreeMap::new();
        attrs.insert(
            ConcretePath {
                endpoint: 1,
                cluster: 29,
                attribute: 0,
            },
            MValue::Array(vec![MValue::Struct(vec![
                (0, MValue::U(14)),
                (1, MValue::U(1)),
            ])]),
        );
        let rec = NodeRecord {
            node_id: 1,
            fabric_index: 1,
            date_commissioned: String::new(),
            last_interview: String::new(),
            attrs,
            available: true,
        };
        assert!(rec.to_json()["is_bridge"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn write_attribute_rejects_wildcard_before_checking_node_existence() {
        // WIRE_PROTOCOL.md §6 / matterjs-server WebSocketControllerHandler.ts#handleWriteAttribute:
        // the wildcard-path check happens before the node lookup, so an unknown node id with a
        // wildcard path must still surface error 8 (InvalidArguments), never error 5 (NodeNotExists).
        use crate::backend::FabricSummary;
        use crate::mock::MockBackend;
        use crate::names::NoNames;
        use crate::server::{NoLogControl, Server, ServerConfig};
        use std::sync::Arc;

        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ws-protocol-write-attr-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let backend = Arc::new(MockBackend::new(FabricSummary {
            fabric_id: 1,
            compressed_fabric_id: 0x1234_5678_9abc_def0,
            fabric_index: 1,
            controller_node_id: 112233,
        }));
        let server = Server::new(
            backend,
            Arc::new(NoNames),
            ServerConfig {
                sdk_version: "test/0.0.0".into(),
                storage_dir: dir.clone(),
                default_fabric_label: None,
            },
            Arc::new(NoLogControl),
        );
        let conn = server.connect();

        let req = crate::wire::Request {
            message_id: "1".into(),
            command: "write_attribute".into(),
            args: json!({"node_id": 999999, "attribute_path": "1/6/*", "value": true}),
        };
        let err = server.handle(&conn, &req).await.unwrap_err();
        assert_eq!(u16::from(err.code), 8, "wildcard path must be rejected as InvalidArguments, not NodeNotExists, even for an unknown node");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn matter_version_from_spec_version() {
        let mut attrs = BTreeMap::new();
        // 1.3.0 -> 0x01030000
        attrs.insert(
            ConcretePath {
                endpoint: 0,
                cluster: 40,
                attribute: 21,
            },
            MValue::U(0x0103_0000),
        );
        let rec = NodeRecord {
            node_id: 1,
            fabric_index: 1,
            date_commissioned: String::new(),
            last_interview: String::new(),
            attrs,
            available: true,
        };
        assert_eq!(rec.to_json()["matter_version"], "1.3.0");
    }
}
