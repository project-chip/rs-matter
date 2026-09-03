//! Dispatch table: every `APICommand` (`matter_server/common/models.py`), matched against the
//! WS controller's switch (`WebSocketControllerHandler.ts:690-823`). Unknown command -> error 9,
//! same as `subscribe_attribute` (declared as a type but never wired into the real dispatch).
//!
//! Also home to the handlers that don't fit `nodes.rs` (commissioning/read/write/ping) or
//! `creds.rs` (credentials/fabric label/log level): device commands, ICD, ACL/bindings, device
//! fabrics — plus the shared argument-parsing helpers every handler file uses.

use std::sync::atomic::Ordering;

use serde_json::{json, Value as Json};

use crate::backend::{AclEntry, AclTarget, BindingTarget, InvokeOutcome};
use crate::names::camelize;
use crate::path::AttrPath;
use crate::wire::{Request, ServerError};

use super::events::Connection;
use super::Server;

pub async fn dispatch(
    server: &Server,
    conn: &Connection,
    req: &Request,
) -> Result<Json, ServerError> {
    let args = &req.args;
    match req.command.as_str() {
        "start_listening" => {
            conn.listening.store(true, Ordering::Relaxed);
            Ok(server.get_nodes(None).await)
        }
        "server_info" => Ok(server.server_info().await),
        "diagnostics" => Ok(server.diagnostics().await),
        "get_nodes" => Ok(server.get_nodes(opt_bool(args, "only_available")).await),
        "get_node" => server.get_node(req_u64(args, "node_id")?).await,
        "commission_with_code" => server.cmd_commission_with_code(args).await,
        "commission_on_network" => server.cmd_commission_on_network(args).await,
        "set_wifi_credentials" => server.cmd_set_wifi_credentials(args).await,
        "set_thread_dataset" => server.cmd_set_thread_dataset(args).await,
        "remove_wifi_credentials" => server.cmd_remove_wifi_credentials(args).await,
        "remove_thread_dataset" => server.cmd_remove_thread_dataset(args).await,
        "get_all_credentials" => Ok(server.creds.read().await.all_credentials_summary()),
        "get_thread_border_routers" => Ok(Json::Array(vec![])),
        "get_thread_diagnostics" => {
            conn.wants_thread.store(true, Ordering::Relaxed);
            Ok(cmd_thread_diagnostics(args))
        }
        "get_network_topology" => {
            conn.wants_topology.store(true, Ordering::Relaxed);
            Ok(cmd_network_topology())
        }
        "open_commissioning_window" => server.cmd_open_commissioning_window(args).await,
        "discover" | "discover_commissionable_nodes" => Ok(server.cmd_discover().await),
        "interview_node" => {
            server.interview(req_u64(args, "node_id")?).await?;
            Ok(Json::Null)
        }
        "get_icd_state" => server.cmd_icd_state(args).await,
        "register_icd" => server.cmd_register_icd(args).await,
        "resync_icd" => {
            server.ensure_node(req_u64(args, "node_id")?).await?;
            Ok(Json::Null)
        }
        "unregister_icd" => server.cmd_unregister_icd(args).await,
        "device_command" => server.cmd_device_command(args).await,
        "send_webrtc_provider_command" => {
            Err(ServerError::not_implemented("send_webrtc_provider_command"))
        }
        "remove_node" => server.cmd_remove_node(args).await,
        "get_vendor_names" => Ok(Json::Object(Default::default())),
        // Declared as a type only (WMT/model.ts), never reachable in the real dispatch switch.
        "subscribe_attribute" => Err(ServerError::invalid_command("subscribe_attribute")),
        "read_attribute" => server.cmd_read_attribute(args).await,
        "write_attribute" => server.cmd_write_attribute(args).await,
        "ping_node" => server.cmd_ping_node(args).await,
        "import_test_node" => {
            req_str(args, "dump")?;
            Ok(Json::Null)
        }
        "get_node_ip_addresses" => server.cmd_get_node_ip_addresses(args).await,
        "check_node_update" => {
            server.ensure_node(req_u64(args, "node_id")?).await?;
            Ok(Json::Null)
        }
        "update_node" => {
            server.ensure_node(req_u64(args, "node_id")?).await?;
            Ok(Json::Null)
        }
        "initiate_ota_upload" => Err(ServerError::not_implemented("initiate_ota_upload")),
        "get_matter_fabrics" => server.cmd_get_matter_fabrics(args).await,
        "remove_matter_fabric" => server.cmd_remove_matter_fabric(args).await,
        "set_acl_entry" => server.cmd_set_acl_entry(args).await,
        "set_node_binding" => server.cmd_set_node_binding(args).await,
        "set_default_fabric_label" => server.cmd_set_default_fabric_label(conn, args).await,
        "get_fabric_label" => Ok(server.cmd_get_fabric_label().await),
        "get_loglevel" => Ok(server.cmd_get_loglevel().await),
        "set_loglevel" => server.cmd_set_loglevel(args).await,
        other => Err(ServerError::invalid_command(other)),
    }
}

// ---- argument helpers, shared with nodes.rs / creds.rs ------------------------------------

pub(super) fn req_u64(args: &Json, key: &str) -> Result<u64, ServerError> {
    args.get(key).and_then(Json::as_u64).ok_or_else(|| {
        ServerError::invalid_arguments(format!("missing/invalid integer arg '{key}'"))
    })
}

pub(super) fn req_str<'a>(args: &'a Json, key: &str) -> Result<&'a str, ServerError> {
    args.get(key)
        .and_then(Json::as_str)
        .ok_or_else(|| ServerError::invalid_arguments(format!("missing string arg '{key}'")))
}

pub(super) fn opt_str<'a>(args: &'a Json, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Json::as_str)
}

pub(super) fn opt_u64(args: &Json, key: &str) -> Option<u64> {
    args.get(key).and_then(Json::as_u64)
}

pub(super) fn opt_u16(args: &Json, key: &str) -> Option<u16> {
    opt_u64(args, key).and_then(|v| v.try_into().ok())
}

pub(super) fn opt_u32(args: &Json, key: &str) -> Option<u32> {
    opt_u64(args, key).and_then(|v| v.try_into().ok())
}

pub(super) fn opt_bool(args: &Json, key: &str) -> Option<bool> {
    args.get(key).and_then(Json::as_bool)
}

pub(super) fn parse_attribute_paths(v: Option<&Json>) -> Result<Vec<AttrPath>, ServerError> {
    match v {
        Some(Json::String(s)) => Ok(vec![AttrPath::parse(s)]),
        Some(Json::Array(items)) => items
            .iter()
            .map(|it| {
                it.as_str().map(AttrPath::parse).ok_or_else(|| {
                    ServerError::invalid_arguments("attribute_path array must contain strings")
                })
            })
            .collect(),
        _ => Err(ServerError::invalid_arguments("missing attribute_path")),
    }
}

fn parse_acl_target(v: &Json) -> AclTarget {
    AclTarget {
        cluster: v.get("cluster").and_then(Json::as_u64).map(|x| x as u32),
        endpoint: v.get("endpoint").and_then(Json::as_u64).map(|x| x as u16),
        device_type: v
            .get("device_type")
            .and_then(Json::as_u64)
            .map(|x| x as u32),
    }
}

/// Minimal static table (WIRE_PROTOCOL.md §12: "omitted if unknown"). The full CSA vendor list is
/// `get_vendor_names` territory (Milestone 3), not needed for this one lookup.
fn vendor_name(vendor_id: u16) -> Option<&'static str> {
    match vendor_id {
        0xFFF1..=0xFFF4 => Some("Test Vendor"),
        _ => None,
    }
}

fn cmd_thread_diagnostics(args: &Json) -> Json {
    if opt_str(args, "ext_pan_id").is_some() {
        Json::Null
    } else {
        Json::Array(vec![])
    }
}

fn cmd_network_topology() -> Json {
    json!({"collected_at": super::now_ms(), "nodes": [], "connections": []})
}

// ---- command handlers that don't fit nodes.rs / creds.rs ----------------------------------

impl Server {
    async fn cmd_icd_state(&self, args: &Json) -> Result<Json, ServerError> {
        let id = req_u64(args, "node_id")?;
        self.ensure_node(id).await?;
        let state = self.backend.icd_state(id).await?;
        Ok(serde_json::to_value(state).unwrap_or(Json::Null))
    }

    async fn cmd_register_icd(&self, args: &Json) -> Result<Json, ServerError> {
        let id = req_u64(args, "node_id")?;
        self.ensure_node(id).await?;
        let state = self.backend.icd_register(id).await?;
        self.emit_node_updated(id).await;
        Ok(serde_json::to_value(state).unwrap_or(Json::Null))
    }

    async fn cmd_unregister_icd(&self, args: &Json) -> Result<Json, ServerError> {
        let id = req_u64(args, "node_id")?;
        self.ensure_node(id).await?;
        let force = opt_bool(args, "force").unwrap_or(false);
        let state = self.backend.icd_unregister(id, force).await?;
        self.emit_node_updated(id).await;
        Ok(serde_json::to_value(state).unwrap_or(Json::Null))
    }

    async fn cmd_device_command(&self, args: &Json) -> Result<Json, ServerError> {
        let node_id = req_u64(args, "node_id")?;
        self.ensure_node(node_id).await?;
        let endpoint = opt_u16(args, "endpoint_id")
            .ok_or_else(|| ServerError::invalid_arguments("missing endpoint_id"))?;
        let cluster = opt_u32(args, "cluster_id")
            .ok_or_else(|| ServerError::invalid_arguments("missing cluster_id"))?;
        let name = camelize(req_str(args, "command_name")?);
        let payload = args.get("payload").cloned().unwrap_or(Json::Null);
        let timed_ms = opt_u64(args, "timed_request_timeout_ms").and_then(|v| v.try_into().ok());
        let (command_id, fields) = self.names.encode_command(cluster, &name, &payload)?;
        let outcome = self
            .backend
            .invoke(node_id, endpoint, cluster, command_id, fields, timed_ms)
            .await?;
        Ok(match outcome {
            InvokeOutcome::Status(_) => Json::Null,
            InvokeOutcome::Fields(mv) => self.names.decode_response(cluster, &name, &mv),
        })
    }

    async fn cmd_get_matter_fabrics(&self, args: &Json) -> Result<Json, ServerError> {
        let node_id = req_u64(args, "node_id")?;
        self.ensure_node(node_id).await?;
        let fabrics = self.backend.device_fabrics(node_id).await?;
        let list: Vec<Json> = fabrics
            .into_iter()
            .map(|f| {
                let mut m = json!({
                    "fabric_id": f.fabric_id,
                    "vendor_id": f.vendor_id,
                    "fabric_index": f.fabric_index,
                    "fabric_label": f.fabric_label,
                });
                if let Some(name) = vendor_name(f.vendor_id) {
                    m.as_object_mut()
                        .unwrap()
                        .insert("vendor_name".into(), Json::String(name.into()));
                }
                m
            })
            .collect();
        Ok(Json::Array(list))
    }

    async fn cmd_remove_matter_fabric(&self, args: &Json) -> Result<Json, ServerError> {
        let node_id = req_u64(args, "node_id")?;
        self.ensure_node(node_id).await?;
        let fabric_index = req_u64(args, "fabric_index")? as u8;
        self.backend
            .remove_device_fabric(node_id, fabric_index)
            .await?;
        Ok(json!({}))
    }

    async fn cmd_set_acl_entry(&self, args: &Json) -> Result<Json, ServerError> {
        let node_id = req_u64(args, "node_id")?;
        let fabric_index = self.node_fabric_index(node_id).await?;
        let entries_json = args
            .get("entry")
            .and_then(Json::as_array)
            .ok_or_else(|| ServerError::invalid_arguments("missing entry array"))?;
        let mut entries = Vec::with_capacity(entries_json.len());
        for e in entries_json {
            let privilege = e
                .get("privilege")
                .and_then(Json::as_u64)
                .ok_or_else(|| ServerError::invalid_arguments("acl entry missing privilege"))?
                as u8;
            let auth_mode = e
                .get("auth_mode")
                .and_then(Json::as_u64)
                .ok_or_else(|| ServerError::invalid_arguments("acl entry missing auth_mode"))?
                as u8;
            // Subjects equal to the target node's own id are stripped (WIRE_PROTOCOL.md §13).
            let subjects: Vec<u64> = e
                .get("subjects")
                .and_then(Json::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Json::as_u64)
                        .filter(|s| *s != node_id)
                        .collect()
                })
                .unwrap_or_default();
            let targets = e
                .get("targets")
                .and_then(Json::as_array)
                .map(|arr| arr.iter().map(parse_acl_target).collect::<Vec<_>>());
            entries.push(AclEntry {
                privilege,
                auth_mode,
                subjects,
                targets,
                fabric_index,
            });
        }
        self.backend.set_acl(node_id, entries).await?;
        Ok(json!([{"path": {"endpoint_id": 0, "cluster_id": 31, "attribute_id": 0}, "status": 0}]))
    }

    async fn cmd_set_node_binding(&self, args: &Json) -> Result<Json, ServerError> {
        let node_id = req_u64(args, "node_id")?;
        self.ensure_node(node_id).await?;
        let endpoint = opt_u16(args, "endpoint")
            .ok_or_else(|| ServerError::invalid_arguments("missing endpoint"))?;
        let bindings_json = args
            .get("bindings")
            .and_then(Json::as_array)
            .ok_or_else(|| ServerError::invalid_arguments("missing bindings array"))?;
        let targets: Vec<BindingTarget> = bindings_json
            .iter()
            .map(|b| BindingTarget {
                node: b.get("node").and_then(Json::as_u64),
                group: b.get("group").and_then(Json::as_u64).map(|x| x as u16),
                endpoint: b.get("endpoint").and_then(Json::as_u64).map(|x| x as u16),
                cluster: b.get("cluster").and_then(Json::as_u64).map(|x| x as u32),
            })
            .collect();
        self.backend
            .set_bindings(node_id, endpoint, targets)
            .await?;
        Ok(
            json!([{"path": {"endpoint_id": endpoint, "cluster_id": 30, "attribute_id": 0}, "status": 0}]),
        )
    }
}
