//! Named credential lists + fabric label persistence (WIRE_PROTOCOL.md §11). One file,
//! `creds.json`, under the storage dir; secrets (`password`, `dataset`) never leave this module.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};

use crate::wire::{Event, ServerError};

use super::commands::opt_str;
use super::events::{Connection, EventGate};
use super::nodes::NodeRecord;
use super::{Server, MIN_SUPPORTED_SCHEMA_VERSION, SCHEMA_VERSION};

/// `"default"` / `"delete"` are reserved: matterjs never lets a caller create/rename an entry to
/// either (ConfigStorage.ts:26-27). `"default"` is the implicit/synthesized entry; `"delete"` is
/// reserved for a future bulk-delete sentinel and is simply refused today, same as upstream.
pub const RESERVED_IDS: [&str; 2] = ["default", "delete"];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WifiCred {
    pub ssid: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreadCred {
    pub dataset: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredStore {
    #[serde(default)]
    pub wifi: BTreeMap<String, WifiCred>,
    #[serde(default)]
    pub thread: BTreeMap<String, ThreadCred>,
    /// Persisted fabric label (independent of any live connection's ownership of it).
    #[serde(default)]
    pub fabric_label: Option<String>,
}

impl CredStore {
    pub fn load(storage_dir: &Path) -> Self {
        std::fs::read_to_string(creds_path(storage_dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, storage_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(storage_dir)?;
        // Secrets live here at rest, same as the ssid/password fields matterjs stores in its own
        // config file; keep the mode owner-only where the platform supports it.
        let data = serde_json::to_string_pretty(self).unwrap_or_default();
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(creds_path(storage_dir))?;
            f.write_all(data.as_bytes())
        }
        #[cfg(not(unix))]
        {
            std::fs::write(creds_path(storage_dir), data)
        }
    }

    /// `get_all_credentials` (WIRE_PROTOCOL.md §11): summaries only, `"default"` always present.
    pub fn all_credentials_summary(&self) -> Json {
        let mut wifi: Vec<Json> = self
            .wifi
            .iter()
            .map(|(id, c)| json!({"id": id, "ssid": c.ssid}))
            .collect();
        if !self.wifi.contains_key("default") {
            wifi.push(json!({"id": "default", "ssid": ""}));
        }
        let thread: Vec<Json> = self
            .thread
            .iter()
            .map(|(id, c)| {
                let (network_name, ext_pan_id) = parse_thread_dataset(&c.dataset);
                let mut entry = json!({"id": id});
                let obj = entry.as_object_mut().unwrap();
                if let Some(n) = network_name {
                    obj.insert("networkName".into(), Json::String(n));
                }
                if let Some(p) = ext_pan_id {
                    obj.insert("extPanId".into(), Json::String(p));
                }
                entry
            })
            .collect();
        json!({"wifi": wifi, "thread": thread})
    }

    pub fn wifi_credentials_set(&self) -> bool {
        self.wifi
            .get("default")
            .is_some_and(|w| !w.ssid.is_empty() && !w.password.is_empty())
    }

    pub fn wifi_ssid(&self) -> Option<&str> {
        self.wifi
            .get("default")
            .filter(|w| !w.ssid.is_empty() && !w.password.is_empty())
            .map(|w| w.ssid.as_str())
    }

    pub fn thread_credentials_set(&self) -> bool {
        self.thread
            .get("default")
            .is_some_and(|t| !t.dataset.is_empty())
    }
}

fn creds_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join("creds.json")
}

/// Best-effort Thread Operational Dataset TLV scan for `NetworkName` (type 0x03) and
/// `ExtendedPanId` (type 0x02, 8 bytes -> uppercase hex), given as a hex string. Returns `(None,
/// None)` for anything that doesn't parse as `type(1) len(1) value(len)` TLV — we do not need a
/// full dataset codec, only these two display fields (WIRE_PROTOCOL.md §11).
fn parse_thread_dataset(hex: &str) -> (Option<String>, Option<String>) {
    let Ok(bytes) = hex_decode(hex) else {
        return (None, None);
    };
    let mut i = 0;
    let mut name = None;
    let mut ext_pan_id = None;
    while i + 2 <= bytes.len() {
        let ty = bytes[i];
        let len = bytes[i + 1] as usize;
        let start = i + 2;
        if start + len > bytes.len() {
            break;
        }
        let val = &bytes[start..start + len];
        match ty {
            0x02 if len == 8 => ext_pan_id = Some(val.iter().map(|b| format!("{b:02X}")).collect()),
            0x03 => name = std::str::from_utf8(val).ok().map(str::to_owned),
            _ => {}
        }
        i = start + len;
    }
    (name, ext_pan_id)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// `normalizeFabricLabel` (WIRE_PROTOCOL.md §11): trim, empty -> "HomeAssistant", max 32 chars.
pub fn normalize_fabric_label(label: &str) -> String {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return "HomeAssistant".into();
    }
    trimmed.chars().take(32).collect()
}

fn canonical_level(input: &str) -> Result<&'static str, ServerError> {
    match input {
        "critical" | "fatal" => Ok("critical"),
        "error" => Ok("error"),
        "warning" | "warn" => Ok("warning"),
        "notice" => Ok("notice"),
        "info" => Ok("info"),
        "debug" => Ok("debug"),
        other => Err(ServerError::invalid_arguments(format!(
            "unknown log level '{other}'"
        ))),
    }
}

fn tracing_directive(canonical: &str) -> &'static str {
    match canonical {
        "critical" | "error" => "error",
        "warning" => "warn",
        "debug" => "debug",
        _ => "info", // notice, info
    }
}

impl Server {
    /// Also the bare object the binary pushes on WS connect, before any request
    /// (WIRE_PROTOCOL.md §1: "a bare `ServerInfoMessage` object").
    pub async fn server_info(&self) -> Json {
        let fabric = self.backend.fabric_info().await;
        let creds = self.creds.read().await;
        let mut obj = json!({
            "fabric_id": fabric.fabric_id,
            "compressed_fabric_id": fabric.compressed_fabric_id,
            "fabric_index": fabric.fabric_index,
            "schema_version": SCHEMA_VERSION,
            "min_supported_schema_version": MIN_SUPPORTED_SCHEMA_VERSION,
            "sdk_version": self.config.sdk_version,
            "wifi_credentials_set": creds.wifi_credentials_set(),
            "thread_credentials_set": creds.thread_credentials_set(),
            "bluetooth_enabled": false,
            "ble_proxy_enabled": false,
            "controller_node_id": fabric.controller_node_id,
        });
        if let Some(ssid) = creds.wifi_ssid() {
            obj.as_object_mut()
                .unwrap()
                .insert("wifi_ssid".into(), Json::String(ssid.to_string()));
        }
        obj
    }

    pub(super) async fn diagnostics(&self) -> Json {
        let info = self.server_info().await;
        let nodes: Vec<Json> = self
            .nodes
            .read()
            .await
            .values()
            .map(NodeRecord::to_json)
            .collect();
        let events = self.event_history.read().await.snapshot();
        json!({"info": info, "nodes": nodes, "events": events})
    }

    async fn broadcast_server_info_updated(&self) {
        let info = self.server_info().await;
        self.broadcaster
            .send(Event::new("server_info_updated", info), EventGate::Always);
    }

    pub(super) async fn cmd_set_wifi_credentials(&self, args: &Json) -> Result<Json, ServerError> {
        let ssid = super::commands::req_str(args, "ssid")?.to_string();
        let password = super::commands::req_str(args, "credentials")?.to_string();
        let id = opt_str(args, "id").unwrap_or("default");
        if id != "default" && RESERVED_IDS.contains(&id) {
            return Err(ServerError::invalid_arguments(format!(
                "credential id '{id}' is reserved"
            )));
        }
        {
            let mut creds = self.creds.write().await;
            creds
                .wifi
                .insert(id.to_string(), WifiCred { ssid, password });
            if let Err(e) = creds.save(&self.config.storage_dir) {
                tracing::warn!(error = %e, "failed to persist creds.json");
            }
        }
        self.broadcast_server_info_updated().await;
        Ok(json!({}))
    }

    pub(super) async fn cmd_set_thread_dataset(&self, args: &Json) -> Result<Json, ServerError> {
        let dataset = super::commands::req_str(args, "dataset")?.to_string();
        let id = opt_str(args, "id").unwrap_or("default");
        if id != "default" && RESERVED_IDS.contains(&id) {
            return Err(ServerError::invalid_arguments(format!(
                "credential id '{id}' is reserved"
            )));
        }
        {
            let mut creds = self.creds.write().await;
            creds.thread.insert(id.to_string(), ThreadCred { dataset });
            if let Err(e) = creds.save(&self.config.storage_dir) {
                tracing::warn!(error = %e, "failed to persist creds.json");
            }
        }
        self.broadcast_server_info_updated().await;
        Ok(json!({}))
    }

    pub(super) async fn cmd_remove_wifi_credentials(
        &self,
        args: &Json,
    ) -> Result<Json, ServerError> {
        let id = opt_str(args, "id").unwrap_or("default");
        {
            let mut creds = self.creds.write().await;
            creds.wifi.remove(id);
            let _ = creds.save(&self.config.storage_dir);
        }
        self.broadcast_server_info_updated().await;
        Ok(json!({}))
    }

    pub(super) async fn cmd_remove_thread_dataset(&self, args: &Json) -> Result<Json, ServerError> {
        let id = opt_str(args, "id").unwrap_or("default");
        {
            let mut creds = self.creds.write().await;
            creds.thread.remove(id);
            let _ = creds.save(&self.config.storage_dir);
        }
        self.broadcast_server_info_updated().await;
        Ok(json!({}))
    }

    pub(super) async fn cmd_set_default_fabric_label(
        &self,
        conn: &Connection,
        args: &Json,
    ) -> Result<Json, ServerError> {
        let raw = match args.get("label") {
            Some(Json::String(s)) => s.as_str(),
            Some(Json::Null) | None => "",
            _ => {
                return Err(ServerError::invalid_arguments(
                    "label must be a string or null",
                ))
            }
        };
        let normalized = normalize_fabric_label(raw);
        {
            let mut state = self.fabric_label.write().await;
            if state.pinned {
                return Ok(Json::Null); // CLI/env-pinned: permanent silent no-op.
            }
            if let Some(owner) = state.owner_conn {
                if owner != conn.id {
                    return Ok(Json::Null); // Owned by another live connection: silent no-op.
                }
            }
            state.owner_conn = Some(conn.id);
        }
        let mut creds = self.creds.write().await;
        creds.fabric_label = Some(normalized);
        let _ = creds.save(&self.config.storage_dir);
        Ok(Json::Null)
    }

    pub(super) async fn cmd_get_fabric_label(&self) -> Json {
        let label = self.creds.read().await.fabric_label.clone();
        json!({"fabric_label": label})
    }

    pub(super) async fn cmd_get_loglevel(&self) -> Json {
        let console = *self.console_level.read().await;
        let file = *self.file_level.read().await;
        json!({"console_loglevel": console, "file_loglevel": file})
    }

    pub(super) async fn cmd_set_loglevel(&self, args: &Json) -> Result<Json, ServerError> {
        if let Some(s) = opt_str(args, "console_loglevel") {
            let canonical = canonical_level(s)?;
            self.log.set_console_level(tracing_directive(canonical));
            *self.console_level.write().await = canonical;
        }
        if let Some(s) = opt_str(args, "file_loglevel") {
            let canonical = canonical_level(s)?;
            *self.file_level.write().await = Some(canonical);
        }
        Ok(self.cmd_get_loglevel().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_entry_always_present_and_secret_free() {
        let store = CredStore::default();
        let summary = store.all_credentials_summary();
        let wifi = summary["wifi"].as_array().unwrap();
        assert_eq!(wifi.len(), 1);
        assert_eq!(wifi[0]["id"], "default");
        assert_eq!(wifi[0]["ssid"], "");
        assert!(wifi[0].get("password").is_none());
        assert!(wifi[0].get("credentials").is_none());
    }

    #[test]
    fn secrets_never_in_summary_even_when_set() {
        let mut store = CredStore::default();
        store.wifi.insert(
            "default".into(),
            WifiCred {
                ssid: "MyWifi".into(),
                password: "hunter2".into(),
            },
        );
        let summary = store.all_credentials_summary();
        let json = summary.to_string();
        assert!(!json.contains("hunter2"));
        assert!(json.contains("MyWifi"));
        assert!(store.wifi_credentials_set());
        assert_eq!(store.wifi_ssid(), Some("MyWifi"));
    }

    #[test]
    fn normalize_label() {
        assert_eq!(normalize_fabric_label("  "), "HomeAssistant");
        assert_eq!(normalize_fabric_label(" Home "), "Home");
        let long = "x".repeat(40);
        assert_eq!(normalize_fabric_label(&long).len(), 32);
    }
}
