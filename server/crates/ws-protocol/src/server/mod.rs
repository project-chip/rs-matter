//! The shared, backend-agnostic server (PLAN.md §3): interview cache, credential store, fabric
//! label ownership, event history, per-connection gating. Implements every `APICommand`
//! (`matter_server/common/models.py`) against a `Backend`.

mod commands;
mod creds;
mod events;
mod nodes;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::Value as Json;
use tokio::sync::RwLock;

use crate::backend::{Backend, BackendEvent};
use crate::names::CommandNames;
use crate::wire::{Request, ServerError};

pub use events::Connection;
use events::{Broadcaster, EventGate, EventHistory};
use nodes::NodeRecord;

pub const SCHEMA_VERSION: u32 = 13;
pub const MIN_SUPPORTED_SCHEMA_VERSION: u32 = 11;

pub struct ServerConfig {
    /// e.g. `"matter-fast/0.1.0 (backend-mock)"` — WIRE_PROTOCOL.md §8 `sdk_version`.
    pub sdk_version: String,
    pub storage_dir: PathBuf,
    /// `--default-fabric-label` / env pin: when set, `set_default_fabric_label` is a permanent
    /// silent no-op (WIRE_PROTOCOL.md §11).
    pub default_fabric_label: Option<String>,
}

struct FabricLabelState {
    owner_conn: Option<u64>,
    pinned: bool,
}

/// Log-level reload seam (T2 owns the mapping; the reload mechanism itself is the binary's
/// tracing-subscriber handle). `None` is a valid no-op control, used in tests.
pub trait LogControl: Send + Sync {
    fn set_console_level(&self, tracing_directive: &str);
}

pub struct NoLogControl;
impl LogControl for NoLogControl {
    fn set_console_level(&self, _tracing_directive: &str) {}
}

pub struct Server {
    backend: Arc<dyn Backend>,
    names: Arc<dyn CommandNames>,
    config: ServerConfig,
    nodes: RwLock<HashMap<u64, NodeRecord>>,
    creds: RwLock<creds::CredStore>,
    fabric_label: RwLock<FabricLabelState>,
    broadcaster: Broadcaster,
    event_history: RwLock<EventHistory>,
    next_conn_id: AtomicU64,
    log: Arc<dyn LogControl>,
    console_level: RwLock<&'static str>,
    file_level: RwLock<Option<&'static str>>,
}

impl Server {
    pub fn new(
        backend: Arc<dyn Backend>,
        names: Arc<dyn CommandNames>,
        config: ServerConfig,
        log: Arc<dyn LogControl>,
    ) -> Arc<Self> {
        let mut creds = creds::CredStore::load(&config.storage_dir);
        let pinned = config.default_fabric_label.is_some();
        if let Some(pin) = &config.default_fabric_label {
            creds.fabric_label = Some(pin.clone());
        }
        let server = Arc::new(Self {
            backend,
            names,
            config,
            nodes: RwLock::new(HashMap::new()),
            creds: RwLock::new(creds),
            fabric_label: RwLock::new(FabricLabelState {
                owner_conn: None,
                pinned,
            }),
            broadcaster: Broadcaster::new(),
            event_history: RwLock::new(EventHistory::default()),
            next_conn_id: AtomicU64::new(1),
            log,
            console_level: RwLock::new("info"),
            file_level: RwLock::new(None),
        });
        // Subscribe synchronously, before spawning: `broadcast::Sender::send` silently drops an
        // event when it has zero receivers, so subscribing from inside the spawned task would
        // leave a window (until that task is first polled) where a backend event fired right
        // after `Server::new` returns is lost. Taking the receiver here means the very next
        // `Backend::events()` call already has a live subscriber.
        let rx = server.backend.events();
        tokio::spawn(forward_backend_events(Arc::clone(&server), rx));
        server
    }

    pub fn connect(&self) -> Connection {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        self.broadcaster.subscribe(id)
    }

    pub async fn disconnect(&self, conn_id: u64) {
        let mut label = self.fabric_label.write().await;
        if label.owner_conn == Some(conn_id) {
            label.owner_conn = None;
        }
    }

    /// Dispatches one request. Never panics on bad input; every error path is a `ServerError`
    /// with the wire-correct code (WIRE_PROTOCOL.md §1).
    pub async fn handle(&self, conn: &Connection, req: &Request) -> Result<Json, ServerError> {
        commands::dispatch(self, conn, req).await
    }
}

async fn forward_backend_events(
    server: Arc<Server>,
    mut rx: tokio::sync::broadcast::Receiver<BackendEvent>,
) {
    loop {
        match rx.recv().await {
            Ok(ev) => server.handle_backend_event(ev).await,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

impl Server {
    async fn handle_backend_event(&self, ev: BackendEvent) {
        match ev {
            BackendEvent::AttributeChanged {
                node_id,
                path,
                value,
            } => {
                {
                    let mut nodes = self.nodes.write().await;
                    if let Some(rec) = nodes.get_mut(&node_id) {
                        rec.attrs.insert(path, value.clone());
                    }
                }
                let data = serde_json::json!([node_id, path.to_string(), value.to_json()]);
                self.broadcaster.send(
                    crate::wire::Event::new("attribute_updated", data),
                    EventGate::Listening,
                );
            }
            BackendEvent::Event {
                node_id,
                endpoint,
                cluster,
                event,
                event_number,
                priority,
                timestamp_ms,
                data,
            } => {
                let (timestamp, timestamp_type) = match timestamp_ms {
                    Some(ms) => (ms, 1u8),
                    None => (now_ms(), 2u8),
                };
                let decoded = self.names.decode_event(cluster, event, &data);
                let payload = serde_json::json!({
                    "node_id": node_id,
                    "endpoint_id": endpoint,
                    "cluster_id": cluster,
                    "event_id": event,
                    "event_number": event_number,
                    "priority": priority,
                    "timestamp": timestamp,
                    "timestamp_type": timestamp_type,
                    "data": decoded,
                });
                self.event_history.write().await.push(payload.clone());
                self.broadcaster.send(
                    crate::wire::Event::new("node_event", payload),
                    EventGate::Listening,
                );
            }
            BackendEvent::NodeAvailability { node_id, available } => {
                let updated = {
                    let mut nodes = self.nodes.write().await;
                    nodes.get_mut(&node_id).map(|rec| {
                        rec.available = available;
                        rec.to_json()
                    })
                };
                if let Some(node_json) = updated {
                    self.broadcaster.send(
                        crate::wire::Event::new("node_updated", node_json),
                        EventGate::Listening,
                    );
                }
            }
            BackendEvent::SubscriptionLost { node_id } => {
                tracing::warn!(node_id, "backend subscription lost");
            }
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::FabricSummary;
    use crate::mock::MockBackend;
    use crate::names::NoNames;

    fn fabric() -> FabricSummary {
        FabricSummary {
            fabric_id: 1,
            compressed_fabric_id: 0x1234_5678_9abc_def0,
            fabric_index: 1,
            controller_node_id: 112233,
        }
    }

    async fn test_server(dir: &std::path::Path) -> Arc<Server> {
        let backend = Arc::new(MockBackend::new(fabric()));
        Server::new(
            backend,
            Arc::new(NoNames),
            ServerConfig {
                sdk_version: "test/0.0.0".into(),
                storage_dir: dir.to_path_buf(),
                default_fabric_label: None,
            },
            Arc::new(NoLogControl),
        )
    }

    #[tokio::test]
    async fn credential_store_default_entry_and_no_secrets_via_server() {
        let dir = tempdir();
        let server = test_server(dir.path()).await;
        let conn = server.connect();

        let req = Request {
            message_id: "1".into(),
            command: "set_wifi_credentials".into(),
            args: serde_json::json!({"ssid": "MyWifi", "credentials": "hunter2"}),
        };
        server.handle(&conn, &req).await.unwrap();

        let req2 = Request {
            message_id: "2".into(),
            command: "get_all_credentials".into(),
            args: serde_json::json!({}),
        };
        let result = server.handle(&conn, &req2).await.unwrap();
        let text = result.to_string();
        assert!(!text.contains("hunter2"));
        assert!(text.contains("MyWifi"));

        let info_req = Request {
            message_id: "3".into(),
            command: "server_info".into(),
            args: serde_json::json!({}),
        };
        let info = server.handle(&conn, &info_req).await.unwrap();
        assert_eq!(info["wifi_credentials_set"], true);
        assert_eq!(info["wifi_ssid"], "MyWifi");
    }

    #[tokio::test]
    async fn fabric_label_ownership_across_two_connections() {
        let dir = tempdir();
        let server = test_server(dir.path()).await;
        let conn_a = server.connect();
        let conn_b = server.connect();

        let set = |label: &str| Request {
            message_id: "1".into(),
            command: "set_default_fabric_label".into(),
            args: serde_json::json!({"label": label}),
        };
        let get = Request {
            message_id: "2".into(),
            command: "get_fabric_label".into(),
            args: serde_json::json!({}),
        };

        // A claims ownership.
        let r = server.handle(&conn_a, &set("Alice's Home")).await.unwrap();
        assert!(r.is_null());
        let label = server.handle(&conn_a, &get).await.unwrap();
        assert_eq!(label["fabric_label"], "Alice's Home");

        // B tries to change it while A is still connected: silent no-op.
        let r = server.handle(&conn_b, &set("Bob's Home")).await.unwrap();
        assert!(r.is_null());
        let label = server.handle(&conn_b, &get).await.unwrap();
        assert_eq!(label["fabric_label"], "Alice's Home");

        // A disconnects, releasing ownership; B can now claim it.
        server.disconnect(conn_a.id).await;
        let r = server.handle(&conn_b, &set("Bob's Home")).await.unwrap();
        assert!(r.is_null());
        let label = server.handle(&conn_b, &get).await.unwrap();
        assert_eq!(label["fabric_label"], "Bob's Home");
    }

    fn tempdir() -> tempdir_shim::TempDir {
        tempdir_shim::TempDir::new()
    }

    /// Minimal self-cleaning temp dir so this crate doesn't need a `tempfile` dev-dependency.
    mod tempdir_shim {
        pub struct TempDir(std::path::PathBuf);
        impl TempDir {
            pub fn new() -> Self {
                // Nanosecond timestamps alone can collide between test threads on platforms with
                // coarser clock resolution (see backend-mc's fabric_identity.rs TempDir::new());
                // an in-process counter keeps every directory name unique.
                static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let dir = std::env::temp_dir().join(format!(
                    "ws-protocol-test-{}-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos(),
                    n
                ));
                std::fs::create_dir_all(&dir).unwrap();
                Self(dir)
            }
            pub fn path(&self) -> &std::path::Path {
                &self.0
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
