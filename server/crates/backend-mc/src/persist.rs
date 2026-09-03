//! Small JSON side-files this backend keeps next to `matter-controller`'s own
//! `controller-state.bin` (which is an opaque, private-to-that-crate blob we cannot extend):
//!
//! - `nodes.json`: node id -> `(date_commissioned epoch ms, label)`. `matter_controller::NodeInfo`
//!   carries a caller-supplied `label` but no commissioning timestamp, and PLAN.md T4 asks for one
//!   kept anyway (useful the day `ws_protocol::server::Server` grows a "reload nodes from the
//!   backend at boot" path -- it does not yet; see `lib.rs`'s module doc for that gap).
//! - `icd-registrations.json`: node id -> the ICD client registration this controller holds with
//!   that device (`IcdRegistration`, minus its symmetric key, which never leaves memory unless
//!   truly needed to verify a Check-In -- key material at rest on disk should stay minimal on a
//!   home box). `icd_state`'s `registered` flag is read from this file's key set
//!   (WIRE_PROTOCOL.md §14: "registered ... from the controller's own ICD client state").
//!
//! Both are best-effort: a read failure (missing/corrupt file) degrades to "empty", a write
//! failure only logs -- neither ever fails the caller's actual Matter operation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeMeta {
    pub date_commissioned_ms: u64,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodesMeta(BTreeMap<String, NodeMeta>);

impl NodesMeta {
    fn path(storage_dir: &Path) -> PathBuf {
        storage_dir.join("nodes.json")
    }

    pub fn load(storage_dir: &Path) -> Self {
        std::fs::read_to_string(Self::path(storage_dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, storage_dir: &Path) {
        if let Ok(data) = serde_json::to_string_pretty(self) {
            if let Err(e) = std::fs::write(Self::path(storage_dir), data) {
                tracing::warn!(error = %e, "failed to persist nodes.json");
            }
        }
    }

    pub fn record_commissioned(
        &mut self,
        node_id: u64,
        date_commissioned_ms: u64,
        label: Option<String>,
    ) {
        self.0.insert(
            node_id.to_string(),
            NodeMeta {
                date_commissioned_ms,
                label,
            },
        );
    }

    pub fn remove(&mut self, node_id: u64) {
        self.0.remove(&node_id.to_string());
    }

    // Not read anywhere yet -- see `lib.rs`'s module doc on the "reload nodes from the backend at
    // boot" gap this file is written in preparation for; kept (and unit-tested below) as the
    // accessor that future caller will need.
    #[allow(dead_code)]
    pub fn get(&self, node_id: u64) -> Option<&NodeMeta> {
        self.0.get(&node_id.to_string())
    }
}

/// An ICD client registration, key material excluded (see module doc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcdRegistrationMeta {
    pub check_in_node_id: u64,
    pub monitored_subject: u64,
    pub start_counter: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IcdRegistrations(BTreeMap<String, IcdRegistrationMeta>);

impl IcdRegistrations {
    fn path(storage_dir: &Path) -> PathBuf {
        storage_dir.join("icd-registrations.json")
    }

    pub fn load(storage_dir: &Path) -> Self {
        std::fs::read_to_string(Self::path(storage_dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, storage_dir: &Path) {
        if let Ok(data) = serde_json::to_string_pretty(self) {
            if let Err(e) = std::fs::write(Self::path(storage_dir), data) {
                tracing::warn!(error = %e, "failed to persist icd-registrations.json");
            }
        }
    }

    pub fn insert(&mut self, node_id: u64, meta: IcdRegistrationMeta) {
        self.0.insert(node_id.to_string(), meta);
    }

    pub fn remove(&mut self, node_id: u64) {
        self.0.remove(&node_id.to_string());
    }

    pub fn contains(&self, node_id: u64) -> bool {
        self.0.contains_key(&node_id.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> TempDir {
        TempDir::new()
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            // See fabric_identity.rs's TempDir::new() for why a bare nanosecond timestamp is not
            // enough to keep parallel test threads from colliding on the same directory.
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "backend-mc-persist-test-{}-{}-{}",
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
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn nodes_meta_roundtrips_through_disk() {
        let dir = tempdir();
        let mut m = NodesMeta::load(dir.path());
        assert!(m.get(42).is_none());
        m.record_commissioned(42, 1_700_000_000_000, Some("kitchen".into()));
        m.save(dir.path());

        let reloaded = NodesMeta::load(dir.path());
        let meta = reloaded.get(42).unwrap();
        assert_eq!(meta.date_commissioned_ms, 1_700_000_000_000);
        assert_eq!(meta.label.as_deref(), Some("kitchen"));

        let mut reloaded = reloaded;
        reloaded.remove(42);
        assert!(reloaded.get(42).is_none());
    }

    #[test]
    fn icd_registrations_roundtrip_and_track_membership() {
        let dir = tempdir();
        let mut r = IcdRegistrations::load(dir.path());
        assert!(!r.contains(7));
        r.insert(
            7,
            IcdRegistrationMeta {
                check_in_node_id: 112233,
                monitored_subject: 112233,
                start_counter: 0,
            },
        );
        r.save(dir.path());
        let reloaded = IcdRegistrations::load(dir.path());
        assert!(reloaded.contains(7));
    }
}
