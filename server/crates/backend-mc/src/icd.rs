//! `get_icd_state` / `register_icd` / `unregister_icd` (WIRE_PROTOCOL.md §14).
//!
//! `IcdManagement` (cluster `0x46` / 70) attribute ids, from `crates/matter-names/src/generated.rs`
//! (the checked-in IDL table -- *not* the `0x0006` this task's own starting notes guessed;
//! generated.rs's `Cluster{id:70,...}` entry is the actual source of truth and was read before
//! writing this):
const ICD_MANAGEMENT_CLUSTER: u32 = 0x46;
const ATTR_OPERATING_MODE: u32 = 8;
const ATTR_FEATURE_MAP: u32 = 0xFFFC; // 65532, global attribute
/// `IcdManagement.Feature` bit 2 = `LITS` (Long Idle Time Support), Matter Core Spec §9.17.4.
const FEATURE_LIT_SUPPORT: u64 = 0x04;

use std::path::Path;

use matter_codec::Value;
use matter_controller::{IcdClientType, MatterController, ReadPath};
use ws_protocol::backend::IcdState;
use ws_protocol::ServerError;

use crate::errors::operational;
use crate::persist::{IcdRegistrationMeta, IcdRegistrations};

/// Read `OperatingMode`/`FeatureMap` off the device (best-effort) and combine with our own
/// persisted registration state. Never errors: an unreachable device or a device with no
/// `IcdManagement` cluster both simply report `supported: false` (WIRE_PROTOCOL.md §14), not a
/// wire error -- `get_icd_state` is a status query, not an operation that can fail.
pub async fn state(controller: &MatterController, storage_dir: &Path, node_id: u64) -> IcdState {
    let node = controller.node(node_id);
    let paths = [
        ReadPath::concrete(0, ICD_MANAGEMENT_CLUSTER, ATTR_OPERATING_MODE),
        ReadPath::concrete(0, ICD_MANAGEMENT_CLUSTER, ATTR_FEATURE_MAP),
    ];
    let mut supported = false;
    let mut operating_mode = None;
    let mut lit_supported = false;
    if let Ok(report) = node.read(&paths).await {
        for (path, value) in &report {
            match (path.attribute, value) {
                (ATTR_OPERATING_MODE, Value::Uint(v)) => {
                    supported = true;
                    operating_mode = Some(if *v == 1 { "LIT" } else { "SIT" }.to_string());
                }
                (ATTR_FEATURE_MAP, Value::Uint(v)) => {
                    supported = true;
                    lit_supported = v & FEATURE_LIT_SUPPORT != 0;
                }
                _ => {}
            }
        }
    }
    let registered = IcdRegistrations::load(storage_dir).contains(node_id);
    IcdState {
        supported,
        lit_supported,
        registered,
        operating_mode,
        // `awake`/`next_expected_checkin` need a live Check-In listener
        // (`MatterController::listen_for_checkin_once`), which this backend does not run
        // continuously -- documented gap, not a silent guess. `available` is approximated as
        // "we could just read the cluster", which is the only liveness signal available without
        // that listener.
        awake: Some(false),
        available: Some(supported),
        next_expected_checkin: None,
    }
}

pub async fn register(
    controller: &MatterController,
    storage_dir: &Path,
    node_id: u64,
    commissioner_node_id: u64,
) -> Result<IcdState, ServerError> {
    let reg = controller
        .node(node_id)
        .register_icd_client(commissioner_node_id, IcdClientType::Permanent)
        .await
        .map_err(operational)?;
    let mut regs = IcdRegistrations::load(storage_dir);
    regs.insert(
        node_id,
        IcdRegistrationMeta {
            check_in_node_id: reg.check_in_node_id,
            monitored_subject: reg.monitored_subject,
            start_counter: reg.start_counter,
        },
    );
    regs.save(storage_dir);
    Ok(state(controller, storage_dir, node_id).await)
}

pub async fn unregister(
    controller: &MatterController,
    storage_dir: &Path,
    node_id: u64,
    force: bool,
) -> Result<IcdState, ServerError> {
    match controller.node(node_id).unregister_icd_client().await {
        Ok(()) => {}
        Err(e) if force => {
            tracing::warn!(node_id, error = %e, "UnregisterClient rejected by the device; force=true, dropping our local registration anyway");
        }
        Err(e) => return Err(operational(e)),
    }
    let mut regs = IcdRegistrations::load(storage_dir);
    regs.remove(node_id);
    regs.save(storage_dir);
    Ok(state(controller, storage_dir, node_id).await)
}
