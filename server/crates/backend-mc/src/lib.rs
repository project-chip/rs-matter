//! `backend-mc`: `ws_protocol::Backend` on top of the third-party `matter-controller` crate
//! (PLAN.md T4) -- the fast path to a lamp in Home Assistant, ported from `../matter-rs/src/app.rs`.
//!
//! Known gaps, each documented at its point of use rather than silently papered over:
//! - `fabric_identity.rs`: `compressed_fabric_id` cannot be read from `matter-controller`'s public
//!   API before at least one device has been reached; this backend mints a synthetic placeholder
//!   at boot and upgrades to the real, spec-derived value the first chance it gets.
//! - `mdns.rs`: `node_addresses`/`discover_commissionable_nodes` do their own short mDNS browse,
//!   entirely separate from the controller's own internal device resolution (which has no public
//!   "what address did you last use" accessor).
//! - `icd.rs`: `awake`/`next_expected_checkin` are not tracked (no continuous Check-In listener
//!   runs in this backend); `available` is approximated from whether the ICD cluster is currently
//!   readable.
//! - Nothing here re-populates `ws_protocol::server::Server`'s in-memory node map from an already-
//!   populated `controller-state.bin` at boot -- that map is server-layer state the shared
//!   `ws-protocol` crate owns, and PLAN.md T4 does not ask backend-mc to change it. `nodes.json`
//!   (`persist.rs`) is written so that feature has a timestamp/label source ready when it lands;
//!   nothing reads it back yet.

mod errors;
mod fabric_identity;
mod icd;
mod manual_code;
mod mdns;
mod persist;
mod subscribe;
mod value;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use matter_controller::{
    AttestationTrust, AttributePath, CommandPath, EventPath, FabricConfig, FileStore, InvokeResult,
    MatterController, MatterTime, NodeInfo, OpenWindowOpts, ReadPath, DEFAULT_WINDOW_ITERATIONS,
};
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;

use ws_protocol::backend::{
    AclEntry, AclTarget, BErr, Backend, BackendEvent, BindingTarget, CommissionableNode,
    DeviceFabric, DiscoveryFilter, FabricSummary, IcdState, InvokeOutcome, NodeIdentity,
    WindowCodes,
};
use ws_protocol::{AttrPath, ConcretePath, MValue, ServerError};

use value::{mvalue_to_value, value_to_mvalue};

/// Matches the convention PLAN.md §5 R1 uses for `backend-rsm`'s controller NOC, and the fixed
/// id `crates/matter-server/src/main.rs`'s mock-backend wiring already reports in `server_info` --
/// kept identical across backends so a `server_info.controller_node_id` a user has seen once stays
/// meaningful across a `--backend mock|mc|rsm` switch.
const CONTROLLER_NODE_ID: u64 = 112_233;
/// Arbitrary, stable RCAC subject id (`FabricConfig::rcac_id`) -- only needs to be a fixed value
/// for this controller's one fabric, never compared against anything external.
const RCAC_ID: u64 = 1;
/// How far back to backdate the fabric's `not_before` so a device with a slightly-behind clock
/// still accepts the certificate (`FabricConfig::validity`'s own recommendation).
const FABRIC_VALIDITY_BACKDATE_SECS: u64 = 3600;
/// Live-query budget for the diagnostic mDNS lookups (`ping_node`/`get_node_ip_addresses`).
const NODE_ADDRESS_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

pub struct McConfig {
    pub storage_dir: PathBuf,
    pub fabric_id: u64,
    pub admin_vendor_id: u16,
    pub paa_roots_dir: Option<PathBuf>,
    pub cd_roots_dir: Option<PathBuf>,
}

pub struct McBackend {
    controller: MatterController,
    fabric_id: u64,
    /// Our own fabric's index on this controller. `matter-controller` has no notion of "fabric
    /// index" on the controller side (it addresses fabrics by `fabric_id`, not a 1-based index --
    /// `state.rs`/`fabric_info.rs` were read in full confirming this); a controller in this build
    /// only ever administers one fabric, so `1` is the only value that will ever appear here,
    /// matching the convention `ws_protocol::MockBackend` already uses for the same field.
    fabric_index: u8,
    commissioner_node_id: u64,
    storage_dir: PathBuf,
    events_tx: broadcast::Sender<BackendEvent>,
    subs: RwLock<HashMap<u64, JoinHandle<()>>>,
    compressed_fabric_id: Arc<RwLock<u64>>,
}

impl McBackend {
    pub async fn new(cfg: McConfig) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&cfg.storage_dir)?;

        let trust = match (&cfg.paa_roots_dir, &cfg.cd_roots_dir) {
            (Some(paa), Some(cd)) => AttestationTrust::from_dirs(paa, cd)?,
            _ => {
                tracing::warn!(
                    "no PAA_ROOTS_DIR/CD_ROOTS_DIR configured: attestation only validates \
                     example/test devices (chip's synthetic loopback root + CSA test CD signing \
                     keys); set both env vars for production hardware"
                );
                AttestationTrust::example_device_roots()
            }
        };

        let store = Arc::new(FileStore::new(cfg.storage_dir.join("controller-state.bin")));
        let controller = MatterController::builder(store)
            .attestation_trust(trust)
            .admin_vendor_id(cfg.admin_vendor_id)
            .build()
            .await?;

        let fabrics = controller.fabrics().await?;
        let commissioner_node_id = match fabrics.iter().find(|f| f.fabric_id == cfg.fabric_id) {
            Some(existing) => existing.commissioner_node_id,
            None => {
                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(1_700_000_000);
                controller
                    .create_fabric(FabricConfig::new(
                        cfg.fabric_id,
                        RCAC_ID,
                        CONTROLLER_NODE_ID,
                        (
                            MatterTime::from_unix_secs(
                                now_unix.saturating_sub(FABRIC_VALIDITY_BACKDATE_SECS),
                            ),
                            MatterTime::NO_EXPIRY,
                        ),
                    ))
                    .await?;
                CONTROLLER_NODE_ID
            }
        };

        let compressed_fabric_id = Arc::new(RwLock::new(fabric_identity::load_or_mint_synthetic(
            &cfg.storage_dir,
            cfg.fabric_id,
        )));

        // Best-effort, non-blocking: if we booted with only a synthetic compressed_fabric_id
        // (fabric_identity.rs), try every already-commissioned node in turn until one answers a
        // Fabrics read, then permanently upgrade the cache. Spawned rather than awaited so a
        // currently-unreachable device never delays server startup.
        if fabric_identity::is_synthetic(&cfg.storage_dir) {
            let controller_bg = controller.clone();
            let storage_dir_bg = cfg.storage_dir.clone();
            let fabric_id_bg = cfg.fabric_id;
            let compressed_bg = Arc::clone(&compressed_fabric_id);
            tokio::spawn(async move {
                if let Ok(nodes) = controller_bg.nodes().await {
                    for n in nodes.into_iter().filter(|n| n.fabric_id == fabric_id_bg) {
                        if let Some(real) = learn_real_compressed_fabric_id(
                            &controller_bg,
                            &storage_dir_bg,
                            fabric_id_bg,
                            n.node_id,
                        )
                        .await
                        {
                            *compressed_bg.write().await = real;
                            tracing::info!(
                                node_id = n.node_id,
                                "learned the real compressed_fabric_id from an existing node"
                            );
                            return;
                        }
                    }
                }
            });
        }

        let (events_tx, _) = broadcast::channel(1024);

        Ok(Self {
            controller,
            fabric_id: cfg.fabric_id,
            fabric_index: 1,
            commissioner_node_id,
            storage_dir: cfg.storage_dir,
            events_tx,
            subs: RwLock::new(HashMap::new()),
            compressed_fabric_id,
        })
    }

    /// Persist commissioning metadata (`persist.rs`) and kick off the best-effort
    /// compressed-fabric-id upgrade for a freshly commissioned node. Shared by
    /// `commission_with_code`/`commission_on_network`.
    async fn record_commission(&self, info: &NodeInfo) {
        let mut meta = persist::NodesMeta::load(&self.storage_dir);
        meta.record_commissioned(info.node_id, now_ms(), info.label.clone());
        meta.save(&self.storage_dir);

        let controller = self.controller.clone();
        let storage_dir = self.storage_dir.clone();
        let fabric_id = self.fabric_id;
        let compressed = Arc::clone(&self.compressed_fabric_id);
        let node_id = info.node_id;
        tokio::spawn(async move {
            if let Some(real) =
                learn_real_compressed_fabric_id(&controller, &storage_dir, fabric_id, node_id).await
            {
                *compressed.write().await = real;
            }
        });
    }
}

async fn learn_real_compressed_fabric_id(
    controller: &MatterController,
    storage_dir: &std::path::Path,
    fabric_id: u64,
    node_id: u64,
) -> Option<u64> {
    let fabrics = controller.node(node_id).list_fabrics().await.ok()?;
    let entry = fabrics.iter().find(|f| f.fabric_id == fabric_id)?;
    fabric_identity::upgrade_to_real(storage_dir, &entry.root_public_key, fabric_id)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn privilege_from_u8(v: u8) -> matter_controller::AclPrivilege {
    use matter_controller::AclPrivilege::{Administer, Manage, Operate, ProxyView, Unknown, View};
    match v {
        1 => View,
        2 => ProxyView,
        3 => Operate,
        4 => Manage,
        5 => Administer,
        other => Unknown(other),
    }
}

fn auth_mode_from_u8(v: u8) -> matter_controller::AclAuthMode {
    use matter_controller::AclAuthMode::{Case, Group, Pase, Unknown};
    match v {
        1 => Pase,
        2 => Case,
        3 => Group,
        other => Unknown(other),
    }
}

/// `Node::write_acl`/`Node::write_binding` return a per-path device status list rather than a
/// single pass/fail; the `Backend` trait's `set_acl`/`set_bindings` collapse that to one
/// `Result<(), BErr>` (WIRE_PROTOCOL.md never surfaces per-path status for these two commands --
/// §13 always returns a synthesized single-element `status: 0`), so any rejected path fails the
/// whole call with every rejected path named in the detail.
fn ensure_all_success(
    statuses: &[(AttributePath, matter_controller::ImStatus)],
) -> Result<(), BErr> {
    let failures: Vec<String> = statuses
        .iter()
        .filter(|(_, s)| !s.is_success())
        .map(|(p, s)| {
            format!(
                "{}/{}/{} -> IM status {:#04x}",
                p.endpoint,
                p.cluster,
                p.attribute,
                s.to_u8()
            )
        })
        .collect();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ServerError::sdk_stack(format!(
            "device rejected: {}",
            failures.join(", ")
        )))
    }
}

#[async_trait]
impl Backend for McBackend {
    async fn fabric_info(&self) -> FabricSummary {
        FabricSummary {
            fabric_id: self.fabric_id,
            compressed_fabric_id: *self.compressed_fabric_id.read().await,
            fabric_index: self.fabric_index,
            controller_node_id: self.commissioner_node_id,
        }
    }

    async fn nodes(&self) -> Vec<NodeIdentity> {
        match self.controller.nodes().await {
            Ok(list) => list
                .into_iter()
                .filter(|n| n.fabric_id == self.fabric_id)
                .map(|n| NodeIdentity {
                    node_id: n.node_id,
                    fabric_id: n.fabric_id,
                    fabric_index: self.fabric_index,
                })
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "MatterController::nodes() failed");
                Vec::new()
            }
        }
    }

    /// PLAN.md task 4(b): `code` reaches `MatterController::commission` exactly as HA sent it if
    /// it's a QR payload (`"MT:..."`, WIRE_PROTOCOL.md §9) -- that distinction is
    /// `matter-controller`'s to make, not ours. A manual pairing code is the one exception: HA (and
    /// any human) hands it over in its printed, dash-separated display form
    /// (e.g. `"3497-0112-332"`), and `matter_controller::commission` requires the bare 11-digit
    /// string (confirmed live 2026-09-03 against an rs-matter reference device: passing the
    /// dash-separated form fails commissioning immediately with
    /// `"invalid setup code: ManualCodeWrongLength(13)"`), so this backend strips non-digits before
    /// forwarding one. Not covered by an automated test: `MatterController` and its `commission()`
    /// device I/O have no public seam for a fake device/session, so this is a by-inspection
    /// guarantee, re-checked here every time this function changes.
    async fn commission_with_code(
        &self,
        code: &str,
        network_only: bool,
    ) -> Result<NodeIdentity, BErr> {
        if !network_only {
            tracing::warn!(
                "commission_with_code: BLE discovery was requested but this build has no `ble` \
                 feature enabled; commissioning over IP only (matches network_only=true behavior)"
            );
        }
        // HA (and any human typing a manual pairing code) sends it in its printed,
        // dash-separated display form (e.g. "3497-0112-332", per Matter Core Spec §5.1.4.2 /
        // `manual_code.rs` above, which only ever produces the bare 11-digit string). A QR
        // payload (`code` starting `"MT:"`, WIRE_PROTOCOL.md §9) is left untouched --
        // `matter_controller::commission` branches on that prefix itself. Stripping dashes here
        // (rather than requiring the caller to pre-normalize) matches what every real client does:
        // matter.js's `ManualPairingCodeCodec.decode` strips all non-digits before parsing.
        let normalized;
        let code = if code.starts_with("MT:") {
            code
        } else {
            normalized = code
                .chars()
                .filter(char::is_ascii_digit)
                .collect::<String>();
            normalized.as_str()
        };
        let info = errors::with_timeout(
            errors::COMMISSION_TIMEOUT,
            "commission_with_code",
            self.controller.commission(code, None),
            errors::commission_failed,
        )
        .await?;
        self.record_commission(&info).await;
        Ok(NodeIdentity {
            node_id: info.node_id,
            fabric_id: info.fabric_id,
            fabric_index: self.fabric_index,
        })
    }

    async fn commission_on_network(
        &self,
        pin: u32,
        filter: DiscoveryFilter,
        ip: Option<IpAddr>,
    ) -> Result<NodeIdentity, BErr> {
        if ip.is_some() {
            tracing::debug!(
                "commission_on_network: ip_addr hint accepted but not honored -- \
                 matter-controller 0.11's commission() has no address-hint parameter and always \
                 resolves the device itself via mDNS"
            );
        }
        let code = match filter {
            DiscoveryFilter::LongDiscriminator(d) => manual_code::manual_code(pin, d, None)?,
            DiscoveryFilter::None => {
                return Err(ServerError::invalid_arguments(
                    "commission_on_network requires filter_type 2 (long discriminator) in this \
                     backend build; unfiltered/short-discriminator/vendor-id discovery is not \
                     implemented",
                ))
            }
            DiscoveryFilter::ShortDiscriminator(_) => {
                return Err(ServerError::invalid_arguments(
                    "commission_on_network: short-discriminator filtering (filter_type 1) is not \
                     supported by this backend; pass filter_type 2 with the full long discriminator",
                ))
            }
            DiscoveryFilter::VendorId(_) => {
                return Err(ServerError::invalid_arguments(
                    "commission_on_network: vendor-id filtering (filter_type 3) is not supported \
                     by this backend; pass filter_type 2 with the long discriminator",
                ))
            }
        };
        let info = errors::with_timeout(
            errors::COMMISSION_TIMEOUT,
            "commission_on_network",
            self.controller.commission(&code, None),
            errors::commission_failed,
        )
        .await?;
        self.record_commission(&info).await;
        Ok(NodeIdentity {
            node_id: info.node_id,
            fabric_id: info.fabric_id,
            fabric_index: self.fabric_index,
        })
    }

    async fn read(
        &self,
        node: u64,
        paths: &[AttrPath],
    ) -> Result<Vec<(ConcretePath, MValue)>, BErr> {
        let read_paths: Vec<ReadPath> = paths
            .iter()
            .map(|p| ReadPath::new(p.endpoint, p.cluster, p.attribute))
            .collect();
        let report = errors::with_timeout(
            errors::READ_WRITE_INVOKE_TIMEOUT,
            "read",
            self.controller.node(node).read(&read_paths),
            errors::operational,
        )
        .await?;
        Ok(report
            .into_iter()
            .map(|(p, v)| {
                (
                    ConcretePath {
                        endpoint: p.endpoint,
                        cluster: p.cluster,
                        attribute: p.attribute,
                    },
                    value_to_mvalue(&v),
                )
            })
            .collect())
    }

    async fn write(
        &self,
        node: u64,
        path: ConcretePath,
        value: MValue,
        timed_ms: Option<u16>,
    ) -> Result<Vec<(ConcretePath, u8)>, BErr> {
        let ap = AttributePath {
            endpoint: path.endpoint,
            cluster: path.cluster,
            attribute: path.attribute,
        };
        let v = mvalue_to_value(&value);
        let node_handle = self.controller.node(node);
        let results = errors::with_timeout(
            errors::READ_WRITE_INVOKE_TIMEOUT,
            "write",
            async {
                match timed_ms {
                    Some(ms) => node_handle.write_timed(&[(ap, v)], Some(ms)).await,
                    None => node_handle.write(&[(ap, v)]).await,
                }
            },
            errors::operational,
        )
        .await?;
        Ok(results
            .into_iter()
            .map(|(p, status)| {
                (
                    ConcretePath {
                        endpoint: p.endpoint,
                        cluster: p.cluster,
                        attribute: p.attribute,
                    },
                    status.to_u8(),
                )
            })
            .collect())
    }

    async fn invoke(
        &self,
        node: u64,
        endpoint: u16,
        cluster: u32,
        command: u32,
        fields: MValue,
        timed_ms: Option<u16>,
    ) -> Result<InvokeOutcome, BErr> {
        let path = CommandPath {
            endpoint,
            cluster,
            command,
        };
        let v = mvalue_to_value(&fields);
        let node_handle = self.controller.node(node);
        let result = errors::with_timeout(
            errors::READ_WRITE_INVOKE_TIMEOUT,
            "invoke",
            async {
                match timed_ms {
                    Some(ms) => node_handle.invoke_timed(path, v, Some(ms)).await,
                    None => node_handle.invoke(path, v).await,
                }
            },
            errors::operational,
        )
        .await?;
        Ok(match result {
            InvokeResult::Status(s) => InvokeOutcome::Status(s.to_u8()),
            InvokeResult::Data { fields, .. } => InvokeOutcome::Fields(value_to_mvalue(&fields)),
            // Non-exhaustive: matter-controller may add response shapes; nothing today produces
            // one, so surface it as a status-only success rather than losing the response.
            _ => InvokeOutcome::Status(0),
        })
    }

    async fn subscribe_all(&self, node: u64) -> Result<(), BErr> {
        if self.subs.read().await.contains_key(&node) {
            return Ok(()); // already subscribed -- PLAN.md T4: one whole-node subscription per node.
        }
        let node_handle = self.controller.node(node);
        let sub = node_handle
            .subscribe(&[ReadPath::all()], &[EventPath::default()], 1, 60)
            .await
            .map_err(errors::operational)?;
        let handle = subscribe::spawn_pump(node_handle, node, sub, self.events_tx.clone());
        self.subs.write().await.insert(node, handle);
        Ok(())
    }

    async fn unsubscribe(&self, node: u64) {
        if let Some(handle) = self.subs.write().await.remove(&node) {
            handle.abort();
        }
    }

    async fn remove_node(&self, node: u64) -> Result<(), BErr> {
        match self.controller.node(node).list_fabrics().await {
            Ok(fabrics) => match fabrics.iter().find(|f| f.fabric_id == self.fabric_id) {
                Some(entry) => {
                    if let Err(e) = self.controller.node(node).remove_fabric(entry.fabric_index).await
                    {
                        tracing::warn!(node, error = %e, "RemoveFabric on the device failed; forgetting it locally anyway");
                    }
                }
                None => tracing::warn!(
                    node,
                    "device did not report our fabric in its Fabrics list; forgetting it locally anyway"
                ),
            },
            Err(e) => tracing::warn!(node, error = %e, "device unreachable while removing (could not read its Fabrics list); forgetting it locally anyway"),
        }
        self.controller
            .forget_node(node)
            .await
            .map_err(errors::operational)?;

        let mut meta = persist::NodesMeta::load(&self.storage_dir);
        meta.remove(node);
        meta.save(&self.storage_dir);
        let mut regs = persist::IcdRegistrations::load(&self.storage_dir);
        regs.remove(node);
        regs.save(&self.storage_dir);
        Ok(())
    }

    async fn open_commissioning_window(
        &self,
        node: u64,
        timeout_s: u16,
        discriminator: Option<u16>,
    ) -> Result<WindowCodes, BErr> {
        if discriminator.is_some() {
            tracing::debug!(
                "open_commissioning_window: discriminator hint accepted but matter-controller \
                 0.11 always generates its own random discriminator for an enhanced window -- \
                 matches matterjs-server's own behavior (WIRE_PROTOCOL.md §10: only node_id and \
                 timeout are actually used upstream either)"
            );
        }
        let (vendor_id, product_id) = self
            .controller
            .nodes()
            .await
            .ok()
            .and_then(|nodes| nodes.into_iter().find(|n| n.node_id == node))
            .map(|n| (n.vendor_id, n.product_id))
            .unwrap_or((None, None));
        // `OpenWindowOpts` is `#[non_exhaustive]`, so it cannot be built with a struct literal
        // from outside matter-controller even with `..Default::default()`; mutate the default
        // instance's public fields instead.
        let mut opts = OpenWindowOpts::default();
        opts.timeout_s = timeout_s;
        opts.iterations = DEFAULT_WINDOW_ITERATIONS;
        opts.vendor_id = vendor_id;
        opts.product_id = product_id;
        let window = errors::with_timeout(
            errors::OPEN_WINDOW_TIMEOUT,
            "open_commissioning_window",
            self.controller.node(node).open_commissioning_window(opts),
            errors::operational,
        )
        .await?;
        Ok(WindowCodes {
            setup_pin_code: window.passcode,
            setup_manual_code: window.manual_code,
            // No vendor/product id known for this node yet (never captured post-commission) ->
            // no QR is possible (Matter Core Spec §5.1.3: VID/PID are mandatory QR fields); the
            // manual code above is still always usable.
            setup_qr_code: window.qr_code.unwrap_or_default(),
        })
    }

    async fn device_fabrics(&self, node: u64) -> Result<Vec<DeviceFabric>, BErr> {
        let fabrics = self
            .controller
            .node(node)
            .list_fabrics()
            .await
            .map_err(errors::operational)?;
        Ok(fabrics
            .into_iter()
            .map(|f| DeviceFabric {
                fabric_id: f.fabric_id,
                vendor_id: f.vendor_id,
                fabric_index: f.fabric_index,
                fabric_label: f.label,
            })
            .collect())
    }

    async fn remove_device_fabric(&self, node: u64, fabric_index: u8) -> Result<(), BErr> {
        self.controller
            .node(node)
            .remove_fabric(fabric_index)
            .await
            .map_err(errors::operational)
    }

    async fn update_fabric_label(&self, node: u64, label: &str) -> Result<(), BErr> {
        self.controller
            .node(node)
            .update_fabric_label(label)
            .await
            .map_err(errors::operational)
    }

    async fn set_acl(&self, node: u64, entries: Vec<AclEntry>) -> Result<(), BErr> {
        let mapped: Vec<matter_controller::AclEntry> = entries
            .into_iter()
            .map(|e| {
                // WIRE_PROTOCOL.md §13's `subjects` is always a concrete (possibly empty) list at
                // the `ws_protocol::backend::AclEntry` layer -- that type already collapsed the
                // wire's `null` (wildcard) and `[]` cases together before this backend ever sees
                // it (`ws-protocol/src/server/commands.rs::cmd_set_acl_entry`). An empty list is
                // read back here as the wildcard, matching the common "fabric-admin ACL" shape HA
                // actually sends (`subjects: null`).
                let subjects = if e.subjects.is_empty() {
                    None
                } else {
                    Some(e.subjects)
                };
                let targets = e.targets.map(|ts| {
                    ts.into_iter()
                        .map(|t: AclTarget| {
                            matter_controller::AclTarget::new(t.cluster, t.endpoint, t.device_type)
                        })
                        .collect()
                });
                matter_controller::AclEntry::new(
                    privilege_from_u8(e.privilege),
                    auth_mode_from_u8(e.auth_mode),
                    subjects,
                    targets,
                )
            })
            .collect();
        let statuses = self
            .controller
            .node(node)
            .write_acl(&mapped)
            .await
            .map_err(errors::operational)?;
        ensure_all_success(&statuses)
    }

    async fn set_bindings(
        &self,
        node: u64,
        endpoint: u16,
        targets: Vec<BindingTarget>,
    ) -> Result<(), BErr> {
        let mapped: Vec<matter_controller::BindingTarget> = targets
            .into_iter()
            .map(|t| matter_controller::BindingTarget::new(t.node, t.group, t.endpoint, t.cluster))
            .collect();
        let statuses = self
            .controller
            .node(node)
            .write_binding(endpoint, &mapped)
            .await
            .map_err(errors::operational)?;
        ensure_all_success(&statuses)
    }

    async fn node_addresses(&self, node: u64, prefer_cache: bool) -> Result<Vec<IpAddr>, BErr> {
        let _ = prefer_cache; // mdns.rs: no address cache kept here, so every call is a live query.
        let compressed = *self.compressed_fabric_id.read().await;
        Ok(mdns::node_addresses(compressed, node, NODE_ADDRESS_QUERY_TIMEOUT).await)
    }

    async fn discover_commissionable(&self, timeout: Duration) -> Vec<CommissionableNode> {
        mdns::discover_commissionable(timeout).await
    }

    async fn icd_register(&self, node: u64) -> Result<IcdState, BErr> {
        icd::register(
            &self.controller,
            &self.storage_dir,
            node,
            self.commissioner_node_id,
        )
        .await
    }

    async fn icd_unregister(&self, node: u64, force: bool) -> Result<IcdState, BErr> {
        icd::unregister(&self.controller, &self.storage_dir, node, force).await
    }

    async fn icd_state(&self, node: u64) -> Result<IcdState, BErr> {
        Ok(icd::state(&self.controller, &self.storage_dir, node).await)
    }

    fn events(&self) -> broadcast::Receiver<BackendEvent> {
        self.events_tx.subscribe()
    }
}
