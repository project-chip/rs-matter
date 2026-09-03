//! `node_addresses` / `discover_commissionable_nodes` (WIRE_PROTOCOL.md §17/§18): pure diagnostic
//! reads over mDNS, kept entirely separate from `matter-controller`'s own internal resolution --
//! the controller resolves and reaches devices for `read`/`write`/`invoke`/`subscribe`/commission
//! on its own, via its own `mdns-sd`-backed `Discovery`, and exposes no public "what address did
//! you last use for this node" accessor (`node.rs`/`state.rs` were read in full; `DeviceEntry`,
//! which does carry `last_known_addr`, is reachable only from inside the crate's actor). So HA's
//! `ping_node`/`get_node_ip_addresses`/`discover_commissionable_nodes` are served by this backend
//! doing its own short, one-off `mdns-sd` browse, same approach `../matter-rs/src/app.rs`'s
//! prototype used.
//!
//! `discover_commissionable_nodes` browses the commissionable-node service type
//! (`_matterc._udp.local.`) and needs no fabric knowledge. `node_addresses` targets an
//! *operational* device already on our fabric: Matter's operational mDNS instance name is
//! `<compressed-fabric-id-hex>-<node-id-hex>` (both 16 uppercase hex digits, Matter Core Spec
//! §4.3.1), browsed under `_matter._tcp.local.`. If our own `compressed_fabric_id` is still the
//! synthetic placeholder (`fabric_identity.rs` -- true only before this backend has ever reached
//! any real device), the constructed name cannot match a real device's advertisement and this
//! degrades to an empty result, same as a browse that times out with no match; both are within
//! `Backend::node_addresses`'s documented `Ok(vec![])`-shaped "nothing found" contract.

use std::net::IpAddr;
use std::time::Duration;

use ws_protocol::backend::CommissionableNode;

const COMMISSIONABLE_SERVICE: &str = "_matterc._udp.local.";
const OPERATIONAL_SERVICE: &str = "_matter._tcp.local.";

/// Browse `_matterc._udp.local.` for `timeout`, collecting every resolved commissionable node.
pub async fn discover_commissionable(timeout: Duration) -> Vec<CommissionableNode> {
    tokio::task::spawn_blocking(move || browse_commissionable_blocking(timeout))
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "mdns discover_commissionable task panicked");
            Vec::new()
        })
}

fn browse_commissionable_blocking(timeout: Duration) -> Vec<CommissionableNode> {
    let Ok(daemon) = mdns_sd::ServiceDaemon::new() else {
        tracing::warn!("failed to start mdns-sd daemon for discover_commissionable_nodes");
        return Vec::new();
    };
    let Ok(receiver) = daemon.browse(COMMISSIONABLE_SERVICE) else {
        tracing::warn!("failed to browse {COMMISSIONABLE_SERVICE}");
        let _ = daemon.shutdown();
        return Vec::new();
    };
    let deadline = std::time::Instant::now() + timeout;
    let mut out = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match receiver.recv_timeout(remaining) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                out.push(commissionable_node_from_service_info(&info));
            }
            Ok(_) => {}
            Err(_) => break, // timeout or channel closed
        }
    }
    let _ = daemon.stop_browse(COMMISSIONABLE_SERVICE);
    let _ = daemon.shutdown();
    out
}

/// Look up a commissioned node's operational addresses by browsing for its
/// `<compressed-fabric-id>-<node-id>` instance name under `_matter._tcp.local.`.
///
/// `prefer_cache` is accepted (WIRE_PROTOCOL.md §17) but this backend keeps no address cache, so
/// every call does a fresh, short live query regardless -- the same behavior HA already gets from
/// upstream matterjs-server when `prefer_cache` is `false`.
pub async fn node_addresses(
    compressed_fabric_id: u64,
    node_id: u64,
    timeout: Duration,
) -> Vec<IpAddr> {
    let target = format!("{compressed_fabric_id:016X}-{node_id:016X}").to_ascii_lowercase();
    tokio::task::spawn_blocking(move || resolve_operational_blocking(&target, timeout))
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "mdns node_addresses task panicked");
            Vec::new()
        })
}

fn resolve_operational_blocking(target_instance: &str, timeout: Duration) -> Vec<IpAddr> {
    let Ok(daemon) = mdns_sd::ServiceDaemon::new() else {
        tracing::warn!("failed to start mdns-sd daemon for node_addresses");
        return Vec::new();
    };
    let Ok(receiver) = daemon.browse(OPERATIONAL_SERVICE) else {
        tracing::warn!("failed to browse {OPERATIONAL_SERVICE}");
        let _ = daemon.shutdown();
        return Vec::new();
    };
    let deadline = std::time::Instant::now() + timeout;
    let mut addrs = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match receiver.recv_timeout(remaining) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                // Fullname is `<instance>.<service>.<domain>.`; compare only the instance label.
                let instance = info
                    .get_fullname()
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if instance == target_instance {
                    addrs.extend(info.get_addresses().iter().copied());
                    break; // found our device; no need to keep browsing out the full timeout
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.stop_browse(OPERATIONAL_SERVICE);
    let _ = daemon.shutdown();
    addrs
}

/// Parse a resolved `_matterc._udp` `ServiceInfo` into the wire shape (WIRE_PROTOCOL.md §18).
/// TXT keys per Matter Core Spec §4.3.1; every field is best-effort -- a missing or unparseable
/// key just leaves that field `None` rather than dropping the whole record.
fn commissionable_node_from_service_info(info: &mdns_sd::ServiceInfo) -> CommissionableNode {
    let txt = |key: &str| -> Option<String> { info.get_property_val_str(key).map(str::to_owned) };
    let txt_u = |key: &str| txt(key).and_then(|v| v.parse::<u64>().ok());

    let (vendor_id, product_id) = txt("VP")
        .and_then(|vp| {
            let (v, p) = vp.split_once('+')?;
            Some((v.parse::<u16>().ok()?, p.parse::<u16>().ok()?))
        })
        .map_or((None, None), |(v, p)| (Some(v), Some(p)));

    CommissionableNode {
        instance_name: Some(
            info.get_fullname()
                .split('.')
                .next()
                .unwrap_or_default()
                .to_owned(),
        ),
        // Matches matterjs-server's own placeholder (WIRE_PROTOCOL.md §18): the real value would
        // require a longer resolve; HA does not read it for anything functional.
        host_name: Some("000000000000".into()),
        port: Some(info.get_port()),
        long_discriminator: txt_u("D").and_then(|d| u16::try_from(d).ok()),
        vendor_id,
        product_id,
        commissioning_mode: txt_u("CM").and_then(|v| u8::try_from(v).ok()),
        device_type: txt_u("DT").and_then(|v| u32::try_from(v).ok()),
        device_name: txt("DN"),
        pairing_instruction: txt("PI"),
        pairing_hint: txt_u("PH").and_then(|v| u16::try_from(v).ok()),
        mrp_retry_interval_idle: txt_u("SII").and_then(|v| u32::try_from(v).ok()),
        mrp_retry_interval_active: txt_u("SAI").and_then(|v| u32::try_from(v).ok()),
        supports_tcp: txt("T").map(|v| v != "0"),
        addresses: info.get_addresses().iter().map(IpAddr::to_string).collect(),
        rotating_id: txt("RI"),
    }
}
