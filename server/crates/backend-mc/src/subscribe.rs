//! The whole-node subscription pump (PLAN.md T4 Part B): one `Node::subscribe` per commissioned
//! node, `[ReadPath::all()]` + `[EventPath::default()]` (all events), min 1s / max 60s, kept alive
//! for the process lifetime by a dedicated tokio task that drains `Subscription::next()` and
//! translates every `SubscriptionEvent` into a `BackendEvent` the shared `ws_protocol::server`
//! layer already knows how to fan out.

use matter_controller::{
    EventPriority, EventReport, EventTimestamp, Node, ReadPath, Subscription, SubscriptionEvent,
};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use ws_protocol::{BackendEvent, ConcretePath};

use crate::value::value_to_mvalue;

/// Spawn the pump task and return its handle (`unsubscribe` aborts it; abort drops the moved-in
/// `Subscription`, whose `Drop` best-effort-cancels it on the controller side).
pub fn spawn_pump(
    node: Node,
    node_id: u64,
    mut sub: Subscription,
    events_tx: broadcast::Sender<BackendEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Some(ev) = sub.next().await else {
                // The actor stopped or the subscription was cancelled out from under us (not via
                // our own `unsubscribe`, which aborts this very task instead of waiting for this
                // branch) -- tell the server layer the node's live state can no longer be trusted.
                tracing::warn!(node_id, "subscription ended (channel closed)");
                let _ = events_tx.send(BackendEvent::SubscriptionLost { node_id });
                break;
            };
            handle_event(&node, node_id, ev, &events_tx).await;
        }
    })
}

async fn handle_event(
    node: &Node,
    node_id: u64,
    ev: SubscriptionEvent,
    events_tx: &broadcast::Sender<BackendEvent>,
) {
    match ev {
        SubscriptionEvent::Report(report) => {
            let _ = events_tx.send(BackendEvent::AttributeChanged {
                node_id,
                path: ConcretePath {
                    endpoint: report.path.endpoint,
                    cluster: report.path.cluster,
                    attribute: report.path.attribute,
                },
                value: value_to_mvalue(&report.value),
            });
        }
        SubscriptionEvent::Event(EventReport::Data(item)) => {
            let priority = match item.priority {
                EventPriority::Debug => 0,
                EventPriority::Info => 1,
                EventPriority::Critical => 2,
                // Preserve an out-of-range future priority verbatim rather than guessing.
                EventPriority::Unknown(v) => v,
                // Non-exhaustive enum: a variant added by a future matter-interaction release.
                _ => 0,
            };
            let timestamp_ms = match item.timestamp {
                EventTimestamp::Epoch(ms) => Some(ms),
                // System/delta timestamps and "none" all lack an absolute epoch value; the server
                // layer already falls back to its own wall-clock `now()` for `None`
                // (`ws_protocol::server::handle_backend_event`, matching WIRE_PROTOCOL.md §3's
                // `timestamp_type: 2`).
                EventTimestamp::System(_)
                | EventTimestamp::DeltaEpoch(_)
                | EventTimestamp::DeltaSystem(_)
                | EventTimestamp::None => None,
                // Non-exhaustive enum: a variant added by a future matter-interaction release.
                _ => None,
            };
            let _ = events_tx.send(BackendEvent::Event {
                node_id,
                endpoint: item.path.endpoint.unwrap_or(0),
                cluster: item.path.cluster.unwrap_or(0),
                event: item.path.event.unwrap_or(0),
                event_number: item.event_number,
                priority,
                timestamp_ms,
                data: value_to_mvalue(&item.value),
            });
        }
        SubscriptionEvent::Event(EventReport::Status { path, status }) => {
            // No `BackendEvent` shape carries a per-event-path error; log and move on, same as
            // matterjs's own AttributeDataCache does for a status-only report (WIRE_PROTOCOL.md §5).
            tracing::warn!(
                node_id,
                ?path,
                status,
                "device reported an event-path status error"
            );
        }
        // PLAN.md task 4(c): on `Resubscribing`, mark the node unavailable; on `Established`,
        // re-read and mark it available again. Both branches only ever emit `BackendEvent::
        // NodeAvailability`, whose *only* handler (`ws_protocol::server::handle_backend_event`,
        // `crates/ws-protocol/src/server/mod.rs`) sets `NodeRecord::available` and broadcasts a
        // `node_updated` carrying the full node object (`NodeRecord::to_json`, WIRE_PROTOCOL.md
        // §3) — so "full node object, available:false/true" is guaranteed by that one shared
        // code path regardless of which backend produced the availability change, and is already
        // covered there (`ws-protocol`'s own tests exercise `NodeAvailability` end to end). Not
        // separately unit-tested *here*: `matter_controller::{Node, Subscription}` have no public
        // constructor a test could hand a fake `SubscriptionEvent` stream to (both are only ever
        // produced by `MatterController::node(id).subscribe(..)` against a real/commissioned
        // device), so this file's `handle_event` dispatch is a by-inspection guarantee, re-checked
        // here every time this function changes — manual check: commission a real device, kill its
        // network mid-session and confirm `node_updated{available:false}` arrives, then restore
        // it and confirm `node_updated{available:true}` follows with fresh attribute values.
        SubscriptionEvent::Established { subscription_id } => {
            tracing::debug!(
                node_id,
                subscription_id,
                "subscription established; re-reading whole node"
            );
            reread_and_report(node, node_id, events_tx).await;
            let _ = events_tx.send(BackendEvent::NodeAvailability {
                node_id,
                available: true,
            });
        }
        SubscriptionEvent::Resubscribing { cause } => {
            tracing::warn!(node_id, %cause, "subscription resubscribing; node considered unavailable meanwhile");
            let _ = events_tx.send(BackendEvent::NodeAvailability {
                node_id,
                available: false,
            });
        }
        SubscriptionEvent::Lagged { dropped } => {
            tracing::warn!(
                node_id,
                dropped,
                "subscription lagged; re-reading whole node to recover"
            );
            reread_and_report(node, node_id, events_tx).await;
        }
        // Non-exhaustive: a future SubscriptionEvent variant is silently ignored rather than
        // breaking the pump loop.
        _ => {}
    }
}

async fn reread_and_report(node: &Node, node_id: u64, events_tx: &broadcast::Sender<BackendEvent>) {
    match node.read(&[ReadPath::all()]).await {
        Ok(report) => {
            for (path, value) in report {
                let _ = events_tx.send(BackendEvent::AttributeChanged {
                    node_id,
                    path: ConcretePath {
                        endpoint: path.endpoint,
                        cluster: path.cluster,
                        attribute: path.attribute,
                    },
                    value: value_to_mvalue(&value),
                });
            }
        }
        Err(e) => {
            tracing::warn!(node_id, error = %e, "full re-read after Established/Lagged failed");
        }
    }
}
