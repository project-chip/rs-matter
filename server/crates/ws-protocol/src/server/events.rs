//! Event fan-out: one internal broadcast channel, per-connection gating by `start_listening` /
//! thread+topology opt-in (WIRE_PROTOCOL.md §1 delivery modes, §3 opt-in events). We collapse
//! matterjs's sendReliable/sendOrdered/sendCoalescable distinction (backpressure policy on a
//! real slow client) since a bounded broadcast channel already drops the oldest frame under
//! backpressure for every subscriber uniformly — the wire *shapes* this crate promises are
//! unaffected either way (WIRE_PROTOCOL.md §1).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::broadcast;

use crate::wire::Event;

/// Which connections a given broadcast event may reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventGate {
    /// `server_info_updated`, `server_shutdown`: every connected client, `start_listening` or not.
    Always,
    /// Structural + attribute events: only connections that have called `start_listening`.
    Listening,
    /// `thread_diagnostics_updated`: listening connections that issued `get_thread_diagnostics`.
    /// Not yet sent by anything (Milestone 3, WIRE_PROTOCOL.md §21) — `Connection::wants_thread`
    /// is already tracked so the gate is ready the day a backend starts emitting the event.
    #[allow(dead_code)]
    Thread,
    /// `network_topology_updated`: listening connections that issued `get_network_topology`.
    /// Same status as `Thread` above.
    #[allow(dead_code)]
    Topology,
}

pub struct OutEvent {
    pub event: Event,
    pub gate: EventGate,
}

pub const EVENT_HISTORY_LIMIT: usize = 25;

/// Ring buffer of the last N `node_event` payloads, for `diagnostics` (WIRE_PROTOCOL.md §15).
#[derive(Default)]
pub struct EventHistory(VecDeque<serde_json::Value>);

impl EventHistory {
    pub fn push(&mut self, event: serde_json::Value) {
        if self.0.len() == EVENT_HISTORY_LIMIT {
            self.0.pop_front();
        }
        self.0.push_back(event);
    }

    pub fn snapshot(&self) -> Vec<serde_json::Value> {
        self.0.iter().cloned().collect()
    }
}

/// Per-connection handle: gating flags + a broadcast subscription.
pub struct Connection {
    pub id: u64,
    pub listening: Arc<AtomicBool>,
    pub wants_thread: Arc<AtomicBool>,
    pub wants_topology: Arc<AtomicBool>,
    rx: broadcast::Receiver<Arc<OutEvent>>,
}

impl Connection {
    pub(crate) fn new(id: u64, rx: broadcast::Receiver<Arc<OutEvent>>) -> Self {
        Self {
            id,
            listening: Arc::new(AtomicBool::new(false)),
            wants_thread: Arc::new(AtomicBool::new(false)),
            wants_topology: Arc::new(AtomicBool::new(false)),
            rx,
        }
    }

    /// Cheap: the gating flags are already `Arc`-shared, and a fresh broadcast subscription
    /// costs nothing until something is sent on it. Lets a WS connection spawn one task per
    /// in-flight request (each needing its own `&Connection`) while the main loop keeps using
    /// the original for event delivery — see `matter-server`'s `handle_ws`.
    pub fn clone_for_task(&self) -> Self {
        Self {
            id: self.id,
            listening: Arc::clone(&self.listening),
            wants_thread: Arc::clone(&self.wants_thread),
            wants_topology: Arc::clone(&self.wants_topology),
            rx: self.rx.resubscribe(),
        }
    }

    fn passes_gate(&self, gate: EventGate) -> bool {
        match gate {
            EventGate::Always => true,
            EventGate::Listening => self.listening.load(Ordering::Relaxed),
            EventGate::Thread => {
                self.listening.load(Ordering::Relaxed) && self.wants_thread.load(Ordering::Relaxed)
            }
            EventGate::Topology => {
                self.listening.load(Ordering::Relaxed)
                    && self.wants_topology.load(Ordering::Relaxed)
            }
        }
    }

    /// Waits for the next event this connection is allowed to see. `None` means the broadcaster
    /// (and so the server) is gone.
    pub async fn recv(&mut self) -> Option<Event> {
        loop {
            match self.rx.recv().await {
                Ok(out) if self.passes_gate(out.gate) => return Some(out.event.clone()),
                Ok(_) => continue,
                // A slow connection missed frames; nothing to resend (matches matterjs's
                // FIFO-drop-oldest policy) — just resume from the next one.
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

#[derive(Clone)]
pub struct Broadcaster(broadcast::Sender<Arc<OutEvent>>);

impl Broadcaster {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self(tx)
    }

    pub fn subscribe(&self, id: u64) -> Connection {
        Connection::new(id, self.0.subscribe())
    }

    pub fn send(&self, event: Event, gate: EventGate) {
        let _ = self.0.send(Arc::new(OutEvent { event, gate }));
    }
}

impl Default for Broadcaster {
    fn default() -> Self {
        Self::new()
    }
}
