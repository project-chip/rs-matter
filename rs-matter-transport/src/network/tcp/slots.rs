/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! Per-peer TCP slot state, shared slot table, and bounded TX frame queue.

use core::net::SocketAddr;

use super::frame::{encode_frame_header, Frame, FRAME_HDR_LEN};
use crate::error::{Error, ErrorCode};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, init_array_from_fn, Init};
use crate::utils::storage::Vec as StorageVec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::{IfMultiMutex, MultiNotification, Notification};
use crate::utils::timers::Instant;

pub(super) enum RxOutcome {
    Read(Result<usize, Error>),
    Consumed,
}

pub(super) enum TxOutcome {
    Wrote(Result<usize, Error>),
    Changed,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum PeerState {
    Idle,
    Connecting(SocketAddr),
    Connected(SocketAddr),
}

impl PeerState {
    pub(super) const fn addr(self) -> Option<SocketAddr> {
        match self {
            Self::Idle => None,
            Self::Connecting(addr) | Self::Connected(addr) => Some(addr),
        }
    }
}

pub(super) struct PeerSlot<S, const N: usize, const TX_QUEUE: usize> {
    socket: Mutex<RefCell<Option<S>>>,
    pub(super) rx: IfMultiMutex<Frame<N>>,
    pub(super) tx_producer: IfMultiMutex<()>,
    pub(super) tx: TxQueue<N, TX_QUEUE>,
    pub(super) rx_consumed: Notification,
    pub(super) tx_changed: Notification,
    pub(super) tx_space_available: MultiNotification,
    pub(super) wakeup: Notification,
}

impl<S, const N: usize, const TX_QUEUE: usize> PeerSlot<S, N, TX_QUEUE> {
    pub(super) const fn new() -> Self {
        Self {
            socket: Mutex::new(RefCell::new(None)),
            rx: IfMultiMutex::new(Frame::new()),
            tx_producer: IfMultiMutex::new(()),
            tx: TxQueue::new(),
            rx_consumed: Notification::new(),
            tx_changed: Notification::new(),
            tx_space_available: MultiNotification::new(),
            wakeup: Notification::new(),
        }
    }

    pub(super) fn init() -> impl Init<Self> {
        init!(Self {
            socket: Mutex::new(RefCell::new(None)),
            rx <- IfMultiMutex::init(Frame::init()),
            tx_producer: IfMultiMutex::new(()),
            tx <- TxQueue::init(),
            rx_consumed <- Notification::init(),
            tx_changed <- Notification::init(),
            tx_space_available <- MultiNotification::init(),
            wakeup <- Notification::init(),
        })
    }

    pub(super) fn set_socket(&self, socket: S) {
        self.socket.lock(|cell| *cell.borrow_mut() = Some(socket));
    }

    pub(super) fn take_socket(&self) -> Option<S> {
        self.socket.lock(|cell| cell.borrow_mut().take())
    }
}

#[derive(Copy, Clone)]
pub(super) struct PeerSlotState {
    pub(super) peer: PeerState,
    pub(super) last_activity: Instant,
    pub(super) rx_ready: bool,
    pub(super) tx_head: usize,
    pub(super) tx_count: usize,
    pub(super) close_requested: bool,
    pub(super) authenticated: bool,
}

impl PeerSlotState {
    pub(super) const fn new() -> Self {
        Self {
            peer: PeerState::Idle,
            last_activity: Instant::from_ticks(0),
            rx_ready: false,
            tx_head: 0,
            tx_count: 0,
            close_requested: false,
            authenticated: false,
        }
    }

    pub(super) fn reset(&mut self) {
        self.peer = PeerState::Idle;
        self.last_activity = Instant::from_ticks(0);
        self.rx_ready = false;
        self.tx_head = 0;
        self.tx_count = 0;
        self.close_requested = false;
        self.authenticated = false;
    }

    pub(super) fn connected_addr(&self) -> Option<SocketAddr> {
        match self.peer {
            PeerState::Connected(addr) => Some(addr),
            PeerState::Idle | PeerState::Connecting(_) => None,
        }
    }
}

const CLOSED_PEER_QUEUE: usize = 8;

pub(super) struct SharedState<const SLOTS: usize> {
    pub(super) slots: [PeerSlotState; SLOTS],
    rx_cursor: usize,
    closed_peers: [Option<SocketAddr>; CLOSED_PEER_QUEUE],
    closed_head: usize,
    closed_count: usize,
}

impl<const SLOTS: usize> SharedState<SLOTS> {
    pub(super) const fn new() -> Self {
        Self {
            slots: [const { PeerSlotState::new() }; SLOTS],
            rx_cursor: 0,
            closed_peers: [None; CLOSED_PEER_QUEUE],
            closed_head: 0,
            closed_count: 0,
        }
    }

    pub(super) fn find_peer(&self, addr: SocketAddr) -> Option<usize> {
        self.slots.iter().position(|s| s.peer.addr() == Some(addr))
    }

    pub(super) fn mark_connected(&mut self, idx: usize, addr: SocketAddr, reset_auth: bool) {
        self.slots[idx].peer = PeerState::Connected(addr);
        self.slots[idx].last_activity = Instant::now();
        self.slots[idx].close_requested = false;
        if reset_auth {
            self.slots[idx].authenticated = false;
        }
        self.remove_closed_peer(addr);
    }

    pub(super) fn find_connecting(&self, addr: SocketAddr) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.peer == PeerState::Connecting(addr))
    }

    pub(super) fn next_connecting(&self) -> Option<(usize, SocketAddr)> {
        self.slots
            .iter()
            .enumerate()
            .find_map(|(i, s)| match s.peer {
                PeerState::Connecting(addr) => Some((i, addr)),
                _ => None,
            })
    }

    pub(super) fn find_idle(&self) -> Option<usize> {
        self.slots.iter().position(|s| s.peer == PeerState::Idle)
    }

    /// Pick the best slot to evict when all `SLOTS` are occupied:
    /// 1. Only `Connected` slots (not already `close_requested`) are eligible.
    /// 2. Prefer unauthenticated slots over authenticated slots.
    /// 3. Within the same auth tier, prefer slots with an empty TX queue.
    /// 4. Break ties by longest-idle (`last_activity`).
    pub(super) fn find_evictable(&self) -> Option<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s.peer, PeerState::Connected(_)) && !s.close_requested)
            .min_by_key(|(_, s)| (s.authenticated, s.tx_count > 0, s.last_activity))
            .map(|(i, _)| i)
    }

    pub(super) fn any_rx_ready(&self) -> bool {
        self.slots.iter().any(|s| s.rx_ready)
    }

    pub(super) fn next_rx_ready_slot(&mut self) -> Option<usize> {
        for offset in 0..SLOTS {
            let idx = (self.rx_cursor + offset) % SLOTS;
            if self.slots[idx].rx_ready {
                self.rx_cursor = (idx + 1) % SLOTS;
                return Some(idx);
            }
        }
        None
    }

    pub(super) fn push_closed_peer(&mut self, addr: SocketAddr) {
        for offset in 0..self.closed_count {
            let idx = (self.closed_head + offset) % CLOSED_PEER_QUEUE;
            if self.closed_peers[idx] == Some(addr) {
                return;
            }
        }
        if self.closed_count == CLOSED_PEER_QUEUE {
            let dropped = self.closed_peers[self.closed_head].take();
            warn!(
                "TCP closed-peer queue full; dropping unread close notification for {:?}",
                dropped
            );
            self.closed_head = (self.closed_head + 1) % CLOSED_PEER_QUEUE;
            self.closed_count -= 1;
        }
        let tail = (self.closed_head + self.closed_count) % CLOSED_PEER_QUEUE;
        self.closed_peers[tail] = Some(addr);
        self.closed_count += 1;
    }

    pub(super) fn remove_closed_peer(&mut self, addr: SocketAddr) {
        for offset in 0..self.closed_count {
            let idx = (self.closed_head + offset) % CLOSED_PEER_QUEUE;
            if self.closed_peers[idx] == Some(addr) {
                for shift in offset..self.closed_count - 1 {
                    let cur = (self.closed_head + shift) % CLOSED_PEER_QUEUE;
                    let next = (self.closed_head + shift + 1) % CLOSED_PEER_QUEUE;
                    self.closed_peers[cur] = self.closed_peers[next].take();
                }
                self.closed_count -= 1;
                return;
            }
        }
    }

    pub(super) fn pop_closed_peer(&mut self) -> Option<SocketAddr> {
        if self.closed_count == 0 {
            return None;
        }
        let addr = self.closed_peers[self.closed_head].take();
        self.closed_head = (self.closed_head + 1) % CLOSED_PEER_QUEUE;
        self.closed_count -= 1;
        addr
    }
}

/// Returns `true` if `frame` looks like an encrypted Matter message (`sess_id != 0`).
///
/// Matter `PlainHdr` is at least 8 bytes (`msg_flags: u8`, `sess_id: u16` LE, ...).
pub(super) fn is_encrypted_matter_frame(frame: &[u8]) -> bool {
    frame.len() >= 8 && u16::from_le_bytes([frame[1], frame[2]]) != 0
}

pub(super) struct TxQueue<const N: usize, const Q: usize> {
    pub(super) frames: [IfMultiMutex<TxFrame<N>>; Q],
}

impl<const N: usize, const Q: usize> TxQueue<N, Q> {
    pub(super) const fn new() -> Self {
        Self {
            frames: [const { IfMultiMutex::new(TxFrame::new()) }; Q],
        }
    }

    pub(super) fn init() -> impl Init<Self> {
        init!(Self {
            frames <- init_array_from_fn(|_| IfMultiMutex::init(TxFrame::init())),
        })
    }
}

pub(super) struct TxFrame<const N: usize> {
    header: [u8; FRAME_HDR_LEN],
    payload: StorageVec<u8, N>,
    written: usize,
    pub(super) queued_at: Instant,
}

impl<const N: usize> TxFrame<N> {
    pub(super) const fn new() -> Self {
        Self {
            header: [0; FRAME_HDR_LEN],
            payload: StorageVec::new(),
            written: 0,
            queued_at: Instant::from_ticks(0),
        }
    }

    pub(super) fn init() -> impl Init<Self> {
        init!(Self {
            header: [0; FRAME_HDR_LEN],
            payload <- StorageVec::init(),
            written: 0,
            queued_at: Instant::from_ticks(0),
        })
    }

    pub(super) fn encode(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.is_empty() || data.len() > N {
            return Err(ErrorCode::BufferTooSmall.into());
        }
        self.header = encode_frame_header(data.len())?;
        self.payload.clear();
        self.payload
            .extend_from_slice(data)
            .map_err(|_| ErrorCode::BufferTooSmall)?;
        self.written = 0;
        self.queued_at = Instant::now();
        Ok(())
    }

    pub(super) fn unwritten(&self) -> &[u8] {
        if self.written < FRAME_HDR_LEN {
            &self.header[self.written..]
        } else {
            &self.payload[self.written - FRAME_HDR_LEN..]
        }
    }

    pub(super) fn advance(&mut self, count: usize) {
        debug_assert!(self.written + count <= FRAME_HDR_LEN + self.payload.len());
        self.written += count;
    }

    pub(super) fn is_complete(&self) -> bool {
        self.written == FRAME_HDR_LEN + self.payload.len()
    }
}
