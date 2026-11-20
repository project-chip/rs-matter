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
use crate::utils::init::{init, zeroed, Init};
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

pub(super) struct PeerSlot<const N: usize, const TX_BUF: usize> {
    pub(super) rx: IfMultiMutex<Frame<N>>,
    pub(super) rx_consumed: Notification,
    pub(super) tx_changed: Notification,
    pub(super) tx_space_available: MultiNotification,
    pub(super) wakeup: Notification,
    tx: Mutex<RefCell<TxQueue<TX_BUF>>>,
}

impl<const N: usize, const TX_BUF: usize> PeerSlot<N, TX_BUF> {
    pub(super) const fn new() -> Self {
        Self {
            rx: IfMultiMutex::new(Frame::new()),
            rx_consumed: Notification::new(),
            tx_changed: Notification::new(),
            tx_space_available: MultiNotification::new(),
            wakeup: Notification::new(),
            tx: Mutex::new(RefCell::new(TxQueue::new())),
        }
    }

    pub(super) fn init() -> impl Init<Self> {
        init!(Self {
            rx <- IfMultiMutex::init(Frame::init()),
            tx <- Mutex::init(RefCell::init(TxQueue::init())),
            rx_consumed <- Notification::init(),
            tx_changed <- Notification::init(),
            tx_space_available <- MultiNotification::init(),
            wakeup <- Notification::init(),
        })
    }

    #[inline]
    pub(super) fn with_tx<R>(&self, f: impl FnOnce(&TxQueue<TX_BUF>) -> R) -> R {
        self.tx.lock(|cell| f(&cell.borrow()))
    }

    #[inline]
    pub(super) fn with_tx_mut<R>(&self, f: impl FnOnce(&mut TxQueue<TX_BUF>) -> R) -> R {
        self.tx.lock(|cell| f(&mut cell.borrow_mut()))
    }
}

#[derive(Copy, Clone)]
pub(super) struct PeerSlotState {
    pub(super) peer: PeerState,
    pub(super) last_activity: Instant,
    pub(super) rx_ready: bool,
    pub(super) tx_pending: bool,
    pub(super) close_requested: bool,
    pub(super) authenticated: bool,
}

impl PeerSlotState {
    pub(super) const fn new() -> Self {
        Self {
            peer: PeerState::Idle,
            last_activity: Instant::from_ticks(0),
            rx_ready: false,
            tx_pending: false,
            close_requested: false,
            authenticated: false,
        }
    }

    pub(super) fn reset(&mut self) {
        self.peer = PeerState::Idle;
        self.last_activity = Instant::from_ticks(0);
        self.rx_ready = false;
        self.tx_pending = false;
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

    pub(super) fn find_idle(&self) -> Option<usize> {
        self.slots.iter().position(|s| s.peer == PeerState::Idle)
    }

    /// Pick the best slot to evict when all `SLOTS` are occupied:
    /// 1. Only `Connected`, unauthenticated slots (not already `close_requested`) are eligible;
    ///    authenticated slots are never evicted.
    /// 2. Prefer slots with an empty TX queue.
    /// 3. Break ties by longest-idle (`last_activity`).
    pub(super) fn find_evictable(&self) -> Option<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                matches!(s.peer, PeerState::Connected(_)) && !s.close_requested && !s.authenticated
            })
            .min_by_key(|(_, s)| (s.tx_pending, s.last_activity))
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

pub(super) struct TxQueue<const TX_BUF: usize> {
    buf: [u8; TX_BUF],
    head: usize,
    len: usize,
    oldest_queued_at: Instant,
}

impl<const TX_BUF: usize> TxQueue<TX_BUF> {
    pub(super) const fn new() -> Self {
        Self {
            buf: [0; TX_BUF],
            head: 0,
            len: 0,
            oldest_queued_at: Instant::from_ticks(0),
        }
    }

    pub(super) fn init() -> impl Init<Self> {
        init!(Self {
            buf <- zeroed(),
            head: 0,
            len: 0,
            oldest_queued_at: Instant::from_ticks(0),
        })
    }

    pub(super) fn reset(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(super) fn free(&self) -> usize {
        TX_BUF - self.len
    }

    pub(super) fn queued_at(&self) -> Option<Instant> {
        (self.len > 0).then_some(self.oldest_queued_at)
    }

    pub(super) fn enqueue(&mut self, data: &[u8]) -> Result<(), Error> {
        let total = FRAME_HDR_LEN + data.len();
        if data.is_empty() || total > TX_BUF {
            return Err(ErrorCode::BufferTooSmall.into());
        }
        if self.free() < total {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        let hdr = encode_frame_header(data.len())?;
        let was_empty = self.len == 0;
        self.write_ring(&hdr);
        self.write_ring(data);
        if was_empty {
            self.oldest_queued_at = Instant::now();
        }
        Ok(())
    }

    pub(super) fn copy_chunk(&self, dst: &mut [u8]) -> usize {
        let count = self.len.min(dst.len());
        if count == 0 {
            return 0;
        }
        let first = (TX_BUF - self.head).min(count);
        dst[..first].copy_from_slice(&self.buf[self.head..self.head + first]);
        if first < count {
            dst[first..count].copy_from_slice(&self.buf[..count - first]);
        }
        count
    }

    pub(super) fn advance(&mut self, count: usize) {
        debug_assert!(count <= self.len);
        self.head = (self.head + count) % TX_BUF;
        self.len -= count;
        if self.len > 0 && count > 0 {
            self.oldest_queued_at = Instant::now();
        }
    }

    fn write_ring(&mut self, src: &[u8]) {
        let tail = (self.head + self.len) % TX_BUF;
        let first = (TX_BUF - tail).min(src.len());
        self.buf[tail..tail + first].copy_from_slice(&src[..first]);
        if first < src.len() {
            self.buf[..src.len() - first].copy_from_slice(&src[first..]);
        }
        self.len += src.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_queue_wraps_header_and_payload_across_ring_boundary() {
        let mut q = TxQueue::<12>::new();
        // Frame 1: 4-byte header + 6-byte payload = 10 bytes (head=0, tail=10).
        q.enqueue(b"abcdef").unwrap();
        assert_eq!(q.free(), 2);

        let mut out = [0u8; 16];
        let n = q.copy_chunk(&mut out[..10]);
        assert_eq!(n, 10);
        assert_eq!(&out[..n], b"\x06\0\0\0abcdef");
        q.advance(10); // head=10, len=0 (only 2 bytes before end of 12-byte ring)
        assert!(q.is_empty());
        assert_eq!(q.free(), 12);

        // Frame 2: 4-byte header wraps (2 bytes at [10..12], 2 bytes at [0..2]),
        // followed by 5-byte payload at [2..7] (total 9 bytes).
        q.enqueue(b"12345").unwrap();
        assert_eq!(q.free(), 3);

        // Read in partial chunks across the wraparound boundary.
        let n1 = q.copy_chunk(&mut out[..5]);
        assert_eq!(n1, 5);
        assert_eq!(&out[..5], b"\x05\0\0\x001");
        q.advance(3); // Partial write: only 3 of the 5 copied bytes were written (head=1, len=6).

        let n2 = q.copy_chunk(&mut out[..16]);
        assert_eq!(n2, 6);
        assert_eq!(&out[..6], b"\x0012345");
        q.advance(6);
        assert!(q.is_empty());

        // Frame 3: header at [7..11], payload wraps across [11..12] and [0..4].
        q.enqueue(b"vwxyz").unwrap();
        let n3 = q.copy_chunk(&mut out);
        assert_eq!(n3, 9);
        assert_eq!(&out[..n3], b"\x05\0\0\0vwxyz");
        q.advance(9);
        assert!(q.is_empty());
    }

    #[test]
    fn tx_queue_handles_exact_capacity_and_backpressure() {
        let mut q = TxQueue::<10>::new();
        q.enqueue(b"123456").unwrap(); // 4 + 6 = 10 bytes (exact fill)
        assert_eq!(q.free(), 0);
        assert!(!q.is_empty());

        let err = q.enqueue(b"x").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceExhausted);

        q.reset();
        assert!(q.is_empty());
        assert_eq!(q.free(), 10);
        assert_eq!(q.queued_at(), None);
    }

    #[test]
    fn tx_queue_rejects_empty_and_oversized_frames() {
        let mut q = TxQueue::<10>::new();
        assert_eq!(
            q.enqueue(&[]).unwrap_err().code(),
            ErrorCode::BufferTooSmall
        );
        assert_eq!(
            q.enqueue(b"1234567").unwrap_err().code(),
            ErrorCode::BufferTooSmall
        );
    }

    #[test]
    fn tx_queue_init_empty_copy_zero_advance_and_queued_at() {
        use crate::utils::init::InitMaybeUninit;
        use core::mem::MaybeUninit;

        let mut slot = MaybeUninit::<TxQueue<20>>::uninit();
        let q = slot.init_with(TxQueue::init());
        assert!(q.is_empty());
        assert_eq!(q.queued_at(), None);

        let mut out = [0u8; 8];
        assert_eq!(q.copy_chunk(&mut out), 0);

        q.enqueue(b"ab").unwrap();
        let first_ts = q.queued_at().unwrap();
        assert_eq!(q.copy_chunk(&mut []), 0);

        // Enqueuing a second frame while non-empty keeps `oldest_queued_at`.
        q.enqueue(b"cd").unwrap();
        assert_eq!(q.queued_at(), Some(first_ts));

        // Advancing 0 bytes is a no-op.
        q.advance(0);
        assert_eq!(q.free(), 20 - 12);
        assert_eq!(q.queued_at(), Some(first_ts));

        // Partial advance while still non-empty keeps `queued_at()` Some.
        q.advance(6);
        assert!(!q.is_empty());
        assert!(q.queued_at().is_some());

        // Full drain clears `queued_at()`.
        q.advance(6);
        assert!(q.is_empty());
        assert_eq!(q.queued_at(), None);

        // SAFETY: `slot` was initialized via `init_with` above.
        unsafe { slot.assume_init_drop() };
    }
}
