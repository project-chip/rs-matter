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

//! Static TCP buffer pool, bound listener handle, and async slot/peer I/O loops.

use core::future::{pending, Future};
use core::net::SocketAddr;
use core::pin::pin;

use super::frame::{encode_frame_header, Frame, FRAME_HDR_LEN};
use super::slots::{
    is_encrypted_matter_frame, PeerSlot, PeerState, RxOutcome, SharedState, TxFrame, TxOutcome,
};
use super::{NetTcpListener, NetTcpRead, NetTcpSocket, NetTcpWrite, TcpConfig};
use crate::error::{Error, ErrorCode};
use crate::network::{Address, NetworkReceive, NetworkSend};
use crate::plain_hdr::PlainHdr;
use crate::proto_hdr::ProtoHdr;
use crate::sc::{GeneralCode, OpCode, StatusReport, PROTO_ID_SECURE_CHANNEL};
use crate::utils::cell::RefCell;
use crate::utils::futures::{join, join_array, select, select3, yield_now, Either, Either3};
use crate::utils::init::{init, init_array_from_fn, Init};
use crate::utils::storage::WriteBuf;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::{IfMultiMutexGuard, IfMutex, MultiNotification, Notification};
use crate::utils::timers::{with_timeout, Duration, Instant, Timer};

/// Caller-owned static buffers and slot state for [`TcpBound`] / [`super::TcpNetwork`].
///
/// Initialize in static storage via [`Self::init`] or [`Self::init_with_config`]
/// so large frame arrays live outside async task futures.
pub struct TcpBuffers<
    S,
    const N: usize = { crate::MAX_RX_BUF_SIZE },
    const SLOTS: usize = 4,
    const TX_QUEUE: usize = 2,
> {
    state: Mutex<RefCell<SharedState<SLOTS>>>,
    slots: [PeerSlot<S, N, TX_QUEUE>; SLOTS],
    rx_available: MultiNotification,
    listener_wakeup: Notification,
    slot_freed: MultiNotification,
    config: TcpConfig,
}

/// Lightweight bound operational TCP runner backed by caller-owned [`TcpBuffers`].
pub struct TcpBound<
    'a,
    L: NetTcpListener,
    const N: usize = { crate::MAX_RX_BUF_SIZE },
    const SLOTS: usize = 4,
    const TX_QUEUE: usize = 2,
> {
    listener: IfMutex<L>,
    buffers: &'a TcpBuffers<L::Socket, N, SLOTS, TX_QUEUE>,
}

enum PeerAction {
    Continue,
    Close { send_too_large: bool },
}

const fn validate_config<const N: usize, const SLOTS: usize, const TX_QUEUE: usize>() {
    assert!(N > 0, "TCP frame buffer size N must be non-zero");
    assert!(
        N <= crate::MAX_RX_BUF_SIZE,
        "TCP frame buffer size N must not exceed MAX_RX_BUF_SIZE"
    );
    assert!(SLOTS > 0, "TCP SLOTS must be non-zero");
    assert!(TX_QUEUE > 0, "TX_QUEUE must be non-zero");
}

impl<S> TcpBuffers<S, { crate::MAX_RX_BUF_SIZE }, 4, 2> {
    /// Create TCP buffers with default configuration.
    pub const fn new() -> Self {
        Self::with_config(TcpConfig::new())
    }

    /// Create an in-place initializer for TCP buffers with default configuration.
    pub fn init() -> impl Init<Self> {
        Self::init_with_config(TcpConfig::new())
    }
}

impl<S> Default for TcpBuffers<S, { crate::MAX_RX_BUF_SIZE }, 4, 2> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, const N: usize, const SLOTS: usize, const TX_QUEUE: usize>
    TcpBuffers<S, N, SLOTS, TX_QUEUE>
{
    /// Create TCP buffers with custom configuration.
    pub const fn with_config(config: TcpConfig) -> Self {
        const {
            validate_config::<N, SLOTS, TX_QUEUE>();
        }
        Self {
            state: Mutex::new(RefCell::new(SharedState::new())),
            slots: [const { PeerSlot::new() }; SLOTS],
            rx_available: MultiNotification::new(),
            listener_wakeup: Notification::new(),
            slot_freed: MultiNotification::new(),
            config,
        }
    }

    /// Create an in-place initializer for TCP buffers with custom configuration.
    ///
    /// Prefer this over [`Self::with_config`] for large `N` or `SLOTS` to avoid
    /// materializing multi-KiB buffers on the stack.
    pub fn init_with_config(config: TcpConfig) -> impl Init<Self> {
        const {
            validate_config::<N, SLOTS, TX_QUEUE>();
        }
        init!(Self {
            state: Mutex::new(RefCell::new(SharedState::new())),
            slots <- init_array_from_fn(|_| PeerSlot::init()),
            rx_available <- MultiNotification::init(),
            listener_wakeup <- Notification::init(),
            slot_freed <- MultiNotification::init(),
            config,
        })
    }

    /// Bind `listener` to these buffers, returning a lightweight [`TcpBound`] handle.
    pub fn bind<L>(&self, listener: L) -> TcpBound<'_, L, N, SLOTS, TX_QUEUE>
    where
        L: NetTcpListener<Socket = S>,
    {
        self.reset_all();
        TcpBound {
            listener: IfMutex::new(listener),
            buffers: self,
        }
    }

    fn reset_all(&self) {
        self.state
            .lock(|cell| *cell.borrow_mut() = SharedState::new());
        for slot in &self.slots {
            let _ = slot.take_socket();
            if let Ok(mut rx) = slot.rx.try_lock() {
                rx.reset();
            }
        }
    }
}

impl<L: NetTcpListener, const N: usize, const SLOTS: usize, const TX_QUEUE: usize>
    TcpBound<'_, L, N, SLOTS, TX_QUEUE>
{
    /// Drive TCP accept/connect and all `SLOTS` concurrent peer I/O loops.
    ///
    /// Run concurrently with the Matter transport. No blocking mutex is held across `.await`.
    pub async fn run(&self) -> Result<(), Error> {
        self.buffers.run_with_listener(&self.listener).await
    }
}

impl<S: NetTcpSocket, const N: usize, const SLOTS: usize, const TX_QUEUE: usize>
    TcpBuffers<S, N, SLOTS, TX_QUEUE>
{
    /// Drive TCP accept/connect and all `SLOTS` concurrent peer I/O loops.
    pub(super) async fn run_with_listener<L>(&self, listener: &IfMutex<L>) -> Result<(), Error>
    where
        L: NetTcpListener<Socket = S>,
    {
        let listener_fut = self.run_listener(listener);
        let slots_fut = join_array(core::array::from_fn::<_, SLOTS, _>(|i| self.run_slot(i)));
        let (res, _) = join(listener_fut, slots_fut).await;
        res
    }

    async fn connect_pending_slot<L>(&self, listener: &mut L, slot_idx: usize, addr: SocketAddr)
    where
        L: NetTcpListener<Socket = S>,
    {
        match listener.connect(addr).await {
            Ok(mut socket) => {
                let claimed = self.with_state_mut(|s| {
                    if s.slots[slot_idx].peer == PeerState::Connecting(addr) {
                        s.mark_connected(slot_idx, addr, false);
                        true
                    } else {
                        false
                    }
                });
                if claimed {
                    self.slots[slot_idx].set_socket(socket);
                    self.slots[slot_idx].wakeup.notify();
                } else {
                    let _ = socket.close().await;
                }
            }
            Err(e) => {
                warn!("TCP connect to {} failed: {:?}", addr, e);
                self.reset_slot(slot_idx, true).await;
            }
        }
    }

    async fn run_listener<L>(&self, listener: &IfMutex<L>) -> Result<(), Error>
    where
        L: NetTcpListener<Socket = S>,
    {
        let mut listener = listener.lock().await;
        loop {
            if let Some((slot_idx, addr)) = self.with_state(|s| s.next_connecting()) {
                self.connect_pending_slot(&mut *listener, slot_idx, addr)
                    .await;
                continue;
            }

            let wakeup = self.listener_wakeup.wait();
            let freed = self.slot_freed.wait();
            let can_accept =
                self.with_state(|s| s.find_idle().is_some() || s.find_evictable().is_some());
            if !can_accept {
                select(pin!(wakeup), pin!(freed)).await;
                continue;
            }

            match select(pin!(listener.accept()), pin!(wakeup)).await {
                Either::First(Ok((addr, socket))) => {
                    self.assign_accepted_socket(addr, socket).await;
                }
                Either::First(Err(e)) => {
                    warn!("TCP accept error: {:?}", e);
                    Timer::after(Duration::from_millis(10)).await;
                }
                Either::Second(()) => {}
            }
        }
    }

    async fn assign_accepted_socket(&self, addr: SocketAddr, mut socket: S) {
        loop {
            let freed_wait = self.slot_freed.wait();
            enum AssignOutcome {
                Assigned(usize),
                WaitEviction(usize),
                Reject,
            }

            let outcome = self.with_state_mut(|s| {
                if let Some(idx) = s.find_connecting(addr) {
                    s.mark_connected(idx, addr, false);
                    return AssignOutcome::Assigned(idx);
                }
                if let Some(idx) = s.find_idle() {
                    s.mark_connected(idx, addr, true);
                    return AssignOutcome::Assigned(idx);
                }
                if let Some(evict_idx) = s.find_evictable() {
                    s.slots[evict_idx].close_requested = true;
                    return AssignOutcome::WaitEviction(evict_idx);
                }
                AssignOutcome::Reject
            });

            match outcome {
                AssignOutcome::Assigned(idx) => {
                    self.slots[idx].set_socket(socket);
                    self.slots[idx].wakeup.notify();
                    return;
                }
                AssignOutcome::WaitEviction(evict_idx) => {
                    self.slots[evict_idx].tx_changed.notify();
                    if with_timeout(self.config.send_timeout, freed_wait)
                        .await
                        .is_err()
                    {
                        let _ = socket.close().await;
                        return;
                    }
                }
                AssignOutcome::Reject => {
                    let _ = socket.close().await;
                    return;
                }
            }
        }
    }

    async fn run_slot(&self, slot_idx: usize) {
        let slot = &self.slots[slot_idx];
        loop {
            let wait = slot.wakeup.wait();
            let Some(mut socket) = slot.take_socket() else {
                wait.await;
                continue;
            };

            if let Err(e) = socket.set_keep_alive(self.config.keep_alive) {
                let addr = self.with_state(|s| s.slots[slot_idx].peer.addr());
                warn!("TCP set_keep_alive failed for {:?}: {:?}", addr, e);
            }

            self.with_state_mut(|s| {
                s.slots[slot_idx].last_activity = Instant::now();
                s.slots[slot_idx].rx_ready = false;
                s.slots[slot_idx].close_requested = false;
            });
            {
                let mut rx = slot.rx.lock().await;
                rx.reset();
            }

            let send_too_large = self.run_peer(slot_idx, &mut socket).await;

            if send_too_large {
                self.send_message_too_large(&mut socket).await;
            }

            let _ = socket.close().await;
            drop(socket);

            self.reset_slot(slot_idx, true).await;
        }
    }

    async fn reset_slot(&self, slot_idx: usize, notify_closed: bool) {
        let closed_addr = self.with_state_mut(|s| {
            let addr = if notify_closed {
                s.slots[slot_idx].peer.addr()
            } else {
                None
            };
            s.slots[slot_idx].reset();
            if let Some(addr) = addr {
                s.push_closed_peer(addr);
            }
            addr
        });
        {
            let mut rx = self.slots[slot_idx].rx.lock().await;
            rx.reset();
        }
        self.slots[slot_idx].tx_space_available.notify();
        self.slot_freed.notify();
        self.listener_wakeup.notify();
        if closed_addr.is_some() {
            self.rx_available.notify();
        }
    }

    fn next_deadline(
        &self,
        last_activity: Instant,
        tx_frame: Option<&TxFrame<N>>,
    ) -> Option<Instant> {
        let idle_deadline = self.config.idle_timeout.map(|t| last_activity + t);
        let send_deadline = tx_frame.map(|frame| frame.queued_at + self.config.send_timeout);
        match (idle_deadline, send_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    fn mark_rx_ready(&self, slot_idx: usize, authenticated: bool) {
        self.with_state_mut(|s| {
            s.slots[slot_idx].rx_ready = true;
            if authenticated {
                s.slots[slot_idx].authenticated = true;
            }
        });
        self.rx_available.notify();
    }

    fn handle_rx_outcome(
        &self,
        slot_idx: usize,
        outcome: RxOutcome,
        rx_guard: Option<IfMultiMutexGuard<'_, Frame<N>>>,
    ) -> PeerAction {
        match outcome {
            RxOutcome::Read(Ok(0) | Err(_)) => PeerAction::Close {
                send_too_large: false,
            },
            RxOutcome::Read(Ok(count)) => {
                self.with_state_mut(|s| s.slots[slot_idx].last_activity = Instant::now());
                if let Some(mut rx) = rx_guard {
                    if rx.advance(count).is_err() {
                        return PeerAction::Close {
                            send_too_large: true,
                        };
                    }
                    if rx.is_complete() {
                        let authenticated = rx.message().is_some_and(is_encrypted_matter_frame);
                        drop(rx);
                        self.mark_rx_ready(slot_idx, authenticated);
                    }
                }
                PeerAction::Continue
            }
            RxOutcome::Consumed => PeerAction::Continue,
        }
    }

    fn handle_tx_outcome(
        &self,
        slot_idx: usize,
        outcome: TxOutcome,
        mut tx_guard: Option<IfMultiMutexGuard<'_, TxFrame<N>>>,
    ) -> PeerAction {
        match outcome {
            TxOutcome::Wrote(Ok(0) | Err(_)) => PeerAction::Close {
                send_too_large: false,
            },
            TxOutcome::Wrote(Ok(count)) => {
                self.with_state_mut(|s| s.slots[slot_idx].last_activity = Instant::now());
                if let Some(mut tx) = tx_guard.take() {
                    tx.advance(count);
                    if tx.is_complete() {
                        drop(tx);
                        self.with_state_mut(|s| {
                            s.slots[slot_idx].tx_head = (s.slots[slot_idx].tx_head + 1) % TX_QUEUE;
                            s.slots[slot_idx].tx_count -= 1;
                        });
                        self.slots[slot_idx].tx_space_available.notify();
                    }
                }
                PeerAction::Continue
            }
            TxOutcome::Changed => PeerAction::Continue,
        }
    }

    async fn run_peer(&self, slot_idx: usize, socket: &mut S) -> bool {
        let slot = &self.slots[slot_idx];
        let (mut rx_sock, mut tx_sock) = socket.split();

        loop {
            let rx_wait = slot.rx_consumed.wait();
            let tx_wait = slot.tx_changed.wait();

            let (rx_ready, tx_slot, last_activity, close_requested) = self.with_state(|s| {
                let st = &s.slots[slot_idx];
                (
                    st.rx_ready,
                    (st.tx_count > 0).then_some(st.tx_head),
                    st.last_activity,
                    st.close_requested,
                )
            });

            if close_requested {
                return false;
            }

            let mut rx_guard = if !rx_ready {
                let rx = slot.rx.lock().await;
                if rx.is_complete() {
                    let authenticated = rx.message().is_some_and(is_encrypted_matter_frame);
                    drop(rx);
                    self.mark_rx_ready(slot_idx, authenticated);
                    continue;
                }
                Some(rx)
            } else {
                None
            };

            let tx_guard = if let Some(q_slot) = tx_slot {
                Some(slot.tx.frames[q_slot].lock().await)
            } else {
                None
            };

            let deadline = self.next_deadline(last_activity, tx_guard.as_deref());

            let outcome = select3(
                pin!(async {
                    if let Some(rx) = rx_guard.as_mut() {
                        RxOutcome::Read(rx_sock.read(rx.next_read_buf_mut()).await)
                    } else {
                        rx_wait.await;
                        RxOutcome::Consumed
                    }
                }),
                pin!(async {
                    if let Some(tx) = tx_guard.as_ref() {
                        TxOutcome::Wrote(tx_sock.write(tx.unwritten()).await)
                    } else {
                        tx_wait.await;
                        TxOutcome::Changed
                    }
                }),
                pin!(async {
                    match deadline {
                        Some(d) => Timer::at(d).await,
                        None => pending().await,
                    }
                }),
            )
            .await;

            let action = match outcome {
                Either3::First(rx_outcome) => {
                    self.handle_rx_outcome(slot_idx, rx_outcome, rx_guard)
                }
                Either3::Second(tx_outcome) => {
                    self.handle_tx_outcome(slot_idx, tx_outcome, tx_guard)
                }
                Either3::Third(()) => PeerAction::Close {
                    send_too_large: false,
                },
            };
            if let PeerAction::Close { send_too_large } = action {
                return send_too_large;
            }
        }
    }

    async fn send_message_too_large(&self, socket: &mut S) {
        if let Ok((buf, len)) = encode_message_too_large_frame() {
            let (_, mut tx_sock) = socket.split();
            let _ = with_timeout(self.config.send_timeout, async {
                let mut written = 0;
                while written < len {
                    match tx_sock.write(&buf[written..len]).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => written += n,
                    }
                }
            })
            .await;
        }
    }

    pub(super) async fn wait_available(&self) -> Result<(), Error> {
        loop {
            let notif = self.rx_available.wait();
            if self.with_state(|s| s.any_rx_ready()) {
                return Ok(());
            }
            notif.await;
        }
    }

    pub(super) async fn wait_available_or_closed(&self) -> Result<Option<Address>, Error> {
        loop {
            let notif = self.rx_available.wait();
            enum ReadyEvent {
                Closed(SocketAddr),
                RxReady,
                None,
            }
            let event = self.with_state_mut(|s| {
                if let Some(addr) = s.pop_closed_peer() {
                    ReadyEvent::Closed(addr)
                } else if s.any_rx_ready() {
                    ReadyEvent::RxReady
                } else {
                    ReadyEvent::None
                }
            });
            match event {
                ReadyEvent::Closed(addr) => return Ok(Some(Address::Tcp(addr))),
                ReadyEvent::RxReady => return Ok(None),
                ReadyEvent::None => notif.await,
            }
        }
    }

    pub(super) async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        loop {
            self.wait_available().await?;

            let Some(slot_idx) = self.with_state_mut(|s| s.next_rx_ready_slot()) else {
                continue;
            };

            let mut rx = self.slots[slot_idx].rx.lock().await;
            let Some(addr) = self.with_state(|s| {
                s.slots[slot_idx]
                    .rx_ready
                    .then(|| s.slots[slot_idx].connected_addr())
                    .flatten()
            }) else {
                continue;
            };

            let result = if let Some(message) = rx.message() {
                let len = message.len();
                if len > buffer.len() {
                    rx.reset();
                    self.with_state_mut(|s| {
                        s.slots[slot_idx].rx_ready = false;
                        s.slots[slot_idx].close_requested = true;
                    });
                    self.slots[slot_idx].tx_changed.notify();
                    self.slots[slot_idx].rx_consumed.notify();
                    Err(Error::new(ErrorCode::BufferTooSmall))
                } else {
                    buffer[..len].copy_from_slice(message);
                    rx.reset();
                    self.with_state_mut(|s| {
                        s.slots[slot_idx].rx_ready = false;
                    });
                    self.slots[slot_idx].rx_consumed.notify();
                    Ok(Some((len, Address::Tcp(addr))))
                }
            } else {
                Ok(None)
            };
            drop(rx);

            if let Some(pkt) = result? {
                return Ok(pkt);
            }
        }
    }

    async fn wait_until_deadline(
        wait: impl Future<Output = ()>,
        deadline: Instant,
    ) -> Result<(), Error> {
        if Instant::now() >= deadline {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        if matches!(
            select(pin!(wait), pin!(Timer::at(deadline))).await,
            Either::Second(())
        ) {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        Ok(())
    }

    async fn acquire_slot_for_send(
        &self,
        addr: SocketAddr,
        deadline: Instant,
    ) -> Result<usize, Error> {
        loop {
            let freed_wait = self.slot_freed.wait();

            enum SlotAlloc {
                Found(usize),
                NewConnecting(usize),
                EvictAndWait(usize),
                Wait,
            }

            let alloc = self.with_state_mut(|s| {
                if let Some(idx) = s.find_peer(addr) {
                    return SlotAlloc::Found(idx);
                }
                if let Some(idx) = s.find_idle() {
                    s.slots[idx].peer = PeerState::Connecting(addr);
                    s.slots[idx].last_activity = Instant::now();
                    s.slots[idx].close_requested = false;
                    s.slots[idx].authenticated = false;
                    s.remove_closed_peer(addr);
                    return SlotAlloc::NewConnecting(idx);
                }
                if let Some(evict_idx) = s.find_evictable() {
                    s.slots[evict_idx].close_requested = true;
                    return SlotAlloc::EvictAndWait(evict_idx);
                }
                SlotAlloc::Wait
            });

            match alloc {
                SlotAlloc::Found(idx) => return Ok(idx),
                SlotAlloc::NewConnecting(idx) => {
                    self.listener_wakeup.notify();
                    return Ok(idx);
                }
                SlotAlloc::EvictAndWait(evict_idx) => {
                    self.slots[evict_idx].tx_changed.notify();
                    self.listener_wakeup.notify();
                }
                SlotAlloc::Wait => {}
            }

            Self::wait_until_deadline(freed_wait, deadline).await?;
        }
    }

    async fn wait_tx_queue_slot(
        &self,
        slot_idx: usize,
        addr: SocketAddr,
        deadline: Instant,
    ) -> Result<usize, Error> {
        loop {
            let space_wait = self.slots[slot_idx].tx_space_available.wait();

            let q_slot = self.with_state(|s| {
                let st = &s.slots[slot_idx];
                if st.peer.addr() != Some(addr) || st.close_requested {
                    return Err(Error::new(ErrorCode::ResourceExhausted));
                }
                if st.tx_count < TX_QUEUE {
                    Ok(Some((st.tx_head + st.tx_count) % TX_QUEUE))
                } else {
                    Ok(None)
                }
            })?;

            if let Some(q_slot) = q_slot {
                return Ok(q_slot);
            }

            Self::wait_until_deadline(space_wait, deadline).await?;
        }
    }

    pub(super) async fn send_to(&self, data: &[u8], address: Address) -> Result<(), Error> {
        let Address::Tcp(addr) = address else {
            return Err(ErrorCode::NoNetworkInterface.into());
        };
        if data.is_empty() || data.len() > N {
            return Err(ErrorCode::BufferTooSmall.into());
        }

        let deadline = Instant::now() + self.config.send_timeout;
        let slot_idx = self.acquire_slot_for_send(addr, deadline).await?;

        let producer = match select(
            pin!(self.slots[slot_idx].tx_producer.lock()),
            pin!(Timer::at(deadline)),
        )
        .await
        {
            Either::First(guard) => guard,
            Either::Second(()) => return Err(ErrorCode::ResourceExhausted.into()),
        };

        let q_slot = self.wait_tx_queue_slot(slot_idx, addr, deadline).await?;

        {
            let mut frame = self.slots[slot_idx].tx.frames[q_slot]
                .try_lock()
                .map_err(|_| ErrorCode::ResourceExhausted)?;
            frame.encode(data)?;
        }

        let authenticated = is_encrypted_matter_frame(data);
        self.with_state_mut(|s| {
            let st = &mut s.slots[slot_idx];
            if st.peer.addr() != Some(addr) || st.close_requested {
                return Err(Error::new(ErrorCode::ResourceExhausted));
            }
            st.tx_count += 1;
            if authenticated {
                st.authenticated = true;
            }
            Ok(())
        })?;

        drop(producer);
        self.slots[slot_idx].tx_changed.notify();
        yield_now().await;
        Ok(())
    }

    #[inline]
    pub(super) fn with_state<R>(&self, f: impl FnOnce(&SharedState<SLOTS>) -> R) -> R {
        self.state.lock(|cell| f(&cell.borrow()))
    }

    #[inline]
    fn with_state_mut<R>(&self, f: impl FnOnce(&mut SharedState<SLOTS>) -> R) -> R {
        self.state.lock(|cell| f(&mut cell.borrow_mut()))
    }
}

macro_rules! impl_tcp_network_traits {
    ($($ty:ty),* $(,)?) => {
        $(
            impl<L: NetTcpListener, const N: usize, const SLOTS: usize, const TX_QUEUE: usize>
                NetworkSend for $ty
            {
                async fn send_to(&mut self, data: &[u8], address: Address) -> Result<(), Error> {
                    self.buffers.send_to(data, address).await
                }
            }

            impl<L: NetTcpListener, const N: usize, const SLOTS: usize, const TX_QUEUE: usize>
                NetworkReceive for $ty
            {
                async fn wait_available(&mut self) -> Result<(), Error> {
                    self.buffers.wait_available().await
                }

                async fn recv_from(
                    &mut self,
                    buffer: &mut [u8],
                ) -> Result<(usize, Address), Error> {
                    self.buffers.recv_from(buffer).await
                }

                async fn wait_available_or_closed(&mut self) -> Result<Option<Address>, Error> {
                    self.buffers.wait_available_or_closed().await
                }
            }
        )*
    };
}

pub(super) use impl_tcp_network_traits;

impl_tcp_network_traits!(
    TcpBound<'_, L, N, SLOTS, TX_QUEUE>,
    &TcpBound<'_, L, N, SLOTS, TX_QUEUE>,
);

fn encode_message_too_large_frame() -> Result<([u8; 64], usize), Error> {
    let mut buf = [0u8; 64];
    let mut wb = WriteBuf::new(&mut buf[FRAME_HDR_LEN..]);
    let plain = PlainHdr::new();
    plain.encode(&mut wb)?;
    let mut proto = ProtoHdr::new();
    proto.set_initiator();
    proto.proto_id = PROTO_ID_SECURE_CHANNEL;
    proto.proto_opcode = OpCode::StatusReport as u8;
    proto.encode(&mut wb)?;
    StatusReport {
        general_code: GeneralCode::MessageTooLarge,
        proto_id: PROTO_ID_SECURE_CHANNEL as u32,
        proto_code: 0,
        proto_data: &[],
    }
    .write(&mut wb)?;
    let payload_len = wb.as_slice().len();
    let hdr = encode_frame_header(payload_len)?;
    buf[..FRAME_HDR_LEN].copy_from_slice(&hdr);
    Ok((buf, FRAME_HDR_LEN + payload_len))
}
