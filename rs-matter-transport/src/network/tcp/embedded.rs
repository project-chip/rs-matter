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

//! Resource-bounded Matter TCP transport for embedded network drivers.
//!
//! [`TcpServer`] accepts one operational peer, rejecting additional peers until
//! that stream closes. Its fixed receive buffer supports the transport's normal
//! packet size; larger announced frames are rejected before reading the payload.

use core::future::{pending, poll_fn};
use core::net::SocketAddr;
use core::task::{Context, Poll};

use crate::error::{Error, ErrorCode};
use crate::network::{Address, NetworkReceive, NetworkSend, MAX_RX_PACKET_SIZE};
use crate::utils::cell::RefCell;
use crate::utils::futures::{select3, yield_now, Either3};
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::MultiNotification;
use crate::utils::timers::{Instant, Timer};

use super::frame::{encode_frame_header, Frame, FRAME_HDR_LEN};
pub use super::{NetTcpListener, NetTcpSocket, NoTcp, TcpConfig};

/// A single-peer, allocation-free TCP transport with Matter's 4-byte LE framing.
///
/// Both halves borrow the server, permitting concurrent sending and receiving.
/// Run [`Self::run`] alongside the transport to drain the outbound queue.
/// Partial receive state survives cancellation by a competing UDP receive.
/// Outbound frames are queued in two fixed slots. A full queue or a timed-out
/// write closes only that TCP peer; the shared UDP sender never waits for TCP.
pub struct TcpServer<L: NetTcpListener, const TX_QUEUE: usize = 2> {
    state: Mutex<RefCell<State<L, TX_QUEUE>>>,
    changed: MultiNotification,
    config: TcpConfig,
}

impl<L: NetTcpListener> TcpServer<L, 2> {
    /// Create a server over a listener already bound to the Matter port,
    /// using the default queue depth of two outbound frames.
    pub fn new(listener: L, config: TcpConfig) -> Self {
        Self::with_queue(listener, config)
    }
}

impl<L: NetTcpListener, const TX_QUEUE: usize> TcpServer<L, TX_QUEUE> {
    /// Create a server with a custom outbound frame queue capacity.
    pub fn with_queue(listener: L, config: TcpConfig) -> Self {
        assert!(TX_QUEUE > 0, "TX_QUEUE must be non-zero");
        Self {
            state: Mutex::new(RefCell::new(State {
                listener,
                peer: None,
                next_id: 0,
                rx: RxFrame::new(),
                tx: TxQueue::new(),
            })),
            changed: MultiNotification::new(),
            config,
        }
    }

    /// Drain queued TCP frames. Run concurrently with the Matter transport.
    /// No socket operation holds a lock across an await, and each poll writes
    /// at most one chunk before yielding to the other network tasks.
    pub async fn run(&self) -> Result<(), Error> {
        loop {
            let changed = self.changed.wait();
            let deadline = self.with_state(|state| {
                state.peer.as_ref().and_then(|peer| {
                    state
                        .tx
                        .front()
                        .map(|tx| (peer.id, tx.queued_at + self.config.send_timeout))
                })
            });
            let timeout = async {
                if let Some((id, deadline)) = deadline {
                    Timer::at(deadline).await;
                    self.expire(id, Timeout::Send);
                } else {
                    pending::<()>().await;
                }
            };
            if matches!(
                select3(poll_fn(|cx| self.poll_write(cx)), timeout, changed).await,
                Either3::First(())
            ) {
                self.changed.notify();
            }
            yield_now().await;
        }
    }

    async fn wait_available(&self) -> Result<(), Error> {
        loop {
            // Subscribe before observing state so a concurrent update cannot
            // be missed between the deadline snapshot and registering a waiter.
            let changed = self.changed.wait();
            let deadline = self.with_state(|state| {
                state
                    .peer
                    .as_ref()
                    .map(|peer| (peer.id, peer.last_activity + self.config.idle_timeout))
            });
            let idle = async {
                if let Some((id, deadline)) = deadline {
                    Timer::at(deadline).await;
                    self.expire(id, Timeout::Idle);
                } else {
                    pending::<()>().await;
                }
            };
            match select3(poll_fn(|cx| self.poll_available(cx)), idle, changed).await {
                Either3::First(Ok(Event::Frame)) => return Ok(()),
                Either3::First(Err(error)) => return Err(error),
                Either3::First(Ok(Event::Progress)) => self.changed.notify(),
                _ => {}
            }
            yield_now().await;
        }
    }

    fn recv_from(&self, buffer: &mut [u8]) -> Result<Option<(usize, Address)>, Error> {
        let result = self.with_state_mut(|state| {
            let Some(message) = state.rx.message() else {
                return Ok(None);
            };
            let len = message.len();
            if len > buffer.len() {
                state.clear_peer();
                return Err(ErrorCode::BufferTooSmall.into());
            }
            buffer[..len].copy_from_slice(message);
            let address = state
                .peer
                .as_ref()
                .ok_or(ErrorCode::NoNetworkInterface)?
                .address;
            state.rx.reset();
            Ok(Some((len, Address::Tcp(address))))
        });
        if result.is_err() {
            self.changed.notify();
        }
        result
    }

    async fn send_to(&self, data: &[u8], address: Address) -> Result<(), Error> {
        let Address::Tcp(address) = address else {
            return Err(ErrorCode::NoNetworkInterface.into());
        };
        if data.is_empty() || data.len() > MAX_RX_PACKET_SIZE {
            return Err(ErrorCode::BufferTooSmall.into());
        }
        let result = self.with_state_mut(|state| {
            if !state
                .peer
                .as_ref()
                .is_some_and(|peer| peer.address == address)
            {
                return Err(Error::new(ErrorCode::NoNetworkInterface));
            }
            if state.tx.is_full() {
                // A slow peer may not block the shared Matter sender (which also
                // carries UDP). Close it rather than dropping a frame silently
                // or building up an unbounded queue.
                state.clear_peer();
                return Err(ErrorCode::NoSpace.into());
            }
            state.tx.enqueue(data)
        });
        self.changed.notify();
        result?;
        yield_now().await;
        Ok(())
    }

    fn poll_available(&self, cx: &mut Context<'_>) -> Poll<Result<Event, Error>> {
        self.with_state_mut(|state| {
            if state.rx.message().is_some() {
                return Poll::Ready(Ok(Event::Frame));
            }

            // Poll the active stream before accepting/rejecting another peer so
            // a flood of connection attempts cannot starve the operational peer.
            let remaining = state.rx.remaining();
            if let Some(peer) = state.peer.as_mut() {
                let mut bytes = [0u8; 256];
                let count = bytes.len().min(remaining);
                match peer.socket.poll_read(cx, &mut bytes[..count]) {
                    Poll::Ready(Ok(0) | Err(_)) => {
                        state.clear_peer();
                        return Poll::Ready(Ok(Event::Progress));
                    }
                    Poll::Ready(Ok(count)) => {
                        peer.last_activity = Instant::now();
                        if state.rx.feed(&bytes[..count]).is_err() {
                            state.clear_peer();
                        }
                        return Poll::Ready(Ok(Event::Progress));
                    }
                    Poll::Pending => {}
                }
            }

            match state.listener.poll_accept(cx) {
                Poll::Ready(Ok((address, socket))) => {
                    if state.peer.is_none() {
                        let id = state.next_id;
                        state.next_id = id.wrapping_add(1);
                        state.peer = Some(Peer {
                            socket,
                            address,
                            id,
                            last_activity: Instant::now(),
                        });
                        state.rx.reset();
                    }
                    // Otherwise `socket` is dropped, rejecting the newcomer.
                    Poll::Ready(Ok(Event::Progress))
                }
                // Acceptor resource pressure must not unwind the transport
                // while a healthy peer is already using the single slot. Its
                // read waker or idle timer will let us retry later.
                Poll::Ready(Err(_)) if state.peer.is_some() => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
    }

    fn poll_write(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.with_state_mut(|state| {
            let State { peer, tx, .. } = state;
            let (Some(peer), Some(frame)) = (peer.as_mut(), tx.front_mut()) else {
                return Poll::Pending;
            };
            match peer.socket.poll_write(cx, frame.unwritten()) {
                Poll::Ready(Ok(0) | Err(_)) => state.clear_peer(),
                Poll::Ready(Ok(count)) => {
                    peer.last_activity = Instant::now();
                    frame.advance(count);
                    if frame.is_complete() {
                        tx.pop();
                    }
                }
                Poll::Pending => return Poll::Pending,
            }
            Poll::Ready(())
        })
    }

    fn expire(&self, id: u64, timeout: Timeout) {
        let closed = self.with_state_mut(|state| {
            let Some(peer) = state.peer.as_ref().filter(|peer| peer.id == id) else {
                return false;
            };
            // Activity or a completed write may have changed the deadline while
            // the timer was being polled on another task/thread.
            let expired = match timeout {
                Timeout::Send => state
                    .tx
                    .front()
                    .is_some_and(|tx| tx.queued_at + self.config.send_timeout <= Instant::now()),
                Timeout::Idle => peer.last_activity + self.config.idle_timeout <= Instant::now(),
            };
            if expired {
                state.clear_peer();
            }
            expired
        });
        if closed {
            self.changed.notify();
        }
    }

    #[inline]
    fn with_state<R>(&self, f: impl FnOnce(&State<L, TX_QUEUE>) -> R) -> R {
        self.state.lock(|cell| f(&cell.borrow()))
    }

    #[inline]
    fn with_state_mut<R>(&self, f: impl FnOnce(&mut State<L, TX_QUEUE>) -> R) -> R {
        self.state.lock(|cell| f(&mut cell.borrow_mut()))
    }
}

impl<L: NetTcpListener, const TX_QUEUE: usize> NetworkSend for &TcpServer<L, TX_QUEUE> {
    async fn send_to(&mut self, data: &[u8], address: Address) -> Result<(), Error> {
        TcpServer::send_to(self, data, address).await
    }
}

impl<L: NetTcpListener, const TX_QUEUE: usize> NetworkReceive for &TcpServer<L, TX_QUEUE> {
    async fn wait_available(&mut self) -> Result<(), Error> {
        TcpServer::wait_available(self).await
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        loop {
            if let Some(packet) = TcpServer::recv_from(self, buffer)? {
                return Ok(packet);
            }
            TcpServer::wait_available(self).await?;
        }
    }
}

/// Single-frame inbound reassembly buffer.
type RxFrame = Frame<MAX_RX_PACKET_SIZE>;

struct State<L: NetTcpListener, const TX_QUEUE: usize> {
    listener: L,
    peer: Option<Peer<L::Socket>>,
    next_id: u64,
    rx: RxFrame,
    tx: TxQueue<TX_QUEUE>,
}

impl<L: NetTcpListener, const TX_QUEUE: usize> State<L, TX_QUEUE> {
    fn clear_peer(&mut self) {
        self.peer = None;
        self.rx.reset();
        self.tx.clear();
    }
}

/// Fixed-capacity, allocation-free ring buffer for outbound frames.
struct TxQueue<const N: usize> {
    frames: [TxFrame; N],
    head: usize,
    count: usize,
}

impl<const N: usize> TxQueue<N> {
    const fn new() -> Self {
        Self {
            frames: [TxFrame::new(); N],
            head: 0,
            count: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.count == N
    }

    fn front(&self) -> Option<&TxFrame> {
        if self.count > 0 {
            Some(&self.frames[self.head])
        } else {
            None
        }
    }

    fn front_mut(&mut self) -> Option<&mut TxFrame> {
        if self.count > 0 {
            Some(&mut self.frames[self.head])
        } else {
            None
        }
    }

    fn enqueue(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.is_full() {
            return Err(ErrorCode::NoSpace.into());
        }
        let index = (self.head + self.count) % N;
        self.frames[index].encode(data)?;
        self.count += 1;
        Ok(())
    }

    fn pop(&mut self) {
        if self.count > 0 {
            self.count -= 1;
            self.head = (self.head + 1) % N;
        }
    }

    fn clear(&mut self) {
        self.head = 0;
        self.count = 0;
    }
}

#[derive(Copy, Clone)]
struct TxFrame {
    bytes: [u8; MAX_RX_PACKET_SIZE + FRAME_HDR_LEN],
    len: usize,
    written: usize,
    queued_at: Instant,
}

impl TxFrame {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_RX_PACKET_SIZE + FRAME_HDR_LEN],
            len: 0,
            written: 0,
            queued_at: Instant::from_ticks(0),
        }
    }

    fn encode(&mut self, data: &[u8]) -> Result<(), Error> {
        let hdr = encode_frame_header(data.len())?;
        self.bytes[..FRAME_HDR_LEN].copy_from_slice(&hdr);
        self.bytes[FRAME_HDR_LEN..FRAME_HDR_LEN + data.len()].copy_from_slice(data);
        self.len = data.len() + FRAME_HDR_LEN;
        self.written = 0;
        self.queued_at = Instant::now();
        Ok(())
    }

    fn unwritten(&self) -> &[u8] {
        &self.bytes[self.written..self.len]
    }

    fn advance(&mut self, count: usize) {
        self.written += count;
    }

    fn is_complete(&self) -> bool {
        self.written == self.len
    }
}

struct Peer<S> {
    socket: S,
    address: SocketAddr,
    id: u64,
    last_activity: Instant,
}

enum Event {
    Frame,
    Progress,
}

enum Timeout {
    Idle,
    Send,
}

#[cfg(test)]
mod tests {
    use core::pin::pin;
    use futures_lite::future::{block_on, poll_once};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex as StdMutex};

    use super::*;
    use crate::utils::timers::{with_timeout, Duration};

    #[derive(Default)]
    struct StreamState {
        input: VecDeque<u8>,
        output: Vec<u8>,
        eof: bool,
        closed: bool,
        write_budget: Option<usize>,
    }

    struct Stream(Arc<StdMutex<StreamState>>);

    impl Drop for Stream {
        fn drop(&mut self) {
            self.0.lock().unwrap().closed = true;
        }
    }

    impl NetTcpSocket for Stream {
        fn poll_read(
            &mut self,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<Result<usize, Error>> {
            let mut state = self.0.lock().unwrap();
            if state.input.is_empty() && !state.eof {
                return Poll::Pending;
            }
            let count = state.input.len().min(buf.len());
            for byte in &mut buf[..count] {
                *byte = state.input.pop_front().unwrap();
            }
            Poll::Ready(Ok(count))
        }

        fn poll_write(&mut self, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
            let mut state = self.0.lock().unwrap();
            let count = state.write_budget.unwrap_or(buf.len()).min(buf.len());
            if count == 0 {
                return Poll::Pending;
            }
            if let Some(budget) = state.write_budget.as_mut() {
                *budget -= count;
            }
            state.output.extend_from_slice(&buf[..count]);
            Poll::Ready(Ok(count))
        }
    }

    #[derive(Default, Clone)]
    struct Listener(Arc<StdMutex<VecDeque<(SocketAddr, Stream)>>>);

    impl Listener {
        fn peer(&self, port: u16, input: &[u8]) -> Arc<StdMutex<StreamState>> {
            let stream = Arc::new(StdMutex::new(StreamState {
                input: input.iter().copied().collect(),
                ..Default::default()
            }));
            self.0.lock().unwrap().push_back((
                SocketAddr::from(([127, 0, 0, 1], port)),
                Stream(stream.clone()),
            ));
            stream
        }
    }

    impl NetTcpListener for Listener {
        type Socket = Stream;
        fn poll_accept(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(SocketAddr, Self::Socket), Error>> {
            self.0
                .lock()
                .unwrap()
                .pop_front()
                .map_or(Poll::Pending, |peer| Poll::Ready(Ok(peer)))
        }
    }

    async fn poll_until_pending<L: NetTcpListener, const N: usize>(server: &TcpServer<L, N>) {
        let mut receive = pin!(server.wait_available());
        for _ in 0..16 {
            assert!(poll_once(&mut receive).await.is_none());
        }
    }

    #[test]
    fn partial_receive_survives_cancellation_by_another_transport() {
        block_on(async {
            let listener = Listener::default();
            let peer = listener.peer(10, &[3, 0]);
            let server = TcpServer::new(listener, TcpConfig::default());
            poll_until_pending(&server).await;
            peer.lock().unwrap().input.extend([0, 0, b'a', b'b', b'c']);
            server.wait_available().await.unwrap();
            let mut buffer = [0u8; 16];
            let (count, address) = server.recv_from(&mut buffer).unwrap().unwrap();
            assert_eq!(&buffer[..count], b"abc");
            assert_eq!(
                address,
                Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 10)))
            );
        });
    }

    #[test]
    fn accept_resource_pressure_does_not_disrupt_the_active_peer() {
        struct FullListener(Option<(SocketAddr, Stream)>);
        impl NetTcpListener for FullListener {
            type Socket = Stream;
            fn poll_accept(
                &mut self,
                _: &mut Context<'_>,
            ) -> Poll<Result<(SocketAddr, Stream), Error>> {
                Poll::Ready(self.0.take().ok_or(ErrorCode::NoSpace.into()))
            }
        }
        block_on(async {
            let peer = Arc::new(StdMutex::new(StreamState::default()));
            let address = SocketAddr::from(([127, 0, 0, 1], 10));
            let server = TcpServer::new(
                FullListener(Some((address, Stream(peer.clone())))),
                TcpConfig::default(),
            );
            poll_until_pending(&server).await;
            assert!(!peer.lock().unwrap().closed);
            peer.lock().unwrap().input.extend([1, 0, 0, 0, b'a']);
            server.wait_available().await.unwrap();
            let mut bytes = [0u8; 8];
            assert_eq!(
                server.recv_from(&mut bytes).unwrap(),
                Some((1, Address::Tcp(address)))
            );
            assert_eq!(bytes[0], b'a');
        });
    }

    #[test]
    fn second_peer_is_closed_without_disrupting_the_active_peer() {
        block_on(async {
            let listener = Listener::default();
            let first = listener.peer(10, &[]);
            let second = listener.peer(11, &[]);
            let server = TcpServer::new(listener, TcpConfig::default());
            poll_until_pending(&server).await;
            assert!(second.lock().unwrap().closed);
            assert!(!first.lock().unwrap().closed);
            first.lock().unwrap().input.extend([1, 0, 0, 0, b'a']);
            server.wait_available().await.unwrap();
            let mut buffer = [0u8; 16];
            let (_, address) = server.recv_from(&mut buffer).unwrap().unwrap();
            server.send_to(b"pong", address).await.unwrap();
            let mut writer = pin!(server.run());
            for _ in 0..16 {
                assert!(poll_once(&mut writer).await.is_none());
            }
            assert_eq!(first.lock().unwrap().output, b"\x04\0\0\0pong");
        });
    }

    #[test]
    fn idle_peer_releases_its_socket_and_a_new_peer_can_connect() {
        block_on(async {
            let listener = Listener::default();
            let first = listener.peer(10, &[4]);
            let server = TcpServer::new(
                listener.clone(),
                TcpConfig {
                    idle_timeout: Duration::from_millis(5),
                    ..Default::default()
                },
            );
            assert!(
                with_timeout(Duration::from_millis(30), server.wait_available())
                    .await
                    .is_err()
            );
            assert!(first.lock().unwrap().closed);
            listener.peer(11, &[1, 0, 0, 0, b'b']);
            server.wait_available().await.unwrap();
            let mut buffer = [0u8; 16];
            assert_eq!(server.recv_from(&mut buffer).unwrap().unwrap().0, 1);
            assert_eq!(buffer[0], b'b');
        });
    }

    #[test]
    fn eof_discards_partial_frame_and_releases_the_peer() {
        block_on(async {
            let listener = Listener::default();
            let first = listener.peer(10, &[4, 0]);
            first.lock().unwrap().eof = true;
            listener.peer(11, &[1, 0, 0, 0, b'b']);
            let server = TcpServer::new(listener, TcpConfig::default());
            server.wait_available().await.unwrap();
            let mut buffer = [0u8; 16];
            server.recv_from(&mut buffer).unwrap().unwrap();
            assert!(first.lock().unwrap().closed);
            assert_eq!(buffer[0], b'b');
        });
    }

    #[test]
    fn a_canceled_writer_resumes_without_duplicating_bytes() {
        block_on(async {
            let listener = Listener::default();
            let peer = listener.peer(10, &[]);
            peer.lock().unwrap().write_budget = Some(1);
            let server = TcpServer::new(listener, TcpConfig::default());
            poll_until_pending(&server).await;
            server
                .send_to(
                    b"data",
                    Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 10))),
                )
                .await
                .unwrap();
            {
                let mut writer = pin!(server.run());
                assert!(poll_once(&mut writer).await.is_none());
            }
            assert_eq!(peer.lock().unwrap().output, [4]);
            assert!(!peer.lock().unwrap().closed);
            peer.lock().unwrap().write_budget = None;
            let mut writer = pin!(server.run());
            for _ in 0..16 {
                assert!(poll_once(&mut writer).await.is_none());
            }
            assert_eq!(peer.lock().unwrap().output, b"\x04\0\0\0data");
        });
    }

    #[test]
    fn a_stalled_writer_times_out_and_releases_the_stream() {
        block_on(async {
            let listener = Listener::default();
            let peer = listener.peer(10, &[]);
            peer.lock().unwrap().write_budget = Some(0);
            let server = TcpServer::new(
                listener,
                TcpConfig {
                    send_timeout: Duration::from_millis(5),
                    ..Default::default()
                },
            );
            poll_until_pending(&server).await;
            server
                .send_to(
                    b"data",
                    Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 10))),
                )
                .await
                .unwrap();
            assert!(with_timeout(Duration::from_millis(30), server.run())
                .await
                .is_err());
            assert!(peer.lock().unwrap().closed);
        });
    }

    #[test]
    fn a_stalled_tcp_writer_does_not_delay_a_udp_send() {
        use crate::network::ChainedNetwork;
        struct UdpProbe<'a>(&'a mut usize);
        impl NetworkSend for UdpProbe<'_> {
            async fn send_to(&mut self, _: &[u8], _: Address) -> Result<(), Error> {
                *self.0 += 1;
                Ok(())
            }
        }
        block_on(async {
            let listener = Listener::default();
            let peer = listener.peer(10, &[]);
            peer.lock().unwrap().write_budget = Some(0);
            let server = TcpServer::new(listener, TcpConfig::default());
            poll_until_pending(&server).await;
            let mut udp_count = 0;
            {
                let mut send =
                    ChainedNetwork::new(Address::is_udp, UdpProbe(&mut udp_count), &server);
                let address = SocketAddr::from(([127, 0, 0, 1], 10));
                send.send_to(b"tcp", Address::Tcp(address)).await.unwrap();
                let mut writer = pin!(server.run());
                assert!(poll_once(&mut writer).await.is_none());
                send.send_to(b"udp", Address::Udp(address)).await.unwrap();
            }
            assert_eq!(udp_count, 1);
            assert!(peer.lock().unwrap().output.is_empty());
            assert!(!peer.lock().unwrap().closed);
        });
    }

    #[test]
    fn a_full_tcp_queue_closes_only_that_peer() {
        block_on(async {
            let listener = Listener::default();
            let peer = listener.peer(10, &[]);
            let server = TcpServer::new(listener, TcpConfig::default());
            poll_until_pending(&server).await;
            let address = Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 10)));
            server.send_to(b"one", address).await.unwrap();
            server.send_to(b"two", address).await.unwrap();
            assert_eq!(
                server.send_to(b"three", address).await.unwrap_err().code(),
                ErrorCode::NoSpace
            );
            assert!(peer.lock().unwrap().closed);
        });
    }

    #[test]
    fn custom_tx_queue_capacity_allows_more_queued_frames() {
        block_on(async {
            let listener = Listener::default();
            let peer = listener.peer(10, &[]);
            let server = TcpServer::<_, 4>::with_queue(listener, TcpConfig::default());
            poll_until_pending(&server).await;
            let address = Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 10)));
            server.send_to(b"one", address).await.unwrap();
            server.send_to(b"two", address).await.unwrap();
            server.send_to(b"three", address).await.unwrap();
            server.send_to(b"four", address).await.unwrap();
            assert_eq!(
                server.send_to(b"five", address).await.unwrap_err().code(),
                ErrorCode::NoSpace
            );
            assert!(peer.lock().unwrap().closed);
        });
    }

    #[test]
    fn back_to_back_frames_in_single_read() {
        block_on(async {
            let listener = Listener::default();
            let mut input = Vec::new();
            input.extend([3, 0, 0, 0, b'o', b'n', b'e']);
            input.extend([3, 0, 0, 0, b't', b'w', b'o']);
            let _peer = listener.peer(10, &input);
            let server = TcpServer::new(listener, TcpConfig::default());

            // Receive first frame via NetworkReceive
            let mut buf = [0u8; 16];
            let (len, _) = NetworkReceive::recv_from(&mut &server, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf[..len], b"one");

            // Receive second frame
            let (len, _) = NetworkReceive::recv_from(&mut &server, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf[..len], b"two");
        });
    }

    #[test]
    fn recv_buffer_too_small_discards_peer() {
        block_on(async {
            let listener = Listener::default();
            let peer = listener.peer(10, &[5, 0, 0, 0, b'h', b'e', b'l', b'l', b'o']);
            let server = TcpServer::new(listener, TcpConfig::default());

            server.wait_available().await.unwrap();
            let mut small_buf = [0u8; 2];
            assert_eq!(
                server.recv_from(&mut small_buf).unwrap_err().code(),
                ErrorCode::BufferTooSmall
            );
            assert!(peer.lock().unwrap().closed);
        });
    }

    #[test]
    fn oversized_frame_header_closes_peer() {
        block_on(async {
            let listener = Listener::default();
            // Announce payload larger than MAX_RX_PACKET_SIZE
            let len = (MAX_RX_PACKET_SIZE + 1) as u32;
            let mut input = len.to_le_bytes().to_vec();
            input.extend([0u8; 16]);
            let peer = listener.peer(10, &input);
            listener.peer(11, &[2, 0, 0, 0, b'o', b'k']);
            let server = TcpServer::new(listener, TcpConfig::default());

            server.wait_available().await.unwrap();
            assert!(peer.lock().unwrap().closed);

            let mut buf = [0u8; 16];
            let (len, _) = server.recv_from(&mut buf).unwrap().unwrap();
            assert_eq!(&buf[..len], b"ok");
        });
    }

    #[cfg(feature = "os")]
    #[test]
    fn real_os_socket_bidirectional_roundtrip() {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let async_listener = async_io::Async::new(std_listener).unwrap();
        let server = TcpServer::new(async_listener, TcpConfig::default());

        // Spawn client on background thread
        let client_thread = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).unwrap();
            client.set_nodelay(true).unwrap();

            // Client sends framed "ping!"
            let payload = b"ping!";
            let len = (payload.len() as u32).to_le_bytes();
            client.write_all(&len).unwrap();
            client.write_all(payload).unwrap();
            client.flush().unwrap();

            // Client reads reply "pong!"
            let mut resp_hdr = [0u8; 4];
            client.read_exact(&mut resp_hdr).unwrap();
            let resp_len = u32::from_le_bytes(resp_hdr) as usize;
            assert_eq!(resp_len, 5);
            let mut resp_payload = vec![0u8; resp_len];
            client.read_exact(&mut resp_payload).unwrap();
            assert_eq!(&resp_payload, b"pong!");
        });

        block_on(async {
            // Server receives
            server.wait_available().await.unwrap();
            let mut buf = [0u8; 32];
            let (count, client_addr) = server.recv_from(&mut buf).unwrap().unwrap();
            assert_eq!(&buf[..count], b"ping!");

            // Server replies with "pong!"
            server.send_to(b"pong!", client_addr).await.unwrap();

            // Run server drain runner until client completes
            let mut runner = pin!(server.run());
            for _ in 0..64 {
                let _ = poll_once(&mut runner).await;
                if client_thread.is_finished() {
                    break;
                }
                Timer::after(Duration::from_millis(5)).await;
            }
        });

        client_thread.join().unwrap();
    }

    #[cfg(feature = "os")]
    #[test]
    fn real_os_socket_client_disconnect_and_reconnect() {
        use std::io::Write;
        use std::net::TcpStream;

        block_on(async {
            let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = std_listener.local_addr().unwrap();
            std_listener.set_nonblocking(true).unwrap();
            let async_listener = async_io::Async::new(std_listener).unwrap();
            let server = TcpServer::new(async_listener, TcpConfig::default());

            // First client connects and immediately disconnects (EOF)
            {
                let _client = TcpStream::connect(addr).unwrap();
            }

            // Connect second client
            let mut client2 = TcpStream::connect(addr).unwrap();
            let payload = b"hello";
            let len = (payload.len() as u32).to_le_bytes();
            client2.write_all(&len).unwrap();
            client2.write_all(payload).unwrap();
            client2.flush().unwrap();

            server.wait_available().await.unwrap();
            let mut buf = [0u8; 32];
            let (count, _) = server.recv_from(&mut buf).unwrap().unwrap();
            assert_eq!(&buf[..count], b"hello");
        });
    }
}
