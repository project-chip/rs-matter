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

//! Matter-over-TCP transports, framing, and socket abstractions.

use core::future::{pending, Future};
use core::net::SocketAddr;

use crate::error::{Error, ErrorCode};
use crate::network::{Address, NetworkReceive, NetworkSend};
use crate::utils::cell::RefCell;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::{IfMutex, MaybeSend};
use crate::utils::timers::Duration;

pub mod frame;
pub use frame::{check_frame_slice, encode_frame_header, parse_frame_header, Frame, FRAME_HDR_LEN};

#[cfg(all(feature = "std", feature = "async-io"))]
pub mod std;

mod buffers;
mod slots;

pub use buffers::TcpNetworkBuffers;

/// TCP keep-alive configuration for [`NetTcpSocket::set_keep_alive`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TcpKeepAlive {
    /// Time a connection must be idle before sending the first keep-alive probe.
    pub idle: Duration,
    /// Interval between consecutive keep-alive probes.
    pub interval: Duration,
    /// Number of unacknowledged probes before considering the connection dead.
    pub retries: u32,
}

impl TcpKeepAlive {
    /// Default TCP keep-alive configuration (CHIP's 25 s interval, 5 probes).
    pub const fn new() -> Self {
        Self {
            idle: Duration::from_secs(25),
            interval: Duration::from_secs(25),
            retries: 5,
        }
    }
}

impl Default for TcpKeepAlive {
    fn default() -> Self {
        Self::new()
    }
}

/// An owned TCP listener and optional outbound connector.
///
/// Returning a socket transfers ownership to the caller.
pub trait NetTcpListener: MaybeSend {
    /// The accepted or connected stream type.
    type Socket: NetTcpSocket;

    /// Accept at most one incoming peer.
    ///
    /// Must be cancel-safe: dropping the returned future before completion
    /// must not lose an accepted connection.
    fn accept(
        &mut self,
    ) -> impl Future<Output = Result<(SocketAddr, Self::Socket), Error>> + MaybeSend;

    /// Establish an outbound TCP connection to `addr`.
    ///
    /// Server-only listeners that do not support outbound connections may keep
    /// the default implementation, which returns [`ErrorCode::NoNetworkInterface`].
    fn connect(
        &mut self,
        _addr: SocketAddr,
    ) -> impl Future<Output = Result<Self::Socket, Error>> + MaybeSend {
        core::future::ready(Err(ErrorCode::NoNetworkInterface.into()))
    }
}

/// Readable half of a split [`NetTcpSocket`].
pub trait NetTcpRead: MaybeSend {
    /// Read stream bytes; zero indicates EOF.
    ///
    /// Must be cancel-safe: dropping a pending future must not consume input bytes.
    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize, Error>> + MaybeSend;
}

/// Writable half of a split [`NetTcpSocket`].
pub trait NetTcpWrite: MaybeSend {
    /// Write stream bytes; zero indicates a closed stream.
    ///
    /// Must be cancel-safe: dropping a pending future must not report bytes as written.
    fn write(&mut self, buf: &[u8]) -> impl Future<Output = Result<usize, Error>> + MaybeSend;
}

/// An owned full-duplex TCP stream.
///
/// All async methods must be cancel-safe: dropping a pending future must not
/// consume input bytes or leave partial state that corrupts subsequent calls.
pub trait NetTcpSocket: MaybeSend {
    /// Borrowed reader half returned by [`Self::split`].
    type Read<'a>: NetTcpRead + 'a
    where
        Self: 'a;

    /// Borrowed writer half returned by [`Self::split`].
    type Write<'a>: NetTcpWrite + 'a
    where
        Self: 'a;

    /// Split the stream into independent reader and writer halves for concurrent I/O.
    fn split(&mut self) -> (Self::Read<'_>, Self::Write<'_>);

    /// Gracefully close the stream (for example, send TCP FIN and flush).
    fn close(&mut self) -> impl Future<Output = Result<(), Error>> + MaybeSend;

    /// Configure TCP keep-alive on this stream.
    ///
    /// Implementations that do not support keep-alive configuration may keep
    /// the default no-op implementation.
    fn set_keep_alive(&mut self, _keep_alive: Option<TcpKeepAlive>) -> Result<(), Error> {
        Ok(())
    }
}

/// Placeholder used by UDP-only drivers' default TCP binding.
pub struct NoTcp;

impl NetTcpListener for NoTcp {
    type Socket = Self;

    fn accept(
        &mut self,
    ) -> impl Future<Output = Result<(SocketAddr, Self::Socket), Error>> + MaybeSend {
        pending()
    }
}

impl NetTcpRead for NoTcp {
    fn read(&mut self, _buf: &mut [u8]) -> impl Future<Output = Result<usize, Error>> + MaybeSend {
        core::future::ready(Err(ErrorCode::NoNetworkInterface.into()))
    }
}

impl NetTcpWrite for NoTcp {
    fn write(&mut self, _buf: &[u8]) -> impl Future<Output = Result<usize, Error>> + MaybeSend {
        core::future::ready(Err(ErrorCode::NoNetworkInterface.into()))
    }
}

impl NetTcpSocket for NoTcp {
    type Read<'a> = Self;
    type Write<'a> = Self;

    fn split(&mut self) -> (Self::Read<'_>, Self::Write<'_>) {
        (NoTcp, NoTcp)
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        core::future::ready(Ok(()))
    }
}

/// Timeouts and socket options for Matter TCP transports.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TcpConfig {
    /// Optional idle timeout: close a stream when neither reading nor writing has
    /// made progress for this duration. Defaults to `None` so quiet long-lived
    /// connections (such as WebRTC signaling) are preserved by TCP keep-alive.
    pub idle_timeout: Option<Duration>,
    /// Bound a complete outbound frame write, including time spent queued.
    pub send_timeout: Duration,
    /// Optional TCP keep-alive configuration applied to accepted and connected sockets.
    pub keep_alive: Option<TcpKeepAlive>,
}

impl TcpConfig {
    /// Default TCP transport configuration.
    pub const fn new() -> Self {
        Self {
            idle_timeout: None,
            send_timeout: Duration::from_secs(5),
            keep_alive: Some(TcpKeepAlive::new()),
        }
    }
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// A resource-bounded, multi-slot TCP transport with Matter's 4-byte LE framing.
///
/// Both [`NetworkSend`] and [`NetworkReceive`] are implemented for `&TcpNetwork`
/// (and `TcpNetwork`), permitting concurrent sending and receiving across up to
/// `SLOTS` concurrent peers (both accepted inbound and outbound-connected).
/// Run [`Self::run`] concurrently with the Matter transport to drive accept/connect,
/// per-slot frame reads, outbound frame writes, keep-alive, and eviction.
///
/// # Slot Eviction Policy
///
/// When all `SLOTS` are occupied and a new peer is accepted or needs an outbound
/// connection:
/// 1. Slots in `Connecting` are never evicted mid-handshake.
/// 2. Among `Connected` slots, unauthenticated slots (no encrypted
///    Matter session frame observed) are preferred for eviction over authenticated
///    ones.
/// 3. Within the same tier, slots with an empty TX queue are preferred, breaking
///    ties by longest-idle (`last_activity`).
///
/// `N` configures the maximum framed Matter payload size in bytes (at most
/// [`crate::MAX_RX_BUF_SIZE`]). `SLOTS` configures the maximum concurrent peer
/// connections, and `TX_QUEUE` configures each peer's outbound frame queue depth.
pub struct TcpNetwork<
    'a,
    L: NetTcpListener,
    const N: usize = { crate::MAX_RX_BUF_SIZE },
    const SLOTS: usize = 4,
    const TX_QUEUE: usize = 2,
> {
    listener: IfMutex<L>,
    sockets: [Mutex<RefCell<Option<L::Socket>>>; SLOTS],
    buffers: &'a TcpNetworkBuffers<N, SLOTS, TX_QUEUE>,
    config: TcpConfig,
}

impl<'a, L: NetTcpListener, const N: usize, const SLOTS: usize, const TX_QUEUE: usize>
    TcpNetwork<'a, L, N, SLOTS, TX_QUEUE>
{
    /// Try to bind `sockets` to caller-owned `buffers` with `config`.
    ///
    /// Returns [`ErrorCode::ResourceExhausted`] if `buffers` is already bound
    /// to another active [`TcpNetwork`] instance.
    pub fn try_new(
        sockets: L,
        buffers: &'a TcpNetworkBuffers<N, SLOTS, TX_QUEUE>,
        config: &TcpConfig,
    ) -> Result<Self, Error> {
        if !buffers.acquire() {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        buffers.reset_all();
        Ok(Self {
            listener: IfMutex::new(sockets),
            sockets: [const { Mutex::new(RefCell::new(None)) }; SLOTS],
            buffers,
            config: *config,
        })
    }

    /// Bind `sockets` to caller-owned `buffers` with `config`.
    ///
    /// # Panics
    ///
    /// Panics if `buffers` is already bound to another active [`TcpNetwork`] instance.
    pub fn new(
        sockets: L,
        buffers: &'a TcpNetworkBuffers<N, SLOTS, TX_QUEUE>,
        config: &TcpConfig,
    ) -> Self {
        Self::try_new(sockets, buffers, config).expect("TcpNetworkBuffers already bound")
    }

    /// Drive TCP accept/connect and all `SLOTS` concurrent peer I/O loops.
    ///
    /// Run concurrently with the Matter transport. No blocking mutex is held across `.await`.
    pub async fn run(&self) -> Result<(), Error> {
        self.buffers
            .run_with_listener(&self.listener, &self.sockets, &self.config)
            .await
    }
}

impl<L: NetTcpListener, const N: usize, const SLOTS: usize, const TX_QUEUE: usize> Drop
    for TcpNetwork<'_, L, N, SLOTS, TX_QUEUE>
{
    fn drop(&mut self) {
        self.buffers.release();
    }
}

impl<L: NetTcpListener, const N: usize, const SLOTS: usize, const TX_QUEUE: usize> NetworkSend
    for TcpNetwork<'_, L, N, SLOTS, TX_QUEUE>
{
    async fn send_to(&mut self, data: &[u8], address: Address) -> Result<(), Error> {
        self.buffers.send_to(data, address, &self.config).await
    }
}

impl<L: NetTcpListener, const N: usize, const SLOTS: usize, const TX_QUEUE: usize> NetworkSend
    for &TcpNetwork<'_, L, N, SLOTS, TX_QUEUE>
{
    async fn send_to(&mut self, data: &[u8], address: Address) -> Result<(), Error> {
        self.buffers.send_to(data, address, &self.config).await
    }
}

impl<L: NetTcpListener, const N: usize, const SLOTS: usize, const TX_QUEUE: usize> NetworkReceive
    for TcpNetwork<'_, L, N, SLOTS, TX_QUEUE>
{
    async fn wait_available(&mut self) -> Result<(), Error> {
        self.buffers.wait_available().await
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        self.buffers.recv_from(buffer).await
    }

    async fn wait_available_or_closed(&mut self) -> Result<Option<Address>, Error> {
        self.buffers.wait_available_or_closed().await
    }
}

impl<L: NetTcpListener, const N: usize, const SLOTS: usize, const TX_QUEUE: usize> NetworkReceive
    for &TcpNetwork<'_, L, N, SLOTS, TX_QUEUE>
{
    async fn wait_available(&mut self) -> Result<(), Error> {
        self.buffers.wait_available().await
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        self.buffers.recv_from(buffer).await
    }

    async fn wait_available_or_closed(&mut self) -> Result<Option<Address>, Error> {
        self.buffers.wait_available_or_closed().await
    }
}

#[cfg(test)]
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use core::mem::MaybeUninit;
    use core::pin::pin;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use ::std::sync::Mutex as StdMutex;
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use futures_lite::future::{block_on, poll_once};

    use super::*;
    use crate::plain_hdr::PlainHdr;
    use crate::proto_hdr::ProtoHdr;
    use crate::sc::{GeneralCode, OpCode, StatusReport, PROTO_ID_SECURE_CHANNEL};
    use crate::utils::futures::{join, select, Either};
    use crate::utils::init::InitMaybeUninit;
    use crate::utils::storage::ParseBuf;
    use crate::utils::sync::Notification;
    use crate::utils::timers::{with_timeout, Duration, Timer};

    #[derive(Default)]
    struct StreamState {
        input: VecDeque<u8>,
        output: Vec<u8>,
        eof: bool,
        closed: bool,
        write_budget: Option<usize>,
        keep_alive: Option<TcpKeepAlive>,
        read_notif: Arc<Notification>,
        write_notif: Arc<Notification>,
    }

    #[derive(Clone)]
    struct MockStream(Arc<StdMutex<StreamState>>);

    struct MockRead<'a>(&'a MockStream);
    struct MockWrite<'a>(&'a MockStream);

    impl NetTcpRead for MockRead<'_> {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            loop {
                let notif = {
                    let mut state = self.0 .0.lock().unwrap();
                    if !state.input.is_empty() {
                        let count = state.input.len().min(buf.len());
                        for byte in &mut buf[..count] {
                            *byte = state.input.pop_front().unwrap();
                        }
                        return Ok(count);
                    }
                    if state.eof {
                        return Ok(0);
                    }
                    state.read_notif.clone()
                };
                notif.wait().await;
            }
        }
    }

    impl NetTcpWrite for MockWrite<'_> {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
            loop {
                let notif = {
                    let mut state = self.0 .0.lock().unwrap();
                    let count = state.write_budget.unwrap_or(buf.len()).min(buf.len());
                    if count > 0 {
                        if let Some(budget) = state.write_budget.as_mut() {
                            *budget -= count;
                        }
                        state.output.extend_from_slice(&buf[..count]);
                        return Ok(count);
                    }
                    state.write_notif.clone()
                };
                notif.wait().await;
            }
        }
    }

    impl NetTcpSocket for MockStream {
        type Read<'a> = MockRead<'a>;
        type Write<'a> = MockWrite<'a>;

        fn split(&mut self) -> (Self::Read<'_>, Self::Write<'_>) {
            (MockRead(self), MockWrite(self))
        }

        async fn close(&mut self) -> Result<(), Error> {
            let mut state = self.0.lock().unwrap();
            state.closed = true;
            state.eof = true;
            state.read_notif.notify();
            Ok(())
        }

        fn set_keep_alive(&mut self, keep_alive: Option<TcpKeepAlive>) -> Result<(), Error> {
            self.0.lock().unwrap().keep_alive = keep_alive;
            Ok(())
        }
    }

    #[derive(Default, Clone)]
    struct MockListener {
        peers: Arc<StdMutex<VecDeque<(SocketAddr, MockStream)>>>,
        errors_remaining: Arc<AtomicUsize>,
        accept_calls: Arc<AtomicUsize>,
        connect_calls: Arc<AtomicUsize>,
        connect_gate: Arc<StdMutex<Option<Arc<Notification>>>>,
        notif: Arc<Notification>,
        outbound: Arc<StdMutex<Option<Arc<StdMutex<StreamState>>>>>,
    }

    impl MockListener {
        fn peer(&self, port: u16, input: &[u8]) -> Arc<StdMutex<StreamState>> {
            let stream = Arc::new(StdMutex::new(StreamState {
                input: input.iter().copied().collect(),
                ..Default::default()
            }));
            self.peers.lock().unwrap().push_back((
                SocketAddr::from(([127, 0, 0, 1], port)),
                MockStream(stream.clone()),
            ));
            self.notif.notify();
            stream
        }
    }

    impl NetTcpListener for MockListener {
        type Socket = MockStream;

        async fn accept(&mut self) -> Result<(SocketAddr, Self::Socket), Error> {
            loop {
                self.accept_calls.fetch_add(1, Ordering::SeqCst);
                if self
                    .errors_remaining
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
                    .is_ok()
                {
                    return Err(ErrorCode::ResourceExhausted.into());
                }
                let wait = {
                    let mut peers = self.peers.lock().unwrap();
                    if let Some(peer) = peers.pop_front() {
                        return Ok(peer);
                    }
                    self.notif.wait()
                };
                wait.await;
            }
        }

        async fn connect(&mut self, _addr: SocketAddr) -> Result<Self::Socket, Error> {
            self.connect_calls.fetch_add(1, Ordering::SeqCst);
            let gate = self.connect_gate.lock().unwrap().clone();
            if let Some(gate) = gate {
                gate.wait().await;
            }
            let stream = Arc::new(StdMutex::new(StreamState::default()));
            *self.outbound.lock().unwrap() = Some(stream.clone());
            Ok(MockStream(stream))
        }
    }

    #[test]
    fn static_init_initializes_tcp_network_buffers_in_place() {
        let mut slot = MaybeUninit::<TcpNetworkBuffers<256, 2, 2>>::uninit();
        let buffers = slot.init_with(TcpNetworkBuffers::init());
        assert!(!buffers.with_state(|s| s.any_rx_ready()));
        // SAFETY: `slot` was initialized by `init_with` above.
        unsafe { slot.assume_init_drop() };
    }

    #[test]
    fn buffers_cannot_be_bound_twice_until_dropped() {
        let buffers = TcpNetworkBuffers::<64, 1, 1>::new();
        let config = TcpConfig::default();

        let first = TcpNetwork::try_new(MockListener::default(), &buffers, &config);
        assert!(first.is_ok());

        let second = TcpNetwork::try_new(MockListener::default(), &buffers, &config);
        assert!(matches!(
            second,
            Err(e) if e.code() == ErrorCode::ResourceExhausted
        ));

        drop(first);

        let third = TcpNetwork::try_new(MockListener::default(), &buffers, &config);
        assert!(third.is_ok());
    }

    #[test]
    fn partial_receive_survives_cancellation_by_another_transport() {
        block_on(async {
            let listener = MockListener::default();
            let peer = listener.peer(10, &[3, 0]);
            let buffers = TcpNetworkBuffers::<64>::new();
            let net = TcpNetwork::new(listener, &buffers, &TcpConfig::default());

            let runner = pin!(net.run());
            let test = pin!(async {
                {
                    let mut rx = &net;
                    let mut wait = pin!(NetworkReceive::wait_available(&mut rx));
                    assert!(poll_once(&mut wait).await.is_none());
                }
                {
                    let mut s = peer.lock().unwrap();
                    s.input.extend([0, 0, b'a', b'b', b'c']);
                    s.read_notif.notify();
                }
                let mut buffer = [0u8; 16];
                let (count, address) = NetworkReceive::recv_from(&mut &net, &mut buffer)
                    .await
                    .unwrap();
                assert_eq!(&buffer[..count], b"abc");
                assert_eq!(
                    address,
                    Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 10)))
                );
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    fn accept_error_is_logged_and_retried() {
        block_on(async {
            let listener = MockListener::default();
            listener.errors_remaining.store(2, Ordering::SeqCst);
            let _peer = listener.peer(11, &[2, 0, 0, 0, b'o', b'k']);
            let buffers = TcpNetworkBuffers::<64>::new();
            let net = TcpNetwork::new(listener, &buffers, &TcpConfig::default());

            let runner = pin!(net.run());
            let test = pin!(async {
                let mut buffer = [0u8; 16];
                let (count, _) = with_timeout(
                    Duration::from_secs(2),
                    NetworkReceive::recv_from(&mut &net, &mut buffer),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(&buffer[..count], b"ok");
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    fn oversized_frame_sends_message_too_large_status_report_and_closes() {
        block_on(async {
            let listener = MockListener::default();
            // Announce payload larger than N=64
            let len = 65u32.to_le_bytes();
            let peer = listener.peer(12, &len);
            let buffers = TcpNetworkBuffers::<64>::new();
            let net = TcpNetwork::new(listener, &buffers, &TcpConfig::default());

            let runner = pin!(net.run());
            let test = pin!(async {
                loop {
                    if peer.lock().unwrap().closed {
                        break;
                    }
                    Timer::after(Duration::from_millis(5)).await;
                }
                let mut output = peer.lock().unwrap().output.clone();
                assert!(output.len() > FRAME_HDR_LEN);
                let frame_len =
                    u32::from_le_bytes(output[..FRAME_HDR_LEN].try_into().unwrap()) as usize;
                assert_eq!(output.len(), FRAME_HDR_LEN + frame_len);

                let mut pb = ParseBuf::new(&mut output[FRAME_HDR_LEN..]);
                let mut plain = PlainHdr::new();
                plain.decode(&mut pb).unwrap();
                let mut proto = ProtoHdr::new();
                proto
                    .decrypt_and_decode(crate::crypto::test_only_crypto(), None, 0, &plain, &mut pb)
                    .unwrap();
                assert_eq!(proto.proto_id, PROTO_ID_SECURE_CHANNEL);
                assert_eq!(proto.proto_opcode, OpCode::StatusReport as u8);
                let report = StatusReport::read(&mut pb).unwrap();
                assert_eq!(report.general_code, GeneralCode::MessageTooLarge);
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    fn multi_slot_concurrent_peers_send_and_receive() {
        block_on(async {
            let listener = MockListener::default();
            let peer1 = listener.peer(20, &[1, 0, 0, 0, b'a']);
            let peer2 = listener.peer(21, &[1, 0, 0, 0, b'b']);
            let buffers = TcpNetworkBuffers::<64, 2>::new();
            let net = TcpNetwork::new(listener, &buffers, &TcpConfig::default());

            let runner = pin!(net.run());
            let test = pin!(async {
                let mut buffer = [0u8; 8];
                let (c1, addr1) = with_timeout(
                    Duration::from_secs(2),
                    NetworkReceive::recv_from(&mut &net, &mut buffer),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(&buffer[..c1], b"a");
                assert_eq!(addr1, Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 20))));

                let (c2, addr2) = with_timeout(
                    Duration::from_secs(2),
                    NetworkReceive::recv_from(&mut &net, &mut buffer),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(&buffer[..c2], b"b");
                assert_eq!(addr2, Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 21))));

                // Both peers remain open concurrently and can receive replies.
                assert!(!peer1.lock().unwrap().closed);
                assert!(!peer2.lock().unwrap().closed);

                NetworkSend::send_to(&mut &net, b"r1", addr1).await.unwrap();
                NetworkSend::send_to(&mut &net, b"r2", addr2).await.unwrap();

                with_timeout(Duration::from_secs(2), async {
                    while peer1.lock().unwrap().output != b"\x02\0\0\0r1"
                        || peer2.lock().unwrap().output != b"\x02\0\0\0r2"
                    {
                        Timer::after(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn idle_peer_releases_socket_and_new_peer_can_connect() {
        block_on(async {
            let listener = MockListener::default();
            let peer1 = listener.peer(30, &[]);
            let _peer2 = listener.peer(31, &[2, 0, 0, 0, b'h', b'i']);
            let buffers = TcpNetworkBuffers::<64, 1>::new();
            let net = TcpNetwork::new(
                listener,
                &buffers,
                &TcpConfig {
                    idle_timeout: Some(Duration::from_millis(30)),
                    ..Default::default()
                },
            );

            let runner = pin!(net.run());
            let test = pin!(async {
                let mut buffer = [0u8; 8];
                let (count, addr) = with_timeout(
                    Duration::from_secs(2),
                    NetworkReceive::recv_from(&mut &net, &mut buffer),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(peer1.lock().unwrap().closed);
                assert_eq!(&buffer[..count], b"hi");
                assert_eq!(addr, Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 31))));
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    fn stalled_writer_times_out_and_releases_stream() {
        block_on(async {
            let listener = MockListener::default();
            let peer = listener.peer(40, &[]);
            peer.lock().unwrap().write_budget = Some(0);
            let buffers = TcpNetworkBuffers::<64>::new();
            let net = TcpNetwork::new(
                listener,
                &buffers,
                &TcpConfig {
                    send_timeout: Duration::from_millis(30),
                    idle_timeout: Some(Duration::from_secs(5)),
                    ..Default::default()
                },
            );

            let runner = pin!(net.run());
            let test = pin!(async {
                // Wait for peer to be accepted
                while !net
                    .buffers
                    .with_state(|s| s.slots.iter().any(|slot| slot.connected_addr().is_some()))
                {
                    Timer::after(Duration::from_millis(2)).await;
                }
                NetworkSend::send_to(
                    &mut &net,
                    b"hello",
                    Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 40))),
                )
                .await
                .unwrap();
                with_timeout(Duration::from_secs(2), async {
                    while !peer.lock().unwrap().closed {
                        Timer::after(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    fn outbound_connect_sends_and_receives() {
        block_on(async {
            let listener = MockListener::default();
            let outbound = listener.outbound.clone();
            let buffers = TcpNetworkBuffers::<64>::new();
            let net = TcpNetwork::new(listener, &buffers, &TcpConfig::default());
            let addr = Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 5540)));

            let runner = pin!(net.run());
            let done = Arc::new(AtomicBool::new(false));
            let test = pin!(async {
                NetworkSend::send_to(&mut &net, b"ping", addr)
                    .await
                    .unwrap();
                with_timeout(Duration::from_secs(2), async {
                    loop {
                        if let Some(stream) = outbound.lock().unwrap().as_ref() {
                            if stream.lock().unwrap().output == b"\x04\0\0\0ping" {
                                break;
                            }
                        }
                        Timer::after(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
                done.store(true, Ordering::SeqCst);
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => assert!(done.load(Ordering::SeqCst)),
            }
        });
    }

    #[test]
    fn concurrent_connecting_queues_same_peer_and_rejects_mismatch_when_full() {
        block_on(async {
            let listener = MockListener::default();
            let gate = Arc::new(Notification::new());
            *listener.connect_gate.lock().unwrap() = Some(gate.clone());
            let connect_calls = listener.connect_calls.clone();
            let outbound = listener.outbound.clone();

            let buffers = TcpNetworkBuffers::<64, 1, 4>::new();
            let net = TcpNetwork::new(
                listener,
                &buffers,
                &TcpConfig {
                    send_timeout: Duration::from_millis(40),
                    ..Default::default()
                },
            );
            let addr1 = Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 5541)));
            let addr2 = Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 5542)));

            let mut runner = pin!(net.run());
            let test = pin!(async {
                // First send transitions slot 0 to Connecting(addr1)
                NetworkSend::send_to(&mut &net, b"one", addr1)
                    .await
                    .unwrap();

                // Second send to the same addr1 while connect() is still pending
                NetworkSend::send_to(&mut &net, b"two", addr1)
                    .await
                    .unwrap();

                // Send to a different addr2 while the only slot is Connecting(addr1) must fail
                let err = NetworkSend::send_to(&mut &net, b"bad", addr2)
                    .await
                    .unwrap_err();
                assert_eq!(err.code(), ErrorCode::ResourceExhausted);

                // Release connect() and verify both queued frames are written over a single connection
                gate.notify();
                with_timeout(Duration::from_secs(2), async {
                    loop {
                        if let Some(stream) = outbound.lock().unwrap().as_ref() {
                            if stream.lock().unwrap().output == b"\x03\0\0\0one\x03\0\0\0two" {
                                break;
                            }
                        }
                        Timer::after(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();

                assert_eq!(connect_calls.load(Ordering::SeqCst), 1);
            });

            match select(&mut runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    fn full_slot_evicts_unauthenticated_before_authenticated_and_longest_idle() {
        block_on(async {
            let listener = MockListener::default();
            // Peer 1 sends an encrypted-looking Matter frame (sess_id = 1, len = 8)
            let auth_frame = [8, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            let peer1 = listener.peer(60, &auth_frame);
            // Peer 2 sends an unsecured frame (sess_id = 0, len = 8)
            let unauth_frame = [8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let peer2 = listener.peer(61, &unauth_frame);

            let buffers = TcpNetworkBuffers::<64, 2>::new();
            let net = TcpNetwork::new(listener.clone(), &buffers, &TcpConfig::default());

            let runner = pin!(net.run());
            let test = pin!(async {
                let mut buf = [0u8; 16];
                for _ in 0..2 {
                    with_timeout(
                        Duration::from_secs(2),
                        NetworkReceive::recv_from(&mut &net, &mut buf),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                }
                assert!(!peer1.lock().unwrap().closed);
                assert!(!peer2.lock().unwrap().closed);

                // Peer 3 arrives when both slots are full: unauthenticated peer 2 must be evicted.
                let peer3 = listener.peer(62, &auth_frame);
                let (_, addr3) = with_timeout(
                    Duration::from_secs(2),
                    NetworkReceive::recv_from(&mut &net, &mut buf),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(addr3, Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 62))));
                assert!(peer2.lock().unwrap().closed);
                assert!(!peer1.lock().unwrap().closed);
                assert!(!peer3.lock().unwrap().closed);

                // Both peer1 and peer3 are now authenticated; peer4 arrives -> longest-idle peer1 evicted.
                let _peer4 = listener.peer(63, &auth_frame);
                let (_, addr4) = with_timeout(
                    Duration::from_secs(2),
                    NetworkReceive::recv_from(&mut &net, &mut buf),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(addr4, Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 63))));
                assert!(peer1.lock().unwrap().closed);
                assert!(!peer3.lock().unwrap().closed);
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    fn keep_alive_applied_on_accept_and_connect_and_quiet_peer_stays_open() {
        block_on(async {
            let listener = MockListener::default();
            let outbound = listener.outbound.clone();
            let accepted = listener.peer(70, &[]);

            let config = TcpConfig::default();
            assert_eq!(config.idle_timeout, None);
            assert_eq!(
                config.keep_alive,
                Some(TcpKeepAlive {
                    idle: Duration::from_secs(25),
                    interval: Duration::from_secs(25),
                    retries: 5,
                })
            );

            let buffers = TcpNetworkBuffers::<64, 2>::new();
            let net = TcpNetwork::new(listener, &buffers, &config);
            let runner = pin!(net.run());
            let test = pin!(async {
                // Outbound connect triggers set_keep_alive on connected socket too.
                NetworkSend::send_to(
                    &mut &net,
                    b"hi",
                    Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 71))),
                )
                .await
                .unwrap();

                with_timeout(Duration::from_secs(2), async {
                    loop {
                        if accepted.lock().unwrap().keep_alive.is_some()
                            && outbound
                                .lock()
                                .unwrap()
                                .as_ref()
                                .is_some_and(|s| s.lock().unwrap().keep_alive.is_some())
                        {
                            break;
                        }
                        Timer::after(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();

                assert_eq!(accepted.lock().unwrap().keep_alive, config.keep_alive);
                assert_eq!(
                    outbound
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .keep_alive,
                    config.keep_alive
                );

                // Quiet connection remains open with idle_timeout = None.
                Timer::after(Duration::from_millis(50)).await;
                assert!(!accepted.lock().unwrap().closed);
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn bounded_tx_backpressure_waits_for_drain_and_times_out_with_resource_exhausted() {
        block_on(async {
            let listener = MockListener::default();
            let peer = listener.peer(80, &[]);
            peer.lock().unwrap().write_budget = Some(0);

            let buffers = TcpNetworkBuffers::<64, 1, 1>::new();
            let net = TcpNetwork::new(
                listener,
                &buffers,
                &TcpConfig {
                    send_timeout: Duration::from_millis(50),
                    ..Default::default()
                },
            );
            let addr = Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 80)));

            let runner = pin!(net.run());
            let test = pin!(async {
                while !net
                    .buffers
                    .with_state(|s| s.slots[0].connected_addr().is_some())
                {
                    Timer::after(Duration::from_millis(2)).await;
                }

                // Frame 1 fills TX_QUEUE = 1.
                NetworkSend::send_to(&mut &net, b"one", addr).await.unwrap();

                // Frame 2 must wait for drain; unblock write_budget after 15ms.
                let unblocker = async {
                    Timer::after(Duration::from_millis(15)).await;
                    let mut st = peer.lock().unwrap();
                    st.write_budget = Some(100);
                    st.write_notif.notify();
                };
                let (_, send_res) =
                    join(unblocker, NetworkSend::send_to(&mut &net, b"two", addr)).await;
                send_res.unwrap();

                // Now stall writer again and fill queue; third send must time out with ResourceExhausted.
                {
                    let mut st = peer.lock().unwrap();
                    st.write_budget = Some(0);
                }
                NetworkSend::send_to(&mut &net, b"three", addr)
                    .await
                    .unwrap();
                let err = NetworkSend::send_to(&mut &net, b"four", addr)
                    .await
                    .unwrap_err();
                assert_eq!(err.code(), ErrorCode::ResourceExhausted);
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    fn closed_peer_emits_notification_via_wait_available_or_closed() {
        block_on(async {
            let listener = MockListener::default();
            let peer = listener.peer(90, &[]);
            let buffers = TcpNetworkBuffers::<64, 2>::new();
            let net = TcpNetwork::new(listener, &buffers, &TcpConfig::default());

            let runner = pin!(net.run());
            let test = pin!(async {
                while !net
                    .buffers
                    .with_state(|s| s.slots[0].connected_addr().is_some())
                {
                    Timer::after(Duration::from_millis(2)).await;
                }

                {
                    let mut st = peer.lock().unwrap();
                    st.eof = true;
                    st.read_notif.notify();
                }

                let closed = with_timeout(
                    Duration::from_secs(2),
                    NetworkReceive::wait_available_or_closed(&mut &net),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(
                    closed,
                    Some(Address::Tcp(SocketAddr::from(([127, 0, 0, 1], 90))))
                );
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }
}
