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

//! The TCP transport of a node: its framing, its connection slots, and their timeouts,
//! with TCP peers that do what the input says.
//!
//! Each step of the input starts with a byte that selects what happens, modulo 9:
//! - 0: a peer connects, from the port in the next byte (one of a few);
//! - 1: a peer sends bytes: the connection (1 byte), the length (1 byte), the bytes;
//! - 2: a peer sends a frame: the connection (1 byte), the length in the frame header
//!   (2 bytes), and a byte that fills the payload;
//! - 3: a peer closes its side of the connection (1 byte);
//! - 4: a peer resets the connection (1 byte);
//! - 5: a peer reads at most the next byte more from the node (the connection, then the
//!   number; 255 for no limit);
//! - 6: the node sends a message: the port (1 byte), the length (1 byte), and whether the
//!   message looks encrypted, which protects its connection from eviction (1 byte);
//! - 7: time passes: tenths of a second (2 bytes);
//! - 8: the next accept fails (0), the next connect fails (1) or never ends (2), the next
//!   keep-alive setting fails (3), or the close of a connection never ends (4, then the
//!   connection).
//!
//! A connection byte selects any connection made so far, modulo their number.
//!
//! The target checks that each message that the node receives is a frame that the peer
//! sent, in the order sent, and not twice; that what the node writes is made of frames of
//! the messages that it sends, and of its status report for a frame that is too large; and
//! that the node holds no more open connections than its slots, plus one that waits for
//! the eviction of another.

#![no_main]

use core::future::{pending, poll_fn, Future};
use core::net::{Ipv4Addr, SocketAddr};
use core::pin::{pin, Pin};
use core::task::{Context, Poll, Waker};
use std::collections::VecDeque;

use libfuzzer_sys::fuzz_target;

use rs_matter::crypto::test_only_crypto;
use rs_matter::error::{Error, ErrorCode};
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::storage::ParseBuf;
use rs_matter::utils::sync::blocking::Mutex;
use rs_matter::utils::timers::Duration;
use rs_matter_transport::network::tcp::{
    TcpConfig, TcpKeepAlive, TcpNetwork, TcpNetworkBuffers, TcpNetworkRead, TcpNetworkSocket,
    TcpNetworkSockets, TcpNetworkWrite, FRAME_HDR_LEN,
};
use rs_matter_transport::network::{Address, NetworkReceive, NetworkSend};
use rs_matter_transport::plain_hdr::PlainHdr;
use rs_matter_transport::proto_hdr::ProtoHdr;

#[path = "clock.rs"]
mod clock;

/// The largest message, in bytes.
const N: usize = 128;
/// How many connections the node can have.
const SLOTS: usize = 3;
/// The size of the queue of bytes to send on each connection.
const TX_BUF: usize = 200;
/// How many ports the peers connect from, and the node sends to.
const PORTS: u8 = 4;
/// How many kinds of steps there are.
const STEPS: u8 = 9;

/// How many polls without anything happening mean that the node has nothing left to do.
const QUIET_POLLS: usize = 32;
/// The most polls for one step.
const MAX_POLLS: usize = 4096;
/// The most ways to match the received messages to connections that the target follows.
const MAX_DELIVERIES: usize = 256;

/// The opcode of a Secure Channel status report.
const STATUS_REPORT: u8 = 0x40;

/// What the next connect of the node does.
#[derive(Clone, Copy)]
enum Connect {
    Fail,
    Hang,
}

/// One TCP connection, with what each side sent.
struct Conn {
    addr: SocketAddr,
    /// Everything that the peer sent.
    sent: Vec<u8>,
    /// How much of it the node has read.
    read: usize,
    /// The peer closed its side.
    eof: bool,
    /// The peer reset the connection.
    reset: bool,
    /// How many more bytes the peer reads, if limited.
    budget: Option<usize>,
    /// Everything that the node wrote.
    output: Vec<u8>,
    /// The close of the node never ends.
    close_hangs: bool,
    /// The node closed or aborted the connection.
    closed: bool,
    /// The node holds the connection.
    held: bool,
}

impl Conn {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            sent: Vec::new(),
            read: 0,
            eof: false,
            reset: false,
            budget: None,
            output: Vec::new(),
            close_hangs: false,
            closed: false,
            held: false,
        }
    }

    /// Whether the peer still has the connection, as then it cannot connect again from
    /// the same port.
    fn is_open(&self) -> bool {
        !self.closed && !self.reset
    }
}

/// The peers, and what the node did with them.
struct World {
    conns: Vec<Conn>,
    /// The ways in which the messages that the node received can come from the
    /// connections: for each connection, how many of its frames the node has received
    /// or skipped. A message carries only an address, and connections can share one.
    /// Empty when there were too many ways to follow, which ends the check.
    deliveries: Vec<Vec<usize>>,
    /// The connections that the node has not accepted yet.
    to_accept: VecDeque<usize>,
    accept_errors: usize,
    keep_alive_errors: usize,
    connects: VecDeque<Connect>,
    /// The messages that the node was asked to send, by port, and whether they were
    /// found in what it wrote.
    messages: Vec<(SocketAddr, Vec<u8>, bool)>,
    /// How many messages the node was asked to send.
    sends: u32,
    /// Counts what happens, to see when the node has nothing left to do.
    progress: usize,
}

impl World {
    fn new() -> Self {
        Self {
            conns: Vec::new(),
            deliveries: vec![Vec::new()],
            to_accept: VecDeque::new(),
            accept_errors: 0,
            keep_alive_errors: 0,
            connects: VecDeque::new(),
            messages: Vec::new(),
            sends: 0,
            progress: 0,
        }
    }

    fn add(&mut self, conn: Conn) -> usize {
        self.conns.push(conn);
        for delivered in &mut self.deliveries {
            delivered.push(0);
        }

        self.conns.len() - 1
    }

    fn conn(&mut self, byte: u8) -> Option<&mut Conn> {
        let len = self.conns.len();
        (len > 0).then(|| &mut self.conns[byte as usize % len])
    }

    fn held_open(&self) -> usize {
        self.conns.iter().filter(|c| c.held && !c.closed).count()
    }

    /// Checks a message that the node received from `addr`.
    fn received(&mut self, addr: SocketAddr, message: &[u8]) {
        self.progress += 1;

        if self.deliveries.is_empty() {
            return;
        }

        let mut deliveries = Vec::new();

        for (i, conn) in self.conns.iter().enumerate() {
            if conn.addr != addr {
                continue;
            }

            // The node can only have received the frames that it has read in full
            let frames = frames(&conn.sent[..conn.read]);

            for delivered in &self.deliveries {
                if let Some(j) = (delivered[i]..frames.len()).find(|&j| frames[j] == message) {
                    let mut delivered = delivered.clone();
                    delivered[i] = j + 1;

                    if !deliveries.contains(&delivered) {
                        deliveries.push(delivered);
                    }
                }
            }
        }

        assert!(
            !deliveries.is_empty(),
            "Received a message of {} bytes from {} that its peer did not send, or not then",
            message.len(),
            addr
        );

        if deliveries.len() > MAX_DELIVERIES {
            deliveries.clear();
        }

        self.deliveries = deliveries;
    }

    /// Checks what the node wrote on each connection.
    fn check_output(&mut self) {
        for i in 0..self.conns.len() {
            let addr = self.conns[i].addr;
            let output = self.conns[i].output.clone();
            let too_large = oversized(&self.conns[i].sent);
            let frames = frames(&output);

            for (j, frame) in frames.iter().enumerate() {
                assert!(frame.len() <= N, "Wrote a frame of {} bytes", frame.len());

                let message = self
                    .messages
                    .iter_mut()
                    .find(|(to, m, found)| !*found && *to == addr && m == frame);
                if let Some((_, _, found)) = message {
                    *found = true;
                } else {
                    assert!(
                        too_large && j == frames.len() - 1 && is_too_large_report(frame),
                        "Wrote a frame of {} bytes to {} that is not a message for it",
                        frame.len(),
                        addr
                    );
                }
            }

            if let Some(len) = frame_len(&output[frame_bytes(&output)..]) {
                assert!(len <= N, "Wrote the header of a frame of {} bytes", len);
            }
        }
    }
}

/// The complete frames at the start of `data`, up to one that is too large.
fn frames(data: &[u8]) -> Vec<&[u8]> {
    let mut frames = Vec::new();
    let mut rest = data;

    while let Some(len) = frame_len(rest) {
        if len > N || rest.len() < FRAME_HDR_LEN + len {
            break;
        }
        frames.push(&rest[FRAME_HDR_LEN..FRAME_HDR_LEN + len]);
        rest = &rest[FRAME_HDR_LEN + len..];
    }

    frames
}

/// How many bytes the complete frames at the start of `data` take.
fn frame_bytes(data: &[u8]) -> usize {
    frames(data).iter().map(|f| FRAME_HDR_LEN + f.len()).sum()
}

/// The length in the frame header at the start of `data`.
fn frame_len(data: &[u8]) -> Option<usize> {
    let hdr = data.first_chunk::<FRAME_HDR_LEN>()?;
    Some(u32::from_le_bytes(*hdr) as usize)
}

/// Whether `data` holds the header of a frame that is too large, after complete frames.
fn oversized(data: &[u8]) -> bool {
    frame_len(&data[frame_bytes(data)..]).is_some_and(|len| len > N)
}

/// Whether `frame` is an unencrypted Secure Channel status report.
fn is_too_large_report(frame: &[u8]) -> bool {
    let mut frame = frame.to_vec();
    let mut pb = ParseBuf::new(&mut frame);
    let mut plain = PlainHdr::new();
    let mut proto = ProtoHdr::new();

    plain.decode(&mut pb).is_ok()
        && !plain.is_encrypted()
        && proto
            .decrypt_and_decode(test_only_crypto(), None, 0, &plain, &mut pb)
            .is_ok()
        && proto.proto_id == 0
        && proto.proto_opcode == STATUS_REPORT
}

fn port(byte: u8) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 5540 + u16::from(byte % PORTS)))
}

/// Waits forever, as a socket that never answers.
async fn hang<T>() -> T {
    pending().await
}

struct Sockets<'a>(&'a Mutex<RefCell<World>>);

impl<'a> TcpNetworkSockets for Sockets<'a> {
    type Socket = Socket<'a>;

    async fn accept(&self) -> Result<(SocketAddr, Self::Socket), Error> {
        poll_fn(|_| {
            self.0.lock(|world| {
                let mut world = world.borrow_mut();

                if world.accept_errors > 0 {
                    world.accept_errors -= 1;
                    world.progress += 1;
                    return Poll::Ready(Err(ErrorCode::NoNetworkInterface.into()));
                }

                let Some(idx) = world.to_accept.pop_front() else {
                    return Poll::Pending;
                };

                world.conns[idx].held = true;
                world.progress += 1;

                Poll::Ready(Ok((world.conns[idx].addr, Socket { world: self.0, idx })))
            })
        })
        .await
    }

    async fn connect(&self, addr: SocketAddr) -> Result<Self::Socket, Error> {
        let connect = self.0.lock(|world| {
            let mut world = world.borrow_mut();
            world.progress += 1;
            world.connects.pop_front()
        });

        match connect {
            Some(Connect::Fail) => Err(ErrorCode::NoNetworkInterface.into()),
            Some(Connect::Hang) => hang().await,
            None => Ok(self.0.lock(|world| {
                let mut world = world.borrow_mut();
                let mut conn = Conn::new(addr);
                conn.held = true;

                Socket {
                    world: self.0,
                    idx: world.add(conn),
                }
            })),
        }
    }
}

struct Socket<'a> {
    world: &'a Mutex<RefCell<World>>,
    idx: usize,
}

impl Socket<'_> {
    fn with<R>(&self, f: impl FnOnce(&mut Conn, &mut usize) -> R) -> R {
        self.world.lock(|world| {
            let world = &mut *world.borrow_mut();
            f(&mut world.conns[self.idx], &mut world.progress)
        })
    }
}

impl Drop for Socket<'_> {
    fn drop(&mut self) {
        self.with(|conn, _| conn.held = false);
    }
}

struct Read<'a, 'b>(&'a Socket<'b>);

impl TcpNetworkRead for Read<'_, '_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        poll_fn(|_| {
            self.0.with(|conn, progress| {
                if conn.reset {
                    return Poll::Ready(Err(ErrorCode::NoNetworkInterface.into()));
                }

                let unread = &conn.sent[conn.read..];
                if unread.is_empty() {
                    return if conn.eof || conn.closed {
                        Poll::Ready(Ok(0))
                    } else {
                        Poll::Pending
                    };
                }

                let len = unread.len().min(buf.len());
                buf[..len].copy_from_slice(&unread[..len]);
                conn.read += len;
                *progress += 1;

                Poll::Ready(Ok(len))
            })
        })
        .await
    }
}

struct Write<'a, 'b>(&'a Socket<'b>);

impl TcpNetworkWrite for Write<'_, '_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        poll_fn(|_| {
            self.0.with(|conn, progress| {
                if conn.reset || conn.closed {
                    return Poll::Ready(Err(ErrorCode::NoNetworkInterface.into()));
                }

                let len = conn
                    .budget
                    .map_or(buf.len(), |budget| budget.min(buf.len()));
                if len == 0 {
                    return Poll::Pending;
                }

                conn.output.extend_from_slice(&buf[..len]);
                if let Some(budget) = conn.budget.as_mut() {
                    *budget -= len;
                }
                *progress += 1;

                Poll::Ready(Ok(len))
            })
        })
        .await
    }
}

impl<'b> TcpNetworkSocket for Socket<'b> {
    type Read<'a>
        = Read<'a, 'b>
    where
        Self: 'a;
    type Write<'a>
        = Write<'a, 'b>
    where
        Self: 'a;

    fn split(&mut self) -> (Self::Read<'_>, Self::Write<'_>) {
        (Read(self), Write(self))
    }

    async fn close(&mut self) -> Result<(), Error> {
        let hangs = self.with(|conn, progress| {
            *progress += 1;
            if conn.close_hangs {
                true
            } else {
                conn.closed = true;
                false
            }
        });

        if hangs {
            hang().await
        } else {
            Ok(())
        }
    }

    async fn abort(&mut self) -> Result<(), Error> {
        self.with(|conn, progress| {
            conn.closed = true;
            *progress += 1;
        });

        Ok(())
    }

    fn set_keep_alive(&mut self, _keep_alive: Option<TcpKeepAlive>) -> Result<(), Error> {
        self.world.lock(|world| {
            let mut world = world.borrow_mut();
            if world.keep_alive_errors > 0 {
                world.keep_alive_errors -= 1;
                Err(ErrorCode::NoNetworkInterface.into())
            } else {
                Ok(())
            }
        })
    }
}

/// Polls the node, its receiver and its senders until nothing happens any more.
fn run_until_idle(
    futures: &mut [Pin<&mut dyn Future<Output = ()>>],
    senders: &mut Vec<Pin<Box<dyn Future<Output = ()> + '_>>>,
    world: &Mutex<RefCell<World>>,
) {
    let mut cx = Context::from_waker(Waker::noop());
    let mut quiet = 0;
    let mut last = usize::MAX;

    for _ in 0..MAX_POLLS {
        for future in futures.iter_mut() {
            assert!(
                future.as_mut().poll(&mut cx).is_pending(),
                "The TCP network stopped"
            );
        }

        senders.retain_mut(|sender| sender.as_mut().poll(&mut cx).is_pending());

        let progress = world.lock(|world| world.borrow().progress);
        if progress == last {
            quiet += 1;
            if quiet >= QUIET_POLLS {
                break;
            }
        } else {
            quiet = 0;
        }

        last = progress;
    }

    let held = world.lock(|world| world.borrow().held_open());
    assert!(
        held <= SLOTS + 1,
        "The node holds {} open connections",
        held
    );
}

/// Takes `L` bytes from the input.
fn take<'a, const L: usize>(input: &mut &'a [u8]) -> Option<&'a [u8; L]> {
    let (taken, rest) = input.split_first_chunk::<L>()?;
    *input = rest;
    Some(taken)
}

fn run(data: &[u8]) {
    clock::reset();

    let world = Mutex::new(RefCell::new(World::new()));
    let buffers = TcpNetworkBuffers::<N, SLOTS, TX_BUF>::new();
    let config = TcpConfig {
        idle_timeout: Some(Duration::from_secs(30)),
        ..TcpConfig::new()
    };
    let net = TcpNetwork::new(Sockets(&world), &buffers, &config).unwrap();

    let runner = pin!(async {
        let _ = net.run().await;
    });
    let receiver = pin!(async {
        let mut buf = [0; N];
        let mut net = &net;

        loop {
            match net.wait_available_or_closed().await {
                Ok(Some(_)) => world.lock(|world| world.borrow_mut().progress += 1),
                Ok(None) => {
                    let (len, addr) = net.recv_from(&mut buf).await.unwrap();
                    let Address::Tcp(addr) = addr else {
                        panic!("Received from {:?}", addr);
                    };
                    world.lock(|world| world.borrow_mut().received(addr, &buf[..len]));
                }
                Err(e) => panic!("Receive failed: {:?}", e),
            }
        }
    });

    let mut futures: [Pin<&mut dyn Future<Output = ()>>; 2] = [runner, receiver];
    let mut senders: Vec<Pin<Box<dyn Future<Output = ()> + '_>>> = Vec::new();

    let mut input = data;

    run_until_idle(&mut futures, &mut senders, &world);

    while let Some(&[step]) = take::<1>(&mut input) {
        match step % STEPS {
            0 => {
                let Some(&[port_byte]) = take::<1>(&mut input) else {
                    break;
                };
                let addr = port(port_byte);
                world.lock(|world| {
                    let mut world = world.borrow_mut();
                    if !world.conns.iter().any(|c| c.addr == addr && c.is_open()) {
                        let idx = world.add(Conn::new(addr));
                        world.to_accept.push_back(idx);
                    }
                });
            }
            1 => {
                let Some(&[conn, len]) = take::<2>(&mut input) else {
                    break;
                };
                let len = (len as usize).min(input.len());
                let (bytes, rest) = input.split_at(len);
                input = rest;
                world.lock(|world| {
                    if let Some(conn) = world.borrow_mut().conn(conn) {
                        conn.sent.extend_from_slice(bytes);
                    }
                });
            }
            2 => {
                let Some(&[conn, len_lo, len_hi, fill]) = take::<4>(&mut input) else {
                    break;
                };
                let len = u16::from_le_bytes([len_lo, len_hi]) as usize;
                world.lock(|world| {
                    if let Some(conn) = world.borrow_mut().conn(conn) {
                        conn.sent.extend_from_slice(&(len as u32).to_le_bytes());
                        conn.sent
                            .extend((0..len.min(N + 1)).map(|i| fill.wrapping_add(i as u8)));
                    }
                });
            }
            3 => {
                let Some(&[conn]) = take::<1>(&mut input) else {
                    break;
                };
                world.lock(|world| {
                    if let Some(conn) = world.borrow_mut().conn(conn) {
                        conn.eof = true;
                    }
                });
            }
            4 => {
                let Some(&[conn]) = take::<1>(&mut input) else {
                    break;
                };
                world.lock(|world| {
                    if let Some(conn) = world.borrow_mut().conn(conn) {
                        conn.reset = true;
                    }
                });
            }
            5 => {
                let Some(&[conn, budget]) = take::<2>(&mut input) else {
                    break;
                };
                world.lock(|world| {
                    if let Some(conn) = world.borrow_mut().conn(conn) {
                        conn.budget = (budget != 255).then_some(budget as usize);
                    }
                });
            }
            6 => {
                let Some(&[port_byte, len, flags]) = take::<3>(&mut input) else {
                    break;
                };
                let addr = port(port_byte);
                let message = world.lock(|world| {
                    let mut world = world.borrow_mut();
                    world.sends += 1;

                    // A message that cannot be mistaken for another one, as far as its
                    // length allows. One with a session ID that is not 0 looks encrypted.
                    let mut message = vec![0; (len as usize % N) + 1];
                    let mut unique = [0; 7];
                    unique[1..3].copy_from_slice(&u16::from(flags & 1 != 0).to_le_bytes());
                    unique[3..7].copy_from_slice(&world.sends.to_le_bytes());
                    let prefix = message.len().min(unique.len());
                    message[..prefix].copy_from_slice(&unique[..prefix]);

                    world.messages.push((addr, message.clone(), false));
                    message
                });

                let net = &net;
                senders.push(Box::pin(async move {
                    let mut net = net;
                    let _ = net.send_to(&message, Address::Tcp(addr)).await;
                }));
            }
            7 => {
                let Some(tenths) = take::<2>(&mut input) else {
                    break;
                };
                let ms = u64::from(u16::from_le_bytes(*tenths)) * 100;
                clock::advance(ms, || {
                    run_until_idle(&mut futures, &mut senders, &world);
                    true
                });
            }
            _ => {
                let Some(&[fault]) = take::<1>(&mut input) else {
                    break;
                };
                match fault % 5 {
                    0 => world.lock(|world| world.borrow_mut().accept_errors += 1),
                    1 => world.lock(|world| world.borrow_mut().connects.push_back(Connect::Fail)),
                    2 => world.lock(|world| world.borrow_mut().connects.push_back(Connect::Hang)),
                    3 => world.lock(|world| world.borrow_mut().keep_alive_errors += 1),
                    _ => {
                        let Some(&[conn]) = take::<1>(&mut input) else {
                            break;
                        };
                        world.lock(|world| {
                            if let Some(conn) = world.borrow_mut().conn(conn) {
                                conn.close_hangs = true;
                            }
                        });
                    }
                }
            }
        }

        run_until_idle(&mut futures, &mut senders, &world);
    }

    drop(senders);
    world.lock(|world| world.borrow_mut().check_output());
}

fuzz_target!(|data: &[u8]| {
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = env_logger::try_init();
    }

    run(data);
});
