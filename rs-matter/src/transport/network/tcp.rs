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

#![cfg(all(feature = "std", feature = "async-io"))]

//! TCP transport implementation for async-io.
//!
//! This module provides a TCP-based implementation of the [`NetworkSend`] and [`NetworkReceive`]
//! traits, hiding the connection-oriented nature of TCP behind the connectionless `NetworkSend`/`NetworkReceive`
//! abstractions used by the Matter transport layer.
//!
//! Per the Matter Core Specification (Section 4.7), TCP messages are framed with a 4-byte little-endian
//! message length prefix. This module handles the framing/de-framing transparently.
//!
//! # Connection Management
//!
//! The [`TcpNetwork`] struct manages:
//! - A [`TcpListener`](std::net::TcpListener) for accepting incoming connections.
//! - A pool of active TCP connections (both accepted and outgoing), keyed by remote [`SocketAddr`].
//!
//! When sending, if no connection exists to the target address, one is established on-the-fly.
//! When receiving, new incoming connections are accepted and added to the pool automatically.
//!
//! # Full-Duplex Support
//!
//! Both [`NetworkSend`] and [`NetworkReceive`] are implemented for `&TcpNetwork` (shared reference),
//! allowing the same `TcpNetwork` instance to be used concurrently for sending and receiving — as
//! required by [`TransportRunner::run`](crate::transport::TransportRunner::run) which takes separate
//! `NetworkSend` and `NetworkReceive` implementations.
//!
//! Interior mutability is achieved via [`Mutex`](crate::utils::sync::blocking::Mutex)`<`[`RefCell`](crate::utils::cell::RefCell)`<...>>`,
//! following the same pattern as the BTP transport.
//!
//! # I/O Multiplexing
//!
//! The [`NetworkReceive::wait_available`] implementation uses [`Async::poll_readable`](async_io::Async::poll_readable)
//! inside a [`core::future::poll_fn`] to register wakers for ALL file descriptors (the listener + every
//! open connection) in a single poll call. This means any fd becoming ready wakes the task, avoiding
//! the starvation problem that a naive round-robin approach would have.
//!
//! # Usage
//!
//! ```rust,ignore
//! use std::net::TcpListener;
//! use async_io::Async;
//! use rs_matter::transport::network::tcp::TcpNetwork;
//!
//! let listener = Async::<TcpListener>::bind(([0, 0, 0, 0, 0, 0, 0, 0], 5540))?;
//! let tcp = TcpNetwork::<8>::new(listener);
//!
//! // Both `&tcp` implements `NetworkSend` and `NetworkReceive`.
//! // Pass `&tcp` as both the send and recv implementation to `TransportRunner::run`,
//! // or chain it with a UDP network via `ChainedNetwork`.
//! ```

use core::future::poll_fn;
use core::pin::pin;
use core::task::Poll;

use alloc::vec::Vec;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};

use async_io::Async;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use crate::error::{Error, ErrorCode};
use crate::transport::network::Address;
use crate::utils::cell::RefCell;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::{IfMutex, Notification};

use super::{NetworkReceive, NetworkSend, MAX_RX_LARGE_PACKET_SIZE};

extern crate alloc;

/// Timeout for a single `send_to` call (including one retry).
///
/// If a send stalls for longer than this (e.g. the peer's TCP window is full and never drains),
/// the send fails with an error rather than blocking all other sends indefinitely.
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of TCP connections that can be maintained simultaneously.
///
/// This is a reasonable default; users can customize by adjusting the `N` const generic.
pub const DEFAULT_MAX_TCP_CONNECTIONS: usize = 8;

/// Size of the TCP framing header (4-byte little-endian message length prefix).
///
/// Per the Matter Core Specification (Section 4.7.2).
const FRAME_HDR_LEN: usize = 4;

/// Maximum size of the per-connection receive buffer.
///
/// This limits the amount of data a connection can buffer before a complete message is consumed.
/// Based on `MAX_RX_LARGE_PACKET_SIZE` (the maximum TCP message payload, 1 MiB per Matter spec)
/// plus the 4-byte framing header.
///
/// If a peer streams data faster than the consumer drains frames and this limit is exceeded,
/// the connection is dropped to prevent unbounded heap growth (DoS mitigation).
const MAX_RX_BUF_SIZE: usize = MAX_RX_LARGE_PACKET_SIZE + FRAME_HDR_LEN;

/// A TCP network transport implementation that hides the connection-oriented nature of TCP
/// behind the connectionless [`NetworkSend`]/[`NetworkReceive`] abstractions.
///
/// The const generic `N` controls the maximum number of simultaneous TCP connections.
///
/// Both [`NetworkSend`] and [`NetworkReceive`] are implemented for `&TcpNetwork` (shared reference),
/// enabling full-duplex operation where sending and receiving happen concurrently on the same
/// `TcpNetwork` instance.
///
/// Per the Matter Core Specification (Section 4.7), TCP messages are framed with a 4-byte
/// little-endian message length prefix. This is handled transparently by this implementation.
pub struct TcpNetwork<const N: usize = DEFAULT_MAX_TCP_CONNECTIONS> {
    /// The TCP listener for accepting incoming connections.
    listener: Async<TcpListener>,
    /// The inner mutable state, behind a blocking mutex for interior mutability.
    /// The mutex is only held for short synchronous critical sections (never across `.await`).
    inner: Mutex<RefCell<TcpInner>>,
    /// Notification sent when the connection pool is modified (e.g. a new outgoing connection
    /// was established by the send path). This wakes the recv path's `wait_available` so it
    /// can re-register wakers for the new connection's fd.
    pool_changed: Notification,
    /// Async mutex that serializes the entire send-side frame write (4-byte length prefix + payload).
    /// This prevents two concurrent `send_to` calls from interleaving their bytes on the same
    /// TCP stream when targeting the same remote address.
    // TODO: This blocks all sends, even to different addresses.
    send_mutex: IfMutex<()>,
}

impl<const N: usize> TcpNetwork<N> {
    /// Create a new TCP network transport backed by the given listener.
    ///
    /// The listener should already be bound to the desired address/port.
    pub fn new(listener: Async<TcpListener>) -> Self {
        Self {
            listener,
            inner: Mutex::new(RefCell::new(TcpInner::new())),
            pool_changed: Notification::new(),
            send_mutex: IfMutex::new(()),
        }
    }

    /// Return the local address this TCP network is listening on.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.get_ref().local_addr()
    }

    async fn wait_available(&self) -> Result<(), Error> {
        // Check if we already have a complete message buffered
        let ready = self
            .inner
            .lock(|inner| inner.borrow().find_ready_connection().is_some());
        if ready {
            return Ok(());
        }

        // Fast-path: try opportunistic non-blocking reads on existing connections.
        let ready = self
            .inner
            .lock(|inner| inner.borrow_mut().try_read_all().is_some());
        if ready {
            return Ok(());
        }

        // No complete messages available. We need to wait for either:
        // (a) A new incoming connection on the listener, or
        // (b) Data becoming available on ANY existing connection, or
        // (c) The connection pool being modified by the send path.
        //
        // We use `core::future::poll_fn` with `Async::poll_readable` to register
        // wakers for ALL file descriptors (listener + every connection) in a single
        // poll call. We combine this with a `Notification` wait via `select` so that
        // new connections added by the send path also wake us.
        loop {
            let event = {
                let io_poll = poll_fn(|cx| {
                    // 1) Poll the listener for incoming connections.
                    if self.listener.poll_readable(cx).is_ready() {
                        return Poll::Ready(IoEvent::ListenerReady);
                    }

                    // 2) Poll ALL existing connections for readability.
                    //    The mutex is held only for the duration of this synchronous closure.
                    self.inner.lock(|inner| {
                        let inner = inner.borrow();
                        for (i, conn) in inner.connections.iter().enumerate() {
                            match conn.stream.poll_readable(cx) {
                                Poll::Ready(Ok(())) => {
                                    return Poll::Ready(IoEvent::ConnectionReadable(i));
                                }
                                Poll::Ready(Err(_)) => {
                                    return Poll::Ready(IoEvent::ConnectionError(i));
                                }
                                Poll::Pending => {}
                            }
                        }

                        Poll::Pending
                    })
                });

                // Combine I/O polling with the pool-changed notification.
                // If the send path adds a new connection, we wake up and re-register
                // wakers to include the new connection's fd.
                let mut io_poll = pin!(io_poll);
                let mut pool_notif = pin!(self.pool_changed.wait());

                match select(&mut io_poll, &mut pool_notif).await {
                    Either::First(event) => event,
                    Either::Second(()) => IoEvent::PoolChanged,
                }
            };

            match event {
                IoEvent::ListenerReady => {
                    // Accept the connection (async, outside the lock)
                    match self.listener.accept().await {
                        Ok((stream, addr)) => {
                            self.inner.lock(|inner| {
                                inner.borrow_mut().add_connection::<N>(stream, addr);
                            });
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    }
                }
                IoEvent::ConnectionReadable(idx) => {
                    self.inner.lock(|inner| {
                        let mut inner = inner.borrow_mut();
                        if idx < inner.connections.len()
                            && inner.connections[idx].try_read_nonblocking().is_err()
                        {
                            inner.remove_connection(idx);
                        }
                    });
                }
                IoEvent::ConnectionError(idx) => {
                    self.inner.lock(|inner| {
                        let mut inner = inner.borrow_mut();
                        if idx < inner.connections.len() {
                            inner.remove_connection(idx);
                        }
                    });
                }
                IoEvent::PoolChanged => {
                    // Pool was modified by the send path; just re-loop to re-register wakers.
                }
            }

            // After handling the event, check for complete messages.
            let ready = self
                .inner
                .lock(|inner| inner.borrow().find_ready_connection().is_some());
            if ready {
                return Ok(());
            }

            let ready = self
                .inner
                .lock(|inner| inner.borrow_mut().try_read_all().is_some());
            if ready {
                return Ok(());
            }

            // No complete message yet — loop back and re-register all wakers.
        }
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        loop {
            // Ensure at least one connection has a complete message ready
            self.wait_available().await?;

            let result = self.inner.lock(|inner| {
                let mut inner = inner.borrow_mut();

                let Some(idx) = inner.find_ready_connection() else {
                    return Ok(None);
                };

                let conn = &mut inner.connections[idx];

                let Some(msg_len) = conn.has_complete_message() else {
                    return Ok(None);
                };

                if msg_len > buffer.len() {
                    // Message too large for the provided buffer; discard it
                    conn.rx_buf.drain(..FRAME_HDR_LEN + msg_len);
                    Err(ErrorCode::BufferTooSmall)?;
                }

                let payload = conn.extract_message(msg_len);
                buffer[..msg_len].copy_from_slice(&payload);

                let remote = conn.remote;

                // Advance round-robin index
                inner.poll_index = (idx + 1) % inner.connections.len().max(1);

                Ok::<_, Error>(Some((msg_len, Address::Tcp(remote))))
            })?;

            if let Some((len, addr)) = result {
                break Ok((len, addr));
            }
        }
    }

    async fn send_to(&self, data: &[u8], addr: Address) -> Result<(), Error> {
        let sock_addr = addr.tcp().ok_or(ErrorCode::NoNetworkInterface)?;

        // Wrap the entire send (including one retry) in a timeout. If a write stalls
        // (e.g. the peer's TCP receive window is full and never drains), we must not
        // block the global send mutex indefinitely — that would stall ALL sends.
        let send_result = select(
            pin!(async {
                // Ensure the connection exists (outside the send lock — connecting is slow
                // and doesn't write to the stream, so it's safe to overlap with other sends).
                let conn_id = self.ensure_connected(sock_addr).await?;

                // Acquire the send-side lock to guarantee that the entire framed message
                // (4-byte length prefix + payload) is written atomically. Without this,
                // two concurrent sends to the same address would interleave their bytes.
                let _send_guard = self.send_mutex.lock().await;

                // Attempt to send; on failure, remove the broken connection and retry once
                let result = self.send_framed_to(sock_addr, conn_id, data).await;
                if result.is_err() {
                    self.inner.lock(|inner| {
                        let mut inner = inner.borrow_mut();
                        // Remove by exact conn_id so we don't accidentally remove a
                        // replacement connection that was established in the meantime.
                        if let Some(idx) = inner.find_connection_exact(&sock_addr, conn_id) {
                            inner.remove_connection(idx);
                        }
                    });

                    // Retry with a fresh connection (still under send lock)
                    let new_conn_id = self.ensure_connected(sock_addr).await?;
                    self.send_framed_to(sock_addr, new_conn_id, data).await?;
                }

                Ok::<(), Error>(())
            }),
            pin!(Timer::after(SEND_TIMEOUT)),
        )
        .await;

        match send_result {
            Either::First(result) => result,
            Either::Second(()) => Err(ErrorCode::TxTimeout.into()),
        }
    }

    /// Ensure a connection to the given remote address exists in the pool.
    ///
    /// If no connection exists, one is established asynchronously and added to the pool.
    /// Returns the `conn_id` of the (existing or newly created) connection.
    async fn ensure_connected(&self, addr: SocketAddr) -> Result<u64, Error> {
        // Check for an existing connection
        let existing_id = self
            .inner
            .lock(|inner| inner.borrow().find_connection_id(&addr));

        if let Some(id) = existing_id {
            return Ok(id);
        }

        // Connect outside the lock (async operation)
        let stream = Async::<TcpStream>::connect(addr).await?;

        // Insert into pool
        let conn_id = self.inner.lock(|inner| {
            let mut inner = inner.borrow_mut();

            // Double-check: another task may have connected in the meantime
            if let Some(id) = inner.find_connection_id(&addr) {
                // Discard the new connection, use the existing one
                let _ = stream.get_ref().shutdown(Shutdown::Both);
                return id;
            }

            inner.add_connection::<N>(stream, addr)
        });

        // Notify the recv path so it can register wakers for the new connection's fd
        self.pool_changed.notify();

        Ok(conn_id)
    }

    /// Send a framed message (4-byte LE length prefix + payload) to the connection
    /// identified by `(addr, conn_id)`.
    ///
    /// The entire frame (length prefix + payload) is pre-built into a single contiguous
    /// buffer and written via a single [`write_all_to`](Self::write_all_to) call. This
    /// ensures that if the connection dies mid-write, we never accidentally continue
    /// writing the remainder of a partial frame onto a replacement connection.
    async fn send_framed_to(
        &self,
        addr: SocketAddr,
        conn_id: u64,
        data: &[u8],
    ) -> Result<(), Error> {
        // Pre-build the complete frame: 4-byte LE length prefix + payload
        let len = data.len() as u32;
        let mut frame = Vec::with_capacity(FRAME_HDR_LEN + data.len());
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(data);

        self.write_all_to(addr, conn_id, &frame).await
    }

    /// Write all bytes to the connection identified by `(addr, conn_id)`.
    ///
    /// Uses the optimistic I/O pattern expected by `async-io`: try the
    /// non-blocking write first; only wait for writability (via `poll_writable`)
    /// when the write returns `WouldBlock`. After any wakeup, we optimistically
    /// retry the write immediately rather than re-checking `poll_writable`,
    /// because the reactor only guarantees that the waker is called — not that
    /// `poll_writable` will return `Ready`.
    ///
    /// Each access to the connection pool goes through the mutex, looking up the
    /// connection by **both** address and connection ID. If the original
    /// connection was removed and a new connection to the same address was
    /// established, the ID will not match and the write fails immediately —
    /// preventing partial frame data from leaking onto a different connection.
    async fn write_all_to(
        &self,
        addr: SocketAddr,
        conn_id: u64,
        mut data: &[u8],
    ) -> Result<(), Error> {
        while !data.is_empty() {
            // Attempt a non-blocking write (optimistic: assume writable)
            let written: Result<usize, Error> = self.inner.lock(|inner| {
                let inner = inner.borrow();
                if let Some(idx) = inner.find_connection_exact(&addr, conn_id) {
                    match inner.connections[idx].stream.get_ref().write(data) {
                        Ok(0) => Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "failed to write to TCP stream",
                        )
                        .into()),
                        Ok(n) => Ok(n),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                        Err(e) => Err(e.into()),
                    }
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "TCP connection removed from pool",
                    )
                    .into())
                }
            });

            match written? {
                0 => {
                    // WouldBlock — register interest for writability, wait for
                    // any wakeup, then optimistically retry the write.
                    //
                    // This mirrors `async-io`'s `optimistic()` helper: poll the
                    // inner `Writable` future once (which registers a waker with
                    // the reactor and returns `Pending`), then on the next wakeup
                    // return `Ready(Ok(()))` without re-checking the reactor
                    // state.  This is correct because:
                    //   - The reactor guarantees it will wake us when the fd
                    //     becomes writable.
                    //   - If the wakeup was spurious, the outer loop will
                    //     just get `WouldBlock` again and re-register.
                    let mut registered = false;
                    poll_fn(|cx| {
                        if !registered {
                            registered = true;
                            self.inner.lock(|inner| {
                                let inner = inner.borrow();
                                if let Some(idx) = inner.find_connection_exact(&addr, conn_id) {
                                    let _ = inner.connections[idx].stream.poll_writable(cx);
                                    Poll::Pending
                                } else {
                                    Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::NotConnected,
                                        "TCP connection removed from pool",
                                    )))
                                }
                            })
                        } else {
                            Poll::Ready(Ok(()))
                        }
                    })
                    .await?;
                }
                n => data = &data[n..],
            }
        }

        Ok(())
    }
}

impl<const N: usize> NetworkSend for TcpNetwork<N> {
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        TcpNetwork::<N>::send_to(self, data, addr).await
    }
}

impl<const N: usize> NetworkReceive for TcpNetwork<N> {
    async fn wait_available(&mut self) -> Result<(), Error> {
        TcpNetwork::<N>::wait_available(self).await
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        TcpNetwork::<N>::recv_from(self, buffer).await
    }
}

impl<const N: usize> NetworkSend for &TcpNetwork<N> {
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        TcpNetwork::<N>::send_to(*self, data, addr).await
    }
}

impl<const N: usize> NetworkReceive for &TcpNetwork<N> {
    async fn wait_available(&mut self) -> Result<(), Error> {
        TcpNetwork::<N>::wait_available(self).await
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        TcpNetwork::<N>::recv_from(*self, buffer).await
    }
}

/// The inner mutable state of a [`TcpNetwork`], protected by a blocking mutex.
struct TcpInner {
    /// Pool of currently active connections.
    connections: Vec<TcpConnection>,
    /// Index tracking which connection to check next when extracting messages (round-robin fairness).
    poll_index: usize,
    /// Monotonic counter for assigning unique connection IDs.
    next_conn_id: u64,
}

impl TcpInner {
    const fn new() -> Self {
        Self {
            connections: Vec::new(),
            poll_index: 0,
            next_conn_id: 0,
        }
    }

    /// Find the connection ID for the connection to the given address.
    fn find_connection_id(&self, addr: &SocketAddr) -> Option<u64> {
        self.connections
            .iter()
            .find(|c| c.remote == *addr)
            .map(|c| c.conn_id)
    }

    /// Find the index of a connection by `(addr, conn_id)` pair.
    ///
    /// This ensures we are operating on the exact same physical connection,
    /// not a replacement connection to the same address.
    fn find_connection_exact(&self, addr: &SocketAddr, conn_id: u64) -> Option<usize> {
        self.connections
            .iter()
            .position(|c| c.remote == *addr && c.conn_id == conn_id)
    }

    /// Add an already-accepted or outgoing connection to the pool.
    ///
    /// Evicts the oldest connection if at capacity. Returns the assigned connection ID.
    fn add_connection<const N: usize>(
        &mut self,
        stream: Async<TcpStream>,
        addr: SocketAddr,
    ) -> u64 {
        stream.get_ref().set_nodelay(true).ok();

        if self.connections.len() >= N {
            let evicted = self.connections.remove(0);
            let _ = evicted.stream.get_ref().shutdown(Shutdown::Both);
        }

        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;

        self.connections
            .push(TcpConnection::new(conn_id, addr, stream));

        conn_id
    }

    /// Remove a connection at the given index, shutting it down gracefully.
    fn remove_connection(&mut self, index: usize) {
        if index < self.connections.len() {
            let evicted = self.connections.remove(index);
            let _ = evicted.stream.get_ref().shutdown(Shutdown::Both);
        }
    }

    /// Check if any existing connection has a complete message ready.
    /// Returns the index of the connection with a ready message, if any.
    fn find_ready_connection(&self) -> Option<usize> {
        let len = self.connections.len();
        if len == 0 {
            return None;
        }

        // Round-robin starting from poll_index
        for i in 0..len {
            let idx = (self.poll_index + i) % len;
            if self.connections[idx].has_complete_message().is_some() {
                return Some(idx);
            }
        }

        None
    }

    /// Try non-blocking reads on all connections, removing broken ones.
    /// Returns the index of the first connection that has a complete message, if any.
    fn try_read_all(&mut self) -> Option<usize> {
        let mut i = 0;
        while i < self.connections.len() {
            match self.connections[i].try_read_nonblocking() {
                Ok(_) => {
                    if self.connections[i].has_complete_message().is_some() {
                        return Some(i);
                    }
                    i += 1;
                }
                Err(_) => {
                    self.remove_connection(i);
                }
            }
        }

        None
    }
}

/// An active TCP connection, associated with a remote address.
struct TcpConnection {
    /// A unique identifier for this connection, assigned from a monotonic counter.
    /// Used by the send path to ensure writes always target the same physical connection,
    /// even if a connection to the same address is dropped and re-established.
    conn_id: u64,
    /// The remote socket address of this connection.
    remote: SocketAddr,
    /// The async TCP stream.
    stream: Async<TcpStream>,
    /// Persistent receive buffer for accumulating partial reads from this connection.
    /// TCP is a stream protocol, so we may read partial messages or multiple messages at once.
    ///
    /// When a connection is removed (via [`TcpInner::remove_connection`]), this buffer is dropped
    /// along with the connection, discarding any partially-received messages. This is the correct
    /// behavior: partial frames from a dead connection are meaningless.
    rx_buf: Vec<u8>,
}

impl TcpConnection {
    const fn new(conn_id: u64, remote: SocketAddr, stream: Async<TcpStream>) -> Self {
        Self {
            conn_id,
            remote,
            stream,
            rx_buf: Vec::new(),
        }
    }

    /// Check if we have a complete framed message in the receive buffer.
    /// Returns `Some(message_len)` if a complete message is available (the 4-byte length prefix + payload).
    fn has_complete_message(&self) -> Option<usize> {
        if self.rx_buf.len() < FRAME_HDR_LEN {
            return None;
        }

        let hdr: [u8; 4] = self.rx_buf[..4].try_into().unwrap();
        let msg_len = u32::from_le_bytes(hdr) as usize;

        if self.rx_buf.len() >= FRAME_HDR_LEN + msg_len {
            Some(msg_len)
        } else {
            None
        }
    }

    /// Extract a complete message from the receive buffer, removing it and its length prefix.
    fn extract_message(&mut self, msg_len: usize) -> Vec<u8> {
        // Skip the 4-byte length prefix, take msg_len bytes
        let payload = self.rx_buf[FRAME_HDR_LEN..FRAME_HDR_LEN + msg_len].to_vec();
        self.rx_buf.drain(..FRAME_HDR_LEN + msg_len);
        payload
    }

    /// Try to read more data from the stream (non-blocking).
    ///
    /// This uses `get_ref().read()` which performs a non-blocking read because
    /// `Async::new()` / `Async::connect()` guarantee the underlying fd is in non-blocking mode.
    /// This is the standard async-io pattern for reading after `poll_readable` has signaled
    /// readability, or for opportunistic polling of already-buffered OS socket data.
    ///
    /// Returns `Ok(bytes_read)` or `Err` if the connection is closed/errored.
    ///
    /// If the receive buffer exceeds [`MAX_RX_BUF_SIZE`], returns an error to signal that the
    /// connection should be dropped (DoS protection).
    fn try_read_nonblocking(&mut self) -> std::io::Result<usize> {
        // Enforce maximum buffer size to prevent unbounded heap growth.
        // If exceeded, the connection will be dropped by the caller.
        if self.rx_buf.len() >= MAX_RX_BUF_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "TCP receive buffer exceeded maximum size",
            ));
        }

        let mut tmp = [0u8; 4096];
        match self.stream.get_ref().read(&mut tmp) {
            Ok(0) => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "TCP connection closed by peer",
            )),
            Ok(n) => {
                self.rx_buf.extend_from_slice(&tmp[..n]);

                // Check again after extending — a single read could push us over the limit
                if self.rx_buf.len() > MAX_RX_BUF_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::OutOfMemory,
                        "TCP receive buffer exceeded maximum size",
                    ));
                }

                Ok(n)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }
}

/// Internal event type for the I/O multiplexing in [`TcpNetwork::wait_available`].
enum IoEvent {
    /// The listener has become readable (ready to accept).
    ListenerReady,
    /// The connection at the given pool index signaled readability.
    ConnectionReadable(usize),
    /// The connection at the given pool index encountered an I/O error.
    ConnectionError(usize),
    /// The connection pool was modified (e.g. by the send path adding a new connection).
    PoolChanged,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use async_io::Async;

    use futures_lite::future::block_on;

    /// Helper: create an `Async<TcpListener>` bound to an ephemeral port on localhost.
    fn ephemeral_listener() -> Async<std::net::TcpListener> {
        Async::<std::net::TcpListener>::bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            0,
        )))
        .unwrap()
    }

    /// Helper: get the local address of a listener.
    fn local_addr(listener: &Async<std::net::TcpListener>) -> SocketAddr {
        listener.get_ref().local_addr().unwrap()
    }

    /// Helper: send a raw framed message (4-byte LE prefix + payload) over a plain TCP stream.
    fn send_framed_raw(stream: &mut std::net::TcpStream, payload: &[u8]) {
        let len = payload.len() as u32;
        stream.write_all(&len.to_le_bytes()).unwrap();
        stream.write_all(payload).unwrap();
        stream.flush().unwrap();
    }

    // ── TcpConnection unit tests ─────────────────────────────────────────

    #[test]
    fn has_complete_message_empty_buffer() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let laddr = listener.local_addr().unwrap();
        let raw = std::net::TcpStream::connect(laddr).unwrap();
        raw.set_nonblocking(true).unwrap();
        let conn = TcpConnection::new(0, laddr, Async::new(raw).unwrap());

        assert!(conn.has_complete_message().is_none());
    }

    #[test]
    fn has_complete_message_partial_header() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let laddr = listener.local_addr().unwrap();
        let raw = std::net::TcpStream::connect(laddr).unwrap();
        raw.set_nonblocking(true).unwrap();
        let mut conn = TcpConnection::new(0, laddr, Async::new(raw).unwrap());

        // Only 1-3 bytes of the 4-byte header
        conn.rx_buf.push(0x05);
        assert!(conn.has_complete_message().is_none());

        conn.rx_buf.extend_from_slice(&[0x00, 0x00]);
        assert!(conn.has_complete_message().is_none());
    }

    #[test]
    fn has_complete_message_header_only_no_payload() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let laddr = listener.local_addr().unwrap();
        let raw = std::net::TcpStream::connect(laddr).unwrap();
        raw.set_nonblocking(true).unwrap();
        let mut conn = TcpConnection::new(0, laddr, Async::new(raw).unwrap());

        // Header says 5 bytes of payload, but none present yet
        conn.rx_buf.extend_from_slice(&5u32.to_le_bytes());
        assert!(conn.has_complete_message().is_none());
    }

    #[test]
    fn has_complete_message_partial_payload() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let laddr = listener.local_addr().unwrap();
        let raw = std::net::TcpStream::connect(laddr).unwrap();
        raw.set_nonblocking(true).unwrap();
        let mut conn = TcpConnection::new(0, laddr, Async::new(raw).unwrap());

        // Header says 5 bytes, only 3 present
        conn.rx_buf.extend_from_slice(&5u32.to_le_bytes());
        conn.rx_buf.extend_from_slice(&[1, 2, 3]);
        assert!(conn.has_complete_message().is_none());
    }

    #[test]
    fn has_complete_message_exact_payload() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let laddr = listener.local_addr().unwrap();
        let raw = std::net::TcpStream::connect(laddr).unwrap();
        raw.set_nonblocking(true).unwrap();
        let mut conn = TcpConnection::new(0, laddr, Async::new(raw).unwrap());

        conn.rx_buf.extend_from_slice(&5u32.to_le_bytes());
        conn.rx_buf.extend_from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(conn.has_complete_message(), Some(5));
    }

    #[test]
    fn has_complete_message_zero_length() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let laddr = listener.local_addr().unwrap();
        let raw = std::net::TcpStream::connect(laddr).unwrap();
        raw.set_nonblocking(true).unwrap();
        let mut conn = TcpConnection::new(0, laddr, Async::new(raw).unwrap());

        // Zero-length message — header present, zero payload bytes needed
        conn.rx_buf.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(conn.has_complete_message(), Some(0));
    }

    #[test]
    fn extract_message_removes_frame() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let laddr = listener.local_addr().unwrap();
        let raw = std::net::TcpStream::connect(laddr).unwrap();
        raw.set_nonblocking(true).unwrap();
        let mut conn = TcpConnection::new(0, laddr, Async::new(raw).unwrap());

        // Two back-to-back framed messages: [3, "abc"] [2, "xy"]
        conn.rx_buf.extend_from_slice(&3u32.to_le_bytes());
        conn.rx_buf.extend_from_slice(b"abc");
        conn.rx_buf.extend_from_slice(&2u32.to_le_bytes());
        conn.rx_buf.extend_from_slice(b"xy");

        // Extract first
        assert_eq!(conn.has_complete_message(), Some(3));
        let msg = conn.extract_message(3);
        assert_eq!(msg, b"abc");

        // Second message should now be available
        assert_eq!(conn.has_complete_message(), Some(2));
        let msg = conn.extract_message(2);
        assert_eq!(msg, b"xy");

        // Buffer should be empty
        assert!(conn.rx_buf.is_empty());
        assert!(conn.has_complete_message().is_none());
    }

    // ── TcpInner unit tests ──────────────────────────────────────────────

    fn make_inner_connection(
        inner: &mut TcpInner,
        addr: SocketAddr,
    ) -> (u64, std::net::TcpListener) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let laddr = listener.local_addr().unwrap();
        let raw = std::net::TcpStream::connect(laddr).unwrap();
        raw.set_nonblocking(true).unwrap();
        let stream = Async::new(raw).unwrap();
        let id = inner.add_connection::<8>(stream, addr);
        (id, listener)
    }

    #[test]
    fn add_connection_assigns_unique_ids() {
        let mut inner = TcpInner::new();
        let (id1, _l1) = make_inner_connection(&mut inner, "1.2.3.4:100".parse().unwrap());
        let (id2, _l2) = make_inner_connection(&mut inner, "1.2.3.4:101".parse().unwrap());
        let (id3, _l3) = make_inner_connection(&mut inner, "1.2.3.4:102".parse().unwrap());

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_eq!(inner.connections.len(), 3);
    }

    #[test]
    fn add_connection_evicts_oldest_at_capacity() {
        let mut inner = TcpInner::new();
        let mut _listeners = Vec::new();

        // Fill to capacity (N=2 for this test)
        let listener1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let l1addr = listener1.local_addr().unwrap();
        let raw1 = std::net::TcpStream::connect(l1addr).unwrap();
        raw1.set_nonblocking(true).unwrap();
        let id1 =
            inner.add_connection::<2>(Async::new(raw1).unwrap(), "1.2.3.4:100".parse().unwrap());
        _listeners.push(listener1);

        let listener2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let l2addr = listener2.local_addr().unwrap();
        let raw2 = std::net::TcpStream::connect(l2addr).unwrap();
        raw2.set_nonblocking(true).unwrap();
        let _id2 =
            inner.add_connection::<2>(Async::new(raw2).unwrap(), "1.2.3.4:101".parse().unwrap());
        _listeners.push(listener2);

        assert_eq!(inner.connections.len(), 2);

        // Add a 3rd — should evict the oldest (id1)
        let listener3 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let l3addr = listener3.local_addr().unwrap();
        let raw3 = std::net::TcpStream::connect(l3addr).unwrap();
        raw3.set_nonblocking(true).unwrap();
        let _id3 =
            inner.add_connection::<2>(Async::new(raw3).unwrap(), "1.2.3.4:102".parse().unwrap());
        _listeners.push(listener3);

        assert_eq!(inner.connections.len(), 2);
        assert!(inner
            .find_connection_exact(&"1.2.3.4:100".parse().unwrap(), id1)
            .is_none());
    }

    #[test]
    fn find_connection_exact_matches_both_addr_and_id() {
        let mut inner = TcpInner::new();
        let addr: SocketAddr = "1.2.3.4:100".parse().unwrap();
        let (id1, _l1) = make_inner_connection(&mut inner, addr);

        // Correct addr + id
        assert!(inner.find_connection_exact(&addr, id1).is_some());
        // Correct addr, wrong id
        assert!(inner.find_connection_exact(&addr, id1 + 999).is_none());
        // Wrong addr, correct id
        assert!(inner
            .find_connection_exact(&"5.6.7.8:200".parse().unwrap(), id1)
            .is_none());
    }

    #[test]
    fn remove_connection_drops_partial_buffer() {
        let mut inner = TcpInner::new();
        let addr: SocketAddr = "1.2.3.4:100".parse().unwrap();
        let (id, _l) = make_inner_connection(&mut inner, addr);

        // Simulate partial data in the buffer
        let idx = inner.find_connection_exact(&addr, id).unwrap();
        inner.connections[idx]
            .rx_buf
            .extend_from_slice(&[0x05, 0x00, 0x01]); // partial: header says 5 bytes, only 1 present

        inner.remove_connection(idx);
        assert!(inner.connections.is_empty());
    }

    #[test]
    fn find_ready_connection_round_robin() {
        let mut inner = TcpInner::new();

        let addr_a: SocketAddr = "1.2.3.4:100".parse().unwrap();
        let addr_b: SocketAddr = "1.2.3.4:101".parse().unwrap();
        let (_id_a, _la) = make_inner_connection(&mut inner, addr_a);
        let (_id_b, _lb) = make_inner_connection(&mut inner, addr_b);

        // Put a complete message in both connections
        inner.connections[0]
            .rx_buf
            .extend_from_slice(&3u32.to_le_bytes());
        inner.connections[0].rx_buf.extend_from_slice(b"aaa");
        inner.connections[1]
            .rx_buf
            .extend_from_slice(&3u32.to_le_bytes());
        inner.connections[1].rx_buf.extend_from_slice(b"bbb");

        // poll_index = 0 → should pick index 0
        inner.poll_index = 0;
        assert_eq!(inner.find_ready_connection(), Some(0));

        // poll_index = 1 → should pick index 1
        inner.poll_index = 1;
        assert_eq!(inner.find_ready_connection(), Some(1));
    }

    // ── Integration tests (TcpNetwork) ───────────────────────────────────

    #[test]
    fn send_and_receive_single_message() {
        block_on(async {
            let listener = ephemeral_listener();
            let addr = local_addr(&listener);
            let tcp = TcpNetwork::<8>::new(listener);

            // Spawn a "client" that connects and sends a framed message
            let client = std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                send_framed_raw(&mut stream, b"hello matter");
                stream
            });

            let mut buf = [0u8; 256];
            let net: &TcpNetwork<8> = &tcp;
            let (len, from) = NetworkReceive::recv_from(&mut { net }, &mut buf)
                .await
                .unwrap();

            assert_eq!(&buf[..len], b"hello matter");
            assert!(from.is_tcp());

            let _stream = client.join().unwrap();
        });
    }

    #[test]
    fn send_and_receive_multiple_messages_same_connection() {
        block_on(async {
            let listener = ephemeral_listener();
            let addr = local_addr(&listener);
            let tcp = TcpNetwork::<8>::new(listener);

            let client = std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                send_framed_raw(&mut stream, b"msg1");
                send_framed_raw(&mut stream, b"msg2");
                send_framed_raw(&mut stream, b"msg3");
                stream
            });

            let net: &TcpNetwork<8> = &tcp;
            let mut buf = [0u8; 256];

            let (len, _) = NetworkReceive::recv_from(&mut { net }, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf[..len], b"msg1");

            let (len, _) = NetworkReceive::recv_from(&mut { net }, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf[..len], b"msg2");

            let (len, _) = NetworkReceive::recv_from(&mut { net }, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf[..len], b"msg3");

            let _stream = client.join().unwrap();
        });
    }

    #[test]
    fn send_to_creates_connection_and_delivers() {
        block_on(async {
            // Set up a "server" listener that the TcpNetwork will connect to
            let server_listener = ephemeral_listener();
            let server_addr = local_addr(&server_listener);

            let our_listener = ephemeral_listener();
            let tcp = TcpNetwork::<8>::new(our_listener);
            let net: &TcpNetwork<8> = &tcp;

            // Send via the NetworkSend trait
            NetworkSend::send_to(&mut { net }, b"outgoing", Address::Tcp(server_addr))
                .await
                .unwrap();

            // Accept the connection on the server side and read the framed message
            let (stream, _) = server_listener.accept().await.unwrap();
            // Read synchronously from the raw stream
            let raw = stream.into_inner().unwrap();
            raw.set_nonblocking(false).unwrap();
            let mut reader = std::io::BufReader::new(raw);
            let mut hdr = [0u8; 4];
            std::io::Read::read_exact(&mut reader, &mut hdr).unwrap();
            let msg_len = u32::from_le_bytes(hdr) as usize;
            let mut payload = vec![0u8; msg_len];
            std::io::Read::read_exact(&mut reader, &mut payload).unwrap();

            assert_eq!(payload, b"outgoing");
        });
    }

    #[test]
    fn recv_from_returns_tcp_address() {
        block_on(async {
            let listener = ephemeral_listener();
            let addr = local_addr(&listener);
            let tcp = TcpNetwork::<8>::new(listener);

            let client = std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                send_framed_raw(&mut stream, b"x");
                stream
            });

            let net: &TcpNetwork<8> = &tcp;
            let mut buf = [0u8; 256];
            let (_, from) = NetworkReceive::recv_from(&mut { net }, &mut buf)
                .await
                .unwrap();

            match from {
                Address::Tcp(sa) => {
                    // The remote address should be localhost
                    assert!(sa.ip().is_loopback());
                }
                other => panic!("Expected Address::Tcp, got {:?}", other),
            }

            let _stream = client.join().unwrap();
        });
    }

    #[test]
    fn multiple_clients_multiplexed() {
        block_on(async {
            let listener = ephemeral_listener();
            let addr = local_addr(&listener);
            let tcp = TcpNetwork::<8>::new(listener);

            // Two clients connect and each sends a message
            let c1 = std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                send_framed_raw(&mut stream, b"client1");
                stream
            });

            let c2 = std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                send_framed_raw(&mut stream, b"client2");
                stream
            });

            let net: &TcpNetwork<8> = &tcp;
            let mut buf = [0u8; 256];

            let mut messages = Vec::new();
            for _ in 0..2 {
                let (len, _) = NetworkReceive::recv_from(&mut { net }, &mut buf)
                    .await
                    .unwrap();
                messages.push(buf[..len].to_vec());
            }

            messages.sort();
            assert_eq!(messages, vec![b"client1".to_vec(), b"client2".to_vec()]);

            let _s1 = c1.join().unwrap();
            let _s2 = c2.join().unwrap();
        });
    }

    #[test]
    fn message_too_large_for_buffer_returns_no_space() {
        block_on(async {
            let listener = ephemeral_listener();
            let addr = local_addr(&listener);
            let tcp = TcpNetwork::<8>::new(listener);

            let client = std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                // Send a 100-byte message
                let payload = vec![0xAB; 100];
                send_framed_raw(&mut stream, &payload);
                stream
            });

            let net: &TcpNetwork<8> = &tcp;
            // Provide only a 10-byte buffer
            let mut buf = [0u8; 10];
            let result = NetworkReceive::recv_from(&mut { net }, &mut buf).await;

            assert!(result.is_err());

            let _stream = client.join().unwrap();
        });
    }

    #[test]
    fn conn_pool_eviction_at_capacity() {
        block_on(async {
            let listener = ephemeral_listener();
            let addr = local_addr(&listener);
            // Pool of size 2
            let tcp = TcpNetwork::<2>::new(listener);

            // Connect 3 clients — the first should get evicted
            let mut streams = Vec::new();
            for _ in 0..3 {
                let c = std::thread::spawn(move || {
                    let mut stream = std::net::TcpStream::connect(addr).unwrap();
                    send_framed_raw(&mut stream, b"hi");
                    stream
                });
                streams.push(c);
            }

            let net: &TcpNetwork<2> = &tcp;
            let mut buf = [0u8; 256];

            // Accept all three; pool has size 2 so oldest is evicted
            // We should be able to receive from the surviving connections
            let mut received = 0;
            for _ in 0..3 {
                // Use wait_available + recv_from
                if NetworkReceive::wait_available(&mut { net }).await.is_ok()
                    && NetworkReceive::recv_from(&mut { net }, &mut buf)
                        .await
                        .is_ok()
                {
                    received += 1;
                }
            }

            // At least 2 should succeed (the surviving connections)
            assert!(
                received >= 2,
                "Expected at least 2 messages, got {received}"
            );

            for c in streams {
                let _s = c.join().unwrap();
            }
        });
    }

    #[test]
    fn framing_4_byte_le_prefix() {
        // Test that the framing encodes a 4-byte LE prefix correctly
        // by sending via TcpNetwork and verifying the raw bytes on the wire.
        block_on(async {
            let server_listener = ephemeral_listener();
            let server_addr = local_addr(&server_listener);

            let our_listener = ephemeral_listener();
            let tcp = TcpNetwork::<8>::new(our_listener);
            let net: &TcpNetwork<8> = &tcp;

            // Send a 300-byte payload (length > 255 to test multiple LE bytes)
            let payload = vec![0x42; 300];
            NetworkSend::send_to(&mut { net }, &payload, Address::Tcp(server_addr))
                .await
                .unwrap();

            let (stream, _) = server_listener.accept().await.unwrap();
            let raw = stream.into_inner().unwrap();
            raw.set_nonblocking(false).unwrap();

            let mut hdr = [0u8; 4];
            std::io::Read::read_exact(&mut &raw, &mut hdr).unwrap();
            let wire_len = u32::from_le_bytes(hdr);
            assert_eq!(wire_len, 300);

            let mut body = vec![0u8; 300];
            std::io::Read::read_exact(&mut &raw, &mut body).unwrap();
            assert_eq!(body, payload);
        });
    }

    #[test]
    fn send_to_wrong_address_type_fails() {
        block_on(async {
            let listener = ephemeral_listener();
            let tcp = TcpNetwork::<8>::new(listener);
            let net: &TcpNetwork<8> = &tcp;

            // Sending to a UDP address should fail
            let result = NetworkSend::send_to(
                &mut { net },
                b"data",
                Address::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999))),
            )
            .await;

            assert!(result.is_err());
        });
    }

    #[test]
    fn back_to_back_frames_in_single_tcp_write() {
        // Send two framed messages in a single TCP write to test that the
        // de-framing logic correctly separates them.
        block_on(async {
            let listener = ephemeral_listener();
            let addr = local_addr(&listener);
            let tcp = TcpNetwork::<8>::new(listener);

            let client = std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                // Build two framed messages into a single buffer and write at once
                let mut wire = Vec::new();
                wire.extend_from_slice(&4u32.to_le_bytes());
                wire.extend_from_slice(b"aaaa");
                wire.extend_from_slice(&3u32.to_le_bytes());
                wire.extend_from_slice(b"bbb");
                stream.write_all(&wire).unwrap();
                stream.flush().unwrap();
                stream
            });

            let net: &TcpNetwork<8> = &tcp;
            let mut buf = [0u8; 256];

            let (len1, _) = NetworkReceive::recv_from(&mut { net }, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf[..len1], b"aaaa");

            let (len2, _) = NetworkReceive::recv_from(&mut { net }, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf[..len2], b"bbb");

            let _stream = client.join().unwrap();
        });
    }

    #[test]
    fn zero_length_message() {
        block_on(async {
            let listener = ephemeral_listener();
            let addr = local_addr(&listener);
            let tcp = TcpNetwork::<8>::new(listener);

            let client = std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                // Send a zero-length framed message
                send_framed_raw(&mut stream, b"");
                // Follow it with a real message to confirm the stream is still usable
                send_framed_raw(&mut stream, b"after-empty");
                stream
            });

            let net: &TcpNetwork<8> = &tcp;
            let mut buf = [0u8; 256];

            let (len, _) = NetworkReceive::recv_from(&mut { net }, &mut buf)
                .await
                .unwrap();
            assert_eq!(len, 0);

            let (len, _) = NetworkReceive::recv_from(&mut { net }, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf[..len], b"after-empty");

            let _stream = client.join().unwrap();
        });
    }

    #[test]
    fn connection_closed_by_peer_is_handled() {
        block_on(async {
            let listener = ephemeral_listener();
            let addr = local_addr(&listener);
            let tcp = TcpNetwork::<8>::new(listener);
            let net: &TcpNetwork<8> = &tcp;

            // Client connects and immediately drops (closes the connection)
            let client = std::thread::spawn(move || {
                let stream = std::net::TcpStream::connect(addr).unwrap();
                // Let the connection be accepted, then drop it
                std::thread::sleep(std::time::Duration::from_millis(50));
                drop(stream);
            });
            client.join().unwrap();

            // After the client closes, another client sends a real message
            let client2 = std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                // Small delay to let the server process the dead connection
                std::thread::sleep(std::time::Duration::from_millis(50));
                send_framed_raw(&mut stream, b"alive");
                stream
            });

            let mut buf = [0u8; 256];
            let (len, _) = NetworkReceive::recv_from(&mut { net }, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf[..len], b"alive");

            let _stream = client2.join().unwrap();
        });
    }

    #[test]
    fn ensure_connected_reuses_existing_connection() {
        block_on(async {
            let server_listener = ephemeral_listener();
            let server_addr = local_addr(&server_listener);

            let our_listener = ephemeral_listener();
            let tcp = TcpNetwork::<8>::new(our_listener);

            let id1 = tcp.ensure_connected(server_addr).await.unwrap();
            let id2 = tcp.ensure_connected(server_addr).await.unwrap();

            // Same connection should be reused, so same conn_id
            assert_eq!(id1, id2);

            // Pool should have exactly one connection
            tcp.inner.lock(|inner| {
                assert_eq!(inner.borrow().connections.len(), 1);
            });
        });
    }

    #[test]
    fn send_framed_encodes_correctly() {
        block_on(async {
            let server_listener = ephemeral_listener();
            let server_addr = local_addr(&server_listener);

            let our_listener = ephemeral_listener();
            let tcp = TcpNetwork::<8>::new(our_listener);

            let conn_id = tcp.ensure_connected(server_addr).await.unwrap();
            tcp.send_framed_to(server_addr, conn_id, b"test")
                .await
                .unwrap();

            // Read raw bytes from the server side
            let (stream, _) = server_listener.accept().await.unwrap();
            let raw = stream.into_inner().unwrap();
            raw.set_nonblocking(false).unwrap();

            let mut hdr = [0u8; 4];
            std::io::Read::read_exact(&mut &raw, &mut hdr).unwrap();
            assert_eq!(u32::from_le_bytes(hdr), 4); // "test" is 4 bytes

            let mut body = [0u8; 4];
            std::io::Read::read_exact(&mut &raw, &mut body).unwrap();
            assert_eq!(&body, b"test");
        });
    }

    #[test]
    fn bidirectional_communication() {
        // Test that the same TcpNetwork can send and receive
        block_on(async {
            let listener_a = ephemeral_listener();
            let addr_a = local_addr(&listener_a);
            let tcp_a = TcpNetwork::<8>::new(listener_a);

            let listener_b = ephemeral_listener();
            let addr_b = local_addr(&listener_b);
            let tcp_b = TcpNetwork::<8>::new(listener_b);

            let net_a: &TcpNetwork<8> = &tcp_a;
            let net_b: &TcpNetwork<8> = &tcp_b;

            // A sends to B
            NetworkSend::send_to(&mut { net_a }, b"a-to-b", Address::Tcp(addr_b))
                .await
                .unwrap();

            let mut buf = [0u8; 256];
            let (len, _) = NetworkReceive::recv_from(&mut { net_b }, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf[..len], b"a-to-b");

            // B sends to A
            NetworkSend::send_to(&mut { net_b }, b"b-to-a", Address::Tcp(addr_a))
                .await
                .unwrap();

            let (len, _) = NetworkReceive::recv_from(&mut { net_a }, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf[..len], b"b-to-a");
        });
    }

    #[test]
    fn try_read_all_removes_dead_connections() {
        let mut inner = TcpInner::new();
        let addr: SocketAddr = "1.2.3.4:100".parse().unwrap();

        // Create a connection whose peer has been shut down
        let peer_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer_listener.local_addr().unwrap();
        let raw = std::net::TcpStream::connect(peer_addr).unwrap();
        raw.set_nonblocking(true).unwrap();
        // Accept and immediately drop to simulate dead peer
        let (accepted, _) = peer_listener.accept().unwrap();
        accepted.shutdown(std::net::Shutdown::Both).unwrap();
        drop(accepted);
        drop(peer_listener);

        // Give OS time to propagate the RST/FIN
        std::thread::sleep(std::time::Duration::from_millis(50));

        inner.add_connection::<8>(Async::new(raw).unwrap(), addr);
        assert_eq!(inner.connections.len(), 1);

        // try_read_all should detect the dead connection and remove it
        let _ = inner.try_read_all();
        assert_eq!(inner.connections.len(), 0);
    }

    #[test]
    fn try_read_nonblocking_rejects_oversized_buffer() {
        // Unit test: verify that try_read_nonblocking returns an error when
        // the receive buffer exceeds MAX_RX_BUF_SIZE (DoS protection).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let laddr = listener.local_addr().unwrap();
        let raw = std::net::TcpStream::connect(laddr).unwrap();
        raw.set_nonblocking(true).unwrap();
        let mut conn = TcpConnection::new(0, laddr, Async::new(raw).unwrap());

        // Manually fill the buffer to exactly MAX_RX_BUF_SIZE
        conn.rx_buf.resize(MAX_RX_BUF_SIZE, 0);

        // Next read attempt should fail with OutOfMemory error
        let result = conn.try_read_nonblocking();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::OutOfMemory);
    }
}
