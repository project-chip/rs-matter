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

use core::net::SocketAddr;
use core::task::{Context, Poll};

use crate::error::{Error, ErrorCode};
use crate::utils::sync::MaybeSend;
use crate::utils::timers::Duration;

pub mod frame;
pub use frame::{check_frame_slice, encode_frame_header, parse_frame_header, Frame, FRAME_HDR_LEN};

/// An owned TCP listener. Each poll must be non-blocking and register its
/// waker when pending. Returning a socket transfers ownership to the caller.
pub trait NetTcpListener: MaybeSend {
    /// The accepted stream type.
    type Socket: NetTcpSocket;

    /// Accept at most one peer without blocking.
    fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(SocketAddr, Self::Socket), Error>>;
}

/// An owned full-duplex TCP stream.
///
/// Poll methods must register independent read and write wakers when pending.
/// A pending operation must not consume input or write output; the caller may
/// cancel it and resume with a different buffer. Dropping the stream closes it.
pub trait NetTcpSocket: MaybeSend {
    /// Read stream bytes; zero indicates EOF.
    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, Error>>;

    /// Write stream bytes; zero indicates a closed stream.
    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>>;
}

/// Placeholder used by UDP-only drivers' default TCP binding.
pub struct NoTcp;

impl NetTcpListener for NoTcp {
    type Socket = Self;

    fn poll_accept(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(SocketAddr, Self::Socket), Error>> {
        Poll::Pending
    }
}

impl NetTcpSocket for NoTcp {
    fn poll_read(&mut self, _cx: &mut Context<'_>, _buf: &mut [u8]) -> Poll<Result<usize, Error>> {
        Poll::Ready(Err(ErrorCode::NoNetworkInterface.into()))
    }

    fn poll_write(&mut self, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<Result<usize, Error>> {
        Poll::Ready(Err(ErrorCode::NoNetworkInterface.into()))
    }
}

/// Timeouts for Matter TCP transports.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TcpConfig {
    /// Close a stream when neither reading nor writing has made progress for
    /// this duration. Partial headers and stalled peers are subject to it too.
    pub idle_timeout: Duration,
    /// Bound a complete outbound frame write, including time spent queued.
    pub send_timeout: Duration,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            send_timeout: Duration::from_secs(5),
        }
    }
}

pub mod embedded;
pub use embedded::TcpServer;

#[cfg(all(feature = "std", feature = "async-io"))]
pub mod std;

#[cfg(all(feature = "std", feature = "async-io"))]
pub use self::std::{TcpNetwork, DEFAULT_MAX_TCP_CONNECTIONS};
