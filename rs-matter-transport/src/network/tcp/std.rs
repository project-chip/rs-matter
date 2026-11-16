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

//! `async-io` implementations of [`TcpNetworkSockets`] and [`TcpNetworkSocket`].

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};

use async_io::Async;
use socket2::{SockRef, TcpKeepalive};

use crate::error::Error;

use super::{TcpKeepAlive, TcpNetworkRead, TcpNetworkSocket, TcpNetworkSockets, TcpNetworkWrite};

impl TcpNetworkSockets for Async<TcpListener> {
    type Socket = Async<TcpStream>;

    async fn accept(&self) -> Result<(SocketAddr, Self::Socket), Error> {
        let (stream, addr) = Async::<TcpListener>::accept(self).await?;
        let _ = stream.get_ref().set_nodelay(true);
        Ok((addr, stream))
    }

    async fn connect(&self, addr: SocketAddr) -> Result<Self::Socket, Error> {
        let stream = Async::<TcpStream>::connect(addr).await?;
        let _ = stream.get_ref().set_nodelay(true);
        Ok(stream)
    }
}

/// Readable half of an [`Async<TcpStream>`].
pub struct AsyncTcpRead<'a>(&'a Async<TcpStream>);

impl TcpNetworkRead for AsyncTcpRead<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.0
            .read_with(|mut stream| stream.read(buf))
            .await
            .map_err(Into::into)
    }
}

/// Writable half of an [`Async<TcpStream>`].
pub struct AsyncTcpWrite<'a>(&'a Async<TcpStream>);

impl TcpNetworkWrite for AsyncTcpWrite<'_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.0
            .write_with(|mut stream| stream.write(buf))
            .await
            .map_err(Into::into)
    }
}

impl TcpNetworkSocket for Async<TcpStream> {
    type Read<'a> = AsyncTcpRead<'a>;
    type Write<'a> = AsyncTcpWrite<'a>;

    fn split(&mut self) -> (Self::Read<'_>, Self::Write<'_>) {
        (AsyncTcpRead(self), AsyncTcpWrite(self))
    }

    async fn close(&mut self) -> Result<(), Error> {
        let _ = self.get_ref().shutdown(Shutdown::Both);
        Ok(())
    }

    fn set_keep_alive(&mut self, keep_alive: Option<TcpKeepAlive>) -> Result<(), Error> {
        let sock = SockRef::from(self.get_ref());
        match keep_alive {
            Some(ka) => {
                let params = TcpKeepalive::new()
                    .with_time(core::time::Duration::from_millis(ka.idle.as_millis()))
                    .with_interval(core::time::Duration::from_millis(ka.interval.as_millis()));
                #[cfg(unix)]
                let params = params.with_retries(ka.retries);
                sock.set_tcp_keepalive(&params)?;
            }
            None => {
                sock.set_keepalive(false)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use core::pin::pin;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use futures_lite::future::block_on;
    use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::network::tcp::{
        encode_frame_header, TcpConfig, TcpNetwork, TcpNetworkBuffers, FRAME_HDR_LEN,
    };
    use crate::network::{Address, NetworkReceive, NetworkSend};
    use crate::plain_hdr::PlainHdr;
    use crate::proto_hdr::ProtoHdr;
    use crate::sc::{GeneralCode, OpCode, StatusReport, PROTO_ID_SECURE_CHANNEL};
    use crate::utils::futures::{select, Either};
    use crate::utils::storage::ParseBuf;
    use crate::utils::timers::{with_timeout, Duration};

    fn ephemeral_listener() -> Async<TcpListener> {
        Async::<TcpListener>::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .unwrap()
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn async_io_send_and_receive_single_message() {
        block_on(async {
            let listener = ephemeral_listener();
            let addr = listener.get_ref().local_addr().unwrap();
            let buffers = TcpNetworkBuffers::<256>::new();
            let net = TcpNetwork::new(listener, &buffers, &TcpConfig::default());

            let runner = pin!(net.run());
            let test = pin!(async {
                let mut client = Async::<TcpStream>::connect(addr).await.unwrap();
                let payload = b"hello matter tcp";
                let hdr = encode_frame_header(payload.len()).unwrap();
                client.write_all(&hdr).await.unwrap();
                client.write_all(payload).await.unwrap();

                let mut buf = [0u8; 64];
                let (len, peer) = with_timeout(
                    Duration::from_secs(2),
                    NetworkReceive::recv_from(&mut &net, &mut buf),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(&buf[..len], payload);

                NetworkSend::send_to(&mut &net, b"ack", peer).await.unwrap();

                let mut reply = [0u8; 7];
                with_timeout(Duration::from_secs(2), client.read_exact(&mut reply))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&reply, b"\x03\0\0\0ack");
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn async_io_outbound_connect_and_exchange() {
        block_on(async {
            let remote = ephemeral_listener();
            let remote_addr = remote.get_ref().local_addr().unwrap();

            let local = ephemeral_listener();
            let buffers = TcpNetworkBuffers::<256>::new();
            let net = TcpNetwork::new(local, &buffers, &TcpConfig::default());

            let runner = pin!(net.run());
            let test = pin!(async {
                NetworkSend::send_to(&mut &net, b"outbound", Address::Tcp(remote_addr))
                    .await
                    .unwrap();

                let (mut peer, _) = with_timeout(Duration::from_secs(2), remote.accept())
                    .await
                    .unwrap()
                    .unwrap();

                let mut frame = [0u8; 12];
                with_timeout(Duration::from_secs(2), peer.read_exact(&mut frame))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&frame[..4], &8u32.to_le_bytes());
                assert_eq!(&frame[4..], b"outbound");

                peer.write_all(b"\x05\0\0\0reply").await.unwrap();

                let mut buf = [0u8; 64];
                let (len, from) = with_timeout(
                    Duration::from_secs(2),
                    NetworkReceive::recv_from(&mut &net, &mut buf),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(&buf[..len], b"reply");
                assert_eq!(from, Address::Tcp(remote_addr));
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn async_io_oversized_frame_sends_message_too_large() {
        block_on(async {
            let listener = ephemeral_listener();
            let addr = listener.get_ref().local_addr().unwrap();
            let buffers = TcpNetworkBuffers::<64>::new();
            let net = TcpNetwork::new(listener, &buffers, &TcpConfig::default());

            let runner = pin!(net.run());
            let test = pin!(async {
                let mut client = Async::<TcpStream>::connect(addr).await.unwrap();
                client.write_all(&100u32.to_le_bytes()).await.unwrap();

                let mut hdr = [0u8; FRAME_HDR_LEN];
                with_timeout(Duration::from_secs(2), client.read_exact(&mut hdr))
                    .await
                    .unwrap()
                    .unwrap();
                let len = u32::from_le_bytes(hdr) as usize;
                let mut payload = vec![0u8; len];
                with_timeout(Duration::from_secs(2), client.read_exact(&mut payload))
                    .await
                    .unwrap()
                    .unwrap();

                let mut pb = ParseBuf::new(&mut payload);
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

                // Peer should close after sending the StatusReport.
                let mut eof = [0u8; 1];
                let n = with_timeout(Duration::from_secs(2), client.read(&mut eof))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(n, 0);
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn async_io_keep_alive_configuration() {
        block_on(async {
            let listener = ephemeral_listener();
            let addr = listener.get_ref().local_addr().unwrap();
            let mut client = Async::<TcpStream>::connect(addr).await.unwrap();
            let (mut server, _) = listener.accept().await.unwrap();

            server
                .set_keep_alive(Some(TcpKeepAlive::default()))
                .unwrap();
            server.set_keep_alive(None).unwrap();

            TcpNetworkSocket::close(&mut client).await.unwrap();
            TcpNetworkSocket::close(&mut server).await.unwrap();
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn async_io_back_to_back_frames_in_single_write() {
        block_on(async {
            let listener = ephemeral_listener();
            let addr = listener.get_ref().local_addr().unwrap();
            let buffers = TcpNetworkBuffers::<256>::new();
            let net = TcpNetwork::new(listener, &buffers, &TcpConfig::default());

            let runner = pin!(net.run());
            let test = pin!(async {
                let mut client = Async::<TcpStream>::connect(addr).await.unwrap();
                let mut batch = Vec::new();
                batch.extend_from_slice(&3u32.to_le_bytes());
                batch.extend_from_slice(b"one");
                batch.extend_from_slice(&3u32.to_le_bytes());
                batch.extend_from_slice(b"two");
                client.write_all(&batch).await.unwrap();

                let mut buf = [0u8; 32];
                let (len1, _) = with_timeout(
                    Duration::from_secs(2),
                    NetworkReceive::recv_from(&mut &net, &mut buf),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(&buf[..len1], b"one");

                let (len2, _) = with_timeout(
                    Duration::from_secs(2),
                    NetworkReceive::recv_from(&mut &net, &mut buf),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(&buf[..len2], b"two");
            });

            match select(runner, test).await {
                Either::First(r) => panic!("runner exited unexpectedly: {:?}", r),
                Either::Second(()) => {}
            }
        });
    }
}
