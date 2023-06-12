/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

#[cfg(feature = "std")]
pub use smol_udp::*;

#[cfg(not(feature = "std"))]
pub use dummy_udp::*;

#[cfg(feature = "std")]
mod smol_udp {
    use crate::error::*;
    use log::{debug, info, warn};
    use smol::net::UdpSocket;

    use crate::transport::network::{IpAddr, Ipv4Addr, SocketAddr};

    pub struct UdpListener {
        socket: UdpSocket,
    }

    impl UdpListener {
        pub async fn new(addr: SocketAddr) -> Result<UdpListener, Error> {
            let listener = UdpListener {
                socket: UdpSocket::bind((addr.ip(), addr.port())).await?,
            };

            info!("Listening on {:?}", addr);

            Ok(listener)
        }

        pub async fn join_multicast(&mut self, ip_addr: IpAddr) -> Result<(), Error> {
            match ip_addr {
                IpAddr::V4(ip_addr) => self
                    .socket
                    .join_multicast_v4(ip_addr, Ipv4Addr::UNSPECIFIED)?,
                IpAddr::V6(ip_addr) => self.socket.join_multicast_v6(&ip_addr, 0)?,
            }

            Ok(())
        }

        pub async fn recv(&self, in_buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
            let (size, addr) = self.socket.recv_from(in_buf).await.map_err(|e| {
                warn!("Error on the network: {:?}", e);
                ErrorCode::Network
            })?;

            debug!("Got packet {:?} from addr {:?}", &in_buf[..size], addr);

            Ok((size, addr))
        }

        pub async fn send(&self, addr: SocketAddr, out_buf: &[u8]) -> Result<usize, Error> {
            let len = self.socket.send_to(out_buf, addr).await.map_err(|e| {
                warn!("Error on the network: {:?}", e);
                ErrorCode::Network
            })?;

            debug!(
                "Send packet {:?} ({}/{}) to addr {:?}",
                out_buf,
                out_buf.len(),
                len,
                addr
            );

            Ok(len)
        }
    }
}

#[cfg(not(feature = "std"))]
mod dummy_udp {
    use core::future::pending;

    use crate::error::*;
    use log::{debug, info};

    use crate::transport::network::SocketAddr;

    pub struct UdpListener {}

    impl UdpListener {
        pub async fn new(addr: SocketAddr) -> Result<UdpListener, Error> {
            let listener = UdpListener {};

            info!("Pretending to listen on {:?}", addr);

            Ok(listener)
        }

        pub async fn join_multicast(&mut self, ip_addr: IpAddr) -> Result<(), Error> {
            Ok(())
        }

        pub async fn recv(&self, _in_buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
            info!("Pretending to wait for incoming packets (looping forever)");

            pending().await
        }

        pub async fn send(&self, addr: SocketAddr, out_buf: &[u8]) -> Result<usize, Error> {
            debug!(
                "Send packet {:?} ({}/{}) to addr {:?}",
                out_buf,
                out_buf.len(),
                out_buf.len(),
                addr
            );

            Ok(out_buf.len())
        }
    }
}
