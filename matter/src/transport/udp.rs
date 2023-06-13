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

    use crate::transport::network::{Ipv4Addr, Ipv6Addr, SocketAddr};

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

        pub fn join_multicast_v6(
            &mut self,
            multiaddr: Ipv6Addr,
            interface: u32,
        ) -> Result<(), Error> {
            self.socket.join_multicast_v6(&multiaddr, interface)?;

            info!("Joined IPV6 multicast {}/{}", multiaddr, interface);

            Ok(())
        }

        pub fn join_multicast_v4(
            &mut self,
            multiaddr: Ipv4Addr,
            interface: Ipv4Addr,
        ) -> Result<(), Error> {
            #[cfg(not(target_os = "espidf"))]
            self.socket.join_multicast_v4(multiaddr, interface)?;

            // join_multicast_v4() is broken for ESP-IDF, most likely due to wrong `ip_mreq` signature in the `libc` crate
            // Note that also most *_multicast_v4 and *_multicast_v6 methods are broken as well in Rust STD for the ESP-IDF
            // due to mismatch w.r.t. sizes (u8 expected but u32 passed to setsockopt() and sometimes the other way around)
            #[cfg(target_os = "espidf")]
            {
                fn esp_setsockopt<T>(
                    socket: &mut UdpSocket,
                    proto: u32,
                    option: u32,
                    value: T,
                ) -> Result<(), Error> {
                    use std::os::fd::AsRawFd;

                    esp_idf_sys::esp!(unsafe {
                        esp_idf_sys::lwip_setsockopt(
                            socket.as_raw_fd(),
                            proto as _,
                            option as _,
                            &value as *const _ as *const _,
                            core::mem::size_of::<T>() as _,
                        )
                    })
                    .map_err(|_| ErrorCode::StdIoError)?;

                    Ok(())
                }

                let mreq = esp_idf_sys::ip_mreq {
                    imr_multiaddr: esp_idf_sys::in_addr {
                        s_addr: u32::from_ne_bytes(multiaddr.octets()),
                    },
                    imr_interface: esp_idf_sys::in_addr {
                        s_addr: u32::from_ne_bytes(interface.octets()),
                    },
                };

                esp_setsockopt(
                    &mut self.socket,
                    esp_idf_sys::IPPROTO_IP,
                    esp_idf_sys::IP_ADD_MEMBERSHIP,
                    mreq,
                )?;
            }

            info!("Joined IP multicast {}/{}", multiaddr, interface);

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

    use crate::transport::network::{Ipv4Addr, Ipv6Addr, SocketAddr};

    pub struct UdpListener {}

    impl UdpListener {
        pub async fn new(addr: SocketAddr) -> Result<UdpListener, Error> {
            let listener = UdpListener {};

            info!("Pretending to listen on {:?}", addr);

            Ok(listener)
        }

        pub fn join_multicast_v6(
            &mut self,
            multiaddr: Ipv6Addr,
            interface: u32,
        ) -> Result<(), Error> {
            info!(
                "Pretending to join IPV6 multicast {}/{}",
                multiaddr, interface
            );

            Ok(())
        }

        pub fn join_multicast_v4(
            &mut self,
            multiaddr: Ipv4Addr,
            interface: Ipv4Addr,
        ) -> Result<(), Error> {
            info!(
                "Pretending to join IP multicast {}/{}",
                multiaddr, interface
            );

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
