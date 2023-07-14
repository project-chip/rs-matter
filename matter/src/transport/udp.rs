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

#[cfg(all(feature = "std", not(feature = "embassy-net")))]
pub use smol_udp::*;

#[cfg(feature = "embassy-net")]
pub use embassy_udp::*;

#[cfg(all(feature = "std", not(feature = "embassy-net")))]
mod smol_udp {
    use crate::error::*;
    use log::{debug, info, warn};
    use smol::net::UdpSocket;

    use crate::transport::network::{
        Ipv4Addr, Ipv6Addr, NetworkStack, NetworkStackDriver, NetworkStackMulticastDriver,
        SocketAddr,
    };

    pub struct UdpBuffers(());

    impl UdpBuffers {
        pub const fn new() -> Self {
            Self(())
        }
    }

    pub struct UdpListener<'a, D>(UdpSocket, &'a NetworkStack<D>)
    where
        D: NetworkStackDriver;

    impl<'a, D> UdpListener<'a, D>
    where
        D: NetworkStackDriver + 'a,
    {
        pub async fn new(
            stack: &'a NetworkStack<D>,
            addr: SocketAddr,
            _buffers: &'a mut UdpBuffers,
        ) -> Result<UdpListener<'a, D>, Error> {
            let listener = UdpListener(UdpSocket::bind((addr.ip(), addr.port())).await?, stack);

            info!("Listening on {:?}", addr);

            Ok(listener)
        }

        pub fn join_multicast_v6(
            &mut self,
            multiaddr: Ipv6Addr,
            interface: u32,
        ) -> Result<(), Error>
        where
            D: NetworkStackMulticastDriver + 'static,
        {
            self.0.join_multicast_v6(&multiaddr, interface)?;

            info!("Joined IPV6 multicast {}/{}", multiaddr, interface);

            Ok(())
        }

        pub fn join_multicast_v4(
            &mut self,
            multiaddr: Ipv4Addr,
            interface: Ipv4Addr,
        ) -> Result<(), Error>
        where
            D: NetworkStackMulticastDriver + 'static,
        {
            #[cfg(not(target_os = "espidf"))]
            self.0.join_multicast_v4(multiaddr, interface)?;

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
                    &mut self.0,
                    esp_idf_sys::IPPROTO_IP,
                    esp_idf_sys::IP_ADD_MEMBERSHIP,
                    mreq,
                )?;
            }

            info!("Joined IP multicast {}/{}", multiaddr, interface);

            Ok(())
        }

        pub async fn recv(&self, in_buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
            let (len, addr) = self.0.recv_from(in_buf).await.map_err(|e| {
                warn!("Error on the network: {:?}", e);
                ErrorCode::Network
            })?;

            debug!("Got packet {:?} from addr {:?}", &in_buf[..len], addr);

            Ok((len, addr))
        }

        pub async fn send(&self, addr: SocketAddr, out_buf: &[u8]) -> Result<usize, Error> {
            let len = self.0.send_to(out_buf, addr).await.map_err(|e| {
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

#[cfg(feature = "embassy-net")]
mod embassy_udp {
    use core::mem::MaybeUninit;

    use embassy_net::udp::{PacketMetadata, UdpSocket};

    use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv6Address};

    use crate::error::*;

    use log::{debug, info, warn};

    use crate::transport::network::{
        IpAddr, Ipv4Addr, Ipv6Addr, NetworkStack, NetworkStackDriver, NetworkStackMulticastDriver,
        SocketAddr,
    };

    const RX_BUF_SIZE: usize = 4096;
    const TX_BUF_SIZE: usize = 4096;

    pub struct UdpBuffers {
        rx_buffer: MaybeUninit<[u8; RX_BUF_SIZE]>,
        tx_buffer: MaybeUninit<[u8; TX_BUF_SIZE]>,
        rx_meta: [PacketMetadata; 16],
        tx_meta: [PacketMetadata; 16],
    }

    impl UdpBuffers {
        pub const fn new() -> Self {
            Self {
                rx_buffer: MaybeUninit::uninit(),
                tx_buffer: MaybeUninit::uninit(),

                rx_meta: [PacketMetadata::EMPTY; 16],
                tx_meta: [PacketMetadata::EMPTY; 16],
            }
        }
    }

    pub struct UdpListener<'a, D>(UdpSocket<'a>, &'a NetworkStack<D>)
    where
        D: NetworkStackDriver;

    impl<'a, D> UdpListener<'a, D>
    where
        D: NetworkStackDriver + 'a,
    {
        pub async fn new(
            stack: &'a NetworkStack<D>,
            addr: SocketAddr,
            buffers: &'a mut UdpBuffers,
        ) -> Result<UdpListener<'a, D>, Error> {
            let mut socket = UdpSocket::new(
                stack,
                &mut buffers.rx_meta,
                unsafe { buffers.rx_buffer.assume_init_mut() },
                &mut buffers.tx_meta,
                unsafe { buffers.tx_buffer.assume_init_mut() },
            );

            socket.bind(addr.port()).map_err(|e| {
                warn!("Error on the network: {:?}", e);
                ErrorCode::Network
            })?;

            info!("Listening on {:?}", addr);

            Ok(UdpListener(socket, stack))
        }

        pub fn join_multicast_v6(
            &mut self,
            multiaddr: Ipv6Addr,
            _interface: u32,
        ) -> Result<(), Error>
        where
            D: NetworkStackMulticastDriver + 'static,
        {
            self.1
                .join_multicast_group(Self::from_ip_addr(IpAddr::V6(multiaddr)))
                .map_err(|e| {
                    warn!("Error on the network: {:?}", e);
                    ErrorCode::Network
                })?;

            info!("Joined IP multicast {}", multiaddr);

            Ok(())
        }

        pub fn join_multicast_v4(
            &mut self,
            multiaddr: Ipv4Addr,
            _interface: Ipv4Addr,
        ) -> Result<(), Error>
        where
            D: NetworkStackMulticastDriver + 'static,
        {
            self.1
                .join_multicast_group(Self::from_ip_addr(IpAddr::V4(multiaddr)))
                .map_err(|e| {
                    warn!("Error on the network: {:?}", e);
                    ErrorCode::Network
                })?;

            info!("Joined IP multicast {}", multiaddr);

            Ok(())
        }

        pub async fn recv(&self, in_buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
            let (len, ep) = self.0.recv_from(in_buf).await.map_err(|e| {
                warn!("Error on the network: {:?}", e);
                ErrorCode::Network
            })?;

            let addr = Self::to_socket_addr(ep);

            debug!("Got packet {:?} from addr {:?}", &in_buf[..len], addr);

            Ok((len, addr))
        }

        pub async fn send(&self, addr: SocketAddr, out_buf: &[u8]) -> Result<usize, Error> {
            self.0
                .send_to(out_buf, Self::from_socket_addr(addr))
                .await
                .map_err(|e| {
                    warn!("Error on the network: {:?}", e);
                    ErrorCode::Network
                })?;

            debug!(
                "Send packet {:?} ({}/{}) to addr {:?}",
                out_buf,
                out_buf.len(),
                out_buf.len(),
                addr
            );

            Ok(out_buf.len())
        }

        fn to_socket_addr(ep: IpEndpoint) -> SocketAddr {
            SocketAddr::new(Self::to_ip_addr(ep.addr), ep.port)
        }

        fn from_socket_addr(addr: SocketAddr) -> IpEndpoint {
            IpEndpoint::new(Self::from_ip_addr(addr.ip()), addr.port())
        }

        fn to_ip_addr(ip: IpAddress) -> IpAddr {
            match ip {
                IpAddress::Ipv4(addr) => IpAddr::V4(Ipv4Addr::from(addr.0)),
                IpAddress::Ipv6(addr) => IpAddr::V6(Ipv6Addr::from(addr.0)),
            }
        }

        fn from_ip_addr(ip: IpAddr) -> IpAddress {
            match ip {
                IpAddr::V4(v4) => IpAddress::Ipv4(Ipv4Address::from_bytes(&v4.octets())),
                IpAddr::V6(v6) => IpAddress::Ipv6(Ipv6Address::from_bytes(&v6.octets())),
            }
        }
    }
}
