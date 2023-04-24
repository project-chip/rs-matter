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

use crate::error::*;
use log::{info, warn};
use smol::net::{Ipv6Addr, UdpSocket};

use super::network::Address;

// We could get rid of the smol here, but keeping it around in case we have to process
// any other events in this thread's context
pub struct UdpListener {
    socket: UdpSocket,
}

// Currently matches with the one in connectedhomeip repo
pub const MAX_RX_BUF_SIZE: usize = 1583;

/* The Matter Port */
pub const MATTER_PORT: u16 = 5540;

impl UdpListener {
    pub async fn new() -> Result<UdpListener, Error> {
        let listener = UdpListener {
            socket: UdpSocket::bind((Ipv6Addr::UNSPECIFIED, MATTER_PORT)).await?,
        };

        info!(
            "Listening on {:?} port {}",
            Ipv6Addr::UNSPECIFIED,
            MATTER_PORT
        );

        Ok(listener)
    }

    pub async fn recv(&self, in_buf: &mut [u8]) -> Result<(usize, Address), Error> {
        info!("Waiting for incoming packets");

        let (size, addr) = self.socket.recv_from(in_buf).await.map_err(|e| {
            warn!("Error on the network: {:?}", e);
            Error::Network
        })?;

        info!("Got packet: {:?} from addr {:?}", in_buf, addr);

        Ok((size, Address::Udp(addr)))
    }

    pub async fn send(&self, addr: Address, out_buf: &[u8]) -> Result<usize, Error> {
        match addr {
            Address::Udp(addr) => {
                let len = self.socket.send_to(out_buf, addr).await.map_err(|e| {
                    warn!("Error on the network: {:?}", e);
                    Error::Network
                })?;

                info!(
                    "Send packet: {:?} ({}/{}) to addr {:?}",
                    out_buf,
                    out_buf.len(),
                    len,
                    addr
                );

                Ok(len)
            }
        }
    }
}
