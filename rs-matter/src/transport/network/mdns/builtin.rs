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

//! The built-in mDNS implementation of `rs-matter`.
//!
//! Can be used on any OS / platform, as long as the platform-specific mDNS implementation
//! (if there is one) is stopped and not running on the mDNS port 5353.

use core::net::IpAddr;
use core::pin::pin;

use embassy_futures::select::select;
use embassy_time::{Duration, Timer};

use rand_core::RngCore;

use crate::crypto::Crypto;
use crate::error::{Error, ErrorCode};
use crate::fabric::MAX_FABRICS;
use crate::transport::network::mdns::{
    MDNS_IPV4_BROADCAST_ADDR, MDNS_IPV6_BROADCAST_ADDR, MDNS_PORT,
};
use crate::transport::network::{
    Address, Ipv4Addr, NetworkReceive, NetworkSend, SocketAddr, SocketAddrV4, SocketAddrV6,
};
use crate::utils::select::Coalesce;
use crate::utils::storage::pooled::BufferAccess;
use crate::utils::sync::IfMutex;
use crate::{Matter, MatterMdnsService};

use self::proto::Services;
use super::Service;

pub use proto::Host;
pub use querier::discover_commissionable;

mod proto;
pub mod querier;

/// A built-in mDNS responder for Matter, utilizing a custom mDNS protocol implementation.
///
/// `no_std` and `no-alloc` and thus suitable for MCUs as well when there is no running mDNS service as part of the OS,
pub struct BuiltinMdnsResponder<'a, C> {
    matter: &'a Matter<'a>,
    crypto: C,
}

impl<'a, C> BuiltinMdnsResponder<'a, C>
where
    C: Crypto,
{
    /// Create a new instance of the built-in mDNS responder.
    ///
    /// # Arguments
    /// * `matter` - A reference to the Matter instance that this responder will use.
    pub const fn new(matter: &'a Matter<'a>, crypto: C) -> Self {
        Self { matter, crypto }
    }

    /// Run the mDNS responder.
    ///
    /// # Arguments
    /// * `rand` - An object implementing the `RngCore` trait for generating random numbers.
    /// * `send` - An object implementing the `NetworkSend` trait for sending mDNS packets.
    /// * `recv` - An object implementing the `NetworkReceive` trait for receiving mDNS packets.
    /// * `host` - A reference to the `Host` instance that provides basic mDNS host information.
    /// * `ipv4_interface` - An optional IPv4 address for the interface to use for mDNS broadcasts.
    /// * `ipv6_interface` - An optional IPv6 interface index for the interface to use for mDNS broadcasts.
    #[allow(clippy::too_many_arguments)]
    pub async fn run<S, R>(
        &self,
        send: S,
        recv: R,
        host: &Host<'_>,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
    {
        let send = IfMutex::new(send);

        let mut broadcast = pin!(self.broadcast(&send, host, ipv4_interface, ipv6_interface));
        let mut respond = pin!(self.respond(&send, recv, host, ipv4_interface, ipv6_interface));

        select(&mut broadcast, &mut respond).coalesce().await
    }

    async fn broadcast<S>(
        &self,
        send: &IfMutex<S>,
        host: &Host<'_>,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
    {
        // Track the set of services published in the previous broadcast
        // so we can emit Goodbye records (TTL=0) for any that have just
        // been retired (RFC 6762 §10.1). Without that, OS-level mDNS
        // caches (avahi, mDNSResponder, ...) keep stale instance names
        // around for the full TTL window — TC-SC-4.1 fails on the
        // resulting duplicate `_CM._sub` PTR records.
        //
        // Capacity = `MAX_FABRICS` commissioned services + 1
        // commissionable window.
        const MAX_TRACKED_SERVICES: usize = MAX_FABRICS + 1;
        let mut last: heapless::Vec<MatterMdnsService, MAX_TRACKED_SERVICES> = heapless::Vec::new();

        loop {
            let mut notification = pin!(self.matter.wait_mdns());
            let mut timeout = pin!(Timer::after(Duration::from_secs(30)));

            select(&mut notification, &mut timeout).await;

            // Snapshot the services that should be live now.
            let mut current: heapless::Vec<MatterMdnsService, MAX_TRACKED_SERVICES> =
                heapless::Vec::new();
            self.matter.mdns_services(|s| {
                current
                    .push(s)
                    .map_err(|_| Error::from(ErrorCode::ResourceExhausted))
            })?;

            // Anything in `last` that's no longer in `current` was just
            // retired and needs a Goodbye broadcast.
            let mut removed: heapless::Vec<MatterMdnsService, MAX_TRACKED_SERVICES> =
                heapless::Vec::new();
            for prev in &last {
                if !current.iter().any(|c| c == prev) {
                    let _ = removed.push(prev.clone());
                }
            }

            for addr in Iterator::chain(
                ipv4_interface
                    .map(|_| SocketAddr::V4(SocketAddrV4::new(MDNS_IPV4_BROADCAST_ADDR, MDNS_PORT)))
                    .into_iter(),
                ipv6_interface.map(|interface| {
                    SocketAddr::V6(SocketAddrV6::new(
                        MDNS_IPV6_BROADCAST_ADDR,
                        MDNS_PORT,
                        0,
                        interface,
                    ))
                }),
            ) {
                let buffer = self.matter.transport_tx_buffer();

                if !removed.is_empty() {
                    let mut buf = buffer.get().await.ok_or(ErrorCode::ResourceExhausted)?;
                    let mut send = send.lock().await;

                    let goodbye = GoodbyeServices {
                        services: &removed,
                        dev_det: self.matter.dev_det(),
                        port: self.matter.port(),
                    };
                    let len = host.broadcast_goodbye(&goodbye, &mut buf)?;
                    if len > 0 {
                        if let Err(e) = send.send_to(&buf[..len], Address::Udp(addr)).await {
                            warn!("Failed to send mDNS goodbye to {}: {}", addr, e);
                        } else {
                            debug!(
                                "Broadcasting mDNS goodbye for {} retired service(s) to {}",
                                removed.len(),
                                addr
                            );
                        }
                    }
                }

                let mut buf = buffer.get().await.ok_or(ErrorCode::ResourceExhausted)?;
                let mut send = send.lock().await;

                let len = host.broadcast(self, &mut buf, 60)?;

                if len > 0 {
                    if let Err(e) = send.send_to(&buf[..len], Address::Udp(addr)).await {
                        warn!("Failed to send mDNS broadcast to {}: {}", addr, e);
                    } else {
                        debug!("Broadcasting mDNS entry to {}", addr);
                    }
                }
            }

            last = current;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn respond<S, R>(
        &self,
        send: &IfMutex<S>,
        mut recv: R,
        host: &Host<'_>,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
    {
        loop {
            recv.wait_available().await?;

            {
                let tx_buf = self.matter.transport_tx_buffer();
                let rx_buf = self.matter.transport_rx_buffer();

                let mut rx = rx_buf.get().await.ok_or(ErrorCode::ResourceExhausted)?;
                let (len, addr) = recv.recv_from(&mut rx).await?;

                let mut tx = tx_buf.get().await.ok_or(ErrorCode::ResourceExhausted)?;
                let mut send = send.lock().await;

                let (len, delay) = match host.respond(self, &rx[..len], &mut tx, 60) {
                    Ok((len, delay)) => (len, delay),
                    Err(err) => {
                        warn!("mDNS protocol error {} while replying to {}", err, addr);
                        continue;
                    }
                };

                if len > 0 {
                    let ipv4 = addr
                        .udp()
                        .map(|addr| matches!(addr.ip().to_canonical(), IpAddr::V4(_)))
                        .unwrap_or(true);

                    let reply_addr = if ipv4 {
                        ipv4_interface.map(|_| {
                            SocketAddr::V4(SocketAddrV4::new(MDNS_IPV4_BROADCAST_ADDR, MDNS_PORT))
                        })
                    } else {
                        ipv6_interface.map(|interface| {
                            SocketAddr::V6(SocketAddrV6::new(
                                MDNS_IPV6_BROADCAST_ADDR,
                                MDNS_PORT,
                                0,
                                interface,
                            ))
                        })
                    };

                    if let Some(reply_addr) = reply_addr {
                        if delay {
                            let mut b = [0];

                            let mut rand = self.crypto.weak_rand()?;

                            rand.fill_bytes(&mut b);

                            // Generate a delay between 20 and 120 ms, as per spec
                            let delay_ms = 20 + (b[0] as u32 * 100 / 256);

                            debug!(
                                "Replying to mDNS query from {} on {}, delay {}ms",
                                addr, reply_addr, delay_ms
                            );
                            Timer::after(Duration::from_millis(delay_ms as _)).await;
                        } else {
                            debug!("Replying to mDNS query from {} on {}", addr, reply_addr);
                        }

                        if let Err(e) = send.send_to(&tx[..len], Address::Udp(reply_addr)).await {
                            warn!("Failed to send mDNS response to {}: {}", reply_addr, e);
                        }
                    } else {
                        debug!("Cannot reply to mDNS query from {}: no suitable broadcast address found", addr);
                    }
                }
            }
        }
    }
}

impl<C> Services for BuiltinMdnsResponder<'_, C>
where
    C: Crypto,
{
    fn for_each<F>(&self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(&Service) -> Result<(), Error>,
    {
        self.matter.mdns_services(|service| {
            Service::call_with(
                &service,
                self.matter.dev_det(),
                self.matter.port(),
                &mut callback,
            )
        })
    }
}

/// `Services` adapter that expands a slice of `MatterMdnsService` values
/// into full `Service` descriptions on demand. Used to feed the goodbye
/// broadcast path with services that are no longer live (and therefore
/// no longer reachable through `Matter::mdns_services`).
struct GoodbyeServices<'a> {
    services: &'a [MatterMdnsService],
    dev_det: &'a crate::BasicInfoConfig<'a>,
    port: u16,
}

impl Services for GoodbyeServices<'_> {
    fn for_each<F>(&self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(&Service) -> Result<(), Error>,
    {
        for matter_service in self.services {
            Service::call_with(matter_service, self.dev_det, self.port, &mut callback)?;
        }
        Ok(())
    }
}
