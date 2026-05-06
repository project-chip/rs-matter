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
use crate::utils::init::{init, Init};
use crate::utils::select::Coalesce;
use crate::utils::storage::pooled::BufferAccess;
use crate::utils::storage::Vec;
use crate::utils::sync::IfMutex;
use crate::Matter;

use super::{MatterService, Service};

pub use proto::{Host, RespondMode};
pub use querier::discover_commissionable;

mod proto;
pub mod querier;
mod types;

const MAX_SERVICES: usize = MAX_FABRICS + 1;

/// A built-in mDNS responder for Matter, utilizing a custom mDNS protocol implementation.
///
/// `no_std` and `no-alloc` and thus suitable for MCUs as well when there is no running mDNS service as part of the OS,
pub struct BuiltinMdnsResponder {
    services_cur: Vec<MatterService, MAX_SERVICES>,
    services_new: Vec<MatterService, MAX_SERVICES>,
}

impl BuiltinMdnsResponder {
    /// Create a new instance of the built-in mDNS responder.
    pub const fn new() -> Self {
        Self {
            services_cur: Vec::new(),
            services_new: Vec::new(),
        }
    }

    /// Return an in-place initializer for the built-in mDNS responder.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            services_cur <- Vec::init(),
            services_new <- Vec::init(),
        })
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
    pub async fn run<S, R, C>(
        &mut self,
        send: S,
        recv: R,
        host: &Host<'_>,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
        matter: &Matter<'_>,
        crypto: C,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
        C: Crypto,
    {
        self.services_cur.clear();
        self.services_new.clear();

        matter.mdns_services(|s| {
            self.services_cur
                .push(s)
                .map_err(|_| Error::from(ErrorCode::ResourceExhausted))
        })?;

        let send = IfMutex::new((send, &mut self.services_new));

        let mut broadcast = pin!(Self::broadcast(
            &send,
            &mut self.services_cur,
            host,
            ipv4_interface,
            ipv6_interface,
            matter,
            &crypto
        ));
        let mut respond = pin!(Self::respond(
            &send,
            recv,
            host,
            ipv4_interface,
            ipv6_interface,
            matter,
            &crypto
        ));

        select(&mut broadcast, &mut respond).coalesce().await
    }

    #[allow(clippy::too_many_arguments)]
    async fn broadcast<S, C>(
        send: &IfMutex<(S, &mut Vec<MatterService, MAX_SERVICES>)>,
        services_cur: &mut Vec<MatterService, MAX_SERVICES>,
        host: &Host<'_>,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
        matter: &Matter<'_>,
        crypto: C,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        C: Crypto,
    {
        loop {
            let mut notification = pin!(matter.wait_mdns());
            let mut timeout = pin!(Timer::after(Duration::from_secs(30)));

            select(&mut notification, &mut timeout).await;

            let tx_buf = matter.transport_tx_buffer();
            let mut tx_buf = tx_buf.get().await.ok_or(ErrorCode::ResourceExhausted)?;
            let tx_buf = &mut *tx_buf;

            let mut send_guard = send.lock().await;

            let send_guard = &mut *send_guard;
            let (send, services_new) = (&mut send_guard.0, &mut *send_guard.1);

            services_new.clear();
            matter.mdns_services(|s| {
                services_new
                    .push(s)
                    .map_err(|_| Error::from(ErrorCode::ResourceExhausted))
            })?;

            for service in &*services_cur {
                if !services_new.iter().any(|s| s == service) {
                    trace!(
                        "Service {:?} is no longer live and will be retired",
                        service
                    );

                    Self::broadcast_one(
                        &mut *send,
                        host,
                        service,
                        true,
                        ipv4_interface,
                        ipv6_interface,
                        matter,
                        &crypto,
                        tx_buf,
                    )
                    .await?;
                }
            }

            for service in &*services_new {
                trace!("Announcing service {:?}", service);

                Self::broadcast_one(
                    &mut *send,
                    host,
                    service,
                    false,
                    ipv4_interface,
                    ipv6_interface,
                    matter,
                    &crypto,
                    tx_buf,
                )
                .await?;
            }

            services_cur.clear();
            services_cur
                .extend_from_slice(services_new)
                .map_err(|_| Error::from(ErrorCode::ResourceExhausted))?;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn broadcast_one<S, C>(
        mut send: S,
        host: &Host<'_>,
        service: &MatterService,
        service_remove: bool,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
        matter: &Matter<'_>,
        crypto: C,
        buf: &mut [u8],
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        C: Crypto,
    {
        let ttl = if service_remove { 0 } else { 60 };

        let (service, buf) = service.service(matter.dev_det(), matter.port(), buf)?;
        let len = host.broadcast(&service, buf, 60, ttl)?;

        if len > 0 {
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
                Self::rand_delay(&crypto).await?;

                if let Err(e) = send.send_to(&buf[..len], Address::Udp(addr)).await {
                    warn!("Failed to send mDNS broadcast to {}: {}", addr, e);
                } else {
                    debug!("Broadcasting mDNS entry to {}", addr);
                }
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn respond<S, R, C>(
        send: &IfMutex<(S, &mut Vec<MatterService, MAX_SERVICES>)>,
        mut recv: R,
        host: &Host<'_>,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
        matter: &Matter<'_>,
        crypto: C,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
        C: Crypto,
    {
        loop {
            recv.wait_available().await?;

            {
                let tx_buf = matter.transport_tx_buffer();
                let mut tx_buf = tx_buf.get().await.ok_or(ErrorCode::ResourceExhausted)?;
                let tx_buf = &mut *tx_buf;

                let rx_buf = matter.transport_rx_buffer();
                let mut rx_buf = rx_buf.get().await.ok_or(ErrorCode::ResourceExhausted)?;
                let rx_buf = &mut *rx_buf;

                let mut send_guard = send.lock().await;

                let send_guard = &mut *send_guard;
                let (send, services_new) = (&mut send_guard.0, &mut *send_guard.1);

                services_new.clear();
                matter.mdns_services(|s| {
                    services_new
                        .push(s)
                        .map_err(|_| Error::from(ErrorCode::ResourceExhausted))
                })?;

                let (len, addr) = recv.recv_from(rx_buf).await?;
                let query = &rx_buf[..len];

                for service in &*services_new {
                    trace!(
                        "Considering mDNS query for service {:?} from {}",
                        service,
                        addr
                    );

                    Self::respond_one(
                        &mut *send,
                        addr,
                        query,
                        host,
                        service,
                        ipv4_interface,
                        ipv6_interface,
                        matter,
                        &crypto,
                        tx_buf,
                    )
                    .await?;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn respond_one<S, C>(
        mut send: S,
        addr: Address,
        query: &[u8],
        host: &Host<'_>,
        service: &MatterService,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
        matter: &Matter<'_>,
        crypto: C,
        buf: &mut [u8],
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        C: Crypto,
    {
        let (service, buf) = service.service(matter.dev_det(), matter.port(), buf)?;

        // RFC 6762 §6.7: a query whose UDP source port is not 5353 comes from
        // a legacy unicast resolver and gets a unicast reply with the legacy
        // semantics (echoed question section, original query ID, capped TTL,
        // no cache-flush bit).
        let src_addr = unwrap!(addr.udp());
        let legacy_unicast = src_addr.port() != MDNS_PORT;

        let (len, mode) = match host.respond(&service, query, buf, 60, legacy_unicast) {
            Ok(r) => r,
            Err(err) => {
                warn!("mDNS protocol error {} while replying to {}", err, addr);
                return Ok(());
            }
        };

        if len == 0 || matches!(mode, RespondMode::Skip) {
            return Ok(());
        }

        let reply_addr = match mode {
            RespondMode::Skip => return Ok(()),
            RespondMode::Unicast => Some(src_addr),
            RespondMode::Multicast { delay } => {
                if delay {
                    Self::rand_delay(&crypto).await?;
                }

                let ipv4 = matches!(src_addr.ip().to_canonical(), IpAddr::V4(_));
                if ipv4 {
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
                }
            }
        };

        if let Some(reply_addr) = reply_addr {
            debug!("Replying to mDNS query from {} on {}", addr, reply_addr);

            if let Err(e) = send.send_to(&buf[..len], Address::Udp(reply_addr)).await {
                warn!("Failed to send mDNS response to {}: {}", reply_addr, e);
            }
        } else {
            debug!(
                "Cannot reply to mDNS query from {}: no suitable broadcast address found",
                addr
            );
        }

        Ok(())
    }

    async fn rand_delay<C: Crypto>(crypto: C) -> Result<(), Error> {
        let mut b = [0];

        let mut rand = crypto.weak_rand()?;

        rand.fill_bytes(&mut b);

        // Generate a delay between 20 and 120 ms, as per spec
        let delay_ms = 20 + (b[0] as u32 * 100 / 256);

        Timer::after(Duration::from_millis(delay_ms as _)).await;

        Ok(())
    }
}

impl Default for BuiltinMdnsResponder {
    fn default() -> Self {
        Self::new()
    }
}
