/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

use domain::base::Message;

use embassy_futures::select::{select, select4};
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
use crate::utils::storage::pooled::Buffers;
use crate::utils::storage::Vec;
use crate::utils::sync::IfMutex;
use crate::Matter;

use super::{MatterLocalService, MdnsLocalService};

pub use query::{build_browse_query, build_resolve_query, parse_into_answer};
pub use respond::{Host, RespondMode};

use types::NameSlice;

mod query;
mod respond;
mod types;

const MAX_SERVICES: usize = MAX_FABRICS + 1;

/// A built-in mDNS responder for Matter, utilizing a custom mDNS protocol implementation.
///
/// `no_std` and `no-alloc` and thus suitable for MCUs as well when there is no running mDNS service as part of the OS,
pub struct BuiltinMdns {
    services_cur: Vec<MatterLocalService, MAX_SERVICES>,
    services_new: Vec<MatterLocalService, MAX_SERVICES>,
}

impl BuiltinMdns {
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

    /// Run the built-in mDNS responder + querier.
    ///
    /// On a single shared socket, this concurrently:
    /// - broadcasts the local Matter services and answers inbound queries about them,
    /// - services [`Transport::resolve`](crate::transport::Transport::resolve) requests, and
    /// - services [`Transport::browse_commissionable`](crate::transport::Transport::browse_commissionable)
    ///   requests,
    ///
    /// firing the corresponding mDNS query and depositing the parsed answers back
    /// for the awaiting caller.
    ///
    /// # Arguments
    /// * `send` - An object implementing the `NetworkSend` trait for sending mDNS packets.
    /// * `recv` - An object implementing the `NetworkReceive` trait for receiving mDNS packets.
    /// * `host` - A reference to the `Host` instance that provides basic mDNS host information.
    /// * `ipv4_interface` - An optional IPv4 address for the interface to use for mDNS broadcasts.
    /// * `ipv6_interface` - An optional IPv6 interface index for the interface to use for mDNS broadcasts.
    /// * `matter` - The Matter instance whose services to publish / whose resolve+browse to service.
    /// * `crypto` - The crypto backend (used for randomized send delays).
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
            &crypto,
        ));
        let mut resolve = pin!(Self::resolve(
            &send,
            ipv4_interface,
            ipv6_interface,
            matter,
            &crypto,
        ));
        let mut browse = pin!(Self::browse(
            &send,
            ipv4_interface,
            ipv6_interface,
            matter,
            &crypto,
        ));

        select4(&mut broadcast, &mut respond, &mut resolve, &mut browse)
            .coalesce()
            .await
    }

    /// MdnsLocalService [`Matter::resolve`] requests: pick up a pending resolve request
    /// and emit the corresponding mDNS query on the shared socket.
    async fn resolve<S, C>(
        send: &IfMutex<(S, &mut Vec<MatterLocalService, MAX_SERVICES>)>,
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
            let service = matter.transport().wait_mdns_resolve_request().await;

            // Compose the instance name straight from labels (a tiny buffer for
            // the variable hex label; the rest are static `&str`s) - no full-name
            // buffer + re-parse.
            let mut label = heapless::String::<33>::new();
            let name = NameSlice::new(service.query_name_labels(&mut label));

            // A small random delay before sending, as per spec (collision avoidance).
            Self::rand_delay(&crypto).await?;

            let mut send_guard = send.lock().await;
            let send = &mut send_guard.0;

            // Acquire the Matter transport TX buffer only for the duration of
            // this one query, so as not to starve the Matter send loop.
            let tx_buf = matter.transport_tx_buffer();
            let mut tx_buf = tx_buf.get().await.ok_or(ErrorCode::ResourceExhausted)?;
            let buf = &mut *tx_buf;

            let len = build_resolve_query(&name, buf)?;

            for addr in Self::broadcast_addrs(ipv4_interface, ipv6_interface) {
                if let Err(e) = send.send_to(&buf[..len], Address::Udp(addr)).await {
                    warn!("Failed to send mDNS query to {}: {}", addr, e);
                } else {
                    debug!("Sent mDNS resolve query {} to {}", name, addr);
                }
            }
        }
    }

    /// MdnsLocalService [`Transport::browse_commissionable`] requests: pick up a pending
    /// browse request and emit the corresponding commissionable mDNS query on the
    /// shared socket. The query is narrowed to the most selective subtype the
    /// filter offers (`_L`/`_S`/`_V`/`_T`/`_CM`, see
    /// [`CommissionableFilter::service_type`]); the responder then deposits the
    /// first answer matching the full filter.
    async fn browse<S, C>(
        send: &IfMutex<(S, &mut Vec<MatterLocalService, MAX_SERVICES>)>,
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
            let filter = matter.transport().wait_mdns_browse_request().await;

            // A small random delay before sending, as per spec (collision avoidance).
            Self::rand_delay(&crypto).await?;

            let mut send_guard = send.lock().await;
            let send = &mut send_guard.0;

            let tx_buf = matter.transport_tx_buffer();
            let mut tx_buf = tx_buf.get().await.ok_or(ErrorCode::ResourceExhausted)?;
            let buf = &mut *tx_buf;

            // Compose the browse name straight from labels: the most-selective
            // subtype (a tiny buffer) under `_sub._matterc._udp.local`, or the
            // bare service type for an unfiltered browse - no full-name buffer.
            let mut sbuf = heapless::String::<24>::new();
            let len = if let Some(sub) = filter.subtype(&mut sbuf) {
                build_browse_query(
                    NameSlice::new([sub, "_sub", "_matterc", "_udp", "local"]),
                    buf,
                )?
            } else {
                build_browse_query(NameSlice::new(["_matterc", "_udp", "local"]), buf)?
            };

            for addr in Self::broadcast_addrs(ipv4_interface, ipv6_interface) {
                if let Err(e) = send.send_to(&buf[..len], Address::Udp(addr)).await {
                    warn!("Failed to send mDNS browse query to {}: {}", addr, e);
                } else {
                    debug!("Sent mDNS browse query to {}", addr);
                }
            }
        }
    }

    /// The mDNS multicast send targets for the configured interfaces.
    fn broadcast_addrs(
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
    ) -> impl Iterator<Item = SocketAddr> {
        Iterator::chain(
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
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn broadcast<S, C>(
        send: &IfMutex<(S, &mut Vec<MatterLocalService, MAX_SERVICES>)>,
        services_cur: &mut Vec<MatterLocalService, MAX_SERVICES>,
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
            let mut notification = pin!(matter.transport().wait_mdns());
            let mut timeout = pin!(Timer::after(Duration::from_secs(30)));

            select(&mut notification, &mut timeout).await;

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
                        "MdnsLocalService {:?} is no longer live and will be retired",
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
        service: &MatterLocalService,
        service_remove: bool,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
        matter: &Matter<'_>,
        crypto: C,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        C: Crypto,
    {
        let ttl = if service_remove { 0 } else { 60 };

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

            // Acquire the Matter transport TX buffer *per send-target*
            // rather than across the whole broadcast iteration. Holding
            // it across the iteration would starve the Matter IM
            // responder of TX, especially during the post-`OpenCommissioningWindow`
            // announce burst.
            let tx_buf = matter.transport_tx_buffer();
            let mut tx_buf = tx_buf.get().await.ok_or(ErrorCode::ResourceExhausted)?;
            let buf = &mut *tx_buf;

            let (service_dns, buf) = service.service(matter.dev_det(), matter.port(), buf)?;
            let len = host.broadcast(&service_dns, buf, 60, ttl)?;
            if len == 0 {
                continue;
            }

            if let Err(e) = send.send_to(&buf[..len], Address::Udp(addr)).await {
                warn!("Failed to send mDNS broadcast to {}: {}", addr, e);
            } else {
                debug!("Broadcasting mDNS entry to {}", addr);
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn respond<S, R, C>(
        send: &IfMutex<(S, &mut Vec<MatterLocalService, MAX_SERVICES>)>,
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
                // NOTE: We only hold the Matter transport RX buffer for the
                // duration of the `recv_from` + `services_new` snapshot +
                // per-service response dispatch — the TX buffer is taken
                // per-send by `respond_one` so the Matter IM responder can
                // interleave with us. See the matching change in
                // `broadcast_one` for why this matters (TC_IDM_1_2 flake).
                let rx_buf = matter.transport_rx_buffer();
                let mut rx_buf = rx_buf.get().await.ok_or(ErrorCode::ResourceExhausted)?;
                let rx_buf = &mut *rx_buf;

                let (len, addr) = recv.recv_from(rx_buf).await?;
                let packet = &rx_buf[..len];

                // Demultiplex the inbound packet by the DNS QR bit: responses
                // (QR=1) are answers to our own browse/resolve queries; queries
                // (QR=0) are questions about our services to be responded to.
                let is_response = matches!(
                    Message::from_octets(packet).map(|m| m.header().flags().qr),
                    Ok(true)
                );

                if is_response {
                    // Deposit any answer that matches an in-flight resolve or
                    // browse request.
                    match parse_into_answer(packet) {
                        Ok(Some(answer)) => {
                            matter.transport().try_deposit_mdns_resolve(&answer);
                            matter.transport().try_deposit_mdns_browse(&answer);
                        }
                        Ok(None) => {}
                        Err(e) => debug!("Failed to parse mDNS response: {:?}", e),
                    }
                    continue;
                }

                let mut send_guard = send.lock().await;

                let send_guard = &mut *send_guard;
                let (send, services_new) = (&mut send_guard.0, &mut *send_guard.1);

                services_new.clear();
                matter.mdns_services(|s| {
                    services_new
                        .push(s)
                        .map_err(|_| Error::from(ErrorCode::ResourceExhausted))
                })?;

                for service in &*services_new {
                    trace!(
                        "Considering mDNS query for service {:?} from {}",
                        service,
                        addr
                    );

                    Self::respond_one(
                        &mut *send,
                        addr,
                        packet,
                        host,
                        service,
                        ipv4_interface,
                        ipv6_interface,
                        matter,
                        &crypto,
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
        service: &MatterLocalService,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
        matter: &Matter<'_>,
        crypto: C,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        C: Crypto,
    {
        // Acquire the Matter transport TX buffer only for the
        // duration of this one response so as not to starve the Matter
        // send loop.
        let tx_buf = matter.transport_tx_buffer();
        let mut tx_buf = tx_buf.get().await.ok_or(ErrorCode::ResourceExhausted)?;
        let buf = &mut *tx_buf;

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

impl Default for BuiltinMdns {
    fn default() -> Self {
        Self::new()
    }
}
