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

//! A Linux-specific mDNS implementation based on Avahi.
//!
//! Requires the Avahi daemon to be installed and running.

use core::pin::pin;

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_lite::StreamExt;

use zbus::zvariant::{ObjectPath, OwnedObjectPath};
use zbus::Connection;

use crate::error::Error;
use crate::transport::network::mdns::{DottedName, MdnsRemoteService};
use crate::transport::network::MatterLocalService;
use crate::transport::MdnsResponder;
use crate::utils::futures::{select, select3, Coalesce, Either, Either3};
use crate::utils::storage;
use crate::utils::timers::{Duration, Timer};
use crate::utils::zbus_proxies::avahi::entry_group::EntryGroupProxy;
use crate::utils::zbus_proxies::avahi::record_browser::RecordBrowserProxy;
use crate::utils::zbus_proxies::avahi::server2::Server2Proxy;
use crate::utils::zbus_proxies::avahi::service_browser::ServiceBrowserProxy;
use crate::Matter;

/// An Avahi browser object, freed through a [`BrowserGuard`].
trait Browser {
    async fn free(&self) -> zbus::Result<()>;
}

impl Browser for ServiceBrowserProxy<'_> {
    async fn free(&self) -> zbus::Result<()> {
        ServiceBrowserProxy::free(self).await
    }
}

impl Browser for RecordBrowserProxy<'_> {
    async fn free(&self) -> zbus::Result<()> {
        RecordBrowserProxy::free(self).await
    }
}

/// Frees an Avahi browser even if the future that owns it is cancelled
/// (dropped) mid-loop - otherwise the browser leaks on the daemon.
///
/// The normal path calls [`BrowserGuard::free`], releasing the browser
/// asynchronously and disarming the guard. Only a cancellation leaves it armed, in
/// which case `Drop` frees it with a **blocking** call - safe here because zbus
/// drives the D-Bus connection's I/O on its own task, independently of the future
/// being torn down, so `block_on` can complete rather than deadlock. (The same
/// `block_on`-in-`Drop` idiom is used for D-Bus cleanup elsewhere in the crate, e.g.
/// the NetworkManager and wpa_supplicant controllers.)
struct BrowserGuard<'b, B: Browser> {
    browser: &'b B,
    armed: bool,
}

impl<'b, B: Browser> BrowserGuard<'b, B> {
    fn new(browser: &'b B) -> Self {
        Self {
            browser,
            armed: true,
        }
    }

    /// Free the browser asynchronously (the non-cancelled path) and disarm the
    /// blocking `Drop` fallback.
    async fn free(mut self) {
        self.armed = false;
        if let Err(e) = self.browser.free().await {
            warn!("Failed to free Avahi browser: {:?}", e);
        }
    }
}

impl<B: Browser> Drop for BrowserGuard<'_, B> {
    fn drop(&mut self) {
        if self.armed {
            // Reached only if the future was cancelled before `free` was called.
            let _ = futures_lite::future::block_on(self.browser.free());
        }
    }
}

/// Avahi constant for "any interface"
const AVAHI_IF_UNSPEC: i32 = -1;
/// Avahi constant for "any protocol" (IPv4 or IPv6)
const AVAHI_PROTO_UNSPEC: i32 = -1;

/// The `IN` DNS class.
const DNS_CLASS_IN: u16 = 1;
/// The `A` DNS record type.
const DNS_TYPE_A: u16 = 1;
/// The `AAAA` DNS record type.
const DNS_TYPE_AAAA: u16 = 28;

/// Upper bound (ms) on reading a host's addresses from Avahi's cache, in case
/// the daemon never signals the end of it.
const HOST_ADDRS_TIMEOUT_MS: u64 = 500;

/// Interval (ms) at which a running browse re-checks whether it is still in
/// flight (first match consumed, or caller timed out / dropped).
const BROWSE_POLL_INTERVAL_MS: u64 = 250;

/// An mDNS implementation for Matter utilizing the Avahi daemon over DBus.
pub struct AvahiMdns {
    services: HashMap<MatterLocalService, OwnedObjectPath>,
    connection: Connection,
}

impl AvahiMdns {
    /// Create a new instance of the Avahi mDNS implementation.
    pub fn new(connection: Connection) -> Self {
        Self {
            services: HashMap::new(),
            connection,
        }
    }

    /// Run the mDNS responder + querier.
    ///
    /// # Arguments
    /// - `matter`: A reference to the Matter instance to get mDNS services from.
    pub async fn run(&mut self, matter: &Matter<'_>) -> Result<(), Error> {
        let connection = self.connection.clone();

        let responder = matter.transport().mdns_responder();
        let mut respond = pin!(self.run_respond(matter));
        let mut resolve = pin!(Self::run_resolve(matter, &responder, &connection));
        let mut browse = pin!(Self::run_browse(matter, &responder, &connection));

        select3(&mut respond, &mut resolve, &mut browse)
            .coalesce()
            .await
    }

    /// Publish the local Matter services and keep them in sync with the stack.
    async fn run_respond(&mut self, matter: &Matter<'_>) -> Result<(), Error> {
        {
            let avahi = Server2Proxy::new(&self.connection).await?;
            info!("Avahi API version: {}", avahi.get_apiversion().await?);
        }

        loop {
            matter.transport().wait_mdns().await;

            let mut services = HashSet::new();
            matter.mdns_services(|service| {
                services.insert(service);

                Ok(())
            })?;

            info!("mDNS services changed, updating...");

            self.update_services(matter, &services).await?;

            info!("mDNS services updated");
        }
    }

    /// Service operational-resolve requests via Avahi over DBus.
    ///
    /// This uses a **live `ServiceBrowser`** on the operational service type
    /// (`_matter._tcp`) and only resolves the target once the browser reports the
    /// matching instance appearing — rather than polling Avahi's `ResolveService`
    /// on the target's name.
    ///
    /// That distinction matters a great deal in practice. `ResolveService` on an
    /// instance that does not exist *yet* blocks for Avahi's full resolve timeout
    /// (~5 s) before failing, and does not aggressively re-query afterwards — so
    /// polling it while waiting for a device to come up wastes ~5 s per attempt
    /// and can lag many tens of seconds behind the record actually being
    /// published. This is exactly the situation for a device that has just been
    /// told to join Thread: its operational `_matter._tcp` record appears (via the
    /// Border Router's SRP advertising proxy) a fraction of a second after it
    /// attaches, and a browser fires `ItemNew` for it essentially immediately,
    /// whereas name-resolve polling would only notice it much later. Once the
    /// instance exists, resolving it is near-instant.
    async fn run_resolve(
        matter: &Matter<'_>,
        responder: &MdnsResponder<'_>,
        connection: &Connection,
    ) -> Result<(), Error> {
        loop {
            let service = responder.wait_resolve_request().await;

            // The label we're looking for (e.g. `<compressed-fabric>-<node-id>`),
            // and the full instance name to deposit under.
            let mut name_buf: storage::String<128> = storage::String::new();
            service.instance_name(&mut name_buf);
            let target_label = name_buf
                .split('.')
                .next()
                .unwrap_or(name_buf.as_str())
                .to_string();
            let service_type = service.service_type();

            let avahi = Server2Proxy::new(connection).await?;

            // A live browser on the operational service type. `ItemNew` fires as
            // soon as Avahi sees the record on the wire.
            let browser_path = avahi
                .service_browser_prepare(AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, service_type, "", 0)
                .await?;
            let browser = ServiceBrowserProxy::builder(connection)
                .path(browser_path)?
                .build()
                .await?;
            let mut item_new_stream = browser.receive_item_new().await?;
            browser.start().await?;

            // Frees the browser on cancellation too (see `BrowserGuard`).
            let guard = BrowserGuard::new(&browser);

            while matter.transport().mdns_resolve_in_flight() {
                let item = pin!(item_new_stream.next());
                let tick = pin!(Timer::after(Duration::from_millis(BROWSE_POLL_INTERVAL_MS)));

                let signal = match select(item, tick).await {
                    Either::First(Some(signal)) => signal,
                    Either::First(None) => break, // browser stream ended
                    Either::Second(_) => continue, // re-check in-flight
                };

                let Ok(args) = signal.args() else { continue };

                // Only the instance we're waiting for.
                if !args.name.eq_ignore_ascii_case(&target_label) {
                    continue;
                }

                // The instance exists now, so this resolve is near-instant.
                let Some(mut resolved) = resolve_browsed(
                    &avahi,
                    args.interface,
                    args.protocol,
                    args.name,
                    args.type_,
                    args.domain,
                )
                .await
                else {
                    continue;
                };

                // All of the peer's addresses, so the transport can rank them.
                resolved.add_cached_host_addrs(connection, &avahi).await;

                debug!("Avahi resolved {}: {:?}", name_buf, resolved.ips);

                let txt_pairs = txt_pairs(&resolved.txt);
                // Deposit under the full requested instance name (the transport
                // matches on it). `name` from the browser is the bare label.
                matter.transport().try_deposit_mdns_resolve(
                    &MdnsRemoteService {
                        instance_name: DottedName(name_buf.as_str()),
                        port: Some(resolved.port),
                        addrs: resolved.ips.iter().copied(),
                        txt: txt_pairs.iter().copied(),
                        scope_id: resolved.scope_id(),
                    },
                    // The Avahi daemon owns the host A/AAAA records; this backend never
                    // sees the local interface addresses.
                    &[],
                );
            }

            guard.free().await;
        }
    }

    /// Service commissionable-browse requests via Avahi over DBus.
    ///
    /// The filter's most-selective subtype narrows the wire query; each
    /// discovered service is resolved and deposited (the full filter + exclude
    /// checks happen in the deposit). Avahi is async over DBus, so this
    /// interleaves naturally with the Matter transport. Polls the in-flight flag
    /// so it stops as soon as the first match is consumed or the caller gives up.
    async fn run_browse(
        matter: &Matter<'_>,
        responder: &MdnsResponder<'_>,
        connection: &Connection,
    ) -> Result<(), Error> {
        loop {
            let query = responder.wait_browse_request().await;

            let mut service_type: storage::String<64> = storage::String::new();
            query.service_type(&mut service_type, false);

            let avahi = Server2Proxy::new(connection).await?;
            let browser_path = avahi
                .service_browser_prepare(AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, &service_type, "", 0)
                .await?;
            let browser = ServiceBrowserProxy::builder(connection)
                .path(browser_path)?
                .build()
                .await?;
            let mut item_new_stream = browser.receive_item_new().await?;
            browser.start().await?;

            // Frees the browser on cancellation too (see `BrowserGuard`).
            let guard = BrowserGuard::new(&browser);

            while matter.transport().mdns_browse_in_flight() {
                let item = pin!(item_new_stream.next());
                let tick = pin!(Timer::after(Duration::from_millis(BROWSE_POLL_INTERVAL_MS)));

                let signal = match select(item, tick).await {
                    Either::First(Some(signal)) => signal,
                    Either::First(None) => break, // browser stream ended
                    Either::Second(_) => continue, // re-check in-flight
                };

                let Ok(args) = signal.args() else { continue };

                if !query.needs_resolve() {
                    matter
                        .transport()
                        .try_deposit_mdns_browse(&MdnsRemoteService {
                            instance_name: DottedName(args.name),
                            port: None,
                            addrs: core::iter::empty::<IpAddr>(),
                            txt: core::iter::empty::<(&str, &str)>(),
                            scope_id: 0,
                        });
                    continue;
                }

                // A browse matches on the TXT records; the addresses come from a
                // later resolve.
                let Some(resolved) = resolve_browsed(
                    &avahi,
                    args.interface,
                    args.protocol,
                    args.name,
                    args.type_,
                    args.domain,
                )
                .await
                else {
                    continue;
                };

                let txt_pairs = txt_pairs(&resolved.txt);
                matter
                    .transport()
                    .try_deposit_mdns_browse(&MdnsRemoteService {
                        instance_name: DottedName(&resolved.name),
                        port: Some(resolved.port),
                        addrs: resolved.ips.iter().copied(),
                        txt: txt_pairs.iter().copied(),
                        scope_id: resolved.scope_id(),
                    });
            }

            guard.free().await;
        }
    }

    async fn update_services(
        &mut self,
        matter: &Matter<'_>,
        services: &HashSet<MatterLocalService>,
    ) -> Result<(), Error> {
        for service in services {
            if !self.services.contains_key(service) {
                info!("Registering mDNS service: {:?}", service);
                let path = self.register(matter, service).await?;
                self.services.insert(service.clone(), path);
            }
        }

        loop {
            let removed = self
                .services
                .iter()
                .find(|(service, _)| !services.contains(service));

            if let Some((service, path)) = removed {
                info!("Deregistering mDNS service: {:?}", service);
                self.deregister(path.as_ref()).await?;
                self.services.remove(&service.clone());
            } else {
                break;
            }
        }

        Ok(())
    }

    async fn register(
        &mut self,
        matter: &Matter<'_>,
        service: &MatterLocalService,
    ) -> Result<OwnedObjectPath, Error> {
        // Scratch buffer for expanding `MatterLocalService` into a `MdnsLocalService` view —
        // the strings (name, subtypes, TXT values) are formatted into this buffer.
        let mut buf = [0u8; 512];
        let (service, _) = service.service(matter, &mut buf)?;

        let avahi = Server2Proxy::new(&self.connection).await?;

        let path = avahi.entry_group_new().await?;

        let group = EntryGroupProxy::builder(&self.connection)
            .path(path.clone())?
            .build()
            .await?;

        let mut txt_buf = Vec::new();

        let offsets = service
            .txt_kvs
            .clone()
            .map(|(k, v)| {
                let start = txt_buf.len();

                if v.is_empty() {
                    txt_buf.extend_from_slice(k.as_bytes());
                } else {
                    write_unwrap!(&mut txt_buf, "{}={}", k, v);
                }

                txt_buf.len() - start
            })
            .collect::<Vec<_>>();

        let mut txt_slice = txt_buf.as_slice();
        let mut txt = Vec::new();

        for offset in offsets {
            let (entry, next_slice) = txt_slice.split_at(offset);

            txt.push(entry);

            txt_slice = next_slice;
        }

        group
            .add_service(
                AVAHI_IF_UNSPEC,
                AVAHI_PROTO_UNSPEC,
                0,
                service.name,
                service.service_protocol,
                "",
                "",
                service.port,
                &txt,
            )
            .await?;

        for subtype in service.service_subtypes.clone() {
            // Unclear why, but Avahi wants this very special
            // way of formatting service subtypes
            let avahi_subtype = format!("{}._sub.{}", subtype, service.service_protocol);

            group
                .add_service_subtype(
                    AVAHI_IF_UNSPEC,
                    AVAHI_PROTO_UNSPEC,
                    0,
                    service.name,
                    service.service_protocol,
                    "",
                    &avahi_subtype,
                )
                .await?;
        }

        group.commit().await?;

        Ok(path)
    }

    async fn deregister(&self, path: ObjectPath<'_>) -> Result<(), Error> {
        let group = EntryGroupProxy::builder(&self.connection)
            .path(path)?
            .build()
            .await?;

        group.free().await?;

        Ok(())
    }
}

/// A browsed instance, resolved by [`resolve_browsed`].
struct ResolvedService {
    name: String,
    /// The SRV target host.
    host: String,
    /// The interface the instance was resolved on.
    interface: i32,
    ips: Vec<IpAddr>,
    port: u16,
    txt: Vec<Vec<u8>>,
}

impl ResolvedService {
    /// The IPv6 scope id for a link-local address among `ips`, else `0`.
    fn scope_id(&self) -> u32 {
        if self.interface > 0 && self.ips.iter().any(is_link_local_v6) {
            self.interface as u32
        } else {
            0
        }
    }

    /// Add every address Avahi has cached for the host to `ips`.
    ///
    /// `ResolveService` returns one address, and for a dual-stack peer that is
    /// often the IPv4 one. The host's A/AAAA records came with its SRV record, so
    /// they are cached by now: reading just the cache gets all of them without
    /// waiting, also when the host lacks a family.
    async fn add_cached_host_addrs(&mut self, connection: &Connection, avahi: &Server2Proxy<'_>) {
        for type_ in [DNS_TYPE_AAAA, DNS_TYPE_A] {
            if let Err(e) = self.add_cached_records(connection, avahi, type_).await {
                debug!("Avahi record browse for {} failed: {:?}", self.host, e);
            }
        }
    }

    /// Add the addresses of the host's cached `type_` (A or AAAA) records.
    async fn add_cached_records(
        &mut self,
        connection: &Connection,
        avahi: &Server2Proxy<'_>,
        type_: u16,
    ) -> Result<(), Error> {
        let browser_path = avahi
            .record_browser_prepare(
                self.interface,
                AVAHI_PROTO_UNSPEC,
                &self.host,
                DNS_CLASS_IN,
                type_,
                0,
            )
            .await?;
        let browser = RecordBrowserProxy::builder(connection)
            .path(browser_path)?
            .build()
            .await?;
        let mut item_new_stream = browser.receive_item_new().await?;
        let mut cache_exhausted_stream = browser.receive_cache_exhausted().await?;
        let mut failure_stream = browser.receive_failure().await?;
        browser.start().await?;

        // Frees the browser on cancellation too (see `BrowserGuard`).
        let guard = BrowserGuard::new(&browser);

        let mut timer = pin!(Timer::after(Duration::from_millis(HOST_ADDRS_TIMEOUT_MS)));

        loop {
            // Items go first: the cached ones are signalled before
            // `CacheExhausted`, so they are all queued once it is.
            let item = pin!(item_new_stream.next());
            let end = pin!(select(cache_exhausted_stream.next(), failure_stream.next()));

            let Either3::First(Some(signal)) = select3(item, end, &mut timer).await else {
                break;
            };

            let Ok(args) = signal.args() else { continue };

            let ip = if let Ok(octets) = <[u8; 16]>::try_from(args.rdata.as_slice()) {
                IpAddr::V6(Ipv6Addr::from(octets))
            } else if let Ok(octets) = <[u8; 4]>::try_from(args.rdata.as_slice()) {
                IpAddr::V4(Ipv4Addr::from(octets))
            } else {
                continue;
            };

            if !self.ips.contains(&ip) {
                self.ips.push(ip);
            }
        }

        guard.free().await;

        Ok(())
    }
}

/// Parse Avahi TXT entries (`key=value` / bare `key` byte strings) into borrowed
/// `(key, value)` pairs.
fn txt_pairs(txt: &[Vec<u8>]) -> Vec<(&str, &str)> {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for entry in txt {
        if let Ok(s) = core::str::from_utf8(entry) {
            match s.find('=') {
                Some(eq) => pairs.push((&s[..eq], &s[eq + 1..])),
                None => pairs.push((s, "")),
            }
        }
    }
    pairs
}

/// Resolve a *browsed* instance (identified by the browser's
/// `name`/`type_`/`domain`).
///
/// One `ResolveService` with `aprotocol = AVAHI_PROTO_UNSPEC`, rather than one
/// per address family: a family the instance lacks would block for Avahi's ~5 s
/// resolve timeout (a Thread device has no IPv4). It yields a single address;
/// see [`ResolvedService::add_cached_host_addrs`] for the rest.
async fn resolve_browsed(
    avahi: &Server2Proxy<'_>,
    interface: i32,
    protocol: i32,
    name: &str,
    type_: &str,
    domain: &str,
) -> Option<ResolvedService> {
    match avahi
        .resolve_service(
            interface,
            protocol,
            name,
            type_,
            domain,
            AVAHI_PROTO_UNSPEC,
            0,
        )
        .await
    {
        Ok((iface, _proto, rname, _type, _domain, host, _ap, address, port, txt, _fl)) => {
            match address.parse::<IpAddr>() {
                Ok(ip) => Some(ResolvedService {
                    name: rname,
                    host,
                    interface: iface,
                    ips: vec![ip],
                    port,
                    txt,
                }),
                Err(_) => {
                    warn!("Could not parse IP address: {address}");
                    None
                }
            }
        }
        Err(e) => {
            debug!("Avahi resolve (browsed) failed: {e:?}");
            None
        }
    }
}

/// `true` for a unicast link-local IPv6 address (`fe80::/10`) — the only kind
/// that needs an interface scope id to be routable.
fn is_link_local_v6(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
}
