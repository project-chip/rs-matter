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
use std::net::IpAddr;

use embassy_futures::select::{select, select3, Either};
use embassy_time::{Duration, Timer};
use futures_lite::StreamExt;

use zbus::zvariant::{ObjectPath, OwnedObjectPath};
use zbus::Connection;

use crate::error::Error;
use crate::transport::network::mdns::{DottedName, MdnsRemoteService};
use crate::transport::network::MatterLocalService;
use crate::utils::select::Coalesce;
use crate::utils::zbus_proxies::avahi::entry_group::EntryGroupProxy;
use crate::utils::zbus_proxies::avahi::server2::Server2Proxy;
use crate::utils::zbus_proxies::avahi::service_browser::ServiceBrowserProxy;
use crate::Matter;

/// Frees an Avahi `ServiceBrowser` even if the future that owns it is cancelled
/// (dropped) mid-loop - otherwise the browser leaks on the daemon.
///
/// The normal path calls [`BrowserGuard::free`], releasing the browser
/// asynchronously and disarming the guard. Only a cancellation leaves it armed, in
/// which case `Drop` frees it with a **blocking** call - safe here because zbus
/// drives the D-Bus connection's I/O on its own task, independently of the future
/// being torn down, so `block_on` can complete rather than deadlock. (The same
/// `block_on`-in-`Drop` idiom is used for D-Bus cleanup elsewhere in the crate, e.g.
/// the NetworkManager and wpa_supplicant controllers.)
struct BrowserGuard<'b, 'a> {
    browser: &'b ServiceBrowserProxy<'a>,
    armed: bool,
}

impl<'b, 'a> BrowserGuard<'b, 'a> {
    fn new(browser: &'b ServiceBrowserProxy<'a>) -> Self {
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

impl Drop for BrowserGuard<'_, '_> {
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

        let mut respond = pin!(self.run_respond(matter));
        let mut resolve = pin!(Self::run_resolve(matter, &connection));
        let mut browse = pin!(Self::run_browse(matter, &connection));

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
    async fn run_resolve(matter: &Matter<'_>, connection: &Connection) -> Result<(), Error> {
        loop {
            let service = matter.transport().wait_mdns_resolve_request().await;

            // The label we're looking for (e.g. `<compressed-fabric>-<node-id>`),
            // and the full instance name to deposit under.
            let mut name_buf: heapless::String<128> = heapless::String::new();
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
                let (name, ips, port, txt, scope_id) = resolve_browsed_all_families(
                    &avahi,
                    args.interface,
                    args.protocol,
                    args.name,
                    args.type_,
                    args.domain,
                )
                .await;

                let _ = name;
                if !ips.is_empty() {
                    let txt_pairs = txt_pairs(&txt);
                    // Deposit under the full requested instance name (the transport
                    // matches on it). `name` from the browser is the bare label.
                    matter.transport().try_deposit_mdns_resolve(
                        &MdnsRemoteService {
                            instance_name: DottedName(name_buf.as_str()),
                            port: Some(port),
                            addrs: ips.iter().copied(),
                            txt: txt_pairs.iter().copied(),
                            scope_id,
                        },
                        // The Avahi daemon owns the host A/AAAA records; this backend never
                        // sees the local interface addresses.
                        &[],
                    );
                }
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
    async fn run_browse(matter: &Matter<'_>, connection: &Connection) -> Result<(), Error> {
        loop {
            let filter = matter.transport().wait_mdns_browse_request().await;

            let mut service_type: heapless::String<64> = heapless::String::new();
            filter.service_type(&mut service_type, false);

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

                // Resolve both families for this browsed instance and deposit all
                // addresses together (transport prefers IPv6 via
                // `score_ip_address`).
                let (name, ips, port, txt, scope_id) = resolve_browsed_all_families(
                    &avahi,
                    args.interface,
                    args.protocol,
                    args.name,
                    args.type_,
                    args.domain,
                )
                .await;

                if !ips.is_empty() {
                    let txt_pairs = txt_pairs(&txt);
                    matter
                        .transport()
                        .try_deposit_mdns_browse(&MdnsRemoteService {
                            instance_name: DottedName(&name),
                            port: Some(port),
                            addrs: ips.iter().copied(),
                            txt: txt_pairs.iter().copied(),
                            scope_id,
                        });
                }
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
/// `name`/`type_`/`domain`), returning the resolved instance name plus its
/// address, port and TXT.
///
/// We resolve with `aprotocol = AVAHI_PROTO_UNSPEC` in a **single** call, letting
/// Avahi return the address it already has for this browsed instance. We do *not*
/// loop over IPv6 then IPv4: `ResolveService` for an address family the instance
/// does not have blocks for Avahi's full ~5 s resolve timeout before failing, and
/// a Thread device typically advertises only an IPv6 (mesh-local) address — so a
/// per-family loop would stall ~5 s on the missing IPv4 every time, which (given
/// the caller's own resolve timeout) makes the resolve appear to fail even though
/// the record is right there. One UNSPEC resolve returns immediately with the
/// address that exists, which is all CASE needs to reach the peer.
#[allow(clippy::type_complexity)]
async fn resolve_browsed_all_families(
    avahi: &Server2Proxy<'_>,
    interface: i32,
    protocol: i32,
    name: &str,
    type_: &str,
    domain: &str,
) -> (String, Vec<IpAddr>, u16, Vec<Vec<u8>>, u32) {
    let mut instance_name = String::new();
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut port = 0u16;
    let mut txt: Vec<Vec<u8>> = Vec::new();
    // Interface index of a link-local result → IPv6 scope id, so a `fe80::`
    // address is routable.
    let mut scope_id = 0u32;

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
        Ok((iface, _proto, rname, _type, _domain, _host, _ap, address, p, t, _fl)) => {
            if let Ok(ip) = address.parse::<IpAddr>() {
                if is_link_local_v6(&ip) && iface > 0 {
                    scope_id = iface as u32;
                }
                ips.push(ip);
                instance_name = rname;
                port = p;
                txt = t;
            } else {
                warn!("Could not parse IP address: {address}");
            }
        }
        Err(e) => debug!("Avahi resolve (browsed) failed: {e:?}"),
    }

    (instance_name, ips, port, txt, scope_id)
}

/// `true` for a unicast link-local IPv6 address (`fe80::/10`) — the only kind
/// that needs an interface scope id to be routable.
fn is_link_local_v6(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
}
