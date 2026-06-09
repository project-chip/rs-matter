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
use crate::transport::network::mdns::MdnsRemoteService;
use crate::transport::network::MatterLocalService;
use crate::utils::select::Coalesce;
use crate::utils::zbus_proxies::avahi::entry_group::EntryGroupProxy;
use crate::utils::zbus_proxies::avahi::server2::Server2Proxy;
use crate::utils::zbus_proxies::avahi::service_browser::ServiceBrowserProxy;
use crate::Matter;

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
    /// Concurrently (a) publishes the local Matter services and keeps them in
    /// sync, and (b) services
    /// [`Transport::browse_commissionable`](crate::transport::Transport::browse_commissionable)
    /// requests by browsing via Avahi and depositing matches.
    ///
    /// # Arguments
    /// - `matter`: A reference to the Matter instance to get mDNS services from.
    pub async fn run(&mut self, matter: &Matter<'_>) -> Result<(), Error> {
        let connection = self.connection.clone();

        let mut responder = pin!(self.run_responder(matter));
        let mut browse = pin!(Self::run_browse(matter, &connection));
        let mut resolve = pin!(Self::run_resolve(matter, &connection));

        select3(&mut responder, &mut browse, &mut resolve)
            .coalesce()
            .await
    }

    /// Service operational-resolve requests via Avahi over DBus.
    ///
    /// Resolves the requested instance (`name`/`type`/`local`) and deposits the
    /// address + MRP params; retries (with a yield) while the resolve is still in
    /// flight, since the target may not have answered yet.
    async fn run_resolve(matter: &Matter<'_>, connection: &Connection) -> Result<(), Error> {
        loop {
            let service = matter.transport().wait_mdns_resolve_request().await;

            let mut name_buf: heapless::String<128> = heapless::String::new();
            service.instance_name(&mut name_buf);
            let label = name_buf
                .split('.')
                .next()
                .unwrap_or(name_buf.as_str())
                .to_string();
            let service_type = service.service_type();

            let avahi = Server2Proxy::new(connection).await?;

            while matter.transport().mdns_resolve_in_flight() {
                match avahi
                    .resolve_service(
                        AVAHI_IF_UNSPEC,
                        AVAHI_PROTO_UNSPEC,
                        &label,
                        service_type,
                        "local",
                        AVAHI_PROTO_UNSPEC,
                        0,
                    )
                    .await
                {
                    Ok((
                        _if,
                        _proto,
                        _name,
                        _type,
                        _domain,
                        _host,
                        _ap,
                        address,
                        port,
                        txt,
                        _fl,
                    )) => {
                        if let Ok(ip) = address.parse::<IpAddr>() {
                            let mut txt_pairs: Vec<(&str, &str)> = Vec::new();
                            for entry in &txt {
                                if let Ok(s) = core::str::from_utf8(entry) {
                                    match s.find('=') {
                                        Some(eq) => txt_pairs.push((&s[..eq], &s[eq + 1..])),
                                        None => txt_pairs.push((s, "")),
                                    }
                                }
                            }
                            // Match is by the full instance name we requested.
                            matter
                                .transport()
                                .try_deposit_mdns_resolve(&MdnsRemoteService {
                                    instance_name: name_buf.as_str(),
                                    port: Some(port),
                                    addrs: core::iter::once(ip),
                                    txt: txt_pairs.iter().copied(),
                                });
                        }
                    }
                    Err(e) => debug!("Avahi resolve of {} failed: {:?}", label, e),
                }

                Timer::after(Duration::from_millis(BROWSE_POLL_INTERVAL_MS)).await;
            }
        }
    }

    /// Publish the local Matter services and keep them in sync with the stack.
    async fn run_responder(&mut self, matter: &Matter<'_>) -> Result<(), Error> {
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

            while matter.transport().mdns_browse_in_flight() {
                let item = pin!(item_new_stream.next());
                let tick = pin!(Timer::after(Duration::from_millis(BROWSE_POLL_INTERVAL_MS)));

                let signal = match select(item, tick).await {
                    Either::First(Some(signal)) => signal,
                    Either::First(None) => break, // browser stream ended
                    Either::Second(_) => continue, // re-check in-flight
                };

                let Ok(args) = signal.args() else { continue };

                if let Ok((
                    _if,
                    _proto,
                    name,
                    _type,
                    _domain,
                    _host,
                    _ap,
                    address,
                    port,
                    txt,
                    _fl,
                )) = avahi
                    .resolve_service(
                        args.interface,
                        args.protocol,
                        args.name,
                        args.type_,
                        args.domain,
                        AVAHI_PROTO_UNSPEC,
                        0,
                    )
                    .await
                {
                    let Ok(ip) = address.parse::<IpAddr>() else {
                        warn!("Could not parse IP address: {}", address);
                        continue;
                    };

                    let mut txt_pairs: Vec<(&str, &str)> = Vec::new();
                    for entry in &txt {
                        if let Ok(s) = core::str::from_utf8(entry) {
                            match s.find('=') {
                                Some(eq) => txt_pairs.push((&s[..eq], &s[eq + 1..])),
                                None => txt_pairs.push((s, "")),
                            }
                        }
                    }

                    matter
                        .transport()
                        .try_deposit_mdns_browse(&MdnsRemoteService {
                            instance_name: &name,
                            port: Some(port),
                            addrs: core::iter::once(ip),
                            txt: txt_pairs.iter().copied(),
                        });
                }
            }

            if let Err(e) = browser.free().await {
                warn!("Failed to free Avahi browser: {:?}", e);
            }
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
        let (service, _) = service.service(matter.dev_det(), matter.port(), &mut buf)?;

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
