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

//! A Linux-specific mDNS implementation based on Avahi.
//!
//! Requires the Avahi daemon to be installed and running.

use core::fmt::Write as _;
use core::pin::pin;

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::net::IpAddr;

use embassy_futures::select::{select3, Either3};
use embassy_time::{Duration, Instant, Timer};
use futures_lite::StreamExt;

use zbus::zvariant::{ObjectPath, OwnedObjectPath};
use zbus::Connection;

use crate::crypto::Crypto;
use crate::dm::ChangeNotify;
use crate::error::Error;
use crate::transport::network::mdns::Service;
use crate::utils::zbus_proxies::avahi::entry_group::EntryGroupProxy;
use crate::utils::zbus_proxies::avahi::server2::Server2Proxy;
use crate::utils::zbus_proxies::avahi::service_browser::ServiceBrowserProxy;

use super::{CommissionableFilter, DiscoveredDevice, PushUnique};
use crate::{Matter, MatterMdnsService};

/// Avahi constant for "any interface"
const AVAHI_IF_UNSPEC: i32 = -1;
/// Avahi constant for "any protocol" (IPv4 or IPv6)
const AVAHI_PROTO_UNSPEC: i32 = -1;

/// An mDNS responder for Matter utilizing the Avahi daemon over DBus.
pub struct AvahiMdnsResponder<'a> {
    matter: &'a Matter<'a>,
    services: HashMap<MatterMdnsService, OwnedObjectPath>,
}

impl<'a> AvahiMdnsResponder<'a> {
    /// Create a new instance of the Avahi mDNS responder.
    pub fn new(matter: &'a Matter<'a>) -> Self {
        Self {
            matter,
            services: HashMap::new(),
        }
    }

    /// Run the mDNS responder
    ///
    /// # Arguments
    /// - `connection`: A reference to the DBus system connection to use for communication with Avahi.
    /// - `crypto`: A crypto provider instance.
    /// - `notify`: A change notification interface.
    pub async fn run<C: Crypto>(
        &mut self,
        connection: &Connection,
        crypto: C,
        notify: &dyn ChangeNotify,
    ) -> Result<(), Error> {
        {
            let avahi = Server2Proxy::new(connection).await?;
            info!("Avahi API version: {}", avahi.get_apiversion().await?);
        }

        loop {
            self.matter.wait_mdns().await;

            let mut services = HashSet::new();
            self.matter.mdns_services(&crypto, notify, |service| {
                services.insert(service);

                Ok(())
            })?;

            info!("mDNS services changed, updating...");

            self.update_services(connection, &services).await?;

            info!("mDNS services updated");
        }
    }

    async fn update_services(
        &mut self,
        connection: &Connection,
        services: &HashSet<MatterMdnsService>,
    ) -> Result<(), Error> {
        for service in services {
            if !self.services.contains_key(service) {
                info!("Registering mDNS service: {:?}", service);
                let path = self.register(connection, service).await?;
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
                Self::deregister(connection, path.as_ref()).await?;
                self.services.remove(&service.clone());
            } else {
                break;
            }
        }

        Ok(())
    }

    async fn register(
        &mut self,
        connection: &Connection,
        service: &MatterMdnsService,
    ) -> Result<OwnedObjectPath, Error> {
        Service::async_call_with(
            service,
            self.matter.dev_det(),
            self.matter.port(),
            async |service| {
                let avahi = Server2Proxy::new(connection).await?;

                let path = avahi.entry_group_new().await?;

                let group = EntryGroupProxy::builder(connection)
                    .path(path.clone())?
                    .build()
                    .await?;

                let mut txt_buf = Vec::new();

                let offsets = service
                    .txt_kvs
                    .iter()
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

                for subtype in service.service_subtypes {
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
            },
        )
        .await
    }

    async fn deregister(connection: &Connection, path: ObjectPath<'_>) -> Result<(), Error> {
        let group = EntryGroupProxy::builder(connection)
            .path(path)?
            .build()
            .await?;

        group.free().await?;

        Ok(())
    }
}

/// Maximum number of pending services to track during discovery
const MAX_PENDING_SERVICES: usize = 16;

/// A pending service discovered via browse that needs resolution
struct PendingService {
    interface: i32,
    protocol: i32,
    name: heapless::String<64>,
    type_: heapless::String<64>,
    domain: heapless::String<64>,
}

impl PendingService {
    fn new(interface: i32, protocol: i32, name: &str, type_: &str, domain: &str) -> Self {
        let mut pending_name = heapless::String::new();
        let mut pending_type_ = heapless::String::new();
        let mut pending_domain = heapless::String::new();
        let _ = write!(&mut pending_name, "{}", name);
        let _ = write!(&mut pending_type_, "{}", type_);
        let _ = write!(&mut pending_domain, "{}", domain);

        Self {
            interface,
            protocol,
            name: pending_name,
            type_: pending_type_,
            domain: pending_domain,
        }
    }
}

/// Discover commissionable Matter devices using Avahi over DBus.
///
/// # Arguments
/// * `connection` - A reference to the DBus system connection
/// * `filter` - Filter criteria for discovered devices
/// * `timeout_ms` - Discovery timeout in milliseconds
///
/// # Returns
/// A vector of discovered devices matching the filter criteria
pub async fn discover_commissionable(
    connection: &Connection,
    filter: &CommissionableFilter,
    timeout_ms: u32,
) -> Result<Vec<DiscoveredDevice>, Error> {
    let mut results = Vec::new();

    // Build the service type query
    let mut service_type: heapless::String<64> = heapless::String::new();
    filter.service_type(&mut service_type, false);

    info!("Browsing for mDNS services via Avahi: {}", service_type);

    let avahi = Server2Proxy::new(connection).await?;

    // Create service browser
    let browser_path = avahi
        .service_browser_prepare(AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, &service_type, "", 0)
        .await?;

    let browser = ServiceBrowserProxy::builder(connection)
        .path(browser_path)?
        .build()
        .await?;

    // Set up signal stream for ItemNew events
    let mut item_new_stream = browser.receive_item_new().await?;
    let mut all_for_now_stream = browser.receive_all_for_now().await?;

    // Start the browser
    browser.start().await?;

    let timeout = Duration::from_millis(timeout_ms as u64);
    let deadline = Instant::now() + timeout;

    // Track discovered services to resolve
    let mut pending_services = Vec::new();

    // Collect discovered services until timeout or AllForNow signal
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.as_millis() == 0 {
            break;
        }

        let item_new_fut = pin!(item_new_stream.next());
        let all_for_now_fut = pin!(all_for_now_stream.next());
        let timeout_fut = pin!(Timer::after(remaining));

        match select3(item_new_fut, all_for_now_fut, timeout_fut).await {
            Either3::First(Some(signal)) => {
                if let Ok(args) = signal.args() {
                    debug!(
                        "Discovered service: {} (type: {}, domain: {})",
                        args.name, args.type_, args.domain
                    );

                    pending_services.push(PendingService::new(
                        args.interface,
                        args.protocol,
                        &args.name,
                        &args.type_,
                        &args.domain,
                    ));
                }
            }
            Either3::First(None) => {
                break;
            }
            Either3::Second(_) => {
                debug!("Received AllForNow signal");
                break;
            }
            Either3::Third(_) => {
                debug!("Browse timeout reached");
                break;
            }
        }
    }

    // Resolve each discovered service
    for pending in pending_services {
        match avahi
            .resolve_service(
                pending.interface,
                pending.protocol,
                &pending.name,
                &pending.type_,
                &pending.domain,
                AVAHI_PROTO_UNSPEC,
                0,
            )
            .await
        {
            Ok((
                _interface,
                _protocol,
                resolved_name,
                _type,
                _domain,
                _host,
                _aprotocol,
                address,
                port,
                txt,
                _flags,
            )) => {
                debug!(
                    "Resolved service: {} -> {}:{}",
                    resolved_name, address, port
                );

                let mut device = DiscoveredDevice::default();
                device.set_instance_name(&resolved_name);
                device.port = port;

                if let Ok(ip) = address.parse::<IpAddr>() {
                    device.add_address(ip);
                } else {
                    warn!("Could not parse IP address: {}", address);
                    continue;
                }

                for entry in txt {
                    if let Ok(s) = core::str::from_utf8(&entry) {
                        if let Some(eq_pos) = s.find('=') {
                            let key = &s[..eq_pos];
                            let value = &s[eq_pos + 1..];
                            device.set_txt_value(key, value);
                        }
                    }
                }

                if filter.matches(&device) {
                    results.push_if_unique(device);
                }
            }
            Err(e) => {
                warn!("Failed to resolve service {}: {:?}", pending.name, e);
            }
        }
    }

    // Clean up browser
    browser.free().await;

    info!("Avahi mDNS discovery found {} devices", results.len());

    Ok(results)
}
