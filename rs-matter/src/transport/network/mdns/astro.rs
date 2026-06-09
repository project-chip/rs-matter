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

//! An mDNS implementation based on the `astro-dnssd` crate.
//! Supports both service advertisement (responder) and service discovery (querier).
//! (On Linux requires the Avahi daemon to be installed and running; does not work with `systemd-resolved`.)

use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService, ServiceBrowserBuilder};

use embassy_futures::select::select3;
use embassy_time::Timer;

use crate::utils::select::Coalesce;

use std::collections::{HashMap, HashSet};
use std::net::ToSocketAddrs;
use std::time::Duration;

use crate::error::{Error, ErrorCode};
use crate::transport::network::mdns::{CommissionableFilter, MdnsRemoteService};
use crate::transport::network::MatterLocalService;
use crate::Matter;

/// mDNS interval (ms) between non-blocking polls of the OS browser while a
/// commissionable browse is in flight; we yield to the executor in between so
/// the Matter transport (running on the same executor) is not starved.
const BROWSE_POLL_INTERVAL_MS: u64 = 50;

/// An mDNS implementation for Matter utilizing the `astro-dnssd` crate.
/// In theory, it should work on all of Linux, MacOS and Windows, however only known to work on MacOSX.
///
/// NOTE: For Linux, you need to install the avahi-compat libraries. E.g., on Ubuntu:
/// `sudo apt install -y libavahi-compat-libdnssd-dev libavahi-compat-libdnssd1`
pub struct AstroMdns {
    services: HashMap<MatterLocalService, RegisteredDnsService>,
}

impl Default for AstroMdns {
    fn default() -> Self {
        Self::new()
    }
}

impl AstroMdns {
    /// Create a new `AstroMdns`.
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    /// Run the mDNS responder + querier.
    ///
    /// Concurrently (a) publishes the local Matter services and keeps them in
    /// sync, and (b) services [`Transport::browse_commissionable`](crate::transport::Transport::browse_commissionable)
    /// requests by browsing the system DNS-SD daemon and depositing matches.
    ///
    /// # Arguments
    /// - `matter`: A reference to the Matter instance to get mDNS services from.
    pub async fn run(&mut self, matter: &Matter<'_>) -> Result<(), Error> {
        let mut responder = core::pin::pin!(self.run_responder(matter));
        let mut browse = core::pin::pin!(Self::run_browse(matter));
        let mut resolve = core::pin::pin!(Self::run_resolve(matter));

        select3(&mut responder, &mut browse, &mut resolve)
            .coalesce()
            .await
    }

    /// Service operational-resolve requests.
    ///
    /// `astro-dnssd` has no targeted "resolve this instance" call, so we browse
    /// the requested service's type and match its instance label, then resolve
    /// the address and deposit it. Polled non-blocking with a yield, only while
    /// the resolve is in flight.
    async fn run_resolve(matter: &Matter<'_>) -> Result<(), Error> {
        loop {
            let service = matter.transport().wait_mdns_resolve_request().await;

            let mut name_buf: heapless::String<128> = heapless::String::new();
            service.instance_name(&mut name_buf);
            let label = name_buf.split('.').next().unwrap_or("").to_string();

            let browser = ServiceBrowserBuilder::new(service.service_type())
                .browse()
                .map_err(|e| {
                    error!("Failed to create service browser: {:?}", e);
                    ErrorCode::MdnsError
                })?;

            while matter.transport().mdns_resolve_in_flight() {
                match browser.recv_timeout(Duration::ZERO) {
                    Ok(svc) if svc.name == label => {
                        let host_with_port = format!("{}:{}", svc.hostname, svc.port);
                        let ip = host_with_port
                            .to_socket_addrs()
                            .ok()
                            .and_then(|mut addrs| addrs.next())
                            .map(|addr| addr.ip());

                        if let Some(ip) = ip {
                            let mut txt: Vec<(&str, &str)> = Vec::new();
                            if let Some(ref txt_record) = svc.txt_record {
                                for (key, value) in txt_record {
                                    txt.push((key, value));
                                }
                            }
                            // Match is by the full instance name we requested.
                            matter
                                .transport()
                                .try_deposit_mdns_resolve(&MdnsRemoteService {
                                    instance_name: name_buf.as_str(),
                                    port: Some(svc.port),
                                    addrs: core::iter::once(ip),
                                    txt: txt.iter().copied(),
                                });
                        }
                    }
                    Ok(_) => {} // a different instance of the same type
                    Err(astro_dnssd::BrowseError::Timeout) => {}
                    Err(e) => debug!("Browse error: {:?}", e),
                }

                Timer::after(embassy_time::Duration::from_millis(BROWSE_POLL_INTERVAL_MS)).await;
            }
        }
    }

    /// Publish the local Matter services and keep them in sync with the stack.
    async fn run_responder(&mut self, matter: &Matter<'_>) -> Result<(), Error> {
        loop {
            matter.transport().wait_mdns().await;

            let mut services = HashSet::new();
            matter.mdns_services(|service| {
                services.insert(service);

                Ok(())
            })?;

            info!("mDNS services changed, updating...");

            self.update_services(matter, &services)?;

            info!("mDNS services updated");
        }
    }

    /// Service commissionable-browse requests via the system DNS-SD daemon.
    ///
    /// `astro-dnssd` does not support subtype-filtered browse, so we browse all
    /// `_matterc._udp` services and let the deposit apply the full filter. The
    /// daemon's browser is polled non-blocking with a yield in between, and only
    /// while the browse is in flight, so the Matter transport is not starved.
    async fn run_browse(matter: &Matter<'_>) -> Result<(), Error> {
        loop {
            let _filter: CommissionableFilter = matter.transport().wait_mdns_browse_request().await;

            let browser = ServiceBrowserBuilder::new("_matterc._udp")
                .browse()
                .map_err(|e| {
                    error!("Failed to create service browser: {:?}", e);
                    ErrorCode::MdnsError
                })?;

            while matter.transport().mdns_browse_in_flight() {
                match browser.recv_timeout(Duration::ZERO) {
                    // Resolve address + TXT and deposit; the filter/exclude checks
                    // happen inside the deposit. `to_socket_addrs` is a brief
                    // blocking lookup, acceptable on the commissioning-browse path.
                    Ok(service) => {
                        let host_with_port = format!("{}:{}", service.hostname, service.port);
                        let ip = host_with_port
                            .to_socket_addrs()
                            .ok()
                            .and_then(|mut addrs| addrs.next())
                            .map(|addr| addr.ip());

                        if let Some(ip) = ip {
                            let mut txt: Vec<(&str, &str)> = Vec::new();
                            if let Some(ref txt_record) = service.txt_record {
                                for (key, value) in txt_record {
                                    txt.push((key, value));
                                }
                            }

                            matter
                                .transport()
                                .try_deposit_mdns_browse(&MdnsRemoteService {
                                    instance_name: service.name.as_str(),
                                    port: Some(service.port),
                                    addrs: core::iter::once(ip),
                                    txt: txt.iter().copied(),
                                });
                        } else {
                            warn!("Could not resolve hostname: {}", service.hostname);
                        }
                    }
                    Err(astro_dnssd::BrowseError::Timeout) => {}
                    Err(e) => debug!("Browse error: {:?}", e),
                }

                Timer::after(embassy_time::Duration::from_millis(BROWSE_POLL_INTERVAL_MS)).await;
            }
        }
    }

    fn update_services(
        &mut self,
        matter: &Matter<'_>,
        services: &HashSet<MatterLocalService>,
    ) -> Result<(), Error> {
        for service in services {
            if !self.services.contains_key(service) {
                info!("Registering mDNS service: {:?}", service);
                let registered = self.register(matter, service)?;
                self.services.insert(service.clone(), registered);
            }
        }

        loop {
            let removed = self
                .services
                .iter()
                .find(|(service, _)| !services.contains(service));

            if let Some((service, _)) = removed {
                info!("Deregistering mDNS service: {:?}", service);
                self.services.remove(&service.clone());
            } else {
                break;
            }
        }

        Ok(())
    }

    fn register(
        &mut self,
        matter: &Matter<'_>,
        service: &MatterLocalService,
    ) -> Result<RegisteredDnsService, Error> {
        // Scratch buffer for expanding `MatterLocalService` into a `MdnsLocalService` view —
        // the strings (name, subtypes, TXT values) are formatted into this buffer.
        let mut buf = [0u8; 512];
        let (service, _) = service.service(matter.dev_det(), matter.port(), &mut buf)?;

        // Materialize subtypes once: we need both `is_empty` and `join`.
        let subtypes: Vec<&str> = service.service_subtypes.clone().collect();
        let composite_service_type = if !subtypes.is_empty() {
            format!(
                "{}.{},{}",
                service.service,
                service.protocol,
                subtypes.join(",")
            )
        } else {
            format!("{}.{}", service.service, service.protocol)
        };

        let mut builder =
            DNSServiceBuilder::new(&composite_service_type, service.port).with_name(service.name);

        for (k, v) in service.txt_kvs.clone() {
            trace!("mDNS TXT key {} val {}", k, v);
            builder = builder.with_key_value(k.to_string(), v.to_string());
        }

        let svc = builder.register().map_err(|_| ErrorCode::MdnsError)?;

        Ok(svc)
    }
}
