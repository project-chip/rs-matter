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

//! An mDNS implementation based on the `astro-dnssd` crate.
//! Supports both service advertisement (responder) and service discovery (querier).
//! (On Linux requires the Avahi daemon to be installed and running; does not work with `systemd-resolved`.)

use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService, ServiceBrowserBuilder};

use std::collections::{HashMap, HashSet};
use std::net::ToSocketAddrs;
use std::time::Duration;

use crate::crypto::Crypto;
use crate::dm::ChangeNotify;
use crate::error::{Error, ErrorCode};
use crate::transport::network::mdns::Service;
use crate::{Matter, MatterMdnsService};

use super::{CommissionableFilter, DiscoveredDevice, PushUnique};

/// An mDNS responder for Matter utilizing the `astro-dnssd` crate.
/// In theory, it should work on all of Linux, MacOS and Windows, however only known to work on MacOSX.
///
/// NOTE: For Linux, you need to install the avahi-compat libraries. E.g., on Ubuntu:
/// `sudo apt install -y libavahi-compat-libdnssd-dev libavahi-compat-libdnssd1`
pub struct AstroMdnsResponder<'a> {
    matter: &'a Matter<'a>,
    services: HashMap<MatterMdnsService, RegisteredDnsService>,
}

impl<'a> AstroMdnsResponder<'a> {
    /// Create a new `AstroMdnsResponder` for the given `Matter` instance.
    pub fn new(matter: &'a Matter<'a>) -> Self {
        Self {
            matter,
            services: HashMap::new(),
        }
    }

    /// Run the mDNS responder
    ///
    /// # Arguments
    /// - `crypto`: A crypto provider instance.
    /// - `notify`: A change notification interface.
    pub async fn run<C: Crypto>(
        &mut self,
        crypto: C,
        notify: &dyn ChangeNotify,
    ) -> Result<(), Error> {
        loop {
            self.matter.wait_mdns().await;

            let mut services = HashSet::new();
            self.matter.mdns_services(&crypto, notify, |service| {
                services.insert(service);

                Ok(())
            })?;

            info!("mDNS services changed, updating...");

            self.update_services(&services).await?;

            info!("mDNS services updated");
        }
    }

    async fn update_services(
        &mut self,
        services: &HashSet<MatterMdnsService>,
    ) -> Result<(), Error> {
        for service in services {
            if !self.services.contains_key(service) {
                info!("Registering mDNS service: {:?}", service);
                let registered = self.register(service)?;
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

    fn register(&mut self, service: &MatterMdnsService) -> Result<RegisteredDnsService, Error> {
        Service::call_with(
            service,
            self.matter.dev_det(),
            self.matter.port(),
            |service| {
                let composite_service_type = if !service.service_subtypes.is_empty() {
                    format!(
                        "{}.{},{}",
                        service.service,
                        service.protocol,
                        service.service_subtypes.join(",")
                    )
                } else {
                    format!("{}.{}", service.service, service.protocol)
                };

                let mut builder = DNSServiceBuilder::new(&composite_service_type, service.port)
                    .with_name(service.name);

                for kvs in service.txt_kvs {
                    trace!("mDNS TXT key {} val {}", kvs.0, kvs.1);
                    builder = builder.with_key_value(kvs.0.to_string(), kvs.1.to_string());
                }

                let svc = builder.register().map_err(|_| ErrorCode::MdnsError)?;

                Ok(svc)
            },
        )
    }
}

/// Discover commissionable Matter devices using the system's DNS-SD service.
///
/// This function uses the `astro-dnssd` crate which wraps the system's native
/// DNS-SD implementation (Bonjour on macOS, Avahi on Linux).
///
/// # Arguments
/// * `filter` - Filter criteria for discovered devices
/// * `timeout_ms` - Discovery timeout in milliseconds
///
/// # Returns
/// A vector of discovered devices matching the filter criteria
pub fn discover_commissionable(
    filter: &CommissionableFilter,
    timeout_ms: u32,
) -> Result<Vec<DiscoveredDevice>, Error> {
    let mut results = Vec::new();

    // Build the service type
    let mut service_type_buf: heapless::String<64> = heapless::String::new();
    filter.service_type(&mut service_type_buf, false);
    let service_type = service_type_buf.as_str();

    info!("Browsing for mDNS services: {}", service_type);

    let browser = ServiceBrowserBuilder::new(&service_type)
        .browse()
        .map_err(|e| {
            error!("Failed to create service browser: {:?}", e);
            ErrorCode::MdnsError
        })?;

    let timeout = Duration::from_millis(timeout_ms as u64);
    let start = std::time::Instant::now();

    // Poll for services until timeout
    while start.elapsed() < timeout {
        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }

        match browser.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(service) => {
                info!(
                    "Discovered service: {} on {}:{} (domain: {})",
                    service.name, service.hostname, service.port, service.domain
                );

                let mut device = DiscoveredDevice::default();
                device.set_instance_name(&service.name);
                device.port = service.port;

                let host_with_port = format!("{}:{}", service.hostname, service.port);
                let resolved = if let Ok(addrs) = host_with_port.to_socket_addrs() {
                    // Add all resolved addresses (they will be sorted by priority)
                    for addr in addrs {
                        device.add_address(addr.ip());
                    }
                    true
                } else {
                    // Try resolving just the hostname
                    let host: &str = &service.hostname;
                    if let Ok(addrs) = (host, service.port).to_socket_addrs() {
                        for addr in addrs {
                            device.add_address(addr.ip());
                        }
                        true
                    } else {
                        false
                    }
                };

                if !resolved || device.addresses().is_empty() {
                    warn!("Could not resolve hostname: {}", service.hostname);
                    continue;
                }

                if let Some(ref txt_record) = service.txt_record {
                    for (key, value) in txt_record {
                        device.set_txt_value(key, value);
                    }
                }

                if filter.matches(&device) {
                    results.push_if_unique(device);
                }
            }
            Err(astro_dnssd::BrowseError::Timeout) => {
                // Continue polling
            }
            Err(e) => {
                debug!("Browse error: {:?}", e);
                // Continue trying until timeout
            }
        }
    }

    info!("mDNS discovery found {} devices", results.len());

    Ok(results)
}
