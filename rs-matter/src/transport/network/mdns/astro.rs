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

//! An mDNS implementation (responder only!) based on the `asto-dnssd` crate.
//! (On Linux requires the Avahi daemon to be installed and running; does not work with `systemd-resolved`.)

use std::collections::{HashMap, HashSet};

use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService};

use crate::crypto::Crypto;
use crate::dm::ChangeNotify;
use crate::error::{Error, ErrorCode};
use crate::transport::network::mdns::Service;
use crate::{Matter, MatterMdnsService};

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
