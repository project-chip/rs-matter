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

use std::collections::HashMap;

use crate::{error::Error, mdns::Mdns};
use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService};
use log::info;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ServiceId {
    name: String,
    service_type: String,
    port: u16,
}

pub struct MacOsMdns {
    services: HashMap<RegisteredDnsService, RegisteredDnsService>,
}

impl MacOsMdns {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            services: HashMap::new(),
        })
    }

    pub fn add(
        &mut self,
        name: &str,
        service_type: &str,
        port: u16,
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        info!(
            "Registering mDNS service {}/{}/{}",
            name, service_type, port
        );

        let _ = self.remove(name, service_type, port);

        let mut builder = DNSServiceBuilder::new(service_type, port).with_name(name);

        for kvs in txt_kvs {
            info!("mDNS TXT key {} val {}", kvs.0, kvs.1);
            builder = builder.with_key_value(kvs.0.to_string(), kvs.1.to_string());
        }

        let service = builder.register().map_err(|_| Error::MdnsError)?;

        self.services.insert(
            ServiceId {
                name: name.into(),
                service_type: service_type.into(),
                port,
            },
            service,
        );

        Ok(())
    }

    pub fn remove(&mut self, name: &str, service_type: &str, port: u16) -> Result<(), Error> {
        let id = ServiceId {
            name: name.into(),
            service_type: service_type.into(),
            port,
        };

        if self.services.remove(&id).is_some() {
            info!(
                "Deregistering mDNS service {}/{}/{}",
                name, service_type, port
            );
        }

        Ok(())
    }
}

impl Mdns for MacOsMdns {
    fn add(
        &mut self,
        name: &str,
        service_type: &str,
        port: u16,
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        MacOsMdns::add(self, name, service_type, port, txt_kvs)
    }

    fn remove(&mut self, name: &str, service_type: &str, port: u16) -> Result<(), Error> {
        MacOsMdns::remove(self, name, service_type, port)
    }
}
