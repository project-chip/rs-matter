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

use crate::error::Error;
use crate::mdns::Mdns;
use libmdns::{Responder, Service};
use log::info;
use std::collections::HashMap;
use std::vec::Vec;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ServiceId {
    name: String,
    service_type: String,
    port: u16,
}

pub struct LinuxMdns {
    responder: Responder,
    services: HashMap<ServiceId, Service>,
}

impl LinuxMdns {
    pub fn new() -> Result<Self, Error> {
        let responder = Responder::new()?;

        Ok(Self {
            responder,
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

        let mut properties = Vec::new();
        for kvs in txt_kvs {
            info!("mDNS TXT key {} val {}", kvs.0, kvs.1);
            properties.push(format!("{}={}", kvs.0, kvs.1));
        }
        let properties: Vec<&str> = properties.iter().map(|entry| entry.as_str()).collect();

        let service =
            self.responder
                .register(service_type.to_owned(), name.to_owned(), port, &properties);

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

impl Mdns for LinuxMdns {
    fn add(
        &mut self,
        name: &str,
        service_type: &str,
        port: u16,
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        LinuxMdns::add(self, name, service_type, port, txt_kvs)
    }

    fn remove(&mut self, name: &str, service_type: &str, port: u16) -> Result<(), Error> {
        LinuxMdns::remove(self, name, service_type, port)
    }
}
