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

//! A MacOS-specific mDNS implementation based on the `astro-dnssd` crate.

use std::collections::BTreeMap;

use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService};

use crate::dm::clusters::basic_info::BasicInfoConfig;
use crate::error::{Error, ErrorCode};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};

use super::ServiceMode;

pub struct MdnsImpl<'a> {
    dev_det: &'a BasicInfoConfig<'a>,
    matter_port: u16,
    services: RefCell<BTreeMap<String, RegisteredDnsService>>,
}

impl<'a> MdnsImpl<'a> {
    pub const fn new(dev_det: &'a BasicInfoConfig<'a>, matter_port: u16) -> Self {
        Self {
            dev_det,
            matter_port,
            services: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn init(dev_det: &'a BasicInfoConfig<'a>, matter_port: u16) -> impl Init<Self> {
        init!(Self {
            dev_det,
            matter_port,
            services <- RefCell::init(BTreeMap::new()),
        })
    }

    pub fn reset(&self) {
        self.services.borrow_mut().clear();
    }

    pub fn add(&self, name: &str, mode: ServiceMode) -> Result<(), Error> {
        let _ = self.remove(name);

        info!("Registering mDNS service {}/{:?}", name, mode);

        mode.service(self.dev_det, self.matter_port, name, |service| {
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
                debug!("mDNS TXT key {} val {}", kvs.0, kvs.1);
                builder = builder.with_key_value(kvs.0.to_string(), kvs.1.to_string());
            }

            let svc = builder.register().map_err(|_| ErrorCode::MdnsError)?;

            self.services.borrow_mut().insert(service.name.into(), svc);

            Ok(())
        })
    }

    pub fn remove(&self, name: &str) -> Result<(), Error> {
        if self.services.borrow_mut().remove(name).is_some() {
            info!("Deregistering mDNS service {}", name);
        }

        Ok(())
    }
}
