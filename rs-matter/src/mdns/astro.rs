use std::collections::BTreeMap;

use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService};

use log::info;

use crate::data_model::cluster_basic_information::BasicInfoConfig;
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
                info!("mDNS TXT key {} val {}", kvs.0, kvs.1);
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
