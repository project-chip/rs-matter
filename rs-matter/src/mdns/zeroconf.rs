use std::collections::BTreeMap;
use std::sync::mpsc::{sync_channel, SyncSender};

use zeroconf::{prelude::TEventLoop, service::TMdnsService, txt_record::TTxtRecord, ServiceType};

use crate::dm::basic_info::BasicInfoConfig;
use crate::error::{Error, ErrorCode};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};

use super::ServiceMode;

struct MdnsEntry(SyncSender<()>);

impl Drop for MdnsEntry {
    fn drop(&mut self) {
        if let Err(e) = self.0.send(()) {
            error!("Deregistering mDNS entry failed: {}", debug2format!(e));
        }
    }
}

pub struct MdnsImpl<'a> {
    dev_det: &'a BasicInfoConfig<'a>,
    matter_port: u16,
    services: RefCell<BTreeMap<String, MdnsEntry>>,
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
            let service_name = service.service.strip_prefix('_').unwrap_or(service.service);
            let protocol = service
                .protocol
                .strip_prefix('_')
                .unwrap_or(service.protocol);

            let service_type = if !service.service_subtypes.is_empty() {
                let subtypes = service
                    .service_subtypes
                    .iter()
                    .map(|subtype| subtype.strip_prefix('_').unwrap_or(*subtype))
                    .collect();

                ServiceType::with_sub_types(service_name, protocol, subtypes)
            } else {
                ServiceType::new(service_name, protocol)
            }
            .map_err(|err| {
                error!(
                    "Encountered error building service type: {}",
                    err.to_string()
                );
                ErrorCode::MdnsError
            })?;

            let (sender, receiver) = sync_channel(1);

            let service_port = service.port;
            let mut txt_kvs = vec![];
            for (k, v) in service.txt_kvs {
                txt_kvs.push((k.to_string(), v.to_string()));
            }

            let name_copy = name.to_owned();

            std::thread::spawn(move || {
                let mut mdns_service = zeroconf::MdnsService::new(service_type, service_port);

                let mut txt_record = zeroconf::TxtRecord::new();
                for (k, v) in txt_kvs {
                    debug!("mDNS TXT key {} val {}", k, v);
                    if let Err(err) = txt_record.insert(&k, &v) {
                        error!(
                            "Encountered error inserting kv-pair into txt record {}",
                            err.to_string()
                        );
                    }
                }
                mdns_service.set_name(&name_copy);
                mdns_service.set_txt_record(txt_record);
                mdns_service.set_registered_callback(Box::new(|_, _| {}));

                match mdns_service.register() {
                    Ok(event_loop) => loop {
                        if let Ok(()) = receiver.try_recv() {
                            break;
                        }
                        if let Err(err) = event_loop.poll(std::time::Duration::from_secs(1)) {
                            error!(
                                "Failed to poll mDNS service event loop: {}",
                                err.to_string()
                            );
                            break;
                        }
                    },
                    Err(err) => error!(
                        "Encountered error registering mDNS service: {}",
                        err.to_string()
                    ),
                }
            });

            self.services
                .borrow_mut()
                .insert(name.to_owned(), MdnsEntry(sender));

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
