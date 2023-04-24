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

use core::fmt::Write;

use crate::error::Error;

pub trait Mdns {
    fn add(
        &mut self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
        service_subtypes: &[&str],
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error>;

    fn remove(&mut self, name: &str, service: &str, protocol: &str, port: u16)
        -> Result<(), Error>;
}

impl<T> Mdns for &mut T
where
    T: Mdns,
{
    fn add(
        &mut self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
        service_subtypes: &[&str],
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        (**self).add(name, service, protocol, port, service_subtypes, txt_kvs)
    }

    fn remove(
        &mut self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
    ) -> Result<(), Error> {
        (**self).remove(name, service, protocol, port)
    }
}

pub struct DummyMdns;

impl Mdns for DummyMdns {
    fn add(
        &mut self,
        _name: &str,
        _service: &str,
        _protocol: &str,
        _port: u16,
        _service_subtypes: &[&str],
        _txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        Ok(())
    }

    fn remove(
        &mut self,
        _name: &str,
        _service: &str,
        _protocol: &str,
        _port: u16,
    ) -> Result<(), Error> {
        Ok(())
    }
}

pub enum ServiceMode {
    /// The commissioned state
    Commissioned,
    /// The commissionable state with the discriminator that should be used
    Commissionable(u16),
}

/// The mDNS service handler
pub struct MdnsMgr<'a> {
    /// Vendor ID
    vid: u16,
    /// Product ID
    pid: u16,
    /// Device name
    device_name: heapless::String<32>,
    /// Matter port
    matter_port: u16,
    /// mDns service
    mdns: &'a mut dyn Mdns,
}

impl<'a> MdnsMgr<'a> {
    pub fn new(
        vid: u16,
        pid: u16,
        device_name: &str,
        matter_port: u16,
        mdns: &'a mut dyn Mdns,
    ) -> Self {
        Self {
            vid,
            pid,
            device_name: device_name.chars().take(32).collect(),
            matter_port,
            mdns,
        }
    }

    /// Publish an mDNS service
    /// name - is the service name (comma separated subtypes may follow)
    /// mode - the current service mode
    #[allow(clippy::needless_pass_by_value)]
    pub fn publish_service(&mut self, name: &str, mode: ServiceMode) -> Result<(), Error> {
        match mode {
            ServiceMode::Commissioned => {
                self.mdns
                    .add(name, "_matter", "_tcp", self.matter_port, &[], &[])
            }
            ServiceMode::Commissionable(discriminator) => {
                let discriminator_str = Self::get_discriminator_str(discriminator);
                let vp = self.get_vp();

                let txt_kvs = [
                    ("D", discriminator_str.as_str()),
                    ("CM", "1"),
                    ("DN", self.device_name.as_str()),
                    ("VP", &vp),
                    ("SII", "5000"), /* Sleepy Idle Interval */
                    ("SAI", "300"),  /* Sleepy Active Interval */
                    ("PH", "33"),    /* Pairing Hint */
                    ("PI", ""),      /* Pairing Instruction */
                ];

                self.mdns.add(
                    name,
                    "_matterc",
                    "_udp",
                    self.matter_port,
                    &[
                        &self.get_long_service_subtype(discriminator),
                        &self.get_short_service_type(discriminator),
                    ],
                    &txt_kvs,
                )
            }
        }
    }

    pub fn unpublish_service(&mut self, name: &str, mode: ServiceMode) -> Result<(), Error> {
        match mode {
            ServiceMode::Commissioned => {
                self.mdns.remove(name, "_matter", "_tcp", self.matter_port)
            }
            ServiceMode::Commissionable(_) => {
                self.mdns.remove(name, "_matterc", "_udp", self.matter_port)
            }
        }
    }

    fn get_long_service_subtype(&self, discriminator: u16) -> heapless::String<32> {
        let mut serv_type = heapless::String::new();
        write!(&mut serv_type, "_L{}", discriminator).unwrap();

        serv_type
    }

    fn get_short_service_type(&self, discriminator: u16) -> heapless::String<32> {
        let short = Self::compute_short_discriminator(discriminator);

        let mut serv_type = heapless::String::new();
        write!(&mut serv_type, "_S{}", short).unwrap();

        serv_type
    }

    fn get_discriminator_str(discriminator: u16) -> heapless::String<5> {
        discriminator.into()
    }

    fn get_vp(&self) -> heapless::String<11> {
        let mut vp = heapless::String::new();

        write!(&mut vp, "{}+{}", self.vid, self.pid).unwrap();

        vp
    }

    fn compute_short_discriminator(discriminator: u16) -> u16 {
        const SHORT_DISCRIMINATOR_MASK: u16 = 0xF00;
        const SHORT_DISCRIMINATOR_SHIFT: u16 = 8;

        (discriminator & SHORT_DISCRIMINATOR_MASK) >> SHORT_DISCRIMINATOR_SHIFT
    }
}

#[cfg(all(feature = "std", feature = "astro-dnssd"))]
pub mod astro {
    use std::collections::HashMap;

    use super::Mdns;
    use crate::error::Error;
    use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService};
    use log::info;

    #[derive(Debug, Clone, Eq, PartialEq, Hash)]
    pub struct ServiceId {
        name: String,
        service: String,
        protocol: String,
        port: u16,
    }

    pub struct AstroMdns {
        services: HashMap<ServiceId, RegisteredDnsService>,
    }

    impl AstroMdns {
        pub fn new() -> Result<Self, Error> {
            Ok(Self {
                services: HashMap::new(),
            })
        }

        pub fn add(
            &mut self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
            service_subtypes: &[&str],
            txt_kvs: &[(&str, &str)],
        ) -> Result<(), Error> {
            info!(
                "Registering mDNS service {}/{}.{} [{:?}]/{}",
                name, service, protocol, service_subtypes, port
            );

            let _ = self.remove(name, service, protocol, port);

            let composite_service_type = if !service_subtypes.is_empty() {
                format!("{}.{},{}", service, protocol, service_subtypes.join(","))
            } else {
                format!("{}.{}", service, protocol)
            };

            let mut builder = DNSServiceBuilder::new(&composite_service_type, port).with_name(name);

            for kvs in txt_kvs {
                info!("mDNS TXT key {} val {}", kvs.0, kvs.1);
                builder = builder.with_key_value(kvs.0.to_string(), kvs.1.to_string());
            }

            let svc = builder.register().map_err(|_| Error::MdnsError)?;

            self.services.insert(
                ServiceId {
                    name: name.into(),
                    service: service.into(),
                    protocol: protocol.into(),
                    port,
                },
                svc,
            );

            Ok(())
        }

        pub fn remove(
            &mut self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
        ) -> Result<(), Error> {
            let id = ServiceId {
                name: name.into(),
                service: service.into(),
                protocol: protocol.into(),
                port,
            };

            if self.services.remove(&id).is_some() {
                info!(
                    "Deregistering mDNS service {}/{}.{}/{}",
                    name, service, protocol, port
                );
            }

            Ok(())
        }
    }

    impl Mdns for AstroMdns {
        fn add(
            &mut self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
            service_subtypes: &[&str],
            txt_kvs: &[(&str, &str)],
        ) -> Result<(), Error> {
            AstroMdns::add(
                self,
                name,
                service,
                protocol,
                port,
                service_subtypes,
                txt_kvs,
            )
        }

        fn remove(
            &mut self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
        ) -> Result<(), Error> {
            AstroMdns::remove(self, name, service, protocol, port)
        }
    }
}

// TODO: Maybe future
// #[cfg(all(feature = "std", feature = "zeroconf"))]
// pub mod zeroconf {
//     use std::collections::HashMap;

//     use super::Mdns;
//     use crate::error::Error;
//     use log::info;
//     use zeroconf::prelude::*;
//     use zeroconf::{MdnsService, ServiceType, TxtRecord};

//     #[derive(Debug, Clone, Eq, PartialEq, Hash)]
//     pub struct ServiceId {
//         name: String,
//         service: String,
//         protocol: String,
//         port: u16,
//     }

//     pub struct ZeroconfMdns {
//         services: HashMap<ServiceId, MdnsService>,
//     }

//     impl ZeroconfMdns {
//         pub fn new() -> Result<Self, Error> {
//             Ok(Self {
//                 services: HashMap::new(),
//             })
//         }

//         pub fn add(
//             &mut self,
//             name: &str,
//             service: &str,
//             protocol: &str,
//             port: u16,
//             service_subtypes: &[&str],
//             txt_kvs: &[(&str, &str)],
//         ) -> Result<(), Error> {
//             info!(
//                 "Registering mDNS service {}/{}.{} [{:?}]/{}",
//                 name, service, protocol, service_subtypes, port
//             );

//             let _ = self.remove(name, service, protocol, port);

//             let mut svc = MdnsService::new(
//                 ServiceType::with_sub_types(service, protocol, service_subtypes.into()).unwrap(),
//                 port,
//             );

//             let mut txt = TxtRecord::new();

//             for kvs in txt_kvs {
//                 info!("mDNS TXT key {} val {}", kvs.0, kvs.1);
//                 txt.insert(kvs.0, kvs.1);
//             }

//             svc.set_txt_record(txt);

//             //let event_loop = svc.register().map_err(|_| Error::MdnsError)?;

//             self.services.insert(
//                 ServiceId {
//                     name: name.into(),
//                     service: service.into(),
//                     protocol: protocol.into(),
//                     port,
//                 },
//                 svc,
//             );

//             Ok(())
//         }

//         pub fn remove(
//             &mut self,
//             name: &str,
//             service: &str,
//             protocol: &str,
//             port: u16,
//         ) -> Result<(), Error> {
//             let id = ServiceId {
//                 name: name.into(),
//                 service: service.into(),
//                 protocol: protocol.into(),
//                 port,
//             };

//             if self.services.remove(&id).is_some() {
//                 info!(
//                     "Deregistering mDNS service {}.{}/{}/{}",
//                     name, service, protocol, port
//                 );
//             }

//             Ok(())
//         }
//     }

//     impl Mdns for ZeroconfMdns {
//         fn add(
//             &mut self,
//             name: &str,
//             service: &str,
//             protocol: &str,
//             port: u16,
//             service_subtypes: &[&str],
//             txt_kvs: &[(&str, &str)],
//         ) -> Result<(), Error> {
//             ZeroconfMdns::add(
//                 self,
//                 name,
//                 service,
//                 protocol,
//                 port,
//                 service_subtypes,
//                 txt_kvs,
//             )
//         }

//         fn remove(
//             &mut self,
//             name: &str,
//             service: &str,
//             protocol: &str,
//             port: u16,
//         ) -> Result<(), Error> {
//             ZeroconfMdns::remove(self, name, service, protocol, port)
//         }
//     }
// }

#[cfg(feature = "std")]
pub mod libmdns {
    use super::Mdns;
    use crate::error::Error;
    use libmdns::{Responder, Service};
    use log::info;
    use std::collections::HashMap;
    use std::vec::Vec;

    #[derive(Debug, Clone, Eq, PartialEq, Hash)]
    pub struct ServiceId {
        name: String,
        service: String,
        protocol: String,
        port: u16,
    }

    pub struct LibMdns {
        responder: Responder,
        services: HashMap<ServiceId, Service>,
    }

    impl LibMdns {
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
            service: &str,
            protocol: &str,
            port: u16,
            txt_kvs: &[(&str, &str)],
        ) -> Result<(), Error> {
            info!(
                "Registering mDNS service {}/{}.{}/{}",
                name, service, protocol, port
            );

            let _ = self.remove(name, service, protocol, port);

            let mut properties = Vec::new();
            for kvs in txt_kvs {
                info!("mDNS TXT key {} val {}", kvs.0, kvs.1);
                properties.push(format!("{}={}", kvs.0, kvs.1));
            }
            let properties: Vec<&str> = properties.iter().map(|entry| entry.as_str()).collect();

            let svc = self.responder.register(
                format!("{}.{}", service, protocol),
                name.to_owned(),
                port,
                &properties,
            );

            self.services.insert(
                ServiceId {
                    name: name.into(),
                    service: service.into(),
                    protocol: protocol.into(),
                    port,
                },
                svc,
            );

            Ok(())
        }

        pub fn remove(
            &mut self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
        ) -> Result<(), Error> {
            let id = ServiceId {
                name: name.into(),
                service: service.into(),
                protocol: protocol.into(),
                port,
            };

            if self.services.remove(&id).is_some() {
                info!(
                    "Deregistering mDNS service {}/{}.{}/{}",
                    name, service, protocol, port
                );
            }

            Ok(())
        }
    }

    impl Mdns for LibMdns {
        fn add(
            &mut self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
            _service_subtypes: &[&str],
            txt_kvs: &[(&str, &str)],
        ) -> Result<(), Error> {
            LibMdns::add(self, name, service, protocol, port, txt_kvs)
        }

        fn remove(
            &mut self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
        ) -> Result<(), Error> {
            LibMdns::remove(self, name, service, protocol, port)
        }
    }
}

// TODO: Maybe future
// #[cfg(feature = "std")]
// pub mod simplemdns {
//     use std::net::Ipv4Addr;

//     use crate::error::Error;
//     use super::Mdns;
//     use log::info;
//     use simple_dns::{
//         rdata::{RData, A, SRV, TXT, PTR},
//         CharacterString, Name, ResourceRecord, CLASS,
//     };
//     use simple_mdns::sync_discovery::SimpleMdnsResponder;

//     #[derive(Debug, Clone, Eq, PartialEq, Hash)]
//     pub struct ServiceId {
//         name: String,
//         service_type: String,
//         port: u16,
//     }

//     pub struct SimpleMdns {
//         responder: SimpleMdnsResponder,
//     }

//     impl SimpleMdns {
//         pub fn new() -> Result<Self, Error> {
//             Ok(Self {
//                 responder: Default::default(),
//             })
//         }

//         pub fn add(
//             &mut self,
//             name: &str,
//             service_type: &str,
//             port: u16,
//             txt_kvs: &[(&str, &str)],
//         ) -> Result<(), Error> {
//             info!(
//                 "Registering mDNS service {}/{}/{}",
//                 name, service_type, port
//             );

//             let _ = self.remove(name, service_type, port);

//             let mut txt = TXT::new();
//             for kvs in txt_kvs {
//                 info!("mDNS TXT key {} val {}", kvs.0, kvs.1);

//                 let string = format!("{}={}", kvs.0, kvs.1);
//                 txt.add_char_string(
//                     CharacterString::new(string.as_bytes())
//                         .unwrap()
//                         .into_owned(),
//                 );
//             }

//             let name = Name::new_unchecked(name).into_owned();
//             let service_type = Name::new_unchecked(service_type).into_owned();

//             self.responder.add_resource(ResourceRecord::new(
//                 name.clone(),
//                 CLASS::IN,
//                 10,
//                 RData::A(A {
//                     address: Ipv4Addr::new(192, 168, 10, 189).into(),
//                 }),
//             ));

//             self.responder.add_resource(ResourceRecord::new(
//                 name.clone(),
//                 CLASS::IN,
//                 10,
//                 RData::SRV(SRV {
//                     port: port,
//                     priority: 0,
//                     weight: 0,
//                     target: service_type.clone(),
//                 }),
//             ));

//             self.responder.add_resource(ResourceRecord::new(
//                 srv_name.clone(),
//                 CLASS::IN,
//                 10,
//                 RData::PTR(PTR(srv_name.clone()),
//             )));

//             self.responder.add_resource(ResourceRecord::new(
//                 srv_name,
//                 CLASS::IN,
//                 10,
//                 RData::TXT(txt),
//             ));

//             Ok(())
//         }

//         pub fn remove(&mut self, name: &str, service_type: &str, port: u16) -> Result<(), Error> {
//             // TODO
//             // let id = ServiceId {
//             //     name: name.into(),
//             //     service_type: service_type.into(),
//             //     port,
//             // };

//             // if self.responder.remove_resource_record(resource).remove(&id).is_some() {
//             //     info!(
//             //         "Deregistering mDNS service {}/{}/{}",
//             //         name, service_type, port
//             //     );
//             // }

//             Ok(())
//         }
//     }

//     impl Mdns for SimpleMdns {
//         fn add(
//             &mut self,
//             name: &str,
//             service_type: &str,
//             port: u16,
//             _service_subtypes: &[&str],
//             txt_kvs: &[(&str, &str)],
//         ) -> Result<(), Error> {
//             SimpleMdns::add(self, name, service_type, port, txt_kvs)
//         }

//         fn remove(&mut self, name: &str, service_type: &str, port: u16) -> Result<(), Error> {
//             SimpleMdns::remove(self, name, service_type, port)
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_compute_short_discriminator() {
        let discriminator: u16 = 0b0000_1111_0000_0000;
        let short = MdnsMgr::compute_short_discriminator(discriminator);
        assert_eq!(short, 0b1111);

        let discriminator: u16 = 840;
        let short = MdnsMgr::compute_short_discriminator(discriminator);
        assert_eq!(short, 3);
    }
}
