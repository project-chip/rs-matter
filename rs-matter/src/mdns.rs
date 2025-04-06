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

use crate::data_model::cluster_basic_information::BasicInfoConfig;
use crate::error::Error;
use crate::utils::init::{init, Init};

#[cfg(all(feature = "std", target_os = "macos"))]
#[path = "mdns/astro.rs"]
mod builtin;
#[cfg(not(all(
    feature = "std",
    any(target_os = "macos", all(feature = "zeroconf", target_os = "linux"))
)))]
mod builtin;
#[cfg(all(feature = "std", feature = "zeroconf", target_os = "linux"))]
#[path = "mdns/zeroconf.rs"]
mod builtin;

#[cfg(not(all(
    feature = "std",
    any(target_os = "macos", all(feature = "zeroconf", target_os = "linux"))
)))]
pub use builtin::{
    Host, MDNS_IPV4_BROADCAST_ADDR, MDNS_IPV6_BROADCAST_ADDR, MDNS_PORT, MDNS_SOCKET_BIND_ADDR,
};

/// A trait representing an mDNS implementation capable of registering and de-registering Matter-specific services
pub trait Mdns {
    /// Remove all Matter-specific services registered in the responder
    fn reset(&self);

    /// Register a new service; if it is already registered, it will be updated
    fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error>;

    /// Remove a service; if service with that name is not registered, it will be ignored
    fn remove(&self, service: &str) -> Result<(), Error>;
}

impl<T> Mdns for &mut T
where
    T: Mdns,
{
    fn reset(&self) {
        (**self).reset();
    }

    fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        (**self).add(service, mode)
    }

    fn remove(&self, service: &str) -> Result<(), Error> {
        (**self).remove(service)
    }
}

impl<T> Mdns for &T
where
    T: Mdns,
{
    fn reset(&self) {
        (**self).reset();
    }

    fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        (**self).add(service, mode)
    }

    fn remove(&self, service: &str) -> Result<(), Error> {
        (**self).remove(service)
    }
}

/// Models the mDNS implementation to be used by the Matter stack
pub enum MdnsService<'a> {
    /// Don't use any mDNS implementation. Useful for unit and integration tests
    Disabled,
    /// Use the built-in mDNS implementation, which is based on:
    /// - Bonjour on macOS
    /// - Avahi on Linux (if feature `zeroconf` is enabled)
    /// - Our own pure-Rust implementation, in all other cases
    Builtin,
    /// Use an mDNS implementation provided by the user
    Provided(&'a dyn Mdns),
}

pub(crate) struct MdnsImpl<'a> {
    service: MdnsService<'a>,
    builtin: builtin::MdnsImpl<'a>,
}

impl<'a> MdnsImpl<'a> {
    pub(crate) const fn new(
        service: MdnsService<'a>,
        dev_det: &'a BasicInfoConfig<'a>,
        matter_port: u16,
    ) -> Self {
        Self {
            service,
            builtin: builtin::MdnsImpl::new(dev_det, matter_port),
        }
    }

    pub(crate) fn init(
        service: MdnsService<'a>,
        dev_det: &'a BasicInfoConfig<'a>,
        matter_port: u16,
    ) -> impl Init<Self> {
        init!(Self {
            service,
            builtin <- builtin::MdnsImpl::init(dev_det, matter_port),
        })
    }

    #[allow(unused)]
    pub(crate) fn builtin(&self) -> Option<&builtin::MdnsImpl> {
        matches!(self.service, MdnsService::Builtin).then_some(&self.builtin)
    }

    pub(crate) fn update(&mut self, service: MdnsService<'a>) {
        self.service = service;
    }
}

impl Mdns for MdnsImpl<'_> {
    fn reset(&self) {
        match self.service {
            MdnsService::Disabled => {}
            MdnsService::Builtin => self.builtin.reset(),
            MdnsService::Provided(mdns) => mdns.reset(),
        }
    }

    fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        match self.service {
            MdnsService::Disabled => Ok(()),
            MdnsService::Builtin => self.builtin.add(service, mode),
            MdnsService::Provided(mdns) => mdns.add(service, mode),
        }?;

        // Do not remove this logging line or change its formatting.
        // C++ E2E tests rely on this log line to determine when the mDNS service is published
        info!("mDNS service published: {}::{:?}", service, mode);

        Ok(())
    }

    fn remove(&self, service: &str) -> Result<(), Error> {
        match self.service {
            MdnsService::Disabled => Ok(()),
            MdnsService::Builtin => self.builtin.remove(service),
            MdnsService::Provided(mdns) => mdns.remove(service),
        }?;

        info!("mDNS service removed: {}", service);

        Ok(())
    }
}

pub struct Service<'a> {
    pub name: &'a str,
    pub service: &'a str,
    pub protocol: &'a str,
    pub port: u16,
    pub service_subtypes: &'a [&'a str],
    pub txt_kvs: &'a [(&'a str, &'a str)],
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServiceMode {
    /// The commissioned state
    Commissioned,
    /// The commissionable state with the discriminator that should be used
    Commissionable(u16),
}

impl ServiceMode {
    pub fn service<R, F: for<'a> FnOnce(&Service<'a>) -> Result<R, Error>>(
        &self,
        dev_att: &BasicInfoConfig,
        matter_port: u16,
        name: &str,
        f: F,
    ) -> Result<R, Error> {
        match self {
            Self::Commissioned => f(&Service {
                name,
                service: "_matter",
                protocol: "_tcp",
                port: matter_port,
                service_subtypes: &[],
                txt_kvs: &[("", "")],
            }),
            ServiceMode::Commissionable(discriminator) => {
                let discriminator_str = Self::get_discriminator_str(*discriminator);
                let vp = Self::get_vp(dev_att.vid, dev_att.pid);

                let mut sai_str = heapless::String::<5>::new();
                write!(sai_str, "{}", dev_att.sai.unwrap_or(300)).unwrap();

                let mut sii_str = heapless::String::<5>::new();
                write!(sii_str, "{}", dev_att.sii.unwrap_or(5000)).unwrap();

                let txt_kvs = &[
                    ("D", discriminator_str.as_str()),
                    ("CM", "1"),
                    ("DN", dev_att.device_name),
                    ("VP", &vp),
                    ("SAI", sai_str.as_str()), // Session Active Interval
                    ("SII", sii_str.as_str()), // Session Idle Interval
                    ("PH", "33"),              // Pairing Hint
                    ("PI", ""),                // Pairing Instruction
                ];

                f(&Service {
                    name,
                    service: "_matterc",
                    protocol: "_udp",
                    port: matter_port,
                    service_subtypes: &[
                        &Self::get_long_service_subtype(*discriminator),
                        &Self::get_short_service_type(*discriminator),
                        "_CM",
                    ],
                    txt_kvs,
                })
            }
        }
    }

    fn get_long_service_subtype(discriminator: u16) -> heapless::String<32> {
        let mut serv_type = heapless::String::new();
        write!(&mut serv_type, "_L{}", discriminator).unwrap();

        serv_type
    }

    fn get_short_service_type(discriminator: u16) -> heapless::String<32> {
        let short = Self::compute_short_discriminator(discriminator);

        let mut serv_type = heapless::String::new();
        write!(&mut serv_type, "_S{}", short).unwrap();

        serv_type
    }

    fn get_discriminator_str(discriminator: u16) -> heapless::String<5> {
        discriminator.try_into().unwrap()
    }

    fn get_vp(vid: u16, pid: u16) -> heapless::String<11> {
        let mut vp = heapless::String::new();

        write!(&mut vp, "{}+{}", vid, pid).unwrap();

        vp
    }

    fn compute_short_discriminator(discriminator: u16) -> u16 {
        const SHORT_DISCRIMINATOR_MASK: u16 = 0xF00;
        const SHORT_DISCRIMINATOR_SHIFT: u16 = 8;

        (discriminator & SHORT_DISCRIMINATOR_MASK) >> SHORT_DISCRIMINATOR_SHIFT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_compute_short_discriminator() {
        let discriminator: u16 = 0b0000_1111_0000_0000;
        let short = ServiceMode::compute_short_discriminator(discriminator);
        assert_eq!(short, 0b1111);

        let discriminator: u16 = 840;
        let short = ServiceMode::compute_short_discriminator(discriminator);
        assert_eq!(short, 3);
    }
}
