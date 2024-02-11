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

use crate::{data_model::cluster_basic_information::BasicInfoConfig, error::Error};

#[cfg(all(feature = "std", target_os = "macos"))]
pub mod astro;
pub mod builtin;
pub mod proto;
#[cfg(all(feature = "std", feature = "zeroconf", target_os = "linux"))]
pub mod zeroconf;

pub trait Mdns {
    fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error>;
    fn remove(&self, service: &str) -> Result<(), Error>;
}

impl<T> Mdns for &mut T
where
    T: Mdns,
{
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
    fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        (**self).add(service, mode)
    }

    fn remove(&self, service: &str) -> Result<(), Error> {
        (**self).remove(service)
    }
}

#[cfg(not(all(feature = "std", target_os = "macos")))]
pub use builtin::MdnsService;

pub struct DummyMdns;

impl Mdns for DummyMdns {
    fn add(&self, _service: &str, _mode: ServiceMode) -> Result<(), Error> {
        Ok(())
    }

    fn remove(&self, _service: &str) -> Result<(), Error> {
        Ok(())
    }
}

pub type Service<'a> = proto::Service<'a>;

#[derive(Debug, Clone, Eq, PartialEq)]
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
                txt_kvs: &[],
            }),
            ServiceMode::Commissionable(discriminator) => {
                let discriminator_str = Self::get_discriminator_str(*discriminator);
                let vp = Self::get_vp(dev_att.vid, dev_att.pid);

                let txt_kvs = &[
                    ("D", discriminator_str.as_str()),
                    ("CM", "1"),
                    ("DN", dev_att.device_name),
                    ("VP", &vp),
                    ("SII", "5000"), /* Sleepy Idle Interval */
                    ("SAI", "300"),  /* Sleepy Active Interval */
                    ("PH", "33"),    /* Pairing Hint */
                    ("PI", ""),      /* Pairing Instruction */
                ];

                f(&Service {
                    name,
                    service: "_matterc",
                    protocol: "_udp",
                    port: matter_port,
                    service_subtypes: &[
                        &Self::get_long_service_subtype(*discriminator),
                        &Self::get_short_service_type(*discriminator),
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
