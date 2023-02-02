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
        service_type: &str,
        port: u16,
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error>;

    fn remove(&mut self, name: &str, service_type: &str, port: u16) -> Result<(), Error>;
}

impl<T> Mdns for &mut T
where
    T: Mdns,
{
    fn add(
        &mut self,
        name: &str,
        service_type: &str,
        port: u16,
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        (**self).add(name, service_type, port, txt_kvs)
    }

    fn remove(&mut self, name: &str, service_type: &str, port: u16) -> Result<(), Error> {
        (**self).remove(name, service_type, port)
    }
}

pub struct DummyMdns;

impl Mdns for DummyMdns {
    fn add(
        &mut self,
        _name: &str,
        _service_type: &str,
        _port: u16,
        _txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        Ok(())
    }

    fn remove(&mut self, _name: &str, _service_type: &str, _port: u16) -> Result<(), Error> {
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
            ServiceMode::Commissioned => self.mdns.add(name, "_matter._tcp", self.matter_port, &[]),
            ServiceMode::Commissionable(discriminator) => {
                let discriminator_str = Self::get_discriminator_str(discriminator);

                let serv_type = self.get_service_type(discriminator);
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
                self.mdns.add(name, &serv_type, self.matter_port, &txt_kvs)
            }
        }
    }

    pub fn unpublish_service(&mut self, name: &str, mode: ServiceMode) -> Result<(), Error> {
        match mode {
            ServiceMode::Commissioned => self.mdns.remove(name, "_matter._tcp", self.matter_port),
            ServiceMode::Commissionable(discriminator) => {
                let serv_type = self.get_service_type(discriminator);

                self.mdns.remove(name, &serv_type, self.matter_port)
            }
        }
    }

    fn get_service_type(&self, discriminator: u16) -> heapless::String<32> {
        let short = Self::compute_short_discriminator(discriminator);
        let mut serv_type = heapless::String::new();

        write!(
            &mut serv_type,
            "_matterc._udp,_S{},_L{}",
            short, discriminator
        )
        .unwrap();

        serv_type
    }

    fn get_vp(&self) -> heapless::String<11> {
        let mut vp = heapless::String::new();

        write!(&mut vp, "{}+{}", self.vid, self.pid).unwrap();

        vp
    }

    fn get_discriminator_str(discriminator: u16) -> heapless::String<5> {
        discriminator.into()
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
        let short = MdnsMgr::compute_short_discriminator(discriminator);
        assert_eq!(short, 0b1111);

        let discriminator: u16 = 840;
        let short = MdnsMgr::compute_short_discriminator(discriminator);
        assert_eq!(short, 3);
    }
}
