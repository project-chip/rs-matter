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

use std::sync::{Arc, Mutex, Once};

use crate::{
    error::Error,
    sys::{sys_publish_service, SysMdnsService},
    transport::udp::MATTER_PORT,
};

#[derive(Default)]
/// The mDNS service handler
pub struct MdnsInner {
    /// Vendor ID
    vid: u16,
    /// Product ID
    pid: u16,
    /// Discriminator
    discriminator: u16,
    /// Device name
    device_name: String,
}

pub struct Mdns {
    inner: Mutex<MdnsInner>,
}

const SHORT_DISCRIMINATOR_MASK: u16 = 0xF00;
const SHORT_DISCRIMINATOR_SHIFT: u16 = 8;

static mut G_MDNS: Option<Arc<Mdns>> = None;
static INIT: Once = Once::new();

pub enum ServiceMode {
    /// The commissioned state
    Commissioned,
    /// The commissionable state with the discriminator that should be used
    Commissionable(u16),
}

impl Mdns {
    fn new() -> Self {
        Self {
            inner: Mutex::new(MdnsInner {
                ..Default::default()
            }),
        }
    }

    /// Get a handle to the globally unique mDNS instance
    pub fn get() -> Result<Arc<Self>, Error> {
        unsafe {
            INIT.call_once(|| {
                G_MDNS = Some(Arc::new(Mdns::new()));
            });
            Ok(G_MDNS.as_ref().ok_or(Error::Invalid)?.clone())
        }
    }

    /// Set mDNS service specific values
    /// Values like vid, pid, discriminator etc
    // TODO: More things like device-type etc can be added here
    pub fn set_values(&self, vid: u16, pid: u16, discriminator: u16, device_name: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.vid = vid;
        inner.pid = pid;
        inner.discriminator = discriminator;
        inner.device_name = device_name.chars().take(32).collect();
    }

    /// Publish a mDNS service
    /// name - is the service name (comma separated subtypes may follow)
    /// mode - the current service mode
    #[allow(clippy::needless_pass_by_value)]
    pub fn publish_service(&self, name: &str, mode: ServiceMode) -> Result<SysMdnsService, Error> {
        match mode {
            ServiceMode::Commissioned => {
                sys_publish_service(name, "_matter._tcp", MATTER_PORT, &[])
            }
            ServiceMode::Commissionable => {
                let inner = self.inner.lock().unwrap();
                let short = compute_short_discriminator(inner.discriminator);
                let serv_type = format!("_matterc._udp,_S{},_L{}", short, inner.discriminator);

                let str_discriminator = format!("{}", inner.discriminator);
                let txt_kvs = [
                    ["D", &str_discriminator],
                    ["CM", "1"],
                    ["DN", &inner.device_name],
                    ["VP", &format!("{}+{}", inner.vid, inner.pid)],
                    ["SII", "5000"], /* Sleepy Idle Interval */
                    ["SAI", "300"],  /* Sleepy Active Interval */
                    ["T", "1"],      /* TCP supported */
                    ["PH", "33"],    /* Pairing Hint */
                    ["PI", ""],      /* Pairing Instruction */
                ];
                sys_publish_service(name, &serv_type, MATTER_PORT, &txt_kvs)
            }
        }
    }
}

fn compute_short_discriminator(discriminator: u16) -> u16 {
    (discriminator & SHORT_DISCRIMINATOR_MASK) >> SHORT_DISCRIMINATOR_SHIFT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_compute_short_discriminator() {
        let discriminator: u16 = 0b0000_1111_0000_0000;
        let short = compute_short_discriminator(discriminator);
        assert_eq!(short, 0b1111);

        let discriminator: u16 = 840;
        let short = compute_short_discriminator(discriminator);
        assert_eq!(short, 3);
    }
}
