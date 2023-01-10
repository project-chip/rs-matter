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
}

pub struct Mdns {
    inner: Mutex<MdnsInner>,
}

const SHORT_DISCRIMINATOR_MASK: u16 = 0xf00;
const SHORT_DISCRIMINATOR_SHIFT: u16 = 8;

static mut G_MDNS: Option<Arc<Mdns>> = None;
static INIT: Once = Once::new();

#[derive(Clone, Copy)]
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
    pub fn set_values(&self, vid: u16, pid: u16) {
        let mut inner = self.inner.lock().unwrap();
        inner.vid = vid;
        inner.pid = pid;
    }

    /// Publish a mDNS service
    /// name - is the service name (comma separated subtypes may follow)
    /// mode - the current service mode
    pub fn publish_service(&self, name: &str, mode: ServiceMode) -> Result<SysMdnsService, Error> {
        match mode {
            ServiceMode::Commissioned => {
                sys_publish_service(name, "_matter._tcp", MATTER_PORT, &[])
            }
            ServiceMode::Commissionable(discriminator) => {
                let short = (discriminator & SHORT_DISCRIMINATOR_MASK) >> SHORT_DISCRIMINATOR_SHIFT;
                let serv_type = format!("_matterc._udp,_S{},_L{}", short, discriminator);

                let str_discriminator = format!("{}", discriminator);
                let txt_kvs = [["D", &str_discriminator], ["CM", "1"]];
                sys_publish_service(name, &serv_type, MATTER_PORT, &txt_kvs)
            }
        }
    }
}
