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
use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService};
use log::info;

#[allow(dead_code)]
pub struct SysMdnsService {
    s: RegisteredDnsService,
}

/// Publish a mDNS service
/// name - can be a service name (comma separate subtypes may follow)
/// regtype - registration type (e.g. _matter_.tcp etc)
/// port - the port
pub fn sys_publish_service(
    name: &str,
    regtype: &str,
    port: u16,
    txt_kvs: &[[&str; 2]],
) -> Result<SysMdnsService, Error> {
    let mut builder = DNSServiceBuilder::new(regtype, port).with_name(name);

    info!("mDNS Registration Type {}", regtype);
    for kvs in txt_kvs {
        info!("mDNS TXT key {} val {}", kvs[0], kvs[1]);
        builder = builder.with_key_value(kvs[0].to_string(), kvs[1].to_string());
    }
    let s = builder.register().map_err(|_| Error::MdnsError)?;
    Ok(SysMdnsService { s })
}
