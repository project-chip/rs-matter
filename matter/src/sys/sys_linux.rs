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
use lazy_static::lazy_static;
use libmdns::{Responder, Service};
use log::info;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

#[allow(dead_code)]
pub struct SysMdnsService {
    service: Service,
}

lazy_static! {
    static ref RESPONDER: Arc<Mutex<Responder>> = Arc::new(Mutex::new(Responder::new().unwrap()));
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
    info!("mDNS Registration Type {}", regtype);
    info!("mDNS properties {:?}", txt_kvs);

    let mut properties = Vec::new();
    for kvs in txt_kvs {
        info!("mDNS TXT key {} val {}", kvs[0], kvs[1]);
        properties.push(format!("{}={}", kvs[0], kvs[1]));
    }
    let properties: Vec<&str> = properties.iter().map(|entry| entry.as_str()).collect();

    let responder = RESPONDER.lock().map_err(|_| Error::MdnsError)?;
    let service = responder.register(regtype.to_owned(), name.to_owned(), port, &properties);

    Ok(SysMdnsService { service })
}
