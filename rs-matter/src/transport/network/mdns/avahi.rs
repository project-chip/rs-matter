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

//! A Linux-specific mDNS implementation based on Avahi.
//!
//! Requires the Avahi daemon to be installed and running.

use std::collections::{HashMap, HashSet};
use std::io::Write as _;

use zbus::zvariant::{ObjectPath, OwnedObjectPath};
use zbus::Connection;

use crate::error::Error;
use crate::transport::network::mdns::Service;
use crate::utils::zbus_proxies::avahi::entry_group::EntryGroupProxy;
use crate::utils::zbus_proxies::avahi::server2::Server2Proxy;
use crate::{Matter, MatterMdnsService};

/// An mDNS responder for Matter utilizing the Avahi daemon over DBus.
pub struct AvahiMdnsResponder<'a> {
    matter: &'a Matter<'a>,
    services: HashMap<MatterMdnsService, OwnedObjectPath>,
}

impl<'a> AvahiMdnsResponder<'a> {
    /// Create a new instance of the Avahi mDNS responder.
    pub fn new(matter: &'a Matter<'a>) -> Self {
        Self {
            matter,
            services: HashMap::new(),
        }
    }

    /// Run the mDNS responder
    ///
    /// # Arguments
    /// - `connection`: A reference to the DBus system connection to use for communication with Avahi.
    pub async fn run(&mut self, connection: &Connection) -> Result<(), Error> {
        {
            let avahi = Server2Proxy::new(connection).await?;
            info!("Avahi API version: {}", avahi.get_apiversion().await?);
        }

        loop {
            self.matter.wait_mdns().await;

            let mut services = HashSet::new();
            self.matter.mdns_services(|service| {
                services.insert(service);

                Ok(())
            })?;

            info!("mDNS services changed, updating...");

            self.update_services(connection, &services).await?;

            info!("mDNS services updated");
        }
    }

    async fn update_services(
        &mut self,
        connection: &Connection,
        services: &HashSet<MatterMdnsService>,
    ) -> Result<(), Error> {
        for service in services {
            if !self.services.contains_key(service) {
                info!("Registering mDNS service: {:?}", service);
                let path = self.register(connection, service).await?;
                self.services.insert(service.clone(), path);
            }
        }

        loop {
            let removed = self
                .services
                .iter()
                .find(|(service, _)| !services.contains(service));

            if let Some((service, path)) = removed {
                info!("Deregistering mDNS service: {:?}", service);
                Self::deregister(connection, path.as_ref()).await?;
                self.services.remove(&service.clone());
            } else {
                break;
            }
        }

        Ok(())
    }

    async fn register(
        &mut self,
        connection: &Connection,
        service: &MatterMdnsService,
    ) -> Result<OwnedObjectPath, Error> {
        Service::async_call_with(
            service,
            self.matter.dev_det(),
            self.matter.port(),
            async |service| {
                let avahi = Server2Proxy::new(connection).await?;

                let path = avahi.entry_group_new().await?;

                let group = EntryGroupProxy::builder(connection)
                    .path(path.clone())?
                    .build()
                    .await?;

                let mut txt_buf = Vec::new();

                let offsets = service
                    .txt_kvs
                    .iter()
                    .map(|(k, v)| {
                        let start = txt_buf.len();

                        if v.is_empty() {
                            txt_buf.extend_from_slice(k.as_bytes());
                        } else {
                            write_unwrap!(&mut txt_buf, "{}={}", k, v);
                        }

                        txt_buf.len() - start
                    })
                    .collect::<Vec<_>>();

                let mut txt_slice = txt_buf.as_slice();
                let mut txt = Vec::new();

                for offset in offsets {
                    let (entry, next_slice) = txt_slice.split_at(offset);

                    txt.push(entry);

                    txt_slice = next_slice;
                }

                group
                    .add_service(
                        -1,
                        -1,
                        0,
                        service.name,
                        service.service_protocol,
                        "",
                        "",
                        service.port,
                        &txt,
                    )
                    .await?;

                for subtype in service.service_subtypes {
                    // Unclear why, but Avahi wants this very special
                    // way of formatting service subtypes
                    let avahi_subtype = format!("{}._sub.{}", subtype, service.service_protocol);

                    group
                        .add_service_subtype(
                            -1,
                            -1,
                            0,
                            service.name,
                            service.service_protocol,
                            "",
                            &avahi_subtype,
                        )
                        .await?;
                }

                group.commit().await?;

                Ok(path)
            },
        )
        .await
    }

    async fn deregister(connection: &Connection, path: ObjectPath<'_>) -> Result<(), Error> {
        let group = EntryGroupProxy::builder(connection)
            .path(path)?
            .build()
            .await?;

        group.free().await?;

        Ok(())
    }
}
