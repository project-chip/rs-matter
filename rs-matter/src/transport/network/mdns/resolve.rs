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

//! A Linux-specific mDNS implementation based on systemd-resolved.
//!
//! Requires the systemd-resolved daemon to be installed, configured with mDNS enabled and running.

use std::collections::{HashMap, HashSet};

use zbus::zvariant::{ObjectPath, OwnedObjectPath};
use zbus::Connection;

use crate::error::Error;
use crate::transport::network::mdns::Service;
use crate::utils::zbus_proxies::resolve::manager::ManagerProxy;
use crate::{Matter, MatterMdnsService};

/// An mDNS responder for Matter utilizing the systemd-resolved daemon over DBus.
///
/// Note that typically Ubuntu Desktop and other desktop distros - while distributing and running `systemd-resolved` -
/// do not have mDNS enabled by default in it and instead do have the Avahi daemon running by default. So during development,
/// you might just want to use the Avahi mDNS responder instead, which is also available in the `zbus` feature.
///
/// To use this responder, you need to have your `systemd-resolved` daemon installed, running and configured with
/// mDNS enabled - also on the particular network interface(s) where you want mDNS multicasting. Doing so usually requires:
/// - Stopping and/or uninstalling the avahi daemon if it is installed and running (e.g. `sudo service avahi-daemon stop`)
/// - Eabling mDNS in the systemd-resolved configuration file, usually located at `/etc/systemd/resolved.conf` (`MulticastDNS=yes`)
///   and then restarting the daemon (e.g. `sudo systemctl restart systemd-resolved`).
/// - Enabling mDNS on the network interface(s) you want to use, by e.g. running `sudo resolvectl mdns eno0 yes`
///   (you can check all is well by e.g. running `sudo resolvectl status eno1` after that)
/// - See also https://unix.stackexchange.com/questions/459991/how-to-configure-systemd-resolved-for-mdns-multicast-dns-on-local-network
///   for more details
///
/// NOTE: If you are greeted with an
/// "Error: Error::DBusError: org.freedesktop.DBus.Error.InteractiveAuthorizationRequired: Interactive authentication required."
/// message, this is an indication that the Linux user on behalf of which you are running the app does not have the elevated privileges
/// required by the systemd-resolved daemon so as to register mDNS services.
///
/// For testing, easiest is to run the application with `sudo` or as root.
pub struct ResolveMdnsResponder<'a> {
    matter: &'a Matter<'a>,
    services: HashMap<MatterMdnsService, OwnedObjectPath>,
}

impl<'a> ResolveMdnsResponder<'a> {
    /// Create a new instance of the systemd-resolved mDNS responder.
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
                let resolve = ManagerProxy::new(connection).await?;

                let txt = service
                    .txt_kvs
                    .iter()
                    .map(|(k, v)| (*k, v.as_bytes()))
                    .collect::<HashMap<_, _>>();

                // NOTE: By looking at the DBus `register_service` implementation it seems
                // that the `register_service` call does not support mDNS subtypes at all:
                // https://github.com/systemd/systemd/blob/0ae3a8d147f12cd47aa0cfbaa4c92570ae8ff949/src/resolve/resolved-bus.c#L1861
                //
                // (They are supported for mDNS configurations in config files though.)

                // Make our ID a bit more unique
                let id = format!("rs-matter-{}", service.name);

                let path = resolve
                    .register_service(
                        &id,
                        service.name,
                        service.service_protocol,
                        service.port,
                        0,
                        0,
                        &[txt],
                    )
                    .await?;

                Ok(path)
            },
        )
        .await
    }

    async fn deregister(connection: &Connection, path: ObjectPath<'_>) -> Result<(), Error> {
        let resolve = ManagerProxy::new(connection).await?;

        resolve.unregister_service(&path).await?;

        Ok(())
    }
}
