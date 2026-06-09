/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

//! An mDNS implementation based on the `zeroconf` crate.
//! (On Linux requires the Avahi daemon to be installed and running; does not work with `systemd-resolved`.)

use core::pin::pin;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use embassy_futures::select::select3;
use embassy_time::Timer;

use zeroconf::browser::TMdnsBrowser;
use zeroconf::prelude::TEventLoop;
use zeroconf::service::TMdnsService;
use zeroconf::txt_record::TTxtRecord;
use zeroconf::{MdnsBrowser, ServiceDiscovery, ServiceType};

use crate::error::{Error, ErrorCode};
use crate::transport::network::mdns::MdnsRemoteService;
use crate::transport::network::MatterLocalService;
use crate::utils::select::Coalesce;
use crate::Matter;

/// Interval (ms) at which the async side drains discovered services from the
/// browser thread and re-checks whether the query is still in flight.
const QUERY_POLL_INTERVAL_MS: u64 = 100;

/// Collect a discovered service's TXT records into owned `(key, value)` pairs.
fn txt_pairs(svc: &ServiceDiscovery) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    if let Some(txt) = svc.txt() {
        for (key, value) in txt.iter() {
            pairs.push((key, value));
        }
    }
    pairs
}

/// An mDNS implementation for Matter utilizing the `zeroconf` crate.
/// In theory, it should work on all of Linux, MacOS and Windows, however seems to have issues on MacOSX and Windows.
pub struct ZeroconfMdns {
    services: HashMap<MatterLocalService, MdnsEntry>,
}

impl Default for ZeroconfMdns {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroconfMdns {
    /// Create a new `ZeroconfMdns`.
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    /// Run the mDNS responder + querier.
    ///
    /// Concurrently (a) publishes the local Matter services and keeps them in
    /// sync, and (b) services the resolve and
    /// [`Transport::browse_commissionable`](crate::transport::Transport::browse_commissionable)
    /// rendezvous. `zeroconf`'s browser is `!Send` and event-loop based, so each
    /// query runs the browser on a dedicated thread that collects results into a
    /// shared buffer which the async side drains and deposits.
    ///
    /// # Arguments
    /// - `matter`: A reference to the Matter instance to get mDNS services from.
    pub async fn run(&mut self, matter: &Matter<'_>) -> Result<(), Error> {
        let mut responder = pin!(self.run_responder(matter));
        let mut browse = pin!(Self::run_browse(matter));
        let mut resolve = pin!(Self::run_resolve(matter));

        select3(&mut responder, &mut browse, &mut resolve)
            .coalesce()
            .await
    }

    /// Publish the local Matter services and keep them in sync with the stack.
    async fn run_responder(&mut self, matter: &Matter<'_>) -> Result<(), Error> {
        loop {
            matter.transport().wait_mdns().await;

            let mut services = HashSet::new();
            matter.mdns_services(|service| {
                services.insert(service);

                Ok(())
            })?;

            info!("mDNS services changed, updating...");

            self.update_services(matter, &services)?;

            info!("mDNS services updated");
        }
    }

    /// Service commissionable-browse requests: run a `_matterc._udp` browser on a
    /// worker thread and deposit each discovered service (filter + exclude checks
    /// happen in the deposit) while the browse is in flight.
    async fn run_browse(matter: &Matter<'_>) -> Result<(), Error> {
        loop {
            let _filter = matter.transport().wait_mdns_browse_request().await;

            let service_type = ServiceType::new("matterc", "udp")?;
            let (discovered, _stop) = Self::spawn_browser(service_type);

            while matter.transport().mdns_browse_in_flight() {
                Self::drain(&discovered, |svc| {
                    if let Ok(ip) = svc.address().parse::<IpAddr>() {
                        let pairs = txt_pairs(svc);
                        matter
                            .transport()
                            .try_deposit_mdns_browse(&MdnsRemoteService {
                                instance_name: svc.name(),
                                port: Some(*svc.port()),
                                addrs: core::iter::once(ip),
                                txt: pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                            });
                    }
                });

                Timer::after(embassy_time::Duration::from_millis(QUERY_POLL_INTERVAL_MS)).await;
            }
        }
    }

    /// Service operational-resolve requests: run a browser for the requested
    /// service's type on a worker thread and deposit the instance whose name
    /// matches the requested one, while the resolve is in flight.
    async fn run_resolve(matter: &Matter<'_>) -> Result<(), Error> {
        loop {
            let service = matter.transport().wait_mdns_resolve_request().await;

            let mut name_buf: heapless::String<128> = heapless::String::new();
            service.instance_name(&mut name_buf);
            let label = name_buf.split('.').next().unwrap_or("").to_string();

            // `_matter._tcp` -> ("matter", "tcp"), `_matterc._udp` -> ("matterc", "udp")
            let mut parts = service.service_type().trim_start_matches('_').split("._");
            let svc_name = parts.next().unwrap_or("matter");
            let proto = parts.next().unwrap_or("tcp");
            let service_type = ServiceType::new(svc_name, proto)?;

            let (discovered, _stop) = Self::spawn_browser(service_type);

            while matter.transport().mdns_resolve_in_flight() {
                Self::drain(&discovered, |svc| {
                    if svc.name() != &label {
                        return;
                    }
                    if let Ok(ip) = svc.address().parse::<IpAddr>() {
                        let pairs = txt_pairs(svc);
                        // Match is by the full instance name we requested.
                        matter
                            .transport()
                            .try_deposit_mdns_resolve(&MdnsRemoteService {
                                instance_name: name_buf.as_str(),
                                port: Some(*svc.port()),
                                addrs: core::iter::once(ip),
                                txt: pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                            });
                    }
                });

                Timer::after(embassy_time::Duration::from_millis(QUERY_POLL_INTERVAL_MS)).await;
            }
        }
    }

    /// Spawn a `zeroconf` browser for `service_type` on a worker thread (the
    /// browser is `!Send` + event-loop based), collecting discoveries into a
    /// shared buffer. The returned [`MdnsEntry`] signals the thread to stop on drop.
    fn spawn_browser(service_type: ServiceType) -> (Arc<Mutex<Vec<ServiceDiscovery>>>, MdnsEntry) {
        let discovered: Arc<Mutex<Vec<ServiceDiscovery>>> = Arc::new(Mutex::new(Vec::new()));
        let discovered_thread = discovered.clone();
        let (stop_tx, stop_rx) = sync_channel::<()>(1);

        let _ = std::thread::spawn(move || {
            let mut browser = MdnsBrowser::new(service_type);
            browser.set_service_discovered_callback(Box::new(
                move |result: zeroconf::Result<ServiceDiscovery>, _context| {
                    if let Ok(service) = result {
                        if let Ok(mut guard) = discovered_thread.lock() {
                            guard.push(service);
                        }
                    }
                },
            ));

            match browser.browse_services() {
                Ok(event_loop) => {
                    while stop_rx.try_recv().is_err() {
                        if let Err(e) = event_loop.poll(Duration::from_millis(100)) {
                            warn!("Browser poll error: {:?}", e);
                            break;
                        }
                    }
                }
                Err(e) => error!("Failed to start zeroconf browser: {:?}", e),
            }
        });

        (discovered, MdnsEntry(stop_tx))
    }

    /// Drain the discovered-services buffer, invoking `f` for each.
    fn drain(discovered: &Arc<Mutex<Vec<ServiceDiscovery>>>, mut f: impl FnMut(&ServiceDiscovery)) {
        if let Ok(mut guard) = discovered.lock() {
            for svc in guard.drain(..) {
                f(&svc);
            }
        }
    }

    fn update_services(
        &mut self,
        matter: &Matter<'_>,
        services: &HashSet<MatterLocalService>,
    ) -> Result<(), Error> {
        for service in services {
            if !self.services.contains_key(service) {
                info!("Registering mDNS service: {:?}", service);

                let zeroconf_service = SendableZeroconfMdnsService::new(matter, service)?;
                let (sender, receiver) = sync_channel(1);

                // Spawning a thread for each service is not ideal, but unavoidable with the current API of `zeroconf`
                //
                // TODO: What is worse is that if the thread exits with an error, we wouldn't know and we would currently
                // be left with a dangling `MdnsEntry` in the hashmap table

                let _ = std::thread::spawn(move || zeroconf_service.run(receiver));

                self.services.insert(service.clone(), MdnsEntry(sender));
            }
        }

        loop {
            let removed = self
                .services
                .iter()
                .find(|(service, _)| !services.contains(service));

            if let Some((service, _)) = removed {
                info!("Deregistering mDNS service: {:?}", service);
                self.services.remove(&service.clone());
            } else {
                break;
            }
        }

        Ok(())
    }
}

/// This type is necessary because of a number of weird design decisions in the `zeroconf` crate:
/// - `MdnsService` is not `Send` (contains `Rc`s which are not really used?),
///   so we cannot create it in our own thread context and then send it to the worker thread
/// - The need for a worker thread in the first place is also problematic but unavoidable unless
///   the whole `poll` / event loop thing in `zeroconf` is reworked
struct SendableZeroconfMdnsService {
    name: String,
    service_type: ServiceType,
    port: u16,
    txt_kvs: Vec<(String, String)>,
}

impl SendableZeroconfMdnsService {
    /// Create a new `SendableZeroconfMdnsService` from a `MatterLocalService`.
    fn new(matter: &Matter<'_>, mdns_service: &MatterLocalService) -> Result<Self, Error> {
        // Scratch buffer for expanding `MatterLocalService` into a `MdnsLocalService` view —
        // the strings (name, subtypes, TXT values) are formatted into this buffer.
        let mut buf = [0u8; 512];
        let (service, _) = mdns_service.service(matter.dev_det(), matter.port(), &mut buf)?;

        let service_name = service.service.strip_prefix('_').unwrap_or(service.service);

        let protocol = service
            .protocol
            .strip_prefix('_')
            .unwrap_or(service.protocol);

        let subtypes: Vec<&str> = service
            .service_subtypes
            .clone()
            .map(|subtype| subtype.strip_prefix('_').unwrap_or(subtype))
            .collect();

        let service_type = if !subtypes.is_empty() {
            ServiceType::with_sub_types(service_name, protocol, subtypes)?
        } else {
            ServiceType::new(service_name, protocol)?
        };

        let txt_kvs = service
            .txt_kvs
            .clone()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<Vec<_>>();

        Ok(Self {
            name: service.name.to_string(),
            service_type,
            port: service.port,
            txt_kvs,
        })
    }

    /// Run the service by polling it
    /// Due to the current design of `zeroconf`, this must be run in a separate thread.
    fn run(self, receiver: Receiver<()>) -> Result<(), Error> {
        let mut mdns_service = zeroconf::MdnsService::new(self.service_type, self.port);

        let mut txt_record = zeroconf::TxtRecord::new();
        for (k, v) in &self.txt_kvs {
            trace!("mDNS TXT key {} val {}", k, v);
            txt_record.insert(k, v)?;
        }

        mdns_service.set_name(&self.name);
        mdns_service.set_txt_record(txt_record);
        mdns_service.set_registered_callback(Box::new(|_, _| {}));

        let event_loop = mdns_service.register()?;

        while receiver.try_recv().is_err() {
            event_loop.poll(std::time::Duration::from_secs(1))?;
        }

        Ok(())
    }
}

/// A way to notify the daemon thread for a running mDNS service registration
/// that it should quit.
struct MdnsEntry(SyncSender<()>);

impl Drop for MdnsEntry {
    fn drop(&mut self) {
        if let Err(e) = self.0.send(()) {
            error!("Deregistering mDNS entry failed: {}", debug2format!(e));
        }
    }
}

impl From<zeroconf::error::Error> for Error {
    fn from(e: zeroconf::error::Error) -> Self {
        Self::new_with_details(ErrorCode::MdnsError, Box::new(e))
    }
}
