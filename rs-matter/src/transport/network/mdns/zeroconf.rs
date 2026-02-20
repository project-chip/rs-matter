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

//! An mDNS implementation based on the `zeroconf` crate.
//! (On Linux requires the Avahi daemon to be installed and running; does not work with `systemd-resolved`.)

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroconf::browser::TMdnsBrowser;
use zeroconf::prelude::TEventLoop;
use zeroconf::service::TMdnsService;
use zeroconf::txt_record::TTxtRecord;
use zeroconf::{MdnsBrowser, ServiceDiscovery, ServiceType};

use crate::crypto::Crypto;
use crate::dm::ChangeNotify;
use crate::error::{Error, ErrorCode};
use crate::transport::network::mdns::Service;
use crate::{Matter, MatterMdnsService};

use super::{CommissionableFilter, DiscoveredDevice, PushUnique};

/// An mDNS responder for Matter utilizing the `zeroconf` crate.
/// In theory, it should work on all of Linux, MacOS and Windows, however seems to have issues on MacOSX and Windows.
pub struct ZeroconfMdnsResponder<'a> {
    matter: &'a Matter<'a>,
    services: HashMap<MatterMdnsService, MdnsEntry>,
}

impl<'a> ZeroconfMdnsResponder<'a> {
    /// Create a new `ZeroconfMdnsResponder` for the given `Matter` instance.
    pub fn new(matter: &'a Matter<'a>) -> Self {
        Self {
            matter,
            services: HashMap::new(),
        }
    }

    /// Run the mDNS responder.
    ///
    /// # Arguments
    /// - `crypto`: A crypto provider instance.
    /// - `notify`: A change notification interface.
    pub async fn run<C: Crypto>(
        &mut self,
        crypto: C,
        notify: &dyn ChangeNotify,
    ) -> Result<(), Error> {
        loop {
            self.matter.wait_mdns().await;

            let mut services = HashSet::new();
            self.matter.mdns_services(&crypto, notify, |service| {
                services.insert(service);

                Ok(())
            })?;

            info!("mDNS services changed, updating...");

            self.update_services(&services)?;

            info!("mDNS services updated");
        }
    }

    fn update_services(&mut self, services: &HashSet<MatterMdnsService>) -> Result<(), Error> {
        for service in services {
            if !self.services.contains_key(service) {
                info!("Registering mDNS service: {:?}", service);

                let zeroconf_service = SendableZeroconfMdnsService::new(self.matter, service)?;
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
    /// Create a new `SendableZeroconfMdnsService` from a `MatterMdnsService`.
    fn new(matter: &Matter<'_>, mdns_service: &MatterMdnsService) -> Result<Self, Error> {
        Service::call_with(mdns_service, matter.dev_det(), matter.port(), |service| {
            let service_name = service.service.strip_prefix('_').unwrap_or(service.service);

            let protocol = service
                .protocol
                .strip_prefix('_')
                .unwrap_or(service.protocol);

            let service_type = if !service.service_subtypes.is_empty() {
                let subtypes = service
                    .service_subtypes
                    .iter()
                    .map(|subtype| subtype.strip_prefix('_').unwrap_or(*subtype))
                    .collect();

                ServiceType::with_sub_types(service_name, protocol, subtypes)?
            } else {
                ServiceType::new(service_name, protocol)?
            };

            let txt_kvs = service
                .txt_kvs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<Vec<_>>();

            Ok(Self {
                name: service.name.to_string(),
                service_type,
                port: service.port,
                txt_kvs,
            })
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

/// Discover commissionable Matter devices using the zeroconf crate.
///
/// # Arguments
/// * `filter` - Filter criteria for discovered devices
/// * `timeout_ms` - Discovery timeout in milliseconds
///
/// # Returns
/// A vector of discovered devices matching the filter criteria
///
/// # Note
/// This function is blocking and spawns a background thread for the mDNS browser event loop.
pub fn discover_commissionable<const A: usize>(
    filter: &CommissionableFilter,
    timeout_ms: u32,
) -> Result<Vec<DiscoveredDevice<A>>, Error> {
    // Build the service type - zeroconf doesn't support subtype filtering in browse,
    // so we browse for all _matterc._udp and filter results afterward
    let service_type = ServiceType::new("matterc", "udp")?;

    info!("Browsing for mDNS services via zeroconf: _matterc._udp");

    // Shared state for collecting discovered devices
    let discovered: Arc<Mutex<Vec<ServiceDiscovery>>> = Arc::new(Mutex::new(Vec::new()));
    let discovered_clone = discovered.clone();

    // Channel to signal the browser thread to stop
    let (stop_tx, stop_rx) = sync_channel::<()>(1);

    let browser_handle = std::thread::spawn(move || -> Result<(), Error> {
        let mut browser = MdnsBrowser::new(service_type);

        let discovered_callback = discovered_clone.clone();
        browser.set_service_discovered_callback(Box::new(
            move |result: zeroconf::Result<ServiceDiscovery>, _context| {
                if let Ok(service) = result {
                    debug!(
                        "Discovered service: {} at {}:{}",
                        service.name(),
                        service.address(),
                        service.port()
                    );
                    if let Ok(mut guard) = discovered_callback.lock() {
                        guard.push(service);
                    }
                }
            },
        ));

        let event_loop = browser.browse_services()?;

        // Poll until stop signal or timeout
        while stop_rx.try_recv().is_err() {
            if let Err(e) = event_loop.poll(Duration::from_millis(100)) {
                warn!("Browser poll error: {:?}", e);
                break;
            }
        }

        Ok(())
    });

    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }

    // Signal browser thread to stop
    let _ = stop_tx.send(());

    // Wait for browser thread to finish and handle any errors
    match browser_handle.join() {
        Ok(bg_thread_res) => bg_thread_res?,
        Err(panic_payload) => {
            let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };

            return Err(Error::new_with_details(
                ErrorCode::MdnsError,
                format!("Browser thread panicked: {panic_msg}").into(),
            ));
        }
    }

    // Process discovered services
    let mut results = Vec::new();

    let services = discovered
        .lock()
        .map_err(|_| Error::new(ErrorCode::MdnsError))?;

    for service in services.iter() {
        let mut device = DiscoveredDevice::default();

        device.set_instance_name(service.name());
        device.port = *service.port();

        // Parse and add IP address
        if let Ok(ip) = service.address().parse::<IpAddr>() {
            device.add_address(ip);
        } else {
            warn!("Could not parse IP address: {}", service.address());
            continue;
        }

        // Parse TXT records
        if let Some(txt) = service.txt() {
            for (key, value) in txt.iter() {
                device.set_txt_value(key.as_str(), value.as_str());
            }
        }

        // Apply filters and add to results if unique
        if filter.matches(&device) {
            results.push_if_unique(device);
        }
    }

    info!("Zeroconf mDNS discovery found {} devices", results.len());

    Ok(results)
}
