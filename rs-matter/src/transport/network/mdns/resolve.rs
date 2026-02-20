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
use std::net::IpAddr;

use domain::base::Name;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};
use zbus::Connection;

use crate::crypto::Crypto;
use crate::dm::ChangeNotify;
use crate::error::Error;
use crate::transport::network::mdns::Service;
use crate::utils::zbus_proxies::resolve::manager::ManagerProxy;
use crate::{Matter, MatterMdnsService};

use super::{CommissionableFilter, DiscoveredDevice, PushUnique};

/// Interface index for "any interface"
const IF_INDEX_ANY: i32 = 0;
/// Address family for "unspecified" (both IPv4 and IPv6)
const AF_UNSPEC: i32 = 0;
/// DNS class IN (Internet)
const DNS_CLASS_IN: u16 = 1;
/// DNS record type PTR
const DNS_TYPE_PTR: u16 = 12;

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
    /// - `crypto`: A crypto provider instance.
    /// - `notify`: A change notification interface.
    pub async fn run<C: Crypto>(
        &mut self,
        connection: &Connection,
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

/// Discover commissionable Matter devices using systemd-resolved over DBus.
///
/// # Arguments
/// * `connection` - A reference to the DBus system connection
/// * `filter` - Filter criteria for discovered devices
///
/// # Returns
/// A vector of discovered devices matching the filter criteria
///
/// # Note
/// systemd-resolved doesn't support service browsing with subtypes, so we browse for all
/// `_matterc._udp.local` services and filter the results afterward.
pub async fn discover_commissionable<const A: usize>(
    connection: &Connection,
    filter: &CommissionableFilter,
) -> Result<Vec<DiscoveredDevice<A>>, Error> {
    let mut results = Vec::new();

    info!("Browsing for mDNS services via systemd-resolved: _matterc._udp.local");

    let resolve = ManagerProxy::new(connection).await?;

    let ptr_query = "_matterc._udp.local";
    let (records, _flags) = match resolve
        .resolve_record(IF_INDEX_ANY, ptr_query, DNS_CLASS_IN, DNS_TYPE_PTR, 0)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            warn!("Failed to query PTR records: {:?}", e);
            return Ok(results);
        }
    };

    let service_instances = records
        .into_iter()
        .filter_map(|(_ifindex, _rtype, _rclass, rdata)| parse_dns_name(&rdata))
        .collect::<Vec<_>>();

    for instance in &service_instances {
        let (name, type_, domain) = match parse_service_instance(&instance) {
            Some(parts) => parts,
            None => {
                warn!("Failed to parse service instance: {}", instance);
                continue;
            }
        };

        debug!(
            "Resolving service: name='{}', type='{}', domain='{}'",
            name, type_, domain
        );

        match resolve
            .resolve_service(IF_INDEX_ANY, &name, &type_, &domain, AF_UNSPEC, 0)
            .await
        {
            Ok((
                srv_data,
                txt_data,
                _canonical_name,
                _canonical_type,
                _canonical_domain,
                _flags,
            )) => {
                for (_priority, _weight, port, _hostname, addresses, _canonical_hostname) in
                    srv_data
                {
                    let mut device = DiscoveredDevice::default();
                    device.set_instance_name(&name);
                    device.port = port;

                    // Add all available addresses (they will be sorted by priority)
                    for (_ifindex, family, addr_bytes) in &addresses {
                        if let Some(ip) = parse_ip_address(*family, addr_bytes) {
                            device.add_address(ip);
                        }
                    }

                    if device.addresses().is_empty() {
                        warn!("No valid address found for service: {}", name);
                        continue;
                    }

                    for txt_record in &txt_data {
                        if let Ok(s) = core::str::from_utf8(txt_record) {
                            if let Some(eq_pos) = s.find('=') {
                                let key = &s[..eq_pos];
                                let value = &s[eq_pos + 1..];
                                device.set_txt_value(key, value);
                            }
                        }
                    }

                    if filter.matches(&device) {
                        results.push_if_unique(device);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to resolve service {}: {:?}", name, e);
            }
        }
    }

    info!(
        "systemd-resolved mDNS discovery found {} devices",
        results.len()
    );

    Ok(results)
}

/// Parse a DNS wire format domain name into a string.
///
/// Note that compressed names (with 0xC0 pointers) will return an error.
/// In the context of systemd-resolved's D-Bus API, PTR record RDATA
/// is typically returned uncompressed.
fn parse_dns_name(data: &[u8]) -> Option<String> {
    Name::from_slice(data)
        .map(|name| name.to_string())
        .ok()
        .and_then(|result| {
            if result.is_empty() || result == "." {
                None
            } else {
                Some(result)
            }
        })
}

/// Parse a service instance name into (name, type, domain) components
/// Input format: "Instance Name._matterc._udp.local"
fn parse_service_instance(instance: &str) -> Option<(String, String, String)> {
    let instance = instance.trim_end_matches('.');

    let type_start = instance.find("._matterc._udp")?;
    let name = &instance[..type_start];

    // Find the domain (everything after the service type)
    let after_name = &instance[type_start + 1..]; // Skip the dot before _matterc
    let domain_start = after_name.find(".local")?;
    let type_ = &after_name[..domain_start + ".local".len()];

    // Split type into service type and domain
    let dot_local_pos = type_.rfind(".local")?;
    let service_type = &type_[..dot_local_pos];
    let domain = "local";

    Some((
        name.to_string(),
        service_type.to_string(),
        domain.to_string(),
    ))
}

/// Parse an IP address from systemd-resolved format
fn parse_ip_address(family: i32, addr_bytes: &[u8]) -> Option<IpAddr> {
    match family {
        2 => {
            // AF_INET (IPv4)
            if addr_bytes.len() >= 4 {
                Some(IpAddr::V4(std::net::Ipv4Addr::new(
                    addr_bytes[0],
                    addr_bytes[1],
                    addr_bytes[2],
                    addr_bytes[3],
                )))
            } else {
                None
            }
        }
        10 => {
            // AF_INET6 (IPv6)
            if addr_bytes.len() >= 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&addr_bytes[..16]);
                Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dns_name_simple() {
        // "local" in DNS wire format: 5 l o c a l 0
        let data = [5, b'l', b'o', b'c', b'a', b'l', 0];
        assert_eq!(parse_dns_name(&data), Some("local".to_string()));
    }

    #[test]
    fn parse_dns_name_multi_label() {
        // "_matterc._udp.local" in DNS wire format
        let data = [
            8, b'_', b'm', b'a', b't', b't', b'e', b'r', b'c', // _matterc
            4, b'_', b'u', b'd', b'p', // _udp
            5, b'l', b'o', b'c', b'a', b'l', // local
            0,    // terminator
        ];
        assert_eq!(
            parse_dns_name(&data),
            Some("_matterc._udp.local".to_string())
        );
    }

    #[test]
    fn parse_dns_name_service_instance() {
        // "Matter Device._matterc._udp.local" in DNS wire format
        let data = [
            13, b'M', b'a', b't', b't', b'e', b'r', b' ', b'D', b'e', b'v', b'i', b'c',
            b'e', // Matter Device
            8, b'_', b'm', b'a', b't', b't', b'e', b'r', b'c', // _matterc
            4, b'_', b'u', b'd', b'p', // _udp
            5, b'l', b'o', b'c', b'a', b'l', // local
            0,    // terminator
        ];
        assert_eq!(
            parse_dns_name(&data),
            Some("Matter Device._matterc._udp.local".to_string())
        );
    }

    #[test]
    fn parse_dns_name_empty() {
        // Just a null terminator
        let data = [0];
        assert_eq!(parse_dns_name(&data), None);
    }

    #[test]
    fn parse_dns_name_truncated() {
        // Label claims 10 bytes but only 5 are present
        let data = [10, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(parse_dns_name(&data), None);
    }

    // Tests for parse_service_instance()

    #[test]
    fn parse_service_instance_simple() {
        let result = parse_service_instance("MyDevice._matterc._udp.local");
        assert!(result.is_some());
        let (name, type_, domain) = result.unwrap();
        assert_eq!(name, "MyDevice");
        assert_eq!(type_, "_matterc._udp");
        assert_eq!(domain, "local");
    }

    #[test]
    fn parse_service_instance_with_spaces() {
        let result = parse_service_instance("Matter Test Device._matterc._udp.local");
        assert!(result.is_some());
        let (name, type_, domain) = result.unwrap();
        assert_eq!(name, "Matter Test Device");
        assert_eq!(type_, "_matterc._udp");
        assert_eq!(domain, "local");
    }

    #[test]
    fn parse_service_instance_with_trailing_dot() {
        let result = parse_service_instance("MyDevice._matterc._udp.local.");
        assert!(result.is_some());
        let (name, type_, domain) = result.unwrap();
        assert_eq!(name, "MyDevice");
        assert_eq!(type_, "_matterc._udp");
        assert_eq!(domain, "local");
    }

    #[test]
    fn parse_service_instance_invalid_no_matterc() {
        let result = parse_service_instance("MyDevice._http._tcp.local");
        assert!(result.is_none());
    }

    #[test]
    fn parse_service_instance_invalid_no_local() {
        let result = parse_service_instance("MyDevice._matterc._udp.example.com");
        assert!(result.is_none());
    }

    // Tests for parse_ip_address()

    #[test]
    fn parse_ip_address_ipv4() {
        let addr_bytes = [192, 168, 1, 100];
        let result = parse_ip_address(2, &addr_bytes);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100))
        );
    }

    #[test]
    fn parse_ip_address_ipv4_localhost() {
        let addr_bytes = [127, 0, 0, 1];
        let result = parse_ip_address(2, &addr_bytes);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    #[test]
    fn parse_ip_address_ipv6_localhost() {
        let addr_bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let result = parse_ip_address(10, &addr_bytes);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn parse_ip_address_ipv6_link_local() {
        // fe80::1
        let addr_bytes = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let result = parse_ip_address(10, &addr_bytes);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn parse_ip_address_ipv4_too_short() {
        let addr_bytes = [192, 168, 1]; // Only 3 bytes
        let result = parse_ip_address(2, &addr_bytes);
        assert!(result.is_none());
    }

    #[test]
    fn parse_ip_address_ipv6_too_short() {
        let addr_bytes = [0, 0, 0, 0, 0, 0, 0, 0]; // Only 8 bytes
        let result = parse_ip_address(10, &addr_bytes);
        assert!(result.is_none());
    }

    #[test]
    fn parse_ip_address_unknown_family() {
        let addr_bytes = [192, 168, 1, 100];
        let result = parse_ip_address(99, &addr_bytes); // Unknown family
        assert!(result.is_none());
    }
}
