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
use core::future::Future;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use crate::dm::clusters::basic_info::BasicInfoConfig;
use crate::error::Error;
use crate::{MatterMdnsService, MATTER_SERVICE_MAX_NAME_LEN};

#[cfg(feature = "astro-dnssd")]
pub mod astro;
#[cfg(feature = "zbus")]
pub mod avahi;
pub mod builtin;
#[cfg(feature = "zbus")]
pub mod resolve;
#[cfg(feature = "zeroconf")]
pub mod zeroconf;

/// The standard mDNS IPv6 broadcast address
pub const MDNS_IPV6_BROADCAST_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

/// The standard mDNS IPv4 broadcast address
pub const MDNS_IPV4_BROADCAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// The standard mDNS port
pub const MDNS_PORT: u16 = 5353;

/// Maximum number of devices that can be discovered in a single query
pub const MAX_DISCOVERED_DEVICES: usize = 8;

/// Maximum number of IP addresses stored per discovered device
pub const MAX_ADDRESSES_PER_DEVICE: usize = 4;

/// Extension trait for pushing unique devices to a collection.
pub trait PushUnique {
    /// Push a device to the collection if no device with the same instance name exists.
    ///
    /// Returns `true` if the device was added, `false` if it was a duplicate or the collection is full.
    fn push_if_unique(&mut self, device: DiscoveredDevice) -> bool;
}

impl PushUnique for heapless::Vec<DiscoveredDevice, MAX_DISCOVERED_DEVICES> {
    fn push_if_unique(&mut self, device: DiscoveredDevice) -> bool {
        let is_duplicate = self.iter().any(|d| {
            d.instance_name
                .as_str()
                .eq_ignore_ascii_case(device.instance_name.as_str())
        });

        if !is_duplicate {
            self.push(device).is_ok()
        } else {
            false
        }
    }
}

#[cfg(feature = "std")]
impl PushUnique for std::vec::Vec<DiscoveredDevice> {
    fn push_if_unique(&mut self, device: DiscoveredDevice) -> bool {
        let is_duplicate = self.iter().any(|d| {
            d.instance_name
                .as_str()
                .eq_ignore_ascii_case(device.instance_name.as_str())
        });

        if !is_duplicate {
            self.push(device);
            true
        } else {
            false
        }
    }
}

/// Filter criteria for discovering commissionable devices.
///
/// This filter is used by mDNS discovery implementations to narrow down
/// the search for commissionable Matter devices on the local network.
///
/// The mDNS subtype filtering supports discriminator, short discriminator,
/// vendor ID, device type, and commissioning mode. Product ID filtering
/// is done post-discovery by checking TXT records.
#[derive(Debug, Clone, Default)]
pub struct CommissionableFilter {
    /// Filter by long discriminator (12-bit)
    pub discriminator: Option<u16>,
    /// Filter by short discriminator (4-bit, derived from long discriminator)
    pub short_discriminator: Option<u8>,
    /// Filter by vendor ID
    pub vendor_id: Option<u16>,
    /// Filter by product ID (applied post-discovery via TXT record check)
    pub product_id: Option<u16>,
    /// Filter by device type (uses `_T{type}` subtype)
    pub device_type: Option<u32>,
    /// Filter to only find devices in commissioning mode (uses `_CM` subtype)
    pub commissioning_mode_only: bool,
}

impl CommissionableFilter {
    /// Build the mDNS service type string for browsing commissionable devices.
    ///
    /// If the filter specifies a discriminator, short discriminator, vendor ID,
    /// device type, or commissioning mode, the service type will include the
    /// appropriate subtype for more efficient discovery.
    ///
    /// The priority order for subtypes is:
    /// 1. Long discriminator (`_L{disc}`)
    /// 2. Short discriminator (`_S{short}`)
    /// 3. Vendor ID (`_V{vid}`)
    /// 4. Device type (`_T{type}`)
    /// 5. Commissioning mode (`_CM`)
    ///
    /// Note: Product ID is not included in the service type because the Matter
    /// specification only defines it as part of the VP TXT record, not as a subtype.
    ///
    /// # Arguments
    /// * `buf` - A mutable string buffer to write the service type into
    /// * `include_local` - Whether to append `.local` suffix (needed for raw DNS queries)
    pub fn service_type(&self, buf: &mut heapless::String<64>, include_local: bool) {
        buf.clear();
        let suffix = if include_local { ".local" } else { "" };

        if let Some(disc) = self.discriminator {
            let _ = write!(buf, "_L{}._sub._matterc._udp{}", disc, suffix);
        } else if let Some(short_disc) = self.short_discriminator {
            let _ = write!(buf, "_S{}._sub._matterc._udp{}", short_disc, suffix);
        } else if let Some(vid) = self.vendor_id {
            let _ = write!(buf, "_V{}._sub._matterc._udp{}", vid, suffix);
        } else if let Some(dt) = self.device_type {
            let _ = write!(buf, "_T{}._sub._matterc._udp{}", dt, suffix);
        } else if self.commissioning_mode_only {
            let _ = write!(buf, "_CM._sub._matterc._udp{}", suffix);
        } else {
            let _ = write!(buf, "_matterc._udp{}", suffix);
        }
    }

    /// Check if a discovered device matches this filter's criteria.
    ///
    /// Returns `true` if the device matches all specified filter fields,
    /// or if no filter fields are set (empty filter matches all devices).
    pub fn matches(&self, device: &DiscoveredDevice) -> bool {
        if let Some(disc) = self.discriminator {
            if device.discriminator != disc {
                return false;
            }
        }

        if let Some(short_disc) = self.short_discriminator {
            // Short discriminator is the upper 4 bits of the 12-bit discriminator
            let device_short = (device.discriminator >> 8) as u8;
            if device_short != short_disc {
                return false;
            }
        }

        if let Some(vid) = self.vendor_id {
            if device.vendor_id != vid {
                return false;
            }
        }

        if let Some(pid) = self.product_id {
            if device.product_id != pid {
                return false;
            }
        }

        if let Some(dt) = self.device_type {
            if device.device_type != dt {
                return false;
            }
        }

        if self.commissioning_mode_only && !device.commissioning_mode.is_commissionable() {
            return false;
        }

        true
    }
}

/// Commissioning mode values for Matter devices.
///
/// This indicates whether a device is in commissioning mode and what type
/// of commissioning window is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CommissioningMode {
    /// Device is not in commissioning mode
    #[default]
    Disabled = 0,
    /// Basic commissioning window is open
    Basic = 1,
    /// Enhanced commissioning window is open (with passcode verifier)
    Enhanced = 2,
}

impl CommissioningMode {
    /// Parse a commissioning mode from a string value.
    pub fn from_txt_value(value: &str) -> Self {
        match value {
            "1" => Self::Basic,
            "2" => Self::Enhanced,
            _ => Self::Disabled,
        }
    }

    /// Returns true if the device is in any commissioning mode.
    pub fn is_commissionable(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// Score an IP address for prioritization.
///
/// Higher scores indicate more preferred addresses. The priority order follows
/// the Matter specification:
///
/// 1. Link-local IPv6 (highest priority) - most likely to work for local discovery
/// 2. Unique local IPv6 (ULA, fc00::/7) - private network addresses
/// 3. Global unicast IPv6 - routable addresses
/// 4. IPv4 (lowest priority)
///
/// This prioritization prefers IPv6 over IPv4 and local addresses over global ones,
/// which aligns with Matter's preference for link-local communication.
pub fn score_ip_address(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V6(ipv6) => {
            if is_ipv6_link_local(ipv6) {
                // Link-local IPv6 (fe80::/10) - highest priority
                100
            } else if is_ipv6_unique_local(ipv6) {
                // Unique local address (fc00::/7) - second priority
                80
            } else if is_ipv6_global_unicast(ipv6) {
                // Global unicast - third priority
                60
            } else {
                // Other IPv6 (multicast, etc.)
                40
            }
        }
        IpAddr::V4(_) => {
            // IPv4 - lowest priority
            20
        }
    }
}

/// Check if an IPv6 address is link-local (fe80::/10)
fn is_ipv6_link_local(addr: &Ipv6Addr) -> bool {
    let segments = addr.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

/// Check if an IPv6 address is unique local (fc00::/7)
fn is_ipv6_unique_local(addr: &Ipv6Addr) -> bool {
    let segments = addr.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

/// Check if an IPv6 address is global unicast (2000::/3)
fn is_ipv6_global_unicast(addr: &Ipv6Addr) -> bool {
    let segments = addr.segments();
    (segments[0] & 0xe000) == 0x2000
}

/// A discovered commissionable Matter device.
///
/// This struct contains the information parsed from mDNS PTR, SRV, TXT, and A/AAAA
/// records for a commissionable Matter device.
///
/// Multiple IP addresses may be available for a device. Use [`addr()`](Self::addr)
/// to get the best (highest priority) address, or [`addresses()`](Self::addresses)
/// to iterate over all addresses.
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    /// IP addresses for this device, sorted by priority (best first)
    addresses: heapless::Vec<IpAddr, MAX_ADDRESSES_PER_DEVICE>,
    /// The device's port from SRV record
    pub port: u16,
    /// The device's discriminator from TXT record
    pub discriminator: u16,
    /// Vendor ID from TXT record
    pub vendor_id: u16,
    /// Product ID from TXT record
    pub product_id: u16,
    /// Commissioning mode from TXT record
    pub commissioning_mode: CommissioningMode,
    /// Device type from TXT record (optional, 0 means not set)
    pub device_type: u32,
    /// MRP retry interval for idle mode in milliseconds (SII TXT field)
    ///
    /// This is the retry interval used when the device is in idle mode.
    /// `None` means the field was not present in the TXT record.
    pub mrp_retry_interval_idle: Option<u32>,
    /// MRP retry interval for active mode in milliseconds (SAI TXT field)
    ///
    /// This is the retry interval used when the device is in active mode.
    /// `None` means the field was not present in the TXT record.
    pub mrp_retry_interval_active: Option<u32>,
    /// Pairing hint bitmap (PH TXT field)
    ///
    /// A bitmap indicating which pairing methods are supported by the device.
    /// `None` means the field was not present in the TXT record.
    pub pairing_hint: Option<u16>,
    /// Pairing instruction (PI TXT field)
    ///
    /// Human-readable pairing instructions for the device.
    pub pairing_instruction: heapless::String<128>,
    /// Device name from TXT record (optional)
    pub device_name: heapless::String<32>,
    /// Instance name from mDNS
    pub instance_name: heapless::String<64>,
}

impl Default for DiscoveredDevice {
    fn default() -> Self {
        Self {
            addresses: heapless::Vec::new(),
            port: 0,
            discriminator: 0,
            vendor_id: 0,
            product_id: 0,
            commissioning_mode: CommissioningMode::default(),
            device_type: 0,
            mrp_retry_interval_idle: None,
            mrp_retry_interval_active: None,
            pairing_hint: None,
            pairing_instruction: heapless::String::new(),
            device_name: heapless::String::new(),
            instance_name: heapless::String::new(),
        }
    }
}

impl DiscoveredDevice {
    /// Get the best (highest priority) socket address for this device.
    ///
    /// Returns the address with the highest score according to [`score_ip_address`],
    /// preferring link-local IPv6 over other address types.
    ///
    /// Returns `None` if no addresses are available.
    pub fn addr(&self) -> Option<SocketAddr> {
        self.addresses
            .first()
            .map(|ip| SocketAddr::new(*ip, self.port))
    }

    /// Get all IP addresses for this device, sorted by priority (best first).
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Get all socket addresses for this device, sorted by priority (best first).
    pub fn socket_addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.addresses
            .iter()
            .map(move |ip| SocketAddr::new(*ip, self.port))
    }

    /// Add an IP address to this device.
    ///
    /// The address is inserted in priority order (highest score first).
    /// If the address already exists, it is not added again.
    /// If the address list is full, lower-priority addresses may be evicted.
    pub fn add_address(&mut self, addr: IpAddr) {
        // Check for duplicates
        if self.addresses.contains(&addr) {
            return;
        }

        let score = score_ip_address(&addr);

        // Find insertion position (maintain sorted order by score, descending)
        let pos = self
            .addresses
            .iter()
            .position(|a| score_ip_address(a) < score)
            .unwrap_or(self.addresses.len());

        if pos < MAX_ADDRESSES_PER_DEVICE {
            if self.addresses.len() >= MAX_ADDRESSES_PER_DEVICE {
                // Remove lowest priority address to make room
                self.addresses.pop();
            }
            // Insert at the correct position
            let _ = self.addresses.insert(pos, addr);
        }
    }

    /// Set the address from a SocketAddr (convenience method for single-address case).
    ///
    /// This clears any existing addresses and sets both the IP and port.
    pub fn set_addr(&mut self, addr: SocketAddr) {
        self.addresses.clear();
        let _ = self.addresses.push(addr.ip());
        self.port = addr.port();
    }

    /// Parse and set a TXT record key-value pair.
    ///
    /// Handles the standard Matter TXT record fields:
    /// - `D`: Discriminator (12-bit value)
    /// - `VP`: Vendor ID + Product ID in format "VID+PID"
    /// - `CM`: Commissioning mode (0=disabled, 1=basic, 2=enhanced)
    /// - `DT`: Device type (32-bit value from Matter device type hierarchy)
    /// - `SII`: Sleepy Idle Interval - MRP retry interval for idle mode (ms)
    /// - `SAI`: Sleepy Active Interval - MRP retry interval for active mode (ms)
    /// - `PH`: Pairing hint bitmap
    /// - `PI`: Pairing instruction (human-readable)
    /// - `DN`: Device name
    ///
    /// Other keys (RI, T, ICD, CP, etc.) are ignored.
    pub fn set_txt_value(&mut self, key: &str, value: &str) {
        match key.to_ascii_lowercase().as_str() {
            "d" => {
                if let Ok(d) = value.parse::<u16>() {
                    // Discriminator is a 12-bit value (0-4095)
                    if d <= 0xFFF {
                        self.discriminator = d;
                    }
                }
            }
            "vp" => {
                if let Some(plus_pos) = value.find('+') {
                    if let Ok(vid) = value[..plus_pos].parse::<u16>() {
                        self.vendor_id = vid;
                    }
                    if let Ok(pid) = value[plus_pos + 1..].parse::<u16>() {
                        self.product_id = pid;
                    }
                }
            }
            "cm" => {
                self.commissioning_mode = CommissioningMode::from_txt_value(value);
            }
            "dt" => {
                if let Ok(dt) = value.parse::<u32>() {
                    self.device_type = dt;
                }
            }
            "sii" => {
                if let Ok(sii) = value.parse::<u32>() {
                    self.mrp_retry_interval_idle = Some(sii);
                }
            }
            "sai" => {
                if let Ok(sai) = value.parse::<u32>() {
                    self.mrp_retry_interval_active = Some(sai);
                }
            }
            "ph" => {
                if let Ok(ph) = value.parse::<u16>() {
                    self.pairing_hint = Some(ph);
                }
            }
            "pi" => {
                self.pairing_instruction.clear();
                let _ = write!(&mut self.pairing_instruction, "{}", value);
            }
            "dn" => {
                self.device_name.clear();
                let _ = write!(&mut self.device_name, "{}", value);
            }
            _ => {}
        }
    }

    pub fn set_instance_name(&mut self, name: &str) {
        let _ = write!(&mut self.instance_name, "{}", name);
    }
}

/// A default bind address for mDNS sockets. Binds to all available interfaces
pub const MDNS_SOCKET_DEFAULT_BIND_ADDR: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0));

/// A trait for resolving Matter nodes to socket addresses over mDNS
pub trait MdnsResolver {
    /// Resolve a Matter node's address using mDNS.
    ///
    /// # Arguments
    /// - `compressed_fabric_id`: The compressed fabric ID of the Matter node.
    /// - `node_id`: The node ID of the Matter node.
    async fn resolve(
        &mut self,
        compressed_fabric_id: u64,
        node_id: u64,
    ) -> Result<SocketAddr, Error>;
}

impl<T> MdnsResolver for &mut T
where
    T: MdnsResolver,
{
    fn resolve(
        &mut self,
        compressed_fabric_id: u64,
        node_id: u64,
    ) -> impl Future<Output = Result<SocketAddr, Error>> {
        (*self).resolve(compressed_fabric_id, node_id)
    }
}

/// A utility type for expanding a `MatterMdnsService` type into a full mDNS service description
///
/// Useful as an implementation detail when interfacing with OS-specific mDNS libraries.
pub struct Service<'a> {
    /// The name of the service, typically the mDNS name
    pub name: &'a str,
    /// The service type, e.g. "_matter" or "_matterc"
    pub service: &'a str,
    /// The protocol used, e.g. "_tcp" or "_udp"
    pub protocol: &'a str,
    /// The service and protocol combined, e.g. "_matter._tcp" or "_matterc._udp"
    pub service_protocol: &'a str,
    /// The port number the service is running on
    pub port: u16,
    /// Optional service subtypes, e.g. "_L1234" or "_S12"
    pub service_subtypes: &'a [&'a str],
    /// Key-value pairs for TXT records, e.g. ("D", "1234")
    pub txt_kvs: &'a [(&'a str, &'a str)],
}

impl Service<'_> {
    /// Asynchronously expand a `MatterMdnsService` into a full service description
    ///
    /// # Arguments
    /// - `matter_service`: The Matter mDNS service to expand.
    /// - `dev_det`: The device details configuration.
    /// - `matter_port`: The port number the Matter service is running on.
    /// - `f`: A closure that takes a reference to the expanded service and returns a result.
    pub async fn async_call_with<R, F: for<'a> AsyncFnOnce(&'a Service<'a>) -> Result<R, Error>>(
        matter_service: &MatterMdnsService,
        dev_det: &BasicInfoConfig<'_>,
        matter_port: u16,
        f: F,
    ) -> Result<R, Error> {
        let mut name_buf = [0; MATTER_SERVICE_MAX_NAME_LEN];

        match matter_service {
            MatterMdnsService::Commissioned { .. } => {
                f(&Service {
                    name: matter_service.name(&mut name_buf),
                    service: "_matter",
                    protocol: "_tcp",
                    service_protocol: "_matter._tcp",
                    port: matter_port,
                    service_subtypes: &[],
                    // Some mDNS responders do not accept empty TXT records
                    txt_kvs: &[("dummy", "dummy")],
                })
                .await
            }
            MatterMdnsService::Commissionable { discriminator, .. } => {
                // "_L{u16}""
                let mut discr_svc_str = heapless::String::<7>::new();
                // "_S{u16}""
                let mut short_discr_svc_str = heapless::String::<7>::new();
                // "_V{u16}P{u16}""
                let mut vp_svc_str = heapless::String::<13>::new();

                // "{u16}
                let mut discr_str = heapless::String::<5>::new();
                // "{u16}+{u16}"
                let mut vp_str = heapless::String::<11>::new();
                // "{u16}"
                let mut sai_str = heapless::String::<5>::new();
                // "{u16}"
                let mut sii_str = heapless::String::<5>::new();
                // "{u16}"
                let mut dt_str = heapless::String::<6>::new();
                // "{u32}"
                let mut ph_str = heapless::String::<12>::new();

                let mut txt_kvs = heapless::Vec::<_, 9>::new();

                write_unwrap!(&mut discr_svc_str, "_L{}", *discriminator);
                write_unwrap!(
                    &mut short_discr_svc_str,
                    "_S{}",
                    Self::compute_short_discriminator(*discriminator)
                );
                write_unwrap!(&mut vp_svc_str, "_V{}P{}", dev_det.vid, dev_det.pid);

                write_unwrap!(discr_str, "{}", *discriminator);
                unwrap!(txt_kvs.push(("D", discr_str.as_str())));

                unwrap!(txt_kvs.push(("CM", "1")));

                write_unwrap!(&mut vp_str, "{}+{}", dev_det.vid, dev_det.pid);
                unwrap!(txt_kvs.push(("VP", &vp_str)));

                write_unwrap!(sai_str, "{}", dev_det.sai.unwrap_or(300));
                unwrap!(txt_kvs.push(("SAI", sai_str.as_str())));

                write_unwrap!(sii_str, "{}", dev_det.sii.unwrap_or(5000));
                unwrap!(txt_kvs.push(("SII", sii_str.as_str())));

                if !dev_det.device_name.is_empty() {
                    unwrap!(txt_kvs.push(("DN", dev_det.device_name)));
                }

                if let Some(device_type) = dev_det.device_type {
                    write_unwrap!(&mut dt_str, "{}", device_type);
                    unwrap!(txt_kvs.push(("DT", dt_str.as_str())));
                }

                if !dev_det.pairing_hint.is_empty() {
                    write_unwrap!(&mut ph_str, "{}", dev_det.pairing_hint.bits());
                    unwrap!(txt_kvs.push(("PH", ph_str.as_str())));
                }

                if !dev_det.pairing_instruction.is_empty() {
                    unwrap!(txt_kvs.push(("PI", dev_det.pairing_instruction)));
                }

                f(&Service {
                    name: matter_service.name(&mut name_buf),
                    service: "_matterc",
                    protocol: "_udp",
                    service_protocol: "_matterc._udp",
                    port: matter_port,
                    service_subtypes: &[
                        discr_svc_str.as_str(),
                        short_discr_svc_str.as_str(),
                        vp_svc_str.as_str(),
                        "_CM",
                    ],
                    txt_kvs: txt_kvs.as_slice(),
                })
                .await
            }
        }
    }

    /// Expand a `MatterMdnsService` into a full service description
    ///
    /// # Arguments
    /// - `matter_service`: The Matter mDNS service to expand.
    /// - `dev_det`: The device details configuration.
    /// - `matter_port`: The port number the Matter service is running on.
    /// - `f`: A closure that takes a reference to the expanded service and returns a result.
    pub fn call_with<R, F: for<'a> FnOnce(&'a Service<'a>) -> Result<R, Error>>(
        matter_service: &MatterMdnsService,
        dev_det: &BasicInfoConfig<'_>,
        matter_port: u16,
        f: F,
    ) -> Result<R, Error> {
        // Not the most elegant solution to cut down on code duplication,
        // but works fine because we _know_ the future will resolve immediately,
        // because the `f` closure does not block and resolves immediately as well.
        embassy_futures::block_on(Self::async_call_with(
            matter_service,
            dev_det,
            matter_port,
            async |service| f(service),
        ))
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
        let short = Service::compute_short_discriminator(discriminator);
        assert_eq!(short, 0b1111);

        let discriminator: u16 = 840;
        let short = Service::compute_short_discriminator(discriminator);
        assert_eq!(short, 3);
    }

    fn make_device(discriminator: u16, vendor_id: u16, product_id: u16) -> DiscoveredDevice {
        let mut device = DiscoveredDevice::default();
        device.discriminator = discriminator;
        device.vendor_id = vendor_id;
        device.product_id = product_id;
        device
    }

    #[test]
    fn filter_matches_empty_filter_matches_all() {
        let filter = CommissionableFilter::default();
        let device = make_device(1234, 0xFFF1, 0x8000);
        assert!(filter.matches(&device));
    }

    #[test]
    fn filter_matches_discriminator() {
        let filter = CommissionableFilter {
            discriminator: Some(1234),
            ..Default::default()
        };
        let device = make_device(1234, 0xFFF1, 0x8000);
        assert!(filter.matches(&device));
    }

    #[test]
    fn filter_rejects_wrong_discriminator() {
        let filter = CommissionableFilter {
            discriminator: Some(1234),
            ..Default::default()
        };
        let device = make_device(5678, 0xFFF1, 0x8000);
        assert!(!filter.matches(&device));
    }

    #[test]
    fn filter_matches_short_discriminator() {
        // Short discriminator is upper 4 bits of 12-bit discriminator
        // Discriminator 840 (0x348) has short discriminator 3 (0x3)
        let filter = CommissionableFilter {
            short_discriminator: Some(3),
            ..Default::default()
        };
        let device = make_device(840, 0xFFF1, 0x8000);
        assert!(filter.matches(&device));

        // Any discriminator in range 0x300-0x3FF should match short discriminator 3
        let device2 = make_device(0x3FF, 0xFFF1, 0x8000);
        assert!(filter.matches(&device2));
    }

    #[test]
    fn filter_rejects_wrong_short_discriminator() {
        let filter = CommissionableFilter {
            short_discriminator: Some(3),
            ..Default::default()
        };
        // Discriminator 0x400 has short discriminator 4
        let device = make_device(0x400, 0xFFF1, 0x8000);
        assert!(!filter.matches(&device));
    }

    #[test]
    fn filter_matches_vendor_id() {
        let filter = CommissionableFilter {
            vendor_id: Some(0xFFF1),
            ..Default::default()
        };
        let device = make_device(1234, 0xFFF1, 0x8000);
        assert!(filter.matches(&device));
    }

    #[test]
    fn filter_rejects_wrong_vendor_id() {
        let filter = CommissionableFilter {
            vendor_id: Some(0xFFF1),
            ..Default::default()
        };
        let device = make_device(1234, 0xFFF2, 0x8000);
        assert!(!filter.matches(&device));
    }

    #[test]
    fn filter_matches_product_id() {
        let filter = CommissionableFilter {
            product_id: Some(0x8000),
            ..Default::default()
        };
        let device = make_device(1234, 0xFFF1, 0x8000);
        assert!(filter.matches(&device));
    }

    #[test]
    fn filter_rejects_wrong_product_id() {
        let filter = CommissionableFilter {
            product_id: Some(0x8000),
            ..Default::default()
        };
        let device = make_device(1234, 0xFFF1, 0x8001);
        assert!(!filter.matches(&device));
    }

    #[test]
    fn filter_matches_combined_filters() {
        let filter = CommissionableFilter {
            discriminator: Some(1234),
            vendor_id: Some(0xFFF1),
            product_id: Some(0x8000),
            ..Default::default()
        };
        let device = make_device(1234, 0xFFF1, 0x8000);
        assert!(filter.matches(&device));
    }

    #[test]
    fn filter_rejects_partial_match() {
        // All filter criteria must match
        let filter = CommissionableFilter {
            discriminator: Some(1234),
            vendor_id: Some(0xFFF1),
            ..Default::default()
        };
        // Discriminator matches but vendor_id doesn't
        let device = make_device(1234, 0xFFF2, 0x8000);
        assert!(!filter.matches(&device));
    }

    #[test]
    fn filter_matches_device_type() {
        let filter = CommissionableFilter {
            device_type: Some(257),
            ..Default::default()
        };

        let mut device = make_device(1234, 0xFFF1, 0x8000);
        device.device_type = 257;
        assert!(filter.matches(&device));
    }

    #[test]
    fn filter_rejects_wrong_device_type() {
        let filter = CommissionableFilter {
            device_type: Some(257),
            ..Default::default()
        };

        let mut device = make_device(1234, 0xFFF1, 0x8000);
        device.device_type = 258; // Wrong device type
        assert!(!filter.matches(&device));
    }

    #[test]
    fn filter_matches_commissioning_mode_only() {
        let filter = CommissionableFilter {
            commissioning_mode_only: true,
            ..Default::default()
        };

        let mut device = make_device(1234, 0xFFF1, 0x8000);
        device.commissioning_mode = CommissioningMode::Basic;
        assert!(filter.matches(&device));

        device.commissioning_mode = CommissioningMode::Enhanced;
        assert!(filter.matches(&device));
    }

    #[test]
    fn filter_rejects_non_commissioning_device() {
        let filter = CommissionableFilter {
            commissioning_mode_only: true,
            ..Default::default()
        };

        let mut device = make_device(1234, 0xFFF1, 0x8000);
        device.commissioning_mode = CommissioningMode::Disabled;
        assert!(!filter.matches(&device));
    }

    #[test]
    fn filter_without_commissioning_mode_matches_all() {
        // When commissioning_mode_only is false, match all devices regardless of CM
        let filter = CommissionableFilter::default();

        let mut device = make_device(1234, 0xFFF1, 0x8000);
        device.commissioning_mode = CommissioningMode::Disabled;
        assert!(filter.matches(&device));

        device.commissioning_mode = CommissioningMode::Basic;
        assert!(filter.matches(&device));
    }

    #[test]
    fn service_type_no_filter() {
        let filter = CommissionableFilter::default();
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_matterc._udp");

        filter.service_type(&mut buf, true);
        assert_eq!(buf.as_str(), "_matterc._udp.local");
    }

    #[test]
    fn service_type_with_discriminator() {
        let filter = CommissionableFilter {
            discriminator: Some(1234),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_L1234._sub._matterc._udp");

        filter.service_type(&mut buf, true);
        assert_eq!(buf.as_str(), "_L1234._sub._matterc._udp.local");
    }

    #[test]
    fn service_type_with_short_discriminator() {
        let filter = CommissionableFilter {
            short_discriminator: Some(3),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_S3._sub._matterc._udp");

        filter.service_type(&mut buf, true);
        assert_eq!(buf.as_str(), "_S3._sub._matterc._udp.local");
    }

    #[test]
    fn service_type_with_vendor_id() {
        // Vendor ID creates a subtype; product ID is filtered post-discovery
        let filter = CommissionableFilter {
            vendor_id: Some(0xFFF1),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_V65521._sub._matterc._udp");

        filter.service_type(&mut buf, true);
        assert_eq!(buf.as_str(), "_V65521._sub._matterc._udp.local");
    }

    #[test]
    fn service_type_with_vendor_and_product_id() {
        // Product ID does not affect service type - only vendor ID is used for subtype
        let filter = CommissionableFilter {
            vendor_id: Some(0xFFF1),
            product_id: Some(0x8000),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_V65521._sub._matterc._udp");

        filter.service_type(&mut buf, true);
        assert_eq!(buf.as_str(), "_V65521._sub._matterc._udp.local");
    }

    #[test]
    fn service_type_discriminator_takes_priority() {
        // When discriminator is set, it takes priority over short_discriminator and vendor/product
        let filter = CommissionableFilter {
            discriminator: Some(1234),
            short_discriminator: Some(3),
            vendor_id: Some(0xFFF1),
            product_id: Some(0x8000),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_L1234._sub._matterc._udp");
    }

    #[test]
    fn service_type_short_discriminator_priority_over_vendor() {
        // Short discriminator takes priority over vendor ID
        let filter = CommissionableFilter {
            short_discriminator: Some(3),
            vendor_id: Some(0xFFF1),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_S3._sub._matterc._udp");
    }

    #[test]
    fn service_type_product_id_alone_no_subtype() {
        // Product ID alone does not create a subtype (vendor ID is required for VP filtering)
        let filter = CommissionableFilter {
            product_id: Some(0x8000),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_matterc._udp");
    }

    #[test]
    fn service_type_with_device_type() {
        // Device type 257 (0x101) = On/Off Light
        let filter = CommissionableFilter {
            device_type: Some(257),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_T257._sub._matterc._udp");

        filter.service_type(&mut buf, true);
        assert_eq!(buf.as_str(), "_T257._sub._matterc._udp.local");
    }

    #[test]
    fn service_type_with_commissioning_mode_only() {
        let filter = CommissionableFilter {
            commissioning_mode_only: true,
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_CM._sub._matterc._udp");

        filter.service_type(&mut buf, true);
        assert_eq!(buf.as_str(), "_CM._sub._matterc._udp.local");
    }

    #[test]
    fn service_type_device_type_priority_over_cm() {
        // Device type takes priority over commissioning mode only
        let filter = CommissionableFilter {
            device_type: Some(257),
            commissioning_mode_only: true,
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_T257._sub._matterc._udp");
    }

    #[test]
    fn service_type_vendor_id_priority_over_device_type() {
        // Vendor ID takes priority over device type
        let filter = CommissionableFilter {
            vendor_id: Some(0xFFF1),
            device_type: Some(257),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_V65521._sub._matterc._udp");
    }

    #[test]
    fn set_txt_value_discriminator() {
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("D", "1234");
        assert_eq!(device.discriminator, 1234);
    }

    #[test]
    fn set_txt_value_discriminator_invalid() {
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("D", "not_a_number");
        assert_eq!(device.discriminator, 0); // Should remain default
    }

    #[test]
    fn set_txt_value_discriminator_range_valid() {
        let mut device = DiscoveredDevice::default();

        // Maximum valid discriminator (12-bit = 4095)
        device.set_txt_value("D", "4095");
        assert_eq!(device.discriminator, 4095);

        // Minimum valid discriminator
        device.set_txt_value("D", "0");
        assert_eq!(device.discriminator, 0);
    }

    #[test]
    fn set_txt_value_discriminator_range_invalid() {
        let mut device = DiscoveredDevice::default();

        // Set a valid value first
        device.set_txt_value("D", "1234");
        assert_eq!(device.discriminator, 1234);

        // Value above 4095 should be rejected (discriminator unchanged)
        device.set_txt_value("D", "4096");
        assert_eq!(device.discriminator, 1234); // Still 1234

        // Much larger value should also be rejected
        device.set_txt_value("D", "65535");
        assert_eq!(device.discriminator, 1234); // Still 1234
    }

    #[test]
    fn set_txt_value_vendor_product() {
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("VP", "65521+32768");
        assert_eq!(device.vendor_id, 65521);
        assert_eq!(device.product_id, 32768);
    }

    #[test]
    fn set_txt_value_vendor_product_invalid_format() {
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("VP", "65521"); // Missing +PID
        assert_eq!(device.vendor_id, 0);
        assert_eq!(device.product_id, 0);
    }

    #[test]
    fn set_txt_value_vendor_product_invalid_numbers() {
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("VP", "abc+def");
        assert_eq!(device.vendor_id, 0);
        assert_eq!(device.product_id, 0);
    }

    #[test]
    fn set_txt_value_device_name() {
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("DN", "Test Device");
        assert_eq!(device.device_name.as_str(), "Test Device");
    }

    #[test]
    fn set_txt_value_device_name_truncated() {
        let mut device = DiscoveredDevice::default();
        // Device name buffer is 32 chars, this string is longer
        let long_name = "This is a very long device name that exceeds the buffer";
        device.set_txt_value("DN", long_name);
        // Should be truncated to fit in the buffer
        assert!(device.device_name.len() <= 32);
    }

    #[test]
    fn set_txt_value_unknown_key_ignored() {
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("UNKNOWN", "value");
        device.set_txt_value("XYZ", "123");
        // Device should remain at defaults
        assert_eq!(device.discriminator, 0);
        assert_eq!(device.vendor_id, 0);
        assert_eq!(device.product_id, 0);
        assert!(device.device_name.is_empty());
        assert_eq!(device.commissioning_mode, CommissioningMode::Disabled);
    }

    #[test]
    fn set_txt_value_keys_are_case_insensitive() {
        // Test D (discriminator) - lowercase, uppercase, mixed
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("d", "1000");
        assert_eq!(device.discriminator, 1000);

        device.set_txt_value("D", "2000");
        assert_eq!(device.discriminator, 2000);

        // Test VP (vendor+product) - lowercase, uppercase, mixed
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("vp", "100+200");
        assert_eq!(device.vendor_id, 100);
        assert_eq!(device.product_id, 200);

        let mut device = DiscoveredDevice::default();
        device.set_txt_value("VP", "101+201");
        assert_eq!(device.vendor_id, 101);
        assert_eq!(device.product_id, 201);

        let mut device = DiscoveredDevice::default();
        device.set_txt_value("Vp", "102+202");
        assert_eq!(device.vendor_id, 102);
        assert_eq!(device.product_id, 202);

        // Test CM (commissioning mode) - lowercase, uppercase, mixed
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("cm", "1");
        assert_eq!(device.commissioning_mode, CommissioningMode::Basic);

        device.set_txt_value("CM", "2");
        assert_eq!(device.commissioning_mode, CommissioningMode::Enhanced);

        device.set_txt_value("Cm", "0");
        assert_eq!(device.commissioning_mode, CommissioningMode::Disabled);

        // Test DT (device type) - lowercase, uppercase, mixed
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("dt", "256");
        assert_eq!(device.device_type, 256);

        device.set_txt_value("DT", "257");
        assert_eq!(device.device_type, 257);

        device.set_txt_value("Dt", "258");
        assert_eq!(device.device_type, 258);

        // Test DN (device name) - lowercase, uppercase, mixed
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("dn", "name1");
        assert_eq!(device.device_name.as_str(), "name1");

        device.set_txt_value("DN", "name2");
        assert_eq!(device.device_name.as_str(), "name2");

        device.set_txt_value("Dn", "name3");
        assert_eq!(device.device_name.as_str(), "name3");

        // Test SII (MRP idle interval) - lowercase, uppercase, mixed
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("sii", "1000");
        assert_eq!(device.mrp_retry_interval_idle, Some(1000));

        device.set_txt_value("SII", "2000");
        assert_eq!(device.mrp_retry_interval_idle, Some(2000));

        device.set_txt_value("Sii", "3000");
        assert_eq!(device.mrp_retry_interval_idle, Some(3000));

        // Test SAI (MRP active interval) - lowercase, uppercase, mixed
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("sai", "100");
        assert_eq!(device.mrp_retry_interval_active, Some(100));

        device.set_txt_value("SAI", "200");
        assert_eq!(device.mrp_retry_interval_active, Some(200));

        device.set_txt_value("Sai", "300");
        assert_eq!(device.mrp_retry_interval_active, Some(300));

        // Test PH (pairing hint) - lowercase, uppercase, mixed
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("ph", "10");
        assert_eq!(device.pairing_hint, Some(10));

        device.set_txt_value("PH", "20");
        assert_eq!(device.pairing_hint, Some(20));

        device.set_txt_value("Ph", "30");
        assert_eq!(device.pairing_hint, Some(30));

        // Test PI (pairing instruction) - lowercase, uppercase, mixed
        let mut device = DiscoveredDevice::default();
        device.set_txt_value("pi", "instruction1");
        assert_eq!(device.pairing_instruction.as_str(), "instruction1");

        device.set_txt_value("PI", "instruction2");
        assert_eq!(device.pairing_instruction.as_str(), "instruction2");

        device.set_txt_value("Pi", "instruction3");
        assert_eq!(device.pairing_instruction.as_str(), "instruction3");
    }

    // Tests for CommissioningMode

    #[test]
    fn commissioning_mode_from_txt_value_disabled() {
        assert_eq!(
            CommissioningMode::from_txt_value("0"),
            CommissioningMode::Disabled
        );
    }

    #[test]
    fn commissioning_mode_from_txt_value_basic() {
        assert_eq!(
            CommissioningMode::from_txt_value("1"),
            CommissioningMode::Basic
        );
    }

    #[test]
    fn commissioning_mode_from_txt_value_enhanced() {
        assert_eq!(
            CommissioningMode::from_txt_value("2"),
            CommissioningMode::Enhanced
        );
    }

    #[test]
    fn commissioning_mode_from_txt_value_invalid() {
        // Invalid values should default to Disabled
        assert_eq!(
            CommissioningMode::from_txt_value("3"),
            CommissioningMode::Disabled
        );
        assert_eq!(
            CommissioningMode::from_txt_value(""),
            CommissioningMode::Disabled
        );
        assert_eq!(
            CommissioningMode::from_txt_value("abc"),
            CommissioningMode::Disabled
        );
    }

    #[test]
    fn commissioning_mode_is_commissionable() {
        assert!(!CommissioningMode::Disabled.is_commissionable());
        assert!(CommissioningMode::Basic.is_commissionable());
        assert!(CommissioningMode::Enhanced.is_commissionable());
    }

    #[test]
    fn set_txt_value_commissioning_mode() {
        let mut device = DiscoveredDevice::default();
        assert_eq!(device.commissioning_mode, CommissioningMode::Disabled);

        device.set_txt_value("CM", "1");
        assert_eq!(device.commissioning_mode, CommissioningMode::Basic);

        device.set_txt_value("CM", "2");
        assert_eq!(device.commissioning_mode, CommissioningMode::Enhanced);

        device.set_txt_value("CM", "0");
        assert_eq!(device.commissioning_mode, CommissioningMode::Disabled);
    }

    #[test]
    fn set_txt_value_device_type() {
        let mut device = DiscoveredDevice::default();
        assert_eq!(device.device_type, 0);

        // Device type 257 (0x101) = On/Off Light
        device.set_txt_value("DT", "257");
        assert_eq!(device.device_type, 257);
    }

    #[test]
    fn set_txt_value_device_type_large_value() {
        let mut device = DiscoveredDevice::default();

        // Device type can be up to 32 bits
        device.set_txt_value("DT", "4294967295");
        assert_eq!(device.device_type, u32::MAX);
    }

    #[test]
    fn set_txt_value_device_type_invalid() {
        let mut device = DiscoveredDevice::default();

        // Invalid value should leave device_type unchanged
        device.set_txt_value("DT", "not_a_number");
        assert_eq!(device.device_type, 0);

        // Overflow should not crash (parse returns Err)
        device.set_txt_value("DT", "99999999999999999999");
        assert_eq!(device.device_type, 0);
    }

    #[test]
    fn set_txt_value_mrp_idle_interval() {
        let mut device = DiscoveredDevice::default();
        assert_eq!(device.mrp_retry_interval_idle, None);

        // SII = 5000 ms (typical idle interval)
        device.set_txt_value("SII", "5000");
        assert_eq!(device.mrp_retry_interval_idle, Some(5000));
    }

    #[test]
    fn set_txt_value_mrp_active_interval() {
        let mut device = DiscoveredDevice::default();
        assert_eq!(device.mrp_retry_interval_active, None);

        // SAI = 300 ms (typical active interval)
        device.set_txt_value("SAI", "300");
        assert_eq!(device.mrp_retry_interval_active, Some(300));
    }

    #[test]
    fn set_txt_value_mrp_both_intervals() {
        let mut device = DiscoveredDevice::default();

        device.set_txt_value("SII", "5000");
        device.set_txt_value("SAI", "300");

        assert_eq!(device.mrp_retry_interval_idle, Some(5000));
        assert_eq!(device.mrp_retry_interval_active, Some(300));
    }

    #[test]
    fn set_txt_value_mrp_invalid_values() {
        let mut device = DiscoveredDevice::default();

        // Invalid values should leave the fields as None
        device.set_txt_value("SII", "not_a_number");
        device.set_txt_value("SAI", "also_invalid");

        assert_eq!(device.mrp_retry_interval_idle, None);
        assert_eq!(device.mrp_retry_interval_active, None);
    }

    #[test]
    fn set_txt_value_mrp_large_values() {
        let mut device = DiscoveredDevice::default();

        // Large values should work (C++ SDK allows up to 1 hour = 3,600,000 ms)
        device.set_txt_value("SII", "3600000");
        device.set_txt_value("SAI", "3600000");

        assert_eq!(device.mrp_retry_interval_idle, Some(3_600_000));
        assert_eq!(device.mrp_retry_interval_active, Some(3_600_000));
    }

    // Tests for pairing hint (PH) and pairing instruction (PI)

    #[test]
    fn set_txt_value_pairing_hint() {
        let mut device = DiscoveredDevice::default();
        assert_eq!(device.pairing_hint, None);

        // PH=33 means bits 0 and 5 set (Power Cycle + Administrator's Guide)
        device.set_txt_value("PH", "33");
        assert_eq!(device.pairing_hint, Some(33));
    }

    #[test]
    fn set_txt_value_pairing_hint_invalid() {
        let mut device = DiscoveredDevice::default();

        device.set_txt_value("PH", "not_a_number");
        assert_eq!(device.pairing_hint, None);
    }

    #[test]
    fn set_txt_value_pairing_instruction() {
        let mut device = DiscoveredDevice::default();
        assert!(device.pairing_instruction.is_empty());

        device.set_txt_value("PI", "Press the button on the device");
        assert_eq!(
            device.pairing_instruction.as_str(),
            "Press the button on the device"
        );
    }

    #[test]
    fn set_txt_value_pairing_instruction_truncated() {
        let mut device = DiscoveredDevice::default();

        // Pairing instruction buffer is 128 chars, this string is longer
        let long_instruction = "This is a very long pairing instruction that exceeds the buffer size limit and should be truncated to fit within the maximum allowed length for pairing instructions in Matter devices";
        device.set_txt_value("PI", long_instruction);

        // Should be truncated to fit in the buffer
        assert!(device.pairing_instruction.len() <= 128);
    }

    #[test]
    fn push_if_unique_adds_new_device() {
        let mut devices = heapless::Vec::<DiscoveredDevice, MAX_DISCOVERED_DEVICES>::new();
        let mut device = DiscoveredDevice::default();
        device.set_instance_name("device1");

        assert!(devices.push_if_unique(device));
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn push_if_unique_rejects_duplicate() {
        let mut devices = heapless::Vec::<DiscoveredDevice, MAX_DISCOVERED_DEVICES>::new();

        let mut device1 = DiscoveredDevice::default();
        device1.set_instance_name("device1");
        devices.push_if_unique(device1);

        let mut device2 = DiscoveredDevice::default();
        device2.set_instance_name("device1");

        assert!(!devices.push_if_unique(device2));
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn push_if_unique_rejects_case_insensitive_duplicate() {
        let mut devices = heapless::Vec::<DiscoveredDevice, MAX_DISCOVERED_DEVICES>::new();

        let mut device1 = DiscoveredDevice::default();
        device1.set_instance_name("device1");
        devices.push_if_unique(device1);

        let mut device2 = DiscoveredDevice::default();
        device2.set_instance_name("Device1");

        assert!(!devices.push_if_unique(device2));
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn push_if_unique_allows_different_names() {
        let mut devices = heapless::Vec::<DiscoveredDevice, MAX_DISCOVERED_DEVICES>::new();

        let mut device1 = DiscoveredDevice::default();
        device1.set_instance_name("device1");
        devices.push_if_unique(device1);

        let mut device2 = DiscoveredDevice::default();
        device2.set_instance_name("device2");

        assert!(devices.push_if_unique(device2));
        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn push_if_unique_returns_false_when_full() {
        let mut devices = heapless::Vec::<DiscoveredDevice, MAX_DISCOVERED_DEVICES>::new();

        // Fill up the vector
        for i in 0..MAX_DISCOVERED_DEVICES {
            let mut device = DiscoveredDevice::default();
            device.set_instance_name(&format!("device{i}"));
            assert!(devices.push_if_unique(device));
        }

        // Try to add one more
        let mut extra = DiscoveredDevice::default();
        extra.set_instance_name("extra");
        assert!(!devices.push_if_unique(extra));
        assert_eq!(devices.len(), MAX_DISCOVERED_DEVICES);
    }

    #[cfg(feature = "std")]
    #[test]
    fn push_if_unique_std_vec_adds_new_device() {
        let mut devices: Vec<DiscoveredDevice> = Vec::new();
        let mut device = DiscoveredDevice::default();
        device.set_instance_name("device1");

        assert!(devices.push_if_unique(device));
        assert_eq!(devices.len(), 1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn push_if_unique_std_vec_rejects_duplicate() {
        let mut devices: Vec<DiscoveredDevice> = Vec::new();

        let mut device1 = DiscoveredDevice::default();
        device1.set_instance_name("device1");
        devices.push_if_unique(device1);

        let mut device2 = DiscoveredDevice::default();
        device2.set_instance_name("device1");

        assert!(!devices.push_if_unique(device2));
        assert_eq!(devices.len(), 1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn push_if_unique_std_vec_rejects_case_insensitive_duplicate() {
        let mut devices: Vec<DiscoveredDevice> = Vec::new();

        let mut device1 = DiscoveredDevice::default();
        device1.set_instance_name("device1");
        devices.push_if_unique(device1);

        let mut device2 = DiscoveredDevice::default();
        device2.set_instance_name("Device1");

        assert!(!devices.push_if_unique(device2));
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn score_ip_address_ipv6_link_local_highest() {
        // fe80::1 is link-local
        let addr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(score_ip_address(&addr), 100);
    }

    #[test]
    fn score_ip_address_ipv6_unique_local() {
        // fd00::1 is unique local (ULA)
        let addr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(score_ip_address(&addr), 80);

        // fc00::1 is also ULA
        let addr2 = IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(score_ip_address(&addr2), 80);
    }

    #[test]
    fn score_ip_address_ipv6_global_unicast() {
        // 2001:db8::1 is global unicast
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(score_ip_address(&addr), 60);
    }

    #[test]
    fn score_ip_address_ipv6_other() {
        // ::1 is loopback (not link-local, ULA, or global unicast)
        let addr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(score_ip_address(&addr), 40);
    }

    #[test]
    fn score_ip_address_ipv4_lowest() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(score_ip_address(&addr), 20);
    }

    #[test]
    fn score_ip_address_priority_order() {
        let link_local = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let ula = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let global = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        assert!(score_ip_address(&link_local) > score_ip_address(&ula));
        assert!(score_ip_address(&ula) > score_ip_address(&global));
        assert!(score_ip_address(&global) > score_ip_address(&ipv4));
    }

    #[test]
    fn device_addr_returns_none_when_empty() {
        let device = DiscoveredDevice::default();
        assert!(device.addr().is_none());
        assert!(device.addresses().is_empty());
    }

    #[test]
    fn device_add_address_single() {
        let mut device = DiscoveredDevice::default();
        device.port = 5540;
        device.add_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        assert_eq!(device.addresses().len(), 1);
        assert_eq!(
            device.addr(),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                5540
            ))
        );
    }

    #[test]
    fn device_add_address_maintains_priority_order() {
        let mut device = DiscoveredDevice::default();
        device.port = 5540;

        // Add in wrong order - IPv4 first, then link-local IPv6
        device.add_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        device.add_address(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));

        // Link-local IPv6 should be first (highest priority)
        assert_eq!(device.addresses().len(), 2);
        assert_eq!(
            device.addresses()[0],
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(
            device.addresses()[1],
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn device_add_address_rejects_duplicates() {
        let mut device = DiscoveredDevice::default();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        device.add_address(addr);
        device.add_address(addr); // Duplicate

        assert_eq!(device.addresses().len(), 1);
    }

    #[test]
    fn device_add_address_limits_to_max() {
        let mut device = DiscoveredDevice::default();

        // Add more than MAX_ADDRESSES_PER_DEVICE addresses
        for i in 0..10u8 {
            device.add_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)));
        }

        assert_eq!(device.addresses().len(), MAX_ADDRESSES_PER_DEVICE);
    }

    #[test]
    fn device_add_address_evicts_lower_priority() {
        let mut device = DiscoveredDevice::default();

        // Fill with IPv4 addresses (lowest priority)
        for i in 0..MAX_ADDRESSES_PER_DEVICE as u8 {
            device.add_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)));
        }

        assert_eq!(device.addresses().len(), MAX_ADDRESSES_PER_DEVICE);

        // Add a link-local IPv6 (highest priority) - should evict an IPv4
        let link_local = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        device.add_address(link_local);

        assert_eq!(device.addresses().len(), MAX_ADDRESSES_PER_DEVICE);
        assert_eq!(device.addresses()[0], link_local);
    }

    #[test]
    fn device_set_addr_clears_and_sets() {
        let mut device = DiscoveredDevice::default();

        // Add multiple addresses
        device.add_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        device.add_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        assert_eq!(device.addresses().len(), 2);

        // set_addr should clear and set single address
        device.set_addr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5540,
        ));

        assert_eq!(device.addresses().len(), 1);
        assert_eq!(
            device.addresses()[0],
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(device.port, 5540);
    }

    #[test]
    fn device_socket_addresses_iterator() {
        let mut device = DiscoveredDevice::default();
        device.port = 5540;
        device.add_address(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        device.add_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        let addrs: Vec<SocketAddr> = device.socket_addresses().collect();
        assert_eq!(addrs.len(), 2);
        assert_eq!(
            addrs[0],
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 5540)
        );
        assert_eq!(
            addrs[1],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5540)
        );
    }

    #[test]
    fn is_ipv6_link_local_correct() {
        // fe80::/10 range
        assert!(is_ipv6_link_local(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_ipv6_link_local(&Ipv6Addr::new(
            0xfebf, 0xffff, 0, 0, 0, 0, 0, 1
        )));

        // Not link-local
        assert!(!is_ipv6_link_local(&Ipv6Addr::new(
            0xfec0, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_link_local(&Ipv6Addr::new(
            0x2001, 0, 0, 0, 0, 0, 0, 1
        )));
    }

    #[test]
    fn is_ipv6_unique_local_correct() {
        // fc00::/7 range
        assert!(is_ipv6_unique_local(&Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_ipv6_unique_local(&Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_ipv6_unique_local(&Ipv6Addr::new(
            0xfdff, 0xffff, 0, 0, 0, 0, 0, 1
        )));

        // Not ULA
        assert!(!is_ipv6_unique_local(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_unique_local(&Ipv6Addr::new(
            0x2001, 0, 0, 0, 0, 0, 0, 1
        )));
    }

    #[test]
    fn is_ipv6_global_unicast_correct() {
        // 2000::/3 range
        assert!(is_ipv6_global_unicast(&Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_ipv6_global_unicast(&Ipv6Addr::new(
            0x2607, 0xf8b0, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_ipv6_global_unicast(&Ipv6Addr::new(
            0x3fff, 0xffff, 0, 0, 0, 0, 0, 1
        )));

        // Not global unicast
        assert!(!is_ipv6_global_unicast(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_global_unicast(&Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_global_unicast(&Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0, 1
        )));
    }
}
