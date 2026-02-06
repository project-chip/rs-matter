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

//! mDNS querier for discovering Matter devices.
//!
//! This module provides functionality to discover commissionable Matter devices
//! on the local network using mDNS (multicast DNS).

use core::fmt::Write;
use core::pin::pin;

use domain::base::header::Flags;
use domain::base::iana::{Class, Opcode, Rcode, Rtype};
use domain::base::message_builder::MessageBuilder;
use domain::base::{Message, Name};
use domain::rdata::{Aaaa, Ptr, Srv, Txt, A};

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Instant, Timer};

use super::proto::Buf;

use crate::error::Error;
use crate::transport::network::mdns::{
    CommissionableFilter, DiscoveredDevice, MAX_DISCOVERED_DEVICES, MDNS_IPV4_BROADCAST_ADDR,
    MDNS_IPV6_BROADCAST_ADDR, MDNS_PORT,
};
use crate::transport::network::{
    Address, IpAddr, Ipv4Addr, NetworkReceive, NetworkSend, SocketAddr, SocketAddrV4, SocketAddrV6,
};

/// Internal state for tracking a device being discovered
#[derive(Debug, Clone, Default)]
struct DiscoveryState {
    /// The device info we're building up
    device: DiscoveredDevice,
    /// Have we received a port?
    has_port: bool,
    /// Have we received TXT records?
    has_txt: bool,
    /// The hostname from SRV record (needed to match A/AAAA records)
    hostname: heapless::String<64>,
}

impl DiscoveryState {
    fn is_complete(&self) -> bool {
        !self.device.addresses().is_empty() && self.has_port && self.has_txt
    }
}

/// Build an mDNS query for PTR records of a service type
fn build_ptr_query(service_type: &str, buf: &mut [u8]) -> Result<usize, Error> {
    let buf = Buf(buf, 0);
    let message = MessageBuilder::from_target(buf)?;

    let mut question = message.question();

    // Set query header (QR=0 for query)
    let header = question.header_mut();
    header.set_id(0); // mDNS queries use ID 0
    header.set_opcode(Opcode::QUERY);
    header.set_rcode(Rcode::NOERROR);

    let mut flags = Flags::new();
    flags.qr = false; // This is a query
    header.set_flags(flags);

    // Add PTR question WITHOUT QU (unicast response requested) bit
    // We want multicast responses so all listeners receive them
    // With QU bit, responses may be unicast and get routed to the wrong socket
    // when multiple processes share port 5353 with SO_REUSEPORT
    let name = Name::<heapless::Vec<u8, 64>>::from_chars(service_type.chars())?;
    question.push((&name, Rtype::PTR, Class::IN))?;

    let buf = question.finish();
    Ok(buf.1)
}

/// Check if two domain names match
fn names_match(name1: &str, name2: &str) -> bool {
    name1
        .trim_end_matches('.')
        .eq_ignore_ascii_case(name2.trim_end_matches('.'))
}

/// Parse TXT record key-value pairs directly from the Txt record
fn parse_txt_record(txt: &Txt<&[u8]>, device: &mut DiscoveredDevice) {
    for item in txt.iter() {
        // Each item is a raw string like b"D=3840"
        if let Some(eq_pos) = item.iter().position(|&b| b == b'=') {
            let key = &item[..eq_pos];
            let value = &item[eq_pos + 1..];

            if let (Ok(key_str), Ok(value_str)) =
                (core::str::from_utf8(key), core::str::from_utf8(value))
            {
                device.set_txt_value(key_str, value_str);
            }
        }
    }
}

/// Process SRV record and update matching states
fn process_srv(
    owner: &str,
    port: u16,
    target: &str,
    states: &mut heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES>,
) {
    for state in states.iter_mut() {
        if names_match(owner, state.device.instance_name.as_str()) {
            state.device.port = port;
            state.has_port = true;
            state.hostname.clear();
            let _ = write!(&mut state.hostname, "{}", target.trim_end_matches('.'));
        }
    }
}

/// Process TXT record and update matching states
fn process_txt(
    owner: &str,
    txt: &Txt<&[u8]>,
    states: &mut heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES>,
) {
    for state in states.iter_mut() {
        if names_match(owner, state.device.instance_name.as_str()) {
            parse_txt_record(txt, &mut state.device);
            state.has_txt = true;
        }
    }
}

/// Process A record (IPv4) and update matching states
fn process_a(
    owner: &str,
    ip: Ipv4Addr,
    states: &mut heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES>,
) {
    for state in states.iter_mut() {
        if !state.hostname.is_empty() && names_match(owner, state.hostname.as_str()) {
            state.device.add_address(IpAddr::V4(ip));
        }
    }
}

/// Process AAAA record (IPv6) and update matching states
fn process_aaaa(
    owner: &str,
    ip: core::net::Ipv6Addr,
    states: &mut heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES>,
) {
    for state in states.iter_mut() {
        if !state.hostname.is_empty() && names_match(owner, state.hostname.as_str()) {
            state.device.add_address(IpAddr::V6(ip));
        }
    }
}

/// Parse an mDNS response and update discovery state
fn parse_response(
    data: &[u8],
    states: &mut heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES>,
) -> Result<(), Error> {
    let message = Message::from_octets(data)?;

    // Check if this is a response (QR=1)
    if !message.header().flags().qr {
        return Ok(()); // Not a response, ignore
    }

    // Process answer section
    if let Ok(answer) = message.answer() {
        for record in answer.flatten() {
            let owner = record.owner().to_string();

            if let Ok(Some(ptr)) = record.to_record::<Ptr<_>>() {
                let instance_name = ptr.data().ptrdname().to_string();

                let exists = states
                    .iter()
                    .any(|s| s.device.instance_name.as_str() == instance_name.as_str());

                if !exists && states.len() < MAX_DISCOVERED_DEVICES {
                    let mut state = DiscoveryState::default();
                    state.device.set_instance_name(&instance_name);
                    let _ = states.push(state);
                }
                continue;
            }

            if let Ok(Some(srv)) = record.to_record::<Srv<_>>() {
                process_srv(
                    &owner,
                    srv.data().port(),
                    &srv.data().target().to_string(),
                    states,
                );
                continue;
            }

            if let Ok(Some(txt)) = record.to_record::<Txt<_>>() {
                process_txt(&owner, txt.data(), states);
                continue;
            }

            if let Ok(Some(a)) = record.to_record::<A>() {
                process_a(&owner, Ipv4Addr::from(a.data().addr().octets()), states);
                continue;
            }

            if let Ok(Some(aaaa)) = record.to_record::<Aaaa>() {
                process_aaaa(
                    &owner,
                    core::net::Ipv6Addr::from(aaaa.data().addr().octets()),
                    states,
                );
            }
        }
    }

    // Also check additional section for SRV, TXT, A, and AAAA records
    if let Ok(additional) = message.additional() {
        for record in additional.flatten() {
            let owner = record.owner().to_string();

            if let Ok(Some(srv)) = record.to_record::<Srv<_>>() {
                process_srv(
                    &owner,
                    srv.data().port(),
                    &srv.data().target().to_string(),
                    states,
                );
                continue;
            }

            if let Ok(Some(txt)) = record.to_record::<Txt<_>>() {
                process_txt(&owner, txt.data(), states);
                continue;
            }

            if let Ok(Some(a)) = record.to_record::<A>() {
                process_a(&owner, Ipv4Addr::from(a.data().addr().octets()), states);
                continue;
            }

            if let Ok(Some(aaaa)) = record.to_record::<Aaaa>() {
                process_aaaa(
                    &owner,
                    core::net::Ipv6Addr::from(aaaa.data().addr().octets()),
                    states,
                );
            }
        }
    }

    Ok(())
}

/// Discover commissionable Matter devices on the network.
///
/// # Arguments
/// * `send` - Network send interface for sending mDNS queries
/// * `recv` - Network receive interface for receiving mDNS responses
/// * `filter` - Optional filter criteria for discovered devices
/// * `timeout_ms` - Discovery timeout in milliseconds
/// * `ipv4_interface` - Optional IPv4 interface address for sending queries
/// * `ipv6_interface` - Optional IPv6 interface index for sending queries
///
/// # Returns
/// A vector of discovered devices matching the filter criteria
pub async fn discover_commissionable<S, R>(
    send: &mut S,
    recv: &mut R,
    filter: &CommissionableFilter,
    timeout_ms: u32,
    ipv4_interface: Option<Ipv4Addr>,
    ipv6_interface: Option<u32>,
) -> Result<heapless::Vec<DiscoveredDevice, MAX_DISCOVERED_DEVICES>, Error>
where
    S: NetworkSend,
    R: NetworkReceive,
{
    let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> = heapless::Vec::new();
    let mut query_buf = [0u8; 512];
    let mut recv_buf = [0u8; 1500];

    // Build the service type query
    let mut service_type = heapless::String::<64>::new();
    filter.service_type(&mut service_type, true);

    // Build the query
    let query_len = build_ptr_query(&service_type, &mut query_buf)?;

    debug!("Built mDNS query: {} bytes for {}", query_len, service_type);

    // Send query to mDNS multicast addresses
    for addr in Iterator::chain(
        ipv4_interface
            .map(|_| SocketAddr::V4(SocketAddrV4::new(MDNS_IPV4_BROADCAST_ADDR, MDNS_PORT)))
            .into_iter(),
        ipv6_interface
            .map(|interface| {
                SocketAddr::V6(SocketAddrV6::new(
                    MDNS_IPV6_BROADCAST_ADDR,
                    MDNS_PORT,
                    0,
                    interface,
                ))
            })
            .into_iter(),
    ) {
        info!("Sending mDNS query for {} to {}", service_type, addr);
        if let Err(e) = send
            .send_to(&query_buf[..query_len], Address::Udp(addr))
            .await
        {
            warn!("Failed to send mDNS query to {}: {:?}", addr, e);
        }
    }

    // Collect responses until timeout
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.as_millis() == 0 {
            break;
        }

        // Use a simple timeout-based receive approach
        let recv_result = {
            let mut timer = pin!(Timer::after(remaining));
            let mut recv_op = pin!(async {
                recv.wait_available().await?;
                recv.recv_from(&mut recv_buf).await
            });

            select(&mut recv_op, &mut timer).await
        };

        match recv_result {
            Either::First(Ok((len, addr))) => {
                debug!("Received mDNS packet from {}, {} bytes", addr, len);

                if let Err(e) = parse_response(&recv_buf[..len], &mut states) {
                    debug!("Failed to parse mDNS response: {:?}", e);
                }
            }
            Either::First(Err(e)) => {
                debug!("Error receiving mDNS response: {:?}", e);
                break;
            }
            Either::Second(_) => {
                // Timeout
                break;
            }
        }
    }

    // Filter and collect complete results
    let mut results: heapless::Vec<DiscoveredDevice, MAX_DISCOVERED_DEVICES> = heapless::Vec::new();

    for state in states {
        if !state.is_complete() {
            debug!(
                "Incomplete device discovery for '{}': addresses={}, has_port={}, has_txt={}",
                state.device.instance_name,
                state.device.addresses().len(),
                state.has_port,
                state.has_txt
            );
            continue;
        }

        // Apply any additional filters on the TXT record data
        if !filter.matches(&state.device) {
            continue;
        }

        if results.push(state.device).is_err() {
            break; // Results full
        }
    }

    info!("mDNS discovery found {} devices", results.len());

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a DiscoveryState with a given instance name
    fn make_state(instance_name: &str) -> DiscoveryState {
        let mut state = DiscoveryState::default();
        state.device.set_instance_name(instance_name);
        state
    }

    // Helper to create a DiscoveryState with instance name and hostname
    fn make_state_with_hostname(instance_name: &str, hostname: &str) -> DiscoveryState {
        let mut state = make_state(instance_name);
        let _ = write!(&mut state.hostname, "{}", hostname);
        state
    }

    #[test]
    fn names_match_exact() {
        assert!(names_match("example.local", "example.local"));
    }

    #[test]
    fn names_match_trailing_dot_left() {
        assert!(names_match("example.local.", "example.local"));
    }

    #[test]
    fn names_match_trailing_dot_right() {
        assert!(names_match("example.local", "example.local."));
    }

    #[test]
    fn names_match_trailing_dot_both() {
        assert!(names_match("example.local.", "example.local."));
    }

    #[test]
    fn names_match_case_insensitive() {
        assert!(names_match("Example.Local", "example.local"));
        assert!(names_match("EXAMPLE.LOCAL", "example.local"));
        assert!(names_match("example.local", "EXAMPLE.LOCAL"));
    }

    #[test]
    fn names_match_case_insensitive_with_trailing_dot() {
        assert!(names_match("Example.Local.", "example.local"));
        assert!(names_match("example.local", "EXAMPLE.LOCAL."));
    }

    #[test]
    fn names_match_different_names() {
        assert!(!names_match("device1.local", "device2.local"));
        assert!(!names_match("example.local", "example.com"));
    }

    #[test]
    fn names_match_prefix_not_matched() {
        // Ensure we don't do prefix matching (this was a previous bug)
        assert!(!names_match("device.local", "device.local.extra"));
        assert!(!names_match("device", "device.local"));
    }

    #[test]
    fn names_match_service_instance_names() {
        // Real-world Matter service instance names
        assert!(names_match(
            "ABCD1234._matterc._udp.local.",
            "ABCD1234._matterc._udp.local"
        ));
        assert!(names_match(
            "abcd1234._matterc._udp.local",
            "ABCD1234._MATTERC._UDP.LOCAL."
        ));
    }

    #[test]
    fn parse_txt_record_single_item() {
        // Create a Txt record with a single item
        let txt_data = [6, b'D', b'=', b'1', b'2', b'3', b'4'];
        let txt = Txt::from_octets(&txt_data[..]).unwrap();
        let mut device = DiscoveredDevice::default();
        parse_txt_record(&txt, &mut device);
        assert_eq!(device.discriminator, 1234);
    }

    #[test]
    fn parse_txt_record_empty() {
        // Empty TXT record (just a zero-length string per RFC)
        let txt_data = [0u8];
        let txt = Txt::from_octets(&txt_data[..]).unwrap();
        let mut device = DiscoveredDevice::default();
        parse_txt_record(&txt, &mut device);
        // Device should remain at defaults
        assert_eq!(device.discriminator, 0);
    }

    #[test]
    fn test_build_ptr_query() {
        let mut buf = [0u8; 512];
        let len = build_ptr_query("_matterc._udp.local", &mut buf).unwrap();

        assert!(len > 0);

        // Verify it's a valid DNS message
        let message = Message::from_octets(&buf[..len]).unwrap();
        assert!(!message.header().flags().qr); // Should be a query
        assert_eq!(message.header().opcode(), Opcode::QUERY);
    }

    #[test]
    fn test_parse_txt_record() {
        let mut device = DiscoveredDevice::default();

        // TXT record format: length-prefixed strings
        // D=3840, VP=65521+32769, DN=Test Device
        let txt_data = [
            6, b'D', b'=', b'3', b'8', b'4', b'0', // D=3840
            14, b'V', b'P', b'=', b'6', b'5', b'5', b'2', b'1', b'+', b'3', b'2', b'7', b'6',
            b'9', // VP=65521+32769
            14, b'D', b'N', b'=', b'T', b'e', b's', b't', b' ', b'D', b'e', b'v', b'i', b'c',
            b'e', // DN=Test Device
        ];
        let txt = Txt::from_octets(&txt_data[..]).unwrap();

        parse_txt_record(&txt, &mut device);

        assert_eq!(device.discriminator, 3840);
        assert_eq!(device.vendor_id, 65521);
        assert_eq!(device.product_id, 32769);
        assert_eq!(device.device_name.as_str(), "Test Device");
    }

    #[test]
    fn parse_txt_record_with_all_fields() {
        let mut device = DiscoveredDevice::default();

        // D=1234, VP=100+200, CM=1, DT=257, DN=Light, SII=5000, SAI=300, PH=33, PI=Press
        #[rustfmt::skip]
        let txt_data = [
            6, b'D', b'=', b'1', b'2', b'3', b'4',           // D=1234
            10, b'V', b'P', b'=', b'1', b'0', b'0', b'+', b'2', b'0', b'0', // VP=100+200
            4, b'C', b'M', b'=', b'1',                       // CM=1
            6, b'D', b'T', b'=', b'2', b'5', b'7',           // DT=257
            8, b'D', b'N', b'=', b'L', b'i', b'g', b'h', b't', // DN=Light
            8, b'S', b'I', b'I', b'=', b'5', b'0', b'0', b'0', // SII=5000
            7, b'S', b'A', b'I', b'=', b'3', b'0', b'0',     // SAI=300
            5, b'P', b'H', b'=', b'3', b'3',                 // PH=33
            8, b'P', b'I', b'=', b'P', b'r', b'e', b's', b's', // PI=Press
        ];
        let txt = Txt::from_octets(&txt_data[..]).unwrap();

        parse_txt_record(&txt, &mut device);

        assert_eq!(device.discriminator, 1234);
        assert_eq!(device.vendor_id, 100);
        assert_eq!(device.product_id, 200);
        assert_eq!(
            device.commissioning_mode,
            crate::transport::network::mdns::CommissioningMode::Basic
        );
        assert_eq!(device.device_type, 257);
        assert_eq!(device.device_name.as_str(), "Light");
        assert_eq!(device.mrp_retry_interval_idle, Some(5000));
        assert_eq!(device.mrp_retry_interval_active, Some(300));
        assert_eq!(device.pairing_hint, Some(33));
        assert_eq!(device.pairing_instruction.as_str(), "Press");
    }

    #[test]
    fn parse_txt_record_malformed_no_equals() {
        let mut device = DiscoveredDevice::default();

        // Item without equals sign should be skipped
        let txt_data = [4, b'T', b'E', b'S', b'T'];
        let txt = Txt::from_octets(&txt_data[..]).unwrap();

        parse_txt_record(&txt, &mut device);

        // Device should remain at defaults
        assert_eq!(device.discriminator, 0);
    }

    #[test]
    fn process_srv_updates_matching_state() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state("device1._matterc._udp.local"))
            .unwrap();

        process_srv(
            "device1._matterc._udp.local.",
            5540,
            "device1-host.local.",
            &mut states,
        );

        assert_eq!(states[0].device.port, 5540);
        assert!(states[0].has_port);
        assert_eq!(states[0].hostname.as_str(), "device1-host.local");
    }

    #[test]
    fn process_srv_case_insensitive_match() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state("DEVICE1._matterc._udp.local"))
            .unwrap();

        process_srv(
            "device1._matterc._udp.local.",
            5540,
            "host.local.",
            &mut states,
        );

        assert_eq!(states[0].device.port, 5540);
        assert!(states[0].has_port);
    }

    #[test]
    fn process_srv_no_match() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state("device1._matterc._udp.local"))
            .unwrap();

        process_srv(
            "device2._matterc._udp.local.",
            5540,
            "host.local.",
            &mut states,
        );

        assert_eq!(states[0].device.port, 0);
        assert!(!states[0].has_port);
    }

    #[test]
    fn process_srv_multiple_states() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state("device1._matterc._udp.local"))
            .unwrap();
        states
            .push(make_state("device2._matterc._udp.local"))
            .unwrap();

        process_srv(
            "device2._matterc._udp.local.",
            5541,
            "host2.local.",
            &mut states,
        );

        // First device unchanged
        assert_eq!(states[0].device.port, 0);
        assert!(!states[0].has_port);

        // Second device updated
        assert_eq!(states[1].device.port, 5541);
        assert!(states[1].has_port);
        assert_eq!(states[1].hostname.as_str(), "host2.local");
    }

    #[test]
    fn process_srv_strips_trailing_dot_from_target() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state("device1._matterc._udp.local"))
            .unwrap();

        process_srv(
            "device1._matterc._udp.local",
            5540,
            "hostname.local.",
            &mut states,
        );

        // Hostname should have trailing dot stripped
        assert_eq!(states[0].hostname.as_str(), "hostname.local");
    }

    #[test]
    fn process_a_updates_matching_state() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state_with_hostname(
                "device1._matterc._udp.local",
                "host.local",
            ))
            .unwrap();

        let ip = Ipv4Addr::new(192, 168, 1, 100);
        process_a("host.local.", ip, &mut states);

        assert_eq!(states[0].device.addresses().len(), 1);
        assert_eq!(states[0].device.addresses()[0], IpAddr::V4(ip));
    }

    #[test]
    fn process_a_case_insensitive_match() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state_with_hostname(
                "device1._matterc._udp.local",
                "HOST.LOCAL",
            ))
            .unwrap();

        let ip = Ipv4Addr::new(192, 168, 1, 100);
        process_a("host.local.", ip, &mut states);

        assert_eq!(states[0].device.addresses().len(), 1);
    }

    #[test]
    fn process_a_no_match_wrong_hostname() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state_with_hostname(
                "device1._matterc._udp.local",
                "host1.local",
            ))
            .unwrap();

        let ip = Ipv4Addr::new(192, 168, 1, 100);
        process_a("host2.local.", ip, &mut states);

        assert!(states[0].device.addresses().is_empty());
    }

    #[test]
    fn process_a_no_match_empty_hostname() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        // State without hostname set (no SRV record received yet)
        states
            .push(make_state("device1._matterc._udp.local"))
            .unwrap();

        let ip = Ipv4Addr::new(192, 168, 1, 100);
        process_a("host.local.", ip, &mut states);

        // Should not add IP since hostname is empty
        assert!(states[0].device.addresses().is_empty());
    }

    #[test]
    fn process_a_multiple_addresses() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state_with_hostname(
                "device1._matterc._udp.local",
                "host.local",
            ))
            .unwrap();

        process_a("host.local", Ipv4Addr::new(192, 168, 1, 100), &mut states);
        process_a("host.local", Ipv4Addr::new(192, 168, 1, 101), &mut states);

        assert_eq!(states[0].device.addresses().len(), 2);
    }

    #[test]
    fn process_aaaa_updates_matching_state() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state_with_hostname(
                "device1._matterc._udp.local",
                "host.local",
            ))
            .unwrap();

        let ip = core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        process_aaaa("host.local.", ip, &mut states);

        assert_eq!(states[0].device.addresses().len(), 1);
        assert_eq!(states[0].device.addresses()[0], IpAddr::V6(ip));
    }

    #[test]
    fn process_aaaa_case_insensitive_match() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state_with_hostname(
                "device1._matterc._udp.local",
                "host.local",
            ))
            .unwrap();

        let ip = core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        process_aaaa("HOST.LOCAL.", ip, &mut states);

        assert_eq!(states[0].device.addresses().len(), 1);
    }

    #[test]
    fn process_aaaa_no_match_empty_hostname() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state("device1._matterc._udp.local"))
            .unwrap();

        let ip = core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        process_aaaa("host.local.", ip, &mut states);

        assert!(states[0].device.addresses().is_empty());
    }

    #[test]
    fn process_aaaa_multiple_addresses() {
        let mut states: heapless::Vec<DiscoveryState, MAX_DISCOVERED_DEVICES> =
            heapless::Vec::new();
        states
            .push(make_state_with_hostname(
                "device1._matterc._udp.local",
                "host.local",
            ))
            .unwrap();

        let ip1 = core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let ip2 = core::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        process_aaaa("host.local", ip1, &mut states);
        process_aaaa("host.local", ip2, &mut states);

        assert_eq!(states[0].device.addresses().len(), 2);
    }

    #[test]
    fn discovery_state_is_complete_all_fields() {
        let mut state = make_state_with_hostname("device1._matterc._udp.local", "host.local");
        state.device.port = 5540;
        state
            .device
            .add_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        state.has_port = true;
        state.has_txt = true;

        assert!(state.is_complete());
    }

    #[test]
    fn discovery_state_incomplete_no_address() {
        let mut state = make_state("device1._matterc._udp.local");
        state.has_port = true;
        state.has_txt = true;

        assert!(!state.is_complete());
    }

    #[test]
    fn discovery_state_incomplete_no_port() {
        let mut state = make_state("device1._matterc._udp.local");
        state
            .device
            .add_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        state.has_txt = true;

        assert!(!state.is_complete());
    }

    #[test]
    fn discovery_state_incomplete_no_txt() {
        let mut state = make_state("device1._matterc._udp.local");
        state
            .device
            .add_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        state.has_port = true;

        assert!(!state.is_complete());
    }
}
